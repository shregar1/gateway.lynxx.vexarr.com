//! S3-FIFO + TinyLFU cache eviction (TinyUFO variant).
//!
//! Two FIFO queues (small = 10% capacity, main = 90%) with a Count-Min Sketch
//! for TinyLFU admission filtering.  Achieves better hit ratios than LRU on
//! real workloads with frequency-skewed access patterns.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};

// ── Count-Min Sketch ────────────────────────────────────────────────

struct CountMinSketch {
    table: Vec<Vec<u32>>,
    depth: usize,
    width: usize,
    additions: u64,
    reset_threshold: u64,
}

impl CountMinSketch {
    fn new(width: usize, depth: usize) -> Self {
        Self {
            table: vec![vec![0u32; width]; depth],
            depth,
            width,
            additions: 0,
            reset_threshold: (width as u64) * 10,
        }
    }

    fn increment(&mut self, hash: u64) {
        for i in 0..self.depth {
            let idx = self.index(hash, i);
            self.table[i][idx] = self.table[i][idx].saturating_add(1);
        }
        self.additions += 1;
        if self.additions >= self.reset_threshold {
            self.reset();
        }
    }

    fn estimate(&self, hash: u64) -> u32 {
        let mut min = u32::MAX;
        for i in 0..self.depth {
            let idx = self.index(hash, i);
            min = min.min(self.table[i][idx]);
        }
        min
    }

    fn reset(&mut self) {
        for row in &mut self.table {
            for cell in row.iter_mut() {
                *cell /= 2;
            }
        }
        self.additions = 0;
    }

    #[inline]
    fn index(&self, hash: u64, row: usize) -> usize {
        let h = hash.wrapping_mul(0x9E3779B97F4A7C15u64.wrapping_add(row as u64));
        (h as usize ^ (h >> 32) as usize) % self.width
    }
}

// ── Cache entry & location ──────────────────────────────────────────

struct CacheEntry<K, V> {
    key: K,
    value: V,
    weight: u16,
    freq: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    Small,
    Main,
}

// ── S3FifoCache ─────────────────────────────────────────────────────

/// S3-FIFO cache with TinyLFU admission filtering.
///
/// Maintains two FIFO queues — *small* (≈10 % of capacity) and *main*
/// (≈90 %) — plus a ghost list of recently-evicted key hashes. A Count-Min
/// Sketch tracks access frequency for admission decisions.
///
/// **Insertion flow:**
/// 1. New keys enter the *small* queue.
/// 2. If a key's hash is found in the ghost list (prior eviction), it is
///    promoted directly into *main*.
/// 3. When the small queue exceeds its budget, entries with `freq > 0` are
///    promoted to *main*; zero-frequency entries are evicted and their hash
///    is added to the ghost list.
/// 4. Main-queue eviction decrements frequency counters, giving popular
///    entries multiple chances before removal.
///
/// Frequency is capped at 3 to prevent pollution from brief bursts.
///
/// # Examples
///
/// ```
/// use lynxx_structures::s3fifo::S3FifoCache;
///
/// let mut cache = S3FifoCache::new(100);
/// cache.insert("route:/api/v1", "upstream_a");
/// cache.insert_weighted("route:/static", "cdn_node", 5);
///
/// if let Some(upstream) = cache.get(&"route:/api/v1") {
///     println!("hit: {upstream}");
/// }
/// ```
pub struct S3FifoCache<K: Clone + Eq + Hash, V: Clone> {
    small: VecDeque<CacheEntry<K, V>>,
    main: VecDeque<CacheEntry<K, V>>,
    /// Recently-evicted key *hashes* (not full keys) — the standard space-saving
    /// ghost-list design. A 64-bit hash collision would cause one spurious
    /// promotion to `main`; at any realistic cache size the birthday-bound
    /// probability is negligible, so this is an accepted trade-off vs. storing
    /// full keys.
    ghost: VecDeque<u64>,
    map: HashMap<K, Location>,
    freq: CountMinSketch,
    capacity: usize,
    small_capacity: usize,
    current_size: usize,
}

impl<K: Clone + Eq + Hash, V: Clone> S3FifoCache<K, V> {
    /// Build an S3-FIFO cache. `capacity` is the maximum total weight of all
    /// entries (clamped to a minimum of 1). The small queue is sized to 10 %
    /// of capacity and the Count-Min Sketch width matches `capacity`.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let small_capacity = (capacity / 10).max(1);
        Self {
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghost: VecDeque::new(),
            map: HashMap::new(),
            freq: CountMinSketch::new(capacity.max(64), 4),
            capacity,
            small_capacity,
            current_size: 0,
        }
    }

    /// Look up `key`, incrementing its frequency counter (capped at 3) and
    /// updating the Count-Min Sketch. Returns `None` on a miss.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let loc = self.map.get(key)?;
        let queue = match loc {
            Location::Small => &mut self.small,
            Location::Main => &mut self.main,
        };
        for entry in queue.iter_mut() {
            if entry.key == *key {
                entry.freq = entry.freq.saturating_add(1).min(3);
                let h = hash_key(key);
                self.freq.increment(h);
                return Some(&entry.value);
            }
        }
        None
    }

    /// Insert `key`/`value` with a default weight of 1.
    /// Equivalent to `insert_weighted(key, value, 1)`.
    pub fn insert(&mut self, key: K, value: V) {
        self.insert_weighted(key, value, 1);
    }

    /// Insert `key`/`value` with an explicit `weight` (clamped to ≥ 1).
    /// If the key already exists, its value and weight are updated in place.
    /// New keys enter the small queue unless their hash is in the ghost list,
    /// in which case they are promoted directly to main.
    pub fn insert_weighted(&mut self, key: K, value: V, weight: u16) {
        let weight = weight.max(1);
        let incoming_hash = hash_key(&key);
        self.freq.increment(incoming_hash);

        if let Some(loc) = self.map.get(&key) {
            let queue = match loc {
                Location::Small => &mut self.small,
                Location::Main => &mut self.main,
            };
            for entry in queue.iter_mut() {
                if entry.key == key {
                    let old_w = entry.weight as usize;
                    entry.value = value;
                    entry.weight = weight;
                    entry.freq = entry.freq.saturating_add(1).min(3);
                    self.current_size = self.current_size - old_w + weight as usize;
                    return;
                }
            }
        }

        while self.current_size + weight as usize > self.capacity && !self.map.is_empty() {
            self.evict();
        }

        let is_ghost = self.ghost.contains(&incoming_hash);

        if is_ghost {
            // TinyLFU admission: a ghost hit means this key was recently
            // evicted. Seed the re-admitted entry's frequency from the Count-Min
            // Sketch estimate (capped at the freq ceiling of 3) so a genuinely
            // hot key re-enters `main` with standing and survives more eviction
            // passes, while a one-hit wonder does not. This is the admission
            // decision the sketch is maintained for — previously the sketch was
            // incremented on every access but its estimate was never read.
            let seed_freq = self.freq.estimate(incoming_hash).min(3) as u8;
            self.main.push_back(CacheEntry {
                key: key.clone(),
                value,
                weight,
                freq: seed_freq,
            });
            self.map.insert(key, Location::Main);
        } else {
            self.small.push_back(CacheEntry {
                key: key.clone(),
                value,
                weight,
                freq: 0,
            });
            self.map.insert(key, Location::Small);
        }
        self.current_size += weight as usize;
    }

    /// Remove `key` from whichever queue it resides in and return its value.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let loc = self.map.remove(key)?;
        let queue = match loc {
            Location::Small => &mut self.small,
            Location::Main => &mut self.main,
        };
        for i in 0..queue.len() {
            if queue[i].key == *key {
                let entry = queue.remove(i).unwrap();
                self.current_size -= entry.weight as usize;
                return Some(entry.value);
            }
        }
        None
    }

    /// Number of distinct entries across both queues.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Maximum total weight the cache can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    // ── eviction ────────────────────────────────────────────────────

    fn evict(&mut self) {
        if self.small_queue_size() > self.small_capacity || self.main.is_empty() {
            self.evict_small();
        } else {
            self.evict_main();
        }
    }

    fn evict_small(&mut self) {
        while let Some(entry) = self.small.pop_front() {
            self.map.remove(&entry.key);
            self.current_size -= entry.weight as usize;

            if entry.freq > 0 {
                self.main.push_back(CacheEntry {
                    key: entry.key.clone(),
                    value: entry.value,
                    weight: entry.weight,
                    freq: 0,
                });
                self.map.insert(entry.key, Location::Main);
                self.current_size += entry.weight as usize;
            } else {
                let h = hash_key(&entry.key);
                self.add_ghost(h);
                return;
            }
        }
        if !self.main.is_empty() {
            self.evict_main();
        }
    }

    fn evict_main(&mut self) {
        let mut attempts = self.main.len();
        while attempts > 0 {
            if let Some(mut entry) = self.main.pop_front() {
                if entry.freq > 0 {
                    entry.freq -= 1;
                    self.main.push_back(entry);
                    attempts -= 1;
                } else {
                    self.map.remove(&entry.key);
                    self.current_size -= entry.weight as usize;
                    return;
                }
            } else {
                break;
            }
        }
    }

    fn small_queue_size(&self) -> usize {
        self.small.iter().map(|e| e.weight as usize).sum()
    }

    fn add_ghost(&mut self, hash: u64) {
        let ghost_capacity = self.capacity;
        if self.ghost.len() >= ghost_capacity {
            self.ghost.pop_front();
        }
        self.ghost.push_back(hash);
    }
}

fn hash_key<K: Hash>(key: &K) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cache_is_empty() {
        let cache: S3FifoCache<u64, String> = S3FifoCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.capacity(), 100);
    }

    #[test]
    fn insert_and_get() {
        let mut cache = S3FifoCache::new(10);
        cache.insert(1u64, "one".to_string());
        assert_eq!(cache.get(&1), Some(&"one".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn overwrite_existing_key() {
        let mut cache = S3FifoCache::new(10);
        cache.insert(1u64, "one".to_string());
        cache.insert(1u64, "ONE".to_string());
        assert_eq!(cache.get(&1), Some(&"ONE".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn remove_existing_key() {
        let mut cache = S3FifoCache::new(10);
        cache.insert(1u64, "one".to_string());
        let v = cache.remove(&1);
        assert_eq!(v, Some("one".to_string()));
        assert!(cache.is_empty());
        assert_eq!(cache.get(&1), None);
    }

    #[test]
    fn remove_nonexistent_key() {
        let mut cache: S3FifoCache<u64, String> = S3FifoCache::new(10);
        assert_eq!(cache.remove(&42), None);
    }

    #[test]
    fn eviction_respects_capacity() {
        let mut cache = S3FifoCache::new(5);
        for i in 0..20u64 {
            cache.insert(i, i.to_string());
        }
        assert!(cache.len() <= 5);
        assert!(cache.current_size <= 5);
    }

    #[test]
    fn frequent_items_survive_eviction() {
        let mut cache = S3FifoCache::new(5);
        cache.insert(1u64, "hot".to_string());
        for _ in 0..5 {
            cache.get(&1);
        }

        for i in 10..20u64 {
            cache.insert(i, i.to_string());
        }
        assert_eq!(cache.get(&1), Some(&"hot".to_string()));
    }

    #[test]
    fn weighted_insert_basic() {
        let mut cache = S3FifoCache::new(10);
        cache.insert_weighted(1u64, "big".to_string(), 5);
        assert_eq!(cache.get(&1), Some(&"big".to_string()));
        assert_eq!(cache.current_size, 5);
    }

    #[test]
    fn weighted_insert_evicts_to_stay_within_capacity() {
        let mut cache = S3FifoCache::new(10);
        cache.insert_weighted(1u64, "a".to_string(), 4);
        cache.insert_weighted(2u64, "b".to_string(), 4);
        cache.insert_weighted(3u64, "c".to_string(), 4);
        assert!(cache.current_size <= 10);
    }

    #[test]
    fn ghost_promotes_to_main() {
        let mut cache = S3FifoCache::new(3);
        cache.insert(1u64, "a".to_string());
        cache.insert(2u64, "b".to_string());
        cache.insert(3u64, "c".to_string());
        cache.insert(4u64, "d".to_string());

        cache.insert(1u64, "a-again".to_string());
        assert_eq!(cache.get(&1), Some(&"a-again".to_string()));
    }

    #[test]
    fn string_keys() {
        let mut cache = S3FifoCache::new(5);
        cache.insert("hello".to_string(), 42u32);
        cache.insert("world".to_string(), 99u32);
        assert_eq!(cache.get(&"hello".to_string()), Some(&42));
        assert_eq!(cache.get(&"world".to_string()), Some(&99));
    }

    #[test]
    fn min_capacity_of_one() {
        let mut cache = S3FifoCache::new(0);
        assert_eq!(cache.capacity(), 1);
        cache.insert(1u64, "x".to_string());
        assert_eq!(cache.len(), 1);
        cache.insert(2u64, "y".to_string());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn count_min_sketch_increment_and_estimate() {
        let mut cms = CountMinSketch::new(128, 4);
        let h = 0xDEADBEEF_u64;
        assert_eq!(cms.estimate(h), 0);
        cms.increment(h);
        assert!(cms.estimate(h) >= 1);
        for _ in 0..10 {
            cms.increment(h);
        }
        assert!(cms.estimate(h) >= 10);
    }

    #[test]
    fn count_min_sketch_reset_halves() {
        let mut cms = CountMinSketch::new(128, 4);
        let h = 42u64;
        for _ in 0..100 {
            cms.increment(h);
        }
        let before = cms.estimate(h);
        cms.reset();
        let after = cms.estimate(h);
        assert!(after <= before / 2 + 1);
    }

    #[test]
    fn large_workload_no_panic() {
        let mut cache = S3FifoCache::new(100);
        for i in 0..10_000u64 {
            cache.insert(i, i);
            if i % 3 == 0 {
                cache.get(&(i / 2));
            }
        }
        assert!(cache.len() <= 100);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let mut cache: S3FifoCache<u32, u32> = S3FifoCache::new(10);
        assert_eq!(cache.get(&999), None);
    }

    #[test]
    fn frequency_capped_at_3() {
        let mut cache = S3FifoCache::new(10);
        cache.insert(1u64, "v".to_string());
        for _ in 0..100 {
            cache.get(&1);
        }
        let entry = cache.small.iter().chain(cache.main.iter())
            .find(|e| e.key == 1).unwrap();
        assert!(entry.freq <= 3);
    }

    #[test]
    fn weight_update_on_overwrite() {
        let mut cache = S3FifoCache::new(20);
        cache.insert_weighted(1u64, "a".to_string(), 5);
        assert_eq!(cache.current_size, 5);
        cache.insert_weighted(1u64, "b".to_string(), 3);
        assert_eq!(cache.current_size, 3);
    }
}
