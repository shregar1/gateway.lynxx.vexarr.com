use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};

/// Cost-LFU with Size-aware admission cache (CLFUS).
///
/// Combines an LRU eviction order with a frequency×size value score and a
/// probabilistic seen-filter to reject one-hit-wonder insertions.
///
/// **Admission policy:**
/// 1. A Bloom-like *seen filter* blocks the very first insertion of any key,
///    allowing it only on the second attempt (filters one-hit-wonders).
/// 2. Once seen, the incoming item's *value score* (`hits / size`) must exceed
///    a running exponential moving average of evicted items' scores.
///
/// **Eviction policy:** scans the LRU-coldest quarter for the entry with the
/// lowest value score, evicts it, and records its metadata in a bounded ghost
/// history list so `was_recently_evicted` can be queried.
pub struct ClfusCache<K: Clone + Eq + Hash, V: Clone> {
    data: HashMap<K, ClfusEntry<K, V>>,
    history: VecDeque<HistoryEntry>,
    seen_filter: Vec<u16>,
    capacity: usize,
    current_size: usize,
    average_value: f64,
    history_capacity: usize,
    lru_order: VecDeque<K>,
}

struct ClfusEntry<K, V> {
    key: K,
    value: V,
    size: usize,
    hits: u32,
    #[allow(dead_code)]
    compressed: bool,
}

#[allow(dead_code)]
struct HistoryEntry {
    key_hash: u64,
    hits: u32,
    size: usize,
}

const FILTER_SIZE: usize = 4096;

/// Multiplicative decay applied to `average_value` each time the admission gate
/// rejects a new key. Mirrors the EMA smoothing factor (0.9) and guarantees the
/// rejection threshold relaxes toward 0 in bounded steps so a full cache cannot
/// freeze permanently.
const AVERAGE_DECAY: f64 = 0.9;

impl<K, V> ClfusCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    /// Build a CLFUS cache that can hold entries whose sizes sum to at most
    /// `capacity`. The ghost history is sized to `capacity / 2 + 1` and the
    /// seen-filter has 4096 fingerprint slots.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::new(),
            history: VecDeque::new(),
            seen_filter: vec![0u16; FILTER_SIZE],
            capacity,
            current_size: 0,
            average_value: 1.0,
            history_capacity: capacity / 2 + 1,
            lru_order: VecDeque::new(),
        }
    }

    /// Look up `key`, incrementing its hit counter and promoting it to the
    /// most-recently-used position. Returns `None` on a miss.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if let Some(entry) = self.data.get_mut(key) {
            entry.hits = entry.hits.saturating_add(1);
            // Move to back of LRU (most recently used)
            if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
                self.lru_order.remove(pos);
                self.lru_order.push_back(key.clone());
            }
            Some(&self.data.get(key).unwrap().value)
        } else {
            None
        }
    }

    /// Insert a value with size. Uses admission filter:
    /// 1. Check seen_filter — if not seen before, mark seen and skip
    /// 2. Compute value = hits / size for the incoming item
    /// 3. Only admit if value > average_value
    /// 4. On eviction, move evicted item's metadata to history ghost list
    pub fn insert(&mut self, key: K, value: V, size: usize) {
        if size == 0 || size > self.capacity {
            return;
        }

        // If already present, update in place (reject sizes that cannot fit).
        if self.data.contains_key(&key) {
            if size > self.capacity {
                return;
            }
            let entry = self.data.get_mut(&key).unwrap();
            self.current_size = self.current_size.saturating_sub(entry.size);
            entry.value = value;
            entry.size = size;
            self.current_size = self.current_size.saturating_add(size);

            // BUG FIX: the in-place update path used to return here without any
            // make-room logic, so growing one or more existing entries let
            // `current_size` exceed `capacity` (unbounded memory growth past the
            // configured cap — N entries could each grow toward `capacity`).
            // Now run the same eviction the new-key path uses to restore the
            // size invariant. Detach the just-updated key from the LRU order so
            // it is never chosen as its own eviction victim (eviction only ever
            // picks from `lru_order`), then re-attach it as most-recently-used.
            let detached = self
                .lru_order
                .iter()
                .position(|k| k == &key)
                .map(|pos| self.lru_order.remove(pos).is_some())
                .unwrap_or(false);
            while self.current_size > self.capacity && !self.lru_order.is_empty() {
                self.evict_one();
            }
            // Re-attach the updated key. Because `size <= capacity` is enforced
            // above, evicting every other entry always leaves room for it, so
            // the invariant `current_size <= capacity` holds afterwards.
            if detached {
                self.lru_order.push_back(key.clone());
            }
            return;
        }

        let key_hash = self.hash_key(&key);

        // Admission filter: skip one-hit-wonders
        if !self.check_seen(key_hash) {
            self.mark_seen(key_hash);
            return;
        }

        // For new items, assume 1 hit for admission scoring
        let incoming_score = Self::value_score(1, size);

        // Only apply admission gating once we have eviction history.
        // Before that, the running average is not yet meaningful.
        if self.current_size >= self.capacity
            && !self.history.is_empty()
            && incoming_score < self.average_value
        {
            // BUG FIX: this gate used to `return` outright. Because the running
            // average could ONLY decrease via `update_average` (reachable only
            // from `evict_one`, which is reachable only AFTER passing this gate),
            // a full cache that began rejecting stayed frozen forever — the
            // threshold was pinned and every subsequent new key was rejected,
            // collapsing the hit rate to near-zero. Decay the average on each
            // rejected admission attempt so the threshold relaxes over time and
            // a stalled cache always recovers in a bounded number of attempts.
            // (A plain EMA toward `incoming_score` is avoided here: with f64 it
            // can stick exactly one ULP above the target and never cross the
            // strict `<`, so the freeze would not be guaranteed to lift.)
            self.average_value *= AVERAGE_DECAY;
            return;
        }

        // Evict until we have space
        while self.current_size + size > self.capacity && !self.lru_order.is_empty() {
            self.evict_one();
        }

        if self.current_size + size > self.capacity {
            return;
        }

        self.lru_order.push_back(key.clone());
        self.data.insert(
            key.clone(),
            ClfusEntry {
                key,
                value,
                size,
                hits: 1,
                compressed: false,
            },
        );
        self.current_size += size;
    }

    /// Remove `key` from the cache, returning its value if present.
    /// The freed size is subtracted from `current_size` immediately.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(entry) = self.data.remove(key) {
            self.current_size -= entry.size;
            if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
                self.lru_order.remove(pos);
            }
            Some(entry.value)
        } else {
            None
        }
    }

    /// Check the ghost history for a previous eviction of the key identified
    /// by `key_hash`. Useful for external second-chance or promotion logic.
    pub fn was_recently_evicted(&self, key_hash: u64) -> bool {
        self.history.iter().any(|h| h.key_hash == key_hash)
    }

    /// Total size (sum of entry sizes) currently stored in the cache.
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Maximum total size the cache can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of distinct entries currently in the cache.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn value_score(hits: u32, size: usize) -> f64 {
        if size == 0 {
            return 0.0;
        }
        hits as f64 / size as f64
    }

    fn update_average(&mut self, evicted_hits: u32, evicted_size: usize) {
        let evicted_score = Self::value_score(evicted_hits, evicted_size);
        // Exponential moving average with alpha=0.1
        self.average_value = self.average_value * 0.9 + evicted_score * 0.1;
    }

    fn check_seen(&self, key_hash: u64) -> bool {
        let idx = (key_hash as usize) % FILTER_SIZE;
        let fingerprint = ((key_hash >> 16) as u16) | 1;
        self.seen_filter[idx] == fingerprint
    }

    fn mark_seen(&mut self, key_hash: u64) {
        let idx = (key_hash as usize) % FILTER_SIZE;
        let fingerprint = ((key_hash >> 16) as u16) | 1;
        self.seen_filter[idx] = fingerprint;
    }

    fn hash_key(&self, key: &K) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn evict_one(&mut self) {
        // Evict from front of LRU (least recently used) with lowest value score
        if let Some(victim_key) = self.find_eviction_victim() {
            if let Some(entry) = self.data.remove(&victim_key) {
                self.current_size -= entry.size;
                if let Some(pos) = self.lru_order.iter().position(|k| k == &victim_key) {
                    self.lru_order.remove(pos);
                }
                self.update_average(entry.hits, entry.size);

                // Add to ghost history
                let key_hash = self.hash_key(&entry.key);
                self.history.push_back(HistoryEntry {
                    key_hash,
                    hits: entry.hits,
                    size: entry.size,
                });
                while self.history.len() > self.history_capacity {
                    self.history.pop_front();
                }
            }
        }
    }

    fn find_eviction_victim(&self) -> Option<K> {
        // Scan the first quarter of LRU for the lowest value-score item
        let scan_limit = (self.lru_order.len() / 4).max(1).min(self.lru_order.len());
        let mut worst_key: Option<K> = None;
        let mut worst_score = f64::MAX;

        for key in self.lru_order.iter().take(scan_limit) {
            if let Some(entry) = self.data.get(key) {
                let score = Self::value_score(entry.hits, entry.size);
                if score < worst_score {
                    worst_score = score;
                    worst_key = Some(key.clone());
                }
            }
        }
        worst_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_basic_insert_get() {
        let mut cache = ClfusCache::new(1000);
        // First insert is blocked by seen filter; mark seen first
        cache.insert("a".to_string(), 1, 100);
        // Second insert passes the filter
        cache.insert("a".to_string(), 1, 100);
        assert_eq!(cache.get(&"a".to_string()), Some(&1));
    }

    #[test]
    fn test_seen_filter_blocks_first_access() {
        let mut cache: ClfusCache<String, i32> = ClfusCache::new(1000);
        cache.insert("new_key".to_string(), 42, 100);
        // First insertion is blocked by the admission filter
        assert_eq!(cache.get(&"new_key".to_string()), None);
        // Second insertion passes
        cache.insert("new_key".to_string(), 42, 100);
        assert_eq!(cache.get(&"new_key".to_string()), Some(&42));
    }

    #[test]
    fn test_eviction_to_ghost_history() {
        let mut cache = ClfusCache::new(200);
        // Insert items (need to see them first)
        for i in 0..5 {
            let key = format!("k{}", i);
            cache.insert(key.clone(), i, 100);
            cache.insert(key, i, 100);
        }
        // Cache can hold 2 items (200 / 100 = 2)
        // Some items should have been evicted to history
        assert!(cache.len() <= 2);
        assert!(!cache.history.is_empty());
    }

    #[test]
    fn test_was_recently_evicted() {
        let mut cache = ClfusCache::new(100);
        // Insert and evict
        let key = "victim".to_string();
        cache.insert(key.clone(), 1, 50);
        cache.insert(key.clone(), 1, 50);

        let key2 = "replacer".to_string();
        cache.insert(key2.clone(), 2, 60);
        cache.insert(key2.clone(), 2, 60);

        // The first key should have been evicted
        if cache.get(&key).is_none() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            let hash = hasher.finish();
            assert!(cache.was_recently_evicted(hash));
        }
    }

    #[test]
    fn test_remove() {
        let mut cache = ClfusCache::new(1000);
        cache.insert("a".to_string(), 1, 100);
        cache.insert("a".to_string(), 1, 100);
        assert_eq!(cache.remove(&"a".to_string()), Some(1));
        assert_eq!(cache.get(&"a".to_string()), None);
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_zero_size_rejected() {
        let mut cache = ClfusCache::new(1000);
        cache.insert("a".to_string(), 1, 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_oversize_rejected() {
        let mut cache = ClfusCache::new(100);
        cache.insert("a".to_string(), 1, 200);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_update_existing_key() {
        let mut cache = ClfusCache::new(1000);
        cache.insert("a".to_string(), 1, 100);
        cache.insert("a".to_string(), 1, 100);
        assert_eq!(cache.get(&"a".to_string()), Some(&1));
        // Update in place (key already exists)
        cache.insert("a".to_string(), 99, 200);
        assert_eq!(cache.get(&"a".to_string()), Some(&99));
        assert_eq!(cache.size(), 200);
    }

    #[test]
    fn test_capacity_reporting() {
        let cache: ClfusCache<String, i32> = ClfusCache::new(512);
        assert_eq!(cache.capacity(), 512);
        assert_eq!(cache.size(), 0);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_hit_count_increments() {
        let mut cache = ClfusCache::new(1000);
        cache.insert("a".to_string(), 1, 100);
        cache.insert("a".to_string(), 1, 100);
        // Multiple gets should increment hits
        for _ in 0..10 {
            cache.get(&"a".to_string());
        }
        // Entry still accessible
        assert_eq!(cache.get(&"a".to_string()), Some(&1));
    }

    #[test]
    fn test_lru_ordering() {
        let mut cache = ClfusCache::new(500);
        // Insert multiple items
        for i in 0..3 {
            let key = format!("k{}", i);
            cache.insert(key.clone(), i, 100);
            cache.insert(key, i, 100);
        }
        // Access first item to make it recently used
        cache.get(&"k0".to_string());
        // Insert more to cause eviction
        let key = "new".to_string();
        cache.insert(key.clone(), 99, 100);
        cache.insert(key, 99, 100);
        // k0 should still be present (recently used)
        assert_eq!(cache.get(&"k0".to_string()), Some(&0));
    }

    /// Regression for the "admission filter permanently freezes the cache after
    /// it fills" bug. Once the cache filled and the gate started rejecting,
    /// `average_value` could only ever be lowered by an eviction that the gate
    /// itself prevented, so every subsequent new key was rejected forever
    /// (admissions collapsed to ~1). With the fix the threshold decays on each
    /// rejected attempt, so a steady stream of brand-new keys keeps being
    /// admitted. Fails on the frozen code (admitted == 1), passes with the fix.
    #[test]
    fn test_admission_filter_recovers_after_cache_fills() {
        let mut cache: ClfusCache<u64, u64> = ClfusCache::new(1000);

        // Fill exactly to capacity with ten low-value (score = 1/100) items.
        for i in 0..10u64 {
            cache.insert(i, i, 100); // first insert only marks the seen filter
            cache.insert(i, i, 100); // second insert is admitted
        }
        assert_eq!(cache.size(), 1000);
        assert_eq!(cache.len(), 10);

        // Stream a long run of brand-new keys of the same size/score. On the
        // buggy (frozen) cache only the very first eviction-triggering insert is
        // admitted; the rest are rejected forever. With the fix the running
        // average relaxes over rejected attempts and admissions resume.
        let mut admitted = 0usize;
        for i in 100..1100u64 {
            cache.insert(i, i, 100);
            cache.insert(i, i, 100);
            if cache.get(&i).is_some() {
                admitted += 1;
            }
        }

        assert!(
            admitted > 50,
            "admission filter froze: only {} of 1000 new keys were admitted",
            admitted
        );
        // The cache must still respect its capacity throughout.
        assert!(cache.size() <= cache.capacity());
    }

    /// Regression for the "in-place update bypasses eviction and lets
    /// current_size exceed capacity" bug. Growing existing entries used to skip
    /// all make-room logic, so the summed size could blow past `capacity`. With
    /// the fix, growing entries triggers eviction of *other* entries (never the
    /// just-updated one) and the size invariant is preserved.
    #[test]
    fn test_in_place_update_growth_respects_capacity() {
        let mut cache: ClfusCache<u64, u64> = ClfusCache::new(1000);

        // Admit two entries that comfortably fit (200 of 1000 used).
        cache.insert(1, 1, 100);
        cache.insert(1, 1, 100);
        cache.insert(2, 2, 100);
        cache.insert(2, 2, 100);
        assert_eq!(cache.size(), 200);
        assert_eq!(cache.len(), 2);

        // Grow both existing keys far past what fits together (900 + 900).
        cache.insert(1, 1, 900);
        cache.insert(2, 2, 900);

        // Without the fix this left current_size == 1800 (> capacity 1000).
        assert!(
            cache.size() <= cache.capacity(),
            "in-place update overflowed capacity: size {} > capacity {}",
            cache.size(),
            cache.capacity()
        );
        // The most-recently-updated key (2) must still fit and be resident.
        assert_eq!(cache.get(&2), Some(&2));
    }

    proptest! {
        #[test]
        fn prop_size_never_exceeds_capacity(
            capacity in 100usize..1000,
            ref keys in proptest::collection::vec(0u32..50, 1..100),
            item_size in 1usize..100,
        ) {
            let item_size = item_size.min(capacity);
            let mut cache = ClfusCache::new(capacity);
            for &key in keys {
                cache.insert(key, key as i32, item_size);
                cache.insert(key, key as i32, item_size);
                prop_assert!(cache.size() <= capacity,
                    "size {} > capacity {}", cache.size(), capacity);
            }
        }

        #[test]
        fn prop_get_after_admitted_insert(
            key in 0u32..1000,
            value in 0i32..1_000_000,
        ) {
            let mut cache = ClfusCache::new(10_000);
            cache.insert(key, value, 100);
            cache.insert(key, value, 100);
            let got = cache.get(&key).copied();
            prop_assert_eq!(got, Some(value));
        }
    }
}
