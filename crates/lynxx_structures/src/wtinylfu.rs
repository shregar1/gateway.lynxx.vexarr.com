//! W-TinyLFU cache: Window LRU + Segmented LRU with frequency-sketch admission.
//!
//! From Einziger, Friedman & Manes (2015): "TinyLFU: A Highly Efficient
//! Cache Admission Policy." Combines a small window LRU (1% of capacity)
//! with a main Segmented LRU (99%), using a 4-bit Count-Min Sketch for
//! frequency estimation. Incoming items are admitted to the main cache
//! only if their estimated frequency exceeds that of the main-cache
//! eviction victim.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

// ── Segment tag ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Segment {
    Window,
    Probation,
    Protected,
}

// ── Frequency sketch (4-bit Count-Min Sketch) ─────────────────────

/// 4-bit Count-Min Sketch packed into `u64` words (16 counters each).
struct FrequencySketch {
    table: Vec<u64>,
    mask: u64,
    seeds: [u64; 4],
}

impl FrequencySketch {
    fn new(capacity: usize) -> Self {
        let table_len = capacity.next_power_of_two().max(16) / 16;
        let table_len = table_len.max(1);
        Self {
            table: vec![0u64; table_len],
            mask: (table_len as u64).wrapping_sub(1),
            seeds: [
                0x9e3779b97f4a7c15,
                0xbf58476d1ce4e5b9,
                0x94d049bb133111eb,
                0x6c62272e07bb0142,
            ],
        }
    }

    fn index(&self, hash: u64, seed_idx: usize) -> (usize, u32) {
        let h = hash.wrapping_mul(self.seeds[seed_idx]);
        let h = h ^ (h >> 17);
        let word = (h & self.mask) as usize;
        let nibble = ((h >> 32) & 0xF) as u32;
        (word, nibble * 4)
    }

    fn increment(&mut self, hash: u64) {
        for i in 0..4 {
            let (word, shift) = self.index(hash, i);
            let counter = (self.table[word] >> shift) & 0xF;
            if counter < 15 {
                self.table[word] += 1u64 << shift;
            }
        }
    }

    fn frequency(&self, hash: u64) -> u8 {
        let mut min = 15u8;
        for i in 0..4 {
            let (word, shift) = self.index(hash, i);
            let counter = ((self.table[word] >> shift) & 0xF) as u8;
            if counter < min {
                min = counter;
            }
        }
        min
    }

    /// Halve all counters (aging / reset). Implemented by right-shifting
    /// each nibble independently using a mask to prevent bit bleed.
    fn reset(&mut self) {
        const ONES: u64 = 0x1111_1111_1111_1111;
        for word in &mut self.table {
            *word = (*word >> 1) & !ONES | (*word & ONES) >> 1;
        }
    }
}

// ── W-TinyLFU ──────────────────────────────────────────────────────

/// A W-TinyLFU cache with window LRU (1%) and main Segmented LRU (99%).
pub struct WTinyLfu<K: Clone + Eq + Hash, V> {
    capacity: usize,
    window: VecDeque<K>,
    window_cap: usize,
    probation: VecDeque<K>,
    probation_cap: usize,
    protected: VecDeque<K>,
    protected_cap: usize,
    data: HashMap<K, (V, Segment)>,
    sketch: FrequencySketch,
    sketch_reset_threshold: usize,
    sketch_count: usize,
}

fn key_hash<K: Hash>(key: &K) -> u64 {
    use std::hash::Hasher;
    let mut h = FnvHasher(0xcbf29ce484222325);
    key.hash(&mut h);
    h.finish()
}

struct FnvHasher(u64);

impl std::hash::Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

impl<K, V> WTinyLfu<K, V>
where
    K: Clone + Eq + Hash,
{
    /// Create a new W-TinyLFU cache with the given total capacity.
    ///
    /// The window region is ~1% of capacity (minimum 1), and the main
    /// region is split 20/80 between probation and protected.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let window_cap = (capacity / 100).max(1);
        let main_cap = capacity - window_cap;
        let probation_cap = (main_cap * 20 / 100).max(if main_cap > 0 { 1 } else { 0 });
        let protected_cap = main_cap - probation_cap;

        Self {
            capacity,
            window: VecDeque::new(),
            window_cap,
            probation: VecDeque::new(),
            probation_cap,
            protected: VecDeque::new(),
            protected_cap,
            data: HashMap::new(),
            sketch: FrequencySketch::new(capacity),
            sketch_reset_threshold: capacity * 10,
            sketch_count: 0,
        }
    }

    /// Look up a key, promoting it within the SLRU and incrementing its
    /// frequency in the sketch. Returns `None` on a miss.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.record_access(key);

        let seg = self.data.get(key)?.1;
        if seg == Segment::Probation {
            self.promote_to_protected(key);
        }

        self.data.get(key).map(|(v, _)| v)
    }

    /// Insert or update a key-value pair.
    ///
    /// New entries always enter the window. When the window is full, its
    /// LRU victim is compared against the main-cache eviction candidate
    /// using the frequency sketch: the one with lower frequency is discarded.
    pub fn insert(&mut self, key: K, value: V) {
        self.record_access(&key);

        if self.data.contains_key(&key) {
            let (v, seg) = self.data.get_mut(&key).unwrap();
            *v = value;
            if *seg == Segment::Probation {
                self.promote_to_protected(&key);
            }
            return;
        }

        // Insert into window
        self.window.push_back(key.clone());
        self.data.insert(key.clone(), (value, Segment::Window));

        if self.window.len() > self.window_cap {
            self.evict_from_window();
        }
    }

    /// Remove a key from the cache. Returns the value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some((v, seg)) = self.data.remove(key) {
            match seg {
                Segment::Window => {
                    if let Some(pos) = self.window.iter().position(|k| k == key) {
                        self.window.remove(pos);
                    }
                }
                Segment::Probation => {
                    if let Some(pos) = self.probation.iter().position(|k| k == key) {
                        self.probation.remove(pos);
                    }
                }
                Segment::Protected => {
                    if let Some(pos) = self.protected.iter().position(|k| k == key) {
                        self.protected.remove(pos);
                    }
                }
            }
            Some(v)
        } else {
            None
        }
    }

    /// Whether the key is present.
    pub fn contains(&self, key: &K) -> bool {
        self.data.contains_key(key)
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Total capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    // ── private ────────────────────────────────────────────────────

    fn record_access(&mut self, key: &K) {
        let hash = key_hash(key);
        self.sketch.increment(hash);
        self.sketch_count += 1;
        if self.sketch_count >= self.sketch_reset_threshold {
            self.sketch.reset();
            self.sketch_count /= 2;
        }
    }

    fn frequency_of(&self, key: &K) -> u8 {
        self.sketch.frequency(key_hash(key))
    }

    fn promote_to_protected(&mut self, key: &K) {
        if let Some(pos) = self.probation.iter().position(|k| k == key) {
            self.probation.remove(pos);
        }

        self.protected.push_back(key.clone());
        if let Some(entry) = self.data.get_mut(key) {
            entry.1 = Segment::Protected;
        }

        // If protected overflows, demote its LRU to probation
        while self.protected.len() > self.protected_cap && self.protected_cap > 0 {
            if let Some(demoted) = self.protected.pop_front() {
                self.probation.push_back(demoted.clone());
                if let Some(entry) = self.data.get_mut(&demoted) {
                    entry.1 = Segment::Probation;
                }
            }
        }
    }

    fn evict_from_window(&mut self) {
        let victim_key = match self.window.pop_front() {
            Some(k) => k,
            None => return,
        };

        // Remove from window segment tracking
        if let Some(entry) = self.data.get_mut(&victim_key) {
            entry.1 = Segment::Probation;
        }

        let main_victim = self.main_eviction_candidate();

        let main_cap = self.probation_cap + self.protected_cap;
        if main_cap == 0 {
            self.data.remove(&victim_key);
            return;
        }

        let main_len = self.probation.len() + self.protected.len();
        if main_len >= main_cap {
            if let Some(ref main_key) = main_victim {
                let window_freq = self.frequency_of(&victim_key);
                let main_freq = self.frequency_of(main_key);

                if window_freq > main_freq {
                    let evicted = main_key.clone();
                    self.remove_from_segment(&evicted);
                    self.data.remove(&evicted);
                    self.probation.push_back(victim_key);
                } else {
                    self.data.remove(&victim_key);
                }
            } else {
                self.data.remove(&victim_key);
            }
        } else {
            self.probation.push_back(victim_key);
        }
    }

    fn main_eviction_candidate(&self) -> Option<K> {
        self.probation.front().cloned()
    }

    fn remove_from_segment(&mut self, key: &K) {
        if let Some(pos) = self.probation.iter().position(|k| k == key) {
            self.probation.remove(pos);
        } else if let Some(pos) = self.protected.iter().position(|k| k == key) {
            self.protected.remove(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cache_is_empty() {
        let cache: WTinyLfu<u32, &str> = WTinyLfu::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.capacity(), 100);
    }

    #[test]
    fn insert_and_get() {
        let mut cache = WTinyLfu::new(100);
        cache.insert(1, "one");
        cache.insert(2, "two");
        assert_eq!(cache.get(&1), Some(&"one"));
        assert_eq!(cache.get(&2), Some(&"two"));
        assert_eq!(cache.get(&3), None);
    }

    #[test]
    fn contains_and_len() {
        let mut cache = WTinyLfu::new(100);
        cache.insert(42, "answer");
        assert!(cache.contains(&42));
        assert!(!cache.contains(&43));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn update_existing_key() {
        let mut cache = WTinyLfu::new(100);
        cache.insert(1, "old");
        cache.insert(1, "new");
        assert_eq!(cache.get(&1), Some(&"new"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn remove_key() {
        let mut cache = WTinyLfu::new(100);
        cache.insert(1, "one");
        assert_eq!(cache.remove(&1), Some("one"));
        assert!(!cache.contains(&1));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let mut cache: WTinyLfu<u32, u32> = WTinyLfu::new(100);
        assert_eq!(cache.remove(&999), None);
    }

    #[test]
    fn capacity_respected() {
        let cap = 50;
        let mut cache = WTinyLfu::new(cap);
        for i in 0..(cap * 3) as u32 {
            cache.insert(i, i);
        }
        assert!(
            cache.len() <= cap,
            "cache size {} exceeds capacity {}",
            cache.len(),
            cap
        );
    }

    #[test]
    fn frequency_sketch_basics() {
        let mut s = FrequencySketch::new(256);
        let hash = 0xDEADBEEF;
        assert_eq!(s.frequency(hash), 0);
        s.increment(hash);
        assert!(s.frequency(hash) >= 1);
        for _ in 0..20 {
            s.increment(hash);
        }
        assert!(s.frequency(hash) <= 15);
    }

    #[test]
    fn frequency_sketch_reset_halves() {
        let mut s = FrequencySketch::new(256);
        let hash = 0xCAFE;
        for _ in 0..14 {
            s.increment(hash);
        }
        let before = s.frequency(hash);
        assert!(before > 5);
        s.reset();
        let after = s.frequency(hash);
        assert!(
            after <= (before + 1) / 2 + 1,
            "after reset: before={before}, after={after}"
        );
    }

    #[test]
    fn frequency_sketch_different_keys() {
        let mut s = FrequencySketch::new(1024);
        for _ in 0..10 {
            s.increment(111);
        }
        s.increment(222);
        assert!(s.frequency(111) > s.frequency(222));
    }

    #[test]
    fn frequent_items_survive_eviction() {
        let mut cache = WTinyLfu::new(20);

        // Build frequency for keys 0..10
        for _ in 0..20 {
            for k in 0..10u32 {
                cache.insert(k, k);
                cache.get(&k);
            }
        }

        // Insert cold keys to trigger eviction
        for k in 100..130u32 {
            cache.insert(k, k);
        }

        // Frequent keys should mostly survive
        let mut survivors = 0;
        for k in 0..10u32 {
            if cache.contains(&k) {
                survivors += 1;
            }
        }
        assert!(
            survivors >= 5,
            "only {survivors}/10 frequent keys survived"
        );
    }

    #[test]
    fn minimum_capacity() {
        let mut cache = WTinyLfu::new(1);
        cache.insert(1, "a");
        assert_eq!(cache.len(), 1);
        cache.insert(2, "b");
        assert!(cache.len() <= 1);
    }

    #[test]
    fn small_capacity() {
        let mut cache = WTinyLfu::new(3);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");
        assert!(cache.len() <= 3);
        cache.insert(4, "d");
        assert!(cache.len() <= 3);
    }

    #[test]
    fn get_miss_returns_none() {
        let mut cache: WTinyLfu<&str, u32> = WTinyLfu::new(10);
        assert_eq!(cache.get(&"missing"), None);
    }

    #[test]
    fn string_keys() {
        let mut cache = WTinyLfu::new(50);
        cache.insert("hello".to_string(), 1);
        cache.insert("world".to_string(), 2);
        assert_eq!(cache.get(&"hello".to_string()), Some(&1));
        assert_eq!(cache.get(&"world".to_string()), Some(&2));
    }

    #[test]
    fn insert_many_unique_keys() {
        let mut cache = WTinyLfu::new(100);
        for i in 0..1000u32 {
            cache.insert(i, i * 10);
        }
        assert!(cache.len() <= 100);
        // At least some recent keys should be present
        let mut found = 0;
        for i in 900..1000u32 {
            if cache.contains(&i) {
                found += 1;
            }
        }
        assert!(found > 0, "should have some recent keys");
    }

    #[test]
    fn probation_to_protected_promotion() {
        let mut cache = WTinyLfu::new(200);

        // Insert enough to push items from window into probation
        for i in 0..200u32 {
            cache.insert(i, i);
        }

        // Access key 0 multiple times to promote from probation to protected
        for _ in 0..5 {
            cache.get(&0);
        }

        assert!(cache.contains(&0), "promoted key should survive");
    }
}
