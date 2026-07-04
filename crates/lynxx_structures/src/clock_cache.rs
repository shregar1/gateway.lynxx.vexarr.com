use std::collections::HashMap;

/// Fixed-capacity cache using the CLOCK (second-chance) eviction algorithm.
///
/// Entries live in a fixed-size slot array. A rotating *hand* pointer sweeps
/// the array when an eviction is needed: if the entry under the hand has its
/// *referenced* bit set, the bit is cleared and the hand advances (giving it a
/// second chance); if the bit is already clear, the entry is evicted. Lookups
/// set the referenced bit, so frequently accessed entries survive longer.
///
/// CLOCK approximates LRU with O(1) amortised eviction cost and no per-access
/// list manipulation.
pub struct ClockCache<K: Clone + Eq + std::hash::Hash, V: Clone> {
    entries: Vec<Option<ClockEntry<K, V>>>,
    map: HashMap<K, usize>,
    hand: usize,
    capacity: usize,
    len: usize,
}

struct ClockEntry<K, V> {
    key: K,
    value: V,
    referenced: bool,
}

impl<K, V> ClockCache<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    /// Allocate a clock cache that holds exactly `capacity` entries.
    ///
    /// # Panics
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "ClockCache capacity must be > 0");
        Self {
            entries: (0..capacity).map(|_| None).collect(),
            map: HashMap::with_capacity(capacity),
            hand: 0,
            capacity,
            len: 0,
        }
    }

    /// Get a value. Sets the referenced bit so the entry gets a second chance.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let &idx = self.map.get(key)?;
        if let Some(ref mut entry) = self.entries[idx] {
            entry.referenced = true;
            Some(&entry.value)
        } else {
            None
        }
    }

    /// Insert a value. If the key already exists, update it in place.
    /// If full, use the clock algorithm to find an eviction victim:
    /// scan from hand — if referenced bit is set, clear it and advance;
    /// if not referenced, evict that slot.
    /// Returns the evicted (key, value) pair if an eviction occurred.
    pub fn insert(&mut self, key: K, value: V) -> Option<(K, V)> {
        if let Some(&idx) = self.map.get(&key) {
            if let Some(ref mut entry) = self.entries[idx] {
                entry.value = value;
                entry.referenced = true;
            }
            return None;
        }

        if self.len < self.capacity {
            let slot = self.find_empty_slot();
            self.entries[slot] = Some(ClockEntry {
                key: key.clone(),
                value,
                referenced: false,
            });
            self.map.insert(key, slot);
            self.len += 1;
            return None;
        }

        let evicted = self.evict_one();
        self.entries[self.hand] = Some(ClockEntry {
            key: key.clone(),
            value,
            referenced: false,
        });
        self.map.insert(key, self.hand);
        self.advance_hand();
        evicted
    }

    /// Remove a key from the cache.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.map.remove(key)?;
        let entry = self.entries[idx].take()?;
        self.len -= 1;
        Some(entry.value)
    }

    /// Returns `true` if `key` is present. Does **not** set the referenced bit.
    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of entries the cache can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn find_empty_slot(&self) -> usize {
        for (i, slot) in self.entries.iter().enumerate() {
            if slot.is_none() {
                return i;
            }
        }
        unreachable!("find_empty_slot called when cache is full");
    }

    /// Clock sweep: advance the hand, clearing referenced bits until we find
    /// an unreferenced entry to evict.
    fn evict_one(&mut self) -> Option<(K, V)> {
        loop {
            if let Some(ref mut entry) = self.entries[self.hand] {
                if entry.referenced {
                    entry.referenced = false;
                    self.advance_hand();
                } else {
                    let entry = self.entries[self.hand].take().unwrap();
                    self.map.remove(&entry.key);
                    // len stays the same because caller will immediately fill this slot
                    return Some((entry.key, entry.value));
                }
            } else {
                self.advance_hand();
            }
        }
    }

    fn advance_hand(&mut self) {
        self.hand = (self.hand + 1) % self.capacity;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_new_cache() {
        let cache: ClockCache<String, i32> = ClockCache::new(16);
        assert_eq!(cache.capacity(), 16);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn test_zero_capacity_panics() {
        let _: ClockCache<String, i32> = ClockCache::new(0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache = ClockCache::new(4);
        assert!(cache.insert("a".to_string(), 1).is_none());
        assert_eq!(cache.get(&"a".to_string()), Some(&1));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_get_missing_key() {
        let mut cache: ClockCache<String, i32> = ClockCache::new(4);
        assert_eq!(cache.get(&"missing".to_string()), None);
    }

    #[test]
    fn test_update_existing_key() {
        let mut cache = ClockCache::new(4);
        cache.insert("a".to_string(), 1);
        cache.insert("a".to_string(), 42);
        assert_eq!(cache.get(&"a".to_string()), Some(&42));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_contains() {
        let mut cache = ClockCache::new(4);
        assert!(!cache.contains(&"a".to_string()));
        cache.insert("a".to_string(), 1);
        assert!(cache.contains(&"a".to_string()));
    }

    #[test]
    fn test_remove() {
        let mut cache = ClockCache::new(4);
        cache.insert("a".to_string(), 1);
        assert_eq!(cache.remove(&"a".to_string()), Some(1));
        assert!(!cache.contains(&"a".to_string()));
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_remove_missing_key() {
        let mut cache: ClockCache<String, i32> = ClockCache::new(4);
        assert_eq!(cache.remove(&"nope".to_string()), None);
    }

    #[test]
    fn test_eviction_returns_victim() {
        let mut cache = ClockCache::new(2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        // Cache is full, inserting "c" must evict something
        let evicted = cache.insert("c".to_string(), 3);
        assert!(evicted.is_some());
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&"c".to_string()));
    }

    #[test]
    fn test_second_chance_spares_referenced() {
        let mut cache = ClockCache::new(2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        // Access "a" to set its referenced bit
        cache.get(&"a".to_string());
        // Now insert "c" — "a" should get a second chance, "b" should be evicted
        let evicted = cache.insert("c".to_string(), 3);
        assert_eq!(evicted, Some(("b".to_string(), 2)));
        assert!(cache.contains(&"a".to_string()));
        assert!(cache.contains(&"c".to_string()));
    }

    #[test]
    fn test_eviction_all_referenced_clears_and_evicts() {
        let mut cache = ClockCache::new(2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.get(&"a".to_string());
        cache.get(&"b".to_string());
        // Both referenced — clock should clear both and evict the first one it re-visits
        let evicted = cache.insert("c".to_string(), 3);
        assert!(evicted.is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_fill_and_evict_cycle() {
        let mut cache = ClockCache::new(3);
        for i in 0..10 {
            cache.insert(i, i * 10);
        }
        assert_eq!(cache.len(), 3);
        // The last 3 inserted should have displaced earlier ones
        // (exact victims depend on hand position & referenced bits)
        let mut found = 0;
        for i in 0..10 {
            if cache.contains(&i) {
                found += 1;
            }
        }
        assert_eq!(found, 3);
    }

    #[test]
    fn test_insert_after_remove_reuses_slot() {
        let mut cache = ClockCache::new(3);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.insert("c".to_string(), 3);
        cache.remove(&"b".to_string());
        assert_eq!(cache.len(), 2);
        // Insert new item — should go into the freed slot without eviction
        let evicted = cache.insert("d".to_string(), 4);
        assert!(evicted.is_none());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_integer_keys() {
        let mut cache = ClockCache::new(8);
        for i in 0u64..8 {
            cache.insert(i, i * 100);
        }
        assert_eq!(cache.len(), 8);
        assert_eq!(cache.get(&3), Some(&300));
    }

    #[test]
    fn test_get_sets_referenced_bit() {
        let mut cache = ClockCache::new(3);
        cache.insert(1, 10);
        cache.insert(2, 20);
        cache.insert(3, 30);
        // Access key 1 to protect it
        cache.get(&1);
        // Force two evictions — key 1 should survive the first round
        cache.insert(4, 40);
        assert!(cache.contains(&1), "recently accessed key should survive eviction");
    }

    #[test]
    fn test_large_cache() {
        let mut cache = ClockCache::new(1024);
        for i in 0..2048u32 {
            cache.insert(i, i);
        }
        assert_eq!(cache.len(), 1024);
        // Most recent inserts should be present
        assert!(cache.contains(&2047));
    }

    #[test]
    fn test_clone_values() {
        let mut cache = ClockCache::new(4);
        cache.insert("key".to_string(), vec![1, 2, 3]);
        let val = cache.get(&"key".to_string()).cloned();
        assert_eq!(val, Some(vec![1, 2, 3]));
    }

    proptest! {
        #[test]
        fn prop_len_never_exceeds_capacity(
            capacity in 1usize..64,
            ref keys in proptest::collection::vec(0u32..500, 1..200),
        ) {
            let mut cache = ClockCache::new(capacity);
            for (i, &k) in keys.iter().enumerate() {
                cache.insert(k, i);
                prop_assert!(cache.len() <= capacity,
                    "len {} > capacity {}", cache.len(), capacity);
            }
        }

        #[test]
        fn prop_get_after_insert(
            capacity in 1usize..64,
            key in 0u32..1000,
            value in 0i64..1_000_000,
        ) {
            let mut cache = ClockCache::new(capacity);
            cache.insert(key, value);
            let got = cache.get(&key).copied();
            prop_assert_eq!(got, Some(value));
        }
    }
}
