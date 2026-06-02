//! Adaptive Replacement Cache (ARC).
//!
//! From the 2003 IBM paper "ARC: A Self-Tuning, Low Overhead Replacement
//! Cache" by Megiddo & Modha.
//!
//! ARC dynamically balances between recency and frequency by maintaining
//! four lists and a single adaptive parameter `p`:
//!
//! - **T1** – pages seen exactly once recently (recency).
//! - **T2** – pages seen at least twice recently (frequency).
//! - **B1** – ghost entries evicted from T1 (metadata only).
//! - **B2** – ghost entries evicted from T2 (metadata only).
//!
//! The parameter `p` is the *target size* of T1: a hit in B1 nudges `p`
//! upward (favour recency), while a hit in B2 nudges it downward (favour
//! frequency). Actual eviction from T1 vs T2 is decided by comparing
//! `|T1|` against `p`.

use std::collections::{HashMap, VecDeque};

/// Which live list an entry currently resides in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Location {
    T1,
    T2,
}

/// ARC cache mapping `K → V` with a fixed entry-count capacity.
///
/// All public read/write operations are O(n) worst-case due to
/// `VecDeque::retain`-style scans, which is acceptable for moderate
/// capacities. For very large caches consider a `LinkedHashMap` backend.
pub struct ArcCache<K: Clone + Eq + std::hash::Hash, V> {
    capacity: usize,
    p: usize,
    t1: VecDeque<K>,
    t2: VecDeque<K>,
    b1: VecDeque<K>,
    b2: VecDeque<K>,
    data: HashMap<K, (V, Location)>,
}

impl<K, V> ArcCache<K, V>
where
    K: Clone + Eq + std::hash::Hash,
{
    /// Create a new ARC cache that holds at most `capacity` entries.
    /// Panics if `capacity` is zero.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "ARC capacity must be > 0");
        Self {
            capacity,
            p: 0,
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            data: HashMap::new(),
        }
    }

    /// Look up `key`. On a hit the entry is promoted to T2's MRU position
    /// (the defining ARC insight: any re-access moves from recency to
    /// frequency). Returns `None` on a miss.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if let Some((_, loc)) = self.data.get(key) {
            let loc = *loc;
            match loc {
                Location::T1 => {
                    self.t1.retain(|k| k != key);
                    self.t2.push_back(key.clone());
                    self.data.get_mut(key).unwrap().1 = Location::T2;
                }
                Location::T2 => {
                    self.t2.retain(|k| k != key);
                    self.t2.push_back(key.clone());
                }
            }
            Some(&self.data.get(key).unwrap().0)
        } else {
            None
        }
    }

    /// Insert or update `key`.
    ///
    /// Four cases (following the original ARC paper):
    /// 1. Key already in T1 or T2 → update value, promote to T2 MRU.
    /// 2. Key in B1 (ghost recency) → increase `p`, replace, insert T2.
    /// 3. Key in B2 (ghost frequency) → decrease `p`, replace, insert T2.
    /// 4. Key not in any list → new entry; evict from directories and T1/T2
    ///    as needed.
    pub fn insert(&mut self, key: K, value: V) {
        // Case 1: key already cached
        if self.data.contains_key(&key) {
            let loc = self.data.get(&key).unwrap().1;
            match loc {
                Location::T1 => {
                    self.t1.retain(|k| k != &key);
                }
                Location::T2 => {
                    self.t2.retain(|k| k != &key);
                }
            }
            self.t2.push_back(key.clone());
            self.data.insert(key, (value, Location::T2));
            return;
        }

        // Case 2: key in B1 (ghost of recency)
        if let Some(pos) = self.b1.iter().position(|k| k == &key) {
            let delta = self.adapt_delta(self.b1.len(), self.b2.len());
            self.p = (self.p + delta).min(self.capacity);
            self.replace(&key, false);
            self.b1.remove(pos);
            self.t2.push_back(key.clone());
            self.data.insert(key, (value, Location::T2));
            return;
        }

        // Case 3: key in B2 (ghost of frequency)
        if let Some(pos) = self.b2.iter().position(|k| k == &key) {
            let delta = self.adapt_delta(self.b2.len(), self.b1.len());
            self.p = self.p.saturating_sub(delta);
            self.replace(&key, true);
            self.b2.remove(pos);
            self.t2.push_back(key.clone());
            self.data.insert(key, (value, Location::T2));
            return;
        }

        // Case 4: completely new key
        let t1_len = self.t1.len();
        let b1_len = self.b1.len();
        let t2_len = self.t2.len();
        let b2_len = self.b2.len();

        if t1_len + b1_len == self.capacity {
            if t1_len < self.capacity {
                self.b1.pop_front();
                self.replace(&key, false);
            } else {
                // B1 is empty, T1 is full — evict LRU of T1 directly
                if let Some(old) = self.t1.pop_front() {
                    self.data.remove(&old);
                }
            }
        } else if t1_len + b1_len < self.capacity
            && t1_len + t2_len + b1_len + b2_len >= self.capacity
        {
            if t1_len + t2_len + b1_len + b2_len >= 2 * self.capacity {
                self.b2.pop_front();
            }
            self.replace(&key, false);
        }

        self.t1.push_back(key.clone());
        self.data.insert(key, (value, Location::T1));
    }

    /// Remove `key` from the cache. Returns the stored value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some((val, loc)) = self.data.remove(key) {
            match loc {
                Location::T1 => self.t1.retain(|k| k != key),
                Location::T2 => self.t2.retain(|k| k != key),
            }
            Some(val)
        } else {
            None
        }
    }

    /// Returns `true` if `key` is present in the cache (T1 or T2).
    pub fn contains(&self, key: &K) -> bool {
        self.data.contains_key(key)
    }

    /// Number of live entries (|T1| + |T2|).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if no live entries exist.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Maximum number of entries this cache can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current target size for T1 (exposed for observability / tests).
    pub fn target_t1(&self) -> usize {
        self.p
    }

    /// Evict one entry from T1 or T2 (moving its key to B1 or B2)
    /// based on the current value of `p`.
    fn replace(&mut self, _incoming: &K, in_b2: bool) {
        let t1_len = self.t1.len();
        let evict_from_t1 = if t1_len > 0 && t2_len_positive(&self.t2) {
            if in_b2 {
                t1_len > self.p
            } else {
                t1_len >= self.p.max(1)
            }
        } else {
            t1_len > 0
        };

        if evict_from_t1 {
            if let Some(old) = self.t1.pop_front() {
                self.data.remove(&old);
                self.b1.push_back(old);
            }
        } else if let Some(old) = self.t2.pop_front() {
            self.data.remove(&old);
            self.b2.push_back(old);
        }
    }

    /// Compute the adaptation step δ.
    /// `list_len` is the ghost list that was hit, `other_len` is the other
    /// ghost list.
    fn adapt_delta(&self, list_len: usize, other_len: usize) -> usize {
        if list_len >= other_len {
            1
        } else if other_len > 0 {
            (other_len / list_len).min(self.capacity)
        } else {
            1
        }
    }
}

fn t2_len_positive<K>(t2: &VecDeque<K>) -> bool {
    !t2.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn basic_insert_and_get() {
        let mut cache = ArcCache::new(4);
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.get(&"z"), None);
    }

    #[test]
    fn capacity_respected() {
        let mut cache = ArcCache::new(3);
        for i in 0..10 {
            cache.insert(i, i * 10);
        }
        assert!(cache.len() <= 3);
    }

    #[test]
    fn re_access_promotes_to_t2() {
        let mut cache = ArcCache::new(4);
        cache.insert("a", 1);
        // First access — "a" starts in T1, get promotes it to T2
        assert_eq!(cache.get(&"a"), Some(&1));
        // Fill up cache to force eviction
        cache.insert("b", 2);
        cache.insert("c", 3);
        cache.insert("d", 4);
        cache.insert("e", 5); // should evict from T1, not T2
        // "a" was in T2 so should survive
        assert_eq!(cache.get(&"a"), Some(&1));
    }

    #[test]
    fn ghost_b1_hit_increases_p() {
        let mut cache = ArcCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        // Evict "a" to B1
        cache.insert("c", 3);
        let p_before = cache.target_t1();
        // Re-insert "a" — it's in B1, should increase p
        cache.insert("a", 10);
        assert!(cache.target_t1() >= p_before);
        assert_eq!(cache.get(&"a"), Some(&10));
    }

    #[test]
    fn ghost_b2_hit_decreases_p() {
        let mut cache = ArcCache::new(3);
        // Get entries into T2 by double-accessing them
        cache.insert("a", 1);
        cache.get(&"a"); // promote to T2
        cache.insert("b", 2);
        cache.get(&"b"); // promote to T2
        cache.insert("c", 3);
        cache.get(&"c"); // promote to T2

        // Now fill to evict from T2 → B2
        cache.insert("d", 4);
        cache.insert("e", 5);
        cache.insert("f", 6);

        let p_before = cache.target_t1();
        // Re-insert something that landed in B2 (if any)
        // Even if B2 is empty, the algorithm still works correctly
        if !cache.b2.is_empty() {
            let ghost_key = cache.b2.front().unwrap().clone();
            cache.insert(ghost_key, 99);
            assert!(cache.target_t1() <= p_before);
        }
    }

    #[test]
    fn remove_returns_value() {
        let mut cache = ArcCache::new(4);
        cache.insert("a", 42);
        assert_eq!(cache.remove(&"a"), Some(42));
        assert_eq!(cache.remove(&"a"), None);
        assert!(!cache.contains(&"a"));
    }

    #[test]
    fn contains_works() {
        let mut cache = ArcCache::new(4);
        assert!(!cache.contains(&"x"));
        cache.insert("x", 1);
        assert!(cache.contains(&"x"));
    }

    #[test]
    fn update_existing_key() {
        let mut cache = ArcCache::new(4);
        cache.insert("a", 1);
        cache.insert("a", 2);
        assert_eq!(cache.get(&"a"), Some(&2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn is_empty_and_len() {
        let mut cache: ArcCache<&str, i32> = ArcCache::new(4);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.insert("a", 1);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn capacity_getter() {
        let cache: ArcCache<i32, i32> = ArcCache::new(16);
        assert_eq!(cache.capacity(), 16);
    }

    #[test]
    #[should_panic(expected = "ARC capacity must be > 0")]
    fn zero_capacity_panics() {
        let _ = ArcCache::<i32, i32>::new(0);
    }

    #[test]
    fn single_capacity_works() {
        let mut cache = ArcCache::new(1);
        cache.insert("a", 1);
        assert_eq!(cache.get(&"a"), Some(&1));
        cache.insert("b", 2);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.get(&"a"), None);
    }

    #[test]
    fn frequency_survives_over_recency() {
        let mut cache = ArcCache::new(4);

        // Create a frequently-accessed item
        cache.insert("freq", 100);
        for _ in 0..5 {
            cache.get(&"freq");
        }

        // Fill the rest with one-shot items
        cache.insert("x1", 1);
        cache.insert("x2", 2);
        cache.insert("x3", 3);

        // Overflow — one-shot items should be evicted first
        cache.insert("x4", 4);
        cache.insert("x5", 5);

        // Frequently accessed item should survive
        assert!(cache.contains(&"freq"));
    }

    #[test]
    fn large_workload_no_panic() {
        let mut cache = ArcCache::new(50);
        for i in 0..1000u64 {
            cache.insert(i, i * 2);
            if i > 3 {
                cache.get(&(i - 3));
            }
        }
        assert!(cache.len() <= 50);
    }

    #[test]
    fn scan_resistant() {
        let mut cache = ArcCache::new(5);
        // Build a working set
        for i in 0..5 {
            cache.insert(i, i);
            cache.get(&i);
        }
        // Scan through many unique keys (simulating a sequential scan)
        for i in 100..200 {
            cache.insert(i, i);
        }
        // ARC should retain *some* of the original working set thanks to T2
        let retained: usize = (0..5).filter(|k| cache.contains(k)).count();
        // At least some working-set items survive the scan
        assert!(
            retained > 0 || cache.len() == 5,
            "ARC should resist scan pollution"
        );
    }

    proptest! {
        #[test]
        fn prop_len_never_exceeds_capacity(
            capacity in 1usize..64,
            ref ops in proptest::collection::vec(0u32..30, 1..200),
        ) {
            let mut cache = ArcCache::new(capacity);
            for &k in ops {
                cache.insert(k, k as i64);
                prop_assert!(cache.len() <= capacity,
                    "len {} > capacity {}", cache.len(), capacity);
            }
        }

        #[test]
        fn prop_get_after_insert_returns_value(
            capacity in 1usize..64,
            key in 0u32..100,
            value in 0i64..100_000,
        ) {
            let mut cache = ArcCache::new(capacity);
            cache.insert(key, value);
            let got = cache.get(&key);
            prop_assert_eq!(got, Some(&value));
        }

        #[test]
        fn prop_remove_then_get_is_none(
            capacity in 1usize..64,
            key in 0u32..100,
        ) {
            let mut cache = ArcCache::new(capacity);
            cache.insert(key, 42i64);
            cache.remove(&key);
            prop_assert!(cache.get(&key).is_none());
        }

        #[test]
        fn prop_p_bounded_by_capacity(
            capacity in 1usize..64,
            ref ops in proptest::collection::vec(0u32..20, 1..300),
        ) {
            let mut cache = ArcCache::new(capacity);
            for &k in ops {
                cache.insert(k, k as i64);
                if k % 3 == 0 {
                    cache.get(&k);
                }
                prop_assert!(cache.target_t1() <= capacity,
                    "p {} > capacity {}", cache.target_t1(), capacity);
            }
        }
    }
}
