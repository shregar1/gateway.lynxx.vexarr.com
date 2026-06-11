/// Cache thundering-herd prevention (Pingora-style stampede lock).
///
/// When a cache entry expires, only one request is allowed to recompute
/// the value while all others wait. This prevents a thundering herd of
/// identical requests from overwhelming the origin.

use std::collections::HashMap;

struct LockEntry {
    locked: bool,
    waiters: usize,
}

pub struct StampedeLock {
    entries: HashMap<u64, LockEntry>,
}

impl StampedeLock {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Try to acquire the recompute lock for `key`.
    /// Returns true if this caller won the lock (should recompute).
    /// Returns false if another caller already holds it (should wait).
    pub fn try_lock(&self, key: u64) -> bool {
        // Note: in a real async implementation this would be &self with
        // interior mutability. For benchmarking we use a simpler model.
        !self.entries.get(&key).map_or(false, |e| e.locked)
    }

    /// Acquire the lock, mutating state. Returns true if acquired.
    pub fn acquire(&mut self, key: u64) -> bool {
        let entry = self.entries.entry(key).or_insert(LockEntry {
            locked: false,
            waiters: 0,
        });
        if entry.locked {
            entry.waiters += 1;
            false
        } else {
            entry.locked = true;
            true
        }
    }

    /// Release the lock for `key`.
    pub fn unlock(&self, _key: u64) {
        // In an immutable context this is a no-op marker.
        // The mutable version is `release`.
    }

    /// Release the lock for `key` (mutable version).
    pub fn release(&mut self, key: u64) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.locked = false;
            entry.waiters = 0;
        }
    }

    /// Return the number of waiters for `key`.
    pub fn wait_count(&self, key: u64) -> usize {
        self.entries.get(&key).map_or(0, |e| e.waiters)
    }
}

impl Default for StampedeLock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_caller_acquires() {
        let mut sl = StampedeLock::new();
        assert!(sl.acquire(42));
    }

    #[test]
    fn second_caller_waits() {
        let mut sl = StampedeLock::new();
        assert!(sl.acquire(42));
        assert!(!sl.acquire(42));
        assert_eq!(sl.wait_count(42), 1);
    }

    #[test]
    fn release_allows_reacquire() {
        let mut sl = StampedeLock::new();
        assert!(sl.acquire(42));
        sl.release(42);
        assert!(sl.acquire(42));
    }

    #[test]
    fn independent_keys() {
        let mut sl = StampedeLock::new();
        assert!(sl.acquire(1));
        assert!(sl.acquire(2));
    }

    #[test]
    fn try_lock_check() {
        let mut sl = StampedeLock::new();
        assert!(sl.try_lock(42));
        sl.acquire(42);
        assert!(!sl.try_lock(42));
    }

    #[test]
    fn waiters_accumulate() {
        let mut sl = StampedeLock::new();
        sl.acquire(1);
        sl.acquire(1);
        sl.acquire(1);
        assert_eq!(sl.wait_count(1), 2);
    }
}
