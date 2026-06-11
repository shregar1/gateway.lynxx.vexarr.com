//! Maglev consistent hash table (Envoy / Google).
//!
//! Builds a lookup table of size 65537 (prime) using the permutation-based
//! algorithm from the Maglev paper. Every slot maps to exactly one backend.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Table size — smallest prime >= 65536.
const TABLE_SIZE: usize = 65537;

/// Maglev consistent hash lookup table.
pub struct MaglevTable {
    table: Vec<usize>,
    backend_count: usize,
}

impl MaglevTable {
    /// Build a new Maglev table for the given backend names.
    pub fn new(backends: &[&str]) -> Self {
        assert!(!backends.is_empty(), "backends must not be empty");
        let n = backends.len();

        // Compute offset and skip for each backend
        let mut offset = Vec::with_capacity(n);
        let mut skip = Vec::with_capacity(n);

        for &name in backends {
            let mut h1 = DefaultHasher::new();
            name.hash(&mut h1);
            let hash1 = h1.finish();

            let mut h2 = DefaultHasher::new();
            (name, 0xDEAD_BEEFu64).hash(&mut h2);
            let hash2 = h2.finish();

            offset.push((hash1 % TABLE_SIZE as u64) as usize);
            skip.push((hash2 % (TABLE_SIZE as u64 - 1) + 1) as usize);
        }

        // Populate the table
        let mut table = vec![usize::MAX; TABLE_SIZE];
        let mut next = vec![0usize; n];
        let mut filled = 0;

        while filled < TABLE_SIZE {
            for i in 0..n {
                let mut c = (offset[i] + next[i] * skip[i]) % TABLE_SIZE;
                while table[c] != usize::MAX {
                    next[i] += 1;
                    c = (offset[i] + next[i] * skip[i]) % TABLE_SIZE;
                }
                table[c] = i;
                next[i] += 1;
                filled += 1;
                if filled >= TABLE_SIZE {
                    break;
                }
            }
        }

        Self {
            table,
            backend_count: n,
        }
    }

    /// Look up which backend owns the given key.
    pub fn lookup(&self, key: u64) -> usize {
        let slot = (key % TABLE_SIZE as u64) as usize;
        self.table[slot]
    }

    /// Size of the lookup table.
    pub fn table_size(&self) -> usize {
        TABLE_SIZE
    }

    /// Number of backends.
    pub fn backend_count(&self) -> usize {
        self.backend_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let t = MaglevTable::new(&["a", "b", "c"]);
        assert_eq!(t.lookup(42), t.lookup(42));
    }

    #[test]
    fn all_slots_filled() {
        let t = MaglevTable::new(&["a", "b", "c"]);
        for slot in 0..TABLE_SIZE {
            assert!(t.table[slot] < 3);
        }
    }

    #[test]
    fn distributes_across_backends() {
        let t = MaglevTable::new(&["a", "b", "c"]);
        let mut counts = [0u32; 3];
        for key in 0..TABLE_SIZE as u64 {
            counts[t.lookup(key)] += 1;
        }
        // Each backend should get roughly TABLE_SIZE/3 ≈ 21845
        for &c in &counts {
            assert!(c > 15000, "each backend should get significant share");
        }
    }

    #[test]
    fn single_backend() {
        let t = MaglevTable::new(&["only"]);
        for key in 0..100 {
            assert_eq!(t.lookup(key), 0);
        }
    }
}
