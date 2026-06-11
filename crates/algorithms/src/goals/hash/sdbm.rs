//! SDBM — shift-add hash function from the SDBM database library.
//!
//! Classic formula: `hash = hash * 65599 + byte`, which the compiler
//! can lower to `(hash << 6) + (hash << 16) - hash + byte`.
//! Simple, fast, good distribution for short string keys.

/// Compute the SDBM hash of `data`.
///
/// Returns a 32-bit hash using the traditional SDBM recurrence.
#[inline]
pub fn sdbm_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &b in data {
        // hash = hash * 65599 + byte
        // Equivalent to: (hash << 6) + (hash << 16) - hash + byte
        hash = (b as u32)
            .wrapping_add(hash << 6)
            .wrapping_add(hash << 16)
            .wrapping_sub(hash);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = sdbm_hash(b"hello world");
        let b = sdbm_hash(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_input() {
        assert_eq!(sdbm_hash(b""), 0);
    }

    #[test]
    fn single_byte() {
        // hash = 0 * 65599 + byte = byte
        assert_eq!(sdbm_hash(b"A"), b'A' as u32);
    }

    #[test]
    fn different_inputs_differ() {
        let a = sdbm_hash(b"abc");
        let b = sdbm_hash(b"abd");
        assert_ne!(a, b);
    }

    #[test]
    fn matches_multiply_form() {
        // Verify the shift form equals the multiply form.
        let data = b"The quick brown fox";
        let mut h_mul: u32 = 0;
        for &b in data.iter() {
            h_mul = h_mul.wrapping_mul(65599).wrapping_add(b as u32);
        }
        assert_eq!(sdbm_hash(data), h_mul);
    }

    #[test]
    fn non_zero_output() {
        let h = sdbm_hash(b"test key");
        assert_ne!(h, 0);
    }

    #[test]
    fn large_input() {
        let data: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let h = sdbm_hash(&data);
        assert_ne!(h, 0);
    }
}
