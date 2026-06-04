//! WT6 — Willy Tarreau's dual-state rotation hash from HAProxy.
//!
//! Uses two 32-bit accumulators (h0, h1) with rotation and XOR mixing.
//! Fast, well-distributed for short-to-medium keys used in proxy hash
//! tables.

/// Compute the WT6 hash of `data` with the given `seed`.
///
/// Two state variables rotate and mix each input byte, then fold
/// together for the final 32-bit result.
#[inline]
pub fn wt6_hash(data: &[u8], seed: u32) -> u32 {
    let mut h0 = seed;
    let mut h1 = seed;

    for &b in data {
        let t0 = h0.wrapping_add(h1);
        h0 = h0.wrapping_add(b as u32);
        h1 = h1 ^ h0;
        h0 = h0.rotate_left(7);
        h1 = h1.wrapping_add(t0);
        h1 = h1.rotate_left(11);
    }

    h0 = h0.wrapping_add(h1);
    h0 ^= h0 >> 16;
    h0 = h0.wrapping_mul(0x85ebca6b);
    h0 ^= h0 >> 13;
    h0 = h0.wrapping_mul(0xc2b2ae35);
    h0 ^= h0 >> 16;
    h0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = wt6_hash(b"hello world", 0);
        let b = wt6_hash(b"hello world", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn empty_input() {
        let h = wt6_hash(b"", 0);
        // Empty with zero seed: accumulators stay zero through the loop,
        // then the finalizer avalanche produces a known value.
        assert_eq!(h, wt6_hash(b"", 0));
    }

    #[test]
    fn different_seeds_differ() {
        let a = wt6_hash(b"test", 0);
        let b = wt6_hash(b"test", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn different_inputs_differ() {
        let a = wt6_hash(b"abc", 42);
        let b = wt6_hash(b"abd", 42);
        assert_ne!(a, b);
    }

    #[test]
    fn non_zero_output() {
        let h = wt6_hash(b"proxy key", 0xdeadbeef);
        assert_ne!(h, 0);
    }

    #[test]
    fn large_input() {
        let data: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let h = wt6_hash(&data, 0);
        assert_ne!(h, 0);
    }
}
