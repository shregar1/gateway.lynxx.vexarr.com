//! SipHash — keyed DoS-resistant hash function.
//!
//! Implements SipHash-2-4 (standard, default) and SipHash-1-3 (fast variant).
//! The 128-bit key ensures unpredictable output for hash-table collision
//! resistance even when the attacker controls input keys.

/// Incremental SipHash hasher supporting configurable round counts.
pub struct SipHasher {
    #[allow(dead_code)]
    k0: u64,
    #[allow(dead_code)]
    k1: u64,
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: [u8; 8],
    buf_len: usize,
    total_len: usize,
    c_rounds: usize,
    d_rounds: usize,
}

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[inline(always)]
fn u8_to_u64_le(buf: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*buf)
}

impl SipHasher {
    /// Create a SipHash-2-4 hasher with a 128-bit key split into two `u64`s.
    pub fn new(key0: u64, key1: u64) -> Self {
        Self::with_rounds(key0, key1, 2, 4)
    }

    /// Create a SipHash hasher with custom round counts.
    ///
    /// Standard SipHash-2-4 uses `c_rounds = 2, d_rounds = 4`.
    /// Fast variant SipHash-1-3 uses `c_rounds = 1, d_rounds = 3`.
    pub fn with_rounds(key0: u64, key1: u64, c_rounds: usize, d_rounds: usize) -> Self {
        Self {
            k0: key0,
            k1: key1,
            v0: key0 ^ 0x736f6d6570736575,
            v1: key1 ^ 0x646f72616e646f6d,
            v2: key0 ^ 0x6c7967656e657261,
            v3: key1 ^ 0x7465646279746573,
            buf: [0u8; 8],
            buf_len: 0,
            total_len: 0,
            c_rounds,
            d_rounds,
        }
    }

    /// Feed data into the hasher.
    pub fn write(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len());
        let mut offset = 0;

        if self.buf_len > 0 {
            let need = 8 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()]
                    .copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..8].copy_from_slice(&data[..need]);
            let m = u8_to_u64_le(&self.buf);
            self.compress(m);
            self.buf_len = 0;
            offset = need;
        }

        while offset + 8 <= data.len() {
            let mut block = [0u8; 8];
            block.copy_from_slice(&data[offset..offset + 8]);
            let m = u8_to_u64_le(&block);
            self.compress(m);
            offset += 8;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    #[inline]
    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..self.c_rounds {
            sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^= m;
    }

    /// Finalize and return the 64-bit hash value.
    ///
    /// Does not consume `self` — the hasher state is cloned internally so
    /// `finish` can be called repeatedly (though the result is always the same).
    pub fn finish(&self) -> u64 {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;

        let mut last = (self.total_len as u64 & 0xff) << 56;
        let buf = &self.buf[..self.buf_len];

        // Pack remaining bytes in little-endian order below the length byte
        if buf.len() >= 7 { last |= (buf[6] as u64) << 48; }
        if buf.len() >= 6 { last |= (buf[5] as u64) << 40; }
        if buf.len() >= 5 { last |= (buf[4] as u64) << 32; }
        if buf.len() >= 4 { last |= (buf[3] as u64) << 24; }
        if buf.len() >= 3 { last |= (buf[2] as u64) << 16; }
        if buf.len() >= 2 { last |= (buf[1] as u64) << 8; }
        if !buf.is_empty()  { last |= buf[0] as u64; }

        v3 ^= last;
        for _ in 0..self.c_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= last;

        v2 ^= 0xff;
        for _ in 0..self.d_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }

        v0 ^ v1 ^ v2 ^ v3
    }

    /// One-shot SipHash-2-4.
    pub fn hash(key0: u64, key1: u64, data: &[u8]) -> u64 {
        let mut h = Self::new(key0, key1);
        h.write(data);
        h.finish()
    }

    /// One-shot SipHash-1-3 (fast variant).
    pub fn hash_fast(key0: u64, key1: u64, data: &[u8]) -> u64 {
        let mut h = Self::with_rounds(key0, key1, 1, 3);
        h.write(data);
        h.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official SipHash-2-4 test vectors from the reference paper (Appendix A).
    // Key = 00 01 02 ... 0f, input = 00 01 02 ... (length varies).
    const VECTORS: [u64; 16] = [
        0x726fdb47dd0e0e31,
        0x74f839c593dc67fd,
        0x0d6c8009d9a94f5a,
        0x85676696d7fb7e2d,
        0xcf2794e0277187b7,
        0x18765564cd99a68d,
        0xcbc9466e58fee3ce,
        0xab0200f58b01d137,
        0x93f5f5799a932462,
        0x9e0082df0ba9e4b0,
        0x7a5dbbc594ddb9f3,
        0xf4b32f46226bada7,
        0x751e8fbc860ee5fb,
        0x14ea5627c0843d90,
        0xf723ca908e7af2ee,
        0xa129ca6149be45e5,
    ];

    fn test_key() -> (u64, u64) {
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        (k0, k1)
    }

    #[test]
    fn reference_vectors() {
        let (k0, k1) = test_key();
        for (i, &expected) in VECTORS.iter().enumerate() {
            let input: Vec<u8> = (0..i as u8).collect();
            let got = SipHasher::hash(k0, k1, &input);
            assert_eq!(got, expected, "vector {i}: expected {expected:#018x}, got {got:#018x}");
        }
    }

    #[test]
    fn empty_input() {
        let (k0, k1) = test_key();
        assert_eq!(SipHasher::hash(k0, k1, b""), VECTORS[0]);
    }

    #[test]
    fn deterministic() {
        let a = SipHasher::hash(42, 99, b"hello world");
        let b = SipHasher::hash(42, 99, b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_differ() {
        let a = SipHasher::hash(0, 0, b"test");
        let b = SipHasher::hash(1, 0, b"test");
        assert_ne!(a, b);
    }

    #[test]
    fn different_inputs_differ() {
        let a = SipHasher::hash(0, 0, b"abc");
        let b = SipHasher::hash(0, 0, b"abd");
        assert_ne!(a, b);
    }

    #[test]
    fn incremental_equals_oneshot() {
        let (k0, k1) = test_key();
        let data = b"The quick brown fox jumps over the lazy dog";

        let oneshot = SipHasher::hash(k0, k1, data);

        let mut h = SipHasher::new(k0, k1);
        h.write(&data[..10]);
        h.write(&data[10..20]);
        h.write(&data[20..]);
        assert_eq!(h.finish(), oneshot);
    }

    #[test]
    fn incremental_byte_at_a_time() {
        let (k0, k1) = test_key();
        let data = b"0123456789abcdef";

        let oneshot = SipHasher::hash(k0, k1, data);

        let mut h = SipHasher::new(k0, k1);
        for &b in data.iter() {
            h.write(&[b]);
        }
        assert_eq!(h.finish(), oneshot);
    }

    #[test]
    fn fast_variant_differs_from_standard() {
        let a = SipHasher::hash(1, 2, b"test");
        let b = SipHasher::hash_fast(1, 2, b"test");
        assert_ne!(a, b, "SipHash-2-4 and SipHash-1-3 should differ");
    }

    #[test]
    fn finish_is_idempotent() {
        let mut h = SipHasher::new(0, 0);
        h.write(b"hello");
        let a = h.finish();
        let b = h.finish();
        assert_eq!(a, b);
    }

    #[test]
    fn with_rounds_custom() {
        let mut h = SipHasher::with_rounds(0, 0, 4, 8);
        h.write(b"custom rounds");
        let result = h.finish();
        assert_ne!(result, 0);
        assert_ne!(result, SipHasher::hash(0, 0, b"custom rounds"));
    }

    #[test]
    fn large_input() {
        let data: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
        let h = SipHasher::hash(0xdead, 0xbeef, &data);
        assert_ne!(h, 0);
    }
}
