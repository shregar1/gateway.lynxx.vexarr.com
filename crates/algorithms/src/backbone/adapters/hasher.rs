//! Hasher adapters — wrap hash functions into the `Hasher` trait.

use crate::backbone::traits::Hasher;

// ── core hashers ──────────────────────────────────────────────────

/// DJB hash — classic shift-add hash.
#[derive(Debug, Clone, Copy, Default)]
pub struct DjbHasher;

impl Hasher for DjbHasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        lynxx_algo::ngx_hash_key(data) as u64
    }
    fn name(&self) -> &'static str { "djb" }
}

/// DJB hash with lowercase folding.
#[derive(Debug, Clone, Copy, Default)]
pub struct DjbLcHasher;

impl Hasher for DjbLcHasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        lynxx_algo::ngx_hash_key_lc(data) as u64
    }
    fn name(&self) -> &'static str { "djb_lc" }
}

/// MurmurHash2 — fast non-cryptographic hash.
#[derive(Debug, Clone, Copy, Default)]
pub struct MurmurHasher;

impl Hasher for MurmurHasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        lynxx_algo::ngx_murmur_hash2(data) as u64
    }
    fn name(&self) -> &'static str { "murmur2" }
}

// ── custom hashers ─────────────────────────────────────────────────

/// SDBM hash — simple shift-add hash.
#[derive(Debug, Clone, Copy, Default)]
pub struct SdbmHasher;

impl Hasher for SdbmHasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::sdbm_hash(data) as u64
    }
    fn name(&self) -> &'static str { "sdbm" }
}

/// CRC32c used as a hash function.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32cHasher;

impl Hasher for Crc32cHasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::crc32c_hash(data) as u64
    }
    fn name(&self) -> &'static str { "crc32c" }
}

/// SipHash-2-4 — standard keyed hash.
pub struct SipHasher24 {
    pub key0: u64,
    pub key1: u64,
}

impl Default for SipHasher24 {
    fn default() -> Self { Self { key0: 0, key1: 0 } }
}

impl Hasher for SipHasher24 {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::SipHasher::hash(self.key0, self.key1, data)
    }
    fn name(&self) -> &'static str { "siphash24" }
}

/// SipHash-1-3 — fast keyed hash variant.
pub struct SipHasher13Adapter {
    pub key0: u64,
    pub key1: u64,
}

impl Default for SipHasher13Adapter {
    fn default() -> Self { Self { key0: 0, key1: 0 } }
}

impl Hasher for SipHasher13Adapter {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::SipHasher::hash_fast(self.key0, self.key1, data)
    }
    fn name(&self) -> &'static str { "siphash13" }
}

/// WT6 hash from HAProxy.
pub struct Wt6Hasher {
    pub seed: u32,
}

impl Default for Wt6Hasher {
    fn default() -> Self { Self { seed: 0 } }
}

impl Hasher for Wt6Hasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::wt6_hash(data, self.seed) as u64
    }
    fn name(&self) -> &'static str { "wt6" }
}

/// XXH32 hash.
pub struct Xxh32Hasher {
    pub seed: u32,
}

impl Default for Xxh32Hasher {
    fn default() -> Self { Self { seed: 0 } }
}

impl Hasher for Xxh32Hasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::xxh32(data, self.seed) as u64
    }
    fn name(&self) -> &'static str { "xxh32" }
}

/// XXH64 hash — fastest for large inputs.
pub struct Xxh64Hasher {
    pub seed: u64,
}

impl Default for Xxh64Hasher {
    fn default() -> Self { Self { seed: 0 } }
}

impl Hasher for Xxh64Hasher {
    #[inline]
    fn hash(&self, data: &[u8]) -> u64 {
        crate::goals::hash::xxh64(data, self.seed)
    }
    fn name(&self) -> &'static str { "xxh64" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::Hasher;

    const DATA: &[u8] = b"hello backbone";

    fn assert_hasher_contract(h: &dyn Hasher) {
        assert!(!h.name().is_empty(), "name must be non-empty");
        let d1 = h.hash(DATA);
        let d2 = h.hash(DATA);
        assert_eq!(d1, d2, "hash must be deterministic");
        assert_ne!(h.hash(DATA), h.hash(b"different"), "different inputs should differ");
    }

    #[test] fn djb()       { assert_hasher_contract(&DjbHasher); }
    #[test] fn djb_lc()    { assert_hasher_contract(&DjbLcHasher); }
    #[test] fn murmur()    { assert_hasher_contract(&MurmurHasher); }
    #[test] fn sdbm()      { assert_hasher_contract(&SdbmHasher); }
    #[test] fn crc32c()    { assert_hasher_contract(&Crc32cHasher); }
    #[test] fn siphash24() { assert_hasher_contract(&SipHasher24::default()); }
    #[test] fn siphash13() { assert_hasher_contract(&SipHasher13Adapter::default()); }
    #[test] fn wt6()       { assert_hasher_contract(&Wt6Hasher::default()); }
    #[test] fn xxh32()     { assert_hasher_contract(&Xxh32Hasher::default()); }
    #[test] fn xxh64()     { assert_hasher_contract(&Xxh64Hasher::default()); }

    #[test]
    fn empty_input_does_not_panic() {
        // All hashers must handle empty input without panicking.
        let hashers: Vec<Box<dyn Hasher>> = vec![
            Box::new(DjbHasher),
            Box::new(MurmurHasher),
            Box::new(SdbmHasher),
            Box::new(Crc32cHasher),
            Box::new(SipHasher24::default()),
            Box::new(SipHasher13Adapter::default()),
            Box::new(Wt6Hasher::default()),
            Box::new(Xxh32Hasher::default()),
            Box::new(Xxh64Hasher::default()),
        ];
        for h in &hashers {
            let _ = h.hash(b"");
        }
    }
}
