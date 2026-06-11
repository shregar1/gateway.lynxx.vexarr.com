//! Checksummer adapters — wrap CRC32 variants into the `Checksummer` trait.

use crate::backbone::traits::Checksummer;

// ── core CRC32 variants ───────────────────────────────────────────

/// CRC32 short — nibble-at-a-time, no lookup table.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32Short;

impl Checksummer for Crc32Short {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        lynxx_algo::ngx_crc32_short(data)
    }
    fn name(&self) -> &'static str { "crc32_short" }
}

/// CRC32 short nibble — small lookup table.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32ShortNibble;

impl Checksummer for Crc32ShortNibble {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        lynxx_algo::ngx_crc32_short_nibble(data)
    }
    fn name(&self) -> &'static str { "crc32_short_nibble" }
}

/// CRC32 long — byte-at-a-time with 256-entry table.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32Long;

impl Checksummer for Crc32Long {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        lynxx_algo::ngx_crc32_long(data)
    }
    fn name(&self) -> &'static str { "crc32_long" }
}

/// CRC32 long table — multi-table for larger payloads.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32LongTable;

impl Checksummer for Crc32LongTable {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        lynxx_algo::ngx_crc32_long_table(data)
    }
    fn name(&self) -> &'static str { "crc32_long_table" }
}

// ── optimized CRC32 variants ───────────────────────────────────────

/// Slice-by-4 CRC32 — 4-way parallel table lookup.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32Slice4;

impl Checksummer for Crc32Slice4 {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        crate::goals::optimized::crc32::crc32_slice4(data)
    }
    fn name(&self) -> &'static str { "crc32_slice4" }
}

/// Slice-by-8 CRC32 — 8-way parallel table lookup, fastest.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32Slice8;

impl Checksummer for Crc32Slice8 {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        crate::goals::optimized::crc32::crc32_slice8(data)
    }
    fn name(&self) -> &'static str { "crc32_slice8" }
}

/// CRC32c (Castagnoli) used as a checksummer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Crc32cDirect;

impl Checksummer for Crc32cDirect {
    #[inline]
    fn checksum(&self, data: &[u8]) -> u32 {
        crate::goals::hash::crc32c_hash(data)
    }
    fn name(&self) -> &'static str { "crc32c" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::Checksummer;

    const DATA: &[u8] = b"checksum test payload";

    fn assert_checksummer_contract(c: &dyn Checksummer) {
        assert!(!c.name().is_empty());
        let s1 = c.checksum(DATA);
        let s2 = c.checksum(DATA);
        assert_eq!(s1, s2, "checksum must be deterministic");
        assert_ne!(c.checksum(DATA), c.checksum(b"other"), "different inputs should differ");
    }

    #[test] fn crc32_short()        { assert_checksummer_contract(&Crc32Short); }
    #[test] fn crc32_short_nibble() { assert_checksummer_contract(&Crc32ShortNibble); }
    #[test] fn crc32_long()         { assert_checksummer_contract(&Crc32Long); }
    #[test] fn crc32_long_table()   { assert_checksummer_contract(&Crc32LongTable); }
    #[test] fn crc32_slice4()       { assert_checksummer_contract(&Crc32Slice4); }
    #[test] fn crc32_slice8()       { assert_checksummer_contract(&Crc32Slice8); }
    #[test] fn crc32c_direct()      { assert_checksummer_contract(&Crc32cDirect); }

    #[test]
    fn empty_input() {
        // CRC32 of empty data is well-defined (should not panic).
        let _ = Crc32Short.checksum(b"");
        let _ = Crc32Slice8.checksum(b"");
    }
}
