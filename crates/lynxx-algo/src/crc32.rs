//! `ngx_crc32_*` — `src/core/ngx_crc32.h`
//!
//! - **Long / short:** `crc32fast` when available (bit-identical to NGINX CRC).
//! - **Table:** `ngx_crc32_long_table` / `ngx_crc32_update` for incremental NGINX paths.

use crate::crc32_tables::TABLE256;

/// Bit-identical to NGINX `ngx_crc32_short` / `ngx_crc32_long` (IEEE polynomial).
#[inline]
pub fn ngx_crc32_short(p: &[u8]) -> u32 {
    crc32fast::hash(p)
}

/// Hardware-accelerated where available.
#[inline]
pub fn ngx_crc32_long(p: &[u8]) -> u32 {
    crc32fast::hash(p)
}

/// Incremental update (NGINX `ngx_crc32_update` semantics, table-driven).
#[inline]
pub fn ngx_crc32_update(mut crc: u32, p: &[u8]) -> u32 {
    for &b in p {
        crc = TABLE256[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[inline]
pub fn ngx_crc32_final(crc: u32) -> u32 {
    crc ^ 0xffff_ffff
}

#[inline]
pub fn ngx_crc32_init() -> u32 {
    0xffff_ffff
}

/// Table loop — C parity / `bench vs_nginx_c`.
#[inline]
pub fn ngx_crc32_long_table(p: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in p {
        crc = TABLE256[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// Nibble table path (NGINX tiny-buffer algorithm).
#[inline]
pub fn ngx_crc32_short_nibble(p: &[u8]) -> u32 {
    use crate::crc32_tables::TABLE16;
    let mut crc = 0xffff_ffffu32;
    for &c in p {
        crc = TABLE16[((crc ^ (c & 0xf) as u32) & 0xf) as usize] ^ (crc >> 4);
        crc = TABLE16[((crc ^ (c >> 4) as u32) & 0xf) as usize] ^ (crc >> 4);
    }
    crc ^ 0xffff_ffff
}
