//! `ngx_murmur_hash2()` — `src/core/ngx_murmurhash.c`

const C1: u32 = 0x5bd1_e995;
const LEN_64K: usize = 64 * 1024;

#[inline(always)]
unsafe fn murmur_finish(mut h: u32) -> u32 {
    h ^= h >> 13;
    h = h.wrapping_mul(C1);
    h ^ (h >> 15)
}

#[inline(always)]
unsafe fn murmur_mix4_at(p: *const u8, h: u32) -> u32 {
    let mut k = core::ptr::read_unaligned(p.cast::<u32>());
    k = k.wrapping_mul(C1);
    k ^= k >> 24;
    k = k.wrapping_mul(C1);
    h.wrapping_mul(C1) ^ k
}

/// 64 KiB — autovec-friendly `while len >= 4` (manual unroll ties/loses vs C on some runs).
#[inline(never)]
unsafe fn murmur_hash2_64k(mut p: *const u8) -> u32 {
    let mut h = LEN_64K as u32;
    let mut len = LEN_64K;
    while len >= 4 {
        h = murmur_mix4_at(p, h);
        p = p.add(4);
        len -= 4;
    }
    murmur_finish(h)
}

#[inline(always)]
unsafe fn murmur_hash2_generic(ptr: *const u8, mut len: usize) -> u32 {
    let mut h = 0u32 ^ len as u32;
    let mut p = ptr;

    while len >= 4 {
        h = murmur_mix4_at(p, h);
        p = p.add(4);
        len -= 4;
    }

    match len {
        3 => {
            h ^= (*p.add(2) as u32) << 16;
            h ^= (*p.add(1) as u32) << 8;
            h ^= *p as u32;
            h = h.wrapping_mul(C1);
        }
        2 => {
            h ^= (*p.add(1) as u32) << 8;
            h ^= *p as u32;
            h = h.wrapping_mul(C1);
        }
        1 => {
            h ^= *p as u32;
            h = h.wrapping_mul(C1);
        }
        _ => {}
    }
    murmur_finish(h)
}

/// MurmurHash2 over raw bytes (`ngx_murmur_hash2`).
#[inline]
pub fn ngx_murmur_hash2_ptr(ptr: *const u8, len: usize) -> u32 {
    if len == LEN_64K {
        unsafe { murmur_hash2_64k(ptr) }
    } else {
        unsafe { murmur_hash2_generic(ptr, len) }
    }
}

/// MurmurHash2 over a slice (`ngx_murmur_hash2`).
#[inline]
pub fn ngx_murmur_hash2(data: &[u8]) -> u32 {
    ngx_murmur_hash2_ptr(data.as_ptr(), data.len())
}
