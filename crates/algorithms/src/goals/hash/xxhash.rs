//! XXHash — XXH32 and XXH64 non-cryptographic hash functions.
//!
//! State-of-the-art speed with excellent distribution.  Uses four
//! accumulator lanes with prime-constant mixing for bulk processing and
//! a single-lane tail pass for remaining bytes.

// ── XXH32 prime constants ──────────────────────────────────────────

const XXH32_PRIME1: u32 = 0x9E3779B1;
const XXH32_PRIME2: u32 = 0x85EBCA77;
const XXH32_PRIME3: u32 = 0xC2B2AE3D;
const XXH32_PRIME4: u32 = 0x27D4EB2F;
const XXH32_PRIME5: u32 = 0x165667B1;

// ── XXH64 prime constants ──────────────────────────────────────────

const XXH64_PRIME1: u64 = 0x9E3779B185EBCA87;
const XXH64_PRIME2: u64 = 0xC2B2AE3D27D4EB4F;
const XXH64_PRIME3: u64 = 0x165667B19E3779F9;
const XXH64_PRIME4: u64 = 0x85EBCA77C2B2AE63;
const XXH64_PRIME5: u64 = 0x27D4EB2F165667C5;

// ── XXH32 helpers ──────────────────────────────────────────────────

#[inline(always)]
fn xxh32_round(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(XXH32_PRIME2))
        .rotate_left(13)
        .wrapping_mul(XXH32_PRIME1)
}

#[inline(always)]
fn xxh32_avalanche(mut h: u32) -> u32 {
    h ^= h >> 15;
    h = h.wrapping_mul(XXH32_PRIME2);
    h ^= h >> 13;
    h = h.wrapping_mul(XXH32_PRIME3);
    h ^= h >> 16;
    h
}

#[inline(always)]
fn read_u32_le(buf: &[u8]) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[..4]);
    u32::from_le_bytes(b)
}

#[inline(always)]
fn read_u64_le(buf: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[..8]);
    u64::from_le_bytes(b)
}

/// Compute the XXH32 hash of `data` with the given `seed`.
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let len = data.len();
    let mut p = 0usize;
    let mut h: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(XXH32_PRIME1).wrapping_add(XXH32_PRIME2);
        let mut v2 = seed.wrapping_add(XXH32_PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(XXH32_PRIME1);

        let limit = len - 16;
        while p <= limit {
            v1 = xxh32_round(v1, read_u32_le(&data[p..]));
            v2 = xxh32_round(v2, read_u32_le(&data[p + 4..]));
            v3 = xxh32_round(v3, read_u32_le(&data[p + 8..]));
            v4 = xxh32_round(v4, read_u32_le(&data[p + 12..]));
            p += 16;
        }

        h = v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(XXH32_PRIME5);
    }

    h = h.wrapping_add(len as u32);

    // Remaining 4-byte chunks
    let limit = len.saturating_sub(3);
    while p < limit {
        h = h.wrapping_add(read_u32_le(&data[p..]).wrapping_mul(XXH32_PRIME3));
        h = h.rotate_left(17).wrapping_mul(XXH32_PRIME4);
        p += 4;
    }

    // Remaining bytes
    while p < len {
        h = h.wrapping_add((data[p] as u32).wrapping_mul(XXH32_PRIME5));
        h = h.rotate_left(11).wrapping_mul(XXH32_PRIME1);
        p += 1;
    }

    xxh32_avalanche(h)
}

// ── XXH64 helpers ──────────────────────────────────────────────────

#[inline(always)]
fn xxh64_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(XXH64_PRIME2))
        .rotate_left(31)
        .wrapping_mul(XXH64_PRIME1)
}

#[inline(always)]
fn xxh64_merge_round(acc: u64, val: u64) -> u64 {
    let val = xxh64_round(0, val);
    acc.wrapping_mul(XXH64_PRIME1).wrapping_add(XXH64_PRIME4) ^ val
}

#[inline(always)]
fn xxh64_avalanche(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(XXH64_PRIME2);
    h ^= h >> 29;
    h = h.wrapping_mul(XXH64_PRIME3);
    h ^= h >> 32;
    h
}

/// Compute the XXH64 hash of `data` with the given `seed`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut p = 0usize;
    let mut h: u64;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(XXH64_PRIME1).wrapping_add(XXH64_PRIME2);
        let mut v2 = seed.wrapping_add(XXH64_PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(XXH64_PRIME1);

        let limit = len - 32;
        while p <= limit {
            v1 = xxh64_round(v1, read_u64_le(&data[p..]));
            v2 = xxh64_round(v2, read_u64_le(&data[p + 8..]));
            v3 = xxh64_round(v3, read_u64_le(&data[p + 16..]));
            v4 = xxh64_round(v4, read_u64_le(&data[p + 24..]));
            p += 32;
        }

        h = v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        h = xxh64_merge_round(h, v1);
        h = xxh64_merge_round(h, v2);
        h = xxh64_merge_round(h, v3);
        h = xxh64_merge_round(h, v4);
    } else {
        h = seed.wrapping_add(XXH64_PRIME5);
    }

    h = h.wrapping_add(len as u64);

    // Remaining 8-byte chunks
    while p + 8 <= len {
        let k = xxh64_round(0, read_u64_le(&data[p..]));
        h ^= k;
        h = h.rotate_left(27).wrapping_mul(XXH64_PRIME1).wrapping_add(XXH64_PRIME4);
        p += 8;
    }

    // Remaining 4-byte chunk
    if p + 4 <= len {
        h ^= (read_u32_le(&data[p..]) as u64).wrapping_mul(XXH64_PRIME1);
        h = h.rotate_left(23).wrapping_mul(XXH64_PRIME2).wrapping_add(XXH64_PRIME3);
        p += 4;
    }

    // Remaining bytes
    while p < len {
        h ^= (data[p] as u64).wrapping_mul(XXH64_PRIME5);
        h = h.rotate_left(11).wrapping_mul(XXH64_PRIME1);
        p += 1;
    }

    xxh64_avalanche(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── XXH32 tests ────────────────────────────────────────────────

    #[test]
    fn xxh32_deterministic() {
        let a = xxh32(b"hello world", 0);
        let b = xxh32(b"hello world", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn xxh32_empty_seed0() {
        // XXH32("", 0) = 0x02CC5D05
        assert_eq!(xxh32(b"", 0), 0x02CC5D05);
    }

    #[test]
    fn xxh32_different_seeds_differ() {
        let a = xxh32(b"test", 0);
        let b = xxh32(b"test", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn xxh32_different_inputs_differ() {
        let a = xxh32(b"abc", 0);
        let b = xxh32(b"abd", 0);
        assert_ne!(a, b);
    }

    #[test]
    fn xxh32_short_input() {
        // XXH32 with input < 16 bytes takes the short path
        let h = xxh32(b"Hello", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn xxh32_medium_input() {
        // Exactly 16 bytes triggers the 4-lane path
        let h = xxh32(b"0123456789abcdef", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn xxh32_large_input() {
        let data: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let h = xxh32(&data, 0);
        assert_ne!(h, 0);
    }

    // ── XXH64 tests ────────────────────────────────────────────────

    #[test]
    fn xxh64_deterministic() {
        let a = xxh64(b"hello world", 0);
        let b = xxh64(b"hello world", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn xxh64_empty_seed0() {
        // XXH64("", 0) = 0xEF46DB3751D8E999
        assert_eq!(xxh64(b"", 0), 0xEF46DB3751D8E999);
    }

    #[test]
    fn xxh64_different_seeds_differ() {
        let a = xxh64(b"test", 0);
        let b = xxh64(b"test", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn xxh64_different_inputs_differ() {
        let a = xxh64(b"abc", 0);
        let b = xxh64(b"abd", 0);
        assert_ne!(a, b);
    }

    #[test]
    fn xxh64_short_input() {
        let h = xxh64(b"Hello", 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn xxh64_large_input() {
        let data: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let h = xxh64(&data, 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn xxh32_and_xxh64_differ() {
        let h32 = xxh32(b"test", 0) as u64;
        let h64 = xxh64(b"test", 0);
        assert_ne!(h32, h64);
    }
}
