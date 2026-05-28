//! CRC32c — Castagnoli CRC-32 with a compile-time lookup table.
//!
//! Uses the Castagnoli polynomial `0x1EDC6F41` (reflected: `0x82F63B78`).
//! Provides a one-shot `crc32c_hash` and an incremental `crc32c_update`
//! for streaming use cases.

/// Reflected Castagnoli polynomial.
const POLY: u32 = 0x82F63B78;

/// 256-entry lookup table, generated at compile time.
const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        t[i as usize] = crc;
        i += 1;
    }
    t
};

/// Update a running CRC32c value with additional data.
///
/// Start with `crc = 0` for a fresh computation, or pass the previous
/// return value for incremental hashing.
#[inline]
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = TABLE[((c as u8) ^ b) as usize] ^ (c >> 8);
    }
    !c
}

/// Compute the CRC32c hash of `data` from scratch.
#[inline]
pub fn crc32c_hash(data: &[u8]) -> u32 {
    crc32c_update(0, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = crc32c_hash(b"hello world");
        let b = crc32c_hash(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_input() {
        assert_eq!(crc32c_hash(b""), 0);
    }

    #[test]
    fn known_vector() {
        // CRC32c("123456789") = 0xE3069283
        assert_eq!(crc32c_hash(b"123456789"), 0xE3069283);
    }

    #[test]
    fn different_inputs_differ() {
        let a = crc32c_hash(b"abc");
        let b = crc32c_hash(b"abd");
        assert_ne!(a, b);
    }

    #[test]
    fn incremental_equals_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = crc32c_hash(data);

        let partial = crc32c_update(0, &data[..10]);
        let full = crc32c_update(partial, &data[10..]);
        assert_eq!(full, oneshot);
    }

    #[test]
    fn incremental_byte_at_a_time() {
        let data = b"0123456789abcdef";
        let oneshot = crc32c_hash(data);

        let mut crc = 0u32;
        for &b in data.iter() {
            crc = crc32c_update(crc, &[b]);
        }
        assert_eq!(crc, oneshot);
    }

    #[test]
    fn table_first_entry() {
        assert_eq!(TABLE[0], 0);
    }

    #[test]
    fn large_input() {
        let data: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let h = crc32c_hash(&data);
        assert_ne!(h, 0);
    }
}
