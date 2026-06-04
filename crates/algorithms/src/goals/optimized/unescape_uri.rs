//! Optimized URI unescape — SIMD-style bulk scanning for '%' with memcpy between.
//!
//! The original scans byte-by-byte with a 3-state machine. This version:
//! 1. Scans for '%' using chunk-at-a-time XOR technique (processes 8 bytes at a time)
//! 2. Bulk-copies literal runs using ptr::copy_nonoverlapping
//! 3. Decodes hex pairs with a single 256-entry lookup table (no branching)
//!
//! Expected speedup: 2-4x on typical URLs (mostly ASCII, few percent-encoded chars)

/// Optimized percent-decode. Returns bytes written to `dst`.
///
/// If `uri` is true, stops at decoded or literal '?' (NGINX `NGX_UNESCAPE_URI` semantics).
#[inline(always)]
pub fn unescape_uri_fast(dst: &mut [u8], src: &[u8], uri: bool) -> usize {
    let src_len = src.len();
    if src_len == 0 {
        return 0;
    }

    let mut s = 0usize;
    let mut d = 0usize;

    unsafe {
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr();

        loop {
            // Phase 1: Scan for '%' or '?' using word-at-a-time technique
            let scan_start = s;

            // Fast path: scan 8 bytes at a time looking for '%' (0x25) or '?' (0x3f)
            if !uri {
                while s + 8 <= src_len {
                    let p = src_ptr.add(s) as *const u64;
                    let word = p.read_unaligned();
                    // Check if any byte is '%' (0x25)
                    if has_byte(word, 0x25) {
                        break;
                    }
                    s += 8;
                }
            } else {
                while s + 8 <= src_len {
                    let p = src_ptr.add(s) as *const u64;
                    let word = p.read_unaligned();
                    if has_byte(word, 0x25) || has_byte(word, 0x3f) {
                        break;
                    }
                    s += 8;
                }
            }

            // Scalar scan for the exact position
            while s < src_len {
                let ch = *src_ptr.add(s);
                if ch == b'%' {
                    break;
                }
                if uri && ch == b'?' {
                    // Copy the literal run including '?'
                    let run_len = s - scan_start + 1;
                    if run_len > 0 {
                        core::ptr::copy_nonoverlapping(
                            src_ptr.add(scan_start),
                            dst_ptr.add(d),
                            run_len,
                        );
                        d += run_len;
                    }
                    return d;
                }
                s += 1;
            }

            // Copy the literal run before '%'
            let run_len = s - scan_start;
            if run_len > 0 {
                core::ptr::copy_nonoverlapping(
                    src_ptr.add(scan_start),
                    dst_ptr.add(d),
                    run_len,
                );
                d += run_len;
            }

            // End of input?
            if s >= src_len {
                break;
            }

            // Phase 2: Decode percent-encoded sequence(s)
            // We're at '%', decode the hex pair
            s += 1; // skip '%'

            if s + 2 <= src_len {
                let hi = *src_ptr.add(s);
                let lo = *src_ptr.add(s + 1);
                let hi_val = HEX_DECODE[hi as usize];
                let lo_val = HEX_DECODE[lo as usize];

                if hi_val != 0xff && lo_val != 0xff {
                    let decoded = (hi_val << 4) | lo_val;
                    if uri && decoded == b'?' {
                        *dst_ptr.add(d) = decoded;
                        d += 1;
                        return d;
                    }
                    *dst_ptr.add(d) = decoded;
                    d += 1;
                    s += 2;
                } else if hi_val == 0xff {
                    // First hex digit invalid (state 1, hex_val(ch) == None in the
                    // reference): emit the char after '%' as a literal and consume
                    // only that one byte; the second byte is re-scanned as input.
                    *dst_ptr.add(d) = hi;
                    d += 1;
                    s += 1;
                } else {
                    // BUG FIX: first hex digit valid but second invalid. The previous
                    // single else-branch wrongly emitted `hi` as a literal and advanced
                    // s by 1, leaving the second byte to be re-scanned — diverging from
                    // ngx_unescape_uri (e.g. "%4G" yielded "4G" instead of ""). The
                    // reference state machine reaches state 2 (decoded = hi), then on the
                    // invalid second digit (hex_val == None) emits NOTHING and has already
                    // advanced past BOTH pair bytes. Mirror that: consume both, emit none.
                    s += 2;
                }
            } else if s < src_len {
                // Only one char after '%' — emit it
                *dst_ptr.add(d) = *src_ptr.add(s);
                d += 1;
                s += 1;
            }
        }
    }

    d
}

/// SWAR technique: detect if any byte in a u64 word equals `needle`.
#[inline(always)]
const fn has_byte(word: u64, needle: u8) -> bool {
    let mask = 0x0101_0101_0101_0101u64;
    let needle_word = mask * (needle as u64);
    let xor = word ^ needle_word;
    // A byte is zero iff (byte - 1) & !byte & 0x80 is set
    let result = (xor.wrapping_sub(mask)) & !xor & (mask << 7);
    result != 0
}

/// Hex decode lookup table. Maps ASCII char -> nibble value (0-15), or 0xff for invalid.
const HEX_DECODE: [u8; 256] = {
    let mut t = [0xffu8; 256];
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = c - b'0';
        c += 1;
    }
    let mut c = b'a';
    while c <= b'f' {
        t[c as usize] = c - b'a' + 10;
        c += 1;
    }
    let mut c = b'A';
    while c <= b'F' {
        t[c as usize] = c - b'A' + 10;
        c += 1;
    }
    t
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_unescape() {
        let src = b"hello%20world";
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, src, false);
        assert_eq!(&dst[..n], b"hello world");
    }

    #[test]
    fn no_escapes() {
        let src = b"hello-world_test.html";
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, src, false);
        assert_eq!(&dst[..n], src.as_slice());
    }

    #[test]
    fn uri_stops_at_question() {
        let src = b"path%2Fto?query=1";
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, src, true);
        assert_eq!(&dst[..n], b"path/to?");
    }

    #[test]
    fn consecutive_escapes() {
        let src = b"%41%42%43";
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, src, false);
        assert_eq!(&dst[..n], b"ABC");
    }

    #[test]
    fn empty_input() {
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, b"", false);
        assert_eq!(n, 0);
    }

    #[test]
    fn valid_then_invalid_hex_consumes_both_emits_nothing() {
        // Regression for the '%<valid-hex><invalid-hex>' divergence. The reference
        // ngx_unescape_uri reaches state 2 (first digit valid) and then, on an invalid
        // second digit, consumes both pair bytes and emits NOTHING. The old code emitted
        // the first hex char as a literal and re-scanned the second, producing extra bytes.

        // First digit valid, second invalid -> "" (both bytes consumed).
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, b"%4G", false);
        assert_eq!(&dst[..n], b"", "%4G must decode to empty, not \"4G\"");

        // Trailing '%' as the invalid second digit must also be consumed, not re-scanned.
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, b"%0%", false);
        assert_eq!(&dst[..n], b"", "%0%: trailing '%' is consumed as the 2nd pair byte");

        // Same divergence in uri mode where the invalid 2nd digit is '?'.
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, b"%1?", true);
        assert_eq!(&dst[..n], b"", "%1? must decode to empty in uri mode");

        // Boundary check: when the FIRST digit is invalid, the reference DOES emit that
        // char and re-scans the rest, so this branch must be preserved unchanged.
        let mut dst = [0u8; 64];
        let n = unescape_uri_fast(&mut dst, b"%G4", false);
        assert_eq!(&dst[..n], b"G4", "%G4: first digit invalid emits 'G' then literal '4'");
    }

    #[test]
    fn has_byte_works() {
        assert!(has_byte(0x0025000000000000, 0x25));
        assert!(has_byte(0x0000000000000025, 0x25));
        assert!(!has_byte(0x0101010101010101, 0x25));
    }
}
