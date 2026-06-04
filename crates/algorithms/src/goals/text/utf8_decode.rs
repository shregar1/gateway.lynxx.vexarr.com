/// UTF-8 decode and validate.
///
/// Manual byte-level decoder following RFC 3629. Validates continuation
/// bytes and rejects overlong encodings and surrogates.

/// Validate that `data` is well-formed UTF-8. Returns true if valid.
pub fn utf8_validate(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let width = match b {
            0x00..=0x7F => 1,
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return false, // invalid lead byte (includes 0x80-0xBF, 0xC0-0xC1, 0xF5+)
        };

        if i + width > data.len() {
            return false;
        }

        match width {
            1 => {}
            2 => {
                if data[i + 1] & 0xC0 != 0x80 {
                    return false;
                }
            }
            3 => {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 {
                    return false;
                }
                // Reject overlong and surrogates
                match b {
                    0xE0 if b1 < 0xA0 => return false,
                    0xED if b1 > 0x9F => return false, // surrogates U+D800..U+DFFF
                    _ => {}
                }
            }
            4 => {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                let b3 = data[i + 3];
                if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                    return false;
                }
                // Reject overlong and > U+10FFFF
                match b {
                    0xF0 if b1 < 0x90 => return false,
                    0xF4 if b1 > 0x8F => return false,
                    _ => {}
                }
            }
            _ => unreachable!(),
        }

        i += width;
    }
    true
}

/// Decode one UTF-8 character from the start of `data`.
/// Returns the decoded char and the number of bytes consumed,
/// or None if the data is empty or malformed.
pub fn utf8_decode_char(data: &[u8]) -> Option<(char, usize)> {
    if data.is_empty() {
        return None;
    }

    let b0 = data[0];
    let (cp, width) = match b0 {
        0x00..=0x7F => (b0 as u32, 1),
        0xC2..=0xDF => {
            if data.len() < 2 || data[1] & 0xC0 != 0x80 {
                return None;
            }
            let cp = ((b0 as u32 & 0x1F) << 6) | (data[1] as u32 & 0x3F);
            (cp, 2)
        }
        0xE0..=0xEF => {
            if data.len() < 3 || data[1] & 0xC0 != 0x80 || data[2] & 0xC0 != 0x80 {
                return None;
            }
            let b1 = data[1];
            match b0 {
                0xE0 if b1 < 0xA0 => return None,
                0xED if b1 > 0x9F => return None,
                _ => {}
            }
            let cp = ((b0 as u32 & 0x0F) << 12)
                | ((data[1] as u32 & 0x3F) << 6)
                | (data[2] as u32 & 0x3F);
            (cp, 3)
        }
        0xF0..=0xF4 => {
            if data.len() < 4
                || data[1] & 0xC0 != 0x80
                || data[2] & 0xC0 != 0x80
                || data[3] & 0xC0 != 0x80
            {
                return None;
            }
            let b1 = data[1];
            match b0 {
                0xF0 if b1 < 0x90 => return None,
                0xF4 if b1 > 0x8F => return None,
                _ => {}
            }
            let cp = ((b0 as u32 & 0x07) << 18)
                | ((data[1] as u32 & 0x3F) << 12)
                | ((data[2] as u32 & 0x3F) << 6)
                | (data[3] as u32 & 0x3F);
            (cp, 4)
        }
        _ => return None,
    };

    char::from_u32(cp).map(|ch| (ch, width))
}

/// Bulk UTF-8 validator with an ASCII fast-path.
///
/// Processes runs of pure-ASCII bytes 8 at a time by reading a `u64`
/// and testing the high bit of every byte at once. Non-ASCII bytes fall
/// back to per-codepoint multi-byte validation. Correctly rejects
/// overlong encodings, surrogates (U+D800..=U+DFFF) and codepoints
/// beyond U+10FFFF.
pub fn utf8_scan_valid(data: &[u8]) -> bool {
    const ASCII_MASK: u64 = 0x8080_8080_8080_8080;
    let len = data.len();
    let mut i = 0;

    while i < len {
        // ASCII fast-path: consume 8 bytes at a time while they are pure ASCII.
        if data[i] < 0x80 {
            while i + 8 <= len {
                let chunk = u64::from_ne_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                if chunk & ASCII_MASK != 0 {
                    break; // a non-ASCII byte lives in this chunk
                }
                i += 8;
            }
            // Consume any remaining ASCII bytes one at a time.
            while i < len && data[i] < 0x80 {
                i += 1;
            }
            continue;
        }

        // Multi-byte sequence: validate one codepoint.
        let b = data[i];
        let width = match b {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return false, // invalid lead byte (0x80-0xBF, 0xC0-0xC1, 0xF5+)
        };

        if i + width > len {
            return false;
        }

        match width {
            2 => {
                if data[i + 1] & 0xC0 != 0x80 {
                    return false;
                }
            }
            3 => {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 {
                    return false;
                }
                match b {
                    0xE0 if b1 < 0xA0 => return false, // overlong
                    0xED if b1 > 0x9F => return false, // surrogates U+D800..U+DFFF
                    _ => {}
                }
            }
            4 => {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                let b3 = data[i + 3];
                if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                    return false;
                }
                match b {
                    0xF0 if b1 < 0x90 => return false, // overlong
                    0xF4 if b1 > 0x8F => return false, // > U+10FFFF
                    _ => {}
                }
            }
            _ => unreachable!(),
        }

        i += width;
    }

    true
}

/// Count the number of Unicode scalar values in `data` if it is valid
/// UTF-8, or `None` if it is malformed. Uses the same ASCII fast-path
/// as [`utf8_scan_valid`].
pub fn utf8_count_chars(data: &[u8]) -> Option<usize> {
    const ASCII_MASK: u64 = 0x8080_8080_8080_8080;
    let len = data.len();
    let mut i = 0;
    let mut count = 0;

    while i < len {
        if data[i] < 0x80 {
            while i + 8 <= len {
                let chunk = u64::from_ne_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                if chunk & ASCII_MASK != 0 {
                    break;
                }
                i += 8;
                count += 8;
            }
            while i < len && data[i] < 0x80 {
                i += 1;
                count += 1;
            }
            continue;
        }

        let b = data[i];
        let width = match b {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return None,
        };

        if i + width > len {
            return None;
        }

        match width {
            2 => {
                if data[i + 1] & 0xC0 != 0x80 {
                    return None;
                }
            }
            3 => {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 {
                    return None;
                }
                match b {
                    0xE0 if b1 < 0xA0 => return None,
                    0xED if b1 > 0x9F => return None,
                    _ => {}
                }
            }
            4 => {
                let b1 = data[i + 1];
                let b2 = data[i + 2];
                let b3 = data[i + 3];
                if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                    return None;
                }
                match b {
                    0xF0 if b1 < 0x90 => return None,
                    0xF4 if b1 > 0x8F => return None,
                    _ => {}
                }
            }
            _ => unreachable!(),
        }

        i += width;
        count += 1;
    }

    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_valid() {
        assert!(utf8_validate(b"Hello, world!"));
    }

    #[test]
    fn multibyte_valid() {
        assert!(utf8_validate("Grüße 日本語 🦀".as_bytes()));
    }

    #[test]
    fn invalid_continuation() {
        assert!(!utf8_validate(&[0xC0, 0xAF])); // overlong
    }

    #[test]
    fn truncated_sequence() {
        assert!(!utf8_validate(&[0xE0, 0xA0])); // missing 3rd byte
    }

    #[test]
    fn surrogate_rejected() {
        assert!(!utf8_validate(&[0xED, 0xA0, 0x80])); // U+D800
    }

    #[test]
    fn decode_ascii() {
        assert_eq!(utf8_decode_char(b"A"), Some(('A', 1)));
    }

    #[test]
    fn decode_multibyte() {
        let bytes = "ü".as_bytes();
        assert_eq!(utf8_decode_char(bytes), Some(('ü', 2)));
    }

    #[test]
    fn decode_4byte() {
        let bytes = "🦀".as_bytes();
        assert_eq!(utf8_decode_char(bytes), Some(('🦀', 4)));
    }

    #[test]
    fn decode_empty() {
        assert_eq!(utf8_decode_char(b""), None);
    }

    #[test]
    fn scan_ascii_valid_and_counts() {
        let s = b"Hello, world!";
        assert!(utf8_scan_valid(s));
        assert_eq!(utf8_count_chars(s), Some(s.len()));
    }

    #[test]
    fn scan_empty() {
        assert!(utf8_scan_valid(b""));
        assert_eq!(utf8_count_chars(b""), Some(0));
    }

    #[test]
    fn scan_multibyte_valid_and_count() {
        let s = "héllo wörld 你好 😀";
        assert!(utf8_scan_valid(s.as_bytes()));
        assert_eq!(
            utf8_count_chars(s.as_bytes()),
            Some(s.chars().count())
        );
    }

    #[test]
    fn scan_lone_continuation_byte() {
        assert!(!utf8_scan_valid(&[0x80]));
        assert_eq!(utf8_count_chars(&[0x80]), None);
    }

    #[test]
    fn scan_overlong() {
        assert!(!utf8_scan_valid(&[0xC0, 0x80]));
        assert_eq!(utf8_count_chars(&[0xC0, 0x80]), None);
    }

    #[test]
    fn scan_surrogate() {
        assert!(!utf8_scan_valid(&[0xED, 0xA0, 0x80])); // U+D800
        assert_eq!(utf8_count_chars(&[0xED, 0xA0, 0x80]), None);
    }

    #[test]
    fn scan_too_large_codepoint() {
        // F4 90 80 80 would encode U+110000, beyond U+10FFFF.
        assert!(!utf8_scan_valid(&[0xF4, 0x90, 0x80, 0x80]));
        assert_eq!(utf8_count_chars(&[0xF4, 0x90, 0x80, 0x80]), None);
    }

    #[test]
    fn scan_truncated_multibyte() {
        assert!(!utf8_scan_valid(&[0xE0, 0xA0])); // missing 3rd byte
        assert_eq!(utf8_count_chars(&[0xE0, 0xA0]), None);
    }

    #[test]
    fn scan_long_ascii_fast_path() {
        let s = "a".repeat(100);
        assert!(s.len() > 64);
        assert!(utf8_scan_valid(s.as_bytes()));
        assert_eq!(utf8_count_chars(s.as_bytes()), Some(100));
    }

    #[test]
    fn scan_long_ascii_with_trailing_multibyte() {
        // Exercise the fast-path boundary: 70 ASCII bytes + a multibyte char.
        let mut s = "x".repeat(70);
        s.push('é');
        s.push_str("yz");
        assert!(utf8_scan_valid(s.as_bytes()));
        assert_eq!(utf8_count_chars(s.as_bytes()), Some(s.chars().count()));
    }
}
