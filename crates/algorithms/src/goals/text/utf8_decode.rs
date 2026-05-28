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
}
