//! JSON string escaping (nginx origin).
//!
//! Escapes control characters (0x00..0x1F), backslash, and double quotes
//! as required by RFC 8259. Non-ASCII control characters use `\uXXXX` form.

/// Escape a byte slice for embedding inside a JSON string value.
///
/// The output does **not** include the surrounding `"` delimiters.
/// Control characters (0x00..0x1F), `\`, and `"` are escaped.
pub fn escape_json(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    for &b in input {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\x08' => out.extend_from_slice(b"\\b"),
            b'\x0C' => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1F => {
                // \uXXXX for remaining control characters
                out.extend_from_slice(b"\\u00");
                let hi = b >> 4;
                let lo = b & 0x0F;
                out.push(HEX_DIGITS[hi as usize]);
                out.push(HEX_DIGITS[lo as usize]);
            }
            _ => out.push(b),
        }
    }
}

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii() {
        let mut out = Vec::new();
        escape_json(b"hello world", &mut out);
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn escapes_quotes() {
        let mut out = Vec::new();
        escape_json(b"say \"hi\"", &mut out);
        assert_eq!(out, b"say \\\"hi\\\"");
    }

    #[test]
    fn escapes_backslash() {
        let mut out = Vec::new();
        escape_json(b"a\\b", &mut out);
        assert_eq!(out, b"a\\\\b");
    }

    #[test]
    fn escapes_common_controls() {
        let mut out = Vec::new();
        escape_json(b"\n\r\t", &mut out);
        assert_eq!(out, b"\\n\\r\\t");
    }

    #[test]
    fn escapes_backspace_formfeed() {
        let mut out = Vec::new();
        escape_json(b"\x08\x0C", &mut out);
        assert_eq!(out, b"\\b\\f");
    }

    #[test]
    fn escapes_null() {
        let mut out = Vec::new();
        escape_json(b"\x00", &mut out);
        assert_eq!(out, b"\\u0000");
    }

    #[test]
    fn escapes_other_control() {
        let mut out = Vec::new();
        escape_json(b"\x1F", &mut out);
        assert_eq!(out, b"\\u001f");
    }

    #[test]
    fn high_bytes_passthrough() {
        let input = vec![0x80u8, 0xC0, 0xFF];
        let mut out = Vec::new();
        escape_json(&input, &mut out);
        assert_eq!(out, input);
    }

    #[test]
    fn empty_input() {
        let mut out = Vec::new();
        escape_json(b"", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn mixed_content() {
        let mut out = Vec::new();
        escape_json(b"key: \"val\"\nnext\\line", &mut out);
        assert_eq!(out, b"key: \\\"val\\\"\\nnext\\\\line");
    }
}
