//! HTML entity escaping (nginx origin).
//!
//! Escapes the five HTML-significant characters (`&`, `<`, `>`, `"`, `'`)
//! using a const lookup table for O(n) performance.

/// Lookup table: for each byte 0..255, the replacement entity string (if any).
/// Empty slices mean the byte passes through unchanged.
const ESCAPE_TABLE: [&[u8]; 256] = {
    let mut t: [&[u8]; 256] = [b""; 256];
    t[b'&' as usize] = b"&amp;";
    t[b'<' as usize] = b"&lt;";
    t[b'>' as usize] = b"&gt;";
    t[b'"' as usize] = b"&quot;";
    t[b'\'' as usize] = b"&#39;";
    t
};

/// Escape HTML-significant characters in `input`, appending the result to `out`.
///
/// Characters `&`, `<`, `>`, `"`, and `'` are replaced with their entity
/// equivalents. All other bytes pass through unchanged.
pub fn escape_html(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    for &b in input {
        let replacement = ESCAPE_TABLE[b as usize];
        if replacement.is_empty() {
            out.push(b);
        } else {
            out.extend_from_slice(replacement);
        }
    }
}

/// Check whether `input` contains any bytes that would be escaped.
///
/// Returns `true` if at least one of `&`, `<`, `>`, `"`, `'` is present.
pub fn needs_escape(input: &[u8]) -> bool {
    input.iter().any(|&b| !ESCAPE_TABLE[b as usize].is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_escape_needed() {
        let input = b"hello world 123";
        let mut out = Vec::new();
        escape_html(input, &mut out);
        assert_eq!(out, input);
        assert!(!needs_escape(input));
    }

    #[test]
    fn escapes_ampersand() {
        let mut out = Vec::new();
        escape_html(b"a&b", &mut out);
        assert_eq!(out, b"a&amp;b");
    }

    #[test]
    fn escapes_lt_gt() {
        let mut out = Vec::new();
        escape_html(b"<div>", &mut out);
        assert_eq!(out, b"&lt;div&gt;");
    }

    #[test]
    fn escapes_quotes() {
        let mut out = Vec::new();
        escape_html(b"a=\"b'c\"", &mut out);
        assert_eq!(out, b"a=&quot;b&#39;c&quot;");
    }

    #[test]
    fn escapes_all_five() {
        let mut out = Vec::new();
        escape_html(b"&<>\"'", &mut out);
        assert_eq!(out, b"&amp;&lt;&gt;&quot;&#39;");
    }

    #[test]
    fn needs_escape_detects() {
        assert!(needs_escape(b"foo&bar"));
        assert!(needs_escape(b"<html>"));
        assert!(needs_escape(b"say \"hi\""));
        assert!(needs_escape(b"it's"));
        assert!(!needs_escape(b"plain text"));
    }

    #[test]
    fn empty_input() {
        let mut out = Vec::new();
        escape_html(b"", &mut out);
        assert!(out.is_empty());
        assert!(!needs_escape(b""));
    }

    #[test]
    fn binary_passthrough() {
        let input: Vec<u8> = (0u8..=255).filter(|&b| b != b'&' && b != b'<' && b != b'>' && b != b'"' && b != b'\'').collect();
        let mut out = Vec::new();
        escape_html(&input, &mut out);
        assert_eq!(out, input);
    }
}
