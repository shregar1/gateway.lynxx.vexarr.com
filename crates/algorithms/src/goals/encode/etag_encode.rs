//! ETag generation (Caddy origin).
//!
//! Generates strong and weak ETags from file metadata (size + modification time)
//! and provides comparison functions per RFC 7232.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encode a `u64` as lowercase hex into `buf`.
fn hex_u64(val: u64, buf: &mut Vec<u8>) {
    if val == 0 {
        buf.push(b'0');
        return;
    }
    // Find the highest non-zero nibble
    let leading_zeros = val.leading_zeros() as usize;
    let nibbles = 16 - leading_zeros / 4;
    for i in (0..nibbles).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        buf.push(HEX[nibble]);
    }
}

/// Generate a strong ETag from file size and modification time.
///
/// Format: `"<size_hex>-<mtime_hex>"`
pub fn etag_strong(size: u64, mtime_secs: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.push(b'"');
    hex_u64(size, &mut buf);
    buf.push(b'-');
    hex_u64(mtime_secs, &mut buf);
    buf.push(b'"');
    buf
}

/// Generate a weak ETag from file size and modification time.
///
/// Format: `W/"<size_hex>-<mtime_hex>"`
pub fn etag_weak(size: u64, mtime_secs: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(b"W/");
    buf.push(b'"');
    hex_u64(size, &mut buf);
    buf.push(b'-');
    hex_u64(mtime_secs, &mut buf);
    buf.push(b'"');
    buf
}

/// Weak ETag comparison (RFC 7232, Section 2.3.2).
///
/// Two ETags match weakly if their opaque-tags are identical after stripping
/// any `W/` prefix.
pub fn etag_weak_match(a: &[u8], b: &[u8]) -> bool {
    let a_tag = strip_weak_prefix(a);
    let b_tag = strip_weak_prefix(b);
    a_tag == b_tag
}

/// Strong ETag comparison (RFC 7232, Section 2.3.2).
///
/// Two ETags match strongly only if **neither** has a `W/` prefix and
/// their opaque-tags are byte-identical.
pub fn etag_strong_match(a: &[u8], b: &[u8]) -> bool {
    let a_weak = a.starts_with(b"W/") || a.starts_with(b"w/");
    let b_weak = b.starts_with(b"W/") || b.starts_with(b"w/");
    if a_weak || b_weak {
        return false;
    }
    a == b
}

fn strip_weak_prefix(tag: &[u8]) -> &[u8] {
    if tag.starts_with(b"W/") || tag.starts_with(b"w/") {
        &tag[2..]
    } else {
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_etag_format() {
        let etag = etag_strong(1024, 1700000000);
        let s = String::from_utf8(etag).unwrap();
        assert!(s.starts_with('"'));
        assert!(s.ends_with('"'));
        assert!(s.contains('-'));
    }

    #[test]
    fn weak_etag_format() {
        let etag = etag_weak(1024, 1700000000);
        let s = String::from_utf8(etag).unwrap();
        assert!(s.starts_with("W/\""));
        assert!(s.ends_with('"'));
    }

    #[test]
    fn strong_etag_deterministic() {
        let a = etag_strong(42, 99);
        let b = etag_strong(42, 99);
        assert_eq!(a, b);
    }

    #[test]
    fn different_params_differ() {
        let a = etag_strong(42, 99);
        let b = etag_strong(43, 99);
        assert_ne!(a, b);
    }

    #[test]
    fn weak_match_same_strong() {
        let a = etag_strong(10, 20);
        let b = etag_strong(10, 20);
        assert!(etag_weak_match(&a, &b));
    }

    #[test]
    fn weak_match_weak_vs_strong() {
        let a = etag_weak(10, 20);
        let b = etag_strong(10, 20);
        assert!(etag_weak_match(&a, &b));
    }

    #[test]
    fn weak_match_both_weak() {
        let a = etag_weak(10, 20);
        let b = etag_weak(10, 20);
        assert!(etag_weak_match(&a, &b));
    }

    #[test]
    fn strong_match_same_strong() {
        let a = etag_strong(10, 20);
        let b = etag_strong(10, 20);
        assert!(etag_strong_match(&a, &b));
    }

    #[test]
    fn strong_match_rejects_weak() {
        let a = etag_weak(10, 20);
        let b = etag_strong(10, 20);
        assert!(!etag_strong_match(&a, &b));
    }

    #[test]
    fn strong_match_rejects_both_weak() {
        let a = etag_weak(10, 20);
        let b = etag_weak(10, 20);
        assert!(!etag_strong_match(&a, &b));
    }

    #[test]
    fn zero_values() {
        let etag = etag_strong(0, 0);
        let s = String::from_utf8(etag).unwrap();
        assert_eq!(s, "\"0-0\"");
    }
}
