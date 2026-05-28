//! Path prefix/suffix stripping (Caddy origin).
//!
//! Byte-level path manipulation utilities for stripping prefixes, suffixes,
//! and managing trailing slashes.

/// Strip `prefix` from the beginning of `path`.
///
/// Returns the remainder of `path` after removing the prefix. If `path`
/// does not start with `prefix`, returns `path` unchanged.
pub fn strip_prefix<'a>(path: &'a [u8], prefix: &[u8]) -> &'a [u8] {
    if path.starts_with(prefix) {
        &path[prefix.len()..]
    } else {
        path
    }
}

/// Strip `suffix` from the end of `path`.
///
/// Returns the leading portion of `path` after removing the suffix. If `path`
/// does not end with `suffix`, returns `path` unchanged.
pub fn strip_suffix<'a>(path: &'a [u8], suffix: &[u8]) -> &'a [u8] {
    if path.ends_with(suffix) {
        &path[..path.len() - suffix.len()]
    } else {
        path
    }
}

/// Remove a trailing `/` from `path` (if present and path is longer than 1 byte).
///
/// The root path `/` is returned as-is.
pub fn trim_trailing_slash(path: &[u8]) -> &[u8] {
    if path.len() > 1 && path.last() == Some(&b'/') {
        &path[..path.len() - 1]
    } else {
        path
    }
}

/// Ensure `path` ends with a `/`, appending one if necessary.
///
/// Returns a new `Vec<u8>` (allocation only when a slash must be added).
pub fn ensure_trailing_slash(path: &[u8]) -> Vec<u8> {
    if path.is_empty() || path.last() == Some(&b'/') {
        path.to_vec()
    } else {
        let mut out = Vec::with_capacity(path.len() + 1);
        out.extend_from_slice(path);
        out.push(b'/');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_prefix ──

    #[test]
    fn prefix_match() {
        assert_eq!(strip_prefix(b"/api/v1/users", b"/api"), b"/v1/users");
    }

    #[test]
    fn prefix_no_match() {
        assert_eq!(strip_prefix(b"/web/index", b"/api"), b"/web/index");
    }

    #[test]
    fn prefix_exact() {
        assert_eq!(strip_prefix(b"/api", b"/api"), b"");
    }

    #[test]
    fn prefix_empty() {
        assert_eq!(strip_prefix(b"/path", b""), b"/path");
    }

    // ── strip_suffix ──

    #[test]
    fn suffix_match() {
        assert_eq!(strip_suffix(b"/api/v1.json", b".json"), b"/api/v1");
    }

    #[test]
    fn suffix_no_match() {
        assert_eq!(strip_suffix(b"/api/v1.xml", b".json"), b"/api/v1.xml");
    }

    #[test]
    fn suffix_exact() {
        assert_eq!(strip_suffix(b".json", b".json"), b"");
    }

    #[test]
    fn suffix_empty() {
        assert_eq!(strip_suffix(b"/path", b""), b"/path");
    }

    // ── trim_trailing_slash ──

    #[test]
    fn trim_trailing() {
        assert_eq!(trim_trailing_slash(b"/api/v1/"), b"/api/v1");
    }

    #[test]
    fn trim_no_trailing() {
        assert_eq!(trim_trailing_slash(b"/api/v1"), b"/api/v1");
    }

    #[test]
    fn trim_root_preserved() {
        assert_eq!(trim_trailing_slash(b"/"), b"/");
    }

    #[test]
    fn trim_empty() {
        assert_eq!(trim_trailing_slash(b""), b"");
    }

    // ── ensure_trailing_slash ──

    #[test]
    fn ensure_adds_slash() {
        assert_eq!(ensure_trailing_slash(b"/api/v1"), b"/api/v1/");
    }

    #[test]
    fn ensure_already_has_slash() {
        assert_eq!(ensure_trailing_slash(b"/api/v1/"), b"/api/v1/");
    }

    #[test]
    fn ensure_empty() {
        assert_eq!(ensure_trailing_slash(b""), b"");
    }

    #[test]
    fn ensure_root() {
        assert_eq!(ensure_trailing_slash(b"/"), b"/");
    }
}
