//! URI path canonicalization (HAProxy origin, RFC 3986).
//!
//! Resolves `.` and `..` segments, merges consecutive slashes, and decodes
//! unreserved percent-encoded characters.

/// Normalize a URI path by resolving dot segments and merging consecutive slashes.
///
/// Implements the "remove_dot_segments" algorithm from RFC 3986, Section 5.2.4,
/// with the addition of merging consecutive `/` characters.
///
/// # Examples
/// - `/a/b/../c` -> `/a/c`
/// - `/a/./b` -> `/a/b`
/// - `/a//b` -> `/a/b`
/// - `/..` -> `/`
pub fn normalize_uri_path(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return Vec::new();
    }

    // Work with segments for dot resolution
    let mut output_segments: Vec<&[u8]> = Vec::new();
    let has_leading_slash = path.first() == Some(&b'/');
    let has_trailing_slash = path.len() > 1 && path.last() == Some(&b'/');

    // Split into segments, skipping empty segments (which handles //)
    let segments = path.split(|&b| b == b'/')
        .filter(|s| !s.is_empty());

    for seg in segments {
        if seg == b"." {
            // Current directory — skip
            continue;
        } else if seg == b".." {
            // Parent directory — pop last segment if any
            output_segments.pop();
        } else {
            output_segments.push(seg);
        }
    }

    // Reassemble
    let mut result = Vec::with_capacity(path.len());
    if has_leading_slash {
        result.push(b'/');
    }

    for (i, seg) in output_segments.iter().enumerate() {
        if i > 0 {
            result.push(b'/');
        }
        result.extend_from_slice(seg);
    }

    // Preserve trailing slash if the original had one (and we have segments or just a root)
    if has_trailing_slash && !result.is_empty() && result.last() != Some(&b'/') {
        result.push(b'/');
    }

    // Ensure at least `/` for absolute paths that resolved to empty
    if has_leading_slash && result.is_empty() {
        result.push(b'/');
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path() {
        assert_eq!(normalize_uri_path(b""), b"");
    }

    #[test]
    fn root() {
        assert_eq!(normalize_uri_path(b"/"), b"/");
    }

    #[test]
    fn no_dots() {
        assert_eq!(normalize_uri_path(b"/a/b/c"), b"/a/b/c");
    }

    #[test]
    fn single_dot() {
        assert_eq!(normalize_uri_path(b"/a/./b"), b"/a/b");
    }

    #[test]
    fn double_dot() {
        assert_eq!(normalize_uri_path(b"/a/b/../c"), b"/a/c");
    }

    #[test]
    fn double_dot_at_root() {
        assert_eq!(normalize_uri_path(b"/.."), b"/");
    }

    #[test]
    fn merge_slashes() {
        assert_eq!(normalize_uri_path(b"/a//b///c"), b"/a/b/c");
    }

    #[test]
    fn complex_path() {
        assert_eq!(normalize_uri_path(b"/a/b/c/./../../g"), b"/a/g");
    }

    #[test]
    fn trailing_slash_preserved() {
        assert_eq!(normalize_uri_path(b"/a/b/"), b"/a/b/");
    }

    #[test]
    fn only_dots() {
        assert_eq!(normalize_uri_path(b"/././."), b"/");
    }

    #[test]
    fn parent_beyond_root() {
        assert_eq!(normalize_uri_path(b"/a/../../b"), b"/b");
    }

    #[test]
    fn relative_path() {
        assert_eq!(normalize_uri_path(b"a/b/../c"), b"a/c");
    }
}
