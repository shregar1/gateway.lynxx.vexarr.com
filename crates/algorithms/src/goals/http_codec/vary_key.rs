/// Vary-key computation for HTTP cache variants (inspired by Pingora).
///
/// A cache may store multiple variants of a response keyed on the `Vary`
/// header.  `parse_vary_fields` splits the comma-separated Vary header into
/// normalised (lowercased, trimmed) field names.  `compute_vary_key` hashes
/// a sorted set of (field-name, field-value) pairs into a `u64` digest
/// suitable for use as a variant discriminator.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Parse a `Vary` header value into a sorted, deduplicated list of
/// lowercased field names.
pub fn parse_vary_fields(vary_header: &str) -> Vec<String> {
    let mut fields: Vec<String> = vary_header
        .split(',')
        .map(|f| f.trim().to_ascii_lowercase())
        .filter(|f| !f.is_empty())
        .collect();
    fields.sort();
    fields.dedup();
    fields
}

/// Compute a `u64` hash over a sorted slice of `(field-name, field-value)`
/// pairs.  The caller is responsible for sorting by field name before calling.
pub fn compute_vary_key(vary_fields: &[(&str, &str)]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for &(name, value) in vary_fields {
        name.to_ascii_lowercase().hash(&mut hasher);
        value.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single() {
        assert_eq!(parse_vary_fields("Accept-Encoding"), vec!["accept-encoding"]);
    }

    #[test]
    fn test_parse_multiple() {
        let fields = parse_vary_fields("Accept-Encoding, Accept-Language, Cookie");
        assert_eq!(fields, vec!["accept-encoding", "accept-language", "cookie"]);
    }

    #[test]
    fn test_parse_dedup() {
        let fields = parse_vary_fields("Accept, accept, ACCEPT");
        assert_eq!(fields, vec!["accept"]);
    }

    #[test]
    fn test_parse_whitespace() {
        let fields = parse_vary_fields("  Accept-Encoding ,  Cookie  ");
        assert_eq!(fields, vec!["accept-encoding", "cookie"]);
    }

    #[test]
    fn test_parse_empty() {
        let fields = parse_vary_fields("");
        assert!(fields.is_empty());
    }

    #[test]
    fn test_compute_deterministic() {
        let pairs = [("accept-encoding", "gzip"), ("cookie", "session=abc")];
        let h1 = compute_vary_key(&pairs);
        let h2 = compute_vary_key(&pairs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_differs_on_value() {
        let a = [("accept-encoding", "gzip")];
        let b = [("accept-encoding", "br")];
        assert_ne!(compute_vary_key(&a), compute_vary_key(&b));
    }

    #[test]
    fn test_compute_case_insensitive_name() {
        let a = [("Accept-Encoding", "gzip")];
        let b = [("accept-encoding", "gzip")];
        assert_eq!(compute_vary_key(&a), compute_vary_key(&b));
    }
}
