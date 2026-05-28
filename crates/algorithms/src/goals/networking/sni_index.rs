/// SNI-indexed policy fast path (inspired by Caddy).
///
/// Provides O(1) exact-match lookup by SNI hostname with a wildcard
/// fallback.  Wildcard entries are stored as `*.example.com` and tried
/// if an exact match fails.
use std::collections::HashMap;

/// An index mapping SNI hostnames to values of type `T`.
pub struct SniIndex<T> {
    exact: HashMap<String, T>,
    wildcard: HashMap<String, T>,
}

impl<T> SniIndex<T> {
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard: HashMap::new(),
        }
    }

    /// Insert a domain-to-value mapping.
    ///
    /// If `domain` starts with `*.` it is stored as a wildcard entry;
    /// otherwise it is an exact-match entry.
    pub fn insert(&mut self, domain: &str, value: T) {
        let lower = domain.trim().to_ascii_lowercase();
        if let Some(suffix) = lower.strip_prefix("*.") {
            self.wildcard.insert(suffix.to_string(), value);
        } else {
            self.exact.insert(lower, value);
        }
    }

    /// Look up the value associated with an SNI hostname.
    ///
    /// Tries exact match first, then wildcard fallback by stripping the
    /// first label from the SNI and checking the wildcard table.
    pub fn lookup(&self, sni: &str) -> Option<&T> {
        let lower = sni.trim().to_ascii_lowercase();

        // Try exact match.
        if let Some(val) = self.exact.get(&lower) {
            return Some(val);
        }

        // Try wildcard fallback: strip the first label.
        if let Some(dot_pos) = lower.find('.') {
            let suffix = &lower[dot_pos + 1..];
            if let Some(val) = self.wildcard.get(suffix) {
                return Some(val);
            }
        }

        None
    }
}

impl<T> Default for SniIndex<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut idx = SniIndex::new();
        idx.insert("example.com", 42);
        assert_eq!(idx.lookup("example.com"), Some(&42));
    }

    #[test]
    fn test_exact_miss() {
        let mut idx = SniIndex::new();
        idx.insert("example.com", 42);
        assert_eq!(idx.lookup("other.com"), None);
    }

    #[test]
    fn test_wildcard_match() {
        let mut idx = SniIndex::new();
        idx.insert("*.example.com", 99);
        assert_eq!(idx.lookup("foo.example.com"), Some(&99));
    }

    #[test]
    fn test_wildcard_no_bare() {
        let mut idx = SniIndex::new();
        idx.insert("*.example.com", 99);
        assert_eq!(idx.lookup("example.com"), None);
    }

    #[test]
    fn test_exact_preferred_over_wildcard() {
        let mut idx = SniIndex::new();
        idx.insert("*.example.com", 1);
        idx.insert("foo.example.com", 2);
        assert_eq!(idx.lookup("foo.example.com"), Some(&2));
    }

    #[test]
    fn test_case_insensitive() {
        let mut idx = SniIndex::new();
        idx.insert("Example.COM", 10);
        assert_eq!(idx.lookup("EXAMPLE.com"), Some(&10));
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        let mut idx = SniIndex::new();
        idx.insert("*.Example.COM", 20);
        assert_eq!(idx.lookup("FOO.example.com"), Some(&20));
    }

    #[test]
    fn test_empty_index() {
        let idx: SniIndex<i32> = SniIndex::new();
        assert_eq!(idx.lookup("anything.com"), None);
    }
}
