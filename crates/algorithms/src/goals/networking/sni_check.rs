/// Domain fronting protection (inspired by Traefik).
///
/// Validates SNI (Server Name Indication) against allowed patterns and
/// detects domain-fronting attacks where the TLS SNI differs from the
/// HTTP Host header.

/// Check if an SNI value matches an allowed pattern.
///
/// Supports exact match and wildcard match (`*.example.com` matches
/// `foo.example.com` but not `example.com` or `foo.bar.example.com`).
pub fn sni_matches(sni: &str, allowed: &str) -> bool {
    let sni = sni.trim().to_ascii_lowercase();
    let allowed = allowed.trim().to_ascii_lowercase();

    if sni == allowed {
        return true;
    }

    // Wildcard matching: *.example.com
    if let Some(suffix) = allowed.strip_prefix("*.") {
        // SNI must end with .suffix and have exactly one label before it.
        if let Some(rest) = sni.strip_suffix(&format!(".{suffix}")) {
            // The part before .suffix must be a single label (no dots).
            return !rest.is_empty() && !rest.contains('.');
        }
    }

    false
}

/// Detect domain fronting: returns `true` if the SNI and Host header
/// represent the same domain (no fronting), `false` if they differ
/// (potential fronting attack).
///
/// Comparison is case-insensitive.  Port suffixes on the Host header
/// (e.g., `:443`) are stripped before comparison.
pub fn check_domain_fronting(sni: &str, host_header: &str) -> bool {
    let sni = sni.trim().to_ascii_lowercase();
    let host = host_header.trim().to_ascii_lowercase();

    // Strip port from host header.
    let host_domain = if let Some(bracket_end) = host.find(']') {
        // IPv6 literal: [::1]:443
        &host[..bracket_end + 1]
    } else if let Some(colon_pos) = host.rfind(':') {
        // Check if everything after the colon is a valid port.
        let after = &host[colon_pos + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            &host[..colon_pos]
        } else {
            host.as_str()
        }
    } else {
        host.as_str()
    };

    sni == host_domain
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sni_matches ──

    #[test]
    fn test_exact_match() {
        assert!(sni_matches("example.com", "example.com"));
    }

    #[test]
    fn test_exact_mismatch() {
        assert!(!sni_matches("other.com", "example.com"));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(sni_matches("Example.COM", "example.com"));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(sni_matches("foo.example.com", "*.example.com"));
    }

    #[test]
    fn test_wildcard_no_match_bare() {
        assert!(!sni_matches("example.com", "*.example.com"));
    }

    #[test]
    fn test_wildcard_no_multi_level() {
        assert!(!sni_matches("a.b.example.com", "*.example.com"));
    }

    #[test]
    fn test_wildcard_no_match_different_domain() {
        assert!(!sni_matches("foo.other.com", "*.example.com"));
    }

    // ── check_domain_fronting ──

    #[test]
    fn test_fronting_same() {
        assert!(check_domain_fronting("example.com", "example.com"));
    }

    #[test]
    fn test_fronting_same_with_port() {
        assert!(check_domain_fronting("example.com", "example.com:443"));
    }

    #[test]
    fn test_fronting_different() {
        assert!(!check_domain_fronting("evil.com", "example.com"));
    }

    #[test]
    fn test_fronting_case_insensitive() {
        assert!(check_domain_fronting("Example.COM", "example.com:8080"));
    }
}
