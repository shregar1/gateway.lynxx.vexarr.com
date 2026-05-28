/// ACME domain deduplication (inspired by Traefik).
///
/// When requesting certificates, duplicate and redundant domains should be
/// removed.  A wildcard `*.example.com` makes explicit sub-domains like
/// `foo.example.com` redundant, but NOT `example.com` itself.

/// Sort, deduplicate, and remove domains that are already covered by a
/// wildcard entry in the list.
///
/// After this function returns the list is sorted, contains no duplicates,
/// and every domain that would be matched by a present wildcard has been
/// removed (wildcards themselves are kept).
pub fn dedup_domains(domains: &mut Vec<String>) {
    if domains.len() <= 1 {
        return;
    }

    // Normalise to lowercase.
    for d in domains.iter_mut() {
        *d = d.trim().to_ascii_lowercase();
    }

    // Sort so wildcards (*.x) come before their sub-domains.
    domains.sort();
    domains.dedup();

    // Collect wildcards first.
    let wildcards: Vec<String> = domains
        .iter()
        .filter(|d| d.starts_with("*."))
        .cloned()
        .collect();

    // Remove non-wildcard domains covered by a wildcard.
    domains.retain(|d| {
        if d.starts_with("*.") {
            return true; // keep wildcards
        }
        // Check if any wildcard covers this domain.
        for wc in &wildcards {
            let suffix = &wc[1..]; // e.g. ".example.com"
            if let Some(prefix) = d.strip_suffix(suffix) {
                // The domain is covered if the prefix is a single label (no dots).
                if !prefix.is_empty() && !prefix.contains('.') {
                    return false; // redundant
                }
            }
        }
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_simple_dedup() {
        let mut domains = sv(&["b.com", "a.com", "b.com"]);
        dedup_domains(&mut domains);
        assert_eq!(domains, sv(&["a.com", "b.com"]));
    }

    #[test]
    fn test_wildcard_removes_subdomain() {
        let mut domains = sv(&["*.example.com", "foo.example.com", "bar.example.com"]);
        dedup_domains(&mut domains);
        assert_eq!(domains, sv(&["*.example.com"]));
    }

    #[test]
    fn test_wildcard_keeps_bare_domain() {
        let mut domains = sv(&["*.example.com", "example.com"]);
        dedup_domains(&mut domains);
        assert_eq!(domains, sv(&["*.example.com", "example.com"]));
    }

    #[test]
    fn test_wildcard_no_multi_level() {
        let mut domains = sv(&["*.example.com", "a.b.example.com"]);
        dedup_domains(&mut domains);
        // a.b.example.com is NOT covered by *.example.com (multi-level).
        assert_eq!(domains, sv(&["*.example.com", "a.b.example.com"]));
    }

    #[test]
    fn test_case_normalisation() {
        let mut domains = sv(&["Example.COM", "EXAMPLE.com"]);
        dedup_domains(&mut domains);
        assert_eq!(domains, sv(&["example.com"]));
    }

    #[test]
    fn test_empty() {
        let mut domains: Vec<String> = vec![];
        dedup_domains(&mut domains);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_single() {
        let mut domains = sv(&["example.com"]);
        dedup_domains(&mut domains);
        assert_eq!(domains, sv(&["example.com"]));
    }

    #[test]
    fn test_mixed() {
        let mut domains = sv(&[
            "sub.a.com",
            "*.a.com",
            "b.com",
            "sub.a.com",
            "other.b.com",
        ]);
        dedup_domains(&mut domains);
        // sub.a.com is covered by *.a.com; other.b.com is NOT (no *.b.com).
        assert_eq!(domains, sv(&["*.a.com", "b.com", "other.b.com"]));
    }
}
