/// Certificate selection algorithm (inspired by Caddy).
///
/// Given a set of certificate candidates, selects the best match for an
/// incoming SNI by considering: exact vs wildcard match, expiration, and
/// key type preference (ECDSA preferred over RSA).

/// Key type of the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ecdsa,
    Rsa,
}

/// A certificate candidate for selection.
#[derive(Debug, Clone)]
pub struct CertCandidate {
    /// Domain the certificate covers (e.g. `"example.com"` or `"*.example.com"`).
    pub domain: String,
    /// Expiry time as seconds since epoch.
    pub not_after: u64,
    /// Whether this is a wildcard certificate.
    pub is_wildcard: bool,
    /// Key type of the certificate.
    pub key_type: KeyType,
}

/// Select the best certificate for the given SNI at time `now`.
///
/// Returns the index into `candidates` of the best match, or `None` if
/// no certificate matches.
///
/// Selection criteria (highest priority first):
/// 1. Must match the SNI (exact or wildcard).
/// 2. Must not be expired (`not_after > now`).
/// 3. Prefer exact match over wildcard.
/// 4. Prefer ECDSA over RSA.
/// 5. Prefer the certificate that expires latest (most remaining validity).
pub fn select_cert(candidates: &[CertCandidate], sni: &str, now: u64) -> Option<usize> {
    let sni_lower = sni.to_ascii_lowercase();

    let mut best_idx: Option<usize> = None;
    let mut best_score: (bool, bool, u64) = (false, false, 0); // (exact, ecdsa, not_after)

    for (i, cert) in candidates.iter().enumerate() {
        // Check expiry.
        if cert.not_after <= now {
            continue;
        }

        // Check domain match.
        let cert_domain = cert.domain.to_ascii_lowercase();
        let matches = if cert.is_wildcard {
            // *.example.com matches foo.example.com
            if let Some(suffix) = cert_domain.strip_prefix("*.") {
                if let Some(prefix) = sni_lower.strip_suffix(&format!(".{suffix}")) {
                    !prefix.is_empty() && !prefix.contains('.')
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            cert_domain == sni_lower
        };

        if !matches {
            continue;
        }

        let is_exact = !cert.is_wildcard;
        let is_ecdsa = cert.key_type == KeyType::Ecdsa;
        let score = (is_exact, is_ecdsa, cert.not_after);

        if best_idx.is_none() || score > best_score {
            best_idx = Some(i);
            best_score = score;
        }
    }

    best_idx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(domain: &str, not_after: u64, is_wildcard: bool, key_type: KeyType) -> CertCandidate {
        CertCandidate {
            domain: domain.to_string(),
            not_after,
            is_wildcard,
            key_type,
        }
    }

    #[test]
    fn test_exact_match() {
        let certs = vec![make_cert("example.com", 2000, false, KeyType::Rsa)];
        assert_eq!(select_cert(&certs, "example.com", 1000), Some(0));
    }

    #[test]
    fn test_wildcard_match() {
        let certs = vec![make_cert("*.example.com", 2000, true, KeyType::Rsa)];
        assert_eq!(select_cert(&certs, "foo.example.com", 1000), Some(0));
    }

    #[test]
    fn test_no_match() {
        let certs = vec![make_cert("other.com", 2000, false, KeyType::Rsa)];
        assert_eq!(select_cert(&certs, "example.com", 1000), None);
    }

    #[test]
    fn test_expired() {
        let certs = vec![make_cert("example.com", 500, false, KeyType::Rsa)];
        assert_eq!(select_cert(&certs, "example.com", 1000), None);
    }

    #[test]
    fn test_prefer_exact_over_wildcard() {
        let certs = vec![
            make_cert("*.example.com", 2000, true, KeyType::Ecdsa),
            make_cert("foo.example.com", 2000, false, KeyType::Rsa),
        ];
        assert_eq!(select_cert(&certs, "foo.example.com", 1000), Some(1));
    }

    #[test]
    fn test_prefer_ecdsa() {
        let certs = vec![
            make_cert("example.com", 2000, false, KeyType::Rsa),
            make_cert("example.com", 2000, false, KeyType::Ecdsa),
        ];
        assert_eq!(select_cert(&certs, "example.com", 1000), Some(1));
    }

    #[test]
    fn test_prefer_longer_validity() {
        let certs = vec![
            make_cert("example.com", 2000, false, KeyType::Ecdsa),
            make_cert("example.com", 3000, false, KeyType::Ecdsa),
        ];
        assert_eq!(select_cert(&certs, "example.com", 1000), Some(1));
    }

    #[test]
    fn test_empty_candidates() {
        let certs: Vec<CertCandidate> = vec![];
        assert_eq!(select_cert(&certs, "example.com", 1000), None);
    }
}
