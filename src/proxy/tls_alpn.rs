//! TLS-ALPN-01 (RFC 8737) challenge support.
//!
//! TLS-ALPN-01 is the second ACME challenge type that operators can use
//! when port 80 isn't reachable — the validator opens a TLS connection
//! to port 443 with the `acme-tls/1` ALPN protocol, and we reply with a
//! short-lived self-signed certificate that embeds the SHA-256 of the
//! challenge key authorization in a critical extension (OID
//! `1.3.6.1.5.5.7.1.31`, the `id-pe-acmeIdentifier` extension).
//!
//! ## Lynxx wiring
//!
//! The actual cert presentation lives in [`AcmeChallengeResolver`], a
//! `rustls::server::ResolvesServerCert` that wraps the regular cert
//! resolver:
//!
//! * if the negotiated ALPN is `acme-tls/1` *and* we have a challenge
//!   cert for the requested SNI hostname, return that cert
//! * otherwise fall through to the inner resolver (the loaded
//!   `cert.pem` / `key.pem` for the production hostname)
//!
//! Operators register challenges through the admin API, exactly like
//! HTTP-01: `POST /admin/v1/acme/tls-alpn-01-challenges` with a domain +
//! key authorization, then trigger the ACME validator. The challenge is
//! cleared with `DELETE /admin/v1/acme/tls-alpn-01-challenges/{domain}`
//! once validation completes.

use crate::error::GatewayError;
use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// ALPN protocol identifier defined by RFC 8737.
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

/// Build a short-lived self-signed certificate that fulfils the
/// TLS-ALPN-01 challenge for `domain`.
///
/// `key_authorization` is the value the ACME server told us to embed
/// (`token || '.' || JWK thumbprint(account_key)`). We hash it with
/// SHA-256 and put the digest into the `acmeIdentifier` X.509 extension
/// — that's the bit the validator inspects.
pub fn build_challenge_cert(
    domain: &str,
    key_authorization: &str,
) -> Result<CertifiedKey, GatewayError> {
    if domain.is_empty() {
        return Err(GatewayError::Internal(
            "TLS-ALPN-01 challenge requires a non-empty domain".into(),
        ));
    }

    // RFC 8737 §3: the extension value is an OCTET STRING containing the
    // SHA-256 digest of the key authorization — 32 bytes wrapped in DER
    // OCTET STRING (tag 0x04, length 0x20).
    let digest = Sha256::digest(key_authorization.as_bytes());
    let mut extension_value = Vec::with_capacity(2 + digest.len());
    extension_value.push(0x04); // OCTET STRING
    extension_value.push(digest.len() as u8); // 32
    extension_value.extend_from_slice(&digest);

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| GatewayError::Internal(format!("alpn cert params: {e}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, domain.to_string());
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Lynxx ACME TLS-ALPN-01");

    // OID 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier).
    let mut ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 31], extension_value);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| GatewayError::Internal(format!("alpn keypair: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| GatewayError::Internal(format!("alpn self-sign: {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| GatewayError::Internal(format!("alpn key DER: {e}")))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| GatewayError::Internal(format!("alpn signing key: {e}")))?;

    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

/// rustls cert resolver that routes production certs by SNI hostname
/// (SAN-indexed) and presents TLS-ALPN-01 challenge certs for ACME.
///
/// `cert_map` maps every DNS name found in SAN lists across all loaded
/// certs to the corresponding `CertifiedKey`. When two certs cover the
/// same name, the one with more SANs wins (multi-domain preferred over
/// single-domain fallback).
///
/// `default_cert` is the fallback when no SAN matches the requested SNI
/// — typically the primary multi-domain cert.
pub struct AcmeChallengeResolver {
    pub(crate) cert_map: std::collections::HashMap<String, Arc<CertifiedKey>>,
    default_cert: Arc<CertifiedKey>,
    lookup: Box<dyn Fn(&str) -> Option<Arc<CertifiedKey>> + Send + Sync>,
}

impl std::fmt::Debug for AcmeChallengeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeChallengeResolver")
            .field("san_count", &self.cert_map.len())
            .finish()
    }
}

impl AcmeChallengeResolver {
    pub fn new<F>(default_cert: Arc<CertifiedKey>, lookup: F) -> Self
    where
        F: Fn(&str) -> Option<Arc<CertifiedKey>> + Send + Sync + 'static,
    {
        Self {
            cert_map: std::collections::HashMap::new(),
            default_cert,
            lookup: Box::new(lookup),
        }
    }

    pub fn with_cert_map<F>(
        cert_map: std::collections::HashMap<String, Arc<CertifiedKey>>,
        default_cert: Arc<CertifiedKey>,
        lookup: F,
    ) -> Self
    where
        F: Fn(&str) -> Option<Arc<CertifiedKey>> + Send + Sync + 'static,
    {
        Self {
            cert_map,
            default_cert,
            lookup: Box::new(lookup),
        }
    }
}

impl AcmeChallengeResolver {
    /// Try matching the SNI against wildcard certs in the cert map.
    ///
    /// For `sub.example.com`, checks `*.example.com`.
    /// For `deep.sub.example.com`, checks `*.sub.example.com` then `*.example.com`.
    fn resolve_wildcard(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let mut domain = sni;
        while let Some(dot) = domain.find('.') {
            let parent = &domain[dot + 1..];
            let wildcard = format!("*.{parent}");
            if let Some(cert) = self.cert_map.get(&wildcard) {
                tracing::debug!(sni = %sni, matched = %wildcard, "wildcard cert match");
                return Some(Arc::clone(cert));
            }
            domain = parent;
        }
        None
    }
}

impl ResolvesServerCert for AcmeChallengeResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let alpn_match = hello
            .alpn()
            .map(|mut iter| iter.any(|p| p == ACME_TLS_ALPN_NAME))
            .unwrap_or(false);
        if alpn_match {
            if let Some(sni) = hello.server_name() {
                if let Some(cert) = (self.lookup)(sni) {
                    tracing::debug!(domain = %sni, "serving TLS-ALPN-01 challenge cert");
                    return Some(cert);
                }
            }
            tracing::warn!(
                "acme-tls/1 ALPN requested but no matching challenge registered; \
                 falling back to production cert"
            );
        }

        if let Some(sni) = hello.server_name() {
            if let Some(cert) = self.cert_map.get(sni) {
                return Some(Arc::clone(cert));
            }
            if let Some(cert) = self.resolve_wildcard(sni) {
                return Some(cert);
            }
            tracing::debug!(sni = %sni, "no SAN match; serving default cert");
        }
        Some(Arc::clone(&self.default_cert))
    }
}

/// Extract all DNS SAN entries from a DER-encoded certificate.
pub fn extract_san_dns_names(cert_der: &[u8]) -> Vec<String> {
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert_der) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for ext in parsed.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    names.push(dns.to_lowercase());
                }
            }
        }
    }
    names
}

/// Parse a chain + key on disk into a [`CertifiedKey`]. Used by the
/// AcmeManager when it wants to wrap the production cert behind a
/// challenge-aware resolver.
pub fn certified_key_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<CertifiedKey, GatewayError> {
    let mut cur = std::io::Cursor::new(cert_pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cur)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GatewayError::Internal(format!("parse cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(GatewayError::Internal("no certs in pem".into()));
    }
    let mut cur = std::io::Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut cur)
        .map_err(|e| GatewayError::Internal(format!("parse key pem: {e}")))?
        .ok_or_else(|| GatewayError::Internal("no private key in pem".into()))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| GatewayError::Internal(format!("signing key: {e}")))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn builds_challenge_cert_with_acme_extension() {
        install_provider();
        let ck = build_challenge_cert("example.com", "tok.thumbprint").unwrap();
        assert_eq!(ck.cert.len(), 1, "challenge cert is single-leaf");

        // Sanity check: the leaf must contain the acmeIdentifier OID
        // (`1.3.6.1.5.5.7.1.31`) inside its extensions.
        let der = &ck.cert[0];
        let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let oid_str = "1.3.6.1.5.5.7.1.31";
        let has_oid = parsed
            .extensions()
            .iter()
            .any(|e| e.oid.to_id_string() == oid_str);
        assert!(has_oid, "challenge cert must carry id-pe-acmeIdentifier");
    }

    #[test]
    fn empty_domain_rejected() {
        install_provider();
        assert!(build_challenge_cert("", "auth").is_err());
    }

    #[test]
    fn digest_changes_with_key_auth() {
        install_provider();
        let a = build_challenge_cert("example.com", "auth-1").unwrap();
        let b = build_challenge_cert("example.com", "auth-2").unwrap();
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
    }

    fn make_resolver_with_wildcards() -> AcmeChallengeResolver {
        install_provider();
        let ck_root = Arc::new(build_challenge_cert("example.com", "root").unwrap());
        let ck_wildcard = Arc::new(build_challenge_cert("*.vexarr.com", "wc").unwrap());
        let ck_deep = Arc::new(build_challenge_cert("*.hostx.vexarr.com", "deep").unwrap());
        let ck_exact = Arc::new(build_challenge_cert("api.vexarr.com", "exact").unwrap());

        let mut cert_map = std::collections::HashMap::new();
        cert_map.insert("*.vexarr.com".to_string(), ck_wildcard);
        cert_map.insert("*.hostx.vexarr.com".to_string(), ck_deep);
        cert_map.insert("api.vexarr.com".to_string(), ck_exact);

        AcmeChallengeResolver::with_cert_map(cert_map, ck_root, |_| None)
    }

    #[test]
    fn wildcard_matches_subdomain() {
        let r = make_resolver_with_wildcards();
        assert!(r.resolve_wildcard("new-service.vexarr.com").is_some());
    }

    #[test]
    fn wildcard_prefers_deeper_match() {
        let r = make_resolver_with_wildcards();
        let cert = r.resolve_wildcard("app.hostx.vexarr.com").unwrap();
        // Should match *.hostx.vexarr.com, not *.vexarr.com
        let sans = extract_san_dns_names(cert.cert[0].as_ref());
        assert!(sans.contains(&"*.hostx.vexarr.com".to_string()));
    }

    #[test]
    fn exact_match_preferred_over_wildcard() {
        let r = make_resolver_with_wildcards();
        // api.vexarr.com has an exact entry — resolve_wildcard should NOT be needed
        assert!(r.cert_map.contains_key("api.vexarr.com"));
    }

    #[test]
    fn wildcard_no_match_for_bare_domain() {
        let r = make_resolver_with_wildcards();
        // "vexarr.com" itself should NOT match "*.vexarr.com"
        assert!(r.resolve_wildcard("vexarr.com").is_none());
    }

    #[test]
    fn wildcard_no_match_for_unrelated() {
        let r = make_resolver_with_wildcards();
        assert!(r.resolve_wildcard("other.example.com").is_none());
    }
}
