//! Built-in PKI / internal Certificate Authority.
//!
//! When enabled, the gateway acts as a private CA that can issue TLS
//! certificates for internal services — similar to Caddy's built-in
//! ACME server or Vault's PKI secrets engine, but zero-config.
//!
//! ## Architecture
//!
//! ```text
//! Root CA (self-signed, ECDSA P-256, 10-year validity)
//!   └─ Intermediate CA (signed by root, 5-year validity)
//!        └─ Leaf certs (signed by intermediate, configurable validity)
//! ```
//!
//! The root key never signs leaf certificates directly. Clients only
//! need the root CA in their trust store; the leaf cert's chain
//! includes the intermediate so verification works end-to-end.
//!
//! ## Storage layout
//!
//! ```text
//! ~/.lynxx/pki/
//!   root.pem              # Root CA certificate
//!   root-key.pem          # Root CA private key (mode 0600)
//!   intermediate.pem      # Intermediate CA certificate
//!   intermediate-key.pem  # Intermediate CA private key (mode 0600)
//! ```

use crate::config::PkiConfig;
use crate::error::GatewayError;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

/// A leaf certificate issued by the internal CA.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// PEM-encoded leaf certificate.
    pub cert_pem: String,
    /// PEM-encoded private key for the leaf certificate.
    pub key_pem: String,
    /// Full chain PEM: leaf + intermediate + root (for TLS handshake).
    pub chain_pem: String,
}

/// Internal PKI authority backed by an on-disk root + intermediate CA.
pub struct PkiAuthority {
    root_cert_pem: String,
    root_key_pem: String,
    intermediate_cert_pem: String,
    intermediate_key_pem: String,
    storage_dir: PathBuf,
    config: PkiConfig,
}

impl PkiAuthority {
    /// Load an existing CA from disk, or generate a brand-new root +
    /// intermediate pair if none exists. `storage_dir` overrides the
    /// config value when provided.
    pub async fn load_or_create(
        config: &PkiConfig,
        storage_dir: Option<&str>,
    ) -> Result<Self, GatewayError> {
        let dir = resolve_storage_dir(storage_dir.unwrap_or(&config.storage_dir));
        std::fs::create_dir_all(&dir).map_err(|e| {
            GatewayError::Internal(format!("create pki dir {}: {e}", dir.display()))
        })?;

        let root_cert_path = dir.join("root.pem");
        let root_key_path = dir.join("root-key.pem");
        let inter_cert_path = dir.join("intermediate.pem");
        let inter_key_path = dir.join("intermediate-key.pem");

        // If all four files exist, load from disk.
        if root_cert_path.exists()
            && root_key_path.exists()
            && inter_cert_path.exists()
            && inter_key_path.exists()
        {
            tracing::info!(dir = %dir.display(), "loading existing PKI from disk");
            let root_cert_pem = read_file(&root_cert_path)?;
            let root_key_pem = read_file(&root_key_path)?;
            let inter_cert_pem = read_file(&inter_cert_path)?;
            let inter_key_pem = read_file(&inter_key_path)?;

            // Validate that the loaded PEMs parse correctly.
            validate_pem_keypair(&root_cert_pem, &root_key_pem, "root")?;
            validate_pem_keypair(&inter_cert_pem, &inter_key_pem, "intermediate")?;

            return Ok(Self {
                root_cert_pem,
                root_key_pem,
                intermediate_cert_pem: inter_cert_pem,
                intermediate_key_pem: inter_key_pem,
                storage_dir: dir,
                config: config.clone(),
            });
        }

        // Generate fresh CA hierarchy.
        tracing::info!(
            dir = %dir.display(),
            cn = %config.root_cn,
            "generating new PKI root + intermediate CA"
        );

        let (root_cert_pem, root_key_pem) = generate_root_ca(&config.root_cn)?;
        let (inter_cert_pem, inter_key_pem) =
            generate_intermediate_ca(&root_cert_pem, &root_key_pem, &config.root_cn)?;

        // Persist to disk.
        write_pem(&root_cert_path, &root_cert_pem)?;
        write_key(&root_key_path, &root_key_pem)?;
        write_pem(&inter_cert_path, &inter_cert_pem)?;
        write_key(&inter_key_path, &inter_key_pem)?;

        tracing::info!(
            root = %root_cert_path.display(),
            intermediate = %inter_cert_path.display(),
            "PKI CA written to disk"
        );

        Ok(Self {
            root_cert_pem,
            root_key_pem,
            intermediate_cert_pem: inter_cert_pem,
            intermediate_key_pem: inter_key_pem,
            storage_dir: dir,
            config: config.clone(),
        })
    }

    /// Issue a leaf certificate for the given domain names, valid for
    /// `days` days. The certificate is signed by the intermediate CA.
    pub fn issue_cert(&self, domains: &[String], days: u32) -> Result<IssuedCert, GatewayError> {
        if domains.is_empty() {
            return Err(GatewayError::ConfigError(
                "pki: at least one domain is required".into(),
            ));
        }

        let validity = if days == 0 {
            self.config.default_validity_days
        } else {
            days
        };

        // Parse the intermediate CA so rcgen can sign the leaf.
        let inter_key = KeyPair::from_pem(&self.intermediate_key_pem)
            .map_err(|e| GatewayError::Internal(format!("parse intermediate key: {e}")))?;
        let inter_params = CertificateParams::from_ca_cert_pem(&self.intermediate_cert_pem)
            .map_err(|e| GatewayError::Internal(format!("parse intermediate cert: {e}")))?;
        let inter_cert = inter_params
            .self_signed(&inter_key)
            .map_err(|e| GatewayError::Internal(format!("reconstruct intermediate cert: {e}")))?;

        // Build leaf params.
        let mut leaf_params = CertificateParams::new(domains.to_vec())
            .map_err(|e| GatewayError::Internal(format!("leaf cert params: {e}")))?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, domains[0].clone());
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "Lynxx PKI");
        leaf_params.not_before = OffsetDateTime::now_utc();
        leaf_params.not_after = OffsetDateTime::now_utc() + Duration::days(i64::from(validity));
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| GatewayError::Internal(format!("generate leaf key: {e}")))?;

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_cert, &inter_key)
            .map_err(|e| GatewayError::Internal(format!("sign leaf cert: {e}")))?;

        let cert_pem = leaf_cert.pem();
        let key_pem = leaf_key.serialize_pem();
        let chain_pem = format!(
            "{}\n{}\n{}",
            cert_pem.trim(),
            self.intermediate_cert_pem.trim(),
            self.root_cert_pem.trim()
        );

        Ok(IssuedCert {
            cert_pem,
            key_pem,
            chain_pem,
        })
    }

    /// Return the root CA certificate PEM so clients can add it to
    /// their trust store.
    pub fn root_ca_pem(&self) -> String {
        self.root_cert_pem.clone()
    }

    /// Return the full CA chain PEM (intermediate + root).
    pub fn ca_chain_pem(&self) -> String {
        format!(
            "{}\n{}",
            self.intermediate_cert_pem.trim(),
            self.root_cert_pem.trim()
        )
    }

    /// The directory where CA material is stored.
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }
}

// ======================================================================
// CA generation helpers
// ======================================================================

/// Generate a self-signed root CA certificate + key (ECDSA P-256).
/// Validity: 10 years.
fn generate_root_ca(cn: &str) -> Result<(String, String), GatewayError> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Lynxx PKI");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| GatewayError::Internal(format!("generate root key: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| GatewayError::Internal(format!("self-sign root CA: {e}")))?;

    Ok((cert.pem(), key.serialize_pem()))
}

/// Generate an intermediate CA signed by the root. Validity: 5 years.
fn generate_intermediate_ca(
    root_cert_pem: &str,
    root_key_pem: &str,
    root_cn: &str,
) -> Result<(String, String), GatewayError> {
    // Reconstruct the root CA for signing.
    let root_key = KeyPair::from_pem(root_key_pem)
        .map_err(|e| GatewayError::Internal(format!("parse root key: {e}")))?;
    let root_params = CertificateParams::from_ca_cert_pem(root_cert_pem)
        .map_err(|e| GatewayError::Internal(format!("parse root cert: {e}")))?;
    let root_cert = root_params
        .self_signed(&root_key)
        .map_err(|e| GatewayError::Internal(format!("reconstruct root cert: {e}")))?;

    // Build the intermediate.
    let inter_cn = format!("{root_cn} Intermediate");
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, &inter_cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Lynxx PKI");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(1825);

    let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| GatewayError::Internal(format!("generate intermediate key: {e}")))?;
    let inter_cert = params
        .signed_by(&inter_key, &root_cert, &root_key)
        .map_err(|e| GatewayError::Internal(format!("sign intermediate CA: {e}")))?;

    Ok((inter_cert.pem(), inter_key.serialize_pem()))
}

// ======================================================================
// I/O helpers
// ======================================================================

/// Resolve the storage directory. Falls back to `~/.lynxx/pki/` when
/// the provided string is empty.
fn resolve_storage_dir(configured: &str) -> PathBuf {
    if configured.is_empty() {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/var/lib/lynxx"))
            .join(".lynxx")
            .join("pki")
    } else {
        PathBuf::from(configured)
    }
}

fn read_file(path: &Path) -> Result<String, GatewayError> {
    std::fs::read_to_string(path)
        .map_err(|e| GatewayError::Internal(format!("read {}: {e}", path.display())))
}

fn write_pem(path: &Path, contents: &str) -> Result<(), GatewayError> {
    std::fs::write(path, contents.as_bytes())
        .map_err(|e| GatewayError::Internal(format!("write {}: {e}", path.display())))
}

fn write_key(path: &Path, contents: &str) -> Result<(), GatewayError> {
    std::fs::write(path, contents.as_bytes())
        .map_err(|e| GatewayError::Internal(format!("write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Validate that a PEM cert + key pair can be parsed. Used on load to
/// fail fast with a clear error rather than a cryptic signing failure
/// later.
fn validate_pem_keypair(cert_pem: &str, key_pem: &str, label: &str) -> Result<(), GatewayError> {
    let _key = KeyPair::from_pem(key_pem)
        .map_err(|e| GatewayError::Internal(format!("invalid {label} key PEM: {e}")))?;
    let _params = CertificateParams::from_ca_cert_pem(cert_pem)
        .map_err(|e| GatewayError::Internal(format!("invalid {label} cert PEM: {e}")))?;
    Ok(())
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PkiConfig {
        PkiConfig {
            enabled: true,
            storage_dir: String::new(),
            root_cn: "Lynxx Test CA".to_string(),
            default_validity_days: 90,
        }
    }

    #[test]
    fn test_resolve_storage_dir_default() {
        let dir = resolve_storage_dir("");
        assert!(
            dir.to_string_lossy().contains("pki"),
            "default dir should contain 'pki', got: {}",
            dir.display()
        );
    }

    #[test]
    fn test_resolve_storage_dir_custom() {
        let dir = resolve_storage_dir("/custom/pki");
        assert_eq!(dir, PathBuf::from("/custom/pki"));
    }

    #[test]
    fn test_generate_root_ca() {
        let (cert_pem, key_pem) = generate_root_ca("Test Root CA").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));

        // Should be parseable by x509-parser.
        let der = pem_to_der(&cert_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let cn = parsed.subject().to_string();
        assert!(cn.contains("Test Root CA"), "CN mismatch: {cn}");
        assert!(parsed.is_ca(), "root should be a CA");
    }

    #[test]
    fn test_generate_intermediate_ca() {
        let (root_cert, root_key) = generate_root_ca("Test Root").unwrap();
        let (inter_cert, inter_key) =
            generate_intermediate_ca(&root_cert, &root_key, "Test Root").unwrap();

        assert!(inter_cert.contains("BEGIN CERTIFICATE"));
        assert!(inter_key.contains("BEGIN PRIVATE KEY"));

        let der = pem_to_der(&inter_cert);
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let cn = parsed.subject().to_string();
        assert!(
            cn.contains("Test Root Intermediate"),
            "intermediate CN mismatch: {cn}"
        );
        assert!(parsed.is_ca(), "intermediate should be a CA");

        // Issuer should be the root.
        let issuer = parsed.issuer().to_string();
        assert!(
            issuer.contains("Test Root"),
            "intermediate issuer mismatch: {issuer}"
        );
    }

    #[tokio::test]
    async fn test_load_or_create_generates_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();

        // Files should exist.
        assert!(tmp.path().join("root.pem").exists());
        assert!(tmp.path().join("root-key.pem").exists());
        assert!(tmp.path().join("intermediate.pem").exists());
        assert!(tmp.path().join("intermediate-key.pem").exists());

        // Key files should have restricted permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tmp.path().join("root-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "root key should be mode 0600");
        }

        // root_ca_pem should be non-empty and valid.
        let root_pem = pki.root_ca_pem();
        assert!(root_pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_load_or_create_reloads_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        // First run: generate.
        let pki1 = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let root1 = pki1.root_ca_pem();

        // Second run: should load from disk, same root cert.
        let pki2 = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let root2 = pki2.root_ca_pem();

        assert_eq!(root1, root2, "reload should return the same root CA");
    }

    #[tokio::test]
    async fn test_issue_cert_single_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let issued = pki
            .issue_cert(&["api.internal.local".to_string()], 30)
            .unwrap();

        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(issued
            .chain_pem
            .contains(&issued.cert_pem.trim().to_string()));

        // Parse the leaf and verify SAN + issuer.
        let der = pem_to_der(&issued.cert_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(!parsed.is_ca(), "leaf should not be a CA");

        let cn = parsed.subject().to_string();
        assert!(cn.contains("api.internal.local"), "leaf CN mismatch: {cn}");

        // Issuer should be the intermediate.
        let issuer = parsed.issuer().to_string();
        assert!(
            issuer.contains("Intermediate"),
            "leaf issuer should be intermediate, got: {issuer}"
        );

        // Check SAN.
        let san = parsed
            .subject_alternative_name()
            .ok()
            .flatten()
            .expect("leaf should have SAN");
        let dns_names: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| {
                if let x509_parser::prelude::GeneralName::DNSName(dns) = gn {
                    Some(dns.to_string())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            dns_names.contains(&"api.internal.local".to_string()),
            "SAN should contain the domain, got: {dns_names:?}"
        );
    }

    #[tokio::test]
    async fn test_issue_cert_multiple_domains() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let domains = vec![
            "app.internal".to_string(),
            "api.internal".to_string(),
            "admin.internal".to_string(),
        ];
        let issued = pki.issue_cert(&domains, 365).unwrap();

        let der = pem_to_der(&issued.cert_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();

        let san = parsed
            .subject_alternative_name()
            .ok()
            .flatten()
            .expect("leaf should have SAN");
        let dns_names: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| {
                if let x509_parser::prelude::GeneralName::DNSName(dns) = gn {
                    Some(dns.to_string())
                } else {
                    None
                }
            })
            .collect();
        for d in &domains {
            assert!(
                dns_names.contains(d),
                "SAN should contain {d}, got: {dns_names:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_issue_cert_empty_domains_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let result = pki.issue_cert(&[], 30);
        assert!(result.is_err(), "empty domains should fail");
    }

    #[tokio::test]
    async fn test_issue_cert_default_validity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();
        cfg.default_validity_days = 45;

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let issued = pki.issue_cert(&["svc.internal".to_string()], 0).unwrap();

        let der = pem_to_der(&issued.cert_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        let actual_days = (not_after - not_before) / 86400;
        // Allow 1-day tolerance for clock edge.
        assert!(
            (44..=46).contains(&actual_days),
            "expected ~45 day validity, got {actual_days}"
        );
    }

    #[tokio::test]
    async fn test_ca_chain_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let chain = pki.ca_chain_pem();

        // Chain should contain both intermediate and root certs.
        let cert_count = chain.matches("BEGIN CERTIFICATE").count();
        assert_eq!(
            cert_count, 2,
            "chain should have 2 certs (intermediate + root)"
        );
        assert!(chain.contains(pki.root_ca_pem().trim()));
    }

    #[tokio::test]
    async fn test_issued_chain_validates_against_root() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.storage_dir = tmp.path().to_string_lossy().into_owned();

        let pki = PkiAuthority::load_or_create(&cfg, None).await.unwrap();
        let issued = pki
            .issue_cert(&["verify.internal".to_string()], 30)
            .unwrap();

        // Parse all certs from the chain.
        let chain_certs = parse_pem_chain(&issued.chain_pem);
        assert_eq!(
            chain_certs.len(),
            3,
            "chain should have leaf + intermediate + root"
        );

        // Verify the leaf was signed by the intermediate (issuer DN match).
        let (_, leaf) = x509_parser::parse_x509_certificate(&chain_certs[0]).unwrap();
        let (_, inter) = x509_parser::parse_x509_certificate(&chain_certs[1]).unwrap();
        let (_, root) = x509_parser::parse_x509_certificate(&chain_certs[2]).unwrap();

        assert_eq!(
            leaf.issuer(),
            inter.subject(),
            "leaf issuer should match intermediate subject"
        );
        assert_eq!(
            inter.issuer(),
            root.subject(),
            "intermediate issuer should match root subject"
        );
        assert_eq!(root.issuer(), root.subject(), "root should be self-signed");
    }

    #[tokio::test]
    async fn test_storage_dir_override() {
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("custom");
        let cfg = test_config();

        let pki = PkiAuthority::load_or_create(&cfg, Some(override_dir.to_str().unwrap()))
            .await
            .unwrap();

        assert_eq!(pki.storage_dir(), override_dir);
        assert!(override_dir.join("root.pem").exists());
    }

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    /// Extract the first DER certificate from a PEM string.
    fn pem_to_der(pem: &str) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .expect("valid PEM");
        assert!(!certs.is_empty(), "PEM should contain at least one cert");
        certs[0].to_vec()
    }

    /// Parse all certificates from a PEM chain string.
    fn parse_pem_chain(pem: &str) -> Vec<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .expect("valid PEM chain")
            .into_iter()
            .map(|c| c.to_vec())
            .collect()
    }
}
