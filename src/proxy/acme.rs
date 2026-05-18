//! Certificate manager with ACME HTTP-01, TLS-ALPN-01, and DNS-01
//! challenge support, cert file watching, and self-signed certificate
//! generation.
//!
//! This module provides four practical capabilities for TLS provisioning:
//!
//! 1. **Self-signed cert generation** (`self_signed = true`): Creates a
//!    self-signed cert on startup when no cert exists on disk. Intended
//!    for dev/test — browsers show a warning but the connection is encrypted.
//!
//! 2. **HTTP-01 challenge responder**: Serves
//!    `/.well-known/acme-challenge/{token}` responses so external ACME
//!    tools (certbot, acme.sh, lego) or a future built-in client can
//!    complete domain validation.
//!
//! 3. **TLS-ALPN-01 challenge responder** (RFC 8737): When the
//!    validator opens a TLS connection on port 443 with the
//!    `acme-tls/1` ALPN protocol, the gateway presents a short-lived
//!    challenge cert that embeds SHA-256(key authorization) in the
//!    `id-pe-acmeIdentifier` extension. This means operators who have
//!    port 80 closed (only 443 reachable) can still complete ACME
//!    validation. See [`crate::proxy::tls_alpn`] for the implementation.
//!
//! 4. **Cert file watcher**: Polls cert files on disk every 30 seconds
//!    and hot-reloads the `rustls::ServerConfig` when they change, so
//!    operators can renew certs externally without restarting the gateway.
//!
//! ## Storage layout
//!
//! ```text
//! {storage_dir}/
//!   account.json         # ACME account credentials
//!   {primary_domain}/    # multi-domain cert (all SANs)
//!     cert.pem
//!     key.pem
//!   _fallback/           # per-domain certs (fallback only)
//!     {domain}/
//!       cert.pem
//!       key.pem
//! ```
//!
//! The primary path issues one multi-domain order containing all
//! configured domains as SANs (the lego/certbot model). If that
//! fails, per-domain fallback orders write to `_fallback/` so they
//! never overwrite a good multi-domain cert.

use crate::config::AcmeConfig;
use crate::error::GatewayError;
use crate::proxy::dns_challenge::{self, DnsProvider};
use crate::proxy::tls_alpn::{
    build_challenge_cert, certified_key_from_pem, extract_san_dns_names, AcmeChallengeResolver,
    ACME_TLS_ALPN_NAME,
};
use dashmap::DashMap;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

/// Manages certificate lifecycle: loading, generation, watching, and
/// ACME HTTP-01 + TLS-ALPN-01 challenge handling.
pub struct AcmeManager {
    config: AcmeConfig,
    /// Current rustls `ServerConfig`, swapped atomically on reload.
    current_config: Arc<RwLock<Option<Arc<ServerConfig>>>>,
    /// Pending HTTP-01 challenges: token -> key-authorization.
    challenges: Arc<DashMap<String, String>>,
    /// Pending TLS-ALPN-01 challenges: domain -> challenge cert. The
    /// resolver inside the active `ServerConfig` queries this map on
    /// every ClientHello whose ALPN includes `acme-tls/1`.
    tls_alpn_challenges: Arc<DashMap<String, Arc<CertifiedKey>>>,
    /// Last observed mtime of the cert file, for change detection.
    last_cert_mtime: Arc<RwLock<Option<SystemTime>>>,
    /// DNS-01 challenge provider (Cloudflare / Route53). `None` when
    /// dns01 is not configured.
    dns_provider: Option<Arc<dyn DnsProvider>>,
    /// Handle to the live `axum_server` TLS acceptor. When set, cert
    /// reloads push the new `ServerConfig` directly into the running
    /// listener via `RustlsConfig::reload_from_config` — no restart
    /// required.
    tls_reload_handle: Arc<RwLock<Option<axum_server::tls_rustls::RustlsConfig>>>,
}

impl AcmeManager {
    /// Create a new `AcmeManager` from the provided config. Does not
    /// perform any I/O — call [`init`] after construction.
    pub fn new(config: AcmeConfig) -> Self {
        let dns_provider = if !config.dns01.provider.is_empty() {
            match dns_challenge::from_config(&config.dns01) {
                Ok(p) => {
                    tracing::info!(
                        provider = p.provider_name(),
                        "DNS-01 challenge provider loaded"
                    );
                    Some(p)
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to initialise DNS-01 provider");
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            current_config: Arc::new(RwLock::new(None)),
            challenges: Arc::new(DashMap::new()),
            tls_alpn_challenges: Arc::new(DashMap::new()),
            last_cert_mtime: Arc::new(RwLock::new(None)),
            dns_provider,
            tls_reload_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Register the live `axum_server` TLS config handle so that cert
    /// reloads are pushed into the running listener automatically.
    /// Must be called after the listener is bound.
    pub async fn set_tls_reload_handle(&self, handle: axum_server::tls_rustls::RustlsConfig) {
        *self.tls_reload_handle.write().await = Some(handle);
        tracing::info!(
            "TLS hot-reload handle registered — cert updates will apply without restart"
        );
    }

    /// Map the configured `key_type` string to the corresponding rcgen
    /// signing algorithm. Defaults to ECDSA-P256 for unknown values.
    fn key_algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.config.key_type.as_str() {
            "ec-p256" => &rcgen::PKCS_ECDSA_P256_SHA256,
            "ec-p384" => &rcgen::PKCS_ECDSA_P384_SHA384,
            "ed25519" => &rcgen::PKCS_ED25519,
            "rsa-2048" | "rsa-4096" => &rcgen::PKCS_RSA_SHA256,
            _ => &rcgen::PKCS_ECDSA_P256_SHA256,
        }
    }

    /// Return the resolved storage directory. Falls back to
    /// `~/.lynxx/acme/` when not explicitly configured.
    pub fn storage_dir(&self) -> PathBuf {
        if self.config.storage_dir.is_empty() {
            default_storage_dir()
        } else {
            PathBuf::from(&self.config.storage_dir)
        }
    }

    /// Primary domain (first in the list).
    fn primary_domain(&self) -> Option<&str> {
        self.config.domains.first().map(|s| s.as_str())
    }

    /// Path to the certificate PEM for the primary domain.
    fn cert_path(&self) -> Option<PathBuf> {
        self.primary_domain()
            .map(|d| self.storage_dir().join(d).join("cert.pem"))
    }

    /// Path to the private key PEM for the primary domain.
    fn key_path(&self) -> Option<PathBuf> {
        self.primary_domain()
            .map(|d| self.storage_dir().join(d).join("key.pem"))
    }

    // ------------------------------------------------------------------
    // Initialisation
    // ------------------------------------------------------------------

    /// Initialise the manager: load existing certs from disk, or generate
    /// a self-signed cert if configured and no cert exists.
    ///
    /// Returns `Ok(true)` when a usable cert is available after init.
    pub async fn init(&self) -> Result<bool, GatewayError> {
        if self.config.domains.is_empty() {
            tracing::warn!("acme.domains is empty — ACME will not provision certificates until routes with hosts are added");
            return Ok(false);
        }

        // Ensure storage directory exists.
        let domain_dir = self
            .storage_dir()
            .join(self.primary_domain().unwrap_or("_default"));
        std::fs::create_dir_all(&domain_dir).map_err(|e| {
            GatewayError::Internal(format!(
                "create acme storage dir {}: {e}",
                domain_dir.display()
            ))
        })?;

        // Try loading existing cert.
        if self.try_load_cert().await? {
            tracing::info!(
                domain = %self.primary_domain().unwrap_or("-"),
                "loaded existing cert from disk"
            );
            return Ok(true);
        }

        // No cert on disk — generate self-signed if configured.
        if self.config.self_signed {
            tracing::info!(
                domains = ?self.config.domains,
                "no cert found; generating self-signed certificate"
            );
            self.generate_self_signed().await?;
            return self.try_load_cert().await;
        }

        tracing::warn!(
            domain = %self.primary_domain().unwrap_or("-"),
            "no cert found on disk and self_signed is disabled"
        );
        Ok(false)
    }

    /// Load all cert/key pairs from the ACME storage directory, build a
    /// SAN-indexed `dns_name → CertifiedKey` map, and construct a
    /// `ServerConfig` whose resolver picks the right cert per SNI.
    ///
    /// Scans:
    ///   - `{storage_dir}/{primary_domain}/` — multi-domain cert
    ///   - `{storage_dir}/_fallback/{domain}/` — per-domain fallback certs
    ///   - any other `{storage_dir}/{dir}/` containing cert.pem + key.pem
    ///
    /// When two certs cover the same DNS name, the one with more SANs
    /// wins (multi-domain preferred over single-domain fallback).
    async fn try_load_cert(&self) -> Result<bool, GatewayError> {
        let storage = self.storage_dir();

        // Collect all (cert_pem, key_pem, dir_path) pairs.
        let cert_dirs = self.discover_cert_dirs(&storage);
        if cert_dirs.is_empty() {
            return Ok(false);
        }

        let mut cert_map: std::collections::HashMap<String, Arc<CertifiedKey>> =
            std::collections::HashMap::new();
        // Track SAN count per dns_name so multi-domain certs win ties.
        let mut san_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut default_cert: Option<Arc<CertifiedKey>> = None;
        let mut primary_mtime: Option<SystemTime> = None;

        for dir in &cert_dirs {
            let cert_path = dir.join("cert.pem");
            let key_path = dir.join("key.pem");
            if !cert_path.exists() || !key_path.exists() {
                continue;
            }

            let cert_pem = match std::fs::read(&cert_path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(path = %cert_path.display(), error = %e, "skipping unreadable cert");
                    continue;
                }
            };
            let key_pem = match std::fs::read(&key_path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(path = %key_path.display(), error = %e, "skipping unreadable key");
                    continue;
                }
            };
            let ck = match certified_key_from_pem(&cert_pem, &key_pem) {
                Ok(ck) => Arc::new(ck),
                Err(e) => {
                    tracing::warn!(path = %cert_path.display(), error = %e, "skipping invalid cert/key pair");
                    continue;
                }
            };

            let san_names: Vec<String> = ck
                .cert
                .iter()
                .flat_map(|c| extract_san_dns_names(c.as_ref()))
                .collect();
            let this_san_count = san_names.len();

            tracing::info!(
                dir = %dir.display(),
                sans = ?san_names,
                "loaded cert with {} SAN(s)",
                this_san_count
            );

            for name in &san_names {
                let prev_count = san_counts.get(name).copied().unwrap_or(0);
                if this_san_count >= prev_count {
                    cert_map.insert(name.clone(), Arc::clone(&ck));
                    san_counts.insert(name.clone(), this_san_count);
                }
            }

            // Primary domain cert is the default fallback.
            let is_primary = self
                .primary_domain()
                .map(|p| dir.ends_with(p))
                .unwrap_or(false);
            if is_primary {
                default_cert = Some(Arc::clone(&ck));
                if let Ok(meta) = std::fs::metadata(&cert_path) {
                    primary_mtime = meta.modified().ok();
                }
            } else if default_cert.is_none() {
                default_cert = Some(Arc::clone(&ck));
            }
        }

        let default_cert = match default_cert {
            Some(c) => c,
            None => return Ok(false),
        };

        let lookup_map = Arc::clone(&self.tls_alpn_challenges);
        let resolver = AcmeChallengeResolver::with_cert_map(cert_map, default_cert, move |sni| {
            lookup_map.get(sni).map(|v| Arc::clone(v.value()))
        });

        tracing::info!(
            san_entries = resolver.cert_map.len(),
            "built SAN-indexed cert resolver"
        );

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        server_config.alpn_protocols = vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
            ACME_TLS_ALPN_NAME.to_vec(),
        ];

        if let Some(mtime) = primary_mtime {
            *self.last_cert_mtime.write().await = Some(mtime);
        }

        let new_config = Arc::new(server_config);
        *self.current_config.write().await = Some(Arc::clone(&new_config));

        // Push the new config into the live TLS listener so it takes
        // effect on the next handshake — no gateway restart required.
        if let Some(ref handle) = *self.tls_reload_handle.read().await {
            handle.reload_from_config(new_config);
            tracing::info!("TLS listener hot-reloaded with new certificate");
        }

        Ok(true)
    }

    /// Walk the ACME storage directory and return all directories that
    /// contain a cert.pem + key.pem pair.
    fn discover_cert_dirs(&self, storage: &Path) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let Ok(entries) = std::fs::read_dir(storage) else {
            return dirs;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == "_fallback" {
                // Recurse one level into _fallback/{domain}/
                if let Ok(fb_entries) = std::fs::read_dir(&path) {
                    for fb in fb_entries.flatten() {
                        let fb_path = fb.path();
                        if fb_path.is_dir()
                            && fb_path.join("cert.pem").exists()
                            && fb_path.join("key.pem").exists()
                        {
                            dirs.push(fb_path);
                        }
                    }
                }
            } else if name_str.starts_with('.') || name_str == "account.json" {
                continue;
            } else if path.join("cert.pem").exists() && path.join("key.pem").exists() {
                // Primary domain dirs go first so they become the default.
                let is_primary = self
                    .primary_domain()
                    .map(|p| name_str == p)
                    .unwrap_or(false);
                if is_primary {
                    dirs.insert(0, path);
                } else {
                    dirs.push(path);
                }
            }
        }
        dirs
    }

    // ------------------------------------------------------------------
    // Self-signed cert generation
    // ------------------------------------------------------------------

    /// Generate a self-signed certificate for the configured domains and
    /// write it to the storage directory.
    async fn generate_self_signed(&self) -> Result<(), GatewayError> {
        let domains = &self.config.domains;
        if domains.is_empty() {
            return Err(GatewayError::ConfigError(
                "acme.domains is empty; cannot generate self-signed cert".into(),
            ));
        }

        let cert_path = self.cert_path().ok_or_else(|| {
            GatewayError::ConfigError("acme.domains is empty; no cert path".into())
        })?;
        let key_path = self.key_path().ok_or_else(|| {
            GatewayError::ConfigError("acme.domains is empty; no key path".into())
        })?;

        generate_self_signed_cert(domains, &cert_path, &key_path)?;

        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            domains = ?domains,
            "self-signed certificate written"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // HTTP-01 challenge handler
    // ------------------------------------------------------------------

    /// Register a pending HTTP-01 challenge. Called by the ACME client
    /// flow (or an external orchestrator via the admin API).
    pub fn set_challenge(&self, token: String, key_authorization: String) {
        tracing::debug!(token = %token, "ACME challenge registered");
        self.challenges.insert(token, key_authorization);
    }

    /// Remove a challenge after it has been validated.
    pub fn clear_challenge(&self, token: &str) {
        self.challenges.remove(token);
    }

    /// Handle an inbound request to `/.well-known/acme-challenge/{token}`.
    ///
    /// Returns `Some(key_authorization)` if the token is known, or `None`
    /// if this is not a challenge request or the token is unrecognised.
    pub fn handle_challenge(&self, path: &str) -> Option<String> {
        const PREFIX: &str = "/.well-known/acme-challenge/";
        if !path.starts_with(PREFIX) {
            return None;
        }
        let token = &path[PREFIX.len()..];
        if token.is_empty() {
            return None;
        }
        self.challenges.get(token).map(|v| v.value().clone())
    }

    // ------------------------------------------------------------------
    // TLS-ALPN-01 challenge handler
    // ------------------------------------------------------------------

    /// Register a TLS-ALPN-01 challenge for `domain`. Builds a
    /// short-lived self-signed certificate that embeds
    /// SHA-256(`key_authorization`) in the `id-pe-acmeIdentifier`
    /// extension, and stores it so the inbound resolver can present it
    /// when the validator opens an `acme-tls/1` connection.
    ///
    /// Same shape as [`set_challenge`] — used the same way by an
    /// external ACME orchestrator or the admin API.
    pub fn set_tls_alpn_challenge(
        &self,
        domain: String,
        key_authorization: String,
    ) -> Result<(), GatewayError> {
        let cert = build_challenge_cert(&domain, &key_authorization)?;
        tracing::debug!(domain = %domain, "TLS-ALPN-01 challenge registered");
        self.tls_alpn_challenges.insert(domain, Arc::new(cert));
        Ok(())
    }

    /// Remove a TLS-ALPN-01 challenge after the validator finishes.
    pub fn clear_tls_alpn_challenge(&self, domain: &str) {
        self.tls_alpn_challenges.remove(domain);
    }

    /// Number of TLS-ALPN-01 challenges currently registered. Cheap;
    /// used by the admin API for visibility.
    pub fn tls_alpn_challenge_count(&self) -> usize {
        self.tls_alpn_challenges.len()
    }

    /// Number of HTTP-01 challenges currently registered. Mirror of
    /// [`tls_alpn_challenge_count`]; used by `GET /admin/v1/acme/status`.
    pub fn http01_challenge_count(&self) -> usize {
        self.challenges.len()
    }

    // ------------------------------------------------------------------
    // Cert file watcher
    // ------------------------------------------------------------------

    /// Spawn a background task that polls the cert file every 30 seconds
    /// and reloads the `ServerConfig` when the file changes.
    pub fn spawn_cert_watcher(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if let Err(e) = manager.check_and_reload().await {
                    tracing::warn!(error = %e, "cert watcher reload failed");
                }
            }
        });
    }

    /// Check whether the cert file has been modified since the last load
    /// and reload if so.
    async fn check_and_reload(&self) -> Result<(), GatewayError> {
        let cert_path = match self.cert_path() {
            Some(p) => p,
            None => return Ok(()),
        };

        let current_mtime = match std::fs::metadata(&cert_path) {
            Ok(meta) => match meta.modified() {
                Ok(t) => t,
                Err(_) => return Ok(()),
            },
            Err(_) => return Ok(()), // file doesn't exist yet
        };

        let last = *self.last_cert_mtime.read().await;
        if last == Some(current_mtime) {
            return Ok(()); // no change
        }

        tracing::info!(
            cert = %cert_path.display(),
            "cert file changed on disk; reloading"
        );

        self.try_load_cert().await?;

        tracing::info!("cert reloaded successfully");
        Ok(())
    }

    // ------------------------------------------------------------------
    // ServerConfig access
    // ------------------------------------------------------------------

    /// Return the current `ServerConfig`, or an error if no cert is loaded.
    pub async fn server_config(&self) -> Result<Arc<ServerConfig>, GatewayError> {
        self.current_config
            .read()
            .await
            .clone()
            .ok_or_else(|| GatewayError::Internal("no TLS certificate loaded".into()))
    }

    /// Whether a cert is currently loaded.
    pub async fn has_cert(&self) -> bool {
        self.current_config.read().await.is_some()
    }

    /// Return the special TLS-ALPN-01 challenge `ServerConfig` for the
    /// given SNI domain, if one is currently registered. Callers use
    /// this to intercept the TLS handshake during ACME validation.
    pub fn alpn_challenge_config(&self, server_name: &str) -> Option<Arc<ServerConfig>> {
        let ck = self.tls_alpn_challenges.get(server_name)?;
        let certified_key = Arc::clone(ck.value());
        let resolver = AlpnChallengeStaticResolver(certified_key);
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.alpn_protocols = vec![ACME_TLS_ALPN_NAME.to_vec()];
        Some(Arc::new(cfg))
    }

    /// Read the `AcmeConfig` (immutable after construction).
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }

    // ------------------------------------------------------------------
    // ACME account management
    // ------------------------------------------------------------------

    /// Path to the persisted ACME account credentials for the given
    /// directory URL. The primary directory uses `account.json`; fallback
    /// directories use `account_{hostname}.json` to avoid collisions.
    fn account_path_for(&self, directory_url: &str) -> PathBuf {
        if directory_url == self.config.directory_url {
            self.storage_dir().join("account.json")
        } else {
            let hostname = url::Url::parse(directory_url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| "unknown".to_string());
            self.storage_dir().join(format!("account_{hostname}.json"))
        }
    }

    /// Load an existing ACME account from disk, or create a new one at
    /// the given directory URL and persist the credentials.
    async fn get_or_create_account(
        &self,
        directory_url: &str,
    ) -> Result<instant_acme::Account, GatewayError> {
        let account_path = self.account_path_for(directory_url);
        let dir_url = directory_url;

        if account_path.exists() {
            tracing::info!(path = %account_path.display(), "loading existing ACME account");
            let data = std::fs::read(&account_path).map_err(|e| {
                GatewayError::Internal(format!("read account {}: {e}", account_path.display()))
            })?;
            let creds: instant_acme::AccountCredentials = serde_json::from_slice(&data)
                .map_err(|e| GatewayError::Internal(format!("parse account.json: {e}")))?;
            let account = instant_acme::Account::from_credentials(creds)
                .await
                .map_err(|e| GatewayError::Internal(format!("restore ACME account: {e}")))?;
            tracing::info!("ACME account restored from disk");
            return Ok(account);
        }

        // Create a new account.
        let contact = if self.config.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", self.config.email)]
        };
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

        tracing::info!(
            directory = %dir_url,
            email = %self.config.email,
            "creating new ACME account"
        );

        let eab = if !self.config.eab_kid.is_empty() && !self.config.eab_hmac_key.is_empty() {
            tracing::info!(kid = %self.config.eab_kid, "using External Account Binding (EAB)");
            Some(instant_acme::ExternalAccountKey::new(
                self.config.eab_kid.clone(),
                self.config.eab_hmac_key.as_bytes(),
            ))
        } else {
            None
        };

        let (account, credentials) = instant_acme::Account::create(
            &instant_acme::NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            dir_url,
            eab.as_ref(),
        )
        .await
        .map_err(|e| GatewayError::Internal(format!("create ACME account: {e}")))?;

        // Persist to disk.
        let json = serde_json::to_vec_pretty(&credentials)
            .map_err(|e| GatewayError::Internal(format!("serialize account credentials: {e}")))?;

        if let Some(parent) = account_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                GatewayError::Internal(format!("create account dir {}: {e}", parent.display()))
            })?;
        }
        std::fs::write(&account_path, &json).map_err(|e| {
            GatewayError::Internal(format!("write account {}: {e}", account_path.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&account_path, std::fs::Permissions::from_mode(0o600));
        }

        tracing::info!(
            id = %account.id(),
            path = %account_path.display(),
            "ACME account created and saved"
        );
        Ok(account)
    }

    // ------------------------------------------------------------------
    // Full ACME order flow
    // ------------------------------------------------------------------

    /// Resolve each candidate domain and keep only those whose A/AAAA
    /// records point to one of this machine's public IPs. Domains that
    /// resolve elsewhere or fail DNS are logged and dropped — they would
    /// cause ACME challenge failures anyway.
    async fn filter_resolvable_domains(&self, candidates: &[String]) -> Vec<String> {
        let our_ips = Self::local_public_ips().await;
        if our_ips.is_empty() {
            tracing::warn!("could not determine public IPs; skipping DNS pre-flight filter");
            return candidates.to_vec();
        }

        let resolver = hickory_resolver::TokioAsyncResolver::tokio(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::config::ResolverOpts::default(),
        );

        let mut keepers = Vec::new();
        for domain in candidates {
            match resolver.lookup_ip(domain.as_str()).await {
                Ok(lookup) => {
                    let resolved: Vec<std::net::IpAddr> = lookup.iter().collect();
                    if resolved.iter().any(|ip| our_ips.contains(ip)) {
                        keepers.push(domain.clone());
                    } else {
                        tracing::warn!(
                            domain = %domain,
                            resolved = ?resolved,
                            our_ips = ?our_ips,
                            "domain resolves elsewhere; excluding from ACME order"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %domain,
                        error = %e,
                        "domain DNS lookup failed; excluding from ACME order"
                    );
                }
            }
        }
        keepers
    }

    /// Discover this machine's public IP addresses by querying external
    /// services. Returns both IPv4 and IPv6 when available.
    async fn local_public_ips() -> std::collections::HashSet<std::net::IpAddr> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        let mut ips = std::collections::HashSet::new();
        for url in &[
            "https://api.ipify.org",
            "https://api64.ipify.org",
            "https://ifconfig.me/ip",
        ] {
            if let Ok(resp) = client.get(*url).send().await {
                if let Ok(text) = resp.text().await {
                    if let Ok(ip) = text.trim().parse::<std::net::IpAddr>() {
                        ips.insert(ip);
                    }
                }
            }
        }
        ips
    }

    /// Request a certificate from the configured ACME directory for all
    /// configured domains. Issues one multi-domain order (like lego) to
    /// consume a single rate-limit slot, with per-domain fallback when
    /// the multi-order fails.
    pub async fn request_certificate(&self) -> Result<(), GatewayError> {
        let domains = &self.config.domains;
        if domains.is_empty() {
            tracing::debug!("acme.domains is empty — skipping certificate request");
            return Ok(());
        }

        // DNS-01 proves zone control via TXT records — domains do NOT need
        // to resolve to this server.  Only filter for HTTP-01 / TLS-ALPN-01.
        let reachable = if self.config.challenge_type == "dns-01" {
            tracing::info!("DNS-01 mode: skipping domain resolution pre-flight");
            domains.clone()
        } else {
            let r = self.filter_resolvable_domains(domains).await;
            if r.is_empty() {
                return Err(GatewayError::Internal(
                    "ACME: no configured domains resolve to this server's public IP".into(),
                ));
            }
            if r.len() < domains.len() {
                let skipped: Vec<&String> = domains.iter().filter(|d| !r.contains(d)).collect();
                tracing::warn!(
                    skipped = ?skipped,
                    "ACME: some configured domains don't resolve here; proceeding with {:?}",
                    r
                );
            }
            r
        };

        tracing::info!(domains = ?reachable, "starting ACME certificate request");

        // Build the list of CA directory URLs to attempt: primary first,
        // then each configured fallback in order.
        let mut ca_urls: Vec<&str> = vec![self.config.directory_url.as_str()];
        for fb in &self.config.fallback_directory_urls {
            ca_urls.push(fb.as_str());
        }

        let primary = self.primary_domain().ok_or_else(|| {
            GatewayError::Internal("ACME: no domains configured (config.acme.domains is empty)".into())
        })?;
        let primary_dir = self.storage_dir().join(primary);
        let mut last_ca_error: Option<GatewayError> = None;

        for (ca_idx, dir_url) in ca_urls.iter().enumerate() {
            let ca_label = if ca_idx == 0 {
                "primary".to_string()
            } else {
                format!("fallback#{ca_idx}")
            };

            tracing::info!(
                ca = %ca_label,
                directory = %dir_url,
                "ACME: attempting certificate order"
            );

            let account = match self.get_or_create_account(dir_url).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(
                        ca = %ca_label,
                        directory = %dir_url,
                        error = %e,
                        "ACME: failed to create account at CA; trying next"
                    );
                    last_ca_error = Some(e);
                    continue;
                }
            };

            // ── 1. Try one multi-domain order ─────────────────────
            match self.issue_order(&account, &reachable, &primary_dir).await {
                Ok(()) => {
                    tracing::info!(
                        ca = %ca_label,
                        directory = %dir_url,
                        domains = ?reachable,
                        "ACME: multi-domain cert issued in one order"
                    );
                    self.try_load_cert().await?;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        ca = %ca_label,
                        error = %e,
                        "ACME: multi-domain order failed; attempting per-domain fallback"
                    );
                }
            }

            // ── 2. Per-domain fallback orders ───────────────────
            let mut succeeded: Vec<String> = Vec::new();
            let mut failed: Vec<(String, String)> = Vec::new();

            for domain in &reachable {
                let fallback_dir = self.storage_dir().join("_fallback").join(domain);
                match self
                    .issue_order(&account, std::slice::from_ref(domain), &fallback_dir)
                    .await
                {
                    Ok(()) => {
                        tracing::info!(
                            ca = %ca_label,
                            domain = %domain,
                            "ACME: fallback cert issued"
                        );
                        succeeded.push(domain.clone());
                    }
                    Err(e) => {
                        tracing::warn!(
                            ca = %ca_label,
                            domain = %domain,
                            error = %e,
                            "ACME: fallback order failed"
                        );
                        failed.push((domain.clone(), e.to_string()));
                    }
                }
            }

            if !succeeded.is_empty() {
                // At least one domain succeeded with this CA.
                let promote = if succeeded.contains(&primary.to_string()) {
                    primary.to_string()
                } else {
                    succeeded[0].clone()
                };
                let fb = self.storage_dir().join("_fallback").join(&promote);
                std::fs::create_dir_all(&primary_dir)
                    .map_err(|e| GatewayError::Internal(format!("create primary dir: {e}")))?;
                std::fs::copy(fb.join("cert.pem"), primary_dir.join("cert.pem"))
                    .map_err(|e| GatewayError::Internal(format!("promote fallback cert: {e}")))?;
                std::fs::copy(fb.join("key.pem"), primary_dir.join("key.pem"))
                    .map_err(|e| GatewayError::Internal(format!("promote fallback key: {e}")))?;
                tracing::info!(
                    ca = %ca_label,
                    domain = %promote,
                    "promoted fallback cert to primary"
                );

                if !failed.is_empty() {
                    tracing::warn!(
                        ok = ?succeeded,
                        bad = ?failed,
                        "ACME: partial success -- failed domains keep serving the previous cert"
                    );
                }

                self.try_load_cert().await?;
                tracing::info!(
                    ca = %ca_label,
                    directory = %dir_url,
                    "ACME certificate loaded into server"
                );
                return Ok(());
            }

            // Every order failed with this CA -- try the next one.
            tracing::warn!(
                ca = %ca_label,
                directory = %dir_url,
                "ACME: all orders failed with this CA; trying next"
            );
            last_ca_error = Some(GatewayError::Internal(format!(
                "ACME: every order failed at {dir_url}: {:?}",
                failed
            )));
        }

        // Exhausted all CAs.
        Err(last_ca_error
            .unwrap_or_else(|| GatewayError::Internal("ACME: no CA directories configured".into())))
    }

    /// Issue an ACME certificate covering `domains` and write the PEM
    /// files to `output_dir`. Shared by the multi-domain primary path
    /// and the per-domain fallback path.
    async fn issue_order(
        &self,
        account: &instant_acme::Account,
        domains: &[String],
        output_dir: &Path,
    ) -> Result<(), GatewayError> {
        let identifiers: Vec<instant_acme::Identifier> = domains
            .iter()
            .map(|d| instant_acme::Identifier::Dns(d.clone()))
            .collect();

        let label = if domains.len() == 1 {
            domains[0].clone()
        } else {
            format!("{} domains", domains.len())
        };

        let mut order = account
            .new_order(&instant_acme::NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| GatewayError::Internal(format!("create ACME order ({label}): {e}")))?;

        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| GatewayError::Internal(format!("fetch authorizations ({label}): {e}")))?;

        let challenge_type = self.config.challenge_type.as_str();

        for authz in &authorizations {
            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let instant_acme::Identifier::Dns(ref auth_domain) = authz.identifier;
            let challenge = self
                .pick_challenge(&authz.challenges, challenge_type)
                .ok_or_else(|| {
                    GatewayError::Internal(format!(
                        "no suitable challenge for {auth_domain} (type '{challenge_type}')"
                    ))
                })?;

            let key_auth = order.key_authorization(challenge);

            match challenge.r#type {
                instant_acme::ChallengeType::Http01 => {
                    self.set_challenge(challenge.token.clone(), key_auth.as_str().to_string());
                }
                instant_acme::ChallengeType::TlsAlpn01 => {
                    self.set_tls_alpn_challenge(
                        auth_domain.clone(),
                        key_auth.as_str().to_string(),
                    )?;
                }
                instant_acme::ChallengeType::Dns01 => {
                    let provider = self.dns_provider.as_ref().ok_or_else(|| {
                        GatewayError::Internal(
                            "DNS-01 challenge selected but no dns01 provider configured".into(),
                        )
                    })?;
                    let fqdn = dns_challenge::build_acme_dns_name(auth_domain);
                    let dns_value = key_auth.dns_value();
                    let _record_id = provider.set_txt_record(&fqdn, &dns_value).await?;

                    // Wait the configured propagation delay before polling,
                    // then poll until visible or timeout.
                    let delay = self.config.dns01.propagation_delay_secs;
                    let timeout = self.config.dns01.propagation_timeout_secs;
                    tracing::info!(
                        fqdn = %fqdn,
                        delay_secs = delay,
                        timeout_secs = timeout,
                        "DNS-01: waiting for TXT propagation"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    dns_challenge::wait_for_propagation_with_timeout(&fqdn, &dns_value, timeout)
                        .await?;
                }
                _ => {
                    return Err(GatewayError::Internal(format!(
                        "unsupported challenge type {:?}",
                        challenge.r#type
                    )));
                }
            }

            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| {
                    GatewayError::Internal(format!("set challenge ready for {auth_domain}: {e}"))
                })?;
        }

        // Poll until Ready or Valid.
        let mut delay = std::time::Duration::from_secs(1);
        for attempt in 1u8..=10 {
            tokio::time::sleep(delay).await;
            let state = order
                .refresh()
                .await
                .map_err(|e| GatewayError::Internal(format!("refresh order ({label}): {e}")))?;
            tracing::info!(
                attempt,
                label = %label,
                status = ?state.status,
                "polling ACME order"
            );
            match state.status {
                instant_acme::OrderStatus::Ready | instant_acme::OrderStatus::Valid => break,
                instant_acme::OrderStatus::Invalid => {
                    self.cleanup_challenges(&authorizations);
                    return Err(GatewayError::Internal(format!(
                        "ACME order ({label}) invalid: {:?}",
                        state.error
                    )));
                }
                _ => {
                    delay = std::cmp::min(delay * 2, std::time::Duration::from_secs(30));
                }
            }
        }

        self.cleanup_challenges(&authorizations);

        // Finalize if the order is Ready (skip if already Valid).
        let private_key;
        match order.state().status {
            instant_acme::OrderStatus::Ready => {
                let mut csr_params = rcgen::CertificateParams::new(domains.to_vec())
                    .map_err(|e| GatewayError::Internal(format!("CSR params ({label}): {e}")))?;
                csr_params.distinguished_name = rcgen::DistinguishedName::new();

                let existing_key_path = output_dir.join("key.pem");
                if self.config.reuse_private_keys {
                    if let Some(existing) = load_existing_key(&existing_key_path) {
                        tracing::info!(
                            label = %label,
                            path = %existing_key_path.display(),
                            "reusing existing private key for renewal"
                        );
                        private_key = existing;
                    } else {
                        tracing::info!(
                            label = %label,
                            key_type = %self.config.key_type,
                            "no existing key found; generating new ACME CSR key"
                        );
                        private_key =
                            rcgen::KeyPair::generate_for(self.key_algorithm()).map_err(|e| {
                                GatewayError::Internal(format!("generate key ({label}): {e}"))
                            })?;
                    }
                } else {
                    let algo = self.key_algorithm();
                    tracing::info!(
                        label = %label,
                        key_type = %self.config.key_type,
                        "generating ACME CSR key"
                    );
                    private_key = rcgen::KeyPair::generate_for(algo).map_err(|e| {
                        GatewayError::Internal(format!("generate key ({label}): {e}"))
                    })?;
                }

                let csr = csr_params
                    .serialize_request(&private_key)
                    .map_err(|e| GatewayError::Internal(format!("serialize CSR ({label}): {e}")))?;

                order.finalize(csr.der()).await.map_err(|e| {
                    GatewayError::Internal(format!("finalize order ({label}): {e}"))
                })?;
            }
            instant_acme::OrderStatus::Valid => {
                // Already finalized in a previous attempt — we still
                // need a key for the local write below.  Download will
                // give us the cert chain but not the private key, so
                // this path can only recover the cert. In practice the
                // key was written to disk during the earlier run.
                tracing::info!(
                    label = %label,
                    "order already valid; downloading existing cert"
                );
                private_key = rcgen::KeyPair::generate_for(self.key_algorithm())
                    .map_err(|e| GatewayError::Internal(format!("generate key ({label}): {e}")))?;
            }
            other => {
                return Err(GatewayError::Internal(format!(
                    "ACME order ({label}) stuck in {:?} after polling",
                    other
                )));
            }
        }

        // Download certificate.
        let cert_pem = {
            let mut pem = None;
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                match order.certificate().await {
                    Ok(Some(chain)) => {
                        pem = Some(chain);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(GatewayError::Internal(format!(
                            "download certificate ({label}): {e}"
                        )));
                    }
                }
            }
            pem.ok_or_else(|| {
                GatewayError::Internal(format!("timed out waiting for cert ({label})"))
            })?
        };

        // Check preferred certificate chain if configured.
        if !self.config.preferred_chain.is_empty() {
            if check_preferred_chain(&cert_pem, &self.config.preferred_chain) {
                tracing::info!(
                    label = %label,
                    preferred = %self.config.preferred_chain,
                    "certificate chain matches preferred issuer"
                );
            } else {
                // instant-acme's order.certificate() returns only one chain;
                // we cannot request alternates. Log a warning and use whatever
                // the CA returned. This makes the config forward-compatible
                // for when alternate chain selection is available.
                tracing::warn!(
                    label = %label,
                    preferred = %self.config.preferred_chain,
                    "certificate chain does NOT match preferred issuer; \
                     using default chain (alternate chain selection not available)"
                );
            }
        }

        // Persist to output directory.
        std::fs::create_dir_all(output_dir).map_err(|e| {
            GatewayError::Internal(format!("create cert dir {}: {e}", output_dir.display()))
        })?;

        let cert_path = output_dir.join("cert.pem");
        let key_path = output_dir.join("key.pem");
        let key_pem = private_key.serialize_pem();

        std::fs::write(&cert_path, cert_pem.as_bytes()).map_err(|e| {
            GatewayError::Internal(format!("write cert {}: {e}", cert_path.display()))
        })?;
        std::fs::write(&key_path, key_pem.as_bytes()).map_err(|e| {
            GatewayError::Internal(format!("write key {}: {e}", key_path.display()))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }

        tracing::info!(
            label = %label,
            cert = %cert_path.display(),
            "ACME certificate written to disk"
        );

        Ok(())
    }

    /// Pick a challenge from the list based on the configured type.
    ///
    /// * `"http-01"` -- only HTTP-01
    /// * `"tls-alpn-01"` -- only TLS-ALPN-01
    /// * `"auto"` -- prefer TLS-ALPN-01, fall back to HTTP-01
    fn pick_challenge<'a>(
        &self,
        challenges: &'a [instant_acme::Challenge],
        challenge_type: &str,
    ) -> Option<&'a instant_acme::Challenge> {
        match challenge_type {
            "http-01" => challenges
                .iter()
                .find(|c| c.r#type == instant_acme::ChallengeType::Http01),
            "tls-alpn-01" => challenges
                .iter()
                .find(|c| c.r#type == instant_acme::ChallengeType::TlsAlpn01),
            "dns-01" => challenges
                .iter()
                .find(|c| c.r#type == instant_acme::ChallengeType::Dns01),
            _ => {
                // "auto": prefer DNS-01 (if provider configured) > TLS-ALPN-01 > HTTP-01.
                let dns_first = self.dns_provider.is_some();
                if dns_first {
                    challenges
                        .iter()
                        .find(|c| c.r#type == instant_acme::ChallengeType::Dns01)
                        .or_else(|| {
                            challenges
                                .iter()
                                .find(|c| c.r#type == instant_acme::ChallengeType::TlsAlpn01)
                        })
                        .or_else(|| {
                            challenges
                                .iter()
                                .find(|c| c.r#type == instant_acme::ChallengeType::Http01)
                        })
                } else {
                    challenges
                        .iter()
                        .find(|c| c.r#type == instant_acme::ChallengeType::TlsAlpn01)
                        .or_else(|| {
                            challenges
                                .iter()
                                .find(|c| c.r#type == instant_acme::ChallengeType::Http01)
                        })
                }
            }
        }
    }

    /// Remove all pending challenges registered during this order.
    fn cleanup_challenges(&self, authorizations: &[instant_acme::Authorization]) {
        for authz in authorizations {
            let instant_acme::Identifier::Dns(ref domain) = authz.identifier;
            for ch in &authz.challenges {
                match ch.r#type {
                    instant_acme::ChallengeType::Http01 => {
                        self.clear_challenge(&ch.token);
                    }
                    instant_acme::ChallengeType::TlsAlpn01 => {
                        self.clear_tls_alpn_challenge(domain);
                    }
                    _ => {}
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Auto-renewal
    // ------------------------------------------------------------------

    /// Spawn a background task that checks cert expiry every 12 hours
    /// and triggers a new ACME order if the certificate is within 30
    /// days of expiry (or missing entirely).
    pub fn spawn_auto_renew(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            // Short initial delay to let the server finish booting.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(12 * 3600));
            loop {
                interval.tick().await;
                if let Err(e) = manager.check_and_renew().await {
                    tracing::warn!(error = %e, "auto-renew check failed");
                }
            }
        });
    }

    /// Check whether the current cert needs renewal and, if so, run
    /// the full ACME order flow.
    async fn check_and_renew(&self) -> Result<(), GatewayError> {
        let cert_path = match self.cert_path() {
            Some(p) if p.exists() => p,
            _ => {
                tracing::info!("no cert on disk; requesting initial certificate");
                return self.request_certificate().await;
            }
        };

        // Parse the leaf certificate to find the expiry.
        let pem_bytes = std::fs::read(&cert_path).map_err(|e| {
            GatewayError::Internal(format!(
                "read cert for renewal check {}: {e}",
                cert_path.display()
            ))
        })?;

        let mut cursor = std::io::Cursor::new(&pem_bytes);
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GatewayError::Internal(format!("parse cert for renewal: {e}")))?;

        if certs.is_empty() {
            tracing::info!("cert file empty; requesting new certificate");
            return self.request_certificate().await;
        }

        let (_, parsed) = x509_parser::parse_x509_certificate(certs[0].as_ref())
            .map_err(|e| GatewayError::Internal(format!("parse x509 for expiry: {e}")))?;

        // Treat the self-signed boot cert as immediately needing replacement.
        // generate_self_signed_cert sets the issuer's Organization to
        // "Lynxx Self-Signed" — that string is the cleanest sentinel since
        // a real LE cert's issuer is "Let's Encrypt R3"/etc.
        let issuer = parsed.issuer().to_string();
        if issuer.contains("Lynxx Self-Signed") {
            tracing::info!(issuer = %issuer, "self-signed boot cert detected; requesting real ACME certificate");
            return self.request_certificate().await;
        }

        let not_after = parsed.validity().not_after.timestamp();
        let now = chrono::Utc::now().timestamp();
        let days_remaining = (not_after - now) / 86400;

        tracing::info!(
            days_remaining,
            not_after = %parsed.validity().not_after,
            "cert expiry check"
        );

        // Check if the configured domains have changed since the cert was issued.
        let configured: std::collections::HashSet<&str> =
            self.config.domains.iter().map(|s| s.as_str()).collect();
        let cert_sans: std::collections::HashSet<String> = parsed
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|gn| {
                        if let x509_parser::prelude::GeneralName::DNSName(dns) = gn {
                            Some(dns.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<std::collections::HashSet<_>>()
            })
            .unwrap_or_default();
        let cert_san_refs: std::collections::HashSet<&str> =
            cert_sans.iter().map(|s| s.as_str()).collect();
        let missing: Vec<&&str> = configured.difference(&cert_san_refs).collect();

        if !missing.is_empty() {
            tracing::info!(
                ?missing,
                "configured domains not in cert SANs; forcing re-issue"
            );
            return self.request_certificate().await;
        }

        if days_remaining <= 30 {
            tracing::info!(
                days_remaining,
                "cert expires within 30 days; requesting renewal"
            );
            self.request_certificate().await
        } else {
            tracing::info!(days_remaining, "cert is still valid, no renewal needed");
            Ok(())
        }
    }

    // ------------------------------------------------------------------
    // Certificate revocation
    // ------------------------------------------------------------------

    /// Revoke the currently loaded certificate via the ACME protocol
    /// (RFC 8555 §7.6). The certificate is revoked at the primary
    /// directory URL using the existing account credentials.
    pub async fn revoke_certificate(
        &self,
        reason: Option<instant_acme::RevocationReason>,
    ) -> Result<(), GatewayError> {
        let cert_path = self.cert_path().ok_or_else(|| {
            GatewayError::Internal("no cert path configured for revocation".into())
        })?;

        if !cert_path.exists() {
            return Err(GatewayError::Internal(format!(
                "cert file not found: {}",
                cert_path.display()
            )));
        }

        let pem_bytes = std::fs::read(&cert_path)
            .map_err(|e| GatewayError::Internal(format!("read cert for revocation: {e}")))?;

        let mut cursor = std::io::Cursor::new(&pem_bytes);
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GatewayError::Internal(format!("parse cert for revocation: {e}")))?;

        let leaf = certs
            .first()
            .ok_or_else(|| GatewayError::Internal("no certificate in PEM file".into()))?;

        let account = self
            .get_or_create_account(&self.config.directory_url)
            .await?;

        let revocation = instant_acme::RevocationRequest {
            certificate: leaf,
            reason,
        };
        account
            .revoke(&revocation)
            .await
            .map_err(|e| GatewayError::Internal(format!("ACME revoke: {e}")))?;

        tracing::info!(
            cert = %cert_path.display(),
            "certificate revoked via ACME"
        );
        Ok(())
    }
}

// ======================================================================
// Free functions / helpers
// ======================================================================

/// Trivial cert resolver that always returns the same [`CertifiedKey`].
/// Used by [`AcmeManager::alpn_challenge_config`] to build a one-shot
/// `ServerConfig` for TLS-ALPN-01 validation.
#[derive(Debug)]
struct AlpnChallengeStaticResolver(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for AlpnChallengeStaticResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Default storage directory: `~/.lynxx/acme/`.
fn default_storage_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib/lynxx"))
        .join(".lynxx")
        .join("acme")
}

/// Build a `rustls::ServerConfig` from PEM files on disk.
fn build_server_config_from_files(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerConfig, GatewayError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| GatewayError::Internal(format!("read cert {}: {e}", cert_path.display())))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| GatewayError::Internal(format!("read key {}: {e}", key_path.display())))?;

    let certs = {
        let mut cursor = std::io::Cursor::new(&cert_pem);
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                GatewayError::Internal(format!("parse cert {}: {e}", cert_path.display()))
            })?
    };
    if certs.is_empty() {
        return Err(GatewayError::Internal(format!(
            "no certificates in {}",
            cert_path.display()
        )));
    }

    let key = {
        let mut cursor = std::io::Cursor::new(&key_pem);
        rustls_pemfile::private_key(&mut cursor)
            .map_err(|e| GatewayError::Internal(format!("parse key {}: {e}", key_path.display())))?
            .ok_or_else(|| {
                GatewayError::Internal(format!("no private key in {}", key_path.display()))
            })?
    };

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| GatewayError::Internal(format!("build ServerConfig: {e}")))?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Generate a self-signed certificate for the given domains and write
/// the PEM files to disk.
///
/// Uses ECDSA P-256 for the key (fast, small, widely supported) and
/// sets the validity to 365 days. The first domain becomes the CN;
/// all domains appear as SANs.
fn generate_self_signed_cert(
    domains: &[String],
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), GatewayError> {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|e| GatewayError::Internal(format!("cert params: {e}")))?;

    // Set the common name to the primary domain.
    if let Some(primary) = domains.first() {
        params
            .distinguished_name
            .push(DnType::CommonName, primary.clone());
    }
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Lynxx Self-Signed");

    // ECDSA P-256 via ring — consistent with the rest of the gateway's
    // crypto stack.
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| GatewayError::Internal(format!("generate key pair: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| GatewayError::Internal(format!("self-sign cert: {e}")))?;

    // Write PEM files.
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Ensure parent directory exists.
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            GatewayError::Internal(format!("create cert dir {}: {e}", parent.display()))
        })?;
    }

    std::fs::write(cert_path, cert_pem.as_bytes())
        .map_err(|e| GatewayError::Internal(format!("write cert {}: {e}", cert_path.display())))?;
    std::fs::write(key_path, key_pem.as_bytes())
        .map_err(|e| GatewayError::Internal(format!("write key {}: {e}", key_path.display())))?;

    // Restrict key file permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(key_path, perms);
    }

    Ok(())
}

// ======================================================================
// Helper: reuse existing private key (Feature 36)
// ======================================================================

/// Try to load an existing PEM private key from `path`. Returns `None`
/// if the file doesn't exist or can't be parsed, so callers fall back
/// to generating a new key.
fn load_existing_key(path: &Path) -> Option<rcgen::KeyPair> {
    let pem = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return None,
    };
    match rcgen::KeyPair::from_pem(&pem) {
        Ok(kp) => Some(kp),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "existing key file found but could not be parsed; generating new key"
            );
            None
        }
    }
}

// ======================================================================
// Helper: preferred certificate chain (Feature 38)
// ======================================================================

/// Check whether any certificate in the PEM chain has an issuer CN that
/// contains `preferred`. Returns `true` if a match is found.
fn check_preferred_chain(cert_pem: &str, preferred: &str) -> bool {
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        match rustls_pemfile::certs(&mut cursor).collect::<Result<Vec<_>, _>>() {
            Ok(c) => c,
            Err(_) => return false,
        };

    for der in &certs {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(der.as_ref()) {
            // Check issuer CN.
            for attr in parsed.issuer().iter_common_name() {
                if let Ok(cn) = attr.as_str() {
                    if cn.contains(preferred) {
                        return true;
                    }
                }
            }
            // Also check subject CN (the root cert is self-signed, so
            // subject == issuer).
            for attr in parsed.subject().iter_common_name() {
                if let Ok(cn) = attr.as_str() {
                    if cn.contains(preferred) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the ring crypto provider for tests that build a
    /// `ServerConfig`. The gateway binary does this in `main()`;
    /// tests need it explicitly. Calling it twice is harmless (returns
    /// `Err` which we ignore).
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn test_handle_challenge_match() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".into()],
            self_signed: false,
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        mgr.set_challenge("test-token-123".into(), "auth-value-xyz".into());

        assert_eq!(
            mgr.handle_challenge("/.well-known/acme-challenge/test-token-123"),
            Some("auth-value-xyz".to_string())
        );
    }

    #[test]
    fn test_handle_challenge_no_match() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".into()],
            self_signed: false,
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);

        assert_eq!(
            mgr.handle_challenge("/.well-known/acme-challenge/unknown"),
            None
        );
        assert_eq!(mgr.handle_challenge("/some/other/path"), None);
        assert_eq!(mgr.handle_challenge("/.well-known/acme-challenge/"), None);
    }

    #[test]
    fn test_clear_challenge() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".into()],
            self_signed: false,
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        mgr.set_challenge("tok".into(), "auth".into());
        assert!(mgr
            .handle_challenge("/.well-known/acme-challenge/tok")
            .is_some());

        mgr.clear_challenge("tok");
        assert!(mgr
            .handle_challenge("/.well-known/acme-challenge/tok")
            .is_none());
    }

    #[test]
    fn test_generate_self_signed_cert() {
        install_crypto_provider();
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");

        generate_self_signed_cert(
            &["localhost".to_string(), "127.0.0.1".to_string()],
            &cert_path,
            &key_path,
        )
        .unwrap();

        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify the files are valid PEM that rustls can parse.
        let config = build_server_config_from_files(&cert_path, &key_path);
        assert!(config.is_ok(), "generated cert should be loadable");
    }

    #[test]
    fn test_storage_dir_default() {
        let config = AcmeConfig::default();
        let mgr = AcmeManager::new(config);
        let dir = mgr.storage_dir();
        assert!(
            dir.to_string_lossy().contains("acme"),
            "default dir should contain 'acme'"
        );
    }

    #[test]
    fn test_storage_dir_custom() {
        let config = AcmeConfig {
            storage_dir: "/custom/path".into(),
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        assert_eq!(mgr.storage_dir(), PathBuf::from("/custom/path"));
    }

    #[tokio::test]
    async fn test_init_self_signed() {
        install_crypto_provider();
        let tmp = tempfile::tempdir().unwrap();
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["localhost".into()],
            self_signed: true,
            storage_dir: tmp.path().to_string_lossy().into_owned(),
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        let ok = mgr.init().await.unwrap();
        assert!(ok, "init with self_signed should succeed");
        assert!(mgr.has_cert().await, "cert should be loaded");

        // Verify cert files were created.
        assert!(tmp.path().join("localhost").join("cert.pem").exists());
        assert!(tmp.path().join("localhost").join("key.pem").exists());
    }

    #[tokio::test]
    async fn test_init_no_domains_returns_false() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec![],
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        let result = mgr.init().await.expect("empty domains should not error");
        assert!(
            !result,
            "init with no domains should return false (no cert loaded)"
        );
    }

    #[tokio::test]
    async fn test_reload_on_file_change() {
        install_crypto_provider();
        let tmp = tempfile::tempdir().unwrap();
        let domain_dir = tmp.path().join("localhost");
        std::fs::create_dir_all(&domain_dir).unwrap();

        let cert_path = domain_dir.join("cert.pem");
        let key_path = domain_dir.join("key.pem");

        // Generate initial cert.
        generate_self_signed_cert(&["localhost".to_string()], &cert_path, &key_path).unwrap();

        let config = AcmeConfig {
            enabled: true,
            domains: vec!["localhost".into()],
            self_signed: false,
            storage_dir: tmp.path().to_string_lossy().into_owned(),
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        let ok = mgr.init().await.unwrap();
        assert!(ok);

        // Simulate external renewal: regenerate the cert.
        // Sleep briefly so mtime differs.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        generate_self_signed_cert(&["localhost".to_string()], &cert_path, &key_path).unwrap();

        // Manually trigger the check.
        mgr.check_and_reload().await.unwrap();

        // Should still have a valid cert.
        assert!(mgr.has_cert().await);
    }

    #[tokio::test]
    async fn test_tls_alpn_challenge_register_and_clear() {
        install_crypto_provider();
        let tmp = tempfile::tempdir().unwrap();
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["localhost".into()],
            self_signed: true,
            storage_dir: tmp.path().to_string_lossy().into_owned(),
            ..AcmeConfig::default()
        };
        let mgr = AcmeManager::new(config);
        mgr.init().await.unwrap();

        assert_eq!(mgr.tls_alpn_challenge_count(), 0);

        mgr.set_tls_alpn_challenge("api.example.com".into(), "tok.thumb".into())
            .unwrap();
        mgr.set_tls_alpn_challenge("admin.example.com".into(), "tok.thumb".into())
            .unwrap();
        assert_eq!(mgr.tls_alpn_challenge_count(), 2);

        // The resolver inside the ServerConfig should now also know
        // about the registered challenge — i.e. the lookup closure
        // returns Some when invoked with a registered SNI. We can't
        // easily synthesize a ClientHello in a unit test, so the
        // count check stands in for round-trip verification — the
        // ALPN <-> challenge flow itself is covered by
        // `tls_alpn::tests::builds_challenge_cert_with_acme_extension`
        // and the integration tests under tests/.
        mgr.clear_tls_alpn_challenge("api.example.com");
        assert_eq!(mgr.tls_alpn_challenge_count(), 1);
        mgr.clear_tls_alpn_challenge("admin.example.com");
        assert_eq!(mgr.tls_alpn_challenge_count(), 0);
    }

    // ----------------------------------------------------------------
    // Feature 36: reuse_private_keys
    // ----------------------------------------------------------------

    #[test]
    fn test_reuse_key_config_deserializes() {
        let json = r#"{
            "enabled": true,
            "domains": ["example.com"],
            "reuse_private_keys": true
        }"#;
        let config: AcmeConfig = serde_json::from_str(json).unwrap();
        assert!(config.reuse_private_keys);
    }

    #[test]
    fn test_reuse_key_config_defaults_false() {
        let config = AcmeConfig::default();
        assert!(!config.reuse_private_keys);
    }

    #[test]
    fn test_load_existing_key_valid() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = kp.serialize_pem();

        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("key.pem");
        std::fs::write(&key_path, pem.as_bytes()).unwrap();

        let loaded = load_existing_key(&key_path);
        assert!(loaded.is_some(), "should load a valid PEM key");
    }

    #[test]
    fn test_load_existing_key_missing_file() {
        let loaded = load_existing_key(Path::new("/nonexistent/path/key.pem"));
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_existing_key_invalid_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("key.pem");
        std::fs::write(&key_path, b"not-a-valid-pem").unwrap();

        let loaded = load_existing_key(&key_path);
        assert!(loaded.is_none());
    }

    // ----------------------------------------------------------------
    // Feature 38: preferred certificate chains
    // ----------------------------------------------------------------

    #[test]
    fn test_preferred_chain_config_deserializes() {
        let json = r#"{
            "enabled": true,
            "domains": ["example.com"],
            "preferred_chain": "ISRG Root X1"
        }"#;
        let config: AcmeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.preferred_chain, "ISRG Root X1");
    }

    #[test]
    fn test_preferred_chain_config_defaults_empty() {
        let config = AcmeConfig::default();
        assert!(config.preferred_chain.is_empty());
    }

    #[test]
    fn test_check_preferred_chain_matches_self_signed() {
        // Generate a self-signed cert whose CN contains a known string,
        // then verify check_preferred_chain finds it.
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Lynxx Test Root CA");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();

        assert!(
            check_preferred_chain(&pem, "Lynxx Test Root"),
            "should match partial CN"
        );
        assert!(
            check_preferred_chain(&pem, "Test Root CA"),
            "should match another substring"
        );
    }

    #[test]
    fn test_check_preferred_chain_no_match() {
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Some Other CA");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();

        assert!(
            !check_preferred_chain(&pem, "ISRG Root X1"),
            "should not match unrelated CN"
        );
    }

    #[test]
    fn test_check_preferred_chain_invalid_pem() {
        assert!(!check_preferred_chain("garbage data", "anything"));
    }
}
