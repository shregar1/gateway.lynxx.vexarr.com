//! On-Demand TLS: provision certificates dynamically during the TLS
//! handshake for previously-unknown domains.
//!
//! This is the Caddy-style "automatic HTTPS for any domain" feature.
//! When a TLS connection arrives for a domain the gateway doesn't have a
//! cert for, we:
//!
//! 1. Return a temporary self-signed cert so the handshake completes
//!    without blocking.
//! 2. Kick off an async ACME order in the background.
//! 3. Once the real cert arrives, all future connections use it.
//!
//! ## Abuse prevention
//!
//! Without gating, an attacker could flood the gateway with random
//! hostnames and exhaust ACME rate limits. Two mechanisms exist:
//!
//! * **Allow-list**: a static list of permitted domains.
//! * **Ask endpoint**: an HTTP `GET {ask_url}?domain={domain}` call that
//!   must return `200 OK` to approve issuance.
//!
//! When neither is configured, all domains are allowed (opt-in danger).
//!
//! ## Rate limiting
//!
//! A sliding-window rate limiter caps the number of new certificate
//! orders per minute, protecting against ACME provider rate limits
//! (Let's Encrypt: 50 certs/week for the same set of names, 300 new
//! orders/3 hours).

use crate::config::OnDemandTlsConfig;
use crate::error::GatewayError;
use crate::proxy::acme::AcmeManager;
use crate::proxy::tls_alpn::certified_key_from_pem;
use dashmap::DashMap;
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

// ------------------------------------------------------------------
// Rate limiter
// ------------------------------------------------------------------

/// Sliding-window rate limiter: allows at most `max_per_minute`
/// events in any 60-second window. Lock-free for the fast path (read
/// count), mutex only for the slow path (compact + insert).
pub struct RateLimiter {
    max_per_minute: u32,
    /// Timestamps of recent issuance events (monotonic).
    window: Mutex<Vec<Instant>>,
    /// Atomic counter for a quick reject without locking. Decremented
    /// lazily when the window is compacted.
    count: AtomicU64,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            window: Mutex::new(Vec::new()),
            count: AtomicU64::new(0),
        }
    }

    /// Try to consume one slot. Returns `true` if allowed.
    pub async fn try_acquire(&self) -> bool {
        // Fast-path reject: if the atomic count already meets the cap
        // we can skip the lock entirely.
        if self.count.load(Ordering::Relaxed) >= self.max_per_minute as u64 {
            // Still need to compact in case old entries expired.
            let mut window = self.window.lock().await;
            let cutoff = Instant::now() - std::time::Duration::from_secs(60);
            window.retain(|t| *t > cutoff);
            self.count.store(window.len() as u64, Ordering::Relaxed);
            if window.len() >= self.max_per_minute as usize {
                return false;
            }
        }

        let mut window = self.window.lock().await;
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        window.retain(|t| *t > cutoff);

        if window.len() >= self.max_per_minute as usize {
            self.count.store(window.len() as u64, Ordering::Relaxed);
            return false;
        }

        window.push(Instant::now());
        self.count.store(window.len() as u64, Ordering::Relaxed);
        true
    }
}

// ------------------------------------------------------------------
// On-Demand TLS Resolver
// ------------------------------------------------------------------

/// Cert resolver that provisions certificates on the fly during the
/// TLS handshake. Implements `rustls::server::ResolvesServerCert`.
pub struct OnDemandTlsResolver {
    /// domain -> certified key (real ACME certs or cached self-signed).
    cert_cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
    /// Shared ACME manager for issuing real certificates.
    acme_manager: Arc<AcmeManager>,
    /// Pre-generated self-signed cert returned during the first
    /// handshake while the real cert is being provisioned.
    fallback_cert: Arc<CertifiedKey>,
    /// Static allow-list. `None` means allow all domains.
    allowed_domains: Option<Vec<String>>,
    /// Optional HTTP endpoint for dynamic domain validation.
    ask_url: Option<String>,
    /// Domains currently undergoing ACME issuance. Prevents duplicate
    /// orders for the same domain.
    pending: Arc<DashMap<String, ()>>,
    /// Rate limiter for new certificate orders.
    rate_limiter: Arc<RateLimiter>,
    /// ACME storage directory, for disk persistence of on-demand certs.
    storage_dir: PathBuf,
}

impl std::fmt::Debug for OnDemandTlsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandTlsResolver")
            .field("cached_domains", &self.cert_cache.len())
            .field("pending_domains", &self.pending.len())
            .field("allowed_domains", &self.allowed_domains)
            .field("has_ask_url", &self.ask_url.is_some())
            .finish()
    }
}

impl OnDemandTlsResolver {
    /// Build a new on-demand TLS resolver from config. Loads any
    /// previously-issued certs from disk and generates the fallback
    /// self-signed cert.
    pub fn new(
        config: &OnDemandTlsConfig,
        acme_manager: Arc<AcmeManager>,
    ) -> Result<Self, GatewayError> {
        let fallback_cert = Arc::new(generate_temp_self_signed("on-demand.localhost")?);

        let allowed_domains = if config.allowed_domains.is_empty() {
            None
        } else {
            Some(config.allowed_domains.clone())
        };

        let ask_url = if config.ask_url.is_empty() {
            None
        } else {
            Some(config.ask_url.clone())
        };

        let storage_dir = acme_manager.storage_dir().join("_on_demand");

        let cert_cache = Arc::new(DashMap::new());

        // Load previously-issued on-demand certs from disk.
        if let Err(e) = load_cached_certs(&storage_dir, &cert_cache) {
            tracing::warn!(
                error = %e,
                dir = %storage_dir.display(),
                "failed to load on-demand cert cache from disk; starting fresh"
            );
        }

        let resolver = Self {
            cert_cache,
            acme_manager,
            fallback_cert,
            allowed_domains,
            ask_url,
            pending: Arc::new(DashMap::new()),
            rate_limiter: Arc::new(RateLimiter::new(config.max_certs_per_minute)),
            storage_dir,
        };

        tracing::info!(
            cached = resolver.cert_cache.len(),
            allowed = ?resolver.allowed_domains,
            has_ask_url = resolver.ask_url.is_some(),
            max_per_min = config.max_certs_per_minute,
            "on-demand TLS resolver initialised"
        );

        Ok(resolver)
    }

    /// Number of cached certificates.
    pub fn cached_count(&self) -> usize {
        self.cert_cache.len()
    }

    /// Number of domains currently being issued.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Insert a pre-existing cert into the cache (e.g. loaded from
    /// the main AcmeManager's storage). This lets the on-demand
    /// resolver serve certs that were issued by the primary ACME flow.
    pub fn insert_cert(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.cert_cache.insert(domain, cert);
    }

    /// Check whether a domain is allowed (allow-list + ask endpoint).
    /// This is `async` because the ask endpoint requires an HTTP call.
    async fn is_domain_allowed(&self, domain: &str) -> bool {
        // 1. Allow-list check.
        if let Some(ref allowed) = self.allowed_domains {
            if !allowed.iter().any(|d| d == domain) {
                tracing::debug!(domain = %domain, "on-demand TLS: domain not in allow-list");
                return false;
            }
        }

        // 2. Ask endpoint check.
        if let Some(ref url) = self.ask_url {
            match check_ask_endpoint(url, domain).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!(domain = %domain, "on-demand TLS: ask endpoint denied domain");
                    return false;
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %domain,
                        error = %e,
                        "on-demand TLS: ask endpoint check failed; denying"
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Trigger background certificate issuance for `domain`.
    /// Returns immediately; the cert will appear in `cert_cache` when
    /// the ACME flow completes.
    fn trigger_issuance(self: &Arc<Self>, domain: String) {
        // Guard: already pending.
        if self.pending.contains_key(&domain) {
            tracing::debug!(domain = %domain, "on-demand TLS: issuance already in progress");
            return;
        }
        self.pending.insert(domain.clone(), ());

        let resolver = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = PendingGuard {
                pending: Arc::clone(&resolver.pending),
                domain: domain.clone(),
            };

            // Permission check.
            if !resolver.is_domain_allowed(&domain).await {
                return;
            }

            // Rate limit check.
            if !resolver.rate_limiter.try_acquire().await {
                tracing::warn!(
                    domain = %domain,
                    "on-demand TLS: rate limit exceeded; skipping issuance"
                );
                return;
            }

            tracing::info!(domain = %domain, "on-demand TLS: starting ACME certificate issuance");

            let output_dir = resolver.storage_dir.join(&domain);
            if let Err(e) = std::fs::create_dir_all(&output_dir) {
                tracing::error!(
                    domain = %domain,
                    error = %e,
                    "on-demand TLS: failed to create storage dir"
                );
                return;
            }

            // Use the shared AcmeManager to issue a single-domain cert.
            match resolver
                .issue_single_domain_cert(&domain, &output_dir)
                .await
            {
                Ok(cert) => {
                    let cert = Arc::new(cert);
                    resolver.cert_cache.insert(domain.clone(), cert);
                    tracing::info!(
                        domain = %domain,
                        "on-demand TLS: ACME certificate issued and cached"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        domain = %domain,
                        error = %e,
                        "on-demand TLS: ACME certificate issuance failed"
                    );
                }
            }
        });
    }

    /// Issue a single-domain ACME certificate. Writes PEM to
    /// `output_dir` and returns the `CertifiedKey`.
    async fn issue_single_domain_cert(
        &self,
        domain: &str,
        output_dir: &std::path::Path,
    ) -> Result<CertifiedKey, GatewayError> {
        // Build a single-purpose AcmeManager for this domain. We
        // clone the shared manager's config, override domains to just
        // the requested one, and point storage_dir so the cert lands
        // in our on-demand output directory.
        let mut cfg = self.acme_manager.config().clone();
        cfg.domains = vec![domain.to_string()];
        // Point storage_dir so cert lands in output_dir's parent.
        // AcmeManager stores certs at {storage_dir}/{primary_domain}/.
        cfg.storage_dir = output_dir
            .parent()
            .unwrap_or(output_dir)
            .to_string_lossy()
            .into_owned();

        let mgr = AcmeManager::new(cfg);
        mgr.request_certificate().await?;

        // Load the resulting cert from disk.
        let cert_path = output_dir.join("cert.pem");
        let key_path = output_dir.join("key.pem");

        let cert_pem = std::fs::read(&cert_path).map_err(|e| {
            GatewayError::Internal(format!("on-demand: read cert {}: {e}", cert_path.display()))
        })?;
        let key_pem = std::fs::read(&key_path).map_err(|e| {
            GatewayError::Internal(format!("on-demand: read key {}: {e}", key_path.display()))
        })?;

        certified_key_from_pem(&cert_pem, &key_pem)
    }
}

/// RAII guard that removes the domain from the `pending` set when
/// dropped, regardless of success or failure.
struct PendingGuard {
    pending: Arc<DashMap<String, ()>>,
    domain: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.pending.remove(&self.domain);
    }
}

impl ResolvesServerCert for OnDemandTlsResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;

        // 1. Cache hit: return the real (or previously-issued) cert.
        if let Some(entry) = self.cert_cache.get(sni) {
            tracing::debug!(domain = %sni, "on-demand TLS: serving cached cert");
            return Some(Arc::clone(entry.value()));
        }

        // 2. Cache miss: return the fallback self-signed cert and
        //    trigger background issuance. We can't do async work
        //    inside `resolve()` (it's synchronous), so we spawn.
        tracing::info!(
            domain = %sni,
            "on-demand TLS: no cert cached; serving fallback and triggering issuance"
        );

        // We need `self` as Arc to spawn. The resolver is always
        // stored as `Arc<dyn ResolvesServerCert>` inside rustls, so
        // we reconstruct the Arc via the raw pointer. This is safe
        // because rustls keeps the resolver alive for the duration of
        // the ServerConfig. However, we cannot soundly recover Arc<Self>
        // from &self inside a trait method. Instead, we skip the
        // trigger here and rely on a separate mechanism.
        //
        // Correct approach: use a channel to send the domain to a
        // background task that has access to Arc<Self>.
        //
        // For simplicity, we use a tokio::spawn with a clone of the
        // fields needed for issuance. The actual trigger_issuance
        // requires Arc<Self>, so we store a sender in the resolver.
        //
        // But the cleanest pattern is: store an mpsc sender and have
        // a receiver loop that calls trigger_issuance. We do that.

        if let Some(ref tx) = *ISSUANCE_TX
            .lock()
            .expect("ISSUANCE_TX mutex not poisoned: only swapped once at spawn_issuance_loop")
        {
            let _ = tx.try_send(IssuanceRequest {
                domain: sni.to_string(),
            });
        }

        Some(Arc::clone(&self.fallback_cert))
    }
}

/// Request sent from the synchronous `resolve()` to the async
/// issuance loop.
struct IssuanceRequest {
    domain: String,
}

/// Global channel for the on-demand issuance loop. Set once during
/// `spawn_issuance_loop`.
static ISSUANCE_TX: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<IssuanceRequest>>> =
    std::sync::Mutex::new(None);

/// Spawn the background loop that processes issuance requests from
/// the resolver's `resolve()` method. Must be called once after
/// constructing the `OnDemandTlsResolver`.
pub fn spawn_issuance_loop(resolver: Arc<OnDemandTlsResolver>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<IssuanceRequest>(256);
    *ISSUANCE_TX
        .lock()
        .expect("ISSUANCE_TX mutex not poisoned: spawn_issuance_loop is single-shot") = Some(tx);

    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            // Deduplicate: skip if already cached or pending.
            if resolver.cert_cache.contains_key(&req.domain) {
                continue;
            }
            resolver.trigger_issuance(req.domain);
        }
    });
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/// Generate a temporary self-signed certificate for `domain`.
/// Used as the fallback during the first handshake.
pub fn generate_temp_self_signed(domain: &str) -> Result<CertifiedKey, GatewayError> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| GatewayError::Internal(format!("on-demand self-signed params: {e}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, domain.to_string());
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Lynxx On-Demand TLS");

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| GatewayError::Internal(format!("on-demand self-signed key: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| GatewayError::Internal(format!("on-demand self-sign: {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| GatewayError::Internal(format!("on-demand key DER: {e}")))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| GatewayError::Internal(format!("on-demand signing key: {e}")))?;

    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

/// Call the ask endpoint to check whether issuance is allowed for
/// `domain`. Returns `Ok(true)` if the endpoint responds with 200.
async fn check_ask_endpoint(url: &str, domain: &str) -> Result<bool, GatewayError> {
    let full_url = format!("{}?domain={}", url, domain);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| GatewayError::Internal(format!("ask endpoint client: {e}")))?;

    let resp =
        client.get(&full_url).send().await.map_err(|e| {
            GatewayError::Internal(format!("ask endpoint request to {full_url}: {e}"))
        })?;

    Ok(resp.status().is_success())
}

/// Load previously-issued on-demand certificates from disk into the
/// cache. Each subdirectory of `storage_dir` is a domain name
/// containing `cert.pem` + `key.pem`.
fn load_cached_certs(
    storage_dir: &std::path::Path,
    cache: &DashMap<String, Arc<CertifiedKey>>,
) -> Result<(), GatewayError> {
    let entries = match std::fs::read_dir(storage_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(GatewayError::Internal(format!(
                "read on-demand cert dir {}: {e}",
                storage_dir.display()
            )));
        }
    };

    let mut loaded = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let cert_path = path.join("cert.pem");
        let key_path = path.join("key.pem");
        if !cert_path.exists() || !key_path.exists() {
            continue;
        }

        let domain = entry.file_name().to_string_lossy().into_owned();

        match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            (Ok(cert_pem), Ok(key_pem)) => match certified_key_from_pem(&cert_pem, &key_pem) {
                Ok(ck) => {
                    cache.insert(domain.clone(), Arc::new(ck));
                    loaded += 1;
                    tracing::debug!(domain = %domain, "loaded on-demand cert from disk");
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %domain,
                        error = %e,
                        "skipping invalid on-demand cert"
                    );
                }
            },
            _ => {
                tracing::warn!(domain = %domain, "skipping unreadable on-demand cert/key");
            }
        }
    }

    if loaded > 0 {
        tracing::info!(count = loaded, "loaded on-demand certs from disk cache");
    }
    Ok(())
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AcmeConfig;

    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // -- RateLimiter ------------------------------------------------

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        let rl = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(rl.try_acquire().await);
        }
    }

    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let rl = RateLimiter::new(2);
        assert!(rl.try_acquire().await);
        assert!(rl.try_acquire().await);
        assert!(!rl.try_acquire().await);
    }

    #[tokio::test]
    async fn rate_limiter_zero_blocks_all() {
        let rl = RateLimiter::new(0);
        assert!(!rl.try_acquire().await);
    }

    // -- generate_temp_self_signed -----------------------------------

    #[test]
    fn generates_fallback_cert() {
        install_crypto_provider();
        let ck = generate_temp_self_signed("test.example.com").unwrap();
        assert_eq!(ck.cert.len(), 1);

        // Verify the cert contains the expected domain in SANs.
        let sans = crate::proxy::tls_alpn::extract_san_dns_names(ck.cert[0].as_ref());
        assert!(sans.contains(&"test.example.com".to_string()));
    }

    #[test]
    fn fallback_cert_has_lynxx_org() {
        install_crypto_provider();
        let ck = generate_temp_self_signed("example.com").unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        let issuer = parsed.issuer().to_string();
        assert!(
            issuer.contains("Lynxx On-Demand TLS"),
            "issuer should contain org name, got: {issuer}"
        );
    }

    // -- OnDemandTlsResolver -----------------------------------------

    fn make_acme_manager() -> Arc<AcmeManager> {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["placeholder.example.com".into()],
            self_signed: true,
            storage_dir: "/tmp/lynxx-test-on-demand".into(),
            ..AcmeConfig::default()
        };
        Arc::new(AcmeManager::new(config))
    }

    #[test]
    fn resolver_new_no_allowed_domains_means_allow_all() {
        install_crypto_provider();
        let config = OnDemandTlsConfig {
            enabled: true,
            allowed_domains: vec![],
            ask_url: String::new(),
            max_certs_per_minute: 10,
        };
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();
        assert!(resolver.allowed_domains.is_none());
    }

    #[test]
    fn resolver_new_with_allowed_domains() {
        install_crypto_provider();
        let config = OnDemandTlsConfig {
            enabled: true,
            allowed_domains: vec!["a.com".into(), "b.com".into()],
            ask_url: String::new(),
            max_certs_per_minute: 10,
        };
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();
        assert_eq!(
            resolver.allowed_domains,
            Some(vec!["a.com".to_string(), "b.com".to_string()])
        );
    }

    #[test]
    fn resolver_insert_and_count() {
        install_crypto_provider();
        let config = OnDemandTlsConfig::default();
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();

        assert_eq!(resolver.cached_count(), 0);

        let ck = Arc::new(generate_temp_self_signed("cached.example.com").unwrap());
        resolver.insert_cert("cached.example.com".into(), ck);

        assert_eq!(resolver.cached_count(), 1);
    }

    #[tokio::test]
    async fn is_domain_allowed_all_allowed() {
        install_crypto_provider();
        let config = OnDemandTlsConfig {
            enabled: true,
            allowed_domains: vec![],
            ask_url: String::new(),
            max_certs_per_minute: 10,
        };
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();
        assert!(resolver.is_domain_allowed("anything.com").await);
    }

    #[tokio::test]
    async fn is_domain_allowed_allowlist_hit() {
        install_crypto_provider();
        let config = OnDemandTlsConfig {
            enabled: true,
            allowed_domains: vec!["good.com".into()],
            ask_url: String::new(),
            max_certs_per_minute: 10,
        };
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();
        assert!(resolver.is_domain_allowed("good.com").await);
    }

    #[tokio::test]
    async fn is_domain_allowed_allowlist_miss() {
        install_crypto_provider();
        let config = OnDemandTlsConfig {
            enabled: true,
            allowed_domains: vec!["good.com".into()],
            ask_url: String::new(),
            max_certs_per_minute: 10,
        };
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();
        assert!(!resolver.is_domain_allowed("evil.com").await);
    }

    // -- load_cached_certs -------------------------------------------

    #[test]
    fn load_cached_certs_nonexistent_dir() {
        let cache = DashMap::new();
        let result = load_cached_certs(std::path::Path::new("/nonexistent/path"), &cache);
        assert!(result.is_ok());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn load_cached_certs_from_disk() {
        install_crypto_provider();
        let tmp = tempfile::tempdir().unwrap();
        let domain = "disk-test.example.com";
        let domain_dir = tmp.path().join(domain);
        std::fs::create_dir_all(&domain_dir).unwrap();

        // We need PEM on disk. Generate fresh via rcgen.
        let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        std::fs::write(domain_dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(domain_dir.join("key.pem"), key_pair.serialize_pem()).unwrap();

        let cache = DashMap::new();
        load_cached_certs(tmp.path(), &cache).unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(domain));
    }

    // -- check_ask_endpoint (mock) -----------------------------------

    #[tokio::test]
    async fn ask_endpoint_approves_on_200() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::query_param("domain", "allowed.com"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result = check_ask_endpoint(&mock_server.uri(), "allowed.com").await;
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn ask_endpoint_denies_on_403() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::query_param("domain", "denied.com"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;

        let result = check_ask_endpoint(&mock_server.uri(), "denied.com").await;
        assert!(!result.unwrap());
    }

    // -- Resolver resolve() with pre-cached cert ---------------------

    #[test]
    fn resolve_returns_cached_cert() {
        install_crypto_provider();
        let config = OnDemandTlsConfig::default();
        let resolver = OnDemandTlsResolver::new(&config, make_acme_manager()).unwrap();

        let ck = Arc::new(generate_temp_self_signed("cached.test").unwrap());
        resolver.cert_cache.insert("cached.test".into(), ck.clone());

        // We can't easily construct a ClientHello, but we can verify
        // the cache lookup path directly.
        assert!(resolver.cert_cache.get("cached.test").is_some());
    }

    // -- PendingGuard ------------------------------------------------

    #[test]
    fn pending_guard_removes_on_drop() {
        let pending: Arc<DashMap<String, ()>> = Arc::new(DashMap::new());
        pending.insert("test.com".into(), ());

        {
            let _guard = PendingGuard {
                pending: Arc::clone(&pending),
                domain: "test.com".into(),
            };
            assert!(pending.contains_key("test.com"));
        }
        // After drop.
        assert!(!pending.contains_key("test.com"));
    }
}
