//! License gating — keyx-backed signed-bundle model.
//!
//! Vexarr ops mints a licence bundle via `keyx license issue` (or the
//! `POST /v1/keys/{urn}/sign-license` endpoint directly). The customer
//! pastes the resulting `{license_urn, payload, signature}` into their
//! lynxx config (`[keyx].license_urn`, `[license].payload`,
//! `[license].signature`). On boot, lynxx asks keyx whether the
//! signature still matches against an active signing key. A successful
//! verify is cached at `~/.lynxx/license.cache.json` (or
//! `$LYNXX_CACHE_DIR/license.cache.json`) so a transient keyx outage
//! doesn't bring the gateway down — the offline grace is
//! [`OFFLINE_GRACE_DAYS`].
//!
//! ## No-licence fallback
//!
//! When `[keyx]` is *not* configured, `License::load` returns a
//! permissive default (Enterprise tier, no caps, no kill-switch).
//! This is the right default for self-host / dev / internal builds —
//! lynxx is functionally feature-complete without keyx, and there's no
//! customer model to enforce restrictions against.
//!
//! ## Re-verifier
//!
//! [`spawn_license_refresher`] re-checks the bundle against keyx every
//! [`REVERIFY_INTERVAL_SECS`] and flips an atomic kill-switch on a
//! confirmed `valid = false` (revocation). Network failures leave the
//! switch alone — the cache covers them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use crate::config::LicenseSettings;
use crate::integrations::abstraction::{LicenseVerifier, VerifierError};
use crate::quota::PlanTier;
use std::sync::Arc;

const OFFLINE_GRACE_DAYS: i64 = 7;
/// How often the running gateway re-verifies the licence against keyx.
const REVERIFY_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours

/// A verified, ready-to-use licence.
#[derive(Debug, Clone)]
pub struct License {
    pub customer_id: String,
    pub tier: PlanTier,
    pub expires_at: Option<DateTime<Utc>>,
    pub from_cache: bool,
    pub max_nodes: Option<u32>,
    pub active_nodes: u32,
    pub allow_overage: bool,
    pub monthly_call_limit: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("[license].payload + [license].signature required when [keyx] is configured")]
    Missing,
    #[error("licence verification rejected: {0}")]
    Rejected(String),
    #[error("licence verifier unreachable and no cached licence available: {0}")]
    Offline(String),
    #[error("cached licence expired (no successful verify in {0} days)")]
    StaleCache(i64),
    #[error("licence response malformed: {0}")]
    Malformed(String),
}

/// Payload schema embedded in every signed bundle. Vexarr's
/// `keyx license issue` builds this; lynxx parses it locally and asks
/// keyx to confirm the signature.
#[derive(Debug, Serialize, Deserialize)]
struct VerifyResponse {
    #[serde(alias = "customer_id")]
    customer_urn: String,
    tier: String,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    max_nodes: Option<u32>,
    #[serde(default)]
    active_nodes: u32,
    #[serde(default)]
    monthly_call_limit: Option<u64>,
    #[serde(default)]
    allow_overage: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    api_key_hash: String,
    customer_id: String,
    tier: String,
    expires_at: Option<i64>,
    verified_at: i64,
    #[serde(default)]
    max_nodes: Option<u32>,
    #[serde(default)]
    active_nodes: Option<u32>,
}

impl License {
    /// Load and verify the licence.
    ///
    /// * `verifier = Some(…)` + `[license].payload` + `signature` set →
    ///   verify the signed bundle against the supplied backend.
    /// * `verifier = None` → return a permissive default. Used for
    ///   self-host / dev / internal-only deployments.
    /// * `verifier = Some(…)` but bundle missing → `Missing` error.
    pub async fn load(
        license_cfg: &LicenseSettings,
        verifier: Option<&dyn LicenseVerifier>,
    ) -> Result<Self, LicenseError> {
        let Some(verifier) = verifier else {
            return Ok(Self::unverified_default());
        };
        if license_cfg.payload.trim().is_empty() || license_cfg.signature.trim().is_empty() {
            return Err(LicenseError::Missing);
        }
        Self::load_via_verifier(license_cfg, verifier).await
    }

    /// Permissive default for unlicensed deployments. Enterprise tier,
    /// no quotas, never expires, no kill-switch.
    fn unverified_default() -> Self {
        License {
            customer_id: "unverified".into(),
            tier: PlanTier::Enterprise,
            expires_at: None,
            from_cache: false,
            max_nodes: None,
            active_nodes: 0,
            allow_overage: true,
            monthly_call_limit: None,
        }
    }

    async fn load_via_verifier(
        license_cfg: &LicenseSettings,
        verifier: &dyn LicenseVerifier,
    ) -> Result<Self, LicenseError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;

        let payload = B64
            .decode(license_cfg.payload.trim())
            .map_err(|e| LicenseError::Malformed(format!("license.payload not base64: {e}")))?;
        let parsed: VerifyResponse = serde_json::from_slice(&payload)
            .map_err(|e| LicenseError::Malformed(format!("license payload JSON: {e}")))?;
        let signature = license_cfg.signature.trim().to_string();
        let cache_id = signature.as_str();

        match verifier.verify_license(&payload, &signature).await {
            Ok(true) => {
                let lic = License::from_verify_response(&parsed, false);
                let _ = write_cache(cache_id, &parsed);
                Ok(lic)
            }
            Ok(false) => Err(LicenseError::Rejected(
                "verifier rejected the licence signature (revoked or tampered)".into(),
            )),
            Err(VerifierError::Transport(e)) | Err(VerifierError::Http { body: e, .. }) => {
                match read_cache(cache_id)? {
                    Some(entry) => License::from_cache_entry(entry),
                    None => Err(LicenseError::Offline(e)),
                }
            }
            Err(VerifierError::Malformed(e)) => Err(LicenseError::Malformed(e)),
            Err(VerifierError::Rejected(e)) => Err(LicenseError::Rejected(e)),
            Err(VerifierError::NotConfigured) => Err(LicenseError::Missing),
        }
    }

    fn from_verify_response(resp: &VerifyResponse, from_cache: bool) -> Self {
        License {
            customer_id: resp.customer_urn.clone(),
            tier: PlanTier::from_str(&resp.tier),
            expires_at: resp
                .expires_at
                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
            from_cache,
            max_nodes: resp.max_nodes,
            active_nodes: resp.active_nodes,
            allow_overage: resp.allow_overage,
            monthly_call_limit: resp.monthly_call_limit,
        }
    }

    fn from_cache_entry(entry: CacheEntry) -> Result<Self, LicenseError> {
        let age_days = (Utc::now().timestamp() - entry.verified_at).max(0) / 86_400;
        if age_days > OFFLINE_GRACE_DAYS {
            return Err(LicenseError::StaleCache(age_days));
        }
        let tier = PlanTier::from_str(&entry.tier);
        Ok(License {
            customer_id: entry.customer_id,
            tier,
            expires_at: entry
                .expires_at
                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
            from_cache: true,
            max_nodes: entry.max_nodes,
            active_nodes: entry.active_nodes.unwrap_or(0),
            allow_overage: matches!(tier, PlanTier::Pro | PlanTier::Business),
            monthly_call_limit: tier.monthly_limit(),
        })
    }

    /// Days until the licence expires, clamped at zero. `None` for
    /// perpetual (Business/Enterprise without expiry).
    pub fn days_remaining(&self) -> Option<i64> {
        self.expires_at
            .map(|exp| (exp - Utc::now()).num_days().max(0))
    }
}

/// Live licence state shared across the gateway. Wraps an
/// `AtomicBool` kill-switch that the re-verifier flips off on a
/// confirmed rejection — customer revocation kicks in within
/// `REVERIFY_INTERVAL_SECS` instead of waiting for the offline cache
/// to expire.
#[derive(Clone)]
pub struct LicenseState {
    inner: std::sync::Arc<LicenseStateInner>,
}

struct LicenseStateInner {
    /// `Some` when a verifier-backed re-verifier is running; `None`
    /// for the unlicensed default (no re-verifier, no kill-switch).
    refresh: Option<VerifierRefresh>,
    active: std::sync::atomic::AtomicBool,
    tier: std::sync::RwLock<PlanTier>,
    node_counts: std::sync::RwLock<(u32, Option<u32>)>,
}

#[derive(Clone)]
struct VerifierRefresh {
    verifier: Arc<dyn LicenseVerifier>,
    payload: Vec<u8>,
    signature: String,
}

impl LicenseState {
    /// Unlicensed-default state. No kill-switch, no re-verifier.
    pub fn unverified(tier: PlanTier) -> Self {
        Self {
            inner: std::sync::Arc::new(LicenseStateInner {
                refresh: None,
                active: std::sync::atomic::AtomicBool::new(true),
                tier: std::sync::RwLock::new(tier),
                node_counts: std::sync::RwLock::new((0, None)),
            }),
        }
    }

    /// Build a verifier-backed state. The background refresher
    /// re-checks the signed `(payload, signature)` bundle against the
    /// verifier on the `REVERIFY_INTERVAL_SECS` schedule.
    pub fn new_verified(
        verifier: Arc<dyn LicenseVerifier>,
        payload: Vec<u8>,
        signature: String,
        tier: PlanTier,
        active_nodes: u32,
        max_nodes: Option<u32>,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(LicenseStateInner {
                refresh: Some(VerifierRefresh {
                    verifier,
                    payload,
                    signature,
                }),
                active: std::sync::atomic::AtomicBool::new(true),
                tier: std::sync::RwLock::new(tier),
                node_counts: std::sync::RwLock::new((active_nodes, max_nodes)),
            }),
        }
    }

    /// Cheap check used in the proxy hot path. `false` only after the
    /// re-verifier sees a `valid: false` from the backend.
    pub fn is_active(&self) -> bool {
        self.inner.active.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `"verified"` when a verifier-backed state is running;
    /// `"unverified"` for the no-licence default. Surfaced on `/status`
    /// so operators can see what mode a node booted into.
    pub fn mode(&self) -> &'static str {
        if self.inner.refresh.is_some() {
            "verified"
        } else {
            "unverified"
        }
    }

    pub fn tier(&self) -> PlanTier {
        *self.inner.tier.read().expect("tier lock poisoned")
    }

    pub fn active_nodes(&self) -> u32 {
        self.inner.node_counts.read().expect("node lock poisoned").0
    }

    pub fn max_nodes(&self) -> Option<u32> {
        self.inner.node_counts.read().expect("node lock poisoned").1
    }

    fn flip_inactive(&self, reason: &str) {
        self.inner
            .active
            .store(false, std::sync::atomic::Ordering::Relaxed);
        tracing::error!(
            reason,
            "licence revoked — gateway is in kill-switch mode; all requests will return 402"
        );
    }
}

/// Spawn the background re-verifier. No-op for unlicensed states.
pub fn spawn_license_refresher(
    state: LicenseState,
    _quota: Option<Arc<crate::quota::QuotaTracker>>,
) {
    let Some(refresh) = state.inner.refresh.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(REVERIFY_INTERVAL_SECS));
        interval.tick().await;
        loop {
            interval.tick().await;
            match refresh
                .verifier
                .verify_license(&refresh.payload, &refresh.signature)
                .await
            {
                Ok(true) => tracing::debug!("licence re-verify ok"),
                Ok(false) => {
                    state.flip_inactive("verifier says licence is no longer valid (revoked)")
                }
                Err(e) => {
                    tracing::warn!(error = %e, "licence re-verify failed; keeping current state")
                }
            }
        }
    });
}

/// Deterministic node identifier — used by the admin status endpoint
/// so a cluster of gateways shows distinct rows. Hashes hostname +
/// data directory + a tenant seed (customer URN or an empty string for
/// unlicensed nodes) so the same physical install always gets the same
/// ID even across restarts.
pub fn compute_instance_id(tenant_seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let hostname = gethostname();
    let data_dir = dirs::home_dir()
        .map(|d| d.join(".lynxx").to_string_lossy().to_string())
        .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(hostname.as_bytes());
    h.update(b":");
    h.update(data_dir.as_bytes());
    h.update(b":");
    h.update(tenant_seed.as_bytes());
    format!("node_{:x}", h.finalize())[..24].to_string()
}

fn cache_path() -> Option<PathBuf> {
    let dir = if let Ok(p) = env::var("LYNXX_CACHE_DIR") {
        PathBuf::from(p)
    } else {
        dirs::home_dir()?.join(".lynxx")
    };
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("license.cache.json"))
}

fn key_fingerprint(api_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(api_key.as_bytes());
    format!("{:x}", h.finalize())
}

fn write_cache(api_key: &str, resp: &VerifyResponse) -> Result<(), std::io::Error> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    let entry = CacheEntry {
        api_key_hash: key_fingerprint(api_key),
        customer_id: resp.customer_urn.clone(),
        tier: resp.tier.clone(),
        expires_at: resp.expires_at,
        verified_at: Utc::now().timestamp(),
        max_nodes: resp.max_nodes,
        active_nodes: Some(resp.active_nodes),
    };
    let body = serde_json::to_vec_pretty(&entry).unwrap();
    std::fs::write(path, body)
}

fn read_cache(api_key: &str) -> Result<Option<CacheEntry>, LicenseError> {
    let Some(path) = cache_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let body =
        std::fs::read(&path).map_err(|e| LicenseError::Offline(format!("cache read: {e}")))?;
    let entry: CacheEntry = serde_json::from_slice(&body)
        .map_err(|e| LicenseError::Malformed(format!("cache parse: {e}")))?;
    if entry.api_key_hash != key_fingerprint(api_key) {
        return Ok(None);
    }
    Ok(Some(entry))
}

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_fingerprint_stable_and_distinct() {
        let a = key_fingerprint("sig-aaa");
        let b = key_fingerprint("sig-aaa");
        let c = key_fingerprint("sig-bbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn unverified_default_is_enterprise_with_no_caps() {
        let lic = License::unverified_default();
        assert_eq!(lic.tier, PlanTier::Enterprise);
        assert!(lic.max_nodes.is_none());
        assert!(lic.monthly_call_limit.is_none());
        assert!(lic.allow_overage);
    }

    #[test]
    fn license_state_unverified_constructor_reports_unverified_mode() {
        let s = LicenseState::unverified(PlanTier::Pro);
        assert_eq!(s.mode(), "unverified");
        assert!(s.is_active());
    }

    #[test]
    fn license_state_verified_constructor_reports_verified_mode() {
        use crate::integrations::abstraction::VerifierError;
        use crate::integrations::LicenseVerifier;
        use async_trait::async_trait;

        struct AlwaysOk;
        #[async_trait]
        impl LicenseVerifier for AlwaysOk {
            async fn verify_license(&self, _: &[u8], _: &str) -> Result<bool, VerifierError> {
                Ok(true)
            }
        }

        let v: Arc<dyn LicenseVerifier> = Arc::new(AlwaysOk);
        let s = LicenseState::new_verified(v, vec![1, 2], "sig".into(), PlanTier::Pro, 0, None);
        assert_eq!(s.mode(), "verified");
    }
}

/// Integration tests for the verifier code path through `License::load`.
/// Exercises the keyx client as a concrete [`LicenseVerifier`] impl —
/// the licence layer itself only knows about the trait.
#[cfg(test)]
mod keyx_load_tests {
    use super::*;
    use crate::config::LicenseSettings;
    use crate::integrations::keyx::{KeyxClient, KeyxConfig};
    use crate::integrations::LicenseVerifier;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use std::sync::Mutex;
    use wiremock::matchers::{header, method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const URN: &str = "00000000-0000-0000-0000-000000000099";

    fn sample_payload_b64() -> String {
        let json = serde_json::json!({
            "customer_urn": "cus_abc",
            "tier": "pro",
            "expires_at": 1893456000_i64,
            "max_nodes": 5,
            "active_nodes": 1,
            "allow_overage": true,
            "monthly_call_limit": 1_000_000,
        });
        B64.encode(serde_json::to_vec(&json).unwrap())
    }

    fn keyx_verifier(uri: String) -> Arc<dyn LicenseVerifier> {
        let c = KeyxClient::new(KeyxConfig {
            base_url: uri,
            service_token: "svc".into(),
            license_urn: URN.into(),
        })
        .unwrap();
        Arc::new(c)
    }

    fn lic_cfg(payload: String, signature: String) -> LicenseSettings {
        LicenseSettings {
            api_key: String::new(),
            payload,
            signature,
        }
    }

    fn envelope(data: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "transactionUrn": "urn:keyx:txn:test",
            "status": "SUCCESS",
            "responseMessage": "OK",
            "responseKey": "SUCCESS",
            "errors": [],
            "timestamp": "2026-05-16T00:00:00+00:00",
            "metadata": {},
            "data": data,
        })
    }

    struct EnvGuard {
        _tmp: tempfile::TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn isolated_env() -> EnvGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        env::set_var("LYNXX_CACHE_DIR", tmp.path());
        EnvGuard {
            _tmp: tmp,
            _lock: lock,
        }
    }

    #[tokio::test]
    async fn keyx_mode_happy_path_returns_parsed_license() {
        let _e = isolated_env();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path(format!("/v1/keys/{}/verify-license", URN)))
            .and(header("authorization", "Bearer svc"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": true }))),
            )
            .mount(&server)
            .await;

        let v = keyx_verifier(server.uri());
        let lic = License::load(
            &lic_cfg(sample_payload_b64(), "sig".into()),
            Some(v.as_ref()),
        )
        .await
        .unwrap();

        assert_eq!(lic.customer_id, "cus_abc");
        assert_eq!(lic.tier, PlanTier::Pro);
        assert_eq!(lic.max_nodes, Some(5));
        assert!(!lic.from_cache);
    }

    #[tokio::test]
    async fn keyx_mode_rejects_when_keyx_says_invalid() {
        let _e = isolated_env();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": false }))),
            )
            .mount(&server)
            .await;
        let v = keyx_verifier(server.uri());
        let err = License::load(
            &lic_cfg(sample_payload_b64(), "tampered".into()),
            Some(v.as_ref()),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LicenseError::Rejected(_)));
    }

    #[tokio::test]
    async fn keyx_mode_offline_without_cache_returns_offline_error() {
        let _e = isolated_env();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;
        let v = keyx_verifier(server.uri());
        let err = License::load(
            &lic_cfg(sample_payload_b64(), "sig-fresh".into()),
            Some(v.as_ref()),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LicenseError::Offline(_)));
    }

    #[tokio::test]
    async fn keyx_mode_offline_falls_back_to_warm_cache() {
        let _e = isolated_env();
        let server = MockServer::start().await;
        let ok_mock = Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": true }))),
            )
            .up_to_n_times(1)
            .mount_as_scoped(&server)
            .await;

        let cfg_l = lic_cfg(sample_payload_b64(), "sig-warm".into());
        let v = keyx_verifier(server.uri());

        let _seed = License::load(&cfg_l, Some(v.as_ref())).await.unwrap();
        drop(ok_mock);

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;
        let lic = License::load(&cfg_l, Some(v.as_ref())).await.unwrap();
        assert!(lic.from_cache);
        assert_eq!(lic.customer_id, "cus_abc");
    }

    #[tokio::test]
    async fn no_verifier_returns_unverified_default() {
        let _e = isolated_env();
        let lic = License::load(&LicenseSettings::default(), None)
            .await
            .unwrap();
        assert_eq!(lic.customer_id, "unverified");
        assert_eq!(lic.tier, PlanTier::Enterprise);
    }

    #[tokio::test]
    async fn verifier_without_bundle_errors_missing() {
        let _e = isolated_env();
        let server = MockServer::start().await;
        let v = keyx_verifier(server.uri());
        let err = License::load(&LicenseSettings::default(), Some(v.as_ref()))
            .await
            .unwrap_err();
        assert!(matches!(err, LicenseError::Missing));
    }
}
