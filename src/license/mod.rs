//! Licence gating — keyx-backed api-key model.
//!
//! Customer flow: log into vexarr.com → copy an `lnx_live_…` api key →
//! paste into `LYNXX_API_KEY` (env) or `[license].api_key` (config.toml).
//! On boot, lynxx asks keyx whether the key is still active. Keyx
//! replies with the licence (tier, expiry, node caps, quota); that's
//! the state the gateway runs on.
//!
//! ## Re-verifier
//!
//! [`spawn_license_refresher`] re-validates the api key against keyx
//! every [`REVERIFY_INTERVAL_SECS`] and flips an atomic kill-switch on
//! a confirmed rejection (revocation). Network failures leave the
//! switch alone — the offline cache covers them up to
//! [`OFFLINE_GRACE_DAYS`].
//!
//! ## Offline cache
//!
//! The first successful validate writes
//! `~/.lynxx/license.cache.json` (or `$LYNXX_CACHE_DIR`). On subsequent
//! boots, if keyx is unreachable, the cache covers boot for up to
//! `OFFLINE_GRACE_DAYS` provided the api-key hash matches.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration as StdDuration;

use crate::integrations::abstraction::{LicenseInfo, LicenseVerifier, VerifierError};
use crate::quota::PlanTier;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

const OFFLINE_GRACE_DAYS: i64 = 7;
/// How often the running gateway re-validates the api key against keyx.
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
    #[error("LYNXX_API_KEY (or [license].api_key) is required")]
    Missing,
    #[error("api key rejected: {0}")]
    Rejected(String),
    #[error("keyx unreachable and no cached licence available: {0}")]
    Offline(String),
    #[error("cached licence expired (no successful verify in {0} days)")]
    StaleCache(i64),
    #[error("licence has expired (expired at {0})")]
    Expired(DateTime<Utc>),
    #[error("licence response malformed: {0}")]
    Malformed(String),
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
    #[serde(default)]
    monthly_call_limit: Option<u64>,
    #[serde(default)]
    allow_overage: bool,
    /// Keyed-MAC over the canonical form of the fields above. Binds the
    /// cache to this api key + machine so a copied or hand-edited cache is
    /// rejected. NOTE: this raises the bar against casual tampering but is
    /// NOT a substitute for a server-issued signature — the key holder can
    /// in principle recompute it. TODO: verify an ed25519 signature minted by
    /// the billing server (the gateway already depends on ed25519-dalek).
    #[serde(default)]
    mac: String,
}

impl CacheEntry {
    /// Canonical bytes the MAC is computed over (everything except `mac`).
    fn mac_payload(&self) -> Vec<u8> {
        // Field order is fixed, so this is deterministic.
        format!(
            "{}|{}|{}|{:?}|{}|{:?}|{:?}|{:?}|{}",
            self.api_key_hash,
            self.customer_id,
            self.tier,
            self.expires_at,
            self.verified_at,
            self.max_nodes,
            self.active_nodes,
            self.monthly_call_limit,
            self.allow_overage,
        )
        .into_bytes()
    }
}

/// Per-install MAC key for the offline cache. Derived from the api key and
/// the machine instance id so the cache is non-portable. Not exported.
fn cache_mac_key(api_key: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"lynxx-license-cache-mac-v1\x00");
    h.update(api_key.as_bytes());
    h.update(b"\x00");
    h.update(compute_instance_id(api_key).as_bytes());
    h.finalize().to_vec()
}

fn compute_cache_mac(api_key: &str, entry: &CacheEntry) -> String {
    let mut mac = HmacSha256::new_from_slice(&cache_mac_key(api_key))
        .expect("hmac accepts any key length");
    mac.update(&entry.mac_payload());
    let bytes = mac.finalize().into_bytes();
    hex::encode(bytes)
}

impl License {
    /// Validate the api key against the licence backend. Falls back to
    /// the offline cache (up to `OFFLINE_GRACE_DAYS`) on transport / HTTP
    /// failures; surfaces `Rejected` immediately when keyx confirms the
    /// key is no longer active.
    pub async fn load(api_key: &str, verifier: &dyn LicenseVerifier) -> Result<Self, LicenseError> {
        let key = api_key.trim();
        if key.is_empty() {
            return Err(LicenseError::Missing);
        }

        match verifier.validate_license(key).await {
            Ok(info) => {
                let lic = License::from_info(&info, false);
                lic.enforce_not_expired()?;
                let _ = write_cache(key, &info);
                Ok(lic)
            }
            Err(VerifierError::Rejected(e)) => Err(LicenseError::Rejected(e)),
            Err(VerifierError::Transport(e)) | Err(VerifierError::Http { body: e, .. }) => {
                match read_cache(key)? {
                    Some(entry) => {
                        let lic = License::from_cache_entry(entry)?;
                        // The cached licence's own expiry is still enforced —
                        // a stale offline cache cannot outlive the server-set
                        // expiry even within the offline grace window.
                        lic.enforce_not_expired()?;
                        Ok(lic)
                    }
                    None => Err(LicenseError::Offline(e)),
                }
            }
            Err(VerifierError::Malformed(e)) => Err(LicenseError::Malformed(e)),
            Err(VerifierError::NotConfigured) => Err(LicenseError::Missing),
        }
    }

    /// Reject a licence whose server-set expiry has already passed. Called at
    /// load time; the running gateway keeps enforcing it via
    /// [`LicenseState::is_active`].
    fn enforce_not_expired(&self) -> Result<(), LicenseError> {
        if let Some(exp) = self.expires_at {
            if Utc::now() >= exp {
                return Err(LicenseError::Expired(exp));
            }
        }
        Ok(())
    }

    fn from_info(info: &LicenseInfo, from_cache: bool) -> Self {
        License {
            customer_id: info.customer_urn.clone(),
            tier: PlanTier::from_str(&info.tier),
            expires_at: info
                .expires_at
                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
            from_cache,
            max_nodes: info.max_nodes,
            active_nodes: info.active_nodes,
            allow_overage: info.allow_overage,
            monthly_call_limit: info.monthly_call_limit,
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
            allow_overage: entry.allow_overage,
            monthly_call_limit: entry.monthly_call_limit.or_else(|| tier.monthly_limit()),
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
    refresh: VerifierRefresh,
    active: std::sync::atomic::AtomicBool,
    tier: std::sync::RwLock<PlanTier>,
    node_counts: std::sync::RwLock<(u32, Option<u32>)>,
    /// Server-set expiry as a unix timestamp; `0` means perpetual. Folded
    /// into [`LicenseState::is_active`] so an expired licence trips the same
    /// kill-switch as a revoked one, continuously (not just at boot).
    expires_at: AtomicI64,
    /// Unix timestamp of the last SUCCESSFUL keyx verification. The
    /// re-verifier flips the kill-switch once this falls outside the offline
    /// grace window, so persistently blocking gateway→keyx traffic can no
    /// longer keep a revoked licence alive indefinitely.
    last_verified_at: AtomicI64,
}

#[derive(Clone)]
struct VerifierRefresh {
    verifier: Arc<dyn LicenseVerifier>,
    api_key: String,
}

impl LicenseState {
    /// Build a verifier-backed state. The background refresher
    /// re-validates the api key against the verifier on the
    /// `REVERIFY_INTERVAL_SECS` schedule.
    pub fn new(
        verifier: Arc<dyn LicenseVerifier>,
        api_key: String,
        tier: PlanTier,
        active_nodes: u32,
        max_nodes: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(LicenseStateInner {
                refresh: VerifierRefresh { verifier, api_key },
                active: std::sync::atomic::AtomicBool::new(true),
                tier: std::sync::RwLock::new(tier),
                node_counts: std::sync::RwLock::new((active_nodes, max_nodes)),
                expires_at: AtomicI64::new(expires_at.map(|e| e.timestamp()).unwrap_or(0)),
                last_verified_at: AtomicI64::new(Utc::now().timestamp()),
            }),
        }
    }

    /// Cheap check used in the proxy hot path. `false` after the re-verifier
    /// sees a `Rejected` (revocation) OR once the licence's expiry passes.
    pub fn is_active(&self) -> bool {
        if !self.inner.active.load(Ordering::Relaxed) {
            return false;
        }
        !self.is_expired()
    }

    /// True once the server-set expiry has passed. Perpetual licences
    /// (`expires_at == 0`) never expire.
    pub fn is_expired(&self) -> bool {
        let exp = self.inner.expires_at.load(Ordering::Relaxed);
        exp != 0 && Utc::now().timestamp() >= exp
    }

    /// Refresh the live tier / node caps / expiry from a fresh verify
    /// response so an upgrade or renewal takes effect without a restart.
    fn apply_refresh(&self, info: &LicenseInfo) {
        if let Ok(mut t) = self.inner.tier.write() {
            *t = PlanTier::from_str(&info.tier);
        }
        if let Ok(mut nc) = self.inner.node_counts.write() {
            *nc = (info.active_nodes, info.max_nodes);
        }
        self.inner
            .expires_at
            .store(info.expires_at.unwrap_or(0), Ordering::Relaxed);
        self.inner
            .last_verified_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);
    }

    /// True once we've gone longer than the offline grace window without a
    /// successful keyx verification.
    fn offline_grace_exceeded(&self) -> bool {
        let last = self.inner.last_verified_at.load(Ordering::Relaxed);
        Utc::now().timestamp() - last > OFFLINE_GRACE_DAYS * 86_400
    }

    /// Always `"verified"` now — api-key-only mode has no unverified
    /// path. Kept on the status endpoint for backwards compatibility
    /// with dashboards that still read the field.
    pub fn mode(&self) -> &'static str {
        "verified"
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

    /// Forward an arbitrary customer api key to the licence backend for
    /// validation. The node dashboard's sign-in flow uses this so it
    /// never has to talk to keyx directly — every key check goes
    /// through the gateway.
    pub async fn validate_key(&self, api_key: &str) -> Result<LicenseInfo, VerifierError> {
        self.inner.refresh.verifier.validate_license(api_key).await
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

/// Spawn the background re-verifier. Re-validates the api key against
/// keyx on the [`REVERIFY_INTERVAL_SECS`] schedule. A confirmed
/// rejection flips the kill-switch; network failures leave state alone.
pub fn spawn_license_refresher(
    state: LicenseState,
    _quota: Option<Arc<crate::quota::QuotaTracker>>,
) {
    let refresh = state.inner.refresh.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(REVERIFY_INTERVAL_SECS));
        interval.tick().await;
        loop {
            interval.tick().await;
            match refresh.verifier.validate_license(&refresh.api_key).await {
                Ok(info) => {
                    // Pick up tier upgrades / renewals (new expiry) live.
                    state.apply_refresh(&info);
                    tracing::debug!("licence re-verify ok");
                }
                Err(VerifierError::Rejected(e)) => state.flip_inactive(&e),
                Err(e) => {
                    // Network/transport failure. Tolerate it WITHIN the offline
                    // grace window, but fail closed once we've gone that long
                    // with no successful verify — otherwise an attacker who can
                    // block gateway→keyx traffic keeps a revoked licence alive
                    // forever, defeating the kill-switch.
                    if state.offline_grace_exceeded() {
                        state.flip_inactive(&format!(
                            "no successful licence verify in {OFFLINE_GRACE_DAYS} days ({e})"
                        ));
                    } else {
                        tracing::warn!(error = %e, "licence re-verify failed; within offline grace, keeping current state");
                    }
                }
            }
        }
    });
}

/// Deterministic node identifier — used by the admin status endpoint
/// so a cluster of gateways shows distinct rows. Hashes hostname +
/// data directory + a tenant seed (customer URN) so the same physical
/// install always gets the same ID even across restarts.
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

fn write_cache(api_key: &str, info: &LicenseInfo) -> Result<(), std::io::Error> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    let mut entry = CacheEntry {
        api_key_hash: key_fingerprint(api_key),
        customer_id: info.customer_urn.clone(),
        tier: info.tier.clone(),
        expires_at: info.expires_at,
        verified_at: Utc::now().timestamp(),
        max_nodes: info.max_nodes,
        active_nodes: Some(info.active_nodes),
        monthly_call_limit: info.monthly_call_limit,
        allow_overage: info.allow_overage,
        mac: String::new(),
    };
    entry.mac = compute_cache_mac(api_key, &entry);
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
    // Integrity: a cache whose MAC doesn't verify was hand-edited or copied
    // from another install (the MAC is bound to this api key + machine).
    // Treat it as no usable cache rather than trusting forged tier/expiry.
    let expected = compute_cache_mac(api_key, &entry);
    if !constant_time_eq(entry.mac.as_bytes(), expected.as_bytes()) {
        tracing::warn!("offline licence cache failed integrity check — ignoring");
        return Ok(None);
    }
    // Clock-rollback: a `verified_at` in the future means the wall clock was
    // moved backwards to stretch the offline grace window. Refuse it.
    if Utc::now().timestamp() < entry.verified_at {
        tracing::warn!(
            "offline licence cache verified_at is in the future — clock rollback suspected; ignoring"
        );
        return Ok(None);
    }
    Ok(Some(entry))
}

/// Length-checked constant-time byte comparison for the cache MAC.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    use async_trait::async_trait;

    #[test]
    fn key_fingerprint_stable_and_distinct() {
        let a = key_fingerprint("lnx_live_aaa");
        let b = key_fingerprint("lnx_live_aaa");
        let c = key_fingerprint("lnx_live_bbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn license_state_reports_verified_mode() {
        struct AlwaysOk;
        #[async_trait]
        impl LicenseVerifier for AlwaysOk {
            async fn validate_license(&self, _: &str) -> Result<LicenseInfo, VerifierError> {
                unreachable!()
            }
        }
        let v: Arc<dyn LicenseVerifier> = Arc::new(AlwaysOk);
        let s = LicenseState::new(v, "k".into(), PlanTier::Pro, 0, None, None);
        assert_eq!(s.mode(), "verified");
        assert!(s.is_active());
    }

    #[test]
    fn license_state_inactive_once_expired() {
        struct AlwaysOk;
        #[async_trait]
        impl LicenseVerifier for AlwaysOk {
            async fn validate_license(&self, _: &str) -> Result<LicenseInfo, VerifierError> {
                unreachable!()
            }
        }
        let v: Arc<dyn LicenseVerifier> = Arc::new(AlwaysOk);
        let past = Utc::now() - chrono::Duration::hours(1);
        let s = LicenseState::new(v, "k".into(), PlanTier::Pro, 0, None, Some(past));
        assert!(s.is_expired());
        assert!(!s.is_active(), "an expired licence must not be active");
    }

    #[tokio::test]
    async fn load_rejects_expired_license() {
        struct ExpiredOk;
        #[async_trait]
        impl LicenseVerifier for ExpiredOk {
            async fn validate_license(&self, _: &str) -> Result<LicenseInfo, VerifierError> {
                Ok(LicenseInfo {
                    customer_urn: "cus_x".into(),
                    tier: "pro".into(),
                    expires_at: Some((Utc::now() - chrono::Duration::days(1)).timestamp()),
                    max_nodes: None,
                    active_nodes: 0,
                    monthly_call_limit: None,
                    allow_overage: false,
                })
            }
        }
        let err = License::load("lnx_live_x", &ExpiredOk).await.unwrap_err();
        assert!(matches!(err, LicenseError::Expired(_)));
    }

    #[tokio::test]
    async fn load_returns_missing_when_api_key_blank() {
        struct Never;
        #[async_trait]
        impl LicenseVerifier for Never {
            async fn validate_license(&self, _: &str) -> Result<LicenseInfo, VerifierError> {
                unreachable!("blank key must short-circuit before reaching the verifier")
            }
        }
        let err = License::load("   ", &Never).await.unwrap_err();
        assert!(matches!(err, LicenseError::Missing));
    }

    #[tokio::test]
    async fn load_propagates_rejected_from_verifier() {
        struct Reject;
        #[async_trait]
        impl LicenseVerifier for Reject {
            async fn validate_license(&self, _: &str) -> Result<LicenseInfo, VerifierError> {
                Err(VerifierError::Rejected("revoked".into()))
            }
        }
        let err = License::load("lnx_live_x", &Reject).await.unwrap_err();
        assert!(matches!(err, LicenseError::Rejected(_)));
    }
}
