//! License gating — simple API-key model.
//!
//! The user pastes a short key like `lnx_live_abc123` into config or
//! the `LYNXX_API_KEY` env var. On startup the gateway calls the licence
//! server to verify the key; on success it caches the result locally so
//! subsequent restarts work offline for up to 7 days.
//!
//! ## Verify request
//!
//! `GET ${LYNXX_BASE_URL}/v1/license/verify`
//! Header: `Authorization: Bearer <api_key>`
//! (default base: `https://api.lynxx.vexarr.com`)
//!
//! ## Verify response (200)
//!
//! ```json
//! { "customer_id": "cus_abc", "tier": "pro", "expires_at": 1759104800 }
//! ```
//!
//! Any non-200 (401 cancelled, 403 invalid, 5xx server error) is fatal
//! on first start. After a successful verify the result is cached at
//! `~/.lynxx/license.cache.json`. On later restarts a network failure
//! is tolerated for up to `OFFLINE_GRACE_DAYS` after the last good
//! verify; past that the gateway refuses to start.
//!
//! ## Dev-mode keys
//!
//! Debug builds accept keys of the form `lnx_dev_<tier>` (e.g.
//! `lnx_dev_pro`) without contacting the server. Release builds reject
//! them — see `try_dev_key` below. This keeps local development cheap
//! without weakening shipped binaries.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use crate::quota::PlanTier;

const DEFAULT_LYNXX_BASE_URL: &str = "https://api.lynxx.vexarr.com";

fn resolve_lynxx_base_url() -> String {
    env::var("LYNXX_BASE_URL")
        .or_else(|_| env::var("LYNXX_LICENSE_VERIFY_URL").map(|u| {
            u.trim_end_matches("/v1/license/verify").to_string()
        }))
        .unwrap_or_else(|_| DEFAULT_LYNXX_BASE_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn verify_url() -> String {
    format!("{}/v1/license/verify", resolve_lynxx_base_url())
}

/// Whether `url` must use https. Every licence/billing request carries the
/// API key as a bearer token, so it must never reach a *remote* host over
/// cleartext http. Loopback (local auth stubs, CI) is exempt so dev/test
/// setups keep working.
fn https_required(url: &str) -> bool {
    use url::Host;
    match url::Url::parse(url) {
        // Loopback is exempt: `localhost`, all of 127.0.0.0/8, and ::1.
        // `Host`/`is_loopback` handles bracketed IPv6 + the full v4 range,
        // which a plain `host_str()` string-match would miss.
        Ok(u) => match u.host() {
            Some(Host::Domain("localhost")) => false,
            Some(Host::Ipv4(ip)) => !ip.is_loopback(),
            Some(Host::Ipv6(ip)) => !ip.is_loopback(),
            _ => true,
        },
        // Unparseable → fail closed (treat as if https is required).
        Err(_) => true,
    }
}

/// Build the HTTP client used for every licence/billing call. `https_only`
/// is enforced for non-loopback targets, so a misconfigured `http://`
/// `LYNXX_BASE_URL` makes reqwest refuse the request rather than leak the
/// API key in cleartext.
fn lynxx_api_client(timeout_secs: u64, target_url: &str) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(StdDuration::from_secs(timeout_secs))
        .https_only(https_required(target_url))
        .build()
}

/// Ed25519 public key for verifying signed `/v1/license/verify`
/// responses. Compiled into the binary — a MITM cannot forge a
/// valid signature without the billing server's private key.
const VERIFY_PUBLIC_KEY_HEX: &str = "c43513dfc2942cc71b2def4cdcc766422d8ae23bbb2809de223de705b9ce71e9";
const VERIFY_TIMEOUT_SECS: u64 = 10;
const OFFLINE_GRACE_DAYS: i64 = 7;
/// How often the running gateway re-verifies the licence. The startup
/// check is hard-fail; this background check switches the kill-switch
/// off when the server says the key is no longer active.
const REVERIFY_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours
const HEARTBEAT_INTERVAL_SECS: u64 = 5 * 60; // 5 minutes

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
    #[error("API key missing — set LYNXX_API_KEY or [license].api_key in config.toml")]
    Missing,
    #[error("API key format invalid (expected `lnx_live_…` or `lnx_test_…`)")]
    BadFormat,
    #[error("licence server rejected the key: {0}")]
    Rejected(String),
    #[error("licence server unreachable and no cached licence available: {0}")]
    Offline(String),
    #[error("cached licence expired (no successful verify in {0} days)")]
    StaleCache(i64),
    #[error("licence response malformed: {0}")]
    Malformed(String),
    #[error(
        "refusing to send the API key over plaintext http to a non-loopback host: {0} — \
         use an https:// LYNXX_BASE_URL"
    )]
    InsecureUrl(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyResponse {
    /// Server-side identifier — the licence service emits `customer_urn`
    /// (the cross-cutting URN convention). The `alias` keeps older
    /// licence-server deployments + offline caches written by older
    /// binaries usable.
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
    /// Echo of the per-request `x-lynxx-nonce`, signed by the billing
    /// server inside this body. Present only once the server supports it;
    /// when present the client requires it to match (anti-replay). `None`
    /// from current servers — the check is inert until then.
    #[serde(default)]
    nonce: Option<String>,
}

/// On-disk offline cache. Stores the **exact signed response body** plus
/// its Ed25519 signature, not the parsed fields — so the signature is
/// re-verified on read and a hand-edited cache file (e.g. `tier` bumped to
/// enterprise) is rejected the same way an in-flight tamper would be.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    api_key_hash: String,
    verified_at: i64,
    /// Verbatim signed body (UTF-8 JSON exactly as the server sent it).
    body: String,
    /// Hex Ed25519 signature over `body`. `None` only when the original
    /// response was unsigned (debug build / insecure-skip).
    #[serde(default)]
    sig_hex: Option<String>,
}

/// A cache entry whose signature has already been re-verified on read.
struct CachedLicense {
    resp: VerifyResponse,
    verified_at: i64,
}

impl License {
    /// Load an API key from env/config and verify it. Hard-fails the
    /// gateway when missing or rejected. Falls back to a local cache if
    /// the server is unreachable but a recent successful verify exists.
    pub async fn load(config_api_key: Option<&str>) -> Result<Self, LicenseError> {
        let api_key = match env::var("LYNXX_API_KEY").ok() {
            Some(k) if !k.trim().is_empty() => k,
            _ => match config_api_key {
                Some(k) if !k.trim().is_empty() => k.to_string(),
                _ => return Err(LicenseError::Missing),
            },
        };
        let api_key = api_key.trim().to_string();

        if let Some(lic) = try_dev_key(&api_key) {
            return Ok(lic);
        }

        if !is_valid_format(&api_key) {
            return Err(LicenseError::BadFormat);
        }

        let vurl = verify_url();
        // Fail closed: never transmit the API key to a remote host over
        // cleartext http (loopback stubs are exempt).
        if https_required(&vurl) && !vurl.starts_with("https://") {
            return Err(LicenseError::InsecureUrl(vurl));
        }

        match verify_online(&api_key, &vurl).await {
            Ok(verified) => {
                let lic = License::from_verify(&verified.resp, false);
                let _ = write_cache(&api_key, &verified.body, verified.sig_hex.as_deref());
                Ok(lic)
            }
            Err(LicenseError::Rejected(_)) => Err(LicenseError::Rejected(
                "key not active (cancelled or invalid)".into(),
            )),
            Err(net_err) => match read_cache(&api_key)? {
                Some(cached) => {
                    let age_days =
                        (Utc::now().timestamp() - cached.verified_at).max(0) / 86_400;
                    if age_days > OFFLINE_GRACE_DAYS {
                        Err(LicenseError::StaleCache(age_days))
                    } else {
                        Ok(License::from_verify(&cached.resp, true))
                    }
                }
                None => Err(net_err),
            },
        }
    }

    /// Build a `License` from a verified response. Shared by the online
    /// path and the (signature-re-verified) offline cache path so both
    /// derive every field identically — no tier-guessing in the offline
    /// branch.
    fn from_verify(resp: &VerifyResponse, from_cache: bool) -> Self {
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

    /// Days until the licence expires, clamped at zero. `None` for
    /// perpetual (Business/Enterprise without expiry).
    pub fn days_remaining(&self) -> Option<i64> {
        self.expires_at
            .map(|exp| (exp - Utc::now()).num_days().max(0))
    }
}

/// Live licence state shared across the gateway. Wraps an
/// `AtomicBool` kill-switch that the periodic re-verifier flips off
/// when the licence server reports the key is no longer active —
/// a customer cancellation kicks in within `REVERIFY_INTERVAL_SECS`
/// instead of waiting `OFFLINE_GRACE_DAYS` for the cache to expire.
#[derive(Clone)]
pub struct LicenseState {
    inner: std::sync::Arc<LicenseStateInner>,
}

struct LicenseStateInner {
    api_key: String,
    verify_url: String,
    /// `true` while the licence is good. Flipped to `false` on
    /// confirmed rejection from the licence server. Network failures
    /// and parse errors do NOT flip it — the offline cache plus the
    /// 7-day grace already cover transient outages.
    active: std::sync::atomic::AtomicBool,
    /// Latest known tier. Loaded at startup; refreshed on every
    /// successful re-verify so a tier upgrade / downgrade applies
    /// without a restart.
    tier: std::sync::RwLock<PlanTier>,
    node_counts: std::sync::RwLock<(u32, Option<u32>)>,
}

impl LicenseState {
    pub fn new(
        api_key: impl Into<String>,
        verify_url: impl Into<String>,
        tier: PlanTier,
        active_nodes: u32,
        max_nodes: Option<u32>,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(LicenseStateInner {
                api_key: api_key.into(),
                verify_url: verify_url.into(),
                active: std::sync::atomic::AtomicBool::new(true),
                tier: std::sync::RwLock::new(tier),
                node_counts: std::sync::RwLock::new((active_nodes, max_nodes)),
            }),
        }
    }

    /// Cheap check used in the proxy hot path. Returns `false` after
    /// the re-verifier sees a rejection.
    pub fn is_active(&self) -> bool {
        self.inner.active.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Latest tier from the most recent successful re-verify.
    pub fn tier(&self) -> PlanTier {
        *self.inner.tier.read().expect("tier lock poisoned")
    }

    /// Runtime algorithm tier for the backbone factory.
    ///
    /// A single binary compiles every adapter; this maps the current
    /// subscription plan onto the [`algorithms::backbone::Tier`] that
    /// the factory uses to pick which adapter is instantiated. Cheap
    /// enough to call per-request: one rwlock read + a `match`.
    pub fn algorithm_tier(&self) -> algorithms::backbone::Tier {
        self.tier().algorithm_tier()
    }

    pub fn active_nodes(&self) -> u32 {
        self.inner.node_counts.read().expect("node lock poisoned").0
    }

    pub fn max_nodes(&self) -> Option<u32> {
        self.inner.node_counts.read().expect("node lock poisoned").1
    }

    /// Always `"verified"` — api-key-only mode has no unverified path.
    /// Kept on the status endpoint for backwards compatibility with
    /// dashboards that still read the field.
    pub fn mode(&self) -> &'static str {
        "verified"
    }

    /// Forward an arbitrary customer api key to the licence backend for
    /// validation. The node dashboard's sign-in flow uses this so it
    /// never has to talk to the licence server directly.
    pub async fn validate_key(
        &self,
        api_key: &str,
    ) -> Result<crate::integrations::abstraction::LicenseInfo, crate::integrations::abstraction::VerifierError> {
        use crate::integrations::abstraction::{LicenseInfo, VerifierError};
        match verify_online(api_key, &self.inner.verify_url).await {
            Ok(verified) => {
                let resp = verified.resp;
                Ok(LicenseInfo {
                    customer_urn: resp.customer_urn,
                    tier: resp.tier,
                    expires_at: resp.expires_at,
                    max_nodes: resp.max_nodes,
                    active_nodes: resp.active_nodes,
                    monthly_call_limit: resp.monthly_call_limit,
                    allow_overage: resp.allow_overage,
                })
            }
            Err(LicenseError::Rejected(msg)) => Err(VerifierError::Rejected(msg)),
            Err(LicenseError::Offline(msg)) => Err(VerifierError::Transport(msg)),
            Err(LicenseError::Malformed(msg)) => Err(VerifierError::Malformed(msg)),
            Err(other) => Err(VerifierError::Transport(other.to_string())),
        }
    }

    fn update_node_counts(&self, active: u32, max: Option<u32>) {
        let mut nc = self.inner.node_counts.write().expect("node lock poisoned");
        *nc = (active, max);
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

    /// Re-arm the kill-switch. Counterpart to [`flip_inactive`] — without
    /// this the switch was write-once (only ever set to `false`), so a
    /// single stray `flagged` usage-report or a transient rejection wedged
    /// the gateway into permanent 402 until a full process restart, even
    /// after an authoritative, signature-verified re-verify confirmed the
    /// key was active again. Called from the re-verifier success branch so
    /// a confirmed-active `/v1/license/verify` restores service.
    fn flip_active(&self) {
        let was_active = self
            .inner
            .active
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        if !was_active {
            tracing::warn!(
                "licence re-verified as active — clearing kill-switch; requests resume"
            );
        }
    }

    fn update_tier(&self, new_tier: PlanTier) {
        let mut t = self.inner.tier.write().expect("tier lock poisoned");
        if *t != new_tier {
            tracing::info!(old = %t.as_str(), new = %new_tier.as_str(), "licence tier updated");
            *t = new_tier;
        }
    }
}

/// Spawn the background re-verifier. Hits the licence server every
/// `REVERIFY_INTERVAL_SECS` and:
///   - On success → updates the tier and refreshes the offline cache.
///   - On rejection → flips the kill-switch off; the proxy starts
///     returning 402 Payment Required for every request.
///   - On network failure → logs a warning, leaves the switch alone.
///     The 7-day cache still covers extended outages.
pub fn spawn_license_refresher(
    state: LicenseState,
    quota: Option<std::sync::Arc<crate::quota::QuotaTracker>>,
) {
    if state.inner.api_key.starts_with("lnx_dev_") {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(REVERIFY_INTERVAL_SECS));
        interval.tick().await;
        loop {
            interval.tick().await;
            match verify_online(&state.inner.api_key, &state.inner.verify_url).await {
                Ok(verified) => {
                    let resp = &verified.resp;
                    // An authoritative, signature-verified verify confirming
                    // the key is active re-arms the kill-switch. Closes the
                    // bug where a stray usage-report `flagged` (or a transient
                    // rejection) left `active=false` forever with no in-process
                    // path back to service short of a restart.
                    state.flip_active();
                    state.update_tier(PlanTier::from_str(&resp.tier));
                    state.update_node_counts(resp.active_nodes, resp.max_nodes);
                    if let Some(ref q) = quota {
                        q.set_limit(resp.monthly_call_limit);
                        q.set_allow_overage(resp.allow_overage);
                    }
                    let _ = write_cache(
                        &state.inner.api_key,
                        &verified.body,
                        verified.sig_hex.as_deref(),
                    );
                }
                Err(LicenseError::Rejected(msg)) => {
                    state.flip_inactive(&msg);
                }
                Err(other) => {
                    tracing::warn!(error = %other, "licence re-verify failed; keeping current state");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Node registration + heartbeat
// ---------------------------------------------------------------------------

/// Deterministic instance ID for this gateway installation. Hashes
/// hostname + data directory + API key so the same physical install
/// always gets the same ID, avoiding duplicate registrations on restart.
pub fn compute_instance_id(api_key: &str) -> String {
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
    h.update(api_key.as_bytes());
    format!("node_{:x}", h.finalize())[..24].to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("node limit reached ({active}/{max}); upgrade to add more nodes")]
    LimitReached { active: u32, max: u32 },
    #[error("node registration failed: {0}")]
    RegisterFailed(String),
}

#[derive(Debug, Serialize)]
struct RegisterReq {
    instance_id: String,
    hostname: String,
    version: Option<String>,
    ip_address: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    data_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterResp {
    #[allow(dead_code)]
    node_id: i64,
    active_nodes: i64,
    max_nodes: Option<i32>,
}

/// Register this gateway node with the billing API. Returns error if
/// the customer has reached their node limit.
pub async fn register_node(api_key: &str, lynxx_base_url: &str) -> Result<(), NodeError> {
    if api_key.starts_with("lnx_dev_") {
        return Ok(());
    }
    let instance_id = compute_instance_id(api_key);
    let hostname = gethostname();
    let data_dir = dirs::home_dir()
        .map(|d| d.join(".lynxx").to_string_lossy().to_string());

    let url = format!(
        "{}/v1/nodes/register",
        lynxx_base_url.trim_end_matches('/'),
    );
    let body = RegisterReq {
        instance_id,
        hostname,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        ip_address: None,
        os: Some(std::env::consts::OS.to_string()),
        arch: Some(std::env::consts::ARCH.to_string()),
        data_dir,
    };

    let client = lynxx_api_client(VERIFY_TIMEOUT_SECS, &url)
        .map_err(|e| NodeError::RegisterFailed(e.to_string()))?;

    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| NodeError::RegisterFailed(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN {
        let text = resp.text().await.unwrap_or_default();
        if text.contains("node limit") {
            // Bug fix: previously returned LimitReached { active: 0, max: 0 },
            // so the operator log always rendered a literal `(0/0)` regardless
            // of the customer's real cap (e.g. 5/5). The 403 body carries no
            // structured counts here, so surface the server's message verbatim
            // — mirroring the sibling RegisterFailed branch below — instead of
            // fabricating zeros.
            return Err(NodeError::RegisterFailed(text));
        }
        return Err(NodeError::RegisterFailed(text));
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(NodeError::RegisterFailed(format!("{status}: {text}")));
    }

    let reg: RegisterResp = resp
        .json()
        .await
        .map_err(|e| NodeError::RegisterFailed(e.to_string()))?;

    tracing::info!(
        active_nodes = reg.active_nodes,
        max_nodes = ?reg.max_nodes,
        "node registered with billing service"
    );
    Ok(())
}

/// Spawn the background heartbeat loop. Sends a heartbeat to the billing
/// API every 5 minutes so the system knows which nodes are alive.
pub fn spawn_node_heartbeat(api_key: String, lynxx_base_url: String) {
    if api_key.starts_with("lnx_dev_") {
        return;
    }
    let instance_id = compute_instance_id(&api_key);
    let heartbeat_url = format!("{}/v1/nodes/heartbeat", lynxx_base_url.trim_end_matches('/'));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(HEARTBEAT_INTERVAL_SECS));
        interval.tick().await; // skip immediate tick
        let client = match lynxx_api_client(VERIFY_TIMEOUT_SECS, &heartbeat_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "node heartbeat client build failed; not starting");
                return;
            }
        };
        loop {
            interval.tick().await;
            let body = serde_json::json!({ "instance_id": instance_id });
            match client
                .post(&heartbeat_url)
                .bearer_auth(&api_key)
                .json(&body)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("node heartbeat sent");
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "node heartbeat rejected");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "node heartbeat failed");
                }
            }
        }
    });
}

/// Deregister this node on clean shutdown.
pub async fn deregister_node(api_key: &str, lynxx_base_url: &str) {
    if api_key.starts_with("lnx_dev_") {
        return;
    }
    let instance_id = compute_instance_id(api_key);
    let url = format!(
        "{}/v1/nodes/deregister",
        lynxx_base_url.trim_end_matches('/'),
    );
    let body = serde_json::json!({ "instance_id": instance_id });
    let client = lynxx_api_client(5, &url);
    if let Ok(client) = client {
        let _ = client
            .post(&url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await;
        tracing::info!("node deregistered");
    }
}

const USAGE_REPORT_INTERVAL_SECS: u64 = 60;

/// Spawn the background usage reporter. Pushes this node's call counts
/// to the billing API every 60 seconds so overage billing can aggregate
/// across all customer nodes.
pub fn spawn_usage_reporter(
    api_key: String,
    lynxx_base_url: String,
    quota: std::sync::Arc<crate::quota::QuotaTracker>,
    license_state: LicenseState,
) {
    if api_key.starts_with("lnx_dev_") {
        return;
    }
    let instance_id = compute_instance_id(&api_key);
    let report_url = format!("{}/v1/usage/report", lynxx_base_url.trim_end_matches('/'));

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(StdDuration::from_secs(USAGE_REPORT_INTERVAL_SECS));
        interval.tick().await;
        let client = match lynxx_api_client(VERIFY_TIMEOUT_SECS, &report_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "usage reporter client build failed; not starting");
                return;
            }
        };
        loop {
            interval.tick().await;
            let snap = quota.snapshot();
            let body = serde_json::json!({
                "instance_id": instance_id,
                "period": snap.period,
                "calls_total": snap.calls_total,
            });
            match client
                .post(&report_url)
                .bearer_auth(&api_key)
                .json(&body)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if json.get("flagged").and_then(|v| v.as_bool()).unwrap_or(false) {
                            license_state.flip_inactive("tamper detected — account suspended by billing server");
                        }
                    }
                    tracing::debug!(calls = snap.calls_total, "usage report sent");
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "usage report rejected");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "usage report failed");
                }
            }
        }
    });
}

fn is_valid_format(key: &str) -> bool {
    let prefixes = ["lnx_live_", "lnx_test_"];
    prefixes.iter().any(|p| key.starts_with(p)) && key.len() >= 16
}

/// Debug-build escape hatch — `lnx_dev_<tier>` bypasses the server call.
/// Release builds always return `None`, so shipped binaries can't be
/// bypassed by guessing a magic key.
#[cfg(debug_assertions)]
fn try_dev_key(api_key: &str) -> Option<License> {
    let tier_str = api_key.strip_prefix("lnx_dev_")?;
    let tier = match tier_str.to_lowercase().as_str() {
        "free" | "pro" | "business" | "enterprise" => PlanTier::from_str(tier_str),
        _ => return None,
    };
    Some(License {
        customer_id: format!("dev_{}", tier.as_str()),
        tier,
        expires_at: None,
        from_cache: false,
        max_nodes: None,
        active_nodes: 0,
        allow_overage: matches!(tier, PlanTier::Pro | PlanTier::Business),
        monthly_call_limit: tier.monthly_limit(),
    })
}

#[cfg(not(debug_assertions))]
fn try_dev_key(api_key: &str) -> Option<License> {
    // Allow dev keys in release builds for local/CI benchmarking.
    // Production deploys should always use a real API key.
    if std::env::var("LYNXX_ALLOW_DEV_KEY").ok().as_deref() == Some("1") {
        let tier_str = api_key.strip_prefix("lnx_dev_")?;
        let tier = match tier_str.to_lowercase().as_str() {
            "free" | "pro" | "business" | "enterprise" => PlanTier::from_str(tier_str),
            _ => return None,
        };
        return Some(License {
            customer_id: format!("dev_{}", tier.as_str()),
            tier,
            expires_at: None,
            from_cache: false,
            max_nodes: None,
            active_nodes: 0,
            allow_overage: false,
            monthly_call_limit: None,
        });
    }
    None
}

/// A freshly verified online response: the parsed plan plus the exact
/// signed bytes + signature, so the caller can persist a re-verifiable
/// cache entry.
struct VerifiedLicense {
    resp: VerifyResponse,
    body: Vec<u8>,
    sig_hex: Option<String>,
}

async fn verify_online(api_key: &str, url: &str) -> Result<VerifiedLicense, LicenseError> {
    let client = lynxx_api_client(VERIFY_TIMEOUT_SECS, url)
        .map_err(|e| LicenseError::Offline(e.to_string()))?;

    // Per-request anti-replay nonce. Once the billing server echoes this
    // back *inside the signed body* (`VerifyResponse.nonce`), a replayed
    // old response fails the match below. Until the server supports it,
    // the response carries no nonce and the check is inert.
    let nonce = uuid::Uuid::new_v4().to_string();

    let resp = client
        .get(url)
        .bearer_auth(api_key)
        .header("x-lynxx-nonce", &nonce)
        .send()
        .await
        .map_err(|e| LicenseError::Offline(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Rejected(format!("{status}: {body}")));
    }
    if !status.is_success() {
        return Err(LicenseError::Offline(format!("server returned {status}")));
    }

    // Extract the Ed25519 signature header before consuming the body.
    let sig_hex = resp
        .headers()
        .get("x-lynxx-sig")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| LicenseError::Malformed(format!("read body: {e}")))?;

    // Verify the signature if the server sent one. Release builds
    // REQUIRE a valid signature — missing or invalid = rejected.
    // Debug builds warn but continue (for local dev without the key).
    verify_response_signature(&body_bytes, sig_hex.as_deref())?;

    let parsed = serde_json::from_slice::<VerifyResponse>(&body_bytes)
        .map_err(|e| LicenseError::Malformed(e.to_string()))?;

    // Anti-replay: if the (signed) body echoes a nonce, it MUST match the
    // one we just sent. A replayed older response carries a stale nonce.
    if let Some(echoed) = parsed.nonce.as_deref() {
        if echoed != nonce {
            return Err(LicenseError::Rejected(
                "verify response nonce mismatch — possible replay or MITM".into(),
            ));
        }
    }

    Ok(VerifiedLicense {
        resp: parsed,
        body: body_bytes.to_vec(),
        sig_hex,
    })
}

/// Verify the Ed25519 signature on the response body against the
/// compiled-in billing public key.
fn verify_response_signature(
    body: &[u8],
    sig_hex: Option<&str>,
) -> Result<(), LicenseError> {
    use ed25519_dalek::VerifyingKey;

    let pub_bytes = hex::decode(VERIFY_PUBLIC_KEY_HEX)
        .map_err(|_| LicenseError::Malformed("compiled public key is invalid hex".into()))?;
    let pub_key = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LicenseError::Malformed("compiled public key wrong length".into()))?,
    )
    .map_err(|_| LicenseError::Malformed("compiled public key invalid".into()))?;

    verify_signature_with(body, sig_hex, &pub_key)
}

/// Core signature check against an explicit key. Split out from
/// [`verify_response_signature`] so it can be unit-tested with a generated
/// keypair (the compiled key's private half lives only on the billing
/// server). Same policy for both the live response and the offline cache.
fn verify_signature_with(
    body: &[u8],
    sig_hex: Option<&str>,
    pub_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), LicenseError> {
    use ed25519_dalek::{Signature, Verifier};

    match sig_hex {
        Some(hex_str) => {
            let sig_bytes = hex::decode(hex_str).map_err(|_| {
                LicenseError::Rejected(
                    "verify response signature is invalid hex — possible MITM".into(),
                )
            })?;
            let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(
                |_| {
                    LicenseError::Rejected(
                        "verify response signature wrong length — possible MITM".into(),
                    )
                },
            )?);
            pub_key.verify(body, &signature).map_err(|_| {
                LicenseError::Rejected(
                    "verify response signature INVALID — response tampered (possible MITM)".into(),
                )
            })?;
            tracing::debug!("verify response signature valid");
            Ok(())
        }
        None => {
            // No signature header. In release builds, this is fatal —
            // the billing server should always sign. In debug builds,
            // tolerate it for local dev without the signing key.
            //
            // Release-build escape hatch for the bench rig: setting
            // `LYNXX_INSECURE_SKIP_LICENSE_SIG=1` tolerates a missing
            // signature even in release. This lets the gateway run
            // against the local auth stub on the bench VM, which does
            // not have access to the Ed25519 signing key. The env var
            // name is deliberately ugly so nobody enables it in
            // production by accident.
            if cfg!(debug_assertions)
                || env::var("LYNXX_INSECURE_SKIP_LICENSE_SIG").as_deref() == Ok("1")
            {
                tracing::warn!(
                    "verify response has no signature (tolerating — debug build or \
                     LYNXX_INSECURE_SKIP_LICENSE_SIG=1)"
                );
                Ok(())
            } else {
                Err(LicenseError::Rejected(
                    "verify response missing signature — possible MITM or downgrade attack".into(),
                ))
            }
        }
    }
}

fn cache_path() -> Option<PathBuf> {
    let dir = dirs::home_dir()?.join(".lynxx");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("license.cache.json"))
}

fn key_fingerprint(api_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(api_key.as_bytes());
    format!("{:x}", h.finalize())
}

fn write_cache(
    api_key: &str,
    body: &[u8],
    sig_hex: Option<&str>,
) -> Result<(), std::io::Error> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    // The signed body is UTF-8 JSON; store it verbatim so the signature
    // re-verifies byte-for-byte on read. If somehow not UTF-8, skip
    // caching rather than corrupt the signed bytes.
    let Ok(body_str) = std::str::from_utf8(body) else {
        return Ok(());
    };
    let entry = CacheEntry {
        api_key_hash: key_fingerprint(api_key),
        verified_at: Utc::now().timestamp(),
        body: body_str.to_string(),
        sig_hex: sig_hex.map(|s| s.to_string()),
    };
    let data = serde_json::to_vec_pretty(&entry).unwrap();
    std::fs::write(path, data)
}

fn read_cache(api_key: &str) -> Result<Option<CachedLicense>, LicenseError> {
    let Some(path) = cache_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read(&path).map_err(|e| LicenseError::Offline(format!("cache read: {e}")))?;
    // A stale/old-format or unparseable cache is simply ignored (fall
    // through to a fresh verify), not treated as an error.
    let Ok(entry) = serde_json::from_slice::<CacheEntry>(&raw) else {
        return Ok(None);
    };
    if entry.api_key_hash != key_fingerprint(api_key) {
        return Ok(None);
    }

    // Re-verify the Ed25519 signature over the cached body. A hand-edited
    // cache file (e.g. `tier` bumped to enterprise) fails here exactly
    // like an in-flight tamper would. Treat failure as "no usable cache"
    // (and log loudly) rather than trusting it.
    let body = entry.body.as_bytes();
    if let Err(e) = verify_response_signature(body, entry.sig_hex.as_deref()) {
        tracing::warn!(
            error = %e,
            "cached licence failed signature re-verification — ignoring (tampered or corrupt cache)"
        );
        return Ok(None);
    }

    let resp = serde_json::from_slice::<VerifyResponse>(body)
        .map_err(|e| LicenseError::Malformed(format!("cache body parse: {e}")))?;
    Ok(Some(CachedLicense {
        resp,
        verified_at: entry.verified_at,
    }))
}

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// Silence unused import warning when compiled in release mode (Duration
// is only referenced by some helpers via chrono internals).
#[allow(dead_code)]
fn _ensure_duration_used() -> Duration {
    Duration::days(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_key_pro() {
        let lic = try_dev_key("lnx_dev_pro").unwrap();
        assert_eq!(lic.tier, PlanTier::Pro);
        assert_eq!(lic.customer_id, "dev_pro");
    }

    #[test]
    fn dev_key_unknown_tier_rejected() {
        assert!(try_dev_key("lnx_dev_godmode").is_none());
    }

    #[test]
    fn rejects_garbage_format() {
        assert!(!is_valid_format("not-a-key"));
        assert!(!is_valid_format("lnx_live_short"));
        assert!(is_valid_format("lnx_live_abc123def456"));
        assert!(is_valid_format("lnx_test_abc123def456"));
    }

    #[test]
    fn key_fingerprint_stable_and_distinct() {
        let a = key_fingerprint("lnx_live_aaa");
        let b = key_fingerprint("lnx_live_aaa");
        let c = key_fingerprint("lnx_live_bbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    // ── https_only hardening ──

    #[test]
    fn https_required_exempts_loopback_only() {
        // Loopback hosts may use plaintext http (local stubs, CI).
        assert!(!https_required("http://127.0.0.1:9100/v1/license/verify"));
        assert!(!https_required("http://127.0.0.2/x")); // all of 127.0.0.0/8
        assert!(!https_required("http://localhost:9100/v1/license/verify"));
        assert!(!https_required("http://[::1]:9100/v1/license/verify"));
        // Any remote host requires https.
        assert!(https_required("http://api.lynxx.vexarr.com/v1/license/verify"));
        assert!(https_required("http://10.0.0.5/x"));
        // https is always fine.
        assert!(https_required("https://api.lynxx.vexarr.com/v1/license/verify"));
        // Unparseable → fail closed (require https).
        assert!(https_required("not even a url"));
    }

    // ── signature verification (tamper rejection) ──

    fn test_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        // Deterministic seed — no RNG needed, reproducible across runs.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn valid_signature_passes() {
        use ed25519_dalek::Signer;
        let (signing, verifying) = test_keypair();
        let body = br#"{"customer_urn":"cus_x","tier":"pro"}"#;
        let sig_hex = hex::encode(signing.sign(body).to_bytes());
        assert!(verify_signature_with(body, Some(&sig_hex), &verifying).is_ok());
    }

    #[test]
    fn tampered_body_is_rejected() {
        use ed25519_dalek::Signer;
        let (signing, verifying) = test_keypair();
        let body = br#"{"customer_urn":"cus_x","tier":"free"}"#;
        let sig_hex = hex::encode(signing.sign(body).to_bytes());

        // Attacker bumps the tier — same signature, different body.
        let tampered = br#"{"customer_urn":"cus_x","tier":"enterprise"}"#;
        let err = verify_signature_with(tampered, Some(&sig_hex), &verifying);
        assert!(matches!(err, Err(LicenseError::Rejected(_))));
    }

    #[test]
    fn garbage_signature_is_rejected() {
        let (_signing, verifying) = test_keypair();
        let body = br#"{"tier":"pro"}"#;
        // Not valid hex.
        assert!(verify_signature_with(body, Some("zzzz"), &verifying).is_err());
        // Valid hex, wrong length.
        assert!(verify_signature_with(body, Some("deadbeef"), &verifying).is_err());
    }

    // ── cache: signed-blob round-trip + old-format tolerance ──

    #[test]
    fn cache_entry_roundtrips_body_and_sig() {
        let entry = CacheEntry {
            api_key_hash: "abc".into(),
            verified_at: 123,
            body: r#"{"customer_urn":"c","tier":"pro"}"#.into(),
            sig_hex: Some("ff00".into()),
        };
        let json = serde_json::to_vec(&entry).unwrap();
        let back: CacheEntry = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.body, entry.body);
        assert_eq!(back.sig_hex, entry.sig_hex);
        assert_eq!(back.verified_at, 123);
    }

    #[test]
    fn old_format_cache_is_ignored_not_trusted() {
        // A pre-hardening cache file (plaintext fields, no signed `body`)
        // must fail to parse as the new CacheEntry → read_cache treats it
        // as "no cache" rather than trusting the plaintext tier.
        let old = serde_json::json!({
            "api_key_hash": "abc",
            "customer_id": "cus_x",
            "tier": "enterprise",
            "expires_at": null,
            "verified_at": 1,
        });
        let parsed = serde_json::from_slice::<CacheEntry>(old.to_string().as_bytes());
        assert!(parsed.is_err(), "old-format cache must not deserialize as new CacheEntry");
    }

    // ── from_verify field mapping ──

    // ── kill-switch re-arming (regression: write-once active flag) ──

    #[test]
    fn kill_switch_re_arms_after_flip_active() {
        // Regression for the "kill-switch never re-activates" bug: a stray
        // usage-report `flagged` (or transient rejection) called flip_inactive
        // and there was no in-process path back — `active` was write-once.
        // flip_active() (called by the re-verifier's confirmed-active branch)
        // must restore service. Without flip_active this test fails to compile
        // / the gateway stays inactive forever.
        let state = LicenseState::new(
            "lnx_live_abc123def456",
            "https://api.lynxx.vexarr.com/v1/license/verify",
            PlanTier::Pro,
            0,
            None,
        );
        assert!(state.is_active(), "fresh state starts active");

        // Simulate the stray usage-report `flagged` -> kill-switch.
        state.flip_inactive("tamper detected — account suspended by billing server");
        assert!(!state.is_active(), "kill-switch engaged");

        // A subsequent authoritative confirmed-active verify re-arms service.
        state.flip_active();
        assert!(
            state.is_active(),
            "confirmed-active re-verify must clear the kill-switch"
        );
    }

    // ── node-limit error no longer fabricates 0/0 ──

    #[test]
    fn node_limit_error_carries_server_message_not_zero_zero() {
        // Regression for the hardcoded `(0/0)` bug: the node-limit 403 branch
        // used to return LimitReached { active: 0, max: 0 }, so the operator
        // log always showed `(0/0)` even when the customer was really at e.g.
        // 5/5. The fix surfaces the server's body verbatim via RegisterFailed.
        let server_msg = "node limit reached (5/5)";
        let err = NodeError::RegisterFailed(server_msg.to_string());
        let rendered = err.to_string();
        assert!(
            rendered.contains("5/5"),
            "operator log must reflect the real cap, got: {rendered}"
        );
        assert!(
            !rendered.contains("0/0"),
            "must not fabricate 0/0, got: {rendered}"
        );

        // Guard the old behaviour explicitly: the LimitReached Display with
        // zeros is exactly the misleading string we no longer emit.
        let old = NodeError::LimitReached { active: 0, max: 0 }.to_string();
        assert!(
            old.contains("(0/0)"),
            "sanity: the abandoned variant rendered the misleading 0/0"
        );
    }

    #[test]
    fn from_verify_maps_all_fields() {
        let resp = VerifyResponse {
            customer_urn: "cus_42".into(),
            tier: "business".into(),
            expires_at: None,
            scopes: vec![],
            max_nodes: Some(5),
            active_nodes: 2,
            monthly_call_limit: Some(100_000_000),
            allow_overage: true,
            nonce: None,
        };
        let lic = License::from_verify(&resp, true);
        assert_eq!(lic.customer_id, "cus_42");
        assert_eq!(lic.tier, PlanTier::Business);
        assert!(lic.from_cache);
        assert_eq!(lic.max_nodes, Some(5));
        assert_eq!(lic.active_nodes, 2);
        assert!(lic.allow_overage);
        assert_eq!(lic.monthly_call_limit, Some(100_000_000));
    }
}
