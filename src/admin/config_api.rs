//! Live config management API — read, replace, patch, validate, and
//! roll back the running gateway configuration with history tracking.
//!
//! Endpoints are mounted under `/admin/v1/config` by [`config_router`].
//! All mutations snapshot the current config before applying, and
//! automatically roll back if validation or re-initialisation fails.

use crate::config::GatewayConfig;
use crate::error::GatewayError;
use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Config store — shared state for the live config + history
// ---------------------------------------------------------------------------

/// In-memory config store that backs the live-config API. Holds the
/// current running config plus the last N snapshots for rollback.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<ConfigStoreInner>>,
}

struct ConfigStoreInner {
    current: GatewayConfig,
    history: VecDeque<ConfigSnapshot>,
}

/// A point-in-time snapshot of the config, kept for rollback and audit.
#[derive(Clone, Serialize)]
pub struct ConfigSnapshot {
    pub timestamp: DateTime<Utc>,
    pub reason: String,
    pub config: GatewayConfig,
}

const MAX_HISTORY: usize = 10;

impl ConfigStore {
    /// Create a new store seeded with the given config.
    pub fn new(initial: GatewayConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConfigStoreInner {
                current: initial,
                history: VecDeque::with_capacity(MAX_HISTORY + 1),
            })),
        }
    }

    /// Return a clone of the current config.
    pub async fn current(&self) -> GatewayConfig {
        self.inner.read().await.current.clone()
    }

    /// Replace the current config, pushing the old one onto the history
    /// ring. Returns the previous config for rollback use.
    pub async fn replace(&self, new: GatewayConfig, reason: String) -> GatewayConfig {
        let mut inner = self.inner.write().await;
        let prev = inner.current.clone();
        inner.history.push_back(ConfigSnapshot {
            timestamp: Utc::now(),
            reason,
            config: prev.clone(),
        });
        if inner.history.len() > MAX_HISTORY {
            inner.history.pop_front();
        }
        inner.current = new;
        prev
    }

    /// Restore a previous config (used during rollback). Does NOT push
    /// an additional history entry to avoid infinite growth on repeated
    /// failures.
    pub async fn restore(&self, config: GatewayConfig) {
        let mut inner = self.inner.write().await;
        inner.current = config;
    }

    /// Return the most recent history snapshots (newest last).
    pub async fn history(&self) -> Vec<ConfigSnapshot> {
        let inner = self.inner.read().await;
        inner.history.iter().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Axum state wrapper
// ---------------------------------------------------------------------------

/// Axum state for the config API sub-router.
#[derive(Clone)]
pub struct ConfigApiState {
    pub store: ConfigStore,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ApplyResult {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rolled_back: Option<bool>,
}

#[derive(Deserialize)]
pub struct PatchBody {
    pub value: serde_json::Value,
}

#[derive(Serialize)]
pub struct ValidateResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct HistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Validation helper
// ---------------------------------------------------------------------------

/// Validate a config by round-tripping through serde. Returns an error
/// string if anything looks wrong.
fn validate_config(cfg: &GatewayConfig) -> Result<(), String> {
    // Round-trip to JSON to ensure serialisability.
    let json = serde_json::to_value(cfg).map_err(|e| format!("serialisation error: {e}"))?;
    let _: GatewayConfig =
        serde_json::from_value(json).map_err(|e| format!("deserialisation error: {e}"))?;

    // Semantic checks.
    if cfg.gateway.proxy_port == 0 {
        return Err("gateway.proxy_port must be non-zero".into());
    }
    if cfg.gateway.admin_port == 0 {
        return Err("gateway.admin_port must be non-zero".into());
    }
    if cfg.gateway.proxy_port == cfg.gateway.admin_port {
        return Err("proxy_port and admin_port must differ".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------

/// Placeholder substituted for secret values in API responses. When a
/// client echoes this value back in a PUT/PATCH we treat it as "keep the
/// existing secret" so the dashboard's read-edit-write loop never clobbers
/// a credential it was never shown.
pub const REDACTED_PLACEHOLDER: &str = "***REDACTED***";

/// True when the JSON object key names a secret whose string value must
/// never leave the process in an API response. Matched case-insensitively.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    // Exact secret field names anywhere in the config tree.
    const EXACT: &[&str] = &[
        "api_key",
        "api_token",
        "secret",
        "secret_access_key",
        "access_key_id",
        "password",
        "passwd",
        "client_secret",
        "private_key",
        "dns_api_token",
        "eab_hmac_key",
        "eab_key",
        "hmac_secret",
        "shared_secret",
        "bearer_token",
        "auth_token",
        "license_key",
        "webhook_secret",
        "encryption_key",
        "signing_key",
    ];
    EXACT.contains(&k.as_str())
        || k.ends_with("_secret")
        || k.ends_with("_password")
        || k.ends_with("_token")
        || k.ends_with("_api_key")
        || k.ends_with("_private_key")
        || k.ends_with("_access_key")
}

/// Keys carrying connection strings that embed credentials in userinfo.
fn is_credential_url_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "database_url" | "db_url" | "dsn" | "connection_string" | "redis_url"
    )
}

/// Mask the `user:password@` userinfo of a URL, preserving the rest so the
/// dashboard can still display which host it points at.
fn mask_url_credentials(s: &str) -> String {
    if let Some(scheme_end) = s.find("://") {
        let after = &s[scheme_end + 3..];
        if let Some(at) = after.find('@') {
            return format!(
                "{}://{}@{}",
                &s[..scheme_end],
                REDACTED_PLACEHOLDER,
                &after[at + 1..]
            );
        }
    }
    s.to_string()
}

/// Recursively replace secret string values with the redaction placeholder.
fn redact_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_secret_key(k) {
                    if val.is_string() {
                        *val = serde_json::Value::String(REDACTED_PLACEHOLDER.to_string());
                        continue;
                    }
                } else if is_credential_url_key(k) {
                    if let serde_json::Value::String(s) = val {
                        *s = mask_url_credentials(s);
                        continue;
                    }
                }
                redact_value(val);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_value(item);
            }
        }
        _ => {}
    }
}

fn is_redacted_string(v: &serde_json::Value) -> bool {
    v.as_str() == Some(REDACTED_PLACEHOLDER)
}

/// Walk an incoming config value and, wherever the client sent back the
/// redaction placeholder (or a masked credential URL), substitute the real
/// value from `current`. This keeps a read-edit-write round trip from
/// destroying secrets the client was never allowed to see.
fn restore_redacted(new: &mut serde_json::Value, current: &serde_json::Value) {
    match (new, current) {
        (serde_json::Value::Object(nmap), serde_json::Value::Object(cmap)) => {
            for (k, nval) in nmap.iter_mut() {
                let Some(cval) = cmap.get(k) else { continue };
                if is_redacted_string(nval) {
                    *nval = cval.clone();
                } else if is_credential_url_key(k)
                    && nval.as_str().is_some_and(|s| s.contains(REDACTED_PLACEHOLDER))
                {
                    *nval = cval.clone();
                } else {
                    restore_redacted(nval, cval);
                }
            }
        }
        (serde_json::Value::Array(narr), serde_json::Value::Array(carr)) => {
            for (i, nval) in narr.iter_mut().enumerate() {
                if let Some(cval) = carr.get(i) {
                    restore_redacted(nval, cval);
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /admin/v1/config` — return the current running config as JSON with
/// all secret values redacted. Mounted behind an Admin-role guard, but we
/// redact regardless so credentials never end up in logs, proxies, or
/// browser history even for legitimate admins.
pub async fn get_config(
    State(state): State<ConfigApiState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let config = state.store.current().await;
    let mut value = serde_json::to_value(&config)
        .map_err(|e| GatewayError::Internal(format!("failed to serialise config: {e}")))?;
    redact_value(&mut value);
    Ok(Json(serde_json::json!({ "config": value })))
}

/// `PUT /admin/v1/config` — replace the entire config atomically.
pub async fn put_config(
    State(state): State<ConfigApiState>,
    Json(mut incoming): Json<serde_json::Value>,
) -> Result<Json<ApplyResult>, GatewayError> {
    // 0. Restore any secret values the client echoed back as the redaction
    //    placeholder (GET never reveals real secrets), then deserialise.
    let current_json = serde_json::to_value(&state.store.current().await)
        .map_err(|e| GatewayError::Internal(format!("failed to serialise current config: {e}")))?;
    restore_redacted(&mut incoming, &current_json);
    let new_config: GatewayConfig = serde_json::from_value(incoming)
        .map_err(|e| GatewayError::BadRequest(format!("invalid config: {e}")))?;

    // 1. Validate the incoming config.
    if let Err(msg) = validate_config(&new_config) {
        return Ok(Json(ApplyResult {
            ok: false,
            message: format!("validation failed: {msg}"),
            rolled_back: None,
        }));
    }

    // 2. Snapshot the current config, then apply the new one.
    let prev = state
        .store
        .replace(new_config.clone(), "PUT /admin/v1/config".into())
        .await;

    // 3. Try to "reinitialise" with the new config. In a full
    //    integration the gateway would reload listeners, plugins, etc.
    //    here. If that fails, roll back.
    if let Err(msg) = try_reinitialize(&new_config).await {
        tracing::warn!("config reinitialise failed, rolling back: {msg}");
        state.store.restore(prev).await;
        return Ok(Json(ApplyResult {
            ok: false,
            message: format!("reinitialise failed: {msg}"),
            rolled_back: Some(true),
        }));
    }

    tracing::info!("config replaced via PUT /admin/v1/config");
    Ok(Json(ApplyResult {
        ok: true,
        message: "config replaced successfully".into(),
        rolled_back: None,
    }))
}

/// `PATCH /admin/v1/config/{path}` — update a specific config section.
///
/// The `path` uses `/` separators, e.g. `gateway/proxy_port`. The
/// request body is `{ "value": <new_value> }`.
pub async fn patch_config(
    State(state): State<ConfigApiState>,
    Path(json_path): Path<String>,
    Json(body): Json<PatchBody>,
) -> Result<Json<ApplyResult>, GatewayError> {
    let current = state.store.current().await;

    // Convert the current config to a mutable JSON value.
    let mut doc = serde_json::to_value(&current)
        .map_err(|e| GatewayError::Internal(format!("failed to serialise current config: {e}")))?;

    // Navigate to the target path.
    let segments: Vec<&str> = json_path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Ok(Json(ApplyResult {
            ok: false,
            message: "empty path — use PUT to replace the entire config".into(),
            rolled_back: None,
        }));
    }

    // Walk to the parent and set the leaf.
    let mut cursor = &mut doc;
    for seg in &segments[..segments.len() - 1] {
        cursor = cursor.get_mut(*seg).ok_or_else(|| {
            GatewayError::BadRequest(format!("path segment '{seg}' not found in config"))
        })?;
    }
    let leaf = segments.last().unwrap();
    // Echoing the redaction placeholder back means "leave the existing secret
    // untouched" — silently skip the write rather than overwriting a real
    // credential with the placeholder string.
    if is_redacted_string(&body.value) {
        return Ok(Json(ApplyResult {
            ok: true,
            message: format!("'{json_path}' left unchanged (redaction placeholder ignored)"),
            rolled_back: None,
        }));
    }
    match cursor {
        serde_json::Value::Object(map) => {
            if !map.contains_key(*leaf) {
                return Err(GatewayError::BadRequest(format!(
                    "key '{leaf}' does not exist at the given path"
                )));
            }
            map.insert(leaf.to_string(), body.value);
        }
        _ => {
            return Err(GatewayError::BadRequest(
                "parent of target path is not an object".into(),
            ));
        }
    }

    // Deserialise back to a typed config.
    let new_config: GatewayConfig = serde_json::from_value(doc)
        .map_err(|e| GatewayError::BadRequest(format!("patched config is invalid: {e}")))?;

    // Validate.
    if let Err(msg) = validate_config(&new_config) {
        return Ok(Json(ApplyResult {
            ok: false,
            message: format!("validation after patch failed: {msg}"),
            rolled_back: None,
        }));
    }

    // Snapshot + apply.
    let prev = state
        .store
        .replace(
            new_config.clone(),
            format!("PATCH /admin/v1/config/{json_path}"),
        )
        .await;

    if let Err(msg) = try_reinitialize(&new_config).await {
        tracing::warn!("config reinitialise failed after PATCH, rolling back: {msg}");
        state.store.restore(prev).await;
        return Ok(Json(ApplyResult {
            ok: false,
            message: format!("reinitialise failed: {msg}"),
            rolled_back: Some(true),
        }));
    }

    tracing::info!("config patched at {json_path}");
    Ok(Json(ApplyResult {
        ok: true,
        message: format!("config patched at '{json_path}'"),
        rolled_back: None,
    }))
}

/// `POST /admin/v1/config/validate` — dry-run validation without applying.
pub async fn validate_config_handler(Json(config): Json<GatewayConfig>) -> Json<ValidateResult> {
    match validate_config(&config) {
        Ok(()) => Json(ValidateResult {
            valid: true,
            error: None,
        }),
        Err(msg) => Json(ValidateResult {
            valid: false,
            error: Some(msg),
        }),
    }
}

/// `GET /admin/v1/config/history` — list the last 10 config changes.
pub async fn config_history(State(state): State<ConfigApiState>) -> Json<Vec<HistoryEntry>> {
    let snaps = state.store.history().await;
    let entries: Vec<HistoryEntry> = snaps
        .into_iter()
        .map(|s| HistoryEntry {
            timestamp: s.timestamp,
            reason: s.reason,
        })
        .collect();
    Json(entries)
}

// ---------------------------------------------------------------------------
// Reinitialisation stub
// ---------------------------------------------------------------------------

/// Attempt to reinitialise gateway components with the new config.
///
/// In a full integration this would propagate port changes, rebuild
/// plugin chains, update TLS listeners, etc. For now it performs
/// extended validation that goes beyond structural checks — the kind
/// of thing that can only fail at apply time (e.g. port conflicts).
///
/// Returns `Err(message)` if the config cannot be applied.
async fn try_reinitialize(cfg: &GatewayConfig) -> Result<(), String> {
    // Extended semantic checks that may fail at apply time.
    if cfg.gateway.tls.enabled {
        if cfg.gateway.tls.cert_path.is_empty() {
            return Err("TLS enabled but cert_path is empty".into());
        }
        if cfg.gateway.tls.key_path.is_empty() {
            return Err("TLS enabled but key_path is empty".into());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// @id tag lookup
// ---------------------------------------------------------------------------

/// Result returned by `GET /admin/v1/config/@id/:tag`.
#[derive(Serialize)]
pub struct IdLookupResult {
    pub kind: String,
    pub index: usize,
    pub value: serde_json::Value,
}

/// `GET /admin/v1/config/@id/:tag` — find a service, route, or plugin
/// config entry by its `@id` tag.
pub async fn get_by_id_tag(
    State(state): State<ConfigApiState>,
    Path(tag): Path<String>,
) -> Result<Json<IdLookupResult>, GatewayError> {
    let config = state.store.current().await;

    for (i, svc) in config.services.iter().enumerate() {
        if svc.id_tag.as_deref() == Some(&tag) {
            let mut value = serde_json::to_value(svc)
                .map_err(|e| GatewayError::Internal(format!("serialisation error: {e}")))?;
            redact_value(&mut value);
            return Ok(Json(IdLookupResult {
                kind: "service".into(),
                index: i,
                value,
            }));
        }
    }

    for (i, rt) in config.routes.iter().enumerate() {
        if rt.id_tag.as_deref() == Some(&tag) {
            let mut value = serde_json::to_value(rt)
                .map_err(|e| GatewayError::Internal(format!("serialisation error: {e}")))?;
            redact_value(&mut value);
            return Ok(Json(IdLookupResult {
                kind: "route".into(),
                index: i,
                value,
            }));
        }
    }

    for (i, pl) in config.plugins.iter().enumerate() {
        if pl.id_tag.as_deref() == Some(&tag) {
            let mut value = serde_json::to_value(pl)
                .map_err(|e| GatewayError::Internal(format!("serialisation error: {e}")))?;
            redact_value(&mut value);
            return Ok(Json(IdLookupResult {
                kind: "plugin".into(),
                index: i,
                value,
            }));
        }
    }

    Err(GatewayError::NotFound(format!("@id tag '{tag}' not found")))
}

// ---------------------------------------------------------------------------
// Router constructor
// ---------------------------------------------------------------------------

/// Build an axum router for the live-config API endpoints. Intended to
/// be nested under `/admin/v1/config` in the main admin router.
pub fn config_router(store: ConfigStore) -> axum::Router {
    let state = ConfigApiState { store };

    axum::Router::new()
        .route("/", axum::routing::get(get_config).put(put_config))
        .route("/@id/:tag", axum::routing::get(get_by_id_tag))
        .route("/*path", axum::routing::patch(patch_config))
        .route("/validate", axum::routing::post(validate_config_handler))
        .route("/history", axum::routing::get(config_history))
        .with_state(state)
}
