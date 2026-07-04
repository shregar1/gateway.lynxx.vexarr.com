//! Axum middleware for admin-API authentication and role enforcement.
//!
//! Two layers compose:
//!   * [`extract_token`]: looks up the bearer token, attaches an
//!     `Option<AdminToken>` to request extensions, and 401s on bad tokens.
//!     When `auth_required` is false (NOT the default), a request with no
//!     Authorization header is allowed through with `CurrentActor(None)` —
//!     an explicit "no admin auth" mode for trusted isolated networks. The
//!     default is `auth_required = true`; first-run setup still works because
//!     the Lynxx license API key is accepted as a master admin credential
//!     (see [`resolve_actor`]).
//!   * [`require_role`]: per-route guard that 403s if the actor's role is
//!     below the route's minimum.

use crate::admin::routes::AdminState;
use crate::auth::{hash_token, AdminToken, Role};
use crate::integrations::{AdminPrincipal, TokenValidator};
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use dashmap::DashMap;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// In-memory cache for verifier-validated admin tokens. Optional —
/// when the cache is `None` (TTL = 0 in config) every admin request
/// hits the verifier. When present, a successful validate populates
/// an entry keyed by the SHA-256 hash of the raw token (raw tokens
/// are never stored in memory); subsequent requests reuse it until
/// `ttl` elapses.
///
/// The TTL is also the upper bound on revocation staleness. Without
/// real-time revocation events from the backend, a revoked token
/// keeps working until the entry expires.
pub struct AdminAuthCache {
    // ahash for the internal admin-token cache. Keys are SHA-256
    // fingerprints of admin bearers — server-side derived, not
    // attacker-controlled — so the default SipHash DoS resistance is
    // wasted on this hot lookup path.
    entries: DashMap<String, CachedEntry, ahash::RandomState>,
    ttl: Duration,
}

struct CachedEntry {
    token: AdminToken,
    expires_at: Instant,
}

impl AdminAuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::with_hasher(ahash::RandomState::default()),
            ttl,
        }
    }

    fn get(&self, token_hash: &str) -> Option<AdminToken> {
        let e = self.entries.get(token_hash)?;
        if e.expires_at > Instant::now() {
            Some(e.token.clone())
        } else {
            // Expired entries fall through to a fresh keyx call; we
            // don't bother removing the row here, the next `insert`
            // overwrites it and any other expired entries are pruned
            // opportunistically below.
            None
        }
    }

    fn insert(&self, token_hash: String, token: AdminToken) {
        self.entries.insert(
            token_hash,
            CachedEntry {
                token,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Cheap: number of live (potentially-stale) entries. Exposed so
    /// tests can assert cache population.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Wrapper around `Option<AdminToken>` so we can `Extension::<CurrentActor>`
/// from handlers without colliding with bare `Option<T>`.
#[derive(Clone, Debug, Default)]
pub struct CurrentActor(pub Option<AdminToken>);

/// Data extracted from a verified PASETO runtime grant.
#[derive(Clone, Debug)]
pub struct GrantActor {
    pub customer_urn: String,
    pub device_id: Uuid,
    pub capabilities: Vec<crate::auth::grant::Capability>,
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response()
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": msg }))).into_response()
}

/// Middleware that validates the PASETO runtime grant token.
/// Required for all "commercial" endpoints where premium features are executed.
pub async fn validate_grant(
    State(state): State<Arc<crate::auth::handshake::HandshakeState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth_header = req.headers().get(header::AUTHORIZATION);
    let token = match auth_header
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => return unauthorized("missing runtime grant token"),
    };

    let claims = match state.grant_manager.verify_grant(token) {
        Ok(c) => c,
        Err(e) => return unauthorized(&format!("invalid grant token: {e}")),
    };

    // Check revocation in DB
    match state.repo.get_runtime_grant_by_token_id(&claims.jti).await {
        Ok(Some(grant)) if grant.revoked_at.is_some() => return unauthorized("grant revoked"),
        Ok(Some(_)) => {}
        _ => return unauthorized("grant session not found"),
    };

    let device_id = Uuid::parse_str(&claims.device_id).unwrap_or_else(|_| Uuid::nil());

    req.extensions_mut().insert(GrantActor {
        customer_urn: claims.sub,
        device_id,
        capabilities: claims.caps,
    });

    next.run(req).await
}

/// Axum middleware: extract bearer token, look it up, attach a
/// [`CurrentActor`] extension. Bootstrap mode (no tokens in DB) lets the
/// request through with `CurrentActor(None)`.
pub async fn extract_token(
    State(state): State<AdminState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let actor = match resolve_actor(&state, req.headers().get(header::AUTHORIZATION)).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    // Best-effort `last_used_at` bump — never blocks the request.
    if let Some(token) = actor.as_ref() {
        let repo = state.repo.clone();
        let id = token.id;
        tokio::spawn(async move {
            if let Err(e) = repo.update_admin_token_last_used(&id, Utc::now()).await {
                tracing::warn!(error = %e, token_id = %id, "failed to update last_used_at");
            }
        });
    }

    req.extensions_mut().insert(CurrentActor(actor));
    next.run(req).await
}

async fn resolve_actor(
    state: &AdminState,
    auth_header: Option<&axum::http::HeaderValue>,
) -> Result<Option<AdminToken>, Response> {
    let header_value = match auth_header {
        Some(h) => h,
        None => {
            if !state.auth_required {
                return Ok(None);
            }
            return Err(unauthorized("missing Authorization header"));
        }
    };

    let raw = header_value
        .to_str()
        .ok()
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let raw = match raw {
        Some(r) => r,
        None => return Err(unauthorized("malformed Authorization header")),
    };

    let is_jwt = raw.split('.').count() == 3;
    if is_jwt {
        if let Some(userx) = state.userx_client.as_ref() {
            match userx.verify_jwt(raw).await {
                Ok(payload) => {
                    let sub_str = payload.get("sub")
                        .and_then(|v| v.as_str())
                        .or_else(|| payload.get("user_urn").and_then(|v| v.as_str()))
                        .unwrap_or("00000000-0000-0000-0000-000000000000");
                    let id = uuid::Uuid::parse_str(sub_str).unwrap_or_else(|_| uuid::Uuid::nil());
                    let scopes: Vec<String> = payload.get("scopes")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let expires_at = payload.get("expires_at")
                        .and_then(|v| v.as_str())
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc));
                    
                    let mut role = Role::Viewer;
                    if let Some(role_val) = payload.get("role").and_then(|v| v.as_str()) {
                        if let Some(r) = map_principal_role(role_val) {
                            role = r;
                        }
                    } else {
                        let scope_strings: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
                        if scope_strings.contains(&"user:admin") || scope_strings.contains(&"admin") {
                            role = Role::Admin;
                        } else if scope_strings.contains(&"user:operator") || scope_strings.contains(&"operator") {
                            role = Role::Operator;
                        } else if scope_strings.contains(&"user:viewer") || scope_strings.contains(&"viewer") {
                            role = Role::Viewer;
                        }
                    }
                    
                    return Ok(Some(AdminToken {
                        id,
                        name: format!("userx:{}", &sub_str.chars().take(8).collect::<String>()),
                        role,
                        created_at: chrono::Utc::now(),
                        expires_at,
                        last_used_at: None,
                        scopes,
                    }));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "userx JWT verification failed");
                    return Err(unauthorized("invalid token"));
                }
            }
        }
    }

    // Fast path: the Lynxx license API key is always a valid master admin
    // credential. Customers can use the same key they got from their account
    // dashboard at lynxx.vexarr.com — no separate token creation needed.
    // Constant-time compare so the master key can't be recovered byte-by-byte
    // via response timing.
    if !state.license_api_key.is_empty()
        && crate::utilities::constant_time_eq(raw.as_bytes(), state.license_api_key.as_bytes())
    {
        return Ok(Some(AdminToken {
            id: uuid::Uuid::nil(),
            name: "license-key".to_string(),
            role: crate::auth::Role::Admin,
            created_at: chrono::Utc::now(),
            expires_at: None,
            last_used_at: None,
            scopes: Vec::new(),
        }));
    }

    let hash = hash_token(raw);
    let token = state
        .repo
        .get_admin_token_by_hash(&hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "admin_tokens lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "auth backend error" })),
            )
                .into_response()
        })?;

    let token = match token {
        Some(t) => t,
        None => {
            // Local miss → cache → verifier.
            if let Some(cache) = state.token_cache.as_ref() {
                if let Some(cached) = cache.get(&hash) {
                    if !cached.is_expired(Utc::now()) {
                        return Ok(Some(cached));
                    }
                }
            }
            if let Some(validator) = state.token_validator.as_ref() {
                let resolved = resolve_via_validator(validator.as_ref(), raw).await?;
                if let Some(tok) = resolved.as_ref() {
                    if let Some(cache) = state.token_cache.as_ref() {
                        cache.insert(hash.clone(), tok.clone());
                    }
                }
                return Ok(resolved);
            }
            return Err(unauthorized("invalid token"));
        }
    };
    if token.is_expired(Utc::now()) {
        return Err(unauthorized("token expired"));
    }
    Ok(Some(token))
}

/// Synthesise an `AdminToken` from a backend-validated principal.
/// Used as the fallback path inside [`resolve_actor`] when the local
/// `admin_tokens` table doesn't know the bearer the caller presented.
async fn resolve_via_validator(
    validator: &dyn TokenValidator,
    raw: &str,
) -> Result<Option<AdminToken>, Response> {
    match validator.validate(raw).await {
        Ok(principal) => admin_token_from_principal(principal),
        Err(e) => {
            tracing::debug!(error = %e, "validator failed");
            Err(unauthorized("invalid token"))
        }
    }
}

fn admin_token_from_principal(p: AdminPrincipal) -> Result<Option<AdminToken>, Response> {
    match map_principal_role(&p.role) {
        Some(role) => Ok(Some(AdminToken {
            id: p.key_urn,
            // First 8 hex chars are enough for log correlation; the
            // full URN goes to the audit log on a separate path.
            name: format!("verifier:{}:{}", p.role, &p.key_urn.to_string()[..8]),
            role,
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            scopes: p.scopes,
        })),
        None => {
            tracing::info!(
                role = %p.role,
                key_urn = %p.key_urn,
                "principal role not permitted on lynxx admin surface"
            );
            Err(unauthorized("token role not permitted on lynxx admin"))
        }
    }
}

/// Map a backend role string onto a lynxx [`Role`]. Conservative:
/// anything we don't recognise denies access rather than silently
/// widening. Vocabulary mirrors keyx's role enum but isn't tied to it
/// — any backend that uses these strings is supported.
fn map_principal_role(role: &str) -> Option<Role> {
    match role.to_ascii_lowercase().as_str() {
        "admin" | "owner" => Some(Role::Admin),
        "service" => Some(Role::Operator),
        "pat" | "viewer" => Some(Role::Viewer),
        _ => None,
    }
}

/// Per-role guards. `axum::middleware::from_fn` needs a concrete async fn,
/// so we provide one per role rather than a generic closure. The dispatch
/// shares [`enforce_role`].
pub async fn require_viewer(req: Request<axum::body::Body>, next: Next) -> Response {
    enforce_role(Role::Viewer, req, next).await
}

/// True when the current actor satisfies a scope requirement. Admins
/// (Role::Admin) implicitly satisfy every scope so the gateway's own
/// master keys keep working without scope-config churn. Legacy local
/// `admin_tokens` rows (which today carry no scopes) only satisfy
/// scopes via the admin shortcut. Keyx-issued tokens satisfy a scope
/// when their principal carried it OR when they're Admin/Owner-mapped.
pub fn actor_has_scope(actor: &CurrentActor, scope: &str) -> bool {
    match actor.0.as_ref() {
        None => true, // bootstrap / auth-disabled mode
        Some(t) if t.role == Role::Admin => true,
        Some(t) => t.scopes.iter().any(|s| s == scope || s == "*"),
    }
}

/// Per-route scope guard. Composes like `require_viewer` /
/// `require_operator`. Use sparingly — most routes are already
/// well-served by role-based guards. Reach for scope when keyx is the
/// source of truth for fine-grained per-key permissions.
pub fn require_scope(
    scope: &'static str,
) -> impl Fn(
    Request<axum::body::Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone {
    move |req, next| {
        Box::pin(async move {
            let actor = req
                .extensions()
                .get::<CurrentActor>()
                .cloned()
                .unwrap_or_default();
            if actor_has_scope(&actor, scope) {
                next.run(req).await
            } else {
                tracing::info!(
                    required_scope = scope,
                    actor_scopes = ?actor.0.as_ref().map(|t| &t.scopes),
                    "scope check denied"
                );
                forbidden(&format!("missing required scope '{scope}'"))
            }
        })
    }
}

pub async fn require_operator(req: Request<axum::body::Body>, next: Next) -> Response {
    enforce_role(Role::Operator, req, next).await
}

pub async fn require_admin(req: Request<axum::body::Body>, next: Next) -> Response {
    enforce_role(Role::Admin, req, next).await
}

async fn enforce_role(min: Role, req: Request<axum::body::Body>, next: Next) -> Response {
    let actor = req
        .extensions()
        .get::<CurrentActor>()
        .cloned()
        .unwrap_or_default();
    match actor.0 {
        None => next.run(req).await, // unauthenticated (auth_required=false)
        Some(token) if token.role >= min => next.run(req).await,
        Some(token) => {
            tracing::info!(
                role = %token.role,
                required = %min,
                token_id = %token.id,
                "RBAC denied"
            );
            forbidden(&format!(
                "role '{}' is below required '{}'",
                token.role, min
            ))
        }
    }
}

/// Convenience: pick the right concrete guard for a role. Returns a fn
/// pointer (`Copy`/`Send`/`Sync`/`'static`) so it composes with
/// `axum::middleware::from_fn`.
pub fn require_role(
    min: Role,
) -> fn(
    Request<axum::body::Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    match min {
        Role::Viewer => |req, next| Box::pin(require_viewer(req, next)),
        Role::Operator => |req, next| Box::pin(require_operator(req, next)),
        Role::Admin => |req, next| Box::pin(require_admin(req, next)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use axum::http::HeaderValue;
    use utilx::vexarr::client::UserxClient;
    use utilx::vexarr::client::mock::{MockBody, MockTransport, success_envelope, failed_envelope};
    use crate::quota::PlanTier;
    use crate::db::Repository;
    use crate::error::GatewayError;
    use crate::health::HealthRegistry;
    use crate::proxy::loadbalancer::LoadBalancerRegistry;
    use uuid::Uuid;
    use chrono::Utc;

    // Stub repository — only userx/admin token methods matter; everything else is a no-op
    struct StubRepo;

    #[async_trait::async_trait]
    impl Repository for StubRepo {
        async fn list_services(&self) -> Result<Vec<crate::models::Service>, GatewayError> { Ok(vec![]) }
        async fn get_service(&self, _id: &Uuid) -> Result<Option<crate::models::Service>, GatewayError> { Ok(None) }
        async fn get_service_by_name(&self, _name: &str) -> Result<Option<crate::models::Service>, GatewayError> { Ok(None) }
        async fn create_service(&self, _svc: &crate::models::Service) -> Result<(), GatewayError> { Ok(()) }
        async fn update_service(&self, _id: &Uuid, _svc: &crate::models::Service) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_service(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_routes(&self) -> Result<Vec<crate::models::Route>, GatewayError> { Ok(vec![]) }
        async fn get_route(&self, _id: &Uuid) -> Result<Option<crate::models::Route>, GatewayError> { Ok(None) }
        async fn create_route(&self, _route: &crate::models::Route) -> Result<(), GatewayError> { Ok(()) }
        async fn update_route(&self, _id: &Uuid, _route: &crate::models::Route) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_route(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_plugins(&self) -> Result<Vec<crate::models::PluginInstance>, GatewayError> { Ok(vec![]) }
        async fn get_plugin(&self, _id: &Uuid) -> Result<Option<crate::models::PluginInstance>, GatewayError> { Ok(None) }
        async fn create_plugin(&self, _plugin: &crate::models::PluginInstance) -> Result<(), GatewayError> { Ok(()) }
        async fn update_plugin(&self, _id: &Uuid, _plugin: &crate::models::PluginInstance) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_plugin(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_consumers(&self) -> Result<Vec<crate::models::Consumer>, GatewayError> { Ok(vec![]) }
        async fn create_consumer(&self, _consumer: &crate::models::Consumer) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_consumer(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_targets(&self) -> Result<Vec<crate::models::Target>, GatewayError> { Ok(vec![]) }
        async fn list_targets_for_service(&self, _id: &Uuid) -> Result<Vec<crate::models::Target>, GatewayError> { Ok(vec![]) }
        async fn get_target(&self, _id: &Uuid) -> Result<Option<crate::models::Target>, GatewayError> { Ok(None) }
        async fn create_target(&self, _t: &crate::models::Target) -> Result<(), GatewayError> { Ok(()) }
        async fn update_target(&self, _id: &Uuid, _t: &crate::models::Target) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_target(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn update_target_state(&self, _id: &Uuid, _state: &str) -> Result<bool, GatewayError> { Ok(false) }
        async fn is_empty(&self) -> Result<bool, GatewayError> { Ok(true) }
        async fn seed_from_config(&self, _config: &crate::config::GatewayConfig) -> Result<(), GatewayError> { Ok(()) }
        async fn clear_config_seed(&self) -> Result<(), GatewayError> { Ok(()) }
        async fn mark_config_source(&self, _s: &[Uuid], _r: &[Uuid], _p: &[Uuid]) -> Result<(), GatewayError> { Ok(()) }
        async fn list_admin_tokens(&self) -> Result<Vec<crate::auth::AdminToken>, GatewayError> { Ok(vec![]) }
        async fn get_admin_token_by_hash(&self, _h: &str) -> Result<Option<crate::auth::AdminToken>, GatewayError> { Ok(None) }
        async fn get_admin_token(&self, _id: &Uuid) -> Result<Option<crate::auth::AdminToken>, GatewayError> { Ok(None) }
        async fn create_admin_token(&self, _t: &crate::db::NewAdminToken) -> Result<(), GatewayError> { Ok(()) }
        async fn update_admin_token(&self, _id: &Uuid, _patch: &crate::db::AdminTokenPatch) -> Result<Option<crate::auth::AdminToken>, GatewayError> { Ok(None) }
        async fn delete_admin_token(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn update_admin_token_last_used(&self, _id: &Uuid, _ts: chrono::DateTime<Utc>) -> Result<(), GatewayError> { Ok(()) }
        async fn has_any_admin_token(&self) -> Result<bool, GatewayError> { Ok(false) }
        async fn append_audit(&self, entry: &crate::audit::NewAuditEntry) -> Result<crate::audit::AuditEntry, GatewayError> {
            Ok(crate::audit::AuditEntry {
                id: 0, ts: entry.ts, actor_id: entry.actor_id,
                actor_name: entry.actor_name.clone(), actor_role: entry.actor_role.clone(),
                action: entry.action.clone(), resource_type: entry.resource_type.clone(),
                resource_id: entry.resource_id.clone(), diff: entry.diff.clone(),
                hash: String::new(), prev_hash: None,
            })
        }
        async fn list_audit(&self, _f: &crate::audit::AuditFilter) -> Result<Vec<crate::audit::AuditEntry>, GatewayError> { Ok(vec![]) }
        async fn last_audit_hash(&self) -> Result<Option<String>, GatewayError> { Ok(None) }
        fn cluster_bus(&self) -> Arc<dyn crate::cluster::ClusterBus> { Arc::new(crate::cluster::NoopBus) }
        async fn get_quota_usage(&self, _period: &str) -> Result<Option<(u64, u64, u64)>, GatewayError> { Ok(None) }
        async fn upsert_quota_usage(&self, _period: &str, _calls_total: u64, _calls_rejected: u64, _calls_overage: u64) -> Result<(), GatewayError> { Ok(()) }
        async fn append_recording(&self, _row: &crate::recording::RecordingIndexRow) -> Result<(), GatewayError> { Ok(()) }
        async fn list_recordings(&self, _f: &crate::recording::RecordingFilter) -> Result<Vec<crate::recording::RecordingIndexRow>, GatewayError> { Ok(vec![]) }
        async fn get_recording_index(&self, _id: &str) -> Result<Option<crate::recording::RecordingIndexRow>, GatewayError> { Ok(None) }
        async fn delete_recording(&self, _id: &str) -> Result<bool, GatewayError> { Ok(false) }
        async fn delete_recordings_before(&self, _ts: chrono::DateTime<chrono::Utc>) -> Result<u64, GatewayError> { Ok(0) }
        async fn get_device_fingerprint(&self, _customer_id: i64, _hardware_id: &str) -> Result<Option<crate::models::DeviceFingerprint>, GatewayError> { Ok(None) }
        async fn create_device_fingerprint(&self, _device: &crate::models::DeviceFingerprint) -> Result<(), GatewayError> { Ok(()) }
        async fn update_device_last_seen(&self, _id: &Uuid, _ts: chrono::DateTime<chrono::Utc>) -> Result<(), GatewayError> { Ok(()) }
        async fn create_runtime_grant(&self, _grant: &crate::models::RuntimeGrant) -> Result<(), GatewayError> { Ok(()) }
        async fn get_runtime_grant_by_token_id(&self, _token_id: &str) -> Result<Option<crate::models::RuntimeGrant>, GatewayError> { Ok(None) }
        async fn update_grant_heartbeat(&self, _token_id: &str, _ts: chrono::DateTime<chrono::Utc>) -> Result<(), GatewayError> { Ok(()) }
        async fn revoke_grant(&self, _token_id: &str) -> Result<bool, GatewayError> { Ok(false) }
        async fn get_api_key_by_prefix(&self, _prefix: &str) -> Result<Option<crate::models::ApiKeyRow>, GatewayError> { Ok(None) }
        async fn list_projects(&self) -> Result<Vec<crate::models::Project>, GatewayError> { Ok(vec![]) }
        async fn get_project(&self, _id: &Uuid) -> Result<Option<crate::models::Project>, GatewayError> { Ok(None) }
        async fn create_project(&self, _p: &crate::models::Project) -> Result<(), GatewayError> { Ok(()) }
        async fn update_project(&self, _id: &Uuid, _p: &crate::models::Project) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_project(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_services_for_project(&self, _id: &Uuid) -> Result<Vec<crate::models::Service>, GatewayError> { Ok(vec![]) }
        async fn soft_delete_plugins_for_route(&self, _id: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn soft_delete_plugins_for_service(&self, _id: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn soft_delete_routes_for_service(&self, _id: &Uuid) -> Result<Vec<Uuid>, GatewayError> { Ok(vec![]) }
        async fn soft_delete_targets_for_service(&self, _id: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn soft_delete_services_for_project(&self, _id: &Uuid) -> Result<Vec<Uuid>, GatewayError> { Ok(vec![]) }
        async fn insert_logs(&self, _entries: &[crate::models::LogEntry]) -> Result<(), GatewayError> { Ok(()) }
        async fn list_logs(&self, _filter: &crate::db::LogFilter) -> Result<Vec<crate::models::LogEntry>, GatewayError> { Ok(vec![]) }
        async fn prune_logs(&self, _days: u32) -> Result<u64, GatewayError> { Ok(0) }
        async fn upsert_metric_bucket(&self, _b: &crate::models::MetricBucket) -> Result<(), GatewayError> { Ok(()) }
        async fn list_metric_buckets(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>, _g: &str) -> Result<Vec<crate::models::MetricBucket>, GatewayError> { Ok(vec![]) }
        async fn upsert_geo_bucket(&self, _b: &crate::models::GeoBucket) -> Result<(), GatewayError> { Ok(()) }
        async fn list_geo_buckets(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>) -> Result<Vec<crate::models::GeoBucket>, GatewayError> { Ok(vec![]) }
        async fn upsert_rate_limit_bucket(&self, _b: &crate::models::RateLimitBucket) -> Result<(), GatewayError> { Ok(()) }
        async fn list_rate_limit_buckets(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>) -> Result<Vec<crate::models::RateLimitBucket>, GatewayError> { Ok(vec![]) }
        async fn list_probes(&self, _sid: &Uuid) -> Result<Vec<crate::models::Probe>, GatewayError> { Ok(vec![]) }
        async fn get_probe(&self, _id: &Uuid) -> Result<Option<crate::models::Probe>, GatewayError> { Ok(None) }
        async fn create_probe(&self, _p: &crate::models::Probe) -> Result<(), GatewayError> { Ok(()) }
        async fn update_probe(&self, _id: &Uuid, _p: &crate::models::Probe) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_probe(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn append_probe_result(&self, _r: &crate::models::ProbeResult) -> Result<(), GatewayError> { Ok(()) }
        async fn list_probe_results(&self, _pid: &Uuid, _limit: u32) -> Result<Vec<crate::models::ProbeResult>, GatewayError> { Ok(vec![]) }
        async fn list_snapshots(&self, _sid: &Uuid) -> Result<Vec<crate::models::Snapshot>, GatewayError> { Ok(vec![]) }
        async fn get_snapshot(&self, _id: &Uuid) -> Result<Option<crate::models::Snapshot>, GatewayError> { Ok(None) }
        async fn create_snapshot(&self, _s: &crate::models::Snapshot) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_snapshot(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_alert_rules(&self, _sid: &Uuid) -> Result<Vec<crate::models::AlertRule>, GatewayError> { Ok(vec![]) }
        async fn get_alert_rule(&self, _id: &Uuid) -> Result<Option<crate::models::AlertRule>, GatewayError> { Ok(None) }
        async fn create_alert_rule(&self, _r: &crate::models::AlertRule) -> Result<(), GatewayError> { Ok(()) }
        async fn update_alert_rule(&self, _id: &Uuid, _r: &crate::models::AlertRule) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_alert_rule(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_alert_events(&self, _sid: &Uuid, _limit: u32) -> Result<Vec<crate::models::AlertEvent>, GatewayError> { Ok(vec![]) }
        async fn create_alert_event(&self, _e: &crate::models::AlertEvent) -> Result<(), GatewayError> { Ok(()) }
        async fn resolve_alert_event(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_ip_rules(&self, _sid: &Uuid) -> Result<Vec<crate::models::IpRule>, GatewayError> { Ok(vec![]) }
        async fn get_ip_rule(&self, _id: &Uuid) -> Result<Option<crate::models::IpRule>, GatewayError> { Ok(None) }
        async fn create_ip_rule(&self, _r: &crate::models::IpRule) -> Result<(), GatewayError> { Ok(()) }
        async fn update_ip_rule(&self, _id: &Uuid, _r: &crate::models::IpRule) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_ip_rule(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_error_pages(&self, _sid: &Uuid) -> Result<Vec<crate::models::ErrorPage>, GatewayError> { Ok(vec![]) }
        async fn get_error_page(&self, _id: &Uuid) -> Result<Option<crate::models::ErrorPage>, GatewayError> { Ok(None) }
        async fn create_error_page(&self, _p: &crate::models::ErrorPage) -> Result<(), GatewayError> { Ok(()) }
        async fn update_error_page(&self, _id: &Uuid, _p: &crate::models::ErrorPage) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_error_page(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_consumer_groups(&self, _sid: &Uuid) -> Result<Vec<crate::models::ConsumerGroup>, GatewayError> { Ok(vec![]) }
        async fn get_consumer_group(&self, _id: &Uuid) -> Result<Option<crate::models::ConsumerGroup>, GatewayError> { Ok(None) }
        async fn create_consumer_group(&self, _g: &crate::models::ConsumerGroup) -> Result<(), GatewayError> { Ok(()) }
        async fn update_consumer_group(&self, _id: &Uuid, _g: &crate::models::ConsumerGroup) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_consumer_group(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_consumer_group_members(&self, _gid: &Uuid) -> Result<Vec<crate::models::ConsumerGroupMember>, GatewayError> { Ok(vec![]) }
        async fn add_consumer_group_member(&self, _m: &crate::models::ConsumerGroupMember) -> Result<(), GatewayError> { Ok(()) }
        async fn remove_consumer_group_member(&self, _gid: &Uuid, _cid: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_cache_entries(&self, _sid: &Uuid) -> Result<Vec<crate::models::CacheEntry>, GatewayError> { Ok(vec![]) }
        async fn get_cache_entry(&self, _id: &Uuid) -> Result<Option<crate::models::CacheEntry>, GatewayError> { Ok(None) }
        async fn upsert_cache_entry(&self, _e: &crate::models::CacheEntry) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_cache_entry(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn purge_cache(&self, _sid: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn cache_stats(&self, _sid: &Uuid) -> Result<crate::models::CacheStats, GatewayError> {
            Ok(crate::models::CacheStats {
                service_id: *_sid, total_entries: 0, total_size_bytes: 0,
                hit_count: 0, miss_count: 0, hit_rate: 0.0, eviction_count: 0,
            })
        }
        async fn list_traces(&self, _sid: &Uuid, _limit: u32) -> Result<Vec<crate::models::TraceRecord>, GatewayError> { Ok(vec![]) }
        async fn get_trace(&self, _id: &Uuid) -> Result<Option<crate::models::TraceRecord>, GatewayError> { Ok(None) }
        async fn create_trace(&self, _t: &crate::models::TraceRecord) -> Result<(), GatewayError> { Ok(()) }
        async fn list_spans(&self, _tid: &str) -> Result<Vec<crate::models::SpanRecord>, GatewayError> { Ok(vec![]) }
        async fn create_span(&self, _s: &crate::models::SpanRecord) -> Result<(), GatewayError> { Ok(()) }
        async fn list_transform_rules(&self, _sid: &Uuid) -> Result<Vec<crate::models::TransformRule>, GatewayError> { Ok(vec![]) }
        async fn get_transform_rule(&self, _id: &Uuid) -> Result<Option<crate::models::TransformRule>, GatewayError> { Ok(None) }
        async fn create_transform_rule(&self, _r: &crate::models::TransformRule) -> Result<(), GatewayError> { Ok(()) }
        async fn update_transform_rule(&self, _id: &Uuid, _r: &crate::models::TransformRule) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_transform_rule(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_api_versions(&self, _sid: &Uuid) -> Result<Vec<crate::models::ApiVersion>, GatewayError> { Ok(vec![]) }
        async fn get_api_version(&self, _id: &Uuid) -> Result<Option<crate::models::ApiVersion>, GatewayError> { Ok(None) }
        async fn create_api_version(&self, _v: &crate::models::ApiVersion) -> Result<(), GatewayError> { Ok(()) }
        async fn update_api_version(&self, _id: &Uuid, _v: &crate::models::ApiVersion) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_api_version(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_incidents(&self, _sid: &Uuid) -> Result<Vec<crate::models::Incident>, GatewayError> { Ok(vec![]) }
        async fn get_incident(&self, _id: &Uuid) -> Result<Option<crate::models::Incident>, GatewayError> { Ok(None) }
        async fn create_incident(&self, _i: &crate::models::Incident) -> Result<(), GatewayError> { Ok(()) }
        async fn update_incident(&self, _id: &Uuid, _i: &crate::models::Incident) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_incident(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_incident_updates(&self, _iid: &Uuid) -> Result<Vec<crate::models::IncidentUpdate>, GatewayError> { Ok(vec![]) }
        async fn create_incident_update(&self, _u: &crate::models::IncidentUpdate) -> Result<(), GatewayError> { Ok(()) }
        async fn list_webhooks(&self, _sid: &Uuid) -> Result<Vec<crate::models::Webhook>, GatewayError> { Ok(vec![]) }
        async fn get_webhook(&self, _id: &Uuid) -> Result<Option<crate::models::Webhook>, GatewayError> { Ok(None) }
        async fn create_webhook(&self, _w: &crate::models::Webhook) -> Result<(), GatewayError> { Ok(()) }
        async fn update_webhook(&self, _id: &Uuid, _w: &crate::models::Webhook) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_webhook(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_webhook_deliveries(&self, _wid: &Uuid, _limit: u32) -> Result<Vec<crate::models::WebhookDelivery>, GatewayError> { Ok(vec![]) }
        async fn create_webhook_delivery(&self, _d: &crate::models::WebhookDelivery) -> Result<(), GatewayError> { Ok(()) }
        async fn list_load_tests(&self, _sid: &Uuid) -> Result<Vec<crate::models::LoadTest>, GatewayError> { Ok(vec![]) }
        async fn get_load_test(&self, _id: &Uuid) -> Result<Option<crate::models::LoadTest>, GatewayError> { Ok(None) }
        async fn create_load_test(&self, _t: &crate::models::LoadTest) -> Result<(), GatewayError> { Ok(()) }
        async fn update_load_test(&self, _id: &Uuid, _t: &crate::models::LoadTest) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_load_test(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_marketplace_plugins(&self) -> Result<Vec<crate::models::MarketplacePlugin>, GatewayError> { Ok(vec![]) }
        async fn get_marketplace_plugin(&self, _id: &Uuid) -> Result<Option<crate::models::MarketplacePlugin>, GatewayError> { Ok(None) }
        async fn create_marketplace_plugin(&self, _p: &crate::models::MarketplacePlugin) -> Result<(), GatewayError> { Ok(()) }
        async fn update_marketplace_plugin(&self, _id: &Uuid, _p: &crate::models::MarketplacePlugin) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_marketplace_plugin(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_cost_records(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>) -> Result<Vec<crate::models::CostRecord>, GatewayError> { Ok(vec![]) }
        async fn upsert_cost_record(&self, _r: &crate::models::CostRecord) -> Result<(), GatewayError> { Ok(()) }
        async fn list_cluster_nodes(&self) -> Result<Vec<crate::models::ClusterNode>, GatewayError> { Ok(vec![]) }
        async fn get_cluster_node(&self, _id: &Uuid) -> Result<Option<crate::models::ClusterNode>, GatewayError> { Ok(None) }
        async fn upsert_cluster_node(&self, _n: &crate::models::ClusterNode) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_cluster_node(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_rate_limit_simulations(&self, _sid: &Uuid) -> Result<Vec<crate::models::RateLimitSimulation>, GatewayError> { Ok(vec![]) }
        async fn create_rate_limit_simulation(&self, _s: &crate::models::RateLimitSimulation) -> Result<(), GatewayError> { Ok(()) }
        async fn get_rate_limit_simulation(&self, _id: &Uuid) -> Result<Option<crate::models::RateLimitSimulation>, GatewayError> { Ok(None) }
        async fn list_certificates(&self, _sid: Option<&Uuid>) -> Result<Vec<crate::models::Certificate>, GatewayError> { Ok(vec![]) }
        async fn get_certificate(&self, _id: &Uuid) -> Result<Option<crate::models::Certificate>, GatewayError> { Ok(None) }
        async fn create_certificate(&self, _c: &crate::models::Certificate) -> Result<(), GatewayError> { Ok(()) }
        async fn update_certificate(&self, _id: &Uuid, _c: &crate::models::Certificate) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_certificate(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn update_consumer(&self, _id: &Uuid, _c: &crate::models::Consumer) -> Result<(), GatewayError> { Ok(()) }
    }

    async fn make_test_admin_state(userx_client: Option<Arc<UserxClient>>) -> AdminState {
        use std::sync::OnceLock;
        static METRICS: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
        let metrics_handle = METRICS.get_or_init(|| crate::metrics::install()).clone();

        static CRYPTO_INIT: std::sync::Once = std::sync::Once::new();
        CRYPTO_INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let route_table = Arc::new(crate::proxy::router::RouteTable::new());
        let repo = Arc::new(StubRepo);
        let health = Arc::new(HealthRegistry::new());
        let lb = Arc::new(LoadBalancerRegistry::new());
        
        let client_cfg = crate::proxy::http_client::HttpClientConfig::default();
        let default_client = crate::proxy::http_client::build_http_proxy_client(&client_cfg).unwrap();
        let client_pool = Arc::new(crate::proxy::http_client::ProxyClientPool::new(default_client, client_cfg).unwrap());

        let temp_dir = std::env::temp_dir();
        let recording_store = Arc::new(crate::recording::ContentAddressedStore::new(temp_dir));

        let quota = crate::quota::QuotaTracker::load(
            crate::quota::PlanTier::Enterprise,
            None,
            repo.clone(),
        ).await.unwrap();

        let status_response = crate::admin::routes::StatusResponse {
            status: "ok".to_string(),
            version: "0.1.0".to_string(),
            build_hash: "abcd".to_string(),
            uptime_seconds: 0,
            services_count: 0,
            routes_count: 0,
            plugins_count: 0,
            consumers_count: 0,
            tier: "Enterprise".to_string(),
            active_nodes: 1,
            max_nodes: None,
            instance_id: "inst".to_string(),
            licence_mode: "keyx".to_string(),
        };
        let status_cache = crate::health::StatusCache::new(status_response);

        AdminState {
            route_table,
            repo: repo.clone(),
            health,
            lb,
            start_time: Utc::now(),
            metrics_handle,
            reload: crate::reload::ReloadHandle::dummy(),
            plugin_exec: Arc::new(crate::plugins::PluginExecutor::new(crate::quota::PlanTier::Enterprise)),
            bus: Arc::new(crate::cluster::NoopBus),
            node_id: Uuid::new_v4(),
            audit: crate::audit::AuditLog::new(repo),
            auth_required: true,
            client_pool,
            recording_store,
            http_client: reqwest::Client::new(),
            proxy_port: 8080,
            quota,
            acme: None,
            license_api_key: String::new(),
            license_state: None,
            deploy_registry: None,
            status_cache,
            token_validator: None,
            token_cache: None,
            userx_client,
        }
    }

    #[test]
    fn role_mapping_is_conservative() {
        assert_eq!(map_principal_role("admin"), Some(Role::Admin));
        assert_eq!(map_principal_role("OWNER"), Some(Role::Admin));
        assert_eq!(map_principal_role("service"), Some(Role::Operator));
        assert_eq!(map_principal_role("pat"), Some(Role::Viewer));
        assert_eq!(map_principal_role("viewer"), Some(Role::Viewer));
        assert_eq!(map_principal_role("publishable"), None);
        assert_eq!(map_principal_role("restricted"), None);
        assert_eq!(map_principal_role(""), None);
    }

    fn admin_token_stub(role: Role) -> AdminToken {
        AdminToken {
            id: uuid::Uuid::nil(),
            name: "test".into(),
            role,
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            scopes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn cache_miss_returns_none() {
        let cache = AdminAuthCache::new(Duration::from_secs(60));
        assert!(cache.get("nope").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn cache_hit_within_ttl_returns_token() {
        let cache = AdminAuthCache::new(Duration::from_secs(60));
        cache.insert("h".into(), admin_token_stub(Role::Admin));
        let got = cache.get("h").unwrap();
        assert_eq!(got.role, Role::Admin);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn cache_get_after_ttl_elapses_returns_none() {
        let cache = AdminAuthCache::new(Duration::from_millis(20));
        cache.insert("h".into(), admin_token_stub(Role::Operator));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(cache.get("h").is_none());
    }

    #[tokio::test]
    async fn cache_overwrite_replaces_entry() {
        let cache = AdminAuthCache::new(Duration::from_secs(60));
        cache.insert("h".into(), admin_token_stub(Role::Viewer));
        cache.insert("h".into(), admin_token_stub(Role::Admin));
        assert_eq!(cache.get("h").unwrap().role, Role::Admin);
        assert_eq!(cache.len(), 1);
    }

    fn token_with_scopes(role: Role, scopes: Vec<String>) -> AdminToken {
        AdminToken {
            id: uuid::Uuid::nil(),
            name: "t".into(),
            role,
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            scopes,
        }
    }

    #[test]
    fn scope_check_admin_passes_unconditionally() {
        let actor = CurrentActor(Some(token_with_scopes(Role::Admin, vec![])));
        assert!(actor_has_scope(&actor, "services.write"));
    }

    #[test]
    fn scope_check_wildcard_satisfies_anything() {
        let actor = CurrentActor(Some(token_with_scopes(Role::Viewer, vec!["*".into()])));
        assert!(actor_has_scope(&actor, "anything.at.all"));
    }

    #[test]
    fn scope_check_exact_match() {
        let actor = CurrentActor(Some(token_with_scopes(
            Role::Viewer,
            vec!["services.read".into(), "services.write".into()],
        )));
        assert!(actor_has_scope(&actor, "services.write"));
        assert!(!actor_has_scope(&actor, "plugins.write"));
    }

    #[test]
    fn scope_check_legacy_token_without_scopes_fails_unless_admin() {
        let actor = CurrentActor(Some(token_with_scopes(Role::Operator, vec![])));
        assert!(!actor_has_scope(&actor, "services.write"));
    }

    #[test]
    fn scope_check_bootstrap_mode_passes() {
        let actor = CurrentActor(None);
        assert!(actor_has_scope(&actor, "services.write"));
    }

    #[tokio::test]
    async fn userx_jwt_admin_role_mapped_via_role_field() {
        let transport = Arc::new(MockTransport::new(vec![(
            200,
            MockBody::Json(success_envelope(serde_json::json!({
                "sub": "11111111-1111-1111-1111-111111111111",
                "role": "admin",
                "scopes": ["user:admin"],
                "expires_at": "2026-06-26T20:00:00Z"
            })))
        )]));
        let userx_client = Arc::new(UserxClient::new(transport, "test-svc-key"));
        let state = make_test_admin_state(Some(userx_client)).await;

        let auth = Some(HeaderValue::from_static("Bearer abc.def.ghi"));
        let res = resolve_actor(&state, auth.as_ref()).await.unwrap().unwrap();

        assert_eq!(res.role, Role::Admin);
        assert_eq!(res.id.to_string(), "11111111-1111-1111-1111-111111111111");
        assert_eq!(res.scopes, vec!["user:admin"]);
    }

    #[tokio::test]
    async fn userx_jwt_operator_role_mapped_via_scopes() {
        let transport = Arc::new(MockTransport::new(vec![(
            200,
            MockBody::Json(success_envelope(serde_json::json!({
                "sub": "22222222-2222-2222-2222-222222222222",
                "scopes": ["user:operator"],
                "expires_at": "2026-06-26T20:00:00Z"
            })))
        )]));
        let userx_client = Arc::new(UserxClient::new(transport, "test-svc-key"));
        let state = make_test_admin_state(Some(userx_client)).await;

        let auth = Some(HeaderValue::from_static("Bearer abc.def.ghi"));
        let res = resolve_actor(&state, auth.as_ref()).await.unwrap().unwrap();

        assert_eq!(res.role, Role::Operator);
        assert_eq!(res.id.to_string(), "22222222-2222-2222-2222-222222222222");
    }

    #[tokio::test]
    async fn userx_jwt_viewer_role_mapped_via_scopes() {
        let transport = Arc::new(MockTransport::new(vec![(
            200,
            MockBody::Json(success_envelope(serde_json::json!({
                "sub": "33333333-3333-3333-3333-333333333333",
                "scopes": ["user:viewer"],
                "expires_at": "2026-06-26T20:00:00Z"
            })))
        )]));
        let userx_client = Arc::new(UserxClient::new(transport, "test-svc-key"));
        let state = make_test_admin_state(Some(userx_client)).await;

        let auth = Some(HeaderValue::from_static("Bearer abc.def.ghi"));
        let res = resolve_actor(&state, auth.as_ref()).await.unwrap().unwrap();

        assert_eq!(res.role, Role::Viewer);
        assert_eq!(res.id.to_string(), "33333333-3333-3333-3333-333333333333");
    }

    #[tokio::test]
    async fn userx_jwt_default_role_viewer() {
        let transport = Arc::new(MockTransport::new(vec![(
            200,
            MockBody::Json(success_envelope(serde_json::json!({
                "sub": "44444444-4444-4444-4444-444444444444",
                "expires_at": "2026-06-26T20:00:00Z"
            })))
        )]));
        let userx_client = Arc::new(UserxClient::new(transport, "test-svc-key"));
        let state = make_test_admin_state(Some(userx_client)).await;

        let auth = Some(HeaderValue::from_static("Bearer abc.def.ghi"));
        let res = resolve_actor(&state, auth.as_ref()).await.unwrap().unwrap();

        assert_eq!(res.role, Role::Viewer);
    }

    #[tokio::test]
    async fn userx_jwt_verification_failure() {
        let transport = Arc::new(MockTransport::new(vec![(
            401,
            MockBody::Json(failed_envelope("INVALID_TOKEN", "invalid token"))
        )]));
        let userx_client = Arc::new(UserxClient::new(transport, "test-svc-key"));
        let state = make_test_admin_state(Some(userx_client)).await;

        let auth = Some(HeaderValue::from_static("Bearer abc.def.ghi"));
        let res = resolve_actor(&state, auth.as_ref()).await;

        assert!(res.is_err());
        let resp = res.unwrap_err();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
