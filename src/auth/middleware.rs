//! Axum middleware for admin-API authentication and role enforcement.
//!
//! Two layers compose:
//!   * [`extract_token`]: looks up the bearer token, attaches an
//!     `Option<AdminToken>` to request extensions, and 401s on bad tokens.
//!     If the DB has zero tokens we are in *bootstrap mode* and the request
//!     is allowed through without an actor (matches Kong's first-run UX).
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

    // Fast path: the Lynxx license API key is always a valid master admin
    // credential. Customers can use the same key they got from their account
    // dashboard at lynxx.vexarr.com — no separate token creation needed.
    if !state.license_api_key.is_empty() && raw == state.license_api_key {
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
        None => next.run(req).await, // license-key auth or unauthenticated (auth_required=false)
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
}
