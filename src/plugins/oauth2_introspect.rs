use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{Request, Response};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// RFC 7662 OAuth2 token introspection. Tokens are POSTed to the
/// configured introspection endpoint with HTTP Basic auth (client_id +
/// client_secret) and the response (`{"active": true, "sub": "...",
/// "scope": "..."}`) is cached locally per-instance for `cache_ttl_seconds`
/// so we don't hammer the IdP on every request.
pub struct Oauth2IntrospectPlugin {
    introspection_url: String,
    client_id: String,
    client_secret: String,
    header_name: HeaderName,
    scheme: String,
    cache_ttl: Duration,
    required_scopes: Vec<String>,
    cache: DashMap<String, CacheEntry>,
    http: reqwest::Client,
}

#[derive(Clone)]
struct CacheEntry {
    sub: Option<String>,
    scope: Option<String>,
    active: bool,
    expires_at: Instant,
}

impl Oauth2IntrospectPlugin {
    pub fn from_config(
        cfg: &serde_json::Value,
        _repo: Option<Arc<dyn Repository>>,
    ) -> Result<Self, GatewayError> {
        let introspection_url = cfg
            .get("introspection_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GatewayError::BadRequest(
                    "oauth2-introspect: `introspection_url` is required".into(),
                )
            })?
            .to_string();
        let client_id = cfg
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GatewayError::BadRequest("oauth2-introspect: `client_id` is required".into())
            })?
            .to_string();
        let client_secret = cfg
            .get("client_secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GatewayError::BadRequest("oauth2-introspect: `client_secret` is required".into())
            })?
            .to_string();
        let header = cfg
            .get("header")
            .and_then(|v| v.as_str())
            .unwrap_or("Authorization");
        let header_name = HeaderName::from_str(header)
            .map_err(|e| GatewayError::BadRequest(format!("invalid header name: {e}")))?;
        let scheme = cfg
            .get("scheme")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer")
            .to_string();
        let cache_ttl = Duration::from_secs(
            cfg.get("cache_ttl_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(60),
        );
        let required_scopes = cfg
            .get("required_scopes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // reqwest::Client is cheap to clone and pools internally; one per
        // plugin instance is fine.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                GatewayError::BadRequest(format!("oauth2-introspect: build client: {e}"))
            })?;

        Ok(Self {
            introspection_url,
            client_id,
            client_secret,
            header_name,
            scheme,
            cache_ttl,
            required_scopes,
            cache: DashMap::new(),
            http,
        })
    }

    fn token_key(token: &str) -> String {
        // Hash so we never hold raw bearer tokens in memory longer than
        // the request that introduced them.
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        format!("{:x}", h.finalize())
    }

    fn extract_token<'a>(&self, raw: &'a str) -> Option<&'a str> {
        if self.scheme.is_empty() {
            return Some(raw.trim());
        }
        let prefix = format!("{} ", self.scheme);
        raw.strip_prefix(&prefix).map(str::trim)
    }

    async fn introspect(&self, token: &str) -> Result<CacheEntry, PluginError> {
        let resp = self
            .http
            .post(&self.introspection_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|e| PluginError::Internal(format!("introspect request: {e}")))?;
        if !resp.status().is_success() {
            return Err(PluginError::Unauthorized(format!(
                "introspection endpoint returned {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| PluginError::Internal(format!("introspect parse: {e}")))?;
        let active = body
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let sub = body.get("sub").and_then(|v| v.as_str()).map(String::from);
        let scope = body.get("scope").and_then(|v| v.as_str()).map(String::from);

        // Cap the cache entry at the token's own `exp` (RFC 7662) so an
        // expired token is never served as active for the full cache TTL. The
        // cache TTL only bounds *revocation* staleness for still-valid tokens.
        let mut expires_at = Instant::now() + self.cache_ttl;
        if let Some(exp_ts) = body.get("exp").and_then(|v| v.as_i64()) {
            let secs_until_exp = exp_ts - chrono::Utc::now().timestamp();
            if secs_until_exp <= 0 {
                expires_at = Instant::now();
            } else if (secs_until_exp as u64) < self.cache_ttl.as_secs() {
                expires_at = Instant::now() + Duration::from_secs(secs_until_exp as u64);
            }
        }

        Ok(CacheEntry {
            sub,
            scope,
            active,
            expires_at,
        })
    }

    fn scopes_satisfied(&self, scope: Option<&str>) -> bool {
        if self.required_scopes.is_empty() {
            return true;
        }
        let granted: std::collections::HashSet<&str> = scope
            .map(|s| s.split_whitespace().collect())
            .unwrap_or_default();
        self.required_scopes
            .iter()
            .all(|req| granted.contains(req.as_str()))
    }
}

#[async_trait]
impl Plugin for Oauth2IntrospectPlugin {
    fn name(&self) -> &str {
        "oauth2-introspect"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let raw = req
            .headers()
            .get(&self.header_name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| PluginError::Unauthorized("missing token".into()))?
            .to_string();
        let token = self
            .extract_token(&raw)
            .ok_or_else(|| PluginError::Unauthorized("malformed token header".into()))?
            .to_string();

        let key = Self::token_key(&token);
        let now = Instant::now();
        let cached = self.cache.get(&key).and_then(|e| {
            if e.expires_at > now {
                Some(e.clone())
            } else {
                None
            }
        });
        let entry = match cached {
            Some(e) => e,
            None => {
                let fresh = self.introspect(&token).await?;
                self.cache.insert(key.clone(), fresh.clone());
                fresh
            }
        };

        if !entry.active {
            return Err(PluginError::Unauthorized("inactive token".into()));
        }
        if !self.scopes_satisfied(entry.scope.as_deref()) {
            return Err(PluginError::Forbidden("insufficient scope".into()));
        }

        if let Some(sub) = &entry.sub {
            if let Ok(v) = HeaderValue::from_str(sub) {
                req.headers_mut().insert("x-oauth-subject", v);
            }
        }
        if let Some(scope) = &entry.scope {
            if let Ok(v) = HeaderValue::from_str(scope) {
                req.headers_mut().insert("x-oauth-scope", v);
            }
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
