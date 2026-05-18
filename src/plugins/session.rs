use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::HeaderValue;
use axum::http::{Request, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Bridge an externally-issued, HMAC-signed cookie into the
/// `X-Consumer-Username` convention used by the rest of the plugin
/// chain (notably ACL). This plugin does NOT issue or refresh
/// sessions — it only validates and forwards.
///
/// Cookie value format: `username|expires_at|signature` where
/// `signature = base64url(HMAC-SHA256(secret, "username|expires_at"))`
/// and `expires_at` is a unix timestamp (seconds).
///
/// On invalid or missing cookie: do nothing. Other plugins handle
/// authentication enforcement. This is idempotent — applying it twice
/// just sets the header twice with the same value.
pub struct SessionPlugin {
    secret: Vec<u8>,
    cookie_name: String,
    max_age_seconds: u64,
}

impl SessionPlugin {
    pub fn from_config(
        cfg: &serde_json::Value,
        _repo: Option<Arc<dyn Repository>>,
    ) -> Result<Self, GatewayError> {
        let secret = cfg
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::BadRequest("session: `secret` is required".into()))?;
        if secret.is_empty() {
            return Err(GatewayError::BadRequest(
                "session: `secret` must not be empty".into(),
            ));
        }
        let cookie_name = cfg
            .get("cookie_name")
            .and_then(|v| v.as_str())
            .unwrap_or("lynxx_session")
            .to_string();
        let max_age_seconds = cfg
            .get("max_age_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        Ok(Self {
            secret: secret.as_bytes().to_vec(),
            cookie_name,
            max_age_seconds,
        })
    }

    fn parse_cookie<'a>(&self, header: &'a str) -> Option<&'a str> {
        // Hand-rolled instead of pulling the `cookie` crate into the hot
        // path — Cookie headers are simple `;`-separated `k=v` pairs.
        for part in header.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k == self.cookie_name {
                    return Some(v);
                }
            }
        }
        None
    }

    fn verify(&self, raw: &str) -> Option<String> {
        let (payload, sig_b64) = raw.rsplit_once('|')?;

        let sig = B64.decode(sig_b64).ok()?;

        let mut mac = HmacSha256::new_from_slice(&self.secret).ok()?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&sig).ok()?;

        let (username, expires) = payload.split_once('|')?;
        let expires_at: u64 = expires.parse().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        if expires_at < now {
            return None;
        }
        // max_age_seconds is a sanity ceiling: refuse cookies whose
        // declared lifetime is wildly larger than what the deployment
        // expects (defends against forged-but-invalid cookies that
        // somehow pass HMAC, e.g. truncated secret reuse).
        if expires_at.saturating_sub(now) > self.max_age_seconds * 2 {
            return None;
        }
        Some(username.to_string())
    }
}

#[async_trait]
impl Plugin for SessionPlugin {
    fn name(&self) -> &str {
        "session"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let cookie_header = match req.headers().get("cookie").and_then(|v| v.to_str().ok()) {
            Some(s) => s.to_string(),
            None => return Ok(()),
        };
        let raw = match self.parse_cookie(&cookie_header) {
            Some(s) => s,
            None => return Ok(()),
        };
        if let Some(username) = self.verify(raw) {
            if let Ok(v) = HeaderValue::from_str(&username) {
                req.headers_mut().insert("x-consumer-username", v);
            }
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
