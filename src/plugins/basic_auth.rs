use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::HeaderValue;
use axum::http::{Request, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::sync::Arc;

/// HTTP Basic auth backed by the consumer table.
///
/// **Password verification priority:**
///
/// 1. If the matched consumer has a `password_hash` (Argon2id), the supplied
///    password is verified against that hash. This is the recommended production
///    path — set `password_hash` via the admin API's consumer endpoint.
///
/// 2. Otherwise, the consumer's stored `api_key` (a random UUID generated at
///    consumer creation time) is compared as the basic-auth password. This
///    preserves backward compatibility with the v1 schema.
pub struct BasicAuthPlugin {
    repo: Option<Arc<dyn Repository>>,
    hide_credentials: bool,
}

impl BasicAuthPlugin {
    pub fn from_config(
        cfg: &serde_json::Value,
        repo: Option<Arc<dyn Repository>>,
    ) -> Result<Self, GatewayError> {
        let hide_credentials = cfg
            .get("hide_credentials")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(Self {
            repo,
            hide_credentials,
        })
    }

    fn unauthorized() -> PluginError {
        PluginError::Unauthorized(r#"Basic realm="lynxx""#.into())
    }

    /// Verify `password` against an Argon2id PHC-format hash string.
    fn verify_argon2(hash: &str, password: &str) -> bool {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        use argon2::Argon2;
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }
}

#[async_trait]
impl Plugin for BasicAuthPlugin {
    fn name(&self) -> &str {
        "basic-auth"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let raw = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(Self::unauthorized)?;
        let encoded = raw.strip_prefix("Basic ").ok_or_else(Self::unauthorized)?;
        let decoded = B64
            .decode(encoded.trim())
            .map_err(|_| Self::unauthorized())?;
        let pair = std::str::from_utf8(&decoded).map_err(|_| Self::unauthorized())?;
        let (username, password) = pair.split_once(':').ok_or_else(Self::unauthorized)?;

        let repo = self
            .repo
            .as_ref()
            .ok_or_else(|| PluginError::Internal("basic-auth: no repository".into()))?;

        let consumers = repo
            .list_consumers()
            .await
            .map_err(|e| PluginError::Internal(format!("consumer lookup: {e}")))?;

        let matched = consumers.into_iter().find(|c| {
            if c.username != username {
                return false;
            }
            // Priority 1: Argon2id password hash
            if let Some(ref hash) = c.password_hash {
                return Self::verify_argon2(hash, password);
            }
            // Priority 2: legacy api_key comparison
            c.api_key.as_deref() == Some(password)
        });
        let consumer = matched.ok_or_else(Self::unauthorized)?;

        if let Ok(v) = HeaderValue::from_str(&consumer.username) {
            req.headers_mut().insert("x-consumer-username", v);
        }
        if let Ok(v) = HeaderValue::from_str(&consumer.id.to_string()) {
            req.headers_mut().insert("x-consumer-id", v);
        }
        if self.hide_credentials {
            req.headers_mut().remove("authorization");
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_argon2_round_trip() {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        use argon2::Argon2;
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"hunter2", &salt)
            .unwrap()
            .to_string();
        assert!(BasicAuthPlugin::verify_argon2(&hash, "hunter2"));
        assert!(!BasicAuthPlugin::verify_argon2(&hash, "wrong"));
    }

    #[test]
    fn verify_argon2_rejects_garbage() {
        assert!(!BasicAuthPlugin::verify_argon2("not-a-hash", "password"));
    }
}
