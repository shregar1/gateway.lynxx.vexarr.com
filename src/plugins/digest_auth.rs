//! HTTP Digest Authentication plugin (RFC 7616, SHA-256 only).
//!
//! Implements the `auth` quality-of-protection with SHA-256. MD5 is not
//! supported — only `algorithm=SHA-256`.
//!
//! Config:
//! ```json
//! {
//!   "users": { "alice": "password123" },
//!   "realm": "lynxx",
//!   "use_ha1": false
//! }
//! ```
//!
//! When `use_ha1` is `true`, the values in `users` are treated as
//! pre-computed HA1 hashes (`SHA256(username:realm:password)`).

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{Request, Response, StatusCode};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct DigestAuthPlugin {
    /// username → password (or HA1 hex string when `use_ha1` is true).
    users: HashMap<String, String>,
    realm: String,
    use_ha1: bool,
}

/// Stored in request extensions when we need to send a 401 challenge
/// (either missing or invalid Authorization header). The `on_response`
/// handler checks for this and overrides the response accordingly.
#[derive(Clone, Debug)]
struct DigestChallenge {
    www_authenticate: String,
}

impl DigestAuthPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let users = cfg
            .get("users")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        if users.is_empty() {
            return Err(GatewayError::BadRequest(
                "digest-auth: 'users' map must contain at least one entry".into(),
            ));
        }

        let realm = cfg
            .get("realm")
            .and_then(|v| v.as_str())
            .unwrap_or("lynxx")
            .to_string();
        let use_ha1 = cfg
            .get("use_ha1")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(Self {
            users,
            realm,
            use_ha1,
        })
    }

    /// Generate a random nonce (32 hex chars).
    fn generate_nonce() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 16] = rng.gen();
        hex::encode(bytes)
    }

    /// SHA-256 hex digest of the input string.
    fn sha256_hex(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Build the WWW-Authenticate challenge header value.
    fn build_challenge(&self) -> String {
        let nonce = Self::generate_nonce();
        format!(
            r#"Digest realm="{}", qop="auth", nonce="{}", algorithm=SHA-256"#,
            self.realm, nonce
        )
    }

    /// Compute HA1 = SHA256(username:realm:password).
    fn compute_ha1(&self, username: &str) -> Option<String> {
        let credential = self.users.get(username)?;
        if self.use_ha1 {
            Some(credential.clone())
        } else {
            Some(Self::sha256_hex(&format!(
                "{}:{}:{}",
                username, self.realm, credential
            )))
        }
    }

    /// Parse a `Digest` authorization header into key-value pairs.
    fn parse_digest_params(header: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        // Strip "Digest " prefix.
        let body = header
            .strip_prefix("Digest ")
            .or_else(|| header.strip_prefix("digest "))
            .unwrap_or(header);

        for part in body.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().trim_matches('"').to_string();
                params.insert(key, value);
            }
        }
        params
    }

    /// Validate the digest response against the expected value.
    fn validate(&self, method: &str, params: &HashMap<String, String>) -> bool {
        let username = match params.get("username") {
            Some(u) => u,
            None => return false,
        };
        let nonce = match params.get("nonce") {
            Some(n) => n,
            None => return false,
        };
        let nc = match params.get("nc") {
            Some(n) => n,
            None => return false,
        };
        let cnonce = match params.get("cnonce") {
            Some(c) => c,
            None => return false,
        };
        let qop = match params.get("qop") {
            Some(q) => q,
            None => return false,
        };
        let response = match params.get("response") {
            Some(r) => r,
            None => return false,
        };
        let uri = match params.get("uri") {
            Some(u) => u,
            None => return false,
        };

        let ha1 = match self.compute_ha1(username) {
            Some(h) => h,
            None => return false,
        };

        let ha2 = Self::sha256_hex(&format!("{}:{}", method, uri));
        let expected = Self::sha256_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop, ha2
        ));

        expected == *response
    }
}

#[async_trait]
impl Plugin for DigestAuthPlugin {
    fn name(&self) -> &str {
        "digest-auth"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match auth_header {
            None => {
                // No Authorization header — issue a challenge.
                let challenge = self.build_challenge();
                req.extensions_mut().insert(DigestChallenge {
                    www_authenticate: challenge,
                });
            }
            Some(ref header)
                if !header.starts_with("Digest ") && !header.starts_with("digest ") =>
            {
                // Wrong auth scheme.
                let challenge = self.build_challenge();
                req.extensions_mut().insert(DigestChallenge {
                    www_authenticate: challenge,
                });
            }
            Some(ref header) => {
                let params = Self::parse_digest_params(header);
                let method = req.method().as_str();

                if !self.validate(method, &params) {
                    let challenge = self.build_challenge();
                    req.extensions_mut().insert(DigestChallenge {
                        www_authenticate: challenge,
                    });
                }
            }
        }

        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        if let Some(challenge) = resp.extensions().get::<DigestChallenge>().cloned() {
            *resp.status_mut() = StatusCode::UNAUTHORIZED;
            if let Ok(val) = axum::http::HeaderValue::from_str(&challenge.www_authenticate) {
                resp.headers_mut().insert("www-authenticate", val);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn test_plugin() -> DigestAuthPlugin {
        DigestAuthPlugin {
            users: HashMap::from([("alice".to_string(), "secret".to_string())]),
            realm: "lynxx".to_string(),
            use_ha1: false,
        }
    }

    fn make_request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn missing_auth_header_triggers_challenge() {
        let plugin = test_plugin();
        let mut req = make_request("GET", "/protected");
        plugin.on_request(&mut req).await.unwrap();

        let challenge = req.extensions().get::<DigestChallenge>();
        assert!(challenge.is_some(), "should set DigestChallenge extension");
        let www = &challenge.unwrap().www_authenticate;
        assert!(www.contains("realm=\"lynxx\""));
        assert!(www.contains("qop=\"auth\""));
        assert!(www.contains("algorithm=SHA-256"));
    }

    #[tokio::test]
    async fn missing_auth_header_produces_401_response() {
        let plugin = test_plugin();
        let mut req = make_request("GET", "/protected");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = Response::builder().body(Body::empty()).unwrap();
        resp.extensions_mut()
            .insert(req.extensions().get::<DigestChallenge>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get("www-authenticate").is_some());
    }

    #[tokio::test]
    async fn valid_credentials_pass() {
        let plugin = test_plugin();

        // Pre-compute the expected digest response.
        let method = "GET";
        let uri = "/protected";
        let nonce = "testnonce1234567890abcdef12345678";
        let nc = "00000001";
        let cnonce = "clientnonce";
        let qop = "auth";

        let ha1 = DigestAuthPlugin::sha256_hex("alice:lynxx:secret");
        let ha2 = DigestAuthPlugin::sha256_hex(&format!("{}:{}", method, uri));
        let response_hash = DigestAuthPlugin::sha256_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop, ha2
        ));

        let auth_header = format!(
            r#"Digest username="alice", realm="lynxx", nonce="{}", uri="{}", qop={}, nc={}, cnonce="{}", response="{}", algorithm=SHA-256"#,
            nonce, uri, qop, nc, cnonce, response_hash
        );

        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();

        plugin.on_request(&mut req).await.unwrap();

        assert!(
            req.extensions().get::<DigestChallenge>().is_none(),
            "valid credentials should not produce a challenge"
        );
    }

    #[tokio::test]
    async fn invalid_password_triggers_challenge() {
        let plugin = test_plugin();

        let method = "GET";
        let uri = "/protected";
        let nonce = "testnonce1234567890abcdef12345678";
        let nc = "00000001";
        let cnonce = "clientnonce";
        let qop = "auth";

        // Compute with wrong password.
        let ha1 = DigestAuthPlugin::sha256_hex("alice:lynxx:wrongpassword");
        let ha2 = DigestAuthPlugin::sha256_hex(&format!("{}:{}", method, uri));
        let response_hash = DigestAuthPlugin::sha256_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop, ha2
        ));

        let auth_header = format!(
            r#"Digest username="alice", realm="lynxx", nonce="{}", uri="{}", qop={}, nc={}, cnonce="{}", response="{}", algorithm=SHA-256"#,
            nonce, uri, qop, nc, cnonce, response_hash
        );

        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();

        plugin.on_request(&mut req).await.unwrap();

        assert!(
            req.extensions().get::<DigestChallenge>().is_some(),
            "wrong password must produce a challenge"
        );
    }

    #[tokio::test]
    async fn unknown_user_triggers_challenge() {
        let plugin = test_plugin();

        let auth_header = r#"Digest username="bob", realm="lynxx", nonce="abc", uri="/x", qop=auth, nc=00000001, cnonce="cc", response="deadbeef", algorithm=SHA-256"#;

        let mut req = Request::builder()
            .method("GET")
            .uri("/x")
            .header("authorization", auth_header)
            .body(Body::empty())
            .unwrap();

        plugin.on_request(&mut req).await.unwrap();

        assert!(req.extensions().get::<DigestChallenge>().is_some());
    }

    #[test]
    fn nonce_generation_is_32_hex_chars() {
        let nonce = DigestAuthPlugin::generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn nonces_are_unique() {
        let a = DigestAuthPlugin::generate_nonce();
        let b = DigestAuthPlugin::generate_nonce();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn ha1_mode_works() {
        let method = "GET";
        let uri = "/secure";
        let nonce = "fixednonce12345678901234567890ab";
        let nc = "00000001";
        let cnonce = "cn";
        let qop = "auth";

        // Pre-compute HA1 for alice:lynxx:secret.
        let ha1 = DigestAuthPlugin::sha256_hex("alice:lynxx:secret");

        let plugin = DigestAuthPlugin {
            users: HashMap::from([("alice".to_string(), ha1.clone())]),
            realm: "lynxx".to_string(),
            use_ha1: true,
        };

        let ha2 = DigestAuthPlugin::sha256_hex(&format!("{}:{}", method, uri));
        let response_hash = DigestAuthPlugin::sha256_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop, ha2
        ));

        let auth_header = format!(
            r#"Digest username="alice", realm="lynxx", nonce="{}", uri="{}", qop={}, nc={}, cnonce="{}", response="{}", algorithm=SHA-256"#,
            nonce, uri, qop, nc, cnonce, response_hash
        );

        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();

        plugin.on_request(&mut req).await.unwrap();

        assert!(
            req.extensions().get::<DigestChallenge>().is_none(),
            "HA1 mode with correct hash should pass"
        );
    }

    #[test]
    fn parse_digest_params_extracts_fields() {
        let header = r#"Digest username="alice", realm="lynxx", nonce="abc123", uri="/foo", qop=auth, nc=00000001, cnonce="xyz", response="deadbeef""#;
        let params = DigestAuthPlugin::parse_digest_params(header);

        assert_eq!(params.get("username").unwrap(), "alice");
        assert_eq!(params.get("realm").unwrap(), "lynxx");
        assert_eq!(params.get("nonce").unwrap(), "abc123");
        assert_eq!(params.get("uri").unwrap(), "/foo");
        assert_eq!(params.get("qop").unwrap(), "auth");
        assert_eq!(params.get("nc").unwrap(), "00000001");
        assert_eq!(params.get("cnonce").unwrap(), "xyz");
        assert_eq!(params.get("response").unwrap(), "deadbeef");
    }

    #[test]
    fn from_config_rejects_empty_users() {
        let result = DigestAuthPlugin::from_config(&serde_json::json!({
            "users": {}
        }));
        assert!(result.is_err());
    }

    #[test]
    fn from_config_defaults() {
        let plugin = DigestAuthPlugin::from_config(&serde_json::json!({
            "users": { "bob": "pw" }
        }))
        .unwrap();
        assert_eq!(plugin.realm, "lynxx");
        assert!(!plugin.use_ha1);
    }
}
