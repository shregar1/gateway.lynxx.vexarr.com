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
use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a server-issued nonce stays valid.
const NONCE_TTL: Duration = Duration::from_secs(300);
/// Backstop so a flood of challenges can't grow the nonce map without bound
/// (each entry is also pruned by TTL on every challenge).
const MAX_NONCES: usize = 8192;

/// Tracks a nonce the server issued: when, and the highest `nc` (request
/// counter) seen with it. A reused (nonce, nc) pair — i.e. `nc <= max_nc` —
/// is a replay and is rejected.
struct NonceEntry {
    created: Instant,
    max_nc: u64,
}

pub struct DigestAuthPlugin {
    /// username → password (or HA1 hex string when `use_ha1` is true).
    users: HashMap<String, String>,
    realm: String,
    use_ha1: bool,
    /// Nonces this instance has issued. A digest response is only accepted
    /// if it quotes a nonce we minted (and that is still fresh) — without
    /// this, any client-chosen nonce would validate, enabling unbounded
    /// replay.
    nonces: DashMap<String, NonceEntry>,
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
            nonces: DashMap::new(),
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

    /// Build the WWW-Authenticate challenge header value, recording the
    /// freshly-minted nonce so a later response quoting it can be accepted.
    fn build_challenge(&self) -> String {
        let nonce = Self::generate_nonce();
        self.prune_nonces();
        self.nonces.insert(
            nonce.clone(),
            NonceEntry {
                created: Instant::now(),
                max_nc: 0,
            },
        );
        format!(
            r#"Digest realm="{}", qop="auth", nonce="{}", algorithm=SHA-256"#,
            self.realm, nonce
        )
    }

    /// Drop expired nonces; clear entirely if a flood pushed us over the cap.
    fn prune_nonces(&self) {
        let now = Instant::now();
        self.nonces
            .retain(|_, e| now.duration_since(e.created) < NONCE_TTL);
        if self.nonces.len() > MAX_NONCES {
            self.nonces.clear();
        }
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
    ///
    /// `request_target` is the actual request-target (path + query) the
    /// gateway received; the digest `uri` parameter MUST equal it. Otherwise
    /// a client could compute a valid digest over an innocuous path (e.g.
    /// `/`) and replay it against a protected path — the response hash only
    /// covers the *claimed* uri, not the request line.
    fn validate(&self, method: &str, request_target: &str, params: &HashMap<String, String>) -> bool {
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

        // Bind the digest to the real request target.
        if uri != request_target {
            return false;
        }

        // The nonce must be one we issued and still fresh, and the request
        // counter (nc) must strictly increase per nonce to defeat replay.
        let nc_val = match u64::from_str_radix(nc, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let mut entry = match self.nonces.get_mut(nonce) {
            Some(e) => e,
            None => return false,
        };
        if Instant::now().duration_since(entry.created) >= NONCE_TTL {
            return false;
        }
        if nc_val <= entry.max_nc {
            return false;
        }

        let ha1 = match self.compute_ha1(username) {
            Some(h) => h,
            None => return false,
        };

        let ha2 = Self::sha256_hex(&format!("{}:{}", method, uri));
        let expected = Self::sha256_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop, ha2
        ));

        if crate::utilities::constant_time_eq(expected.as_bytes(), response.as_bytes()) {
            // Commit the new high-water mark only on success so a failed
            // guess can't burn a counter value.
            entry.max_nc = nc_val;
            true
        } else {
            false
        }
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
                let method = req.method().as_str().to_string();
                let request_target = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| req.uri().path().to_string());

                if !self.validate(&method, &request_target, &params) {
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
            nonces: DashMap::new(),
        }
    }

    /// Pretend the server already issued `nonce` (as `build_challenge`
    /// would), so a subsequent valid response can be accepted.
    fn seed_nonce(plugin: &DigestAuthPlugin, nonce: &str) {
        plugin.nonces.insert(
            nonce.to_string(),
            NonceEntry {
                created: Instant::now(),
                max_nc: 0,
            },
        );
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

        seed_nonce(&plugin, nonce);
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

        // Replaying the exact same (nonce, nc) must now fail.
        let mut replay = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();
        plugin.on_request(&mut replay).await.unwrap();
        assert!(
            replay.extensions().get::<DigestChallenge>().is_some(),
            "replaying the same nonce+nc must be rejected"
        );
    }

    #[tokio::test]
    async fn unissued_nonce_is_rejected() {
        let plugin = test_plugin();
        let method = "GET";
        let uri = "/protected";
        let nonce = "attackerchosen0000000000000000ab";
        let nc = "00000001";
        let cnonce = "cn";
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
        // NOTE: nonce is NOT seeded — the server never issued it.
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();
        plugin.on_request(&mut req).await.unwrap();
        assert!(
            req.extensions().get::<DigestChallenge>().is_some(),
            "a nonce the server never issued must be rejected"
        );
    }

    #[tokio::test]
    async fn uri_mismatch_is_rejected() {
        let plugin = test_plugin();
        let method = "GET";
        let signed_uri = "/public"; // what the digest is computed over
        let real_target = "/admin"; // the path actually requested
        let nonce = "fixednonce99999999999999999999ab";
        let nc = "00000001";
        let cnonce = "cn";
        let qop = "auth";
        let ha1 = DigestAuthPlugin::sha256_hex("alice:lynxx:secret");
        let ha2 = DigestAuthPlugin::sha256_hex(&format!("{}:{}", method, signed_uri));
        let response_hash = DigestAuthPlugin::sha256_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop, ha2
        ));
        let auth_header = format!(
            r#"Digest username="alice", realm="lynxx", nonce="{}", uri="{}", qop={}, nc={}, cnonce="{}", response="{}", algorithm=SHA-256"#,
            nonce, signed_uri, qop, nc, cnonce, response_hash
        );
        seed_nonce(&plugin, nonce);
        let mut req = Request::builder()
            .method(method)
            .uri(real_target)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();
        plugin.on_request(&mut req).await.unwrap();
        assert!(
            req.extensions().get::<DigestChallenge>().is_some(),
            "digest signed over a different uri than the request target must be rejected"
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
            nonces: DashMap::new(),
        };
        seed_nonce(&plugin, nonce);

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
