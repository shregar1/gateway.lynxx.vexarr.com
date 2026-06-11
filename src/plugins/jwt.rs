use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{Request, Response};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::OnceCell;

const JWKS_FETCH_TIMEOUT_SECS: u64 = 10;

/// Source of the verification key.
enum KeySource {
    /// Built once at plugin init from `secret` (HS*) or `public_key` PEM (RS*).
    Static(DecodingKey),
    /// JWKS endpoint — fetched lazily on first request, cached for the
    /// plugin's lifetime. Each request decodes the JWT header's `kid` and
    /// looks up the matching JWK in the cached set, then builds a
    /// per-token DecodingKey. Re-fetch the JWKS by reloading the plugin
    /// (admin API → PluginExecutor::rebuild).
    Jwks {
        url: String,
        cache: OnceCell<JwkSet>,
    },
}

/// Real JWT verification. Three key sources, in priority order:
///   * `jwks_url`   — JWKS endpoint (e.g. keyx `/v1/jwks.json`); per-token
///     `kid` resolves to a JWK, no key rotation friction
///   * `public_key` — PEM (RS\*); static single-key verification
///   * `secret`     — shared secret (HS\*)
///
/// On success, injects the verified claims as a JSON-encoded
/// `X-Jwt-Claims` header so downstream services can consume them without
/// re-verifying.
pub struct JwtPlugin {
    key: KeySource,
    validation: Validation,
    header_name: HeaderName,
    scheme: String,
    claims_required: Vec<String>,
}

impl JwtPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
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
        let alg_str = cfg
            .get("algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("HS256");
        let algorithm = match alg_str {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            other => {
                return Err(GatewayError::BadRequest(format!(
                    "unsupported jwt algorithm: {other}"
                )))
            }
        };

        let key = if let Some(url) = cfg
            .get("jwks_url")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            KeySource::Jwks {
                url: url.to_string(),
                cache: OnceCell::new(),
            }
        } else if let Some(pk) = cfg.get("public_key").and_then(|v| v.as_str()) {
            // Static PEM. RS\* path.
            KeySource::Static(DecodingKey::from_rsa_pem(pk.as_bytes()).map_err(|e| {
                GatewayError::BadRequest(format!("invalid jwt public_key PEM: {e}"))
            })?)
        } else {
            // Static secret. HS\* path.
            let secret = cfg.get("secret").and_then(|v| v.as_str()).unwrap_or("");
            KeySource::Static(DecodingKey::from_secret(secret.as_bytes()))
        };

        let mut validation = Validation::new(algorithm);
        // We perform our own required-claims check below so we can name the
        // missing claim in the error.
        validation.required_spec_claims.clear();
        validation.validate_exp = true;
        validation.validate_nbf = cfg
            .get("validate_nbf")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(leeway) = cfg.get("leeway_secs").and_then(|v| v.as_u64()) {
            validation.leeway = leeway;
        }
        // Issuer / audience binding. Without these a token minted by the same
        // IdP (same signing key) for a DIFFERENT service/audience would be
        // accepted here. Accept a string or an array for each.
        let str_or_array = |v: &serde_json::Value| -> Vec<String> {
            if let Some(s) = v.as_str() {
                vec![s.to_string()]
            } else if let Some(arr) = v.as_array() {
                arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()
            } else {
                Vec::new()
            }
        };
        match cfg.get("issuer").map(str_or_array) {
            Some(iss) if !iss.is_empty() => validation.set_issuer(&iss),
            _ => {}
        }
        match cfg.get("audience").map(str_or_array) {
            Some(aud) if !aud.is_empty() => validation.set_audience(&aud),
            // No audience configured: don't reject tokens that merely carry an
            // `aud` claim (preserves existing behaviour). Operators bind it
            // explicitly via config to enforce.
            _ => validation.validate_aud = false,
        }

        let claims_required = cfg
            .get("claims_required")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["sub".into(), "exp".into()]);

        Ok(Self {
            key,
            validation,
            header_name,
            scheme,
            claims_required,
        })
    }

    /// Resolve the JWKS-mode per-token DecodingKey. Fetches the JWKS on
    /// first call (cached for the plugin's lifetime), then matches the
    /// JWT header's `kid` against the set.
    async fn resolve_jwks_key(
        url: &str,
        cache: &OnceCell<JwkSet>,
        token: &str,
    ) -> Result<DecodingKey, PluginError> {
        let jwks = cache
            .get_or_try_init(|| fetch_jwks(url))
            .await
            .map_err(|e| PluginError::Unauthorized(format!("JWKS fetch failed: {e}")))?;

        let header = decode_header(token)
            .map_err(|e| PluginError::Unauthorized(format!("JWT header parse: {e}")))?;
        let kid = header.kid.ok_or_else(|| {
            PluginError::Unauthorized("JWT missing `kid` (required in JWKS mode)".into())
        })?;
        let jwk = jwks
            .find(&kid)
            .ok_or_else(|| PluginError::Unauthorized(format!("kid `{kid}` not in JWKS")))?;
        DecodingKey::from_jwk(jwk)
            .map_err(|e| PluginError::Unauthorized(format!("JWK→DecodingKey: {e}")))
    }

    fn extract_token<'a>(&self, raw: &'a str) -> Option<&'a str> {
        if self.scheme.is_empty() {
            return Some(raw.trim());
        }
        let prefix = format!("{} ", self.scheme);
        raw.strip_prefix(&prefix).map(str::trim)
    }
}

#[async_trait]
impl Plugin for JwtPlugin {
    fn name(&self) -> &str {
        "jwt"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let raw = req
            .headers()
            .get(&self.header_name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| PluginError::Unauthorized("missing JWT header".into()))?;
        let token = self
            .extract_token(raw)
            .ok_or_else(|| PluginError::Unauthorized("malformed JWT header".into()))?;

        let data = match &self.key {
            KeySource::Static(k) => decode::<serde_json::Value>(token, k, &self.validation)
                .map_err(|e| PluginError::Unauthorized(format!("invalid JWT: {e}")))?,
            KeySource::Jwks { url, cache } => {
                let dk = Self::resolve_jwks_key(url, cache, token).await?;
                decode::<serde_json::Value>(token, &dk, &self.validation)
                    .map_err(|e| PluginError::Unauthorized(format!("invalid JWT: {e}")))?
            }
        };

        for claim in &self.claims_required {
            if data.claims.get(claim).is_none() {
                return Err(PluginError::Unauthorized(format!(
                    "missing required claim: {claim}"
                )));
            }
        }

        let claims_json = serde_json::to_string(&data.claims)
            .map_err(|e| PluginError::Internal(format!("claims serialize: {e}")))?;
        if let Ok(value) = HeaderValue::from_str(&claims_json) {
            req.headers_mut().insert("x-jwt-claims", value);
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

async fn fetch_jwks(url: &str) -> Result<JwkSet, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(JWKS_FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    resp.json::<JwkSet>().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Symmetric HS256 keypair-equivalent (just a shared secret) wrapped
    /// as a JWK so we don't need RSA material in tests. The `kid`
    /// matches what the test JWTs carry in their header.
    fn oct_jwks(kid: &str, secret: &str) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        serde_json::json!({
            "keys": [{
                "kty": "oct",
                "alg": "HS256",
                "kid": kid,
                "k":   URL_SAFE_NO_PAD.encode(secret.as_bytes()),
            }]
        })
    }

    fn sign_token(kid: &str, secret: &str, sub: &str) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.into());
        let claims = serde_json::json!({
            "sub": sub,
            "exp": (chrono::Utc::now() + chrono::Duration::seconds(60)).timestamp(),
        });
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn req_with_bearer(token: &str) -> Request<Body> {
        Request::builder()
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn jwks_mode_verifies_token_signed_by_published_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(oct_jwks("k1", "shared-secret-bytes-do-not-leak")),
            )
            .mount(&server)
            .await;

        let plugin = JwtPlugin::from_config(&serde_json::json!({
            "algorithm": "HS256",
            "jwks_url": format!("{}/jwks.json", server.uri()),
        }))
        .unwrap();

        let token = sign_token("k1", "shared-secret-bytes-do-not-leak", "alice");
        let mut req = req_with_bearer(&token);
        plugin.on_request(&mut req).await.unwrap();
        assert!(req.headers().get("x-jwt-claims").is_some());
    }

    #[tokio::test]
    async fn jwks_mode_rejects_token_with_unknown_kid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(oct_jwks("k1", "secret")))
            .mount(&server)
            .await;

        let plugin = JwtPlugin::from_config(&serde_json::json!({
            "algorithm": "HS256",
            "jwks_url": format!("{}/jwks.json", server.uri()),
        }))
        .unwrap();

        let token = sign_token("rotated-kid", "secret", "alice");
        let mut req = req_with_bearer(&token);
        let err = plugin.on_request(&mut req).await.unwrap_err();
        match err {
            PluginError::Unauthorized(msg) => {
                assert!(msg.contains("not in JWKS"), "want 'not in JWKS', got {msg}")
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn jwks_mode_rejects_token_missing_kid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(oct_jwks("k1", "secret")))
            .mount(&server)
            .await;

        let plugin = JwtPlugin::from_config(&serde_json::json!({
            "algorithm": "HS256",
            "jwks_url": format!("{}/jwks.json", server.uri()),
        }))
        .unwrap();

        // Sign WITHOUT a kid in the header.
        let header = Header::new(Algorithm::HS256);
        let claims = serde_json::json!({
            "sub": "alice",
            "exp": (chrono::Utc::now() + chrono::Duration::seconds(60)).timestamp(),
        });
        let token = encode(&header, &claims, &EncodingKey::from_secret(b"secret")).unwrap();

        let mut req = req_with_bearer(&token);
        let err = plugin.on_request(&mut req).await.unwrap_err();
        match err {
            PluginError::Unauthorized(msg) => assert!(msg.contains("missing `kid`")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn jwks_mode_propagates_fetch_failure() {
        // Point at a port that's almost certainly closed.
        let plugin = JwtPlugin::from_config(&serde_json::json!({
            "algorithm": "HS256",
            "jwks_url": "http://127.0.0.1:1/nope",
        }))
        .unwrap();

        let token = sign_token("k1", "secret", "alice");
        let mut req = req_with_bearer(&token);
        let err = plugin.on_request(&mut req).await.unwrap_err();
        assert!(matches!(err, PluginError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn static_secret_path_still_works() {
        let plugin = JwtPlugin::from_config(&serde_json::json!({
            "algorithm": "HS256",
            "secret": "shared-secret",
        }))
        .unwrap();
        let header = Header::new(Algorithm::HS256);
        let claims = serde_json::json!({
            "sub": "alice",
            "exp": (chrono::Utc::now() + chrono::Duration::seconds(60)).timestamp(),
        });
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap();
        let mut req = req_with_bearer(&token);
        plugin.on_request(&mut req).await.unwrap();
        assert!(req.headers().get("x-jwt-claims").is_some());
    }
}
