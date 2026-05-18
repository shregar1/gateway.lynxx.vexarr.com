//! keyx — API key & licence management (api.keyx.vexarr.com).
//!
//! Phase 1 surface: licence verification only.
//!
//! A keyx-issued licence is a signed bundle: an Ed25519 signature over
//! a JSON payload that the operator pastes into `[license]`. On boot,
//! lynxx parses the payload locally for tier / expiry / quota fields
//! and asks keyx to confirm the signature is still bound to an active
//! signing key. Revocation = keyx flips the signing key off; the next
//! re-verify cycle catches it.
//!
//! ## Wire format
//!
//! Request:
//! ```http
//! POST {base_url}/v1/keys/{license_urn}/verify-license
//! Authorization: Bearer {service_token}
//! Content-Type: application/json
//!
//! { "payload": "<base64 payload>", "signature": "<base64 ed25519>" }
//! ```
//!
//! No `X-Tenant-Id` is sent — keyx looks the tenant up from the URN
//! itself on this endpoint, so the operator never has to know it.
//!
//! Response (Vexarr envelope):
//! ```json
//! { "status": "SUCCESS", "data": { "valid": true }, ... }
//! ```

use crate::integrations::abstraction::{
    AdminPrincipal, HmacVerifier, LicenseVerifier, TokenValidator, VerifierError,
};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use std::time::Duration;
use uuid::Uuid;

const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Default)]
pub struct KeyxConfig {
    pub base_url: String,
    pub service_token: String,
    pub license_urn: String,
}

impl KeyxConfig {
    /// True once every field the client needs has been populated.
    /// Empty / whitespace counts as unset.
    pub fn is_configured(&self) -> bool {
        !self.base_url.trim().is_empty()
            && !self.service_token.trim().is_empty()
            && !self.license_urn.trim().is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyxError {
    #[error(
        "keyx not configured (set VEXARR_KEYX_URL, VEXARR_SERVICE_API_KEY, VEXARR_KEYX_LICENSE_URN \
         — or the legacy KEYX_BASE_URL / KEYX_SERVICE_TOKEN / KEYX_LICENSE_URN)"
    )]
    NotConfigured,
    #[error("keyx request failed: {0}")]
    Transport(String),
    #[error("keyx returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("keyx response malformed: {0}")]
    Malformed(String),
}

#[derive(Clone)]
pub struct KeyxClient {
    inner: reqwest::Client,
    config: KeyxConfig,
}

impl KeyxClient {
    pub fn new(config: KeyxConfig) -> Result<Self, KeyxError> {
        if !config.is_configured() {
            return Err(KeyxError::NotConfigured);
        }
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| KeyxError::Transport(e.to_string()))?;
        Ok(Self { inner, config })
    }

    /// Validate an arbitrary api-key token against keyx — used by the
    /// admin-auth middleware to accept keyx-issued tokens alongside the
    /// local `admin_tokens` table. Returns the keyx principal on
    /// success (caller maps `role` → lynxx Role); returns
    /// `KeyxError::Http { status: 401, .. }` when keyx rejects the
    /// token.
    pub async fn validate_token(&self, token: &str) -> Result<KeyxPrincipal, KeyxError> {
        let url = format!(
            "{}/v1/keys/validate",
            self.config.base_url.trim_end_matches('/'),
        );
        let body = serde_json::json!({ "key": token });

        let resp = self
            .inner
            .post(&url)
            .bearer_auth(&self.config.service_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KeyxError::Transport(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| KeyxError::Transport(e.to_string()))?;

        if !status.is_success() {
            return Err(KeyxError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<KeyxPrincipal> = serde_json::from_str(&text)
            .map_err(|e| KeyxError::Malformed(format!("{e}: {text}")))?;

        match envelope.status {
            EnvelopeStatus::Success => Ok(envelope.data),
            EnvelopeStatus::Failed => Err(KeyxError::Http {
                status: status.as_u16(),
                body: envelope.response_message,
            }),
        }
    }

    /// Ask keyx whether `signature` is a valid HMAC-SHA256 of `payload`
    /// produced by the HMAC secret behind the configured `license_urn`.
    /// Wire format: keyx accepts `signature` as **hex**, not base64 —
    /// callers that work with binary or base64 must convert.
    pub async fn verify_hmac(
        &self,
        urn: &str,
        payload: &[u8],
        signature_hex: &str,
    ) -> Result<bool, KeyxError> {
        let url = format!(
            "{}/v1/keys/{}/verify-hmac",
            self.config.base_url.trim_end_matches('/'),
            urn,
        );
        let body = serde_json::json!({
            "payload":   B64.encode(payload),
            "signature": signature_hex,
        });

        let resp = self
            .inner
            .post(&url)
            .bearer_auth(&self.config.service_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KeyxError::Transport(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| KeyxError::Transport(e.to_string()))?;

        if !status.is_success() {
            return Err(KeyxError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<ValidPayload> = serde_json::from_str(&text)
            .map_err(|e| KeyxError::Malformed(format!("{e}: {text}")))?;

        match envelope.status {
            EnvelopeStatus::Success => Ok(envelope.data.valid),
            EnvelopeStatus::Failed => Err(KeyxError::Http {
                status: status.as_u16(),
                body: envelope.response_message,
            }),
        }
    }

    /// Ask keyx whether `signature` is a valid Ed25519 signature over
    /// `payload` produced by the signing key behind `license_urn`.
    /// Returns `Ok(true)` on a valid signature for an active key,
    /// `Ok(false)` when keyx says the signature does not verify (either
    /// because the bytes are wrong or the key has been revoked), and
    /// `Err` for transport / HTTP / parse failures.
    pub async fn verify_license(&self, payload: &[u8], signature: &str) -> Result<bool, KeyxError> {
        let url = format!(
            "{}/v1/keys/{}/verify-license",
            self.config.base_url.trim_end_matches('/'),
            self.config.license_urn,
        );
        let body = serde_json::json!({
            "payload": B64.encode(payload),
            "signature": signature,
        });

        let resp = self
            .inner
            .post(&url)
            .bearer_auth(&self.config.service_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KeyxError::Transport(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| KeyxError::Transport(e.to_string()))?;

        if !status.is_success() {
            return Err(KeyxError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<ValidPayload> = serde_json::from_str(&text)
            .map_err(|e| KeyxError::Malformed(format!("{e}: {text}")))?;

        match envelope.status {
            EnvelopeStatus::Success => Ok(envelope.data.valid),
            EnvelopeStatus::Failed => Err(KeyxError::Http {
                status: status.as_u16(),
                body: envelope.response_message,
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum EnvelopeStatus {
    Success,
    Failed,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    status: EnvelopeStatus,
    #[serde(rename = "responseMessage", default)]
    response_message: String,
    data: T,
}

#[derive(Debug, Deserialize)]
struct ValidPayload {
    valid: bool,
}

/// Principal returned by `POST /v1/keys/validate`. Only the fields
/// lynxx needs are decoded — keyx returns more.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyxPrincipal {
    pub tenant_id: i64,
    pub api_key_urn: Uuid,
    /// Keyx's role string ("admin" / "owner" / "service" / "pat" / …).
    /// The caller maps this onto its own role model.
    pub role: String,
    pub key_type: String,
    pub environment: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

// ─── Trait implementations ──────────────────────────────────────────────
//
// Lynxx domain code consumes the traits from `integrations::abstraction`
// — never a concrete `KeyxClient`. These thin impls bridge the inherent
// methods above to the abstract interface, translating `KeyxError` into
// the backend-agnostic `VerifierError`.

impl From<KeyxError> for VerifierError {
    fn from(e: KeyxError) -> Self {
        match e {
            KeyxError::NotConfigured => VerifierError::NotConfigured,
            KeyxError::Transport(s) => VerifierError::Transport(s),
            KeyxError::Http { status, body } => VerifierError::Http { status, body },
            KeyxError::Malformed(s) => VerifierError::Malformed(s),
        }
    }
}

#[async_trait]
impl LicenseVerifier for KeyxClient {
    async fn verify_license(&self, payload: &[u8], signature: &str) -> Result<bool, VerifierError> {
        KeyxClient::verify_license(self, payload, signature)
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl TokenValidator for KeyxClient {
    async fn validate(&self, token: &str) -> Result<AdminPrincipal, VerifierError> {
        let p = KeyxClient::validate_token(self, token)
            .await
            .map_err(VerifierError::from)?;
        Ok(AdminPrincipal {
            tenant_id: p.tenant_id,
            key_urn: p.api_key_urn,
            role: p.role,
            scopes: p.scopes,
        })
    }
}

#[async_trait]
impl HmacVerifier for KeyxClient {
    async fn verify_hmac(
        &self,
        key_urn: &str,
        payload: &[u8],
        signature_hex: &str,
    ) -> Result<bool, VerifierError> {
        KeyxClient::verify_hmac(self, key_urn, payload, signature_hex)
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(base_url: String) -> KeyxConfig {
        KeyxConfig {
            base_url,
            service_token: "svc_token".into(),
            license_urn: "00000000-0000-0000-0000-000000000001".into(),
        }
    }

    fn envelope(data: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "transactionUrn": "urn:keyx:txn:abc",
            "status": "SUCCESS",
            "responseMessage": "OK",
            "responseKey": "SUCCESS",
            "errors": [],
            "timestamp": "2026-05-16T00:00:00+00:00",
            "metadata": {},
            "data": data,
        })
    }

    #[tokio::test]
    async fn rejects_empty_config() {
        let empty = KeyxConfig::default();
        assert!(matches!(
            KeyxClient::new(empty),
            Err(KeyxError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn verify_license_sends_signed_payload_with_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/keys/00000000-0000-0000-0000-000000000001/verify-license",
            ))
            .and(header("authorization", "Bearer svc_token"))
            .and(body_json(serde_json::json!({
                "payload": B64.encode(b"hello"),
                "signature": "sig-bytes",
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": true }))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let ok = client.verify_license(b"hello", "sig-bytes").await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn verify_license_returns_false_when_keyx_says_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": false }))),
            )
            .mount(&server)
            .await;

        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let ok = client.verify_license(b"x", "y").await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn verify_license_propagates_http_error_with_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let err = client.verify_license(b"x", "y").await.unwrap_err();
        match err {
            KeyxError::Http { status, body } => {
                assert_eq!(status, 401);
                assert_eq!(body, "unauthorized");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_license_flags_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let err = client.verify_license(b"x", "y").await.unwrap_err();
        assert!(matches!(err, KeyxError::Malformed(_)));
    }

    #[tokio::test]
    async fn verify_hmac_round_trips_payload_and_hex_signature() {
        let server = MockServer::start().await;
        let urn = "00000000-0000-0000-0000-0000000000bb";
        Mock::given(method("POST"))
            .and(path(format!("/v1/keys/{urn}/verify-hmac")))
            .and(header("authorization", "Bearer svc_token"))
            .and(body_json(serde_json::json!({
                "payload":   B64.encode(b"date: Mon, 16 May 2026 00:00:00 GMT"),
                "signature": "deadbeef",
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": true }))),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let ok = client
            .verify_hmac(urn, b"date: Mon, 16 May 2026 00:00:00 GMT", "deadbeef")
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn verify_hmac_returns_false_when_keyx_says_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": false }))),
            )
            .mount(&server)
            .await;
        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let ok = client
            .verify_hmac("00000000-0000-0000-0000-0000000000bb", b"x", "00")
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn validate_token_returns_principal_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/keys/validate"))
            .and(header("authorization", "Bearer svc_token"))
            .and(body_json(serde_json::json!({ "key": "ak_live_xxx" })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(envelope(serde_json::json!({
                    "tenant_id":   42,
                    "tenant_urn":  "00000000-0000-0000-0000-000000000042",
                    "api_key_id":  7,
                    "api_key_urn": "00000000-0000-0000-0000-000000000007",
                    "role":        "admin",
                    "key_type":    "admin",
                    "environment": "live",
                    "scopes":      ["read", "write"],
                }))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let p = client.validate_token("ak_live_xxx").await.unwrap();
        assert_eq!(p.tenant_id, 42);
        assert_eq!(p.role, "admin");
        assert_eq!(p.scopes, vec!["read", "write"]);
    }

    #[tokio::test]
    async fn validate_token_propagates_401() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid_key"))
            .mount(&server)
            .await;
        let client = KeyxClient::new(cfg(server.uri())).unwrap();
        let err = client.validate_token("bad").await.unwrap_err();
        assert!(matches!(err, KeyxError::Http { status: 401, .. }));
    }

    #[tokio::test]
    async fn base_url_trailing_slash_does_not_double_up() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/keys/00000000-0000-0000-0000-000000000001/verify-license",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(envelope(serde_json::json!({ "valid": true }))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let mut c = cfg(server.uri());
        c.base_url.push('/');
        let client = KeyxClient::new(c).unwrap();
        assert!(client.verify_license(b"x", "y").await.unwrap());
    }
}
