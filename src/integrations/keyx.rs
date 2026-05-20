//! keyx — API key & licence management (auth.vexarr.com).
//!
//! Single responsibility: take a customer api key (`lnx_live_…`) and
//! ask keyx whether it is still active. On success, keyx returns the
//! associated licence (tier, expiry, node caps, quota) — that's what
//! the gateway runs on. Revocation = keyx flips the key inactive; the
//! next re-verify cycle catches it.
//!
//! ## Wire format
//!
//! Request:
//! ```http
//! POST https://auth.vexarr.com/v1/keys/verify
//! Authorization: Bearer {api_key}
//! ```
//!
//! Response (Vexarr envelope):
//! ```json
//! {
//!   "status": "SUCCESS",
//!   "data": {
//!     "valid":              true,
//!     "customer_urn":       "cus_abc",
//!     "tier":               "enterprise",
//!     "expires_at":         1893456000,
//!     "max_nodes":          5,
//!     "active_nodes":       1,
//!     "monthly_call_limit": 1000000,
//!     "allow_overage":      true
//!   }
//! }
//! ```
//!
//! When `data.valid` is `false` the call surfaces as
//! [`KeyxError::Rejected`] — the key is revoked / unknown / out of seats.

use crate::integrations::abstraction::{LicenseInfo, LicenseVerifier, VerifierError};
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

/// Keyx instance. Picked up at **compile time** from the `AUTH_URL`
/// env var — `env!` fails the build if it is unset, so there is no
/// silent default and no runtime override. Whatever URL the dev
/// passes to `cargo build` is what the binary talks to. Production:
/// `AUTH_URL=https://auth.vexarr.com cargo build --release`. Local
/// stub: `AUTH_URL=http://127.0.0.1:9100 cargo run`.
const KEYX_BASE_URL: &str = env!(
    "AUTH_URL",
    "AUTH_URL is required at compile time and was not set. \
     Pass it on the cargo command, e.g. \
     `AUTH_URL=https://auth.vexarr.com cargo build --release` for production, \
     or `AUTH_URL=http://127.0.0.1:9100 cargo run` for local keyx-stub testing. \
     There is intentionally NO default — this prevents shipping a binary \
     that points at the wrong auth backend.",
);

const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, thiserror::Error)]
pub enum KeyxError {
    #[error("keyx request failed: {0}")]
    Transport(String),
    #[error("keyx returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("keyx rejected the api key: {0}")]
    Rejected(String),
    #[error("keyx response malformed: {0}")]
    Malformed(String),
}

#[derive(Clone)]
pub struct KeyxClient {
    inner: reqwest::Client,
}

impl KeyxClient {
    pub fn new() -> Result<Self, KeyxError> {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| KeyxError::Transport(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Override the base URL (test-only). Production code constructs via
    /// [`KeyxClient::new`] which always uses [`KEYX_BASE_URL`].
    #[cfg(test)]
    fn with_base_url(base_url: String) -> Result<KeyxClientTest, KeyxError> {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| KeyxError::Transport(e.to_string()))?;
        Ok(KeyxClientTest { inner, base_url })
    }

    pub async fn validate_license(&self, api_key: &str) -> Result<LicenseInfo, KeyxError> {
        validate_license_against(&self.inner, KEYX_BASE_URL, api_key).await
    }
}

#[cfg(test)]
struct KeyxClientTest {
    inner: reqwest::Client,
    base_url: String,
}

#[cfg(test)]
impl KeyxClientTest {
    async fn validate_license(&self, api_key: &str) -> Result<LicenseInfo, KeyxError> {
        validate_license_against(&self.inner, &self.base_url, api_key).await
    }
}

async fn validate_license_against(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
) -> Result<LicenseInfo, KeyxError> {
    let url = format!("{}/v1/keys/verify", base_url.trim_end_matches('/'),);

    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .header("content-length", "0")
        .send()
        .await
        .map_err(|e| KeyxError::Transport(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| KeyxError::Transport(e.to_string()))?;

    // 4xx from keyx is an authoritative verdict on the request (bad key,
    // malformed request, forbidden) — surface as Rejected so the caller
    // does NOT fall back to the offline cache. 5xx / transport remain
    // ambiguous; those still map to Http and the cache covers them.
    if status.is_client_error() {
        let msg = parse_envelope_message(&text).unwrap_or_else(|| {
            if text.is_empty() {
                format!("keyx returned {}", status.as_u16())
            } else {
                text.clone()
            }
        });
        return Err(KeyxError::Rejected(msg));
    }
    if !status.is_success() {
        return Err(KeyxError::Http {
            status: status.as_u16(),
            body: text,
        });
    }

    let envelope: ApiEnvelope<LicensePayload> =
        serde_json::from_str(&text).map_err(|e| KeyxError::Malformed(format!("{e}: {text}")))?;

    match envelope.status {
        EnvelopeStatus::Success => {
            if !envelope.data.valid {
                return Err(KeyxError::Rejected(
                    if envelope.response_message.is_empty() {
                        "key is not active".into()
                    } else {
                        envelope.response_message
                    },
                ));
            }
            Ok(LicenseInfo {
                customer_urn: envelope.data.customer_urn,
                tier: envelope.data.tier,
                expires_at: envelope.data.expires_at,
                max_nodes: envelope.data.max_nodes,
                active_nodes: envelope.data.active_nodes,
                monthly_call_limit: envelope.data.monthly_call_limit,
                allow_overage: envelope.data.allow_overage,
            })
        }
        EnvelopeStatus::Failed => Err(KeyxError::Rejected(envelope.response_message)),
    }
}

/// Pull `responseMessage` out of a Vexarr envelope body — returns
/// `None` if the body isn't an envelope or doesn't carry a message.
/// Used on non-2xx replies to give the operator the actionable line
/// instead of the full envelope blob.
fn parse_envelope_message(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("responseMessage")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
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
struct LicensePayload {
    #[serde(default)]
    valid: bool,
    #[serde(default, alias = "customer_id")]
    customer_urn: String,
    #[serde(default)]
    tier: String,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    max_nodes: Option<u32>,
    #[serde(default)]
    active_nodes: u32,
    #[serde(default)]
    monthly_call_limit: Option<u64>,
    #[serde(default)]
    allow_overage: bool,
}

impl From<KeyxError> for VerifierError {
    fn from(e: KeyxError) -> Self {
        match e {
            KeyxError::Transport(s) => VerifierError::Transport(s),
            KeyxError::Http { status, body } => VerifierError::Http { status, body },
            KeyxError::Rejected(s) => VerifierError::Rejected(s),
            KeyxError::Malformed(s) => VerifierError::Malformed(s),
        }
    }
}

#[async_trait]
impl LicenseVerifier for KeyxClient {
    async fn validate_license(&self, api_key: &str) -> Result<LicenseInfo, VerifierError> {
        KeyxClient::validate_license(self, api_key)
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    async fn validate_license_sends_api_key_as_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/keys/verify"))
            .and(header("authorization", "Bearer lnx_live_xxx"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(envelope(serde_json::json!({
                    "valid":              true,
                    "customer_urn":       "cus_abc",
                    "tier":               "enterprise",
                    "expires_at":         1893456000_i64,
                    "max_nodes":          5,
                    "active_nodes":       1,
                    "monthly_call_limit": 1000000,
                    "allow_overage":      true,
                }))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = KeyxClient::with_base_url(server.uri()).unwrap();
        let info = client.validate_license("lnx_live_xxx").await.unwrap();
        assert_eq!(info.customer_urn, "cus_abc");
        assert_eq!(info.tier, "enterprise");
        assert_eq!(info.max_nodes, Some(5));
        assert!(info.allow_overage);
    }

    #[tokio::test]
    async fn validate_license_surfaces_rejected_when_keyx_says_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(envelope(serde_json::json!({
                    "valid": false,
                }))),
            )
            .mount(&server)
            .await;

        let client = KeyxClient::with_base_url(server.uri()).unwrap();
        let err = client.validate_license("revoked").await.unwrap_err();
        assert!(matches!(err, KeyxError::Rejected(_)));
    }

    #[tokio::test]
    async fn validate_license_maps_4xx_to_rejected_with_envelope_message() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "transactionUrn":  "urn:keyx:err:1",
                "status":          "FAILED",
                "responseMessage": "invalid service api key",
                "responseKey":     "INVALID_SERVICE_KEY",
                "errors":          [],
                "data":            null,
            })))
            .mount(&server)
            .await;

        let client = KeyxClient::with_base_url(server.uri()).unwrap();
        let err = client.validate_license("bad").await.unwrap_err();
        match err {
            KeyxError::Rejected(msg) => assert_eq!(msg, "invalid service api key"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_license_maps_4xx_to_rejected_with_raw_body_fallback() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let client = KeyxClient::with_base_url(server.uri()).unwrap();
        let err = client.validate_license("bad").await.unwrap_err();
        match err {
            KeyxError::Rejected(msg) => assert_eq!(msg, "forbidden"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_license_keeps_5xx_as_http_for_cache_fallback() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let client = KeyxClient::with_base_url(server.uri()).unwrap();
        let err = client.validate_license("any").await.unwrap_err();
        match err {
            KeyxError::Http { status, body } => {
                assert_eq!(status, 503);
                assert_eq!(body, "down");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_license_flags_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = KeyxClient::with_base_url(server.uri()).unwrap();
        let err = client.validate_license("x").await.unwrap_err();
        assert!(matches!(err, KeyxError::Malformed(_)));
    }
}
