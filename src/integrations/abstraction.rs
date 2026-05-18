//! Trait surface for outbound credential / signature services.
//!
//! Lynxx domain code consumes these traits — never a concrete client.
//! `KeyxClient` is one implementation today; tomorrow a different
//! backend can drop in (self-hosted Vault, static-key verifier, mock
//! for tests) by implementing the same traits and swapping the
//! `Arc<dyn …>` handed to `main.rs`.

use async_trait::async_trait;
use uuid::Uuid;

/// Principal returned by a [`TokenValidator`]. Backend-agnostic shape
/// — the impl translates from whatever its native representation is.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    pub tenant_id: i64,
    pub key_urn: Uuid,
    pub role: String,
    pub scopes: Vec<String>,
}

/// Uniform error shape across all verifier traits.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// Network / transport-level failure. Callers typically fall back
    /// to a cache or return 401 — do not retry on the hot path.
    #[error("verifier transport failure: {0}")]
    Transport(String),
    /// Backend HTTP / protocol error with a body for diagnostics.
    #[error("verifier returned {status}: {body}")]
    Http { status: u16, body: String },
    /// Backend confirmed the input is invalid (revoked / tampered /
    /// unknown). Distinct from `Http` — there's no network ambiguity
    /// to fall back from.
    #[error("verifier rejected: {0}")]
    Rejected(String),
    /// Backend response couldn't be parsed.
    #[error("verifier response malformed: {0}")]
    Malformed(String),
    /// The verifier was constructed without the config it needs (the
    /// concrete impl decides what "configured" means).
    #[error("verifier not configured")]
    NotConfigured,
}

/// Verifies a signed licence bundle (`payload` + `signature`) against
/// whatever the implementation considers an active signing key.
#[async_trait]
pub trait LicenseVerifier: Send + Sync {
    async fn verify_license(&self, payload: &[u8], signature: &str) -> Result<bool, VerifierError>;
}

/// Validates an opaque admin token (e.g. a keyx-issued bearer) and
/// returns the principal behind it.
#[async_trait]
pub trait TokenValidator: Send + Sync {
    async fn validate(&self, token: &str) -> Result<AdminPrincipal, VerifierError>;
}

/// Verifies an HMAC signature against a payload using a named key
/// (URN of the signing key managed by the backend).
#[async_trait]
pub trait HmacVerifier: Send + Sync {
    async fn verify_hmac(
        &self,
        key_urn: &str,
        payload: &[u8],
        signature_hex: &str,
    ) -> Result<bool, VerifierError>;
}
