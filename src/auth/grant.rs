//! Zero-Trust Runtime Capability Tokens (JWT).
//!
//! This module handles the generation and verification of short-lived
//! execution grants. A grant is a signed JWT that
//! carries the set of features the client is allowed to execute.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Features or capabilities granted by the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Allow basic proxying.
    ProxyBasic,
    /// Allow high-performance LLM routing.
    LlmGateway,
    /// Allow semantic caching.
    SemanticCache,
    /// Allow WAF and security filters.
    SecurityWaf,
    /// Allow eBPF observability.
    ObservabilityEbpf,
    /// Allow time-travel debugging (recordings).
    TimeTravelDebug,
}

/// The internal state of a grant token.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantClaims {
    /// Unique token identifier (for revocation).
    pub jti: String,
    /// The customer/organization URN.
    pub sub: String,
    /// Device fingerprint ID.
    pub device_id: String,
    /// List of granted capabilities.
    pub caps: Vec<Capability>,
    /// Issued at (unix timestamp).
    pub iat: i64,
    /// Expiration (unix timestamp).
    pub exp: i64,
}

pub struct GrantManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    ttl: Duration,
}

impl GrantManager {
    pub fn new(secret: &str) -> anyhow::Result<Self> {
        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            ttl: Duration::minutes(5),
        })
    }

    /// Generate a new signed grant for a customer/device pair.
    pub fn create_grant(
        &self,
        customer_urn: &str,
        device_id: Uuid,
        capabilities: Vec<Capability>,
    ) -> anyhow::Result<(String, String)> {
        let token_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + self.ttl;

        let claims = GrantClaims {
            jti: token_id.clone(),
            sub: customer_urn.to_string(),
            device_id: device_id.to_string(),
            caps: capabilities,
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow::anyhow!("failed to encode jwt: {e}"))?;

        Ok((token, token_id))
    }

    /// Verify a token and return the claims.
    pub fn verify_grant(&self, token: &str) -> anyhow::Result<GrantClaims> {
        let token_data = decode::<GrantClaims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| anyhow::anyhow!("jwt verification failed: {e}"))?;

        Ok(token_data.claims)
    }
}
