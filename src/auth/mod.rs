//! Admin API authentication.
//!
//! Bearer-token model: tokens are stored as SHA-256 hashes in the
//! `admin_tokens` table. The raw token value is only ever returned to the
//! caller once, at creation time. Tokens carry a [`Role`] which the
//! per-route guard middleware compares against the route's minimum.

pub mod grant;
pub mod handshake;
pub mod middleware;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Argon2id hashing for commercial API keys.
/// API keys are hashed with a unique salt and stored in the database.
pub fn hash_api_key(raw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(raw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string();
    Ok(password_hash)
}

/// Verify a raw API key against a stored Argon2id hash.
pub fn verify_api_key(raw: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(raw.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Role assigned to an admin token.
///
/// Ordering: `Viewer < Operator < Admin`. The middleware uses `>=` to
/// compare a request's role against a route's minimum requirement.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    fn rank(&self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Operator => 1,
            Role::Admin => 2,
        }
    }
}

impl PartialOrd for Role {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Role {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        };
        f.write_str(s)
    }
}

impl FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

/// An admin token row, minus the raw token (which we never persist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminToken {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Per-token scopes. Currently populated only for keyx-issued
    /// tokens (the keyx principal carries `scopes`); local
    /// `admin_tokens` rows have no scope column today, so the field
    /// is always empty for them. Persisted-via-serde tolerant via
    /// `#[serde(default)]`.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl AdminToken {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// Hex-encoded SHA-256 of the raw token. Used as the lookup key in
/// `admin_tokens.token_hash` so the raw value never touches storage.
pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Generate a new random token: `lnx_` + base64-url(no pad) of 32 random
/// bytes. ~43 chars after the prefix. Use [`hash_token`] before storing.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body = URL_SAFE_NO_PAD.encode(bytes);
    format!("lnx_{body}")
}

/// Tiny hex encoder; avoids pulling in `hex` crate just for this.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ordering() {
        assert!(Role::Viewer < Role::Operator);
        assert!(Role::Operator < Role::Admin);
        assert!(Role::Admin >= Role::Viewer);
    }

    #[test]
    fn role_roundtrip() {
        for r in [Role::Viewer, Role::Operator, Role::Admin] {
            assert_eq!(Role::from_str(&r.to_string()).unwrap(), r);
        }
    }

    #[test]
    fn token_format() {
        let t = generate_token();
        assert!(t.starts_with("lnx_"));
        assert!(t.len() > 20);
    }

    #[test]
    fn hash_is_stable() {
        assert_eq!(hash_token("hello"), hash_token("hello"));
        assert_ne!(hash_token("a"), hash_token("b"));
        assert_eq!(hash_token("").len(), 64);
    }
}
