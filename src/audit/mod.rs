//! Tamper-evident audit log for admin mutations.
//!
//! Each row's `hash` is `sha256(prev_hash || canonical_serialised_row)` —
//! tampering with any past row breaks the chain. The chain head lives in
//! `audit_log.hash` of the row with the largest `id`.
//!
//! Writes are best-effort: failures are logged at WARN and never block the
//! admin request that triggered the audit.

use crate::auth::AdminToken;
use crate::db::Repository;
use crate::error::GatewayError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditAction {
    Create,
    Update,
    Delete,
    Reload,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Create => "create",
            AuditAction::Update => "update",
            AuditAction::Delete => "delete",
            AuditAction::Reload => "reload",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    Project,
    Service,
    Route,
    Plugin,
    Consumer,
    Target,
    Token,
    Config,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::Project => "project",
            ResourceType::Service => "service",
            ResourceType::Route => "route",
            ResourceType::Plugin => "plugin",
            ResourceType::Consumer => "consumer",
            ResourceType::Target => "target",
            ResourceType::Token => "token",
            ResourceType::Config => "config",
        }
    }
}

/// One row of the audit log.
///
/// `id` is auto-assigned by the DB; we don't include it in the hash so
/// hashes are reproducible across SQLite/PG (where AUTOINCREMENT vs
/// BIGSERIAL semantics differ slightly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
    pub actor_name: Option<String>,
    pub actor_role: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub diff: Option<serde_json::Value>,
    pub hash: String,
    pub prev_hash: Option<String>,
}

/// Filter for audit-log queries (`GET /audit`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    /// When true, include the full `diff` JSON blob per row. The list
    /// endpoint defaults to false (diff omitted) to keep payloads small;
    /// chain verification sets this to true because diffs are hashed.
    #[serde(default)]
    pub include_diff: bool,
}

impl AuditFilter {
    pub fn effective_limit(&self) -> u32 {
        self.limit.unwrap_or(100).clamp(1, 1000)
    }
}

/// New-row payload — the chain `hash` and `prev_hash` are filled in by
/// `Repository::append_audit` so that hash computation and insertion stay
/// atomic at the DB layer.
#[derive(Debug, Clone, Serialize)]
pub struct NewAuditEntry {
    pub ts: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
    pub actor_name: Option<String>,
    pub actor_role: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub diff: Option<serde_json::Value>,
}

/// Compute the chained hash for a row. Inputs in a fixed order so SQLite
/// and Postgres backends agree.
pub fn compute_hash(prev: Option<&str>, entry: &NewAuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(entry.ts.to_rfc3339().as_bytes());
    hasher.update(b"|");
    hasher.update(
        entry
            .actor_id
            .map(|u| u.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(b"|");
    hasher.update(entry.actor_name.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(entry.actor_role.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(entry.action.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.resource_type.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.resource_id.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"|");
    let diff_bytes = match entry.diff.as_ref() {
        Some(v) => serde_json::to_vec(v).unwrap_or_default(),
        None => Vec::new(),
    };
    hasher.update(&diff_bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChainVerification {
    pub ok: bool,
    pub checked: u64,
    pub broken_at: Option<i64>,
}

/// High-level audit-log facade used by admin handlers. Wraps the
/// repository so handlers don't need to spell out the full row each time.
#[derive(Clone)]
pub struct AuditLog {
    repo: Arc<dyn Repository>,
}

impl AuditLog {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    /// Record an admin mutation. Failures are logged but never propagated;
    /// audit must not break the surrounding admin request.
    pub async fn record(
        &self,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: Option<String>,
        diff: Option<serde_json::Value>,
        actor: Option<&AdminToken>,
    ) {
        let entry = NewAuditEntry {
            ts: Utc::now(),
            actor_id: actor.map(|a| a.id),
            actor_name: actor.map(|a| a.name.clone()),
            actor_role: actor.map(|a| a.role.to_string()),
            action: action.as_str().to_string(),
            resource_type: resource_type.as_str().to_string(),
            resource_id,
            diff,
        };
        if let Err(e) = self.repo.append_audit(&entry).await {
            tracing::warn!(error = %e, "audit append failed (non-blocking)");
        }
    }

    pub async fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, GatewayError> {
        self.repo.list_audit(filter).await
    }

    /// Recompute the chain backwards from the newest row to genesis and report inconsistencies.
    pub async fn verify_chain(&self) -> Result<ChainVerification, GatewayError> {
        let mut offset = 0;
        let limit = 1000;
        let mut checked: u64 = 0;
        let mut expected_prev_hash: Option<String> = None;

        loop {
            let chunk = self
                .repo
                .list_audit(&AuditFilter {
                    limit: Some(limit),
                    offset: Some(offset),
                    include_diff: true,
                    ..Default::default()
                })
                .await?;
            if chunk.is_empty() {
                break;
            }

            for row in chunk {
                let new_entry = NewAuditEntry {
                    ts: row.ts,
                    actor_id: row.actor_id,
                    actor_name: row.actor_name.clone(),
                    actor_role: row.actor_role.clone(),
                    action: row.action.clone(),
                    resource_type: row.resource_type.clone(),
                    resource_id: row.resource_id.clone(),
                    diff: row.diff.clone(),
                };
                let expected = compute_hash(row.prev_hash.as_deref(), &new_entry);
                if expected != row.hash {
                    return Ok(ChainVerification {
                        ok: false,
                        checked,
                        broken_at: Some(row.id),
                    });
                }
                if let Some(eph) = &expected_prev_hash {
                    if eph != &row.hash {
                        return Ok(ChainVerification {
                            ok: false,
                            checked,
                            broken_at: Some(row.id),
                        });
                    }
                }
                expected_prev_hash = row.prev_hash.clone();
                checked += 1;
            }
            offset += limit;
        }

        if expected_prev_hash.is_some() {
            return Ok(ChainVerification {
                ok: false,
                checked,
                broken_at: Some(0),
            });
        }

        Ok(ChainVerification {
            ok: true,
            checked,
            broken_at: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_changes_with_prev() {
        let entry = NewAuditEntry {
            ts: Utc::now(),
            actor_id: None,
            actor_name: None,
            actor_role: None,
            action: "create".into(),
            resource_type: "service".into(),
            resource_id: Some("abc".into()),
            diff: None,
        };
        let a = compute_hash(None, &entry);
        let b = compute_hash(Some("deadbeef"), &entry);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }
}
