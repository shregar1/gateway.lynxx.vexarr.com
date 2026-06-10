//! Shared, short-TTL cache of consumers for the auth plugins.
//!
//! `key-auth`, `basic-auth`, and `hmac-auth` previously called
//! `repo.list_consumers()` and linear-scanned the **entire** consumers table
//! on every authenticated request — an O(N) DB round-trip per request on the
//! proxy hot path. This module fetches the table at most once per
//! [`TTL`] window and serves indexed lookups by api-key / username from the
//! in-memory snapshot.
//!
//! Consistency: a created/updated/deleted consumer takes effect within `TTL`
//! (revocation latency is bounded by `TTL`). This matches the staleness model
//! already used by the admin-token cache and is the standard trade-off for an
//! auth lookup on a latency-sensitive path. Mutating endpoints may call
//! [`invalidate`] to drop the snapshot immediately.

use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::Consumer;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// How long a consumers snapshot is reused before a refresh.
const TTL: Duration = Duration::from_secs(5);

struct Snapshot {
    by_api_key: HashMap<String, Arc<Consumer>>,
    by_username: HashMap<String, Arc<Consumer>>,
    refreshed_at: Instant,
}

static CACHE: OnceLock<RwLock<Option<Arc<Snapshot>>>> = OnceLock::new();

fn cell() -> &'static RwLock<Option<Arc<Snapshot>>> {
    CACHE.get_or_init(|| RwLock::new(None))
}

/// Drop the cached snapshot so the next lookup refreshes from the repository.
pub fn invalidate() {
    if let Ok(mut g) = cell().write() {
        *g = None;
    }
}

async fn current(repo: &Arc<dyn Repository>) -> Result<Arc<Snapshot>, GatewayError> {
    // Fast path: a fresh snapshot is reused without touching the DB. The read
    // guard is dropped before any `.await`.
    {
        let guard = cell().read().expect("consumer cache lock poisoned");
        if let Some(snap) = guard.as_ref() {
            if snap.refreshed_at.elapsed() < TTL {
                return Ok(snap.clone());
            }
        }
    }

    // Refresh: fetch outside any lock, then publish.
    let consumers = repo.list_consumers().await?;
    let mut by_api_key = HashMap::new();
    let mut by_username = HashMap::new();
    for c in consumers {
        let arc = Arc::new(c);
        if let Some(k) = arc.api_key.as_deref() {
            by_api_key.insert(k.to_string(), arc.clone());
        }
        by_username.insert(arc.username.clone(), arc.clone());
    }
    let snap = Arc::new(Snapshot {
        by_api_key,
        by_username,
        refreshed_at: Instant::now(),
    });
    *cell().write().expect("consumer cache lock poisoned") = Some(snap.clone());
    Ok(snap)
}

/// Look up a consumer by its `api_key`.
pub async fn by_api_key(
    repo: &Arc<dyn Repository>,
    api_key: &str,
) -> Result<Option<Arc<Consumer>>, GatewayError> {
    Ok(current(repo).await?.by_api_key.get(api_key).cloned())
}

/// Look up a consumer by `username`.
pub async fn by_username(
    repo: &Arc<dyn Repository>,
    username: &str,
) -> Result<Option<Arc<Consumer>>, GatewayError> {
    Ok(current(repo).await?.by_username.get(username).cloned())
}
