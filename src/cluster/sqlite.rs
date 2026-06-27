//! SQLite-backed cluster bus using a polled `_sync_log` table.
//!
//! Single-node / dev-only fallback. `publish` inserts a row; `subscribe`
//! polls for new rows every second and dispatches them. `last_seen_seq` is
//! kept in memory only — restarts replay no history, which is acceptable
//! because the on-disk DB is the source of truth and there are no remote
//! peers to keep in sync.

use crate::cluster::{ChangeEvent, ChangeHandler, ClusterBus};
use crate::error::GatewayError;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub struct SqliteBus {
    pool: SqlitePool,
}

impl SqliteBus {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ClusterBus for SqliteBus {
    async fn publish(&self, event: ChangeEvent) -> Result<(), GatewayError> {
        let payload = serde_json::to_string(&event)
            .map_err(|e| GatewayError::Internal(format!("serialize event: {e}")))?;
        sqlx::query("INSERT INTO _sync_log (payload, created_at) VALUES (?, ?)")
            .bind(&payload)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        tracing::debug!(
            kind = event.kind(),
            origin = %event.origin(),
            "cluster event published"
        );
        Ok(())
    }

    fn subscribe(&self, node_id: Uuid, handler: ChangeHandler) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        tokio::spawn(async move {
            // Skip whatever is already in the log on startup — those are
            // historical events we don't want to replay.
            let mut last_seen: i64 = match sqlx::query(
                "SELECT COALESCE(MAX(seq), 0) AS m FROM _sync_log",
            )
            .fetch_one(&pool)
            .await
            {
                Ok(row) => row.try_get::<i64, _>("m").unwrap_or(0),
                Err(e) => {
                    tracing::warn!(error = %e, "could not seed last_seen from _sync_log; defaulting to 0");
                    0
                }
            };
            tracing::info!(node_id = %node_id, last_seen, "sqlite cluster subscriber starting");

            loop {
                tokio::time::sleep(POLL_INTERVAL).await;
                let rows = match sqlx::query(
                    "SELECT seq, payload FROM _sync_log WHERE seq > ? ORDER BY seq ASC",
                )
                .bind(last_seen)
                .fetch_all(&pool)
                .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "sqlite bus poll failed");
                        continue;
                    }
                };

                for row in rows {
                    let seq: i64 = match row.try_get("seq") {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let payload: String = match row.try_get("payload") {
                        Ok(p) => p,
                        Err(_) => {
                            last_seen = seq.max(last_seen);
                            continue;
                        }
                    };
                    last_seen = seq.max(last_seen);

                    let event: ChangeEvent = match serde_json::from_str(&payload) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                payload = %payload,
                                "failed to parse cluster event"
                            );
                            continue;
                        }
                    };

                    tracing::info!(
                        kind = event.kind(),
                        origin = %event.origin(),
                        "cluster event consumed"
                    );
                    handler(event).await;
                }
            }
        })
    }
}
