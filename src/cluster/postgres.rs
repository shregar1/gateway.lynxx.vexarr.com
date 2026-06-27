//! Postgres-backed cluster bus using LISTEN/NOTIFY on channel `lynxx_events`.

use crate::cluster::{ChangeEvent, ChangeHandler, ClusterBus};
use crate::error::GatewayError;
use async_trait::async_trait;
use sqlx::postgres::{PgListener, PgPool};
use std::time::Duration;
use uuid::Uuid;

const CHANNEL: &str = "lynxx_events";

pub struct PostgresBus {
    pool: PgPool,
}

impl PostgresBus {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ClusterBus for PostgresBus {
    async fn publish(&self, event: ChangeEvent) -> Result<(), GatewayError> {
        let payload = serde_json::to_string(&event)
            .map_err(|e| GatewayError::Internal(format!("serialize event: {e}")))?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANNEL)
            .bind(&payload)
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
            loop {
                let mut listener = match PgListener::connect_with(&pool).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(error = %e, "PgListener connect failed; retrying in 2s");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };
                if let Err(e) = listener.listen(CHANNEL).await {
                    tracing::error!(error = %e, "PgListener LISTEN failed; retrying in 2s");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                tracing::info!(channel = CHANNEL, node_id = %node_id, "cluster subscriber connected");

                loop {
                    match listener.recv().await {
                        Ok(notification) => {
                            let payload = notification.payload();
                            let event: ChangeEvent = match serde_json::from_str(payload) {
                                Ok(e) => e,
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        payload = payload,
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
                        Err(e) => {
                            tracing::error!(error = %e, "PgListener recv error; reconnecting in 2s");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            break;
                        }
                    }
                }
            }
        })
    }
}
