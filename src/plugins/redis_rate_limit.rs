use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderValue, Request, Response};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Distributed rate limit backed by Redis. Uses a per-second sliding bucket
/// keyed by `<namespace>:<key>:<unix_secs>` with INCR + EXPIRE. Falls back
/// to **allow** on Redis errors so a Redis outage doesn't take down traffic.
pub struct RedisRateLimitPlugin {
    redis_url: String,
    rps: u64,
    key_strategy: KeyStrategy,
    namespace: String,
    /// Lazy-initialized so plugin construction doesn't block on a Redis
    /// round-trip; rebuilds shouldn't fail just because Redis is down.
    conn: Arc<OnceCell<ConnectionManager>>,
}

#[derive(Clone, Copy)]
enum KeyStrategy {
    Ip,
    Consumer,
    Service,
}

impl RedisRateLimitPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let redis_url = cfg
            .get("redis_url")
            .and_then(|v| v.as_str())
            .unwrap_or("redis://127.0.0.1:6379")
            .to_string();
        let rps = cfg
            .get("requests_per_second")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        let key_strategy = match cfg
            .get("key_strategy")
            .and_then(|v| v.as_str())
            .unwrap_or("ip")
        {
            "consumer" => KeyStrategy::Consumer,
            "service" => KeyStrategy::Service,
            _ => KeyStrategy::Ip,
        };
        let namespace = cfg
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("lynxx:rl")
            .to_string();
        Ok(Self {
            redis_url,
            rps,
            key_strategy,
            namespace,
            conn: Arc::new(OnceCell::new()),
        })
    }

    async fn connection(&self) -> Result<ConnectionManager, redis::RedisError> {
        if let Some(c) = self.conn.get() {
            return Ok(c.clone());
        }
        let url = self.redis_url.clone();
        let cell = self.conn.clone();
        let conn = cell
            .get_or_try_init(|| async move {
                let client = redis::Client::open(url)?;
                ConnectionManager::new(client).await
            })
            .await?
            .clone();
        Ok(conn)
    }

    fn extract_key(&self, req: &Request<Body>) -> String {
        match self.key_strategy {
            KeyStrategy::Ip => req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(str::trim)
                .unwrap_or("unknown")
                .to_string(),
            KeyStrategy::Consumer => req
                .headers()
                .get("x-consumer-username")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("anonymous")
                .to_string(),
            KeyStrategy::Service => req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string(),
        }
    }
}

#[async_trait]
impl Plugin for RedisRateLimitPlugin {
    fn name(&self) -> &str {
        "redis-rate-limit"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let bucket = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = format!("{}:{}:{}", self.namespace, self.extract_key(req), bucket);

        let mut conn = match self.connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "redis-rate-limit: connection failed; allowing request");
                return Ok(());
            }
        };

        let count: Result<i64, redis::RedisError> = conn.incr(&key, 1).await;
        let count = match count {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "redis-rate-limit: INCR failed; allowing request");
                return Ok(());
            }
        };
        if count == 1 {
            // Best-effort — if EXPIRE fails the key will linger but won't
            // poison subsequent windows.
            let _: Result<(), redis::RedisError> = conn.expire(&key, 2).await;
        }

        if count as u64 > self.rps {
            return Err(PluginError::ShortCircuit {
                status: 429,
                headers: vec![
                    ("Retry-After".into(), "1".into()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body: br#"{"error":"rate limit exceeded"}"#.to_vec().into(),
            });
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

#[allow(dead_code)]
fn _suppress_unused(v: HeaderValue) -> HeaderValue {
    v
}
