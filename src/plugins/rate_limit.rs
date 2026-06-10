use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{Request, Response};
use dashmap::DashMap;
use std::time::Instant;

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Above this many tracked clients we sweep idle (fully-refilled) buckets so a
/// flood of distinct client keys can't grow the map without bound.
const MAX_BUCKETS: usize = 100_000;

pub struct RateLimitPlugin {
    buckets: DashMap<String, TokenBucket>,
    requests_per_second: f64,
    burst_size: f64,
}

impl RateLimitPlugin {
    pub fn new(requests_per_second: f64) -> Self {
        Self {
            buckets: DashMap::new(),
            requests_per_second,
            burst_size: requests_per_second * 2.0,
        }
    }

    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let rps = cfg
            .get("requests_per_second")
            .and_then(|v| v.as_f64())
            .unwrap_or(100.0);
        Ok(Self::new(rps))
    }

    /// Drop fully-refilled (idle) buckets. A bucket that has refilled back to
    /// capacity carries no state — recreating it on the next request yields an
    /// identical full bucket — so evicting it is semantically free and bounds
    /// memory to the set of currently-active clients.
    fn evict_idle(&self) {
        let now = Instant::now();
        self.buckets.retain(|_, b| {
            let elapsed = now.duration_since(b.last_refill).as_secs_f64();
            let refilled = (b.tokens + elapsed * b.refill_rate).min(b.capacity);
            refilled < b.capacity
        });
    }

    fn get_client_id(req: &Request<axum::body::Body>) -> String {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .split(',')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string()
    }
}

#[async_trait]
impl Plugin for RateLimitPlugin {
    fn name(&self) -> &str {
        "rate-limit"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let client_id = Self::get_client_id(req);
        // Bound memory: sweep idle buckets when the map gets large (e.g. a
        // flood of spoofed/unique client keys).
        if self.buckets.len() > MAX_BUCKETS {
            self.evict_idle();
        }
        let mut bucket = self
            .buckets
            .entry(client_id)
            .or_insert_with(|| TokenBucket::new(self.burst_size, self.requests_per_second));

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(PluginError::RateLimited)
        }
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
