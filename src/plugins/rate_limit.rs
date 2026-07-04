//! Per-client rate-limit plugin.
//!
//! Backed by the HAProxy-inspired stick-table engine in
//! [`crate::proxy::rate_limit`]. The limiting *algorithm* is gated by the
//! deployment's subscription [`Tier`]: a single binary ships every
//! strategy, and the tier decides which one this plugin may use. A
//! configured strategy above the current tier is locked down to the best
//! the tier allows (see [`RateLimitStrategy::resolve_for_tier`]).

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use crate::proxy::rate_limit::{
    RateLimitResult, RateLimitStrategy, RateLimiter, RateLimiterConfig, StickTableConfig,
};
use algorithms::backbone::Tier;
use async_trait::async_trait;
use axum::http::{Request, Response};
use std::time::Duration;

pub struct RateLimitPlugin {
    /// Stick-table engine; handles per-client state internally (replaces
    /// the previous `DashMap<client_id, TokenBucket>`).
    limiter: RateLimiter,
    requests_per_second: f64,
}

impl RateLimitPlugin {
    /// Build a limiter for `requests_per_second` using the strategy that
    /// `tier` permits. `requested` is the operator's desired strategy
    /// (from config); it is locked down if the tier doesn't allow it.
    pub fn new(requests_per_second: f64, requested: RateLimitStrategy, tier: Tier) -> Self {
        // A non-finite or negative `requests_per_second` is a misconfiguration
        // (e.g. admin/lynxfile `requests_per_second: 0` or `-10`). Collapse it
        // to 0.0 here so the engine never receives a NaN/negative rate — which
        // would otherwise either bypass limiting or panic the process in
        // `Duration::from_secs_f64` (panic="abort"). 0.0 admits the initial
        // burst, then denies.
        let requests_per_second = if requests_per_second.is_finite() && requests_per_second > 0.0 {
            requests_per_second
        } else {
            0.0
        };
        // Burst headroom of 2× rps preserves the previous plugin's feel
        // (token bucket capacity was `rps * 2`). Clamp to ≥1 so a sub-1
        // rps config still admits a single request.
        let burst = (requests_per_second * 2.0).ceil().max(1.0) as u32;
        let per_window = requests_per_second.ceil().max(1.0) as u32;

        let limiter_config = RateLimiterConfig {
            strategy: requested,
            token_rate: requests_per_second,
            token_burst: burst,
            window: Duration::from_secs(1),
            max_requests: per_window,
            leak_rate: requests_per_second,
            leak_capacity: burst,
        };

        Self {
            limiter: RateLimiter::for_tier(tier, StickTableConfig::default(), limiter_config),
            requests_per_second,
        }
    }

    /// Construct from a JSON config blob and the deployment's tier.
    ///
    /// Config keys:
    /// * `requests_per_second` (f64, default 100)
    /// * `strategy` (string, optional) — one of `token_bucket`,
    ///   `sliding_window`, `fixed_window`, `leaky_bucket`. Defaults to
    ///   `token_bucket`. Unknown values fall back to the default.
    pub fn from_config(cfg: &serde_json::Value, tier: Tier) -> Result<Self, GatewayError> {
        let rps = cfg
            .get("requests_per_second")
            .and_then(|v| v.as_f64())
            .unwrap_or(100.0);

        let requested = cfg
            .get("strategy")
            .and_then(|v| v.as_str())
            .and_then(RateLimitStrategy::from_name)
            .unwrap_or(RateLimitStrategy::TokenBucket);

        Ok(Self::new(rps, requested, tier))
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

    /// The effective (post-lockdown) strategy this plugin is running.
    #[cfg(test)]
    fn strategy(&self) -> RateLimitStrategy {
        self.limiter.strategy()
    }
}

#[async_trait]
impl Plugin for RateLimitPlugin {
    fn name(&self) -> &str {
        "rate-limit"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let client_id = Self::get_client_id(req);
        match self.limiter.check(&client_id) {
            RateLimitResult::Allow { .. } => Ok(()),
            RateLimitResult::Deny { .. } => Err(PluginError::RateLimited),
        }
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_from(ip: &str) -> Request<axum::body::Body> {
        Request::builder()
            .header("x-forwarded-for", ip)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn allows_then_denies_after_burst() {
        // 1 rps, Pro tier so the requested token bucket is honored.
        // Burst = ceil(1*2) = 2, so the first 2 requests pass, 3rd denied.
        let plugin = RateLimitPlugin::new(1.0, RateLimitStrategy::TokenBucket, Tier::Pro);
        let mut r1 = req_from("10.0.0.1");
        let mut r2 = req_from("10.0.0.1");
        let mut r3 = req_from("10.0.0.1");

        assert!(plugin.on_request(&mut r1).await.is_ok());
        assert!(plugin.on_request(&mut r2).await.is_ok());
        assert!(matches!(
            plugin.on_request(&mut r3).await,
            Err(PluginError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn different_clients_are_independent() {
        let plugin = RateLimitPlugin::new(1.0, RateLimitStrategy::TokenBucket, Tier::Pro);
        // Drain client A.
        let mut a1 = req_from("1.1.1.1");
        let mut a2 = req_from("1.1.1.1");
        let mut a3 = req_from("1.1.1.1");
        assert!(plugin.on_request(&mut a1).await.is_ok());
        assert!(plugin.on_request(&mut a2).await.is_ok());
        assert!(plugin.on_request(&mut a3).await.is_err());

        // Client B is untouched.
        let mut b1 = req_from("2.2.2.2");
        assert!(plugin.on_request(&mut b1).await.is_ok());
    }

    #[test]
    fn starter_tier_locks_down_token_bucket_to_leaky() {
        // Default config requests token_bucket, but Starter can't use it.
        let plugin = RateLimitPlugin::from_config(
            &serde_json::json!({ "requests_per_second": 50.0 }),
            Tier::Starter,
        )
        .unwrap();
        assert_eq!(plugin.strategy(), RateLimitStrategy::LeakyBucket);
        assert_eq!(plugin.requests_per_second, 50.0);
    }

    #[test]
    fn pro_tier_honors_requested_sliding_window() {
        let plugin = RateLimitPlugin::from_config(
            &serde_json::json!({ "requests_per_second": 10.0, "strategy": "sliding_window" }),
            Tier::Pro,
        )
        .unwrap();
        assert_eq!(plugin.strategy(), RateLimitStrategy::SlidingWindow);
    }

    #[test]
    fn growth_tier_keeps_token_bucket_but_locks_sliding() {
        let token = RateLimitPlugin::from_config(
            &serde_json::json!({ "strategy": "token_bucket" }),
            Tier::Growth,
        )
        .unwrap();
        assert_eq!(token.strategy(), RateLimitStrategy::TokenBucket);

        let sliding = RateLimitPlugin::from_config(
            &serde_json::json!({ "strategy": "sliding_window" }),
            Tier::Growth,
        )
        .unwrap();
        // Sliding is Pro-only → locked down to Growth's best (token bucket).
        assert_eq!(sliding.strategy(), RateLimitStrategy::TokenBucket);
    }

    #[test]
    fn unknown_strategy_falls_back_to_default() {
        let plugin = RateLimitPlugin::from_config(
            &serde_json::json!({ "strategy": "nonsense" }),
            Tier::Pro,
        )
        .unwrap();
        // Unknown → default token_bucket, allowed on Pro.
        assert_eq!(plugin.strategy(), RateLimitStrategy::TokenBucket);
    }
}
