//! In-flight request limiter plugin.
//!
//! Limits the number of concurrent in-flight requests, optionally
//! per source IP or per host.
//!
//! Config:
//! ```json
//! {
//!   "amount": 100,
//!   "source_criterion": "general"
//! }
//! ```
//!
//! `source_criterion` values:
//! - `"general"` — single global counter (default)
//! - `"request.ip"` — per source IP
//! - `"request.host"` — per Host header

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{Request, Response};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Source criterion for grouping in-flight counts.
#[derive(Clone, Debug, PartialEq)]
enum SourceCriterion {
    General,
    RequestIp,
    RequestHost,
}

/// RAII guard for the global counter. Decrements the shared `AtomicU64` on
/// drop, ensuring the count is released even if the response pipeline panics
/// or the extensions are dropped.
struct InFlightGuardGlobal(Arc<AtomicU64>);

impl Drop for InFlightGuardGlobal {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard for per-key counters. Holds an `Arc` to the per-key
/// `AtomicU64` inside the `DashMap` and decrements it on drop.
struct InFlightGuardKeyed {
    counter: Arc<AtomicU64>,
}

impl Drop for InFlightGuardKeyed {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Marker stored in request extensions when the limit is exceeded so
/// `on_response` can emit a 429.
#[derive(Clone, Debug)]
struct InFlightRejected;

pub struct InFlightReqPlugin {
    amount: u64,
    criterion: SourceCriterion,
    /// Global counter (used when criterion is `General`).
    global_counter: Arc<AtomicU64>,
    /// Per-key counters (used for `RequestIp` / `RequestHost`).
    keyed_counters: Arc<DashMap<String, Arc<AtomicU64>>>,
}

impl InFlightReqPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let amount = cfg
            .get("amount")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| GatewayError::BadRequest("inflight-req: 'amount' is required".into()))?;

        let criterion = match cfg
            .get("source_criterion")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
        {
            "request.ip" => SourceCriterion::RequestIp,
            "request.host" => SourceCriterion::RequestHost,
            _ => SourceCriterion::General,
        };

        Ok(Self {
            amount,
            criterion,
            global_counter: Arc::new(AtomicU64::new(0)),
            keyed_counters: Arc::new(DashMap::new()),
        })
    }

    /// Extract the source key from the request based on the configured criterion.
    fn extract_key(&self, req: &Request<axum::body::Body>) -> String {
        match self.criterion {
            SourceCriterion::General => String::new(),
            SourceCriterion::RequestIp => req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
                .or_else(|| {
                    req.headers()
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim().to_string())
                })
                .unwrap_or_else(|| "unknown".to_string()),
            SourceCriterion::RequestHost => req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string(),
        }
    }
}

#[async_trait]
impl Plugin for InFlightReqPlugin {
    fn name(&self) -> &str {
        "inflight-req"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        match self.criterion {
            SourceCriterion::General => {
                let prev = self.global_counter.fetch_add(1, Ordering::Relaxed);
                if prev >= self.amount {
                    // Over limit — roll back and mark rejected.
                    self.global_counter.fetch_sub(1, Ordering::Relaxed);
                    req.extensions_mut().insert(InFlightRejected);
                } else {
                    // Store the RAII guard so the counter decrements when the
                    // request/response extensions are dropped.
                    req.extensions_mut()
                        .insert(Arc::new(InFlightGuardGlobal(self.global_counter.clone())));
                }
            }
            SourceCriterion::RequestIp | SourceCriterion::RequestHost => {
                let key = self.extract_key(req);
                let counter = self
                    .keyed_counters
                    .entry(key)
                    .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                    .clone();

                let prev = counter.fetch_add(1, Ordering::Relaxed);
                if prev >= self.amount {
                    counter.fetch_sub(1, Ordering::Relaxed);
                    req.extensions_mut().insert(InFlightRejected);
                } else {
                    req.extensions_mut()
                        .insert(Arc::new(InFlightGuardKeyed { counter }));
                }
            }
        }
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        if resp.extensions().get::<InFlightRejected>().is_some() {
            *resp.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;

    fn global_plugin(amount: u64) -> InFlightReqPlugin {
        InFlightReqPlugin {
            amount,
            criterion: SourceCriterion::General,
            global_counter: Arc::new(AtomicU64::new(0)),
            keyed_counters: Arc::new(DashMap::new()),
        }
    }

    fn per_ip_plugin(amount: u64) -> InFlightReqPlugin {
        InFlightReqPlugin {
            amount,
            criterion: SourceCriterion::RequestIp,
            global_counter: Arc::new(AtomicU64::new(0)),
            keyed_counters: Arc::new(DashMap::new()),
        }
    }

    fn make_request_with_ip(ip: &str) -> Request<Body> {
        Request::builder()
            .uri("/test")
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request() -> Request<Body> {
        Request::builder().uri("/test").body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn under_limit_passes() {
        let plugin = global_plugin(2);
        let mut req = make_request();
        plugin.on_request(&mut req).await.unwrap();

        assert!(
            req.extensions().get::<InFlightRejected>().is_none(),
            "request under limit should pass"
        );
        assert_eq!(plugin.global_counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn at_limit_rejects_with_429() {
        let plugin = global_plugin(1);

        // First request — should pass and hold the slot.
        let mut req1 = make_request();
        plugin.on_request(&mut req1).await.unwrap();
        assert!(req1.extensions().get::<InFlightRejected>().is_none());

        // Second request — should be rejected.
        let mut req2 = make_request();
        plugin.on_request(&mut req2).await.unwrap();
        assert!(req2.extensions().get::<InFlightRejected>().is_some());

        // Verify on_response sets 429.
        let mut resp = Response::builder().body(Body::empty()).unwrap();
        resp.extensions_mut().insert(InFlightRejected);
        plugin.on_response(&mut resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn guard_decrements_on_drop() {
        let plugin = global_plugin(1);

        {
            let mut req = make_request();
            plugin.on_request(&mut req).await.unwrap();
            assert_eq!(plugin.global_counter.load(Ordering::Relaxed), 1);
            // `req` goes out of scope here, dropping the guard.
        }

        assert_eq!(
            plugin.global_counter.load(Ordering::Relaxed),
            0,
            "guard should decrement counter on drop"
        );
    }

    #[tokio::test]
    async fn guard_allows_next_request_after_drop() {
        let plugin = global_plugin(1);

        {
            let mut req = make_request();
            plugin.on_request(&mut req).await.unwrap();
            assert!(req.extensions().get::<InFlightRejected>().is_none());
        }
        // Guard dropped, counter back to 0.

        let mut req2 = make_request();
        plugin.on_request(&mut req2).await.unwrap();
        assert!(
            req2.extensions().get::<InFlightRejected>().is_none(),
            "after guard drop, new request should be allowed"
        );
    }

    #[tokio::test]
    async fn per_ip_separate_counters() {
        let plugin = per_ip_plugin(1);

        let mut req_a = make_request_with_ip("10.0.0.1");
        plugin.on_request(&mut req_a).await.unwrap();
        assert!(req_a.extensions().get::<InFlightRejected>().is_none());

        // Different IP — should also pass.
        let mut req_b = make_request_with_ip("10.0.0.2");
        plugin.on_request(&mut req_b).await.unwrap();
        assert!(
            req_b.extensions().get::<InFlightRejected>().is_none(),
            "different IP should have its own counter"
        );

        // Same IP as first — should be rejected (limit=1, one already held).
        let mut req_a2 = make_request_with_ip("10.0.0.1");
        plugin.on_request(&mut req_a2).await.unwrap();
        assert!(
            req_a2.extensions().get::<InFlightRejected>().is_some(),
            "same IP over limit should be rejected"
        );
    }

    #[tokio::test]
    async fn per_ip_guard_decrements() {
        let plugin = per_ip_plugin(1);

        {
            let mut req = make_request_with_ip("192.168.1.1");
            plugin.on_request(&mut req).await.unwrap();
            assert!(req.extensions().get::<InFlightRejected>().is_none());
        }
        // Guard dropped.

        let mut req2 = make_request_with_ip("192.168.1.1");
        plugin.on_request(&mut req2).await.unwrap();
        assert!(
            req2.extensions().get::<InFlightRejected>().is_none(),
            "after guard drop, same IP should be allowed again"
        );
    }

    #[tokio::test]
    async fn response_ok_when_not_rejected() {
        let plugin = global_plugin(10);
        let mut resp = Response::builder().body(Body::empty()).unwrap();
        plugin.on_response(&mut resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn from_config_requires_amount() {
        let result = InFlightReqPlugin::from_config(&serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn from_config_defaults_to_general() {
        let plugin = InFlightReqPlugin::from_config(&serde_json::json!({
            "amount": 50
        }))
        .unwrap();
        assert_eq!(plugin.amount, 50);
        assert_eq!(plugin.criterion, SourceCriterion::General);
    }

    #[test]
    fn from_config_per_ip() {
        let plugin = InFlightReqPlugin::from_config(&serde_json::json!({
            "amount": 10,
            "source_criterion": "request.ip"
        }))
        .unwrap();
        assert_eq!(plugin.criterion, SourceCriterion::RequestIp);
    }

    #[test]
    fn from_config_per_host() {
        let plugin = InFlightReqPlugin::from_config(&serde_json::json!({
            "amount": 5,
            "source_criterion": "request.host"
        }))
        .unwrap();
        assert_eq!(plugin.criterion, SourceCriterion::RequestHost);
    }
}
