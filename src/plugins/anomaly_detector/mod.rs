//! `anomaly-detector` — statistical outlier detection on the hot path.
//!
//! Per-key rolling EWMA baselines on four signals (request rate, body size,
//! path diversity, error rate). Each request samples the current value,
//! computes a z-score against the baseline, and triggers an anomaly when
//! any enabled signal exceeds its configured sigma threshold.
//!
//! Three response modes:
//! - `log_only`  — never short-circuits, emits metrics + WARN log.
//! - `challenge` — short-circuits 429 with `Retry-After`.
//! - `block`    — short-circuits 403.
//!
//! State lives in a `DashMap<String, Mutex<Baseline>>` keyed by the
//! configured strategy (consumer / ip / global). The mutex critical section
//! is small and synchronous — no async work runs while it's held.
//!
//! A background pruner runs every 5 minutes and drops baselines that have
//! seen no anomaly and no traffic increase in the last 30 minutes. Without
//! the pruner the map would grow unbounded across IP rotations.

pub mod baselines;
pub mod config;
pub mod scoring;

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use baselines::Baseline;
use config::{Config, KeyStrategy, Mode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Extension stash so `on_response` can find the same key without re-parsing
/// headers. Cloned out of `req.extensions_mut()` after `on_request`.
#[derive(Clone)]
struct AnomalyCtx {
    key: String,
}

pub struct AnomalyDetectorPlugin {
    cfg: Config,
    state: Arc<DashMap<String, Mutex<Baseline>>>,
    /// Pre-hashed exempt set for cheap O(1) lookups on the hot path.
    exempt: std::collections::HashSet<String>,
    /// JoinHandle to the background pruner, kept alive for the lifetime of
    /// the plugin. Dropping it aborts the task — exactly what we want when
    /// the plugin is rebuilt out from under us.
    _pruner: Option<Arc<PrunerHandle>>,
}

struct PrunerHandle {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for PrunerHandle {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl AnomalyDetectorPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let parsed: Config = serde_json::from_value(cfg.clone())
            .map_err(|e| GatewayError::BadRequest(format!("anomaly-detector config: {e}")))?;
        let exempt = parsed.exempt_consumers.iter().cloned().collect();
        let state: Arc<DashMap<String, Mutex<Baseline>>> = Arc::new(DashMap::new());

        // Spawn the pruner only when we're inside a Tokio runtime. Plugins
        // are typically built from inside the gateway's runtime, but the
        // unit tests in this module construct plugins via `from_config`
        // outside one — so we tolerate `Handle::try_current` failing.
        let pruner = if tokio::runtime::Handle::try_current().is_ok() {
            let weak = Arc::downgrade(&state);
            let handle = tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(300));
                tick.tick().await; // first tick fires immediately; skip
                loop {
                    tick.tick().await;
                    let Some(state) = weak.upgrade() else {
                        return;
                    };
                    prune(&state);
                }
            });
            Some(Arc::new(PrunerHandle { handle }))
        } else {
            None
        };

        Ok(Self {
            cfg: parsed,
            state,
            exempt,
            _pruner: pruner,
        })
    }

    fn resolve_key(&self, req: &Request<axum::body::Body>) -> String {
        match self.cfg.key_strategy {
            KeyStrategy::Consumer => req
                .headers()
                .get("x-consumer-username")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("anonymous")
                .to_string(),
            KeyStrategy::Ip => req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .split(',')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string(),
            KeyStrategy::Global => "__global__".to_string(),
        }
    }

    fn body_size(req: &Request<axum::body::Body>) -> Option<f64> {
        req.headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| n as f64)
    }

    fn hash_path(path: &str) -> u64 {
        let mut h = DefaultHasher::new();
        path.hash(&mut h);
        h.finish()
    }

    /// Core scoring routine. Lock is held for the duration; keep it tight.
    fn check_and_update(
        &self,
        key: &str,
        body_size: Option<f64>,
        path_hash: u64,
    ) -> Option<TriggeredSignal> {
        let entry = self.state.entry(key.to_string()).or_insert_with(|| {
            Mutex::new(Baseline::new(
                self.cfg.ewma_alpha,
                self.cfg.signals.request_rate.window_secs,
                self.cfg.signals.path_diversity.window_secs,
                self.cfg.signals.error_rate.window_secs,
            ))
        });
        let mut b = entry
            .lock()
            .expect("anomaly-detector baseline mutex poisoned");
        let now = Instant::now();

        let req_count = b.push_request(now);
        let path_count = b.path_window.observe(path_hash, now);
        let in_warmup = b.seen < self.cfg.warmup_requests;

        // Observed values (per-signal).
        let req_window_secs = self.cfg.signals.request_rate.window_secs.max(1) as f64;
        let observed_rate = req_count as f64 / req_window_secs;
        let observed_paths = path_count as f64;

        let mut triggered: Option<TriggeredSignal> = None;

        if !in_warmup {
            if self.cfg.signals.request_rate.enabled {
                if let Some(out) = scoring::score(
                    observed_rate,
                    &b.request_rate_ewma,
                    self.cfg.signals.request_rate.sigma_threshold,
                ) {
                    if out.triggered && triggered.is_none() {
                        triggered = Some(TriggeredSignal {
                            name: "request_rate",
                            observed: out.observed,
                            mean: out.mean,
                            std: out.std,
                            zscore: out.zscore,
                        });
                    }
                }
            }
            if self.cfg.signals.path_diversity.enabled {
                if let Some(out) = scoring::score(
                    observed_paths,
                    &b.path_diversity_ewma,
                    self.cfg.signals.path_diversity.sigma_threshold,
                ) {
                    if out.triggered && triggered.is_none() {
                        triggered = Some(TriggeredSignal {
                            name: "path_diversity",
                            observed: out.observed,
                            mean: out.mean,
                            std: out.std,
                            zscore: out.zscore,
                        });
                    }
                }
            }
            if self.cfg.signals.body_size.enabled {
                if let Some(sz) = body_size {
                    if let Some(out) = scoring::score(
                        sz,
                        &b.body_size_ewma,
                        self.cfg.signals.body_size.sigma_threshold,
                    ) {
                        if out.triggered && triggered.is_none() {
                            triggered = Some(TriggeredSignal {
                                name: "body_size",
                                observed: out.observed,
                                mean: out.mean,
                                std: out.std,
                                zscore: out.zscore,
                            });
                        }
                    }
                }
            }
        }

        // Always update baselines — including during warmup, including on
        // anomaly. Letting an attacker shift our mean is the price we pay
        // for self-tuning; if that becomes a problem we can gate updates
        // behind `!triggered`.
        b.request_rate_ewma.update(observed_rate);
        b.path_diversity_ewma.update(observed_paths);
        if let Some(sz) = body_size {
            b.body_size_ewma.update(sz);
        }
        b.seen = b.seen.saturating_add(1);
        b.last_activity = now;

        if triggered.is_some() {
            b.last_anomaly = Some(now);
        }
        triggered
    }

    /// Same flow as `check_and_update` but for the response-side error rate.
    fn check_response(&self, key: &str, status: u16) -> Option<TriggeredSignal> {
        if !self.cfg.signals.error_rate.enabled {
            // Still want totals to be tracked so toggles work mid-flight,
            // but cheap path: skip entirely.
            return None;
        }
        let entry = self.state.get(key)?;
        let mut b = entry
            .lock()
            .expect("anomaly-detector baseline mutex poisoned");
        let now = Instant::now();
        b.error_window.record(status >= 400, now);
        let frac = b.error_window.fraction();

        let in_warmup = b.seen < self.cfg.warmup_requests;
        let mut triggered: Option<TriggeredSignal> = None;

        if !in_warmup {
            if let Some(out) = scoring::score(
                frac,
                &b.error_rate_ewma,
                self.cfg.signals.error_rate.sigma_threshold,
            ) {
                if out.triggered {
                    triggered = Some(TriggeredSignal {
                        name: "error_rate",
                        observed: out.observed,
                        mean: out.mean,
                        std: out.std,
                        zscore: out.zscore,
                    });
                }
            }
        }
        b.error_rate_ewma.update(frac);
        if triggered.is_some() {
            b.last_anomaly = Some(now);
        }
        triggered
    }

    fn build_short_circuit(&self, sig: &TriggeredSignal) -> PluginError {
        match self.cfg.mode {
            Mode::LogOnly => unreachable!("log_only never short-circuits"),
            Mode::Challenge => {
                let body = format!(
                    r#"{{"error":{{"code":"anomalous_traffic","retry_after":{}}}}}"#,
                    self.cfg.challenge_retry_after
                )
                .into_bytes();
                PluginError::ShortCircuit {
                    status: 429,
                    headers: vec![
                        (
                            "retry-after".into(),
                            self.cfg.challenge_retry_after.to_string(),
                        ),
                        ("content-type".into(), "application/json".into()),
                        ("x-lynxx-anomaly".into(), sig.name.into()),
                    ],
                    body: body.into(),
                }
            }
            Mode::Block => {
                let body = br#"{"error":{"code":"anomalous_traffic_blocked"}}"#.to_vec();
                PluginError::ShortCircuit {
                    status: 403,
                    headers: vec![
                        ("content-type".into(), "application/json".into()),
                        ("x-lynxx-anomaly".into(), sig.name.into()),
                    ],
                    body: body.into(),
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct TriggeredSignal {
    name: &'static str,
    observed: f64,
    mean: f64,
    std: f64,
    zscore: f64,
}

#[async_trait]
impl Plugin for AnomalyDetectorPlugin {
    fn name(&self) -> &str {
        "anomaly-detector"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let key = self.resolve_key(req);
        if self.exempt.contains(&key) {
            return Ok(());
        }
        let body_size = Self::body_size(req);
        let path_hash = Self::hash_path(req.uri().path());

        // Stash for on_response before we mutate state.
        req.extensions_mut().insert(AnomalyCtx { key: key.clone() });

        let triggered = self.check_and_update(&key, body_size, path_hash);
        if let Some(sig) = triggered {
            metrics::counter!(
                "lynxx_anomaly_detected_total",
                "signal" => sig.name,
                "key_strategy" => self.cfg.key_strategy_tag(),
                "mode" => self.cfg.mode_tag(),
            )
            .increment(1);
            tracing::warn!(
                key = %key,
                signal = sig.name,
                observed = sig.observed,
                baseline_mean = sig.mean,
                std = sig.std,
                zscore = sig.zscore,
                "anomaly detected"
            );
            if matches!(self.cfg.mode, Mode::LogOnly) {
                return Ok(());
            }
            return Err(self.build_short_circuit(&sig));
        }
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let ctx = match resp.extensions().get::<AnomalyCtx>().cloned() {
            Some(c) => c,
            None => return Ok(()),
        };
        if self.exempt.contains(&ctx.key) {
            return Ok(());
        }

        // Collect body to check for anomalies (v1 logic)
        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let collected = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("anomaly-detector body: {e}")))?
            .to_bytes();

        let status = resp.status().as_u16();
        let triggered = self.check_response(&ctx.key, status);
        if let Some(sig) = triggered {
            metrics::counter!(
                "lynxx_anomaly_detected_total",
                "signal" => sig.name,
                "key_strategy" => self.cfg.key_strategy_tag(),
                "mode" => self.cfg.mode_tag(),
            )
            .increment(1);
            tracing::warn!(
                key = %ctx.key,
                signal = sig.name,
                observed = sig.observed,
                baseline_mean = sig.mean,
                std = sig.std,
                zscore = sig.zscore,
                "anomaly detected (response)"
            );
            // Response-side detection cannot short-circuit — the upstream
            // already produced a response. We only emit metrics + log.
        }

        // Restore body
        *resp.body_mut() = Body::from(collected);
        Ok(())
    }
}

/// Drop baselines that are stale: no anomaly recorded *and* no new traffic
/// in the last 30 minutes. Called from the background pruner.
fn prune(state: &DashMap<String, Mutex<Baseline>>) {
    let cutoff = Duration::from_secs(30 * 60);
    let now = Instant::now();
    state.retain(|_, slot| {
        // `slot` is `&mut Mutex<Baseline>`, so `get_mut` avoids the lock —
        // there can be no contending readers if we have exclusive access.
        // `PoisonError` still surfaces here so a panicked baseline can be
        // re-evaluated cleanly.
        let b = match slot.get_mut() {
            Ok(g) => g,
            Err(_) => return true, // poisoned — leave it; next access will surface the panic
        };
        if b.last_anomaly.is_some() {
            return true;
        }
        now.duration_since(b.last_activity) < cutoff
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(cfg: serde_json::Value) -> AnomalyDetectorPlugin {
        AnomalyDetectorPlugin::from_config(&cfg).unwrap()
    }

    fn req(path: &str, headers: &[(&str, &str)]) -> Request<axum::body::Body> {
        let mut b = Request::builder().method("GET").uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn log_only_never_short_circuits_even_on_spike() {
        let p = plugin(serde_json::json!({
            "key_strategy": "consumer",
            "warmup_requests": 50,
            "ewma_alpha": 0.1,
            "mode": "log_only",
            "signals": {
                "request_rate": { "enabled": true, "sigma_threshold": 2.0, "window_secs": 60 },
                "body_size": { "enabled": false, "sigma_threshold": 5.0, "window_secs": 60 },
                "path_diversity": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 },
                "error_rate": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 }
            }
        }));
        for _ in 0..200 {
            let mut r = req("/v1/x", &[("x-consumer-username", "alice")]);
            assert!(p.on_request(&mut r).await.is_ok());
        }
        // Even with sigma=2.0 and 200 hits, log_only must never error out.
        for _ in 0..200 {
            let mut r = req("/v1/x", &[("x-consumer-username", "alice")]);
            let outcome = p.on_request(&mut r).await;
            assert!(outcome.is_ok(), "log_only must never short-circuit");
        }
    }

    #[tokio::test]
    async fn challenge_returns_429_with_retry_after() {
        // Force an immediate trigger by setting sigma absurdly low and giving
        // the EWMA enough samples + variance.
        let p = plugin(serde_json::json!({
            "key_strategy": "consumer",
            "warmup_requests": 10,
            "ewma_alpha": 0.5,
            "mode": "challenge",
            "challenge_retry_after": 7,
            "signals": {
                "request_rate": { "enabled": true, "sigma_threshold": 0.001, "window_secs": 60 },
                "body_size": { "enabled": false, "sigma_threshold": 5.0, "window_secs": 60 },
                "path_diversity": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 },
                "error_rate": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 }
            }
        }));
        // Warm up + ensure variance.
        for i in 0..50 {
            let path = if i % 2 == 0 { "/a" } else { "/b" };
            let mut r = req(path, &[("x-consumer-username", "bob")]);
            let _ = p.on_request(&mut r).await;
        }
        // After warmup with tiny sigma, next request should trigger.
        let mut found_429 = false;
        for _ in 0..20 {
            let mut r = req("/a", &[("x-consumer-username", "bob")]);
            if let Err(PluginError::ShortCircuit {
                status, headers, ..
            }) = p.on_request(&mut r).await
            {
                assert_eq!(status, 429);
                assert!(headers.iter().any(|(k, v)| k == "retry-after" && v == "7"));
                found_429 = true;
                break;
            }
        }
        assert!(found_429, "expected at least one 429 short-circuit");
    }

    #[tokio::test]
    async fn block_returns_403() {
        let p = plugin(serde_json::json!({
            "key_strategy": "consumer",
            "warmup_requests": 10,
            "ewma_alpha": 0.5,
            "mode": "block",
            "signals": {
                "request_rate": { "enabled": true, "sigma_threshold": 0.001, "window_secs": 60 },
                "body_size": { "enabled": false, "sigma_threshold": 5.0, "window_secs": 60 },
                "path_diversity": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 },
                "error_rate": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 }
            }
        }));
        for i in 0..50 {
            let path = if i % 2 == 0 { "/a" } else { "/b" };
            let mut r = req(path, &[("x-consumer-username", "carol")]);
            let _ = p.on_request(&mut r).await;
        }
        let mut found_403 = false;
        for _ in 0..20 {
            let mut r = req("/a", &[("x-consumer-username", "carol")]);
            if let Err(PluginError::ShortCircuit { status, .. }) = p.on_request(&mut r).await {
                assert_eq!(status, 403);
                found_403 = true;
                break;
            }
        }
        assert!(found_403);
    }

    #[tokio::test]
    async fn exempt_consumer_skipped() {
        let p = plugin(serde_json::json!({
            "key_strategy": "consumer",
            "warmup_requests": 1,
            "ewma_alpha": 0.5,
            "mode": "block",
            "exempt_consumers": ["dave"],
            "signals": {
                "request_rate": { "enabled": true, "sigma_threshold": 0.0001, "window_secs": 60 },
                "body_size": { "enabled": false, "sigma_threshold": 5.0, "window_secs": 60 },
                "path_diversity": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 },
                "error_rate": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 }
            }
        }));
        for _ in 0..500 {
            let mut r = req("/x", &[("x-consumer-username", "dave")]);
            assert!(
                p.on_request(&mut r).await.is_ok(),
                "exempt key must always pass"
            );
        }
        // No baseline should have been created for the exempt key.
        assert!(!p.state.contains_key("dave"));
    }

    #[tokio::test]
    async fn warmup_does_not_score() {
        let p = plugin(serde_json::json!({
            "key_strategy": "consumer",
            "warmup_requests": 1000,
            "ewma_alpha": 0.5,
            "mode": "block",
            "signals": {
                "request_rate": { "enabled": true, "sigma_threshold": 0.0001, "window_secs": 60 },
                "body_size": { "enabled": false, "sigma_threshold": 5.0, "window_secs": 60 },
                "path_diversity": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 },
                "error_rate": { "enabled": false, "sigma_threshold": 4.0, "window_secs": 60 }
            }
        }));
        for _ in 0..200 {
            let mut r = req("/x", &[("x-consumer-username", "eve")]);
            assert!(
                p.on_request(&mut r).await.is_ok(),
                "must not score during warmup"
            );
        }
    }

    #[tokio::test]
    async fn ip_strategy_uses_x_forwarded_for() {
        let p = plugin(serde_json::json!({
            "key_strategy": "ip",
            "warmup_requests": 5,
            "mode": "log_only"
        }));
        let mut r = req("/x", &[("x-forwarded-for", "10.0.0.5, 10.0.0.6")]);
        p.on_request(&mut r).await.unwrap();
        assert!(p.state.contains_key("10.0.0.5"));
    }

    #[tokio::test]
    async fn global_strategy_shares_one_bucket() {
        let p = plugin(serde_json::json!({
            "key_strategy": "global",
            "warmup_requests": 5,
            "mode": "log_only"
        }));
        for who in &["alice", "bob", "carol"] {
            let mut r = req("/x", &[("x-consumer-username", *who)]);
            p.on_request(&mut r).await.unwrap();
        }
        assert_eq!(p.state.len(), 1);
        assert!(p.state.contains_key("__global__"));
    }

    #[tokio::test]
    async fn on_response_updates_error_window() {
        let p = plugin(serde_json::json!({
            "key_strategy": "consumer",
            "warmup_requests": 1,
            "mode": "log_only"
        }));
        let mut req1 = req("/x", &[("x-consumer-username", "frank")]);
        p.on_request(&mut req1).await.unwrap();
        let ctx = req1.extensions().get::<AnomalyCtx>().cloned().unwrap();

        let mut resp = Response::builder().status(500).body(Body::empty()).unwrap();
        resp.extensions_mut().insert(ctx);
        p.on_response(&mut resp).await.unwrap();

        let entry = p.state.get("frank").unwrap();
        let b = entry.lock().unwrap();
        assert_eq!(b.error_window.errors, 1);
        assert_eq!(b.error_window.total, 1);
    }

    #[tokio::test]
    async fn factory_rejects_garbage_config() {
        let bad = serde_json::json!({ "key_strategy": "nonsense" });
        assert!(AnomalyDetectorPlugin::from_config(&bad).is_err());
    }
}
