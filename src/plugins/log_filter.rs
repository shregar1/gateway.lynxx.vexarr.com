//! Log filter plugin — suppress or sample access log entries per-route.
//!
//! ## Config
//!
//! ```json
//! {
//!   "skip_paths": ["/healthz", "/readyz"],
//!   "skip_status": [200, 204],
//!   "sample_rate": 0.1
//! }
//! ```
//!
//! When `sample_rate` < 1.0, only a random fraction of requests are logged.
//! `skip_paths` and `skip_status` suppress logging entirely for matching
//! requests. This plugin sets a request extension that logging plugins
//! can check to decide whether to emit a log line.

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use axum::body::Body;
use axum::http::Request;
use std::sync::atomic::{AtomicU64, Ordering};

/// Extension marker that logging plugins check.
#[derive(Clone, Debug)]
pub struct LogFilterDecision {
    pub suppress: bool,
}

pub struct LogFilterPlugin {
    skip_paths: Vec<String>,
    skip_status: Vec<u16>,
    sample_rate: f64,
    counter: AtomicU64,
}

impl LogFilterPlugin {
    pub fn from_config(config: &serde_json::Value) -> Result<Self, GatewayError> {
        let skip_paths = config["skip_paths"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let skip_status = config["skip_status"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_default();

        let sample_rate = config["sample_rate"]
            .as_f64()
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);

        Ok(Self {
            skip_paths,
            skip_status,
            sample_rate,
            counter: AtomicU64::new(0),
        })
    }
}

#[async_trait::async_trait]
impl Plugin for LogFilterPlugin {
    fn name(&self) -> &'static str {
        "log-filter"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let path = req.uri().path().to_string();

        // Path-based suppression.
        let path_skip = self.skip_paths.iter().any(|p| path.starts_with(p.as_str()));

        // Sampling: only log a fraction of requests.
        let sampled_out = if self.sample_rate < 1.0 {
            let c = self.counter.fetch_add(1, Ordering::Relaxed);
            let threshold = (self.sample_rate * 1000.0) as u64;
            (c % 1000) >= threshold
        } else {
            false
        };

        req.extensions_mut().insert(LogFilterDecision {
            suppress: path_skip || sampled_out,
        });

        Ok(())
    }

    async fn on_response(
        &self,
        resp: &mut axum::http::Response<BoxBody>,
    ) -> Result<(), PluginError> {
        // Post-response status check: mark suppress if status matches skip list.
        if !self.skip_status.is_empty() {
            let status = resp.status().as_u16();
            if self.skip_status.contains(&status) {
                resp.extensions_mut()
                    .insert(LogFilterDecision { suppress: true });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let cfg = serde_json::json!({
            "skip_paths": ["/healthz"],
            "skip_status": [200],
            "sample_rate": 0.5
        });
        let plugin = LogFilterPlugin::from_config(&cfg).unwrap();
        assert_eq!(plugin.skip_paths, vec!["/healthz"]);
        assert_eq!(plugin.skip_status, vec![200]);
        assert!((plugin.sample_rate - 0.5).abs() < 0.001);
    }
}
