//! `openapi-drift` — passive observer that compares actual response shapes
//! against the OpenAPI spec.
//!
//! This is observability, not enforcement. We never block a request: when
//! the upstream returns a payload that violates the spec, we log it and
//! emit a Prometheus counter. Operators wire that counter into alerts.
//!
//! # Why this is a separate plugin from `request-validator`
//!
//! `request-validator` validates *requests* against a single JSON Schema
//! you pass in via config. This plugin validates *responses* against the
//! schema embedded in the spec for the matched (path, method, status).
//! Different schema source, different direction, different failure mode
//! (passive vs blocking).
//!
//! # Sampling and rate limiting
//!
//! Schema validation isn't free — `jsonschema` compiles each schema once
//! and then walks the response body. On a hot route at thousands of RPS
//! you do *not* want to pay this on every request. The `sample_rate` knob
//! drops most requests cheaply (single PRNG draw), and
//! `max_violations_per_minute` caps the log/metric spam if a deploy ships
//! a regression that fails on every response.

pub mod config;
pub mod spec_loader;
pub mod validator;

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use std::sync::Arc;

pub use config::OpenApiDriftConfig;

pub struct OpenApiDriftPlugin {
    cfg: OpenApiDriftConfig,
    inner: Arc<validator::DriftValidator>,
}

impl OpenApiDriftPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let parsed: OpenApiDriftConfig = serde_json::from_value(cfg.clone())
            .map_err(|e| GatewayError::BadRequest(format!("openapi-drift config: {e}")))?;
        let raw = spec_loader::load(&parsed)?;
        let validator = validator::DriftValidator::build(&raw, &parsed)?;
        Ok(Self {
            cfg: parsed,
            inner: Arc::new(validator),
        })
    }
}

#[async_trait]
impl Plugin for OpenApiDriftPlugin {
    fn name(&self) -> &str {
        "openapi-drift"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        // Stash the request method+path into extensions so on_response can
        // recover them without a parallel side-channel. We can't simply
        // re-read the request because Response doesn't carry it.
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();
        req.extensions_mut().insert(DriftCtx { method, path });
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        // Sampling: cheap PRNG draw before doing any work.
        if self.cfg.sample_rate < 1.0 {
            let r: f64 = rand::random();
            if r > self.cfg.sample_rate {
                return Ok(());
            }
        }

        // Recover request context from extensions.
        let ctx = match resp.extensions().get::<DriftCtx>().cloned() {
            Some(c) => c,
            None => return Ok(()), // request hook didn't run; nothing to compare against
        };

        // Only inspect JSON bodies — text/html etc. don't have a JSON Schema.
        let is_json = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| {
                ct.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
            .unwrap_or(false);
        if !is_json {
            return Ok(());
        }

        let status = resp.status().as_u16();

        // Drain → validate → restore.
        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return Ok(()), // can't fail the response over an observability collect error
        };

        // Parse + validate — both can fail, both we just log.
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => {
                self.inner.check(&ctx.method, &ctx.path, status, &value);
            }
            Err(_) => {
                // Body wasn't JSON despite the header — record and move on.
                self.inner.record(&ctx.method, &ctx.path, "non_json_body");
            }
        }

        // Always restore the body — we are passive.
        *resp.body_mut() = Body::from(bytes);
        Ok(())
    }
}

#[derive(Clone)]
struct DriftCtx {
    method: String,
    path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_spec_path() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("spec.yaml");
        std::fs::write(
            &p,
            r#"
openapi: 3.0.3
info: { title: t, version: '1.0' }
paths:
  /widgets/{id}:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id, name]
                properties:
                  id: { type: integer }
                  name: { type: string }
"#,
        )
        .unwrap();
        let path = p.to_string_lossy().to_string();
        (dir, path)
    }

    #[tokio::test]
    async fn flags_missing_field() {
        let (_dir, path) = tiny_spec_path();
        let cfg = serde_json::json!({
            "spec_path": path,
            "sample_rate": 1.0,
            "max_violations_per_minute": 1000,
            "log_level": "warn",
            "alert_on_violation": true,
        });
        let plugin = OpenApiDriftPlugin::from_config(&cfg).unwrap();

        let mut req = axum::http::Request::builder()
            .method("GET")
            .uri("/widgets/42")
            .body(axum::body::Body::empty())
            .unwrap();
        plugin.on_request(&mut req).await.unwrap();

        // Build a response that *violates* the schema (missing `name`).
        let mut resp = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id": 42}"#))
            .unwrap();
        resp.extensions_mut()
            .insert(req.extensions().get::<DriftCtx>().cloned().unwrap());

        plugin.on_response(&mut resp).await.unwrap();

        // Body restored.
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..], br#"{"id": 42}"#);

        // Violation was recorded.
        let total = plugin.inner.violations_recorded();
        assert!(total >= 1, "expected at least one violation, got {total}");
    }

    #[tokio::test]
    async fn passes_compliant_response() {
        let (_dir, path) = tiny_spec_path();
        let cfg = serde_json::json!({
            "spec_path": path,
            "sample_rate": 1.0,
            "max_violations_per_minute": 1000,
            "log_level": "warn",
            "alert_on_violation": true,
        });
        let plugin = OpenApiDriftPlugin::from_config(&cfg).unwrap();

        let mut req = axum::http::Request::builder()
            .method("GET")
            .uri("/widgets/7")
            .body(axum::body::Body::empty())
            .unwrap();
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id": 7, "name": "alpha"}"#))
            .unwrap();
        resp.extensions_mut()
            .insert(req.extensions().get::<DriftCtx>().cloned().unwrap());
        plugin.on_response(&mut resp).await.unwrap();
        assert_eq!(plugin.inner.violations_recorded(), 0);
    }
}
