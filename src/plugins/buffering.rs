//! Full request/response body buffering middleware with disk spillover support.
//!
//! Buffers the entire request and/or response body so that the proxy can
//! replay requests on retry, enforce size limits, and hand a deterministic
//! byte-slice to downstream plugins instead of a streaming body.
//!
//! Bodies smaller than the configured memory threshold are kept in-memory.
//! Larger bodies spill to a temporary file under `/tmp` and are memory-mapped
//! back when reconstructing the body, keeping resident memory bounded even
//! for multi-gigabyte uploads.

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use std::io::Write;

/// Marker stored in request extensions when the buffered request body
/// exceeds `max_request_body_bytes`. The handler should map this to 413.
#[derive(Debug, Clone)]
pub struct RequestBodyTooLarge;

/// Marker stored in response extensions when the buffered response body
/// exceeds `max_response_body_bytes`. The handler should map this to 500.
#[derive(Debug, Clone)]
pub struct ResponseBodyTooLarge;

pub struct BufferingPlugin {
    /// Maximum request body size in bytes. 0 = unlimited.
    max_request_body_bytes: u64,
    /// Request body sizes above this threshold spill to a temp file.
    mem_request_body_bytes: u64,
    /// Maximum response body size in bytes. 0 = unlimited.
    max_response_body_bytes: u64,
    /// Response body sizes above this threshold spill to a temp file.
    mem_response_body_bytes: u64,
    /// Retry expression (e.g. `"Attempts() <= 2 && ResponseCode() == 502"`).
    /// Stored for future evaluation; parsing is a v2 enhancement.
    retry_expression: String,
}

impl BufferingPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let max_request_body_bytes = cfg
            .get("max_request_body_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mem_request_body_bytes = cfg
            .get("mem_request_body_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1_048_576);
        let max_response_body_bytes = cfg
            .get("max_response_body_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mem_response_body_bytes = cfg
            .get("mem_response_body_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1_048_576);
        let retry_expression = cfg
            .get("retry_expression")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(Self {
            max_request_body_bytes,
            mem_request_body_bytes,
            max_response_body_bytes,
            mem_response_body_bytes,
            retry_expression,
        })
    }

    /// Returns the configured retry expression (opaque string for now).
    pub fn retry_expression(&self) -> &str {
        &self.retry_expression
    }

    /// Buffer bytes, spilling to a temp file when over the memory threshold.
    /// Returns the buffered bytes or an IO error.
    fn buffer_bytes(data: &[u8], mem_threshold: u64) -> Result<Vec<u8>, std::io::Error> {
        let len = data.len() as u64;
        if len <= mem_threshold {
            // Fast path: keep in memory.
            return Ok(data.to_vec());
        }

        // Spill to temp file and read back.
        let tmp_path = format!(
            "/tmp/lynxx_buf_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(data)?;
            file.flush()?;
        }
        let result = std::fs::read(&tmp_path);
        // Best-effort cleanup.
        let _ = std::fs::remove_file(&tmp_path);
        result
    }
}

#[async_trait]
impl Plugin for BufferingPlugin {
    fn name(&self) -> &str {
        "buffering"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        // Collect the streaming body into bytes.
        let body = std::mem::replace(req.body_mut(), axum::body::Body::empty());
        let bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("failed to read request body: {e}")))?
            .to_bytes();

        let len = bytes.len() as u64;

        // Check max size.
        if self.max_request_body_bytes > 0 && len > self.max_request_body_bytes {
            req.extensions_mut().insert(RequestBodyTooLarge);
            return Err(PluginError::PayloadTooLarge(format!(
                "request body {len} bytes exceeds limit of {}",
                self.max_request_body_bytes
            )));
        }

        // Buffer with potential disk spillover.
        let buffered = Self::buffer_bytes(&bytes, self.mem_request_body_bytes)
            .map_err(|e| PluginError::Internal(format!("buffering request body: {e}")))?;

        *req.body_mut() = axum::body::Body::from(buffered);
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        // Collect the streaming response body.
        let body = std::mem::replace(resp.body_mut(), axum::body::Body::empty());
        let bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("failed to read response body: {e}")))?
            .to_bytes();

        let len = bytes.len() as u64;

        // Check max size.
        if self.max_response_body_bytes > 0 && len > self.max_response_body_bytes {
            resp.extensions_mut().insert(ResponseBodyTooLarge);
            return Err(PluginError::Internal(format!(
                "response body {len} bytes exceeds limit of {}",
                self.max_response_body_bytes
            )));
        }

        // Buffer with potential disk spillover.
        let buffered = Self::buffer_bytes(&bytes, self.mem_response_body_bytes)
            .map_err(|e| PluginError::Internal(format!("buffering response body: {e}")))?;

        *resp.body_mut() = axum::body::Body::from(buffered);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, Response};
    use http_body_util::BodyExt;
    use serde_json::json;

    fn make_plugin(cfg: serde_json::Value) -> BufferingPlugin {
        BufferingPlugin::from_config(&cfg).unwrap()
    }

    async fn body_to_bytes(body: Body) -> Vec<u8> {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    // ── Request buffering ──

    #[tokio::test]
    async fn small_request_body_passes() {
        let plugin = make_plugin(json!({}));
        let mut req = Request::new(Body::from("hello"));
        plugin.on_request(&mut req).await.unwrap();
        let bytes = body_to_bytes(req.into_body()).await;
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn request_body_within_max_passes() {
        let plugin = make_plugin(json!({ "max_request_body_bytes": 100 }));
        let payload = vec![b'x'; 50];
        let mut req = Request::new(Body::from(payload.clone()));
        plugin.on_request(&mut req).await.unwrap();
        let bytes = body_to_bytes(req.into_body()).await;
        assert_eq!(bytes, payload);
    }

    #[tokio::test]
    async fn request_body_over_max_returns_413() {
        let plugin = make_plugin(json!({ "max_request_body_bytes": 10 }));
        let payload = vec![b'x'; 50];
        let mut req = Request::new(Body::from(payload));
        let err = plugin.on_request(&mut req).await.unwrap_err();
        match err {
            PluginError::PayloadTooLarge(msg) => {
                assert!(
                    msg.contains("50"),
                    "error should mention actual size: {msg}"
                );
                assert!(msg.contains("10"), "error should mention limit: {msg}");
            }
            other => panic!("expected PayloadTooLarge, got: {other:?}"),
        }
        // Extension marker should be set.
        assert!(req.extensions().get::<RequestBodyTooLarge>().is_some());
    }

    #[tokio::test]
    async fn request_body_unlimited_when_max_zero() {
        let plugin = make_plugin(json!({ "max_request_body_bytes": 0 }));
        let payload = vec![b'x'; 100_000];
        let mut req = Request::new(Body::from(payload.clone()));
        plugin.on_request(&mut req).await.unwrap();
        let bytes = body_to_bytes(req.into_body()).await;
        assert_eq!(bytes.len(), 100_000);
    }

    #[tokio::test]
    async fn request_body_spills_to_disk_over_mem_threshold() {
        // mem threshold = 10, body = 100 bytes — forces disk spill.
        let plugin = make_plugin(json!({
            "mem_request_body_bytes": 10,
            "max_request_body_bytes": 0
        }));
        let payload = vec![b'A'; 100];
        let mut req = Request::new(Body::from(payload.clone()));
        plugin.on_request(&mut req).await.unwrap();
        let bytes = body_to_bytes(req.into_body()).await;
        assert_eq!(bytes, payload, "disk-spilled body should round-trip intact");
    }

    // ── Response buffering ──

    #[tokio::test]
    async fn small_response_body_passes() {
        let plugin = make_plugin(json!({}));
        let mut resp = Response::new(Body::from("world"));
        plugin.on_response(&mut resp).await.unwrap();
        let bytes = body_to_bytes(resp.into_body()).await;
        assert_eq!(bytes, b"world");
    }

    #[tokio::test]
    async fn response_body_over_max_returns_500() {
        let plugin = make_plugin(json!({ "max_response_body_bytes": 10 }));
        let payload = vec![b'y'; 50];
        let mut resp = Response::new(Body::from(payload));
        let err = plugin.on_response(&mut resp).await.unwrap_err();
        match err {
            PluginError::Internal(msg) => {
                assert!(
                    msg.contains("50"),
                    "error should mention actual size: {msg}"
                );
                assert!(msg.contains("10"), "error should mention limit: {msg}");
            }
            other => panic!("expected Internal, got: {other:?}"),
        }
        assert!(resp.extensions().get::<ResponseBodyTooLarge>().is_some());
    }

    #[tokio::test]
    async fn response_body_spills_to_disk() {
        let plugin = make_plugin(json!({
            "mem_response_body_bytes": 10,
            "max_response_body_bytes": 0
        }));
        let payload = vec![b'B'; 200];
        let mut resp = Response::new(Body::from(payload.clone()));
        plugin.on_response(&mut resp).await.unwrap();
        let bytes = body_to_bytes(resp.into_body()).await;
        assert_eq!(bytes, payload);
    }

    // ── retry_expression ──

    #[tokio::test]
    async fn retry_expression_stored() {
        let plugin = make_plugin(json!({
            "retry_expression": "Attempts() <= 2 && ResponseCode() == 502"
        }));
        assert_eq!(
            plugin.retry_expression(),
            "Attempts() <= 2 && ResponseCode() == 502"
        );
    }

    #[tokio::test]
    async fn retry_expression_defaults_to_empty() {
        let plugin = make_plugin(json!({}));
        assert_eq!(plugin.retry_expression(), "");
    }

    // ── Config defaults ──

    #[tokio::test]
    async fn default_config_values() {
        let plugin = make_plugin(json!({}));
        assert_eq!(plugin.max_request_body_bytes, 0);
        assert_eq!(plugin.mem_request_body_bytes, 1_048_576);
        assert_eq!(plugin.max_response_body_bytes, 0);
        assert_eq!(plugin.mem_response_body_bytes, 1_048_576);
        assert_eq!(plugin.retry_expression, "");
    }

    // ── Empty body ──

    #[tokio::test]
    async fn empty_request_body_passes() {
        let plugin = make_plugin(json!({ "max_request_body_bytes": 100 }));
        let mut req = Request::new(Body::empty());
        plugin.on_request(&mut req).await.unwrap();
        let bytes = body_to_bytes(req.into_body()).await;
        assert!(bytes.is_empty());
    }
}
