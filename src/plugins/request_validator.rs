use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use jsonschema::JSONSchema;
use std::sync::Arc;

/// JSON Schema validation of request bodies.
///
/// **v1 limitation:** the body is fully buffered in memory (up to
/// `max_body_bytes`). This is fine for the existing HTTP/1.1 buffered
/// proxy path but breaks streaming uploads. Disable on routes that
/// stream multi-MB payloads.
pub struct RequestValidatorPlugin {
    schema: JSONSchema,
    content_types: Vec<String>,
    max_body_bytes: usize,
}

impl RequestValidatorPlugin {
    pub fn from_config(
        cfg: &serde_json::Value,
        _repo: Option<Arc<dyn Repository>>,
    ) -> Result<Self, GatewayError> {
        let body_schema = cfg.get("body_schema").ok_or_else(|| {
            GatewayError::BadRequest("request-validator: `body_schema` is required".into())
        })?;
        let schema = JSONSchema::compile(body_schema)
            .map_err(|e| GatewayError::BadRequest(format!("invalid JSON schema: {e}")))?;
        let content_types = cfg
            .get("content_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["application/json".into()]);
        let max_body_bytes = cfg
            .get("max_body_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1_048_576) as usize;
        Ok(Self {
            schema,
            content_types,
            max_body_bytes,
        })
    }

    fn content_type_matches(&self, ct: Option<&str>) -> bool {
        let Some(ct) = ct else { return false };
        let head = ct
            .split(';')
            .next()
            .unwrap_or(ct)
            .trim()
            .to_ascii_lowercase();
        self.content_types.iter().any(|c| c == &head)
    }
}

fn bad_request_short_circuit(body: Vec<u8>) -> PluginError {
    PluginError::ShortCircuit {
        status: 400,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.into(),
    }
}

#[async_trait]
impl Plugin for RequestValidatorPlugin {
    fn name(&self) -> &str {
        "request-validator"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        if !self.content_type_matches(ct.as_deref()) {
            return Ok(());
        }

        // Up-front Content-Length check so we don't buffer giant payloads
        // that we'd reject anyway.
        if let Some(len) = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
        {
            if len > self.max_body_bytes {
                return Err(PluginError::PayloadTooLarge(format!(
                    "body {len} bytes exceeds limit {}",
                    self.max_body_bytes
                )));
            }
        }

        // Drain, validate, restore. Works because the gateway's HTTP/1.1
        // path already buffers; streaming uploads would break here.
        let body = std::mem::replace(req.body_mut(), Body::empty());
        let bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("body collect: {e}")))?
            .to_bytes();
        if bytes.len() > self.max_body_bytes {
            return Err(PluginError::PayloadTooLarge(format!(
                "body {} bytes exceeds limit {}",
                bytes.len(),
                self.max_body_bytes
            )));
        }
        if bytes.is_empty() {
            *req.body_mut() = Body::from(bytes);
            return Ok(());
        }

        let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "error": "invalid JSON",
                    "detail": e.to_string(),
                }))
                .unwrap_or_else(|_| br#"{"error":"invalid JSON"}"#.to_vec());
                return Err(bad_request_short_circuit(body));
            }
        };

        if let Err(errors) = self.schema.validate(&parsed) {
            let detail: Vec<String> = errors.map(|e| format!("{e}")).collect();
            let body = serde_json::to_vec(&serde_json::json!({
                "error": "request validation failed",
                "errors": detail,
            }))
            .unwrap_or_else(|_| br#"{"error":"request validation failed"}"#.to_vec());
            // Restore body before returning so error logging downstream
            // doesn't see a stripped request.
            *req.body_mut() = Body::from(bytes);
            return Err(bad_request_short_circuit(body));
        }

        *req.body_mut() = Body::from(bytes);
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
