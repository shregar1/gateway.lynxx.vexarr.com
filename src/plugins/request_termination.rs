use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};

/// Always short-circuit with a canned response. Useful for maintenance
/// windows, blocking specific routes, or mocking endpoints during dev. Set
/// it as a route-scoped plugin to mock just that route.
pub struct RequestTerminationPlugin {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

impl RequestTerminationPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let status = cfg
            .get("status")
            .and_then(|v| v.as_u64())
            .map(|n| n as u16)
            .unwrap_or(503);
        let content_type = cfg
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("application/json")
            .to_string();

        // `body` wins over `message`. If neither is provided we fall back to
        // a tiny JSON envelope so consumers don't get an empty 503.
        let body = if let Some(b) = cfg.get("body").and_then(|v| v.as_str()) {
            b.as_bytes().to_vec()
        } else if let Some(msg) = cfg.get("message").and_then(|v| v.as_str()) {
            serde_json::to_vec(&serde_json::json!({ "message": msg }))
                .map_err(|e| GatewayError::BadRequest(format!("encode termination body: {e}")))?
        } else {
            br#"{"error":"request terminated"}"#.to_vec()
        };

        Ok(Self {
            status,
            content_type,
            body,
        })
    }
}

#[async_trait]
impl Plugin for RequestTerminationPlugin {
    fn name(&self) -> &str {
        "request-termination"
    }

    async fn on_request(&self, _req: &mut Request<Body>) -> Result<(), PluginError> {
        Err(PluginError::ShortCircuit {
            status: self.status,
            headers: vec![("content-type".into(), self.content_type.clone())],
            body: self.body.clone().into(),
        })
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
