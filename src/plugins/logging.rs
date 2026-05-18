use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{Request, Response};
use uuid::Uuid;

pub struct LoggingPlugin;

impl Default for LoggingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggingPlugin {
    pub fn new() -> Self {
        Self
    }

    pub fn from_config(_cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        Ok(Self)
    }
}

#[async_trait]
impl Plugin for LoggingPlugin {
    fn name(&self) -> &str {
        "logging"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        tracing::info!(
            request_id = %request_id,
            method = %req.method(),
            path = %req.uri().path(),
            "incoming request"
        );

        req.headers_mut()
            .insert("x-request-id", request_id.parse().unwrap());

        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let request_id = resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        tracing::info!(
            request_id = %request_id,
            status = %resp.status().as_u16(),
            "outgoing response"
        );

        Ok(())
    }
}
