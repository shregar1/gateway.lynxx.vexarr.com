use crate::error::{GatewayError, PluginError, SyncBody};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::HeaderName;
use axum::http::{Request, Response};
use std::str::FromStr;
use std::time::Duration;

/// Forward-auth subrequest plugin.
///
/// On each inbound request, makes an HTTP subrequest to a configured
/// auth service. If the auth service returns 2xx, configured response
/// headers are copied onto the original request and it proceeds to
/// upstream. On any non-2xx, the auth service's status code, headers,
/// and body are returned verbatim to the client via `ShortCircuit`.
pub struct ForwardAuthPlugin {
    auth_url: String,
    method: String,
    headers_to_forward: Vec<HeaderName>,
    headers_to_copy_back: Vec<HeaderName>,
    timeout: Duration,
    http: reqwest::Client,
}

impl ForwardAuthPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let auth_url = cfg
            .get("auth_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::BadRequest("forward-auth: `auth_url` is required".into()))?
            .to_string();

        let method = cfg
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();

        let headers_to_forward = parse_header_names(cfg.get("headers_to_forward"));
        let headers_to_copy_back = parse_header_names(cfg.get("headers_to_copy_back"));

        let timeout_secs = cfg
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(5);

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| GatewayError::BadRequest(format!("forward-auth: build client: {e}")))?;

        Ok(Self {
            auth_url,
            method,
            headers_to_forward,
            headers_to_copy_back,
            timeout: Duration::from_secs(timeout_secs),
            http,
        })
    }
}

fn parse_header_names(val: Option<&serde_json::Value>) -> Vec<HeaderName> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| HeaderName::from_str(s).ok())
        .collect()
}

#[async_trait]
impl Plugin for ForwardAuthPlugin {
    fn name(&self) -> &str {
        "forward-auth"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let mut builder = match self.method.as_str() {
            "POST" => self.http.post(&self.auth_url),
            "PUT" => self.http.put(&self.auth_url),
            _ => self.http.get(&self.auth_url),
        };

        // Forward configured headers from the original request.
        // If no explicit list, forward Authorization and Cookie by default.
        if self.headers_to_forward.is_empty() {
            for name in &[
                axum::http::header::AUTHORIZATION,
                axum::http::header::COOKIE,
            ] {
                if let Some(v) = req.headers().get(name) {
                    if let Ok(s) = v.to_str() {
                        builder = builder.header(name.as_str(), s);
                    }
                }
            }
        } else {
            for name in &self.headers_to_forward {
                if let Some(v) = req.headers().get(name) {
                    if let Ok(s) = v.to_str() {
                        builder = builder.header(name.as_str(), s);
                    }
                }
            }
        }

        // Also forward X-Forwarded-* context.
        builder = builder.header("X-Forwarded-Method", req.method().as_str());
        builder = builder.header("X-Forwarded-Uri", req.uri().to_string());
        if let Some(host) = req.headers().get(axum::http::header::HOST) {
            if let Ok(s) = host.to_str() {
                builder = builder.header("X-Forwarded-Host", s);
            }
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| PluginError::Internal(format!("forward-auth subrequest: {e}")))?;

        let status = resp.status().as_u16();

        if (200..300).contains(&status) {
            // Auth succeeded — copy configured headers back onto the request.
            let resp_headers = resp.headers().clone();
            for name in &self.headers_to_copy_back {
                if let Some(v) = resp_headers.get(name) {
                    req.headers_mut().insert(name.clone(), v.clone());
                }
            }
            return Ok(());
        }

        // Auth denied — short-circuit with the auth service's response.
        let resp_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();

        let body_bytes = resp.bytes().await.unwrap_or_default();

        Err(PluginError::ShortCircuit {
            status,
            headers: resp_headers,
            body: SyncBody::from(body_bytes.to_vec()),
        })
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
