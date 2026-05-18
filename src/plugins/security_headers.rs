//! Security headers plugin — add a preset of security response headers.
//!
//! ## Config
//!
//! ```json
//! {
//!   "content_security_policy": "default-src 'self'",
//!   "strict_transport_security": "max-age=31536000; includeSubDomains",
//!   "x_frame_options": "DENY",
//!   "x_content_type_options": "nosniff",
//!   "referrer_policy": "strict-origin-when-cross-origin",
//!   "permissions_policy": "camera=(), microphone=()",
//!   "cross_origin_opener_policy": "same-origin",
//!   "cross_origin_embedder_policy": "require-corp"
//! }
//! ```
//!
//! All fields are optional. When set, the corresponding header is added
//! to every response. This saves operators from manually configuring
//! response_transformer for common security headers.

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use axum::body::Body;
use axum::http::{Request, Response};

pub struct SecurityHeadersPlugin {
    headers: Vec<(String, String)>,
}

impl SecurityHeadersPlugin {
    pub fn from_config(config: &serde_json::Value) -> Result<Self, GatewayError> {
        let mapping = [
            ("content_security_policy", "Content-Security-Policy"),
            ("strict_transport_security", "Strict-Transport-Security"),
            ("x_frame_options", "X-Frame-Options"),
            ("x_content_type_options", "X-Content-Type-Options"),
            ("referrer_policy", "Referrer-Policy"),
            ("permissions_policy", "Permissions-Policy"),
            ("cross_origin_opener_policy", "Cross-Origin-Opener-Policy"),
            (
                "cross_origin_embedder_policy",
                "Cross-Origin-Embedder-Policy",
            ),
            (
                "cross_origin_resource_policy",
                "Cross-Origin-Resource-Policy",
            ),
            ("x_xss_protection", "X-XSS-Protection"),
        ];

        let mut headers = Vec::new();

        // If no explicit config, apply sensible defaults.
        let obj = config.as_object();
        let is_empty = obj.is_none_or(|o| o.is_empty());

        if is_empty {
            headers.push(("X-Content-Type-Options".into(), "nosniff".into()));
            headers.push(("X-Frame-Options".into(), "DENY".into()));
            headers.push((
                "Referrer-Policy".into(),
                "strict-origin-when-cross-origin".into(),
            ));
            headers.push((
                "Strict-Transport-Security".into(),
                "max-age=31536000; includeSubDomains".into(),
            ));
            headers.push(("X-XSS-Protection".into(), "0".into()));
        } else {
            for (config_key, header_name) in &mapping {
                if let Some(val) = config[config_key].as_str() {
                    headers.push((header_name.to_string(), val.to_string()));
                }
            }
        }

        Ok(Self { headers })
    }
}

#[async_trait::async_trait]
impl Plugin for SecurityHeadersPlugin {
    fn name(&self) -> &'static str {
        "security-headers"
    }

    async fn on_request(&self, _req: &mut Request<Body>) -> Result<(), PluginError> {
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        for (name, value) in &self.headers {
            if let (Ok(n), Ok(v)) = (
                axum::http::header::HeaderName::from_bytes(name.as_bytes()),
                axum::http::header::HeaderValue::from_str(value),
            ) {
                // Don't overwrite existing headers (upstream may have set them).
                if !resp.headers().contains_key(&n) {
                    resp.headers_mut().insert(n, v);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_applied() {
        let cfg = serde_json::json!({});
        let plugin = SecurityHeadersPlugin::from_config(&cfg).unwrap();
        assert!(!plugin.headers.is_empty());
        assert!(plugin.headers.iter().any(|(k, _)| k == "X-Frame-Options"));
    }

    #[test]
    fn custom_csp() {
        let cfg = serde_json::json!({
            "content_security_policy": "default-src 'self'",
            "x_frame_options": "SAMEORIGIN"
        });
        let plugin = SecurityHeadersPlugin::from_config(&cfg).unwrap();
        assert_eq!(plugin.headers.len(), 2);
    }
}
