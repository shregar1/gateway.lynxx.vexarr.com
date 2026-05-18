use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use std::collections::HashMap;

/// Custom error pages plugin. Maps HTTP error status codes to custom
/// response bodies (HTML, JSON, or plain text). Caddy equivalent of
/// `handle_errors`.
///
/// Config:
/// ```json
/// {
///   "pages": {
///     "404": { "body": "<h1>Not Found</h1>", "content_type": "text/html" },
///     "500": { "body": "{\"error\": \"internal\"}", "content_type": "application/json" },
///     "502": { "redirect": "/maintenance.html" }
///   }
/// }
/// ```
pub struct ErrorHandlerPlugin {
    pages: HashMap<u16, ErrorPage>,
}

enum ErrorPage {
    Body { body: String, content_type: String },
    Redirect { location: String },
}

impl ErrorHandlerPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let mut pages = HashMap::new();
        if let Some(obj) = cfg.get("pages").and_then(|v| v.as_object()) {
            for (code_str, val) in obj {
                let code: u16 = code_str.parse().map_err(|_| {
                    GatewayError::BadRequest(format!("invalid status code: {code_str}"))
                })?;
                if let Some(redirect) = val.get("redirect").and_then(|v| v.as_str()) {
                    pages.insert(
                        code,
                        ErrorPage::Redirect {
                            location: redirect.to_string(),
                        },
                    );
                } else if let Some(body) = val.get("body").and_then(|v| v.as_str()) {
                    let ct = val
                        .get("content_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("text/html; charset=utf-8")
                        .to_string();
                    pages.insert(
                        code,
                        ErrorPage::Body {
                            body: body.to_string(),
                            content_type: ct,
                        },
                    );
                }
            }
        }
        Ok(Self { pages })
    }
}

#[async_trait]
impl Plugin for ErrorHandlerPlugin {
    fn name(&self) -> &str {
        "error-handler"
    }

    async fn on_request(&self, _req: &mut Request<Body>) -> Result<(), PluginError> {
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let status = resp.status().as_u16();
        if status < 400 {
            return Ok(());
        }
        let Some(page) = self.pages.get(&status) else {
            return Ok(());
        };
        match page {
            ErrorPage::Body { body, content_type } => {
                *resp.body_mut() = Body::from(body.clone());
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    content_type
                        .parse()
                        .unwrap_or_else(|_| "text/html".parse().unwrap()),
                );
                resp.headers_mut().insert(
                    header::CONTENT_LENGTH,
                    body.len().to_string().parse().unwrap(),
                );
            }
            ErrorPage::Redirect { location } => {
                *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
                *resp.body_mut() = Body::empty();
                if let Ok(v) = location.parse() {
                    resp.headers_mut().insert(header::LOCATION, v);
                }
            }
        }
        Ok(())
    }
}
