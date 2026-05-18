//! Dedicated redirect plugin.
//!
//! Returns HTTP redirects (301, 302, 307, 308) without forwarding to an
//! upstream. Equivalent to Caddy's `redir` directive.
//!
//! Config:
//! ```json
//! {
//!   "status": 301,
//!   "location": "https://example.com{path}",
//!   "preserve_query": true
//! }
//! ```
//!
//! The `{path}` and `{query}` placeholders in `location` are expanded
//! from the incoming request. `{host}` expands to the Host header.

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::LOCATION;
use axum::http::{HeaderValue, Request, Response, StatusCode};

pub struct RedirectPlugin {
    status: StatusCode,
    location_template: String,
    preserve_query: bool,
}

impl RedirectPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let status_code = cfg.get("status").and_then(|v| v.as_u64()).unwrap_or(302) as u16;

        let status = StatusCode::from_u16(status_code).map_err(|_| {
            GatewayError::BadRequest(format!("redirect: invalid status code {status_code}"))
        })?;

        let location_template = cfg
            .get("location")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::BadRequest("redirect: missing 'location'".into()))?
            .to_string();

        let preserve_query = cfg
            .get("preserve_query")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(Self {
            status,
            location_template,
            preserve_query,
        })
    }

    fn expand_location(&self, req: &Request<Body>) -> String {
        let path = req.uri().path();
        let query = req.uri().query().unwrap_or("");
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");

        let mut location = self
            .location_template
            .replace("{path}", path)
            .replace("{host}", host)
            .replace("{query}", query);

        // Append query string if not in template and preserve_query is true
        if self.preserve_query && !query.is_empty() && !self.location_template.contains("{query}") {
            if location.contains('?') {
                location.push('&');
            } else {
                location.push('?');
            }
            location.push_str(query);
        }

        location
    }
}

#[async_trait]
impl Plugin for RedirectPlugin {
    fn name(&self) -> &str {
        "redirect"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let location = self.expand_location(req);

        // Stash the redirect info in extensions for on_response to act on.
        req.extensions_mut().insert(RedirectInfo {
            status: self.status,
            location,
        });
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        if let Some(info) = resp.extensions().get::<RedirectInfo>().cloned() {
            *resp.status_mut() = info.status;
            if let Ok(val) = HeaderValue::from_str(&info.location) {
                resp.headers_mut().insert(LOCATION, val);
            }
            *resp.body_mut() = Body::empty();
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RedirectInfo {
    status: StatusCode,
    location: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_location_simple() {
        let plugin = RedirectPlugin {
            status: StatusCode::MOVED_PERMANENTLY,
            location_template: "https://new.example.com{path}".to_string(),
            preserve_query: true,
        };
        let req = Request::builder()
            .uri("http://old.example.com/foo/bar?x=1")
            .header("host", "old.example.com")
            .body(Body::empty())
            .unwrap();
        let loc = plugin.expand_location(&req);
        assert_eq!(loc, "https://new.example.com/foo/bar?x=1");
    }

    #[test]
    fn expand_location_host() {
        let plugin = RedirectPlugin {
            status: StatusCode::FOUND,
            location_template: "https://{host}/new{path}".to_string(),
            preserve_query: false,
        };
        let req = Request::builder()
            .uri("/old/page")
            .header("host", "mysite.com")
            .body(Body::empty())
            .unwrap();
        let loc = plugin.expand_location(&req);
        assert_eq!(loc, "https://mysite.com/new/old/page");
    }
}
