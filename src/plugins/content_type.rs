//! Content-Type auto-detection plugin.
//!
//! Middleware that auto-detects and sets the `Content-Type` response header
//! when it is missing or set to the generic `application/octet-stream`.
//! Detection is based on the request URI path extension using `mime_guess`.
//!
//! Config:
//! ```json
//! {
//!   "auto_detect": true,
//!   "default_type": "application/octet-stream"
//! }
//! ```

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, Request, Response};

/// Extension stored during `on_request` so `on_response` can access the
/// original request URI path for MIME guessing.
#[derive(Clone, Debug)]
struct RequestPath(String);

pub struct ContentTypePlugin {
    auto_detect: bool,
    default_type: String,
}

impl ContentTypePlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let auto_detect = cfg
            .get("auto_detect")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let default_type = cfg
            .get("default_type")
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_string();
        Ok(Self {
            auto_detect,
            default_type,
        })
    }
}

#[async_trait]
impl Plugin for ContentTypePlugin {
    fn name(&self) -> &str {
        "content-type"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let path = req.uri().path().to_string();
        req.extensions_mut().insert(RequestPath(path));
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        if !self.auto_detect {
            return Ok(());
        }

        // Check whether we should attempt detection: either no Content-Type
        // header at all, or the header is set to application/octet-stream.
        let should_detect = match resp.headers().get(CONTENT_TYPE) {
            None => true,
            Some(val) => val
                .to_str()
                .map(|s| s == "application/octet-stream")
                .unwrap_or(false),
        };

        if !should_detect {
            return Ok(());
        }

        let path = match resp.extensions().get::<RequestPath>() {
            Some(p) => p.0.clone(),
            None => return Ok(()),
        };

        // Extract the file extension from the path and guess MIME type.
        let guessed = mime_guess::from_path(&path).first_raw();

        let content_type = match guessed {
            Some(mime) => mime,
            None => &self.default_type,
        };

        if let Ok(val) = HeaderValue::from_str(content_type) {
            resp.headers_mut().insert(CONTENT_TYPE, val);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    /// Build a request with the given URI path.
    fn make_request(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    /// Build a response, optionally with a Content-Type header already set.
    fn make_response(content_type: Option<&str>) -> Response<BoxBody> {
        let mut builder = Response::builder();
        if let Some(ct) = content_type {
            builder = builder.header(CONTENT_TYPE, ct);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn default_plugin() -> ContentTypePlugin {
        ContentTypePlugin {
            auto_detect: true,
            default_type: "application/octet-stream".to_string(),
        }
    }

    #[tokio::test]
    async fn html_extension_sets_text_html() {
        let plugin = default_plugin();
        let mut req = make_request("/index.html");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(None);
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/html"
        );
    }

    #[tokio::test]
    async fn json_extension_sets_application_json() {
        let plugin = default_plugin();
        let mut req = make_request("/api/data.json");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(None);
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn css_extension_sets_text_css() {
        let plugin = default_plugin();
        let mut req = make_request("/styles/main.css");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(None);
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/css"
        );
    }

    #[tokio::test]
    async fn js_extension_sets_text_javascript() {
        let plugin = default_plugin();
        let mut req = make_request("/app.js");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(None);
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        // mime_guess returns "application/javascript" — both are valid JS MIME types.
        assert!(
            ct == "application/javascript" || ct == "text/javascript",
            "unexpected content-type for .js: {ct}"
        );
    }

    #[tokio::test]
    async fn existing_content_type_preserved() {
        let plugin = default_plugin();
        let mut req = make_request("/index.html");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(Some("text/plain"));
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        // Should NOT be overridden — it was already set to something other than
        // application/octet-stream.
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn octet_stream_gets_replaced() {
        let plugin = default_plugin();
        let mut req = make_request("/report.pdf");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(Some("application/octet-stream"));
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/pdf"
        );
    }

    #[tokio::test]
    async fn missing_extension_uses_default() {
        let plugin = ContentTypePlugin {
            auto_detect: true,
            default_type: "text/plain".to_string(),
        };
        let mut req = make_request("/no-extension");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(None);
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn auto_detect_disabled_skips_detection() {
        let plugin = ContentTypePlugin {
            auto_detect: false,
            default_type: "application/octet-stream".to_string(),
        };
        let mut req = make_request("/index.html");
        plugin.on_request(&mut req).await.unwrap();

        let mut resp = make_response(None);
        resp.extensions_mut()
            .insert(req.extensions().get::<RequestPath>().unwrap().clone());
        plugin.on_response(&mut resp).await.unwrap();

        // No Content-Type should be added when auto_detect is off.
        assert!(resp.headers().get(CONTENT_TYPE).is_none());
    }

    #[tokio::test]
    async fn from_config_defaults() {
        let plugin = ContentTypePlugin::from_config(&serde_json::json!({})).unwrap();
        assert!(plugin.auto_detect);
        assert_eq!(plugin.default_type, "application/octet-stream");
    }

    #[tokio::test]
    async fn from_config_custom() {
        let plugin = ContentTypePlugin::from_config(&serde_json::json!({
            "auto_detect": false,
            "default_type": "text/plain"
        }))
        .unwrap();
        assert!(!plugin.auto_detect);
        assert_eq!(plugin.default_type, "text/plain");
    }
}
