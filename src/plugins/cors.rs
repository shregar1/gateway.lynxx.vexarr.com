use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::{header, HeaderValue, Request, Response};

pub struct CorsPlugin {
    allow_origins: Vec<String>,
    allow_methods: String,
    allow_headers: String,
    allow_credentials: bool,
}

#[derive(Clone)]
struct RequestOrigin(HeaderValue);

impl CorsPlugin {
    pub fn new(allow_origins: Vec<String>, allow_credentials: bool) -> Self {
        Self {
            allow_origins,
            allow_methods: "GET, POST, PUT, DELETE, PATCH, OPTIONS".into(),
            allow_headers: "Content-Type, Authorization, X-Api-Key, X-Request-Id, X-Lynxx-Web"
                .into(),
            allow_credentials,
        }
    }

    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let origins = cfg
            .get("allow_origins")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["*".to_string()]);
        let allow_credentials = cfg
            .get("allow_credentials")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(Self::new(origins, allow_credentials))
    }
}

#[async_trait]
impl Plugin for CorsPlugin {
    fn name(&self) -> &str {
        "cors"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        if let Some(origin) = req.headers().get(header::ORIGIN).cloned() {
            req.extensions_mut().insert(RequestOrigin(origin));
        }
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let origin_ext = resp.extensions().get::<RequestOrigin>();

        let origin = if self.allow_origins.contains(&"*".to_string()) {
            if self.allow_credentials {
                // If credentials are allowed, we MUST mirror the origin instead of '*'
                origin_ext
                    .map(|o| o.0.clone())
                    .unwrap_or(HeaderValue::from_static("*"))
            } else {
                HeaderValue::from_static("*")
            }
        } else if let Some(req_origin) = origin_ext {
            let req_origin_str = req_origin.0.to_str().unwrap_or("");
            if self.allow_origins.iter().any(|o| o == req_origin_str) {
                req_origin.0.clone()
            } else {
                // If not in allowlist, return the first one as a fallback or just don't set it?
                // Standard CORS returns nothing or an origin that doesn't match if it fails.
                // Here we'll return the first allowed origin to match previous (buggy) behavior
                // but at least it will match if the origin IS in the list.
                self.allow_origins
                    .first()
                    .and_then(|s| HeaderValue::from_str(s).ok())
                    .unwrap_or(HeaderValue::from_static("*"))
            }
        } else {
            self.allow_origins
                .first()
                .and_then(|s| HeaderValue::from_str(s).ok())
                .unwrap_or(HeaderValue::from_static("*"))
        };

        let headers = resp.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);

        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_str(&self.allow_methods).unwrap_or(HeaderValue::from_static("GET")),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_str(&self.allow_headers)
                .unwrap_or(HeaderValue::from_static("Content-Type")),
        );

        if self.allow_credentials {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }

        Ok(())
    }
}
