use crate::error::{GatewayError, PluginError};
use crate::plugins::request_transformer::{
    apply_body_field_transforms, apply_transforms, is_json_content_type, parse_header_list,
    parse_header_map,
};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{Request, Response};
use http_body_util::BodyExt;

pub struct ResponseTransformerPlugin {
    add: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
    replace: Vec<(HeaderName, HeaderValue)>,
    add_body_fields: Option<serde_json::Map<String, serde_json::Value>>,
    remove_body_fields: Vec<String>,
    replace_body_fields: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ResponseTransformerPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        Ok(Self {
            add: parse_header_map(cfg.get("add_headers"))?,
            remove: parse_header_list(cfg.get("remove_headers"))?,
            replace: parse_header_map(cfg.get("replace_headers"))?,
            add_body_fields: cfg
                .get("add_body_fields")
                .and_then(|v| v.as_object())
                .cloned(),
            remove_body_fields: parse_string_list(cfg.get("remove_body_fields")),
            replace_body_fields: cfg
                .get("replace_body_fields")
                .and_then(|v| v.as_object())
                .cloned(),
        })
    }

    /// Returns `true` when at least one body-level transform is configured.
    fn has_body_transforms(&self) -> bool {
        self.add_body_fields.is_some()
            || !self.remove_body_fields.is_empty()
            || self.replace_body_fields.is_some()
    }
}

fn parse_string_list(val: Option<&serde_json::Value>) -> Vec<String> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

#[async_trait]
impl Plugin for ResponseTransformerPlugin {
    fn name(&self) -> &str {
        "response-transformer"
    }

    async fn on_request(&self, _req: &mut Request<Body>) -> Result<(), PluginError> {
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        // --- header transforms (existing) ---
        apply_transforms(resp.headers_mut(), &self.add, &self.remove, &self.replace);

        // --- body transforms ---
        if !self.has_body_transforms() || !is_json_content_type(resp.headers()) {
            return Ok(());
        }

        // Drain the body so we can parse/mutate it, then restore.
        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return Ok(()),
        };

        if bytes.is_empty() {
            *resp.body_mut() = Body::from(bytes);
            return Ok(());
        }

        // Parse; skip silently when body is not valid JSON.
        let mut parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                *resp.body_mut() = Body::from(bytes);
                return Ok(());
            }
        };

        // Only transform top-level objects.
        if let Some(obj) = parsed.as_object_mut() {
            apply_body_field_transforms(
                obj,
                self.add_body_fields.as_ref(),
                &self.remove_body_fields,
                self.replace_body_fields.as_ref(),
            );
        }

        let new_bytes = serde_json::to_vec(&parsed)
            .map_err(|e| PluginError::Internal(format!("json serialize: {e}")))?;
        *resp.body_mut() = Body::from(new_bytes);
        Ok(())
    }
}
