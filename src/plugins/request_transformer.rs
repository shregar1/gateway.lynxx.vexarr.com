use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::{HeaderMap, HeaderName, HeaderValue};
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use std::str::FromStr;

/// Maximum request body size we will buffer for JSON transforms (10 MB).
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

pub struct RequestTransformerPlugin {
    add: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
    replace: Vec<(HeaderName, HeaderValue)>,
    add_body_fields: Option<serde_json::Map<String, serde_json::Value>>,
    remove_body_fields: Vec<String>,
    replace_body_fields: Option<serde_json::Map<String, serde_json::Value>>,
}

impl RequestTransformerPlugin {
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

pub(crate) fn parse_header_map(
    val: Option<&serde_json::Value>,
) -> Result<Vec<(HeaderName, HeaderValue)>, GatewayError> {
    let Some(obj) = val.and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        let name = HeaderName::from_str(k)
            .map_err(|e| GatewayError::BadRequest(format!("invalid header name {k}: {e}")))?;
        let s = v
            .as_str()
            .ok_or_else(|| GatewayError::BadRequest(format!("header {k} value must be string")))?;
        let value = HeaderValue::from_str(s)
            .map_err(|e| GatewayError::BadRequest(format!("invalid header value for {k}: {e}")))?;
        out.push((name, value));
    }
    Ok(out)
}

pub(crate) fn parse_header_list(
    val: Option<&serde_json::Value>,
) -> Result<Vec<HeaderName>, GatewayError> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v
            .as_str()
            .ok_or_else(|| GatewayError::BadRequest("header name must be string".into()))?;
        let name = HeaderName::from_str(s)
            .map_err(|e| GatewayError::BadRequest(format!("invalid header name {s}: {e}")))?;
        out.push(name);
    }
    Ok(out)
}

/// Parse a JSON array of strings into a `Vec<String>`. Returns an empty vec if
/// the value is absent or not an array.
fn parse_string_list(val: Option<&serde_json::Value>) -> Vec<String> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

/// Expand Caddy-style placeholders in a string:
///
///   `{http.request.method}`, `{http.request.uri}`, `{http.request.host}`,
///   `{http.request.header.X-Foo}`, `{env.HOME}`, `{time.now}`,
///   `{time.now.unix}`.
///
/// Unknown placeholders are left as-is.
pub(crate) fn expand_placeholders(
    template: &str,
    req: &axum::http::Request<axum::body::Body>,
) -> String {
    if !template.contains('{') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('}') {
            let key = &after[..end];
            let replacement = match key {
                "http.request.method" => Some(req.method().as_str().to_string()),
                "http.request.uri" => Some(req.uri().to_string()),
                "http.request.path" => Some(req.uri().path().to_string()),
                "http.request.host" => req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| req.uri().host().map(|h| h.to_string())),
                "http.request.query" => req.uri().query().map(|q| q.to_string()),
                "http.request.remote" => req
                    .extensions()
                    .get::<std::net::SocketAddr>()
                    .map(|a| a.to_string()),
                "time.now" => Some(chrono::Utc::now().to_rfc3339()),
                "time.now.unix" => Some(chrono::Utc::now().timestamp().to_string()),
                _ if key.starts_with("http.request.header.") => {
                    let hdr_name = &key["http.request.header.".len()..];
                    req.headers()
                        .get(hdr_name)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                }
                _ if key.starts_with("env.") => {
                    let var_name = &key["env.".len()..];
                    std::env::var(var_name).ok()
                }
                _ => None,
            };
            match replacement {
                Some(val) => out.push_str(&val),
                None => {
                    out.push('{');
                    out.push_str(key);
                    out.push('}');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

pub(crate) fn apply_transforms(
    headers: &mut HeaderMap,
    add: &[(HeaderName, HeaderValue)],
    remove: &[HeaderName],
    replace: &[(HeaderName, HeaderValue)],
) {
    for name in remove {
        headers.remove(name);
    }
    for (name, value) in add {
        headers.append(name.clone(), value.clone());
    }
    for (name, value) in replace {
        headers.insert(name.clone(), value.clone());
    }
}

/// Mutate a top-level JSON object in place: add new fields, remove fields,
/// and replace existing fields. Shared by both request and response
/// transformer plugins.
pub(crate) fn apply_body_field_transforms(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    add: Option<&serde_json::Map<String, serde_json::Value>>,
    remove: &[String],
    replace: Option<&serde_json::Map<String, serde_json::Value>>,
) {
    // Remove first so adds/replaces take precedence.
    for key in remove {
        obj.remove(key);
    }
    // Add: insert unconditionally (new or overwrite).
    if let Some(fields) = add {
        for (k, v) in fields {
            obj.insert(k.clone(), v.clone());
        }
    }
    // Replace: only touch keys that already exist.
    if let Some(fields) = replace {
        for (k, v) in fields {
            if obj.contains_key(k) {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
}

/// Returns `true` when the Content-Type header indicates JSON.
pub(crate) fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false)
}

#[async_trait]
impl Plugin for RequestTransformerPlugin {
    fn name(&self) -> &str {
        "request-transformer"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        // Expand placeholders in add/replace header values before applying.
        // Skip the whole block — two Vec allocations + HeaderName clones — when
        // no header transforms are configured (the common case). And within a
        // configured value, skip the expand+rebuild when it has no placeholder.
        if !self.add.is_empty() || !self.replace.is_empty() || !self.remove.is_empty() {
            // `req` is passed in (not captured) so no immutable borrow is held
            // across the `req.headers_mut()` mutable borrow below.
            fn expand_one(
                n: &HeaderName,
                v: &HeaderValue,
                req: &Request<axum::body::Body>,
            ) -> Option<(HeaderName, HeaderValue)> {
                let raw = v.to_str().ok()?;
                if !raw.contains('{') {
                    return Some((n.clone(), v.clone()));
                }
                let expanded = expand_placeholders(raw, req);
                Some((n.clone(), HeaderValue::from_str(&expanded).ok()?))
            }
            let expanded_add: Vec<(HeaderName, HeaderValue)> = self
                .add
                .iter()
                .filter_map(|(n, v)| expand_one(n, v, req))
                .collect();
            let expanded_replace: Vec<(HeaderName, HeaderValue)> = self
                .replace
                .iter()
                .filter_map(|(n, v)| expand_one(n, v, req))
                .collect();
            apply_transforms(
                req.headers_mut(),
                &expanded_add,
                &self.remove,
                &expanded_replace,
            );
        }

        // --- body transforms ---
        if !self.has_body_transforms() || !is_json_content_type(req.headers()) {
            return Ok(());
        }

        // Drain the streaming body into memory so we can parse/mutate it.
        let body = std::mem::replace(req.body_mut(), axum::body::Body::empty());
        let bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("body collect: {e}")))?
            .to_bytes();

        if bytes.len() > MAX_BODY_BYTES {
            // Restore original bytes and bail — don't silently drop the body.
            *req.body_mut() = axum::body::Body::from(bytes);
            return Ok(());
        }

        if bytes.is_empty() {
            *req.body_mut() = axum::body::Body::from(bytes);
            return Ok(());
        }

        // Parse; skip silently when body is not valid JSON.
        let mut parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                *req.body_mut() = axum::body::Body::from(bytes);
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
        *req.body_mut() = axum::body::Body::from(new_bytes);
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
