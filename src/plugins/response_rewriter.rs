use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use regex::Regex;

pub struct ResponseRewriterPlugin {
    rules: Vec<RewriteRule>,
    content_types: Vec<String>,
    max_body_bytes: usize,
}

struct RewriteRule {
    pattern: RewritePattern,
    replacement: String,
}

enum RewritePattern {
    Regex(Regex),
    Literal(String),
}

impl ResponseRewriterPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let mut rules = Vec::new();

        if let Some(arr) = cfg.get("rules").and_then(|v| v.as_array()) {
            for item in arr {
                let replacement = item
                    .get("replacement")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let is_regex = item.get("regex").and_then(|v| v.as_bool()).unwrap_or(false);

                let pattern_str =
                    item.get("pattern")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            GatewayError::BadRequest(
                                "response-rewriter: each rule needs a `pattern`".into(),
                            )
                        })?;

                let pattern = if is_regex {
                    let re = Regex::new(pattern_str).map_err(|e| {
                        GatewayError::BadRequest(format!(
                            "response-rewriter: invalid regex '{pattern_str}': {e}"
                        ))
                    })?;
                    RewritePattern::Regex(re)
                } else {
                    RewritePattern::Literal(pattern_str.to_string())
                };

                rules.push(RewriteRule {
                    pattern,
                    replacement,
                });
            }
        }

        let content_types = cfg
            .get("content_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    "text/html".into(),
                    "text/plain".into(),
                    "text/xml".into(),
                    "application/json".into(),
                    "application/xml".into(),
                    "text/css".into(),
                    "application/javascript".into(),
                ]
            });

        let max_body_bytes = cfg
            .get("max_body_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(5 * 1024 * 1024) as usize;

        if rules.is_empty() {
            return Err(GatewayError::BadRequest(
                "response-rewriter: at least one rule is required".into(),
            ));
        }

        Ok(Self {
            rules,
            content_types,
            max_body_bytes,
        })
    }

    fn is_rewritable_content_type(&self, headers: &axum::http::HeaderMap) -> bool {
        let ct = match headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            Some(s) => s,
            None => return false,
        };
        self.content_types
            .iter()
            .any(|allowed| ct.starts_with(allowed.as_str()))
    }
}

#[async_trait]
impl Plugin for ResponseRewriterPlugin {
    fn name(&self) -> &str {
        "response-rewriter"
    }

    async fn on_request(&self, _req: &mut Request<Body>) -> Result<(), PluginError> {
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        if !self.is_rewritable_content_type(resp.headers()) {
            return Ok(());
        }

        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return Ok(()),
        };

        if bytes.is_empty() || bytes.len() > self.max_body_bytes {
            *resp.body_mut() = Body::from(bytes);
            return Ok(());
        }

        let mut text = match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                *resp.body_mut() = Body::from(bytes);
                return Ok(());
            }
        };

        for rule in &self.rules {
            match &rule.pattern {
                RewritePattern::Regex(re) => {
                    text = re
                        .replace_all(&text, rule.replacement.as_str())
                        .into_owned();
                }
                RewritePattern::Literal(lit) => {
                    text = text.replace(lit, &rule.replacement);
                }
            }
        }

        let new_bytes = text.into_bytes();
        if let Ok(len) = HeaderValue::from_str(&new_bytes.len().to_string()) {
            resp.headers_mut()
                .insert(axum::http::header::CONTENT_LENGTH, len);
        }
        *resp.body_mut() = Body::from(new_bytes);
        Ok(())
    }
}

use axum::http::HeaderValue;
