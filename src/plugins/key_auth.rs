use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::HeaderValue;
use axum::http::{Request, Response};
use std::sync::Arc;

/// API-key authentication. The key is checked against the `api_key` of every
/// consumer in the DB. On match the consumer identity is forwarded as
/// `X-Consumer-Username` / `X-Consumer-Id`.
pub struct KeyAuthPlugin {
    repo: Option<Arc<dyn Repository>>,
    key_names: Vec<String>,
    key_in_header: bool,
    key_in_query: bool,
    hide_credentials: bool,
}

impl KeyAuthPlugin {
    pub fn from_config(
        cfg: &serde_json::Value,
        repo: Option<Arc<dyn Repository>>,
    ) -> Result<Self, GatewayError> {
        let key_names = cfg
            .get("key_names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["apikey".into(), "X-API-Key".into()]);

        Ok(Self {
            repo,
            key_names,
            key_in_header: cfg
                .get("key_in_header")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            key_in_query: cfg
                .get("key_in_query")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            hide_credentials: cfg
                .get("hide_credentials")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
    }

    fn extract_key(&self, req: &Request<axum::body::Body>) -> Option<(String, KeySource)> {
        if self.key_in_header {
            for name in &self.key_names {
                if let Some(v) = req.headers().get(name).and_then(|v| v.to_str().ok()) {
                    return Some((v.to_string(), KeySource::Header(name.clone())));
                }
            }
        }
        if self.key_in_query {
            if let Some(q) = req.uri().query() {
                for pair in q.split('&') {
                    let Some((k, v)) = pair.split_once('=') else {
                        continue;
                    };
                    if self.key_names.iter().any(|n| n.eq_ignore_ascii_case(k)) {
                        return Some((v.to_string(), KeySource::Query));
                    }
                }
            }
        }
        None
    }
}

enum KeySource {
    Header(String),
    Query,
}

#[async_trait]
impl Plugin for KeyAuthPlugin {
    fn name(&self) -> &str {
        "key-auth"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let (key, source) = self
            .extract_key(req)
            .ok_or_else(|| PluginError::Unauthorized("missing api key".into()))?;

        let repo = self
            .repo
            .as_ref()
            .ok_or_else(|| PluginError::Internal("key-auth: no repository".into()))?;
        // Indexed lookup via the shared short-TTL consumer cache — avoids
        // fetching and linear-scanning the whole consumers table per request.
        let consumer = crate::plugins::consumer_cache::by_api_key(repo, &key)
            .await
            .map_err(|e| PluginError::Internal(format!("consumer lookup: {e}")))?
            .ok_or_else(|| PluginError::Unauthorized("invalid api key".into()))?;

        if let Ok(v) = HeaderValue::from_str(&consumer.username) {
            req.headers_mut().insert("x-consumer-username", v);
        }
        if let Ok(v) = HeaderValue::from_str(&consumer.id.to_string()) {
            req.headers_mut().insert("x-consumer-id", v);
        }

        if self.hide_credentials {
            match source {
                KeySource::Header(name) => {
                    req.headers_mut().remove(name.as_str());
                }
                KeySource::Query => {
                    // Strip the matching key from the query string.
                    if let Some(q) = req.uri().query() {
                        let filtered = q
                            .split('&')
                            .filter(|pair| {
                                let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
                                !self.key_names.iter().any(|n| n.eq_ignore_ascii_case(k))
                            })
                            .collect::<Vec<_>>()
                            .join("&");
                        let path = req.uri().path().to_string();
                        let new_path_and_query = if filtered.is_empty() {
                            path
                        } else {
                            format!("{path}?{filtered}")
                        };
                        let mut parts = req.uri().clone().into_parts();
                        if let Ok(pq) =
                            axum::http::uri::PathAndQuery::from_maybe_shared(new_path_and_query)
                        {
                            parts.path_and_query = Some(pq);
                            if let Ok(uri) = axum::http::Uri::from_parts(parts) {
                                *req.uri_mut() = uri;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
