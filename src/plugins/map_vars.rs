//! Map / variable plugin — general-purpose variable mapping and
//! conditional variable resolution in request headers.
//!
//! ## Config
//!
//! ```json
//! {
//!   "mappings": {
//!     "X-Backend": {
//!       "source": "header:X-Api-Version",
//!       "map": {
//!         "v1": "legacy-backend",
//!         "v2": "new-backend"
//!       },
//!       "default": "new-backend"
//!     }
//!   },
//!   "vars": {
//!     "X-Request-Start": "{now_ms}",
//!     "X-Gateway": "lynxx"
//!   }
//! }
//! ```
//!
//! `mappings`: for each output header, look up a source value (from a
//! header, query param, or path segment) in the `map` table and set the
//! output header to the mapped value.
//!
//! `vars`: set static or templated header values on every request.
//! Supports `{now_ms}`, `{now_iso}`, `{method}`, `{path}`, `{host}`.

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use axum::body::Body;
use axum::http::{Request, Response};
use std::collections::HashMap;

pub struct MapVarsPlugin {
    mappings: Vec<Mapping>,
    vars: Vec<(String, String)>,
}

struct Mapping {
    output_header: String,
    source: MappingSource,
    map: HashMap<String, String>,
    default: String,
}

enum MappingSource {
    Header(String),
    Query(String),
}

impl MapVarsPlugin {
    pub fn from_config(config: &serde_json::Value) -> Result<Self, GatewayError> {
        let mut mappings = Vec::new();

        if let Some(m) = config["mappings"].as_object() {
            for (output_header, def) in m {
                let source_str = def["source"].as_str().unwrap_or("header:X-Api-Version");
                let source = if let Some(h) = source_str.strip_prefix("header:") {
                    MappingSource::Header(h.to_string())
                } else if let Some(q) = source_str.strip_prefix("query:") {
                    MappingSource::Query(q.to_string())
                } else {
                    MappingSource::Header(source_str.to_string())
                };

                let map: HashMap<String, String> = def["map"]
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                let default = def["default"].as_str().unwrap_or("").to_string();

                mappings.push(Mapping {
                    output_header: output_header.clone(),
                    source,
                    map,
                    default,
                });
            }
        }

        let mut vars = Vec::new();
        if let Some(v) = config["vars"].as_object() {
            for (header, value) in v {
                if let Some(val) = value.as_str() {
                    vars.push((header.clone(), val.to_string()));
                }
            }
        }

        Ok(Self { mappings, vars })
    }
}

#[async_trait::async_trait]
impl Plugin for MapVarsPlugin {
    fn name(&self) -> &'static str {
        "map-vars"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        // Apply mappings.
        for mapping in &self.mappings {
            let source_value = match &mapping.source {
                MappingSource::Header(h) => req
                    .headers()
                    .get(h.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                MappingSource::Query(q) => req.uri().query().and_then(|qs| {
                    qs.split('&')
                        .filter_map(|p| p.split_once('='))
                        .find(|(k, _)| *k == q.as_str())
                        .map(|(_, v)| v.to_string())
                }),
            };

            let resolved = source_value
                .as_deref()
                .and_then(|v| mapping.map.get(v))
                .unwrap_or(&mapping.default);

            if !resolved.is_empty() {
                if let (Ok(n), Ok(v)) = (
                    axum::http::header::HeaderName::from_bytes(mapping.output_header.as_bytes()),
                    axum::http::header::HeaderValue::from_str(resolved),
                ) {
                    req.headers_mut().insert(n, v);
                }
            }
        }

        // Apply static vars with template expansion.
        let now = chrono::Utc::now();
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost")
            .to_string();

        for (header, template) in &self.vars {
            let value = template
                .replace("{now_ms}", &now.timestamp_millis().to_string())
                .replace("{now_iso}", &now.to_rfc3339())
                .replace("{method}", &method)
                .replace("{path}", &path)
                .replace("{host}", &host);

            if let (Ok(n), Ok(v)) = (
                axum::http::header::HeaderName::from_bytes(header.as_bytes()),
                axum::http::header::HeaderValue::from_str(&value),
            ) {
                req.headers_mut().insert(n, v);
            }
        }

        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let cfg = serde_json::json!({
            "mappings": {
                "X-Backend": {
                    "source": "header:X-Version",
                    "map": {"v1": "old", "v2": "new"},
                    "default": "new"
                }
            },
            "vars": {
                "X-Gateway": "lynxx"
            }
        });
        let plugin = MapVarsPlugin::from_config(&cfg).unwrap();
        assert_eq!(plugin.mappings.len(), 1);
        assert_eq!(plugin.vars.len(), 1);
    }
}
