//! `graphql-guard` — native GraphQL awareness for the gateway.
//!
//! Kong (and most generic API gateways) treat GraphQL as opaque HTTP — every
//! `POST /graphql` is the same to the proxy, so DoS-shaped queries (deep
//! nesting, hundreds of aliases, paginated joins) sail straight to the
//! upstream. This plugin parses the query, scores it, enforces per-field
//! limits, and supports Apollo APQ-style persisted queries.
//!
//! All checks run in `on_request`; `on_response` is a no-op. The plugin is
//! body-shape-detected, not path-pinned: any `application/json` POST whose
//! body has a `query` string or an `extensions.persistedQuery.sha256Hash` is
//! treated as a GraphQL request. Everything else passes through.
//!
//! # v1 limitations
//!
//! - Fragment-aware complexity scoring isn't implemented (named fragment
//!   spreads are charged the default field cost; their definitions are not
//!   recursively walked). Inline fragments are walked normally.
//! - GraphQL Federation `@key` / `_entities` queries pass through but don't
//!   get special complexity treatment.
//! - Per-field rate limits are local to the gateway process. Use the
//!   `redis-rate-limit` plugin pattern (clustered v2 work) for cross-node
//!   buckets.

pub mod buckets;
pub mod config;
pub mod error;
pub mod parse;

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, Response};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;

use buckets::FieldBuckets;
use config::GraphqlGuardConfig;
use error::short_circuit;

/// 4 MiB cap on the request body we'll fully buffer for parsing. Generous
/// for any real GraphQL document — Apollo's recommended max document size
/// is ~100KB.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

pub struct GraphqlGuardPlugin {
    cfg: GraphqlGuardConfig,
    buckets: Arc<FieldBuckets>,
}

impl GraphqlGuardPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let parsed: GraphqlGuardConfig = serde_json::from_value(cfg.clone())
            .map_err(|e| GatewayError::BadRequest(format!("graphql-guard config: {e}")))?;
        Ok(Self {
            cfg: parsed,
            buckets: Arc::new(FieldBuckets::new()),
        })
    }
}

/// Body shape recognised as a GraphQL request: either a plain `query` string
/// or an APQ-style `extensions.persistedQuery.sha256Hash`. Both query and
/// hash being absent -> not GraphQL, return None.
fn classify(body: &Value) -> Option<GraphqlBody> {
    let obj = body.as_object()?;
    let query = obj
        .get("query")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let operation_name = obj
        .get("operationName")
        .and_then(|v| v.as_str())
        .map(String::from);
    let persisted_hash = obj
        .get("extensions")
        .and_then(|v| v.get("persistedQuery"))
        .and_then(|v| v.get("sha256Hash"))
        .and_then(|v| v.as_str())
        .map(String::from);
    if query.is_none() && persisted_hash.is_none() {
        return None;
    }
    Some(GraphqlBody {
        query,
        operation_name,
        persisted_hash,
    })
}

#[derive(Debug)]
struct GraphqlBody {
    query: Option<String>,
    operation_name: Option<String>,
    persisted_hash: Option<String>,
}

#[async_trait]
impl Plugin for GraphqlGuardPlugin {
    fn name(&self) -> &str {
        "graphql-guard"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        // Cheap pre-filter: GraphQL-over-HTTP is nearly always JSON. Skip if
        // not. We don't restrict by method (POST only is convention but
        // Apollo permits GET-with-query for cacheable reads); the body-shape
        // check below is the real gate.
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        let is_json = ct
            .as_deref()
            .map(|s| s.split(';').next().unwrap_or("").trim() == "application/json")
            .unwrap_or(false);
        if !is_json {
            return Ok(());
        }

        // Drain the body. We will restore it before returning success.
        let body = std::mem::replace(req.body_mut(), Body::empty());
        let bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("graphql-guard body: {e}")))?
            .to_bytes();
        if bytes.len() > MAX_BODY_BYTES {
            return Err(PluginError::PayloadTooLarge(format!(
                "graphql-guard: request body exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        if bytes.is_empty() {
            *req.body_mut() = Body::from(bytes);
            return Ok(());
        }

        let mut json: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                // Not JSON — restore and pass through. The upstream may
                // accept some other shape (multipart graphql-upload, etc).
                *req.body_mut() = Body::from(bytes);
                return Ok(());
            }
        };

        let parsed = match classify(&json) {
            Some(p) => p,
            None => {
                *req.body_mut() = Body::from(bytes);
                return Ok(());
            }
        };

        // -- Persisted query resolution --------------------------------
        let mut persisted_used = false;
        let mut effective_query: String = match (&parsed.query, &parsed.persisted_hash) {
            (Some(q), _) => {
                if self.cfg.persisted_queries_only {
                    metric_block("PERSISTED_QUERY_NOT_REGISTERED", "");
                    return Err(short_circuit(
                        400,
                        "PersistedQueryNotRegistered",
                        "PERSISTED_QUERY_NOT_REGISTERED",
                        None,
                        vec![],
                    ));
                }
                q.clone()
            }
            (None, Some(hash)) => {
                if let Some(stored) = self.cfg.persisted_queries.get(hash) {
                    persisted_used = true;
                    stored.clone()
                } else if self.cfg.persisted_queries_only {
                    metric_block("PERSISTED_QUERY_NOT_FOUND", "");
                    return Err(short_circuit(
                        400,
                        "PersistedQueryNotFound",
                        "PERSISTED_QUERY_NOT_FOUND",
                        None,
                        vec![],
                    ));
                } else {
                    // SECURITY: we have only a hash, not the query text, so we
                    // cannot run any depth/complexity/guard checks. Passing the
                    // unknown hash straight through let a client bypass the
                    // entire guard via APQ. Instead return the standard APQ
                    // `PersistedQueryNotFound` so the client re-sends the FULL
                    // query — which then flows through the analyser below.
                    metric_block("PERSISTED_QUERY_NOT_FOUND", "");
                    return Err(short_circuit(
                        400,
                        "PersistedQueryNotFound",
                        "PERSISTED_QUERY_NOT_FOUND",
                        None,
                        vec![],
                    ));
                }
            }
            (None, None) => unreachable!("classify guarantees at least one"),
        };

        // -- Parse + analyse ------------------------------------------
        let summary = match parse::analyze(
            &effective_query,
            &self.cfg,
            parsed.operation_name.as_deref(),
        ) {
            Ok(s) => s,
            Err(msg) => {
                metric_block("GRAPHQL_PARSE_FAILED", "");
                return Err(short_circuit(
                    400,
                    &format!("GraphQL parse error: {msg}"),
                    "GRAPHQL_PARSE_FAILED",
                    None,
                    vec![],
                ));
            }
        };

        // -- Operation name required ----------------------------------
        if self.cfg.operation_name_required && summary.operation_name.is_none() {
            metric_block("OPERATION_NAME_REQUIRED", summary.operation_type);
            return Err(short_circuit(
                400,
                "operationName is required",
                "OPERATION_NAME_REQUIRED",
                None,
                vec![],
            ));
        }

        // -- Block mutations for anonymous ----------------------------
        let consumer = req
            .headers()
            .get("x-consumer-username")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let is_anon = matches!(consumer.as_deref(), None | Some("anonymous") | Some(""));
        if self.cfg.block_mutations_for_anonymous && summary.operation_type == "mutation" && is_anon
        {
            metric_block("ANONYMOUS_MUTATIONS_BLOCKED", "mutation");
            return Err(short_circuit(
                401,
                "anonymous mutations are blocked",
                "ANONYMOUS_MUTATIONS_BLOCKED",
                None,
                vec![],
            ));
        }

        // -- Introspection block --------------------------------------
        if self.cfg.production_mode
            && self.cfg.introspection_disabled_in_production
            && (summary.root_field_names.contains("__schema")
                || summary.root_field_names.contains("__type"))
        {
            metric_block("INTROSPECTION_DISABLED", summary.operation_type);
            return Err(short_circuit(
                403,
                "introspection is disabled in production",
                "INTROSPECTION_DISABLED",
                None,
                vec![],
            ));
        }

        // -- Depth check ----------------------------------------------
        if summary.depth > self.cfg.max_depth {
            metric_block("QUERY_TOO_DEEP", summary.operation_type);
            return Err(short_circuit(
                400,
                &format!(
                    "query depth {} exceeds limit {}",
                    summary.depth, self.cfg.max_depth
                ),
                "QUERY_TOO_DEEP",
                Some(serde_json::json!({
                    "depth": summary.depth,
                    "max_depth": self.cfg.max_depth,
                })),
                vec![],
            ));
        }

        // -- Alias count ----------------------------------------------
        if summary.aliases > self.cfg.max_aliases {
            metric_block("TOO_MANY_ALIASES", summary.operation_type);
            return Err(short_circuit(
                400,
                &format!(
                    "alias count {} exceeds limit {}",
                    summary.aliases, self.cfg.max_aliases
                ),
                "TOO_MANY_ALIASES",
                Some(serde_json::json!({
                    "aliases": summary.aliases,
                    "max_aliases": self.cfg.max_aliases,
                })),
                vec![],
            ));
        }

        // -- Complexity score -----------------------------------------
        if summary.complexity > self.cfg.max_complexity {
            metric_block("QUERY_TOO_COMPLEX", summary.operation_type);
            return Err(short_circuit(
                400,
                &format!(
                    "query complexity {} exceeds limit {}",
                    summary.complexity, self.cfg.max_complexity
                ),
                "QUERY_TOO_COMPLEX",
                Some(serde_json::json!({
                    "complexity": summary.complexity,
                    "max_complexity": self.cfg.max_complexity,
                })),
                vec![],
            ));
        }

        // -- Per-field rate limits ------------------------------------
        for rl in &self.cfg.field_rate_limits {
            if !summary.all_field_names.contains(&rl.field) {
                continue;
            }
            let key = match rl.key_strategy.as_str() {
                "ip" => req
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(',').next())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".into()),
                "global" => rl.field.clone(),
                _ => consumer.clone().unwrap_or_else(|| "anonymous".into()),
            };
            if !self
                .buckets
                .try_consume(&rl.field, &key, rl.requests_per_second)
            {
                metric_block("FIELD_RATE_LIMIT", summary.operation_type);
                return Err(short_circuit(
                    429,
                    &format!("rate limit exceeded for field {}", rl.field),
                    "FIELD_RATE_LIMIT",
                    Some(serde_json::json!({
                        "field": rl.field,
                        "key_strategy": rl.key_strategy,
                    })),
                    vec![("retry-after".into(), "1".into())],
                ));
            }
        }

        // -- Rewrite body if we substituted a persisted query ---------
        let outbound_bytes = if persisted_used {
            // Replace the body's `extensions.persistedQuery` with `query`.
            if let Some(obj) = json.as_object_mut() {
                obj.remove("extensions");
                obj.insert(
                    "query".to_string(),
                    Value::String(std::mem::take(&mut effective_query)),
                );
            }
            serde_json::to_vec(&json)
                .map_err(|e| PluginError::Internal(format!("graphql-guard rewrite: {e}")))?
        } else {
            bytes.to_vec()
        };

        // -- Inject metadata headers ----------------------------------
        let headers = req.headers_mut();
        if let Some(name) = &summary.operation_name {
            insert_header(headers, "x-lynxx-graphql-operation", name);
        }
        insert_header(
            headers,
            "x-lynxx-graphql-operation-type",
            summary.operation_type,
        );
        insert_header(
            headers,
            "x-lynxx-graphql-complexity",
            &summary.complexity.to_string(),
        );
        insert_header(headers, "x-lynxx-graphql-depth", &summary.depth.to_string());
        insert_header(
            headers,
            "x-lynxx-graphql-persisted",
            if persisted_used { "true" } else { "false" },
        );
        // Update content-length so the upstream gets the right framing if
        // we rewrote the body. axum/hyper will redo this when streaming, but
        // some downstream plugins read `content-length` directly.
        insert_header(headers, "content-length", &outbound_bytes.len().to_string());

        // -- Metrics --------------------------------------------------
        metrics::counter!(
            "lynxx_graphql_requests_total",
            "operation_type" => summary.operation_type,
            "persisted" => if persisted_used { "true" } else { "false" },
            "blocked_reason" => "",
        )
        .increment(1);
        metrics::histogram!("lynxx_graphql_complexity").record(summary.complexity as f64);
        metrics::histogram!("lynxx_graphql_depth").record(summary.depth as f64);

        *req.body_mut() = Body::from(outbound_bytes);
        Ok(())
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

fn insert_header(map: &mut axum::http::HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) {
        map.insert(n, v);
    }
}

fn metric_block(reason: &'static str, op_type: &str) {
    metrics::counter!(
        "lynxx_graphql_requests_total",
        "operation_type" => op_type.to_string(),
        "persisted" => "false",
        "blocked_reason" => reason,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(cfg: serde_json::Value) -> GraphqlGuardPlugin {
        GraphqlGuardPlugin::from_config(&cfg).expect("config builds")
    }

    #[test]
    fn empty_config_accepted() {
        let p = build(serde_json::json!({}));
        assert_eq!(p.name(), "graphql-guard");
    }

    #[test]
    fn classify_recognises_query() {
        let v = serde_json::json!({"query": "{ a }"});
        assert!(classify(&v).is_some());
    }

    #[test]
    fn classify_recognises_persisted() {
        let v = serde_json::json!({
            "extensions": {"persistedQuery": {"sha256Hash": "abc"}}
        });
        assert!(classify(&v).is_some());
    }

    #[test]
    fn classify_rejects_plain_json() {
        let v = serde_json::json!({"foo": "bar"});
        assert!(classify(&v).is_none());
    }
}
