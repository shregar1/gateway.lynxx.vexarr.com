//! `llm-gateway` — native multi-provider LLM dispatcher.
//!
//! This is the headline plugin in Lynxx: a single hop that turns the proxy
//! into a smart gateway in front of OpenAI, Anthropic, and self-hosted LLM
//! APIs. It bundles seven capabilities behind one config:
//!
//! 1. **Provider routing** — pick an upstream by model id,
//! 2. **Token counting** — `tiktoken` for OpenAI, `len/4` estimate elsewhere,
//! 3. **Exact-match cache** — sha256 over a canonical request payload,
//! 4. **Prompt-injection guard** — configurable regex blocklist,
//! 5. **PII redaction** — email / SSN / phone / credit card / IP,
//! 6. **Per-consumer token & request rate limits** — rolling 60s buckets,
//! 7. **Multi-provider fallback** — 429/5xx walks the chain,
//! 8. **Cost tracking** — Prometheus `lynxx_llm_*` counters per consumer.
//! 9. **Hedging** — parallel dispatch to multiple providers for p99 latency reduction.
//!
//! Architecturally the plugin is a *short-circuiting* plugin (like
//! `aws-lambda`): on a request to a recognised LLM path it makes the upstream
//! call itself and returns `PluginError::ShortCircuit` with the rendered
//! response. This keeps the proxy hot path untouched and lets the plugin own
//! end-to-end behaviour — fallback retries, cache writes, streaming consumption,
//! response decoration with `X-Lynxx-LLM-*` headers — without surgery on
//! `proxy/handler.rs`.
//!
//! The plugin is path-aware: only `/v1/chat/completions`, `/v1/completions`,
//! `/v1/messages`, and `/v1/embeddings` activate the LLM pipeline. Other paths
//! pass through as no-ops so a route can mix LLM and non-LLM upstreams without
//! the plugin getting in the way.

pub mod buckets;
pub mod cache;
pub mod config;
pub mod cost;
pub mod fallback;
pub mod guard;
pub mod router;
pub mod stream;
pub mod tokens;

#[cfg(test)]
mod integration_tests;

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use buckets::{Buckets, Decision, DenyReason};
use cache::ResponseCache;
use config::LlmGatewayConfig;
use cost::CostTable;
use guard::Guard;
use http_body_util::BodyExt;
use router::Router;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

const LLM_PATHS: [&str; 4] = [
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/v1/embeddings",
];

const H_CACHE: &str = "X-Lynxx-LLM-Cache";
const H_PROVIDER: &str = "X-Lynxx-LLM-Provider";
const H_TOKENS_IN: &str = "X-Lynxx-LLM-Tokens-In";
const H_TOKENS_OUT: &str = "X-Lynxx-LLM-Tokens-Out";
const H_COST: &str = "X-Lynxx-LLM-Cost";
const H_REDACTED: &str = "X-Lynxx-LLM-Redacted";
const H_FALLBACK: &str = "X-Lynxx-LLM-Fallback";

pub struct LlmGatewayPlugin {
    router: Router,
    cache: Arc<ResponseCache>,
    guard: Arc<Guard>,
    buckets: Arc<Buckets>,
    cost: CostTable,
    http: reqwest::Client,
    hedging: config::HedgingCfg,
}

impl LlmGatewayPlugin {
    fn short_circuit_with_entry(
        &self,
        entry: crate::plugins::llm_gateway::cache::CacheEntry,
    ) -> Result<Response<Body>, crate::error::GatewayError> {
        let mut headers = entry.headers;
        headers.push(("x-lynxx-llm-cache".into(), "hit_semantic".into()));
        Err(crate::error::GatewayError::PluginError(
            crate::error::PluginError::ShortCircuit {
                status: entry.status,
                headers,
                body: entry.body.into(),
            },
        ))
    }

    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let parsed: LlmGatewayConfig = serde_json::from_value(cfg.clone())
            .map_err(|e| GatewayError::BadRequest(format!("llm-gateway config: {e}")))?;
        let router = Router::build(&parsed).map_err(GatewayError::BadRequest)?;

        let cache = ResponseCache::new(
            parsed.cache.enabled,
            parsed.cache.strategy.clone(),
            parsed.cache.reusex_url.clone(),
            parsed.cache.reusex_api_key.clone(),
            reqwest::Client::new(),
            parsed.cache.ttl_seconds,
        );
        if parsed.cache.strategy != "exact" {
            tracing::warn!(
                strategy = %parsed.cache.strategy,
                "llm-gateway: cache strategy other than `exact` is reserved for v2; falling back to exact"
            );
        }

        let guard = Arc::new(Guard::build(
            parsed.guard.block_prompt_injection,
            &parsed.guard.injection_patterns,
            &parsed.guard.redact_pii,
        ));

        let buckets = Buckets::new(
            parsed.rate_limit.enabled,
            parsed.rate_limit.tokens_per_minute_per_consumer,
            parsed.rate_limit.requests_per_minute_per_consumer,
        );

        let cost = CostTable::new(
            parsed.cost_tracking.enabled,
            parsed.cost_tracking.model_costs,
        );

        let http = reqwest::Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| GatewayError::BadRequest(format!("llm-gateway http: {e}")))?;

        Ok(Self {
            router,
            cache,
            guard,
            buckets,
            cost,
            http,
            hedging: parsed.hedging,
        })
    }

    fn is_llm_path(path: &str) -> bool {
        LLM_PATHS.iter().any(|p| path.starts_with(p))
    }
}

#[async_trait]
impl Plugin for LlmGatewayPlugin {
    fn name(&self) -> &str {
        "llm-gateway"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let path = req.uri().path();
        if !Self::is_llm_path(path) {
            return Ok(());
        }

        let consumer = req
            .headers()
            .get("x-consumer-username")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("anonymous")
            .to_string();

        let path = path.to_string();

        // Drain body to parse JSON. v1 buffers up to 4MiB; larger payloads
        // (e.g. giant embedding batches) are rejected.
        let body = std::mem::replace(req.body_mut(), Body::empty());
        let collected = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("llm-gateway body: {e}")))?
            .to_bytes();
        if collected.len() > 4 * 1024 * 1024 {
            return Err(PluginError::PayloadTooLarge(
                "llm-gateway: request body exceeds 4 MiB".into(),
            ));
        }
        let mut json: Value = match serde_json::from_slice(&collected) {
            Ok(v) => v,
            Err(_) => {
                *req.body_mut() = Body::from(collected);
                return Ok(());
            }
        };

        let model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let messages_owned: Vec<Value> = json
            .get("messages")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let stream_requested = json
            .get("stream")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || req
                .headers()
                .get(axum::http::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("text/event-stream"))
                .unwrap_or(false);

        // -- Guard: prompt injection -----------------------------------
        if let Some(_pat) = self.guard.check_injection(&messages_owned) {
            metrics::counter!(
                "lynxx_llm_guard_total",
                "consumer" => consumer.clone(),
                "action" => "injection_blocked",
            )
            .increment(1);
            let body = serde_json::to_vec(&serde_json::json!({
                "error": {
                    "code": "prompt_injection_detected",
                    "message": "request blocked by llm-gateway prompt-injection guard"
                }
            }))
            .unwrap();
            return Err(PluginError::ShortCircuit {
                status: 400,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.into(),
            });
        }

        // -- Guard: PII redaction --------------------------------------
        let mut messages = messages_owned;
        let redacted = self.guard.redact_pii(&mut messages);
        if redacted > 0 {
            metrics::counter!(
                "lynxx_llm_guard_total",
                "consumer" => consumer.clone(),
                "action" => "pii_redacted",
            )
            .increment(redacted);
            if let Some(obj) = json.as_object_mut() {
                obj.insert("messages".to_string(), Value::Array(messages.clone()));
            }
        }

        // -- Token estimation for the rate limiter ---------------------
        let est_input = tokens::count_messages(&model, &messages) as u64;

        // -- Rate limit: per-consumer tokens + requests ----------------
        match self.buckets.check(&consumer, est_input) {
            Decision::Allow => {}
            Decision::Deny {
                reason,
                retry_after,
            } => {
                let code = match reason {
                    DenyReason::Tokens => "token_rate_limit_exceeded",
                    DenyReason::Requests => "request_rate_limit_exceeded",
                };
                let body = serde_json::to_vec(&serde_json::json!({
                    "error": { "code": code, "retry_after": retry_after }
                }))
                .unwrap();
                return Err(PluginError::ShortCircuit {
                    status: 429,
                    headers: vec![
                        ("Content-Type".into(), "application/json".into()),
                        ("Retry-After".into(), retry_after.to_string()),
                    ],
                    body: body.into(),
                });
            }
        }

        // -- Provider pick + dispatch chain ----------------------------
        let primary_p = self.router.pick(&model);
        let primary = primary_p.name.clone();
        let dispatch_chain = self.router.dispatch_order(&primary);

        // -- Cache lookup ----------------------------------------------
        let cache_key = self.cache.key(&model, &json);
        if !stream_requested {
            if let Some(hit) = self.cache.get(&cache_key) {
                metrics::counter!(
                    "lynxx_llm_cache_total",
                    "consumer" => consumer.clone(),
                    "result" => "hit",
                )
                .increment(1);
                let mut headers = hit.headers.clone();
                headers.push((H_CACHE.into(), "HIT".into()));
                headers.push((H_PROVIDER.into(), primary.clone()));
                if redacted > 0 {
                    headers.push((H_REDACTED.into(), redacted.to_string()));
                }
                return Err(PluginError::ShortCircuit {
                    status: hit.status,
                    headers,
                    body: hit.body.into(),
                });
            }
            metrics::counter!(
                "lynxx_llm_cache_total",
                "consumer" => consumer.clone(),
                "result" => "miss",
            )
            .increment(1);
        }

        // Re-serialize the (possibly PII-redacted) body for the upstream.
        let outbound = serde_json::to_vec(&json)
            .map_err(|e| PluginError::Internal(format!("llm-gateway encode: {e}")))?;

        // Snapshot client headers (we'll filter inside `dispatch`).
        let forwarded_headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();

        // -- Dispatch with fallback / hedging --------------------------
        let consumer_for_metric = consumer.clone();

        let dispatch_result = if self.hedging.enabled {
            // Resolve providers for hedging.
            let mut hedge_list = Vec::new();
            if self.hedging.hedge_providers.is_empty() {
                // Default: primary + first fallback.
                hedge_list.push(primary_p.clone());
                if dispatch_chain.len() > 1 {
                    hedge_list.push(dispatch_chain[1].clone());
                }
            } else {
                for name in &self.hedging.hedge_providers {
                    if let Some(p) = self.router.get_provider(name) {
                        hedge_list.push(p);
                    }
                }
            }

            fallback::dispatch_hedged(
                &self.http,
                &hedge_list,
                &path,
                &reqwest::Method::POST,
                &forwarded_headers,
                &outbound,
            )
            .await
            .map_err(PluginError::Internal)?
        } else {
            fallback::dispatch(
                &self.http,
                &dispatch_chain,
                &path,
                &reqwest::Method::POST,
                &forwarded_headers,
                &outbound,
                |from, to| {
                    metrics::counter!(
                        "lynxx_llm_provider_fallback_total",
                        "from_provider" => from.to_string(),
                        "to_provider" => to.to_string(),
                    )
                    .increment(1);
                },
            )
            .await
            .map_err(PluginError::Internal)?
        };

        // -- Streaming vs Buffered Handling ----------------------------
        let content_type = dispatch_result
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str());

        if stream_requested && stream::is_event_stream(content_type) {
            // INCREMENTAL STREAMING
            let stream = stream::TokenCountingStream::new(
                dispatch_result.response.bytes_stream(),
                model.clone(),
                consumer.clone(),
                self.buckets.clone(),
                est_input,
            );

            let mut headers = dispatch_result.headers.clone();
            headers.push((H_PROVIDER.into(), dispatch_result.provider.clone()));
            headers.push((H_CACHE.into(), "MISS".into()));
            headers.push((
                H_FALLBACK.into(),
                dispatch_result.fallback_count.to_string(),
            ));

            return Err(PluginError::ShortCircuit {
                status: dispatch_result.status,
                headers,
                body: Body::from_stream(stream).into(),
            });
        }

        // BUFFERED HANDLING (non-stream or cacheable)
        let result_body = dispatch_result
            .response
            .bytes()
            .await
            .map_err(|e| PluginError::Internal(format!("llm-gateway read body: {e}")))?
            .to_vec();

        // -- Token / cost accounting -----------------------------------
        let (input_tokens, output_tokens) = {
            let parsed: Value = serde_json::from_slice(&result_body).unwrap_or(Value::Null);
            match tokens::extract_usage(&parsed) {
                Some(u) => u,
                None => {
                    let mut out = 0u64;
                    if let Some(choices) = parsed.get("choices").and_then(|c| c.as_array()) {
                        for c in choices {
                            if let Some(t) = c.pointer("/message/content").and_then(|v| v.as_str())
                            {
                                out += tokens::count_text(&model, t) as u64;
                            }
                        }
                    }
                    if let Some(content) = parsed.get("content").and_then(|c| c.as_array()) {
                        for c in content {
                            if let Some(t) = c.get("text").and_then(|v| v.as_str()) {
                                out += tokens::count_text(&model, t) as u64;
                            }
                        }
                    }
                    (est_input, out)
                }
            }
        };

        let extra = input_tokens.saturating_sub(est_input) + output_tokens;
        self.buckets.deduct(&consumer_for_metric, extra);

        // -- Metrics ---------------------------------------------------
        let provider_label = dispatch_result.provider.clone();
        let model_label = model.clone();
        metrics::counter!(
            "lynxx_llm_input_tokens_total",
            "consumer" => consumer_for_metric.clone(),
            "model" => model_label.clone(),
            "provider" => provider_label.clone(),
        )
        .increment(input_tokens);
        metrics::counter!(
            "lynxx_llm_output_tokens_total",
            "consumer" => consumer_for_metric.clone(),
            "model" => model_label.clone(),
            "provider" => provider_label.clone(),
        )
        .increment(output_tokens);
        let dollars = self.cost.dollars(&model, input_tokens, output_tokens);
        if self.cost.enabled() {
            let micro = (dollars * 1_000_000.0).round() as u64;
            metrics::counter!(
                "lynxx_llm_cost_dollars_total",
                "consumer" => consumer_for_metric,
                "model" => model_label,
                "provider" => provider_label,
            )
            .increment(micro);
        }

        // -- Build the short-circuit response --------------------------
        let mut headers = dispatch_result.headers.clone();
        headers.push((H_PROVIDER.into(), dispatch_result.provider.clone()));
        headers.push((H_CACHE.into(), "MISS".into()));
        headers.push((
            H_FALLBACK.into(),
            dispatch_result.fallback_count.to_string(),
        ));
        headers.push((H_TOKENS_IN.into(), input_tokens.to_string()));
        headers.push((H_TOKENS_OUT.into(), output_tokens.to_string()));
        if self.cost.enabled() {
            headers.push((H_COST.into(), format!("{dollars:.6}")));
        }
        if redacted > 0 {
            headers.push((H_REDACTED.into(), redacted.to_string()));
        }

        if !stream_requested {
            self.cache.put(
                cache_key,
                dispatch_result.status,
                dispatch_result.headers.clone(),
                result_body.clone(),
            );
        }

        Err(PluginError::ShortCircuit {
            status: dispatch_result.status,
            headers,
            body: result_body.into(),
        })
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(cfg: serde_json::Value) -> LlmGatewayPlugin {
        LlmGatewayPlugin::from_config(&cfg).expect("config builds")
    }

    #[test]
    fn config_with_minimum_fields() {
        let p = build(serde_json::json!({
            "providers": [{"name":"openai","base_url":"https://api.openai.com/v1"}]
        }));
        assert_eq!(p.name(), "llm-gateway");
    }

    #[test]
    fn rejects_no_providers() {
        let err = LlmGatewayPlugin::from_config(&serde_json::json!({"providers":[]})).err();
        assert!(err.is_some());
    }

    #[test]
    fn rejects_unknown_default_provider() {
        let err = LlmGatewayPlugin::from_config(&serde_json::json!({
            "providers":[{"name":"a","base_url":"http://x"}],
            "default_provider":"b"
        }))
        .err();
        assert!(err.is_some());
    }

    #[test]
    fn is_llm_path_recognises_endpoints() {
        assert!(LlmGatewayPlugin::is_llm_path("/v1/chat/completions"));
        assert!(LlmGatewayPlugin::is_llm_path("/v1/messages"));
        assert!(LlmGatewayPlugin::is_llm_path("/v1/embeddings"));
        assert!(!LlmGatewayPlugin::is_llm_path("/healthz"));
        assert!(!LlmGatewayPlugin::is_llm_path("/"));
    }
}
