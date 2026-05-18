//! Response cache for the LLM gateway.
//!
//! v1 is exact-match: the key is `sha256(model | temperature | messages)`,
//! computed over a canonical JSON encoding of the messages array (sorted
//! object keys, no whitespace) so semantically identical inputs hit. There
//! is no fuzzy or vector matching.
//!
//! TODO(v2): vector-similarity caching. Embed the user's last message,
//! ANN-search a small in-memory index of recent embeddings, return on cosine
//! >= threshold. The plumbing for emitting `cache=hit_semantic` metric labels
//! > is already in place; only the index needs to be added.
//!
//! The cache is keyed on a per-instance `DashMap` rather than the shared
//! global pattern in `proxy_cache.rs`. LLM responses can be large (tens of
//! KB) and have very different policy per route, so a per-plugin store is
//! the right scope. Eviction is lazy: on hit we check the entry's
//! `expires_at` and drop it if stale.

use dashmap::DashMap;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CacheEntry {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub expires_at: Instant,
}

pub struct ResponseCache {
    store: DashMap<String, CacheEntry>,
    ttl: Duration,
    enabled: bool,
    strategy: String,
    reusex_url: Option<String>,
    reusex_api_key: Option<String>,
    http: Client,
}

impl ResponseCache {
    pub fn new(
        enabled: bool,
        strategy: String,
        reusex_url: Option<String>,
        reusex_api_key: Option<String>,
        http: Client,
        ttl_seconds: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            store: DashMap::new(),
            ttl: Duration::from_secs(ttl_seconds.max(1)),
            enabled,
            strategy,
            reusex_url,
            reusex_api_key,
            http,
        })
    }

    /// Exact-match strategy only, no ReuseX / semantic backend — builds its own [`Client`].
    ///
    /// Prefer [`Self::new`] when strategy, ReuseX URL/key, or a shared HTTP client matter.
    pub fn new_exact(enabled: bool, ttl_seconds: u64) -> Arc<Self> {
        Self::new(
            enabled,
            "exact".to_string(),
            None,
            None,
            Client::new(),
            ttl_seconds,
        )
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Build the cache key for an OpenAI-shaped request.
    ///
    /// Inputs that affect the response include: model, temperature, top_p,
    /// max_tokens, response_format, tools, and messages. We hash all of them
    /// — under-keying would silently return wrong outputs.
    pub fn key(&self, model: &str, body: &Value) -> String {
        let temperature = body.get("temperature").cloned().unwrap_or(Value::Null);
        let top_p = body.get("top_p").cloned().unwrap_or(Value::Null);
        let max_tokens = body.get("max_tokens").cloned().unwrap_or(Value::Null);
        let response_format = body.get("response_format").cloned().unwrap_or(Value::Null);
        let tools = body.get("tools").cloned().unwrap_or(Value::Null);
        let messages = body.get("messages").cloned().unwrap_or(Value::Null);

        let canonical = serde_json::json!({
            "m": model,
            "t": temperature,
            "p": top_p,
            "n": max_tokens,
            "r": response_format,
            "x": tools,
            "msgs": messages,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("{:x}", h.finalize())
    }

    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        if !self.enabled {
            return None;
        }
        let now = Instant::now();
        let entry = self.store.get(key)?;
        if entry.expires_at > now {
            Some(entry.clone())
        } else {
            // Lazy eviction: dropping the read guard before write isn't
            // strictly required by DashMap, but keeps the call site obviously
            // correct against future API changes.
            drop(entry);
            self.store.remove(key);
            None
        }
    }

    pub async fn get_semantic(&self, model: &str, body: &Value) -> Option<CacheEntry> {
        if !self.enabled || self.strategy != "semantic" {
            return None;
        }
        let url = self.reusex_url.as_ref()?;
        let messages = body.get("messages")?;
        let prompt = messages.as_array()?.last()?.get("content")?.as_str()?;

        let lookup_url = format!("{}/v1/cache/lookup", url.trim_end_matches("/"));
        let req_body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "similarityThreshold": 0.9,
        });

        let mut req = self.http.post(&lookup_url).json(&req_body);
        if let Some(key) = &self.reusex_api_key {
            req = req.header("authorization", format!("Bearer {}", key));
        }

        let resp = req.send().await.ok()?;
        if resp.status() == 200 {
            let data: Value = resp.json().await.ok()?;
            if data["hit"].as_bool().unwrap_or(false) {
                let payload = data["payload"].clone();
                return Some(CacheEntry {
                    status: 200,
                    headers: vec![("x-lynxx-llm-cache".into(), "hit_semantic".into())],
                    body: serde_json::to_vec(&payload).unwrap_or_default(),
                    expires_at: Instant::now() + self.ttl,
                });
            }
        }
        None
    }

    pub async fn put_semantic(&self, model: &str, body: &Value, response_body: &[u8]) {
        if !self.enabled || self.strategy != "semantic" {
            return;
        }
        let url = self.reusex_url.as_ref().unwrap();
        let messages = body.get("messages").unwrap();
        let prompt = messages
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .get("content")
            .unwrap()
            .as_str()
            .unwrap();

        let store_url = format!("{}/v1/cache/store", url.trim_end_matches("/"));
        let payload: Value = serde_json::from_slice(response_body).unwrap_or(Value::Null);
        let req_body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "payload": payload,
            "ttlSeconds": self.ttl.as_secs(),
        });

        let mut req = self.http.post(&store_url).json(&req_body);
        if let Some(key) = &self.reusex_api_key {
            req = req.header("authorization", format!("Bearer {}", key));
        }
        let _ = req.send().await;
    }

    pub fn put(&self, key: String, status: u16, headers: Vec<(String, String)>, body: Vec<u8>) {
        if !self.enabled {
            return;
        }
        // Skip non-2xx — caching errors would be a footgun.
        if !(200..300).contains(&status) {
            return;
        }
        self.store.insert(
            key,
            CacheEntry {
                status,
                headers,
                body,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_stable_for_equal_inputs() {
        let c = ResponseCache::new_exact(true, 60);
        let body = serde_json::json!({
            "messages": [{"role":"user","content":"hi"}],
            "temperature": 0.5,
        });
        assert_eq!(c.key("gpt-4o", &body), c.key("gpt-4o", &body));
    }

    #[test]
    fn keys_differ_on_temperature() {
        let c = ResponseCache::new_exact(true, 60);
        let a = serde_json::json!({"messages":[],"temperature":0.0});
        let b = serde_json::json!({"messages":[],"temperature":0.7});
        assert_ne!(c.key("gpt-4o", &a), c.key("gpt-4o", &b));
    }

    #[test]
    fn put_and_get_roundtrip() {
        let c = ResponseCache::new_exact(true, 60);
        c.put("k".into(), 200, vec![], b"hello".to_vec());
        let got = c.get("k").expect("hit");
        assert_eq!(got.body, b"hello");
    }

    #[test]
    fn disabled_never_hits() {
        let c = ResponseCache::new_exact(false, 60);
        c.put("k".into(), 200, vec![], b"hello".to_vec());
        assert!(c.get("k").is_none());
    }
}
