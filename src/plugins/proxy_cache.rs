use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use dashmap::DashMap;
use http_body_util::BodyExt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct CacheEntry {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    expires_at: Instant,
}

type CacheMap = DashMap<String, CacheEntry>;

/// Process-global cache shared by all proxy-cache plugin instances. Keying
/// includes the configured strategy so multiple instances with different
/// strategies don't collide.
static CACHE: OnceLock<Arc<CacheMap>> = OnceLock::new();

fn cache() -> &'static Arc<CacheMap> {
    CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

/// Header used to forward the cache key from `on_request` to `on_response`
/// across the upstream call. The proxy handler copies this header onto the
/// response before running response-side plugins (see proxy/handler.rs).
pub const CACHE_KEY_HEADER: &str = "x-lynxx-proxy-cache-key";

#[derive(Clone, Copy)]
enum KeyStrategy {
    Uri,
    MethodPathQuery,
}

/// Default ceiling on cached entries. The cache is process-global, so without
/// a bound a stream of unique URLs would grow it until OOM.
const DEFAULT_MAX_ENTRIES: usize = 10_000;
/// Default per-response body ceiling; larger bodies are not cached.
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

pub struct ProxyCachePlugin {
    ttl: Duration,
    cache_methods: Vec<String>,
    cache_status: Vec<u16>,
    key_strategy: KeyStrategy,
    max_entries: usize,
    max_body_bytes: usize,
    cache: Arc<CacheMap>,
}

impl ProxyCachePlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let ttl = cfg
            .get("ttl_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(60);
        let cache_methods = cfg
            .get("cache_methods")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_uppercase()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["GET".into()]);
        let cache_status = cfg
            .get("cache_status")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u16))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![200]);
        let key_strategy = match cfg
            .get("cache_key_strategy")
            .and_then(|v| v.as_str())
            .unwrap_or("uri")
        {
            "method_path_query" => KeyStrategy::MethodPathQuery,
            _ => KeyStrategy::Uri,
        };

        let max_entries = cfg
            .get("max_entries")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_ENTRIES);
        let max_body_bytes = cfg
            .get("max_body_bytes")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);

        Ok(Self {
            ttl: Duration::from_secs(ttl),
            cache_methods,
            cache_status,
            key_strategy,
            max_entries,
            max_body_bytes,
            cache: cache().clone(),
        })
    }

    fn build_key(&self, req: &Request<Body>) -> String {
        match self.key_strategy {
            KeyStrategy::Uri => format!(
                "{}|{}",
                req.method(),
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
            ),
            KeyStrategy::MethodPathQuery => format!(
                "{}|{}|{}",
                req.method(),
                req.uri().path(),
                req.uri().query().unwrap_or("")
            ),
        }
    }

    fn method_cacheable(&self, method: &str) -> bool {
        self.cache_methods.iter().any(|m| m == method)
    }
}

#[async_trait]
impl Plugin for ProxyCachePlugin {
    fn name(&self) -> &str {
        "proxy-cache"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        if !self.method_cacheable(req.method().as_str()) {
            return Ok(());
        }
        let key = self.build_key(req);

        // Eviction: if entry exists but has expired, drop it before lookup.
        let now = Instant::now();
        let hit = self.cache.get(&key).and_then(|e| {
            if e.expires_at > now {
                Some(e.clone())
            } else {
                None
            }
        });
        if hit.is_none() {
            // Proactively remove a stale entry so it can't linger forever for
            // a key that is never re-requested with a fresh value.
            self.cache
                .remove_if(&key, |_, e| e.expires_at <= now);
        }

        if let Some(entry) = hit {
            let mut headers = entry.headers.clone();
            headers.push(("X-Cache".into(), "HIT".into()));
            return Err(PluginError::ShortCircuit {
                status: entry.status,
                headers,
                body: entry.body.into(),
            });
        }

        // Stash the key for `on_response` to pick up. The proxy handler
        // forwards this header onto the response before running the response
        // plugin chain.
        if let Ok(v) = axum::http::HeaderValue::from_str(&key) {
            req.headers_mut().insert(CACHE_KEY_HEADER, v);
        }
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let key = match resp
            .headers()
            .get(CACHE_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
        {
            Some(k) => k,
            // No key on the response means this method/path wasn't cacheable
            // (or another plugin stripped the header). Nothing to record.
            None => return Ok(()),
        };
        // The header was for our internal use only; don't leak it downstream.
        resp.headers_mut().remove(CACHE_KEY_HEADER);

        let status = resp.status().as_u16();
        if !self.cache_status.contains(&status) {
            return Ok(());
        }

        // Don't cache responses the upstream marked as private/no-store, or
        // anything that sets cookies.
        if let Some(cc) = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
        {
            let lc = cc.to_ascii_lowercase();
            if lc.contains("no-store") || lc.contains("private") {
                return Ok(());
            }
        }
        if resp.headers().contains_key("set-cookie") {
            return Ok(());
        }

        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();

        // Drain the body so we can both cache it and rebuild the response.
        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let collected = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("body collect: {e}")))?
            .to_bytes();
        let bytes_vec = collected.to_vec();

        // Don't cache oversized bodies.
        if bytes_vec.len() > self.max_body_bytes {
            *resp.body_mut() = Body::from(bytes_vec);
            resp.headers_mut()
                .insert("x-cache", axum::http::HeaderValue::from_static("MISS"));
            return Ok(());
        }

        // Bound the global cache. When at capacity, first sweep expired
        // entries; if still full of live entries, skip caching this one rather
        // than letting the map grow without limit.
        if self.cache.len() >= self.max_entries {
            let now = Instant::now();
            self.cache.retain(|_, e| e.expires_at > now);
            if self.cache.len() >= self.max_entries {
                tracing::debug!(
                    entries = self.cache.len(),
                    "proxy-cache at capacity; skipping insert"
                );
                *resp.body_mut() = Body::from(bytes_vec);
                resp.headers_mut()
                    .insert("x-cache", axum::http::HeaderValue::from_static("MISS"));
                return Ok(());
            }
        }

        self.cache.insert(
            key,
            CacheEntry {
                status,
                headers,
                body: bytes_vec.clone(),
                expires_at: Instant::now() + self.ttl,
            },
        );

        // Restore the body and add MISS marker.
        *resp.body_mut() = Body::from(bytes_vec);
        resp.headers_mut()
            .insert("x-cache", axum::http::HeaderValue::from_static("MISS"));
        Ok(())
    }
}
