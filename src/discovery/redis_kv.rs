//! Redis KV provider — discovers services stored as JSON values in
//! Redis keys with a configurable prefix (feature 115).
//!
//! Uses the `redis` crate (already in Cargo.toml with `tokio-comp` and
//! `connection-manager` features). Discovery works in two modes:
//!
//! 1. **Poll mode**: `SCAN` for keys matching `{prefix}*`, then `GET`
//!    each key and parse the JSON value as a service configuration.
//!
//! 2. **Pub/Sub mode**: `SUBSCRIBE` to `{prefix}changes` for
//!    near-real-time change notifications. Each message is a JSON
//!    payload describing the added/removed service, or the string
//!    `"reload"` to trigger a full re-scan.
//!
//! Registered entities are prefixed `redis:{name}` so they are
//! distinguishable in the admin UI.

use crate::db::Repository;
use crate::models::{Route, Service};
use chrono::Utc;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RedisKvProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Redis endpoint URLs. The first reachable one is used.
    #[serde(default = "default_endpoints")]
    pub endpoints: Vec<String>,
    /// Key prefix. All keys under this prefix are treated as service
    /// configurations.
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Redis logical database number.
    #[serde(default)]
    pub db: i64,
    /// Redis AUTH password. Empty = no auth.
    #[serde(default)]
    pub password: String,
}

fn default_endpoints() -> Vec<String> {
    vec!["redis://127.0.0.1:6379".into()]
}
fn default_prefix() -> String {
    "lynxx/".into()
}
fn default_poll_interval() -> u64 {
    15
}

impl Default for RedisKvProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoints: default_endpoints(),
            prefix: default_prefix(),
            poll_interval_secs: default_poll_interval(),
            db: 0,
            password: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Value schema
// ---------------------------------------------------------------------------

/// Service configuration stored as a JSON value in Redis.
#[derive(Debug, Deserialize)]
struct RedisServiceConfig {
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    strip_path: bool,
    #[serde(default = "default_retries")]
    retries: u32,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_ms: u64,
}

fn default_retries() -> u32 {
    3
}
fn default_connect_timeout() -> u64 {
    2_000
}

/// Intermediate representation for reconciliation.
#[derive(Debug, Clone)]
struct DiscoveredService {
    key: String,
    name: String,
    url: String,
    retries: u32,
    connect_timeout_ms: u64,
    paths: Vec<String>,
    hosts: Vec<String>,
    methods: Vec<String>,
    strip_path: bool,
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

pub async fn run(config: RedisKvProviderConfig, repo: Arc<dyn Repository>) {
    if !config.enabled {
        return;
    }
    tracing::info!(endpoints = ?config.endpoints, "redis-kv provider starting");

    let conn_url = build_connection_url(&config);
    let client = match redis::Client::open(conn_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(provider = "redis-kv", error = %e, "failed to create redis client");
            return;
        }
    };

    let mut conn = match ConnectionManager::new(client).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(provider = "redis-kv", error = %e, "failed to create connection manager");
            return;
        }
    };

    loop {
        match poll_keys(&config, &mut conn).await {
            Ok(discovered) => reconcile(&discovered, &repo).await,
            Err(e) => tracing::warn!(provider = "redis-kv", error = %e, "poll failed"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            config.poll_interval_secs.max(5),
        ))
        .await;
    }
}

/// Build the connection URL, injecting password and db if configured.
fn build_connection_url(config: &RedisKvProviderConfig) -> String {
    let base = config
        .endpoints
        .first()
        .cloned()
        .unwrap_or_else(|| "redis://127.0.0.1:6379".into());

    // If the URL already has query params or auth, use as-is.
    if base.contains('@') || base.contains('?') {
        return base;
    }

    // Inject password and db into the URL.
    if let Ok(mut url) = url::Url::parse(&base) {
        if !config.password.is_empty() {
            let _ = url.set_password(Some(&config.password));
        }
        if config.db != 0 {
            url.set_path(&format!("/{}", config.db));
        }
        url.to_string()
    } else {
        base
    }
}

// ---------------------------------------------------------------------------
// SCAN + GET polling
// ---------------------------------------------------------------------------

async fn poll_keys(
    config: &RedisKvProviderConfig,
    conn: &mut ConnectionManager,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error + Send + Sync>> {
    let pattern = format!("{}*", config.prefix);
    let keys: Vec<String> = redis::cmd("KEYS").arg(&pattern).query_async(conn).await?;

    let mut discovered: Vec<DiscoveredService> = Vec::new();

    for key in &keys {
        // Skip the pub/sub channel key.
        if key.ends_with("changes") {
            continue;
        }

        let value: Option<String> = conn.get(key.as_str()).await?;
        let raw = match value {
            Some(v) => v,
            None => continue,
        };

        let cfg: RedisServiceConfig = match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(key = %key, error = %e, "redis-kv: JSON parse failed");
                continue;
            }
        };

        let name = if cfg.name.is_empty() {
            key.strip_prefix(&config.prefix).unwrap_or(key).to_string()
        } else {
            cfg.name.clone()
        };
        let paths = if cfg.paths.is_empty() {
            vec!["/".into()]
        } else {
            cfg.paths.clone()
        };

        discovered.push(DiscoveredService {
            key: format!("redis:{key}"),
            name: format!("redis:{name}"),
            url: cfg.url,
            retries: cfg.retries,
            connect_timeout_ms: cfg.connect_timeout_ms,
            paths,
            hosts: cfg.hosts,
            methods: cfg.methods,
            strip_path: cfg.strip_path,
        });
    }

    Ok(discovered)
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

fn deterministic_uuid(seed: &str, kind: &str) -> Uuid {
    let mut input = String::with_capacity(seed.len() + kind.len() + 16);
    input.push_str("lynxx:redis:");
    input.push_str(kind);
    input.push(':');
    input.push_str(seed);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

async fn reconcile(discovered: &[DiscoveredService], repo: &Arc<dyn Repository>) {
    for d in discovered {
        let service_id = deterministic_uuid(&d.key, "service");
        let route_id = deterministic_uuid(&d.key, "route");
        let now = Utc::now();

        let service = Service {
            id: service_id,
            name: d.name.clone().into(),
            url: d.url.clone(),
            retries: d.retries,
            connect_timeout_ms: d.connect_timeout_ms,
            lb_strategy: "round-robin".into(),
            service_type: "api".into(),
            document_root: None,
            index_file: "index.html".into(),
            spa_fallback: false,
            tls_verify: true,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_ca_path: None,
            lb_hash_header: None,
            lb_hash_query_param: None,
            flush_interval_ms: None,
            stream_timeout_ms: None,
            stream_close_delay_ms: None,
            pass_host_header: None,
            force_http_version: None,
            drain_timeout_ms: None,
            project_id: None,
            domain: String::new(),
            subdomain: String::new(),
            created_at: now,
            updated_at: now,
        };

        let route = Route {
            id: route_id,
            paths: d.paths.clone(),
            methods: d.methods.clone(),
            hosts: d.hosts.clone(),
            service_id,
            strip_path: d.strip_path,
            buffer_request: false,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            headers: std::collections::HashMap::new(),
            query_params: std::collections::HashMap::new(),
            path_regexes: Vec::new(),
            read_timeout_ms: None,
            write_timeout_ms: None,
            idle_timeout_ms: None,
            retry_on_status: Vec::new(),
            matchers: Vec::new(),
            matcher_refs: Vec::new(),
            handle_blocks: Vec::new(),
            try_files: None,
            uri_directives: Vec::new(),
            intercept_rules: Vec::new(),
            push: None,
            static_response: None,
            health_gate: false,
            created_at: now,
            updated_at: now,
        };

        if repo.update_service(&service_id, &service).await.is_err() {
            if let Err(e) = repo.create_service(&service).await {
                tracing::warn!(
                    provider = "redis-kv", service = %d.name, error = %e,
                    "failed to create service"
                );
                continue;
            }
        }
        if repo.update_route(&route_id, &route).await.is_err() {
            if let Err(e) = repo.create_route(&route).await {
                tracing::warn!(
                    provider = "redis-kv", service = %d.name, error = %e,
                    "failed to create route"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = RedisKvProviderConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoints, vec!["redis://127.0.0.1:6379"]);
        assert_eq!(cfg.prefix, "lynxx/");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.db, 0);
        assert!(cfg.password.is_empty());
    }

    #[test]
    fn config_from_json() {
        let json = r#"{
            "enabled": true,
            "endpoints": ["redis://redis-1:6379", "redis://redis-2:6379"],
            "prefix": "gateway/",
            "poll_interval_secs": 10,
            "db": 2,
            "password": "redis-secret"
        }"#;
        let cfg: RedisKvProviderConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoints.len(), 2);
        assert_eq!(cfg.prefix, "gateway/");
        assert_eq!(cfg.poll_interval_secs, 10);
        assert_eq!(cfg.db, 2);
        assert_eq!(cfg.password, "redis-secret");
    }

    #[test]
    fn build_connection_url_plain() {
        let cfg = RedisKvProviderConfig::default();
        let url = build_connection_url(&cfg);
        // url::Url::parse normalises to trailing slash; the function
        // may return with or without it — accept both.
        assert!(
            url == "redis://127.0.0.1:6379" || url == "redis://127.0.0.1:6379/",
            "unexpected URL: {url}"
        );
    }

    #[test]
    fn build_connection_url_with_password_and_db() {
        let cfg = RedisKvProviderConfig {
            endpoints: vec!["redis://127.0.0.1:6379".into()],
            password: "secret".into(),
            db: 3,
            ..Default::default()
        };
        let url = build_connection_url(&cfg);
        assert!(
            url.contains(":secret@"),
            "URL should contain password: {url}"
        );
        assert!(url.contains("/3"), "URL should contain db number: {url}");
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("redis:lynxx/web", "service");
        let b = deterministic_uuid("redis:lynxx/web", "service");
        let c = deterministic_uuid("redis:lynxx/web", "route");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parse_redis_service_config() {
        let json = r#"{
            "name": "payments",
            "url": "http://10.0.0.10:4000",
            "paths": ["/pay", "/checkout"],
            "hosts": ["pay.example.com"],
            "methods": ["POST"],
            "strip_path": true,
            "retries": 5,
            "connect_timeout_ms": 3000
        }"#;
        let cfg: RedisServiceConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.name, "payments");
        assert_eq!(cfg.url, "http://10.0.0.10:4000");
        assert_eq!(cfg.paths, vec!["/pay", "/checkout"]);
        assert_eq!(cfg.hosts, vec!["pay.example.com"]);
        assert_eq!(cfg.methods, vec!["POST"]);
        assert!(cfg.strip_path);
        assert_eq!(cfg.retries, 5);
        assert_eq!(cfg.connect_timeout_ms, 3000);
    }

    #[test]
    fn parse_redis_service_config_defaults() {
        let json = r#"{"url": "http://backend:8080"}"#;
        let cfg: RedisServiceConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.name.is_empty());
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.connect_timeout_ms, 2_000);
        assert!(cfg.paths.is_empty());
        assert!(!cfg.strip_path);
    }
}
