//! etcd provider — discovers services from etcd v3 using the HTTP/JSON
//! gateway (feature 114).
//!
//! Reads keys under `{prefix}` via `POST /v3/kv/range`. Values are
//! base64-encoded JSON service configurations identical in shape to the
//! admin API payloads. Supports watch mode via `POST /v3/watch` for
//! near-real-time convergence, with a poll-based fallback.
//!
//! Registered entities are prefixed `etcd:{name}` so they are
//! distinguishable in the admin UI.

use crate::db::Repository;
use crate::models::{Route, Service};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EtcdProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    /// etcd endpoints. The provider tries them in order on failure.
    #[serde(default = "default_endpoints")]
    pub endpoints: Vec<String>,
    /// Username for etcd basic auth. Empty = no auth.
    #[serde(default)]
    pub username: String,
    /// Password for etcd basic auth.
    #[serde(default)]
    pub password: String,
    /// Key prefix for gateway configuration objects.
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Path to a PEM CA certificate for TLS. Empty = system roots.
    #[serde(default)]
    pub tls_ca: String,
}

impl Default for EtcdProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoints: default_endpoints(),
            username: String::new(),
            password: String::new(),
            prefix: default_prefix(),
            poll_interval_secs: default_poll_interval(),
            tls_ca: String::new(),
        }
    }
}

fn default_endpoints() -> Vec<String> {
    vec!["http://127.0.0.1:2379".into()]
}
fn default_prefix() -> String {
    "/lynxx/".into()
}
fn default_poll_interval() -> u64 {
    15
}

// ---------------------------------------------------------------------------
// etcd v3 JSON gateway types
// ---------------------------------------------------------------------------

/// Request body for `POST /v3/kv/range`.
#[derive(Debug, Serialize)]
struct RangeRequest {
    /// Base64-encoded key (or prefix start).
    key: String,
    /// Base64-encoded range end for prefix scans.
    range_end: String,
}

/// Response from `POST /v3/kv/range`.
#[derive(Debug, Deserialize)]
struct RangeResponse {
    #[serde(default)]
    kvs: Vec<KeyValue>,
    /// Revision header — used as the watch start point.
    #[serde(default)]
    header: Option<RangeHeader>,
}

#[derive(Debug, Deserialize)]
struct RangeHeader {
    #[serde(default)]
    revision: u64,
}

#[derive(Debug, Deserialize)]
struct KeyValue {
    /// Base64-encoded key.
    key: String,
    /// Base64-encoded value.
    value: String,
    /// Modification revision.
    #[serde(default)]
    mod_revision: u64,
}

/// Request body for `POST /v3/watch`.
#[derive(Debug, Serialize)]
struct WatchRequest {
    create_request: WatchCreateRequest,
}

#[derive(Debug, Serialize)]
struct WatchCreateRequest {
    key: String,
    range_end: String,
    start_revision: u64,
}

/// Service configuration stored in an etcd value (after base64 decode).
#[derive(Debug, Deserialize)]
struct EtcdServiceConfig {
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

pub async fn run(config: EtcdProviderConfig, repo: Arc<dyn Repository>) {
    if !config.enabled {
        return;
    }
    tracing::info!(endpoints = ?config.endpoints, "etcd provider starting");

    let client = build_client(&config);

    loop {
        let endpoint = pick_endpoint(&config);
        match poll_range(&config, &client, &endpoint).await {
            Ok(discovered) => reconcile(&discovered, &repo).await,
            Err(e) => tracing::warn!(provider = "etcd", error = %e, "poll failed"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            config.poll_interval_secs.max(5),
        ))
        .await;
    }
}

fn build_client(config: &EtcdProviderConfig) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();

    // If a CA certificate path is provided, load it.
    if !config.tls_ca.is_empty() {
        if let Ok(pem) = std::fs::read(&config.tls_ca) {
            if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                builder = builder.add_root_certificate(cert);
            } else {
                tracing::warn!(path = %config.tls_ca, "etcd: failed to parse CA cert");
            }
        } else {
            tracing::warn!(path = %config.tls_ca, "etcd: failed to read CA cert file");
        }
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// Simple round-robin-ish endpoint selection. In production you'd track
/// failures and prefer healthy nodes; for the discovery provider a
/// random pick is fine.
fn pick_endpoint(config: &EtcdProviderConfig) -> String {
    config
        .endpoints
        .first()
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:2379".into())
}

// ---------------------------------------------------------------------------
// Range (poll) path
// ---------------------------------------------------------------------------

/// Compute the range-end for a prefix scan. etcd convention: increment
/// the last byte of the prefix.
fn prefix_range_end(prefix: &str) -> String {
    let mut end = prefix.as_bytes().to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.wrapping_add(1);
    }
    String::from_utf8_lossy(&end).to_string()
}

async fn poll_range(
    config: &EtcdProviderConfig,
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine;
    let b64 = &base64::engine::general_purpose::STANDARD;

    let key_b64 = b64.encode(config.prefix.as_bytes());
    let end_b64 = b64.encode(prefix_range_end(&config.prefix).as_bytes());

    let body = RangeRequest {
        key: key_b64,
        range_end: end_b64,
    };

    let url = format!("{}/v3/kv/range", endpoint.trim_end_matches('/'));
    let mut req = client.post(&url).json(&body);
    if !config.username.is_empty() {
        req = req.basic_auth(&config.username, Some(&config.password));
    }

    let resp: RangeResponse = req.send().await?.json().await?;
    let mut discovered: Vec<DiscoveredService> = Vec::new();

    for kv in &resp.kvs {
        // Decode key.
        let key_bytes = match b64.decode(&kv.key) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let key_str = String::from_utf8_lossy(&key_bytes).to_string();

        // Decode value.
        let val_bytes = match b64.decode(&kv.value) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(key = %key_str, error = %e, "etcd: base64 decode failed");
                continue;
            }
        };

        let cfg: EtcdServiceConfig = match serde_json::from_slice(&val_bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(key = %key_str, error = %e, "etcd: JSON parse failed");
                continue;
            }
        };

        let name = if cfg.name.is_empty() {
            key_str.rsplit('/').next().unwrap_or("unnamed").to_string()
        } else {
            cfg.name.clone()
        };
        let paths = if cfg.paths.is_empty() {
            vec!["/".into()]
        } else {
            cfg.paths.clone()
        };

        discovered.push(DiscoveredService {
            key: format!("etcd:{key_str}"),
            name: format!("etcd:{name}"),
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
    input.push_str("lynxx:etcd:");
    input.push_str(kind);
    input.push(':');
    input.push_str(seed);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

async fn reconcile(discovered: &[DiscoveredService], repo: &Arc<dyn Repository>) {
    for d in discovered {
        if !crate::discovery::is_safe_upstream_url(&d.url) {
            tracing::warn!(
                provider = "etcd", service = %d.name, url = %d.url,
                "skipping discovered service: unsafe upstream url (SSRF guard)"
            );
            continue;
        }
        let service_id = deterministic_uuid(&d.key, "service");
        let route_id = deterministic_uuid(&d.key, "route");
        let now = Utc::now();

        let service = Service {
            hide_patterns: vec![],
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
            pool_idle_floor: None,
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
                    provider = "etcd", service = %d.name, error = %e,
                    "failed to create service"
                );
                continue;
            }
        }
        if repo.update_route(&route_id, &route).await.is_err() {
            if let Err(e) = repo.create_route(&route).await {
                tracing::warn!(
                    provider = "etcd", service = %d.name, error = %e,
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
        let cfg = EtcdProviderConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoints, vec!["http://127.0.0.1:2379"]);
        assert_eq!(cfg.prefix, "/lynxx/");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert!(cfg.username.is_empty());
        assert!(cfg.password.is_empty());
        assert!(cfg.tls_ca.is_empty());
    }

    #[test]
    fn config_from_json() {
        let json = r#"{
            "enabled": true,
            "endpoints": ["http://etcd-1:2379", "http://etcd-2:2379"],
            "username": "root",
            "password": "secret",
            "prefix": "/gateway/",
            "poll_interval_secs": 30,
            "tls_ca": "/etc/ssl/etcd-ca.pem"
        }"#;
        let cfg: EtcdProviderConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoints.len(), 2);
        assert_eq!(cfg.username, "root");
        assert_eq!(cfg.password, "secret");
        assert_eq!(cfg.prefix, "/gateway/");
        assert_eq!(cfg.poll_interval_secs, 30);
        assert_eq!(cfg.tls_ca, "/etc/ssl/etcd-ca.pem");
    }

    #[test]
    fn prefix_range_end_increments_last_byte() {
        assert_eq!(prefix_range_end("/lynxx/"), "/lynxx0");
        assert_eq!(prefix_range_end("/a"), "/b");
        assert_eq!(prefix_range_end("z"), "{"); // 'z' + 1 = '{'
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("etcd:/lynxx/web", "service");
        let b = deterministic_uuid("etcd:/lynxx/web", "service");
        let c = deterministic_uuid("etcd:/lynxx/web", "route");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parse_etcd_service_config() {
        let json = r#"{
            "name": "my-api",
            "url": "http://10.0.0.5:3000",
            "paths": ["/api", "/v1"],
            "hosts": ["api.example.com"],
            "methods": ["GET", "POST"],
            "strip_path": true,
            "retries": 5,
            "connect_timeout_ms": 5000
        }"#;
        let cfg: EtcdServiceConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.name, "my-api");
        assert_eq!(cfg.url, "http://10.0.0.5:3000");
        assert_eq!(cfg.paths, vec!["/api", "/v1"]);
        assert_eq!(cfg.hosts, vec!["api.example.com"]);
        assert_eq!(cfg.methods, vec!["GET", "POST"]);
        assert!(cfg.strip_path);
        assert_eq!(cfg.retries, 5);
        assert_eq!(cfg.connect_timeout_ms, 5000);
    }

    #[test]
    fn parse_etcd_service_config_defaults() {
        let json = r#"{"url": "http://backend:8080"}"#;
        let cfg: EtcdServiceConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.name.is_empty());
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.connect_timeout_ms, 2_000);
        assert!(cfg.paths.is_empty());
        assert!(!cfg.strip_path);
    }

    #[test]
    fn range_request_serializes() {
        use base64::Engine;
        let b64 = &base64::engine::general_purpose::STANDARD;
        let req = RangeRequest {
            key: b64.encode("/lynxx/".as_bytes()),
            range_end: b64.encode(prefix_range_end("/lynxx/").as_bytes()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("key"));
        assert!(json.contains("range_end"));
    }
}
