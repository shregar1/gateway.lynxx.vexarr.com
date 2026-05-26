//! Consul provider — discovers services from the Consul Catalog API
//! (feature 111) and reads gateway configuration from the Consul KV
//! store (feature 112).
//!
//! ## Catalog discovery
//!
//! Polls `GET /v1/catalog/services` to enumerate registered services,
//! then fetches `GET /v1/catalog/service/{name}` for each to obtain
//! address, port, and tags. Supports Consul blocking queries
//! (`?index=N&wait=30s`) for near-real-time convergence.
//!
//! ## KV configuration
//!
//! Reads keys under `{prefix}` recursively via
//! `GET /v1/kv/{prefix}?recurse=true`. Values are base64-encoded JSON
//! objects describing services and routes, identical in shape to the
//! admin API payloads.
//!
//! ## Tag conventions
//!
//! Services are only registered when:
//! - `expose_by_default` is `true`, OR
//! - the service carries the tag specified in `config.tag`
//!   (default `lynxx`).
//!
//! Registered entities are prefixed `consul:{name}` so they are
//! distinguishable in the admin UI.

use crate::db::Repository;
use crate::models::{Route, Service};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConsulProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Consul ACL token. Sent as `X-Consul-Token` header.
    #[serde(default)]
    pub token: String,
    /// Consul datacenter to query. Empty = agent default.
    #[serde(default)]
    pub datacenter: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// KV key prefix for gateway configuration objects.
    #[serde(default = "default_kv_prefix")]
    pub prefix: String,
    /// Only register catalog services carrying this tag. Empty = match all.
    #[serde(default = "default_tag")]
    pub tag: String,
    /// When `true`, catalog services without the required tag are still
    /// registered. Default `true`.
    #[serde(default = "default_expose")]
    pub expose_by_default: bool,
    /// Allow stale Consul reads (lower latency, eventual consistency).
    #[serde(default)]
    pub stale: bool,
    /// Consul Enterprise namespace. Empty = default namespace.
    #[serde(default)]
    pub namespace: String,
}

fn default_endpoint() -> String {
    "http://127.0.0.1:8500".into()
}
fn default_poll_interval() -> u64 {
    15
}
fn default_kv_prefix() -> String {
    "lynxx/".into()
}
fn default_tag() -> String {
    "lynxx".into()
}
fn default_expose() -> bool {
    true
}

impl Default for ConsulProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            token: String::new(),
            datacenter: String::new(),
            poll_interval_secs: default_poll_interval(),
            prefix: default_kv_prefix(),
            tag: default_tag(),
            expose_by_default: default_expose(),
            stale: false,
            namespace: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// API response types (Consul HTTP)
// ---------------------------------------------------------------------------

/// Response element from `GET /v1/catalog/service/{name}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CatalogServiceNode {
    #[serde(default)]
    service_name: String,
    #[serde(default)]
    service_address: String,
    #[serde(default)]
    service_port: u16,
    #[serde(default)]
    service_tags: Vec<String>,
    #[serde(default, alias = "ServiceID")]
    service_id: String,
    /// Fallback address when ServiceAddress is empty.
    #[serde(default)]
    address: String,
}

/// A single KV pair returned by `GET /v1/kv/...?recurse=true`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KvEntry {
    key: String,
    /// Base64-encoded value.
    value: Option<String>,
}

/// Service configuration stored in a KV value (after base64 decode).
#[derive(Debug, Deserialize)]
struct KvServiceConfig {
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

/// Intermediate representation of a discovered service + route pair
/// ready for reconciliation.
#[derive(Debug, Clone)]
struct DiscoveredService {
    /// Deterministic UUID seed (e.g. `consul:catalog:my-svc`).
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

pub async fn run(config: ConsulProviderConfig, repo: Arc<dyn Repository>) {
    if !config.enabled {
        return;
    }
    tracing::info!(endpoint = %config.endpoint, "consul provider starting");

    let client = reqwest::Client::new();
    let mut catalog_index: u64 = 0;

    loop {
        // --- Catalog discovery ---
        match poll_catalog(&config, &client, &mut catalog_index).await {
            Ok(discovered) => reconcile(&discovered, &repo, "catalog").await,
            Err(e) => {
                tracing::warn!(provider = "consul", mode = "catalog", error = %e, "poll failed")
            }
        }

        // --- KV configuration ---
        match poll_kv(&config, &client).await {
            Ok(discovered) => reconcile(&discovered, &repo, "kv").await,
            Err(e) => tracing::warn!(provider = "consul", mode = "kv", error = %e, "poll failed"),
        }

        tokio::time::sleep(std::time::Duration::from_secs(
            config.poll_interval_secs.max(5),
        ))
        .await;
    }
}

// ---------------------------------------------------------------------------
// Catalog polling
// ---------------------------------------------------------------------------

async fn poll_catalog(
    config: &ConsulProviderConfig,
    client: &reqwest::Client,
    last_index: &mut u64,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error + Send + Sync>> {
    // Step 1: list all services.
    let mut url = format!(
        "{}/v1/catalog/services",
        config.endpoint.trim_end_matches('/')
    );
    let mut params: Vec<String> = Vec::new();
    if *last_index > 0 {
        params.push(format!("index={last_index}"));
        params.push("wait=30s".into());
    }
    if config.stale {
        params.push("stale".into());
    }
    if !config.datacenter.is_empty() {
        params.push(format!("dc={}", config.datacenter));
    }
    if !config.namespace.is_empty() {
        params.push(format!("ns={}", config.namespace));
    }
    if !params.is_empty() {
        url = format!("{}?{}", url, params.join("&"));
    }

    let mut req = client.get(&url);
    if !config.token.is_empty() {
        req = req.header("X-Consul-Token", &config.token);
    }
    let resp = req.send().await?;

    // Update blocking-query index.
    if let Some(idx) = resp.headers().get("X-Consul-Index") {
        if let Ok(s) = idx.to_str() {
            if let Ok(n) = s.parse::<u64>() {
                *last_index = n;
            }
        }
    }

    let services_map: HashMap<String, Vec<String>> = resp.json().await?;

    // Step 2: for each service, fetch its nodes.
    let mut discovered: Vec<DiscoveredService> = Vec::new();

    for (svc_name, tags) in &services_map {
        // Tag filtering.
        if !config.expose_by_default && !config.tag.is_empty() && !tags.contains(&config.tag) {
            continue;
        }

        let nodes = fetch_catalog_service(config, client, svc_name).await?;
        for node in &nodes {
            let addr = if node.service_address.is_empty() {
                &node.address
            } else {
                &node.service_address
            };
            if addr.is_empty() || node.service_port == 0 {
                continue;
            }

            let unique_id = if node.service_id.is_empty() {
                format!("{}:{}", svc_name, addr)
            } else {
                node.service_id.clone()
            };

            discovered.push(DiscoveredService {
                key: format!("consul:catalog:{unique_id}"),
                name: format!("consul:{svc_name}"),
                url: format!("http://{addr}:{}", node.service_port),
                retries: 3,
                connect_timeout_ms: 2_000,
                paths: vec!["/".into()],
                hosts: Vec::new(),
                methods: Vec::new(),
                strip_path: false,
            });
        }
    }

    Ok(discovered)
}

async fn fetch_catalog_service(
    config: &ConsulProviderConfig,
    client: &reqwest::Client,
    name: &str,
) -> Result<Vec<CatalogServiceNode>, Box<dyn std::error::Error + Send + Sync>> {
    let mut url = format!(
        "{}/v1/catalog/service/{}",
        config.endpoint.trim_end_matches('/'),
        name,
    );
    let mut params: Vec<String> = Vec::new();
    if config.stale {
        params.push("stale".into());
    }
    if !config.datacenter.is_empty() {
        params.push(format!("dc={}", config.datacenter));
    }
    if !config.namespace.is_empty() {
        params.push(format!("ns={}", config.namespace));
    }
    if !params.is_empty() {
        url = format!("{}?{}", url, params.join("&"));
    }

    let mut req = client.get(&url);
    if !config.token.is_empty() {
        req = req.header("X-Consul-Token", &config.token);
    }
    let nodes: Vec<CatalogServiceNode> = req.send().await?.json().await?;
    Ok(nodes)
}

// ---------------------------------------------------------------------------
// KV polling
// ---------------------------------------------------------------------------

async fn poll_kv(
    config: &ConsulProviderConfig,
    client: &reqwest::Client,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error + Send + Sync>> {
    let mut url = format!(
        "{}/v1/kv/{}?recurse=true",
        config.endpoint.trim_end_matches('/'),
        config.prefix.trim_matches('/'),
    );
    if config.stale {
        url.push_str("&stale");
    }
    if !config.datacenter.is_empty() {
        url = format!("{url}&dc={}", config.datacenter);
    }
    if !config.namespace.is_empty() {
        url = format!("{url}&ns={}", config.namespace);
    }

    let mut req = client.get(&url);
    if !config.token.is_empty() {
        req = req.header("X-Consul-Token", &config.token);
    }
    let resp = req.send().await?;

    // A 404 means no keys exist yet — that's fine.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    let entries: Vec<KvEntry> = resp.json().await?;
    let mut discovered: Vec<DiscoveredService> = Vec::new();

    for entry in &entries {
        let raw = match &entry.value {
            Some(v) => v,
            None => continue,
        };
        let decoded = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw)
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(key = %entry.key, error = %e, "consul kv: base64 decode failed");
                continue;
            }
        };
        let cfg: KvServiceConfig = match serde_json::from_slice(&decoded) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(key = %entry.key, error = %e, "consul kv: JSON parse failed");
                continue;
            }
        };

        let name = if cfg.name.is_empty() {
            entry
                .key
                .rsplit('/')
                .next()
                .unwrap_or("unnamed")
                .to_string()
        } else {
            cfg.name.clone()
        };
        let paths = if cfg.paths.is_empty() {
            vec!["/".into()]
        } else {
            cfg.paths.clone()
        };

        discovered.push(DiscoveredService {
            key: format!("consul:kv:{}", entry.key),
            name: format!("consul:{name}"),
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
    input.push_str("lynxx:consul:");
    input.push_str(kind);
    input.push(':');
    input.push_str(seed);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

async fn reconcile(discovered: &[DiscoveredService], repo: &Arc<dyn Repository>, mode: &str) {
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

        let route = Route::new(
            d.paths.clone(),
            d.methods.clone(),
            d.hosts.clone(),
            service_id,
            d.strip_path,
        );
        let route = Route {
            id: route_id,
            created_at: now,
            updated_at: now,
            ..route
        };

        // Upsert: try update first, create on miss.
        if repo.update_service(&service_id, &service).await.is_err() {
            if let Err(e) = repo.create_service(&service).await {
                tracing::warn!(
                    provider = "consul", mode = mode, service = %d.name, error = %e,
                    "failed to create service"
                );
                continue;
            }
        }
        if repo.update_route(&route_id, &route).await.is_err() {
            if let Err(e) = repo.create_route(&route).await {
                tracing::warn!(
                    provider = "consul", mode = mode, service = %d.name, error = %e,
                    "failed to create route"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers used in parsing
// ---------------------------------------------------------------------------

/// Check whether a tag list contains a given tag (case-insensitive).
fn has_tag(tags: &[String], tag: &str) -> bool {
    tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
}

/// Parse tags like `lynxx.route.paths=/api,/v1` into a key-value map.
fn parse_tag_labels(tags: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for t in tags {
        if let Some((k, v)) = t.split_once('=') {
            if k.starts_with("lynxx.") {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = ConsulProviderConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "http://127.0.0.1:8500");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.prefix, "lynxx/");
        assert_eq!(cfg.tag, "lynxx");
        assert!(cfg.expose_by_default);
        assert!(!cfg.stale);
        assert!(cfg.token.is_empty());
        assert!(cfg.datacenter.is_empty());
        assert!(cfg.namespace.is_empty());
    }

    #[test]
    fn config_from_json() {
        let json = r#"{
            "enabled": true,
            "endpoint": "http://consul:8500",
            "token": "secret-token",
            "datacenter": "dc1",
            "poll_interval_secs": 30,
            "prefix": "gateway/",
            "tag": "public",
            "expose_by_default": false,
            "stale": true,
            "namespace": "team-a"
        }"#;
        let cfg: ConsulProviderConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, "http://consul:8500");
        assert_eq!(cfg.token, "secret-token");
        assert_eq!(cfg.datacenter, "dc1");
        assert_eq!(cfg.poll_interval_secs, 30);
        assert_eq!(cfg.prefix, "gateway/");
        assert_eq!(cfg.tag, "public");
        assert!(!cfg.expose_by_default);
        assert!(cfg.stale);
        assert_eq!(cfg.namespace, "team-a");
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("consul:catalog:web", "service");
        let b = deterministic_uuid("consul:catalog:web", "service");
        let c = deterministic_uuid("consul:catalog:web", "route");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parse_catalog_service_node() {
        let json = r#"{
            "ServiceName": "web",
            "ServiceAddress": "10.0.0.5",
            "ServicePort": 8080,
            "ServiceTags": ["lynxx", "production"],
            "ServiceID": "web-1",
            "Address": "10.0.0.1"
        }"#;
        let node: CatalogServiceNode = serde_json::from_str(json).unwrap();
        assert_eq!(node.service_name, "web");
        assert_eq!(node.service_address, "10.0.0.5");
        assert_eq!(node.service_port, 8080);
        assert_eq!(node.service_tags, vec!["lynxx", "production"]);
        assert_eq!(node.service_id, "web-1");
        assert_eq!(node.address, "10.0.0.1");
    }

    #[test]
    fn parse_catalog_service_node_uses_fallback_address() {
        let json = r#"{
            "ServiceName": "api",
            "ServiceAddress": "",
            "ServicePort": 3000,
            "ServiceTags": [],
            "ServiceID": "api-1",
            "Address": "192.168.1.10"
        }"#;
        let node: CatalogServiceNode = serde_json::from_str(json).unwrap();
        let addr = if node.service_address.is_empty() {
            &node.address
        } else {
            &node.service_address
        };
        assert_eq!(addr, "192.168.1.10");
    }

    #[test]
    fn has_tag_case_insensitive() {
        let tags = vec!["LYNXX".into(), "production".into()];
        assert!(has_tag(&tags, "lynxx"));
        assert!(has_tag(&tags, "LYNXX"));
        assert!(has_tag(&tags, "Lynxx"));
        assert!(!has_tag(&tags, "staging"));
    }

    #[test]
    fn parse_tag_labels_extracts_lynxx_keys() {
        let tags = vec![
            "lynxx.route.paths=/api,/v1".into(),
            "lynxx.route.host=example.com".into(),
            "version=v2".into(),
            "unrelated-tag".into(),
        ];
        let map = parse_tag_labels(&tags);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("lynxx.route.paths").unwrap(), "/api,/v1");
        assert_eq!(map.get("lynxx.route.host").unwrap(), "example.com");
    }

    #[test]
    fn kv_service_config_defaults() {
        let json = r#"{"url": "http://backend:3000"}"#;
        let cfg: KvServiceConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.url, "http://backend:3000");
        assert!(cfg.name.is_empty());
        assert!(cfg.paths.is_empty());
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.connect_timeout_ms, 2_000);
        assert!(!cfg.strip_path);
    }

    #[test]
    fn kv_entry_base64_decode() {
        use base64::Engine;
        let payload = r#"{"name":"my-svc","url":"http://10.0.0.5:8080","paths":["/api"]}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let entry = KvEntry {
            key: "lynxx/services/my-svc".into(),
            value: Some(encoded),
        };

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(entry.value.as_ref().unwrap())
            .unwrap();
        let cfg: KvServiceConfig = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(cfg.name, "my-svc");
        assert_eq!(cfg.url, "http://10.0.0.5:8080");
        assert_eq!(cfg.paths, vec!["/api"]);
    }
}
