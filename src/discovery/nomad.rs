//! Nomad provider — discovers services registered via Nomad's native
//! service discovery (feature 113).
//!
//! Polls `GET /v1/services` to enumerate services, then
//! `GET /v1/service/{name}` for each to resolve addresses, ports, and
//! tags. Gateway configuration is encoded in Nomad service tags
//! following the convention:
//!
//! ```text
//! lynxx.enable=true
//! lynxx.http.routers.myapp.rule=Host(`example.com`)
//! lynxx.http.services.myapp.url=http://10.0.0.5:8080
//! ```
//!
//! Registered entities are prefixed `nomad:{name}` so they are
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
pub struct NomadProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Nomad ACL token. Sent as `X-Nomad-Token` header.
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Tag prefix used to identify gateway-managed tags.
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Allow stale Nomad reads.
    #[serde(default)]
    pub stale: bool,
    /// Nomad namespace. Empty = default namespace.
    #[serde(default)]
    pub namespace: String,
    /// When `true`, services without `lynxx.enable=true` are still
    /// registered. Default `true`.
    #[serde(default = "default_expose")]
    pub expose_by_default: bool,
}

fn default_endpoint() -> String {
    "http://127.0.0.1:4646".into()
}
fn default_poll_interval() -> u64 {
    15
}
fn default_prefix() -> String {
    "lynxx".into()
}
fn default_expose() -> bool {
    true
}

impl Default for NomadProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            token: String::new(),
            poll_interval_secs: default_poll_interval(),
            prefix: default_prefix(),
            stale: false,
            namespace: String::new(),
            expose_by_default: default_expose(),
        }
    }
}

// ---------------------------------------------------------------------------
// API response types (Nomad HTTP)
// ---------------------------------------------------------------------------

/// Element of `GET /v1/services` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NomadServiceStub {
    #[serde(default)]
    service_name: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Wrapper: Nomad returns an array of namespace-keyed objects.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NomadServicesResponse {
    #[serde(default)]
    services: Vec<NomadServiceStub>,
}

/// Element of `GET /v1/service/{name}` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NomadServiceRegistration {
    #[serde(default)]
    service_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default, rename = "ID")]
    id: String,
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

pub async fn run(config: NomadProviderConfig, repo: Arc<dyn Repository>) {
    if !config.enabled {
        return;
    }
    tracing::info!(endpoint = %config.endpoint, "nomad provider starting");

    let client = reqwest::Client::new();

    loop {
        match poll_services(&config, &client).await {
            Ok(discovered) => reconcile(&discovered, &repo).await,
            Err(e) => tracing::warn!(provider = "nomad", error = %e, "poll failed"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            config.poll_interval_secs.max(5),
        ))
        .await;
    }
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

async fn poll_services(
    config: &NomadProviderConfig,
    client: &reqwest::Client,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error + Send + Sync>> {
    // Step 1: list services.
    let mut url = format!("{}/v1/services", config.endpoint.trim_end_matches('/'));
    let mut params: Vec<String> = Vec::new();
    if config.stale {
        params.push("stale".into());
    }
    if !config.namespace.is_empty() {
        params.push(format!("namespace={}", config.namespace));
    }
    if !params.is_empty() {
        url = format!("{}?{}", url, params.join("&"));
    }

    let mut req = client.get(&url);
    if !config.token.is_empty() {
        req = req.header("X-Nomad-Token", &config.token);
    }
    let resp = req.send().await?;
    let service_stubs: Vec<NomadServicesResponse> = resp.json().await?;

    // Flatten: Nomad groups by namespace.
    let mut all_names: Vec<(String, Vec<String>)> = Vec::new();
    for ns_block in &service_stubs {
        for stub in &ns_block.services {
            all_names.push((stub.service_name.clone(), stub.tags.clone()));
        }
    }

    // Step 2: fetch registrations for each service.
    let mut discovered: Vec<DiscoveredService> = Vec::new();

    for (svc_name, stub_tags) in &all_names {
        // Check if this service should be exposed.
        let tag_map = parse_tag_labels(stub_tags, &config.prefix);
        let enabled = tag_map
            .get(&format!("{}.enable", config.prefix))
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(config.expose_by_default);
        if !enabled {
            continue;
        }

        let registrations = fetch_service_registrations(config, client, svc_name).await?;
        for reg in &registrations {
            if reg.address.is_empty() || reg.port == 0 {
                continue;
            }

            let reg_tag_map = parse_tag_labels(&reg.tags, &config.prefix);
            let unique_key = if reg.id.is_empty() {
                format!("{}:{}:{}", svc_name, reg.address, reg.port)
            } else {
                reg.id.clone()
            };

            let url = reg_tag_map
                .get(&format!("{}.http.services.{}.url", config.prefix, svc_name))
                .cloned()
                .unwrap_or_else(|| format!("http://{}:{}", reg.address, reg.port));

            let paths = reg_tag_map
                .get(&format!("{}.route.paths", config.prefix))
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["/".into()]);

            let hosts = reg_tag_map
                .get(&format!("{}.route.host", config.prefix))
                .or_else(|| {
                    // Traefik-style rule parsing: Host(`example.com`)
                    reg_tag_map
                        .get(&format!("{}.http.routers.{}.rule", config.prefix, svc_name))
                        .and(None::<&String>) // simplified — full rule parser not implemented
                })
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let methods = reg_tag_map
                .get(&format!("{}.route.methods", config.prefix))
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let strip_path = reg_tag_map
                .get(&format!("{}.route.strip_path", config.prefix))
                .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
                .unwrap_or(false);

            discovered.push(DiscoveredService {
                key: format!("nomad:{unique_key}"),
                name: format!("nomad:{svc_name}"),
                url,
                retries: 3,
                connect_timeout_ms: 2_000,
                paths,
                hosts,
                methods,
                strip_path,
            });
        }
    }

    Ok(discovered)
}

async fn fetch_service_registrations(
    config: &NomadProviderConfig,
    client: &reqwest::Client,
    name: &str,
) -> Result<Vec<NomadServiceRegistration>, Box<dyn std::error::Error + Send + Sync>> {
    let mut url = format!(
        "{}/v1/service/{}",
        config.endpoint.trim_end_matches('/'),
        name,
    );
    let mut params: Vec<String> = Vec::new();
    if config.stale {
        params.push("stale".into());
    }
    if !config.namespace.is_empty() {
        params.push(format!("namespace={}", config.namespace));
    }
    if !params.is_empty() {
        url = format!("{}?{}", url, params.join("&"));
    }

    let mut req = client.get(&url);
    if !config.token.is_empty() {
        req = req.header("X-Nomad-Token", &config.token);
    }
    let registrations: Vec<NomadServiceRegistration> = req.send().await?.json().await?;
    Ok(registrations)
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

fn deterministic_uuid(seed: &str, kind: &str) -> Uuid {
    let mut input = String::with_capacity(seed.len() + kind.len() + 16);
    input.push_str("lynxx:nomad:");
    input.push_str(kind);
    input.push(':');
    input.push_str(seed);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

async fn reconcile(discovered: &[DiscoveredService], repo: &Arc<dyn Repository>) {
    for d in discovered {
        if !crate::discovery::is_safe_upstream_url(&d.url) {
            tracing::warn!(
                provider = "nomad", service = %d.name, url = %d.url,
                "skipping discovered service: unsafe upstream url (SSRF guard)"
            );
            continue;
        }
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
                    provider = "nomad", service = %d.name, error = %e,
                    "failed to create service"
                );
                continue;
            }
        }
        if repo.update_route(&route_id, &route).await.is_err() {
            if let Err(e) = repo.create_route(&route).await {
                tracing::warn!(
                    provider = "nomad", service = %d.name, error = %e,
                    "failed to create route"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse tags like `lynxx.enable=true` into a key-value map, filtering
/// for the given prefix.
fn parse_tag_labels(tags: &[String], prefix: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for t in tags {
        if let Some((k, v)) = t.split_once('=') {
            if k.starts_with(prefix) {
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
        let cfg = NomadProviderConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "http://127.0.0.1:4646");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.prefix, "lynxx");
        assert!(cfg.expose_by_default);
        assert!(!cfg.stale);
        assert!(cfg.token.is_empty());
        assert!(cfg.namespace.is_empty());
    }

    #[test]
    fn config_from_json() {
        let json = r#"{
            "enabled": true,
            "endpoint": "http://nomad:4646",
            "token": "nomad-secret",
            "poll_interval_secs": 20,
            "prefix": "gw",
            "stale": true,
            "namespace": "production",
            "expose_by_default": false
        }"#;
        let cfg: NomadProviderConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, "http://nomad:4646");
        assert_eq!(cfg.token, "nomad-secret");
        assert_eq!(cfg.poll_interval_secs, 20);
        assert_eq!(cfg.prefix, "gw");
        assert!(cfg.stale);
        assert_eq!(cfg.namespace, "production");
        assert!(!cfg.expose_by_default);
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("nomad:web-1", "service");
        let b = deterministic_uuid("nomad:web-1", "service");
        let c = deterministic_uuid("nomad:web-1", "route");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parse_tag_labels_filters_by_prefix() {
        let tags = vec![
            "lynxx.enable=true".into(),
            "lynxx.route.paths=/api".into(),
            "lynxx.route.host=example.com".into(),
            "version=v2".into(),
            "plain-tag".into(),
        ];
        let map = parse_tag_labels(&tags, "lynxx");
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("lynxx.enable").unwrap(), "true");
        assert_eq!(map.get("lynxx.route.paths").unwrap(), "/api");
        assert_eq!(map.get("lynxx.route.host").unwrap(), "example.com");
    }

    #[test]
    fn parse_nomad_service_registration() {
        let json = r#"{
            "ServiceName": "web",
            "Address": "10.0.0.5",
            "Port": 8080,
            "Tags": ["lynxx.enable=true", "lynxx.route.paths=/web"],
            "ID": "web-abc123"
        }"#;
        let reg: NomadServiceRegistration = serde_json::from_str(json).unwrap();
        assert_eq!(reg.service_name, "web");
        assert_eq!(reg.address, "10.0.0.5");
        assert_eq!(reg.port, 8080);
        assert_eq!(reg.tags.len(), 2);
        assert_eq!(reg.id, "web-abc123");
    }

    #[test]
    fn parse_nomad_service_stub() {
        let json = r#"{"ServiceName": "api", "Tags": ["lynxx.enable=true"]}"#;
        let stub: NomadServiceStub = serde_json::from_str(json).unwrap();
        assert_eq!(stub.service_name, "api");
        assert_eq!(stub.tags, vec!["lynxx.enable=true"]);
    }
}
