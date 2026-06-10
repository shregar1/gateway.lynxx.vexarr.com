//! HTTP provider — fetches gateway configuration from an external HTTP
//! endpoint that returns a JSON document with `services` and `routes`
//! arrays (feature 118).
//!
//! This is the simplest provider to integrate with: point it at any URL
//! that returns the expected JSON shape and the gateway will reconcile
//! on each poll. Useful for:
//!
//! - Central configuration servers
//! - GitOps pipelines that publish rendered config to an S3/GCS bucket
//! - Custom service registries with an HTTP API
//!
//! ## Expected response format
//!
//! ```json
//! {
//!   "services": [
//!     { "name": "web", "url": "http://10.0.0.5:8080", ... },
//!     ...
//!   ],
//!   "routes": [
//!     { "paths": ["/api"], "service_name": "web", ... },
//!     ...
//!   ]
//! }
//! ```
//!
//! Registered entities are prefixed `http:{name}` so they are
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
pub struct HttpProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    /// URL to fetch the configuration document from.
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Custom HTTP headers added to every request. Commonly used for
    /// `Authorization: Bearer ...` or `X-Api-Key: ...`.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Path to a PEM CA certificate for TLS. Empty = system roots.
    #[serde(default)]
    pub tls_ca: String,
    /// Whether to follow HTTP redirects. Default `true`.
    #[serde(default = "default_follow_redirects")]
    pub follow_redirects: bool,
}

fn default_poll_interval() -> u64 {
    15
}
fn default_follow_redirects() -> bool {
    true
}

impl Default for HttpProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            poll_interval_secs: default_poll_interval(),
            headers: HashMap::new(),
            tls_ca: String::new(),
            follow_redirects: default_follow_redirects(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response schema
// ---------------------------------------------------------------------------

/// Top-level JSON document returned by the HTTP endpoint.
#[derive(Debug, Deserialize)]
struct ConfigDocument {
    #[serde(default)]
    services: Vec<HttpServiceEntry>,
    #[serde(default)]
    routes: Vec<HttpRouteEntry>,
}

/// A service entry in the configuration document.
#[derive(Debug, Clone, Deserialize)]
struct HttpServiceEntry {
    /// Display name. Also used to link routes via `service_name`.
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default = "default_retries")]
    retries: u32,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_ms: u64,
}

/// A route entry in the configuration document.
#[derive(Debug, Clone, Deserialize)]
struct HttpRouteEntry {
    /// Links this route to a service by name.
    #[serde(default)]
    service_name: String,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    strip_path: bool,
}

fn default_retries() -> u32 {
    3
}
fn default_connect_timeout() -> u64 {
    2_000
}

/// Flattened service + route pair for reconciliation.
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

pub async fn run(config: HttpProviderConfig, repo: Arc<dyn Repository>) {
    if !config.enabled {
        return;
    }
    if config.endpoint.is_empty() {
        tracing::warn!(provider = "http", "endpoint is empty, provider disabled");
        return;
    }
    tracing::info!(endpoint = %config.endpoint, "http provider starting");

    let client = build_client(&config);
    let mut previous_hash: Option<u64> = None;

    loop {
        match poll_endpoint(&config, &client).await {
            Ok(discovered) => {
                // Quick change detection: hash the discovered set and
                // skip reconciliation if nothing changed.
                let hash = hash_discovered(&discovered);
                if previous_hash != Some(hash) {
                    reconcile(&discovered, &repo).await;
                    previous_hash = Some(hash);
                }
            }
            Err(e) => tracing::warn!(provider = "http", error = %e, "poll failed"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            config.poll_interval_secs.max(5),
        ))
        .await;
    }
}

fn build_client(config: &HttpProviderConfig) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().redirect(if config.follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    });

    if !config.tls_ca.is_empty() {
        if let Ok(pem) = std::fs::read(&config.tls_ca) {
            if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                builder = builder.add_root_certificate(cert);
            } else {
                tracing::warn!(path = %config.tls_ca, "http provider: failed to parse CA cert");
            }
        } else {
            tracing::warn!(path = %config.tls_ca, "http provider: failed to read CA cert file");
        }
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

async fn poll_endpoint(
    config: &HttpProviderConfig,
    client: &reqwest::Client,
) -> Result<Vec<DiscoveredService>, Box<dyn std::error::Error + Send + Sync>> {
    let mut req = client.get(&config.endpoint);
    for (k, v) in &config.headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()).into());
    }

    let doc: ConfigDocument = resp.json().await?;

    // Build a name -> service map for route linking.
    let svc_map: HashMap<String, &HttpServiceEntry> =
        doc.services.iter().map(|s| (s.name.clone(), s)).collect();

    let mut discovered: Vec<DiscoveredService> = Vec::new();

    // Services without explicit routes get a default `/` route.
    let mut services_with_routes: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for r in &doc.routes {
        services_with_routes.insert(r.service_name.clone());
    }

    // Process explicit routes first.
    for r in &doc.routes {
        let svc = match svc_map.get(&r.service_name) {
            Some(s) => *s,
            None => {
                tracing::warn!(
                    provider = "http",
                    route_service = %r.service_name,
                    "route references unknown service, skipping"
                );
                continue;
            }
        };

        let paths = if r.paths.is_empty() {
            vec!["/".into()]
        } else {
            r.paths.clone()
        };

        discovered.push(DiscoveredService {
            key: format!("http:{}:{}", svc.name, paths.join(",")),
            name: format!("http:{}", svc.name),
            url: svc.url.clone(),
            retries: svc.retries,
            connect_timeout_ms: svc.connect_timeout_ms,
            paths,
            hosts: r.hosts.clone(),
            methods: r.methods.clone(),
            strip_path: r.strip_path,
        });
    }

    // Services without explicit routes get a catch-all.
    for svc in &doc.services {
        if !services_with_routes.contains(&svc.name) {
            discovered.push(DiscoveredService {
                key: format!("http:{}:/", svc.name),
                name: format!("http:{}", svc.name),
                url: svc.url.clone(),
                retries: svc.retries,
                connect_timeout_ms: svc.connect_timeout_ms,
                paths: vec!["/".into()],
                hosts: Vec::new(),
                methods: Vec::new(),
                strip_path: false,
            });
        }
    }

    Ok(discovered)
}

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

fn hash_discovered(discovered: &[DiscoveredService]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for d in discovered {
        d.key.hash(&mut hasher);
        d.url.hash(&mut hasher);
        d.paths.hash(&mut hasher);
        d.hosts.hash(&mut hasher);
        d.methods.hash(&mut hasher);
        d.strip_path.hash(&mut hasher);
    }
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

fn deterministic_uuid(seed: &str, kind: &str) -> Uuid {
    let mut input = String::with_capacity(seed.len() + kind.len() + 16);
    input.push_str("lynxx:http:");
    input.push_str(kind);
    input.push(':');
    input.push_str(seed);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

async fn reconcile(discovered: &[DiscoveredService], repo: &Arc<dyn Repository>) {
    for d in discovered {
        if !crate::discovery::is_safe_upstream_url(&d.url) {
            tracing::warn!(
                provider = "http", service = %d.name, url = %d.url,
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
                    provider = "http", service = %d.name, error = %e,
                    "failed to create service"
                );
                continue;
            }
        }
        if repo.update_route(&route_id, &route).await.is_err() {
            if let Err(e) = repo.create_route(&route).await {
                tracing::warn!(
                    provider = "http", service = %d.name, error = %e,
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
        let cfg = HttpProviderConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.endpoint.is_empty());
        assert_eq!(cfg.poll_interval_secs, 15);
        assert!(cfg.headers.is_empty());
        assert!(cfg.tls_ca.is_empty());
        assert!(cfg.follow_redirects);
    }

    #[test]
    fn config_from_json() {
        let json = r#"{
            "enabled": true,
            "endpoint": "https://config.internal/gateway.json",
            "poll_interval_secs": 60,
            "headers": {
                "Authorization": "Bearer tok123",
                "X-Custom": "value"
            },
            "tls_ca": "/etc/ssl/internal-ca.pem",
            "follow_redirects": false
        }"#;
        let cfg: HttpProviderConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, "https://config.internal/gateway.json");
        assert_eq!(cfg.poll_interval_secs, 60);
        assert_eq!(cfg.headers.len(), 2);
        assert_eq!(cfg.headers.get("Authorization").unwrap(), "Bearer tok123");
        assert_eq!(cfg.tls_ca, "/etc/ssl/internal-ca.pem");
        assert!(!cfg.follow_redirects);
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("http:web:/api", "service");
        let b = deterministic_uuid("http:web:/api", "service");
        let c = deterministic_uuid("http:web:/api", "route");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parse_config_document() {
        let json = r#"{
            "services": [
                {"name": "web", "url": "http://10.0.0.5:8080", "retries": 2, "connect_timeout_ms": 1000},
                {"name": "api", "url": "http://10.0.0.6:3000"}
            ],
            "routes": [
                {"service_name": "web", "paths": ["/"], "hosts": ["example.com"]},
                {"service_name": "api", "paths": ["/api", "/v1"], "methods": ["GET", "POST"], "strip_path": true}
            ]
        }"#;
        let doc: ConfigDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.services.len(), 2);
        assert_eq!(doc.routes.len(), 2);

        assert_eq!(doc.services[0].name, "web");
        assert_eq!(doc.services[0].retries, 2);
        assert_eq!(doc.services[1].connect_timeout_ms, 2_000); // default

        assert_eq!(doc.routes[0].service_name, "web");
        assert_eq!(doc.routes[0].hosts, vec!["example.com"]);
        assert_eq!(doc.routes[1].methods, vec!["GET", "POST"]);
        assert!(doc.routes[1].strip_path);
    }

    #[test]
    fn parse_config_document_empty() {
        let json = r#"{}"#;
        let doc: ConfigDocument = serde_json::from_str(json).unwrap();
        assert!(doc.services.is_empty());
        assert!(doc.routes.is_empty());
    }

    #[test]
    fn hash_discovered_changes_on_mutation() {
        let base = vec![DiscoveredService {
            key: "http:web:/".into(),
            name: "http:web".into(),
            url: "http://10.0.0.5:8080".into(),
            retries: 3,
            connect_timeout_ms: 2_000,
            paths: vec!["/".into()],
            hosts: Vec::new(),
            methods: Vec::new(),
            strip_path: false,
        }];
        let h1 = hash_discovered(&base);

        let mut modified = base.clone();
        modified[0].url = "http://10.0.0.6:8080".into();
        let h2 = hash_discovered(&modified);

        assert_ne!(h1, h2, "hash should change when URL changes");
    }

    #[test]
    fn hash_discovered_stable_for_same_input() {
        let d = vec![DiscoveredService {
            key: "http:api:/v1".into(),
            name: "http:api".into(),
            url: "http://10.0.0.1:3000".into(),
            retries: 3,
            connect_timeout_ms: 2_000,
            paths: vec!["/v1".into()],
            hosts: vec!["api.example.com".into()],
            methods: vec!["GET".into()],
            strip_path: true,
        }];
        assert_eq!(hash_discovered(&d), hash_discovered(&d));
    }
}
