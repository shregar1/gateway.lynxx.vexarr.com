//! Docker Swarm provider — discovers Swarm *services* (not individual
//! containers) and registers gateway services + routes from their
//! labels.
//!
//! This differs from the regular Docker provider in two key ways:
//!
//! 1. **Scope**: operates on Swarm services (`docker service ls`),
//!    not containers. A single Swarm service with N replicas produces
//!    one gateway service, not N.
//! 2. **Addressing**: uses the Swarm VIP (Virtual IP) or DNS
//!    round-robin name instead of individual container IPs.
//!
//! Labels follow the Traefik-compatible format:
//!
//! ```text
//! lynxx.enable=true
//! lynxx.http.routers.myapp.rule=Host(`example.com`)
//! lynxx.http.services.myapp.loadbalancer.server.port=8080
//! ```
//!
//! The provider uses `bollard` to enumerate services and optionally
//! watches Swarm events for real-time updates.

use crate::cluster::{ChangeEvent, ClusterBus};
use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Route, Service};
use bollard::service::{ListServicesOptions, ServiceSpec};
use bollard::system::EventsOptions;
use bollard::Docker;
use chrono::Utc;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

// ── Configuration ──────────────────────────────────────────────────

/// Configuration for [`DockerSwarmProvider`]. Lives under
/// `[gateway.providers.docker_swarm]` in the gateway config.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DockerSwarmProviderConfig {
    /// Master switch — provider is a no-op unless `true`.
    #[serde(default)]
    pub enabled: bool,

    /// Docker daemon endpoint. Defaults to the platform default
    /// (`unix:///var/run/docker.sock`).
    #[serde(default = "default_endpoint")]
    pub endpoint: String,

    /// How often (in seconds) to run a full reconciliation against
    /// the Swarm service list.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    /// Swarm overlay network name. When set, only services attached
    /// to this network are considered.
    #[serde(default)]
    pub network: String,

    /// When `true`, every Swarm service is registered unless it sets
    /// `lynxx.enable=false`. When `false`, services must opt in with
    /// `lynxx.enable=true`.
    #[serde(default)]
    pub expose_by_default: bool,

    /// When `true`, the upstream URL uses the container's bind port
    /// IP instead of the Swarm VIP.
    #[serde(default)]
    pub use_bind_port_ip: bool,

    /// Label-based constraints. A Swarm service must have *all*
    /// listed labels (with matching values) to be discovered.
    /// Format: `["env=production", "team=platform"]`.
    #[serde(default)]
    pub constraints: Vec<String>,

    /// Default routing rule template applied when a service doesn't
    /// define `lynxx.http.routers.*.rule`. Use `{{.Name}}` as a
    /// placeholder for the service name.
    #[serde(default = "default_rule")]
    pub default_rule: String,
}

fn default_endpoint() -> String {
    "unix:///var/run/docker.sock".to_string()
}

fn default_poll_interval() -> u64 {
    15
}

fn default_rule() -> String {
    "Host(`{{.Name}}.localhost`)".to_string()
}

impl Default for DockerSwarmProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            poll_interval_secs: default_poll_interval(),
            network: String::new(),
            expose_by_default: false,
            use_bind_port_ip: false,
            constraints: Vec::new(),
            default_rule: default_rule(),
        }
    }
}

// ── Label parsing ─────────────────────────────────────────────────

/// Parsed label set for a Swarm service. Supports both the simple
/// `lynxx.*` labels and the Traefik-compatible
/// `lynxx.http.routers.xxx.rule` / `lynxx.http.services.xxx.*`
/// format.
#[derive(Debug, Clone)]
pub(crate) struct ParsedSwarmLabels {
    pub service_name: String,
    pub upstream_url: Option<String>,
    pub port: Option<u16>,
    pub rule: Option<String>,
    pub paths: Vec<String>,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub strip_path: bool,
    pub retries: u32,
    pub connect_timeout_ms: u64,
}

/// Parse Swarm service labels. Returns `None` when the service
/// should be skipped.
pub(crate) fn parse_swarm_labels(
    labels: &HashMap<String, String>,
    expose_by_default: bool,
    default_rule: &str,
    service_name_fallback: &str,
) -> Option<ParsedSwarmLabels> {
    let enable = labels
        .get("lynxx.enable")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(expose_by_default);
    if !enable {
        return None;
    }

    let service_name = labels
        .get("lynxx.service.name")
        .cloned()
        .unwrap_or_else(|| service_name_fallback.to_string());

    let upstream_url = labels.get("lynxx.service.url").cloned();

    // Traefik-style port extraction:
    // lynxx.http.services.{name}.loadbalancer.server.port=8080
    let port = labels
        .iter()
        .find_map(|(k, v)| {
            if k.starts_with("lynxx.http.services.") && k.ends_with(".loadbalancer.server.port") {
                v.parse::<u16>().ok()
            } else {
                None
            }
        })
        .or_else(|| {
            labels
                .get("lynxx.service.port")
                .and_then(|v| v.parse::<u16>().ok())
        });

    // Traefik-style rule extraction:
    // lynxx.http.routers.{name}.rule=Host(`example.com`)
    let rule = labels
        .iter()
        .find_map(|(k, v)| {
            if k.starts_with("lynxx.http.routers.") && k.ends_with(".rule") {
                Some(v.clone())
            } else {
                None
            }
        })
        .or_else(|| {
            if default_rule.is_empty() {
                None
            } else {
                Some(default_rule.replace("{{.Name}}", &service_name))
            }
        });

    // Extract hosts from rule like Host(`example.com`)
    let hosts = rule
        .as_ref()
        .map(|r| parse_hosts_from_rule(r))
        .unwrap_or_default();

    let paths = csv(labels.get("lynxx.route.paths")).unwrap_or_else(|| vec!["/".to_string()]);
    let methods = csv(labels.get("lynxx.route.methods")).unwrap_or_default();
    let strip_path = labels
        .get("lynxx.route.strip_path")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    let retries = labels
        .get("lynxx.service.retries")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let connect_timeout_ms = labels
        .get("lynxx.service.connect_timeout_ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);

    Some(ParsedSwarmLabels {
        service_name,
        upstream_url,
        port,
        rule,
        paths,
        hosts,
        methods,
        strip_path,
        retries,
        connect_timeout_ms,
    })
}

/// Extract hostnames from a Traefik-style `Host(...)` rule.
/// `Host(`a.com`) && Host(`b.com`)` → `["a.com", "b.com"]`.
pub(crate) fn parse_hosts_from_rule(rule: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut remaining = rule;
    while let Some(start) = remaining.find("Host(`") {
        let after = &remaining[start + 6..];
        if let Some(end) = after.find("`)") {
            hosts.push(after[..end].to_string());
            remaining = &after[end + 2..];
        } else {
            break;
        }
    }
    hosts
}

fn csv(value: Option<&String>) -> Option<Vec<String>> {
    value.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
}

// ── Provider ──────────────────────────────────────────────────────

/// Zero UUID used as the `origin` field for change events.
const PROVIDER_ORIGIN: Uuid = Uuid::nil();

pub struct DockerSwarmProvider {
    config: DockerSwarmProviderConfig,
    docker: Docker,
    repo: Arc<dyn Repository>,
    bus: Arc<dyn ClusterBus>,
    node_id: Uuid,
    /// Swarm service ID -> (gateway service_id, route_id).
    owned: tokio::sync::Mutex<HashMap<String, OwnedRow>>,
}

#[derive(Clone, Debug)]
struct OwnedRow {
    service_id: Uuid,
    route_id: Uuid,
}

impl DockerSwarmProvider {
    /// Connect to the Docker daemon and verify it's a Swarm manager.
    pub async fn connect(
        config: DockerSwarmProviderConfig,
        repo: Arc<dyn Repository>,
        bus: Arc<dyn ClusterBus>,
        node_id: Uuid,
    ) -> Result<Arc<Self>, GatewayError> {
        let docker = if config.endpoint == default_endpoint() || config.endpoint.is_empty() {
            Docker::connect_with_local_defaults()
        } else if config.endpoint.starts_with("tcp://")
            || config.endpoint.starts_with("http://")
            || config.endpoint.starts_with("https://")
        {
            Docker::connect_with_http(&config.endpoint, 4, bollard::API_DEFAULT_VERSION)
        } else {
            Docker::connect_with_local(&config.endpoint, 120, bollard::API_DEFAULT_VERSION)
        }
        .map_err(|e| GatewayError::Internal(format!("docker swarm connect: {e}")))?;

        // Verify we can talk to the daemon.
        docker
            .ping()
            .await
            .map_err(|e| GatewayError::Internal(format!("docker swarm ping: {e}")))?;

        Ok(Arc::new(Self {
            config,
            docker,
            repo,
            bus,
            node_id,
            owned: tokio::sync::Mutex::new(HashMap::new()),
        }))
    }

    /// Spawn the reconcile + event watch loops.
    pub fn spawn(self: Arc<Self>) {
        let reconcile_handle = Arc::clone(&self);
        tokio::spawn(async move {
            if let Err(e) = reconcile_handle.reconcile().await {
                tracing::warn!(error = %e, "swarm provider initial reconcile failed");
            }
            let interval = Duration::from_secs(reconcile_handle.config.poll_interval_secs.max(5));
            loop {
                sleep(interval).await;
                if let Err(e) = reconcile_handle.reconcile().await {
                    tracing::warn!(error = %e, "swarm provider reconcile failed");
                }
            }
        });

        let watch_handle = self;
        tokio::spawn(async move {
            loop {
                if let Err(e) = watch_handle.watch_events().await {
                    tracing::warn!(error = %e, "swarm provider event stream broke; retrying");
                }
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    /// Watch Swarm service events for real-time updates.
    async fn watch_events(&self) -> Result<(), GatewayError> {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["service".to_string()]);
        filters.insert(
            "event".to_string(),
            vec![
                "create".to_string(),
                "update".to_string(),
                "remove".to_string(),
            ],
        );
        let opts = EventsOptions::<String> {
            filters,
            ..Default::default()
        };

        let mut stream = self.docker.events(Some(opts));
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(_ev) => {
                    // On any service event, do a full reconcile. Swarm
                    // events don't carry enough detail to do targeted
                    // updates efficiently.
                    if let Err(e) = self.reconcile().await {
                        tracing::warn!(error = %e, "swarm event-triggered reconcile failed");
                    }
                }
                Err(e) => {
                    return Err(GatewayError::Internal(format!("swarm events: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Full reconciliation: list Swarm services, parse labels,
    /// register / unregister as needed.
    async fn reconcile(&self) -> Result<(), GatewayError> {
        let opts = ListServicesOptions::<String> {
            ..Default::default()
        };
        let services = self
            .docker
            .list_services(Some(opts))
            .await
            .map_err(|e| GatewayError::Internal(format!("list swarm services: {e}")))?;

        let mut alive: HashSet<String> = HashSet::new();

        for svc in &services {
            let svc_id = match &svc.id {
                Some(id) => id.clone(),
                None => continue,
            };
            alive.insert(svc_id.clone());

            if let Err(e) = self
                .maybe_register_service(&svc_id, svc.spec.as_ref())
                .await
            {
                tracing::warn!(
                    swarm_service = %svc_id,
                    error = %e,
                    "swarm reconcile register failed"
                );
            }
        }

        // Unregister services we own that are no longer in the Swarm.
        let owned_now: Vec<String> = {
            let map = self.owned.lock().await;
            map.keys().cloned().collect()
        };
        for id in owned_now {
            if !alive.contains(&id) {
                if let Err(e) = self.unregister_service(&id).await {
                    tracing::warn!(
                        swarm_service = %id,
                        error = %e,
                        "swarm reconcile unregister failed"
                    );
                }
            }
        }

        Ok(())
    }

    async fn maybe_register_service(
        &self,
        swarm_id: &str,
        spec: Option<&ServiceSpec>,
    ) -> Result<(), GatewayError> {
        let spec = match spec {
            Some(s) => s,
            None => return Ok(()),
        };

        let labels = spec.labels.clone().unwrap_or_default();
        let svc_name = spec.name.clone().unwrap_or_else(|| swarm_id.to_string());

        // Check constraints.
        if !self.matches_constraints(&labels) {
            return Ok(());
        }

        // Check network filter.
        if !self.config.network.is_empty() && !self.service_in_network(spec) {
            return Ok(());
        }

        let parsed = match parse_swarm_labels(
            &labels,
            self.config.expose_by_default,
            &self.config.default_rule,
            &svc_name,
        ) {
            Some(p) => p,
            None => return Ok(()),
        };

        // Build upstream URL. Swarm services are addressable by their
        // service name on the overlay network, or by VIP.
        let upstream = parsed.upstream_url.unwrap_or_else(|| {
            let port = parsed.port.unwrap_or(80);
            if self.config.use_bind_port_ip {
                format!("http://{}:{}", svc_name, port)
            } else {
                // Use the Swarm DNS name (VIP-backed).
                format!("http://{}:{}", svc_name, port)
            }
        });

        let now = Utc::now();
        let mut owned = self.owned.lock().await;

        let (service_id, route_id) = match owned.get(swarm_id) {
            Some(existing) => (existing.service_id, existing.route_id),
            None => (
                deterministic_uuid(swarm_id, "service"),
                deterministic_uuid(swarm_id, "route"),
            ),
        };

        let service = Service {
            id: service_id,
            name: format!("swarm:{}", parsed.service_name).into(),
            url: upstream,
            retries: parsed.retries,
            connect_timeout_ms: parsed.connect_timeout_ms,
            lb_strategy: "round-robin".to_string(),
            service_type: "api".to_string(),
            document_root: None,
            index_file: "index.html".to_string(),
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
            paths: parsed.paths,
            methods: parsed.methods,
            hosts: parsed.hosts,
            service_id,
            strip_path: parsed.strip_path,
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

        let already_owned = owned.contains_key(swarm_id);
        if already_owned {
            self.repo
                .update_service(&service_id, &service)
                .await
                .map_err(|e| GatewayError::Internal(format!("update service: {e}")))?;
            self.repo
                .update_route(&route_id, &route)
                .await
                .map_err(|e| GatewayError::Internal(format!("update route: {e}")))?;
            self.publish(ChangeEvent::ServiceUpdated {
                id: service_id,
                origin: self.node_id,
            })
            .await;
            self.publish(ChangeEvent::RouteUpdated {
                id: route_id,
                origin: self.node_id,
            })
            .await;
        } else {
            self.repo
                .create_service(&service)
                .await
                .map_err(|e| GatewayError::Internal(format!("create service: {e}")))?;
            self.repo
                .create_route(&route)
                .await
                .map_err(|e| GatewayError::Internal(format!("create route: {e}")))?;
            owned.insert(
                swarm_id.to_string(),
                OwnedRow {
                    service_id,
                    route_id,
                },
            );
            self.publish(ChangeEvent::ServiceCreated {
                id: service_id,
                origin: self.node_id,
            })
            .await;
            self.publish(ChangeEvent::RouteCreated {
                id: route_id,
                origin: self.node_id,
            })
            .await;
            tracing::info!(
                swarm_service = %swarm_id,
                name = %service.name,
                upstream = %service.url,
                "swarm provider registered service"
            );
        }

        Ok(())
    }

    async fn unregister_service(&self, swarm_id: &str) -> Result<(), GatewayError> {
        let row = {
            let mut owned = self.owned.lock().await;
            owned.remove(swarm_id)
        };
        let row = match row {
            Some(r) => r,
            None => return Ok(()),
        };

        let _ = self.repo.delete_route(&row.route_id).await;
        let _ = self.repo.delete_service(&row.service_id).await;
        self.publish(ChangeEvent::RouteDeleted {
            id: row.route_id,
            origin: self.node_id,
        })
        .await;
        self.publish(ChangeEvent::ServiceDeleted {
            id: row.service_id,
            origin: self.node_id,
        })
        .await;
        tracing::info!(swarm_service = %swarm_id, "swarm provider unregistered service");
        Ok(())
    }

    /// Check whether a Swarm service's labels satisfy all configured
    /// constraints.
    fn matches_constraints(&self, labels: &HashMap<String, String>) -> bool {
        for constraint in &self.config.constraints {
            if let Some((key, value)) = constraint.split_once('=') {
                match labels.get(key) {
                    Some(v) if v == value => {}
                    _ => return false,
                }
            }
        }
        true
    }

    /// Check whether a service is attached to the configured overlay
    /// network.
    fn service_in_network(&self, spec: &ServiceSpec) -> bool {
        let networks = match spec
            .task_template
            .as_ref()
            .and_then(|t| t.networks.as_ref())
        {
            Some(n) => n,
            None => return true, // unknown → don't filter
        };

        networks.iter().any(|n| {
            n.target
                .as_ref()
                .map(|t| t == &self.config.network)
                .unwrap_or(false)
        })
    }

    async fn publish(&self, ev: ChangeEvent) {
        if let Err(e) = self.bus.publish(ev).await {
            tracing::warn!(error = %e, "swarm provider cluster publish failed");
        }
    }
}

/// Deterministic UUID derived from Swarm service ID + kind.
fn deterministic_uuid(swarm_id: &str, kind: &str) -> Uuid {
    let mut input = String::with_capacity(swarm_id.len() + kind.len() + 12);
    input.push_str("lynxx:swarm:");
    input.push_str(kind);
    input.push(':');
    input.push_str(swarm_id);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn config_defaults() {
        let cfg = DockerSwarmProviderConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "unix:///var/run/docker.sock");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert!(cfg.network.is_empty());
        assert!(!cfg.expose_by_default);
        assert!(!cfg.use_bind_port_ip);
        assert!(cfg.constraints.is_empty());
        assert_eq!(cfg.default_rule, "Host(`{{.Name}}.localhost`)");
    }

    #[test]
    fn config_deserialize_partial() {
        let json = r#"{
            "enabled": true,
            "network": "lynxx-public",
            "expose_by_default": true
        }"#;
        let cfg: DockerSwarmProviderConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.network, "lynxx-public");
        assert!(cfg.expose_by_default);
        // Defaults fill in the rest.
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.endpoint, "unix:///var/run/docker.sock");
    }

    #[test]
    fn parse_swarm_labels_enable_required() {
        let l = labels(&[("lynxx.service.url", "http://svc:80")]);
        assert!(
            parse_swarm_labels(&l, false, "", "test-svc").is_none(),
            "should skip when expose_by_default is false and no enable label"
        );

        let l = labels(&[
            ("lynxx.enable", "true"),
            ("lynxx.service.url", "http://svc:80"),
        ]);
        let p = parse_swarm_labels(&l, false, "", "test-svc").unwrap();
        assert_eq!(p.upstream_url.as_deref(), Some("http://svc:80"));
    }

    #[test]
    fn parse_swarm_labels_expose_by_default() {
        let l = labels(&[("lynxx.service.url", "http://svc:80")]);
        let p = parse_swarm_labels(&l, true, "", "test-svc").unwrap();
        assert_eq!(p.upstream_url.as_deref(), Some("http://svc:80"));

        // Explicit disable overrides expose_by_default.
        let l = labels(&[
            ("lynxx.enable", "false"),
            ("lynxx.service.url", "http://svc:80"),
        ]);
        assert!(parse_swarm_labels(&l, true, "", "test-svc").is_none());
    }

    #[test]
    fn parse_traefik_style_labels() {
        let l = labels(&[
            ("lynxx.enable", "true"),
            (
                "lynxx.http.routers.myapp.rule",
                "Host(`example.com`) && Host(`www.example.com`)",
            ),
            ("lynxx.http.services.myapp.loadbalancer.server.port", "8080"),
        ]);
        let p = parse_swarm_labels(&l, false, "", "myapp").unwrap();
        assert_eq!(p.port, Some(8080));
        assert_eq!(p.hosts, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn parse_hosts_from_rule_single() {
        let hosts = parse_hosts_from_rule("Host(`api.example.com`)");
        assert_eq!(hosts, vec!["api.example.com"]);
    }

    #[test]
    fn parse_hosts_from_rule_multiple() {
        let hosts = parse_hosts_from_rule("Host(`a.com`) && Host(`b.com`) || Host(`c.com`)");
        assert_eq!(hosts, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn parse_hosts_from_rule_empty() {
        let hosts = parse_hosts_from_rule("PathPrefix(`/api`)");
        assert!(hosts.is_empty());
    }

    #[test]
    fn default_rule_template_substitution() {
        let l = labels(&[("lynxx.enable", "true")]);
        let p = parse_swarm_labels(&l, false, "Host(`{{.Name}}.localhost`)", "my-web-app").unwrap();
        assert_eq!(p.rule.as_deref(), Some("Host(`my-web-app.localhost`)"));
        assert_eq!(p.hosts, vec!["my-web-app.localhost"]);
    }

    #[test]
    fn constraints_matching() {
        let cfg = DockerSwarmProviderConfig {
            constraints: vec!["env=production".to_string(), "team=platform".to_string()],
            ..Default::default()
        };
        // Simulating the constraint check logic from the provider.
        let check = |labels: &HashMap<String, String>| -> bool {
            for constraint in &cfg.constraints {
                if let Some((key, value)) = constraint.split_once('=') {
                    match labels.get(key) {
                        Some(v) if v == value => {}
                        _ => return false,
                    }
                }
            }
            true
        };

        let good = labels(&[("env", "production"), ("team", "platform")]);
        assert!(check(&good));

        let bad = labels(&[("env", "staging"), ("team", "platform")]);
        assert!(!check(&bad));

        let missing = labels(&[("env", "production")]);
        assert!(!check(&missing));
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("swarm-svc-123", "service");
        let b = deterministic_uuid("swarm-svc-123", "service");
        let r = deterministic_uuid("swarm-svc-123", "route");
        assert_eq!(a, b, "same input produces same uuid");
        assert_ne!(a, r, "different kind produces different uuid");
    }
}
