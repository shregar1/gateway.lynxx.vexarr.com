//! Docker provider — watches the Docker Engine API and registers
//! gateway services + routes from container labels.
//!
//! Mirrors Traefik's Docker provider so existing label conventions
//! transfer directly. The minimum viable container looks like this:
//!
//! ```yaml
//! labels:
//!   lynxx.enable: "true"
//!   lynxx.service.url: "http://my-api:3000"
//!   lynxx.route.paths: "/api"
//!   lynxx.route.host: "api.example.com"
//! ```
//!
//! When that container starts, the gateway:
//!
//! 1. Picks up the `containerStart` event from the Docker socket.
//! 2. Parses the `lynxx.*` labels.
//! 3. Calls `repo.create_service` / `repo.create_route` with derived
//!    UUIDs (deterministic from the container ID, so a second start
//!    after a restart re-uses the same gateway-side row).
//! 4. Publishes `ServiceCreated` + `RouteCreated` on the cluster bus.
//! 5. Reloads the route table.
//!
//! When the container dies, the matching service + route are removed
//! the same way.
//!
//! ## Label reference
//!
//! | Label | Default | Meaning |
//! |-------|---------|---------|
//! | `lynxx.enable` | `false` | Container is ignored unless this is `"true"` |
//! | `lynxx.service.name` | container name | Display name of the gateway service |
//! | `lynxx.service.url` | derived from the first published port | Upstream URL |
//! | `lynxx.service.retries` | `3` | Per-request retry budget |
//! | `lynxx.service.connect_timeout_ms` | `2000` | Dial timeout |
//! | `lynxx.route.paths` | `/` | Comma-separated path prefixes |
//! | `lynxx.route.methods` | empty (any) | Comma-separated HTTP methods |
//! | `lynxx.route.host` | empty (any) | Comma-separated host filters |
//! | `lynxx.route.strip_path` | `false` | Strip the path prefix before forwarding |
//!
//! Anything beyond this — multi-route, plugins, mTLS — is operator
//! territory: configure those through the admin API or `config.toml`
//! and let the Docker provider only manage the `(service, route)`
//! plumbing.

use crate::cluster::{ChangeEvent, ClusterBus};
use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Route, Service};
use bollard::container::ListContainersOptions;
use bollard::models::{ContainerSummary, EventMessage};
use bollard::system::EventsOptions;
use bollard::Docker;
use chrono::Utc;
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

/// Configuration for [`DockerProvider`]. Mirrors the fields exposed in
/// `[gateway.providers.docker]` so the provider can be constructed
/// directly from a parsed config block.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct DockerProviderConfig {
    /// Master switch. The provider is a no-op unless this is `true`.
    #[serde(default)]
    pub enabled: bool,
    /// Docker daemon endpoint. Defaults to the platform's default
    /// (Unix socket on Linux/macOS, named pipe on Windows). Examples:
    /// `unix:///var/run/docker.sock`, `tcp://localhost:2375`,
    /// `npipe:////./pipe/docker_engine`.
    #[serde(default)]
    pub endpoint: String,
    /// When set, only containers attached to this Docker network are
    /// considered. Useful when the gateway runs in a separate
    /// `lynxx-public` network and you don't want it discovering every
    /// container on the host. Default: empty (all containers).
    #[serde(default)]
    pub network: String,
    /// Default value to use for `lynxx.enable` when a container has no
    /// label. `false` (Traefik's default) means containers must opt in
    /// explicitly. Set to `true` for "discover everything that
    /// publishes a port" semantics.
    #[serde(default)]
    pub expose_by_default: bool,
    /// Polling fallback interval when the streaming `events` API isn't
    /// available (e.g. older daemons or a flaky connection). The
    /// provider also runs a full reconcile on this cadence regardless,
    /// so a missed event self-heals within `poll_interval_secs`.
    /// Default: 30s.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval() -> u64 {
    30
}

impl Default for DockerProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            network: String::new(),
            expose_by_default: false,
            poll_interval_secs: default_poll_interval(),
        }
    }
}

/// The provider runtime. Owns the Docker client + a handle to the
/// repository and cluster bus so it can converge state when events
/// arrive.
pub struct DockerProvider {
    config: DockerProviderConfig,
    docker: Docker,
    repo: Arc<dyn Repository>,
    bus: Arc<dyn ClusterBus>,
    node_id: Uuid,
    /// Container ID -> (service_id, route_id). Tracks what the
    /// provider has previously registered so we can remove rows when
    /// the container goes away.
    owned: tokio::sync::Mutex<HashMap<String, OwnedRow>>,
}

#[derive(Clone, Debug)]
struct OwnedRow {
    service_id: Uuid,
    route_id: Uuid,
}

impl DockerProvider {
    /// Connect to the Docker daemon at `config.endpoint` (or the
    /// platform default when empty). Errors if the socket isn't
    /// reachable — the caller is expected to surface the error and
    /// keep the gateway running without the provider.
    pub async fn connect(
        config: DockerProviderConfig,
        repo: Arc<dyn Repository>,
        bus: Arc<dyn ClusterBus>,
        node_id: Uuid,
    ) -> Result<Arc<Self>, GatewayError> {
        let docker = if config.endpoint.is_empty() {
            Docker::connect_with_local_defaults()
        } else if config.endpoint.starts_with("tcp://")
            || config.endpoint.starts_with("http://")
            || config.endpoint.starts_with("https://")
        {
            Docker::connect_with_http(&config.endpoint, 4, bollard::API_DEFAULT_VERSION)
        } else {
            // Treat anything else (unix:///, npipe:////) as a local
            // socket path; bollard handles the platform routing.
            Docker::connect_with_local(&config.endpoint, 120, bollard::API_DEFAULT_VERSION)
        }
        .map_err(|e| GatewayError::Internal(format!("docker connect: {e}")))?;

        // Quick handshake so a misconfigured endpoint fails loudly at
        // boot instead of in the watch loop.
        docker
            .ping()
            .await
            .map_err(|e| GatewayError::Internal(format!("docker ping: {e}")))?;

        Ok(Arc::new(Self {
            config,
            docker,
            repo,
            bus,
            node_id,
            owned: tokio::sync::Mutex::new(HashMap::new()),
        }))
    }

    /// Spawn the watch + reconcile loops. Returns immediately. Both
    /// loops back off and retry on transient errors so a flaky Docker
    /// daemon doesn't kill the gateway.
    pub fn spawn(self: Arc<Self>) {
        let reconcile_handle = Arc::clone(&self);
        tokio::spawn(async move {
            // Initial full reconcile so containers that were already
            // running before the gateway started get registered.
            if let Err(e) = reconcile_handle.reconcile().await {
                tracing::warn!(error = %e, "docker provider initial reconcile failed");
            }
            let interval = Duration::from_secs(reconcile_handle.config.poll_interval_secs.max(5));
            loop {
                sleep(interval).await;
                if let Err(e) = reconcile_handle.reconcile().await {
                    tracing::warn!(error = %e, "docker provider reconcile failed");
                }
            }
        });

        let watch_handle = self;
        tokio::spawn(async move {
            // Stream container lifecycle events. We back off on error
            // and reconnect — the reconcile loop above is the
            // safety-net so even a long network blip self-heals.
            loop {
                if let Err(e) = watch_handle.watch_events().await {
                    tracing::warn!(error = %e, "docker provider event stream broke; retrying");
                }
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    /// Stream `containerStart` / `containerDie` events and update the
    /// repository in response.
    async fn watch_events(&self) -> Result<(), GatewayError> {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert(
            "event".to_string(),
            vec!["start".to_string(), "die".to_string()],
        );
        let opts = EventsOptions::<String> {
            filters,
            ..Default::default()
        };

        let mut stream = self.docker.events(Some(opts));
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(ev) => {
                    if let Err(e) = self.handle_event(ev).await {
                        tracing::warn!(error = %e, "docker provider event handler error");
                    }
                }
                Err(e) => {
                    return Err(GatewayError::Internal(format!("docker events: {e}")));
                }
            }
        }
        Ok(())
    }

    async fn handle_event(&self, ev: EventMessage) -> Result<(), GatewayError> {
        let action = ev.action.unwrap_or_default();
        let actor = match ev.actor {
            Some(a) => a,
            None => return Ok(()),
        };
        let container_id = match actor.id {
            Some(id) => id,
            None => return Ok(()),
        };

        match action.as_str() {
            "start" => {
                if let Err(e) = self.register_container(&container_id).await {
                    tracing::warn!(error = %e, container = %container_id, "docker register failed");
                }
            }
            "die" => {
                if let Err(e) = self.unregister_container(&container_id).await {
                    tracing::warn!(error = %e, container = %container_id, "docker unregister failed");
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Full reconciliation: list every container, register the ones
    /// that match `lynxx.enable=true`, and unregister anything we
    /// previously owned that isn't running anymore.
    async fn reconcile(&self) -> Result<(), GatewayError> {
        let opts = ListContainersOptions::<String> {
            all: false, // only running
            ..Default::default()
        };
        let containers = self
            .docker
            .list_containers(Some(opts))
            .await
            .map_err(|e| GatewayError::Internal(format!("list containers: {e}")))?;

        let mut alive: HashSet<String> = HashSet::new();
        for c in &containers {
            if let Some(id) = &c.id {
                alive.insert(id.clone());
            }
            if let Err(e) = self.maybe_register_summary(c).await {
                let id = c.id.as_deref().unwrap_or("?");
                tracing::warn!(error = %e, container = %id, "docker reconcile register failed");
            }
        }

        // Unregister anything we own that's no longer running.
        let owned_now: Vec<String> = {
            let map = self.owned.lock().await;
            map.keys().cloned().collect()
        };
        for id in owned_now {
            if !alive.contains(&id) {
                if let Err(e) = self.unregister_container(&id).await {
                    tracing::warn!(error = %e, container = %id, "docker reconcile unregister failed");
                }
            }
        }
        Ok(())
    }

    async fn maybe_register_summary(&self, c: &ContainerSummary) -> Result<(), GatewayError> {
        let id = match &c.id {
            Some(s) => s.clone(),
            None => return Ok(()),
        };
        let labels = c.labels.clone().unwrap_or_default();
        let derived_url = derive_upstream_url(c);
        self.register_with_labels(&id, &labels, derived_url).await
    }

    async fn register_container(&self, container_id: &str) -> Result<(), GatewayError> {
        let inspect = self
            .docker
            .inspect_container(container_id, None)
            .await
            .map_err(|e| GatewayError::Internal(format!("inspect: {e}")))?;
        let labels = inspect
            .config
            .as_ref()
            .and_then(|c| c.labels.clone())
            .unwrap_or_default();
        let derived_url = derive_upstream_url_from_inspect(&inspect);
        self.register_with_labels(container_id, &labels, derived_url)
            .await
    }

    async fn register_with_labels(
        &self,
        container_id: &str,
        labels: &HashMap<String, String>,
        derived_upstream: Option<String>,
    ) -> Result<(), GatewayError> {
        let parsed = match parse_labels(labels, self.config.expose_by_default) {
            Some(p) => p,
            None => return Ok(()), // not lynxx-managed
        };

        // Optional network filter — only register containers attached
        // to the requested network.
        if !self.config.network.is_empty() {
            let in_network = container_in_network(labels, &self.config.network);
            if !in_network {
                return Ok(());
            }
        }

        let upstream = parsed.upstream_url.or(derived_upstream).ok_or_else(|| {
            GatewayError::ConfigError(format!(
                "container {container_id} has lynxx.enable=true but no \
                 lynxx.service.url and no published port to derive from"
            ))
        })?;

        let now = Utc::now();
        let mut owned = self.owned.lock().await;

        let (service_id, route_id) = match owned.get(container_id) {
            Some(existing) => (existing.service_id, existing.route_id),
            None => (
                deterministic_uuid(container_id, "service"),
                deterministic_uuid(container_id, "route"),
            ),
        };

        let service = Service {
            hide_patterns: vec![],
            id: service_id,
            name: format!("docker:{}", parsed.service_name).into(),
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

        let already_owned = owned.contains_key(container_id);
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
                container_id.to_string(),
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
                container = %container_id,
                service = %service.name,
                upstream = %service.url,
                "docker provider registered service",
            );
        }
        Ok(())
    }

    async fn unregister_container(&self, container_id: &str) -> Result<(), GatewayError> {
        let row = {
            let mut owned = self.owned.lock().await;
            owned.remove(container_id)
        };
        let row = match row {
            Some(r) => r,
            None => return Ok(()), // not ours
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
        tracing::info!(container = %container_id, "docker provider unregistered service");
        Ok(())
    }

    async fn publish(&self, ev: ChangeEvent) {
        if let Err(e) = self.bus.publish(ev).await {
            tracing::warn!(error = %e, "docker provider cluster publish failed");
        }
    }
}

/// Parsed `lynxx.*` labels for a single container.
#[derive(Debug, Clone)]
pub(crate) struct ParsedLabels {
    pub service_name: String,
    pub upstream_url: Option<String>,
    pub retries: u32,
    pub connect_timeout_ms: u64,
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    pub hosts: Vec<String>,
    pub strip_path: bool,
}

/// Parse the `lynxx.*` label set off a container. Returns `None` when
/// the container is not lynxx-managed (i.e. `lynxx.enable` is false /
/// missing and `expose_by_default` is false).
pub(crate) fn parse_labels(
    labels: &HashMap<String, String>,
    expose_by_default: bool,
) -> Option<ParsedLabels> {
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
        .unwrap_or_else(|| {
            // Fall back to the Docker container name (without leading
            // slash). Some older daemons stash that in the
            // `com.docker.compose.service` label too.
            labels
                .get("com.docker.compose.service")
                .cloned()
                .unwrap_or_else(|| "unnamed".into())
        });

    let upstream_url = labels.get("lynxx.service.url").cloned();
    let retries = labels
        .get("lynxx.service.retries")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let connect_timeout_ms = labels
        .get("lynxx.service.connect_timeout_ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);

    let paths = csv(labels.get("lynxx.route.paths"))
        .or_else(|| Some(vec!["/".to_string()]))
        .unwrap_or_default();
    let methods = csv(labels.get("lynxx.route.methods")).unwrap_or_default();
    let hosts = csv(labels.get("lynxx.route.host"))
        .or_else(|| csv(labels.get("lynxx.route.hosts")))
        .unwrap_or_default();
    let strip_path = labels
        .get("lynxx.route.strip_path")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);

    Some(ParsedLabels {
        service_name,
        upstream_url,
        retries,
        connect_timeout_ms,
        paths,
        methods,
        hosts,
        strip_path,
    })
}

fn csv(value: Option<&String>) -> Option<Vec<String>> {
    value.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
}

/// Derive the upstream URL from a container's published port — used
/// when `lynxx.service.url` isn't set. Picks the first TCP port the
/// container is listening on; the gateway addresses it via the
/// container's primary IP on its first network.
fn derive_upstream_url(c: &ContainerSummary) -> Option<String> {
    let networks = c
        .network_settings
        .as_ref()
        .and_then(|s| s.networks.as_ref())?;
    let (_, net) = networks.iter().next()?;
    let ip = net.ip_address.clone()?;
    if ip.is_empty() {
        return None;
    }
    let ports = c.ports.as_ref()?;
    let port = ports.iter().map(|p| p.private_port).find(|&p| p != 0)?;
    Some(format!("http://{ip}:{port}"))
}

fn derive_upstream_url_from_inspect(
    inspect: &bollard::secret::ContainerInspectResponse,
) -> Option<String> {
    let ip = inspect
        .network_settings
        .as_ref()
        .and_then(|s| s.networks.as_ref())
        .and_then(|n| n.values().next())
        .and_then(|n| n.ip_address.clone())?;
    if ip.is_empty() {
        return None;
    }
    let port = inspect
        .config
        .as_ref()
        .and_then(|c| c.exposed_ports.as_ref())
        .and_then(|map| map.keys().next())
        .and_then(|k| k.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())?;
    Some(format!("http://{ip}:{port}"))
}

fn container_in_network(labels: &HashMap<String, String>, network: &str) -> bool {
    // The network membership isn't directly in labels, but Compose
    // surfaces it in `com.docker.compose.network`. For the inspect
    // path we'd check NetworkSettings.networks; the conservative call
    // is to treat unknown as in-network so we don't drop traffic for
    // people who haven't set the label.
    match labels.get("com.docker.compose.network") {
        Some(n) => n == network,
        None => true,
    }
}

/// UUID v5 derived from `(namespace, container_id, kind)`. Re-deriving
/// across restarts means the gateway upserts the same row instead of
/// piling on duplicates.
fn deterministic_uuid(container_id: &str, kind: &str) -> Uuid {
    // UUID v5 with the URL namespace.
    let mut input = String::with_capacity(container_id.len() + kind.len() + 8);
    input.push_str("lynxx:docker:");
    input.push_str(kind);
    input.push(':');
    input.push_str(container_id);
    Uuid::new_v5(&Uuid::NAMESPACE_URL, input.as_bytes())
}

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
    fn parse_labels_enable_required() {
        let l = labels(&[("lynxx.service.url", "http://x:1")]);
        assert!(parse_labels(&l, false).is_none());

        let l = labels(&[
            ("lynxx.enable", "true"),
            ("lynxx.service.url", "http://x:1"),
        ]);
        let p = parse_labels(&l, false).unwrap();
        assert_eq!(p.upstream_url.as_deref(), Some("http://x:1"));
    }

    #[test]
    fn parse_labels_expose_by_default() {
        let l = labels(&[("lynxx.service.url", "http://x:1")]);
        let p = parse_labels(&l, true).unwrap();
        assert_eq!(p.upstream_url.as_deref(), Some("http://x:1"));

        // explicit false still wins
        let l = labels(&[
            ("lynxx.enable", "false"),
            ("lynxx.service.url", "http://x:1"),
        ]);
        assert!(parse_labels(&l, true).is_none());
    }

    #[test]
    fn parse_labels_csv_lists() {
        let l = labels(&[
            ("lynxx.enable", "true"),
            ("lynxx.service.url", "http://x:1"),
            ("lynxx.route.paths", "/api,/v1, /v2"),
            ("lynxx.route.methods", "GET, POST"),
            ("lynxx.route.host", "api.example.com"),
            ("lynxx.route.strip_path", "true"),
        ]);
        let p = parse_labels(&l, false).unwrap();
        assert_eq!(p.paths, vec!["/api", "/v1", "/v2"]);
        assert_eq!(p.methods, vec!["GET", "POST"]);
        assert_eq!(p.hosts, vec!["api.example.com"]);
        assert!(p.strip_path);
    }

    #[test]
    fn parse_labels_default_path_root() {
        let l = labels(&[
            ("lynxx.enable", "true"),
            ("lynxx.service.url", "http://x:1"),
        ]);
        let p = parse_labels(&l, false).unwrap();
        assert_eq!(p.paths, vec!["/"]);
    }

    #[test]
    fn parse_labels_service_name_fallback_to_compose() {
        let l = labels(&[
            ("lynxx.enable", "true"),
            ("lynxx.service.url", "http://x:1"),
            ("com.docker.compose.service", "user-svc"),
        ]);
        let p = parse_labels(&l, false).unwrap();
        assert_eq!(p.service_name, "user-svc");
    }

    #[test]
    fn deterministic_uuid_is_stable_per_container() {
        let a1 = deterministic_uuid("abc123", "service");
        let a2 = deterministic_uuid("abc123", "service");
        let r = deterministic_uuid("abc123", "route");
        assert_eq!(a1, a2, "same input → same uuid");
        assert_ne!(a1, r, "kind separates namespaces");
    }
}
