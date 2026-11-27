//! Hot config reload.
//!
//! Re-reads `config.toml`, diffs it against the DB state for services / routes
//! / plugin records, and applies the diff (insert / update / delete) — both in
//! the persistent store and in the live in-memory `RouteTable`,
//! `HealthRegistry`, and `LoadBalancerRegistry`. Triggered by SIGHUP or
//! `POST /reload`. Reloads are serialised through a single mpsc receiver, so
//! at most one runs at a time.
//!
//! Reload syncs services, routes, and global (unscoped) plugin records from
//! `config.toml`. Service- and route-scoped plugins are owned exclusively by
//! the admin API and are not touched here. After a plugin diff, the in-memory
//! `PluginExecutor` cache is rebuilt so live behaviour reflects the new
//! configuration. Consumers and targets are managed exclusively via the admin
//! API.

use crate::cluster::{ChangeEvent, ClusterBus};
use crate::config::{load_config, GatewayConfig};
use crate::db::Repository;
use crate::error::GatewayError;
use crate::health::HealthRegistry;
use crate::models::{PluginInstance, Route, Service};
use crate::plugins::PluginExecutor;
use crate::proxy::loadbalancer::{LbStrategy, LoadBalancerRegistry};
use crate::proxy::router::SharedRouteTable;
use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReloadResult {
    pub added_services: usize,
    pub updated_services: usize,
    pub removed_services: usize,
    pub added_routes: usize,
    pub updated_routes: usize,
    pub removed_routes: usize,
    pub added_plugins: usize,
    pub updated_plugins: usize,
    pub removed_plugins: usize,
    pub errors: Vec<String>,
}

type Trigger = oneshot::Sender<ReloadResult>;

#[derive(Clone)]
pub struct ReloadHandle {
    tx: mpsc::Sender<Trigger>,
}

impl ReloadHandle {
    pub async fn trigger(&self) -> Result<ReloadResult, GatewayError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(resp_tx)
            .await
            .map_err(|_| GatewayError::Internal("reload task is gone".into()))?;
        resp_rx
            .await
            .map_err(|_| GatewayError::Internal("reload task dropped response".into()))
    }

    #[cfg(test)]
    pub fn dummy() -> Self {
        let (tx, _) = mpsc::channel(1);
        Self { tx }
    }
}

pub fn spawn_reloader(
    config_path: String,
    repo: Arc<dyn Repository>,
    route_table: SharedRouteTable,
    health: Arc<HealthRegistry>,
    lb: Arc<LoadBalancerRegistry>,
    plugin_exec: Arc<PluginExecutor>,
    bus: Arc<dyn ClusterBus>,
    node_id: Uuid,
) -> ReloadHandle {
    let (tx, mut rx) = mpsc::channel::<Trigger>(8);

    tokio::spawn(async move {
        use futures_util::FutureExt;
        while let Some(resp) = rx.recv().await {
            tracing::info!(path = %config_path, "config reload starting");
            // Isolate each reload behind catch_unwind: a panic in run_reload
            // would otherwise unwind this task entirely, dropping the receiver
            // and permanently disabling ALL future config reloads until the
            // process restarts. Surfacing it as an error result keeps the
            // reloader alive for the next trigger.
            let result = match std::panic::AssertUnwindSafe(run_reload(
                &config_path,
                &repo,
                &route_table,
                &health,
                &lb,
                &plugin_exec,
            ))
            .catch_unwind()
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    tracing::error!(
                        "config reload panicked; reloader stays alive for future triggers"
                    );
                    ReloadResult {
                        errors: vec!["config reload panicked".to_string()],
                        ..Default::default()
                    }
                }
            };
            tracing::info!(?result, "config reload complete");
            if result.errors.is_empty() {
                if let Err(e) = bus.publish(ChangeEvent::FullSync { origin: node_id }).await {
                    tracing::warn!(error = %e, "failed to publish FullSync after reload");
                }
            }
            let _ = resp.send(result);
        }
    });

    ReloadHandle { tx }
}

#[cfg(unix)]
pub fn install_sighup_handler(handle: ReloadHandle) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to install SIGHUP handler: {e}");
                return;
            }
        };
        while sig.recv().await.is_some() {
            tracing::info!("SIGHUP received; triggering reload");
            if let Err(e) = handle.trigger().await {
                tracing::error!("reload via SIGHUP failed: {e}");
            }
        }
    });
}

#[cfg(not(unix))]
pub fn install_sighup_handler(_handle: ReloadHandle) {
    tracing::info!("SIGHUP not available on this platform; use POST /reload");
}

async fn run_reload(
    config_path: &str,
    repo: &Arc<dyn Repository>,
    route_table: &SharedRouteTable,
    health: &Arc<HealthRegistry>,
    lb: &Arc<LoadBalancerRegistry>,
    plugin_exec: &Arc<PluginExecutor>,
) -> ReloadResult {
    let mut result = ReloadResult::default();

    let new_config = match load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("parse config: {e}"));
            return result;
        }
    };

    if let Err(e) = diff_services(&new_config, repo, route_table, health, lb, &mut result).await {
        result.errors.push(format!("services: {e}"));
    }
    if let Err(e) = diff_routes(&new_config, repo, route_table, &mut result).await {
        result.errors.push(format!("routes: {e}"));
    }
    if let Err(e) = diff_plugins(&new_config, repo, &mut result).await {
        result.errors.push(format!("plugins: {e}"));
    }

    if result.added_plugins + result.updated_plugins + result.removed_plugins > 0 {
        if let Err(e) = plugin_exec.rebuild(repo).await {
            result.errors.push(format!("plugin rebuild: {e}"));
        }
    }

    // ── Fast path sync ──────────────────────────────────────────────────────
    // After the route table has been reconciled, rebuild the fast-path routing
    // table from the live route snapshot. Also apply the FastPathSettings flags
    // (enabled / mode) so operator config changes take effect immediately.
    if result.errors.is_empty() {
        let fp = &new_config.gateway.fast_path;
        let mode = match fp.mode.as_str() {
            "splice"         => crate::proxy::fast_path::FastPathMode::Splice,
            "buffered_copy"  => crate::proxy::fast_path::FastPathMode::BufferedCopy,
            "off"            => crate::proxy::fast_path::FastPathMode::Off,
            _                => crate::proxy::fast_path::FastPathMode::Auto,
        };
        // Update the global atomic toggles.
        let effective_enabled = fp.enabled && mode != crate::proxy::fast_path::FastPathMode::Off;
        crate::proxy::fast_path::set_fast_path_enabled(effective_enabled);
        crate::proxy::fast_path::set_fast_path_mode(mode);

        // ── Workers settings sync ────────────────────────────────────────
        // The worker model + CPU pinning + RLIMIT_NOFILE controls are
        // (re-)applied on every reload. The model + pinning flags take
        // effect on the NEXT listener bind (i.e. the next process
        // restart — they aren't hot-pluggable on a running socket); the
        // rlimit raise IS hot-pluggable and a `setrlimit` raise takes
        // effect immediately across the process.
        let workers = &new_config.gateway.workers;
        match crate::proxy::worker::apply_workers_settings(
            &workers.model,
            workers.cpu_pinning,
            workers.rlimit_nofile,
        ) {
            Ok(()) => {}
            Err(e) => tracing::warn!(
                error = %e,
                "workers: invalid reload config; keeping previous settings"
            ),
        }

        if effective_enabled {
            // Build a list of route specs from the current route table.
            let routes_snapshot: Vec<crate::proxy::fast_path::FastPathRouteSpec> = {
                // Fetch services for URL → upstream mapping.
                let services: HashMap<uuid::Uuid, crate::models::Service> =
                    match repo.list_services().await {
                        Ok(svcs) => svcs.into_iter().map(|s| (s.id, s)).collect(),
                        Err(e) => {
                            tracing::warn!(error = %e, "fast_path: failed to list services for sync");
                            HashMap::new()
                        }
                    };
                match repo.list_routes().await {
                    Ok(rt_routes) => rt_routes
                        .into_iter()
                        .filter_map(|r| {
                            let svc = services.get(&r.service_id)?;
                            // Determine upstream address from service URL.
                            let upstream_addr = svc_url_to_addr(&svc.url)?;
                            // Use first path as the prefix; multi-path routes
                            // are represented as separate entries per-path.
                            let specs: Vec<_> = r.paths.iter().map(|path| {
                                let profile = crate::proxy::fast_path::RouteProfile {
                                    route_id: r.id.to_string(),
                                    service_id: svc.id.to_string(),
                                    plugin_count: 0, // global plugin check is done separately
                                    has_header_add: r.headers.iter().any(|(_, v)| !v.is_empty()),
                                    has_header_remove: false,
                                    has_header_replace: false,
                                    has_path_rewrite: r.path_rewrite_pattern.is_some(),
                                    has_body_buffering: r.buffer_request,
                                    has_request_transform: false,
                                    has_response_transform: false,
                                    has_auth: false,
                                    has_rate_limit: false,
                                    upstream_is_tls: svc.url.starts_with("https://"),
                                    is_websocket: false,
                                    is_grpc: false,
                                };
                                crate::proxy::fast_path::FastPathRouteSpec {
                                    route_id: r.id.to_string(),
                                    path_prefix: path.clone(),
                                    upstream_addr: upstream_addr.clone(),
                                    host: r.hosts.first().cloned(),
                                    profile,
                                }
                            }).collect();
                            Some(specs)
                        })
                        .flatten()
                        .collect(),
                    Err(e) => {
                        tracing::warn!(error = %e, "fast_path: failed to list routes for sync");
                        Vec::new()
                    }
                }
            };

            crate::proxy::fast_path::sync_fast_path_routes(&routes_snapshot);
            tracing::info!(
                routes = routes_snapshot.len(),
                "fast_path: routing table synced after reload"
            );
        } else {
            // Disabled — clear the table.
            crate::proxy::fast_path::sync_fast_path_routes(&[]);
        }
    }

    result
}

/// Extract `host:port` from an HTTP service URL for direct TCP forwarding.
/// Returns `None` for non-HTTP/HTTPS URLs or if parsing fails.
fn svc_url_to_addr(url: &str) -> Option<String> {
    let stripped = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        return None;
    };
    // Take only the authority part (before any path).
    let authority = stripped.split('/').next()?;
    if authority.contains(':') {
        Some(authority.to_string())
    } else {
        // No explicit port — use default for scheme.
        let port = if url.starts_with("https://") { 443u16 } else { 80u16 };
        Some(format!("{authority}:{port}"))
    }
}

// ---------- services ----------

async fn diff_services(
    cfg: &GatewayConfig,
    repo: &Arc<dyn Repository>,
    route_table: &SharedRouteTable,
    health: &Arc<HealthRegistry>,
    lb: &Arc<LoadBalancerRegistry>,
    result: &mut ReloadResult,
) -> Result<(), GatewayError> {
    let existing = repo.list_services().await?;
    // Index existing services by name. Use `Arc<str>` as the key (matching
    // the model field type) so the lookup is a pointer-key hash rather than
    // re-allocating a `String` per row.
    let by_name: HashMap<Arc<str>, Service> = existing
        .iter()
        .map(|s| (s.name.clone(), s.clone()))
        .collect();
    let cfg_names: std::collections::HashSet<&str> =
        cfg.services.iter().map(|s| s.name.as_str()).collect();

    for svc_cfg in &cfg.services {
        // `by_name` is keyed by `Arc<str>`; `svc_cfg.name` is a `String` from
        // the config. Look up via &str (Arc<str>: Borrow<str>) to avoid an
        // alloc and the missing Borrow<String> impl.
        match by_name.get(svc_cfg.name.as_str()) {
            Some(cur) => {
                if cur.url != svc_cfg.url
                    || cur.retries != svc_cfg.retries
                    || cur.connect_timeout_ms != svc_cfg.connect_timeout_ms
                {
                    let url_changed = cur.url != svc_cfg.url;
                    let updated = Service { hide_patterns: vec![],
            
            
                        id: cur.id,
                        name: cur.name.clone(),
                        url: svc_cfg.url.clone(),
                        retries: svc_cfg.retries,
                        connect_timeout_ms: svc_cfg.connect_timeout_ms,
                        lb_strategy: cur.lb_strategy.clone(),
                        service_type: cur.service_type.clone(),
                        document_root: cur.document_root.clone(),
                        index_file: cur.index_file.clone(),
                        spa_fallback: cur.spa_fallback,
                        tls_verify: cur.tls_verify,
                        tls_client_cert_path: cur.tls_client_cert_path.clone(),
                        tls_client_key_path: cur.tls_client_key_path.clone(),
                        tls_ca_path: cur.tls_ca_path.clone(),
                        lb_hash_header: cur.lb_hash_header.clone(),
                        lb_hash_query_param: cur.lb_hash_query_param.clone(),
                        flush_interval_ms: cur.flush_interval_ms,
                        stream_timeout_ms: cur.stream_timeout_ms,
                        stream_close_delay_ms: cur.stream_close_delay_ms,
                        pass_host_header: cur.pass_host_header,
                        force_http_version: cur.force_http_version.clone(),
                        pool_idle_floor: cur.pool_idle_floor,
                        drain_timeout_ms: None,
                        project_id: cur.project_id,
                        domain: cur.domain.clone(),
                        subdomain: cur.subdomain.clone(),
                        created_at: cur.created_at,
                        updated_at: Utc::now(),
                    };
                    match repo.update_service(&cur.id, &updated).await {
                        Ok(_) => {
                            route_table.update_service(&cur.id, updated);
                            if url_changed {
                                health.reset_on_upstream_change(
                                    &cur.id,
                                    &cur.name,
                                    "upstream URL changed",
                                );
                            }
                            result.updated_services += 1;
                        }
                        Err(e) => result
                            .errors
                            .push(format!("update service {}: {e}", cur.name)),
                    }
                }
            }
            None => {
                let svc = Service::new(
                    svc_cfg.name.clone(),
                    svc_cfg.url.clone(),
                    svc_cfg.retries,
                    svc_cfg.connect_timeout_ms,
                );
                match repo.create_service(&svc).await {
                    Ok(_) => {
                        route_table.add_service(svc.clone());
                        health.register(svc.id);
                        lb.rebuild_for_service(
                            svc.id,
                            LbStrategy::from_str(&svc.lb_strategy),
                            Vec::new(),
                        );
                        result.added_services += 1;
                    }
                    Err(e) => result
                        .errors
                        .push(format!("create service {}: {e}", svc.name)),
                }
            }
        }
    }

    for cur in &existing {
        if cfg_names.contains(&*cur.name) {
            continue;
        }
        match repo.delete_service(&cur.id).await {
            Ok(true) => {
                route_table.remove_service(&cur.id);
                health.unregister(&cur.id);
                lb.remove_service(&cur.id);
                result.removed_services += 1;
            }
            Ok(false) => {}
            Err(e) => result
                .errors
                .push(format!("delete service {}: {e}", cur.name)),
        }
    }

    Ok(())
}

// ---------- routes ----------

fn route_key(service_name: &str, paths: &[String]) -> String {
    let mut p = paths.to_vec();
    p.sort();
    format!("{service_name}|{}", p.join(","))
}

async fn diff_routes(
    cfg: &GatewayConfig,
    repo: &Arc<dyn Repository>,
    route_table: &SharedRouteTable,
    result: &mut ReloadResult,
) -> Result<(), GatewayError> {
    // service name -> id, refreshed post-service-diff.
    let services = repo.list_services().await?;
    let svc_id_by_name: HashMap<Arc<str>, Uuid> =
        services.iter().map(|s| (s.name.clone(), s.id)).collect();
    let svc_name_by_id: HashMap<Uuid, Arc<str>> =
        services.iter().map(|s| (s.id, s.name.clone())).collect();

    let existing = repo.list_routes().await?;
    let mut by_key: HashMap<String, Route> = HashMap::new();
    for r in &existing {
        if let Some(name) = svc_name_by_id.get(&r.service_id) {
            by_key.insert(route_key(name, &r.paths), r.clone());
        }
    }

    let mut wanted_keys = std::collections::HashSet::new();

    for rt_cfg in &cfg.routes {
        let Some(service_id) = svc_id_by_name.get(rt_cfg.service.as_str()).copied() else {
            result
                .errors
                .push(format!("route refs unknown service {}", rt_cfg.service));
            continue;
        };
        let key = route_key(&rt_cfg.service, &rt_cfg.paths);
        wanted_keys.insert(key.clone());

        match by_key.get(&key) {
            Some(cur) => {
                if cur.methods != rt_cfg.methods
                    || cur.hosts != rt_cfg.hosts
                    || cur.strip_path != rt_cfg.strip_path
                    || cur.service_id != service_id
                {
                    let updated = Route {
                        id: cur.id,
                        paths: cur.paths.clone(),
                        methods: rt_cfg.methods.clone(),
                        hosts: rt_cfg.hosts.clone(),
                        service_id,
                        strip_path: rt_cfg.strip_path,
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
                        created_at: cur.created_at,
                        updated_at: Utc::now(),
                    };
                    match repo.update_route(&cur.id, &updated).await {
                        Ok(_) => {
                            route_table.update_route(&cur.id, updated);
                            result.updated_routes += 1;
                        }
                        Err(e) => result.errors.push(format!("update route {}: {e}", cur.id)),
                    }
                }
            }
            None => {
                let route = Route::new(
                    rt_cfg.paths.clone(),
                    rt_cfg.methods.clone(),
                    rt_cfg.hosts.clone(),
                    service_id,
                    rt_cfg.strip_path,
                );
                match repo.create_route(&route).await {
                    Ok(_) => {
                        route_table.add_route(route);
                        result.added_routes += 1;
                    }
                    Err(e) => result.errors.push(format!("create route: {e}")),
                }
            }
        }
    }

    for (key, cur) in &by_key {
        if wanted_keys.contains(key) {
            continue;
        }
        match repo.delete_route(&cur.id).await {
            Ok(true) => {
                route_table.remove_route(&cur.id);
                result.removed_routes += 1;
            }
            Ok(false) => {}
            Err(e) => result.errors.push(format!("delete route {}: {e}", cur.id)),
        }
    }

    Ok(())
}

// ---------- plugins (DB records only — see module-level note) ----------

async fn diff_plugins(
    cfg: &GatewayConfig,
    repo: &Arc<dyn Repository>,
    result: &mut ReloadResult,
) -> Result<(), GatewayError> {
    // Reload only manages global (unscoped) plugins; service- and route-scoped
    // plugins are owned by the admin API and left alone here.
    let existing: Vec<PluginInstance> = repo
        .list_plugins()
        .await?
        .into_iter()
        .filter(|p| p.service_id.is_none() && p.route_id.is_none())
        .collect();
    let by_name: HashMap<String, PluginInstance> = existing
        .iter()
        .map(|p| (p.name.clone(), p.clone()))
        .collect();
    let cfg_names: std::collections::HashSet<&str> =
        cfg.plugins.iter().map(|p| p.name.as_str()).collect();

    for plugin_cfg in &cfg.plugins {
        let new_config =
            serde_json::to_value(&plugin_cfg.config).unwrap_or(serde_json::Value::Null);
        match by_name.get(&plugin_cfg.name) {
            Some(cur) => {
                if cur.enabled != plugin_cfg.enabled || cur.config != new_config {
                    let updated = PluginInstance {
                        id: cur.id,
                        name: cur.name.clone(),
                        service_id: cur.service_id,
                        route_id: cur.route_id,
                        enabled: plugin_cfg.enabled,
                        config: new_config,
                        created_at: cur.created_at,
                        updated_at: Utc::now(),
                    };
                    match repo.update_plugin(&cur.id, &updated).await {
                        Ok(_) => result.updated_plugins += 1,
                        Err(e) => result
                            .errors
                            .push(format!("update plugin {}: {e}", plugin_cfg.name)),
                    }
                }
            }
            None => {
                let now = Utc::now();
                let plugin = PluginInstance {
                    id: Uuid::new_v4(),
                    name: plugin_cfg.name.clone(),
                    service_id: None,
                    route_id: None,
                    enabled: plugin_cfg.enabled,
                    config: new_config,
                    created_at: now,
                    updated_at: now,
                };
                match repo.create_plugin(&plugin).await {
                    Ok(_) => result.added_plugins += 1,
                    Err(e) => result
                        .errors
                        .push(format!("create plugin {}: {e}", plugin_cfg.name)),
                }
            }
        }
    }

    for cur in &existing {
        if cfg_names.contains(&*cur.name) {
            continue;
        }
        match repo.delete_plugin(&cur.id).await {
            Ok(true) => result.removed_plugins += 1,
            Ok(false) => {}
            Err(e) => result
                .errors
                .push(format!("delete plugin {}: {e}", cur.name)),
        }
    }

    Ok(())
}
