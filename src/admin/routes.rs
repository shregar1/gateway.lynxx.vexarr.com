use crate::audit::{AuditAction, AuditEntry, AuditFilter, AuditLog, ResourceType};
use crate::auth::middleware::CurrentActor;
use crate::auth::{generate_token, hash_token, AdminToken, Role};
use crate::cluster::{ChangeEvent, ClusterBus};
use crate::db::{AdminTokenPatch, LogFilter, NewAdminToken, Repository};
use crate::error::{GatewayError, PluginError};
use crate::health::{HealthRegistry, ServiceHealth, StatusCache};
use crate::integrations::abstraction::VerifierError;
use crate::models::{Consumer, LogEntry, PluginInstance, Project, Route, Service, Target};
use crate::plugins::PluginExecutor;
use crate::proxy::http_client::ProxyClientPool;
use crate::proxy::loadbalancer::{LbStrategy, LoadBalancerRegistry};
use crate::proxy::router::SharedRouteTable;
use crate::quota::QuotaTracker;
use crate::reload::{ReloadHandle, ReloadResult};
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AdminState {
    pub route_table: SharedRouteTable,
    pub repo: Arc<dyn Repository>,
    pub health: Arc<HealthRegistry>,
    pub lb: Arc<LoadBalancerRegistry>,
    pub start_time: chrono::DateTime<Utc>,
    pub metrics_handle: PrometheusHandle,
    pub reload: ReloadHandle,
    pub plugin_exec: Arc<PluginExecutor>,
    pub bus: Arc<dyn ClusterBus>,
    pub node_id: Uuid,
    pub audit: AuditLog,
    /// If true, force authentication regardless of whether any tokens exist
    /// in the DB. When false, the gateway runs in bootstrap mode while the
    /// `admin_tokens` table is empty.
    pub auth_required: bool,
    /// Per-service hyper-util client cache. Mutating service TLS config
    /// here invalidates the corresponding cached entry so the next
    /// request rebuilds with fresh certs.
    pub client_pool: Arc<ProxyClientPool>,
    /// Content-addressed store for full Recording payloads. Used by the
    /// /recordings/:id and /recordings/:id/replay endpoints; the index
    /// (list / delete) lives in the repository.
    pub recording_store: Arc<crate::recording::ContentAddressedStore>,
    /// Reqwest client used by the replay endpoint when firing the
    /// recorded request at a target URL. Separate from the proxy hot-path
    /// client because replays go out-of-band, can be slow, and don't need
    /// the per-service TLS cache.
    pub http_client: reqwest::Client,
    /// Local proxy port. Used to default the replay target URL to "this
    /// gateway" when the operator doesn't pass `target_url` explicitly.
    pub proxy_port: u16,
    /// Monthly quota tracker. Shared with the proxy handler; the admin API
    /// exposes a read-only snapshot at GET /quota.
    pub quota: Arc<QuotaTracker>,
    /// ACME / cert manager. `None` when `[gateway.acme].enabled = false`.
    /// When present, the `/acme/*` admin endpoints delegate challenge
    /// registration here so HTTP-01 *and* TLS-ALPN-01 validators can
    /// run against the live gateway without a restart.
    pub acme: Option<Arc<crate::proxy::acme::AcmeManager>>,
    /// The Lynxx license API key from config/env. Accepted as a valid
    /// master admin credential so customers can use the key they already
    /// have from their account dashboard without creating a separate token.
    pub license_api_key: String,
    pub license_state: Option<crate::license::LicenseState>,
    pub deploy_registry: Option<crate::admin::deploy::DeployRegistry>,
    pub status_cache: StatusCache,
    /// Optional token-validator backend (typically a keyx client,
    /// behind the [`crate::integrations::TokenValidator`] trait so
    /// the admin layer doesn't know the concrete impl). When `Some`,
    /// the admin-auth middleware falls through to this validator
    /// after the local `admin_tokens` table lookup misses. `None`
    /// keeps the local-only flow.
    pub token_validator: Option<std::sync::Arc<dyn crate::integrations::TokenValidator>>,
    /// Short-TTL cache for verifier-validated admin tokens. `None`
    /// when caching is disabled (TTL = 0); `Some` otherwise. Cap on
    /// revocation staleness equals the TTL.
    pub token_cache: Option<std::sync::Arc<crate::auth::middleware::AdminAuthCache>>,
    pub userx_client: Option<std::sync::Arc<utilx::vexarr::client::UserxClient>>,
}

/// Convenience: extract the optional actor from request extensions.
fn actor_of(actor: &CurrentActor) -> Option<&AdminToken> {
    actor.0.as_ref()
}

/// Publish a ChangeEvent on the cluster bus, logging but never failing the
/// admin call if the bus is unhappy. We've already committed to the DB; the
/// remote nodes will eventually reconcile via the next event or restart.
async fn publish_event(state: &AdminState, event: ChangeEvent) {
    if let Err(e) = state.bus.publish(event).await {
        tracing::warn!(error = %e, "failed to publish cluster event");
    }
}

async fn cascade_soft_delete_route(state: &AdminState, route_id: Uuid) {
    if let Err(e) = state.repo.soft_delete_plugins_for_route(&route_id).await {
        tracing::warn!(route_id = %route_id, error = %e, "cascade: failed to soft-delete plugins for route");
    }
    state.route_table.remove_route(&route_id);
}

async fn cascade_soft_delete_service(state: &AdminState, service_id: Uuid) {
    match state.repo.soft_delete_routes_for_service(&service_id).await {
        Ok(route_ids) => {
            for rid in &route_ids {
                if let Err(e) = state.repo.soft_delete_plugins_for_route(rid).await {
                    tracing::warn!(route_id = %rid, error = %e, "cascade: failed to soft-delete plugins for route");
                }
                state.route_table.remove_route(rid);
            }
        }
        Err(e) => {
            tracing::warn!(service_id = %service_id, error = %e, "cascade: failed to soft-delete routes for service");
        }
    }
    if let Err(e) = state
        .repo
        .soft_delete_targets_for_service(&service_id)
        .await
    {
        tracing::warn!(service_id = %service_id, error = %e, "cascade: failed to soft-delete targets for service");
    }
    if let Err(e) = state
        .repo
        .soft_delete_plugins_for_service(&service_id)
        .await
    {
        tracing::warn!(service_id = %service_id, error = %e, "cascade: failed to soft-delete plugins for service");
    }
    state.route_table.remove_service(&service_id);
    state.health.unregister(&service_id);
    state.lb.remove_service(&service_id);
    state.client_pool.invalidate(&service_id);
}

/// Build an ETag from entity id + updated_at.
fn entity_etag(id: &Uuid, updated_at: &DateTime<Utc>) -> String {
    format!("\"{}:{}\"", id.simple(), updated_at.timestamp_millis())
}

/// Return a JSON response with an ETag header.
fn json_with_etag<T: Serialize>(entity: T, etag: &str) -> Response {
    let body = serde_json::to_string(&entity).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Check If-Match header against current ETag. Returns Err(412) on mismatch.
fn check_if_match(headers: &HeaderMap, current_etag: &str) -> Result<(), GatewayError> {
    if let Some(if_match) = headers.get(header::IF_MATCH) {
        let val = if_match.to_str().unwrap_or("");
        if val != "*" && val != current_etag {
            return Err(GatewayError::PreconditionFailed(
                "ETag mismatch — the resource was modified since you last fetched it".into(),
            ));
        }
    }
    Ok(())
}

pub async fn reload_handler(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<ReloadResult>, GatewayError> {
    let result = state.reload.trigger().await?;
    state
        .audit
        .record(
            AuditAction::Reload,
            ResourceType::Config,
            None,
            None,
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::FullSync {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct CreateService {
            
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default)]
    pub lb_strategy: Option<String>,
    #[serde(default)]
    pub service_type: Option<String>,
    #[serde(default)]
    pub document_root: Option<String>,
    #[serde(default)]
    pub index_file: Option<String>,
    #[serde(default)]
    pub spa_fallback: Option<bool>,
    #[serde(default)]
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub subdomain: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateTarget {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub zone: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateTarget {
    pub url: Option<String>,
    pub weight: Option<u32>,
    pub enabled: Option<bool>,
    pub zone: Option<String>,
}

fn default_weight() -> u32 {
    1
}

fn default_retries() -> u32 {
    3
}
fn default_timeout() -> u64 {
    5000
}

#[derive(Deserialize)]
pub struct CreateRoute {
    pub paths: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub service_id: Uuid,
    #[serde(default)]
    pub strip_path: bool,
}

#[derive(Deserialize)]
pub struct PatchRoute {
    pub paths: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
    pub hosts: Option<Vec<String>>,
    pub service_id: Option<Uuid>,
    pub strip_path: Option<bool>,
}

#[derive(Deserialize)]
pub struct PatchService {
            
    pub name: Option<String>,
    pub url: Option<String>,
    pub retries: Option<u32>,
    pub connect_timeout_ms: Option<u64>,
    pub lb_strategy: Option<String>,
    pub service_type: Option<String>,
    pub document_root: Option<String>,
    pub index_file: Option<String>,
    pub spa_fallback: Option<bool>,
    pub project_id: Option<Uuid>,
    pub domain: Option<String>,
    pub subdomain: Option<String>,
}

#[derive(Deserialize)]
pub struct CreatePlugin {
    pub name: String,
    #[serde(default)]
    pub service_id: Option<Uuid>,
    #[serde(default)]
    pub route_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
pub struct CreateConsumer {
    pub username: String,
    pub custom_id: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub build_hash: String,
    pub uptime_seconds: i64,
    pub services_count: usize,
    pub routes_count: usize,
    pub plugins_count: usize,
    pub consumers_count: usize,
    pub tier: String,
    pub active_nodes: u32,
    pub max_nodes: Option<u32>,
    pub instance_id: String,
    /// `"keyx"` or `"legacy"` — which licence-verification path this
    /// node booted into. Useful as the canonical signal that a keyx
    /// migration actually took effect.
    pub licence_mode: String,
}

pub async fn list_services(State(state): State<AdminState>) -> Json<Vec<Service>> {
    Json(state.route_table.list_services().into_iter().map(|s| (*s).clone()).collect())
}

pub async fn create_service(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateService>,
) -> Result<Json<Service>, GatewayError> {
    let mut service = Service::new(
        input.name,
        input.url,
        input.retries,
        input.connect_timeout_ms,
    );
    if let Some(s) = input.lb_strategy {
        service.lb_strategy = s;
    }
    if let Some(t) = input.service_type {
        service.service_type = t;
    }
    if let Some(root) = input.document_root {
        service.document_root = Some(root);
    }
    if let Some(idx) = input.index_file {
        service.index_file = idx;
    }
    if let Some(spa) = input.spa_fallback {
        service.spa_fallback = spa;
    }
    service.project_id = input.project_id;
    if let Some(d) = input.domain {
        service.domain = d;
    }
    if let Some(s) = input.subdomain {
        service.subdomain = s;
    }
    validate_domain_subdomain(
        &service.domain,
        &service.subdomain,
        &state.route_table,
        None,
    )?;
    state.repo.create_service(&service).await?;
    state.route_table.add_service(service.clone());
    state.health.register(service.id);
    state.lb.rebuild_for_service(
        service.id,
        LbStrategy::from_str(&service.lb_strategy),
        Vec::new(),
    );
    tracing::info!(id = %service.id, "service created");
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Service,
            Some(service.id.to_string()),
            serde_json::to_value(&service).ok(),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ServiceCreated {
            id: service.id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(service))
}

pub async fn get_service(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Response, GatewayError> {
    let svc = state
        .route_table
        .get_service(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {id}")))?;
    let etag = entity_etag(&svc.id, &svc.updated_at);
    Ok(json_with_etag(svc, &etag))
}

pub async fn update_service(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateService>,
) -> Result<Json<Service>, GatewayError> {
    let now = Utc::now();
    let existing = state
        .route_table
        .get_service(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    let new_domain = input
        .domain
        .clone()
        .unwrap_or_else(|| existing.domain.clone());
    let new_subdomain = input
        .subdomain
        .clone()
        .unwrap_or_else(|| existing.subdomain.clone());
    validate_domain_subdomain(&new_domain, &new_subdomain, &state.route_table, Some(&id))?;

    let new_strategy = input
        .lb_strategy
        .clone()
        .unwrap_or_else(|| existing.lb_strategy.clone());
    let strategy_changed = new_strategy != existing.lb_strategy;

    let updated = Service {
        hide_patterns: vec![],
        id,
        name: input.name.into(),
        url: input.url,
        retries: input.retries,
        connect_timeout_ms: input.connect_timeout_ms,
        lb_strategy: new_strategy,
        service_type: input
            .service_type
            .unwrap_or_else(|| existing.service_type.clone()),
        document_root: input
            .document_root
            .or_else(|| existing.document_root.clone()),
        index_file: input
            .index_file
            .unwrap_or_else(|| existing.index_file.clone()),
        spa_fallback: input.spa_fallback.unwrap_or(existing.spa_fallback),
        tls_verify: existing.tls_verify,
        tls_client_cert_path: existing.tls_client_cert_path.clone(),
        tls_client_key_path: existing.tls_client_key_path.clone(),
        tls_ca_path: existing.tls_ca_path.clone(),
        lb_hash_header: existing.lb_hash_header.clone(),
        lb_hash_query_param: existing.lb_hash_query_param.clone(),
        flush_interval_ms: existing.flush_interval_ms,
        stream_timeout_ms: existing.stream_timeout_ms,
        stream_close_delay_ms: existing.stream_close_delay_ms,
        pass_host_header: existing.pass_host_header,
        pool_idle_floor: existing.pool_idle_floor,
        force_http_version: existing.force_http_version.clone(),
        drain_timeout_ms: existing.drain_timeout_ms,
        project_id: input.project_id.or(existing.project_id),
        domain: input.domain.unwrap_or_else(|| existing.domain.clone()),
        subdomain: input
            .subdomain
            .unwrap_or_else(|| existing.subdomain.clone()),
        created_at: existing.created_at,
        updated_at: now,
    };

    let url_changed = existing.url != updated.url;
    state.repo.update_service(&id, &updated).await?;
    state.route_table.update_service(&id, updated.clone());
    state.client_pool.invalidate(&id);
    if url_changed {
        state
            .health
            .reset_on_upstream_change(&id, &updated.name, "upstream URL changed");
    }

    if strategy_changed {
        let targets = state.repo.list_targets_for_service(&id).await?;
        state
            .lb
            .rebuild_for_service(id, LbStrategy::from_str(&updated.lb_strategy), targets);
    }

    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Service,
            Some(id.to_string()),
            Some(serde_json::json!({
                "before": existing,
                "after": updated,
            })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ServiceUpdated {
            id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

pub async fn delete_service(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    if let Some(existing) = state.route_table.get_service(&id) {
        check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;
    }
    let deleted = state.repo.delete_service(&id).await?;
    if deleted {
        cascade_soft_delete_service(&state, id).await;
        state.plugin_exec.rebuild(&state.repo).await?;
        state
            .audit
            .record(
                AuditAction::Delete,
                ResourceType::Service,
                Some(id.to_string()),
                None,
                actor_of(&actor),
            )
            .await;
        publish_event(
            &state,
            ChangeEvent::ServiceDeleted {
                id,
                origin: state.node_id,
            },
        )
        .await;
        Ok(Json(serde_json::json!({"deleted": true})))
    } else {
        Err(GatewayError::NotFound(format!("service {id}")))
    }
}

pub async fn list_health(State(state): State<AdminState>) -> Json<Vec<ServiceHealth>> {
    Json(state.health.list())
}

pub async fn get_health(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Response, GatewayError> {
    let health = state
        .health
        .get(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("health for service {id}")))?;
    let ts = health.last_check_at.unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    let etag = entity_etag(&health.service_id, &ts);
    Ok(json_with_etag(health, &etag))
}

// ── Upstream status API ──

/// Per-target snapshot returned by `GET /admin/upstreams`.
#[derive(Serialize)]
pub struct UpstreamTargetStatus {
    pub target_id: Uuid,
    pub service_id: Uuid,
    pub service_name: String,
    pub url: String,
    pub weight: u32,
    pub enabled: bool,
    pub healthy: bool,
    pub in_flight: u64,
    pub zone: Option<String>,
}

/// Aggregate response for `GET /admin/upstreams`.
#[derive(Serialize)]
pub struct UpstreamStatusResponse {
    pub total_targets: usize,
    pub healthy_targets: usize,
    pub unhealthy_targets: usize,
    pub targets: Vec<UpstreamTargetStatus>,
}

/// `GET /admin/upstreams` — live snapshot of all upstream targets across
/// every service, including health, in-flight count, and weight.
pub async fn list_upstreams(State(state): State<AdminState>) -> Json<UpstreamStatusResponse> {
    let services = state.route_table.list_services();
    let mut targets = Vec::new();

    for svc in &services {
        let snapshot = state.lb.snapshot(&svc.id);
        for ts in snapshot {
            targets.push(UpstreamTargetStatus {
                target_id: ts.target.id,
                service_id: svc.id,
                service_name: svc.name.to_string(),
                url: ts.target.url.to_string(),
                weight: ts.target.weight,
                enabled: ts.target.enabled,
                healthy: ts.healthy.load(std::sync::atomic::Ordering::Relaxed),
                in_flight: ts.in_flight.load(std::sync::atomic::Ordering::Relaxed),
                zone: ts.target.zone.clone(),
            });
        }
    }

    let healthy = targets.iter().filter(|t| t.healthy && t.enabled).count();
    let unhealthy = targets.iter().filter(|t| !t.healthy && t.enabled).count();
    let total = targets.len();

    Json(UpstreamStatusResponse {
        total_targets: total,
        healthy_targets: healthy,
        unhealthy_targets: unhealthy,
        targets,
    })
}

pub async fn list_routes(State(state): State<AdminState>) -> Json<Vec<std::sync::Arc<Route>>> {
    Json(state.route_table.list_routes())
}

pub async fn create_route(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateRoute>,
) -> Result<Json<Route>, GatewayError> {
    if state.route_table.get_service(&input.service_id).is_none() {
        return Err(GatewayError::BadRequest(format!(
            "service {} not found",
            input.service_id
        )));
    }

    let route = Route::new(
        input.paths,
        input.methods,
        input.hosts,
        input.service_id,
        input.strip_path,
    );
    state.repo.create_route(&route).await?;
    state.route_table.add_route(route.clone());
    tracing::info!(id = %route.id, "route created");
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Route,
            Some(route.id.to_string()),
            serde_json::to_value(&route).ok(),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::RouteCreated {
            id: route.id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(route))
}

pub async fn get_route(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Response, GatewayError> {
    let route = state
        .route_table
        .get_route(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("route {id}")))?;
    let etag = entity_etag(&route.id, &route.updated_at);
    Ok(json_with_etag(route, &etag))
}

pub async fn update_route(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateRoute>,
) -> Result<Json<Route>, GatewayError> {
    let now = Utc::now();
    let existing = state
        .route_table
        .get_route(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("route {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    let updated = Route {
        id,
        paths: input.paths,
        methods: input.methods,
        hosts: input.hosts,
        service_id: input.service_id,
        strip_path: input.strip_path,
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
        health_gate: existing.health_gate,
        created_at: existing.created_at,
        updated_at: now,
    };

    state.repo.update_route(&id, &updated).await?;
    state.route_table.update_route(&id, updated.clone());
    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Route,
            Some(id.to_string()),
            Some(serde_json::json!({ "before": existing, "after": updated })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::RouteUpdated {
            id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

pub async fn patch_route(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<PatchRoute>,
) -> Result<Json<Route>, GatewayError> {
    let now = Utc::now();
    let existing = state
        .route_table
        .get_route(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("route {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    if let Some(ref sid) = input.service_id {
        if state.route_table.get_service(sid).is_none() {
            return Err(GatewayError::BadRequest(format!(
                "service {} not found",
                sid
            )));
        }
    }

    let updated = Route {
        id,
        paths: input.paths.unwrap_or_else(|| existing.paths.clone()),
        methods: input.methods.unwrap_or_else(|| existing.methods.clone()),
        hosts: input.hosts.unwrap_or_else(|| existing.hosts.clone()),
        service_id: input.service_id.unwrap_or(existing.service_id),
        strip_path: input.strip_path.unwrap_or(existing.strip_path),
        buffer_request: existing.buffer_request,
        path_rewrite_pattern: existing.path_rewrite_pattern.clone(),
        path_rewrite_replacement: existing.path_rewrite_replacement.clone(),
        headers: existing.headers.clone(),
        query_params: existing.query_params.clone(),
        path_regexes: existing.path_regexes.clone(),
        read_timeout_ms: existing.read_timeout_ms,
        write_timeout_ms: existing.write_timeout_ms,
        idle_timeout_ms: existing.idle_timeout_ms,
        retry_on_status: existing.retry_on_status.clone(),
        matchers: existing.matchers.clone(),
        matcher_refs: existing.matcher_refs.clone(),
        handle_blocks: existing.handle_blocks.clone(),
        try_files: existing.try_files.clone(),
        uri_directives: existing.uri_directives.clone(),
        intercept_rules: existing.intercept_rules.clone(),
        push: existing.push.clone(),
        static_response: existing.static_response.clone(),
        health_gate: existing.health_gate,
        created_at: existing.created_at,
        updated_at: now,
    };

    state.repo.update_route(&id, &updated).await?;
    state.route_table.update_route(&id, updated.clone());
    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Route,
            Some(id.to_string()),
            Some(serde_json::json!({ "before": existing, "after": updated })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::RouteUpdated {
            id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

pub async fn patch_service(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<PatchService>,
) -> Result<Json<Service>, GatewayError> {
    let now = Utc::now();
    let existing = state
        .route_table
        .get_service(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    let new_domain = input
        .domain
        .clone()
        .unwrap_or_else(|| existing.domain.clone());
    let new_subdomain = input
        .subdomain
        .clone()
        .unwrap_or_else(|| existing.subdomain.clone());
    validate_domain_subdomain(&new_domain, &new_subdomain, &state.route_table, Some(&id))?;

    let new_strategy = input
        .lb_strategy
        .unwrap_or_else(|| existing.lb_strategy.clone());
    let strategy_changed = new_strategy != existing.lb_strategy;

    let updated = Service {
        hide_patterns: vec![],
        id,
        name: input
            .name
            .unwrap_or_else(|| existing.name.to_string())
            .into(),
        url: input.url.unwrap_or_else(|| existing.url.clone()),
        retries: input.retries.unwrap_or(existing.retries),
        connect_timeout_ms: input
            .connect_timeout_ms
            .unwrap_or(existing.connect_timeout_ms),
        lb_strategy: new_strategy,
        service_type: input
            .service_type
            .unwrap_or_else(|| existing.service_type.clone()),
        document_root: input
            .document_root
            .or_else(|| existing.document_root.clone()),
        index_file: input
            .index_file
            .unwrap_or_else(|| existing.index_file.clone()),
        spa_fallback: input.spa_fallback.unwrap_or(existing.spa_fallback),
        tls_verify: existing.tls_verify,
        tls_client_cert_path: existing.tls_client_cert_path.clone(),
        tls_client_key_path: existing.tls_client_key_path.clone(),
        tls_ca_path: existing.tls_ca_path.clone(),
        lb_hash_header: existing.lb_hash_header.clone(),
        lb_hash_query_param: existing.lb_hash_query_param.clone(),
        flush_interval_ms: existing.flush_interval_ms,
        stream_timeout_ms: existing.stream_timeout_ms,
        stream_close_delay_ms: existing.stream_close_delay_ms,
        pass_host_header: existing.pass_host_header,
        pool_idle_floor: existing.pool_idle_floor,
        force_http_version: existing.force_http_version.clone(),
        drain_timeout_ms: existing.drain_timeout_ms,
        project_id: input.project_id.or(existing.project_id),
        domain: input.domain.unwrap_or_else(|| existing.domain.clone()),
        subdomain: input
            .subdomain
            .unwrap_or_else(|| existing.subdomain.clone()),
        created_at: existing.created_at,
        updated_at: now,
    };

    let url_changed = existing.url != updated.url;
    state.repo.update_service(&id, &updated).await?;
    state.route_table.update_service(&id, updated.clone());
    state.client_pool.invalidate(&id);
    if url_changed {
        state
            .health
            .reset_on_upstream_change(&id, &updated.name, "upstream URL changed");
    }

    if strategy_changed {
        let targets = state.repo.list_targets_for_service(&id).await?;
        state
            .lb
            .rebuild_for_service(id, LbStrategy::from_str(&updated.lb_strategy), targets);
    }

    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Service,
            Some(id.to_string()),
            Some(serde_json::json!({ "before": existing, "after": updated })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ServiceUpdated {
            id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

pub async fn delete_route(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    if let Some(existing) = state.route_table.get_route(&id) {
        check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;
    }
    let deleted = state.repo.delete_route(&id).await?;
    if deleted {
        cascade_soft_delete_route(&state, id).await;
        state.plugin_exec.rebuild(&state.repo).await?;
        state
            .audit
            .record(
                AuditAction::Delete,
                ResourceType::Route,
                Some(id.to_string()),
                None,
                actor_of(&actor),
            )
            .await;
        publish_event(
            &state,
            ChangeEvent::RouteDeleted {
                id,
                origin: state.node_id,
            },
        )
        .await;
        Ok(Json(serde_json::json!({"deleted": true})))
    } else {
        Err(GatewayError::NotFound(format!("route {id}")))
    }
}

pub async fn list_plugins(
    State(state): State<AdminState>,
) -> Result<Json<Vec<PluginInstance>>, GatewayError> {
    Ok(Json(state.repo.list_plugins().await?))
}

pub async fn create_plugin(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreatePlugin>,
) -> Result<Json<PluginInstance>, GatewayError> {
    validate_plugin_scope(&state, input.service_id, input.route_id).await?;
    // Eagerly validate the plugin can be built before persisting.
    let _ = crate::plugins::factory::build(
        &input.name,
        &input.config,
        Some(state.repo.clone()),
        state.plugin_exec.context(),
        state.plugin_exec.algorithm_tier(),
    )?;
    let now = Utc::now();
    let plugin = PluginInstance {
        id: Uuid::new_v4(),
        name: input.name,
        service_id: input.service_id,
        route_id: input.route_id,
        enabled: input.enabled,
        config: input.config,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_plugin(&plugin).await?;
    state.plugin_exec.rebuild(&state.repo).await?;
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Plugin,
            Some(plugin.id.to_string()),
            serde_json::to_value(&plugin).ok(),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::PluginChanged {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(plugin))
}

pub async fn get_plugin(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Response, GatewayError> {
    let plugin = state
        .repo
        .get_plugin(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("plugin {id}")))?;
    let etag = entity_etag(&plugin.id, &plugin.updated_at);
    Ok(json_with_etag(plugin, &etag))
}

pub async fn update_plugin(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreatePlugin>,
) -> Result<Json<PluginInstance>, GatewayError> {
    let existing = state
        .repo
        .get_plugin(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("plugin {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    validate_plugin_scope(&state, input.service_id, input.route_id).await?;
    let _ = crate::plugins::factory::build(
        &input.name,
        &input.config,
        Some(state.repo.clone()),
        state.plugin_exec.context(),
        state.plugin_exec.algorithm_tier(),
    )?;

    let updated = PluginInstance {
        id: existing.id,
        name: input.name,
        service_id: input.service_id,
        route_id: input.route_id,
        enabled: input.enabled,
        config: input.config,
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };
    state.repo.update_plugin(&id, &updated).await?;
    state.plugin_exec.rebuild(&state.repo).await?;
    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Plugin,
            Some(id.to_string()),
            Some(serde_json::json!({ "before": existing, "after": updated })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::PluginChanged {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

pub async fn delete_plugin(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let existing = state
        .repo
        .get_plugin(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("plugin {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;
    let deleted = state.repo.delete_plugin(&id).await?;
    if deleted {
        state.plugin_exec.rebuild(&state.repo).await?;
        state
            .audit
            .record(
                AuditAction::Delete,
                ResourceType::Plugin,
                Some(id.to_string()),
                None,
                actor_of(&actor),
            )
            .await;
        publish_event(
            &state,
            ChangeEvent::PluginChanged {
                origin: state.node_id,
            },
        )
        .await;
        Ok(Json(serde_json::json!({"deleted": true})))
    } else {
        Err(GatewayError::NotFound(format!("plugin {id}")))
    }
}

fn validate_domain_subdomain(
    domain: &str,
    subdomain: &str,
    route_table: &SharedRouteTable,
    exclude_service: Option<&Uuid>,
) -> Result<(), GatewayError> {
    if !domain.is_empty() {
        if domain.contains("://") || domain.contains('/') || domain.contains(' ') {
            return Err(GatewayError::BadRequest(
                "domain must be a valid hostname (no protocol, no path)".into(),
            ));
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.iter().any(|l| l.is_empty()) || labels.len() < 2 {
            return Err(GatewayError::BadRequest(
                "domain must be a valid hostname with at least two labels".into(),
            ));
        }
    }
    if !subdomain.is_empty() {
        let valid = subdomain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid || subdomain.starts_with('-') || subdomain.ends_with('-') {
            return Err(GatewayError::BadRequest(
                "subdomain must be alphanumeric and hyphens only (no leading/trailing hyphen)"
                    .into(),
            ));
        }
    }
    if !domain.is_empty() && !subdomain.is_empty() {
        let fqdn = format!("{subdomain}.{domain}").to_ascii_lowercase();
        if route_table.is_host_taken(&fqdn, exclude_service) {
            return Err(GatewayError::Conflict(format!(
                "host {fqdn} is already assigned to another service"
            )));
        }
    }
    Ok(())
}

async fn validate_plugin_scope(
    state: &AdminState,
    service_id: Option<Uuid>,
    route_id: Option<Uuid>,
) -> Result<(), GatewayError> {
    if let Some(sid) = service_id {
        if state.route_table.get_service(&sid).is_none() {
            return Err(GatewayError::BadRequest(format!("service {sid} not found")));
        }
    }
    if let Some(rid) = route_id {
        if state.route_table.get_route(&rid).is_none() {
            return Err(GatewayError::BadRequest(format!("route {rid} not found")));
        }
    }
    Ok(())
}

pub async fn list_consumers(
    State(state): State<AdminState>,
) -> Result<Json<Vec<Consumer>>, GatewayError> {
    Ok(Json(state.repo.list_consumers().await?))
}

pub async fn create_consumer(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateConsumer>,
) -> Result<Json<Consumer>, GatewayError> {
    let consumer = Consumer::new(input.username, input.custom_id);
    state.repo.create_consumer(&consumer).await?;
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Consumer,
            Some(consumer.id.to_string()),
            serde_json::to_value(&consumer).ok(),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ConsumerChanged {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(consumer))
}

pub async fn delete_consumer(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let deleted = state.repo.delete_consumer(&id).await?;
    if deleted {
        state
            .audit
            .record(
                AuditAction::Delete,
                ResourceType::Consumer,
                Some(id.to_string()),
                None,
                actor_of(&actor),
            )
            .await;
        publish_event(
            &state,
            ChangeEvent::ConsumerChanged {
                origin: state.node_id,
            },
        )
        .await;
        Ok(Json(serde_json::json!({"deleted": true})))
    } else {
        Err(GatewayError::NotFound(format!("consumer {id}")))
    }
}

// ---------- consumer key regeneration ----------

pub async fn regenerate_consumer_key(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<Consumer>, GatewayError> {
    let mut consumer = state
        .repo
        .list_consumers()
        .await?
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| GatewayError::NotFound(format!("consumer {id}")))?;

    let new_key = Uuid::new_v4().to_string();
    consumer.api_key = Some(new_key);
    consumer.updated_at = Utc::now();
    state.repo.update_consumer(&id, &consumer).await?;

    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Consumer,
            Some(id.to_string()),
            Some(serde_json::json!({"action": "regenerate_key"})),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ConsumerChanged {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(consumer))
}

pub async fn metrics(State(state): State<AdminState>) -> Response {
    let body = state.metrics_handle.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        body,
    )
        .into_response()
}

// ---------- targets ----------

async fn rebuild_lb(state: &AdminState, service_id: Uuid) -> Result<(), GatewayError> {
    let Some(svc) = state.route_table.get_service(&service_id) else {
        return Ok(());
    };
    let targets = state.repo.list_targets_for_service(&service_id).await?;
    state
        .lb
        .rebuild_for_service(service_id, LbStrategy::from_str(&svc.lb_strategy), targets);
    Ok(())
}

pub async fn list_all_targets(
    State(state): State<AdminState>,
) -> Result<Json<Vec<Target>>, GatewayError> {
    Ok(Json(state.repo.list_targets().await?))
}

pub async fn list_service_targets(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<Target>>, GatewayError> {
    if state.route_table.get_service(&service_id).is_none() {
        return Err(GatewayError::NotFound(format!("service {service_id}")));
    }
    Ok(Json(
        state.repo.list_targets_for_service(&service_id).await?,
    ))
}

pub async fn create_service_target(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateTarget>,
) -> Result<Json<Target>, GatewayError> {
    if state.route_table.get_service(&service_id).is_none() {
        return Err(GatewayError::NotFound(format!("service {service_id}")));
    }
    let mut target = Target::new(service_id, input.url, input.weight);
    target.enabled = input.enabled;
    target.zone = input.zone;
    state.repo.create_target(&target).await?;
    rebuild_lb(&state, service_id).await?;
    tracing::info!(target_id = %target.id, service_id = %service_id, "target created");
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Target,
            Some(target.id.to_string()),
            serde_json::to_value(&target).ok(),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::TargetChanged {
            service_id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(target))
}

pub async fn update_target_handler(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<UpdateTarget>,
) -> Result<Json<Target>, GatewayError> {
    let existing = state
        .repo
        .get_target(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("target {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    let updated = Target {
        id: existing.id,
        service_id: existing.service_id,
        url: input
            .url
            .clone()
            .unwrap_or_else(|| existing.url.to_string())
            .into(),
        weight: input.weight.unwrap_or(existing.weight).max(1),
        enabled: input.enabled.unwrap_or(existing.enabled),
        zone: input.zone.or(existing.zone.clone()),
        state: existing.state,
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

    state.repo.update_target(&id, &updated).await?;
    rebuild_lb(&state, updated.service_id).await?;
    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Target,
            Some(id.to_string()),
            Some(serde_json::json!({ "before": existing, "after": updated })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::TargetChanged {
            service_id: updated.service_id,
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

#[derive(Deserialize)]
pub struct DrainQuery {
    pub drain: Option<bool>,
    pub timeout: Option<u64>,
}

pub async fn get_target_handler(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Response, GatewayError> {
    let target = state
        .repo
        .get_target(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("target {id}")))?;
    let in_flight = state
        .lb
        .snapshot(&target.service_id)
        .iter()
        .find(|ts| ts.target.id == id)
        .map(|ts| ts.in_flight.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    let lifecycle = state
        .lb
        .snapshot(&target.service_id)
        .iter()
        .find(|ts| ts.target.id == id)
        .map(|ts| ts.lifecycle().as_str())
        .unwrap_or(target.state.as_str());
    let mut val = serde_json::to_value(&target).unwrap();
    val.as_object_mut()
        .unwrap()
        .insert("in_flight".to_string(), serde_json::json!(in_flight));
    val.as_object_mut()
        .unwrap()
        .insert("state".to_string(), serde_json::json!(lifecycle));
    let etag = entity_etag(&target.id, &target.updated_at);
    Ok(json_with_etag(val, &etag))
}

pub async fn delete_target_handler(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(drain_q): Query<DrainQuery>,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let existing = state
        .repo
        .get_target(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("target {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    if drain_q.drain.unwrap_or(false) {
        let timeout_ms = drain_q.timeout.unwrap_or(30).saturating_mul(1000);
        state.repo.update_target_state(&id, "draining").await?;
        state.lb.set_target_lifecycle(
            &existing.service_id,
            &id,
            crate::models::TargetLifecycle::Draining,
        );
        let repo = state.repo.clone();
        let lb = state.lb.clone();
        let service_id = existing.service_id;
        let target_id = id;
        state.lb.drain_target(&existing.service_id, &id, timeout_ms);
        let bus = state.bus.clone();
        let node_id = state.node_id;
        tokio::spawn(async move {
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms + 500);
            loop {
                let snap = lb.snapshot(&service_id);
                let ts = snap.iter().find(|s| s.target.id == target_id);
                let done = match ts {
                    Some(t) => t.lifecycle() == crate::models::TargetLifecycle::Inactive,
                    None => true,
                };
                if done || tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            let _ = repo.update_target_state(&target_id, "inactive").await;
            let _ = repo.delete_target(&target_id).await;
            let svc = lb.snapshot(&service_id);
            drop(svc);
            if let Err(e) = bus
                .publish(ChangeEvent::TargetChanged {
                    service_id,
                    origin: node_id,
                })
                .await
            {
                tracing::warn!(error = %e, "failed to publish drain-complete event");
            }
        });
        tracing::info!(target_id = %id, timeout_ms, "target drain initiated");
        state
            .audit
            .record(
                AuditAction::Update,
                ResourceType::Target,
                Some(id.to_string()),
                Some(serde_json::json!({"action": "drain", "timeout_ms": timeout_ms})),
                actor_of(&actor),
            )
            .await;
        return Ok(Json(serde_json::json!({
            "draining": true,
            "target_id": id,
            "timeout_ms": timeout_ms,
        })));
    }

    let deleted = state.repo.delete_target(&id).await?;
    if deleted {
        rebuild_lb(&state, existing.service_id).await?;
        state
            .audit
            .record(
                AuditAction::Delete,
                ResourceType::Target,
                Some(id.to_string()),
                None,
                actor_of(&actor),
            )
            .await;
        publish_event(
            &state,
            ChangeEvent::TargetChanged {
                service_id: existing.service_id,
                origin: state.node_id,
            },
        )
        .await;
        Ok(Json(serde_json::json!({"deleted": true})))
    } else {
        Err(GatewayError::NotFound(format!("target {id}")))
    }
}

// ---------- admin tokens ----------

#[derive(Serialize)]
pub struct AdminTokenView {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<AdminToken> for AdminTokenView {
    fn from(t: AdminToken) -> Self {
        Self {
            id: t.id,
            name: t.name,
            role: t.role,
            created_at: t.created_at,
            expires_at: t.expires_at,
            last_used_at: t.last_used_at,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateTokenInput {
    pub name: String,
    pub role: Role,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct CreatedTokenResponse {
    #[serde(flatten)]
    pub view: AdminTokenView,
    /// Raw token. Returned ONCE on creation; never retrievable again.
    pub token: String,
}

#[derive(Deserialize)]
pub struct UpdateTokenInput {
    pub name: Option<String>,
    pub role: Option<Role>,
    /// `null` clears the expiry; field absence leaves it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
}

pub async fn list_tokens(
    State(state): State<AdminState>,
) -> Result<Json<Vec<AdminTokenView>>, GatewayError> {
    let tokens = state.repo.list_admin_tokens().await?;
    Ok(Json(tokens.into_iter().map(Into::into).collect()))
}

pub async fn create_token(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateTokenInput>,
) -> Result<Json<CreatedTokenResponse>, GatewayError> {
    if input.name.trim().is_empty() {
        return Err(GatewayError::BadRequest("token name required".into()));
    }
    let raw = generate_token();
    let new = NewAdminToken {
        id: Uuid::new_v4(),
        name: input.name,
        token_hash: hash_token(&raw),
        role: input.role,
        created_at: Utc::now(),
        expires_at: input.expires_at,
    };
    state.repo.create_admin_token(&new).await?;
    let view = AdminTokenView {
        id: new.id,
        name: new.name.clone(),
        role: new.role,
        created_at: new.created_at,
        expires_at: new.expires_at,
        last_used_at: None,
    };
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Token,
            Some(new.id.to_string()),
            Some(serde_json::json!({
                "name": new.name,
                "role": new.role,
                "expires_at": new.expires_at,
            })),
            actor_of(&actor),
        )
        .await;
    Ok(Json(CreatedTokenResponse { view, token: raw }))
}

pub async fn update_token(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<UpdateTokenInput>,
) -> Result<Json<AdminTokenView>, GatewayError> {
    let patch = AdminTokenPatch {
        name: input.name,
        role: input.role,
        expires_at: input.expires_at,
    };
    let updated = state
        .repo
        .update_admin_token(&id, &patch)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("token {id}")))?;
    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Token,
            Some(id.to_string()),
            Some(serde_json::json!({
                "name": updated.name,
                "role": updated.role,
                "expires_at": updated.expires_at,
            })),
            actor_of(&actor),
        )
        .await;
    Ok(Json(updated.into()))
}

pub async fn delete_token(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let deleted = state.repo.delete_admin_token(&id).await?;
    if !deleted {
        return Err(GatewayError::NotFound(format!("token {id}")));
    }
    state
        .audit
        .record(
            AuditAction::Delete,
            ResourceType::Token,
            Some(id.to_string()),
            None,
            actor_of(&actor),
        )
        .await;
    Ok(Json(serde_json::json!({"deleted": true})))
}

// ---------- audit log ----------

#[derive(Deserialize)]
pub struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub include_diff: bool,
}

pub async fn list_audit(
    State(state): State<AdminState>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, GatewayError> {
    let filter = AuditFilter {
        offset: None,
        actor: q.actor,
        action: q.action,
        resource_type: q.resource_type,
        since: q.since,
        limit: q.limit,
        include_diff: q.include_diff,
    };
    Ok(Json(state.audit.query(&filter).await?))
}

pub async fn verify_audit(
    State(state): State<AdminState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let result = state.audit.verify_chain().await?;
    Ok(Json(serde_json::json!({
        "ok": result.ok,
        "checked": result.checked,
        "broken_at": result.broken_at,
    })))
}

// Quiet unused-import warnings for items wired by mod.rs only.
#[allow(dead_code)]
const _USE_ROLE: fn() -> Role = || Role::Admin;
#[allow(dead_code)]
const _USE_FROMSTR: fn(&str) -> Result<Role, String> = Role::from_str;

// ---------- recordings (Time-Travel Debug A3) ----------

#[derive(Deserialize)]
pub struct ListRecordingsQuery {
    pub since: Option<DateTime<Utc>>,
    pub method: Option<String>,
    pub path_prefix: Option<String>,
    pub status: Option<u16>,
    pub service_id: Option<Uuid>,
    pub limit: Option<usize>,
}

#[derive(Deserialize, Default)]
pub struct ReplayBody {
    /// Optional override. When `None`, replays go through the local proxy.
    pub target_url: Option<String>,
}

pub async fn list_recordings(
    State(state): State<AdminState>,
    Query(q): Query<ListRecordingsQuery>,
) -> Result<Json<Vec<crate::recording::RecordingIndexRow>>, GatewayError> {
    let filter = crate::recording::RecordingFilter {
        since: q.since,
        method: q.method,
        path_prefix: q.path_prefix,
        status: q.status,
        service_id: q.service_id,
        limit: q.limit.unwrap_or(0),
    };
    let rows = state.repo.list_recordings(&filter).await?;
    Ok(Json(rows))
}

pub async fn get_recording(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> Result<Json<crate::recording::Recording>, GatewayError> {
    match state.recording_store.get(&id).await? {
        Some(rec) => Ok(Json(rec)),
        None => Err(GatewayError::NotFound(format!("recording {id}"))),
    }
}

pub async fn delete_recording_handler(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> Result<StatusCode, GatewayError> {
    let store_deleted = state.recording_store.delete(&id).await?;
    let index_deleted = state.repo.delete_recording(&id).await?;
    if store_deleted || index_deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound(format!("recording {id}")))
    }
}

pub async fn replay_recording(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(body): Json<ReplayBody>,
) -> Result<Json<crate::recording::ReplayResult>, GatewayError> {
    let rec = state
        .recording_store
        .get(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("recording {id}")))?;
    let target_url = body
        .target_url
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", state.proxy_port));
    let result = crate::recording::replay(&rec, &target_url, &state.http_client).await?;
    Ok(Json(result))
}

pub async fn gateway_status(
    State(state): State<AdminState>,
) -> Result<Json<StatusResponse>, GatewayError> {
    let uptime = Utc::now()
        .signed_duration_since(state.start_time)
        .num_seconds();

    let plugins_count = state.repo.list_plugins().await?.len();
    let consumers_count = state.repo.list_consumers().await?.len();

    let (tier, active_nodes, max_nodes, licence_mode) = match &state.license_state {
        Some(ls) => {
            let t = ls.tier();
            (
                t.as_str().to_string(),
                ls.active_nodes(),
                ls.max_nodes(),
                ls.mode().to_string(),
            )
        }
        None => ("unknown".into(), 0, None, "unknown".into()),
    };
    let instance_id = crate::license::compute_instance_id(&state.license_api_key);

    Ok(Json(StatusResponse {
        status: "running".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        build_hash: env!("LYNXX_BUILD_HASH").into(),
        uptime_seconds: uptime,
        services_count: state.route_table.list_services().len(),
        routes_count: state.route_table.list_routes().len(),
        plugins_count,
        consumers_count,
        tier,
        active_nodes,
        max_nodes,
        instance_id,
        licence_mode,
    }))
}

pub async fn healthz(State(state): State<AdminState>) -> Json<StatusResponse> {
    Json(state.status_cache.get().await)
}

// ---------- /auth/sign-in (public) ----------
//
// The node dashboard hits this with `Authorization: Bearer <api_key>`.
// The gateway forwards the key to the licence backend (keyx) and
// returns the licence payload on success — so the dashboard never
// talks to keyx directly. Public route: bypasses `extract_token`.

#[derive(Serialize)]
pub struct SignInResponse {
    pub customer_urn: String,
    pub tier: String,
    pub expires_at: Option<i64>,
    pub max_nodes: Option<u32>,
    pub active_nodes: u32,
    pub allow_overage: bool,
}

struct RateLimitEntry {
    tokens: f64,
    last_updated: std::time::Instant,
}

struct RateLimiter {
    attempts: dashmap::DashMap<String, RateLimitEntry>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            attempts: dashmap::DashMap::new(),
        }
    }

    fn check_limit(&self, ip: &str) -> bool {
        let max_tokens = 5.0;
        let refill_rate = 0.1; // 1 token every 10 seconds (6 tokens per minute)
        let now = std::time::Instant::now();

        let mut entry = self.attempts.entry(ip.to_string()).or_insert_with(|| RateLimitEntry {
            tokens: max_tokens,
            last_updated: now,
        });

        let elapsed = now.duration_since(entry.last_updated).as_secs_f64();
        let refilled = elapsed * refill_rate;
        entry.tokens = (entry.tokens + refilled).min(max_tokens);
        entry.last_updated = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

static SIGNIN_LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();

fn check_rate_limit(ip: &str) -> Result<(), GatewayError> {
    let limiter = SIGNIN_LIMITER.get_or_init(RateLimiter::new);
    if limiter.check_limit(ip) {
        Ok(())
    } else {
        Err(GatewayError::PluginError(PluginError::RateLimited))
    }
}

pub async fn auth_sign_in(
    State(state): State<AdminState>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<SignInResponse>, GatewayError> {
    let client_ip = headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| connect_info.map(|ConnectInfo(addr)| addr.ip().to_string()))
        .unwrap_or_else(|| "127.0.0.1".to_string());

    check_rate_limit(&client_ip)?;

    let license_state = state
        .license_state
        .as_ref()
        .ok_or_else(|| GatewayError::Internal("licence verifier not configured".into()))?;

    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            GatewayError::PluginError(PluginError::Unauthorized(
                "Authorization: Bearer required".into(),
            ))
        })?;

    let info = license_state.validate_key(raw).await.map_err(|e| match e {
        VerifierError::Rejected(msg) => GatewayError::PluginError(PluginError::Unauthorized(msg)),
        VerifierError::Http { status, body } => {
            GatewayError::ServiceUnavailable(format!("keyx HTTP {status}: {body}"))
        }
        VerifierError::Transport(msg) => {
            GatewayError::ServiceUnavailable(format!("keyx unreachable: {msg}"))
        }
        VerifierError::Malformed(msg) => GatewayError::Internal(format!("keyx malformed: {msg}")),
        VerifierError::NotConfigured => GatewayError::Internal("verifier not configured".into()),
    })?;

    Ok(Json(SignInResponse {
        customer_urn: info.customer_urn,
        tier: info.tier,
        expires_at: info.expires_at,
        max_nodes: info.max_nodes,
        active_nodes: info.active_nodes,
        allow_overage: info.allow_overage,
    }))
}

// ---------- circuit breakers ----------

pub async fn list_circuit_breakers(State(state): State<AdminState>) -> Json<Vec<ServiceHealth>> {
    Json(state.health.list())
}

pub async fn reset_circuit_breaker(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    state
        .health
        .reset_circuit(&service_id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {service_id}")))?;
    tracing::info!(service_id = %service_id, "circuit breaker manually reset");
    Ok(Json(
        serde_json::json!({"reset": true, "service_id": service_id}),
    ))
}

// ---------- per-service circuit breaker state ----------

/// `GET /circuit-breakers/:service_id` — return the circuit breaker state for
/// a specific service, including config values and current health.
pub async fn get_service_circuit_breaker(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let health = state
        .health
        .get(&service_id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {service_id}")))?;

    let config = state.health.config();

    Ok(Json(serde_json::json!({
        "service_id": service_id,
        "circuit": health.circuit,
        "status": health.status,
        "consecutive_failures": health.consecutive_failures,
        "consecutive_successes": health.consecutive_successes,
        "total_checks": health.total_checks,
        "total_failures": health.total_failures,
        "last_check_at": health.last_check_at,
        "last_error": health.last_error,
        "opened_at": health.opened_at,
        "config": {
            "failure_threshold": config.failure_threshold,
            "success_threshold": config.success_threshold,
            "open_duration_ms": config.open_duration_ms,
        },
    })))
}

/// `PATCH /circuit-breakers/:service_id` — update circuit breaker config for
/// a specific service. Currently resets the circuit to closed as a side-effect
/// when any config field is patched since the HealthRegistry uses a global
/// config. Returns the updated state.
#[derive(Deserialize)]
pub struct PatchCircuitBreakerBody {
    pub failure_threshold: Option<u32>,
    pub success_threshold: Option<u32>,
    pub open_duration_ms: Option<u64>,
    /// Optionally force-reset the circuit to closed.
    #[serde(default)]
    pub reset: bool,
}

pub async fn patch_service_circuit_breaker(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Extension(actor): Extension<CurrentActor>,
    Json(body): Json<PatchCircuitBreakerBody>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let health = state
        .health
        .get(&service_id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {service_id}")))?;

    if body.reset {
        state
            .health
            .reset_circuit(&service_id)
            .ok_or_else(|| GatewayError::NotFound(format!("service {service_id}")))?;
        tracing::info!(service_id = %service_id, "circuit breaker reset via PATCH");
    }

    let config = state.health.config();
    let patched_config = serde_json::json!({
        "failure_threshold": body.failure_threshold.unwrap_or(config.failure_threshold),
        "success_threshold": body.success_threshold.unwrap_or(config.success_threshold),
        "open_duration_ms": body.open_duration_ms.unwrap_or(config.open_duration_ms),
    });

    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Service,
            Some(service_id.to_string()),
            Some(serde_json::json!({
                "action": "patch_circuit_breaker",
                "config": patched_config,
                "reset": body.reset,
            })),
            actor_of(&actor),
        )
        .await;

    let updated = state.health.get(&service_id).unwrap_or(health);

    Ok(Json(serde_json::json!({
        "service_id": service_id,
        "circuit": updated.circuit,
        "status": updated.status,
        "config": patched_config,
        "reset": body.reset,
    })))
}

// ---------- ACME force renew ----------

#[derive(Deserialize)]
pub struct AcmeRenewQuery {
    pub force: Option<bool>,
}

pub async fn acme_renew(
    State(state): State<AdminState>,
    Query(q): Query<AcmeRenewQuery>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mgr = require_acme(&state)?;
    if q.force.unwrap_or(false) {
        mgr.request_certificate().await?;
        Ok(Json(serde_json::json!({"renewed": true, "forced": true})))
    } else {
        mgr.request_certificate().await?;
        Ok(Json(serde_json::json!({"renewed": true})))
    }
}

// ---------------------------------------------------------------------------
// POST /acme/revoke
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AcmeRevokeQuery {
    pub reason: Option<String>,
}

pub async fn acme_revoke(
    State(state): State<AdminState>,
    Query(q): Query<AcmeRevokeQuery>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mgr = require_acme(&state)?;
    let reason = q.reason.as_deref().and_then(|r| match r {
        "key_compromise" => Some(instant_acme::RevocationReason::KeyCompromise),
        "affiliation_changed" => Some(instant_acme::RevocationReason::AffiliationChanged),
        "superseded" => Some(instant_acme::RevocationReason::Superseded),
        "cessation_of_operation" => Some(instant_acme::RevocationReason::CessationOfOperation),
        _ => None,
    });
    mgr.revoke_certificate(reason).await?;
    Ok(Json(serde_json::json!({"revoked": true})))
}

// ---------------------------------------------------------------------------
// GET /quota
// ---------------------------------------------------------------------------

/// Return the current period's quota snapshot: plan tier, calls allowed,
/// calls remaining, calls rejected. Useful for dashboards and billing UIs.
pub async fn quota_snapshot(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, GatewayError> {
    Ok(Json(state.quota.snapshot()))
}

// ============================================================================
// ACME challenge admin endpoints
// ============================================================================
//
// External ACME orchestrators (lego, custom clients, certbot --manual)
// drive validation by:
//   1. Asking the ACME directory for a token + key authorization.
//   2. POSTing it to the running gateway here.
//   3. Telling the directory "go validate now".
//   4. DELETEing the challenge to free the slot.
//
// HTTP-01 and TLS-ALPN-01 share the shape; the only difference is the
// resource the validator hits (a path on port 80 vs. a TLS handshake on
// port 443). The same gateway process serves both without any restart.

#[derive(Debug, Deserialize)]
pub struct Http01ChallengeReq {
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Deserialize)]
pub struct TlsAlpnChallengeReq {
    pub domain: String,
    pub key_authorization: String,
}

#[derive(Debug, Serialize)]
pub struct AcmeStatus {
    pub enabled: bool,
    pub has_cert: bool,
    pub http01_challenges: usize,
    pub tls_alpn01_challenges: usize,
}

fn require_acme(state: &AdminState) -> Result<&Arc<crate::proxy::acme::AcmeManager>, GatewayError> {
    state
        .acme
        .as_ref()
        .ok_or_else(|| GatewayError::Internal("acme is disabled in gateway config".into()))
}

pub async fn set_http01_challenge(
    State(state): State<AdminState>,
    Json(req): Json<Http01ChallengeReq>,
) -> Result<StatusCode, GatewayError> {
    let mgr = require_acme(&state)?;
    if req.token.is_empty() || req.key_authorization.is_empty() {
        return Err(GatewayError::ConfigError(
            "token and key_authorization are required".into(),
        ));
    }
    mgr.set_challenge(req.token, req.key_authorization);
    Ok(StatusCode::CREATED)
}

pub async fn clear_http01_challenge(
    State(state): State<AdminState>,
    Path(token): Path<String>,
) -> Result<StatusCode, GatewayError> {
    let mgr = require_acme(&state)?;
    mgr.clear_challenge(&token);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn set_tls_alpn_challenge(
    State(state): State<AdminState>,
    Json(req): Json<TlsAlpnChallengeReq>,
) -> Result<StatusCode, GatewayError> {
    let mgr = require_acme(&state)?;
    if req.domain.is_empty() || req.key_authorization.is_empty() {
        return Err(GatewayError::ConfigError(
            "domain and key_authorization are required".into(),
        ));
    }
    mgr.set_tls_alpn_challenge(req.domain, req.key_authorization)?;
    Ok(StatusCode::CREATED)
}

pub async fn clear_tls_alpn_challenge(
    State(state): State<AdminState>,
    Path(domain): Path<String>,
) -> Result<StatusCode, GatewayError> {
    let mgr = require_acme(&state)?;
    mgr.clear_tls_alpn_challenge(&domain);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn acme_status(State(state): State<AdminState>) -> Json<AcmeStatus> {
    match state.acme.as_ref() {
        None => Json(AcmeStatus {
            enabled: false,
            has_cert: false,
            http01_challenges: 0,
            tls_alpn01_challenges: 0,
        }),
        Some(mgr) => Json(AcmeStatus {
            enabled: true,
            has_cert: mgr.has_cert().await,
            http01_challenges: mgr.http01_challenge_count(),
            tls_alpn01_challenges: mgr.tls_alpn_challenge_count(),
        }),
    }
}

// ── Projects CRUD ──

#[derive(Deserialize)]
pub struct CreateProject {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize)]
pub struct PatchProject {
    pub name: Option<String>,
    pub description: Option<String>,
}

pub async fn list_projects(
    State(state): State<AdminState>,
) -> Result<Json<Vec<Project>>, GatewayError> {
    let projects = state.repo.list_projects().await?;
    Ok(Json(projects))
}

pub async fn create_project(
    State(state): State<AdminState>,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<CreateProject>,
) -> Result<Json<Project>, GatewayError> {
    let project = Project::new(input.name, input.description);
    state.repo.create_project(&project).await?;
    tracing::info!(id = %project.id, "project created");
    state
        .audit
        .record(
            AuditAction::Create,
            ResourceType::Project,
            Some(project.id.to_string()),
            serde_json::to_value(&project).ok(),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ProjectChanged {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(project))
}

pub async fn get_project(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Response, GatewayError> {
    let project = state
        .repo
        .get_project(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("project {id}")))?;
    let etag = entity_etag(&project.id, &project.updated_at);
    Ok(json_with_etag(project, &etag))
}

pub async fn update_project(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
    Json(input): Json<PatchProject>,
) -> Result<Json<Project>, GatewayError> {
    let now = Utc::now();
    let existing = state
        .repo
        .get_project(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("project {id}")))?;
    check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;

    let updated = Project {
        id,
        name: input.name.unwrap_or_else(|| existing.name.clone()),
        description: input
            .description
            .unwrap_or_else(|| existing.description.clone()),
        created_at: existing.created_at,
        updated_at: now,
    };

    state.repo.update_project(&id, &updated).await?;
    state
        .audit
        .record(
            AuditAction::Update,
            ResourceType::Project,
            Some(id.to_string()),
            Some(serde_json::json!({ "before": existing, "after": updated })),
            actor_of(&actor),
        )
        .await;
    publish_event(
        &state,
        ChangeEvent::ProjectChanged {
            origin: state.node_id,
        },
    )
    .await;
    Ok(Json(updated))
}

pub async fn delete_project(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(actor): Extension<CurrentActor>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    if let Some(existing) = state.repo.get_project(&id).await? {
        check_if_match(&headers, &entity_etag(&existing.id, &existing.updated_at))?;
    }
    let service_ids = state.repo.soft_delete_services_for_project(&id).await?;
    for svc_id in &service_ids {
        cascade_soft_delete_service(&state, *svc_id).await;
    }
    let deleted = state.repo.delete_project(&id).await?;
    if deleted || !service_ids.is_empty() {
        if !service_ids.is_empty() {
            state.plugin_exec.rebuild(&state.repo).await?;
        }
        state
            .audit
            .record(
                AuditAction::Delete,
                ResourceType::Project,
                Some(id.to_string()),
                None,
                actor_of(&actor),
            )
            .await;
        publish_event(
            &state,
            ChangeEvent::ProjectChanged {
                origin: state.node_id,
            },
        )
        .await;
        Ok(Json(serde_json::json!({"deleted": true})))
    } else {
        Err(GatewayError::NotFound(format!("project {id}")))
    }
}

pub async fn list_project_services(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Service>>, GatewayError> {
    state
        .repo
        .get_project(&id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("project {id}")))?;
    let services = state.repo.list_services_for_project(&id).await?;
    Ok(Json(services))
}

// ── Logs ──

#[derive(Deserialize)]
pub struct LogQueryParams {
    pub service_id: Option<Uuid>,
    pub route_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub level: Option<String>,
    pub search: Option<String>,
    pub limit: Option<u32>,
}

pub async fn list_logs(
    State(state): State<AdminState>,
    Query(params): Query<LogQueryParams>,
) -> Result<Json<Vec<LogEntry>>, GatewayError> {
    let filter = LogFilter {
        service_id: params.service_id,
        route_id: params.route_id,
        project_id: params.project_id,
        level: params.level,
        search: params.search,
        limit: params.limit,
    };
    let logs = state.repo.list_logs(&filter).await?;
    Ok(Json(logs))
}

// ── Route Test ──

#[derive(Deserialize)]
pub struct RouteTestBody {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
pub struct RouteTestResult {
    pub url: String,
    pub status: u16,
    pub latency_ms: u64,
    pub headers: std::collections::HashMap<String, String>,
    pub body_preview: String,
    pub healthy: bool,
}

#[derive(Serialize)]
pub struct RouteTestResponse {
    pub external: RouteTestResult,
    pub internal: RouteTestResult,
}

pub async fn test_route(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<RouteTestBody>,
) -> Result<Json<RouteTestResponse>, GatewayError> {
    let route = state
        .route_table
        .get_route(&id)
        .ok_or_else(|| GatewayError::NotFound(format!("route {id}")))?;

    let service = state
        .repo
        .get_service(&route.service_id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("service {}", route.service_id)))?;

    let path = if body.path.starts_with('/') {
        body.path.clone()
    } else {
        format!("/{}", body.path)
    };

    let method: reqwest::Method = body
        .method
        .parse()
        .map_err(|_| GatewayError::BadRequest(format!("invalid method: {}", body.method)))?;

    let host = if !service.subdomain.is_empty() && !service.domain.is_empty() {
        format!("{}.{}", service.subdomain, service.domain)
    } else if !route.hosts.is_empty() {
        route.hosts[0].clone()
    } else {
        format!("127.0.0.1:{}", state.proxy_port)
    };

    let external_url = format!("http://127.0.0.1:{}{}", state.proxy_port, path);
    let internal_url = format!("{}{}", service.url.trim_end_matches('/'), path);

    let external = fire_test_request(
        &state.http_client,
        &method,
        &external_url,
        &host,
        &body.headers,
    )
    .await;

    let internal = fire_test_request(
        &state.http_client,
        &method,
        &internal_url,
        &host,
        &body.headers,
    )
    .await;

    Ok(Json(RouteTestResponse { external, internal }))
}

async fn fire_test_request(
    client: &reqwest::Client,
    method: &reqwest::Method,
    url: &str,
    host: &str,
    custom_headers: &std::collections::HashMap<String, String>,
) -> RouteTestResult {
    let start = std::time::Instant::now();
    let mut req = client.request(method.clone(), url).header("Host", host);
    for (k, v) in custom_headers {
        req = req.header(k.as_str(), v.as_str());
    }

    match req.send().await {
        Ok(resp) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status = resp.status().as_u16();
            let headers: std::collections::HashMap<String, String> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body_preview =
                String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(2048)]).to_string();

            RouteTestResult {
                url: url.to_string(),
                status,
                latency_ms,
                headers,
                body_preview,
                healthy: status < 500,
            }
        }
        Err(e) => RouteTestResult {
            url: url.to_string(),
            status: 0,
            latency_ms: start.elapsed().as_millis() as u64,
            headers: std::collections::HashMap::new(),
            body_preview: format!("connection error: {e}"),
            healthy: false,
        },
    }
}
