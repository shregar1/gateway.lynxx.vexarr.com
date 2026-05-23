pub mod alerts;
pub mod analytics;
pub mod cache;
pub mod cluster_mgmt;
pub mod config_api;
pub mod consumer_groups;
pub mod cost;
pub mod deploy;
pub mod docs;
pub mod error_pages;
pub mod graph;
pub mod incidents;
pub mod ip_rules;
pub mod loadtest;
pub mod marketplace;
pub mod pki;
pub mod probes;
pub mod profiling;
pub mod ratelimit_sim;
pub mod replay;
pub mod routes;
pub mod snapshots;
pub mod tracing_api;
pub mod transforms;
pub mod versioning;
pub mod webhooks;

use crate::audit::AuditLog;
use crate::auth::middleware::{extract_token, require_role};
use crate::auth::Role;
use crate::cluster::ClusterBus;
use crate::config::GatewayConfig;
use crate::db::Repository;
use crate::health::HealthRegistry;
use crate::plugins::PluginExecutor;
use crate::proxy::http_client::ProxyClientPool;
use crate::proxy::loadbalancer::LoadBalancerRegistry;
use crate::proxy::router::SharedRouteTable;
use crate::quota::QuotaTracker;
use crate::reload::ReloadHandle;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use chrono::Utc;
use http_body_util::BodyExt;
use metrics_exporter_prometheus::PrometheusHandle;
use routes::AdminState;
use rust_embed::RustEmbed;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

#[derive(RustEmbed)]
#[folder = "dashboard-dist/"]
struct DashboardAssets;

#[allow(clippy::too_many_arguments)]
pub fn admin_router(
    route_table: SharedRouteTable,
    repo: Arc<dyn Repository>,
    health: Arc<HealthRegistry>,
    lb: Arc<LoadBalancerRegistry>,
    metrics_handle: PrometheusHandle,
    reload: ReloadHandle,
    plugin_exec: Arc<PluginExecutor>,
    bus: Arc<dyn ClusterBus>,
    node_id: Uuid,
    auth_required: bool,
    client_pool: Arc<ProxyClientPool>,
    recording_store: Arc<crate::recording::ContentAddressedStore>,
    http_client: reqwest::Client,
    proxy_port: u16,
    quota: Arc<QuotaTracker>,
    acme: Option<Arc<crate::proxy::acme::AcmeManager>>,
    license_api_key: String,
    license_state: Option<crate::license::LicenseState>,
    gateway_config: GatewayConfig,
    deploy_registry: deploy::DeployRegistry,
    status_cache: crate::health::StatusCache,
    token_validator: Option<Arc<dyn crate::integrations::TokenValidator>>,
    token_cache: Option<Arc<crate::auth::middleware::AdminAuthCache>>,
) -> Router {
    let audit = AuditLog::new(repo.clone());
    let state = AdminState {
        route_table,
        repo,
        health,
        lb,
        start_time: Utc::now(),
        metrics_handle,
        reload,
        plugin_exec,
        bus,
        node_id,
        audit,
        auth_required,
        client_pool,
        recording_store,
        http_client,
        proxy_port,
        quota,
        acme,
        license_api_key,
        license_state,
        deploy_registry: Some(deploy_registry),
        status_cache,
        token_validator,
        token_cache,
    };

    // Routes that mutate live state require Operator or higher; token
    // management is Admin-only. Reads are Viewer.
    let viewer = require_role(Role::Viewer);
    let operator = require_role(Role::Operator);
    let admin_only = require_role(Role::Admin);

    // ---- read-only (viewer) ----
    let reads = Router::new()
        .route("/projects", get(routes::list_projects))
        .route("/projects/:id", get(routes::get_project))
        .route("/projects/:id/services", get(routes::list_project_services))
        .route("/services", get(routes::list_services))
        .route("/services/:id", get(routes::get_service))
        .route("/services/:id/targets", get(routes::list_service_targets))
        .route("/targets", get(routes::list_all_targets))
        .route("/targets/:id", get(routes::get_target_handler))
        .route("/routes", get(routes::list_routes))
        .route("/routes/:id", get(routes::get_route))
        .route("/plugins", get(routes::list_plugins))
        .route("/plugins/:id", get(routes::get_plugin))
        .route("/consumers", get(routes::list_consumers))
        .route("/health", get(routes::list_health))
        .route("/healthz", get(routes::healthz))
        .route("/health/:service_id", get(routes::get_health))
        .route("/status", get(routes::gateway_status))
        .route("/metrics", get(routes::metrics))
        .route("/quota", get(routes::quota_snapshot))
        .route("/circuit-breakers", get(routes::list_circuit_breakers))
        .route("/upstreams", get(routes::list_upstreams))
        .route("/debug/pprof/heap", get(profiling::heap_profile))
        .route("/debug/pprof/tasks", get(profiling::tasks_profile))
        .route("/debug/pprof/threads", get(profiling::threads_profile))
        .route("/debug/pprof/uptime", get(profiling::runtime_profile))
        .route("/debug/pprof/stats", get(profiling::combined_profile))
        .route("/logs", get(routes::list_logs))
        // ── analytics (read-only) ──
        .route("/services/:id/analytics", get(analytics::service_analytics))
        .route(
            "/services/:id/rate-limits",
            get(analytics::service_rate_limits),
        )
        .route(
            "/services/:id/rate-limit-stats",
            get(analytics::service_rate_limit_stats),
        )
        .route("/services/:id/geo", get(analytics::service_geo))
        // ── probes (read-only) ──
        .route("/services/:id/probes", get(probes::list_probes))
        .route("/probes/:id/results", get(probes::probe_results))
        .route("/probes/:id/stats", get(probes::probe_stats))
        // ── snapshots (read-only) ──
        .route("/services/:id/snapshots", get(snapshots::list_snapshots))
        // ── alerts (read-only) ──
        .route("/services/:id/alerts", get(alerts::list_alert_rules))
        .route("/services/:id/alert-events", get(alerts::list_alert_events))
        // ── ip rules (read-only) ──
        .route("/services/:id/ip-rules", get(ip_rules::list_ip_rules))
        // ── error pages (read-only) ──
        .route(
            "/services/:id/error-pages",
            get(error_pages::list_error_pages),
        )
        // ── consumer groups (read-only) ──
        .route(
            "/services/:id/consumer-groups",
            get(consumer_groups::list_consumer_groups),
        )
        .route(
            "/consumer-groups/:id/members",
            get(consumer_groups::list_members),
        )
        .route(
            "/consumer-groups/:id/usage",
            get(consumer_groups::group_usage),
        )
        // ── dependency graph ──
        .route("/services/:id/graph", get(graph::service_graph))
        // ── api docs ──
        .route("/services/:id/docs", get(docs::service_docs))
        // ── cache (read-only) ──
        .route("/services/:id/cache", get(cache::list_cache_entries))
        .route("/services/:id/cache/stats", get(cache::cache_stats))
        // ── tracing (read-only) ──
        .route("/services/:id/traces", get(tracing_api::list_traces))
        .route("/traces/:id", get(tracing_api::get_trace))
        .route("/traces/:id/spans", get(tracing_api::list_spans))
        // ── transforms (read-only) ──
        .route("/services/:id/transforms", get(transforms::list_transforms))
        // ── versioning (read-only) ──
        .route("/services/:id/versions", get(versioning::list_versions))
        // ── incidents (read-only) ──
        .route("/services/:id/incidents", get(incidents::list_incidents))
        .route("/incidents/:id", get(incidents::get_incident))
        .route(
            "/incidents/:id/updates",
            get(incidents::list_incident_updates),
        )
        // ── webhooks (read-only) ──
        .route("/services/:id/webhooks", get(webhooks::list_webhooks))
        .route("/webhooks/:id", get(webhooks::get_webhook))
        .route("/webhooks/:id/deliveries", get(webhooks::list_deliveries))
        // ── load testing (read-only) ──
        .route("/services/:id/load-tests", get(loadtest::list_load_tests))
        .route("/load-tests/:id", get(loadtest::get_load_test))
        // ── marketplace (read-only) ──
        .route("/marketplace/plugins", get(marketplace::list_plugins))
        .route("/marketplace/plugins/:id", get(marketplace::get_plugin))
        // ── cost analytics (read-only) ──
        .route("/services/:id/costs", get(cost::list_cost_records))
        .route("/services/:id/costs/summary", get(cost::cost_summary))
        // ── cluster management (read-only) ──
        .route("/cluster/nodes", get(cluster_mgmt::list_nodes))
        .route("/cluster/nodes/:id", get(cluster_mgmt::get_node))
        // ── rate limit simulator (read-only) ──
        .route(
            "/services/:id/rate-limit-sim",
            get(ratelimit_sim::list_simulations),
        )
        .route("/rate-limit-sim/:id", get(ratelimit_sim::get_simulation))
        // ── PKI / certificates (read-only) ──
        .route("/certificates", get(pki::list_certificates))
        .route("/certificates/:id", get(pki::get_certificate))
        // ── circuit breaker per-service (read-only) ──
        .route(
            "/services/:id/circuit-breaker",
            get(routes::get_service_circuit_breaker),
        )
        .route_layer(middleware::from_fn(viewer));

    // ---- mutations (operator) ----
    let mutations = Router::new()
        .route("/projects", post(routes::create_project))
        .route(
            "/projects/:id",
            patch(routes::update_project).delete(routes::delete_project),
        )
        .route("/services", post(routes::create_service))
        .route(
            "/services/:id",
            put(routes::update_service)
                .patch(routes::patch_service)
                .delete(routes::delete_service),
        )
        .route("/services/:id/targets", post(routes::create_service_target))
        .route(
            "/targets/:id",
            put(routes::update_target_handler).delete(routes::delete_target_handler),
        )
        .route("/routes", post(routes::create_route))
        .route(
            "/routes/:id",
            put(routes::update_route)
                .patch(routes::patch_route)
                .delete(routes::delete_route),
        )
        .route("/plugins", post(routes::create_plugin))
        .route(
            "/plugins/:id",
            put(routes::update_plugin).delete(routes::delete_plugin),
        )
        .route("/consumers", post(routes::create_consumer))
        .route("/consumers/:id", delete(routes::delete_consumer))
        .route("/reload", post(routes::reload_handler))
        // audit read access lives here — operator+ may inspect, viewers may not.
        .route("/audit", get(routes::list_audit))
        .route("/audit/verify", get(routes::verify_audit))
        // recordings (Time-Travel Debug A3)
        .route("/recordings", get(routes::list_recordings))
        .route(
            "/recordings/:id",
            get(routes::get_recording).delete(routes::delete_recording_handler),
        )
        .route("/recordings/:id/replay", post(routes::replay_recording))
        .route("/routes/:id/test", post(routes::test_route))
        // ACME challenge endpoints — let an external orchestrator
        // (lego, certbot --manual, custom client) push HTTP-01 and
        // TLS-ALPN-01 challenges into the running gateway without
        // restarting it.
        .route(
            "/acme/http-01-challenges",
            post(routes::set_http01_challenge),
        )
        .route(
            "/acme/http-01-challenges/:token",
            axum::routing::delete(routes::clear_http01_challenge),
        )
        .route(
            "/acme/tls-alpn-01-challenges",
            post(routes::set_tls_alpn_challenge),
        )
        .route(
            "/acme/tls-alpn-01-challenges/:domain",
            axum::routing::delete(routes::clear_tls_alpn_challenge),
        )
        .route("/acme/status", get(routes::acme_status))
        .route("/acme/renew", post(routes::acme_renew))
        .route("/acme/revoke", post(routes::acme_revoke))
        .route(
            "/circuit-breakers/:service_id/reset",
            post(routes::reset_circuit_breaker),
        )
        .route("/services/:id/deploy", post(deploy::start_deploy))
        .route("/services/:id/deploy/status", get(deploy::deploy_status))
        // ── probes (mutations) ──
        .route("/services/:id/probes", post(probes::create_probe))
        .route(
            "/probes/:id",
            patch(probes::patch_probe).delete(probes::delete_probe),
        )
        // ── snapshots (mutations) ──
        .route("/services/:id/snapshots", post(snapshots::create_snapshot))
        .route(
            "/services/:id/snapshots/:sid/diff",
            get(snapshots::snapshot_diff),
        )
        .route(
            "/services/:id/snapshots/:sid/rollback",
            post(snapshots::rollback_snapshot),
        )
        .route(
            "/services/:id/snapshots/:sid",
            delete(snapshots::delete_snapshot),
        )
        // ── alerts (mutations) ──
        .route("/services/:id/alerts", post(alerts::create_alert_rule))
        .route(
            "/alerts/:id",
            patch(alerts::patch_alert_rule).delete(alerts::delete_alert_rule),
        )
        .route(
            "/alert-events/:id/resolve",
            post(alerts::resolve_alert_event),
        )
        .route("/alerts/:id/test", post(alerts::test_alert))
        // ── ip rules (mutations) ──
        .route("/services/:id/ip-rules", post(ip_rules::create_ip_rule))
        .route(
            "/services/:id/ip-rules/bulk",
            post(ip_rules::bulk_create_ip_rules),
        )
        .route(
            "/ip-rules/:id",
            patch(ip_rules::patch_ip_rule).delete(ip_rules::delete_ip_rule),
        )
        // ── error pages (mutations) ──
        .route(
            "/services/:id/error-pages",
            post(error_pages::create_error_page),
        )
        .route(
            "/error-pages/:id",
            patch(error_pages::patch_error_page).delete(error_pages::delete_error_page),
        )
        // ── consumer groups (mutations) ──
        .route(
            "/services/:id/consumer-groups",
            post(consumer_groups::create_consumer_group),
        )
        .route(
            "/consumer-groups/:id",
            patch(consumer_groups::patch_consumer_group)
                .delete(consumer_groups::delete_consumer_group),
        )
        .route(
            "/consumer-groups/:id/members",
            post(consumer_groups::add_member),
        )
        .route(
            "/consumer-groups/:id/members/:cid",
            delete(consumer_groups::remove_member),
        )
        // ── proxy helpers ──
        .route("/proxy/try", post(docs::proxy_try))
        .route("/proxy/replay", post(replay::proxy_replay))
        // ── consumer key regen ──
        .route(
            "/consumers/:id/regenerate-key",
            post(routes::regenerate_consumer_key),
        )
        // ── cache (mutations) ──
        .route("/services/:id/cache/purge", post(cache::purge_cache))
        .route("/services/:id/cache/warm", post(cache::warm_cache))
        // ── tracing (mutations) ──
        .route("/services/:id/traces", post(tracing_api::ingest_trace))
        // ── transforms (mutations) ──
        .route(
            "/services/:id/transforms",
            post(transforms::create_transform),
        )
        .route(
            "/transforms/:id",
            patch(transforms::patch_transform).delete(transforms::delete_transform),
        )
        // ── versioning (mutations) ──
        .route("/services/:id/versions", post(versioning::create_version))
        .route(
            "/versions/:id",
            patch(versioning::patch_version).delete(versioning::delete_version),
        )
        // ── incidents (mutations) ──
        .route("/services/:id/incidents", post(incidents::create_incident))
        .route(
            "/incidents/:id",
            patch(incidents::update_incident).delete(incidents::delete_incident),
        )
        .route(
            "/incidents/:id/updates",
            post(incidents::create_incident_update),
        )
        // ── webhooks (mutations) ──
        .route("/services/:id/webhooks", post(webhooks::create_webhook))
        .route(
            "/webhooks/:id",
            patch(webhooks::patch_webhook).delete(webhooks::delete_webhook),
        )
        .route("/webhooks/:id/test", post(webhooks::test_webhook))
        // ── load testing (mutations) ──
        .route("/services/:id/load-tests", post(loadtest::create_load_test))
        .route("/load-tests/:id", delete(loadtest::delete_load_test))
        // ── marketplace (mutations) ──
        .route("/marketplace/plugins", post(marketplace::install_plugin))
        // ── cluster management (mutations) ──
        .route("/cluster/nodes/:id/drain", post(cluster_mgmt::drain_node))
        .route("/cluster/nodes/:id", delete(cluster_mgmt::remove_node))
        // ── rate limit simulator (mutations) ──
        .route(
            "/services/:id/rate-limit-sim",
            post(ratelimit_sim::run_simulation),
        )
        // ── PKI / certificates (mutations) ──
        .route("/certificates", post(pki::create_certificate))
        .route("/certificates/:id", delete(pki::delete_certificate))
        // ── circuit breaker per-service (mutations) ──
        .route(
            "/services/:id/circuit-breaker",
            patch(routes::patch_service_circuit_breaker),
        )
        // ── probes (mutations) ──
        .route("/services/:id/probes", post(probes::create_probe))
        .route("/probes/:id", patch(probes::patch_probe).delete(probes::delete_probe))
        // ── snapshots (mutations) ──
        .route("/services/:id/snapshots", post(snapshots::create_snapshot))
        .route("/services/:id/snapshots/:sid/diff", get(snapshots::snapshot_diff))
        .route("/services/:id/snapshots/:sid/rollback", post(snapshots::rollback_snapshot))
        .route("/services/:id/snapshots/:sid", delete(snapshots::delete_snapshot))
        // ── alerts (mutations) ──
        .route("/services/:id/alerts", post(alerts::create_alert_rule))
        .route("/alerts/:id", patch(alerts::patch_alert_rule).delete(alerts::delete_alert_rule))
        .route("/alert-events/:id/resolve", post(alerts::resolve_alert_event))
        .route("/alerts/:id/test", post(alerts::test_alert))
        // ── ip rules (mutations) ──
        .route("/services/:id/ip-rules", post(ip_rules::create_ip_rule))
        .route("/services/:id/ip-rules/bulk", post(ip_rules::bulk_create_ip_rules))
        .route("/ip-rules/:id", patch(ip_rules::patch_ip_rule).delete(ip_rules::delete_ip_rule))
        // ── error pages (mutations) ──
        .route("/services/:id/error-pages", post(error_pages::create_error_page))
        .route("/error-pages/:id", patch(error_pages::patch_error_page).delete(error_pages::delete_error_page))
        // ── consumer groups (mutations) ──
        .route("/services/:id/consumer-groups", post(consumer_groups::create_consumer_group))
        .route("/consumer-groups/:id", patch(consumer_groups::patch_consumer_group).delete(consumer_groups::delete_consumer_group))
        .route("/consumer-groups/:id/members", post(consumer_groups::add_member))
        .route("/consumer-groups/:id/members/:cid", delete(consumer_groups::remove_member))
        // ── proxy helpers ──
        .route("/proxy/try", post(docs::proxy_try))
        .route("/proxy/replay", post(replay::proxy_replay))
        .route_layer(middleware::from_fn(operator));

    // ---- token management (admin) ----
    let tokens = Router::new()
        .route(
            "/tokens",
            get(routes::list_tokens).post(routes::create_token),
        )
        .route(
            "/tokens/:id",
            put(routes::update_token).delete(routes::delete_token),
        )
        .route_layer(middleware::from_fn(admin_only));

    // ---- live config API ----
    let config_store = config_api::ConfigStore::new(gateway_config);
    let config_sub =
        config_api::config_router(config_store).layer(middleware::from_fn(api_envelope));

    // ---- dashboard serving ----
    let dashboard = Router::new().fallback(dashboard_handler);

    // ---- routes assembly ----
    let api = reads
        .merge(mutations)
        .merge(tokens)
        .layer(middleware::from_fn_with_state(state.clone(), extract_token))
        .layer(middleware::from_fn(api_envelope));

    // Public sign-in endpoint. The node dashboard hits this with the
    // customer's api key as Bearer; the gateway forwards it to the
    // licence backend (keyx) and returns the licence info. Bypasses
    // `extract_token` so unrecognised keys can be validated — they're
    // the WHOLE POINT of the endpoint.
    let auth_public = Router::new()
        .route("/auth/sign-in", post(routes::auth_sign_in))
        .layer(middleware::from_fn(api_envelope));

    dashboard
        .merge(api)
        .merge(auth_public)
        .with_state(state)
        .nest("/admin/v1/config", config_sub)
        .layer(middleware::from_fn(spa_navigation_guard))
        .layer(admin_cors())
}

/// Browser navigation requests (`Accept: text/html`) get the SPA shell
/// instead of hitting API routes like `/services` that would return JSON.
///
/// Also normalises trailing slashes on `/admin/*` paths in-place so that
/// `/admin/v1/config/` routes the same as `/admin/v1/config` — axum 0.7's
/// `nest()` doesn't match the inner `/` route under both forms.
async fn spa_navigation_guard(mut req: Request, next: Next) -> Response {
    // Trailing-slash normalisation for nested admin routes — see
    // comment above. We rebuild the Uri via its `Parts` because
    // `Uri::from_str` rejects origin-form paths in some http crate
    // versions; assembling Parts goes through the path-and-query
    // parser directly.
    {
        let path = req.uri().path().to_string();
        if path.starts_with("/admin/") && path.len() > "/admin/".len() && path.ends_with('/') {
            let trimmed = path.trim_end_matches('/');
            let new_pq_str = match req.uri().query() {
                Some(q) => format!("{trimmed}?{q}"),
                None => trimmed.to_string(),
            };
            if let Ok(new_pq) = new_pq_str.parse::<axum::http::uri::PathAndQuery>() {
                let mut parts = req.uri().clone().into_parts();
                parts.path_and_query = Some(new_pq);
                if let Ok(new_uri) = Uri::from_parts(parts) {
                    tracing::debug!(from = %path, to = %new_uri, "normalised trailing slash on admin path");
                    *req.uri_mut() = new_uri;
                }
            }
        }
    }

    if req.method() == Method::GET {
        let prefers_html = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("text/html"))
            .unwrap_or(false);

        let path = req.uri().path();
        let is_static_asset = path.contains('.') && !path.ends_with(".html");

        if prefers_html && !is_static_asset {
            return index_handler().await.into_response();
        }
    }

    next.run(req).await
}

async fn dashboard_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // /admin/* paths are API surface. If we got here, the route truly
    // doesn't exist — return a proper envelope-shaped 404 instead of
    // silently serving the SPA shell (which would mask the routing
    // miss with a 200 + HTML).
    if path.starts_with("admin/") || path == "admin" {
        let body = serde_json::json!({
            "transactionUrn":  format!("urn:lynxx:err:{}", Uuid::new_v4()),
            "status":          "FAILED",
            "responseMessage": "Not Found",
            "responseKey":     "NOT_FOUND",
            "errors":          [{ "code": "NOT_FOUND", "message": format!("route /{path} not found") }],
            "timestamp":       Utc::now().to_rfc3339(),
            "metadata":        {},
            "data":            serde_json::Value::Null,
            "reference_urn":   "",
        });
        return (StatusCode::NOT_FOUND, axum::Json(body)).into_response();
    }

    if path.is_empty() || path == "index.html" {
        return index_handler().await.into_response();
    }

    match DashboardAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => {
            // Fallback to index.html for SPA routing
            index_handler().await.into_response()
        }
    }
}

async fn index_handler() -> impl IntoResponse {
    match DashboardAssets::get("index.html") {
        Some(content) => Html(content.data).into_response(),
        None => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
    }
}

async fn api_envelope(req: Request, next: Next) -> Response {
    use crate::dtos::envelope::ApiEnvelope;

    let txn_urn = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    let reference_urn = req
        .headers()
        .get("X-Reference-URN")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let response = next.run(req).await;
    let status_code = response.status();

    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    let is_no_content = status_code == StatusCode::NO_CONTENT;

    if !is_json && !is_no_content && status_code.is_success() {
        return response;
    }

    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

    let data: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };

    let envelope: serde_json::Value = if status_code.is_success() {
        let env = ApiEnvelope::success(data, txn_urn, timestamp, reference_urn);
        serde_json::to_value(env).unwrap_or_default()
    } else {
        let response_key = match status_code.as_u16() {
            400 => "VALIDATION_ERROR",
            401 => "UNAUTHORIZED",
            403 => "FORBIDDEN",
            404 => "NOT_FOUND",
            409 => "CONFLICT",
            412 => "PRECONDITION_FAILED",
            429 => "QUOTA_EXCEEDED",
            502 => "BAD_GATEWAY",
            503 => "SERVICE_UNAVAILABLE",
            _ => "INTERNAL_ERROR",
        };
        let msg = data
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("An error occurred");
        let env = ApiEnvelope::error(response_key, msg, txn_urn, timestamp, reference_urn);
        serde_json::to_value(env).unwrap_or_default()
    };

    let body_bytes = serde_json::to_vec(&envelope).unwrap_or_default();
    let content_len = body_bytes.len();
    let mut response = Response::from_parts(parts, Body::from(body_bytes));
    *response.status_mut() = status_code;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(content_len));
    response
}

fn admin_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .allow_origin(Any)
        .expose_headers(Any)
}
