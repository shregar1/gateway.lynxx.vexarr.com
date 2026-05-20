use crate::admin::deploy::DeployRegistry;
use crate::error::GatewayError;
use crate::health::passive::PassiveHealthTracker;
use crate::health::HealthRegistry;
use crate::metrics as gw_metrics;
use crate::models::TargetLifecycle;
use crate::plugins::PluginExecutor;
use crate::proxy::grpc::{handle_grpc, GrpcClient};
use crate::proxy::http_client::{HttpProxyClient, ProxyClientPool};
use crate::proxy::loadbalancer::{
    InFlightGuard, LbStrategy, LoadBalancerRegistry, RequestContext, STICKY_COOKIE_NAME,
};
use crate::proxy::router::SharedRouteTable;
use crate::proxy::websocket::handle_websocket;
use crate::quota::QuotaTracker;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Instant;

/// Context attached to the request after the proxy matches a service+route
/// but before the plugin chain runs. Plugins (notably `request-recorder`)
/// pull this out of the request extensions to enrich their own captures
/// without re-doing the routing work.
#[derive(Clone, Debug)]
pub struct MatchContext {
    pub service_id: uuid::Uuid,
    pub route_id: uuid::Uuid,
    pub upstream_url: String,
    pub consumer_username: Option<String>,
}

#[derive(Clone)]
pub struct ProxyState {
    pub route_table: SharedRouteTable,
    pub plugins: Arc<PluginExecutor>,
    pub log_writer: crate::logs::LogWriter,
    /// Parsed CIDR ranges for trusted proxy validation. When non-empty,
    /// X-Forwarded-For is only honoured from source IPs matching a range.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Streaming hyper-util client used for the default HTTP/1.1 + HTTP/2
    /// proxy hot path. Bodies forward without buffering. See
    /// `crate::proxy::http_client` for the rationale.
    ///
    /// For HTTPS upstreams that need bespoke TLS (mTLS, private CA, or
    /// `tls_verify = false`) the pool keeps per-service clients keyed
    /// by service id; the `default_client` here is used for everything
    /// else (the common case).
    pub http_client: HttpProxyClient,
    /// Per-service client pool. See [`ProxyClientPool`] for cache semantics.
    pub client_pool: Arc<ProxyClientPool>,
    pub grpc_client: GrpcClient,
    pub health: Arc<HealthRegistry>,
    pub lb: Arc<LoadBalancerRegistry>,
    pub passive_health: Arc<PassiveHealthTracker>,
    pub quota: Arc<QuotaTracker>,
    /// Live licence state. The proxy hot path checks `is_active()`
    /// before serving — flipped off by the periodic re-verifier when
    /// the licence server reports the key is no longer active.
    pub license: crate::license::LicenseState,
    pub deploy_registry: Option<DeployRegistry>,
    pub local_zone: Option<String>,
    /// When true, the success-path telemetry block (prometheus counter +
    /// histogram + access-log write) is skipped. Initialised from
    /// `config.gateway.minimal_telemetry` at startup — the env-var override
    /// happens in `config::apply_env_overrides` so this struct only sees
    /// the resolved value. Per-request cost when false is one bool load.
    pub minimal_telemetry: bool,
}

// ── Phase 1F helpers: gated per-request telemetry
//
// Each per-request metric / access-log emission goes through these methods
// instead of inlining the macro. The `minimal_telemetry` gate lives ONCE
// here, so flipping the config knob deterministically silences every
// per-request signal — no scattered `if !state.minimal_telemetry` blocks
// to maintain. Label `.to_string()` allocations happen ONLY when telemetry
// is actually enabled.
impl ProxyState {
    #[inline]
    fn record_request_metric(
        &self,
        svc: &str,
        route: &str,
        method: &str,
        status: &'static str,
        target: &str,
    ) {
        if self.minimal_telemetry {
            return;
        }
        metrics::counter!(
            "lynxx_requests_total",
            "service" => svc.to_string(),
            "route" => route.to_string(),
            "method" => method.to_string(),
            "status" => status,
            "target" => target.to_string(),
        )
        .increment(1);
    }

    #[inline]
    fn record_request_duration(
        &self,
        svc: &str,
        route: &str,
        method: &str,
        target: &str,
        seconds: f64,
    ) {
        if self.minimal_telemetry {
            return;
        }
        metrics::histogram!(
            "lynxx_request_duration_seconds",
            "service" => svc.to_string(),
            "route" => route.to_string(),
            "method" => method.to_string(),
            "target" => target.to_string(),
        )
        .record(seconds);
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn log_request(
        &self,
        method: &str,
        path: &str,
        client_ip: &str,
        service_id: Option<uuid::Uuid>,
        route_id: Option<uuid::Uuid>,
        project_id: Option<uuid::Uuid>,
        status: Option<u16>,
        duration_ms: i64,
        level: &str,
        message: &str,
    ) {
        if self.minimal_telemetry {
            return;
        }
        self.log_writer.log(
            method,
            path,
            client_ip,
            service_id,
            route_id,
            project_id,
            status,
            duration_ms,
            level,
            message,
        );
    }
}

/// Hop-by-hop headers that must not be forwarded to the upstream. RFC 7230 §6.1.
/// `host` is also excluded so hyper synthesises it from the upstream URI.
const HOP_BY_HOP: [&str; 9] = [
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

#[inline]
fn is_hop_by_hop(name: &HeaderName) -> bool {
    let s = name.as_str();
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(s))
}

fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .find_map(|pair| {
            let pair = pair.trim();
            let (key, val) = pair.split_once('=')?;
            if key.trim() == name {
                Some(val.trim().to_string())
            } else {
                None
            }
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolKind {
    WebSocket,
    Grpc,
    GrpcWeb,
    Http,
}

fn detect_protocol(req: &Request<Body>) -> ProtocolKind {
    let is_websocket = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_websocket {
        return ProtocolKind::WebSocket;
    }

    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.starts_with("application/grpc-web") {
        return ProtocolKind::GrpcWeb;
    }
    if content_type.starts_with("application/grpc") {
        return ProtocolKind::Grpc;
    }

    ProtocolKind::Http
}

/// Parse a `unix:///path/to/socket` URL into `(socket_path, http_path)`.
/// Format: `unix:///var/run/app.sock` or `unix:///var/run/app.sock:/custom/path`
/// The part after the colon-separated path is the HTTP request path.
fn parse_unix_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("unix://")?;
    if let Some((sock, path)) = rest.split_once(':') {
        Some((sock.to_string(), path.to_string()))
    } else {
        Some((rest.to_string(), "/".to_string()))
    }
}

/// Proxy a request over a Unix domain socket using raw hyper HTTP/1.1.
#[cfg(unix)]
async fn proxy_via_unix(
    socket_path: &str,
    mut req: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| GatewayError::UpstreamError(format!("unix connect {socket_path}: {e}")))?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| GatewayError::UpstreamError(format!("unix handshake {socket_path}: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "unix upstream connection closed");
        }
    });

    // Ensure the request has a Host header (required by HTTP/1.1).
    if !req.headers().contains_key(axum::http::header::HOST) {
        if let Ok(v) = axum::http::HeaderValue::from_str("localhost") {
            req.headers_mut().insert(axum::http::header::HOST, v);
        }
    }

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| GatewayError::UpstreamError(format!("unix upstream send: {e}")))?;

    let (parts, incoming) = resp.into_parts();
    Ok(Response::from_parts(parts, Body::new(incoming)))
}

pub async fn proxy_handler(
    State(state): State<ProxyState>,
    mut req: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let start = Instant::now();
    // Clone the `Uri` once at the top so `path` / `query_string` can be
    // borrowed `&str` for the rest of the function without holding an
    // immutable borrow on `req` (which is mutated downstream). Internally
    // `Uri` wraps refcounted `Bytes`, so this is two atomic increments
    // (~10ns) and avoids the heap allocation that
    // `req.uri().path().to_string()` would do per request.
    let uri = req.uri().clone();
    let path: &str = uri.path();
    let query_string: Option<&str> = uri.query();
    // `Method` is a small enum — clone is cheap for the standard verbs
    // (no allocation) and we need it owned so `method.as_str()` borrows
    // from a local rather than from `req`.
    let method_obj = req.method().clone();
    let method: &str = method_obj.as_str();
    // HTTP/1.1 sends the hostname in the `Host` header; HTTP/2 uses the
    // `:authority` pseudo-header which hyper maps into `uri.host()`.
    // Check both so route matching works regardless of protocol version.
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| uri.host().map(|h| h.to_string()));

    let peer_ip_early = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();

    // Subdomain routing: try matching host against service domain/subdomain first.
    let host_match = host.as_deref().and_then(|h| {
        let svc = state.route_table.match_by_host(h)?;
        let route = state
            .route_table
            .match_route_for_service(&svc.id, path, method)
            .unwrap_or_else(|| std::sync::Arc::new(crate::models::Route::passthrough(svc.id)));
        Some((route, svc))
    });

    let (route, service) = match host_match.or_else(|| {
        state.route_table.match_route_full(
            path,
            method,
            host.as_deref(),
            Some(req.headers()),
            query_string,
        )
    }) {
        Some(pair) => pair,
        None => {
            state.record_request_metric("-", "-", method, "no_route", "-");
            state.log_request(
                method,
                path,
                &peer_ip_early,
                None,
                None,
                None,
                None,
                start.elapsed().as_millis() as i64,
                "error",
                "no matching route",
            );
            // Browsers (Accept: text/html) get a branded page with instructions
            // for registering the missing route. API/SDK callers fall through
            // to the existing JSON error body so machine parsers don't break.
            if crate::proxy::error_pages::wants_html(req.headers()) {
                return Ok(crate::proxy::error_pages::render_route_not_found(path));
            }
            return Err(GatewayError::RouteNotFound(path.to_string()));
        }
    };

    let svc_name = service.name.clone();
    let route_id = route.id.to_string();
    // `method` and `path` are &str borrowed from owned locals (method_obj /
    // uri) at the top of this function, so they remain valid through every
    // downstream call. No need to allocate `log_method` / `log_path`
    // copies — pass `method` / `path` directly to `log_writer.log()`.
    let log_svc_id = Some(service.id);
    let log_route_id = Some(route.id);
    let log_project_id = service.project_id;

    if route.health_gate && !state.lb.has_healthy_active_target(&service.id) {
        state.record_request_metric(&svc_name, &route_id, method, "health_gated", "-");
        state.log_request(
            method,
            path,
            &peer_ip_early,
            log_svc_id,
            log_route_id,
            log_project_id,
            Some(503),
            start.elapsed().as_millis() as i64,
            "error",
            "health gated — no healthy targets",
        );
        return Err(GatewayError::ServiceUnavailable(format!(
            "service {} has no healthy targets",
            service.name
        )));
    }

    let open_duration_ms = state.health.config().open_duration_ms;
    if !state
        .health
        .should_allow_request(&service.id, open_duration_ms)
    {
        state.record_request_metric(&svc_name, &route_id, method, "circuit_open", "-");
        state.log_request(
            method,
            path,
            &peer_ip_early,
            log_svc_id,
            log_route_id,
            log_project_id,
            Some(503),
            start.elapsed().as_millis() as i64,
            "error",
            "circuit breaker open",
        );
        return Err(GatewayError::CircuitOpen(format!(
            "service {} circuit breaker open",
            service.name
        )));
    }

    // Licence kill-switch — flipped off by the background re-verifier
    // when the licence server reports the key is cancelled / invalid.
    // Returns 402 Payment Required so customers see a clear billing
    // signal rather than a generic 5xx.
    if !state.license.is_active() {
        state.record_request_metric(&svc_name, &route_id, method, "license_revoked", "-");
        state.log_request(
            method,
            path,
            &peer_ip_early,
            log_svc_id,
            log_route_id,
            log_project_id,
            Some(402),
            start.elapsed().as_millis() as i64,
            "error",
            "license revoked",
        );
        return Err(GatewayError::LicenseRevoked);
    }

    let quota_result = state.quota.check_and_count();
    if quota_result == crate::quota::QuotaResult::Rejected {
        state.record_request_metric(&svc_name, &route_id, method, "quota_exceeded", "-");
        state.log_request(
            method,
            path,
            &peer_ip_early,
            log_svc_id,
            log_route_id,
            log_project_id,
            Some(429),
            start.elapsed().as_millis() as i64,
            "error",
            "quota exceeded",
        );
        return Err(GatewayError::QuotaExceeded);
    }
    let is_overage = quota_result == crate::quota::QuotaResult::Overage;

    // Extract client IP, respecting trusted_proxies CIDR allowlist.
    // When trusted_proxies is configured, only honour X-Forwarded-For
    // from source addresses that match the allowlist.
    let peer_ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|a| a.ip());
    let trust_headers = if state.trusted_proxies.is_empty() {
        true // no allowlist → trust unconditionally (backward compat)
    } else {
        peer_ip
            .map(|ip| state.trusted_proxies.iter().any(|net| net.contains(&ip)))
            .unwrap_or(false)
    };
    let client_ip_owned = if trust_headers {
        req.headers()
            .get("x-real-ip")
            .or_else(|| req.headers().get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .unwrap_or_else(|| peer_ip.map(|ip| ip.to_string()).unwrap_or_default())
    } else {
        peer_ip.map(|ip| ip.to_string()).unwrap_or_default()
    };
    let sticky_cookie_owned = extract_cookie(req.headers(), STICKY_COOKIE_NAME);
    // Extract header/query hash values for hash-based LB strategies.
    let header_hash_owned = service.lb_hash_header.as_ref().and_then(|hdr| {
        req.headers()
            .get(hdr.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });
    let query_hash_owned = service.lb_hash_query_param.as_ref().and_then(|param| {
        req.uri().query().and_then(|qs| {
            url::form_urlencoded::parse(qs.as_bytes())
                .find(|(k, _)| k == param)
                .map(|(_, v)| v.to_string())
        })
    });
    let lb_ctx = RequestContext {
        client_ip: Some(client_ip_owned.as_str()),
        uri_path: Some(path),
        sticky_cookie: sticky_cookie_owned.as_deref(),
        header_hash_value: header_hash_owned.as_deref(),
        query_hash_value: query_hash_owned.as_deref(),
    };

    // Pick a target via load balancer if one is configured for this service.
    // Falls back to `service.url` if no targets exist.
    let picked = state
        .lb
        .pick(&service.id, state.local_zone.as_deref(), &lb_ctx);
    let mut picked_target_id = picked.as_ref().map(|ts| ts.target.id);
    let (upstream_base, mut target_label, _in_flight): (Arc<str>, Arc<str>, _) = match &picked {
        Some(ts) => {
            let guard = InFlightGuard::new(ts.clone());
            (ts.target.url.clone(), ts.target.url.clone(), Some(guard))
        }
        // Fallback: no LB targets — use the service's default URL. The
        // `Arc::from(&str)` allocates once here (cold path; only hit when
        // a service has no `targets` rows) so downstream consumers can
        // treat `upstream_base` uniformly as `Arc<str>`.
        None => (Arc::from(service.url.as_str()), Arc::from("-"), None),
    };

    // Compute upstream_url up-front so we can attach it to the MatchContext
    // before plugins run; the recorder needs it to populate `Recording.upstream_url`.
    let upstream_path = state.route_table.resolve_upstream_path(&route, path);
    // Reuse the `query_string: Option<&str>` borrowed from the owned `uri`
    // at the top of the function — saves the redundant `to_string()` that
    // the original code did here just to satisfy the downstream &str use.
    let trimmed_base = upstream_base.trim_end_matches('/');
    let mut upstream_url = String::with_capacity(
        trimmed_base.len() + upstream_path.len() + query_string.map(|q| q.len() + 1).unwrap_or(0),
    );
    upstream_url.push_str(trimmed_base);
    upstream_url.push_str(&upstream_path);
    if let Some(q) = query_string {
        upstream_url.push('?');
        upstream_url.push_str(q);
    }

    // Stash routing context on the request so plugins (e.g. request-recorder)
    // can read service_id / route_id / upstream_url without re-matching. The
    // only reader is `src/plugins/request_recorder/mod.rs`; if the plugin
    // executor is empty, no plugin will ever observe this — saves a header
    // lookup, a `String` alloc, a `String::clone`, and a `Box` allocation on
    // the no-plugin hot path. `PluginExecutor::is_empty()` is a single
    // atomic load so the gate is essentially free.
    if !state.plugins.is_empty() {
        let consumer_username = req
            .headers()
            .get("x-consumer-username")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        req.extensions_mut().insert(MatchContext {
            service_id: service.id,
            route_id: route.id,
            upstream_url: upstream_url.clone(),
            consumer_username,
        });

        state
            .plugins
            .run_request(&mut req, Some(service.id), Some(route.id))
            .await
            .map_err(GatewayError::PluginError)?;
    }

    // ── Static file serving: short-circuit the proxy path ──
    if service.service_type == "static" {
        if let Some(ref root) = service.document_root {
            let accept_enc = req
                .headers()
                .get(axum::http::header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let if_none_match = req
                .headers()
                .get(axum::http::header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let if_modified_since = req
                .headers()
                .get(axum::http::header::IF_MODIFIED_SINCE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let range_header = req
                .headers()
                .get(axum::http::header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let serve_opts = crate::proxy::static_files::ServeOptions {
                hide_patterns: &[],
                cache_control: None,
                if_none_match: if_none_match.as_deref(),
                if_modified_since: if_modified_since.as_deref(),
                range: range_header.as_deref(),
                browse: false,
                browse_template: None,
                browse_sort: None,
                browse_file_limit: 10_000,
                browse_reveal_symlinks: false,
                pass_thru: false,
                precompressed: None,
                disable_canonical_uris: false,
                status_override: None,
            };
            let mut file_resp = crate::proxy::static_files::serve_with_options(
                root,
                &service.index_file,
                service.spa_fallback,
                path,
                accept_enc,
                &serve_opts,
            )
            .await;

            // Transfer request extensions so script-runner's on_response
            // can access the ScriptRequestContext stashed during on_request.
            if let Some(ctx) = req
                .extensions()
                .get::<crate::plugins::script_runner::ScriptRequestContext>()
            {
                file_resp.extensions_mut().insert(ctx.clone());
            }

            state
                .plugins
                .run_response(&mut file_resp, Some(service.id), Some(route.id))
                .await
                .map_err(GatewayError::PluginError)?;

            let bucket = gw_metrics::status_bucket(file_resp.status().as_u16());
            state.record_request_metric(&svc_name, &route_id, method, bucket, "static");
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                "static",
                start.elapsed().as_secs_f64(),
            );

            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                Some(file_resp.status().as_u16()),
                start.elapsed().as_millis() as i64,
                "info",
                "",
            );
            return Ok(file_resp);
        }
    }

    // Dispatch on protocol. WebSocket and gRPC need streaming flows that the
    // reqwest-based path below cannot provide.
    match detect_protocol(&req) {
        ProtocolKind::WebSocket => {
            let result = handle_websocket(req, upstream_url).await;
            let status_label = match &result {
                Ok(r) => gw_metrics::status_bucket(r.status().as_u16()),
                Err(_) => "5xx",
            };
            state.record_request_metric(&svc_name, &route_id, method, status_label, &target_label);
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                &target_label,
                start.elapsed().as_secs_f64(),
            );
            let ws_status = result.as_ref().ok().map(|r| r.status().as_u16());
            let ws_level = if result.is_err() { "error" } else { "info" };
            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                ws_status,
                start.elapsed().as_millis() as i64,
                ws_level,
                "",
            );
            return result;
        }
        ProtocolKind::GrpcWeb => {
            let result =
                crate::proxy::grpc::handle_grpc_web(&state.grpc_client, req, upstream_url).await;
            let status_label = match &result {
                Ok(r) => gw_metrics::status_bucket(r.status().as_u16()),
                Err(_) => "5xx",
            };
            match &result {
                Ok(_) => state.health.record_success(&service.id, &svc_name),
                Err(e) => state.health.record_failure(
                    &service.id,
                    &svc_name,
                    format!("grpc-web upstream error: {e}"),
                ),
            }
            state.record_request_metric(&svc_name, &route_id, method, status_label, &target_label);
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                &target_label,
                start.elapsed().as_secs_f64(),
            );
            let gw_status = result.as_ref().ok().map(|r| r.status().as_u16());
            let gw_level = if result.is_err() { "error" } else { "info" };
            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                gw_status,
                start.elapsed().as_millis() as i64,
                gw_level,
                "",
            );
            return result;
        }
        ProtocolKind::Grpc => {
            let result = handle_grpc(&state.grpc_client, req, upstream_url).await;
            let status_label = match &result {
                Ok(r) => gw_metrics::status_bucket(r.status().as_u16()),
                Err(_) => "5xx",
            };
            match &result {
                Ok(_) => state.health.record_success(&service.id, &svc_name),
                Err(e) => state.health.record_failure(
                    &service.id,
                    &svc_name,
                    format!("grpc upstream error: {e}"),
                ),
            }
            state.record_request_metric(&svc_name, &route_id, method, status_label, &target_label);
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                &target_label,
                start.elapsed().as_secs_f64(),
            );
            let grpc_status = result.as_ref().ok().map(|r| r.status().as_u16());
            let grpc_level = if result.is_err() { "error" } else { "info" };
            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                grpc_status,
                start.elapsed().as_millis() as i64,
                grpc_level,
                "",
            );
            return result;
        }
        ProtocolKind::Http => {}
    }

    // ---- Unix socket upstream: bypass hyper-util, use raw HTTP/1.1. -------
    #[cfg(unix)]
    if upstream_url.starts_with("unix://") {
        if let Some((sock_path, http_path)) = parse_unix_url(&upstream_url) {
            let cache_key = req
                .headers()
                .get(crate::plugins::proxy_cache::CACHE_KEY_HEADER)
                .cloned();
            let recorder_id = req.headers().get("x-lynxx-recorder-id").cloned();

            // Feature 110: capture original Host before HOP_BY_HOP stripping.
            let unix_original_host_hv = req.headers().get(axum::http::header::HOST).cloned();

            let (mut parts, body) = req.into_parts();

            let unix_uri: Uri = http_path.parse().unwrap_or_else(|_| Uri::from_static("/"));
            parts.uri = unix_uri;

            let extensions = std::mem::take(&mut parts.extensions);

            parts
                .headers
                .remove(crate::plugins::proxy_cache::CACHE_KEY_HEADER);
            parts.headers.remove("x-lynxx-recorder-id");
            for h in HOP_BY_HOP.iter() {
                if let Ok(name) = HeaderName::from_bytes(h.as_bytes()) {
                    parts.headers.remove(&name);
                }
            }

            // Feature 110: passHostHeader for unix socket upstreams.
            if service.pass_host_header.unwrap_or(false) {
                if let Some(hv) = unix_original_host_hv {
                    parts.headers.insert(axum::http::header::HOST, hv);
                }
            }

            parts.version = axum::http::Version::HTTP_11;

            let unix_req = Request::from_parts(parts, body);
            let unix_resp = match proxy_via_unix(&sock_path, unix_req).await {
                Ok(r) => r,
                Err(e) => {
                    state.health.record_failure(
                        &service.id,
                        &svc_name,
                        format!("unix socket upstream: {e}"),
                    );
                    state.record_request_metric(&svc_name, &route_id, method, "5xx", &target_label);
                    state.log_request(
                        method,
                        path,
                        &client_ip_owned,
                        log_svc_id,
                        log_route_id,
                        log_project_id,
                        None,
                        start.elapsed().as_millis() as i64,
                        "error",
                        &format!("unix socket: {e}"),
                    );
                    return Err(e);
                }
            };

            let (resp_parts, incoming) = unix_resp.into_parts();
            let status = resp_parts.status;
            let resp_body = match axum::body::to_bytes(Body::new(incoming), usize::MAX).await {
                Ok(b) => b,
                Err(e) => {
                    state.log_request(
                        method,
                        path,
                        &client_ip_owned,
                        log_svc_id,
                        log_route_id,
                        log_project_id,
                        None,
                        start.elapsed().as_millis() as i64,
                        "error",
                        &format!("unix body read: {e}"),
                    );
                    return Err(GatewayError::UpstreamError(format!("unix body read: {e}")));
                }
            };

            if status.is_server_error() {
                state
                    .health
                    .record_failure(&service.id, &svc_name, format!("upstream {status}"));
            } else {
                state.health.record_success(&service.id, &svc_name);
            }

            let mut plugin_resp = Response::new(Body::from(resp_body.clone()));
            *plugin_resp.status_mut() = status;
            *plugin_resp.headers_mut() = resp_parts.headers;
            *plugin_resp.extensions_mut() = extensions;
            if let Some(v) = cache_key {
                plugin_resp
                    .headers_mut()
                    .insert(crate::plugins::proxy_cache::CACHE_KEY_HEADER, v);
            }
            if let Some(v) = recorder_id {
                plugin_resp.headers_mut().insert("x-lynxx-recorder-id", v);
            }

            state
                .plugins
                .run_response(&mut plugin_resp, Some(service.id), Some(route.id))
                .await
                .map_err(GatewayError::PluginError)?;

            let (final_parts, _) = plugin_resp.into_parts();
            let mut final_resp = Response::new(Body::from(resp_body));
            *final_resp.status_mut() = final_parts.status;
            *final_resp.headers_mut() = final_parts.headers;
            if is_overage {
                if let Ok(v) = "true".parse() {
                    final_resp.headers_mut().insert("x-lynxx-overage", v);
                }
            }

            let bucket = gw_metrics::status_bucket(status.as_u16());
            state.record_request_metric(&svc_name, &route_id, method, bucket, &target_label);
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                &target_label,
                start.elapsed().as_secs_f64(),
            );

            let unix_level = if status.is_server_error() {
                "error"
            } else {
                "info"
            };
            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                Some(status.as_u16()),
                start.elapsed().as_millis() as i64,
                unix_level,
                "",
            );
            return Ok(final_resp);
        }
    }

    // ---- Hot path: stream the body straight through hyper-util. -----------
    //
    // OPTIMIZATION: this branch deliberately avoids three sources of overhead
    // that the previous reqwest-based path paid on every request:
    //   1. body buffering (`axum::body::to_bytes`) — replaced by streaming
    //      `axum::body::Body` directly into the upstream request,
    //   2. `HeaderMap` clone + per-header `to_str` — we move the inbound
    //      headers into the upstream request via `into_parts`, only patching
    //      the few we must change (URI, hop-by-hop strip, optional cache key),
    //   3. URL re-parsing inside reqwest — we parse once into `hyper::Uri`.
    //
    // Body buffering is still necessary on the *response* side because the
    // plugin chain (`on_response`) operates on a fully-materialised
    // `Response<BoxBody>`. With an empty plugin chain the fast-path in
    // `PluginExecutor` skips that work; we still buffer once to satisfy the
    // type, but no heap copy beyond that.
    //
    // Expected win: ~80-150µs at p50 in synthetic benchmarks against
    // a tiny echo upstream, with a larger win at p99 due to fewer allocator hits.
    let upstream_uri: Uri = upstream_url
        .parse()
        .map_err(|e| GatewayError::BadRequest(format!("invalid upstream uri: {e}")))?;

    // Capture the proxy-cache key (set by the request-side plugin) before we
    // strip it; we need to re-attach it to the response for `on_response`.
    let cache_key = req
        .headers()
        .get(crate::plugins::proxy_cache::CACHE_KEY_HEADER)
        .cloned();
    // Same bridge for the request-recorder's capture id. The plugin sets a
    // request header in on_request and reads it back in on_response.
    let recorder_id = req.headers().get("x-lynxx-recorder-id").cloned();

    // Feature 110: capture the original Host header before HOP_BY_HOP
    // stripping so we can re-insert it when pass_host_header is enabled.
    let original_host_hv = req.headers().get(axum::http::header::HOST).cloned();

    // Move parts out so we don't clone the HeaderMap. `req` is consumed.
    let (mut parts, body) = req.into_parts();
    parts.uri = upstream_uri;

    // Capture extensions before they are lost so we can re-attach them to
    // the response for the plugin chain.
    let extensions = std::mem::take(&mut parts.extensions);

    // Strip hop-by-hop and our internal proxy-cache marker.
    parts
        .headers
        .remove(crate::plugins::proxy_cache::CACHE_KEY_HEADER);
    parts.headers.remove("x-lynxx-recorder-id");
    for h in HOP_BY_HOP.iter() {
        // safety: the constants are valid header names.
        if let Ok(name) = HeaderName::from_bytes(h.as_bytes()) {
            parts.headers.remove(&name);
        }
    }

    // Feature 110: passHostHeader — re-insert the original client Host header
    // when the service opts in. By default the Host is stripped (standard
    // reverse-proxy behaviour) and hyper sets it from the upstream URI.
    if service.pass_host_header.unwrap_or(false) {
        if let Some(hv) = original_host_hv {
            parts.headers.insert(axum::http::header::HOST, hv);
        }
    }

    // Force HTTP/1.1 over the wire — the connector negotiates h2 via ALPN
    // for https. For http:// we use HTTP/1.1 which is what most
    // upstreams expect from a forward proxy.
    parts.version = axum::http::Version::HTTP_11;

    // Per-service client lookup. For plain HTTP and for HTTPS services that
    // don't customise TLS (the common case) this resolves to the shared
    // default client without a hashmap miss in the steady state.
    let client = match state.client_pool.client_for(&service) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                service = %svc_name,
                error = %e,
                "failed to build per-service tls client; falling back to default"
            );
            state.http_client.clone()
        }
    };

    let deploy_active = state
        .deploy_registry
        .as_ref()
        .map(|r| crate::admin::deploy::has_active_deploy(r, &service.id))
        .unwrap_or(false);
    let target_is_draining = picked
        .as_ref()
        .map(|ts| ts.lifecycle() == TargetLifecycle::Draining)
        .unwrap_or(false);

    let max_attempts = (service.retries + 1).max(1) as usize;
    let retry_on_status = &route.retry_on_status;
    let force_buffer =
        route.buffer_request || !retry_on_status.is_empty() || deploy_active || target_is_draining;
    let mut last_err = String::new();
    let mut upstream_resp = None;
    let mut deploy_retried = false;

    if max_attempts <= 1 && !force_buffer {
        let upstream_req = Request::from_parts(parts, body);
        match client.request(upstream_req).await {
            Ok(r) => upstream_resp = Some(r),
            Err(e) => {
                let kind = if e.is_connect() { "connect" } else { "other" };
                if !state.minimal_telemetry {
                    metrics::counter!(
                        "lynxx_upstream_errors_total",
                        "service" => svc_name.clone(),
                        "kind" => kind,
                    )
                    .increment(1);
                }
                last_err = e.to_string();
            }
        }
    } else {
        let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .map_err(|e| GatewayError::BadRequest(format!("failed to buffer request body: {e}")))?;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                if !state.minimal_telemetry {
                    metrics::counter!(
                        "lynxx_upstream_retries_total",
                        "service" => svc_name.clone(),
                    )
                    .increment(1);
                }
                tokio::time::sleep(std::time::Duration::from_millis(50 * (1 << attempt.min(4))))
                    .await;
            }

            let retry_body = Body::from(body_bytes.clone());
            let upstream_req = Request::from_parts(parts.clone(), retry_body);
            match client.request(upstream_req).await {
                Ok(r) => {
                    // Check if we should retry based on status code.
                    if !retry_on_status.is_empty()
                        && retry_on_status.contains(&r.status().as_u16())
                        && attempt + 1 < max_attempts
                    {
                        last_err = format!("upstream returned {}", r.status());
                        if !state.minimal_telemetry {
                            metrics::counter!(
                                "lynxx_upstream_retries_total",
                                "service" => svc_name.clone(),
                            )
                            .increment(1);
                        }
                        continue;
                    }
                    upstream_resp = Some(r);
                    break;
                }
                Err(e) => {
                    let kind = if e.is_connect() { "connect" } else { "other" };
                    if !state.minimal_telemetry {
                        metrics::counter!(
                            "lynxx_upstream_errors_total",
                            "service" => svc_name.clone(),
                            "kind" => kind,
                        )
                        .increment(1);
                    }
                    last_err = e.to_string();
                    if !e.is_connect() {
                        break;
                    }
                }
            }
        }

        // Deploy-aware retry: on connection error or 502, try a different
        // healthy target when the service has an active deploy or the
        // originally picked target started draining mid-request.
        if deploy_active || target_is_draining {
            let is_retryable = match &upstream_resp {
                Some(r) => r.status().as_u16() == 502,
                None => true,
            };
            if is_retryable {
                let mut exclude: Vec<uuid::Uuid> = Vec::new();
                if let Some(tid) = picked_target_id {
                    exclude.push(tid);
                }
                for _ in 0..2u8 {
                    let retry_ts = match state.lb.pick_excluding(
                        &service.id,
                        &exclude,
                        state.local_zone.as_deref(),
                    ) {
                        Some(ts) => ts,
                        None => break,
                    };
                    exclude.push(retry_ts.target.id);
                    let _guard = InFlightGuard::new(retry_ts.clone());

                    let retry_base = retry_ts.target.url.trim_end_matches('/');
                    let mut retry_url = String::with_capacity(
                        retry_base.len()
                            + upstream_path.len()
                            + query_string.map(|q| q.len() + 1).unwrap_or(0),
                    );
                    retry_url.push_str(retry_base);
                    retry_url.push_str(&upstream_path);
                    if let Some(q) = query_string {
                        retry_url.push('?');
                        retry_url.push_str(q);
                    }

                    let retry_uri: Uri = match retry_url.parse() {
                        Ok(u) => u,
                        Err(_) => break,
                    };

                    let mut retry_parts = parts.clone();
                    retry_parts.uri = retry_uri;
                    let retry_body = Body::from(body_bytes.clone());
                    let retry_req = Request::from_parts(retry_parts, retry_body);

                    if !state.minimal_telemetry {
                        metrics::counter!(
                            "lynxx_deploy_retries_total",
                            "service" => svc_name.clone(),
                        )
                        .increment(1);
                    }

                    tracing::debug!(
                        service = %svc_name,
                        target_id = %retry_ts.target.id,
                        target_url = %retry_ts.target.url,
                        "deploy-aware retry"
                    );

                    match client.request(retry_req).await {
                        Ok(r) => {
                            if r.status().as_u16() == 502 {
                                last_err = "deploy retry: upstream 502".to_string();
                                continue;
                            }
                            upstream_resp = Some(r);
                            picked_target_id = Some(retry_ts.target.id);
                            target_label = retry_ts.target.url.clone();
                            deploy_retried = true;
                            break;
                        }
                        Err(e) => {
                            last_err = e.to_string();
                            continue;
                        }
                    }
                }
            }
        }
    }

    let upstream_resp = match upstream_resp {
        Some(r) => r,
        None => {
            state.record_request_metric(&svc_name, &route_id, method, "5xx", &target_label);
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                &target_label,
                start.elapsed().as_secs_f64(),
            );
            state.health.record_failure(
                &service.id,
                &svc_name,
                format!("upstream send error: {last_err}"),
            );
            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                None,
                start.elapsed().as_millis() as i64,
                "error",
                &last_err,
            );
            return Err(GatewayError::UpstreamError(last_err));
        }
    };

    let (resp_parts, incoming) = upstream_resp.into_parts();
    let status = resp_parts.status;

    // Buffer the response body once so the plugin chain can mutate it. With
    // the empty-chain fast path this stays cheap — only one heap allocation.
    let resp_body = match axum::body::to_bytes(Body::new(incoming), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            if !state.minimal_telemetry {
                metrics::counter!(
                    "lynxx_upstream_errors_total",
                    "service" => svc_name.clone(),
                    "kind" => "other",
                )
                .increment(1);
            }
            state.record_request_metric(&svc_name, &route_id, method, "5xx", &target_label);
            state.record_request_duration(
                &svc_name,
                &route_id,
                method,
                &target_label,
                start.elapsed().as_secs_f64(),
            );
            state.health.record_failure(
                &service.id,
                &svc_name,
                format!("upstream body error: {e}"),
            );
            state.log_request(
                method,
                path,
                &client_ip_owned,
                log_svc_id,
                log_route_id,
                log_project_id,
                None,
                start.elapsed().as_millis() as i64,
                "error",
                &format!("upstream body error: {e}"),
            );
            return Err(GatewayError::UpstreamError(e.to_string()));
        }
    };

    if status.is_server_error() {
        if !state.minimal_telemetry {
            metrics::counter!(
                "lynxx_upstream_errors_total",
                "service" => svc_name.clone(),
                "kind" => "5xx",
            )
            .increment(1);
        }
        state
            .health
            .record_failure(&service.id, &svc_name, format!("upstream {status}"));
    } else {
        state.health.record_success(&service.id, &svc_name);
    }

    // ── Passive per-target health tracking ──
    // Record the outcome for the specific target we picked so passive
    // health can trip individual upstreams without waiting for active polls.
    if let Some(tid) = picked_target_id {
        if state.passive_health.is_fail_status(status.as_u16()) {
            if state.passive_health.record_failure(&service.id, &tid) {
                tracing::warn!(
                    service = %svc_name,
                    target_id = %tid,
                    "passive health: target tripped unhealthy"
                );
                state.lb.mark_target_health(&service.id, &tid, false);
            }
        } else {
            if state.passive_health.record_success(&service.id, &tid) {
                tracing::info!(
                    service = %svc_name,
                    target_id = %tid,
                    "passive health: target recovered"
                );
                state.lb.mark_target_health(&service.id, &tid, true);
            }
        }
    }

    // Build the plugin-facing response. We reuse the upstream HeaderMap by
    // moving it through `Response::from_parts` — no clone.
    let mut plugin_resp = Response::new(Body::from(resp_body.clone()));
    *plugin_resp.status_mut() = status;
    *plugin_resp.headers_mut() = resp_parts.headers;
    *plugin_resp.extensions_mut() = extensions;

    if let Some(v) = cache_key {
        plugin_resp
            .headers_mut()
            .insert(crate::plugins::proxy_cache::CACHE_KEY_HEADER, v);
    }
    if let Some(v) = recorder_id {
        plugin_resp.headers_mut().insert("x-lynxx-recorder-id", v);
    }

    state
        .plugins
        .run_response(&mut plugin_resp, Some(service.id), Some(route.id))
        .await
        .map_err(GatewayError::PluginError)?;

    let (final_parts, _bb) = plugin_resp.into_parts();
    let mut final_resp = Response::new(Body::from(resp_body));
    *final_resp.status_mut() = final_parts.status;
    *final_resp.headers_mut() = final_parts.headers;

    // Set sticky-session cookie so subsequent requests from this client
    // land on the same target.
    if matches!(
        LbStrategy::from_str(&service.lb_strategy),
        LbStrategy::CookieSticky
    ) {
        if let Some(tid) = picked_target_id {
            if let Ok(val) = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax",
                STICKY_COOKIE_NAME, tid
            )
            .parse()
            {
                final_resp
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, val);
            }
        }
    }

    if is_overage {
        if let Ok(v) = "true".parse() {
            final_resp.headers_mut().insert("x-lynxx-overage", v);
        }
    }
    if deploy_retried {
        if let Ok(v) = "true".parse() {
            final_resp.headers_mut().insert("x-lynxx-deploy-retry", v);
        }
    }

    // Per-request telemetry: counter + histogram + access-log. Each helper
    // short-circuits internally on `state.minimal_telemetry`, so when the
    // config knob is on these three calls cost ~3 bool loads + branches.
    let bucket = gw_metrics::status_bucket(status.as_u16());
    state.record_request_metric(&svc_name, &route_id, method, bucket, &target_label);
    state.record_request_duration(
        &svc_name,
        &route_id,
        method,
        &target_label,
        start.elapsed().as_secs_f64(),
    );
    let http_level = if status.is_server_error() {
        "error"
    } else {
        "info"
    };
    state.log_request(
        method,
        path,
        &client_ip_owned,
        log_svc_id,
        log_route_id,
        log_project_id,
        Some(status.as_u16()),
        start.elapsed().as_millis() as i64,
        http_level,
        "",
    );

    Ok(final_resp)
}
