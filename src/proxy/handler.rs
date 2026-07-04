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
use axum::http::{HeaderName, HeaderValue, Request, Response, Uri};
use chrono::{DateTime, Utc};
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
    /// the resolved value.
    ///
    /// The gate is checked at every `state.record_*` / `state.log_request`
    /// call site (search for `if !state.minimal_telemetry` in this file),
    /// so when this is true the helper call itself is elided — no argument
    /// preparation (no `&svc_name` borrow, no `status_bucket(...)` call) is
    /// paid on the fast path. The helpers themselves no longer carry an
    /// inner short-circuit; if you add a new call site, gate it explicitly.
    pub minimal_telemetry: bool,
    /// When true AND `plugins.is_empty()` for the request, the upstream
    /// response body is forwarded by streaming the hyper `Incoming` body
    /// directly into the downstream `axum::body::Body` — no full-body
    /// `to_bytes(...)` allocation/copy. Saves the single biggest p99 hit
    /// on the hot path. See `config::default_stream_response_body`.
    pub stream_response_body: bool,
    /// When true, per-request `HealthRegistry::record_success_at` /
    /// `record_failure_at` calls are skipped on the streamed + buffered hot
    /// paths. Set at startup when `gateway.health_check_interval_ms` is so
    /// large (≥1 hour) that no active checker is polling the counters with
    /// any useful frequency — i.e. the bench rig and any deployment that
    /// explicitly turns active health off. Pre-refactor each record_success
    /// path showed ~40k samples + ~30k nested `Utc::now()` in the
    /// flamegraph at 100k RPS, dominated by DashMap entry-mut acquisition.
    ///
    /// The active health checker (when enabled) still drives the registry
    /// via the cold path; this only suppresses the per-request *passive*
    /// emission. The flag is off by default so production behaviour is
    /// unchanged.
    pub passive_record_disabled: bool,
}

// ── Per-request telemetry helpers
//
// Each per-request metric / access-log emission goes through these methods
// instead of inlining the macro — the macro call sites are noisy and the
// label-allocation pattern (`.to_string()` per request) is centralised here.
//
// The `minimal_telemetry` gate is enforced at every CALL SITE, not inside
// these helpers. When the knob is on, the call itself is elided so the
// borrows / `status_bucket(...)` / `format!(...)` arguments aren't paid.
// The helpers used to carry an inner `if self.minimal_telemetry { return; }`
// short-circuit; that meant every "skipped" emission still cost the
// argument preparation in the caller. Don't reintroduce the inner guard —
// gate at the call site instead.
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
        // Build owned-but-once Strings rather than letting the metrics!
        // macro do `.to_string()` on each `&str`: the macro expansion
        // otherwise calls `to_string()` on the same `svc` for both the
        // counter and the histogram path on the success branch, so any
        // string conversion saving happens at the call site. (Real
        // allocation reduction would require a per-(svc,route,method)
        // handle cache — left as a follow-up benchmark target.)
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
        now: DateTime<Utc>,
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
        self.log_writer.log_at(
            now,
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
///
/// Stored as pre-parsed `HeaderName` values so the per-request strip loop
/// can call `headers.remove(&name)` directly instead of re-running
/// `HeaderName::from_bytes(...)` per header per request. At 100k RPS that
/// was ~900k `from_bytes` calls/sec — pure waste, since these strings are
/// known-valid at compile time.
///
/// `HeaderName::from_static` is `const fn`, so this is one-time work at
/// program-load with zero runtime overhead.
static HOP_BY_HOP: [HeaderName; 9] = [
    HeaderName::from_static("host"),
    HeaderName::from_static("connection"),
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-authenticate"),
    HeaderName::from_static("proxy-authorization"),
    HeaderName::from_static("te"),
    HeaderName::from_static("trailers"),
    HeaderName::from_static("transfer-encoding"),
    HeaderName::from_static("upgrade"),
];

#[inline]
fn is_hop_by_hop(name: &HeaderName) -> bool {
    // `HeaderName` equality is an interned-string byte compare — much
    // cheaper than re-parsing each entry via `from_bytes` per call.
    HOP_BY_HOP.iter().any(|h| h == name)
}

/// Install the outbound keepalive headers we want every upstream
/// request to carry. Inserts (replacing any prior value) `Connection:
/// keep-alive` plus a `Keep-Alive: timeout=75, max=1000000` advisory
/// matching the nginx default. Call AFTER `strip_hop_by_hop` so the
/// client's inbound `Connection`/`Keep-Alive` (which is per-hop) is
/// removed before we put ours back.
///
/// `Connection: keep-alive` is the default behaviour on HTTP/1.1 so
/// strictly speaking it's redundant, but several upstreams (and
/// intermediaries that re-examine the header) misbehave when it's
/// absent — nginx and kong both explicitly set it on every forwarded
/// request, and we match that here.
///
/// The `Keep-Alive: timeout=75, max=1000000` line lets the upstream
/// know we intend to keep the conn around for a long time; some HTTP/1.1
/// servers tear connections down aggressively without it, which forces
/// a fresh TCP handshake on the next request and shows up as p99.9 tail.
#[inline]
fn install_outbound_keepalive(headers: &mut axum::http::HeaderMap) {
    // `HeaderName::from_static` + `HeaderValue::from_static` are both
    // const, so these are zero-cost beyond the actual map insert.
    static CONNECTION_KEEP_ALIVE: HeaderValue = HeaderValue::from_static("keep-alive");
    static KEEP_ALIVE_HINT: HeaderValue =
        HeaderValue::from_static("timeout=75, max=1000000");
    headers.insert(
        HeaderName::from_static("connection"),
        CONNECTION_KEEP_ALIVE.clone(),
    );
    headers.insert(
        HeaderName::from_static("keep-alive"),
        KEEP_ALIVE_HINT.clone(),
    );
}

/// Resolve the outbound HTTP version for an upstream request based on
/// the service's `force_http_version` knob. Default is HTTP/1.1 — the
/// hyper-util H1 idle pool is meaningfully bigger than its H2 stream
/// pool, and most plain-HTTP upstreams expect H1 from a forward proxy.
///
/// Recognised values (case-insensitive): `"1.1"`, `"http/1.1"`, `"h1"`
/// → HTTP/1.1; `"2"`, `"2.0"`, `"http/2"`, `"h2"` → HTTP/2; `"auto"`
/// → leave whatever the `axum::extract::Request` carries (the
/// connector will negotiate via ALPN on https://).
#[inline]
fn resolve_outbound_http_version(
    svc: &crate::models::Service,
    inbound: axum::http::Version,
) -> axum::http::Version {
    match svc
        .force_http_version
        .as_deref()
        .map(|s| s.trim())
        .unwrap_or("1.1")
        .to_ascii_lowercase()
        .as_str()
    {
        "1.1" | "http/1.1" | "h1" | "1" => axum::http::Version::HTTP_11,
        "2" | "2.0" | "http/2" | "h2" => axum::http::Version::HTTP_2,
        "auto" => inbound,
        other => {
            tracing::debug!(
                service = %svc.name,
                value = other,
                "force_http_version: unrecognised value, defaulting to HTTP/1.1"
            );
            axum::http::Version::HTTP_11
        }
    }
}

/// Strip hop-by-hop headers in a single pass over the map.
///
/// Pre-refactor this looped over the 9-entry `HOP_BY_HOP` array and
/// called `headers.remove(&name)` once per entry — 9 hash probes per
/// request even though most requests carry zero hop-by-hop headers.
///
/// The http 1.4 `HeaderMap` doesn't expose `retain()`, so we walk the
/// map's keys once, stash matching names on the stack, and call
/// `remove()` only for entries that are actually present. For the
/// common case (zero hop-by-hop headers) this collapses to a single
/// linear walk with zero removals — no allocations either, because
/// the local `Vec` stays at capacity 0 unless a match is pushed.
#[inline]
fn strip_hop_by_hop(headers: &mut axum::http::HeaderMap) {
    // Most requests have zero hop-by-hop headers; we keep this Vec at
    // its empty inline state and only allocate if we find a match. At
    // worst we collect a handful of names — the 9-entry HOP_BY_HOP list
    // is the hard upper bound.
    let mut to_remove: Vec<HeaderName> = Vec::new();
    for name in headers.keys() {
        if is_hop_by_hop(name) {
            to_remove.push(name.clone());
        }
    }
    for name in &to_remove {
        headers.remove(name);
    }
}

/// Find the value of a cookie named `name` in any `Cookie:` header.
/// Returns a borrowed slice into the header map — no allocation on the
/// hot path. The slice's lifetime is bound to `headers`, which on the
/// proxy hot path means it's bound to `&req`. Caller must release the
/// borrow before mutating `req` (e.g. before `req.extensions_mut()` or
/// plugin invocation).
///
/// Pre-refactor this returned `Option<String>` — every request paid a
/// `String` allocation for the cookie even though the cookie value
/// was immediately re-borrowed as `&str` for the load balancer
/// context. `str::trim()` returns a sub-slice, so the trim doesn't
/// require ownership; the only reason for the allocation was the
/// API shape.
fn extract_cookie<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .find_map(|pair| {
            let pair = pair.trim();
            let (key, val) = pair.split_once('=')?;
            if key.trim() == name {
                Some(val.trim())
            } else {
                None
            }
        })
}

/// Lookup a single query parameter by name without running a full
/// `url::form_urlencoded::parse` over the whole query string and
/// without allocating a `String` for the result. Returns a slice
/// into `qs`.
///
/// We deliberately do **not** percent-decode the value. For the only
/// two callers — consistent-hash load balancing and the routing
/// matcher's `match_query` comparisons — hashing or comparing the raw
/// encoded bytes is correct: a single client's encoding choice is
/// consistent from request to request, so the LB bucket stays stable,
/// and `match_query` compares against operator-supplied literal values
/// which the operator can write in encoded form if needed. For any
/// callsite that genuinely needs decoded values, fall back to
/// `url::form_urlencoded::parse(...)`.
fn extract_query_param<'a>(qs: &'a str, name: &str) -> Option<&'a str> {
    qs.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| if k == name { Some(v) } else { None })
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
    State(state): State<Arc<ProxyState>>,
    mut req: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let start = Instant::now();
    // SECURITY: strip any client-supplied identity headers at the very edge,
    // before routing or any plugin runs. Downstream ACL, per-consumer rate
    // limiting, anomaly detection, LLM tenant cache keys, and access logs all
    // trust `x-consumer-*` as the authenticated identity — but auth plugins
    // (key-auth / basic-auth / hmac-auth) are the ONLY components allowed to
    // set them. Anything the caller sends is forged and must be removed here,
    // otherwise an unauthenticated client could impersonate any consumer just
    // by adding `x-consumer-username: <victim>`.
    {
        let forged: Vec<HeaderName> = req
            .headers()
            .keys()
            .filter(|n| n.as_str().starts_with("x-consumer-"))
            .cloned()
            .collect();
        for name in forged {
            req.headers_mut().remove(&name);
        }
    }

    // Cache the wall-clock at request entry and thread the same value through
    // every per-request consumer (health registry, quota tracker, log
    // writer). Each `Utc::now()` is a `clock_gettime` syscall; the
    // pre-refactor handler fired ~4 of them per success-path request. The
    // few hundred microseconds of skew between request-entry and the actual
    // log write are irrelevant for an access log timestamp.
    let request_started: DateTime<Utc> = Utc::now();
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
            .match_route_for_service(
                &svc.id,
                path,
                method,
                Some(h),
                Some(req.headers()),
                query_string,
            )
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
            if !state.minimal_telemetry {
                state.record_request_metric("-", "-", method, "no_route", "-");
                state.log_request(
                    request_started,
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
            }
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
    // `route_id` is used exclusively as a prometheus metric label inside
    // `record_request_metric` / `record_request_duration`. Those call
    // sites are already gated behind `if !state.minimal_telemetry`, so
    // when the knob is on the formatted string is never read.
    //
    // The flamegraph at 100k RPS showed `uuid::Uuid::to_string` /
    // `spec_to_string<uuid::Uuid>` at ~30k samples — pure work for a
    // value that's discarded in the bench's `minimal_telemetry=true`
    // configuration. Defer the format until we know we'll use it.
    //
    // We can't trivially return `&'static ""` here because callers
    // borrow `&route_id` from this owned `String`, and a `let` binding
    // unifies the two branches' types. An empty `String` allocates
    // exactly zero bytes (the inline `Vec` is null-init), so the
    // `minimal_telemetry=true` path pays no heap allocation.
    let route_id: String = if state.minimal_telemetry {
        String::new()
    } else {
        route.id.to_string()
    };
    // `method` and `path` are &str borrowed from owned locals (method_obj /
    // uri) at the top of this function, so they remain valid through every
    // downstream call. No need to allocate `log_method` / `log_path`
    // copies — pass `method` / `path` directly to `log_writer.log()`.
    let log_svc_id = Some(service.id);
    let log_route_id = Some(route.id);
    let log_project_id = service.project_id;

    if route.health_gate && !state.lb.has_healthy_active_target(&service.id) {
        if !state.minimal_telemetry {
            state.record_request_metric(&svc_name, &route_id, method, "health_gated", "-");
            state.log_request(
                request_started,
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
        }
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
        if !state.minimal_telemetry {
            state.record_request_metric(&svc_name, &route_id, method, "circuit_open", "-");
            state.log_request(
                request_started,
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
        }
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
        if !state.minimal_telemetry {
            state.record_request_metric(&svc_name, &route_id, method, "license_revoked", "-");
            state.log_request(
                request_started,
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
        }
        return Err(GatewayError::LicenseRevoked);
    }

    let quota_result = state.quota.check_and_count_at(request_started);
    if quota_result == crate::quota::QuotaResult::Rejected {
        if !state.minimal_telemetry {
            state.record_request_metric(&svc_name, &route_id, method, "quota_exceeded", "-");
            state.log_request(
                request_started,
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
        }
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
        // SECURITY: with no trusted-proxy allowlist configured, do NOT trust
        // client-supplied X-Forwarded-For / X-Real-IP — any caller could spoof
        // its source IP to bypass IP ACLs / per-IP rate limits or poison access
        // logs. Fall back to the real socket peer address. Deployments behind a
        // load balancer must list it in `trusted_proxies` for XFF to be honoured
        // (same model as nginx `set_real_ip_from` / Caddy `trusted_proxies`).
        false
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
    // Zero-alloc LB context extraction.
    //
    // Pre-refactor each of these went through `Option<String>` →
    // `.as_deref()` purely to fit `RequestContext`'s `Option<&str>`
    // fields. The owned `String` was never read elsewhere — the
    // `as_deref()` on the line below it was the only consumer. That's
    // one `to_string()` per hash-based LB request (header / query)
    // plus one per sticky-cookie request. With this rewrite the LB
    // hot path holds only `&str` slices borrowed from `req.headers()`
    // / `req.uri().query()`, valid until the next `&mut req` (which
    // is the plugin-chain invocation further down).
    let sticky_cookie: Option<&str> = extract_cookie(req.headers(), STICKY_COOKIE_NAME);
    let header_hash: Option<&str> = service.lb_hash_header.as_ref().and_then(|hdr| {
        req.headers()
            .get(hdr.as_str())
            .and_then(|v| v.to_str().ok())
    });
    let query_hash: Option<&str> = service.lb_hash_query_param.as_ref().and_then(|param| {
        req.uri()
            .query()
            .and_then(|qs| extract_query_param(qs, param))
    });
    let lb_ctx = RequestContext {
        client_ip: Some(client_ip_owned.as_str()),
        uri_path: Some(path),
        sticky_cookie,
        header_hash_value: header_hash,
        query_hash_value: query_hash,
        rdp_cookie: None,
    };

    // Pick a target via load balancer if one is configured for this service.
    // Falls back to `service.url` if no targets exist.
    let picked = state
        .lb
        .pick(&service.id, state.local_zone.as_deref(), &lb_ctx);
    let mut picked_target_id = picked.as_ref().map(|ts| ts.target.id);
    // Parse the LB strategy once. The downstream sticky-cookie attach sites
    // (one in the streaming path, one in the buffered path) only need to
    // know whether this service uses cookie-sticky; doing the
    // `LbStrategy::from_str(...)` match on `service.lb_strategy` twice per
    // request showed up at ~90M samples in the post-fix flamegraph (a
    // chain of `match` arms over `&str`). Compute it once here.
    let is_cookie_sticky = matches!(
        LbStrategy::from_str(&service.lb_strategy),
        LbStrategy::CookieSticky
    );
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
            // `ServeOptions` already takes `Option<&'a str>` — the
            // old code allocated `String` owners just to satisfy
            // `as_deref()` on the next line. The borrows on these
            // header values are valid for the lifetime of `req`, and
            // `req` outlives `serve_opts` / the `.await` on
            // `serve_with_options` below.
            let if_none_match = req
                .headers()
                .get(axum::http::header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok());
            let if_modified_since = req
                .headers()
                .get(axum::http::header::IF_MODIFIED_SINCE)
                .and_then(|v| v.to_str().ok());
            let range_header = req
                .headers()
                .get(axum::http::header::RANGE)
                .and_then(|v| v.to_str().ok());
            let serve_opts = crate::proxy::static_files::ServeOptions {
                hide_patterns: &service.hide_patterns,
                cache_control: None,
                if_none_match,
                if_modified_since,
                range: range_header,
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

            if !state.minimal_telemetry {
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
                    request_started,
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
            }
            return Ok(file_resp);
        }
    }

    // Dispatch on protocol. WebSocket and gRPC need streaming flows that the
    // reqwest-based path below cannot provide.
    match detect_protocol(&req) {
        ProtocolKind::WebSocket => {
            let result = handle_websocket(req, upstream_url).await;
            if !state.minimal_telemetry {
                let status_label = match &result {
                    Ok(r) => gw_metrics::status_bucket(r.status().as_u16()),
                    Err(_) => "5xx",
                };
                state.record_request_metric(
                    &svc_name,
                    &route_id,
                    method,
                    status_label,
                    &target_label,
                );
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
                    request_started,
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
            }
            return result;
        }
        ProtocolKind::GrpcWeb => {
            let result =
                crate::proxy::grpc::handle_grpc_web(&state.grpc_client, req, upstream_url).await;
            match &result {
                Ok(_) => state.health.record_success_at(&service.id, &svc_name, request_started),
                Err(e) => state.health.record_failure_at(
                    &service.id,
                    &svc_name,
                    format!("grpc-web upstream error: {e}"),
                    request_started,
                ),
            }
            if !state.minimal_telemetry {
                let status_label = match &result {
                    Ok(r) => gw_metrics::status_bucket(r.status().as_u16()),
                    Err(_) => "5xx",
                };
                state.record_request_metric(
                    &svc_name,
                    &route_id,
                    method,
                    status_label,
                    &target_label,
                );
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
                    request_started,
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
            }
            return result;
        }
        ProtocolKind::Grpc => {
            let result = handle_grpc(&state.grpc_client, req, upstream_url).await;
            match &result {
                Ok(_) => state.health.record_success_at(&service.id, &svc_name, request_started),
                Err(e) => state.health.record_failure_at(
                    &service.id,
                    &svc_name,
                    format!("grpc upstream error: {e}"),
                    request_started,
                ),
            }
            if !state.minimal_telemetry {
                let status_label = match &result {
                    Ok(r) => gw_metrics::status_bucket(r.status().as_u16()),
                    Err(_) => "5xx",
                };
                state.record_request_metric(
                    &svc_name,
                    &route_id,
                    method,
                    status_label,
                    &target_label,
                );
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
                    request_started,
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
            }
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
            strip_hop_by_hop(&mut parts.headers);
            install_outbound_keepalive(&mut parts.headers);

            // Feature 110: passHostHeader for unix socket upstreams.
            if service.pass_host_header.unwrap_or(false) {
                if let Some(hv) = unix_original_host_hv {
                    parts.headers.insert(axum::http::header::HOST, hv);
                }
            }

            // Unix-socket upstreams always speak HTTP/1.1 — there's no
            // ALPN over a Unix domain socket and no h2c by default. The
            // `force_http_version` knob still has effect for *standard*
            // TCP upstreams in the main branch below.
            parts.version = axum::http::Version::HTTP_11;

            let unix_req = Request::from_parts(parts, body);
            let unix_resp = match proxy_via_unix(&sock_path, unix_req).await {
                Ok(r) => r,
                Err(e) => {
                    state.health.record_failure_at(
                        &service.id,
                        &svc_name,
                        format!("unix socket upstream: {e}"),
                        request_started,
                    );
                    if !state.minimal_telemetry {
                        state.record_request_metric(
                            &svc_name,
                            &route_id,
                            method,
                            "5xx",
                            &target_label,
                        );
                        state.log_request(
                            request_started,
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
                    }
                    return Err(e);
                }
            };

            let (resp_parts, incoming) = unix_resp.into_parts();
            let status = resp_parts.status;
            let resp_body = match axum::body::to_bytes(Body::new(incoming), usize::MAX).await {
                Ok(b) => b,
                Err(e) => {
                    if !state.minimal_telemetry {
                        state.log_request(
                            request_started,
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
                    }
                    return Err(GatewayError::UpstreamError(format!("unix body read: {e}")));
                }
            };

            if status.is_server_error() {
                state
                    .health
                    .record_failure_at(&service.id, &svc_name, format!("upstream {status}"), request_started);
            } else {
                state.health.record_success_at(&service.id, &svc_name, request_started);
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

            if !state.minimal_telemetry {
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
                    request_started,
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
            }
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

    // Both the proxy-cache marker and the request-recorder capture-id are
    // ONLY ever set by their respective plugins on the request side. With
    // an empty plugin chain there's no producer of these headers, so the
    // `.get(...)` and `.remove(...)` calls below are pure waste — three
    // hash probes per request that always return None. Gate them on
    // `plugins.is_empty()` (single atomic load).
    //
    // Feature 110 (Host re-insertion for `pass_host_header`) needs the
    // original Host header captured before HOP_BY_HOP strip; that's per
    // service, not per plugin, so it stays.
    let plugins_active = !state.plugins.is_empty();
    let (cache_key, recorder_id) = if plugins_active {
        (
            req.headers()
                .get(crate::plugins::proxy_cache::CACHE_KEY_HEADER)
                .cloned(),
            req.headers().get("x-lynxx-recorder-id").cloned(),
        )
    } else {
        (None, None)
    };
    let original_host_hv = if service.pass_host_header.unwrap_or(false) {
        req.headers().get(axum::http::header::HOST).cloned()
    } else {
        None
    };

    // Move parts out so we don't clone the HeaderMap. `req` is consumed.
    let (mut parts, body) = req.into_parts();
    parts.uri = upstream_uri;

    // Capture extensions before they are lost so we can re-attach them to
    // the response for the plugin chain.
    let extensions = std::mem::take(&mut parts.extensions);

    // Strip hop-by-hop. The internal proxy-cache + recorder markers are
    // only present if plugins are active — skip the `.remove()` probes
    // on the no-plugin hot path.
    if plugins_active {
        parts
            .headers
            .remove(crate::plugins::proxy_cache::CACHE_KEY_HEADER);
        parts.headers.remove("x-lynxx-recorder-id");
    }
    strip_hop_by_hop(&mut parts.headers);
    install_outbound_keepalive(&mut parts.headers);

    // Feature 110: passHostHeader — re-insert the original client Host
    // header when the service opts in. `original_host_hv` is only
    // populated above when `service.pass_host_header == true`, so a
    // `Some` here implies the service opted in.
    if let Some(hv) = original_host_hv {
        parts.headers.insert(axum::http::header::HOST, hv);
    }

    // Outbound HTTP version is controlled per-service via
    // `service.force_http_version` ("1.1" / "2" / "auto"). Default is
    // HTTP/1.1 — hyper-util's H1 idle pool is meaningfully bigger than
    // its H2 stream pool for plaintext upstreams, which is exactly the
    // pool-floor knob this branch is tuning around.
    parts.version = resolve_outbound_http_version(&service, parts.version);

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
        let upstream_start = Instant::now();
        match client.request(upstream_req).await {
            Ok(r) => {
                // Feed the EWMA that the LeastTime LB strategy depends on. This
                // was never recorded on the request path, so LeastTime silently
                // degraded to least-connections.
                if let Some(ref ts) = picked {
                    ts.record_response_time(upstream_start.elapsed().as_micros() as u64);
                }
                upstream_resp = Some(r);
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
            let upstream_start = Instant::now();
            match client.request(upstream_req).await {
                Ok(r) => {
                    // Check if we should retry based on status code.
                    if !retry_on_status.is_empty()
                        && retry_on_status.contains(&r.status().as_u16())
                        && attempt + 1 < max_attempts
                    {
                        last_err = format!("upstream returned {}", r.status());
                        // Do NOT increment lynxx_upstream_retries_total here:
                        // the retry is counted once at the top of the next loop
                        // iteration (the `attempt > 0` arm). Incrementing in
                        // both places double-counted every status-based retry.
                        continue;
                    }
                    // Accepted response — record the upstream latency for the
                    // LeastTime LB EWMA. (All attempts in this loop hit the same
                    // picked target, so `picked` is the serving target.)
                    if let Some(ref ts) = picked {
                        ts.record_response_time(upstream_start.elapsed().as_micros() as u64);
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

                    let upstream_start = Instant::now();
                    match client.request(retry_req).await {
                        Ok(r) => {
                            if r.status().as_u16() == 502 {
                                last_err = "deploy retry: upstream 502".to_string();
                                continue;
                            }
                            // Record latency on the target that actually served.
                            retry_ts.record_response_time(
                                upstream_start.elapsed().as_micros() as u64,
                            );
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
            state.health.record_failure_at(
                &service.id,
                &svc_name,
                format!("upstream send error: {last_err}"),
                request_started,
            );
            if !state.minimal_telemetry {
                state.record_request_metric(&svc_name, &route_id, method, "5xx", &target_label);
                state.record_request_duration(
                    &svc_name,
                    &route_id,
                    method,
                    &target_label,
                    start.elapsed().as_secs_f64(),
                );
                state.log_request(
                    request_started,
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
            }
            return Err(GatewayError::UpstreamError(last_err));
        }
    };

    let (resp_parts, incoming) = upstream_resp.into_parts();
    let status = resp_parts.status;

    // ── Streaming fast path ───────────────────────────────────────────
    // When no plugins are registered (the *common* case for any
    // route that isn't doing body inspection/mutation), bypass the
    // full-body buffer. Buffering costs one heap allocation + memcpy
    // of the entire response per request. At 100k RPS on a small
    // response that was the single biggest contributor to lynxx's
    // p99 vs nginx — see `default_stream_response_body` doc-comment.
    //
    // We still need the *body* for plugins that mutate it
    // (proxy-cache, response-transformer, etc.), so the bypass
    // triggers only when:
    //   1. `state.stream_response_body` is on (default true; users
    //      who set it false force the buffering path), AND
    //   2. The plugin chain is empty — `state.plugins.is_empty()` is
    //      a single atomic load that handlers already pay elsewhere,
    //      and the call exists precisely so hot paths can skip the
    //      executor.
    //
    // Operations after this branch that do NOT need the body (header
    // mutations, telemetry, health tracking) are duplicated below for
    // the streaming path, so we don't have to re-buffer just to
    // run them.
    let streaming = state.stream_response_body && state.plugins.is_empty();
    if streaming {
        // Server-error + passive-target health tracking (status only).
        if status.is_server_error() {
            if !state.minimal_telemetry {
                metrics::counter!(
                    "lynxx_upstream_errors_total",
                    "service" => svc_name.clone(),
                    "kind" => "5xx",
                )
                .increment(1);
            }
            if !state.passive_record_disabled {
                state.health.record_failure_at(
                    &service.id,
                    &svc_name,
                    format!("upstream {status}"),
                    request_started,
                );
            }
        } else if !state.passive_record_disabled {
            state.health.record_success_at(&service.id, &svc_name, request_started);
        }
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
            } else if state.passive_health.record_success(&service.id, &tid) {
                tracing::info!(
                    service = %svc_name,
                    target_id = %tid,
                    "passive health: target recovered"
                );
                state.lb.mark_target_health(&service.id, &tid, true);
            }
        }

        // Build the streamed downstream response. `Body::new(incoming)`
        // wraps the hyper `Incoming` in axum's body type — no read,
        // no copy. Bytes flow upstream→downstream as they arrive.
        let mut final_resp = Response::new(Body::new(incoming));
        *final_resp.status_mut() = status;
        *final_resp.headers_mut() = resp_parts.headers;

        // Sticky-session cookie + bench-info headers — these mutate
        // headers only, no body access needed.
        if is_cookie_sticky {
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

        // Telemetry (status only — uses `status.as_u16()`, body unread).
        // The whole block is gated at the call site so the bucket / format
        // / borrows aren't paid when `minimal_telemetry` is on.
        if !state.minimal_telemetry {
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
                request_started,
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
        }

        return Ok(final_resp);
    }

    // ── Buffered (plugin-aware) path ──────────────────────────────────
    // Plugins (proxy-cache, response-transformer, etc.) inspect or
    // mutate the body, so we must materialise it first. One heap
    // allocation per response.
    let resp_body = match axum::body::to_bytes(Body::new(incoming), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            state.health.record_failure_at(
                &service.id,
                &svc_name,
                format!("upstream body error: {e}"),
                request_started,
            );
            if !state.minimal_telemetry {
                metrics::counter!(
                    "lynxx_upstream_errors_total",
                    "service" => svc_name.clone(),
                    "kind" => "other",
                )
                .increment(1);
                state.record_request_metric(&svc_name, &route_id, method, "5xx", &target_label);
                state.record_request_duration(
                    &svc_name,
                    &route_id,
                    method,
                    &target_label,
                    start.elapsed().as_secs_f64(),
                );
                state.log_request(
                    request_started,
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
            }
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
        if !state.passive_record_disabled {
            state.health.record_failure_at(
                &service.id,
                &svc_name,
                format!("upstream {status}"),
                request_started,
            );
        }
    } else if !state.passive_record_disabled {
        state.health.record_success_at(&service.id, &svc_name, request_started);
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
    // land on the same target. `is_cookie_sticky` parsed once at LB-pick
    // time so both telemetry branches share it.
    if is_cookie_sticky {
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

    // Per-request telemetry: counter + histogram + access-log. The whole
    // block is gated at the call site so when `minimal_telemetry` is on the
    // bucket/format/borrow work isn't paid — the helpers themselves no
    // longer carry an inner guard.
    if !state.minimal_telemetry {
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
            request_started,
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
    }

    Ok(final_resp)
}

#[cfg(test)]
mod handler_helpers_tests {
    use super::{extract_cookie, extract_query_param};
    use axum::http::{header::COOKIE, HeaderMap, HeaderValue};

    fn cookies_to_headers(values: &[&str]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for v in values {
            m.append(COOKIE, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn extract_cookie_returns_borrowed_value() {
        let h = cookies_to_headers(&["a=one; b=two; c=three"]);
        let got = extract_cookie(&h, "b");
        assert_eq!(got, Some("two"));
    }

    #[test]
    fn extract_cookie_handles_multiple_cookie_headers() {
        let h = cookies_to_headers(&["a=one", "b=two"]);
        assert_eq!(extract_cookie(&h, "a"), Some("one"));
        assert_eq!(extract_cookie(&h, "b"), Some("two"));
    }

    #[test]
    fn extract_cookie_strips_whitespace_around_value() {
        let h = cookies_to_headers(&["  sticky =   abc123  "]);
        assert_eq!(extract_cookie(&h, "sticky"), Some("abc123"));
    }

    #[test]
    fn extract_cookie_missing_returns_none() {
        let h = cookies_to_headers(&["a=one"]);
        assert_eq!(extract_cookie(&h, "missing"), None);
    }

    #[test]
    fn extract_cookie_empty_headers_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(extract_cookie(&h, "anything"), None);
    }

    #[test]
    fn extract_query_param_finds_value() {
        let qs = "foo=1&bar=hello&baz=42";
        assert_eq!(extract_query_param(qs, "bar"), Some("hello"));
    }

    #[test]
    fn extract_query_param_returns_first_occurrence() {
        // Spec doesn't enforce uniqueness; we take the first hit,
        // consistent with how a hash-LB would pick a bucket.
        let qs = "x=1&x=2";
        assert_eq!(extract_query_param(qs, "x"), Some("1"));
    }

    #[test]
    fn extract_query_param_handles_empty_value() {
        let qs = "k=&other=v";
        assert_eq!(extract_query_param(qs, "k"), Some(""));
    }

    #[test]
    fn extract_query_param_missing_returns_none() {
        let qs = "foo=1&bar=2";
        assert_eq!(extract_query_param(qs, "missing"), None);
    }

    #[test]
    fn extract_query_param_pairs_without_equals_are_skipped() {
        // `split_once('=')` returns None for tokens that have no `=`,
        // and `filter_map` drops them. The named param is still found.
        let qs = "flagonly&named=value";
        assert_eq!(extract_query_param(qs, "named"), Some("value"));
        assert_eq!(extract_query_param(qs, "flagonly"), None);
    }

    #[test]
    fn extract_query_param_does_not_decode_percent_escapes() {
        // Intentional: we return the raw encoded value. Documented
        // tradeoff for the LB consistent-hashing + route matchers.
        let qs = "name=hello%20world";
        assert_eq!(extract_query_param(qs, "name"), Some("hello%20world"));
    }
}
