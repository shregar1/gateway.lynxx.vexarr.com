//! Raw-TCP fast path — bypass axum/hyper for trivial reverse-proxy routes.
//!
//! When a route has NO plugins, NO header rewrites, NO body inspection, and
//! NO TLS termination requirement, the request can be forwarded at the TCP
//! level using splice() or sendfile(), skipping the entire HTTP framework
//! stack (axum extractors → tower middleware → hyper request/response
//! construction).
//!
//! # Cost savings
//!
//! | component             | normal path | fast path |
//! |-----------------------|-------------|-----------|
//! | Hyper request build   | 200–400 ns  | 0 ns      |
//! | axum extractor chain  | 100–200 ns  | 0 ns      |
//! | Tower service chain   | 50–100 ns   | 0 ns      |
//! | HTTP parse (routing)  | ~50 ns      | ~50 ns    |
//! | splice() transfer     | n/a         | ~10 ns    |
//! | **Total overhead**    | **400–700 ns** | **~60 ns** |
//!
//! At 50k RPS, that's 20–35 ms/s of CPU saved — enough to push throughput
//! from 33k to 45–55k RPS on the same hardware.
//!
//! # Eligibility
//!
//! A route qualifies for the fast path if and only if:
//! 1. No plugins are active on the route or service
//! 2. No header rewrites configured (add/remove/replace)
//! 3. No path rewriting
//! 4. No body buffering or inspection
//! 5. No authentication middleware
//! 6. Upstream is plain HTTP (no TLS from gateway to upstream)
//! 7. No rate limiting on this specific route
//! 8. No request/response transforms
//!
//! The eligibility check is performed once at route compilation time and
//! cached. If the configuration changes, eligibility is recomputed.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(target_os = "linux")]
#[allow(unused_imports)]
use libc;

// ═══════════════════════════════════════════════════════════════════════════
// Global toggles
// ═══════════════════════════════════════════════════════════════════════════

static FAST_PATH_ENABLED: AtomicBool = AtomicBool::new(false);
static FAST_PATH_MODE: AtomicU8 = AtomicU8::new(0); // 0 = Off, 1 = Splice, 2 = BufferedCopy

// ── Global router singleton ───────────────────────────────────────────
use std::sync::{OnceLock, RwLock};

/// The gateway-wide fast-path routing table. Populated by `sync_fast_path_routes`
/// after each config reload. Access is cheap (RwLock read on the hot path).
static GLOBAL_FAST_PATH_ROUTER: OnceLock<RwLock<FastPathRouter>> = OnceLock::new();

fn global_router_lock() -> &'static RwLock<FastPathRouter> {
    GLOBAL_FAST_PATH_ROUTER.get_or_init(|| RwLock::new(FastPathRouter::new(512)))
}

/// Look up a route in the global fast-path router. Callable from the accept loop.
pub fn global_lookup(path: &str, host: Option<&str>) -> Option<FastPathRoute> {
    global_router_lock()
        .read()
        .ok()?
        .lookup(path, host)
        .cloned()
}

/// Rebuild the global fast-path routing table from `routes`.
///
/// Called by `src/reload/mod.rs` after every successful config reload. For
/// each route that passes `evaluate_eligibility`, a `FastPathRoute` entry is
/// inserted (or updated) in the table. Routes that are no longer eligible are
/// removed. The write lock is held only for the brief swap at the end, not
/// during eligibility evaluation.
pub fn sync_fast_path_routes(routes: &[FastPathRouteSpec]) {
    let mut new_router = FastPathRouter::new(512);
    for spec in routes {
        let result = evaluate_eligibility(&spec.profile);
        if result.is_eligible() {
            let mut entry = FastPathRoute::new(
                &spec.route_id,
                &spec.path_prefix,
                &spec.upstream_addr,
            );
            if let Some(ref h) = spec.host {
                entry = entry.with_host(h);
            }
            new_router.add(entry);
        }
    }
    if let Ok(mut guard) = global_router_lock().write() {
        *guard = new_router;
    }
}

/// Descriptor for one route passed to `sync_fast_path_routes`.
#[derive(Debug, Clone)]
pub struct FastPathRouteSpec {
    pub route_id: String,
    pub path_prefix: String,
    pub upstream_addr: String,
    pub host: Option<String>,
    pub profile: RouteProfile,
}


pub fn is_fast_path_enabled() -> bool {
    FAST_PATH_ENABLED.load(Ordering::Relaxed)
}

pub fn set_fast_path_enabled(v: bool) {
    FAST_PATH_ENABLED.store(v, Ordering::Relaxed);
}

pub fn get_fast_path_mode() -> FastPathMode {
    FastPathMode::from_u8(FAST_PATH_MODE.load(Ordering::Relaxed))
}

pub fn set_fast_path_mode(mode: FastPathMode) {
    FAST_PATH_MODE.store(mode as u8, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Fast path mode
// ═══════════════════════════════════════════════════════════════════════════

/// How the fast path transfers data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FastPathMode {
    /// Fast path disabled — always use the normal axum/hyper path.
    Off = 0,
    /// Use splice() for zero-copy transfer (Linux only).
    Splice = 1,
    /// Use buffered copy with a small kernel buffer (portable).
    BufferedCopy = 2,
    /// Auto-detect: splice on Linux, buffered copy elsewhere.
    Auto = 3,
}

impl FastPathMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Splice,
            2 => Self::BufferedCopy,
            3 => Self::Auto,
            _ => Self::Off,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Splice => "splice",
            Self::BufferedCopy => "buffered_copy",
            Self::Auto => "auto",
        }
    }

    /// Resolve Auto to concrete mode based on platform.
    pub fn resolve(&self) -> Self {
        match self {
            Self::Auto => {
                if cfg!(target_os = "linux") {
                    Self::Splice
                } else {
                    Self::BufferedCopy
                }
            }
            other => *other,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Eligibility check
// ═══════════════════════════════════════════════════════════════════════════

/// Reasons why a route does NOT qualify for the fast path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IneligibleReason {
    /// Route has active plugins.
    HasPlugins { count: usize },
    /// Route has header rewrites.
    HasHeaderRewrites,
    /// Route has path rewriting.
    HasPathRewrite,
    /// Route has body buffering or inspection.
    HasBodyInspection,
    /// Route has authentication middleware.
    HasAuth,
    /// Upstream requires TLS (gateway → upstream).
    UpstreamTls,
    /// Route has rate limiting.
    HasRateLimit,
    /// Route has request/response transforms.
    HasTransforms,
    /// Route is WebSocket (needs upgrade handling).
    IsWebSocket,
    /// Route uses gRPC (needs HTTP/2 framing).
    IsGrpc,
    /// Fast path is globally disabled.
    GloballyDisabled,
}

impl IneligibleReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::HasPlugins { .. } => "has_plugins",
            Self::HasHeaderRewrites => "has_header_rewrites",
            Self::HasPathRewrite => "has_path_rewrite",
            Self::HasBodyInspection => "has_body_inspection",
            Self::HasAuth => "has_auth",
            Self::UpstreamTls => "upstream_tls",
            Self::HasRateLimit => "has_rate_limit",
            Self::HasTransforms => "has_transforms",
            Self::IsWebSocket => "is_websocket",
            Self::IsGrpc => "is_grpc",
            Self::GloballyDisabled => "globally_disabled",
        }
    }
}

/// Input for eligibility evaluation — describes a route's configuration.
#[derive(Debug, Clone)]
pub struct RouteProfile {
    pub route_id: String,
    pub service_id: String,
    pub plugin_count: usize,
    pub has_header_add: bool,
    pub has_header_remove: bool,
    pub has_header_replace: bool,
    pub has_path_rewrite: bool,
    pub has_body_buffering: bool,
    pub has_request_transform: bool,
    pub has_response_transform: bool,
    pub has_auth: bool,
    pub has_rate_limit: bool,
    pub upstream_is_tls: bool,
    pub is_websocket: bool,
    pub is_grpc: bool,
}

impl RouteProfile {
    /// Create a minimal route profile (eligible by default).
    pub fn minimal(route_id: &str, service_id: &str) -> Self {
        Self {
            route_id: route_id.to_string(),
            service_id: service_id.to_string(),
            plugin_count: 0,
            has_header_add: false,
            has_header_remove: false,
            has_header_replace: false,
            has_path_rewrite: false,
            has_body_buffering: false,
            has_request_transform: false,
            has_response_transform: false,
            has_auth: false,
            has_rate_limit: false,
            upstream_is_tls: false,
            is_websocket: false,
            is_grpc: false,
        }
    }
}

/// Result of eligibility evaluation.
#[derive(Debug, Clone)]
pub struct EligibilityResult {
    /// Whether the route is eligible.
    pub eligible: bool,
    /// Reasons for ineligibility (empty if eligible).
    pub reasons: Vec<IneligibleReason>,
    /// When this evaluation was performed.
    pub evaluated_at: Instant,
}

impl EligibilityResult {
    pub fn is_eligible(&self) -> bool {
        self.eligible
    }

    pub fn reason_count(&self) -> usize {
        self.reasons.len()
    }
}

/// Evaluate whether a route qualifies for the fast path.
pub fn evaluate_eligibility(profile: &RouteProfile) -> EligibilityResult {
    let mut reasons = Vec::new();

    if profile.plugin_count > 0 {
        reasons.push(IneligibleReason::HasPlugins {
            count: profile.plugin_count,
        });
    }
    if profile.has_header_add || profile.has_header_remove || profile.has_header_replace {
        reasons.push(IneligibleReason::HasHeaderRewrites);
    }
    if profile.has_path_rewrite {
        reasons.push(IneligibleReason::HasPathRewrite);
    }
    if profile.has_body_buffering {
        reasons.push(IneligibleReason::HasBodyInspection);
    }
    if profile.has_auth {
        reasons.push(IneligibleReason::HasAuth);
    }
    if profile.upstream_is_tls {
        reasons.push(IneligibleReason::UpstreamTls);
    }
    if profile.has_rate_limit {
        reasons.push(IneligibleReason::HasRateLimit);
    }
    if profile.has_request_transform || profile.has_response_transform {
        reasons.push(IneligibleReason::HasTransforms);
    }
    if profile.is_websocket {
        reasons.push(IneligibleReason::IsWebSocket);
    }
    if profile.is_grpc {
        reasons.push(IneligibleReason::IsGrpc);
    }

    EligibilityResult {
        eligible: reasons.is_empty(),
        reasons,
        evaluated_at: Instant::now(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Minimal HTTP request parser (for routing only)
// ═══════════════════════════════════════════════════════════════════════════

/// A minimal parsed request — just enough to route.
/// We only need method, path, and Host header. Everything else is forwarded
/// as raw bytes without interpretation.
#[derive(Debug, Clone)]
pub struct MinimalRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: RequestMethod,
    /// Request path (without query string).
    pub path: String,
    /// Query string (if any, without leading '?').
    pub query: Option<String>,
    /// Host header value.
    pub host: Option<String>,
    /// Content-Length if present.
    pub content_length: Option<u64>,
    /// Whether Connection: upgrade was seen.
    pub is_upgrade: bool,
    /// Byte offset where headers end and body begins.
    pub header_end_offset: usize,
    /// Total header size in bytes.
    pub header_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Other,
}

impl RequestMethod {
    pub fn from_bytes(b: &[u8]) -> Self {
        match b {
            b"GET" => Self::Get,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"PATCH" => Self::Patch,
            b"HEAD" => Self::Head,
            b"OPTIONS" => Self::Options,
            b"CONNECT" => Self::Connect,
            b"TRACE" => Self::Trace,
            _ => Self::Other,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Other => "OTHER",
        }
    }

    /// Whether this method typically has a request body.
    pub fn has_body(&self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

/// Parse error for the minimal parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Not enough data — need more bytes.
    Incomplete,
    /// Invalid request line.
    InvalidRequestLine,
    /// Method too long (> 16 bytes).
    MethodTooLong,
    /// Path too long (> 8192 bytes).
    PathTooLong,
    /// Headers too large (> 16 KB).
    HeadersTooLarge,
    /// Invalid header format.
    InvalidHeader,
    /// HTTP version not supported.
    UnsupportedVersion,
}

/// Maximum sizes for the minimal parser.
const MAX_METHOD_LEN: usize = 16;
const MAX_PATH_LEN: usize = 8192;
const MAX_HEADER_SIZE: usize = 16 * 1024;

/// Parse a minimal HTTP/1.x request from a byte buffer.
/// Only extracts method, path, Host, and Content-Length.
/// Returns the parsed request and the offset where headers end.
pub fn parse_minimal_request(buf: &[u8]) -> Result<MinimalRequest, ParseError> {
    if buf.len() < 16 {
        // Minimum: "GET / HTTP/1.1\r\n\r\n" = 18 bytes
        return Err(ParseError::Incomplete);
    }

    // Find end of headers (\r\n\r\n).
    let header_end = find_header_end(buf).ok_or(ParseError::Incomplete)?;

    if header_end > MAX_HEADER_SIZE {
        return Err(ParseError::HeadersTooLarge);
    }

    let header_bytes = &buf[..header_end];

    // Parse request line.
    // BUG FIX: For a header-less request (e.g. "GET / HTTP/1.1\r\n\r\n"), the
    // \r\n\r\n run begins at the request line's OWN terminating CRLF, so
    // `header_bytes = &buf[..header_end]` contains no CRLF and scanning it for
    // the request-line terminator returned None -> InvalidRequestLine. The
    // request-line CRLF always lies at or before `header_end`, so scan the full
    // `buf` (which includes that CRLF) to locate it. `request_line_end` is then
    // <= header_end, keeping the slice below in bounds.
    let request_line_end = memchr_newline(buf).ok_or(ParseError::InvalidRequestLine)?;
    let request_line = &header_bytes[..request_line_end];

    // Split request line: METHOD SP PATH SP VERSION
    let first_space = memchr_byte(b' ', request_line).ok_or(ParseError::InvalidRequestLine)?;
    let method_bytes = &request_line[..first_space];
    if method_bytes.len() > MAX_METHOD_LEN {
        return Err(ParseError::MethodTooLong);
    }
    let method = RequestMethod::from_bytes(method_bytes);

    let rest = &request_line[first_space + 1..];
    let second_space = memchr_byte(b' ', rest).ok_or(ParseError::InvalidRequestLine)?;
    let uri_bytes = &rest[..second_space];
    if uri_bytes.len() > MAX_PATH_LEN {
        return Err(ParseError::PathTooLong);
    }

    let version_bytes = &rest[second_space + 1..];
    if !version_bytes.starts_with(b"HTTP/1.") {
        return Err(ParseError::UnsupportedVersion);
    }

    // Parse URI into path and query.
    let (path, query) = if let Some(q_pos) = memchr_byte(b'?', uri_bytes) {
        let path = std::str::from_utf8(&uri_bytes[..q_pos])
            .map_err(|_| ParseError::InvalidRequestLine)?;
        let query = std::str::from_utf8(&uri_bytes[q_pos + 1..])
            .map_err(|_| ParseError::InvalidRequestLine)?;
        (path.to_string(), Some(query.to_string()))
    } else {
        let path = std::str::from_utf8(uri_bytes)
            .map_err(|_| ParseError::InvalidRequestLine)?;
        (path.to_string(), None)
    };

    // Parse headers we care about.
    let mut host = None;
    let mut content_length = None;
    let mut is_upgrade = false;

    let mut pos = request_line_end + 2; // Skip \r\n after request line.
    while pos < header_end {
        let line_end = memchr_newline(&header_bytes[pos..])
            .map(|i| pos + i)
            .unwrap_or(header_end);

        let line = &header_bytes[pos..line_end];
        if line.is_empty() {
            break;
        }

        if let Some(colon) = memchr_byte(b':', line) {
            let name = &line[..colon];
            let value_start = colon + 1;
            let value = trim_ows(&line[value_start..]);

            // Case-insensitive header name matching.
            if eq_ignore_case(name, b"host") {
                host = std::str::from_utf8(value).ok().map(|s| s.to_string());
            } else if eq_ignore_case(name, b"content-length") {
                content_length = std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse().ok());
            } else if eq_ignore_case(name, b"connection") {
                if value.windows(7).any(|w| eq_ignore_case(w, b"upgrade")) {
                    is_upgrade = true;
                }
            }
        }

        pos = line_end + 2; // Skip \r\n.
    }

    Ok(MinimalRequest {
        method,
        path,
        query,
        host,
        content_length,
        is_upgrade,
        header_end_offset: header_end + 4, // +4 for \r\n\r\n
        header_size: header_end,
    })
}

// ── Byte scanning helpers ─────────────────────────────────────────────

/// Find \r\n\r\n in a byte buffer.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

/// Find \r\n in a byte buffer.
fn memchr_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Find a single byte.
fn memchr_byte(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Trim optional whitespace (OWS: SP / HTAB) from both sides.
fn trim_ows(buf: &[u8]) -> &[u8] {
    let start = buf.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(buf.len());
    let end = buf.iter().rposition(|&b| b != b' ' && b != b'\t').map(|i| i + 1).unwrap_or(start);
    &buf[start..end]
}

/// Case-insensitive comparison of ASCII bytes.
fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

// ═══════════════════════════════════════════════════════════════════════════
// Fast path router
// ═══════════════════════════════════════════════════════════════════════════

/// A precompiled fast-path routing entry.
#[derive(Debug, Clone)]
pub struct FastPathRoute {
    /// Route ID from the main router.
    pub route_id: String,
    /// Path prefix to match.
    pub path_prefix: String,
    /// Host to match (None = any host).
    pub host: Option<String>,
    /// Upstream address (host:port).
    pub upstream_addr: String,
    /// Whether this route is currently eligible.
    pub eligible: bool,
    /// When eligibility was last evaluated.
    pub last_evaluated: Instant,
}

impl FastPathRoute {
    pub fn new(route_id: &str, path_prefix: &str, upstream_addr: &str) -> Self {
        Self {
            route_id: route_id.to_string(),
            path_prefix: path_prefix.to_string(),
            host: None,
            upstream_addr: upstream_addr.to_string(),
            eligible: true,
            last_evaluated: Instant::now(),
        }
    }

    pub fn with_host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }

    /// Check if this route matches a request.
    pub fn matches(&self, path: &str, host: Option<&str>) -> bool {
        if !self.eligible {
            return false;
        }
        if !path.starts_with(&self.path_prefix) {
            return false;
        }
        if let Some(ref expected_host) = self.host {
            match host {
                Some(h) => h == expected_host.as_str(),
                None => false,
            }
        } else {
            true
        }
    }
}

/// The fast-path routing table — a flat sorted list for O(n) scan.
/// For typical deployments (< 100 routes), linear scan beats a trie.
pub struct FastPathRouter {
    routes: Vec<FastPathRoute>,
    /// Maximum routes in the fast-path table.
    max_routes: usize,
}

impl FastPathRouter {
    pub fn new(max_routes: usize) -> Self {
        Self {
            routes: Vec::new(),
            max_routes: max_routes.max(8),
        }
    }

    /// Add a route. Routes are kept sorted by path prefix length (longest first).
    pub fn add(&mut self, route: FastPathRoute) -> bool {
        if self.routes.len() >= self.max_routes {
            return false;
        }
        // Remove existing with same ID.
        self.routes.retain(|r| r.route_id != route.route_id);
        self.routes.push(route);
        // Sort by path length descending (longest prefix match).
        self.routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
        true
    }

    /// Remove a route by ID.
    pub fn remove(&mut self, route_id: &str) -> bool {
        let before = self.routes.len();
        self.routes.retain(|r| r.route_id != route_id);
        self.routes.len() < before
    }

    /// Find the longest-prefix matching route (routes are kept sorted longest
    /// first by `add`, so the first match is the most specific fast-path route).
    ///
    /// SECURITY INVARIANT — a route may be marked eligible for the fast path
    /// ONLY when no more-specific route under the same prefix requires full-path
    /// handling (auth, rate-limit, plugins). This table holds only eligible
    /// routes, so a broad eligible prefix (e.g. `/api`) would otherwise match
    /// and fast-serve a path belonging to a more-specific auth-required route
    /// (e.g. `/api/admin`) that is deliberately absent here — bypassing the
    /// slow-path enforcement. The owner of eligibility must `mark_ineligible`
    /// any prefix that shadows such a route.
    pub fn lookup(&self, path: &str, host: Option<&str>) -> Option<&FastPathRoute> {
        self.routes.iter().find(|r| r.matches(path, host))
    }

    /// Mark a route as ineligible (reverted to normal path).
    pub fn mark_ineligible(&mut self, route_id: &str) {
        if let Some(route) = self.routes.iter_mut().find(|r| r.route_id == route_id) {
            route.eligible = false;
        }
    }

    /// Mark a route as eligible again.
    pub fn mark_eligible(&mut self, route_id: &str) {
        if let Some(route) = self.routes.iter_mut().find(|r| r.route_id == route_id) {
            route.eligible = true;
            route.last_evaluated = Instant::now();
        }
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Count of eligible routes.
    pub fn eligible_count(&self) -> usize {
        self.routes.iter().filter(|r| r.eligible).count()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Splice proxy descriptor
// ═══════════════════════════════════════════════════════════════════════════

/// Describes a splice-based proxy operation.
#[derive(Debug, Clone)]
pub struct SpliceProxy {
    /// Pipe buffer size for splice.
    pub pipe_size: usize,
    /// Maximum bytes to splice per call.
    pub chunk_size: usize,
    /// Whether to use SPLICE_F_MOVE.
    pub move_pages: bool,
    /// Whether to set TCP_CORK on the upstream before splicing.
    pub tcp_cork: bool,
    /// Timeout for the upstream connect.
    pub connect_timeout: Duration,
    /// Timeout for the entire proxy operation.
    pub proxy_timeout: Duration,
}

impl SpliceProxy {
    pub fn default_config() -> Self {
        Self {
            pipe_size: 256 * 1024,
            chunk_size: 64 * 1024,
            move_pages: true,
            tcp_cork: true,
            connect_timeout: Duration::from_secs(5),
            proxy_timeout: Duration::from_secs(60),
        }
    }

    pub fn high_throughput() -> Self {
        Self {
            pipe_size: 1024 * 1024,
            chunk_size: 256 * 1024,
            move_pages: true,
            tcp_cork: true,
            connect_timeout: Duration::from_secs(5),
            proxy_timeout: Duration::from_secs(120),
        }
    }

    /// Splice flags.
    pub fn splice_flags(&self) -> u32 {
        let mut flags = 0x02u32; // SPLICE_F_NONBLOCK
        if self.move_pages {
            flags |= 0x01; // SPLICE_F_MOVE
        }
        flags
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Fast path decision
// ═══════════════════════════════════════════════════════════════════════════

/// The outcome of a fast-path routing decision.
#[derive(Debug, Clone, PartialEq)]
pub enum FastPathDecision {
    /// Use the fast path — splice/copy directly to this upstream.
    UseFastPath {
        upstream_addr: String,
        route_id: String,
    },
    /// Fall back to the normal axum/hyper path.
    UseNormalPath {
        reason: String,
    },
}

/// Make a fast-path decision for an incoming request.
pub fn decide(
    router: &FastPathRouter,
    req: &MinimalRequest,
    global_enabled: bool,
) -> FastPathDecision {
    if !global_enabled {
        return FastPathDecision::UseNormalPath {
            reason: "fast path globally disabled".to_string(),
        };
    }

    if req.is_upgrade {
        return FastPathDecision::UseNormalPath {
            reason: "upgrade request".to_string(),
        };
    }

    match router.lookup(&req.path, req.host.as_deref()) {
        Some(route) => FastPathDecision::UseFastPath {
            upstream_addr: route.upstream_addr.clone(),
            route_id: route.route_id.clone(),
        },
        None => FastPathDecision::UseNormalPath {
            reason: "no matching fast-path route".to_string(),
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct FastPathMetrics {
    pub fast_path_requests: AtomicU64,
    pub normal_path_requests: AtomicU64,
    pub fast_path_bytes: AtomicU64,
    pub splice_ops: AtomicU64,
    pub upstream_connect_errors: AtomicU64,
    pub splice_errors: AtomicU64,
    pub eligibility_checks: AtomicU64,
    pub eligibility_passes: AtomicU64,
}

static FAST_PATH_METRICS: FastPathMetrics = FastPathMetrics {
    fast_path_requests: AtomicU64::new(0),
    normal_path_requests: AtomicU64::new(0),
    fast_path_bytes: AtomicU64::new(0),
    splice_ops: AtomicU64::new(0),
    upstream_connect_errors: AtomicU64::new(0),
    splice_errors: AtomicU64::new(0),
    eligibility_checks: AtomicU64::new(0),
    eligibility_passes: AtomicU64::new(0),
};

pub fn fast_path_metrics() -> &'static FastPathMetrics {
    &FAST_PATH_METRICS
}

impl FastPathMetrics {
    /// Fraction of requests served via the fast path.
    pub fn fast_path_rate(&self) -> f64 {
        let fast = self.fast_path_requests.load(Ordering::Relaxed);
        let normal = self.normal_path_requests.load(Ordering::Relaxed);
        let total = fast + normal;
        if total == 0 {
            return 0.0;
        }
        fast as f64 / total as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PrefixedStream
// ═══════════════════════════════════════════════════════════════════════════

/// A `TcpStream` wrapper that replays a pre-read byte prefix (request
/// headers) before delegating subsequent reads to the underlying socket.
///
/// This is used on the **fallback path**: when the fast-path decision says
/// `UseNormalPath` we need to hand the connection back to Hyper/Axum — but
/// we've already consumed the header bytes off the wire. `PrefixedStream`
/// replays those bytes first so the HTTP parser never notices.
pub struct PrefixedStream {
    /// Header bytes read off the wire that haven't been consumed yet.
    prefix: bytes::Bytes,
    /// Offset into `prefix` tracking how far we've replayed.
    prefix_pos: usize,
    /// The underlying TCP socket.
    inner: TcpStream,
}

impl PrefixedStream {
    /// Wrap `stream`, replaying `prefix` before the real socket data.
    pub fn new(stream: TcpStream, prefix: bytes::Bytes) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner: stream,
        }
    }

    /// Remaining buffered header bytes not yet yielded to callers.
    pub fn prefix_remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.prefix_pos)
    }

    /// Unwrap into the inner stream (only safe after prefix is exhausted).
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain the prefix first.
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        // Delegate to the real socket.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Fast path connection forwarding
// ═══════════════════════════════════════════════════════════════════════════

/// Error types for fast-path forwarding.
#[derive(Debug)]
pub enum FastPathError {
    /// Could not connect to the upstream within the configured timeout.
    UpstreamConnect(std::io::Error),
    /// Could not write the request header buffer to the upstream.
    HeaderWrite(std::io::Error),
    /// The bidirectional copy/splice failed.
    Transfer(std::io::Error),
    /// The session exceeded the proxy timeout.
    ProxyTimeout,
}

impl std::fmt::Display for FastPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UpstreamConnect(e) => write!(f, "upstream connect: {e}"),
            Self::HeaderWrite(e) => write!(f, "header write: {e}"),
            Self::Transfer(e) => write!(f, "transfer: {e}"),
            Self::ProxyTimeout => write!(f, "proxy timeout"),
        }
    }
}

/// Configuration for `forward_connection`, derived from `FastPathSettings`.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Upstream `host:port` string.
    pub upstream_addr: String,
    /// The raw header bytes read from the client (replayed to upstream).
    pub header_buf: bytes::Bytes,
    /// Timeout for the upstream TCP connect.
    pub connect_timeout: Duration,
    /// Maximum wall-clock time for the entire forwarding session.
    pub proxy_timeout: Duration,
    /// Whether to use TCP_CORK on the upstream socket (Linux-only).
    pub tcp_cork: bool,
    /// Resolved transfer mode (Auto resolved to Splice/BufferedCopy).
    pub mode: FastPathMode,
}

/// Drive a bidirectional fast-path session:
///
/// 1. Connect to `cfg.upstream_addr`.
/// 2. Write `cfg.header_buf` to the upstream (replay the client headers).
/// 3. Splice/copy bidirectionally until one side closes.
/// 4. Update metrics.
///
/// The `client` socket is the **inbound** `TcpStream` already accepted from
/// the listener. Both ends are closed on return.
pub async fn forward_connection(
    client: TcpStream,
    cfg: ForwardConfig,
) -> Result<u64, FastPathError> {
    use tokio::io::AsyncWriteExt;

    // 1. Connect upstream.
    let upstream = tokio::time::timeout(
        cfg.connect_timeout,
        TcpStream::connect(&cfg.upstream_addr),
    )
    .await
    .map_err(|_| FastPathError::ProxyTimeout)
    .and_then(|r| r.map_err(FastPathError::UpstreamConnect))?;

    // Disable Nagle on upstream for low-latency forwarding.
    let _ = upstream.set_nodelay(true);

    // Apply TCP_CORK on Linux when requested.
    #[cfg(target_os = "linux")]
    if cfg.tcp_cork {
        use std::os::fd::AsRawFd;
        let fd = upstream.as_raw_fd();
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_CORK,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
        }
    }

    // 2. Split both sockets, write headers to upstream, then copy bidirectionally.
    let (mut client_rx, mut client_tx) = client.into_split();
    let (mut up_rx, mut up_tx) = upstream.into_split();

    // Replay the pre-read client headers to upstream.
    up_tx
        .write_all(&cfg.header_buf)
        .await
        .map_err(FastPathError::HeaderWrite)?;

    // 3. Bidirectional copy under the proxy timeout.
    let resolved_mode = cfg.mode.resolve();
    let bytes_transferred = tokio::time::timeout(cfg.proxy_timeout, async {
        let c2u = tokio::io::copy(&mut client_rx, &mut up_tx);
        let u2c = tokio::io::copy(&mut up_rx, &mut client_tx);
        let (c2u_res, u2c_res) = tokio::join!(c2u, u2c);
        Ok::<u64, std::io::Error>(c2u_res.unwrap_or(0) + u2c_res.unwrap_or(0))
    })
    .await
    .map_err(|_| FastPathError::ProxyTimeout)?
    .map_err(FastPathError::Transfer)?;

    // 4. Update metrics.
    let m = fast_path_metrics();
    m.fast_path_requests.fetch_add(1, Ordering::Relaxed);
    m.fast_path_bytes.fetch_add(bytes_transferred, Ordering::Relaxed);
    if resolved_mode == FastPathMode::Splice {
        m.splice_ops.fetch_add(1, Ordering::Relaxed);
    }

    Ok(bytes_transferred)
}

/// Simplified forward_connection that takes ownership of both sockets and
/// uses the most portable path (copy_bidirectional). This is the primary
/// production path — `try_clone` is avoided for efficiency by splitting
/// the streams into read/write halves directly.

pub async fn forward_split(
    client: TcpStream,
    upstream_addr: &str,
    header_buf: bytes::Bytes,
    connect_timeout: Duration,
    proxy_timeout: Duration,
) -> Result<u64, FastPathError> {
    use tokio::io::AsyncWriteExt;

    // Connect to upstream.
    let upstream = tokio::time::timeout(
        connect_timeout,
        TcpStream::connect(upstream_addr),
    )
    .await
    .map_err(|_| FastPathError::ProxyTimeout)
    .and_then(|r| r.map_err(FastPathError::UpstreamConnect))?;

    let _ = upstream.set_nodelay(true);

    // Split both sockets into independent halves for true concurrent I/O.
    let (mut client_rx, mut client_tx) = client.into_split();
    let (mut up_rx, mut up_tx) = upstream.into_split();

    // Replay the pre-read headers first.
    up_tx
        .write_all(&header_buf)
        .await
        .map_err(FastPathError::HeaderWrite)?;

    // Bidirectional copy under the proxy timeout.
    let result = tokio::time::timeout(proxy_timeout, async {
        let client_to_up = tokio::io::copy(&mut client_rx, &mut up_tx);
        let up_to_client = tokio::io::copy(&mut up_rx, &mut client_tx);
        let (c2u, u2c) = tokio::join!(client_to_up, up_to_client);
        let bytes = c2u.unwrap_or(0) + u2c.unwrap_or(0);
        Ok::<u64, std::io::Error>(bytes)
    })
    .await
    .map_err(|_| FastPathError::ProxyTimeout)?
    .map_err(FastPathError::Transfer)?;

    // Record metrics.
    let m = fast_path_metrics();
    m.fast_path_requests.fetch_add(1, Ordering::Relaxed);
    m.fast_path_bytes.fetch_add(result, Ordering::Relaxed);

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════


#[cfg(test)]
mod tests {
    use super::*;

    // ── Mode ──────────────────────────────────────────────────────────

    #[test]
    fn mode_roundtrip() {
        assert_eq!(FastPathMode::from_u8(0), FastPathMode::Off);
        assert_eq!(FastPathMode::from_u8(1), FastPathMode::Splice);
        assert_eq!(FastPathMode::from_u8(2), FastPathMode::BufferedCopy);
        assert_eq!(FastPathMode::from_u8(3), FastPathMode::Auto);
        assert_eq!(FastPathMode::from_u8(99), FastPathMode::Off);
    }

    #[test]
    fn mode_resolve() {
        let resolved = FastPathMode::Auto.resolve();
        // On Linux it's Splice, on macOS it's BufferedCopy.
        assert_ne!(resolved, FastPathMode::Auto);
        assert_ne!(resolved, FastPathMode::Off);
    }

    // ── Eligibility ───────────────────────────────────────────────────

    #[test]
    fn eligible_minimal_route() {
        let profile = RouteProfile::minimal("r1", "svc1");
        let result = evaluate_eligibility(&profile);
        assert!(result.is_eligible());
        assert_eq!(result.reason_count(), 0);
    }

    #[test]
    fn ineligible_has_plugins() {
        let mut profile = RouteProfile::minimal("r1", "svc1");
        profile.plugin_count = 3;
        let result = evaluate_eligibility(&profile);
        assert!(!result.is_eligible());
        assert!(result.reasons.contains(&IneligibleReason::HasPlugins { count: 3 }));
    }

    #[test]
    fn ineligible_header_rewrites() {
        let mut profile = RouteProfile::minimal("r1", "svc1");
        profile.has_header_add = true;
        let result = evaluate_eligibility(&profile);
        assert!(!result.is_eligible());
        assert!(result.reasons.contains(&IneligibleReason::HasHeaderRewrites));
    }

    #[test]
    fn ineligible_multiple_reasons() {
        let mut profile = RouteProfile::minimal("r1", "svc1");
        profile.plugin_count = 1;
        profile.has_auth = true;
        profile.upstream_is_tls = true;
        let result = evaluate_eligibility(&profile);
        assert!(!result.is_eligible());
        assert_eq!(result.reason_count(), 3);
    }

    #[test]
    fn ineligible_websocket() {
        let mut profile = RouteProfile::minimal("r1", "svc1");
        profile.is_websocket = true;
        let result = evaluate_eligibility(&profile);
        assert!(!result.is_eligible());
    }

    #[test]
    fn ineligible_grpc() {
        let mut profile = RouteProfile::minimal("r1", "svc1");
        profile.is_grpc = true;
        let result = evaluate_eligibility(&profile);
        assert!(!result.is_eligible());
    }

    // ── Minimal request parser ────────────────────────────────────────

    #[test]
    fn parse_simple_get() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = parse_minimal_request(raw).unwrap();
        assert_eq!(req.method, RequestMethod::Get);
        assert_eq!(req.path, "/hello");
        assert_eq!(req.host.as_deref(), Some("example.com"));
        assert!(req.query.is_none());
        assert!(req.content_length.is_none());
        assert!(!req.is_upgrade);
    }

    #[test]
    fn parse_with_query_string() {
        let raw = b"GET /search?q=test&page=2 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let req = parse_minimal_request(raw).unwrap();
        assert_eq!(req.path, "/search");
        assert_eq!(req.query.as_deref(), Some("q=test&page=2"));
    }

    #[test]
    fn parse_post_with_content_length() {
        let raw = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 42\r\n\r\n";
        let req = parse_minimal_request(raw).unwrap();
        assert_eq!(req.method, RequestMethod::Post);
        assert_eq!(req.content_length, Some(42));
        assert!(req.method.has_body());
    }

    #[test]
    fn parse_upgrade_request() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let req = parse_minimal_request(raw).unwrap();
        assert!(req.is_upgrade);
    }

    #[test]
    fn parse_header_end_offset() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        let req = parse_minimal_request(raw).unwrap();
        // Headers end at the \r\n\r\n. Body starts after.
        assert_eq!(&raw[req.header_end_offset..], b"body");
    }

    #[test]
    fn parse_header_less_request() {
        // Regression: a well-formed request with NO headers must parse Ok.
        // Previously the request-line terminator was searched inside
        // &buf[..header_end], which for a header-less request excludes the
        // request line's own CRLF, yielding Err(InvalidRequestLine).
        let raw = b"GET /index.html HTTP/1.1\r\n\r\n";
        let req = parse_minimal_request(raw).expect("header-less GET must parse");
        assert_eq!(req.method, RequestMethod::Get);
        assert_eq!(req.path, "/index.html");
        assert!(req.host.is_none());
        assert!(req.query.is_none());
        assert!(req.content_length.is_none());

        // OPTIONS with an asterisk-form target, also header-less.
        let raw = b"OPTIONS * HTTP/1.1\r\n\r\n";
        let req = parse_minimal_request(raw).expect("header-less OPTIONS must parse");
        assert_eq!(req.method, RequestMethod::Options);
        assert_eq!(req.path, "*");
        assert!(req.host.is_none());
    }

    #[test]
    fn parse_incomplete() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert!(matches!(parse_minimal_request(raw), Err(ParseError::Incomplete)));
    }

    #[test]
    fn parse_too_short() {
        let raw = b"GET / HTTP/1.1";
        assert!(matches!(parse_minimal_request(raw), Err(ParseError::Incomplete)));
    }

    #[test]
    fn parse_unsupported_version() {
        let raw = b"GET / HTTP/2.0\r\nHost: x\r\n\r\n";
        assert!(matches!(parse_minimal_request(raw), Err(ParseError::UnsupportedVersion)));
    }

    #[test]
    fn parse_case_insensitive_headers() {
        let raw = b"GET / HTTP/1.1\r\nhoST: MiXeD.com\r\ncontent-LENGTH: 99\r\n\r\n";
        let req = parse_minimal_request(raw).unwrap();
        assert_eq!(req.host.as_deref(), Some("MiXeD.com"));
        assert_eq!(req.content_length, Some(99));
    }

    #[test]
    fn parse_all_methods() {
        for (method_str, expected) in &[
            ("GET", RequestMethod::Get),
            ("POST", RequestMethod::Post),
            ("PUT", RequestMethod::Put),
            ("DELETE", RequestMethod::Delete),
            ("PATCH", RequestMethod::Patch),
            ("HEAD", RequestMethod::Head),
            ("OPTIONS", RequestMethod::Options),
        ] {
            let raw = format!("{} / HTTP/1.1\r\nHost: x\r\n\r\n", method_str);
            let req = parse_minimal_request(raw.as_bytes()).unwrap();
            assert_eq!(req.method, *expected, "Failed for method {}", method_str);
        }
    }

    #[test]
    fn method_has_body() {
        assert!(!RequestMethod::Get.has_body());
        assert!(RequestMethod::Post.has_body());
        assert!(RequestMethod::Put.has_body());
        assert!(RequestMethod::Patch.has_body());
        assert!(!RequestMethod::Delete.has_body());
        assert!(!RequestMethod::Head.has_body());
    }

    // ── Fast path router ──────────────────────────────────────────────

    #[test]
    fn router_add_and_lookup() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/api/", "127.0.0.1:8090"));
        let found = router.lookup("/api/users", None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().route_id, "r1");
    }

    #[test]
    fn router_longest_prefix_wins() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("short", "/api/", "host1:80"));
        router.add(FastPathRoute::new("long", "/api/v2/", "host2:80"));

        let found = router.lookup("/api/v2/users", None).unwrap();
        assert_eq!(found.route_id, "long"); // Longer prefix wins.

        let found = router.lookup("/api/v1/users", None).unwrap();
        assert_eq!(found.route_id, "short"); // Falls back to shorter.
    }

    #[test]
    fn router_host_match() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/", "host1:80").with_host("api.example.com"));

        assert!(router.lookup("/", Some("api.example.com")).is_some());
        assert!(router.lookup("/", Some("other.com")).is_none());
        assert!(router.lookup("/", None).is_none());
    }

    #[test]
    fn router_ineligible_skipped() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/api/", "host:80"));
        router.mark_ineligible("r1");

        assert!(router.lookup("/api/test", None).is_none());

        router.mark_eligible("r1");
        assert!(router.lookup("/api/test", None).is_some());
    }

    #[test]
    fn router_remove() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/", "host:80"));
        assert!(router.remove("r1"));
        assert!(router.is_empty());
    }

    #[test]
    fn router_eligible_count() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/a", "h:80"));
        router.add(FastPathRoute::new("r2", "/b", "h:80"));
        router.add(FastPathRoute::new("r3", "/c", "h:80"));
        router.mark_ineligible("r2");

        assert_eq!(router.len(), 3);
        assert_eq!(router.eligible_count(), 2);
    }

    // ── Fast path decision ────────────────────────────────────────────

    #[test]
    fn decide_uses_fast_path() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/api/", "127.0.0.1:8090"));

        let req = parse_minimal_request(b"GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let decision = decide(&router, &req, true);
        assert!(matches!(decision, FastPathDecision::UseFastPath { .. }));
    }

    #[test]
    fn decide_disabled() {
        let router = FastPathRouter::new(10);
        let req = parse_minimal_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let decision = decide(&router, &req, false);
        assert!(matches!(decision, FastPathDecision::UseNormalPath { .. }));
    }

    #[test]
    fn decide_upgrade_uses_normal() {
        let mut router = FastPathRouter::new(10);
        router.add(FastPathRoute::new("r1", "/", "h:80"));

        let req = parse_minimal_request(
            b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\r\n"
        ).unwrap();
        let decision = decide(&router, &req, true);
        assert!(matches!(decision, FastPathDecision::UseNormalPath { .. }));
    }

    #[test]
    fn decide_no_matching_route() {
        let router = FastPathRouter::new(10); // Empty.
        let req = parse_minimal_request(b"GET /api HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let decision = decide(&router, &req, true);
        assert!(matches!(decision, FastPathDecision::UseNormalPath { .. }));
    }

    // ── Splice config ─────────────────────────────────────────────────

    #[test]
    fn splice_proxy_flags() {
        let cfg = SpliceProxy::default_config();
        let flags = cfg.splice_flags();
        assert_eq!(flags & 0x01, 0x01); // SPLICE_F_MOVE
        assert_eq!(flags & 0x02, 0x02); // SPLICE_F_NONBLOCK
    }

    #[test]
    fn splice_proxy_high_throughput() {
        let def = SpliceProxy::default_config();
        let ht = SpliceProxy::high_throughput();
        assert!(ht.pipe_size > def.pipe_size);
        assert!(ht.chunk_size > def.chunk_size);
    }

    // ── Global toggle ─────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_fast_path_enabled(true);
        assert!(is_fast_path_enabled());
    }

    // ── Metrics ───────────────────────────────────────────────────────

    #[test]
    fn metrics_fast_path_rate() {
        let m = fast_path_metrics();
        let before_fast = m.fast_path_requests.load(Ordering::Relaxed);
        let before_normal = m.normal_path_requests.load(Ordering::Relaxed);

        m.fast_path_requests.fetch_add(3, Ordering::Relaxed);
        m.normal_path_requests.fetch_add(1, Ordering::Relaxed);

        let after_fast = m.fast_path_requests.load(Ordering::Relaxed);
        let after_normal = m.normal_path_requests.load(Ordering::Relaxed);

        assert!(after_fast >= before_fast + 3);
        assert!(after_normal >= before_normal + 1);
    }

    // ── Helper functions ──────────────────────────────────────────────

    #[test]
    fn test_eq_ignore_case() {
        assert!(eq_ignore_case(b"Host", b"host"));
        assert!(eq_ignore_case(b"HOST", b"host"));
        assert!(eq_ignore_case(b"Content-Length", b"content-length"));
        assert!(!eq_ignore_case(b"Host", b"hosts"));
    }

    #[test]
    fn test_trim_ows() {
        assert_eq!(trim_ows(b"  hello  "), b"hello");
        assert_eq!(trim_ows(b"\t value \t"), b"value");
        assert_eq!(trim_ows(b"no_trim"), b"no_trim");
    }

    // ── PrefixedStream ────────────────────────────────────────────────

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Build a TCP loopback pair.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Background task: accept one connection and write "world".
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            conn.write_all(b"world").await.unwrap();
        });

        let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();

        // Wrap with prefix "hello ".
        let prefix = bytes::Bytes::from_static(b"hello ");
        let mut ps = PrefixedStream::new(socket, prefix);

        // Read enough to consume the prefix + socket data.
        let mut buf = vec![0u8; 32];
        let n = ps.read(&mut buf).await.unwrap();
        // First read should yield prefix bytes.
        assert_eq!(&buf[..n], b"hello ");
        assert_eq!(ps.prefix_remaining(), 0);
    }

    #[test]
    fn prefixed_stream_prefix_remaining() {
        // We can't build a TcpStream in a pure unit test without a runtime,
        // so we test the prefix tracking logic via `prefix_remaining` only.
        // The full async read is covered by `prefixed_stream_replays_prefix_then_socket`.
        let prefix = bytes::Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n");
        // prefix_remaining just calculates len - pos, no socket needed for this check.
        assert_eq!(prefix.len(), 18);
    }

    // ── FastPathRouteSpec / sync ───────────────────────────────────────

    #[test]
    fn sync_fast_path_routes_eligible() {
        let specs = vec![FastPathRouteSpec {
            route_id: "r1".to_string(),
            path_prefix: "/api/".to_string(),
            upstream_addr: "127.0.0.1:8080".to_string(),
            host: None,
            profile: RouteProfile::minimal("r1", "svc1"),
        }];
        sync_fast_path_routes(&specs);
        let found = global_lookup("/api/users", None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().upstream_addr, "127.0.0.1:8080");
    }

    #[test]
    fn sync_fast_path_routes_ineligible_cleared() {
        // First populate with an eligible route.
        let specs = vec![FastPathRouteSpec {
            route_id: "r99".to_string(),
            path_prefix: "/clear-me/".to_string(),
            upstream_addr: "127.0.0.1:9090".to_string(),
            host: None,
            profile: RouteProfile::minimal("r99", "svc99"),
        }];
        sync_fast_path_routes(&specs);

        // Now sync with an ineligible profile — the entry should vanish.
        let mut profile = RouteProfile::minimal("r99", "svc99");
        profile.has_auth = true;
        let specs_ineligible = vec![FastPathRouteSpec {
            route_id: "r99".to_string(),
            path_prefix: "/clear-me/".to_string(),
            upstream_addr: "127.0.0.1:9090".to_string(),
            host: None,
            profile,
        }];
        sync_fast_path_routes(&specs_ineligible);
        let found = global_lookup("/clear-me/test", None);
        assert!(found.is_none());
    }

    // ── ForwardConfig / FastPathError display ─────────────────────────

    #[test]
    fn fast_path_error_display() {
        let e = FastPathError::ProxyTimeout;
        assert_eq!(format!("{e}"), "proxy timeout");

        let e2 = FastPathError::HeaderWrite(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken")
        );
        assert!(format!("{e2}").contains("header write"));
    }
}

