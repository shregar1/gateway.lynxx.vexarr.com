use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::abstractions::IModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TargetLifecycle {
    #[default]
    Active,
    Draining,
    Inactive,
}

impl TargetLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Inactive => "inactive",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "draining" => Self::Draining,
            "inactive" => Self::Inactive,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Project {
    pub fn new(name: String, description: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: Uuid,
    /// Service name. Stored as `Arc<str>` so per-request clones (every
    /// proxy hot path emits this as a metric label and tracing field)
    /// are atomic refcount bumps instead of heap allocations.
    pub name: Arc<str>,
    pub url: String,
    pub retries: u32,
    pub connect_timeout_ms: u64,
    #[serde(default = "default_lb_strategy")]
    pub lb_strategy: String,
    #[serde(default = "default_service_type")]
    pub service_type: String,
    /// Filesystem root for `service_type = "static"`. Lynxx serves files
    /// directly from this directory instead of proxying to an upstream.
    #[serde(default)]
    pub document_root: Option<String>,
    #[serde(default = "default_index_file")]
    pub index_file: String,
    #[serde(default)]
    pub spa_fallback: bool,
    #[serde(default)]
    pub hide_patterns: Vec<String>,
    /// Outbound TLS verification toggle for `https://` upstreams. When
    /// `false`, the per-service hyper-util client skips certificate
    /// validation entirely. Defaults to `true` and should stay there
    /// for any production upstream.
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    /// Optional client certificate (PEM) presented by the gateway when
    /// initiating mTLS to this service. Both this and `tls_client_key_path`
    /// must be set for client auth to take effect.
    #[serde(default)]
    pub tls_client_cert_path: Option<String>,
    /// PEM-encoded private key paired with `tls_client_cert_path`.
    #[serde(default)]
    pub tls_client_key_path: Option<String>,
    /// Additional CA bundle (PEM) to trust when validating the upstream's
    /// server certificate. Useful for private/internal CAs.
    #[serde(default)]
    pub tls_ca_path: Option<String>,
    /// Request header name to hash for `header-hash` LB strategy.
    /// E.g. `"X-Tenant-Id"` — all requests with the same value land on
    /// the same upstream.
    #[serde(default)]
    pub lb_hash_header: Option<String>,
    /// Query parameter name to hash for `query-hash` LB strategy.
    /// E.g. `"user_id"` — all requests with `?user_id=42` go to the same
    /// upstream.
    #[serde(default)]
    pub lb_hash_query_param: Option<String>,
    /// Flush interval in milliseconds for chunked/streamed response
    /// forwarding. `0` = flush every chunk immediately (default). `-1` =
    /// buffer the full response before sending. Positive values flush on
    /// the given cadence.
    #[serde(default)]
    pub flush_interval_ms: Option<i64>,
    /// Overall stream timeout in milliseconds. If the entire response body
    /// is not received within this window the proxy aborts.
    #[serde(default)]
    pub stream_timeout_ms: Option<u64>,
    /// Grace period in milliseconds after the upstream closes to let
    /// in-progress writes to the client finish.
    #[serde(default)]
    pub stream_close_delay_ms: Option<u64>,
    /// When `true`, the proxy re-inserts the original client `Host` header
    /// into the upstream request instead of letting hyper derive it from the
    /// upstream URI. Useful for upstreams that perform virtual-host routing.
    #[serde(default)]
    pub pass_host_header: Option<bool>,
    /// Floor for the upstream idle-connection pool — the number of
    /// keep-alive sockets the gateway tries to keep warm for this
    /// service at all times. Matches nginx's `keepalive N` directive.
    /// When unset, the global `[gateway].pool_idle_floor_per_host`
    /// applies; when neither is set, the prewarmer treats this as
    /// "feature off" (single-HEAD heartbeat, original behaviour).
    ///
    /// The floor is independent of `[gateway].pool_max_idle_per_host`
    /// (which is the hyper-util CAP). Setting `pool_idle_floor` higher
    /// than `pool_max_idle_per_host` is harmless — hyper-util will
    /// drop the extra to the cap and our prewarmer rediscovers a new
    /// floor on the next tick.
    #[serde(default)]
    pub pool_idle_floor: Option<usize>,
    /// Force the HTTP version used on the outbound (upstream-facing)
    /// request. Accepts `"1.1"`, `"2"`, or `"auto"`. Default is `"1.1"` —
    /// hyper-util's H1 idle pool is meaningfully bigger than its H2
    /// stream pool for plaintext upstreams. Set to `"2"` to insist on
    /// h2 (cleartext h2c won't negotiate via ALPN; for h2 you need
    /// `https://` upstream). `"auto"` falls back to whatever the
    /// connector negotiates via ALPN.
    #[serde(default)]
    pub force_http_version: Option<String>,
    #[serde(default)]
    pub drain_timeout_ms: Option<u64>,
    #[serde(default)]
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub subdomain: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_service_type() -> String {
    "api".to_string()
}

fn default_index_file() -> String {
    "index.html".to_string()
}

fn default_tls_verify() -> bool {
    true
}

impl Service {
    /// Cache key fingerprint that captures every TLS-relevant field.
    /// Used by `ProxyClientPool` to invalidate cached per-service clients
    /// on update without resorting to full equality checks.
    pub fn tls_fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.tls_verify as u8,
            self.tls_client_cert_path.as_deref().unwrap_or(""),
            self.tls_client_key_path.as_deref().unwrap_or(""),
            self.tls_ca_path.as_deref().unwrap_or(""),
        )
    }
}

fn default_lb_strategy() -> String {
    "round-robin".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: Uuid,
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub service_id: Uuid,
    pub strip_path: bool,
    /// Regex-based URI rewrite: `path_rewrite_pattern` is the regex to
    /// match and `path_rewrite_replacement` is the substitution string.
    /// E.g. pattern=`^/api/v1/(.*)` replacement=`/v1/$1`.
    #[serde(default)]
    pub path_rewrite_pattern: Option<String>,
    #[serde(default)]
    pub path_rewrite_replacement: Option<String>,
    /// When true, the proxy buffers the entire request body before
    /// forwarding to the upstream. Normally bodies stream through.
    #[serde(default)]
    pub buffer_request: bool,
    /// Header-based matching: route only matches when ALL listed headers
    /// are present with matching values. Format: `{"X-Api-Version": "v2"}`.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// Query-parameter matching: route matches when ALL listed params
    /// are present with matching values. Format: `{"version": "2"}`.
    #[serde(default)]
    pub query_params: std::collections::HashMap<String, String>,
    /// Regex path patterns. When non-empty, paths are matched using
    /// these regex patterns instead of the literal `paths` field.
    /// E.g. `["^/api/v[0-9]+/users/[0-9]+$"]`.
    #[serde(default)]
    pub path_regexes: Vec<String>,
    /// Per-route read timeout in milliseconds. Overrides the global
    /// default when set. `0` = no timeout.
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,
    /// Per-route write timeout in milliseconds.
    #[serde(default)]
    pub write_timeout_ms: Option<u64>,
    /// Per-route idle timeout in milliseconds.
    #[serde(default)]
    pub idle_timeout_ms: Option<u64>,
    /// HTTP status codes that trigger a retry (e.g. `[502, 503, 504]`).
    /// Empty = retry only on connection errors (default behavior).
    #[serde(default)]
    pub retry_on_status: Vec<u16>,

    // ── Advanced matchers & directives (Caddy parity) ──
    /// Additional matchers beyond basic path/method/host. All must pass
    /// (implicit AND). Supports `remote_ip`, `client_ip`, `not`,
    /// `expression`, `header`, `query`, `path_prefix`, `path_regex`,
    /// `all`, `any`.
    #[serde(default)]
    pub matchers: Vec<crate::proxy::matchers::Matcher>,
    /// References to named matcher blocks defined in the gateway config.
    /// E.g. `["@internal", "@api_only"]`. All referenced matchers must
    /// pass for the route to match.
    #[serde(default)]
    pub matcher_refs: Vec<String>,
    /// Mutually-exclusive first-match handler groups. Evaluated in order;
    /// the first matching block wins and the rest are skipped. Implements
    /// Caddy's `handle` / `handle_path` semantics.
    #[serde(default)]
    pub handle_blocks: Vec<crate::proxy::directives::HandleBlock>,
    /// `try_files` configuration. When set, the proxy checks for file
    /// existence on disk before forwarding to the upstream, rewriting
    /// the path to the first existing file or the fallback.
    #[serde(default)]
    pub try_files: Option<crate::proxy::directives::TryFilesConfig>,
    /// URI manipulation directives applied to the request path before
    /// proxying. Supports `strip_prefix`, `strip_suffix`, `replace`,
    /// `path_escape`, and `rewrite`.
    #[serde(default)]
    pub uri_directives: Vec<crate::proxy::directives::UriDirective>,
    /// Response interception rules. Evaluated after the upstream responds.
    /// Can rewrite status, body, or headers based on the upstream response.
    #[serde(default)]
    pub intercept_rules: Vec<crate::proxy::directives::InterceptRule>,
    /// HTTP/2 server push configuration. When set, the proxy sends
    /// PUSH_PROMISE frames for the configured resources.
    #[serde(default)]
    pub push: Option<crate::proxy::h2_push::PushConfig>,
    /// Static response without upstream. When set, the route returns this
    /// response directly without proxying to any upstream. Implements
    /// Caddy's `respond` directive.
    #[serde(default)]
    pub static_response: Option<StaticResponse>,
    #[serde(default)]
    pub health_gate: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Route {
    /// Synthetic route for subdomain-routed requests that don't match any
    /// explicit route. Passes the path through unchanged.
    pub fn passthrough(service_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::nil(),
            paths: vec!["/*".into()],
            methods: Vec::new(),
            hosts: Vec::new(),
            service_id,
            strip_path: false,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            buffer_request: false,
            headers: Default::default(),
            query_params: Default::default(),
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
        }
    }
}

/// Static response configuration for the `respond` directive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticResponse {
    pub status: u16,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInstance {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub service_id: Option<Uuid>,
    #[serde(default)]
    pub route_id: Option<Uuid>,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consumer {
    pub id: Uuid,
    pub username: String,
    pub custom_id: Option<String>,
    pub api_key: Option<String>,
    /// Argon2id password hash. When set, basic-auth verifies the supplied
    /// password against this hash instead of comparing against `api_key`.
    #[serde(default)]
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: Uuid,
    pub service_id: Uuid,
    /// Target URL. Stored as `Arc<str>` because the proxy hot path clones
    /// this on every request (used as a target_label metric tag, and the
    /// load balancer's pick result carries it back to the caller). The
    /// Arc bump is ~5ns vs the ~50ns heap alloc of `String::clone()`.
    pub url: Arc<str>,
    pub weight: u32,
    pub enabled: bool,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub state: TargetLifecycle,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub id: Uuid,
    pub customer_id: i64,
    pub hardware_id: String,
    pub name: Option<String>,
    pub os_info: Option<String>,
    pub is_blocked: bool,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeGrant {
    pub id: Uuid,
    pub customer_id: i64,
    pub device_id: Option<Uuid>,
    pub token_id: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRow {
    pub id: i64,
    pub customer_id: i64,
    pub name: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
}

impl Target {
    pub fn new(service_id: Uuid, url: impl Into<Arc<str>>, weight: u32) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            service_id,
            url: url.into(),
            weight: weight.max(1),
            enabled: true,
            zone: None,
            state: TargetLifecycle::Active,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Service {
    pub fn new(
        name: impl Into<Arc<str>>,
        url: String,
        retries: u32,
        connect_timeout_ms: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            url,
            retries,
            connect_timeout_ms,
            lb_strategy: default_lb_strategy(),
            service_type: default_service_type(),
            document_root: None,
            index_file: default_index_file(),
            spa_fallback: false,
            hide_patterns: vec![],
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
        }
    }
}

impl Route {
    pub fn new(
        paths: Vec<String>,
        methods: Vec<String>,
        hosts: Vec<String>,
        service_id: Uuid,
        strip_path: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            paths,
            methods,
            hosts,
            service_id,
            strip_path,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            buffer_request: false,
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
        }
    }
}

impl Consumer {
    pub fn new(username: String, custom_id: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            custom_id,
            api_key: Some(Uuid::new_v4().to_string()),
            password_hash: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Uuid,
    pub urn: String,
    pub ts: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub service_id: Option<Uuid>,
    pub route_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<i32>,
    pub duration_ms: Option<i64>,
    pub client_ip: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Analytics ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBucket {
    pub id: Uuid,
    pub service_id: Uuid,
    pub route_id: Option<Uuid>,
    pub bucket_ts: DateTime<Utc>,
    pub granularity: String,
    pub total_requests: i64,
    pub success_count: i64,
    pub error_4xx: i64,
    pub error_5xx: i64,
    pub total_latency_ms: i64,
    pub min_latency_ms: Option<i64>,
    pub max_latency_ms: Option<i64>,
    pub bytes_in: i64,
    pub bytes_out: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoBucket {
    pub id: Uuid,
    pub service_id: Uuid,
    pub bucket_ts: DateTime<Utc>,
    pub country_code: String,
    pub city: String,
    pub request_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub id: Uuid,
    pub service_id: Uuid,
    pub consumer_id: Option<Uuid>,
    pub bucket_ts: DateTime<Utc>,
    pub allowed: i64,
    pub throttled: i64,
}

// ── Uptime Probes ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub id: Uuid,
    pub service_id: Uuid,
    pub route_id: Option<Uuid>,
    pub name: String,
    pub method: String,
    pub path: String,
    pub interval_seconds: i32,
    pub timeout_ms: i32,
    pub expected_status: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: Uuid,
    pub probe_id: Uuid,
    pub ts: DateTime<Utc>,
    pub status: Option<i32>,
    pub latency_ms: Option<i32>,
    pub healthy: bool,
    pub error: Option<String>,
}

// ── Snapshots ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: Uuid,
    pub service_id: Uuid,
    pub name: String,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

// ── Alerts ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: Uuid,
    pub service_id: Uuid,
    pub name: String,
    pub metric: String,
    pub operator: String,
    pub threshold: f64,
    pub window_seconds: i32,
    pub cooldown_seconds: i32,
    pub channels: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub service_id: Uuid,
    pub ts: DateTime<Utc>,
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
    pub message: String,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
}

// ── IP Rules ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    pub id: Uuid,
    pub service_id: Uuid,
    pub route_id: Option<Uuid>,
    pub cidr: String,
    pub action: String,
    pub description: String,
    pub priority: i32,
    pub enabled: bool,
    pub hits: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Error Pages ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPage {
    pub id: Uuid,
    pub service_id: Uuid,
    pub status_code: i32,
    pub content_type: String,
    pub body: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Cache ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub id: Uuid,
    pub service_id: Uuid,
    pub cache_key: String,
    pub content_hash: String,
    pub size_bytes: i64,
    pub ttl_seconds: i32,
    pub hits: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub service_id: Uuid,
    pub total_entries: i64,
    pub total_size_bytes: i64,
    pub hit_count: i64,
    pub miss_count: i64,
    pub hit_rate: f64,
    pub eviction_count: i64,
}

// ── Distributed Tracing ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub id: Uuid,
    pub trace_id: String,
    pub service_id: Uuid,
    pub route_id: Option<Uuid>,
    pub method: String,
    pub path: String,
    pub status: i32,
    pub duration_ms: i64,
    pub span_count: i32,
    pub has_errors: bool,
    pub metadata: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanRecord {
    pub id: Uuid,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub operation: String,
    pub service_name: String,
    pub status: String,
    pub duration_ms: i64,
    pub tags: Option<serde_json::Value>,
    pub logs: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
}

// ── Request/Response Transforms ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRule {
    pub id: Uuid,
    pub service_id: Uuid,
    pub route_id: Option<Uuid>,
    pub name: String,
    pub phase: String,
    pub action: String,
    pub target: String,
    pub value: String,
    pub condition: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── API Versioning ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    pub id: Uuid,
    pub service_id: Uuid,
    pub version: String,
    pub base_path: String,
    pub upstream_path: String,
    pub status: String,
    pub deprecated_at: Option<DateTime<Utc>>,
    pub sunset_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Incidents ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub service_id: Uuid,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub description: String,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentUpdate {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub status: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
}

// ── Webhooks ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Uuid,
    pub service_id: Uuid,
    pub name: String,
    pub url: String,
    pub events: serde_json::Value,
    pub secret: Option<String>,
    pub enabled: bool,
    pub retry_count: i32,
    pub timeout_ms: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub response_status: Option<i32>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempts: i32,
    pub delivered_at: DateTime<Utc>,
}

// ── Load Testing ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTest {
    pub id: Uuid,
    pub service_id: Uuid,
    pub name: String,
    pub target_rps: i32,
    pub duration_seconds: i32,
    pub concurrent_users: i32,
    pub method: String,
    pub path: String,
    pub headers: Option<serde_json::Value>,
    pub body: Option<String>,
    pub status: String,
    pub result: Option<serde_json::Value>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Plugin Marketplace ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlugin {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub category: String,
    pub schema: serde_json::Value,
    pub readme: String,
    pub downloads: i64,
    pub rating: f64,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Cost Analytics ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecord {
    pub id: Uuid,
    pub service_id: Uuid,
    pub bucket_ts: DateTime<Utc>,
    pub compute_cost: f64,
    pub bandwidth_cost: f64,
    pub storage_cost: f64,
    pub total_cost: f64,
    pub currency: String,
    pub requests: i64,
    pub bytes_transferred: i64,
}

// ── Cluster Management ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: i32,
    pub role: String,
    pub status: String,
    pub version: String,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub active_connections: i64,
    pub last_heartbeat: DateTime<Utc>,
    pub joined_at: DateTime<Utc>,
}

// ── Rate Limit Simulator ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSimulation {
    pub id: Uuid,
    pub service_id: Uuid,
    pub consumer_id: Option<Uuid>,
    pub requests_per_second: i32,
    pub duration_seconds: i32,
    pub limit: i32,
    pub window_seconds: i32,
    pub burst: i32,
    pub result: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

// ── PKI / Certificates ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    pub service_id: Option<Uuid>,
    pub domain: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
    pub auto_renew: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Consumer Groups ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerGroup {
    pub id: Uuid,
    pub service_id: Uuid,
    pub name: String,
    pub description: String,
    pub rate_limit: i32,
    pub rate_window_seconds: i32,
    pub burst_limit: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerGroupMember {
    pub group_id: Uuid,
    pub consumer_id: Uuid,
    pub joined_at: DateTime<Utc>,
}

// ── IModel implementations ──

impl IModel for Project {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Service {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Route {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for PluginInstance {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Consumer {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Target {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for LogEntry {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Probe {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Snapshot {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for AlertRule {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for IpRule {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for ErrorPage {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for CacheEntry {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for TransformRule {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for ApiVersion {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Incident {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for IncidentUpdate {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Webhook {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for LoadTest {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for MarketplacePlugin {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for RateLimitSimulation {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for Certificate {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl IModel for ConsumerGroup {
    fn id(&self) -> Uuid {
        self.id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}
