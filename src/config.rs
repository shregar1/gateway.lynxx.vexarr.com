use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GatewayConfig {
    #[serde(default = "default_gateway")]
    pub gateway: GatewaySettings,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    /// Subscription licence — required at startup. Set the `token` here
    /// or via the `LYNXX_LICENSE` env var. Without a valid token the
    /// gateway refuses to start. See `src/license/mod.rs`.
    #[serde(default)]
    pub license: LicenseSettings,
    /// keyx integration. When populated alongside a signed `[license]`
    /// bundle, licence verification routes through keyx instead of the
    /// legacy billing endpoint.
    #[serde(default)]
    pub keyx: KeyxSettings,
    /// OpenTelemetry export. Env vars `LYNXX_TELEMETRY_URL` and
    /// `LYNXX_TELEMETRY_API_KEY` override the TOML values.
    #[serde(default)]
    pub telemetry: TelemetrySettings,
    /// Named matchers (`@name`) that can be referenced by routes.
    /// Equivalent to Caddy's `@name` matcher blocks.
    #[serde(default)]
    pub named_matchers: Vec<crate::proxy::matchers::NamedMatcher>,
    /// Named reusable config snippets. Define a block once under
    /// `[snippets.<name>]` and reference it via `import = "<name>"`.
    /// When an import value matches a snippet name (rather than a file
    /// path), the snippet is inlined at the import site.
    #[serde(default)]
    pub snippets: HashMap<String, serde_json::Value>,
    /// Directive execution order. Plugins are evaluated in this order;
    /// plugins not listed run after all listed ones in their natural
    /// (creation) order. Mirrors Caddy's `order` global option.
    #[serde(default)]
    pub order: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LicenseSettings {
    /// DEPRECATED, unused. Was the API key for the retired
    /// `/v1/license/verify` billing endpoint. Field kept (with
    /// `#[serde(default)]`) so existing config.toml files don't fail
    /// to parse; ignored at runtime. Licence verification is now
    /// keyx-only — see `[keyx]` + `payload` / `signature` below.
    #[serde(default)]
    pub api_key: String,
    /// Base64-encoded JSON licence payload (used with keyx). The JSON
    /// schema matches the legacy `VerifyResponse` (customer_urn, tier,
    /// expires_at, max_nodes, monthly_call_limit, allow_overage).
    #[serde(default)]
    pub payload: String,
    /// Ed25519 signature over `payload`, produced by keyx
    /// `POST /v1/keys/{urn}/sign-license`. Base64-encoded.
    #[serde(default)]
    pub signature: String,
}

/// Settings for the keyx integration (api.keyx.vexarr.com).
///
/// Every field is overridable from the environment:
///   * `KEYX_BASE_URL`       → `base_url`
///   * `KEYX_SERVICE_TOKEN`  → `service_token`
///   * `KEYX_LICENSE_URN`    → `license_urn`
///
/// Tenant isn't a separate field: keyx resolves the owning tenant
/// from the licence URN itself on URN-routed endpoints.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct KeyxSettings {
    /// Root URL of the keyx API, e.g. `https://api.keyx.vexarr.com`.
    #[serde(default)]
    pub base_url: String,
    /// Bearer token issued to this lynxx node for calling keyx.
    /// Treated as a secret — keep it in env, not TOML.
    #[serde(default)]
    pub service_token: String,
    /// URN of the keyx signing key that issued this gateway's licence.
    #[serde(default)]
    pub license_urn: String,
    /// Seconds to cache the result of a keyx `/v1/keys/validate` call
    /// for an admin-API token. `0` (default) hits keyx on every admin
    /// request — instant revocation, more network. Setting to e.g.
    /// `60` smooths bursts (`/status` polling, dashboards) and caps the
    /// staleness of a revoked token at the TTL. When keyx grows
    /// real-time revocation events (M4), this can be raised
    /// aggressively without trading off staleness.
    #[serde(default)]
    pub admin_cache_ttl_secs: u64,
}

impl KeyxSettings {
    /// True once every field the keyx client needs is populated.
    pub fn is_configured(&self) -> bool {
        !self.base_url.trim().is_empty()
            && !self.service_token.trim().is_empty()
            && !self.license_urn.trim().is_empty()
    }

    /// Names of the keyx-related env vars whose values are empty/missing.
    /// Used by the boot-time preflight to give operators a precise list
    /// of what to set rather than a generic "not configured" error.
    pub fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.base_url.trim().is_empty() {
            missing.push("KEYX_BASE_URL");
        }
        if self.service_token.trim().is_empty() {
            missing.push("KEYX_SERVICE_TOKEN");
        }
        if self.license_urn.trim().is_empty() {
            missing.push("KEYX_LICENSE_URN");
        }
        missing
    }
}

/// Pre-flight check for the keyx integration. Mirrors userx's
/// `check_mode_consistency`: fail fast at boot rather than surfacing a
/// misconfiguration on the first admin request hours later.
///
/// Two failure modes:
///
///   * **partial config** — at least one keyx field is set but not all
///     three. This is almost always a typo or a half-applied env file.
///     We can't tell which side is correct, so we error.
///   * **integrated mode without keyx** — `VEXARR_MODE=integrated` is set
///     but no keyx URL is configured. Integrated mode implies a real
///     keyx is reachable; if it isn't, admin auth and licence verify
///     will both 500 on first use. Fail at boot instead.
///
/// Pure proxy deployments (no admin API exposed, no licence verification
/// required) can leave `[keyx]` unset entirely — this returns Ok(()) in
/// that case.
pub fn check_keyx_consistency(keyx: &KeyxSettings, mode_value: Option<&str>) -> anyhow::Result<()> {
    let is_integrated = matches!(mode_value, Some(v) if v.eq_ignore_ascii_case("integrated"));
    let missing = keyx.missing_fields();
    let any_set = missing.len() < 3;

    if is_integrated && !missing.is_empty() {
        anyhow::bail!(
            "VEXARR_MODE=integrated but keyx is not fully configured. Missing: {}. \
             Set these (or the legacy KEYX_BASE_URL / KEYX_SERVICE_TOKEN / KEYX_LICENSE_URN), \
             or unset VEXARR_MODE to run lynxx in pure-proxy mode without keyx.",
            missing.join(", ")
        );
    }

    if any_set && !missing.is_empty() {
        anyhow::bail!(
            "keyx integration is partially configured — missing: {}. Either set all three keyx \
             fields (admin auth + licence verification both require them) or clear the partial \
             values to disable the integration entirely.",
            missing.join(", ")
        );
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TelemetrySettings {
    /// OTLP endpoint URL (e.g. `http://localhost:4318`).
    /// Env override: `LYNXX_TELEMETRY_URL` or `OTEL_EXPORTER_OTLP_ENDPOINT`.
    #[serde(default)]
    pub endpoint: String,
    /// API key / bearer token sent as `Authorization` header on OTLP exports.
    /// Env override: `LYNXX_TELEMETRY_API_KEY`.
    #[serde(default)]
    pub api_key: String,
    /// Logical service name embedded in every span. Defaults to `lynxx-gateway`.
    /// Env override: `OTEL_SERVICE_NAME`.
    #[serde(default = "default_telemetry_service_name")]
    pub service_name: String,
    /// Optional secondary endpoint (e.g. Fluxx sidecar). When set, spans
    /// are exported to both endpoints.
    /// Env override: `FLUXX_OTEL_ENDPOINT`.
    #[serde(default)]
    pub fluxx_endpoint: String,
}

fn default_telemetry_service_name() -> String {
    "lynxx-gateway".into()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GatewaySettings {
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,

    /// When true, the gateway will fail immediately if the configured port
    /// is unavailable instead of retrying or falling back to an OS-assigned
    /// port. Default: false (self-healing mode).
    #[serde(default)]
    pub strict_port: bool,
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default)]
    pub seed_from_config: bool,
    #[serde(default = "default_hc_interval")]
    pub health_check_interval_ms: u64,
    #[serde(default = "default_hc_failure_threshold")]
    pub health_circuit_failure_threshold: u32,
    #[serde(default = "default_hc_success_threshold")]
    pub health_circuit_success_threshold: u32,
    #[serde(default = "default_hc_open_duration")]
    pub health_circuit_open_duration_ms: u64,

    /// Inbound TLS termination for the proxy listener. Off by default;
    /// when enabled the proxy listener serves HTTPS via axum-server +
    /// rustls. See [`TlsSettings`].
    #[serde(default)]
    pub tls: TlsSettings,

    /// ACME / automatic certificate provisioning. When enabled, the
    /// gateway manages its own TLS certificates — loading from disk,
    /// generating self-signed certs for dev, serving HTTP-01 +
    /// TLS-ALPN-01 challenges, and hot-reloading on renewal. See
    /// [`AcmeConfig`].
    #[serde(default)]
    pub acme: AcmeConfig,

    /// External service-discovery providers (Docker today, Kubernetes
    /// next). Each provider is a no-op until its `enabled` flag is
    /// flipped. The Docker provider watches the Docker socket and
    /// registers services + routes from container labels; see
    /// `crate::discovery::docker`.
    #[serde(default)]
    pub providers: ProvidersConfig,

    /// Background connection pre-warmer interval in seconds. `0` disables
    /// pre-warming. Pre-warm respects circuit-breaker state — services
    /// whose circuit is `Open` are skipped.
    #[serde(default = "default_prewarm_interval")]
    pub prewarm_interval_secs: u64,

    /// Maximum number of concurrent pre-warm requests. Capped to avoid
    /// thundering-herd against many upstreams at once.
    #[serde(default = "default_prewarm_concurrency")]
    pub prewarm_concurrency: usize,

    /// When true, admin API requests must always present a valid token
    /// (no bootstrap mode). Defaults to false: bootstrap mode is allowed
    /// while `admin_tokens` is empty, and auth turns on automatically as
    /// soon as any token exists.
    #[serde(default)]
    pub auth_required: bool,

    /// When true, the proxy's per-request telemetry (prometheus counter +
    /// histogram emission and the access-log write) is skipped on the
    /// success path. Off by default.
    ///
    /// Useful for raw-throughput benchmarks against bare-bones gateways
    /// (HAProxy, NGINX) where the comparison would otherwise be unfair —
    /// those gateways emit zero telemetry per request by default. The
    /// observed delta is ~13% RPS on a 4-core box; not recommended for
    /// production unless you've replaced the dropped signals with a
    /// sampling collector at a higher level.
    ///
    /// Env override: `LYNXX_MINIMAL_TELEMETRY=1` (or legacy `LYNXX_BENCH_MODE=1`).
    #[serde(default)]
    pub minimal_telemetry: bool,

    /// Filesystem root for the request-recorder content-addressed store
    /// and the place the admin recording API loads recordings from. When
    /// `None`, the runtime resolves to `~/.lynxx/recordings` (or
    /// `/var/lib/lynxx/recordings` if no home dir is available).
    #[serde(default)]
    pub recordings_directory: Option<String>,

    /// Licence tier that determines the monthly API call quota.
    /// Accepted values: `"free"` (1 M), `"pro"` (10 M), `"business"` (∞),
    /// `"enterprise"` (∞). Defaults to `"free"` when not set.
    #[serde(default = "default_plan_tier")]
    pub plan_tier: String,

    /// Maximum number of idle connections per upstream host.
    /// Default: 128.
    #[serde(default = "default_pool_max_idle")]
    pub pool_max_idle_per_host: usize,
    /// Idle connection timeout in seconds. Default: 120.
    #[serde(default = "default_pool_idle_timeout")]
    pub pool_idle_timeout_secs: u64,
    /// HTTP/2 keepalive ping interval in seconds. Default: 10.
    #[serde(default = "default_h2_keepalive")]
    pub h2_keepalive_interval_secs: u64,
    /// Maximum request header size in bytes. Default: 16384 (16 KB).
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,

    /// Local zone/region identifier for locality-aware load balancing.
    /// When set, the load balancer prioritizes targets in the same zone.
    #[serde(default)]
    pub local_zone: Option<String>,

    /// CIDR ranges of trusted reverse proxies. When set, the gateway
    /// only honours `X-Forwarded-For` / `X-Real-IP` headers from source
    /// IPs matching one of these ranges. Connections from untrusted
    /// sources use the socket peer address instead.
    /// Example: `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]`
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Admin API TLS. When enabled, the admin port serves HTTPS and
    /// optionally requires client certs for mTLS authentication.
    #[serde(default)]
    pub admin_tls: AdminTlsConfig,

    /// Built-in PKI / internal Certificate Authority. When enabled, the
    /// gateway can issue certificates for internal services.
    #[serde(default)]
    pub pki: PkiConfig,

    /// Certificate storage backend for clustered deployments. Controls
    /// where ACME certs, OCSP responses, and STEK keys are persisted.
    /// Defaults to `"file"` (local disk). Use `"redis"` or `"postgres"`
    /// to share state across multiple gateway nodes.
    #[serde(default)]
    pub cert_store: CertStoreConfig,

    /// Delay in seconds before the server starts draining after
    /// receiving a shutdown signal. During this window the server
    /// continues accepting new connections normally so upstream
    /// load balancers can detect the pending shutdown via failing
    /// health checks. Default: 0 (drain immediately).
    #[serde(default)]
    pub shutdown_delay_secs: u64,

    /// Maximum time in seconds to wait for in-flight requests to
    /// complete after the shutdown delay. Connections still active
    /// after this grace period are forcibly closed. Default: 30.
    #[serde(default = "default_grace_period")]
    pub grace_period_secs: u64,

    /// Automatic HTTPS behaviour. Controls HTTP→HTTPS redirects and
    /// automatic certificate management.
    /// - `"on"` (default): enable both redirects and automatic certs
    /// - `"off"`: disable automatic HTTPS entirely
    /// - `"disable_redirects"`: keep auto certs but skip HTTP→HTTPS redirects
    /// - `"disable_certs"`: keep redirects but skip auto cert management
    #[serde(default = "default_auto_https")]
    pub auto_https: String,

    /// Shorthand alias for `cert_store.backend`. When set, overrides the
    /// cert store backend selection. Accepted values: `"file"` (default),
    /// `"redis"`, `"postgres"`.
    #[serde(default = "default_storage_backend")]
    pub storage_backend: String,

    /// Interval in seconds between automatic cleanup runs for expired
    /// or stale certificate data in the storage backend. Default: 86400
    /// (24 hours).
    #[serde(default = "default_storage_clean_interval")]
    pub storage_clean_interval_secs: u64,

    /// TCP keepalive idle time in seconds. The connection must be idle
    /// for this long before keepalive probes start. Default: 60.
    #[serde(default = "default_keepalive_idle")]
    pub keepalive_idle_secs: u64,

    /// Interval in seconds between TCP keepalive probes. Default: 15.
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,

    /// Number of unacknowledged TCP keepalive probes before the
    /// connection is dropped. Default: 3.
    #[serde(default = "default_keepalive_count")]
    pub keepalive_count: u32,

    /// Network address to bind the proxy listener to. Default: `"0.0.0.0"`.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Persist the running config to disk on changes. Default: `true`.
    #[serde(default = "default_true_bool")]
    pub persist_config: bool,

    /// Health/unhealthy webhook event notifications.
    #[serde(default)]
    pub events: EventsConfig,

    /// When true, don't redact auth headers in access logs. Default: false.
    #[serde(default)]
    pub log_credentials: bool,

    /// When true, enable full-duplex (simultaneous read/write) on
    /// proxy connections. Default: false.
    #[serde(default)]
    pub enable_full_duplex: bool,

    /// When true, log each invoked handler for debugging. Default: false.
    #[serde(default)]
    pub trace_handlers: bool,

    /// When true, parse X-Forwarded-For right-to-left (strict mode).
    /// Default: false.
    #[serde(default)]
    pub trusted_proxies_strict: bool,

    /// Custom headers to read the client IP from. When empty, the
    /// standard X-Forwarded-For header is used. Default: empty.
    #[serde(default)]
    pub client_ip_headers: Vec<String>,

    /// Named filesystem mappings. Maps logical names to root paths.
    /// Used by the file server and file matcher. Default: empty.
    #[serde(default)]
    pub filesystems: HashMap<String, String>,

    /// TCP L4 routing configuration.
    #[serde(default)]
    pub tcp: TcpConfig,
    /// UDP L4 routing configuration.
    #[serde(default)]
    pub udp: UdpConfig,

    /// When true, apply Linux sysctl tuning (TCP buffers, fd limits,
    /// backlog, TIME_WAIT) at startup for high-throughput proxy workloads.
    /// No-op on non-Linux. Default: true.
    #[serde(default = "default_true_bool")]
    pub auto_tune_kernel: bool,

    #[serde(default = "default_drain_timeout")]
    pub default_drain_timeout_ms: u64,
    #[serde(default = "default_deploy_hc_interval")]
    pub deploy_health_check_interval_ms: u64,
    #[serde(default = "default_deploy_hc_timeout")]
    pub deploy_health_check_timeout_ms: u64,
    #[serde(default = "default_deploy_hc_threshold")]
    pub deploy_health_check_threshold: u32,
}

/// Webhook URLs called on upstream health transitions.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct EventsConfig {
    /// URLs to POST when an upstream becomes healthy.
    #[serde(default)]
    pub on_healthy: Vec<String>,
    /// URLs to POST when an upstream becomes unhealthy.
    #[serde(default)]
    pub on_unhealthy: Vec<String>,
}

/// Built-in PKI configuration. When `enabled = true` the gateway
/// generates an internal root + intermediate CA on first start and
/// can issue leaf certificates for internal services — similar to
/// Caddy's built-in ACME server or Vault's PKI secrets engine.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PkiConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Where to store the CA keypairs. Defaults to `~/.lynxx/pki/`.
    #[serde(default)]
    pub storage_dir: String,
    /// Root CA common name.
    #[serde(default = "default_pki_cn")]
    pub root_cn: String,
    /// Default cert validity in days for issued leaf certs.
    #[serde(default = "default_pki_validity")]
    pub default_validity_days: u32,
}

impl Default for PkiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_dir: String::new(),
            root_cn: default_pki_cn(),
            default_validity_days: default_pki_validity(),
        }
    }
}

/// Certificate storage backend configuration. In single-node deployments
/// the default `"file"` backend reads/writes cert material to local disk.
/// Multi-node clusters should use `"redis"` or `"postgres"` so all nodes
/// share ACME certificates, OCSP staples, and STEK rotation keys.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertStoreConfig {
    /// Backend type: `"file"` (default), `"redis"`, `"postgres"`.
    #[serde(default = "default_cert_store_backend")]
    pub backend: String,
    /// Redis URL (only used when `backend = "redis"`).
    /// Example: `redis://127.0.0.1:6379/1`
    #[serde(default)]
    pub redis_url: String,
    /// Directory for the file backend. When empty, falls back to the ACME
    /// `storage_dir` or `~/.lynxx/certs/`.
    #[serde(default)]
    pub file_dir: String,
}

impl Default for CertStoreConfig {
    fn default() -> Self {
        Self {
            backend: default_cert_store_backend(),
            redis_url: String::new(),
            file_dir: String::new(),
        }
    }
}

fn default_cert_store_backend() -> String {
    "file".to_string()
}

fn default_pki_cn() -> String {
    "Lynxx Internal CA".to_string()
}

fn default_pki_validity() -> u32 {
    90
}

/// ACME / automatic certificate provisioning settings. When
/// `enabled = true` the gateway manages its own TLS certificates:
///
/// * On startup, looks for `cert.pem` + `key.pem` in
///   `{storage_dir}/{primary_domain}/`.
/// * If `self_signed = true` and no cert exists, generates a self-signed
///   cert (useful for development / local testing).
/// * Serves `/.well-known/acme-challenge/{token}` responses so external
///   ACME clients (certbot, acme.sh) can complete HTTP-01 validation.
/// * Polls cert files every 30 seconds and hot-reloads the TLS config
///   when they change on disk — no restart needed after renewal.
///
/// `acme` and `tls` are complementary: `tls` provides static cert paths
/// and mTLS knobs, while `acme` adds automatic provisioning. When both
/// are enabled, `acme` takes precedence for the server certificate.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Domain names for the certificate. The first entry becomes the CN;
    /// all entries are added as Subject Alternative Names. Required when
    /// `enabled = true`.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Contact email for the ACME account (e.g. Let's Encrypt). Not
    /// used for self-signed certs but stored for future ACME flows.
    #[serde(default)]
    pub email: String,
    /// ACME directory URL. Defaults to Let's Encrypt production.
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    /// Where to store certs and account keys. Defaults to
    /// `~/.lynxx/acme/`.
    #[serde(default)]
    pub storage_dir: String,
    /// Generate a self-signed certificate on startup when no cert exists
    /// on disk. Intended for development / local testing. Defaults to
    /// `false`.
    #[serde(default)]
    pub self_signed: bool,
    /// When ACME is enabled, also bind a plain HTTP listener on this port
    /// for HTTP-01 challenges and HTTP→HTTPS redirects. Defaults to `80`.
    /// Set to `0` to disable the HTTP listener.
    #[serde(default = "default_acme_http_port")]
    pub http_port: u16,
    /// The external HTTPS port visible to clients, used in HTTP→HTTPS
    /// redirects. Defaults to `443`. Set this when the gateway runs
    /// behind Docker port mapping (e.g. host 443 → container 8443).
    #[serde(default = "default_acme_external_port")]
    pub external_https_port: u16,

    /// ACME challenge type: `"http-01"`, `"tls-alpn-01"`, or `"auto"`.
    /// `auto` tries TLS-ALPN-01 first and falls back to HTTP-01.
    /// Defaults to `"auto"`.
    #[serde(default = "default_acme_challenge_type")]
    pub challenge_type: String,

    /// Fallback ACME directory URLs. If the primary `directory_url` fails,
    /// each fallback is tried in order. Defaults to ZeroSSL.
    #[serde(default = "default_acme_fallback_urls")]
    pub fallback_directory_urls: Vec<String>,

    /// On-Demand TLS: provision certificates during the TLS handshake
    /// for previously-unknown domains. When enabled, a TLS connection
    /// for an uncached domain triggers a background ACME order while a
    /// temporary self-signed cert is served for the initial handshake.
    #[serde(default)]
    pub on_demand: OnDemandTlsConfig,

    /// DNS-01 challenge provider. When configured, the gateway can
    /// complete DNS-01 challenges for wildcard certs or when ports
    /// 80/443 are not reachable.
    #[serde(default)]
    pub dns01: Dns01Config,

    /// External Account Binding (EAB) credentials. Required by some
    /// commercial CAs (ZeroSSL, BuyPass, Google Trust Services).
    #[serde(default)]
    pub eab_kid: String,
    /// HMAC key for EAB, base64url-encoded.
    #[serde(default)]
    pub eab_hmac_key: String,
    /// Key type for ACME certificate issuance. Accepted values:
    /// `"ec-p256"` (default), `"ec-p384"`, `"ed25519"`, `"rsa-2048"`,
    /// `"rsa-4096"`. Controls the key algorithm used in CSR generation
    /// and the resulting certificate.
    #[serde(default = "default_acme_key_type")]
    pub key_type: String,

    /// Fraction of cert lifetime before expiry at which renewal starts.
    /// For a 90-day cert with ratio 0.3333, renewal starts ~30 days
    /// before expiry. Default: 0.3333.
    #[serde(default = "default_renewal_window_ratio")]
    pub renewal_window_ratio: f64,

    /// Desired certificate lifetime in days. Default: 90.
    #[serde(default = "default_cert_lifetime_days")]
    pub cert_lifetime_days: u32,

    /// How often (in seconds) to check whether certificates need
    /// renewal. Default: 43200 (12 hours).
    #[serde(default = "default_renew_interval")]
    pub renew_interval_secs: u64,

    /// When `true`, certificate renewals reuse the existing private key
    /// instead of generating a fresh one. Reduces HPKP / pin rotation
    /// churn. Defaults to `false`.
    #[serde(default)]
    pub reuse_private_keys: bool,

    /// Preferred certificate chain issuer CN. When non-empty, the
    /// gateway checks whether the downloaded chain's issuer contains
    /// this string (e.g. `"ISRG Root X1"`). If the chain doesn't
    /// match, a warning is logged. Forward-compatible: when the ACME
    /// API supports alternate chains, the gateway will select the
    /// matching one automatically. Defaults to `""` (accept any chain).
    #[serde(default)]
    pub preferred_chain: String,
}

/// On-Demand TLS settings. When enabled, the gateway provisions ACME
/// certificates dynamically during the TLS handshake for domains it
/// doesn't already have a cert for. A temporary self-signed cert is
/// returned for the first connection while the real cert is obtained.
///
/// To prevent abuse (attackers flooding with random domains to exhaust
/// ACME rate limits), configure `allowed_domains` or `ask_url`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OnDemandTlsConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Optional list of allowed domains. Empty = allow all.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Optional HTTP endpoint to validate domain before issuing.
    /// `GET {ask_url}?domain={domain}` -- 200 = allow, anything else = deny.
    #[serde(default)]
    pub ask_url: String,
    /// Max certificates to issue per minute (rate limit).
    #[serde(default = "default_on_demand_rate")]
    pub max_certs_per_minute: u32,
}

impl Default for OnDemandTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_domains: Vec::new(),
            ask_url: String::new(),
            max_certs_per_minute: default_on_demand_rate(),
        }
    }
}

fn default_on_demand_rate() -> u32 {
    10
}

/// DNS-01 ACME challenge provider configuration. Supports Cloudflare
/// and Route53. When configured, `challenge_type` should include
/// `"dns-01"` or `"auto"`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Dns01Config {
    /// Provider name: `"cloudflare"` or `"route53"`.
    #[serde(default)]
    pub provider: String,
    /// Cloudflare API token with Zone:DNS:Edit permission.
    #[serde(default)]
    pub api_token: String,
    /// Cloudflare Zone ID.
    #[serde(default)]
    pub zone_id: String,
    /// Route53 hosted zone ID.
    #[serde(default)]
    pub hosted_zone_id: String,
    /// AWS region (defaults to `us-east-1`). Also reads `AWS_REGION`.
    #[serde(default)]
    pub region: String,
    /// AWS access key ID. Also reads `AWS_ACCESS_KEY_ID`.
    #[serde(default)]
    pub access_key_id: String,
    /// AWS secret access key. Also reads `AWS_SECRET_ACCESS_KEY`.
    #[serde(default)]
    pub secret_access_key: String,
    /// Seconds to wait for DNS propagation. Default 120.
    #[serde(default = "default_dns_propagation_timeout")]
    pub propagation_timeout_secs: u64,

    /// Override domain for DNS-01 challenge TXT records. When set,
    /// the `_acme-challenge` TXT record is created under this domain
    /// instead of the certificate domain. Useful for CNAME delegation
    /// setups. Empty (default) means use the certificate domain.
    #[serde(default)]
    pub dns_challenge_override_domain: String,

    /// Delay in seconds to wait after creating the DNS TXT record
    /// before asking the ACME server to validate. Gives DNS caches
    /// time to clear. Default: 0 (no extra delay).
    #[serde(default)]
    pub propagation_delay_secs: u64,
}

impl Default for Dns01Config {
    fn default() -> Self {
        Self {
            provider: String::new(),
            api_token: String::new(),
            zone_id: String::new(),
            hosted_zone_id: String::new(),
            region: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            propagation_timeout_secs: default_dns_propagation_timeout(),
            dns_challenge_override_domain: String::new(),
            propagation_delay_secs: 0,
        }
    }
}

fn default_dns_propagation_timeout() -> u64 {
    // Must exceed typical SOA negative-cache TTL (300s) to avoid
    // failing on freshly created records whose absence was cached.
    360
}

/// Admin API TLS settings. When enabled, the admin port serves HTTPS
/// and optionally requires client certs (mTLS) for authentication.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AdminTlsConfig {
    /// Enable TLS on the admin listener.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the admin server certificate PEM.
    #[serde(default)]
    pub cert_path: String,
    /// Path to the admin server private key PEM.
    #[serde(default)]
    pub key_path: String,
    /// Path to the CA bundle for client certificate verification.
    /// When set, only clients presenting a cert signed by this CA
    /// can access the admin API (mutual TLS).
    #[serde(default)]
    pub client_ca_path: String,
    /// Require client certs (true) or make them optional (false).
    #[serde(default)]
    pub client_cert_required: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            email: String::new(),
            directory_url: default_acme_directory_url(),
            storage_dir: String::new(),
            self_signed: false,
            http_port: default_acme_http_port(),
            external_https_port: default_acme_external_port(),
            challenge_type: default_acme_challenge_type(),
            fallback_directory_urls: default_acme_fallback_urls(),
            on_demand: OnDemandTlsConfig::default(),
            dns01: Dns01Config::default(),
            eab_kid: String::new(),
            eab_hmac_key: String::new(),
            key_type: default_acme_key_type(),
            renewal_window_ratio: default_renewal_window_ratio(),
            cert_lifetime_days: default_cert_lifetime_days(),
            renew_interval_secs: default_renew_interval(),
            reuse_private_keys: false,
            preferred_chain: String::new(),
        }
    }
}

fn default_acme_http_port() -> u16 {
    80
}

fn default_acme_external_port() -> u16 {
    443
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_challenge_type() -> String {
    "auto".to_string()
}

fn default_acme_key_type() -> String {
    "ec-p256".to_string()
}

fn default_acme_fallback_urls() -> Vec<String> {
    vec!["https://acme.zerossl.com/v2/DV90".to_string()]
}

fn default_renewal_window_ratio() -> f64 {
    0.3333
}

fn default_cert_lifetime_days() -> u32 {
    90
}

fn default_renew_interval() -> u64 {
    43200
}

/// External service-discovery providers.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProvidersConfig {
    #[serde(default)]
    pub docker: crate::discovery::docker::DockerProviderConfig,
    /// SRV/A DNS-based dynamic upstream discovery. Polls DNS SRV records
    /// and reconciles the discovered hosts as targets for the referenced
    /// service, adding new ones and removing stale ones automatically.
    #[serde(default)]
    pub srv_dns: crate::discovery::srv_dns::SrvDnsProviderConfig,
    #[serde(default)]
    pub consul: crate::discovery::consul::ConsulProviderConfig,
    #[serde(default)]
    pub nomad: crate::discovery::nomad::NomadProviderConfig,
    #[serde(default)]
    pub etcd: crate::discovery::etcd::EtcdProviderConfig,
    #[serde(default)]
    pub redis_kv: crate::discovery::redis_kv::RedisKvProviderConfig,
    #[serde(default)]
    pub zookeeper: crate::discovery::zookeeper::ZooKeeperProviderConfig,
    #[serde(default)]
    pub ecs: crate::discovery::ecs::EcsProviderConfig,
    #[serde(default)]
    pub http: crate::discovery::http_provider::HttpProviderConfig,
    #[serde(default)]
    pub docker_swarm: crate::discovery::docker_swarm::DockerSwarmProviderConfig,
}

/// Inbound TLS termination knobs. When `enabled = false` (the default)
/// the proxy port serves plain HTTP exactly as before. When set, the
/// listener binds via `axum_server::bind_rustls` using the provided
/// cert/key. If `client_ca_path` is non-empty the gateway additionally
/// performs mTLS — incoming connections must present a client cert that
/// chains to the configured CA.
///
/// `client_cert_required` toggles between optional and required client
/// auth: with `optional`, the connection is accepted either way and any
/// presented cert is verified; with `required`, the handshake fails if
/// no client cert is sent.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
    /// Optional. If set, mTLS is enabled — client certs are verified
    /// against this CA bundle (PEM).
    #[serde(default)]
    pub client_ca_path: String,
    /// `false` (default) = optional client auth; `true` = required.
    /// Only meaningful when `client_ca_path` is set.
    #[serde(default)]
    pub client_cert_required: bool,
    /// Minimum TLS version. Defaults to `"1.2"`. Accepted: `"1.2"`, `"1.3"`.
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
    /// Maximum TLS version. Defaults to `"1.3"`.
    #[serde(default = "default_tls_max_version")]
    pub max_version: String,
    /// Named groups / curves for key exchange. Defaults to all supported
    /// by the ring provider: `["x25519", "secp256r1", "secp384r1"]`.
    ///
    /// Post-quantum key exchange (`x25519mlkem768`) requires switching to
    /// the `aws-lc-rs` crypto provider in a future release.
    #[serde(default)]
    pub curves: Vec<String>,
    /// Explicit cipher suite selection. When non-empty, only the listed
    /// suites are offered. Names follow the IANA registry (e.g.
    /// `"TLS13_AES_256_GCM_SHA384"`, `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`).
    /// Empty = use rustls defaults (recommended).
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    /// Path to write TLS pre-master secrets for Wireshark decryption.
    /// Same semantics as `SSLKEYLOGFILE` env var. When set, every TLS
    /// session's keys are appended to this file (NSS key log format).
    /// **Security warning:** never use in production.
    #[serde(default)]
    pub sslkeylogfile: String,
    /// Enable PROXY protocol v1/v2 on the proxy listener. When true,
    /// the gateway expects every inbound TCP connection to start with a
    /// PROXY protocol header. Required for AWS NLB, HAProxy, etc.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Base64-encoded ECH (Encrypted ClientHello) config list. When
    /// non-empty the gateway stores the decoded config for future use.
    /// Server-side ECH is not yet supported by rustls — a warning is
    /// logged at startup when this field is set.
    #[serde(default)]
    pub ech_config_list: String,
    /// Enable TLS 1.3 0-RTT (early data) acceptance. When true *and*
    /// max_version includes TLS 1.3, the server advertises support for
    /// up to 16 KB of early data. **Warning:** 0-RTT data is susceptible
    /// to replay attacks — only enable when upstream endpoints are
    /// idempotent or replay-safe.
    #[serde(default)]
    pub enable_0rtt: bool,
    /// Crypto provider backend. Defaults to `"ring"`. Set to
    /// `"aws-lc-rs"` to unlock post-quantum key exchange
    /// (`x25519mlkem768`). Requires the `aws-lc-rs` cargo feature.
    #[serde(default = "default_crypto_provider")]
    pub crypto_provider: String,

    /// Default SNI value. When a client connects without an SNI
    /// extension, this hostname is used for certificate selection.
    /// Empty (default) means no default SNI is assumed.
    #[serde(default)]
    pub default_sni: String,

    /// Fallback SNI value. When the SNI presented by the client does
    /// not match any configured certificate, the gateway falls back
    /// to this hostname for certificate selection. Empty (default)
    /// means no fallback.
    #[serde(default)]
    pub fallback_sni: String,

    /// When true, the gateway requires that the TLS SNI hostname
    /// matches the HTTP Host header. Connections where they differ
    /// are rejected. Default: false.
    #[serde(default)]
    pub strict_sni_host: bool,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            client_ca_path: String::new(),
            client_cert_required: false,
            min_version: default_tls_min_version(),
            max_version: default_tls_max_version(),
            curves: Vec::new(),
            cipher_suites: Vec::new(),
            sslkeylogfile: String::new(),
            proxy_protocol: false,
            ech_config_list: String::new(),
            enable_0rtt: false,
            crypto_provider: default_crypto_provider(),
            default_sni: String::new(),
            fallback_sni: String::new(),
            strict_sni_host: false,
        }
    }
}

fn default_crypto_provider() -> String {
    "ring".to_string()
}

fn default_tls_min_version() -> String {
    "1.2".to_string()
}

fn default_tls_max_version() -> String {
    "1.3".to_string()
}

impl TlsSettings {
    /// Whether mTLS (client cert verification) is configured.
    pub fn mtls_enabled(&self) -> bool {
        !self.client_ca_path.is_empty()
    }
}

/// TCP routing configuration.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TcpConfig {
    /// TCP entrypoint listen address. Empty = disabled.
    #[serde(default)]
    pub listen: String,
    /// TCP routes.
    #[serde(default)]
    pub routes: Vec<crate::proxy::tcp_router::TcpRoute>,
}

/// UDP routing configuration.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UdpConfig {
    /// UDP entrypoint listen address. Empty = disabled.
    #[serde(default)]
    pub listen: String,
    /// UDP services.
    #[serde(default)]
    pub services: Vec<crate::proxy::udp_router::UdpServiceConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServiceConfig {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default)]
    pub service_type: Option<String>,
    #[serde(default)]
    pub document_root: Option<String>,
    #[serde(default)]
    pub index_file: Option<String>,
    #[serde(default)]
    pub spa_fallback: Option<bool>,
    /// Optional stable identifier for JSON config traversal. When set,
    /// this entry can be looked up via `GET /admin/v1/config/@id/<tag>`
    /// instead of navigating array indices.
    #[serde(default, rename = "@id")]
    pub id_tag: Option<String>,

    // -- Feature 82: streaming timeout controls --
    /// Max duration in seconds for streaming (WebSocket/SSE) connections.
    /// 0 = no timeout.
    #[serde(default)]
    pub stream_timeout_secs: u64,
    /// Delay in seconds before force-closing after server-side close. 0 = immediate.
    #[serde(default)]
    pub stream_close_delay_secs: u64,

    // -- Feature 83: retry resilience controls --
    /// Maximum duration in ms to keep retrying. 0 = no limit.
    #[serde(default)]
    pub lb_try_duration_ms: u64,
    /// Interval in ms between retry attempts.
    #[serde(default = "default_lb_try_interval")]
    pub lb_try_interval_ms: u64,
    /// Status codes that trigger a retry (e.g. ["502", "503"]).
    #[serde(default)]
    pub lb_retry_match: Vec<String>,

    // -- Feature 84: request/response buffer sizes --
    /// Request body buffer size in bytes. 0 = no buffering.
    #[serde(default)]
    pub request_buffer_size: u64,
    /// Response body buffer size in bytes. 0 = no buffering.
    #[serde(default)]
    pub response_buffer_size: u64,

    // -- Feature 85: flush interval --
    /// Response flush frequency in ms. -1 = auto-detect, 0 = flush after
    /// every write, >0 = flush every N ms.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: i64,

    /// When true, the original client Host header is forwarded to the
    /// upstream server instead of being replaced by the upstream hostname.
    /// Default: false (standard reverse-proxy behaviour).
    #[serde(default)]
    pub pass_host_header: bool,

    /// Site root directory for file operations. When set, serves as the
    /// base path for file serving and file matchers.
    #[serde(default)]
    pub root: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteConfig {
    pub paths: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub service: String,
    #[serde(default)]
    pub strip_path: bool,
    /// Optional stable identifier for JSON config traversal. When set,
    /// this entry can be looked up via `GET /admin/v1/config/@id/<tag>`
    /// instead of navigating array indices.
    #[serde(default, rename = "@id")]
    pub id_tag: Option<String>,

    /// Arbitrary variables set on this route. Available to matchers and
    /// templates via the `vars` context.
    #[serde(default)]
    pub vars: HashMap<String, String>,

    /// When set, this route delegates to another route by name instead
    /// of proxying to an upstream.
    #[serde(default)]
    pub invoke: Option<String>,

    /// When true, the route's handlers execute in literal definition
    /// order rather than directive-order.
    #[serde(default)]
    pub literal_order: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PluginConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
    /// Optional stable identifier for JSON config traversal. When set,
    /// this entry can be looked up via `GET /admin/v1/config/@id/<tag>`
    /// instead of navigating array indices.
    #[serde(default, rename = "@id")]
    pub id_tag: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            gateway: default_gateway(),
            services: Vec::new(),
            routes: Vec::new(),
            plugins: Vec::new(),
            license: LicenseSettings::default(),
            keyx: KeyxSettings::default(),
            telemetry: TelemetrySettings::default(),
            named_matchers: Vec::new(),
            snippets: HashMap::new(),
            order: Vec::new(),
        }
    }
}

fn default_gateway() -> GatewaySettings {
    GatewaySettings {
        proxy_port: 8000,
        admin_port: 8001,
        strict_port: false,
        database_url: default_database_url(),
        seed_from_config: false,
        health_check_interval_ms: default_hc_interval(),
        health_circuit_failure_threshold: default_hc_failure_threshold(),
        health_circuit_success_threshold: default_hc_success_threshold(),
        health_circuit_open_duration_ms: default_hc_open_duration(),
        tls: TlsSettings::default(),
        acme: AcmeConfig::default(),
        providers: ProvidersConfig::default(),
        pool_max_idle_per_host: default_pool_max_idle(),
        pool_idle_timeout_secs: default_pool_idle_timeout(),
        h2_keepalive_interval_secs: default_h2_keepalive(),
        max_header_size: default_max_header_size(),
        prewarm_interval_secs: default_prewarm_interval(),
        prewarm_concurrency: default_prewarm_concurrency(),
        auth_required: false,
        minimal_telemetry: false,
        recordings_directory: None,
        plan_tier: default_plan_tier(),
        local_zone: None,
        admin_tls: AdminTlsConfig::default(),
        pki: PkiConfig::default(),
        cert_store: CertStoreConfig::default(),
        trusted_proxies: Vec::new(),
        shutdown_delay_secs: 0,
        grace_period_secs: default_grace_period(),
        auto_https: default_auto_https(),
        storage_backend: default_storage_backend(),
        storage_clean_interval_secs: default_storage_clean_interval(),
        keepalive_idle_secs: default_keepalive_idle(),
        keepalive_interval_secs: default_keepalive_interval(),
        keepalive_count: default_keepalive_count(),
        bind_address: default_bind_address(),
        persist_config: true,
        events: EventsConfig::default(),
        log_credentials: false,
        enable_full_duplex: false,
        trace_handlers: false,
        trusted_proxies_strict: false,
        client_ip_headers: Vec::new(),
        filesystems: HashMap::new(),
        tcp: TcpConfig::default(),
        udp: UdpConfig::default(),
        auto_tune_kernel: true,
        default_drain_timeout_ms: default_drain_timeout(),
        deploy_health_check_interval_ms: default_deploy_hc_interval(),
        deploy_health_check_timeout_ms: default_deploy_hc_timeout(),
        deploy_health_check_threshold: default_deploy_hc_threshold(),
    }
}

fn default_grace_period() -> u64 {
    30
}

fn default_auto_https() -> String {
    "on".to_string()
}

fn default_storage_backend() -> String {
    "file".to_string()
}

fn default_storage_clean_interval() -> u64 {
    86400
}

fn default_keepalive_idle() -> u64 {
    60
}

fn default_keepalive_interval() -> u64 {
    15
}

fn default_keepalive_count() -> u32 {
    3
}

fn default_prewarm_interval() -> u64 {
    // 30s by default — keeps idle pools hot without flooding lightly-used
    // upstreams. Set to 0 in config to disable.
    30
}

fn default_prewarm_concurrency() -> usize {
    8
}

fn default_hc_interval() -> u64 {
    10_000
}

fn default_hc_failure_threshold() -> u32 {
    3
}

fn default_hc_success_threshold() -> u32 {
    2
}

fn default_hc_open_duration() -> u64 {
    30_000
}

fn default_plan_tier() -> String {
    "free".to_string()
}

fn default_pool_max_idle() -> usize {
    128
}

fn default_pool_idle_timeout() -> u64 {
    120
}

fn default_h2_keepalive() -> u64 {
    10
}

fn default_max_header_size() -> usize {
    16384
}

fn default_database_url() -> String {
    "sqlite://lynxx.db?mode=rwc".to_string()
}

fn default_proxy_port() -> u16 {
    8000
}

fn default_admin_port() -> u16 {
    8001
}

fn default_lb_try_interval() -> u64 {
    250
}

fn default_flush_interval() -> i64 {
    -1
}

fn default_retries() -> u32 {
    3
}

fn default_timeout() -> u64 {
    5000
}

fn default_true() -> bool {
    true
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_true_bool() -> bool {
    true
}

fn default_drain_timeout() -> u64 {
    30_000
}

fn default_deploy_hc_interval() -> u64 {
    2_000
}

fn default_deploy_hc_timeout() -> u64 {
    3_000
}

fn default_deploy_hc_threshold() -> u32 {
    3
}

/// Detected config file format based on extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Toml,
    Yaml,
    Json,
}

/// Strip single-line (`//`) and block (`/* */`) comments from JSONC content,
/// producing valid JSON. Handles comments inside string literals correctly.
fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;

    while i < len {
        if in_string {
            out.push(chars[i]);
            if chars[i] == '\\' && i + 1 < len {
                out.push(chars[i + 1]);
                i += 2;
            } else {
                if chars[i] == '"' {
                    in_string = false;
                }
                i += 1;
            }
        } else if chars[i] == '"' {
            in_string = true;
            out.push(chars[i]);
            i += 1;
        } else if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
            // Single-line comment — skip to end of line.
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
        } else if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            // Block comment — skip to closing `*/`.
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2; // skip `*/`
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Detect config format from file extension.
fn detect_format(path: &str) -> Option<ConfigFormat> {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    match ext.as_deref() {
        Some("toml") => Some(ConfigFormat::Toml),
        Some("yaml" | "yml") => Some(ConfigFormat::Yaml),
        Some("json" | "jsonc") => Some(ConfigFormat::Json),
        _ => None,
    }
}

/// Parse a config string in the given format.
fn parse_config(contents: &str, format: ConfigFormat) -> anyhow::Result<GatewayConfig> {
    match format {
        ConfigFormat::Toml => Ok(toml::from_str(contents)?),
        ConfigFormat::Yaml => Ok(serde_yaml::from_str(contents)?),
        ConfigFormat::Json => {
            let clean = strip_jsonc_comments(contents);
            Ok(serde_json::from_str(&clean)?)
        }
    }
}

/// Process `import` directives in a config file. Lines matching
/// `import = "path"` or `import = ["path1", "path2"]` in TOML, or
/// `import: path` in YAML, are resolved relative to the parent
/// directory of the main config file and merged via deep overlay.
fn resolve_imports(
    contents: &str,
    base_dir: &std::path::Path,
    format: ConfigFormat,
) -> anyhow::Result<String> {
    match format {
        ConfigFormat::Toml => {
            let mut table: toml::Value = toml::from_str(contents)?;
            // Extract named snippets before processing imports.
            let snippets: toml::map::Map<String, toml::Value> = table
                .as_table_mut()
                .and_then(|t| t.remove("snippets"))
                .and_then(|v| match v {
                    toml::Value::Table(m) => Some(m),
                    _ => None,
                })
                .unwrap_or_default();
            if let Some(imports) = table.as_table_mut().and_then(|t| t.remove("import")) {
                let paths = match imports {
                    toml::Value::String(s) => vec![s],
                    toml::Value::Array(arr) => arr
                        .into_iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                    _ => vec![],
                };
                for p in &paths {
                    if let Some(snippet_val) = snippets.get(p) {
                        tracing::info!("expanding snippet '{p}'");
                        let snippet_as_table = toml::Value::Table({
                            let mut m = toml::map::Map::new();
                            m.insert(p.clone(), snippet_val.clone());
                            m
                        });
                        // Snippets are tables — merge their content directly.
                        merge_toml(
                            &mut table,
                            &toml::Value::Table(snippet_val.as_table().cloned().unwrap_or_else(
                                || {
                                    let mut m = toml::map::Map::new();
                                    m.insert(p.clone(), snippet_val.clone());
                                    m
                                },
                            )),
                        );
                        let _ = snippet_as_table; // suppress warning
                    } else {
                        let resolved = resolve_import_path(p, base_dir);
                        let snippet = std::fs::read_to_string(&resolved)
                            .map_err(|e| anyhow::anyhow!("import {}: {e}", resolved.display()))?;
                        tracing::info!("importing config snippet from {}", resolved.display());
                        let snippet_val: toml::Value = toml::from_str(&snippet)?;
                        merge_toml(&mut table, &snippet_val);
                    }
                }
            }
            Ok(toml::to_string_pretty(&table)?)
        }
        ConfigFormat::Yaml => {
            let mut val: serde_yaml::Value = serde_yaml::from_str(contents)?;
            // Extract named snippets before processing imports.
            let snippets: serde_yaml::Mapping = val
                .as_mapping_mut()
                .and_then(|m| m.remove(serde_yaml::Value::String("snippets".into())))
                .and_then(|v| match v {
                    serde_yaml::Value::Mapping(m) => Some(m),
                    _ => None,
                })
                .unwrap_or_default();
            if let Some(imports) = val
                .as_mapping_mut()
                .and_then(|m| m.remove(serde_yaml::Value::String("import".into())))
            {
                let paths: Vec<String> = match imports {
                    serde_yaml::Value::String(s) => vec![s],
                    serde_yaml::Value::Sequence(seq) => seq
                        .into_iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                    _ => vec![],
                };
                for p in &paths {
                    let key = serde_yaml::Value::String(p.clone());
                    if let Some(snippet_val) = snippets.get(&key) {
                        tracing::info!("expanding snippet '{p}'");
                        if let serde_yaml::Value::Mapping(ref m) = snippet_val {
                            merge_yaml(&mut val, &serde_yaml::Value::Mapping(m.clone()));
                        }
                    } else {
                        let resolved = resolve_import_path(p, base_dir);
                        let snippet = std::fs::read_to_string(&resolved)
                            .map_err(|e| anyhow::anyhow!("import {}: {e}", resolved.display()))?;
                        tracing::info!("importing config snippet from {}", resolved.display());
                        let snippet_val: serde_yaml::Value = serde_yaml::from_str(&snippet)?;
                        merge_yaml(&mut val, &snippet_val);
                    }
                }
            }
            Ok(serde_yaml::to_string(&val)?)
        }
        ConfigFormat::Json => {
            let clean = strip_jsonc_comments(contents);
            let mut val: serde_json::Value = serde_json::from_str(&clean)?;
            // Extract named snippets before processing imports.
            let snippets: serde_json::Map<String, serde_json::Value> = val
                .as_object_mut()
                .and_then(|m| m.remove("snippets"))
                .and_then(|v| match v {
                    serde_json::Value::Object(m) => Some(m),
                    _ => None,
                })
                .unwrap_or_default();
            if let Some(imports) = val.as_object_mut().and_then(|m| m.remove("import")) {
                let paths: Vec<String> = match imports {
                    serde_json::Value::String(s) => vec![s],
                    serde_json::Value::Array(arr) => arr
                        .into_iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                    _ => vec![],
                };
                for p in &paths {
                    if let Some(snippet_val) = snippets.get(p) {
                        tracing::info!("expanding snippet '{p}'");
                        if let serde_json::Value::Object(ref m) = snippet_val {
                            merge_json(&mut val, &serde_json::Value::Object(m.clone()));
                        }
                    } else {
                        let resolved = resolve_import_path(p, base_dir);
                        let snippet = std::fs::read_to_string(&resolved)
                            .map_err(|e| anyhow::anyhow!("import {}: {e}", resolved.display()))?;
                        tracing::info!("importing config snippet from {}", resolved.display());
                        let snippet_clean = strip_jsonc_comments(&snippet);
                        let snippet_val: serde_json::Value = serde_json::from_str(&snippet_clean)?;
                        merge_json(&mut val, &snippet_val);
                    }
                }
            }
            Ok(serde_json::to_string_pretty(&val)?)
        }
    }
}

fn resolve_import_path(path: &str, base_dir: &std::path::Path) -> std::path::PathBuf {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

fn merge_toml(base: &mut toml::Value, overlay: &toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(b), toml::Value::Table(o)) => {
            for (k, v) in o {
                let entry = b
                    .entry(k.clone())
                    .or_insert_with(|| toml::Value::Boolean(false));
                merge_toml(entry, v);
            }
        }
        (toml::Value::Array(b), toml::Value::Array(o)) => {
            b.extend(o.iter().cloned());
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}

fn merge_yaml(base: &mut serde_yaml::Value, overlay: &serde_yaml::Value) {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(b), serde_yaml::Value::Mapping(o)) => {
            for (k, v) in o {
                let entry = b.entry(k.clone()).or_insert(serde_yaml::Value::Null);
                merge_yaml(entry, v);
            }
        }
        (serde_yaml::Value::Sequence(b), serde_yaml::Value::Sequence(o)) => {
            b.extend(o.iter().cloned());
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}

fn merge_json(base: &mut serde_json::Value, overlay: &serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                let entry = b.entry(k.clone()).or_insert(serde_json::Value::Null);
                merge_json(entry, v);
            }
        }
        (serde_json::Value::Array(b), serde_json::Value::Array(o)) => {
            b.extend(o.iter().cloned());
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}

/// Expand `{env.VAR_NAME}` placeholders in config strings with the
/// corresponding environment variable values. Unknown vars are left as-is.
fn expand_env_vars(input: &str) -> String {
    static ENV_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re =
        ENV_RE.get_or_init(|| regex::Regex::new(r"\{env\.([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());
    re.replace_all(input, |caps: &regex::Captures| {
        let var_name = &caps[1];
        std::env::var(var_name).unwrap_or_else(|_| caps[0].to_string())
    })
    .into_owned()
}

pub fn load_config(path: &str) -> anyhow::Result<GatewayConfig> {
    match std::fs::read_to_string(path) {
        Ok(raw_contents) => {
            // Expand {env.VAR} placeholders before parsing.
            let contents = expand_env_vars(&raw_contents);
            let base_dir = std::path::Path::new(path)
                .parent()
                .unwrap_or(std::path::Path::new("."));

            if let Some(fmt) = detect_format(path) {
                tracing::info!("loading config as {:?} from {path}", fmt);
                let processed = resolve_imports(&contents, base_dir, fmt)?;
                parse_config(&processed, fmt)
            } else {
                tracing::info!("no recognised extension for {path}, probing TOML → YAML → JSON");
                parse_config(&contents, ConfigFormat::Toml)
                    .or_else(|_| parse_config(&contents, ConfigFormat::Yaml))
                    .or_else(|_| parse_config(&contents, ConfigFormat::Json))
                    .map_err(|e| {
                        anyhow::anyhow!("failed to parse {path} as TOML, YAML, or JSON: {e}")
                    })
            }
        }
        Err(_) => {
            tracing::warn!("config file not found at {path}, using defaults");
            Ok(GatewayConfig::default())
        }
    }
}

/// Watch the config file for changes and trigger a reload callback.
/// Polls every `interval` and calls `on_change` when the file mtime changes.
pub fn spawn_config_watcher<F>(path: String, interval: std::time::Duration, on_change: F)
where
    F: Fn() + Send + 'static,
{
    tokio::spawn(async move {
        let mut last_mtime: Option<std::time::SystemTime> = None;
        loop {
            tokio::time::sleep(interval).await;
            if let Ok(meta) = tokio::fs::metadata(&path).await {
                if let Ok(mtime) = meta.modified() {
                    if last_mtime != Some(mtime) {
                        if last_mtime.is_some() {
                            tracing::info!(
                                path = %path,
                                "config file changed, triggering reload"
                            );
                            on_change();
                        }
                        last_mtime = Some(mtime);
                    }
                }
            }
        }
    });
}

/// Apply environment-variable overrides on top of the loaded TOML config.
///
/// TOML remains the primary source of truth; env vars provide a thin overlay
/// for the values most commonly set in container/Helm deployments.
///
/// Recognised vars:
///   * `DATABASE_URL`            overrides `gateway.database_url`
///   * `LYNXX_PROXY_PORT`        overrides `gateway.proxy_port`
///   * `LYNXX_ADMIN_PORT`        overrides `gateway.admin_port`
///   * `LYNXX_TELEMETRY_URL`     overrides `telemetry.endpoint` (fallback: `OTEL_EXPORTER_OTLP_ENDPOINT`)
///   * `LYNXX_TELEMETRY_API_KEY` overrides `telemetry.api_key`
///   * `OTEL_SERVICE_NAME`       overrides `telemetry.service_name`
///   * `FLUXX_OTEL_ENDPOINT`     overrides `telemetry.fluxx_endpoint`
///   * `LYNXX_MINIMAL_TELEMETRY` overrides `gateway.minimal_telemetry`
///     (legacy alias: `LYNXX_BENCH_MODE`)
pub fn apply_env_overrides(config: &mut GatewayConfig) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        if !url.is_empty() {
            tracing::info!("DATABASE_URL env override applied");
            config.gateway.database_url = url;
        }
    }
    if let Some(port) = parse_port_env("LYNXX_PROXY_PORT") {
        tracing::info!(port, "LYNXX_PROXY_PORT env override applied");
        config.gateway.proxy_port = port;
    }
    if let Some(port) = parse_port_env("LYNXX_ADMIN_PORT") {
        tracing::info!(port, "LYNXX_ADMIN_PORT env override applied");
        config.gateway.admin_port = port;
    }
    if let Ok(url) = std::env::var("LYNXX_TELEMETRY_URL") {
        if !url.is_empty() {
            config.telemetry.endpoint = url;
        }
    } else if let Ok(url) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        if !url.is_empty() {
            config.telemetry.endpoint = url;
        }
    }
    if let Ok(key) = std::env::var("LYNXX_TELEMETRY_API_KEY") {
        if !key.is_empty() {
            config.telemetry.api_key = key;
        }
    }
    if let Ok(name) = std::env::var("OTEL_SERVICE_NAME") {
        if !name.is_empty() {
            config.telemetry.service_name = name;
        }
    }
    if let Ok(url) = std::env::var("FLUXX_OTEL_ENDPOINT") {
        if !url.is_empty() {
            config.telemetry.fluxx_endpoint = url;
        }
    }
    // Telemetry-skip flag. Reads the new name first; falls back to the
    // legacy `LYNXX_BENCH_MODE` so existing bench scripts keep working.
    // Parse "1" / "true" / "yes" as on; everything else (incl. empty) as off.
    let parse_truthy = |v: &str| {
        let v = v.to_lowercase();
        !v.is_empty() && v != "0" && v != "false" && v != "no"
    };
    if let Ok(v) = std::env::var("LYNXX_MINIMAL_TELEMETRY") {
        let on = parse_truthy(&v);
        if on {
            tracing::info!("LYNXX_MINIMAL_TELEMETRY env override applied");
        }
        config.gateway.minimal_telemetry = on;
    } else if let Ok(v) = std::env::var("LYNXX_BENCH_MODE") {
        let on = parse_truthy(&v);
        if on {
            tracing::warn!(
                "LYNXX_BENCH_MODE (legacy) env override applied; prefer LYNXX_MINIMAL_TELEMETRY \
                 or [gateway].minimal_telemetry in config.toml"
            );
        }
        config.gateway.minimal_telemetry = on;
    }
    if let Ok(url) = std::env::var("KEYX_BASE_URL") {
        if !url.is_empty() {
            config.keyx.base_url = url;
        }
    }
    if let Ok(tok) = std::env::var("KEYX_SERVICE_TOKEN") {
        if !tok.is_empty() {
            config.keyx.service_token = tok;
        }
    }
    if let Ok(urn) = std::env::var("KEYX_LICENSE_URN") {
        if !urn.is_empty() {
            config.keyx.license_urn = urn;
        }
    }
    if let Ok(raw) = std::env::var("KEYX_ADMIN_CACHE_TTL_SECS") {
        match raw.parse::<u64>() {
            Ok(n) => config.keyx.admin_cache_ttl_secs = n,
            Err(e) => tracing::warn!(
                value = %raw, error = %e,
                "ignoring invalid KEYX_ADMIN_CACHE_TTL_SECS"
            ),
        }
    }
}

fn parse_port_env(name: &str) -> Option<u16> {
    let raw = std::env::var(name).ok()?;
    match raw.parse::<u16>() {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(var = name, value = %raw, error = %e, "ignoring invalid port env var");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_grace_period_30s() {
        let gw = default_gateway();
        assert_eq!(gw.grace_period_secs, 30);
    }

    #[test]
    fn default_shutdown_delay_0() {
        let gw = default_gateway();
        assert_eq!(gw.shutdown_delay_secs, 0);
    }

    #[test]
    fn custom_shutdown_config_deserializes() {
        let toml_str = r#"
[gateway]
shutdown_delay_secs = 5
grace_period_secs = 60
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.shutdown_delay_secs, 5);
        assert_eq!(cfg.gateway.grace_period_secs, 60);
    }

    // --- Feature 51: @id shortcut tag tests ---

    #[test]
    fn id_tag_deserializes() {
        let json = r#"{
            "services": [
                { "name": "my-svc", "url": "http://localhost:3000", "@id": "my-svc" }
            ],
            "routes": [
                { "paths": ["/api"], "service": "my-svc", "@id": "api-route" }
            ],
            "plugins": [
                { "name": "cors", "@id": "cors-global" }
            ]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].id_tag.as_deref(), Some("my-svc"));
        assert_eq!(cfg.routes[0].id_tag.as_deref(), Some("api-route"));
        assert_eq!(cfg.plugins[0].id_tag.as_deref(), Some("cors-global"));
    }

    #[test]
    fn id_tag_optional() {
        let json = r#"{
            "services": [
                { "name": "plain-svc", "url": "http://localhost:4000" }
            ],
            "routes": [
                { "paths": ["/health"], "service": "plain-svc" }
            ],
            "plugins": [
                { "name": "logging" }
            ]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert!(cfg.services[0].id_tag.is_none());
        assert!(cfg.routes[0].id_tag.is_none());
        assert!(cfg.plugins[0].id_tag.is_none());
    }

    // --- Feature 52: directive ordering tests ---

    #[test]
    fn order_deserializes() {
        let json = r#"{
            "order": ["cors", "rate_limit", "jwt"]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.order, vec!["cors", "rate_limit", "jwt"]);
    }

    #[test]
    fn order_default_empty() {
        let cfg = GatewayConfig::default();
        assert!(cfg.order.is_empty());
    }

    // --- Feature 48: snippets tests ---

    #[test]
    fn snippet_inline_toml() {
        let dir = std::env::temp_dir().join("lynxx_snippet_test_inline");
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = dir.join("config.toml");
        let toml_str = r#"
[snippets.common_service]
retries = 5
connect_timeout_ms = 10000

import = "common_service"

[[services]]
name = "api"
url = "http://localhost:3000"
"#;
        std::fs::write(&cfg_path, toml_str).unwrap();
        let cfg = load_config(cfg_path.to_str().unwrap()).expect("snippet should expand");
        assert_eq!(cfg.services.len(), 1);
        // The snippets field should not remain in the deserialized config
        // (it's stripped during preprocessing).
        assert!(cfg.snippets.is_empty());
    }

    #[test]
    fn snippet_field_deserializes() {
        let json = r#"{
            "snippets": {
                "common": { "retries": 5 }
            }
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.snippets.len(), 1);
        assert!(cfg.snippets.contains_key("common"));
    }

    #[test]
    fn snippet_default_empty() {
        let cfg = GatewayConfig::default();
        assert!(cfg.snippets.is_empty());
    }

    // --- Config format detection tests ---

    #[test]
    fn detect_format_from_extension() {
        assert_eq!(detect_format("config.toml"), Some(ConfigFormat::Toml));
        assert_eq!(detect_format("config.yaml"), Some(ConfigFormat::Yaml));
        assert_eq!(detect_format("config.yml"), Some(ConfigFormat::Yaml));
        assert_eq!(detect_format("config.json"), Some(ConfigFormat::Json));
        assert_eq!(detect_format("config.jsonc"), Some(ConfigFormat::Json));
        assert_eq!(detect_format("config.unknown"), None);
    }

    #[test]
    fn strip_jsonc_comments_basic() {
        let input = r#"{ // comment
            "key": "value" /* block */
        }"#;
        let clean = strip_jsonc_comments(input);
        assert!(!clean.contains("comment"));
        assert!(!clean.contains("block"));
        assert!(clean.contains("\"key\""));
    }

    #[test]
    fn env_var_expansion() {
        std::env::set_var("LYNXX_TEST_PORT", "9999");
        let result = expand_env_vars("port = {env.LYNXX_TEST_PORT}");
        assert_eq!(result, "port = 9999");
        std::env::remove_var("LYNXX_TEST_PORT");
    }

    #[test]
    fn merge_toml_arrays_extend() {
        let mut base: toml::Value = toml::from_str(r#"arr = [1, 2]"#).unwrap();
        let overlay: toml::Value = toml::from_str(r#"arr = [3]"#).unwrap();
        merge_toml(&mut base, &overlay);
        let arr = base.get("arr").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn merge_json_deep() {
        let mut base: serde_json::Value = serde_json::json!({"a": {"b": 1}});
        let overlay: serde_json::Value = serde_json::json!({"a": {"c": 2}});
        merge_json(&mut base, &overlay);
        assert_eq!(base["a"]["b"], 1);
        assert_eq!(base["a"]["c"], 2);
    }

    // --- Feature 60: auto_https ---

    #[test]
    fn auto_https_defaults_on() {
        let gw = default_gateway();
        assert_eq!(gw.auto_https, "on");
    }

    #[test]
    fn auto_https_deserializes() {
        let toml_str = r#"
[gateway]
auto_https = "disable_redirects"
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.auto_https, "disable_redirects");
    }

    #[test]
    fn auto_https_off_deserializes() {
        let toml_str = r#"
[gateway]
auto_https = "off"
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.auto_https, "off");
    }

    // --- Feature 61: default_sni / fallback_sni ---

    #[test]
    fn default_sni_defaults_empty() {
        let tls = TlsSettings::default();
        assert!(tls.default_sni.is_empty());
        assert!(tls.fallback_sni.is_empty());
    }

    #[test]
    fn default_sni_deserializes() {
        let json = r#"{"default_sni": "example.com", "fallback_sni": "fallback.example.com"}"#;
        let tls: TlsSettings = serde_json::from_str(json).unwrap();
        assert_eq!(tls.default_sni, "example.com");
        assert_eq!(tls.fallback_sni, "fallback.example.com");
    }

    // --- Feature 62: strict_sni_host ---

    #[test]
    fn strict_sni_host_defaults_false() {
        let tls = TlsSettings::default();
        assert!(!tls.strict_sni_host);
    }

    #[test]
    fn strict_sni_host_deserializes() {
        let json = r#"{"strict_sni_host": true}"#;
        let tls: TlsSettings = serde_json::from_str(json).unwrap();
        assert!(tls.strict_sni_host);
    }

    // --- Feature 74: dns_challenge_override_domain ---

    #[test]
    fn dns_challenge_override_domain_defaults_empty() {
        let dns = Dns01Config::default();
        assert!(dns.dns_challenge_override_domain.is_empty());
    }

    #[test]
    fn dns_challenge_override_domain_deserializes() {
        let json = r#"{"dns_challenge_override_domain": "acme.example.com"}"#;
        let dns: Dns01Config = serde_json::from_str(json).unwrap();
        assert_eq!(dns.dns_challenge_override_domain, "acme.example.com");
    }

    // --- Feature 75: propagation_delay ---

    #[test]
    fn propagation_delay_defaults_zero() {
        let dns = Dns01Config::default();
        assert_eq!(dns.propagation_delay_secs, 0);
    }

    #[test]
    fn propagation_delay_deserializes() {
        let json = r#"{"propagation_delay_secs": 30}"#;
        let dns: Dns01Config = serde_json::from_str(json).unwrap();
        assert_eq!(dns.propagation_delay_secs, 30);
    }

    // --- Feature 76: renewal_window_ratio, cert_lifetime, renew_interval ---

    #[test]
    fn acme_renewal_defaults() {
        let acme = AcmeConfig::default();
        assert!((acme.renewal_window_ratio - 0.3333).abs() < 0.0001);
        assert_eq!(acme.cert_lifetime_days, 90);
        assert_eq!(acme.renew_interval_secs, 43200);
    }

    #[test]
    fn acme_renewal_deserializes() {
        let json = r#"{
            "renewal_window_ratio": 0.5,
            "cert_lifetime_days": 30,
            "renew_interval_secs": 3600
        }"#;
        let acme: AcmeConfig = serde_json::from_str(json).unwrap();
        assert!((acme.renewal_window_ratio - 0.5).abs() < 0.0001);
        assert_eq!(acme.cert_lifetime_days, 30);
        assert_eq!(acme.renew_interval_secs, 3600);
    }

    // --- Feature 77: storage_backend ---

    #[test]
    fn storage_backend_defaults_file() {
        let gw = default_gateway();
        assert_eq!(gw.storage_backend, "file");
    }

    #[test]
    fn storage_backend_deserializes() {
        let toml_str = r#"
[gateway]
storage_backend = "redis"
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.storage_backend, "redis");
    }

    // --- Feature 78: storage_clean_interval ---

    #[test]
    fn storage_clean_interval_defaults_24h() {
        let gw = default_gateway();
        assert_eq!(gw.storage_clean_interval_secs, 86400);
    }

    #[test]
    fn storage_clean_interval_deserializes() {
        let toml_str = r#"
[gateway]
storage_clean_interval_secs = 3600
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.storage_clean_interval_secs, 3600);
    }

    // --- Feature 81: TCP keepalive tuning ---

    #[test]
    fn keepalive_defaults() {
        let gw = default_gateway();
        assert_eq!(gw.keepalive_idle_secs, 60);
        assert_eq!(gw.keepalive_interval_secs, 15);
        assert_eq!(gw.keepalive_count, 3);
    }

    #[test]
    fn keepalive_deserializes() {
        let toml_str = r#"
[gateway]
keepalive_idle_secs = 120
keepalive_interval_secs = 30
keepalive_count = 5
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.keepalive_idle_secs, 120);
        assert_eq!(cfg.gateway.keepalive_interval_secs, 30);
        assert_eq!(cfg.gateway.keepalive_count, 5);
    }

    // --- Feature 82: stream_timeout / stream_close_delay ---

    #[test]
    fn stream_timeout_defaults_zero() {
        let json = r#"{ "services": [{ "name": "svc", "url": "http://localhost:3000" }] }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].stream_timeout_secs, 0);
        assert_eq!(cfg.services[0].stream_close_delay_secs, 0);
    }

    #[test]
    fn stream_timeout_deserializes() {
        let json = r#"{
            "services": [{
                "name": "ws-svc",
                "url": "http://localhost:3000",
                "stream_timeout_secs": 300,
                "stream_close_delay_secs": 5
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].stream_timeout_secs, 300);
        assert_eq!(cfg.services[0].stream_close_delay_secs, 5);
    }

    // --- Feature 83: lb_try_duration / lb_try_interval / lb_retry_match ---

    #[test]
    fn lb_retry_defaults() {
        let json = r#"{ "services": [{ "name": "svc", "url": "http://localhost:3000" }] }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].lb_try_duration_ms, 0);
        assert_eq!(cfg.services[0].lb_try_interval_ms, 250);
        assert!(cfg.services[0].lb_retry_match.is_empty());
    }

    #[test]
    fn lb_retry_deserializes() {
        let json = r#"{
            "services": [{
                "name": "retry-svc",
                "url": "http://localhost:3000",
                "lb_try_duration_ms": 30000,
                "lb_try_interval_ms": 500,
                "lb_retry_match": ["502", "503", "504"]
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].lb_try_duration_ms, 30000);
        assert_eq!(cfg.services[0].lb_try_interval_ms, 500);
        assert_eq!(cfg.services[0].lb_retry_match, vec!["502", "503", "504"]);
    }

    // --- Feature 84: request_buffer_size / response_buffer_size ---

    #[test]
    fn buffer_size_defaults_zero() {
        let json = r#"{ "services": [{ "name": "svc", "url": "http://localhost:3000" }] }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].request_buffer_size, 0);
        assert_eq!(cfg.services[0].response_buffer_size, 0);
    }

    #[test]
    fn buffer_size_deserializes() {
        let json = r#"{
            "services": [{
                "name": "buf-svc",
                "url": "http://localhost:3000",
                "request_buffer_size": 4096,
                "response_buffer_size": 8192
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].request_buffer_size, 4096);
        assert_eq!(cfg.services[0].response_buffer_size, 8192);
    }

    // --- Feature 85: flush_interval ---

    #[test]
    fn flush_interval_default_auto() {
        let json = r#"{ "services": [{ "name": "svc", "url": "http://localhost:3000" }] }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].flush_interval_ms, -1);
    }

    #[test]
    fn flush_interval_deserializes() {
        let json = r#"{
            "services": [{
                "name": "flush-svc",
                "url": "http://localhost:3000",
                "flush_interval_ms": 100
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].flush_interval_ms, 100);
    }

    #[test]
    fn flush_interval_zero_means_every_write() {
        let json = r#"{
            "services": [{
                "name": "flush-svc",
                "url": "http://localhost:3000",
                "flush_interval_ms": 0
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].flush_interval_ms, 0);
    }

    // --- Feature 63: bind_address ---

    #[test]
    fn bind_address_defaults_to_all() {
        let gw = default_gateway();
        assert_eq!(gw.bind_address, "0.0.0.0");
    }

    #[test]
    fn bind_address_deserializes() {
        let toml_str = r#"
[gateway]
bind_address = "127.0.0.1"
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(cfg.gateway.bind_address, "127.0.0.1");
    }

    // --- Feature 64: root directive ---

    #[test]
    fn service_root_defaults_empty() {
        let json = r#"{
            "services": [{ "name": "svc", "url": "http://localhost:3000" }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert!(cfg.services[0].root.is_empty());
    }

    #[test]
    fn service_root_deserializes() {
        let json = r#"{
            "services": [{ "name": "static-svc", "url": "", "root": "/var/www/html" }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.services[0].root, "/var/www/html");
    }

    // --- Feature 65: error directive (handled by error_handler plugin) ---

    #[test]
    fn error_handler_plugin_config_deserializes() {
        let json = r#"{
            "plugins": [{
                "name": "error-handler",
                "config": {
                    "pages": {
                        "404": { "body": "<h1>Not Found</h1>", "content_type": "text/html" }
                    }
                }
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.plugins[0].name, "error-handler");
        assert!(cfg.plugins[0].config.get("pages").is_some());
    }

    // --- Feature 66: vars directive ---

    #[test]
    fn route_vars_default_empty() {
        let json = r#"{
            "routes": [{ "paths": ["/api"], "service": "svc" }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert!(cfg.routes[0].vars.is_empty());
    }

    #[test]
    fn route_vars_deserializes() {
        let json = r#"{
            "routes": [{
                "paths": ["/api"],
                "service": "svc",
                "vars": { "env": "production", "version": "v2" }
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.routes[0].vars.get("env").unwrap(), "production");
        assert_eq!(cfg.routes[0].vars.get("version").unwrap(), "v2");
    }

    // --- Feature 67: invoke (named routes) ---

    #[test]
    fn route_invoke_default_none() {
        let json = r#"{
            "routes": [{ "paths": ["/api"], "service": "svc" }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert!(cfg.routes[0].invoke.is_none());
    }

    #[test]
    fn route_invoke_deserializes() {
        let json = r#"{
            "routes": [{
                "paths": ["/api"],
                "service": "svc",
                "invoke": "other-route"
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.routes[0].invoke.as_deref(), Some("other-route"));
    }

    // --- Feature 68: literal_order ---

    #[test]
    fn route_literal_order_default_false() {
        let json = r#"{
            "routes": [{ "paths": ["/api"], "service": "svc" }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert!(!cfg.routes[0].literal_order);
    }

    #[test]
    fn route_literal_order_deserializes() {
        let json = r#"{
            "routes": [{
                "paths": ["/api"],
                "service": "svc",
                "literal_order": true
            }]
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert!(cfg.routes[0].literal_order);
    }

    // --- Feature 79: persist_config ---

    #[test]
    fn persist_config_defaults_true() {
        let gw = default_gateway();
        assert!(gw.persist_config);
    }

    #[test]
    fn persist_config_deserializes() {
        let toml_str = r#"
[gateway]
persist_config = false
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert!(!cfg.gateway.persist_config);
    }

    // --- Feature 93: events system ---

    #[test]
    fn events_default_empty() {
        let gw = default_gateway();
        assert!(gw.events.on_healthy.is_empty());
        assert!(gw.events.on_unhealthy.is_empty());
    }

    #[test]
    fn events_deserializes() {
        let json = r#"{
            "gateway": {
                "events": {
                    "on_healthy": ["https://hooks.example.com/healthy"],
                    "on_unhealthy": ["https://hooks.example.com/down", "https://pager.example.com/alert"]
                }
            }
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.gateway.events.on_healthy.len(), 1);
        assert_eq!(cfg.gateway.events.on_unhealthy.len(), 2);
    }

    // --- Feature 94: log_credentials ---

    #[test]
    fn log_credentials_defaults_false() {
        let gw = default_gateway();
        assert!(!gw.log_credentials);
    }

    #[test]
    fn log_credentials_deserializes() {
        let toml_str = r#"
[gateway]
log_credentials = true
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert!(cfg.gateway.log_credentials);
    }

    // --- Feature 95: enable_full_duplex ---

    #[test]
    fn enable_full_duplex_defaults_false() {
        let gw = default_gateway();
        assert!(!gw.enable_full_duplex);
    }

    #[test]
    fn enable_full_duplex_deserializes() {
        let toml_str = r#"
[gateway]
enable_full_duplex = true
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert!(cfg.gateway.enable_full_duplex);
    }

    // --- Feature 96: trace_handlers ---

    #[test]
    fn trace_handlers_defaults_false() {
        let gw = default_gateway();
        assert!(!gw.trace_handlers);
    }

    #[test]
    fn trace_handlers_deserializes() {
        let toml_str = r#"
[gateway]
trace_handlers = true
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert!(cfg.gateway.trace_handlers);
    }

    // --- Feature 97: trusted_proxies_strict ---

    #[test]
    fn trusted_proxies_strict_defaults_false() {
        let gw = default_gateway();
        assert!(!gw.trusted_proxies_strict);
    }

    #[test]
    fn trusted_proxies_strict_deserializes() {
        let toml_str = r#"
[gateway]
trusted_proxies_strict = true
"#;
        let cfg: GatewayConfig = toml::from_str(toml_str).expect("valid TOML");
        assert!(cfg.gateway.trusted_proxies_strict);
    }

    // --- Feature 98: client_ip_headers ---

    #[test]
    fn client_ip_headers_defaults_empty() {
        let gw = default_gateway();
        assert!(gw.client_ip_headers.is_empty());
    }

    #[test]
    fn client_ip_headers_deserializes() {
        let json = r#"{
            "gateway": {
                "client_ip_headers": ["X-Real-IP", "CF-Connecting-IP"]
            }
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(
            cfg.gateway.client_ip_headers,
            vec!["X-Real-IP", "CF-Connecting-IP"]
        );
    }

    // --- Feature 99: named filesystems ---

    #[test]
    fn filesystems_defaults_empty() {
        let gw = default_gateway();
        assert!(gw.filesystems.is_empty());
    }

    // --- Feature 100: pass_host_header ---

    #[test]
    fn pass_host_header_defaults_false() {
        // Just verifies the empty-services case parses cleanly. The
        // service-level default is checked in `pass_host_header_round_trip`.
        let _cfg: GatewayConfig = toml::from_str("[gateway]\n").unwrap();
    }

    #[test]
    fn filesystems_deserializes() {
        let json = r#"{
            "gateway": {
                "filesystems": {
                    "static": "/var/www/static",
                    "uploads": "/var/data/uploads"
                }
            }
        }"#;
        let cfg: GatewayConfig = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(cfg.gateway.filesystems.len(), 2);
        assert_eq!(
            cfg.gateway.filesystems.get("static").unwrap(),
            "/var/www/static"
        );
        assert_eq!(
            cfg.gateway.filesystems.get("uploads").unwrap(),
            "/var/data/uploads"
        );
    }
}
