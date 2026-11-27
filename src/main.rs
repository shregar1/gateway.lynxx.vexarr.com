#![allow(dead_code)]

// `mimalloc` is the allocator on the proxy hot path. We tried switching
// to jemalloc with `background_threads` expecting smoother tail
// behavior; in practice on the 8-core bench rig (8 tokio workers +
// 1-2 jemalloc background threads = oversubscribed) p99 went from
// 15 ms to ~185 ms at saturation and throughput dropped from 76k → 65k
// RPS. mimalloc's inline page-reclamation pass is the lesser evil
// here. See the journal entry on commit 45bd5cb for the test numbers.
#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod abstractions;
mod admin;
mod audit;
mod auth;
mod cluster;
mod config;
mod configurations;
mod controllers;
mod db;
mod discovery;
mod dtos;
mod error;
mod health;
mod install;
mod integrations;
mod kernel_tuning;
mod license;
mod logging;
mod logs;
mod lynxfile;
mod metrics;
mod models;
mod plugins;
mod proxy;
mod quota;
mod recording;
mod reload;
mod repositories;
mod services;
mod utilities;

use crate::cluster::ChangeEvent;
use crate::config::{apply_env_overrides, load_config, GatewayConfig};
use crate::db::Repository;
use crate::health::{HealthConfig, HealthRegistry};
use crate::plugins::PluginExecutor;
use crate::proxy::handler::{proxy_handler, ProxyState};
use crate::proxy::loadbalancer::{LbStrategy, LoadBalancerRegistry};
use crate::proxy::router::{RouteTable, SharedRouteTable};
use axum::extract::DefaultBodyLimit;
use axum::response::IntoResponse;
use clap::Parser;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Command-line arguments for the Lynxx gateway.
///
/// Precedence (highest first): clap arg > env var (via clap `env` attr) >
/// TOML file > built-in default.
#[derive(Parser, Debug)]
#[command(version, about = "Lynxx API gateway")]
struct Args {
    /// Path to config.toml
    #[arg(long, env = "LYNXX_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// Override [gateway].proxy_port
    #[arg(long, env = "LYNXX_PROXY_PORT")]
    proxy_port: Option<u16>,

    /// Override [gateway].admin_port
    #[arg(long, env = "LYNXX_ADMIN_PORT")]
    admin_port: Option<u16>,

    /// Override [gateway].database_url
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Disable seed_from_config on first boot
    #[arg(long)]
    no_seed: bool,

    /// Force re-seed from config.toml even if the database already has data.
    /// Overwrites existing services/routes/plugins with the config file state.
    #[arg(long)]
    reseed: bool,

    /// Override [gateway].health_check_interval_ms
    #[arg(long, env = "LYNXX_HEALTH_INTERVAL_MS")]
    health_check_interval_ms: Option<u64>,

    /// Regenerate the master admin token and print it to stderr, invalidating
    /// all existing tokens.
    #[arg(long)]
    reset_admin: bool,

    /// Secondary confirmation (2FA) flag required when passing --reset-admin.
    #[arg(long)]
    force: bool,

    /// Fail immediately if the configured port is unavailable instead of
    /// retrying or falling back to an OS-assigned port.
    #[arg(long, env = "LYNXX_STRICT_PORT")]
    strict_port: bool,
}

/// Apply CLI overrides on top of the loaded TOML config. Each `Some` value
/// wins over whatever the file specified; absent flags leave the config
/// untouched. Boolean flags are applied unconditionally when set to true.
fn apply_cli_overrides(config: &mut GatewayConfig, args: &Args) {
    if let Some(port) = args.proxy_port {
        tracing::info!(port, "--proxy-port override applied");
        config.gateway.proxy_port = port;
    }
    if let Some(port) = args.admin_port {
        tracing::info!(port, "--admin-port override applied");
        config.gateway.admin_port = port;
    }
    if let Some(url) = &args.database_url {
        if !url.is_empty() {
            tracing::info!("--database-url override applied");
            config.gateway.database_url = url.clone();
        }
    }
    if let Some(ms) = args.health_check_interval_ms {
        tracing::info!(ms, "--health-check-interval-ms override applied");
        config.gateway.health_check_interval_ms = ms;
    }
    if args.no_seed {
        tracing::info!("--no-seed: disabling seed_from_config");
        config.gateway.seed_from_config = false;
    }
    if args.strict_port {
        tracing::info!("--strict-port: port fallback disabled");
        config.gateway.strict_port = true;
    }
}

/// Suffix appended to the proxy-listener startup log line when
/// io_uring accept-thread plumbing is engaged. Empty when off so the
/// existing log format is preserved.
fn io_uring_log_suffix(cfg: &crate::config::IoUringConfig) -> &'static str {
    if cfg.accept_thread_enabled {
        ", io_uring accept thread requested"
    } else {
        ""
    }
}

/// Linux: probe io_uring + spawn the dedicated accept thread when the
/// operator opted in and the kernel supports it. Returns the live
/// acceptor + receiver pair, or `None` when the feature is off or the
/// probe failed (in which case we log a warning and the caller falls
/// back to the standard `tokio::net::TcpListener::accept` path).
///
/// The acceptor must outlive the `serve_with_io_uring` future — its
/// drop signals the SQ/CQ thread to exit. Keeping the returned value
/// bound in the surrounding scope guarantees that ordering.
#[cfg(target_os = "linux")]
fn maybe_spawn_io_uring_acceptor(
    listener: &tokio::net::TcpListener,
    cfg: &crate::config::IoUringConfig,
) -> Option<(
    crate::utilities::io_uring_accept::IoUringAcceptor,
    tokio::sync::mpsc::UnboundedReceiver<crate::utilities::io_uring_accept::AcceptedConn>,
)> {
    use crate::utilities::io_uring_accept::{self, Available};
    use std::os::fd::AsRawFd;

    if !cfg.accept_thread_enabled {
        return None;
    }
    match io_uring_accept::probe() {
        Available::Yes => {
            let fd = listener.as_raw_fd();
            match io_uring_accept::IoUringAcceptor::start(fd, cfg.ring_entries) {
                Ok((acceptor, rx)) => {
                    tracing::info!(
                        ring_entries = cfg.ring_entries,
                        "io_uring accept thread started (fd={fd})"
                    );
                    Some((acceptor, rx))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to start io_uring acceptor; falling back to tokio accept"
                    );
                    None
                }
            }
        }
        Available::Unavailable(reason) => {
            tracing::warn!(
                reason = %reason,
                "io_uring not available on this host; falling back to tokio accept"
            );
            None
        }
    }
}

/// Non-Linux: just emit a one-shot warning when the operator asked
/// for io_uring on a platform that can't deliver it, so the
/// missing speedup isn't a silent surprise.
#[cfg(not(target_os = "linux"))]
fn log_io_uring_unavailable_if_requested(cfg: &crate::config::IoUringConfig) {
    if cfg.accept_thread_enabled {
        tracing::warn!(
            "[gateway.io_uring].accept_thread_enabled = true but this build is not Linux; \
             io_uring acceleration ignored. Rebuild on Linux to enable."
        );
    }
}

/// Explicit runtime construction. Beats `#[tokio::main]` for high-RPS proxy
/// workloads because we can size the worker pool to physical cores, name
/// the threads (helps `perf` / flamegraphs), and pin each worker to a
/// specific core via `core_affinity`.
///
/// CPU pinning gives ~3-5% on tight synthetic benchmarks and noticeably
/// more on NUMA boxes where the scheduler would otherwise migrate a
/// worker across sockets — every migration costs a full L1/L2 reload
/// for that worker. We round-robin worker N onto core N (modulo the
/// available core count) so the pin order is deterministic across
/// boots.
fn main() -> anyhow::Result<()> {
    install_panic_hook();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let core_ids = core_affinity::get_core_ids();
    let core_count = core_ids.as_ref().map(|v| v.len()).unwrap_or(0);
    if core_count == 0 {
        tracing::debug!("core_affinity returned no cores; workers will float (no pinning)");
    }
    let worker_count = num_cpus::get();
    let next_worker_id = std::sync::atomic::AtomicUsize::new(0);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_count)
        .thread_name("lynxx-worker")
        .on_thread_start(move || {
            let cores = match core_ids.as_ref() {
                Some(c) if !c.is_empty() => c,
                _ => return,
            };
            let idx = next_worker_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let core = cores[idx % cores.len()];
            if !core_affinity::set_for_current(core) {
                // Soft failure — container with restricted cpuset, or
                // a platform whose set_for_current is a stub. Log once
                // and carry on; tokio will still schedule across the
                // available cores, just without our pin hints.
                tracing::debug!(
                    worker_index = idx,
                    "core_affinity::set_for_current returned false"
                );
            }
        })
        .build()?;
    rt.block_on(async_main())
}

/// Replace the default Rust panic hook with one that logs via tracing
/// and omits the source `file:line:col` (which leaks our internal layout
/// to anyone reading panic output). Backtrace is still emitted when
/// `RUST_BACKTRACE=1` for legitimate debugging; the operator opts in
/// explicitly when they need it.
///
/// In `--release` with `panic = "abort"` this only fires once before the
/// process exits, so the cost is negligible. The trade-off is debug
/// ergonomics for opacity — the gateway hot path has zero remaining
/// panic surface (audit, 2026-05-18) so in practice this hook is only
/// ever called for a programming bug, not a routine failure.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("panic");
        tracing::error!(target: "lynxx::panic", error = msg, "gateway aborted");
        if std::env::var("RUST_BACKTRACE").is_ok() {
            eprintln!("{:?}", std::backtrace::Backtrace::force_capture());
        }
    }));
}

async fn async_main() -> anyhow::Result<()> {
    // --- Load config early so telemetry settings are available ----------
    let args = Args::parse();
    let config_path: String = args.config.to_string_lossy().into_owned();
    let mut config = load_config(&config_path)?;
    apply_env_overrides(&mut config);
    apply_cli_overrides(&mut config, &args);

    // --- Worker settings ------------------------------------------------
    // Apply the [gateway.workers] block (worker model, CPU pinning,
    // RLIMIT_NOFILE) BEFORE any listener is bound — the FD limit raise
    // has to happen while we're still single-threaded (it applies to
    // the process), and the per-core / SO_REUSEPORT decision is read
    // by `serve_per_worker` when it constructs each accept thread.
    let workers = &config.gateway.workers;
    if let Err(e) = crate::proxy::worker::apply_workers_settings(
        &workers.model,
        workers.cpu_pinning,
        workers.rlimit_nofile,
    ) {
        tracing::warn!(error = %e, "workers: invalid config; using defaults");
        let _ = crate::proxy::worker::apply_workers_settings(
            "per_core",
            true,
            workers.rlimit_nofile,
        );
    }
    tracing::info!(
        model = %workers.model,
        cpu_pinning = workers.cpu_pinning,
        rlimit_nofile = workers.rlimit_nofile,
        "workers: settings applied"
    );

    // --- Telemetry init -------------------------------------------------
    // Reads from config.telemetry (populated from TOML + env overrides).
    // Primary endpoint: [telemetry].endpoint / LYNXX_TELEMETRY_URL / OTEL_EXPORTER_OTLP_ENDPOINT
    // Fluxx sidecar:    [telemetry].fluxx_endpoint / FLUXX_OTEL_ENDPOINT
    // When neither is set the OTel layer is omitted entirely.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("lynxx_gateway=info,tower_http=debug"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    let primary_endpoint = if config.telemetry.endpoint.is_empty() {
        None
    } else {
        Some(config.telemetry.endpoint.clone())
    };
    let fluxx_endpoint = if config.telemetry.fluxx_endpoint.is_empty() {
        None
    } else {
        Some(config.telemetry.fluxx_endpoint.clone())
    };
    let telemetry_api_key = if config.telemetry.api_key.is_empty() {
        None
    } else {
        Some(config.telemetry.api_key.clone())
    };

    if primary_endpoint.is_some() || fluxx_endpoint.is_some() {
        // Inject the telemetry API key via the standard OTEL headers env var
        // so the OTLP HTTP exporter picks it up automatically.
        if let Some(ref key) = telemetry_api_key {
            if std::env::var("OTEL_EXPORTER_OTLP_HEADERS").is_err() {
                std::env::set_var(
                    "OTEL_EXPORTER_OTLP_HEADERS",
                    format!("Authorization=Bearer {key}"),
                );
            }
        }

        let svc_name = config.telemetry.service_name.clone();

        let mut provider_builder = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_resource(opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", svc_name),
            ]));

        // --- primary exporter ---
        if let Some(ref endpoint) = primary_endpoint {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(format!("{endpoint}/v1/traces"))
                .build()
                .expect("primary otlp exporter");
            provider_builder =
                provider_builder.with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio);
            tracing::info!("primary otel exporter → {endpoint}");
        }

        // --- fluxx exporter (additional, loopback-only) ---
        // Enforce the loopback-only contract: spans may carry request metadata,
        // so the fluxx exporter must point at a LOCAL collector. Reject any
        // non-loopback endpoint (fail closed) rather than silently shipping
        // telemetry to an arbitrary remote host.
        fn is_loopback_endpoint(endpoint: &str) -> bool {
            let after_scheme = endpoint.split("://").nth(1).unwrap_or(endpoint);
            let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
            // Host part, handling [IPv6]:port and host:port.
            let host = if let Some(rest) = authority.strip_prefix('[') {
                rest.split(']').next().unwrap_or(rest)
            } else {
                authority.split(':').next().unwrap_or(authority)
            };
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        if let Some(ref endpoint) = fluxx_endpoint {
            if !is_loopback_endpoint(endpoint) {
                tracing::warn!(
                    endpoint = %endpoint,
                    "fluxx telemetry endpoint is not loopback; refusing to enable the loopback-only exporter"
                );
            } else if let Ok(fluxx_exporter) = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(format!("{endpoint}/v1/traces"))
                .build()
            {
                provider_builder = provider_builder
                    .with_batch_exporter(fluxx_exporter, opentelemetry_sdk::runtime::Tokio);
                tracing::info!("fluxx telemetry enabled → {endpoint}");
            }
        }

        let provider = provider_builder.build();
        opentelemetry::global::set_tracer_provider(provider.clone());
        let otel_layer =
            tracing_opentelemetry::layer().with_tracer(provider.tracer("lynxx-gateway"));
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    let metrics_handle = metrics::install();
    metrics::describe();

    if config.gateway.auto_tune_kernel {
        kernel_tuning::apply_kernel_tuning();
    }

    // ---------- licence gate ----------
    // Validate the customer api key against auth.vexarr.com before
    // doing any other startup work. On success the result is cached
    // locally so later restarts work offline for up to 7 days. The
    // keyx-reported tier overrides config.gateway.plan_tier.
    let api_key = config.license.api_key.trim().to_string();
    if api_key.is_empty() {
        eprintln!("LYNXX_API_KEY (or [license].api_key) is required.");
        eprintln!("Get a key at https://lynxx.vexarr.com/account/api-keys");
        return Err(anyhow::anyhow!("LYNXX_API_KEY not set"));
    }

    let keyx_client = Arc::new(crate::integrations::keyx::KeyxClient::new()?);
    let _license_verifier: Arc<dyn crate::integrations::LicenseVerifier> = keyx_client.clone();
    // Admin tokens (other than the master api key) come from the local
    // `admin_tokens` table; HMAC plugin secrets come from local config.
    // No remote validators in the api-key-only model.
    let token_validator: Option<Arc<dyn crate::integrations::TokenValidator>> = None;
    let hmac_verifier: Option<Arc<dyn crate::integrations::HmacVerifier>> = None;

    let license = match crate::license::License::load(Some(&api_key)).await {
        Ok(lic) => {
            tracing::info!(
                customer_id = %lic.customer_id,
                tier = %lic.tier.as_str(),
                from_cache = lic.from_cache,
                "licence verified"
            );
            if let Some(days) = lic.days_remaining() {
                if days <= 14 {
                    tracing::warn!(days_remaining = days, "licence expires soon — renew to avoid downtime");
                }
            }
            config.gateway.plan_tier = lic.tier.as_str().to_string();
            lic
        }
        Err(err) => {
            eprintln!("licence verification failed: {err}");
            eprintln!("This Lynxx binary requires an active subscription.");
            eprintln!("Get a key at https://lynxx.vexarr.com/account/api-keys");
            return Err(anyhow::anyhow!("licence required: {err}"));
        }
    };

    tracing::info!(
        proxy_port = config.gateway.proxy_port,
        admin_port = config.gateway.admin_port,
        customer = %license.customer_id,
        "starting lynxx gateway"
    );

    let repo: Arc<dyn Repository> = crate::db::connect(&config.gateway.database_url).await?;
    tracing::info!(database_url = %config.gateway.database_url, "database ready");

    // Config-seeded rows are tagged `source = 'config'`; admin-API rows
    // are `source = 'api'`. Seeding only replaces config-sourced entries,
    // so dynamic state created via the admin API always survives.
    if args.reseed || config.gateway.seed_from_config {
        tracing::info!("syncing config.toml → database (config-sourced rows only)");
        repo.seed_from_config(&config).await?;
    }

    // Admin auth is always enforced. The license API key (lnx_live_...)
    // serves as the master admin credential — no separate token creation
    // needed. Customers use the same key from their lynxx.vexarr.com account.
    tracing::info!("admin API auth enforced via license key + stored tokens");

    let route_table = Arc::new(RouteTable::new());
    let (svc_count, route_count) = route_table.load_from_repo(repo.as_ref()).await?;
    let plugin_count = repo.list_plugins().await?.len();
    let consumer_count = repo.list_consumers().await?.len();
    tracing::info!(
        services = svc_count,
        routes = route_count,
        plugins = plugin_count,
        consumers = consumer_count,
        "loaded persisted state"
    );

    let plugin_ctx = crate::plugins::PluginContext {
        hmac_verifier: hmac_verifier.clone(),
    };
    let plugin_exec = Arc::new(PluginExecutor::new_with_context(license.tier, plugin_ctx));
    plugin_exec.rebuild(&repo).await?;
    tracing::info!("plugin executor ready");

    // WASM hot-reload listener. The file watcher inside PluginExecutor
    // polls registered `.wasm` module paths for mtime changes. When one
    // changes it fires `reload_signal`; this task catches that and
    // rebuilds all plugins from the DB so the new module is compiled and
    // swapped in without a gateway restart.
    {
        let signal = plugin_exec.reload_signal.clone();
        let exec = plugin_exec.clone();
        let repo = repo.clone();
        tokio::spawn(async move {
            loop {
                signal.notified().await;
                tracing::info!("wasm hot-reload: rebuilding plugins");
                if let Err(e) = exec.rebuild(&repo).await {
                    tracing::error!(error = %e, "wasm hot-reload: rebuild failed");
                }
            }
        });
    }

    // Streaming hyper-util client used by the proxy hot path (HTTP/1.1 + h2
    // via ALPN). Separate from the `reqwest::Client` used by the health
    // checker and out-of-band plugins (oauth2-introspect) — those benefit
    // from reqwest's higher-level conveniences and aren't latency-critical.
    let http_client_cfg = crate::proxy::http_client::HttpClientConfig {
        pool_max_idle_per_host: config.gateway.pool_max_idle_per_host,
        pool_idle_timeout_secs: config.gateway.pool_idle_timeout_secs,
        h2_keepalive_interval_secs: config.gateway.h2_keepalive_interval_secs,
        max_header_size: config.gateway.max_header_size,
    };
    let http_client = crate::proxy::http_client::build_http_proxy_client(&http_client_cfg)?;
    let health_http_client = reqwest::Client::new();
    let grpc_client = crate::proxy::grpc::build_grpc_client();

    let health_config = HealthConfig {
        failure_threshold: config.gateway.health_circuit_failure_threshold,
        success_threshold: config.gateway.health_circuit_success_threshold,
        open_duration_ms: config.gateway.health_circuit_open_duration_ms,
    };
    let health = Arc::new(HealthRegistry::with_config(health_config));
    let lb = Arc::new(LoadBalancerRegistry::new());
    for svc in route_table.list_services() {
        health.register(svc.id);
        let targets = repo.list_targets_for_service(&svc.id).await?;
        lb.rebuild_for_service(svc.id, LbStrategy::from_str(&svc.lb_strategy), targets);
    }

    let hc_config = Arc::new(health::checker::HealthCheckConfig::default());
    health::checker::spawn_health_checker(
        route_table.clone(),
        health.clone(),
        repo.clone(),
        lb.clone(),
        health_http_client,
        config.gateway.health_check_interval_ms,
        hc_config,
    );

    let passive_health = Arc::new(health::PassiveHealthTracker::default());

    let client_pool = Arc::new(
        crate::proxy::http_client::ProxyClientPool::new(http_client.clone(), http_client_cfg)
            .expect("init proxy client pool"),
    );

    // Quota tracker — load persisted monthly counters, start background flush.
    // The limit comes from the license server's verify response; falls back
    // to the hardcoded tier limit if the server didn't provide one.
    let plan_tier = crate::quota::PlanTier::from_str(&config.gateway.plan_tier);
    let quota =
        crate::quota::QuotaTracker::load(plan_tier, license.monthly_call_limit, repo.clone())
            .await?;
    quota.set_allow_overage(license.allow_overage);
    crate::quota::spawn_quota_flusher(quota.clone());

    // Live licence state + periodic re-verifier. The startup verify
    // above is hard-fail; this background loop catches mid-run
    // cancellations within REVERIFY_INTERVAL_SECS instead of waiting
    // for the offline cache to expire (7 days).
    let lynxx_base_url = std::env::var("LYNXX_BASE_URL")
        .or_else(|_| std::env::var("LYNXX_LICENSE_VERIFY_URL").map(|u| {
            u.trim_end_matches("/v1/license/verify").to_string()
        }))
        .unwrap_or_else(|_| "https://api.lynxx.vexarr.com".to_string());
    let lynxx_base_url = lynxx_base_url.trim_end_matches('/').to_string();
    let license_api_key = std::env::var("LYNXX_API_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| config.license.api_key.clone());
    let license_verify_url = format!("{}/v1/license/verify", lynxx_base_url);
    // Note: utilx::license::LicenseState handles expiry internally via its
    // ed25519-signed verify protocol, so we don't pass `license.expires_at`
    // here — my interim HMAC-cache hardening in src/license/mod.rs was
    // superseded by the utilx architecture.
    let license_state = crate::license::LicenseState::new(
        license_api_key.clone(),
        license_verify_url,
        plan_tier,
        license.active_nodes,
        license.max_nodes,
    );
    crate::license::spawn_license_refresher(
        license_state.clone(),
        Some(quota.clone() as std::sync::Arc<dyn utilx::license::QuotaControl>),
    );

    // Register this node with the billing API and start heartbeat.
    if let Err(e) = crate::license::register_node(&license_api_key, &lynxx_base_url).await {
        tracing::error!(error = %e, "node registration failed — gateway may not be tracked for billing");
    }
    crate::license::spawn_node_heartbeat(license_api_key.clone(), lynxx_base_url.clone());
    crate::license::spawn_usage_reporter(
        license_api_key.clone(),
        lynxx_base_url.clone(),
        quota.clone(),
        license_state.clone(),
    );

    // Verify that the io_uring accept thread (which is only hookable via the kTLS listener)
    // is not enabled without kernel_tls or on a non-Linux platform where it's a no-op.
    if config.gateway.io_uring.accept_thread_enabled
        && (!config.gateway.tls.kernel_tls || !crate::proxy::ktls_listener::supported_on_host())
    {
        tracing::warn!(
            "[gateway.io_uring].accept_thread_enabled = true but kernel_tls is false (or not supported on host); \
             the io_uring accept thread is a no-op. Enable kernel_tls on Linux to use io_uring accept acceleration."
        );
    }

    let trusted_proxies: Vec<ipnet::IpNet> = config
        .gateway
        .trusted_proxies
        .iter()
        .filter_map(|cidr| cidr.parse().ok())
        .collect();

    let deploy_registry = crate::admin::deploy::new_deploy_registry();

    let log_writer = crate::logs::LogWriter::new(repo.clone(), 4096);
    crate::logs::spawn_log_pruner(repo.clone(), 30);

    // Active health is effectively disabled when the interval is ≥1 hour
    // — at that cadence the per-request passive emission isn't being
    // consumed by anyone with useful freshness, so we can skip it entirely
    // on the hot path. The flag is sticky for the lifetime of the process;
    // we'd need to rewire on a runtime reload to flip it back on.
    let passive_record_disabled = config.gateway.health_check_interval_ms >= 3_600_000;

    let proxy_state = ProxyState {
        route_table: route_table.clone(),
        plugins: plugin_exec.clone(),
        log_writer,
        trusted_proxies,
        http_client: http_client.clone(),
        client_pool: client_pool.clone(),
        grpc_client,
        health: health.clone(),
        lb: lb.clone(),
        passive_health: passive_health.clone(),
        quota: quota.clone(),
        license: license_state.clone(),
        deploy_registry: Some(deploy_registry.clone()),
        local_zone: None,
        minimal_telemetry: config.gateway.minimal_telemetry,
        stream_response_body: config.gateway.stream_response_body,
        passive_record_disabled,
    };

    // Background connection pre-warmer. Keeps the upstream pool hot so
    // previously-idle services don't pay a TCP+TLS handshake on the next
    // real request — one of the bigger contributors to the p99.9 long
    // tail. Disabled when `prewarm_interval_secs == 0`.
    //
    // The shared `PrewarmState` lets both paths (the startup burst-warm
    // below and the periodic top-up here) bump the same per-service
    // idle-conn counters.
    let prewarm_state = crate::proxy::prewarm::PrewarmState::new();
    let _prewarm_handle = crate::proxy::prewarm::spawn_prewarmer(
        route_table.clone(),
        client_pool.clone(),
        health.clone(),
        prewarm_state.clone(),
        config.gateway.prewarm_interval_secs,
        config.gateway.prewarm_concurrency,
        config.gateway.pool_idle_floor_per_host,
    );

    // Startup burst-warm: fill the upstream idle pool to the configured
    // floor BEFORE we start accepting client traffic. Without this the
    // first ~`pool_idle_floor` real requests after a fresh start each
    // pay a TCP+TLS handshake — exactly the gap to nginx that this work
    // is closing. 5s overall cap; whichever conns came back are in the
    // pool, the rest the periodic prewarmer will pick up on the next
    // tick.
    if config.gateway.pool_idle_floor_per_host.is_some()
        || route_table
            .list_services()
            .iter()
            .any(|s| s.pool_idle_floor.is_some())
    {
        crate::proxy::prewarm::burst_warm(
            &route_table,
            &client_pool,
            &health,
            &prewarm_state,
            config.gateway.pool_idle_floor_per_host,
            config.gateway.prewarm_concurrency,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(2),
        )
        .await;
    }

    // ---------- ACME / cert manager ----------
    // Derive wildcard domains from route hosts so the ACME config doesn't
    // need a static `domains` list — the DB is the source of truth.
    if config.gateway.acme.enabled {
        let db_domains = derive_acme_domains_from_routes(&route_table);
        if !db_domains.is_empty() {
            let before = config.gateway.acme.domains.len();
            for d in db_domains {
                if !config.gateway.acme.domains.contains(&d) {
                    config.gateway.acme.domains.push(d);
                }
            }
            let added = config.gateway.acme.domains.len() - before;
            if added > 0 {
                tracing::info!(
                    added,
                    total = config.gateway.acme.domains.len(),
                    "derived ACME domains from route hosts"
                );
            }
        }
    }

    // Initialise before building the proxy app so we can inject the
    // challenge handler route and have a ServerConfig ready for bind.
    let acme_manager: Option<Arc<crate::proxy::acme::AcmeManager>> = if config.gateway.acme.enabled
    {
        let mut mgr = crate::proxy::acme::AcmeManager::new(config.gateway.acme.clone());
        // Bake kTLS-friendly secret extraction into the ServerConfig
        // builds inside the manager BEFORE init() runs — flipping the
        // flag after the initial cert load would leave the in-memory
        // ServerConfig opted out of secret extraction, and the kTLS
        // upgrade would fail until the first renewal.
        if config.gateway.tls.kernel_tls && crate::proxy::ktls_listener::supported_on_host() {
            mgr.enable_kernel_tls();
        }
        let mgr = Arc::new(mgr);
        match mgr.init().await {
            Ok(true) => {
                tracing::info!("ACME cert manager initialised with certificate");
            }
            Ok(false) => {
                tracing::warn!(
                    "ACME cert manager initialised but no certificate available; \
                         the proxy will not serve HTTPS until a cert is provisioned"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "ACME cert manager init failed");
                return Err(anyhow::anyhow!("ACME init: {e}"));
            }
        }
        // Start background cert file watcher (polls every 30s) and the
        // auto-renewal loop (first tick ~10s, every 12h after). The renewal
        // loop is what actually drives initial ACME issuance — without it
        // nothing replaces a self-signed boot cert.
        mgr.spawn_cert_watcher();
        mgr.spawn_auto_renew();
        Some(mgr)
    } else {
        None
    };

    // Raise axum's default 2 MB body limit to 64 MB so the gateway can
    // forward large request bodies (file uploads, 5 MB+ API payloads, etc.)
    // without returning 413. Kong defaults to 64 MB; we match it.
    //
    // When ACME is enabled, mount the HTTP-01 challenge responder at
    // `/.well-known/acme-challenge/*` so ACME validators can reach it
    // even on the plain-HTTP listener. The challenge route runs before
    // the catch-all proxy fallback.
    let proxy_app = {
        let router = axum::Router::new();
        let router = if let Some(ref mgr) = acme_manager {
            let mgr_clone = Arc::clone(mgr);
            router.route(
                "/.well-known/acme-challenge/{token}",
                axum::routing::get(
                    move |axum::extract::Path(token): axum::extract::Path<String>| {
                        let mgr = Arc::clone(&mgr_clone);
                        async move {
                            let full_path = format!("/.well-known/acme-challenge/{token}");
                            match mgr.handle_challenge(&full_path) {
                                Some(auth) => (
                                    axum::http::StatusCode::OK,
                                    [(axum::http::header::CONTENT_TYPE, "text/plain")],
                                    auth,
                                )
                                    .into_response(),
                                None => (axum::http::StatusCode::NOT_FOUND, "challenge not found")
                                    .into_response(),
                            }
                        }
                    },
                ),
            )
        } else {
            router
        };
        let proxy_router = router
            .fallback(proxy_handler)
            .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
            .layer(tower_http::trace::TraceLayer::new_for_http())
            // Wrap in `Arc` so axum's per-request `State` extractor clones
            // exactly one atomic refcount instead of cloning every one of
            // ProxyState's ~8 internal `Arc<...>` fields. The symbolized
            // perf record at 100k RPS / 4096 conns showed `drop_in_place
            // <ProxyState>` and its child `drop_in_place<Client>` totalling
            // ~14% of CPU samples — pure cache-line ping-pong from
            // per-request fan-out clones of state-resident `Arc`s.
            .with_state(std::sync::Arc::new(proxy_state));

        // Mount the install endpoints. Their routes take precedence over the
        // proxy fallback because merge() resolves explicit routes before the
        // fallback runs. Scripts and the /v1/install/binary streamer are
        // self-contained — they don't share state with the proxy pipeline.
        let install_state = Arc::new(install::InstallState::new());
        install::router(install_state).merge(proxy_router)
    };

    metrics::spawn_metrics_collector(route_table.clone(), repo.clone(), health.clone(), 5_000);

    // ---------- cluster bus ----------
    let node_id = Uuid::new_v4();
    tracing::info!(node_id = %node_id, "cluster node id assigned");
    let bus = repo.cluster_bus();

    let _subscriber_handle = spawn_cluster_subscriber(
        node_id,
        bus.clone(),
        repo.clone(),
        route_table.clone(),
        health.clone(),
        lb.clone(),
        plugin_exec.clone(),
        client_pool.clone(),
    );

    let reload_handle = reload::spawn_reloader(
        config_path.clone(),
        repo.clone(),
        route_table.clone(),
        health.clone(),
        lb.clone(),
        plugin_exec.clone(),
        bus.clone(),
        node_id,
    );
    reload::install_sighup_handler(reload_handle.clone());

    // ---------- Docker provider ----------
    // Optional. When enabled, watches the Docker socket and registers
    // services + routes from container labels — same shape as
    // Traefik's Docker provider. Failure here logs and continues —
    // gateway should still serve config-defined routes even if the
    // Docker socket isn't reachable.
    if config.gateway.providers.docker.enabled {
        let docker_cfg = config.gateway.providers.docker.clone();
        let docker_repo = repo.clone();
        let docker_bus = bus.clone();
        match crate::discovery::docker::DockerProvider::connect(
            docker_cfg,
            docker_repo,
            docker_bus,
            node_id,
        )
        .await
        {
            Ok(provider) => {
                tracing::info!("docker provider connected; watching Docker socket");
                provider.spawn();
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "docker provider connect failed; continuing without docker discovery"
                );
            }
        }
    }

    // ---------- SRV DNS provider ----------
    if config.gateway.providers.srv_dns.enabled {
        let srv_cfg = config.gateway.providers.srv_dns.clone();
        match crate::discovery::srv_dns::SrvDnsProvider::new(srv_cfg, repo.clone(), bus.clone()) {
            Ok(provider) => {
                tracing::info!("srv-dns provider started; polling SRV records");
                provider.spawn();
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "srv-dns provider init failed; continuing without DNS discovery"
                );
            }
        }
    }

    // Recording store + replay HTTP client. Both are owned by AdminState
    // for the recording API; the request-recorder plugin builds its own
    // store independently from its plugin config so the two don't share
    // a singleton.
    let recording_dir = config
        .gateway
        .recordings_directory
        .clone()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".lynxx").join("recordings"))
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/lynxx/recordings"))
                .to_string_lossy()
                .into_owned()
        });
    let recording_store = Arc::new(crate::recording::ContentAddressedStore::new(recording_dir));
    let admin_http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client builds");

    let start_time = chrono::Utc::now();
    let initial_status = health::status_cache::build_status(
        &route_table,
        &repo,
        &Some(license_state.clone()),
        &license_api_key,
        start_time,
    )
    .await;
    let status_cache = health::StatusCache::new(initial_status);
    health::status_cache::spawn_status_updater(
        status_cache.clone(),
        route_table.clone(),
        repo.clone(),
        Some(license_state.clone()),
        license_api_key.clone(),
        start_time,
        5_000,
    );

    // Token validator handed to the admin-auth middleware. None in the
    // api-key-only model — admin tokens come from the local
    // `admin_tokens` table; the master api key is matched directly.
    let admin_token_validator = token_validator.clone();
    let admin_token_cache: Option<Arc<crate::auth::middleware::AdminAuthCache>> = None;

    let userx_client = if let (Some(ref url), Some(ref key)) = (config.gateway.userx_url.as_ref(), config.gateway.userx_service_key.as_ref()) {
        let transport = utilx::vexarr::client::transport::reqwest_transport(url, std::time::Duration::from_secs(10))
            .map_err(|e| anyhow::anyhow!("userx transport error: {e}"))?;
        Some(Arc::new(utilx::vexarr::client::UserxClient::new(transport, (*key).clone())))
    } else {
        None
    };

    let admin_app = admin::admin_router(
        route_table,
        repo,
        health,
        lb,
        metrics_handle,
        reload_handle,
        plugin_exec,
        bus,
        node_id,
        config.gateway.auth_required,
        client_pool.clone(),
        recording_store,
        admin_http_client,
        config.gateway.proxy_port,
        quota.clone(),
        acme_manager.clone(),
        license_api_key.clone(),
        Some(license_state),
        config.clone(),
        deploy_registry,
        status_cache,
        admin_token_validator,
        admin_token_cache,
        userx_client,
    );

    let bind_addr = config.gateway.bind_address.clone();
    let strict_port = config.gateway.strict_port;

    let admin_tls_enabled = config.gateway.admin_tls.enabled;
    let admin_bind = utilities::resilient_bind(&utilities::BindConfig::new(
        &bind_addr,
        config.gateway.admin_port,
        strict_port,
    ))
    .await?;
    let actual_admin_port = admin_bind.port;
    let admin_listener = admin_bind.listener;
    if actual_admin_port != config.gateway.admin_port {
        tracing::warn!(
            configured = config.gateway.admin_port,
            actual = actual_admin_port,
            "admin port changed due to fallback"
        );
        config.gateway.admin_port = actual_admin_port;
    }
    let admin_addr = format!("{}:{}", bind_addr, actual_admin_port);
    let admin_scheme = if admin_tls_enabled { "https" } else { "http" };
    tracing::info!(addr = %admin_addr, tls = admin_tls_enabled, "admin API listening");
    tracing::info!("Dashboard available at {admin_scheme}://localhost:{actual_admin_port}");
    tracing::info!("admin listening on {admin_addr}");

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    {
        let n = shutdown_notify.clone();
        tokio::spawn(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = sigterm.recv() => tracing::info!("SIGTERM received, draining connections…"),
                res = tokio::signal::ctrl_c() => {
                    if res.is_ok() {
                        tracing::info!("SIGINT received, draining connections…");
                    }
                }
            }
            n.notify_waiters();
        });
    }

    // ---------- ACME HTTP Listener (Challenges + Redirect) ----------
    // Spawn a plain-HTTP listener for ACME HTTP-01 challenges and
    // HTTP→HTTPS redirects. This must run even if no cert exists yet,
    // otherwise we can never complete the first challenge.
    let acme_http_handle = if let Some(ref mgr) = acme_manager {
        let http_port = config.gateway.acme.http_port;
        let https_port = config.gateway.acme.external_https_port;
        if http_port > 0 {
            let acme_mgr = Arc::clone(mgr);
            Some(tokio::spawn(async move {
                let addr = format!("0.0.0.0:{http_port}");
                let listener = match TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("ACME HTTP listener bind {addr}: {e}");
                        return;
                    }
                };
                tracing::info!("ACME HTTP listener on {addr} (challenges + redirect)");

                let app = axum::Router::new()
                    .route(
                        "/.well-known/acme-challenge/{token}",
                        axum::routing::get({
                            let mgr = acme_mgr;
                            move |axum::extract::Path(token): axum::extract::Path<String>| {
                                let mgr = Arc::clone(&mgr);
                                async move {
                                    let full = format!("/.well-known/acme-challenge/{token}");
                                    match mgr.handle_challenge(&full) {
                                        Some(auth) => (
                                            axum::http::StatusCode::OK,
                                            [(axum::http::header::CONTENT_TYPE, "text/plain")],
                                            auth,
                                        )
                                            .into_response(),
                                        None => (axum::http::StatusCode::NOT_FOUND, "not found")
                                            .into_response(),
                                    }
                                }
                            }
                        }),
                    )
                    .fallback(
                        move |req: axum::http::Request<axum::body::Body>| async move {
                            let host = req
                                .headers()
                                .get(axum::http::header::HOST)
                                .and_then(|v| v.to_str().ok())
                                .map(|h| h.split(':').next().unwrap_or(h))
                                .unwrap_or("localhost");
                            let path = req
                                .uri()
                                .path_and_query()
                                .map(|p| p.as_str())
                                .unwrap_or("/");
                            let port_suffix = if https_port == 443 {
                                String::new()
                            } else {
                                format!(":{https_port}")
                            };
                            let location = format!("https://{host}{port_suffix}{path}");
                            (
                                axum::http::StatusCode::MOVED_PERMANENTLY,
                                [(axum::http::header::LOCATION, location)],
                                "",
                            )
                                .into_response()
                        },
                    );

                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("ACME HTTP listener error: {e}");
                }
            }))
        } else {
            None
        }
    } else {
        None
    };

    // ---------- Proxy Listener ----------
    // Pre-bind the proxy socket with resilient_bind (SO_REUSEADDR, retry,
    // fallback) so all TLS/non-TLS branches share the same listener.
    let proxy_bind = utilities::resilient_bind(&utilities::BindConfig::new(
        &bind_addr,
        config.gateway.proxy_port,
        strict_port,
    ))
    .await?;
    let actual_proxy_port = proxy_bind.port;
    let proxy_listener = proxy_bind.listener;
    if actual_proxy_port != config.gateway.proxy_port {
        tracing::warn!(
            configured = config.gateway.proxy_port,
            actual = actual_proxy_port,
            "proxy port changed due to fallback"
        );
        config.gateway.proxy_port = actual_proxy_port;
    }
    let proxy_addr = format!("{}:{}", bind_addr, actual_proxy_port);

    let acme_has_cert = if let Some(ref mgr) = acme_manager {
        mgr.has_cert().await
    } else {
        false
    };

    let admin_addr_socket: std::net::SocketAddr = admin_addr.parse()?;

    // Admin server: plain HTTP or HTTPS+mTLS depending on config.
    // Admin server: plain HTTP or HTTPS+mTLS depending on config.
    enum AdminServe {
        Plain(axum::serve::Serve<axum::Router, axum::Router>),
        Tls(axum_server::Handle),
    }

    let admin_serve_mode = if admin_tls_enabled {
        let admin_tls_cfg = &config.gateway.admin_tls;
        let server_config = crate::proxy::tls::build_admin_tls_config(admin_tls_cfg)?;
        let rustls_cfg =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        let app = admin_app.clone();
        drop(admin_listener);
        tokio::spawn(async move {
            if let Err(e) = axum_server::bind_rustls(admin_addr_socket, rustls_cfg)
                .handle(h)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
            {
                tracing::error!("admin TLS server error: {e}");
            }
        });
        tracing::info!(
            mtls = !admin_tls_cfg.client_ca_path.is_empty(),
            "admin API serving over TLS"
        );
        AdminServe::Tls(handle)
    } else {
        AdminServe::Plain(axum::serve(admin_listener, admin_app))
    };

    // Helper: run the proxy + admin select loop. When admin runs over
    // TLS it's already spawned as a background task — we just need to
    // shut it down gracefully. When admin is plain HTTP we await it
    // alongside the proxy.
    let shutdown_delay = std::time::Duration::from_secs(config.gateway.shutdown_delay_secs);
    let grace_period = std::time::Duration::from_secs(config.gateway.grace_period_secs);

    macro_rules! run_select {
        ($proxy_fut:expr, $shutdown_handle:expr) => {
            match admin_serve_mode {
                AdminServe::Plain(admin_serve) => {
                    tokio::select! {
                        _ = shutdown_notify.notified() => {
                            if !shutdown_delay.is_zero() {
                                tracing::info!(
                                    delay_secs = shutdown_delay.as_secs(),
                                    "shutdown delay: waiting for load balancer drain"
                                );
                                tokio::time::sleep(shutdown_delay).await;
                            }
                            tracing::info!(
                                grace_secs = grace_period.as_secs(),
                                "graceful shutdown: draining in-flight requests"
                            );
                            if let Some(ref h) = $shutdown_handle {
                                h.graceful_shutdown(Some(grace_period));
                            }
                        }
                        result = $proxy_fut => { if let Err(e) = result { tracing::error!("proxy server error: {e}"); } }
                        result = admin_serve => { if let Err(e) = result { tracing::error!("admin server error: {e}"); } }
                    }
                }
                AdminServe::Tls(admin_handle) => {
                    tokio::select! {
                        _ = shutdown_notify.notified() => {
                            if !shutdown_delay.is_zero() {
                                tracing::info!(
                                    delay_secs = shutdown_delay.as_secs(),
                                    "shutdown delay: waiting for load balancer drain"
                                );
                                tokio::time::sleep(shutdown_delay).await;
                            }
                            tracing::info!(
                                grace_secs = grace_period.as_secs(),
                                "graceful shutdown: draining in-flight requests"
                            );
                            if let Some(ref h) = $shutdown_handle {
                                h.graceful_shutdown(Some(grace_period));
                            }
                            admin_handle.graceful_shutdown(Some(grace_period));
                        }
                        result = $proxy_fut => { if let Err(e) = result { tracing::error!("proxy server error: {e}"); } }
                    }
                }
            }
        };
    }

    if acme_has_cert {
        let mgr = acme_manager.as_ref().unwrap();

        // ACME + kTLS path: register a watch channel with the manager
        // so cert renewals reach the kTLS listener, then run our
        // custom accept loop instead of axum-server. The standard arm
        // below fetches `server_config()` directly because axum-server
        // takes an owned `Arc`; the kTLS arm doesn't need it because
        // `set_ktls_reload_handle` primes a Receiver with the current
        // config internally.
        if config.gateway.tls.kernel_tls && crate::proxy::ktls_listener::supported_on_host() {
            crate::proxy::ktls_listener::register_ktls_metrics();
            let config_rx = mgr.set_ktls_reload_handle().await?;
            let handle = crate::proxy::ktls_listener::KtlsHandle::new();
            let shutdown_handle = handle.clone();

            #[cfg(target_os = "linux")]
            let _io_uring_acceptor =
                maybe_spawn_io_uring_acceptor(&proxy_listener, &config.gateway.io_uring);
            #[cfg(not(target_os = "linux"))]
            log_io_uring_unavailable_if_requested(&config.gateway.io_uring);

            tracing::info!(
                "proxy listening on {proxy_addr} (TLS via ACME, kernel TLS offload enabled{}, \
                 domains={:?})",
                io_uring_log_suffix(&config.gateway.io_uring),
                config.gateway.acme.domains
            );

            #[cfg(target_os = "linux")]
            let serve = match _io_uring_acceptor {
                Some((_, rx)) => Box::pin(crate::proxy::ktls_listener::serve_with_io_uring(
                    proxy_listener,
                    rx,
                    config_rx,
                    proxy_app,
                    handle,
                ))
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>,
                    >,
                None => Box::pin(crate::proxy::ktls_listener::serve(
                    proxy_listener,
                    config_rx,
                    proxy_app,
                    handle,
                )),
            };
            #[cfg(not(target_os = "linux"))]
            let serve =
                crate::proxy::ktls_listener::serve(proxy_listener, config_rx, proxy_app, handle);

            run_select!(serve, Some(shutdown_handle));
        } else {
            if config.gateway.tls.kernel_tls {
                tracing::warn!(
                    "kernel_tls=true requested on the ACME path but the host is not Linux; \
                     falling back to userspace TLS via axum-server."
                );
            }
            let server_config = mgr.server_config().await?;
            tracing::info!(
                "proxy listening on {proxy_addr} (TLS via ACME, domains={:?})",
                config.gateway.acme.domains
            );
            let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
            mgr.set_tls_reload_handle(rustls_cfg.clone()).await;
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            let std_listener = proxy_listener.into_std()?;
            let serve = axum_server::from_tcp_rustls(std_listener, rustls_cfg)
                .handle(handle)
                .serve(proxy_app.into_make_service());
            run_select!(serve, Some(shutdown_handle));
        }
    } else if config.gateway.tls.enabled {
        // kTLS opt-in: bypass axum-server entirely and run the custom
        // accept loop that upgrades each connection to kernel TLS after
        // the rustls handshake completes. Linux only; on other hosts
        // we log a warning and fall through to the standard path.
        if config.gateway.tls.kernel_tls && crate::proxy::ktls_listener::supported_on_host() {
            crate::proxy::ktls_listener::register_ktls_metrics();
            let server_config =
                crate::proxy::ktls_listener::build_server_config_for_ktls(&config.gateway.tls)?;
            // Static-cert path: build a watch channel with the single
            // never-changing ServerConfig. Holding the Sender keeps the
            // Receiver alive for the listener's lifetime.
            let (config_tx, config_rx) = tokio::sync::watch::channel(Arc::new(server_config));
            let handle = crate::proxy::ktls_listener::KtlsHandle::new();
            let shutdown_handle = handle.clone();

            // Optional io_uring accept thread (Linux-only). When the
            // probe says yes and the operator opted in, we replace the
            // tokio accept call with a channel fed by `IoUringAcceptor`.
            // The acceptor + listener must outlive the serve future,
            // so they're bound in this scope.
            #[cfg(target_os = "linux")]
            let _io_uring_acceptor =
                maybe_spawn_io_uring_acceptor(&proxy_listener, &config.gateway.io_uring);
            #[cfg(not(target_os = "linux"))]
            log_io_uring_unavailable_if_requested(&config.gateway.io_uring);

            tracing::info!(
                "proxy listening on {proxy_addr} (TLS{}, kernel TLS offload enabled{})",
                if config.gateway.tls.mtls_enabled() {
                    ", mTLS"
                } else {
                    ""
                },
                io_uring_log_suffix(&config.gateway.io_uring),
            );

            #[cfg(target_os = "linux")]
            let serve = match _io_uring_acceptor {
                Some((_, rx)) => Box::pin(crate::proxy::ktls_listener::serve_with_io_uring(
                    proxy_listener,
                    rx,
                    config_rx,
                    proxy_app,
                    handle,
                ))
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>,
                    >,
                None => Box::pin(crate::proxy::ktls_listener::serve(
                    proxy_listener,
                    config_rx,
                    proxy_app,
                    handle,
                )),
            };
            #[cfg(not(target_os = "linux"))]
            let serve =
                crate::proxy::ktls_listener::serve(proxy_listener, config_rx, proxy_app, handle);

            run_select!(serve, Some(shutdown_handle));
            // Keep `config_tx` alive across the serve future. The Drop
            // would close the watch channel and cause the listener
            // future to error; tying it to this scope via a no-op
            // `drop` keeps the borrow checker satisfied.
            drop(config_tx);
        } else {
            if config.gateway.tls.kernel_tls {
                tracing::warn!(
                    "kernel_tls=true requested but the host is not Linux; \
                     falling back to userspace TLS. Rebuild the binary on Linux \
                     to benefit from kTLS offload."
                );
            }
            let server_config = crate::proxy::tls::build_server_config(&config.gateway.tls)?;
            tracing::info!(
                "proxy listening on {proxy_addr} (TLS{})",
                if config.gateway.tls.mtls_enabled() {
                    ", mTLS"
                } else {
                    ""
                }
            );
            let rustls_cfg =
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            let std_listener = proxy_listener.into_std()?;
            let serve = axum_server::from_tcp_rustls(std_listener, rustls_cfg)
                .handle(handle)
                .serve(proxy_app.into_make_service());
            run_select!(serve, Some(shutdown_handle));
        }
    } else if config.gateway.acme.enabled {
        tracing::warn!(
            "ACME enabled but no certificate available; waiting for background provisioning..."
        );
        let proxy_addr_socket: std::net::SocketAddr = proxy_addr.parse()?;
        let proxy_serve = serve_proxy_plain(proxy_listener, proxy_addr_socket, proxy_app);
        run_select!(proxy_serve, None::<axum_server::Handle>);
    } else {
        tracing::info!("proxy listening on {proxy_addr}");
        let proxy_addr_socket: std::net::SocketAddr = proxy_addr.parse()?;
        let proxy_serve = serve_proxy_plain(proxy_listener, proxy_addr_socket, proxy_app);
        run_select!(proxy_serve, None::<axum_server::Handle>);
    }

    crate::license::deregister_node(&license_api_key, &lynxx_base_url).await;

    if let Some(h) = acme_http_handle {
        h.abort();
    }

    // Flush any pending OTel spans before exit.
    opentelemetry::global::shutdown_tracer_provider();

    Ok(())
}

/// Serve the proxy on the plain (no TLS) listener path. On Linux this
/// dispatches to [`crate::proxy::listener::serve_per_worker`], which
/// fans out N independent `SO_REUSEPORT` listeners across N OS threads
/// each running a private `current_thread` tokio runtime + `LocalSet`.
/// The kernel's socket-hash spreads incoming SYN packets across those
/// listeners, so a connection enters one thread on accept() and stays
/// there for its whole lifetime — no work-stealing migration, no
/// cross-worker cache-line traffic.
///
/// On non-Linux platforms the fanout is not available (Darwin's
/// `SO_REUSEPORT` doesn't load-balance; it just lets multiple binds
/// coexist). We fall back to the single-listener path so contributors
/// on macOS still get a working `cargo run`.
///
/// `proxy_listener` is the resilient-bind socket built in `async_main`
/// — used as-is on non-Linux. On Linux it's dropped here because each
/// per-worker thread re-binds its own `SO_REUSEPORT` socket; the brief
/// drop-then-rebind window (microseconds) is acceptable on a
/// single-tenant proxy host. `proxy_addr` is the resolved bind address
/// (after any fallback in resilient_bind), used by the per-worker
/// path to re-bind.
async fn serve_proxy_plain(
    proxy_listener: tokio::net::TcpListener,
    proxy_addr: std::net::SocketAddr,
    proxy_app: axum::Router,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Release the resilient_bind listener so the per-worker
        // sockets can rebind to the same port. Without this the kernel
        // would distribute incoming connections across the original
        // single listener (which we'd never accept from) *and* the
        // workers, and the orphan listener's share of connections
        // would time out. Drop is synchronous; the worker rebinds
        // typically complete within a few microseconds.
        drop(proxy_listener);
        let core_ids = core_affinity::get_core_ids().unwrap_or_default();
        let workers = num_cpus::get().max(1);
        tracing::info!(
            workers,
            cores = core_ids.len(),
            "proxy: launching per-worker SO_REUSEPORT runtimes"
        );
        crate::proxy::listener::serve_per_worker(proxy_addr, proxy_app, workers, core_ids).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        // proxy_addr is unused on non-Linux; the listener is already
        // bound. Silence the warning explicitly so the linter stays
        // useful elsewhere.
        let _ = proxy_addr;
        axum::serve(proxy_listener, proxy_app).await
    }
}

/// Spawn a task that subscribes to the cluster bus and refreshes local
/// in-memory state when a remote node mutates the DB. Self-published
/// events are filtered by `node_id` inside the bus implementation.
fn spawn_cluster_subscriber(
    node_id: Uuid,
    bus: Arc<dyn cluster::ClusterBus>,
    repo: Arc<dyn Repository>,
    route_table: SharedRouteTable,
    health: Arc<HealthRegistry>,
    lb: Arc<LoadBalancerRegistry>,
    plugin_exec: Arc<PluginExecutor>,
    client_pool: Arc<crate::proxy::http_client::ProxyClientPool>,
) -> tokio::task::JoinHandle<()> {
    let handler: cluster::ChangeHandler = Arc::new(move |event: ChangeEvent| {
        let repo = repo.clone();
        let route_table = route_table.clone();
        let health = health.clone();
        let lb = lb.clone();
        let plugin_exec = plugin_exec.clone();
        let client_pool = client_pool.clone();
        Box::pin(async move {
            if let Err(e) = apply_remote_event(
                event,
                &repo,
                &route_table,
                &health,
                &lb,
                &plugin_exec,
                &client_pool,
            )
            .await
            {
                tracing::warn!(error = %e, "failed to apply remote cluster event");
            }
        })
    });
    bus.subscribe(node_id, handler)
}

/// Apply a remote `ChangeEvent` by re-fetching the affected entity from the
/// repository and updating local in-memory state. The DB is the source of
/// truth — events only carry IDs.
async fn apply_remote_event(
    event: ChangeEvent,
    repo: &Arc<dyn Repository>,
    route_table: &SharedRouteTable,
    health: &Arc<HealthRegistry>,
    lb: &Arc<LoadBalancerRegistry>,
    plugin_exec: &Arc<PluginExecutor>,
    client_pool: &Arc<crate::proxy::http_client::ProxyClientPool>,
) -> Result<(), error::GatewayError> {
    match event {
        ChangeEvent::ServiceCreated { id, .. } | ChangeEvent::ServiceUpdated { id, .. } => {
            match repo.get_service(&id).await? {
                Some(svc) => {
                    let old_svc = route_table.get_service(&id);
                    let is_new = old_svc.is_none();
                    let url_changed = old_svc
                        .as_ref()
                        .map(|old| old.url != svc.url)
                        .unwrap_or(false);
                    route_table.add_service(svc.clone());
                    if is_new {
                        health.register(svc.id);
                    } else if url_changed {
                        health.reset_on_upstream_change(&svc.id, &svc.name, "upstream URL changed");
                    }
                    // Drop any cached per-service TLS client. The pool
                    // rebuilds on the next request using the fresh row.
                    client_pool.invalidate(&svc.id);
                    let targets = repo.list_targets_for_service(&id).await?;
                    lb.rebuild_for_service(svc.id, LbStrategy::from_str(&svc.lb_strategy), targets);
                }
                None => {
                    tracing::warn!(
                        service_id = %id,
                        "remote ServiceCreated/Updated but row missing in DB"
                    );
                }
            }
        }
        ChangeEvent::ServiceDeleted { id, .. } => {
            route_table.remove_service(&id);
            health.unregister(&id);
            lb.remove_service(&id);
            client_pool.invalidate(&id);
        }
        ChangeEvent::RouteCreated { id, .. } | ChangeEvent::RouteUpdated { id, .. } => {
            match repo.get_route(&id).await? {
                Some(route) => {
                    route_table.add_route(route);
                }
                None => {
                    tracing::warn!(
                        route_id = %id,
                        "remote RouteCreated/Updated but row missing in DB"
                    );
                }
            }
        }
        ChangeEvent::RouteDeleted { id, .. } => {
            route_table.remove_route(&id);
        }
        ChangeEvent::TargetChanged { service_id, .. } => {
            match route_table.get_service(&service_id) {
                Some(svc) => {
                    let targets = repo.list_targets_for_service(&service_id).await?;
                    lb.rebuild_for_service(
                        service_id,
                        LbStrategy::from_str(&svc.lb_strategy),
                        targets,
                    );
                    health.reset_on_upstream_change(&service_id, &svc.name, "targets changed");
                }
                None => {
                    tracing::warn!(
                        service_id = %service_id,
                        "remote TargetChanged for unknown service; ignoring"
                    );
                }
            }
        }
        ChangeEvent::PluginChanged { .. } => {
            plugin_exec.rebuild(repo).await?;
        }
        ChangeEvent::ProjectChanged { .. } => {
            // Projects are metadata-only; no in-memory state to refresh.
        }
        ChangeEvent::ConsumerChanged { .. } => {
            // Consumers are read on-demand by basic-auth/key-auth/hmac-auth
            // plugins; nothing in-memory to refresh.
        }
        ChangeEvent::FullSync { .. } => {
            route_table.load_from_repo(repo.as_ref()).await?;
            for svc in route_table.list_services() {
                health.register(svc.id);
                let targets = repo.list_targets_for_service(&svc.id).await?;
                lb.rebuild_for_service(svc.id, LbStrategy::from_str(&svc.lb_strategy), targets);
            }
            plugin_exec.rebuild(repo).await?;
        }
    }
    Ok(())
}

/// Derive ACME wildcard domains from route hosts in the DB.
///
/// Scans every route's `hosts` list and produces wildcard entries:
///   `api.hostx.vexarr.com`  → `*.hostx.vexarr.com`, `*.vexarr.com`
///   `*.hostx.vexarr.com`    → kept as-is, plus `*.vexarr.com`
///   `vexarr.com`            → `*.vexarr.com`, `vexarr.com`
///   `*`                     → skipped (catchall)
fn derive_acme_domains_from_routes(route_table: &crate::proxy::router::RouteTable) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut domains = BTreeSet::new();

    for route in route_table.list_routes() {
        for host in &route.hosts {
            let host = host.trim().to_lowercase();
            if host.is_empty() || host == "*" {
                continue;
            }

            // Already a wildcard — keep it and derive the parent wildcard.
            if let Some(rest) = host.strip_prefix("*.") {
                domains.insert(host.clone());
                if let Some(parent) = parent_wildcard(rest) {
                    domains.insert(parent);
                }
                continue;
            }

            // Bare domain (vexarr.com) — add itself and *.vexarr.com.
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() == 2 {
                domains.insert(host.clone());
                domains.insert(format!("*.{host}"));
            } else if parts.len() > 2 {
                // Sub-domain — derive wildcard for the parent.
                let parent = &host[host.find('.').unwrap() + 1..];
                domains.insert(format!("*.{parent}"));
                // Also add a higher-level wildcard if there's enough depth.
                if let Some(grandparent) = parent_wildcard(parent) {
                    domains.insert(grandparent);
                }
            }
        }
    }

    domains.into_iter().collect()
}

fn parent_wildcard(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 3 {
        let parent = &domain[domain.find('.').unwrap() + 1..];
        Some(format!("*.{parent}"))
    } else {
        None
    }
}
