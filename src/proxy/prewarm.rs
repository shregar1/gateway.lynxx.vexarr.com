//! Background connection pre-warmer.
//!
//! Maintains a floor of warm idle upstream connections so that bursty
//! traffic finds the hyper-util keep-alive pool already populated and
//! pays no TCP handshake on the hot path. This is the nginx
//! `keepalive 1024` analogue.
//!
//! Two entry points:
//!
//! * [`burst_warm`] — fired at startup, **before** the proxy accepts
//!   any client traffic. For every service the gateway knows about,
//!   it issues `pool_idle_floor` parallel `HEAD /` requests against
//!   the upstream and waits for all of them to finish (5 s overall
//!   cap). On success those sockets land in hyper-util's idle pool —
//!   the floor.
//!
//! * [`spawn_prewarmer`] — the long-running task. Every
//!   `prewarm_interval_secs` it tops the pool back up by issuing
//!   `max(0, pool_idle_floor - estimated_idle)` parallel HEADs per
//!   service. The estimate is tracked via a per-service AtomicUsize
//!   counter we bump on each successful HEAD response and reset on
//!   every tick (hyper-util's pool can drop conns at the
//!   `pool_idle_timeout` mark; we trust the pool to behave correctly
//!   between ticks and re-establish the floor on the next one).
//!
//! When the resolved floor is `0` (the default — neither the
//! per-service nor the global knob is set), both paths fall back to
//! the original single-HEAD-per-tick heartbeat that just keeps one
//! conn alive. That preserves behaviour for operators who haven't
//! opted in to the new floor.
//!
//! Design notes that carry over from the original heartbeat:
//!
//! * Respects per-service circuit-breaker state. Services with `Open`
//!   circuits are skipped — pre-warming a known-broken upstream just
//!   wastes connections and skews health metrics.
//! * Per-tick concurrency is bounded (`prewarm_concurrency`) so we
//!   don't create a thundering herd against many upstreams at once.
//! * Failures are silent — we increment a counter and move on. Real
//!   health is tracked by `health::checker`, not here.
//! * Uses the per-service [`ProxyClientPool`] entry so mTLS upstreams
//!   pre-warm with their actual cert config — no mismatch.

use crate::health::{CircuitState, HealthRegistry};
use crate::models::Service;
use crate::proxy::http_client::{HttpProxyClient, ProxyClientPool};
use crate::proxy::router::SharedRouteTable;
use axum::body::Body;
use axum::http::{Method, Request, Uri};
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Per-service prewarm bookkeeping.
///
/// `estimated_idle` is our best-effort guess at how many keep-alive
/// conns to this service are currently sitting in the hyper-util idle
/// pool. We bump it on every successful prewarm HEAD response and the
/// periodic tick reads it to decide how many top-up HEADs to fire. The
/// counter is intentionally per-service: each upstream host has its
/// own hyper-util pool depth so a shared global counter would be
/// meaningless.
///
/// `total_warmed` is monotonic — handy for observability (Prometheus,
/// admin endpoint) without inferring it from log lines.
#[derive(Debug, Default)]
struct ServicePrewarmState {
    estimated_idle: AtomicUsize,
    total_warmed: AtomicUsize,
    total_failed: AtomicUsize,
}

/// Cross-cutting state for the prewarmer. Wrapped in an `Arc` and
/// shared between the burst-warm path at startup and the periodic
/// top-up task; both update the same per-service counters.
#[derive(Debug, Default)]
pub struct PrewarmState {
    by_service: DashMap<Uuid, ServicePrewarmState>,
}

impl PrewarmState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn entry(&self, id: Uuid) -> dashmap::mapref::one::RefMut<'_, Uuid, ServicePrewarmState> {
        self.by_service.entry(id).or_default()
    }

    fn record_success(&self, id: Uuid) {
        let entry = self.entry(id);
        entry.estimated_idle.fetch_add(1, Ordering::Relaxed);
        entry.total_warmed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self, id: Uuid) {
        let entry = self.entry(id);
        entry.total_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the current estimated idle pool depth for a service. Used
    /// by the periodic tick to decide top-up volume.
    fn estimated_idle(&self, id: Uuid) -> usize {
        self.by_service
            .get(&id)
            .map(|e| e.estimated_idle.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Reset the per-service estimate at the start of a top-up tick.
    /// We can't introspect hyper-util's idle pool, so the next tick
    /// re-derives the count from its own successful HEADs only. This
    /// is conservative (we over-warm rather than under-warm) and the
    /// per-tick cap is small enough that the upstream cost is bounded.
    fn reset_estimate(&self, id: Uuid) {
        if let Some(entry) = self.by_service.get(&id) {
            entry.estimated_idle.store(0, Ordering::Relaxed);
        }
    }
}

/// Resolve the per-service idle-conn floor:
/// per-service knob > global default > 0 (feature off).
#[inline]
fn resolve_idle_floor(svc: &Service, global_default: Option<usize>) -> usize {
    svc.pool_idle_floor.or(global_default).unwrap_or(0)
}

/// Issue a single `HEAD /` to the service's upstream and report
/// success/failure to `PrewarmState`. Caller holds the concurrency
/// permit. Bounded by `per_request_timeout` so a slow upstream can't
/// stall the larger burst/top-up window.
async fn one_head(
    pool: &ProxyClientPool,
    state: &Arc<PrewarmState>,
    svc: &Service,
    uri: Uri,
    per_request_timeout: Duration,
) {
    let client: HttpProxyClient = match pool.client_for(svc) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(service = %svc.name, error = %e, "prewarm: build client");
            state.record_failure(svc.id);
            return;
        }
    };

    let req = match Request::builder()
        .method(Method::HEAD)
        .uri(uri)
        .header("user-agent", "lynxx-prewarm/1")
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(_) => {
            state.record_failure(svc.id);
            return;
        }
    };

    let fut = client.request(req);
    match tokio::time::timeout(per_request_timeout, fut).await {
        Ok(Ok(_resp)) => {
            // Hyper-util parks the underlying conn back in the idle
            // pool when the response body is dropped at the end of
            // `_resp`. HEAD has no body so this is immediate.
            state.record_success(svc.id);
            metrics::counter!(
                "lynxx_prewarm_total",
                "service" => svc.name.to_string(),
                "result" => "ok",
            )
            .increment(1);
        }
        Ok(Err(_)) | Err(_) => {
            state.record_failure(svc.id);
            metrics::counter!(
                "lynxx_prewarm_total",
                "service" => svc.name.to_string(),
                "result" => "error",
            )
            .increment(1);
        }
    }
}

/// Build the prewarm target URI from a service URL. Returns `None`
/// if the URL doesn't parse (we just skip that service).
fn target_uri(svc_url: &str) -> Option<Uri> {
    let base = svc_url.trim_end_matches('/');
    base.parse::<Uri>().ok()
}

/// Whether this service is currently OK to prewarm. We skip services
/// whose circuit-breaker is `Open` — pre-warming a known-broken
/// upstream just wastes connections and skews health metrics.
fn should_prewarm(svc: &Service, health: &HealthRegistry) -> bool {
    match health.get(&svc.id) {
        Some(h) => !matches!(h.circuit, CircuitState::Open),
        None => true,
    }
}

/// Fire `floor` parallel HEAD requests per service, in parallel across
/// services, and wait for all to settle (or `overall_timeout` to
/// elapse). Run this at startup **before** the proxy accepts traffic
/// so the first burst of real requests finds the pool already warm.
///
/// `concurrency_per_service` caps the per-service in-flight HEAD count
/// — the existing `prewarm_concurrency` knob plays double duty here so
/// operators get the same global ceiling as the periodic tick.
///
/// `overall_timeout` is a hard cap (default 5s): if a service
/// stubbornly doesn't respond we don't want the startup to hang. The
/// future just returns; conns that did come back are already in the
/// pool. The whole function logs a single summary line per service
/// (`prewarm: established <N>/<M> idle conns in <ms>ms`).
pub async fn burst_warm(
    route_table: &SharedRouteTable,
    pool: &Arc<ProxyClientPool>,
    health: &Arc<HealthRegistry>,
    state: &Arc<PrewarmState>,
    global_floor: Option<usize>,
    concurrency_per_service: usize,
    overall_timeout: Duration,
    per_request_timeout: Duration,
) {
    let services = route_table.list_services();
    if services.is_empty() {
        return;
    }

    let mut all = tokio::task::JoinSet::new();
    let started = Instant::now();

    for svc in services {
        if !should_prewarm(&svc, health) {
            continue;
        }
        let floor = resolve_idle_floor(&svc, global_floor);
        if floor == 0 {
            continue;
        }
        let Some(uri) = target_uri(&svc.url) else {
            tracing::debug!(service = %svc.name, "prewarm: skip bad url");
            continue;
        };

        // Cap the per-service in-flight HEADs to the configured
        // concurrency. Without this a floor=4096 service would
        // briefly hold 4096 sockets open during burst.
        let sem = Arc::new(Semaphore::new(concurrency_per_service.max(1)));
        let pool = pool.clone();
        let state = state.clone();
        let svc_arc = Arc::new(svc);

        all.spawn(async move {
            let svc_name = svc_arc.name.clone();
            let mut joinset = tokio::task::JoinSet::new();
            let started_svc = Instant::now();
            for _ in 0..floor {
                let pool = pool.clone();
                let state = state.clone();
                let svc = svc_arc.clone();
                let uri = uri.clone();
                let sem = sem.clone();
                joinset.spawn(async move {
                    let Ok(_permit) = sem.acquire_owned().await else {
                        return;
                    };
                    one_head(&pool, &state, &svc, uri, per_request_timeout).await;
                });
            }
            while joinset.join_next().await.is_some() {}
            let established = state.estimated_idle(svc_arc.id);
            tracing::info!(
                service = %svc_name,
                established,
                target = floor,
                elapsed_ms = started_svc.elapsed().as_millis() as u64,
                "prewarm: established idle conns",
            );
        });
    }

    let total = tokio::time::timeout(overall_timeout, async {
        while all.join_next().await.is_some() {}
    })
    .await;

    if total.is_err() {
        tracing::warn!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "prewarm: burst-warm overall timeout — some services may have an under-warmed pool",
        );
    }
}

/// Spawn the pre-warmer task. Returns immediately; the task runs forever
/// until the runtime shuts down. `interval_secs == 0` disables it.
///
/// `state` should be the same `Arc<PrewarmState>` used by [`burst_warm`]
/// so both paths share the per-service counters.
pub fn spawn_prewarmer(
    route_table: SharedRouteTable,
    pool: Arc<ProxyClientPool>,
    health: Arc<HealthRegistry>,
    state: Arc<PrewarmState>,
    interval_secs: u64,
    concurrency: usize,
    global_floor: Option<usize>,
) -> Option<tokio::task::JoinHandle<()>> {
    if interval_secs == 0 {
        tracing::info!("connection pre-warmer disabled (prewarm_interval_secs = 0)");
        return None;
    }
    let concurrency = concurrency.max(1);
    tracing::info!(
        interval_secs,
        concurrency,
        global_floor = ?global_floor,
        "spawning connection pre-warmer"
    );

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        // Skip the initial tick so we don't fire mid-startup before the
        // route table or health registry have been seeded.
        ticker.tick().await;

        let sem = Arc::new(Semaphore::new(concurrency));

        loop {
            ticker.tick().await;
            run_once(&route_table, &pool, &health, &state, &sem, global_floor).await;
        }
    });
    Some(handle)
}

async fn run_once(
    route_table: &SharedRouteTable,
    pool: &Arc<ProxyClientPool>,
    health: &Arc<HealthRegistry>,
    state: &Arc<PrewarmState>,
    sem: &Arc<Semaphore>,
    global_floor: Option<usize>,
) {
    let services = route_table.list_services();
    let mut joinset = tokio::task::JoinSet::new();

    for svc in services {
        if !should_prewarm(&svc, health) {
            continue;
        }

        let floor = resolve_idle_floor(&svc, global_floor);
        let estimated = state.estimated_idle(svc.id);
        // Top-up volume. When `floor == 0` (feature off for this
        // service), fall back to the original single-HEAD heartbeat
        // so behaviour matches the pre-floor build.
        let to_fire = if floor == 0 {
            1
        } else if estimated >= floor {
            // Reset estimate so the next tick can re-derive from its
            // own successful HEADs only; conservative on purpose.
            state.reset_estimate(svc.id);
            continue;
        } else {
            floor - estimated
        };

        let Some(uri) = target_uri(&svc.url) else {
            tracing::debug!(service = %svc.name, "prewarm: skip bad url");
            continue;
        };

        let pool = pool.clone();
        let state = state.clone();
        let svc_arc = Arc::new(svc);
        let sem = sem.clone();

        joinset.spawn(async move {
            // Reset the estimate at the START of the tick so successive
            // ticks can each re-derive their own count. We don't trust
            // hyper-util's pool between ticks because pool_idle_timeout
            // can drop conns silently in the gap.
            state.reset_estimate(svc_arc.id);
            let svc_name = svc_arc.name.clone();
            let started = Instant::now();
            let mut local = tokio::task::JoinSet::new();
            for _ in 0..to_fire {
                let pool = pool.clone();
                let state = state.clone();
                let svc = svc_arc.clone();
                let uri = uri.clone();
                let sem = sem.clone();
                local.spawn(async move {
                    let Ok(_permit) = sem.acquire_owned().await else {
                        return;
                    };
                    one_head(&pool, &state, &svc, uri, Duration::from_secs(2)).await;
                });
            }
            while local.join_next().await.is_some() {}
            let established = state.estimated_idle(svc_arc.id);
            if to_fire > 1 {
                tracing::debug!(
                    service = %svc_name,
                    established,
                    target = to_fire,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "prewarm: top-up complete",
                );
            }
        });
    }

    while joinset.join_next().await.is_some() {}
}
