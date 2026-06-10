//! Background connection pre-warmer.
//!
//! Issues a cheap HEAD request to every known upstream every N seconds so
//! the hyper-util connection pool stays hot. Without this, an upstream
//! that's been idle for longer than the pool idle timeout (`120s`) costs a
//! TCP handshake on the next real request — which is exactly the long-tail
//! spike we're trying to eliminate from p99.9.
//!
//! Design notes:
//!
//! * Respects per-service circuit-breaker state. Services with `Open`
//!   circuits are skipped — pre-warming a known-broken upstream just
//!   wastes connections and skews health metrics.
//! * Per-tick concurrency is bounded (`prewarm_concurrency`) so we don't
//!   create a thundering herd against many upstreams at once.
//! * Failures are silent — we increment a counter and move on. Real
//!   health is tracked by `health::checker`, not here.
//! * Uses the per-service [`ProxyClientPool`] entry so mTLS upstreams
//!   pre-warm with their actual cert config — no mismatch.

use crate::health::{CircuitState, HealthRegistry};
use crate::proxy::http_client::ProxyClientPool;
use crate::proxy::router::SharedRouteTable;
use axum::body::Body;
use axum::http::{Method, Request, Uri};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Spawn the pre-warmer task. Returns immediately; the task runs forever
/// until the runtime shuts down. `interval_secs == 0` disables it.
pub fn spawn_prewarmer(
    route_table: SharedRouteTable,
    pool: Arc<ProxyClientPool>,
    health: Arc<HealthRegistry>,
    interval_secs: u64,
    concurrency: usize,
) -> Option<tokio::task::JoinHandle<()>> {
    if interval_secs == 0 {
        tracing::info!("connection pre-warmer disabled (prewarm_interval_secs = 0)");
        return None;
    }
    let concurrency = concurrency.max(1);
    tracing::info!(interval_secs, concurrency, "spawning connection pre-warmer");

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        // Skip the initial tick so we don't fire mid-startup before the
        // route table or health registry have been seeded.
        ticker.tick().await;

        let sem = Arc::new(Semaphore::new(concurrency));

        loop {
            ticker.tick().await;
            run_once(&route_table, &pool, &health, &sem).await;
        }
    });
    Some(handle)
}

async fn run_once(
    route_table: &SharedRouteTable,
    pool: &Arc<ProxyClientPool>,
    health: &Arc<HealthRegistry>,
    sem: &Arc<Semaphore>,
) {
    let services = route_table.list_services();
    let mut joinset = tokio::task::JoinSet::new();

    for svc in services {
        // Respect circuit-breaker state — pre-warming an Open circuit
        // wastes work and confuses health metrics. Closed and HalfOpen
        // are both fair game.
        if let Some(h) = health.get(&svc.id) {
            if matches!(h.circuit, CircuitState::Open) {
                continue;
            }
        }

        // Build the URL once. We use the service-level URL (not the
        // load-balancer-picked target) so the pool stays warm even when
        // a particular target is currently down.
        let url = svc.url.trim_end_matches('/').to_string();
        let uri: Uri = match url.parse() {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!(service = %svc.name, error = %e, "prewarm: skip bad url");
                continue;
            }
        };

        let pool = pool.clone();
        let svc_name = svc.name.clone();
        // `svc` is owned by this loop iteration and not used after this point,
        // so MOVE it into the task rather than cloning the whole Service a
        // second time (list_services already handed us an owned copy).
        let svc_clone = svc;
        let permit_owner = sem.clone();

        joinset.spawn(async move {
            // Bound concurrency.
            let _permit = match permit_owner.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };

            let client = match pool.client_for(&svc_clone) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(service = %svc_name, error = %e, "prewarm: build client");
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
                Err(_) => return,
            };

            // Cap each pre-warm at 2s so a slow upstream can't stall the
            // whole pre-warmer for the next interval.
            let fut = client.request(req);
            match tokio::time::timeout(Duration::from_secs(2), fut).await {
                Ok(Ok(_)) => {
                    metrics::counter!(
                        "lynxx_prewarm_total",
                        "service" => svc_name,
                        "result" => "ok",
                    )
                    .increment(1);
                }
                Ok(Err(_)) | Err(_) => {
                    metrics::counter!(
                        "lynxx_prewarm_total",
                        "service" => svc_name,
                        "result" => "error",
                    )
                    .increment(1);
                }
            }
        });
    }

    while joinset.join_next().await.is_some() {}
}
