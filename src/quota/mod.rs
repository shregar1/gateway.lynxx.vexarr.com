//! Monthly API call quota enforcement with overage support.
//!
//! Each Lynxx licence tier carries a monthly call limit:
//!
//!   free       →  1 000 000 calls / month  (hard block)
//!   pro        → 10 000 000 calls / month  (soft limit, overage billed)
//!   business   → 100 000 000 calls / month (soft limit, overage billed)
//!   enterprise →  unlimited
//!
//! Paid tiers allow overages: requests above the limit are still proxied
//! but flagged with `X-Lynxx-Overage: true`. The billing API charges per
//! million overage calls at the tier's rate.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, Utc};
use serde::Serialize;
use tokio::time::interval;
use tracing::{info, warn};

use crate::db::Repository;
use crate::error::GatewayError;

const FLUSH_INTERVAL_SECS: u64 = 30;

/// Number of `check_and_count` calls absorbed into a thread-local Cell
/// before the increment is flushed to the shared `calls` atomic. At 100k
/// RPS this turns the per-request `AtomicU64::fetch_add` into a thread-
/// local `Cell` write 63 calls out of 64 (the 64th call pays for the
/// batch). Drift between the shared count and the true call count is
/// bounded by `BATCH_SIZE × num_threads`, which for our usage (monthly
/// tier limits in the millions) is well inside precision tolerance.
///
/// The drift is one-sided when reading (the global undercounts in-flight
/// batches), which matters at two points:
///   * `snapshot()` — admin API; off by < BATCH_SIZE per thread, fine.
///   * `flush()` — periodic DB persist every 30s; same drift, fine.
///   * `check_and_count` itself — the comparison `(global + local_pending)
///     < limit` accounts for the current thread's pending count, so a
///     thread cannot fool itself into thinking it has more quota than it
///     does. Inter-thread drift can still cause a request to be classed
///     as Allowed when it is just past the boundary; the next batch flush
///     resyncs.
const QUOTA_BATCH_SIZE: u32 = 64;

thread_local! {
    /// Per-thread accumulator for `check_and_count`. Flushed to
    /// `QuotaTracker::calls` every `QUOTA_BATCH_SIZE` calls.
    ///
    /// There is exactly one `QuotaTracker` instance per process (see
    /// `main.rs` boot), so a process-global thread-local is safe — it
    /// is only ever read in the context of that one tracker. If we ever
    /// support multiple trackers, this needs to be promoted to a
    /// per-tracker store (e.g. `DashMap<TrackerId, Cell<u32>>` per thread).
    static QUOTA_BATCH: Cell<u32> = const { Cell::new(0) };
}

// ---------------------------------------------------------------------------
// Plan tier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Free,
    Pro,
    Business,
    Enterprise,
}

impl PlanTier {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pro" => PlanTier::Pro,
            "business" => PlanTier::Business,
            "enterprise" => PlanTier::Enterprise,
            _ => PlanTier::Free,
        }
    }

    pub fn monthly_limit(self) -> Option<u64> {
        match self {
            PlanTier::Free => Some(1_000_000),
            PlanTier::Pro => Some(10_000_000),
            PlanTier::Business => Some(100_000_000),
            PlanTier::Enterprise => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PlanTier::Free => "free",
            PlanTier::Pro => "pro",
            PlanTier::Business => "business",
            PlanTier::Enterprise => "enterprise",
        }
    }
}

// ---------------------------------------------------------------------------
// Quota result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaResult {
    Allowed,
    Overage,
    Rejected,
}

// ---------------------------------------------------------------------------
// QuotaTracker
// ---------------------------------------------------------------------------

pub struct QuotaTracker {
    plan: PlanTier,
    /// 0 = unlimited. Updated dynamically from the license verify response.
    limit: AtomicU64,
    /// Current period encoded as `year * 12 + (month - 1)`. Checked on
    /// every `check_and_count` to detect rollover — a single relaxed
    /// atomic load on the hot path. Previously this comparison went
    /// through a `Mutex<String>::lock()` per request which serialised
    /// 100k req/s through one lock.
    period_epoch: AtomicU64,
    /// String form of the current period (e.g. `"2026-05"`). Only read
    /// by `snapshot()` and `flush()` — both cold paths. The mutex
    /// guards both the string and the rollover transition; the hot
    /// path never touches it.
    period_string: std::sync::Mutex<String>,
    calls: AtomicU64,
    rejected: AtomicU64,
    overage: AtomicU64,
    allow_overage: AtomicBool,
    repo: Arc<dyn Repository>,
}

impl QuotaTracker {
    /// `server_limit` overrides the hardcoded tier limit when present.
    pub async fn load(
        plan: PlanTier,
        server_limit: Option<u64>,
        repo: Arc<dyn Repository>,
    ) -> Result<Arc<Self>, GatewayError> {
        let period = current_period();
        let (calls, rejected) = repo
            .get_quota_usage(&period)
            .await?
            .map(|(c, r)| (c, r))
            .unwrap_or((0, 0));

        let allow_overage = matches!(plan, PlanTier::Pro | PlanTier::Business);
        let effective_limit = server_limit.or_else(|| plan.monthly_limit()).unwrap_or(0);

        let tracker = Arc::new(Self {
            plan,
            limit: AtomicU64::new(effective_limit),
            period_epoch: AtomicU64::new(current_period_epoch()),
            period_string: std::sync::Mutex::new(period.clone()),
            calls: AtomicU64::new(calls),
            rejected: AtomicU64::new(rejected),
            overage: AtomicU64::new(0),
            allow_overage: AtomicBool::new(allow_overage),
            repo,
        });

        info!(
            plan = plan.as_str(),
            period = %period,
            calls,
            limit = effective_limit,
            source = if server_limit.is_some() { "server" } else { "hardcoded" },
            allow_overage,
            "quota tracker initialised"
        );

        Ok(tracker)
    }

    pub fn set_allow_overage(&self, allow: bool) {
        self.allow_overage.store(allow, Ordering::Relaxed);
    }

    pub fn set_limit(&self, new_limit: Option<u64>) {
        let val = new_limit.unwrap_or(0);
        let old = self.limit.swap(val, Ordering::Relaxed);
        if old != val {
            info!(
                old_limit = old,
                new_limit = val,
                "quota limit updated from server"
            );
        }
    }

    pub fn check_and_count(&self) -> QuotaResult {
        self.maybe_rollover();

        // Hot path:
        //   1. Bump the thread-local batch counter (no atomic).
        //   2. If the batch reached BATCH_SIZE, flush to the shared atomic
        //      with a single `fetch_add(BATCH_SIZE)`.
        //   3. Decide on Allowed / Overage / Rejected using
        //      `(global + local_pending)` as the approximate post-count.
        //
        // Pre-batching cost: 1× `fetch_add` per request (+ extra atomics on
        // the Overage / Rejected branches). Post-batching cost: 1 atomic per
        // 64 requests on the Allowed branch — a 64× reduction at the call
        // rate that motivated this change.
        let limit = self.limit.load(Ordering::Relaxed);

        // `post_total`: the inclusive count *after* counting this request,
        // expressed as global_total + local_pending.
        let post_total = QUOTA_BATCH.with(|batch| {
            let n = batch.get() + 1;
            if n >= QUOTA_BATCH_SIZE {
                // Flush. fetch_add returns the value before the add; the
                // post-flush global is `prev_global + n`.
                let prev_global = self.calls.fetch_add(n as u64, Ordering::Relaxed);
                batch.set(0);
                prev_global + n as u64
            } else {
                batch.set(n);
                self.calls.load(Ordering::Relaxed) + n as u64
            }
        });

        if limit == 0 {
            // Unlimited (enterprise) — no comparison needed.
            return QuotaResult::Allowed;
        }

        if post_total <= limit {
            QuotaResult::Allowed
        } else if self.allow_overage.load(Ordering::Relaxed) {
            self.overage.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Overage
        } else {
            // Reject: cold path. Roll back the count we just charged so
            // `calls` continues to reflect only served requests. If the
            // local batch is non-empty, decrement there; otherwise we
            // already flushed in this call, so undo the global add.
            QUOTA_BATCH.with(|batch| {
                let n = batch.get();
                if n > 0 {
                    batch.set(n - 1);
                } else {
                    self.calls.fetch_sub(1, Ordering::Relaxed);
                }
            });
            self.rejected.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Rejected
        }
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        let period = self.period_string.lock().expect("period_string mutex").clone();
        let calls = self.calls.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        let overage = self.overage.load(Ordering::Relaxed);
        let raw_limit = self.limit.load(Ordering::Relaxed);
        let limit = if raw_limit == 0 {
            None
        } else {
            Some(raw_limit)
        };
        QuotaSnapshot {
            plan: self.plan,
            period,
            calls_total: calls,
            calls_rejected: rejected,
            calls_overage: overage,
            calls_limit: limit,
            calls_remaining: limit.map(|l| l.saturating_sub(calls)),
            allow_overage: self.allow_overage.load(Ordering::Relaxed),
        }
    }

    pub async fn flush(&self) {
        let period = self
            .period_string
            .lock()
            .expect("period_string mutex")
            .clone();
        let calls = self.calls.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        if let Err(e) = self.repo.upsert_quota_usage(&period, calls, rejected).await {
            warn!(error = %e, "quota flush failed");
        }
    }

    /// Detect period rollover with a single atomic load on the common case.
    /// Pre-refactor this acquired `period: Mutex<String>` on every request
    /// just to compare it to the current month — at 100k RPS that serialised
    /// every request through one global lock. Now the fast path is one
    /// relaxed `AtomicU64::load` + integer compare; the mutex is only taken
    /// when the epoch actually changes (once per month).
    fn maybe_rollover(&self) {
        let now_epoch = current_period_epoch();
        if self.period_epoch.load(Ordering::Acquire) == now_epoch {
            return;
        }
        // Slow path: take the lock, double-check (another thread may have
        // rolled over while we waited), update both fields, reset counters.
        let mut period = self.period_string.lock().expect("period_string mutex");
        if self.period_epoch.load(Ordering::Acquire) == now_epoch {
            return;
        }
        let new_str = current_period();
        info!(old = %*period, new = %new_str, "quota period rollover — resetting counters");
        *period = new_str;
        self.period_epoch.store(now_epoch, Ordering::Release);
        self.calls.store(0, Ordering::Relaxed);
        self.rejected.store(0, Ordering::Relaxed);
        self.overage.store(0, Ordering::Relaxed);
        // We can't reach into other threads' QUOTA_BATCH thread-locals
        // from here, so up to (QUOTA_BATCH_SIZE - 1) × num_threads
        // increments collected before the rollover will leak into the
        // new period's count when those threads next flush. For a
        // month-boundary rollover with millions of monthly calls, this
        // drift is negligible.
    }
}

// ---------------------------------------------------------------------------
// Background flush task
// ---------------------------------------------------------------------------

pub fn spawn_quota_flusher(tracker: Arc<QuotaTracker>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            tracker.flush().await;
        }
    });
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct QuotaSnapshot {
    pub plan: PlanTier,
    pub period: String,
    pub calls_total: u64,
    pub calls_rejected: u64,
    pub calls_overage: u64,
    pub calls_limit: Option<u64>,
    pub calls_remaining: Option<u64>,
    pub allow_overage: bool,
}

fn current_period() -> String {
    Utc::now().format("%Y-%m").to_string()
}

/// Period encoded as `year * 12 + (month - 1)`. Comparing two epochs is a
/// single integer compare; storing it in an `AtomicU64` lets the rollover
/// fast path be lockless. Year is clamped to non-negative — Lynxx is not
/// concerned with BCE quotas.
fn current_period_epoch() -> u64 {
    let now = Utc::now();
    (now.year().max(0) as u64) * 12 + (now.month() as u64 - 1)
}
