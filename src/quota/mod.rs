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
//!
//! # Counter strategies
//!
//! Two counting strategies are supported, selectable at runtime:
//!
//! | Strategy          | Cross-thread atomics | Accuracy drift           |
//! |-------------------|---------------------|--------------------------|
//! | `BatchedAtomic`   | 1 per 64 requests   | ≤ BATCH_SIZE × threads   |
//! | `PerThread`       | 0 (fully per-thread) | ≤ aggregate interval     |
//!
//! **`BatchedAtomic`** (original) — Thread-local `Cell<u32>` accumulates
//! 64 increments before flushing to a shared `AtomicU64`. One atomic per
//! 64 requests.
//!
//! **`PerThread`** (HAProxy-inspired) — Each Tokio worker thread keeps a
//! fully independent `Cell<u64>` counter. No cross-thread atomics on the
//! hot path at all. The global total is computed on-demand by summing
//! registered per-thread counters during `snapshot()` and `flush()`.
//! HAProxy uses this approach — per-thread counters with no global atomic —
//! because even batched atomics cause cache-line bouncing under extreme
//! load.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;
use tokio::time::interval;
use tracing::{info, warn};

use crate::db::Repository;
use crate::error::GatewayError;

const FLUSH_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Counter strategy
// ---------------------------------------------------------------------------

/// How quota increments are counted. Stored as `AtomicU8` for lock-free
/// runtime switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CounterStrategy {
    /// Thread-local batch of 64, then flush to shared `AtomicU64`.
    /// 1 atomic operation per 64 requests.
    BatchedAtomic = 0,
    /// Fully per-thread counters — zero cross-thread atomics on the hot
    /// path. HAProxy's approach. Trades a small accuracy window for zero
    /// cache-line contention.
    PerThread = 1,
}

impl CounterStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::PerThread,
            _ => Self::BatchedAtomic,
        }
    }
}

static COUNTER_STRATEGY: AtomicU8 = AtomicU8::new(CounterStrategy::PerThread as u8);

pub fn set_counter_strategy(s: CounterStrategy) {
    COUNTER_STRATEGY.store(s as u8, Ordering::Relaxed);
}

pub fn counter_strategy() -> CounterStrategy {
    CounterStrategy::from_u8(COUNTER_STRATEGY.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Batched-atomic counter (original strategy)
// ---------------------------------------------------------------------------

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
    /// Per-thread accumulator for the `BatchedAtomic` strategy. Flushed to
    /// `QuotaTracker::calls` every `QUOTA_BATCH_SIZE` calls.
    static QUOTA_BATCH: Cell<u32> = const { Cell::new(0) };
}

// ---------------------------------------------------------------------------
// Per-thread counter (HAProxy-inspired strategy)
// ---------------------------------------------------------------------------

/// Maximum number of worker threads we support for per-thread counters.
/// Tokio typically spawns `num_cpus()` workers; 128 covers even large
/// servers. Threads beyond this limit fall back to the batched-atomic
/// path.
const MAX_THREAD_SLOTS: usize = 128;

/// Global array of per-thread counters. Each slot is an `AtomicU64` that
/// is **only written by its owning thread** (via relaxed store) and
/// **only read by the aggregator** (via relaxed load). Because there is
/// exactly one writer per slot, no `fetch_add` is needed — just `load`
/// + increment + `store`. This eliminates all cross-thread cache-line
/// contention on the write path.
///
/// This is HAProxy's model: each thread owns its counters, and the
/// "global total" is computed by summing all slots when needed.
static PER_THREAD_CALLS: [AtomicU64; MAX_THREAD_SLOTS] = {
    // const-init all 128 slots to 0.
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_THREAD_SLOTS]
};

/// How many slots are actually in use. Threads register on first use
/// and receive a slot index.
static THREAD_SLOT_COUNT: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// This thread's slot index in PER_THREAD_CALLS. Lazily assigned on
    /// first `check_and_count` when using the PerThread strategy.
    /// `u32::MAX` = unassigned.
    static THREAD_SLOT: Cell<u32> = const { Cell::new(u32::MAX) };
}

/// Assign this thread a slot if it doesn't have one yet.
/// Returns the slot index, or `None` if all slots are exhausted.
fn ensure_thread_slot() -> Option<usize> {
    THREAD_SLOT.with(|slot| {
        let idx = slot.get();
        if idx != u32::MAX {
            return Some(idx as usize);
        }
        let new_idx = THREAD_SLOT_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
        if new_idx >= MAX_THREAD_SLOTS {
            // Too many threads — don't assign. The caller should fall
            // back to the batched-atomic path.
            THREAD_SLOT_COUNT.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        slot.set(new_idx as u32);
        Some(new_idx)
    })
}

/// Sum all per-thread slots to get the aggregate call count. This is
/// an O(N) scan over registered slots — acceptable for the cold paths
/// (`snapshot()`, `flush()`, and the infrequent quota-boundary check).
fn aggregate_per_thread_calls() -> u64 {
    let n = THREAD_SLOT_COUNT.load(Ordering::Relaxed) as usize;
    let n = n.min(MAX_THREAD_SLOTS);
    let mut total = 0u64;
    for i in 0..n {
        total += PER_THREAD_CALLS[i].load(Ordering::Relaxed);
    }
    total
}

/// Reset all per-thread slots to zero (used on period rollover).
fn reset_per_thread_calls() {
    let n = THREAD_SLOT_COUNT.load(Ordering::Relaxed) as usize;
    let n = n.min(MAX_THREAD_SLOTS);
    for i in 0..n {
        PER_THREAD_CALLS[i].store(0, Ordering::Relaxed);
    }
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
            counter_strategy = ?counter_strategy(),
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

    /// Cached-timestamp variant for the proxy hot path. The handler captures
    /// `Utc::now()` once per request at entry and threads the same
    /// `DateTime` through every per-request consumer to eliminate
    /// redundant `clock_gettime` syscalls. See `proxy_handler`.
    pub fn check_and_count_at(&self, now: DateTime<Utc>) -> QuotaResult {
        let now_epoch = epoch_from_datetime(now);
        self.maybe_rollover_at(now_epoch, now);
        self.check_and_count_inner()
    }

    /// Convenience: calls `check_and_count_at(Utc::now())`. The proxy
    /// hot path uses `check_and_count_at` directly.
    pub fn check_and_count(&self) -> QuotaResult {
        self.maybe_rollover();
        self.check_and_count_inner()
    }

    fn check_and_count_inner(&self) -> QuotaResult {
        match counter_strategy() {
            CounterStrategy::BatchedAtomic => self.check_and_count_batched(),
            CounterStrategy::PerThread => self.check_and_count_per_thread(),
        }
    }

    /// **BatchedAtomic strategy** (original).
    ///
    /// Hot path:
    ///   1. Bump the thread-local batch counter (no atomic).
    ///   2. If the batch reached BATCH_SIZE, flush to the shared atomic
    ///      with a single `fetch_add(BATCH_SIZE)`.
    ///   3. Decide on Allowed / Overage / Rejected using
    ///      `(global + local_pending)` as the approximate post-count.
    ///
    /// Cost: 1 atomic per 64 requests on the Allowed branch.
    fn check_and_count_batched(&self) -> QuotaResult {
        let limit = self.limit.load(Ordering::Relaxed);

        let post_total = QUOTA_BATCH.with(|batch| {
            let n = batch.get() + 1;
            if n >= QUOTA_BATCH_SIZE {
                let prev_global = self.calls.fetch_add(n as u64, Ordering::Relaxed);
                batch.set(0);
                prev_global + n as u64
            } else {
                batch.set(n);
                self.calls.load(Ordering::Relaxed) + n as u64
            }
        });

        if limit == 0 {
            return QuotaResult::Allowed;
        }

        if post_total <= limit {
            QuotaResult::Allowed
        } else if self.allow_overage.load(Ordering::Relaxed) {
            self.overage.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Overage
        } else {
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

    /// **PerThread strategy** (HAProxy-inspired).
    ///
    /// Each Tokio worker thread owns a dedicated slot in `PER_THREAD_CALLS`.
    /// The increment is a thread-local load + add + store — zero atomic
    /// RMW operations, zero cache-line bouncing.
    ///
    /// The quota check reads the thread-local counter plus a cached
    /// snapshot of the global total. The snapshot is approximate, but for
    /// monthly limits in the millions the error (bounded by the aggregate
    /// interval × request rate) is negligible.
    ///
    /// Cost: 0 cross-thread atomics per request.
    fn check_and_count_per_thread(&self) -> QuotaResult {
        let limit = self.limit.load(Ordering::Relaxed);

        // Try to get this thread's dedicated slot. If slots are exhausted
        // (>128 threads), fall back to the batched-atomic path.
        let slot_idx = match ensure_thread_slot() {
            Some(idx) => idx,
            None => return self.check_and_count_batched(),
        };

        // Increment this thread's counter — pure thread-local, no atomic
        // RMW. Only this thread writes to PER_THREAD_CALLS[slot_idx], so
        // a relaxed load + store is safe.
        let my_count = PER_THREAD_CALLS[slot_idx].load(Ordering::Relaxed) + 1;
        PER_THREAD_CALLS[slot_idx].store(my_count, Ordering::Relaxed);

        if limit == 0 {
            return QuotaResult::Allowed;
        }

        // Approximate global total: the last cached aggregate (written by
        // the periodic flush task) plus this thread's own count.
        //
        // The cached aggregate may include a stale version of our own
        // slot, making the sum slightly conservative (over-estimate). This
        // is safe — it means we hit the limit slightly early rather than
        // late. For monthly limits in the millions, the error is negligible.
        let cached_aggregate = self.calls.load(Ordering::Relaxed);
        let post_total = cached_aggregate + my_count;

        if post_total <= limit {
            QuotaResult::Allowed
        } else if self.allow_overage.load(Ordering::Relaxed) {
            self.overage.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Overage
        } else {
            // Roll back: decrement this thread's slot.
            PER_THREAD_CALLS[slot_idx].store(my_count - 1, Ordering::Relaxed);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            QuotaResult::Rejected
        }
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        let period = self.period_string.lock().expect("period_string mutex").clone();
        let calls = match counter_strategy() {
            CounterStrategy::BatchedAtomic => self.calls.load(Ordering::Relaxed),
            CounterStrategy::PerThread => aggregate_per_thread_calls(),
        };
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
        let calls = match counter_strategy() {
            CounterStrategy::BatchedAtomic => self.calls.load(Ordering::Relaxed),
            CounterStrategy::PerThread => {
                // Aggregate all per-thread slots and cache the result
                // in `self.calls` so the per-thread quota check has a
                // reasonably fresh global view.
                let total = aggregate_per_thread_calls();
                self.calls.store(total, Ordering::Relaxed);
                total
            }
        };
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
        self.maybe_rollover_at(current_period_epoch(), Utc::now());
    }

    fn maybe_rollover_at(&self, now_epoch: u64, now: DateTime<Utc>) {
        if self.period_epoch.load(Ordering::Acquire) == now_epoch {
            return;
        }
        // Slow path: take the lock, double-check (another thread may have
        // rolled over while we waited), update both fields, reset counters.
        let mut period = self.period_string.lock().expect("period_string mutex");
        if self.period_epoch.load(Ordering::Acquire) == now_epoch {
            return;
        }
        let new_str = now.format("%Y-%m").to_string();
        info!(old = %*period, new = %new_str, "quota period rollover — resetting counters");
        *period = new_str;
        self.period_epoch.store(now_epoch, Ordering::Release);
        self.calls.store(0, Ordering::Relaxed);
        self.rejected.store(0, Ordering::Relaxed);
        self.overage.store(0, Ordering::Relaxed);
        // Reset per-thread counters for the PerThread strategy.
        reset_per_thread_calls();
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
    epoch_from_datetime(Utc::now())
}

fn epoch_from_datetime(now: DateTime<Utc>) -> u64 {
    (now.year().max(0) as u64) * 12 + (now.month() as u64 - 1)
}
