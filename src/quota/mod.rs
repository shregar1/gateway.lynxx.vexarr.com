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

    /// Map a billing `PlanTier` onto the runtime algorithm `Tier`.
    ///
    /// Free → Starter, Pro → Growth, Business / Enterprise → Pro. The
    /// algorithms crate has only three performance tiers; Business and
    /// Enterprise share the top-tier algorithm set and are distinguished
    /// purely by quota.
    pub fn algorithm_tier(self) -> algorithms::backbone::Tier {
        use algorithms::backbone::Tier;
        match self {
            PlanTier::Free => Tier::Starter,
            PlanTier::Pro => Tier::Growth,
            PlanTier::Business | PlanTier::Enterprise => Tier::Pro,
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
    /// Call counter. Its meaning depends on the active `CounterStrategy`:
    ///   * `BatchedAtomic` — the shared running total (flushed batches of 64).
    ///   * `PerThread`      — the period BASELINE: usage carried over from
    ///     prior process runs (DB-seeded in `load()`) that is not represented
    ///     in any live per-thread slot. The running total under PerThread is
    ///     `calls + aggregate_per_thread_calls()`. flush() must NOT overwrite
    ///     this with the bare slot aggregate (that previously dropped the
    ///     baseline and let the Free hard-block tier overshoot the limit).
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

        // BUG FIX (live-aggregate under-count / N× overshoot): the old code
        // computed `self.calls.load() + my_count`, i.e. a 30s-stale global
        // cache plus ONLY this thread's own slot. Because `self.calls` was
        // refreshed just once every FLUSH_INTERVAL_SECS and the hot path
        // never observed sibling threads' live slots, each of the N worker
        // threads independently believed it still had the full remaining
        // quota. On the Free hard-block tier (allow_overage=false) that let
        // the gateway serve up to ~N× the limit before any thread tripped.
        //
        // Fix: derive the post-increment global total from the LIVE slots of
        // every worker thread so all threads share one consistent view.
        //   * `aggregate_per_thread_calls()` already includes this request —
        //     the increment was stored into our own slot just above — so we
        //     add NO +1 (that would over-count by one per request).
        //   * `self.calls` is the period BASELINE: usage carried over from
        //     prior process runs (DB-seeded in `load()`) / earlier in this
        //     period, which is not represented in any live slot. The true
        //     running total is therefore `baseline + live per-thread sum`.
        // This O(num_threads) (~128 relaxed loads) scan only runs for limited
        // tiers (the `limit == 0` unlimited case returned above) and is
        // negligible next to the per-request proxy/TLS work.
        let baseline = self.calls.load(Ordering::Relaxed);
        let post_total = baseline + aggregate_per_thread_calls();

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
            // BUG FIX: report baseline + live per-thread sum (the true total).
            // Reading only `aggregate_per_thread_calls()` here would omit the
            // period baseline now that flush() no longer folds it into the
            // slots, under-reporting usage to the admin API.
            CounterStrategy::PerThread => {
                self.calls.load(Ordering::Relaxed) + aggregate_per_thread_calls()
            }
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
                // Persist the true period total = baseline + live per-thread
                // sum. `self.calls` is the BASELINE (prior usage not held in
                // any slot); the live delta is the sum of all slots.
                //
                // BUG FIX: previously this did `self.calls.store(aggregate)`,
                // which clobbered the baseline ~30s after boot with the bare
                // slot sum (dropping the DB-seeded prior usage) and would have
                // re-broken the hot-path check that now reads the baseline.
                // The hot path reads the live slots directly, so flush no
                // longer needs to (and must not) cache anything into
                // `self.calls`; it only persists the total to the DB.
                self.calls.load(Ordering::Relaxed) + aggregate_per_thread_calls()
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    use async_trait::async_trait;
    use chrono::Utc;
    use uuid::Uuid;

    use crate::db::Repository;
    use crate::error::GatewayError;

    // A global mutex to serialise tests that touch shared statics
    // (PER_THREAD_CALLS, THREAD_SLOT_COUNT, COUNTER_STRATEGY, QUOTA_BATCH).
    // Without this, `cargo test` runs tests in parallel within the same
    // process, causing interference between tests that read/write the same
    // statics.
    static TEST_MUTEX: std::sync::LazyLock<StdMutex<()>> = std::sync::LazyLock::new(|| StdMutex::new(()));

    /// Acquire the test serialisation lock, recovering from poison if a
    /// previous test panicked while holding it.
    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reset all shared statics to a clean state before each test.
    fn reset_globals() {
        set_counter_strategy(CounterStrategy::BatchedAtomic);
        // Zero out per-thread slots.
        for i in 0..MAX_THREAD_SLOTS {
            PER_THREAD_CALLS[i].store(0, Ordering::Relaxed);
        }
        THREAD_SLOT_COUNT.store(0, Ordering::Relaxed);
        THREAD_SLOT.with(|s| s.set(u32::MAX));
        // Zero the batched-atomic thread-local accumulator.
        QUOTA_BATCH.with(|b| b.set(0));
    }

    // -----------------------------------------------------------------------
    // Stub repository — only quota methods matter; everything else is a no-op
    // -----------------------------------------------------------------------

    struct StubRepo;

    #[async_trait]
    impl Repository for StubRepo {
        async fn list_services(&self) -> Result<Vec<crate::models::Service>, GatewayError> { Ok(vec![]) }
        async fn get_service(&self, _id: &Uuid) -> Result<Option<crate::models::Service>, GatewayError> { Ok(None) }
        async fn get_service_by_name(&self, _name: &str) -> Result<Option<crate::models::Service>, GatewayError> { Ok(None) }
        async fn create_service(&self, _svc: &crate::models::Service) -> Result<(), GatewayError> { Ok(()) }
        async fn update_service(&self, _id: &Uuid, _svc: &crate::models::Service) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_service(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_routes(&self) -> Result<Vec<crate::models::Route>, GatewayError> { Ok(vec![]) }
        async fn get_route(&self, _id: &Uuid) -> Result<Option<crate::models::Route>, GatewayError> { Ok(None) }
        async fn create_route(&self, _route: &crate::models::Route) -> Result<(), GatewayError> { Ok(()) }
        async fn update_route(&self, _id: &Uuid, _route: &crate::models::Route) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_route(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_plugins(&self) -> Result<Vec<crate::models::PluginInstance>, GatewayError> { Ok(vec![]) }
        async fn get_plugin(&self, _id: &Uuid) -> Result<Option<crate::models::PluginInstance>, GatewayError> { Ok(None) }
        async fn create_plugin(&self, _plugin: &crate::models::PluginInstance) -> Result<(), GatewayError> { Ok(()) }
        async fn update_plugin(&self, _id: &Uuid, _plugin: &crate::models::PluginInstance) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_plugin(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_consumers(&self) -> Result<Vec<crate::models::Consumer>, GatewayError> { Ok(vec![]) }
        async fn create_consumer(&self, _consumer: &crate::models::Consumer) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_consumer(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_targets(&self) -> Result<Vec<crate::models::Target>, GatewayError> { Ok(vec![]) }
        async fn list_targets_for_service(&self, _id: &Uuid) -> Result<Vec<crate::models::Target>, GatewayError> { Ok(vec![]) }
        async fn get_target(&self, _id: &Uuid) -> Result<Option<crate::models::Target>, GatewayError> { Ok(None) }
        async fn create_target(&self, _t: &crate::models::Target) -> Result<(), GatewayError> { Ok(()) }
        async fn update_target(&self, _id: &Uuid, _t: &crate::models::Target) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_target(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn update_target_state(&self, _id: &Uuid, _state: &str) -> Result<bool, GatewayError> { Ok(false) }
        async fn is_empty(&self) -> Result<bool, GatewayError> { Ok(true) }
        async fn seed_from_config(&self, _config: &crate::config::GatewayConfig) -> Result<(), GatewayError> { Ok(()) }
        async fn clear_config_seed(&self) -> Result<(), GatewayError> { Ok(()) }
        async fn mark_config_source(&self, _s: &[Uuid], _r: &[Uuid], _p: &[Uuid]) -> Result<(), GatewayError> { Ok(()) }
        async fn list_admin_tokens(&self) -> Result<Vec<crate::auth::AdminToken>, GatewayError> { Ok(vec![]) }
        async fn get_admin_token_by_hash(&self, _h: &str) -> Result<Option<crate::auth::AdminToken>, GatewayError> { Ok(None) }
        async fn get_admin_token(&self, _id: &Uuid) -> Result<Option<crate::auth::AdminToken>, GatewayError> { Ok(None) }
        async fn create_admin_token(&self, _t: &crate::db::NewAdminToken) -> Result<(), GatewayError> { Ok(()) }
        async fn update_admin_token(&self, _id: &Uuid, _patch: &crate::db::AdminTokenPatch) -> Result<Option<crate::auth::AdminToken>, GatewayError> { Ok(None) }
        async fn delete_admin_token(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn update_admin_token_last_used(&self, _id: &Uuid, _ts: chrono::DateTime<Utc>) -> Result<(), GatewayError> { Ok(()) }
        async fn has_any_admin_token(&self) -> Result<bool, GatewayError> { Ok(false) }
        async fn append_audit(&self, entry: &crate::audit::NewAuditEntry) -> Result<crate::audit::AuditEntry, GatewayError> {
            Ok(crate::audit::AuditEntry {
                id: 0, ts: entry.ts, actor_id: entry.actor_id,
                actor_name: entry.actor_name.clone(), actor_role: entry.actor_role.clone(),
                action: entry.action.clone(), resource_type: entry.resource_type.clone(),
                resource_id: entry.resource_id.clone(), diff: entry.diff.clone(),
                hash: String::new(), prev_hash: None,
            })
        }
        async fn list_audit(&self, _f: &crate::audit::AuditFilter) -> Result<Vec<crate::audit::AuditEntry>, GatewayError> { Ok(vec![]) }
        async fn last_audit_hash(&self) -> Result<Option<String>, GatewayError> { Ok(None) }
        fn cluster_bus(&self) -> Arc<dyn crate::cluster::ClusterBus> { unimplemented!("test stub") }
        async fn get_quota_usage(&self, _period: &str) -> Result<Option<(u64, u64)>, GatewayError> { Ok(None) }
        async fn upsert_quota_usage(&self, _period: &str, _calls_total: u64, _calls_rejected: u64) -> Result<(), GatewayError> { Ok(()) }
        async fn append_recording(&self, _row: &crate::recording::RecordingIndexRow) -> Result<(), GatewayError> { Ok(()) }
        async fn list_recordings(&self, _f: &crate::recording::RecordingFilter) -> Result<Vec<crate::recording::RecordingIndexRow>, GatewayError> { Ok(vec![]) }
        async fn get_recording_index(&self, _id: &str) -> Result<Option<crate::recording::RecordingIndexRow>, GatewayError> { Ok(None) }
        async fn delete_recording(&self, _id: &str) -> Result<bool, GatewayError> { Ok(false) }
        async fn delete_recordings_before(&self, _ts: chrono::DateTime<chrono::Utc>) -> Result<u64, GatewayError> { Ok(0) }
        async fn get_device_fingerprint(&self, _customer_id: i64, _hardware_id: &str) -> Result<Option<crate::models::DeviceFingerprint>, GatewayError> { Ok(None) }
        async fn create_device_fingerprint(&self, _device: &crate::models::DeviceFingerprint) -> Result<(), GatewayError> { Ok(()) }
        async fn update_device_last_seen(&self, _id: &Uuid, _ts: chrono::DateTime<chrono::Utc>) -> Result<(), GatewayError> { Ok(()) }
        async fn create_runtime_grant(&self, _grant: &crate::models::RuntimeGrant) -> Result<(), GatewayError> { Ok(()) }
        async fn get_runtime_grant_by_token_id(&self, _token_id: &str) -> Result<Option<crate::models::RuntimeGrant>, GatewayError> { Ok(None) }
        async fn update_grant_heartbeat(&self, _token_id: &str, _ts: chrono::DateTime<chrono::Utc>) -> Result<(), GatewayError> { Ok(()) }
        async fn revoke_grant(&self, _token_id: &str) -> Result<bool, GatewayError> { Ok(false) }
        async fn get_api_key_by_prefix(&self, _prefix: &str) -> Result<Option<crate::models::ApiKeyRow>, GatewayError> { Ok(None) }
        async fn list_projects(&self) -> Result<Vec<crate::models::Project>, GatewayError> { Ok(vec![]) }
        async fn get_project(&self, _id: &Uuid) -> Result<Option<crate::models::Project>, GatewayError> { Ok(None) }
        async fn create_project(&self, _p: &crate::models::Project) -> Result<(), GatewayError> { Ok(()) }
        async fn update_project(&self, _id: &Uuid, _p: &crate::models::Project) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_project(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_services_for_project(&self, _id: &Uuid) -> Result<Vec<crate::models::Service>, GatewayError> { Ok(vec![]) }
        async fn soft_delete_plugins_for_route(&self, _id: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn soft_delete_plugins_for_service(&self, _id: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn soft_delete_routes_for_service(&self, _id: &Uuid) -> Result<Vec<Uuid>, GatewayError> { Ok(vec![]) }
        async fn soft_delete_targets_for_service(&self, _id: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn soft_delete_services_for_project(&self, _id: &Uuid) -> Result<Vec<Uuid>, GatewayError> { Ok(vec![]) }
        async fn insert_logs(&self, _entries: &[crate::models::LogEntry]) -> Result<(), GatewayError> { Ok(()) }
        async fn list_logs(&self, _filter: &crate::db::LogFilter) -> Result<Vec<crate::models::LogEntry>, GatewayError> { Ok(vec![]) }
        async fn prune_logs(&self, _days: u32) -> Result<u64, GatewayError> { Ok(0) }
        async fn upsert_metric_bucket(&self, _b: &crate::models::MetricBucket) -> Result<(), GatewayError> { Ok(()) }
        async fn list_metric_buckets(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>, _g: &str) -> Result<Vec<crate::models::MetricBucket>, GatewayError> { Ok(vec![]) }
        async fn upsert_geo_bucket(&self, _b: &crate::models::GeoBucket) -> Result<(), GatewayError> { Ok(()) }
        async fn list_geo_buckets(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>) -> Result<Vec<crate::models::GeoBucket>, GatewayError> { Ok(vec![]) }
        async fn upsert_rate_limit_bucket(&self, _b: &crate::models::RateLimitBucket) -> Result<(), GatewayError> { Ok(()) }
        async fn list_rate_limit_buckets(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>) -> Result<Vec<crate::models::RateLimitBucket>, GatewayError> { Ok(vec![]) }
        async fn list_probes(&self, _sid: &Uuid) -> Result<Vec<crate::models::Probe>, GatewayError> { Ok(vec![]) }
        async fn get_probe(&self, _id: &Uuid) -> Result<Option<crate::models::Probe>, GatewayError> { Ok(None) }
        async fn create_probe(&self, _p: &crate::models::Probe) -> Result<(), GatewayError> { Ok(()) }
        async fn update_probe(&self, _id: &Uuid, _p: &crate::models::Probe) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_probe(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn append_probe_result(&self, _r: &crate::models::ProbeResult) -> Result<(), GatewayError> { Ok(()) }
        async fn list_probe_results(&self, _pid: &Uuid, _limit: u32) -> Result<Vec<crate::models::ProbeResult>, GatewayError> { Ok(vec![]) }
        async fn list_snapshots(&self, _sid: &Uuid) -> Result<Vec<crate::models::Snapshot>, GatewayError> { Ok(vec![]) }
        async fn get_snapshot(&self, _id: &Uuid) -> Result<Option<crate::models::Snapshot>, GatewayError> { Ok(None) }
        async fn create_snapshot(&self, _s: &crate::models::Snapshot) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_snapshot(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_alert_rules(&self, _sid: &Uuid) -> Result<Vec<crate::models::AlertRule>, GatewayError> { Ok(vec![]) }
        async fn get_alert_rule(&self, _id: &Uuid) -> Result<Option<crate::models::AlertRule>, GatewayError> { Ok(None) }
        async fn create_alert_rule(&self, _r: &crate::models::AlertRule) -> Result<(), GatewayError> { Ok(()) }
        async fn update_alert_rule(&self, _id: &Uuid, _r: &crate::models::AlertRule) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_alert_rule(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_alert_events(&self, _sid: &Uuid, _limit: u32) -> Result<Vec<crate::models::AlertEvent>, GatewayError> { Ok(vec![]) }
        async fn create_alert_event(&self, _e: &crate::models::AlertEvent) -> Result<(), GatewayError> { Ok(()) }
        async fn resolve_alert_event(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_ip_rules(&self, _sid: &Uuid) -> Result<Vec<crate::models::IpRule>, GatewayError> { Ok(vec![]) }
        async fn get_ip_rule(&self, _id: &Uuid) -> Result<Option<crate::models::IpRule>, GatewayError> { Ok(None) }
        async fn create_ip_rule(&self, _r: &crate::models::IpRule) -> Result<(), GatewayError> { Ok(()) }
        async fn update_ip_rule(&self, _id: &Uuid, _r: &crate::models::IpRule) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_ip_rule(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_error_pages(&self, _sid: &Uuid) -> Result<Vec<crate::models::ErrorPage>, GatewayError> { Ok(vec![]) }
        async fn get_error_page(&self, _id: &Uuid) -> Result<Option<crate::models::ErrorPage>, GatewayError> { Ok(None) }
        async fn create_error_page(&self, _p: &crate::models::ErrorPage) -> Result<(), GatewayError> { Ok(()) }
        async fn update_error_page(&self, _id: &Uuid, _p: &crate::models::ErrorPage) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_error_page(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_consumer_groups(&self, _sid: &Uuid) -> Result<Vec<crate::models::ConsumerGroup>, GatewayError> { Ok(vec![]) }
        async fn get_consumer_group(&self, _id: &Uuid) -> Result<Option<crate::models::ConsumerGroup>, GatewayError> { Ok(None) }
        async fn create_consumer_group(&self, _g: &crate::models::ConsumerGroup) -> Result<(), GatewayError> { Ok(()) }
        async fn update_consumer_group(&self, _id: &Uuid, _g: &crate::models::ConsumerGroup) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_consumer_group(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_consumer_group_members(&self, _gid: &Uuid) -> Result<Vec<crate::models::ConsumerGroupMember>, GatewayError> { Ok(vec![]) }
        async fn add_consumer_group_member(&self, _m: &crate::models::ConsumerGroupMember) -> Result<(), GatewayError> { Ok(()) }
        async fn remove_consumer_group_member(&self, _gid: &Uuid, _cid: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_cache_entries(&self, _sid: &Uuid) -> Result<Vec<crate::models::CacheEntry>, GatewayError> { Ok(vec![]) }
        async fn get_cache_entry(&self, _id: &Uuid) -> Result<Option<crate::models::CacheEntry>, GatewayError> { Ok(None) }
        async fn upsert_cache_entry(&self, _e: &crate::models::CacheEntry) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_cache_entry(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn purge_cache(&self, _sid: &Uuid) -> Result<u64, GatewayError> { Ok(0) }
        async fn cache_stats(&self, _sid: &Uuid) -> Result<crate::models::CacheStats, GatewayError> {
            Ok(crate::models::CacheStats {
                service_id: *_sid, total_entries: 0, total_size_bytes: 0,
                hit_count: 0, miss_count: 0, hit_rate: 0.0, eviction_count: 0,
            })
        }
        async fn list_traces(&self, _sid: &Uuid, _limit: u32) -> Result<Vec<crate::models::TraceRecord>, GatewayError> { Ok(vec![]) }
        async fn get_trace(&self, _id: &Uuid) -> Result<Option<crate::models::TraceRecord>, GatewayError> { Ok(None) }
        async fn create_trace(&self, _t: &crate::models::TraceRecord) -> Result<(), GatewayError> { Ok(()) }
        async fn list_spans(&self, _tid: &str) -> Result<Vec<crate::models::SpanRecord>, GatewayError> { Ok(vec![]) }
        async fn create_span(&self, _s: &crate::models::SpanRecord) -> Result<(), GatewayError> { Ok(()) }
        async fn list_transform_rules(&self, _sid: &Uuid) -> Result<Vec<crate::models::TransformRule>, GatewayError> { Ok(vec![]) }
        async fn get_transform_rule(&self, _id: &Uuid) -> Result<Option<crate::models::TransformRule>, GatewayError> { Ok(None) }
        async fn create_transform_rule(&self, _r: &crate::models::TransformRule) -> Result<(), GatewayError> { Ok(()) }
        async fn update_transform_rule(&self, _id: &Uuid, _r: &crate::models::TransformRule) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_transform_rule(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_api_versions(&self, _sid: &Uuid) -> Result<Vec<crate::models::ApiVersion>, GatewayError> { Ok(vec![]) }
        async fn get_api_version(&self, _id: &Uuid) -> Result<Option<crate::models::ApiVersion>, GatewayError> { Ok(None) }
        async fn create_api_version(&self, _v: &crate::models::ApiVersion) -> Result<(), GatewayError> { Ok(()) }
        async fn update_api_version(&self, _id: &Uuid, _v: &crate::models::ApiVersion) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_api_version(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_incidents(&self, _sid: &Uuid) -> Result<Vec<crate::models::Incident>, GatewayError> { Ok(vec![]) }
        async fn get_incident(&self, _id: &Uuid) -> Result<Option<crate::models::Incident>, GatewayError> { Ok(None) }
        async fn create_incident(&self, _i: &crate::models::Incident) -> Result<(), GatewayError> { Ok(()) }
        async fn update_incident(&self, _id: &Uuid, _i: &crate::models::Incident) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_incident(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_incident_updates(&self, _iid: &Uuid) -> Result<Vec<crate::models::IncidentUpdate>, GatewayError> { Ok(vec![]) }
        async fn create_incident_update(&self, _u: &crate::models::IncidentUpdate) -> Result<(), GatewayError> { Ok(()) }
        async fn list_webhooks(&self, _sid: &Uuid) -> Result<Vec<crate::models::Webhook>, GatewayError> { Ok(vec![]) }
        async fn get_webhook(&self, _id: &Uuid) -> Result<Option<crate::models::Webhook>, GatewayError> { Ok(None) }
        async fn create_webhook(&self, _w: &crate::models::Webhook) -> Result<(), GatewayError> { Ok(()) }
        async fn update_webhook(&self, _id: &Uuid, _w: &crate::models::Webhook) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_webhook(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_webhook_deliveries(&self, _wid: &Uuid, _limit: u32) -> Result<Vec<crate::models::WebhookDelivery>, GatewayError> { Ok(vec![]) }
        async fn create_webhook_delivery(&self, _d: &crate::models::WebhookDelivery) -> Result<(), GatewayError> { Ok(()) }
        async fn list_load_tests(&self, _sid: &Uuid) -> Result<Vec<crate::models::LoadTest>, GatewayError> { Ok(vec![]) }
        async fn get_load_test(&self, _id: &Uuid) -> Result<Option<crate::models::LoadTest>, GatewayError> { Ok(None) }
        async fn create_load_test(&self, _t: &crate::models::LoadTest) -> Result<(), GatewayError> { Ok(()) }
        async fn update_load_test(&self, _id: &Uuid, _t: &crate::models::LoadTest) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_load_test(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_marketplace_plugins(&self) -> Result<Vec<crate::models::MarketplacePlugin>, GatewayError> { Ok(vec![]) }
        async fn get_marketplace_plugin(&self, _id: &Uuid) -> Result<Option<crate::models::MarketplacePlugin>, GatewayError> { Ok(None) }
        async fn create_marketplace_plugin(&self, _p: &crate::models::MarketplacePlugin) -> Result<(), GatewayError> { Ok(()) }
        async fn update_marketplace_plugin(&self, _id: &Uuid, _p: &crate::models::MarketplacePlugin) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_marketplace_plugin(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_cost_records(&self, _sid: &Uuid, _from: chrono::DateTime<Utc>, _to: chrono::DateTime<Utc>) -> Result<Vec<crate::models::CostRecord>, GatewayError> { Ok(vec![]) }
        async fn upsert_cost_record(&self, _r: &crate::models::CostRecord) -> Result<(), GatewayError> { Ok(()) }
        async fn list_cluster_nodes(&self) -> Result<Vec<crate::models::ClusterNode>, GatewayError> { Ok(vec![]) }
        async fn get_cluster_node(&self, _id: &Uuid) -> Result<Option<crate::models::ClusterNode>, GatewayError> { Ok(None) }
        async fn upsert_cluster_node(&self, _n: &crate::models::ClusterNode) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_cluster_node(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn list_rate_limit_simulations(&self, _sid: &Uuid) -> Result<Vec<crate::models::RateLimitSimulation>, GatewayError> { Ok(vec![]) }
        async fn create_rate_limit_simulation(&self, _s: &crate::models::RateLimitSimulation) -> Result<(), GatewayError> { Ok(()) }
        async fn get_rate_limit_simulation(&self, _id: &Uuid) -> Result<Option<crate::models::RateLimitSimulation>, GatewayError> { Ok(None) }
        async fn list_certificates(&self, _sid: Option<&Uuid>) -> Result<Vec<crate::models::Certificate>, GatewayError> { Ok(vec![]) }
        async fn get_certificate(&self, _id: &Uuid) -> Result<Option<crate::models::Certificate>, GatewayError> { Ok(None) }
        async fn create_certificate(&self, _c: &crate::models::Certificate) -> Result<(), GatewayError> { Ok(()) }
        async fn update_certificate(&self, _id: &Uuid, _c: &crate::models::Certificate) -> Result<(), GatewayError> { Ok(()) }
        async fn delete_certificate(&self, _id: &Uuid) -> Result<bool, GatewayError> { Ok(false) }
        async fn update_consumer(&self, _id: &Uuid, _c: &crate::models::Consumer) -> Result<(), GatewayError> { Ok(()) }
    }

    /// Build a QuotaTracker directly (bypassing `load()` which hits the DB)
    /// with a given plan, limit, and initial call count.
    fn make_tracker(plan: PlanTier, limit: u64, calls: u64) -> Arc<QuotaTracker> {
        let allow_overage = matches!(plan, PlanTier::Pro | PlanTier::Business);
        Arc::new(QuotaTracker {
            plan,
            limit: AtomicU64::new(limit),
            period_epoch: AtomicU64::new(current_period_epoch()),
            period_string: std::sync::Mutex::new(current_period()),
            calls: AtomicU64::new(calls),
            rejected: AtomicU64::new(0),
            overage: AtomicU64::new(0),
            allow_overage: AtomicBool::new(allow_overage),
            repo: Arc::new(StubRepo),
        })
    }

    // ===================================================================
    // CounterStrategy enum
    // ===================================================================

    #[test]
    fn counter_strategy_u8_roundtrip() {
        assert_eq!(CounterStrategy::from_u8(0), CounterStrategy::BatchedAtomic);
        assert_eq!(CounterStrategy::from_u8(1), CounterStrategy::PerThread);
        // Unknown values default to BatchedAtomic.
        assert_eq!(CounterStrategy::from_u8(2), CounterStrategy::BatchedAtomic);
        assert_eq!(CounterStrategy::from_u8(255), CounterStrategy::BatchedAtomic);
        // Enum discriminant values are stable.
        assert_eq!(CounterStrategy::BatchedAtomic as u8, 0);
        assert_eq!(CounterStrategy::PerThread as u8, 1);
    }

    #[test]
    fn counter_strategy_set_get_toggle() {
        let _lock = lock_tests();
        reset_globals();

        set_counter_strategy(CounterStrategy::BatchedAtomic);
        assert_eq!(counter_strategy(), CounterStrategy::BatchedAtomic);

        set_counter_strategy(CounterStrategy::PerThread);
        assert_eq!(counter_strategy(), CounterStrategy::PerThread);

        // Toggle back.
        set_counter_strategy(CounterStrategy::BatchedAtomic);
        assert_eq!(counter_strategy(), CounterStrategy::BatchedAtomic);
    }

    // ===================================================================
    // Per-thread slot management
    // ===================================================================

    #[test]
    fn ensure_thread_slot_assigns_and_is_idempotent() {
        let _lock = lock_tests();
        reset_globals();

        let slot1 = ensure_thread_slot().expect("should assign a slot");
        let slot2 = ensure_thread_slot().expect("should return same slot");
        assert_eq!(slot1, slot2, "calling ensure_thread_slot twice should return the same index");
        assert_eq!(THREAD_SLOT_COUNT.load(Ordering::Relaxed), 1);
    }

    // ===================================================================
    // Aggregate / reset helpers
    // ===================================================================

    #[test]
    fn aggregate_per_thread_calls_returns_sum() {
        let _lock = lock_tests();
        reset_globals();

        // Simulate 3 slots with known values.
        THREAD_SLOT_COUNT.store(3, Ordering::Relaxed);
        PER_THREAD_CALLS[0].store(10, Ordering::Relaxed);
        PER_THREAD_CALLS[1].store(20, Ordering::Relaxed);
        PER_THREAD_CALLS[2].store(30, Ordering::Relaxed);

        assert_eq!(aggregate_per_thread_calls(), 60);
    }

    #[test]
    fn aggregate_per_thread_calls_empty() {
        let _lock = lock_tests();
        reset_globals();

        // No slots registered — aggregate should be 0.
        assert_eq!(aggregate_per_thread_calls(), 0);
    }

    #[test]
    fn reset_per_thread_calls_zeros_everything() {
        let _lock = lock_tests();
        reset_globals();

        THREAD_SLOT_COUNT.store(4, Ordering::Relaxed);
        for i in 0..4 {
            PER_THREAD_CALLS[i].store(100 + i as u64, Ordering::Relaxed);
        }

        reset_per_thread_calls();

        for i in 0..4 {
            assert_eq!(PER_THREAD_CALLS[i].load(Ordering::Relaxed), 0);
        }
    }

    // ===================================================================
    // PlanTier
    // ===================================================================

    #[test]
    fn plan_tier_from_str() {
        assert_eq!(PlanTier::from_str("free"), PlanTier::Free);
        assert_eq!(PlanTier::from_str("Free"), PlanTier::Free);
        assert_eq!(PlanTier::from_str("pro"), PlanTier::Pro);
        assert_eq!(PlanTier::from_str("PRO"), PlanTier::Pro);
        assert_eq!(PlanTier::from_str("business"), PlanTier::Business);
        assert_eq!(PlanTier::from_str("enterprise"), PlanTier::Enterprise);
        // Unknown defaults to Free.
        assert_eq!(PlanTier::from_str("unknown"), PlanTier::Free);
    }

    #[test]
    fn plan_tier_monthly_limits() {
        assert_eq!(PlanTier::Free.monthly_limit(), Some(1_000_000));
        assert_eq!(PlanTier::Pro.monthly_limit(), Some(10_000_000));
        assert_eq!(PlanTier::Business.monthly_limit(), Some(100_000_000));
        assert_eq!(PlanTier::Enterprise.monthly_limit(), None);
    }

    #[test]
    fn plan_tier_as_str() {
        assert_eq!(PlanTier::Free.as_str(), "free");
        assert_eq!(PlanTier::Pro.as_str(), "pro");
        assert_eq!(PlanTier::Business.as_str(), "business");
        assert_eq!(PlanTier::Enterprise.as_str(), "enterprise");
    }

    // ===================================================================
    // check_and_count — BatchedAtomic strategy
    // ===================================================================

    #[test]
    fn batched_atomic_allowed_under_limit() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);
    }

    #[test]
    fn batched_atomic_zero_limit_always_allowed() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        // limit=0 means unlimited (Enterprise tier).
        let tracker = make_tracker(PlanTier::Enterprise, 0, 999_999_999);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);
    }

    #[test]
    fn batched_atomic_batch_flushing() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);

        // First 63 calls should stay in the thread-local batch.
        for _ in 0..63 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }
        // The global atomic should still be 0 (all in the batch).
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 0);

        // The 64th call triggers a flush.
        assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 64);
    }

    #[test]
    fn batched_atomic_rejected_when_over_limit_free_tier() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        // Start at exactly the limit.
        let tracker = make_tracker(PlanTier::Free, 100, 100);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Rejected);
        // Rejected counter should be incremented.
        assert_eq!(tracker.rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn batched_atomic_overage_for_paid_tier() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        // Pro tier allows overage.
        let tracker = make_tracker(PlanTier::Pro, 100, 100);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Overage);
        assert_eq!(tracker.overage.load(Ordering::Relaxed), 1);
    }

    // ===================================================================
    // check_and_count — PerThread strategy
    // ===================================================================

    #[test]
    fn per_thread_allowed_under_limit() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);

        // The per-thread slot should have been incremented.
        let slot = THREAD_SLOT.with(|s| s.get()) as usize;
        assert_eq!(PER_THREAD_CALLS[slot].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn per_thread_zero_limit_always_allowed() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        let tracker = make_tracker(PlanTier::Enterprise, 0, 0);
        for _ in 0..10 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }
    }

    #[test]
    fn per_thread_increments_correctly() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);
        for _ in 0..10 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }

        let slot = THREAD_SLOT.with(|s| s.get()) as usize;
        assert_eq!(PER_THREAD_CALLS[slot].load(Ordering::Relaxed), 10);
    }

    #[test]
    fn per_thread_rejected_when_over_limit_free_tier() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        // baseline (calls) = 95; this thread's slot adds 1 each call, and the
        // check is baseline + live per-thread sum.
        let tracker = make_tracker(PlanTier::Free, 100, 95);

        // 5 calls should succeed (95+1=96..95+5=100 <= 100).
        for _ in 0..5 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }

        // 6th call: baseline(95) + live_sum(6) = 101 > 100 => Rejected.
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Rejected);
        assert_eq!(tracker.rejected.load(Ordering::Relaxed), 1);

        // Per-thread slot should have been rolled back to 5.
        let slot = THREAD_SLOT.with(|s| s.get()) as usize;
        assert_eq!(PER_THREAD_CALLS[slot].load(Ordering::Relaxed), 5);
    }

    #[test]
    fn per_thread_overage_for_paid_tier() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        let tracker = make_tracker(PlanTier::Business, 100, 100);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Overage);
        assert_eq!(tracker.overage.load(Ordering::Relaxed), 1);
    }

    /// Regression test for the live-aggregate under-count (N× overshoot) bug.
    ///
    /// In PerThread mode each worker thread owns its own slot. The old hot
    /// path computed `self.calls (30s-stale cache) + my_count (only this
    /// thread's slot)`, so a thread never observed the calls already served
    /// by its N-1 sibling worker threads. On the Free hard-block tier that
    /// let every thread keep serving while it alone was under the limit,
    /// overshooting by ~N× before any thread tripped.
    ///
    /// Here three "sibling" worker threads have already counted 99 calls
    /// (slots 0..3, just under the limit of 100), with the baseline `calls`
    /// at 0. A fourth thread (this test thread, which is assigned slot 3)
    /// then issues requests. With the fix it sees the live global of 99 and
    /// trips on the call that would push the global past 100. Under the bug
    /// it would only see its own slot and wrongly keep returning `Allowed`
    /// (the overshoot), so the second assertion below would fail.
    #[test]
    fn per_thread_check_sees_sibling_threads_live_aggregate() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        // limit = 100, baseline (self.calls) = 0.
        let tracker = make_tracker(PlanTier::Free, 100, 0);

        // Three sibling worker threads have collectively counted 99 calls.
        // This thread will register as slot index 3 (count was 3).
        THREAD_SLOT_COUNT.store(3, Ordering::Relaxed);
        PER_THREAD_CALLS[0].store(33, Ordering::Relaxed);
        PER_THREAD_CALLS[1].store(33, Ordering::Relaxed);
        PER_THREAD_CALLS[2].store(33, Ordering::Relaxed);

        // 1st request from this thread: global becomes 99 + 1 = 100 <= 100.
        assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);

        // 2nd request: global would be 99 + 2 = 101 > 100 => MUST be Rejected.
        // Under the bug this thread only saw `self.calls(0) + my_count(2) = 2`
        // and returned Allowed, serving past the hard limit.
        assert_eq!(tracker.check_and_count(), QuotaResult::Rejected);
        assert_eq!(tracker.rejected.load(Ordering::Relaxed), 1);

        // This thread's own slot (index 3) is rolled back to 1 after the
        // rejection; the sibling slots are untouched. Live global stays 100.
        assert_eq!(PER_THREAD_CALLS[3].load(Ordering::Relaxed), 1);
        assert_eq!(aggregate_per_thread_calls(), 100);
    }

    // ===================================================================
    // snapshot()
    // ===================================================================

    #[test]
    fn snapshot_reflects_per_thread_counts() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        // Simulate two slots with known values.
        THREAD_SLOT_COUNT.store(2, Ordering::Relaxed);
        PER_THREAD_CALLS[0].store(42, Ordering::Relaxed);
        PER_THREAD_CALLS[1].store(58, Ordering::Relaxed);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);
        let snap = tracker.snapshot();

        // snapshot should aggregate per-thread slots, not read the shared
        // `calls` atomic (which is 0).
        assert_eq!(snap.calls_total, 100);
        assert_eq!(snap.plan, PlanTier::Free);
        assert_eq!(snap.calls_limit, Some(1_000_000));
        assert_eq!(snap.calls_remaining, Some(1_000_000 - 100));
        assert!(!snap.allow_overage);
    }

    #[test]
    fn snapshot_reads_atomic_for_batched_strategy() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Pro, 10_000_000, 5000);
        let snap = tracker.snapshot();

        assert_eq!(snap.calls_total, 5000);
        assert_eq!(snap.plan, PlanTier::Pro);
        assert!(snap.allow_overage);
    }

    #[test]
    fn snapshot_unlimited_plan() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Enterprise, 0, 1234);
        let snap = tracker.snapshot();

        assert_eq!(snap.calls_limit, None);
        assert_eq!(snap.calls_remaining, None);
    }

    // ===================================================================
    // flush()
    // ===================================================================

    #[tokio::test]
    async fn flush_preserves_baseline_for_per_thread() {
        // Regression guard for the live-aggregate fix: in PerThread mode,
        // `self.calls` is the period BASELINE (prior usage not held in any
        // slot). flush() must persist `baseline + live slot sum` to the DB
        // WITHOUT overwriting the baseline. The old code did
        // `self.calls.store(aggregate)`, dropping the baseline ~30s after
        // boot and re-opening the Free-tier overshoot.
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        // Non-zero baseline (e.g. DB-seeded prior usage this period).
        let tracker = make_tracker(PlanTier::Free, 1_000_000, 500_000);

        // Simulate live per-thread counts from two worker threads.
        THREAD_SLOT_COUNT.store(2, Ordering::Relaxed);
        PER_THREAD_CALLS[0].store(30, Ordering::Relaxed);
        PER_THREAD_CALLS[1].store(70, Ordering::Relaxed);

        // Before flush, the baseline is intact.
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 500_000);

        tracker.flush().await;

        // After flush, the baseline must be UNCHANGED (not clobbered with the
        // bare slot aggregate of 100).
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 500_000);

        // The reported total is baseline + live slots = 500_000 + 100.
        assert_eq!(tracker.snapshot().calls_total, 500_100);
    }

    #[tokio::test]
    async fn flush_does_not_change_calls_for_batched() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 42);

        tracker.flush().await;

        // For BatchedAtomic, flush just reads `self.calls` — doesn't
        // overwrite it from per-thread slots.
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 42);
    }

    // ===================================================================
    // Strategy switching mid-flight
    // ===================================================================

    #[test]
    fn strategy_switch_mid_flight() {
        let _lock = lock_tests();
        reset_globals();

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);

        // Start with BatchedAtomic.
        set_counter_strategy(CounterStrategy::BatchedAtomic);
        for _ in 0..10 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }

        // Switch to PerThread.
        set_counter_strategy(CounterStrategy::PerThread);
        for _ in 0..10 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }

        // Switch back to BatchedAtomic.
        set_counter_strategy(CounterStrategy::BatchedAtomic);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);
    }

    // ===================================================================
    // Edge cases
    // ===================================================================

    #[test]
    fn edge_case_quota_exactly_at_limit_batched() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        // calls = 99, limit = 100. The next call should bring it to 100
        // (== limit), which is Allowed.
        let tracker = make_tracker(PlanTier::Free, 100, 99);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);

        // The batch has n=1 pending. The second call will compute
        // post_total = global(99) + batch(2) = 101 > 100 => Rejected.
        let result2 = tracker.check_and_count();
        assert_eq!(result2, QuotaResult::Rejected);
    }

    #[test]
    fn edge_case_quota_exactly_at_limit_per_thread() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        // baseline = 99, limit = 100.
        let tracker = make_tracker(PlanTier::Free, 100, 99);

        // First call: baseline(99) + live_sum(1) = 100 <= 100 => Allowed.
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);

        // Second call: baseline(99) + live_sum(2) = 101 > 100 => Rejected.
        let result2 = tracker.check_and_count();
        assert_eq!(result2, QuotaResult::Rejected);
    }

    #[test]
    fn edge_case_zero_quota_free_tier() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        // A free tier with limit = 0 is treated as unlimited (the `if limit == 0`
        // early return produces Allowed).
        let tracker = make_tracker(PlanTier::Free, 0, 0);
        let result = tracker.check_and_count();
        assert_eq!(result, QuotaResult::Allowed);
    }

    #[test]
    fn edge_case_limit_one() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 1, 0);

        // First call: post_total = 0 + 1 = 1 <= 1 => Allowed.
        assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);

        // Second call: post_total = 0 + 2 = 2 > 1 => Rejected.
        assert_eq!(tracker.check_and_count(), QuotaResult::Rejected);
    }

    // ===================================================================
    // set_limit / set_allow_overage
    // ===================================================================

    #[test]
    fn set_limit_updates_limit() {
        let _lock = lock_tests();
        reset_globals();

        let tracker = make_tracker(PlanTier::Free, 100, 0);
        assert_eq!(tracker.limit.load(Ordering::Relaxed), 100);

        tracker.set_limit(Some(200));
        assert_eq!(tracker.limit.load(Ordering::Relaxed), 200);

        tracker.set_limit(None);
        assert_eq!(tracker.limit.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn set_allow_overage_toggles() {
        let _lock = lock_tests();
        reset_globals();

        let tracker = make_tracker(PlanTier::Free, 100, 0);
        assert!(!tracker.allow_overage.load(Ordering::Relaxed));

        tracker.set_allow_overage(true);
        assert!(tracker.allow_overage.load(Ordering::Relaxed));

        tracker.set_allow_overage(false);
        assert!(!tracker.allow_overage.load(Ordering::Relaxed));
    }

    // ===================================================================
    // Rollover detection
    // ===================================================================

    #[test]
    fn rollover_resets_counters() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 500);

        // Simulate per-thread data.
        THREAD_SLOT_COUNT.store(1, Ordering::Relaxed);
        PER_THREAD_CALLS[0].store(500, Ordering::Relaxed);

        // Force a rollover by passing an epoch from a different month.
        let fake_epoch = current_period_epoch() + 1;
        let fake_now = Utc::now() + chrono::Duration::days(32);
        tracker.maybe_rollover_at(fake_epoch, fake_now);

        // After rollover, all counters should be zeroed.
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.rejected.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.overage.load(Ordering::Relaxed), 0);
        assert_eq!(PER_THREAD_CALLS[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn no_rollover_same_epoch() {
        let _lock = lock_tests();
        reset_globals();

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 500);

        // Same epoch — should be a no-op.
        let same_epoch = current_period_epoch();
        tracker.maybe_rollover_at(same_epoch, Utc::now());

        assert_eq!(tracker.calls.load(Ordering::Relaxed), 500);
    }

    // ===================================================================
    // check_and_count_at (cached-timestamp variant)
    // ===================================================================

    #[test]
    fn check_and_count_at_works() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);
        let now = Utc::now();
        let result = tracker.check_and_count_at(now);
        assert_eq!(result, QuotaResult::Allowed);
    }

    // ===================================================================
    // epoch_from_datetime
    // ===================================================================

    #[test]
    fn epoch_from_datetime_deterministic() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2026, 5, 23, 12, 0, 0).unwrap();
        let epoch = epoch_from_datetime(dt);
        // 2026 * 12 + (5 - 1) = 24312 + 4 = 24316
        assert_eq!(epoch, 24316);
    }

    #[test]
    fn epoch_from_datetime_january() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let epoch = epoch_from_datetime(dt);
        assert_eq!(epoch, 2026 * 12 + 0);
    }

    #[test]
    fn epoch_from_datetime_december() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
        let epoch = epoch_from_datetime(dt);
        assert_eq!(epoch, 2026 * 12 + 11);
    }

    // ===================================================================
    // QuotaTracker::load()
    // ===================================================================

    #[tokio::test]
    async fn load_initialises_correctly() {
        let _lock = lock_tests();
        reset_globals();

        let repo: Arc<dyn Repository> = Arc::new(StubRepo);
        let tracker = QuotaTracker::load(PlanTier::Free, None, repo)
            .await
            .unwrap();

        assert_eq!(tracker.plan, PlanTier::Free);
        assert_eq!(tracker.limit.load(Ordering::Relaxed), 1_000_000);
        assert!(!tracker.allow_overage.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn load_with_server_limit_override() {
        let _lock = lock_tests();
        reset_globals();

        let repo: Arc<dyn Repository> = Arc::new(StubRepo);
        let tracker = QuotaTracker::load(PlanTier::Free, Some(42), repo)
            .await
            .unwrap();

        assert_eq!(tracker.limit.load(Ordering::Relaxed), 42);
    }

    #[tokio::test]
    async fn load_enterprise_is_unlimited() {
        let _lock = lock_tests();
        reset_globals();

        let repo: Arc<dyn Repository> = Arc::new(StubRepo);
        let tracker = QuotaTracker::load(PlanTier::Enterprise, None, repo)
            .await
            .unwrap();

        assert_eq!(tracker.limit.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn load_pro_allows_overage() {
        let _lock = lock_tests();
        reset_globals();

        let repo: Arc<dyn Repository> = Arc::new(StubRepo);
        let tracker = QuotaTracker::load(PlanTier::Pro, None, repo)
            .await
            .unwrap();

        assert!(tracker.allow_overage.load(Ordering::Relaxed));
    }

    // ===================================================================
    // Multiple rejected calls — regression
    // ===================================================================

    #[test]
    fn multiple_rejections_increment_counter() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 10, 100);

        for _ in 0..5 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Rejected);
        }
        assert_eq!(tracker.rejected.load(Ordering::Relaxed), 5);
    }

    // ===================================================================
    // Full batch cycle: 64 calls then flush
    // ===================================================================

    #[test]
    fn batched_atomic_full_batch_cycle() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        let tracker = make_tracker(PlanTier::Free, 1_000_000, 0);

        // Run two full batch cycles (128 calls).
        for _ in 0..128 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Allowed);
        }

        // After exactly 128 calls, the global should have been flushed twice.
        assert_eq!(tracker.calls.load(Ordering::Relaxed), 128);
    }

    // ===================================================================
    // Overage counter accumulation
    // ===================================================================

    #[test]
    fn overage_counter_accumulates() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::PerThread);

        let tracker = make_tracker(PlanTier::Pro, 10, 10);

        for _ in 0..5 {
            assert_eq!(tracker.check_and_count(), QuotaResult::Overage);
        }
        assert_eq!(tracker.overage.load(Ordering::Relaxed), 5);
    }

    // ===================================================================
    // Snapshot remaining count
    // ===================================================================

    #[test]
    fn snapshot_remaining_saturates_at_zero() {
        let _lock = lock_tests();
        reset_globals();
        set_counter_strategy(CounterStrategy::BatchedAtomic);

        // More calls than the limit.
        let tracker = make_tracker(PlanTier::Free, 100, 200);
        let snap = tracker.snapshot();

        assert_eq!(snap.calls_remaining, Some(0));
    }
}
