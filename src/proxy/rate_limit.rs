//! HAProxy-inspired rate limiting with stick-table sharding, multiple
//! algorithms, and native peer replication support.
//!
//! # Architecture
//!
//! ```text
//! RateLimiter (configurable strategy)
//! ├── StickTable              — Sharded hash map (configurable bucket count)
//! │   ├── Shard[0..N]         — Per-bucket Mutex<HashMap> (no cross-shard lock)
//! │   └── StickEntry          — Per-key state + HAProxy-style counters
//! ├── TokenBucket             — Classic token bucket (rate + burst)
//! ├── SlidingWindow           — Weighted sliding window counter
//! ├── FixedWindow             — Fixed time window counter
//! ├── LeakyBucket             — Leaky bucket (drain rate + capacity)
//! ├── PeerUpdate              — Serializable updates for native replication
//! └── StickTableMetrics       — Hit/miss/eviction/expiration counters
//! ```
//!
//! # Why stick tables over DashMap
//!
//! Lynxx's current rate limiter uses `DashMap<String, TokenBucket>` which
//! provides ~64 shards (CPU count × 4). HAProxy's stick tables use
//! dedicated per-bucket locking with a **configurable** shard count
//! (`CONFIG_HAP_TBL_BUCKETS`), giving finer-grained parallelism.
//!
//! More importantly, HAProxy's peer replication is native — stick table
//! entries are replicated to peer instances without an external dependency
//! (Redis). This eliminates a network round-trip from the hot path.
//!
//! # Algorithms
//!
//! All four algorithms are supported and switchable at runtime:
//!
//! | Algorithm       | Best for                        | Burst tolerance |
//! |----------------|---------------------------------|-----------------|
//! | Token bucket   | API rate limits, steady rate    | Configurable    |
//! | Sliding window | Smooth rate enforcement         | Low             |
//! | Fixed window   | Simple counting (HAProxy default)| Window-edge spike |
//! | Leaky bucket   | Queue-based shaping             | None            |

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Rate limit strategy
// ═══════════════════════════════════════════════════════════════════════════

/// Rate limiting algorithm. Stored as `AtomicU8` for lock-free switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RateLimitStrategy {
    /// Classic token bucket: tokens refill at `rate` per second,
    /// bursts allowed up to `burst` tokens. Default.
    TokenBucket = 0,
    /// Sliding window counter: weighted average of current and previous
    /// fixed windows. Smoother than fixed window.
    SlidingWindow = 1,
    /// Fixed window counter: simple count per time window. Cheapest but
    /// allows 2× burst at window boundaries.
    FixedWindow = 2,
    /// Leaky bucket: requests drain at a fixed rate. No burst tolerance.
    /// Best for strict traffic shaping.
    LeakyBucket = 3,
}

impl RateLimitStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::SlidingWindow,
            2 => Self::FixedWindow,
            3 => Self::LeakyBucket,
            _ => Self::TokenBucket,
        }
    }
}

static DEFAULT_STRATEGY: AtomicU8 = AtomicU8::new(RateLimitStrategy::TokenBucket as u8);
static RATE_LIMITING_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_default_strategy(s: RateLimitStrategy) {
    DEFAULT_STRATEGY.store(s as u8, Ordering::Relaxed);
}

pub fn default_strategy() -> RateLimitStrategy {
    RateLimitStrategy::from_u8(DEFAULT_STRATEGY.load(Ordering::Relaxed))
}

pub fn set_rate_limiting_enabled(enabled: bool) {
    RATE_LIMITING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_rate_limiting_enabled() -> bool {
    RATE_LIMITING_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// Rate limit result
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of a rate limit check.
#[derive(Clone, Debug)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allow {
        /// Approximate remaining quota in this window/bucket.
        remaining: u32,
        /// Configured limit.
        limit: u32,
    },
    /// Request is denied — rate limit exceeded.
    Deny {
        /// How long the client should wait before retrying.
        retry_after: Duration,
        /// Configured limit.
        limit: u32,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HAProxy-style counters
// ═══════════════════════════════════════════════════════════════════════════

/// Per-key counters modeled after HAProxy's stick-table data types:
/// `http_req_cnt`, `http_err_cnt`, `conn_cnt`, `bytes_in_cnt`,
/// `bytes_out_cnt`, and general purpose counters (`gpc0`–`gpc3`).
#[derive(Clone, Debug, Default)]
pub struct RateLimitCounters {
    pub http_req_cnt: u64,
    pub http_err_cnt: u64,
    pub conn_cnt: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// General purpose counters (HAProxy's gpc0–gpc3).
    pub gpc: [u64; 4],
}

impl RateLimitCounters {
    /// Merge with a peer update using `max()` for monotonic convergence.
    /// This is the CRDT-style merge that ensures eventually consistent
    /// counters across peers without coordination.
    pub fn merge_max(&mut self, other: &Self) {
        self.http_req_cnt = self.http_req_cnt.max(other.http_req_cnt);
        self.http_err_cnt = self.http_err_cnt.max(other.http_err_cnt);
        self.conn_cnt = self.conn_cnt.max(other.conn_cnt);
        self.bytes_in = self.bytes_in.max(other.bytes_in);
        self.bytes_out = self.bytes_out.max(other.bytes_out);
        for i in 0..4 {
            self.gpc[i] = self.gpc[i].max(other.gpc[i]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Stick entry — per-key state
// ═══════════════════════════════════════════════════════════════════════════

/// Per-key entry in the stick table. Contains algorithm-specific state
/// and general-purpose counters.
pub struct StickEntry {
    // ── Timestamps ──
    pub created_at: Instant,
    pub last_seen: Instant,
    /// Last modification time (for peer replication delta collection).
    pub updated_at: Instant,

    // ── Token bucket state ──
    pub tokens: f64,
    pub last_refill: Instant,

    // ── Sliding / fixed window state ──
    pub current_count: u32,
    pub previous_count: u32,
    pub window_start: Instant,

    // ── Leaky bucket state ──
    pub leak_level: f64,
    pub last_leak: Instant,

    // ── HAProxy-style counters ──
    pub counters: RateLimitCounters,
}

impl StickEntry {
    fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            last_seen: now,
            updated_at: now,
            tokens: 0.0,
            last_refill: now,
            current_count: 0,
            previous_count: 0,
            window_start: now,
            leak_level: 0.0,
            last_leak: now,
            counters: RateLimitCounters::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Shard — per-bucket storage
// ═══════════════════════════════════════════════════════════════════════════

struct Shard {
    entries: HashMap<String, StickEntry, FastHasher>,
}

impl Shard {
    fn new() -> Self {
        Self {
            entries: HashMap::with_hasher(FastHasher::default()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// StickTable — HAProxy-inspired sharded hash map
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the stick table.
#[derive(Clone, Debug)]
pub struct StickTableConfig {
    /// Number of shards (must be a power of 2). Default: 256.
    /// HAProxy's `CONFIG_HAP_TBL_BUCKETS` equivalent.
    pub shard_count: usize,
    /// Maximum entries per shard before LRU eviction. Default: 4096.
    pub max_entries_per_shard: usize,
    /// Entry TTL — entries not seen within this window are expired.
    /// Default: 10 minutes.
    pub entry_ttl: Duration,
}

impl Default for StickTableConfig {
    fn default() -> Self {
        Self {
            shard_count: 256,
            max_entries_per_shard: 4096,
            entry_ttl: Duration::from_secs(600),
        }
    }
}

/// Performance counters for the stick table.
pub struct StickTableMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub expirations: AtomicU64,
}

impl StickTableMetrics {
    const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            expirations: AtomicU64::new(0),
        }
    }
}

/// Sharded hash map with per-bucket `Mutex` locking. Each shard holds
/// an independent `HashMap` — zero cross-shard contention.
///
/// This is Lynxx's equivalent of HAProxy's `struct stktable` with
/// `stk_per_bucket` per-bucket locks.
pub struct StickTable {
    shards: Box<[Mutex<Shard>]>,
    shard_mask: usize,
    hasher: FastHasher,
    config: StickTableConfig,
    pub metrics: StickTableMetrics,
}

impl StickTable {
    pub fn new(config: StickTableConfig) -> Self {
        // Ensure shard_count is a power of 2.
        let shard_count = config.shard_count.next_power_of_two();
        let shards: Vec<Mutex<Shard>> = (0..shard_count)
            .map(|_| Mutex::new(Shard::new()))
            .collect();

        Self {
            shards: shards.into_boxed_slice(),
            shard_mask: shard_count - 1,
            hasher: FastHasher::default(),
            config,
            metrics: StickTableMetrics::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(StickTableConfig::default())
    }

    /// Number of shards.
    pub fn shard_count(&self) -> usize {
        self.shard_mask + 1
    }

    /// Compute the shard index for a key.
    fn shard_index(&self, key: &str) -> usize {
        let mut h = self.hasher.build_hasher();
        key.hash(&mut h);
        h.finish() as usize & self.shard_mask
    }

    /// Lock the shard containing `key`. Returns the mutex guard.
    fn shard_for(&self, key: &str) -> std::sync::MutexGuard<'_, Shard> {
        let idx = self.shard_index(key);
        self.shards[idx].lock().unwrap()
    }

    /// Get or create an entry, applying `init` to new entries.
    /// Also handles LRU eviction when the shard is full.
    fn get_or_create(
        &self,
        key: &str,
        now: Instant,
        init: impl FnOnce(&mut StickEntry),
    ) -> std::sync::MutexGuard<'_, Shard> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].lock().unwrap();

        if shard.entries.contains_key(key) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            if let Some(entry) = shard.entries.get_mut(key) {
                entry.last_seen = now;
            }
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            // Evict if shard is full.
            if shard.entries.len() >= self.config.max_entries_per_shard {
                self.evict_oldest(&mut shard);
            }
            let mut entry = StickEntry::new(now);
            init(&mut entry);
            shard.entries.insert(key.to_string(), entry);
        }

        shard
    }

    /// Evict the entry with the oldest `last_seen` from a shard.
    fn evict_oldest(&self, shard: &mut Shard) {
        let oldest_key = shard
            .entries
            .iter()
            .min_by_key(|(_, v)| v.last_seen)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest_key {
            shard.entries.remove(&key);
            self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Expire entries not seen within the TTL. Returns the count removed.
    pub fn expire_stale(&self) -> usize {
        let now = Instant::now();
        let ttl = self.config.entry_ttl;
        let mut total = 0;

        for shard_mutex in self.shards.iter() {
            let mut shard = shard_mutex.lock().unwrap();
            let before = shard.entries.len();
            shard
                .entries
                .retain(|_, entry| now.duration_since(entry.last_seen) < ttl);
            let expired = before - shard.entries.len();
            total += expired;
        }

        self.metrics
            .expirations
            .fetch_add(total as u64, Ordering::Relaxed);
        total
    }

    /// Total entries across all shards.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap().entries.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries.
    pub fn clear(&self) {
        for shard_mutex in self.shards.iter() {
            shard_mutex.lock().unwrap().entries.clear();
        }
    }

    /// Collect entries modified since `since` for peer replication.
    pub fn collect_updates(&self, since: Instant) -> Vec<PeerUpdate> {
        let mut updates = Vec::new();
        for shard_mutex in self.shards.iter() {
            let shard = shard_mutex.lock().unwrap();
            for (key, entry) in shard.entries.iter() {
                if entry.updated_at >= since {
                    updates.push(PeerUpdate {
                        key: key.clone(),
                        counters: entry.counters.clone(),
                        timestamp: entry.updated_at,
                    });
                }
            }
        }
        updates
    }

    /// Apply a peer update — merge counters using CRDT-style `max()`.
    pub fn apply_update(&self, update: &PeerUpdate) {
        let mut shard = self.shard_for(&update.key);
        let now = Instant::now();
        let entry = shard
            .entries
            .entry(update.key.clone())
            .or_insert_with(|| StickEntry::new(now));
        entry.counters.merge_max(&update.counters);
        entry.updated_at = now;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Peer update — native replication (no Redis)
// ═══════════════════════════════════════════════════════════════════════════

/// Serializable stick-table update for peer replication. Replaces Redis
/// INCR + EXPIRE with native cross-instance synchronization, eliminating
/// a network round-trip from the rate-limit hot path.
#[derive(Clone, Debug)]
pub struct PeerUpdate {
    pub key: String,
    pub counters: RateLimitCounters,
    pub timestamp: Instant,
}

// ═══════════════════════════════════════════════════════════════════════════
// RateLimiter — top-level dispatcher
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for a rate limiter instance.
#[derive(Clone, Debug)]
pub struct RateLimiterConfig {
    pub strategy: RateLimitStrategy,
    // ── Token bucket ──
    /// Tokens added per second.
    pub token_rate: f64,
    /// Maximum tokens (burst size).
    pub token_burst: u32,
    // ── Sliding / fixed window ──
    /// Window duration.
    pub window: Duration,
    /// Max requests per window.
    pub max_requests: u32,
    // ── Leaky bucket ──
    /// Drain rate (requests per second).
    pub leak_rate: f64,
    /// Bucket capacity.
    pub leak_capacity: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            strategy: RateLimitStrategy::TokenBucket,
            token_rate: 10.0,
            token_burst: 20,
            window: Duration::from_secs(60),
            max_requests: 100,
            leak_rate: 10.0,
            leak_capacity: 20,
        }
    }
}

/// Rate limiter combining a stick table with a configurable algorithm.
///
/// Thread-safe: the stick table uses per-shard `Mutex` locks and can
/// be shared via `Arc<RateLimiter>` across Tokio tasks.
pub struct RateLimiter {
    table: StickTable,
    config: RateLimiterConfig,
}

impl RateLimiter {
    pub fn new(table_config: StickTableConfig, limiter_config: RateLimiterConfig) -> Self {
        Self {
            table: StickTable::new(table_config),
            config: limiter_config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(StickTableConfig::default(), RateLimiterConfig::default())
    }

    /// Check if a request for `key` is allowed. Uses `Instant::now()`.
    pub fn check(&self, key: &str) -> RateLimitResult {
        self.check_at(key, Instant::now())
    }

    /// Check with an explicit timestamp (for testing / deterministic replay).
    pub fn check_at(&self, key: &str, now: Instant) -> RateLimitResult {
        match self.config.strategy {
            RateLimitStrategy::TokenBucket => self.check_token_bucket(key, now),
            RateLimitStrategy::SlidingWindow => self.check_sliding_window(key, now),
            RateLimitStrategy::FixedWindow => self.check_fixed_window(key, now),
            RateLimitStrategy::LeakyBucket => self.check_leaky_bucket(key, now),
        }
    }

    // ── Token bucket ──

    fn check_token_bucket(&self, key: &str, now: Instant) -> RateLimitResult {
        let burst = self.config.token_burst;
        let rate = self.config.token_rate;

        let mut shard = self.table.get_or_create(key, now, |entry| {
            entry.tokens = burst as f64; // Start with full bucket.
        });
        let entry = shard.entries.get_mut(key).unwrap();

        // Refill tokens.
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rate).min(burst as f64);
        entry.last_refill = now;
        entry.updated_at = now;
        entry.counters.http_req_cnt += 1;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            RateLimitResult::Allow {
                remaining: entry.tokens as u32,
                limit: burst,
            }
        } else {
            let wait = (1.0 - entry.tokens) / rate;
            RateLimitResult::Deny {
                retry_after: Duration::from_secs_f64(wait),
                limit: burst,
            }
        }
    }

    // ── Sliding window ──

    fn check_sliding_window(&self, key: &str, now: Instant) -> RateLimitResult {
        let window = self.config.window;
        let max = self.config.max_requests;
        let window_secs = window.as_secs_f64();

        let mut shard = self.table.get_or_create(key, now, |_| {});
        let entry = shard.entries.get_mut(key).unwrap();

        // Rotate windows if the current window has elapsed.
        let elapsed_since_window = now.duration_since(entry.window_start).as_secs_f64();
        if elapsed_since_window >= window_secs {
            let full_windows = (elapsed_since_window / window_secs) as u32;
            if full_windows >= 2 {
                entry.previous_count = 0;
                entry.current_count = 0;
            } else {
                entry.previous_count = entry.current_count;
                entry.current_count = 0;
            }
            // Align window_start to the most recent window boundary.
            let offset_secs = (full_windows as f64) * window_secs;
            entry.window_start += Duration::from_secs_f64(offset_secs);
        }

        // Compute the weighted count across the sliding window.
        let elapsed_in_window = now.duration_since(entry.window_start).as_secs_f64();
        let fraction = (elapsed_in_window / window_secs).clamp(0.0, 1.0);
        let weighted =
            entry.previous_count as f64 * (1.0 - fraction) + entry.current_count as f64;

        entry.updated_at = now;
        entry.counters.http_req_cnt += 1;

        if weighted < max as f64 {
            entry.current_count += 1;
            RateLimitResult::Allow {
                remaining: (max as f64 - weighted - 1.0).max(0.0) as u32,
                limit: max,
            }
        } else {
            let retry_secs = window_secs * (1.0 - fraction);
            RateLimitResult::Deny {
                retry_after: Duration::from_secs_f64(retry_secs.max(0.001)),
                limit: max,
            }
        }
    }

    // ── Fixed window ──

    fn check_fixed_window(&self, key: &str, now: Instant) -> RateLimitResult {
        let window = self.config.window;
        let max = self.config.max_requests;

        let mut shard = self.table.get_or_create(key, now, |_| {});
        let entry = shard.entries.get_mut(key).unwrap();

        // Reset if the window has elapsed.
        if now.duration_since(entry.window_start) >= window {
            entry.current_count = 0;
            entry.window_start = now;
        }

        entry.updated_at = now;
        entry.counters.http_req_cnt += 1;

        if entry.current_count < max {
            entry.current_count += 1;
            RateLimitResult::Allow {
                remaining: max - entry.current_count,
                limit: max,
            }
        } else {
            let elapsed = now.duration_since(entry.window_start);
            RateLimitResult::Deny {
                retry_after: window.saturating_sub(elapsed),
                limit: max,
            }
        }
    }

    // ── Leaky bucket ──

    fn check_leaky_bucket(&self, key: &str, now: Instant) -> RateLimitResult {
        let rate = self.config.leak_rate;
        let capacity = self.config.leak_capacity;

        let mut shard = self.table.get_or_create(key, now, |_| {});
        let entry = shard.entries.get_mut(key).unwrap();

        // Drain leaked water.
        let elapsed = now.duration_since(entry.last_leak).as_secs_f64();
        entry.leak_level = (entry.leak_level - elapsed * rate).max(0.0);
        entry.last_leak = now;
        entry.updated_at = now;
        entry.counters.http_req_cnt += 1;

        if entry.leak_level < capacity as f64 {
            entry.leak_level += 1.0;
            RateLimitResult::Allow {
                remaining: (capacity as f64 - entry.leak_level) as u32,
                limit: capacity,
            }
        } else {
            let wait = (entry.leak_level - capacity as f64 + 1.0) / rate;
            RateLimitResult::Deny {
                retry_after: Duration::from_secs_f64(wait),
                limit: capacity,
            }
        }
    }

    // ── Counter operations (HAProxy stick-table stores) ──

    /// Record a request for a key (increments `http_req_cnt`).
    pub fn record_request(&self, key: &str) {
        let now = Instant::now();
        let mut shard = self.table.shard_for(key);
        if let Some(entry) = shard.entries.get_mut(key) {
            entry.counters.http_req_cnt += 1;
            entry.last_seen = now;
            entry.updated_at = now;
        }
    }

    /// Record an error for a key (increments `http_err_cnt`).
    pub fn record_error(&self, key: &str) {
        let now = Instant::now();
        let mut shard = self.table.shard_for(key);
        if let Some(entry) = shard.entries.get_mut(key) {
            entry.counters.http_err_cnt += 1;
            entry.last_seen = now;
            entry.updated_at = now;
        }
    }

    /// Record byte counters for a key.
    pub fn record_bytes(&self, key: &str, bytes_in: u64, bytes_out: u64) {
        let now = Instant::now();
        let mut shard = self.table.shard_for(key);
        if let Some(entry) = shard.entries.get_mut(key) {
            entry.counters.bytes_in += bytes_in;
            entry.counters.bytes_out += bytes_out;
            entry.last_seen = now;
            entry.updated_at = now;
        }
    }

    /// Increment a general-purpose counter (gpc0–gpc3).
    pub fn increment_gpc(&self, key: &str, index: usize) {
        if index >= 4 {
            return;
        }
        let now = Instant::now();
        let mut shard = self.table.shard_for(key);
        if let Some(entry) = shard.entries.get_mut(key) {
            entry.counters.gpc[index] += 1;
            entry.last_seen = now;
            entry.updated_at = now;
        }
    }

    /// Read the current counters for a key.
    pub fn get_counters(&self, key: &str) -> Option<RateLimitCounters> {
        let shard = self.table.shard_for(key);
        shard.entries.get(key).map(|e| e.counters.clone())
    }

    // ── Delegation to stick table ──

    pub fn table(&self) -> &StickTable {
        &self.table
    }

    pub fn expire_stale(&self) -> usize {
        self.table.expire_stale()
    }

    pub fn entry_count(&self) -> usize {
        self.table.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn token_bucket_limiter(rate: f64, burst: u32) -> RateLimiter {
        RateLimiter::new(
            StickTableConfig {
                shard_count: 16,
                max_entries_per_shard: 64,
                entry_ttl: Duration::from_secs(60),
            },
            RateLimiterConfig {
                strategy: RateLimitStrategy::TokenBucket,
                token_rate: rate,
                token_burst: burst,
                ..Default::default()
            },
        )
    }

    fn sliding_window_limiter(window: Duration, max: u32) -> RateLimiter {
        RateLimiter::new(
            StickTableConfig {
                shard_count: 16,
                max_entries_per_shard: 64,
                entry_ttl: Duration::from_secs(60),
            },
            RateLimiterConfig {
                strategy: RateLimitStrategy::SlidingWindow,
                window,
                max_requests: max,
                ..Default::default()
            },
        )
    }

    fn fixed_window_limiter(window: Duration, max: u32) -> RateLimiter {
        RateLimiter::new(
            StickTableConfig {
                shard_count: 16,
                max_entries_per_shard: 64,
                entry_ttl: Duration::from_secs(60),
            },
            RateLimiterConfig {
                strategy: RateLimitStrategy::FixedWindow,
                window,
                max_requests: max,
                ..Default::default()
            },
        )
    }

    fn leaky_bucket_limiter(rate: f64, capacity: u32) -> RateLimiter {
        RateLimiter::new(
            StickTableConfig {
                shard_count: 16,
                max_entries_per_shard: 64,
                entry_ttl: Duration::from_secs(60),
            },
            RateLimiterConfig {
                strategy: RateLimitStrategy::LeakyBucket,
                leak_rate: rate,
                leak_capacity: capacity,
                ..Default::default()
            },
        )
    }

    // ── StickTable ──

    #[test]
    fn stick_table_shard_count_power_of_two() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 100, // Not a power of 2.
            ..Default::default()
        });
        // Rounds up to 128.
        assert_eq!(table.shard_count(), 128);
    }

    #[test]
    fn stick_table_insert_and_len() {
        let table = StickTable::with_defaults();
        assert_eq!(table.len(), 0);

        // Simulate entry creation via shard access.
        {
            let mut shard = table.shard_for("key1");
            shard
                .entries
                .insert("key1".to_string(), StickEntry::new(Instant::now()));
        }
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn stick_table_shard_distribution() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 8,
            ..Default::default()
        });

        // Different keys should (likely) hash to different shards.
        let idx1 = table.shard_index("user:1");
        let idx2 = table.shard_index("user:2");
        let idx3 = table.shard_index("user:3");

        // At least two out of three should differ (probabilistic but
        // extremely likely with a good hash).
        let unique = [idx1, idx2, idx3]
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique >= 2, "poor shard distribution: all same shard");
    }

    #[test]
    fn stick_table_expire_stale() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 4,
            entry_ttl: Duration::from_millis(1),
            ..Default::default()
        });

        {
            let mut shard = table.shard_for("stale");
            let mut entry = StickEntry::new(Instant::now());
            // Backdate last_seen so it appears stale.
            entry.last_seen = Instant::now() - Duration::from_secs(1);
            shard.entries.insert("stale".to_string(), entry);
        }
        assert_eq!(table.len(), 1);

        let expired = table.expire_stale();
        assert_eq!(expired, 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn stick_table_eviction_on_full() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 1, // Single shard for determinism.
            max_entries_per_shard: 2,
            entry_ttl: Duration::from_secs(60),
        });

        let now = Instant::now();
        // Insert 3 entries into the same shard; the 3rd should evict.
        {
            let mut shard = table.shards[0].lock().unwrap();
            let mut e1 = StickEntry::new(now);
            e1.last_seen = now - Duration::from_secs(10); // Oldest.
            shard.entries.insert("a".to_string(), e1);
            shard
                .entries
                .insert("b".to_string(), StickEntry::new(now));
        }
        assert_eq!(table.len(), 2);

        // get_or_create should evict "a" (oldest last_seen).
        // Drop the returned MutexGuard before calling len() — len()
        // needs to lock all shards, including shard 0.
        drop(table.get_or_create("c", now, |_| {}));
        assert_eq!(table.len(), 2); // Still 2 — old one evicted.
        assert!(table.metrics.evictions.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn stick_table_peer_update() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 4,
            ..Default::default()
        });

        // Insert an entry.
        {
            let mut shard = table.shard_for("peer_key");
            let mut entry = StickEntry::new(Instant::now());
            entry.counters.http_req_cnt = 10;
            shard.entries.insert("peer_key".to_string(), entry);
        }

        // Apply a peer update with higher count.
        table.apply_update(&PeerUpdate {
            key: "peer_key".to_string(),
            counters: RateLimitCounters {
                http_req_cnt: 20,
                ..Default::default()
            },
            timestamp: Instant::now(),
        });

        // Verify merge_max applied.
        let shard = table.shard_for("peer_key");
        let entry = shard.entries.get("peer_key").unwrap();
        assert_eq!(entry.counters.http_req_cnt, 20);
    }

    #[test]
    fn stick_table_collect_updates() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 4,
            ..Default::default()
        });

        let before = Instant::now();
        {
            let mut shard = table.shard_for("k1");
            shard
                .entries
                .insert("k1".to_string(), StickEntry::new(Instant::now()));
        }
        let updates = table.collect_updates(before);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].key, "k1");
    }

    // ── Token bucket ──

    #[test]
    fn token_bucket_allows_up_to_burst() {
        let limiter = token_bucket_limiter(10.0, 5);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(limiter.check_at("client", now).is_allowed());
        }
        // 6th request should be denied.
        assert!(limiter.check_at("client", now).is_denied());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = token_bucket_limiter(10.0, 5);
        let t0 = Instant::now();

        // Drain all tokens.
        for _ in 0..5 {
            limiter.check_at("client", t0);
        }
        assert!(limiter.check_at("client", t0).is_denied());

        // After 0.5 seconds, 5 tokens should have refilled (10/s × 0.5s).
        let t1 = t0 + Duration::from_millis(500);
        for _ in 0..5 {
            assert!(limiter.check_at("client", t1).is_allowed());
        }
        assert!(limiter.check_at("client", t1).is_denied());
    }

    #[test]
    fn token_bucket_retry_after() {
        let limiter = token_bucket_limiter(10.0, 1);
        let now = Instant::now();

        assert!(limiter.check_at("client", now).is_allowed());
        let result = limiter.check_at("client", now);
        if let RateLimitResult::Deny { retry_after, limit } = result {
            assert!(retry_after.as_millis() <= 100); // ~100ms for 1 token at 10/s.
            assert_eq!(limit, 1);
        } else {
            panic!("expected Deny");
        }
    }

    // ── Sliding window ──

    #[test]
    fn sliding_window_allows_up_to_max() {
        let limiter = sliding_window_limiter(Duration::from_secs(60), 5);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(limiter.check_at("client", now).is_allowed());
        }
        assert!(limiter.check_at("client", now).is_denied());
    }

    #[test]
    fn sliding_window_decays_previous() {
        let limiter = sliding_window_limiter(Duration::from_secs(10), 10);
        let t0 = Instant::now();

        // Fill up the first window.
        for _ in 0..10 {
            limiter.check_at("client", t0);
        }
        assert!(limiter.check_at("client", t0).is_denied());

        // At 50% into the next window, previous count is weighted at 50%.
        // Weighted = 10 * 0.5 + 0 = 5.0, so 5 more requests should fit.
        let t1 = t0 + Duration::from_secs(15);
        let mut allowed = 0;
        for _ in 0..10 {
            if limiter.check_at("client", t1).is_allowed() {
                allowed += 1;
            }
        }
        assert!(allowed >= 4 && allowed <= 6, "expected ~5, got {allowed}");
    }

    // ── Fixed window ──

    #[test]
    fn fixed_window_allows_up_to_max() {
        let limiter = fixed_window_limiter(Duration::from_secs(60), 5);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(limiter.check_at("client", now).is_allowed());
        }
        assert!(limiter.check_at("client", now).is_denied());
    }

    #[test]
    fn fixed_window_resets_after_expiry() {
        let limiter = fixed_window_limiter(Duration::from_secs(1), 3);
        let t0 = Instant::now();

        for _ in 0..3 {
            limiter.check_at("client", t0);
        }
        assert!(limiter.check_at("client", t0).is_denied());

        // After the window expires, counter resets.
        let t1 = t0 + Duration::from_secs(2);
        assert!(limiter.check_at("client", t1).is_allowed());
    }

    // ── Leaky bucket ──

    #[test]
    fn leaky_bucket_allows_up_to_capacity() {
        let limiter = leaky_bucket_limiter(10.0, 5);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(limiter.check_at("client", now).is_allowed());
        }
        assert!(limiter.check_at("client", now).is_denied());
    }

    #[test]
    fn leaky_bucket_drains_over_time() {
        let limiter = leaky_bucket_limiter(10.0, 3);
        let t0 = Instant::now();

        // Fill the bucket.
        for _ in 0..3 {
            limiter.check_at("client", t0);
        }
        assert!(limiter.check_at("client", t0).is_denied());

        // After 0.5 seconds, 5 units have drained (10/s × 0.5s).
        // Bucket should be empty and accept 3 more.
        let t1 = t0 + Duration::from_millis(500);
        for _ in 0..3 {
            assert!(limiter.check_at("client", t1).is_allowed());
        }
        assert!(limiter.check_at("client", t1).is_denied());
    }

    // ── Counters ──

    #[test]
    fn counters_increment() {
        let limiter = token_bucket_limiter(100.0, 100);
        let now = Instant::now();

        // Create the entry.
        limiter.check_at("client", now);

        limiter.record_error("client");
        limiter.record_bytes("client", 1024, 2048);
        limiter.increment_gpc("client", 0);
        limiter.increment_gpc("client", 0);
        limiter.increment_gpc("client", 1);

        let counters = limiter.get_counters("client").unwrap();
        assert_eq!(counters.http_req_cnt, 1); // From the check.
        assert_eq!(counters.http_err_cnt, 1);
        assert_eq!(counters.bytes_in, 1024);
        assert_eq!(counters.bytes_out, 2048);
        assert_eq!(counters.gpc[0], 2);
        assert_eq!(counters.gpc[1], 1);
    }

    #[test]
    fn counters_merge_max() {
        let mut a = RateLimitCounters {
            http_req_cnt: 10,
            http_err_cnt: 5,
            conn_cnt: 3,
            bytes_in: 1000,
            bytes_out: 2000,
            gpc: [1, 2, 3, 4],
        };
        let b = RateLimitCounters {
            http_req_cnt: 8,
            http_err_cnt: 7,
            conn_cnt: 1,
            bytes_in: 1500,
            bytes_out: 500,
            gpc: [0, 5, 2, 4],
        };
        a.merge_max(&b);

        assert_eq!(a.http_req_cnt, 10); // max(10, 8)
        assert_eq!(a.http_err_cnt, 7); // max(5, 7)
        assert_eq!(a.conn_cnt, 3); // max(3, 1)
        assert_eq!(a.bytes_in, 1500); // max(1000, 1500)
        assert_eq!(a.bytes_out, 2000); // max(2000, 500)
        assert_eq!(a.gpc, [1, 5, 3, 4]); // per-element max
    }

    // ── Strategy toggles ──

    #[test]
    fn strategy_toggle() {
        set_default_strategy(RateLimitStrategy::SlidingWindow);
        assert_eq!(default_strategy(), RateLimitStrategy::SlidingWindow);

        set_default_strategy(RateLimitStrategy::FixedWindow);
        assert_eq!(default_strategy(), RateLimitStrategy::FixedWindow);

        set_default_strategy(RateLimitStrategy::LeakyBucket);
        assert_eq!(default_strategy(), RateLimitStrategy::LeakyBucket);

        set_default_strategy(RateLimitStrategy::TokenBucket);
        assert_eq!(default_strategy(), RateLimitStrategy::TokenBucket);
    }

    #[test]
    fn strategy_u8_roundtrip() {
        for v in 0..=3u8 {
            let s = RateLimitStrategy::from_u8(v);
            assert_eq!(s as u8, v);
        }
        assert_eq!(
            RateLimitStrategy::from_u8(99),
            RateLimitStrategy::TokenBucket
        );
    }

    #[test]
    fn rate_limiting_enabled_by_default() {
        assert!(is_rate_limiting_enabled());
    }

    // ── Per-key isolation ──

    #[test]
    fn different_keys_independent() {
        let limiter = token_bucket_limiter(10.0, 3);
        let now = Instant::now();

        // Drain key A.
        for _ in 0..3 {
            limiter.check_at("a", now);
        }
        assert!(limiter.check_at("a", now).is_denied());

        // Key B should still have full quota.
        assert!(limiter.check_at("b", now).is_allowed());
    }

    // ── StickTableConfig defaults ──

    #[test]
    fn stick_table_config_defaults() {
        let cfg = StickTableConfig::default();
        assert_eq!(cfg.shard_count, 256);
        assert_eq!(cfg.max_entries_per_shard, 4096);
        assert_eq!(cfg.entry_ttl, Duration::from_secs(600));
    }

    // ── StickTable::is_empty ──

    #[test]
    fn stick_table_is_empty() {
        let table = StickTable::with_defaults();
        assert!(table.is_empty());

        {
            let mut shard = table.shard_for("x");
            shard
                .entries
                .insert("x".to_string(), StickEntry::new(Instant::now()));
        }
        assert!(!table.is_empty());

        table.clear();
        assert!(table.is_empty());
    }

    // ── StickTableMetrics ──

    #[test]
    fn stick_table_metrics_hit_miss_eviction() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 1,
            max_entries_per_shard: 2,
            entry_ttl: Duration::from_secs(60),
        });
        let now = Instant::now();

        // First access is a miss.
        drop(table.get_or_create("k1", now, |_| {}));
        assert_eq!(table.metrics.misses.load(Ordering::Relaxed), 1);
        assert_eq!(table.metrics.hits.load(Ordering::Relaxed), 0);

        // Second access to the same key is a hit.
        drop(table.get_or_create("k1", now, |_| {}));
        assert_eq!(table.metrics.hits.load(Ordering::Relaxed), 1);

        // Fill shard to capacity then trigger eviction.
        drop(table.get_or_create("k2", now, |_| {}));
        assert_eq!(table.metrics.misses.load(Ordering::Relaxed), 2);
        drop(table.get_or_create("k3", now, |_| {}));
        assert!(table.metrics.evictions.load(Ordering::Relaxed) >= 1);
    }

    // ── RateLimiter::new / with_defaults ──

    #[test]
    fn rate_limiter_defaults() {
        let limiter = RateLimiter::with_defaults();
        // Default config: token bucket, rate=10, burst=20.
        assert_eq!(limiter.entry_count(), 0);
        // First 20 requests should be allowed (burst=20).
        let now = Instant::now();
        for _ in 0..20 {
            assert!(limiter.check_at("client", now).is_allowed());
        }
        assert!(limiter.check_at("client", now).is_denied());
    }

    // ── RateLimiter::check (public API, not check_at) ──

    #[test]
    fn rate_limiter_check_public_api() {
        let limiter = token_bucket_limiter(1000.0, 5);
        // check() uses Instant::now() internally.
        for _ in 0..5 {
            let result = limiter.check("user1");
            assert!(result.is_allowed());
        }
        let result = limiter.check("user1");
        assert!(result.is_denied());
    }

    // ── increment_gpc ──

    #[test]
    fn increment_gpc_counter() {
        let limiter = token_bucket_limiter(100.0, 100);
        let now = Instant::now();
        limiter.check_at("gpc_test", now); // Create entry.

        limiter.increment_gpc("gpc_test", 2);
        limiter.increment_gpc("gpc_test", 2);
        limiter.increment_gpc("gpc_test", 3);
        // Out-of-bounds index should be ignored.
        limiter.increment_gpc("gpc_test", 4);
        limiter.increment_gpc("gpc_test", 99);

        let c = limiter.get_counters("gpc_test").unwrap();
        assert_eq!(c.gpc[0], 0);
        assert_eq!(c.gpc[1], 0);
        assert_eq!(c.gpc[2], 2);
        assert_eq!(c.gpc[3], 1);
    }

    // ── get_counters for non-existing key ──

    #[test]
    fn get_counters_nonexistent_key() {
        let limiter = token_bucket_limiter(10.0, 5);
        assert!(limiter.get_counters("does_not_exist").is_none());
    }

    // ── entry_count delegation ──

    #[test]
    fn entry_count_matches_table_len() {
        let limiter = token_bucket_limiter(10.0, 5);
        let now = Instant::now();
        assert_eq!(limiter.entry_count(), 0);

        limiter.check_at("a", now);
        limiter.check_at("b", now);
        assert_eq!(limiter.entry_count(), 2);

        limiter.check_at("a", now); // Hit existing entry, no new entry.
        assert_eq!(limiter.entry_count(), 2);
    }

    // ── RateLimitCounters::default ──

    #[test]
    fn rate_limit_counters_default_all_zeros() {
        let c = RateLimitCounters::default();
        assert_eq!(c.http_req_cnt, 0);
        assert_eq!(c.http_err_cnt, 0);
        assert_eq!(c.conn_cnt, 0);
        assert_eq!(c.bytes_in, 0);
        assert_eq!(c.bytes_out, 0);
        assert_eq!(c.gpc, [0, 0, 0, 0]);
    }

    // ── PeerUpdate creates entry for non-existing key ──

    #[test]
    fn peer_update_creates_new_entry() {
        let table = StickTable::new(StickTableConfig {
            shard_count: 4,
            ..Default::default()
        });
        assert_eq!(table.len(), 0);

        table.apply_update(&PeerUpdate {
            key: "new_peer_key".to_string(),
            counters: RateLimitCounters {
                http_req_cnt: 42,
                conn_cnt: 7,
                gpc: [1, 2, 3, 4],
                ..Default::default()
            },
            timestamp: Instant::now(),
        });

        assert_eq!(table.len(), 1);
        let shard = table.shard_for("new_peer_key");
        let entry = shard.entries.get("new_peer_key").unwrap();
        assert_eq!(entry.counters.http_req_cnt, 42);
        assert_eq!(entry.counters.conn_cnt, 7);
        assert_eq!(entry.counters.gpc, [1, 2, 3, 4]);
    }

    // ── Token bucket: retry_after is reasonable ──

    #[test]
    fn token_bucket_retry_after_reasonable_duration() {
        // rate=2/s, burst=1 => after 1 request, next needs ~0.5s.
        let limiter = token_bucket_limiter(2.0, 1);
        let now = Instant::now();
        assert!(limiter.check_at("c", now).is_allowed());

        match limiter.check_at("c", now) {
            RateLimitResult::Deny { retry_after, limit } => {
                assert_eq!(limit, 1);
                // Should be around 500ms (1 token / 2 per sec).
                assert!(retry_after.as_millis() >= 400, "retry_after too short: {:?}", retry_after);
                assert!(retry_after.as_millis() <= 600, "retry_after too long: {:?}", retry_after);
            }
            _ => panic!("expected Deny"),
        }
    }

    // ── Sliding window: exact boundary ──

    #[test]
    fn sliding_window_exact_boundary() {
        let limiter = sliding_window_limiter(Duration::from_secs(10), 5);
        let t0 = Instant::now();

        // Fill the first window.
        for _ in 0..5 {
            limiter.check_at("client", t0);
        }
        assert!(limiter.check_at("client", t0).is_denied());

        // At exactly the window boundary (t0+10s), the previous window
        // rotates out. fraction=0 so weighted = previous_count * 1.0 = 5.
        // This means still denied at the exact boundary.
        let t_boundary = t0 + Duration::from_secs(10);
        assert!(limiter.check_at("client", t_boundary).is_denied());

        // Just past two full windows, everything resets.
        let t_past = t0 + Duration::from_secs(20) + Duration::from_millis(1);
        assert!(limiter.check_at("client", t_past).is_allowed());
    }

    // ── Fixed window: concurrent keys don't interfere ──

    #[test]
    fn fixed_window_concurrent_keys_independent() {
        let limiter = fixed_window_limiter(Duration::from_secs(60), 3);
        let now = Instant::now();

        // Fill key "alpha" to capacity.
        for _ in 0..3 {
            limiter.check_at("alpha", now);
        }
        assert!(limiter.check_at("alpha", now).is_denied());

        // "beta" is independent and should still have full quota.
        for _ in 0..3 {
            assert!(limiter.check_at("beta", now).is_allowed());
        }
        assert!(limiter.check_at("beta", now).is_denied());

        // "alpha" is still denied, unaffected by "beta".
        assert!(limiter.check_at("alpha", now).is_denied());
    }

    // ── Leaky bucket: capacity overflow ──

    #[test]
    fn leaky_bucket_capacity_overflow() {
        // capacity=3, rate=1/s. Fill to capacity then verify overflow.
        let limiter = leaky_bucket_limiter(1.0, 3);
        let now = Instant::now();

        for _ in 0..3 {
            assert!(limiter.check_at("client", now).is_allowed());
        }
        // Bucket is full (level=3, capacity=3). Next request overflows.
        let result = limiter.check_at("client", now);
        assert!(result.is_denied());

        // Verify retry_after reflects the drain needed.
        if let RateLimitResult::Deny { retry_after, limit } = result {
            assert_eq!(limit, 3);
            // level=3, need to drain to <3 then add 1, so wait=(3-3+1)/1=1s.
            assert!(retry_after.as_millis() >= 900, "retry_after too short: {:?}", retry_after);
            assert!(retry_after.as_millis() <= 1100, "retry_after too long: {:?}", retry_after);
        }

        // After enough time, bucket drains and accepts again.
        let t1 = now + Duration::from_secs(4); // Drains 4 units, level goes to -1 → clamped to 0.
        for _ in 0..3 {
            assert!(limiter.check_at("client", t1).is_allowed());
        }
        assert!(limiter.check_at("client", t1).is_denied());
    }
}
