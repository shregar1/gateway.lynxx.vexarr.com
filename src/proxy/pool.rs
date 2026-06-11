//! HAProxy-inspired slab pool allocator for the proxy hot path.
//!
//! # Architecture
//!
//! ```text
//! PoolAllocator (configurable: enabled / disabled)
//! ├── BytePool (tiered: Small 4K / Medium 16K / Large 64K)
//! │   ├── ThreadCache   (per-thread, zero-lock free list)
//! │   └── GlobalPool    (cross-thread, Mutex-protected)
//! ├── StringPool (reusable String buffers)
//! │   ├── ThreadCache
//! │   └── GlobalPool
//! └── PoolMetrics (per-pool atomic counters)
//! ```
//!
//! # Why
//!
//! HAProxy's `pool_cache_head` (pool-t.h:60) is `THREAD_ALIGNED()` — each
//! worker thread has its own cache-line-aligned free list. Common-path
//! allocation is a linked-list pop with **zero locking**. Lynxx previously
//! relied on the system allocator (mimalloc) for every `Vec<u8>` body
//! buffer, every header `String`, every per-request object. Under high
//! concurrency, even mimalloc's thread caches can't match a dedicated slab
//! pool that eliminates syscalls entirely.
//!
//! # Design
//!
//! - **Thread-local cache**: Each thread maintains a bounded free list per
//!   buffer tier. `acquire()` is a Vec pop — zero locks, zero atomics on
//!   the hot path. This mirrors HAProxy's `pool_cache_head`.
//!
//! - **Global pool**: When a thread's cache is empty, it refills in batch
//!   from the global pool (one Mutex acquisition per batch, not per item).
//!   When a thread's cache is full, excess items drain to the global pool.
//!
//! - **System fallback**: When both caches are empty, a fresh allocation
//!   goes to the system allocator. When pools are disabled, all operations
//!   transparently fall back to normal allocation/deallocation.
//!
//! - **Fixed-size tiers**: Byte buffers come in Small (4KB), Medium (16KB),
//!   and Large (64KB). This eliminates fragmentation — the same buffer
//!   capacity is reused for the same class of request, keeping the working
//!   set hot in L1/L2 cache.
//!
//! # Usage
//!
//! ```ignore
//! use crate::proxy::pool;
//!
//! // Acquire a byte buffer (returns to pool on drop)
//! let mut buf = pool::acquire_buf(1024); // size hint → Small tier
//! buf.extend_from_slice(b"hello");
//!
//! // Acquire a reusable string
//! let mut s = pool::acquire_string();
//! s.push_str("header-value");
//!
//! // Both return to their pools when dropped
//! drop(buf);
//! drop(s);
//! ```

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Pool allocator configuration. Set once at startup via [`configure`].
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Master switch. When false, all acquire/release operations fall
    /// through to the system allocator. Default: **true**.
    pub enabled: bool,
    /// Max items per thread per buffer tier. Default: 64.
    /// HAProxy uses 256 per pool_head; 64 is conservative for Rust's
    /// larger Vec metadata.
    pub thread_cache_limit: usize,
    /// Max items in the global pool per tier. Default: 1024.
    pub global_pool_limit: usize,
    /// Number of items transferred between thread cache and global pool
    /// in one batch. Amortises the Mutex acquisition cost. Default: 8.
    pub batch_size: usize,
    /// Small byte buffer capacity in bytes. Default: 4096.
    pub small_buf_cap: usize,
    /// Medium byte buffer capacity in bytes. Default: 16384.
    pub medium_buf_cap: usize,
    /// Large byte buffer capacity in bytes. Default: 65536.
    pub large_buf_cap: usize,
    /// Initial capacity for pooled String buffers. Default: 256.
    pub string_initial_cap: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            thread_cache_limit: 64,
            global_pool_limit: 1024,
            batch_size: 8,
            small_buf_cap: 4096,
            medium_buf_cap: 16_384,
            large_buf_cap: 65_536,
            string_initial_cap: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// Buffer tier
// ---------------------------------------------------------------------------

/// Byte buffer size tier. Each tier has its own thread-local and global
/// pool so buffers of similar size are recycled together — zero
/// fragmentation, optimal cache-line reuse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BufTier {
    /// ≤ 4 KB — typical HTTP headers, small JSON payloads.
    Small = 0,
    /// ≤ 16 KB — medium API responses.
    Medium = 1,
    /// ≤ 64 KB — large bodies, file uploads, gRPC streams.
    Large = 2,
}

impl BufTier {
    /// Select tier from a size hint. Rounds up to the next tier.
    fn from_size_hint(hint: usize, config: &PoolConfig) -> Self {
        if hint <= config.small_buf_cap {
            Self::Small
        } else if hint <= config.medium_buf_cap {
            Self::Medium
        } else {
            Self::Large
        }
    }

    /// Target capacity for this tier.
    fn capacity(self, config: &PoolConfig) -> usize {
        match self {
            Self::Small => config.small_buf_cap,
            Self::Medium => config.medium_buf_cap,
            Self::Large => config.large_buf_cap,
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

const NUM_BUF_TIERS: usize = 3;

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Per-pool performance counters. All atomic — safe to read from any thread
/// (e.g. the metrics exporter) without locking.
pub struct PoolMetrics {
    /// Total `acquire_*` calls.
    pub acquires: AtomicU64,
    /// Acquisitions served from the thread-local cache (zero-lock fast path).
    pub thread_hits: AtomicU64,
    /// Acquisitions served from the global pool (one Mutex lock).
    pub global_hits: AtomicU64,
    /// Acquisitions that allocated a new object from the system allocator.
    pub system_allocs: AtomicU64,
    /// Total `release` calls (items returned to some pool).
    pub releases: AtomicU64,
    /// Items returned to the thread-local cache.
    pub thread_returns: AtomicU64,
    /// Items drained from thread cache to global pool.
    pub global_returns: AtomicU64,
    /// Items dropped (neither pool had room).
    pub drops: AtomicU64,
}

impl PoolMetrics {
    const fn new() -> Self {
        Self {
            acquires: AtomicU64::new(0),
            thread_hits: AtomicU64::new(0),
            global_hits: AtomicU64::new(0),
            system_allocs: AtomicU64::new(0),
            releases: AtomicU64::new(0),
            thread_returns: AtomicU64::new(0),
            global_returns: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        }
    }

    /// Snapshot all counters into a plain struct (for JSON serialisation, etc.).
    pub fn snapshot(&self) -> PoolMetricsSnapshot {
        PoolMetricsSnapshot {
            acquires: self.acquires.load(Ordering::Relaxed),
            thread_hits: self.thread_hits.load(Ordering::Relaxed),
            global_hits: self.global_hits.load(Ordering::Relaxed),
            system_allocs: self.system_allocs.load(Ordering::Relaxed),
            releases: self.releases.load(Ordering::Relaxed),
            thread_returns: self.thread_returns.load(Ordering::Relaxed),
            global_returns: self.global_returns.load(Ordering::Relaxed),
            drops: self.drops.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PoolMetricsSnapshot {
    pub acquires: u64,
    pub thread_hits: u64,
    pub global_hits: u64,
    pub system_allocs: u64,
    pub releases: u64,
    pub thread_returns: u64,
    pub global_returns: u64,
    pub drops: u64,
}

// ---------------------------------------------------------------------------
// Global pool (cross-thread, Mutex-protected)
// ---------------------------------------------------------------------------

/// Shared pool for one buffer tier or string type. Protected by a Mutex.
/// Only accessed when the thread-local cache is empty (refill) or full
/// (drain) — contention is rare because transfers happen in batches.
struct GlobalPool {
    free: Mutex<Vec<Vec<u8>>>,
    limit: usize,
}

impl GlobalPool {
    fn new(limit: usize) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            limit,
        }
    }

    /// Take up to `count` items from the global pool.
    fn take_batch(&self, count: usize) -> Vec<Vec<u8>> {
        let mut guard = match self.free.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(), // poisoned — recover
        };
        let n = count.min(guard.len());
        let split_at = guard.len() - n;
        guard.split_off(split_at)
    }

    /// Return a batch of items to the global pool. Excess items beyond
    /// the limit are dropped.
    fn return_batch(&self, items: &mut Vec<Vec<u8>>) {
        let mut guard = match self.free.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let room = self.limit.saturating_sub(guard.len());
        let n = room.min(items.len());
        guard.extend(items.drain(..n));
        // remaining items in `items` are dropped by the caller
    }
}

/// Global pool for strings.
struct GlobalStringPool {
    free: Mutex<Vec<String>>,
    limit: usize,
}

impl GlobalStringPool {
    fn new(limit: usize) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            limit,
        }
    }

    fn take_batch(&self, count: usize) -> Vec<String> {
        let mut guard = match self.free.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let n = count.min(guard.len());
        let split_at = guard.len() - n;
        guard.split_off(split_at)
    }

    fn return_batch(&self, items: &mut Vec<String>) {
        let mut guard = match self.free.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let room = self.limit.saturating_sub(guard.len());
        let n = room.min(items.len());
        guard.extend(items.drain(..n));
    }
}

// ---------------------------------------------------------------------------
// Global state (singleton)
// ---------------------------------------------------------------------------

/// Master enable/disable toggle. Checked on every acquire/release.
static POOL_ENABLED: AtomicBool = AtomicBool::new(true);

/// Configuration. Set once at startup.
static POOL_CONFIG: OnceLock<PoolConfig> = OnceLock::new();

fn config() -> &'static PoolConfig {
    POOL_CONFIG.get_or_init(PoolConfig::default)
}

/// Global byte pools (one per tier).
static GLOBAL_BUF_POOLS: OnceLock<[GlobalPool; NUM_BUF_TIERS]> = OnceLock::new();

fn global_buf_pools() -> &'static [GlobalPool; NUM_BUF_TIERS] {
    GLOBAL_BUF_POOLS.get_or_init(|| {
        let cfg = config();
        [
            GlobalPool::new(cfg.global_pool_limit),
            GlobalPool::new(cfg.global_pool_limit),
            GlobalPool::new(cfg.global_pool_limit),
        ]
    })
}

/// Global string pool.
static GLOBAL_STRING_POOL: OnceLock<GlobalStringPool> = OnceLock::new();

fn global_string_pool() -> &'static GlobalStringPool {
    GLOBAL_STRING_POOL.get_or_init(|| GlobalStringPool::new(config().global_pool_limit))
}

/// Byte buffer metrics.
static BUF_METRICS: PoolMetrics = PoolMetrics::new();

/// String pool metrics.
static STRING_METRICS: PoolMetrics = PoolMetrics::new();

// ---------------------------------------------------------------------------
// Thread-local cache
// ---------------------------------------------------------------------------

/// Per-thread cache state. One instance per thread via `thread_local!`.
/// Holds free lists for each byte buffer tier and for strings.
///
/// This mirrors HAProxy's `pool_cache_head` which is `THREAD_ALIGNED()`
/// — each worker thread has its own cache-line-isolated free list. On the
/// hot path, allocation is a `Vec::pop` with **zero** atomics or locks.
struct ThreadCache {
    buf_caches: [Vec<Vec<u8>>; NUM_BUF_TIERS],
    string_cache: Vec<String>,
}

impl ThreadCache {
    fn new() -> Self {
        Self {
            buf_caches: [Vec::new(), Vec::new(), Vec::new()],
            string_cache: Vec::new(),
        }
    }

    /// Pop a buffer from the thread-local cache for the given tier.
    fn pop_buf(&mut self, tier: BufTier) -> Option<Vec<u8>> {
        self.buf_caches[tier.index()].pop()
    }

    /// Push a buffer to the thread-local cache. Returns the buffer if
    /// the cache is full (caller should drain to global or drop).
    fn push_buf(&mut self, tier: BufTier, buf: Vec<u8>) -> Option<Vec<u8>> {
        let cache = &mut self.buf_caches[tier.index()];
        let limit = config().thread_cache_limit;
        if cache.len() < limit {
            cache.push(buf);
            None
        } else {
            Some(buf) // cache full
        }
    }

    /// Refill this thread's cache from the global pool.
    fn refill_buf(&mut self, tier: BufTier) {
        let batch = global_buf_pools()[tier.index()].take_batch(config().batch_size);
        self.buf_caches[tier.index()].extend(batch);
    }

    /// Drain excess buffers from thread cache to global pool.
    ///
    /// BUG FIX: the guard was previously `cache.len() > limit`, but `push_buf`
    /// caps the cache at exactly `limit` (it rejects once `len == limit`), so
    /// the cache length could never *exceed* `limit` and this branch was dead
    /// code. The global byte-pool tier therefore never received any buffers,
    /// cross-thread reuse never functioned, and overflow buffers were dropped
    /// instead of pooled. Drain at `>= limit` down to a low-water mark so the
    /// caller's retried `push_buf` has room and the global tier actually fills.
    fn drain_buf_to_global(&mut self, tier: BufTier) {
        let cfg = config();
        let limit = cfg.thread_cache_limit;
        let batch_size = cfg.batch_size;
        let cache = &mut self.buf_caches[tier.index()];
        if limit > 0 && cache.len() >= limit {
            // Drain down to a low-water mark (limit - batch_size) so that after
            // draining the cache has spare slots for the retried push. Draining
            // only the single at-limit item would leave the cache full again and
            // the retry would still fail.
            let low_water = limit.saturating_sub(batch_size.max(1));
            let split_at = low_water.min(cache.len());
            let mut batch: Vec<Vec<u8>> = cache.split_off(split_at);
            let offered = batch.len();
            global_buf_pools()[tier.index()].return_batch(&mut batch);
            // return_batch drains accepted items out of `batch`; whatever
            // remains did not fit in the global pool and is dropped here.
            let accepted = offered - batch.len();
            if accepted > 0 {
                BUF_METRICS
                    .global_returns
                    .fetch_add(accepted as u64, Ordering::Relaxed);
            }
        }
    }

    fn pop_string(&mut self) -> Option<String> {
        self.string_cache.pop()
    }

    fn push_string(&mut self, s: String) -> Option<String> {
        let limit = config().thread_cache_limit;
        if self.string_cache.len() < limit {
            self.string_cache.push(s);
            None
        } else {
            Some(s)
        }
    }

    fn refill_string(&mut self) {
        let batch = global_string_pool().take_batch(config().batch_size);
        self.string_cache.extend(batch);
    }
}

thread_local! {
    static THREAD_CACHE: RefCell<ThreadCache> = RefCell::new(ThreadCache::new());
}

// ---------------------------------------------------------------------------
// PooledBuf — RAII byte buffer that returns to pool on drop
// ---------------------------------------------------------------------------

/// A byte buffer backed by the slab pool. When dropped, the buffer is
/// cleared and returned to the thread-local cache instead of being freed.
///
/// Dereferences to `Vec<u8>` for transparent use. When pools are disabled,
/// behaves identically to a normal `Vec<u8>`.
pub struct PooledBuf {
    inner: Option<Vec<u8>>,
    tier: BufTier,
}

impl PooledBuf {
    /// Unwrap into a plain `Vec<u8>`, detaching from the pool.
    /// The buffer will NOT be returned to the pool.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.inner.take().unwrap_or_default()
    }

    /// Current data length.
    pub fn len(&self) -> usize {
        self.inner.as_ref().map_or(0, |v| v.len())
    }

    /// True if the buffer has no data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Deref for PooledBuf {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        self.inner.as_ref().expect("PooledBuf used after into_vec")
    }
}

impl DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        self.inner.as_mut().expect("PooledBuf used after into_vec")
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        let Some(mut buf) = self.inner.take() else {
            return; // already consumed via into_vec
        };

        if !POOL_ENABLED.load(Ordering::Relaxed) {
            return; // buf drops normally via system allocator
        }

        // Clear data but keep capacity — the next user reuses the
        // allocation without a fresh malloc.
        buf.clear();

        BUF_METRICS.releases.fetch_add(1, Ordering::Relaxed);

        // try_with: gracefully handle thread shutdown (TLS destructors).
        let returned = THREAD_CACHE.try_with(|tc| {
            let mut cache = tc.borrow_mut();
            if let Some(overflow) = cache.push_buf(self.tier, buf) {
                // Thread cache full — drain a batch to global pool.
                cache.drain_buf_to_global(self.tier);
                // Try again after drain.
                if cache.push_buf(self.tier, overflow).is_some() {
                    // Still full (shouldn't happen after drain) — count as drop.
                    BUF_METRICS.drops.fetch_add(1, Ordering::Relaxed);
                } else {
                    BUF_METRICS.thread_returns.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                BUF_METRICS.thread_returns.fetch_add(1, Ordering::Relaxed);
            }
        });

        if returned.is_err() {
            // Thread is shutting down — buffer drops normally.
            BUF_METRICS.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// PooledString — RAII string that returns to pool on drop
// ---------------------------------------------------------------------------

/// A `String` backed by the slab pool. When dropped, the string is cleared
/// and returned to the thread-local cache.
pub struct PooledString {
    inner: Option<String>,
}

impl PooledString {
    /// Unwrap into a plain `String`, detaching from the pool.
    pub fn into_string(mut self) -> String {
        self.inner.take().unwrap_or_default()
    }
}

impl Deref for PooledString {
    type Target = String;
    fn deref(&self) -> &String {
        self.inner.as_ref().expect("PooledString used after into_string")
    }
}

impl DerefMut for PooledString {
    fn deref_mut(&mut self) -> &mut String {
        self.inner.as_mut().expect("PooledString used after into_string")
    }
}

impl Drop for PooledString {
    fn drop(&mut self) {
        let Some(mut s) = self.inner.take() else {
            return;
        };

        if !POOL_ENABLED.load(Ordering::Relaxed) {
            return;
        }

        s.clear();

        STRING_METRICS.releases.fetch_add(1, Ordering::Relaxed);

        let returned = THREAD_CACHE.try_with(|tc| {
            let mut cache = tc.borrow_mut();
            if let Some(overflow) = cache.push_string(s) {
                // Thread cache full — drain batch to global.
                // BUG FIX: same off-by-one as drain_buf_to_global — push_string
                // caps string_cache at exactly `limit`, so the old `> limit`
                // guard was never true and the global string pool stayed dead.
                // Drain at `>= limit` down to a low-water mark so the retried
                // push_string below has room and the global tier actually fills.
                let cfg = config();
                let limit = cfg.thread_cache_limit;
                let batch_size = cfg.batch_size;
                if limit > 0 && cache.string_cache.len() >= limit {
                    let low_water = limit.saturating_sub(batch_size.max(1));
                    let split_at = low_water.min(cache.string_cache.len());
                    let mut batch: Vec<String> =
                        cache.string_cache.split_off(split_at);
                    let offered = batch.len();
                    global_string_pool().return_batch(&mut batch);
                    let accepted = offered - batch.len();
                    if accepted > 0 {
                        STRING_METRICS
                            .global_returns
                            .fetch_add(accepted as u64, Ordering::Relaxed);
                    }
                }
                if cache.push_string(overflow).is_some() {
                    STRING_METRICS.drops.fetch_add(1, Ordering::Relaxed);
                } else {
                    STRING_METRICS.thread_returns.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                STRING_METRICS.thread_returns.fetch_add(1, Ordering::Relaxed);
            }
        });

        if returned.is_err() {
            STRING_METRICS.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set the pool configuration. Must be called before the pool is first
/// touched (any `acquire_*`/drop or global-pool init, typically at startup).
/// Once the configuration has been initialised, subsequent calls are ignored
/// **in full** — neither the sizing/limits nor the `enabled` flag are applied.
///
/// To toggle the master switch after startup, use [`set_enabled`].
pub fn configure(config: PoolConfig) {
    // BUG FIX: previously POOL_ENABLED was stored unconditionally while the
    // sizing config was applied via POOL_CONFIG.set(), whose Err (the OnceLock
    // was already initialised — e.g. by an earlier acquire/drop) was silently
    // discarded. That left an inconsistent state: the new `enabled` bit paired
    // with default sizing/limits. Apply both atomically — only flip the enable
    // flag if the config was actually accepted, so the two never diverge.
    let enabled = config.enabled;
    if POOL_CONFIG.set(config).is_ok() {
        POOL_ENABLED.store(enabled, Ordering::Relaxed);
    }
}

/// Enable or disable the pool allocator at runtime. When disabled, all
/// `acquire_*` calls return fresh allocations and `drop` frees normally.
/// Existing pooled objects are unaffected — they return to (or bypass)
/// the pool based on the flag at drop time.
pub fn set_enabled(enabled: bool) {
    POOL_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Returns true if the pool allocator is currently enabled.
pub fn is_enabled() -> bool {
    POOL_ENABLED.load(Ordering::Relaxed)
}

/// Acquire a byte buffer from the pool. The `size_hint` selects the
/// buffer tier (Small ≤ 4K, Medium ≤ 16K, Large ≤ 64K).
///
/// The returned `PooledBuf` dereferences to `Vec<u8>` and returns its
/// allocation to the pool when dropped.
///
/// When pools are disabled, returns a fresh `Vec::with_capacity(size_hint)`.
pub fn acquire_buf(size_hint: usize) -> PooledBuf {
    let cfg = config();
    let tier = BufTier::from_size_hint(size_hint, cfg);

    BUF_METRICS.acquires.fetch_add(1, Ordering::Relaxed);

    if !POOL_ENABLED.load(Ordering::Relaxed) {
        BUF_METRICS.system_allocs.fetch_add(1, Ordering::Relaxed);
        return PooledBuf {
            inner: Some(Vec::with_capacity(size_hint)),
            tier,
        };
    }

    // 1. Thread-local cache (zero-lock fast path).
    let buf = THREAD_CACHE.with(|tc| {
        let mut cache = tc.borrow_mut();
        if let Some(buf) = cache.pop_buf(tier) {
            BUF_METRICS.thread_hits.fetch_add(1, Ordering::Relaxed);
            return Some(buf);
        }

        // 2. Refill from global pool.
        cache.refill_buf(tier);
        if let Some(buf) = cache.pop_buf(tier) {
            BUF_METRICS.global_hits.fetch_add(1, Ordering::Relaxed);
            return Some(buf);
        }

        None
    });

    if let Some(buf) = buf {
        return PooledBuf {
            inner: Some(buf),
            tier,
        };
    }

    // 3. System allocator fallback.
    BUF_METRICS.system_allocs.fetch_add(1, Ordering::Relaxed);
    PooledBuf {
        inner: Some(Vec::with_capacity(tier.capacity(cfg))),
        tier,
    }
}

/// Acquire a string buffer from the pool. Returns a cleared `String` with
/// pre-allocated capacity.
pub fn acquire_string() -> PooledString {
    let cfg = config();

    STRING_METRICS.acquires.fetch_add(1, Ordering::Relaxed);

    if !POOL_ENABLED.load(Ordering::Relaxed) {
        STRING_METRICS.system_allocs.fetch_add(1, Ordering::Relaxed);
        return PooledString {
            inner: Some(String::with_capacity(cfg.string_initial_cap)),
        };
    }

    let s = THREAD_CACHE.with(|tc| {
        let mut cache = tc.borrow_mut();
        if let Some(s) = cache.pop_string() {
            STRING_METRICS.thread_hits.fetch_add(1, Ordering::Relaxed);
            return Some(s);
        }
        cache.refill_string();
        if let Some(s) = cache.pop_string() {
            STRING_METRICS.global_hits.fetch_add(1, Ordering::Relaxed);
            return Some(s);
        }
        None
    });

    if let Some(s) = s {
        return PooledString { inner: Some(s) };
    }

    STRING_METRICS.system_allocs.fetch_add(1, Ordering::Relaxed);
    PooledString {
        inner: Some(String::with_capacity(cfg.string_initial_cap)),
    }
}

/// Return byte buffer metrics.
pub fn buf_metrics() -> &'static PoolMetrics {
    &BUF_METRICS
}

/// Return string pool metrics.
pub fn string_metrics() -> &'static PoolMetrics {
    &STRING_METRICS
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure pools are enabled for tests.
    fn enable_pools() {
        POOL_ENABLED.store(true, Ordering::Relaxed);
    }

    #[test]
    fn acquire_and_drop_returns_to_pool() {
        enable_pools();
        let initial_acquires = BUF_METRICS.acquires.load(Ordering::Relaxed);

        {
            let mut buf = acquire_buf(100);
            buf.extend_from_slice(b"hello world");
            assert_eq!(buf.len(), 11);
            // buf dropped here → returned to thread cache
        }

        // Second acquire should hit the thread cache.
        let buf2 = acquire_buf(100);
        // The returned buffer should be cleared (len=0) but have capacity.
        assert_eq!(buf2.len(), 0);
        assert!(buf2.capacity() >= 100);

        // Metrics are global + tests run in parallel, so check ≥ not ==.
        let total = BUF_METRICS.acquires.load(Ordering::Relaxed) - initial_acquires;
        assert!(total >= 2, "expected at least 2 acquires, got {total}");
    }

    #[test]
    fn tier_selection() {
        let cfg = PoolConfig::default();
        assert_eq!(BufTier::from_size_hint(100, &cfg), BufTier::Small);
        assert_eq!(BufTier::from_size_hint(4096, &cfg), BufTier::Small);
        assert_eq!(BufTier::from_size_hint(4097, &cfg), BufTier::Medium);
        assert_eq!(BufTier::from_size_hint(16384, &cfg), BufTier::Medium);
        assert_eq!(BufTier::from_size_hint(16385, &cfg), BufTier::Large);
        assert_eq!(BufTier::from_size_hint(100_000, &cfg), BufTier::Large);
    }

    #[test]
    fn pooled_buf_into_vec_detaches() {
        enable_pools();
        let buf = acquire_buf(100);
        let vec = buf.into_vec();
        // vec is a normal Vec<u8> — not returned to pool.
        assert!(vec.capacity() >= 100);
    }

    #[test]
    fn pooled_string_acquire_and_drop() {
        enable_pools();
        {
            let mut s = acquire_string();
            s.push_str("test-value");
            assert_eq!(&**s, "test-value");
        }
        // Second acquire from thread cache.
        let s2 = acquire_string();
        assert!(s2.is_empty());
        assert!(s2.capacity() > 0);
    }

    #[test]
    fn disabled_pool_uses_system_allocator() {
        POOL_ENABLED.store(false, Ordering::Relaxed);
        let initial = BUF_METRICS.system_allocs.load(Ordering::Relaxed);

        let buf = acquire_buf(200);
        assert!(buf.capacity() >= 200);
        drop(buf);

        let after = BUF_METRICS.system_allocs.load(Ordering::Relaxed);
        assert!(after > initial);

        // Re-enable for other tests.
        POOL_ENABLED.store(true, Ordering::Relaxed);
    }

    #[test]
    fn thread_cache_respects_limit() {
        enable_pools();
        // Fill the thread cache beyond its limit.
        let limit = config().thread_cache_limit;
        let mut bufs: Vec<PooledBuf> = (0..limit + 10)
            .map(|_| acquire_buf(100))
            .collect();
        // Drop all — thread cache accepts up to `limit`, rest go to global or drop.
        bufs.clear();

        // After dropping, thread cache should have at most `limit` items.
        THREAD_CACHE.with(|tc| {
            let cache = tc.borrow();
            assert!(cache.buf_caches[BufTier::Small.index()].len() <= limit);
        });
    }

    #[test]
    fn metrics_tracking() {
        enable_pools();
        let before = BUF_METRICS.snapshot();

        let buf = acquire_buf(500);
        drop(buf);

        let after = BUF_METRICS.snapshot();
        assert!(after.acquires > before.acquires);
        assert!(after.releases > before.releases);
    }

    #[test]
    fn pooled_buf_deref_mut() {
        enable_pools();
        let mut buf = acquire_buf(1024);
        buf.push(42);
        buf.push(43);
        buf.extend_from_slice(&[44, 45, 46]);
        assert_eq!(&buf[..], &[42, 43, 44, 45, 46]);
    }

    #[test]
    fn pooled_string_deref_mut() {
        enable_pools();
        let mut s = acquire_string();
        s.push_str("hello");
        s.push(' ');
        s.push_str("world");
        assert_eq!(&**s, "hello world");
    }

    #[test]
    fn buf_tier_capacity() {
        let cfg = PoolConfig::default();
        assert_eq!(BufTier::Small.capacity(&cfg), 4096);
        assert_eq!(BufTier::Medium.capacity(&cfg), 16_384);
        assert_eq!(BufTier::Large.capacity(&cfg), 65_536);
    }

    #[test]
    fn global_pool_take_empty() {
        let pool = GlobalPool::new(10);
        let batch = pool.take_batch(5);
        assert!(batch.is_empty());
    }

    #[test]
    fn global_pool_return_and_take() {
        let pool = GlobalPool::new(100);
        let mut items = vec![
            Vec::with_capacity(64),
            Vec::with_capacity(64),
            Vec::with_capacity(64),
        ];
        pool.return_batch(&mut items);
        assert!(items.is_empty()); // all accepted

        let taken = pool.take_batch(2);
        assert_eq!(taken.len(), 2);

        let taken2 = pool.take_batch(5);
        assert_eq!(taken2.len(), 1); // only 1 left
    }

    #[test]
    fn global_pool_respects_limit() {
        let pool = GlobalPool::new(2);
        let mut items = vec![
            Vec::with_capacity(64),
            Vec::with_capacity(64),
            Vec::with_capacity(64),
        ];
        pool.return_batch(&mut items);
        // Pool accepted 2 (limit), 1 remains in items.
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn multithreaded_pool_usage() {
        enable_pools();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..100 {
                        let mut buf = acquire_buf(512);
                        buf.extend_from_slice(&[0u8; 256]);
                        assert_eq!(buf.len(), 256);
                        drop(buf);

                        let mut s = acquire_string();
                        s.push_str("thread-test");
                        drop(s);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // If we got here without panics, the pool is thread-safe.
        let snap = BUF_METRICS.snapshot();
        assert!(snap.acquires > 0);
    }

    // ── PooledBuf: Deref / DerefMut to Vec<u8> ──

    #[test]
    fn pooled_buf_deref_read_and_write() {
        enable_pools();
        let mut buf = acquire_buf(128);
        // DerefMut: write via Vec methods
        buf.extend_from_slice(b"hello");
        buf.push(b' ');
        buf.extend_from_slice(b"world");
        // Deref: read via Vec methods
        assert_eq!(buf.len(), 11);
        assert_eq!(&buf[0..5], b"hello");
        assert_eq!(&buf[..], b"hello world");
        assert!(buf.starts_with(b"hello"));
        assert!(buf.ends_with(b"world"));
    }

    // ── PooledBuf: Drop returns to pool ──

    #[test]
    fn pooled_buf_drop_returns_to_pool() {
        enable_pools();
        let releases_before = BUF_METRICS.releases.load(Ordering::Relaxed);

        {
            let mut buf = acquire_buf(100);
            buf.extend_from_slice(b"drop me");
        } // dropped here

        let releases_after = BUF_METRICS.releases.load(Ordering::Relaxed);
        assert!(
            releases_after > releases_before,
            "release count should increase after drop"
        );
    }

    // ── PooledBuf: multiple allocate/release cycles ──

    #[test]
    fn pooled_buf_multiple_cycles() {
        enable_pools();
        for i in 0..20 {
            let mut buf = acquire_buf(256);
            buf.extend_from_slice(format!("cycle-{i}").as_bytes());
            assert!(!buf.is_empty());
            // buf dropped → returned to pool, reused next iteration
        }
        // After many cycles, thread cache should still be bounded.
        THREAD_CACHE.with(|tc| {
            let cache = tc.borrow();
            let limit = config().thread_cache_limit;
            assert!(cache.buf_caches[BufTier::Small.index()].len() <= limit);
        });
    }

    // ── Allocate all, release all, reallocate ──

    #[test]
    fn allocate_release_reallocate_cycle() {
        enable_pools();
        // Allocate a batch of buffers.
        let mut bufs: Vec<PooledBuf> = (0..32).map(|_| acquire_buf(100)).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            buf.extend_from_slice(format!("buf-{i}").as_bytes());
        }
        // Release all.
        drop(bufs);

        // Reallocate — should hit thread cache.
        let thread_hits_before = BUF_METRICS.thread_hits.load(Ordering::Relaxed);
        let bufs2: Vec<PooledBuf> = (0..16).map(|_| acquire_buf(100)).collect();
        let thread_hits_after = BUF_METRICS.thread_hits.load(Ordering::Relaxed);
        assert!(
            thread_hits_after > thread_hits_before,
            "re-acquire should hit thread cache"
        );
        // Verify re-acquired bufs are clean (cleared on return).
        for buf in &bufs2 {
            assert_eq!(buf.len(), 0, "recycled buf should be empty");
        }
        drop(bufs2);
    }

    // ── PooledString: into_string detaches ──

    #[test]
    fn pooled_string_into_string_detaches() {
        enable_pools();
        let mut s = acquire_string();
        s.push_str("detach-me");
        let plain = s.into_string();
        assert_eq!(plain, "detach-me");
        // plain is a normal String, not pooled.
    }

    // ── PooledString: multiple cycles ──

    #[test]
    fn pooled_string_multiple_cycles() {
        enable_pools();
        for i in 0..15 {
            let mut s = acquire_string();
            s.push_str(&format!("string-cycle-{i}"));
            assert!(!s.is_empty());
            drop(s);
        }
        // Re-acquire — should get recycled strings.
        let s = acquire_string();
        assert!(s.is_empty(), "recycled string should be empty");
        assert!(s.capacity() > 0, "recycled string should have capacity");
    }

    // ── GlobalStringPool: return and take ──

    #[test]
    fn global_string_pool_return_and_take() {
        let pool = GlobalStringPool::new(100);
        let mut items = vec![
            String::with_capacity(32),
            String::with_capacity(32),
        ];
        pool.return_batch(&mut items);
        assert!(items.is_empty());

        let taken = pool.take_batch(1);
        assert_eq!(taken.len(), 1);

        let taken2 = pool.take_batch(5);
        assert_eq!(taken2.len(), 1); // only 1 left
    }

    #[test]
    fn global_string_pool_respects_limit() {
        let pool = GlobalStringPool::new(2);
        let mut items = vec![
            String::from("a"),
            String::from("b"),
            String::from("c"),
        ];
        pool.return_batch(&mut items);
        assert_eq!(items.len(), 1); // 1 rejected (limit=2)
    }

    // ── Metrics snapshot correctness ──

    #[test]
    fn metrics_snapshot_reflects_operations() {
        enable_pools();
        let before = BUF_METRICS.snapshot();

        let buf1 = acquire_buf(200);
        let buf2 = acquire_buf(200);
        drop(buf1);
        drop(buf2);

        let after = BUF_METRICS.snapshot();
        assert!(after.acquires >= before.acquires + 2);
        assert!(after.releases >= before.releases + 2);
    }

    // ── is_enabled / set_enabled toggle ──

    #[test]
    fn set_enabled_toggles_pool() {
        let original = is_enabled();
        set_enabled(false);
        assert!(!is_enabled());
        set_enabled(true);
        assert!(is_enabled());
        // Restore original state.
        set_enabled(original);
    }

    // ── Regression: overflow buffers reach the global pool tier ──
    //
    // BUG: the drain guard `cache.len() > limit` was unreachable because
    // push_buf caps the cache at exactly `limit`, so the global byte-pool tier
    // never received buffers (global_returns stayed 0 forever) and overflow
    // buffers were dropped instead of pooled. Runs on a dedicated thread so the
    // thread-local cache starts empty and the fill is deterministic. Without the
    // fix the drain branch never executes and `global_returns` never advances;
    // with the fix the over-limit buffers are batched to the global pool.
    #[test]
    fn drain_to_global_fills_global_pool_tier() {
        enable_pools();
        let before = BUF_METRICS.global_returns.load(Ordering::Relaxed);

        std::thread::spawn(move || {
            let limit = config().thread_cache_limit;
            // Acquire then drop well past the per-thread limit so at least one
            // drain-to-global fires. Holding them all first guarantees the
            // cache is genuinely at `limit` when the surplus drops.
            let bufs: Vec<PooledBuf> =
                (0..limit + config().batch_size + 8).map(|_| acquire_buf(64)).collect();
            drop(bufs);

            // Thread cache must remain bounded by `limit` after draining.
            THREAD_CACHE.with(|tc| {
                let cache = tc.borrow();
                assert!(
                    cache.buf_caches[BufTier::Small.index()].len() <= limit,
                    "thread cache must stay bounded by limit after drain"
                );
            });
        })
        .join()
        .unwrap();

        let after = BUF_METRICS.global_returns.load(Ordering::Relaxed);
        assert!(
            after > before,
            "over-limit buffers must drain to the global pool \
             (global_returns advanced from {before} to {after})"
        );
    }

    // ── Regression: configure() never half-applies once the pool is touched ──
    //
    // BUG: configure() wrote POOL_ENABLED unconditionally but discarded the Err
    // from POOL_CONFIG.set(); once the pool had been touched (POOL_CONFIG
    // already initialised) a later configure() flipped `enabled` while leaving
    // every size/limit at the default — an inconsistent half-applied state.
    // The fix flips POOL_ENABLED only when the config is actually accepted, so
    // the enable bit and the sizing can never diverge.
    #[test]
    fn configure_does_not_half_apply_after_pool_touched() {
        // Force the config OnceLock to initialise (simulates the pool having
        // been touched before configure() is called), so the configure() below
        // is guaranteed to be in the already-initialised / ignored regime.
        let _ = acquire_buf(64);
        assert_eq!(
            config().small_buf_cap,
            PoolConfig::default().small_buf_cap,
            "precondition: config is at defaults"
        );

        // Establish a known enabled state, then attempt to configure() with the
        // OPPOSITE enabled flag and a non-default size. Because the config is
        // already initialised, configure() must be ignored *in full*.
        set_enabled(true);
        let mut cfg = PoolConfig::default();
        cfg.enabled = false; // would flip POOL_ENABLED under the old buggy code
        cfg.small_buf_cap = 999; // sizing change that the OnceLock rejects
        configure(cfg);

        // Sizing was (correctly) rejected by the OnceLock...
        assert_eq!(
            config().small_buf_cap,
            PoolConfig::default().small_buf_cap,
            "sizing must remain at defaults — configure() is ignored after init"
        );
        // ...and therefore the enable flag must NOT have been applied either.
        // Under the old code POOL_ENABLED would now be false (divergent state).
        assert!(
            is_enabled(),
            "enabled flag must not change when configure() is ignored \
             (no half-applied state)"
        );

        // Leave the pool enabled for any subsequent tests.
        set_enabled(true);
    }
}
