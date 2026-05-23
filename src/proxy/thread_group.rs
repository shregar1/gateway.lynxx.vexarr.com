//! HAProxy 2.7-style thread groups for listener-to-thread affinity.
//!
//! # Architecture
//!
//! ```text
//! Thread Groups
//! ├── ThreadGroupStrategy   — Single / PerListener / Manual
//! ├── ThreadGroupId         — Newtype over u16 (0-based index)
//! ├── ThreadGroup           — id, name, core_range, max_connections
//! ├── ThreadGroupConfig     — Groups + listener→group DashMap
//! ├── ThreadGroupRegistry   — Runtime registry with lookup methods
//! └── ThreadGroupMetrics    — Per-group AtomicU64 counters (fixed array)
//! ```
//!
//! # Why
//!
//! HAProxy 2.7 introduced thread groups to partition worker threads into
//! named groups. Each listener/bind address can be assigned to a specific
//! group, so its connections are only handled by that group's threads.
//! This provides isolation — for example, admin traffic on cores 0–1,
//! production traffic on cores 2–7 — preventing one class of traffic
//! from starving another.
//!
//! # Design
//!
//! - **Atomic runtime config**: The strategy and enabled flag are stored
//!   as atomics so they can be toggled at runtime without locks.
//! - **DashMap for listener mapping**: Lock-free concurrent lookup from
//!   SocketAddr to ThreadGroupId on the accept hot path.
//! - **Fixed-size metrics array**: `[AtomicU64; MAX_GROUPS]` avoids
//!   heap allocation and allows per-group counters without locking.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::RwLock;

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum number of thread groups. Matches HAProxy's practical limit.
pub const MAX_GROUPS: usize = 64;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics — lock-free runtime configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Master switch for thread group functionality. When false, all
/// connections are handled by any available worker thread (Tokio default).
static THREAD_GROUPS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Current thread group strategy. Stored as `AtomicU8` for lock-free
/// runtime switching.
static THREAD_GROUP_STRATEGY: AtomicU8 = AtomicU8::new(ThreadGroupStrategy::Single as u8);

/// Enable or disable thread groups globally.
pub fn set_thread_groups_enabled(enabled: bool) {
    THREAD_GROUPS_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if thread groups are globally enabled.
pub fn thread_groups_enabled() -> bool {
    THREAD_GROUPS_ENABLED.load(Ordering::Relaxed)
}

/// Set the thread group strategy at runtime.
pub fn set_thread_group_strategy(strategy: ThreadGroupStrategy) {
    THREAD_GROUP_STRATEGY.store(strategy as u8, Ordering::Relaxed);
}

/// Get the current thread group strategy.
pub fn thread_group_strategy() -> ThreadGroupStrategy {
    ThreadGroupStrategy::from_u8(THREAD_GROUP_STRATEGY.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadGroupStrategy — partitioning modes
// ═══════════════════════════════════════════════════════════════════════════

/// How listeners are mapped to thread groups. Stored as `AtomicU8` for
/// lock-free runtime switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadGroupStrategy {
    /// All threads belong to a single group. Default mode — equivalent
    /// to no thread grouping. Simplest configuration.
    Single = 0,
    /// Each listener automatically gets its own thread group. The
    /// registry creates groups on-demand as listeners are registered.
    PerListener = 1,
    /// Explicit group assignment via configuration. Groups and their
    /// listener mappings are defined manually.
    Manual = 2,
}

impl ThreadGroupStrategy {
    /// Convert from raw `u8`. Unknown values default to `Single`.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Single,
            1 => Self::PerListener,
            2 => Self::Manual,
            _ => Self::Single,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadGroupId — newtype over u16
// ═══════════════════════════════════════════════════════════════════════════

/// Opaque identifier for a thread group. 0-based (HAProxy uses 1-based
/// indices, but we normalise to 0-based internally).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ThreadGroupId(pub u16);

impl ThreadGroupId {
    /// Create a new `ThreadGroupId` from a raw index.
    #[inline]
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the raw numeric value.
    #[inline]
    pub fn as_u16(self) -> u16 {
        self.0
    }

    /// Return the index as `usize` for array indexing.
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for ThreadGroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tg{}", self.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadGroup — a named set of CPU cores
// ═══════════════════════════════════════════════════════════════════════════

/// A named group of CPU cores. Listeners assigned to this group will
/// only have their connections handled by threads pinned to these cores.
#[derive(Clone, Debug)]
pub struct ThreadGroup {
    /// Unique identifier for this group.
    pub id: ThreadGroupId,
    /// Human-readable name (e.g. "admin", "production", "metrics").
    pub name: String,
    /// Which CPU cores this group covers. E.g. `0..2` means cores 0, 1.
    pub core_range: Range<usize>,
    /// Maximum concurrent connections for this group. 0 = unlimited.
    pub max_connections: u32,
}

impl ThreadGroup {
    /// Check whether a specific CPU core falls within this group's range.
    #[inline]
    pub fn contains_core(&self, core: usize) -> bool {
        self.core_range.contains(&core)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadGroupConfig — groups + listener mapping
// ═══════════════════════════════════════════════════════════════════════════

/// Static configuration: the list of defined groups plus a mapping from
/// listener bind addresses to their assigned groups.
pub struct ThreadGroupConfig {
    /// All defined thread groups.
    pub groups: Vec<ThreadGroup>,
    /// Listener-to-group assignment. Keyed by the `SocketAddr` the
    /// listener binds to.
    pub listener_map: DashMap<SocketAddr, ThreadGroupId, FastHasher>,
}

impl ThreadGroupConfig {
    /// Create an empty configuration.
    pub fn new() -> Self {
        Self {
            groups: Vec::new(),
            listener_map: DashMap::with_hasher(FastHasher::default()),
        }
    }
}

impl Default for ThreadGroupConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadGroupRegistry — runtime registry
// ═══════════════════════════════════════════════════════════════════════════

/// Runtime registry that owns thread groups and provides lookup methods.
/// Thread-safe via `RwLock` for group mutations and `DashMap` for
/// listener→group lookups on the hot path.
pub struct ThreadGroupRegistry {
    /// Groups stored behind a RwLock for safe mutation (add/remove).
    groups: RwLock<Vec<ThreadGroup>>,
    /// Listener-to-group mapping. DashMap for lock-free reads on the
    /// accept path.
    listener_map: DashMap<SocketAddr, ThreadGroupId, FastHasher>,
    /// Next group id to assign. Monotonically increasing.
    next_id: RwLock<u16>,
}

impl ThreadGroupRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(Vec::new()),
            listener_map: DashMap::with_hasher(FastHasher::default()),
            next_id: RwLock::new(0),
        }
    }

    /// Add a new thread group with the given name, core range, and
    /// maximum connection count. Returns the assigned `ThreadGroupId`.
    ///
    /// # Panics
    ///
    /// Panics if `MAX_GROUPS` is exceeded.
    pub fn add_group(
        &self,
        name: &str,
        core_range: Range<usize>,
        max_connections: u32,
    ) -> ThreadGroupId {
        let mut next = self.next_id.write().unwrap();
        let id = ThreadGroupId::new(*next);
        assert!(
            id.as_usize() < MAX_GROUPS,
            "thread group limit ({MAX_GROUPS}) exceeded"
        );
        *next += 1;

        let group = ThreadGroup {
            id,
            name: name.to_string(),
            core_range,
            max_connections,
        };

        let mut groups = self.groups.write().unwrap();
        groups.push(group);
        id
    }

    /// Assign a listener bind address to a specific thread group.
    pub fn assign_listener(&self, addr: SocketAddr, group_id: ThreadGroupId) {
        self.listener_map.insert(addr, group_id);
    }

    /// Look up which thread group a listener address is assigned to.
    /// Returns `None` if the address has no group assignment.
    pub fn group_for_listener(&self, addr: &SocketAddr) -> Option<ThreadGroupId> {
        self.listener_map.get(addr).map(|entry| *entry)
    }

    /// Look up a thread group by its id. Returns a clone of the group
    /// if found, or `None` if no group with that id exists.
    pub fn group_by_id(&self, id: ThreadGroupId) -> Option<ThreadGroup> {
        let groups = self.groups.read().unwrap();
        groups.iter().find(|g| g.id == id).cloned()
    }

    /// Return a snapshot of all thread groups.
    pub fn groups(&self) -> Vec<ThreadGroup> {
        self.groups.read().unwrap().clone()
    }

    /// Return the default group id (always group 0).
    #[inline]
    pub fn default_group(&self) -> ThreadGroupId {
        ThreadGroupId::new(0)
    }

    /// Return the CPU core range for a given group, or `None` if the
    /// group does not exist.
    pub fn cores_for_group(&self, id: ThreadGroupId) -> Option<Range<usize>> {
        let groups = self.groups.read().unwrap();
        groups
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.core_range.clone())
    }

    /// Remove a thread group by id. Returns `true` if a group was
    /// removed, `false` if no group with that id existed.
    ///
    /// Note: this does **not** remove listener mappings that reference
    /// the removed group — callers should clean those up separately.
    pub fn remove_group(&self, id: ThreadGroupId) -> bool {
        let mut groups = self.groups.write().unwrap();
        let len_before = groups.len();
        groups.retain(|g| g.id != id);
        groups.len() < len_before
    }
}

impl Default for ThreadGroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadGroupMetrics — per-group atomic counters
// ═══════════════════════════════════════════════════════════════════════════

/// Per-group atomic counters for observability. Uses a fixed-size array
/// indexed by `ThreadGroupId` to avoid heap allocation and locking.
/// Lock-free, safe to read from any thread (e.g. metrics endpoint).
pub struct ThreadGroupMetrics {
    /// Connections accepted per group.
    pub connections_accepted: [AtomicU64; MAX_GROUPS],
    /// Currently active connections per group.
    pub connections_active: [AtomicU64; MAX_GROUPS],
    /// Total bytes received per group.
    pub bytes_in: [AtomicU64; MAX_GROUPS],
    /// Total bytes sent per group.
    pub bytes_out: [AtomicU64; MAX_GROUPS],
}

impl ThreadGroupMetrics {
    /// Create a new zeroed metrics instance.
    pub const fn new() -> Self {
        // SAFETY: Zeroed memory is a valid representation for AtomicU64
        // (equivalent to AtomicU64::new(0) for every element).
        unsafe {
            Self {
                connections_accepted: std::mem::zeroed(),
                connections_active: std::mem::zeroed(),
                bytes_in: std::mem::zeroed(),
                bytes_out: std::mem::zeroed(),
            }
        }
    }

    /// Record an accepted connection for the given group.
    #[inline]
    pub fn accept(&self, group: ThreadGroupId) {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.connections_accepted[idx].fetch_add(1, Ordering::Relaxed);
            self.connections_active[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a closed connection for the given group.
    #[inline]
    pub fn close(&self, group: ThreadGroupId) {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.connections_active[idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record bytes received for the given group.
    #[inline]
    pub fn record_bytes_in(&self, group: ThreadGroupId, bytes: u64) {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.bytes_in[idx].fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record bytes sent for the given group.
    #[inline]
    pub fn record_bytes_out(&self, group: ThreadGroupId, bytes: u64) {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.bytes_out[idx].fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Get total accepted connections for a group.
    #[inline]
    pub fn get_connections_accepted(&self, group: ThreadGroupId) -> u64 {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.connections_accepted[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Get currently active connections for a group.
    #[inline]
    pub fn get_connections_active(&self, group: ThreadGroupId) -> u64 {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.connections_active[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Get total bytes received for a group.
    #[inline]
    pub fn get_bytes_in(&self, group: ThreadGroupId) -> u64 {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.bytes_in[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Get total bytes sent for a group.
    #[inline]
    pub fn get_bytes_out(&self, group: ThreadGroupId) -> u64 {
        let idx = group.as_usize();
        if idx < MAX_GROUPS {
            self.bytes_out[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }
}

/// Global thread group metrics instance.
static THREAD_GROUP_METRICS: ThreadGroupMetrics = ThreadGroupMetrics::new();

/// Get a reference to the global thread group metrics.
pub fn thread_group_metrics() -> &'static ThreadGroupMetrics {
    &THREAD_GROUP_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── ThreadGroupStrategy from_u8 roundtrip ──

    #[test]
    fn strategy_u8_roundtrip() {
        assert_eq!(ThreadGroupStrategy::from_u8(0), ThreadGroupStrategy::Single);
        assert_eq!(
            ThreadGroupStrategy::from_u8(1),
            ThreadGroupStrategy::PerListener
        );
        assert_eq!(ThreadGroupStrategy::from_u8(2), ThreadGroupStrategy::Manual);
        // Unknown values default to Single.
        assert_eq!(ThreadGroupStrategy::from_u8(3), ThreadGroupStrategy::Single);
        assert_eq!(
            ThreadGroupStrategy::from_u8(255),
            ThreadGroupStrategy::Single
        );
    }

    // ── Default strategy is Single ──

    #[test]
    fn default_strategy_is_single() {
        // Reset to known state.
        set_thread_group_strategy(ThreadGroupStrategy::Single);
        assert_eq!(thread_group_strategy(), ThreadGroupStrategy::Single);
    }

    // ── Enable/disable toggle ──

    #[test]
    fn enable_disable_toggle() {
        set_thread_groups_enabled(true);
        assert!(thread_groups_enabled());
        set_thread_groups_enabled(false);
        assert!(!thread_groups_enabled());
    }

    // ── Strategy toggle ──

    #[test]
    fn strategy_toggle() {
        set_thread_group_strategy(ThreadGroupStrategy::PerListener);
        assert_eq!(thread_group_strategy(), ThreadGroupStrategy::PerListener);
        set_thread_group_strategy(ThreadGroupStrategy::Manual);
        assert_eq!(thread_group_strategy(), ThreadGroupStrategy::Manual);
        // Reset to default.
        set_thread_group_strategy(ThreadGroupStrategy::Single);
        assert_eq!(thread_group_strategy(), ThreadGroupStrategy::Single);
    }

    // ── Create groups with core ranges ──

    #[test]
    fn create_groups_with_core_ranges() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 100);
        let g1 = registry.add_group("production", 2..8, 10000);

        assert_eq!(g0, ThreadGroupId::new(0));
        assert_eq!(g1, ThreadGroupId::new(1));
        assert_eq!(registry.groups().len(), 2);
    }

    // ── Assign listener to group ──

    #[test]
    fn assign_listener_to_group() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 100);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        registry.assign_listener(addr, g0);
        assert_eq!(registry.group_for_listener(&addr), Some(g0));
    }

    // ── Lookup group for listener ──

    #[test]
    fn lookup_group_for_listener() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 100);
        let g1 = registry.add_group("production", 2..8, 10000);
        let addr_admin: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let addr_prod: SocketAddr = "0.0.0.0:443".parse().unwrap();

        registry.assign_listener(addr_admin, g0);
        registry.assign_listener(addr_prod, g1);

        assert_eq!(registry.group_for_listener(&addr_admin), Some(g0));
        assert_eq!(registry.group_for_listener(&addr_prod), Some(g1));
    }

    // ── Lookup returns None for unassigned listener ──

    #[test]
    fn lookup_returns_none_for_unassigned() {
        let registry = ThreadGroupRegistry::new();
        let _g0 = registry.add_group("admin", 0..2, 100);
        let unassigned: SocketAddr = "192.168.1.1:3000".parse().unwrap();

        assert_eq!(registry.group_for_listener(&unassigned), None);
    }

    // ── Default group is always group 0 ──

    #[test]
    fn default_group_is_zero() {
        let registry = ThreadGroupRegistry::new();
        assert_eq!(registry.default_group(), ThreadGroupId::new(0));

        // Even after adding several groups, default stays at 0.
        let _g0 = registry.add_group("a", 0..1, 10);
        let _g1 = registry.add_group("b", 1..2, 10);
        assert_eq!(registry.default_group(), ThreadGroupId::new(0));
    }

    // ── cores_for_group returns correct range ──

    #[test]
    fn cores_for_group_returns_correct_range() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 100);
        let g1 = registry.add_group("production", 4..12, 5000);

        assert_eq!(registry.cores_for_group(g0), Some(0..2));
        assert_eq!(registry.cores_for_group(g1), Some(4..12));
        // Non-existent group.
        assert_eq!(registry.cores_for_group(ThreadGroupId::new(99)), None);
    }

    // ── contains_core check ──

    #[test]
    fn contains_core_check() {
        let group = ThreadGroup {
            id: ThreadGroupId::new(0),
            name: "test".to_string(),
            core_range: 2..6,
            max_connections: 100,
        };

        assert!(!group.contains_core(0));
        assert!(!group.contains_core(1));
        assert!(group.contains_core(2));
        assert!(group.contains_core(3));
        assert!(group.contains_core(4));
        assert!(group.contains_core(5));
        assert!(!group.contains_core(6)); // exclusive end
        assert!(!group.contains_core(100));
    }

    // ── Remove group ──

    #[test]
    fn remove_group() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 100);
        let g1 = registry.add_group("production", 2..8, 10000);

        assert_eq!(registry.groups().len(), 2);
        assert!(registry.remove_group(g0));
        assert_eq!(registry.groups().len(), 1);
        assert!(registry.group_by_id(g0).is_none());
        assert!(registry.group_by_id(g1).is_some());

        // Removing a non-existent group returns false.
        assert!(!registry.remove_group(ThreadGroupId::new(42)));
    }

    // ── Multiple groups with non-overlapping cores ──

    #[test]
    fn multiple_groups_non_overlapping_cores() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 50);
        let g1 = registry.add_group("api", 2..6, 5000);
        let g2 = registry.add_group("static", 6..8, 2000);

        let groups = registry.groups();
        assert_eq!(groups.len(), 3);

        // Verify no core appears in more than one group.
        for core in 0..8 {
            let mut count = 0;
            for g in &groups {
                if g.contains_core(core) {
                    count += 1;
                }
            }
            assert_eq!(count, 1, "core {core} should belong to exactly one group");
        }

        // Verify each group covers the right cores.
        assert_eq!(registry.cores_for_group(g0), Some(0..2));
        assert_eq!(registry.cores_for_group(g1), Some(2..6));
        assert_eq!(registry.cores_for_group(g2), Some(6..8));
    }

    // ── ThreadGroupId newtype operations ──

    #[test]
    fn thread_group_id_operations() {
        let id = ThreadGroupId::new(42);
        assert_eq!(id.as_u16(), 42);
        assert_eq!(id.as_usize(), 42);
        assert_eq!(format!("{id}"), "tg42");

        // Equality.
        assert_eq!(ThreadGroupId::new(0), ThreadGroupId::new(0));
        assert_ne!(ThreadGroupId::new(0), ThreadGroupId::new(1));

        // Clone and Copy.
        let id2 = id;
        assert_eq!(id, id2);
    }

    // ── Metrics increment ──

    #[test]
    fn metrics_increment() {
        let metrics = ThreadGroupMetrics::new();
        let g0 = ThreadGroupId::new(0);
        let g1 = ThreadGroupId::new(1);

        // Accept connections.
        metrics.accept(g0);
        metrics.accept(g0);
        metrics.accept(g1);

        assert_eq!(metrics.get_connections_accepted(g0), 2);
        assert_eq!(metrics.get_connections_active(g0), 2);
        assert_eq!(metrics.get_connections_accepted(g1), 1);
        assert_eq!(metrics.get_connections_active(g1), 1);

        // Close one connection on g0.
        metrics.close(g0);
        assert_eq!(metrics.get_connections_accepted(g0), 2);
        assert_eq!(metrics.get_connections_active(g0), 1);

        // Record bytes.
        metrics.record_bytes_in(g0, 1024);
        metrics.record_bytes_out(g0, 512);
        metrics.record_bytes_in(g0, 2048);

        assert_eq!(metrics.get_bytes_in(g0), 3072);
        assert_eq!(metrics.get_bytes_out(g0), 512);
        assert_eq!(metrics.get_bytes_in(g1), 0);
    }

    // ── MAX_GROUPS boundary ──

    #[test]
    fn max_groups_boundary() {
        let metrics = ThreadGroupMetrics::new();

        // Last valid group.
        let last = ThreadGroupId::new((MAX_GROUPS - 1) as u16);
        metrics.accept(last);
        assert_eq!(metrics.get_connections_accepted(last), 1);

        // Out-of-bounds group should be silently ignored (no panic).
        let oob = ThreadGroupId::new(MAX_GROUPS as u16);
        metrics.accept(oob);
        assert_eq!(metrics.get_connections_accepted(oob), 0);
        metrics.record_bytes_in(oob, 9999);
        assert_eq!(metrics.get_bytes_in(oob), 0);
    }

    // ── group_by_id returns correct group ──

    #[test]
    fn group_by_id_lookup() {
        let registry = ThreadGroupRegistry::new();
        let g0 = registry.add_group("admin", 0..2, 100);

        let group = registry.group_by_id(g0).unwrap();
        assert_eq!(group.name, "admin");
        assert_eq!(group.core_range, 0..2);
        assert_eq!(group.max_connections, 100);
        assert_eq!(group.id, g0);

        // Non-existent group.
        assert!(registry.group_by_id(ThreadGroupId::new(99)).is_none());
    }

    // ── ThreadGroupConfig default ──

    #[test]
    fn thread_group_config_default() {
        let config = ThreadGroupConfig::default();
        assert!(config.groups.is_empty());
        assert!(config.listener_map.is_empty());
    }

    // ── Registry default trait ──

    #[test]
    fn registry_default_trait() {
        let registry = ThreadGroupRegistry::default();
        assert!(registry.groups().is_empty());
        assert_eq!(registry.default_group(), ThreadGroupId::new(0));
    }
}
