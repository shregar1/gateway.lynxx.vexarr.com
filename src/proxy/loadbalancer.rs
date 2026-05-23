//! Per-service load balancer with weighted round-robin, least-connections,
//! IP hash, cookie sticky-session, and consistent-hash (rendezvous / HRW)
//! strategies. Targets are runtime-tracked for in-flight count and health.

use crate::models::{Target, TargetLifecycle};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use ahash::AHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const STICKY_COOKIE_NAME: &str = "_lynxx_upstream";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    /// Virtual-time FWRR (default). O(log N) pick, O(N) memory regardless of
    /// weights, incremental weight updates. Inspired by HAProxy's FWRR.
    RoundRobin,
    /// Pre-expanded ring: O(1) pick but memory ∝ sum-of-weights and full
    /// rebuild on any weight change. Better when N is small and weights are
    /// low.
    RoundRobinRing,
    LeastConn,
    /// Explicit opt-in to O(N) linear scan for least-connections. The default
    /// `LeastConn` uses a BTreeMap-indexed O(log N) pick inspired by HAProxy's
    /// FWLC algorithm. Use this when you need the simpler scan (e.g. debugging
    /// or when N is tiny and the Mutex overhead isn't worth it).
    LeastConnScan,
    IpHash,
    CookieSticky,
    /// Ketama-style virtual-node ring with O(log V) lookup via BTreeMap.
    /// Each target gets `150 * weight` virtual nodes on the ring, so higher
    /// weight targets capture proportionally more of the hash space. Inspired
    /// by HAProxy's eb32-tree consistent hashing.
    ConsistentHash,
    /// Explicit opt-in to O(N) rendezvous/HRW hashing for consistent-hash
    /// routing. The default `ConsistentHash` uses a virtual-node ring. Use
    /// this when N is tiny or you need exact HRW semantics.
    ConsistentHashHrw,
    Random,
    /// Power-of-2 random choices: pick 2 random healthy targets, forward to
    /// the one with fewer in-flight requests. Gives near-optimal spread
    /// without the coordination overhead of pure least-conn.
    RandomChoose,
    /// Primary / failover: always pick the first healthy, enabled target in
    /// target-list order. Traffic only moves to the next target when all
    /// preceding ones are unhealthy.
    First,
    /// Hash a configurable request header to pin sessions. The header name
    /// is stored on the Service model (`lb_hash_header`).
    HeaderHash,
    /// Hash a configurable query parameter to pin sessions. The param name
    /// is stored on the Service model (`lb_hash_query_param`).
    QueryHash,
    /// Hash the request URI path for consistent routing. Same path always
    /// goes to the same target.
    UriHash,
    /// Hash the X-Forwarded-For client IP (as opposed to IpHash which uses
    /// the direct remote/socket IP).
    ClientIpHash,
    /// Least-time: routes to the target with the lowest composite score of
    /// response latency and active connections. Score = avg_response_us * (in_flight + 1).
    LeastTime,
    /// Hash the RDP `mstshash=` cookie from an X.224 Connection Request PDU
    /// for TCP-level session persistence. Mirrors HAProxy's `balance rdp-cookie`.
    RdpCookie,
}

impl LbStrategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "round-robin-ring" | "round_robin_ring" => LbStrategy::RoundRobinRing,
            "least-conn" | "least_conn" | "leastconn" => LbStrategy::LeastConn,
            "least-conn-scan" | "least_conn_scan" => LbStrategy::LeastConnScan,
            "ip-hash" | "ip_hash" | "iphash" => LbStrategy::IpHash,
            "cookie" | "cookie-sticky" | "sticky" => LbStrategy::CookieSticky,
            "consistent-hash" | "consistent_hash" | "consistenthash" => LbStrategy::ConsistentHash,
            "consistent-hash-hrw" | "consistent_hash_hrw" => LbStrategy::ConsistentHashHrw,
            "random" => LbStrategy::Random,
            "random-choose" | "random_choose" | "p2c" => LbStrategy::RandomChoose,
            "first" | "failover" | "primary" => LbStrategy::First,
            "header-hash" | "header_hash" | "headerhash" => LbStrategy::HeaderHash,
            "query-hash" | "query_hash" | "queryhash" => LbStrategy::QueryHash,
            "uri-hash" | "uri_hash" | "urihash" => LbStrategy::UriHash,
            "client-ip-hash" | "client_ip_hash" => LbStrategy::ClientIpHash,
            "least-time" | "least_time" | "leasttime" => LbStrategy::LeastTime,
            "rdp-cookie" | "rdp_cookie" | "rdpcookie" => LbStrategy::RdpCookie,
            _ => LbStrategy::RoundRobin,
        }
    }
}

/// Request-scoped context for hash-based LB strategies.
#[derive(Default)]
pub struct RequestContext<'a> {
    pub client_ip: Option<&'a str>,
    pub uri_path: Option<&'a str>,
    pub sticky_cookie: Option<&'a str>,
    /// Value of the header named by `Service.lb_hash_header`. Populated by
    /// the handler before calling `pick()`.
    pub header_hash_value: Option<&'a str>,
    /// Value of the query parameter named by `Service.lb_hash_query_param`.
    pub query_hash_value: Option<&'a str>,
    /// RDP cookie value extracted from TCP connection initiation.
    /// Populated by the TCP router for RDP connections.
    pub rdp_cookie: Option<&'a str>,
}

fn hrw_hash(key: &str, target_id: &Uuid) -> u64 {
    let mut hasher = AHasher::default();
    key.hash(&mut hasher);
    target_id.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Indexed least-connections (HAProxy FWLC-inspired)
// ---------------------------------------------------------------------------

struct LcIndexInner {
    /// BTreeMap keyed by `(score, target_index)`. The BTree keeps entries
    /// sorted so finding the minimum is a walk to the first key — O(log N)
    /// for remove + reinsert vs the old O(N) linear scan.
    tree: BTreeMap<(u64, usize), ()>,
    /// `scores[idx]` = the key currently in `tree` for target `idx`.
    /// Maintained under the same Mutex so the two never diverge.
    scores: Vec<u64>,
}

/// Sorted index of targets by connection score. Inspired by HAProxy's FWLC
/// which uses an eb32 tree + per-proxy rwlock. We use a BTreeMap + Mutex;
/// the critical section is ~100 ns (a BTree remove + insert) so throughput
/// through the lock exceeds 5 M ops/s — well above typical proxy RPS.
pub(crate) struct LcIndex {
    inner: Mutex<LcIndexInner>,
}

impl std::fmt::Debug for LcIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LcIndex").finish_non_exhaustive()
    }
}

impl LcIndex {
    fn new(num_targets: usize) -> Self {
        let mut tree = BTreeMap::new();
        let mut scores = Vec::with_capacity(num_targets);
        for idx in 0..num_targets {
            tree.insert((0u64, idx), ());
            scores.push(0u64);
        }
        Self {
            inner: Mutex::new(LcIndexInner { tree, scores }),
        }
    }

    /// O(log N) pick: find the first routable target in ascending score order,
    /// remove its entry and reinsert at `score + 1`.
    fn pick(&self, targets: &[Arc<TargetState>]) -> Option<usize> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner
            .tree
            .iter()
            .find(|&(&(_, idx), _)| targets.get(idx).map_or(false, |t| t.is_routable()))
            .map(|(&key, _)| key);
        let (score, idx) = entry?;
        inner.tree.remove(&(score, idx));
        let new_score = score + 1;
        inner.tree.insert((new_score, idx), ());
        inner.scores[idx] = new_score;
        Some(idx)
    }

    /// Increment the score for `idx` (used by subset / excluding picks that
    /// bypass the tree's own `pick` but still need to keep scores in sync).
    fn increment(&self, idx: usize) {
        let mut inner = self.inner.lock().unwrap();
        if idx >= inner.scores.len() {
            return;
        }
        let old = inner.scores[idx];
        inner.tree.remove(&(old, idx));
        let new = old + 1;
        inner.tree.insert((new, idx), ());
        inner.scores[idx] = new;
    }

    /// Decrement the score for `idx` (called from `InFlightGuard::drop`).
    fn release(&self, idx: usize) {
        let mut inner = self.inner.lock().unwrap();
        if idx >= inner.scores.len() {
            return;
        }
        let old = inner.scores[idx];
        inner.tree.remove(&(old, idx));
        let new = old.saturating_sub(1);
        inner.tree.insert((new, idx), ());
        inner.scores[idx] = new;
    }

    /// Rebuild tree scores from the actual `in_flight` atomics.
    #[cfg(test)]
    fn sync_from_atomics(&self, targets: &[Arc<TargetState>]) {
        let mut inner = self.inner.lock().unwrap();
        inner.tree.clear();
        for (idx, t) in targets.iter().enumerate() {
            let count = t.in_flight.load(Ordering::Relaxed);
            if idx < inner.scores.len() {
                inner.scores[idx] = count;
            }
            inner.tree.insert((count, idx), ());
        }
    }
}

// ---------------------------------------------------------------------------
// Fast Weighted Round Robin (HAProxy FWRR-inspired)
// ---------------------------------------------------------------------------

/// Precision multiplier for virtual-time stride computation.
/// `stride = FWRR_SCALE / weight` — higher scale → finer granularity for
/// weight ratios at the cost of faster vtime growth. 2^20 (~1M) gives
/// sub-0.1% error for weights up to 10 000 and overflows after ~17 trillion
/// picks at weight-1 (centuries at 100k RPS).
const FWRR_SCALE: u64 = 1 << 20;

struct FwrrInner {
    tree: BTreeMap<(u64, usize), ()>,
    vtimes: Vec<u64>,
    weights: Vec<u32>,
}

/// Virtual-time fair-queuing scheduler for weighted round-robin. Each target
/// maintains a virtual timestamp that advances by `FWRR_SCALE / weight` on
/// every pick. Targets with higher weight advance slower and therefore get
/// picked more often.
///
/// Compared to the pre-expanded ring:
///   * Memory: O(N) regardless of weights (ring is O(Σ weights))
///   * Weight change: O(log N) incremental (ring requires full rebuild)
///   * Pick: O(log N) via BTree (ring is O(1))
pub(crate) struct FwrrIndex {
    inner: Mutex<FwrrInner>,
}

impl std::fmt::Debug for FwrrIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FwrrIndex").finish_non_exhaustive()
    }
}

impl FwrrIndex {
    fn new(targets: &[Arc<TargetState>]) -> Self {
        let mut tree = BTreeMap::new();
        let mut vtimes = Vec::with_capacity(targets.len());
        let mut weights = Vec::with_capacity(targets.len());
        for (idx, t) in targets.iter().enumerate() {
            tree.insert((0u64, idx), ());
            vtimes.push(0u64);
            weights.push(t.target.weight.max(1));
        }
        Self {
            inner: Mutex::new(FwrrInner {
                tree,
                vtimes,
                weights,
            }),
        }
    }

    /// O(log N) pick: find the first routable target with the lowest virtual
    /// time, advance it by its stride, and reinsert.
    fn pick(&self, targets: &[Arc<TargetState>]) -> Option<usize> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner
            .tree
            .iter()
            .find(|&(&(_, idx), _)| targets.get(idx).map_or(false, |t| t.is_routable()))
            .map(|(&key, _)| key);
        let (vtime, idx) = entry?;
        inner.tree.remove(&(vtime, idx));
        let stride = FWRR_SCALE / inner.weights[idx].max(1) as u64;
        let new_vtime = vtime + stride;
        inner.tree.insert((new_vtime, idx), ());
        inner.vtimes[idx] = new_vtime;
        // Compact when vtimes grow large to prevent eventual overflow.
        Self::maybe_compact(&mut inner);
        Some(idx)
    }

    /// Advance a target's vtime without going through the tree-walk pick
    /// (used by zone-aware subset picks to keep vtimes in sync).
    fn advance(&self, idx: usize) {
        let mut inner = self.inner.lock().unwrap();
        if idx >= inner.vtimes.len() {
            return;
        }
        let old = inner.vtimes[idx];
        inner.tree.remove(&(old, idx));
        let stride = FWRR_SCALE / inner.weights[idx].max(1) as u64;
        let new = old + stride;
        inner.tree.insert((new, idx), ());
        inner.vtimes[idx] = new;
    }

    /// O(log N) incremental weight update. Changes the stride for future
    /// picks without rebuilding the entire tree.
    fn update_weight(&self, idx: usize, new_weight: u32) {
        let mut inner = self.inner.lock().unwrap();
        if idx >= inner.weights.len() {
            return;
        }
        let old_vtime = inner.vtimes[idx];
        inner.tree.remove(&(old_vtime, idx));
        inner.weights[idx] = new_weight.max(1);
        inner.tree.insert((old_vtime, idx), ());
    }

    /// Subtract the global minimum vtime from every entry when values grow
    /// too large. O(N) but fires at most once per ~2^52 picks.
    fn maybe_compact(inner: &mut FwrrInner) {
        let min_vtime = match inner.tree.keys().next() {
            Some(&(v, _)) => v,
            None => return,
        };
        if min_vtime < (1u64 << 52) {
            return;
        }
        let entries: Vec<(u64, usize)> = inner.tree.keys().copied().collect();
        inner.tree.clear();
        for (vtime, idx) in entries {
            let shifted = vtime - min_vtime;
            inner.tree.insert((shifted, idx), ());
            inner.vtimes[idx] = shifted;
        }
    }
}

// ---------------------------------------------------------------------------
// Consistent-hash ring (ketama-style, HAProxy-inspired)
// ---------------------------------------------------------------------------

/// Virtual nodes per unit of weight. With 150 × weight-1, a 10-target pool
/// creates 1 500 ring entries — O(log 1500) ≈ 11 comparisons per lookup vs
/// O(10) hash+compare for HRW. The ring wins clearly above ~20 targets.
const RING_VNODES_PER_UNIT: u32 = 150;

struct ConsistentHashRing {
    ring: BTreeMap<u64, usize>,
}

impl std::fmt::Debug for ConsistentHashRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsistentHashRing")
            .field("vnodes", &self.ring.len())
            .finish()
    }
}

impl ConsistentHashRing {
    fn new(targets: &[Arc<TargetState>]) -> Self {
        let mut ring = BTreeMap::new();
        for (idx, t) in targets.iter().enumerate() {
            let vnodes = RING_VNODES_PER_UNIT * t.target.weight.max(1);
            for v in 0..vnodes {
                let hash = Self::node_hash(&t.target.id, v);
                ring.insert(hash, idx);
            }
        }
        Self { ring }
    }

    fn node_hash(target_id: &Uuid, vnode: u32) -> u64 {
        let mut hasher = AHasher::default();
        target_id.hash(&mut hasher);
        vnode.hash(&mut hasher);
        hasher.finish()
    }

    fn key_hash(key: &str) -> u64 {
        let mut hasher = AHasher::default();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// O(log V) lookup: hash the key, walk the ring clockwise from that
    /// point until a routable target is found.
    fn pick(&self, key: &str, targets: &[Arc<TargetState>]) -> Option<usize> {
        if self.ring.is_empty() {
            return None;
        }
        let hash = Self::key_hash(key);
        let iter = self.ring.range(hash..).chain(self.ring.range(..hash));
        for (_, &idx) in iter {
            if targets.get(idx).map_or(false, |t| t.is_routable()) {
                return Some(idx);
            }
        }
        None
    }
}

const LIFECYCLE_ACTIVE: u8 = 0;
const LIFECYCLE_DRAINING: u8 = 1;
const LIFECYCLE_INACTIVE: u8 = 2;

fn lifecycle_to_u8(lc: TargetLifecycle) -> u8 {
    match lc {
        TargetLifecycle::Active => LIFECYCLE_ACTIVE,
        TargetLifecycle::Draining => LIFECYCLE_DRAINING,
        TargetLifecycle::Inactive => LIFECYCLE_INACTIVE,
    }
}

fn u8_to_lifecycle(v: u8) -> TargetLifecycle {
    match v {
        LIFECYCLE_DRAINING => TargetLifecycle::Draining,
        LIFECYCLE_INACTIVE => TargetLifecycle::Inactive,
        _ => TargetLifecycle::Active,
    }
}

/// Runtime state for a single target.
#[derive(Debug)]
pub struct TargetState {
    pub target: Target,
    pub in_flight: AtomicU64,
    pub healthy: AtomicBool,
    /// Exponentially weighted moving average of response time in microseconds.
    pub avg_response_us: AtomicU64,
    lifecycle: AtomicU8,
    /// Position in the parent `ServiceLoadBalancer.targets` vec. Used by
    /// `InFlightGuard::drop` to update the `LcIndex` tree on release.
    lb_index: u32,
    /// Back-reference to the LcIndex this target participates in. `Some`
    /// only when the parent LB uses `LeastConn` (indexed mode). Held as
    /// `Arc` so in-flight guards keep the index alive across LB rebuilds.
    lc_index: Option<Arc<LcIndex>>,
}

impl TargetState {
    fn new(target: Target, lb_index: u32, lc_index: Option<Arc<LcIndex>>) -> Self {
        let lc = lifecycle_to_u8(target.state);
        Self {
            target,
            in_flight: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            avg_response_us: AtomicU64::new(0),
            lifecycle: AtomicU8::new(lc),
            lb_index,
            lc_index,
        }
    }

    pub fn lifecycle(&self) -> TargetLifecycle {
        u8_to_lifecycle(self.lifecycle.load(Ordering::Relaxed))
    }

    pub fn set_lifecycle(&self, lc: TargetLifecycle) {
        self.lifecycle.store(lifecycle_to_u8(lc), Ordering::Relaxed);
    }

    pub fn is_routable(&self) -> bool {
        self.target.enabled
            && self.healthy.load(Ordering::Relaxed)
            && self.lifecycle() == TargetLifecycle::Active
    }

    /// Update the EWMA response time with a new sample.
    /// Uses alpha=0.25: new = old*0.75 + sample*0.25.
    pub fn record_response_time(&self, micros: u64) {
        let old = self.avg_response_us.load(Ordering::Relaxed);
        let new = if old == 0 {
            micros
        } else {
            (old * 3 + micros) / 4
        };
        self.avg_response_us.store(new, Ordering::Relaxed);
    }
}

/// RAII guard that decrements `in_flight` on drop.
///
/// `in_flight` is read synchronously by `pick_least_conn`,
/// `pick_random_choose` (P2C), `pick_least_time`, and the drain-completion
/// poll in `ServiceLoadBalancer::find_and_drain`. All four need an
/// up-to-date per-target count to behave correctly:
///
///   * The LB pick algorithms make a routing decision *now*, using the
///     count from every worker — batching per-worker would let other
///     workers' increments lag behind and skew the choice.
///   * Drain completion waits for `in_flight == 0`; a stale per-worker
///     batch would mask a non-zero pending count and the drain would
///     hang.
///
/// So unlike the quota counter (which is consulted approximately and at
/// human-comprehensible scale), the `in_flight` counter must stay
/// strictly correct per-update. We pay one `fetch_add` on increment and
/// one `fetch_sub` on drop per request.
pub struct InFlightGuard {
    state: Arc<TargetState>,
}

impl InFlightGuard {
    pub fn new(state: Arc<TargetState>) -> Self {
        state.in_flight.fetch_add(1, Ordering::Relaxed);
        Self { state }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::Relaxed);
        if let Some(ref index) = self.state.lc_index {
            index.release(self.state.lb_index as usize);
        }
    }
}

pub struct ServiceLoadBalancer {
    strategy: LbStrategy,
    targets: Vec<Arc<TargetState>>,
    /// Pre-expanded virtual ring for weighted RR. Only populated when
    /// `strategy == RoundRobinRing`.
    rr_ring: Vec<usize>,
    /// Shared counter used by ring-mode RR, Random, and P2C.
    rr_counter: AtomicU64,
    /// Sorted index for O(log N) least-connections picks. Present only when
    /// `strategy == LeastConn` and `targets` is non-empty.
    lc_index: Option<Arc<LcIndex>>,
    /// Virtual-time FWRR scheduler. Present only when `strategy == RoundRobin`
    /// and `targets` is non-empty.
    fwrr_index: Option<Arc<FwrrIndex>>,
    /// Ketama-style virtual-node ring for O(log V) consistent-hash lookups.
    /// Present only when `strategy == ConsistentHash` and targets is non-empty.
    hash_ring: Option<ConsistentHashRing>,
}

impl ServiceLoadBalancer {
    fn new(strategy: LbStrategy, targets: Vec<Target>) -> Self {
        let n = targets.len();
        let lc_index = if strategy == LbStrategy::LeastConn && n > 0 {
            Some(Arc::new(LcIndex::new(n)))
        } else {
            None
        };

        let states: Vec<Arc<TargetState>> = targets
            .into_iter()
            .enumerate()
            .map(|(idx, t)| Arc::new(TargetState::new(t, idx as u32, lc_index.clone())))
            .collect();

        // Build pre-expanded ring only for the ring variant.
        let rr_ring = if strategy == LbStrategy::RoundRobinRing {
            let mut ring = Vec::new();
            for (idx, s) in states.iter().enumerate() {
                let w = s.target.weight.max(1) as usize;
                for _ in 0..w {
                    ring.push(idx);
                }
            }
            ring
        } else {
            Vec::new()
        };

        // Build FWRR index for the default round-robin variant.
        let fwrr_index = if strategy == LbStrategy::RoundRobin && n > 0 {
            Some(Arc::new(FwrrIndex::new(&states)))
        } else {
            None
        };

        // Build ketama-style hash ring for O(log V) consistent-hash lookups.
        let hash_ring = if strategy == LbStrategy::ConsistentHash && n > 0 {
            Some(ConsistentHashRing::new(&states))
        } else {
            None
        };

        Self {
            strategy,
            targets: states,
            rr_ring,
            rr_counter: AtomicU64::new(0),
            lc_index,
            fwrr_index,
            hash_ring,
        }
    }

    pub fn strategy(&self) -> LbStrategy {
        self.strategy
    }

    pub fn targets(&self) -> &[Arc<TargetState>] {
        &self.targets
    }

    /// Pick a target according to the strategy. Skips disabled and unhealthy
    /// targets. Returns `None` if no target is configured or all are out.
    ///
    /// If `local_zone` is provided **and** the strategy is RoundRobin or
    /// LeastConn, the balancer first tries to find a healthy target in the
    /// same zone. Hash-based strategies skip zone preference to preserve
    /// their consistency guarantees.
    pub fn pick(&self, local_zone: Option<&str>, ctx: &RequestContext) -> Option<Arc<TargetState>> {
        if self.targets.is_empty() {
            return None;
        }

        // Zone-aware first try (only for strategies where locality makes sense).
        if let Some(zone) = local_zone {
            if matches!(
                self.strategy,
                LbStrategy::RoundRobin
                    | LbStrategy::RoundRobinRing
                    | LbStrategy::LeastConn
                    | LbStrategy::LeastConnScan
                    | LbStrategy::RandomChoose
                    | LbStrategy::First
                    | LbStrategy::LeastTime
            ) {
                let zone_targets: Vec<_> = self
                    .targets
                    .iter()
                    .filter(|s| s.is_routable() && s.target.zone.as_deref() == Some(zone))
                    .collect();

                if !zone_targets.is_empty() {
                    return match self.strategy {
                        LbStrategy::RoundRobin | LbStrategy::RoundRobinRing => {
                            self.pick_rr_from_subset(&zone_targets)
                        }
                        LbStrategy::LeastConn | LbStrategy::LeastConnScan => {
                            self.pick_least_conn_from_subset(&zone_targets)
                        }
                        LbStrategy::RandomChoose => {
                            self.pick_random_choose_from_subset(&zone_targets)
                        }
                        LbStrategy::First => Some(zone_targets[0].clone()),
                        LbStrategy::LeastTime => self.pick_least_time_from_subset(&zone_targets),
                        _ => unreachable!(),
                    };
                }
            }
        }

        match self.strategy {
            LbStrategy::RoundRobin | LbStrategy::RoundRobinRing => self.pick_rr(),
            LbStrategy::LeastConn | LbStrategy::LeastConnScan => self.pick_least_conn(),
            LbStrategy::IpHash => self.pick_hrw(ctx.client_ip.unwrap_or("0.0.0.0")),
            LbStrategy::ConsistentHash => self.pick_hash_ring(ctx.uri_path.unwrap_or("/")),
            LbStrategy::ConsistentHashHrw => self.pick_hrw(ctx.uri_path.unwrap_or("/")),
            LbStrategy::CookieSticky => self.pick_cookie_sticky(ctx.sticky_cookie),
            LbStrategy::Random => self.pick_random(),
            LbStrategy::RandomChoose => self.pick_random_choose(),
            LbStrategy::First => self.pick_first(),
            LbStrategy::HeaderHash => {
                self.pick_hrw(ctx.header_hash_value.unwrap_or("__no_header__"))
            }
            LbStrategy::QueryHash => self.pick_hrw(ctx.query_hash_value.unwrap_or("__no_query__")),
            LbStrategy::UriHash => self.pick_hrw(ctx.uri_path.unwrap_or("/")),
            LbStrategy::ClientIpHash => self.pick_hrw(ctx.client_ip.unwrap_or("0.0.0.0")),
            LbStrategy::LeastTime => self.pick_least_time(),
            LbStrategy::RdpCookie => self.pick_hrw(ctx.rdp_cookie.unwrap_or("__no_rdp_cookie__")),
        }
    }

    fn pick_rr_from_subset(&self, subset: &[&Arc<TargetState>]) -> Option<Arc<TargetState>> {
        let i = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let target = (*subset[i % subset.len()]).clone();
        // Keep FWRR vtimes in sync when present.
        if let Some(ref fwrr) = self.fwrr_index {
            fwrr.advance(target.lb_index as usize);
        }
        Some(target)
    }

    fn pick_least_conn_from_subset(
        &self,
        subset: &[&Arc<TargetState>],
    ) -> Option<Arc<TargetState>> {
        let mut best: Option<&Arc<TargetState>> = None;
        let mut best_count = u64::MAX;
        for s in subset {
            let c = s.in_flight.load(Ordering::Relaxed);
            if c < best_count {
                best_count = c;
                best = Some(s);
            }
        }
        let target = best.cloned()?;
        // Keep the indexed tree in sync when present.
        if let Some(ref index) = self.lc_index {
            index.increment(target.lb_index as usize);
        }
        Some(target)
    }

    /// Dispatch to FWRR virtual-time scheduler or pre-expanded ring.
    fn pick_rr(&self) -> Option<Arc<TargetState>> {
        match &self.fwrr_index {
            Some(fwrr) => self.pick_rr_fwrr(fwrr),
            None => self.pick_rr_ring(),
        }
    }

    /// O(log N) pick via FWRR virtual-time scheduling. The target with the
    /// lowest virtual time is picked and its vtime advances by
    /// `FWRR_SCALE / weight`, so higher-weight targets are picked more often.
    fn pick_rr_fwrr(&self, fwrr: &FwrrIndex) -> Option<Arc<TargetState>> {
        let idx = fwrr.pick(&self.targets)?;
        Some(self.targets[idx].clone())
    }

    /// O(1) pick from the pre-expanded ring. Each target appears `weight`
    /// times; an atomic counter cycles through. Fast but memory ∝ Σ weights.
    fn pick_rr_ring(&self) -> Option<Arc<TargetState>> {
        if self.rr_ring.is_empty() {
            return None;
        }
        let len = self.rr_ring.len();
        for _ in 0..len {
            let i = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let idx = self.rr_ring[i % len];
            let state = &self.targets[idx];
            if state.is_routable() {
                return Some(state.clone());
            }
        }
        None
    }

    /// Dispatch to indexed O(log N) pick or classic O(N) scan.
    fn pick_least_conn(&self) -> Option<Arc<TargetState>> {
        match &self.lc_index {
            Some(index) => self.pick_least_conn_indexed(index),
            None => self.pick_least_conn_scan(),
        }
    }

    /// O(log N) pick via the sorted BTreeMap index. Finds the first routable
    /// target in ascending score order, then removes and reinserts at score+1.
    fn pick_least_conn_indexed(&self, index: &LcIndex) -> Option<Arc<TargetState>> {
        let idx = index.pick(&self.targets)?;
        Some(self.targets[idx].clone())
    }

    /// Classic O(N) linear scan — reads every target's `in_flight` atomic and
    /// picks the minimum. No locking, no auxiliary state.
    fn pick_least_conn_scan(&self) -> Option<Arc<TargetState>> {
        let mut best: Option<&Arc<TargetState>> = None;
        let mut best_count = u64::MAX;
        for s in &self.targets {
            if !s.is_routable() {
                continue;
            }
            let c = s.in_flight.load(Ordering::Relaxed);
            if c < best_count {
                best_count = c;
                best = Some(s);
            }
        }
        best.cloned()
    }

    /// Rendezvous / Highest-Random-Weight hashing. For each healthy target,
    /// compute hash(key, target_id) and pick the highest. Adding or removing
    /// a target only remaps requests that were pinned to that target.
    fn pick_hrw(&self, key: &str) -> Option<Arc<TargetState>> {
        let mut best: Option<&Arc<TargetState>> = None;
        let mut best_hash: u64 = 0;
        for s in &self.targets {
            if !s.is_routable() {
                continue;
            }
            let h = hrw_hash(key, &s.target.id);
            if best.is_none() || h > best_hash {
                best_hash = h;
                best = Some(s);
            }
        }
        best.cloned()
    }

    /// O(log V) pick via the ketama-style consistent-hash ring.
    fn pick_hash_ring(&self, key: &str) -> Option<Arc<TargetState>> {
        let ring = self.hash_ring.as_ref()?;
        let idx = ring.pick(key, &self.targets)?;
        Some(self.targets[idx].clone())
    }

    /// Cookie sticky: honour an existing affinity cookie when the pinned
    /// target is still healthy, otherwise fall back to round-robin.
    fn pick_cookie_sticky(&self, cookie: Option<&str>) -> Option<Arc<TargetState>> {
        if let Some(val) = cookie {
            if let Ok(target_id) = Uuid::parse_str(val) {
                for s in &self.targets {
                    if s.target.id == target_id && s.is_routable() {
                        return Some(s.clone());
                    }
                }
            }
        }
        self.pick_rr()
    }

    /// Random selection among healthy, enabled targets.
    fn pick_random(&self) -> Option<Arc<TargetState>> {
        let healthy: Vec<_> = self.targets.iter().filter(|s| s.is_routable()).collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
        // Use the counter XOR'd with a fast mix to approximate random
        // without pulling in a RNG crate — good enough for load balancing.
        let mixed = idx.wrapping_mul(6364136223846793005).wrapping_add(1);
        Some(healthy[mixed % healthy.len()].clone())
    }

    /// Power-of-2 random choices (P2C): pick 2 random healthy targets, use
    /// the one with fewer in-flight requests. Statistically near-optimal
    /// distribution without the coordination cost of full least-conn.
    fn pick_random_choose(&self) -> Option<Arc<TargetState>> {
        let healthy: Vec<_> = self.targets.iter().filter(|s| s.is_routable()).collect();
        self.p2c_from(&healthy)
    }

    fn pick_random_choose_from_subset(
        &self,
        subset: &[&Arc<TargetState>],
    ) -> Option<Arc<TargetState>> {
        self.p2c_from(subset)
    }

    fn p2c_from(&self, pool: &[&Arc<TargetState>]) -> Option<Arc<TargetState>> {
        if pool.is_empty() {
            return None;
        }
        if pool.len() == 1 {
            return Some(pool[0].clone());
        }
        let ctr = self.rr_counter.fetch_add(2, Ordering::Relaxed) as usize;
        let mix_a = ctr.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mix_b = (ctr + 1).wrapping_mul(6364136223846793005).wrapping_add(1);
        let a = pool[mix_a % pool.len()];
        let mut b_idx = mix_b % pool.len();
        // Ensure b != a when possible.
        if b_idx == mix_a % pool.len() {
            b_idx = (b_idx + 1) % pool.len();
        }
        let b = pool[b_idx];
        let fa = a.in_flight.load(Ordering::Relaxed);
        let fb = b.in_flight.load(Ordering::Relaxed);
        Some(if fa <= fb { a } else { b }.clone())
    }

    /// Least-time: pick the healthy, enabled target with the lowest composite
    /// score of `avg_response_us * (in_flight + 1)`. Combines latency
    /// awareness with connection count for optimal routing.
    fn pick_least_time(&self) -> Option<Arc<TargetState>> {
        let mut best: Option<&Arc<TargetState>> = None;
        let mut best_score = u64::MAX;
        for s in &self.targets {
            if !s.is_routable() {
                continue;
            }
            let avg = s.avg_response_us.load(Ordering::Relaxed);
            let inflight = s.in_flight.load(Ordering::Relaxed);
            // Use max(avg, 1) so that targets with no samples yet (avg=0)
            // get a score equal to their in-flight count + 1, giving them
            // a slight advantage to attract initial probes.
            let score = avg.max(1).saturating_mul(inflight + 1);
            if score < best_score {
                best_score = score;
                best = Some(s);
            }
        }
        best.cloned()
    }

    fn pick_least_time_from_subset(
        &self,
        subset: &[&Arc<TargetState>],
    ) -> Option<Arc<TargetState>> {
        let mut best: Option<&Arc<TargetState>> = None;
        let mut best_score = u64::MAX;
        for s in subset {
            let avg = s.avg_response_us.load(Ordering::Relaxed);
            let inflight = s.in_flight.load(Ordering::Relaxed);
            let score = avg.max(1).saturating_mul(inflight + 1);
            if score < best_score {
                best_score = score;
                best = Some(s);
            }
        }
        best.cloned()
    }

    /// Primary / failover: always pick the first healthy, enabled target in
    /// list order. Traffic only moves to the next when preceding ones are down.
    fn pick_first(&self) -> Option<Arc<TargetState>> {
        self.targets.iter().find(|s| s.is_routable()).cloned()
    }

    /// Rebuild the LcIndex tree from the actual `in_flight` atomics.
    #[cfg(test)]
    fn sync_lc_index(&self) {
        if let Some(ref index) = self.lc_index {
            index.sync_from_atomics(&self.targets);
        }
    }
}

/// Registry of per-service load balancers.
///
/// Reads (the per-request `pick`) outnumber writes (rebuild on config change,
/// health flip) by ~6 orders of magnitude at steady state. We use `ArcSwap`
/// instead of `RwLock` so the hot path becomes a single atomic load + `Arc`
/// clone — no read-side lock acquisition, no cache-line ping-pong across
/// cores at 100k RPS.
///
/// Per-target runtime state (`healthy`, `lifecycle`, `in_flight`,
/// `avg_response_us`) is already stored in atomics on `Arc<TargetState>`
/// inside `ServiceLoadBalancer`, so `mark_target_health` and
/// `set_target_lifecycle` keep mutating in place via `load()` rather than
/// RCU-replacing the whole `ServiceLoadBalancer` (which would also reset the
/// `rr_counter`). RCU-style replacement only fires on `rebuild_for_service`,
/// which is the only mutator that changes target topology.
pub struct LoadBalancerRegistry {
    inner: DashMap<Uuid, Arc<ArcSwap<ServiceLoadBalancer>>>,
}

impl LoadBalancerRegistry {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn rebuild_for_service(
        &self,
        service_id: Uuid,
        strategy: LbStrategy,
        targets: Vec<Target>,
    ) {
        let lb = ServiceLoadBalancer::new(strategy, targets);
        // Swap in-place when an `ArcSwap` already exists for this service so
        // any reader currently holding an `Arc<ArcSwap<_>>` clone picks up
        // the new targets on its next `load()`. Otherwise insert a fresh
        // `ArcSwap` for first-time registration.
        if let Some(existing) = self.inner.get(&service_id) {
            existing.store(Arc::new(lb));
        } else {
            self.inner
                .insert(service_id, Arc::new(ArcSwap::from_pointee(lb)));
        }
    }

    pub fn pick(
        &self,
        service_id: &Uuid,
        local_zone: Option<&str>,
        ctx: &RequestContext,
    ) -> Option<Arc<TargetState>> {
        let lb = self.inner.get(service_id)?.load_full();
        lb.pick(local_zone, ctx)
    }

    /// Pick any routable target not in `exclude`, using least-connections as
    /// the tie-breaker. Used by deploy-aware retry to failover to a different
    /// upstream after a connection error or 502 during a blue-green deploy.
    pub fn pick_excluding(
        &self,
        service_id: &Uuid,
        exclude: &[Uuid],
        _local_zone: Option<&str>,
    ) -> Option<Arc<TargetState>> {
        let lb = self.inner.get(service_id)?.load_full();
        let target = lb
            .targets()
            .iter()
            .filter(|s| s.is_routable() && !exclude.contains(&s.target.id))
            .min_by_key(|s| s.in_flight.load(Ordering::Relaxed))
            .cloned()?;
        // Keep the indexed tree in sync when present.
        if let Some(ref index) = lb.lc_index {
            index.increment(target.lb_index as usize);
        }
        Some(target)
    }

    pub fn strategy_for(&self, service_id: &Uuid) -> Option<LbStrategy> {
        let lb = self.inner.get(service_id)?.load_full();
        Some(lb.strategy())
    }

    pub fn remove_service(&self, service_id: &Uuid) {
        self.inner.remove(service_id);
    }

    pub fn mark_target_health(&self, service_id: &Uuid, target_id: &Uuid, healthy: bool) {
        if let Some(entry) = self.inner.get(service_id) {
            let lb = entry.load();
            for s in lb.targets() {
                if s.target.id == *target_id {
                    s.healthy.store(healthy, Ordering::Relaxed);
                    break;
                }
            }
        }
    }

    pub fn set_target_lifecycle(&self, service_id: &Uuid, target_id: &Uuid, lc: TargetLifecycle) {
        if let Some(entry) = self.inner.get(service_id) {
            let lb = entry.load();
            for s in lb.targets() {
                if s.target.id == *target_id {
                    s.set_lifecycle(lc);
                    break;
                }
            }
        }
    }

    /// Initiate a graceful drain of a target. Sets lifecycle to `Draining`,
    /// then spawns a background task that waits until in-flight hits 0 or
    /// the timeout expires. On completion, sets lifecycle to `Inactive`.
    /// Returns the `Arc<TargetState>` if the target was found (for callers
    /// that want to track it), or `None` if the target wasn't in the LB.
    pub fn drain_target(
        &self,
        service_id: &Uuid,
        target_id: &Uuid,
        timeout_ms: u64,
    ) -> Option<Arc<TargetState>> {
        let ts = {
            let lb = self.inner.get(service_id)?.load_full();
            lb.targets()
                .iter()
                .find(|s| s.target.id == *target_id)
                .cloned()?
        };
        ts.set_lifecycle(TargetLifecycle::Draining);
        let target_arc = ts.clone();
        tokio::spawn(async move {
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
            loop {
                if target_arc.in_flight.load(Ordering::Relaxed) == 0 {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    tracing::warn!(
                        target_id = %target_arc.target.id,
                        "drain timeout expired with {} in-flight requests",
                        target_arc.in_flight.load(Ordering::Relaxed)
                    );
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            target_arc.set_lifecycle(TargetLifecycle::Inactive);
            tracing::info!(
                target_id = %target_arc.target.id,
                "target drain complete"
            );
        });
        Some(ts)
    }

    /// Incrementally update a single target's weight without rebuilding the
    /// entire LB. Only effective when the service uses FWRR (`RoundRobin`);
    /// ring-mode services ignore this and require `rebuild_for_service`.
    pub fn update_target_weight(
        &self,
        service_id: &Uuid,
        target_id: &Uuid,
        new_weight: u32,
    ) {
        if let Some(entry) = self.inner.get(service_id) {
            let lb = entry.load();
            if let Some(ref fwrr) = lb.fwrr_index {
                for s in lb.targets() {
                    if s.target.id == *target_id {
                        fwrr.update_weight(s.lb_index as usize, new_weight);
                        break;
                    }
                }
            }
        }
    }

    pub fn has_healthy_active_target(&self, service_id: &Uuid) -> bool {
        match self.inner.get(service_id) {
            Some(entry) => entry.load().targets().iter().any(|s| s.is_routable()),
            None => false,
        }
    }

    /// Snapshot of all targets for a service (including runtime state).
    pub fn snapshot(&self, service_id: &Uuid) -> Vec<Arc<TargetState>> {
        match self.inner.get(service_id) {
            Some(entry) => entry.load().targets().to_vec(),
            None => Vec::new(),
        }
    }
}

impl Default for LoadBalancerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Target;
    use chrono::Utc;

    fn make_targets(n: usize) -> Vec<Target> {
        (0..n)
            .map(|i| Target {
                id: Uuid::new_v4(),
                service_id: Uuid::nil(),
                url: format!("http://host-{i}:8080").into(),
                weight: 1,
                enabled: true,
                zone: None,
                state: TargetLifecycle::Active,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .collect()
    }

    fn make_weighted_targets(weights: &[u32]) -> Vec<Target> {
        weights
            .iter()
            .enumerate()
            .map(|(i, &w)| Target {
                id: Uuid::new_v4(),
                service_id: Uuid::nil(),
                url: format!("http://host-{i}:8080").into(),
                weight: w,
                enabled: true,
                zone: None,
                state: TargetLifecycle::Active,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .collect()
    }

    fn default_ctx<'a>() -> RequestContext<'a> {
        RequestContext::default()
    }

    // ── RoundRobin (FWRR — default) ──

    #[test]
    fn fwrr_cycles_through_all_targets() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        let ctx = default_ctx();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..6 {
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn fwrr_respects_weights() {
        let targets = make_weighted_targets(&[3, 1]);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        let ctx = default_ctx();
        let mut counts = std::collections::HashMap::new();
        for _ in 0..40 {
            let t = lb.pick(None, &ctx).unwrap();
            *counts.entry(t.target.url.clone()).or_insert(0) += 1;
        }
        let h0 = *counts.get("http://host-0:8080").unwrap_or(&0);
        let h1 = *counts.get("http://host-1:8080").unwrap_or(&0);
        // Weight 3:1 → ~30:10 distribution over 40 picks.
        assert!(h0 > h1 * 2, "fwrr weight ratio wrong: h0={h0} h1={h1}");
    }

    #[test]
    fn fwrr_skips_unhealthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        lb.targets[0].healthy.store(false, Ordering::Relaxed);
        let ctx = default_ctx();
        for _ in 0..10 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_ne!(&*t.target.url, "http://host-0:8080");
        }
    }

    #[test]
    fn fwrr_returns_none_when_all_unhealthy() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        for ts in &lb.targets {
            ts.healthy.store(false, Ordering::Relaxed);
        }
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    #[test]
    fn fwrr_extreme_weights_bounded_memory() {
        // Weight 1000 vs 1: ring would allocate 1001 entries, FWRR uses 2.
        let targets = make_weighted_targets(&[1000, 1]);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        assert!(lb.rr_ring.is_empty(), "FWRR should not build a ring");
        assert!(lb.fwrr_index.is_some());
        let ctx = default_ctx();
        let mut counts = std::collections::HashMap::new();
        for _ in 0..1001 {
            let t = lb.pick(None, &ctx).unwrap();
            *counts.entry(t.target.url.clone()).or_insert(0) += 1;
        }
        let h0 = *counts.get("http://host-0:8080").unwrap_or(&0);
        let h1 = *counts.get("http://host-1:8080").unwrap_or(&0);
        assert!(h0 > 900, "weight-1000 target should dominate: h0={h0}");
        assert!(h1 >= 1, "weight-1 target should get at least 1 pick: h1={h1}");
    }

    #[test]
    fn fwrr_incremental_weight_update() {
        let targets = make_weighted_targets(&[1, 1]);
        let svc_id = Uuid::new_v4();
        let reg = LoadBalancerRegistry::new();
        reg.rebuild_for_service(svc_id, LbStrategy::RoundRobin, targets.clone());
        // Before weight change: 50/50 split.
        let ctx = default_ctx();
        let mut h0 = 0;
        for _ in 0..20 {
            if reg.pick(&svc_id, None, &ctx).unwrap().target.url.as_ref() == "http://host-0:8080" {
                h0 += 1;
            }
        }
        assert!((8..=12).contains(&h0), "before weight change: h0={h0}/20");
        // Change weight of target 0 to 9 → should get ~90% of traffic.
        reg.update_target_weight(&svc_id, &targets[0].id, 9);
        let mut h0 = 0;
        for _ in 0..100 {
            if reg.pick(&svc_id, None, &ctx).unwrap().target.url.as_ref() == "http://host-0:8080" {
                h0 += 1;
            }
        }
        assert!(h0 > 75, "after weight change to 9:1, h0={h0}/100");
    }

    // ── RoundRobin (ring mode) ──

    #[test]
    fn ring_cycles_through_all_targets() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobinRing, targets);
        let ctx = default_ctx();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..6 {
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn ring_respects_weights() {
        let targets = make_weighted_targets(&[3, 1]);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobinRing, targets);
        let ctx = default_ctx();
        let mut counts = std::collections::HashMap::new();
        // 4 slots in the ring: [0,0,0,1]
        for _ in 0..8 {
            let t = lb.pick(None, &ctx).unwrap();
            *counts.entry(t.target.url.clone()).or_insert(0) += 1;
        }
        assert!(
            *counts.get("http://host-0:8080").unwrap_or(&0)
                > *counts.get("http://host-1:8080").unwrap_or(&0)
        );
    }

    #[test]
    fn ring_skips_unhealthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobinRing, targets);
        lb.targets[0].healthy.store(false, Ordering::Relaxed);
        let ctx = default_ctx();
        for _ in 0..10 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_ne!(&*t.target.url, "http://host-0:8080");
        }
    }

    #[test]
    fn ring_returns_none_when_all_unhealthy() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobinRing, targets);
        for ts in &lb.targets {
            ts.healthy.store(false, Ordering::Relaxed);
        }
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    // ── LeastConn (scan mode) ──

    #[test]
    fn least_conn_scan_picks_lowest_inflight() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastConnScan, targets);
        lb.targets[0].in_flight.store(10, Ordering::Relaxed);
        lb.targets[1].in_flight.store(5, Ordering::Relaxed);
        lb.targets[2].in_flight.store(0, Ordering::Relaxed);
        let ctx = default_ctx();
        let picked = lb.pick(None, &ctx).unwrap();
        assert_eq!(&*picked.target.url, "http://host-2:8080");
    }

    // ── LeastConn (indexed mode — default) ──

    #[test]
    fn least_conn_indexed_picks_lowest_inflight() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastConn, targets);
        lb.targets[0].in_flight.store(10, Ordering::Relaxed);
        lb.targets[1].in_flight.store(5, Ordering::Relaxed);
        lb.targets[2].in_flight.store(0, Ordering::Relaxed);
        lb.sync_lc_index();
        let ctx = default_ctx();
        let picked = lb.pick(None, &ctx).unwrap();
        assert_eq!(&*picked.target.url, "http://host-2:8080");
    }

    #[test]
    fn least_conn_indexed_distributes_evenly() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastConn, targets);
        let ctx = default_ctx();
        // All start at 0 — tree breaks ties by index, so picks cycle 0,1,2,0,1,2...
        let mut counts = [0u32; 3];
        let mut guards = Vec::new();
        for _ in 0..9 {
            let t = lb.pick(None, &ctx).unwrap();
            let idx = t.target.url.strip_prefix("http://host-").unwrap()
                .strip_suffix(":8080").unwrap()
                .parse::<usize>().unwrap();
            counts[idx] += 1;
            guards.push(InFlightGuard::new(t));
        }
        // Each target should have exactly 3 picks.
        assert_eq!(counts, [3, 3, 3]);
    }

    #[test]
    fn least_conn_indexed_release_rebalances() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastConn, targets);
        let ctx = default_ctx();
        // Pick target 0, hold the guard.
        let t0 = lb.pick(None, &ctx).unwrap();
        assert_eq!(&*t0.target.url, "http://host-0:8080");
        let guard0 = InFlightGuard::new(t0);
        // Pick again — target 1 now has lower score.
        let t1 = lb.pick(None, &ctx).unwrap();
        assert_eq!(&*t1.target.url, "http://host-1:8080");
        let _guard1 = InFlightGuard::new(t1);
        // Release target 0 — it should become preferred again.
        drop(guard0);
        let t = lb.pick(None, &ctx).unwrap();
        assert_eq!(&*t.target.url, "http://host-0:8080");
    }

    #[test]
    fn least_conn_indexed_skips_unhealthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastConn, targets);
        lb.targets[0].healthy.store(false, Ordering::Relaxed);
        let ctx = default_ctx();
        for _ in 0..6 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_ne!(&*t.target.url, "http://host-0:8080");
        }
    }

    #[test]
    fn least_conn_indexed_returns_none_when_all_unhealthy() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastConn, targets);
        for ts in &lb.targets {
            ts.healthy.store(false, Ordering::Relaxed);
        }
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    // ── RandomChoose (P2C) ──

    #[test]
    fn p2c_prefers_lower_inflight() {
        let targets = make_targets(4);
        let lb = ServiceLoadBalancer::new(LbStrategy::RandomChoose, targets);
        // Make one target clearly best.
        lb.targets[0].in_flight.store(100, Ordering::Relaxed);
        lb.targets[1].in_flight.store(100, Ordering::Relaxed);
        lb.targets[2].in_flight.store(0, Ordering::Relaxed);
        lb.targets[3].in_flight.store(100, Ordering::Relaxed);
        let ctx = default_ctx();
        let mut picked_2 = 0;
        for _ in 0..100 {
            let t = lb.pick(None, &ctx).unwrap();
            if &*t.target.url == "http://host-2:8080" {
                picked_2 += 1;
            }
        }
        // host-2 should be picked more often than random 25%.
        assert!(picked_2 > 25, "P2C picked host-2 only {picked_2}/100 times");
    }

    #[test]
    fn p2c_single_target() {
        let targets = make_targets(1);
        let lb = ServiceLoadBalancer::new(LbStrategy::RandomChoose, targets);
        let t = lb.pick(None, &default_ctx()).unwrap();
        assert_eq!(&*t.target.url, "http://host-0:8080");
    }

    #[test]
    fn p2c_empty() {
        let lb = ServiceLoadBalancer::new(LbStrategy::RandomChoose, Vec::new());
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    // ── First / Failover ──

    #[test]
    fn first_always_picks_first_healthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::First, targets);
        let ctx = default_ctx();
        for _ in 0..10 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(&*t.target.url, "http://host-0:8080");
        }
    }

    #[test]
    fn first_failover_when_primary_down() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::First, targets);
        lb.targets[0].healthy.store(false, Ordering::Relaxed);
        let ctx = default_ctx();
        let t = lb.pick(None, &ctx).unwrap();
        assert_eq!(&*t.target.url, "http://host-1:8080");
    }

    #[test]
    fn first_failover_cascading() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::First, targets);
        lb.targets[0].healthy.store(false, Ordering::Relaxed);
        lb.targets[1].healthy.store(false, Ordering::Relaxed);
        let t = lb.pick(None, &default_ctx()).unwrap();
        assert_eq!(&*t.target.url, "http://host-2:8080");
    }

    #[test]
    fn first_none_when_all_down() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::First, targets);
        for ts in &lb.targets {
            ts.healthy.store(false, Ordering::Relaxed);
        }
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    // ── HeaderHash ──

    #[test]
    fn header_hash_consistent() {
        let targets = make_targets(5);
        let lb = ServiceLoadBalancer::new(LbStrategy::HeaderHash, targets);
        let ctx = RequestContext {
            header_hash_value: Some("tenant-42"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(t.target.id, first.target.id, "header hash not consistent");
        }
    }

    #[test]
    fn header_hash_different_values_spread() {
        let targets = make_targets(4);
        let lb = ServiceLoadBalancer::new(LbStrategy::HeaderHash, targets);
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            let val = format!("tenant-{i}");
            let ctx = RequestContext {
                header_hash_value: Some(&val),
                ..Default::default()
            };
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        // With 20 distinct values and 4 targets, expect > 1 distinct target.
        assert!(seen.len() > 1, "header hash didn't spread: {:?}", seen);
    }

    // ── QueryHash ──

    #[test]
    fn query_hash_consistent() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::QueryHash, targets);
        let ctx = RequestContext {
            query_hash_value: Some("user_99"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(t.target.id, first.target.id);
        }
    }

    // ── Zone-aware subset ──

    #[test]
    fn zone_aware_p2c() {
        let mut targets = make_targets(4);
        targets[0].zone = Some("us-east-1a".to_string());
        targets[1].zone = Some("us-east-1a".to_string());
        targets[2].zone = Some("us-east-1b".to_string());
        targets[3].zone = Some("us-east-1b".to_string());
        let lb = ServiceLoadBalancer::new(LbStrategy::RandomChoose, targets);
        let ctx = default_ctx();
        // Zone-aware should prefer 1a targets.
        for _ in 0..20 {
            let t = lb.pick(Some("us-east-1a"), &ctx).unwrap();
            assert!(
                &*t.target.url == "http://host-0:8080" || &*t.target.url == "http://host-1:8080",
                "expected zone-a target, got {}",
                t.target.url
            );
        }
    }

    #[test]
    fn zone_aware_first() {
        let mut targets = make_targets(3);
        targets[0].zone = Some("zone-b".to_string());
        targets[1].zone = Some("zone-a".to_string());
        targets[2].zone = Some("zone-a".to_string());
        let lb = ServiceLoadBalancer::new(LbStrategy::First, targets);
        let t = lb.pick(Some("zone-a"), &default_ctx()).unwrap();
        assert_eq!(&*t.target.url, "http://host-1:8080");
    }

    // ── LbStrategy::from_str ──

    #[test]
    fn strategy_parsing() {
        assert_eq!(
            LbStrategy::from_str("random-choose"),
            LbStrategy::RandomChoose
        );
        assert_eq!(LbStrategy::from_str("p2c"), LbStrategy::RandomChoose);
        assert_eq!(LbStrategy::from_str("first"), LbStrategy::First);
        assert_eq!(LbStrategy::from_str("failover"), LbStrategy::First);
        assert_eq!(LbStrategy::from_str("header-hash"), LbStrategy::HeaderHash);
        assert_eq!(LbStrategy::from_str("header_hash"), LbStrategy::HeaderHash);
        assert_eq!(LbStrategy::from_str("query-hash"), LbStrategy::QueryHash);
        assert_eq!(LbStrategy::from_str("query_hash"), LbStrategy::QueryHash);
        assert_eq!(LbStrategy::from_str("least-time"), LbStrategy::LeastTime);
        assert_eq!(LbStrategy::from_str("least_time"), LbStrategy::LeastTime);
        assert_eq!(LbStrategy::from_str("leasttime"), LbStrategy::LeastTime);
        assert_eq!(
            LbStrategy::from_str("least-conn-scan"),
            LbStrategy::LeastConnScan
        );
        assert_eq!(
            LbStrategy::from_str("least_conn_scan"),
            LbStrategy::LeastConnScan
        );
        assert_eq!(
            LbStrategy::from_str("round-robin-ring"),
            LbStrategy::RoundRobinRing
        );
        assert_eq!(
            LbStrategy::from_str("round_robin_ring"),
            LbStrategy::RoundRobinRing
        );
        assert_eq!(
            LbStrategy::from_str("unknown-thing"),
            LbStrategy::RoundRobin
        );
    }

    // ── InFlightGuard ──

    #[test]
    fn in_flight_guard_increments_and_decrements() {
        let targets = make_targets(1);
        let lb = ServiceLoadBalancer::new(LbStrategy::First, targets);
        let ts = lb.targets[0].clone();
        assert_eq!(ts.in_flight.load(Ordering::Relaxed), 0);
        {
            let _g = InFlightGuard::new(ts.clone());
            assert_eq!(ts.in_flight.load(Ordering::Relaxed), 1);
            {
                let _g2 = InFlightGuard::new(ts.clone());
                assert_eq!(ts.in_flight.load(Ordering::Relaxed), 2);
            }
            assert_eq!(ts.in_flight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(ts.in_flight.load(Ordering::Relaxed), 0);
    }

    // ── Registry ──

    #[test]
    fn registry_snapshot_includes_state() {
        let reg = LoadBalancerRegistry::new();
        let sid = Uuid::new_v4();
        let targets = make_targets(2);
        let tid = targets[0].id;
        reg.rebuild_for_service(sid, LbStrategy::RoundRobin, targets);
        reg.mark_target_health(&sid, &tid, false);
        let snap = reg.snapshot(&sid);
        assert_eq!(snap.len(), 2);
        let t0 = snap.iter().find(|s| s.target.id == tid).unwrap();
        assert!(!t0.healthy.load(Ordering::Relaxed));
    }

    // ── Feature 86: UriHash ──

    #[test]
    fn uri_hash_consistent_for_same_path() {
        let targets = make_targets(5);
        let lb = ServiceLoadBalancer::new(LbStrategy::UriHash, targets);
        let ctx = RequestContext {
            uri_path: Some("/api/v1/users"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(
                t.target.id, first.target.id,
                "uri_hash not consistent for same path"
            );
        }
    }

    #[test]
    fn uri_hash_different_paths_spread() {
        let targets = make_targets(4);
        let lb = ServiceLoadBalancer::new(LbStrategy::UriHash, targets);
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            let path = format!("/path/{i}");
            let ctx = RequestContext {
                uri_path: Some(&path),
                ..Default::default()
            };
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        assert!(
            seen.len() > 1,
            "uri_hash didn't spread across targets: {:?}",
            seen
        );
    }

    // ── Feature 87: ClientIpHash ──

    #[test]
    fn client_ip_hash_consistent() {
        let targets = make_targets(5);
        let lb = ServiceLoadBalancer::new(LbStrategy::ClientIpHash, targets);
        let ctx = RequestContext {
            client_ip: Some("203.0.113.42"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(
                t.target.id, first.target.id,
                "client_ip_hash not consistent"
            );
        }
    }

    #[test]
    fn client_ip_hash_different_ips_spread() {
        let targets = make_targets(4);
        let lb = ServiceLoadBalancer::new(LbStrategy::ClientIpHash, targets);
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            let ip = format!("10.0.0.{i}");
            let ctx = RequestContext {
                client_ip: Some(&ip),
                ..Default::default()
            };
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        assert!(seen.len() > 1, "client_ip_hash didn't spread: {:?}", seen);
    }

    // ── Feature 108: LeastTime ──

    #[test]
    fn least_time_picks_fastest_server() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastTime, targets);
        // Simulate different response times.
        lb.targets[0].record_response_time(5000); // 5ms
        lb.targets[1].record_response_time(1000); // 1ms — fastest
        lb.targets[2].record_response_time(8000); // 8ms
        let ctx = default_ctx();
        let picked = lb.pick(None, &ctx).unwrap();
        assert_eq!(
            &*picked.target.url, "http://host-1:8080",
            "should pick the target with the lowest response time"
        );
    }

    #[test]
    fn least_time_picks_least_loaded_when_times_equal() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastTime, targets);
        // Same response times, different in-flight counts.
        for t in &lb.targets {
            t.record_response_time(2000);
        }
        lb.targets[0].in_flight.store(10, Ordering::Relaxed);
        lb.targets[1].in_flight.store(1, Ordering::Relaxed);
        lb.targets[2].in_flight.store(5, Ordering::Relaxed);
        let ctx = default_ctx();
        let picked = lb.pick(None, &ctx).unwrap();
        assert_eq!(
            &*picked.target.url, "http://host-1:8080",
            "with equal times, should pick the target with fewest in-flight"
        );
    }

    #[test]
    fn least_time_handles_all_unhealthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastTime, targets);
        for t in &lb.targets {
            t.healthy.store(false, Ordering::Relaxed);
        }
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    #[test]
    fn ewma_updates_correctly() {
        let targets = make_targets(1);
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastTime, targets);
        let ts = &lb.targets[0];

        // First sample initialises directly.
        ts.record_response_time(1000);
        assert_eq!(ts.avg_response_us.load(Ordering::Relaxed), 1000);

        // Second sample: EWMA = 1000*0.75 + 2000*0.25 = 1250.
        ts.record_response_time(2000);
        assert_eq!(ts.avg_response_us.load(Ordering::Relaxed), 1250);

        // Third sample: EWMA = 1250*0.75 + 4000*0.25 = 937 + 1000 = 1937.
        ts.record_response_time(4000);
        let avg = ts.avg_response_us.load(Ordering::Relaxed);
        // Integer arithmetic: (1250*3 + 4000) / 4 = (3750+4000)/4 = 7750/4 = 1937.
        assert_eq!(avg, 1937);
    }

    #[test]
    fn least_time_zone_aware() {
        let mut targets = make_targets(4);
        targets[0].zone = Some("us-east-1a".to_string());
        targets[1].zone = Some("us-east-1a".to_string());
        targets[2].zone = Some("us-east-1b".to_string());
        targets[3].zone = Some("us-east-1b".to_string());
        let lb = ServiceLoadBalancer::new(LbStrategy::LeastTime, targets);
        // Make target 1 faster than target 0 in zone-a.
        lb.targets[0].record_response_time(5000);
        lb.targets[1].record_response_time(1000);
        lb.targets[2].record_response_time(100); // zone-b is fastest overall
        lb.targets[3].record_response_time(100);
        let ctx = default_ctx();
        // Zone-aware should restrict to zone-a.
        let picked = lb.pick(Some("us-east-1a"), &ctx).unwrap();
        assert_eq!(
            &*picked.target.url, "http://host-1:8080",
            "zone-aware least-time should pick fastest in zone"
        );
    }

    #[test]
    fn strategy_parsing_uri_and_client_ip() {
        assert_eq!(LbStrategy::from_str("uri-hash"), LbStrategy::UriHash);
        assert_eq!(LbStrategy::from_str("uri_hash"), LbStrategy::UriHash);
        assert_eq!(LbStrategy::from_str("urihash"), LbStrategy::UriHash);
        assert_eq!(
            LbStrategy::from_str("client-ip-hash"),
            LbStrategy::ClientIpHash
        );
        assert_eq!(
            LbStrategy::from_str("client_ip_hash"),
            LbStrategy::ClientIpHash
        );
    }

    // ── Drain lifecycle ──

    #[test]
    fn draining_target_not_routable() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        lb.targets[0].set_lifecycle(TargetLifecycle::Draining);
        let ctx = default_ctx();
        for _ in 0..10 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(&*t.target.url, "http://host-1:8080");
        }
    }

    #[test]
    fn inactive_target_not_routable() {
        let targets = make_targets(2);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        lb.targets[1].set_lifecycle(TargetLifecycle::Inactive);
        let ctx = default_ctx();
        for _ in 0..10 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(&*t.target.url, "http://host-0:8080");
        }
    }

    #[test]
    fn lifecycle_transitions() {
        let targets = make_targets(1);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        let ts = &lb.targets[0];
        assert_eq!(ts.lifecycle(), TargetLifecycle::Active);
        assert!(ts.is_routable());

        ts.set_lifecycle(TargetLifecycle::Draining);
        assert_eq!(ts.lifecycle(), TargetLifecycle::Draining);
        assert!(!ts.is_routable());

        ts.set_lifecycle(TargetLifecycle::Inactive);
        assert_eq!(ts.lifecycle(), TargetLifecycle::Inactive);
        assert!(!ts.is_routable());
    }

    #[test]
    fn all_draining_returns_none() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::RoundRobin, targets);
        for ts in &lb.targets {
            ts.set_lifecycle(TargetLifecycle::Draining);
        }
        assert!(lb.pick(None, &default_ctx()).is_none());
    }

    // ── ConsistentHash (ring — default) ──

    #[test]
    fn consistent_hash_ring_consistent() {
        let targets = make_targets(5);
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHash, targets);
        let ctx = RequestContext {
            uri_path: Some("/api/v1/users"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(t.target.id, first.target.id, "ring not consistent");
        }
    }

    #[test]
    fn consistent_hash_ring_spreads() {
        let targets = make_targets(4);
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHash, targets);
        let mut seen = std::collections::HashSet::new();
        for i in 0..40 {
            let path = format!("/path/{i}");
            let ctx = RequestContext {
                uri_path: Some(&path),
                ..Default::default()
            };
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        assert!(seen.len() > 1, "ring didn't spread: {:?}", seen);
    }

    #[test]
    fn consistent_hash_ring_skips_unhealthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHash, targets);
        let ctx = RequestContext {
            uri_path: Some("/test"),
            ..Default::default()
        };
        let original = lb.pick(None, &ctx).unwrap();
        original.healthy.store(false, Ordering::Relaxed);
        let fallback = lb.pick(None, &ctx).unwrap();
        assert_ne!(fallback.target.id, original.target.id);
    }

    #[test]
    fn consistent_hash_ring_respects_weights() {
        let targets = make_weighted_targets(&[3, 1]);
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHash, targets);
        let mut counts = std::collections::HashMap::new();
        for i in 0..400 {
            let path = format!("/key/{i}");
            let ctx = RequestContext {
                uri_path: Some(&path),
                ..Default::default()
            };
            let t = lb.pick(None, &ctx).unwrap();
            *counts.entry(t.target.url.clone()).or_insert(0) += 1;
        }
        let h0 = *counts.get("http://host-0:8080").unwrap_or(&0);
        let h1 = *counts.get("http://host-1:8080").unwrap_or(&0);
        assert!(h0 > h1, "weight-3 target should get more: h0={h0} h1={h1}");
    }

    #[test]
    fn consistent_hash_ring_empty() {
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHash, Vec::new());
        let ctx = RequestContext {
            uri_path: Some("/test"),
            ..Default::default()
        };
        assert!(lb.pick(None, &ctx).is_none());
    }

    #[test]
    fn consistent_hash_ring_all_unhealthy() {
        let targets = make_targets(3);
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHash, targets);
        for t in &lb.targets {
            t.healthy.store(false, Ordering::Relaxed);
        }
        let ctx = RequestContext {
            uri_path: Some("/test"),
            ..Default::default()
        };
        assert!(lb.pick(None, &ctx).is_none());
    }

    // ── ConsistentHashHrw (legacy) ──

    #[test]
    fn consistent_hash_hrw_consistent() {
        let targets = make_targets(5);
        let lb = ServiceLoadBalancer::new(LbStrategy::ConsistentHashHrw, targets);
        let ctx = RequestContext {
            uri_path: Some("/api/v1/users"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(t.target.id, first.target.id, "HRW not consistent");
        }
    }

    #[test]
    fn strategy_parsing_consistent_hash_variants() {
        assert_eq!(
            LbStrategy::from_str("consistent-hash"),
            LbStrategy::ConsistentHash
        );
        assert_eq!(
            LbStrategy::from_str("consistent-hash-hrw"),
            LbStrategy::ConsistentHashHrw
        );
        assert_eq!(
            LbStrategy::from_str("consistent_hash_hrw"),
            LbStrategy::ConsistentHashHrw
        );
    }

    // ── pick_excluding ──

    #[test]
    fn pick_excluding_skips_excluded() {
        let targets = make_targets(3);
        let ids: Vec<Uuid> = targets.iter().map(|t| t.id).collect();
        let svc_id = Uuid::new_v4();
        let reg = LoadBalancerRegistry::new();
        reg.rebuild_for_service(svc_id, LbStrategy::RoundRobin, targets);

        let exclude = vec![ids[0], ids[1]];
        let picked = reg.pick_excluding(&svc_id, &exclude, None).unwrap();
        assert_eq!(picked.target.id, ids[2]);
    }

    #[test]
    fn pick_excluding_all_returns_none() {
        let targets = make_targets(2);
        let ids: Vec<Uuid> = targets.iter().map(|t| t.id).collect();
        let svc_id = Uuid::new_v4();
        let reg = LoadBalancerRegistry::new();
        reg.rebuild_for_service(svc_id, LbStrategy::RoundRobin, targets);

        let picked = reg.pick_excluding(&svc_id, &ids, None);
        assert!(picked.is_none());
    }

    #[test]
    fn pick_excluding_prefers_least_inflight() {
        let targets = make_targets(3);
        let ids: Vec<Uuid> = targets.iter().map(|t| t.id).collect();
        let svc_id = Uuid::new_v4();
        let reg = LoadBalancerRegistry::new();
        reg.rebuild_for_service(svc_id, LbStrategy::RoundRobin, targets);

        let snap = reg.snapshot(&svc_id);
        snap[1].in_flight.store(100, Ordering::Relaxed);
        snap[2].in_flight.store(1, Ordering::Relaxed);

        let picked = reg.pick_excluding(&svc_id, &[ids[0]], None).unwrap();
        assert_eq!(picked.target.id, ids[2]);
    }

    // ── RdpCookie ──

    #[test]
    fn rdp_cookie_consistent() {
        let targets = make_targets(5);
        let lb = ServiceLoadBalancer::new(LbStrategy::RdpCookie, targets);
        let ctx = RequestContext {
            rdp_cookie: Some("admin-pc"),
            ..Default::default()
        };
        let first = lb.pick(None, &ctx).unwrap();
        for _ in 0..20 {
            let t = lb.pick(None, &ctx).unwrap();
            assert_eq!(t.target.id, first.target.id, "rdp_cookie not consistent");
        }
    }

    #[test]
    fn rdp_cookie_different_values_spread() {
        let targets = make_targets(4);
        let lb = ServiceLoadBalancer::new(LbStrategy::RdpCookie, targets);
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            let cookie = format!("user-{i}");
            let ctx = RequestContext {
                rdp_cookie: Some(&cookie),
                ..Default::default()
            };
            let t = lb.pick(None, &ctx).unwrap();
            seen.insert(t.target.url.clone());
        }
        assert!(seen.len() > 1, "rdp_cookie didn't spread: {:?}", seen);
    }

    #[test]
    fn strategy_parsing_rdp_cookie() {
        assert_eq!(LbStrategy::from_str("rdp-cookie"), LbStrategy::RdpCookie);
        assert_eq!(LbStrategy::from_str("rdp_cookie"), LbStrategy::RdpCookie);
        assert_eq!(LbStrategy::from_str("rdpcookie"), LbStrategy::RdpCookie);
    }
}
