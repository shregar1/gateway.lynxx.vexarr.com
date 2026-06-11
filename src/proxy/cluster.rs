//! AWS-inspired DNS-based cluster mode for horizontal LB node scaling.
//!
//! # Architecture
//!
//! ```text
//! DNS Cluster Mode
//! ├── ClusterNode         — Identity of a single LB node (id, addr, weight, health)
//! ├── ClusterState        — Snapshot of all live nodes (DashMap<NodeId, ClusterNode>)
//! ├── ClusterStrategy     — DNS record selection (RoundRobin / Weighted / LatencyBased / GeoAware)
//! ├── DnsRecordManager    — Builds A/AAAA record sets from healthy nodes
//! ├── NodeHealthTracker   — Heartbeat-based failure detection (φ accrual style)
//! ├── SurgeController     — AWS-style auto-scaling: aggressive up, conservative down
//! ├── ClusterMetrics      — Global AtomicU64 counters for cluster operations
//! └── PrewarmEstimator    — Predicts when to pre-scale based on capacity headroom
//! ```
//!
//! # Why
//!
//! AWS ELB's primary scaling trick: multiple identical LB nodes behind a DNS
//! name, each getting a share of traffic via DNS round-robin. When load
//! increases, new nodes are added and DNS is updated. When load decreases,
//! nodes are drained and removed.
//!
//! This module provides the **control plane logic** — node registration,
//! health tracking, DNS record computation, and scaling decisions. The
//! actual DNS record publication is left to an external integration (Route53
//! API, CoreDNS etcd, or a local DNS server).
//!
//! # Scaling Algorithm
//!
//! - **Scale-up**: When any capacity metric > 80% for 30s, add `ceil(current * 0.5)` nodes.
//! - **Scale-down**: When all capacity metrics < 30% for 15 minutes, remove 1 node.
//! - **Predictive**: Exponential moving average of hourly load → pre-scale before predicted peaks.
//! - **Cooldown**: 60s after scale-up, 300s after scale-down.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

static CLUSTER_ENABLED: AtomicBool = AtomicBool::new(false);
static CLUSTER_STRATEGY: AtomicU8 = AtomicU8::new(0); // RoundRobin

pub fn set_cluster_enabled(enabled: bool) {
    CLUSTER_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_cluster_enabled() -> bool {
    CLUSTER_ENABLED.load(Ordering::Relaxed)
}

pub fn set_cluster_strategy(strategy: ClusterStrategy) {
    CLUSTER_STRATEGY.store(strategy as u8, Ordering::Relaxed);
}

pub fn get_cluster_strategy() -> ClusterStrategy {
    ClusterStrategy::from_u8(CLUSTER_STRATEGY.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// Cluster strategy enum
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClusterStrategy {
    /// Each healthy node gets one A record — clients round-robin via DNS.
    RoundRobin = 0,
    /// Nodes with higher capacity get more weight (DNS SRV or weighted A).
    Weighted = 1,
    /// Route to geographically closest node (requires GeoIP integration).
    GeoAware = 2,
    /// Route to lowest-latency node (requires cross-node latency probes).
    LatencyBased = 3,
}

impl ClusterStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => ClusterStrategy::Weighted,
            2 => ClusterStrategy::GeoAware,
            3 => ClusterStrategy::LatencyBased,
            _ => ClusterStrategy::RoundRobin,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "weighted" => ClusterStrategy::Weighted,
            "geo" | "geo-aware" | "geo_aware" => ClusterStrategy::GeoAware,
            "latency" | "latency-based" | "latency_based" => ClusterStrategy::LatencyBased,
            _ => ClusterStrategy::RoundRobin,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Node identity & health
// ═══════════════════════════════════════════════════════════════════════════

pub type NodeId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Draining,
}

/// A single LB node in the cluster.
#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub id: NodeId,
    pub addr: IpAddr,
    pub weight: u32,
    pub health: NodeHealth,
    pub region: Option<String>,
    pub az: Option<String>,
    /// Capacity used as a fraction [0.0, 1.0].
    pub load_fraction: f64,
    /// Last heartbeat from this node.
    pub last_heartbeat: Instant,
    /// Connections currently served by this node.
    pub active_connections: u64,
    /// Requests per second (rolling average).
    pub rps: f64,
}

impl ClusterNode {
    pub fn new(id: NodeId, addr: IpAddr) -> Self {
        Self {
            id,
            addr,
            weight: 100,
            health: NodeHealth::Healthy,
            region: None,
            az: None,
            load_fraction: 0.0,
            last_heartbeat: Instant::now(),
            active_connections: 0,
            rps: 0.0,
        }
    }

    pub fn with_weight(mut self, w: u32) -> Self {
        self.weight = w;
        self
    }

    pub fn with_region(mut self, region: &str, az: &str) -> Self {
        self.region = Some(region.to_string());
        self.az = Some(az.to_string());
        self
    }

    pub fn is_available(&self) -> bool {
        matches!(self.health, NodeHealth::Healthy | NodeHealth::Degraded)
    }

    pub fn heartbeat_age(&self) -> Duration {
        self.last_heartbeat.elapsed()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Cluster state — the central registry
// ═══════════════════════════════════════════════════════════════════════════

pub struct ClusterState {
    nodes: DashMap<NodeId, ClusterNode, FastHasher>,
    /// Heartbeat timeout — nodes missing heartbeats beyond this are marked Unhealthy.
    heartbeat_timeout: Duration,
    /// Minimum nodes that must remain healthy (never scale below this).
    min_nodes: u32,
    /// Maximum nodes allowed (cap scaling).
    max_nodes: u32,
}

impl ClusterState {
    pub fn new(heartbeat_timeout: Duration, min_nodes: u32, max_nodes: u32) -> Self {
        Self {
            nodes: DashMap::with_hasher(FastHasher::default()),
            heartbeat_timeout,
            min_nodes: min_nodes.max(1),
            max_nodes: max_nodes.max(min_nodes.max(1)),
        }
    }

    /// Register a new node. Returns false if the node already exists.
    pub fn register_node(&self, node: ClusterNode) -> bool {
        // BUG FIX: previously `contains_key` then `insert` were two separate
        // DashMap ops with no guard held across them (TOCTOU). Two threads
        // registering the SAME brand-new id could both see contains_key==false,
        // both insert (overwriting a live node), both return true, and double-
        // count nodes_registered. The entry API performs the existence check and
        // insert atomically under the shard lock, so exactly one caller wins and
        // the metric only counts a truly-new node.
        use dashmap::mapref::entry::Entry;
        match self.nodes.entry(node.id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(node);
                CLUSTER_METRICS.nodes_registered.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    /// Deregister a node. Returns the removed node if it existed.
    pub fn deregister_node(&self, id: &NodeId) -> Option<ClusterNode> {
        let removed = self.nodes.remove(id).map(|(_, n)| n);
        if removed.is_some() {
            CLUSTER_METRICS.nodes_deregistered.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// Update heartbeat for a node. Returns false if node not found.
    pub fn heartbeat(&self, id: &NodeId, load_fraction: f64, active_conns: u64, rps: f64) -> bool {
        if let Some(mut entry) = self.nodes.get_mut(id) {
            entry.last_heartbeat = Instant::now();
            // BUG FIX: `f64::clamp(NaN, 0.0, 1.0) == NaN`, so a node reporting a
            // non-finite load_fraction (e.g. NaN from a 0.0/0.0 capacity calc)
            // used to store NaN unchanged. That NaN then poisoned avg_load()
            // (stuck scale-down), the LatencyBased DNS sort, and best_az_for_placement
            // (panic via partial_cmp().unwrap()). Reject non-finite values at
            // ingestion so NaN/Inf can never enter the registry.
            entry.load_fraction = if load_fraction.is_finite() {
                load_fraction.clamp(0.0, 1.0)
            } else {
                0.0
            };
            entry.active_connections = active_conns;
            entry.rps = rps;
            // Auto-recover from Unhealthy if heartbeat resumes.
            if entry.health == NodeHealth::Unhealthy {
                entry.health = NodeHealth::Healthy;
                CLUSTER_METRICS.nodes_recovered.fetch_add(1, Ordering::Relaxed);
            }
            CLUSTER_METRICS.heartbeats_received.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Mark stale nodes as Unhealthy based on heartbeat timeout.
    pub fn check_heartbeats(&self) -> Vec<NodeId> {
        let mut stale = Vec::new();
        for mut entry in self.nodes.iter_mut() {
            if entry.health != NodeHealth::Draining
                && entry.heartbeat_age() > self.heartbeat_timeout
            {
                if entry.health != NodeHealth::Unhealthy {
                    entry.health = NodeHealth::Unhealthy;
                    CLUSTER_METRICS.nodes_failed.fetch_add(1, Ordering::Relaxed);
                    stale.push(entry.id);
                }
            }
        }
        stale
    }

    /// Set a node to Draining state (graceful removal).
    pub fn drain_node(&self, id: &NodeId) -> bool {
        if let Some(mut entry) = self.nodes.get_mut(id) {
            entry.health = NodeHealth::Draining;
            CLUSTER_METRICS.nodes_drained.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get all healthy nodes.
    pub fn healthy_nodes(&self) -> Vec<ClusterNode> {
        self.nodes
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.clone())
            .collect()
    }

    /// Get all nodes regardless of health.
    pub fn all_nodes(&self) -> Vec<ClusterNode> {
        self.nodes.iter().map(|e| e.clone()).collect()
    }

    /// Total number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of healthy nodes.
    pub fn healthy_count(&self) -> usize {
        self.nodes.iter().filter(|e| e.is_available()).count()
    }

    /// Average load fraction across healthy nodes.
    pub fn avg_load(&self) -> f64 {
        let healthy: Vec<_> = self.nodes.iter().filter(|e| e.is_available()).collect();
        if healthy.is_empty() {
            return 0.0;
        }
        let total: f64 = healthy.iter().map(|e| e.load_fraction).sum();
        total / healthy.len() as f64
    }

    /// Maximum load across any healthy node.
    pub fn max_load(&self) -> f64 {
        self.nodes
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.load_fraction)
            .fold(0.0_f64, f64::max)
    }

    /// Total RPS across all healthy nodes.
    pub fn total_rps(&self) -> f64 {
        self.nodes
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.rps)
            .sum()
    }

    pub fn min_nodes(&self) -> u32 {
        self.min_nodes
    }

    pub fn max_nodes(&self) -> u32 {
        self.max_nodes
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS record generation
// ═══════════════════════════════════════════════════════════════════════════

/// A DNS A/AAAA record for publication.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub addr: IpAddr,
    pub weight: u32,
    /// TTL in seconds — lower = faster failover, higher = less DNS traffic.
    pub ttl: u32,
}

/// Build the DNS record set from healthy nodes based on the active strategy.
pub struct DnsRecordManager {
    pub ttl: u32,
}

impl DnsRecordManager {
    pub fn new(ttl: u32) -> Self {
        Self { ttl: ttl.max(10) }
    }

    /// Build A/AAAA record set from the cluster state.
    pub fn build_records(&self, state: &ClusterState, strategy: ClusterStrategy) -> Vec<DnsRecord> {
        let healthy = state.healthy_nodes();
        if healthy.is_empty() {
            return Vec::new();
        }

        CLUSTER_METRICS.dns_updates.fetch_add(1, Ordering::Relaxed);

        match strategy {
            ClusterStrategy::RoundRobin => {
                // All healthy nodes get equal weight.
                healthy
                    .iter()
                    .map(|n| DnsRecord {
                        addr: n.addr,
                        weight: 1,
                        ttl: self.ttl,
                    })
                    .collect()
            }
            ClusterStrategy::Weighted => {
                // Weight proportional to node weight * (1 - load_fraction).
                // Higher spare capacity → higher DNS weight.
                healthy
                    .iter()
                    .map(|n| {
                        let spare = 1.0 - n.load_fraction;
                        let effective_weight = (n.weight as f64 * spare).max(1.0) as u32;
                        DnsRecord {
                            addr: n.addr,
                            weight: effective_weight,
                            ttl: self.ttl,
                        }
                    })
                    .collect()
            }
            ClusterStrategy::GeoAware => {
                // Group by region; for each region, pick the healthiest nodes.
                // Without a client-region context, just return all with region tags.
                healthy
                    .iter()
                    .map(|n| DnsRecord {
                        addr: n.addr,
                        weight: n.weight,
                        ttl: self.ttl,
                    })
                    .collect()
            }
            ClusterStrategy::LatencyBased => {
                // Prefer nodes with lower load (proxy for lower latency).
                // Sort by load, assign descending weights.
                let mut sorted = healthy.clone();
                // BUG FIX: partial_cmp returns None for any NaN operand, so the
                // old `.unwrap()` panicked on a non-finite load_fraction. Use a
                // total order (total_cmp) so the sort can never panic even if a
                // non-finite value slips past ingestion sanitization.
                sorted.sort_by(|a, b| a.load_fraction.total_cmp(&b.load_fraction));
                let n = sorted.len() as u32;
                sorted
                    .iter()
                    .enumerate()
                    .map(|(i, node)| DnsRecord {
                        addr: node.addr,
                        weight: n - i as u32,
                        ttl: self.ttl,
                    })
                    .collect()
            }
        }
    }

    /// Build records filtered by region (for geo-aware routing).
    pub fn build_records_for_region(
        &self,
        state: &ClusterState,
        region: &str,
    ) -> Vec<DnsRecord> {
        let healthy = state.healthy_nodes();
        let regional: Vec<_> = healthy
            .iter()
            .filter(|n| n.region.as_deref() == Some(region))
            .collect();

        // If no nodes in this region, fall back to all healthy nodes.
        let nodes = if regional.is_empty() { &healthy } else {
            // This is slightly awkward but avoids an allocation.
            return regional
                .iter()
                .map(|n| DnsRecord {
                    addr: n.addr,
                    weight: n.weight,
                    ttl: self.ttl,
                })
                .collect();
        };

        nodes
            .iter()
            .map(|n| DnsRecord {
                addr: n.addr,
                weight: n.weight,
                ttl: self.ttl,
            })
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Surge controller — AWS-style auto-scaling
// ═══════════════════════════════════════════════════════════════════════════

/// Scaling decision from the surge controller.
#[derive(Debug, Clone, PartialEq)]
pub enum ScaleAction {
    /// No change needed — within acceptable bounds.
    None,
    /// Add N nodes.
    ScaleUp(u32),
    /// Remove N nodes (drain first, then deregister).
    ScaleDown(u32),
    /// Blocked by cooldown — last scaling event too recent.
    CooldownActive { remaining: Duration },
}

/// Thresholds for scaling decisions.
#[derive(Debug, Clone)]
pub struct ScalePolicy {
    /// Scale up when max load exceeds this (0.0-1.0). Default: 0.80.
    pub scale_up_threshold: f64,
    /// Duration the threshold must be exceeded before scaling up. Default: 30s.
    pub scale_up_sustained: Duration,
    /// Scale down when avg load falls below this. Default: 0.30.
    pub scale_down_threshold: f64,
    /// Duration the avg load must stay below threshold. Default: 15 min.
    pub scale_down_sustained: Duration,
    /// Cooldown after a scale-up event. Default: 60s.
    pub scale_up_cooldown: Duration,
    /// Cooldown after a scale-down event. Default: 300s.
    pub scale_down_cooldown: Duration,
    /// Multiplier for scale-up: new_count = ceil(current * (1 + factor)).
    /// Default: 0.5 → add 50% more nodes.
    pub scale_up_factor: f64,
}

impl Default for ScalePolicy {
    fn default() -> Self {
        Self {
            scale_up_threshold: 0.80,
            scale_up_sustained: Duration::from_secs(30),
            scale_down_threshold: 0.30,
            scale_down_sustained: Duration::from_secs(900), // 15 min
            scale_up_cooldown: Duration::from_secs(60),
            scale_down_cooldown: Duration::from_secs(300),
            scale_up_factor: 0.5,
        }
    }
}

pub struct SurgeController {
    policy: ScalePolicy,
    /// When max_load first exceeded the up-threshold (None if not exceeded).
    high_load_since: Option<Instant>,
    /// When avg_load first dropped below down-threshold.
    low_load_since: Option<Instant>,
    /// Last time a scale event was executed.
    last_scale_up: Option<Instant>,
    last_scale_down: Option<Instant>,
}

impl SurgeController {
    pub fn new(policy: ScalePolicy) -> Self {
        Self {
            policy,
            high_load_since: None,
            low_load_since: None,
            last_scale_up: None,
            last_scale_down: None,
        }
    }

    pub fn with_default_policy() -> Self {
        Self::new(ScalePolicy::default())
    }

    /// Evaluate whether scaling should happen based on current cluster state.
    pub fn evaluate(&mut self, state: &ClusterState) -> ScaleAction {
        let now = Instant::now();
        let max_load = state.max_load();
        let avg_load = state.avg_load();
        let current_count = state.healthy_count() as u32;

        // BUG FIX: cooldowns were previously both checked up front, so an active
        // scale-DOWN cooldown (default 300s) would return CooldownActive and
        // short-circuit before the scale-up check — meaning a sudden high-load
        // surge shortly after a scale-down was ignored for up to 5 minutes,
        // defeating the documented aggressive-scale-up guarantee. Each cooldown
        // is now gated to its OWN direction: the scale-up path consults only
        // scale_up_cooldown and the scale-down path only scale_down_cooldown, so
        // a high-load surge can trigger ScaleUp even right after a scale-down
        // while same-direction churn is still throttled.

        // ── Scale-up check (aggressive) ────────────────────────────────
        if max_load > self.policy.scale_up_threshold {
            // Per-direction cooldown: a scale-up surge consults ONLY the scale-up
            // cooldown, so a recent scale-down can no longer wedge scale-up.
            if let Some(last_up) = self.last_scale_up {
                let elapsed = now.duration_since(last_up);
                if elapsed < self.policy.scale_up_cooldown {
                    return ScaleAction::CooldownActive {
                        remaining: self.policy.scale_up_cooldown - elapsed,
                    };
                }
            }
            let since = self.high_load_since.get_or_insert(now);
            if now.duration_since(*since) >= self.policy.scale_up_sustained {
                let to_add = ((current_count as f64 * self.policy.scale_up_factor).ceil() as u32)
                    .max(1);
                let capped = to_add.min(state.max_nodes().saturating_sub(current_count));
                if capped > 0 {
                    self.last_scale_up = Some(now);
                    self.high_load_since = None;
                    CLUSTER_METRICS.scale_up_events.fetch_add(1, Ordering::Relaxed);
                    return ScaleAction::ScaleUp(capped);
                }
            }
        } else {
            self.high_load_since = None;
        }

        // ── Scale-down check (conservative) ────────────────────────────
        if avg_load < self.policy.scale_down_threshold && current_count > state.min_nodes() {
            // Per-direction cooldown: a scale-down consults ONLY the scale-down
            // cooldown, not the scale-up one.
            if let Some(last_down) = self.last_scale_down {
                let elapsed = now.duration_since(last_down);
                if elapsed < self.policy.scale_down_cooldown {
                    return ScaleAction::CooldownActive {
                        remaining: self.policy.scale_down_cooldown - elapsed,
                    };
                }
            }
            let since = self.low_load_since.get_or_insert(now);
            if now.duration_since(*since) >= self.policy.scale_down_sustained {
                let to_remove = 1u32; // Always remove just 1 at a time.
                let safe = to_remove.min(current_count.saturating_sub(state.min_nodes()));
                if safe > 0 {
                    self.last_scale_down = Some(now);
                    self.low_load_since = None;
                    CLUSTER_METRICS.scale_down_events.fetch_add(1, Ordering::Relaxed);
                    return ScaleAction::ScaleDown(safe);
                }
            }
        } else {
            self.low_load_since = None;
        }

        ScaleAction::None
    }

    /// Record that a scale-up was externally triggered (e.g. pre-warm).
    pub fn record_scale_up(&mut self) {
        self.last_scale_up = Some(Instant::now());
        self.high_load_since = None;
    }

    /// Record that a scale-down was externally triggered.
    pub fn record_scale_down(&mut self) {
        self.last_scale_down = Some(Instant::now());
        self.low_load_since = None;
    }

    pub fn policy(&self) -> &ScalePolicy {
        &self.policy
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Predictive pre-scaler (EMA-based)
// ═══════════════════════════════════════════════════════════════════════════

/// Exponential moving average predictor for traffic patterns.
/// Tracks hourly load snapshots and predicts the next hour's load
/// to pre-scale before demand arrives.
pub struct PrewarmEstimator {
    /// EMA of load per hour-of-day slot (24 slots).
    hourly_ema: [f64; 24],
    /// Smoothing factor for EMA (0.0-1.0). Higher = more weight on recent data.
    alpha: f64,
    /// Headroom multiplier — pre-scale to predicted * (1 + headroom).
    headroom: f64,
    /// Total samples ingested.
    samples: u64,
}

impl PrewarmEstimator {
    pub fn new(alpha: f64, headroom: f64) -> Self {
        Self {
            hourly_ema: [0.0; 24],
            alpha: alpha.clamp(0.01, 0.99),
            headroom: headroom.clamp(0.0, 2.0),
            samples: 0,
        }
    }

    /// Record a load observation for the given hour (0-23).
    pub fn record(&mut self, hour: u8, load: f64) {
        let slot = (hour % 24) as usize;
        if self.samples == 0 {
            // First observation — initialize.
            self.hourly_ema[slot] = load;
        } else {
            self.hourly_ema[slot] = self.alpha * load + (1.0 - self.alpha) * self.hourly_ema[slot];
        }
        self.samples += 1;
    }

    /// Predict the load for the given hour.
    pub fn predict(&self, hour: u8) -> f64 {
        let slot = (hour % 24) as usize;
        self.hourly_ema[slot] * (1.0 + self.headroom)
    }

    /// Given a predicted load and per-node capacity, compute how many
    /// nodes are needed.
    pub fn nodes_needed(&self, hour: u8, capacity_per_node: f64) -> u32 {
        if capacity_per_node <= 0.0 {
            return 1;
        }
        let predicted = self.predict(hour);
        ((predicted / capacity_per_node).ceil() as u32).max(1)
    }

    /// Total samples recorded.
    pub fn sample_count(&self) -> u64 {
        self.samples
    }

    /// Get the EMA array (for debugging / export).
    pub fn hourly_profile(&self) -> &[f64; 24] {
        &self.hourly_ema
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-AZ awareness
// ═══════════════════════════════════════════════════════════════════════════

/// Snapshot of capacity per availability zone.
#[derive(Debug, Clone)]
pub struct AzCapacity {
    pub az: String,
    pub healthy_nodes: u32,
    pub total_rps: f64,
    pub avg_load: f64,
}

/// Compute per-AZ capacity from the cluster state.
pub fn az_capacity_report(state: &ClusterState) -> Vec<AzCapacity> {
    let nodes = state.healthy_nodes();
    let mut az_map: std::collections::HashMap<String, (u32, f64, f64)> =
        std::collections::HashMap::new();

    for node in &nodes {
        let az = node.az.clone().unwrap_or_else(|| "unknown".to_string());
        let entry = az_map.entry(az).or_insert((0, 0.0, 0.0));
        entry.0 += 1;
        entry.1 += node.rps;
        entry.2 += node.load_fraction;
    }

    az_map
        .into_iter()
        .map(|(az, (count, rps, load_sum))| AzCapacity {
            az,
            healthy_nodes: count,
            total_rps: rps,
            avg_load: if count > 0 {
                load_sum / count as f64
            } else {
                0.0
            },
        })
        .collect()
}

/// Identify the least-loaded AZ for placing new nodes.
pub fn best_az_for_placement(state: &ClusterState) -> Option<String> {
    let report = az_capacity_report(state);
    report
        .into_iter()
        // BUG FIX: partial_cmp returns None on a NaN avg_load (which arose when an
        // AZ aggregated a non-finite node load_fraction), so the old `.unwrap()`
        // panicked. total_cmp gives a total order so min_by can never panic.
        .min_by(|a, b| a.avg_load.total_cmp(&b.avg_load))
        .map(|az| az.az)
}

// ═══════════════════════════════════════════════════════════════════════════
// Composite capacity metric (AWS LCU equivalent)
// ═══════════════════════════════════════════════════════════════════════════

/// LCU-style composite capacity unit for a single node.
/// Mirrors AWS ELB LCU dimensions: new connections, active connections,
/// bandwidth, and rule evaluations.
#[derive(Debug, Clone)]
pub struct CapacityUnit {
    /// New connections per second (capacity = 25 per LCU).
    pub new_conns_per_sec: f64,
    /// Active connections per minute (capacity = 3000 per LCU).
    pub active_conns_per_min: f64,
    /// Bytes processed per hour (capacity = 1 GB per LCU).
    pub bytes_per_hour: f64,
    /// Rule evaluations per second (capacity = 1000 per LCU).
    pub rule_evals_per_sec: f64,
}

impl CapacityUnit {
    pub fn new() -> Self {
        Self {
            new_conns_per_sec: 0.0,
            active_conns_per_min: 0.0,
            bytes_per_hour: 0.0,
            rule_evals_per_sec: 0.0,
        }
    }

    /// Compute LCU count — whichever dimension is highest determines the LCU.
    pub fn lcu(&self) -> f64 {
        let conn_lcu = self.new_conns_per_sec / 25.0;
        let active_lcu = self.active_conns_per_min / 3000.0;
        let bw_lcu = self.bytes_per_hour / 1_073_741_824.0; // 1 GB
        let rule_lcu = self.rule_evals_per_sec / 1000.0;

        conn_lcu.max(active_lcu).max(bw_lcu).max(rule_lcu)
    }

    /// The dimension driving cost (for diagnostics).
    pub fn bottleneck_dimension(&self) -> &'static str {
        let conn_lcu = self.new_conns_per_sec / 25.0;
        let active_lcu = self.active_conns_per_min / 3000.0;
        let bw_lcu = self.bytes_per_hour / 1_073_741_824.0;
        let rule_lcu = self.rule_evals_per_sec / 1000.0;

        let max = conn_lcu.max(active_lcu).max(bw_lcu).max(rule_lcu);
        if max == conn_lcu {
            "new_connections"
        } else if max == active_lcu {
            "active_connections"
        } else if max == bw_lcu {
            "bandwidth"
        } else {
            "rule_evaluations"
        }
    }
}

impl Default for CapacityUnit {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct ClusterMetrics {
    pub nodes_registered: AtomicU64,
    pub nodes_deregistered: AtomicU64,
    pub nodes_failed: AtomicU64,
    pub nodes_recovered: AtomicU64,
    pub nodes_drained: AtomicU64,
    pub heartbeats_received: AtomicU64,
    pub dns_updates: AtomicU64,
    pub scale_up_events: AtomicU64,
    pub scale_down_events: AtomicU64,
}

static CLUSTER_METRICS: ClusterMetrics = ClusterMetrics {
    nodes_registered: AtomicU64::new(0),
    nodes_deregistered: AtomicU64::new(0),
    nodes_failed: AtomicU64::new(0),
    nodes_recovered: AtomicU64::new(0),
    nodes_drained: AtomicU64::new(0),
    heartbeats_received: AtomicU64::new(0),
    dns_updates: AtomicU64::new(0),
    scale_up_events: AtomicU64::new(0),
    scale_down_events: AtomicU64::new(0),
};

pub fn cluster_metrics() -> &'static ClusterMetrics {
    &CLUSTER_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn make_state(min: u32, max: u32) -> ClusterState {
        ClusterState::new(Duration::from_secs(10), min, max)
    }

    fn make_node(last: u8) -> ClusterNode {
        ClusterNode::new(Uuid::new_v4(), ip(last))
    }

    // ── Strategy enum ──────────────────────────────────────────────────

    #[test]
    fn strategy_from_u8_roundtrip() {
        assert_eq!(ClusterStrategy::from_u8(0), ClusterStrategy::RoundRobin);
        assert_eq!(ClusterStrategy::from_u8(1), ClusterStrategy::Weighted);
        assert_eq!(ClusterStrategy::from_u8(2), ClusterStrategy::GeoAware);
        assert_eq!(ClusterStrategy::from_u8(3), ClusterStrategy::LatencyBased);
        assert_eq!(ClusterStrategy::from_u8(99), ClusterStrategy::RoundRobin);
    }

    #[test]
    fn strategy_from_str() {
        assert_eq!(ClusterStrategy::from_str("weighted"), ClusterStrategy::Weighted);
        assert_eq!(ClusterStrategy::from_str("geo"), ClusterStrategy::GeoAware);
        assert_eq!(ClusterStrategy::from_str("geo-aware"), ClusterStrategy::GeoAware);
        assert_eq!(ClusterStrategy::from_str("latency"), ClusterStrategy::LatencyBased);
        assert_eq!(ClusterStrategy::from_str("latency-based"), ClusterStrategy::LatencyBased);
        assert_eq!(ClusterStrategy::from_str("unknown"), ClusterStrategy::RoundRobin);
    }

    // ── Global toggle ──────────────────────────────────────────────────

    #[test]
    fn global_enable_disable() {
        set_cluster_enabled(true);
        assert!(is_cluster_enabled());
        // Don't disable — other tests may run in parallel.
    }

    #[test]
    fn global_strategy_switch() {
        set_cluster_strategy(ClusterStrategy::Weighted);
        assert_eq!(get_cluster_strategy(), ClusterStrategy::Weighted);
        set_cluster_strategy(ClusterStrategy::RoundRobin);
        assert_eq!(get_cluster_strategy(), ClusterStrategy::RoundRobin);
    }

    // ── Node registration ──────────────────────────────────────────────

    #[test]
    fn register_and_deregister_node() {
        let state = make_state(1, 10);
        let node = make_node(1);
        let id = node.id;

        assert!(state.register_node(node.clone()));
        assert_eq!(state.node_count(), 1);

        // Duplicate registration returns false.
        assert!(!state.register_node(node));

        // Deregister.
        let removed = state.deregister_node(&id);
        assert!(removed.is_some());
        assert_eq!(state.node_count(), 0);
    }

    #[test]
    fn deregister_unknown_returns_none() {
        let state = make_state(1, 10);
        assert!(state.deregister_node(&Uuid::new_v4()).is_none());
    }

    // ── Heartbeat ──────────────────────────────────────────────────────

    #[test]
    fn heartbeat_updates_load() {
        let state = make_state(1, 10);
        let node = make_node(1);
        let id = node.id;
        state.register_node(node);

        assert!(state.heartbeat(&id, 0.5, 100, 1000.0));

        let n = state.healthy_nodes();
        assert_eq!(n.len(), 1);
        assert!((n[0].load_fraction - 0.5).abs() < 0.001);
        assert_eq!(n[0].active_connections, 100);
    }

    #[test]
    fn heartbeat_unknown_node_returns_false() {
        let state = make_state(1, 10);
        assert!(!state.heartbeat(&Uuid::new_v4(), 0.5, 0, 0.0));
    }

    #[test]
    fn heartbeat_clamps_load() {
        let state = make_state(1, 10);
        let node = make_node(1);
        let id = node.id;
        state.register_node(node);

        state.heartbeat(&id, 1.5, 0, 0.0); // Over 1.0.
        let n = state.healthy_nodes();
        assert!((n[0].load_fraction - 1.0).abs() < 0.001);

        state.heartbeat(&id, -0.5, 0, 0.0); // Below 0.0.
        let n = state.healthy_nodes();
        assert!((n[0].load_fraction - 0.0).abs() < 0.001);
    }

    // ── Heartbeat timeout ──────────────────────────────────────────────

    #[test]
    fn check_heartbeats_marks_stale() {
        let state = ClusterState::new(Duration::from_millis(1), 1, 10);
        let node = make_node(1);
        let id = node.id;
        state.register_node(node);

        std::thread::sleep(Duration::from_millis(5));
        let stale = state.check_heartbeats();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], id);

        // Node should now be Unhealthy.
        assert_eq!(state.healthy_count(), 0);
    }

    #[test]
    fn heartbeat_recovers_unhealthy_node() {
        let state = ClusterState::new(Duration::from_millis(1), 1, 10);
        let node = make_node(1);
        let id = node.id;
        state.register_node(node);

        std::thread::sleep(Duration::from_millis(5));
        state.check_heartbeats();
        assert_eq!(state.healthy_count(), 0);

        // Heartbeat recovers.
        state.heartbeat(&id, 0.1, 10, 500.0);
        assert_eq!(state.healthy_count(), 1);
    }

    // ── Drain ──────────────────────────────────────────────────────────

    #[test]
    fn drain_node_excludes_from_healthy() {
        let state = make_state(1, 10);
        let node = make_node(1);
        let id = node.id;
        state.register_node(node);

        assert_eq!(state.healthy_count(), 1);
        assert!(state.drain_node(&id));
        assert_eq!(state.healthy_count(), 0);
        // Still registered.
        assert_eq!(state.node_count(), 1);
    }

    #[test]
    fn drain_unknown_returns_false() {
        let state = make_state(1, 10);
        assert!(!state.drain_node(&Uuid::new_v4()));
    }

    // ── Aggregate stats ────────────────────────────────────────────────

    #[test]
    fn avg_and_max_load() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);

        state.heartbeat(&id1, 0.3, 0, 0.0);
        state.heartbeat(&id2, 0.7, 0, 0.0);

        assert!((state.avg_load() - 0.5).abs() < 0.001);
        assert!((state.max_load() - 0.7).abs() < 0.001);
    }

    #[test]
    fn total_rps() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);

        state.heartbeat(&id1, 0.1, 0, 500.0);
        state.heartbeat(&id2, 0.2, 0, 1500.0);

        assert!((state.total_rps() - 2000.0).abs() < 0.001);
    }

    #[test]
    fn avg_load_empty_returns_zero() {
        let state = make_state(1, 10);
        assert!((state.avg_load() - 0.0).abs() < 0.001);
    }

    // ── DNS record generation ──────────────────────────────────────────

    #[test]
    fn dns_round_robin_equal_weight() {
        let state = make_state(1, 10);
        state.register_node(make_node(1));
        state.register_node(make_node(2));
        state.register_node(make_node(3));

        let mgr = DnsRecordManager::new(60);
        let records = mgr.build_records(&state, ClusterStrategy::RoundRobin);

        assert_eq!(records.len(), 3);
        for r in &records {
            assert_eq!(r.weight, 1);
            assert_eq!(r.ttl, 60);
        }
    }

    #[test]
    fn dns_weighted_prefers_spare_capacity() {
        let state = make_state(1, 10);
        let n1 = make_node(1).with_weight(100);
        let n2 = make_node(2).with_weight(100);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);

        // n1 is heavily loaded, n2 is idle.
        state.heartbeat(&id1, 0.9, 0, 0.0);
        state.heartbeat(&id2, 0.1, 0, 0.0);

        let mgr = DnsRecordManager::new(60);
        let records = mgr.build_records(&state, ClusterStrategy::Weighted);

        let w1 = records.iter().find(|r| r.addr == ip(1)).unwrap().weight;
        let w2 = records.iter().find(|r| r.addr == ip(2)).unwrap().weight;
        assert!(w2 > w1, "idle node should get higher weight: w1={w1} w2={w2}");
    }

    #[test]
    fn dns_latency_sorts_by_load() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let n3 = make_node(3);
        let id1 = n1.id;
        let id2 = n2.id;
        let id3 = n3.id;
        state.register_node(n1);
        state.register_node(n2);
        state.register_node(n3);

        state.heartbeat(&id1, 0.8, 0, 0.0);
        state.heartbeat(&id2, 0.2, 0, 0.0);
        state.heartbeat(&id3, 0.5, 0, 0.0);

        let mgr = DnsRecordManager::new(60);
        let records = mgr.build_records(&state, ClusterStrategy::LatencyBased);

        // Lowest load should get highest weight.
        let w_low = records.iter().find(|r| r.addr == ip(2)).unwrap().weight;
        let w_high = records.iter().find(|r| r.addr == ip(1)).unwrap().weight;
        assert!(w_low > w_high, "low-load node should get highest weight");
    }

    #[test]
    fn dns_empty_cluster_returns_no_records() {
        let state = make_state(1, 10);
        let mgr = DnsRecordManager::new(60);
        let records = mgr.build_records(&state, ClusterStrategy::RoundRobin);
        assert!(records.is_empty());
    }

    #[test]
    fn dns_ttl_floor_at_10() {
        let mgr = DnsRecordManager::new(1);
        assert_eq!(mgr.ttl, 10);
    }

    // ── Geo-aware DNS ──────────────────────────────────────────────────

    #[test]
    fn dns_geo_filters_by_region() {
        let state = make_state(1, 10);
        let n1 = make_node(1).with_region("us-east-1", "us-east-1a");
        let n2 = make_node(2).with_region("eu-west-1", "eu-west-1a");
        state.register_node(n1);
        state.register_node(n2);

        let mgr = DnsRecordManager::new(60);
        let us_records = mgr.build_records_for_region(&state, "us-east-1");
        assert_eq!(us_records.len(), 1);
        assert_eq!(us_records[0].addr, ip(1));

        let eu_records = mgr.build_records_for_region(&state, "eu-west-1");
        assert_eq!(eu_records.len(), 1);
        assert_eq!(eu_records[0].addr, ip(2));
    }

    #[test]
    fn dns_geo_fallback_to_all_when_no_regional_nodes() {
        let state = make_state(1, 10);
        let n1 = make_node(1).with_region("us-east-1", "us-east-1a");
        state.register_node(n1);

        let mgr = DnsRecordManager::new(60);
        let records = mgr.build_records_for_region(&state, "ap-southeast-1");
        // Fallback to all healthy nodes.
        assert_eq!(records.len(), 1);
    }

    // ── Surge controller ───────────────────────────────────────────────

    #[test]
    fn surge_no_action_when_load_normal() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let id1 = n1.id;
        state.register_node(n1);
        state.heartbeat(&id1, 0.5, 0, 0.0);

        let mut ctrl = SurgeController::with_default_policy();
        assert_eq!(ctrl.evaluate(&state), ScaleAction::None);
    }

    #[test]
    fn surge_scale_up_after_sustained_high() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let id1 = n1.id;
        state.register_node(n1);
        state.heartbeat(&id1, 0.95, 0, 0.0); // Over 80%.

        let policy = ScalePolicy {
            scale_up_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_millis(1),
            scale_down_cooldown: Duration::from_millis(1),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);

        // First call starts the timer.
        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));

        // Second call after sustained period → ScaleUp.
        match ctrl.evaluate(&state) {
            ScaleAction::ScaleUp(n) => assert!(n >= 1),
            other => panic!("expected ScaleUp, got {other:?}"),
        }
    }

    #[test]
    fn surge_scale_down_after_sustained_low() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);
        state.heartbeat(&id1, 0.1, 0, 0.0);
        state.heartbeat(&id2, 0.1, 0, 0.0);

        let policy = ScalePolicy {
            scale_down_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_millis(1),
            scale_down_cooldown: Duration::from_millis(1),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);

        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));

        match ctrl.evaluate(&state) {
            ScaleAction::ScaleDown(n) => assert_eq!(n, 1),
            other => panic!("expected ScaleDown(1), got {other:?}"),
        }
    }

    #[test]
    fn surge_respects_min_nodes() {
        let state = make_state(2, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);
        state.heartbeat(&id1, 0.05, 0, 0.0);
        state.heartbeat(&id2, 0.05, 0, 0.0);

        let policy = ScalePolicy {
            scale_down_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_millis(1),
            scale_down_cooldown: Duration::from_millis(1),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);

        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));

        // Can't scale below min_nodes (2), so should be None.
        match ctrl.evaluate(&state) {
            ScaleAction::None => {}
            other => panic!("expected None (at min_nodes), got {other:?}"),
        }
    }

    #[test]
    fn surge_respects_max_nodes_on_scale_up() {
        let state = make_state(1, 2);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);
        state.heartbeat(&id1, 0.95, 0, 0.0);
        state.heartbeat(&id2, 0.95, 0, 0.0);

        let policy = ScalePolicy {
            scale_up_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_millis(1),
            scale_down_cooldown: Duration::from_millis(1),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);

        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));

        // Already at max_nodes (2), can't add more.
        match ctrl.evaluate(&state) {
            ScaleAction::None => {}
            ScaleAction::CooldownActive { .. } => {}
            other => panic!("expected None (at max_nodes), got {other:?}"),
        }
    }

    #[test]
    fn surge_cooldown_blocks_rapid_scaling() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let id1 = n1.id;
        state.register_node(n1);
        state.heartbeat(&id1, 0.95, 0, 0.0);

        let policy = ScalePolicy {
            scale_up_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_secs(300), // Long cooldown.
            scale_down_cooldown: Duration::from_millis(1),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);

        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));
        let first = ctrl.evaluate(&state);
        assert!(matches!(first, ScaleAction::ScaleUp(_)));

        // Immediately after → cooldown.
        match ctrl.evaluate(&state) {
            ScaleAction::CooldownActive { remaining } => {
                assert!(remaining.as_secs() > 0);
            }
            other => panic!("expected CooldownActive, got {other:?}"),
        }
    }

    // ── Prewarm estimator ──────────────────────────────────────────────

    #[test]
    fn prewarm_ema_converges() {
        let mut est = PrewarmEstimator::new(0.3, 0.2);

        // Record the same load at hour 10 several times.
        for _ in 0..10 {
            est.record(10, 1000.0);
        }

        // Prediction should be close to 1000 * 1.2 = 1200.
        let pred = est.predict(10);
        assert!(
            (pred - 1200.0).abs() < 50.0,
            "expected ~1200, got {pred}"
        );
    }

    #[test]
    fn prewarm_nodes_needed() {
        let mut est = PrewarmEstimator::new(0.5, 0.0); // No headroom.
        est.record(14, 5000.0);

        // 5000 load / 1000 capacity = 5 nodes.
        assert_eq!(est.nodes_needed(14, 1000.0), 5);
    }

    #[test]
    fn prewarm_nodes_needed_zero_capacity() {
        let est = PrewarmEstimator::new(0.5, 0.0);
        assert_eq!(est.nodes_needed(10, 0.0), 1);
    }

    #[test]
    fn prewarm_hourly_profile_24_slots() {
        let est = PrewarmEstimator::new(0.5, 0.1);
        assert_eq!(est.hourly_profile().len(), 24);
    }

    #[test]
    fn prewarm_first_sample_initializes() {
        let mut est = PrewarmEstimator::new(0.5, 0.0);
        est.record(0, 42.0);
        assert!((est.predict(0) - 42.0).abs() < 0.001);
    }

    // ── AZ capacity ────────────────────────────────────────────────────

    #[test]
    fn az_capacity_groups_by_az() {
        let state = make_state(1, 10);
        let n1 = make_node(1).with_region("us-east-1", "us-east-1a");
        let n2 = make_node(2).with_region("us-east-1", "us-east-1a");
        let n3 = make_node(3).with_region("us-east-1", "us-east-1b");
        let id1 = n1.id;
        let id2 = n2.id;
        let id3 = n3.id;
        state.register_node(n1);
        state.register_node(n2);
        state.register_node(n3);

        state.heartbeat(&id1, 0.5, 0, 100.0);
        state.heartbeat(&id2, 0.3, 0, 200.0);
        state.heartbeat(&id3, 0.4, 0, 300.0);

        let report = az_capacity_report(&state);
        assert_eq!(report.len(), 2);

        let az_a = report.iter().find(|r| r.az == "us-east-1a").unwrap();
        assert_eq!(az_a.healthy_nodes, 2);
        assert!((az_a.total_rps - 300.0).abs() < 0.001);

        let az_b = report.iter().find(|r| r.az == "us-east-1b").unwrap();
        assert_eq!(az_b.healthy_nodes, 1);
    }

    #[test]
    fn best_az_picks_lowest_load() {
        let state = make_state(1, 10);
        let n1 = make_node(1).with_region("us-east-1", "us-east-1a");
        let n2 = make_node(2).with_region("us-east-1", "us-east-1b");
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);

        state.heartbeat(&id1, 0.8, 0, 0.0);
        state.heartbeat(&id2, 0.2, 0, 0.0);

        assert_eq!(best_az_for_placement(&state).unwrap(), "us-east-1b");
    }

    // ── LCU capacity unit ──────────────────────────────────────────────

    #[test]
    fn lcu_picks_highest_dimension() {
        let cu = CapacityUnit {
            new_conns_per_sec: 50.0,    // 50/25 = 2 LCU
            active_conns_per_min: 3000.0, // 3000/3000 = 1 LCU
            bytes_per_hour: 1_073_741_824.0 * 3.0, // 3 LCU ← highest
            rule_evals_per_sec: 500.0,  // 500/1000 = 0.5 LCU
        };

        assert!((cu.lcu() - 3.0).abs() < 0.001);
        assert_eq!(cu.bottleneck_dimension(), "bandwidth");
    }

    #[test]
    fn lcu_default_zero() {
        let cu = CapacityUnit::default();
        assert!((cu.lcu() - 0.0).abs() < 0.001);
    }

    #[test]
    fn lcu_bottleneck_new_connections() {
        let cu = CapacityUnit {
            new_conns_per_sec: 100.0, // 4 LCU
            active_conns_per_min: 0.0,
            bytes_per_hour: 0.0,
            rule_evals_per_sec: 0.0,
        };
        assert_eq!(cu.bottleneck_dimension(), "new_connections");
    }

    // ── Node helpers ───────────────────────────────────────────────────

    #[test]
    fn node_availability() {
        let mut node = make_node(1);
        assert!(node.is_available()); // Healthy.

        node.health = NodeHealth::Degraded;
        assert!(node.is_available());

        node.health = NodeHealth::Unhealthy;
        assert!(!node.is_available());

        node.health = NodeHealth::Draining;
        assert!(!node.is_available());
    }

    #[test]
    fn node_with_region() {
        let node = make_node(1).with_region("us-east-1", "us-east-1a");
        assert_eq!(node.region.as_deref(), Some("us-east-1"));
        assert_eq!(node.az.as_deref(), Some("us-east-1a"));
    }

    #[test]
    fn node_with_weight() {
        let node = make_node(1).with_weight(200);
        assert_eq!(node.weight, 200);
    }

    // ── Regression: NaN/Inf load_fraction handling ─────────────────────
    // A node reporting a non-finite load_fraction (e.g. NaN from a 0.0/0.0
    // capacity computation) used to be stored unchanged because
    // `f64::clamp(NaN, 0.0, 1.0) == NaN`. That NaN then poisoned the
    // LatencyBased DNS sort and best_az_for_placement (panic via
    // partial_cmp().unwrap()) and avg_load() (stuck scale-down).

    #[test]
    fn heartbeat_sanitizes_non_finite_load_to_zero() {
        let state = make_state(1, 10);
        let node = make_node(1);
        let id = node.id;
        state.register_node(node);

        // NaN must not be stored verbatim.
        assert!(state.heartbeat(&id, f64::NAN, 0, 0.0));
        let n = state.healthy_nodes();
        assert!(n[0].load_fraction.is_finite(), "NaN load must be sanitized");
        assert!((n[0].load_fraction - 0.0).abs() < 0.001);

        // +Inf must not be stored verbatim either.
        assert!(state.heartbeat(&id, f64::INFINITY, 0, 0.0));
        let n = state.healthy_nodes();
        assert!(n[0].load_fraction.is_finite(), "Inf load must be sanitized");
    }

    #[test]
    fn dns_latency_does_not_panic_on_non_finite_load() {
        // Before the fix, the LatencyBased sort_by used partial_cmp().unwrap(),
        // which panics on a NaN operand. Even if a NaN somehow reached the
        // registry, building records must not panic.
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let n3 = make_node(3);
        let id1 = n1.id;
        let id2 = n2.id;
        let id3 = n3.id;
        state.register_node(n1);
        state.register_node(n2);
        state.register_node(n3);

        // These get sanitized at ingestion, but the comparator is also made
        // total-order-safe; either way this must not panic.
        state.heartbeat(&id1, f64::NAN, 0, 0.0);
        state.heartbeat(&id2, 0.2, 0, 0.0);
        state.heartbeat(&id3, 0.5, 0, 0.0);

        let mgr = DnsRecordManager::new(60);
        let records = mgr.build_records(&state, ClusterStrategy::LatencyBased);
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn best_az_does_not_panic_on_non_finite_load() {
        // Before the fix, min_by used partial_cmp().unwrap(), which panics when
        // an AZ's avg_load is NaN. Must return a valid AZ instead of panicking.
        let state = make_state(1, 10);
        let n1 = make_node(1).with_region("us-east-1", "us-east-1a");
        let n2 = make_node(2).with_region("us-east-1", "us-east-1b");
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);

        state.heartbeat(&id1, f64::NAN, 0, 0.0); // sanitized to 0.0
        state.heartbeat(&id2, 0.5, 0, 0.0);

        let best = best_az_for_placement(&state);
        assert!(best.is_some(), "best_az must not panic and must return an AZ");
        // Sanitized NaN -> 0.0, so az-a (0.0) is the least loaded.
        assert_eq!(best.unwrap(), "us-east-1a");
    }

    #[test]
    fn avg_load_stays_finite_with_non_finite_node() {
        // A single node reporting NaN used to make cluster-wide avg_load NaN,
        // and `NaN < scale_down_threshold` is false, silently disabling
        // scale-down forever.
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let n2 = make_node(2);
        let id1 = n1.id;
        let id2 = n2.id;
        state.register_node(n1);
        state.register_node(n2);

        state.heartbeat(&id1, f64::NAN, 0, 0.0); // sanitized to 0.0
        state.heartbeat(&id2, 0.1, 0, 0.0);

        let avg = state.avg_load();
        assert!(avg.is_finite(), "avg_load must stay finite, got {avg}");
        // (0.0 + 0.1) / 2 == 0.05
        assert!((avg - 0.05).abs() < 0.001, "expected ~0.05, got {avg}");

        // And scale-down must therefore still be reachable.
        let policy = ScalePolicy {
            scale_down_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_millis(1),
            scale_down_cooldown: Duration::from_millis(1),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);
        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));
        match ctrl.evaluate(&state) {
            ScaleAction::ScaleDown(n) => assert_eq!(n, 1),
            other => panic!("expected ScaleDown(1) despite a NaN node, got {other:?}"),
        }
    }

    // ── Regression: scale-down cooldown must NOT block emergency scale-up ─
    // Previously both cooldowns were checked up front, so a recent scale-down
    // returned CooldownActive and short-circuited the scale-up branch, ignoring
    // a high-load surge for up to scale_down_cooldown (default 300s).

    #[test]
    fn scale_down_cooldown_does_not_block_scale_up_surge() {
        let state = make_state(1, 10);
        let n1 = make_node(1);
        let id1 = n1.id;
        state.register_node(n1);
        state.heartbeat(&id1, 0.95, 0, 0.0); // surge: well over 80%

        let policy = ScalePolicy {
            scale_up_sustained: Duration::from_millis(1),
            scale_up_cooldown: Duration::from_millis(1),
            // Long scale-DOWN cooldown that must NOT interfere with scale-up.
            scale_down_cooldown: Duration::from_secs(300),
            ..Default::default()
        };
        let mut ctrl = SurgeController::new(policy);

        // Simulate a very recent scale-down event.
        ctrl.record_scale_down();

        // Start the high-load timer.
        let _ = ctrl.evaluate(&state);
        std::thread::sleep(Duration::from_millis(5));

        // Despite last_scale_down being only milliseconds ago (well within the
        // 300s scale-down cooldown), the surge must still trigger ScaleUp.
        // Before the fix this returned CooldownActive.
        match ctrl.evaluate(&state) {
            ScaleAction::ScaleUp(n) => assert!(n >= 1),
            other => panic!(
                "scale-down cooldown wrongly blocked emergency scale-up: {other:?}"
            ),
        }
    }

    // ── Regression: register_node atomicity (TOCTOU) ───────────────────
    // contains_key + insert were two separate DashMap ops, so concurrent
    // registration of the SAME fresh id could both insert (overwriting a live
    // node) and both return true. The entry API makes it a single atomic op.

    #[test]
    fn register_node_concurrent_same_id_exactly_one_wins() {
        use std::sync::Arc;

        let state = Arc::new(make_state(1, 100));
        let id = Uuid::new_v4();

        // Spawn many threads all racing to register the SAME brand-new id.
        // Each thread tags its node with a distinct weight so we can tell which
        // insert actually landed and confirm it was never overwritten by a
        // racing "duplicate" insert.
        let n_threads = 16u32;
        let mut handles = Vec::new();
        for t in 0..n_threads {
            let state = Arc::clone(&state);
            handles.push(std::thread::spawn(move || {
                let node = ClusterNode::new(id, ip(1)).with_weight(1000 + t);
                state.register_node(node)
            }));
        }

        let wins: u32 = handles
            .into_iter()
            .map(|h| if h.join().unwrap() { 1 } else { 0 })
            .sum();

        // Exactly one caller may win; all others must observe the id as present.
        assert_eq!(wins, 1, "exactly one concurrent register_node must succeed");
        assert_eq!(state.node_count(), 1, "id must be stored exactly once");

        // The single stored node must be the winner's node, untouched by any
        // racing duplicate insert.
        let stored = state.healthy_nodes();
        assert_eq!(stored.len(), 1);
        assert!(
            (1000..1000 + n_threads).contains(&stored[0].weight),
            "stored node must be a registered one, not a partial overwrite: weight={}",
            stored[0].weight
        );
    }

    #[test]
    fn register_node_duplicate_does_not_overwrite() {
        // Sequential duplicate: second register must be rejected and must not
        // overwrite the live node.
        let state = make_state(1, 10);
        let id = Uuid::new_v4();

        assert!(state.register_node(ClusterNode::new(id, ip(1)).with_weight(111)));
        assert!(!state.register_node(ClusterNode::new(id, ip(2)).with_weight(222)));

        let stored = state.all_nodes();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].weight, 111, "duplicate must not overwrite live node");
        assert_eq!(stored[0].addr, ip(1));
    }
}
