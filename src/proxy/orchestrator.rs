//! Cluster orchestrator — the control loop that ties together monitoring,
//! scaling decisions, node provisioning, and DNS record management.
//!
//! # Architecture
//!
//! ```text
//! Orchestrator Control Loop
//! ├── MetricsCollector        — Aggregates per-node metrics into cluster-wide view
//! ├── ScaleDecisionEngine     — Combines reactive (surge) + predictive signals
//! ├── NodeProvisioner         — Interface for provisioning/deprovisioning nodes
//! ├── DnsPublisher            — Interface for publishing DNS record sets
//! ├── HealthGate              — Blocks scaling until new nodes pass health checks
//! ├── DrainCoordinator        — Graceful drain before node removal
//! ├── OrchestratorConfig      — All tunable knobs in one place
//! ├── OrchestratorState       — Finite state machine for the control loop
//! └── OrchestratorMetrics     — Global AtomicU64 counters
//! ```
//!
//! # Control Loop
//!
//! Every `tick_interval`:
//! 1. **Collect** metrics from all registered nodes
//! 2. **Check** heartbeats — mark stale nodes unhealthy
//! 3. **Evaluate** scaling decision (surge + predictive)
//! 4. **Execute** scaling action (provision/drain/deregister)
//! 5. **Publish** updated DNS records
//! 6. **Report** metrics and events
//!
//! # Integration Points
//!
//! The orchestrator uses trait-based abstractions for provisioning and DNS
//! so it can integrate with any cloud provider or local setup:
//! - `NodeProvisioner`: AWS EC2, Docker, K8s, or a local process spawner
//! - `DnsPublisher`: Route53, CoreDNS, PowerDNS, or a local DNS server

use crate::proxy::cluster::{
    az_capacity_report, best_az_for_placement, ClusterNode, ClusterState, DnsRecord,
    DnsRecordManager, NodeId, ScaleAction, ScalePolicy, SurgeController,
};
use crate::proxy::predictive_scaling::{
    CooldownManager, PredictionResult, PredictionSignal, ScalingPredictor,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

static ORCHESTRATOR_ENABLED: AtomicBool = AtomicBool::new(false);
static ORCHESTRATOR_MODE: AtomicU8 = AtomicU8::new(0); // Reactive

pub fn set_orchestrator_enabled(enabled: bool) {
    ORCHESTRATOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_orchestrator_enabled() -> bool {
    ORCHESTRATOR_ENABLED.load(Ordering::Relaxed)
}

pub fn set_orchestrator_mode(mode: OrchestratorMode) {
    ORCHESTRATOR_MODE.store(mode as u8, Ordering::Relaxed);
}

pub fn get_orchestrator_mode() -> OrchestratorMode {
    OrchestratorMode::from_u8(ORCHESTRATOR_MODE.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// Orchestrator mode
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OrchestratorMode {
    /// Only reactive scaling (surge controller).
    Reactive = 0,
    /// Reactive + predictive scaling combined.
    Predictive = 1,
    /// Dry-run — compute decisions but don't execute them.
    DryRun = 2,
    /// Disabled — no scaling actions at all.
    Disabled = 3,
}

impl OrchestratorMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => OrchestratorMode::Predictive,
            2 => OrchestratorMode::DryRun,
            3 => OrchestratorMode::Disabled,
            _ => OrchestratorMode::Reactive,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "predictive" => OrchestratorMode::Predictive,
            "dry-run" | "dry_run" | "dryrun" => OrchestratorMode::DryRun,
            "disabled" | "off" => OrchestratorMode::Disabled,
            _ => OrchestratorMode::Reactive,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Provisioner and DNS publisher traits
// ═══════════════════════════════════════════════════════════════════════════

/// Abstraction for provisioning new LB nodes.
/// Implement for your cloud provider (EC2, Docker, K8s, etc.)
pub trait NodeProvisioner: Send + Sync {
    /// Provision N new nodes. Returns their IDs and IPs once healthy.
    /// `preferred_az` is a hint for placement.
    fn provision(
        &self,
        count: u32,
        preferred_az: Option<&str>,
    ) -> Result<Vec<ProvisionedNode>, ProvisionError>;

    /// Decommission a node entirely (after drain).
    fn decommission(&self, node_id: &NodeId) -> Result<(), ProvisionError>;

    /// Check if a provisioned node is ready to accept traffic.
    fn is_ready(&self, node_id: &NodeId) -> Result<bool, ProvisionError>;
}

#[derive(Debug, Clone)]
pub struct ProvisionedNode {
    pub id: NodeId,
    pub addr: std::net::IpAddr,
    pub region: Option<String>,
    pub az: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ProvisionError {
    CapacityExhausted,
    Timeout,
    CloudApiError(String),
    NotFound,
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::CapacityExhausted => write!(f, "no capacity available"),
            ProvisionError::Timeout => write!(f, "provision timed out"),
            ProvisionError::CloudApiError(msg) => write!(f, "cloud API error: {msg}"),
            ProvisionError::NotFound => write!(f, "node not found"),
        }
    }
}

/// Abstraction for publishing DNS records.
pub trait DnsPublisher: Send + Sync {
    /// Publish (upsert) the record set for the cluster's DNS name.
    fn publish(&self, domain: &str, records: &[DnsRecord]) -> Result<(), DnsPublishError>;

    /// Remove all records for the domain (emergency teardown).
    fn clear(&self, domain: &str) -> Result<(), DnsPublishError>;
}

#[derive(Debug, Clone)]
pub enum DnsPublishError {
    ApiError(String),
    RateLimited,
    InvalidDomain,
}

impl std::fmt::Display for DnsPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsPublishError::ApiError(msg) => write!(f, "DNS API error: {msg}"),
            DnsPublishError::RateLimited => write!(f, "DNS API rate limited"),
            DnsPublishError::InvalidDomain => write!(f, "invalid domain"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Orchestrator configuration
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// How often the control loop ticks.
    pub tick_interval: Duration,
    /// DNS domain to publish records for.
    pub dns_domain: String,
    /// DNS record TTL.
    pub dns_ttl: u32,
    /// How long to wait for a new node to become healthy.
    pub provision_timeout: Duration,
    /// How long to drain a node before decommissioning.
    pub drain_timeout: Duration,
    /// Scaling policy for the surge controller.
    pub scale_policy: ScalePolicy,
    /// Capacity per node (for predictive scaling node-count math).
    pub capacity_per_node: f64,
    /// Predictive scaling target metric value.
    pub target_metric: f64,
    /// Minimum nodes in the cluster.
    pub min_nodes: u32,
    /// Maximum nodes in the cluster.
    pub max_nodes: u32,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(10),
            dns_domain: "lb.lynxx.local".to_string(),
            dns_ttl: 60,
            provision_timeout: Duration::from_secs(120),
            drain_timeout: Duration::from_secs(30),
            scale_policy: ScalePolicy::default(),
            capacity_per_node: 10000.0, // 10K RPS per node.
            target_metric: 0.7,        // 70% load target.
            min_nodes: 2,
            max_nodes: 50,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Health gate — blocks traffic until new nodes pass checks
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks health check state for newly provisioned nodes.
#[derive(Debug, Clone)]
pub struct HealthGate {
    /// Number of consecutive healthy checks required.
    pub required_passes: u32,
    /// Current consecutive passes per node.
    passes: std::collections::HashMap<NodeId, u32>,
    /// Nodes that have passed the gate.
    cleared: std::collections::HashSet<NodeId>,
}

impl HealthGate {
    pub fn new(required_passes: u32) -> Self {
        Self {
            required_passes: required_passes.max(1),
            passes: std::collections::HashMap::new(),
            cleared: std::collections::HashSet::new(),
        }
    }

    /// Record a health check result. Returns true if the node just cleared the gate.
    pub fn record_check(&mut self, node_id: NodeId, healthy: bool) -> bool {
        if self.cleared.contains(&node_id) {
            return false; // Already cleared.
        }

        if healthy {
            let count = self.passes.entry(node_id).or_insert(0);
            *count += 1;
            if *count >= self.required_passes {
                self.cleared.insert(node_id);
                ORCHESTRATOR_METRICS
                    .health_gates_passed
                    .fetch_add(1, Ordering::Relaxed);
                return true;
            }
        } else {
            // Reset on any failure.
            self.passes.insert(node_id, 0);
        }
        false
    }

    /// Check if a node has cleared the health gate.
    pub fn is_cleared(&self, node_id: &NodeId) -> bool {
        self.cleared.contains(node_id)
    }

    /// How many nodes are still pending.
    pub fn pending_count(&self) -> usize {
        self.passes.len() - self.cleared.len()
    }

    /// Remove a node from tracking.
    pub fn remove(&mut self, node_id: &NodeId) {
        self.passes.remove(node_id);
        self.cleared.remove(node_id);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Drain coordinator
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks drain state for nodes being removed.
#[derive(Debug, Clone)]
pub struct DrainEntry {
    pub node_id: NodeId,
    pub started: Instant,
    pub timeout: Duration,
    /// Active connections when drain started.
    pub initial_conns: u64,
}

impl DrainEntry {
    pub fn is_expired(&self) -> bool {
        self.started.elapsed() > self.timeout
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

pub struct DrainCoordinator {
    draining: std::collections::HashMap<NodeId, DrainEntry>,
    default_timeout: Duration,
}

impl DrainCoordinator {
    pub fn new(default_timeout: Duration) -> Self {
        Self {
            draining: std::collections::HashMap::new(),
            default_timeout,
        }
    }

    /// Start draining a node. Returns false if already draining.
    pub fn start_drain(&mut self, node_id: NodeId, active_conns: u64) -> bool {
        if self.draining.contains_key(&node_id) {
            return false;
        }
        self.draining.insert(
            node_id,
            DrainEntry {
                node_id,
                started: Instant::now(),
                timeout: self.default_timeout,
                initial_conns: active_conns,
            },
        );
        ORCHESTRATOR_METRICS
            .drains_started
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Get nodes whose drain has expired (ready for decommission).
    pub fn expired_drains(&self) -> Vec<NodeId> {
        self.draining
            .values()
            .filter(|e| e.is_expired())
            .map(|e| e.node_id)
            .collect()
    }

    /// Remove a node from drain tracking (after decommission).
    pub fn complete_drain(&mut self, node_id: &NodeId) -> Option<DrainEntry> {
        let removed = self.draining.remove(node_id);
        if removed.is_some() {
            ORCHESTRATOR_METRICS
                .drains_completed
                .fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// Number of nodes currently draining.
    pub fn draining_count(&self) -> usize {
        self.draining.len()
    }

    /// Is a specific node currently draining?
    pub fn is_draining(&self, node_id: &NodeId) -> bool {
        self.draining.contains_key(node_id)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Orchestrator state machine
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorPhase {
    /// Normal operation — monitoring and scaling as needed.
    Steady,
    /// Scaling up — waiting for new nodes to provision and pass health gate.
    ScalingUp { target_count: u32 },
    /// Scaling down — draining nodes before decommission.
    ScalingDown { to_remove: u32 },
    /// Emergency — too many nodes unhealthy, alerting.
    Emergency,
}

// ═══════════════════════════════════════════════════════════════════════════
// Tick result — what happened during one control loop iteration
// ═══════════════════════════════════════════════════════════════════════════

/// Summary of one control loop tick.
#[derive(Debug, Clone)]
pub struct TickResult {
    pub phase: OrchestratorPhase,
    pub healthy_nodes: u32,
    pub total_nodes: u32,
    pub avg_load: f64,
    pub max_load: f64,
    pub scale_action: ScaleAction,
    pub prediction: Option<PredictionResult>,
    pub dns_records_published: usize,
    pub nodes_provisioned: u32,
    pub nodes_decommissioned: u32,
    pub drains_expired: u32,
    pub stale_nodes_detected: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// The Orchestrator
// ═══════════════════════════════════════════════════════════════════════════

pub struct Orchestrator {
    config: OrchestratorConfig,
    cluster: ClusterState,
    surge: SurgeController,
    predictor: ScalingPredictor,
    dns_manager: DnsRecordManager,
    health_gate: HealthGate,
    drain_coordinator: DrainCoordinator,
    cooldowns: CooldownManager,
    phase: OrchestratorPhase,
    last_tick: Option<Instant>,
    last_dns_records: Vec<DnsRecord>,
    /// Per-instance mode override. When set, takes precedence over the
    /// global `ORCHESTRATOR_MODE` atomic. This avoids race conditions in
    /// parallel tests that share the global.
    mode_override: Option<OrchestratorMode>,
}

impl Orchestrator {
    pub fn new(config: OrchestratorConfig) -> Self {
        let cluster = ClusterState::new(
            Duration::from_secs(30), // heartbeat timeout
            config.min_nodes,
            config.max_nodes,
        );
        let surge = SurgeController::new(config.scale_policy.clone());
        let predictor = ScalingPredictor::new(
            1440,                    // 24h of 1-min samples
            60,                      // 1h anomaly window
            config.capacity_per_node,
            config.target_metric,
            config.min_nodes,
            config.max_nodes,
        );
        let dns_manager = DnsRecordManager::new(config.dns_ttl);
        let health_gate = HealthGate::new(3);
        let drain_coordinator = DrainCoordinator::new(config.drain_timeout);

        Self {
            config,
            cluster,
            surge,
            predictor,
            dns_manager,
            health_gate,
            drain_coordinator,
            cooldowns: CooldownManager::new(),
            phase: OrchestratorPhase::Steady,
            last_tick: None,
            last_dns_records: Vec::new(),
            mode_override: None,
        }
    }

    /// Set a per-instance mode override (bypasses the global atomic).
    pub fn set_mode_override(&mut self, mode: OrchestratorMode) {
        self.mode_override = Some(mode);
    }

    /// Effective mode: per-instance override takes precedence over global.
    fn effective_mode(&self) -> OrchestratorMode {
        self.mode_override.unwrap_or_else(get_orchestrator_mode)
    }

    /// Register a node with the cluster.
    pub fn register_node(&self, node: ClusterNode) -> bool {
        self.cluster.register_node(node)
    }

    /// Process a heartbeat from a node.
    pub fn heartbeat(
        &self,
        node_id: &NodeId,
        load: f64,
        conns: u64,
        rps: f64,
    ) -> bool {
        self.cluster.heartbeat(node_id, load, conns, rps)
    }

    /// Run one tick of the control loop.
    /// In production this is called by a tokio::spawn timer loop.
    /// Returns a summary of what happened.
    pub fn tick(
        &mut self,
        provisioner: &dyn NodeProvisioner,
        dns_publisher: &dyn DnsPublisher,
    ) -> TickResult {
        let now = Instant::now();
        self.last_tick = Some(now);
        ORCHESTRATOR_METRICS
            .ticks_executed
            .fetch_add(1, Ordering::Relaxed);

        let mut result = TickResult {
            phase: self.phase,
            healthy_nodes: self.cluster.healthy_count() as u32,
            total_nodes: self.cluster.node_count() as u32,
            avg_load: self.cluster.avg_load(),
            max_load: self.cluster.max_load(),
            scale_action: ScaleAction::None,
            prediction: None,
            dns_records_published: 0,
            nodes_provisioned: 0,
            nodes_decommissioned: 0,
            drains_expired: 0,
            stale_nodes_detected: 0,
        };

        // ── 1. Check heartbeats ────────────────────────────────────────
        let stale = self.cluster.check_heartbeats();
        result.stale_nodes_detected = stale.len() as u32;

        // Emergency: if >50% of nodes are unhealthy, enter emergency mode.
        let healthy = self.cluster.healthy_count();
        let total = self.cluster.node_count();
        if total > 0 && healthy < (total + 1) / 2 {
            self.phase = OrchestratorPhase::Emergency;
            result.phase = self.phase;
            ORCHESTRATOR_METRICS
                .emergency_events
                .fetch_add(1, Ordering::Relaxed);
        } else if self.phase == OrchestratorPhase::Emergency && healthy >= (total + 1) / 2 {
            // Recover from emergency.
            self.phase = OrchestratorPhase::Steady;
        }

        let mode = self.effective_mode();
        if mode == OrchestratorMode::Disabled {
            return result;
        }

        // ── 2. Process expired drains ──────────────────────────────────
        let expired = self.drain_coordinator.expired_drains();
        for node_id in &expired {
            if mode != OrchestratorMode::DryRun {
                let _ = provisioner.decommission(node_id);
                self.cluster.deregister_node(node_id);
                self.health_gate.remove(node_id);
            }
            self.drain_coordinator.complete_drain(node_id);
            result.nodes_decommissioned += 1;
        }
        result.drains_expired = expired.len() as u32;

        // ── 3. Evaluate scaling decision ───────────────────────────────
        let surge_action = self.surge.evaluate(&self.cluster);

        let prediction = if mode == OrchestratorMode::Predictive {
            let unix_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Approximate hour and day_of_week from unix timestamp.
            let hour = ((unix_now / 3600) % 24) as u8;
            let day = ((unix_now / 86400 + 3) % 7) as u8; // Unix epoch was Thursday.
            let load_metric = self.cluster.avg_load() * self.config.capacity_per_node;
            Some(self.predictor.observe(
                unix_now,
                load_metric,
                day,
                hour,
                self.cluster.healthy_count() as u32,
            ))
        } else {
            None
        };

        result.prediction = prediction.clone();

        // Pick the more aggressive action between surge and predictive.
        let final_action = match (&surge_action, &prediction) {
            (ScaleAction::ScaleUp(surge_n), Some(pred))
                if pred.primary_signal != PredictionSignal::Insufficient =>
            {
                let pred_needs = pred
                    .recommended_nodes
                    .saturating_sub(self.cluster.healthy_count() as u32);
                if pred_needs > *surge_n {
                    ScaleAction::ScaleUp(pred_needs)
                } else {
                    surge_action.clone()
                }
            }
            (ScaleAction::None, Some(pred))
                if pred.primary_signal != PredictionSignal::Insufficient
                    && pred.recommended_nodes > self.cluster.healthy_count() as u32 =>
            {
                let to_add = pred
                    .recommended_nodes
                    .saturating_sub(self.cluster.healthy_count() as u32);
                ScaleAction::ScaleUp(to_add)
            }
            _ => surge_action,
        };

        result.scale_action = final_action.clone();

        // Snapshot the phase as it stood coming into the execute step (after
        // emergency/drain handling). The ScalingUp health-gate logic below
        // keys off this snapshot so that a ScalingUp transition *set* during
        // this same tick's execute step is not acted on (and clobbered) until
        // the NEXT tick — guaranteeing ScalingUp is observable for at least
        // one full tick. See the FSM-clobber fix at the idle-reset below.
        let phase_at_tick_start = self.phase;

        // ── 4. Execute scaling action ──────────────────────────────────
        if mode != OrchestratorMode::DryRun {
            match &final_action {
                ScaleAction::ScaleUp(count) => {
                    if !self.cooldowns.is_on_cooldown("scale_up") {
                        let az = best_az_for_placement(&self.cluster);
                        match provisioner.provision(*count, az.as_deref()) {
                            Ok(nodes) => {
                                for pn in &nodes {
                                    let cn = ClusterNode::new(pn.id, pn.addr)
                                        .with_region(
                                            pn.region.as_deref().unwrap_or("default"),
                                            pn.az.as_deref().unwrap_or("default"),
                                        );
                                    self.cluster.register_node(cn);
                                }
                                result.nodes_provisioned = nodes.len() as u32;
                                self.phase = OrchestratorPhase::ScalingUp {
                                    target_count: self.cluster.healthy_count() as u32,
                                };
                                self.cooldowns
                                    .record("scale_up", self.config.scale_policy.scale_up_cooldown);
                                ORCHESTRATOR_METRICS
                                    .nodes_provisioned
                                    .fetch_add(nodes.len() as u64, Ordering::Relaxed);
                            }
                            Err(_) => {
                                ORCHESTRATOR_METRICS
                                    .provision_failures
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                ScaleAction::ScaleDown(count) => {
                    if !self.cooldowns.is_on_cooldown("scale_down") {
                        // Pick the least-loaded healthy nodes to drain.
                        let mut candidates = self.cluster.healthy_nodes();
                        candidates.sort_by(|a, b| {
                            // total_cmp: a NaN load_fraction must not panic the
                            // control loop (partial_cmp returns None → unwrap
                            // panics). Matches the total_cmp ordering used
                            // elsewhere on this branch (e.g. cluster.rs).
                            a.load_fraction.total_cmp(&b.load_fraction)
                        });

                        let to_drain: Vec<_> =
                            candidates.iter().take(*count as usize).collect();

                        for node in &to_drain {
                            self.cluster.drain_node(&node.id);
                            self.drain_coordinator
                                .start_drain(node.id, node.active_connections);
                        }

                        if !to_drain.is_empty() {
                            self.phase = OrchestratorPhase::ScalingDown {
                                to_remove: to_drain.len() as u32,
                            };
                            self.cooldowns.record(
                                "scale_down",
                                self.config.scale_policy.scale_down_cooldown,
                            );
                        }
                    }
                }
                ScaleAction::CooldownActive { .. } | ScaleAction::None => {}
            }
        }

        // ── ScalingUp progression / exit ───────────────────────────────
        // BUG FIX (FSM phase clobber): previously the idle-reset below also
        // matched ScalingUp, so the phase set to ScalingUp in the execute
        // step above was reset to Steady within the SAME tick (drain count is
        // 0 on a scale-up), making ScalingUp unobservable and the target_count
        // payload dead. We now drive newly provisioned nodes through the
        // health gate and only fall back to Steady once they have passed it —
        // honouring the documented "waiting for new nodes to provision and
        // pass health gate" contract.
        //
        // We only act on a ScalingUp that was already in effect at the START
        // of this tick (phase_at_tick_start), never the one just set above, so
        // ScalingUp survives for at least one full tick before any exit.
        if let OrchestratorPhase::ScalingUp { target_count } = phase_at_tick_start {
            if mode != OrchestratorMode::DryRun {
                // Feed a readiness check for every healthy node that has not
                // yet cleared the gate. is_ready failures count as a failed
                // check, keeping the node pending until it actually comes up.
                let mut tracked_any = false;
                for node in self.cluster.healthy_nodes() {
                    tracked_any = true;
                    if self.health_gate.is_cleared(&node.id) {
                        continue;
                    }
                    let ready = provisioner.is_ready(&node.id).unwrap_or(false);
                    self.health_gate.record_check(node.id, ready);
                }
                // Exit ScalingUp once every tracked node has cleared the gate
                // and the cluster has reached the target healthy count.
                if tracked_any
                    && self.health_gate.pending_count() == 0
                    && self.cluster.healthy_count() as u32 >= target_count
                {
                    self.phase = OrchestratorPhase::Steady;
                }
            } else {
                // DryRun never provisions, so it must not get stuck waiting on
                // a health gate that will never see real nodes.
                self.phase = OrchestratorPhase::Steady;
            }
        }

        // Return to Steady if no active scaling operations.
        // NOTE: Emergency and ScalingUp are intentionally excluded — Emergency
        // clears via heartbeat recovery, and ScalingUp has its own gate-driven
        // exit above. Without the ScalingUp exclusion this block would clobber
        // the ScalingUp phase in the same tick it was entered (the bug above).
        if self.drain_coordinator.draining_count() == 0
            && !matches!(
                self.phase,
                OrchestratorPhase::Emergency | OrchestratorPhase::ScalingUp { .. }
            )
        {
            self.phase = OrchestratorPhase::Steady;
        }
        result.phase = self.phase;

        // ── 5. Publish DNS records ─────────────────────────────────────
        let strategy = crate::proxy::cluster::get_cluster_strategy();
        let records = self.dns_manager.build_records(&self.cluster, strategy);

        if records != self.last_dns_records && !records.is_empty() {
            if mode != OrchestratorMode::DryRun {
                let _ = dns_publisher.publish(&self.config.dns_domain, &records);
            }
            result.dns_records_published = records.len();
            ORCHESTRATOR_METRICS
                .dns_publishes
                .fetch_add(1, Ordering::Relaxed);
            self.last_dns_records = records;
        }

        result
    }

    // ── Accessors ──────────────────────────────────────────────────────

    pub fn phase(&self) -> OrchestratorPhase {
        self.phase
    }

    pub fn cluster(&self) -> &ClusterState {
        &self.cluster
    }

    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }

    pub fn health_gate(&self) -> &HealthGate {
        &self.health_gate
    }

    pub fn drain_coordinator(&self) -> &DrainCoordinator {
        &self.drain_coordinator
    }

    pub fn health_gate_mut(&mut self) -> &mut HealthGate {
        &mut self.health_gate
    }

    pub fn az_report(&self) -> Vec<crate::proxy::cluster::AzCapacity> {
        az_capacity_report(&self.cluster)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct OrchestratorMetrics {
    pub ticks_executed: AtomicU64,
    pub nodes_provisioned: AtomicU64,
    pub provision_failures: AtomicU64,
    pub drains_started: AtomicU64,
    pub drains_completed: AtomicU64,
    pub health_gates_passed: AtomicU64,
    pub dns_publishes: AtomicU64,
    pub emergency_events: AtomicU64,
}

static ORCHESTRATOR_METRICS: OrchestratorMetrics = OrchestratorMetrics {
    ticks_executed: AtomicU64::new(0),
    nodes_provisioned: AtomicU64::new(0),
    provision_failures: AtomicU64::new(0),
    drains_started: AtomicU64::new(0),
    drains_completed: AtomicU64::new(0),
    health_gates_passed: AtomicU64::new(0),
    dns_publishes: AtomicU64::new(0),
    emergency_events: AtomicU64::new(0),
};

pub fn orchestrator_metrics() -> &'static OrchestratorMetrics {
    &ORCHESTRATOR_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    // ── Mock provisioner ───────────────────────────────────────────────

    struct MockProvisioner {
        next_ip: Mutex<u8>,
        decommissioned: Mutex<Vec<NodeId>>,
        should_fail: bool,
    }

    impl MockProvisioner {
        fn new() -> Self {
            Self {
                next_ip: Mutex::new(100),
                decommissioned: Mutex::new(Vec::new()),
                should_fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                next_ip: Mutex::new(100),
                decommissioned: Mutex::new(Vec::new()),
                should_fail: true,
            }
        }
    }

    impl NodeProvisioner for MockProvisioner {
        fn provision(
            &self,
            count: u32,
            _preferred_az: Option<&str>,
        ) -> Result<Vec<ProvisionedNode>, ProvisionError> {
            if self.should_fail {
                return Err(ProvisionError::CapacityExhausted);
            }
            let mut nodes = Vec::new();
            let mut next = self.next_ip.lock().unwrap();
            for _ in 0..count {
                nodes.push(ProvisionedNode {
                    id: Uuid::new_v4(),
                    addr: ip(*next),
                    region: Some("us-east-1".to_string()),
                    az: Some("us-east-1a".to_string()),
                });
                *next += 1;
            }
            Ok(nodes)
        }

        fn decommission(&self, node_id: &NodeId) -> Result<(), ProvisionError> {
            self.decommissioned.lock().unwrap().push(*node_id);
            Ok(())
        }

        fn is_ready(&self, _node_id: &NodeId) -> Result<bool, ProvisionError> {
            Ok(true)
        }
    }

    // ── Mock DNS publisher ─────────────────────────────────────────────

    struct MockDnsPublisher {
        published: Mutex<Vec<(String, Vec<DnsRecord>)>>,
    }

    impl MockDnsPublisher {
        fn new() -> Self {
            Self {
                published: Mutex::new(Vec::new()),
            }
        }
    }

    impl DnsPublisher for MockDnsPublisher {
        fn publish(&self, domain: &str, records: &[DnsRecord]) -> Result<(), DnsPublishError> {
            self.published
                .lock()
                .unwrap()
                .push((domain.to_string(), records.to_vec()));
            Ok(())
        }

        fn clear(&self, _domain: &str) -> Result<(), DnsPublishError> {
            Ok(())
        }
    }

    fn test_config() -> OrchestratorConfig {
        OrchestratorConfig {
            tick_interval: Duration::from_millis(100),
            scale_policy: ScalePolicy {
                scale_up_sustained: Duration::from_millis(1),
                scale_down_sustained: Duration::from_millis(1),
                scale_up_cooldown: Duration::from_millis(1),
                scale_down_cooldown: Duration::from_millis(1),
                ..Default::default()
            },
            min_nodes: 1,
            max_nodes: 20,
            ..Default::default()
        }
    }

    // ── Mode enum ──────────────────────────────────────────────────────

    #[test]
    fn mode_from_u8_roundtrip() {
        assert_eq!(OrchestratorMode::from_u8(0), OrchestratorMode::Reactive);
        assert_eq!(OrchestratorMode::from_u8(1), OrchestratorMode::Predictive);
        assert_eq!(OrchestratorMode::from_u8(2), OrchestratorMode::DryRun);
        assert_eq!(OrchestratorMode::from_u8(3), OrchestratorMode::Disabled);
        assert_eq!(OrchestratorMode::from_u8(99), OrchestratorMode::Reactive);
    }

    #[test]
    fn mode_from_str() {
        assert_eq!(OrchestratorMode::from_str("predictive"), OrchestratorMode::Predictive);
        assert_eq!(OrchestratorMode::from_str("dry-run"), OrchestratorMode::DryRun);
        assert_eq!(OrchestratorMode::from_str("disabled"), OrchestratorMode::Disabled);
        assert_eq!(OrchestratorMode::from_str("unknown"), OrchestratorMode::Reactive);
    }

    // ── Global toggle ──────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_orchestrator_enabled(true);
        assert!(is_orchestrator_enabled());
    }

    #[test]
    fn global_mode_switch() {
        set_orchestrator_mode(OrchestratorMode::DryRun);
        assert_eq!(get_orchestrator_mode(), OrchestratorMode::DryRun);
        set_orchestrator_mode(OrchestratorMode::Reactive);
    }

    // ── Health gate ────────────────────────────────────────────────────

    #[test]
    fn health_gate_requires_consecutive_passes() {
        let mut gate = HealthGate::new(3);
        let id = Uuid::new_v4();

        assert!(!gate.record_check(id, true));  // 1/3
        assert!(!gate.record_check(id, true));  // 2/3
        assert!(gate.record_check(id, true));   // 3/3 → cleared!

        assert!(gate.is_cleared(&id));
    }

    #[test]
    fn health_gate_resets_on_failure() {
        let mut gate = HealthGate::new(3);
        let id = Uuid::new_v4();

        gate.record_check(id, true);  // 1/3
        gate.record_check(id, true);  // 2/3
        gate.record_check(id, false); // Reset!
        assert!(!gate.record_check(id, true)); // 1/3 again
    }

    #[test]
    fn health_gate_already_cleared_returns_false() {
        let mut gate = HealthGate::new(1);
        let id = Uuid::new_v4();

        assert!(gate.record_check(id, true)); // Cleared.
        assert!(!gate.record_check(id, true)); // Already cleared.
    }

    #[test]
    fn health_gate_remove() {
        let mut gate = HealthGate::new(1);
        let id = Uuid::new_v4();
        gate.record_check(id, true);
        assert!(gate.is_cleared(&id));

        gate.remove(&id);
        assert!(!gate.is_cleared(&id));
    }

    // ── Drain coordinator ──────────────────────────────────────────────

    #[test]
    fn drain_start_and_expire() {
        let mut dc = DrainCoordinator::new(Duration::from_millis(1));
        let id = Uuid::new_v4();

        assert!(dc.start_drain(id, 100));
        assert!(dc.is_draining(&id));
        assert_eq!(dc.draining_count(), 1);

        // Duplicate returns false.
        assert!(!dc.start_drain(id, 100));

        std::thread::sleep(Duration::from_millis(5));
        let expired = dc.expired_drains();
        assert_eq!(expired.len(), 1);

        dc.complete_drain(&id);
        assert_eq!(dc.draining_count(), 0);
    }

    #[test]
    fn drain_not_expired_yet() {
        let mut dc = DrainCoordinator::new(Duration::from_secs(300));
        let id = Uuid::new_v4();
        dc.start_drain(id, 50);

        let expired = dc.expired_drains();
        assert!(expired.is_empty());
    }

    // ── Orchestrator steady state ──────────────────────────────────────

    #[test]
    fn orchestrator_steady_state_tick() {
        set_orchestrator_mode(OrchestratorMode::Reactive);
        let mut orch = Orchestrator::new(test_config());
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        // Register 2 healthy nodes at moderate load.
        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let n2 = ClusterNode::new(Uuid::new_v4(), ip(2));
        let id1 = n1.id;
        let id2 = n2.id;
        orch.register_node(n1);
        orch.register_node(n2);
        orch.heartbeat(&id1, 0.5, 100, 1000.0);
        orch.heartbeat(&id2, 0.4, 80, 800.0);

        let result = orch.tick(&prov, &dns);

        assert_eq!(result.healthy_nodes, 2);
        assert_eq!(result.total_nodes, 2);
        assert!((result.avg_load - 0.45).abs() < 0.01);
        assert_eq!(result.phase, OrchestratorPhase::Steady);
    }

    // ── Orchestrator scale-up ──────────────────────────────────────────

    #[test]
    fn orchestrator_scales_up_on_high_load() {
        set_orchestrator_mode(OrchestratorMode::Reactive);
        let mut orch = Orchestrator::new(test_config());
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.heartbeat(&id1, 0.95, 500, 5000.0);

        // First tick starts the timer.
        let _ = orch.tick(&prov, &dns);
        std::thread::sleep(Duration::from_millis(5));

        // Second tick triggers scale-up.
        let result = orch.tick(&prov, &dns);

        assert!(result.nodes_provisioned > 0 || matches!(result.scale_action, ScaleAction::ScaleUp(_)));
    }

    // ── Orchestrator ScalingUp phase visibility (regression) ───────────

    /// Regression for the FSM phase-clobber bug: on the tick that provisions
    /// nodes the orchestrator must REPORT `ScalingUp`. Before the fix the
    /// idle-reset matched ScalingUp and reset the phase to Steady within the
    /// same tick (drain count is 0 on a scale-up), so this assertion failed.
    #[test]
    fn orchestrator_reports_scaling_up_phase_on_provision_tick() {
        let mut orch = Orchestrator::new(test_config());
        orch.set_mode_override(OrchestratorMode::Reactive);
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.heartbeat(&id1, 0.95, 500, 5000.0);

        // First tick arms the sustained-high-load timer.
        let _ = orch.tick(&prov, &dns);
        std::thread::sleep(Duration::from_millis(5));

        // Second tick provisions — and must surface ScalingUp, not Steady.
        let result = orch.tick(&prov, &dns);

        assert!(result.nodes_provisioned > 0, "expected a scale-up to occur");
        assert!(
            matches!(result.phase, OrchestratorPhase::ScalingUp { .. }),
            "provision tick must report ScalingUp, got {:?}",
            result.phase
        );
        assert!(
            matches!(orch.phase(), OrchestratorPhase::ScalingUp { .. }),
            "orchestrator must remain in ScalingUp after provisioning"
        );
    }

    /// Once provisioned nodes pass the health gate the orchestrator must leave
    /// ScalingUp and return to Steady (the documented exit), rather than either
    /// staying stuck in ScalingUp forever or being clobbered to Steady on the
    /// provision tick.
    #[test]
    fn orchestrator_scaling_up_exits_to_steady_after_health_gate() {
        // Long scale-up cooldown so we provision exactly once and the following
        // ticks just drive the health gate instead of re-provisioning.
        let config = OrchestratorConfig {
            scale_policy: ScalePolicy {
                scale_up_sustained: Duration::from_millis(1),
                scale_up_cooldown: Duration::from_secs(60),
                scale_down_sustained: Duration::from_millis(1),
                scale_down_cooldown: Duration::from_secs(60),
                ..Default::default()
            },
            min_nodes: 1,
            max_nodes: 20,
            ..test_config()
        };
        let mut orch = Orchestrator::new(config);
        orch.set_mode_override(OrchestratorMode::Reactive);
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.heartbeat(&id1, 0.95, 500, 5000.0);

        // Arm + provision.
        let _ = orch.tick(&prov, &dns);
        std::thread::sleep(Duration::from_millis(5));
        let provision_result = orch.tick(&prov, &dns);
        assert!(provision_result.nodes_provisioned > 0);
        assert!(
            matches!(provision_result.phase, OrchestratorPhase::ScalingUp { .. }),
            "must enter ScalingUp on provision"
        );

        // Subsequent ticks drive the (mock-ready) nodes through the gate. The
        // gate needs `required_passes` (3) passes, so allow a small budget.
        let mut reached_steady = false;
        for _ in 0..6 {
            let r = orch.tick(&prov, &dns);
            if r.phase == OrchestratorPhase::Steady {
                reached_steady = true;
                break;
            }
            // Until it clears, it must stay in ScalingUp (no re-provision, no
            // spurious Steady), never anything else.
            assert!(
                matches!(r.phase, OrchestratorPhase::ScalingUp { .. }),
                "should stay ScalingUp until health gate clears, got {:?}",
                r.phase
            );
            // Cooldown holds — no extra provisioning while waiting.
            assert_eq!(r.nodes_provisioned, 0, "should not re-provision during cooldown");
        }
        assert!(
            reached_steady,
            "ScalingUp must exit to Steady once provisioned nodes pass the health gate"
        );
        assert_eq!(orch.phase(), OrchestratorPhase::Steady);
    }

    // ── Orchestrator scale-down ────────────────────────────────────────

    #[test]
    fn orchestrator_scales_down_on_low_load() {
        set_orchestrator_mode(OrchestratorMode::Reactive);
        let mut orch = Orchestrator::new(test_config());
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let n2 = ClusterNode::new(Uuid::new_v4(), ip(2));
        let n3 = ClusterNode::new(Uuid::new_v4(), ip(3));
        let id1 = n1.id;
        let id2 = n2.id;
        let id3 = n3.id;
        orch.register_node(n1);
        orch.register_node(n2);
        orch.register_node(n3);
        orch.heartbeat(&id1, 0.1, 10, 100.0);
        orch.heartbeat(&id2, 0.1, 10, 100.0);
        orch.heartbeat(&id3, 0.1, 10, 100.0);

        let _ = orch.tick(&prov, &dns);
        std::thread::sleep(Duration::from_millis(5));

        let result = orch.tick(&prov, &dns);

        assert!(
            matches!(result.scale_action, ScaleAction::ScaleDown(_))
                || orch.drain_coordinator().draining_count() > 0,
        );
    }

    // ── Orchestrator dry-run ───────────────────────────────────────────

    #[test]
    fn orchestrator_dry_run_no_provisioning() {
        // Use per-instance mode override to avoid global state races.
        let mut orch = Orchestrator::new(test_config());
        orch.set_mode_override(OrchestratorMode::DryRun);
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.heartbeat(&id1, 0.95, 500, 5000.0);

        let _ = orch.tick(&prov, &dns);
        std::thread::sleep(Duration::from_millis(5));
        let result = orch.tick(&prov, &dns);

        // In DryRun mode, DNS must not be published.
        assert!(
            dns.published.lock().unwrap().is_empty(),
            "dry-run should not publish DNS records"
        );
        // No nodes should be provisioned.
        assert_eq!(result.nodes_provisioned, 0);
        // Provisioner should not have been called for decommission.
        assert!(
            prov.decommissioned.lock().unwrap().is_empty(),
            "dry-run should not decommission nodes"
        );
    }

    // ── Orchestrator disabled ──────────────────────────────────────────

    #[test]
    fn orchestrator_disabled_skips_everything() {
        let mut orch = Orchestrator::new(test_config());
        orch.set_mode_override(OrchestratorMode::Disabled);
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let result = orch.tick(&prov, &dns);
        assert_eq!(result.nodes_provisioned, 0);
        assert_eq!(result.dns_records_published, 0);
    }

    // ── Orchestrator DNS publishing ────────────────────────────────────

    #[test]
    fn orchestrator_publishes_dns_on_change() {
        set_orchestrator_mode(OrchestratorMode::Reactive);
        let mut orch = Orchestrator::new(test_config());
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.heartbeat(&id1, 0.5, 100, 1000.0);

        let result = orch.tick(&prov, &dns);
        assert!(result.dns_records_published > 0);

        // Second tick with same state → no publish.
        let result2 = orch.tick(&prov, &dns);
        assert_eq!(result2.dns_records_published, 0);
    }

    // ── Orchestrator emergency ─────────────────────────────────────────

    #[test]
    fn orchestrator_emergency_on_majority_unhealthy() {
        set_orchestrator_mode(OrchestratorMode::Reactive);
        let config = OrchestratorConfig {
            min_nodes: 1,
            max_nodes: 20,
            ..test_config()
        };
        let mut orch = Orchestrator::new(config);
        let prov = MockProvisioner::new();
        let dns = MockDnsPublisher::new();

        // Register 3 nodes, make 2 of them stale.
        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let n2 = ClusterNode::new(Uuid::new_v4(), ip(2));
        let n3 = ClusterNode::new(Uuid::new_v4(), ip(3));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.register_node(n2);
        orch.register_node(n3);

        // Only heartbeat n1 — n2, n3 will time out.
        // We need a very short heartbeat timeout for this test.
        // Since ClusterState is built in the constructor with 30s timeout,
        // we manually set health to Unhealthy instead.
        orch.heartbeat(&id1, 0.5, 100, 1000.0);
        {
            // Manually mark n2, n3 unhealthy to avoid waiting.
            let nodes = orch.cluster().all_nodes();
            for n in nodes {
                if n.id != id1 {
                    orch.cluster.drain_node(&n.id); // Not exactly unhealthy, but excludes from healthy_count.
                }
            }
        }

        let result = orch.tick(&prov, &dns);
        // 1 healthy out of 3 → emergency.
        assert_eq!(result.phase, OrchestratorPhase::Emergency);
    }

    // ── Orchestrator provision failure ──────────────────────────────────

    #[test]
    fn orchestrator_handles_provision_failure() {
        set_orchestrator_mode(OrchestratorMode::Reactive);
        let mut orch = Orchestrator::new(test_config());
        let prov = MockProvisioner::failing();
        let dns = MockDnsPublisher::new();

        let n1 = ClusterNode::new(Uuid::new_v4(), ip(1));
        let id1 = n1.id;
        orch.register_node(n1);
        orch.heartbeat(&id1, 0.95, 500, 5000.0);

        let _ = orch.tick(&prov, &dns);
        std::thread::sleep(Duration::from_millis(5));
        let result = orch.tick(&prov, &dns);

        // Provisioning failed → no new nodes.
        assert_eq!(result.nodes_provisioned, 0);
    }

    // ── Provision error display ────────────────────────────────────────

    #[test]
    fn provision_error_display() {
        assert_eq!(format!("{}", ProvisionError::CapacityExhausted), "no capacity available");
        assert_eq!(format!("{}", ProvisionError::Timeout), "provision timed out");
        assert_eq!(format!("{}", ProvisionError::NotFound), "node not found");
    }

    #[test]
    fn dns_publish_error_display() {
        assert_eq!(format!("{}", DnsPublishError::RateLimited), "DNS API rate limited");
        assert_eq!(format!("{}", DnsPublishError::InvalidDomain), "invalid domain");
    }
}
