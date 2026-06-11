//! Advanced deployment strategies — blue/green, canary, and rolling deploys
//! with health-gated promotion and automatic rollback.
//!
//! # Architecture
//!
//! ```text
//! Auto Deploy
//! ├── DeployStrategy         — BlueGreen / Canary / Rolling
//! ├── DeployPlan             — Concrete plan: what to deploy, how, when
//! ├── DeployExecutor         — State machine that drives the deploy lifecycle
//! ├── CanaryAnalyzer         — Compares canary vs baseline error/latency metrics
//! ├── RollbackTrigger        — Automatic rollback conditions
//! ├── TrafficShifter         — Gradual weight shifting for canary/rolling
//! ├── DeployHook             — Pre/post deploy webhook notifications
//! ├── DeployHistory          — Audit log of all deploys
//! └── AutoDeployMetrics      — Global AtomicU64 counters
//! ```
//!
//! # Strategies
//!
//! **Blue/Green**: Deploy the new version alongside the old, health-check it,
//! then atomically switch all traffic. Zero-downtime, instant rollback.
//!
//! **Canary**: Shift a small percentage of traffic (e.g. 5%) to the new version,
//! monitor error rate and latency, then gradually increase to 100%. Automatic
//! rollback if canary metrics degrade.
//!
//! **Rolling**: Replace nodes one at a time (or in batches), waiting for each
//! batch to become healthy before proceeding. `max_unavailable` controls how
//! many can be down simultaneously.

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

static AUTO_DEPLOY_ENABLED: AtomicBool = AtomicBool::new(false);
static DEFAULT_STRATEGY: AtomicU8 = AtomicU8::new(0); // BlueGreen

pub fn set_auto_deploy_enabled(enabled: bool) {
    AUTO_DEPLOY_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_auto_deploy_enabled() -> bool {
    AUTO_DEPLOY_ENABLED.load(Ordering::Relaxed)
}

pub fn set_default_strategy(strategy: DeployStrategy) {
    DEFAULT_STRATEGY.store(strategy as u8, Ordering::Relaxed);
}

pub fn get_default_strategy() -> DeployStrategy {
    DeployStrategy::from_u8(DEFAULT_STRATEGY.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// Deploy strategy enum
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeployStrategy {
    /// Deploy new version alongside old, health-check, atomic switch.
    BlueGreen = 0,
    /// Gradual traffic shift with metric-gated promotion.
    Canary = 1,
    /// Replace nodes in batches with health-gated progression.
    Rolling = 2,
}

impl DeployStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => DeployStrategy::Canary,
            2 => DeployStrategy::Rolling,
            _ => DeployStrategy::BlueGreen,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "canary" => DeployStrategy::Canary,
            "rolling" => DeployStrategy::Rolling,
            "blue-green" | "blue_green" | "bluegreen" => DeployStrategy::BlueGreen,
            _ => DeployStrategy::BlueGreen,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Deploy plan — what to deploy
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct DeployPlan {
    pub id: Uuid,
    pub service_id: Uuid,
    pub strategy: DeployStrategy,
    pub new_version: String,
    pub old_version: String,
    pub new_target_urls: Vec<String>,
    pub old_target_ids: Vec<Uuid>,
    /// For canary: starting traffic percentage.
    pub canary_initial_pct: u8,
    /// For canary: increment per step.
    pub canary_step_pct: u8,
    /// For canary: time between each step.
    pub canary_step_interval: Duration,
    /// For rolling: max nodes unavailable simultaneously.
    pub max_unavailable: u32,
    /// For rolling: batch size.
    pub batch_size: u32,
    /// Health check requirements.
    pub health_check_path: String,
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
    pub health_check_threshold: u32,
    /// Automatic rollback conditions.
    pub rollback_on_error_rate: f64,
    pub rollback_on_latency_ms: u64,
    /// Maximum deploy duration before auto-abort.
    pub deploy_timeout: Duration,
    /// Webhook for notifications.
    pub webhook_url: Option<String>,
}

impl DeployPlan {
    pub fn blue_green(
        service_id: Uuid,
        new_version: &str,
        old_version: &str,
        new_target_urls: Vec<String>,
        old_target_ids: Vec<Uuid>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            service_id,
            strategy: DeployStrategy::BlueGreen,
            new_version: new_version.to_string(),
            old_version: old_version.to_string(),
            new_target_urls,
            old_target_ids,
            canary_initial_pct: 0,
            canary_step_pct: 0,
            canary_step_interval: Duration::ZERO,
            max_unavailable: 0,
            batch_size: 0,
            health_check_path: "/health".to_string(),
            health_check_interval: Duration::from_secs(2),
            health_check_timeout: Duration::from_secs(3),
            health_check_threshold: 3,
            rollback_on_error_rate: 0.05, // 5%
            rollback_on_latency_ms: 5000,
            deploy_timeout: Duration::from_secs(600),
            webhook_url: None,
        }
    }

    pub fn canary(
        service_id: Uuid,
        new_version: &str,
        old_version: &str,
        new_target_urls: Vec<String>,
        old_target_ids: Vec<Uuid>,
        initial_pct: u8,
        step_pct: u8,
        step_interval: Duration,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            service_id,
            strategy: DeployStrategy::Canary,
            new_version: new_version.to_string(),
            old_version: old_version.to_string(),
            new_target_urls,
            old_target_ids,
            canary_initial_pct: initial_pct.clamp(1, 100),
            canary_step_pct: step_pct.clamp(1, 100),
            canary_step_interval: step_interval,
            max_unavailable: 0,
            batch_size: 0,
            health_check_path: "/health".to_string(),
            health_check_interval: Duration::from_secs(2),
            health_check_timeout: Duration::from_secs(3),
            health_check_threshold: 3,
            rollback_on_error_rate: 0.05,
            rollback_on_latency_ms: 5000,
            deploy_timeout: Duration::from_secs(1800),
            webhook_url: None,
        }
    }

    pub fn rolling(
        service_id: Uuid,
        new_version: &str,
        old_version: &str,
        new_target_urls: Vec<String>,
        old_target_ids: Vec<Uuid>,
        batch_size: u32,
        max_unavailable: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            service_id,
            strategy: DeployStrategy::Rolling,
            new_version: new_version.to_string(),
            old_version: old_version.to_string(),
            new_target_urls,
            old_target_ids,
            canary_initial_pct: 0,
            canary_step_pct: 0,
            canary_step_interval: Duration::ZERO,
            max_unavailable: max_unavailable.max(1),
            batch_size: batch_size.max(1),
            health_check_path: "/health".to_string(),
            health_check_interval: Duration::from_secs(2),
            health_check_timeout: Duration::from_secs(3),
            health_check_threshold: 3,
            rollback_on_error_rate: 0.05,
            rollback_on_latency_ms: 5000,
            deploy_timeout: Duration::from_secs(1200),
            webhook_url: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Deploy lifecycle state machine
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployPhase {
    /// Validating the deploy plan.
    Validating,
    /// Provisioning new targets (for blue/green or first canary batch).
    Provisioning,
    /// Running health checks on new targets.
    HealthChecking,
    /// Shifting traffic (canary: gradual, blue/green: atomic).
    TrafficShifting,
    /// Monitoring metrics after traffic shift (canary bake time).
    Monitoring,
    /// Deploy successful — draining old targets.
    Draining,
    /// Deploy complete.
    Complete,
    /// Deploy failed — rolling back.
    RollingBack,
    /// Rollback complete.
    RolledBack,
    /// Deploy timed out.
    TimedOut,
}

// ═══════════════════════════════════════════════════════════════════════════
// Traffic shifter — gradual weight management
// ═══════════════════════════════════════════════════════════════════════════

/// Manages traffic weight distribution between old and new targets.
pub struct TrafficShifter {
    /// Current percentage of traffic going to new targets [0, 100].
    new_pct: u8,
    /// Target percentage (final state).
    target_pct: u8,
    /// Step size per increment.
    step_pct: u8,
    /// Time of last step.
    last_step: Option<Instant>,
    /// Minimum interval between steps.
    step_interval: Duration,
}

impl TrafficShifter {
    pub fn new(initial_pct: u8, step_pct: u8, step_interval: Duration) -> Self {
        Self {
            new_pct: initial_pct.min(100),
            target_pct: 100,
            // BUG FIX: a step_pct > 100 was previously accepted here (only
            // `.max(1)` was applied), which could overflow the u8 add in
            // `step()`. Clamp to the [1, 100] range — mirroring the canary
            // constructor — so the percentage step can never exceed 100.
            step_pct: step_pct.clamp(1, 100),
            last_step: None,
            step_interval,
        }
    }

    /// Atomic switch — set new traffic to 100% immediately.
    pub fn atomic_switch() -> Self {
        Self {
            new_pct: 100,
            target_pct: 100,
            step_pct: 100,
            last_step: None,
            step_interval: Duration::ZERO,
        }
    }

    /// Try to advance one step. Returns true if traffic was shifted.
    pub fn step(&mut self) -> bool {
        if self.new_pct >= self.target_pct {
            return false;
        }
        if let Some(last) = self.last_step {
            if last.elapsed() < self.step_interval {
                return false; // Too soon.
            }
        }
        // BUG FIX: `new_pct + step_pct` overflowed u8 when step_pct was large
        // (e.g. 255), panicking under overflow-checks and silently wrapping in
        // release (causing non-monotonic traffic regression like 99 -> 98).
        // Widen to u16 for the add+min, then narrow back; the result is always
        // <= target_pct <= 100 so the final cast is lossless.
        self.new_pct =
            ((self.new_pct as u16 + self.step_pct as u16).min(self.target_pct as u16)) as u8;
        self.last_step = Some(Instant::now());
        true
    }

    /// Rollback — set new traffic to 0%.
    pub fn rollback(&mut self) {
        self.new_pct = 0;
        self.target_pct = 0;
    }

    pub fn new_pct(&self) -> u8 {
        self.new_pct
    }

    pub fn old_pct(&self) -> u8 {
        100 - self.new_pct
    }

    pub fn is_complete(&self) -> bool {
        self.new_pct >= self.target_pct
    }

    /// Compute weight for the old target group.
    pub fn old_weight(&self, base_weight: u32) -> u32 {
        ((base_weight as f64 * self.old_pct() as f64) / 100.0).round() as u32
    }

    /// Compute weight for the new target group.
    pub fn new_weight(&self, base_weight: u32) -> u32 {
        ((base_weight as f64 * self.new_pct() as f64) / 100.0).round() as u32
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Canary analyzer — metric comparison
// ═══════════════════════════════════════════════════════════════════════════

/// Metrics snapshot for comparison between canary and baseline.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub error_rate: f64,        // 0.0-1.0
    pub p50_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub rps: f64,
    pub timestamp: Instant,
}

impl MetricsSnapshot {
    pub fn new(error_rate: f64, p50: f64, p99: f64, rps: f64) -> Self {
        Self {
            error_rate: error_rate.clamp(0.0, 1.0),
            p50_latency_ms: p50,
            p99_latency_ms: p99,
            rps,
            timestamp: Instant::now(),
        }
    }
}

/// Canary analysis result.
#[derive(Debug, Clone, PartialEq)]
pub enum CanaryVerdict {
    /// Canary looks good — safe to promote.
    Healthy,
    /// Canary metrics are degraded but within tolerance.
    Degraded { reason: String },
    /// Canary is failing — trigger rollback.
    Failing { reason: String },
    /// Not enough data yet — keep monitoring.
    Insufficient,
}

pub struct CanaryAnalyzer {
    /// Maximum acceptable error rate increase over baseline (absolute delta).
    max_error_delta: f64,
    /// Maximum acceptable latency increase over baseline (multiplier).
    max_latency_multiplier: f64,
    /// Minimum observation duration before making a verdict.
    min_observation: Duration,
    /// Baseline metrics.
    baseline: Option<MetricsSnapshot>,
    /// Canary metrics.
    canary: Option<MetricsSnapshot>,
    /// When observation started.
    started: Instant,
}

impl CanaryAnalyzer {
    pub fn new(max_error_delta: f64, max_latency_multiplier: f64, min_observation: Duration) -> Self {
        Self {
            max_error_delta: max_error_delta.clamp(0.001, 1.0),
            max_latency_multiplier: max_latency_multiplier.max(1.0),
            min_observation,
            baseline: None,
            canary: None,
            started: Instant::now(),
        }
    }

    /// Update baseline metrics.
    pub fn update_baseline(&mut self, snapshot: MetricsSnapshot) {
        self.baseline = Some(snapshot);
    }

    /// Update canary metrics.
    pub fn update_canary(&mut self, snapshot: MetricsSnapshot) {
        self.canary = Some(snapshot);
    }

    /// Analyze canary vs baseline and produce a verdict.
    pub fn analyze(&self) -> CanaryVerdict {
        let (baseline, canary) = match (&self.baseline, &self.canary) {
            (Some(b), Some(c)) => (b, c),
            _ => return CanaryVerdict::Insufficient,
        };

        if self.started.elapsed() < self.min_observation {
            return CanaryVerdict::Insufficient;
        }

        // ── Error rate check ───────────────────────────────────────────
        let error_delta = canary.error_rate - baseline.error_rate;
        if error_delta > self.max_error_delta {
            AUTO_DEPLOY_METRICS
                .canary_failures
                .fetch_add(1, Ordering::Relaxed);
            return CanaryVerdict::Failing {
                reason: format!(
                    "error rate +{:.2}% over baseline (threshold: +{:.2}%)",
                    error_delta * 100.0,
                    self.max_error_delta * 100.0,
                ),
            };
        }

        // ── Latency check ──────────────────────────────────────────────
        if baseline.p99_latency_ms > 0.0 {
            let latency_ratio = canary.p99_latency_ms / baseline.p99_latency_ms;
            if latency_ratio > self.max_latency_multiplier {
                AUTO_DEPLOY_METRICS
                    .canary_failures
                    .fetch_add(1, Ordering::Relaxed);
                return CanaryVerdict::Failing {
                    reason: format!(
                        "p99 latency {:.1}x baseline ({:.0}ms vs {:.0}ms, threshold: {:.1}x)",
                        latency_ratio,
                        canary.p99_latency_ms,
                        baseline.p99_latency_ms,
                        self.max_latency_multiplier,
                    ),
                };
            }
        }

        // ── Degraded check (softer thresholds) ─────────────────────────
        if error_delta > self.max_error_delta * 0.5 {
            return CanaryVerdict::Degraded {
                reason: format!("error rate slightly elevated (+{:.2}%)", error_delta * 100.0),
            };
        }

        CanaryVerdict::Healthy
    }

    pub fn reset(&mut self) {
        self.baseline = None;
        self.canary = None;
        self.started = Instant::now();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Rollback trigger
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum RollbackReason {
    CanaryFailing(String),
    ErrorRateExceeded(f64),
    LatencyExceeded(u64),
    HealthChecksFailed,
    DeployTimeout,
    Manual,
}

pub struct RollbackTrigger {
    max_error_rate: f64,
    max_latency_ms: u64,
    max_health_failures: u32,
    current_health_failures: u32,
    deploy_start: Instant,
    deploy_timeout: Duration,
}

impl RollbackTrigger {
    pub fn new(max_error_rate: f64, max_latency_ms: u64, deploy_timeout: Duration) -> Self {
        Self {
            max_error_rate: max_error_rate.clamp(0.0, 1.0),
            max_latency_ms,
            max_health_failures: 3,
            current_health_failures: 0,
            deploy_start: Instant::now(),
            deploy_timeout,
        }
    }

    /// Check if rollback should be triggered based on current metrics.
    pub fn check(
        &mut self,
        error_rate: f64,
        latency_ms: u64,
        health_check_ok: bool,
    ) -> Option<RollbackReason> {
        // Timeout check.
        if self.deploy_start.elapsed() > self.deploy_timeout {
            AUTO_DEPLOY_METRICS
                .rollbacks
                .fetch_add(1, Ordering::Relaxed);
            return Some(RollbackReason::DeployTimeout);
        }

        // Error rate check.
        if error_rate > self.max_error_rate {
            AUTO_DEPLOY_METRICS
                .rollbacks
                .fetch_add(1, Ordering::Relaxed);
            return Some(RollbackReason::ErrorRateExceeded(error_rate));
        }

        // Latency check.
        if latency_ms > self.max_latency_ms {
            AUTO_DEPLOY_METRICS
                .rollbacks
                .fetch_add(1, Ordering::Relaxed);
            return Some(RollbackReason::LatencyExceeded(latency_ms));
        }

        // Health check failures.
        if !health_check_ok {
            self.current_health_failures += 1;
            if self.current_health_failures >= self.max_health_failures {
                AUTO_DEPLOY_METRICS
                    .rollbacks
                    .fetch_add(1, Ordering::Relaxed);
                return Some(RollbackReason::HealthChecksFailed);
            }
        } else {
            self.current_health_failures = 0;
        }

        None
    }

    /// Force a manual rollback trigger.
    pub fn manual_rollback(&self) -> RollbackReason {
        AUTO_DEPLOY_METRICS
            .rollbacks
            .fetch_add(1, Ordering::Relaxed);
        RollbackReason::Manual
    }

    /// Reset health failure counter (after recovery).
    pub fn reset_health(&mut self) {
        self.current_health_failures = 0;
    }

    pub fn elapsed(&self) -> Duration {
        self.deploy_start.elapsed()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Deploy executor — state machine
// ═══════════════════════════════════════════════════════════════════════════

pub struct DeployExecutor {
    pub plan: DeployPlan,
    phase: DeployPhase,
    shifter: TrafficShifter,
    analyzer: Option<CanaryAnalyzer>,
    rollback: RollbackTrigger,
    started: Instant,
    phase_entered: Instant,
    health_passes: u32,
}

impl DeployExecutor {
    pub fn new(plan: DeployPlan) -> Self {
        let shifter = match plan.strategy {
            DeployStrategy::BlueGreen => TrafficShifter::atomic_switch(),
            DeployStrategy::Canary => TrafficShifter::new(
                plan.canary_initial_pct,
                plan.canary_step_pct,
                plan.canary_step_interval,
            ),
            DeployStrategy::Rolling => TrafficShifter::new(
                0,
                // Compute the step in usize so the divisor is clamped to >= 1
                // BEFORE any cast. The old `... .len().max(1) as u8` cast the
                // length to u8 *after* `.max(1)`, so a fleet size that is a
                // nonzero multiple of 256 truncated to 0 and `100 / 0u8`
                // aborted the process.
                (100usize / plan.old_target_ids.len().max(1)).clamp(1, 100) as u8,
                Duration::from_secs(30),
            ),
        };

        let analyzer = if plan.strategy == DeployStrategy::Canary {
            Some(CanaryAnalyzer::new(
                plan.rollback_on_error_rate,
                2.0, // p99 latency 2x threshold
                Duration::from_secs(60),
            ))
        } else {
            None
        };

        let rollback = RollbackTrigger::new(
            plan.rollback_on_error_rate,
            plan.rollback_on_latency_ms,
            plan.deploy_timeout,
        );

        let now = Instant::now();
        AUTO_DEPLOY_METRICS
            .deploys_started
            .fetch_add(1, Ordering::Relaxed);

        Self {
            plan,
            phase: DeployPhase::Validating,
            shifter,
            analyzer,
            rollback,
            started: now,
            phase_entered: now,
            health_passes: 0,
        }
    }

    /// Advance the deploy one step. Call this from a timer loop.
    /// Returns the current phase and whether the deploy is terminal.
    pub fn advance(
        &mut self,
        health_check_ok: bool,
        error_rate: f64,
        latency_ms: u64,
        baseline: Option<MetricsSnapshot>,
        canary: Option<MetricsSnapshot>,
    ) -> (DeployPhase, bool) {
        // ── Check rollback conditions first ────────────────────────────
        if !matches!(
            self.phase,
            DeployPhase::Complete
                | DeployPhase::RolledBack
                | DeployPhase::TimedOut
                | DeployPhase::Validating
        ) {
            if let Some(reason) = self.rollback.check(error_rate, latency_ms, health_check_ok) {
                self.initiate_rollback(&reason);
                return (self.phase, self.is_terminal());
            }
        }

        match self.phase {
            DeployPhase::Validating => {
                // Validate plan then proceed.
                if self.plan.new_target_urls.is_empty() {
                    self.initiate_rollback(&RollbackReason::HealthChecksFailed);
                } else {
                    self.transition(DeployPhase::Provisioning);
                }
            }
            DeployPhase::Provisioning => {
                // In a real implementation, this would start target containers.
                // For now, proceed to health checking.
                self.transition(DeployPhase::HealthChecking);
            }
            DeployPhase::HealthChecking => {
                if health_check_ok {
                    self.health_passes += 1;
                } else {
                    self.health_passes = 0;
                }

                if self.health_passes >= self.plan.health_check_threshold {
                    self.transition(DeployPhase::TrafficShifting);
                    self.health_passes = 0;
                }
            }
            DeployPhase::TrafficShifting => {
                match self.plan.strategy {
                    DeployStrategy::BlueGreen => {
                        // Atomic switch — go to 100% immediately.
                        self.shifter = TrafficShifter::atomic_switch();
                        self.transition(DeployPhase::Monitoring);
                    }
                    DeployStrategy::Canary => {
                        if self.shifter.step() {
                            // Traffic shifted. If 100%, go to draining.
                            if self.shifter.is_complete() {
                                self.transition(DeployPhase::Draining);
                            } else {
                                // Monitor the canary at this percentage.
                                self.transition(DeployPhase::Monitoring);
                            }
                        }
                        // else: waiting for step interval.
                    }
                    DeployStrategy::Rolling => {
                        if self.shifter.step() {
                            if self.shifter.is_complete() {
                                self.transition(DeployPhase::Draining);
                            } else {
                                // Wait for batch to become healthy.
                                self.transition(DeployPhase::HealthChecking);
                            }
                        }
                    }
                }
            }
            DeployPhase::Monitoring => {
                // Update canary analyzer if applicable.
                if let Some(ref mut analyzer) = self.analyzer {
                    if let Some(b) = baseline {
                        analyzer.update_baseline(b);
                    }
                    if let Some(c) = canary {
                        analyzer.update_canary(c);
                    }

                    match analyzer.analyze() {
                        CanaryVerdict::Healthy => {
                            // Canary looks good — shift more traffic.
                            self.transition(DeployPhase::TrafficShifting);
                        }
                        CanaryVerdict::Degraded { .. } => {
                            // Keep monitoring — don't advance yet.
                        }
                        CanaryVerdict::Failing { reason } => {
                            self.initiate_rollback(&RollbackReason::CanaryFailing(reason));
                        }
                        CanaryVerdict::Insufficient => {
                            // Not enough data yet — keep waiting.
                        }
                    }
                } else {
                    // Blue/green: just a bake time check.
                    if self.phase_entered.elapsed() > Duration::from_secs(30) {
                        self.transition(DeployPhase::Draining);
                    }
                }
            }
            DeployPhase::Draining => {
                // In production, wait for old targets to drain connections.
                // For the state machine, transition to complete.
                self.transition(DeployPhase::Complete);
                AUTO_DEPLOY_METRICS
                    .deploys_completed
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeployPhase::RollingBack => {
                self.shifter.rollback();
                self.transition(DeployPhase::RolledBack);
            }
            DeployPhase::Complete | DeployPhase::RolledBack | DeployPhase::TimedOut => {
                // Terminal states — no-op.
            }
        }

        (self.phase, self.is_terminal())
    }

    fn initiate_rollback(&mut self, reason: &RollbackReason) {
        let _ = reason; // Would log in production.
        self.transition(DeployPhase::RollingBack);
        AUTO_DEPLOY_METRICS
            .deploys_rolled_back
            .fetch_add(1, Ordering::Relaxed);
    }

    fn transition(&mut self, new_phase: DeployPhase) {
        self.phase = new_phase;
        self.phase_entered = Instant::now();
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            DeployPhase::Complete | DeployPhase::RolledBack | DeployPhase::TimedOut
        )
    }

    pub fn phase(&self) -> DeployPhase {
        self.phase
    }

    pub fn traffic_distribution(&self) -> (u8, u8) {
        (self.shifter.old_pct(), self.shifter.new_pct())
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn strategy(&self) -> DeployStrategy {
        self.plan.strategy
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Deploy history
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct DeployRecord {
    pub id: Uuid,
    pub service_id: Uuid,
    pub strategy: DeployStrategy,
    pub new_version: String,
    pub old_version: String,
    pub final_phase: DeployPhase,
    pub duration: Duration,
    pub started_at: Instant,
}

pub struct DeployHistory {
    records: DashMap<Uuid, DeployRecord, FastHasher>,
    /// Maximum records to keep.
    max_records: usize,
}

impl DeployHistory {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: DashMap::with_hasher(FastHasher::default()),
            max_records: max_records.max(10),
        }
    }

    /// Record a completed deploy.
    pub fn record(&self, executor: &DeployExecutor) {
        let record = DeployRecord {
            id: executor.plan.id,
            service_id: executor.plan.service_id,
            strategy: executor.plan.strategy,
            new_version: executor.plan.new_version.clone(),
            old_version: executor.plan.old_version.clone(),
            final_phase: executor.phase(),
            duration: executor.elapsed(),
            started_at: executor.started,
        };

        // Evict oldest if at capacity.
        if self.records.len() >= self.max_records {
            // Remove the oldest entry by comparing started_at.
            if let Some(oldest) = self
                .records
                .iter()
                .min_by_key(|e| e.started_at)
                .map(|e| *e.key())
            {
                self.records.remove(&oldest);
            }
        }

        self.records.insert(record.id, record);
    }

    /// Get the last N deploys for a service.
    pub fn recent_for_service(&self, service_id: &Uuid, limit: usize) -> Vec<DeployRecord> {
        let mut records: Vec<_> = self
            .records
            .iter()
            .filter(|e| e.service_id == *service_id)
            .map(|e| e.clone())
            .collect();
        records.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        records.truncate(limit);
        records
    }

    /// Get deploy count by strategy.
    pub fn count_by_strategy(&self) -> (u64, u64, u64) {
        let mut bg = 0u64;
        let mut canary = 0u64;
        let mut rolling = 0u64;
        for entry in self.records.iter() {
            match entry.strategy {
                DeployStrategy::BlueGreen => bg += 1,
                DeployStrategy::Canary => canary += 1,
                DeployStrategy::Rolling => rolling += 1,
            }
        }
        (bg, canary, rolling)
    }

    pub fn total(&self) -> usize {
        self.records.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct AutoDeployMetrics {
    pub deploys_started: AtomicU64,
    pub deploys_completed: AtomicU64,
    pub deploys_rolled_back: AtomicU64,
    pub canary_failures: AtomicU64,
    pub rollbacks: AtomicU64,
}

static AUTO_DEPLOY_METRICS: AutoDeployMetrics = AutoDeployMetrics {
    deploys_started: AtomicU64::new(0),
    deploys_completed: AtomicU64::new(0),
    deploys_rolled_back: AtomicU64::new(0),
    canary_failures: AtomicU64::new(0),
    rollbacks: AtomicU64::new(0),
};

pub fn auto_deploy_metrics() -> &'static AutoDeployMetrics {
    &AUTO_DEPLOY_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn svc_id() -> Uuid {
        Uuid::new_v4()
    }

    // ── Strategy enum ──────────────────────────────────────────────────

    #[test]
    fn strategy_from_u8_roundtrip() {
        assert_eq!(DeployStrategy::from_u8(0), DeployStrategy::BlueGreen);
        assert_eq!(DeployStrategy::from_u8(1), DeployStrategy::Canary);
        assert_eq!(DeployStrategy::from_u8(2), DeployStrategy::Rolling);
        assert_eq!(DeployStrategy::from_u8(99), DeployStrategy::BlueGreen);
    }

    #[test]
    fn strategy_from_str() {
        assert_eq!(DeployStrategy::from_str("canary"), DeployStrategy::Canary);
        assert_eq!(DeployStrategy::from_str("rolling"), DeployStrategy::Rolling);
        assert_eq!(DeployStrategy::from_str("blue-green"), DeployStrategy::BlueGreen);
        assert_eq!(DeployStrategy::from_str("blue_green"), DeployStrategy::BlueGreen);
        assert_eq!(DeployStrategy::from_str("unknown"), DeployStrategy::BlueGreen);
    }

    // ── Global toggle ──────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_auto_deploy_enabled(true);
        assert!(is_auto_deploy_enabled());
    }

    #[test]
    fn global_default_strategy() {
        set_default_strategy(DeployStrategy::Canary);
        assert_eq!(get_default_strategy(), DeployStrategy::Canary);
        set_default_strategy(DeployStrategy::BlueGreen);
    }

    // ── Traffic shifter ────────────────────────────────────────────────

    #[test]
    fn shifter_atomic_switch() {
        let s = TrafficShifter::atomic_switch();
        assert_eq!(s.new_pct(), 100);
        assert_eq!(s.old_pct(), 0);
        assert!(s.is_complete());
    }

    #[test]
    fn shifter_gradual_steps() {
        let mut s = TrafficShifter::new(10, 20, Duration::from_millis(1));

        assert_eq!(s.new_pct(), 10);
        assert_eq!(s.old_pct(), 90);

        // Step to 30%.
        std::thread::sleep(Duration::from_millis(2));
        assert!(s.step());
        assert_eq!(s.new_pct(), 30);

        // Step to 50%.
        std::thread::sleep(Duration::from_millis(2));
        assert!(s.step());
        assert_eq!(s.new_pct(), 50);
    }

    #[test]
    fn shifter_respects_interval() {
        let mut s = TrafficShifter::new(10, 20, Duration::from_secs(300));
        assert!(s.step()); // First step always works (no last_step).
        assert!(!s.step()); // Too soon.
    }

    #[test]
    fn shifter_caps_at_100() {
        let mut s = TrafficShifter::new(90, 20, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        s.step();
        assert_eq!(s.new_pct(), 100);
        assert!(s.is_complete());
    }

    #[test]
    fn shifter_rollback() {
        let mut s = TrafficShifter::new(50, 10, Duration::ZERO);
        s.rollback();
        assert_eq!(s.new_pct(), 0);
        assert_eq!(s.old_pct(), 100);
    }

    #[test]
    fn shifter_large_step_pct_does_not_overflow() {
        // Regression: a large step_pct used to overflow the u8 add in step()
        // (panic under overflow-checks, silent wrap to a *lower* pct in
        // release — e.g. 99 -> 98). Start high so the next step crosses the
        // u8 boundary, and pass the maximum possible step_pct.
        let mut s = TrafficShifter::new(99, 255, Duration::ZERO);

        // The constructor must clamp step_pct into [1, 100] (no longer stores
        // 255), so step() can never push new_pct past target_pct (100).
        assert!(s.step());
        assert_eq!(
            s.new_pct(),
            100,
            "step must saturate at target_pct, never wrap below the current pct"
        );
        assert!(s.is_complete());

        // Monotonicity guard: a further step at the cap is a no-op, never a
        // regression to a smaller value.
        assert!(!s.step());
        assert_eq!(s.new_pct(), 100);
    }

    #[test]
    fn shifter_weight_computation() {
        let s = TrafficShifter::new(30, 10, Duration::ZERO);
        assert_eq!(s.new_weight(100), 30);
        assert_eq!(s.old_weight(100), 70);
    }

    // ── Canary analyzer ────────────────────────────────────────────────

    #[test]
    fn canary_healthy() {
        let mut a = CanaryAnalyzer::new(0.05, 2.0, Duration::from_millis(1));
        a.update_baseline(MetricsSnapshot::new(0.01, 10.0, 50.0, 1000.0));
        a.update_canary(MetricsSnapshot::new(0.02, 12.0, 55.0, 1000.0));

        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(a.analyze(), CanaryVerdict::Healthy);
    }

    #[test]
    fn canary_failing_error_rate() {
        let mut a = CanaryAnalyzer::new(0.05, 2.0, Duration::from_millis(1));
        a.update_baseline(MetricsSnapshot::new(0.01, 10.0, 50.0, 1000.0));
        a.update_canary(MetricsSnapshot::new(0.10, 12.0, 55.0, 1000.0)); // +9% error

        std::thread::sleep(Duration::from_millis(5));
        match a.analyze() {
            CanaryVerdict::Failing { reason } => {
                assert!(reason.contains("error rate"));
            }
            other => panic!("expected Failing, got {other:?}"),
        }
    }

    #[test]
    fn canary_failing_latency() {
        let mut a = CanaryAnalyzer::new(0.05, 2.0, Duration::from_millis(1));
        a.update_baseline(MetricsSnapshot::new(0.01, 10.0, 50.0, 1000.0));
        a.update_canary(MetricsSnapshot::new(0.01, 10.0, 150.0, 1000.0)); // 3x p99

        std::thread::sleep(Duration::from_millis(5));
        match a.analyze() {
            CanaryVerdict::Failing { reason } => {
                assert!(reason.contains("latency"));
            }
            other => panic!("expected Failing, got {other:?}"),
        }
    }

    #[test]
    fn canary_insufficient_before_min_observation() {
        let a = CanaryAnalyzer::new(0.05, 2.0, Duration::from_secs(300));
        assert_eq!(a.analyze(), CanaryVerdict::Insufficient);
    }

    #[test]
    fn canary_degraded() {
        let mut a = CanaryAnalyzer::new(0.10, 2.0, Duration::from_millis(1));
        a.update_baseline(MetricsSnapshot::new(0.01, 10.0, 50.0, 1000.0));
        // Error delta = 0.06, which is > 0.10 * 0.5 = 0.05 but < 0.10.
        a.update_canary(MetricsSnapshot::new(0.07, 12.0, 55.0, 1000.0));

        std::thread::sleep(Duration::from_millis(5));
        match a.analyze() {
            CanaryVerdict::Degraded { .. } => {}
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    // ── Rollback trigger ───────────────────────────────────────────────

    #[test]
    fn rollback_on_error_rate() {
        let mut trigger = RollbackTrigger::new(0.05, 5000, Duration::from_secs(600));
        let result = trigger.check(0.10, 100, true);
        assert!(matches!(result, Some(RollbackReason::ErrorRateExceeded(_))));
    }

    #[test]
    fn rollback_on_latency() {
        let mut trigger = RollbackTrigger::new(0.05, 5000, Duration::from_secs(600));
        let result = trigger.check(0.01, 6000, true);
        assert!(matches!(result, Some(RollbackReason::LatencyExceeded(_))));
    }

    #[test]
    fn rollback_on_health_failures() {
        let mut trigger = RollbackTrigger::new(0.05, 5000, Duration::from_secs(600));
        assert!(trigger.check(0.01, 100, false).is_none()); // 1/3
        assert!(trigger.check(0.01, 100, false).is_none()); // 2/3
        assert!(matches!(
            trigger.check(0.01, 100, false),
            Some(RollbackReason::HealthChecksFailed)
        )); // 3/3
    }

    #[test]
    fn rollback_health_resets_on_success() {
        let mut trigger = RollbackTrigger::new(0.05, 5000, Duration::from_secs(600));
        trigger.check(0.01, 100, false); // 1/3
        trigger.check(0.01, 100, false); // 2/3
        trigger.check(0.01, 100, true);  // Reset!
        assert!(trigger.check(0.01, 100, false).is_none()); // 1/3 again
    }

    #[test]
    fn rollback_on_timeout() {
        let mut trigger = RollbackTrigger::new(0.05, 5000, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(
            trigger.check(0.01, 100, true),
            Some(RollbackReason::DeployTimeout)
        ));
    }

    #[test]
    fn rollback_manual() {
        let trigger = RollbackTrigger::new(0.05, 5000, Duration::from_secs(600));
        assert_eq!(trigger.manual_rollback(), RollbackReason::Manual);
    }

    // ── Deploy executor — blue/green ───────────────────────────────────

    #[test]
    fn blue_green_happy_path() {
        let plan = DeployPlan::blue_green(
            svc_id(),
            "v2",
            "v1",
            vec!["http://new:80".to_string()],
            vec![Uuid::new_v4()],
        );
        let mut exec = DeployExecutor::new(plan);

        assert_eq!(exec.phase(), DeployPhase::Validating);

        // Validate → Provisioning.
        exec.advance(true, 0.0, 0, None, None);
        assert_eq!(exec.phase(), DeployPhase::Provisioning);

        // Provision → HealthChecking.
        exec.advance(true, 0.0, 0, None, None);
        assert_eq!(exec.phase(), DeployPhase::HealthChecking);

        // Health checks: need 3 passes.
        exec.advance(true, 0.0, 0, None, None); // 1/3
        exec.advance(true, 0.0, 0, None, None); // 2/3
        exec.advance(true, 0.0, 0, None, None); // 3/3 → TrafficShifting
        assert_eq!(exec.phase(), DeployPhase::TrafficShifting);

        // Blue/green: atomic switch → Monitoring.
        exec.advance(true, 0.0, 0, None, None);
        assert_eq!(exec.phase(), DeployPhase::Monitoring);

        assert_eq!(exec.traffic_distribution(), (0, 100));
    }

    #[test]
    fn blue_green_rollback_on_error() {
        let mut plan = DeployPlan::blue_green(
            svc_id(),
            "v2",
            "v1",
            vec!["http://new:80".to_string()],
            vec![Uuid::new_v4()],
        );
        plan.rollback_on_error_rate = 0.05;

        let mut exec = DeployExecutor::new(plan);

        // Get to HealthChecking.
        exec.advance(true, 0.0, 0, None, None); // Validate
        exec.advance(true, 0.0, 0, None, None); // Provision
        exec.advance(true, 0.0, 0, None, None); // HC 1/3

        // High error rate triggers rollback.
        exec.advance(true, 0.10, 0, None, None); // HC 2/3 but error rate!
        assert_eq!(exec.phase(), DeployPhase::RollingBack);

        exec.advance(true, 0.0, 0, None, None); // Completes rollback.
        assert_eq!(exec.phase(), DeployPhase::RolledBack);
        assert!(exec.is_terminal());
    }

    // ── Deploy executor — canary ───────────────────────────────────────

    #[test]
    fn canary_gradual_shift() {
        let plan = DeployPlan::canary(
            svc_id(),
            "v2",
            "v1",
            vec!["http://new:80".to_string()],
            vec![Uuid::new_v4()],
            10,  // Start at 10%
            20,  // Step by 20%
            Duration::from_millis(1),
        );
        let mut exec = DeployExecutor::new(plan);

        // Get to TrafficShifting.
        exec.advance(true, 0.0, 0, None, None); // Validate
        exec.advance(true, 0.0, 0, None, None); // Provision
        for _ in 0..3 {
            exec.advance(true, 0.0, 0, None, None); // HC
        }
        assert_eq!(exec.phase(), DeployPhase::TrafficShifting);

        // First shift: 10% → 30%.
        std::thread::sleep(Duration::from_millis(2));
        exec.advance(true, 0.0, 0, None, None);
        let (old, new) = exec.traffic_distribution();
        assert!(new > 10, "expected > 10%, got new={new} old={old}");
    }

    // ── Deploy executor — empty targets validation ─────────────────────

    #[test]
    fn deploy_rejects_empty_targets() {
        let plan = DeployPlan::blue_green(svc_id(), "v2", "v1", vec![], vec![Uuid::new_v4()]);
        let mut exec = DeployExecutor::new(plan);

        exec.advance(true, 0.0, 0, None, None);
        // Should roll back due to empty target list.
        assert_eq!(exec.phase(), DeployPhase::RollingBack);
    }

    // ── Deploy history ─────────────────────────────────────────────────

    #[test]
    fn history_records_and_queries() {
        let history = DeployHistory::new(100);
        let sid = svc_id();

        let plan = DeployPlan::blue_green(
            sid,
            "v2",
            "v1",
            vec!["http://new:80".to_string()],
            vec![Uuid::new_v4()],
        );
        let exec = DeployExecutor::new(plan);
        history.record(&exec);

        assert_eq!(history.total(), 1);
        let recent = history.recent_for_service(&sid, 10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].new_version, "v2");
    }

    #[test]
    fn history_evicts_oldest() {
        let history = DeployHistory::new(10);

        for i in 0..15 {
            let plan = DeployPlan::blue_green(
                svc_id(),
                &format!("v{i}"),
                "v0",
                vec!["http://new:80".to_string()],
                vec![],
            );
            let exec = DeployExecutor::new(plan);
            history.record(&exec);
        }

        assert!(history.total() <= 10);
    }

    #[test]
    fn history_count_by_strategy() {
        let history = DeployHistory::new(100);

        let p1 = DeployPlan::blue_green(svc_id(), "v1", "v0", vec!["a".into()], vec![]);
        let p2 = DeployPlan::canary(svc_id(), "v2", "v0", vec!["b".into()], vec![], 5, 10, Duration::from_secs(1));
        let p3 = DeployPlan::rolling(svc_id(), "v3", "v0", vec!["c".into()], vec![], 2, 1);

        history.record(&DeployExecutor::new(p1));
        history.record(&DeployExecutor::new(p2));
        history.record(&DeployExecutor::new(p3));

        let (bg, canary, rolling) = history.count_by_strategy();
        assert_eq!(bg, 1);
        assert_eq!(canary, 1);
        assert_eq!(rolling, 1);
    }

    // ── Deploy plan constructors ───────────────────────────────────────

    #[test]
    fn plan_blue_green_defaults() {
        let plan = DeployPlan::blue_green(svc_id(), "v2", "v1", vec!["a".into()], vec![]);
        assert_eq!(plan.strategy, DeployStrategy::BlueGreen);
        assert_eq!(plan.health_check_threshold, 3);
        assert!((plan.rollback_on_error_rate - 0.05).abs() < 0.001);
    }

    #[test]
    fn plan_canary_clamps_pct() {
        let plan = DeployPlan::canary(svc_id(), "v2", "v1", vec!["a".into()], vec![], 0, 0, Duration::ZERO);
        assert!(plan.canary_initial_pct >= 1);
        assert!(plan.canary_step_pct >= 1);
    }

    #[test]
    fn plan_rolling_clamps_batch() {
        let plan = DeployPlan::rolling(svc_id(), "v2", "v1", vec!["a".into()], vec![], 0, 0);
        assert!(plan.batch_size >= 1);
        assert!(plan.max_unavailable >= 1);
    }
}
