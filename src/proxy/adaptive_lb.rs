//! Adaptive load balancer selection — auto-detect the optimal algorithm
//! per service based on observed traffic patterns.
//!
//! # Architecture
//!
//! ```text
//! Adaptive LB
//! ├── TrafficProfile         — Characterise traffic (uniform/skewed/bursty/sticky)
//! ├── BackendProfile         — Characterise backends (homogeneous/heterogeneous/variable)
//! ├── AlgorithmScorer        — Score each LB algorithm for the current profile
//! ├── AdaptiveSelector       — Pick the best algorithm, switch at runtime
//! ├── ProfileWindow          — Rolling window of traffic observations
//! ├── SwitchPolicy           — How aggressively to switch algorithms
//! └── AdaptiveMetrics        — Switch count, profile changes, improvement %
//! ```
//!
//! # Why This Beats AWS
//!
//! AWS ALB only does round-robin. AWS NLB does flow-hash. Users manually
//! pick the algorithm and hope for the best. Lynxx observes the actual
//! traffic pattern and automatically switches to the optimal algorithm:
//!
//! - Uniform traffic, homogeneous backends → Round Robin (lowest overhead)
//! - Skewed latency across backends → Least Time (route to fastest)
//! - Session-heavy traffic → Cookie Sticky (avoid session migration)
//! - Variable backend capacity → Weighted Round Robin (respect capacity)
//! - Burst traffic → Random Two Choices (best under contention)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

static ADAPTIVE_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_adaptive_enabled(enabled: bool) {
    ADAPTIVE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_adaptive_enabled() -> bool {
    ADAPTIVE_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// Traffic profile — characterise the request pattern
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPattern {
    /// Requests are evenly distributed — no hot paths.
    Uniform,
    /// A few paths get most traffic (power-law / Zipf distribution).
    Skewed,
    /// Traffic comes in short intense bursts with quiet periods.
    Bursty,
    /// Most requests carry session cookies / sticky tokens.
    Sticky,
    /// Not enough data to classify.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendVariance {
    /// All backends have similar capacity and latency.
    Homogeneous,
    /// Backends have significantly different capacity or latency.
    Heterogeneous,
    /// Backend performance varies over time (auto-scaling, shared infra).
    Variable,
    /// Not enough data.
    Unknown,
}

/// Observed traffic characteristics for a service.
#[derive(Debug, Clone)]
pub struct TrafficProfile {
    pub pattern: TrafficPattern,
    pub backend_variance: BackendVariance,
    /// Coefficient of variation of request latencies (stddev / mean).
    pub latency_cv: f64,
    /// Fraction of requests that carry a session identifier.
    pub session_fraction: f64,
    /// Requests per second (recent average).
    pub rps: f64,
    /// Number of active backends.
    pub backend_count: u32,
    /// Coefficient of variation of per-backend request counts.
    pub distribution_cv: f64,
    /// How bursty the traffic is (peak / avg ratio).
    pub burst_ratio: f64,
}

impl TrafficProfile {
    pub fn unknown() -> Self {
        Self {
            pattern: TrafficPattern::Unknown,
            backend_variance: BackendVariance::Unknown,
            latency_cv: 0.0,
            session_fraction: 0.0,
            rps: 0.0,
            backend_count: 0,
            distribution_cv: 0.0,
            burst_ratio: 1.0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Profile window — rolling observations
// ═══════════════════════════════════════════════════════════════════════════

/// One observation point.
#[derive(Debug, Clone)]
pub struct Observation {
    pub timestamp: Instant,
    pub rps: f64,
    /// Per-backend latencies (ms).
    pub backend_latencies: Vec<f64>,
    /// Per-backend request counts in this window.
    pub backend_request_counts: Vec<u64>,
    /// Fraction of requests with session cookies.
    pub session_fraction: f64,
}

pub struct ProfileWindow {
    observations: Vec<Observation>,
    max_size: usize,
}

impl ProfileWindow {
    pub fn new(max_size: usize) -> Self {
        Self {
            observations: Vec::with_capacity(max_size),
            max_size: max_size.max(5),
        }
    }

    pub fn push(&mut self, obs: Observation) {
        if self.observations.len() >= self.max_size {
            self.observations.remove(0);
        }
        self.observations.push(obs);
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Compute the traffic profile from the observation window.
    pub fn compute_profile(&self) -> TrafficProfile {
        if self.observations.len() < 3 {
            return TrafficProfile::unknown();
        }

        let n = self.observations.len() as f64;

        // ── RPS stats ──────────────────────────────────────────────────
        let rps_values: Vec<f64> = self.observations.iter().map(|o| o.rps).collect();
        let avg_rps = rps_values.iter().sum::<f64>() / n;
        let max_rps = rps_values.iter().cloned().fold(0.0_f64, f64::max);
        let burst_ratio = if avg_rps > 0.0 {
            max_rps / avg_rps
        } else {
            1.0
        };

        // ── Session fraction ───────────────────────────────────────────
        let avg_session: f64 =
            self.observations.iter().map(|o| o.session_fraction).sum::<f64>() / n;

        // ── Backend latency variance ───────────────────────────────────
        let all_latencies: Vec<f64> = self
            .observations
            .iter()
            .flat_map(|o| o.backend_latencies.iter().cloned())
            .collect();

        let latency_cv = coefficient_of_variation(&all_latencies);

        // ── Request distribution across backends ───────────────────────
        let last = self.observations.last().unwrap();
        let distribution_cv =
            coefficient_of_variation_u64(&last.backend_request_counts);
        let backend_count = last.backend_request_counts.len() as u32;

        // ── Classify pattern ───────────────────────────────────────────
        let pattern = if avg_session > 0.5 {
            TrafficPattern::Sticky
        } else if burst_ratio > 3.0 {
            TrafficPattern::Bursty
        } else if distribution_cv > 0.5 {
            TrafficPattern::Skewed
        } else {
            TrafficPattern::Uniform
        };

        let backend_variance = if latency_cv > 0.5 {
            BackendVariance::Heterogeneous
        } else if latency_cv > 0.3 {
            BackendVariance::Variable
        } else {
            BackendVariance::Homogeneous
        };

        TrafficProfile {
            pattern,
            backend_variance,
            latency_cv,
            session_fraction: avg_session,
            rps: avg_rps,
            backend_count,
            distribution_cv,
            burst_ratio,
        }
    }
}

fn coefficient_of_variation(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    if mean.abs() < 1e-12 {
        return 0.0;
    }
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
    variance.sqrt() / mean
}

fn coefficient_of_variation_u64(values: &[u64]) -> f64 {
    let floats: Vec<f64> = values.iter().map(|v| *v as f64).collect();
    coefficient_of_variation(&floats)
}

// ═══════════════════════════════════════════════════════════════════════════
// Algorithm scorer
// ═══════════════════════════════════════════════════════════════════════════

/// Recommended LB algorithm with a confidence score.
#[derive(Debug, Clone)]
pub struct AlgorithmRecommendation {
    pub algorithm: &'static str,
    pub score: f64,
    pub reason: String,
}

/// Score each LB algorithm for the given traffic profile.
pub fn score_algorithms(profile: &TrafficProfile) -> Vec<AlgorithmRecommendation> {
    let mut recommendations = Vec::new();

    // ── Round Robin ────────────────────────────────────────────────────
    let mut rr_score = 50.0;
    if profile.pattern == TrafficPattern::Uniform
        && profile.backend_variance == BackendVariance::Homogeneous
    {
        rr_score = 95.0; // Perfect conditions for RR.
    }
    if profile.backend_variance == BackendVariance::Heterogeneous {
        rr_score -= 30.0; // RR ignores capacity differences.
    }
    recommendations.push(AlgorithmRecommendation {
        algorithm: "round-robin",
        score: rr_score,
        reason: "lowest overhead, ideal for uniform/homogeneous".to_string(),
    });

    // ── Least Connections ──────────────────────────────────────────────
    let mut lc_score = 60.0;
    if profile.backend_variance == BackendVariance::Heterogeneous {
        lc_score = 85.0;
    }
    if profile.pattern == TrafficPattern::Bursty {
        lc_score += 10.0; // Naturally handles bursts.
    }
    recommendations.push(AlgorithmRecommendation {
        algorithm: "least-conn",
        score: lc_score,
        reason: "adapts to varying backend speed".to_string(),
    });

    // ── Least Time ─────────────────────────────────────────────────────
    let mut lt_score = 55.0;
    if profile.latency_cv > 0.3 {
        lt_score = 90.0; // High latency variance → least-time shines.
    }
    if profile.backend_variance == BackendVariance::Variable {
        lt_score += 10.0;
    }
    recommendations.push(AlgorithmRecommendation {
        algorithm: "least-time",
        score: lt_score,
        reason: "routes to fastest backend based on observed latency".to_string(),
    });

    // ── Cookie Sticky ──────────────────────────────────────────────────
    let mut sticky_score = 30.0;
    if profile.session_fraction > 0.5 {
        sticky_score = 85.0;
    }
    if profile.session_fraction > 0.8 {
        sticky_score = 95.0;
    }
    recommendations.push(AlgorithmRecommendation {
        algorithm: "cookie-sticky",
        score: sticky_score,
        reason: "preserves sessions without backend session store".to_string(),
    });

    // ── Random Two Choices ─────────────────────────────────────────────
    let mut r2c_score = 50.0;
    if profile.pattern == TrafficPattern::Bursty {
        r2c_score = 88.0; // Best under high contention.
    }
    if profile.rps > 10000.0 && profile.backend_count > 5 {
        r2c_score += 10.0; // Scales well at high RPS.
    }
    recommendations.push(AlgorithmRecommendation {
        algorithm: "random-two-choices",
        score: r2c_score,
        reason: "near-optimal spread without coordination".to_string(),
    });

    // ── IP Hash ────────────────────────────────────────────────────────
    let mut ip_score = 40.0;
    if profile.session_fraction > 0.3 && profile.session_fraction <= 0.6 {
        ip_score = 70.0; // Moderate session affinity without cookies.
    }
    recommendations.push(AlgorithmRecommendation {
        algorithm: "ip-hash",
        score: ip_score,
        reason: "cookie-less session affinity".to_string(),
    });

    // Sort by score descending.
    recommendations.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    recommendations
}

// ═══════════════════════════════════════════════════════════════════════════
// Adaptive selector
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchPolicy {
    /// Only switch if the new algorithm scores > 20 points higher.
    Conservative,
    /// Switch if the new algorithm scores > 10 points higher.
    Moderate,
    /// Switch on any improvement.
    Aggressive,
}

impl SwitchPolicy {
    fn threshold(&self) -> f64 {
        match self {
            SwitchPolicy::Conservative => 20.0,
            SwitchPolicy::Moderate => 10.0,
            SwitchPolicy::Aggressive => 1.0,
        }
    }
}

pub struct AdaptiveSelector {
    window: ProfileWindow,
    current_algorithm: String,
    current_score: f64,
    switch_policy: SwitchPolicy,
    last_switch: Option<Instant>,
    /// Minimum time between switches to avoid flapping.
    min_switch_interval: Duration,
    switches: u32,
}

/// Result of an adaptive evaluation.
#[derive(Debug, Clone)]
pub enum AdaptiveDecision {
    /// Keep the current algorithm.
    Keep {
        algorithm: String,
        score: f64,
    },
    /// Switch to a better algorithm.
    Switch {
        from: String,
        to: String,
        score_improvement: f64,
        reason: String,
    },
    /// Not enough data yet.
    Insufficient,
}

impl AdaptiveSelector {
    pub fn new(
        initial_algorithm: &str,
        switch_policy: SwitchPolicy,
        min_switch_interval: Duration,
    ) -> Self {
        Self {
            window: ProfileWindow::new(60), // 60 observation windows.
            current_algorithm: initial_algorithm.to_string(),
            current_score: 50.0,
            switch_policy,
            last_switch: None,
            min_switch_interval,
            switches: 0,
        }
    }

    /// Record a traffic observation.
    pub fn observe(&mut self, obs: Observation) {
        self.window.push(obs);
    }

    /// Evaluate whether to switch algorithms.
    pub fn evaluate(&mut self) -> AdaptiveDecision {
        if self.window.len() < 5 {
            return AdaptiveDecision::Insufficient;
        }

        // Check switch cooldown.
        if let Some(last) = self.last_switch {
            if last.elapsed() < self.min_switch_interval {
                return AdaptiveDecision::Keep {
                    algorithm: self.current_algorithm.clone(),
                    score: self.current_score,
                };
            }
        }

        let profile = self.window.compute_profile();
        let recommendations = score_algorithms(&profile);

        if recommendations.is_empty() {
            return AdaptiveDecision::Insufficient;
        }

        let best = &recommendations[0];

        // Find current algorithm's score.
        let current_score = recommendations
            .iter()
            .find(|r| r.algorithm == self.current_algorithm)
            .map(|r| r.score)
            .unwrap_or(50.0);

        let improvement = best.score - current_score;

        if best.algorithm != self.current_algorithm
            && improvement >= self.switch_policy.threshold()
        {
            let decision = AdaptiveDecision::Switch {
                from: self.current_algorithm.clone(),
                to: best.algorithm.to_string(),
                score_improvement: improvement,
                reason: best.reason.clone(),
            };

            self.current_algorithm = best.algorithm.to_string();
            self.current_score = best.score;
            self.last_switch = Some(Instant::now());
            self.switches += 1;

            ADAPTIVE_METRICS
                .algorithm_switches
                .fetch_add(1, Ordering::Relaxed);

            decision
        } else {
            self.current_score = current_score;
            AdaptiveDecision::Keep {
                algorithm: self.current_algorithm.clone(),
                score: current_score,
            }
        }
    }

    pub fn current_algorithm(&self) -> &str {
        &self.current_algorithm
    }

    pub fn switch_count(&self) -> u32 {
        self.switches
    }

    pub fn profile(&self) -> TrafficProfile {
        self.window.compute_profile()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct AdaptiveMetrics {
    pub algorithm_switches: AtomicU64,
    pub profiles_computed: AtomicU64,
    pub observations_recorded: AtomicU64,
}

static ADAPTIVE_METRICS: AdaptiveMetrics = AdaptiveMetrics {
    algorithm_switches: AtomicU64::new(0),
    profiles_computed: AtomicU64::new(0),
    observations_recorded: AtomicU64::new(0),
};

pub fn adaptive_metrics() -> &'static AdaptiveMetrics {
    &ADAPTIVE_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn uniform_obs() -> Observation {
        Observation {
            timestamp: Instant::now(),
            rps: 1000.0,
            backend_latencies: vec![10.0, 11.0, 10.5, 10.2],
            backend_request_counts: vec![250, 260, 245, 255],
            session_fraction: 0.1,
        }
    }

    fn sticky_obs() -> Observation {
        Observation {
            timestamp: Instant::now(),
            rps: 500.0,
            backend_latencies: vec![10.0, 11.0],
            backend_request_counts: vec![250, 250],
            session_fraction: 0.9,
        }
    }

    fn bursty_obs(rps: f64) -> Observation {
        Observation {
            timestamp: Instant::now(),
            rps,
            backend_latencies: vec![10.0, 10.0, 10.0],
            backend_request_counts: vec![100, 100, 100],
            session_fraction: 0.1,
        }
    }

    fn hetero_obs() -> Observation {
        Observation {
            timestamp: Instant::now(),
            rps: 1000.0,
            // Very different latencies across backends.
            backend_latencies: vec![5.0, 50.0, 100.0, 200.0],
            backend_request_counts: vec![250, 250, 250, 250],
            session_fraction: 0.1,
        }
    }

    // ── Traffic profile classification ──────────────────────────────────

    #[test]
    fn profile_uniform() {
        let mut w = ProfileWindow::new(10);
        for _ in 0..5 {
            w.push(uniform_obs());
        }
        let p = w.compute_profile();
        assert_eq!(p.pattern, TrafficPattern::Uniform);
        assert_eq!(p.backend_variance, BackendVariance::Homogeneous);
    }

    #[test]
    fn profile_sticky() {
        let mut w = ProfileWindow::new(10);
        for _ in 0..5 {
            w.push(sticky_obs());
        }
        let p = w.compute_profile();
        assert_eq!(p.pattern, TrafficPattern::Sticky);
    }

    #[test]
    fn profile_bursty() {
        let mut w = ProfileWindow::new(10);
        // Mix of low and high RPS to create burst_ratio > 3.
        w.push(bursty_obs(100.0));
        w.push(bursty_obs(100.0));
        w.push(bursty_obs(100.0));
        w.push(bursty_obs(5000.0)); // Spike!
        w.push(bursty_obs(100.0));

        let p = w.compute_profile();
        assert_eq!(p.pattern, TrafficPattern::Bursty);
    }

    #[test]
    fn profile_heterogeneous_backends() {
        let mut w = ProfileWindow::new(10);
        for _ in 0..5 {
            w.push(hetero_obs());
        }
        let p = w.compute_profile();
        assert_eq!(p.backend_variance, BackendVariance::Heterogeneous);
    }

    #[test]
    fn profile_unknown_with_few_observations() {
        let mut w = ProfileWindow::new(10);
        w.push(uniform_obs());
        let p = w.compute_profile();
        assert_eq!(p.pattern, TrafficPattern::Unknown);
    }

    // ── Algorithm scoring ──────────────────────────────────────────────

    #[test]
    fn score_favors_round_robin_for_uniform() {
        let mut w = ProfileWindow::new(10);
        for _ in 0..5 {
            w.push(uniform_obs());
        }
        let profile = w.compute_profile();
        let recs = score_algorithms(&profile);

        assert_eq!(recs[0].algorithm, "round-robin");
        assert!(recs[0].score > 90.0);
    }

    #[test]
    fn score_favors_sticky_for_session_heavy() {
        let mut w = ProfileWindow::new(10);
        for _ in 0..5 {
            w.push(sticky_obs());
        }
        let profile = w.compute_profile();
        let recs = score_algorithms(&profile);

        assert_eq!(recs[0].algorithm, "cookie-sticky");
    }

    #[test]
    fn score_favors_least_time_for_hetero_latency() {
        let mut w = ProfileWindow::new(10);
        for _ in 0..5 {
            w.push(hetero_obs());
        }
        let profile = w.compute_profile();
        let recs = score_algorithms(&profile);

        assert_eq!(recs[0].algorithm, "least-time");
    }

    #[test]
    fn score_favors_random_two_for_bursty() {
        let mut w = ProfileWindow::new(10);
        w.push(bursty_obs(100.0));
        w.push(bursty_obs(100.0));
        w.push(bursty_obs(100.0));
        w.push(bursty_obs(5000.0));
        w.push(bursty_obs(100.0));

        let profile = w.compute_profile();
        let recs = score_algorithms(&profile);

        assert_eq!(recs[0].algorithm, "random-two-choices");
    }

    // ── Adaptive selector ──────────────────────────────────────────────

    #[test]
    fn selector_switches_on_profile_change() {
        let mut sel = AdaptiveSelector::new(
            "round-robin",
            SwitchPolicy::Aggressive,
            Duration::from_millis(1),
        );

        // Feed sticky traffic.
        for _ in 0..10 {
            sel.observe(sticky_obs());
        }

        match sel.evaluate() {
            AdaptiveDecision::Switch { to, .. } => {
                assert_eq!(to, "cookie-sticky");
            }
            other => panic!("expected Switch, got {other:?}"),
        }

        assert_eq!(sel.current_algorithm(), "cookie-sticky");
        assert_eq!(sel.switch_count(), 1);
    }

    #[test]
    fn selector_keeps_optimal_algorithm() {
        let mut sel = AdaptiveSelector::new(
            "round-robin",
            SwitchPolicy::Conservative,
            Duration::from_millis(1),
        );

        // Feed uniform traffic — round-robin is already optimal.
        for _ in 0..10 {
            sel.observe(uniform_obs());
        }

        match sel.evaluate() {
            AdaptiveDecision::Keep { algorithm, .. } => {
                assert_eq!(algorithm, "round-robin");
            }
            other => panic!("expected Keep, got {other:?}"),
        }
    }

    #[test]
    fn selector_insufficient_data() {
        let mut sel = AdaptiveSelector::new(
            "round-robin",
            SwitchPolicy::Moderate,
            Duration::from_millis(1),
        );

        sel.observe(uniform_obs());

        match sel.evaluate() {
            AdaptiveDecision::Insufficient => {}
            other => panic!("expected Insufficient, got {other:?}"),
        }
    }

    #[test]
    fn selector_respects_cooldown() {
        let mut sel = AdaptiveSelector::new(
            "round-robin",
            SwitchPolicy::Aggressive,
            Duration::from_secs(300), // Long cooldown.
        );

        for _ in 0..10 {
            sel.observe(sticky_obs());
        }
        sel.evaluate(); // Switches.

        // Immediately evaluate again — should be Keep due to cooldown.
        for _ in 0..10 {
            sel.observe(uniform_obs());
        }
        match sel.evaluate() {
            AdaptiveDecision::Keep { .. } => {}
            other => panic!("expected Keep (cooldown), got {other:?}"),
        }
    }

    // ── Switch policy thresholds ───────────────────────────────────────

    #[test]
    fn switch_policy_thresholds() {
        assert!((SwitchPolicy::Conservative.threshold() - 20.0).abs() < 0.001);
        assert!((SwitchPolicy::Moderate.threshold() - 10.0).abs() < 0.001);
        assert!((SwitchPolicy::Aggressive.threshold() - 1.0).abs() < 0.001);
    }

    // ── Coefficient of variation ───────────────────────────────────────

    #[test]
    fn cv_uniform_data() {
        let cv = coefficient_of_variation(&[10.0, 10.0, 10.0, 10.0]);
        assert!(cv < 0.01);
    }

    #[test]
    fn cv_variable_data() {
        let cv = coefficient_of_variation(&[1.0, 100.0, 1.0, 100.0]);
        assert!(cv > 0.5);
    }

    #[test]
    fn cv_empty() {
        assert!((coefficient_of_variation(&[]) - 0.0).abs() < 0.001);
    }

    // ── Global toggle ──────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_adaptive_enabled(true);
        assert!(is_adaptive_enabled());
    }

    // ── Profile window ─────────────────────────────────────────────────

    #[test]
    fn window_evicts_oldest() {
        // Constructor clamps max_size to at least 5.
        let mut w = ProfileWindow::new(5);
        for _ in 0..5 {
            w.push(uniform_obs());
        }
        assert_eq!(w.len(), 5);
        w.push(uniform_obs()); // Should evict oldest.
        assert_eq!(w.len(), 5); // Still at capacity.
    }
}
