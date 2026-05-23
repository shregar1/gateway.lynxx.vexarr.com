//! HAProxy-style agent-check — external health agent that dynamically
//! adjusts server weights and admin state via a simple TCP probe protocol.
//!
//! # Architecture
//!
//! ```text
//! AgentCheck (configurable: enabled / disabled)
//! ├── AgentResponse          — Parsed probe response (Up/Down/Drain/Weight/…)
//! ├── AgentState             — Per-target consecutive OK/fail + last response
//! ├── AgentCheckTracker      — DashMap<Uuid, AgentState> with rise/fall logic
//! ├── AgentCheckConfig       — Interval, timeout, rise, fall thresholds
//! └── AgentCheckMetrics      — Atomic counters (checks, timeouts, changes)
//! ```
//!
//! # Protocol
//!
//! HAProxy's agent-check connects to a TCP port on each backend server.
//! The server responds with a single line containing one or more tokens:
//!
//! | Token          | Meaning                              |
//! |----------------|--------------------------------------|
//! | `up`           | Force server healthy                 |
//! | `down`         | Force server unhealthy               |
//! | `drain`        | Enter drain mode (no new connections)|
//! | `maint`        | Enter maintenance mode               |
//! | `ready`        | Exit maintenance/drain               |
//! | `75%`          | Set weight to 75% (1–100)            |
//! | `maxconn:500`  | Set maximum connections              |
//!
//! Tokens are case-insensitive, whitespace-trimmed, and may be combined
//! on a single line (e.g. `"up 75%"`). When combined, weight takes
//! precedence as the returned `AgentResponse`.
//!
//! # Rise / Fall
//!
//! Modeled after HAProxy's `rise` and `fall` parameters:
//!
//! - **rise** (default 2): consecutive successful checks before marking
//!   a server healthy.
//! - **fall** (default 3): consecutive failed checks before marking a
//!   server unhealthy.
//!
//! This prevents flapping from a single transient failure or success.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use uuid::Uuid;

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics — lock-free runtime configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Master kill-switch for agent-check. When false, no probes are sent.
static AGENT_CHECK_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable agent-check globally.
pub fn set_agent_check_enabled(enabled: bool) {
    AGENT_CHECK_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if agent-check is globally enabled.
pub fn is_agent_check_enabled() -> bool {
    AGENT_CHECK_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// AgentCheckConfig
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for agent-check probes. Mirrors HAProxy's
/// `agent-check` directive parameters.
#[derive(Clone, Debug)]
pub struct AgentCheckConfig {
    /// Master switch. When false, probes are skipped even if the global
    /// static is enabled. Default: **true**.
    pub enabled: bool,
    /// Interval between consecutive probes in milliseconds.
    /// HAProxy default: 2000ms. Lynxx default: **5000ms** (more
    /// conservative for cloud workloads).
    pub interval_ms: u64,
    /// TCP connect + read timeout per probe in milliseconds.
    /// Default: **2000ms**.
    pub timeout_ms: u64,
    /// Consecutive successful checks required before marking a server
    /// healthy. HAProxy default: 2. Default: **2**.
    pub rise: u32,
    /// Consecutive failed checks required before marking a server
    /// unhealthy. HAProxy default: 3. Default: **3**.
    pub fall: u32,
}

impl Default for AgentCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 5000,
            timeout_ms: 2000,
            rise: 2,
            fall: 3,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AgentResponse — parsed probe response
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed response from an agent-check TCP probe. Each variant maps to
/// a HAProxy agent-check token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentResponse {
    /// Set server weight to a percentage (1–100).
    Weight(u8),
    /// Set maximum concurrent connections.
    MaxConn(u32),
    /// Force server healthy.
    Up,
    /// Force server unhealthy.
    Down,
    /// Enter drain mode — stop sending new connections but allow
    /// existing ones to complete.
    Drain,
    /// Enter maintenance mode — server is completely out of rotation.
    Maint,
    /// Exit maintenance or drain mode — server is ready to serve.
    Ready,
    /// Unrecognized response string.
    Unknown(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a single agent-check response line into an `AgentResponse`.
///
/// Handles:
/// - Keywords: `up`, `down`, `drain`, `maint`, `ready` (case-insensitive)
/// - Weight: `<number>%` where number is 0–100 (0 is clamped to 1)
/// - MaxConn: `maxconn:<number>`
/// - Combinations: `"up 75%"` — weight takes precedence
/// - Whitespace trimming
///
/// Unknown tokens produce `AgentResponse::Unknown`.
pub fn parse_agent_response(line: &str) -> AgentResponse {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return AgentResponse::Unknown(String::new());
    }

    let lower = trimmed.to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();

    // Track the most significant parsed response. Priority order:
    // Weight > MaxConn > state keywords > Unknown
    let mut best: Option<AgentResponse> = None;

    for token in &tokens {
        if let Some(parsed) = parse_single_token(token) {
            best = Some(match (&best, &parsed) {
                // Weight always wins.
                (_, AgentResponse::Weight(_)) => parsed,
                // MaxConn wins over state keywords.
                (Some(AgentResponse::Weight(_)), _) => best.unwrap(),
                (_, AgentResponse::MaxConn(_)) => parsed,
                (Some(AgentResponse::MaxConn(_)), _) => best.unwrap(),
                // First state keyword wins if no weight/maxconn yet.
                (None, _) => parsed,
                _ => best.unwrap(),
            });
        }
    }

    best.unwrap_or_else(|| AgentResponse::Unknown(trimmed.to_string()))
}

/// Parse a single whitespace-delimited token.
fn parse_single_token(token: &str) -> Option<AgentResponse> {
    match token {
        "up" => Some(AgentResponse::Up),
        "down" => Some(AgentResponse::Down),
        "drain" => Some(AgentResponse::Drain),
        "maint" => Some(AgentResponse::Maint),
        "ready" => Some(AgentResponse::Ready),
        _ => {
            // Check for weight: "<number>%"
            if let Some(num_str) = token.strip_suffix('%') {
                if let Ok(pct) = num_str.parse::<u8>() {
                    // Clamp 0% to 1% — a server at 0% weight receives no
                    // traffic, which is semantically equivalent to `drain`.
                    let clamped = pct.max(1);
                    // Cap at 100%.
                    let capped = clamped.min(100);
                    return Some(AgentResponse::Weight(capped));
                }
            }
            // Check for maxconn: "maxconn:<number>"
            if let Some(num_str) = token.strip_prefix("maxconn:") {
                if let Ok(val) = num_str.parse::<u32>() {
                    return Some(AgentResponse::MaxConn(val));
                }
            }
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AgentState — per-target probe state
// ═══════════════════════════════════════════════════════════════════════════

/// Per-target agent-check state. Tracks consecutive successes/failures
/// and the last probe response.
#[derive(Clone, Debug)]
pub struct AgentState {
    /// Identifier of the upstream target (backend server).
    pub target_id: Uuid,
    /// TCP address of the agent endpoint on the target.
    pub agent_addr: SocketAddr,
    /// Consecutive successful probes since last failure.
    pub consecutive_ok: u32,
    /// Consecutive failed probes since last success.
    pub consecutive_fail: u32,
    /// Last successfully parsed agent response.
    pub last_response: Option<AgentResponse>,
    /// Timestamp of the last probe (success or failure).
    pub last_check: Option<Instant>,
}

// ═══════════════════════════════════════════════════════════════════════════
// AgentCheckTracker — concurrent state map
// ═══════════════════════════════════════════════════════════════════════════

/// Concurrent tracker for all registered agent-check targets. Uses
/// `DashMap` with `ahash` for lock-free reads on the hot path.
pub struct AgentCheckTracker {
    states: DashMap<Uuid, AgentState, FastHasher>,
}

impl AgentCheckTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            states: DashMap::with_hasher(FastHasher::default()),
        }
    }

    /// Register a new target for agent-check probing. If the target is
    /// already registered, its state is reset.
    pub fn register(&self, target_id: Uuid, agent_addr: SocketAddr) {
        self.states.insert(
            target_id,
            AgentState {
                target_id,
                agent_addr,
                consecutive_ok: 0,
                consecutive_fail: 0,
                last_response: None,
                last_check: None,
            },
        );
    }

    /// Remove a target from agent-check tracking.
    pub fn unregister(&self, target_id: Uuid) {
        self.states.remove(&target_id);
    }

    /// Record a successful probe. Increments `consecutive_ok`, resets
    /// `consecutive_fail`, and stores the parsed response.
    pub fn record_success(&self, target_id: Uuid, response: AgentResponse) {
        if let Some(mut entry) = self.states.get_mut(&target_id) {
            entry.consecutive_ok += 1;
            entry.consecutive_fail = 0;
            entry.last_response = Some(response);
            entry.last_check = Some(Instant::now());
        }
    }

    /// Record a failed probe (timeout, connection refused, parse error).
    /// Increments `consecutive_fail`, resets `consecutive_ok`.
    pub fn record_failure(&self, target_id: Uuid) {
        if let Some(mut entry) = self.states.get_mut(&target_id) {
            entry.consecutive_fail += 1;
            entry.consecutive_ok = 0;
            entry.last_check = Some(Instant::now());
        }
    }

    /// Determine if the target's health state should change based on
    /// rise/fall thresholds.
    ///
    /// Returns:
    /// - `Some(true)` — consecutive successes >= `config.rise`, mark healthy.
    /// - `Some(false)` — consecutive failures >= `config.fall`, mark unhealthy.
    /// - `None` — thresholds not yet met, no change.
    pub fn should_change_health(
        &self,
        target_id: &Uuid,
        config: &AgentCheckConfig,
    ) -> Option<bool> {
        let entry = self.states.get(target_id)?;
        if entry.consecutive_ok >= config.rise {
            Some(true)
        } else if entry.consecutive_fail >= config.fall {
            Some(false)
        } else {
            None
        }
    }

    /// Get a snapshot of the current state for a target.
    pub fn get_state(&self, target_id: &Uuid) -> Option<AgentState> {
        self.states.get(target_id).map(|entry| entry.clone())
    }
}

impl Default for AgentCheckTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AgentCheckMetrics — atomic counters
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters tracking agent-check activity. Lock-free, safe to
/// read from any thread (e.g. metrics/prometheus endpoint).
pub struct AgentCheckMetrics {
    /// Total number of agent-check probes attempted.
    pub checks_total: AtomicU64,
    /// Probes that received a valid response.
    pub checks_ok: AtomicU64,
    /// Probes that failed (connection refused, parse error, etc.).
    pub checks_failed: AtomicU64,
    /// Probes that timed out waiting for a response.
    pub checks_timeout: AtomicU64,
    /// Number of weight adjustments applied from agent responses.
    pub weight_changes: AtomicU64,
    /// Number of health state transitions (up→down, down→up, etc.).
    pub state_changes: AtomicU64,
}

impl AgentCheckMetrics {
    /// Create a new zeroed metrics instance.
    const fn new() -> Self {
        Self {
            checks_total: AtomicU64::new(0),
            checks_ok: AtomicU64::new(0),
            checks_failed: AtomicU64::new(0),
            checks_timeout: AtomicU64::new(0),
            weight_changes: AtomicU64::new(0),
            state_changes: AtomicU64::new(0),
        }
    }

    /// Record a successful probe.
    #[inline]
    pub fn record_ok(&self) {
        self.checks_total.fetch_add(1, Ordering::Relaxed);
        self.checks_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed probe.
    #[inline]
    pub fn record_failed(&self) {
        self.checks_total.fetch_add(1, Ordering::Relaxed);
        self.checks_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a timed-out probe.
    #[inline]
    pub fn record_timeout(&self) {
        self.checks_total.fetch_add(1, Ordering::Relaxed);
        self.checks_timeout.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a weight change applied from an agent response.
    #[inline]
    pub fn record_weight_change(&self) {
        self.weight_changes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a health state transition.
    #[inline]
    pub fn record_state_change(&self) {
        self.state_changes.fetch_add(1, Ordering::Relaxed);
    }
}

/// Global agent-check metrics instance.
static AGENT_CHECK_METRICS: AgentCheckMetrics = AgentCheckMetrics::new();

/// Get a reference to the global agent-check metrics.
pub fn agent_check_metrics() -> &'static AgentCheckMetrics {
    &AGENT_CHECK_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parser: keyword tokens ──

    #[test]
    fn parse_up() {
        assert_eq!(parse_agent_response("up"), AgentResponse::Up);
    }

    #[test]
    fn parse_down() {
        assert_eq!(parse_agent_response("down"), AgentResponse::Down);
    }

    #[test]
    fn parse_drain() {
        assert_eq!(parse_agent_response("drain"), AgentResponse::Drain);
    }

    #[test]
    fn parse_maint() {
        assert_eq!(parse_agent_response("maint"), AgentResponse::Maint);
    }

    #[test]
    fn parse_ready() {
        assert_eq!(parse_agent_response("ready"), AgentResponse::Ready);
    }

    // ── Parser: weight ──

    #[test]
    fn parse_weight_75() {
        assert_eq!(parse_agent_response("75%"), AgentResponse::Weight(75));
    }

    #[test]
    fn parse_weight_zero_clamped() {
        // 0% is clamped to 1% — zero weight means no traffic, use drain instead.
        assert_eq!(parse_agent_response("0%"), AgentResponse::Weight(1));
    }

    #[test]
    fn parse_weight_100() {
        assert_eq!(parse_agent_response("100%"), AgentResponse::Weight(100));
    }

    // ── Parser: maxconn ──

    #[test]
    fn parse_maxconn() {
        assert_eq!(
            parse_agent_response("maxconn:1000"),
            AgentResponse::MaxConn(1000)
        );
    }

    // ── Parser: unknown ──

    #[test]
    fn parse_unknown() {
        assert_eq!(
            parse_agent_response("foobar"),
            AgentResponse::Unknown("foobar".to_string())
        );
    }

    // ── Parser: case insensitive ──

    #[test]
    fn parse_case_insensitive_up() {
        assert_eq!(parse_agent_response("UP"), AgentResponse::Up);
        assert_eq!(parse_agent_response("Up"), AgentResponse::Up);
        assert_eq!(parse_agent_response("uP"), AgentResponse::Up);
    }

    // ── Parser: whitespace trimming ──

    #[test]
    fn parse_whitespace_drain() {
        assert_eq!(parse_agent_response("  drain  "), AgentResponse::Drain);
    }

    // ── Parser: combination (weight takes precedence) ──

    #[test]
    fn parse_combination_up_weight() {
        assert_eq!(parse_agent_response("up 75%"), AgentResponse::Weight(75));
    }

    // ── Tracker: register / unregister ──

    #[test]
    fn tracker_register_unregister() {
        let tracker = AgentCheckTracker::new();
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        tracker.register(id, addr);
        assert!(tracker.get_state(&id).is_some());

        tracker.unregister(id);
        assert!(tracker.get_state(&id).is_none());
    }

    // ── Tracker: record_success increments ok, resets fail ──

    #[test]
    fn tracker_record_success() {
        let tracker = AgentCheckTracker::new();
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        tracker.register(id, addr);
        // Simulate a prior failure.
        tracker.record_failure(id);
        assert_eq!(tracker.get_state(&id).unwrap().consecutive_fail, 1);

        // Success resets consecutive_fail.
        tracker.record_success(id, AgentResponse::Up);
        let state = tracker.get_state(&id).unwrap();
        assert_eq!(state.consecutive_ok, 1);
        assert_eq!(state.consecutive_fail, 0);
        assert_eq!(state.last_response, Some(AgentResponse::Up));
    }

    // ── Tracker: record_failure increments fail, resets ok ──

    #[test]
    fn tracker_record_failure() {
        let tracker = AgentCheckTracker::new();
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        tracker.register(id, addr);
        // Simulate a prior success.
        tracker.record_success(id, AgentResponse::Up);
        assert_eq!(tracker.get_state(&id).unwrap().consecutive_ok, 1);

        // Failure resets consecutive_ok.
        tracker.record_failure(id);
        let state = tracker.get_state(&id).unwrap();
        assert_eq!(state.consecutive_fail, 1);
        assert_eq!(state.consecutive_ok, 0);
    }

    // ── Tracker: should_change_health — rise threshold ──

    #[test]
    fn should_change_health_rise() {
        let tracker = AgentCheckTracker::new();
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let config = AgentCheckConfig::default(); // rise = 2

        tracker.register(id, addr);
        tracker.record_success(id, AgentResponse::Up);
        // 1 success — not enough for rise (2).
        assert_eq!(tracker.should_change_health(&id, &config), None);

        tracker.record_success(id, AgentResponse::Up);
        // 2 successes — rise threshold met.
        assert_eq!(tracker.should_change_health(&id, &config), Some(true));
    }

    // ── Tracker: should_change_health — fall threshold ──

    #[test]
    fn should_change_health_fall() {
        let tracker = AgentCheckTracker::new();
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let config = AgentCheckConfig::default(); // fall = 3

        tracker.register(id, addr);
        tracker.record_failure(id);
        tracker.record_failure(id);
        // 2 failures — not enough for fall (3).
        assert_eq!(tracker.should_change_health(&id, &config), None);

        tracker.record_failure(id);
        // 3 failures — fall threshold met.
        assert_eq!(tracker.should_change_health(&id, &config), Some(false));
    }

    // ── Tracker: should_change_health — thresholds not met ──

    #[test]
    fn should_change_health_none() {
        let tracker = AgentCheckTracker::new();
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let config = AgentCheckConfig::default();

        tracker.register(id, addr);
        // No probes yet — neither threshold met.
        assert_eq!(tracker.should_change_health(&id, &config), None);

        // 1 success, then 1 failure — resets, neither threshold met.
        tracker.record_success(id, AgentResponse::Up);
        tracker.record_failure(id);
        assert_eq!(tracker.should_change_health(&id, &config), None);
    }

    // ── Config: default values ──

    #[test]
    fn default_config_values() {
        let config = AgentCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_ms, 5000);
        assert_eq!(config.timeout_ms, 2000);
        assert_eq!(config.rise, 2);
        assert_eq!(config.fall, 3);
    }

    // ── Metrics: increment ──

    #[test]
    fn metrics_increment() {
        let metrics = AgentCheckMetrics::new();

        metrics.record_ok();
        assert_eq!(metrics.checks_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.checks_ok.load(Ordering::Relaxed), 1);

        metrics.record_failed();
        assert_eq!(metrics.checks_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.checks_failed.load(Ordering::Relaxed), 1);

        metrics.record_timeout();
        assert_eq!(metrics.checks_total.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.checks_timeout.load(Ordering::Relaxed), 1);

        metrics.record_weight_change();
        assert_eq!(metrics.weight_changes.load(Ordering::Relaxed), 1);

        metrics.record_state_change();
        assert_eq!(metrics.state_changes.load(Ordering::Relaxed), 1);
    }
}
