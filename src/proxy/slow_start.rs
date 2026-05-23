//! HAProxy-style slow start (server weight ramp-up after recovery).
//!
//! # Architecture
//!
//! ```text
//! Slow Start
//! ├── SlowStartConfig       — Atomic runtime config (enabled, duration, min weight)
//! ├── SlowStartState        — NotStarted / Ramping / Complete
//! ├── SlowStartEntry        — Per-target ramp state + configured weight
//! ├── SlowStartTracker      — DashMap<Uuid, SlowStartEntry> with FastHasher
//! └── SlowStartMetrics      — Ramps started / completed / interrupted counters
//! ```
//!
//! # Why
//!
//! When a backend server transitions from unhealthy to healthy, sending it
//! full-weight traffic immediately can overwhelm it (cold caches, JIT not
//! warmed, connection pools empty). HAProxy's `slowstart` directive ramps
//! the server's effective weight linearly from a floor to its configured
//! weight over a configurable duration, giving the server time to warm up.
//!
//! This module provides the ramp engine that sits between health checks
//! and the load balancer's weight calculation, adjusting effective weights
//! during the warm-up window.

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics — lock-free runtime configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Master kill-switch for slow start. When false, `get_effective_weight`
/// always returns the configured weight immediately.
static SLOW_START_ENABLED: AtomicBool = AtomicBool::new(false);

/// Default slow start duration in milliseconds. Default: 30_000 (30s).
static SLOW_START_DURATION_MS: AtomicU64 = AtomicU64::new(30_000);

/// Enable or disable slow start globally.
pub fn set_slow_start_enabled(enabled: bool) {
    SLOW_START_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if slow start is globally enabled.
pub fn is_slow_start_enabled() -> bool {
    SLOW_START_ENABLED.load(Ordering::Relaxed)
}

/// Set the global slow start duration.
pub fn set_slow_start_duration(duration: Duration) {
    SLOW_START_DURATION_MS.store(duration.as_millis() as u64, Ordering::Relaxed);
}

/// Get the current global slow start duration.
pub fn slow_start_duration() -> Duration {
    Duration::from_millis(SLOW_START_DURATION_MS.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// SlowStartConfig — per-instance configuration with atomic fields
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic runtime configuration for slow start. All fields can be
/// updated lock-free from any thread (e.g. config reload, admin API).
pub struct SlowStartConfig {
    /// Whether slow start is enabled for this instance.
    pub enabled: AtomicBool,
    /// Ramp duration in milliseconds. Default: 30_000 (30 seconds).
    pub duration_ms: AtomicU64,
    /// Minimum weight as a percentage (1–100). The server always receives
    /// at least this fraction of its configured weight so health probes
    /// still reach it. Default: 1 (1%).
    pub min_weight_pct: AtomicU8,
}

impl SlowStartConfig {
    /// Create a new config with default values.
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            duration_ms: AtomicU64::new(30_000),
            min_weight_pct: AtomicU8::new(1),
        }
    }

    /// Get the ramp duration as a `Duration`.
    pub fn duration(&self) -> Duration {
        Duration::from_millis(self.duration_ms.load(Ordering::Relaxed))
    }

    /// Get the minimum weight percentage (1–100).
    pub fn min_pct(&self) -> u8 {
        self.min_weight_pct.load(Ordering::Relaxed)
    }

    /// Check if this instance has slow start enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl Default for SlowStartConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SlowStartState — ramp lifecycle
// ═══════════════════════════════════════════════════════════════════════════

/// Lifecycle state of a slow start ramp for a single target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlowStartState {
    /// Target has not begun a ramp (either never recovered, or was
    /// explicitly reset).
    NotStarted,
    /// Target is actively ramping. Weight increases linearly from
    /// min_weight to `target_weight` over the configured duration.
    Ramping {
        started_at: Instant,
        target_weight: u32,
    },
    /// Ramp completed — target receives full configured weight.
    Complete,
}

// ═══════════════════════════════════════════════════════════════════════════
// SlowStartEntry — per-target ramp state
// ═══════════════════════════════════════════════════════════════════════════

/// Per-target slow start entry stored in the tracker's `DashMap`.
pub struct SlowStartEntry {
    /// Current ramp state.
    pub state: SlowStartState,
    /// The target's configured weight (what it should reach after ramp).
    pub configured_weight: u32,
    /// When the ramp started (if currently ramping).
    pub started_at: Option<Instant>,
}

impl SlowStartEntry {
    /// Create a new entry in `NotStarted` state.
    pub fn new(configured_weight: u32) -> Self {
        Self {
            state: SlowStartState::NotStarted,
            configured_weight,
            started_at: None,
        }
    }

    /// Compute the effective weight at time `now` given the ramp `duration`
    /// and minimum weight percentage `min_pct`.
    ///
    /// Formula: `max(min_weight, configured_weight * elapsed / duration)`
    ///
    /// When elapsed >= duration, returns full `configured_weight` and
    /// transitions to `Complete`.
    pub fn effective_weight(&mut self, now: Instant, duration: Duration, min_pct: u8) -> u32 {
        let min_weight = self.min_weight(min_pct);

        match &self.state {
            SlowStartState::NotStarted => self.configured_weight,
            SlowStartState::Complete => self.configured_weight,
            SlowStartState::Ramping {
                started_at,
                target_weight,
            } => {
                let target = *target_weight;
                let elapsed = now.duration_since(*started_at);

                if elapsed >= duration {
                    // Ramp complete — transition to Complete.
                    self.state = SlowStartState::Complete;
                    self.configured_weight
                } else {
                    // Linear interpolation: weight = configured * (elapsed / duration).
                    let elapsed_ms = elapsed.as_millis() as u64;
                    let duration_ms = duration.as_millis() as u64;
                    let ramped = if duration_ms > 0 {
                        (target as u64 * elapsed_ms / duration_ms) as u32
                    } else {
                        target
                    };
                    ramped.max(min_weight)
                }
            }
        }
    }

    /// Compute the minimum weight floor from the configured weight and
    /// the minimum percentage.
    fn min_weight(&self, min_pct: u8) -> u32 {
        let pct = (min_pct as u32).clamp(1, 100);
        (self.configured_weight * pct / 100).max(1)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SlowStartMetrics — atomic counters for observability
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters tracking slow start ramp events. Lock-free,
/// safe to read from any thread (e.g. metrics endpoint).
pub struct SlowStartMetrics {
    /// Number of ramps started (unhealthy → healthy transitions).
    pub ramps_started: AtomicU64,
    /// Number of ramps that completed the full duration.
    pub ramps_completed: AtomicU64,
    /// Number of ramps interrupted (target went unhealthy during ramp).
    pub ramps_interrupted: AtomicU64,
}

impl SlowStartMetrics {
    /// Create a new zeroed metrics instance.
    pub const fn new() -> Self {
        Self {
            ramps_started: AtomicU64::new(0),
            ramps_completed: AtomicU64::new(0),
            ramps_interrupted: AtomicU64::new(0),
        }
    }
}

/// Global slow start metrics instance.
static SLOW_START_METRICS: SlowStartMetrics = SlowStartMetrics::new();

/// Get a reference to the global slow start metrics.
pub fn slow_start_metrics() -> &'static SlowStartMetrics {
    &SLOW_START_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// SlowStartTracker — the main tracker used by the LB module
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks slow start state for all targets. Thread-safe via `DashMap`
/// with `ahash::RandomState` for fast hashing. The LB module calls
/// `get_effective_weight()` on every pick and `on_health_change()` when
/// health check results arrive.
pub struct SlowStartTracker {
    entries: DashMap<Uuid, SlowStartEntry, FastHasher>,
    config: SlowStartConfig,
}

impl SlowStartTracker {
    /// Create a new tracker with default configuration.
    pub fn new() -> Self {
        Self {
            entries: DashMap::with_hasher(FastHasher::default()),
            config: SlowStartConfig::new(),
        }
    }

    /// Create a new tracker with custom configuration.
    pub fn with_config(config: SlowStartConfig) -> Self {
        Self {
            entries: DashMap::with_hasher(FastHasher::default()),
            config,
        }
    }

    /// Called by the health checker when a target's health status changes.
    ///
    /// - **unhealthy → healthy**: starts a new ramp from min_weight to
    ///   `configured_weight` over the configured duration.
    /// - **healthy → unhealthy**: if the target is currently ramping,
    ///   increments `ramps_interrupted` and resets to `NotStarted`.
    pub fn on_health_change(&self, target_id: Uuid, healthy: bool, configured_weight: u32) {
        if healthy {
            // Unhealthy → healthy: start a ramp (only if not already
            // ramping or complete).
            let mut entry = self
                .entries
                .entry(target_id)
                .or_insert_with(|| SlowStartEntry::new(configured_weight));

            match &entry.state {
                SlowStartState::NotStarted => {
                    let now = Instant::now();
                    entry.state = SlowStartState::Ramping {
                        started_at: now,
                        target_weight: configured_weight,
                    };
                    entry.started_at = Some(now);
                    entry.configured_weight = configured_weight;
                    SLOW_START_METRICS
                        .ramps_started
                        .fetch_add(1, Ordering::Relaxed);
                }
                SlowStartState::Ramping { .. } | SlowStartState::Complete => {
                    // Already ramping or complete — no-op. Don't restart
                    // on duplicate healthy signals.
                }
            }
        } else {
            // Healthy → unhealthy: reset to NotStarted.
            if let Some(mut entry) = self.entries.get_mut(&target_id) {
                let was_ramping = matches!(entry.state, SlowStartState::Ramping { .. });
                entry.state = SlowStartState::NotStarted;
                entry.started_at = None;
                if was_ramping {
                    SLOW_START_METRICS
                        .ramps_interrupted
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Get the effective weight for a target, accounting for slow start.
    /// If slow start is disabled or the target is not tracked, returns
    /// `configured_weight` unchanged.
    pub fn get_effective_weight(&self, target_id: Uuid, configured_weight: u32) -> u32 {
        if !self.config.is_enabled() {
            return configured_weight;
        }

        let duration = self.config.duration();
        let min_pct = self.config.min_pct();

        match self.entries.get_mut(&target_id) {
            Some(mut entry) => {
                let now = Instant::now();
                let was_ramping = matches!(entry.state, SlowStartState::Ramping { .. });
                let weight = entry.effective_weight(now, duration, min_pct);

                // If the entry just transitioned to Complete, record it.
                if was_ramping && matches!(entry.state, SlowStartState::Complete) {
                    SLOW_START_METRICS
                        .ramps_completed
                        .fetch_add(1, Ordering::Relaxed);
                }

                weight
            }
            None => configured_weight,
        }
    }

    /// Check if a target is currently in the ramping phase.
    pub fn is_ramping(&self, target_id: Uuid) -> bool {
        self.entries
            .get(&target_id)
            .map(|e| matches!(e.state, SlowStartState::Ramping { .. }))
            .unwrap_or(false)
    }

    /// Remove a target from the tracker entirely (e.g. target deleted).
    pub fn remove_target(&self, target_id: Uuid) {
        self.entries.remove(&target_id);
    }

    /// Number of tracked targets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the tracker has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a reference to this tracker's configuration.
    pub fn config(&self) -> &SlowStartConfig {
        &self.config
    }
}

impl Default for SlowStartTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_tracker() -> SlowStartTracker {
        let config = SlowStartConfig {
            enabled: AtomicBool::new(true),
            duration_ms: AtomicU64::new(10_000), // 10s for faster tests
            min_weight_pct: AtomicU8::new(1),
        };
        SlowStartTracker::with_config(config)
    }

    fn enabled_tracker_with_duration(duration_ms: u64) -> SlowStartTracker {
        let config = SlowStartConfig {
            enabled: AtomicBool::new(true),
            duration_ms: AtomicU64::new(duration_ms),
            min_weight_pct: AtomicU8::new(1),
        };
        SlowStartTracker::with_config(config)
    }

    fn enabled_tracker_with_min_pct(min_pct: u8) -> SlowStartTracker {
        let config = SlowStartConfig {
            enabled: AtomicBool::new(true),
            duration_ms: AtomicU64::new(10_000),
            min_weight_pct: AtomicU8::new(min_pct),
        };
        SlowStartTracker::with_config(config)
    }

    // ── 1. Default config values ──

    #[test]
    fn default_config_values() {
        let config = SlowStartConfig::new();
        assert!(!config.is_enabled());
        assert_eq!(config.duration_ms.load(Ordering::Relaxed), 30_000);
        assert_eq!(config.min_pct(), 1);
        assert_eq!(config.duration(), Duration::from_millis(30_000));
    }

    // ── 2. Enable/disable toggle ──

    #[test]
    fn enable_disable_toggle() {
        set_slow_start_enabled(false);
        assert!(!is_slow_start_enabled());
        set_slow_start_enabled(true);
        assert!(is_slow_start_enabled());
        set_slow_start_enabled(false);
        assert!(!is_slow_start_enabled());
    }

    // ── 3. effective_weight at t=0 returns min_weight ──

    #[test]
    fn effective_weight_at_start_returns_min_weight() {
        let now = Instant::now();
        let mut entry = SlowStartEntry::new(100);
        entry.state = SlowStartState::Ramping {
            started_at: now,
            target_weight: 100,
        };
        entry.started_at = Some(now);

        // At exactly t=0, elapsed=0, so ramped = 100 * 0 / 10000 = 0.
        // Floor is max(1, 100 * 1 / 100) = 1.
        let weight = entry.effective_weight(now, Duration::from_secs(10), 1);
        assert_eq!(weight, 1, "at t=0 should return min_weight (1% of 100 = 1)");
    }

    // ── 4. effective_weight at t=duration/2 returns ~50% weight ──

    #[test]
    fn effective_weight_at_half_duration() {
        let start = Instant::now();
        let duration = Duration::from_secs(10);
        let half = start + Duration::from_secs(5);

        let mut entry = SlowStartEntry::new(100);
        entry.state = SlowStartState::Ramping {
            started_at: start,
            target_weight: 100,
        };

        let weight = entry.effective_weight(half, duration, 1);
        assert_eq!(weight, 50, "at t=duration/2 should return ~50% of 100");
    }

    // ── 5. effective_weight at t=duration returns full weight ──

    #[test]
    fn effective_weight_at_full_duration() {
        let start = Instant::now();
        let duration = Duration::from_secs(10);
        let end = start + Duration::from_secs(10);

        let mut entry = SlowStartEntry::new(100);
        entry.state = SlowStartState::Ramping {
            started_at: start,
            target_weight: 100,
        };

        let weight = entry.effective_weight(end, duration, 1);
        assert_eq!(weight, 100, "at t=duration should return full weight");
        assert_eq!(
            entry.state,
            SlowStartState::Complete,
            "should transition to Complete"
        );
    }

    // ── 6. effective_weight past duration returns full weight ──

    #[test]
    fn effective_weight_past_duration() {
        let start = Instant::now();
        let duration = Duration::from_secs(10);
        let past = start + Duration::from_secs(20);

        let mut entry = SlowStartEntry::new(100);
        entry.state = SlowStartState::Ramping {
            started_at: start,
            target_weight: 100,
        };

        let weight = entry.effective_weight(past, duration, 1);
        assert_eq!(weight, 100, "past duration should return full weight");
        assert_eq!(entry.state, SlowStartState::Complete);
    }

    // ── 7. on_health_change unhealthy→healthy starts ramp ──

    #[test]
    fn on_health_change_starts_ramp() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        tracker.on_health_change(id, true, 100);

        assert!(
            tracker.is_ramping(id),
            "should be ramping after healthy signal"
        );
        assert_eq!(tracker.len(), 1);
    }

    // ── 8. on_health_change healthy→unhealthy during ramp increments interrupted ──

    #[test]
    fn on_health_change_interrupts_ramp() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        let before = SLOW_START_METRICS.ramps_interrupted.load(Ordering::Relaxed);

        // Start a ramp.
        tracker.on_health_change(id, true, 100);
        assert!(tracker.is_ramping(id));

        // Interrupt it.
        tracker.on_health_change(id, false, 100);
        assert!(!tracker.is_ramping(id));

        let after = SLOW_START_METRICS.ramps_interrupted.load(Ordering::Relaxed);
        assert!(after > before, "ramps_interrupted should have incremented");
    }

    // ── 9. on_health_change double healthy doesn't restart ──

    #[test]
    fn on_health_change_double_healthy_no_restart() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        let before = SLOW_START_METRICS.ramps_started.load(Ordering::Relaxed);

        tracker.on_health_change(id, true, 100);
        let started_at_first = tracker.entries.get(&id).unwrap().started_at;

        tracker.on_health_change(id, true, 100);
        let started_at_second = tracker.entries.get(&id).unwrap().started_at;

        // The start time should not change on the second healthy signal.
        assert_eq!(
            started_at_first, started_at_second,
            "double healthy should not restart the ramp"
        );

        let after = SLOW_START_METRICS.ramps_started.load(Ordering::Relaxed);
        assert!(
            after - before >= 1,
            "ramps_started should increment at least once, delta={}",
            after - before
        );
    }

    // ── 10. is_ramping during ramp ──

    #[test]
    fn is_ramping_during_ramp() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        assert!(
            !tracker.is_ramping(id),
            "unknown target should not be ramping"
        );

        tracker.on_health_change(id, true, 100);
        assert!(tracker.is_ramping(id), "should be ramping after healthy");
    }

    // ── 11. is_ramping after complete ──

    #[test]
    fn is_ramping_after_complete() {
        // Use a very short duration so the ramp completes immediately.
        let tracker = enabled_tracker_with_duration(1); // 1ms
        let id = Uuid::new_v4();

        tracker.on_health_change(id, true, 100);

        // Wait just enough for the ramp to complete.
        std::thread::sleep(Duration::from_millis(5));

        // Calling get_effective_weight triggers the Complete transition.
        let w = tracker.get_effective_weight(id, 100);
        assert_eq!(w, 100);
        assert!(
            !tracker.is_ramping(id),
            "should not be ramping after completion"
        );
    }

    // ── 12. remove_target cleans up ──

    #[test]
    fn remove_target_cleans_up() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        tracker.on_health_change(id, true, 100);
        assert_eq!(tracker.len(), 1);

        tracker.remove_target(id);
        assert_eq!(tracker.len(), 0);
        assert!(!tracker.is_ramping(id));
    }

    // ── 13. get_effective_weight for unknown target returns configured ──

    #[test]
    fn get_effective_weight_unknown_target() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        let w = tracker.get_effective_weight(id, 42);
        assert_eq!(w, 42, "unknown target should return configured weight");
    }

    // ── 14. metrics counting ──

    #[test]
    fn metrics_counting() {
        let tracker = enabled_tracker_with_duration(1); // 1ms
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let started_before = SLOW_START_METRICS.ramps_started.load(Ordering::Relaxed);
        let interrupted_before = SLOW_START_METRICS.ramps_interrupted.load(Ordering::Relaxed);
        let _completed_before = SLOW_START_METRICS.ramps_completed.load(Ordering::Relaxed);

        // Start two ramps.
        tracker.on_health_change(id1, true, 100);
        tracker.on_health_change(id2, true, 100);

        let started_after = SLOW_START_METRICS.ramps_started.load(Ordering::Relaxed);
        assert_eq!(started_after - started_before, 2);

        // Interrupt one.
        tracker.on_health_change(id1, false, 100);
        let interrupted_after = SLOW_START_METRICS.ramps_interrupted.load(Ordering::Relaxed);
        assert_eq!(interrupted_after - interrupted_before, 1);

        // Let the other complete.
        std::thread::sleep(Duration::from_millis(5));
        // Snapshot right before the call that will trigger the completion.
        let completed_before2 = SLOW_START_METRICS.ramps_completed.load(Ordering::Relaxed);
        let _ = tracker.get_effective_weight(id2, 100);
        let completed_after = SLOW_START_METRICS.ramps_completed.load(Ordering::Relaxed);
        // At least 1 new completion from id2 (other tests sharing the
        // global metric may add more, so use >= not ==).
        assert!(
            completed_after > completed_before2,
            "expected at least 1 completion, before={completed_before2} after={completed_after}"
        );
    }

    // ── 15. min_weight_pct floor ──

    #[test]
    fn min_weight_pct_floor() {
        let tracker = enabled_tracker_with_min_pct(10); // 10% floor
        let id = Uuid::new_v4();

        tracker.on_health_change(id, true, 200);

        // At t=0, the ramped weight is 0 but the floor is 10% of 200 = 20.
        let entry = tracker.entries.get(&id).unwrap();
        let _now = entry.started_at.unwrap();
        drop(entry);

        // Access via get_effective_weight to test through the public API.
        // We need to check the weight right at the start time. Since
        // get_effective_weight uses Instant::now(), we test via the entry
        // directly.
        let mut entry_mut = tracker.entries.get_mut(&id).unwrap();
        let started = entry_mut.started_at.unwrap();
        let weight = entry_mut.effective_weight(started, Duration::from_secs(10), 10);
        assert_eq!(
            weight, 20,
            "min_weight_pct=10 with configured_weight=200 should floor at 20"
        );
    }

    // ── 16. disabled tracker returns configured weight ──

    #[test]
    fn disabled_tracker_returns_configured_weight() {
        let tracker = SlowStartTracker::new(); // disabled by default
        let id = Uuid::new_v4();

        // Even after starting a ramp, disabled tracker returns full weight.
        tracker.on_health_change(id, true, 100);
        let w = tracker.get_effective_weight(id, 100);
        assert_eq!(w, 100, "disabled tracker should return configured weight");
    }

    // ── 17. global duration getter/setter ──

    #[test]
    fn global_duration_getter_setter() {
        let original = slow_start_duration();

        set_slow_start_duration(Duration::from_secs(60));
        assert_eq!(slow_start_duration(), Duration::from_secs(60));

        set_slow_start_duration(Duration::from_millis(500));
        assert_eq!(slow_start_duration(), Duration::from_millis(500));

        // Restore original.
        set_slow_start_duration(original);
    }

    // ── 18. effective_weight for NotStarted returns configured ──

    #[test]
    fn effective_weight_not_started_returns_configured() {
        let mut entry = SlowStartEntry::new(75);
        assert_eq!(entry.state, SlowStartState::NotStarted);

        let w = entry.effective_weight(Instant::now(), Duration::from_secs(10), 1);
        assert_eq!(w, 75, "NotStarted should return configured weight");
    }

    // ── 19. effective_weight for Complete returns configured ──

    #[test]
    fn effective_weight_complete_returns_configured() {
        let mut entry = SlowStartEntry::new(75);
        entry.state = SlowStartState::Complete;

        let w = entry.effective_weight(Instant::now(), Duration::from_secs(10), 1);
        assert_eq!(w, 75, "Complete should return configured weight");
    }

    // ── 20. min_weight always at least 1 ──

    #[test]
    fn min_weight_always_at_least_one() {
        // Even with a very small configured_weight, the floor is 1.
        let mut entry = SlowStartEntry::new(1);
        entry.state = SlowStartState::Ramping {
            started_at: Instant::now(),
            target_weight: 1,
        };

        let w = entry.effective_weight(Instant::now(), Duration::from_secs(10), 1);
        assert!(w >= 1, "min_weight should always be at least 1");
    }

    // ── 21. on_health_change unhealthy when not tracked is no-op ──

    #[test]
    fn on_health_change_unhealthy_untracked() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        // Sending unhealthy for an untracked target should not panic or
        // create an entry.
        tracker.on_health_change(id, false, 100);
        assert_eq!(tracker.len(), 0);
    }

    // ── 22. tracker is_empty ──

    #[test]
    fn tracker_is_empty() {
        let tracker = enabled_tracker();
        assert!(tracker.is_empty());

        let id = Uuid::new_v4();
        tracker.on_health_change(id, true, 100);
        assert!(!tracker.is_empty());

        tracker.remove_target(id);
        assert!(tracker.is_empty());
    }

    // ── 23. effective_weight at 25% duration ──

    #[test]
    fn effective_weight_at_quarter_duration() {
        let start = Instant::now();
        let duration = Duration::from_secs(20);
        let quarter = start + Duration::from_secs(5);

        let mut entry = SlowStartEntry::new(200);
        entry.state = SlowStartState::Ramping {
            started_at: start,
            target_weight: 200,
        };

        let weight = entry.effective_weight(quarter, duration, 1);
        assert_eq!(
            weight, 50,
            "at t=duration/4, weight should be ~25% of 200 = 50"
        );
    }

    // ── 24. on_health_change unhealthy on Complete resets to NotStarted ──

    #[test]
    fn unhealthy_after_complete_resets() {
        let tracker = enabled_tracker_with_duration(1); // 1ms
        let id = Uuid::new_v4();

        // Start and complete a ramp.
        tracker.on_health_change(id, true, 100);
        std::thread::sleep(Duration::from_millis(5));
        let _ = tracker.get_effective_weight(id, 100);
        assert!(!tracker.is_ramping(id));

        // Now mark unhealthy — should reset to NotStarted.
        tracker.on_health_change(id, false, 100);
        let entry = tracker.entries.get(&id).unwrap();
        assert_eq!(entry.state, SlowStartState::NotStarted);
    }

    // ── 25. re-ramp after unhealthy→healthy→unhealthy→healthy ──

    #[test]
    fn re_ramp_after_flap() {
        let tracker = enabled_tracker();
        let id = Uuid::new_v4();

        let started_before = SLOW_START_METRICS.ramps_started.load(Ordering::Relaxed);

        // First ramp.
        tracker.on_health_change(id, true, 100);
        assert!(tracker.is_ramping(id));

        // Interrupt.
        tracker.on_health_change(id, false, 100);
        assert!(!tracker.is_ramping(id));

        // Second ramp — should start a new ramp.
        tracker.on_health_change(id, true, 100);
        assert!(tracker.is_ramping(id));

        let started_after = SLOW_START_METRICS.ramps_started.load(Ordering::Relaxed);
        assert_eq!(
            started_after - started_before,
            2,
            "should have started 2 ramps total"
        );
    }
}
