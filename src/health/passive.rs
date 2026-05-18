//! Passive health checking: track per-target failures in the proxy hot path
//! and mark targets unhealthy when the failure rate exceeds a threshold
//! within a sliding time window. No extra polling — the proxy response
//! itself drives health decisions.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Configuration for passive health monitoring.
#[derive(Debug, Clone)]
pub struct PassiveHealthConfig {
    /// Number of failures within `window` before marking a target unhealthy.
    pub fail_threshold: u32,
    /// Number of successes to re-mark healthy after passive trip.
    pub success_threshold: u32,
    /// Sliding window over which failures are counted.
    pub window: Duration,
    /// HTTP status codes considered a failure (e.g. 502, 503, 504).
    /// Empty = connection errors only.
    pub fail_statuses: Vec<u16>,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            fail_threshold: 3,
            success_threshold: 2,
            window: Duration::from_secs(30),
            fail_statuses: vec![502, 503, 504],
        }
    }
}

/// Per-target sliding window tracker.
struct TargetWindow {
    failures: VecDeque<Instant>,
    consecutive_successes: u32,
    tripped: bool,
}

impl TargetWindow {
    fn new() -> Self {
        Self {
            failures: VecDeque::new(),
            consecutive_successes: 0,
            tripped: false,
        }
    }
}

/// Registry that tracks passive health for all targets across all services.
/// The key is `(service_id, target_id)`.
pub struct PassiveHealthTracker {
    config: PassiveHealthConfig,
    windows: DashMap<(Uuid, Uuid), Mutex<TargetWindow>>,
}

impl PassiveHealthTracker {
    pub fn new(config: PassiveHealthConfig) -> Self {
        Self {
            config,
            windows: DashMap::new(),
        }
    }

    /// Record a successful response from a target.
    /// Returns `true` if the target was previously tripped and has now
    /// recovered (caller should mark it healthy in the LB).
    pub fn record_success(&self, service_id: &Uuid, target_id: &Uuid) -> bool {
        let key = (*service_id, *target_id);
        let entry = self
            .windows
            .entry(key)
            .or_insert_with(|| Mutex::new(TargetWindow::new()));
        let mut w = entry.lock().unwrap();
        w.consecutive_successes = w.consecutive_successes.saturating_add(1);
        if w.tripped && w.consecutive_successes >= self.config.success_threshold {
            w.tripped = false;
            w.failures.clear();
            true // recovered
        } else {
            false
        }
    }

    /// Record a failed response from a target.
    /// Returns `true` if the target just tripped (caller should mark it
    /// unhealthy in the LB).
    pub fn record_failure(&self, service_id: &Uuid, target_id: &Uuid) -> bool {
        let key = (*service_id, *target_id);
        let entry = self
            .windows
            .entry(key)
            .or_insert_with(|| Mutex::new(TargetWindow::new()));
        let mut w = entry.lock().unwrap();
        w.consecutive_successes = 0;
        let now = Instant::now();
        w.failures.push_back(now);
        // Expire old entries outside the window.
        let cutoff = now - self.config.window;
        while w.failures.front().map(|t| *t < cutoff).unwrap_or(false) {
            w.failures.pop_front();
        }
        if !w.tripped && w.failures.len() as u32 >= self.config.fail_threshold {
            w.tripped = true;
            true // just tripped
        } else {
            false
        }
    }

    /// Whether a given status code is considered a passive failure.
    pub fn is_fail_status(&self, status: u16) -> bool {
        self.config.fail_statuses.contains(&status)
    }

    /// Remove tracking data for targets that no longer exist.
    pub fn remove_service(&self, service_id: &Uuid) {
        self.windows.retain(|k, _| k.0 != *service_id);
    }

    /// Remove tracking for a specific target.
    pub fn remove_target(&self, service_id: &Uuid, target_id: &Uuid) {
        self.windows.remove(&(*service_id, *target_id));
    }
}

impl Default for PassiveHealthTracker {
    fn default() -> Self {
        Self::new(PassiveHealthConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_after_threshold() {
        let cfg = PassiveHealthConfig {
            fail_threshold: 3,
            success_threshold: 2,
            window: Duration::from_secs(60),
            fail_statuses: vec![502, 503],
        };
        let tracker = PassiveHealthTracker::new(cfg);
        let sid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        assert!(!tracker.record_failure(&sid, &tid)); // 1
        assert!(!tracker.record_failure(&sid, &tid)); // 2
        assert!(tracker.record_failure(&sid, &tid)); // 3 → tripped!
    }

    #[test]
    fn does_not_double_trip() {
        let cfg = PassiveHealthConfig {
            fail_threshold: 2,
            success_threshold: 1,
            window: Duration::from_secs(60),
            fail_statuses: vec![502],
        };
        let tracker = PassiveHealthTracker::new(cfg);
        let sid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        assert!(!tracker.record_failure(&sid, &tid));
        assert!(tracker.record_failure(&sid, &tid)); // tripped
        assert!(!tracker.record_failure(&sid, &tid)); // already tripped, no re-trigger
    }

    #[test]
    fn recovers_after_success_threshold() {
        let cfg = PassiveHealthConfig {
            fail_threshold: 2,
            success_threshold: 2,
            window: Duration::from_secs(60),
            fail_statuses: vec![502],
        };
        let tracker = PassiveHealthTracker::new(cfg);
        let sid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        tracker.record_failure(&sid, &tid);
        tracker.record_failure(&sid, &tid); // tripped
        assert!(!tracker.record_success(&sid, &tid)); // 1 success — not enough
        assert!(tracker.record_success(&sid, &tid)); // 2 successes → recovered
    }

    #[test]
    fn success_resets_consecutive_count() {
        let cfg = PassiveHealthConfig {
            fail_threshold: 3,
            success_threshold: 1,
            window: Duration::from_secs(60),
            fail_statuses: vec![502],
        };
        let tracker = PassiveHealthTracker::new(cfg);
        let sid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        tracker.record_failure(&sid, &tid); // 1
        tracker.record_failure(&sid, &tid); // 2
        tracker.record_success(&sid, &tid); // resets consecutive
                                            // Failures still in window, but we need a fresh sequence of
                                            // consecutive failures from the tracker's sliding window perspective.
                                            // The window still has 2 failures, so one more should trip.
        assert!(tracker.record_failure(&sid, &tid)); // 3 in window → tripped
    }

    #[test]
    fn is_fail_status_checks_configured_codes() {
        let cfg = PassiveHealthConfig {
            fail_statuses: vec![502, 503, 504],
            ..Default::default()
        };
        let tracker = PassiveHealthTracker::new(cfg);
        assert!(tracker.is_fail_status(502));
        assert!(tracker.is_fail_status(503));
        assert!(!tracker.is_fail_status(200));
        assert!(!tracker.is_fail_status(500));
    }

    #[test]
    fn remove_service_clears_all_targets() {
        let tracker = PassiveHealthTracker::default();
        let sid = Uuid::new_v4();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        tracker.record_failure(&sid, &t1);
        tracker.record_failure(&sid, &t2);
        assert_eq!(tracker.windows.len(), 2);
        tracker.remove_service(&sid);
        assert_eq!(tracker.windows.len(), 0);
    }

    #[test]
    fn independent_targets_tracked_separately() {
        let cfg = PassiveHealthConfig {
            fail_threshold: 2,
            success_threshold: 1,
            window: Duration::from_secs(60),
            fail_statuses: vec![502],
        };
        let tracker = PassiveHealthTracker::new(cfg);
        let sid = Uuid::new_v4();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        tracker.record_failure(&sid, &t1);
        tracker.record_failure(&sid, &t2);
        // t1 has 1 failure, t2 has 1 failure — neither should be tripped.
        assert!(tracker.record_failure(&sid, &t1)); // t1 → 2 → tripped
        assert!(!tracker.record_failure(&sid, &t1)); // already tripped
                                                     // t2 still only has 1 failure.
        assert!(tracker.record_failure(&sid, &t2)); // t2 → 2 → tripped
    }
}
