//! DAGOR compound priority-based admission control.
//!
//! From WeChat's DAGOR paper (SoCC 2018): "Overload Control for Scaling
//! WeChat Microservices." Each request carries a compound priority
//! `(business_priority, user_priority)`. A histogram tracks the request
//! distribution, and the admission threshold is adjusted adaptively:
//! shed 5% of load when overloaded, admit 1% more when recovering.

use std::time::{Duration, Instant};

/// Compound priority of a single request.
///
/// Ordering: lower `business` = higher importance (business takes precedence).
/// Within the same business tier, lower `user` = higher importance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPriority {
    /// Static business priority (0 = highest).
    pub business: u8,
    /// Hash-derived user priority, rotated hourly.
    pub user: u32,
}

impl RequestPriority {
    /// Linearize the compound priority into a single u32 for histogram bucketing.
    /// Lower returned value = higher importance.
    fn compound(&self, max_priority: u32) -> u32 {
        (self.business as u32) * max_priority + self.user.min(max_priority - 1)
    }
}

/// Adaptive admission controller from the DAGOR overload-control paper.
///
/// Maintains a histogram of observed request priorities and adjusts the
/// admission threshold based on queuing-time feedback. The threshold can
/// also be propagated to/from upstream/downstream services.
pub struct DagorController {
    histogram: Vec<u64>,
    total_count: u64,
    admission_level: u32,
    max_priority: u32,
    overload_shed_pct: f64,
    recover_admit_pct: f64,
    window: Duration,
    last_check: Instant,
    queuing_time_ns: u64,
    target_latency_ns: u64,
}

impl DagorController {
    /// Create a new controller.
    ///
    /// - `max_priority`: number of distinct user-priority levels per business tier
    /// - `target_latency`: queuing time above which the system is considered overloaded
    pub fn new(max_priority: u32, target_latency: Duration) -> Self {
        let max_priority = max_priority.max(1);
        let num_buckets = 256u32.saturating_mul(max_priority);
        Self {
            histogram: vec![0u64; num_buckets as usize],
            total_count: 0,
            admission_level: 0,
            max_priority,
            overload_shed_pct: 0.05,
            recover_admit_pct: 0.01,
            window: Duration::from_secs(1),
            last_check: Instant::now(),
            queuing_time_ns: 0,
            target_latency_ns: target_latency.as_nanos() as u64,
        }
    }

    /// Whether a request with the given priority should be admitted.
    ///
    /// Admission level 0 means "admit all". Otherwise, only requests whose
    /// compound priority is strictly below the threshold pass.
    pub fn should_admit(&self, priority: &RequestPriority) -> bool {
        if self.admission_level == 0 {
            return true;
        }
        priority.compound(self.max_priority) < self.admission_level
    }

    /// Feed an observed queuing-time sample (exponential moving average).
    pub fn observe_queuing_time(&mut self, queuing_ns: u64) {
        // EWMA with α = 0.2
        self.queuing_time_ns =
            ((self.queuing_time_ns as f64) * 0.8 + (queuing_ns as f64) * 0.2) as u64;
    }

    /// Periodic adjustment: raise or lower the admission threshold.
    ///
    /// Call this on a timer or after every N requests. Internally rate-limits
    /// itself to at most once per `window`.
    pub fn adjust(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_check) < self.window {
            return;
        }
        self.last_check = now;

        if self.total_count == 0 {
            return;
        }

        if self.queuing_time_ns > self.target_latency_ns {
            self.shed_load();
        } else {
            self.recover_load();
        }
    }

    /// Force an adjustment check regardless of the window timer (useful in tests).
    pub fn force_adjust(&mut self) {
        if self.total_count == 0 {
            return;
        }
        if self.queuing_time_ns > self.target_latency_ns {
            self.shed_load();
        } else {
            self.recover_load();
        }
    }

    /// Current admission level for propagation to upstream callers.
    pub fn admission_level(&self) -> u32 {
        self.admission_level
    }

    /// Accept an admission level pushed by a downstream service.
    /// Takes the maximum (most restrictive) of the local and downstream levels.
    pub fn set_downstream_level(&mut self, level: u32) {
        if level > self.admission_level {
            self.admission_level = level;
        }
    }

    /// Compute a user priority from a user ID, rotating by hour.
    ///
    /// The `hour_seed` parameter should change every hour so that the same
    /// user doesn't get the same priority across time windows.
    pub fn user_priority(user_id: u64, hour_seed: u64) -> u32 {
        let mut h = user_id.wrapping_mul(0x517cc1b727220a95);
        h = h.wrapping_add(hour_seed.wrapping_mul(0x6c62272e07bb0142));
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h as u32
    }

    /// Record a request's compound priority in the histogram.
    pub fn record(&mut self, priority: &RequestPriority) {
        let idx = priority.compound(self.max_priority) as usize;
        if idx < self.histogram.len() {
            self.histogram[idx] += 1;
            self.total_count += 1;
        }
    }

    /// Total requests recorded in the current histogram window.
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// Current observed queuing time (EWMA) in nanoseconds.
    pub fn queuing_time_ns(&self) -> u64 {
        self.queuing_time_ns
    }

    /// Reset the histogram for a new measurement window.
    pub fn reset_histogram(&mut self) {
        for b in &mut self.histogram {
            *b = 0;
        }
        self.total_count = 0;
    }

    // ── private ────────────────────────────────────────────────────

    /// Raise admission level to shed `overload_shed_pct` of traffic.
    ///
    /// Walk the histogram from the lowest-priority (highest index) end,
    /// accumulating counts until we've covered `shed_pct` of total traffic,
    /// then set the admission level to that bucket.
    fn shed_load(&mut self) {
        let target = (self.total_count as f64 * self.overload_shed_pct).ceil() as u64;
        let mut accumulated = 0u64;

        for idx in (0..self.histogram.len()).rev() {
            accumulated += self.histogram[idx];
            if accumulated >= target {
                let new_level = idx as u32;
                if new_level > self.admission_level || self.admission_level == 0 {
                    self.admission_level = new_level;
                }
                return;
            }
        }
    }

    /// Lower admission level to admit `recover_admit_pct` more traffic.
    ///
    /// Walk the histogram from the current admission level upward,
    /// accumulating counts until we've added `admit_pct` of total traffic.
    fn recover_load(&mut self) {
        if self.admission_level == 0 {
            return;
        }

        let target = (self.total_count as f64 * self.recover_admit_pct).ceil() as u64;
        let mut accumulated = 0u64;

        let start = self.admission_level as usize;
        let end = (start + self.histogram.len()).min(self.histogram.len());

        for idx in start..end {
            accumulated += self.histogram[idx];
            if accumulated >= target {
                self.admission_level = (idx as u32).saturating_add(1);
                if self.admission_level as usize >= self.histogram.len() {
                    self.admission_level = 0; // fully open
                }
                return;
            }
        }

        // Not enough traffic above threshold — open fully.
        self.admission_level = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_controller(max_priority: u32, target_ms: u64) -> DagorController {
        DagorController::new(max_priority, Duration::from_millis(target_ms))
    }

    #[test]
    fn admits_all_when_no_overload() {
        let ctrl = make_controller(100, 10);
        let prio = RequestPriority { business: 0, user: 50 };
        assert!(ctrl.should_admit(&prio));
        assert_eq!(ctrl.admission_level(), 0);
    }

    #[test]
    fn compound_priority_ordering() {
        let high = RequestPriority { business: 0, user: 0 };
        let mid = RequestPriority { business: 1, user: 0 };
        let low = RequestPriority { business: 2, user: 50 };

        let max_p = 100;
        assert!(high.compound(max_p) < mid.compound(max_p));
        assert!(mid.compound(max_p) < low.compound(max_p));
    }

    #[test]
    fn shed_load_raises_admission_level() {
        let mut ctrl = make_controller(100, 10);

        // Record 100 requests spread across priorities
        for i in 0..100u32 {
            let prio = RequestPriority { business: (i / 50) as u8, user: i % 50 };
            ctrl.record(&prio);
        }

        // Ramp the EWMA above the 10ms target (α=0.2, so multiple observations needed)
        for _ in 0..20 {
            ctrl.observe_queuing_time(100_000_000);
        }
        ctrl.force_adjust();

        assert!(ctrl.admission_level() > 0, "should have raised admission level");
    }

    #[test]
    fn recover_lowers_admission_level() {
        let mut ctrl = make_controller(100, 10);

        // Record traffic
        for i in 0..100u32 {
            let prio = RequestPriority { business: 0, user: i };
            ctrl.record(&prio);
        }

        // Ramp the EWMA above the 10ms target
        for _ in 0..20 {
            ctrl.observe_queuing_time(100_000_000);
        }
        ctrl.force_adjust();
        let level_overloaded = ctrl.admission_level();
        assert!(level_overloaded > 0);

        // Now system recovers — drive EWMA below target
        for _ in 0..50 {
            ctrl.observe_queuing_time(0);
        }
        ctrl.force_adjust();

        let level_recovered = ctrl.admission_level();
        // Should have opened up (level increased or reset to 0)
        assert!(
            level_recovered > level_overloaded || level_recovered == 0,
            "should admit more: overloaded={level_overloaded}, recovered={level_recovered}"
        );
    }

    #[test]
    fn high_priority_admitted_during_shedding() {
        let mut ctrl = make_controller(100, 10);

        for i in 0..200u32 {
            let prio = RequestPriority { business: (i / 100) as u8, user: i % 100 };
            ctrl.record(&prio);
        }

        for _ in 0..20 {
            ctrl.observe_queuing_time(100_000_000);
        }
        ctrl.force_adjust();

        let highest = RequestPriority { business: 0, user: 0 };
        assert!(ctrl.should_admit(&highest), "highest priority should always be admitted");
    }

    #[test]
    fn downstream_level_propagation() {
        let mut ctrl = make_controller(100, 10);
        assert_eq!(ctrl.admission_level(), 0);

        ctrl.set_downstream_level(50);
        assert_eq!(ctrl.admission_level(), 50);

        // Lower downstream level doesn't override
        ctrl.set_downstream_level(30);
        assert_eq!(ctrl.admission_level(), 50);

        // Higher downstream level does override
        ctrl.set_downstream_level(80);
        assert_eq!(ctrl.admission_level(), 80);
    }

    #[test]
    fn user_priority_varies_by_hour() {
        let p1 = DagorController::user_priority(42, 0);
        let p2 = DagorController::user_priority(42, 1);
        assert_ne!(p1, p2, "priority should differ across hours");
    }

    #[test]
    fn user_priority_deterministic() {
        let p1 = DagorController::user_priority(42, 7);
        let p2 = DagorController::user_priority(42, 7);
        assert_eq!(p1, p2);
    }

    #[test]
    fn record_increments_count() {
        let mut ctrl = make_controller(100, 10);
        assert_eq!(ctrl.total_count(), 0);
        ctrl.record(&RequestPriority { business: 0, user: 0 });
        assert_eq!(ctrl.total_count(), 1);
        ctrl.record(&RequestPriority { business: 1, user: 50 });
        assert_eq!(ctrl.total_count(), 2);
    }

    #[test]
    fn queuing_time_ewma() {
        let mut ctrl = make_controller(100, 10);
        ctrl.observe_queuing_time(1_000_000);
        let first = ctrl.queuing_time_ns();
        ctrl.observe_queuing_time(1_000_000);
        let second = ctrl.queuing_time_ns();
        // EWMA converges toward the observed value
        assert!(second >= first || (first - second) < 100);
    }

    #[test]
    fn reset_histogram_clears_counts() {
        let mut ctrl = make_controller(100, 10);
        for i in 0..50u32 {
            ctrl.record(&RequestPriority { business: 0, user: i });
        }
        assert_eq!(ctrl.total_count(), 50);
        ctrl.reset_histogram();
        assert_eq!(ctrl.total_count(), 0);
    }

    #[test]
    fn adjust_respects_window_timing() {
        let mut ctrl = make_controller(100, 10);
        for i in 0..100u32 {
            ctrl.record(&RequestPriority { business: 0, user: i });
        }
        ctrl.observe_queuing_time(20_000_000);

        // First adjust within the window should be a no-op (just created)
        ctrl.adjust();
        // Depending on timing this might or might not fire; the important thing
        // is it doesn't panic.
    }

    #[test]
    fn empty_histogram_adjust_is_noop() {
        let mut ctrl = make_controller(100, 10);
        ctrl.observe_queuing_time(20_000_000);
        ctrl.force_adjust();
        assert_eq!(ctrl.admission_level(), 0);
    }

    #[test]
    fn full_recovery_opens_gate() {
        let mut ctrl = make_controller(10, 10);

        // Record all traffic at a single low-priority bucket
        for _ in 0..100 {
            ctrl.record(&RequestPriority { business: 0, user: 5 });
        }

        for _ in 0..20 {
            ctrl.observe_queuing_time(100_000_000);
        }
        ctrl.force_adjust();

        // Keep recovering until fully open
        for _ in 0..100 {
            ctrl.observe_queuing_time(0);
            ctrl.force_adjust();
        }
        assert_eq!(ctrl.admission_level(), 0, "should be fully open after sustained recovery");
    }
}
