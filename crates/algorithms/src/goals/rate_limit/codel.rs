//! CoDel (Controlled Delay) active queue management.
//!
//! From RFC 8289 by Nichols & Jacobson (2012). Manages request-queue
//! latency by tracking minimum sojourn time. When the minimum delay
//! exceeds a target for longer than an interval, CoDel enters a
//! dropping state and rejects requests at an increasing rate
//! proportional to `1 / sqrt(count)`.

use std::time::{Duration, Instant};

/// Decision returned by [`CoDel::should_drop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoDelDecision {
    /// The request should be processed normally.
    Accept,
    /// The request should be dropped / rejected.
    Drop,
}

/// CoDel active queue manager.
///
/// Tracks the minimum sojourn (queuing) time over a sliding interval.
/// When that minimum persistently exceeds `target`, enters a dropping
/// state where requests are shed at an increasing rate (interval
/// shrinks by `1 / sqrt(drop_count)`).
pub struct CoDel {
    target: Duration,
    interval: Duration,
    first_above: Option<Instant>,
    drop_next: Instant,
    dropping: bool,
    drop_count: u32,
}

impl CoDel {
    /// Create a new CoDel instance.
    ///
    /// - `target`: acceptable queuing delay (paper default: 5 ms)
    /// - `interval`: measurement window (paper default: 100 ms)
    pub fn new(target: Duration, interval: Duration) -> Self {
        Self {
            target,
            interval,
            first_above: None,
            drop_next: Instant::now(),
            dropping: false,
            drop_count: 0,
        }
    }

    /// Evaluate a dequeued request.
    ///
    /// `sojourn` is how long the request waited in the queue.
    /// Returns [`CoDelDecision::Drop`] when CoDel determines the queue
    /// is persistently over-target and this request should be shed.
    pub fn should_drop(&mut self, sojourn: Duration, now: Instant) -> CoDelDecision {
        if sojourn < self.target {
            self.first_above = None;
            if self.dropping {
                self.dropping = false;
            }
            return CoDelDecision::Accept;
        }

        // sojourn >= target
        match self.first_above {
            None => {
                self.first_above = Some(now);
                CoDelDecision::Accept
            }
            Some(first) => {
                if now.duration_since(first) < self.interval {
                    return CoDelDecision::Accept;
                }

                // Persistent delay — manage drops
                if !self.dropping {
                    self.dropping = true;
                    self.drop_count = 1;
                    let inv_sqrt = 1.0 / (self.drop_count as f64).sqrt();
                    self.drop_next = now
                        + Duration::from_nanos(
                            (self.interval.as_nanos() as f64 * inv_sqrt) as u64,
                        );
                    return CoDelDecision::Drop;
                }

                if now >= self.drop_next {
                    self.drop_count += 1;
                    let inv_sqrt = 1.0 / (self.drop_count as f64).sqrt();
                    self.drop_next =
                        now + Duration::from_nanos(
                            (self.interval.as_nanos() as f64 * inv_sqrt) as u64,
                        );
                    CoDelDecision::Drop
                } else {
                    CoDelDecision::Accept
                }
            }
        }
    }

    /// Reset all state (e.g., when the queue fully drains).
    pub fn reset(&mut self) {
        self.first_above = None;
        self.dropping = false;
        self.drop_count = 0;
    }

    /// Number of drops since entering the current dropping state.
    pub fn drop_count(&self) -> u32 {
        self.drop_count
    }

    /// Whether CoDel is currently in its dropping state.
    pub fn is_dropping(&self) -> bool {
        self.dropping
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_codel() -> CoDel {
        CoDel::new(Duration::from_millis(5), Duration::from_millis(100))
    }

    #[test]
    fn accepts_below_target() {
        let mut c = default_codel();
        let now = Instant::now();
        let decision = c.should_drop(Duration::from_millis(1), now);
        assert_eq!(decision, CoDelDecision::Accept);
        assert!(!c.is_dropping());
    }

    #[test]
    fn accepts_first_above_target() {
        let mut c = default_codel();
        let now = Instant::now();
        let decision = c.should_drop(Duration::from_millis(10), now);
        assert_eq!(decision, CoDelDecision::Accept);
        assert!(!c.is_dropping());
    }

    #[test]
    fn enters_dropping_after_interval() {
        let mut c = default_codel();
        let t0 = Instant::now();

        // First above-target observation
        assert_eq!(c.should_drop(Duration::from_millis(10), t0), CoDelDecision::Accept);

        // Still within the interval
        let t1 = t0 + Duration::from_millis(50);
        assert_eq!(c.should_drop(Duration::from_millis(10), t1), CoDelDecision::Accept);

        // Past the interval
        let t2 = t0 + Duration::from_millis(101);
        assert_eq!(c.should_drop(Duration::from_millis(10), t2), CoDelDecision::Drop);
        assert!(c.is_dropping());
        assert_eq!(c.drop_count(), 1);
    }

    #[test]
    fn exits_dropping_when_sojourn_drops() {
        let mut c = default_codel();
        let t0 = Instant::now();

        c.should_drop(Duration::from_millis(10), t0);
        let t1 = t0 + Duration::from_millis(101);
        c.should_drop(Duration::from_millis(10), t1);
        assert!(c.is_dropping());

        // Sojourn drops below target
        let t2 = t1 + Duration::from_millis(1);
        assert_eq!(c.should_drop(Duration::from_millis(2), t2), CoDelDecision::Accept);
        assert!(!c.is_dropping());
    }

    #[test]
    fn drop_rate_increases_with_count() {
        let mut c = default_codel();
        let t0 = Instant::now();

        c.should_drop(Duration::from_millis(10), t0);
        let t1 = t0 + Duration::from_millis(101);
        assert_eq!(c.should_drop(Duration::from_millis(10), t1), CoDelDecision::Drop);
        assert_eq!(c.drop_count(), 1);

        // First drop set drop_next = t1 + 100ms. Second drop at t1 + 101ms.
        let t2 = t1 + Duration::from_millis(101);
        let d = c.should_drop(Duration::from_millis(10), t2);
        assert_eq!(d, CoDelDecision::Drop);
        assert_eq!(c.drop_count(), 2);

        // Third drop should happen sooner (interval/sqrt(3) ≈ 58ms)
        let t3 = t2 + Duration::from_millis(75);
        let d = c.should_drop(Duration::from_millis(10), t3);
        assert_eq!(d, CoDelDecision::Drop);
        assert_eq!(c.drop_count(), 3);
    }

    #[test]
    fn reset_clears_state() {
        let mut c = default_codel();
        let t0 = Instant::now();

        c.should_drop(Duration::from_millis(10), t0);
        let t1 = t0 + Duration::from_millis(101);
        c.should_drop(Duration::from_millis(10), t1);
        assert!(c.is_dropping());

        c.reset();
        assert!(!c.is_dropping());
        assert_eq!(c.drop_count(), 0);
    }

    #[test]
    fn below_target_resets_first_above() {
        let mut c = default_codel();
        let t0 = Instant::now();

        c.should_drop(Duration::from_millis(10), t0);
        assert!(c.first_above.is_some());

        c.should_drop(Duration::from_millis(1), t0 + Duration::from_millis(10));
        assert!(c.first_above.is_none());
    }

    #[test]
    fn accepts_between_drops() {
        let mut c = default_codel();
        let t0 = Instant::now();

        c.should_drop(Duration::from_millis(10), t0);
        let t1 = t0 + Duration::from_millis(101);
        assert_eq!(c.should_drop(Duration::from_millis(10), t1), CoDelDecision::Drop);

        // Next check too soon for next drop
        let t2 = t1 + Duration::from_millis(10);
        assert_eq!(c.should_drop(Duration::from_millis(10), t2), CoDelDecision::Accept);
    }

    #[test]
    fn zero_sojourn_always_accepts() {
        let mut c = default_codel();
        let now = Instant::now();
        for i in 0..100 {
            let t = now + Duration::from_millis(i);
            assert_eq!(c.should_drop(Duration::ZERO, t), CoDelDecision::Accept);
        }
        assert!(!c.is_dropping());
    }

    #[test]
    fn custom_target_and_interval() {
        let mut c = CoDel::new(Duration::from_millis(20), Duration::from_millis(200));
        let t0 = Instant::now();

        // 15ms < 20ms target → accept
        assert_eq!(c.should_drop(Duration::from_millis(15), t0), CoDelDecision::Accept);

        // 25ms > 20ms target → first above, still accept
        assert_eq!(c.should_drop(Duration::from_millis(25), t0), CoDelDecision::Accept);

        // After 200ms interval → drop
        let t1 = t0 + Duration::from_millis(201);
        assert_eq!(c.should_drop(Duration::from_millis(25), t1), CoDelDecision::Drop);
    }

    #[test]
    fn sustained_overload_increases_drop_count() {
        let mut c = default_codel();
        let t0 = Instant::now();
        let sojourn = Duration::from_millis(50);

        c.should_drop(sojourn, t0);
        let t1 = t0 + Duration::from_millis(101);
        c.should_drop(sojourn, t1); // drop 1

        // Feed many delayed requests well-spaced in time
        let mut t = t1;
        for _ in 0..10 {
            t += Duration::from_millis(200);
            c.should_drop(sojourn, t);
        }
        assert!(c.drop_count() > 2, "drop count should grow: {}", c.drop_count());
    }
}
