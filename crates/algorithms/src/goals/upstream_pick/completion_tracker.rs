//! Load completion signaling (linkerd2-proxy).
//!
//! Tracks per-endpoint in-flight requests and success rates. The
//! `best_endpoint` method picks the backend with the highest success rate,
//! breaking ties by fewest in-flight requests.

use std::sync::atomic::{AtomicU64, Ordering};

/// Per-endpoint completion tracker.
pub struct CompletionTracker {
    in_flight: Vec<AtomicU64>,
    successes: Vec<AtomicU64>,
    failures: Vec<AtomicU64>,
    count: usize,
}

impl CompletionTracker {
    /// Create a new tracker for `count` endpoints.
    pub fn new(count: usize) -> Self {
        assert!(count > 0, "count must be > 0");
        Self {
            in_flight: (0..count).map(|_| AtomicU64::new(0)).collect(),
            successes: (0..count).map(|_| AtomicU64::new(0)).collect(),
            failures: (0..count).map(|_| AtomicU64::new(0)).collect(),
            count,
        }
    }

    /// Signal that a request has started on endpoint `idx`.
    pub fn start(&self, idx: usize) {
        self.in_flight[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Signal that a request on endpoint `idx` completed.
    pub fn complete(&self, idx: usize, success: bool) {
        self.in_flight[idx].fetch_sub(1, Ordering::Relaxed);
        if success {
            self.successes[idx].fetch_add(1, Ordering::Relaxed);
        } else {
            self.failures[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Pick the best endpoint: highest success rate, then fewest in-flight.
    pub fn best_endpoint(&self) -> usize {
        let mut best_idx = 0;
        let mut best_rate = -1.0_f64;
        let mut best_inflight = u64::MAX;

        for i in 0..self.count {
            let s = self.successes[i].load(Ordering::Relaxed);
            let f = self.failures[i].load(Ordering::Relaxed);
            let total = s + f;
            let rate = if total > 0 {
                s as f64 / total as f64
            } else {
                1.0 // Unknown endpoints are assumed perfect
            };

            let inflight = self.in_flight[i].load(Ordering::Relaxed);

            if rate > best_rate || (rate == best_rate && inflight < best_inflight) {
                best_rate = rate;
                best_inflight = inflight;
                best_idx = i;
            }
        }
        best_idx
    }

    /// Current in-flight count for endpoint `idx`.
    pub fn in_flight(&self, idx: usize) -> u64 {
        self.in_flight[idx].load(Ordering::Relaxed)
    }

    /// Success rate for endpoint `idx` (0.0 – 1.0), or 1.0 if no data.
    pub fn success_rate(&self, idx: usize) -> f64 {
        let s = self.successes[idx].load(Ordering::Relaxed);
        let f = self.failures[idx].load(Ordering::Relaxed);
        let total = s + f;
        if total == 0 {
            1.0
        } else {
            s as f64 / total as f64
        }
    }

    /// Number of endpoints.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true when there are no endpoints.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_endpoints_assumed_perfect() {
        let t = CompletionTracker::new(3);
        // All unknown — picks first
        assert_eq!(t.best_endpoint(), 0);
    }

    #[test]
    fn prefers_higher_success_rate() {
        let t = CompletionTracker::new(2);
        // Endpoint 0: 50% success
        t.start(0);
        t.complete(0, true);
        t.start(0);
        t.complete(0, false);
        // Endpoint 1: 100% success
        t.start(1);
        t.complete(1, true);

        assert_eq!(t.best_endpoint(), 1);
    }

    #[test]
    fn breaks_ties_by_inflight() {
        let t = CompletionTracker::new(2);
        // Both 100% success
        t.start(0);
        t.complete(0, true);
        t.start(1);
        t.complete(1, true);
        // Add in-flight to endpoint 0
        t.start(0);
        t.start(0);

        assert_eq!(t.best_endpoint(), 1);
    }

    #[test]
    fn inflight_tracking() {
        let t = CompletionTracker::new(1);
        t.start(0);
        t.start(0);
        assert_eq!(t.in_flight(0), 2);
        t.complete(0, true);
        assert_eq!(t.in_flight(0), 1);
    }

    #[test]
    fn success_rate_calculation() {
        let t = CompletionTracker::new(1);
        t.start(0);
        t.complete(0, true);
        t.start(0);
        t.complete(0, true);
        t.start(0);
        t.complete(0, false);
        let rate = t.success_rate(0);
        assert!((rate - 2.0 / 3.0).abs() < 1e-10);
    }
}
