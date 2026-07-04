/// Passive health checker (Traefik-style).
///
/// Monitors the success/failure ratio within a sliding time window.
/// If consecutive failures exceed a threshold, the backend is marked
/// unhealthy until the window expires.

use std::collections::VecDeque;

pub struct PassiveHealthCheck {
    threshold: u32,
    window_ms: u64,
    /// (timestamp_ms, success)
    events: VecDeque<(u64, bool)>,
    consecutive_failures: u32,
    last_failure_ms: u64,
}

impl PassiveHealthCheck {
    pub fn new(threshold: u32, window_ms: u64) -> Self {
        Self {
            threshold,
            window_ms,
            events: VecDeque::new(),
            consecutive_failures: 0,
            last_failure_ms: 0,
        }
    }

    /// Record a success or failure at time `now_ms`.
    pub fn record(&mut self, success: bool, now_ms: u64) {
        self.expire(now_ms);
        self.events.push_back((now_ms, success));
        if success {
            self.consecutive_failures = 0;
        } else {
            self.consecutive_failures += 1;
            self.last_failure_ms = now_ms;
        }
    }

    /// Check if the backend is currently healthy.
    pub fn is_healthy(&self, now_ms: u64) -> bool {
        if self.consecutive_failures >= self.threshold {
            // Unhealthy until the window expires from the last failure
            now_ms.saturating_sub(self.last_failure_ms) >= self.window_ms
        } else {
            true
        }
    }

    fn expire(&mut self, now_ms: u64) {
        while let Some(&(ts, _)) = self.events.front() {
            if now_ms.saturating_sub(ts) > self.window_ms {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_by_default() {
        let phc = PassiveHealthCheck::new(3, 5000);
        assert!(phc.is_healthy(0));
    }

    #[test]
    fn unhealthy_after_threshold() {
        let mut phc = PassiveHealthCheck::new(3, 5000);
        phc.record(false, 100);
        phc.record(false, 200);
        assert!(phc.is_healthy(300)); // only 2 failures
        phc.record(false, 300);
        assert!(!phc.is_healthy(300)); // 3 failures
    }

    #[test]
    fn success_resets() {
        let mut phc = PassiveHealthCheck::new(3, 5000);
        phc.record(false, 100);
        phc.record(false, 200);
        phc.record(true, 300);
        phc.record(false, 400);
        assert!(phc.is_healthy(400)); // only 1 consecutive failure
    }

    #[test]
    fn recovers_after_window() {
        let mut phc = PassiveHealthCheck::new(3, 1000);
        phc.record(false, 0);
        phc.record(false, 1);
        phc.record(false, 2);
        assert!(!phc.is_healthy(500));
        assert!(phc.is_healthy(1002)); // window expired
    }
}
