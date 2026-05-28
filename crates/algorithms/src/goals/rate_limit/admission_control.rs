/// Client-side adaptive admission control (Envoy-style).
///
/// Tracks recent request outcomes in a sliding window and computes a
/// rejection probability from the ratio of failures. When the backend
/// is healthy the probability stays near 0; under overload it rises
/// towards 1, shedding load before it reaches the server.

use std::collections::VecDeque;

pub struct AdmissionController {
    window: VecDeque<bool>,
    window_size: usize,
    successes: u64,
    total: u64,
}

impl AdmissionController {
    pub fn new(window_size: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size,
            successes: 0,
            total: 0,
        }
    }

    pub fn record(&mut self, success: bool) {
        if self.window.len() >= self.window_size {
            if let Some(old) = self.window.pop_front() {
                self.total -= 1;
                if old {
                    self.successes -= 1;
                }
            }
        }
        self.window.push_back(success);
        self.total += 1;
        if success {
            self.successes += 1;
        }
    }

    /// Probability that a new request should be rejected (0.0 = healthy).
    pub fn rejection_probability(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let success_rate = self.successes as f64 / self.total as f64;
        // Envoy formula: max(0, (total - successes / success_rate) / (total + 1))
        // Simplified: rejection_prob = 1 - success_rate^2 when success_rate < 1
        let p = 1.0 - success_rate;
        // Amplify: requests * (1 - 1/ratio) clamped to [0, 1]
        (p * (2.0 - success_rate)).clamp(0.0, 1.0)
    }

    /// Deterministic admission check (no randomness for benchmarkability).
    /// Returns true if the request should be admitted.
    pub fn should_admit(&self) -> bool {
        self.rejection_probability() < 0.5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_success_admits() {
        let mut ac = AdmissionController::new(100);
        for _ in 0..100 {
            ac.record(true);
        }
        assert!(ac.should_admit());
        assert!(ac.rejection_probability() < 0.01);
    }

    #[test]
    fn all_failure_rejects() {
        let mut ac = AdmissionController::new(100);
        for _ in 0..100 {
            ac.record(false);
        }
        assert!(!ac.should_admit());
        assert!(ac.rejection_probability() > 0.9);
    }

    #[test]
    fn window_slides() {
        let mut ac = AdmissionController::new(10);
        for _ in 0..10 {
            ac.record(false);
        }
        assert!(!ac.should_admit());
        // Now push 10 successes — old failures slide out
        for _ in 0..10 {
            ac.record(true);
        }
        assert!(ac.should_admit());
    }

    #[test]
    fn empty_admits() {
        let ac = AdmissionController::new(10);
        assert!(ac.should_admit());
    }
}
