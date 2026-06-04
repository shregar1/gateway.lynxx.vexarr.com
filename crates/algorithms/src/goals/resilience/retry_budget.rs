/// Proportional retry limiting (Envoy-style).
///
/// Retries are allowed as long as the retry ratio stays below a configured
/// fraction of total requests. A minimum retries-per-second floor ensures
/// low-traffic services can still retry.

use std::collections::VecDeque;

pub struct RetryBudget {
    ratio: f64,
    min_retries_per_sec: u32,
    /// Timestamped request counts (ms, count).
    requests: VecDeque<(u64, u32)>,
    retries: VecDeque<(u64, u32)>,
    window_ms: u64,
}

impl RetryBudget {
    pub fn new(ratio: f64, min_retries_per_sec: u32) -> Self {
        Self {
            ratio,
            min_retries_per_sec,
            requests: VecDeque::new(),
            retries: VecDeque::new(),
            window_ms: 1000, // 1-second window
        }
    }

    /// Record an outgoing request at time `now_ms`.
    pub fn record_request(&mut self, now_ms: u64) {
        self.expire(now_ms);
        match self.requests.back_mut() {
            Some((ts, count)) if *ts == now_ms => *count += 1,
            _ => self.requests.push_back((now_ms, 1)),
        }
    }

    /// Check if a retry is allowed at time `now_ms`.
    /// If allowed, the retry is recorded.
    pub fn allow_retry(&mut self, now_ms: u64) -> bool {
        self.expire(now_ms);

        let total_requests: u32 = self.requests.iter().map(|(_, c)| c).sum();
        let total_retries: u32 = self.retries.iter().map(|(_, c)| c).sum();

        // Floor: always allow up to min_retries_per_sec
        let elapsed_sec = self.window_ms as f64 / 1000.0;
        let min_allowed = (self.min_retries_per_sec as f64 * elapsed_sec) as u32;
        if total_retries < min_allowed {
            self.record_retry(now_ms);
            return true;
        }

        // Budget check: retries < ratio * requests
        let budget = (total_requests as f64 * self.ratio) as u32;
        if total_retries < budget {
            self.record_retry(now_ms);
            true
        } else {
            false
        }
    }

    fn record_retry(&mut self, now_ms: u64) {
        match self.retries.back_mut() {
            Some((ts, count)) if *ts == now_ms => *count += 1,
            _ => self.retries.push_back((now_ms, 1)),
        }
    }

    fn expire(&mut self, now_ms: u64) {
        while let Some(&(ts, _)) = self.requests.front() {
            if now_ms.saturating_sub(ts) > self.window_ms {
                self.requests.pop_front();
            } else {
                break;
            }
        }
        while let Some(&(ts, _)) = self.retries.front() {
            if now_ms.saturating_sub(ts) > self.window_ms {
                self.retries.pop_front();
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
    fn allows_initial_retries() {
        let mut rb = RetryBudget::new(0.2, 3);
        rb.record_request(0);
        assert!(rb.allow_retry(0));
    }

    #[test]
    fn min_floor_allows() {
        let mut rb = RetryBudget::new(0.0, 5); // 0% ratio but min=5/sec
        rb.record_request(0);
        assert!(rb.allow_retry(0)); // min floor
    }

    #[test]
    fn budget_exhausted() {
        let mut rb = RetryBudget::new(0.1, 0); // 10% ratio, no floor
        for _ in 0..10 {
            rb.record_request(0);
        }
        // Budget = 10 * 0.1 = 1 retry
        assert!(rb.allow_retry(0));
        assert!(!rb.allow_retry(0)); // exhausted
    }

    #[test]
    fn window_expires() {
        let mut rb = RetryBudget::new(0.1, 0);
        for _ in 0..10 {
            rb.record_request(0);
        }
        rb.allow_retry(0); // use the budget
        // After window expires, budget resets
        for _ in 0..10 {
            rb.record_request(1500);
        }
        assert!(rb.allow_retry(1500));
    }
}
