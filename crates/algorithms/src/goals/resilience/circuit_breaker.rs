/// Three-state circuit breaker (Traefik-style).
///
/// States: Closed (passing traffic), Open (rejecting), HalfOpen (probing).
/// - Closed → Open: after `threshold` consecutive failures.
/// - Open → HalfOpen: after `timeout_ms` elapses.
/// - HalfOpen → Closed: on success.
/// - HalfOpen → Open: on failure.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: State,
    threshold: u32,
    timeout_ms: u64,
    failure_count: u32,
    last_failure_ms: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, timeout_ms: u64) -> Self {
        Self {
            state: State::Closed,
            threshold,
            timeout_ms,
            failure_count: 0,
            last_failure_ms: 0,
        }
    }

    /// Check if a request should be allowed at time `now_ms`.
    pub fn allow_request(&mut self, now_ms: u64) -> bool {
        match self.state {
            State::Closed => true,
            State::Open => {
                if now_ms.saturating_sub(self.last_failure_ms) >= self.timeout_ms {
                    self.state = State::HalfOpen;
                    true // allow one probe
                } else {
                    false
                }
            }
            State::HalfOpen => {
                // Only one request at a time in half-open
                false
            }
        }
    }

    pub fn record_success(&mut self) {
        match self.state {
            State::HalfOpen => {
                self.state = State::Closed;
                self.failure_count = 0;
            }
            State::Closed => {
                self.failure_count = 0;
            }
            State::Open => {}
        }
    }

    pub fn record_failure(&mut self) {
        match self.state {
            State::HalfOpen => {
                self.state = State::Open;
                // keep last_failure_ms (will be reset on next allow_request timeout)
            }
            State::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.threshold {
                    self.state = State::Open;
                    // last_failure_ms will be set by caller or we use a sentinel
                }
            }
            State::Open => {}
        }
    }

    /// Record failure with timestamp (for timeout tracking).
    fn set_last_failure(&mut self, now_ms: u64) {
        self.last_failure_ms = now_ms;
    }

    /// Combined record_failure + timestamp.
    pub fn record_failure_at(&mut self, now_ms: u64) {
        self.set_last_failure(now_ms);
        self.record_failure();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_allows() {
        let mut cb = CircuitBreaker::new(3, 5000);
        assert!(cb.allow_request(0));
    }

    #[test]
    fn opens_after_threshold() {
        let mut cb = CircuitBreaker::new(3, 5000);
        for _ in 0..3 {
            cb.record_failure_at(100);
        }
        assert!(!cb.allow_request(100));
    }

    #[test]
    fn half_open_after_timeout() {
        let mut cb = CircuitBreaker::new(2, 1000);
        cb.record_failure_at(0);
        cb.record_failure_at(0);
        assert!(!cb.allow_request(500)); // still open
        assert!(cb.allow_request(1000)); // transitions to half-open, allows probe
        assert!(!cb.allow_request(1001)); // half-open rejects second
    }

    #[test]
    fn success_in_half_open_closes() {
        let mut cb = CircuitBreaker::new(2, 1000);
        cb.record_failure_at(0);
        cb.record_failure_at(0);
        cb.allow_request(1000); // half-open
        cb.record_success();
        assert!(cb.allow_request(1001)); // back to closed
    }

    #[test]
    fn failure_in_half_open_reopens() {
        let mut cb = CircuitBreaker::new(2, 1000);
        cb.record_failure_at(0);
        cb.record_failure_at(0);
        cb.allow_request(1000); // half-open
        cb.record_failure_at(1000);
        assert!(!cb.allow_request(1001)); // back to open
    }
}
