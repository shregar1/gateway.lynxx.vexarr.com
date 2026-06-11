/// Readiness-based circuit breaker (linkerd2-proxy failfast).
///
/// Unlike a traditional circuit breaker, failfast tracks *readiness*:
/// if no success is observed within `timeout_ms` of the last failure,
/// the service is considered not ready and requests are rejected
/// immediately.

pub struct Failfast {
    timeout_ms: u64,
    last_success_ms: u64,
    last_failure_ms: u64,
    has_failed: bool,
}

impl Failfast {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            last_success_ms: 0,
            last_failure_ms: 0,
            has_failed: false,
        }
    }

    /// Check if the service is ready at time `now_ms`.
    pub fn is_ready(&self, now_ms: u64) -> bool {
        if !self.has_failed {
            return true;
        }
        // If we've had a recent success after the failure, we're ready
        if self.last_success_ms >= self.last_failure_ms {
            return true;
        }
        // If enough time has passed since last failure, allow a probe
        now_ms.saturating_sub(self.last_failure_ms) >= self.timeout_ms
    }

    pub fn record_success(&mut self, now_ms: u64) {
        self.last_success_ms = now_ms;
        self.has_failed = false;
    }

    pub fn record_failure(&mut self, now_ms: u64) {
        self.last_failure_ms = now_ms;
        self.has_failed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_by_default() {
        let ff = Failfast::new(5000);
        assert!(ff.is_ready(0));
    }

    #[test]
    fn not_ready_after_failure() {
        let mut ff = Failfast::new(5000);
        ff.record_failure(100);
        assert!(!ff.is_ready(200));
    }

    #[test]
    fn ready_after_timeout() {
        let mut ff = Failfast::new(1000);
        ff.record_failure(100);
        assert!(!ff.is_ready(500));
        assert!(ff.is_ready(1100));
    }

    #[test]
    fn success_resets() {
        let mut ff = Failfast::new(5000);
        ff.record_failure(100);
        assert!(!ff.is_ready(200));
        ff.record_success(300);
        assert!(ff.is_ready(300));
    }

    #[test]
    fn failure_after_success() {
        let mut ff = Failfast::new(1000);
        ff.record_success(100);
        assert!(ff.is_ready(200));
        ff.record_failure(300);
        assert!(!ff.is_ready(400));
    }
}
