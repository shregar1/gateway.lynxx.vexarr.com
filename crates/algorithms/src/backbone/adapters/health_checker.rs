//! HealthChecker adapters — wrap resilience algorithms into the
//! `HealthChecker` trait.

use crate::backbone::traits::HealthChecker;

// ── Starter tier ───────────────────────────────────────────────────

/// Classic 3-state circuit breaker (Closed → Open → HalfOpen).
pub struct CircuitBreakerChecker {
    inner: crate::goals::resilience::circuit_breaker::CircuitBreaker,
}

impl CircuitBreakerChecker {
    pub fn new(threshold: u32, timeout_ms: u64) -> Self {
        Self {
            inner: crate::goals::resilience::circuit_breaker::CircuitBreaker::new(
                threshold,
                timeout_ms,
            ),
        }
    }
}

impl HealthChecker for CircuitBreakerChecker {
    #[inline]
    fn allow_request(&mut self, now_ms: u64) -> bool {
        self.inner.allow_request(now_ms)
    }

    #[inline]
    fn record_success(&mut self, _now_ms: u64) {
        self.inner.record_success();
    }

    #[inline]
    fn record_failure(&mut self, now_ms: u64) {
        self.inner.record_failure_at(now_ms);
    }

    fn name(&self) -> &'static str { "circuit_breaker" }
}

// ── Growth tier ────────────────────────────────────────────────────

/// Fail-fast detector — quick rejection after first failure.
#[cfg(feature = "tier-growth")]
pub struct FailfastChecker {
    inner: crate::goals::resilience::failfast::Failfast,
}

#[cfg(feature = "tier-growth")]
impl FailfastChecker {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            inner: crate::goals::resilience::failfast::Failfast::new(timeout_ms),
        }
    }
}

#[cfg(feature = "tier-growth")]
impl HealthChecker for FailfastChecker {
    #[inline]
    fn allow_request(&mut self, now_ms: u64) -> bool {
        self.inner.is_ready(now_ms)
    }

    #[inline]
    fn record_success(&mut self, now_ms: u64) {
        self.inner.record_success(now_ms);
    }

    #[inline]
    fn record_failure(&mut self, now_ms: u64) {
        self.inner.record_failure(now_ms);
    }

    fn name(&self) -> &'static str { "failfast" }
}

/// Passive health check — windowed success/failure tracking.
#[cfg(feature = "tier-growth")]
pub struct PassiveHealthChecker {
    inner: crate::goals::resilience::passive_health::PassiveHealthCheck,
}

#[cfg(feature = "tier-growth")]
impl PassiveHealthChecker {
    pub fn new(threshold: u32, window_ms: u64) -> Self {
        Self {
            inner: crate::goals::resilience::passive_health::PassiveHealthCheck::new(
                threshold,
                window_ms,
            ),
        }
    }
}

#[cfg(feature = "tier-growth")]
impl HealthChecker for PassiveHealthChecker {
    #[inline]
    fn allow_request(&mut self, now_ms: u64) -> bool {
        self.inner.is_healthy(now_ms)
    }

    #[inline]
    fn record_success(&mut self, now_ms: u64) {
        self.inner.record(true, now_ms);
    }

    #[inline]
    fn record_failure(&mut self, now_ms: u64) {
        self.inner.record(false, now_ms);
    }

    fn name(&self) -> &'static str { "passive_health" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backbone::traits::HealthChecker;

    fn assert_health_checker_contract(hc: &mut dyn HealthChecker) {
        assert!(!hc.name().is_empty());
        // Fresh checker should allow requests
        assert!(hc.allow_request(1000));
        // Success should keep it healthy
        hc.record_success(1001);
        assert!(hc.allow_request(1002));
    }

    #[test]
    fn circuit_breaker_opens_on_failures() {
        let mut cb = CircuitBreakerChecker::new(2, 5000);
        assert_health_checker_contract(&mut cb);

        // Reset and trigger threshold
        let mut cb2 = CircuitBreakerChecker::new(2, 5000);
        cb2.record_failure(100);
        cb2.record_failure(101);
        // After threshold failures, should be open (deny)
        assert!(!cb2.allow_request(102));
        assert_eq!(cb2.name(), "circuit_breaker");
    }

    #[cfg(feature = "tier-growth")]
    #[test]
    fn failfast_contract() {
        let mut ff = FailfastChecker::new(5000);
        assert_health_checker_contract(&mut ff);
        assert_eq!(ff.name(), "failfast");
    }

    #[cfg(feature = "tier-growth")]
    #[test]
    fn passive_health_contract() {
        let mut ph = PassiveHealthChecker::new(3, 10000);
        assert_health_checker_contract(&mut ph);
        assert_eq!(ph.name(), "passive_health");
    }
}
