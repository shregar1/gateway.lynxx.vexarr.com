//! Runtime tier dispatch for `HealthChecker`.
//!
//! Starter uses the classic circuit breaker; Growth and Pro upgrade to
//! windowed passive health checks (more accurate, slightly more state).

use crate::backbone::adapters::health_checker::{
    CircuitBreakerChecker, PassiveHealthChecker,
};
use crate::backbone::tier::Tier;
use crate::backbone::traits::HealthChecker;

pub enum TierHealthChecker {
    Starter(CircuitBreakerChecker),
    Growth(PassiveHealthChecker),
    Pro(PassiveHealthChecker),
}

impl TierHealthChecker {
    /// Starter: 3-state circuit breaker.
    ///
    /// - `threshold`: failures before opening
    /// - `timeout_ms`: how long to stay open
    pub fn starter(threshold: u32, timeout_ms: u64) -> Self {
        TierHealthChecker::Starter(CircuitBreakerChecker::new(threshold, timeout_ms))
    }

    /// Growth: windowed passive health check.
    pub fn growth(threshold: u32, window_ms: u64) -> Self {
        TierHealthChecker::Growth(PassiveHealthChecker::new(threshold, window_ms))
    }

    /// Pro: windowed passive health check (same adapter, may diverge
    /// once a higher-accuracy checker is added).
    pub fn pro(threshold: u32, window_ms: u64) -> Self {
        TierHealthChecker::Pro(PassiveHealthChecker::new(threshold, window_ms))
    }

    /// Construct from a uniform `(threshold, time_param_ms)` pair.
    pub fn for_tier(tier: Tier, threshold: u32, time_param_ms: u64) -> Self {
        match tier {
            Tier::Starter => Self::starter(threshold, time_param_ms),
            Tier::Growth => Self::growth(threshold, time_param_ms),
            Tier::Pro => Self::pro(threshold, time_param_ms),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierHealthChecker::Starter(_) => Tier::Starter,
            TierHealthChecker::Growth(_) => Tier::Growth,
            TierHealthChecker::Pro(_) => Tier::Pro,
        }
    }
}

impl HealthChecker for TierHealthChecker {
    #[inline]
    fn allow_request(&mut self, now_ms: u64) -> bool {
        match self {
            TierHealthChecker::Starter(h) => h.allow_request(now_ms),
            TierHealthChecker::Growth(h) => h.allow_request(now_ms),
            TierHealthChecker::Pro(h) => h.allow_request(now_ms),
        }
    }

    #[inline]
    fn record_success(&mut self, now_ms: u64) {
        match self {
            TierHealthChecker::Starter(h) => h.record_success(now_ms),
            TierHealthChecker::Growth(h) => h.record_success(now_ms),
            TierHealthChecker::Pro(h) => h.record_success(now_ms),
        }
    }

    #[inline]
    fn record_failure(&mut self, now_ms: u64) {
        match self {
            TierHealthChecker::Starter(h) => h.record_failure(now_ms),
            TierHealthChecker::Growth(h) => h.record_failure(now_ms),
            TierHealthChecker::Pro(h) => h.record_failure(now_ms),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierHealthChecker::Starter(h) => h.name(),
            TierHealthChecker::Growth(h) => h.name(),
            TierHealthChecker::Pro(h) => h.name(),
        }
    }
}
