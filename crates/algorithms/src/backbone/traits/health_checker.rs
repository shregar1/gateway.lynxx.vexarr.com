//! HealthChecker trait — endpoint health decisions.

/// Health checker that tracks endpoint success/failure and decides
/// whether to route requests to it.
pub trait HealthChecker {
    /// Returns `true` if the endpoint should receive requests.
    fn allow_request(&mut self, now_ms: u64) -> bool;

    /// Record a successful response.
    fn record_success(&mut self, now_ms: u64);

    /// Record a failed response.
    fn record_failure(&mut self, now_ms: u64);

    fn name(&self) -> &'static str;
}
