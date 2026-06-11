//! RateLimiter trait — request admission control.

/// Context passed to rate limiters on each request.
pub struct RateLimitContext {
    /// Current timestamp in nanoseconds.
    pub now_ns: u64,
    /// Number of tokens to consume (default 1.0).
    pub tokens: f64,
}

impl RateLimitContext {
    pub fn new(now_ns: u64) -> Self {
        Self {
            now_ns,
            tokens: 1.0,
        }
    }
}

/// Rate limiter that decides whether a request should be admitted.
pub trait RateLimiter {
    /// Returns `true` if the request should be allowed.
    fn allow(&mut self, ctx: &RateLimitContext) -> bool;

    fn name(&self) -> &'static str;
}
