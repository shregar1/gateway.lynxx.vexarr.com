//! RateLimiter adapters — wrap rate-limiting algorithms into the
//! `RateLimiter` trait.

use crate::backbone::traits::{RateLimitContext, RateLimiter};

// ── Starter tier ───────────────────────────────────────────────────

/// Leaky-bucket rate limiter.
///
/// Wraps the stateless leaky-bucket functions with the minimal state
/// needed to track excess and timestamps.
pub struct LeakyBucketLimiter {
    /// Configured rate (requests per second * 1000).
    rate: u32,
    /// Maximum burst above rate.
    burst: u32,
    /// Current excess value (accumulated).
    stored_excess: i64,
    /// Timestamp of last request (milliseconds).
    ///
    /// `ngx_limit_req_excess` is millisecond-native (it computes
    /// `rate * ms / 1000`), so this must be stored in the same unit as
    /// the value handed to that function — see `allow`.
    last_ms: i64,
}

impl LeakyBucketLimiter {
    /// Create a new leaky-bucket rate limiter.
    ///
    /// - `rate`: requests per second * 1000 (e.g. 1000 = 1 req/s)
    /// - `burst`: number of excess requests allowed
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate,
            burst,
            stored_excess: 0,
            last_ms: 0,
        }
    }
}

impl RateLimiter for LeakyBucketLimiter {
    #[inline]
    fn allow(&mut self, ctx: &RateLimitContext) -> bool {
        // BUG FIX: `ngx_limit_req_excess` is millisecond-native — it treats
        // `now - last` as milliseconds and decays by `rate * ms / 1000`.
        // Previously `ctx.now_ns` (nanoseconds) was passed in verbatim, making
        // the elapsed delta ~1e6x too large; the decay term then dwarfed the
        // `+1000` per-request charge, excess always clamped to 0, and every
        // request was admitted — i.e. the leaky bucket never limited anything.
        // Convert to milliseconds before calling, and keep `last_ms` in the
        // same unit so successive deltas stay consistent.
        let now = (ctx.now_ns / 1_000_000) as i64;
        let excess = lynxx_algo::ngx_limit_req_excess(
            self.stored_excess,
            self.rate,
            now,
            self.last_ms,
        );
        self.last_ms = now;
        if lynxx_algo::ngx_limit_req_allows(excess, self.burst) {
            self.stored_excess = excess as i64;
            true
        } else {
            false
        }
    }

    fn name(&self) -> &'static str { "leaky_bucket" }
}

// ── Growth tier ────────────────────────────────────────────────────

/// Atomic token bucket — lock-free, good burst handling.
pub struct TokenBucketLimiter {
    inner: crate::goals::rate_limit::atomic_token_bucket::AtomicTokenBucket,
}

impl TokenBucketLimiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            inner: crate::goals::rate_limit::atomic_token_bucket::AtomicTokenBucket::new(
                rate, burst,
            ),
        }
    }
}

impl RateLimiter for TokenBucketLimiter {
    #[inline]
    fn allow(&mut self, ctx: &RateLimitContext) -> bool {
        self.inner.consume(ctx.tokens, ctx.now_ns)
    }

    fn name(&self) -> &'static str { "token_bucket" }
}

/// Admission controller — probabilistic rejection based on success rate.
pub struct AdmissionLimiter {
    inner: crate::goals::rate_limit::admission_control::AdmissionController,
}

impl AdmissionLimiter {
    pub fn new(window_size: usize) -> Self {
        Self {
            inner: crate::goals::rate_limit::admission_control::AdmissionController::new(
                window_size,
            ),
        }
    }
}

impl RateLimiter for AdmissionLimiter {
    #[inline]
    fn allow(&mut self, _ctx: &RateLimitContext) -> bool {
        self.inner.should_admit()
    }

    fn name(&self) -> &'static str { "admission_control" }
}

// ── Pro tier ───────────────────────────────────────────────────────

/// Gradient concurrency controller — RTT-aware.
pub struct GradientLimiter {
    inner: crate::goals::rate_limit::gradient_controller::GradientController,
}

impl GradientLimiter {
    pub fn new() -> Self {
        Self {
            inner: crate::goals::rate_limit::gradient_controller::GradientController::new(
                crate::goals::rate_limit::gradient_controller::GradientConfig::default(),
            ),
        }
    }

    pub fn with_config(
        config: crate::goals::rate_limit::gradient_controller::GradientConfig,
    ) -> Self {
        Self {
            inner: crate::goals::rate_limit::gradient_controller::GradientController::new(config),
        }
    }
}

impl Default for GradientLimiter {
    fn default() -> Self { Self::new() }
}

impl RateLimiter for GradientLimiter {
    #[inline]
    fn allow(&mut self, _ctx: &RateLimitContext) -> bool {
        self.inner.should_allow()
    }

    fn name(&self) -> &'static str { "gradient" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaky_bucket_allows_within_rate() {
        let mut rl = LeakyBucketLimiter::new(1000, 0); // 1 req/s, no burst
        let ctx = RateLimitContext::new(1_000_000_000); // 1s in ns
        // First request at t=1s should be allowed
        assert!(rl.allow(&ctx));
        assert_eq!(rl.name(), "leaky_bucket");
    }

    #[test]
    fn leaky_bucket_rejects_second_request_one_ms_apart() {
        // Regression: rate=1000 (1 req/s), burst=0. Two requests issued only
        // 1ms apart must NOT both pass — the second is well within the 1s
        // spacing the rate demands and has to be rejected.
        //
        // Before the unit fix, `now_ns` was fed straight into the ms-native
        // excess formula, so the elapsed delta was ~1e6x inflated, excess
        // always clamped to 0, and BOTH requests were admitted (limiter
        // defeated). With the fix the second request is correctly rejected.
        let mut rl = LeakyBucketLimiter::new(1000, 0);

        let first = RateLimitContext::new(1_000_000_000); // t = 1.000s
        assert!(rl.allow(&first), "first request should be admitted");

        let second = RateLimitContext::new(1_001_000_000); // t = 1.001s (+1ms)
        assert!(
            !rl.allow(&second),
            "second request only 1ms later must be rejected at 1 req/s"
        );
    }

    #[test]
    fn token_bucket_allows_within_burst() {
        let mut rl = TokenBucketLimiter::new(10.0, 10.0); // 10/s, burst 10
        let ctx = RateLimitContext::new(1_000_000_000);
        assert!(rl.allow(&ctx));
        assert_eq!(rl.name(), "token_bucket");
    }

    #[test]
    fn admission_initially_admits() {
        let mut rl = AdmissionLimiter::new(100);
        let ctx = RateLimitContext::new(0);
        // Fresh controller with no history should admit
        assert!(rl.allow(&ctx));
        assert_eq!(rl.name(), "admission_control");
    }

    #[test]
    fn gradient_initially_allows() {
        let mut rl = GradientLimiter::new();
        let ctx = RateLimitContext::new(0);
        assert!(rl.allow(&ctx));
        assert_eq!(rl.name(), "gradient");
    }
}
