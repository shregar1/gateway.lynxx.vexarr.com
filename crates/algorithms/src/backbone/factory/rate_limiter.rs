//! Runtime tier dispatch for `RateLimiter`.
//!
//! Each tier's rate limiter has different constructor arguments, so
//! the factory exposes per-tier constructors. The caller picks the
//! one matching its license tier; the others are not instantiated.

use crate::backbone::adapters::rate_limiter::{
    GradientLimiter, LeakyBucketLimiter, TokenBucketLimiter,
};
use crate::backbone::tier::Tier;
use crate::backbone::traits::{RateLimitContext, RateLimiter};

pub enum TierRateLimiter {
    Starter(LeakyBucketLimiter),
    Growth(TokenBucketLimiter),
    Pro(GradientLimiter),
}

impl TierRateLimiter {
    /// Starter rate limiter — leaky bucket.
    ///
    /// - `rate`: requests per second * 1000 (e.g. 1000 = 1 req/s)
    /// - `burst`: number of excess requests allowed
    pub fn starter(rate: u32, burst: u32) -> Self {
        TierRateLimiter::Starter(LeakyBucketLimiter::new(rate, burst))
    }

    /// Growth rate limiter — atomic token bucket.
    pub fn growth(rate: f64, burst: f64) -> Self {
        TierRateLimiter::Growth(TokenBucketLimiter::new(rate, burst))
    }

    /// Pro rate limiter — gradient (RTT-aware) controller.
    pub fn pro() -> Self {
        TierRateLimiter::Pro(GradientLimiter::new())
    }

    /// Construct using the tier's default configuration.
    ///
    /// Defaults: 1 req/s with no burst (Starter), 100 req/s with burst
    /// 100 (Growth), gradient defaults (Pro). Call the explicit
    /// per-tier constructor when you need different parameters.
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Starter => TierRateLimiter::starter(1_000, 0),
            Tier::Growth => TierRateLimiter::growth(100.0, 100.0),
            Tier::Pro => TierRateLimiter::pro(),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierRateLimiter::Starter(_) => Tier::Starter,
            TierRateLimiter::Growth(_) => Tier::Growth,
            TierRateLimiter::Pro(_) => Tier::Pro,
        }
    }
}

impl RateLimiter for TierRateLimiter {
    #[inline]
    fn allow(&mut self, ctx: &RateLimitContext) -> bool {
        match self {
            TierRateLimiter::Starter(l) => l.allow(ctx),
            TierRateLimiter::Growth(l) => l.allow(ctx),
            TierRateLimiter::Pro(l) => l.allow(ctx),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierRateLimiter::Starter(l) => l.name(),
            TierRateLimiter::Growth(l) => l.name(),
            TierRateLimiter::Pro(l) => l.name(),
        }
    }
}
