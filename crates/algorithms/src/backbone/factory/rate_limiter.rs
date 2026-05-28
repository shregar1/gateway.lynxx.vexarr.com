//! Tier selection for RateLimiter.
//!
//! No `create_rate_limiter()` — each type has different constructor args.
//! Use `TierRateLimiter::new(...)` directly.

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierRateLimiter = adapters::rate_limiter::GradientLimiter;

#[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
pub type TierRateLimiter = adapters::rate_limiter::TokenBucketLimiter;

#[cfg(not(feature = "tier-growth"))]
pub type TierRateLimiter = adapters::rate_limiter::LeakyBucketLimiter;
