//! Tier selection for HealthChecker.
//!
//! No `create_health_checker()` — each type has different constructor args.
//! Use `TierHealthChecker::new(...)` directly.

use crate::backbone::adapters;

#[cfg(feature = "tier-growth")]
pub type TierHealthChecker = adapters::health_checker::PassiveHealthChecker;

#[cfg(not(feature = "tier-growth"))]
pub type TierHealthChecker = adapters::health_checker::CircuitBreakerChecker;
