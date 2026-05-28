//! Tier selection for LoadBalancer.
//!
//! No `create_load_balancer()` — each type has different constructor args.
//! Use `TierLoadBalancer::new(...)` directly.

use crate::backbone::adapters;

#[cfg(feature = "tier-pro")]
pub type TierLoadBalancer = adapters::load_balancer::MaglevLb;

#[cfg(all(feature = "tier-growth", not(feature = "tier-pro")))]
pub type TierLoadBalancer = adapters::load_balancer::PeakEwmaAdapter;

#[cfg(not(feature = "tier-growth"))]
pub type TierLoadBalancer = adapters::load_balancer::FwrrLb;
