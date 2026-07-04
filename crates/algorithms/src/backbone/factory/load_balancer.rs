//! Runtime tier dispatch for `LoadBalancer`.
//!
//! Each tier's load balancer takes different constructor arguments
//! (weight slice vs backend slice vs (count, decay)), so per-tier
//! constructors are exposed. `for_tier_weighted` covers the common
//! case where weights are available for all tiers.

use crate::backbone::adapters::load_balancer::{FwrrLb, MaglevLb, PeakEwmaAdapter};
use crate::backbone::tier::Tier;
use crate::backbone::traits::{LbContext, LoadBalancer};

pub enum TierLoadBalancer {
    Starter(FwrrLb),
    Growth(PeakEwmaAdapter),
    Pro(MaglevLb),
}

impl TierLoadBalancer {
    /// Starter LB — fast weighted round-robin.
    pub fn starter(weights: &[u32]) -> Self {
        TierLoadBalancer::Starter(FwrrLb::new(weights))
    }

    /// Growth LB — peak EWMA latency-aware picker.
    pub fn growth(count: usize, decay_ns: u64) -> Self {
        TierLoadBalancer::Growth(PeakEwmaAdapter::new(count, decay_ns))
    }

    /// Pro LB — Maglev consistent hash.
    pub fn pro(backends: &[&str]) -> Self {
        TierLoadBalancer::Pro(MaglevLb::new(backends))
    }

    /// Construct from a uniform `(weights, backend_names)` pair.
    ///
    /// Builds the right shape for whichever tier is active:
    /// Starter uses `weights`, Growth uses `weights.len()` and a 10s
    /// decay, Pro uses `backend_names`. The slices must agree on
    /// length.
    pub fn for_tier(tier: Tier, weights: &[u32], backend_names: &[&str]) -> Self {
        debug_assert_eq!(
            weights.len(),
            backend_names.len(),
            "weights and backend_names must align"
        );
        match tier {
            Tier::Starter => Self::starter(weights),
            Tier::Growth => Self::growth(weights.len(), 10_000_000_000),
            Tier::Pro => Self::pro(backend_names),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            TierLoadBalancer::Starter(_) => Tier::Starter,
            TierLoadBalancer::Growth(_) => Tier::Growth,
            TierLoadBalancer::Pro(_) => Tier::Pro,
        }
    }
}

impl LoadBalancer for TierLoadBalancer {
    #[inline]
    fn pick(&mut self, ctx: &LbContext<'_>) -> usize {
        match self {
            TierLoadBalancer::Starter(l) => l.pick(ctx),
            TierLoadBalancer::Growth(l) => l.pick(ctx),
            TierLoadBalancer::Pro(l) => l.pick(ctx),
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            TierLoadBalancer::Starter(l) => l.name(),
            TierLoadBalancer::Growth(l) => l.name(),
            TierLoadBalancer::Pro(l) => l.name(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            TierLoadBalancer::Starter(l) => l.len(),
            TierLoadBalancer::Growth(l) => l.len(),
            TierLoadBalancer::Pro(l) => l.len(),
        }
    }
}
