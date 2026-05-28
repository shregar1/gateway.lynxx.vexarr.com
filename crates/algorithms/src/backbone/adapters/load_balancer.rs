//! LoadBalancer adapters — wrap upstream-pick algorithms into the
//! `LoadBalancer` trait.

use crate::backbone::traits::{LbContext, LoadBalancer};

// ── Starter tier ───────────────────────────────────────────────────

/// Fast Weighted Round Robin (HAProxy).
pub struct FwrrLb {
    inner: crate::goals::upstream_pick::fwrr::FwrrSelector,
}

impl FwrrLb {
    pub fn new(weights: &[u32]) -> Self {
        Self {
            inner: crate::goals::upstream_pick::fwrr::FwrrSelector::new(weights),
        }
    }
}

impl LoadBalancer for FwrrLb {
    #[inline]
    fn pick(&mut self, _ctx: &LbContext<'_>) -> usize {
        self.inner.pick()
    }
    fn name(&self) -> &'static str { "fwrr" }
    fn len(&self) -> usize { self.inner.len() }
}

/// Fast Weighted Least Connections (HAProxy).
pub struct FwlcLb {
    inner: crate::goals::upstream_pick::fwlc::FwlcSelector,
}

impl FwlcLb {
    pub fn new(weights: &[u32]) -> Self {
        Self {
            inner: crate::goals::upstream_pick::fwlc::FwlcSelector::new(weights),
        }
    }

    /// Call when a connection to `idx` is established.
    pub fn connect(&self, idx: usize) { self.inner.connect(idx) }

    /// Call when a connection to `idx` is released.
    pub fn release(&self, idx: usize) { self.inner.release(idx) }
}

impl LoadBalancer for FwlcLb {
    #[inline]
    fn pick(&mut self, _ctx: &LbContext<'_>) -> usize {
        self.inner.pick()
    }
    fn name(&self) -> &'static str { "fwlc" }
    fn len(&self) -> usize { self.inner.len() }
}

// ── Growth tier ────────────────────────────────────────────────────

/// Peak EWMA latency-based LB (linkerd2-proxy).
#[cfg(feature = "tier-growth")]
pub struct PeakEwmaAdapter {
    inner: crate::goals::upstream_pick::peak_ewma::PeakEwmaLb,
}

#[cfg(feature = "tier-growth")]
impl PeakEwmaAdapter {
    pub fn new(count: usize, decay_ns: u64) -> Self {
        Self {
            inner: crate::goals::upstream_pick::peak_ewma::PeakEwmaLb::new(count, decay_ns),
        }
    }

    /// Record an RTT observation for backend `idx`.
    pub fn record(&self, idx: usize, rtt_ns: u64, now_ns: u64) {
        self.inner.record(idx, rtt_ns, now_ns);
    }
}

#[cfg(feature = "tier-growth")]
impl LoadBalancer for PeakEwmaAdapter {
    #[inline]
    fn pick(&mut self, ctx: &LbContext<'_>) -> usize {
        self.inner.pick(ctx.now_ns)
    }
    fn name(&self) -> &'static str { "peak_ewma" }
    fn len(&self) -> usize { self.inner.len() }
}

/// Earliest Deadline First scheduler (Envoy).
#[cfg(feature = "tier-growth")]
pub struct EdfLb {
    inner: crate::goals::upstream_pick::edf::EdfScheduler,
}

#[cfg(feature = "tier-growth")]
impl EdfLb {
    pub fn new(weights: &[f64]) -> Self {
        Self {
            inner: crate::goals::upstream_pick::edf::EdfScheduler::new(weights),
        }
    }
}

#[cfg(feature = "tier-growth")]
impl LoadBalancer for EdfLb {
    #[inline]
    fn pick(&mut self, _ctx: &LbContext<'_>) -> usize {
        self.inner.pick()
    }
    fn name(&self) -> &'static str { "edf" }
    fn len(&self) -> usize { self.inner.len() }
}

/// Weighted Random Selection Queue (Envoy).
#[cfg(feature = "tier-growth")]
pub struct WrsqLb {
    inner: crate::goals::upstream_pick::wrsq::WrsqSelector,
}

#[cfg(feature = "tier-growth")]
impl WrsqLb {
    pub fn new(weights: &[f64]) -> Self {
        Self {
            inner: crate::goals::upstream_pick::wrsq::WrsqSelector::new(weights),
        }
    }
}

#[cfg(feature = "tier-growth")]
impl LoadBalancer for WrsqLb {
    #[inline]
    fn pick(&mut self, _ctx: &LbContext<'_>) -> usize {
        self.inner.pick()
    }
    fn name(&self) -> &'static str { "wrsq" }
    fn len(&self) -> usize { self.inner.len() }
}

// ── Pro tier ───────────────────────────────────────────────────────

/// Maglev consistent hash table (Google/Envoy).
#[cfg(feature = "tier-pro")]
pub struct MaglevLb {
    inner: crate::goals::upstream_pick::maglev::MaglevTable,
}

#[cfg(feature = "tier-pro")]
impl MaglevLb {
    pub fn new(backends: &[&str]) -> Self {
        Self {
            inner: crate::goals::upstream_pick::maglev::MaglevTable::new(backends),
        }
    }
}

#[cfg(feature = "tier-pro")]
impl LoadBalancer for MaglevLb {
    #[inline]
    fn pick(&mut self, ctx: &LbContext<'_>) -> usize {
        // Use pre-computed hash_key if available, otherwise hash the key bytes
        let key = ctx.hash_key.unwrap_or_else(|| {
            ctx.key.map_or(0, |k| {
                // MurmurHash2 for key-to-slot mapping
                lynxx_algo::ngx_murmur_hash2(k) as u64
            })
        });
        self.inner.lookup(key)
    }
    fn name(&self) -> &'static str { "maglev" }
    fn len(&self) -> usize { self.inner.backend_count() }
}

/// Bounded consistent hash with load factor (HAProxy).
#[cfg(feature = "tier-pro")]
pub struct BoundedCHashAdapter {
    inner: crate::goals::upstream_pick::chash_bounded::BoundedCHash,
}

#[cfg(feature = "tier-pro")]
impl BoundedCHashAdapter {
    pub fn new(nodes: &[&str], replicas: u32, load_factor: f64) -> Self {
        Self {
            inner: crate::goals::upstream_pick::chash_bounded::BoundedCHash::new(
                nodes, replicas, load_factor,
            ),
        }
    }

    pub fn connect(&self, idx: usize) { self.inner.connect(idx) }
    pub fn release(&self, idx: usize) { self.inner.release(idx) }
}

#[cfg(feature = "tier-pro")]
impl LoadBalancer for BoundedCHashAdapter {
    #[inline]
    fn pick(&mut self, ctx: &LbContext<'_>) -> usize {
        let key = ctx.key.unwrap_or(b"");
        self.inner.pick(key)
    }
    fn name(&self) -> &'static str { "chash_bounded" }
    fn len(&self) -> usize { self.inner.node_count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fwrr_picks_within_range() {
        let mut lb = FwrrLb::new(&[10, 20, 30]);
        let ctx = LbContext::new(0);
        for _ in 0..100 {
            assert!(lb.pick(&ctx) < 3);
        }
    }

    #[test]
    fn fwrr_name_and_len() {
        let lb = FwrrLb::new(&[1, 2]);
        assert_eq!(lb.name(), "fwrr");
        assert_eq!(lb.len(), 2);
        assert!(!lb.is_empty());
    }

    #[test]
    fn fwlc_picks_within_range() {
        let mut lb = FwlcLb::new(&[10, 20]);
        let ctx = LbContext::new(0);
        let idx = lb.pick(&ctx);
        assert!(idx < 2);
    }

    #[cfg(feature = "tier-growth")]
    #[test]
    fn peak_ewma_picks_within_range() {
        let mut lb = PeakEwmaAdapter::new(3, 10_000_000_000);
        let ctx = LbContext::new(1_000_000);
        let idx = lb.pick(&ctx);
        assert!(idx < 3);
    }

    #[cfg(feature = "tier-growth")]
    #[test]
    fn edf_picks_within_range() {
        let mut lb = EdfLb::new(&[1.0, 2.0, 3.0]);
        let ctx = LbContext::new(0);
        let idx = lb.pick(&ctx);
        assert!(idx < 3);
    }

    #[cfg(feature = "tier-pro")]
    #[test]
    fn maglev_picks_within_range() {
        let mut lb = MaglevLb::new(&["a", "b", "c"]);
        let ctx = LbContext::new(0);
        let idx = lb.pick(&ctx);
        assert!(idx < 3);
        assert_eq!(lb.name(), "maglev");
    }

    #[cfg(feature = "tier-pro")]
    #[test]
    fn maglev_deterministic_with_hash_key() {
        let mut lb = MaglevLb::new(&["a", "b", "c"]);
        let ctx = LbContext { now_ns: 0, key: None, hash_key: Some(42) };
        let idx1 = lb.pick(&ctx);
        let idx2 = lb.pick(&ctx);
        assert_eq!(idx1, idx2, "same hash_key must pick same backend");
    }
}
