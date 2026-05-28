//! Peak EWMA latency-based load balancer (linkerd2-proxy).
//!
//! Maintains an exponentially weighted moving average of RTT per backend,
//! then picks the backend with the lowest cost = `ewma_rtt * active_conns`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Peak EWMA load balancer.
pub struct PeakEwmaLb {
    /// EWMA of RTT in nanoseconds (stored as u64 bits of f64).
    ewma_ns: Vec<AtomicU64>,
    /// Active connection count per backend.
    active: Vec<AtomicU64>,
    /// Decay constant in nanoseconds.
    decay_ns: u64,
    /// Number of backends.
    count: usize,
}

impl PeakEwmaLb {
    /// Create a new Peak EWMA LB with `count` backends.
    ///
    /// `decay_ns` controls how fast old samples fade (typical: 10_000_000_000
    /// for 10 s).
    pub fn new(count: usize, decay_ns: u64) -> Self {
        assert!(count > 0, "count must be > 0");
        Self {
            ewma_ns: (0..count)
                .map(|_| AtomicU64::new(0))
                .collect(),
            active: (0..count)
                .map(|_| AtomicU64::new(0))
                .collect(),
            decay_ns,
            count,
        }
    }

    /// Pick the backend with the lowest cost.
    ///
    /// Cost = `ewma_rtt * max(active_conns, 1)`. Ties broken by index.
    pub fn pick(&self, now_ns: u64) -> usize {
        let _ = now_ns; // available for future decay-at-pick
        let mut best_idx = 0;
        let mut best_cost = f64::MAX;

        for i in 0..self.count {
            let rtt = f64::from_bits(self.ewma_ns[i].load(Ordering::Relaxed));
            let conns = self.active[i].load(Ordering::Relaxed).max(1) as f64;
            let cost = rtt * conns;
            if cost < best_cost {
                best_cost = cost;
                best_idx = i;
            }
        }
        // Bump active connections for the chosen backend
        self.active[best_idx].fetch_add(1, Ordering::Relaxed);
        best_idx
    }

    /// Record a completed request's RTT and decrement active connections.
    pub fn record(&self, idx: usize, rtt_ns: u64, now_ns: u64) {
        let _ = now_ns; // kept in signature for future timestamp-based decay
        let rtt = rtt_ns as f64;

        // EWMA update: ewma = ewma + alpha * (sample - ewma)
        // where alpha = 1 - exp(-elapsed / decay).  We simplify to a fixed
        // alpha since we don't track per-sample timestamps here.
        let alpha = if self.decay_ns > 0 {
            1.0 - (-1.0_f64 / self.decay_ns as f64).exp()
        } else {
            1.0
        };

        let old_bits = self.ewma_ns[idx].load(Ordering::Relaxed);
        let old_ewma = f64::from_bits(old_bits);
        let new_ewma = old_ewma + alpha * (rtt - old_ewma);

        // Use peak: take the max of new_ewma and the sample
        let peak = new_ewma.max(rtt);
        self.ewma_ns[idx].store(peak.to_bits(), Ordering::Relaxed);

        // Decrement active connections
        self.active[idx].fetch_sub(1, Ordering::Relaxed);
    }

    /// Current EWMA RTT for backend `idx` in nanoseconds.
    pub fn ewma_rtt(&self, idx: usize) -> f64 {
        f64::from_bits(self.ewma_ns[idx].load(Ordering::Relaxed))
    }

    /// Active connections for backend `idx`.
    pub fn active_conns(&self, idx: usize) -> u64 {
        self.active[idx].load(Ordering::Relaxed)
    }

    /// Number of backends.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true when there are no backends.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_lowest_cost() {
        let lb = PeakEwmaLb::new(3, 10_000_000_000);
        // Record different RTTs
        lb.active[0].fetch_add(1, Ordering::Relaxed);
        lb.record(0, 10_000, 1);
        lb.active[1].fetch_add(1, Ordering::Relaxed);
        lb.record(1, 5_000, 2);
        lb.active[2].fetch_add(1, Ordering::Relaxed);
        lb.record(2, 20_000, 3);

        // Backend 1 has lowest RTT → lowest cost
        let picked = lb.pick(4);
        assert_eq!(picked, 1);
    }

    #[test]
    fn new_backends_have_zero_cost() {
        let lb = PeakEwmaLb::new(2, 10_000_000_000);
        // Both have zero EWMA → picks index 0
        assert_eq!(lb.pick(0), 0);
    }

    #[test]
    fn active_conns_incremented_on_pick() {
        let lb = PeakEwmaLb::new(2, 10_000_000_000);
        lb.pick(0);
        assert_eq!(lb.active_conns(0), 1);
    }

    #[test]
    fn record_decrements_active() {
        let lb = PeakEwmaLb::new(1, 10_000_000_000);
        lb.pick(0); // active[0] = 1
        lb.record(0, 1000, 1); // active[0] = 0
        assert_eq!(lb.active_conns(0), 0);
    }
}
