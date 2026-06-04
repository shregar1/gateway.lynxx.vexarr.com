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
    ///
    /// Increments the chosen backend's active-connection count. Callers MUST
    /// balance every `pick()` with exactly one of `record()` (request completed,
    /// with an RTT sample) or `release()` (request failed before producing an
    /// RTT) — otherwise the active count leaks and biases the backend out of
    /// rotation. See the `release()` docs for the bug this asymmetry caused.
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

        // BUG FIX (lost update): the previous load/compute/store sequence was a
        // non-atomic read-modify-write — two concurrent `record()` calls for the
        // same idx could read the same old_bits and the second store would clobber
        // the first, silently dropping an RTT sample. Use a CAS retry loop so every
        // sample is folded into the EWMA atomically.
        let _ = self.ewma_ns[idx].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |old_bits| {
                let old_ewma = f64::from_bits(old_bits);
                let new_ewma = old_ewma + alpha * (rtt - old_ewma);
                // Use peak: take the max of new_ewma and the sample
                let peak = new_ewma.max(rtt);
                Some(peak.to_bits())
            },
        );

        // Decrement active connections.
        // BUG FIX (counter underflow): a plain fetch_sub(1) wraps to u64::MAX when
        // the counter is already 0 (e.g. a completion with no prior pick, or a
        // double-complete). With overflow-checks=false the wrap is silent and the
        // backend's cost becomes ~9.2e22, permanently removing it from selection.
        // Saturate at 0 so an orphan completion is a harmless no-op.
        let _ = self.active[idx].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |x| Some(x.saturating_sub(1)),
        );
    }

    /// Release an active connection for backend `idx` without recording an RTT.
    ///
    /// BUG FIX (resource leak): `pick()` unconditionally increments
    /// `active[idx]`, but the only decrement used to live in `record()`. On the
    /// connection-failure path (backend down / connect timeout) the caller has
    /// no RTT and never calls `record()`, so the counter leaked forever and the
    /// backend's cost (`ewma_rtt * active`) stayed inflated with no self-heal.
    /// This gives the failure path a symmetric counterpart to the `pick()`
    /// increment (mirroring fwlc's `connect`/`release`); it is underflow-safe so
    /// an unmatched release cannot wrap the counter to u64::MAX.
    pub fn release(&self, idx: usize) {
        let _ = self.active[idx].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |x| Some(x.saturating_sub(1)),
        );
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

    // Regression: an orphan `record()` (completion with no prior `pick()`, or a
    // double-complete) used to `fetch_sub(1)` on a 0 counter and wrap to
    // u64::MAX, exploding the backend's cost and removing it from selection.
    // The decrement must now saturate at 0.
    #[test]
    fn orphan_record_does_not_underflow_active() {
        let lb = PeakEwmaLb::new(2, 10_000_000_000);
        // No pick() first: active[0] == 0.
        lb.record(0, 1000, 1);
        assert_eq!(lb.active_conns(0), 0, "orphan record must not wrap to u64::MAX");

        // Double-complete: one pick, two records.
        lb.pick(1); // active[1] == 1
        lb.record(1, 1000, 2); // -> 0
        lb.record(1, 1000, 3); // -> must stay 0, not wrap
        assert_eq!(lb.active_conns(1), 0, "double-complete must not wrap to u64::MAX");

        // The backend must remain selectable (cost finite, not ~9.2e22).
        assert!(lb.pick(4) < 2);
    }

    // Regression: the connection-failure path produces no RTT, so `record()` is
    // never called and the `pick()` increment used to leak forever. `release()`
    // gives that path a symmetric, underflow-safe decrement.
    #[test]
    fn release_balances_pick_on_failure_path() {
        let lb = PeakEwmaLb::new(2, 10_000_000_000);
        let idx = lb.pick(0); // simulate dispatch
        assert_eq!(lb.active_conns(idx), 1);
        lb.release(idx); // simulate connect failure (no RTT recorded)
        assert_eq!(lb.active_conns(idx), 0, "release must reclaim the leaked active count");

        // release on a 0 counter is a harmless no-op, never an underflow.
        lb.release(idx);
        assert_eq!(lb.active_conns(idx), 0);
    }

    // Regression: `record()` used to load/compute/store the EWMA non-atomically,
    // so concurrent same-index records dropped samples and, via the shared
    // active-counter decrement, could lose decrements. With the CAS retry loops
    // every increment is matched by exactly one decrement under contention, so
    // the active count returns to 0.
    #[test]
    fn concurrent_records_do_not_lose_decrements() {
        use std::sync::Arc;

        let lb = Arc::new(PeakEwmaLb::new(1, 10_000_000_000));
        const THREADS: usize = 8;
        const ITERS: usize = 1000;

        // Seed active[0] with exactly THREADS*ITERS outstanding "picks".
        for _ in 0..(THREADS * ITERS) {
            lb.pick(0);
        }
        assert_eq!(lb.active_conns(0), (THREADS * ITERS) as u64);

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let lb = Arc::clone(&lb);
                std::thread::spawn(move || {
                    for i in 0..ITERS {
                        lb.record(0, 1000 + i as u64, i as u64);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // If a single decrement were lost to a non-atomic RMW this would be > 0.
        assert_eq!(
            lb.active_conns(0),
            0,
            "concurrent record() must not lose active-count decrements"
        );
    }
}
