/// Folly-inspired lock-free token bucket (Envoy-style).
///
/// Uses an `AtomicU64` to store the available-tokens count (as f64 bits)
/// and a second `AtomicU64` for the last-refill timestamp. All operations
/// are lock-free via compare-and-swap loops.

use std::sync::atomic::{AtomicU64, Ordering};

pub struct AtomicTokenBucket {
    /// Available tokens stored as f64 bits.
    tokens: AtomicU64,
    /// Last refill time in nanoseconds.
    last_ns: AtomicU64,
    /// Tokens added per nanosecond.
    rate_per_ns: f64,
    /// Maximum tokens (burst size).
    burst: f64,
}

impl AtomicTokenBucket {
    /// Create a new token bucket.
    /// `rate` — tokens per second.
    /// `burst` — maximum tokens that can accumulate.
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: AtomicU64::new(burst.to_bits()),
            last_ns: AtomicU64::new(0),
            rate_per_ns: rate / 1_000_000_000.0,
            burst,
        }
    }

    /// Try to consume `tokens` at time `now_ns`.
    /// Returns true if tokens were consumed.
    pub fn consume(&self, tokens: f64, now_ns: u64) -> bool {
        loop {
            let available = self.refill_and_read(now_ns);
            if available < tokens {
                return false;
            }
            let new_val = available - tokens;
            let old_bits = self.tokens.load(Ordering::Relaxed);
            let old_val = f64::from_bits(old_bits);
            // CAS: only succeed if nobody else changed the value
            if (old_val - available).abs() > 0.001 {
                // Value changed under us, retry
                continue;
            }
            match self.tokens.compare_exchange_weak(
                old_bits,
                new_val.to_bits(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Return the number of tokens available at time `now_ns`.
    pub fn available(&self, now_ns: u64) -> f64 {
        self.refill_and_read(now_ns)
    }

    /// Refill tokens based on elapsed time and return the current count.
    ///
    /// BUG FIX (concurrency / over-admission): the previous implementation
    /// split the refill into two *independent* best-effort CASes — it claimed
    /// the `last_ns` interval with one CAS whose result was discarded, then
    /// unconditionally added the locally-computed `added` tokens with a second
    /// CAS. A thread that lost the `last_ns` race would still apply its own
    /// `added` on top of an already-refilled count, so the same time interval
    /// could be refilled twice (or more) under concurrency, inflating the
    /// bucket up to `burst` and silently granting phantom tokens — a rate-limit
    /// bypass exactly under the contention the limiter exists to handle.
    ///
    /// The interval claim and the token credit are now *coupled*: each interval
    /// `[old_ns, now_ns]` is owned by exactly one thread — the one that wins the
    /// `last_ns` CAS — and only that owner credits the corresponding `added`.
    /// A thread that loses the `last_ns` CAS reloads `last_ns` and recomputes
    /// `elapsed`/`added` from the fresh observed timestamp (which now yields
    /// ~0 elapsed for the already-claimed interval), so no interval is ever
    /// credited twice.
    fn refill_and_read(&self, now_ns: u64) -> f64 {
        loop {
            // Observe the exact last-refill timestamp this iteration will act on.
            let old_ns = self.last_ns.load(Ordering::Acquire);
            let elapsed = now_ns.saturating_sub(old_ns);

            if elapsed == 0 {
                // No new interval to credit; just report the current count.
                return f64::from_bits(self.tokens.load(Ordering::Acquire));
            }

            // Recompute `added` from THIS observed `old_ns` every iteration —
            // never reuse a value computed before a failed CAS.
            let added = elapsed as f64 * self.rate_per_ns;

            // Claim the interval. Only the CAS winner is allowed to credit
            // `added`; losers retry and will recompute against the new last_ns.
            if self
                .last_ns
                .compare_exchange_weak(old_ns, now_ns, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                // Another thread advanced last_ns first; recompute from scratch.
                continue;
            }

            // We own interval [old_ns, now_ns]; credit `added` exactly once,
            // clamping to `burst`. Retry only the token sum on contention —
            // `added` is fixed because this interval belongs solely to us.
            loop {
                let cur_bits = self.tokens.load(Ordering::Acquire);
                let current = f64::from_bits(cur_bits);
                let new_val = (current + added).min(self.burst);
                match self.tokens.compare_exchange_weak(
                    cur_bits,
                    new_val.to_bits(),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return new_val,
                    Err(_) => continue,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_within_burst() {
        let tb = AtomicTokenBucket::new(100.0, 10.0);
        assert!(tb.consume(5.0, 0));
        assert!(tb.consume(5.0, 0));
        assert!(!tb.consume(1.0, 0)); // exhausted
    }

    #[test]
    fn refill_over_time() {
        let tb = AtomicTokenBucket::new(1_000_000_000.0, 10.0); // 1 token/ns
        assert!(tb.consume(10.0, 0)); // drain
        assert!(!tb.consume(1.0, 0));
        // 5 ns later -> 5 tokens refilled
        assert!(tb.consume(5.0, 5));
    }

    #[test]
    fn available_reflects_refill() {
        let tb = AtomicTokenBucket::new(1_000_000_000.0, 100.0);
        tb.consume(100.0, 0);
        let avail = tb.available(50);
        assert!(avail >= 49.0 && avail <= 51.0);
    }

    #[test]
    fn burst_cap() {
        let tb = AtomicTokenBucket::new(1_000_000_000.0, 10.0);
        // Even after a long time, should not exceed burst
        let avail = tb.available(1_000_000);
        assert!(avail <= 10.0 + 0.01);
    }

    /// Regression: a single elapsed interval must be refilled AT MOST ONCE even
    /// when the bucket is shared (its documented `Arc` use) and many threads
    /// concurrently refill the same `now_ns`.
    ///
    /// With the old two-independent-CAS refill, threads that lost the `last_ns`
    /// race still credited their own `added`, so a drained bucket inflated
    /// toward `burst` (here ~1000) instead of staying at the single legitimate
    /// refill (~100) — silently granting phantom tokens. The coupled
    /// claim-then-credit refill makes this invariant hold under any interleaving.
    #[test]
    fn concurrent_refill_credits_interval_at_most_once() {
        use std::sync::{Arc, Barrier};

        // 1 token/ns, large burst so over-admission is visible *below* the cap.
        let burst = 1000.0;
        let added_per_interval = 100.0; // elapsed of 100 ns at 1 token/ns

        // Run several rounds to make the racy window very likely to be hit.
        for _ in 0..200 {
            let tb = Arc::new(AtomicTokenBucket::new(1_000_000_000.0, burst));
            // Drain the bucket to 0 at t=0.
            assert!(tb.consume(burst, 0));
            assert!(!tb.consume(1.0, 0));

            let threads = 16usize;
            let barrier = Arc::new(Barrier::new(threads));
            let mut handles = Vec::with_capacity(threads);
            for _ in 0..threads {
                let tb = Arc::clone(&tb);
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    // All threads slam the SAME now_ns simultaneously.
                    barrier.wait();
                    tb.available(100);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }

            // Exactly one interval [0, 100] elapsed, so the bucket must hold at
            // most one refill's worth of tokens — never the inflated near-burst
            // value the double-refill bug produced.
            let avail = tb.available(100);
            assert!(
                avail <= added_per_interval + 0.001,
                "interval refilled more than once: available={avail} (expected <= {added_per_interval})",
            );
        }
    }
}
