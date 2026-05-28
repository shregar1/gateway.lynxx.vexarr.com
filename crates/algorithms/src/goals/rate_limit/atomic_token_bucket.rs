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
    fn refill_and_read(&self, now_ns: u64) -> f64 {
        // Update last_ns and compute tokens to add
        let old_ns = self.last_ns.load(Ordering::Relaxed);
        let elapsed = now_ns.saturating_sub(old_ns);
        let added = elapsed as f64 * self.rate_per_ns;

        // Try to claim the time interval
        if elapsed > 0 {
            let _ = self.last_ns.compare_exchange_weak(
                old_ns,
                now_ns,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }

        let current = f64::from_bits(self.tokens.load(Ordering::Relaxed));
        let new_val = (current + added).min(self.burst);

        // Store updated value (best-effort, CAS loop in consume handles races)
        let _ = self.tokens.compare_exchange_weak(
            current.to_bits(),
            new_val.to_bits(),
            Ordering::AcqRel,
            Ordering::Relaxed,
        );

        new_val
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
}
