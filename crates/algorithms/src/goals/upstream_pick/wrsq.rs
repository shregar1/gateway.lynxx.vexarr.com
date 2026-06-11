//! Weighted Random Selection Queue (Envoy).
//!
//! Picks a backend randomly with probability proportional to its weight,
//! using a cumulative distribution table. Uses `DefaultHasher` seeded
//! with a counter for deterministic-enough entropy in benchmarks.

use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Weighted random selection queue.
pub struct WrsqSelector {
    cumulative: Vec<f64>,
    total: f64,
    counter: Cell<u64>,
}

impl WrsqSelector {
    /// Build a selector from the given weights (all must be > 0).
    pub fn new(weights: &[f64]) -> Self {
        assert!(!weights.is_empty(), "weights must not be empty");
        let mut cumulative = Vec::with_capacity(weights.len());
        let mut sum = 0.0;
        for &w in weights {
            assert!(w > 0.0, "weight must be > 0");
            sum += w;
            cumulative.push(sum);
        }
        Self {
            cumulative,
            total: sum,
            counter: Cell::new(0),
        }
    }

    /// Pick a random backend weighted by the configured weights.
    pub fn pick(&self) -> usize {
        let c = self.counter.get();
        self.counter.set(c.wrapping_add(1));

        let mut hasher = DefaultHasher::new();
        c.hash(&mut hasher);
        let h = hasher.finish();
        let sample = (h as f64 / u64::MAX as f64) * self.total;

        for (i, &cum) in self.cumulative.iter().enumerate() {
            if sample < cum {
                return i;
            }
        }
        // Floating-point edge case — return the last backend
        self.cumulative.len() - 1
    }

    /// Number of backends.
    pub fn len(&self) -> usize {
        self.cumulative.len()
    }

    /// Returns true when there are no backends.
    pub fn is_empty(&self) -> bool {
        self.cumulative.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_backend() {
        let sel = WrsqSelector::new(&[1.0]);
        for _ in 0..10 {
            assert_eq!(sel.pick(), 0);
        }
    }

    #[test]
    fn distribution_roughly_weighted() {
        let sel = WrsqSelector::new(&[80.0, 20.0]);
        let mut counts = [0u32; 2];
        for _ in 0..10000 {
            counts[sel.pick()] += 1;
        }
        // Backend 0 should get roughly 80% ± some variance
        let ratio = counts[0] as f64 / 10000.0;
        assert!(
            ratio > 0.6 && ratio < 0.95,
            "expected ~80% for backend 0, got {}%",
            ratio * 100.0
        );
    }
}
