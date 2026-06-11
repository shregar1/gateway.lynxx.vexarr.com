//! Fast Weighted Least Connections (HAProxy).
//!
//! Picks the backend with the lowest `active_conns * 65536 / weight` score.
//! Uses atomic counters for interior mutability so `pick`, `connect`, and
//! `release` all take `&self`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Fast Weighted Least Connections selector.
pub struct FwlcSelector {
    weights: Vec<u32>,
    active: Vec<AtomicU64>,
}

impl FwlcSelector {
    /// Create a new selector. Each entry in `weights` must be > 0.
    pub fn new(weights: &[u32]) -> Self {
        assert!(!weights.is_empty(), "weights must not be empty");
        Self {
            weights: weights.to_vec(),
            active: (0..weights.len()).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Pick the backend with the lowest weighted-connection score.
    pub fn pick(&self) -> usize {
        let mut best_idx = 0;
        let mut best_score = u64::MAX;

        for (i, w) in self.weights.iter().enumerate() {
            let conns = self.active[i].load(Ordering::Relaxed);
            let score = conns.wrapping_mul(65536) / (*w as u64);
            if score < best_score {
                best_score = score;
                best_idx = i;
            }
        }
        best_idx
    }

    /// Record a new connection on backend `idx`.
    pub fn connect(&self, idx: usize) {
        self.active[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Release a connection on backend `idx`.
    pub fn release(&self, idx: usize) {
        // Saturating: an unbalanced release must not underflow to u64::MAX,
        // which would permanently starve this backend (always maximal score).
        let _ = self.active[idx].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }

    /// Current active connections for backend `idx`.
    pub fn active_conns(&self, idx: usize) -> u64 {
        self.active[idx].load(Ordering::Relaxed)
    }

    /// Number of backends.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Returns true when there are no backends.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_least_loaded() {
        let sel = FwlcSelector::new(&[1, 1, 1]);
        sel.connect(0);
        sel.connect(0);
        sel.connect(1);
        // Backend 2 has 0 conns → picked
        assert_eq!(sel.pick(), 2);
    }

    #[test]
    fn weight_affects_score() {
        let sel = FwlcSelector::new(&[10, 1]);
        // Backend 0: weight 10, Backend 1: weight 1
        sel.connect(0);
        // Score 0: 1*65536/10 = 6553, Score 1: 0*65536/1 = 0
        assert_eq!(sel.pick(), 1);
        // Now load up backend 1 heavily
        for _ in 0..10 {
            sel.connect(1);
        }
        // Score 0: 1*65536/10 = 6553, Score 1: 10*65536/1 = 655360
        assert_eq!(sel.pick(), 0);
    }

    #[test]
    fn release_decrements() {
        let sel = FwlcSelector::new(&[1, 1]);
        sel.connect(0);
        sel.connect(0);
        assert_eq!(sel.active_conns(0), 2);
        sel.release(0);
        assert_eq!(sel.active_conns(0), 1);
    }
}
