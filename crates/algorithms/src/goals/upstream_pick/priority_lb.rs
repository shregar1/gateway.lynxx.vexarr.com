//! Priority-based distribution (Envoy).
//!
//! Backends are grouped into priority levels. Traffic is sent to the highest
//! (lowest-numbered) priority level that has sufficient healthy backends.
//! Within a level, backends are chosen via weighted round-robin.

use std::cell::Cell;

/// Priority-level load balancer.
pub struct PriorityLb {
    /// `levels[p]` = weights of backends at priority `p`.
    levels: Vec<Vec<u32>>,
    /// Per-level round-robin counter.
    rr_counters: Vec<Cell<usize>>,
}

impl PriorityLb {
    /// Create a new priority LB.
    ///
    /// `priority_levels[p]` is a Vec of weights for the backends at that
    /// priority. A weight of 0 means the backend is unhealthy / drained.
    pub fn new(priority_levels: &[Vec<u32>]) -> Self {
        assert!(!priority_levels.is_empty(), "must have at least one level");
        Self {
            levels: priority_levels.to_vec(),
            rr_counters: (0..priority_levels.len())
                .map(|_| Cell::new(0))
                .collect(),
        }
    }

    /// Pick a `(priority_level, backend_idx)` tuple.
    ///
    /// Uses the first priority level that has at least one healthy (weight > 0)
    /// backend, then round-robins within that level.
    pub fn pick(&self) -> (usize, usize) {
        for (p, level) in self.levels.iter().enumerate() {
            let healthy: Vec<usize> = level
                .iter()
                .enumerate()
                .filter(|(_, &w)| w > 0)
                .map(|(i, _)| i)
                .collect();
            if healthy.is_empty() {
                continue;
            }
            let counter = self.rr_counters[p].get();
            let choice = counter % healthy.len();
            self.rr_counters[p].set(counter.wrapping_add(1));
            return (p, healthy[choice]);
        }
        // All levels empty/unhealthy — return first slot of first level
        (0, 0)
    }

    /// Number of priority levels.
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_highest_priority_first() {
        let lb = PriorityLb::new(&[
            vec![1, 1, 1], // P0 — healthy
            vec![1, 1],    // P1
        ]);
        let (p, _) = lb.pick();
        assert_eq!(p, 0);
    }

    #[test]
    fn falls_through_to_lower_priority() {
        let lb = PriorityLb::new(&[
            vec![0, 0, 0], // P0 — all unhealthy
            vec![1, 1],    // P1 — healthy
        ]);
        let (p, _) = lb.pick();
        assert_eq!(p, 1);
    }

    #[test]
    fn round_robins_within_level() {
        let lb = PriorityLb::new(&[vec![1, 1, 1]]);
        let mut seen = [false; 3];
        for _ in 0..3 {
            let (_, idx) = lb.pick();
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn skips_unhealthy_within_level() {
        let lb = PriorityLb::new(&[vec![0, 1, 0, 1]]);
        for _ in 0..4 {
            let (_, idx) = lb.pick();
            assert!(idx == 1 || idx == 3, "should only pick healthy backends");
        }
    }
}
