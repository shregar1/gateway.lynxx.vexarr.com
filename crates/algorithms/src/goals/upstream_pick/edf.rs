//! Earliest Deadline First scheduler (Envoy).
//!
//! Min-heap based scheduler where each backend has a deadline computed as
//! `current_time + 1 / weight`. The pick operation pops the earliest
//! deadline and re-inserts with the new deadline.

use std::collections::BinaryHeap;
use std::cmp::Ordering as CmpOrdering;

/// A heap entry — ordered by smallest deadline first.
#[derive(Clone)]
struct EdfEntry {
    deadline: f64,
    idx: usize,
}

impl PartialEq for EdfEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.idx == other.idx
    }
}

impl Eq for EdfEntry {}

impl PartialOrd for EdfEntry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for EdfEntry {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse order so BinaryHeap (max-heap) acts as min-heap
        other
            .deadline
            .partial_cmp(&self.deadline)
            .unwrap_or(CmpOrdering::Equal)
            .then(other.idx.cmp(&self.idx))
    }
}

/// Earliest Deadline First scheduler.
pub struct EdfScheduler {
    heap: BinaryHeap<EdfEntry>,
    weights: Vec<f64>,
}

impl EdfScheduler {
    /// Build a new EDF scheduler from the given weights.
    /// All weights must be > 0.
    pub fn new(weights: &[f64]) -> Self {
        assert!(!weights.is_empty(), "weights must not be empty");
        let mut heap = BinaryHeap::with_capacity(weights.len());
        for (i, &w) in weights.iter().enumerate() {
            assert!(w > 0.0, "weight must be > 0");
            heap.push(EdfEntry {
                deadline: 1.0 / w,
                idx: i,
            });
        }
        Self {
            heap,
            weights: weights.to_vec(),
        }
    }

    /// Pick the next backend by popping the earliest deadline and re-inserting.
    pub fn pick(&mut self) -> usize {
        let entry = self.heap.pop().expect("scheduler must not be empty");
        let idx = entry.idx;
        let new_deadline = entry.deadline + 1.0 / self.weights[idx];
        self.heap.push(EdfEntry {
            deadline: new_deadline,
            idx,
        });
        idx
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
    fn equal_weights_round_robin() {
        let mut sched = EdfScheduler::new(&[1.0, 1.0, 1.0]);
        let mut counts = [0u32; 3];
        for _ in 0..9 {
            counts[sched.pick()] += 1;
        }
        assert_eq!(counts, [3, 3, 3]);
    }

    #[test]
    fn weighted_distribution() {
        let mut sched = EdfScheduler::new(&[5.0, 3.0, 2.0]);
        let mut counts = [0u32; 3];
        for _ in 0..100 {
            counts[sched.pick()] += 1;
        }
        assert_eq!(counts[0], 50);
        assert_eq!(counts[1], 30);
        assert_eq!(counts[2], 20);
    }

    #[test]
    fn single_backend() {
        let mut sched = EdfScheduler::new(&[5.0]);
        for _ in 0..10 {
            assert_eq!(sched.pick(), 0);
        }
    }
}
