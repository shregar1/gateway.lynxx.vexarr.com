//! Fast Weighted Round Robin (HAProxy).
//!
//! Current-weight accumulator pattern: each call to `pick` adds the server's
//! weight to its current counter, selects the server with the highest
//! counter, then subtracts the total weight from the selected server.

/// Fast Weighted Round Robin selector.
pub struct FwrrSelector {
    weights: Vec<u32>,
    current: Vec<i64>,
    total_weight: i64,
}

impl FwrrSelector {
    /// Create a new selector from the given weights.
    pub fn new(weights: &[u32]) -> Self {
        assert!(!weights.is_empty(), "weights must not be empty");
        let total_weight: u32 = weights.iter().sum();
        Self {
            weights: weights.to_vec(),
            current: vec![0i64; weights.len()],
            total_weight: total_weight as i64,
        }
    }

    /// Pick the next backend index using the weighted round-robin scheme.
    pub fn pick(&mut self) -> usize {
        // Add each server's weight to its current counter
        for (i, &w) in self.weights.iter().enumerate() {
            self.current[i] += w as i64;
        }

        // Pick the one with the highest current weight
        let mut best_idx = 0;
        let mut best_val = self.current[0];
        for i in 1..self.current.len() {
            if self.current[i] > best_val {
                best_val = self.current[i];
                best_idx = i;
            }
        }

        // Subtract total_weight from the selected backend
        self.current[best_idx] -= self.total_weight;
        best_idx
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
        let mut sel = FwrrSelector::new(&[1, 1, 1]);
        let mut counts = [0u32; 3];
        for _ in 0..9 {
            counts[sel.pick()] += 1;
        }
        assert_eq!(counts, [3, 3, 3]);
    }

    #[test]
    fn weighted_distribution() {
        // 5:3:2 → over 10 picks should see 5, 3, 2
        let mut sel = FwrrSelector::new(&[5, 3, 2]);
        let mut counts = [0u32; 3];
        for _ in 0..10 {
            counts[sel.pick()] += 1;
        }
        assert_eq!(counts, [5, 3, 2]);
    }

    #[test]
    fn single_backend() {
        let mut sel = FwrrSelector::new(&[10]);
        for _ in 0..5 {
            assert_eq!(sel.pick(), 0);
        }
    }
}
