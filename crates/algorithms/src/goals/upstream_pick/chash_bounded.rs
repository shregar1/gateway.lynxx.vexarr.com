//! Consistent Hash with Bounded Loads (HAProxy).
//!
//! Ring-based consistent hashing where each node's load is bounded to
//! `avg_load * load_factor`. If the target node is over-loaded, we walk
//! the ring clockwise until a node with capacity is found.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

/// A point on the hash ring.
struct RingPoint {
    hash: u64,
    node_idx: usize,
}

/// Consistent hash selector with bounded loads.
pub struct BoundedCHash {
    ring: Vec<RingPoint>,
    active: Vec<AtomicU64>,
    node_count: usize,
    load_factor: f64,
}

impl BoundedCHash {
    /// Build a ring with `replicas` virtual nodes per physical node.
    /// `load_factor` is the multiplier on average load that caps per-node
    /// connections (e.g. 1.25 means each node accepts at most 125 % of avg).
    pub fn new(nodes: &[&str], replicas: u32, load_factor: f64) -> Self {
        assert!(!nodes.is_empty(), "nodes must not be empty");
        // Bug fix: replicas == 0 produced an empty ring (the `0..replicas` loop
        // pushes nothing) while `active` still held nodes.len() entries, so any
        // pick() fell through to `self.ring[start]` and panicked on the empty Vec.
        assert!(replicas > 0, "replicas must be > 0");
        let mut ring = Vec::with_capacity(nodes.len() * replicas as usize);

        for (idx, &name) in nodes.iter().enumerate() {
            for r in 0..replicas {
                let mut hasher = DefaultHasher::new();
                name.hash(&mut hasher);
                r.hash(&mut hasher);
                ring.push(RingPoint {
                    hash: hasher.finish(),
                    node_idx: idx,
                });
            }
        }

        ring.sort_by_key(|p| p.hash);

        Self {
            ring,
            active: (0..nodes.len()).map(|_| AtomicU64::new(0)).collect(),
            node_count: nodes.len(),
            load_factor,
        }
    }

    /// Find the node responsible for `key`, respecting load bounds.
    pub fn pick(&self, key: &[u8]) -> usize {
        // Bug fix: guard against an empty ring so pick() is total. With an empty
        // ring the fallback `self.ring[start]` below would index out of bounds.
        if self.ring.is_empty() {
            return 0;
        }

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let h = hasher.finish();

        // Binary search for first ring point >= h
        let start = match self.ring.binary_search_by_key(&h, |p| p.hash) {
            Ok(i) => i,
            Err(i) => {
                if i >= self.ring.len() {
                    0 // wrap around
                } else {
                    i
                }
            }
        };

        let total_active: u64 = self.active.iter().map(|a| a.load(Ordering::Relaxed)).sum();
        let avg = (total_active as f64) / (self.node_count as f64);
        let bound = (avg * self.load_factor).ceil().max(1.0) as u64;

        // Walk the ring until we find a node under the load bound
        for offset in 0..self.ring.len() {
            let idx = (start + offset) % self.ring.len();
            let node = self.ring[idx].node_idx;
            if self.active[node].load(Ordering::Relaxed) < bound {
                return node;
            }
        }

        // Fallback: all nodes over bound — just use the primary
        self.ring[start].node_idx
    }

    /// Record a new connection on node `idx`.
    pub fn connect(&self, idx: usize) {
        self.active[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Release a connection on node `idx`.
    pub fn release(&self, idx: usize) {
        // Saturating: an unbalanced release (double-release / release without a
        // matching connect) must not underflow to u64::MAX, which would make the
        // node look maximally loaded forever and corrupt the cluster-wide bound.
        let _ = self.active[idx].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Number of points on the ring.
    pub fn ring_size(&self) -> usize {
        self.ring.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_pick() {
        let ch = BoundedCHash::new(&["a", "b", "c"], 100, 1.5);
        let first = ch.pick(b"hello");
        let second = ch.pick(b"hello");
        assert_eq!(first, second);
    }

    #[test]
    fn distributes_keys() {
        let ch = BoundedCHash::new(&["a", "b", "c"], 150, 1.5);
        let mut counts = [0u32; 3];
        for i in 0..300 {
            let key = format!("key-{}", i);
            counts[ch.pick(key.as_bytes())] += 1;
        }
        // All nodes should get at least some traffic
        for &c in &counts {
            assert!(c > 0, "every node should receive some keys");
        }
    }

    #[test]
    fn bounded_load_redirects() {
        let ch = BoundedCHash::new(&["a", "b", "c"], 150, 1.25);
        let primary = ch.pick(b"test");
        // Overload the primary
        for _ in 0..100 {
            ch.connect(primary);
        }
        // Now picks should route away from the overloaded node
        let alt = ch.pick(b"test");
        assert_ne!(alt, primary);
    }

    #[test]
    fn ring_size() {
        let ch = BoundedCHash::new(&["x", "y"], 50, 1.5);
        assert_eq!(ch.ring_size(), 100);
    }

    // Regression: replicas == 0 used to build an empty ring, and the first
    // pick() then indexed `self.ring[0]` out of bounds and panicked. new() now
    // rejects replicas == 0 up front, so the empty ring can never be built.
    #[test]
    #[should_panic(expected = "replicas must be > 0")]
    fn zero_replicas_rejected() {
        let _ = BoundedCHash::new(&["a", "b", "c"], 0, 1.25);
    }
}
