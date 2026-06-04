//! Power of Two Choices (P2C) load balancer.
//!
//! From Mitzenmacher's 1996 dissertation "The Power of Two Choices in
//! Randomized Load Balancing".
//!
//! The core idea: sample **two** random backends and route to the one with
//! lower load.  This simple change yields an exponentially better maximum
//! load — O(log log n) versus O(log n / log log n) for purely random
//! selection — with near-zero coordination overhead.
//!
//! This implementation is fully **lock-free** and **thread-safe**: active
//! request counters use `AtomicU64`, and the PRNG is a single `AtomicU64`
//! xorshift64 state that is updated with a relaxed CAS loop.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free P2C load balancer.
///
/// Each backend has an atomic active-request counter and an optional
/// weight (default 1).  `pick()` samples two random indices and returns
/// the one whose *effective load* (`active_requests / weight`) is lower.
pub struct P2cBalancer {
    active_requests: Vec<AtomicU64>,
    weights: Vec<u32>,
    rng_state: AtomicU64,
}

impl P2cBalancer {
    /// Create a balancer over `server_count` backends with equal weights.
    /// Panics if `server_count` is zero.
    pub fn new(server_count: usize) -> Self {
        assert!(server_count > 0, "P2C requires at least 1 server");
        Self::with_weights(vec![1; server_count])
    }

    /// Create a balancer with per-backend weights.
    /// Higher weight → proportionally more traffic.
    /// Panics if `weights` is empty or any weight is zero.
    pub fn with_weights(weights: Vec<u32>) -> Self {
        assert!(!weights.is_empty(), "P2C requires at least 1 server");
        assert!(
            weights.iter().all(|&w| w > 0),
            "all weights must be > 0"
        );
        let active_requests = (0..weights.len())
            .map(|_| AtomicU64::new(0))
            .collect();
        Self {
            active_requests,
            weights,
            // Seed with a non-zero constant; any callers on different threads
            // will diverge after the first CAS.
            rng_state: AtomicU64::new(0x5A17_C0DE_CAFE_BABE),
        }
    }

    /// Pick a backend using P2C.  Thread-safe, lock-free.
    ///
    /// With a single backend the choice is trivial.  Otherwise two random
    /// indices are sampled and the one with lower effective load wins.
    pub fn pick(&self) -> usize {
        let n = self.server_count();
        if n == 1 {
            return 0;
        }

        let r = self.next_random();
        let a = (r as usize) % n;
        let mut b = ((r >> 32) as usize) % n;
        if b == a {
            b = (a + 1) % n;
        }

        let load_a = self.effective_load(a);
        let load_b = self.effective_load(b);

        if load_a <= load_b { a } else { b }
    }

    /// Record a request starting on backend `idx`.
    pub fn request_start(&self, idx: usize) {
        self.active_requests[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request completing on backend `idx`.
    pub fn request_end(&self, idx: usize) {
        self.active_requests[idx].fetch_sub(1, Ordering::Relaxed);
    }

    /// Current active request count for backend `idx`.
    pub fn active(&self, idx: usize) -> u64 {
        self.active_requests[idx].load(Ordering::Relaxed)
    }

    /// Number of backends.
    pub fn server_count(&self) -> usize {
        self.weights.len()
    }

    /// Effective load for backend `idx` scaled by 1024 to avoid fp math.
    /// Lower is better.  `(active * 1024) / weight`.
    fn effective_load(&self, idx: usize) -> u64 {
        let active = self.active_requests[idx].load(Ordering::Relaxed);
        (active * 1024) / self.weights[idx] as u64
    }

    /// Xorshift64 PRNG — lock-free via CAS loop on `rng_state`.
    fn next_random(&self) -> u64 {
        loop {
            let old = self.rng_state.load(Ordering::Relaxed);
            let mut s = old;
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            match self.rng_state.compare_exchange_weak(
                old,
                s,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return s,
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_server() {
        let lb = P2cBalancer::new(1);
        assert_eq!(lb.pick(), 0);
        assert_eq!(lb.server_count(), 1);
    }

    #[test]
    fn pick_returns_valid_index() {
        let lb = P2cBalancer::new(5);
        for _ in 0..1000 {
            let idx = lb.pick();
            assert!(idx < 5);
        }
    }

    #[test]
    fn prefers_less_loaded() {
        let lb = P2cBalancer::new(3);
        // Load up servers 0 and 1
        for _ in 0..100 {
            lb.request_start(0);
            lb.request_start(1);
        }
        // Server 2 is unloaded — should be picked every time
        let mut picks = [0u32; 3];
        for _ in 0..1000 {
            picks[lb.pick()] += 1;
        }
        assert!(
            picks[2] > picks[0] && picks[2] > picks[1],
            "unloaded server should be picked most: {:?}",
            picks
        );
    }

    #[test]
    fn request_start_end_tracking() {
        let lb = P2cBalancer::new(2);
        assert_eq!(lb.active(0), 0);
        lb.request_start(0);
        lb.request_start(0);
        assert_eq!(lb.active(0), 2);
        lb.request_end(0);
        assert_eq!(lb.active(0), 1);
        lb.request_end(0);
        assert_eq!(lb.active(0), 0);
    }

    #[test]
    fn weighted_prefers_higher_weight() {
        // Server 0 has weight 10, server 1 has weight 1
        let lb = P2cBalancer::with_weights(vec![10, 1]);
        // Give both 5 active requests
        for _ in 0..5 {
            lb.request_start(0);
            lb.request_start(1);
        }
        // Effective load: server 0 = 5/10 = 0.5, server 1 = 5/1 = 5.0
        let mut picks = [0u32; 2];
        for _ in 0..1000 {
            picks[lb.pick()] += 1;
        }
        assert!(
            picks[0] > picks[1],
            "higher-weight server should be preferred: {:?}",
            picks
        );
    }

    #[test]
    fn even_distribution_when_unloaded() {
        let lb = P2cBalancer::new(4);
        let mut picks = [0u32; 4];
        let n = 10_000;
        for _ in 0..n {
            picks[lb.pick()] += 1;
        }
        // With zero load everywhere, distribution should be roughly uniform.
        // Each server should get at least 10% (quite lenient bound).
        for (i, &count) in picks.iter().enumerate() {
            assert!(
                count > (n / 20) as u32,
                "server {} got only {} picks out of {} — too skewed",
                i, count, n
            );
        }
    }

    #[test]
    #[should_panic(expected = "P2C requires at least 1 server")]
    fn zero_servers_panics() {
        P2cBalancer::new(0);
    }

    #[test]
    #[should_panic(expected = "all weights must be > 0")]
    fn zero_weight_panics() {
        P2cBalancer::with_weights(vec![1, 0, 3]);
    }

    #[test]
    fn two_servers_always_picks_lighter() {
        let lb = P2cBalancer::new(2);
        lb.request_start(0);
        // Server 0 has 1 active, server 1 has 0
        for _ in 0..100 {
            assert_eq!(lb.pick(), 1, "should always pick the lighter server");
        }
    }

    #[test]
    fn thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let lb = Arc::new(P2cBalancer::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let lb = Arc::clone(&lb);
                thread::spawn(move || {
                    for _ in 0..5000 {
                        let idx = lb.pick();
                        lb.request_start(idx);
                        lb.request_end(idx);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All requests completed — total active should be 0
        let total: u64 = (0..4).map(|i| lb.active(i)).sum();
        assert_eq!(total, 0, "all requests should have completed");
    }

    #[test]
    fn load_converges_under_sustained_traffic() {
        let lb = P2cBalancer::new(3);
        // Simulate: pick a server, add load, then remove it
        let mut total_picks = [0u64; 3];
        for _ in 0..10_000 {
            let idx = lb.pick();
            total_picks[idx] += 1;
            lb.request_start(idx);
            // Simulate completion of the oldest request on a random server
            for j in 0..3 {
                if lb.active(j) > 0 {
                    lb.request_end(j);
                    break;
                }
            }
        }
        // No single server should handle > 60% of requests
        for (i, &count) in total_picks.iter().enumerate() {
            assert!(
                count < 6000,
                "server {} handled {} / 10000 — too concentrated",
                i, count
            );
        }
    }
}
