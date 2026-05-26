//! Cache promotion policy — admission control for cache writes.
//!
//! Prevents "one-hit-wonder" pollution by requiring a URL to accumulate a
//! configurable number of hits or total response bytes before its response
//! is eligible for caching.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};

/// Configuration for the promotion policy.
#[derive(Debug, Clone)]
pub struct PromotionConfig {
    /// Minimum number of hits before the response is promoted (default 1).
    pub hit_threshold: u32,
    /// Minimum cumulative response bytes before promotion (0 = disabled).
    pub byte_threshold: u64,
    /// Maximum number of tracked URL hashes (LRU eviction beyond this).
    pub capacity: usize,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            hit_threshold: 1,
            byte_threshold: 0,
            capacity: 8192,
        }
    }
}

/// Admission-control policy that tracks per-URL hit/byte counters.
pub struct PromotionPolicy {
    config: PromotionConfig,
    tracker: HashMap<u64, PromotionEntry>,
    lru: VecDeque<u64>,
    free_list: Vec<PromotionEntry>,
}

struct PromotionEntry {
    hits: u32,
    bytes: u64,
}

/// Outcome of a promotion check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionDecision {
    /// Allow the response to be cached.
    Promote,
    /// Not enough hits / bytes yet — do not cache.
    Deny,
}

impl PromotionPolicy {
    /// Create a new policy from the given configuration.
    pub fn new(config: PromotionConfig) -> Self {
        Self {
            tracker: HashMap::with_capacity(config.capacity),
            lru: VecDeque::with_capacity(config.capacity),
            free_list: Vec::new(),
            config,
        }
    }

    /// Record a request for `url_hash` carrying `response_bytes` and decide
    /// whether the response should be promoted into cache.
    ///
    /// Returns [`PromotionDecision::Promote`] if **either** the hit threshold
    /// **or** the byte threshold has been reached.
    pub fn should_promote(&mut self, url_hash: u64, response_bytes: u64) -> PromotionDecision {
        if let Some(entry) = self.tracker.get_mut(&url_hash) {
            entry.hits = entry.hits.saturating_add(1);
            entry.bytes = entry.bytes.saturating_add(response_bytes);
            let hits = entry.hits;
            let bytes = entry.bytes;

            // Refresh LRU position
            if let Some(pos) = self.lru.iter().position(|&h| h == url_hash) {
                self.lru.remove(pos);
            }
            self.lru.push_back(url_hash);

            return self.decide(hits, bytes);
        }

        // Evict the oldest entry if at capacity
        if self.tracker.len() >= self.config.capacity {
            if let Some(evicted) = self.lru.pop_front() {
                if let Some(entry) = self.tracker.remove(&evicted) {
                    self.free_list.push(entry);
                }
            }
        }

        let mut entry = self.free_list.pop().unwrap_or(PromotionEntry {
            hits: 0,
            bytes: 0,
        });
        entry.hits = 1;
        entry.bytes = response_bytes;

        let decision = self.decide(entry.hits, entry.bytes);
        self.tracker.insert(url_hash, entry);
        self.lru.push_back(url_hash);
        decision
    }

    #[inline]
    fn decide(&self, hits: u32, bytes: u64) -> PromotionDecision {
        let hit_ok = hits >= self.config.hit_threshold;
        let byte_ok = self.config.byte_threshold > 0 && bytes >= self.config.byte_threshold;

        if hit_ok || byte_ok {
            PromotionDecision::Promote
        } else {
            PromotionDecision::Deny
        }
    }

    /// Read-only query of current stats for a URL hash without recording a hit.
    ///
    /// Returns `(hits, bytes)` if the URL is tracked, `None` otherwise.
    pub fn stats(&self, url_hash: u64) -> Option<(u32, u64)> {
        self.tracker.get(&url_hash).map(|e| (e.hits, e.bytes))
    }

    /// Number of URLs currently tracked.
    pub fn tracked_count(&self) -> usize {
        self.tracker.len()
    }

    /// Clear all tracking state.
    pub fn clear(&mut self) {
        self.tracker.clear();
        self.lru.clear();
        self.free_list.clear();
    }
}

/// Simple chance-based promotion: returns [`PromotionDecision::Promote`] with
/// the given probability (0.0 = never, 1.0 = always).
///
/// Uses `RandomState` for entropy — sufficient for cache policies but
/// not cryptographically secure.
pub fn chance_promote(probability: f64) -> PromotionDecision {
    if probability >= 1.0 {
        return PromotionDecision::Promote;
    }
    if probability <= 0.0 {
        return PromotionDecision::Deny;
    }
    let state = std::collections::hash_map::RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(0);
    let h = hasher.finish();
    let sample = (h as f64) / (u64::MAX as f64);
    if sample < probability {
        PromotionDecision::Promote
    } else {
        PromotionDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> PromotionPolicy {
        PromotionPolicy::new(PromotionConfig::default())
    }

    #[test]
    fn first_hit_promotes_with_threshold_one() {
        let mut p = default_policy();
        assert_eq!(p.should_promote(1, 100), PromotionDecision::Promote);
    }

    #[test]
    fn hit_threshold_two() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 2,
            byte_threshold: 0,
            capacity: 100,
        });
        assert_eq!(p.should_promote(1, 100), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 100), PromotionDecision::Promote);
    }

    #[test]
    fn hit_threshold_three() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 3,
            byte_threshold: 0,
            capacity: 100,
        });
        assert_eq!(p.should_promote(1, 0), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 0), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 0), PromotionDecision::Promote);
    }

    #[test]
    fn byte_threshold() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 100, // won't reach this
            byte_threshold: 500,
            capacity: 100,
        });
        assert_eq!(p.should_promote(1, 200), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 200), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 200), PromotionDecision::Promote);
    }

    #[test]
    fn hit_or_byte_either_promotes() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 5,
            byte_threshold: 100,
            capacity: 100,
        });
        // Byte threshold met first
        assert_eq!(p.should_promote(1, 200), PromotionDecision::Promote);
    }

    #[test]
    fn different_urls_independent() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 2,
            byte_threshold: 0,
            capacity: 100,
        });
        assert_eq!(p.should_promote(1, 0), PromotionDecision::Deny);
        assert_eq!(p.should_promote(2, 0), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 0), PromotionDecision::Promote);
        assert_eq!(p.should_promote(2, 0), PromotionDecision::Promote);
    }

    #[test]
    fn stats_returns_none_for_unknown() {
        let p = default_policy();
        assert_eq!(p.stats(999), None);
    }

    #[test]
    fn stats_tracks_hits_and_bytes() {
        let mut p = default_policy();
        p.should_promote(1, 100);
        p.should_promote(1, 50);
        let (hits, bytes) = p.stats(1).unwrap();
        assert_eq!(hits, 2);
        assert_eq!(bytes, 150);
    }

    #[test]
    fn tracked_count() {
        let mut p = default_policy();
        assert_eq!(p.tracked_count(), 0);
        p.should_promote(1, 0);
        p.should_promote(2, 0);
        assert_eq!(p.tracked_count(), 2);
        p.should_promote(1, 0);
        assert_eq!(p.tracked_count(), 2); // no new entry
    }

    #[test]
    fn clear_resets_all() {
        let mut p = default_policy();
        p.should_promote(1, 100);
        p.should_promote(2, 200);
        p.clear();
        assert_eq!(p.tracked_count(), 0);
        assert_eq!(p.stats(1), None);
    }

    #[test]
    fn lru_eviction() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 1,
            byte_threshold: 0,
            capacity: 3,
        });
        p.should_promote(1, 0);
        p.should_promote(2, 0);
        p.should_promote(3, 0);
        assert_eq!(p.tracked_count(), 3);

        // Adding a 4th should evict the oldest (1)
        p.should_promote(4, 0);
        assert_eq!(p.tracked_count(), 3);
        assert_eq!(p.stats(1), None); // evicted
        assert!(p.stats(2).is_some());
        assert!(p.stats(4).is_some());
    }

    #[test]
    fn lru_refresh() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 1,
            byte_threshold: 0,
            capacity: 3,
        });
        p.should_promote(1, 0);
        p.should_promote(2, 0);
        p.should_promote(3, 0);

        // Touch 1 again — moves it to back of LRU
        p.should_promote(1, 0);

        // Insert 4 — should evict 2 (now oldest)
        p.should_promote(4, 0);
        assert_eq!(p.stats(2), None); // evicted
        assert!(p.stats(1).is_some()); // refreshed, still alive
    }

    #[test]
    fn chance_promote_never() {
        for _ in 0..100 {
            assert_eq!(chance_promote(0.0), PromotionDecision::Deny);
        }
    }

    #[test]
    fn chance_promote_always() {
        for _ in 0..100 {
            assert_eq!(chance_promote(1.0), PromotionDecision::Promote);
        }
    }

    #[test]
    fn chance_promote_negative() {
        assert_eq!(chance_promote(-0.5), PromotionDecision::Deny);
    }

    #[test]
    fn chance_promote_above_one() {
        assert_eq!(chance_promote(1.5), PromotionDecision::Promote);
    }

    #[test]
    fn byte_threshold_disabled_when_zero() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: 3,
            byte_threshold: 0,
            capacity: 100,
        });
        // Even with lots of bytes, still needs 3 hits
        assert_eq!(p.should_promote(1, 999999), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 999999), PromotionDecision::Deny);
        assert_eq!(p.should_promote(1, 999999), PromotionDecision::Promote);
    }

    #[test]
    fn saturating_counters() {
        let mut p = PromotionPolicy::new(PromotionConfig {
            hit_threshold: u32::MAX,
            byte_threshold: u64::MAX,
            capacity: 100,
        });
        // Won't overflow
        for _ in 0..10 {
            let _ = p.should_promote(1, u64::MAX);
        }
        let (hits, bytes) = p.stats(1).unwrap();
        assert_eq!(hits, 10);
        assert_eq!(bytes, u64::MAX); // saturated
    }
}
