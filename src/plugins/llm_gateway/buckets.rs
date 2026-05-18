//! Per-consumer token + request buckets.
//!
//! Two independent rolling-window counters per consumer name:
//!
//! 1. **Tokens per minute** — sum of input + output tokens within the last
//!    60 seconds.
//! 2. **Requests per minute** — count of admitted requests.
//!
//! The window is implemented as a single `last_reset` timestamp + a counter:
//! once 60s have elapsed since `last_reset` the counter is reset to zero on
//! the next access. This is cheaper than a sliding window and within ~1
//! window of accuracy, which is fine for cost/abuse protection.
//!
//! Buckets live in a `DashMap` keyed by consumer name. Eviction is implicit:
//! idle consumers stay in the map but their counters reset on access. For
//! v1 we accept the unbounded map size — a future enhancement is a periodic
//! sweeper. At 100 byte/entry and 100k consumers that's 10 MiB, which is
//! negligible compared to the per-instance reqwest pool.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Admit; deduct tokens after upstream call returns.
    Allow,
    /// Reject — the estimated tokens or the request count would exceed the
    /// configured ceiling within the current window.
    Deny {
        reason: DenyReason,
        retry_after: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    Tokens,
    Requests,
}

#[derive(Default)]
struct Counters {
    tokens: u64,
    requests: u64,
    last_reset: Option<Instant>,
}

impl Counters {
    fn maybe_reset(&mut self, now: Instant) {
        match self.last_reset {
            None => self.last_reset = Some(now),
            Some(t) if now.duration_since(t) >= WINDOW => {
                self.tokens = 0;
                self.requests = 0;
                self.last_reset = Some(now);
            }
            _ => {}
        }
    }
}

pub struct Buckets {
    enabled: bool,
    tokens_per_min: u64,
    requests_per_min: u64,
    inner: DashMap<String, Counters>,
}

impl Buckets {
    pub fn new(enabled: bool, tokens_per_min: u64, requests_per_min: u64) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            tokens_per_min,
            requests_per_min,
            inner: DashMap::new(),
        })
    }

    /// Decide whether to admit a request, given the estimated input tokens.
    /// Atomically increments the request counter on `Allow`. Output tokens
    /// are deducted later via [`Self::deduct`].
    pub fn check(&self, consumer: &str, est_input_tokens: u64) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }
        let now = Instant::now();
        let mut entry = self.inner.entry(consumer.to_string()).or_default();
        entry.maybe_reset(now);

        // Request ceiling — we don't pre-check tokens against the request
        // ceiling, just admitted-count.
        if entry.requests + 1 > self.requests_per_min {
            return Decision::Deny {
                reason: DenyReason::Requests,
                retry_after: WINDOW.as_secs(),
            };
        }
        // Token ceiling — predict using est_input only. Output is deducted
        // post-hoc; over-shoot of one response is acceptable and matches the
        // behaviour of every other LLM gateway we benchmarked.
        if entry.tokens + est_input_tokens > self.tokens_per_min {
            return Decision::Deny {
                reason: DenyReason::Tokens,
                retry_after: WINDOW.as_secs(),
            };
        }

        entry.requests += 1;
        entry.tokens += est_input_tokens;
        Decision::Allow
    }

    /// Add the actual completion tokens (or correction delta on the input
    /// side) after the upstream response is parsed. Capped at the ceiling
    /// to keep the bucket from drifting.
    pub fn deduct(&self, consumer: &str, extra_tokens: u64) {
        if !self.enabled || extra_tokens == 0 {
            return;
        }
        let now = Instant::now();
        let mut entry = self.inner.entry(consumer.to_string()).or_default();
        entry.maybe_reset(now);
        entry.tokens = entry
            .tokens
            .saturating_add(extra_tokens)
            .min(self.tokens_per_min * 2);
    }

    /// Refund tokens back to the consumer's bucket. Used for post-hoc
    /// adjustment when an estimated count was higher than the actual
    /// tokens delivered (e.g. on client-side stream cancellation).
    /// If `delta` is negative, it actually deducts more.
    pub fn refund(&self, consumer: &str, delta: i64) {
        if !self.enabled || delta == 0 {
            return;
        }
        let now = Instant::now();
        let mut entry = self.inner.entry(consumer.to_string()).or_default();
        entry.maybe_reset(now);
        if delta > 0 {
            entry.tokens = entry.tokens.saturating_sub(delta as u64);
        } else {
            entry.tokens = entry
                .tokens
                .saturating_add((-delta) as u64)
                .min(self.tokens_per_min * 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_then_deny_on_tokens() {
        let b = Buckets::new(true, 100, 100);
        assert_eq!(b.check("alice", 50), Decision::Allow);
        assert_eq!(b.check("alice", 50), Decision::Allow);
        match b.check("alice", 1) {
            Decision::Deny { reason, .. } => assert_eq!(reason, DenyReason::Tokens),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn allow_then_deny_on_requests() {
        let b = Buckets::new(true, u64::MAX, 2);
        assert_eq!(b.check("alice", 1), Decision::Allow);
        assert_eq!(b.check("alice", 1), Decision::Allow);
        match b.check("alice", 1) {
            Decision::Deny { reason, .. } => assert_eq!(reason, DenyReason::Requests),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn separate_consumers_isolated() {
        let b = Buckets::new(true, 10, 10);
        assert_eq!(b.check("alice", 10), Decision::Allow);
        assert_eq!(b.check("bob", 10), Decision::Allow);
    }

    #[test]
    fn disabled_always_allows() {
        let b = Buckets::new(false, 1, 1);
        for _ in 0..100 {
            assert_eq!(b.check("alice", 1000), Decision::Allow);
        }
    }
}
