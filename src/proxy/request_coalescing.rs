//! Request coalescing — deduplicate identical concurrent requests to save
//! backend capacity during thundering herds.
//!
//! # Architecture
//!
//! ```text
//! Request Coalescing
//! ├── CoalesceKey            — Identity of a request (method + path + vary headers)
//! ├── CoalesceEntry          — In-flight request + list of waiting receivers
//! ├── CoalesceEngine         — DashMap<CoalesceKey, CoalesceEntry> registry
//! ├── CoalescePolicy         — When to coalesce (GET-only, safe methods, all)
//! ├── CoalesceResponse       — Cached response shared with all waiters
//! ├── CoalesceMetrics        — Hits / misses / in-flight / collapsed counters
//! └── TTL guard              — Auto-expire stale in-flight entries
//! ```
//!
//! # Why This Beats AWS
//!
//! AWS ALB forwards every request individually. If 1,000 clients request
//! the same URL simultaneously, ALB sends 1,000 requests to the backend.
//! With coalescing, Lynxx sends 1 request and fans out the response to
//! all 1,000 waiters. This is critical for:
//!
//! - **Cache stampedes**: cache expires → all clients hit backend at once
//! - **Cold start storms**: new deployment → first requests all miss cache
//! - **Flash crowds**: viral content → thousands of identical GETs
//!
//! # Safety
//!
//! Only safe (idempotent) requests are coalesced by default. POST/PUT/DELETE
//! are never coalesced unless explicitly configured. The `Vary` header is
//! respected — requests with different `Accept-Encoding` get separate entries.

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

type FastHasher = ahash::RandomState;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

static COALESCE_ENABLED: AtomicBool = AtomicBool::new(false);
static COALESCE_POLICY: AtomicU8 = AtomicU8::new(0); // SafeMethods

pub fn set_coalesce_enabled(enabled: bool) {
    COALESCE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_coalesce_enabled() -> bool {
    COALESCE_ENABLED.load(Ordering::Relaxed)
}

pub fn set_coalesce_policy(policy: CoalescePolicy) {
    COALESCE_POLICY.store(policy as u8, Ordering::Relaxed);
}

pub fn get_coalesce_policy() -> CoalescePolicy {
    CoalescePolicy::from_u8(COALESCE_POLICY.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// Coalesce policy
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoalescePolicy {
    /// Only coalesce GET and HEAD (safest).
    SafeMethods = 0,
    /// Coalesce GET, HEAD, and OPTIONS.
    SafeAndOptions = 1,
    /// Coalesce all methods (dangerous — use only for read-only APIs).
    All = 2,
    /// Never coalesce (disable feature).
    Never = 3,
}

impl CoalescePolicy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => CoalescePolicy::SafeAndOptions,
            2 => CoalescePolicy::All,
            3 => CoalescePolicy::Never,
            _ => CoalescePolicy::SafeMethods,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "safe" | "safe-methods" | "safe_methods" => CoalescePolicy::SafeMethods,
            "safe-and-options" | "safe_and_options" => CoalescePolicy::SafeAndOptions,
            "all" => CoalescePolicy::All,
            "never" | "off" | "disabled" => CoalescePolicy::Never,
            _ => CoalescePolicy::SafeMethods,
        }
    }

    /// Check if a given HTTP method is eligible for coalescing under this policy.
    pub fn allows_method(&self, method: &str) -> bool {
        match self {
            CoalescePolicy::SafeMethods => {
                matches!(method.to_uppercase().as_str(), "GET" | "HEAD")
            }
            CoalescePolicy::SafeAndOptions => {
                matches!(method.to_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
            }
            CoalescePolicy::All => true,
            CoalescePolicy::Never => false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Coalesce key — request identity
// ═══════════════════════════════════════════════════════════════════════════

/// Unique identity for a coalesceable request.
/// Two requests with the same key can share the same backend response.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CoalesceKey {
    /// HTTP method (uppercase).
    pub method: String,
    /// Request path (including query string).
    pub path: String,
    /// Vary-header fingerprint — sorted key=value pairs that affect the response.
    /// e.g. Accept-Encoding, Accept-Language.
    pub vary_fingerprint: String,
    /// Service ID — different services never share coalesced responses.
    pub service_id: String,
}

impl CoalesceKey {
    pub fn new(method: &str, path: &str, service_id: &str) -> Self {
        Self {
            method: method.to_uppercase(),
            path: path.to_string(),
            vary_fingerprint: String::new(),
            service_id: service_id.to_string(),
        }
    }

    pub fn with_vary(mut self, vary_headers: &[(String, String)]) -> Self {
        let mut sorted: Vec<_> = vary_headers
            .iter()
            .map(|(k, v)| format!("{}={}", k.to_lowercase(), v))
            .collect();
        sorted.sort();
        self.vary_fingerprint = sorted.join("|");
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Coalesced response
// ═══════════════════════════════════════════════════════════════════════════

/// A response that can be shared with multiple waiters.
#[derive(Debug, Clone)]
pub struct CoalescedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub created_at: Instant,
}

impl CoalescedResponse {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
            created_at: Instant::now(),
        }
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// In-flight entry
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks an in-flight request and the number of waiters collapsed onto it.
#[derive(Debug)]
pub struct InFlightEntry {
    pub key: CoalesceKey,
    /// When the first request was received.
    pub started: Instant,
    /// Number of additional requests waiting for this response.
    pub waiters: u32,
    /// Maximum wait time before this entry is considered stale.
    pub ttl: Duration,
    /// The response, once available.
    pub response: Option<CoalescedResponse>,
}

impl InFlightEntry {
    pub fn new(key: CoalesceKey, ttl: Duration) -> Self {
        Self {
            key,
            started: Instant::now(),
            waiters: 0,
            ttl,
            response: None,
        }
    }

    /// Add a waiter. Returns the waiter's position (1-indexed).
    pub fn add_waiter(&mut self) -> u32 {
        self.waiters += 1;
        COALESCE_METRICS
            .requests_collapsed
            .fetch_add(1, Ordering::Relaxed);
        self.waiters
    }

    /// Set the response. All waiters can now read it.
    pub fn set_response(&mut self, response: CoalescedResponse) {
        self.response = Some(response);
    }

    /// Is this entry stale (TTL expired without a response)?
    pub fn is_stale(&self) -> bool {
        self.response.is_none() && self.started.elapsed() > self.ttl
    }

    /// Is the response ready?
    pub fn is_ready(&self) -> bool {
        self.response.is_some()
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Coalesce engine
// ═══════════════════════════════════════════════════════════════════════════

/// The main coalescing registry. Shared across all worker threads.
pub struct CoalesceEngine {
    /// In-flight requests keyed by CoalesceKey.
    in_flight: DashMap<CoalesceKey, InFlightEntry, FastHasher>,
    /// Default TTL for in-flight entries.
    default_ttl: Duration,
    /// Maximum waiters per entry (prevent unbounded memory growth).
    max_waiters: u32,
    /// Maximum body size to cache (don't coalesce huge responses).
    max_body_size: usize,
}

/// Result of trying to coalesce a request.
#[derive(Debug, PartialEq)]
pub enum CoalesceResult {
    /// No in-flight request for this key — you're the leader, send it.
    Leader,
    /// An in-flight request exists — you're a waiter. Position in queue.
    Waiting { position: u32 },
    /// Coalescing is not applicable for this request.
    NotEligible,
    /// Too many waiters — forward independently.
    CapacityExceeded,
}

impl CoalesceEngine {
    pub fn new(default_ttl: Duration, max_waiters: u32, max_body_size: usize) -> Self {
        Self {
            in_flight: DashMap::with_hasher(FastHasher::default()),
            default_ttl,
            max_waiters: max_waiters.max(1),
            max_body_size: max_body_size.max(1024),
        }
    }

    /// Try to coalesce a request. Called when a new request arrives.
    pub fn try_coalesce(
        &self,
        key: CoalesceKey,
        method: &str,
        policy: CoalescePolicy,
    ) -> CoalesceResult {
        if policy == CoalescePolicy::Never || !policy.allows_method(method) {
            return CoalesceResult::NotEligible;
        }

        // Check if there's already an in-flight request for this key.
        if let Some(mut entry) = self.in_flight.get_mut(&key) {
            if entry.is_stale() {
                // Stale entry — remove and become the new leader.
                drop(entry);
                self.in_flight.remove(&key);
                COALESCE_METRICS
                    .stale_evictions
                    .fetch_add(1, Ordering::Relaxed);
            } else if entry.waiters >= self.max_waiters {
                return CoalesceResult::CapacityExceeded;
            } else {
                let pos = entry.add_waiter();
                COALESCE_METRICS.cache_hits.fetch_add(1, Ordering::Relaxed);
                return CoalesceResult::Waiting { position: pos };
            }
        }

        // No in-flight request — become the leader.
        self.in_flight
            .insert(key.clone(), InFlightEntry::new(key, self.default_ttl));
        COALESCE_METRICS
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);
        CoalesceResult::Leader
    }

    /// Complete an in-flight request with its response.
    /// Returns the number of waiters who will receive this response.
    pub fn complete(
        &self,
        key: &CoalesceKey,
        response: CoalescedResponse,
    ) -> u32 {
        if response.body_len() > self.max_body_size {
            // Response too large to cache — remove the entry.
            self.in_flight.remove(key);
            COALESCE_METRICS
                .oversized_responses
                .fetch_add(1, Ordering::Relaxed);
            return 0;
        }

        if let Some(mut entry) = self.in_flight.get_mut(key) {
            let waiters = entry.waiters;
            entry.set_response(response);
            COALESCE_METRICS
                .responses_shared
                .fetch_add(waiters as u64, Ordering::Relaxed);
            waiters
        } else {
            0
        }
    }

    /// Get the cached response for a key (if ready).
    pub fn get_response(&self, key: &CoalesceKey) -> Option<CoalescedResponse> {
        self.in_flight
            .get(key)
            .and_then(|e| e.response.clone())
    }

    /// Remove a completed entry from the in-flight map.
    pub fn remove(&self, key: &CoalesceKey) {
        self.in_flight.remove(key);
    }

    /// Clean up stale entries.
    pub fn evict_stale(&self) -> u32 {
        let mut evicted = 0;
        let stale_keys: Vec<_> = self
            .in_flight
            .iter()
            .filter(|e| e.is_stale())
            .map(|e| e.key().clone())
            .collect();
        for key in &stale_keys {
            self.in_flight.remove(key);
            evicted += 1;
        }
        if evicted > 0 {
            COALESCE_METRICS
                .stale_evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
        evicted
    }

    /// Number of in-flight entries.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Total waiters across all in-flight entries.
    pub fn total_waiters(&self) -> u32 {
        self.in_flight.iter().map(|e| e.waiters).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct CoalesceMetrics {
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub requests_collapsed: AtomicU64,
    pub responses_shared: AtomicU64,
    pub stale_evictions: AtomicU64,
    pub oversized_responses: AtomicU64,
}

static COALESCE_METRICS: CoalesceMetrics = CoalesceMetrics {
    cache_hits: AtomicU64::new(0),
    cache_misses: AtomicU64::new(0),
    requests_collapsed: AtomicU64::new(0),
    responses_shared: AtomicU64::new(0),
    stale_evictions: AtomicU64::new(0),
    oversized_responses: AtomicU64::new(0),
};

pub fn coalesce_metrics() -> &'static CoalesceMetrics {
    &COALESCE_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CoalesceEngine {
        CoalesceEngine::new(Duration::from_secs(5), 100, 1024 * 1024)
    }

    fn key(path: &str) -> CoalesceKey {
        CoalesceKey::new("GET", path, "svc1")
    }

    // ── Policy ─────────────────────────────────────────────────────────

    #[test]
    fn policy_from_u8_roundtrip() {
        assert_eq!(CoalescePolicy::from_u8(0), CoalescePolicy::SafeMethods);
        assert_eq!(CoalescePolicy::from_u8(1), CoalescePolicy::SafeAndOptions);
        assert_eq!(CoalescePolicy::from_u8(2), CoalescePolicy::All);
        assert_eq!(CoalescePolicy::from_u8(3), CoalescePolicy::Never);
        assert_eq!(CoalescePolicy::from_u8(99), CoalescePolicy::SafeMethods);
    }

    #[test]
    fn policy_from_str() {
        assert_eq!(CoalescePolicy::from_str("safe"), CoalescePolicy::SafeMethods);
        assert_eq!(CoalescePolicy::from_str("all"), CoalescePolicy::All);
        assert_eq!(CoalescePolicy::from_str("never"), CoalescePolicy::Never);
        assert_eq!(CoalescePolicy::from_str("unknown"), CoalescePolicy::SafeMethods);
    }

    #[test]
    fn policy_allows_method() {
        let safe = CoalescePolicy::SafeMethods;
        assert!(safe.allows_method("GET"));
        assert!(safe.allows_method("HEAD"));
        assert!(!safe.allows_method("POST"));
        assert!(!safe.allows_method("OPTIONS"));

        let opts = CoalescePolicy::SafeAndOptions;
        assert!(opts.allows_method("OPTIONS"));

        let all = CoalescePolicy::All;
        assert!(all.allows_method("POST"));
        assert!(all.allows_method("DELETE"));

        let never = CoalescePolicy::Never;
        assert!(!never.allows_method("GET"));
    }

    // ── Global toggle ──────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_coalesce_enabled(true);
        assert!(is_coalesce_enabled());
    }

    // ── CoalesceKey ────────────────────────────────────────────────────

    #[test]
    fn key_equality() {
        let k1 = key("/api/data");
        let k2 = key("/api/data");
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_vary_fingerprint() {
        let k1 = key("/api").with_vary(&[
            ("Accept-Encoding".to_string(), "gzip".to_string()),
        ]);
        let k2 = key("/api").with_vary(&[
            ("Accept-Encoding".to_string(), "br".to_string()),
        ]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_different_service() {
        let k1 = CoalesceKey::new("GET", "/api", "svc1");
        let k2 = CoalesceKey::new("GET", "/api", "svc2");
        assert_ne!(k1, k2);
    }

    // ── Leader / waiter flow ───────────────────────────────────────────

    #[test]
    fn first_request_becomes_leader() {
        let e = engine();
        let result = e.try_coalesce(key("/api/data"), "GET", CoalescePolicy::SafeMethods);
        assert_eq!(result, CoalesceResult::Leader);
        assert_eq!(e.in_flight_count(), 1);
    }

    #[test]
    fn second_request_becomes_waiter() {
        let e = engine();
        let k = key("/api/data");

        let r1 = e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);
        assert_eq!(r1, CoalesceResult::Leader);

        let r2 = e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);
        assert_eq!(r2, CoalesceResult::Waiting { position: 1 });

        let r3 = e.try_coalesce(k, "GET", CoalescePolicy::SafeMethods);
        assert_eq!(r3, CoalesceResult::Waiting { position: 2 });

        assert_eq!(e.total_waiters(), 2);
    }

    #[test]
    fn post_not_eligible_under_safe_policy() {
        let e = engine();
        let k = CoalesceKey::new("POST", "/api/data", "svc1");
        let result = e.try_coalesce(k, "POST", CoalescePolicy::SafeMethods);
        assert_eq!(result, CoalesceResult::NotEligible);
    }

    #[test]
    fn never_policy_rejects_all() {
        let e = engine();
        let result = e.try_coalesce(key("/api"), "GET", CoalescePolicy::Never);
        assert_eq!(result, CoalesceResult::NotEligible);
    }

    // ── Complete and share ─────────────────────────────────────────────

    #[test]
    fn complete_shares_with_waiters() {
        let e = engine();
        let k = key("/api/data");

        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);

        let response = CoalescedResponse::new(
            200,
            vec![("content-type".to_string(), "application/json".to_string())],
            b"{}".to_vec(),
        );

        let shared_count = e.complete(&k, response);
        assert_eq!(shared_count, 2); // 2 waiters (leader doesn't count).
    }

    #[test]
    fn get_response_after_complete() {
        let e = engine();
        let k = key("/api/data");
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);

        let response = CoalescedResponse::new(200, vec![], b"hello".to_vec());
        e.complete(&k, response);

        let cached = e.get_response(&k);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().status, 200);
    }

    #[test]
    fn get_response_before_complete_returns_none() {
        let e = engine();
        let k = key("/api/data");
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);

        assert!(e.get_response(&k).is_none());
    }

    // ── Capacity limit ─────────────────────────────────────────────────

    #[test]
    fn capacity_exceeded() {
        let e = CoalesceEngine::new(Duration::from_secs(5), 2, 1024 * 1024);
        let k = key("/api/limited");

        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods); // Leader.
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods); // Waiter 1.
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods); // Waiter 2.

        // 3rd waiter exceeds max_waiters=2.
        let result = e.try_coalesce(k, "GET", CoalescePolicy::SafeMethods);
        assert_eq!(result, CoalesceResult::CapacityExceeded);
    }

    // ── Oversized response ─────────────────────────────────────────────

    #[test]
    fn oversized_response_not_cached() {
        // Constructor clamps max_body_size to at least 1024, so use 2048 for the limit
        // and a response body larger than that.
        let e = CoalesceEngine::new(Duration::from_secs(5), 100, 2048);
        let k = key("/api/big");

        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);

        let response = CoalescedResponse::new(200, vec![], vec![0u8; 4096]); // 4096 > 2048.
        let shared = e.complete(&k, response);
        assert_eq!(shared, 0);

        // Entry should have been removed.
        assert_eq!(e.in_flight_count(), 0);
    }

    // ── Stale eviction ─────────────────────────────────────────────────

    #[test]
    fn stale_entries_evicted() {
        let e = CoalesceEngine::new(Duration::from_millis(1), 100, 1024 * 1024);
        let k = key("/api/stale");
        e.try_coalesce(k, "GET", CoalescePolicy::SafeMethods);

        std::thread::sleep(Duration::from_millis(5));
        let evicted = e.evict_stale();
        assert_eq!(evicted, 1);
        assert_eq!(e.in_flight_count(), 0);
    }

    #[test]
    fn stale_entry_replaced_by_new_leader() {
        let e = CoalesceEngine::new(Duration::from_millis(1), 100, 1024 * 1024);
        let k = key("/api/retry");
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);

        std::thread::sleep(Duration::from_millis(5));

        // New request should become leader (stale entry gets replaced).
        let result = e.try_coalesce(k, "GET", CoalescePolicy::SafeMethods);
        assert_eq!(result, CoalesceResult::Leader);
    }

    // ── Remove ─────────────────────────────────────────────────────────

    #[test]
    fn remove_clears_entry() {
        let e = engine();
        let k = key("/api/temp");
        e.try_coalesce(k.clone(), "GET", CoalescePolicy::SafeMethods);
        assert_eq!(e.in_flight_count(), 1);

        e.remove(&k);
        assert_eq!(e.in_flight_count(), 0);
    }

    // ── CoalescedResponse ──────────────────────────────────────────────

    #[test]
    fn response_age() {
        let r = CoalescedResponse::new(200, vec![], vec![]);
        std::thread::sleep(Duration::from_millis(5));
        assert!(r.age() >= Duration::from_millis(1));
    }

    #[test]
    fn response_body_len() {
        let r = CoalescedResponse::new(200, vec![], b"hello world".to_vec());
        assert_eq!(r.body_len(), 11);
    }

    // ── InFlightEntry ──────────────────────────────────────────────────

    #[test]
    fn in_flight_stale_detection() {
        let k = key("/api/stale");
        let entry = InFlightEntry::new(k, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(entry.is_stale());
    }

    #[test]
    fn in_flight_not_stale_when_responded() {
        let k = key("/api/ok");
        let mut entry = InFlightEntry::new(k, Duration::from_millis(1));
        entry.set_response(CoalescedResponse::new(200, vec![], vec![]));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!entry.is_stale()); // Has response, not stale.
        assert!(entry.is_ready());
    }
}
