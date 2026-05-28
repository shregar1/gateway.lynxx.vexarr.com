//! LoadBalancer trait — upstream server selection.

/// Context passed to load balancers on each pick.
pub struct LbContext<'a> {
    /// Current timestamp in nanoseconds (for latency-aware LBs).
    pub now_ns: u64,
    /// Optional key bytes (for hash-based LBs like Maglev).
    pub key: Option<&'a [u8]>,
    /// Pre-computed hash of the key (avoids double-hashing).
    pub hash_key: Option<u64>,
}

impl<'a> LbContext<'a> {
    /// Create a minimal context with just a timestamp.
    pub fn new(now_ns: u64) -> Self {
        Self {
            now_ns,
            key: None,
            hash_key: None,
        }
    }

    /// Create a context with a hash key for consistent-hashing LBs.
    pub fn with_key(now_ns: u64, key: &'a [u8]) -> Self {
        Self {
            now_ns,
            key: Some(key),
            hash_key: None,
        }
    }
}

/// Upstream load balancer that picks a backend index.
pub trait LoadBalancer {
    /// Select the next backend. Returns an index into the backend list.
    fn pick(&mut self, ctx: &LbContext<'_>) -> usize;

    fn name(&self) -> &'static str;

    /// Number of backends this balancer is aware of.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
