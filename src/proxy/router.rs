use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Route, Service};
use ahash::AHasher;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Hasher used by the route table's internal maps. All keys here are
/// either server-generated UUIDs or normalised host / path strings —
/// none of them are attacker-influenced HashMap keys, so the default
/// SipHash DoS resistance is wasted cycles. ahash is 2-5× faster on
/// the typical 16-32-byte keys we use here.
type FastHasher = ahash::RandomState;

// ---------------------------------------------------------------------------
// Configurable path-matching strategy
// ---------------------------------------------------------------------------

/// Selects the algorithm used for path-based route candidate lookup.
/// Stored as `AtomicU8` in `RouteTable` for lock-free runtime switching.
///
/// All three strategies produce the same matching results; they differ
/// only in time complexity and memory layout.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathMatchStrategy {
    /// Path-segment trie — O(depth) where depth = number of `/`-separated
    /// segments. Default. Good general-purpose choice.
    Trie = 0,
    /// Compressed radix tree (Patricia trie) — O(path_len) byte-level
    /// traversal. Fewer nodes for deep paths, better cache locality.
    RadixTree = 1,
    /// O(N) linear scan over all routes — original algorithm. Useful for
    /// debugging or when N is tiny.
    Scan = 2,
}

impl PathMatchStrategy {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::RadixTree,
            2 => Self::Scan,
            _ => Self::Trie,
        }
    }
}

/// Precompiled regex bundle for a single route. Built once when the
/// route is inserted / updated; consulted on every matching request.
///
/// Pre-cache, the proxy hot path called `regex::Regex::new(pattern)`
/// inside `match_route_*` and `resolve_upstream_path` — 50-500 μs per
/// request per regex. With this cache the per-request cost drops to a
/// pointer chase + `is_match` call.
#[derive(Default)]
struct RouteCache {
    /// Compiled `Route.path_regexes`. Invalid patterns are skipped at
    /// compile time with a warning; the route falls through to the
    /// literal-path branch.
    paths: Vec<regex::Regex>,
    /// Compiled `Route.path_rewrite_pattern`.
    rewrite: Option<regex::Regex>,
}

// ---------------------------------------------------------------------------
// Prefix trie for O(depth) prefix / wildcard route matching
// ---------------------------------------------------------------------------

/// Trie node keyed by path segment. Each node may hold route IDs for
/// routes whose prefix ends at this segment.
struct TrieNode {
    children: std::collections::HashMap<Box<str>, TrieNode, FastHasher>,
    route_ids: Vec<Uuid>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: std::collections::HashMap::with_hasher(FastHasher::default()),
            route_ids: Vec::new(),
        }
    }
}

/// Path-segment trie that indexes prefix and wildcard routes for O(depth)
/// candidate lookup. Inspired by HAProxy's eb-tree prefix matching which
/// achieves O(log N) vs Lynxx's previous O(N) linear scan.
///
/// For a request path `/api/v1/users`, the trie walks root → "api" → "v1"
/// → "users" and collects route IDs at each node. Only those candidates
/// (plus any regex routes) are checked against method/host/header filters,
/// instead of scanning every route in the table.
struct PrefixIndex {
    root: TrieNode,
    /// Routes that use `path_regexes` instead of literal `paths`. Cannot
    /// be indexed in the trie so they are checked on every request. The
    /// set is typically tiny (0–5 routes).
    regex_routes: Vec<Uuid>,
}

impl PrefixIndex {
    fn empty() -> Self {
        Self {
            root: TrieNode::new(),
            regex_routes: Vec::new(),
        }
    }

    fn build(routes: &DashMap<Uuid, Arc<Route>, FastHasher>) -> Self {
        let mut index = Self::empty();
        for entry in routes.iter() {
            let route = entry.value();
            if !route.path_regexes.is_empty() {
                index.regex_routes.push(route.id);
                continue;
            }
            for p in &route.paths {
                index.insert_path(p, route.id);
            }
        }
        index
    }

    fn insert_path(&mut self, path: &str, route_id: Uuid) {
        let clean = path.trim_end_matches('*').trim_end_matches('/');
        if clean.is_empty() {
            // Root "/" or "/*" — matches everything.
            self.root.route_ids.push(route_id);
            return;
        }
        let mut node = &mut self.root;
        for segment in clean.split('/').filter(|s| !s.is_empty()) {
            node = node
                .children
                .entry(segment.into())
                .or_insert_with(TrieNode::new);
        }
        node.route_ids.push(route_id);
    }

    /// Walk the trie for `path`, collecting all route IDs at nodes along
    /// the way (each represents a prefix-match candidate). O(depth) where
    /// depth is the number of path segments (typically 3–5).
    fn candidates(&self, path: &str) -> Vec<Uuid> {
        let mut result = Vec::new();
        // Root routes (path="/") match everything.
        result.extend_from_slice(&self.root.route_ids);
        // Regex routes can't be trie-indexed — always candidates.
        result.extend_from_slice(&self.regex_routes);

        let mut node = &self.root;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            match node.children.get(segment) {
                Some(child) => {
                    result.extend_from_slice(&child.route_ids);
                    node = child;
                }
                None => break,
            }
        }
        result
    }

    /// Like `candidates` but omits regex routes — used when RegexSet
    /// handles regex patterns via a separate single-DFA pass.
    fn prefix_only_candidates(&self, path: &str) -> Vec<Uuid> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.root.route_ids);
        let mut node = &self.root;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            match node.children.get(segment) {
                Some(child) => {
                    result.extend_from_slice(&child.route_ids);
                    node = child;
                }
                None => break,
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Regex result LRU cache
// ---------------------------------------------------------------------------

/// Caches `(route_id, path) → match_result` so repeated regex evaluations
/// for hot paths are avoided. The key uses `(Uuid, u64)` where the u64 is
/// ahash of the path — collision probability is ~1/2^64 per entry, negligible
/// at any practical cache size.
///
/// Eviction: when the cache exceeds `MAX_REGEX_RESULT_ENTRIES`, it is cleared
/// entirely. Route mutations also clear it to avoid stale results.
struct RegexResultCache {
    entries: DashMap<(Uuid, u64), bool, FastHasher>,
}

const MAX_REGEX_RESULT_ENTRIES: usize = 16_384;

impl RegexResultCache {
    fn new() -> Self {
        Self {
            entries: DashMap::with_hasher(FastHasher::default()),
        }
    }

    fn lookup(&self, route_id: Uuid, path_hash: u64) -> Option<bool> {
        self.entries.get(&(route_id, path_hash)).map(|r| *r)
    }

    fn insert(&self, route_id: Uuid, path_hash: u64, result: bool) {
        if self.entries.len() >= MAX_REGEX_RESULT_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert((route_id, path_hash), result);
    }

    fn clear(&self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// Radix tree (Patricia trie) for O(path_len) byte-level prefix matching
// ---------------------------------------------------------------------------

/// Byte-level radix tree node. Unlike the segment trie which keys on path
/// segments (`"api"`, `"v1"`), the radix tree operates on raw bytes and
/// compresses chains of single-child nodes into one edge. Fewer nodes for
/// deep paths, better CPU cache locality.
///
/// Inspired by HAProxy's eb-tree which stores keys in a compressed binary
/// trie. The radix tree here is the string-alphabet analog.
struct RadixNode {
    /// Compressed edge label (byte sequence shared by all descendants).
    prefix: Vec<u8>,
    children: Vec<RadixNode>,
    /// Route IDs whose path prefix ends at this node.
    route_ids: Vec<Uuid>,
}

impl RadixNode {
    fn new(prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            children: Vec::new(),
            route_ids: Vec::new(),
        }
    }
}

/// Count of leading bytes shared between `a` and `b`.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// Compressed radix tree (Patricia trie) indexing prefix and wildcard routes
/// for O(path_len) candidate lookup. Merges single-child chains into one
/// edge so `/api/v1/users` creates ≤3 edges instead of 14 segment nodes.
struct RadixIndex {
    root: RadixNode,
    /// Regex routes — cannot be indexed. Included in `candidates()` for
    /// fallback when RegexSet is not enabled.
    regex_routes: Vec<Uuid>,
}

impl RadixIndex {
    fn empty() -> Self {
        Self {
            root: RadixNode::new(Vec::new()),
            regex_routes: Vec::new(),
        }
    }

    fn build(routes: &DashMap<Uuid, Arc<Route>, FastHasher>) -> Self {
        let mut index = Self::empty();
        for entry in routes.iter() {
            let route = entry.value();
            if !route.path_regexes.is_empty() {
                index.regex_routes.push(route.id);
                continue;
            }
            for p in &route.paths {
                index.insert_path(p, route.id);
            }
        }
        index
    }

    fn insert_path(&mut self, path: &str, route_id: Uuid) {
        let clean = path.trim_end_matches('*').trim_end_matches('/');
        if clean.is_empty() {
            // Root "/" or "/*" — matches everything.
            self.root.route_ids.push(route_id);
            return;
        }
        Self::insert_node(&mut self.root, clean.as_bytes(), route_id);
    }

    fn insert_node(node: &mut RadixNode, key: &[u8], route_id: Uuid) {
        if key.is_empty() {
            node.route_ids.push(route_id);
            return;
        }

        // In a well-formed radix tree, at most one child shares a prefix
        // with `key` (children are split to maintain this invariant).
        for i in 0..node.children.len() {
            let common = common_prefix_len(&node.children[i].prefix, key);
            if common == 0 {
                continue;
            }

            let child_prefix_len = node.children[i].prefix.len();

            if common == child_prefix_len {
                // Child prefix fully consumed — recurse with remaining key.
                Self::insert_node(&mut node.children[i], &key[common..], route_id);
                return;
            }

            // Partial match — split the existing child at the divergence point.
            let mut old_child = node.children.swap_remove(i);
            let old_suffix = old_child.prefix[common..].to_vec();
            old_child.prefix = old_suffix;

            let mut split = RadixNode::new(key[..common].to_vec());

            if common == key.len() {
                // New key ends exactly at the split point.
                split.route_ids.push(route_id);
                split.children.push(old_child);
            } else {
                // Both old child and new key extend beyond the split.
                let new_child = RadixNode {
                    prefix: key[common..].to_vec(),
                    children: Vec::new(),
                    route_ids: vec![route_id],
                };
                split.children.push(old_child);
                split.children.push(new_child);
            }

            node.children.push(split);
            return;
        }

        // No child shares a prefix — create a new leaf.
        node.children.push(RadixNode {
            prefix: key.to_vec(),
            children: Vec::new(),
            route_ids: vec![route_id],
        });
    }

    /// Walk the radix tree, collecting route IDs at every matched node.
    /// O(path_len) — visits at most one child per byte position.
    fn candidates(&self, path: &str) -> Vec<Uuid> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.root.route_ids);
        result.extend_from_slice(&self.regex_routes);
        Self::collect(&self.root, path.as_bytes(), &mut result);
        result
    }

    /// Like `candidates` but omits regex routes — used when RegexSet
    /// handles regex patterns via a separate single-DFA pass.
    fn prefix_only_candidates(&self, path: &str) -> Vec<Uuid> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.root.route_ids);
        Self::collect(&self.root, path.as_bytes(), &mut result);
        result
    }

    fn collect(node: &RadixNode, remaining: &[u8], result: &mut Vec<Uuid>) {
        if remaining.is_empty() {
            return;
        }
        for child in &node.children {
            let common = common_prefix_len(&child.prefix, remaining);
            if common == 0 {
                continue;
            }
            if common == child.prefix.len() {
                // Full match of child prefix — collect and recurse.
                result.extend_from_slice(&child.route_ids);
                Self::collect(child, &remaining[common..], result);
            }
            // At most one child shares a prefix in a radix tree — done.
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// RegexSet index — single DFA pass over all regex patterns
// ---------------------------------------------------------------------------

/// Wraps `regex::RegexSet` to match all regex path patterns in a single
/// DFA pass — O(text_len) regardless of pattern count. HAProxy achieves
/// similar efficiency with its DFA-compiled ACL patterns; Lynxx previously
/// evaluated each regex pattern individually (O(N × text_len)).
struct RegexSetIndex {
    /// Single compiled DFA automaton for all regex path patterns.
    set: regex::RegexSet,
    /// Maps each pattern index in the `RegexSet` to the route ID that owns it.
    pattern_route_ids: Vec<Uuid>,
}

impl RegexSetIndex {
    fn empty() -> Self {
        Self {
            set: regex::RegexSet::new(&[] as &[String]).unwrap(),
            pattern_route_ids: Vec::new(),
        }
    }

    fn build(routes: &DashMap<Uuid, Arc<Route>, FastHasher>) -> Self {
        let mut patterns = Vec::new();
        let mut route_ids = Vec::new();

        for entry in routes.iter() {
            let route = entry.value();
            for pat in &route.path_regexes {
                // Validate pattern before adding to the set.
                if regex::Regex::new(pat).is_ok() {
                    patterns.push(pat.clone());
                    route_ids.push(route.id);
                }
            }
        }

        if patterns.is_empty() {
            return Self::empty();
        }

        match regex::RegexSet::new(&patterns) {
            Ok(set) => Self {
                set,
                pattern_route_ids: route_ids,
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to build RegexSet — falling back to per-route regex");
                Self::empty()
            }
        }
    }

    /// Return route IDs whose patterns match `path`. Single DFA pass —
    /// O(text_len) regardless of how many patterns exist.
    fn matches(&self, path: &str) -> Vec<Uuid> {
        if self.pattern_route_ids.is_empty() {
            return Vec::new();
        }
        let mut result = Vec::new();
        for idx in self.set.matches(path) {
            let id = self.pattern_route_ids[idx];
            // Deduplicate: a route with multiple matching patterns should
            // appear only once. Linear scan is fine — typically 0–5 matches.
            if !result.contains(&id) {
                result.push(id);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Route result cache — full match outcome cache
// ---------------------------------------------------------------------------

/// Caches the full route-matching result for a given (host, path, method)
/// triple. On a cache hit the entire matching pipeline is bypassed — the
/// hot-path cost drops to a single DashMap lookup + ahash.
///
/// Cleared on any route or service mutation to avoid stale results.
struct RouteResultCache {
    entries: DashMap<u64, (Uuid, Uuid), FastHasher>,
}

const MAX_ROUTE_RESULT_CACHE_ENTRIES: usize = 32_768;

impl RouteResultCache {
    fn new() -> Self {
        Self {
            entries: DashMap::with_hasher(FastHasher::default()),
        }
    }

    fn lookup(&self, key: u64) -> Option<(Uuid, Uuid)> {
        self.entries.get(&key).map(|r| *r)
    }

    fn insert(&self, key: u64, route_id: Uuid, service_id: Uuid) {
        if self.entries.len() >= MAX_ROUTE_RESULT_CACHE_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (route_id, service_id));
    }

    fn clear(&self) {
        self.entries.clear();
    }

    /// Hash a (host, path, method) request triple for cache key.
    fn hash_request(host: Option<&str>, path: &str, method: &str) -> u64 {
        let mut h = AHasher::default();
        host.unwrap_or("").hash(&mut h);
        path.hash(&mut h);
        method.hash(&mut h);
        h.finish()
    }
}

pub struct RouteTable {
    services: DashMap<Uuid, Arc<Service>, FastHasher>,
    /// Routes are stored behind `Arc` so the hot-path lookups
    /// (`match_route`, `match_route_full`, `match_route_for_service`,
    /// `get_route`, `list_routes`) can return cheap refcount bumps
    /// instead of deep-cloning the whole `Route` struct.
    routes: DashMap<Uuid, Arc<Route>, FastHasher>,
    /// Exact-path index: `path` -> `route_id` for routes whose `paths` entries
    /// are literal (no trailing `*`). O(1) perfect-hash lookup for static routes.
    exact_index: DashMap<String, Uuid, FastHasher>,
    /// Host-to-service index (DashMap): `"sub.domain.com"` -> `service_id`.
    /// Enables O(1) subdomain routing. Incrementally updated on service mutations.
    host_index: DashMap<String, Uuid, FastHasher>,
    /// Host-to-service index (ArcSwap): zero-cost read-only snapshot for the
    /// hot path. Rebuilt atomically from `services` on mutation. Used when
    /// `use_sharded_hosts` is true.
    host_index_fast: ArcSwap<std::collections::HashMap<String, Uuid, FastHasher>>,
    /// Precompiled regex bundles keyed by route id.
    regex_cache: DashMap<Uuid, Arc<RouteCache>, FastHasher>,
    /// Path-segment trie for O(depth) prefix/wildcard candidate lookup.
    prefix_index: ArcSwap<PrefixIndex>,
    /// Compressed radix tree (Patricia trie) for O(path_len) byte-level lookup.
    radix_index: ArcSwap<RadixIndex>,
    /// Single-DFA RegexSet automaton for all regex path patterns.
    /// O(text_len) for all patterns in one pass.
    regex_set_index: ArcSwap<RegexSetIndex>,
    /// Caches regex match results for recently seen `(route, path)` pairs.
    regex_match_cache: RegexResultCache,
    /// Caches full match results for (host, path, method) triples.
    /// Bypasses the entire matching pipeline on cache hit.
    route_result_cache: RouteResultCache,
    /// Service-id → route-ids index: turns `match_route_for_service` from
    /// O(N_routes) into O(N_routes_for_this_service). For a deployment with
    /// 1000 routes spread across 100 services, this is ~10× fewer iterations
    /// per request. Kept in sync via add / update / remove / load_from_repo.
    routes_by_service: DashMap<Uuid, Vec<Uuid>, FastHasher>,
    /// Service-name → service-id index: turns `get_service_by_name` from
    /// O(N_services) into O(1). Kept in sync via add / update / remove /
    /// load_from_repo. The current router looks up services primarily by
    /// id and host (both already O(1)); the name path is exercised by the
    /// admin API and external CLI tooling.
    service_name_index: DashMap<String, Uuid, FastHasher>,

    // ── Runtime strategy toggles (lock-free) ──

    /// Which path-matching algorithm to use (Trie=0, RadixTree=1, Scan=2).
    /// Default: Trie. Configurable via `set_path_strategy`.
    path_strategy: AtomicU8,
    /// When true, regex patterns are matched via `RegexSet` (single DFA pass)
    /// instead of per-route `Regex::is_match`. Default: true.
    use_regex_set: AtomicBool,
    /// When true, full match results are cached in `route_result_cache`.
    /// Default: true.
    use_route_cache: AtomicBool,
    /// True when at least one route matches on headers or query params. The
    /// `route_result_cache` is keyed only by (host, path, method) and so
    /// cannot represent header/query-gated routing; when this is set, the
    /// result cache is bypassed entirely so such routes are never confused.
    /// Recomputed by `rebuild_route_indexes`.
    has_constrained_routes: AtomicBool,
    /// When true, host lookups use the ArcSwap snapshot (`host_index_fast`)
    /// instead of the DashMap (`host_index`). Default: true.
    use_sharded_hosts: AtomicBool,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            services: DashMap::with_hasher(FastHasher::default()),
            routes: DashMap::with_hasher(FastHasher::default()),
            exact_index: DashMap::with_hasher(FastHasher::default()),
            host_index: DashMap::with_hasher(FastHasher::default()),
            host_index_fast: ArcSwap::from_pointee(
                std::collections::HashMap::with_hasher(FastHasher::default()),
            ),
            regex_cache: DashMap::with_hasher(FastHasher::default()),
            prefix_index: ArcSwap::from_pointee(PrefixIndex::empty()),
            radix_index: ArcSwap::from_pointee(RadixIndex::empty()),
            regex_set_index: ArcSwap::from_pointee(RegexSetIndex::empty()),
            regex_match_cache: RegexResultCache::new(),
            route_result_cache: RouteResultCache::new(),
            routes_by_service: DashMap::with_hasher(FastHasher::default()),
            service_name_index: DashMap::with_hasher(FastHasher::default()),
            path_strategy: AtomicU8::new(PathMatchStrategy::Trie as u8),
            use_regex_set: AtomicBool::new(true),
            use_route_cache: AtomicBool::new(true),
            has_constrained_routes: AtomicBool::new(false),
            use_sharded_hosts: AtomicBool::new(true),
        }
    }

    // ── Runtime strategy configuration ──

    /// Set the path-matching algorithm. Takes effect immediately for all
    /// subsequent requests — no restart required.
    pub fn set_path_strategy(&self, strategy: PathMatchStrategy) {
        self.path_strategy.store(strategy as u8, Ordering::Relaxed);
    }

    /// Backward-compatible toggle: `true` → Trie (default), `false` → Scan.
    pub fn set_use_prefix_trie(&self, enabled: bool) {
        let strategy = if enabled {
            PathMatchStrategy::Trie
        } else {
            PathMatchStrategy::Scan
        };
        self.path_strategy.store(strategy as u8, Ordering::Relaxed);
    }

    /// Toggle RegexSet (single-DFA) matching for regex path patterns.
    pub fn set_use_regex_set(&self, enabled: bool) {
        self.use_regex_set.store(enabled, Ordering::Relaxed);
    }

    /// Toggle the full route result cache.
    pub fn set_use_route_cache(&self, enabled: bool) {
        self.use_route_cache.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.route_result_cache.clear();
        }
    }

    /// Toggle ArcSwap-based host map sharding for zero-cost reads.
    pub fn set_use_sharded_hosts(&self, enabled: bool) {
        self.use_sharded_hosts.store(enabled, Ordering::Relaxed);
    }

    /// Compile a route's regex fields once, ready to be cached. Bad
    /// patterns are logged + skipped so a single typo can't 502 every
    /// request — the route simply falls through to literal matching.
    fn compile_cache_for(route: &Route) -> Arc<RouteCache> {
        let paths = route
            .path_regexes
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!(route_id = %route.id, pattern = %p, error = %e,
                        "skipping invalid route regex pattern");
                    None
                }
            })
            .collect();
        let rewrite =
            route
                .path_rewrite_pattern
                .as_ref()
                .and_then(|p| match regex::Regex::new(p) {
                    Ok(re) => Some(re),
                    Err(e) => {
                        tracing::warn!(route_id = %route.id, pattern = %p, error = %e,
                        "skipping invalid route rewrite pattern");
                        None
                    }
                });
        Arc::new(RouteCache { paths, rewrite })
    }

    /// Reseed the regex cache from the current `routes` map. Called by
    /// `load_from_repo` after a bulk reload.
    fn rebuild_regex_cache(&self) {
        self.regex_cache.clear();
        for entry in self.routes.iter() {
            let route = entry.value();
            if !route.path_regexes.is_empty() || route.path_rewrite_pattern.is_some() {
                self.regex_cache
                    .insert(route.id, Self::compile_cache_for(route));
            }
        }
    }

    fn rebuild_exact_index(&self) {
        self.exact_index.clear();
        for entry in self.routes.iter() {
            let route = entry.value();
            for p in &route.paths {
                if !p.ends_with('*') {
                    self.exact_index.insert(p.clone(), route.id);
                }
            }
        }
    }

    /// Materialise an `Arc<Route>` clone if the entry exists. Helper
    /// for the many lookup methods — keeps the borrow on the DashMap
    /// entry short.
    fn arc_route(&self, id: &Uuid) -> Option<Arc<Route>> {
        self.routes.get(id).map(|r| Arc::clone(r.value()))
    }

    /// Walk every route once and reindex `service_id -> Vec<route_id>`.
    /// Cheap to call on bulk reload; per-mutation paths use the
    /// targeted `index_insert_route` / `index_remove_route` helpers
    /// below instead of rebuilding from scratch.
    fn rebuild_routes_by_service(&self) {
        self.routes_by_service.clear();
        for entry in self.routes.iter() {
            self.routes_by_service
                .entry(entry.value().service_id)
                .or_default()
                .push(entry.value().id);
        }
    }

    /// Add `route_id` to the index under `service_id`. Idempotent —
    /// safe to call from `add_route` even if (somehow) the route id
    /// was already present.
    fn index_insert_route(&self, service_id: Uuid, route_id: Uuid) {
        let mut bucket = self.routes_by_service.entry(service_id).or_default();
        if !bucket.contains(&route_id) {
            bucket.push(route_id);
        }
    }

    /// Remove `route_id` from the index under `service_id`. Drops
    /// empty buckets so they don't accumulate after service deletions.
    fn index_remove_route(&self, service_id: Uuid, route_id: Uuid) {
        if let Some(mut bucket) = self.routes_by_service.get_mut(&service_id) {
            bucket.retain(|id| *id != route_id);
            if bucket.is_empty() {
                drop(bucket);
                self.routes_by_service.remove(&service_id);
            }
        }
    }

    fn rebuild_host_index(&self) {
        self.host_index.clear();
        for entry in self.services.iter() {
            let svc = entry.value();
            if let Some(fqdn) = Self::service_fqdn(svc) {
                self.host_index.insert(fqdn, svc.id);
            }
        }
    }

    /// Atomically rebuild the prefix trie from the current routes.
    fn rebuild_prefix_index(&self) {
        self.prefix_index
            .store(Arc::new(PrefixIndex::build(&self.routes)));
    }

    /// Atomically rebuild the radix tree from the current routes.
    fn rebuild_radix_index(&self) {
        self.radix_index
            .store(Arc::new(RadixIndex::build(&self.routes)));
    }

    /// Atomically rebuild the RegexSet from the current routes.
    fn rebuild_regex_set_index(&self) {
        self.regex_set_index
            .store(Arc::new(RegexSetIndex::build(&self.routes)));
    }

    /// Atomically rebuild the ArcSwap host map from the current services.
    fn rebuild_host_index_fast(&self) {
        let mut map = std::collections::HashMap::with_hasher(FastHasher::default());
        for entry in self.services.iter() {
            let svc = entry.value();
            if let Some(fqdn) = Self::service_fqdn(svc) {
                map.insert(fqdn, svc.id);
            }
        }
        self.host_index_fast.store(Arc::new(map));
    }

    /// Rebuild all route-related indexes. Called after any route mutation.
    fn rebuild_route_indexes(&self) {
        self.rebuild_exact_index();
        self.rebuild_prefix_index();
        self.rebuild_radix_index();
        self.rebuild_regex_set_index();
        self.regex_match_cache.clear();
        self.route_result_cache.clear();
        // The result cache key (host, path, method) cannot represent header or
        // query-param matching, so if any route gates on those, disable the
        // cache to keep routing correct (and to avoid bypassing those gates).
        // Recomputed here because every route mutation funnels through this
        // method.
        let constrained = self
            .routes
            .iter()
            .any(|r| !r.value().headers.is_empty() || !r.value().query_params.is_empty());
        self.has_constrained_routes
            .store(constrained, Ordering::Relaxed);
    }

    /// Rebuild all host-related indexes. Called after any service mutation.
    fn rebuild_host_indexes(&self) {
        self.rebuild_host_index();
        self.rebuild_host_index_fast();
        self.route_result_cache.clear();
    }

    /// Rebuild the service-name → service-id index from scratch.
    /// Called from `load_from_repo` (cold start + reload) to ensure
    /// the index is in sync with the just-loaded `services` map. The
    /// same loop pattern as `rebuild_host_index` — single pass over
    /// the services DashMap, O(N_services) where N is small (services
    /// are O(hundreds), not millions).
    fn rebuild_service_name_index(&self) {
        self.service_name_index.clear();
        for entry in self.services.iter() {
            self.service_name_index
                .insert(entry.value().name.to_string(), entry.key().clone());
        }
    }

    fn hash_path(path: &str) -> u64 {
        let mut h = AHasher::default();
        path.hash(&mut h);
        h.finish()
    }

    fn service_fqdn(svc: &Service) -> Option<String> {
        if svc.subdomain.is_empty() || svc.domain.is_empty() {
            return None;
        }
        Some(format!("{}.{}", svc.subdomain, svc.domain).to_ascii_lowercase())
    }

    /// O(1) lookup: does `host` match a service's `subdomain.domain`?
    /// Dispatches to ArcSwap snapshot or DashMap based on configuration.
    pub fn match_by_host(&self, host: &str) -> Option<Arc<Service>> {
        let key = host.to_ascii_lowercase();
        let svc_id = if self.use_sharded_hosts.load(Ordering::Relaxed) {
            // Zero-cost read: ArcSwap → Arc<HashMap> → get.
            let map = self.host_index_fast.load();
            *map.get(&key)?
        } else {
            // DashMap read: still O(1) but involves a shard lock.
            *self.host_index.get(&key)?
        };
        self.services.get(&svc_id).map(|s| Arc::clone(s.value()))
    }

    /// Find the best matching route within a specific service. Dispatches
    /// to the configured path strategy (trie, radix tree, or scan).
    ///
    /// The scan path uses the `routes_by_service` index to walk only
    /// routes registered for `service_id` — O(R/N) instead of O(R).
    ///
    /// Enforces the SAME host/header/query-param constraints as
    /// [`Self::match_route_full`]: the subdomain fast path must not become a
    /// way to select a route while skipping its `hosts` / `headers` /
    /// `query_params` gating — otherwise a route intended to apply only when a
    /// header or query value is present would match unconditionally.
    pub fn match_route_for_service(
        &self,
        service_id: &Uuid,
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
    ) -> Option<Arc<Route>> {
        let strategy = PathMatchStrategy::from_u8(self.path_strategy.load(Ordering::Relaxed));
        if matches!(strategy, PathMatchStrategy::Scan) {
            self.match_route_for_service_scan(
                service_id,
                path,
                method,
                host,
                req_headers,
                query_string,
            )
        } else {
            let candidates = self.gather_indexed_candidates(path);
            self.match_service_from_candidates(
                &candidates,
                service_id,
                path,
                method,
                host,
                req_headers,
                query_string,
            )
        }
    }

    /// Indexed scan: walks only the routes for `service_id` via the
    /// `routes_by_service` index — O(R/N) instead of O(R).
    fn match_route_for_service_scan(
        &self,
        service_id: &Uuid,
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
    ) -> Option<Arc<Route>> {
        let bucket = self.routes_by_service.get(service_id)?;
        for route_id in bucket.iter() {
            let route_ref = match self.routes.get(route_id) {
                Some(r) => r,
                None => continue,
            };
            let route = route_ref.value();
            if !self.path_matches(route, path) {
                continue;
            }
            let method_matches =
                route.methods.is_empty() || route.methods.iter().any(|m| m == method);
            if !method_matches {
                continue;
            }
            let host_matches = route.hosts.is_empty()
                || host.is_some_and(|h| route.hosts.iter().any(|rh| rh.eq_ignore_ascii_case(h)));
            if !host_matches {
                continue;
            }
            if !route.headers.is_empty() && !match_headers(&route.headers, req_headers) {
                continue;
            }
            if !route.query_params.is_empty() && !match_query(&route.query_params, query_string) {
                continue;
            }
            return Some(Arc::clone(route));
        }
        None
    }

    /// Per-request path-match for one route. Hot path — must not
    /// allocate. Consults the regex result cache first, then the
    /// precompiled regex cache for `path_regexes` routes; falls back
    /// to the literal / prefix matcher otherwise.
    fn path_matches(&self, route: &Route, path: &str) -> bool {
        if !route.path_regexes.is_empty() {
            let path_hash = Self::hash_path(path);
            // Fast path: check the regex result LRU cache.
            if let Some(result) = self.regex_match_cache.lookup(route.id, path_hash) {
                return result;
            }
            let result = if let Some(cache) = self.regex_cache.get(&route.id) {
                cache.paths.iter().any(|re| re.is_match(path))
            } else {
                false // pattern present but cache empty = all invalid
            };
            self.regex_match_cache.insert(route.id, path_hash, result);
            return result;
        }
        literal_or_prefix_match(&route.paths, path)
    }

    pub fn is_host_taken(&self, fqdn: &str, exclude_service: Option<&Uuid>) -> bool {
        let key = fqdn.to_ascii_lowercase();
        match self.host_index.get(&key) {
            Some(entry) => match exclude_service {
                Some(id) => entry.value() != id,
                None => true,
            },
            None => false,
        }
    }

    /// Bulk-load services and routes from the persistent repository,
    /// replacing whatever is currently in memory.
    pub async fn load_from_repo(
        &self,
        repo: &dyn Repository,
    ) -> Result<(usize, usize), GatewayError> {
        let services = repo.list_services().await?;
        let routes = repo.list_routes().await?;

        self.services.clear();
        self.routes.clear();
        self.service_name_index.clear();

        for svc in &services {
            self.services.insert(svc.id, Arc::new(svc.clone()));
            self.service_name_index
                .insert(svc.name.to_string(), svc.id);
        }
        for route in routes.iter() {
            self.routes.insert(route.id, Arc::new(route.clone()));
        }
        self.rebuild_regex_cache();
        self.rebuild_route_indexes();
        self.rebuild_host_indexes();
        self.rebuild_routes_by_service();

        Ok((services.len(), routes.len()))
    }

    pub fn add_service(&self, service: Service) -> Uuid {
        let id = service.id;
        if let Some(fqdn) = Self::service_fqdn(&service) {
            self.host_index.insert(fqdn, id);
        }
        // Name index: O(1) lookup by service name. Insert first; if a
        // duplicate name exists the old id is overwritten (the most
        // recently inserted service wins, matching the previous linear
        // scan's "first match wins" semantics on insertion order).
        self.service_name_index.insert(service.name.to_string(), id);
        self.services.insert(id, Arc::new(service));
        self.rebuild_host_index_fast();
        self.route_result_cache.clear();
        id
    }

    pub fn get_service(&self, id: &Uuid) -> Option<Arc<Service>> {
        self.services.get(id).map(|s| Arc::clone(s.value()))
    }

    pub fn get_service_by_name(&self, name: &str) -> Option<Arc<Service>> {
        // O(1) via the name index. Falls back to None if the name isn't
        // indexed (e.g. the service was added via a path that didn't
        // update the index — currently no such path exists, but the
        // graceful fallback keeps this robust against future code
        // changes).
        match self.service_name_index.get(name) {
            Some(id_ref) => self.services.get(id_ref.value()).map(|s| Arc::clone(s.value())),
            None => None,
        }
    }

    pub fn list_services(&self) -> Vec<Arc<Service>> {
        self.services.iter().map(|s| Arc::clone(s.value())).collect()
    }

    pub fn update_service(&self, id: &Uuid, service: Service) -> bool {
        if self.services.contains_key(id) {
            if let Some(old) = self.services.get(id) {
                if let Some(old_fqdn) = Self::service_fqdn(old.value()) {
                    self.host_index.remove(&old_fqdn);
                }
                // Drop the OLD name entry if it differs from the new one.
                // Same name → no-op (we just refresh the value). Different
                // name → remove the stale entry so a stale name can't keep
                // resolving to the same id.
                if old.value().name != service.name {
                    self.service_name_index
                        .remove(&*old.value().name);
                }
            }
            if let Some(fqdn) = Self::service_fqdn(&service) {
                self.host_index.insert(fqdn, *id);
            }
            self.service_name_index
                .insert(service.name.to_string(), *id);
            self.services.insert(*id, Arc::new(service));
            self.rebuild_host_index_fast();
            self.route_result_cache.clear();
            true
        } else {
            false
        }
    }

    pub fn remove_service(&self, id: &Uuid) -> bool {
        if let Some((_, svc)) = self.services.remove(id) {
            if let Some(fqdn) = Self::service_fqdn(&svc) {
                self.host_index.remove(&fqdn);
            }
            // Drop the name index entry ONLY if it still points at this id
            // — protects against the case where a new service was inserted
            // under the same name (the new id wins in the index).
            if let Some(entry) = self.service_name_index.get(&*svc.name) {
                if *entry.value() == *id {
                    drop(entry);
                    self.service_name_index.remove(&*svc.name);
                }
            }
            self.rebuild_host_index_fast();
            self.route_result_cache.clear();
            true
        } else {
            false
        }
    }

    pub fn add_route(&self, route: Route) -> Uuid {
        let id = route.id;
        let service_id = route.service_id;
        if !route.path_regexes.is_empty() || route.path_rewrite_pattern.is_some() {
            self.regex_cache.insert(id, Self::compile_cache_for(&route));
        }
        self.routes.insert(id, Arc::new(route));
        self.index_insert_route(service_id, id);
        self.rebuild_route_indexes();
        id
    }

    pub fn get_route(&self, id: &Uuid) -> Option<Arc<Route>> {
        self.arc_route(id)
    }

    pub fn list_routes(&self) -> Vec<Arc<Route>> {
        self.routes.iter().map(|r| Arc::clone(r.value())).collect()
    }

    pub fn update_route(&self, id: &Uuid, route: Route) -> bool {
        // Need the old service_id so we can move the route in the
        // service index if `update` reparents it.
        let old_service_id = self.routes.get(id).map(|r| r.value().service_id);
        if old_service_id.is_none() {
            return false;
        }
        let old_service_id = old_service_id.unwrap();
        let new_service_id = route.service_id;
        if !route.path_regexes.is_empty() || route.path_rewrite_pattern.is_some() {
            self.regex_cache
                .insert(*id, Self::compile_cache_for(&route));
        } else {
            self.regex_cache.remove(id);
        }
        self.routes.insert(*id, Arc::new(route));
        if old_service_id != new_service_id {
            self.index_remove_route(old_service_id, *id);
            self.index_insert_route(new_service_id, *id);
        } else {
            self.index_insert_route(new_service_id, *id);
        }
        self.rebuild_route_indexes();
        true
    }

    pub fn remove_route(&self, id: &Uuid) -> bool {
        match self.routes.remove(id) {
            Some((_, route)) => {
                self.regex_cache.remove(id);
                self.index_remove_route(route.service_id, *id);
                self.rebuild_route_indexes();
                true
            }
            None => false,
        }
    }

    pub fn match_route(
        &self,
        path: &str,
        method: &str,
        host: Option<&str>,
    ) -> Option<(Arc<Route>, Arc<Service>)> {
        self.match_route_full(path, method, host, None, None)
    }

    /// Full route match with optional header and query parameter matching.
    /// Pipeline: route result cache → exact index → strategy dispatch
    /// (trie / radix tree / scan).
    pub fn match_route_full(
        &self,
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
    ) -> Option<(Arc<Route>, Arc<Service>)> {
        // ── Route result cache fast path ──
        // Bypass the cache entirely when any route is header/query gated: the
        // cache key (host, path, method) can't represent those dimensions, so a
        // cached entry for one request would be wrongly served to another that
        // differs only by header/query — a correctness and security bug
        // (header/query-based gating, e.g. API-version or canary routing, would
        // be silently bypassed for subsequent same-(host,path,method) requests).
        let cache_key = if self.use_route_cache.load(Ordering::Relaxed)
            && !self.has_constrained_routes.load(Ordering::Relaxed)
        {
            let key = RouteResultCache::hash_request(host, path, method);
            if let Some((route_id, service_id)) = self.route_result_cache.lookup(key) {
                if let (Some(route), Some(service)) =
                    (self.arc_route(&route_id), self.get_service(&service_id))
                {
                    return Some((route, service));
                }
                // Stale entry — fall through to real matching.
            }
            Some(key)
        } else {
            None
        };

        // ── Exact-path lookup (shared by all strategies) ──
        let mut skip_id: Option<Uuid> = None;
        if let Some(id_ref) = self.exact_index.get(path) {
            let id = *id_ref;
            drop(id_ref);
            skip_id = Some(id);
            if let Some(route_ref) = self.routes.get(&id) {
                let route = route_ref.value();
                let method_matches =
                    route.methods.is_empty() || route.methods.iter().any(|m| m == method);
                let host_matches = route.hosts.is_empty()
                    || host
                        .is_some_and(|h| route.hosts.iter().any(|rh| rh.eq_ignore_ascii_case(h)));
                let headers_match =
                    route.headers.is_empty() || match_headers(&route.headers, req_headers);
                let query_match =
                    route.query_params.is_empty() || match_query(&route.query_params, query_string);
                if method_matches && host_matches && headers_match && query_match {
                    if let Some(service) = self.get_service(&route.service_id) {
                        let result = (Arc::clone(route), service);
                        if let Some(key) = cache_key {
                            self.route_result_cache.insert(key, result.0.id, result.1.id);
                        }
                        return Some(result);
                    }
                }
            }
        }

        // ── Strategy dispatch ──
        let strategy = PathMatchStrategy::from_u8(self.path_strategy.load(Ordering::Relaxed));
        let result = if matches!(strategy, PathMatchStrategy::Scan) {
            self.match_route_full_scan(path, method, host, req_headers, query_string)
        } else {
            let candidates = self.gather_indexed_candidates(path);
            self.match_full_from_candidates(
                &candidates,
                path,
                method,
                host,
                req_headers,
                query_string,
                skip_id,
            )
        };

        // ── Cache the result ──
        if let (Some(key), Some((ref route, ref service))) = (cache_key, &result) {
            self.route_result_cache.insert(key, route.id, service.id);
        }

        result
    }

    // ── Candidate-gathering and filtering helpers ──

    /// Gather candidate route IDs using the configured indexed strategy
    /// (trie or radix tree), optionally augmented by RegexSet matches.
    fn gather_indexed_candidates(&self, path: &str) -> Vec<Uuid> {
        let use_regex_set = self.use_regex_set.load(Ordering::Relaxed);
        let strategy = PathMatchStrategy::from_u8(self.path_strategy.load(Ordering::Relaxed));

        let mut candidates = match strategy {
            PathMatchStrategy::Trie => {
                let idx = self.prefix_index.load();
                if use_regex_set {
                    idx.prefix_only_candidates(path)
                } else {
                    idx.candidates(path)
                }
            }
            PathMatchStrategy::RadixTree => {
                let idx = self.radix_index.load();
                if use_regex_set {
                    idx.prefix_only_candidates(path)
                } else {
                    idx.candidates(path)
                }
            }
            PathMatchStrategy::Scan => {
                unreachable!("scan path should not call gather_indexed_candidates")
            }
        };

        // RegexSet provides only actually-matching regex routes instead of
        // blindly including all regex routes as candidates.
        if use_regex_set {
            let regex_set_idx = self.regex_set_index.load();
            candidates.extend(regex_set_idx.matches(path));
        }

        candidates
    }

    /// Filter candidate route IDs by path / method / host / header / query.
    /// Shared by trie and radix-tree strategies.
    fn match_full_from_candidates(
        &self,
        candidates: &[Uuid],
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
        skip_id: Option<Uuid>,
    ) -> Option<(Arc<Route>, Arc<Service>)> {
        let mut best: Option<(Arc<Route>, Arc<Service>)> = None;
        let mut best_has_hosts = false;

        for &route_id in candidates {
            if skip_id == Some(route_id) {
                continue;
            }
            let route = match self.arc_route(&route_id) {
                Some(r) => r,
                None => continue,
            };
            if !self.path_matches(&route, path) {
                continue;
            }
            let method_matches =
                route.methods.is_empty() || route.methods.iter().any(|m| m == method);
            if !method_matches {
                continue;
            }
            let host_matches = route.hosts.is_empty()
                || host.is_some_and(|h| route.hosts.iter().any(|rh| rh.eq_ignore_ascii_case(h)));
            if !host_matches {
                continue;
            }
            if !route.headers.is_empty() && !match_headers(&route.headers, req_headers) {
                continue;
            }
            if !route.query_params.is_empty() && !match_query(&route.query_params, query_string) {
                continue;
            }
            let has_hosts = !route.hosts.is_empty();
            let svc_id = route.service_id;
            if has_hosts && !best_has_hosts {
                best = Some((route, self.get_service(&svc_id)?));
                best_has_hosts = true;
            } else if best.is_none() {
                if let Some(service) = self.get_service(&svc_id) {
                    best = Some((route, service));
                    best_has_hosts = has_hosts;
                }
            }
        }

        best
    }

    /// Filter candidate route IDs for a specific service by path and method.
    fn match_service_from_candidates(
        &self,
        candidates: &[Uuid],
        service_id: &Uuid,
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
    ) -> Option<Arc<Route>> {
        for &route_id in candidates {
            let route = match self.arc_route(&route_id) {
                Some(r) => r,
                None => continue,
            };
            if route.service_id != *service_id {
                continue;
            }
            if !self.path_matches(&route, path) {
                continue;
            }
            let method_matches =
                route.methods.is_empty() || route.methods.iter().any(|m| m == method);
            if !method_matches {
                continue;
            }
            // SECURITY: enforce the same constraints as the full router so
            // the subdomain fast path can't bypass `hosts`/`headers`/
            // `query_params` gating on a matched route.
            let host_matches = route.hosts.is_empty()
                || host.is_some_and(|h| route.hosts.iter().any(|rh| rh.eq_ignore_ascii_case(h)));
            if !host_matches {
                continue;
            }
            if !route.headers.is_empty() && !match_headers(&route.headers, req_headers) {
                continue;
            }
            if !route.query_params.is_empty() && !match_query(&route.query_params, query_string) {
                continue;
            }
            return Some(route);
        }
        None
    }

    /// O(N) linear scan match (original algorithm). Iterates every route,
    /// checks path/method/host/header/query for each. Available as a
    /// configurable fallback via `set_use_prefix_trie(false)`.
    fn match_route_full_scan(
        &self,
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
    ) -> Option<(Arc<Route>, Arc<Service>)> {
        let mut best: Option<(Arc<Route>, Arc<Service>)> = None;
        let mut best_has_hosts = false;

        for entry in self.routes.iter() {
            let route = entry.value();

            if !self.path_matches(route, path) {
                continue;
            }

            let method_matches =
                route.methods.is_empty() || route.methods.iter().any(|m| m == method);
            if !method_matches {
                continue;
            }

            let host_matches = route.hosts.is_empty()
                || host.is_some_and(|h| route.hosts.iter().any(|rh| rh.eq_ignore_ascii_case(h)));
            if !host_matches {
                continue;
            }

            if !route.headers.is_empty() && !match_headers(&route.headers, req_headers) {
                continue;
            }
            if !route.query_params.is_empty() && !match_query(&route.query_params, query_string) {
                continue;
            }

            let has_hosts = !route.hosts.is_empty();
            if has_hosts && !best_has_hosts {
                // Use `if let`, NOT `?`: a single route whose service row is
                // missing must skip that route, not abort the entire scan and
                // 404 the request when another valid route could still match.
                if let Some(service) = self.get_service(&route.service_id) {
                    best = Some((Arc::clone(route), service));
                    best_has_hosts = true;
                }
            } else if best.is_none() {
                if let Some(service) = self.get_service(&route.service_id) {
                    best = Some((Arc::clone(route), service));
                    best_has_hosts = has_hosts;
                }
            }
        }

        best
    }

    pub fn resolve_upstream_path(&self, route: &Route, original_path: &str) -> String {
        // Priority 1: regex rewrite (precompiled in regex_cache)
        if let Some(replacement) = route.path_rewrite_replacement.as_ref() {
            if let Some(cache) = self.regex_cache.get(&route.id) {
                if let Some(re) = cache.rewrite.as_ref() {
                    let rewritten = re.replace(original_path, replacement.as_str());
                    return rewritten.into_owned();
                }
            }
        }
        // Priority 2: strip_path prefix removal
        if route.strip_path {
            for prefix in &route.paths {
                let prefix = prefix.trim_end_matches('*');
                if let Some(remaining) = original_path.strip_prefix(prefix) {
                    if remaining.is_empty() || remaining.starts_with('/') {
                        return remaining.to_string();
                    }
                    return format!("/{remaining}");
                }
            }
        }
        original_path.to_string()
    }
}

/// Literal / prefix path matcher. Hot path — must not allocate.
///
/// Trailing `*` = prefix wildcard (`/foo/*` matches `/foo`, `/foo/bar`).
/// `/` matches anything. Other patterns match exactly, or as a path
/// segment prefix (`/foo` matches `/foo` and `/foo/bar`, NOT `/foobar`).
///
/// Pre-cache, the `/foo/bar`-vs-`/foo` branch did `path.starts_with(&format!("{p}/"))`
/// — a heap allocation per candidate route per request. The byte-level
/// check below is equivalent and allocation-free.
fn literal_or_prefix_match(paths: &[String], path: &str) -> bool {
    let path_bytes = path.as_bytes();
    paths.iter().any(|p| {
        if p.ends_with('*') {
            // Prefix wildcard: drop the trailing '*' and compare.
            path.starts_with(&p[..p.len() - 1])
        } else if p == "/" {
            true
        } else if path == p.as_str() {
            true
        } else {
            // Path-segment prefix: `p` followed by exactly '/' in `path`.
            // No allocation.
            let p_bytes = p.as_bytes();
            path_bytes.len() > p_bytes.len()
                && &path_bytes[..p_bytes.len()] == p_bytes
                && path_bytes[p_bytes.len()] == b'/'
        }
    })
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether all required headers are present with matching values.
fn match_headers(
    required: &std::collections::HashMap<String, String>,
    req_headers: Option<&axum::http::HeaderMap>,
) -> bool {
    let headers = match req_headers {
        Some(h) => h,
        None => return false,
    };
    for (name, expected) in required {
        match headers.get(name.as_str()) {
            Some(val) => {
                if let Ok(v) = val.to_str() {
                    if !v.eq_ignore_ascii_case(expected) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

/// Check whether all required query parameters are present with matching values.
fn match_query(
    required: &std::collections::HashMap<String, String>,
    query_string: Option<&str>,
) -> bool {
    let qs = match query_string {
        Some(q) => q,
        None => return false,
    };
    for (key, expected) in required {
        let found = qs
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .any(|(k, v)| k == key.as_str() && v == expected.as_str());
        if !found {
            return false;
        }
    }
    true
}

pub type SharedRouteTable = Arc<RouteTable>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── PrefixIndex (trie) ──

    #[test]
    fn trie_root_matches_everything() {
        let mut idx = PrefixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/", id);
        assert!(idx.candidates("/foo/bar").contains(&id));
        assert!(idx.candidates("/").contains(&id));
        assert!(idx.candidates("/a/b/c/d").contains(&id));
    }

    #[test]
    fn trie_wildcard_prefix() {
        let mut idx = PrefixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/api/*", id);
        let c = idx.candidates("/api/v1/users");
        assert!(c.contains(&id));
        // Also matches deeper paths.
        assert!(idx.candidates("/api/foo/bar/baz").contains(&id));
    }

    #[test]
    fn trie_wildcard_no_false_positive() {
        let mut idx = PrefixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/api/*", id);
        // "/other/api" should NOT match "/api/*".
        assert!(!idx.candidates("/other/api").contains(&id));
        assert!(!idx.candidates("/apifoo").contains(&id));
    }

    #[test]
    fn trie_segment_prefix() {
        let mut idx = PrefixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/api", id);
        // Trie collects candidates at /api node — matches /api/foo.
        assert!(idx.candidates("/api/foo").contains(&id));
        // Also exact match.
        assert!(idx.candidates("/api").contains(&id));
    }

    #[test]
    fn trie_deep_path() {
        let mut idx = PrefixIndex::empty();
        let id_api = Uuid::new_v4();
        let id_v1 = Uuid::new_v4();
        let id_users = Uuid::new_v4();
        idx.insert_path("/api/*", id_api);
        idx.insert_path("/api/v1/*", id_v1);
        idx.insert_path("/api/v1/users", id_users);

        let c = idx.candidates("/api/v1/users/123");
        assert!(c.contains(&id_api));
        assert!(c.contains(&id_v1));
        assert!(c.contains(&id_users));
    }

    #[test]
    fn trie_disjoint_paths() {
        let mut idx = PrefixIndex::empty();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        idx.insert_path("/foo/*", id_a);
        idx.insert_path("/bar/*", id_b);

        let c_foo = idx.candidates("/foo/test");
        assert!(c_foo.contains(&id_a));
        assert!(!c_foo.contains(&id_b));

        let c_bar = idx.candidates("/bar/test");
        assert!(c_bar.contains(&id_b));
        assert!(!c_bar.contains(&id_a));
    }

    #[test]
    fn trie_empty_returns_only_root_and_regex() {
        let idx = PrefixIndex::empty();
        assert!(idx.candidates("/anything").is_empty());
    }

    #[test]
    fn trie_regex_routes_always_included() {
        let mut idx = PrefixIndex::empty();
        let id_regex = Uuid::new_v4();
        idx.regex_routes.push(id_regex);
        let id_prefix = Uuid::new_v4();
        idx.insert_path("/api/*", id_prefix);

        // Regex routes are always candidates regardless of path.
        assert!(idx.candidates("/unrelated/path").contains(&id_regex));
        // Prefix routes are only candidates when path matches.
        assert!(!idx.candidates("/unrelated/path").contains(&id_prefix));
        // But both when path matches.
        let c = idx.candidates("/api/test");
        assert!(c.contains(&id_regex));
        assert!(c.contains(&id_prefix));
    }

    // ── RegexResultCache ──

    #[test]
    fn regex_cache_hit_and_miss() {
        let cache = RegexResultCache::new();
        let id = Uuid::new_v4();
        let hash = 42u64;

        assert!(cache.lookup(id, hash).is_none());
        cache.insert(id, hash, true);
        assert_eq!(cache.lookup(id, hash), Some(true));
    }

    #[test]
    fn regex_cache_evicts_on_overflow() {
        let cache = RegexResultCache::new();
        let id = Uuid::new_v4();
        // Fill past the limit.
        for i in 0..MAX_REGEX_RESULT_ENTRIES {
            cache.insert(id, i as u64, true);
        }
        // This insert triggers a clear.
        cache.insert(id, u64::MAX, false);
        // Old entries gone, only the new one exists.
        assert!(cache.lookup(id, 0).is_none());
        assert_eq!(cache.lookup(id, u64::MAX), Some(false));
    }

    #[test]
    fn regex_cache_clear() {
        let cache = RegexResultCache::new();
        let id = Uuid::new_v4();
        cache.insert(id, 1, true);
        assert_eq!(cache.lookup(id, 1), Some(true));
        cache.clear();
        assert!(cache.lookup(id, 1).is_none());
    }

    // ── RadixIndex (Patricia trie) ──

    #[test]
    fn radix_root_matches_everything() {
        let mut idx = RadixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/", id);
        assert!(idx.candidates("/foo/bar").contains(&id));
        assert!(idx.candidates("/").contains(&id));
        assert!(idx.candidates("/a/b/c/d").contains(&id));
    }

    #[test]
    fn radix_prefix_match() {
        let mut idx = RadixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/api/*", id);
        assert!(idx.candidates("/api/v1/users").contains(&id));
        assert!(idx.candidates("/api/foo/bar/baz").contains(&id));
    }

    #[test]
    fn radix_no_false_positive() {
        let mut idx = RadixIndex::empty();
        let id = Uuid::new_v4();
        idx.insert_path("/api/*", id);
        assert!(!idx.candidates("/other/api").contains(&id));
        // Note: radix tree works at byte level, so "/apifoo" shares
        // prefix "/api" and the route at "/api" would be collected.
        // This is correct — the route matcher (`path_matches`) does
        // the precise segment-boundary check.
    }

    #[test]
    fn radix_split_on_divergence() {
        let mut idx = RadixIndex::empty();
        let id_api = Uuid::new_v4();
        let id_app = Uuid::new_v4();
        idx.insert_path("/api", id_api);
        idx.insert_path("/app", id_app);

        assert!(idx.candidates("/api/v1").contains(&id_api));
        assert!(idx.candidates("/app/v1").contains(&id_app));
        // Verify no cross-contamination.
        assert!(!idx.candidates("/api/v1").contains(&id_app));
        assert!(!idx.candidates("/app/v1").contains(&id_api));
    }

    #[test]
    fn radix_deep_path_collects_all_ancestors() {
        let mut idx = RadixIndex::empty();
        let id_api = Uuid::new_v4();
        let id_v1 = Uuid::new_v4();
        let id_users = Uuid::new_v4();
        idx.insert_path("/api", id_api);
        idx.insert_path("/api/v1", id_v1);
        idx.insert_path("/api/v1/users", id_users);

        let c = idx.candidates("/api/v1/users/123");
        assert!(c.contains(&id_api));
        assert!(c.contains(&id_v1));
        assert!(c.contains(&id_users));
    }

    #[test]
    fn radix_prefix_only_excludes_regex() {
        let mut idx = RadixIndex::empty();
        let id_regex = Uuid::new_v4();
        idx.regex_routes.push(id_regex);
        let id_prefix = Uuid::new_v4();
        idx.insert_path("/api/*", id_prefix);

        // candidates() includes regex routes.
        assert!(idx.candidates("/api/test").contains(&id_regex));
        assert!(idx.candidates("/api/test").contains(&id_prefix));

        // prefix_only_candidates() excludes regex routes.
        assert!(!idx.prefix_only_candidates("/api/test").contains(&id_regex));
        assert!(idx.prefix_only_candidates("/api/test").contains(&id_prefix));
    }

    // ── RegexSetIndex ──

    #[test]
    fn regex_set_empty_matches_nothing() {
        let idx = RegexSetIndex::empty();
        assert!(idx.matches("/anything").is_empty());
    }

    #[test]
    fn regex_set_matches_patterns() {
        let routes: DashMap<Uuid, Arc<Route>, FastHasher> =
            DashMap::with_hasher(FastHasher::default());
        let id = Uuid::new_v4();
        let route = Route {
            id,
            path_regexes: vec!["^/api/v[0-9]+/.*$".to_string()],
            ..make_test_route(id, Uuid::new_v4())
        };
        routes.insert(id, Arc::new(route));

        let idx = RegexSetIndex::build(&routes);
        assert!(idx.matches("/api/v1/users").contains(&id));
        assert!(idx.matches("/api/v99/items").contains(&id));
        assert!(!idx.matches("/other/path").contains(&id));
    }

    #[test]
    fn regex_set_deduplicates_route_ids() {
        let routes: DashMap<Uuid, Arc<Route>, FastHasher> =
            DashMap::with_hasher(FastHasher::default());
        let id = Uuid::new_v4();
        // Route with multiple patterns that both match the same path.
        let route = Route {
            id,
            path_regexes: vec!["^/api/.*$".to_string(), "^/api/v1/.*$".to_string()],
            ..make_test_route(id, Uuid::new_v4())
        };
        routes.insert(id, Arc::new(route));

        let idx = RegexSetIndex::build(&routes);
        let matches = idx.matches("/api/v1/users");
        // Should contain the route ID only once despite two patterns matching.
        assert_eq!(matches.iter().filter(|&&r| r == id).count(), 1);
    }

    // ── RouteResultCache ──

    #[test]
    fn route_result_cache_hit_and_miss() {
        let cache = RouteResultCache::new();
        let key = RouteResultCache::hash_request(Some("example.com"), "/api/v1", "GET");
        let route_id = Uuid::new_v4();
        let service_id = Uuid::new_v4();

        assert!(cache.lookup(key).is_none());
        cache.insert(key, route_id, service_id);
        assert_eq!(cache.lookup(key), Some((route_id, service_id)));
    }

    #[test]
    fn route_result_cache_evicts_on_overflow() {
        let cache = RouteResultCache::new();
        let route_id = Uuid::new_v4();
        let service_id = Uuid::new_v4();

        for i in 0..MAX_ROUTE_RESULT_CACHE_ENTRIES {
            cache.insert(i as u64, route_id, service_id);
        }
        // This insert triggers a clear.
        cache.insert(u64::MAX, route_id, service_id);
        assert!(cache.lookup(0).is_none());
        assert_eq!(cache.lookup(u64::MAX), Some((route_id, service_id)));
    }

    #[test]
    fn route_result_cache_cleared_on_mutation() {
        let cache = RouteResultCache::new();
        let key = 42u64;
        cache.insert(key, Uuid::new_v4(), Uuid::new_v4());
        assert!(cache.lookup(key).is_some());
        cache.clear();
        assert!(cache.lookup(key).is_none());
    }

    // ── Configurable dispatch ──

    #[test]
    fn path_strategy_toggle() {
        let table = RouteTable::new();
        // Default: Trie.
        assert_eq!(
            PathMatchStrategy::from_u8(table.path_strategy.load(Ordering::Relaxed)),
            PathMatchStrategy::Trie,
        );
        // Switch to RadixTree.
        table.set_path_strategy(PathMatchStrategy::RadixTree);
        assert_eq!(
            PathMatchStrategy::from_u8(table.path_strategy.load(Ordering::Relaxed)),
            PathMatchStrategy::RadixTree,
        );
        // Switch to Scan.
        table.set_path_strategy(PathMatchStrategy::Scan);
        assert_eq!(
            PathMatchStrategy::from_u8(table.path_strategy.load(Ordering::Relaxed)),
            PathMatchStrategy::Scan,
        );
        // Backward compat: set_use_prefix_trie(true) → Trie.
        table.set_use_prefix_trie(true);
        assert_eq!(
            PathMatchStrategy::from_u8(table.path_strategy.load(Ordering::Relaxed)),
            PathMatchStrategy::Trie,
        );
        // Backward compat: set_use_prefix_trie(false) → Scan.
        table.set_use_prefix_trie(false);
        assert_eq!(
            PathMatchStrategy::from_u8(table.path_strategy.load(Ordering::Relaxed)),
            PathMatchStrategy::Scan,
        );
    }

    #[test]
    fn strategy_toggles_default_enabled() {
        let table = RouteTable::new();
        assert!(table.use_regex_set.load(Ordering::Relaxed));
        assert!(table.use_route_cache.load(Ordering::Relaxed));
        assert!(table.use_sharded_hosts.load(Ordering::Relaxed));
    }

    #[test]
    fn regex_set_toggle() {
        let table = RouteTable::new();
        table.set_use_regex_set(false);
        assert!(!table.use_regex_set.load(Ordering::Relaxed));
        table.set_use_regex_set(true);
        assert!(table.use_regex_set.load(Ordering::Relaxed));
    }

    #[test]
    fn route_cache_toggle_clears_on_disable() {
        let table = RouteTable::new();
        table.route_result_cache.insert(1, Uuid::new_v4(), Uuid::new_v4());
        assert!(table.route_result_cache.lookup(1).is_some());
        table.set_use_route_cache(false);
        // Disabling clears the cache.
        assert!(table.route_result_cache.lookup(1).is_none());
    }

    #[test]
    fn header_or_query_gated_route_disables_result_cache() {
        // Regression: the result cache is keyed by (host, path, method) only,
        // so caching a header/query-gated route silently served the wrong route
        // to a later request differing only by header/query. Adding any gated
        // route must disable the cache.
        let table = RouteTable::new();

        // Plain routes keep the cache enabled.
        table.add_route(make_test_route(Uuid::new_v4(), Uuid::new_v4()));
        assert!(
            !table.has_constrained_routes.load(Ordering::Relaxed),
            "plain routes must not disable the result cache"
        );

        // A header-gated route flips the flag.
        let mut gated = make_test_route(Uuid::new_v4(), Uuid::new_v4());
        gated
            .headers
            .insert("X-Api-Version".to_string(), "v2".to_string());
        let gated_id = gated.id;
        table.add_route(gated);
        assert!(
            table.has_constrained_routes.load(Ordering::Relaxed),
            "a header-gated route must disable the result cache"
        );

        // Removing it re-enables the cache.
        table.remove_route(&gated_id);
        assert!(
            !table.has_constrained_routes.load(Ordering::Relaxed),
            "removing the gated route should re-enable the result cache"
        );

        // A query-param-gated route also disables it.
        let mut q = make_test_route(Uuid::new_v4(), Uuid::new_v4());
        q.query_params.insert("v".to_string(), "2".to_string());
        table.add_route(q);
        assert!(
            table.has_constrained_routes.load(Ordering::Relaxed),
            "a query-gated route must disable the result cache"
        );
    }

    // ── Host sharding ──

    #[test]
    fn host_sharding_toggle() {
        let table = RouteTable::new();
        assert!(table.use_sharded_hosts.load(Ordering::Relaxed));
        table.set_use_sharded_hosts(false);
        assert!(!table.use_sharded_hosts.load(Ordering::Relaxed));
    }

    // ── common_prefix_len ──

    #[test]
    fn common_prefix_len_basic() {
        assert_eq!(common_prefix_len(b"/api/v1", b"/api/v2"), 6);
        assert_eq!(common_prefix_len(b"/api", b"/api"), 4);
        assert_eq!(common_prefix_len(b"/foo", b"/bar"), 1); // just "/"
        assert_eq!(common_prefix_len(b"abc", b"xyz"), 0);
        assert_eq!(common_prefix_len(b"", b"abc"), 0);
    }

    // ── Test helper ──

    /// Minimal route constructor for tests that only need id + service_id.
    /// All other fields are set to their Default / zero values.
    fn make_test_route(id: Uuid, service_id: Uuid) -> Route {
        Route {
            id,
            service_id,
            paths: Vec::new(),
            methods: Vec::new(),
            hosts: Vec::new(),
            strip_path: false,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            path_regexes: Vec::new(),
            headers: std::collections::HashMap::new(),
            query_params: std::collections::HashMap::new(),
            buffer_request: false,
            read_timeout_ms: None,
            write_timeout_ms: None,
            idle_timeout_ms: None,
            retry_on_status: Vec::new(),
            matchers: Vec::new(),
            matcher_refs: Vec::new(),
            handle_blocks: Vec::new(),
            try_files: None,
            uri_directives: Vec::new(),
            intercept_rules: Vec::new(),
            push: None,
            static_response: None,
            health_gate: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // ── literal_or_prefix_match ──

    #[test]
    fn literal_match_exact() {
        assert!(literal_or_prefix_match(
            &["/health".to_string()],
            "/health"
        ));
        assert!(!literal_or_prefix_match(
            &["/health".to_string()],
            "/healthz"
        ));
    }

    #[test]
    fn literal_match_segment_prefix() {
        assert!(literal_or_prefix_match(
            &["/api".to_string()],
            "/api/v1"
        ));
        // Must be a segment boundary — /apifoo should NOT match.
        assert!(!literal_or_prefix_match(
            &["/api".to_string()],
            "/apifoo"
        ));
    }

    #[test]
    fn literal_match_wildcard() {
        assert!(literal_or_prefix_match(
            &["/api/*".to_string()],
            "/api/v1/users"
        ));
        assert!(literal_or_prefix_match(
            &["/api/*".to_string()],
            "/api/"
        ));
    }

    // ── Service name index (O(1) get_service_by_name) ──

    /// Minimal service constructor for the name-index tests below.
    fn make_test_service(name: &str) -> Service {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Service {
            id,
            name: Arc::from(name),
            url: "http://upstream:8080".to_string(),
            retries: 0,
            connect_timeout_ms: 5000,
            lb_strategy: "round_robin".to_string(),
            service_type: "api".to_string(),
            document_root: None,
            index_file: "index.html".to_string(),
            spa_fallback: false,
            hide_patterns: Vec::new(),
            tls_verify: true,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_ca_path: None,
            lb_hash_header: None,
            lb_hash_query_param: None,
            flush_interval_ms: None,
            stream_timeout_ms: None,
            stream_close_delay_ms: None,
            pass_host_header: None,
            pool_idle_floor: None,
            force_http_version: None,
            drain_timeout_ms: None,
            project_id: None,
            domain: String::new(),
            subdomain: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn service_name_index_lookup_after_add() {
        let table = RouteTable::new();
        let svc = make_test_service("orders");
        let id = table.add_service(svc);
        let fetched = table.get_service_by_name("orders").expect("name hit");
        assert_eq!(fetched.id, id);
        assert_eq!(&*fetched.name, "orders");
    }

    #[test]
    fn service_name_index_miss_returns_none() {
        let table = RouteTable::new();
        let svc = make_test_service("orders");
        table.add_service(svc);
        assert!(table.get_service_by_name("nonexistent").is_none());
    }

    #[test]
    fn service_name_index_removes_on_remove_service() {
        let table = RouteTable::new();
        let svc = make_test_service("orders");
        let id = svc.id;
        table.add_service(svc);
        assert!(table.get_service_by_name("orders").is_some());
        table.remove_service(&id);
        assert!(table.get_service_by_name("orders").is_none());
    }

    #[test]
    fn service_name_index_rename_via_update_service() {
        let table = RouteTable::new();
        let svc = make_test_service("orders");
        let id = svc.id;
        table.add_service(svc);
        // Rename: keep id, change name.
        let mut renamed = make_test_service("payments");
        renamed.id = id;
        assert!(table.update_service(&id, renamed));
        // Old name should miss; new name should hit.
        assert!(table.get_service_by_name("orders").is_none());
        let fetched = table.get_service_by_name("payments").expect("renamed hit");
        assert_eq!(fetched.id, id);
    }

    #[test]
    fn service_name_index_keeps_name_on_no_rename_update() {
        // When update_service is called with the same name, the index
        // entry should be preserved (we only remove on a name CHANGE).
        let table = RouteTable::new();
        let svc = make_test_service("orders");
        let id = svc.id;
        table.add_service(svc.clone());
        let mut same_name = make_test_service("orders");
        same_name.id = id;
        same_name.url = "http://other-upstream:9090".to_string();
        assert!(table.update_service(&id, same_name));
        let fetched = table.get_service_by_name("orders").expect("still indexed");
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.url, "http://other-upstream:9090");
    }

    #[test]
    fn literal_match_root() {
        assert!(literal_or_prefix_match(&["/".to_string()], "/anything"));
        assert!(literal_or_prefix_match(&["/".to_string()], "/"));
    }
}
