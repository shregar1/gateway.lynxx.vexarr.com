use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Route, Service};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Hasher used by the route table's internal maps. All keys here are
/// either server-generated UUIDs or normalised host / path strings —
/// none of them are attacker-influenced HashMap keys, so the default
/// SipHash DoS resistance is wasted cycles. ahash is 2-5× faster on
/// the typical 16-32-byte keys we use here.
type FastHasher = ahash::RandomState;

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

pub struct RouteTable {
    services: DashMap<Uuid, Service, FastHasher>,
    /// Routes are stored behind `Arc` so the hot-path lookups
    /// (`match_route`, `match_route_full`, `match_route_for_service`,
    /// `get_route`, `list_routes`) can return cheap refcount bumps
    /// instead of deep-cloning the whole `Route` struct (Vec<String>
    /// for paths, HashMap<String, String> for headers, …). Mutations
    /// go through full replacement — inserts allocate a new `Arc`,
    /// drops decrement the refcount; in-place mutation is not part of
    /// the API and was never supported.
    routes: DashMap<Uuid, Arc<Route>, FastHasher>,
    /// Exact-path index: `path` -> `route_id` for routes whose `paths` entries
    /// are literal (no trailing `*`). The hot path consults this first to turn
    /// route matching from O(N) into O(1) for the common "exact path" case.
    /// Prefix and wildcard routes still fall through to the linear scan.
    exact_index: DashMap<String, Uuid, FastHasher>,
    /// Host-to-service index: `"sub.domain.com"` -> `service_id` for services
    /// with non-empty `subdomain` + `domain`. Enables O(1) subdomain routing.
    host_index: DashMap<String, Uuid, FastHasher>,
    /// Precompiled regex bundles keyed by route id. Kept in sync with
    /// `routes` via the add / update / remove / load_from_repo paths.
    /// Same hasher choice as the other internal maps — UUID keys are
    /// server-generated, not attacker-influenced.
    regex_cache: DashMap<Uuid, Arc<RouteCache>, FastHasher>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            services: DashMap::with_hasher(FastHasher::default()),
            routes: DashMap::with_hasher(FastHasher::default()),
            exact_index: DashMap::with_hasher(FastHasher::default()),
            host_index: DashMap::with_hasher(FastHasher::default()),
            regex_cache: DashMap::with_hasher(FastHasher::default()),
        }
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

    fn rebuild_host_index(&self) {
        self.host_index.clear();
        for entry in self.services.iter() {
            let svc = entry.value();
            if let Some(fqdn) = Self::service_fqdn(svc) {
                self.host_index.insert(fqdn, svc.id);
            }
        }
    }

    fn service_fqdn(svc: &Service) -> Option<String> {
        if svc.subdomain.is_empty() || svc.domain.is_empty() {
            return None;
        }
        Some(format!("{}.{}", svc.subdomain, svc.domain).to_ascii_lowercase())
    }

    /// O(1) lookup: does `host` match a service's `subdomain.domain`?
    pub fn match_by_host(&self, host: &str) -> Option<Service> {
        let key = host.to_ascii_lowercase();
        let svc_id = *self.host_index.get(&key)?;
        self.services.get(&svc_id).map(|s| s.clone())
    }

    /// Find the best matching route within a specific service.
    ///
    /// Enforces the SAME host/header/query-param constraints as
    /// [`Self::match_route_full`]. The subdomain fast path must not become a
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
        for entry in self.routes.iter() {
            let route = entry.value();
            if &route.service_id != service_id {
                continue;
            }
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
    /// allocate. Consults the precompiled regex cache for `path_regexes`
    /// routes; falls back to the literal / prefix matcher otherwise.
    fn path_matches(&self, route: &Route, path: &str) -> bool {
        if !route.path_regexes.is_empty() {
            if let Some(cache) = self.regex_cache.get(&route.id) {
                return cache.paths.iter().any(|re| re.is_match(path));
            }
            return false; // pattern present but cache empty = all invalid
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

        for svc in &services {
            self.services.insert(svc.id, svc.clone());
        }
        for route in routes.iter() {
            self.routes.insert(route.id, Arc::new(route.clone()));
        }
        self.rebuild_exact_index();
        self.rebuild_host_index();
        self.rebuild_regex_cache();

        Ok((services.len(), routes.len()))
    }

    pub fn add_service(&self, service: Service) -> Uuid {
        let id = service.id;
        if let Some(fqdn) = Self::service_fqdn(&service) {
            self.host_index.insert(fqdn, id);
        }
        self.services.insert(id, service);
        id
    }

    pub fn get_service(&self, id: &Uuid) -> Option<Service> {
        self.services.get(id).map(|s| s.clone())
    }

    pub fn get_service_by_name(&self, name: &str) -> Option<Service> {
        self.services
            .iter()
            .find(|s| s.name == name.into())
            .map(|s| s.clone())
    }

    pub fn list_services(&self) -> Vec<Service> {
        self.services.iter().map(|s| s.clone()).collect()
    }

    pub fn update_service(&self, id: &Uuid, service: Service) -> bool {
        if self.services.contains_key(id) {
            if let Some(old) = self.services.get(id) {
                if let Some(old_fqdn) = Self::service_fqdn(old.value()) {
                    self.host_index.remove(&old_fqdn);
                }
            }
            if let Some(fqdn) = Self::service_fqdn(&service) {
                self.host_index.insert(fqdn, *id);
            }
            self.services.insert(*id, service);
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
            true
        } else {
            false
        }
    }

    pub fn add_route(&self, route: Route) -> Uuid {
        let id = route.id;
        if !route.path_regexes.is_empty() || route.path_rewrite_pattern.is_some() {
            self.regex_cache.insert(id, Self::compile_cache_for(&route));
        }
        self.routes.insert(id, Arc::new(route));
        self.rebuild_exact_index();
        id
    }

    pub fn get_route(&self, id: &Uuid) -> Option<Arc<Route>> {
        self.arc_route(id)
    }

    pub fn list_routes(&self) -> Vec<Arc<Route>> {
        self.routes.iter().map(|r| Arc::clone(r.value())).collect()
    }

    pub fn update_route(&self, id: &Uuid, route: Route) -> bool {
        if self.routes.contains_key(id) {
            if !route.path_regexes.is_empty() || route.path_rewrite_pattern.is_some() {
                self.regex_cache
                    .insert(*id, Self::compile_cache_for(&route));
            } else {
                self.regex_cache.remove(id);
            }
            self.routes.insert(*id, Arc::new(route));
            self.rebuild_exact_index();
            true
        } else {
            false
        }
    }

    pub fn remove_route(&self, id: &Uuid) -> bool {
        let removed = self.routes.remove(id).is_some();
        if removed {
            self.regex_cache.remove(id);
            self.rebuild_exact_index();
        }
        removed
    }

    pub fn match_route(
        &self,
        path: &str,
        method: &str,
        host: Option<&str>,
    ) -> Option<(Arc<Route>, Service)> {
        self.match_route_full(path, method, host, None, None)
    }

    /// Full route match with optional header and query parameter matching.
    pub fn match_route_full(
        &self,
        path: &str,
        method: &str,
        host: Option<&str>,
        req_headers: Option<&axum::http::HeaderMap>,
        query_string: Option<&str>,
    ) -> Option<(Arc<Route>, Service)> {
        // Fast path: exact-path lookup. Avoids the O(N) scan for the common
        // case of a busy API with literal route paths.
        if let Some(id_ref) = self.exact_index.get(path) {
            let id = *id_ref;
            drop(id_ref);
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
                        return Some((Arc::clone(route), service));
                    }
                }
            }
        }

        // Prefer routes with explicit host constraints over wildcard ones.
        let mut best: Option<(Arc<Route>, Service)> = None;
        let mut best_has_hosts = false;

        for entry in self.routes.iter() {
            let route = entry.value();

            // Path matching: regex patterns (cached) first, then literal paths.
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

            // Header-based matching.
            if !route.headers.is_empty() && !match_headers(&route.headers, req_headers) {
                continue;
            }

            // Query-parameter matching.
            if !route.query_params.is_empty() && !match_query(&route.query_params, query_string) {
                continue;
            }

            let has_hosts = !route.hosts.is_empty();
            if has_hosts && !best_has_hosts {
                best = Some((Arc::clone(route), self.get_service(&route.service_id)?));
                best_has_hosts = true;
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
