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

pub struct RouteTable {
    services: DashMap<Uuid, Service, FastHasher>,
    routes: DashMap<Uuid, Route, FastHasher>,
    /// Exact-path index: `path` -> `route_id` for routes whose `paths` entries
    /// are literal (no trailing `*`). The hot path consults this first to turn
    /// route matching from O(N) into O(1) for the common "exact path" case.
    /// Prefix and wildcard routes still fall through to the linear scan.
    exact_index: DashMap<String, Uuid, FastHasher>,
    /// Host-to-service index: `"sub.domain.com"` -> `service_id` for services
    /// with non-empty `subdomain` + `domain`. Enables O(1) subdomain routing.
    host_index: DashMap<String, Uuid, FastHasher>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            services: DashMap::with_hasher(FastHasher::default()),
            routes: DashMap::with_hasher(FastHasher::default()),
            exact_index: DashMap::with_hasher(FastHasher::default()),
            host_index: DashMap::with_hasher(FastHasher::default()),
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
    pub fn match_route_for_service(
        &self,
        service_id: &Uuid,
        path: &str,
        method: &str,
    ) -> Option<Route> {
        let mut best: Option<Route> = None;
        for entry in self.routes.iter() {
            let route = entry.value();
            if &route.service_id != service_id {
                continue;
            }
            let path_matches = if !route.path_regexes.is_empty() {
                route.path_regexes.iter().any(|pattern| {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(path))
                        .unwrap_or(false)
                })
            } else {
                route.paths.iter().any(|p| {
                    if p.ends_with('*') {
                        let prefix = &p[..p.len() - 1];
                        path.starts_with(prefix)
                    } else if p == "/" {
                        true
                    } else {
                        path == p || path.starts_with(&format!("{p}/"))
                    }
                })
            };
            if !path_matches {
                continue;
            }
            let method_matches =
                route.methods.is_empty() || route.methods.iter().any(|m| m == method);
            if !method_matches {
                continue;
            }
            best = Some(route.clone());
            break;
        }
        best
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
        for route in &routes {
            self.routes.insert(route.id, route.clone());
        }
        self.rebuild_exact_index();
        self.rebuild_host_index();

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
        self.routes.insert(id, route);
        self.rebuild_exact_index();
        id
    }

    pub fn get_route(&self, id: &Uuid) -> Option<Route> {
        self.routes.get(id).map(|r| r.clone())
    }

    pub fn list_routes(&self) -> Vec<Route> {
        self.routes.iter().map(|r| r.clone()).collect()
    }

    pub fn update_route(&self, id: &Uuid, route: Route) -> bool {
        if self.routes.contains_key(id) {
            self.routes.insert(*id, route);
            self.rebuild_exact_index();
            true
        } else {
            false
        }
    }

    pub fn remove_route(&self, id: &Uuid) -> bool {
        let removed = self.routes.remove(id).is_some();
        if removed {
            self.rebuild_exact_index();
        }
        removed
    }

    pub fn match_route(
        &self,
        path: &str,
        method: &str,
        host: Option<&str>,
    ) -> Option<(Route, Service)> {
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
    ) -> Option<(Route, Service)> {
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
                        return Some((route.clone(), service));
                    }
                }
            }
        }

        // Prefer routes with explicit host constraints over wildcard ones.
        let mut best: Option<(Route, Service)> = None;
        let mut best_has_hosts = false;

        for entry in self.routes.iter() {
            let route = entry.value();

            // Path matching: check regex patterns first, then literal paths.
            let path_matches = if !route.path_regexes.is_empty() {
                route.path_regexes.iter().any(|pattern| {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(path))
                        .unwrap_or(false)
                })
            } else {
                route.paths.iter().any(|p| {
                    if p.ends_with('*') {
                        let prefix = &p[..p.len() - 1];
                        path.starts_with(prefix)
                    } else if p == "/" {
                        true
                    } else {
                        path == p || path.starts_with(&format!("{p}/"))
                    }
                })
            };

            if !path_matches {
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
                best = Some((route.clone(), self.get_service(&route.service_id)?));
                best_has_hosts = true;
            } else if best.is_none() {
                if let Some(service) = self.get_service(&route.service_id) {
                    best = Some((route.clone(), service));
                    best_has_hosts = has_hosts;
                }
            }
        }

        best
    }

    pub fn resolve_upstream_path(&self, route: &Route, original_path: &str) -> String {
        // Priority 1: regex rewrite
        if let (Some(pattern), Some(replacement)) =
            (&route.path_rewrite_pattern, &route.path_rewrite_replacement)
        {
            if let Ok(re) = regex::Regex::new(pattern) {
                let rewritten = re.replace(original_path, replacement.as_str());
                return rewritten.into_owned();
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
