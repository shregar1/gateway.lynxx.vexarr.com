pub mod abort;
pub mod acl;
pub mod anomaly_detector;
pub mod auth;
pub mod aws_lambda;
pub mod basic_auth;
pub mod bot_detection;
pub mod buffering;
pub mod canary;
pub mod client_cert_header;
pub mod content_type;
pub mod correlation_id;
pub mod cors;
pub mod datadog;
pub mod digest_auth;
pub mod error_handler;
pub mod factory;
pub mod file_log;
pub mod forward_auth;
pub mod graphql_guard;
pub mod grpc_web;
pub mod hmac_auth;
pub mod honeycomb;
pub mod inflight_req;
pub mod ip_restriction;
pub mod jwt;
pub mod key_auth;
pub mod llm_gateway;
pub mod log_filter;
pub mod logging;
pub mod map_vars;
pub mod method_override;
pub mod mocking;
pub mod oauth2_introspect;
pub mod openapi_drift;
pub mod openapi_mock;
pub mod opentelemetry;
pub mod prometheus_per_consumer;
pub mod proxy_cache;
pub mod rate_limit;
pub mod redirect;
pub mod redirect_regex;
pub mod redis_rate_limit;
pub mod request_cleaner;
pub mod request_id;
pub mod request_recorder;
pub mod request_size_limit;
pub mod request_termination;
pub mod request_transformer;
pub mod request_validator;
pub mod response_cleaner;
pub mod response_compression;
pub mod response_filter;
pub mod response_ratelimiting;
pub mod response_rewriter;
pub mod response_transformer;
pub mod script_runner;
pub mod security_headers;
pub mod session;
pub mod shadow;
pub mod splunk;
pub mod statsd;
pub mod syslog;
pub mod template;
pub mod wasm;
pub mod websocket_size_limit;

use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::quota::PlanTier;
use async_trait::async_trait;
use axum::http::{Request, Response};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

pub type BoxBody = axum::body::Body;

#[async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError>;
    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError>;
}

/// Index of which plugin instance ids apply at each scope.
#[derive(Default)]
pub struct PluginIndex {
    pub global: Vec<Uuid>,
    pub by_service: HashMap<Uuid, Vec<Uuid>>,
    pub by_route: HashMap<Uuid, Vec<Uuid>>,
}

/// Dynamic plugin registry. Plugins are persisted in the DB and rebuilt into
/// concrete `Arc<dyn Plugin>` instances cached here. Every plugin CRUD op in
/// the admin API triggers `rebuild` to refresh the cache.
/// Plugins available on the Free tier. Everything else requires Pro+.
const CORE_PLUGINS: &[&str] = &[
    "rate_limit",
    "cors",
    "request_transformer",
    "response_transformer",
    "jwt",
    "basic_auth",
    "key_auth",
    "logging",
    "request_size_limit",
    "request_termination",
    "ip_restriction",
    "proxy_cache",
    "response_compression",
];

/// Shared services that the plugin factory can hand to individual
/// plugins at construction time. Currently carries an optional
/// [`crate::integrations::HmacVerifier`] (used by `hmac-auth` to route
/// signature verification through an external backend like keyx).
/// Future shared deps (cluster bus, metrics handle, …) belong here
/// too rather than as additional factory parameters.
///
/// Plugins that don't need anything from the context just ignore it.
#[derive(Clone, Default)]
pub struct PluginContext {
    pub hmac_verifier: Option<Arc<dyn crate::integrations::HmacVerifier>>,
}

pub struct PluginExecutor {
    built: RwLock<HashMap<Uuid, Arc<dyn Plugin>>>,
    index: RwLock<PluginIndex>,
    /// Fast-path flag: `true` when no plugins are configured anywhere. Lets the
    /// hot path skip the `RwLock` reads entirely. Updated atomically on every
    /// `rebuild`. When this is set, both `run_request` and `run_response`
    /// return without acquiring any lock — the common production-default case
    /// when a route has zero scoped plugins.
    is_empty: AtomicBool,
    /// File watcher for WASM modules loaded from disk. Registered paths
    /// are polled for mtime changes; a change signals `reload_signal`.
    wasm_watcher: wasm::watcher::WasmWatcher,
    /// Signalled by the WASM file watcher when a `.wasm` module on disk
    /// changes. The main server loop listens on this and triggers a
    /// `rebuild()`.
    pub reload_signal: Arc<Notify>,
    /// Licence tier that determines which plugins may be loaded.
    tier: PlanTier,
    /// Directive execution order. Plugins whose name appears earlier in
    /// this list run first; unlisted plugins run after all listed ones
    /// in their natural (creation) order.
    order: RwLock<Vec<String>>,
    /// Shared service handles handed to every plugin at construction
    /// (via [`PluginContext`]). Wired in `new_with_context`; default
    /// `new()` leaves it empty for tests / harnesses that don't care.
    context: PluginContext,
}

impl PluginExecutor {
    pub fn new(tier: PlanTier) -> Self {
        Self::new_with_context(tier, PluginContext::default())
    }

    pub fn new_with_context(tier: PlanTier, context: PluginContext) -> Self {
        let reload_signal = Arc::new(Notify::new());
        let wasm_watcher = wasm::watcher::WasmWatcher::new();

        // Spawn the file-watcher polling loop. When any registered WASM
        // module's mtime changes on disk, the callback fires
        // `reload_signal` so the main server loop can trigger a rebuild.
        let signal = reload_signal.clone();
        wasm_watcher.spawn(move |_path| {
            signal.notify_one();
        });

        Self {
            built: RwLock::new(HashMap::new()),
            index: RwLock::new(PluginIndex::default()),
            is_empty: AtomicBool::new(true),
            wasm_watcher,
            reload_signal,
            tier,
            order: RwLock::new(Vec::new()),
            context,
        }
    }

    /// Set the directive execution order. Plugins whose name appears in
    /// `order` run first (in the listed sequence); unlisted plugins run
    /// after them in their natural (creation) order.
    pub async fn set_order(&self, order: Vec<String>) {
        *self.order.write().await = order;
    }

    /// Lock-free check used by the proxy hot path to skip plugin dispatch
    /// entirely when no plugin is configured.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.is_empty.load(Ordering::Acquire)
    }

    /// Shared services available to plugin construction. Used by the
    /// admin API's plugin-validate endpoints so they build under the
    /// same context as production (matters for plugins like hmac-auth
    /// that branch on the presence of a keyx client).
    pub fn context(&self) -> &PluginContext {
        &self.context
    }

    /// Re-fetch all plugin rows from the DB and (re)build every enabled plugin.
    /// Disabled plugins are skipped. Build failures are logged but do not abort
    /// the rebuild — other plugins still load.
    ///
    /// Free-tier licences only load `CORE_PLUGINS`; Pro+ loads everything.
    pub async fn rebuild(&self, repo: &Arc<dyn Repository>) -> Result<(), GatewayError> {
        let rows = repo.list_plugins().await?;
        let mut built: HashMap<Uuid, Arc<dyn Plugin>> = HashMap::with_capacity(rows.len());
        let mut index = PluginIndex::default();

        for row in &rows {
            if !row.enabled {
                continue;
            }
            if self.tier == PlanTier::Free && !CORE_PLUGINS.contains(&row.name.as_str()) {
                tracing::debug!(
                    plugin = %row.name,
                    tier = %self.tier.as_str(),
                    "plugin skipped — requires Pro+"
                );
                continue;
            }
            let plugin =
                match factory::build(&row.name, &row.config, Some(repo.clone()), &self.context) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            plugin = %row.name,
                            id = %row.id,
                            error = %e,
                            "failed to build plugin; skipping"
                        );
                        continue;
                    }
                };

            match (row.service_id, row.route_id) {
                (_, Some(route_id)) => {
                    index.by_route.entry(route_id).or_default().push(row.id);
                }
                (Some(service_id), None) => {
                    index.by_service.entry(service_id).or_default().push(row.id);
                }
                (None, None) => {
                    index.global.push(row.id);
                }
            }

            built.insert(row.id, plugin);
        }

        // Sort plugin chains according to the directive execution order.
        // Plugins whose name appears in `self.order` come first (in the
        // specified sequence); unlisted plugins keep their natural order
        // after the listed ones.
        let order = self.order.read().await;
        if !order.is_empty() {
            let sort_ids = |ids: &mut Vec<Uuid>| {
                ids.sort_by(|a, b| {
                    let name_a = built.get(a).map(|p| p.name().to_string());
                    let name_b = built.get(b).map(|p| p.name().to_string());
                    let pos_a = name_a
                        .as_ref()
                        .and_then(|n| order.iter().position(|o| o == n));
                    let pos_b = name_b
                        .as_ref()
                        .and_then(|n| order.iter().position(|o| o == n));
                    match (pos_a, pos_b) {
                        (Some(pa), Some(pb)) => pa.cmp(&pb),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                });
            };

            sort_ids(&mut index.global);
            for ids in index.by_service.values_mut() {
                sort_ids(ids);
            }
            for ids in index.by_route.values_mut() {
                sort_ids(ids);
            }
        }
        drop(order);

        let empty = built.is_empty()
            && index.global.is_empty()
            && index.by_service.is_empty()
            && index.by_route.is_empty();
        *self.built.write().await = built;
        *self.index.write().await = index;
        self.is_empty.store(empty, Ordering::Release);

        // Sync the WASM file watcher with the current set of file-based
        // module paths. Paths that no longer appear are dropped; new ones
        // are registered with their current mtime as the baseline.
        let mut wasm_paths: Vec<PathBuf> = Vec::new();
        for row in &rows {
            if row.enabled && row.name == "wasm" {
                if let Some(p) = row.config.get("module_path").and_then(|v| v.as_str()) {
                    wasm_paths.push(PathBuf::from(p));
                }
            }
        }
        self.wasm_watcher.sync_paths(wasm_paths).await;

        Ok(())
    }

    /// Resolve the request-time plugin chain: global → service → route.
    async fn resolve_chain(
        &self,
        service_id: Option<Uuid>,
        route_id: Option<Uuid>,
    ) -> Vec<Arc<dyn Plugin>> {
        let index = self.index.read().await;
        let built = self.built.read().await;

        let mut chain: Vec<Arc<dyn Plugin>> = Vec::new();
        for id in &index.global {
            if let Some(p) = built.get(id) {
                chain.push(p.clone());
            }
        }
        if let Some(svc) = service_id {
            if let Some(ids) = index.by_service.get(&svc) {
                for id in ids {
                    if let Some(p) = built.get(id) {
                        chain.push(p.clone());
                    }
                }
            }
        }
        if let Some(rt) = route_id {
            if let Some(ids) = index.by_route.get(&rt) {
                for id in ids {
                    if let Some(p) = built.get(id) {
                        chain.push(p.clone());
                    }
                }
            }
        }
        chain
    }

    pub async fn run_request(
        &self,
        req: &mut Request<axum::body::Body>,
        service_id: Option<Uuid>,
        route_id: Option<Uuid>,
    ) -> Result<(), PluginError> {
        if self.is_empty() {
            return Ok(());
        }
        let chain = self.resolve_chain(service_id, route_id).await;
        for p in &chain {
            p.on_request(req).await?;
        }
        Ok(())
    }

    pub async fn run_response(
        &self,
        resp: &mut Response<BoxBody>,
        service_id: Option<Uuid>,
        route_id: Option<Uuid>,
    ) -> Result<(), PluginError> {
        if self.is_empty() {
            return Ok(());
        }
        let chain = self.resolve_chain(service_id, route_id).await;
        for p in chain.iter().rev() {
            p.on_response(resp).await?;
        }
        Ok(())
    }
}

impl Default for PluginExecutor {
    fn default() -> Self {
        Self::new(PlanTier::Free)
    }
}

/// Sort a list of `(Uuid, name)` pairs according to `order`. Items whose
/// name appears in `order` come first (in the listed sequence); unlisted
/// items keep their relative (natural) order after the listed ones.
///
/// Exposed for testability; the same logic is used inside `rebuild`.
fn sort_ids_by_order(ids: &mut [Uuid], names: &HashMap<Uuid, String>, order: &[String]) {
    ids.sort_by(|a, b| {
        let pos_a = names.get(a).and_then(|n| order.iter().position(|o| o == n));
        let pos_b = names.get(b).and_then(|n| order.iter().position(|o| o == n));
        match (pos_a, pos_b) {
            (Some(pa), Some(pb)) => pa.cmp(&pb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a UUID-to-name map and ID vec from a list of names.
    fn make_ids(names: &[&str]) -> (Vec<Uuid>, HashMap<Uuid, String>) {
        let mut ids = Vec::new();
        let mut map = HashMap::new();
        for name in names {
            let id = Uuid::new_v4();
            ids.push(id);
            map.insert(id, name.to_string());
        }
        (ids, map)
    }

    #[test]
    fn order_sorts_plugins() {
        let (mut ids, names) = make_ids(&["cors", "logging", "rate-limit"]);
        let order = vec![
            "rate-limit".to_string(),
            "cors".to_string(),
            "logging".to_string(),
        ];

        sort_ids_by_order(&mut ids, &names, &order);

        let sorted_names: Vec<&str> = ids.iter().map(|id| names[id].as_str()).collect();
        assert_eq!(sorted_names, vec!["rate-limit", "cors", "logging"]);
    }

    #[test]
    fn order_unlisted_after() {
        let (mut ids, names) = make_ids(&["cors", "logging", "rate-limit", "jwt"]);
        // Only cors and jwt are listed; logging and rate-limit are unlisted.
        let order = vec!["jwt".to_string(), "cors".to_string()];

        sort_ids_by_order(&mut ids, &names, &order);

        let sorted_names: Vec<&str> = ids.iter().map(|id| names[id].as_str()).collect();
        // jwt and cors come first (in order), then unlisted in original order.
        assert_eq!(sorted_names[0], "jwt");
        assert_eq!(sorted_names[1], "cors");
        // Unlisted plugins appear after the ordered ones.
        let unlisted: Vec<&str> = sorted_names[2..].to_vec();
        assert!(unlisted.contains(&"logging"));
        assert!(unlisted.contains(&"rate-limit"));
    }

    #[test]
    fn order_empty_preserves() {
        let (mut ids, names) = make_ids(&["cors", "logging", "rate-limit"]);
        let original_names: Vec<String> = ids.iter().map(|id| names[id].clone()).collect();
        let order: Vec<String> = vec![];

        sort_ids_by_order(&mut ids, &names, &order);

        let sorted_names: Vec<String> = ids.iter().map(|id| names[id].clone()).collect();
        assert_eq!(sorted_names, original_names);
    }
}
