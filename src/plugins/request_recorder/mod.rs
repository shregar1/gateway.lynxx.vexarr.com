//! Time-Travel Debug capture plugin (`request-recorder`).
//!
//! On the request side we sample, buffer the body up to `max_body_bytes`,
//! redact configured headers and JSON body keys, and stash the captured
//! state in a process-local map keyed by a uuid header. On the response
//! side we look that state back up, capture the response body (already
//! buffered into `Full<Bytes>` by the proxy), build a `Recording`, and
//! fire-and-forget it onto a bounded mpsc. A background task writes to
//! the content-addressed store and the DB index. A second task sweeps
//! retention hourly.
//!
//! Failures never fail the request — the gateway continues even if the
//! disk or DB is unavailable.

mod config;

use crate::db::Repository;
use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use crate::recording::{
    redact, ContentAddressedStore, RecordedRequest, RecordedResponse, Recording, RecordingIndexRow,
};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderValue, Request, Response};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use config::Config;
use dashmap::DashMap;
use http_body_util::BodyExt;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// Header used to thread the pending capture id from request to response.
const HDR_CAPTURE_ID: &str = "x-lynxx-recorder-id";

/// Process-global pending-capture map. Plugins are rebuilt on every admin
/// mutation, so a per-instance map would lose in-flight captures across
/// rebuilds. The map is keyed by a uuid the request side mints.
static PENDING: OnceLock<Arc<DashMap<String, PendingCapture>>> = OnceLock::new();

fn pending() -> &'static Arc<DashMap<String, PendingCapture>> {
    PENDING.get_or_init(|| Arc::new(DashMap::new()))
}

/// A pending capture this old will never be matched by an `on_response` — the
/// request errored before producing a response, another plugin stripped the
/// id header, or the client disconnected. Sweep such entries so the map (and
/// the buffered request bodies it holds) can't grow without bound.
const PENDING_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);
/// Hard backstop on the number of in-flight captures.
const PENDING_MAX_ENTRIES: usize = 10_000;

/// Drop pending captures older than [`PENDING_MAX_AGE`].
fn sweep_pending() {
    pending().retain(|_, p| p.started.elapsed() < PENDING_MAX_AGE);
}

#[derive(Clone)]
struct PendingCapture {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    started: Instant,
    started_utc: chrono::DateTime<Utc>,
    cfg_min_status: u16,
    cfg_max_status: u16,
    cfg_max_body_bytes: usize,
    /// Match context fields plumbed in by the proxy handler. `None` if the
    /// request didn't go through the proxy match path (e.g. unit tests).
    service_id: Option<uuid::Uuid>,
    route_id: Option<uuid::Uuid>,
    upstream_url: String,
    consumer: Option<String>,
}

struct RecordingJob {
    recording: Recording,
    index_row: RecordingIndexRow,
}

pub struct RequestRecorderPlugin {
    cfg: Config,
    tx: tokio::sync::mpsc::Sender<RecordingJob>,
}

impl RequestRecorderPlugin {
    pub fn from_config(
        cfg_value: &serde_json::Value,
        repo: Option<Arc<dyn Repository>>,
    ) -> Result<Self, GatewayError> {
        let cfg: Config = if cfg_value.is_null() {
            Config::default()
        } else {
            serde_json::from_value(cfg_value.clone())
                .map_err(|e| GatewayError::BadRequest(format!("request-recorder: {e}")))?
        };
        let repo = repo.ok_or_else(|| {
            GatewayError::BadRequest("request-recorder requires repository".into())
        })?;
        let store = Arc::new(ContentAddressedStore::new(&cfg.directory));
        let (tx, rx) = tokio::sync::mpsc::channel::<RecordingJob>(1024);
        spawn_writer(rx, store, repo.clone());
        spawn_retention_sweeper(repo, cfg.retention_days);
        Ok(Self { cfg, tx })
    }
}

#[async_trait]
impl Plugin for RequestRecorderPlugin {
    fn name(&self) -> &str {
        "request-recorder"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        // Sampling decision is made up front; if we're not capturing this
        // request we don't touch the body at all.
        if rand::random::<f64>() >= self.cfg.sample_rate {
            return Ok(());
        }

        // Pull match context out of extensions before we rip the request
        // apart. The proxy inserts this just before the plugin chain runs;
        // for non-proxy paths (e.g. unit tests) it'll just be absent.
        let match_ctx = req
            .extensions()
            .get::<crate::proxy::handler::MatchContext>()
            .cloned();

        // Drain the request body so we can both record it and rebuild the
        // request for downstream consumers.
        let (parts, body) = std::mem::replace(req, Request::new(Body::empty())).into_parts();
        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::debug!(error = %e, "request-recorder: collect req body");
                // Reassemble with empty body — we lost the original. Better
                // than panicking the request.
                *req = Request::from_parts(parts, Body::empty());
                return Ok(());
            }
        };
        let truncated: Vec<u8> = if body_bytes.len() > self.cfg.max_body_bytes {
            body_bytes[..self.cfg.max_body_bytes].to_vec()
        } else {
            body_bytes.to_vec()
        };

        let content_type = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        redact::redact_headers_defaulted(&mut headers, &self.cfg.redact_headers);

        // Redact bodies before persisting. JSON is redacted by key name,
        // form-urlencoded by parameter name; both on top of a built-in
        // credential denylist so secrets never persist even with empty config.
        // Anything else is recorded as-is (we can't safely parse it).
        let body_for_record: Vec<u8> = match serde_json::from_slice::<serde_json::Value>(&truncated)
        {
            Ok(mut v) => {
                redact::redact_body_paths_defaulted(&mut v, &self.cfg.redact_body_paths);
                serde_json::to_vec(&v).unwrap_or_else(|_| truncated.clone())
            }
            Err(_) if content_type.starts_with("application/x-www-form-urlencoded") => {
                redact::redact_form_urlencoded(&truncated, &self.cfg.redact_body_paths)
            }
            Err(_) => truncated.clone(),
        };

        // Prefer the consumer the proxy already resolved (from the
        // X-Consumer-Username request header at match time); fall back to
        // whatever the auth plugins wrote on the way through.
        let consumer_from_header = parts
            .headers
            .get("x-consumer-username")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let (mc_service, mc_route, mc_upstream, mc_consumer) = match_ctx
            .map(|c| {
                (
                    Some(c.service_id),
                    Some(c.route_id),
                    c.upstream_url,
                    c.consumer_username.or(consumer_from_header.clone()),
                )
            })
            .unwrap_or((None, None, String::new(), consumer_from_header));

        let pending_capture = PendingCapture {
            method: parts.method.as_str().to_string(),
            path: parts.uri.path().to_string(),
            headers,
            body: body_for_record,
            started: Instant::now(),
            started_utc: Utc::now(),
            cfg_min_status: self.cfg.min_status_to_record,
            cfg_max_status: self.cfg.max_status_to_record,
            cfg_max_body_bytes: self.cfg.max_body_bytes,
            service_id: mc_service,
            route_id: mc_route,
            upstream_url: mc_upstream,
            consumer: mc_consumer,
        };

        // Bound the pending map before inserting: sweep captures that will
        // never be matched, and if it is still saturated, skip recording this
        // request rather than leaking its buffered body.
        sweep_pending();
        if pending().len() >= PENDING_MAX_ENTRIES {
            tracing::warn!(
                pending = pending().len(),
                "request-recorder pending map saturated; skipping capture"
            );
            *req = Request::from_parts(parts, Body::from(body_bytes));
            return Ok(());
        }

        // Mint an id, stash the capture, and thread the id forward via a
        // header. The proxy handler copies request headers onto the response
        // before running the response chain, so this id reaches `on_response`.
        let capture_id = uuid::Uuid::new_v4().to_string();
        pending().insert(capture_id.clone(), pending_capture);

        // Reassemble request with the buffered body so downstream consumers
        // still see it.
        let mut req_rebuilt = Request::from_parts(parts, Body::from(body_bytes));
        if let Ok(v) = HeaderValue::from_str(&capture_id) {
            req_rebuilt.headers_mut().insert(HDR_CAPTURE_ID, v);
        }
        *req = req_rebuilt;
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let capture_id = match resp
            .headers()
            .get(HDR_CAPTURE_ID)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
        {
            Some(k) => k,
            None => return Ok(()),
        };
        // Internal header — don't leak it downstream.
        resp.headers_mut().remove(HDR_CAPTURE_ID);

        let pending_capture = match pending().remove(&capture_id) {
            Some((_, p)) => p,
            None => return Ok(()),
        };

        let status = resp.status().as_u16();
        if status < pending_capture.cfg_min_status || status > pending_capture.cfg_max_status {
            return Ok(());
        }

        // Drain the response body so we can both record it and rebuild the
        // response for downstream consumers.
        let (parts, body) = std::mem::replace(resp, Response::new(Body::empty())).into_parts();
        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::debug!(error = %e, "request-recorder: collect resp body");
                *resp = Response::from_parts(parts, Body::empty());
                return Ok(());
            }
        };
        let truncated: Vec<u8> = if body_bytes.len() > pending_capture.cfg_max_body_bytes {
            body_bytes[..pending_capture.cfg_max_body_bytes].to_vec()
        } else {
            body_bytes.to_vec()
        };

        let mut resp_headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        // Response headers were previously persisted in the clear — Set-Cookie,
        // bearer tokens, etc. Redact with the same default-deny set as requests.
        redact::redact_headers_defaulted(&mut resp_headers, &self.cfg.redact_headers);

        // Redact secrets in JSON response bodies (e.g. access_token / refresh
        // token in an auth response) before persisting.
        let resp_content_type = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let resp_body_for_record: Vec<u8> =
            match serde_json::from_slice::<serde_json::Value>(&truncated) {
                Ok(mut v) => {
                    redact::redact_body_paths_defaulted(&mut v, &self.cfg.redact_body_paths);
                    serde_json::to_vec(&v).unwrap_or_else(|_| truncated.clone())
                }
                Err(_) if resp_content_type.starts_with("application/x-www-form-urlencoded") => {
                    redact::redact_form_urlencoded(&truncated, &self.cfg.redact_body_paths)
                }
                Err(_) => truncated.clone(),
            };

        let duration_ms = pending_capture.started.elapsed().as_millis() as u64;

        // Build a Recording. compute_id requires id="" first so the round-trip
        // file content matches the addressed name.
        let mut recording = Recording {
            id: String::new(),
            ts: pending_capture.started_utc,
            service_id: pending_capture.service_id,
            route_id: pending_capture.route_id,
            consumer: pending_capture.consumer.clone(),
            request: RecordedRequest {
                method: pending_capture.method.clone(),
                path: pending_capture.path.clone(),
                headers: pending_capture.headers.clone(),
                body_b64: STANDARD.encode(&pending_capture.body),
            },
            response: RecordedResponse {
                status,
                headers: resp_headers,
                body_b64: STANDARD.encode(&resp_body_for_record),
            },
            upstream_url: pending_capture.upstream_url.clone(),
            duration_ms,
        };
        let id = recording.compute_id();
        recording.id = id.clone();

        let index_row = RecordingIndexRow {
            id: id.clone(),
            ts: pending_capture.started_utc,
            method: pending_capture.method,
            path: pending_capture.path,
            status,
            duration_ms,
            service_id: pending_capture.service_id,
            route_id: pending_capture.route_id,
            consumer: pending_capture.consumer,
            bytes_request: pending_capture.body.len() as u64,
            bytes_response: truncated.len() as u64,
        };

        // Reassemble response with the buffered body.
        *resp = Response::from_parts(parts, Body::from(body_bytes));

        // Fire-and-forget. A full channel just drops; recording is best-effort.
        if let Err(e) = self.tx.try_send(RecordingJob {
            recording,
            index_row,
        }) {
            tracing::debug!(error = %e, "request-recorder: drop (channel full)");
        }
        Ok(())
    }
}

fn spawn_writer(
    mut rx: tokio::sync::mpsc::Receiver<RecordingJob>,
    store: Arc<ContentAddressedStore>,
    repo: Arc<dyn Repository>,
) {
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            if let Err(e) = store.put(&job.recording).await {
                tracing::warn!(error = %e, "request-recorder: store.put failed");
                continue;
            }
            if let Err(e) = repo.append_recording(&job.index_row).await {
                tracing::warn!(error = %e, "request-recorder: append_recording failed");
            }
        }
    });
}

fn spawn_retention_sweeper(repo: Arc<dyn Repository>, retention_days: u32) {
    if retention_days == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
            match repo.delete_recordings_before(cutoff).await {
                Ok(n) if n > 0 => {
                    tracing::info!(deleted = n, "request-recorder retention sweep")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "request-recorder retention sweep failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubRepo;

    #[async_trait]
    impl Repository for StubRepo {
        async fn list_services(&self) -> Result<Vec<crate::models::Service>, GatewayError> {
            Ok(vec![])
        }
        async fn get_service(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Service>, GatewayError> {
            Ok(None)
        }
        async fn get_service_by_name(
            &self,
            _name: &str,
        ) -> Result<Option<crate::models::Service>, GatewayError> {
            Ok(None)
        }
        async fn create_service(&self, _svc: &crate::models::Service) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_service(
            &self,
            _id: &uuid::Uuid,
            _svc: &crate::models::Service,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_service(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_routes(&self) -> Result<Vec<crate::models::Route>, GatewayError> {
            Ok(vec![])
        }
        async fn get_route(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Route>, GatewayError> {
            Ok(None)
        }
        async fn create_route(&self, _route: &crate::models::Route) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_route(
            &self,
            _id: &uuid::Uuid,
            _route: &crate::models::Route,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_route(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_plugins(&self) -> Result<Vec<crate::models::PluginInstance>, GatewayError> {
            Ok(vec![])
        }
        async fn get_plugin(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::PluginInstance>, GatewayError> {
            Ok(None)
        }
        async fn create_plugin(
            &self,
            _plugin: &crate::models::PluginInstance,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_plugin(
            &self,
            _id: &uuid::Uuid,
            _plugin: &crate::models::PluginInstance,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_plugin(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_consumers(&self) -> Result<Vec<crate::models::Consumer>, GatewayError> {
            Ok(vec![])
        }
        async fn create_consumer(
            &self,
            _consumer: &crate::models::Consumer,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_consumer(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_targets(&self) -> Result<Vec<crate::models::Target>, GatewayError> {
            Ok(vec![])
        }
        async fn list_targets_for_service(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Vec<crate::models::Target>, GatewayError> {
            Ok(vec![])
        }
        async fn get_target(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Target>, GatewayError> {
            Ok(None)
        }
        async fn create_target(&self, _t: &crate::models::Target) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_target(
            &self,
            _id: &uuid::Uuid,
            _t: &crate::models::Target,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_target(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn update_target_state(
            &self,
            _id: &uuid::Uuid,
            _state: &str,
        ) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn is_empty(&self) -> Result<bool, GatewayError> {
            Ok(true)
        }
        async fn seed_from_config(
            &self,
            _config: &crate::config::GatewayConfig,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn clear_config_seed(&self) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn mark_config_source(
            &self,
            _s: &[uuid::Uuid],
            _r: &[uuid::Uuid],
            _p: &[uuid::Uuid],
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_admin_tokens(&self) -> Result<Vec<crate::auth::AdminToken>, GatewayError> {
            Ok(vec![])
        }
        async fn get_admin_token_by_hash(
            &self,
            _h: &str,
        ) -> Result<Option<crate::auth::AdminToken>, GatewayError> {
            Ok(None)
        }
        async fn get_admin_token(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::auth::AdminToken>, GatewayError> {
            Ok(None)
        }
        async fn create_admin_token(
            &self,
            _t: &crate::db::NewAdminToken,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_admin_token(
            &self,
            _id: &uuid::Uuid,
            _patch: &crate::db::AdminTokenPatch,
        ) -> Result<Option<crate::auth::AdminToken>, GatewayError> {
            Ok(None)
        }
        async fn delete_admin_token(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn update_admin_token_last_used(
            &self,
            _id: &uuid::Uuid,
            _ts: chrono::DateTime<Utc>,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn has_any_admin_token(&self) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn append_audit(
            &self,
            entry: &crate::audit::NewAuditEntry,
        ) -> Result<crate::audit::AuditEntry, GatewayError> {
            Ok(crate::audit::AuditEntry {
                id: 0,
                ts: entry.ts,
                actor_id: entry.actor_id,
                actor_name: entry.actor_name.clone(),
                actor_role: entry.actor_role.clone(),
                action: entry.action.clone(),
                resource_type: entry.resource_type.clone(),
                resource_id: entry.resource_id.clone(),
                diff: entry.diff.clone(),
                hash: String::new(),
                prev_hash: None,
            })
        }
        async fn list_audit(
            &self,
            _f: &crate::audit::AuditFilter,
        ) -> Result<Vec<crate::audit::AuditEntry>, GatewayError> {
            Ok(vec![])
        }
        async fn last_audit_hash(&self) -> Result<Option<String>, GatewayError> {
            Ok(None)
        }
        fn cluster_bus(&self) -> Arc<dyn crate::cluster::ClusterBus> {
            unimplemented!("test stub")
        }
        async fn get_quota_usage(
            &self,
            _period: &str,
        ) -> Result<Option<(u64, u64, u64)>, GatewayError> {
            Ok(None)
        }
        async fn upsert_quota_usage(
            &self,
            _period: &str,
            _calls_total: u64,
            _calls_rejected: u64,
            _calls_overage: u64,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn append_recording(&self, _row: &RecordingIndexRow) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_recordings(
            &self,
            _f: &crate::recording::RecordingFilter,
        ) -> Result<Vec<RecordingIndexRow>, GatewayError> {
            Ok(vec![])
        }
        async fn get_recording_index(
            &self,
            _id: &str,
        ) -> Result<Option<RecordingIndexRow>, GatewayError> {
            Ok(None)
        }
        async fn delete_recording(&self, _id: &str) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn delete_recordings_before(
            &self,
            _ts: chrono::DateTime<chrono::Utc>,
        ) -> Result<u64, GatewayError> {
            Ok(0)
        }
        async fn get_device_fingerprint(
            &self,
            _customer_id: i64,
            _hardware_id: &str,
        ) -> Result<Option<crate::models::DeviceFingerprint>, GatewayError> {
            Ok(None)
        }
        async fn create_device_fingerprint(
            &self,
            _device: &crate::models::DeviceFingerprint,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_device_last_seen(
            &self,
            _id: &uuid::Uuid,
            _ts: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn create_runtime_grant(
            &self,
            _grant: &crate::models::RuntimeGrant,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn get_runtime_grant_by_token_id(
            &self,
            _token_id: &str,
        ) -> Result<Option<crate::models::RuntimeGrant>, GatewayError> {
            Ok(None)
        }
        async fn update_grant_heartbeat(
            &self,
            _token_id: &str,
            _ts: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn revoke_grant(&self, _token_id: &str) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn get_api_key_by_prefix(
            &self,
            _prefix: &str,
        ) -> Result<Option<crate::models::ApiKeyRow>, GatewayError> {
            Ok(None)
        }

        // Projects
        async fn list_projects(&self) -> Result<Vec<crate::models::Project>, GatewayError> {
            Ok(vec![])
        }
        async fn get_project(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Project>, GatewayError> {
            Ok(None)
        }
        async fn create_project(&self, _p: &crate::models::Project) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_project(
            &self,
            _id: &uuid::Uuid,
            _p: &crate::models::Project,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_project(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_services_for_project(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Vec<crate::models::Service>, GatewayError> {
            Ok(vec![])
        }

        // Cascade soft-delete
        async fn soft_delete_plugins_for_route(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<u64, GatewayError> {
            Ok(0)
        }
        async fn soft_delete_plugins_for_service(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<u64, GatewayError> {
            Ok(0)
        }
        async fn soft_delete_routes_for_service(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Vec<uuid::Uuid>, GatewayError> {
            Ok(vec![])
        }
        async fn soft_delete_targets_for_service(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<u64, GatewayError> {
            Ok(0)
        }
        async fn soft_delete_services_for_project(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Vec<uuid::Uuid>, GatewayError> {
            Ok(vec![])
        }

        // Logs
        async fn insert_logs(
            &self,
            _entries: &[crate::models::LogEntry],
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_logs(
            &self,
            _filter: &crate::db::LogFilter,
        ) -> Result<Vec<crate::models::LogEntry>, GatewayError> {
            Ok(vec![])
        }
        async fn prune_logs(&self, _days: u32) -> Result<u64, GatewayError> {
            Ok(0)
        }

        // Analytics
        async fn upsert_metric_bucket(
            &self,
            _b: &crate::models::MetricBucket,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_metric_buckets(
            &self,
            _sid: &uuid::Uuid,
            _from: chrono::DateTime<Utc>,
            _to: chrono::DateTime<Utc>,
            _g: &str,
        ) -> Result<Vec<crate::models::MetricBucket>, GatewayError> {
            Ok(vec![])
        }
        async fn upsert_geo_bucket(
            &self,
            _b: &crate::models::GeoBucket,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_geo_buckets(
            &self,
            _sid: &uuid::Uuid,
            _from: chrono::DateTime<Utc>,
            _to: chrono::DateTime<Utc>,
        ) -> Result<Vec<crate::models::GeoBucket>, GatewayError> {
            Ok(vec![])
        }
        async fn upsert_rate_limit_bucket(
            &self,
            _b: &crate::models::RateLimitBucket,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_rate_limit_buckets(
            &self,
            _sid: &uuid::Uuid,
            _from: chrono::DateTime<Utc>,
            _to: chrono::DateTime<Utc>,
        ) -> Result<Vec<crate::models::RateLimitBucket>, GatewayError> {
            Ok(vec![])
        }

        // Probes
        async fn list_probes(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::Probe>, GatewayError> {
            Ok(vec![])
        }
        async fn get_probe(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Probe>, GatewayError> {
            Ok(None)
        }
        async fn create_probe(&self, _p: &crate::models::Probe) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_probe(
            &self,
            _id: &uuid::Uuid,
            _p: &crate::models::Probe,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_probe(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn append_probe_result(
            &self,
            _r: &crate::models::ProbeResult,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_probe_results(
            &self,
            _pid: &uuid::Uuid,
            _limit: u32,
        ) -> Result<Vec<crate::models::ProbeResult>, GatewayError> {
            Ok(vec![])
        }

        // Snapshots
        async fn list_snapshots(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::Snapshot>, GatewayError> {
            Ok(vec![])
        }
        async fn get_snapshot(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Snapshot>, GatewayError> {
            Ok(None)
        }
        async fn create_snapshot(&self, _s: &crate::models::Snapshot) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_snapshot(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Alerts
        async fn list_alert_rules(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::AlertRule>, GatewayError> {
            Ok(vec![])
        }
        async fn get_alert_rule(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::AlertRule>, GatewayError> {
            Ok(None)
        }
        async fn create_alert_rule(
            &self,
            _r: &crate::models::AlertRule,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_alert_rule(
            &self,
            _id: &uuid::Uuid,
            _r: &crate::models::AlertRule,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_alert_rule(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_alert_events(
            &self,
            _sid: &uuid::Uuid,
            _limit: u32,
        ) -> Result<Vec<crate::models::AlertEvent>, GatewayError> {
            Ok(vec![])
        }
        async fn create_alert_event(
            &self,
            _e: &crate::models::AlertEvent,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn resolve_alert_event(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // IP Rules
        async fn list_ip_rules(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::IpRule>, GatewayError> {
            Ok(vec![])
        }
        async fn get_ip_rule(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::IpRule>, GatewayError> {
            Ok(None)
        }
        async fn create_ip_rule(&self, _r: &crate::models::IpRule) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_ip_rule(
            &self,
            _id: &uuid::Uuid,
            _r: &crate::models::IpRule,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_ip_rule(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Error Pages
        async fn list_error_pages(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::ErrorPage>, GatewayError> {
            Ok(vec![])
        }
        async fn get_error_page(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::ErrorPage>, GatewayError> {
            Ok(None)
        }
        async fn create_error_page(
            &self,
            _p: &crate::models::ErrorPage,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_error_page(
            &self,
            _id: &uuid::Uuid,
            _p: &crate::models::ErrorPage,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_error_page(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Consumer Groups
        async fn list_consumer_groups(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::ConsumerGroup>, GatewayError> {
            Ok(vec![])
        }
        async fn get_consumer_group(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::ConsumerGroup>, GatewayError> {
            Ok(None)
        }
        async fn create_consumer_group(
            &self,
            _g: &crate::models::ConsumerGroup,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_consumer_group(
            &self,
            _id: &uuid::Uuid,
            _g: &crate::models::ConsumerGroup,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_consumer_group(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_consumer_group_members(
            &self,
            _gid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::ConsumerGroupMember>, GatewayError> {
            Ok(vec![])
        }
        async fn add_consumer_group_member(
            &self,
            _m: &crate::models::ConsumerGroupMember,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn remove_consumer_group_member(
            &self,
            _gid: &uuid::Uuid,
            _cid: &uuid::Uuid,
        ) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Cache
        async fn list_cache_entries(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::CacheEntry>, GatewayError> {
            Ok(vec![])
        }
        async fn get_cache_entry(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::CacheEntry>, GatewayError> {
            Ok(None)
        }
        async fn upsert_cache_entry(
            &self,
            _e: &crate::models::CacheEntry,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_cache_entry(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn purge_cache(&self, _sid: &uuid::Uuid) -> Result<u64, GatewayError> {
            Ok(0)
        }
        async fn cache_stats(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<crate::models::CacheStats, GatewayError> {
            Ok(crate::models::CacheStats {
                service_id: *_sid,
                total_entries: 0,
                total_size_bytes: 0,
                hit_count: 0,
                miss_count: 0,
                hit_rate: 0.0,
                eviction_count: 0,
            })
        }

        // Tracing
        async fn list_traces(
            &self,
            _sid: &uuid::Uuid,
            _limit: u32,
        ) -> Result<Vec<crate::models::TraceRecord>, GatewayError> {
            Ok(vec![])
        }
        async fn get_trace(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::TraceRecord>, GatewayError> {
            Ok(None)
        }
        async fn create_trace(&self, _t: &crate::models::TraceRecord) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn list_spans(
            &self,
            _tid: &str,
        ) -> Result<Vec<crate::models::SpanRecord>, GatewayError> {
            Ok(vec![])
        }
        async fn create_span(&self, _s: &crate::models::SpanRecord) -> Result<(), GatewayError> {
            Ok(())
        }

        // Transforms
        async fn list_transform_rules(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::TransformRule>, GatewayError> {
            Ok(vec![])
        }
        async fn get_transform_rule(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::TransformRule>, GatewayError> {
            Ok(None)
        }
        async fn create_transform_rule(
            &self,
            _r: &crate::models::TransformRule,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_transform_rule(
            &self,
            _id: &uuid::Uuid,
            _r: &crate::models::TransformRule,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_transform_rule(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // API Versions
        async fn list_api_versions(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::ApiVersion>, GatewayError> {
            Ok(vec![])
        }
        async fn get_api_version(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::ApiVersion>, GatewayError> {
            Ok(None)
        }
        async fn create_api_version(
            &self,
            _v: &crate::models::ApiVersion,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_api_version(
            &self,
            _id: &uuid::Uuid,
            _v: &crate::models::ApiVersion,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_api_version(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Incidents
        async fn list_incidents(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::Incident>, GatewayError> {
            Ok(vec![])
        }
        async fn get_incident(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Incident>, GatewayError> {
            Ok(None)
        }
        async fn create_incident(&self, _i: &crate::models::Incident) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_incident(
            &self,
            _id: &uuid::Uuid,
            _i: &crate::models::Incident,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_incident(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_incident_updates(
            &self,
            _iid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::IncidentUpdate>, GatewayError> {
            Ok(vec![])
        }
        async fn create_incident_update(
            &self,
            _u: &crate::models::IncidentUpdate,
        ) -> Result<(), GatewayError> {
            Ok(())
        }

        // Webhooks
        async fn list_webhooks(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::Webhook>, GatewayError> {
            Ok(vec![])
        }
        async fn get_webhook(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Webhook>, GatewayError> {
            Ok(None)
        }
        async fn create_webhook(&self, _w: &crate::models::Webhook) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_webhook(
            &self,
            _id: &uuid::Uuid,
            _w: &crate::models::Webhook,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_webhook(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }
        async fn list_webhook_deliveries(
            &self,
            _wid: &uuid::Uuid,
            _limit: u32,
        ) -> Result<Vec<crate::models::WebhookDelivery>, GatewayError> {
            Ok(vec![])
        }
        async fn create_webhook_delivery(
            &self,
            _d: &crate::models::WebhookDelivery,
        ) -> Result<(), GatewayError> {
            Ok(())
        }

        // Load Tests
        async fn list_load_tests(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::LoadTest>, GatewayError> {
            Ok(vec![])
        }
        async fn get_load_test(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::LoadTest>, GatewayError> {
            Ok(None)
        }
        async fn create_load_test(&self, _t: &crate::models::LoadTest) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_load_test(
            &self,
            _id: &uuid::Uuid,
            _t: &crate::models::LoadTest,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_load_test(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Marketplace
        async fn list_marketplace_plugins(
            &self,
        ) -> Result<Vec<crate::models::MarketplacePlugin>, GatewayError> {
            Ok(vec![])
        }
        async fn get_marketplace_plugin(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::MarketplacePlugin>, GatewayError> {
            Ok(None)
        }
        async fn create_marketplace_plugin(
            &self,
            _p: &crate::models::MarketplacePlugin,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_marketplace_plugin(
            &self,
            _id: &uuid::Uuid,
            _p: &crate::models::MarketplacePlugin,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_marketplace_plugin(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Cost
        async fn list_cost_records(
            &self,
            _sid: &uuid::Uuid,
            _from: chrono::DateTime<Utc>,
            _to: chrono::DateTime<Utc>,
        ) -> Result<Vec<crate::models::CostRecord>, GatewayError> {
            Ok(vec![])
        }
        async fn upsert_cost_record(
            &self,
            _r: &crate::models::CostRecord,
        ) -> Result<(), GatewayError> {
            Ok(())
        }

        // Cluster
        async fn list_cluster_nodes(
            &self,
        ) -> Result<Vec<crate::models::ClusterNode>, GatewayError> {
            Ok(vec![])
        }
        async fn get_cluster_node(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::ClusterNode>, GatewayError> {
            Ok(None)
        }
        async fn upsert_cluster_node(
            &self,
            _n: &crate::models::ClusterNode,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_cluster_node(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Rate Limit Simulator
        async fn list_rate_limit_simulations(
            &self,
            _sid: &uuid::Uuid,
        ) -> Result<Vec<crate::models::RateLimitSimulation>, GatewayError> {
            Ok(vec![])
        }
        async fn create_rate_limit_simulation(
            &self,
            _s: &crate::models::RateLimitSimulation,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn get_rate_limit_simulation(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::RateLimitSimulation>, GatewayError> {
            Ok(None)
        }

        // PKI
        async fn list_certificates(
            &self,
            _sid: Option<&uuid::Uuid>,
        ) -> Result<Vec<crate::models::Certificate>, GatewayError> {
            Ok(vec![])
        }
        async fn get_certificate(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<Option<crate::models::Certificate>, GatewayError> {
            Ok(None)
        }
        async fn create_certificate(
            &self,
            _c: &crate::models::Certificate,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn update_certificate(
            &self,
            _id: &uuid::Uuid,
            _c: &crate::models::Certificate,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn delete_certificate(&self, _id: &uuid::Uuid) -> Result<bool, GatewayError> {
            Ok(false)
        }

        // Consumer update
        async fn update_consumer(
            &self,
            _id: &uuid::Uuid,
            _c: &crate::models::Consumer,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn from_config_default_builds_ok() {
        let repo: Arc<dyn Repository> = Arc::new(StubRepo);
        let v = serde_json::json!({});
        let p = RequestRecorderPlugin::from_config(&v, Some(repo)).unwrap();
        assert_eq!(p.name(), "request-recorder");
    }

    #[tokio::test]
    async fn from_config_out_of_range_sample_rate_still_builds() {
        let repo: Arc<dyn Repository> = Arc::new(StubRepo);
        let v = serde_json::json!({"sample_rate": 99.0, "retention_days": 0});
        let p = RequestRecorderPlugin::from_config(&v, Some(repo)).unwrap();
        assert_eq!(p.name(), "request-recorder");
    }

    #[tokio::test]
    async fn from_config_without_repo_errors() {
        let v = serde_json::json!({});
        let res = RequestRecorderPlugin::from_config(&v, None);
        assert!(res.is_err());
    }
}
