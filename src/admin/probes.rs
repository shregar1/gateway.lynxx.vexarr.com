use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::{Probe, ProbeResult};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateProbeBody {
    pub name: String,
    #[serde(default)]
    pub route_id: Option<Uuid>,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default = "default_interval")]
    pub interval_seconds: i32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: i32,
    #[serde(default = "default_expected")]
    pub expected_status: i32,
}

fn default_method() -> String { "GET".into() }
fn default_path() -> String { "/".into() }
fn default_interval() -> i32 { 60 }
fn default_timeout() -> i32 { 5000 }
fn default_expected() -> i32 { 200 }

#[derive(Deserialize)]
pub struct PatchProbeBody {
    pub enabled: Option<bool>,
    pub name: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub interval_seconds: Option<i32>,
    pub timeout_ms: Option<i32>,
    pub expected_status: Option<i32>,
}

pub async fn list_probes(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<Probe>>, GatewayError> {
    let probes = state.repo.list_probes(&service_id).await?;
    Ok(Json(probes))
}

pub async fn create_probe(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<CreateProbeBody>,
) -> Result<(StatusCode, Json<Probe>), GatewayError> {
    let now = Utc::now();
    let probe = Probe {
        id: Uuid::new_v4(),
        service_id,
        route_id: body.route_id,
        name: body.name,
        method: body.method,
        path: body.path,
        interval_seconds: body.interval_seconds,
        timeout_ms: body.timeout_ms,
        expected_status: body.expected_status,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_probe(&probe).await?;
    Ok((StatusCode::CREATED, Json(probe)))
}

pub async fn patch_probe(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchProbeBody>,
) -> Result<Json<Probe>, GatewayError> {
    let mut probe = state
        .repo
        .get_probe(&id)
        .await?
        .ok_or(GatewayError::NotFound("probe not found".into()))?;

    if let Some(v) = body.enabled { probe.enabled = v; }
    if let Some(v) = body.name { probe.name = v; }
    if let Some(v) = body.method { probe.method = v; }
    if let Some(v) = body.path { probe.path = v; }
    if let Some(v) = body.interval_seconds { probe.interval_seconds = v; }
    if let Some(v) = body.timeout_ms { probe.timeout_ms = v; }
    if let Some(v) = body.expected_status { probe.expected_status = v; }

    state.repo.update_probe(&id, &probe).await?;
    Ok(Json(probe))
}

pub async fn delete_probe(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_probe(&id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("probe not found".into()))
    }
}

pub async fn probe_results(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ProbeResult>>, GatewayError> {
    let results = state.repo.list_probe_results(&id, 100).await?;
    Ok(Json(results))
}

#[derive(serde::Serialize)]
pub struct ProbeStats {
    pub probe_id: Uuid,
    pub total_checks: usize,
    pub healthy_count: usize,
    pub uptime_1h: f64,
    pub uptime_24h: f64,
    pub uptime_7d: f64,
    pub uptime_30d: f64,
    pub avg_latency_ms: f64,
}

pub async fn probe_stats(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProbeStats>, GatewayError> {
    let results = state.repo.list_probe_results(&id, 1000).await?;
    let now = Utc::now();
    let total = results.len();
    let healthy = results.iter().filter(|r| r.healthy).count();

    let compute_uptime = |hours: i64| -> f64 {
        let cutoff = now - chrono::Duration::hours(hours);
        let window: Vec<_> = results.iter().filter(|r| r.ts >= cutoff).collect();
        if window.is_empty() {
            return 100.0;
        }
        let h = window.iter().filter(|r| r.healthy).count();
        h as f64 / window.len() as f64 * 100.0
    };

    let avg_lat = if total > 0 {
        results
            .iter()
            .filter_map(|r| r.latency_ms)
            .sum::<i32>() as f64
            / total as f64
    } else {
        0.0
    };

    Ok(Json(ProbeStats {
        probe_id: id,
        total_checks: total,
        healthy_count: healthy,
        uptime_1h: compute_uptime(1),
        uptime_24h: compute_uptime(24),
        uptime_7d: compute_uptime(168),
        uptime_30d: compute_uptime(720),
        avg_latency_ms: avg_lat,
    }))
}
