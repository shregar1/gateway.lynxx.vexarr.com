use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::RateLimitSimulation;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// POST /services/:id/ratelimit-sim — run a rate limit simulation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RunSimulationBody {
    #[serde(default)]
    pub consumer_id: Option<Uuid>,
    #[serde(default = "default_rps")]
    pub requests_per_second: i32,
    #[serde(default = "default_duration")]
    pub duration_seconds: i32,
    pub limit: i32,
    #[serde(default = "default_window")]
    pub window_seconds: i32,
    #[serde(default)]
    pub burst: i32,
}

fn default_rps() -> i32 {
    100
}
fn default_duration() -> i32 {
    60
}
fn default_window() -> i32 {
    60
}

pub async fn run_simulation(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<RunSimulationBody>,
) -> Result<(StatusCode, Json<RateLimitSimulation>), GatewayError> {
    let now = Utc::now();

    // Simulate the rate limiting locally
    let total_requests = body.requests_per_second * body.duration_seconds;
    let window_capacity = body.limit + body.burst;
    let windows = body.duration_seconds as f64 / body.window_seconds as f64;
    let capacity_per_window = window_capacity as f64;
    let requests_per_window = body.requests_per_second as f64 * body.window_seconds as f64;

    let allowed_per_window = requests_per_window.min(capacity_per_window);
    let rejected_per_window = (requests_per_window - capacity_per_window).max(0.0);
    let total_allowed = (allowed_per_window * windows).round() as i64;
    let total_rejected = (rejected_per_window * windows).round() as i64;
    let rejection_rate = if total_requests > 0 {
        total_rejected as f64 / total_requests as f64 * 100.0
    } else {
        0.0
    };

    let result = serde_json::json!({
        "total_requests": total_requests,
        "total_allowed": total_allowed,
        "total_rejected": total_rejected,
        "rejection_rate_percent": rejection_rate,
        "effective_rps": allowed_per_window / body.window_seconds as f64,
        "windows_simulated": windows.ceil() as i64,
    });

    let sim = RateLimitSimulation {
        id: Uuid::new_v4(),
        service_id,
        consumer_id: body.consumer_id,
        requests_per_second: body.requests_per_second,
        duration_seconds: body.duration_seconds,
        limit: body.limit,
        window_seconds: body.window_seconds,
        burst: body.burst,
        result: Some(result),
        created_at: now,
    };
    state.repo.create_rate_limit_simulation(&sim).await?;

    Ok((StatusCode::CREATED, Json(sim)))
}

// ---------------------------------------------------------------------------
// GET /services/:id/ratelimit-sim — list past simulations for a service
// ---------------------------------------------------------------------------

pub async fn list_simulations(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<RateLimitSimulation>>, GatewayError> {
    let sims = state
        .repo
        .list_rate_limit_simulations(&service_id)
        .await?;
    Ok(Json(sims))
}

// ---------------------------------------------------------------------------
// GET /ratelimit-sim/:id — get a single simulation result
// ---------------------------------------------------------------------------

pub async fn get_simulation(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<RateLimitSimulation>, GatewayError> {
    let sim = state
        .repo
        .get_rate_limit_simulation(&id)
        .await?
        .ok_or(GatewayError::NotFound(
            "rate limit simulation not found".into(),
        ))?;
    Ok(Json(sim))
}
