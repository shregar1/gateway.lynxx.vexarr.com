use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::{AlertEvent, AlertRule};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateAlertRuleBody {
    pub name: String,
    pub metric: String,
    #[serde(default = "default_operator")]
    pub operator: String,
    pub threshold: f64,
    #[serde(default = "default_window")]
    pub window_seconds: i32,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: i32,
    #[serde(default)]
    pub channels: serde_json::Value,
}

fn default_operator() -> String { "gt".into() }
fn default_window() -> i32 { 300 }
fn default_cooldown() -> i32 { 600 }

#[derive(Deserialize)]
pub struct PatchAlertRuleBody {
    pub name: Option<String>,
    pub metric: Option<String>,
    pub operator: Option<String>,
    pub threshold: Option<f64>,
    pub window_seconds: Option<i32>,
    pub cooldown_seconds: Option<i32>,
    pub channels: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

pub async fn list_alert_rules(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<AlertRule>>, GatewayError> {
    let rules = state.repo.list_alert_rules(&service_id).await?;
    Ok(Json(rules))
}

pub async fn create_alert_rule(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<CreateAlertRuleBody>,
) -> Result<(StatusCode, Json<AlertRule>), GatewayError> {
    let now = Utc::now();
    let rule = AlertRule {
        id: Uuid::new_v4(),
        service_id,
        name: body.name,
        metric: body.metric,
        operator: body.operator,
        threshold: body.threshold,
        window_seconds: body.window_seconds,
        cooldown_seconds: body.cooldown_seconds,
        channels: if body.channels.is_null() {
            serde_json::Value::Array(vec![])
        } else {
            body.channels
        },
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_alert_rule(&rule).await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn patch_alert_rule(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchAlertRuleBody>,
) -> Result<Json<AlertRule>, GatewayError> {
    let mut rule = state
        .repo
        .get_alert_rule(&id)
        .await?
        .ok_or(GatewayError::NotFound("alert rule not found".into()))?;

    if let Some(v) = body.name { rule.name = v; }
    if let Some(v) = body.metric { rule.metric = v; }
    if let Some(v) = body.operator { rule.operator = v; }
    if let Some(v) = body.threshold { rule.threshold = v; }
    if let Some(v) = body.window_seconds { rule.window_seconds = v; }
    if let Some(v) = body.cooldown_seconds { rule.cooldown_seconds = v; }
    if let Some(v) = body.channels { rule.channels = v; }
    if let Some(v) = body.enabled { rule.enabled = v; }

    state.repo.update_alert_rule(&id, &rule).await?;
    Ok(Json(rule))
}

pub async fn delete_alert_rule(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_alert_rule(&id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("alert rule not found".into()))
    }
}

pub async fn list_alert_events(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<AlertEvent>>, GatewayError> {
    let events = state.repo.list_alert_events(&service_id, 100).await?;
    Ok(Json(events))
}

pub async fn resolve_alert_event(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    if state.repo.resolve_alert_event(&id).await? {
        Ok(Json(serde_json::json!({ "resolved": true })))
    } else {
        Err(GatewayError::NotFound("alert event not found or already resolved".into()))
    }
}

pub async fn test_alert(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rule = state
        .repo
        .get_alert_rule(&id)
        .await?
        .ok_or(GatewayError::NotFound("alert rule not found".into()))?;

    let now = Utc::now();
    let event = AlertEvent {
        id: Uuid::new_v4(),
        rule_id: rule.id,
        service_id: rule.service_id,
        ts: now,
        metric: rule.metric.clone(),
        value: rule.threshold + 1.0,
        threshold: rule.threshold,
        message: format!("[TEST] Alert '{}' triggered", rule.name),
        resolved: false,
        resolved_at: None,
    };
    state.repo.create_alert_event(&event).await?;

    Ok(Json(serde_json::json!({
        "test": true,
        "event_id": event.id,
        "message": event.message,
    })))
}
