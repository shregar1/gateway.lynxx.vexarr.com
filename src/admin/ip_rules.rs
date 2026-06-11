use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::IpRule;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateIpRuleBody {
    pub cidr: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub route_id: Option<Uuid>,
}

fn default_action() -> String { "deny".into() }

#[derive(Deserialize)]
pub struct PatchIpRuleBody {
    pub cidr: Option<String>,
    pub action: Option<String>,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct BulkIpRulesBody {
    pub rules: Vec<CreateIpRuleBody>,
}

pub async fn list_ip_rules(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<IpRule>>, GatewayError> {
    let rules = state.repo.list_ip_rules(&service_id).await?;
    Ok(Json(rules))
}

pub async fn create_ip_rule(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<CreateIpRuleBody>,
) -> Result<(StatusCode, Json<IpRule>), GatewayError> {
    let now = Utc::now();
    let rule = IpRule {
        id: Uuid::new_v4(),
        service_id,
        route_id: body.route_id,
        cidr: body.cidr,
        action: body.action,
        description: body.description,
        priority: body.priority,
        enabled: true,
        hits: 0,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_ip_rule(&rule).await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn patch_ip_rule(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchIpRuleBody>,
) -> Result<Json<IpRule>, GatewayError> {
    let mut rule = state
        .repo
        .get_ip_rule(&id)
        .await?
        .ok_or(GatewayError::NotFound("ip rule not found".into()))?;

    if let Some(v) = body.cidr { rule.cidr = v; }
    if let Some(v) = body.action { rule.action = v; }
    if let Some(v) = body.description { rule.description = v; }
    if let Some(v) = body.priority { rule.priority = v; }
    if let Some(v) = body.enabled { rule.enabled = v; }

    state.repo.update_ip_rule(&id, &rule).await?;
    Ok(Json(rule))
}

pub async fn delete_ip_rule(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_ip_rule(&id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("ip rule not found".into()))
    }
}

pub async fn bulk_create_ip_rules(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<BulkIpRulesBody>,
) -> Result<(StatusCode, Json<Vec<IpRule>>), GatewayError> {
    let now = Utc::now();
    let mut created = Vec::new();

    for input in body.rules {
        let rule = IpRule {
            id: Uuid::new_v4(),
            service_id,
            route_id: input.route_id,
            cidr: input.cidr,
            action: input.action,
            description: input.description,
            priority: input.priority,
            enabled: true,
            hits: 0,
            created_at: now,
            updated_at: now,
        };
        state.repo.create_ip_rule(&rule).await?;
        created.push(rule);
    }

    Ok((StatusCode::CREATED, Json(created)))
}
