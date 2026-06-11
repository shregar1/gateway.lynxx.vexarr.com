use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::{ConsumerGroup, ConsumerGroupMember};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateConsumerGroupBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: i32,
    #[serde(default = "default_window")]
    pub rate_window_seconds: i32,
    #[serde(default)]
    pub burst_limit: i32,
}

fn default_rate_limit() -> i32 { 100 }
fn default_window() -> i32 { 60 }

#[derive(Deserialize)]
pub struct PatchConsumerGroupBody {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rate_limit: Option<i32>,
    pub rate_window_seconds: Option<i32>,
    pub burst_limit: Option<i32>,
}

#[derive(Deserialize)]
pub struct AddMemberBody {
    pub consumer_id: Uuid,
}

#[derive(Serialize)]
pub struct ConsumerGroupWithCount {
    #[serde(flatten)]
    pub group: ConsumerGroup,
    pub consumer_count: usize,
}

pub async fn list_consumer_groups(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<ConsumerGroupWithCount>>, GatewayError> {
    let groups = state.repo.list_consumer_groups(&service_id).await?;
    let mut result = Vec::new();
    for g in groups {
        let members = state.repo.list_consumer_group_members(&g.id).await?;
        result.push(ConsumerGroupWithCount {
            consumer_count: members.len(),
            group: g,
        });
    }
    Ok(Json(result))
}

pub async fn create_consumer_group(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<CreateConsumerGroupBody>,
) -> Result<(StatusCode, Json<ConsumerGroup>), GatewayError> {
    let now = Utc::now();
    let group = ConsumerGroup {
        id: Uuid::new_v4(),
        service_id,
        name: body.name,
        description: body.description,
        rate_limit: body.rate_limit,
        rate_window_seconds: body.rate_window_seconds,
        burst_limit: body.burst_limit,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_consumer_group(&group).await?;
    Ok((StatusCode::CREATED, Json(group)))
}

pub async fn patch_consumer_group(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchConsumerGroupBody>,
) -> Result<Json<ConsumerGroup>, GatewayError> {
    let mut group = state
        .repo
        .get_consumer_group(&id)
        .await?
        .ok_or(GatewayError::NotFound("consumer group not found".into()))?;

    if let Some(v) = body.name { group.name = v; }
    if let Some(v) = body.description { group.description = v; }
    if let Some(v) = body.rate_limit { group.rate_limit = v; }
    if let Some(v) = body.rate_window_seconds { group.rate_window_seconds = v; }
    if let Some(v) = body.burst_limit { group.burst_limit = v; }

    state.repo.update_consumer_group(&id, &group).await?;
    Ok(Json(group))
}

pub async fn delete_consumer_group(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_consumer_group(&id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("consumer group not found".into()))
    }
}

pub async fn list_members(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ConsumerGroupMember>>, GatewayError> {
    let members = state.repo.list_consumer_group_members(&id).await?;
    Ok(Json(members))
}

pub async fn add_member(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<AddMemberBody>,
) -> Result<(StatusCode, Json<ConsumerGroupMember>), GatewayError> {
    let member = ConsumerGroupMember {
        group_id: id,
        consumer_id: body.consumer_id,
        joined_at: Utc::now(),
    };
    state.repo.add_consumer_group_member(&member).await?;
    Ok((StatusCode::CREATED, Json(member)))
}

pub async fn remove_member(
    State(state): State<AdminState>,
    Path((group_id, consumer_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, GatewayError> {
    if state
        .repo
        .remove_consumer_group_member(&group_id, &consumer_id)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("member not found".into()))
    }
}

#[derive(Serialize)]
pub struct GroupUsage {
    pub group_id: Uuid,
    pub total_members: usize,
    pub rate_limit: i32,
    pub rate_window_seconds: i32,
    pub burst_limit: i32,
}

pub async fn group_usage(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupUsage>, GatewayError> {
    let group = state
        .repo
        .get_consumer_group(&id)
        .await?
        .ok_or(GatewayError::NotFound("consumer group not found".into()))?;

    let members = state.repo.list_consumer_group_members(&id).await?;

    Ok(Json(GroupUsage {
        group_id: id,
        total_members: members.len(),
        rate_limit: group.rate_limit,
        rate_window_seconds: group.rate_window_seconds,
        burst_limit: group.burst_limit,
    }))
}
