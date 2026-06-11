use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::ErrorPage;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateErrorPageBody {
    pub status_code: i32,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    pub body: String,
}

fn default_content_type() -> String { "text/html".into() }

#[derive(Deserialize)]
pub struct PatchErrorPageBody {
    pub status_code: Option<i32>,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn list_error_pages(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<ErrorPage>>, GatewayError> {
    let pages = state.repo.list_error_pages(&service_id).await?;
    Ok(Json(pages))
}

pub async fn create_error_page(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<CreateErrorPageBody>,
) -> Result<(StatusCode, Json<ErrorPage>), GatewayError> {
    let now = Utc::now();
    let page = ErrorPage {
        id: Uuid::new_v4(),
        service_id,
        status_code: body.status_code,
        content_type: body.content_type,
        body: body.body,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state.repo.create_error_page(&page).await?;
    Ok((StatusCode::CREATED, Json(page)))
}

pub async fn patch_error_page(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchErrorPageBody>,
) -> Result<Json<ErrorPage>, GatewayError> {
    let mut page = state
        .repo
        .get_error_page(&id)
        .await?
        .ok_or(GatewayError::NotFound("error page not found".into()))?;

    if let Some(v) = body.status_code { page.status_code = v; }
    if let Some(v) = body.content_type { page.content_type = v; }
    if let Some(v) = body.body { page.body = v; }
    if let Some(v) = body.enabled { page.enabled = v; }

    state.repo.update_error_page(&id, &page).await?;
    Ok(Json(page))
}

pub async fn delete_error_page(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_error_page(&id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("error page not found".into()))
    }
}
