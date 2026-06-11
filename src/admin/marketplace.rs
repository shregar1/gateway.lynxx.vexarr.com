use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::MarketplacePlugin;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// GET /marketplace/plugins — list all available marketplace plugins
// ---------------------------------------------------------------------------

pub async fn list_plugins(
    State(state): State<AdminState>,
) -> Result<Json<Vec<MarketplacePlugin>>, GatewayError> {
    let plugins = state.repo.list_marketplace_plugins().await?;
    Ok(Json(plugins))
}

// ---------------------------------------------------------------------------
// GET /marketplace/plugins/:id — get a single marketplace plugin
// ---------------------------------------------------------------------------

pub async fn get_plugin(
    State(state): State<AdminState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MarketplacePlugin>, GatewayError> {
    let plugin = state
        .repo
        .get_marketplace_plugin(&id)
        .await?
        .ok_or(GatewayError::NotFound("marketplace plugin not found".into()))?;
    Ok(Json(plugin))
}

// ---------------------------------------------------------------------------
// POST /marketplace/plugins/:id/install — install a marketplace plugin
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct InstallPluginBody {
    #[serde(default)]
    pub service_id: Option<Uuid>,
    #[serde(default)]
    pub route_id: Option<Uuid>,
    #[serde(default)]
    pub config: serde_json::Value,
}

pub async fn install_plugin(
    State(state): State<AdminState>,
    Path(plugin_id): Path<Uuid>,
    Json(body): Json<InstallPluginBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let mp = state
        .repo
        .get_marketplace_plugin(&plugin_id)
        .await?
        .ok_or(GatewayError::NotFound("marketplace plugin not found".into()))?;

    // Increment download count
    let mut updated = mp.clone();
    updated.downloads += 1;
    updated.updated_at = Utc::now();
    state
        .repo
        .update_marketplace_plugin(&plugin_id, &updated)
        .await?;

    // Create the actual plugin instance using the marketplace plugin's name
    let now = Utc::now();
    let instance = crate::models::PluginInstance {
        id: Uuid::new_v4(),
        name: mp.name.clone(),
        service_id: body.service_id,
        route_id: body.route_id,
        enabled: true,
        config: if body.config.is_null() {
            serde_json::json!({})
        } else {
            body.config
        },
        created_at: now,
        updated_at: now,
    };
    state.repo.create_plugin(&instance).await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "installed": true,
            "marketplace_plugin_id": plugin_id,
            "plugin_instance_id": instance.id,
            "name": mp.name,
        })),
    ))
}
