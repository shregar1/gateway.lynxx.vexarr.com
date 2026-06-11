use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use crate::models::Snapshot;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateSnapshotBody {
    pub name: String,
}

pub async fn list_snapshots(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<Vec<Snapshot>>, GatewayError> {
    let snaps = state.repo.list_snapshots(&service_id).await?;
    Ok(Json(snaps))
}

pub async fn create_snapshot(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(body): Json<CreateSnapshotBody>,
) -> Result<(StatusCode, Json<Snapshot>), GatewayError> {
    let svc = state
        .repo
        .get_service(&service_id)
        .await?
        .ok_or(GatewayError::NotFound("service not found".into()))?;

    let routes = state.repo.list_routes().await?;
    let svc_routes: Vec<_> = routes.into_iter().filter(|r| r.service_id == service_id).collect();

    let plugins = state.repo.list_plugins().await?;
    let svc_plugins: Vec<_> = plugins
        .into_iter()
        .filter(|p| p.service_id == Some(service_id) || svc_routes.iter().any(|r| p.route_id == Some(r.id)))
        .collect();

    let targets = state.repo.list_targets_for_service(&service_id).await?;

    let data = json!({
        "service": svc,
        "routes": svc_routes,
        "plugins": svc_plugins,
        "targets": targets,
    });

    let snap = Snapshot {
        id: Uuid::new_v4(),
        service_id,
        name: body.name,
        data,
        created_at: Utc::now(),
    };

    state.repo.create_snapshot(&snap).await?;
    Ok((StatusCode::CREATED, Json(snap)))
}

#[derive(Serialize)]
pub struct SnapshotDiff {
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
    pub changed: Vec<DiffChange>,
}

#[derive(Serialize)]
pub struct DiffEntry {
    pub entity_type: String,
    pub id: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct DiffChange {
    pub entity_type: String,
    pub id: String,
    pub changed_fields: Vec<String>,
}

pub async fn snapshot_diff(
    State(state): State<AdminState>,
    Path((service_id, snapshot_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<SnapshotDiff>, GatewayError> {
    let snap = state
        .repo
        .get_snapshot(&snapshot_id)
        .await?
        .ok_or(GatewayError::NotFound("snapshot not found".into()))?;

    let svc = state.repo.get_service(&service_id).await?;
    let routes = state.repo.list_routes().await?;
    let svc_routes: Vec<_> = routes.into_iter().filter(|r| r.service_id == service_id).collect();
    let plugins = state.repo.list_plugins().await?;
    let targets = state.repo.list_targets_for_service(&service_id).await?;

    let current = json!({
        "service": svc,
        "routes": svc_routes,
        "plugins": plugins.into_iter().filter(|p| p.service_id == Some(service_id)).collect::<Vec<_>>(),
        "targets": targets,
    });

    let diff = compute_diff(&snap.data, &current);
    Ok(Json(diff))
}

fn compute_diff(snapshot: &serde_json::Value, current: &serde_json::Value) -> SnapshotDiff {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for entity_type in &["routes", "plugins", "targets"] {
        let snap_arr = snapshot.get(entity_type).and_then(|v| v.as_array());
        let curr_arr = current.get(entity_type).and_then(|v| v.as_array());

        let snap_ids: std::collections::HashSet<String> = snap_arr
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let curr_ids: std::collections::HashSet<String> = curr_arr
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for id in curr_ids.difference(&snap_ids) {
            let name = curr_arr
                .and_then(|arr| arr.iter().find(|v| v.get("id").and_then(|i| i.as_str()) == Some(id)))
                .and_then(|v| v.get("name").and_then(|n| n.as_str()))
                .unwrap_or("")
                .to_string();
            added.push(DiffEntry {
                entity_type: entity_type.to_string(),
                id: id.clone(),
                name,
            });
        }

        for id in snap_ids.difference(&curr_ids) {
            let name = snap_arr
                .and_then(|arr| arr.iter().find(|v| v.get("id").and_then(|i| i.as_str()) == Some(id)))
                .and_then(|v| v.get("name").and_then(|n| n.as_str()))
                .unwrap_or("")
                .to_string();
            removed.push(DiffEntry {
                entity_type: entity_type.to_string(),
                id: id.clone(),
                name,
            });
        }

        for id in snap_ids.intersection(&curr_ids) {
            let snap_obj = snap_arr.and_then(|arr| {
                arr.iter().find(|v| v.get("id").and_then(|i| i.as_str()) == Some(id))
            });
            let curr_obj = curr_arr.and_then(|arr| {
                arr.iter().find(|v| v.get("id").and_then(|i| i.as_str()) == Some(id))
            });

            if let (Some(s), Some(c)) = (snap_obj, curr_obj) {
                let mut fields = Vec::new();
                if let (Some(so), Some(co)) = (s.as_object(), c.as_object()) {
                    for (k, sv) in so {
                        if k == "created_at" || k == "updated_at" {
                            continue;
                        }
                        if co.get(k) != Some(sv) {
                            fields.push(k.clone());
                        }
                    }
                }
                if !fields.is_empty() {
                    changed.push(DiffChange {
                        entity_type: entity_type.to_string(),
                        id: id.clone(),
                        changed_fields: fields,
                    });
                }
            }
        }
    }

    SnapshotDiff { added, removed, changed }
}

pub async fn rollback_snapshot(
    State(state): State<AdminState>,
    Path((_service_id, snapshot_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let snap = state
        .repo
        .get_snapshot(&snapshot_id)
        .await?
        .ok_or(GatewayError::NotFound("snapshot not found".into()))?;

    if let Some(svc_val) = snap.data.get("service") {
        if let Ok(svc) = serde_json::from_value::<crate::models::Service>(svc_val.clone()) {
            let _ = state.repo.update_service(&svc.id, &svc).await;
        }
    }

    if let Some(routes_arr) = snap.data.get("routes").and_then(|v| v.as_array()) {
        for rv in routes_arr {
            if let Ok(route) = serde_json::from_value::<crate::models::Route>(rv.clone()) {
                let _ = state.repo.update_route(&route.id, &route).await;
            }
        }
    }

    let _ = state.reload.trigger().await;

    Ok(Json(json!({ "status": "rolled_back", "snapshot_id": snapshot_id })))
}

pub async fn delete_snapshot(
    State(state): State<AdminState>,
    Path((_service_id, snapshot_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, GatewayError> {
    if state.repo.delete_snapshot(&snapshot_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(GatewayError::NotFound("snapshot not found".into()))
    }
}
