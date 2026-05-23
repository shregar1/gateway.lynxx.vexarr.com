use crate::admin::routes::AdminState;
use crate::error::GatewayError;
use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct DependencyGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Serialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: String,
    pub name: String,
    pub status: String,
    pub metadata: serde_json::Value,
}

#[derive(Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: String,
}

pub async fn service_graph(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<DependencyGraph>, GatewayError> {
    let svc = state
        .repo
        .get_service(&service_id)
        .await?
        .ok_or(GatewayError::NotFound("service not found".into()))?;

    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    let svc_node_id = format!("service:{}", svc.id);
    nodes.push(GraphNode {
        id: svc_node_id.clone(),
        node_type: "service".into(),
        name: svc.name.to_string(),
        status: "active".into(),
        metadata: serde_json::json!({
            "url": svc.url,
            "lb_strategy": svc.lb_strategy,
        }),
    });

    let routes = state.repo.list_routes().await?;
    let svc_routes: Vec<_> = routes
        .into_iter()
        .filter(|r| r.service_id == service_id)
        .collect();

    for route in &svc_routes {
        let route_node_id = format!("route:{}", route.id);
        nodes.push(GraphNode {
            id: route_node_id.clone(),
            node_type: "route".into(),
            name: route.paths.join(", "),
            status: "active".into(),
            metadata: serde_json::json!({
                "methods": route.methods,
                "hosts": route.hosts,
            }),
        });
        edges.push(GraphEdge {
            source: svc_node_id.clone(),
            target: route_node_id,
            edge_type: "has_route".into(),
        });
    }

    let plugins = state.repo.list_plugins().await?;
    for plugin in &plugins {
        let attached = plugin.service_id == Some(service_id)
            || plugin
                .route_id
                .map(|rid| svc_routes.iter().any(|r| r.id == rid))
                .unwrap_or(false);

        if !attached {
            continue;
        }

        let plugin_node_id = format!("plugin:{}", plugin.id);
        nodes.push(GraphNode {
            id: plugin_node_id.clone(),
            node_type: "plugin".into(),
            name: plugin.name.clone(),
            status: if plugin.enabled { "active" } else { "disabled" }.into(),
            metadata: serde_json::Value::Object(Default::default()),
        });

        if let Some(rid) = plugin.route_id {
            edges.push(GraphEdge {
                source: format!("route:{}", rid),
                target: plugin_node_id,
                edge_type: "has_plugin".into(),
            });
        } else {
            edges.push(GraphEdge {
                source: svc_node_id.clone(),
                target: plugin_node_id,
                edge_type: "has_plugin".into(),
            });
        }
    }

    let targets = state.repo.list_targets_for_service(&service_id).await?;
    for target in &targets {
        let health_status = state
            .health
            .get(&service_id)
            .map(|sh| match sh.status {
                crate::health::HealthStatus::Healthy => "healthy",
                _ => "unhealthy",
            })
            .unwrap_or("unknown");

        let target_node_id = format!("target:{}", target.id);
        nodes.push(GraphNode {
            id: target_node_id.clone(),
            node_type: "target".into(),
            name: target.url.to_string(),
            status: health_status.into(),
            metadata: serde_json::json!({
                "weight": target.weight,
                "enabled": target.enabled,
            }),
        });
        edges.push(GraphEdge {
            source: svc_node_id.clone(),
            target: target_node_id,
            edge_type: "has_target".into(),
        });
    }

    Ok(Json(DependencyGraph { nodes, edges }))
}
