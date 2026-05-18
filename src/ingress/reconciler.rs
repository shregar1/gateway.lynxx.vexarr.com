use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use kube::runtime::controller::Action;
use kube::ResourceExt;

use crate::crds::{LynxxPlugin, LynxxRoute, LynxxService};
use crate::gateway_client::GatewayClient;
use crate::state::ControllerState;

pub struct Ctx {
    pub client: GatewayClient,
    pub state: Arc<ControllerState>,
}

#[derive(thiserror::Error, Debug)]
pub enum ReconcileError {
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

fn key(ns: Option<String>, name: String) -> (String, String) {
    (ns.unwrap_or_else(|| "default".into()), name)
}

// ---------- LynxxService ----------

pub async fn reconcile_service(
    obj: Arc<LynxxService>,
    ctx: Arc<Ctx>,
) -> Result<Action, ReconcileError> {
    let name = obj.name_any();
    let ns = obj.namespace();
    let k = key(ns.clone(), name.clone());

    if obj.metadata.deletion_timestamp.is_some() {
        if let Some((_, id)) = ctx.state.svc_map.remove(&k) {
            ctx.client.delete_service(id).await?;
            tracing::info!(?k, %id, "deleted service");
        }
        return Ok(Action::await_change());
    }

    let id = ctx.client.upsert_service(&name, &obj.spec).await?;
    ctx.state.svc_map.insert(k.clone(), id);
    if !obj.spec.targets.is_empty() {
        ctx.client.upsert_targets(id, &obj.spec.targets).await?;
    }
    tracing::info!(?k, %id, "reconciled service");
    Ok(Action::requeue(Duration::from_secs(60)))
}

pub fn error_policy_service(
    _obj: Arc<LynxxService>,
    err: &ReconcileError,
    _ctx: Arc<Ctx>,
) -> Action {
    tracing::warn!(error = %err, "service reconcile error");
    Action::requeue(Duration::from_secs(10))
}

// ---------- LynxxRoute ----------

pub async fn reconcile_route(
    obj: Arc<LynxxRoute>,
    ctx: Arc<Ctx>,
) -> Result<Action, ReconcileError> {
    let name = obj.name_any();
    let ns = obj.namespace();
    let k = key(ns.clone(), name.clone());

    if obj.metadata.deletion_timestamp.is_some() {
        if let Some((_, id)) = ctx.state.route_map.remove(&k) {
            ctx.client.delete_route(id).await?;
            tracing::info!(?k, %id, "deleted route");
        }
        return Ok(Action::await_change());
    }

    let svc_key = (
        ns.clone().unwrap_or_else(|| "default".into()),
        obj.spec.service_ref.clone(),
    );
    let svc_id = match ctx.state.svc_map.get(&svc_key) {
        Some(v) => *v.value(),
        None => {
            tracing::warn!(?svc_key, "service ref not yet known; requeuing");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let existing = ctx.state.route_map.get(&k).map(|v| *v.value());
    let id = ctx.client.upsert_route(existing, svc_id, &obj.spec).await?;
    ctx.state.route_map.insert(k.clone(), id);
    tracing::info!(?k, %id, "reconciled route");
    Ok(Action::requeue(Duration::from_secs(60)))
}

pub fn error_policy_route(_obj: Arc<LynxxRoute>, err: &ReconcileError, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(error = %err, "route reconcile error");
    Action::requeue(Duration::from_secs(10))
}

// ---------- LynxxPlugin ----------

pub async fn reconcile_plugin(
    obj: Arc<LynxxPlugin>,
    ctx: Arc<Ctx>,
) -> Result<Action, ReconcileError> {
    let name = obj.name_any();
    let ns = obj.namespace();
    let k = key(ns.clone(), name.clone());

    if obj.metadata.deletion_timestamp.is_some() {
        if let Some((_, id)) = ctx.state.plugin_map.remove(&k) {
            ctx.client.delete_plugin(id).await?;
            tracing::info!(?k, %id, "deleted plugin");
        }
        return Ok(Action::await_change());
    }

    let scope = obj.spec.scope.as_str();
    let ns_str = ns.clone().unwrap_or_else(|| "default".into());
    let (svc_id, route_id) = match scope {
        "global" => (None, None),
        "service" => {
            let r = obj
                .spec
                .scope_ref
                .clone()
                .ok_or_else(|| anyhow!("plugin scope=service requires scopeRef"))?;
            let sk = (ns_str.clone(), r);
            let id = match ctx.state.svc_map.get(&sk) {
                Some(v) => *v.value(),
                None => {
                    tracing::warn!(?sk, "service ref not known; requeuing plugin");
                    return Ok(Action::requeue(Duration::from_secs(5)));
                }
            };
            (Some(id), None)
        }
        "route" => {
            let r = obj
                .spec
                .scope_ref
                .clone()
                .ok_or_else(|| anyhow!("plugin scope=route requires scopeRef"))?;
            let rk = (ns_str.clone(), r);
            let id = match ctx.state.route_map.get(&rk) {
                Some(v) => *v.value(),
                None => {
                    tracing::warn!(?rk, "route ref not known; requeuing plugin");
                    return Ok(Action::requeue(Duration::from_secs(5)));
                }
            };
            (None, Some(id))
        }
        other => {
            return Err(ReconcileError::Other(anyhow!(
                "invalid plugin scope: {other}"
            )))
        }
    };

    let existing = ctx.state.plugin_map.get(&k).map(|v| *v.value());
    let id = ctx
        .client
        .upsert_plugin(existing, &obj.spec, svc_id, route_id)
        .await?;
    ctx.state.plugin_map.insert(k.clone(), id);
    tracing::info!(?k, %id, "reconciled plugin");
    Ok(Action::requeue(Duration::from_secs(60)))
}

pub fn error_policy_plugin(_obj: Arc<LynxxPlugin>, err: &ReconcileError, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(error = %err, "plugin reconcile error");
    Action::requeue(Duration::from_secs(10))
}
