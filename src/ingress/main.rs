//! lynxx-ingress: a Kubernetes controller that reconciles LynxxService /
//! LynxxRoute / LynxxPlugin custom resources into the lynxx-gateway admin API.

mod crds;
mod gateway_client;
mod reconciler;
mod state;

use std::sync::Arc;

use anyhow::Result;
use futures_util::StreamExt;
use kube::{
    api::Api,
    runtime::{watcher, Controller},
    Client, CustomResourceExt,
};

use crate::crds::{LynxxPlugin, LynxxRoute, LynxxService};
use crate::gateway_client::GatewayClient;
use crate::reconciler::{
    error_policy_plugin, error_policy_route, error_policy_service, reconcile_plugin,
    reconcile_route, reconcile_service, Ctx,
};
use crate::state::ControllerState;

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    if let Some(a) = args.next() {
        if a == "--print-crds" {
            // serde_yaml is provided transitively via kube? fallback: serialize via serde_json then manual.
            // We did not add serde_yaml as a dep; emit JSON-as-YAML via serde_json + a tiny conversion.
            let crds = [
                serde_json::to_value(LynxxService::crd())?,
                serde_json::to_value(LynxxRoute::crd())?,
                serde_json::to_value(LynxxPlugin::crd())?,
            ];
            for (i, c) in crds.iter().enumerate() {
                if i > 0 {
                    println!("---");
                }
                // crude JSON->YAML: print pretty JSON. kubectl accepts JSON manifests.
                println!("{}", serde_json::to_string_pretty(c)?);
            }
            return Ok(());
        }
    }

    let admin_url =
        std::env::var("LYNXX_ADMIN_URL").unwrap_or_else(|_| "http://localhost:28081".to_string());
    let namespace = std::env::var("KUBE_NAMESPACE").ok();

    tracing::info!(%admin_url, ?namespace, "starting lynxx-ingress controller");

    let kube = Client::try_default().await?;
    let state = ControllerState::new();
    let ctx = Arc::new(Ctx {
        client: GatewayClient::new(admin_url),
        state: state.clone(),
    });

    let svc_api: Api<LynxxService> = match namespace.as_deref() {
        Some(ns) => Api::namespaced(kube.clone(), ns),
        None => Api::all(kube.clone()),
    };
    let route_api: Api<LynxxRoute> = match namespace.as_deref() {
        Some(ns) => Api::namespaced(kube.clone(), ns),
        None => Api::all(kube.clone()),
    };
    let plugin_api: Api<LynxxPlugin> = match namespace.as_deref() {
        Some(ns) => Api::namespaced(kube.clone(), ns),
        None => Api::all(kube.clone()),
    };

    let svc_ctx = ctx.clone();
    let svc_ctrl = Controller::new(svc_api, watcher::Config::default())
        .run(reconcile_service, error_policy_service, svc_ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::debug!(?o, "service reconciled"),
                Err(e) => tracing::warn!(error = %e, "service controller err"),
            }
        });

    let route_ctx = ctx.clone();
    let route_ctrl = Controller::new(route_api, watcher::Config::default())
        .run(reconcile_route, error_policy_route, route_ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::debug!(?o, "route reconciled"),
                Err(e) => tracing::warn!(error = %e, "route controller err"),
            }
        });

    let plugin_ctx = ctx.clone();
    let plugin_ctrl = Controller::new(plugin_api, watcher::Config::default())
        .run(reconcile_plugin, error_policy_plugin, plugin_ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::debug!(?o, "plugin reconciled"),
                Err(e) => tracing::warn!(error = %e, "plugin controller err"),
            }
        });

    tokio::join!(svc_ctrl, route_ctrl, plugin_ctrl);
    Ok(())
}
