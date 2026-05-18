use crate::admin::routes::AdminState;
use crate::cluster::ChangeEvent;
use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Target, TargetLifecycle};
use crate::proxy::loadbalancer::LoadBalancerRegistry;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployPhase {
    Pending,
    HealthChecking,
    Switching,
    DrainingOld,
    Complete,
    Failed,
}

#[derive(Debug)]
pub struct DeployState {
    pub service_id: Uuid,
    pub new_target_id: Uuid,
    pub old_target_ids: Vec<Uuid>,
    pub phase: std::sync::RwLock<DeployPhase>,
    pub health_checks_passed: AtomicU32,
    pub health_checks_required: u32,
    pub started_at: chrono::DateTime<Utc>,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
}

impl DeployState {
    fn phase(&self) -> DeployPhase {
        *self.phase.read().unwrap()
    }

    fn set_phase(&self, p: DeployPhase) {
        *self.phase.write().unwrap() = p;
    }
}

pub type DeployRegistry = Arc<DashMap<Uuid, Arc<DeployState>>>;

pub fn new_deploy_registry() -> DeployRegistry {
    Arc::new(DashMap::new())
}

#[derive(Deserialize)]
pub struct DeployRequest {
    pub new_target_url: String,
    #[serde(default = "default_health_path")]
    pub health_check_path: String,
    #[serde(default = "default_hc_interval")]
    pub health_check_interval_ms: u64,
    #[serde(default = "default_hc_timeout")]
    pub health_check_timeout_ms: u64,
    #[serde(default = "default_hc_threshold")]
    pub health_check_threshold: u32,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_ms: u64,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
}

fn default_health_path() -> String {
    "/health".to_string()
}
fn default_hc_interval() -> u64 {
    2000
}
fn default_hc_timeout() -> u64 {
    3000
}
fn default_hc_threshold() -> u32 {
    3
}
fn default_drain_timeout() -> u64 {
    30000
}
fn default_weight() -> u32 {
    100
}

#[derive(Serialize)]
pub struct DeployResponse {
    pub deploy_id: Uuid,
    pub service_id: Uuid,
    pub new_target_id: Uuid,
    pub state: DeployPhase,
    pub health_checks_required: u32,
}

#[derive(Serialize)]
pub struct DeployStatusResponse {
    pub service_id: Uuid,
    pub state: DeployPhase,
    pub new_target_id: Uuid,
    pub old_target_ids: Vec<Uuid>,
    pub health_checks_passed: u32,
    pub health_checks_required: u32,
    pub started_at: String,
}

pub async fn start_deploy(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
    Json(input): Json<DeployRequest>,
) -> Result<Json<DeployResponse>, GatewayError> {
    let _service = state
        .route_table
        .get_service(&service_id)
        .ok_or_else(|| GatewayError::NotFound(format!("service {service_id}")))?;

    let deploys = state
        .deploy_registry
        .as_ref()
        .ok_or_else(|| GatewayError::Internal("deploy registry not initialised".into()))?;

    if deploys.contains_key(&service_id) {
        let existing = deploys.get(&service_id).unwrap();
        let phase = existing.phase();
        if phase != DeployPhase::Complete && phase != DeployPhase::Failed {
            return Err(GatewayError::Conflict(format!(
                "service {service_id} already has a deploy in progress (phase: {phase:?})"
            )));
        }
        deploys.remove(&service_id);
    }

    let now = Utc::now();
    let mut new_target = Target::new(service_id, input.new_target_url.clone(), input.weight);
    new_target.state = TargetLifecycle::Inactive;
    state.repo.create_target(&new_target).await?;

    let old_target_ids: Vec<Uuid> = state
        .lb
        .snapshot(&service_id)
        .iter()
        .filter(|ts| ts.lifecycle() == TargetLifecycle::Active)
        .map(|ts| ts.target.id)
        .collect();

    let deploy = Arc::new(DeployState {
        service_id,
        new_target_id: new_target.id,
        old_target_ids: old_target_ids.clone(),
        phase: std::sync::RwLock::new(DeployPhase::HealthChecking),
        health_checks_passed: AtomicU32::new(0),
        health_checks_required: input.health_check_threshold,
        started_at: now,
        webhook_url: input.webhook_url.clone(),
        webhook_secret: input.webhook_secret.clone(),
    });

    deploys.insert(service_id, deploy.clone());

    tracing::info!(
        service_id = %service_id,
        new_target_id = %new_target.id,
        new_target_url = %input.new_target_url,
        threshold = input.health_check_threshold,
        "deploy started"
    );

    fire_webhook(&deploy, "deploy.health_checking").await;

    let repo = state.repo.clone();
    let lb = state.lb.clone();
    let bus = state.bus.clone();
    let node_id = state.node_id;
    let deploy_ref = deploy.clone();
    let health_path = input.health_check_path;
    let interval_ms = input.health_check_interval_ms;
    let timeout_ms = input.health_check_timeout_ms;
    let threshold = input.health_check_threshold;
    let drain_timeout_ms = input.drain_timeout_ms;
    let target_url = input.new_target_url;
    let new_tid = new_target.id;

    tokio::spawn(async move {
        run_deploy(
            deploy_ref,
            repo,
            lb,
            bus,
            node_id,
            service_id,
            new_tid,
            &target_url,
            &health_path,
            interval_ms,
            timeout_ms,
            threshold,
            drain_timeout_ms,
        )
        .await;
    });

    Ok(Json(DeployResponse {
        deploy_id: service_id,
        service_id,
        new_target_id: new_target.id,
        state: DeployPhase::HealthChecking,
        health_checks_required: input.health_check_threshold,
    }))
}

pub async fn deploy_status(
    State(state): State<AdminState>,
    Path(service_id): Path<Uuid>,
) -> Result<Json<DeployStatusResponse>, GatewayError> {
    let deploys = state
        .deploy_registry
        .as_ref()
        .ok_or_else(|| GatewayError::Internal("deploy registry not initialised".into()))?;

    let ds = deploys
        .get(&service_id)
        .ok_or_else(|| GatewayError::NotFound(format!("no deploy for service {service_id}")))?;

    Ok(Json(DeployStatusResponse {
        service_id: ds.service_id,
        state: ds.phase(),
        new_target_id: ds.new_target_id,
        old_target_ids: ds.old_target_ids.clone(),
        health_checks_passed: ds.health_checks_passed.load(Ordering::Relaxed),
        health_checks_required: ds.health_checks_required,
        started_at: ds.started_at.to_rfc3339(),
    }))
}

pub fn has_active_deploy(registry: &DeployRegistry, service_id: &Uuid) -> bool {
    if let Some(ds) = registry.get(service_id) {
        let phase = ds.phase();
        phase != DeployPhase::Complete && phase != DeployPhase::Failed
    } else {
        false
    }
}

async fn run_deploy(
    deploy: Arc<DeployState>,
    repo: Arc<dyn Repository>,
    lb: Arc<LoadBalancerRegistry>,
    bus: Arc<dyn crate::cluster::ClusterBus>,
    node_id: Uuid,
    service_id: Uuid,
    new_target_id: Uuid,
    target_url: &str,
    health_path: &str,
    interval_ms: u64,
    timeout_ms: u64,
    threshold: u32,
    drain_timeout_ms: u64,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .unwrap_or_default();

    let probe_url = format!("{}{}", target_url.trim_end_matches('/'), health_path);

    let max_wait = Duration::from_millis(interval_ms * threshold as u64 * 2);
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut consecutive = 0u32;

    loop {
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;

        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                service_id = %service_id,
                new_target_id = %new_target_id,
                "deploy health check deadline exceeded — rolling back"
            );
            deploy.set_phase(DeployPhase::Failed);
            let _ = repo.delete_target(&new_target_id).await;
            rebuild_lb_for(&repo, &lb, service_id).await;
            fire_webhook(&deploy, "deploy.failed").await;
            return;
        }

        let healthy = match client.get(&probe_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        };

        if healthy {
            consecutive += 1;
            deploy
                .health_checks_passed
                .store(consecutive, Ordering::Relaxed);
            tracing::info!(
                service_id = %service_id,
                pass = consecutive,
                required = threshold,
                "deploy health check passed"
            );
            if consecutive >= threshold {
                break;
            }
        } else {
            if consecutive > 0 {
                tracing::info!(
                    service_id = %service_id,
                    "deploy health check failed — resetting counter"
                );
            }
            consecutive = 0;
            deploy.health_checks_passed.store(0, Ordering::Relaxed);
        }
    }

    // Health checks passed — switch traffic.
    deploy.set_phase(DeployPhase::Switching);
    fire_webhook(&deploy, "deploy.switching").await;

    let _ = repo.update_target_state(&new_target_id, "active").await;
    lb.set_target_lifecycle(&service_id, &new_target_id, TargetLifecycle::Active);
    rebuild_lb_for(&repo, &lb, service_id).await;

    tracing::info!(
        service_id = %service_id,
        new_target_id = %new_target_id,
        "new target activated — draining old targets"
    );

    // Drain old targets.
    deploy.set_phase(DeployPhase::DrainingOld);
    fire_webhook(&deploy, "deploy.draining_old").await;

    for old_id in &deploy.old_target_ids {
        let _ = repo.update_target_state(old_id, "draining").await;
        lb.drain_target(&service_id, old_id, drain_timeout_ms);
    }

    // Wait for drains to complete.
    let drain_deadline =
        tokio::time::Instant::now() + Duration::from_millis(drain_timeout_ms + 1000);
    loop {
        let all_done = deploy.old_target_ids.iter().all(|oid| {
            let snap = lb.snapshot(&service_id);
            snap.iter()
                .find(|s| s.target.id == *oid)
                .map(|s| s.lifecycle() == TargetLifecycle::Inactive)
                .unwrap_or(true)
        });
        if all_done || tokio::time::Instant::now() >= drain_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Clean up old targets from DB.
    for old_id in &deploy.old_target_ids {
        let _ = repo.delete_target(old_id).await;
    }
    rebuild_lb_for(&repo, &lb, service_id).await;

    deploy.set_phase(DeployPhase::Complete);

    let duration_ms = (Utc::now() - deploy.started_at).num_milliseconds().max(0) as u64;
    tracing::info!(
        service_id = %service_id,
        duration_ms,
        "deploy complete"
    );

    fire_webhook(&deploy, "deploy.complete").await;

    let _ = bus
        .publish(ChangeEvent::TargetChanged {
            service_id,
            origin: node_id,
        })
        .await;
}

async fn rebuild_lb_for(
    repo: &Arc<dyn Repository>,
    lb: &Arc<LoadBalancerRegistry>,
    service_id: Uuid,
) {
    if let Ok(targets) = repo.list_targets_for_service(&service_id).await {
        let active: Vec<_> = targets
            .into_iter()
            .filter(|t| t.state == TargetLifecycle::Active)
            .collect();
        lb.rebuild_for_service(
            service_id,
            crate::proxy::loadbalancer::LbStrategy::RoundRobin,
            active,
        );
    }
}

async fn fire_webhook(deploy: &DeployState, event: &str) {
    let Some(ref url) = deploy.webhook_url else {
        return;
    };

    let payload = serde_json::json!({
        "event": event,
        "service_id": deploy.service_id,
        "new_target_id": deploy.new_target_id,
        "old_target_ids": deploy.old_target_ids,
        "timestamp": Utc::now().to_rfc3339(),
        "deploy_duration_ms": (Utc::now() - deploy.started_at).num_milliseconds().max(0),
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let mut req = client.post(url).json(&payload);

    if let Some(ref secret) = deploy.webhook_secret {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let body = serde_json::to_string(&payload).unwrap_or_default();
        if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
            mac.update(body.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            req = req.header("X-Lynxx-Signature", sig);
        }
    }

    if let Err(e) = req.send().await {
        tracing::warn!(
            event,
            error = %e,
            "deploy webhook delivery failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_deploy(phase: DeployPhase) -> Arc<DeployState> {
        Arc::new(DeployState {
            service_id: Uuid::new_v4(),
            new_target_id: Uuid::new_v4(),
            old_target_ids: vec![Uuid::new_v4()],
            phase: std::sync::RwLock::new(phase),
            health_checks_passed: AtomicU32::new(0),
            health_checks_required: 3,
            started_at: Utc::now(),
            webhook_url: None,
            webhook_secret: None,
        })
    }

    #[test]
    fn deploy_phase_transitions() {
        let ds = make_deploy(DeployPhase::Pending);
        assert_eq!(ds.phase(), DeployPhase::Pending);

        ds.set_phase(DeployPhase::HealthChecking);
        assert_eq!(ds.phase(), DeployPhase::HealthChecking);

        ds.set_phase(DeployPhase::Switching);
        assert_eq!(ds.phase(), DeployPhase::Switching);

        ds.set_phase(DeployPhase::DrainingOld);
        assert_eq!(ds.phase(), DeployPhase::DrainingOld);

        ds.set_phase(DeployPhase::Complete);
        assert_eq!(ds.phase(), DeployPhase::Complete);
    }

    #[test]
    fn deploy_phase_failed() {
        let ds = make_deploy(DeployPhase::HealthChecking);
        ds.set_phase(DeployPhase::Failed);
        assert_eq!(ds.phase(), DeployPhase::Failed);
    }

    #[test]
    fn health_check_counter_atomic() {
        let ds = make_deploy(DeployPhase::HealthChecking);
        assert_eq!(ds.health_checks_passed.load(Ordering::Relaxed), 0);

        ds.health_checks_passed.store(1, Ordering::Relaxed);
        assert_eq!(ds.health_checks_passed.load(Ordering::Relaxed), 1);

        ds.health_checks_passed.store(3, Ordering::Relaxed);
        assert_eq!(ds.health_checks_passed.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn has_active_deploy_true_for_in_progress() {
        let reg = new_deploy_registry();
        let ds = make_deploy(DeployPhase::HealthChecking);
        let svc_id = ds.service_id;
        reg.insert(svc_id, ds);

        assert!(has_active_deploy(&reg, &svc_id));
    }

    #[test]
    fn has_active_deploy_false_for_complete() {
        let reg = new_deploy_registry();
        let ds = make_deploy(DeployPhase::Complete);
        let svc_id = ds.service_id;
        reg.insert(svc_id, ds);

        assert!(!has_active_deploy(&reg, &svc_id));
    }

    #[test]
    fn has_active_deploy_false_for_failed() {
        let reg = new_deploy_registry();
        let ds = make_deploy(DeployPhase::Failed);
        let svc_id = ds.service_id;
        reg.insert(svc_id, ds);

        assert!(!has_active_deploy(&reg, &svc_id));
    }

    #[test]
    fn has_active_deploy_false_for_unknown_service() {
        let reg = new_deploy_registry();
        assert!(!has_active_deploy(&reg, &Uuid::new_v4()));
    }

    #[test]
    fn registry_prevents_concurrent_active_deploys() {
        let reg = new_deploy_registry();
        let svc_id = Uuid::new_v4();
        let ds = Arc::new(DeployState {
            service_id: svc_id,
            new_target_id: Uuid::new_v4(),
            old_target_ids: vec![],
            phase: std::sync::RwLock::new(DeployPhase::Switching),
            health_checks_passed: AtomicU32::new(0),
            health_checks_required: 3,
            started_at: Utc::now(),
            webhook_url: None,
            webhook_secret: None,
        });
        reg.insert(svc_id, ds);

        assert!(has_active_deploy(&reg, &svc_id));
        assert!(reg.contains_key(&svc_id));
    }
}
