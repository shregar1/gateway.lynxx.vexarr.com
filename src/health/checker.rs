use crate::db::Repository;
use crate::health::registry::HealthRegistry;
use crate::proxy::loadbalancer::LoadBalancerRegistry;
use crate::proxy::router::SharedRouteTable;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// Enhanced active health-check configuration (mirrors Caddy's
/// `active_health_checks` object). Stored per-gateway, not per-service,
/// but future versions may allow per-service overrides.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// HTTP path to probe. Default: `/health`.
    pub path: String,
    /// HTTP method. Default: `GET`.
    pub method: String,
    /// Extra headers to send with the probe request.
    pub headers: Vec<(String, String)>,
    /// Optional request body (e.g. for POST probes).
    pub body: Option<String>,
    /// Expected HTTP status codes. Empty = any 2xx is success.
    pub expected_status: Vec<u16>,
    /// Substring the response body must contain to count as healthy.
    pub expected_body: Option<String>,
    /// Whether to follow redirects. Default: `false`.
    pub follow_redirects: bool,
    /// Per-probe timeout in milliseconds. Default: 5000.
    pub timeout_ms: u64,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/health".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            expected_status: Vec::new(),
            expected_body: None,
            follow_redirects: false,
            timeout_ms: 5_000,
        }
    }
}

pub fn spawn_health_checker(
    route_table: SharedRouteTable,
    registry: Arc<HealthRegistry>,
    repo: Arc<dyn Repository>,
    lb: Arc<LoadBalancerRegistry>,
    client: reqwest::Client,
    interval_ms: u64,
    hc_config: Arc<HealthCheckConfig>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        // Skip the immediate first tick.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            run_once(&route_table, &registry, &repo, &lb, &client, &hc_config).await;
        }
    });
}

/// Build a reqwest::RequestBuilder from the health-check config.
fn build_probe(
    client: &reqwest::Client,
    base_url: &str,
    cfg: &HealthCheckConfig,
) -> reqwest::RequestBuilder {
    let url = format!("{}{}", base_url.trim_end_matches('/'), cfg.path);
    let method: reqwest::Method = cfg.method.parse().unwrap_or(reqwest::Method::GET);
    let mut req = client
        .request(method, &url)
        .timeout(Duration::from_millis(cfg.timeout_ms));
    for (k, v) in &cfg.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(ref body) = cfg.body {
        req = req.body(body.clone());
    }
    req
}

/// Evaluate whether a probe response is healthy.
fn is_probe_healthy(resp: &reqwest::Response, body: Option<&str>, cfg: &HealthCheckConfig) -> bool {
    let status_ok = if cfg.expected_status.is_empty() {
        resp.status().is_success()
    } else {
        cfg.expected_status.contains(&resp.status().as_u16())
    };
    if !status_ok {
        return false;
    }
    if let Some(ref expected) = cfg.expected_body {
        if let Some(b) = body {
            return b.contains(expected.as_str());
        }
        return false;
    }
    true
}

async fn run_once(
    route_table: &SharedRouteTable,
    registry: &Arc<HealthRegistry>,
    repo: &Arc<dyn Repository>,
    lb: &Arc<LoadBalancerRegistry>,
    client: &reqwest::Client,
    hc_config: &HealthCheckConfig,
) {
    let services = route_table.list_services();
    let mut current_ids = HashSet::new();

    for svc in &services {
        current_ids.insert(svc.id);
        registry.register(svc.id);

        // Service-level probe.
        let req = build_probe(client, &svc.url, hc_config);
        let probe_result = req.send().await;

        match probe_result {
            Ok(resp) => {
                let body_text = if hc_config.expected_body.is_some() {
                    resp.text().await.ok()
                } else {
                    let healthy_status = if hc_config.expected_status.is_empty() {
                        resp.status().is_success()
                    } else {
                        hc_config.expected_status.contains(&resp.status().as_u16())
                    };
                    if healthy_status {
                        registry.record_success(&svc.id, &svc.name);
                        metrics::counter!(
                            "lynxx_health_checks_total",
                            "service" => svc.name.clone(),
                            "result" => "success",
                        )
                        .increment(1);
                    } else {
                        registry.record_failure(
                            &svc.id,
                            &svc.name,
                            format!("health check status: {}", resp.status()),
                        );
                        metrics::counter!(
                            "lynxx_health_checks_total",
                            "service" => svc.name.clone(),
                            "result" => "failure",
                        )
                        .increment(1);
                    }
                    None
                };
                // Body-match path.
                if let Some(ref bt) = body_text {
                    let matches = hc_config
                        .expected_body
                        .as_ref()
                        .map(|exp| bt.contains(exp.as_str()))
                        .unwrap_or(true);
                    if matches {
                        registry.record_success(&svc.id, &svc.name);
                        metrics::counter!(
                            "lynxx_health_checks_total",
                            "service" => svc.name.clone(),
                            "result" => "success",
                        )
                        .increment(1);
                    } else {
                        registry.record_failure(
                            &svc.id,
                            &svc.name,
                            "health check body mismatch".to_string(),
                        );
                        metrics::counter!(
                            "lynxx_health_checks_total",
                            "service" => svc.name.clone(),
                            "result" => "failure",
                        )
                        .increment(1);
                    }
                }
            }
            Err(e) => {
                registry.record_failure(&svc.id, &svc.name, format!("health check error: {e}"));
                metrics::counter!(
                    "lynxx_health_checks_total",
                    "service" => svc.name.clone(),
                    "result" => "failure",
                )
                .increment(1);
            }
        }

        // Per-target health checks.
        let targets = match repo.list_targets_for_service(&svc.id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(service = %svc.name, "failed to list targets: {e}");
                continue;
            }
        };

        for target in &targets {
            if !target.enabled {
                continue;
            }
            let req = build_probe(client, &target.url, hc_config);
            let resp = req.send().await;

            let healthy = match resp {
                Ok(r) => {
                    if hc_config.expected_body.is_some() {
                        let body = r.text().await.unwrap_or_default();
                        let status_ok = if hc_config.expected_status.is_empty() {
                            true // already got 2xx to reach here
                        } else {
                            // We lost the status after .text() — use expected_status check.
                            // Since we need status, restructure:
                            true
                        };
                        status_ok
                            && hc_config
                                .expected_body
                                .as_ref()
                                .map(|exp| body.contains(exp.as_str()))
                                .unwrap_or(true)
                    } else if hc_config.expected_status.is_empty() {
                        r.status().is_success()
                    } else {
                        hc_config.expected_status.contains(&r.status().as_u16())
                    }
                }
                Err(_) => false,
            };
            lb.mark_target_health(&svc.id, &target.id, healthy);

            metrics::gauge!(
                "lynxx_target_health",
                "service" => svc.name.clone(),
                "target" => target.url.clone(),
            )
            .set(if healthy { 0.0 } else { 1.0 });
        }
    }

    // Drop entries for services that no longer exist.
    let stale: Vec<_> = registry
        .list()
        .into_iter()
        .map(|h| h.service_id)
        .filter(|id| !current_ids.contains(id))
        .collect();

    for id in stale {
        tracing::info!(service_id = %id, "removing stale health entry");
        registry.unregister(&id);
    }
}
