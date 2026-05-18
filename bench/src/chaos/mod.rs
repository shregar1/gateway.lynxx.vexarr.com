//! Chaos / soak / battle-test scenarios for the Lynxx gateway.
//!
//! Each scenario is a small async function with the signature
//! `async fn run(client: &AdminClient, args: &Args) -> anyhow::Result<Report>`.
//! The orchestrator binary (`bin/lynxx-chaos.rs`) wires them up to a clap CLI.
//!
//! The `AdminClient` here is a thin reqwest wrapper covering only the admin
//! API surface chaos needs (services, routes, plugins, health, status). It
//! intentionally does not try to be a full SDK — extending it for a new
//! scenario is fine and expected.

pub mod burst;
pub mod churn;
pub mod extreme;
pub mod malformed;
pub mod memory;
pub mod methods;
pub mod mixed_bodies;
pub mod pg_restart;
pub mod plugin_chain;
pub mod slowloris;
pub mod ws_flood;

use anyhow::{anyhow, Context, Result};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// Common per-scenario knobs. Individual scenarios pick the fields they need;
/// scenarios that want their own knobs can take them via clap subcommand args
/// and merge with this in `lynxx-chaos.rs`.
#[derive(Debug, Clone)]
pub struct Args {
    /// Proxy listener (where data-plane traffic goes), e.g. `http://127.0.0.1:28080`.
    pub proxy_url: String,
    /// Admin API base, e.g. `http://127.0.0.1:28081`.
    pub admin_url: String,
    /// Optional admin token for the `Authorization: Bearer ...` header.
    pub admin_token: Option<String>,
    /// Mock upstream URL the chaos scenarios point services at when they need
    /// a controllable backend (e.g. `http://127.0.0.1:19090`).
    pub mock_upstream_url: String,
    /// Postgres docker container name, used by `pg_restart` only.
    pub pg_container: Option<String>,
    /// Per-scenario duration override. `None` means use the scenario's default.
    pub duration: Option<Duration>,
    /// Per-scenario RPS override. `None` means use the scenario's default.
    pub rps: Option<u64>,
    /// Suppress per-request errors in logs; used by `all` to keep output tidy.
    pub quiet: bool,
}

impl Args {
    pub fn duration_or(&self, default: Duration) -> Duration {
        self.duration.unwrap_or(default)
    }

    pub fn rps_or(&self, default: u64) -> u64 {
        self.rps.unwrap_or(default)
    }
}

/// Result of a scenario run. The orchestrator turns a vec of these into the
/// final summary table.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub scenario: String,
    pub passed: bool,
    pub summary: String,
    pub details: Vec<String>,
}

impl Report {
    pub fn pass(scenario: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            scenario: scenario.into(),
            passed: true,
            summary: summary.into(),
            details: Vec::new(),
        }
    }

    pub fn fail(scenario: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            scenario: scenario.into(),
            passed: false,
            summary: summary.into(),
            details: Vec::new(),
        }
    }

    pub fn detail(mut self, line: impl Into<String>) -> Self {
        self.details.push(line.into());
        self
    }
}

// -- Admin client ------------------------------------------------------------

/// Thin admin-API wrapper. Most methods return the new resource id so
/// scenarios can clean up after themselves.
#[derive(Clone)]
pub struct AdminClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceView {
    pub id: Uuid,
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteView {
    pub id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginView {
    pub id: Uuid,
    #[serde(default)]
    pub name: String,
    pub service_id: Option<Uuid>,
    pub route_id: Option<Uuid>,
    pub enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthEntry {
    pub service_id: Uuid,
    pub circuit: String,
    #[allow(dead_code)]
    pub status: Option<String>,
}

impl AdminClient {
    pub fn new(base: impl Into<String>, token: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("building admin reqwest client")?;
        Ok(Self {
            http,
            base: base.into(),
            token,
        })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base.trim_end_matches('/'), path);
        let mut rb = self.http.request(method, url);
        if let Some(t) = &self.token {
            rb = rb.bearer_auth(t);
        }
        rb
    }

    /// Cheap liveness check — used at the top of every scenario to fail fast
    /// if the gateway isn't running.
    pub async fn ping(&self) -> Result<()> {
        let resp = self.req(reqwest::Method::GET, "/status").send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("admin /status returned {}", resp.status()));
        }
        Ok(())
    }

    pub async fn create_service(
        &self,
        name: &str,
        url: &str,
        retries: u32,
        timeout_ms: u64,
    ) -> Result<Uuid> {
        self.create_service_lb(name, url, retries, timeout_ms, "round-robin")
            .await
    }

    /// Like `create_service` but lets you specify the LB strategy explicitly.
    pub async fn create_service_lb(
        &self,
        name: &str,
        url: &str,
        retries: u32,
        timeout_ms: u64,
        lb_strategy: &str,
    ) -> Result<Uuid> {
        let body = serde_json::json!({
            "name": name,
            "url": url,
            "retries": retries,
            "connect_timeout_ms": timeout_ms,
            "lb_strategy": lb_strategy,
        });
        let resp = self
            .req(reqwest::Method::POST, "/services")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("create_service {name} -> {status}: {txt}"));
        }
        let svc: ServiceView = resp.json().await?;
        Ok(svc.id)
    }

    /// Add a weighted upstream target to a service.
    pub async fn create_target(&self, service_id: Uuid, url: &str, weight: u32) -> Result<Uuid> {
        #[derive(Deserialize)]
        struct TargetView {
            id: Uuid,
        }
        let body = serde_json::json!({ "url": url, "weight": weight, "enabled": true });
        let resp = self
            .req(
                reqwest::Method::POST,
                &format!("/services/{service_id}/targets"),
            )
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("create_target {url} -> {status}: {txt}"));
        }
        let t: TargetView = resp.json().await?;
        Ok(t.id)
    }

    /// Convenience: attach a plugin to a service, silently skip on failure.
    pub async fn create_plugin_for_service(
        &self,
        service_id: Uuid,
        name: &str,
        config: serde_json::Value,
    ) {
        if let Err(e) = self
            .install_plugin(name, config, Some(service_id), None)
            .await
        {
            tracing::warn!(plugin = name, error = %e, "install_plugin failed (continuing)");
        }
    }

    pub async fn create_route(
        &self,
        service_id: Uuid,
        paths: &[&str],
        methods: &[&str],
        strip_path: bool,
    ) -> Result<Uuid> {
        let body = serde_json::json!({
            "service_id": service_id,
            "paths": paths,
            "methods": methods,
            "strip_path": strip_path,
        });
        let resp = self
            .req(reqwest::Method::POST, "/routes")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("create_route -> {status}: {txt}"));
        }
        let route: RouteView = resp.json().await?;
        Ok(route.id)
    }

    pub async fn install_plugin(
        &self,
        name: &str,
        config: serde_json::Value,
        service_id: Option<Uuid>,
        route_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let mut body = serde_json::json!({
            "name": name,
            "config": config,
            "enabled": true,
        });
        if let Some(sid) = service_id {
            body["service_id"] = serde_json::json!(sid);
        }
        if let Some(rid) = route_id {
            body["route_id"] = serde_json::json!(rid);
        }
        let resp = self
            .req(reqwest::Method::POST, "/plugins")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("install_plugin {name} -> {status}: {txt}"));
        }
        let p: PluginView = resp.json().await?;
        Ok(p.id)
    }

    pub async fn delete_service(&self, id: Uuid) -> Result<()> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/services/{id}"))
            .send()
            .await?;
        if !resp.status().is_success() && resp.status().as_u16() != 404 {
            return Err(anyhow!("delete_service {id} -> {}", resp.status()));
        }
        Ok(())
    }

    pub async fn delete_route(&self, id: Uuid) -> Result<()> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/routes/{id}"))
            .send()
            .await?;
        if !resp.status().is_success() && resp.status().as_u16() != 404 {
            return Err(anyhow!("delete_route {id} -> {}", resp.status()));
        }
        Ok(())
    }

    pub async fn list_plugins(&self) -> Result<Vec<PluginView>> {
        let resp = self.req(reqwest::Method::GET, "/plugins").send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("/plugins -> {}", resp.status()));
        }
        Ok(resp.json().await?)
    }

    pub async fn set_plugin_enabled(&self, id: Uuid, enabled: bool) -> Result<()> {
        // GET the current state, then PUT back with only enabled changed.
        let get_resp = self
            .req(reqwest::Method::GET, &format!("/plugins/{id}"))
            .send()
            .await?;
        if !get_resp.status().is_success() {
            return Err(anyhow!("get plugin {id} -> {}", get_resp.status()));
        }
        let mut p: PluginView = get_resp.json().await?;
        p.enabled = enabled;
        let body = serde_json::json!({
            "name": p.name,
            "enabled": p.enabled,
            "config": p.config,
            "service_id": p.service_id,
            "route_id": p.route_id,
        });
        let resp = self
            .req(reqwest::Method::PUT, &format!("/plugins/{id}"))
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("set_plugin_enabled {id} -> {status}: {txt}"));
        }
        Ok(())
    }

    pub async fn delete_plugin(&self, id: Uuid) -> Result<()> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/plugins/{id}"))
            .send()
            .await?;
        if !resp.status().is_success() && resp.status().as_u16() != 404 {
            return Err(anyhow!("delete_plugin {id} -> {}", resp.status()));
        }
        Ok(())
    }

    /// Disable all global (no service/route scope) rate-limit plugins and
    /// return their IDs. Call `restore_plugins` with the returned IDs when done.
    /// Used by high-RPS chaos scenarios to avoid false 429 failures.
    pub async fn disable_global_ratelimit(&self) -> Vec<Uuid> {
        let ids: Vec<Uuid> = self
            .list_plugins()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|p| {
                p.name == "rate-limit"
                    && p.service_id.is_none()
                    && p.route_id.is_none()
                    && p.enabled
            })
            .map(|p| p.id)
            .collect();
        for &id in &ids {
            if let Err(e) = self.set_plugin_enabled(id, false).await {
                tracing::warn!(%id, error = %e, "failed to disable global rate-limit plugin");
            } else {
                tracing::info!(%id, "disabled global rate-limit plugin");
            }
        }
        ids
    }

    /// Re-enable plugins disabled by `disable_global_ratelimit`.
    pub async fn restore_plugins(&self, ids: &[Uuid]) {
        for &id in ids {
            if let Err(e) = self.set_plugin_enabled(id, true).await {
                tracing::warn!(%id, error = %e, "failed to re-enable plugin");
            } else {
                tracing::info!(%id, "re-enabled plugin");
            }
        }
    }

    pub async fn health(&self) -> Result<Vec<HealthEntry>> {
        let resp = self.req(reqwest::Method::GET, "/health").send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("/health -> {}", resp.status()));
        }
        // Health entries come from the gateway as ServiceHealth structs which
        // serialize the circuit field as the enum variant name. We only need
        // the discriminant so deserialize loosely.
        let raw: serde_json::Value = resp.json().await?;
        let mut out = Vec::new();
        if let Some(arr) = raw.as_array() {
            for v in arr {
                let id = v
                    .get("service_id")
                    .and_then(|x| x.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok());
                let circuit = v
                    .get("circuit")
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string());
                let status = v
                    .get("status")
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string());
                if let (Some(id), Some(circuit)) = (id, circuit) {
                    out.push(HealthEntry {
                        service_id: id,
                        circuit,
                        status,
                    });
                }
            }
        }
        Ok(out)
    }
}

// -- Latency histogram helpers ----------------------------------------------

pub fn new_hist() -> Histogram<u64> {
    Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
        .expect("histogram bounds are valid at compile time")
}

pub fn fmt_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}us")
    }
}

pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Find the gateway PID by binary name. Returns None if not found.
/// Used by `memory` and `malformed` for RSS sampling.
pub fn find_gateway_pid() -> Option<u32> {
    let out = std::process::Command::new("pgrep")
        .args(["-f", "lynxx-gateway"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // pgrep can return multiple PIDs (one per match including itself in some
    // shells); pick the first numeric line that isn't our own pid.
    let me = std::process::id();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .find(|p| *p != me)
}

/// RSS in KB for the given pid via `ps -o rss=`. Returns None if ps fails or
/// the process has gone away.
pub fn rss_kb(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}
