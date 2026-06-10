//! End-to-end integration test for the admin API.
//!
//! Spawns `lynxx-gateway` as a child process pointed at a freshly minted
//! temp directory + `config.toml`, waits for `:admin/status` to come up,
//! then exercises a service create/get/delete cycle. The Postgres variant
//! runs the same flow against a Postgres URL and is gated on the
//! `LYNXX_TEST_PG=1` environment variable so it stays out of the way of
//! plain `cargo test` runs.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::process::{Child, Command};

/// Master admin credential the test gateway is launched with (via
/// `LYNXX_API_KEY`). Used to authenticate admin requests now that
/// `auth_required` defaults to true.
const ADMIN_TEST_TOKEN: &str = "admin-test-token";

/// Drop guard that kills the gateway subprocess so a panicking test
/// never leaks a port-bound process.
struct GatewayGuard {
    child: Option<Child>,
}

impl GatewayGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // start_kill is non-async and safe to call from Drop; the
            // OS reaps it when the test process exits.
            let _ = child.start_kill();
        }
    }
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn write_config(dir: &PathBuf, proxy_port: u16, admin_port: u16, db_url: &str) -> PathBuf {
    let path = dir.join("config.toml");
    let mut f = std::fs::File::create(&path).expect("create config");
    writeln!(
        f,
        "[gateway]\n\
         proxy_port = {proxy_port}\n\
         admin_port = {admin_port}\n\
         database_url = \"{db_url}\"\n\
         seed_from_config = false\n\
         health_check_interval_ms = 60000\n\
         health_circuit_failure_threshold = 3\n\
         health_circuit_success_threshold = 2\n\
         health_circuit_open_duration_ms = 30000\n"
    )
    .unwrap();
    path
}

async fn wait_for_status(admin_port: u16, timeout: Duration) -> bool {
    let url = format!("http://127.0.0.1:{admin_port}/status");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            if r.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn run_admin_cycle(admin_port: u16) {
    // The admin surface now requires auth by default (auth_required = true);
    // authenticate every request with the master license key the gateway was
    // launched with.
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {ADMIN_TEST_TOKEN}").parse().unwrap(),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("client");
    let base = format!("http://127.0.0.1:{admin_port}");

    // POST /services
    let resp = client
        .post(format!("{base}/services"))
        .json(&json!({
            "name": "it-test-svc",
            "url": "http://127.0.0.1:1",
            "retries": 1,
            "connect_timeout_ms": 1000,
        }))
        .send()
        .await
        .expect("post");
    assert!(
        resp.status().is_success(),
        "create_service status: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let data = body.get("data").unwrap_or(&body);
    let id = data
        .get("id")
        .and_then(|v| v.as_str())
        .expect("service id in response")
        .to_string();

    // GET /services/:id
    let resp = client
        .get(format!("{base}/services/{id}"))
        .send()
        .await
        .expect("get");
    assert!(
        resp.status().is_success(),
        "get_service status: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let data = body.get("data").unwrap_or(&body);
    assert_eq!(
        data.get("name").and_then(|v| v.as_str()),
        Some("it-test-svc")
    );

    // DELETE /services/:id
    let resp = client
        .delete(format!("{base}/services/{id}"))
        .send()
        .await
        .expect("delete");
    assert!(
        resp.status().is_success(),
        "delete_service status: {}",
        resp.status()
    );

    // confirm gone
    let resp = client
        .get(format!("{base}/services/{id}"))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status().as_u16(), 404, "service should be gone");
}

async fn launch_gateway(db_url: &str) -> (GatewayGuard, u16) {
    let dir = tempfile::tempdir().expect("tempdir");
    // Leak the TempDir so the gateway can keep using files in it until the
    // child is killed at end of test. The OS reclaims the temp dir on exit.
    let dir_path = dir.keep();
    let proxy_port = pick_free_port();
    let admin_port = pick_free_port();
    let config = write_config(&dir_path, proxy_port, admin_port, db_url);

    let bin = env!("CARGO_BIN_EXE_lynxx-gateway");
    let child = Command::new(bin)
        .env("LYNXX_CONFIG", &config)
        // `[keyx]` is unset here, so licence defaults to "unverified"
        // (Enterprise tier, no kill-switch). LYNXX_API_KEY just acts
        // as a master admin token shortcut for the admin API.
        .env("LYNXX_API_KEY", ADMIN_TEST_TOKEN)
        .env("RUST_LOG", "lynxx_gateway=warn")
        .current_dir(&dir_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn lynxx-gateway");

    let guard = GatewayGuard::new(child);
    let up = wait_for_status(admin_port, Duration::from_secs(30)).await;
    assert!(
        up,
        "gateway admin port {admin_port} did not respond in time"
    );
    (guard, admin_port)
}

#[tokio::test]
async fn admin_api_sqlite_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let (_guard, admin_port) = launch_gateway(&db_url).await;
    run_admin_cycle(admin_port).await;
}

/// Regression test for the critical admin-auth findings: the live-config
/// API (`/admin/v1/config`) used to be mounted OUTSIDE the auth middleware,
/// so an unauthenticated client could read the full running config
/// (secrets included) and overwrite it. It must now reject every
/// unauthenticated request and only serve callers with a valid admin
/// credential.
#[tokio::test]
async fn admin_config_api_requires_auth() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("cfg.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let (_guard, admin_port) = launch_gateway(&db_url).await;
    let base = format!("http://127.0.0.1:{admin_port}");

    let anon = reqwest::Client::new();

    // Unauthenticated read — must be denied.
    let resp = anon
        .get(format!("{base}/admin/v1/config"))
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "unauthenticated GET /admin/v1/config must be 401, got {}",
        resp.status()
    );

    // Unauthenticated full replace — must be denied.
    let resp = anon
        .put(format!("{base}/admin/v1/config"))
        .json(&json!({ "gateway": { "proxy_port": 1 } }))
        .send()
        .await
        .expect("put");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "unauthenticated PUT /admin/v1/config must be 401, got {}",
        resp.status()
    );

    // Unauthenticated targeted patch — must be denied.
    let resp = anon
        .patch(format!("{base}/admin/v1/config/gateway/proxy_port"))
        .json(&json!({ "value": 1234 }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "unauthenticated PATCH /admin/v1/config must be 401, got {}",
        resp.status()
    );

    // With the master credential, the read succeeds and returns a config.
    let resp = anon
        .get(format!("{base}/admin/v1/config"))
        .bearer_auth(ADMIN_TEST_TOKEN)
        .send()
        .await
        .expect("authed get");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "authenticated GET /admin/v1/config must be 200, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let cfg = body.get("config").or_else(|| body.get("data").and_then(|d| d.get("config")));
    assert!(
        cfg.is_some(),
        "authenticated config response must contain a config object, got: {body}"
    );
}

#[tokio::test]
async fn admin_api_postgres_lifecycle() {
    if std::env::var("LYNXX_TEST_PG").ok().as_deref() != Some("1") {
        eprintln!("skipping postgres test: set LYNXX_TEST_PG=1 to enable");
        return;
    }
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://lynxx:lynxx@localhost:5432/lynxx".to_string());
    let (_guard, admin_port) = launch_gateway(&db_url).await;
    run_admin_cycle(admin_port).await;
}
