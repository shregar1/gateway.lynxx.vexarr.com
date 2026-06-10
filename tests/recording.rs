//! End-to-end integration test for Time-Travel Debug.
//!
//! Spins up a wiremock upstream, a real `lynxx-gateway` subprocess, wires
//! a service + route + the `request-recorder` plugin (with sample_rate=1
//! so every hit is captured), drives a few requests through the proxy,
//! then exercises the new admin endpoints: list, fetch, replay (against
//! the gateway itself), and delete.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::process::{Child, Command};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

fn write_config(
    dir: &PathBuf,
    proxy_port: u16,
    admin_port: u16,
    db_url: &str,
    recordings_dir: &PathBuf,
) -> PathBuf {
    let path = dir.join("config.toml");
    let mut f = std::fs::File::create(&path).expect("create config");
    writeln!(
        f,
        "[gateway]\n\
         proxy_port = {proxy_port}\n\
         admin_port = {admin_port}\n\
         database_url = \"{db_url}\"\n\
         seed_from_config = false\n\
         recordings_directory = \"{rec}\"\n\
         health_check_interval_ms = 60000\n\
         health_circuit_failure_threshold = 3\n\
         health_circuit_success_threshold = 2\n\
         health_circuit_open_duration_ms = 30000\n",
        rec = recordings_dir.display(),
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

async fn launch_gateway(
    db_url: &str,
    proxy_port: u16,
    admin_port: u16,
    recordings_dir: &PathBuf,
) -> GatewayGuard {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path = dir.keep();
    let config = write_config(&dir_path, proxy_port, admin_port, db_url, recordings_dir);

    let bin = env!("CARGO_BIN_EXE_lynxx-gateway");
    let child = Command::new(bin)
        .env("LYNXX_CONFIG", &config)
        .env("LYNXX_API_KEY", "lnx_dev_pro")
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
    guard
}

#[tokio::test]
async fn time_travel_capture_list_replay_delete() {
    // 1. Mock upstream — every GET /thing returns deterministic JSON.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/thing"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"hello\":\"world\"}")
                .insert_header("content-type", "application/json"),
        )
        .mount(&upstream)
        .await;

    // 2. Spawn the gateway.
    let tmp = tempfile::tempdir().expect("tempdir");
    let recordings_dir = tmp.path().join("recordings");
    std::fs::create_dir_all(&recordings_dir).unwrap();
    let db_path = tmp.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let proxy_port = pick_free_port();
    let admin_port = pick_free_port();
    let _guard = launch_gateway(&db_url, proxy_port, admin_port, &recordings_dir).await;

    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let proxy_base = format!("http://127.0.0.1:{proxy_port}");
    // Admin API now requires auth by default; authenticate with the master
    // license key the gateway was launched with (LYNXX_API_KEY=lnx_dev_pro).
    let mut admin_headers = reqwest::header::HeaderMap::new();
    admin_headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer lnx_dev_pro".parse().unwrap(),
    );
    let http = reqwest::Client::builder()
        .default_headers(admin_headers)
        .build()
        .expect("client");

    // 3. Service + route — point at wiremock.
    let svc: Value = http
        .post(format!("{admin_base}/services"))
        .json(&json!({
            "name": "rec-svc",
            "url": upstream.uri(),
            "retries": 0,
            "connect_timeout_ms": 2000,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_data = svc.get("data").unwrap_or(&svc);
    let svc_id = svc_data["id"].as_str().unwrap().to_string();

    let _: Value = http
        .post(format!("{admin_base}/routes"))
        .json(&json!({
            "paths": ["/thing"],
            "methods": ["GET"],
            "service_id": svc_id,
            "strip_path": false,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 4. Install the request-recorder plugin with sample_rate=1.0 so
    //    every request is captured.
    let plugin_dir = recordings_dir.to_string_lossy().into_owned();
    let resp = http
        .post(format!("{admin_base}/plugins"))
        .json(&json!({
            "name": "request-recorder",
            "enabled": true,
            "config": {
                "directory": plugin_dir,
                "sample_rate": 1.0,
                "retention_days": 0,
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "install plugin: {}",
        resp.status()
    );

    // 5. Drive a few requests through the proxy.
    for _ in 0..3 {
        let r = http
            .get(format!("{proxy_base}/thing"))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "proxy 200: {}", r.status());
    }

    // 6. Wait for the writer task to flush.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 7. List recordings.
    let list_body: Value = http
        .get(format!("{admin_base}/recordings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows_val = list_body.get("data").unwrap_or(&list_body);
    let rows: Vec<Value> = serde_json::from_value(rows_val.clone()).unwrap();
    assert!(rows.len() >= 3, "expected ≥3 captures, got {}", rows.len());

    // The recorder should have plumbed service_id + upstream-bound paths.
    let row = &rows[0];
    assert_eq!(row["method"].as_str(), Some("GET"));
    assert_eq!(row["path"].as_str(), Some("/thing"));
    assert_eq!(row["status"].as_u64(), Some(200));
    assert_eq!(
        row["service_id"].as_str(),
        Some(svc_id.as_str()),
        "service_id should be plumbed via MatchContext"
    );

    let id = row["id"].as_str().unwrap().to_string();

    // 8. Fetch the full recording — request body is empty (GET), response
    //    body decodes back to the wiremock payload.
    let rec_body: Value = http
        .get(format!("{admin_base}/recordings/{id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rec = rec_body.get("data").unwrap_or(&rec_body);
    assert_eq!(rec["id"].as_str(), Some(id.as_str()));
    let resp_b64 = rec["response"]["body_b64"].as_str().unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let decoded = STANDARD.decode(resp_b64).unwrap();
    assert_eq!(
        std::str::from_utf8(&decoded).unwrap(),
        "{\"hello\":\"world\"}"
    );

    // 9. Replay against the gateway itself; wiremock is deterministic so
    //    the body should be identical.
    let replay_body: Value = http
        .post(format!("{admin_base}/recordings/{id}/replay"))
        .json(&json!({ "target_url": null }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let replay = replay_body.get("data").unwrap_or(&replay_body);
    assert_eq!(
        replay["diff"]["body_diff"]["kind"].as_str(),
        Some("identical"),
        "expected Identical body diff, got {:?}",
        replay["diff"]["body_diff"]
    );

    // 10. Delete and verify the row no longer appears.
    let resp = http
        .delete(format!("{admin_base}/recordings/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204, "delete should be 204");

    let after_body: Value = http
        .get(format!("{admin_base}/recordings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let after_val = after_body.get("data").unwrap_or(&after_body);
    let after: Vec<Value> = serde_json::from_value(after_val.clone()).unwrap();
    // Replaying through the gateway itself is also captured (sample_rate=1.0),
    // so we don't compare absolute counts. We just verify the deleted id is
    // no longer listed.
    assert!(
        after.iter().all(|r| r["id"].as_str() != Some(id.as_str())),
        "deleted id should not appear in subsequent list"
    );
}
