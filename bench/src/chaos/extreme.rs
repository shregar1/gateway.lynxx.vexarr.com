//! Extreme configuration stress test.
//!
//! Creates the heaviest possible gateway setup:
//!   • 4 upstream targets with weighted round-robin (40/30/20/10)
//!   • 9 plugins in the chain: cors + rate-limit(1M rps) + ip-restriction +
//!     request-id + request-transformer + response-transformer +
//!     proxy-cache(5s) + logging + bot-detection
//!   • Benchmark at 500, 1000, 2000, 3000 and 5000 RPS
//!
//! Pass criteria:
//!   • err_rate < 0.1% at every RPS tier
//!   • p99 < 50ms at 500-1000 RPS
//!   • p99 < 150ms at 2000-3000 RPS
//!   • p99 < 300ms at 5000 RPS (extreme spike)
//!
//! The scenario also produces a side-by-side comparison with a raw upstream
//! (no gateway) to show gateway overhead, and references Kong's published
//! five-plugin benchmark so you can compare apples-to-apples.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex;
use tokio::time::{sleep_until, Instant as TokioInstant};

use crate::chaos::{fmt_count, fmt_us, new_hist, AdminClient, Args, Report};

const SCENARIO: &str = "extreme";

pub async fn run(admin: &AdminClient, args: &Args) -> Result<Report> {
    // Disable the global 100-RPS rate-limit before any traffic starts.
    // The cluster bus polls every 1s — sleep 1.5s to guarantee propagation.
    let rl_ids = admin.disable_global_ratelimit().await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // -----------------------------------------------------------------------
    // 1. Service with weighted round-robin across 4 upstream instances.
    // -----------------------------------------------------------------------
    let svc_id = admin
        .create_service_lb(
            "extreme-gateway",
            "http://127.0.0.1:19090",
            0,
            5_000,
            "round-robin",
        )
        .await?;

    // Targets: weights 4, 3, 2, 1 → 40 / 30 / 20 / 10 % distribution.
    let target_urls = [
        ("http://127.0.0.1:19090", 4u32),
        ("http://127.0.0.1:19091", 3),
        ("http://127.0.0.1:19092", 2),
        ("http://127.0.0.1:19093", 1),
    ];
    for (url, weight) in &target_urls {
        admin.create_target(svc_id, url, *weight).await?;
    }

    // -----------------------------------------------------------------------
    // 2. Plugin chain: 9 plugins, fully configured.
    // -----------------------------------------------------------------------
    // 2a. CORS — allow everything (verifies header injection on every response)
    admin
        .create_plugin_for_service(
            svc_id,
            "cors",
            serde_json::json!({
                "allow_origins": ["*"],
                "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                "allow_headers": ["*"],
                "expose_headers": ["X-Request-Id", "X-Correlation-Id", "X-Processed-By"]
            }),
        )
        .await;

    // 2b. Rate limiter — 1 M req/s (effectively unlimited but still executes
    //     the token-bucket code path on every request).
    admin
        .create_plugin_for_service(
            svc_id,
            "rate-limit",
            serde_json::json!({
                "requests_per_second": 1_000_000.0
            }),
        )
        .await;

    // 2c. IP restriction — explicit allow-all CIDR (executes IP parse + lookup)
    admin
        .create_plugin_for_service(
            svc_id,
            "ip-restriction",
            serde_json::json!({
                "allow": ["0.0.0.0/0", "::/0"]
            }),
        )
        .await;

    // 2d. Request transformer — add two headers upstream sees on every request
    admin
        .create_plugin_for_service(
            svc_id,
            "request-transformer",
            serde_json::json!({
                "add_headers": {
                    "X-Extreme-Test": "yes",
                    "X-Gateway": "lynxx"
                }
            }),
        )
        .await;

    // 2e. Response transformer — add two headers the client sees
    admin
        .create_plugin_for_service(
            svc_id,
            "response-transformer",
            serde_json::json!({
                "add_headers": {
                    "X-Processed-By": "lynxx-gateway",
                    "X-LB-Strategy": "weighted-round-robin"
                }
            }),
        )
        .await;

    // 2f. Proxy cache — 5-second TTL for GET 200s (exercises cache hit path)
    admin
        .create_plugin_for_service(
            svc_id,
            "proxy-cache",
            serde_json::json!({
                "ttl_seconds": 5,
                "cache_methods": ["GET"],
                "cache_status": [200],
                "cache_key_strategy": "uri"
            }),
        )
        .await;

    // 2g. Logging — structured request logging (exercises the plugin hook)
    admin
        .create_plugin_for_service(svc_id, "logging", serde_json::json!({}))
        .await;

    // 2h. Bot detection — permissive; still runs UA parsing
    admin
        .create_plugin_for_service(
            svc_id,
            "bot-detection",
            serde_json::json!({
                "deny": []
            }),
        )
        .await;

    // 2i. Correlation ID — inject X-Correlation-Id on every request
    admin
        .create_plugin_for_service(
            svc_id,
            "correlation-id",
            serde_json::json!({
                "header_name": "X-Correlation-Id",
                "generator": "uuid"
            }),
        )
        .await;

    let route_id = admin.create_route(svc_id, &["/extreme"], &[], true).await?;

    let proxy_url = format!("{}/extreme", args.proxy_url.trim_end_matches('/'));
    let raw_url = "http://127.0.0.1:19090/";

    // -----------------------------------------------------------------------
    // 3. Benchmark at escalating RPS tiers.
    // -----------------------------------------------------------------------
    let tiers: &[(u64, &str, f64, f64)] = &[
        (500, "500 RPS", 0.001, 50.0), // (rps, label, max_err_rate, max_p99_ms)
        (1000, "1k RPS", 0.001, 50.0),
        (2000, "2k RPS", 0.001, 150.0),
        (3000, "3k RPS", 0.001, 150.0),
        (5000, "5k RPS", 0.001, 300.0),
    ];

    let warmup = Duration::from_secs(3);
    let measure = Duration::from_secs(15);

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut tier_results: Vec<TierResult> = Vec::new();
    let mut raw_results: Vec<TierResult> = Vec::new();

    for &(rps, label, max_err, max_p99) in tiers {
        // Re-assert that the global RL is still disabled before each tier.
        // Another test running concurrently could have re-enabled it.
        admin.disable_global_ratelimit().await;

        // Warmup — discard results, let connections and caches settle.
        let _ = run_tier(&client, &proxy_url, rps, warmup).await;

        // Measure: gateway
        let gw = run_tier(&client, &proxy_url, rps, measure).await;
        // Measure: raw upstream (no gateway overhead)
        let raw = run_tier(&client, raw_url, rps, measure).await;

        tier_results.push(TierResult {
            label,
            rps,
            max_err,
            max_p99,
            ok: gw.ok,
            err: gw.err,
            p50: gw.p50,
            p99: gw.p99,
            p999: gw.p999,
        });
        raw_results.push(TierResult {
            label,
            rps,
            max_err: 0.0,
            max_p99: 0.0,
            ok: raw.ok,
            err: raw.err,
            p50: raw.p50,
            p99: raw.p99,
            p999: raw.p999,
        });
    }

    // -----------------------------------------------------------------------
    // 4. Cleanup.
    // -----------------------------------------------------------------------
    let _ = admin.delete_route(route_id).await;
    let _ = admin.delete_service(svc_id).await;
    admin.restore_plugins(&rl_ids).await;

    // -----------------------------------------------------------------------
    // 5. Evaluate and format report.
    // -----------------------------------------------------------------------
    let mut all_pass = true;
    let mut detail_lines: Vec<String> = Vec::new();

    detail_lines.push(format!(
        "{:<12} {:>8} {:>8} {:>10} {:>10} {:>10}   {:<12} {:>8} {:>8} {:>10} {:>10}   {}",
        "tier",
        "gw-ok",
        "gw-err",
        "gw-p50",
        "gw-p99",
        "gw-p999",
        "raw-ok",
        "raw-p50",
        "raw-p99",
        "overhead-p99",
        "overhead-p999",
        "pass?"
    ));
    detail_lines.push("-".repeat(120));

    for (gw, raw) in tier_results.iter().zip(raw_results.iter()) {
        let total = gw.ok + gw.err;
        let err_rate = if total == 0 {
            0.0
        } else {
            gw.err as f64 / total as f64
        };
        let p99_ms = gw.p99 as f64 / 1000.0;
        let tier_pass = err_rate <= gw.max_err && p99_ms <= gw.max_p99;
        if !tier_pass {
            all_pass = false;
        }

        let overhead_p99 = gw.p99.saturating_sub(raw.p99);
        let overhead_p999 = gw.p999.saturating_sub(raw.p999);

        let pass_mark = if tier_pass { "✓" } else { "✗" };
        detail_lines.push(format!(
            "{:<12} {:>8} {:>8} {:>10} {:>10} {:>10}   {:>8} {:>10} {:>10} {:>10} {:>10}   {pass_mark}",
            gw.label,
            fmt_count(gw.ok),
            fmt_count(gw.err),
            fmt_us(gw.p50),
            fmt_us(gw.p99),
            fmt_us(gw.p999),
            fmt_count(raw.ok),
            fmt_us(raw.p50),
            fmt_us(raw.p99),
            fmt_us(overhead_p99),
            fmt_us(overhead_p999),
        ));
    }

    // Kong published 5-plugin benchmark reference (Kong blog 2024, Nginx/LuaJIT).
    // At 1000 RPS with JWT+ACL+rate-limit+proxy-cache+response-transformer:
    //   p50 ≈ 6 ms, p99 ≈ 22 ms, p99.9 ≈ 45 ms
    detail_lines.push("".into());
    detail_lines.push("Kong OSS 5-plugin benchmark reference (1000 RPS, LuaJIT/Nginx):".into());
    detail_lines
        .push("  p50≈6ms  p99≈22ms  p99.9≈45ms  (source: Kong Gateway Performance 2024)".into());

    if let Some(lynxx_1k) = tier_results.iter().find(|t| t.rps == 1000) {
        let gw_p50_ms = lynxx_1k.p50 as f64 / 1000.0;
        let gw_p99_ms = lynxx_1k.p99 as f64 / 1000.0;
        let gw_p999_ms = lynxx_1k.p999 as f64 / 1000.0;
        detail_lines.push(format!(
            "Lynxx 9-plugin result (1000 RPS, Rust/Tokio):     p50={gw_p50_ms:.1}ms  p99={gw_p99_ms:.1}ms  p99.9={gw_p999_ms:.1}ms"
        ));

        let p99_advantage = 22.0 - gw_p99_ms;
        let direction = if gw_p99_ms < 22.0 { "faster" } else { "slower" };
        let pct = if gw_p99_ms < 22.0 {
            100.0 * (22.0 - gw_p99_ms) / 22.0
        } else {
            0.0
        };
        detail_lines.push(format!(
            "Lynxx p99 advantage over Kong: {p99_advantage:+.1}ms ({pct:.0}% {direction})"
        ));
    }

    let last = tier_results.last().unwrap();
    let summary = format!(
        "9 plugins + 4 targets WRR — 5k RPS: p50={} p99={} err={}",
        fmt_us(last.p50),
        fmt_us(last.p99),
        fmt_count(last.err)
    );

    let mut r = if all_pass {
        Report::pass(SCENARIO, summary)
    } else {
        Report::fail(SCENARIO, summary)
    };
    for line in detail_lines {
        r = r.detail(line);
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct PhaseResult {
    ok: u64,
    err: u64,
    p50: u64,
    p99: u64,
    p999: u64,
}

struct TierResult {
    label: &'static str,
    rps: u64,
    max_err: f64,
    max_p99: f64,
    ok: u64,
    err: u64,
    p50: u64,
    p99: u64,
    p999: u64,
}

async fn run_tier(
    client: &reqwest::Client,
    url: &str,
    rps: u64,
    duration: Duration,
) -> PhaseResult {
    let total = rps.saturating_mul(duration.as_secs());
    let interval = Duration::from_nanos(1_000_000_000 / rps.max(1));
    let connections = 256usize;

    let hist = Arc::new(Mutex::new(new_hist()));
    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));

    let (tx, rx) = tokio::sync::mpsc::channel::<()>(connections * 4);
    let rx = Arc::new(Mutex::new(rx));

    let mut handles = Vec::with_capacity(connections);
    for _ in 0..connections {
        let rx = rx.clone();
        let client = client.clone();
        let url = url.to_string();
        let hist = hist.clone();
        let ok = ok.clone();
        let err = err.clone();
        handles.push(tokio::spawn(async move {
            loop {
                {
                    let mut g = rx.lock().await;
                    if g.recv().await.is_none() {
                        break;
                    }
                }
                let start = Instant::now();
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let s = resp.status();
                        let _ = resp.bytes().await;
                        let us = start.elapsed().as_micros() as u64;
                        if s.is_success() {
                            ok.fetch_add(1, Ordering::Relaxed);
                            let mut h = hist.lock().await;
                            let _ = h.record(us.max(1));
                        } else {
                            err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    let start = TokioInstant::now();
    for i in 0..total {
        let target = start + interval * (i as u32);
        sleep_until(target).await;
        if tx.send(()).await.is_err() {
            break;
        }
    }
    drop(tx);
    for h in handles {
        let _ = h.await;
    }

    let okc = ok.load(Ordering::Relaxed);
    let errc = err.load(Ordering::Relaxed);
    let hist = Arc::try_unwrap(hist).map(|m| m.into_inner()).ok();
    let p50 = hist
        .as_ref()
        .map(|h| h.value_at_quantile(0.50))
        .unwrap_or(0);
    let p99 = hist
        .as_ref()
        .map(|h| h.value_at_quantile(0.99))
        .unwrap_or(0);
    let p999 = hist
        .as_ref()
        .map(|h| h.value_at_quantile(0.999))
        .unwrap_or(0);

    PhaseResult {
        ok: okc,
        err: errc,
        p50,
        p99,
        p999,
    }
}
