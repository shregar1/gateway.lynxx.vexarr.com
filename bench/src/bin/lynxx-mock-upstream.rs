//! lynxx-mock-upstream — a controllable HTTP server for chaos tests.
//!
//! Replaces a fixed-response echo container when scenarios need to inject failures or latency. Not
//! optimised — just correct. The `--echo` mode reflects request data back as
//! JSON so plugin chains can be verified end-to-end.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use clap::Parser;
use rand::Rng;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lynxx-mock-upstream",
    version,
    about = "Controllable mock HTTP upstream for chaos tests"
)]
struct Cli {
    /// Listen port on 127.0.0.1.
    #[arg(long, default_value_t = 19090)]
    port: u16,

    /// Status code distribution `2xx,4xx,5xx` (must sum to 100). Default is "100,0,0".
    /// 4xx picks randomly among 400/401/404; 5xx picks among 500/502/503.
    #[arg(long)]
    status_distribution: Option<String>,

    /// Comma-separated latency values like `1ms,5ms,20ms`. With 3 entries the
    /// default weighting is 50/40/10 (most requests are fast). With other counts
    /// the values are picked round-robin.
    #[arg(long)]
    latency: Option<String>,

    /// Echo mode — respond with a JSON body reflecting method/path/headers/body.
    #[arg(long)]
    echo: bool,
}

#[derive(Clone)]
struct AppState {
    status_dist: Option<StatusDist>,
    latencies: Vec<Duration>,
    latency_weights: Vec<u32>,
    rr: Arc<AtomicUsize>,
    echo: bool,
}

#[derive(Clone, Debug)]
struct StatusDist {
    /// Cumulative buckets: (upper-exclusive percentile 0..100, class 0/1/2 for 2xx/4xx/5xx).
    buckets: Vec<(u32, u8)>,
}

fn parse_status_dist(s: &str) -> Result<StatusDist> {
    let parts: Vec<u32> = s
        .split(',')
        .map(|p| p.trim().parse::<u32>())
        .collect::<Result<_, _>>()?;
    if parts.len() != 3 {
        anyhow::bail!(
            "--status-distribution needs exactly 3 comma-separated values, got {}",
            parts.len()
        );
    }
    if parts.iter().sum::<u32>() != 100 {
        anyhow::bail!("--status-distribution values must sum to 100");
    }
    let mut buckets = Vec::with_capacity(3);
    let mut acc = 0u32;
    for (i, p) in parts.iter().enumerate() {
        acc += p;
        buckets.push((acc, i as u8));
    }
    Ok(StatusDist { buckets })
}

fn parse_latencies(s: &str) -> Result<Vec<Duration>> {
    let mut out = Vec::new();
    for p in s.split(',') {
        let p = p.trim();
        let dur = if let Some(ms) = p.strip_suffix("ms") {
            Duration::from_millis(ms.parse()?)
        } else if let Some(us) = p.strip_suffix("us") {
            Duration::from_micros(us.parse()?)
        } else if let Some(s) = p.strip_suffix('s') {
            Duration::from_secs_f64(s.parse()?)
        } else {
            Duration::from_millis(p.parse()?)
        };
        out.push(dur);
    }
    if out.is_empty() {
        anyhow::bail!("--latency must have at least one value");
    }
    Ok(out)
}

fn pick_status(d: &StatusDist) -> StatusCode {
    let r = rand::thread_rng().gen_range(0..100);
    let class = d
        .buckets
        .iter()
        .find(|(upper, _)| r < *upper)
        .map(|(_, c)| *c)
        .unwrap_or(0);
    let mut rng = rand::thread_rng();
    match class {
        0 => StatusCode::OK,
        1 => *[
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
        ]
        .get(rng.gen_range(0..3))
        .unwrap(),
        _ => *[
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ]
        .get(rng.gen_range(0..3))
        .unwrap(),
    }
}

fn pick_latency(state: &AppState) -> Option<Duration> {
    if state.latencies.is_empty() {
        return None;
    }
    if state.latencies.len() == 3 && !state.latency_weights.is_empty() {
        // Weighted pick.
        let total: u32 = state.latency_weights.iter().sum();
        let mut r = rand::thread_rng().gen_range(0..total);
        for (i, w) in state.latency_weights.iter().enumerate() {
            if r < *w {
                return Some(state.latencies[i]);
            }
            r -= *w;
        }
        return Some(state.latencies[0]);
    }
    // Round-robin.
    let idx = state.rr.fetch_add(1, Ordering::Relaxed) % state.latencies.len();
    Some(state.latencies[idx])
}

async fn handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(d) = pick_latency(&state) {
        tokio::time::sleep(d).await;
    }
    let status = state
        .status_dist
        .as_ref()
        .map(pick_status)
        .unwrap_or(StatusCode::OK);

    if state.echo {
        let mut hdrs = HashMap::new();
        for (k, v) in headers.iter() {
            hdrs.insert(k.as_str().to_string(), v.to_str().unwrap_or("").to_string());
        }
        let payload = json!({
            "method": method.as_str(),
            "path": uri.path(),
            "query": uri.query().unwrap_or(""),
            "headers": hdrs,
            "body_len": body.len(),
            "body": String::from_utf8_lossy(&body).into_owned(),
        });
        return (status, axum::Json(payload)).into_response();
    }

    (status, "ok\n").into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    let status_dist = match cli.status_distribution.as_deref() {
        Some(s) => Some(parse_status_dist(s)?),
        None => None,
    };
    let latencies = match cli.latency.as_deref() {
        Some(s) => parse_latencies(s)?,
        None => Vec::new(),
    };
    let latency_weights = if latencies.len() == 3 {
        vec![50u32, 40, 10]
    } else {
        Vec::new()
    };

    let state = AppState {
        status_dist,
        latencies,
        latency_weights,
        rr: Arc::new(AtomicUsize::new(0)),
        echo: cli.echo,
    };

    let app = Router::new().fallback(any(handler)).with_state(state);
    let addr: SocketAddr = ([0, 0, 0, 0], cli.port).into();
    tracing::info!(%addr, echo = cli.echo, "lynxx-mock-upstream listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
