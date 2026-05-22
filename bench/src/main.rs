//! lynxx-bench — a tiny open-loop HTTP load generator.
//!
//! Drives a steady RPS at one or more target URLs and reports a latency
//! distribution (p50/p95/p99/p99.9), achieved RPS, and error count. When
//! multiple targets are supplied via `--compare`, results are printed in a
//! side-by-side table so a Lynxx run can be compared against Kong (or any
//! other reference gateway) under the same workload.
//!
//! The tool is deliberately small — no Criterion, no external scheduler —
//! so it's easy to read and to ship as a single static binary.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use tokio::time::{sleep_until, Instant as TokioInstant};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lynxx-bench",
    version,
    about = "Open-loop HTTP benchmark tool for the Lynxx gateway"
)]
struct Args {
    /// Primary target URL.
    #[arg(long)]
    target: Option<String>,

    /// Additional named targets in the form `name=url`. Repeatable.
    /// When supplied, results are printed side-by-side.
    #[arg(long, value_parser = parse_compare)]
    compare: Vec<(String, String)>,

    /// Target requests per second (open-loop, token-bucket pacing).
    #[arg(long, default_value_t = 1000)]
    rps: u64,

    /// Total benchmark duration in seconds.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,

    /// Number of concurrent worker tasks (i.e. inflight cap).
    #[arg(long, default_value_t = 64)]
    connections: usize,

    /// Number of independent worker shards. Each shard runs its own
    /// open-loop producer + reqwest::Client + per-shard Histogram, then
    /// the histograms get merged at end via `Histogram::add`. At
    /// 100k+ RPS the single-shard design contends hard on the producer
    /// mpsc receiver mutex (one acquire per request × N workers) and
    /// the shared Histogram mutex (one acquire per measured success),
    /// which caused bench-client OOM/SIGTERM kills at >=300k RPS when
    /// the proxy under test stalled. Shards split RPS and connections
    /// evenly; remainder goes to the first shard.
    ///
    /// 0 = auto: ceil(rps / 50k), clamped to [1, nproc].
    #[arg(long, default_value_t = 0)]
    workers: usize,

    /// HTTP method.
    #[arg(long, value_enum, default_value_t = HttpMethod::Get)]
    method: HttpMethod,

    /// Optional request body file (used for POST/PUT/PATCH).
    #[arg(long)]
    body: Option<PathBuf>,

    /// Extra header in `K=V` form. Repeatable.
    #[arg(long, value_parser = parse_header)]
    header: Vec<(String, String)>,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,

    /// Warmup duration in seconds. Latencies during warmup are discarded.
    #[arg(long, default_value_t = 2)]
    warmup_secs: u64,

    /// Enable ANSI color in the report.
    #[arg(long, default_value_t = false)]
    color: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
}

impl From<HttpMethod> for Method {
    fn from(m: HttpMethod) -> Method {
        match m {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Head => Method::HEAD,
        }
    }
}

fn parse_compare(s: &str) -> Result<(String, String), String> {
    let (name, url) = s
        .split_once('=')
        .ok_or_else(|| format!("expected name=url, got `{s}`"))?;
    if name.is_empty() || url.is_empty() {
        return Err(format!("name and url must be non-empty in `{s}`"));
    }
    Ok((name.to_string(), url.to_string()))
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected K=V, got `{s}`"))?;
    Ok((k.to_string(), v.to_string()))
}

#[derive(Debug, Default)]
struct Stats {
    requests: u64,
    errors: u64,
    duration: Duration,
    histogram: Option<Histogram<u64>>,
}

impl Stats {
    fn achieved_rps(&self) -> f64 {
        let secs = self.duration.as_secs_f64();
        if secs == 0.0 {
            0.0
        } else {
            self.requests as f64 / secs
        }
    }
}

/// Resolve `args.workers` to a concrete shard count.
///
/// 0 = auto: 1 shard per 50k RPS, clamped to [1, nproc]. We picked
/// 50k as the threshold empirically — below that, a single producer
/// + shared-Mutex receiver does fine. Above 100k, contention on the
/// receiver + histogram mutexes shows up as bench-client SIGTERM
/// (OOM-killer trip) when the SUT stalls.
fn resolve_workers(workers: usize, rps: u64) -> usize {
    if workers > 0 {
        return workers.max(1);
    }
    let nproc = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let auto = ((rps + 49_999) / 50_000) as usize;
    auto.clamp(1, nproc.max(1))
}

/// Top-level bench driver. When `workers > 1` we shard the RPS + connection
/// budget across N independent open-loop runners and merge their stats at
/// the end. Each shard is a self-contained mini-bench — its own
/// `reqwest::Client`, its own producer task, its own worker pool, and
/// crucially its own `Histogram` (no cross-shard mutex). The merge step
/// uses `hdrhistogram::Histogram::add`, which is cheap.
async fn run_one(name: &str, url: &str, args: &Args) -> Result<Stats> {
    let n_shards = resolve_workers(args.workers, args.rps);
    let body = match &args.body {
        Some(path) => Some(
            fs::read(path)
                .with_context(|| format!("failed to read body file {}", path.display()))?,
        ),
        None => None,
    };
    let body = body.map(|b| Arc::new(b) as Arc<Vec<u8>>);
    let method: Method = args.method.into();

    eprintln!(
        "[{name}] {method} {url}  rps={} duration={}s connections={} warmup={}s workers={}",
        args.rps, args.duration_secs, args.connections, args.warmup_secs, n_shards
    );

    if n_shards == 1 {
        // Single-shard path is the original code — no need to coordinate.
        return run_one_shard(
            url.to_string(),
            method,
            body,
            args.clone(),
            args.rps,
            args.connections,
            args.warmup_secs,
            args.duration_secs,
        )
        .await;
    }

    // Multi-shard: split RPS + connections evenly; remainder goes to shard 0.
    let base_rps = args.rps / n_shards as u64;
    let extra_rps = args.rps % n_shards as u64;
    let base_conns = args.connections / n_shards;
    let extra_conns = args.connections % n_shards;

    let mut handles = Vec::with_capacity(n_shards);
    for shard_idx in 0..n_shards {
        let url = url.to_string();
        let method = method.clone();
        let body = body.clone();
        let args = args.clone();
        let shard_rps = base_rps + if shard_idx == 0 { extra_rps } else { 0 };
        let shard_conns = base_conns + if shard_idx == 0 { extra_conns } else { 0 };
        handles.push(tokio::spawn(async move {
            run_one_shard(
                url,
                method,
                body,
                args.clone(),
                shard_rps,
                shard_conns.max(1),
                args.warmup_secs,
                args.duration_secs,
            )
            .await
        }));
    }

    // Aggregate: sum counts, max duration (shards finish staggered), merge
    // histograms via `add()`. Errors from any shard surface here.
    let mut merged_hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)?;
    let mut requests: u64 = 0;
    let mut errors: u64 = 0;
    let mut max_duration = Duration::ZERO;
    for h in handles {
        let s = h.await??;
        requests = requests.saturating_add(s.requests);
        errors = errors.saturating_add(s.errors);
        if s.duration > max_duration {
            max_duration = s.duration;
        }
        if let Some(h) = &s.histogram {
            merged_hist
                .add(h)
                .map_err(|e| anyhow!("histogram merge: {e}"))?;
        }
    }
    Ok(Stats {
        requests,
        errors,
        duration: max_duration,
        histogram: Some(merged_hist),
    })
}

/// One independent shard of the open-loop bench. Owns its
/// `reqwest::Client`, producer task, worker pool, and a local
/// `Histogram`. Returns the shard's `Stats` for merging.
///
/// ## Concurrency design (post-upgrade)
///
/// Pre-upgrade this shard wrapped a `tokio::sync::mpsc::Receiver` in
/// `Arc<Mutex<...>>` and shared the histogram via `Arc<Mutex<Histogram>>`.
/// With up to 4 096 worker tasks per shard, every recv + every measured
/// response acquired one of those two mutexes — at 100 k RPS the bench
/// client itself was burning meaningful CPU on lock contention, masking
/// the gateway's true latency profile.
///
/// The upgrade swaps two things:
/// 1. **Ticket distribution**: `flume::bounded` (lock-free MPMC). The
///    receiver is cloneable; each worker owns its own handle and pulls
///    tickets without acquiring a shared mutex.
/// 2. **Latency recording**: each worker keeps a *local* `Histogram`,
///    sized identically to the per-shard merged histogram. On worker
///    exit the local histogram is shipped back over a oneshot and
///    merged into the shard total via `Histogram::add` (cheap, ~1µs
///    per merge regardless of sample count). No more per-sample mutex.
#[allow(clippy::too_many_arguments)]
async fn run_one_shard(
    url: String,
    method: Method,
    body: Option<Arc<Vec<u8>>>,
    args: Args,
    rps: u64,
    connections: usize,
    warmup_secs: u64,
    duration_secs: u64,
) -> Result<Stats> {
    let client = build_client_with_pool(&args, connections)?;

    // Token bucket: emit one tick per request at the shard's RPS.
    let total_secs = warmup_secs + duration_secs;
    let total_requests = rps.saturating_mul(total_secs);
    let interval = (1_000_000_000u64)
        .checked_div(rps.max(1))
        .map(Duration::from_nanos)
        .unwrap_or_else(|| Duration::from_millis(1));

    // Lock-free MPMC channel. Each worker clones the receiver — no shared
    // mutex on the recv path. Capacity matches the pre-upgrade
    // `mpsc::channel(connections * 4)` so behaviour under producer
    // pressure is the same.
    let (tx, rx) = flume::bounded::<Ticket>(connections.saturating_mul(4).max(16));

    let measured_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(connections);
    for _ in 0..connections {
        let rx = rx.clone();
        let client = client.clone();
        let url = url.clone();
        let method = method.clone();
        let body = body.clone();
        let measured = measured_count.clone();
        let errors = error_count.clone();
        handles.push(tokio::spawn(async move {
            // Per-worker histogram — no cross-worker mutex on the record
            // path. Bounds match the shard-level merged histogram below.
            let mut local_hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
                .expect("histogram bounds valid");
            loop {
                let ticket = match rx.recv_async().await {
                    Ok(t) => t,
                    Err(_) => break, // channel closed — producer done
                };
                let req_start = Instant::now();
                let mut req = client.request(method.clone(), &url);
                if let Some(b) = &body {
                    req = req.body((**b).clone());
                }
                let result = req.send().await;
                let elapsed_us = req_start.elapsed().as_micros() as u64;
                let ok = match result {
                    Ok(resp) => {
                        let status = resp.status();
                        let _ = resp.bytes().await;
                        status.is_success() || status.is_redirection()
                    }
                    Err(_) => false,
                };
                if !ticket.measure {
                    continue;
                }
                if ok {
                    let _ = local_hist.record(elapsed_us.max(1));
                    measured.fetch_add(1, Ordering::Relaxed);
                } else {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            local_hist
        }));
    }

    let bench_start = Instant::now();
    let warmup_until = bench_start + Duration::from_secs(warmup_secs);
    let producer_start = TokioInstant::now();
    for i in 0..total_requests {
        let target_at = producer_start + interval * (i as u32);
        sleep_until(target_at).await;
        let measure = Instant::now() >= warmup_until;
        if tx.send_async(Ticket { measure }).await.is_err() {
            break;
        }
    }
    drop(tx);
    // Merge per-worker histograms into the shard total.
    let mut merged_hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)?;
    for h in handles {
        if let Ok(local) = h.await {
            merged_hist
                .add(&local)
                .map_err(|e| anyhow!("histogram merge: {e}"))?;
        }
    }
    let total_elapsed = bench_start.elapsed();
    let measured_duration = total_elapsed.saturating_sub(Duration::from_secs(warmup_secs));

    Ok(Stats {
        requests: measured_count.load(Ordering::Relaxed),
        errors: error_count.load(Ordering::Relaxed),
        duration: measured_duration,
        histogram: Some(merged_hist),
    })
}

/// Variant of `build_client` that lets the per-shard runner override the
/// pool size — so a shard with 512 in-flight connections doesn't end up
/// fighting for an idle pool sized for the whole bench.
fn build_client_with_pool(args: &Args, pool_size: usize) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    for (k, v) in &args.header {
        let name = HeaderName::from_bytes(k.as_bytes())
            .with_context(|| format!("invalid header name `{k}`"))?;
        let value =
            HeaderValue::from_str(v).with_context(|| format!("invalid header value for `{k}`"))?;
        headers.insert(name, value);
    }
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(pool_size)
        .timeout(Duration::from_secs(args.timeout_secs))
        .default_headers(headers)
        .build()?;
    Ok(client)
}

#[derive(Clone, Copy)]
struct Ticket {
    measure: bool,
}

fn fmt_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}us")
    }
}

fn fmt_count(n: u64) -> String {
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

fn print_report(results: &[(String, Stats)], color: bool) {
    let bold = if color { "\x1b[1m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let dim = if color { "\x1b[2m" } else { "" };

    if results.len() == 1 {
        let (name, s) = &results[0];
        let h = s.histogram.as_ref();
        println!("\n{bold}== {name} =={reset}");
        println!("  duration:        {:>12.1}s", s.duration.as_secs_f64());
        println!("  requests:        {:>12}", fmt_count(s.requests));
        println!("  achieved_rps:    {:>12.0}", s.achieved_rps());
        if let Some(h) = h {
            println!(
                "  p50:             {:>12}",
                fmt_us(h.value_at_quantile(0.50))
            );
            println!(
                "  p95:             {:>12}",
                fmt_us(h.value_at_quantile(0.95))
            );
            println!(
                "  p99:             {:>12}",
                fmt_us(h.value_at_quantile(0.99))
            );
            println!(
                "  p99.9:           {:>12}",
                fmt_us(h.value_at_quantile(0.999))
            );
            println!("  min:             {:>12}", fmt_us(h.min().max(1)));
            println!("  max:             {:>12}", fmt_us(h.max()));
        }
        println!("  errors:          {:>12}", fmt_count(s.errors));
        return;
    }

    // Side-by-side table.
    let metric_w = 14;
    let col_w = 14;
    print!("\n{bold}{:<metric_w$}{reset}", "metric");
    for (name, _) in results {
        print!(" {bold}{:>col_w$}{reset}", name);
    }
    println!();
    println!(
        "{dim}{}{reset}",
        "-".repeat(metric_w + (col_w + 1) * results.len())
    );

    let row = |label: &str, vals: &[String]| {
        print!("{:<metric_w$}", label);
        for v in vals {
            print!(" {:>col_w$}", v);
        }
        println!();
    };

    row(
        "duration",
        &results
            .iter()
            .map(|(_, s)| format!("{:.1}s", s.duration.as_secs_f64()))
            .collect::<Vec<_>>(),
    );
    row(
        "requests",
        &results
            .iter()
            .map(|(_, s)| fmt_count(s.requests))
            .collect::<Vec<_>>(),
    );
    row(
        "achieved_rps",
        &results
            .iter()
            .map(|(_, s)| format!("{:.0}", s.achieved_rps()))
            .collect::<Vec<_>>(),
    );
    for (q, label) in [
        (0.50, "p50"),
        (0.95, "p95"),
        (0.99, "p99"),
        (0.999, "p99.9"),
    ] {
        let vals: Vec<String> = results
            .iter()
            .map(|(_, s)| match &s.histogram {
                Some(h) => fmt_us(h.value_at_quantile(q)),
                None => "-".into(),
            })
            .collect();
        row(label, &vals);
    }
    row(
        "min",
        &results
            .iter()
            .map(|(_, s)| {
                s.histogram
                    .as_ref()
                    .map(|h| fmt_us(h.min().max(1)))
                    .unwrap_or("-".into())
            })
            .collect::<Vec<_>>(),
    );
    row(
        "max",
        &results
            .iter()
            .map(|(_, s)| {
                s.histogram
                    .as_ref()
                    .map(|h| fmt_us(h.max()))
                    .unwrap_or("-".into())
            })
            .collect::<Vec<_>>(),
    );
    row(
        "errors",
        &results
            .iter()
            .map(|(_, s)| fmt_count(s.errors))
            .collect::<Vec<_>>(),
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut targets: Vec<(String, String)> = Vec::new();
    if let Some(t) = &args.target {
        targets.push(("lynxx".into(), t.clone()));
    }
    targets.extend(args.compare.iter().cloned());
    if targets.is_empty() {
        return Err(anyhow!(
            "no targets supplied — pass --target <url> and/or --compare name=url"
        ));
    }

    let mut results = Vec::with_capacity(targets.len());
    for (name, url) in &targets {
        let stats = run_one(name, url, &args).await?;
        if stats.requests == 0 && stats.errors > 0 {
            eprintln!("[{name}] WARNING: every request errored");
        }
        results.push((name.clone(), stats));
    }

    print_report(&results, args.color);

    // Non-zero exit if every target had only errors — useful for CI smoke.
    if results.iter().all(|(_, s)| s.requests == 0) {
        std::process::exit(2);
    }
    Ok(())
}
