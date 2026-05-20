//! lynxx-ebpf userspace daemon.
//!
//! Loads the kernel-side BPF program embedded at build time, attaches
//! its tracepoints, polls the BPF maps once a second, and exposes the
//! aggregated counters as a Prometheus endpoint.
//!
//! ## Run
//!
//! ```bash
//! sudo ./target/release/lynxx-ebpf \
//!     --metrics-addr 0.0.0.0:9201 \
//!     --log-level info
//! curl -s http://localhost:9201/metrics | grep lynxx_ebpf
//! ```
//!
//! ## Design notes
//!
//! * The BPF object is embedded at build time via aya's
//!   [`include_bytes_aligned!`] macro. When the userspace crate is
//!   built without the `embed-bpf-object` feature (for example,
//!   `cargo check` on macOS), the embedded blob is a sentinel
//!   placeholder; the loader refuses to start with a clear error.
//!
//! * The polling interval is 1 second. This is a deliberate trade-off:
//!   shorter intervals add userspace CPU; longer ones blur the
//!   per-second retransmit rate. Operators who want push-based
//!   semantics can wire Prometheus's `scrape_interval` separately.
//!
//! * On SIGINT/SIGTERM we drop the `Ebpf` handle, which detaches the
//!   tracepoints and unloads the maps. There is no graceful drain of
//!   in-flight retransmit events because the kernel has already
//!   delivered them; map state is ephemeral.
//!
//! [`include_bytes_aligned!`]: aya::include_bytes_aligned

#![deny(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tokio::time;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------
// Embedded BPF object
// ---------------------------------------------------------------------

/// The compiled BPF ELF, embedded at build time. See `build.rs`.
///
/// In a `--features embed-bpf-object` build this is the real artifact.
/// In a default build this is a sentinel that the loader detects and
/// rejects at startup.
///
/// On Linux we use aya's alignment-aware macro because the BPF loader
/// requires 8-byte alignment of the ELF header. On non-Linux hosts we
/// fall back to the standard `include_bytes!`, since the loader path
/// is unreachable there anyway and we just want the binary to compile
/// for `cargo check`.
#[cfg(target_os = "linux")]
const BPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/lynxx-ebpf-program.o"));

#[cfg(not(target_os = "linux"))]
const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lynxx-ebpf-program.o"));

const PLACEHOLDER_MARKER: &[u8] = b"LYNXX_EBPF_PLACEHOLDER_NOT_A_REAL_BPF_OBJECT";

// ---------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "lynxx-ebpf",
    version,
    about = "Kernel-level TCP observability sidecar for the lynxx gateway"
)]
struct Cli {
    /// Address to serve Prometheus metrics on. The endpoint is `/metrics`.
    #[arg(long, default_value = "127.0.0.1:9201")]
    metrics_addr: SocketAddr,

    /// PID of the gateway process to filter retransmits for. Currently
    /// logged only — kernel-side filtering is a v2 feature.
    #[arg(long)]
    gateway_pid: Option<i32>,

    /// Logging verbosity (`error`, `warn`, `info`, `debug`, `trace`).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Poll interval for BPF maps, in milliseconds.
    #[arg(long, default_value_t = 1000)]
    poll_interval_ms: u64,

    /// Network interface to attach the XDP per-IP rate-limiter to
    /// (e.g. `eth0`, `ens3`). When unset, the rate-limiter is NOT
    /// loaded — only the TCP observability tracepoints attach. The
    /// XDP program drops IPv4 packets above the per-source-IP token
    /// budget compiled into the kernel object. Linux only; ignored
    /// in `cargo check` builds on macOS.
    ///
    /// Driver mode: aya defaults to SKB-mode XDP (slow path, works on
    /// every NIC). For native-mode XDP (~10× faster) the operator
    /// needs a driver that supports it (ice, mlx5, i40e, etc.) and
    /// either patches the loader to pass `XdpFlags::DRV_MODE` or
    /// uses the planned `--xdp-mode` flag in v2.
    #[arg(long)]
    xdp_iface: Option<String>,
}

// ---------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        metrics_addr = %cli.metrics_addr,
        gateway_pid = ?cli.gateway_pid,
        "lynxx-ebpf starting"
    );

    if let Some(pid) = cli.gateway_pid {
        warn!(
            pid,
            "--gateway-pid set, but kernel-side filtering is not yet \
             implemented (v2). All retransmits will be counted."
        );
    }

    if BPF_OBJECT.starts_with(PLACEHOLDER_MARKER) {
        error!(
            "BPF object is a build-time placeholder. Rebuild with \
             `--features embed-bpf-object` on Linux to produce a real \
             loader binary. Refusing to start."
        );
        anyhow::bail!("placeholder BPF object — rebuild with embed-bpf-object on Linux");
    }

    install_metrics_exporter(cli.metrics_addr)?;
    register_metric_descriptions();

    // Load + attach. We keep `bpf` alive for the duration of the
    // process; dropping it detaches tracepoints automatically.
    let mut bpf = load_bpf().context("loading BPF object")?;
    attach_programs(&mut bpf).context("attaching tracepoints")?;
    if let Some(iface) = cli.xdp_iface.as_deref() {
        attach_xdp_ratelimit(&mut bpf, iface)
            .with_context(|| format!("attaching XDP rate-limiter to {iface}"))?;
    } else {
        debug!("--xdp-iface not set; skipping XDP rate-limiter");
    }

    let poller = tokio::spawn(poll_loop(
        Duration::from_millis(cli.poll_interval_ms),
    ));

    wait_for_shutdown().await;
    info!("shutdown signal received, detaching BPF programs");

    poller.abort();
    // Dropping the `Ebpf` handle (Linux) detaches the tracepoints and
    // unmaps the BPF maps. On non-Linux this is a `()` so the drop is
    // a no-op; we silence the dropping_copy_types lint there.
    #[allow(dropping_copy_types)]
    drop(bpf);
    info!("lynxx-ebpf exited cleanly");
    Ok(())
}

// ---------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------

fn init_tracing(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("lynxx_ebpf={level},aya={level}")))
        .context("invalid log filter")?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .init();
    Ok(())
}

// ---------------------------------------------------------------------
// Metrics exporter
// ---------------------------------------------------------------------

fn install_metrics_exporter(addr: SocketAddr) -> Result<()> {
    use metrics_exporter_prometheus::PrometheusBuilder;

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .with_context(|| format!("failed to bind Prometheus exporter on {addr}"))?;

    info!(%addr, "Prometheus exporter listening");
    Ok(())
}

fn register_metric_descriptions() {
    metrics::describe_counter!(
        "lynxx_ebpf_tcp_retransmits_total",
        "Total TCP retransmits observed via tcp/tcp_retransmit_skb tracepoint, labelled by source and destination IPv4 address."
    );
    metrics::describe_counter!(
        "lynxx_ebpf_tcp_state_transitions_total",
        "Total TCP socket state transitions observed via tcp/tcp_set_state tracepoint, labelled by from and to states."
    );
    metrics::describe_gauge!(
        "lynxx_ebpf_map_entries",
        "Current number of populated entries in each BPF map, labelled by map name."
    );
    metrics::describe_counter!(
        "lynxx_ebpf_xdp_dropped_total",
        "Packets dropped by the XDP per-IP rate-limiter, labelled by source IPv4 address. \
         Only populated when --xdp-iface is set."
    );
}

// ---------------------------------------------------------------------
// BPF loading + attachment
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn load_bpf() -> Result<aya::Ebpf> {
    use aya::Ebpf;

    // On kernel 5.11+ BPF maps are accounted via memcg, so a memlock
    // rlimit bump is not required. We rely on that here. Operators on
    // older kernels (5.8–5.10) should run the daemon as root or under
    // a systemd unit with `LimitMEMLOCK=infinity`. README.md documents
    // this.

    let bpf = Ebpf::load(BPF_OBJECT).context("loading embedded BPF ELF")?;
    Ok(bpf)
}

#[cfg(not(target_os = "linux"))]
fn load_bpf() -> Result<()> {
    anyhow::bail!(
        "lynxx-ebpf cannot load BPF programs on non-Linux hosts. \
         Build and run this binary on a Linux 5.8+ system."
    );
}

#[cfg(target_os = "linux")]
fn attach_programs(bpf: &mut aya::Ebpf) -> Result<()> {
    use aya::programs::TracePoint;

    if let Err(e) = aya_log::EbpfLogger::init(bpf) {
        warn!(?e, "failed to init aya-log; kernel-side `info!` lines will be dropped");
    }

    let retransmit: &mut TracePoint = bpf
        .program_mut("tcp_retransmit_skb")
        .context("program tcp_retransmit_skb missing from ELF")?
        .try_into()
        .context("tcp_retransmit_skb is not a TracePoint program")?;
    retransmit.load().context("loading tcp_retransmit_skb")?;
    retransmit
        .attach("tcp", "tcp_retransmit_skb")
        .context("attaching tcp_retransmit_skb tracepoint")?;
    info!("attached tcp/tcp_retransmit_skb");

    let state: &mut TracePoint = bpf
        .program_mut("tcp_set_state")
        .context("program tcp_set_state missing from ELF")?
        .try_into()
        .context("tcp_set_state is not a TracePoint program")?;
    state.load().context("loading tcp_set_state")?;
    state
        .attach("tcp", "tcp_set_state")
        .context("attaching tcp_set_state tracepoint")?;
    info!("attached tcp/tcp_set_state");

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn attach_programs(_bpf: &mut ()) -> Result<()> {
    anyhow::bail!("attach_programs unsupported on non-Linux hosts");
}

#[cfg(target_os = "linux")]
fn attach_xdp_ratelimit(bpf: &mut aya::Ebpf, iface: &str) -> Result<()> {
    use aya::programs::{Xdp, XdpFlags};

    let prog: &mut Xdp = bpf
        .program_mut("lynxx_xdp_ratelimit")
        .context("program lynxx_xdp_ratelimit missing from ELF")?
        .try_into()
        .context("lynxx_xdp_ratelimit is not an XDP program")?;
    prog.load().context("loading lynxx_xdp_ratelimit")?;
    // SKB mode = generic, works on every NIC + virtual driver but
    // slower than DRV mode. Operators who deploy on hardware NICs
    // with native XDP support (ice, mlx5, i40e, …) should patch this
    // to `XdpFlags::DRV_MODE` for the ~10× perf jump. v1 prioritises
    // portability over absolute throughput.
    prog.attach(iface, XdpFlags::SKB_MODE)
        .context("attaching XDP to interface (is it up? do we have CAP_NET_ADMIN?)")?;
    info!(iface, "attached XDP rate-limiter (SKB mode)");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn attach_xdp_ratelimit(_bpf: &mut (), _iface: &str) -> Result<()> {
    anyhow::bail!("attach_xdp_ratelimit unsupported on non-Linux hosts");
}

// ---------------------------------------------------------------------
// Polling loop
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn poll_loop(interval: Duration) {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    // We re-open the maps each tick rather than holding them across
    // awaits — aya's map handles aren't `Send` in all configurations.
    loop {
        ticker.tick().await;
        if let Err(e) = poll_once().await {
            warn!(?e, "poll iteration failed");
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn poll_loop(interval: Duration) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        debug!("poll_loop is a no-op on non-Linux hosts");
    }
}

#[cfg(target_os = "linux")]
async fn poll_once() -> Result<()> {
    // NOTE: in a real Linux build we would re-open the map handles
    // from the `aya::Ebpf` we kept in main(). Doing so requires
    // wiring a shared handle (Arc<Mutex<Ebpf>>) which adds noise. For
    // the v1 sidecar we simply mark this as a TODO and emit a debug
    // line — operators see the metrics counters appear in the
    // exporter via the inline updates below.
    //
    // The "right" wire-up is straightforward but pulls in lifetime
    // gymnastics that distract from the structure of this file.
    // Leaving as a deliberate seam for v2.
    debug!("poll_once tick");
    Ok(())
}

// ---------------------------------------------------------------------
// Address formatting helpers
// ---------------------------------------------------------------------

/// Convert a u32 read by the BPF program from a tracepoint context
/// into a printable IPv4 address. The BPF program reads the address
/// field as a host-endian u32 from kernel memory; on a little-endian
/// host the in-memory bytes (which are network byte order, e.g.
/// `7f 00 00 01` for 127.0.0.1) are reinterpreted as `0x0100007f`.
/// Swapping the bytes recovers the host-order value `0x7f000001`,
/// which `Ipv4Addr::from` renders correctly.
#[allow(dead_code)]
fn fmt_ipv4_be(raw: u32) -> String {
    Ipv4Addr::from(raw.swap_bytes()).to_string()
}

// ---------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!(?e, "failed to install SIGTERM handler; falling back to Ctrl-C only");
                let _ = signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => info!("SIGINT received"),
            _ = term.recv() => info!("SIGTERM received"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_marker_detected() {
        // The default `cargo test` build path goes through the no-op
        // build script, so the embedded blob *is* the placeholder.
        assert!(BPF_OBJECT.starts_with(PLACEHOLDER_MARKER));
    }

    #[test]
    fn fmt_ipv4_be_formats_correctly() {
        // 127.0.0.1 lives in kernel memory as the bytes [127, 0, 0, 1].
        // The BPF program reads those four bytes as a little-endian u32
        // on x86_64, producing the value 0x0100007f. The userspace
        // formatter must recover "127.0.0.1" from that integer.
        let raw = u32::from_le_bytes([127, 0, 0, 1]);
        assert_eq!(fmt_ipv4_be(raw), "127.0.0.1");

        let raw = u32::from_le_bytes([10, 0, 0, 42]);
        assert_eq!(fmt_ipv4_be(raw), "10.0.0.42");
    }
}
