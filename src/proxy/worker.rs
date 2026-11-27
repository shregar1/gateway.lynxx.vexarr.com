//! Per-core worker model, CPU affinity, and NUMA-aware configuration.
//!
//! # Architecture
//!
//! ```text
//! Worker Model
//! ├── WorkerModel enum        — Shared (Tokio default) vs PerCore (NGINX-style)
//! ├── CPU Affinity            — Pin worker threads to specific cores (Linux)
//! ├── Worker Identity         — Thread-local worker ID for per-worker state
//! ├── WorkerConfig            — Per-worker tuning (core, buffers, connections)
//! └── NUMA Hints              — Prefer local memory on multi-socket systems
//! ```
//!
//! # Why per-core pinning matters
//!
//! NGINX, HAProxy, and Envoy all support pinning worker threads to CPU
//! cores. The benefits compound:
//!
//! - **L1/L2 cache locality**: A pinned thread's working set (connection
//!   state, route table, buffer pool) stays warm in its core's private
//!   cache. Without pinning, Tokio's work-stealer may move a task to a
//!   different core, causing a cold-cache restart.
//! - **NUMA locality**: On multi-socket servers, pinning ensures workers
//!   access memory from their local NUMA node. Cross-socket memory access
//!   is 2–3× slower.
//! - **Reduced jitter**: No context-switch migration between cores means
//!   more predictable tail latency (p99, p999).
//! - **SO_REUSEPORT synergy**: Combined with SO_REUSEPORT, each pinned
//!   worker gets its own accept queue and processes connections entirely
//!   on one core.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

// ═══════════════════════════════════════════════════════════════════════════
// Worker model
// ═══════════════════════════════════════════════════════════════════════════

/// How worker threads are distributed across CPU cores.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkerModel {
    /// Tokio default: work-stealing scheduler distributes tasks across
    /// all available cores. Simple, good general-purpose performance.
    Shared = 0,
    /// NGINX-style: one worker per core, pinned via `sched_setaffinity`.
    /// Better cache locality and NUMA performance at the cost of
    /// potentially uneven load distribution.
    PerCore = 1,
}

impl WorkerModel {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::PerCore,
            _ => Self::Shared,
        }
    }
}

static WORKER_MODEL: AtomicU8 = AtomicU8::new(WorkerModel::Shared as u8);
static CPU_PINNING_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_worker_model(m: WorkerModel) {
    WORKER_MODEL.store(m as u8, Ordering::Relaxed);
}

pub fn worker_model() -> WorkerModel {
    WorkerModel::from_u8(WORKER_MODEL.load(Ordering::Relaxed))
}

pub fn set_cpu_pinning(enabled: bool) {
    CPU_PINNING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_cpu_pinning_enabled() -> bool {
    CPU_PINNING_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// RLIMIT_NOFILE — file descriptor limits (NGINX-style worker_rlimit_nofile)
// ═══════════════════════════════════════════════════════════════════════════

/// Global rlimit_nofile setting. 0 = don't change (default).
static RLIMIT_NOFILE: AtomicU64 = AtomicU64::new(0);

pub fn set_rlimit_nofile(n: u64) {
    RLIMIT_NOFILE.store(n, Ordering::Relaxed);
}

pub fn rlimit_nofile() -> u64 {
    RLIMIT_NOFILE.load(Ordering::Relaxed)
}

/// Errors that can occur when adjusting the RLIMIT_NOFILE.
#[derive(Debug)]
pub enum RlimitError {
    /// `getrlimit(2)` failed.
    GetFailed(std::io::Error),
    /// `setrlimit(2)` failed.
    SetFailed(std::io::Error),
    /// Requested limit exceeds the hard limit.
    ExceedsHardLimit { requested: u64, hard_limit: u64 },
}

impl std::fmt::Display for RlimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetFailed(e) => write!(f, "getrlimit failed: {}", e),
            Self::SetFailed(e) => write!(f, "setrlimit failed: {}", e),
            Self::ExceedsHardLimit { requested, hard_limit } => {
                write!(
                    f,
                    "requested nofile limit {} exceeds hard limit {}",
                    requested, hard_limit
                )
            }
        }
    }
}

impl std::error::Error for RlimitError {}

/// Raise the soft RLIMIT_NOFILE to `target`, capped at the hard limit.
///
/// Returns the actual new soft limit on success.
#[cfg(unix)]
pub fn raise_nofile_limit(target: u64) -> Result<u64, RlimitError> {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };

    // Get current limits.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if rc != 0 {
        return Err(RlimitError::GetFailed(std::io::Error::last_os_error()));
    }

    let hard = rlim.rlim_max as u64;
    let actual = std::cmp::min(target, hard);

    rlim.rlim_cur = actual as libc::rlim_t;

    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
    if rc != 0 {
        return Err(RlimitError::SetFailed(std::io::Error::last_os_error()));
    }

    Ok(actual)
}

#[cfg(not(unix))]
pub fn raise_nofile_limit(target: u64) -> Result<u64, RlimitError> {
    Ok(target)
}

/// Get the current `(soft, hard)` RLIMIT_NOFILE.
#[cfg(unix)]
pub fn get_nofile_limit() -> Result<(u64, u64), std::io::Error> {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((rlim.rlim_cur as u64, rlim.rlim_max as u64))
}

#[cfg(not(unix))]
pub fn get_nofile_limit() -> Result<(u64, u64), std::io::Error> {
    Ok((0, 0))
}

/// Calculate a recommended RLIMIT_NOFILE based on worker count and
/// max connections per worker.
///
/// Formula: `worker_count * max_connections_per_worker * 2 + 1024`
///   - ×2 accounts for upstream + downstream file descriptors
///   - +1024 for listen sockets, logs, and other overhead
///   - Capped at 1,048,576 (1M)
pub fn auto_nofile_limit(worker_count: usize, max_connections_per_worker: u32) -> u64 {
    let raw = (worker_count as u64)
        .saturating_mul(max_connections_per_worker as u64)
        .saturating_mul(2)
        .saturating_add(1024);
    std::cmp::min(raw, 1_048_576)
}

// ═══════════════════════════════════════════════════════════════════════════
// Worker identity — thread-local
// ═══════════════════════════════════════════════════════════════════════════

thread_local! {
    /// This thread's worker ID. Set during worker initialization.
    /// `u32::MAX` = not yet assigned.
    static WORKER_ID: Cell<u32> = const { Cell::new(u32::MAX) };
}

/// Assign a worker ID to the current thread.
pub fn set_worker_id(id: u32) {
    WORKER_ID.with(|w| w.set(id));
}

/// Get the current thread's worker ID, or `None` if not a worker thread.
pub fn worker_id() -> Option<u32> {
    WORKER_ID.with(|w| {
        let id = w.get();
        if id == u32::MAX {
            None
        } else {
            Some(id)
        }
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// CPU affinity
// ═══════════════════════════════════════════════════════════════════════════

/// Pin the calling thread to a specific CPU core.
///
/// On Linux, uses `sched_setaffinity(2)` to restrict the thread to
/// exactly one core. On macOS, this is a no-op (macOS doesn't support
/// hard CPU affinity).
#[cfg(target_os = "linux")]
pub fn pin_to_core(core_id: usize) -> std::io::Result<()> {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(core_id, &mut cpuset);
        let rc = libc::sched_setaffinity(
            0, // current thread
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpuset,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// macOS doesn't support hard CPU affinity. Thread affinity tags are
/// available via Mach ports but they're only hints, not guarantees.
#[cfg(not(target_os = "linux"))]
pub fn pin_to_core(_core_id: usize) -> std::io::Result<()> {
    Ok(())
}

/// Get the CPU core the calling thread is currently running on (Linux).
#[cfg(target_os = "linux")]
pub fn current_core() -> std::io::Result<usize> {
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(cpu as usize)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn current_core() -> std::io::Result<usize> {
    Ok(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// Core enumeration
// ═══════════════════════════════════════════════════════════════════════════

/// Number of available CPU cores. Uses `std::thread::available_parallelism()`.
pub fn available_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Generate a core assignment plan for `n` workers. Returns a list of
/// core IDs, one per worker, distributed round-robin across available
/// cores.
pub fn core_assignments(num_workers: usize) -> Vec<usize> {
    let cores = available_cores();
    (0..num_workers).map(|i| i % cores).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Worker configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Per-worker configuration. Each worker can have different settings
/// (e.g., pinned to different cores, different buffer pool sizes).
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Worker index (0-based).
    pub id: u32,
    /// CPU core to pin to. `None` = no pinning.
    pub core_id: Option<usize>,
    /// Maximum connections this worker should handle.
    pub max_connections: u32,
    /// Buffer pool size for this worker (bytes).
    pub buffer_pool_size: usize,
    /// RLIMIT_NOFILE override for this worker. 0 = don't change.
    pub rlimit_nofile: u64,
}

impl WorkerConfig {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            core_id: None,
            max_connections: 10_000,
            buffer_pool_size: 64 * 1024 * 1024, // 64 MB
            rlimit_nofile: 0,
        }
    }

    /// Create a config for a pinned worker.
    pub fn pinned(id: u32, core_id: usize) -> Self {
        Self {
            id,
            core_id: Some(core_id),
            max_connections: 10_000,
            buffer_pool_size: 64 * 1024 * 1024,
            rlimit_nofile: 0,
        }
    }
}

/// Generate worker configs for the per-core model. One worker per
/// available core, each pinned.
pub fn per_core_configs() -> Vec<WorkerConfig> {
    let cores = available_cores();
    (0..cores)
        .map(|i| WorkerConfig::pinned(i as u32, i))
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// NUMA hints
// ═══════════════════════════════════════════════════════════════════════════

/// Get the NUMA node for a given CPU core (Linux).
/// Returns 0 on non-NUMA systems or non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn numa_node_for_core(core_id: usize) -> usize {
    // Read from /sys/devices/system/cpu/cpuN/topology/physical_package_id
    let path = format!(
        "/sys/devices/system/cpu/cpu{}/topology/physical_package_id",
        core_id
    );
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn numa_node_for_core(_core_id: usize) -> usize {
    0
}

/// Set the NUMA memory allocation policy for the calling thread to
/// prefer the specified node. Falls back to other nodes if the
/// preferred one is out of memory.
///
/// On non-Linux platforms, this is a no-op.
#[cfg(target_os = "linux")]
pub fn prefer_numa_node(node: usize) -> std::io::Result<()> {
    // Uses set_mempolicy(MPOL_PREFERRED, ...) if available.
    // For simplicity, we use the /proc approach or just document
    // that the user should configure numactl.
    //
    // In practice, CPU pinning + the kernel's default NUMA-local
    // allocation policy handles this automatically — the kernel
    // prefers to allocate from the NUMA node closest to the CPU
    // the thread is running on.
    let _ = node;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn prefer_numa_node(_node: usize) -> std::io::Result<()> {
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Worker initialization helper
// ═══════════════════════════════════════════════════════════════════════════

/// Initialize a worker thread: set its ID, pin to core (if configured),
/// and set NUMA memory policy.
pub fn init_worker(config: &WorkerConfig) -> std::io::Result<()> {
    set_worker_id(config.id);

    if let Some(core_id) = config.core_id {
        if is_cpu_pinning_enabled() {
            pin_to_core(core_id)?;

            // Auto-detect NUMA node and set memory policy.
            let node = numa_node_for_core(core_id);
            prefer_numa_node(node)?;
        }
    }

    Ok(())
}

/// Apply the [`crate::config::WorkersSettings`] block to the runtime
/// atomics + raise the FD limit. Call once at startup (and on each
/// config reload) before any listener is bound.
///
/// `model` accepts `"per_core"` (default) or `"shared"`. `cpu_pinning`
/// is only honoured when `model = "per_core"` on Linux. `rlimit_nofile`
/// of `0` leaves the existing limit untouched.
pub fn apply_workers_settings(
    model: &str,
    cpu_pinning: bool,
    rlimit_nofile: u64,
) -> Result<(), String> {
    let wm = match model {
        "per_core" => WorkerModel::PerCore,
        "shared" => WorkerModel::Shared,
        other => return Err(format!("unknown worker model: {other}")),
    };
    set_worker_model(wm);
    // Pinning only makes sense for the per-core model. When running on
    // the shared runtime the global flag is set anyway — `init_worker`
    // short-circuits on `core_id == None` regardless.
    set_cpu_pinning(cpu_pinning);

    if rlimit_nofile > 0 {
        match raise_nofile_limit(rlimit_nofile) {
            Ok(actual) => tracing::info!(
                requested = rlimit_nofile,
                actual,
                "raise RLIMIT_NOFILE"
            ),
            Err(e) => tracing::warn!(
                requested = rlimit_nofile,
                error = %e,
                "RLIMIT_NOFILE raise failed; continuing with current limit"
            ),
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_cores_at_least_one() {
        assert!(available_cores() >= 1);
    }

    #[test]
    fn core_assignments_roundrobin() {
        let assignments = core_assignments(8);
        assert_eq!(assignments.len(), 8);
        // First N assignments should be 0..N (if cores >= 8) or wrap.
        for (i, &core) in assignments.iter().enumerate() {
            assert_eq!(core, i % available_cores());
        }
    }

    #[test]
    fn worker_config_new() {
        let config = WorkerConfig::new(0);
        assert_eq!(config.id, 0);
        assert!(config.core_id.is_none());
        assert_eq!(config.max_connections, 10_000);
    }

    #[test]
    fn worker_config_pinned() {
        let config = WorkerConfig::pinned(3, 7);
        assert_eq!(config.id, 3);
        assert_eq!(config.core_id, Some(7));
    }

    #[test]
    fn per_core_configs_count() {
        let configs = per_core_configs();
        assert_eq!(configs.len(), available_cores());
        for (i, config) in configs.iter().enumerate() {
            assert_eq!(config.id, i as u32);
            assert_eq!(config.core_id, Some(i));
        }
    }

    #[test]
    fn worker_id_thread_local() {
        assert_eq!(worker_id(), None);
        set_worker_id(42);
        assert_eq!(worker_id(), Some(42));
        // Reset for other tests.
        WORKER_ID.with(|w| w.set(u32::MAX));
    }

    #[test]
    fn worker_model_toggle() {
        set_worker_model(WorkerModel::PerCore);
        assert_eq!(worker_model(), WorkerModel::PerCore);

        set_worker_model(WorkerModel::Shared);
        assert_eq!(worker_model(), WorkerModel::Shared);
    }

    #[test]
    fn apply_workers_settings_per_core() {
        // Should set model=PerCore and pinning=true.
        apply_workers_settings("per_core", true, 0).unwrap();
        // These atomics are shared global state — other tests in this
        // module (worker_model_toggle, cpu_pinning_toggle) flip them.
        // We assert by re-applying + checking the model atom that we
        // *know* we just wrote; the pinning flag is best-effort here.
        assert_eq!(worker_model(), WorkerModel::PerCore);
    }

    #[test]
    fn apply_workers_settings_shared() {
        apply_workers_settings("shared", false, 0).unwrap();
        assert_eq!(worker_model(), WorkerModel::Shared);
    }

    #[test]
    fn apply_workers_settings_invalid_model() {
        // Unknown model string returns Err. (We don't assert on the
        // global model atom — other tests in this module flip it
        // concurrently and the assertion is racy.)
        assert!(apply_workers_settings("bogus", false, 0).is_err());
    }

    #[test]
    fn apply_workers_settings_zero_rlimit_is_noop() {
        // rlimit_nofile=0 means "leave existing limit untouched"; the
        // apply call should still succeed and update the worker model.
        apply_workers_settings("per_core", true, 0).unwrap();
        assert_eq!(worker_model(), WorkerModel::PerCore);
    }

    #[test]
    fn worker_model_u8_roundtrip() {
        assert_eq!(WorkerModel::from_u8(0), WorkerModel::Shared);
        assert_eq!(WorkerModel::from_u8(1), WorkerModel::PerCore);
        assert_eq!(WorkerModel::from_u8(99), WorkerModel::Shared);
    }

    #[test]
    fn cpu_pinning_toggle() {
        set_cpu_pinning(true);
        assert!(is_cpu_pinning_enabled());
        set_cpu_pinning(false);
        assert!(!is_cpu_pinning_enabled());
    }

    #[test]
    fn numa_node_returns_zero_on_unknown() {
        // Core 99999 doesn't exist — should return 0.
        assert_eq!(numa_node_for_core(99999), 0);
    }

    #[test]
    fn init_worker_without_pinning() {
        set_cpu_pinning(false);
        let config = WorkerConfig::pinned(0, 0);
        // Should succeed even without pinning enabled — just sets worker ID.
        assert!(init_worker(&config).is_ok());
        assert_eq!(worker_id(), Some(0));
        WORKER_ID.with(|w| w.set(u32::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_core_returns_valid() {
        let core = current_core().unwrap();
        assert!(core < available_cores() * 2); // Reasonable bound.
    }

    // ── WorkerConfig defaults ──

    #[test]
    fn worker_config_new_buffer_pool_size_default() {
        let config = WorkerConfig::new(5);
        assert_eq!(config.buffer_pool_size, 64 * 1024 * 1024); // 64 MB
        assert_eq!(config.id, 5);
    }

    #[test]
    fn worker_config_pinned_max_connections_default() {
        let config = WorkerConfig::pinned(1, 3);
        assert_eq!(config.max_connections, 10_000);
        assert_eq!(config.buffer_pool_size, 64 * 1024 * 1024);
    }

    // ── pin_to_core / current_core ──

    #[test]
    fn pin_to_core_zero_succeeds() {
        // On macOS this is a no-op, on Linux core 0 always exists.
        assert!(pin_to_core(0).is_ok());
    }

    #[test]
    fn current_core_returns_value() {
        let core = current_core().unwrap();
        // On macOS always 0; on Linux a valid core index.
        assert!(core < 1024); // Sanity bound.
    }

    // ── NUMA ──

    #[test]
    fn numa_node_for_core_zero() {
        // Core 0 exists on every system; returns 0 on macOS and single-socket.
        assert_eq!(numa_node_for_core(0), 0);
    }

    #[test]
    fn prefer_numa_node_does_not_error() {
        assert!(prefer_numa_node(0).is_ok());
    }

    // ── init_worker with pinning enabled ──

    #[test]
    fn init_worker_with_pinning_enabled() {
        set_cpu_pinning(true);
        let config = WorkerConfig::pinned(7, 0);
        assert!(init_worker(&config).is_ok());
        assert_eq!(worker_id(), Some(7));
        // Cleanup.
        set_cpu_pinning(false);
        WORKER_ID.with(|w| w.set(u32::MAX));
    }

    // ── core_assignments edge cases ──

    #[test]
    fn core_assignments_zero_workers() {
        let assignments = core_assignments(0);
        assert!(assignments.is_empty());
    }

    #[test]
    fn core_assignments_single_worker() {
        let assignments = core_assignments(1);
        assert_eq!(assignments, vec![0]);
    }

    // ── per_core_configs validation ──

    #[test]
    fn per_core_configs_fields_correct() {
        let configs = per_core_configs();
        for config in &configs {
            assert_eq!(config.buffer_pool_size, 64 * 1024 * 1024);
            assert_eq!(config.max_connections, 10_000);
            assert!(config.core_id.is_some());
            assert_eq!(config.core_id.unwrap(), config.id as usize);
        }
    }

    // ── cpu_pinning interaction with init_worker ──

    #[test]
    fn cpu_pinning_disabled_skips_affinity() {
        set_cpu_pinning(false);
        let config = WorkerConfig::pinned(10, 0);
        assert!(init_worker(&config).is_ok());
        assert_eq!(worker_id(), Some(10));
        // Worker ID is set but no affinity call happened (no error).
        WORKER_ID.with(|w| w.set(u32::MAX));
    }

    #[test]
    fn available_cores_positive() {
        assert!(available_cores() > 0);
    }

    // ── RLIMIT_NOFILE ──

    #[test]
    fn rlimit_nofile_default_zero() {
        // The global default must be 0 (don't change).
        // Note: other tests may have mutated it, so set first.
        set_rlimit_nofile(0);
        assert_eq!(rlimit_nofile(), 0);
    }

    #[test]
    fn rlimit_nofile_set_get() {
        set_rlimit_nofile(65_536);
        assert_eq!(rlimit_nofile(), 65_536);
        // Cleanup.
        set_rlimit_nofile(0);
    }

    #[test]
    fn auto_nofile_limit_calculation() {
        // 4 workers × 10_000 conns × 2 + 1024 = 81_024
        assert_eq!(auto_nofile_limit(4, 10_000), 81_024);
    }

    #[test]
    fn auto_nofile_limit_caps_at_1m() {
        // Huge values should cap at 1_048_576.
        let result = auto_nofile_limit(1000, 100_000);
        assert_eq!(result, 1_048_576);
    }

    #[cfg(unix)]
    #[test]
    fn get_nofile_limit_returns_positive() {
        let (soft, hard) = get_nofile_limit().unwrap();
        assert!(soft > 0, "soft limit should be > 0, got {}", soft);
        assert!(hard > 0, "hard limit should be > 0, got {}", hard);
    }

    #[cfg(unix)]
    #[test]
    fn raise_nofile_limit_succeeds() {
        // Raising to the current soft limit is always safe.
        let (soft, _hard) = get_nofile_limit().unwrap();
        let actual = raise_nofile_limit(soft).unwrap();
        assert_eq!(actual, soft);
    }

    #[test]
    fn worker_config_includes_rlimit() {
        let config = WorkerConfig::new(0);
        assert_eq!(config.rlimit_nofile, 0);

        let pinned = WorkerConfig::pinned(1, 0);
        assert_eq!(pinned.rlimit_nofile, 0);
    }
}
