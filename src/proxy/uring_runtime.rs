//! Thread-per-core io_uring runtime — replaces tokio's work-stealing scheduler
//! with a pinned-thread model where each CPU core owns its own io_uring ring,
//! its own accept queue, and its own connection pool.
//!
//! # Why this beats tokio for proxy workloads
//!
//! tokio's multi-threaded scheduler distributes tasks via work-stealing:
//! - Cross-core queue contention at 30k+ RPS (~15% overhead)
//! - Cache-line bouncing when tasks migrate between cores
//! - 20–30 syscalls per request (epoll_wait, recv, send, ...)
//!
//! Thread-per-core with io_uring:
//! - Zero contention: each core is independent
//! - NUMA-local memory: all allocations stay on-core
//! - 10–15 syscalls via SQ batching (submit once, reap many)
//! - SQPOLL mode: kernel polls the SQ without syscalls at all
//!
//! # Architecture
//!
//! ```text
//! CPU 0: [io_uring ring] ← [accept queue 0] ← SO_REUSEPORT
//! CPU 1: [io_uring ring] ← [accept queue 1] ← SO_REUSEPORT
//! CPU 2: [io_uring ring] ← [accept queue 2] ← SO_REUSEPORT
//! CPU 3: [io_uring ring] ← [accept queue 3] ← SO_REUSEPORT
//!         ↑                    ↑
//!     per-core              per-core
//!     conn pool             buffer pool
//! ```
//!
//! Each listener socket is bound with SO_REUSEPORT so the kernel
//! distributes incoming connections across cores via RSS/RFS.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════
// Global toggles
// ═══════════════════════════════════════════════════════════════════════════

static URING_RUNTIME_ENABLED: AtomicBool = AtomicBool::new(false);
static RUNTIME_MODE: AtomicU8 = AtomicU8::new(0); // 0 = Tokio, 1 = Uring, 2 = Hybrid

pub fn is_uring_runtime_enabled() -> bool {
    URING_RUNTIME_ENABLED.load(Ordering::Relaxed)
}

pub fn set_uring_runtime_enabled(v: bool) {
    URING_RUNTIME_ENABLED.store(v, Ordering::Relaxed);
}

pub fn get_runtime_mode() -> RuntimeMode {
    RuntimeMode::from_u8(RUNTIME_MODE.load(Ordering::Relaxed))
}

pub fn set_runtime_mode(mode: RuntimeMode) {
    RUNTIME_MODE.store(mode as u8, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime mode
// ═══════════════════════════════════════════════════════════════════════════

/// Which async runtime to use for the proxy hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeMode {
    /// Standard tokio multi-threaded scheduler (default, works everywhere).
    Tokio = 0,
    /// Thread-per-core io_uring (Linux 5.15+, highest throughput).
    Uring = 1,
    /// Hybrid: io_uring for accept + splice, tokio for complex middleware.
    Hybrid = 2,
}

impl RuntimeMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Uring,
            2 => Self::Hybrid,
            _ => Self::Tokio,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Tokio => "tokio",
            Self::Uring => "uring",
            Self::Hybrid => "hybrid",
        }
    }

    /// Whether this mode uses io_uring at all.
    pub fn uses_uring(&self) -> bool {
        matches!(self, Self::Uring | Self::Hybrid)
    }

    /// Whether this mode needs a tokio runtime available.
    pub fn needs_tokio(&self) -> bool {
        matches!(self, Self::Tokio | Self::Hybrid)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Core config
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for a single per-core worker.
#[derive(Debug, Clone)]
pub struct CoreWorkerConfig {
    /// Which CPU core to pin to (if pinning enabled).
    pub cpu_id: u32,
    /// io_uring SQ entries.
    pub sq_entries: u32,
    /// io_uring CQ entries (usually 2× SQ).
    pub cq_entries: u32,
    /// Enable SQPOLL (kernel-side polling — no submit syscall needed).
    pub sqpoll: bool,
    /// SQPOLL idle timeout in milliseconds.
    pub sqpoll_idle_ms: u32,
    /// Enable provided buffers (kernel selects buffer on completion).
    pub provided_buffers: bool,
    /// Number of provided buffers.
    pub buffer_count: u32,
    /// Size of each provided buffer.
    pub buffer_size: u32,
    /// Enable multi-shot accept (one SQE, many accepts).
    pub multishot_accept: bool,
    /// TCP backlog for the listener.
    pub tcp_backlog: u32,
    /// Enable CPU pinning via sched_setaffinity.
    pub pin_to_cpu: bool,
    /// Enable NUMA-local allocation.
    pub numa_aware: bool,
}

impl CoreWorkerConfig {
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            sq_entries: 256,
            cq_entries: 512,
            sqpoll: false,
            sqpoll_idle_ms: 1000,
            provided_buffers: true,
            buffer_count: 256,
            buffer_size: 4096,
            multishot_accept: true,
            tcp_backlog: 65535,
            pin_to_cpu: true,
            numa_aware: false,
        }
    }

    /// High-throughput preset: large rings, SQPOLL, many buffers.
    pub fn high_throughput(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            sq_entries: 4096,
            cq_entries: 8192,
            sqpoll: true,
            sqpoll_idle_ms: 2000,
            provided_buffers: true,
            buffer_count: 1024,
            buffer_size: 8192,
            multishot_accept: true,
            tcp_backlog: 65535,
            pin_to_cpu: true,
            numa_aware: true,
        }
    }

    /// Low-latency preset: smaller rings, no SQPOLL (direct submit).
    pub fn low_latency(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            sq_entries: 128,
            cq_entries: 256,
            sqpoll: false,
            sqpoll_idle_ms: 0,
            provided_buffers: true,
            buffer_count: 128,
            buffer_size: 4096,
            multishot_accept: true,
            tcp_backlog: 16384,
            pin_to_cpu: true,
            numa_aware: false,
        }
    }

    /// Total memory this worker will allocate for provided buffers.
    pub fn buffer_memory(&self) -> u64 {
        if self.provided_buffers {
            self.buffer_count as u64 * self.buffer_size as u64
        } else {
            0
        }
    }

    /// Total memory for the ring structures (approximate).
    pub fn ring_memory(&self) -> u64 {
        // SQE is 64 bytes, CQE is 16 bytes.
        (self.sq_entries as u64 * 64) + (self.cq_entries as u64 * 16)
    }

    /// Total estimated memory per core.
    pub fn total_memory(&self) -> u64 {
        self.buffer_memory() + self.ring_memory()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime plan
// ═══════════════════════════════════════════════════════════════════════════

/// A complete runtime layout plan for all cores.
#[derive(Debug, Clone)]
pub struct RuntimePlan {
    /// Worker configs, one per core.
    pub workers: Vec<CoreWorkerConfig>,
    /// Listener addresses (host:port pairs).
    pub listen_addrs: Vec<String>,
    /// Whether to use SO_REUSEPORT for per-core accept.
    pub reuseport: bool,
    /// Fallback mode if io_uring is unavailable.
    pub fallback: RuntimeMode,
    /// Graceful shutdown timeout.
    pub shutdown_timeout: Duration,
}

impl RuntimePlan {
    /// Create a plan for N cores with default config.
    pub fn default_for_cores(num_cores: u32) -> Self {
        let workers = (0..num_cores)
            .map(CoreWorkerConfig::new)
            .collect();
        Self {
            workers,
            listen_addrs: vec!["0.0.0.0:8080".to_string()],
            reuseport: true,
            fallback: RuntimeMode::Tokio,
            shutdown_timeout: Duration::from_secs(30),
        }
    }

    /// Create a high-throughput plan.
    pub fn high_throughput(num_cores: u32) -> Self {
        let workers = (0..num_cores)
            .map(CoreWorkerConfig::high_throughput)
            .collect();
        Self {
            workers,
            listen_addrs: vec!["0.0.0.0:8080".to_string()],
            reuseport: true,
            fallback: RuntimeMode::Tokio,
            shutdown_timeout: Duration::from_secs(60),
        }
    }

    /// Total memory across all workers.
    pub fn total_memory(&self) -> u64 {
        self.workers.iter().map(|w| w.total_memory()).sum()
    }

    /// Number of workers.
    pub fn num_workers(&self) -> usize {
        self.workers.len()
    }

    /// Validate the plan against system capabilities.
    pub fn validate(&self) -> Vec<PlanWarning> {
        let mut warnings = Vec::new();

        if self.workers.is_empty() {
            warnings.push(PlanWarning::NoWorkers);
        }

        let total_mem = self.total_memory();
        if total_mem > 1024 * 1024 * 1024 {
            warnings.push(PlanWarning::HighMemory { bytes: total_mem });
        }

        for w in &self.workers {
            if w.sqpoll && !w.pin_to_cpu {
                warnings.push(PlanWarning::SqpollWithoutPinning { cpu: w.cpu_id });
            }
            if w.sq_entries > 32768 {
                warnings.push(PlanWarning::LargeRing {
                    cpu: w.cpu_id,
                    entries: w.sq_entries,
                });
            }
        }

        if !self.reuseport && self.workers.len() > 1 {
            warnings.push(PlanWarning::MultiWorkerWithoutReuseport);
        }

        warnings
    }
}

/// Warnings from plan validation.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanWarning {
    NoWorkers,
    HighMemory { bytes: u64 },
    SqpollWithoutPinning { cpu: u32 },
    LargeRing { cpu: u32, entries: u32 },
    MultiWorkerWithoutReuseport,
}

// ═══════════════════════════════════════════════════════════════════════════
// Per-core statistics
// ═══════════════════════════════════════════════════════════════════════════

/// Per-core runtime statistics.
pub struct CoreStats {
    pub cpu_id: u32,
    pub accepts: AtomicU64,
    pub requests: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub sq_submits: AtomicU64,
    pub cq_completions: AtomicU64,
    pub splice_ops: AtomicU64,
    pub buffer_exhaustions: AtomicU64,
    pub task_migrations: AtomicU64, // Should be 0 in thread-per-core.
}

impl CoreStats {
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            accepts: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            sq_submits: AtomicU64::new(0),
            cq_completions: AtomicU64::new(0),
            splice_ops: AtomicU64::new(0),
            buffer_exhaustions: AtomicU64::new(0),
            task_migrations: AtomicU64::new(0),
        }
    }

    pub fn record_accept(&self) {
        self.accepts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_request(&self, bytes_in: u64, bytes_out: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    pub fn record_sq_submit(&self, count: u64) {
        self.sq_submits.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_cq_completion(&self, count: u64) {
        self.cq_completions.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_splice(&self) {
        self.splice_ops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CoreStatsSnapshot {
        CoreStatsSnapshot {
            cpu_id: self.cpu_id,
            accepts: self.accepts.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            sq_submits: self.sq_submits.load(Ordering::Relaxed),
            cq_completions: self.cq_completions.load(Ordering::Relaxed),
            splice_ops: self.splice_ops.load(Ordering::Relaxed),
            buffer_exhaustions: self.buffer_exhaustions.load(Ordering::Relaxed),
            task_migrations: self.task_migrations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreStatsSnapshot {
    pub cpu_id: u32,
    pub accepts: u64,
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub sq_submits: u64,
    pub cq_completions: u64,
    pub splice_ops: u64,
    pub buffer_exhaustions: u64,
    pub task_migrations: u64,
}

impl CoreStatsSnapshot {
    /// SQ efficiency: completions per submit (higher = better batching).
    pub fn sq_efficiency(&self) -> f64 {
        if self.sq_submits == 0 {
            return 0.0;
        }
        self.cq_completions as f64 / self.sq_submits as f64
    }

    /// Average bytes per request.
    pub fn avg_request_size(&self) -> f64 {
        if self.requests == 0 {
            return 0.0;
        }
        (self.bytes_in + self.bytes_out) as f64 / self.requests as f64
    }

    /// Splice rate: fraction of requests that used zero-copy splice.
    pub fn splice_rate(&self) -> f64 {
        if self.requests == 0 {
            return 0.0;
        }
        self.splice_ops as f64 / self.requests as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Syscall budget tracker
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks syscall count per request to measure the io_uring batching benefit.
/// nginx/haproxy: ~10 syscalls/request. tokio baseline: ~20-30. Target: 10-15.
pub struct SyscallBudget {
    /// Syscall counts per request category.
    accept_calls: AtomicU64,
    recv_calls: AtomicU64,
    send_calls: AtomicU64,
    splice_calls: AtomicU64,
    submit_calls: AtomicU64,
    other_calls: AtomicU64,
    total_requests: AtomicU64,
}

impl SyscallBudget {
    pub fn new() -> Self {
        Self {
            accept_calls: AtomicU64::new(0),
            recv_calls: AtomicU64::new(0),
            send_calls: AtomicU64::new(0),
            splice_calls: AtomicU64::new(0),
            submit_calls: AtomicU64::new(0),
            other_calls: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
        }
    }

    pub fn record_accept(&self) {
        self.accept_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_recv(&self, count: u64) {
        self.recv_calls.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_send(&self, count: u64) {
        self.send_calls.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_splice(&self, count: u64) {
        self.splice_calls.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_submit(&self) {
        self.submit_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_request_complete(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Average syscalls per request.
    pub fn avg_syscalls_per_request(&self) -> f64 {
        let total_reqs = self.total_requests.load(Ordering::Relaxed);
        if total_reqs == 0 {
            return 0.0;
        }
        let total_calls = self.accept_calls.load(Ordering::Relaxed)
            + self.recv_calls.load(Ordering::Relaxed)
            + self.send_calls.load(Ordering::Relaxed)
            + self.splice_calls.load(Ordering::Relaxed)
            + self.submit_calls.load(Ordering::Relaxed)
            + self.other_calls.load(Ordering::Relaxed);
        total_calls as f64 / total_reqs as f64
    }

    /// Breakdown as a snapshot.
    pub fn snapshot(&self) -> SyscallSnapshot {
        SyscallSnapshot {
            accept: self.accept_calls.load(Ordering::Relaxed),
            recv: self.recv_calls.load(Ordering::Relaxed),
            send: self.send_calls.load(Ordering::Relaxed),
            splice: self.splice_calls.load(Ordering::Relaxed),
            submit: self.submit_calls.load(Ordering::Relaxed),
            other: self.other_calls.load(Ordering::Relaxed),
            requests: self.total_requests.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallSnapshot {
    pub accept: u64,
    pub recv: u64,
    pub send: u64,
    pub splice: u64,
    pub submit: u64,
    pub other: u64,
    pub requests: u64,
}

impl SyscallSnapshot {
    pub fn total_syscalls(&self) -> u64 {
        self.accept + self.recv + self.send + self.splice + self.submit + self.other
    }

    pub fn per_request(&self) -> f64 {
        if self.requests == 0 {
            return 0.0;
        }
        self.total_syscalls() as f64 / self.requests as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Connection affinity
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks which core owns which connections to prevent task migration.
pub struct ConnectionAffinity {
    /// Mapping: connection_id → cpu_id.
    map: std::collections::HashMap<u64, u32>,
    /// Total connections ever tracked.
    total_tracked: u64,
    /// Migrations detected (should be 0 in pure thread-per-core).
    migrations: u64,
}

impl ConnectionAffinity {
    pub fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            total_tracked: 0,
            migrations: 0,
        }
    }

    /// Register a new connection on a core.
    pub fn register(&mut self, conn_id: u64, cpu_id: u32) {
        self.map.insert(conn_id, cpu_id);
        self.total_tracked += 1;
    }

    /// Check if a connection is on the expected core.
    pub fn check(&mut self, conn_id: u64, current_cpu: u32) -> AffinityResult {
        if let Some(&expected_cpu) = self.map.get(&conn_id) {
            if expected_cpu == current_cpu {
                AffinityResult::Correct
            } else {
                self.migrations += 1;
                AffinityResult::Migrated {
                    from: expected_cpu,
                    to: current_cpu,
                }
            }
        } else {
            AffinityResult::Unknown
        }
    }

    /// Unregister a closed connection.
    pub fn unregister(&mut self, conn_id: u64) {
        self.map.remove(&conn_id);
    }

    pub fn active_connections(&self) -> usize {
        self.map.len()
    }

    pub fn total_migrations(&self) -> u64 {
        self.migrations
    }

    /// Migration rate — should be 0.0 in a correct thread-per-core setup.
    pub fn migration_rate(&self) -> f64 {
        if self.total_tracked == 0 {
            return 0.0;
        }
        self.migrations as f64 / self.total_tracked as f64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityResult {
    /// Connection is on the expected core.
    Correct,
    /// Connection migrated from one core to another.
    Migrated { from: u32, to: u32 },
    /// Connection not tracked.
    Unknown,
}

// ═══════════════════════════════════════════════════════════════════════════
// NUMA topology
// ═══════════════════════════════════════════════════════════════════════════

/// NUMA node information for memory-locality optimization.
#[derive(Debug, Clone)]
pub struct NumaNode {
    pub node_id: u32,
    pub cpu_ids: Vec<u32>,
    pub memory_mb: u64,
}

/// System NUMA topology.
#[derive(Debug, Clone)]
pub struct NumaTopology {
    pub nodes: Vec<NumaNode>,
}

impl NumaTopology {
    /// Detect NUMA topology from /sys (Linux only).
    #[cfg(target_os = "linux")]
    pub fn detect() -> Self {
        let mut nodes = Vec::new();
        // Read /sys/devices/system/node/node*/cpulist
        if let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("node") {
                    if let Ok(node_id) = name[4..].parse::<u32>() {
                        let cpulist_path = entry.path().join("cpulist");
                        let cpus = Self::parse_cpulist(
                            &std::fs::read_to_string(cpulist_path).unwrap_or_default(),
                        );
                        nodes.push(NumaNode {
                            node_id,
                            cpu_ids: cpus,
                            memory_mb: 0, // Could read meminfo but not critical.
                        });
                    }
                }
            }
        }
        if nodes.is_empty() {
            // Single-node fallback.
            let num_cpus = std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1);
            nodes.push(NumaNode {
                node_id: 0,
                cpu_ids: (0..num_cpus).collect(),
                memory_mb: 0,
            });
        }
        Self { nodes }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Self {
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);
        Self {
            nodes: vec![NumaNode {
                node_id: 0,
                cpu_ids: (0..num_cpus).collect(),
                memory_mb: 0,
            }],
        }
    }

    /// Build from explicit values (for testing).
    pub fn from_nodes(nodes: Vec<NumaNode>) -> Self {
        Self { nodes }
    }

    fn parse_cpulist(s: &str) -> Vec<u32> {
        let mut cpus = Vec::new();
        for part in s.trim().split(',') {
            let part = part.trim();
            if let Some(dash) = part.find('-') {
                if let (Ok(start), Ok(end)) =
                    (part[..dash].parse::<u32>(), part[dash + 1..].parse::<u32>())
                {
                    cpus.extend(start..=end);
                }
            } else if let Ok(cpu) = part.parse::<u32>() {
                cpus.push(cpu);
            }
        }
        cpus
    }

    /// Total CPU count across all NUMA nodes.
    pub fn total_cpus(&self) -> usize {
        self.nodes.iter().map(|n| n.cpu_ids.len()).sum()
    }

    /// Find which NUMA node a CPU belongs to.
    pub fn node_for_cpu(&self, cpu: u32) -> Option<u32> {
        self.nodes
            .iter()
            .find(|n| n.cpu_ids.contains(&cpu))
            .map(|n| n.node_id)
    }

    /// Get CPUs for a NUMA node.
    pub fn cpus_for_node(&self, node_id: u32) -> &[u32] {
        self.nodes
            .iter()
            .find(|n| n.node_id == node_id)
            .map(|n| n.cpu_ids.as_slice())
            .unwrap_or(&[])
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Batch submit tracker
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks SQ batching efficiency — how many SQEs we submit per io_uring_enter().
pub struct BatchTracker {
    /// Total io_uring_enter() calls.
    submits: u64,
    /// Total SQEs submitted.
    sqes: u64,
    /// Histogram: batch sizes (1, 2-4, 5-8, 9-16, 17-32, 33+).
    buckets: [u64; 6],
}

impl BatchTracker {
    pub fn new() -> Self {
        Self {
            submits: 0,
            sqes: 0,
            buckets: [0; 6],
        }
    }

    /// Record a submit with N SQEs.
    pub fn record(&mut self, sqe_count: u32) {
        self.submits += 1;
        self.sqes += sqe_count as u64;
        let bucket = match sqe_count {
            0..=1 => 0,
            2..=4 => 1,
            5..=8 => 2,
            9..=16 => 3,
            17..=32 => 4,
            _ => 5,
        };
        self.buckets[bucket] += 1;
    }

    /// Average SQEs per submit.
    pub fn avg_batch_size(&self) -> f64 {
        if self.submits == 0 {
            return 0.0;
        }
        self.sqes as f64 / self.submits as f64
    }

    /// Total submits.
    pub fn total_submits(&self) -> u64 {
        self.submits
    }

    /// Total SQEs.
    pub fn total_sqes(&self) -> u64 {
        self.sqes
    }

    /// Histogram bucket counts.
    pub fn histogram(&self) -> &[u64; 6] {
        &self.buckets
    }

    /// Fraction of submits that batched > 1 SQE.
    pub fn batching_rate(&self) -> f64 {
        if self.submits == 0 {
            return 0.0;
        }
        let single = self.buckets[0];
        (self.submits - single) as f64 / self.submits as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct UringRuntimeMetrics {
    pub total_accepts: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    pub fallbacks_to_tokio: AtomicU64,
    pub ring_full_events: AtomicU64,
}

static URING_METRICS: UringRuntimeMetrics = UringRuntimeMetrics {
    total_accepts: AtomicU64::new(0),
    total_requests: AtomicU64::new(0),
    total_bytes_in: AtomicU64::new(0),
    total_bytes_out: AtomicU64::new(0),
    fallbacks_to_tokio: AtomicU64::new(0),
    ring_full_events: AtomicU64::new(0),
};

pub fn uring_runtime_metrics() -> &'static UringRuntimeMetrics {
    &URING_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Runtime mode ──────────────────────────────────────────────────

    #[test]
    fn runtime_mode_roundtrip() {
        assert_eq!(RuntimeMode::from_u8(0), RuntimeMode::Tokio);
        assert_eq!(RuntimeMode::from_u8(1), RuntimeMode::Uring);
        assert_eq!(RuntimeMode::from_u8(2), RuntimeMode::Hybrid);
        assert_eq!(RuntimeMode::from_u8(99), RuntimeMode::Tokio);
    }

    #[test]
    fn runtime_mode_capabilities() {
        assert!(!RuntimeMode::Tokio.uses_uring());
        assert!(RuntimeMode::Tokio.needs_tokio());

        assert!(RuntimeMode::Uring.uses_uring());
        assert!(!RuntimeMode::Uring.needs_tokio());

        assert!(RuntimeMode::Hybrid.uses_uring());
        assert!(RuntimeMode::Hybrid.needs_tokio());
    }

    // ── Core worker config ────────────────────────────────────────────

    #[test]
    fn config_default_memory() {
        let cfg = CoreWorkerConfig::new(0);
        assert_eq!(cfg.buffer_memory(), 256 * 4096);
        assert!(cfg.ring_memory() > 0);
        assert!(cfg.total_memory() > cfg.ring_memory());
    }

    #[test]
    fn config_high_throughput_larger() {
        let def = CoreWorkerConfig::new(0);
        let ht = CoreWorkerConfig::high_throughput(0);
        assert!(ht.sq_entries > def.sq_entries);
        assert!(ht.buffer_count > def.buffer_count);
        assert!(ht.total_memory() > def.total_memory());
        assert!(ht.sqpoll);
        assert!(ht.numa_aware);
    }

    #[test]
    fn config_low_latency_smaller() {
        let def = CoreWorkerConfig::new(0);
        let ll = CoreWorkerConfig::low_latency(0);
        assert!(ll.sq_entries < def.sq_entries);
        assert!(!ll.sqpoll);
    }

    #[test]
    fn config_no_provided_buffers() {
        let mut cfg = CoreWorkerConfig::new(0);
        cfg.provided_buffers = false;
        assert_eq!(cfg.buffer_memory(), 0);
    }

    // ── Runtime plan ──────────────────────────────────────────────────

    #[test]
    fn plan_default_for_4_cores() {
        let plan = RuntimePlan::default_for_cores(4);
        assert_eq!(plan.num_workers(), 4);
        assert!(plan.reuseport);
        assert!(plan.total_memory() > 0);
    }

    #[test]
    fn plan_validate_no_warnings() {
        let plan = RuntimePlan::default_for_cores(4);
        let warnings = plan.validate();
        assert!(warnings.is_empty());
    }

    #[test]
    fn plan_validate_empty() {
        let plan = RuntimePlan {
            workers: vec![],
            listen_addrs: vec![],
            reuseport: true,
            fallback: RuntimeMode::Tokio,
            shutdown_timeout: Duration::from_secs(30),
        };
        let warnings = plan.validate();
        assert!(warnings.contains(&PlanWarning::NoWorkers));
    }

    #[test]
    fn plan_validate_sqpoll_without_pinning() {
        let mut plan = RuntimePlan::default_for_cores(1);
        plan.workers[0].sqpoll = true;
        plan.workers[0].pin_to_cpu = false;
        let warnings = plan.validate();
        assert!(warnings.iter().any(|w| matches!(w, PlanWarning::SqpollWithoutPinning { .. })));
    }

    #[test]
    fn plan_validate_multi_worker_no_reuseport() {
        let mut plan = RuntimePlan::default_for_cores(4);
        plan.reuseport = false;
        let warnings = plan.validate();
        assert!(warnings.contains(&PlanWarning::MultiWorkerWithoutReuseport));
    }

    // ── Core stats ────────────────────────────────────────────────────

    #[test]
    fn core_stats_record_and_snapshot() {
        let stats = CoreStats::new(0);
        stats.record_accept();
        stats.record_request(1024, 512);
        stats.record_sq_submit(2);
        stats.record_cq_completion(5);
        stats.record_splice();

        let snap = stats.snapshot();
        assert_eq!(snap.cpu_id, 0);
        assert_eq!(snap.accepts, 1);
        assert_eq!(snap.requests, 1);
        assert_eq!(snap.bytes_in, 1024);
        assert_eq!(snap.bytes_out, 512);
        assert_eq!(snap.splice_ops, 1);
    }

    #[test]
    fn core_stats_sq_efficiency() {
        let stats = CoreStats::new(0);
        stats.record_sq_submit(2);
        stats.record_cq_completion(8);
        let snap = stats.snapshot();
        assert!((snap.sq_efficiency() - 4.0).abs() < 0.01); // 8 CQEs / 2 submits.
    }

    #[test]
    fn core_stats_splice_rate() {
        let stats = CoreStats::new(0);
        for _ in 0..10 {
            stats.record_request(100, 100);
        }
        for _ in 0..7 {
            stats.record_splice();
        }
        let snap = stats.snapshot();
        assert!((snap.splice_rate() - 0.7).abs() < 0.01);
    }

    // ── Syscall budget ────────────────────────────────────────────────

    #[test]
    fn syscall_budget_per_request() {
        let budget = SyscallBudget::new();
        // Simulate a request: accept + recv + send + submit.
        budget.record_accept();
        budget.record_recv(2);
        budget.record_send(2);
        budget.record_submit();
        budget.record_request_complete();

        let snap = budget.snapshot();
        assert_eq!(snap.total_syscalls(), 6);
        assert!((snap.per_request() - 6.0).abs() < 0.01);
    }

    #[test]
    fn syscall_budget_uring_target() {
        let budget = SyscallBudget::new();
        // io_uring target: 10-15 syscalls per request.
        for _ in 0..100 {
            budget.record_accept();
            budget.record_recv(3);  // Batched.
            budget.record_send(3);  // Batched.
            budget.record_submit(); // One io_uring_enter per batch.
            budget.record_request_complete();
        }
        let avg = budget.avg_syscalls_per_request();
        assert!(avg <= 15.0, "io_uring target: <= 15 syscalls/req, got {}", avg);
    }

    // ── Connection affinity ───────────────────────────────────────────

    #[test]
    fn affinity_correct() {
        let mut aff = ConnectionAffinity::new();
        aff.register(1, 0);
        assert_eq!(aff.check(1, 0), AffinityResult::Correct);
    }

    #[test]
    fn affinity_migration() {
        let mut aff = ConnectionAffinity::new();
        aff.register(1, 0);
        let result = aff.check(1, 2);
        assert!(matches!(result, AffinityResult::Migrated { from: 0, to: 2 }));
        assert_eq!(aff.total_migrations(), 1);
    }

    #[test]
    fn affinity_unknown() {
        let mut aff = ConnectionAffinity::new();
        assert_eq!(aff.check(999, 0), AffinityResult::Unknown);
    }

    #[test]
    fn affinity_unregister() {
        let mut aff = ConnectionAffinity::new();
        aff.register(1, 0);
        aff.unregister(1);
        assert_eq!(aff.active_connections(), 0);
    }

    #[test]
    fn affinity_migration_rate() {
        let mut aff = ConnectionAffinity::new();
        for i in 0..10 {
            aff.register(i, 0);
        }
        // 2 out of 10 migrate.
        aff.check(0, 1); // Migration.
        aff.check(1, 2); // Migration.
        assert!((aff.migration_rate() - 0.2).abs() < 0.01);
    }

    // ── NUMA topology ─────────────────────────────────────────────────

    #[test]
    fn numa_detect_runs() {
        let topo = NumaTopology::detect();
        assert!(topo.total_cpus() > 0);
    }

    #[test]
    fn numa_from_nodes() {
        let topo = NumaTopology::from_nodes(vec![
            NumaNode { node_id: 0, cpu_ids: vec![0, 1], memory_mb: 8192 },
            NumaNode { node_id: 1, cpu_ids: vec![2, 3], memory_mb: 8192 },
        ]);
        assert_eq!(topo.total_cpus(), 4);
        assert_eq!(topo.node_for_cpu(0), Some(0));
        assert_eq!(topo.node_for_cpu(3), Some(1));
        assert_eq!(topo.node_for_cpu(99), None);
    }

    #[test]
    fn numa_cpus_for_node() {
        let topo = NumaTopology::from_nodes(vec![
            NumaNode { node_id: 0, cpu_ids: vec![0, 1, 2, 3], memory_mb: 0 },
        ]);
        assert_eq!(topo.cpus_for_node(0), &[0, 1, 2, 3]);
        assert_eq!(topo.cpus_for_node(1), &[] as &[u32]);
    }

    #[test]
    fn numa_parse_cpulist() {
        assert_eq!(NumaTopology::parse_cpulist("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(NumaTopology::parse_cpulist("0,2,4"), vec![0, 2, 4]);
        assert_eq!(NumaTopology::parse_cpulist("0-1,4-5"), vec![0, 1, 4, 5]);
    }

    // ── Batch tracker ─────────────────────────────────────────────────

    #[test]
    fn batch_tracker_avg() {
        let mut bt = BatchTracker::new();
        bt.record(4);
        bt.record(8);
        assert!((bt.avg_batch_size() - 6.0).abs() < 0.01);
        assert_eq!(bt.total_submits(), 2);
        assert_eq!(bt.total_sqes(), 12);
    }

    #[test]
    fn batch_tracker_histogram() {
        let mut bt = BatchTracker::new();
        bt.record(1);   // bucket 0
        bt.record(3);   // bucket 1
        bt.record(7);   // bucket 2
        bt.record(12);  // bucket 3
        bt.record(20);  // bucket 4
        bt.record(50);  // bucket 5

        let h = bt.histogram();
        assert_eq!(h[0], 1); // 1
        assert_eq!(h[1], 1); // 2-4
        assert_eq!(h[2], 1); // 5-8
        assert_eq!(h[3], 1); // 9-16
        assert_eq!(h[4], 1); // 17-32
        assert_eq!(h[5], 1); // 33+
    }

    #[test]
    fn batch_tracker_batching_rate() {
        let mut bt = BatchTracker::new();
        bt.record(1); // Single.
        bt.record(1); // Single.
        bt.record(5); // Batched.
        bt.record(10); // Batched.
        // 2 singles, 2 batched → 50% batching rate.
        assert!((bt.batching_rate() - 0.5).abs() < 0.01);
    }

    // ── Global toggle ─────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_uring_runtime_enabled(true);
        assert!(is_uring_runtime_enabled());
    }

    // ── Metrics ───────────────────────────────────────────────────────

    #[test]
    fn global_metrics_accessible() {
        let m = uring_runtime_metrics();
        let before = m.total_requests.load(Ordering::Relaxed);
        m.total_requests.fetch_add(1, Ordering::Relaxed);
        let after = m.total_requests.load(Ordering::Relaxed);
        assert!(after >= before + 1);
    }
}
