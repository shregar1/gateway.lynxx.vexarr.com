//! HAProxy-inspired event loop optimizations for the Lynxx gateway.
//!
//! # Architecture
//!
//! ```text
//! EventLoop Optimizations
//! ├── ConnState           — 4-state per-direction connection state machine
//! │   ├── HalfState       — Ready / Data / ShutWanted / ShutDone / Error
//! │   └── ConnFlags       — Bitfield: CONNECTED, SSL, H2, KEEPALIVE, …
//! ├── WriteCoalescer      — Batch small writes to reduce syscalls
//! ├── CorkGuard           — RAII TCP_CORK / TCP_NOPUSH for packet batching
//! ├── TaskScheduler       — Multi-level priority queue (eb32-inspired)
//! │   └── TaskPriority    — Critical / High / Normal / Low / Idle
//! ├── ConnTracker         — DashMap-based connection lifecycle tracking
//! └── EventLoopMetrics    — Aggregate counters
//! ```
//!
//! # Why
//!
//! Tokio's work-stealing scheduler is excellent for general-purpose async I/O.
//! These optimizations add HAProxy-specific techniques on top:
//!
//! - **Connection state machine**: Precise half-close handling and error
//!   propagation via a formal 4-state model per I/O direction.
//! - **Write coalescing**: Batches small writes into larger buffers, reducing
//!   `write(2)` syscalls — analogous to HAProxy's coalesced `epoll_ctl`.
//! - **TCP_CORK / TCP_NOPUSH**: Kernel-level write batching that combines
//!   header + body into a single TCP segment, eliminating Nagle-related
//!   latency.
//! - **Priority scheduling**: Multi-level queue ensures health checks and
//!   admin tasks don't starve behind bulk request forwarding.
//! - **Connection tracking**: Per-connection lifecycle metrics for
//!   operational visibility.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

type FastHasher = ahash::RandomState;

// ---------------------------------------------------------------------------
// Process-relative monotonic timestamp
// ---------------------------------------------------------------------------

static PROCESS_START: OnceLock<Instant> = OnceLock::new();

fn process_start() -> Instant {
    *PROCESS_START.get_or_init(Instant::now)
}

/// Monotonic milliseconds since process start. Safe to store in `AtomicU64`
/// for lock-free last-activity tracking.
pub fn elapsed_ms() -> u64 {
    process_start().elapsed().as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════════════════
// Event loop strategy
// ═══════════════════════════════════════════════════════════════════════════

/// Top-level strategy selector. Stored as `AtomicU8` for lock-free switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventLoopStrategy {
    /// Standard Tokio behaviour — no additional optimizations.
    Default = 0,
    /// Write coalescing only.
    Coalesced = 1,
    /// Priority scheduling only.
    Prioritized = 2,
    /// All optimizations: coalescing + priority + state machine tracking.
    Full = 3,
}

impl EventLoopStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Coalesced,
            2 => Self::Prioritized,
            3 => Self::Full,
            _ => Self::Default,
        }
    }
}

static EVENT_LOOP_STRATEGY: AtomicU8 = AtomicU8::new(EventLoopStrategy::Full as u8);
static WRITE_COALESCING_ENABLED: AtomicBool = AtomicBool::new(true);
static PRIORITY_SCHEDULING_ENABLED: AtomicBool = AtomicBool::new(true);
static CONN_TRACKING_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_event_loop_strategy(s: EventLoopStrategy) {
    EVENT_LOOP_STRATEGY.store(s as u8, Ordering::Relaxed);
}

pub fn event_loop_strategy() -> EventLoopStrategy {
    EventLoopStrategy::from_u8(EVENT_LOOP_STRATEGY.load(Ordering::Relaxed))
}

pub fn set_write_coalescing(enabled: bool) {
    WRITE_COALESCING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_write_coalescing_enabled() -> bool {
    WRITE_COALESCING_ENABLED.load(Ordering::Relaxed)
}

pub fn set_priority_scheduling(enabled: bool) {
    PRIORITY_SCHEDULING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_priority_scheduling_enabled() -> bool {
    PRIORITY_SCHEDULING_ENABLED.load(Ordering::Relaxed)
}

pub fn set_conn_tracking(enabled: bool) {
    CONN_TRACKING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_conn_tracking_enabled() -> bool {
    CONN_TRACKING_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// Connection state machine — HalfState
// ═══════════════════════════════════════════════════════════════════════════

/// State of one I/O direction (read or write). HAProxy models each
/// connection as two independent half-connections, enabling precise
/// half-close handling and asymmetric error propagation.
///
/// ```text
///                ┌──────────┐
///          ┌────►│  Ready   │◄────┐
///          │     └─┬──┬──┬──┘     │
///          │       │  │  │        │
///     (idle) ┌────┘  │  └────┐ (done)
///          │ ▼       ▼       ▼   │
///          │ ShutW  Error   Data──┘
///          │  │      ▲       │
///          │  ▼      │       │
///          │ ShutD   └───────┘
///          │ (terminal)
///          └───────────────────
/// ```
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HalfState {
    /// Idle — ready for I/O but not currently transferring.
    Ready = 0,
    /// Actively transferring data.
    Data = 1,
    /// Shutdown requested but not yet executed (FIN queued).
    ShutWanted = 2,
    /// Shutdown complete (FIN sent/received). Terminal.
    ShutDone = 3,
    /// Unrecoverable error. Terminal.
    Error = 4,
}

impl HalfState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Data,
            2 => Self::ShutWanted,
            3 => Self::ShutDone,
            4 => Self::Error,
            _ => Self::Ready,
        }
    }

    /// Returns `true` if transitioning from `self` → `to` is a valid move.
    pub fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            // Ready: can start data transfer, request shutdown, or error out.
            (Self::Ready, Self::Data)
                | (Self::Ready, Self::ShutWanted)
                | (Self::Ready, Self::Error)
                // Data: can finish (idle), request shutdown, or error out.
                | (Self::Data, Self::Ready)
                | (Self::Data, Self::ShutWanted)
                | (Self::Data, Self::Error)
                // ShutWanted: can complete shutdown or error out.
                | (Self::ShutWanted, Self::ShutDone)
                | (Self::ShutWanted, Self::Error)
        )
    }

    /// Terminal states cannot transition further.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::ShutDone | Self::Error)
    }

    /// Is this direction capable of transferring data?
    pub fn is_active(self) -> bool {
        matches!(self, Self::Ready | Self::Data)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Connection flags — bitfield
// ═══════════════════════════════════════════════════════════════════════════

/// Bitfield connection flags, modeled after HAProxy's `CO_FL_*`.
/// Lock-free via `AtomicU32`.
pub struct ConnFlags(AtomicU32);

impl ConnFlags {
    // ── Layer 4 (TCP) ──
    pub const CONNECTED: u32 = 1 << 0;
    pub const WAIT_L4_CONN: u32 = 1 << 1;
    pub const WAIT_L4_ACK: u32 = 1 << 2;

    // ── Layer 6 (TLS) ──
    pub const WAIT_L6_CONN: u32 = 1 << 3;
    pub const SSL: u32 = 1 << 4;
    pub const EARLY_DATA: u32 = 1 << 5;

    // ── Protocol ──
    pub const KEEPALIVE: u32 = 1 << 6;
    pub const H2: u32 = 1 << 7;
    pub const H3: u32 = 1 << 8;
    pub const WEBSOCKET: u32 = 1 << 9;

    // ── Socket options ──
    pub const CORKED: u32 = 1 << 10;
    pub const NODELAY: u32 = 1 << 11;

    // ── Lifecycle ──
    pub const ALIVE: u32 = 1 << 12;
    pub const WANT_DRAIN: u32 = 1 << 13;
    pub const UPGRADED: u32 = 1 << 14;

    pub const fn new() -> Self {
        Self(AtomicU32::new(Self::ALIVE))
    }

    /// Set one or more flags (OR).
    pub fn set(&self, flag: u32) {
        self.0.fetch_or(flag, Ordering::Relaxed);
    }

    /// Clear one or more flags (AND NOT).
    pub fn clear(&self, flag: u32) {
        self.0.fetch_and(!flag, Ordering::Relaxed);
    }

    /// Test whether **all** given flags are set.
    pub fn has(&self, flag: u32) -> bool {
        self.0.load(Ordering::Relaxed) & flag == flag
    }

    /// Test whether **any** of the given flags are set.
    pub fn has_any(&self, flags: u32) -> bool {
        self.0.load(Ordering::Relaxed) & flags != 0
    }

    /// Raw u32 snapshot.
    pub fn raw(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for ConnFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnFlags(0x{:04x})", self.raw())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ConnState — per-connection state machine
// ═══════════════════════════════════════════════════════════════════════════

/// Complete connection state: two half-states (read + write), flags, and
/// timestamps. All mutable fields are lock-free atomics for safe concurrent
/// access from Tokio worker threads.
///
/// HAProxy's `struct connection` tracks similar data: `conn->flags`,
/// `conn->xprt_st`, independent read/write channel states, and per-direction
/// data counters. This is Lynxx's equivalent, designed for Tokio's
/// multi-threaded runtime.
pub struct ConnState {
    read_state: AtomicU8,
    write_state: AtomicU8,
    pub flags: ConnFlags,
    /// Connection creation time (set once, immutable).
    pub created_at: Instant,
    /// Last I/O activity — monotonic ms since process start.
    last_activity: AtomicU64,
    /// Bytes received on the read side.
    bytes_read: AtomicU64,
    /// Bytes sent on the write side.
    bytes_written: AtomicU64,
}

impl ConnState {
    pub fn new() -> Self {
        Self {
            read_state: AtomicU8::new(HalfState::Ready as u8),
            write_state: AtomicU8::new(HalfState::Ready as u8),
            flags: ConnFlags::new(),
            created_at: Instant::now(),
            last_activity: AtomicU64::new(elapsed_ms()),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    // ── State queries ──

    pub fn read(&self) -> HalfState {
        HalfState::from_u8(self.read_state.load(Ordering::Acquire))
    }

    pub fn write(&self) -> HalfState {
        HalfState::from_u8(self.write_state.load(Ordering::Acquire))
    }

    /// True if both directions are terminal (fully closed).
    pub fn is_closed(&self) -> bool {
        self.read().is_terminal() && self.write().is_terminal()
    }

    /// True if either direction can still transfer data.
    pub fn is_active(&self) -> bool {
        self.read().is_active() || self.write().is_active()
    }

    /// Milliseconds since last I/O activity.
    pub fn idle_ms(&self) -> u64 {
        elapsed_ms().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    /// Connection age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    // ── State transitions ──

    /// Transition the read direction. CAS-based for lock-free safety.
    /// Returns `Ok(previous_state)` on success, `Err(current_state)` if
    /// the transition is invalid.
    pub fn transition_read(&self, to: HalfState) -> Result<HalfState, HalfState> {
        self.transition(&self.read_state, to)
    }

    /// Transition the write direction.
    pub fn transition_write(&self, to: HalfState) -> Result<HalfState, HalfState> {
        self.transition(&self.write_state, to)
    }

    fn transition(
        &self,
        state: &AtomicU8,
        to: HalfState,
    ) -> Result<HalfState, HalfState> {
        loop {
            let cur = HalfState::from_u8(state.load(Ordering::Acquire));
            if !cur.can_transition_to(to) {
                return Err(cur);
            }
            match state.compare_exchange_weak(
                cur as u8,
                to as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.touch();
                    return Ok(cur);
                }
                Err(_) => continue, // CAS retry
            }
        }
    }

    // ── I/O accounting ──

    /// Record bytes received.
    pub fn record_read(&self, n: u64) {
        self.bytes_read.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Record bytes sent.
    pub fn record_write(&self, n: u64) {
        self.bytes_written.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Update last-activity timestamp.
    fn touch(&self) {
        self.last_activity.store(elapsed_ms(), Ordering::Relaxed);
    }
}

impl Default for ConnState {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Write coalescing
// ═══════════════════════════════════════════════════════════════════════════

/// Batches small writes into a single larger buffer to reduce `write(2)`
/// syscall overhead. Analogous to HAProxy's coalesced `epoll_ctl` updates
/// which batch FD state changes to minimize kernel round-trips.
///
/// # Usage
///
/// ```ignore
/// let mut coalescer = WriteCoalescer::new(16384, Duration::from_micros(200));
/// coalescer.write(b"HTTP/1.1 200 OK\r\n");
/// coalescer.write(b"Content-Length: 5\r\n\r\n");
/// coalescer.write(b"hello");
/// // One write(2) instead of three:
/// let batch = coalescer.take_buffer();
/// socket.write_all(&batch).await?;
/// ```
pub struct WriteCoalescer {
    buf: Vec<u8>,
    capacity: usize,
    first_write_at: Option<Instant>,
    max_delay: Duration,
    // Metrics
    writes_received: u64,
    flushes: u64,
    bytes_total: u64,
}

impl WriteCoalescer {
    /// Create a new coalescer.
    ///
    /// * `capacity` — flush when buffered data reaches this size (bytes).
    /// * `max_delay` — flush no later than this after the first buffered write.
    pub fn new(capacity: usize, max_delay: Duration) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            capacity,
            first_write_at: None,
            max_delay,
            writes_received: 0,
            flushes: 0,
            bytes_total: 0,
        }
    }

    /// Default coalescer: 16 KB buffer, 200 µs max delay.
    pub fn with_defaults() -> Self {
        Self::new(16384, Duration::from_micros(200))
    }

    /// Buffer a write. Returns `true` if the caller should flush now.
    pub fn write(&mut self, data: &[u8]) -> bool {
        if self.first_write_at.is_none() {
            self.first_write_at = Some(Instant::now());
        }
        self.buf.extend_from_slice(data);
        self.writes_received += 1;
        self.should_flush()
    }

    /// Check if the buffer should be flushed (capacity or time threshold).
    pub fn should_flush(&self) -> bool {
        if self.buf.is_empty() {
            return false;
        }
        self.buf.len() >= self.capacity
            || self
                .first_write_at
                .map(|t| t.elapsed() >= self.max_delay)
                .unwrap_or(false)
    }

    /// Extract the coalesced buffer, resetting internal state.
    /// The caller is responsible for writing the returned data.
    pub fn take_buffer(&mut self) -> Vec<u8> {
        self.first_write_at = None;
        self.flushes += 1;
        self.bytes_total += self.buf.len() as u64;
        let mut out = Vec::with_capacity(self.capacity);
        std::mem::swap(&mut self.buf, &mut out);
        out
    }

    /// Number of buffered bytes waiting to be flushed.
    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Average writes per flush — higher values indicate better coalescing.
    pub fn coalesce_ratio(&self) -> f64 {
        if self.flushes == 0 {
            0.0
        } else {
            self.writes_received as f64 / self.flushes as f64
        }
    }

    /// `(writes_received, flushes, bytes_total)`.
    pub fn metrics(&self) -> (u64, u64, u64) {
        (self.writes_received, self.flushes, self.bytes_total)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TCP_CORK / TCP_NOPUSH — kernel-level write batching
// ═══════════════════════════════════════════════════════════════════════════

// HAProxy uses TCP_CORK to batch response headers + body into a single TCP
// segment, avoiding the "small first packet" problem. While corked, the
// kernel holds partial frames and sends them as one segment on uncork.

/// Set TCP_CORK on a socket (Linux). While active, the kernel delays
/// sending partial segments and combines writes into fewer TCP packets.
#[cfg(target_os = "linux")]
pub fn cork_socket(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    unsafe {
        let val: libc::c_int = 1;
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CORK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Remove TCP_CORK — flush any buffered data as a single segment (Linux).
#[cfg(target_os = "linux")]
pub fn uncork_socket(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    unsafe {
        let val: libc::c_int = 0;
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CORK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set TCP_NOPUSH on a socket (macOS/BSD). Equivalent to TCP_CORK on Linux.
#[cfg(target_os = "macos")]
pub fn cork_socket(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    unsafe {
        let val: libc::c_int = 1;
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOPUSH,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Remove TCP_NOPUSH (macOS/BSD).
#[cfg(target_os = "macos")]
pub fn uncork_socket(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    unsafe {
        let val: libc::c_int = 0;
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOPUSH,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// No-op on platforms without TCP_CORK/TCP_NOPUSH.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn cork_socket(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// No-op on platforms without TCP_CORK/TCP_NOPUSH.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn uncork_socket(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// RAII guard that corks a socket on creation and uncorks on drop.
/// Ensures the socket is always uncorked, even if the writing code panics.
///
/// ```ignore
/// {
///     let _cork = CorkGuard::new(raw_fd)?;
///     socket.write_all(headers).await?;
///     socket.write_all(body).await?;
/// } // _cork drops → uncork → kernel sends combined packet
/// ```
#[cfg(unix)]
pub struct CorkGuard {
    fd: std::os::unix::io::RawFd,
}

#[cfg(unix)]
impl CorkGuard {
    pub fn new(fd: std::os::unix::io::RawFd) -> std::io::Result<Self> {
        cork_socket(fd)?;
        Ok(Self { fd })
    }

    pub fn fd(&self) -> std::os::unix::io::RawFd {
        self.fd
    }
}

#[cfg(unix)]
impl Drop for CorkGuard {
    fn drop(&mut self) {
        let _ = uncork_socket(self.fd);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Priority task scheduler
// ═══════════════════════════════════════════════════════════════════════════

/// Task priority levels, inspired by HAProxy's eb32 tree scheduler which
/// provides O(log n) insertion and extraction ordered by priority key.
///
/// We use a multi-level queue (MLQ) instead — O(1) push/pop with the same
/// priority semantics and better cache locality for the common case.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum TaskPriority {
    /// Health checks, admin endpoints, error handling.
    Critical = 0,
    /// Active request forwarding on established connections.
    High = 1,
    /// New connection acceptance.
    Normal = 2,
    /// Background work: metrics flush, logging, stats.
    Low = 3,
    /// Cleanup, GC, expired entry eviction.
    Idle = 4,
}

impl TaskPriority {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Critical,
            1 => Self::High,
            2 => Self::Normal,
            3 => Self::Low,
            _ => Self::Idle,
        }
    }

    const COUNT: usize = 5;
}

/// Classification of task types for metrics and debugging.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskKind {
    RequestForward = 0,
    HealthCheck = 1,
    MetricsFlush = 2,
    ConnCleanup = 3,
    ConfigReload = 4,
    TlsHandshake = 5,
    DnsResolve = 6,
    Custom = 7,
}

/// A task in the priority scheduler.
pub struct ScheduledTask {
    pub id: u64,
    pub priority: TaskPriority,
    pub kind: TaskKind,
    pub enqueued_at: Instant,
}

/// Multi-level priority queue with anti-starvation.
///
/// Tasks are distributed into 5 priority-indexed `VecDeque`s. `pop()`
/// always takes from the highest-occupied level. To prevent
/// priority-inversion starvation, after `starvation_limit` consecutive
/// pops from the highest level, one pop is forced from the lowest
/// occupied level.
///
/// This is simpler than HAProxy's eb32 tree but provides the same
/// guaranteed scheduling semantics for proxy workloads.
pub struct TaskScheduler {
    levels: [Mutex<VecDeque<ScheduledTask>>; TaskPriority::COUNT],
    starvation_limit: u32,
    consecutive_top: AtomicU32,
    // Metrics
    total_pushed: AtomicU64,
    total_popped: AtomicU64,
    per_level_pushed: [AtomicU64; TaskPriority::COUNT],
    per_level_popped: [AtomicU64; TaskPriority::COUNT],
}

impl TaskScheduler {
    pub fn new(starvation_limit: u32) -> Self {
        Self {
            levels: [
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
            ],
            starvation_limit,
            consecutive_top: AtomicU32::new(0),
            total_pushed: AtomicU64::new(0),
            total_popped: AtomicU64::new(0),
            per_level_pushed: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            per_level_popped: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Default scheduler: starvation limit of 64.
    pub fn with_defaults() -> Self {
        Self::new(64)
    }

    /// Enqueue a task at its priority level. O(1).
    pub fn push(&self, task: ScheduledTask) {
        let level = task.priority as usize;
        self.levels[level].lock().unwrap().push_back(task);
        self.total_pushed.fetch_add(1, Ordering::Relaxed);
        self.per_level_pushed[level].fetch_add(1, Ordering::Relaxed);
    }

    /// Dequeue the highest-priority task, with anti-starvation. O(1)
    /// amortized (scans at most 5 levels).
    pub fn pop(&self) -> Option<ScheduledTask> {
        let consecutive = self.consecutive_top.load(Ordering::Relaxed);

        // Anti-starvation: after N consecutive pops from the Critical
        // level, force a pop from the lowest occupied level to prevent
        // lower-priority tasks from being starved indefinitely.
        if consecutive >= self.starvation_limit {
            self.consecutive_top.store(0, Ordering::Relaxed);
            for level in (0..TaskPriority::COUNT).rev() {
                if let Some(task) = self.try_pop_level(level) {
                    return Some(task);
                }
            }
            return None;
        }

        // Normal path: highest priority first.
        for level in 0..TaskPriority::COUNT {
            if let Some(task) = self.try_pop_level(level) {
                if level == 0 {
                    self.consecutive_top.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.consecutive_top.store(0, Ordering::Relaxed);
                }
                return Some(task);
            }
        }
        None
    }

    fn try_pop_level(&self, level: usize) -> Option<ScheduledTask> {
        let mut queue = self.levels[level].lock().unwrap();
        if let Some(task) = queue.pop_front() {
            self.total_popped.fetch_add(1, Ordering::Relaxed);
            self.per_level_popped[level].fetch_add(1, Ordering::Relaxed);
            Some(task)
        } else {
            None
        }
    }

    /// Total tasks waiting across all levels.
    pub fn pending(&self) -> usize {
        self.levels
            .iter()
            .map(|q| q.lock().unwrap().len())
            .sum()
    }

    /// Tasks waiting at a specific priority.
    pub fn pending_at(&self, priority: TaskPriority) -> usize {
        self.levels[priority as usize].lock().unwrap().len()
    }

    pub fn total_pushed(&self) -> u64 {
        self.total_pushed.load(Ordering::Relaxed)
    }

    pub fn total_popped(&self) -> u64 {
        self.total_popped.load(Ordering::Relaxed)
    }

    pub fn popped_at(&self, priority: TaskPriority) -> u64 {
        self.per_level_popped[priority as usize].load(Ordering::Relaxed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Connection tracker
// ═══════════════════════════════════════════════════════════════════════════

/// Per-connection lifecycle tracker. Uses DashMap for lock-free concurrent
/// reads from Tokio worker threads.
///
/// Each connection gets a unique `u64` ID, a `ConnState` for its lifecycle,
/// and counters for I/O accounting. Operational tooling can query active
/// connections, find idle ones, and reap closed ones.
pub struct ConnTracker {
    connections: DashMap<u64, ConnState, FastHasher>,
    next_id: AtomicU64,
    total_created: AtomicU64,
    total_closed: AtomicU64,
}

impl ConnTracker {
    pub fn new() -> Self {
        Self {
            connections: DashMap::with_hasher(FastHasher::default()),
            next_id: AtomicU64::new(1),
            total_created: AtomicU64::new(0),
            total_closed: AtomicU64::new(0),
        }
    }

    /// Register a new connection. Returns the assigned ID.
    pub fn register(&self) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.connections.insert(id, ConnState::new());
        self.total_created.fetch_add(1, Ordering::Relaxed);
        id
    }

    /// Look up a connection's state by ID.
    pub fn get(
        &self,
        id: u64,
    ) -> Option<dashmap::mapref::one::Ref<'_, u64, ConnState, FastHasher>> {
        self.connections.get(&id)
    }

    /// Remove a connection (closed or errored).
    pub fn remove(&self, id: u64) -> bool {
        let removed = self.connections.remove(&id).is_some();
        if removed {
            self.total_closed.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// Number of currently tracked connections.
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }

    pub fn total_created(&self) -> u64 {
        self.total_created.load(Ordering::Relaxed)
    }

    pub fn total_closed(&self) -> u64 {
        self.total_closed.load(Ordering::Relaxed)
    }

    /// Collect IDs of connections idle longer than `threshold_ms`.
    pub fn idle_connections(&self, threshold_ms: u64) -> Vec<u64> {
        self.connections
            .iter()
            .filter(|entry| entry.value().idle_ms() > threshold_ms)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Remove all connections that are fully closed (both directions
    /// terminal). Returns the number reaped.
    pub fn reap_closed(&self) -> usize {
        let closed: Vec<u64> = self
            .connections
            .iter()
            .filter(|entry| entry.value().is_closed())
            .map(|entry| *entry.key())
            .collect();
        let count = closed.len();
        for id in closed {
            if self.connections.remove(&id).is_some() {
                self.total_closed.fetch_add(1, Ordering::Relaxed);
            }
        }
        count
    }
}

impl Default for ConnTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Event loop metrics
// ═══════════════════════════════════════════════════════════════════════════

/// Aggregate counters for event loop optimizations.
pub struct EventLoopMetrics {
    pub wakeups: AtomicU64,
    pub writes_coalesced: AtomicU64,
    pub cork_batches: AtomicU64,
    pub tasks_scheduled: AtomicU64,
    pub connections_tracked: AtomicU64,
}

impl EventLoopMetrics {
    pub const fn new() -> Self {
        Self {
            wakeups: AtomicU64::new(0),
            writes_coalesced: AtomicU64::new(0),
            cork_batches: AtomicU64::new(0),
            tasks_scheduled: AtomicU64::new(0),
            connections_tracked: AtomicU64::new(0),
        }
    }
}

static GLOBAL_EL_METRICS: EventLoopMetrics = EventLoopMetrics::new();

pub fn global_metrics() -> &'static EventLoopMetrics {
    &GLOBAL_EL_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── HalfState transitions ──

    #[test]
    fn half_state_valid_transitions() {
        // Ready → Data, ShutWanted, Error
        assert!(HalfState::Ready.can_transition_to(HalfState::Data));
        assert!(HalfState::Ready.can_transition_to(HalfState::ShutWanted));
        assert!(HalfState::Ready.can_transition_to(HalfState::Error));

        // Data → Ready, ShutWanted, Error
        assert!(HalfState::Data.can_transition_to(HalfState::Ready));
        assert!(HalfState::Data.can_transition_to(HalfState::ShutWanted));
        assert!(HalfState::Data.can_transition_to(HalfState::Error));

        // ShutWanted → ShutDone, Error
        assert!(HalfState::ShutWanted.can_transition_to(HalfState::ShutDone));
        assert!(HalfState::ShutWanted.can_transition_to(HalfState::Error));
    }

    #[test]
    fn half_state_invalid_transitions() {
        // Terminal states reject all transitions.
        assert!(!HalfState::ShutDone.can_transition_to(HalfState::Ready));
        assert!(!HalfState::ShutDone.can_transition_to(HalfState::Data));
        assert!(!HalfState::ShutDone.can_transition_to(HalfState::Error));
        assert!(!HalfState::Error.can_transition_to(HalfState::Ready));
        assert!(!HalfState::Error.can_transition_to(HalfState::Data));

        // ShutWanted cannot go back to Data or Ready.
        assert!(!HalfState::ShutWanted.can_transition_to(HalfState::Data));
        assert!(!HalfState::ShutWanted.can_transition_to(HalfState::Ready));

        // Self-transitions are not valid.
        assert!(!HalfState::Ready.can_transition_to(HalfState::Ready));
        assert!(!HalfState::Data.can_transition_to(HalfState::Data));
    }

    #[test]
    fn half_state_terminal_and_active() {
        assert!(!HalfState::Ready.is_terminal());
        assert!(!HalfState::Data.is_terminal());
        assert!(!HalfState::ShutWanted.is_terminal());
        assert!(HalfState::ShutDone.is_terminal());
        assert!(HalfState::Error.is_terminal());

        assert!(HalfState::Ready.is_active());
        assert!(HalfState::Data.is_active());
        assert!(!HalfState::ShutWanted.is_active());
        assert!(!HalfState::ShutDone.is_active());
        assert!(!HalfState::Error.is_active());
    }

    #[test]
    fn half_state_u8_roundtrip() {
        for v in 0..=4u8 {
            let state = HalfState::from_u8(v);
            assert_eq!(state as u8, v);
        }
        // Out of range → Ready.
        assert_eq!(HalfState::from_u8(255), HalfState::Ready);
    }

    // ── ConnFlags ──

    #[test]
    fn conn_flags_operations() {
        let flags = ConnFlags::new();
        // ALIVE is set by default.
        assert!(flags.has(ConnFlags::ALIVE));
        assert!(!flags.has(ConnFlags::SSL));

        // Set multiple flags.
        flags.set(ConnFlags::SSL | ConnFlags::CONNECTED);
        assert!(flags.has(ConnFlags::SSL));
        assert!(flags.has(ConnFlags::CONNECTED));
        assert!(flags.has(ConnFlags::SSL | ConnFlags::CONNECTED));

        // has_any: true if at least one flag matches.
        assert!(flags.has_any(ConnFlags::SSL | ConnFlags::H2));
        assert!(!flags.has_any(ConnFlags::H2 | ConnFlags::H3));

        // Clear a flag.
        flags.clear(ConnFlags::SSL);
        assert!(!flags.has(ConnFlags::SSL));
        assert!(flags.has(ConnFlags::CONNECTED));
    }

    // ── ConnState lifecycle ──

    #[test]
    fn conn_state_full_lifecycle() {
        let state = ConnState::new();
        assert_eq!(state.read(), HalfState::Ready);
        assert_eq!(state.write(), HalfState::Ready);
        assert!(state.is_active());
        assert!(!state.is_closed());

        // Start transferring data on read side.
        assert!(state.transition_read(HalfState::Data).is_ok());
        assert_eq!(state.read(), HalfState::Data);

        // Record I/O.
        state.record_read(1024);
        state.record_write(512);
        assert_eq!(state.bytes_read(), 1024);
        assert_eq!(state.bytes_written(), 512);

        // Back to idle.
        assert!(state.transition_read(HalfState::Ready).is_ok());

        // Graceful shutdown: both directions.
        assert!(state.transition_read(HalfState::ShutWanted).is_ok());
        assert!(state.transition_read(HalfState::ShutDone).is_ok());
        assert!(state.transition_write(HalfState::ShutWanted).is_ok());
        assert!(state.transition_write(HalfState::ShutDone).is_ok());

        // Fully closed.
        assert!(state.is_closed());
        assert!(!state.is_active());
    }

    #[test]
    fn conn_state_invalid_transition_rejected() {
        let state = ConnState::new();

        // Move read to terminal ShutDone.
        state.transition_read(HalfState::ShutWanted).unwrap();
        state.transition_read(HalfState::ShutDone).unwrap();

        // All transitions from terminal state fail.
        assert!(state.transition_read(HalfState::Ready).is_err());
        assert!(state.transition_read(HalfState::Data).is_err());
        assert!(state.transition_read(HalfState::Error).is_err());
    }

    #[test]
    fn conn_state_error_is_terminal() {
        let state = ConnState::new();
        state.transition_read(HalfState::Error).unwrap();
        state.transition_write(HalfState::Error).unwrap();
        assert!(state.is_closed());
    }

    #[test]
    fn conn_state_idle_tracking() {
        let state = ConnState::new();
        // Just created — idle time should be very small.
        assert!(state.idle_ms() < 100);
    }

    // ── WriteCoalescer ──

    #[test]
    fn coalescer_batches_writes() {
        let mut coalescer = WriteCoalescer::new(1024, Duration::from_secs(1));

        // Small writes don't trigger flush.
        assert!(!coalescer.write(b"hello "));
        assert!(!coalescer.write(b"world"));
        assert_eq!(coalescer.pending_bytes(), 11);

        // Take produces the combined buffer.
        let batch = coalescer.take_buffer();
        assert_eq!(&batch, b"hello world");
        assert!(coalescer.is_empty());
    }

    #[test]
    fn coalescer_flush_on_capacity() {
        let mut coalescer = WriteCoalescer::new(10, Duration::from_secs(10));

        assert!(!coalescer.write(b"12345")); // 5 bytes, under 10.
        assert!(coalescer.write(b"678901")); // 11 bytes, over 10 → flush.
    }

    #[test]
    fn coalescer_metrics() {
        let mut coalescer = WriteCoalescer::new(1024, Duration::from_secs(1));

        coalescer.write(b"a");
        coalescer.write(b"b");
        coalescer.write(b"c");
        let _ = coalescer.take_buffer();

        let (writes, flushes, bytes) = coalescer.metrics();
        assert_eq!(writes, 3);
        assert_eq!(flushes, 1);
        assert_eq!(bytes, 3);
        assert!((coalescer.coalesce_ratio() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coalescer_empty_no_flush() {
        let coalescer = WriteCoalescer::new(1024, Duration::from_secs(1));
        assert!(!coalescer.should_flush());
    }

    // ── TaskScheduler ──

    #[test]
    fn scheduler_priority_ordering() {
        let sched = TaskScheduler::with_defaults();

        // Push tasks in reverse priority order.
        sched.push(ScheduledTask {
            id: 1,
            priority: TaskPriority::Idle,
            kind: TaskKind::ConnCleanup,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 2,
            priority: TaskPriority::Critical,
            kind: TaskKind::HealthCheck,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 3,
            priority: TaskPriority::Normal,
            kind: TaskKind::RequestForward,
            enqueued_at: Instant::now(),
        });

        // Pop order: Critical, Normal, Idle.
        assert_eq!(sched.pop().unwrap().id, 2);
        assert_eq!(sched.pop().unwrap().id, 3);
        assert_eq!(sched.pop().unwrap().id, 1);
        assert!(sched.pop().is_none());
    }

    #[test]
    fn scheduler_anti_starvation() {
        let sched = TaskScheduler::new(3); // Low limit for testing.

        // Flood with 5 Critical tasks.
        for i in 0..5 {
            sched.push(ScheduledTask {
                id: i,
                priority: TaskPriority::Critical,
                kind: TaskKind::HealthCheck,
                enqueued_at: Instant::now(),
            });
        }
        // One lonely Idle task.
        sched.push(ScheduledTask {
            id: 100,
            priority: TaskPriority::Idle,
            kind: TaskKind::ConnCleanup,
            enqueued_at: Instant::now(),
        });

        // Pop 3 Critical (hits starvation limit).
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);

        // 4th pop triggers anti-starvation — Idle gets served.
        let task = sched.pop().unwrap();
        assert_eq!(task.priority, TaskPriority::Idle);
        assert_eq!(task.id, 100);
    }

    #[test]
    fn scheduler_empty_returns_none() {
        let sched = TaskScheduler::with_defaults();
        assert!(sched.pop().is_none());
        assert_eq!(sched.pending(), 0);
    }

    #[test]
    fn scheduler_pending_counts() {
        let sched = TaskScheduler::with_defaults();

        sched.push(ScheduledTask {
            id: 1,
            priority: TaskPriority::High,
            kind: TaskKind::RequestForward,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 2,
            priority: TaskPriority::High,
            kind: TaskKind::RequestForward,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 3,
            priority: TaskPriority::Low,
            kind: TaskKind::MetricsFlush,
            enqueued_at: Instant::now(),
        });

        assert_eq!(sched.pending(), 3);
        assert_eq!(sched.pending_at(TaskPriority::High), 2);
        assert_eq!(sched.pending_at(TaskPriority::Low), 1);
        assert_eq!(sched.pending_at(TaskPriority::Critical), 0);
    }

    #[test]
    fn scheduler_metrics() {
        let sched = TaskScheduler::with_defaults();

        sched.push(ScheduledTask {
            id: 1,
            priority: TaskPriority::Normal,
            kind: TaskKind::RequestForward,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 2,
            priority: TaskPriority::Low,
            kind: TaskKind::MetricsFlush,
            enqueued_at: Instant::now(),
        });

        assert_eq!(sched.total_pushed(), 2);
        assert_eq!(sched.total_popped(), 0);

        sched.pop();
        assert_eq!(sched.total_popped(), 1);
        assert_eq!(sched.popped_at(TaskPriority::Normal), 1);
    }

    // ── ConnTracker ──

    #[test]
    fn tracker_register_and_remove() {
        let tracker = ConnTracker::new();

        let id1 = tracker.register();
        let id2 = tracker.register();
        assert_ne!(id1, id2);
        assert_eq!(tracker.active_count(), 2);

        assert!(tracker.get(id1).is_some());
        assert!(tracker.remove(id1));
        assert_eq!(tracker.active_count(), 1);
        assert!(tracker.get(id1).is_none());
    }

    #[test]
    fn tracker_metrics() {
        let tracker = ConnTracker::new();

        let id1 = tracker.register();
        let _id2 = tracker.register();
        let _id3 = tracker.register();

        assert_eq!(tracker.total_created(), 3);
        assert_eq!(tracker.total_closed(), 0);

        tracker.remove(id1);
        assert_eq!(tracker.total_closed(), 1);
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn tracker_reap_closed() {
        let tracker = ConnTracker::new();

        let id1 = tracker.register();
        let _id2 = tracker.register();

        // Move id1 to fully closed state.
        {
            let conn = tracker.get(id1).unwrap();
            conn.transition_read(HalfState::ShutWanted).unwrap();
            conn.transition_read(HalfState::ShutDone).unwrap();
            conn.transition_write(HalfState::ShutWanted).unwrap();
            conn.transition_write(HalfState::ShutDone).unwrap();
        }

        let reaped = tracker.reap_closed();
        assert_eq!(reaped, 1);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn tracker_state_through_dashmap() {
        let tracker = ConnTracker::new();
        let id = tracker.register();

        // Transition via DashMap ref — atomics work through &ConnState.
        {
            let conn = tracker.get(id).unwrap();
            conn.transition_read(HalfState::Data).unwrap();
            conn.record_read(4096);
        }

        // Re-read and verify persistence.
        {
            let conn = tracker.get(id).unwrap();
            assert_eq!(conn.read(), HalfState::Data);
            assert_eq!(conn.bytes_read(), 4096);
        }
    }

    // ── Strategy toggles ──

    #[test]
    fn strategy_toggle() {
        set_event_loop_strategy(EventLoopStrategy::Default);
        assert_eq!(event_loop_strategy(), EventLoopStrategy::Default);

        set_event_loop_strategy(EventLoopStrategy::Coalesced);
        assert_eq!(event_loop_strategy(), EventLoopStrategy::Coalesced);

        set_event_loop_strategy(EventLoopStrategy::Prioritized);
        assert_eq!(event_loop_strategy(), EventLoopStrategy::Prioritized);

        set_event_loop_strategy(EventLoopStrategy::Full);
        assert_eq!(event_loop_strategy(), EventLoopStrategy::Full);
    }

    #[test]
    fn feature_toggles() {
        set_write_coalescing(false);
        assert!(!is_write_coalescing_enabled());
        set_write_coalescing(true);
        assert!(is_write_coalescing_enabled());

        set_priority_scheduling(false);
        assert!(!is_priority_scheduling_enabled());
        set_priority_scheduling(true);
        assert!(is_priority_scheduling_enabled());

        set_conn_tracking(false);
        assert!(!is_conn_tracking_enabled());
        set_conn_tracking(true);
        assert!(is_conn_tracking_enabled());
    }

    #[test]
    fn event_loop_strategy_u8_roundtrip() {
        for v in 0..=3u8 {
            let s = EventLoopStrategy::from_u8(v);
            assert_eq!(s as u8, v);
        }
        assert_eq!(EventLoopStrategy::from_u8(99), EventLoopStrategy::Default);
    }

    // ── CorkGuard (Unix only, smoke test) ──

    #[cfg(unix)]
    #[test]
    fn cork_functions_exist() {
        // We can't easily test cork on a non-TCP FD, but verify the
        // functions compile and the error path works.
        let result = cork_socket(-1);
        assert!(result.is_err()); // Bad FD → error.

        let result = uncork_socket(-1);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Additional tests for 95%+ coverage
    // ═══════════════════════════════════════════════════════════════════════

    // ── HalfState: exhaustive transition matrix ──

    #[test]
    fn half_state_shutdone_rejects_all() {
        // ShutDone is terminal — no transitions out.
        assert!(!HalfState::ShutDone.can_transition_to(HalfState::ShutDone));
        assert!(!HalfState::ShutDone.can_transition_to(HalfState::ShutWanted));
    }

    #[test]
    fn half_state_error_rejects_all() {
        // Error is terminal — no transitions out.
        assert!(!HalfState::Error.can_transition_to(HalfState::Error));
        assert!(!HalfState::Error.can_transition_to(HalfState::ShutWanted));
        assert!(!HalfState::Error.can_transition_to(HalfState::ShutDone));
    }

    #[test]
    fn half_state_ready_cannot_reach_shutdone_directly() {
        // Ready → ShutDone is not valid (must go through ShutWanted).
        assert!(!HalfState::Ready.can_transition_to(HalfState::ShutDone));
    }

    #[test]
    fn half_state_data_cannot_reach_shutdone_directly() {
        // Data → ShutDone is not valid (must go through ShutWanted).
        assert!(!HalfState::Data.can_transition_to(HalfState::ShutDone));
    }

    #[test]
    fn half_state_shutwanted_is_not_active_not_terminal() {
        // ShutWanted is in limbo: not active, not terminal.
        assert!(!HalfState::ShutWanted.is_active());
        assert!(!HalfState::ShutWanted.is_terminal());
    }

    // ── ConnFlags: individual flag constants and toggle behavior ──

    #[test]
    fn conn_flags_default_has_alive_only() {
        let flags = ConnFlags::new();
        assert!(flags.has(ConnFlags::ALIVE));
        // No other flags should be set.
        assert!(!flags.has(ConnFlags::CONNECTED));
        assert!(!flags.has(ConnFlags::SSL));
        assert!(!flags.has(ConnFlags::H2));
        assert!(!flags.has(ConnFlags::H3));
        assert!(!flags.has(ConnFlags::KEEPALIVE));
        assert!(!flags.has(ConnFlags::CORKED));
        assert!(!flags.has(ConnFlags::NODELAY));
        assert!(!flags.has(ConnFlags::WEBSOCKET));
        assert!(!flags.has(ConnFlags::UPGRADED));
        assert!(!flags.has(ConnFlags::EARLY_DATA));
        assert!(!flags.has(ConnFlags::WAIT_L4_CONN));
        assert!(!flags.has(ConnFlags::WAIT_L4_ACK));
        assert!(!flags.has(ConnFlags::WAIT_L6_CONN));
        assert!(!flags.has(ConnFlags::WANT_DRAIN));
    }

    #[test]
    fn conn_flags_each_constant_is_unique_bit() {
        // Verify that all flag constants are distinct powers of 2.
        let all_flags = [
            ConnFlags::CONNECTED,
            ConnFlags::WAIT_L4_CONN,
            ConnFlags::WAIT_L4_ACK,
            ConnFlags::WAIT_L6_CONN,
            ConnFlags::SSL,
            ConnFlags::EARLY_DATA,
            ConnFlags::KEEPALIVE,
            ConnFlags::H2,
            ConnFlags::H3,
            ConnFlags::WEBSOCKET,
            ConnFlags::CORKED,
            ConnFlags::NODELAY,
            ConnFlags::ALIVE,
            ConnFlags::WANT_DRAIN,
            ConnFlags::UPGRADED,
        ];
        for (i, &a) in all_flags.iter().enumerate() {
            assert!(a.is_power_of_two(), "flag index {} is not a power of 2", i);
            for (j, &b) in all_flags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "flag index {} and {} collide", i, j);
                }
            }
        }
    }

    #[test]
    fn conn_flags_set_and_clear_individual_flags() {
        let flags = ConnFlags::new();

        // Test each flag individually: set, verify, clear, verify.
        for &flag in &[
            ConnFlags::CONNECTED,
            ConnFlags::SSL,
            ConnFlags::H2,
            ConnFlags::KEEPALIVE,
            ConnFlags::CORKED,
            ConnFlags::WEBSOCKET,
            ConnFlags::UPGRADED,
        ] {
            flags.set(flag);
            assert!(flags.has(flag));
            flags.clear(flag);
            assert!(!flags.has(flag));
        }
    }

    #[test]
    fn conn_flags_multiple_simultaneous() {
        let flags = ConnFlags::new();

        // Set SSL + H2 + KEEPALIVE at once.
        flags.set(ConnFlags::SSL | ConnFlags::H2 | ConnFlags::KEEPALIVE);
        assert!(flags.has(ConnFlags::SSL));
        assert!(flags.has(ConnFlags::H2));
        assert!(flags.has(ConnFlags::KEEPALIVE));
        assert!(flags.has(ConnFlags::SSL | ConnFlags::H2)); // all bits
        assert!(flags.has(ConnFlags::SSL | ConnFlags::H2 | ConnFlags::KEEPALIVE));

        // Clear only H2.
        flags.clear(ConnFlags::H2);
        assert!(flags.has(ConnFlags::SSL));
        assert!(!flags.has(ConnFlags::H2));
        assert!(flags.has(ConnFlags::KEEPALIVE));

        // has() returns false if not ALL bits are set.
        assert!(!flags.has(ConnFlags::SSL | ConnFlags::H2));

        // has_any() returns true if ANY bit matches.
        assert!(flags.has_any(ConnFlags::SSL | ConnFlags::H2));
    }

    #[test]
    fn conn_flags_raw_snapshot() {
        let flags = ConnFlags::new();
        let initial = flags.raw();
        assert_eq!(initial, ConnFlags::ALIVE);

        flags.set(ConnFlags::CONNECTED);
        assert_eq!(flags.raw(), ConnFlags::ALIVE | ConnFlags::CONNECTED);
    }

    #[test]
    fn conn_flags_debug_format() {
        let flags = ConnFlags::new();
        let debug_str = format!("{:?}", flags);
        // Should contain "ConnFlags(0x" prefix.
        assert!(debug_str.starts_with("ConnFlags(0x"));
        assert!(debug_str.ends_with(')'));
    }

    // ── ConnState: detailed independent half-state tests ──

    #[test]
    fn conn_state_new_defaults() {
        let state = ConnState::new();
        assert_eq!(state.read(), HalfState::Ready);
        assert_eq!(state.write(), HalfState::Ready);
        assert_eq!(state.bytes_read(), 0);
        assert_eq!(state.bytes_written(), 0);
        assert!(state.is_active());
        assert!(!state.is_closed());
        assert!(state.flags.has(ConnFlags::ALIVE));
    }

    #[test]
    fn conn_state_default_trait() {
        let state = ConnState::default();
        assert_eq!(state.read(), HalfState::Ready);
        assert_eq!(state.write(), HalfState::Ready);
    }

    #[test]
    fn conn_state_independent_read_write() {
        let state = ConnState::new();

        // Move read to Data, write stays Ready.
        state.transition_read(HalfState::Data).unwrap();
        assert_eq!(state.read(), HalfState::Data);
        assert_eq!(state.write(), HalfState::Ready);
        assert!(state.is_active());

        // Move write to Error, read stays Data.
        state.transition_write(HalfState::Error).unwrap();
        assert_eq!(state.read(), HalfState::Data);
        assert_eq!(state.write(), HalfState::Error);
        assert!(state.is_active()); // read is still active

        // Move read to Error too.
        state.transition_read(HalfState::Error).unwrap();
        assert!(!state.is_active());
        assert!(state.is_closed());
    }

    #[test]
    fn conn_state_read_shut_write_active() {
        let state = ConnState::new();

        // Shut down read side completely.
        state.transition_read(HalfState::ShutWanted).unwrap();
        state.transition_read(HalfState::ShutDone).unwrap();

        // Write side still active → not fully closed.
        assert!(!state.is_closed());
        assert!(state.is_active()); // write side is Ready (active).

        // Now shut down write side.
        state.transition_write(HalfState::ShutWanted).unwrap();
        assert!(!state.is_active()); // ShutWanted is not active.
        assert!(!state.is_closed()); // not terminal yet.

        state.transition_write(HalfState::ShutDone).unwrap();
        assert!(state.is_closed());
    }

    #[test]
    fn conn_state_bytes_accumulation() {
        let state = ConnState::new();

        state.record_read(100);
        state.record_read(200);
        state.record_read(300);
        assert_eq!(state.bytes_read(), 600);

        state.record_write(50);
        state.record_write(150);
        assert_eq!(state.bytes_written(), 200);
    }

    #[test]
    fn conn_state_age_is_positive() {
        let state = ConnState::new();
        // Age should be extremely small but non-negative.
        let age = state.age();
        assert!(age.as_secs() < 1);
    }

    #[test]
    fn conn_state_idle_ms_updates_on_io() {
        let state = ConnState::new();
        // Record I/O to update last_activity.
        state.record_read(1);
        let idle1 = state.idle_ms();
        // Idle should be very small right after I/O.
        assert!(idle1 < 100);
    }

    #[test]
    fn conn_state_transition_read_returns_previous() {
        let state = ConnState::new();
        let prev = state.transition_read(HalfState::Data).unwrap();
        assert_eq!(prev, HalfState::Ready);

        let prev = state.transition_read(HalfState::ShutWanted).unwrap();
        assert_eq!(prev, HalfState::Data);
    }

    #[test]
    fn conn_state_transition_write_returns_previous() {
        let state = ConnState::new();
        let prev = state.transition_write(HalfState::Data).unwrap();
        assert_eq!(prev, HalfState::Ready);

        let prev = state.transition_write(HalfState::Ready).unwrap();
        assert_eq!(prev, HalfState::Data);
    }

    #[test]
    fn conn_state_transition_error_returns_current_on_failure() {
        let state = ConnState::new();
        state.transition_read(HalfState::Error).unwrap();

        let err = state.transition_read(HalfState::Data).unwrap_err();
        assert_eq!(err, HalfState::Error);
    }

    #[test]
    fn conn_state_is_connected_flag() {
        let state = ConnState::new();
        assert!(!state.flags.has(ConnFlags::CONNECTED));

        state.flags.set(ConnFlags::CONNECTED);
        assert!(state.flags.has(ConnFlags::CONNECTED));

        state.flags.clear(ConnFlags::CONNECTED);
        assert!(!state.flags.has(ConnFlags::CONNECTED));
    }

    // ── WriteCoalescer: additional edge cases ──

    #[test]
    fn coalescer_with_defaults() {
        let coalescer = WriteCoalescer::with_defaults();
        assert!(coalescer.is_empty());
        assert_eq!(coalescer.pending_bytes(), 0);
        assert!(!coalescer.should_flush());
    }

    #[test]
    fn coalescer_take_buffer_empty() {
        let mut coalescer = WriteCoalescer::new(1024, Duration::from_secs(1));
        let buf = coalescer.take_buffer();
        assert!(buf.is_empty());
        // Flush count still increments.
        let (_, flushes, bytes) = coalescer.metrics();
        assert_eq!(flushes, 1);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn coalescer_ratio_zero_flushes() {
        let coalescer = WriteCoalescer::new(1024, Duration::from_secs(1));
        assert_eq!(coalescer.coalesce_ratio(), 0.0);
    }

    #[test]
    fn coalescer_small_capacity() {
        let mut coalescer = WriteCoalescer::new(5, Duration::from_secs(10));

        // Exactly at capacity triggers flush.
        assert!(coalescer.write(b"12345"));
        let buf = coalescer.take_buffer();
        assert_eq!(&buf, b"12345");
        assert!(coalescer.is_empty());
    }

    #[test]
    fn coalescer_multiple_flushes() {
        let mut coalescer = WriteCoalescer::new(4, Duration::from_secs(10));

        coalescer.write(b"aa");
        coalescer.write(b"bb"); // 4 bytes = capacity → should_flush
        assert!(coalescer.should_flush());
        let batch1 = coalescer.take_buffer();
        assert_eq!(&batch1, b"aabb");

        coalescer.write(b"cc");
        assert!(!coalescer.should_flush());
        coalescer.write(b"dd"); // 4 bytes again
        assert!(coalescer.should_flush());
        let batch2 = coalescer.take_buffer();
        assert_eq!(&batch2, b"ccdd");

        let (writes, flushes, bytes) = coalescer.metrics();
        assert_eq!(writes, 4);
        assert_eq!(flushes, 2);
        assert_eq!(bytes, 8);
        assert!((coalescer.coalesce_ratio() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coalescer_pending_bytes_tracks_accumulation() {
        let mut coalescer = WriteCoalescer::new(1024, Duration::from_secs(1));
        assert_eq!(coalescer.pending_bytes(), 0);

        coalescer.write(b"hello");
        assert_eq!(coalescer.pending_bytes(), 5);

        coalescer.write(b" world!");
        assert_eq!(coalescer.pending_bytes(), 12);

        coalescer.take_buffer();
        assert_eq!(coalescer.pending_bytes(), 0);
    }

    // ── TaskScheduler: all 5 priority levels ──

    #[test]
    fn scheduler_all_five_priorities() {
        let sched = TaskScheduler::with_defaults();

        // Push one task at each priority.
        let priorities = [
            TaskPriority::Idle,
            TaskPriority::Low,
            TaskPriority::Normal,
            TaskPriority::High,
            TaskPriority::Critical,
        ];
        for (i, &prio) in priorities.iter().enumerate() {
            sched.push(ScheduledTask {
                id: i as u64,
                priority: prio,
                kind: TaskKind::Custom,
                enqueued_at: Instant::now(),
            });
        }

        assert_eq!(sched.pending(), 5);

        // Pop order: Critical(4), High(3), Normal(2), Low(1), Idle(0).
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::High);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Normal);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Low);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Idle);
        assert!(sched.pop().is_none());
    }

    #[test]
    fn scheduler_pending_at_all_levels() {
        let sched = TaskScheduler::with_defaults();

        // Push varying counts per level.
        for _ in 0..3 {
            sched.push(ScheduledTask {
                id: 0,
                priority: TaskPriority::Critical,
                kind: TaskKind::HealthCheck,
                enqueued_at: Instant::now(),
            });
        }
        for _ in 0..2 {
            sched.push(ScheduledTask {
                id: 0,
                priority: TaskPriority::High,
                kind: TaskKind::RequestForward,
                enqueued_at: Instant::now(),
            });
        }
        sched.push(ScheduledTask {
            id: 0,
            priority: TaskPriority::Normal,
            kind: TaskKind::TlsHandshake,
            enqueued_at: Instant::now(),
        });
        // Low and Idle are empty.

        assert_eq!(sched.pending_at(TaskPriority::Critical), 3);
        assert_eq!(sched.pending_at(TaskPriority::High), 2);
        assert_eq!(sched.pending_at(TaskPriority::Normal), 1);
        assert_eq!(sched.pending_at(TaskPriority::Low), 0);
        assert_eq!(sched.pending_at(TaskPriority::Idle), 0);
        assert_eq!(sched.pending(), 6);
    }

    #[test]
    fn scheduler_fifo_within_same_priority() {
        let sched = TaskScheduler::with_defaults();

        for i in 0..5 {
            sched.push(ScheduledTask {
                id: i,
                priority: TaskPriority::Normal,
                kind: TaskKind::RequestForward,
                enqueued_at: Instant::now(),
            });
        }

        // Same-priority tasks come out in FIFO order.
        for i in 0..5 {
            assert_eq!(sched.pop().unwrap().id, i);
        }
    }

    #[test]
    fn scheduler_anti_starvation_picks_lowest_occupied() {
        let sched = TaskScheduler::new(2); // Starvation limit = 2.

        // Push Critical and Low tasks (skip High/Normal/Idle).
        for i in 0..4 {
            sched.push(ScheduledTask {
                id: i,
                priority: TaskPriority::Critical,
                kind: TaskKind::HealthCheck,
                enqueued_at: Instant::now(),
            });
        }
        sched.push(ScheduledTask {
            id: 50,
            priority: TaskPriority::Low,
            kind: TaskKind::MetricsFlush,
            enqueued_at: Instant::now(),
        });

        // Pop 2 Critical (hits starvation limit).
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);

        // 3rd pop: anti-starvation kicks in, scans from lowest (Idle→Low).
        // Only Low has tasks, so it should be picked.
        let task = sched.pop().unwrap();
        assert_eq!(task.priority, TaskPriority::Low);
        assert_eq!(task.id, 50);
    }

    #[test]
    fn scheduler_anti_starvation_resets_counter() {
        let sched = TaskScheduler::new(2);

        // 4 Critical, 1 Idle.
        for i in 0..4 {
            sched.push(ScheduledTask {
                id: i,
                priority: TaskPriority::Critical,
                kind: TaskKind::HealthCheck,
                enqueued_at: Instant::now(),
            });
        }
        sched.push(ScheduledTask {
            id: 100,
            priority: TaskPriority::Idle,
            kind: TaskKind::ConnCleanup,
            enqueued_at: Instant::now(),
        });

        // Pop 2 Critical → starvation fires → Idle gets served.
        sched.pop(); // Critical
        sched.pop(); // Critical
        let anti_starved = sched.pop().unwrap();
        assert_eq!(anti_starved.priority, TaskPriority::Idle);

        // Counter resets, so next pops resume normal (Critical).
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        assert!(sched.pop().is_none());
    }

    #[test]
    fn scheduler_popped_at_per_level() {
        let sched = TaskScheduler::with_defaults();

        sched.push(ScheduledTask {
            id: 1,
            priority: TaskPriority::Critical,
            kind: TaskKind::HealthCheck,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 2,
            priority: TaskPriority::High,
            kind: TaskKind::RequestForward,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 3,
            priority: TaskPriority::Idle,
            kind: TaskKind::ConnCleanup,
            enqueued_at: Instant::now(),
        });

        sched.pop(); // Critical
        sched.pop(); // High
        sched.pop(); // Idle

        assert_eq!(sched.popped_at(TaskPriority::Critical), 1);
        assert_eq!(sched.popped_at(TaskPriority::High), 1);
        assert_eq!(sched.popped_at(TaskPriority::Normal), 0);
        assert_eq!(sched.popped_at(TaskPriority::Low), 0);
        assert_eq!(sched.popped_at(TaskPriority::Idle), 1);
        assert_eq!(sched.total_popped(), 3);
    }

    #[test]
    fn scheduler_non_critical_resets_consecutive_counter() {
        let sched = TaskScheduler::new(10);

        sched.push(ScheduledTask {
            id: 1,
            priority: TaskPriority::Critical,
            kind: TaskKind::HealthCheck,
            enqueued_at: Instant::now(),
        });
        sched.push(ScheduledTask {
            id: 2,
            priority: TaskPriority::Normal,
            kind: TaskKind::RequestForward,
            enqueued_at: Instant::now(),
        });

        // Pop Critical, then Normal — popping Normal resets consecutive_top.
        sched.pop(); // Critical: consecutive_top = 1
        sched.pop(); // Normal: consecutive_top = 0

        // Push more Critical — starvation counter starts fresh.
        for i in 10..20 {
            sched.push(ScheduledTask {
                id: i,
                priority: TaskPriority::Critical,
                kind: TaskKind::HealthCheck,
                enqueued_at: Instant::now(),
            });
        }
        // Can pop 10 Critical without triggering anti-starvation.
        for _ in 0..10 {
            assert_eq!(sched.pop().unwrap().priority, TaskPriority::Critical);
        }
    }

    #[test]
    fn scheduler_anti_starvation_all_empty_returns_none() {
        let sched = TaskScheduler::new(1);

        // Push and pop 1 Critical to trigger anti-starvation state.
        sched.push(ScheduledTask {
            id: 1,
            priority: TaskPriority::Critical,
            kind: TaskKind::HealthCheck,
            enqueued_at: Instant::now(),
        });
        sched.pop(); // consecutive_top = 1 (at limit)

        // Next pop: anti-starvation scans but all queues empty.
        assert!(sched.pop().is_none());
    }

    // ── TaskPriority ──

    #[test]
    fn task_priority_u8_roundtrip() {
        assert_eq!(TaskPriority::from_u8(0), TaskPriority::Critical);
        assert_eq!(TaskPriority::from_u8(1), TaskPriority::High);
        assert_eq!(TaskPriority::from_u8(2), TaskPriority::Normal);
        assert_eq!(TaskPriority::from_u8(3), TaskPriority::Low);
        assert_eq!(TaskPriority::from_u8(4), TaskPriority::Idle);
        // Out of range → Idle.
        assert_eq!(TaskPriority::from_u8(5), TaskPriority::Idle);
        assert_eq!(TaskPriority::from_u8(255), TaskPriority::Idle);
    }

    #[test]
    fn task_priority_ordering() {
        // Critical < High < Normal < Low < Idle (lower value = higher priority).
        assert!(TaskPriority::Critical < TaskPriority::High);
        assert!(TaskPriority::High < TaskPriority::Normal);
        assert!(TaskPriority::Normal < TaskPriority::Low);
        assert!(TaskPriority::Low < TaskPriority::Idle);
    }

    // ── ConnTracker: additional coverage ──

    #[test]
    fn tracker_remove_nonexistent() {
        let tracker = ConnTracker::new();
        assert!(!tracker.remove(999));
        assert_eq!(tracker.total_closed(), 0);
    }

    #[test]
    fn tracker_get_nonexistent() {
        let tracker = ConnTracker::new();
        assert!(tracker.get(999).is_none());
    }

    #[test]
    fn tracker_default_trait() {
        let tracker = ConnTracker::default();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_created(), 0);
        assert_eq!(tracker.total_closed(), 0);
    }

    #[test]
    fn tracker_ids_are_monotonic() {
        let tracker = ConnTracker::new();
        let id1 = tracker.register();
        let id2 = tracker.register();
        let id3 = tracker.register();
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn tracker_reap_only_closed() {
        let tracker = ConnTracker::new();

        let id_active = tracker.register();
        let id_half_closed = tracker.register();
        let id_fully_closed = tracker.register();
        let id_errored = tracker.register();

        // id_active: stays Ready/Ready — not reaped.
        // id_half_closed: read shut, write active — not reaped.
        {
            let conn = tracker.get(id_half_closed).unwrap();
            conn.transition_read(HalfState::ShutWanted).unwrap();
            conn.transition_read(HalfState::ShutDone).unwrap();
        }

        // id_fully_closed: both directions ShutDone — reaped.
        {
            let conn = tracker.get(id_fully_closed).unwrap();
            conn.transition_read(HalfState::ShutWanted).unwrap();
            conn.transition_read(HalfState::ShutDone).unwrap();
            conn.transition_write(HalfState::ShutWanted).unwrap();
            conn.transition_write(HalfState::ShutDone).unwrap();
        }

        // id_errored: both directions Error — also reaped (both terminal).
        {
            let conn = tracker.get(id_errored).unwrap();
            conn.transition_read(HalfState::Error).unwrap();
            conn.transition_write(HalfState::Error).unwrap();
        }

        assert_eq!(tracker.active_count(), 4);
        let reaped = tracker.reap_closed();
        assert_eq!(reaped, 2); // fully_closed + errored
        assert_eq!(tracker.active_count(), 2);

        // Verify surviving connections.
        assert!(tracker.get(id_active).is_some());
        assert!(tracker.get(id_half_closed).is_some());
        assert!(tracker.get(id_fully_closed).is_none());
        assert!(tracker.get(id_errored).is_none());
    }

    #[test]
    fn tracker_reap_updates_total_closed() {
        let tracker = ConnTracker::new();
        let id = tracker.register();

        {
            let conn = tracker.get(id).unwrap();
            conn.transition_read(HalfState::Error).unwrap();
            conn.transition_write(HalfState::Error).unwrap();
        }

        assert_eq!(tracker.total_closed(), 0);
        tracker.reap_closed();
        assert_eq!(tracker.total_closed(), 1);
    }

    #[test]
    fn tracker_idle_connections_filtering() {
        let tracker = ConnTracker::new();

        let id1 = tracker.register();
        let id2 = tracker.register();

        // Touch id1 to update its activity timestamp.
        {
            let conn = tracker.get(id1).unwrap();
            conn.record_read(1);
        }

        // With a threshold of 0ms, both should show up (or very few,
        // depending on timing). With a huge threshold, none.
        let idle = tracker.idle_connections(999_999_999);
        assert!(idle.is_empty());

        // Both were just created, idle should be < 100ms.
        // We can at least verify the function returns a Vec.
        let _ = tracker.idle_connections(0);
        // Verify id2 exists (basic sanity).
        assert!(tracker.get(id2).is_some());
    }

    #[test]
    fn tracker_remove_double_remove() {
        let tracker = ConnTracker::new();
        let id = tracker.register();

        assert!(tracker.remove(id));
        assert!(!tracker.remove(id)); // second remove returns false
        assert_eq!(tracker.total_closed(), 1); // only incremented once
    }

    // ── EventLoopMetrics ──

    #[test]
    fn event_loop_metrics_new() {
        let metrics = EventLoopMetrics::new();
        assert_eq!(metrics.wakeups.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.writes_coalesced.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.cork_batches.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.tasks_scheduled.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.connections_tracked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn event_loop_metrics_increment() {
        let metrics = EventLoopMetrics::new();

        metrics.wakeups.fetch_add(10, Ordering::Relaxed);
        metrics.writes_coalesced.fetch_add(5, Ordering::Relaxed);
        metrics.cork_batches.fetch_add(3, Ordering::Relaxed);
        metrics.tasks_scheduled.fetch_add(42, Ordering::Relaxed);
        metrics.connections_tracked.fetch_add(100, Ordering::Relaxed);

        assert_eq!(metrics.wakeups.load(Ordering::Relaxed), 10);
        assert_eq!(metrics.writes_coalesced.load(Ordering::Relaxed), 5);
        assert_eq!(metrics.cork_batches.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.tasks_scheduled.load(Ordering::Relaxed), 42);
        assert_eq!(metrics.connections_tracked.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn global_metrics_accessible() {
        let m = global_metrics();
        // Global metrics are shared across tests, so we just verify access.
        let _ = m.wakeups.load(Ordering::Relaxed);
        let _ = m.writes_coalesced.load(Ordering::Relaxed);
        let _ = m.cork_batches.load(Ordering::Relaxed);
        let _ = m.tasks_scheduled.load(Ordering::Relaxed);
        let _ = m.connections_tracked.load(Ordering::Relaxed);
    }

    // ── elapsed_ms ──

    #[test]
    fn elapsed_ms_is_small_at_start() {
        let ms = elapsed_ms();
        // Process has been running for tests, but should still be reasonable.
        assert!(ms < 600_000, "elapsed_ms returned unreasonably large value: {}", ms);
    }

    // ── CorkGuard (Unix, additional tests) ──

    #[cfg(unix)]
    #[test]
    fn cork_guard_bad_fd_fails() {
        let result = CorkGuard::new(-1);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cork_guard_fd_accessor() {
        // Use a pipe FD (not a TCP socket, so cork will fail, but we
        // test the accessor on a successfully-created guard is not possible
        // with a non-TCP FD). Instead, test fd() on the struct directly.
        // We can't easily create a valid CorkGuard without a TCP socket,
        // but we can verify the type system.
        let result = CorkGuard::new(-1);
        assert!(result.is_err());
    }

    // ── ConnState: write-side error path ──

    #[test]
    fn conn_state_write_error_path() {
        let state = ConnState::new();
        state.transition_write(HalfState::Data).unwrap();
        state.transition_write(HalfState::Error).unwrap();

        assert_eq!(state.write(), HalfState::Error);
        // Write is terminal, read is still active.
        assert!(!state.is_closed());
        assert!(state.is_active());

        // Cannot transition write out of Error.
        assert!(state.transition_write(HalfState::Ready).is_err());
    }

    #[test]
    fn conn_state_shutwanted_to_error() {
        let state = ConnState::new();

        // Read: Ready → ShutWanted → Error (valid).
        state.transition_read(HalfState::ShutWanted).unwrap();
        state.transition_read(HalfState::Error).unwrap();
        assert_eq!(state.read(), HalfState::Error);

        // Write: Ready → ShutWanted → Error (valid).
        state.transition_write(HalfState::ShutWanted).unwrap();
        state.transition_write(HalfState::Error).unwrap();
        assert_eq!(state.write(), HalfState::Error);

        assert!(state.is_closed());
    }

    // ── TaskKind ──

    #[test]
    fn task_kind_debug() {
        // Ensure all TaskKind variants have Debug output.
        let kinds = [
            TaskKind::RequestForward,
            TaskKind::HealthCheck,
            TaskKind::MetricsFlush,
            TaskKind::ConnCleanup,
            TaskKind::ConfigReload,
            TaskKind::TlsHandshake,
            TaskKind::DnsResolve,
            TaskKind::Custom,
        ];
        for kind in &kinds {
            let debug_str = format!("{:?}", kind);
            assert!(!debug_str.is_empty());
        }
    }

    // ── EventLoopStrategy: exhaustive ──

    #[test]
    fn event_loop_strategy_debug() {
        let strategies = [
            EventLoopStrategy::Default,
            EventLoopStrategy::Coalesced,
            EventLoopStrategy::Prioritized,
            EventLoopStrategy::Full,
        ];
        for s in &strategies {
            let debug_str = format!("{:?}", s);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn event_loop_strategy_equality() {
        assert_eq!(EventLoopStrategy::Default, EventLoopStrategy::Default);
        assert_ne!(EventLoopStrategy::Default, EventLoopStrategy::Full);
        assert_eq!(EventLoopStrategy::Full, EventLoopStrategy::Full);
    }
}
