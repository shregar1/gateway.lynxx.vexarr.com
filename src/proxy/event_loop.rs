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
}
