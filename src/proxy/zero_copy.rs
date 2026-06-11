//! Zero-copy data transfer — splice, sendfile, and MSG_ZEROCOPY support.
//!
//! Eliminates user-space copies on the hot path by leveraging kernel primitives:
//! - **splice()**: pipe-based zero-copy between two file descriptors
//! - **sendfile()**: direct kernel-to-socket transfer for static files
//! - **MSG_ZEROCOPY**: zero-copy send via SO_ZEROCOPY socket option
//! - **copy_file_range()**: server-side copy between files
//!
//! Each method has different prerequisites and trade-offs. This module detects
//! available methods and picks the best one per-transfer.
//!
//! # When zero-copy helps
//!
//! Zero-copy is most effective for large transfers (>= 16 KB) where avoiding
//! the memcpy between kernel and user buffers saves significant CPU. For small
//! transfers (< 4 KB), the overhead of setting up zero-copy often exceeds the
//! copy cost.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════════
// Global toggles
// ═══════════════════════════════════════════════════════════════════════════

static ZERO_COPY_ENABLED: AtomicBool = AtomicBool::new(false);
static PREFERRED_METHOD: AtomicU8 = AtomicU8::new(0); // 0 = Auto

pub fn is_zero_copy_enabled() -> bool {
    ZERO_COPY_ENABLED.load(Ordering::Relaxed)
}

pub fn set_zero_copy_enabled(v: bool) {
    ZERO_COPY_ENABLED.store(v, Ordering::Relaxed);
}

pub fn get_preferred_method() -> TransferMethod {
    TransferMethod::from_u8(PREFERRED_METHOD.load(Ordering::Relaxed))
}

pub fn set_preferred_method(method: TransferMethod) {
    PREFERRED_METHOD.store(method as u8, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Transfer methods
// ═══════════════════════════════════════════════════════════════════════════

/// Available zero-copy transfer methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferMethod {
    /// Auto-detect the best method per transfer.
    Auto = 0,
    /// splice() — pipe-based, works between any two fds.
    Splice = 1,
    /// sendfile() — optimized for file-to-socket.
    Sendfile = 2,
    /// MSG_ZEROCOPY — socket send without copy.
    MsgZerocopy = 3,
    /// copy_file_range() — kernel-side file copy.
    CopyFileRange = 4,
    /// Traditional read/write with user-space buffer (fallback).
    Traditional = 5,
}

impl TransferMethod {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Splice,
            2 => Self::Sendfile,
            3 => Self::MsgZerocopy,
            4 => Self::CopyFileRange,
            5 => Self::Traditional,
            _ => Self::Auto,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Splice => "splice",
            Self::Sendfile => "sendfile",
            Self::MsgZerocopy => "msg_zerocopy",
            Self::CopyFileRange => "copy_file_range",
            Self::Traditional => "traditional",
        }
    }

    /// Whether this method avoids user-space copies.
    pub fn is_zero_copy(&self) -> bool {
        matches!(
            self,
            Self::Splice | Self::Sendfile | Self::MsgZerocopy | Self::CopyFileRange
        )
    }

    /// Whether this method requires a pipe.
    pub fn needs_pipe(&self) -> bool {
        matches!(self, Self::Splice)
    }

    /// Whether this method requires a file fd (not a socket).
    pub fn needs_file_fd(&self) -> bool {
        matches!(self, Self::Sendfile | Self::CopyFileRange)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Transfer descriptor
// ═══════════════════════════════════════════════════════════════════════════

/// Describes a single zero-copy transfer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdType {
    /// Regular file.
    File,
    /// TCP socket.
    TcpSocket,
    /// UDP socket.
    UdpSocket,
    /// Unix domain socket.
    UnixSocket,
    /// Pipe fd.
    Pipe,
    /// Unknown fd type.
    Unknown,
}

impl FdType {
    pub fn is_socket(&self) -> bool {
        matches!(self, Self::TcpSocket | Self::UdpSocket | Self::UnixSocket)
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File)
    }
}

/// A pending transfer to be executed with zero-copy if possible.
#[derive(Debug, Clone)]
pub struct TransferDescriptor {
    /// Source file descriptor type.
    pub src_type: FdType,
    /// Destination file descriptor type.
    pub dst_type: FdType,
    /// Total bytes to transfer (0 = until EOF).
    pub length: u64,
    /// Offset in the source (for sendfile/splice).
    pub src_offset: u64,
    /// Hint: is this a static file being served?
    pub is_static_file: bool,
}

impl TransferDescriptor {
    pub fn new(src_type: FdType, dst_type: FdType, length: u64) -> Self {
        Self {
            src_type,
            dst_type,
            length,
            src_offset: 0,
            is_static_file: false,
        }
    }

    pub fn with_offset(mut self, offset: u64) -> Self {
        self.src_offset = offset;
        self
    }

    pub fn with_static_file(mut self) -> Self {
        self.is_static_file = true;
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Method selector
// ═══════════════════════════════════════════════════════════════════════════

/// Minimum transfer size where zero-copy starts to pay off.
const MIN_ZERO_COPY_SIZE: u64 = 16 * 1024; // 16 KB

/// Below this size, the overhead of zero-copy setup isn't worth it.
const SMALL_TRANSFER_THRESHOLD: u64 = 4 * 1024; // 4 KB

/// Selects the best transfer method for a given descriptor.
pub fn select_method(desc: &TransferDescriptor, caps: &ZeroCopyCapabilities) -> TransferMethod {
    // Tiny transfers: always use traditional.
    if desc.length > 0 && desc.length < SMALL_TRANSFER_THRESHOLD {
        return TransferMethod::Traditional;
    }

    // File → Socket: sendfile is the best if available.
    if desc.src_type.is_file() && desc.dst_type.is_socket() && caps.sendfile {
        return TransferMethod::Sendfile;
    }

    // File → File: copy_file_range if available.
    if desc.src_type.is_file() && desc.dst_type.is_file() && caps.copy_file_range {
        return TransferMethod::CopyFileRange;
    }

    // Socket → Socket (proxying): splice through a pipe.
    if desc.src_type.is_socket() && desc.dst_type.is_socket() && caps.splice {
        if desc.length == 0 || desc.length >= MIN_ZERO_COPY_SIZE {
            return TransferMethod::Splice;
        }
    }

    // Large socket sends: MSG_ZEROCOPY.
    if desc.dst_type.is_socket() && caps.msg_zerocopy {
        if desc.length == 0 || desc.length >= MIN_ZERO_COPY_SIZE {
            return TransferMethod::MsgZerocopy;
        }
    }

    // Splice as general fallback for large transfers.
    if caps.splice && (desc.length == 0 || desc.length >= MIN_ZERO_COPY_SIZE) {
        return TransferMethod::Splice;
    }

    TransferMethod::Traditional
}

// ═══════════════════════════════════════════════════════════════════════════
// Capabilities
// ═══════════════════════════════════════════════════════════════════════════

/// Detected zero-copy capabilities of the running kernel.
#[derive(Debug, Clone)]
pub struct ZeroCopyCapabilities {
    /// splice() available (Linux 2.6.17+).
    pub splice: bool,
    /// sendfile() available (Linux 2.2+).
    pub sendfile: bool,
    /// MSG_ZEROCOPY / SO_ZEROCOPY available (Linux 4.14+).
    pub msg_zerocopy: bool,
    /// copy_file_range() available (Linux 4.5+).
    pub copy_file_range: bool,
    /// TCP cork available (for batching small writes).
    pub tcp_cork: bool,
    /// TCP_NODELAY available.
    pub tcp_nodelay: bool,
}

impl ZeroCopyCapabilities {
    /// Probe the current system.
    #[cfg(target_os = "linux")]
    pub fn detect() -> Self {
        Self {
            splice: true,      // Available since 2.6.17
            sendfile: true,    // Available since 2.2
            msg_zerocopy: Self::check_kernel_version(4, 14),
            copy_file_range: Self::check_kernel_version(4, 5),
            tcp_cork: true,
            tcp_nodelay: true,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Self {
        Self {
            splice: false,
            sendfile: cfg!(target_os = "macos"), // macOS has sendfile
            msg_zerocopy: false,
            copy_file_range: false,
            tcp_cork: false,
            tcp_nodelay: true,
        }
    }

    #[cfg(target_os = "linux")]
    fn check_kernel_version(major: u16, minor: u16) -> bool {
        if let Ok(content) = std::fs::read_to_string("/proc/version") {
            if let Some(version_str) = content.split_whitespace().nth(2) {
                let parts: Vec<u16> = version_str
                    .split('-')
                    .next()
                    .unwrap_or("")
                    .split('.')
                    .filter_map(|p| p.parse().ok())
                    .collect();
                if parts.len() >= 2 {
                    return parts[0] > major || (parts[0] == major && parts[1] >= minor);
                }
            }
        }
        false
    }

    /// Build from explicit values (for testing).
    pub fn all_enabled() -> Self {
        Self {
            splice: true,
            sendfile: true,
            msg_zerocopy: true,
            copy_file_range: true,
            tcp_cork: true,
            tcp_nodelay: true,
        }
    }

    pub fn none_enabled() -> Self {
        Self {
            splice: false,
            sendfile: false,
            msg_zerocopy: false,
            copy_file_range: false,
            tcp_cork: false,
            tcp_nodelay: false,
        }
    }

    /// Count of available zero-copy methods.
    pub fn available_methods(&self) -> u8 {
        let mut count = 0;
        if self.splice {
            count += 1;
        }
        if self.sendfile {
            count += 1;
        }
        if self.msg_zerocopy {
            count += 1;
        }
        if self.copy_file_range {
            count += 1;
        }
        count
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Pipe pool
// ═══════════════════════════════════════════════════════════════════════════

/// A pool of pre-created pipes for splice() operations.
/// Avoids the overhead of pipe() + close() per transfer.
pub struct PipePool {
    /// Available pipes (each is a (read_fd, write_fd) pair represented as indices).
    available: Vec<PipeEntry>,
    /// Maximum pool size.
    max_size: usize,
    /// Default pipe buffer size.
    pipe_size: usize,
    /// Total pipes ever created.
    total_created: u64,
    /// Total pipes reused from pool.
    total_reused: u64,
}

/// A pipe entry in the pool.
#[derive(Debug, Clone)]
pub struct PipeEntry {
    /// Unique ID for tracking.
    pub id: u64,
    /// Pipe buffer size in bytes.
    pub buffer_size: usize,
    /// When this pipe was created.
    pub created_at: Instant,
    /// Number of times this pipe has been reused.
    pub reuse_count: u32,
}

impl PipeEntry {
    pub fn new(id: u64, buffer_size: usize) -> Self {
        Self {
            id,
            buffer_size,
            created_at: Instant::now(),
            reuse_count: 0,
        }
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl PipePool {
    pub fn new(max_size: usize, pipe_size: usize) -> Self {
        Self {
            available: Vec::with_capacity(max_size),
            max_size: max_size.max(4),
            pipe_size: pipe_size.max(4096),
            total_created: 0,
            total_reused: 0,
        }
    }

    /// Acquire a pipe from the pool, or create a new one.
    pub fn acquire(&mut self) -> PipeEntry {
        if let Some(mut pipe) = self.available.pop() {
            pipe.reuse_count += 1;
            self.total_reused += 1;
            pipe
        } else {
            self.total_created += 1;
            PipeEntry::new(self.total_created, self.pipe_size)
        }
    }

    /// Return a pipe to the pool.
    pub fn release(&mut self, pipe: PipeEntry) {
        if self.available.len() < self.max_size {
            self.available.push(pipe);
        }
        // Otherwise, let it drop (close the fds).
    }

    /// Current pool size (available pipes).
    pub fn available_count(&self) -> usize {
        self.available.len()
    }

    /// Total pipes created across the lifetime.
    pub fn total_created(&self) -> u64 {
        self.total_created
    }

    /// Hit rate (reuses / total acquisitions).
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_created + self.total_reused;
        if total == 0 {
            return 0.0;
        }
        self.total_reused as f64 / total as f64
    }

    /// Evict pipes older than the given duration.
    pub fn evict_stale(&mut self, max_age: Duration) -> usize {
        let before = self.available.len();
        self.available.retain(|p| p.age() < max_age);
        before - self.available.len()
    }

    /// Pre-fill the pool with pipes.
    pub fn prefill(&mut self, count: usize) {
        let to_create = count.min(self.max_size - self.available.len());
        for _ in 0..to_create {
            self.total_created += 1;
            self.available
                .push(PipeEntry::new(self.total_created, self.pipe_size));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Transfer tracker
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks an in-progress zero-copy transfer.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Transfer ID.
    pub id: u64,
    /// Method being used.
    pub method: TransferMethod,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Total bytes expected (0 = unknown).
    pub total_bytes: u64,
    /// When the transfer started.
    pub started: Instant,
    /// Number of syscalls made.
    pub syscall_count: u32,
    /// Whether a fallback to traditional I/O occurred.
    pub fell_back: bool,
}

impl TransferProgress {
    pub fn new(id: u64, method: TransferMethod, total_bytes: u64) -> Self {
        Self {
            id,
            method,
            bytes_transferred: 0,
            total_bytes,
            started: Instant::now(),
            syscall_count: 0,
            fell_back: false,
        }
    }

    /// Record bytes transferred.
    pub fn advance(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
        self.syscall_count += 1;
    }

    /// Mark that a fallback occurred.
    pub fn mark_fallback(&mut self) {
        self.fell_back = true;
        self.method = TransferMethod::Traditional;
    }

    /// Is the transfer complete?
    pub fn is_complete(&self) -> bool {
        self.total_bytes > 0 && self.bytes_transferred >= self.total_bytes
    }

    /// Progress as a fraction 0.0 – 1.0.
    pub fn progress(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64).min(1.0)
    }

    /// Throughput in bytes/second.
    pub fn throughput(&self) -> f64 {
        let elapsed = self.started.elapsed().as_secs_f64();
        if elapsed < 0.0001 {
            return 0.0;
        }
        self.bytes_transferred as f64 / elapsed
    }

    /// Average bytes per syscall.
    pub fn avg_bytes_per_syscall(&self) -> f64 {
        if self.syscall_count == 0 {
            return 0.0;
        }
        self.bytes_transferred as f64 / self.syscall_count as f64
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Splice config
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for splice-based transfers.
#[derive(Debug, Clone)]
pub struct SpliceConfig {
    /// Maximum bytes per splice() call.
    pub chunk_size: usize,
    /// Whether to use SPLICE_F_MOVE (hint to move pages instead of copying).
    pub move_pages: bool,
    /// Whether to use SPLICE_F_NONBLOCK.
    pub nonblock: bool,
    /// Whether to use SPLICE_F_MORE (more data coming).
    pub more_data: bool,
    /// Pipe buffer size to request via fcntl(F_SETPIPE_SZ).
    pub pipe_buffer_size: usize,
}

impl SpliceConfig {
    pub fn default_config() -> Self {
        Self {
            chunk_size: 64 * 1024,        // 64 KB per splice call
            move_pages: true,
            nonblock: true,
            more_data: false,
            pipe_buffer_size: 256 * 1024, // 256 KB pipe buffer
        }
    }

    pub fn high_throughput() -> Self {
        Self {
            chunk_size: 256 * 1024,       // 256 KB per splice call
            move_pages: true,
            nonblock: true,
            more_data: true,
            pipe_buffer_size: 1024 * 1024, // 1 MB pipe buffer
        }
    }

    pub fn low_latency() -> Self {
        Self {
            chunk_size: 16 * 1024,        // 16 KB per splice call
            move_pages: false,
            nonblock: true,
            more_data: false,
            pipe_buffer_size: 64 * 1024,  // 64 KB pipe buffer
        }
    }

    /// Build splice flags from config.
    pub fn splice_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.move_pages {
            flags |= 0x01; // SPLICE_F_MOVE
        }
        if self.nonblock {
            flags |= 0x02; // SPLICE_F_NONBLOCK
        }
        if self.more_data {
            flags |= 0x04; // SPLICE_F_MORE
        }
        flags
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sendfile config
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for sendfile-based transfers.
#[derive(Debug, Clone)]
pub struct SendfileConfig {
    /// Maximum bytes per sendfile() call.
    pub chunk_size: usize,
    /// Whether to use TCP_CORK before sendfile.
    pub use_tcp_cork: bool,
    /// Whether to send HTTP headers before the file body in the same TCP segment.
    pub coalesce_headers: bool,
}

impl SendfileConfig {
    pub fn default_config() -> Self {
        Self {
            chunk_size: 128 * 1024,
            use_tcp_cork: true,
            coalesce_headers: true,
        }
    }

    pub fn large_files() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1 MB
            use_tcp_cork: true,
            coalesce_headers: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct ZeroCopyMetrics {
    pub splice_transfers: AtomicU64,
    pub splice_bytes: AtomicU64,
    pub sendfile_transfers: AtomicU64,
    pub sendfile_bytes: AtomicU64,
    pub zerocopy_sends: AtomicU64,
    pub zerocopy_bytes: AtomicU64,
    pub traditional_fallbacks: AtomicU64,
    pub traditional_bytes: AtomicU64,
}

static ZERO_COPY_METRICS: ZeroCopyMetrics = ZeroCopyMetrics {
    splice_transfers: AtomicU64::new(0),
    splice_bytes: AtomicU64::new(0),
    sendfile_transfers: AtomicU64::new(0),
    sendfile_bytes: AtomicU64::new(0),
    zerocopy_sends: AtomicU64::new(0),
    zerocopy_bytes: AtomicU64::new(0),
    traditional_fallbacks: AtomicU64::new(0),
    traditional_bytes: AtomicU64::new(0),
};

pub fn zero_copy_metrics() -> &'static ZeroCopyMetrics {
    &ZERO_COPY_METRICS
}

impl ZeroCopyMetrics {
    pub fn record_transfer(&self, method: TransferMethod, bytes: u64) {
        match method {
            TransferMethod::Splice => {
                self.splice_transfers.fetch_add(1, Ordering::Relaxed);
                self.splice_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            TransferMethod::Sendfile => {
                self.sendfile_transfers.fetch_add(1, Ordering::Relaxed);
                self.sendfile_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            TransferMethod::MsgZerocopy => {
                self.zerocopy_sends.fetch_add(1, Ordering::Relaxed);
                self.zerocopy_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            _ => {
                self.traditional_fallbacks.fetch_add(1, Ordering::Relaxed);
                self.traditional_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    /// Total zero-copy bytes across all methods.
    pub fn total_zero_copy_bytes(&self) -> u64 {
        self.splice_bytes.load(Ordering::Relaxed)
            + self.sendfile_bytes.load(Ordering::Relaxed)
            + self.zerocopy_bytes.load(Ordering::Relaxed)
    }

    /// Zero-copy rate (fraction of transfers that used zero-copy).
    pub fn zero_copy_rate(&self) -> f64 {
        let zc = self.splice_transfers.load(Ordering::Relaxed)
            + self.sendfile_transfers.load(Ordering::Relaxed)
            + self.zerocopy_sends.load(Ordering::Relaxed);
        let traditional = self.traditional_fallbacks.load(Ordering::Relaxed);
        let total = zc + traditional;
        if total == 0 {
            return 0.0;
        }
        zc as f64 / total as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Transfer method ───────────────────────────────────────────────

    #[test]
    fn method_roundtrip() {
        for v in 0..=5 {
            let m = TransferMethod::from_u8(v);
            assert!(!m.label().is_empty());
        }
        assert_eq!(TransferMethod::from_u8(99), TransferMethod::Auto);
    }

    #[test]
    fn method_is_zero_copy() {
        assert!(TransferMethod::Splice.is_zero_copy());
        assert!(TransferMethod::Sendfile.is_zero_copy());
        assert!(TransferMethod::MsgZerocopy.is_zero_copy());
        assert!(TransferMethod::CopyFileRange.is_zero_copy());
        assert!(!TransferMethod::Traditional.is_zero_copy());
        assert!(!TransferMethod::Auto.is_zero_copy());
    }

    #[test]
    fn method_needs_pipe() {
        assert!(TransferMethod::Splice.needs_pipe());
        assert!(!TransferMethod::Sendfile.needs_pipe());
    }

    #[test]
    fn method_needs_file() {
        assert!(TransferMethod::Sendfile.needs_file_fd());
        assert!(TransferMethod::CopyFileRange.needs_file_fd());
        assert!(!TransferMethod::Splice.needs_file_fd());
    }

    // ── Fd type ───────────────────────────────────────────────────────

    #[test]
    fn fd_type_categories() {
        assert!(FdType::TcpSocket.is_socket());
        assert!(FdType::UdpSocket.is_socket());
        assert!(FdType::UnixSocket.is_socket());
        assert!(!FdType::File.is_socket());
        assert!(!FdType::Pipe.is_socket());

        assert!(FdType::File.is_file());
        assert!(!FdType::TcpSocket.is_file());
    }

    // ── Method selection ──────────────────────────────────────────────

    #[test]
    fn select_sendfile_for_file_to_socket() {
        let caps = ZeroCopyCapabilities::all_enabled();
        let desc = TransferDescriptor::new(FdType::File, FdType::TcpSocket, 1024 * 1024);
        assert_eq!(select_method(&desc, &caps), TransferMethod::Sendfile);
    }

    #[test]
    fn select_splice_for_socket_to_socket() {
        let caps = ZeroCopyCapabilities::all_enabled();
        let desc = TransferDescriptor::new(FdType::TcpSocket, FdType::TcpSocket, 1024 * 1024);
        assert_eq!(select_method(&desc, &caps), TransferMethod::Splice);
    }

    #[test]
    fn select_copy_file_range_for_file_to_file() {
        let caps = ZeroCopyCapabilities::all_enabled();
        let desc = TransferDescriptor::new(FdType::File, FdType::File, 1024 * 1024);
        assert_eq!(select_method(&desc, &caps), TransferMethod::CopyFileRange);
    }

    #[test]
    fn select_traditional_for_small_transfer() {
        let caps = ZeroCopyCapabilities::all_enabled();
        let desc = TransferDescriptor::new(FdType::File, FdType::TcpSocket, 100); // 100 bytes
        assert_eq!(select_method(&desc, &caps), TransferMethod::Traditional);
    }

    #[test]
    fn select_traditional_when_no_caps() {
        let caps = ZeroCopyCapabilities::none_enabled();
        let desc = TransferDescriptor::new(FdType::File, FdType::TcpSocket, 1024 * 1024);
        assert_eq!(select_method(&desc, &caps), TransferMethod::Traditional);
    }

    #[test]
    fn select_splice_for_unknown_large_transfer() {
        let caps = ZeroCopyCapabilities {
            splice: true,
            sendfile: false,
            msg_zerocopy: false,
            copy_file_range: false,
            tcp_cork: false,
            tcp_nodelay: true,
        };
        let desc = TransferDescriptor::new(FdType::Pipe, FdType::TcpSocket, 100_000);
        assert_eq!(select_method(&desc, &caps), TransferMethod::Splice);
    }

    // ── Capabilities ──────────────────────────────────────────────────

    #[test]
    fn capabilities_detect_runs() {
        let caps = ZeroCopyCapabilities::detect();
        let _ = caps.available_methods();
    }

    #[test]
    fn capabilities_all_enabled() {
        let caps = ZeroCopyCapabilities::all_enabled();
        assert_eq!(caps.available_methods(), 4);
    }

    #[test]
    fn capabilities_none_enabled() {
        let caps = ZeroCopyCapabilities::none_enabled();
        assert_eq!(caps.available_methods(), 0);
    }

    // ── Pipe pool ─────────────────────────────────────────────────────

    #[test]
    fn pipe_pool_acquire_creates_new() {
        let mut pool = PipePool::new(10, 65536);
        let pipe = pool.acquire();
        assert_eq!(pipe.reuse_count, 0);
        assert_eq!(pool.total_created(), 1);
    }

    #[test]
    fn pipe_pool_release_and_reuse() {
        let mut pool = PipePool::new(10, 65536);
        let pipe = pool.acquire();
        let id = pipe.id;
        pool.release(pipe);
        assert_eq!(pool.available_count(), 1);

        let reused = pool.acquire();
        assert_eq!(reused.id, id);
        assert_eq!(reused.reuse_count, 1);
    }

    #[test]
    fn pipe_pool_capacity_limit() {
        let mut pool = PipePool::new(4, 65536); // min clamped to 4
        // Acquire all 4 first (creates new each time since pool is empty).
        let pipes: Vec<_> = (0..4).map(|_| pool.acquire()).collect();
        assert_eq!(pool.available_count(), 0);
        // Release all 4 back.
        for p in pipes {
            pool.release(p);
        }
        assert_eq!(pool.available_count(), 4);

        // Acquire one — pool has 3 remaining.
        let extra = pool.acquire();
        assert_eq!(pool.available_count(), 3);
        pool.release(extra);
        assert_eq!(pool.available_count(), 4);
    }

    #[test]
    fn pipe_pool_hit_rate() {
        let mut pool = PipePool::new(10, 65536);
        let p1 = pool.acquire(); // Miss
        pool.release(p1);
        let _p2 = pool.acquire(); // Hit
        assert!((pool.hit_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn pipe_pool_prefill() {
        let mut pool = PipePool::new(10, 65536);
        pool.prefill(5);
        assert_eq!(pool.available_count(), 5);
        assert_eq!(pool.total_created(), 5);
    }

    // ── Transfer progress ─────────────────────────────────────────────

    #[test]
    fn progress_tracking() {
        let mut p = TransferProgress::new(1, TransferMethod::Splice, 1000);
        assert!(!p.is_complete());
        assert_eq!(p.progress(), 0.0);

        p.advance(500);
        assert!((p.progress() - 0.5).abs() < 0.01);
        assert!(!p.is_complete());

        p.advance(500);
        assert!(p.is_complete());
        assert!((p.progress() - 1.0).abs() < 0.01);
    }

    #[test]
    fn progress_fallback() {
        let mut p = TransferProgress::new(1, TransferMethod::Splice, 1000);
        p.mark_fallback();
        assert!(p.fell_back);
        assert_eq!(p.method, TransferMethod::Traditional);
    }

    #[test]
    fn progress_avg_bytes_per_syscall() {
        let mut p = TransferProgress::new(1, TransferMethod::Sendfile, 0);
        p.advance(1024);
        p.advance(2048);
        assert!((p.avg_bytes_per_syscall() - 1536.0).abs() < 0.01);
    }

    #[test]
    fn progress_unknown_total() {
        let p = TransferProgress::new(1, TransferMethod::Splice, 0);
        assert_eq!(p.progress(), 0.0);
        assert!(!p.is_complete());
    }

    // ── Splice config ─────────────────────────────────────────────────

    #[test]
    fn splice_config_flags() {
        let cfg = SpliceConfig::default_config();
        let flags = cfg.splice_flags();
        assert_eq!(flags & 0x01, 0x01); // SPLICE_F_MOVE
        assert_eq!(flags & 0x02, 0x02); // SPLICE_F_NONBLOCK
        assert_eq!(flags & 0x04, 0);    // No SPLICE_F_MORE
    }

    #[test]
    fn splice_config_presets() {
        let d = SpliceConfig::default_config();
        let h = SpliceConfig::high_throughput();
        let l = SpliceConfig::low_latency();

        assert!(h.chunk_size > d.chunk_size);
        assert!(l.chunk_size < d.chunk_size);
        assert!(h.pipe_buffer_size > d.pipe_buffer_size);
    }

    // ── Sendfile config ───────────────────────────────────────────────

    #[test]
    fn sendfile_config_presets() {
        let d = SendfileConfig::default_config();
        let l = SendfileConfig::large_files();
        assert!(l.chunk_size > d.chunk_size);
        assert!(d.coalesce_headers);
        assert!(!l.coalesce_headers);
    }

    // ── Global toggle ─────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_zero_copy_enabled(true);
        assert!(is_zero_copy_enabled());
    }

    // ── Metrics (delta-based) ─────────────────────────────────────────

    #[test]
    fn metrics_record_transfer() {
        let m = zero_copy_metrics();
        let before_splice = m.splice_transfers.load(Ordering::Relaxed);
        let before_bytes = m.splice_bytes.load(Ordering::Relaxed);

        m.record_transfer(TransferMethod::Splice, 4096);

        let after_splice = m.splice_transfers.load(Ordering::Relaxed);
        let after_bytes = m.splice_bytes.load(Ordering::Relaxed);

        assert!(after_splice >= before_splice + 1);
        assert!(after_bytes >= before_bytes + 4096);
    }

    // ── Transfer descriptor ───────────────────────────────────────────

    #[test]
    fn descriptor_builder() {
        let d = TransferDescriptor::new(FdType::File, FdType::TcpSocket, 1000)
            .with_offset(500)
            .with_static_file();
        assert_eq!(d.src_offset, 500);
        assert!(d.is_static_file);
    }
}
