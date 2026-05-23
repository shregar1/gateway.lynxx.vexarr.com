//! Socket-level network optimizations for high-performance proxying.
//!
//! # Architecture
//!
//! ```text
//! Socket Optimizations
//! ├── SO_REUSEPORT      — Multiple workers accept connections independently
//! ├── TCP_NODELAY       — Disable Nagle for low-latency responses
//! ├── TCP_FASTOPEN      — Faster TCP handshake (save 1 RTT)
//! ├── TCP_KEEPALIVE     — Detect dead connections (idle, interval, count)
//! ├── SO_BUSY_POLL      — Kernel busy-polling for sub-ms latency (Linux)
//! ├── SO_RCVBUF/SNDBUF  — Tune socket buffer sizes
//! ├── SplicePipe        — Zero-copy socket→socket forwarding via pipe (Linux)
//! └── SocketConfig      — Unified configuration struct
//! ```
//!
//! # Why
//!
//! NGINX and HAProxy set these socket options on every listener and accepted
//! connection. The defaults in this module match NGINX's production tuning:
//!
//! - **SO_REUSEPORT**: Each worker thread gets its own accept queue —
//!   eliminates the thundering-herd accept() bottleneck.
//! - **TCP_NODELAY**: Disables Nagle's algorithm. Critical for proxies
//!   because Nagle + delayed ACK = 40ms latency spikes.
//! - **TCP_FASTOPEN**: Saves one RTT on new connections. The server can
//!   accept data in the SYN packet.
//! - **splice()**: Zero-copy forwarding between sockets via the kernel's
//!   pipe buffer. Avoids memcpy between kernel and userspace.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
use std::os::unix::io::RawFd;

// ═══════════════════════════════════════════════════════════════════════════
// Global defaults
// ═══════════════════════════════════════════════════════════════════════════

static TCP_NODELAY_DEFAULT: AtomicBool = AtomicBool::new(true);
static SO_REUSEPORT_DEFAULT: AtomicBool = AtomicBool::new(true);
static TCP_FASTOPEN_DEFAULT: AtomicBool = AtomicBool::new(true);

pub fn set_tcp_nodelay_default(v: bool) {
    TCP_NODELAY_DEFAULT.store(v, Ordering::Relaxed);
}
pub fn tcp_nodelay_default() -> bool {
    TCP_NODELAY_DEFAULT.load(Ordering::Relaxed)
}
pub fn set_so_reuseport_default(v: bool) {
    SO_REUSEPORT_DEFAULT.store(v, Ordering::Relaxed);
}
pub fn so_reuseport_default() -> bool {
    SO_REUSEPORT_DEFAULT.load(Ordering::Relaxed)
}
pub fn set_tcp_fastopen_default(v: bool) {
    TCP_FASTOPEN_DEFAULT.store(v, Ordering::Relaxed);
}
pub fn tcp_fastopen_default() -> bool {
    TCP_FASTOPEN_DEFAULT.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// SocketConfig — unified configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Unified socket configuration. Applied to listeners and accepted
/// connections via `apply_listener_opts()` / `apply_connection_opts()`.
#[derive(Clone, Debug)]
pub struct SocketConfig {
    // ── Listener options ──
    /// `SO_REUSEPORT`: each worker gets its own accept queue.
    pub reuse_port: bool,
    /// `TCP_FASTOPEN` queue length. 0 = disabled. Default: 256.
    pub tcp_fastopen_queue: u32,

    // ── Connection options ──
    /// `TCP_NODELAY`: disable Nagle. Default: true.
    pub tcp_nodelay: bool,
    /// TCP keepalive idle time in seconds. 0 = disabled. Default: 60.
    pub keepalive_idle_secs: u32,
    /// Interval between keepalive probes. Default: 10.
    pub keepalive_interval_secs: u32,
    /// Number of keepalive probes before declaring dead. Default: 3.
    pub keepalive_count: u32,
    /// `SO_BUSY_POLL` in microseconds (Linux, requires CAP_NET_ADMIN).
    /// 0 = disabled. Default: 0.
    pub busy_poll_us: u32,
    /// `SO_RCVBUF` size in bytes. 0 = OS default.
    pub recv_buf_size: u32,
    /// `SO_SNDBUF` size in bytes. 0 = OS default.
    pub send_buf_size: u32,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            reuse_port: true,
            tcp_fastopen_queue: 256,
            tcp_nodelay: true,
            keepalive_idle_secs: 60,
            keepalive_interval_secs: 10,
            keepalive_count: 3,
            busy_poll_us: 0,
            recv_buf_size: 0,
            send_buf_size: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Low-level socket option helpers (Unix)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(unix)]
fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: libc::c_int,
) -> std::io::Result<()> {
    unsafe {
        let rc = libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn getsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
) -> std::io::Result<libc::c_int> {
    unsafe {
        let mut val: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            level,
            name,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(val)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Individual socket option setters
// ═══════════════════════════════════════════════════════════════════════════

/// Set `SO_REUSEPORT` — allow multiple sockets to bind to the same
/// address:port. The kernel distributes incoming connections across
/// all bound sockets, eliminating the accept() thundering herd.
#[cfg(unix)]
pub fn set_reuse_port(fd: RawFd, enable: bool) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, enable as i32)
}

/// Set `TCP_NODELAY` — disable Nagle's algorithm. Without this, the
/// kernel may delay small writes (like HTTP headers) waiting for more
/// data, causing 40ms latency spikes when combined with delayed ACKs.
#[cfg(unix)]
pub fn set_tcp_nodelay(fd: RawFd, enable: bool) -> std::io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, enable as i32)
}

/// Set `TCP_FASTOPEN` on a **listener** socket (Linux). Allows the
/// server to accept data in the SYN packet, saving one RTT for
/// repeat clients. `queue_len` is the max pending TFO connections.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen(fd: RawFd, queue_len: u32) -> std::io::Result<()> {
    setsockopt_int(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_FASTOPEN,
        queue_len as i32,
    )
}

/// macOS: TCP_FASTOPEN is not well-supported on the server side.
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_fastopen(_fd: RawFd, _queue_len: u32) -> std::io::Result<()> {
    Ok(())
}

/// Configure TCP keepalive with custom idle time, probe interval,
/// and probe count. Detects dead connections without application-level
/// heartbeats.
#[cfg(target_os = "linux")]
pub fn set_keepalive(
    fd: RawFd,
    idle_secs: u32,
    interval_secs: u32,
    count: u32,
) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle_secs as i32)?;
    setsockopt_int(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        interval_secs as i32,
    )?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, count as i32)
}

/// macOS: uses `TCP_KEEPALIVE` instead of `TCP_KEEPIDLE`.
#[cfg(target_os = "macos")]
pub fn set_keepalive(
    fd: RawFd,
    idle_secs: u32,
    interval_secs: u32,
    count: u32,
) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    setsockopt_int(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPALIVE,
        idle_secs as i32,
    )?;
    setsockopt_int(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        interval_secs as i32,
    )?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, count as i32)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn set_keepalive(
    _fd: RawFd,
    _idle_secs: u32,
    _interval_secs: u32,
    _count: u32,
) -> std::io::Result<()> {
    Ok(())
}

/// Set `SO_BUSY_POLL` — kernel busy-polling on the socket's receive
/// queue. Reduces latency by avoiding the interrupt→wakeup path at the
/// cost of CPU. Requires `CAP_NET_ADMIN` or `sysctl net.core.busy_poll`.
#[cfg(target_os = "linux")]
pub fn set_busy_poll(fd: RawFd, us: u32) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL, us as i32)
}

#[cfg(not(target_os = "linux"))]
pub fn set_busy_poll(_fd: RawFd, _us: u32) -> std::io::Result<()> {
    Ok(())
}

/// Set `SO_RCVBUF` — receive buffer size.
#[cfg(unix)]
pub fn set_recv_buffer(fd: RawFd, size: u32) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size as i32)
}

/// Set `SO_SNDBUF` — send buffer size.
#[cfg(unix)]
pub fn set_send_buffer(fd: RawFd, size: u32) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, size as i32)
}

/// Read current `SO_RCVBUF` value.
#[cfg(unix)]
pub fn get_recv_buffer(fd: RawFd) -> std::io::Result<u32> {
    getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).map(|v| v as u32)
}

/// Read current `SO_SNDBUF` value.
#[cfg(unix)]
pub fn get_send_buffer(fd: RawFd) -> std::io::Result<u32> {
    getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF).map(|v| v as u32)
}

/// Set `SO_ZEROCOPY` — enable MSG_ZEROCOPY for `send()`. The kernel
/// avoids copying data to the socket buffer, instead pinning userspace
/// pages. Requires completion notification via `MSG_ERRQUEUE`.
#[cfg(target_os = "linux")]
pub fn set_zerocopy(fd: RawFd, enable: bool) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_ZEROCOPY, enable as i32)
}

#[cfg(not(target_os = "linux"))]
pub fn set_zerocopy(_fd: RawFd, _enable: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_ZEROCOPY not available on this platform",
    ))
}

// ═══════════════════════════════════════════════════════════════════════════
// Bulk apply — listener and connection
// ═══════════════════════════════════════════════════════════════════════════

/// Apply listener-specific socket options. Call before `bind()`.
#[cfg(unix)]
pub fn apply_listener_opts(fd: RawFd, config: &SocketConfig) -> std::io::Result<()> {
    if config.reuse_port {
        set_reuse_port(fd, true)?;
    }
    if config.tcp_fastopen_queue > 0 {
        // TCP_FASTOPEN failure is non-fatal (kernel may not support it).
        let _ = set_tcp_fastopen(fd, config.tcp_fastopen_queue);
    }
    Ok(())
}

/// Apply connection-specific socket options. Call on accepted sockets
/// and outbound upstream connections.
#[cfg(unix)]
pub fn apply_connection_opts(fd: RawFd, config: &SocketConfig) -> std::io::Result<()> {
    set_tcp_nodelay(fd, config.tcp_nodelay)?;

    if config.keepalive_idle_secs > 0 {
        set_keepalive(
            fd,
            config.keepalive_idle_secs,
            config.keepalive_interval_secs,
            config.keepalive_count,
        )?;
    }

    if config.busy_poll_us > 0 {
        // Non-fatal: requires CAP_NET_ADMIN.
        let _ = set_busy_poll(fd, config.busy_poll_us);
    }

    if config.recv_buf_size > 0 {
        set_recv_buffer(fd, config.recv_buf_size)?;
    }

    if config.send_buf_size > 0 {
        set_send_buffer(fd, config.send_buf_size)?;
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// splice() — zero-copy socket→socket forwarding (Linux)
// ═══════════════════════════════════════════════════════════════════════════

/// Zero-copy `splice(2)` wrapper. Moves data between a file descriptor
/// and a pipe without copying through userspace.
///
/// **Linux only.** Combined with a pipe pair, enables zero-copy
/// socket→socket proxying:
///
/// ```text
/// client_fd ──splice──▶ pipe[write_end]
///                       pipe[read_end] ──splice──▶ upstream_fd
/// ```
#[cfg(target_os = "linux")]
pub fn splice(
    fd_in: RawFd,
    fd_out: RawFd,
    len: usize,
    flags: libc::c_uint,
) -> std::io::Result<usize> {
    let n = unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            flags,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// RAII pipe pair for zero-copy splice forwarding. Creates a non-blocking
/// pipe and provides a `forward()` method for socket→socket transfer.
#[cfg(target_os = "linux")]
pub struct SplicePipe {
    read_end: RawFd,
    write_end: RawFd,
}

#[cfg(target_os = "linux")]
impl SplicePipe {
    /// Create a new non-blocking pipe pair.
    pub fn new() -> std::io::Result<Self> {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            read_end: fds[0],
            write_end: fds[1],
        })
    }

    /// Zero-copy forward up to `len` bytes from `source` to `dest`.
    /// Returns the number of bytes actually forwarded.
    ///
    /// The data flows: `source → pipe → dest` with zero userspace copies.
    pub fn forward(
        &self,
        source: RawFd,
        dest: RawFd,
        len: usize,
    ) -> std::io::Result<usize> {
        let flags = (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;

        // source → pipe write end.
        let n = splice(source, self.write_end, len, flags)?;
        if n == 0 {
            return Ok(0);
        }

        // pipe read end → dest.
        let mut remaining = n;
        let mut total = 0;
        while remaining > 0 {
            match splice(self.read_end, dest, remaining, flags) {
                Ok(0) => break,
                Ok(written) => {
                    remaining -= written;
                    total += written;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(total)
    }

    pub fn read_fd(&self) -> RawFd {
        self.read_end
    }

    pub fn write_fd(&self) -> RawFd {
        self.write_end
    }
}

#[cfg(target_os = "linux")]
impl Drop for SplicePipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_end);
            libc::close(self.write_end);
        }
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct SplicePipe;

#[cfg(not(target_os = "linux"))]
impl SplicePipe {
    pub fn new() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "splice not available on this platform",
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn create_test_socket() -> RawFd {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(fd >= 0, "failed to create test socket");
            fd
        }
    }

    #[cfg(unix)]
    fn close_fd(fd: RawFd) {
        unsafe {
            libc::close(fd);
        }
    }

    // ── Config ──

    #[test]
    fn default_config() {
        let config = SocketConfig::default();
        assert!(config.reuse_port);
        assert!(config.tcp_nodelay);
        assert_eq!(config.tcp_fastopen_queue, 256);
        assert_eq!(config.keepalive_idle_secs, 60);
        assert_eq!(config.busy_poll_us, 0);
    }

    // ── Individual options ──

    #[cfg(unix)]
    #[test]
    fn tcp_nodelay_toggle() {
        let fd = create_test_socket();
        assert!(set_tcp_nodelay(fd, true).is_ok());
        assert!(set_tcp_nodelay(fd, false).is_ok());
        close_fd(fd);
    }

    #[cfg(unix)]
    #[test]
    fn reuse_port_toggle() {
        let fd = create_test_socket();
        assert!(set_reuse_port(fd, true).is_ok());
        assert!(set_reuse_port(fd, false).is_ok());
        close_fd(fd);
    }

    #[cfg(unix)]
    #[test]
    fn keepalive_set() {
        let fd = create_test_socket();
        assert!(set_keepalive(fd, 30, 5, 3).is_ok());
        close_fd(fd);
    }

    #[cfg(unix)]
    #[test]
    fn buffer_sizes() {
        let fd = create_test_socket();

        // Set and read back. The kernel may double the value (for
        // bookkeeping overhead), so we just verify no error.
        assert!(set_recv_buffer(fd, 65536).is_ok());
        assert!(set_send_buffer(fd, 65536).is_ok());

        let rcv = get_recv_buffer(fd).unwrap();
        let snd = get_send_buffer(fd).unwrap();
        assert!(rcv >= 65536, "rcv buf too small: {rcv}");
        assert!(snd >= 65536, "snd buf too small: {snd}");

        close_fd(fd);
    }

    #[cfg(unix)]
    #[test]
    fn bad_fd_returns_error() {
        assert!(set_tcp_nodelay(-1, true).is_err());
        assert!(set_reuse_port(-1, true).is_err());
    }

    // ── Bulk apply ──

    #[cfg(unix)]
    #[test]
    fn apply_listener_opts_smoke() {
        let fd = create_test_socket();
        let config = SocketConfig::default();
        assert!(apply_listener_opts(fd, &config).is_ok());
        close_fd(fd);
    }

    #[cfg(unix)]
    #[test]
    fn apply_connection_opts_smoke() {
        let fd = create_test_socket();
        let config = SocketConfig::default();
        assert!(apply_connection_opts(fd, &config).is_ok());
        close_fd(fd);
    }

    // ── SplicePipe (Linux only) ──

    #[cfg(target_os = "linux")]
    #[test]
    fn splice_pipe_create() {
        let pipe = SplicePipe::new().unwrap();
        assert!(pipe.read_fd() >= 0);
        assert!(pipe.write_fd() >= 0);
        assert_ne!(pipe.read_fd(), pipe.write_fd());
        // pipe is closed on drop.
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn splice_pipe_unsupported() {
        assert!(SplicePipe::new().is_err());
    }

    // ── Global toggles ──

    #[test]
    fn global_defaults_toggle() {
        set_tcp_nodelay_default(false);
        assert!(!tcp_nodelay_default());
        set_tcp_nodelay_default(true);
        assert!(tcp_nodelay_default());

        set_so_reuseport_default(false);
        assert!(!so_reuseport_default());
        set_so_reuseport_default(true);
        assert!(so_reuseport_default());

        set_tcp_fastopen_default(false);
        assert!(!tcp_fastopen_default());
        set_tcp_fastopen_default(true);
        assert!(tcp_fastopen_default());
    }

    // ── SocketConfig clone / debug ──

    #[test]
    fn socket_config_clone_and_debug() {
        let config = SocketConfig {
            reuse_port: false,
            tcp_fastopen_queue: 128,
            tcp_nodelay: false,
            keepalive_idle_secs: 30,
            keepalive_interval_secs: 5,
            keepalive_count: 2,
            busy_poll_us: 50,
            recv_buf_size: 8192,
            send_buf_size: 16384,
        };
        let cloned = config.clone();
        assert_eq!(cloned.reuse_port, false);
        assert_eq!(cloned.tcp_fastopen_queue, 128);
        assert_eq!(cloned.tcp_nodelay, false);
        assert_eq!(cloned.keepalive_idle_secs, 30);
        assert_eq!(cloned.keepalive_interval_secs, 5);
        assert_eq!(cloned.keepalive_count, 2);
        assert_eq!(cloned.busy_poll_us, 50);
        assert_eq!(cloned.recv_buf_size, 8192);
        assert_eq!(cloned.send_buf_size, 16384);

        // Debug should produce non-empty output.
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("SocketConfig"));
        assert!(dbg.contains("128"));
    }

    // ── set_tcp_fastopen on a real socket ──

    #[cfg(unix)]
    #[test]
    fn tcp_fastopen_on_socket() {
        let fd = create_test_socket();
        // On macOS this is a no-op, on Linux it sets the option.
        // Either way it should not return an error.
        let result = set_tcp_fastopen(fd, 256);
        assert!(result.is_ok());
        close_fd(fd);
    }

    // ── set_busy_poll on a real socket ──

    #[cfg(unix)]
    #[test]
    fn busy_poll_on_socket() {
        let fd = create_test_socket();
        // On non-Linux this is a no-op. On Linux it may fail without
        // CAP_NET_ADMIN but the no-op stub should succeed.
        let result = set_busy_poll(fd, 100);
        assert!(result.is_ok());
        close_fd(fd);
    }

    // ── set_zerocopy returns Unsupported on macOS ──

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn zerocopy_unsupported_on_non_linux() {
        let fd = create_test_socket();
        let result = set_zerocopy(fd, true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        close_fd(fd);
    }

    // ── get_recv_buffer / get_send_buffer read defaults ──

    #[cfg(unix)]
    #[test]
    fn get_buffer_defaults() {
        let fd = create_test_socket();
        // A fresh socket should have non-zero default buffer sizes.
        let rcv = get_recv_buffer(fd).unwrap();
        let snd = get_send_buffer(fd).unwrap();
        assert!(rcv > 0, "default recv buffer should be > 0, got {rcv}");
        assert!(snd > 0, "default send buffer should be > 0, got {snd}");
        close_fd(fd);
    }

    // ── apply_listener_opts with tcp_fastopen_queue=0 (disabled) ──

    #[cfg(unix)]
    #[test]
    fn apply_listener_opts_fastopen_disabled() {
        let fd = create_test_socket();
        let config = SocketConfig {
            tcp_fastopen_queue: 0, // Disabled.
            ..Default::default()
        };
        assert!(apply_listener_opts(fd, &config).is_ok());
        close_fd(fd);
    }

    // ── apply_connection_opts with all options disabled (zeros) ──

    #[cfg(unix)]
    #[test]
    fn apply_connection_opts_all_disabled() {
        let fd = create_test_socket();
        let config = SocketConfig {
            tcp_nodelay: false,
            keepalive_idle_secs: 0,
            keepalive_interval_secs: 0,
            keepalive_count: 0,
            busy_poll_us: 0,
            recv_buf_size: 0,
            send_buf_size: 0,
            ..Default::default()
        };
        // With everything disabled/zeroed, no socket options should be
        // applied beyond tcp_nodelay=false.
        assert!(apply_connection_opts(fd, &config).is_ok());
        close_fd(fd);
    }

    // ── apply_connection_opts with busy_poll > 0 ──

    #[cfg(unix)]
    #[test]
    fn apply_connection_opts_busy_poll_nonzero() {
        let fd = create_test_socket();
        let config = SocketConfig {
            busy_poll_us: 50,
            ..Default::default()
        };
        // busy_poll is non-fatal (ignored on non-Linux or without CAP_NET_ADMIN).
        assert!(apply_connection_opts(fd, &config).is_ok());
        close_fd(fd);
    }

    // ── SplicePipe stub on macOS returns Unsupported ──

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn splice_pipe_stub_unsupported() {
        let result = SplicePipe::new();
        assert!(result.is_err());
        match result {
            Err(err) => {
                assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
                assert!(err.to_string().contains("splice"));
            }
            Ok(_) => panic!("expected Err"),
        }
    }
}
