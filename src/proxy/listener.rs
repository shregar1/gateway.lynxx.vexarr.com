//! Per-worker SO_REUSEPORT listeners + thread-per-core runtime fanout.
//!
//! On Linux 3.9+, the proxy hot path binds N independent listening
//! sockets to the same port via `SO_REUSEPORT`. The kernel's
//! socket-hash distributes incoming SYN packets across the sockets,
//! and each socket lives on a dedicated OS thread running its own
//! `current_thread` tokio runtime + `LocalSet`. A connection enters
//! one thread on `accept()` and stays there for its whole lifetime —
//! no work-stealing migration, no cross-worker cache-line traffic.
//!
//! On non-Linux platforms this module is not compiled in; main.rs
//! falls back to the single-listener path so contributors on macOS /
//! Windows can still `cargo run`.
//!
//! Why not just bump tokio worker count? Tokio's multi-thread runtime
//! load-balances tasks via work-stealing, which migrates connection
//! state (sockets, buffers) across cores under load. Each migration
//! is a full L1 cache reload for the relevant cache lines, plus
//! coherence traffic. The per-worker model trades a small loss in
//! best-case balance for a large gain in cache locality and tail
//! latency predictability — which is exactly what we need to close
//! the gap from p99=15 ms (queue-bound at 76k RPS) to p99<4 ms.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// TCP listen backlog. The kernel caps this at
/// `/proc/sys/net/core/somaxconn` (8192 on the bench rig, often 4096
/// on stock distros). We ask for 16384 so we get whatever the operator
/// has tuned up to that ceiling; the kernel silently floors the value.
const LISTEN_BACKLOG: i32 = 16384;

/// Bind a fresh SO_REUSEPORT-enabled TCP listener to `addr`. Caller
/// must invoke this from inside the tokio runtime that will drive its
/// accept loop — `TcpListener::from_std` registers the socket with
/// the *currently running* runtime's IO driver.
///
/// Socket options applied, in order, BEFORE `bind`:
///
/// * `SO_REUSEADDR` — rebind allowed after close (no TIME_WAIT churn).
/// * `SO_REUSEPORT` — kernel distributes new connections across the
///   set of sockets bound to the same `(addr, port)` via a 4-tuple
///   hash. The whole point of this module.
/// * `IP_FREEBIND` (Linux) — bind to non-local addresses; useful in
///   container startup where the IP isn't yet attached to an
///   interface. Best-effort; failure is logged at debug.
/// * `TCP_NODELAY` — applied to the listening socket (children
///   inherit it where the kernel supports inheritance; otherwise
///   the accept loop's per-conn opt sets it again).
/// * non-blocking — required for tokio integration.
///
/// Then `bind` + `listen(LISTEN_BACKLOG)`.
pub fn bind_reuseport(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    // Nagle off on the listening socket; the accept handler re-applies
    // it per-connection in the proxy hot path. Setting it here is a
    // belt-and-suspenders for kernels that inherit the option.
    let _ = socket.set_nodelay(true);
    socket.set_nonblocking(true)?;
    set_ip_freebind(&socket);
    socket.bind(&addr.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    TcpListener::from_std(socket.into())
}

#[cfg(target_os = "linux")]
fn set_ip_freebind(socket: &Socket) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_FREEBIND,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            error = %io::Error::last_os_error(),
            "IP_FREEBIND setsockopt failed (kernel < 2.4 / unprivileged); continuing"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_ip_freebind(_socket: &Socket) {
    // IP_FREEBIND is Linux-only. No-op elsewhere.
}

/// Spawn `workers` OS threads, each running its own `current_thread`
/// tokio runtime + `LocalSet` serving a private SO_REUSEPORT listener
/// bound to `addr`. The returned future resolves when:
///
/// * any worker's `axum::serve` exits with `Err` — that error is
///   propagated as the future's `Err`; the other workers are signaled
///   to stop, joined, and their results dropped.
/// * the future is cancelled (dropped by the outer `tokio::select!`) —
///   the `Drop` impl on the internal guard notifies all workers and
///   joins them synchronously before returning. The accept loops exit
///   within microseconds because they're parked in `tokio::select!`
///   on the cancellation `Notify`.
///
/// `core_ids`, when non-empty, pins worker N to `core_ids[N % len()]`
/// via `core_affinity::set_for_current` before any tokio code runs on
/// that thread. Pin failures are logged at debug — typical causes are
/// container cpuset restrictions or platforms whose `set_for_current`
/// is a stub.
///
/// Linux-only. The cfg gate is at the module level via main.rs.
pub async fn serve_per_worker(
    addr: SocketAddr,
    router: axum::Router,
    workers: usize,
    core_ids: Vec<core_affinity::CoreId>,
) -> io::Result<()> {
    use std::thread;

    let workers = workers.max(1);
    let cancel = Arc::new(tokio::sync::Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<io::Result<()>>();
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(workers);

    for i in 0..workers {
        let cancel = cancel.clone();
        let tx = tx.clone();
        let router = router.clone();
        let core = if !core_ids.is_empty() {
            Some(core_ids[i % core_ids.len()])
        } else {
            None
        };
        let h = thread::Builder::new()
            .name(format!("lynxx-proxy-{i}"))
            .spawn(move || {
                if let Some(c) = core {
                    if !core_affinity::set_for_current(c) {
                        tracing::debug!(
                            worker = i,
                            "core_affinity::set_for_current returned false; worker will float"
                        );
                    }
                }
                let result: io::Result<()> = (|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .thread_name(format!("lynxx-proxy-{i}"))
                        .build()?;
                    let local = tokio::task::LocalSet::new();
                    local.block_on(&rt, async move {
                        let listener = bind_reuseport(addr)?;
                        tracing::info!(
                            worker = i,
                            %addr,
                            "proxy worker bound (SO_REUSEPORT)"
                        );
                        let serve = axum::serve(listener, router);
                        tokio::select! {
                            r = serve => r,
                            _ = cancel.notified() => {
                                tracing::debug!(worker = i, "proxy worker cancelled");
                                Ok(())
                            }
                        }
                    })
                })();
                let _ = tx.send(result);
            })
            .map_err(io::Error::from)?;
        handles.push(h);
    }
    // Drop our copy of `tx` so `rx.recv()` eventually returns `None`
    // once every worker has reported in. Without this drop the recv
    // would hang forever even after all workers exit.
    drop(tx);

    // Drop-guard: if the outer future is cancelled (e.g., shutdown
    // signal), Drop fires here and notifies the workers + joins their
    // OS threads. Joining is synchronous but very fast: each worker
    // is parked in `tokio::select!` on `cancel.notified()` and wakes
    // immediately.
    struct Guard {
        cancel: Arc<tokio::sync::Notify>,
        handles: Vec<std::thread::JoinHandle<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            self.cancel.notify_waiters();
            for h in self.handles.drain(..) {
                let _ = h.join();
            }
        }
    }
    let guard = Guard {
        cancel: cancel.clone(),
        handles,
    };

    // Drain worker results. Record the first error, then signal the
    // others to stop and keep draining so every worker reports in
    // before we return. This ordering matters because some kernels
    // (e.g. those with `net.core.somaxconn` set very low) can have
    // a flaky worker that fails repeatedly while others run fine —
    // we want the failure surfaced, not masked by the healthy peers.
    let mut first_err: Option<io::Error> = None;
    while let Some(r) = rx.recv().await {
        if let Err(e) = r {
            if first_err.is_none() {
                first_err = Some(e);
                cancel.notify_waiters();
            }
        }
    }
    drop(guard);
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_reuseport_returns_listener_on_ephemeral_port() {
        // We need a tokio runtime in scope because TcpListener::from_std
        // registers with the current reactor.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = bind_reuseport(addr).expect("bind");
            let local = listener.local_addr().expect("local_addr");
            assert!(local.port() > 0, "port should be assigned");
        });
    }

    #[test]
    fn bind_reuseport_allows_two_listeners_same_port() {
        // The whole point of SO_REUSEPORT: two binds to the same port
        // both succeed. We bind one to get a kernel-assigned port,
        // then rebind a second listener to that same port — this fails
        // without SO_REUSEPORT and succeeds with it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let first = bind_reuseport("127.0.0.1:0".parse().unwrap()).expect("first bind");
            let port = first.local_addr().unwrap().port();
            let second_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let second = bind_reuseport(second_addr).expect("second bind");
            assert_eq!(second.local_addr().unwrap().port(), port);
        });
    }
}
