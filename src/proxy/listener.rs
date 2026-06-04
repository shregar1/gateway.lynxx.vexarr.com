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
//!
//! ## LocalSet discipline (Phase 2 audit)
//!
//! Each worker is built on a `current_thread` runtime + `LocalSet`,
//! so any `tokio::spawn(...)` reachable from the proxy hot path lands
//! on *this worker's* runtime — no inter-worker migration is even
//! possible because no multi_thread scheduler is in scope. Symbolized
//! `perf record` at 100 k RPS confirms: zero
//! `tokio::runtime::scheduler::multi_thread::worker::Stealer::steal`
//! frames on the `lynxx-proxy-*` threads (vs. the pre-Phase-1 capture
//! where `multi_thread::worker::run` dominated `lynxx-worker` stacks).
//!
//! The hot-path spawn audit (commit ref: the Phase 2 follow-up notes)
//! found that with `minimal_telemetry = true` and no plugins configured
//! — the spec bench setup — there are **zero per-request
//! `tokio::spawn` calls active**. The known spawn sites
//! (`handler.rs::proxy_via_unix`, the various `plugins/*.rs` exporters,
//! `loadbalancer.rs::drain_target`, `quota::spawn_quota_flusher`,
//! `auth::middleware::extract_token`) are either dormant in the bench
//! config or are explicitly long-lived background workers that should
//! continue to live on the shared multi-thread runtime built in
//! `main()`. They reach that runtime naturally because they are
//! spawned from `async_main` — which is what `main()`'s `rt.block_on`
//! drives — *not* from inside a per-worker accept loop.
//!
//! If a future PR adds a hot-path spawn (per-request fan-out, request
//! mirroring, etc.), switch it to `tokio::task::spawn_local` so the
//! discipline is enforced by the type system. The `LocalSet` is in
//! scope inside each worker's `block_on`, so `spawn_local` works there
//! without ceremony.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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
    // BUG FIX (lost-wakeup deadlock): `Notify::notify_waiters()` only wakes
    // waiters already registered when it fires and stores no permit for
    // future waiters. A worker still in its startup window (spawn / affinity
    // / runtime build / bind) has not yet created the `Notified` future inside
    // its `select!`, so a notify fired during that window is lost forever —
    // the worker then parks, `axum::serve` never exits, and `Guard::drop`'s
    // `h.join()` (or `rx.recv()`) hangs until SIGKILL. This sticky flag is set
    // (Release) *before* every `notify_waiters()` and checked by the worker
    // before it enters the select and again after binding, so cancellation can
    // never be missed regardless of timing.
    let cancelled = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<io::Result<()>>();
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(workers);

    for i in 0..workers {
        let cancel = cancel.clone();
        let cancelled = cancelled.clone();
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
                        // Sticky-cancel check #1: a shutdown/error may have
                        // fired `notify_waiters()` while this thread was still
                        // spawning/affinitizing/building its runtime — before
                        // any `Notified` future existed to catch it. Bail out
                        // now rather than bind a doomed listener.
                        if cancelled.load(Ordering::Acquire) {
                            tracing::debug!(worker = i, "proxy worker cancelled before bind");
                            return Ok(());
                        }
                        let listener = bind_reuseport(addr)?;
                        tracing::info!(
                            worker = i,
                            %addr,
                            "proxy worker bound (SO_REUSEPORT)"
                        );
                        let serve = axum::serve(listener, router);
                        // Create the `Notified` future BEFORE the final sticky
                        // check. `notified()` snapshots the notify_waiters
                        // generation at creation time, so once this future
                        // exists any later notify_waiters() is guaranteed to
                        // wake it. Checking `cancelled` *after* creating it
                        // therefore leaves no lost-wakeup window: either the
                        // flag is already set (we bail), or it is set strictly
                        // after this point — in which case the matching
                        // notify_waiters() will wake this very future.
                        let notified = cancel.notified();
                        if cancelled.load(Ordering::Acquire) {
                            tracing::debug!(worker = i, "proxy worker cancelled after bind");
                            return Ok(());
                        }
                        tokio::select! {
                            // `biased` so the cancellation arm is polled first.
                            biased;
                            _ = notified => {
                                tracing::debug!(worker = i, "proxy worker cancelled");
                                Ok(())
                            }
                            r = serve => r,
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
        cancelled: Arc<AtomicBool>,
        handles: Vec<std::thread::JoinHandle<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // Set the sticky flag BEFORE notifying so a worker that is still
            // in its startup window (and thus invisible to notify_waiters)
            // observes cancellation via the flag and exits instead of parking
            // forever. Without this ordering the join() below could block the
            // runtime thread until SIGKILL (lost-wakeup deadlock).
            self.cancelled.store(true, Ordering::Release);
            self.cancel.notify_waiters();
            for h in self.handles.drain(..) {
                let _ = h.join();
            }
        }
    }
    let guard = Guard {
        cancel: cancel.clone(),
        cancelled: cancelled.clone(),
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
                // Set the sticky flag before notifying for the same reason as
                // in Guard::drop: a sibling worker still binding would miss a
                // bare notify_waiters(), never drop its `tx`, and this very
                // `rx.recv()` loop would then never see `None` — hanging
                // serve_per_worker and swallowing the bind error.
                cancelled.store(true, Ordering::Release);
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

    /// Regression test for the lost-wakeup deadlock fixed in this file.
    ///
    /// This pins the exact cancellation handshake `serve_per_worker`'s
    /// workers perform: the canceller sets a sticky `AtomicBool` *before*
    /// `notify_waiters()`, and the worker creates its `Notified` future and
    /// then checks the flag before awaiting. The hazard being guarded is
    /// that `Notify::notify_waiters()` stores no permit — a `Notified`
    /// created after the notify fires is never woken.
    ///
    /// PART 1 demonstrates the raw hazard (a `Notified` created *after* the
    /// notify never resolves) so the test documents *why* the flag exists.
    /// PART 2 asserts the fix's ordering: even when cancellation fires while
    /// the worker is still "starting up" (before it would have parked), the
    /// worker observes it and exits promptly instead of hanging forever.
    #[test]
    fn cancellation_signal_is_not_lost_when_fired_before_worker_parks() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            use std::time::Duration;

            // PART 1: the bare-Notify hazard. A waiter that registers AFTER
            // notify_waiters() has fired is never woken. We assert it times
            // out — this is precisely the lost wakeup the old code suffered
            // when a worker reached its select! after the shutdown notify.
            let notify = Arc::new(tokio::sync::Notify::new());
            notify.notify_waiters(); // fires while no waiter is registered
            let late = notify.notified(); // created afterwards -> permit-less
            assert!(
                tokio::time::timeout(Duration::from_millis(150), late)
                    .await
                    .is_err(),
                "sanity: a Notified created after notify_waiters() must hang \
                 (this is the lost-wakeup hazard the sticky flag defends)"
            );

            // PART 2: the fixed handshake. The canceller sets `cancelled`
            // BEFORE notify_waiters(); the worker creates its Notified, then
            // checks the flag before awaiting. Cancellation here fires during
            // the worker's startup window (before it parks), reproducing the
            // deadlock trigger. With the fix the worker must NOT hang.
            let cancel = Arc::new(tokio::sync::Notify::new());
            let cancelled = Arc::new(AtomicBool::new(false));

            // Canceller fires "early" — before the worker below parks.
            cancelled.store(true, Ordering::Release);
            cancel.notify_waiters();

            // Worker mirrors serve_per_worker's parked select: build the
            // Notified first (snapshots the generation), then consult the
            // sticky flag, then select biased on cancellation.
            let worker = {
                let cancel = cancel.clone();
                let cancelled = cancelled.clone();
                async move {
                    let notified = cancel.notified();
                    if cancelled.load(Ordering::Acquire) {
                        return "exited-via-flag";
                    }
                    tokio::select! {
                        biased;
                        _ = notified => "exited-via-notify",
                        // Stand-in for axum::serve, which never self-resolves;
                        // on the buggy path the worker would be stuck here.
                        _ = std::future::pending::<()>() => "stuck-in-serve",
                    }
                }
            };

            let outcome = tokio::time::timeout(Duration::from_secs(5), worker)
                .await
                .expect("worker must observe cancellation and exit, not deadlock");
            assert_eq!(
                outcome, "exited-via-flag",
                "worker should bail via the sticky flag when cancelled before parking"
            );
        });
    }

    /// End-to-end exercise of the real `serve_per_worker` shutdown path
    /// (Path A): drive it on a multi-thread runtime, then cancel it by
    /// dropping the future (via `timeout`), which fires the internal
    /// `Guard::drop` -> `notify_waiters()` + `join()`. The cancellation is
    /// triggered with a zero/near-zero delay so workers are still in their
    /// startup window (OS-thread scheduling + runtime build + bind) when the
    /// notify fires — exactly the lost-wakeup trigger. On the fixed code the
    /// sticky flag guarantees those workers exit, so the join completes and
    /// the future resolves promptly; pre-fix, a worker that parked after the
    /// notify would wedge `join()` and this would never resolve.
    ///
    /// Runs on a multi_thread runtime so the blocking `join()` inside
    /// `Guard::drop` cannot starve the single worker that drives this future.
    #[test]
    fn serve_per_worker_returns_promptly_when_cancelled_during_startup() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use std::time::Duration;

            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            // Cancel almost immediately: the worker OS threads have been
            // spawned (synchronously, before the first await) but are
            // overwhelmingly still initializing, so the cancellation lands in
            // the vulnerable pre-park window.
            let fut = serve_per_worker(addr, axum::Router::new(), 8, Vec::new());
            let _ = tokio::time::timeout(Duration::from_millis(1), fut).await;
            // Reaching here means the future (and its Guard) was dropped and
            // every worker thread joined without deadlocking. A regression of
            // the lost wakeup would hang the join above and never get here.
        });
    }
}
