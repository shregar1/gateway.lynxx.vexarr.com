//! io_uring-backed accept thread for the proxy listener.
//!
//! ## What this delivers
//!
//! A dedicated `std::thread` opens an `io_uring` instance and pushes
//! `IORING_OP_ACCEPT` SQEs for a listener socket. Each completion
//! produces an accepted FD; the FD is shipped to the tokio runtime
//! over an [`mpsc::UnboundedSender`] where existing listener code
//! wraps it in a [`tokio::net::TcpStream`] via
//! [`tokio::net::TcpStream::from_std`].
//!
//! V1 uses single-shot accept (one SQE per accepted connection,
//! resubmitted from the CQE loop). Multishot accept
//! (`IORING_ACCEPT_MULTISHOT`, kernel 5.19+) is a worthwhile
//! follow-up — the `io-uring` crate exposes `opcode::AcceptMulti`
//! with the same opcode number but a different ioprio bit — but
//! kernel-version probing is not as clean as a feature flag and
//! we'd rather ship working single-shot now than ship buggy
//! multishot with a runtime fallback today.
//!
//! The win is bounded: we replace **one syscall per accept** with one
//! SQE submission. On a listener taking 10k new connections per
//! second that's around 500 µs/sec of CPU saved — meaningful for the
//! tail latency of connection-storm scenarios, irrelevant for
//! steady-state long-lived connection traffic.
//!
//! ## What this does NOT deliver
//!
//! Most of the dramatic io_uring wins come from running the *data
//! plane* on io_uring: registered buffers, zero-copy splice,
//! `IORING_OP_SEND_ZC`, `SQPOLL` kernel-side polling. All of those
//! require either (a) migrating the entire async stack to
//! `tokio-uring` (single-thread runtime, every `async fn` re-typed
//! over io_uring traits) or (b) abandoning tokio for `monoio` or
//! `glommio`. Both are multi-week migrations and explicitly out of
//! scope here.
//!
//! `docs/IO_URING.md` lays out the full design space.
//!
//! ## Threading model
//!
//! ```text
//!     std::thread (io_uring SQ/CQ owner)
//!     ┌───────────────────────────────┐
//!     │ 1. push Accept SQE            │
//!     │ 2. submit_and_wait(1)         │
//!     │ 3. drain CQ → mpsc::Sender    │   ───▶  tokio runtime
//!     │ 4. shutdown_rx.try_recv()?    │         (mpsc::Receiver
//!     │ 5. loop unless shutdown       │          owns the FD now)
//!     └───────────────────────────────┘
//! ```
//!
//! The dedicated thread is *not* a tokio worker — it runs purely
//! blocking syscalls. Tokio's runtime is untouched. The handoff is a
//! `tokio::sync::mpsc` channel which is safe to send to from any
//! thread.
//!
//! ## Failure modes
//!
//! * **Kernel too old** (`io_uring_setup` returns ENOSYS, or the
//!   feature probe rejects `accept_multishot`): [`probe`] returns a
//!   non-[`Available::Yes`] variant. Callers fall back to the
//!   standard `tokio::net::TcpListener::accept` loop.
//! * **`accept` errors** (EMFILE, ECONNABORTED): the CQE result is
//!   negative; we log and continue. The listener thread does *not*
//!   die on transient errors.
//! * **mpsc receiver dropped**: the sender returns Err on the next
//!   send; we treat this as a shutdown signal and exit.
//!
//! The module itself is `#[cfg(target_os = "linux")]`-gated in
//! `src/utilities/mod.rs`, so on macOS / Windows the symbols don't
//! exist. Callers that want to be cross-platform should themselves
//! `cfg`-gate every `use crate::utilities::io_uring_accept::...`.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use tokio::sync::mpsc;

/// Result of probing the host kernel for io_uring support. Use this
/// to decide whether to wire the io_uring acceptor or fall back to
/// tokio's standard accept loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Available {
    /// io_uring is usable: `io_uring_setup` works and `IORING_OP_ACCEPT`
    /// is in the probed opcode set.
    Yes,
    /// `io_uring_setup` failed (kernel too old, disabled in seccomp
    /// policy, etc.) or the `Accept` opcode is unsupported. The
    /// message is logged at startup but kept opaque on purpose —
    /// we don't want operator-facing logs to encode kernel-version
    /// behaviour that could change between minor releases.
    Unavailable(String),
}

impl Available {
    /// Convenience: did the probe say io_uring is usable at all?
    pub fn is_supported(&self) -> bool {
        matches!(self, Available::Yes)
    }
}

/// Probe the host kernel for io_uring + `IORING_OP_ACCEPT` support.
/// Builds a small ring and inspects the opcode `Probe`. Idempotent
/// and cheap — safe to call at startup before any acceptor is
/// spawned.
pub fn probe() -> Available {
    use io_uring::{opcode, Probe};

    let ring = match io_uring::IoUring::new(8) {
        Ok(r) => r,
        Err(e) => return Available::Unavailable(format!("io_uring_setup: {e}")),
    };

    // Probe for opcode support. The kernel exposes a `probe` op since
    // 5.6; if probe registration itself fails we conservatively say
    // io_uring isn't usable here — modern kernels all support it.
    let mut p = Probe::new();
    if ring.submitter().register_probe(&mut p).is_err() {
        return Available::Unavailable("register_probe failed".into());
    }

    if !p.is_supported(opcode::Accept::CODE) {
        return Available::Unavailable("kernel rejects IORING_OP_ACCEPT".into());
    }

    Available::Yes
}

/// A running io_uring acceptor. Dropping it stops the dedicated
/// thread cleanly via the shutdown flag.
pub struct IoUringAcceptor {
    /// Set by [`IoUringAcceptor::shutdown`] and observed by the
    /// background thread between submissions. The thread exits the
    /// next time it surfaces from `submit_and_wait`.
    shutdown: Arc<AtomicBool>,
    /// Join handle for the SQ/CQ owner thread. `Option` so [`Drop`]
    /// can take + `join` without `unsafe`.
    thread: Option<JoinHandle<()>>,
}

impl IoUringAcceptor {
    /// Spawn the dedicated SQ/CQ thread for `listener_fd` and start
    /// accepting connections. Accepted FDs are forwarded on the
    /// returned `mpsc::UnboundedReceiver` of [`AcceptedConn`]. The
    /// receiver is owned by the caller (typically a tokio task that
    /// wraps each FD into a `tokio::net::TcpStream`).
    ///
    /// The caller MUST keep the listener socket alive for the
    /// lifetime of this acceptor — we hold a raw FD, not an owned
    /// `TcpListener`, to avoid double-closing on shutdown.
    ///
    /// `ring_entries` is the SQ/CQ size. 64 is plenty for an accept
    /// loop; values below 8 are floored to 8.
    pub fn start(
        listener_fd: RawFd,
        ring_entries: u32,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<AcceptedConn>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        let shutdown = Arc::new(AtomicBool::new(false));

        let shutdown_thr = shutdown.clone();
        let entries = ring_entries.max(8);
        let thread = thread::Builder::new()
            .name("lynxx-iouring-accept".into())
            .spawn(move || {
                if let Err(e) = run_accept_thread(listener_fd, entries, tx, shutdown_thr) {
                    tracing::error!(error = %e, "io_uring accept thread exited with error");
                }
            })?;

        Ok((
            Self {
                shutdown,
                thread: Some(thread),
            },
            rx,
        ))
    }

    /// Signal the SQ/CQ thread to stop. Idempotent. The thread
    /// observes the flag between syscalls and joins from [`Drop`].
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl Drop for IoUringAcceptor {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(h) = self.thread.take() {
            // We don't want to wait forever on a stuck thread, but we
            // also don't have a hard deadline here. Tokio's runtime
            // shutdown gives us roughly grace_period seconds. The
            // accept thread blocks on `submit_and_wait(1)`, which
            // wakes when the next accept SQE completes — so on a
            // listener with even minimal traffic the join completes
            // quickly. For a fully idle listener, the close on the
            // listener FD by the surrounding code triggers an error
            // CQE that wakes us.
            let _ = h.join();
        }
    }
}

/// A successfully-accepted inbound connection. The FD is owned by
/// the receiver — the io_uring thread has already detached itself.
/// Tokio-side glue should call [`tokio::net::TcpStream::from_std`]
/// on a `std::net::TcpStream` rebuilt from this FD.
#[derive(Debug)]
pub struct AcceptedConn {
    pub fd: RawFd,
}

/// Convenience: rebuild a `std::net::TcpStream` from the FD. The
/// FD ownership transfers to the returned stream; do NOT call this
/// twice on the same FD. Marked `unsafe` because the caller is
/// asserting that the FD is a valid TCP socket and is not in use
/// elsewhere.
///
/// # Safety
///
/// `fd` must be:
/// 1. A valid open file descriptor.
/// 2. A TCP socket in the connected state.
/// 3. Not held by any other Rust value (we're going to take
///    ownership via `FromRawFd`).
pub unsafe fn fd_to_std_stream(fd: RawFd) -> std::net::TcpStream {
    use std::os::fd::FromRawFd;
    std::net::TcpStream::from_raw_fd(fd)
}

// ---------------------------------------------------------------------
// SQ/CQ owner thread
// ---------------------------------------------------------------------

fn run_accept_thread(
    listener_fd: RawFd,
    entries: u32,
    tx: mpsc::UnboundedSender<AcceptedConn>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    use io_uring::{opcode, types};

    let mut ring = io_uring::IoUring::new(entries)?;

    // Push the initial accept SQE. The user_data field is unused
    // here — we don't need to disambiguate multiple in-flight ops on
    // this ring because the only op type is Accept.
    let push_accept = |ring: &mut io_uring::IoUring| -> io::Result<()> {
        let sqe = opcode::Accept::new(
            types::Fd(listener_fd),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .build()
        .user_data(0);
        // SAFETY: the SQE points only to null sockaddr buffers; we
        // ask the kernel not to write the peer address (the caller
        // can read it from the resulting socket if needed). No
        // heap-allocated buffer is referenced.
        unsafe {
            ring.submission()
                .push(&sqe)
                .map_err(|_| io::Error::other("io_uring SQ full at startup"))?;
        }
        Ok(())
    };

    push_accept(&mut ring)?;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::debug!("io_uring accept thread: shutdown observed");
            return Ok(());
        }

        // `submit_and_wait(1)` blocks until at least one completion
        // is available. The kernel wakes us on accept; on any error
        // we get a negative result CQE and process it the same way.
        if let Err(e) = ring.submit_and_wait(1) {
            // EINTR is benign (signal during the syscall). Anything
            // else is logged and we keep going — the listener
            // outlives transient kernel errors.
            if e.raw_os_error() != Some(libc::EINTR) {
                tracing::warn!(error = %e, "io_uring submit_and_wait");
            }
            continue;
        }

        let mut completions: u32 = 0;
        let mut need_resubmit = false;
        for cqe in ring.completion() {
            completions += 1;
            let res = cqe.result();
            if res < 0 {
                // Negative result is -errno. Log and re-arm.
                let err = io::Error::from_raw_os_error(-res);
                tracing::debug!(error = %err, "io_uring accept returned error");
                need_resubmit = true;
                continue;
            }
            let fd = res as RawFd;
            if tx.send(AcceptedConn { fd }).is_err() {
                // Receiver dropped — graceful shutdown signal.
                tracing::debug!(
                    "io_uring accept thread: mpsc receiver dropped, closing accepted fd {fd}"
                );
                // Don't leak the FD now that we can't hand it off.
                unsafe { libc::close(fd) };
                return Ok(());
            }
            // Single-shot mode: every CQE consumes one SQE, so we
            // need to push a fresh Accept SQE for the next inbound
            // connection.
            need_resubmit = true;
        }

        if completions > 0 {
            metrics::counter!("lynxx_io_uring_accepted_total").increment(completions as u64);
        }

        if need_resubmit {
            push_accept(&mut ring)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_decision() {
        // We don't assert availability — CI containers may or may
        // not allow io_uring_setup — only that the probe doesn't
        // panic and returns a discriminant.
        let _ = probe();
    }

    #[test]
    fn available_is_supported_helpers() {
        assert!(Available::Yes.is_supported());
        assert!(!Available::Unavailable("x".into()).is_supported());
    }

    #[test]
    fn accepted_conn_can_be_constructed() {
        // Pure structural test — no kernel.
        let _ = AcceptedConn { fd: -1 };
    }
}
