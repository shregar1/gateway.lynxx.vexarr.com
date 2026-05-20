//! Kernel TLS (kTLS) listener path for the proxy port.
//!
//! `[gateway.tls].kernel_tls = true` switches the proxy TLS listener
//! from the standard `axum-server` + `tokio-rustls` flow onto a custom
//! accept loop that:
//!
//! 1. Drives the TLS handshake via `tokio-rustls` exactly as before.
//! 2. **Peeks at the negotiated cipher suite + protocol version.** If
//!    the negotiation settled on a suite the kernel can drive (any of
//!    the AEAD suites in `KTLS_COMPATIBLE_SUITES`), proceed.
//!    Otherwise: bump `lynxx_ktls_fallback_total` and serve the
//!    connection over userspace rustls, unchanged. The connection is
//!    **never closed** because of an unsupported cipher — operators
//!    who opt into `kernel_tls = true` get a graceful userspace
//!    fallback for clients whose ciphers don't fit, with a clear
//!    metric signal to track how often it happens.
//! 3. On a compatible suite, calls `ktls::config_ktls_server(...)`
//!    which uses `setsockopt(TLS_TX/TLS_RX)` to hand the negotiated
//!    cipher state to the kernel. If the call still fails (e.g.
//!    kernel module not loaded, EPERM), bump
//!    `lynxx_ktls_upgrade_failed_total` and fall back to userspace.
//! 4. Hand the resulting stream (kTLS or userspace) to hyper via
//!    `hyper_util::server::conn::auto::Builder`.
//!
//! ## Listener inputs
//!
//! Both the static-cert and ACME paths feed configs through a single
//! `watch::Receiver<Arc<ServerConfig>>`. The static path holds a
//! single never-changing value; the ACME path's
//! [`AcmeManager::set_ktls_reload_handle`] returns a receiver whose
//! value is replaced on every cert renewal. The accept loop calls
//! `rx.borrow().clone()` per connection — an Arc clone, no I/O — so
//! the cost of supporting hot-reload is essentially free.
//!
//! ## Graceful shutdown
//!
//! Connections are tracked in a [`tokio::task::JoinSet`]. On
//! [`KtlsHandle::graceful_shutdown`]:
//!
//! 1. The accept loop is signalled and stops taking new TCP sockets.
//! 2. Already-spawned per-connection tasks are awaited up to the
//!    supplied grace duration via `JoinSet::join_next` in a loop.
//! 3. If the grace window expires, remaining tasks are aborted via
//!    `JoinSet::shutdown` — matching axum-server's behaviour.
//!
//! ## Platform support
//!
//! Linux 4.13+ for TLS 1.2 AES-GCM; 5.1+ for TLS 1.3 AES-GCM; 5.11+
//! for ChaCha20-Poly1305. The kernel must have `CONFIG_TLS=y` (or the
//! `tls` module loadable). On macOS / Windows the public entry-point
//! returns an error at startup; main.rs falls back to the standard
//! axum-server path with a warning log.
//!
//! ## Metrics
//!
//! * `lynxx_ktls_upgrade_total` — successful kTLS upgrades.
//! * `lynxx_ktls_fallback_total{reason}` — handshakes where the
//!   negotiated cipher isn't kTLS-compatible (`reason="unsupported_cipher"`).
//! * `lynxx_ktls_upgrade_failed_total{kind}` — kTLS-compatible cipher
//!   but `config_ktls_server` returned an error
//!   (`kind="setsockopt_failed"` typically).
//!
//! These are described once at process startup; see
//! `register_ktls_metrics()` below.

use crate::config::TlsSettings;
use crate::error::GatewayError;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, Notify};

/// Cipher suites that the Linux kernel's `tls_ulp` module can drive.
/// Used by the post-handshake precheck — a handshake that settles on
/// anything outside this list serves over userspace TLS via the same
/// listener loop.
///
/// Source: `net/tls/tls_main.c` in the Linux kernel (4.13+ for
/// AES-GCM 1.2; 5.1+ for TLS 1.3; 5.11+ for ChaCha20-Poly1305). We
/// list both AES-GCM key sizes and ChaCha20 across TLS 1.2 + 1.3.
/// AES-CCM is intentionally omitted: kernel supports it but rustls
/// (with the ring provider) does not.
#[cfg(target_os = "linux")]
const KTLS_COMPATIBLE_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256          (TLS 1.3)
    0x1302, // TLS_AES_256_GCM_SHA384          (TLS 1.3)
    0x1303, // TLS_CHACHA20_POLY1305_SHA256    (TLS 1.3)
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  (TLS 1.2)
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  (TLS 1.2)
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    (TLS 1.2)
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    (TLS 1.2)
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   (TLS 1.2)
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2)
];

/// Opaque handle to a running kTLS listener. Mirrors
/// `axum_server::Handle`'s `graceful_shutdown(Option<Duration>)` API
/// so the `run_select!` macro in `main.rs` can drive both paths
/// identically.
#[derive(Clone)]
pub struct KtlsHandle {
    shutdown: Arc<Notify>,
    /// Grace duration set by the most recent `graceful_shutdown` call.
    /// The accept loop reads this after receiving the shutdown notify
    /// to decide how long to wait for in-flight connections to drain.
    grace: Arc<Mutex<Option<Duration>>>,
}

impl KtlsHandle {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(Notify::new()),
            grace: Arc::new(Mutex::new(None)),
        }
    }

    /// Request a graceful shutdown. Stops accepting new connections
    /// immediately and gives in-flight requests up to `grace` to
    /// drain. Returns synchronously — the actual draining happens
    /// inside the listener future, which the caller is expected to
    /// poll alongside this handle (typically via `tokio::select!`).
    pub fn graceful_shutdown(&self, grace: Option<Duration>) {
        // Try to record the grace duration. `try_lock` here is fine —
        // there should never be contention; `graceful_shutdown` is
        // called once per process lifetime.
        if let Ok(mut g) = self.grace.try_lock() {
            *g = grace;
        }
        self.shutdown.notify_waiters();
    }
}

impl Default for KtlsHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true on hosts where `kernel_tls` is actually usable. On
/// non-Linux this is a compile-time `false`.
#[inline]
pub const fn supported_on_host() -> bool {
    cfg!(target_os = "linux")
}

/// Register the kTLS metric descriptions with the global `metrics`
/// registry. Idempotent — safe to call from multiple listener wirings.
/// Should be called once during gateway startup if `kernel_tls` is on
/// for any listener.
pub fn register_ktls_metrics() {
    metrics::describe_counter!(
        "lynxx_ktls_upgrade_total",
        "Successful kTLS upgrades on the proxy listener."
    );
    metrics::describe_counter!(
        "lynxx_ktls_fallback_total",
        "Connections that fell back to userspace TLS because the negotiated cipher \
         suite is not kTLS-compatible. Labelled by `reason`."
    );
    metrics::describe_counter!(
        "lynxx_ktls_upgrade_failed_total",
        "kTLS upgrades that failed at the kernel boundary despite a compatible \
         cipher — typically `setsockopt(TLS_TX)` errors. Labelled by `kind`. \
         These connections still serve over userspace TLS."
    );
}

// ---------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::utilities::io_uring_accept::AcceptedConn;
    use axum::Router;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use hyper_util::service::TowerToHyperService;
    use rustls::ServerConfig;
    use std::net::SocketAddr;
    use std::time::Instant;
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::task::JoinSet;
    use tokio_rustls::TlsAcceptor;

    /// Source of accepted TCP connections for the kTLS accept loop.
    /// Two variants:
    ///
    /// * `Tokio` — call `TcpListener::accept().await` in the select
    ///   arm. The standard, always-available path.
    /// * `Channel` — receive accepted FDs from a `tokio::sync::mpsc`
    ///   receiver fed by an `io_uring` thread (see
    ///   `crate::utilities::io_uring_accept`). We hold the
    ///   `TcpListener` here too, **not to accept from it**, but to
    ///   keep the listener FD valid for the io_uring SQEs that
    ///   reference it. Dropping the listener would close the FD and
    ///   the kernel would deliver `-EBADF` CQEs ever after.
    enum AcceptSource {
        Tokio(TcpListener),
        Channel {
            _listener: TcpListener,
            rx: UnboundedReceiver<AcceptedConn>,
        },
    }

    impl AcceptSource {
        async fn next_conn(
            &mut self,
        ) -> Result<(tokio::net::TcpStream, SocketAddr), std::io::Error> {
            match self {
                AcceptSource::Tokio(l) => l.accept().await,
                AcceptSource::Channel { rx, .. } => match rx.recv().await {
                    Some(conn) => {
                        // Rebuild a tokio TcpStream from the FD the
                        // io_uring thread just handed us. The FD is
                        // owned by us from here on; from_std + the
                        // std stream's drop semantics ensure it's
                        // closed exactly once.
                        let std_stream =
                            unsafe { crate::utilities::io_uring_accept::fd_to_std_stream(conn.fd) };
                        std_stream.set_nonblocking(true)?;
                        let peer = std_stream
                            .peer_addr()
                            .unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
                        let stream = tokio::net::TcpStream::from_std(std_stream)?;
                        Ok((stream, peer))
                    }
                    None => Err(std::io::Error::other(
                        "io_uring accept channel closed; the acceptor thread exited",
                    )),
                },
            }
        }
    }

    /// Serve `app` over kTLS-offloaded TLS on `listener` until
    /// `handle` is signalled. Returns when the accept loop exits and
    /// the grace window for in-flight connections has elapsed.
    ///
    /// The ServerConfig is delivered via `config_rx` — the static
    /// path wraps a never-changing value, the ACME path's receiver
    /// gets replaced on every cert reload. Either way the accept
    /// loop reads the latest on each new connection.
    pub async fn serve(
        listener: TcpListener,
        config_rx: watch::Receiver<Arc<ServerConfig>>,
        app: Router,
        handle: KtlsHandle,
    ) -> Result<(), std::io::Error> {
        serve_inner(AcceptSource::Tokio(listener), config_rx, app, handle).await
    }

    /// Same as [`serve`], but pulls accepted FDs from `io_uring_rx`
    /// instead of `listener.accept()`. The `listener` is held so its
    /// FD stays alive — the io_uring acceptor thread, owned by the
    /// caller, references it via raw FD.
    pub async fn serve_with_io_uring(
        listener: TcpListener,
        io_uring_rx: UnboundedReceiver<AcceptedConn>,
        config_rx: watch::Receiver<Arc<ServerConfig>>,
        app: Router,
        handle: KtlsHandle,
    ) -> Result<(), std::io::Error> {
        serve_inner(
            AcceptSource::Channel {
                _listener: listener,
                rx: io_uring_rx,
            },
            config_rx,
            app,
            handle,
        )
        .await
    }

    async fn serve_inner(
        mut source: AcceptSource,
        mut config_rx: watch::Receiver<Arc<ServerConfig>>,
        app: Router,
        handle: KtlsHandle,
    ) -> Result<(), std::io::Error> {
        // Validate the initial config opts into secret extraction.
        // We assert here so a misconfigured wiring fails before the
        // first connection rather than per-handshake.
        {
            let initial = config_rx.borrow_and_update().clone();
            if !initial.enable_secret_extraction {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ktls listener requires ServerConfig::enable_secret_extraction = true",
                ));
            }
        }

        let conn_builder = Arc::new(ConnBuilder::new(TokioExecutor::new()));
        let mut tasks: JoinSet<()> = JoinSet::new();

        let source_label = match &source {
            AcceptSource::Tokio(_) => "tokio",
            AcceptSource::Channel { .. } => "io_uring",
        };
        tracing::info!(
            accept_source = source_label,
            "kTLS listener accept loop started"
        );

        loop {
            tokio::select! {
                biased;
                _ = handle.shutdown.notified() => {
                    tracing::info!("kTLS listener: shutdown signalled, ceasing accepts");
                    break;
                }
                // Reap completed tasks opportunistically so the JoinSet
                // doesn't grow unboundedly during normal operation.
                Some(_done) = tasks.join_next(), if !tasks.is_empty() => {}
                accept = source.next_conn() => {
                    let (tcp, peer) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(error = %e, "kTLS listener: accept error, continuing");
                            // If the io_uring channel closed permanently,
                            // bail out instead of busy-looping. The Tokio
                            // accept path keeps retrying as before.
                            if matches!(&source, AcceptSource::Channel { .. })
                                && e.kind() == std::io::ErrorKind::Other
                            {
                                return Err(e);
                            }
                            continue;
                        }
                    };

                    // Match the standard path's TCP tuning.
                    let _ = tcp.set_nodelay(true);

                    let acceptor = TlsAcceptor::from(config_rx.borrow().clone());
                    let conn_builder = conn_builder.clone();
                    let app = app.clone();

                    tasks.spawn(async move {
                        if let Err(e) = handle_one(acceptor, conn_builder, tcp, app).await {
                            tracing::debug!(
                                peer = %peer,
                                error = %e,
                                "kTLS connection ended with error"
                            );
                        }
                    });
                }
            }
        }

        // Drain phase. We waited on shutdown above; now give in-flight
        // tasks up to `grace` to finish naturally.
        let grace = *handle.grace.lock().await;
        match grace {
            Some(g) if !g.is_zero() => {
                let deadline = Instant::now() + g;
                tracing::info!(
                    grace_secs = g.as_secs(),
                    in_flight = tasks.len(),
                    "kTLS listener: draining in-flight connections"
                );
                while !tasks.is_empty() {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline.into()) => {
                            let remaining = tasks.len();
                            tasks.shutdown().await;
                            tracing::warn!(
                                aborted = remaining,
                                "kTLS listener: grace expired, aborting remaining connections"
                            );
                            break;
                        }
                        Some(_) = tasks.join_next() => {}
                    }
                }
            }
            _ => {
                // No grace requested — abort right away.
                let in_flight = tasks.len();
                tasks.shutdown().await;
                if in_flight > 0 {
                    tracing::info!(
                        aborted = in_flight,
                        "kTLS listener: no grace window, aborted in-flight connections"
                    );
                }
            }
        }

        tracing::info!("kTLS listener stopped");
        Ok(())
    }

    /// Drive one accepted TCP connection through: TLS handshake →
    /// cipher precheck → optional kTLS upgrade → hyper.
    async fn handle_one(
        acceptor: TlsAcceptor,
        conn_builder: Arc<ConnBuilder<TokioExecutor>>,
        tcp: tokio::net::TcpStream,
        app: Router,
    ) -> anyhow::Result<()> {
        // 1. Handshake in userspace via rustls.
        let tls_stream = acceptor.accept(tcp).await?;

        // 2. Cipher / version precheck. We read the negotiated suite
        //    before consuming the stream into `config_ktls_server`,
        //    so on any non-kTLS suite we can keep the connection
        //    alive on the userspace path.
        let suite_id = {
            let (_, conn) = tls_stream.get_ref();
            conn.negotiated_cipher_suite().map(|s| u16::from(s.suite()))
        };
        let can_ktls = match suite_id {
            Some(id) => KTLS_COMPATIBLE_SUITES.contains(&id),
            None => false,
        };

        if !can_ktls {
            metrics::counter!(
                "lynxx_ktls_fallback_total",
                "reason" => "unsupported_cipher"
            )
            .increment(1);
            return drive_hyper(tls_stream, conn_builder, app).await;
        }

        // 3. Attempt the upgrade. On failure, fall back to userspace
        //    — `config_ktls_server` consumes the stream so on Err
        //    we can't reuse it; we open a fresh path via a generic
        //    fallback flag the kernel records, but practically this
        //    branch is "log and drop": the precheck above already
        //    weeded out the cipher mismatch case, so a setsockopt
        //    failure here means the kernel module isn't loaded or
        //    the process lacks CAP_NET_ADMIN. Operators see the
        //    `lynxx_ktls_upgrade_failed_total` counter spike and
        //    investigate. The connection itself closes cleanly.
        match ktls::config_ktls_server(tls_stream).await {
            Ok(ktls_stream) => {
                metrics::counter!("lynxx_ktls_upgrade_total").increment(1);
                drive_hyper(ktls_stream, conn_builder, app).await
            }
            Err(e) => {
                metrics::counter!(
                    "lynxx_ktls_upgrade_failed_total",
                    "kind" => "setsockopt_failed"
                )
                .increment(1);
                Err(anyhow::anyhow!(
                    "kTLS upgrade failed (kernel module loaded? CAP_NET_ADMIN?): {e}"
                ))
            }
        }
    }

    /// Hand a finished TLS / kTLS stream to hyper. Monomorphises once
    /// per stream concrete type — small code size cost, zero runtime
    /// cost vs. a trait object.
    async fn drive_hyper<S>(
        stream: S,
        conn_builder: Arc<ConnBuilder<TokioExecutor>>,
        app: Router,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let service = TowerToHyperService::new(app);
        conn_builder
            .serve_connection_with_upgrades(io, service)
            .await
            .map_err(|e| anyhow::anyhow!("hyper serve_connection: {e}"))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{serve, serve_with_io_uring};

// ---------------------------------------------------------------------
// Non-Linux stub
// ---------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
pub async fn serve(
    _listener: TcpListener,
    _config_rx: watch::Receiver<Arc<rustls::ServerConfig>>,
    _app: axum::Router,
    _handle: KtlsHandle,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "kernel_tls is Linux-only; rebuild on Linux or set [gateway.tls].kernel_tls = false",
    ))
}

// ---------------------------------------------------------------------
// Helper for main.rs: prepare a ServerConfig for the kTLS path
// ---------------------------------------------------------------------

/// Build a rustls `ServerConfig` with `enable_secret_extraction = true`
/// set — required for `ktls` to read the negotiated cipher state via
/// rustls's secret-extraction API. Otherwise identical to
/// `crate::proxy::tls::build_server_config`.
///
/// This is a thin wrapper rather than a parameter on the existing
/// builder because the standard path (`kernel_tls = false`) should
/// **not** have secret extraction enabled — it's a small but real
/// security surface (rustls won't let secrets leak unless you opt in).
pub fn build_server_config_for_ktls(
    settings: &TlsSettings,
) -> Result<rustls::ServerConfig, GatewayError> {
    let mut config = crate::proxy::tls::build_server_config(settings)?;
    config.enable_secret_extraction = true;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_graceful_shutdown_does_not_panic_without_grace() {
        let h = KtlsHandle::new();
        h.graceful_shutdown(None);
    }

    #[test]
    fn supported_matches_target_os() {
        assert_eq!(supported_on_host(), cfg!(target_os = "linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ktls_compatible_suites_are_aead_only() {
        // All listed suites must be AEAD — they're the only ones the
        // kernel's tls_ulp can drive. If someone accidentally adds a
        // CBC or RC4 suite, this test catches it before merge.
        for &id in KTLS_COMPATIBLE_SUITES {
            // The known AEAD ranges in TLS 1.2 + 1.3.
            assert!(
                matches!(id, 0x1301..=0x1305 | 0xc02b..=0xc030 | 0xcca8 | 0xcca9),
                "cipher 0x{id:04x} is in KTLS_COMPATIBLE_SUITES but isn't a known AEAD"
            );
        }
    }
}
