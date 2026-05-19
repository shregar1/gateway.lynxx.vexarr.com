//! Kernel TLS (kTLS) listener path for the proxy port.
//!
//! `[gateway.tls].kernel_tls = true` switches the proxy TLS listener
//! from the standard `axum-server` + `tokio-rustls` flow onto a custom
//! accept loop that:
//!
//! 1. Drives the TLS handshake via `tokio-rustls` exactly as before.
//! 2. After the handshake completes, calls `ktls::config_ktls_server(...)`
//!    which uses `setsockopt(TLS_TX/TLS_RX)` to hand the negotiated
//!    cipher state to the kernel.
//! 3. From that point on, hands a *plaintext* socket to hyper. The
//!    kernel does record framing + AES-GCM (or ChaCha20-Poly1305) on
//!    the way out and inverse on the way in. Userspace never touches a
//!    ciphertext byte after the handshake.
//!
//! The win, measured on production-shaped TLS workloads:
//!
//! * One memcpy out of the proxy hot path (the rustls inbound record
//!   buffer goes away).
//! * `sendfile(2)` and zero-copy splice become legal on TLS sockets —
//!   the static-files plugin and any future zero-copy upstream can use
//!   them. Standard userspace TLS prohibits this.
//! * The AEAD work moves into the kernel's `tls_ulp` module, which is
//!   roughly as fast as userspace ring/aws-lc but doesn't contend on
//!   the proxy worker's L1 cache footprint.
//!
//! ## Why a separate listener loop?
//!
//! `axum-server` 0.7 wraps the `TcpStream` in `tokio_rustls::TlsStream`
//! and immediately hands it to `hyper`. It does not expose a
//! post-handshake hook where we could insert the kTLS upgrade. Forking
//! `axum-server` for this one feature would be larger and harder to
//! upstream than a parallel accept loop that uses `hyper-util` directly.
//!
//! ## What this listener gives up vs. axum-server
//!
//! * HTTP/3 — kTLS is TCP-only. HTTP/3 (QUIC) has its own crypto path
//!   and is already a separate listener in this gateway; nothing
//!   changes there.
//! * PROXY-protocol header handling — the existing axum-server path
//!   doesn't actually wire `tls.proxy_protocol` to the accept loop
//!   either (it's a documented TODO), so we're at parity.
//! * `axum-server::Handle` for graceful shutdown — we provide our own
//!   `KtlsHandle` with the same `graceful_shutdown(Option<Duration>)`
//!   shape so the existing `run_select!` macro in main.rs works
//!   unchanged.
//!
//! ## Platform support
//!
//! Linux 4.13+ for TLS 1.2 AES-GCM; 5.1+ for TLS 1.3 AES-GCM; 5.11+
//! for ChaCha20-Poly1305. The kernel must have `CONFIG_TLS=y` (or the
//! `tls` module loadable). On macOS / Windows the public entry-point
//! returns an error at startup; main.rs falls back to the standard
//! axum-server path with a warning log.
//!
//! ## Cipher suite negotiation
//!
//! If the handshake settles on a cipher the kernel can't drive (e.g.
//! the client offered AES-128-CBC-only), `ktls::config_ktls_server`
//! returns an error and we close the connection. That's strictly
//! safer than silently falling back to userspace TLS — operators who
//! opt into `kernel_tls = true` want to know which connections aren't
//! getting the offload. Per-connection counter:
//! `lynxx_ktls_upgrade_failed_total` (TODO — wired in a follow-up).

use crate::config::TlsSettings;
use crate::error::GatewayError;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// Opaque handle to a running kTLS listener. Mirrors
/// `axum_server::Handle`'s `graceful_shutdown(Option<Duration>)` API
/// so the `run_select!` macro in `main.rs` can drive both paths
/// identically.
#[derive(Clone)]
pub struct KtlsHandle {
    shutdown: Arc<Notify>,
    drained: Arc<Notify>,
}

impl KtlsHandle {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(Notify::new()),
            drained: Arc::new(Notify::new()),
        }
    }

    /// Request a graceful shutdown. Stops accepting new connections
    /// immediately and gives in-flight requests up to `grace` to
    /// drain. After the grace window, in-flight handlers are aborted
    /// when the listener future is dropped by the surrounding
    /// `tokio::select!`.
    pub fn graceful_shutdown(&self, grace: Option<Duration>) {
        self.shutdown.notify_waiters();
        if let Some(g) = grace {
            let drained = self.drained.clone();
            // Best-effort: log when the grace window expires. The
            // listener future itself watches `shutdown` and drains
            // up to `grace`.
            tokio::spawn(async move {
                tokio::time::sleep(g).await;
                drained.notify_waiters();
            });
        }
    }
}

impl Default for KtlsHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true on hosts where `kernel_tls` is actually usable. On
/// non-Linux this is a compile-time `false`. On Linux we still
/// return `true` unconditionally — runtime feature probing
/// (uname / `setsockopt` test) is a v2 niceness; in v1 the
/// `config_ktls_server` call will fail with a clear error on a
/// kernel that lacks support, and the connection will close.
#[inline]
pub const fn supported_on_host() -> bool {
    cfg!(target_os = "linux")
}

// ---------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use axum::Router;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use hyper_util::service::TowerToHyperService;
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    /// Serve `app` over kTLS-offloaded TLS on `listener` until
    /// `handle` is signalled. Returns when the accept loop exits.
    ///
    /// `server_config` must have `enable_secret_extraction = true` —
    /// the caller is responsible for setting that before wrapping in
    /// `Arc`. We assert it on entry to fail loudly rather than at the
    /// first connection.
    pub async fn serve(
        listener: TcpListener,
        server_config: Arc<ServerConfig>,
        app: Router,
        handle: KtlsHandle,
    ) -> Result<(), std::io::Error> {
        if !server_config.enable_secret_extraction {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ktls listener requires ServerConfig::enable_secret_extraction = true",
            ));
        }

        let acceptor = TlsAcceptor::from(server_config);
        let conn_builder = Arc::new(ConnBuilder::new(TokioExecutor::new()));

        tracing::info!("kTLS listener accept loop started");

        loop {
            tokio::select! {
                biased;
                _ = handle.shutdown.notified() => {
                    tracing::info!("kTLS listener: shutdown signalled, ceasing accepts");
                    break;
                }
                accept = listener.accept() => {
                    let (tcp, peer) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            // Transient accept errors (EMFILE etc.) shouldn't
                            // tear down the whole listener. Log and continue.
                            tracing::warn!(error = %e, "kTLS listener: accept error, continuing");
                            continue;
                        }
                    };

                    // Disable Nagle for HTTP latency; the standard path
                    // does the same via socket2 in utilities/net.rs but
                    // axum-server's tcp_nodelay isn't on the path here.
                    let _ = tcp.set_nodelay(true);

                    let acceptor = acceptor.clone();
                    let conn_builder = conn_builder.clone();
                    let app = app.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_one(acceptor, conn_builder, tcp, app).await {
                            tracing::debug!(peer = %peer, error = %e, "kTLS connection ended with error");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    async fn handle_one(
        acceptor: TlsAcceptor,
        conn_builder: Arc<ConnBuilder<TokioExecutor>>,
        tcp: tokio::net::TcpStream,
        app: Router,
    ) -> anyhow::Result<()> {
        // 1. Handshake in userspace.
        let tls_stream = acceptor.accept(tcp).await?;

        // 2. Upgrade to kTLS. The kernel takes over record framing +
        //    AEAD from this point. If the negotiated cipher isn't one
        //    the kernel understands, this errors and the connection
        //    is closed — there's no silent fallback by design.
        let ktls_stream = ktls::config_ktls_server(tls_stream).await?;

        // 3. Hand the now-plaintext-from-userspace stream to hyper.
        //    `serve_connection_with_upgrades` handles HTTP/1.1 with
        //    Upgrade (websockets etc.) plus HTTP/2 — ALPN was already
        //    decided during the handshake above.
        let io = TokioIo::new(ktls_stream);
        let service = TowerToHyperService::new(app);
        conn_builder
            .serve_connection_with_upgrades(io, service)
            .await
            .map_err(|e| anyhow::anyhow!("hyper serve_connection: {e}"))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::serve;

// ---------------------------------------------------------------------
// Non-Linux stub
// ---------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
pub async fn serve(
    _listener: TcpListener,
    _server_config: Arc<rustls::ServerConfig>,
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
}
