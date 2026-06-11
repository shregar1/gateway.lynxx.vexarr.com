use crate::proxy::handler::{proxy_handler, ProxyState};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, Version};
use bytes::Buf;
use futures_util::StreamExt;
use h3_quinn::quinn;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

/// Start the HTTP/3 (QUIC) server on the given UDP address.
///
/// Uses the same `rustls::ServerConfig` as the TCP listener. HTTP/3
/// requires ALPN to include `"h3"`.
pub async fn spawn_h3_server(
    addr: SocketAddr,
    state: Arc<ProxyState>,
    rustls_config: rustls::ServerConfig,
) -> anyhow::Result<()> {
    // quinn 0.11+ uses a specialized wrapper for rustls config.
    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| anyhow::anyhow!("failed to create QUIC server config: {}", e))?;
    let quic_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    let endpoint = quinn::Endpoint::server(quic_config, addr)?;
    info!("HTTP/3 listening on udp://{}", addr);

    tokio::spawn(async move {
        while let Some(new_conn) = endpoint.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                match new_conn.await {
                    Ok(conn) => {
                        if let Err(e) = handle_connection(conn, state).await {
                            error!("H3 connection error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("H3 accept error: {}", e);
                    }
                }
            });
        }
    });

    Ok(())
}

async fn handle_connection(conn: quinn::Connection, state: Arc<ProxyState>) -> anyhow::Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let (req, mut stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!("H3 resolve request error: {}", e);
                    return;
                }
            };

            let (parts, _) = req.into_parts();

            // Collect request body chunks from the stream. Two fixes vs. the
            // previous loop: (1) extend from the chunk slice instead of
            // pushing one byte at a time (the old code was O(n) syscalls and
            // realloc churn for a multi-MB upload); (2) cap the total at 64
            // MiB so a malicious client can't OOM the gateway by streaming an
            // unbounded body over an HTTP/3 datagram.
            const H3_MAX_BODY: usize = 64 * 1024 * 1024;
            let mut body_bytes: Vec<u8> = Vec::new();
            let mut overflowed = false;
            loop {
                match stream.recv_data().await {
                    Ok(Some(chunk)) => {
                        // `Buf::chunk()` returns the contiguous remaining slice
                        // of the current Bytes — no per-byte copying.
                        let slice = chunk.chunk();
                        if body_bytes.len().saturating_add(slice.len()) > H3_MAX_BODY {
                            overflowed = true;
                            break;
                        }
                        body_bytes.extend_from_slice(slice);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("H3 body read error: {}", e);
                        return;
                    }
                }
            }
            if overflowed {
                error!(
                    cap = H3_MAX_BODY,
                    "H3 request body exceeded cap; aborting stream"
                );
                return;
            }

            let mut axum_req = Request::from_parts(parts, Body::from(body_bytes));
            *axum_req.version_mut() = Version::HTTP_3;

            match proxy_handler(State(state.into()), axum_req).await {
                Ok(resp) => {
                    let (parts, body) = resp.into_parts();
                    let h3_resp = Response::from_parts(parts, ());
                    if let Err(e) = stream.send_response(h3_resp).await {
                        error!("H3 send_response error: {}", e);
                        return;
                    }

                    let mut body_stream = body.into_data_stream();
                    while let Some(chunk_result) = body_stream.next().await {
                        match chunk_result {
                            Ok(chunk) => {
                                if let Err(e) = stream.send_data(chunk).await {
                                    error!("H3 send_data error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("H3 body stream error: {}", e);
                                break;
                            }
                        }
                    }

                    if let Err(e) = stream.finish().await {
                        error!("H3 finish stream error: {}", e);
                    }
                }
                Err(e) => {
                    error!("H3 handler error: {}", e);
                    let resp = Response::builder().status(500).body(()).unwrap();
                    let _ = stream.send_response(resp).await;
                    let _ = stream.finish().await;
                }
            }
        });
    }

    Ok(())
}
