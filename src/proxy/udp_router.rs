//! Layer-4 UDP load balancer / proxy with session affinity.
//!
//! Since UDP is connectionless, we track "sessions" keyed by the client's
//! source address. Each session is sticky to a single upstream for its
//! lifetime and expires after a configurable inactivity timeout.

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};

// ── Configuration ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpServiceConfig {
    pub name: String,
    /// Upstream `host:port` addresses to round-robin across.
    pub addresses: Vec<String>,
    /// Session inactivity timeout in seconds. Default: 10.
    #[serde(default = "default_udp_timeout")]
    pub timeout_secs: u64,
}

fn default_udp_timeout() -> u64 {
    10
}

// ── Session tracking ─────────────────────────────────────────────────

/// A UDP "session" mapping a client to its assigned upstream.
struct UdpSession {
    upstream_addr: SocketAddr,
    /// A dedicated socket bound to an ephemeral port for talking to this
    /// upstream. Responses from the upstream arrive here and are forwarded
    /// back to the client.
    upstream_socket: Arc<UdpSocket>,
    last_activity: Instant,
}

// ── Router ───────────────────────────────────────────────────────────

/// Cap on concurrent UDP sessions. UDP source addresses are trivially
/// spoofable, and each session binds an ephemeral socket + spawns a relay
/// task, so an unbounded table is an FD/task/memory-exhaustion vector.
const MAX_UDP_SESSIONS: usize = 65_536;

pub struct UdpRouter {
    services: Vec<UdpServiceConfig>,
    /// Sessions keyed by the client `SocketAddr` string representation.
    sessions: Arc<DashMap<String, UdpSession>>,
    /// Round-robin counter for upstream selection.
    rr_counter: AtomicUsize,
    /// Session timeout derived from the first service config (or default).
    timeout: Duration,
}

impl UdpRouter {
    /// Create a new router from the given service configs.
    pub fn new(services: Vec<UdpServiceConfig>) -> Self {
        let timeout_secs = services
            .first()
            .map(|s| s.timeout_secs)
            .unwrap_or(default_udp_timeout());
        Self {
            services,
            sessions: Arc::new(DashMap::new()),
            rr_counter: AtomicUsize::new(0),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// All upstream addresses flattened from every configured service.
    fn all_upstreams(&self) -> Vec<&str> {
        self.services
            .iter()
            .flat_map(|s| s.addresses.iter().map(String::as_str))
            .collect()
    }

    /// Pick the next upstream in round-robin order.
    fn next_upstream(&self) -> Option<SocketAddr> {
        let upstreams = self.all_upstreams();
        if upstreams.is_empty() {
            return None;
        }
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        upstreams[idx].parse().ok()
    }

    /// Handle an inbound UDP datagram from `src`.
    pub async fn handle_packet(
        self: &Arc<Self>,
        listener: &Arc<UdpSocket>,
        src: SocketAddr,
        data: &[u8],
    ) {
        if let Err(e) = self.handle_packet_inner(listener, src, data).await {
            tracing::debug!(error = %e, %src, "udp proxy error");
        }
    }

    async fn handle_packet_inner(
        self: &Arc<Self>,
        listener: &Arc<UdpSocket>,
        src: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        let key = src.to_string();

        // Fast path: existing session.
        if let Some(mut entry) = self.sessions.get_mut(&key) {
            entry.last_activity = Instant::now();
            entry
                .upstream_socket
                .send_to(data, entry.upstream_addr)
                .await
                .context("send to upstream")?;
            return Ok(());
        }

        // Slow path: create a new session. Bound the session table first — UDP
        // source addresses are spoofable, so without a cap a flood of distinct
        // sources would exhaust ephemeral sockets / relay tasks / FDs.
        if self.sessions.len() >= MAX_UDP_SESSIONS {
            tracing::warn!(%src, sessions = self.sessions.len(), "udp proxy at session cap; dropping packet");
            return Ok(());
        }

        let upstream_addr = self.next_upstream().context("no upstreams configured")?;
        let upstream_socket = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .context("bind ephemeral UDP socket")?,
        );

        upstream_socket
            .send_to(data, upstream_addr)
            .await
            .context("send to upstream")?;

        let session = UdpSession {
            upstream_addr,
            upstream_socket: upstream_socket.clone(),
            last_activity: Instant::now(),
        };
        self.sessions.insert(key.clone(), session);

        // Spawn a response relay task: reads from upstream and forwards back
        // to the client.
        let listener = listener.clone();
        let sessions = self.sessions.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let recv = tokio::time::timeout(timeout, upstream_socket.recv_from(&mut buf));
                match recv.await {
                    Ok(Ok((len, _from))) => {
                        // Refresh activity timestamp.
                        if let Some(mut entry) = sessions.get_mut(&key) {
                            entry.last_activity = Instant::now();
                        } else {
                            // Session was cleaned up; stop relay.
                            break;
                        }
                        if let Err(e) = listener.send_to(&buf[..len], src).await {
                            tracing::debug!(error = %e, "udp relay send to client");
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "udp relay recv from upstream");
                        break;
                    }
                    Err(_) => {
                        // Idle timeout. Remove ONLY if this session is still
                        // the idle one: a client packet may have refreshed
                        // last_activity (or created a replacement session for
                        // the same source) between the last upstream packet and
                        // this timeout firing — removing by key alone would drop
                        // that newer/active session (TOCTOU).
                        let now = Instant::now();
                        sessions.remove_if(&key, |_, s| {
                            now.duration_since(s.last_activity) >= timeout
                        });
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Prune sessions that have been idle longer than their timeout.
    /// Call this from a background sweeper task.
    pub fn prune_expired(&self) {
        let now = Instant::now();
        self.sessions
            .retain(|_key, session| now.duration_since(session.last_activity) < self.timeout);
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// ── Server ───────────────────────────────────────────────────────────

/// Listen for UDP datagrams on `addr` and proxy them through the given
/// [`UdpRouter`].  Also spawns a background task to prune expired sessions.
pub async fn serve_udp(addr: SocketAddr, router: Arc<UdpRouter>) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!(%addr, "udp proxy listening");

    // Background session reaper.
    let reaper_router = router.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            reaper_router.prune_expired();
        }
    });

    let mut buf = vec![0u8; 65535];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..len].to_vec();
        let router = router.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            router.handle_packet(&socket, src, &data).await;
        });
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_config(addrs: Vec<&str>) -> Vec<UdpServiceConfig> {
        vec![UdpServiceConfig {
            name: "test-svc".into(),
            addresses: addrs.into_iter().map(String::from).collect(),
            timeout_secs: 2,
        }]
    }

    #[test]
    fn round_robin_selection() {
        let router = UdpRouter::new(test_config(vec!["127.0.0.1:9001", "127.0.0.1:9002"]));
        let a = router.next_upstream().unwrap();
        let b = router.next_upstream().unwrap();
        let c = router.next_upstream().unwrap();
        // First two calls hit different backends, third wraps around.
        assert_ne!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn round_robin_single_upstream() {
        let router = UdpRouter::new(test_config(vec!["127.0.0.1:9001"]));
        let a = router.next_upstream().unwrap();
        let b = router.next_upstream().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn round_robin_no_upstreams() {
        let router = UdpRouter::new(vec![UdpServiceConfig {
            name: "empty".into(),
            addresses: vec![],
            timeout_secs: 10,
        }]);
        assert!(router.next_upstream().is_none());
    }

    #[test]
    fn session_count_starts_at_zero() {
        let router = UdpRouter::new(test_config(vec!["127.0.0.1:9001"]));
        assert_eq!(router.session_count(), 0);
    }

    #[test]
    fn prune_expired_removes_stale_sessions() {
        let router = UdpRouter::new(test_config(vec!["127.0.0.1:9001"]));
        // Manually insert a session that is already expired.
        let upstream_addr: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9001));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
            let session = UdpSession {
                upstream_addr,
                upstream_socket: sock,
                last_activity: Instant::now() - Duration::from_secs(60),
            };
            router.sessions.insert("192.168.1.1:12345".into(), session);
            assert_eq!(router.session_count(), 1);
            router.prune_expired();
            assert_eq!(router.session_count(), 0);
        });
    }

    #[test]
    fn prune_keeps_active_sessions() {
        let router = UdpRouter::new(test_config(vec!["127.0.0.1:9001"]));
        let upstream_addr: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9001));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
            let session = UdpSession {
                upstream_addr,
                upstream_socket: sock,
                last_activity: Instant::now(), // fresh
            };
            router.sessions.insert("192.168.1.1:12345".into(), session);
            assert_eq!(router.session_count(), 1);
            router.prune_expired();
            assert_eq!(router.session_count(), 1); // still alive
        });
    }

    #[test]
    fn default_timeout_value() {
        assert_eq!(default_udp_timeout(), 10);
    }

    #[test]
    fn config_deserialization() {
        let json = r#"{
            "name": "dns-proxy",
            "addresses": ["8.8.8.8:53", "8.8.4.4:53"]
        }"#;
        let cfg: UdpServiceConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.name, "dns-proxy");
        assert_eq!(cfg.addresses.len(), 2);
        assert_eq!(cfg.timeout_secs, 10); // default
    }

    #[tokio::test]
    async fn handle_packet_creates_session() {
        let upstream_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let router = Arc::new(UdpRouter::new(vec![UdpServiceConfig {
            name: "test".into(),
            addresses: vec![upstream_addr.to_string()],
            timeout_secs: 5,
        }]));

        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = "127.0.0.1:55555".parse().unwrap();

        router.handle_packet(&listener, client_addr, b"hello").await;

        assert_eq!(router.session_count(), 1);

        // Upstream should have received the data.
        let mut buf = vec![0u8; 1024];
        let (len, _from) = tokio::time::timeout(
            Duration::from_secs(2),
            upstream_listener.recv_from(&mut buf),
        )
        .await
        .expect("timeout waiting for upstream")
        .expect("recv failed");
        assert_eq!(&buf[..len], b"hello");
    }
}
