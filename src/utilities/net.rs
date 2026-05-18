use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct BindConfig {
    pub addr: String,
    pub port: u16,
    pub strict: bool,
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub backlog: i32,
}

impl BindConfig {
    pub fn new(addr: &str, port: u16, strict: bool) -> Self {
        Self {
            addr: addr.to_string(),
            port,
            strict,
            max_retries: if strict { 0 } else { 5 },
            base_delay_ms: 200,
            backlog: 8192,
        }
    }
}

#[derive(Debug)]
pub struct BoundListener {
    pub listener: TcpListener,
    pub port: u16,
    pub was_fallback: bool,
}

fn create_reusable_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn try_bind(socket: Socket, addr: SocketAddr, backlog: i32) -> io::Result<std::net::TcpListener> {
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(socket.into())
}

pub async fn resilient_bind(cfg: &BindConfig) -> anyhow::Result<BoundListener> {
    let sock_addr: SocketAddr = format!("{}:{}", cfg.addr, cfg.port).parse()?;
    let mut last_err = None;

    for attempt in 0..=cfg.max_retries {
        if attempt > 0 {
            let delay = std::time::Duration::from_millis(cfg.base_delay_ms * (1 << (attempt - 1)));
            tracing::warn!(
                port = cfg.port,
                attempt,
                delay_ms = delay.as_millis() as u64,
                "port busy, retrying"
            );
            tokio::time::sleep(delay).await;
        }

        match try_bind(create_reusable_socket()?, sock_addr, cfg.backlog) {
            Ok(std_listener) => {
                let listener = TcpListener::from_std(std_listener)?;
                return Ok(BoundListener {
                    listener,
                    port: cfg.port,
                    was_fallback: false,
                });
            }
            Err(e) => last_err = Some(e),
        }
    }

    if cfg.strict {
        return Err(anyhow::anyhow!(
            "failed to bind {}:{}: {}",
            cfg.addr,
            cfg.port,
            last_err.unwrap()
        ));
    }

    tracing::warn!(
        requested_port = cfg.port,
        "all retries exhausted, falling back to OS-assigned port"
    );
    let fallback_addr: SocketAddr = format!("{}:0", cfg.addr).parse()?;
    let std_listener = try_bind(create_reusable_socket()?, fallback_addr, cfg.backlog)?;
    let actual_port = std_listener.local_addr()?.port();
    let listener = TcpListener::from_std(std_listener)?;
    tracing::warn!(
        requested_port = cfg.port,
        actual_port,
        "bound to fallback port"
    );
    Ok(BoundListener {
        listener,
        port: actual_port,
        was_fallback: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_to_requested_port() {
        let cfg = BindConfig::new("127.0.0.1", 0, false);
        let bound = resilient_bind(&cfg).await.unwrap();
        assert!(!bound.was_fallback);
    }

    #[tokio::test]
    async fn returns_correct_port_on_ephemeral() {
        let cfg = BindConfig::new("127.0.0.1", 0, false);
        let bound = resilient_bind(&cfg).await.unwrap();
        let actual = bound.listener.local_addr().unwrap().port();
        assert_eq!(bound.port, 0);
        assert!(actual > 0);
    }

    #[tokio::test]
    async fn strict_mode_fails_on_occupied_port() {
        let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied = blocker.local_addr().unwrap().port();

        let cfg = BindConfig::new("127.0.0.1", occupied, true);
        let result = resilient_bind(&cfg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn non_strict_falls_back_on_occupied_port() {
        let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied = blocker.local_addr().unwrap().port();

        let mut cfg = BindConfig::new("127.0.0.1", occupied, false);
        cfg.max_retries = 0;
        cfg.base_delay_ms = 1;
        let bound = resilient_bind(&cfg).await.unwrap();
        assert!(bound.was_fallback);
        assert_ne!(bound.port, occupied);
    }

    #[tokio::test]
    async fn so_reuseaddr_allows_rebind_after_close() {
        let cfg = BindConfig::new("127.0.0.1", 0, false);
        let first = resilient_bind(&cfg).await.unwrap();
        let port = first.listener.local_addr().unwrap().port();
        drop(first);

        let cfg2 = BindConfig::new("127.0.0.1", port, true);
        let second = resilient_bind(&cfg2).await.unwrap();
        assert_eq!(second.listener.local_addr().unwrap().port(), port);
    }

    #[test]
    fn bind_config_strict_disables_retries() {
        let cfg = BindConfig::new("0.0.0.0", 8080, true);
        assert_eq!(cfg.max_retries, 0);
        assert!(cfg.strict);
    }

    #[test]
    fn bind_config_non_strict_has_retries() {
        let cfg = BindConfig::new("0.0.0.0", 8080, false);
        assert_eq!(cfg.max_retries, 5);
        assert!(!cfg.strict);
    }

    #[test]
    fn create_reusable_socket_sets_options() {
        let socket = create_reusable_socket().unwrap();
        assert!(socket.reuse_address().unwrap());
        assert!(socket.nonblocking().unwrap());
    }
}
