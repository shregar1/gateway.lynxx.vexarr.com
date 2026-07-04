//! Layer-4 TCP proxy with SNI-based routing.
//!
//! Provides TLS-passthrough proxying by peeking at the TLS ClientHello to
//! extract the SNI hostname, then routing to an upstream without terminating
//! TLS. Also supports source-IP matching via CIDR rules.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;

// ── Configuration ────────────────────────────────────────────────────

/// TCP route rule. Matches on HostSNI (TLS) or ClientIP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpRoute {
    pub name: String,
    /// Rule expression: `HostSNI(\`example.com\`)`, `HostSNI(\`*\`)`,
    /// `ClientIP(\`192.168.0.0/24\`)`. Combine with `&&` / `||`.
    pub rule: String,
    /// Upstream service addresses.
    pub services: Vec<TcpServiceConfig>,
    /// When `true` TLS is forwarded as-is (no termination).
    pub tls_passthrough: bool,
    /// Higher priority routes are evaluated first.
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpServiceConfig {
    /// `host:port`
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

// ── Matcher AST ──────────────────────────────────────────────────────

/// Parsed rule for matching incoming TCP connections.
#[derive(Debug)]
enum TcpMatcher {
    /// Exact SNI hostname match (case-insensitive).
    HostSni(String),
    /// `HostSNI(\`*\`)` -- matches any connection (catch-all).
    HostSniWildcard,
    /// Source IP must fall within the given CIDR range.
    ClientIp(IpNet),
    /// All children must match.
    And(Vec<TcpMatcher>),
    /// At least one child must match.
    Or(Vec<TcpMatcher>),
}

impl TcpMatcher {
    fn matches(&self, sni: Option<&str>, client_ip: IpAddr) -> bool {
        match self {
            TcpMatcher::HostSni(expected) => sni
                .map(|s| s.eq_ignore_ascii_case(expected))
                .unwrap_or(false),
            TcpMatcher::HostSniWildcard => true,
            TcpMatcher::ClientIp(net) => net.contains(&client_ip),
            TcpMatcher::And(children) => children.iter().all(|c| c.matches(sni, client_ip)),
            TcpMatcher::Or(children) => children.iter().any(|c| c.matches(sni, client_ip)),
        }
    }
}

// ── Rule parser ──────────────────────────────────────────────────────

/// Parse a rule string into a [`TcpMatcher`].
///
/// Grammar (informal):
/// ```text
/// rule       := or_expr
/// or_expr    := and_expr ( "||" and_expr )*
/// and_expr   := atom ( "&&" atom )*
/// atom       := "HostSNI" "(" tick_string ")"
///             | "ClientIP" "(" tick_string ")"
/// tick_string := "`" <chars> "`"
/// ```
fn parse_rule(input: &str) -> Result<TcpMatcher> {
    let input = input.trim();
    if input.is_empty() {
        bail!("empty rule expression");
    }
    let (matcher, rest) = parse_or(input)?;
    let rest = rest.trim();
    if !rest.is_empty() {
        bail!("unexpected trailing input: {rest}");
    }
    Ok(matcher)
}

fn parse_or(input: &str) -> Result<(TcpMatcher, &str)> {
    let (first, mut rest) = parse_and(input)?;
    let mut parts = vec![first];
    loop {
        let trimmed = rest.trim_start();
        if let Some(after) = trimmed.strip_prefix("||") {
            let (next, r) = parse_and(after)?;
            parts.push(next);
            rest = r;
        } else {
            break;
        }
    }
    if parts.len() == 1 {
        Ok((parts.remove(0), rest))
    } else {
        Ok((TcpMatcher::Or(parts), rest))
    }
}

fn parse_and(input: &str) -> Result<(TcpMatcher, &str)> {
    let (first, mut rest) = parse_atom(input)?;
    let mut parts = vec![first];
    loop {
        let trimmed = rest.trim_start();
        if let Some(after) = trimmed.strip_prefix("&&") {
            let (next, r) = parse_atom(after)?;
            parts.push(next);
            rest = r;
        } else {
            break;
        }
    }
    if parts.len() == 1 {
        Ok((parts.remove(0), rest))
    } else {
        Ok((TcpMatcher::And(parts), rest))
    }
}

fn parse_atom(input: &str) -> Result<(TcpMatcher, &str)> {
    let input = input.trim_start();

    if let Some(rest) = input.strip_prefix("HostSNI") {
        let rest = rest.trim_start();
        let rest = rest
            .strip_prefix('(')
            .context("expected '(' after HostSNI")?;
        let (value, rest) = parse_tick_string(rest)?;
        let rest = rest.trim_start();
        let rest = rest
            .strip_prefix(')')
            .context("expected ')' after tick string")?;
        if value == "*" {
            Ok((TcpMatcher::HostSniWildcard, rest))
        } else {
            Ok((TcpMatcher::HostSni(value.to_ascii_lowercase()), rest))
        }
    } else if let Some(rest) = input.strip_prefix("ClientIP") {
        let rest = rest.trim_start();
        let rest = rest
            .strip_prefix('(')
            .context("expected '(' after ClientIP")?;
        let (value, rest) = parse_tick_string(rest)?;
        let rest = rest.trim_start();
        let rest = rest
            .strip_prefix(')')
            .context("expected ')' after tick string")?;
        let net: IpNet = value.parse().context("invalid CIDR in ClientIP")?;
        Ok((TcpMatcher::ClientIp(net), rest))
    } else {
        bail!(
            "unexpected token in rule: {}",
            &input[..input.len().min(30)]
        );
    }
}

/// Parse a back-tick quoted string: `` `value` ``
fn parse_tick_string(input: &str) -> Result<(String, &str)> {
    let input = input.trim_start();
    let input = input.strip_prefix('`').context("expected opening '`'")?;
    let end = input.find('`').context("unterminated tick string")?;
    let value = &input[..end];
    let rest = &input[end + 1..];
    Ok((value.to_string(), rest))
}

// ── SNI extraction ───────────────────────────────────────────────────

/// Maximum bytes we peek at to find the SNI extension in a TLS ClientHello.
const MAX_PEEK: usize = 16384;
/// Max time to wait for a TLS ClientHello before giving up on the SNI peek —
/// bounds slowloris clients that connect but never send.
const SNI_PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Cap on concurrent L4 connections this listener services at once, to bound
/// FD / task usage under a connection flood.
const MAX_TCP_CONNECTIONS: usize = 8192;

/// Peek at the beginning of a TLS stream and try to extract the SNI hostname
/// from the ClientHello. Returns `None` for non-TLS connections, plaintext
/// traffic, or ClientHellos without an SNI extension.
///
/// The peeked bytes are **not** consumed from the stream so the full
/// handshake can proceed normally when forwarded to the upstream.
async fn peek_sni(stream: &TcpStream) -> Result<Option<String>> {
    let mut buf = vec![0u8; MAX_PEEK];
    // Bound the wait for the ClientHello: a slowloris client that connects but
    // never sends would otherwise hang this task (and hold the FD) forever.
    let n = match tokio::time::timeout(SNI_PEEK_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(r) => r?,
        Err(_) => return Ok(None),
    };
    if n < 5 {
        return Ok(None);
    }
    let buf = &buf[..n];
    extract_sni_from_bytes(buf)
}

/// Pure function that extracts SNI from raw bytes of a TLS ClientHello.
///
/// TLS record layout:
/// ```text
/// byte 0:      ContentType  (0x16 = Handshake)
/// bytes 1-2:   ProtocolVersion
/// bytes 3-4:   Length
/// byte 5:      HandshakeType (0x01 = ClientHello)
/// bytes 6-8:   HandshakeLength (u24)
/// bytes 9-10:  ClientVersion
/// bytes 11-42: Random (32 bytes)
/// byte 43:     SessionIDLength
/// ...          SessionID
/// ...          CipherSuites
/// ...          CompressionMethods
/// ...          Extensions
/// ```
fn extract_sni_from_bytes(buf: &[u8]) -> Result<Option<String>> {
    // Must start with TLS handshake record.
    if buf.len() < 5 || buf[0] != 0x16 {
        return Ok(None);
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = 5 + record_len;
    let buf = if buf.len() < total {
        buf
    } else {
        &buf[..total]
    };

    // Handshake header.
    if buf.len() < 6 || buf[5] != 0x01 {
        return Ok(None); // Not a ClientHello.
    }

    // Skip past handshake header (4 bytes: type + u24 length).
    let mut pos = 9;

    // ClientVersion (2 bytes).
    pos += 2;
    if pos > buf.len() {
        return Ok(None);
    }

    // Random (32 bytes).
    pos += 32;
    if pos >= buf.len() {
        return Ok(None);
    }

    // Session ID.
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > buf.len() {
        return Ok(None);
    }

    // Cipher suites.
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= buf.len() {
        return Ok(None);
    }

    // Compression methods.
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        return Ok(None);
    }

    // Extensions length.
    let ext_total = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > buf.len() {
        // Partial -- work with what we have.
    }

    // Walk extensions looking for SNI (type 0x0000).
    while pos + 4 <= buf.len() && pos < ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension.  Layout:
            //   u16 server_name_list_length
            //   u8  server_name_type  (0 = hostname)
            //   u16 server_name_length
            //   [u8; server_name_length] server_name
            if pos + 5 > buf.len() {
                return Ok(None);
            }
            // Skip list length (2 bytes).
            let name_type = buf[pos + 2];
            let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            if name_type != 0 {
                return Ok(None); // not a hostname
            }
            let name_start = pos + 5;
            let name_end = name_start + name_len;
            if name_end > buf.len() {
                return Ok(None);
            }
            let hostname =
                std::str::from_utf8(&buf[name_start..name_end]).context("invalid UTF-8 in SNI")?;
            return Ok(Some(hostname.to_string()));
        }
        pos += ext_len;
    }

    Ok(None)
}

// ── Router ───────────────────────────────────────────────────────────

pub struct TcpRouter {
    routes: Vec<(TcpMatcher, TcpRoute)>,
}

impl TcpRouter {
    /// Build a router from a set of route configs.  Routes are sorted by
    /// descending priority so higher-priority rules are evaluated first.
    pub fn new(mut routes: Vec<TcpRoute>) -> Result<Self> {
        routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        let compiled: Vec<(TcpMatcher, TcpRoute)> = routes
            .into_iter()
            .map(|r| {
                let matcher = parse_rule(&r.rule)
                    .with_context(|| format!("bad rule in route '{}': {}", r.name, r.rule))?;
                Ok((matcher, r))
            })
            .collect::<Result<_>>()?;
        Ok(Self { routes: compiled })
    }

    /// Find the first matching route for the given SNI and client IP.
    fn match_route(&self, sni: Option<&str>, client_ip: IpAddr) -> Option<&TcpRoute> {
        self.routes
            .iter()
            .find(|(m, _)| m.matches(sni, client_ip))
            .map(|(_, r)| r)
    }

    /// Pick an upstream address using weighted random selection.
    fn pick_upstream(route: &TcpRoute) -> Option<&str> {
        if route.services.is_empty() {
            return None;
        }
        if route.services.len() == 1 {
            return Some(&route.services[0].address);
        }
        let total_weight: u32 = route.services.iter().map(|s| s.weight).sum();
        if total_weight == 0 {
            return Some(&route.services[0].address);
        }
        // Simple deterministic round-robin approximation using timestamp nanos.
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let point = tick % total_weight;
        let mut acc = 0u32;
        for svc in &route.services {
            acc += svc.weight;
            if point < acc {
                return Some(&svc.address);
            }
        }
        // Unreachable when total_weight > 0 (the loop must hit a bucket since
        // point < total_weight == final acc), but keep the fallback panic-free.
        route.services.last().map(|s| s.address.as_str())
    }
}

// ── Connection handler ───────────────────────────────────────────────

async fn handle_tcp_conn(
    mut inbound: TcpStream,
    peer: SocketAddr,
    router: &TcpRouter,
) -> Result<()> {
    let sni = peek_sni(&inbound).await.unwrap_or(None);

    let route = router
        .match_route(sni.as_deref(), peer.ip())
        .context("no matching TCP route")?;

    let upstream_addr = TcpRouter::pick_upstream(route).context("no upstream services")?;

    tracing::debug!(
        peer = %peer,
        sni = sni.as_deref().unwrap_or("-"),
        route = %route.name,
        upstream = %upstream_addr,
        "tcp route matched"
    );

    let mut upstream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("connect to upstream {upstream_addr}"))?;

    tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await?;

    Ok(())
}

// ── Server ───────────────────────────────────────────────────────────

/// Listen for TCP connections on `addr` and route them through the given
/// [`TcpRouter`].  This function runs forever (or until the listener errors).
///
/// The listener is bound with `SO_REUSEPORT` so multiple gateway processes
/// may co-bind to the same address:port — the kernel load-balances new
/// connections across the bound sockets. See
/// [`crate::proxy::listener::bind_reuseport`].
pub async fn serve_tcp(addr: SocketAddr, router: Arc<TcpRouter>) -> Result<()> {
    let listener = crate::proxy::listener::bind_reuseport(addr)?;
    tracing::info!(%addr, "tcp proxy listening");
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        // Bound concurrent connections: under a connection flood / slowloris,
        // drop the new connection rather than spawning unboundedly until we run
        // out of file descriptors or memory.
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(%peer, "tcp proxy at connection cap; dropping connection");
                drop(stream);
                continue;
            }
        };
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection task ends
            if let Err(e) = handle_tcp_conn(stream, peer, &router).await {
                tracing::debug!(error = %e, "tcp proxy connection error");
            }
        });
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // -- SNI extraction ------------------------------------------------

    /// Construct a minimal TLS 1.2 ClientHello with a single SNI extension
    /// for the given hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len();

        // SNI extension payload.
        let sni_entry_len = 1 + 2 + name_len; // type(1) + len(2) + name
        let sni_list_len = sni_entry_len;
        let sni_ext_len = 2 + sni_list_len; // list_len(2) + list

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0u16.to_be_bytes()); // ext type = SNI
        sni_ext.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // ext data len
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes()); // list len
        sni_ext.push(0x00); // name type = hostname
        sni_ext.extend_from_slice(&(name_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let extensions_len = sni_ext.len();

        // ClientHello body (after handshake header).
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        hello_body.extend_from_slice(&[0u8; 32]); // random
        hello_body.push(0); // session id length = 0
        hello_body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        hello_body.extend_from_slice(&[0x00, 0xff]); // one dummy suite
        hello_body.push(1); // compression methods length
        hello_body.push(0); // null compression
        hello_body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        hello_body.extend_from_slice(&sni_ext);

        let handshake_len = hello_body.len();

        // Handshake header: type(1) + u24 length(3).
        let mut handshake = vec![
            0x01, // ClientHello
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello_body);

        // TLS record header.
        let record_len = handshake.len();
        let mut record = vec![0x16]; // ContentType = Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn sni_extraction_basic() {
        let hello = build_client_hello("example.com");
        let sni = extract_sni_from_bytes(&hello).unwrap();
        assert_eq!(sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn sni_extraction_long_hostname() {
        let host = "very-long-subdomain.deeply.nested.example.org";
        let hello = build_client_hello(host);
        let sni = extract_sni_from_bytes(&hello).unwrap();
        assert_eq!(sni.as_deref(), Some(host));
    }

    #[test]
    fn sni_extraction_non_tls() {
        let garbage = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let sni = extract_sni_from_bytes(garbage).unwrap();
        assert!(sni.is_none());
    }

    #[test]
    fn sni_extraction_too_short() {
        let sni = extract_sni_from_bytes(&[0x16, 0x03]).unwrap();
        assert!(sni.is_none());
    }

    // -- Rule parsing --------------------------------------------------

    #[test]
    fn parse_hostsni_exact() {
        let m = parse_rule("HostSNI(`api.example.com`)").unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(m.matches(Some("api.example.com"), ip));
        assert!(m.matches(Some("API.EXAMPLE.COM"), ip)); // case-insensitive
        assert!(!m.matches(Some("other.com"), ip));
        assert!(!m.matches(None, ip));
    }

    #[test]
    fn parse_hostsni_wildcard() {
        let m = parse_rule("HostSNI(`*`)").unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(m.matches(Some("anything.com"), ip));
        assert!(m.matches(None, ip)); // wildcard matches even without SNI
    }

    #[test]
    fn parse_clientip() {
        let m = parse_rule("ClientIP(`192.168.1.0/24`)").unwrap();
        let inside = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let outside = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(m.matches(None, inside));
        assert!(!m.matches(None, outside));
    }

    #[test]
    fn parse_compound_and() {
        let m = parse_rule("HostSNI(`db.internal`) && ClientIP(`10.0.0.0/8`)").unwrap();
        let ip_ok = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let ip_bad = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        assert!(m.matches(Some("db.internal"), ip_ok));
        assert!(!m.matches(Some("db.internal"), ip_bad)); // wrong IP
        assert!(!m.matches(Some("other.com"), ip_ok)); // wrong SNI
    }

    #[test]
    fn parse_compound_or() {
        let m = parse_rule("HostSNI(`a.example.com`) || HostSNI(`b.example.com`)").unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert!(m.matches(Some("a.example.com"), ip));
        assert!(m.matches(Some("b.example.com"), ip));
        assert!(!m.matches(Some("c.example.com"), ip));
    }

    #[test]
    fn parse_complex_rule() {
        // (HostSNI match OR ClientIP match) -- tests mixed operators.
        let m = parse_rule("HostSNI(`secure.io`) && ClientIP(`172.16.0.0/12`) || HostSNI(`*`)")
            .unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(172, 20, 0, 5));
        // The `||` has lower precedence, so this is:
        //   (HostSNI(`secure.io`) && ClientIP(`172.16.0.0/12`)) || HostSNI(`*`)
        // Wildcard always matches, so the whole thing is true for any input.
        assert!(m.matches(Some("random.com"), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // But verify the AND arm also matches independently.
        assert!(m.matches(Some("secure.io"), ip));
    }

    #[test]
    fn parse_rule_error_on_empty() {
        assert!(parse_rule("").is_err());
    }

    #[test]
    fn parse_rule_error_on_bad_token() {
        assert!(parse_rule("Bogus(`x`)").is_err());
    }

    // -- Route matching ------------------------------------------------

    #[test]
    fn route_priority_ordering() {
        let routes = vec![
            TcpRoute {
                name: "catch-all".into(),
                rule: "HostSNI(`*`)".into(),
                services: vec![TcpServiceConfig {
                    address: "fallback:443".into(),
                    weight: 1,
                }],
                tls_passthrough: true,
                priority: 0,
            },
            TcpRoute {
                name: "specific".into(),
                rule: "HostSNI(`api.example.com`)".into(),
                services: vec![TcpServiceConfig {
                    address: "api-upstream:443".into(),
                    weight: 1,
                }],
                tls_passthrough: true,
                priority: 10,
            },
        ];
        let router = TcpRouter::new(routes).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        // Higher-priority specific route should match first.
        let matched = router.match_route(Some("api.example.com"), ip).unwrap();
        assert_eq!(matched.name, "specific");
        assert_eq!(matched.services[0].address, "api-upstream:443");

        // Unknown SNI falls through to catch-all.
        let matched = router.match_route(Some("unknown.com"), ip).unwrap();
        assert_eq!(matched.name, "catch-all");
    }

    #[test]
    fn pick_upstream_single_service() {
        let route = TcpRoute {
            name: "test".into(),
            rule: "HostSNI(`*`)".into(),
            services: vec![TcpServiceConfig {
                address: "backend:8080".into(),
                weight: 1,
            }],
            tls_passthrough: true,
            priority: 0,
        };
        assert_eq!(TcpRouter::pick_upstream(&route), Some("backend:8080"));
    }

    #[test]
    fn pick_upstream_empty_services() {
        let route = TcpRoute {
            name: "empty".into(),
            rule: "HostSNI(`*`)".into(),
            services: vec![],
            tls_passthrough: true,
            priority: 0,
        };
        assert_eq!(TcpRouter::pick_upstream(&route), None);
    }
}
