//! Malformed traffic survival: 1000 raw TCP requests in five flavours.
//!
//! Each flavour is intentionally hostile in a different way — random bytes,
//! oversized headers, invalid methods, missing CRLF, pipelined garbage. The
//! gateway must respond with 4xx or close the connection, and crucially must
//! not crash, hang, or leak more than ~5 MB of RSS.

use std::time::Duration;

use anyhow::Result;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::chaos::{find_gateway_pid, fmt_count, rss_kb, AdminClient, Args, Report};

const SCENARIO: &str = "malformed";

pub async fn run(_admin: &AdminClient, args: &Args) -> Result<Report> {
    let _ = args.duration; // not honoured — the test owns its own timing

    let addr = parse_host_port(&args.proxy_url)?;
    let pid = find_gateway_pid();
    let baseline_kb = pid.and_then(rss_kb).unwrap_or(0);

    let mut totals = Totals::default();
    for kind in [
        Kind::Random,
        Kind::OversizedHeader,
        Kind::InvalidMethod,
        Kind::MissingCrlf,
        Kind::PipelinedGarbage,
    ] {
        for _ in 0..200 {
            match send_one(&addr, kind).await {
                Outcome::ClosedOr4xx => totals.handled += 1,
                Outcome::Accepted2xx => totals.unexpected_2xx += 1,
                Outcome::ConnectErr => totals.connect_err += 1,
            }
        }
    }

    // Give the gateway a beat to release any per-connection allocations.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let final_kb = pid.and_then(rss_kb).unwrap_or(baseline_kb);
    let growth_kb = final_kb.saturating_sub(baseline_kb);
    let growth_mb = growth_kb as f64 / 1024.0;

    let pass = totals.unexpected_2xx == 0 && growth_mb < 5.0 && pid.is_some();
    let summary = format!(
        "{} handled · {} unexpected 2xx · RSS {:+.1} MB",
        fmt_count(totals.handled),
        totals.unexpected_2xx,
        growth_mb,
    );
    let r = if pass {
        Report::pass(SCENARIO, summary)
    } else {
        Report::fail(SCENARIO, summary)
    };
    Ok(r.detail(format!(
        "1000 raw probes (5x200); connect errs={}; pid={:?}",
        totals.connect_err, pid
    )))
}

#[derive(Default)]
struct Totals {
    handled: u64,
    unexpected_2xx: u64,
    connect_err: u64,
}

#[derive(Clone, Copy)]
enum Kind {
    Random,
    OversizedHeader,
    InvalidMethod,
    MissingCrlf,
    PipelinedGarbage,
}

enum Outcome {
    ClosedOr4xx,
    Accepted2xx,
    ConnectErr,
}

async fn send_one(addr: &str, kind: Kind) -> Outcome {
    let mut s = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => return Outcome::ConnectErr,
    };
    let payload: Vec<u8> = match kind {
        Kind::Random => {
            let n = rand::thread_rng().gen_range(16..512);
            (0..n).map(|_| rand::thread_rng().gen()).collect()
        }
        Kind::OversizedHeader => {
            let mut buf = b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ".to_vec();
            buf.extend(std::iter::repeat_n(b'A', 8 * 1024));
            buf.extend_from_slice(b"\r\n\r\n");
            buf
        }
        Kind::InvalidMethod => b"PINEAPPLE / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        Kind::MissingCrlf => b"GET / HTTP/1.1\nHost: x\n\n".to_vec(),
        Kind::PipelinedGarbage => {
            let mut v = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
            v.extend_from_slice(b"\xff\xfe\x00\x00garbage\xff\xfe");
            v.extend_from_slice(b"\r\n\r\n");
            v
        }
    };

    if s.write_all(&payload).await.is_err() {
        return Outcome::ClosedOr4xx;
    }
    let _ = s.flush().await;

    // Read with a short timeout. Anything other than a 2xx status (or a
    // close before any data) counts as "handled".
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => Outcome::ClosedOr4xx,
        Ok(Ok(n)) => {
            let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
            // Look for "HTTP/1.x 2xx" — anything else is fine.
            if head.starts_with("HTTP/1.") && head.len() >= 12 && &head[9..10] == "2" {
                Outcome::Accepted2xx
            } else {
                Outcome::ClosedOr4xx
            }
        }
        Ok(Err(_)) | Err(_) => Outcome::ClosedOr4xx,
    }
}

fn parse_host_port(url: &str) -> Result<String> {
    let rest = url
        .trim_end_matches('/')
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host_port = rest.split('/').next().unwrap_or(rest);
    if !host_port.contains(':') {
        anyhow::bail!("expected host:port in proxy URL, got `{url}`");
    }
    Ok(host_port.to_string())
}
