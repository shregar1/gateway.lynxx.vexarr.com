//! WebSocket flood: 500 concurrent WS sessions, 100 text frames/sec each.
//!
//! Spins up an embedded WS echo server on a **dedicated OS thread** (so it
//! doesn't compete with the 1500 client-side tokio tasks for executor time),
//! points a service+route at it, then opens 500 connections in staggered
//! batches and pumps frames. Pass criteria: ≥95% of connections stay open for
//! the entire test window with no frame drops on connected sessions.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use crate::chaos::{fmt_count, AdminClient, Args, Report};

/// Raise the process file-descriptor soft limit to at least `target`.
/// Silently caps at the hard limit if it's lower.
fn raise_fd_limit(target: u64) {
    #[cfg(unix)]
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            let new_soft = target.min(rl.rlim_max);
            if new_soft > rl.rlim_cur {
                rl.rlim_cur = new_soft;
                libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
            }
        }
    }
}

const SCENARIO: &str = "ws-flood";

/// Spin up a WS echo server in a **separate OS thread** with its own
/// **multi-threaded** tokio runtime (4 worker threads).
///
/// Why multi-threaded?
/// At 100 msg/sec per connection, 500 sessions generate 50 000 echo
/// messages/sec.  A `new_current_thread()` runtime tries to drive both the
/// accept loop *and* all those echo tasks on one thread.  Once the echo load
/// reaches ~250 connections the single thread can no longer drain the OS TCP
/// accept queue fast enough, the listen backlog (128) overflows, and new
/// gateway→upstream connections fail — explaining the consistent ~49%
/// connection rate.  Four threads easily outpace the accept + echo volume.
///
/// The runtime runs in its own OS thread so it never shares CPU with the main
/// tokio runtime that drives the 1 500+ client-side tasks.
fn start_echo_server() -> (SocketAddr, std::thread::JoinHandle<()>) {
    // Bind synchronously on the current thread before handing the fd over.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo");
    std_listener.set_nonblocking(true).expect("nonblocking");
    let addr = std_listener.local_addr().expect("local_addr");

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("ws-echo-worker")
            .build()
            .expect("echo rt");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("convert listener");
            run_ws_echo(listener).await;
        });
    });

    (addr, handle)
}

pub async fn run(admin: &AdminClient, args: &Args) -> Result<Report> {
    let duration = args.duration_or(Duration::from_secs(60));
    let target_conns: u64 = 500;

    // Disable the global 100-RPS rate-limit so the 500-connection burst isn't
    // throttled. Without this, the token bucket (burst=200, refill=100/s) only
    // allows ~245 of the 500 upgrade requests through — the source of the
    // consistent 49% connection rate we observed previously.
    let rl_ids = admin.disable_global_ratelimit().await;
    // Cluster bus polls every 1 s — wait 1.5 s to guarantee propagation before
    // any connection attempts.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // Need ~4× target FDs: client sock + gateway upstream sock + headroom.
    raise_fd_limit(8192);

    // Echo server on its own thread — never starves under load.
    let (upstream_addr, _echo_thread) = start_echo_server();
    // Give the echo server a moment to be ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let upstream_url = format!("http://{upstream_addr}");
    let svc_id = admin
        .create_service("chaos-ws", &upstream_url, 0, 10_000)
        .await?;
    let route_id = admin
        .create_route(svc_id, &["/chaos-ws"], &[], true)
        .await?;

    let proxy_ws = args
        .proxy_url
        .replacen("http://", "ws://", 1)
        .replacen("https://", "wss://", 1);
    let ws_url = format!("{}/chaos-ws", proxy_ws.trim_end_matches('/'));

    let connected = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));
    let recv = Arc::new(AtomicU64::new(0));

    // Stagger connections in batches of 50 to avoid thundering-herd drops.
    // 500 connections / 50 per batch × 50 ms gap = 450 ms of ramp-up.
    let batch_size: u64 = 50;
    let batch_gap = Duration::from_millis(50);
    let mut handles = Vec::with_capacity(target_conns as usize);

    for batch_start in (0..target_conns).step_by(batch_size as usize) {
        for i in batch_start..((batch_start + batch_size).min(target_conns)) {
            let url = ws_url.clone();
            let dur = duration;
            let connected = connected.clone();
            let dropped = dropped.clone();
            let sent = sent.clone();
            let recv = recv.clone();
            handles.push(tokio::spawn(async move {
                let conn = match tokio_tungstenite::connect_async(&url).await {
                    Ok((s, _)) => s,
                    Err(_) => {
                        dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                connected.fetch_add(1, Ordering::Relaxed);
                let (mut tx, mut rx) = conn.split();

                let send_task = {
                    let sent = sent.clone();
                    tokio::spawn(async move {
                        let interval = Duration::from_millis(10); // 100 msg/sec
                        let total_msgs = (dur.as_millis() / interval.as_millis()) as u64;
                        for n in 0..total_msgs {
                            let msg = format!("c{i}-{n}");
                            if tx.send(Message::text(msg)).await.is_err() {
                                return false;
                            }
                            sent.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(interval).await;
                        }
                        let _ = tx.close().await;
                        true
                    })
                };

                let recv_task = {
                    let recv = recv.clone();
                    tokio::spawn(async move {
                        while let Some(Ok(_msg)) = rx.next().await {
                            recv.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                };

                let send_ok = send_task.await.unwrap_or(false);
                let _ = recv_task.await;
                if !send_ok {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        tokio::time::sleep(batch_gap).await;
    }

    for h in handles {
        let _ = h.await;
    }

    let _ = admin.delete_route(route_id).await;
    let _ = admin.delete_service(svc_id).await;
    admin.restore_plugins(&rl_ids).await;

    let conn_n = connected.load(Ordering::Relaxed);
    let drop_n = dropped.load(Ordering::Relaxed);
    let sent_n = sent.load(Ordering::Relaxed);
    let recv_n = recv.load(Ordering::Relaxed);

    // Pass: ≥95% of connections established and all sent frames echoed back.
    let conn_rate = if conn_n + drop_n == 0 {
        0.0
    } else {
        conn_n as f64 / (conn_n + drop_n) as f64
    };
    let frame_ok = sent_n > 0 && recv_n >= sent_n;
    let pass = conn_rate >= 0.95 && frame_ok;
    let summary = format!(
        "{}/{} connected · {} dropped · {} sent · {} recv",
        conn_n,
        target_conns,
        drop_n,
        fmt_count(sent_n),
        fmt_count(recv_n)
    );
    let r = if pass {
        Report::pass(SCENARIO, summary)
    } else {
        Report::fail(SCENARIO, summary)
    };
    Ok(r.detail(format!(
        "ran {}s @ 100 msg/sec/conn; conn_rate={:.1}%",
        duration.as_secs(),
        conn_rate * 100.0
    )))
}

async fn run_ws_echo(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let ws = match tokio_tungstenite::accept_async(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let (mut tx, mut rx) = ws.split();
            while let Some(Ok(msg)) = rx.next().await {
                if msg.is_close() {
                    break;
                }
                if (msg.is_text() || msg.is_binary()) && tx.send(msg).await.is_err() {
                    break;
                }
            }
        });
    }
}
