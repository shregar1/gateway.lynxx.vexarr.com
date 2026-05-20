# io_uring in lynxx — what we ship, what we don't, why

> **TL;DR.** This release adds an opt-in io_uring **accept thread** for
> the proxy listener. That's a bounded, real perf win — typically 1–3%
> RPS on accept-heavy connection storms, near-zero on steady-state
> long-lived connections. **It is not** a migration to io_uring for the
> data plane; that path requires either a tokio→tokio-uring runtime
> swap or moving to `monoio` / `glommio`, both of which are multi-week
> efforts that touch every async fn in the gateway and are scoped
> separately on the roadmap.

## What's in this release

A self-contained module — `src/utilities/io_uring_accept.rs`,
Linux-only — that:

1. Probes the host kernel for `io_uring_setup` + `IORING_OP_ACCEPT`
   support.
2. Spawns a dedicated `std::thread` that owns an `io_uring` instance.
3. Submits `IORING_OP_ACCEPT` SQEs for a caller-supplied listener FD.
4. Drains CQEs and forwards each accepted FD to the tokio runtime via
   a `tokio::sync::mpsc::UnboundedSender<AcceptedConn>`.
5. Tokio-side glue (one helper in the same module) wraps each `AcceptedConn`'s
   FD into a `std::net::TcpStream`, ready for `tokio::net::TcpStream::from_std`.

The thread is **not** a tokio worker. It runs purely blocking
syscalls and doesn't share the tokio executor. The handoff to tokio
is the mpsc channel.

### What you get vs. `tokio::net::TcpListener::accept`

| Cost per accept | Tokio epoll path | io_uring accept thread |
| --- | --- | --- |
| Syscall (`accept4`) | 1 | 0 (replaced by SQE submission) |
| `io_uring_enter` | n/a | 1 amortised across all SQEs in the batch |
| Wake the worker that ran `accept().await` | yes | no — accepted FD lands on a tokio task that consumes the channel |
| Cost of `from_std(fd)` | n/a | 1 small allocation, no syscall |

The win is **bounded**. We're cutting one syscall out of the per-accept
path; we're not changing the data-plane I/O model. For a listener
taking 10k new connections/sec that's ~500 µs/sec saved — meaningful
for connection-storm scenarios, irrelevant for the steady state.

The *unbounded* io_uring wins all live on the data plane and are
discussed below in **Roadmap**.

## When to enable

Opt in via the config block:

```toml
[gateway.tls]
enabled = true
kernel_tls = true            # required — io_uring wires into the kTLS accept loop only

[gateway.io_uring]
accept_thread_enabled = true   # default false
ring_entries = 64              # SQ/CQ size; floor 8, kernel rounds to power-of-two
```

The two features compose: the kTLS listener's accept loop pulls
accepted FDs from `mpsc::UnboundedReceiver<AcceptedConn>` when
`accept_thread_enabled = true` and the runtime probe succeeds;
otherwise it falls back to `tokio::net::TcpListener::accept().await`
as before. The kTLS upgrade pathway is unchanged either way — the
FD source is the only thing that swaps.

**Effective only on the kTLS accept loop.** The standard
`axum-server` path owns its own internal accept loop and there's no
clean hook to swap the FD source. Setting
`io_uring.accept_thread_enabled = true` with `kernel_tls = false`
is therefore a no-op; we don't currently log a warning for the
mismatch but that's a small follow-up if operators want louder
feedback. The runtime probe always logs its decision so the
"is io_uring engaged?" question is answerable from a fresh startup
log.

Recommended scenarios:

* Multi-tenant gateways behind a CGNAT or load balancer that opens
  many short-lived TCP sessions.
* Benchmarks that report on accept overhead specifically (wrk's
  `-c <large> -d <short>` mode, h2load with `--max-streams=1`).
* Kernel 5.6+ deployments (5.4 LTS works but lacks the `Probe`
  introspection op — our probe falls back to "unavailable").

When to leave it off:

* Single-tenant, persistent-connection workloads (gRPC, websockets).
  The amortised gain is in the noise.
* Hosts with < 5.6 kernels — the probe will simply report
  `Unavailable` and we fall through to the tokio path with no log
  spam beyond a one-line startup notice.
* CPU-pinned worker pools tighter than 2 cores total — the dedicated
  thread is a real worker slot.

## What we deliberately did NOT do

### `IORING_ACCEPT_MULTISHOT` (kernel 5.19+)

Multishot accept lets a single SQE service multiple inbound
connections — the kernel keeps the SQE armed until it's explicitly
cancelled. The `io-uring` crate exposes `opcode::AcceptMulti`, but:

* `AcceptMulti::CODE == Accept::CODE` — they share the opcode
  number, differing only in the `IORING_ACCEPT_MULTISHOT` bit in
  `ioprio`. The `Probe` API can't distinguish them at the opcode
  level, so a clean feature probe needs `uname()` or a runtime
  submit-and-observe test.
* Single-shot accept already submits in batches (we push one SQE per
  CQE inside the same `io_uring_enter` window), so the amortised
  syscall cost is near-multishot already.

Multishot is on the follow-up list, gated by either a `uname`-based
kernel-version check or a runtime probe that submits one
`AcceptMulti` SQE on a dummy socket and inspects whether the kernel
returns `-EINVAL`. Neither is hard; both add code that should land
with its own tests.

### Registered buffers (`IORING_REGISTER_BUFFERS`)

The big-throughput io_uring win is registered buffers + `READ_FIXED`
/ `WRITE_FIXED`: userspace pre-registers a slab of memory, the
kernel maps it once, and per-I/O `read`/`write` calls reference the
buffer by index. No `copy_to_user` per record.

This only matters on the **data plane** — once a connection is
accepted and being read from / written to. Wiring it in requires:

* The data-plane I/O has to issue io_uring SQEs instead of
  `tokio::io::AsyncRead::poll_read`.
* That's `hyper::server::conn::http1::Builder::serve_connection` and
  `tokio_rustls::server::TlsStream`, neither of which goes through
  io_uring.
* The realistic path is to swap the entire runtime: tokio →
  tokio-uring (single-threaded, every async fn re-parameterised) or
  tokio → monoio / glommio (whole-listener replacements with
  hyper-compatible bridges).

The migration target is on the roadmap below.

### `SQPOLL` kernel polling thread

`IORING_SETUP_SQPOLL` asks the kernel to spawn a polling thread that
reaps SQEs without us calling `io_uring_enter`. Net win at very high
SQE rates; CPU-cost penalty when idle (the kernel thread spins). On
an accept-only ring it's overkill — accept rates rarely exceed a few
tens of thousands per second per listener.

Worth revisiting if/when we move data-plane I/O onto io_uring.

### File I/O (config reads, access logs, static files)

A common pitch is "use io_uring for access log writes." On lynxx
specifically:

* Access logs already batch into a `tokio::sync::mpsc` and write via
  a dedicated tokio task. The per-write syscall is amortised.
* Static file serving goes through `tower-http::services::ServeFile`,
  which uses `tokio::fs::File` (tokio's spawn_blocking pool). Moving
  it to `tokio_uring::fs::File::read_at` would help — and is a clean
  scope — but again requires the tokio-uring runtime.

These are real opportunities but each is "small but real" and we'd
rather have them coalesce around the same runtime migration than
ship a half-dozen one-off acceptors.

## Roadmap — what unlocks the big wins

The honest gating step is a runtime migration. Two viable options:

### Option A: tokio-uring side runtime (recommended)

Run a `tokio_uring::start` runtime on a dedicated thread, used only
for paths that benefit from io_uring (file I/O, eventually
socket I/O on the data plane). Pass work to / from the main tokio
runtime via channels.

Pros:

* Incremental — we don't rip out the tokio executor everywhere at
  once.
* Composes naturally with the kTLS listener (kTLS upgrades the FD
  post-handshake, and the io_uring data-plane reads start from the
  same FD).
* Battle-tested — Pingora uses essentially this pattern.

Cons:

* Hairy ownership between runtimes. Every borrowed buffer has to
  outlive the io_uring submission.
* Two runtimes' graceful-shutdown semantics to reconcile.

### Option B: monoio / glommio full migration

Drop tokio entirely. Replace with `monoio` (single-threaded
io_uring) or `glommio` (thread-per-core io_uring). Each axum
handler, plugin, and integration becomes re-parameterised over the
new runtime's traits.

Pros:

* Pure-io_uring path everywhere.
* Cleaner mental model — one runtime, no cross-runtime channels.

Cons:

* Multi-week effort. Touches every async fn.
* Plugin authors have to re-target.
* Hyper compatibility shims exist but are less battle-tested than
  the tokio bridge.

### Option C (this PR)

Keep tokio for everything; carve out one specific syscall
(`accept`) into io_uring via a dedicated thread + channel. Low
blast radius. Bounded win. Already shipped.

The hill we'd die on is **not** that Option C is sufficient — it's
that Option A or B is too large a migration to bolt onto the
gateway without a focused PR series of its own. This module is
infrastructure for that future work *and* a useful standalone
optimisation for accept-heavy listeners today.

## Verification status

* `cargo check --bin lynxx-gateway` clean on macOS (the io_uring
  module is `#[cfg(target_os = "linux")]`; macOS sees no symbols).
* `cargo clippy --bin lynxx-gateway -- -D warnings` clean.
* 3 unit tests covering the io_uring public API surface (probe,
  `Available` helpers, struct construction). Run only on Linux due
  to the module cfg-gate.
* **Integrated into the kTLS listener.** When
  `[gateway.tls].kernel_tls = true` and
  `[gateway.io_uring].accept_thread_enabled = true` on a Linux host
  whose `probe()` returns `Available::Yes`, the kTLS listener's
  accept loop pulls from `IoUringAcceptor`'s channel instead of
  `TcpListener::accept().await`. On any other combination the
  standard tokio accept path runs and a warning is logged when the
  feature was requested but isn't usable.
* Linux runtime verification is deferred — requires a kernel with
  `io_uring_setup` available and a listener under traffic load. The
  failure modes (probe says no, acceptor fails to start, channel
  closes mid-flight) all fall back cleanly to either tokio accept
  or a listener-level error; no silent regression path.

## Metric exposed

`lynxx_io_uring_accepted_total` (counter, no labels) — bumped once
per CQE batch on the accept thread. The canonical "is io_uring
actually accepting anything?" signal for operators. Pair with
`lynxx_ktls_upgrade_total` to see the full per-connection picture
on a deployment that runs both features.
