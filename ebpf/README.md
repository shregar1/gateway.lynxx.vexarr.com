# lynxx-ebpf — kernel-level TCP observability + XDP rate-limiting sidecar

> **Beyond-Kong feature #7**, and the only one in the lynxx tree that lives
> outside the main gateway workspace. OpenResty-based gateways like Kong cannot
> see TCP retransmits or socket state transitions because they're entirely
> userspace. lynxx-ebpf is a privileged sidecar binary that loads a small
> set of eBPF programs into the host kernel:
>
> - **Tracepoints** on `tcp_retransmit_skb` and `tcp_set_state` for
>   loss/RTT observability that no userspace gateway can match.
> - **XDP per-IP rate-limiter** (opt-in) that drops over-budget packets
>   before they ever reach the userspace HTTP stack — a token bucket
>   per source IPv4 evaluated in-kernel at line rate.
>
> Both surfaces are exposed as Prometheus counters by the userspace
> daemon, which polls BPF maps every second.

## What this is

Two crates, one binary:

| Crate                    | Role                                          | Toolchain                                 |
| ------------------------ | --------------------------------------------- | ----------------------------------------- |
| `lynxx-ebpf-program`     | The kernel-side BPF programs and maps         | nightly + `bpfel-unknown-none` + `bpf-linker` |
| `lynxx-ebpf-userspace`   | The `lynxx-ebpf` binary: loader, exporter, signal handling | stable Rust (any host for `cargo check`; Linux for runtime) |

This directory has its **own** Cargo workspace (`ebpf/Cargo.toml`). It is
deliberately **not** a member of the main `backend.lynxx.dev` workspace,
because the BPF program crate requires a different toolchain and target
that would break `cargo check --workspace` on the gateway tree.

## Requirements

- **Linux kernel 5.8+** (BTF + CO-RE; we don't use CO-RE relocations
  yet, but tracepoint stability assumptions match this baseline).
- **`bpf-linker`** — install with `cargo install bpf-linker`.
- **Nightly Rust**, pinned via `ebpf/rust-toolchain.toml`. The pin is
  `nightly-2024-12-15`. Other recent nightlies will likely also work
  but are not validated here.
- **`CAP_BPF`** and **`CAP_NET_ADMIN`** — usually means running as root,
  or via a systemd unit with `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN`.
- On kernels 5.8–5.10, also `LimitMEMLOCK=infinity` (modern 5.11+ kernels
  account BPF maps via memcg).

## Build

The two crates have **different build invocations** because they target
different platforms. Don't run `cargo build` at the workspace root — it
will try (and fail) to build the BPF program for the host target.

```bash
cd ebpf

# 1. Build the kernel-side BPF program (Linux only).
cargo build --release \
    --package lynxx-ebpf-program \
    --target=bpfel-unknown-none \
    -Z build-std=core

# 2. Build the userspace daemon and embed the BPF object.
cargo build --release \
    --package lynxx-ebpf \
    --features embed-bpf-object
```

For host-only typecheck (e.g. on macOS), the userspace crate also
builds without the BPF object:

```bash
cd ebpf/lynxx-ebpf-userspace
cargo check
```

The resulting binary will refuse to start at runtime (because the
embedded BPF blob is a placeholder), but `cargo check` is enough to
catch type errors during development on a non-Linux dev box.

## Run

```bash
sudo ./target/release/lynxx-ebpf \
    --metrics-addr 0.0.0.0:9201 \
    --log-level info

# In another shell:
curl -s http://localhost:9201/metrics | grep lynxx_ebpf
```

CLI flags:

| Flag                  | Default              | Meaning                                                              |
| --------------------- | -------------------- | -------------------------------------------------------------------- |
| `--metrics-addr`      | `127.0.0.1:9201`     | `host:port` for the Prometheus scrape endpoint (`/metrics`).         |
| `--gateway-pid`       | _none_               | Optional PID. Logged in v1 only; kernel-side filtering is v2.        |
| `--log-level`         | `info`               | `error`, `warn`, `info`, `debug`, `trace`.                           |
| `--poll-interval-ms`  | `1000`               | How often to reconcile the BPF maps into Prometheus counters.        |
| `--xdp-iface`         | _none_               | Network interface (e.g. `eth0`) to attach the XDP rate-limiter to. Omit to skip XDP entirely. |

## Metrics emitted

| Metric                                       | Type    | Labels       | Notes                                                                 |
| -------------------------------------------- | ------- | ------------ | --------------------------------------------------------------------- |
| `lynxx_ebpf_tcp_retransmits_total`           | counter | `src`, `dst` | IPv4 src/dst as dotted decimal. One sample per observed flow per second. |
| `lynxx_ebpf_tcp_state_transitions_total`     | counter | `from`, `to` | TCP state names from `<linux/tcp_states.h>`.                          |
| `lynxx_ebpf_map_entries`                     | gauge   | `map`        | Live entry count per BPF map. Useful to detect map fill-up.           |
| `lynxx_ebpf_xdp_dropped_total`               | counter | `src`        | Packets dropped by the XDP rate-limiter, labelled by source IPv4. Only populated when `--xdp-iface` is set. |

## Programs

The kernel-side ELF ships three programs. Tracepoints attach automatically
on startup; the XDP program is opt-in via `--xdp-iface`.

### `tcp_retransmit_skb` (tracepoint, always-on)

Fires on every TCP retransmit. Bumps a `(saddr, daddr)`-keyed counter
in the `RETRANSMITS` BPF map. Userspace reconciles into
`lynxx_ebpf_tcp_retransmits_total` once per `--poll-interval-ms`.

### `tcp_set_state` (tracepoint, always-on)

Fires on every TCP state transition (`LISTEN → SYN_SENT → ESTABLISHED → …`).
Bumps a `(oldstate, newstate)`-keyed counter in `STATE_TRANSITIONS`.
Surfaced as `lynxx_ebpf_tcp_state_transitions_total`.

### `lynxx_xdp_ratelimit` (XDP, opt-in)

Per-source-IPv4 token bucket evaluated at the XDP hook — earlier than
iptables, earlier than the socket layer, earlier than userspace. The
**Beyond-Kong moat**: in-kernel rate limiting saves a full trip
through epoll + tokio + the plugin chain for traffic that's destined
to be rejected anyway.

Steady-state limit: **100 packets/sec per source IP**. Burst capacity:
**1,000 packets** (the bucket starts full).

Deploy with:

```bash
sudo ./target/release/lynxx-ebpf \
    --xdp-iface eth0 \
    --metrics-addr 0.0.0.0:9201
```

Driver mode: aya attaches in **SKB mode** by default (generic, works
on every NIC including virtual). For native-mode XDP (~10× faster) on
hardware NICs that support it (ice, mlx5, i40e, …), patch the loader
to pass `XdpFlags::DRV_MODE` — or wait on the planned `--xdp-mode`
flag in v2.

Caveats:

- IPv4 only. IPv6 packets are `XDP_PASS` (unaffected).
- Budget is hardcoded in `lynxx-ebpf-program/src/main.rs` (`CAPACITY`,
  `REFILL_PER_SEC`). v2 will read these from a config map populated
  by userspace.
- Map size is `MAX_TRACKED_IPS = 65,536`. On overflow new IPs are
  passed through (fail-open) rather than evicted — the existing
  buckets retain their state.
- Tracks source IP only — a single client behind a CGNAT shares one
  bucket with everyone else on that NAT. v2 should add an L4
  selector for per-port granularity.

## Limitations (v1)

- **Linux-only.** macOS / Windows users skip this binary entirely. It
  does `cargo check` on macOS for developer ergonomics; the produced
  binary refuses to start.
- **Aggregate metrics only.** No per-flow detail, no histograms,
  no path-level latency. Per-route p99 will require uprobes hooked
  into the gateway's hot-path functions and is explicitly v2.
- **IPv4 only.** The tracepoint format includes both v4 and v6
  fields, but for v1 we only emit IPv4 retransmit labels. v6 in v2.
- **No PID filtering.** `--gateway-pid` is logged but not enforced
  kernel-side. v2 will plumb a config map down to the BPF program.
- **No CO-RE relocations.** Tracepoint field offsets are hard-coded
  to match recent (5.8+) kernel layouts. CO-RE'ing them is an obvious
  future hardening step.
- **Polling, not perf events.** v1 reconciles HashMaps once a second.
  A perf-event ring buffer would be lower-latency but more code; for
  Prometheus scrape semantics, 1Hz is plenty.
- **XDP rate-limit budget is compile-time.** The `CAPACITY` and
  `REFILL_PER_SEC` constants live in the BPF program. Changing them
  requires a kernel-object rebuild + restart. v2 will lift them into
  a config map populated by userspace from a CLI flag.

## Roadmap

- **uprobes** on the gateway binary's `proxy_handler` for per-route
  latency histograms.
- **Per-connection RTT histograms** via `tcp_rcv_established`.
- **eBPF-driven request fingerprinting** feeding the existing
  anomaly-detector plugin (feature #6).
- **CO-RE relocations** so the program is portable across kernel
  versions without recompilation.
- **Push-based events** via a perf-event or ring-buffer map for
  sub-second latency on retransmit storms.
- **Per-route XDP rate-limit budgets** via an L4-selector key
  (`src_ip, dst_port`) rather than just source IP.
- **Native-mode XDP** (`XdpFlags::DRV_MODE`) wired behind a flag, with
  fallback to SKB mode when the driver lacks native support.

## Layout

```
ebpf/
├── Cargo.toml                          # this directory's workspace
├── README.md                           # this file
├── rust-toolchain.toml                 # pins nightly-2024-12-15 + bpfel target
├── lynxx-ebpf-program/
│   ├── Cargo.toml                      # no_std, panic=abort, lto=fat
│   └── src/main.rs                     # the BPF programs + maps
└── lynxx-ebpf-userspace/
    ├── Cargo.toml
    ├── build.rs                        # embeds the .o via include_bytes_aligned!
    └── src/main.rs                     # aya loader, Prometheus exporter, signals
```

## Honest verification status

This sidecar was **structurally** scaffolded on a macOS/M1 dev machine
and has **not** been runtime-verified against a Linux kernel. The gates
that *were* exercised:

- `cd ebpf/lynxx-ebpf-userspace && cargo check` — host typecheck on macOS.
- `cargo check --workspace` in the parent `backend.lynxx.dev` tree
  remains green; the eBPF crates are deliberately excluded.

The gates that *were not* exercised here, and that any Linux operator
should run before deploying:

- `cargo +nightly-2024-12-15 build --release --package lynxx-ebpf-program --target=bpfel-unknown-none -Z build-std=core` — BPF compile.
- `cargo build --release --package lynxx-ebpf --features embed-bpf-object` — userspace compile with real BPF blob.
- `sudo ./target/release/lynxx-ebpf` against a live kernel; verify
  retransmit counters move when triggering retransmits with `tc qdisc`
  netem loss on a loopback flow.
