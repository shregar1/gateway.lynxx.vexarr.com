//! lynxx-ebpf kernel-side BPF programs.
//!
//! Two tracepoints are attached:
//!
//! * `tcp/tcp_retransmit_skb` — fires when the kernel retransmits a TCP
//!   segment. We bump a per-CPU-friendly counter in a `HashMap` keyed by
//!   a packed `(saddr, daddr)` 64-bit value. The userspace daemon polls
//!   this map every second and emits Prometheus counters.
//!
//! * `tcp/tcp_set_state` — fires whenever a TCP connection transitions
//!   states (LISTEN → SYN_SENT → ESTABLISHED → FIN_WAIT_1, etc). We
//!   bump a counter keyed by `(oldstate << 8) | newstate`.
//!
//! V1 caveats:
//!
//! * IPv4 only. The tracepoint format includes both v4 and v6 fields,
//!   but for v1 we treat any non-AF_INET event as key = 0.
//! * The tracepoint context offsets are read using
//!   `TracePointContext::read_at`. Field offsets follow the on-kernel
//!   format string at `/sys/kernel/debug/tracing/events/tcp/<name>/format`
//!   on a 5.8+ kernel. They have been stable for a long time, but if a
//!   future kernel reshuffles them, the read will silently produce
//!   garbage. This is acceptable for v1; CO-RE relocation is a v2 task.
//! * No filtering by gateway PID. The userspace `--gateway-pid` flag is
//!   logged but not yet plumbed through to the BPF side.
//!
//! This file MUST compile to BPF bytecode via bpf-linker on a nightly
//! toolchain. It will not build on the host target.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint, xdp},
    maps::HashMap,
    programs::{TracePointContext, XdpContext},
};
use aya_log_ebpf::info;

/// Maximum tracked (saddr, daddr) flows. 8192 is enough for typical
/// gateway-front workloads; on overflow `insert` returns an error and
/// the retransmit is silently dropped from the metric (it still fires
/// in the kernel of course).
const MAX_FLOW_ENTRIES: u32 = 8192;

/// Counter map for TCP retransmits, keyed by `(saddr << 32) | daddr`
/// (both u32 in network byte order). Value is a monotonically
/// increasing u64 incremented from BPF.
#[map]
static mut RETRANSMITS: HashMap<u64, u64> =
    HashMap::<u64, u64>::with_max_entries(MAX_FLOW_ENTRIES, 0);

/// Counter map for TCP state transitions, keyed by
/// `((oldstate as u32) << 16) | (newstate as u32)`. Both states are
/// `TCP_ESTABLISHED`, `TCP_SYN_SENT`, ... values from
/// `include/net/tcp_states.h`.
#[map]
static mut STATE_TRANSITIONS: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(256, 0);

// ---------------------------------------------------------------------
// tcp_retransmit_skb
// ---------------------------------------------------------------------

/// Tracepoint format (see
/// /sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/format on a
/// recent kernel) — only the offsets we actually read are listed.
///
/// Offsets are from the start of the tracepoint context AFTER the
/// 8-byte common header (aya's `read_at` already accounts for that on
/// most kernels via the same layout the kernel exposes; we use the
/// raw offsets that match the `format` file).
const OFF_SADDR: usize = 8;
const OFF_DADDR: usize = 12;

#[tracepoint]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    match try_tcp_retransmit_skb(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_tcp_retransmit_skb(ctx: &TracePointContext) -> Result<u32, i64> {
    // Both addresses are stored in network byte order in the
    // tracepoint context. We do NOT byteswap here — the userspace
    // side does the formatting. This keeps the BPF program tiny.
    let saddr: u32 = unsafe { ctx.read_at::<u32>(OFF_SADDR).unwrap_or(0) };
    let daddr: u32 = unsafe { ctx.read_at::<u32>(OFF_DADDR).unwrap_or(0) };

    let key: u64 = ((saddr as u64) << 32) | (daddr as u64);

    unsafe {
        let count = RETRANSMITS.get(&key).copied().unwrap_or(0);
        let next = count.wrapping_add(1);
        // BPF_ANY = 0 — insert or update.
        let _ = RETRANSMITS.insert(&key, &next, 0);
    }

    info!(ctx, "tcp_retransmit saddr={:x} daddr={:x}", saddr, daddr);
    Ok(0)
}

// ---------------------------------------------------------------------
// tcp_set_state
// ---------------------------------------------------------------------

/// Field offsets for `tcp/tcp_set_state`. The fields we care about
/// are `oldstate` and `newstate`, both `__u8`, near the end of the
/// context.
const OFF_OLDSTATE: usize = 24;
const OFF_NEWSTATE: usize = 25;

#[tracepoint]
pub fn tcp_set_state(ctx: TracePointContext) -> u32 {
    match try_tcp_set_state(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_tcp_set_state(ctx: &TracePointContext) -> Result<u32, i64> {
    let old: u8 = unsafe { ctx.read_at::<u8>(OFF_OLDSTATE).unwrap_or(0) };
    let new: u8 = unsafe { ctx.read_at::<u8>(OFF_NEWSTATE).unwrap_or(0) };

    let key: u32 = ((old as u32) << 16) | (new as u32);

    unsafe {
        let count = STATE_TRANSITIONS.get(&key).copied().unwrap_or(0);
        let next = count.wrapping_add(1);
        let _ = STATE_TRANSITIONS.insert(&key, &next, 0);
    }

    Ok(0)
}

// ---------------------------------------------------------------------
// xdp_ratelimit — per-IP token-bucket drop at XDP layer
// ---------------------------------------------------------------------
//
// Drops IPv4 packets above a per-source-IP rate budget BEFORE they
// reach the gateway's userspace HTTP stack. This is the Beyond-Kong
// moat: in-kernel rate limiting saves a full trip through epoll +
// tokio + handler + plugin chain for traffic that's destined to be
// rejected anyway.
//
// Steady-state limit: `REFILL_PER_SEC` packets per IP per second.
// Burst (token bucket capacity): `CAPACITY` packets.
//
// V1 caveats:
//   * IPv4 only. v6 is `XDP_PASS` (unaffected).
//   * Hardcoded budget. Userspace can patch the constants via a separate
//     map in v2 (or recompile the program).
//   * Tracks the smallest of source IPs only — a single client behind a
//     CGNAT shares one bucket. Operators who want per-port granularity
//     should add an L4 selector in v2.
//   * The map has a finite size (`MAX_TRACKED_IPS`). On overflow new
//     IPs are passed through (fail-open).

const MAX_TRACKED_IPS: u32 = 65_536;
const CAPACITY: u32 = 1_000;
const REFILL_PER_SEC: u32 = 100;
const NS_PER_SEC: u64 = 1_000_000_000;

/// Token-bucket state per source IPv4 address. `tokens` decrements
/// on every accepted packet; the refill clock advances on every
/// touch.
#[repr(C)]
#[derive(Copy, Clone)]
struct TokenBucket {
    tokens: u32,
    last_refill_ns: u64,
}

/// Per-source-IP bucket map. Key: IPv4 source in network byte order.
#[map]
static mut XDP_BUCKETS: HashMap<u32, TokenBucket> =
    HashMap::<u32, TokenBucket>::with_max_entries(MAX_TRACKED_IPS, 0);

/// Per-source-IP dropped-packet counter. Same key space as XDP_BUCKETS.
/// Userspace polls this map, emits Prometheus counters, and can join
/// against the bucket map to surface "top offenders".
#[map]
static mut XDP_DROPPED: HashMap<u32, u64> =
    HashMap::<u32, u64>::with_max_entries(MAX_TRACKED_IPS, 0);

const ETH_HDR_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0008; // 0x0800 in host byte order, NBO here.

#[xdp]
pub fn lynxx_xdp_ratelimit(ctx: XdpContext) -> u32 {
    try_xdp_ratelimit(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_xdp_ratelimit(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Bounds check: enough for ethernet + minimum IPv4 header (20 B).
    if data + ETH_HDR_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Ethertype is at offset 12. Only handle IPv4.
    // Use read_unaligned: packet field offsets are not guaranteed to satisfy
    // the alignment of u16/u32, and dereferencing a misaligned raw pointer is
    // UB in Rust regardless of what the BPF JIT tolerates at runtime.
    let eth_proto: u16 = unsafe { core::ptr::read_unaligned((data + 12) as *const u16) };
    if eth_proto != ETH_P_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Source IPv4 is at offset 12 inside the IP header.
    let src: u32 =
        unsafe { core::ptr::read_unaligned((data + ETH_HDR_LEN + 12) as *const u32) };

    let now = unsafe { bpf_ktime_get_ns() };

    // TODO(ratelimit-race): this get→mutate→insert is a non-atomic
    // read-modify-write on a plain HashMap. XDP runs concurrently per RX
    // queue/CPU, so two packets from the same source on different CPUs can both
    // read the same token count and the second insert clobbers the first
    // (lost decrement), letting an attacker exceed the per-IP budget by ~#CPUs.
    // Fix is to make the bucket map a PerCpuHashMap (aggregating in userspace)
    // or guard the value with bpf_spin_lock — both require coordinated changes
    // in lynxx-ebpf-userspace and must be validated with the BPF toolchain.
    let mut bucket = unsafe { XDP_BUCKETS.get(&src) }
        .copied()
        .unwrap_or(TokenBucket {
            tokens: CAPACITY,
            last_refill_ns: now,
        });

    // Refill: tokens earned since last touch, capped at CAPACITY.
    let elapsed_ns = now.saturating_sub(bucket.last_refill_ns);
    if elapsed_ns >= NS_PER_SEC {
        let seconds = (elapsed_ns / NS_PER_SEC) as u32;
        let earned = seconds.saturating_mul(REFILL_PER_SEC);
        bucket.tokens = bucket.tokens.saturating_add(earned).min(CAPACITY);
        bucket.last_refill_ns = now;
    }

    if bucket.tokens == 0 {
        // Over budget — drop and bump the per-IP drop counter. The
        // bucket itself doesn't need to be stored back; its tokens
        // stay at 0 implicitly until the next refill window.
        unsafe {
            let prior = XDP_DROPPED.get(&src).copied().unwrap_or(0);
            let _ = XDP_DROPPED.insert(&src, &prior.wrapping_add(1), 0);
        }
        return Ok(xdp_action::XDP_DROP);
    }

    bucket.tokens -= 1;
    unsafe {
        let _ = XDP_BUCKETS.insert(&src, &bucket, 0);
    }
    Ok(xdp_action::XDP_PASS)
}

// ---------------------------------------------------------------------
// no_std plumbing
// ---------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF programs cannot panic; the verifier wouldn't accept it. We
    // park forever — in practice this branch is unreachable because
    // every fallible path above returns `Result<_, i64>`.
    loop {}
}
