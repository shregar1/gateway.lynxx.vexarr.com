//! PROXY protocol v1/v2 IPv4 — `src/core/ngx_proxy_protocol.c`

use crate::inet::{ngx_inet_addr_len, INADDR_NONE};
use crate::parse::ngx_atoi_ptr;

#[inline(always)]
unsafe fn v1_prefix_eq(p: *const u8) -> bool {
    core::ptr::read_unaligned(p.cast::<u64>()) == u64::from_le_bytes(*b"PROXY TC")
        && *p.add(8) == b'P'
        && *p.add(9) == b'4'
        && *p.add(10) == b' '
}

pub const NGX_OK: i32 = 0;
pub const NGX_ERROR: i32 = -1;

const V1_PREFIX: &[u8] = b"PROXY TCP4 ";
const V1_PREFIX_LEN: usize = V1_PREFIX.len();

const HDR: u32 = u32::from_le_bytes([0x21, 0x11, 0x00, 0x0c]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyV2Inet {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

const V2_SIG0: u64 = u64::from_le_bytes([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51]);
const V2_SIG1: u32 = u32::from_le_bytes([0x55, 0x49, 0x54, 0x0a]);

/// Parse PROXY v2 header with IPv4 STREAM PROXY command (`ngx_proxy_protocol_v2_read` inet path).
#[inline(always)]
pub fn ngx_proxy_protocol_v2_parse_inet(buf: &[u8], out: &mut ProxyV2Inet) -> i32 {
    if buf.len() < 28 {
        return NGX_ERROR;
    }
    unsafe {
        let p = buf.as_ptr();
        if (p as *const u64).read_unaligned() != V2_SIG0
            || (p.add(8) as *const u32).read_unaligned() != V2_SIG1
            || (p.add(12) as *const u32).read_unaligned() != HDR
        {
            return NGX_ERROR;
        }

        out.src_addr = (p.add(16) as *const u32).read_unaligned();
        out.dst_addr = (p.add(20) as *const u32).read_unaligned();
        out.src_port = u16::from_be((p.add(24) as *const u16).read_unaligned());
        out.dst_port = u16::from_be((p.add(26) as *const u16).read_unaligned());
    }
    NGX_OK
}

/// Parse PROXY v1 `PROXY TCP4 src dst sport dport` line.
#[inline(always)]
pub fn ngx_proxy_protocol_v1_parse_inet(buf: &[u8], out: &mut ProxyV2Inet) -> i32 {
    if buf.len() < V1_PREFIX_LEN + 16 {
        return NGX_ERROR;
    }
    unsafe {
        let p0 = buf.as_ptr();
        if !v1_prefix_eq(p0) {
            return NGX_ERROR;
        }
        let end = p0.add(buf.len());
        let mut p = p0.add(V1_PREFIX_LEN);
        let mut start = p;

        while p < end && *p != b' ' {
            p = p.add(1);
        }
        if p == start || p >= end {
            return NGX_ERROR;
        }
        let src = ngx_inet_addr_len(start, p.offset_from(start) as usize);
        if src == INADDR_NONE {
            return NGX_ERROR;
        }
        p = p.add(1);
        start = p;

        while p < end && *p != b' ' {
            p = p.add(1);
        }
        if p == start || p >= end {
            return NGX_ERROR;
        }
        let dst = ngx_inet_addr_len(start, p.offset_from(start) as usize);
        if dst == INADDR_NONE {
            return NGX_ERROR;
        }
        p = p.add(1);
        start = p;

        while p < end && *p != b' ' {
            p = p.add(1);
        }
        if p == start {
            return NGX_ERROR;
        }
        let n = p.offset_from(start) as usize;
        let port = ngx_atoi_ptr(start, n);
        if port < 0 || port > 65535 {
            return NGX_ERROR;
        }
        let sp = port as u16;
        p = p.add(1);
        start = p;

        while p < end && *p != b'\r' && *p != b'\n' {
            p = p.add(1);
        }
        if p == start {
            return NGX_ERROR;
        }
        let n = p.offset_from(start) as usize;
        let port = ngx_atoi_ptr(start, n);
        if port < 0 || port > 65535 {
            return NGX_ERROR;
        }
        let dp = port as u16;

        out.src_addr = src;
        out.dst_addr = dst;
        out.src_port = sp;
        out.dst_port = dp;
    }
    NGX_OK
}
