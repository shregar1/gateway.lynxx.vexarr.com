//! HTTP/3 QPACK / QUIC variable-length integers — `ngx_http_v3_encode.c`, `ngx_http_v3_parse.c`

pub const NGX_ERROR: isize = -1;

#[inline(always)]
fn varlen_len_only(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// Write QUIC varint at `p` (NGINX `p++` style); `p` must have room for 8 bytes.
#[inline(always)]
unsafe fn encode_varlen_ptr(p: *mut u8, value: u64) -> usize {
    if value <= 63 {
        *p = value as u8;
        return 1;
    }
    if value <= 16_383 {
        *p = 0x40 | ((value >> 8) as u8);
        *p.add(1) = value as u8;
        return 2;
    }
    if value <= 1_073_741_823 {
        *p = 0x80 | ((value >> 24) as u8);
        *p.add(1) = (value >> 16) as u8;
        *p.add(2) = (value >> 8) as u8;
        *p.add(3) = value as u8;
        return 4;
    }
    *p = 0xc0 | ((value >> 56) as u8);
    *p.add(1) = (value >> 48) as u8;
    *p.add(2) = (value >> 40) as u8;
    *p.add(3) = (value >> 32) as u8;
    *p.add(4) = (value >> 24) as u8;
    *p.add(5) = (value >> 16) as u8;
    *p.add(6) = (value >> 8) as u8;
    *p.add(7) = value as u8;
    8
}

/// Encode variable-length integer (`ngx_http_v3_encode_varlen_int`).
/// Returns bytes written, or required length when `dst` is empty.
#[inline(always)]
pub fn ngx_http_v3_encode_varlen_int(dst: &mut [u8], value: u64) -> usize {
    if dst.is_empty() {
        return varlen_len_only(value);
    }
    unsafe { encode_varlen_ptr(dst.as_mut_ptr(), value) }
}

/// Decode one variable-length integer; returns `(value, bytes_consumed)` or `None`.
#[inline(always)]
pub fn ngx_http_v3_decode_varlen_int(src: &[u8]) -> Option<(u64, usize)> {
    if src.is_empty() {
        return None;
    }
    let ch = src[0];
    let mut v = ch as u64;
    if (ch & 0xc0) == 0 {
        return Some((v, 1));
    }
    if src.len() < 2 {
        return None;
    }
    v = (v << 8) + src[1] as u64;
    if (v & 0xc000) == 0x4000 {
        return Some((v & 0x3fff, 2));
    }
    if src.len() < 4 {
        return None;
    }
    v = (v << 8) + src[2] as u64;
    v = (v << 8) + src[3] as u64;
    if (v & 0xc000_0000) == 0x8000_0000 {
        return Some((v & 0x3fff_ffff, 4));
    }
    if src.len() < 8 {
        return None;
    }
    v = (v << 8) + src[4] as u64;
    v = (v << 8) + src[5] as u64;
    v = (v << 8) + src[6] as u64;
    v = (v << 8) + src[7] as u64;
    Some((v & 0x3fff_ffff_ffff_ffff, 8))
}

/// Encode prefix integer (`ngx_http_v3_encode_prefix_int`); `first` is the first output byte (often 0).
#[inline(always)]
pub fn ngx_http_v3_encode_prefix_int(dst: &mut [u8], first: u8, value: u64, prefix: u32) -> usize {
    let thresh = (1u64 << prefix) - 1;
    if value < thresh {
        if dst.is_empty() {
            return 1;
        }
        dst[0] = first | value as u8;
        return 1;
    }
    let mut rem = value - thresh;
    if dst.is_empty() {
        let mut n = 2usize;
        while rem >= 128 {
            rem >>= 7;
            n += 1;
        }
        return n;
    }
    let mut i = 0usize;
    dst[i] = first | thresh as u8;
    i += 1;
    while rem >= 128 {
        dst[i] = 0x80 | (rem as u8);
        rem >>= 7;
        i += 1;
    }
    dst[i] = rem as u8;
    i + 1
}

/// Decode prefix integer; `prefix` bits are in the first byte.
#[inline(always)]
pub fn ngx_http_v3_decode_prefix_int(src: &[u8], prefix: u32) -> Option<(u64, usize)> {
    unsafe { ngx_http_v3_decode_prefix_int_ptr(src.as_ptr(), src.len(), prefix) }
}

/// Pointer API matching NGINX `u_char *` + `len` (`ngx_http_v3_decode_prefix_int`).
#[inline(always)]
pub unsafe fn ngx_http_v3_decode_prefix_int_ptr(
    p: *const u8,
    len: usize,
    prefix: u32,
) -> Option<(u64, usize)> {
    if len == 0 {
        return None;
    }
    let mask = (1u64 << prefix) - 1;
    let mut v = (*p as u64) & mask;
    if v < mask {
        return Some((v, 1));
    }
    let mut i = 1usize;
    let mut shift = 0u32;
    loop {
        if i >= len {
            return None;
        }
        let b = *p.add(i);
        i += 1;
        v += ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((v, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}
