//! Chunked transfer-encoding (`ngx_http_chunked_filter_module.c`, `ngx_http_parse_chunked`).

const HEX: &[u8; 16] = b"0123456789abcdef";

const fn hex_val_lut() -> [i8; 256] {
    let mut t = [-1i8; 256];
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = (c - b'0') as i8;
        c += 1;
    }
    let mut c = b'a';
    while c <= b'f' {
        t[c as usize] = (c - b'a' + 10) as i8;
        t[(c - 32) as usize] = t[c as usize];
        c += 1;
    }
    t
}

const HEX_VAL: [i8; 256] = hex_val_lut();

const SW_CHUNK_START: u8 = 0;
const SW_CHUNK_SIZE: u8 = 1;
const SW_CHUNK_EXT_ALMOST: u8 = 2;

/// NGINX `ngx_http_chunked_t` size-line states (no extensions/trailers).
#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkedParseCtx {
    pub state: u8,
    pub size: u64,
}

#[inline(always)]
fn hex_val(ch: u8) -> Option<u8> {
    let d = HEX_VAL[ch as usize];
    if d < 0 {
        None
    } else {
        Some(d as u8)
    }
}

/// Byte-at-a-time chunk size line parser (`ngx_http_parse_chunked` size path).
#[inline(always)]
pub fn ngx_http_chunked_parse_byte(ctx: &mut ChunkedParseCtx, ch: u8) -> Option<u64> {
    match ctx.state {
        SW_CHUNK_START => {
            let d = hex_val(ch)?;
            ctx.size = d as u64;
            ctx.state = SW_CHUNK_SIZE;
            None
        }
        SW_CHUNK_SIZE => {
            if let Some(d) = hex_val(ch) {
                if ctx.size > u64::MAX / 16 {
                    return None;
                }
                ctx.size = ctx.size * 16 + d as u64;
                return None;
            }
            if ch != b'\r' {
                return None;
            }
            ctx.state = SW_CHUNK_EXT_ALMOST;
            None
        }
        SW_CHUNK_EXT_ALMOST => {
            if ch != b'\n' {
                return None;
            }
            ctx.state = SW_CHUNK_START;
            Some(ctx.size)
        }
        _ => None,
    }
}

/// Parse concatenated chunk size lines via NGINX-style FSM (byte-at-a-time).
#[inline(always)]
pub fn ngx_http_chunked_parse_stream_fsm(buf: &[u8]) -> Option<(usize, u64)> {
    let mut ctx = ChunkedParseCtx::default();
    let mut count = 0usize;
    let mut sum = 0u64;
    for &ch in buf {
        if let Some(size) = ngx_http_chunked_parse_byte(&mut ctx, ch) {
            sum += size;
            count += 1;
        }
    }
    if ctx.state == SW_CHUNK_START {
        Some((count, sum))
    } else {
        None
    }
}

/// Parse a complete buffer of chunk-size lines (fast path; same result as FSM on full lines).
#[inline(always)]
pub fn ngx_http_chunked_parse_stream(buf: &[u8]) -> Option<(usize, u64)> {
    ngx_http_chunked_parse_buffer(buf)
}

/// Write `"%xO" CRLF` for a non-negative body chunk size; returns bytes written.
#[inline(always)]
pub fn ngx_http_chunked_header(dst: &mut [u8], size: u64) -> usize {
    if size == 0 {
        dst[0] = b'0';
        dst[1] = b'\r';
        dst[2] = b'\n';
        return 3;
    }
    let n = (64 - size.leading_zeros() as usize + 3) / 4;
    let mut i = n;
    let mut v = size;
    while v > 0 {
        i -= 1;
        dst[i] = HEX[(v & 0xf) as usize];
        v >>= 4;
    }
    dst[n] = b'\r';
    dst[n + 1] = b'\n';
    n + 2
}

/// Parse one chunk-size line `HEX\r\n` (no extensions); returns `(size, bytes_consumed)`.
#[inline(always)]
pub fn ngx_http_chunked_parse_line(buf: &[u8]) -> Option<(u64, usize)> {
    unsafe { ngx_http_chunked_parse_line_ptr(buf.as_ptr(), buf.len()) }
}

/// Pointer API — matches NGINX `buf + off, len - off` (`chunked.c`).
#[inline(always)]
pub unsafe fn ngx_http_chunked_parse_line_ptr(ptr: *const u8, len: usize) -> Option<(u64, usize)> {
    if len == 0 {
        return None;
    }
    let d0 = *HEX_VAL.get_unchecked(*ptr as usize);
    if d0 < 0 {
        return None;
    }
    let mut size = d0 as u64;
    let mut i = 1usize;
    while i < len {
        let d = *HEX_VAL.get_unchecked(*ptr.add(i) as usize);
        if d < 0 {
            break;
        }
        if size > u64::MAX / 16 {
            return None;
        }
        size = size * 16 + d as u64;
        i += 1;
    }
    if i + 1 >= len || *ptr.add(i) != b'\r' || *ptr.add(i + 1) != b'\n' {
        return None;
    }
    Some((size, i + 2))
}

/// Scan a buffer of concatenated chunk-size lines; returns count parsed or `None` on error.
#[inline(always)]
pub fn ngx_http_chunked_parse_buffer(buf: &[u8]) -> Option<(usize, u64)> {
    unsafe { ngx_http_chunked_parse_buffer_ptr(buf.as_ptr(), buf.len()) }
}

#[inline(always)]
pub unsafe fn ngx_http_chunked_parse_buffer_ptr(mut ptr: *const u8, len: usize) -> Option<(usize, u64)> {
    let end = ptr.add(len);
    let mut count = 0usize;
    let mut sum = 0u64;
    while ptr < end {
        let rem = end.offset_from(ptr) as usize;
        let (size, n) = ngx_http_chunked_parse_line_ptr(ptr, rem)?;
        sum += size;
        count += 1;
        ptr = ptr.add(n);
    }
    Some((count, sum))
}
