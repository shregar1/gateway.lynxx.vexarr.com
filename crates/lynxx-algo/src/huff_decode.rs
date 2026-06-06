//! `ngx_http_huff_decode()` — `src/http/ngx_http_huff_decode.c` (RFC 7541 HPACK)

pub const NGX_OK: i32 = 0;
pub const NGX_ERROR: i32 = -1;

include!(concat!(env!("OUT_DIR"), "/huff_tables.rs"));
include!(concat!(env!("OUT_DIR"), "/huff_fixtures.rs"));

#[inline(always)]
unsafe fn dec_byte_fast(state: &mut u8, ch: u8, dst: &mut *mut u8) -> i32 {
    let w = *HUFF_DECODE_BYTE.get_unchecked(((*state as usize) << 8) | ch as usize);
    if w & 1 == 0 {
        return NGX_ERROR;
    }
    *state = ((w >> 1) & 0xff) as u8;
    match (w >> 9) & 3 {
        0 => {}
        1 => {
            **dst = ((w >> 11) & 0xff) as u8;
            *dst = (*dst).add(1);
        }
        _ => {
            **dst = ((w >> 11) & 0xff) as u8;
            *dst = (*dst).add(1);
            **dst = ((w >> 19) & 0xff) as u8;
            *dst = (*dst).add(1);
        }
    }
    NGX_OK
}

#[inline(always)]
unsafe fn dec_nibble_last(state: &mut u8, ending: &mut u8, bits: u32, dst: &mut *mut u8) -> i32 {
    let w = *HUFF_DECODE_FLAT.get_unchecked(((*state as usize) << 4) | bits as usize);
    let next = (w & 0xff) as u8;
    if next == *state {
        return NGX_ERROR;
    }
    if w & 0xff00 != 0 {
        **dst = ((w >> 16) & 0xff) as u8;
        *dst = (*dst).add(1);
    }
    *ending = ((w >> 24) & 0xff) as u8;
    *state = next;
    NGX_OK
}

#[inline(always)]
unsafe fn dec_nibble_bounded(
    state: &mut u8,
    ending: &mut u8,
    bits: u32,
    dst: &mut *mut u8,
    dst_end: *mut u8,
) -> i32 {
    let w = *HUFF_DECODE_FLAT.get_unchecked(((*state as usize) << 4) | bits as usize);
    let next = (w & 0xff) as u8;
    if next == *state {
        return NGX_ERROR;
    }
    if w & 0xff00 != 0 {
        if *dst >= dst_end {
            return NGX_ERROR;
        }
        **dst = ((w >> 16) & 0xff) as u8;
        *dst = (*dst).add(1);
    }
    *ending = ((w >> 24) & 0xff) as u8;
    *state = next;
    NGX_OK
}

/// Huffman-decode with NGINX `u_char **` destination pointer (`ngx_http_huff_decode`).
#[inline(always)]
pub unsafe fn ngx_http_huff_decode_ptr(
    state: &mut u8,
    src: *const u8,
    len: usize,
    dst: &mut *mut u8,
    last: bool,
) -> i32 {
    let end = src.add(len);
    let mut p = src;

    if !last {
        while p.add(8) <= end {
            if dec_byte_fast(state, *p, dst) != NGX_OK
                || dec_byte_fast(state, *p.add(1), dst) != NGX_OK
                || dec_byte_fast(state, *p.add(2), dst) != NGX_OK
                || dec_byte_fast(state, *p.add(3), dst) != NGX_OK
                || dec_byte_fast(state, *p.add(4), dst) != NGX_OK
                || dec_byte_fast(state, *p.add(5), dst) != NGX_OK
                || dec_byte_fast(state, *p.add(6), dst) != NGX_OK
                || dec_byte_fast(state, *p.add(7), dst) != NGX_OK
            {
                return NGX_ERROR;
            }
            p = p.add(8);
        }
        while p != end {
            if dec_byte_fast(state, *p, dst) != NGX_OK {
                return NGX_ERROR;
            }
            p = p.add(1);
        }
        return NGX_OK;
    }

    let mut ending = 1u8;
    while p != end {
        let ch = *p;
        p = p.add(1);
        if dec_nibble_last(state, &mut ending, (ch >> 4) as u32, dst) != NGX_OK {
            return NGX_ERROR;
        }
        if dec_nibble_last(state, &mut ending, (ch & 0xf) as u32, dst) != NGX_OK {
            return NGX_ERROR;
        }
    }

    if ending == 0 {
        return NGX_ERROR;
    }
    *state = 0;
    NGX_OK
}

/// Slice wrapper: decode into prefix of `dst` (`ngx_http_huff_decode`).
#[inline(always)]
pub fn ngx_http_huff_decode(
    state: &mut u8,
    src: &[u8],
    dst: &mut [u8],
    last: bool,
) -> i32 {
    let mut dp = dst.as_mut_ptr();
    let dst_end = unsafe { dp.add(dst.len()) };

    if !last {
        unsafe {
            for &ch in src {
                if dec_byte_fast(state, ch, &mut dp) != NGX_OK {
                    return NGX_ERROR;
                }
            }
        }
        return NGX_OK;
    }

    let mut ending = 1u8;
    unsafe {
        for &ch in src {
            if dec_nibble_bounded(state, &mut ending, (ch >> 4) as u32, &mut dp, dst_end)
                != NGX_OK
            {
                return NGX_ERROR;
            }
            if dec_nibble_bounded(state, &mut ending, (ch & 0xf) as u32, &mut dp, dst_end)
                != NGX_OK
            {
                return NGX_ERROR;
            }
        }
        if ending == 0 {
            return NGX_ERROR;
        }
        *state = 0;
    }
    NGX_OK
}
