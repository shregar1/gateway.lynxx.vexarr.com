//! `ngx_encode_base64()` / `ngx_decode_base64()` — `src/core/ngx_string.c`

use crate::parse::NGX_ERROR;

const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const B64_URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const B64_INVALID: u8 = 77;

const fn b64_decode_lut(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut t = [B64_INVALID; 256];
    let mut i = 0usize;
    while i < 64 {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t
}

const B64_DEC: [u8; 256] = b64_decode_lut(B64);

const B64_URL_DEC: [u8; 256] = b64_decode_lut(B64_URL);

/// NGINX-shaped encode loop (`ngx_string.c`); LLVM autovecs the `left > 2` path well.
#[inline(always)]
unsafe fn encode_internal(dst: &mut [u8], src: &[u8], basis: &[u8; 64], padding: bool) -> usize {
    let mut d = dst.as_mut_ptr();
    let mut s = src.as_ptr();
    let mut left = src.len();

    while left > 2 {
        let b0 = *s;
        let b1 = *s.add(1);
        let b2 = *s.add(2);
        *d = *basis.get_unchecked((b0 >> 2) as usize);
        *d.add(1) = *basis.get_unchecked((((b0 & 3) << 4) | (b1 >> 4)) as usize);
        *d.add(2) = *basis.get_unchecked((((b1 & 0x0f) << 2) | (b2 >> 6)) as usize);
        *d.add(3) = *basis.get_unchecked((b2 & 0x3f) as usize);
        s = s.add(3);
        d = d.add(4);
        left -= 3;
    }

    if left == 0 {
        return d.offset_from(dst.as_ptr()) as usize;
    }

    *d = *basis.get_unchecked((*s >> 2) as usize);
    d = d.add(1);

    if left == 1 {
        *d = *basis.get_unchecked(((*s & 3) << 4) as usize);
        if padding {
            *d.add(1) = b'=';
            *d.add(2) = b'=';
            return d.offset_from(dst.as_ptr()) as usize + 3;
        }
        return d.offset_from(dst.as_ptr()) as usize + 1;
    }

    let b1 = *s.add(1);
    *d = *basis.get_unchecked((((*s & 3) << 4) | (b1 >> 4)) as usize);
    *d.add(1) = *basis.get_unchecked(((b1 & 0x0f) << 2) as usize);
    if padding {
        *d.add(2) = b'=';
        return d.offset_from(dst.as_ptr()) as usize + 3;
    }
    d.offset_from(dst.as_ptr()) as usize + 2
}

/// Standard base64 encode with `=` padding (`ngx_encode_base64`).
#[inline(always)]
pub fn ngx_encode_base64(dst: &mut [u8], src: &[u8]) -> usize {
    unsafe { encode_internal(dst, src, B64, true) }
}

/// URL-safe base64 encode without padding (`ngx_encode_base64url`).
#[inline(always)]
pub fn ngx_encode_base64url(dst: &mut [u8], src: &[u8]) -> usize {
    unsafe { encode_internal(dst, src, B64_URL, false) }
}

#[inline(always)]
fn decode_internal(dst: &mut [u8], src: &[u8], lut: &[u8; 256]) -> isize {
    unsafe {
        let mut s = src.as_ptr();
        let end = s.add(src.len());
        let start = s;
        while s < end {
            let c = *s;
            if c == b'=' {
                break;
            }
            if *lut.get_unchecked(c as usize) == B64_INVALID {
                return NGX_ERROR;
            }
            s = s.add(1);
        }
        let len = s.offset_from(start) as usize;
        if len % 4 == 1 {
            return NGX_ERROR;
        }

        let mut d = dst.as_mut_ptr();
        s = start;
        let mut left = len;

        while left > 3 {
            let a = *lut.get_unchecked(*s as usize);
            let b = *lut.get_unchecked(*s.add(1) as usize);
            let c = *lut.get_unchecked(*s.add(2) as usize);
            let e = *lut.get_unchecked(*s.add(3) as usize);
            *d = (a << 2) | (b >> 4);
            *d.add(1) = (b << 4) | (c >> 2);
            *d.add(2) = (c << 6) | e;
            d = d.add(3);
            s = s.add(4);
            left -= 4;
        }

        if left > 1 {
            let a = *lut.get_unchecked(*s as usize);
            let b = *lut.get_unchecked(*s.add(1) as usize);
            *d = (a << 2) | (b >> 4);
            d = d.add(1);
        }

        if left > 2 {
            let b = *lut.get_unchecked(*s.add(1) as usize);
            let c = *lut.get_unchecked(*s.add(2) as usize);
            *d = (b << 4) | (c >> 2);
            d = d.add(1);
        }

        d.offset_from(dst.as_ptr()) as isize
    }
}

/// Decode base64 (`ngx_decode_base64`); returns bytes written or `NGX_ERROR`.
#[inline(always)]
pub fn ngx_decode_base64(dst: &mut [u8], src: &[u8]) -> isize {
    decode_internal(dst, src, &B64_DEC)
}

/// Decode URL-safe base64 (`ngx_decode_base64url`).
#[inline(always)]
pub fn ngx_decode_base64url(dst: &mut [u8], src: &[u8]) -> isize {
    decode_internal(dst, src, &B64_URL_DEC)
}
