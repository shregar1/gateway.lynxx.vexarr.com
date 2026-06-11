//! `ngx_inet_addr()` / `ngx_inet6_addr()` — `src/core/ngx_inet.c`

pub const INADDR_NONE: u32 = 0xffff_ffff;
pub const NGX_OK: i32 = 0;
pub const NGX_INET_ERROR: i32 = -1;

const fn hex_digit_lut() -> [u8; 256] {
    let mut t = [255u8; 256];
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = c - b'0';
        c += 1;
    }
    let mut c = b'a';
    while c <= b'f' {
        t[c as usize] = c - b'a' + 10;
        t[(c - 32) as usize] = t[c as usize];
        c += 1;
    }
    t
}

const HEX: [u8; 256] = hex_digit_lut();

const fn dec_digit_lut() -> [u8; 256] {
    let mut t = [255u8; 256];
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = c - b'0';
        c += 1;
    }
    t
}

const DEC: [u8; 256] = dec_digit_lut();

/// Parse IPv4 dotted-quad; returns network byte order or `INADDR_NONE`.
#[inline(always)]
pub fn ngx_inet_addr(text: &[u8]) -> u32 {
    unsafe { ngx_inet_addr_len(text.as_ptr(), text.len()) }
}

#[inline(always)]
pub(crate) unsafe fn ngx_inet_addr_len(p: *const u8, len: usize) -> u32 {
    let mut addr = 0u32;
    let mut octet = 0u32;
    let mut dots = 0u32;
    let end = p.add(len);
    let mut q = p;

    while q < end {
        let c = *q;
        q = q.add(1);
        let d = *DEC.get_unchecked(c as usize);
        if d != 255 {
            octet = octet.wrapping_mul(10).wrapping_add(d as u32);
            if octet > 255 {
                return INADDR_NONE;
            }
        } else if c == b'.' {
            addr = (addr << 8) | octet;
            octet = 0;
            dots += 1;
        } else {
            return INADDR_NONE;
        }
    }

    if dots == 3 {
        u32::from_be((addr << 8) | octet)
    } else {
        INADDR_NONE
    }
}

/// Parse IPv6 text into 16-byte address (`ngx_inet6_addr`).
#[inline(always)]
pub fn ngx_inet6_addr(text: &[u8], addr: &mut [u8; 16]) -> i32 {
    if text.is_empty() {
        return NGX_INET_ERROR;
    }

    let mut len = text.len();
    let mut p = text.as_ptr();
    let mut ap = addr.as_mut_ptr();

    let mut zero: *mut u8 = core::ptr::null_mut();
    let mut digit: *const u8 = core::ptr::null();
    let mut len4 = 0usize;
    let mut nibbles = 0u32;
    let mut word = 0u32;
    let mut n = 8u32;

    if unsafe { *p } == b':' {
        p = unsafe { p.add(1) };
        len -= 1;
    }

    while len != 0 {
        let c = unsafe { *p };
        p = unsafe { p.add(1) };

        if c == b':' {
            if nibbles > 0 {
                digit = p;
                len4 = len;
                unsafe {
                    *ap = (word >> 8) as u8;
                    ap = ap.add(1);
                    *ap = (word & 0xff) as u8;
                    ap = ap.add(1);
                }
                if n > 1 {
                    n -= 1;
                    nibbles = 0;
                    word = 0;
                } else {
                    return NGX_INET_ERROR;
                }
            } else if zero.is_null() {
                digit = p;
                len4 = len;
                zero = ap;
            } else {
                return NGX_INET_ERROR;
            }
        } else if c == b'.' && nibbles > 0 {
            if n < 2 || digit.is_null() {
                return NGX_INET_ERROR;
            }
            let v4 = unsafe { ngx_inet_addr_len(digit, len4 - 1) };
            if v4 == INADDR_NONE {
                return NGX_INET_ERROR;
            }
            unsafe {
                *ap = (v4 >> 24) as u8;
                ap = ap.add(1);
                *ap = (v4 >> 16) as u8;
                ap = ap.add(1);
            }
            n -= 1;
            break;
        } else {
            nibbles += 1;
            if nibbles > 4 {
                return NGX_INET_ERROR;
            }

            let d = HEX[c as usize];
            if d == 255 {
                return NGX_INET_ERROR;
            }
            word = word * 16 + d as u32;
        }

        len -= 1;
    }

    if nibbles == 0 && zero.is_null() {
        return NGX_INET_ERROR;
    }

    unsafe {
        *ap = (word >> 8) as u8;
        ap = ap.add(1);
        *ap = (word & 0xff) as u8;
        ap = ap.add(1);
    }

    n -= 1;
    if n != 0 {
        if !zero.is_null() {
            let nzero = (n as usize) * 2;
            unsafe {
                let mut s = ap.offset(-1);
                let mut d = s.add(nzero);
                loop {
                    *d = *s;
                    if s == zero {
                        break;
                    }
                    s = s.offset(-1);
                    d = d.offset(-1);
                }
                core::ptr::write_bytes(zero, 0, nzero);
            }
            NGX_OK
        } else {
            NGX_INET_ERROR
        }
    } else if zero.is_null() {
        NGX_OK
    } else {
        NGX_INET_ERROR
    }
}
