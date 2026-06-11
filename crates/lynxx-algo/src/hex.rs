//! `ngx_hextoi()` / `ngx_hex_dump()` — `src/core/ngx_string.c`

use crate::parse::NGX_ERROR;

const MAX_INT: i64 = i64::MAX;

const HEX_DUMP: &[u8; 16] = b"0123456789abcdef";

const fn byte_hex_u16() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        let hi = HEX_DUMP[(b >> 4) as usize];
        let lo = HEX_DUMP[(b & 0x0f) as usize];
        t[i] = hi as u16 | ((lo as u16) << 8);
        i += 1;
    }
    t
}

const BYTE_HEX: [u16; 256] = byte_hex_u16();

const fn hex_lut() -> [u8; 256] {
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

const HEX: [u8; 256] = hex_lut();

/// Parse hexadecimal integer (`ngx_hextoi`).
#[inline(always)]
pub fn ngx_hextoi(line: &[u8]) -> isize {
    if line.is_empty() {
        return NGX_ERROR;
    }
    if line.len() <= 16 {
        let mut value: isize = 0;
        for &c in line {
            let d = HEX[c as usize];
            if d == 255 {
                return NGX_ERROR;
            }
            value = value * 16 + d as isize;
        }
        return value;
    }
    let cutoff = (MAX_INT / 16) as isize;
    let mut value: isize = 0;
    for &c in line {
        if value > cutoff {
            return NGX_ERROR;
        }
        let d = HEX[c as usize];
        if d == 255 {
            return NGX_ERROR;
        }
        value = value.wrapping_mul(16).wrapping_add(d as isize);
    }
    value
}

/// Lowercase hex dump (`ngx_hex_dump`); returns bytes written.
#[inline(always)]
pub fn ngx_hex_dump(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len();
    if dst.len() < n * 2 {
        return 0;
    }
    unsafe {
        let mut d = dst.as_mut_ptr();
        let mut s = src.as_ptr();
        let end = s.add(n);
        while s.add(16) <= end {
            (d as *mut u16).write_unaligned(BYTE_HEX[*s as usize]);
            (d.add(2) as *mut u16).write_unaligned(BYTE_HEX[*s.add(1) as usize]);
            (d.add(4) as *mut u16).write_unaligned(BYTE_HEX[*s.add(2) as usize]);
            (d.add(6) as *mut u16).write_unaligned(BYTE_HEX[*s.add(3) as usize]);
            (d.add(8) as *mut u16).write_unaligned(BYTE_HEX[*s.add(4) as usize]);
            (d.add(10) as *mut u16).write_unaligned(BYTE_HEX[*s.add(5) as usize]);
            (d.add(12) as *mut u16).write_unaligned(BYTE_HEX[*s.add(6) as usize]);
            (d.add(14) as *mut u16).write_unaligned(BYTE_HEX[*s.add(7) as usize]);
            (d.add(16) as *mut u16).write_unaligned(BYTE_HEX[*s.add(8) as usize]);
            (d.add(18) as *mut u16).write_unaligned(BYTE_HEX[*s.add(9) as usize]);
            (d.add(20) as *mut u16).write_unaligned(BYTE_HEX[*s.add(10) as usize]);
            (d.add(22) as *mut u16).write_unaligned(BYTE_HEX[*s.add(11) as usize]);
            (d.add(24) as *mut u16).write_unaligned(BYTE_HEX[*s.add(12) as usize]);
            (d.add(26) as *mut u16).write_unaligned(BYTE_HEX[*s.add(13) as usize]);
            (d.add(28) as *mut u16).write_unaligned(BYTE_HEX[*s.add(14) as usize]);
            (d.add(30) as *mut u16).write_unaligned(BYTE_HEX[*s.add(15) as usize]);
            d = d.add(32);
            s = s.add(16);
        }
        while s < end {
            (d as *mut u16).write_unaligned(BYTE_HEX[*s as usize]);
            d = d.add(2);
            s = s.add(1);
        }
        d.offset_from(dst.as_ptr()) as usize
    }
}
