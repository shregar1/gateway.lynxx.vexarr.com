//! `ngx_escape_uri()` — `src/core/ngx_string.c` (table-driven escape / count).

const HEX: &[u8; 16] = b"0123456789ABCDEF";

const fn hex_tables() -> ([u8; 256], [u8; 256]) {
    let mut hi = [0u8; 256];
    let mut lo = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        hi[i] = HEX[i >> 4] as u8;
        lo[i] = HEX[i & 0x0f] as u8;
        i += 1;
    }
    (hi, lo)
}

const HEX_HI: [u8; 256] = hex_tables().0;
const HEX_LO: [u8; 256] = hex_tables().1;

/// `NGX_ESCAPE_URI` bitmap (`uri[]` in `ngx_string.c`).
pub const URI_MAP: [u32; 8] = [
    0xffff_ffff,
    0xd000_002d,
    0x5000_0000,
    0xb800_0001,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

const fn bit_escape(map: &[u32; 8], ch: usize) -> bool {
    (map[ch >> 5] & (1u32 << (ch & 31))) != 0
}

const fn make_lut(map: &[u32; 8]) -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = bit_escape(map, i);
        i += 1;
    }
    t
}

pub const ESCAPE_URI_LUT: [bool; 256] = make_lut(&URI_MAP);

/// `args[]` — `NGX_ESCAPE_ARGS` in `ngx_string.c`.
pub const ARGS_MAP: [u32; 8] = [
    0xffff_ffff,
    0xd800_086d,
    0x5000_0000,
    0xb800_0001,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

pub const ESCAPE_ARGS_LUT: [bool; 256] = make_lut(&ARGS_MAP);

/// `uri_component[]` — `NGX_ESCAPE_URI_COMPONENT`.
pub const URI_COMPONENT_MAP: [u32; 8] = [
    0xffff_ffff,
    0xfc00_9fff,
    0x7800_0001,
    0xb800_0001,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

pub const ESCAPE_URI_COMPONENT_LUT: [bool; 256] = make_lut(&URI_COMPONENT_MAP);

const fn make_count_lut(map: &[u32; 8]) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = bit_escape(map, i) as u8;
        i += 1;
    }
    t
}

const URI_COUNT_LUT: [u8; 256] = make_count_lut(&URI_MAP);
const ARGS_COUNT_LUT: [u8; 256] = make_count_lut(&ARGS_MAP);
const URI_COMPONENT_COUNT_LUT: [u8; 256] = make_count_lut(&URI_COMPONENT_MAP);

#[inline(always)]
pub fn ngx_escape_uri_component_count(src: &[u8]) -> usize {
    ngx_escape_count_byte_lut(src, &URI_COMPONENT_COUNT_LUT)
}

#[inline(always)]
pub fn ngx_escape_args_count(src: &[u8]) -> usize {
    ngx_escape_count_byte_lut(src, &ARGS_COUNT_LUT)
}

#[inline(always)]
pub fn ngx_escape_args(dst: &mut [u8], src: &[u8]) -> usize {
    ngx_escape_encode_lut(dst, src, &ARGS_COUNT_LUT)
}

/// Count via precomputed 0/1 byte LUT (faster than per-byte bitmap test; parity with NGINX maps).
#[inline(always)]
fn ngx_escape_count_byte_lut(src: &[u8], lut: &[u8; 256]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    let len = src.len();
    let sp = src.as_ptr();
    unsafe {
        while i + 16 <= len {
            n += *lut.get_unchecked(*sp.add(i) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 1) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 2) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 3) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 4) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 5) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 6) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 7) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 8) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 9) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 10) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 11) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 12) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 13) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 14) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 15) as usize) as usize;
            i += 16;
        }
        while i + 8 <= len {
            n += *lut.get_unchecked(*sp.add(i) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 1) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 2) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 3) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 4) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 5) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 6) as usize) as usize;
            n += *lut.get_unchecked(*sp.add(i + 7) as usize) as usize;
            i += 8;
        }
        while i < len {
            n += *lut.get_unchecked(*sp.add(i) as usize) as usize;
            i += 1;
        }
    }
    n
}

/// Count bytes that need escaping (`dst == NULL` path, `NGX_ESCAPE_URI`).
#[inline(always)]
pub fn ngx_escape_uri_count(src: &[u8]) -> usize {
    ngx_escape_count_byte_lut(src, &URI_COUNT_LUT)
}

/// NGINX-identical encode loop (`ngx_string.c`), byte LUT + hex tables.
#[inline(always)]
fn ngx_escape_encode_lut(dst: &mut [u8], src: &[u8], esc: &[u8; 256]) -> usize {
    let mut w = 0usize;
    let mut i = 0usize;
    let len = src.len();
    let sp = src.as_ptr();
    let dp = dst.as_mut_ptr();
    unsafe {
        while i < len {
            let b = *sp.add(i);
            i += 1;
            if *esc.get_unchecked(b as usize) != 0 {
                *dp.add(w) = b'%';
                *dp.add(w + 1) = *HEX_HI.get_unchecked(b as usize);
                *dp.add(w + 2) = *HEX_LO.get_unchecked(b as usize);
                w += 3;
            } else {
                *dp.add(w) = b;
                w += 1;
            }
        }
    }
    w
}

/// Encode into `dst`; returns number of bytes written (`NGX_ESCAPE_URI`, prefix `%`).
#[inline(always)]
pub fn ngx_escape_uri(dst: &mut [u8], src: &[u8]) -> usize {
    ngx_escape_encode_lut(dst, src, &URI_COUNT_LUT)
}
