//! `ngx_unescape_uri()` — `src/core/ngx_string.c` (`NGX_UNESCAPE_URI`).

pub const NGX_UNESCAPE_URI: u32 = 1;

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

#[inline(always)]
fn hex_val(c: u8) -> Option<u8> {
    let v = HEX[c as usize];
    if v == 255 {
        None
    } else {
        Some(v)
    }
}

/// Unescape percent-encoding; returns bytes written. Stops at `?` when `uri` mode.
#[inline(always)]
pub fn ngx_unescape_uri(dst: &mut [u8], src: &[u8], uri: bool) -> usize {
    let mut d = 0usize;
    let mut s = 0usize;
    let mut state = 0u8;
    let mut decoded = 0u8;

    while s < src.len() {
        if state == 0 {
            let start = s;
            while s < src.len() {
                let ch = src[s];
                if ch == b'%' {
                    break;
                }
                if uri && ch == b'?' {
                    dst[d] = ch;
                    return d + 1;
                }
                s += 1;
            }
            if s > start {
                let run = &src[start..s];
                dst[d..d + run.len()].copy_from_slice(run);
                d += run.len();
            }
            if s >= src.len() {
                break;
            }
            state = 1;
            s += 1;
            continue;
        }

        let ch = src[s];
        s += 1;

        if state == 1 {
            if let Some(v) = hex_val(ch) {
                decoded = v;
                state = 2;
            } else {
                state = 0;
                dst[d] = ch;
                d += 1;
            }
        } else {
            state = 0;
            if let Some(v) = hex_val(ch) {
                let out = (decoded << 4) | v;
                if uri && out == b'?' {
                    dst[d] = out;
                    return d + 1;
                }
                dst[d] = out;
                d += 1;
            }
        }
    }

    d
}
