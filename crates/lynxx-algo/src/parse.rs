//! `ngx_atosz` / `ngx_atoi` / `ngx_parse_time` — `ngx_string.c`, `ngx_parse.c`

/// NGINX `NGX_ERROR` for parsers.
pub const NGX_ERROR: isize = -1;

const MAX_INT: i64 = i64::MAX;

const fn digit_lut() -> [u8; 256] {
    let mut t = [255u8; 256];
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = c - b'0';
        c += 1;
    }
    t
}

const DIGIT: [u8; 256] = digit_lut();

/// Fast path for config-sized decimals (≤10 digits never overflow `ssize_t` on 64-bit).
#[inline(always)]
fn ngx_atosz_short(line: &[u8]) -> isize {
    let mut value: isize = 0;
    for &c in line {
        let d = DIGIT[c as usize];
        if d == 255 {
            return NGX_ERROR;
        }
        value = value * 10 + d as isize;
    }
    value
}

#[inline(always)]
fn ngx_atosz_long(line: &[u8]) -> isize {
    let mut n = line.len();
    let cutoff = (usize::MAX / 10) as isize;
    let cutlim = (usize::MAX % 10) as isize;
    let mut value: isize = 0;
    let mut p = line.as_ptr();
    while n != 0 {
        let d = DIGIT[unsafe { *p } as usize];
        if d == 255 {
            return NGX_ERROR;
        }
        if value >= cutoff && (value > cutoff || d as isize > cutlim) {
            return NGX_ERROR;
        }
        value = value.wrapping_mul(10).wrapping_add(d as isize);
        p = unsafe { p.add(1) };
        n -= 1;
    }
    value
}

/// Parse unsigned decimal (`ngx_atosz`) — `ssize_t` loop matches NGINX C.
#[inline(always)]
pub fn ngx_atosz(line: &[u8]) -> isize {
    if line.is_empty() {
        return NGX_ERROR;
    }
    if line.len() <= 10 {
        ngx_atosz_short(line)
    } else {
        ngx_atosz_long(line)
    }
}

#[inline(always)]
fn ngx_atoi_short(line: &[u8]) -> isize {
    unsafe { ngx_atoi_ptr(line.as_ptr(), line.len()) }
}

/// Signed decimal over `len` bytes at `start` (PROXY ports, short fields).
#[inline(always)]
pub unsafe fn ngx_atoi_ptr(mut start: *const u8, len: usize) -> isize {
    if len == 0 {
        return NGX_ERROR;
    }
    let end = start.add(len);
    let mut value: isize = 0;
    while start < end {
        let d = DIGIT[*start as usize];
        if d == 255 {
            return NGX_ERROR;
        }
        value = value * 10 + d as isize;
        start = start.add(1);
    }
    if value > MAX_INT as isize {
        NGX_ERROR
    } else {
        value
    }
}

/// Signed decimal (`ngx_atoi`) — `ssize_t` loop matches NGINX C.
#[inline(always)]
pub fn ngx_atoi(line: &[u8]) -> isize {
    if line.is_empty() {
        return NGX_ERROR;
    }
    if line.len() <= 10 {
        ngx_atoi_short(line)
    } else {
        let mut n = line.len();
        let cutoff = (MAX_INT / 10) as isize;
        let cutlim = (MAX_INT % 10) as isize;
        let mut value: isize = 0;
        let mut p = line.as_ptr();
        while n != 0 {
            let d = DIGIT[unsafe { *p } as usize];
            if d == 255 {
                return NGX_ERROR;
            }
            if value >= cutoff && (value > cutoff || d as isize > cutlim) {
                return NGX_ERROR;
            }
            value = value.wrapping_mul(10).wrapping_add(d as isize);
            p = unsafe { p.add(1) };
            n -= 1;
        }
        value
    }
}

/// Parse size with optional `k`/`m` suffix (`ngx_parse_size`).
#[inline(always)]
pub fn ngx_parse_size(line: &[u8]) -> isize {
    if line.is_empty() {
        return NGX_ERROR;
    }
    let mut len = line.len();
    let last = line[len - 1];
    let (max, scale): (isize, isize) = match last {
        b'K' | b'k' => {
            len -= 1;
            ((usize::MAX / 1024) as isize, 1024)
        }
        b'M' | b'm' => {
            len -= 1;
            ((usize::MAX / (1024 * 1024)) as isize, 1024 * 1024)
        }
        _ => (usize::MAX as isize, 1),
    };
    let prefix = &line[..len];
    let size = if prefix.len() <= 10 {
        ngx_atosz_short(prefix)
    } else {
        ngx_atosz_long(prefix)
    };
    if size == NGX_ERROR || size > max {
        return NGX_ERROR;
    }
    size * scale
}

/// Parse time to milliseconds (`ngx_parse_time`, `is_sec=1` for second resolution).
#[inline]
pub fn ngx_parse_time(line: &[u8], is_sec: bool) -> isize {
    let mut p = 0usize;
    let last = line.len();
    let mut valid = false;
    let mut value: i64 = 0;
    let mut total: i64 = 0;
    let cutoff = MAX_INT / 10;
    let cutlim = (MAX_INT % 10) as u8;
    let mut step = if is_sec { 0u8 } else { 2u8 };
    let mut max: i64;
    let mut scale: i64;

    while p < last {
        let ch = line[p];
        if ch.is_ascii_digit() {
            let d = DIGIT[ch as usize];
            if d == 255 {
                return NGX_ERROR;
            }
            if value >= cutoff && (value > cutoff || d > cutlim) {
                return NGX_ERROR;
            }
            value = value * 10 + d as i64;
            valid = true;
            p += 1;
            continue;
        }

        match ch {
            b'y' if step == 0 => {
                step = 1;
                max = MAX_INT / (60 * 60 * 24 * 365);
                scale = 60 * 60 * 24 * 365;
            }
            b'M' if step < 2 => {
                step = 2;
                max = MAX_INT / (60 * 60 * 24 * 30);
                scale = 60 * 60 * 24 * 30;
            }
            b'w' if step < 3 => {
                step = 3;
                max = MAX_INT / (60 * 60 * 24 * 7);
                scale = 60 * 60 * 24 * 7;
            }
            b'd' if step < 4 => {
                step = 4;
                max = MAX_INT / (60 * 60 * 24);
                scale = 60 * 60 * 24;
            }
            b'h' if step < 5 => {
                step = 5;
                max = MAX_INT / (60 * 60);
                scale = 60 * 60;
            }
            b'm' if p + 1 < last && line[p + 1] == b's' => {
                if is_sec || step >= 8 {
                    return NGX_ERROR;
                }
                p += 1;
                step = 8;
                max = MAX_INT;
                scale = 1;
            }
            b'm' if step < 6 => {
                step = 6;
                max = MAX_INT / 60;
                scale = 60;
            }
            b's' if step < 7 => {
                step = 7;
                max = MAX_INT;
                scale = 1;
            }
            b' ' if step < 7 => {
                step = 9;
                max = MAX_INT;
                scale = 1;
            }
            _ => return NGX_ERROR,
        }

        if step != 8 && !is_sec {
            scale *= 1000;
            max /= 1000;
        }

        if value > max {
            return NGX_ERROR;
        }

        value *= scale;

        if total > MAX_INT - value {
            return NGX_ERROR;
        }

        total += value;
        value = 0;

        p += 1;
        while p < last && line[p] == b' ' {
            p += 1;
        }
    }

    if !valid {
        return NGX_ERROR;
    }

    if !is_sec {
        if value > MAX_INT / 1000 {
            return NGX_ERROR;
        }
        value *= 1000;
    }

    if total > MAX_INT - value {
        return NGX_ERROR;
    }

    (total + value) as isize
}
