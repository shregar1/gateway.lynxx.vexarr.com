//! `ngx_utf8_decode()` — `src/core/ngx_string.c`

/// Decode 2+ byte UTF-8 sequence; advances `*p` on success paths per NGINX.
#[inline(always)]
pub unsafe fn ngx_utf8_decode(p: &mut *const u8, n: usize) -> u32 {
    let mut u = *(*p) as u32;
    let len: usize;
    let valid: u32;

    if u >= 0xf8 {
        *p = p.add(1);
        return 0xffff_ffff;
    } else if u >= 0xf0 {
        u &= 0x07;
        valid = 0xffff;
        len = 3;
    } else if u >= 0xe0 {
        u &= 0x0f;
        valid = 0x7ff;
        len = 2;
    } else if u >= 0xc2 {
        u &= 0x1f;
        valid = 0x7f;
        len = 1;
    } else {
        *p = p.add(1);
        return 0xffff_ffff;
    }

    if n - 1 < len {
        return 0xffff_fffe;
    }

    *p = p.add(1);

    match len {
        1 => {
            let i = *(*p) as u32;
            *p = p.add(1);
            if i < 0x80 {
                return 0xffff_ffff;
            }
            u = (u << 6) | (i & 0x3f);
        }
        2 => {
            let b1 = *(*p) as u32;
            let b2 = *(*p).add(1) as u32;
            *p = p.add(2);
            if b1 < 0x80 || b2 < 0x80 {
                return 0xffff_ffff;
            }
            u = (u << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
        }
        _ => {
            let b1 = *(*p) as u32;
            let b2 = *(*p).add(1) as u32;
            let b3 = *(*p).add(2) as u32;
            *p = p.add(3);
            if b1 < 0x80 || b2 < 0x80 || b3 < 0x80 {
                return 0xffff_ffff;
            }
            u = (u << 18)
                | ((b1 & 0x3f) << 12)
                | ((b2 & 0x3f) << 6)
                | (b3 & 0x3f);
        }
    }

    if u > valid {
        u
    } else {
        0xffff_ffff
    }
}

/// Inline 3-byte UTF-8 (lead `0xe0..=0xef`) when continuations look valid.
#[inline(always)]
unsafe fn try_utf8_3(p: *const u8, end: *const u8) -> Option<(*const u8, u32)> {
    if p.add(3) > end {
        return None;
    }
    let b0 = *p as u32;
    if b0 < 0xe0 || b0 >= 0xf0 {
        return None;
    }
    let b1 = *p.add(1) as u32;
    let b2 = *p.add(2) as u32;
    if b1 < 0x80 || b2 < 0x80 {
        return None;
    }
    let u = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
    if u > 0x7ff {
        Some((p.add(3), u))
    } else {
        None
    }
}

/// Scan `data` and count successfully decoded multibyte codepoints (bench driver).
#[inline(always)]
pub unsafe fn ngx_utf8_decode_scan(data: &[u8]) -> usize {
    let mut p = data.as_ptr();
    let end = unsafe { p.add(data.len()) };
    let mut count = 0usize;
    while p < end {
        let c = *p;
        if c < 0x80 {
            let mut q = unsafe { p.add(1) };
            while q.add(8) <= end {
                let chunk = unsafe { core::ptr::read_unaligned(q as *const u64) };
                if chunk & 0x8080_8080_8080_8080 != 0 {
                    break;
                }
                q = unsafe { q.add(8) };
            }
            while q < end && *q < 0x80 {
                q = unsafe { q.add(1) };
            }
            p = q;
            continue;
        }
        if let Some((np, _)) = try_utf8_3(p, end) {
            count += 1;
            p = np;
            continue;
        }
        let n = end as usize - p as usize;
        let save = p;
        let u = ngx_utf8_decode(&mut p, n);
        if u <= 0x10_ffff && u >= 0x80 {
            count += 1;
        } else if u == 0xffff_fffe {
            break;
        } else {
            p = unsafe { save.add(1) };
        }
    }
    count
}
