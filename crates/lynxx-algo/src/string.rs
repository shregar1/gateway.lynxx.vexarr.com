//! `ngx_strnstr` — `src/core/ngx_string.c`

/// NGINX-identical bounded substring search (stops on `NUL` in haystack).
#[inline]
pub fn ngx_strnstr(haystack: &[u8], needle: &str) -> Option<usize> {
    ngx_strnstr_bytes(haystack, needle.as_bytes())
}

/// Same as [`ngx_strnstr`] with a byte needle.
#[inline]
pub fn ngx_strnstr_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.is_empty() {
        return None;
    }

    let c2 = needle[0];
    let tail = &needle[1..];
    let n = tail.len();
    let limit = nul_limit(haystack);
    if limit == 0 {
        return None;
    }
    let hay = &haystack[..limit];

    if hay.len() >= 64 && n > 0 {
        return strnstr_memchr(hay, c2, tail);
    }

    strnstr_linear(hay, c2, tail, n)
}

#[inline(always)]
fn nul_limit(hay: &[u8]) -> usize {
    const LO: usize = 0x0101_0101_0101_0101;
    const HI: usize = 0x8080_8080_8080_8080;
    let mut i = 0usize;
    let len = hay.len();
    while i + 8 <= len {
        let w = unsafe { std::ptr::read_unaligned(hay.as_ptr().add(i) as *const usize) };
        let z = (w.wrapping_sub(LO)) & !w & HI;
        if z != 0 {
            for j in 0..8 {
                if hay[i + j] == 0 {
                    return i + j;
                }
            }
        }
        i += 8;
    }
    while i < len {
        if hay[i] == 0 {
            return i;
        }
        i += 1;
    }
    len
}

#[inline(always)]
fn strnstr_linear(hay: &[u8], c2: u8, tail: &[u8], n: usize) -> Option<usize> {
    let len = hay.len();
    let mut i = 0usize;
    while i < len {
        let c1 = unsafe { *hay.get_unchecked(i) };
        if c1 == c2 {
            let after = i + 1;
            if n <= len - after && tail_eq(unsafe { hay.get_unchecked(after..) }, tail) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[inline]
fn strnstr_memchr(hay: &[u8], c2: u8, tail: &[u8]) -> Option<usize> {
    let n = tail.len();
    let len = hay.len();
    let mut i = 0usize;

    while i < len {
        let slice = unsafe { hay.get_unchecked(i..) };
        let rel = match memchr::memchr(c2, slice) {
            Some(r) => r,
            None => return None,
        };
        let pos = i + rel;
        let after = pos + 1;
        if n <= len - after && tail_eq(unsafe { hay.get_unchecked(after..) }, tail) {
            return Some(pos);
        }
        i = pos + 1;
    }
    None
}

#[inline(always)]
fn tail_eq(hay: &[u8], tail: &[u8]) -> bool {
    let n = tail.len();
    if hay.len() < n {
        return false;
    }
    if n == 0 {
        return true;
    }
    if n <= 8 {
        let mut x = 0u64;
        let mut y = 0u64;
        for i in 0..n {
            x |= (hay[i] as u64) << (i * 8);
            y |= (tail[i] as u64) << (i * 8);
        }
        return x == y;
    }
    hay[..n] == *tail
}
