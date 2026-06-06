//! `ngx_hash` / `ngx_hash_key` — `src/core/ngx_hash.h`, `ngx_hash.c`

const ASCII_LOWER: [u8; 256] = lower_table();

const fn lower_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let c = i as u8;
        t[i] = if c.is_ascii_uppercase() { c | 0x20 } else { c };
        i += 1;
    }
    t
}

/// `#define ngx_hash(key, c) ((ngx_uint_t) key * 31 + c)`
#[inline(always)]
pub fn ngx_hash(key: usize, c: u8) -> usize {
    key.wrapping_mul(31).wrapping_add(c as usize)
}

const POW31: [usize; 17] = {
    let mut t = [0usize; 17];
    t[0] = 1;
    let mut i = 1;
    while i < 17 {
        t[i] = t[i - 1].wrapping_mul(31);
        i += 1;
    }
    t
};

#[inline(always)]
fn ngx_hash_8(key: usize, b: &[u8; 8]) -> usize {
    key.wrapping_mul(POW31[8])
        .wrapping_add((b[0] as usize).wrapping_mul(POW31[7]))
        .wrapping_add((b[1] as usize).wrapping_mul(POW31[6]))
        .wrapping_add((b[2] as usize).wrapping_mul(POW31[5]))
        .wrapping_add((b[3] as usize).wrapping_mul(POW31[4]))
        .wrapping_add((b[4] as usize).wrapping_mul(POW31[3]))
        .wrapping_add((b[5] as usize).wrapping_mul(POW31[2]))
        .wrapping_add((b[6] as usize).wrapping_mul(POW31[1]))
        .wrapping_add(b[7] as usize)
}

#[inline(always)]
fn ngx_hash_16(mut key: usize, p: *const u8) -> usize {
    key = ngx_hash_8(key, unsafe { &*p.cast::<[u8; 8]>() });
    ngx_hash_8(
        key,
        unsafe { &*p.add(8).cast::<[u8; 8]>() },
    )
}

#[inline(always)]
fn ngx_hash_32(mut key: usize, p: *const u8) -> usize {
    key = ngx_hash_16(key, p);
    ngx_hash_16(key, unsafe { p.add(16) })
}

/// `ngx_hash_key` — same wrapping semantics as NGINX; 32-byte unroll.
#[inline(always)]
pub fn ngx_hash_key(data: &[u8]) -> usize {
    let mut key = 0usize;
    let mut i = 0;
    let len = data.len();
    while i + 32 <= len {
        key = ngx_hash_32(key, unsafe { data.as_ptr().add(i) });
        i += 32;
    }
    while i + 16 <= len {
        key = ngx_hash_16(key, unsafe { data.as_ptr().add(i) });
        i += 16;
    }
    while i + 8 <= len {
        key = ngx_hash_8(key, unsafe { &*data.as_ptr().add(i).cast::<[u8; 8]>() });
        i += 8;
    }
    while i < len {
        key = ngx_hash(key, data[i]);
        i += 1;
    }
    key
}

#[inline(always)]
pub fn ngx_tolower(c: u8) -> u8 {
    if c.is_ascii_uppercase() {
        c | 0x20
    } else {
        c
    }
}

#[inline(always)]
fn ngx_hash_8_lc(key: usize, p: *const u8) -> usize {
    let b = [
        ASCII_LOWER[unsafe { *p } as usize],
        ASCII_LOWER[unsafe { *p.add(1) } as usize],
        ASCII_LOWER[unsafe { *p.add(2) } as usize],
        ASCII_LOWER[unsafe { *p.add(3) } as usize],
        ASCII_LOWER[unsafe { *p.add(4) } as usize],
        ASCII_LOWER[unsafe { *p.add(5) } as usize],
        ASCII_LOWER[unsafe { *p.add(6) } as usize],
        ASCII_LOWER[unsafe { *p.add(7) } as usize],
    ];
    ngx_hash_8(key, &b)
}

#[inline(always)]
fn ngx_hash_16_lc(mut key: usize, p: *const u8) -> usize {
    key = ngx_hash_8_lc(key, p);
    ngx_hash_8_lc(key, unsafe { p.add(8) })
}

#[inline(always)]
fn ngx_hash_32_lc(mut key: usize, p: *const u8) -> usize {
    key = ngx_hash_16_lc(key, p);
    ngx_hash_16_lc(key, unsafe { p.add(16) })
}

/// `ngx_hash_key_lc` — lowercase each byte then DJB (NGINX `ngx_hash_key_lc`).
#[inline(always)]
pub fn ngx_hash_key_lc(data: &[u8]) -> usize {
    let mut key = 0usize;
    let mut i = 0;
    let len = data.len();
    while i + 32 <= len {
        key = ngx_hash_32_lc(key, unsafe { data.as_ptr().add(i) });
        i += 32;
    }
    while i + 16 <= len {
        key = ngx_hash_16_lc(key, unsafe { data.as_ptr().add(i) });
        i += 16;
    }
    while i + 8 <= len {
        key = ngx_hash_8_lc(key, unsafe { data.as_ptr().add(i) });
        i += 8;
    }
    while i < len {
        key = ngx_hash(key, ASCII_LOWER[data[i] as usize]);
        i += 1;
    }
    key
}
