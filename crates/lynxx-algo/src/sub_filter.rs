//! `ngx_http_sub_init_tables` / Horspool — `ngx_http_sub_filter_module.c`

const ASCII_LOWER: [u8; 256] = lower_table();

const fn lower_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let c = i as u8;
        t[i] = if c.is_ascii_uppercase() {
            c | 0x20
        } else {
            c
        };
        i += 1;
    }
    t
}

#[derive(Clone)]
pub struct SubMatch {
    pub pattern: Vec<u8>,
}

impl SubMatch {
    pub fn new(pattern: impl Into<Vec<u8>>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// Reject empty patterns (NGINX config forbids; avoids div-by-zero in tables).
    pub fn validate(patterns: &[SubMatch]) -> Result<(), &'static str> {
        if patterns.is_empty() {
            return Err("at least one pattern required");
        }
        if patterns.iter().any(|m| m.pattern.is_empty()) {
            return Err("empty pattern");
        }
        Ok(())
    }
}

pub struct SubTables {
    pub shift: [u8; 256],
    /// `shift[c] as usize` — avoids per-iteration casts in [`ngx_http_sub_find`].
    pub shift_usize: [usize; 256],
    pub index: [usize; 257],
    pub min_match_len: usize,
    pub max_match_len: usize,
    /// Horspool default skip (`min_match_len` capped to 255) — hot-path branch.
    pub default_shift: usize,
}

#[inline(always)]
fn ngx_min(a: usize, b: usize) -> usize {
    a.min(b)
}

#[inline(always)]
fn ngx_max(a: usize, b: usize) -> usize {
    a.max(b)
}

/// Case-insensitive ASCII match at `pos` (NGINX `ngx_http_sub_match` for ASCII patterns).
#[inline(always)]
fn match_at(hay: &[u8], pos: usize, pat: &[u8]) -> bool {
    let plen = pat.len();
    if pos + plen > hay.len() {
        return false;
    }
    let mut j = 0usize;
    while j < plen {
        if ASCII_LOWER[unsafe { *hay.get_unchecked(pos + j) } as usize]
            != unsafe { *pat.get_unchecked(j) }
        {
            return false;
        }
        j += 1;
    }
    true
}

/// `ngx_http_sub_init_tables()`
pub fn ngx_http_sub_init_tables(matches: &mut [SubMatch]) -> Result<SubTables, &'static str> {
    SubMatch::validate(matches)?;

    let n = matches.len();
    let mut min = matches[0].pattern.len();
    let mut max = min;
    for m in &matches[1..] {
        min = ngx_min(min, m.pattern.len());
        max = ngx_max(max, m.pattern.len());
    }

    let cmp_index = min - 1;
    matches.sort_by(|a, b| {
        let c1 = a.pattern[cmp_index] as i32;
        let c2 = b.pattern[cmp_index] as i32;
        c1.cmp(&c2)
    });

    let min_capped = ngx_min(min, 255);
    let mut shift = [min_capped as u8; 256];
    let mut index = [n; 257];

    let mut ch = 0usize;
    for i in 0..n {
        for j in 0..min {
            let c = matches[i].pattern[min - 1 - j];
            shift[c as usize] = shift[c as usize].min(j as u8);
        }
        let c = matches[i].pattern[min - 1];
        while ch <= c as usize {
            index[ch] = i;
            ch += 1;
        }
    }
    while ch < 257 {
        index[ch] = n;
        ch += 1;
    }

    let mut shift_usize = [0usize; 256];
    for (i, &s) in shift.iter().enumerate() {
        shift_usize[i] = s as usize;
    }

    Ok(SubTables {
        shift,
        shift_usize,
        index,
        min_match_len: min,
        max_match_len: max,
        default_shift: min_capped,
    })
}

/// Horspool scan (NGINX `ngx_http_sub_parse` loop).
#[inline(always)]
pub fn ngx_http_sub_find(
    text: &[u8],
    matches: &[SubMatch],
    tables: &SubTables,
) -> Option<(usize, usize)> {
    if matches.is_empty() || text.len() < tables.min_match_len {
        return None;
    }

    let end = text.len();
    let min_len = tables.min_match_len;
    let default_shift = tables.default_shift;
    let shift = &tables.shift_usize;
    let index = &tables.index;
    let text_ptr = text.as_ptr();
    let mut pos = min_len - 1;
    let mut match_index = 0usize;

    while pos < end {
        let c = ASCII_LOWER[unsafe { *text_ptr.add(pos) } as usize];
        let sh = unsafe { *shift.get_unchecked(c as usize) };

        if sh == default_shift {
            pos += default_shift;
            continue;
        }
        if sh != 0 {
            pos += sh;
            continue;
        }

        let start_u = pos + 1 - min_len;
        let i0 = ngx_max(unsafe { *index.get_unchecked(c as usize) }, match_index);
        let j = unsafe { *index.get_unchecked(c as usize + 1) };

        if i0 + 1 == j {
            if match_at(text, start_u, &matches[i0].pattern) {
                return Some((start_u, i0));
            }
        } else {
            let mut i = i0;
            while i != j {
                if match_at(text, start_u, &matches[i].pattern) {
                    return Some((start_u, i));
                }
                i += 1;
            }
        }

        pos += 1;
        match_index = 0;
    }

    None
}
