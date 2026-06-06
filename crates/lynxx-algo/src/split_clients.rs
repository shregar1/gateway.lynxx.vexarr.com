//! `split_clients` — `ngx_http_split_clients_module.c` lookup path.

/// Pick bucket index: `hash < part[i].percent || part[i].percent == 0`.
#[inline(always)]
pub fn ngx_split_clients_pick(hash: u32, cuts: &[u32]) -> usize {
    match cuts.len() {
        8 => split_pick_8(hash, cuts),
        _ => split_pick_loop(hash, cuts),
    }
}

#[inline(always)]
fn split_pick_8(hash: u32, c: &[u32]) -> usize {
    if hash < c[0] || c[0] == 0 {
        return 0;
    }
    if hash < c[1] || c[1] == 0 {
        return 1;
    }
    if hash < c[2] || c[2] == 0 {
        return 2;
    }
    if hash < c[3] || c[3] == 0 {
        return 3;
    }
    if hash < c[4] || c[4] == 0 {
        return 4;
    }
    if hash < c[5] || c[5] == 0 {
        return 5;
    }
    if hash < c[6] || c[6] == 0 {
        return 6;
    }
    7
}

#[inline(always)]
fn split_pick_loop(hash: u32, cuts: &[u32]) -> usize {
    let mut i = 0usize;
    while i < cuts.len() {
        let cut = cuts[i];
        if hash < cut || cut == 0 {
            return i;
        }
        i += 1;
    }
    cuts.len().saturating_sub(1)
}
