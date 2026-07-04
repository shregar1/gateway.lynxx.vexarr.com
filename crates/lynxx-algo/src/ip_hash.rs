//! IP hash mix — `ngx_http_upstream_ip_hash_module.c`

#[inline(always)]
fn step(hash: u32, b: u8) -> u32 {
    (hash.wrapping_mul(113) + b as u32) % 6271
}

/// Per-byte: `hash = (hash * 113 + addr[i]) % 6271`
#[inline(always)]
pub fn ngx_ip_hash_mix(addr: &[u8], mut hash: u32) -> u32 {
    match addr.len() {
        4 => {
            hash = step(hash, addr[0]);
            hash = step(hash, addr[1]);
            hash = step(hash, addr[2]);
            step(hash, addr[3])
        }
        n => {
            let mut i = 0usize;
            while i < n {
                hash = step(hash, unsafe { *addr.get_unchecked(i) });
                i += 1;
            }
            hash
        }
    }
}

pub fn ngx_ip_hash_select(addr: &[u8], total_weight: u32, weights: &[u32]) -> usize {
    let hash = ngx_ip_hash_mix(addr, 0);
    let mut w = hash % total_weight;
    for (i, &weight) in weights.iter().enumerate() {
        if w < weight {
            return i;
        }
        w -= weight;
    }
    0
}
