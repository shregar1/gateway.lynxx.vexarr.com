//! Leaky-bucket excess — `ngx_http_limit_req_module.c` lookup path

/// `excess = lr->excess - ctx->rate * ms / 1000 + 1000` with ms clamping.
#[inline(always)]
pub fn ngx_limit_req_excess(stored_excess: i64, rate: u32, now: i64, last: i64) -> i32 {
    let mut ms = now - last;
    if ms < -60000 {
        ms = 1;
    } else if ms < 0 {
        ms = 0;
    }
    let mut excess =
        stored_excess as i32 - ((rate as i64) * ms / 1000) as i32 + 1000;
    if excess < 0 {
        excess = 0;
    }
    excess
}

#[inline]
pub fn ngx_limit_req_allows(excess: i32, burst: u32) -> bool {
    (excess as u32) <= burst
}
