//! Config token scan (character rules subset of `ngx_conf_read_token`)

/// Count tokens in a config buffer (whitespace-separated words plus `;` `{` `}`).
#[inline(always)]
pub fn ngx_conf_scan_tokens(buf: &[u8]) -> usize {
    let mut n = 0usize;
    let mut quoted = false;
    let mut s_quoted = false;
    let mut d_quoted = false;
    let mut sharp = false;
    let mut in_token = false;

    unsafe {
        let mut p = buf.as_ptr();
        let end = p.add(buf.len());
        while p < end {
            let ch = *p;
            p = p.add(1);
            if ch == b'\n' {
                sharp = false;
                continue;
            }
            if sharp {
                continue;
            }
            if quoted {
                quoted = false;
                continue;
            }
            if ch == b'#' {
                sharp = true;
                continue;
            }
            if ch == b'\\' && !s_quoted && !d_quoted {
                quoted = true;
                continue;
            }
            if ch == b'"' && !s_quoted {
                d_quoted = !d_quoted;
                in_token = false;
                continue;
            }
            if ch == b'\'' && !d_quoted {
                s_quoted = !s_quoted;
                in_token = false;
                continue;
            }
            if s_quoted || d_quoted {
                continue;
            }
            if ch == b' ' || ch == b'\t' || ch == b'\r' {
                in_token = false;
                continue;
            }
            if ch == b';' || ch == b'{' || ch == b'}' {
                n += 1;
                in_token = false;
                continue;
            }
            if !in_token {
                n += 1;
                in_token = true;
            }
        }
    }
    n
}
