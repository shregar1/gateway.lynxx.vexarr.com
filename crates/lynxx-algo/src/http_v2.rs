//! HTTP/2 frame header — `src/http/v2/ngx_http_v2.h` (`ngx_http_v2_state_head`)

pub const NGX_HTTP_V2_FRAME_HEADER_SIZE: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HttpV2FrameHeader {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub sid: u32,
}

/// Parse 9-byte HTTP/2 frame header (`ngx_http_v2_state_head`).
#[inline(always)]
pub fn ngx_http_v2_parse_frame_header(p: &[u8], out: &mut HttpV2FrameHeader) {
    unsafe { ngx_http_v2_parse_frame_header_ptr(p.as_ptr(), out) }
}

/// Pointer API matching NGINX `u_char *` frame walk.
#[inline(always)]
pub unsafe fn ngx_http_v2_parse_frame_header_ptr(p: *const u8, out: &mut HttpV2FrameHeader) {
    let head = u32::from_be((p as *const u32).read_unaligned());
    out.length = head >> 8;
    out.frame_type = head as u8;
    out.flags = *p.add(4);
    out.sid = u32::from_be((p.add(5) as *const u32).read_unaligned()) & 0x7fff_ffff;
}
