/* HTTP/2 frame header parse — ngx_http_v2.h macros / ngx_http_v2_state_head */

#include <stddef.h>
#include <stdint.h>

typedef unsigned char u_char;

typedef struct {
    uint32_t length;
    uint8_t  frame_type;
    uint8_t  flags;
    uint32_t sid;
} c_h2_frame_hdr_t;

static uint32_t
parse_uint32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

void
c_ngx_http_v2_parse_frame_header(const u_char *p, c_h2_frame_hdr_t *out)
{
    uint32_t  head;

    head = parse_uint32(p);
    out->length = head >> 8;
    out->frame_type = (uint8_t) (head & 0xff);
    out->flags = p[4];
    out->sid = parse_uint32(&p[5]) & 0x7fffffffU;
}
