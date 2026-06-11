/* NGINX `ngx_proxy_protocol_v2_read` IPv4 STREAM PROXY extract — ngx_proxy_protocol.c */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u_char;

#define C_NGX_OK    0
#define C_NGX_ERROR -1

typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
} c_proxy_v2_inet_t;

#define ngx_proxy_protocol_parse_uint16(p)                                    \
    ( ((uint16_t) (p)[0] << 8) + (uint16_t) (p)[1] )

static const u_char c_proxy_v2_sig[12] = "\r\n\r\n\0\r\nQUIT\n";

int
c_ngx_proxy_protocol_v2_parse_inet(const u_char *buf, size_t len,
    c_proxy_v2_inet_t *out)
{
    u_char       *p, *end;
    unsigned      version, command, transport, family;
    uint16_t      alen;

    if (len < 16 + 12) {
        return C_NGX_ERROR;
    }

    if (memcmp(buf, c_proxy_v2_sig, 12) != 0) {
        return C_NGX_ERROR;
    }

    version = buf[12] >> 4;
    if (version != 2) {
        return C_NGX_ERROR;
    }

    command = buf[12] & 0x0f;
    if (command != 1) {
        return C_NGX_ERROR;
    }

    family = buf[13] >> 4;
    if (family != 1) {
        return C_NGX_ERROR;
    }

    transport = buf[13] & 0x0f;
    if (transport != 1) {
        return C_NGX_ERROR;
    }

    alen = ngx_proxy_protocol_parse_uint16(&buf[14]);
    if (alen < 12 || len < 16 + alen) {
        return C_NGX_ERROR;
    }

    p = (u_char *) buf + 16;
    end = p + alen;

    if ((size_t) (end - p) < 12) {
        return C_NGX_ERROR;
    }

    memcpy(&out->src_addr, p, 4);
    memcpy(&out->dst_addr, p + 4, 4);
    out->src_port = ngx_proxy_protocol_parse_uint16(p + 8);
    out->dst_port = ngx_proxy_protocol_parse_uint16(p + 10);

    return C_NGX_OK;
}

extern uint32_t c_ngx_inet_addr(u_char *text, size_t len);
extern ssize_t c_ngx_atoi(u_char *line, size_t n);

int
c_ngx_proxy_protocol_v1_parse_inet(const u_char *buf, size_t len,
    c_proxy_v2_inet_t *out)
{
    u_char  *p, *end, *start;
    size_t   n;

    static const u_char prefix[] = "PROXY TCP4 ";

    if (len < sizeof(prefix) - 1 + 16) {
        return C_NGX_ERROR;
    }

    if (memcmp(buf, prefix, sizeof(prefix) - 1) != 0) {
        return C_NGX_ERROR;
    }

    p = (u_char *) buf + sizeof(prefix) - 1;
    end = (u_char *) buf + len;

    start = p;
    while (p < end && *p != ' ') {
        p++;
    }
    if (p == start || p == end) {
        return C_NGX_ERROR;
    }
    out->src_addr = c_ngx_inet_addr(start, p - start);
    if (out->src_addr == 0xffffffff) {
        return C_NGX_ERROR;
    }
    p++;

    start = p;
    while (p < end && *p != ' ') {
        p++;
    }
    if (p == start || p == end) {
        return C_NGX_ERROR;
    }
    out->dst_addr = c_ngx_inet_addr(start, p - start);
    if (out->dst_addr == 0xffffffff) {
        return C_NGX_ERROR;
    }
    p++;

    start = p;
    while (p < end && *p != ' ') {
        p++;
    }
    if (p == start) {
        return C_NGX_ERROR;
    }
    n = p - start;
    {
        ssize_t  port;

        port = c_ngx_atoi(start, n);
        if (port < 0 || port > 65535) {
            return C_NGX_ERROR;
        }
        out->src_port = (uint16_t) port;
    }
    if (p == end) {
        return C_NGX_ERROR;
    }
    p++;

    start = p;
    while (p < end && *p != '\r' && *p != '\n') {
        p++;
    }
    if (p == start) {
        return C_NGX_ERROR;
    }
    n = p - start;
    {
        ssize_t  port;

        port = c_ngx_atoi(start, n);
        if (port < 0 || port > 65535) {
            return C_NGX_ERROR;
        }
        out->dst_port = (uint16_t) port;
    }

    return C_NGX_OK;
}
