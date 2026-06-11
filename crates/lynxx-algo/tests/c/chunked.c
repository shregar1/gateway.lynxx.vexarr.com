#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u_char;

#define NGX_INT64_LEN  (sizeof(int64_t) * 4)

static const int8_t c_hex_val[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

static size_t
hex_off(u_char *buf, uint64_t ui64)
{
    u_char  *p, temp[NGX_INT64_LEN + 1];
    static u_char   hex[] = "0123456789abcdef";

    p = temp + NGX_INT64_LEN;

    do {
        *--p = hex[(uint32_t) (ui64 & 0xf)];
    } while (ui64 >>= 4);

    size_t  len = (temp + NGX_INT64_LEN) - p;
    memcpy(buf, p, len);
    return len;
}

size_t
c_ngx_http_chunked_header(u_char *buf, uint64_t size)
{
    size_t  len = hex_off(buf, size);
    buf[len] = '\r';
    buf[len + 1] = '\n';
    return len + 2;
}

int
c_ngx_http_chunked_parse_line(const u_char *buf, size_t len, uint64_t *size,
    size_t *consumed)
{
    size_t   i;
    uint64_t v;
    int8_t   d;

    if (len == 0) {
        return -1;
    }

    d = c_hex_val[buf[0]];
    if (d < 0) {
        return -1;
    }

    v = (uint64_t) d;
    i = 1;

    while (i < len) {
        d = c_hex_val[buf[i]];
        if (d < 0) {
            break;
        }
        if (v > UINT64_MAX / 16) {
            return -1;
        }
        v = v * 16 + (uint64_t) d;
        i++;
    }

    if (i + 1 >= len || buf[i] != '\r' || buf[i + 1] != '\n') {
        return -1;
    }

    *size = v;
    *consumed = i + 2;
    return 0;
}

typedef struct {
    uint8_t  state;
    uint64_t size;
} c_chunked_ctx_t;

#define C_SW_CHUNK_START       0
#define C_SW_CHUNK_SIZE        1
#define C_SW_CHUNK_EXT_ALMOST  2

static int
c_chunked_hex(u_char ch, uint64_t *size, int extend)
{
    int8_t  d;

    d = c_hex_val[ch];
    if (d < 0) {
        return 0;
    }

    if (extend) {
        if (*size > UINT64_MAX / 16) {
            return -1;
        }
        *size = *size * 16 + (uint64_t) d;
        return 1;
    }

    *size = (uint64_t) d;
    return 1;
}

static int
c_ngx_http_chunked_parse_byte(c_chunked_ctx_t *ctx, u_char ch, uint64_t *out_size)
{
    int  rc;

    rc = 0;

    switch (ctx->state) {

    case C_SW_CHUNK_START:
        if (c_chunked_hex(ch, &ctx->size, 0) != 1) {
            return -1;
        }
        ctx->state = C_SW_CHUNK_SIZE;
        break;

    case C_SW_CHUNK_SIZE:
        rc = c_chunked_hex(ch, &ctx->size, 1);
        if (rc == 1) {
            break;
        }
        if (rc < 0) {
            return -1;
        }
        if (ch != '\r') {
            return -1;
        }
        ctx->state = C_SW_CHUNK_EXT_ALMOST;
        break;

    case C_SW_CHUNK_EXT_ALMOST:
        if (ch != '\n') {
            return -1;
        }
        ctx->state = C_SW_CHUNK_START;
        *out_size = ctx->size;
        return 1;

    default:
        return -1;
    }

    return 0;
}

int
c_ngx_http_chunked_parse_stream(const u_char *buf, size_t len, size_t *count,
    uint64_t *sum)
{
    size_t           i;
    size_t           cnt;
    uint64_t         total, size;
    c_chunked_ctx_t  ctx;

    ctx.state = C_SW_CHUNK_START;
    ctx.size = 0;
    cnt = 0;
    total = 0;

    for (i = 0; i < len; i++) {
        switch (c_ngx_http_chunked_parse_byte(&ctx, buf[i], &size)) {

        case -1:
            return -1;

        case 1:
            total += size;
            cnt++;
            break;
        }
    }

    if (ctx.state != C_SW_CHUNK_START) {
        return -1;
    }

    *count = cnt;
    *sum = total;
    return 0;
}

int
c_ngx_http_chunked_parse_buffer(const u_char *buf, size_t len, size_t *count,
    uint64_t *sum)
{
    size_t   off, n;
    uint64_t size, total;
    size_t   cnt;

    off = 0;
    total = 0;
    cnt = 0;

    while (off < len) {
        if (c_ngx_http_chunked_parse_line(buf + off, len - off, &size, &n) != 0) {
            return -1;
        }
        total += size;
        off += n;
        cnt++;
    }

    *count = cnt;
    *sum = total;
    return 0;
}
