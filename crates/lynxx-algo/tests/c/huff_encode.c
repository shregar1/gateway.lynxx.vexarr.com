/* NGINX `ngx_http_huff_encode` extract — table in huff_encode_table_gen.c */

#include <stddef.h>
#include <stdint.h>

typedef unsigned char u_char;
typedef uint64_t ngx_uint_t;

typedef struct {
    uint32_t code;
    uint8_t len;
} huff_enc_code_t;

extern const huff_enc_code_t huff_encode_table[256];

#define ngx_align(d, a) (((d) + ((a) - 1)) & ~((a) - 1))

#if defined(__GNUC__)
#define ngx_http_huff_encode_buf(dst, buf) (*(uint64_t *)(dst) = __builtin_bswap64(buf))
#else
#define ngx_http_huff_encode_buf(dst, buf)                                    \
    do {                                                                      \
        (dst)[0] = (u_char)((buf) >> 56);                                     \
        (dst)[1] = (u_char)((buf) >> 48);                                     \
        (dst)[2] = (u_char)((buf) >> 40);                                     \
        (dst)[3] = (u_char)((buf) >> 32);                                     \
        (dst)[4] = (u_char)((buf) >> 24);                                     \
        (dst)[5] = (u_char)((buf) >> 16);                                     \
        (dst)[6] = (u_char)((buf) >> 8);                                      \
        (dst)[7] = (u_char)(buf);                                             \
    } while (0)
#endif

size_t
c_ngx_http_huff_encode(u_char *src, size_t len, u_char *dst)
{
    u_char          *end;
    size_t           hlen;
    ngx_uint_t       buf, pending, code;
    huff_enc_code_t *next;

    hlen = 0;
    buf = 0;
    pending = 0;
    end = src + len;

    while (src != end) {
        next = &huff_encode_table[*src++];
        code = next->code;
        pending += next->len;

        if (pending < sizeof(buf) * 8) {
            buf |= code << (sizeof(buf) * 8 - pending);
            continue;
        }

        pending -= sizeof(buf) * 8;

        buf |= code >> pending;

        ngx_http_huff_encode_buf(&dst[hlen], buf);

        hlen += sizeof(buf);

        buf = pending ? code << (sizeof(buf) * 8 - pending) : 0;
    }

    if (pending == 0) {
        return hlen;
    }

    buf |= (ngx_uint_t)-1 >> pending;

    pending = ngx_align(pending, 8);

    buf >>= sizeof(buf) * 8 - pending;

    do {
        pending -= 8;
        dst[hlen++] = (u_char)(buf >> pending);
    } while (pending);

    return hlen;
}
