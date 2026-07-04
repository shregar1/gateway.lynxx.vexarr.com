/* NGINX `ngx_http_huff_decode` extract — tables in huff_tables_gen.c */

#include <stddef.h>
#include <stdint.h>

typedef unsigned char u_char;

typedef struct {
    uint8_t next;
    uint8_t emit;
    uint8_t sym;
    uint8_t ending;
} huff_code_t;

extern const huff_code_t huff_decode_codes[256][16];

#define C_NGX_OK    0
#define C_NGX_ERROR -1

static int
c_huff_decode_bits(u_char *state, u_char *ending, unsigned bits, u_char **dst)
{
    huff_code_t code;

    code = huff_decode_codes[*state][bits];

    if (code.next == *state) {
        return C_NGX_ERROR;
    }

    if (code.emit) {
        *(*dst)++ = code.sym;
    }

    *ending = code.ending;
    *state = code.next;

    return C_NGX_OK;
}

int
c_ngx_http_huff_decode(u_char *state, u_char *src, size_t len, u_char **dst,
    unsigned last)
{
    u_char  *end, ch, ending;

    ch = 0;
    ending = 1;

    end = src + len;

    while (src != end) {
        ch = *src++;

        if (c_huff_decode_bits(state, &ending, ch >> 4, dst) != C_NGX_OK) {
            return C_NGX_ERROR;
        }

        if (c_huff_decode_bits(state, &ending, ch & 0xf, dst) != C_NGX_OK) {
            return C_NGX_ERROR;
        }
    }

    if (last) {
        if (!ending) {
            return C_NGX_ERROR;
        }

        *state = 0;
    }

    return C_NGX_OK;
}
