/* HTTP/3 variable-length integers — ngx_http_v3_encode.c / ngx_http_v3_parse.c */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef unsigned char u_char;
typedef uintptr_t ngx_uint_t;

size_t
c_ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value)
{
    if (value <= 63) {
        if (p == NULL) {
            return 1;
        }
        *p++ = (u_char)value;
        return 1;
    }

    if (value <= 16383) {
        if (p == NULL) {
            return 2;
        }
        *p++ = 0x40 | (value >> 8);
        *p++ = (u_char)value;
        return 2;
    }

    if (value <= 1073741823) {
        if (p == NULL) {
            return 4;
        }
        *p++ = 0x80 | (value >> 24);
        *p++ = (value >> 16);
        *p++ = (value >> 8);
        *p++ = (u_char)value;
        return 4;
    }

    if (p == NULL) {
        return 8;
    }

    *p++ = 0xc0 | (value >> 56);
    *p++ = (value >> 48);
    *p++ = (value >> 40);
    *p++ = (value >> 32);
    *p++ = (value >> 24);
    *p++ = (value >> 16);
    *p++ = (value >> 8);
    *p++ = (u_char)value;
    return 8;
}

ssize_t
c_ngx_http_v3_decode_varlen_int(const u_char *p, size_t len, uint64_t *value)
{
    uint64_t  v;
    u_char    ch;

    if (len == 0) {
        return -1;
    }

    ch = p[0];
    v = ch;

    if ((ch & 0xc0) == 0) {
        *value = v;
        return 1;
    }

    if (len < 2) {
        return -1;
    }

    v = (v << 8) + p[1];
    if ((v & 0xc000) == 0x4000) {
        *value = v & 0x3fff;
        return 2;
    }

    if (len < 4) {
        return -1;
    }

    v = (v << 8) + p[2];
    v = (v << 8) + p[3];
    if ((v & 0xc0000000) == 0x80000000) {
        *value = v & 0x3fffffff;
        return 4;
    }

    if (len < 8) {
        return -1;
    }

    v = (v << 8) + p[4];
    v = (v << 8) + p[5];
    v = (v << 8) + p[6];
    v = (v << 8) + p[7];
    *value = v & 0x3fffffffffffffff;
    return 8;
}

size_t
c_ngx_http_v3_encode_prefix_int(u_char *p, u_char first, uint64_t value,
    ngx_uint_t prefix)
{
    u_char   *start;
    uint64_t  thresh, n, rem;

    start = p;
    thresh = (1ULL << prefix) - 1;

    if (value < thresh) {
        if (p == NULL) {
            return 1;
        }
        *p++ = first | (u_char)value;
        return 1;
    }

    rem = value - thresh;

    if (p == NULL) {
        for (n = 2; rem >= 128; n++) {
            rem >>= 7;
        }
        return (size_t)n;
    }

    *p++ = first | (u_char)thresh;

    while (rem >= 128) {
        *p++ = 0x80 | (u_char)rem;
        rem >>= 7;
    }

    *p++ = (u_char)rem;
    return (size_t)(p - start);
}

ssize_t
c_ngx_http_v3_decode_prefix_int(const u_char *p, size_t len, ngx_uint_t prefix,
    uint64_t *value)
{
    uint64_t  mask, v;
    size_t    i;
    u_char    b;
    uint32_t  shift;

    if (len == 0) {
        return -1;
    }

    mask = (1ULL << prefix) - 1;
    v = p[0] & mask;

    if (v < mask) {
        *value = v;
        return 1;
    }

    i = 1;
    shift = 0;

    for (;;) {
        if (i >= len) {
            return -1;
        }

        b = p[i++];
        v += ((uint64_t)(b & 0x7f)) << shift;

        if ((b & 0x80) == 0) {
            *value = v;
            return (ssize_t)i;
        }

        shift += 7;
        if (shift > 63) {
            return -1;
        }
    }
}
