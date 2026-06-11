/*
 * Standalone extracts from nginx-master for parity testing (no nginx headers).
 * Sources: ngx_murmurhash.c, ngx_crc32.c, ngx_hash.c, ngx_string.c,
 *           ngx_http_sub_filter_module.c, ngx_http_limit_req (excess),
 *           ngx_http_upstream_ip_hash_module.c
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

typedef unsigned char u_char;

/* --- murmurhash (ngx_murmurhash.c) --- */

uint32_t
c_ngx_murmur_hash2(u_char *data, size_t len)
{
    uint32_t  h, k;

    h = 0 ^ len;

    while (len >= 4) {
        k  = data[0];
        k |= data[1] << 8;
        k |= data[2] << 16;
        k |= data[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        data += 4;
        len -= 4;
    }

    switch (len) {
    case 3:
        h ^= data[2] << 16;
        /* fall through */
    case 2:
        h ^= data[1] << 8;
        /* fall through */
    case 1:
        h ^= data[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}

/* --- crc32 (ngx_crc32.c / ngx_crc32.h) --- */

static uint32_t c_ngx_crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};

static uint32_t c_ngx_crc32_table256[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t
c_ngx_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = c_ngx_crc32_table16[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = c_ngx_crc32_table16[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}

uint32_t
c_ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = c_ngx_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}

/* --- hash (ngx_hash.h / ngx_hash.c) --- */

uintptr_t
c_ngx_hash(uintptr_t key, u_char c)
{
    return key * 31 + c;
}

uintptr_t
c_ngx_hash_key(u_char *data, size_t len)
{
    size_t      i;
    uintptr_t   key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = c_ngx_hash(key, data[i]);
    }

    return key;
}

/* --- strnstr (ngx_string.c) --- */

u_char *
c_ngx_strnstr(u_char *s1, char *s2, size_t len)
{
    u_char  c1, c2;
    size_t  n;

    c2 = *(u_char *) s2++;

    n = strlen(s2);

    do {
        do {
            if (len-- == 0) {
                return NULL;
            }

            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

        if (n > len) {
            return NULL;
        }

    } while (strncmp((char *) s1, s2, n) != 0);

    return --s1;
}

/* --- limit_req excess (ngx_http_limit_req_module.c) --- */

int
c_ngx_limit_req_excess(int64_t stored_excess, uint32_t rate, int64_t now,
    int64_t last, int *out_excess)
{
    int64_t  ms;
    int      excess;

    ms = now - last;

    if (ms < -60000) {
        ms = 1;

    } else if (ms < 0) {
        ms = 0;
    }

    excess = (int) stored_excess - (int) (rate * ms / 1000) + 1000;

    if (excess < 0) {
        excess = 0;
    }

    *out_excess = excess;
    return excess;
}

/* --- ip_hash (ngx_http_upstream_ip_hash_module.c) --- */

uint32_t
c_ngx_ip_hash_mix(u_char *addr, size_t addrlen, uint32_t hash)
{
    size_t  i;

    for (i = 0; i < addrlen; i++) {
        hash = (hash * 113 + addr[i]) % 6271;
    }

    return hash;
}

/* --- timer compare (ngx_rbtree.h insert_timer_value) --- */

int
c_ngx_rbtree_timer_less(uint32_t node_key, uint32_t temp_key)
{
    return (int32_t) (node_key - temp_key) < 0;
}

/* --- sub_filter (ngx_http_sub_filter_module.c) --- */

typedef struct {
    u_char  *pat;
    size_t   len;
} c_sub_match_t;

typedef struct {
    u_char   shift[256];
    u_char   index[257];
    size_t   min_match_len;
    size_t   max_match_len;
} c_sub_tables_t;

static size_t c_sub_cmp_index;

static int
c_sub_cmp_matches(const void *one, const void *two)
{
    const c_sub_match_t  *a = one;
    const c_sub_match_t  *b = two;

    return (int) a->pat[c_sub_cmp_index] - (int) b->pat[c_sub_cmp_index];
}

static u_char
c_sub_tolower(u_char c)
{
    return (c >= 'A' && c <= 'Z') ? (u_char) (c | 0x20) : c;
}

static int
c_sub_match_at(u_char *text, size_t tlen, size_t pos, u_char *pat, size_t plen)
{
    size_t  i;
    u_char  c;

    if (pos + plen > tlen) {
        return 0;
    }

    for (i = 0; i < plen; i++) {
        c = text[pos + i];
        if (c >= 'A' && c <= 'Z') {
            c = (u_char) (c | 0x20);
        }
        if (c != pat[i]) {
            return 0;
        }
    }

    return 1;
}

void
c_ngx_http_sub_init_tables(c_sub_tables_t *tables, c_sub_match_t *match, size_t n)
{
    u_char      c;
    size_t      i, j, min, max, ch;

    min = match[0].len;
    max = match[0].len;

    for (i = 1; i < n; i++) {
        if (min > match[i].len) {
            min = match[i].len;
        }
        if (max < match[i].len) {
            max = match[i].len;
        }
    }

    tables->min_match_len = min;
    tables->max_match_len = max;

    c_sub_cmp_index = min - 1;
    qsort(match, n, sizeof(c_sub_match_t), c_sub_cmp_matches);

    if (min > 255) {
        min = 255;
    }

    memset(tables->shift, (int) min, 256);

    ch = 0;

    for (i = 0; i < n; i++) {
        for (j = 0; j < tables->min_match_len; j++) {
            c = match[i].pat[tables->min_match_len - 1 - j];
            if (tables->shift[c] > j) {
                tables->shift[c] = (u_char) j;
            }
        }

        c = match[i].pat[tables->min_match_len - 1];
        while (ch <= (size_t) c) {
            tables->index[ch++] = (u_char) i;
        }
    }

    while (ch < 257) {
        tables->index[ch++] = (u_char) n;
    }
}

int
c_ngx_http_sub_find(u_char *text, size_t tlen, c_sub_match_t *match, size_t n,
    c_sub_tables_t *tables, size_t *out_pos, size_t *out_idx)
{
    ssize_t     offset, end, start;
    size_t      i, j, pos;
    u_char      c, shift;
    size_t      match_index;

    if (n == 0 || tlen < tables->min_match_len) {
        return 0;
    }

    end = (ssize_t) tlen;
    offset = (ssize_t) tables->min_match_len - 1;
    match_index = 0;

    while (offset < end) {
        pos = (size_t) offset;
        c = c_sub_tolower(text[pos]);
        shift = tables->shift[c];

        if (shift > 1) {
            offset += shift;
            continue;
        }

        if (shift == 1) {
            offset++;
            continue;
        }

        start = offset - (ssize_t) tables->min_match_len + 1;

        i = match_index;
        if (tables->index[c] > i) {
            i = tables->index[c];
        }

        j = tables->index[c + 1];

        while (i != j) {
            if (c_sub_match_at(text, tlen, (size_t) start, match[i].pat,
                               match[i].len))
            {
                *out_pos = (size_t) start;
                *out_idx = i;
                return 1;
            }
            i++;
        }

        offset++;
        match_index = 0;
    }

    return 0;
}

/* --- sort (ngx_string.c ngx_sort) — u32 insertion sort for benchmarks --- */

void
c_ngx_sort_u32(uint32_t *base, size_t n)
{
    uint32_t  tmp;
    size_t    i, j;

    if (n < 2) {
        return;
    }

    for (i = 1; i < n; i++) {
        tmp = base[i];
        j = i;

        while (j > 0 && base[j - 1] > tmp) {
            base[j] = base[j - 1];
            j--;
        }

        base[j] = tmp;
    }
}

/* --- hash_key_lc (ngx_hash.c) --- */

static u_char
c_hash_tolower(u_char c)
{
    return (c >= 'A' && c <= 'Z') ? (u_char) (c | 0x20) : c;
}

uintptr_t
c_ngx_hash_key_lc(u_char *data, size_t len)
{
    uintptr_t  key;
    size_t     i;

    key = 0;

    for (i = 0; i < len; i++) {
        key = c_ngx_hash(key, c_hash_tolower(data[i]));
    }

    return key;
}

/* --- utf8_decode (ngx_string.c) --- */

uint32_t
c_ngx_utf8_decode(u_char **p, size_t n)
{
    size_t    len;
    uint32_t  u, i, valid;

    u = **p;

    if (u >= 0xf8) {

        (*p)++;
        return 0xffffffff;

    } else if (u >= 0xf0) {

        u &= 0x07;
        valid = 0xffff;
        len = 3;

    } else if (u >= 0xe0) {

        u &= 0x0f;
        valid = 0x7ff;
        len = 2;

    } else if (u >= 0xc2) {

        u &= 0x1f;
        valid = 0x7f;
        len = 1;

    } else {
        (*p)++;
        return 0xffffffff;
    }

    if (n - 1 < len) {
        return 0xfffffffe;
    }

    (*p)++;

    while (len) {
        i = *(*p)++;

        if (i < 0x80) {
            return 0xffffffff;
        }

        u = (u << 6) | (i & 0x3f);

        len--;
    }

    if (u > valid) {
        return u;
    }

    return 0xffffffff;
}

size_t
c_ngx_utf8_decode_scan(u_char *data, size_t size)
{
    u_char  *p, *end;
    size_t   count;
    uint32_t u;

    p = data;
    end = data + size;
    count = 0;

    while (p < end) {
        if (*p < 0x80) {
            p++;
            continue;
        }

        u_char *save = p;
        size_t  n = (size_t) (end - p);

        u = c_ngx_utf8_decode(&p, n);
        if (u <= 0x10ffff && u >= 0x80) {
            count++;
        } else if (u == 0xfffffffe) {
            break;
        } else {
            p = save + 1;
        }
    }

    return count;
}

/* --- split_clients (ngx_http_split_clients_module.c) --- */

size_t
c_ngx_split_clients_pick(uint32_t hash, const uint32_t *cuts, size_t n)
{
    size_t  i;

    for (i = 0; i < n; i++) {
        if (hash < cuts[i] || cuts[i] == 0) {
            return i;
        }
    }

    return n > 0 ? n - 1 : 0;
}

/* --- escape_uri count (ngx_string.c, NGX_ESCAPE_URI) --- */

static uint32_t c_uri_escape[] = {
    0xffffffff,
    0xd000002d,
    0x50000000,
    0xb8000001,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff
};

size_t
c_ngx_escape_uri_count(u_char *src, size_t size)
{
    size_t      n;
    uint32_t   *escape;

    escape = c_uri_escape;
    n = 0;

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            n++;
        }
        src++;
        size--;
    }

    return n;
}

uintptr_t
c_ngx_escape_uri(u_char *dst, u_char *src, size_t size)
{
    static u_char  hex[] = "0123456789ABCDEF";
    uint32_t      *escape;
    u_char         prefix;

    escape = c_uri_escape;
    prefix = '%';

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            *dst++ = prefix;
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}

/* --- inet_addr (ngx_inet.c) --- */

uint32_t
c_ngx_inet_addr(u_char *text, size_t len)
{
    u_char      *p, c;
    uint32_t     addr;
    uint32_t     octet, n;

    addr = 0;
    octet = 0;
    n = 0;

    for (p = text; p < text + len; p++) {
        c = *p;

        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');

            if (octet > 255) {
                return 0xffffffff;
            }

            continue;
        }

        if (c == '.') {
            addr = (addr << 8) + octet;
            octet = 0;
            n++;
            continue;
        }

        return 0xffffffff;
    }

    if (n == 3) {
        addr = (addr << 8) + octet;
#if defined(__APPLE__) || defined(__linux__) || defined(__FreeBSD__)
        return __builtin_bswap32(addr);
#else
        return ((addr & 0xff) << 24) | ((addr & 0xff00) << 8)
               | ((addr & 0xff0000) >> 8) | ((addr & 0xff000000) >> 24);
#endif
    }

    return 0xffffffff;
}

/* --- unescape_uri (ngx_string.c, NGX_UNESCAPE_URI) --- */

#define C_NGX_UNESCAPE_URI 1

void
c_ngx_unescape_uri(u_char **dst, u_char **src, size_t size, unsigned type)
{
    u_char  *d, *s, ch, c, decoded;
    enum {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:
            if (ch == '?'
                && (type & (C_NGX_UNESCAPE_URI)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%') {
                state = sw_quoted;
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            state = sw_usual;

            *d++ = ch;

            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + (ch - '0'));

                if (type & C_NGX_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + (c - 'a' + 10));

                if (type & C_NGX_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                break;
            }

            break;
        }
    }

done:

    *dst = d;
    *src = s;
}

/* --- atosz (ngx_string.c) --- */

#define C_NGX_ERROR ((ssize_t) -1)

ssize_t
c_ngx_atosz(u_char *line, size_t n)
{
    ssize_t  value, cutoff, cutlim;

    if (n == 0) {
        return C_NGX_ERROR;
    }

    cutoff = (ssize_t) (SIZE_MAX / 10);
    cutlim = (ssize_t) (SIZE_MAX % 10);

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return C_NGX_ERROR;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return C_NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    return value;
}

/* --- atoi (ngx_string.c) --- */

ssize_t
c_ngx_atoi(u_char *line, size_t n)
{
    ssize_t  value, cutoff, cutlim;

    if (n == 0) {
        return C_NGX_ERROR;
    }

    cutoff = (ssize_t) (LLONG_MAX / 10);
    cutlim = (ssize_t) (LLONG_MAX % 10);

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return C_NGX_ERROR;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return C_NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    return value;
}

/* --- parse_size (ngx_parse.c) --- */

ssize_t
c_ngx_parse_size(u_char *line, size_t len)
{
    u_char   unit;
    ssize_t  size, scale, max;

    if (len == 0) {
        return C_NGX_ERROR;
    }

    unit = line[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = (ssize_t) (SIZE_MAX / 1024);
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = (ssize_t) (SIZE_MAX / (1024 * 1024));
        scale = 1024 * 1024;
        break;

    default:
        max = (ssize_t) SIZE_MAX;
        scale = 1;
    }

    size = c_ngx_atosz(line, len);
    if (size == C_NGX_ERROR || size > max) {
        return C_NGX_ERROR;
    }

    size *= scale;

    return size;
}

/* --- escape_args count --- */

static uint32_t c_args_escape[] = {
    0xffffffff,
    0xd800086d,
    0x50000000,
    0xb8000001,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff
};

size_t
c_ngx_escape_args_count(u_char *src, size_t size)
{
    size_t      n;
    uint32_t   *escape;

    escape = c_args_escape;
    n = 0;

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            n++;
        }
        src++;
        size--;
    }

    return n;
}

/* --- escape_uri_component count --- */

static uint32_t c_uri_component_escape[] = {
    0xffffffff,
    0xfc009fff,
    0x78000001,
    0xb8000001,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff
};

size_t
c_ngx_escape_uri_component_count(u_char *src, size_t size)
{
    size_t      n;
    uint32_t   *escape;

    escape = c_uri_component_escape;
    n = 0;

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            n++;
        }
        src++;
        size--;
    }

    return n;
}

/* --- hextoi (ngx_string.c) --- */

ssize_t
c_ngx_hextoi(u_char *line, size_t n)
{
    u_char     c, ch;
    ssize_t    value, cutoff;

    if (n == 0) {
        return C_NGX_ERROR;
    }

    cutoff = (ssize_t) (LLONG_MAX / 16);

    for (value = 0; n--; line++) {
        if (value > cutoff) {
            return C_NGX_ERROR;
        }

        ch = *line;

        if (ch >= '0' && ch <= '9') {
            value = value * 16 + (ch - '0');
            continue;
        }

        c = (u_char) (ch | 0x20);

        if (c >= 'a' && c <= 'f') {
            value = value * 16 + (c - 'a' + 10);
            continue;
        }

        return C_NGX_ERROR;
    }

    return value;
}

/* --- encode_base64 (ngx_string.c) --- */

size_t
c_ngx_encode_base64(u_char *dst, u_char *src, size_t len)
{
    static u_char  basis64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    u_char  *d, *s;
    size_t   left;

    s = src;
    d = dst;
    left = len;

    while (left > 2) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];
        *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis64[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis64[s[2] & 0x3f];

        s += 3;
        left -= 3;
    }

    if (left) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];

        if (left == 1) {
            *d++ = basis64[(s[0] & 3) << 4];
            *d++ = '=';
        } else {
            *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis64[(s[1] & 0x0f) << 2];
        }

        *d++ = '=';
    }

    return (size_t) (d - dst);
}

/* --- decode_base64 (ngx_string.c) --- */

static u_char c_basis64_decode[] = {
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
    77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
    77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
};

ssize_t
c_ngx_decode_base64(u_char *dst, u_char *src, size_t src_len)
{
    size_t  len;
    u_char *d, *s;

    for (len = 0; len < src_len; len++) {
        if (src[len] == '=') {
            break;
        }

        if (c_basis64_decode[src[len]] == 77) {
            return C_NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return C_NGX_ERROR;
    }

    s = src;
    d = dst;

    while (len > 3) {
        *d++ = (u_char) (c_basis64_decode[s[0]] << 2 | c_basis64_decode[s[1]] >> 4);
        *d++ = (u_char) (c_basis64_decode[s[1]] << 4 | c_basis64_decode[s[2]] >> 2);
        *d++ = (u_char) (c_basis64_decode[s[2]] << 6 | c_basis64_decode[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (c_basis64_decode[s[0]] << 2 | c_basis64_decode[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (c_basis64_decode[s[1]] << 4 | c_basis64_decode[s[2]] >> 2);
    }

    return (ssize_t) (d - dst);
}

/* --- encode_base64url (ngx_string.c) --- */

size_t
c_ngx_encode_base64url(u_char *dst, u_char *src, size_t len)
{
    static u_char  basis64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    u_char  *d, *s;
    size_t   left;

    s = src;
    d = dst;
    left = len;

    while (left > 2) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];
        *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis64[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis64[s[2] & 0x3f];

        s += 3;
        left -= 3;
    }

    if (left) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];

        if (left == 1) {
            *d++ = basis64[(s[0] & 3) << 4];
        } else {
            *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis64[(s[1] & 0x0f) << 2];
        }
    }

    return (size_t) (d - dst);
}

/* --- decode_base64url (ngx_string.c) --- */

static u_char c_basis64url_decode[] = {
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
    77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
    77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
};

ssize_t
c_ngx_decode_base64url(u_char *dst, u_char *src, size_t src_len)
{
    size_t  len;
    u_char *d, *s;

    for (len = 0; len < src_len; len++) {
        if (src[len] == '=') {
            break;
        }

        if (c_basis64url_decode[src[len]] == 77) {
            return C_NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return C_NGX_ERROR;
    }

    s = src;
    d = dst;

    while (len > 3) {
        *d++ = (u_char) (c_basis64url_decode[s[0]] << 2 | c_basis64url_decode[s[1]] >> 4);
        *d++ = (u_char) (c_basis64url_decode[s[1]] << 4 | c_basis64url_decode[s[2]] >> 2);
        *d++ = (u_char) (c_basis64url_decode[s[2]] << 6 | c_basis64url_decode[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (c_basis64url_decode[s[0]] << 2 | c_basis64url_decode[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (c_basis64url_decode[s[1]] << 4 | c_basis64url_decode[s[2]] >> 2);
    }

    return (ssize_t) (d - dst);
}

/* --- hex_dump (ngx_string.c) --- */

size_t
c_ngx_hex_dump(u_char *dst, u_char *src, size_t len)
{
    static u_char  hex[] = "0123456789abcdef";
    u_char        *d, *s;

    s = src;
    d = dst;

    while (len--) {
        *d++ = hex[*s >> 4];
        *d++ = hex[*s++ & 0xf];
    }

    return (size_t) (d - dst);
}

/* --- inet6_addr (ngx_inet.c) --- */

int
c_ngx_inet6_addr(u_char *p, size_t len, u_char *addr)
{
    u_char      c, *zero, *digit, *s, *d;
    size_t      len4;
    unsigned int  n, nibbles, word;
    uint32_t    v4;

    if (len == 0) {
        return C_NGX_ERROR;
    }

    zero = NULL;
    digit = NULL;
    len4 = 0;
    nibbles = 0;
    word = 0;
    n = 8;

    if (p[0] == ':') {
        p++;
        len--;
    }

    for (/* void */; len; len--) {
        c = *p++;

        if (c == ':') {
            if (nibbles) {
                digit = p;
                len4 = len;
                *addr++ = (u_char) (word >> 8);
                *addr++ = (u_char) (word & 0xff);

                if (--n) {
                    nibbles = 0;
                    word = 0;
                    continue;
                }

            } else {
                if (zero == NULL) {
                    digit = p;
                    len4 = len;
                    zero = addr;
                    continue;
                }
            }

            return C_NGX_ERROR;
        }

        if (c == '.' && nibbles) {
            if (n < 2 || digit == NULL) {
                return C_NGX_ERROR;
            }

            v4 = c_ngx_inet_addr(digit, len4 - 1);
            if (v4 == 0xffffffff) {
                return C_NGX_ERROR;
            }

            *addr++ = (u_char) ((v4 >> 24) & 0xff);
            *addr++ = (u_char) ((v4 >> 16) & 0xff);
            n--;
            break;
        }

        if (++nibbles > 4) {
            return C_NGX_ERROR;
        }

        if (c >= '0' && c <= '9') {
            word = word * 16 + (c - '0');
            continue;
        }

        c |= 0x20;

        if (c >= 'a' && c <= 'f') {
            word = word * 16 + (c - 'a') + 10;
            continue;
        }

        return C_NGX_ERROR;
    }

    if (nibbles == 0 && zero == NULL) {
        return C_NGX_ERROR;
    }

    *addr++ = (u_char) (word >> 8);
    *addr++ = (u_char) (word & 0xff);

    if (--n) {
        if (zero) {
            n *= 2;
            s = addr - 1;
            d = s + n;
            while (s >= zero) {
                *d-- = *s--;
            }
            memset(zero, 0, n);
            return 0;
        }

    } else {
        if (zero == NULL) {
            return 0;
        }
    }

    return C_NGX_ERROR;
}
