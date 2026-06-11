#ifndef NGINX_ALGOS_H
#define NGINX_ALGOS_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned char u_char;

uint32_t c_ngx_murmur_hash2(u_char *data, size_t len);
uint32_t c_ngx_crc32_short(u_char *p, size_t len);
uint32_t c_ngx_crc32_long(u_char *p, size_t len);
uintptr_t c_ngx_hash_key(u_char *data, size_t len);
u_char *c_ngx_strnstr(u_char *s1, char *s2, size_t len);
int c_ngx_limit_req_excess(int64_t stored_excess, uint32_t rate, int64_t now,
    int64_t last, int *out_excess);
uint32_t c_ngx_ip_hash_mix(u_char *addr, size_t addrlen, uint32_t hash);
int c_ngx_rbtree_timer_less(uint32_t node_key, uint32_t temp_key);

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

void c_ngx_http_sub_init_tables(c_sub_tables_t *tables, c_sub_match_t *match, size_t n);
int c_ngx_http_sub_find(u_char *text, size_t tlen, c_sub_match_t *match, size_t n,
    c_sub_tables_t *tables, size_t *out_pos, size_t *out_idx);

void c_ngx_sort_u32(uint32_t *base, size_t n);
uintptr_t c_ngx_hash_key_lc(u_char *data, size_t len);
size_t c_ngx_split_clients_pick(uint32_t hash, const uint32_t *cuts, size_t n);
uint32_t c_ngx_utf8_decode(u_char **p, size_t n);
size_t c_ngx_utf8_decode_scan(u_char *data, size_t size);
size_t c_ngx_escape_uri_count(u_char *src, size_t size);
uintptr_t c_ngx_escape_uri(u_char *dst, u_char *src, size_t size);
uint32_t c_ngx_inet_addr(u_char *text, size_t len);
int c_ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
void c_ngx_unescape_uri(u_char **dst, u_char **src, size_t size, unsigned type);
ssize_t c_ngx_atosz(u_char *line, size_t n);
ssize_t c_ngx_atoi(u_char *line, size_t n);
ssize_t c_ngx_parse_size(u_char *line, size_t len);
int64_t c_ngx_parse_time(u_char *line, size_t len, unsigned is_sec);
size_t c_ngx_escape_args_count(u_char *src, size_t size);
size_t c_ngx_escape_uri_component_count(u_char *src, size_t size);
uintptr_t c_radix_bench_find(uint32_t key);
void c_radix_bench_tree_init(void);
ssize_t c_ngx_hextoi(u_char *line, size_t n);
size_t c_ngx_encode_base64(u_char *dst, u_char *src, size_t len);
ssize_t c_ngx_decode_base64(u_char *dst, u_char *src, size_t src_len);
size_t c_ngx_encode_base64url(u_char *dst, u_char *src, size_t len);
ssize_t c_ngx_decode_base64url(u_char *dst, u_char *src, size_t src_len);
size_t c_ngx_hex_dump(u_char *dst, u_char *src, size_t len);
size_t c_ngx_http_chunked_header(u_char *buf, uint64_t size);
int c_ngx_http_chunked_parse_line(const u_char *buf, size_t len, uint64_t *size,
    size_t *consumed);
int c_ngx_http_chunked_parse_buffer(const u_char *buf, size_t len, size_t *count,
    uint64_t *sum);
int c_ngx_http_chunked_parse_stream(const u_char *buf, size_t len, size_t *count,
    uint64_t *sum);

int c_ngx_http_huff_decode(u_char *state, u_char *src, size_t len, u_char **dst,
    unsigned last);
size_t c_ngx_http_huff_encode(u_char *src, size_t len, u_char *dst);

size_t c_ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value);
ssize_t c_ngx_http_v3_decode_varlen_int(const u_char *p, size_t len, uint64_t *value);
size_t c_ngx_http_v3_encode_prefix_int(u_char *p, u_char first, uint64_t value,
    unsigned prefix);
ssize_t c_ngx_http_v3_decode_prefix_int(const u_char *p, size_t len, unsigned prefix,
    uint64_t *value);

#endif
