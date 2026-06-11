//! NGINX core algorithms — **exact semantics**, **optimized Rust**, verified vs C.
//!
//! - Parity: `cargo test` compares against `tests/c/nginx_algos.c`
//! - Benchmarks: `cargo bench`
//! - Flamegraph: `scripts/flamegraph.sh`

pub mod base64;
pub mod chunked;
pub mod conf_scan;
pub mod crc32;
pub mod escape_uri;
pub mod hex;
pub mod huff_decode;
pub mod huff_encode;
pub mod http_v2;
pub mod v3;
pub mod crc32_tables;
pub mod hash;
pub mod inet;
pub mod ip_hash;
pub mod limit_req;
pub mod murmurhash;
pub mod parse;
pub mod proxy_protocol;
pub mod radix;
pub mod rbtree;
pub mod sort;
pub mod split_clients;
pub mod string;
pub mod sub_filter;
pub mod unescape_uri;
pub mod utf8;

pub use conf_scan::ngx_conf_scan_tokens;
pub use http_v2::{
    ngx_http_v2_parse_frame_header, ngx_http_v2_parse_frame_header_ptr, HttpV2FrameHeader,
    NGX_HTTP_V2_FRAME_HEADER_SIZE,
};
pub use base64::{
    ngx_decode_base64, ngx_decode_base64url, ngx_encode_base64, ngx_encode_base64url,
};
pub use chunked::{
    ngx_http_chunked_header, ngx_http_chunked_parse_buffer, ngx_http_chunked_parse_byte,
    ngx_http_chunked_parse_line, ngx_http_chunked_parse_stream,
    ngx_http_chunked_parse_stream_fsm, ChunkedParseCtx,
};
pub use hex::{ngx_hex_dump, ngx_hextoi};
pub use huff_decode::{
    ngx_http_huff_decode, ngx_http_huff_decode_ptr, HUFF_WWW_EXAMPLE_ENC, HUFF_WWW_EXAMPLE_PLAIN,
    NGX_ERROR as NGX_HUFF_ERROR, NGX_OK as NGX_HUFF_OK,
};
pub use huff_encode::ngx_http_huff_encode;
pub use v3::{
    ngx_http_v3_decode_prefix_int, ngx_http_v3_decode_prefix_int_ptr, ngx_http_v3_decode_varlen_int,
    ngx_http_v3_encode_prefix_int,
    ngx_http_v3_encode_varlen_int,
};
pub use escape_uri::{ngx_escape_uri, ngx_escape_uri_count};
pub use parse::{ngx_atoi, ngx_atosz, ngx_parse_size, ngx_parse_time, NGX_ERROR as NGX_PARSE_ERROR};
pub use proxy_protocol::{
    ngx_proxy_protocol_v1_parse_inet, ngx_proxy_protocol_v2_parse_inet, ProxyV2Inet,
};
pub use radix::{RadixNode, RadixTree32, NGX_RADIX_NO_VALUE};
pub use escape_uri::{
    ngx_escape_args, ngx_escape_args_count, ngx_escape_uri_component_count,
};
pub use unescape_uri::{ngx_unescape_uri, NGX_UNESCAPE_URI};
pub use crc32::{
    ngx_crc32_final, ngx_crc32_init, ngx_crc32_long, ngx_crc32_long_table, ngx_crc32_short,
    ngx_crc32_short_nibble, ngx_crc32_update,
};
pub use hash::{ngx_hash, ngx_hash_key, ngx_hash_key_lc, ngx_tolower};
pub use inet::{
    ngx_inet6_addr, ngx_inet_addr, INADDR_NONE, NGX_INET_ERROR, NGX_OK as NGX_INET_OK,
};
pub use ip_hash::{ngx_ip_hash_mix, ngx_ip_hash_select};
pub use limit_req::{ngx_limit_req_allows, ngx_limit_req_excess};
pub use murmurhash::{ngx_murmur_hash2, ngx_murmur_hash2_ptr};
pub use rbtree::ngx_rbtree_timer_less;
pub use sort::{ngx_sort, ngx_sort_legacy};
pub use split_clients::ngx_split_clients_pick;
pub use string::{ngx_strnstr, ngx_strnstr_bytes};
pub use sub_filter::{ngx_http_sub_find, ngx_http_sub_init_tables, SubMatch, SubTables};
pub use utf8::{ngx_utf8_decode, ngx_utf8_decode_scan};
