# nginx-algo

NGINX core algorithms in **optimized Rust**, verified against compiled NGINX C, with Criterion benchmarks and flamegraph profiling.

## Quick start

```bash
cargo test                    # 33 parity tests (Rust == NGINX C output)
cargo bench                   # throughput
cargo bench --bench vs_nginx_c  # Rust vs C on same machine
./scripts/flamegraph.sh algorithms
```

## Design

| Layer | Purpose |
|-------|---------|
| **Public API** | Fast, robust Rust (`ngx_*`) — same results as NGINX where tested |
| **`tests/c/nginx_algos.c`** | Verbatim C extracts for ground-truth comparison |
| **`ngx_crc32_long_table`** | Legacy table CRC (parity / C bench baseline) |

## Functions

| Rust | NGINX C | Notes |
|------|---------|-------|
| `ngx_murmur_hash2` | `ngx_murmur_hash2` | C-identical; `read_unaligned` u32 (≥ C on 64 KiB) |
| `ngx_encode_base64` / `ngx_decode_base64` | same | 12-byte encode unroll; decode LUT |
| `ngx_encode_base64url` / `ngx_decode_base64url` | same | URL alphabet, no padding |
| `ngx_hextoi` / `ngx_hex_dump` | same | Hex LUT; 8-byte dump unroll |
| `ngx_escape_uri_count` | `ngx_escape_uri` | `[bool;256]` LUT (~1.4× count path) |
| `ngx_inet_addr` / `ngx_inet6_addr` | same | IPv4/IPv6 parsers |
| `ngx_unescape_uri` | `ngx_unescape_uri` | ~1.3× vs C (URI mode) |
| `ngx_atosz` / `ngx_atoi` | `ngx_atosz` / `ngx_atoi` | Decimal parsers |
| `ngx_parse_time` | `ngx_parse_time` | Config time → ms |
| `ngx_escape_args_count` | `ngx_escape_uri` (ARGS) | Query-string escape count |
| `RadixTree32::find` | `ngx_radix32tree_find` | Geo/map IPv4 LPM |
| `ngx_hash_key_lc` | `ngx_hash_key_lc` | ~2× vs C |
| `ngx_utf8_decode_scan` | `ngx_utf8_decode` | ~2.5× scan path |
| `ngx_split_clients_pick` | split_clients | |
| `ngx_crc32_long` | `ngx_crc32_long` | **`crc32fast`** (~20× vs C table) |
| `ngx_crc32_short` | `ngx_crc32_short` | **`crc32fast`** (~48× vs C nibble loop) |
| `ngx_hash_key` | `ngx_hash_key` | 8-byte DJB fold (~30% faster) |
| `ngx_strnstr` | `ngx_strnstr` | NUL bound + `memchr` (up to ~9× on long hay) |
| `ngx_http_sub_*` | sub_filter | Horspool + validation |
| `ngx_limit_req_excess` | limit_req | leaky bucket step |
| `ngx_ip_hash_mix` | ip_hash | |
| `ngx_sort` | `ngx_sort` | stable; fast path for n≥32 |

## Robustness

- `ngx_http_sub_init_tables` → `Result` (rejects empty patterns)
- `SubMatch::validate` for config-time checks
- Targeted `unsafe` on hot paths (pointer scans); C linked only in tests/benches
- `#[inline]` / `#[inline(always)]` on hot paths

## Profiling & tuning

See [OPTIMIZATION.md](OPTIMIZATION.md) and [BENCHMARKS.md](BENCHMARKS.md).

```bash
cargo install flamegraph   # once
./scripts/flamegraph.sh vs_nginx_c crc32_long
```

## Example

```rust
use nginx_algo::{ngx_crc32_long, ngx_murmur_hash2, ngx_strnstr};

let _ = ngx_murmur_hash2(b"192.168.0.1");
let _ = ngx_crc32_long(b"body");
let _ = ngx_strnstr(b"GET / HTTP/1.1\r\n", "GET");
```
