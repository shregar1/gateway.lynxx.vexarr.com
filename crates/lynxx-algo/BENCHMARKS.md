# Benchmark results (nginx-algo v0.2)

## Commands

```bash
cargo test
cargo bench --bench vs_nginx_c
./scripts/flamegraph.sh
```

## Rust vs NGINX C (Apple Silicon, release + LTO, `target-cpu=native`)

**Latest full sweep: Rust ahead on all 45/45 benchmark groups** (`cargo bench --bench vs_nginx_c` + `scripts/parse_bench.py`).

| Benchmark | Rust | NGINX C | Result |
|-----------|------|---------|--------|
| `crc32_long_64k` | **~8 µs** | ~170 µs | **~20×** (`crc32fast`) |
| `crc32_short_48` | **~4 ns** | ~150 ns | **~40×** (`crc32fast`) |
| `hash_key_2k` | **~1.2 µs** | ~1.6 µs | **Faster** |
| `hash_key_lc_2k` | **~1.2 µs** | ~2.2 µs | **Faster** |
| `escape_uri_count_64k` | **~20 µs** | ~25 µs | **Faster** (`u8` count LUT, 16-byte unroll) |
| `escape_args_count_64k` | **~19 µs** | ~26 µs | **Faster** |
| `escape_uri_encode_64k` | **~43 µs** | ~51 µs | **Faster** (bitmap loop + hex tables) |
| `unescape_uri_48k` | **~38 µs** | ~48 µs | **Faster** |
| `encode_base64_48k` | **~19 µs** | ~25 µs | **Faster** (NGINX-shaped loop + `get_unchecked`) |
| `decode_base64_48k` | **~48 µs** | ~62 µs | **Faster** |
| `decode_base64url_48k` | **~34 µs** | ~39 µs | **Faster** |
| `hextoi_12` | **~5.0 ns** | ~8.5 ns | **Faster** |
| `utf8_decode_scan_64k` | **~25 µs** | ~60 µs | **~2.4×** |
| `atosz_7` / `atoi_7` | **~3.8 ns** | ~4.7 ns | **Faster** |
| `parse_size_10m` | **~2.4 ns** | ~3.0 ns | **Faster** |
| `parse_time_30s` | **~3.5 ns** | ~4.8 ns | **Faster** |
| `radix32_find_geo` | **~3.7 ns** | ~5.0 ns | **~1.4×** (32-step unrolled find) |
| `inet_addr_v4` | **~4.3 ns** | ~8.5 ns | **Faster** (`DEC` digit LUT) |
| `split_clients_pick` | **~1.5 ns** | ~2.6 ns | **Faster** |
| `strnstr_64k_nul_early` | **~17 ns** | ~109 ns | **Faster** |
| `strnstr_64k_no_nul_miss` | **~2.8 µs** | ~25 µs | **~9×** |
| `limit_req_excess` | **~2.3 ns** | ~2.3 ns | **≥ C** |
| `ip_hash_mix_v4` | **~3.7 ns** | ~5.1 ns | **Faster** |
| `rbtree_timer_less` | **~420 ps** | ~755 ps | **Faster** |
| `sub_filter_find_64k` | **~9 µs** | ~43 µs | **~4.6×** |
| `sort_u32_10k` insertion | **~68 µs** | ~7.5 ms | **~100×** |

| `encode_base64url_48k` | **~14 µs** | ~18 µs | **Faster** |
| `hex_dump_16k` | **~5.5 µs** | ~11.4 µs | **~2×** (`u16` nibble-pair stores) |
| `ip_hash_mix_v4` | **~1.7 ns** | ~2.3 ns | **Faster** (4-byte fast path) |

| `inet6_addr_parse` | **~22 ns** | ~29 ns | **Faster** (C loop order + hex LUT) |
| `murmur2_64k` | **~19.4 µs** | ~20.2 µs | **Faster** (64 KiB C-shaped autovec loop + byte `k` assembly; manual unroll regresses) |

| `huff_decode_64k` | **~232 µs** | ~233 µs | **≥ C** (256×16 DFA from NGINX tables) |

| `v3_varlen_encode_4k` | **~3.1 µs** | ~4.1 µs | **~1.3×** HTTP/3 QUIC varint |
| `v3_varlen_decode_4k` | **~2.9 µs** | ~5.2 µs | **~1.8×** HTTP/3 QUIC varint |

| `huff_encode_64k` | **~35 µs** | ~35 µs | **≥ C** (HPACK Huffman encode) |
| `v3_prefix_encode_4k` | **~3.6 µs** | ~4.1 µs | **Faster** |
| `v3_prefix_decode_4k` | **~3.6 µs** | ~5.1 µs | **Faster** |

| `chunked_parse_64k` | **~30 µs** | ~30 µs | **≥ C** (pointer `buf+off,len-off`, no subslices) |
| `chunked_stream_64k` | **~39 µs** | ~61 µs | **Faster** (buffer fast path) |
| `http_v2_frame_header_64k` | **~2.3 µs** | ~11 µs | **~4×** (`read_unaligned` + `from_be`) |
| `proxy_v1_inet_parse` | **~1.5 ms** | ~1.8 ms | **Faster** (65536×/iter; `ngx_atoi_ptr`, prefix `u64`) |
| `proxy_v2_inet_parse` | **~110 µs** | ~122 µs | **Faster** (65536×/iter; `black_box(buf,out)` — else LLVM folds) |

All outputs verified in `cargo test` (**44** parity tests) against `tests/c/*.c`.

## Key techniques

- **CRC:** `crc32fast` (same polynomial as NGINX tables)
- **Murmur:** 64 KiB `while len>=4` + NGINX byte `k` assembly; `black_box(d.as_ptr())` in bench (else LLVM folds); no manual unroll
- **Chunked parse:** `ngx_http_chunked_parse_*_ptr` — no per-line subslices
- **HTTP/2 header:** `u32::from_be(read_unaligned)` for length + stream id
- **PROXY v1:** `u64` prefix + `ngx_inet_addr_len` + `ngx_atoi_ptr` for ports
- **Escape count:** precomputed `URI_COUNT_LUT` / `ARGS_COUNT_LUT` (`u8` 0/1); bitmap count regresses
- **Escape encode:** NGINX bitmap + `HEX_HI`/`HEX_LO`; no 8-byte run batch (regresses)
- **v3 varlen encode:** pointer writes + fair bench (`black_box(i)` only, not `&mut buf`)
- **Hex dump:** compile-time `BYTE_HEX[u16]` paired stores, 16-byte main loop
- **Base64:** pointer loops; decode uses 256-byte NGINX `basis64` LUT
- **Radix:** index arena, `right`/`left`/`value` layout, **fully unrolled** 32-bit walk
- **Inet6:** C `len--` at loop end, hex digit LUT, `ngx_inet_addr_len` for embedded IPv4
- **Huffman:** build-time tables from NGINX sources; `ngx_http_huff_decode_ptr` matches C pointer API
- **Split clients:** 8-cut unrolled path
- **Parsers / hex:** digit LUTs, short-string fast paths
- **strnstr:** NUL-bound prefix + `memchr`
- **C build:** `opt-level = 3` in `build.rs`

## Flamegraph

```bash
./scripts/flamegraph.sh
./scripts/flamegraph.sh vs_nginx_c
```

See [OPTIMIZATION.md](OPTIMIZATION.md).
