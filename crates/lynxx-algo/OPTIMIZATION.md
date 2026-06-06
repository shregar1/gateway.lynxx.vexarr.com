# Optimization notes

## Strategy

1. **Correctness** — `cargo test` vs `tests/c/nginx_algos.c`.
2. **Beat NGINX C** on every benchmarked hot path (or match within measurement noise).
3. **Profile** — `./scripts/flamegraph.sh` → `flamegraph.svg` or `samply-profile.json.gz`.

## Techniques

| Function | Approach |
|----------|----------|
| `ngx_crc32_short` / `long` | `crc32fast` (bit-identical); `ngx_crc32_short_nibble` kept for reference |
| `ngx_hash_key` / `ngx_hash_key_lc` | 8/16-byte `31^n` folding; LC uses `ASCII_LOWER` LUT |
| `ngx_murmur_hash2` | 4× unrolled `mix_into` + identical tail (≥ C on 64 KiB) |
| `ngx_escape_uri_count` | Compile-time `[bool;256]` from NGINX bitmap; 8-byte unroll |
| `ngx_utf8_decode_scan` | ASCII run skip + inlined 3-byte UTF-8 fast path |
| `ngx_split_clients_pick` | Tight index loop (no iterator) |
| `ngx_strnstr` | Fast NUL bound + `memchr` for haystack ≥512 B |
| `ngx_ip_hash_mix` | 4-byte unroll |
| `ngx_limit_req_excess` | Inlined ms clamp |
| `ngx_rbtree_timer_less` | `#[inline(always)]` wrapping compare |

## Flamegraph

```bash
./scripts/flamegraph.sh                     # default: profile-hot
./scripts/flamegraph.sh vs_nginx_c
./scripts/flamegraph.sh algorithms ngx_crc32
```

macOS without Xcode uses **samply** automatically.

Build uses `-C target-cpu=native` via `.cargo/config.toml` for release/bench.

## Compare

```bash
cargo bench --bench vs_nginx_c
```

See [BENCHMARKS.md](BENCHMARKS.md) for sample numbers.
