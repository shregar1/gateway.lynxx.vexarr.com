#!/usr/bin/env bash
# bench-profile.sh — run per-algorithm criterion benchmarks + optional flamegraph
#
# Usage:
#   ./bench-profile.sh                   # run all benchmarks
#   ./bench-profile.sh hash              # run only the hash group
#   ./bench-profile.sh hash_key          # run a single bench target
#   ./bench-profile.sh --flame hash_key  # bench + flamegraph for one target
#   ./bench-profile.sh optimized         # run all optimized comparison benchmarks
set -euo pipefail

FLAME=false
if [[ "${1:-}" == "--flame" ]]; then
    FLAME=true
    shift
fi

FILTER="${1:-}"

BENCH_TARGETS=(
    # hash (7)
    hash_key hash_key_lc hash_murmur2
    hash_crc32_short hash_crc32_long hash_crc32_long_table hash_crc32_short_nibble
    # encode (6)
    encode_base64_encode encode_base64_decode
    encode_hex_dump encode_hextoi
    encode_escape_uri encode_unescape_uri
    # codec (8)
    codec_huff_encode codec_huff_decode codec_h2_frame
    codec_h3_varint_encode codec_h3_varint_decode
    codec_chunked_parse_line codec_chunked_parse_fsm codec_chunked_header
    # parse (5)
    parse_atoi parse_atosz parse_size parse_time parse_conf_scan
    # string (4)
    string_strnstr string_sub_filter string_sort_fast string_sort_legacy
    # inet (8)
    inet_addr_v4 inet_addr_v6 inet_ip_hash
    inet_proxy_v1 inet_proxy_v2
    inet_limit_req_excess inet_limit_req_allows inet_split_clients
    # goals: hashing (2)
    hashing_siphash hashing_snowflake
    # goals: fingerprint (1)
    fingerprint_ja4
    # goals: http_codec (1)
    http_codec_range_slicer
    # goals: rate_limit (2)
    rate_limit_histogram rate_limit_ip_reputation
    # goals: resilience (1)
    resilience_cache_promote
)

OPT_TARGETS=(
    # optimized: comparison benchmarks (6)
    opt_crc32_vs opt_unescape_uri_vs opt_escape_uri_vs
    opt_base64_decode_vs opt_ja4_vs opt_huff_decode_vs
)

run_bench() {
    local target="$1"
    echo "=== $target ==="
    cargo bench -p algorithms --bench "$target" 2>&1
    if $FLAME; then
        echo "--- flamegraph: $target ---"
        cargo flamegraph --bench "$target" -o "flamegraphs/${target}.svg" -- --bench 2>&1 || echo "(flamegraph skipped — install cargo-flamegraph)"
    fi
}

mkdir -p flamegraphs

if [[ -z "$FILTER" ]]; then
    for t in "${BENCH_TARGETS[@]}"; do
        run_bench "$t"
    done
elif [[ "$FILTER" == "all" ]]; then
    for t in "${BENCH_TARGETS[@]}" "${OPT_TARGETS[@]}"; do
        run_bench "$t"
    done
elif [[ "$FILTER" == "optimized" || "$FILTER" == "opt" ]]; then
    for t in "${OPT_TARGETS[@]}"; do
        run_bench "$t"
    done
elif [[ "$FILTER" == hash || "$FILTER" == encode || "$FILTER" == codec || \
        "$FILTER" == parse || "$FILTER" == string || "$FILTER" == inet || \
        "$FILTER" == hashing || "$FILTER" == fingerprint || \
        "$FILTER" == rate_limit || "$FILTER" == resilience || \
        "$FILTER" == http_codec ]]; then
    for t in "${BENCH_TARGETS[@]}"; do
        if [[ "$t" == "${FILTER}_"* || "$t" == "${FILTER}" ]]; then
            run_bench "$t"
        fi
    done
else
    run_bench "$FILTER"
fi

echo ""
echo "Done. HTML reports in target/criterion/"
