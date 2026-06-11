#!/usr/bin/env bash
# bench-profile.sh — criterion benchmarks for lynxx_structures (ATS + papers)
#
# Usage:
#   ./bench-profile.sh              # all structure benches
#   ./bench-profile.sh ats          # ATS-ported only
#   ./bench-profile.sh papers       # ARC + W-TinyLFU
#   ./bench-profile.sh structures_arc_cache
#   ./bench-profile.sh --flame structures_bravo_lock
set -euo pipefail

FLAME=false
if [[ "${1:-}" == "--flame" ]]; then
    FLAME=true
    shift
fi

FILTER="${1:-}"

BENCH_TARGETS=(
    structures_arc_cache
    structures_wtinylfu
    structures_clfus_cache
    structures_bravo_lock
    structures_clock_cache
    structures_write_buffer
)

ATS_TARGETS=(
    structures_clfus_cache
    structures_bravo_lock
    structures_clock_cache
    structures_write_buffer
)

PAPER_TARGETS=(
    structures_arc_cache
    structures_wtinylfu
)

run_bench() {
    local target="$1"
    echo "=== $target ==="
    cargo bench -p lynxx_structures --bench "$target" 2>&1
    if $FLAME; then
        echo "--- flamegraph: $target ---"
        cargo flamegraph -p lynxx_structures --bench "$target" \
            -o "flamegraphs/${target}.svg" -- --bench 2>&1 \
            || echo "(flamegraph skipped — install cargo-flamegraph)"
    fi
}

mkdir -p flamegraphs

if [[ -z "$FILTER" ]]; then
    for t in "${BENCH_TARGETS[@]}"; do
        run_bench "$t"
    done
elif [[ "$FILTER" == "all" ]]; then
    for t in "${BENCH_TARGETS[@]}"; do
        run_bench "$t"
    done
elif [[ "$FILTER" == "ats" ]]; then
    for t in "${ATS_TARGETS[@]}"; do
        run_bench "$t"
    done
elif [[ "$FILTER" == "papers" ]]; then
    for t in "${PAPER_TARGETS[@]}"; do
        run_bench "$t"
    done
else
    run_bench "$FILTER"
fi

echo ""
echo "Done. HTML reports in target/criterion/"
