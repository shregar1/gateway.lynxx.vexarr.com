#!/usr/bin/env bash
# Compare Rust vs nginx_c for all vs_nginx_c groups (one Criterion run).
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-/tmp/bench_compare.txt}"
cargo bench --bench vs_nginx_c -- --noplot --sample-size 15 2>&1 | tee "$out"
python3 scripts/parse_bench.py "$out"
