#!/usr/bin/env bash
# Compare Rust vs NGINX C median times for each vs_nginx_c group.
set -euo pipefail
cd "$(dirname "$0")/.."

# Extract first median time in nanoseconds from a criterion line.
time_ns() {
  local line="$1"
  if echo "$line" | grep -q 'ns '; then
    echo "$line" | sed -E 's/.*\[([0-9.]+) ns.*/\1/'
  elif echo "$line" | grep -q 'µs '; then
    awk -v u="$(echo "$line" | sed -E 's/.*\[([0-9.]+) µs.*/\1/')" 'BEGIN{printf "%.0f", u*1000}'
  elif echo "$line" | grep -q 'ms '; then
    awk -v m="$(echo "$line" | sed -E 's/.*\[([0-9.]+) ms.*/\1/')" 'BEGIN{printf "%.0f", m*1000000}'
  else
    echo ""
  fi
}

groups=$(grep -o 'benchmark_group("[^"]*")' benches/vs_nginx_c.rs | sed 's/.*"\([^"]*\)"/\1/' | sort -u)

echo "group,rust_ns,c_ns,winner"
for g in $groups; do
  out=$(cargo bench --bench vs_nginx_c -- "$g" --noplot --sample-size 15 2>&1) || true
  rust_line=$(echo "$out" | grep -E "${g}/rust|rust_ngx" | grep "time:" | head -1)
  c_line=$(echo "$out" | grep -E "${g}/nginx_c|nginx_c_insertion" | grep "time:" | head -1)
  rust=$(time_ns "$rust_line")
  c=$(time_ns "$c_line")
  if [[ -n "$rust" && -n "$c" ]]; then
    win=$(awk -v r="$rust" -v c="$c" 'BEGIN{print (r+0 <= c+0) ? "rust" : "nginx_c"}')
    echo "$g,$rust,$c,$win"
  else
    echo "$g,,,skip"
  fi
done
