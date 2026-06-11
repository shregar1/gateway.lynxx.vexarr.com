#!/usr/bin/env bash
# Quick Rust vs C comparison (sample-size 15 minimum for Criterion).
set -uo pipefail
cd "$(dirname "$0")/.."

time_ns() {
  local line="$1"
  local mid
  if echo "$line" | grep -q 'time:.*\[.*ps '; then
    mid=$(echo "$line" | sed -E 's/.*\[([^ ]+) +ps +([^ ]+) +ps.*/\2 \1/')
    awk -v v="$(echo "$mid" | awk '{print $1}')" 'BEGIN{printf "%.0f", v/1000}'
  elif echo "$line" | grep -q 'time:.*\[.*ns '; then
    mid=$(echo "$line" | sed -E 's/.*\[([^ ]+) +ns +([^ ]+) +ns.*/\2 \1/')
    echo "$mid" | awk '{print $1}'
  elif echo "$line" | grep -q 'time:.*\[.*µs '; then
    mid=$(echo "$line" | sed -E 's/.*\[([^ ]+) +µs +([^ ]+) +µs.*/\2 \1/')
    awk -v u="$(echo "$mid" | awk '{print $1}')" 'BEGIN{printf "%.0f", u*1000}'
  elif echo "$line" | grep -q 'time:.*\[.*ms '; then
    mid=$(echo "$line" | sed -E 's/.*\[([^ ]+) +ms +([^ ]+) +ms.*/\2 \1/')
    awk -v m="$(echo "$mid" | awk '{print $1}')" 'BEGIN{printf "%.0f", m*1000000}'
  else
    echo ""
  fi
}

groups=$(grep -o 'benchmark_group("[^"]*")' benches/vs_nginx_c.rs | sed 's/.*"\([^"]*\)"/\1/' | sort -u)

losers=()
winners=0
total=0

echo "group,rust_ns,c_ns,winner"
for g in $groups; do
  out=$(cargo bench --bench vs_nginx_c -- "$g" --noplot --sample-size 15 2>&1) || true
  rust_line=$(echo "$out" | grep -E "${g}/(rust|rust_ngx|rust_crc32fast)" | grep "time:" | head -1)
  c_line=$(echo "$out" | grep -E "${g}/(nginx_c|nginx_c_insertion)" | grep "time:" | head -1)
  rust=$(time_ns "$rust_line")
  c=$(time_ns "$c_line")
  if [[ -n "$rust" && -n "$c" ]]; then
    total=$((total + 1))
    if awk -v r="$rust" -v c="$c" 'BEGIN{exit (r+0 <= c+0) ? 0 : 1}'; then
      win="rust"
      winners=$((winners + 1))
    else
      win="nginx_c"
      losers+=("$g:$rust:$c")
    fi
    echo "$g,$rust,$c,$win"
  else
    echo "$g,,,skip"
  fi
done

echo "---" >&2
echo "rust ahead: $winners / $total" >&2
if ((${#losers[@]} > 0)); then
  echo "LOSERS:" >&2
  printf '  %s\n' "${losers[@]}" >&2
fi
