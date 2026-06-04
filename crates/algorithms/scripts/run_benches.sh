#!/usr/bin/env bash
# Resilient + RESUMABLE benchmark runner. Runs every [[bench]] target
# one-at-a-time so a single crash (OOM/SIGKILL) or an outer timeout cannot lose
# progress. Completed targets are recorded in scripts/.bench_done and skipped on
# re-invocation, so you can call this repeatedly until it reports all-done.
#
# Usage:
#   bash scripts/run_benches.sh           # resume (skip already-done)
#   bash scripts/run_benches.sh --fresh   # wipe state + criterion, start over
set -uo pipefail
cd "$(dirname "$0")/.."

LOG="scripts/bench_run.log"
DONE="scripts/.bench_done"

if [[ "${1:-}" == "--fresh" ]]; then
  rm -f "$DONE"; : > "$LOG"
  # criterion lives at the workspace root target/, not the crate's
  rm -rf ../../target/criterion 2>/dev/null || rm -rf target/criterion 2>/dev/null
  echo "fresh start: cleared state + criterion" | tee -a "$LOG"
fi
touch "$DONE"

targets=$(grep -A2 '^\[\[bench\]\]' Cargo.toml | grep '^name = ' | sed 's/name = "//;s/"//')
total=$(echo "$targets" | wc -l | tr -d ' ')

i=0; ok=0; fail=0; skip=0
for t in $targets; do
  i=$((i+1))
  if grep -qxF "$t" "$DONE"; then
    skip=$((skip+1)); continue
  fi
  printf "[%3d/%3d] %-34s " "$i" "$total" "$t" | tee -a "$LOG"
  if cargo bench -p algorithms --bench "$t" >>"$LOG" 2>&1; then
    echo "OK" | tee -a "$LOG"; echo "$t" >> "$DONE"; ok=$((ok+1))
  else
    echo "FAIL (exit $?)" | tee -a "$LOG"; fail=$((fail+1))
  fi
done

remaining=$(( total - $(wc -l < "$DONE" | tr -d ' ') ))
echo "----------------------------------------" | tee -a "$LOG"
echo "this pass: $ok OK, $fail FAIL, $skip skipped | total done $(wc -l < "$DONE" | tr -d ' ')/$total, remaining $remaining" | tee -a "$LOG"
[[ "$remaining" -eq 0 ]] && echo "ALL DONE" | tee -a "$LOG"
