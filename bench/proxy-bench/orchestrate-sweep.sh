#!/usr/bin/env bash
# orchestrate-sweep.sh — run multiple proxy sweeps in sequence.
#
# This is the entry point for the single-VM bench. Each proxy is its
# own script under proxies/<name>.sh and can be run standalone — the
# orchestrator just selects which ones to run, in what order, with a
# kernel-state cooldown between them.
#
# Usage:
#   ./orchestrate-sweep.sh                           # uses PROXIES_DEFAULT from bench.conf
#   PROXIES="lynxx kong" ./orchestrate-sweep.sh      # subset, override order
#   RPS_LEVELS="10000 25000" ./orchestrate-sweep.sh  # override any bench.conf var
#
# Output: per-level result files at $RESULTS_DIR/<proxy>-<rps>.txt and
# a combined driver log at $RESULTS_DIR/_driver.log.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/bench.conf"
source "$HERE/lib/common.sh"

# Wire stdout/stderr to the driver log AND the terminal. The tee
# survives across the for-loop because we exec it once for the whole
# script.
mkdir -p "$RESULTS_DIR"
exec > >(tee -a "$RESULTS_DIR/_driver.log") 2>&1

PROXIES_TO_RUN="${PROXIES:-$PROXIES_DEFAULT}"

echo_step "Single-VM bench orchestrator"
echo "RPS_LEVELS:    $RPS_LEVELS"
echo "DURATION:      ${DURATION_SECS}s   WARMUP: ${WARMUP_SECS}s   CONNECTIONS: $CONNECTIONS"
echo "Explode:       p99 > ${P99_EXPLODE_MS}ms OR err_rate > $ERR_EXPLODE_RATE"
echo "Proxies:       $PROXIES_TO_RUN"
echo "Cooldown:      ${COOLDOWN_SECS}s between proxies"
echo "Results dir:   $RESULTS_DIR"

# Always-on infra started once, kept alive across every proxy in the
# loop. Each proxies/<name>.sh also calls ensure_infra defensively, but
# this avoids the first-proxy waiting on stub startup.
ensure_infra

# Run each proxy in sequence. A proxy script may exit non-zero (start
# failure, partial ladder, etc.) — we want to KEEP GOING to the next
# proxy in that case, so `|| true` swallows the rc but the script's
# own log lines have already explained what happened.
for proxy in $PROXIES_TO_RUN; do
  script="$HERE/proxies/$proxy.sh"
  if [[ ! -f "$script" ]]; then
    echo "  WARN: $script missing — skipping $proxy"
    continue
  fi
  bash "$script" || echo "  WARN: $proxy script returned non-zero, continuing"

  # Cooldown lets TIME_WAIT drain + SYN-cookie state reset, so the
  # next proxy starts on a clean-ish kernel. Without it the kth proxy
  # sees worse numbers than the 1st purely from run order.
  if [[ "$proxy" != "$(echo "$PROXIES_TO_RUN" | awk '{print $NF}')" ]]; then
    echo "  cooldown: ${COOLDOWN_SECS}s"
    sleep "$COOLDOWN_SECS"
  fi
done

echo_step "DONE"
echo "Results: $RESULTS_DIR"
ls "$RESULTS_DIR"/*-*.txt 2>/dev/null | head -50
