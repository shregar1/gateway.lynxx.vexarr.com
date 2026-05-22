#!/usr/bin/env bash
# proxies/direct.sh — no-proxy baseline.
#
# Hits the mock upstream directly. Establishes the ceiling that any
# proxy is measured against on this rig. p99 here is "what's left on
# the table" — kernel + client + upstream overhead.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="direct"

# direct has no start/stop — sweep targets the mock upstream port
# directly. We still define start_proxy/stop_proxy as no-ops so the
# orchestrator can call them uniformly across proxies.
start_proxy() { :; }
stop_proxy()  { :; }

main() {
  echo_step "PROXY: $PROXY"
  ensure_infra
  run_sweep "$PROXY" "$UPSTREAM_PORT"
}

# Only run main() when invoked as a script, not when sourced.
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
