#!/usr/bin/env bash
# proxies/nginx.sh — bench nginx as a reverse proxy.
#
# Uses the system-installed nginx (apt). Needs sudo because nginx's
# default config writes to /var/log and binds with reuseport on a
# privileged-style listener; stop_proxy also uses sudo because the
# master process runs as root.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="nginx"

start_proxy() {
  echo_sub "start nginx on :$PROXY_PORT"
  sudo nginx -c "$CONFIGS_DIR/nginx.conf" -p "$BENCH_DIR/" \
    >"$RESULTS_DIR/_nginx.log" 2>&1
  wait_for_port "$PROXY_PORT" 10
}

stop_proxy() {
  sudo pkill -f 'nginx: master' 2>/dev/null || true
  sudo pkill -f 'nginx: worker' 2>/dev/null || true
  sleep 2
}

main() {
  echo_step "PROXY: $PROXY"
  ensure_infra
  trap stop_proxy EXIT
  stop_proxy
  start_proxy || { echo "    SKIP: $PROXY failed to start"; return 1; }
  run_sweep "$PROXY" "$PROXY_PORT"
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
