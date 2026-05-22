#!/usr/bin/env bash
# proxies/haproxy.sh — bench haproxy as a reverse proxy.
#
# Earlier runs failed with:
#   [ALERT] FD limit (1048576) too low for maxconn=1000000/maxsock=2000108
# because haproxy reserves 2× FDs per conn (client + upstream side).
# Two ways to fix that: bump the kernel nofile cap, or lower maxconn.
# We pick the latter — configs/haproxy.cfg now sets maxconn=500000,
# which keeps maxsock under the default 1,048,576 nofile cap so
# haproxy boots on a stock Debian without root privileges to raise
# the hard limit (`ulimit -n 2200000` is denied by the kernel cap on
# this host).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="haproxy"

start_proxy() {
  echo_sub "start haproxy on :$PROXY_PORT"
  sudo haproxy -f "$CONFIGS_DIR/haproxy.cfg" -D \
    >"$RESULTS_DIR/_haproxy.log" 2>&1
  wait_for_port "$PROXY_PORT" 10
}

stop_proxy() {
  # Match the process *name* exactly — `pkill -f 'haproxy'` would also
  # match the running `bash proxies/haproxy.sh` script (because
  # "haproxy" is a substring of the script path), killing the script
  # and any parent ssh session before the bench could start.
  sudo pkill -x haproxy 2>/dev/null || true
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
