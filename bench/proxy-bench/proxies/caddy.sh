#!/usr/bin/env bash
# proxies/caddy.sh — bench caddy in docker, --network host.
#
# Caddy 2 with HTTP/1.1 upstream pool and access-log disabled, mirror
# of how envoy/traefik/kong are run so the comparison stays fair.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="caddy"
CONTAINER="bench-caddy"

start_proxy() {
  echo_sub "start caddy on :$PROXY_PORT (docker, --network host, image=$CADDY_IMAGE)"
  sg docker -c "docker run -d --rm --name $CONTAINER --network host \
    -v $CONFIGS_DIR/Caddyfile:/etc/caddy/Caddyfile \
    $CADDY_IMAGE caddy run --config /etc/caddy/Caddyfile --adapter caddyfile" \
    >"$RESULTS_DIR/_caddy.log" 2>&1
  wait_for_port "$PROXY_PORT" 30
}

stop_proxy() {
  sg docker -c "docker rm -f $CONTAINER 2>/dev/null" || true
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
