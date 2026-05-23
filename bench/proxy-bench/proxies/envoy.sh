#!/usr/bin/env bash
# proxies/envoy.sh — bench envoy in docker, --network host.
#
# Host networking means envoy binds :28080 on the host directly (no
# user-space docker-proxy in the hot path). Lets envoy see the same
# latency floor as the native proxies.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="envoy"
CONTAINER="bench-envoy"

start_proxy() {
  echo_sub "start envoy on :$PROXY_PORT (docker, --network host, image=$ENVOY_IMAGE)"
  sg docker -c "docker run -d --rm --name $CONTAINER --network host \
    -v $CONFIGS_DIR/envoy.yaml:/etc/envoy/envoy.yaml \
    $ENVOY_IMAGE -c /etc/envoy/envoy.yaml" \
    >"$RESULTS_DIR/_envoy.log" 2>&1
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
