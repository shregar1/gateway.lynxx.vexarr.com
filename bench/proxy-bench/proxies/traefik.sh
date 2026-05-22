#!/usr/bin/env bash
# proxies/traefik.sh — bench traefik in docker, --network host.
#
# Traefik split-config: static config tells it where to listen and how
# to find providers; dynamic config (the routers/services block) is
# loaded from a file provider. The pre-existing configs/traefik.yml is
# dynamic-only, which is why earlier runs saw "container started but
# :28080 never opened" — traefik had no entryPoint defined. We supply
# a static config inline via CLI flags so the dynamic file is loaded
# correctly.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="traefik"
CONTAINER="bench-traefik"

start_proxy() {
  echo_sub "start traefik on :$PROXY_PORT (docker, --network host, image=$TRAEFIK_IMAGE)"
  sg docker -c "docker run -d --rm --name $CONTAINER --network host \
    -v $CONFIGS_DIR/traefik.yml:/etc/traefik/dynamic.yml \
    $TRAEFIK_IMAGE \
    --entrypoints.web.address=:$PROXY_PORT \
    --providers.file.filename=/etc/traefik/dynamic.yml \
    --log.level=ERROR \
    --accesslog=false" \
    >"$RESULTS_DIR/_traefik.log" 2>&1
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
