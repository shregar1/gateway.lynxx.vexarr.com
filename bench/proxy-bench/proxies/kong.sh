#!/usr/bin/env bash
# proxies/kong.sh — bench kong in docker, --network host, DB-less mode.
#
# KONG_DATABASE=off + declarative YAML is the lowest-overhead kong
# deployment — no postgres roundtrip, no admin API in the hot path.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="kong"
CONTAINER="bench-kong"

start_proxy() {
  echo_sub "start kong on :$PROXY_PORT (docker, declarative DB-less, image=$KONG_IMAGE)"
  # The KONG_NGINX_* + KONG_UPSTREAM_KEEPALIVE_* knobs match the tuned
  # standalone nginx.conf: workers=auto, big upstream keepalive pool
  # (10k idle conns, 1M reqs/conn), no access logs. Without these,
  # kong's defaults (~256 keepalive conns) bottleneck at ~30k RPS the
  # same way envoy did pre-tune.
  sg docker -c "docker run -d --rm --name $CONTAINER --network host \
    -e KONG_DATABASE=off \
    -e KONG_DECLARATIVE_CONFIG=/kong/kong.yml \
    -e KONG_PROXY_LISTEN=0.0.0.0:$PROXY_PORT \
    -e KONG_ADMIN_LISTEN='off' \
    -e KONG_LOG_LEVEL=error \
    -e KONG_PROXY_ACCESS_LOG=off \
    -e KONG_PROXY_ERROR_LOG=/dev/null \
    -e KONG_NGINX_WORKER_PROCESSES=auto \
    -e KONG_NGINX_HTTP_KEEPALIVE_REQUESTS=1000000 \
    -e KONG_NGINX_HTTP_KEEPALIVE_TIMEOUT=75s \
    -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=10000 \
    -e KONG_UPSTREAM_KEEPALIVE_MAX_REQUESTS=1000000 \
    -e KONG_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT=75 \
    -v $CONFIGS_DIR/kong.yml:/kong/kong.yml \
    $KONG_IMAGE" \
    >"$RESULTS_DIR/_kong.log" 2>&1
  wait_for_port "$PROXY_PORT" 60
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
