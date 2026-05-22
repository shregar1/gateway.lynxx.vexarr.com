#!/usr/bin/env bash
# proxies/lynxx.sh — bench lynxx-gateway natively.
#
# Minimal in-memory config with one route /bench → mock upstream.
# RUST_LOG is capped via bench.conf's LYNXX_RUST_LOG (default "error")
# because earlier runs filled /var with a 74 GB _lynxx.log.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../bench.conf"
source "$HERE/../lib/common.sh"

PROXY="lynxx"
CONFIG_TOML="/tmp/lynxx-bench.toml"

write_config() {
  cat > "$CONFIG_TOML" <<EOF
[gateway]
proxy_port = $PROXY_PORT
admin_port = $LYNXX_ADMIN_PORT
database_url = "sqlite::memory:"
seed_from_config = true
minimal_telemetry = true
health_check_interval_ms = 30000

[[services]]
name = "bench"
url = "http://127.0.0.1:$UPSTREAM_PORT"
retries = 0
connect_timeout_ms = 1000

[[routes]]
service = "bench"
paths = ["/bench"]
methods = ["GET","POST"]
strip_path = true
EOF
}

start_proxy() {
  echo_sub "start lynxx-gateway on :$PROXY_PORT (RUST_LOG=$LYNXX_RUST_LOG)"
  write_config
  AUTH_URL="$AUTH_URL" LYNXX_API_KEY="$LYNXX_API_KEY" RUST_LOG="$LYNXX_RUST_LOG" \
    nohup "$SRC_DIR/target/release/lynxx-gateway" --config "$CONFIG_TOML" \
    >"$RESULTS_DIR/_lynxx.log" 2>&1 &
  wait_for_port "$PROXY_PORT" 30
}

stop_proxy() {
  pkill -f 'lynxx-gateway' 2>/dev/null || true
  sleep 2
}

main() {
  echo_step "PROXY: $PROXY"
  ensure_infra
  trap stop_proxy EXIT
  stop_proxy  # idempotent — clear any prior instance
  start_proxy || { echo "    SKIP: $PROXY failed to start"; return 1; }
  run_sweep "$PROXY" "$PROXY_PORT"
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
