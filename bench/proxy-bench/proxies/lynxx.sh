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
# Background workers effectively off: bench duration is 15s, so a
# 1-hour timer never fires. Setting these to 0 would be cleaner but
# tokio::time::interval(Duration::ZERO) panics on startup — the
# crate doesn't currently treat 0 as "disabled".
# Kong runs neither in its DB-less bench mode; matching that is fair.
health_check_interval_ms = 3600000
prewarm_interval_secs = 3600
# Upstream keepalive pool sized to match the high-RPS bench. The crate
# default (128) was the same kind of bottleneck traefik had pre-tune —
# at 100k RPS / 8 cores that's ~16 idle conns/core and lynxx ends up
# tearing down + recreating upstream sockets nearly every request.
# Other tuned gateways in this bench rig use 1024-10000:
#   nginx: keepalive 1024, kong: 10000, traefik: 10000.
pool_max_idle_per_host = 10000
pool_idle_timeout_secs = 75

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
  AUTH_URL="$AUTH_URL" LYNXX_API_KEY="$LYNXX_API_KEY" \
    LYNXX_ALLOW_DEV_KEY="$LYNXX_ALLOW_DEV_KEY" RUST_LOG="$LYNXX_RUST_LOG" \
    nohup "$SRC_DIR/target/release/lynxx-gateway" --config "$CONFIG_TOML" \
    >"$RESULTS_DIR/_lynxx.log" 2>&1 &
  wait_for_port "$PROXY_PORT" 30
}

stop_proxy() {
  # SIGKILL — the bench-side ladder relies on stop+start being
  # near-instant. Newer lynxx-gateway builds added a 30s graceful
  # drain on SIGTERM, which kept the OLD process holding :28080
  # while the next bench level's start_proxy raced to bind it. The
  # new instance silently failed on bind and wait_for_port timed out
  # after 30s with "SKIP: lynxx failed to start". Force-kill here is
  # safe because the bench owns the process lifecycle end-to-end.
  pkill -9 -f 'lynxx-gateway' 2>/dev/null || true
  # Wait for :28080 to actually free (forced exit can leave the
  # socket in TIME_WAIT briefly).
  for _ in 1 2 3 4 5; do
    ss -tln 2>/dev/null | grep -q ":28080 " || break
    sleep 1
  done
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
