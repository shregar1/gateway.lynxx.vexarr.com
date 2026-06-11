#!/usr/bin/env bash
# Run perf record against a live lynxx-gateway under load and emit a
# flamegraph SVG. Designed for the single-VM bench rig.
#
# Env overrides:
#   PROFILE_RPS         target RPS (default 100000)
#   PROFILE_CONNS       client connections (default 4096)
#   PROFILE_BENCH_SECS  bench duration in seconds (default 30)
#   PROFILE_RECORD_SECS perf record window in seconds (default 20)
#   PROFILE_TAG         label embedded in output file names / flame title
#                       (default "${PROFILE_RPS}rps-${PROFILE_CONNS}c")
#
# Flow:
#   1. Ensure infra (mock upstream + auth stub) is up — borrows
#      ensure_infra from lib/common.sh.
#   2. Start lynxx-gateway with the bench TOML (same config the bench
#      itself uses, so what we profile == what we benched).
#   3. Sleep ~5s for the pool to warm.
#   4. Spawn lynxx-bench in the background.
#   5. After 3s of warmup, `perf record -p <lynxx-pid> -F 99 -g
#      --call-graph dwarf` for PROFILE_RECORD_SECS seconds — captures
#      the sustained-load window, not startup transients.
#   6. Stop lynxx-bench, kill lynxx-gateway, then folded-stacks + SVG.
#
# Output: $RESULTS_DIR/lynxx-flame-$TAG.svg + lynxx-perf-$TAG.folded.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/bench.conf"
source "$HERE/lib/common.sh"

PROXY="lynxx"
CONFIG_TOML="/tmp/lynxx-bench.toml"

PROFILE_RPS="${PROFILE_RPS:-100000}"
PROFILE_CONNS="${PROFILE_CONNS:-4096}"
PROFILE_BENCH_SECS="${PROFILE_BENCH_SECS:-30}"
PROFILE_RECORD_SECS="${PROFILE_RECORD_SECS:-20}"
PROFILE_TAG="${PROFILE_TAG:-${PROFILE_RPS}rps-${PROFILE_CONNS}c}"

PERF_DATA="$RESULTS_DIR/lynxx-perf-${PROFILE_TAG}.data"
PERF_FOLDED="$RESULTS_DIR/lynxx-perf-${PROFILE_TAG}.folded"
FLAME_SVG="$RESULTS_DIR/lynxx-flame-${PROFILE_TAG}.svg"

write_config() {
  cat > "$CONFIG_TOML" <<EOF
[gateway]
proxy_port = $PROXY_PORT
admin_port = $LYNXX_ADMIN_PORT
database_url = "sqlite::memory:"
seed_from_config = true
minimal_telemetry = true
health_check_interval_ms = 3600000
prewarm_interval_secs = 3600
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

cleanup() {
  pkill -f 'lynxx-gateway --config /tmp/lynxx-bench.toml' 2>/dev/null || true
  pkill -f 'lynxx-bench --target' 2>/dev/null || true
}
trap cleanup EXIT

echo_step "PROFILE: lynxx @ ${PROFILE_RPS} RPS / ${PROFILE_CONNS} conns under perf"
ensure_infra

cleanup; sleep 1
write_config

echo_sub "start lynxx-gateway"
AUTH_URL="$AUTH_URL" LYNXX_API_KEY="$LYNXX_API_KEY" \
  LYNXX_ALLOW_DEV_KEY="$LYNXX_ALLOW_DEV_KEY" RUST_LOG="$LYNXX_RUST_LOG" \
  nohup "$SRC_DIR/target/release/lynxx-gateway" --config "$CONFIG_TOML" \
  >"$RESULTS_DIR/_lynxx-profile-${PROFILE_TAG}.log" 2>&1 &
LYNXX_PID=$!
wait_for_port "$PROXY_PORT" 30

echo_sub "warmup 5s"
sleep 5

echo_sub "fire bench (${PROFILE_RPS}/${PROFILE_BENCH_SECS}s/${PROFILE_CONNS}c, in background)"
"$SRC_DIR/target/release/lynxx-bench" \
  --target "http://127.0.0.1:${PROXY_PORT}/bench" \
  --rps "$PROFILE_RPS" --duration-secs "$PROFILE_BENCH_SECS" \
  --connections "$PROFILE_CONNS" --warmup-secs 3 \
  >"$RESULTS_DIR/_lynxx-bench-${PROFILE_TAG}.txt" 2>&1 &
BENCH_PID=$!

echo_sub "wait 3s for bench warmup, then perf record ${PROFILE_RECORD_SECS}s on pid=$LYNXX_PID"
sleep 3
sudo perf record -F 99 -p "$LYNXX_PID" -g --call-graph dwarf -o "$PERF_DATA" -- sleep "$PROFILE_RECORD_SECS"

echo_sub "wait for bench to finish"
wait "$BENCH_PID" 2>/dev/null || true

echo_sub "stop lynxx-gateway"
cleanup
sleep 1

echo_sub "fold + SVG"
sudo perf script -f -i "$PERF_DATA" \
  | "$HOME/.cargo/bin/inferno-collapse-perf" \
  > "$PERF_FOLDED"
"$HOME/.cargo/bin/inferno-flamegraph" \
  --title "lynxx-gateway @ ${PROFILE_RPS} RPS / ${PROFILE_CONNS} conns" \
  < "$PERF_FOLDED" > "$FLAME_SVG"

echo
echo "perf.data : $PERF_DATA"
echo "folded    : $PERF_FOLDED"
echo "flamegraph: $FLAME_SVG"
echo
echo "Top-20 hot functions (by inclusive samples):"
sort -k2 -nr "$PERF_FOLDED" | head -20
