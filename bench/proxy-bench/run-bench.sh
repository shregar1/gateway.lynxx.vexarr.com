#!/usr/bin/env bash
# Runs ON the client VM. For each proxy in $PROXIES:
#   - (orchestrator SSHs to SUT to start/stop the proxy — see below)
#   - For each RPS in $RPS_LEVELS, run lynxx-bench for $DURATION_SECS
#   - Mark "exploded" if p99 > P99_EXPLODE_MS or err_rate > ERR_EXPLODE_RATE
#   - Stop at first explosion, record peak as the last good level
#
# The proxy lifecycle (start/health/stop) is owned by the SUT via the
# helper functions below that SSH back to it. The client never SSHs to the
# SUT in the steady state — only at proxy-switch points.
set -euo pipefail
cd "$HOME/bench"
source .bench-env
RESULTS=$HOME/bench/results
mkdir -p "$RESULTS"

# Resolve SUT username (same as client) and SSH options
ME=$(whoami)
SSH_SUT="ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 $ME@$SUT_PRIV"

# ----- helpers --------------------------------------------------------------
start_upstream () {
  $SSH_SUT 'pkill -f lynxx-mock-upstream 2>/dev/null; \
            nohup ~/bench/lynxx-mock-upstream --port 19090 > ~/bench/upstream.log 2>&1 & \
            disown; sleep 1' || true
}

start_proxy () {
  local p="$1"
  if [[ "$p" == "direct" ]]; then return; fi
  $SSH_SUT "cd ~/bench && sg docker -c \"docker compose down --remove-orphans\" 2>/dev/null; \
            sg docker -c \"docker compose up -d $p\" >/dev/null"
  # health: wait up to 30s for proxy to answer on 28080
  for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null -m 2 "http://$SUT_PRIV:28080/"; then return; fi
    sleep 1
  done
  echo "ERROR: $p never became healthy"; return 1
}

stop_proxy () {
  $SSH_SUT 'cd ~/bench && sg docker -c "docker compose down --remove-orphans"' 2>/dev/null || true
  sleep 2
}

# Convert lynxx-bench's "Xms / Xµs / Xs" duration string to microseconds (int).
to_us () {
  python3 - "$1" <<'PY'
import sys
v = sys.argv[1].strip()
units = {"s":1_000_000, "ms":1_000, "µs":1, "us":1}
for u, mul in units.items():
    if v.endswith(u):
        print(int(float(v[:-len(u)]) * mul)); break
else:
    print(0)
PY
}

# Parse a single lynxx-bench run's stdout file → write summary line to CSV.
# Sets the global vars LAST_P99_US and LAST_ERR_RATE for the loop logic.
parse_run () {
  local f="$1" proxy="$2" rps="$3"
  local p50 p95 p99 p999 ach reqs errs
  p50=$(awk  '/^  p50:/{print $2; exit}' "$f")
  p95=$(awk  '/^  p95:/{print $2; exit}' "$f")
  p99=$(awk  '/^  p99:/{print $2; exit}' "$f")
  p999=$(awk '/^  p99\.9:/{print $2; exit}' "$f")
  ach=$(awk  '/^  achieved_rps:/{print $2; exit}' "$f")
  reqs=$(awk '/^  requests:/{gsub(",", "", $2); print $2; exit}' "$f")
  errs=$(awk '/^  errors:/{gsub(",", "", $2); print $2; exit}' "$f")
  : "${p99:=0ms}" "${reqs:=0}" "${errs:=0}" "${ach:=0}"
  LAST_P99_US=$(to_us "$p99")
  if [[ "$reqs" =~ ^[0-9]+$ ]] && (( reqs > 0 )); then
    LAST_ERR_RATE=$(awk -v e="$errs" -v r="$reqs" 'BEGIN{printf "%.6f", e/r}')
  else
    LAST_ERR_RATE=1.0
  fi
  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$proxy" "$rps" "$ach" "$p50" "$p95" "$p99" "$p999" "$errs" "$LAST_ERR_RATE" \
    >> "$RESULTS/summary.csv"
}

# Decide if a run "exploded".
exploded () {
  local p99_us="$1" err_rate="$2"
  local p99_limit_us=$(( P99_EXPLODE_MS * 1000 ))
  if (( p99_us > p99_limit_us )); then return 0; fi
  if awk -v e="$err_rate" -v t="$ERR_EXPLODE_RATE" 'BEGIN{exit !(e>t)}'; then return 0; fi
  return 1
}

# ----- main loop ------------------------------------------------------------
echo "proxy,rps_target,rps_achieved,p50,p95,p99,p99.9,errors,err_rate" > "$RESULTS/summary.csv"
echo > "$RESULTS/peaks.txt"

start_upstream

for proxy in $PROXIES; do
  echo "##########################################################"
  echo "# PROXY: $proxy"
  echo "##########################################################"

  if [[ "$proxy" == "direct" ]]; then
    target="http://$SUT_PRIV:19090/"   # bench straight to upstream
  else
    if ! start_proxy "$proxy"; then
      echo "$proxy SKIPPED — failed to start" >> "$RESULTS/peaks.txt"
      continue
    fi
    target="http://$SUT_PRIV:28080/"
  fi

  LAST_GOOD_RPS=0
  for rps in $RPS_LEVELS; do
    echo "-- $proxy @ ${rps} RPS for ${DURATION_SECS}s -------------------"
    out="$RESULTS/${proxy}_${rps}.txt"
    ./lynxx-bench \
      --target "$target" \
      --rps "$rps" \
      --duration-secs "$DURATION_SECS" \
      --warmup-secs "$WARMUP_SECS" \
      --connections "$CONNECTIONS" \
      --timeout-secs 30 \
      2>&1 | tee "$out"

    parse_run "$out" "$proxy" "$rps"
    echo "    parsed: p99=${LAST_P99_US}µs err_rate=${LAST_ERR_RATE}"

    if exploded "$LAST_P99_US" "$LAST_ERR_RATE"; then
      echo "    💥 exploded at ${rps} RPS — moving on"
      break
    fi
    LAST_GOOD_RPS=$rps
  done

  echo "$proxy peak=$LAST_GOOD_RPS" | tee -a "$RESULTS/peaks.txt"
  stop_proxy
done

echo
echo "==== PEAK RPS BY PROXY ===="
cat "$RESULTS/peaks.txt"
echo
echo "Full per-run details: $RESULTS/summary.csv + $RESULTS/<proxy>_<rps>.txt"
