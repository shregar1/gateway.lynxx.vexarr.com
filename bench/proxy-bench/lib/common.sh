#!/usr/bin/env bash
# lib/common.sh — shared helpers for the proxy-bench rig.
#
# Sourced by orchestrate-sweep.sh AND every proxies/<name>.sh, so each
# function should be:
#   * idempotent      — safe to call when state is already correct.
#   * non-destructive — never kill processes the caller didn't start
#                       (use the proxy-specific stop() in each proxy
#                        script instead, and a deliberate
#                        orchestrate_cleanup_all in the orchestrator).
#
# Public surface:
#   echo_step / echo_sub          — pretty log headers.
#   wait_for_port <port> [timeout]— block until http://127.0.0.1:port responds.
#   ensure_infra                  — start mock upstream + auth stub if missing.
#   run_one <proxy> <rps> <port>  — run a single rps level, return 1 if exploded.
#   run_sweep <proxy> <port>      — walk RPS_LEVELS, cut on first explode, write JSON.
#   parse_p99_ms <result-file>    — normalize lynxx-bench p99 output to ms.
#   parse_lat_ms <raw>            — normalize any us/ms/s value to ms (or "null").
#   write_sweep_json <proxy> <status>
#                                 — emit $BENCH_OUTPUTS_DIR/<proxy>/NN.json.

# Guard against double-sourcing.
[[ "${__BENCH_COMMON_LOADED:-}" == "1" ]] && return 0
__BENCH_COMMON_LOADED=1

# bench.conf must be sourced before us. If a caller forgets, fail loud
# instead of producing baffling unbound-variable errors deep in run_one.
: "${RPS_LEVELS:?lib/common.sh: bench.conf not sourced — source bench.conf first}"
: "${SRC_DIR:?lib/common.sh: bench.conf not sourced — source bench.conf first}"
: "${RESULTS_DIR:?lib/common.sh: bench.conf not sourced — source bench.conf first}"

mkdir -p "$RESULTS_DIR" "$CONFIGS_DIR" 2>/dev/null || true

echo_step() {
  echo
  echo "================================================================"
  echo "  $*"
  echo "================================================================"
}
echo_sub() { echo; echo "  >>> $*"; }

# ─── Network helpers ─────────────────────────────────────────────────────
wait_for_port() {
  local port="$1"; local timeout="${2:-30}"; local start=$SECONDS
  while ! curl -fsS "http://127.0.0.1:$port/bench" -o /dev/null 2>&1 && \
        ! curl -fsS "http://127.0.0.1:$port/"      -o /dev/null 2>&1; do
    if (( SECONDS - start > timeout )); then
      echo "    ERROR: :$port didn't open in ${timeout}s" >&2
      return 1
    fi
    sleep 1
  done
}

# ─── Always-on infra (mock upstream + auth stub) ─────────────────────────
# Started once at orchestrator boot and left running for the entire
# sweep. Each proxy script also calls ensure_infra defensively so it
# works standalone.
ensure_infra() {
  # Use port-bound check (consistent with the auth-stub probe below).
  if ! ss -tln 2>/dev/null | grep -q ":$UPSTREAM_PORT "; then
    echo_sub "start lynxx-mock-upstream on :$UPSTREAM_PORT"
    nohup "$SRC_DIR/target/release/lynxx-mock-upstream" --port "$UPSTREAM_PORT" \
      >"$RESULTS_DIR/_upstream.log" 2>&1 &
    sleep 1
    curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/" -o /dev/null || {
      echo "    ERROR: mock upstream failed to come up" >&2; return 1; }
  fi

  # Check if anything's already listening on AUTH_PORT — most reliable
  # idempotency signal across both keyx_stub.py and the real auth_server.py.
  # We avoid `pgrep -f "a\|b"` here: pgrep uses BRE by default and would
  # treat `\|` as a literal pipe, so the original alternation matched
  # nothing and every proxy spawned a duplicate stub.
  if ! ss -tln 2>/dev/null | grep -q ":$AUTH_PORT "; then
    echo_sub "start keyx auth stub on :$AUTH_PORT"
    local stub
    if [[ -f "$HOME/testing/keyx/auth_server.py" ]]; then
      stub="$HOME/testing/keyx/auth_server.py"
      nohup python3 "$stub" --port "$AUTH_PORT" \
        --config "$HOME/testing/keyx/keys.example.json" \
        >"$RESULTS_DIR/_keyx.log" 2>&1 &
    elif [[ -f "$SRC_DIR/testing/keyx/auth_server.py" ]]; then
      stub="$SRC_DIR/testing/keyx/auth_server.py"
      nohup python3 "$stub" --port "$AUTH_PORT" \
        --config "$SRC_DIR/testing/keyx/keys.example.json" \
        >"$RESULTS_DIR/_keyx.log" 2>&1 &
    else
      # Inline fallback — accepts every key. The real auth_server.py is
      # functionally a superset, so the inline stub is fine for benches.
      cat > /tmp/keyx_stub.py <<'PY'
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import json, uuid, datetime
class H(BaseHTTPRequestHandler):
    def _ok(self, data):
        body = json.dumps({
            "transactionUrn": f"urn:txn:{uuid.uuid4()}", "status": "SUCCESS",
            "responseMessage": "OK", "responseKey": "SUCCESS", "errors": [],
            "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
            "metadata": {}, "data": data, "reference_urn": "",
        }).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):  self._ok({"status": "ok"})
    def do_POST(self): self._ok({
        "valid": True, "customer_urn": "cus_dev_bench", "tier": "enterprise",
        "max_nodes": 100, "active_nodes": 1, "allow_overage": True,
        "role": "admin", "key_type": "service", "environment": "live",
        "scopes": [], "metadata": {}, "expires_at": None,
    })
    def log_message(self, *a, **kw): pass
class T(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 4096
T(('127.0.0.1', __AUTH_PORT__), H).serve_forever()
PY
      sed -i "s/__AUTH_PORT__/$AUTH_PORT/" /tmp/keyx_stub.py
      nohup python3 /tmp/keyx_stub.py >"$RESULTS_DIR/_keyx.log" 2>&1 &
    fi
    sleep 1
    curl -fsS "http://127.0.0.1:$AUTH_PORT/healthz" -o /dev/null 2>/dev/null || \
      curl -fsS "http://127.0.0.1:$AUTH_PORT/"      -o /dev/null 2>/dev/null || true
  fi
}

# ─── Result parsing ──────────────────────────────────────────────────────
# lynxx-bench prints latency values with a unit suffix (us / ms / s).
# parse_lat_ms normalizes any single value to ms (or "null" if absent).
# parse_p99_ms is a convenience wrapper that reads the p99 field from
# a whole result file and falls back to 999999 (used by explode logic).
parse_lat_ms() {
  local v="${1:-}"
  [[ -z "$v" ]] && { echo "null"; return; }
  local unit="${v: -2}"; local num="${v%??}"
  case "$unit" in
    us) awk "BEGIN{printf \"%.4f\", $num/1000}" ;;
    ms) echo "$num" ;;
    s)  awk "BEGIN{printf \"%.4f\", $num*1000}" ;;
    *)  echo "null" ;;
  esac
}

parse_p99_ms() {
  local file="$1"
  local p99_line p99_val
  p99_line=$(grep -E '^\s+p99:' "$file" | head -1 || true)
  [[ -z "$p99_line" ]] && { echo "999999"; return; }
  p99_val=$(awk '{print $2}' <<<"$p99_line")
  local ms
  ms=$(parse_lat_ms "$p99_val")
  [[ "$ms" == "null" ]] && { echo "999999"; return; }
  echo "$ms"
}

# ─── Sweep-level JSON record ─────────────────────────────────────────────
# State accumulated by run_one inside a single run_sweep call. Globals
# (vs returning JSON from each call) keep the call-chain shallow — each
# run_one just appends to __SWEEP_LEVELS_JSON and run_sweep emits the
# final document.
__SWEEP_LEVELS_JSON=""
__SWEEP_STARTED_AT=""
__SWEEP_LADDER_CUT_AT=""

sweep_init() {
  __SWEEP_LEVELS_JSON=""
  __SWEEP_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  __SWEEP_LADDER_CUT_AT=""
}

# Append one level to __SWEEP_LEVELS_JSON. Reads raw fields from the
# .txt file lynxx-bench produced. Missing fields → 0 (numeric) so the
# JSON stays valid even if a level crashed mid-write.
__record_level() {
  local proxy="$1" rps="$2" file="$3" exploded="$4"
  local achieved duration p50 p95 p99 p999 mn mx errs reqs

  achieved=$(grep '^\s*achieved_rps:' "$file" | awk '{print $2}' | tr -d ',')
  duration=$(grep '^\s*duration:'     "$file" | awk '{print $2}' | sed 's/s$//')
  p50=$( parse_lat_ms "$(grep '^\s*p50:'   "$file" | awk '{print $2}')")
  p95=$( parse_lat_ms "$(grep '^\s*p95:'   "$file" | awk '{print $2}')")
  p99=$( parse_lat_ms "$(grep '^\s*p99:'   "$file" | awk '{print $2}')")
  p999=$(parse_lat_ms "$(grep '^\s*p99.9:' "$file" | awk '{print $2}')")
  mn=$(  parse_lat_ms "$(grep '^\s*min:'   "$file" | awk '{print $2}')")
  mx=$(  parse_lat_ms "$(grep '^\s*max:'   "$file" | awk '{print $2}')")
  errs=$(grep '^\s*errors:'  "$file" | awk '{print $2}' | tr -d ',')
  reqs=$(grep '^\s*requests:' "$file" | awk '{print $2}' | tr -d ',')

  local entry
  entry=$(cat <<JSON
    {
      "target_rps": $rps,
      "achieved_rps": ${achieved:-0},
      "duration_secs": ${duration:-0},
      "requests": ${reqs:-0},
      "errors": ${errs:-0},
      "p50_ms": ${p50:-null},
      "p95_ms": ${p95:-null},
      "p99_ms": ${p99:-null},
      "p99_9_ms": ${p999:-null},
      "min_ms": ${mn:-null},
      "max_ms": ${mx:-null},
      "exploded": $exploded,
      "raw_file": "$(basename "$file")"
    }
JSON
)
  if [[ -z "$__SWEEP_LEVELS_JSON" ]]; then
    __SWEEP_LEVELS_JSON="$entry"
  else
    __SWEEP_LEVELS_JSON+=",
$entry"
  fi
}

# Emit one $BENCH_OUTPUTS_DIR/<proxy>/NN.json file with the next free
# sequence number. NN is zero-padded to 2 digits (01, 02, ...). After
# 99 it rolls to 3-digit (100) — that's fine, ls + sort -n still
# returns the right "next" index because we strip the .json suffix
# and do numeric sort.
write_sweep_json() {
  local proxy="$1"
  local status="${2:-complete}"   # complete | ladder_cut | start_failed

  local outdir="$BENCH_OUTPUTS_DIR/$proxy"
  mkdir -p "$outdir"

  local next=1
  if compgen -G "$outdir/*.json" > /dev/null; then
    local last
    last=$(ls -1 "$outdir"/*.json 2>/dev/null \
      | sed 's|.*/||; s/\.json$//' \
      | sort -n | tail -1)
    # Use 10# prefix so "08" / "09" don't get parsed as octal.
    next=$((10#$last + 1))
  fi
  local seq
  seq=$(printf "%02d" "$next")
  local outfile="$outdir/$seq.json"

  local finished_at
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local rps_csv
  rps_csv=$(echo "$RPS_LEVELS" | tr -s ' ' ',' | sed 's/^,//; s/,$//')

  cat > "$outfile" <<JSON
{
  "proxy": "$proxy",
  "seq": $next,
  "status": "$status",
  "started_at": "$__SWEEP_STARTED_AT",
  "finished_at": "$finished_at",
  "ladder_cut_at_rps": ${__SWEEP_LADDER_CUT_AT:-null},
  "config": {
    "rps_levels": [$rps_csv],
    "duration_secs": $DURATION_SECS,
    "warmup_secs": $WARMUP_SECS,
    "connections": $CONNECTIONS,
    "p99_explode_ms": $P99_EXPLODE_MS,
    "err_explode_rate": $ERR_EXPLODE_RATE
  },
  "host": {
    "hostname": "$(hostname 2>/dev/null || echo unknown)",
    "vcpu": $(nproc 2>/dev/null || echo 0),
    "kernel": "$(uname -r 2>/dev/null || echo unknown)",
    "os": "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  },
  "levels": [
$__SWEEP_LEVELS_JSON
  ]
}
JSON
  echo "  -> wrote sweep record: $outfile"
}

# Run one RPS level. Returns 0 if it held, 1 if it exploded (script
# should then cut the ladder for this proxy). Writes the raw bench
# output to $RESULTS_DIR/<proxy>-<rps>.txt AND appends a structured
# entry to __SWEEP_LEVELS_JSON for later JSON emission.
run_one() {
  local proxy="$1"; local rps="$2"; local target_port="$3"
  local out="$RESULTS_DIR/${proxy}-${rps}.txt"

  echo "    --> ${proxy} @ ${rps} RPS / ${DURATION_SECS}s / ${CONNECTIONS} conns ..."
  "$SRC_DIR/target/release/lynxx-bench" \
    --target "http://127.0.0.1:${target_port}/bench" \
    --rps "$rps" --duration-secs "$DURATION_SECS" \
    --connections "$CONNECTIONS" --warmup-secs "$WARMUP_SECS" \
    >"$out" 2>&1 || true

  local p99_ms err_line req_line errs reqs err_rate
  p99_ms=$(parse_p99_ms "$out")
  err_line=$(grep -E '^\s+errors:' "$out" | head -1 || true)
  req_line=$(grep -E '^\s+requests:' "$out" | head -1 || true)
  errs=$(awk '{print $2}' <<<"$err_line" | tr -d ',')
  reqs=$(awk '{print $2}' <<<"$req_line" | tr -d ',')
  if [[ -z "$errs" || -z "$reqs" || "$reqs" == "0" ]]; then
    err_rate=1.0
  else
    err_rate=$(awk "BEGIN{printf \"%.4f\", $errs/$reqs}")
  fi

  printf "        p99=%sms errors=%s/%s (err_rate=%s)\n" \
    "$p99_ms" "${errs:-?}" "${reqs:-?}" "$err_rate"

  local exploded=0
  if awk "BEGIN{exit !($p99_ms > $P99_EXPLODE_MS)}"; then exploded=1; fi
  if awk "BEGIN{exit !($err_rate > $ERR_EXPLODE_RATE)}"; then exploded=1; fi

  # Record into the per-sweep JSON regardless of explode — we want to
  # see the breaking-point row too (helps diff runs).
  local exploded_bool=false
  (( exploded == 1 )) && exploded_bool=true
  __record_level "$proxy" "$rps" "$out" "$exploded_bool"

  if (( exploded == 1 )); then
    echo "        --> EXPLODED (p99>${P99_EXPLODE_MS}ms or err_rate>${ERR_EXPLODE_RATE})"
    return 1
  fi
  return 0
}

# Walk the RPS ladder. Cut on first explode. Emit the per-sweep JSON
# at $BENCH_OUTPUTS_DIR/<proxy>/NN.json whether the ladder completes
# or gets cut.
run_sweep() {
  local proxy="$1"; local target_port="$2"
  sweep_init
  echo "  sweep:"
  for rps in $RPS_LEVELS; do
    if ! run_one "$proxy" "$rps" "$target_port"; then
      __SWEEP_LADDER_CUT_AT=$rps
      echo "  --> ladder cut at $rps RPS for $proxy"
      break
    fi
  done
  local status="complete"
  [[ -n "$__SWEEP_LADDER_CUT_AT" ]] && status="ladder_cut"
  write_sweep_json "$proxy" "$status"
}
