#!/usr/bin/env bash
# Runs ON the client. Verifies every proxy in $PROXIES can serve a single GET /
# end-to-end. Refuses to proceed to bench if anything is broken.
#
# - Starts Postgres (always-on infra) and the mock upstream on SUT
# - Confirms upstream responds directly
# - For each proxy:
#     start → wait healthy → curl through it → check 200 + non-empty body
#     → stop
# - Prints a Pass/Fail table; exit 0 only if every proxy in $PROXIES passes.
set -uo pipefail        # NOT -e — we want to collect all failures, not abort on first
cd "$HOME/bench"
source .bench-env

ME=$(whoami)
SSH_SUT="ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 $ME@$SUT_PRIV"

declare -A STATUS
declare -A DETAIL

note() { echo "[$(date +%H:%M:%S)] $*"; }

note "Starting Postgres + upstream on SUT"
$SSH_SUT 'cd ~/bench && sg docker -c "docker compose up -d postgres" >/dev/null'
$SSH_SUT "nohup ~/bench/lynxx-mock-upstream --port 19090 > ~/bench/upstream.log 2>&1 &"
sleep 2

note "Waiting for Postgres to accept connections"
PG_OK=0
for _ in $(seq 1 30); do
  if $SSH_SUT 'pg_isready -h 127.0.0.1 -p 5432 -U lynxx -q'; then PG_OK=1; break; fi
  sleep 1
done
if [[ $PG_OK -eq 0 ]]; then
  echo "FATAL: Postgres never became ready"; exit 2
fi
note "  ✓ Postgres ready"

note "Verifying upstream responds directly"
if ! curl -fsS -o /tmp/upstream.body -m 5 "http://$SUT_PRIV:19090/"; then
  echo "FATAL: upstream not reachable at $SUT_PRIV:19090"; exit 2
fi
UPSTREAM_BODY=$(head -c 80 /tmp/upstream.body)
note "  ✓ upstream OK; body[:80]=\"$UPSTREAM_BODY\""

ALL_DOCKER_PROXIES="lynxx nginx haproxy envoy traefik kong"

for proxy in $PROXIES; do
  if [[ "$proxy" == "direct" ]]; then
    STATUS[direct]="PASS"
    DETAIL[direct]="(no proxy — upstream verified above)"
    continue
  fi

  note "Smoke-testing $proxy"
  # Stop any other proxy first
  others=$(echo "$ALL_DOCKER_PROXIES" | tr ' ' '\n' | grep -v "^${proxy}$" | tr '\n' ' ')
  $SSH_SUT "cd ~/bench && sg docker -c 'docker compose stop $others' 2>/dev/null; \
            sg docker -c 'docker compose up -d $proxy' >/dev/null"

  # Health: wait up to 60s (lynxx + kong are slowest to come up)
  ok=0
  body=""; code=""; ttfb=""
  for _ in $(seq 1 60); do
    if curl -fsS -o /tmp/proxy.body -m 3 -w '%{http_code} %{time_starttransfer}\n' \
         "http://$SUT_PRIV:28080/" > /tmp/proxy.meta 2>/dev/null; then
      read -r code ttfb < /tmp/proxy.meta
      body=$(head -c 80 /tmp/proxy.body)
      if [[ "$code" == "200" && -n "$body" ]]; then
        ttfb_ms=$(awk -v t="$ttfb" 'BEGIN{printf "%.1f", t*1000}')
        STATUS[$proxy]="PASS"
        DETAIL[$proxy]="code=$code ttfb=${ttfb_ms}ms body=\"${body}\""
        ok=1; break
      fi
    fi
    sleep 1
  done

  if [[ $ok -eq 0 ]]; then
    # Capture container logs for diagnosis
    logs=$($SSH_SUT "sg docker -c 'docker compose logs --tail=10 $proxy 2>&1'" 2>&1 | tail -15 | tr '\n' '|')
    STATUS[$proxy]="FAIL"
    DETAIL[$proxy]="never returned 200 — logs: $logs"
    note "  ✗ $proxy FAILED"
  else
    note "  ✓ ${DETAIL[$proxy]}"
  fi

  # Stop this proxy before next test (postgres + upstream stay)
  $SSH_SUT "cd ~/bench && sg docker -c 'docker compose stop $proxy' 2>/dev/null" >/dev/null
done

echo
echo "============================================================"
echo "SMOKE TEST RESULTS"
echo "============================================================"
fail=0
for proxy in $PROXIES; do
  printf "  %-10s %-6s %s\n" "$proxy" "${STATUS[$proxy]}" "${DETAIL[$proxy]}"
  [[ "${STATUS[$proxy]}" == "FAIL" ]] && fail=1
done
echo "============================================================"

if [[ $fail -eq 1 ]]; then
  echo "❌ One or more proxies failed smoke test — DO NOT bench until fixed."
  exit 1
fi
echo "✅ All proxies passed smoke test — safe to run the sweep."
exit 0
