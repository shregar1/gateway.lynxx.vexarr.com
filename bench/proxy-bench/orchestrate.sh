#!/usr/bin/env bash
# Top-level driver. Run phases one at a time so you can inspect between steps.
#
#   ./orchestrate.sh provision   # az CLI: create RG + VNet + NSG + 2 VMs (~10 min)
#   ./orchestrate.sh setup       # kernel tuning + docker on SUT, rust on client
#   ./orchestrate.sh deploy      # rsync repo, build lynxx image + binaries
#   ./orchestrate.sh bench       # the actual sweep (~1.5-2h)
#   ./orchestrate.sh report      # pull results, generate report.md
#   ./orchestrate.sh teardown    # destroy the whole resource group
#
# Or:
#   ./orchestrate.sh all         # provision → setup → deploy → bench → report (no teardown)
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  echo "Missing .env — copy env.example and edit"; exit 1
fi
source .env
SSH_PRIVKEY="${SSH_PUBKEY%.pub}"
SSH_OPTS="-i ${SSH_PRIVKEY/#\~/$HOME} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null"

ips () { [[ -f .ips ]] && source .ips; }

phase_setup () {
  ips
  [[ -n "${SUT_IP:-}" && -n "${CLIENT_IP:-}" ]] || { echo "Run 'provision' first"; exit 1; }

  echo "==> wait for SSH on both VMs"
  for ip in "$SUT_IP" "$CLIENT_IP"; do
    until ssh $SSH_OPTS -o ConnectTimeout=5 "$ADMIN_USER@$ip" true 2>/dev/null; do sleep 3; done
  done

  echo "==> scp setup scripts"
  scp $SSH_OPTS setup-sut.sh    "$ADMIN_USER@$SUT_IP:~/"
  scp $SSH_OPTS setup-client.sh "$ADMIN_USER@$CLIENT_IP:~/"

  echo "==> SUT setup (kernel tuning, docker, image pre-pull)"
  ssh $SSH_OPTS "$ADMIN_USER@$SUT_IP"    'bash ~/setup-sut.sh'
  echo "==> Client setup (kernel tuning, rust toolchain)"
  ssh $SSH_OPTS "$ADMIN_USER@$CLIENT_IP" 'bash ~/setup-client.sh'

  # Generate a key on client, install on SUT so client can SSH to SUT
  echo "==> Generate SSH key on client and authorize on SUT"
  ssh $SSH_OPTS "$ADMIN_USER@$CLIENT_IP" \
    'test -f ~/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519'
  CLIENT_PUB=$(ssh $SSH_OPTS "$ADMIN_USER@$CLIENT_IP" 'cat ~/.ssh/id_ed25519.pub')
  ssh $SSH_OPTS "$ADMIN_USER@$SUT_IP" \
    "grep -qxF '$CLIENT_PUB' ~/.ssh/authorized_keys || echo '$CLIENT_PUB' >> ~/.ssh/authorized_keys"
}

phase_smoke () {
  ips
  echo "==> Copying smoke-test.sh to client"
  scp $SSH_OPTS smoke-test.sh "$ADMIN_USER@$CLIENT_IP:~/bench/smoke-test.sh"
  ssh $SSH_OPTS "$ADMIN_USER@$CLIENT_IP" 'chmod +x ~/bench/smoke-test.sh'
  echo "==> Running smoke test on client (verifies every proxy works end-to-end)"
  mkdir -p results
  ssh $SSH_OPTS "$ADMIN_USER@$CLIENT_IP" 'cd ~/bench && bash smoke-test.sh' | tee results/smoke.log
  return ${PIPESTATUS[0]}
}

phase_bench () {
  ips
  echo "==> Kicking off bench on client (this runs ~1.5-2h)"
  ssh $SSH_OPTS "$ADMIN_USER@$CLIENT_IP" 'cd ~/bench && bash run-bench.sh' | tee results/bench.log
}

phase_report () {
  ips
  echo "==> Pulling results from client"
  mkdir -p results
  scp $SSH_OPTS -r "$ADMIN_USER@$CLIENT_IP:~/bench/results/*" results/
  python3 report.py
  echo
  echo "==== REPORT (results/report.md) ===="
  cat results/report.md
}

# Cloud selector. `.env` sets CLOUD=azure (default) or CLOUD=gcp; the
# only phase-specific scripts that care are provision + teardown, since
# everything else just uses ssh/scp against the IPs in .ips.
case "${CLOUD:-azure}" in
  azure) PROVISION=00-provision.sh;     TEARDOWN=99-teardown.sh ;;
  gcp)   PROVISION=00-provision-gcp.sh; TEARDOWN=99-teardown-gcp.sh ;;
  *)     echo "ERROR: unknown CLOUD=$CLOUD in .env (expected: azure | gcp)"; exit 1 ;;
esac

case "${1:-help}" in
  provision) bash "$PROVISION" ;;
  setup)     phase_setup ;;
  deploy)    bash deploy-lynxx.sh ;;
  smoke)     phase_smoke ;;
  bench)     phase_bench ;;
  report)    phase_report ;;
  teardown)  bash "$TEARDOWN" ;;
  all)       bash "$PROVISION" && phase_setup && bash deploy-lynxx.sh && phase_smoke && phase_bench && phase_report ;;
  *)         grep '^#' "$0" | head -16; exit 1 ;;
esac
