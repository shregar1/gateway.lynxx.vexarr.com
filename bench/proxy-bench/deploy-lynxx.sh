#!/usr/bin/env bash
# Runs FROM your Mac. Rsyncs the lynxx repo to SUT + Client, builds the lynxx
# image on SUT, builds lynxx-bench + lynxx-mock-upstream on the client.
# Also stages docker-compose.yml + configs on the SUT.
set -euo pipefail
cd "$(dirname "$0")"
source .env
source .ips

SSH_PRIVKEY="${SSH_PUBKEY%.pub}"
SSH="ssh -i ${SSH_PRIVKEY/#\~/$HOME} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null"
RSYNC="rsync -az -e \"$SSH\" --exclude target --exclude .git --exclude node_modules"

REPO_ABS=$(cd "$LOCAL_REPO" && pwd)
echo "==> Source repo: $REPO_ABS"

# --- SUT: rsync source, copy compose + configs, build lynxx image -----------
echo "==> [SUT] rsync source"
eval $RSYNC "$REPO_ABS/" "$ADMIN_USER@$SUT_IP:~/lynxx-src/"
echo "==> [SUT] stage proxy-bench configs"
eval $RSYNC ./docker-compose.yml ./configs "$ADMIN_USER@$SUT_IP:~/bench/"

echo "==> [SUT] build lynxx-gateway:bench image (this is the slow step — ~15 min cold)"
$SSH "$ADMIN_USER@$SUT_IP" "set -ex
  cd ~/lynxx-src
  HASH=\$(git rev-parse --short=8 HEAD 2>/dev/null || echo 'bench')
  sg docker -c \"DOCKER_BUILDKIT=1 docker build --target gateway -t lynxx-gateway:bench \\
    --build-arg LYNXX_BUILD_HASH=\$HASH \\
    --build-arg AUTH_URL=http://127.0.0.1:9100 .\"
"

echo "==> [SUT] build native lynxx-mock-upstream (used as the shared upstream on host:19090)"
$SSH "$ADMIN_USER@$SUT_IP" 'set -ex
  source $HOME/.cargo/env 2>/dev/null || curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source $HOME/.cargo/env
  cd ~/lynxx-src
  RUSTFLAGS="--cfg tokio_unstable" AUTH_URL=http://127.0.0.1:9100 LYNXX_BUILD_HASH=bench \
    cargo build --release -p lynxx-bench --bin lynxx-mock-upstream
  cp target/release/lynxx-mock-upstream ~/bench/
'

# --- Client: rsync source, build lynxx-bench --------------------------------
echo "==> [CLIENT] rsync source"
eval $RSYNC "$REPO_ABS/" "$ADMIN_USER@$CLIENT_IP:~/lynxx-src/"
echo "==> [CLIENT] stage run-bench script + .env-derived config"
scp -i "${SSH_PRIVKEY/#\~/$HOME}" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
    run-bench.sh "$ADMIN_USER@$CLIENT_IP:~/bench/run-bench.sh"
$SSH "$ADMIN_USER@$CLIENT_IP" "chmod +x ~/bench/run-bench.sh && cat > ~/bench/.bench-env <<EOF
SUT_PRIV=$SUT_PRIV
RPS_LEVELS=\"$RPS_LEVELS\"
DURATION_SECS=$DURATION_SECS
WARMUP_SECS=$WARMUP_SECS
CONNECTIONS=$CONNECTIONS
P99_EXPLODE_MS=$P99_EXPLODE_MS
ERR_EXPLODE_RATE=$ERR_EXPLODE_RATE
PROXIES=\"$PROXIES\"
EOF"

echo "==> [CLIENT] build lynxx-bench"
$SSH "$ADMIN_USER@$CLIENT_IP" 'set -ex
  source $HOME/.cargo/env
  cd ~/lynxx-src
  RUSTFLAGS="--cfg tokio_unstable" cargo build --release -p lynxx-bench --bin lynxx-bench
  cp target/release/lynxx-bench ~/bench/
'

echo
echo "================================================================"
echo "Deploy complete."
echo "  SUT has:    lynxx-gateway:bench image, lynxx-mock-upstream binary,"
echo "              docker-compose.yml + configs at ~/bench/"
echo "  Client has: lynxx-bench binary, run-bench.sh at ~/bench/"
echo "================================================================"
