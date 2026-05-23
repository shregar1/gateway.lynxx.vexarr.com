#!/usr/bin/env bash
# Single-VM bench setup: client + SUT colocated on one Linux box.
#
# Trade-off vs the original two-VM rig:
# * The lynxx-bench client contends for the SAME CPU as the proxy under
#   test. Each gateway sees the same contention, so the RELATIVE
#   ordering is preserved, but absolute peak RPS will be lower than a
#   two-machine bench.
# * Network hop client → proxy is loopback (no NIC RX/TX, no actual
#   wire). That makes p50 about as low as it'll ever go.
#
# We picked this because the GCP project's 12-vCPU global CPU quota
# can't fit two 32-vCPU VMs. fluxx-bench-extreme is a 10-vCPU VM
# that's already provisioned + within quota, so we'd rather use it
# than wait days for a quota bump.
#
# Runs on the VM (Ubuntu 24.04). Installs docker + native proxies +
# kernel-tunes, then stages the bench workspace at ~/bench.
set -euxo pipefail

# ---- kernel tuning ---------------------------------------------------------
sudo tee /etc/sysctl.d/99-bench.conf >/dev/null <<'EOF'
net.core.somaxconn=65535
net.core.netdev_max_backlog=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_congestion_control=bbr
fs.file-max=2097152
fs.nr_open=2097152
EOF
sudo sysctl --system >/dev/null

sudo tee /etc/security/limits.d/99-bench.conf >/dev/null <<'EOF'
*  soft  nofile  1048576
*  hard  nofile  1048576
EOF

# CPU governor → performance
for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo performance | sudo tee "$c" >/dev/null 2>&1 || true
done

# ---- Docker (for kong, traefik, envoy) -------------------------------------
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi

# ---- Native proxies + build deps -------------------------------------------
sudo apt-get update -qq
sudo apt-get install -y -qq \
  nginx haproxy build-essential pkg-config libssl-dev curl jq python3 rsync

# Stop the native services that apt auto-starts — we control them
# explicitly later through run-bench.sh, and we don't want their
# default config holding port 80 in the way.
sudo systemctl stop nginx haproxy 2>/dev/null || true
sudo systemctl disable nginx haproxy 2>/dev/null || true

# ---- Rust (lynxx-gateway + lynxx-bench + lynxx-mock-upstream) --------------
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
fi

# ---- Workspace -------------------------------------------------------------
mkdir -p ~/bench/{configs,results}

# Pre-pull docker images for the proxies that need them. Run in
# parallel — these are 100-400 MB each, but pulled once and reused.
sg docker -c '
  for img in nginx:1.27-alpine haproxy:3.0-alpine envoyproxy/envoy:v1.32-latest \
             traefik:v3.2 kong:3.8 postgres:16-alpine ; do
    docker pull "$img" &
  done
  wait
'

echo "Setup complete. Disk + CPU + memory:"
df -h / | tail -1
lscpu | grep -E "Model name|Socket|Core|Thread" | head -5
free -h | head -2
