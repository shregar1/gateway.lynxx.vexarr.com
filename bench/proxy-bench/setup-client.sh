#!/usr/bin/env bash
# Runs ON the client VM (Ubuntu 24.04). Installs Rust, tunes kernel, and prepares
# the workspace. The lynxx-bench binary itself is built after the source is rsynced.
set -euxo pipefail

# ---- kernel tuning (same as SUT — client also opens many sockets) ----------
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

for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo performance | sudo tee "$c" >/dev/null 2>&1 || true
done

# ---- Build deps for lynxx-bench (Rust) -------------------------------------
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl jq python3 rsync

if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

mkdir -p ~/bench/results
echo "Client setup complete."
