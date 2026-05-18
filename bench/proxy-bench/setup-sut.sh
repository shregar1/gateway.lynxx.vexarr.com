#!/usr/bin/env bash
# Runs ON the SUT VM (Ubuntu 24.04). Installs Docker, tunes kernel, pulls proxy
# images, and prepares the bench workspace at ~/bench/.
set -euxo pipefail

# ---- kernel tuning (HTTP-bench standard) -----------------------------------
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

# CPU governor → performance (no frequency scaling skew)
sudo apt-get update -qq
sudo apt-get install -y -qq cpufrequtils linux-tools-common "linux-tools-$(uname -r)" || true
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils >/dev/null
sudo systemctl restart cpufrequtils 2>/dev/null || true
for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo performance | sudo tee "$c" >/dev/null 2>&1 || true
done

# ---- Docker ----------------------------------------------------------------
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi

# Need new shell for group; use sg for the rest of this script
SG() { sg docker -c "$*"; }

# ---- Pre-pull proxy + postgres images --------------------------------------
for img in postgres:16-alpine nginx:1.27-alpine haproxy:3.0-alpine \
           envoyproxy/envoy:v1.32-latest traefik:v3.2 kong:3.8 ; do
  SG "docker pull $img" &
done
wait

# postgres-client for smoke checks
sudo apt-get install -y -qq postgresql-client curl

# ---- Workspace -------------------------------------------------------------
mkdir -p ~/bench/configs ~/bench/results
echo "SUT setup complete. Disk and CPU info:"
df -h / | tail -1
lscpu | grep -E "Model name|Socket|Core|Thread"
free -h
