# Deploy Lynxx API Gateway

Single VM deployment to your GCE instance.

> All ports / URLs / credentials in this guide can be overridden via env vars.
> See [`.env.example`](.env.example) for the full list (`LYNXX_PROXY_PORT`,
> `LYNXX_ADMIN_PORT`, `LYNXX_API_KEY`, `DATABASE_URL`, `LYNXX_TELEMETRY_URL`,
> `LYNXX_GCS_BUCKET`, `LYNXX_VM_NAME`, `LYNXX_VM_ZONE`, …).

## First-time provisioning

Run once on a fresh VM to install deps, config, and the systemd service:

```bash
gcloud compute ssh $VM_NAME --zone=$ZONE --command='
set -e

# Install deps
sudo apt-get update && sudo apt-get install -y --no-install-recommends \
  curl ca-certificates iptables

# Install gsutil
if ! command -v gsutil &>/dev/null; then
  sudo apt-get install -y --no-install-recommends apt-transport-https gnupg
  echo "deb https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
  curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
  sudo apt-get update && sudo apt-get install -y google-cloud-cli
fi

# Create dirs and user
sudo useradd -r -u 10001 -m lynxx 2>/dev/null || true
sudo mkdir -p /etc/lynxx /var/lib/lynxx

# Download latest binary (stable pointer maintained by scripts/deploy.sh)
sudo gsutil cp gs://lynxx-public/gateway/linux/amd64/lynxx-gateway /usr/local/bin/lynxx-gateway
sudo chmod +x /usr/local/bin/lynxx-gateway

# Write config
sudo tee /etc/lynxx/config.toml > /dev/null <<TOML
[gateway]
proxy_port = 28080
admin_port = 28081
database_url = "sqlite:///var/lib/lynxx/lynxx.db?mode=rwc"
seed_from_config = true
health_check_interval_ms = 10000
health_circuit_failure_threshold = 3
health_circuit_success_threshold = 2
health_circuit_open_duration_ms = 30000
TOML

# Write systemd unit — fill in LYNXX_API_KEY before enabling
sudo tee /etc/systemd/system/lynxx.service > /dev/null <<UNIT
[Unit]
Description=Lynxx API Gateway
After=network.target

[Service]
Type=simple
User=root
Environment=HOME=/var/lib/lynxx
Environment=RUST_LOG=info
Environment=LYNXX_API_KEY=CHANGEME
ExecStart=/usr/local/bin/lynxx-gateway --config /etc/lynxx/config.toml
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

# Port forwarding: 443->28080, 80->28080
ExecStartPost=/sbin/iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 28080
ExecStartPost=/sbin/iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 28080
ExecStopPost=/sbin/iptables  -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 28080
ExecStopPost=/sbin/iptables  -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 28080

[Install]
WantedBy=multi-user.target
UNIT

sudo chown -R lynxx:lynxx /var/lib/lynxx
sudo systemctl daemon-reload
echo "Provisioned. Set LYNXX_API_KEY in /etc/systemd/system/lynxx.service, then:"
echo "  sudo systemctl enable --now lynxx.service"
'
```

## Build + deploy (from local machine)

Run from `backend.lynxx.dev/`:

```bash
# Build only (uploads binary to GCS)
./scripts/deploy.sh

# Build + zero-downtime deploy
./scripts/deploy.sh --deploy
```

## Rollback

```bash
# List available versions
./scripts/deploy.sh --rollback

# Rollback to a specific version
./scripts/deploy.sh --rollback v0.1.0-abcd1234
```

## Manual operations

```bash
# SSH into the VM
gcloud compute ssh $VM_NAME --zone=$ZONE

# Check status
sudo systemctl status lynxx.service
curl -s http://localhost:28081/healthz

# View logs
sudo journalctl -u lynxx.service -f

# Restart
sudo systemctl restart lynxx.service
```

## VM details

| Key | Value |
|-----|-------|
| VM | `$VM_NAME` |
| Type | e2-micro (0.25 vCPU / 1GB) |
| Zone | `$ZONE` |
| IP | Static IP reserved in your GCP project |
| Disk | 10GB pd-standard |
| OS | Debian 12 (bookworm) |
| Binary | `/usr/local/bin/lynxx-gateway` |
| Config | `/etc/lynxx/config.toml` |
| Data | `/var/lib/lynxx/` |
| GCS | `gs://lynxx-public/gateway/linux/amd64/` |
