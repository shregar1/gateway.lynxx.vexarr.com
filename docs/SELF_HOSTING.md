# Self-hosting Lynxx

Run the Lynxx API gateway on your own infrastructure. Sub-30-minute install on
a single Linux VM, no external dependencies beyond a Postgres database (or
SQLite for single-node).

This guide is for **operators installing Lynxx for their own use** — not for
contributors hacking on the source. For developer docs, see the rest of
`docs/`.

---

## What you get

A single binary (~50 MB on Linux/amd64) that exposes:

- **Public proxy / data plane** on `:443` (or any port — configurable)
- **Admin API + dashboard** on `:9001` (loopback-only by default)
- TLS via ACME (Let's Encrypt) with DNS-01 challenge, or bring-your-own cert
- Route / service / plugin configuration via TOML, env vars, or admin API
- Cluster mode (multi-node) backed by SQLite + replication or Postgres

The binary has **no runtime dependencies** beyond `glibc` (no JVM, no Node,
no Python).

---

## Requirements

| | |
|---|---|
| OS | Linux x86_64 (Ubuntu 22.04+, Debian 12+, RHEL 9+, Amazon Linux 2023+); ARM64 supported (`darwin/arm64` and `linux/arm64` binaries published) |
| RAM | 512 MB minimum, 2 GB recommended |
| Disk | 500 MB for the binary + state; budget more for logs/audit |
| Network | Inbound `:80` + `:443` from the internet (TLS + ACME challenges); outbound `:443` to `api.keyx.vexarr.com` (license validation) and your upstream services |
| Database | None required for single-node (SQLite is bundled). For HA: Postgres 14+ |
| TLS | Either: a wildcard cert you provide, or a DNS provider supported by [`instant-acme`](https://docs.rs/instant-acme) for ACME DNS-01 |
| OpenSSL | OpenSSL 3+ (for install-time integrity verification; LibreSSL won't work) |
| Tools | `curl`, `bash`, `sha256sum` (or `shasum`) — all standard |

---

## Install (one-liner)

```bash
curl -fsSL https://backend.lynxx.vexarr.com/install_gateway.sh | bash
```

**Important: pipe to `bash`, not `sh`**. The installer uses bash features that
`dash` (Ubuntu's default `/bin/sh`) doesn't support.

The installer:

1. Detects your OS + arch.
2. Downloads the binary from a private GCS bucket via the Lynxx gateway. The
   gateway streams it with `X-Content-SHA256` + `X-Content-Signature` headers.
3. **Verifies the SHA-256** against the header.
4. **Verifies the Ed25519 signature** with the public key pinned in the script
   body.
5. **Fetches the transparency-log entry** for that exact binary and verifies
   both the entry's signature and that the entry's recorded hash + signature
   match the binary it served.
6. **Fetches the witness-signed log root** and confirms the binary is covered
   by a recent attestation from a key in a different security domain than the
   release key.
7. Installs to `/usr/local/bin/lynxx-gateway` (falls back to `~/.local/bin` if
   not root).

Any verification failure → installer **refuses** with a clear error. Re-run
with `LYNXX_FORCE=1` only after you understand what failed.

Available env-var overrides during install:

| Var | Default | Purpose |
|---|---|---|
| `LYNXX_INSTALL_DIR` | `/usr/local/bin` or `~/.local/bin` | Install destination |
| `LYNXX_API_BASE` | `https://backend.lynxx.vexarr.com` | Alternate distribution gateway |
| `LYNXX_FORCE` | unset | Reinstall over an existing binary |
| `LYNXX_REQUIRE_WITNESS` | `0` | Set to `1` to **hard-fail** when the witness root is unreachable (default: soft-warn) |

Verify yourself after install:

```bash
lynxx-gateway --version
```

---

## Configure

The installer drops the binary only. You write the config and systemd unit.

### Minimum `config.toml`

```toml
# /etc/lynxx/config.toml
[gateway]
proxy_port = 443
admin_port = 9001
database_url = "sqlite:///var/lib/lynxx/lynxx.db?mode=rwc"
seed_from_config = true
health_check_interval_ms = 10000

# ACME — pick a challenge type
[gateway.acme]
enabled = true
email = "you@example.com"
storage_dir = "/var/lib/lynxx/acme"
http_port = 80
challenge_type = "dns-01"   # or "http-01" for single-domain setups
domains = ["*.example.com"]

# Routes / services / plugins live in [[route]] / [[service]] / [[plugin]]
# blocks. Easiest to start with the admin API or dashboard.
```

For Postgres-backed HA, swap `database_url`:

```toml
database_url = "postgres://lynxx:<password>@<host>:5432/lynxx"
```

The full schema (50+ keys) is documented in
[`docs/cli-api-reference.md`](cli-api-reference.md) and seeded by `--help`.

### systemd unit

```ini
# /etc/systemd/system/lynxx-gateway.service
[Unit]
Description=Lynxx API Gateway
After=network.target

[Service]
Type=simple
User=root
Environment=HOME=/var/lib/lynxx
Environment=RUST_LOG=info
EnvironmentFile=/etc/lynxx/env       # holds LYNXX_API_KEY + license vars
Environment=LYNXX_STRICT_PORT=true   # refuse to start if port is busy
ExecStart=/usr/local/bin/lynxx-gateway --config /etc/lynxx/config.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Where `/etc/lynxx/env` (`chmod 600`, owned by root) holds:

```
LYNXX_API_KEY=<openssl rand -hex 32>
LYNXX_LICENSE_VERIFY_URL=https://api.keyx.vexarr.com/v1/license/verify
KEYX_BASE_URL=https://api.keyx.vexarr.com
KEYX_LICENSE_URN=<urn from your license email>
KEYX_SERVICE_TOKEN=<token from your license email>
```

Then:

```bash
sudo mkdir -p /etc/lynxx /var/lib/lynxx
sudo systemctl daemon-reload
sudo systemctl enable --now lynxx-gateway
sudo systemctl status lynxx-gateway
```

---

## License activation

Lynxx requires a valid license to start past the trial. Two ways to obtain one:

1. **Free trial**: 14 days, full feature set, no card. Sign up at
   `https://lynxx.vexarr.com`, follow the activation email. The email contains
   `KEYX_LICENSE_URN` + `KEYX_SERVICE_TOKEN`.
2. **Paid plan**: bought via the dashboard or sales, delivered the same way.

Drop both values into `/etc/lynxx/env` and restart. On boot, the gateway
calls `KEYX_BASE_URL/v1/license/verify` with `KEYX_SERVICE_TOKEN` as a Bearer
header. The response is Ed25519-signed by the billing server; an embedded
public key in the binary verifies the signature.

Verify it stuck:

```bash
curl -s http://localhost:9001/healthz | jq .data.licence_mode
# → "paid" or "trial"
```

If you see `"legacy"`, you're still on the master-admin-token path (fine for
single-node trials; needed for production HA).

---

## Day-2 ops

### Check health

```bash
# Liveness
curl -s http://localhost:9001/healthz

# Admin dashboard (loopback only by default — tunnel over SSH for remote)
ssh -L 9001:localhost:9001 your-vm
# then open http://localhost:9001 in a browser
```

### Logs

```bash
sudo journalctl -u lynxx-gateway -f
```

Logs are structured JSON. Drop them into your log aggregator
(Loki/Elastic/Datadog) by tailing the journal.

### Backups

Lynxx ships an HMAC-protected backup endpoint that does the right thing for
your storage backend (pg_dump for Postgres, `sqlite3 .backup` for SQLite)
and writes a restorable artifact to `/var/lib/lynxx/backups/`. The endpoint
is **disabled by default** — it activates when you set
`LYNXX_BACKUP_WEBHOOK_SECRET`.

There are two ways to drive it:

#### Option A — cronX (recommended)

[cronX](https://cronx.vexarr.com) is Vexarr's hosted scheduler. It already
knows how to fire HMAC-signed webhooks on a schedule with retries,
idempotency, and an audit trail. Point it at your gateway's
`/admin/backup` endpoint and you get observable, retryable, alertable
backups for free.

1. **Generate a shared HMAC secret:**

   ```bash
   openssl rand -hex 32
   # → 6c1a... (save this)
   ```

2. **Add it to `/etc/lynxx/env` and restart:**

   ```
   LYNXX_BACKUP_WEBHOOK_SECRET=<the hex string from step 1>
   LYNXX_BACKUP_DIR=/var/lib/lynxx/backups   # optional, this is the default
   ```

   ```bash
   sudo systemctl restart lynxx-gateway
   curl -fsSL -H "X-Cronx-Signature: t=1,v1=0" \
     https://your-gateway.example.com/admin/backup
   # → 401 "signature did not verify" (means the endpoint is live)
   ```

3. **Register the job in cronX:**

   ```bash
   curl -fsSL -X POST https://api.cronx.vexarr.com/v1/jobs \
     -H "Authorization: Bearer <your cronx api key>" \
     -H "Content-Type: application/json" \
     -d '{
       "project_slug": "your-project",
       "slug": "lynxx-backup-daily",
       "name": "Lynxx daily backup",
       "schedule_kind": "cron",
       "schedule_expr": "0 2 * * *",
       "timezone": "UTC",
       "target_kind": "http",
       "target_config": {
         "url": "https://your-gateway.example.com/admin/backup",
         "method": "POST",
         "body": "{}"
       },
       "retry_policy": { "max_attempts": 3, "backoff_secs": 60 }
     }'
   ```

4. **Configure the webhook secret on cronX's side** so its HMAC signatures
   verify against the one you set in step 1. The cronX API + dashboard both
   expose this as "tenant webhook secret".

5. **Verify:**

   ```bash
   # From the cronX dashboard or:
   curl https://api.cronx.vexarr.com/v1/jobs/lynxx-backup-daily/executions
   # → list of past runs with status, attempt count, response code
   ```

The integration gives you:
- Daily (or any schedule) pg_dump/sqlite-backup runs
- Automatic retry on 5xx with backoff
- Per-attempt audit log
- Dead-letter on permanent 4xx
- Idempotency — duplicate deliveries don't redo the dump
- Replay-attack protection (5-minute signature timestamp window)

Restore from the most recent dump:

```bash
# Postgres
pg_restore --clean --if-exists --dbname="$DATABASE_URL" \
  /var/lib/lynxx/backups/backup-<idempotency-key>.dump

# SQLite (single-node)
sudo systemctl stop lynxx-gateway
sudo cp /var/lib/lynxx/backups/backup-<idempotency-key>.db /var/lib/lynxx/lynxx.db
sudo systemctl start lynxx-gateway
```

> **cronX needs to be deployed somewhere reachable.** If you can outbound
> to `api.cronx.vexarr.com` and that hosted instance is appropriate for
> your data residency requirements, use it. Otherwise self-host cronX
> (separate deploy guide; cronX itself depends on keyx for auth).

#### Option B — system cron (no cronX dependency)

If you'd rather not introduce a cronX dependency, drive the same endpoint
from your VM's local cron. You still get HMAC auth + idempotency from the
gateway side; you lose the retry/audit/observability cronX provides.

```cron
# /etc/cron.d/lynxx-backup
0 2 * * * root /usr/local/bin/lynxx-backup-trigger.sh >> /var/log/lynxx-backup.log 2>&1
```

```bash
#!/usr/bin/env bash
# /usr/local/bin/lynxx-backup-trigger.sh
set -euo pipefail
SECRET=$(grep LYNXX_BACKUP_WEBHOOK_SECRET /etc/lynxx/env | cut -d= -f2)
TS=$(date +%s%3N)
KEY=$(uuidgen)
BODY='{}'
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')
curl -fsSL -X POST http://localhost:28080/admin/backup \
  -H "X-Cronx-Signature: t=$TS,v1=$SIG" \
  -H "X-Cronx-Idempotency-Key: $KEY" \
  -H "Content-Type: application/json" \
  --data "$BODY"
```

The endpoint accepts any HMAC-signed POST that follows the
[`X-Cronx-Signature` format](https://github.com/vexarr/api.cronx.vexarr.com)
— cronX itself isn't required.

### Upgrade to a new release

```bash
# Same one-liner — installer detects existing binary and prompts
curl -fsSL https://backend.lynxx.vexarr.com/install_gateway.sh | LYNXX_FORCE=1 bash
sudo systemctl restart lynxx-gateway

# Watch the boot for errors
sudo journalctl -u lynxx-gateway --since "30 seconds ago" --no-pager
```

The upgrade preserves your config + state. If the new binary panics on
startup, restore the previous binary from
`/usr/local/bin/lynxx-gateway.bak.*` and restart.

### Rotate the admin token

```bash
sudo /usr/local/bin/lynxx-gateway --reset-admin --force
# the new token is printed to stderr; copy it into /etc/lynxx/env
sudo systemctl restart lynxx-gateway
```

---

## Verifying releases out of band

The install scripts verify integrity automatically, but you can replay the
verification yourself any time:

```bash
# Download the binary + sidecars
curl -fsSL -o lynxx-gateway https://backend.lynxx.vexarr.com/v1/install/binary?artifact=gateway\&os=linux\&arch=amd64 \
  --dump-header headers.txt

# Verify SHA-256
echo "$(awk 'tolower($1)=="x-content-sha256:"{print tolower($2)}' headers.txt | tr -d '\r')  lynxx-gateway" \
  | sha256sum -c -

# Verify Ed25519 signature (public key pinned in install.sh)
curl -fsSL "https://backend.lynxx.vexarr.com/install_gateway.sh" \
  | awk '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/' \
  | head -3 > release.pub
awk 'tolower($1)=="x-content-signature:"{print $2}' headers.txt | tr -d '\r' \
  | openssl base64 -d -A > binary.sig
openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in lynxx-gateway -sigfile binary.sig

# Confirm transparency log entry exists for this exact binary
HASH=$(sha256sum lynxx-gateway | awk '{print $1}')
curl -fsSL "https://backend.lynxx.vexarr.com/v1/install/transparency?sha256=$HASH" | jq .
```

For the full threat model + design see
[`docs/SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md).

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `installer requires bash. Re-run as: curl ... \| bash` | Used `\| sh` instead of `\| bash`. Re-run with `\| bash`. |
| `checksum mismatch` during install | Bucket was tampered or partial download. Retry. If it persists, do not install. |
| `signature verification FAILED` | Wrong release public key on your side, or the binary has been substituted. Contact support before installing. |
| `binary not in transparency log` | The release wasn't logged. Likely off-the-record signing. Do not install. |
| `openssl lacks Ed25519 support` | LibreSSL detected. Install OpenSSL 3+: `brew install openssl@3` (macOS) or `apt install openssl` on a modern distro. |
| `ACME HTTP listener bind 0.0.0.0:80: Address already in use` | Something else holds `:80` (Apache, nginx, docker-proxy). Stop it, or switch ACME to DNS-01. |
| `port busy, retrying port=443` then OS-assigned port | Same thing on `:443`. Set `proxy_port = <free-port>` + `LYNXX_STRICT_PORT=true` so the failure is loud, not silent. |
| Service flaps every 5s in `journalctl -u lynxx-gateway` | Config error, missing license env vars, or db unreachable. The first error in the journal is the real one. |
| `licence_mode: legacy` in healthz | License env vars missing or wrong. Verify `KEYX_LICENSE_URN` + `KEYX_SERVICE_TOKEN` against the activation email. |

---

## Getting help

- Public docs: `https://lynxx.vexarr.com/docs`
- Support: `support@vexarr.com` (include your `KEYX_LICENSE_URN` + the
  output of `sudo journalctl -u lynxx-gateway --since "5 minutes ago"`)
- Security issues: `security@vexarr.com` (PGP key on the docs site)

When reporting an install failure, the install script prints exactly which
verification layer rejected — paste that line and we can debug fast.
