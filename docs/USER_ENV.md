# User env vars

These are the env vars **you (the customer / operator)** set on the
host or container where the gateway runs. They're read every time the
process starts. Wrong value here means the gateway refuses to boot or
behaves in unexpected ways — but the binary itself is unaffected.

## Required

| Var | Description |
|---|---|
| `LYNXX_API_KEY` | Your Vexarr API key (`lnx_live_…` / `lnx_test_…`). Validated against the auth backend on boot. The gateway refuses to start without it. Also serves as the master admin bearer for the dashboard. |

## Common knobs

| Var | Default | Description |
|---|---|---|
| `LYNXX_PROXY_PORT` | `28080` | Port for customer (data-plane) traffic. Overrides `[gateway].proxy_port` in `config.toml`. |
| `LYNXX_ADMIN_PORT` | `28081` | Port for the admin API and dashboard. Overrides `[gateway].admin_port`. |
| `DATABASE_URL` | `sqlite://lynxx.db?mode=rwc` | Control-plane DB. SQLite for single-node, Postgres for HA. |
| `LYNXX_CACHE_DIR` | `~/.lynxx/` | Where the offline licence-verify cache lives. Useful when `$HOME` is unset (containers). |

## Logging

| Var | Default | Description |
|---|---|---|
| `RUST_LOG` | `lynxx_gateway=info,tower_http=debug` | Tracing filter. |
| `RUST_BACKTRACE` | unset | Set `1` for full backtraces on panics. |

## Telemetry (OTLP — all optional, unset = no export)

| Var | Default | Description |
|---|---|---|
| `LYNXX_TELEMETRY_URL` (alias: `OTEL_EXPORTER_OTLP_ENDPOINT`) | unset | OTLP HTTP endpoint. |
| `LYNXX_TELEMETRY_API_KEY` | unset | Bearer token sent with OTLP exports. |
| `OTEL_SERVICE_NAME` | `lynxx-gateway` | Service name on every span. |
| `LYNXX_MINIMAL_TELEMETRY` (legacy alias: `LYNXX_BENCH_MODE`) | unset (false) | Reduce telemetry detail / cardinality. Turn on when benchmarking. |

## Feature-specific (set only when you use the feature)

| Var | Description |
|---|---|
| `SSLKEYLOGFILE` | TLS handshake logging for Wireshark debugging. Never set in production. |
| `HOSTNAME`, `KUBE_NAMESPACE` | Kubernetes cluster discovery. Kubelet usually sets these automatically. |
| ACME DNS-01 tokens — only set the provider you use: | |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` |
| Azure | `AZURE_DNS_TOKEN`, `AZURE_DNS_ZONE`, `AZURE_RESOURCE_GROUP`, `AZURE_SUBSCRIPTION_ID` |
| DigitalOcean | `DIGITALOCEAN_TOKEN` |
| DuckDNS | `DUCKDNS_TOKEN` |
| Gandi | `GANDI_TOKEN` |
| GCloud | `GCLOUD_DNS_TOKEN`, `GCLOUD_DNS_ZONE`, `GCLOUD_PROJECT` |
| Hetzner | `HETZNER_DNS_TOKEN`, `HETZNER_DNS_ZONE_ID` |
| Linode | `LINODE_TOKEN`, `LINODE_DOMAIN_ID` |
| Namecheap | `NAMECHEAP_API_USER`, `NAMECHEAP_API_KEY`, `NAMECHEAP_CLIENT_IP` |
| OVH | `OVH_APPLICATION_KEY`, `OVH_CONSUMER_KEY`, `OVH_DNS_ZONE` |
| Porkbun | `PORKBUN_API_KEY`, `PORKBUN_SECRET_KEY` |
| Vultr | `VULTR_API_KEY` |

## Minimal startup

```sh
LYNXX_API_KEY=lnx_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx ./lynxx-gateway
```

Defaults take care of everything else.
