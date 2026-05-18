# proxy-bench — head-to-head proxy peak-RPS sweep

Runs the **same** open-loop benchmark against 6 proxies sequentially on
identical hardware to find the peak RPS each can sustain before
exploding (err > 1% OR p99 > 100ms).

## Topology

```
┌────────────────────────────────┐         ┌──────────────────────────────┐
│ CLIENT VM  (F32s_v2, 32 vCPU)  │  ────►  │ SUT VM  (E32bds_v5, 32 vCPU) │
│ lynxx-bench (open-loop HDR)    │  :28080 │ proxy under test             │
│                                │         │ + lynxx-mock-upstream :19090 │
└────────────────────────────────┘         └──────────────────────────────┘
            same Azure region, same proximity placement group
```

Proxy hop is over the wire (real NIC, real RX/TX queues). Proxy → upstream
is localhost on the SUT (every proxy gets the same upstream conditions).

## Proxies tested

| # | Proxy   | Version  | Why it's here                                   |
|---|---------|----------|-------------------------------------------------|
| 1 | lynxx   | local    | The subject                                     |
| 2 | nginx   | 1.27     | C, 20 years of hand-tuning — latency baseline   |
| 3 | haproxy | 3.0      | C, throughput baseline                          |
| 4 | envoy   | 1.32     | C++, service-mesh standard                      |
| 5 | traefik | 3.2      | Go, ergonomic modern proxy                      |
| 6 | kong    | 3.8      | nginx + Lua, API-gateway leader                 |

A **direct** (no-proxy) baseline is run first to subtract upstream+network
overhead from every proxy number.

## SKUs & cost

- SUT: `Standard_E32bds_v5` — 32 vCPU, 256 GB RAM, 1.2 TB local NVMe — **$3.70/hr**
- Client: `Standard_F32s_v2` — 32 vCPU compute-optimized — **$1.40/hr**
- Total: 64 vCPU (under 65 quota), **~$5.10/hr**

Expected wall time: ~3-4h end-to-end (1h setup + ~2h bench + buffer).
**Expected total cost: ~$20.**

## Method

For each proxy, step up RPS through `10k → 25k → 50k → 100k → 200k → 400k
→ 600k → 800k → 1M`, holding each level 60s. Mark the level "exploded"
when error rate > 1% or p99 > 100 ms. **Peak** = highest level before
explosion.

Open-loop pacing (lynxx-bench uses token-bucket) avoids coordinated
omission. HDR histogram captures the full tail.

## Files

```
proxy-bench/
├── README.md               ← this file
├── orchestrate.sh          ← top-level driver (run from your Mac)
├── 00-provision.sh         ← az CLI: create RG, VNet, NSG, 2 VMs
├── setup-sut.sh            ← runs on SUT: docker, kernel tuning, configs
├── setup-client.sh         ← runs on client: build lynxx-bench
├── deploy-lynxx.sh         ← runs from Mac: rsync src + build image on SUT
├── run-bench.sh            ← runs on client: per-proxy ramp sweep
├── report.py               ← parses results → Markdown table + CSV
├── 99-teardown.sh          ← az group delete (one-shot cleanup)
├── docker-compose.yml      ← all 7 services (upstream + 6 proxies)
├── configs/
│   ├── nginx.conf
│   ├── haproxy.cfg
│   ├── envoy.yaml
│   ├── traefik.yml
│   └── kong.yml
└── results/                ← raw bench output + parsed CSV + report.md
```

## Quickstart

```bash
cd backend.lynxx.vexarr.com/bench/proxy-bench
cp env.example .env
# edit .env — pick region, resource group name, your SSH pubkey path
./orchestrate.sh provision     # ~10 min, creates VMs
./orchestrate.sh deploy        # ~15 min, builds lynxx + sets up everything
./orchestrate.sh bench         # ~2 h, runs the sweep
./orchestrate.sh report        # generates results/report.md
./orchestrate.sh teardown      # ~2 min, deletes everything
```

Each phase is idempotent — re-running `deploy` after a config tweak is safe.
