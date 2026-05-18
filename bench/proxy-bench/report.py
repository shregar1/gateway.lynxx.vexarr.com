#!/usr/bin/env python3
"""Parse results/summary.csv → results/report.md.

The report's centerpiece is the iso-load checkpoint table:
for every RPS level where SOMETHING exploded, show every still-alive proxy's
p99 at that load — so you can see, e.g., "at 200k RPS when envoy died,
lynxx was still at p99=1.8ms".
"""
from __future__ import annotations
import csv
import os
import re
import sys
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV = HERE / "results" / "summary.csv"
PEAKS = HERE / "results" / "peaks.txt"
OUT = HERE / "results" / "report.md"

UNIT_TO_US = {"s": 1_000_000, "ms": 1_000, "µs": 1, "us": 1}
P99_EXPLODE_MS = int(os.environ.get("P99_EXPLODE_MS", "100"))
ERR_EXPLODE_RATE = float(os.environ.get("ERR_EXPLODE_RATE", "0.01"))


def to_us(v: str) -> int:
    v = v.strip()
    m = re.match(r"([0-9.]+)\s*(µs|us|ms|s)$", v)
    return int(float(m.group(1)) * UNIT_TO_US[m.group(2)]) if m else 0


def fmt_us(us: int) -> str:
    if us >= 1_000_000: return f"{us/1_000_000:.2f}s"
    if us >= 1_000:     return f"{us/1_000:.2f}ms"
    return f"{us}µs"


def fmt_rps(r) -> str:
    try: v = int(float(r))
    except Exception: return str(r)
    if v >= 1_000_000: return f"{v/1_000_000:.2f}M"
    if v >= 1_000:     return f"{v/1_000:.0f}k"
    return str(v)


def exploded(p99_us: int, err_rate: float) -> bool:
    return p99_us > P99_EXPLODE_MS * 1000 or err_rate > ERR_EXPLODE_RATE


def main() -> int:
    if not CSV.exists():
        print(f"missing {CSV}", file=sys.stderr); return 1

    rows: list[dict] = []
    with CSV.open() as f:
        for r in csv.DictReader(f):
            r["p99_us"] = to_us(r["p99"])
            r["p50_us"] = to_us(r["p50"])
            r["p95_us"] = to_us(r["p95"])
            r["p999_us"] = to_us(r["p99.9"])
            r["err_rate"] = float(r.get("err_rate") or 0)
            r["rps_target"] = int(float(r["rps_target"]))
            r["rps_achieved"] = float(r["rps_achieved"])
            rows.append(r)

    # Proxy order: preserve insertion order in CSV
    proxy_order = list(OrderedDict.fromkeys(r["proxy"] for r in rows))

    # Death events: per proxy, lowest RPS at which it exploded
    deaths: dict[str, int] = {}
    survivors: dict[str, int] = {}     # peak RPS where still alive
    for proxy in proxy_order:
        proxy_rows = sorted([r for r in rows if r["proxy"] == proxy], key=lambda r: r["rps_target"])
        for r in proxy_rows:
            if exploded(r["p99_us"], r["err_rate"]):
                deaths[proxy] = r["rps_target"]; break
            survivors[proxy] = r["rps_target"]

    # All checkpoint RPS levels = any RPS where a death occurred
    checkpoint_rps = sorted(set(deaths.values()))
    all_rps = sorted({r["rps_target"] for r in rows})

    # Lookup table: (proxy, rps) → row
    by_pr: dict[tuple, dict] = {(r["proxy"], r["rps_target"]): r for r in rows}

    out: list[str] = []
    out.append("# Proxy peak-RPS sweep — iso-load checkpoint report\n")
    out.append("**SUT:** `Standard_E32bds_v5` (32 vCPU, 256 GB RAM, 1.2 TB local NVMe), Ubuntu 24.04, BBR+tuned kernel, CPU governor `performance`.  ")
    out.append("**Client:** `Standard_F32s_v2` (32 vCPU compute-optimized), same Azure region + proximity placement group, accelerated networking.  ")
    out.append("**Workload:** `GET /`, empty body, 1KB response from `lynxx-mock-upstream` on SUT loopback.  ")
    out.append("**Load tool:** `lynxx-bench` (open-loop token-bucket pacing, HDR histogram).  ")
    out.append(f"**Explosion threshold:** `p99 > {P99_EXPLODE_MS} ms` OR `error_rate > {ERR_EXPLODE_RATE*100:.0f}%`.\n")

    # ---- Death ranking -----------------------------------------------------
    out.append("## Order of death (who exploded first → last)\n")
    out.append("| Order | Proxy | Died at | Last healthy RPS |")
    out.append("|-------|-------|---------|-----------------:|")
    ranked = sorted(deaths.items(), key=lambda kv: kv[1])
    for i, (proxy, rps) in enumerate(ranked, 1):
        out.append(f"| {i} | **{proxy}** | 💥 {fmt_rps(rps)} | {fmt_rps(survivors.get(proxy, 0))} |")
    still_alive = [p for p in proxy_order if p not in deaths]
    for proxy in still_alive:
        out.append(f"| — | **{proxy}** | (didn't die in tested range) | ≥ {fmt_rps(survivors.get(proxy, 0))} |")

    # ---- The headline: iso-load checkpoint table ---------------------------
    out.append("\n## Iso-load checkpoint table (every survivor's p99 at the moment each proxy died)\n")
    out.append("A row is added at every RPS level where one or more proxies exploded. "
               "Each cell is the surviving proxy's p99 at that load level. `💥` = exploded. `—` = already dead.\n")
    header = "| Checkpoint RPS | Event | " + " | ".join(proxy_order) + " |"
    sep    = "|---:|---|" + "---|" * len(proxy_order)
    out.append(header); out.append(sep)
    for rps in checkpoint_rps:
        deaths_here = [p for p, d in deaths.items() if d == rps]
        event = " ".join(f"💥 {p}" for p in deaths_here)
        cells = [fmt_rps(rps), event]
        for proxy in proxy_order:
            row = by_pr.get((proxy, rps))
            if proxy in deaths and deaths[proxy] < rps:
                cells.append("—")
            elif row is None:
                cells.append("·")
            elif exploded(row["p99_us"], row["err_rate"]):
                cells.append(f"💥 {row['p99']}")
            else:
                cells.append(row["p99"])
        out.append("| " + " | ".join(cells) + " |")

    # ---- Full p99 matrix ---------------------------------------------------
    out.append("\n## Full p99 matrix (all proxies × all RPS levels)\n")
    header = "| RPS | " + " | ".join(proxy_order) + " |"
    sep    = "|---:|" + "---|" * len(proxy_order)
    out.append(header); out.append(sep)
    for rps in all_rps:
        cells = [fmt_rps(rps)]
        for proxy in proxy_order:
            row = by_pr.get((proxy, rps))
            if row is None:
                cells.append("—")
            elif exploded(row["p99_us"], row["err_rate"]):
                cells.append(f"💥 {row['p99']}")
            else:
                cells.append(row["p99"])
        out.append("| " + " | ".join(cells) + " |")

    # ---- Achieved-vs-requested RPS (load-gen saturation check) -------------
    out.append("\n## Achieved vs requested RPS (was the client itself the bottleneck?)\n")
    out.append("If `achieved < target` for a proxy that hasn't exploded yet, the SUT/proxy is the limit. "
               "If `achieved ≈ target` everywhere, we're measuring honestly.\n")
    out.append("| RPS target | " + " | ".join(proxy_order) + " |")
    out.append("|---:|" + "---|" * len(proxy_order))
    for rps in all_rps:
        cells = [fmt_rps(rps)]
        for proxy in proxy_order:
            row = by_pr.get((proxy, rps))
            if row is None: cells.append("—")
            else: cells.append(fmt_rps(int(row['rps_achieved'])))
        out.append("| " + " | ".join(cells) + " |")

    # ---- Per-proxy full latency profiles -----------------------------------
    out.append("\n## Per-proxy full latency profile\n")
    for proxy in proxy_order:
        out.append(f"\n### {proxy}\n")
        out.append("| RPS | Achieved | p50 | p95 | p99 | p99.9 | Errors | err_rate |")
        out.append("|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in sorted([x for x in rows if x['proxy']==proxy], key=lambda r: r["rps_target"]):
            mark = "💥 " if exploded(r["p99_us"], r["err_rate"]) else ""
            out.append(
                f"| {fmt_rps(r['rps_target'])} | {fmt_rps(int(r['rps_achieved']))} "
                f"| {r['p50']} | {r['p95']} | {mark}{r['p99']} | {r['p99.9']} "
                f"| {r['errors']} | {r['err_rate']:.4%} |"
            )

    OUT.write_text("\n".join(out) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
