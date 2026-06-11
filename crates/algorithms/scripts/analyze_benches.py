#!/usr/bin/env python3
"""
Analyze criterion benchmark output into a rich CSV + an optimization plan.

Reads target/criterion/**/new/estimates.json (+ benchmark.json for throughput),
derives per-measurement stats and profile signals, classifies each algorithm,
and emits:
  - scripts/algo_profile.csv   (one row per benchmark measurement)
  - scripts/optimization_plan.md (ranked optimization plan)

Re-runnable: pass --iteration N to tag the run. Designed to be invoked
repeatedly as algorithms are optimized.
"""
import json, os, sys, argparse, math
from collections import defaultdict

def _find_criterion():
    """Criterion output lives in the workspace target/, which may be the crate
    dir or a parent (workspace root). Search upward for target/criterion."""
    here = os.getcwd()
    for d in (here, os.path.dirname(here), os.path.dirname(os.path.dirname(here)),
              os.path.dirname(os.path.dirname(os.path.dirname(here)))):
        cand = os.path.join(d, "target", "criterion")
        if os.path.isdir(cand):
            return cand
    return os.path.join(here, "target", "criterion")  # fallback (will error clearly)

CRIT = _find_criterion()

# Map a criterion group-dir prefix -> (canonical group, group_id, category-domain)
# Category-domain is the high-level functional bucket.
GROUP_META = {
    "hash":        ("hashing", 1, "hash/checksum"),
    "hashing":     ("hashing", 1, "hash/checksum"),
    "checksum":    ("checksum", 2, "hash/checksum"),
    "encode":      ("encoding", 3, "encode/transform"),
    "encoding":    ("encoding", 3, "encode/transform"),
    "codec":       ("http_codec", 4, "protocol-codec"),
    "http":        ("http_codec", 4, "protocol-codec"),
    "inet":        ("networking", 5, "networking"),
    "networking":  ("networking", 5, "networking"),
    "parse":       ("parsing", 6, "parsing"),
    "string":      ("string_ops", 7, "string"),
    "rate":        ("rate_limit", 8, "rate-limit/admission"),
    "upstream":    ("upstream_pick", 9, "load-balancing"),
    "crypto":      ("crypto", 10, "crypto"),
    "text":        ("text", 11, "text"),
    "tree":        ("tree", 12, "data-structure"),
    "congestion":  ("congestion", 13, "congestion-control"),
    "resilience":  ("resilience", 14, "resilience"),
    "fix":         ("fix_protocol", 15, "protocol-parse"),
    "mqtt":        ("mqtt", 16, "protocol-parse"),
    "pattern":     ("pattern", 17, "matching"),
    "fingerprint": ("fingerprint", 18, "fingerprint"),
    "optimized":   ("optimized", 19, "optimized-variant"),
    "opt":         ("optimized", 19, "optimized-variant"),
}

def group_lookup(dirname):
    head = dirname.split("_")[0]
    # try longest prefixes first
    for pref in (dirname, "_".join(dirname.split("_")[:2]), head):
        if pref in GROUP_META:
            return GROUP_META[pref]
    return (head, 0, "uncategorized")

def tier(ns):
    if ns < 10:    return "fast"
    if ns < 100:   return "moderate"
    if ns < 1000:  return "notable"
    return "slow"

def fmt(ns):
    if ns < 1e3: return f"{ns:.2f}ns"
    if ns < 1e6: return f"{ns/1e3:.2f}us"
    return f"{ns/1e6:.2f}ms"

def load():
    """Return list of measurement dicts."""
    rows = []
    if not os.path.isdir(CRIT):
        print(f"ERROR: {CRIT} not found — run benchmarks first.", file=sys.stderr)
        sys.exit(1)
    for group in sorted(os.listdir(CRIT)):
        gp = os.path.join(CRIT, group)
        if not os.path.isdir(gp) or group == "report":
            continue
        gname, gid, domain = group_lookup(group)
        for root, dirs, files in os.walk(gp):
            if "new" not in dirs:
                continue
            est = os.path.join(root, "new", "estimates.json")
            if not os.path.exists(est):
                continue
            with open(est) as f:
                e = json.load(f)
            med = e["median"]["point_estimate"]
            lo = e["median"]["confidence_interval"]["lower_bound"]
            hi = e["median"]["confidence_interval"]["upper_bound"]
            scenario = root.replace(gp + os.sep, "").replace(os.sep, "/")
            # throughput (bytes/sec) if benchmark.json carries it
            thr, thr_unit = "", ""
            bj = os.path.join(root, "new", "benchmark.json")
            if os.path.exists(bj):
                try:
                    with open(bj) as f:
                        b = json.load(f)
                    tp = b.get("throughput") or {}
                    if "Bytes" in tp:
                        gbps = tp["Bytes"] / (med * 1e-9) / 1e9
                        thr, thr_unit = f"{gbps:.2f}", "GiB/s"
                except Exception:
                    pass
            rows.append(dict(
                group=gname, group_id=gid, domain=domain, crit_dir=group,
                scenario=scenario, ns=med, lo=lo, hi=hi,
                thr=thr, thr_unit=thr_unit,
                tier=tier(med),
                variance_pct=round((hi - lo) / med * 100, 1) if med else 0,
            ))
    return rows

def opt_priority(group_rows):
    """Heuristic optimization priority for an algorithm (group of scenarios)."""
    worst = max(r["ns"] for r in group_rows)
    slow_frac = sum(1 for r in group_rows if r["tier"] == "slow") / len(group_rows)
    hi_var = sum(1 for r in group_rows if r["variance_pct"] > 15) / len(group_rows)
    if worst > 10000 or slow_frac > 0.5:
        return "high"
    if worst > 1000 or slow_frac > 0.2 or hi_var > 0.5:
        return "medium"
    if worst > 200 or hi_var > 0.3:
        return "low"
    return "none"

def scaling(group_rows):
    """Detect scaling behavior across sized scenarios (e.g. .../16, /64, /256)."""
    sized = []
    for r in group_rows:
        tail = r["scenario"].rsplit("/", 1)[-1]
        digits = "".join(ch for ch in tail if ch.isdigit())
        if digits:
            sized.append((int(digits), r["ns"]))
    if len(sized) < 2:
        return "n/a"
    sized.sort()
    (s0, t0), (s1, t1) = sized[0], sized[-1]
    if s0 == 0 or t0 == 0:
        return "n/a"
    size_ratio = s1 / s0
    time_ratio = t1 / t0
    # exponent ~ log(time_ratio)/log(size_ratio)
    exp = math.log(time_ratio) / math.log(size_ratio) if size_ratio > 1 else 0
    if exp < 0.3:  return "O(1)-ish"
    if exp < 1.3:  return "linear"
    if exp < 1.8:  return "super-linear"
    return "quadratic+"

HIST_DIR = "scripts/history"

def snapshot_key(group, scenario):
    return f"{group}|{scenario}"

def save_snapshot(iteration, rows):
    """Persist this iteration's per-measurement medians for later diffing."""
    os.makedirs(HIST_DIR, exist_ok=True)
    snap = {snapshot_key(r["group"], r["scenario"]): r["ns"] for r in rows}
    with open(os.path.join(HIST_DIR, f"iter_{iteration}.json"), "w") as f:
        json.dump(snap, f, indent=0)

def load_prev_snapshot(iteration):
    """Load the most recent prior snapshot (highest iter < this one)."""
    if not os.path.isdir(HIST_DIR):
        return None, None
    cur = _as_num(iteration)
    best = None
    for fn in os.listdir(HIST_DIR):
        if not fn.startswith("iter_") or not fn.endswith(".json"):
            continue
        tag = fn[len("iter_"):-len(".json")]
        n = _as_num(tag)
        if cur is not None and n is not None and n >= cur:
            continue
        if best is None or (n is not None and best[0] is not None and n > best[0]) \
           or (best[0] is None):
            best = (n, fn, tag)
    if not best:
        return None, None
    with open(os.path.join(HIST_DIR, best[1])) as f:
        return json.load(f), best[2]

def _as_num(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iteration", default="1")
    args = ap.parse_args()

    rows = load()
    prev, prev_tag = load_prev_snapshot(args.iteration)

    # group rows by (group, algorithm) where algorithm = first scenario segment
    by_algo = defaultdict(list)
    for r in rows:
        algo = r["scenario"].split("/")[0]
        by_algo[(r["group"], r["crit_dir"], algo)].append(r)

    def diff_for(r):
        """Return (prev_ns_str, delta_pct_str) vs previous snapshot."""
        if not prev:
            return "", ""
        p = prev.get(snapshot_key(r["group"], r["scenario"]))
        if p is None or p == 0:
            return "", ""
        return f"{p:.2f}", f'{(r["ns"] - p) / p * 100:+.1f}'

    # write per-measurement CSV (now with diff columns)
    out_csv = "scripts/algo_profile.csv"
    cols = ["iteration","group","group_id","domain","algo","category","scenario",
            "time_ns_median","time_ns_low","time_ns_high","throughput","throughput_unit",
            "tier","variance_pct","scaling","opt_priority","opt_strategy",
            "prev_ns","delta_pct","status"]
    lines = [",".join(cols)]
    plan_items = []
    regressions, improvements = [], []
    for (group, crit_dir, algo), grp in sorted(by_algo.items()):
        pr = opt_priority(grp)
        sc = scaling(grp)
        domain = grp[0]["domain"]
        gid = grp[0]["group_id"]
        strat = strategy_for(sc, pr, grp)
        if pr in ("high", "medium"):
            plan_items.append((pr, group, algo, max(r["ns"] for r in grp), sc, strat))
        # per-algo aggregate delta (worst-scenario) for regression tracking
        for r in grp:
            prev_ns, delta_pct = diff_for(r)
            if delta_pct:
                d = float(delta_pct)
                if d >= 5:  regressions.append((d, group, algo, r["scenario"], r["ns"]))
                elif d <= -5: improvements.append((d, group, algo, r["scenario"], r["ns"]))
            cell = [
                args.iteration, group, str(gid), domain, algo, r["tier"], r["scenario"],
                f'{r["ns"]:.2f}', f'{r["lo"]:.2f}', f'{r["hi"]:.2f}',
                r["thr"], r["thr_unit"], r["tier"], str(r["variance_pct"]),
                sc, pr, strat if r is grp[0] else "",
                prev_ns, delta_pct, "benchmarked",
            ]
            lines.append(",".join(c.replace(",", ";") for c in cell))
    with open(out_csv, "w") as f:
        f.write("\n".join(lines) + "\n")

    save_snapshot(args.iteration, rows)

    # optimization plan
    order = {"high": 0, "medium": 1}
    plan_items.sort(key=lambda x: (order[x[0]], -x[3]))
    plan = [f"# Optimization Plan — iteration {args.iteration}\n",
            f"_{len(by_algo)} algorithms profiled, {len(rows)} measurements._\n",
            f"_{len(plan_items)} flagged for optimization (high/medium priority)._\n"]

    if prev:
        plan.append(f"\n## Δ vs iteration {prev_tag}\n")
        regressions.sort(reverse=True)
        improvements.sort()
        plan.append(f"- **{len(improvements)} improved** (≥5% faster), "
                    f"**{len(regressions)} regressed** (≥5% slower)\n")
        if improvements:
            plan.append("\n### Top improvements\n| group | algo | scenario | now | Δ% |")
            plan.append("|-------|------|----------|-----|----|")
            for d, g, a, sc_, ns in improvements[:15]:
                plan.append(f"| {g} | {a} | {sc_} | {fmt(ns)} | {d:+.1f} |")
        if regressions:
            plan.append("\n### Regressions (investigate)\n| group | algo | scenario | now | Δ% |")
            plan.append("|-------|------|----------|-----|----|")
            for d, g, a, sc_, ns in regressions[:15]:
                plan.append(f"| {g} | {a} | {sc_} | {fmt(ns)} | {d:+.1f} |")
    else:
        plan.append("\n_(first iteration — no previous snapshot to diff against)_\n")

    plan += ["\n## Ranked optimization targets\n",
             "| # | prio | group | algo | worst | scaling | strategy |",
             "|---|------|-------|------|-------|---------|----------|"]
    for i, (pr, group, algo, worst, sc, strat) in enumerate(plan_items, 1):
        plan.append(f"| {i} | {pr} | {group} | {algo} | {fmt(worst)} | {sc} | {strat} |")
    with open("scripts/optimization_plan.md", "w") as f:
        f.write("\n".join(plan) + "\n")

    print(f"Wrote {out_csv} ({len(lines)-1} rows) and scripts/optimization_plan.md "
          f"({len(plan_items)} targets)")

def strategy_for(sc, pr, grp):
    if pr == "none":
        return "—"
    worst = max(r["ns"] for r in grp)
    hi_var = any(r["variance_pct"] > 15 for r in grp)
    hints = []
    if sc == "quadratic+":
        hints.append("replace algo (quadratic) — use n·log n / hashing")
    elif sc == "super-linear":
        hints.append("reduce per-element work; check allocs in loop")
    if worst > 10000:
        hints.append("SIMD/SWAR bulk path")
    elif worst > 1000:
        hints.append("unroll + branch reduction")
    if hi_var:
        hints.append("stabilize: avoid alloc churn / cache misses")
    if not hints:
        hints.append("micro-opt: inline + precompute")
    return "; ".join(hints)

if __name__ == "__main__":
    main()
