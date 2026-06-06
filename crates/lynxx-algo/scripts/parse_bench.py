#!/usr/bin/env python3
"""Parse Criterion vs_nginx_c output; print rust vs nginx_c losers."""
import re
import sys
from pathlib import Path

def to_ns(val: str, unit: str) -> float:
    v = float(val)
    if unit == "ps":
        return v / 1000
    if unit == "ns":
        return v
    if unit == "µs":
        return v * 1000
    if unit == "ms":
        return v * 1_000_000
    raise ValueError(unit)

def parse_time(line: str) -> float | None:
    m = re.search(r"time:\s+\[([^\]]+)\]", line)
    if not m:
        return None
    parts = m.group(1).split()
    if len(parts) < 6:
        return None
    unit = parts[3]
    if unit == "us":
        unit = "µs"
    if unit not in ("ps", "ns", "µs", "ms"):
        return None
    return to_ns(parts[2], unit)

ANSI = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(s: str) -> str:
    return ANSI.sub("", s)

def main() -> int:
    if len(sys.argv) > 1:
        text = "".join(Path(p).read_text(errors="replace") for p in sys.argv[1:])
    else:
        text = sys.stdin.read()
    text = strip_ansi(text)
    entries: dict[str, dict[str, float]] = {}
    cur_group = cur_who = None
    for line in text.splitlines():
        m = re.match(r"^([\w_]+)/(.+?)\s+time:\s+\[", line)
        if m:
            cur_group, cur_who = m.group(1), m.group(2)
            t = parse_time(line)
            if t is not None:
                entries.setdefault(cur_group, {})[cur_who] = t
            continue
        m2 = re.match(r"^([\w_]+)/(.+)$", line.strip())
        if m2:
            cur_group, cur_who = m2.group(1), m2.group(2)
            continue
        if cur_group and cur_who:
            t = parse_time(line)
            if t is not None:
                entries.setdefault(cur_group, {})[cur_who] = t

    losers = []
    winners = total = 0
    print("group,rust_ns,c_ns,winner,margin_pct")
    for g in sorted(entries):
        d = entries[g]
        rust_keys = [k for k in d if k.startswith("rust")]
        c_keys = [k for k in d if "nginx_c" in k]
        if not rust_keys or not c_keys:
            print(f"{g},,,skip,")
            continue
        rust = min(d[k] for k in rust_keys)
        c = min(d[k] for k in c_keys)
        total += 1
        if rust <= c:
            winners += 1
            win = "rust"
            margin = (c - rust) / c * 100
        else:
            win = "nginx_c"
            margin = (rust - c) / c * 100
            losers.append((g, rust, c, margin))
        print(f"{g},{rust:.0f},{c:.0f},{win},{margin:.1f}")

    print(f"\n# rust ahead: {winners}/{total}", file=sys.stderr)
    if losers:
        print("# LOSERS:", file=sys.stderr)
        for g, r, c, m in sorted(losers, key=lambda x: -x[3]):
            print(f"#   {g}: rust {r:.0f}ns c {c:.0f}ns (+{m:.1f}%)", file=sys.stderr)
    return 1 if losers else 0

if __name__ == "__main__":
    raise SystemExit(main())
