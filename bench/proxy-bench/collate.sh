#!/usr/bin/env bash
# collate.sh — combine all outputs/<proxy>/*.json into one view.
#
# Reads every per-sweep JSON the bench wrote and produces:
#   outputs/_collated.json   (canonical: ranking + all selected sweeps inline)
#   outputs/_summary.csv     (one row per (proxy, rps_target), for plotting)
#   outputs/_summary.md      (human-readable proxy-by-proxy comparison)
#
# Usage:
#   ./collate.sh                     # latest sweep per proxy (max seq), all formats
#   ./collate.sh --all               # include every sweep (every NN.json)
#   ./collate.sh --seq 01            # pin a specific seq across all proxies
#   ./collate.sh --proxies "lynxx kong nginx"   # restrict + reorder
#   ./collate.sh --outputs-dir /tmp/foo         # different source dir
#
# Depends on jq. No Python required.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source bench.conf so we get BENCH_OUTPUTS_DIR's default. But the user
# is most likely running this on their laptop against the repo dir, not
# on the VM, so the actual default we want is $HERE/outputs.
OUTPUTS_DIR="$HERE/outputs"
SELECTION="latest"       # latest | all
PIN_SEQ=""               # if set, only include this seq number (e.g. 01)
PROXIES_FILTER=""        # space-separated subset; empty = all found

while (( $# > 0 )); do
  case "$1" in
    --all)            SELECTION="all";       shift ;;
    --latest)         SELECTION="latest";    shift ;;
    --seq)            PIN_SEQ="$2";          shift 2 ;;
    --proxies)        PROXIES_FILTER="$2";   shift 2 ;;
    --outputs-dir)    OUTPUTS_DIR="$2";      shift 2 ;;
    -h|--help)
      sed -n '2,/^set/p' "$0" | grep -E '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }

if [[ ! -d "$OUTPUTS_DIR" ]]; then
  echo "ERROR: outputs dir not found: $OUTPUTS_DIR" >&2; exit 1
fi

# ─── Step 1: enumerate sweeps to include ─────────────────────────────────
# Build a newline-separated list of files we'll feed into jq.
shopt -s nullglob
files=()
proxies_seen=()

# Determine proxy order. With --proxies the caller's order wins;
# otherwise we sort the proxy directories alphabetically but pull
# "direct" to the front since it's the baseline.
if [[ -n "$PROXIES_FILTER" ]]; then
  read -ra proxy_list <<< "$PROXIES_FILTER"
else
  proxy_list=()
  for d in "$OUTPUTS_DIR"/*/; do
    [[ -d "$d" ]] || continue
    name=$(basename "$d")
    [[ "$name" == _* ]] && continue   # skip _foo helper dirs
    proxy_list+=("$name")
  done
  # Pull "direct" to the front if present.
  reordered=()
  for p in "${proxy_list[@]}"; do [[ "$p" == "direct" ]] && reordered+=("$p"); done
  for p in "${proxy_list[@]}"; do [[ "$p" != "direct" ]] && reordered+=("$p"); done
  proxy_list=("${reordered[@]}")
fi

for proxy in "${proxy_list[@]}"; do
  pdir="$OUTPUTS_DIR/$proxy"
  [[ -d "$pdir" ]] || { echo "WARN: no outputs/$proxy dir, skipping" >&2; continue; }
  candidates=("$pdir"/*.json)
  (( ${#candidates[@]} == 0 )) && { echo "WARN: outputs/$proxy is empty" >&2; continue; }

  if [[ -n "$PIN_SEQ" ]]; then
    f="$pdir/$PIN_SEQ.json"
    [[ -f "$f" ]] || { echo "WARN: outputs/$proxy/$PIN_SEQ.json missing" >&2; continue; }
    files+=("$f"); proxies_seen+=("$proxy")
  elif [[ "$SELECTION" == "all" ]]; then
    for f in "${candidates[@]}"; do files+=("$f"); proxies_seen+=("$proxy"); done
  else
    # latest — highest seq per proxy.
    latest=$(printf '%s\n' "${candidates[@]}" \
      | sed 's|.*/||; s/\.json$//' \
      | sort -n | tail -1)
    f="$pdir/$latest.json"
    files+=("$f"); proxies_seen+=("$proxy")
  fi
done

(( ${#files[@]} == 0 )) && { echo "ERROR: no JSON files matched" >&2; exit 1; }

echo "Collating ${#files[@]} sweep file(s) from $OUTPUTS_DIR"
printf '  - %s\n' "${files[@]}"

# Preserve proxy order for jq. Stringify into a JSON array literal.
proxy_order_json=$(printf '%s\n' "${proxy_list[@]}" \
  | jq -R . | jq -s .)

# ─── Step 2: build _collated.json ────────────────────────────────────────
# We slurp every sweep file into an array, then:
#   - rank by ceiling RPS (max achieved across levels)
#   - emit a top-level "ranking_by_ceiling" summary array
#   - keep every full sweep in "sweeps" so consumers can drill in
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

collated_json="$OUTPUTS_DIR/_collated.json"
jq -n --slurpfile sweeps <(jq -s . "${files[@]}") \
      --arg generated_at "$generated_at" \
      --arg selection "$SELECTION" \
      --argjson proxy_order "$proxy_order_json" '
  ($sweeps | first) as $raw |
  {
    generated_at:    $generated_at,
    selection:       $selection,
    n_sweeps:        ($raw | length),
    proxy_order:     $proxy_order,
    ranking_by_ceiling: (
      $raw
      | map({
          proxy,
          seq,
          status,
          ceiling_rps:     ([.levels[].achieved_rps] | max // 0),
          best_p50_ms:     ([.levels[].p50_ms      | select(. != null)] | min // null),
          best_p99_ms:     ([.levels[].p99_ms      | select(. != null)] | min // null),
          worst_p99_ms:    ([.levels[].p99_ms      | select(. != null)] | max // null),
          total_requests:  ([.levels[].requests]   | add // 0),
          total_errors:    ([.levels[].errors]     | add // 0),
          ladder_cut_at_rps,
          started_at, finished_at
        })
      | sort_by(-.ceiling_rps)
    ),
    sweeps: $raw
  }' > "$collated_json"

echo "wrote $collated_json"

# ─── Step 3: build _summary.csv ──────────────────────────────────────────
# One row per (proxy, seq, rps_target). Columns chosen to match what
# report.py expects (proxy, rps_target, rps_achieved, p50, p95, p99,
# p99.9, errors, err_rate) so the existing markdown generator can be
# pointed at this CSV with minimal massaging. Latencies stay in ms.
summary_csv="$OUTPUTS_DIR/_summary.csv"
{
  echo "proxy,seq,rps_target,rps_achieved,duration_secs,requests,errors,err_rate,p50_ms,p95_ms,p99_ms,p99_9_ms,min_ms,max_ms,exploded"
  jq -r '
    .sweeps[]
    | . as $s
    | .levels[]
    | [
        $s.proxy, $s.seq, .target_rps, .achieved_rps, .duration_secs,
        .requests, .errors,
        (if .requests > 0 then (.errors / .requests) else 0 end),
        .p50_ms, .p95_ms, .p99_ms, .p99_9_ms, .min_ms, .max_ms,
        .exploded
      ]
    | @csv
  ' "$collated_json"
} > "$summary_csv"

rows=$(($(wc -l < "$summary_csv") - 1))
echo "wrote $summary_csv ($rows rows)"

# ─── Step 4: build _summary.md ───────────────────────────────────────────
# Two tables:
#   1. Per-proxy headline: ceiling, best p99, status, error count
#   2. Iso-load p99 grid: rows are RPS levels, columns are proxies
summary_md="$OUTPUTS_DIR/_summary.md"
{
  echo "# Proxy bench summary"
  echo
  echo "_Generated $generated_at from $OUTPUTS_DIR — selection: \`$SELECTION\`._"
  echo
  echo "## Headline ranking (sorted by sustained ceiling RPS)"
  echo
  echo "| Proxy | Seq | Status | Ceiling RPS | Best p99 (ms) | Worst p99 (ms) | Errors | Ladder cut |"
  echo "|---|---:|---|---:|---:|---:|---:|---:|"
  jq -r '
    .ranking_by_ceiling[]
    | [
        .proxy, .seq, .status,
        .ceiling_rps,
        (.best_p99_ms // "—"),
        (.worst_p99_ms // "—"),
        .total_errors,
        (.ladder_cut_at_rps // "—")
      ]
    | "| " + (map(tostring) | join(" | ")) + " |"
  ' "$collated_json"
  echo
  echo "## p99 (ms) by RPS level — iso-load grid"
  echo
  # Build the grid in jq. Proxies as columns (in proxy_order),
  # rows are the union of all target_rps seen.
  jq -r '
    (.proxy_order
     | map(. as $p | select( ($p as $px | $px) | tostring ))) as $proxies
    |
    # Filter $proxies to those that actually appear in sweeps
    ([.sweeps[].proxy] | unique) as $present |
    ($proxies | map(select(. as $p | $present | index($p)))) as $cols |
    # Union of all RPS values seen, sorted numerically
    ([.sweeps[].levels[].target_rps] | unique | sort) as $rpss |
    # Lookup: (proxy, rps) → p99_ms (or "—")
    (reduce (.sweeps[] | . as $s | $s.levels[] | {key: ($s.proxy + "@" + (.target_rps|tostring)), v: (.p99_ms // null), exp: .exploded}) as $row
        ({}; . + {($row.key): {v: $row.v, exp: $row.exp}})
    ) as $lk |
    # Header
    "| RPS | " + ($cols | join(" | ")) + " |",
    "|---:|" + ($cols | map("---:") | join("|")) + "|",
    # Rows
    ($rpss[] |
      . as $rps |
      "| " + ($rps|tostring) + " | " +
      ($cols | map(
        ($lk[. + "@" + ($rps|tostring)]) as $cell
        | if $cell == null then "—"
          elif $cell.v == null then "—"
          elif $cell.exp then "💥 " + ($cell.v|tostring)
          else ($cell.v|tostring) end
      ) | join(" | ")) + " |"
    )
  ' "$collated_json"
  echo
  echo "## Achieved RPS — was the SUT the bottleneck?"
  echo
  echo "_When achieved < target, the proxy is the bottleneck. When they match, the bench client could go higher._"
  echo
  jq -r '
    ([.sweeps[].proxy] | unique) as $present |
    (.proxy_order | map(select(. as $p | $present | index($p)))) as $cols |
    ([.sweeps[].levels[].target_rps] | unique | sort) as $rpss |
    (reduce (.sweeps[] | . as $s | $s.levels[] | {key: ($s.proxy + "@" + (.target_rps|tostring)), v: .achieved_rps}) as $row
        ({}; . + {($row.key): $row.v})
    ) as $lk |
    "| RPS target | " + ($cols | join(" | ")) + " |",
    "|---:|" + ($cols | map("---:") | join("|")) + "|",
    ($rpss[] |
      . as $rps |
      "| " + ($rps|tostring) + " | " +
      ($cols | map(
        ($lk[. + "@" + ($rps|tostring)]) as $a
        | if $a == null then "—" else ($a|tostring) end
      ) | join(" | ")) + " |"
    )
  ' "$collated_json"
} > "$summary_md"

echo "wrote $summary_md"

# ─── Step 5: print a tiny terminal table for instant feedback ───────────
echo
echo "=== Ranking ==="
jq -r '
  ["proxy","seq","status","ceiling_rps","best_p99_ms","errors"],
  (.ranking_by_ceiling[]
    | [.proxy, .seq, .status, .ceiling_rps,
       (.best_p99_ms // "—"), .total_errors])
  | @tsv
' "$collated_json" | column -t -s $'\t'
