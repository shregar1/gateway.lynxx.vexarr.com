#!/usr/bin/env bash
# Profile nginx-algo benchmarks and emit flamegraph.svg (or a samply profile on macOS without Xcode).
set -euo pipefail
cd "$(dirname "$0")/.."

BENCH="${1:-profile-hot}"
FILTER="${2:-}"

if [[ "$BENCH" == "profile-hot" ]]; then
  echo "==> Profiling bin profile-hot (fast hot-loop for profilers)"
  ARGS=(--bin profile-hot --profile flamegraph)
else
  echo "==> Profiling bench '${BENCH}' (profile=flamegraph, release + debug symbols)"
  ARGS=(--bench "$BENCH" --profile flamegraph -- --bench)
  if [[ -n "$FILTER" ]]; then
    ARGS+=(-- "$FILTER")
  fi
fi

run_cargo_flamegraph() {
  cargo flamegraph "${ARGS[@]}"
}

run_samply() {
  echo "==> Using samply (Xcode Instruments unavailable)"
  local out="samply-profile.json.gz"
  samply record --save-only --no-open -o "$out" cargo run "${ARGS[@]}"
  echo "==> Wrote $(pwd)/$out"
  echo "    View: samply load $out"
}

if command -v flamegraph >/dev/null 2>&1 || cargo flamegraph --help >/dev/null 2>&1; then
  if run_cargo_flamegraph 2>/tmp/flamegraph.err; then
    if [[ -f flamegraph.svg ]]; then
      echo "==> Wrote $(pwd)/flamegraph.svg"
      if command -v open >/dev/null 2>&1; then
        open flamegraph.svg || true
      fi
      exit 0
    fi
  fi
  if grep -q "xctrace\|Xcode\|sample program" /tmp/flamegraph.err 2>/dev/null; then
    echo "==> cargo flamegraph failed (macOS needs full Xcode or samply)"
    if command -v samply >/dev/null 2>&1; then
      run_samply
      exit 0
    fi
    cat /tmp/flamegraph.err
    echo "Install one of:"
    echo "  - Xcode.app (for xctrace), or"
    echo "  - cargo install samply"
    exit 1
  fi
  cat /tmp/flamegraph.err
  exit 1
fi

echo "Install: cargo install flamegraph   # or: cargo install samply"
exit 1
