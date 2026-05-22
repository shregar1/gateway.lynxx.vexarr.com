#!/usr/bin/env bash
# DEPRECATED — kept as a shim for callers that hardcode this path.
# The bench is now split into:
#   bench.conf              — central config
#   orchestrate-sweep.sh    — orchestrator (this script's replacement)
#   proxies/<name>.sh       — one script per gateway, self-runnable
#   lib/common.sh           — shared helpers
#
# Anything that used to set PROXIES / RPS_LEVELS / etc. via env still
# works — those vars are honored by bench.conf and the new scripts.
exec "$(dirname "$0")/orchestrate-sweep.sh" "$@"
