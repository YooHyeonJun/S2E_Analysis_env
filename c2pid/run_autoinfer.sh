#!/usr/bin/env bash
set -euo pipefail

# One-step helper:
# 1) infer responses from a previous log
# 2) run S2E with inferred scenario file
#
# Usage:
#   c2pid/run_autoinfer.sh /tmp/c2_run.log

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${S2E_C2_LOG_DIR:-$ROOT_DIR/logs}"
AUTO_LOG="${S2E_C2_AUTO_LOG:-$LOG_DIR/c2_run_auto.log}"
IN_LOG="${1:-/tmp/c2_run.log}"
SCEN_FILE="$ROOT_DIR/c2-scenarios.auto.lua"

cd "$ROOT_DIR"
mkdir -p "$LOG_DIR"

chmod +x c2pid/autoinfer_from_log.sh
c2pid/autoinfer_from_log.sh "$IN_LOG" "$SCEN_FILE"

echo c2pid > input-mode.txt

S2E_C2_MODE=concrete \
S2E_C2_SCENARIO_FILE="$SCEN_FILE" \
S2E_C2_SCENARIO=auto_inferred \
./launch-s2e.sh | tee "$AUTO_LOG"

echo "done: $AUTO_LOG"
