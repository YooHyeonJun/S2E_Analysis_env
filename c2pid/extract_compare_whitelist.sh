#!/usr/bin/env bash
set -euo pipefail

# Extract compare-guided whitelist candidates from S2E debug log.
#
# Usage:
#   c2pid/extract_compare_whitelist.sh [debug.txt] [output.env]

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEBUG_LOG="${1:-$ROOT_DIR/s2e-last/debug.txt}"
OUT_FILE="${2:-$ROOT_DIR/c2pid/compare-whitelist.auto.env}"

if [[ ! -f "$DEBUG_LOG" ]]; then
  echo "debug log not found: $DEBUG_LOG" >&2
  exit 1
fi

TMP_CALLS="$(mktemp)"
TMP_RETS="$(mktemp)"
trap 'rm -f "$TMP_CALLS" "$TMP_RETS"' EXIT

# Preferred source: compare-guide logs from hooks.lua
rg -o "caller=[^ ]+" "$DEBUG_LOG" | sed 's/^caller=//' | sort -u > "$TMP_CALLS" || true
rg -o "retaddr=0x[0-9a-fA-F]+" "$DEBUG_LOG" | sed 's/^retaddr=//' | tr 'A-F' 'a-f' | sort -u > "$TMP_RETS" || true

calls_csv=""
rets_csv=""

if [[ -s "$TMP_CALLS" ]]; then
  calls_csv="$(paste -sd, "$TMP_CALLS")"
fi

if [[ -s "$TMP_RETS" ]]; then
  rets_csv="$(paste -sd, "$TMP_RETS")"
fi

{
  echo "# Auto-generated from: $DEBUG_LOG"
  echo "# Source lines expected from hooks:"
  echo "#   [c2pid] <fn> guide caller=<module+offset> module=<name> retaddr=0x... len=... const=..."
  echo
  echo "export S2E_C2_GUIDE_COMPARE=1"
  echo "export S2E_C2_COMPARE_MAX_PREFIX=\${S2E_C2_COMPARE_MAX_PREFIX:-32}"
  echo
  if [[ -n "$calls_csv" ]]; then
    echo "export S2E_C2_COMPARE_CALLSITE_WHITELIST=\"$calls_csv\""
  else
    echo "# No caller=<module+offset> entries found in this debug log."
    echo "# Fill manually after running with compare-guide logs enabled:"
    echo "# export S2E_C2_COMPARE_CALLSITE_WHITELIST=\"target_module+0x1234,msvcrt.dll+0x5678\""
  fi
  echo
  if [[ -n "$rets_csv" ]]; then
    echo "export S2E_C2_COMPARE_RETADDR_WHITELIST=\"$rets_csv\""
  else
    echo "# No retaddr=0x... entries found in this debug log."
    echo "# Optional fallback:"
    echo "# export S2E_C2_COMPARE_RETADDR_WHITELIST=\"0x7ff7deadbeef\""
  fi
  echo
  echo "# Apply in current shell:"
  echo "#   source \"$OUT_FILE\""
} > "$OUT_FILE"

echo "wrote whitelist template: $OUT_FILE"
if [[ -z "$calls_csv" && -z "$rets_csv" ]]; then
  echo "note: no guide callsite/retaddr was found in this log; template contains placeholders" >&2
fi
