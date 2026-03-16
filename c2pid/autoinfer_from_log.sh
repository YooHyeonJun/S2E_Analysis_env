#!/usr/bin/env bash
set -euo pipefail

# Build an inferred C2 scenario from c2pid compare logs.
# Usage:
#   c2pid/autoinfer_from_log.sh /tmp/c2_run.log /home/.../c2-scenarios.auto.lua

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <c2_run.log> <out_scenario.lua>" >&2
  exit 1
fi

LOG_FILE="$1"
OUT_FILE="$2"

if [[ ! -f "$LOG_FILE" ]]; then
  echo "log not found: $LOG_FILE" >&2
  exit 1
fi

tmp_candidates="$(mktemp)"
trap 'rm -f "$tmp_candidates"' EXIT

# Extract expected strings from lines like:
# 1) [c2pid] strcmp a=... b=...
# 2) fallback: [c2pid] inject stage=... data=...
awk '
  function unescape(s,    t) {
    t = s
    gsub(/\\\\\\\\n/, "\n", t)
    gsub(/\\\\\\\\r/, "\r", t)
    gsub(/\\\\\\\\t/, "\t", t)
    gsub(/\\\\n/, "\n", t)
    gsub(/\\\\r/, "\r", t)
    gsub(/\\\\t/, "\t", t)
    gsub(/\\\\\\\\/, "\\", t)
    return t
  }
  /\[c2pid\] strcmp a=/ {
    line = $0
    sub(/^.*\[c2pid\] strcmp a=/, "", line)
    split(line, ab, " b=")
    b = ab[2]
    if (b == "" || b == "<nil>") next
    b = unescape(b)
    # Keep printable-ish tokens and common C2 command style strings.
    if (length(b) < 3) next
    print b
  }
  /\[c2pid\] inject stage=/ {
    line = $0
    sub(/^.* data=/, "", line)
    if (line == "" || line == "<nil>") next
    line = unescape(line)
    if (length(line) < 3) next
    print line
  }
' "$LOG_FILE" > "$tmp_candidates"

if [[ ! -s "$tmp_candidates" ]]; then
  echo "no strcmp candidates found in: $LOG_FILE" >&2
  exit 2
fi

# Deduplicate while preserving order.
mapfile -t uniq_lines < <(awk '!seen[$0]++' "$tmp_candidates")

{
  echo "-- Auto-generated from $LOG_FILE"
  echo "-- Generated at $(date -Iseconds)"
  echo "C2_SCENARIOS = C2_SCENARIOS or {}"
  echo "C2_SCENARIOS.auto_inferred = {"
  echo '    name = "auto-inferred-from-log",'
  echo "    responses = {"
  for s in "${uniq_lines[@]}"; do
    # Escape for Lua string literal.
    esc="${s//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    esc="${esc//$'\n'/\\n}"
    esc="${esc//$'\r'/\\r}"
    esc="${esc//$'\t'/\\t}"
    printf '        "%s",\n' "$esc"
  done
  echo "    },"
  echo "    symbolic_ranges = {},"
  echo "}"
} > "$OUT_FILE"

echo "wrote inferred scenario: $OUT_FILE"
echo "responses: ${#uniq_lines[@]}"
