#!/usr/bin/env bash
set -euo pipefail

# Extract c2pid symbolic response model from solver-queries.smt2
# and generate a Lua scenario file.
#
# Usage:
#   c2pid/extract_solver_model.sh <solver-queries.smt2> <out_scenario.lua>

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <solver-queries.smt2> <out_scenario.lua>" >&2
  exit 1
fi

SMT2="$1"
OUT_FILE="$2"

if [[ ! -f "$SMT2" ]]; then
  echo "solver file not found: $SMT2" >&2
  exit 1
fi

tmp_bytes="$(mktemp)"
tmp_resp="$(mktemp)"
trap 'rm -f "$tmp_bytes" "$tmp_resp"' EXIT

# Parse lines like:
# ;     v0_c2pid_resp_2_0 = [84,65,83,...]
awk '
  {
    if (match($0, /c2pid_resp_([0-9]+)_([0-9]+)/, m)) {
      stage = m[1] + 0
      base = m[2] + 0
      line = $0
      sub(/^.* = \[/, "", line)
      sub(/\].*$/, "", line)
      n = split(line, a, /, */)
      for (i = 1; i <= n; i++) {
        if (a[i] == "") continue
        off = base + (i - 1)
        v = a[i] + 0
        print stage "\t" off "\t" v
      }
    }
  }
' "$SMT2" > "$tmp_bytes"

if [[ ! -s "$tmp_bytes" ]]; then
  echo "no c2pid_resp_* model entries found in $SMT2" >&2
  exit 2
fi

# Keep latest value per (stage, off), then sort.
# Early SAT queries often contain trivial models (e.g., all 0x00/0x0A).
# Using the latest model better reflects the final solved branch.
awk -F'\t' '{ latest[$1 FS $2] = $0 } END { for (k in latest) print latest[k] }' "$tmp_bytes" \
  | sort -t $'\t' -k1,1n -k2,2n > "$tmp_resp"

awk -F'\t' '
  function chr(v) {
    return sprintf("%c", v)
  }
  function esc(s,    i,b,out,ch) {
    out = ""
    for (i = 1; i <= length(s); i++) {
      ch = substr(s, i, 1)
      b = ord[ch]
      if (ch == "\\") out = out "\\\\"
      else if (ch == "\"") out = out "\\\""
      else if (ch == "\n") out = out "\\n"
      else if (ch == "\r") out = out "\\r"
      else if (ch == "\t") out = out "\\t"
      else if (b >= 32 && b <= 126) out = out ch
      else out = out sprintf("\\x%02X", b)
    }
    return out
  }
  BEGIN {
    for (i = 0; i < 256; i++) {
      ord[sprintf("%c", i)] = i
    }
  }
  {
    st = $1 + 0
    off = $2 + 0
    val = $3 + 0
    if (off > maxoff[st]) maxoff[st] = off
    key = st ":" off
    byte[key] = val
    if (!(st in seen_stage)) {
      seen_stage[st] = 1
      stages[++nst] = st
    }
  }
  END {
    print "-- Auto-generated from solver model"
    print "C2_SCENARIOS = C2_SCENARIOS or {}"
    print "C2_SCENARIOS.auto_solved = {"
    print "    name = \"auto-solved-from-solver\","
    print "    responses = {"
    for (si = 1; si <= nst; si++) {
      st = stages[si]
      s = ""
      for (i = 0; i <= maxoff[st]; i++) {
        key = st ":" i
        if (key in byte) s = s chr(byte[key])
      }
      printf("        \"%s\",\n", esc(s))
    }
    print "    },"
    print "    symbolic_ranges = {},"
    print "}"
  }
' "$tmp_resp" > "$OUT_FILE"

echo "wrote solved scenario: $OUT_FILE"
