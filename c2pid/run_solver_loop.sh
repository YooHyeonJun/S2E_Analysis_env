#!/usr/bin/env bash
set -euo pipefail

# Solver loop for c2pid:
# 1) Build seed scenario from log if needed
# 2) Build hybrid symbolic scenario
# 3) Run S2E in hybrid mode
# 4) Extract solved model from solver-queries.smt2
#
# Usage:
#   c2pid/run_solver_loop.sh [/tmp/c2_run.log]

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${S2E_C2_LOG_DIR:-$ROOT_DIR/logs}"
HYBRID_LOG="${S2E_C2_HYBRID_LOG:-$LOG_DIR/c2_run_hybrid.log}"
SEED_LOG="${1:-/tmp/c2_run.log}"
SEED_SCEN="$ROOT_DIR/c2-scenarios.auto.lua"
HYBRID_SCEN="$ROOT_DIR/c2-scenarios.hybrid.lua"
SOLVED_SCEN="$ROOT_DIR/c2-scenarios.solved.lua"
MAX_SYM_BYTES="${S2E_C2_MAX_SYMBOLIC_BYTES:-0}"
DISABLE_INJECT="${S2E_C2_DISABLE_INJECT:-1}"
RECV_FORMAT="${S2E_C2_RECV_FORMAT:-}"
GUIDE_COMPARE="${S2E_C2_GUIDE_COMPARE:-0}"
TRACE_COMPARE="${S2E_C2_TRACE_COMPARE:-1}"
COMPARE_BYPASS_PID="${S2E_C2_COMPARE_BYPASS_PID:-1}"
DEFAULT_TARGET_MODULE="${S2E_TARGET_MODULE:-target.exe}"
COMPARE_FALLBACK_MODULES="${S2E_C2_COMPARE_FALLBACK_MODULES:-${DEFAULT_TARGET_MODULE},msvcrt.dll,ucrtbase.dll,kernel32.dll}"
COMPARE_AFTER_NET_ONLY="${S2E_C2_COMPARE_AFTER_NET_ONLY:-1}"
COMPARE_AFTER_NET_BUDGET="${S2E_C2_COMPARE_AFTER_NET_BUDGET:-8}"
USER_SCEN_FILE="${S2E_C2_SCENARIO_FILE:-}"
USER_SCEN_NAME="${S2E_C2_SCENARIO:-}"

cd "$ROOT_DIR"
mkdir -p "$LOG_DIR"

chmod +x c2pid/autoinfer_from_log.sh c2pid/extract_solver_model.sh

write_fallback_seed_scenario() {
  cat > "$SEED_SCEN" <<'LUA'
-- Auto-generated fallback scenario (no compare candidates found in seed log)
C2_SCENARIOS = C2_SCENARIOS or {}
C2_SCENARIOS.auto_inferred = {
    name = "auto-inferred-fallback",
    responses = {
        "PING\n",
        "OK\n",
        "ACK\n",
    },
    symbolic_ranges = {},
}
LUA
}

# Refresh inferred scenario from the latest log.
# If no compare candidates are found, keep loop alive with a fallback seed.
if ! c2pid/autoinfer_from_log.sh "$SEED_LOG" "$SEED_SCEN"; then
  echo "warning: autoinfer failed for $SEED_LOG; using fallback seed scenario" >&2
  write_fallback_seed_scenario
fi

# Build a hybrid scenario from inferred responses.
# Keep symbolic range tight to avoid tainting unrelated OS/device paths.
awk '
  function decoded_len(s,   t) {
    t = s
    # Collapse escaped byte forms to 1 byte equivalents.
    gsub(/\\x[0-9A-Fa-f][0-9A-Fa-f]/, "X", t)
    gsub(/\\n/, "N", t)
    gsub(/\\r/, "R", t)
    gsub(/\\t/, "T", t)
    gsub(/\\\\/, "B", t)
    return length(t)
  }

  BEGIN {
    in_auto = 0
    in_resp = 0
    n = 0
    max_sym = ENVIRON["MAX_SYM_BYTES"] + 0
    # 0 means "no cap".
  }
  /C2_SCENARIOS\.auto_inferred *= *\{/ { in_auto = 1 }
  in_auto && /responses *= *\{/ { in_resp = 1; next }
  in_auto && in_resp && /^[[:space:]]*}/ { in_resp = 0; next }
  in_auto && in_resp {
    if (match($0, /"([^"]*)"/, m)) {
      resp[++n] = m[1]
    }
  }
  END {
    print "-- Auto-generated hybrid symbolic scenario"
    print "C2_SCENARIOS = C2_SCENARIOS or {}"
    print "C2_SCENARIOS.auto_hybrid = {"
    print "    name = \"auto-hybrid\","
    print "    responses = {"
    for (i = 1; i <= n; i++) {
      printf("        \"%s\",\n", resp[i])
    }
    print "    },"
    print "    symbolic_ranges = {"
    for (i = 1; i <= n; i++) {
      sym_n = decoded_len(resp[i])
      if (sym_n < 1) {
        sym_n = 1
      }
      if (max_sym > 0 && sym_n > max_sym) {
        sym_n = max_sym
      }
      printf("        [%d] = { {0, %d} },\n", i, sym_n)
    }
    print "    },"
    print "}"
  }
' "$SEED_SCEN" > "$HYBRID_SCEN"

RUN_SCEN_FILE="$HYBRID_SCEN"
RUN_SCEN_NAME="auto_hybrid"
if [[ -n "$USER_SCEN_FILE" ]]; then
  RUN_SCEN_FILE="$USER_SCEN_FILE"
fi
if [[ -n "$USER_SCEN_NAME" ]]; then
  RUN_SCEN_NAME="$USER_SCEN_NAME"
fi

echo c2pid > input-mode.txt

S2E_C2_MODE=hybrid \
S2E_C2_SCENARIO_FILE="$RUN_SCEN_FILE" \
S2E_C2_SCENARIO="$RUN_SCEN_NAME" \
S2E_C2_DISABLE_INJECT="$DISABLE_INJECT" \
S2E_C2_TRACE_COMPARE="$TRACE_COMPARE" \
S2E_C2_GUIDE_COMPARE="$GUIDE_COMPARE" \
S2E_C2_COMPARE_BYPASS_PID="$COMPARE_BYPASS_PID" \
S2E_C2_COMPARE_FALLBACK_MODULES="$COMPARE_FALLBACK_MODULES" \
S2E_C2_COMPARE_AFTER_NET_ONLY="$COMPARE_AFTER_NET_ONLY" \
S2E_C2_COMPARE_AFTER_NET_BUDGET="$COMPARE_AFTER_NET_BUDGET" \
./launch-s2e.sh | tee "$HYBRID_LOG"

LAST="$(readlink -f s2e-last)"
SOLVER_FILE="$LAST/solver-queries.smt2"

if [[ ! -s "$SOLVER_FILE" ]]; then
  echo "solver file is empty: $SOLVER_FILE" >&2
  echo "try increasing symbolic coverage or check compare hooks in $HYBRID_LOG" >&2
  exit 2
fi

c2pid/extract_solver_model.sh "$SOLVER_FILE" "$SOLVED_SCEN"

RECV_DECLS="$(rg -o 'declare-fun v[0-9]+_c2pid_recv' "$SOLVER_FILE" | wc -l || true)"
RESP_DECLS="$(rg -o 'declare-fun v[0-9]+_c2pid_resp' "$SOLVER_FILE" | wc -l || true)"
SAT_TRUE="$(rg -o 'Solvable: true' "$SOLVER_FILE" | wc -l || true)"
SAT_FALSE="$(rg -o 'Solvable: false' "$SOLVER_FILE" | wc -l || true)"
GUIDE_HITS="$(rg -o '\[c2pid\] (strcmp|strncmp|memcmp) guide' "$HYBRID_LOG" | wc -l || true)"
COMPARE_HITS="$(rg -o '\[c2pid\] (strcmp|strncmp|memcmp) hit' "$HYBRID_LOG" | wc -l || true)"
FMT_APPLIED="$(rg -o '\[c2pid\] recv-format applied' "$HYBRID_LOG" | wc -l || true)"
INJECT_DISABLED="$(rg -o '\[c2pid\] inject disabled' "$HYBRID_LOG" | wc -l || true)"
NET_EVENTS="$(rg -o '\[c2trace\] kind=net_read' "$HYBRID_LOG" | wc -l || true)"
CMP_EVENTS="$(rg -o '\[c2trace\] kind=compare' "$HYBRID_LOG" | wc -l || true)"
EDGE_EVENTS="$(rg -o '\[c2trace\] kind=edge' "$HYBRID_LOG" | wc -l || true)"
API_EVENTS="$(rg -o '\[c2trace\] kind=interesting_api' "$HYBRID_LOG" | wc -l || true)"

echo "summary:"
echo "  solver recv declares : $RECV_DECLS"
echo "  solver resp declares : $RESP_DECLS"
echo "  solvable true/false  : $SAT_TRUE / $SAT_FALSE"
echo "  compare hit/guide    : $COMPARE_HITS / $GUIDE_HITS"
echo "  trace net/cmp/api/edge: $NET_EVENTS / $CMP_EVENTS / $API_EVENTS / $EDGE_EVENTS"
echo "  recv-format applied  : $FMT_APPLIED"
echo "  inject disabled logs : $INJECT_DISABLED"

if [[ "$RECV_DECLS" -eq 0 && "$RESP_DECLS" -gt 0 ]]; then
  echo "warning: solver is still response-centric (resp), not recv-centric" >&2
fi
if [[ "$COMPARE_HITS" -gt 0 && "$GUIDE_HITS" -eq 0 ]]; then
  echo "warning: compare hooks hit, but guide constraints were not applied" >&2
fi

echo "hybrid log  : $HYBRID_LOG"
echo "solved scen : $SOLVED_SCEN"
echo "run concrete with solved scenario:"
echo "  S2E_C2_MODE=concrete S2E_C2_SCENARIO_FILE=$SOLVED_SCEN S2E_C2_SCENARIO=auto_solved ./launch-s2e.sh"
