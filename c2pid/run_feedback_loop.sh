#!/usr/bin/env bash
set -euo pipefail

# Feedback loop controller:
# - Keep a stable baseline env
# - Apply editable strategy overlays one by one
# - Re-run solver loop and detect forced-I/O lock
# - Escape lock and try next strategy
#
# Usage:
#   c2pid/run_feedback_loop.sh [seed_log]
#
# Optional env:
#   S2E_FEEDBACK_PROFILE=default
#   S2E_FEEDBACK_BASELINE_ENV=profiles/default/profile.env
#   S2E_FEEDBACK_LOCAL_ENV=profiles/default/profile.local.env
#   S2E_FEEDBACK_STRATEGY_DIR=profiles/default/feedback_strategies
#   S2E_FEEDBACK_MAX_ITERS=6
#   S2E_FEEDBACK_FORCED_RATIO_MAX=0.98
#   S2E_FEEDBACK_MIN_RECV_DECLS=1
#   S2E_FEEDBACK_MIN_GUIDE_HITS=1
#   S2E_FEEDBACK_NEXT_INPUT_HOOK=/path/to/hook.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE_NAME="${S2E_FEEDBACK_PROFILE:-default}"
BASELINE_ENV="${S2E_FEEDBACK_BASELINE_ENV:-$ROOT_DIR/profiles/$PROFILE_NAME/profile.env}"
LOCAL_ENV="${S2E_FEEDBACK_LOCAL_ENV:-$ROOT_DIR/profiles/$PROFILE_NAME/profile.local.env}"
STRATEGY_DIR="${S2E_FEEDBACK_STRATEGY_DIR:-$ROOT_DIR/profiles/$PROFILE_NAME/feedback_strategies}"
SEED_LOG="${1:-$ROOT_DIR/run_live.log}"
MAX_ITERS="${S2E_FEEDBACK_MAX_ITERS:-6}"
FORCED_RATIO_MAX="${S2E_FEEDBACK_FORCED_RATIO_MAX:-0.98}"
MIN_RECV_DECLS="${S2E_FEEDBACK_MIN_RECV_DECLS:-1}"
MIN_GUIDE_HITS="${S2E_FEEDBACK_MIN_GUIDE_HITS:-1}"
NEXT_INPUT_HOOK="${S2E_FEEDBACK_NEXT_INPUT_HOOK:-}"

if [[ ! -f "$BASELINE_ENV" ]]; then
  echo "baseline env not found: $BASELINE_ENV" >&2
  exit 1
fi
if [[ ! -f "$SEED_LOG" ]]; then
  echo "seed log not found: $SEED_LOG" >&2
  exit 1
fi

RUN_ID="$(date +%Y%m%d_%H%M%S)_$$"
OUT_DIR="$ROOT_DIR/logs/feedback_loop/$RUN_ID"
mkdir -p "$OUT_DIR"

readarray -t STRATEGIES < <(find "$STRATEGY_DIR" -maxdepth 1 -type f -name '*.env' 2>/dev/null | sort)
if [[ ${#STRATEGIES[@]} -eq 0 ]]; then
  echo "no strategy files found under: $STRATEGY_DIR" >&2
  echo "tip: add *.env files (00_*.env, 10_*.env...)" >&2
  exit 2
fi

echo "feedback run id      : $RUN_ID"
echo "baseline env         : $BASELINE_ENV"
echo "local env            : $LOCAL_ENV"
echo "strategy dir         : $STRATEGY_DIR"
echo "seed log             : $SEED_LOG"
echo "output dir           : $OUT_DIR"

curr_seed="$SEED_LOG"
iter=0
success=0

for strat in "${STRATEGIES[@]}"; do
  iter=$((iter + 1))
  if [[ "$iter" -gt "$MAX_ITERS" ]]; then
    echo "reached max iterations: $MAX_ITERS"
    break
  fi

  strat_name="$(basename "$strat")"
  iter_dir="$OUT_DIR/iter_$iter"
  mkdir -p "$iter_dir"
  hybrid_log="$iter_dir/hybrid.log"
  solver_loop_log="$iter_dir/solver_loop.log"
  fsm_prefix="iter_${iter}"

  echo
  echo "=== iter $iter / strategy: $strat_name ==="

  set +e
  (
    set -a
    # shellcheck disable=SC1090
    . "$BASELINE_ENV"
    if [[ -f "$LOCAL_ENV" ]]; then
      # shellcheck disable=SC1090
      . "$LOCAL_ENV"
    fi
    # shellcheck disable=SC1090
    . "$strat"
    set +a

    export S2E_C2_HYBRID_LOG="$hybrid_log"
    cd "$ROOT_DIR"
    ./c2pid/run_solver_loop.sh "$curr_seed"
  ) 2>&1 | tee "$solver_loop_log"
  run_status=${PIPESTATUS[0]}
  set -e

  if [[ "$run_status" -ne 0 ]]; then
    echo "status: solver loop failed for strategy $strat_name (exit=$run_status), trying next strategy"
    curr_seed="$curr_seed"
    continue
  fi

  if [[ ! -s "$hybrid_log" ]]; then
    echo "hybrid log missing: $hybrid_log" >&2
    curr_seed="$curr_seed"
    continue
  fi

  python3 "$ROOT_DIR/scripts/build_fsm.py" \
    --log "$hybrid_log" \
    --out-dir "$iter_dir/fsm" \
    --prefix "$fsm_prefix" >/dev/null

  summary_json="$iter_dir/fsm/${fsm_prefix}.summary.json"
  summary_txt="$iter_dir/summary.txt"
  timeline_txt="$iter_dir/timeline.txt"

  python3 "$ROOT_DIR/scripts/summarize_c2_log.py" \
    "$hybrid_log" \
    --timeline-limit 120 \
    --write-timeline "$timeline_txt" > "$summary_txt" || true

  forced_ratio="$(python3 - "$summary_json" << 'PY'
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    d=json.load(f)
st=d.get('states',{})
forced=float(st.get('S5_FORCED_IO',0))
total=float(sum(st.values()))
print(f"{(forced/total if total>0 else 0.0):.6f}")
PY
)"

  guide_hits="$(rg -o '\[c2pid\] (strcmp|strncmp|memcmp) guide' "$hybrid_log" | wc -l || true)"
  compare_hits="$(rg -o '\[c2pid\] (strcmp|strncmp|memcmp) hit' "$hybrid_log" | wc -l || true)"

  solver_file="$(readlink -f "$ROOT_DIR/s2e-last/solver-queries.smt2" 2>/dev/null || true)"
  recv_decls=0
  resp_decls=0
  if [[ -n "$solver_file" && -f "$solver_file" ]]; then
    recv_decls="$(rg -o 'declare-fun v[0-9]+_c2pid_recv' "$solver_file" | wc -l || true)"
    resp_decls="$(rg -o 'declare-fun v[0-9]+_c2pid_resp' "$solver_file" | wc -l || true)"
    cp -f "$solver_file" "$iter_dir/solver-queries.smt2" || true
  fi

  echo "iter metrics:"
  echo "  forced_ratio       : $forced_ratio"
  echo "  compare hit/guide  : $compare_hits / $guide_hits"
  echo "  solver recv/resp   : $recv_decls / $resp_decls"

  {
    echo ""
    echo "Feedback Metrics"
    echo "- forced_ratio: $forced_ratio"
    echo "- compare hit/guide: $compare_hits / $guide_hits"
    echo "- solver recv/resp: $recv_decls / $resp_decls"
    echo "- hybrid_log: $hybrid_log"
    echo "- fsm_summary: $summary_json"
    echo "- timeline: $timeline_txt"
  } >> "$summary_txt"

  cat > "$iter_dir/metrics.env" <<MET
ITER=$iter
STRATEGY=$strat_name
SEED_LOG=$curr_seed
HYBRID_LOG=$hybrid_log
FORCED_RATIO=$forced_ratio
COMPARE_HITS=$compare_hits
GUIDE_HITS=$guide_hits
RECV_DECLS=$recv_decls
RESP_DECLS=$resp_decls
MET

  is_good="$(python3 - <<PY
forced=float("$forced_ratio")
forced_max=float("$FORCED_RATIO_MAX")
recv=int("$recv_decls")
guide=int("$guide_hits")
min_recv=int("$MIN_RECV_DECLS")
min_guide=int("$MIN_GUIDE_HITS")
ok = (forced <= forced_max) and (recv >= min_recv) and (guide >= min_guide)
print("1" if ok else "0")
PY
)"

  if [[ "$is_good" == "1" ]]; then
    echo "status: converged on iter $iter"
    success=1
    break
  fi

  echo "status: forced-io lock or weak constraints, escalating strategy"

  if [[ -n "$NEXT_INPUT_HOOK" && -x "$NEXT_INPUT_HOOK" ]]; then
    "$NEXT_INPUT_HOOK" "$iter_dir/metrics.env" || true
  fi

  # Use latest hybrid log as next seed for auto-infer.
  curr_seed="$hybrid_log"
done

echo
if [[ "$success" == "1" ]]; then
  echo "feedback loop finished: success"
  exit 0
fi

echo "feedback loop finished: no convergence"
echo "check: $OUT_DIR"
exit 3
