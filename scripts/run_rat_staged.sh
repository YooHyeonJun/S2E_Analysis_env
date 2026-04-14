#!/usr/bin/env bash
set -euo pipefail

# RAT staged workflow:
# 1) Stage 1 forced/concrete run (single pass)
# 2) Optional Stage 2/3 feedback reruns with overlay strategies
#
# Usage:
#   ./scripts/run_rat_staged.sh [profile] [--feedback]
#
# Env:
#   S2E_STAGE1_SKIP=1             # skip initial forced run
#   S2E_STAGE23_RUN=1             # run feedback loop after stage1
#   S2E_FEEDBACK_MAX_ITERS=6      # feedback-loop bound

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-rat_staged}"
RUN_FEEDBACK="${S2E_STAGE23_RUN:-0}"
if [[ "${2:-}" == "--feedback" ]]; then
  RUN_FEEDBACK=1
fi
PROFILE_DIR="$ROOT_DIR/profiles/$PROFILE"
PROFILE_ENV="$PROFILE_DIR/profile.env"
PROFILE_LOCAL_ENV="$PROFILE_DIR/profile.local.env"
LATEST_LINK="$ROOT_DIR/logs/profiles/$PROFILE/latest.log"

if [[ ! -f "$PROFILE_ENV" ]]; then
  echo "profile not found: $PROFILE_ENV" >&2
  exit 1
fi

run_stage1() {
  echo "[stage1] forced concrete discovery run"
  (
    cd "$ROOT_DIR"
    ./scripts/profilectl.sh run "$PROFILE"
  )
}

prepare_branch_probes() {
  local target_bin target_module out_file
  if [[ ! -f "$PROFILE_ENV" ]]; then
    return 0
  fi
  set -a
  # shellcheck disable=SC1090
  . "$PROFILE_ENV"
  if [[ -f "$PROFILE_LOCAL_ENV" ]]; then
    # shellcheck disable=SC1090
    . "$PROFILE_LOCAL_ENV"
  fi
  set +a
  target_bin="${S2E_TARGET_FILE:-target.exe}"
  target_module="${S2E_TARGET_MODULE:-target.exe}"
  out_file="${S2E_C2_INST_PROBES_FILE:-profiles/$PROFILE/generated/branch_probes_target.txt}"
  if [[ "$out_file" != /* ]]; then
    out_file="$ROOT_DIR/$out_file"
  fi

  (
    cd "$ROOT_DIR"
    ./scripts/generate_branch_probes.sh "$target_bin" "$out_file" "$target_module" >/dev/null
  )
  # Ensure stage1 run inherits the exact probe file that was generated here.
  export S2E_C2_INST_PROBES_FILE="$out_file"
  echo "[stage1] branch probes prepared: $out_file"
}

analyze_stage1_branches() {
  local seed_log="$1"
  local out_report="$ROOT_DIR/logs/profiles/$PROFILE/branch_exec_report.txt"
  (
    cd "$ROOT_DIR"
    python3 ./scripts/analyze_tb_branches.py \
      --project-root "$ROOT_DIR" \
      --log "$seed_log" \
      --target-bin "${S2E_TARGET_FILE:-target.exe}" \
      --target-module "${S2E_TARGET_MODULE:-target.exe}" \
      --out "$out_report" || true
  )
  if [[ -f "$out_report" ]]; then
    echo "[stage1] tb branch report: $out_report"
  fi
}

analyze_stage1_probes() {
  local seed_log="$1"
  local out_report="$ROOT_DIR/logs/profiles/$PROFILE/probe_exec_report.txt"
  local probe_file="${S2E_C2_INST_PROBES_FILE:-profiles/$PROFILE/generated/branch_probes_target.txt}"
  (
    cd "$ROOT_DIR"
    python3 ./scripts/analyze_tb_probes.py \
      --project-root "$ROOT_DIR" \
      --log "$seed_log" \
      --target-module "${S2E_TARGET_MODULE:-target.exe}" \
      --probe-file "$probe_file" \
      --out "$out_report" || true
  )
  if [[ -f "$out_report" ]]; then
    echo "[stage1] tb probe report: $out_report"
  fi
}

latest_seed_log() {
  if [[ -L "$LATEST_LINK" || -f "$LATEST_LINK" ]]; then
    readlink -f "$LATEST_LINK"
    return 0
  fi
  if [[ -f "$ROOT_DIR/run_live.log" ]]; then
    readlink -f "$ROOT_DIR/run_live.log"
    return 0
  fi
  return 1
}

if [[ "${S2E_STAGE1_SKIP:-0}" != "1" ]]; then
  prepare_branch_probes
  run_stage1
fi

SEED_LOG="$(latest_seed_log || true)"
if [[ -z "$SEED_LOG" || ! -f "$SEED_LOG" ]]; then
  echo "seed log not found after stage1" >&2
  exit 2
fi

analyze_stage1_branches "$SEED_LOG"
analyze_stage1_probes "$SEED_LOG"

if [[ "$RUN_FEEDBACK" != "1" ]]; then
  echo "[done] stage1 only. seed log: $SEED_LOG"
  echo "run stage2/3 explicitly: ./scripts/run_rat_staged.sh $PROFILE --feedback"
  exit 0
fi

echo "[stage2/3] feedback rerun from seed: $SEED_LOG"
(
  cd "$ROOT_DIR"
  export S2E_PROFILE="$PROFILE"
  export S2E_FEEDBACK_PROFILE="$PROFILE"
  ./c2pid/run_feedback_loop.sh "$SEED_LOG"
)
