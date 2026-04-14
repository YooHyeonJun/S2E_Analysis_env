#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-rat_staged}"
PROFILE_DIR="$ROOT_DIR/profiles/$PROFILE"
BASE_ENV="$PROFILE_DIR/profile.env"
LOCAL_ENV="$PROFILE_DIR/profile.local.env"
GEN_ENV="$PROFILE_DIR/generated/file_specific_next.env"
LATEST_LOG="$ROOT_DIR/logs/profiles/$PROFILE/latest.log"

if [[ ! -f "$BASE_ENV" ]]; then
  echo "missing base env: $BASE_ENV" >&2
  exit 1
fi
if [[ ! -f "$GEN_ENV" ]]; then
  echo "missing generated env: $GEN_ENV" >&2
  echo "run: ./scripts/build_file_specific_focus.py --project-root $ROOT_DIR --profile $PROFILE" >&2
  exit 2
fi
if [[ ! -f "$LATEST_LOG" ]]; then
  echo "missing latest log: $LATEST_LOG" >&2
  exit 3
fi

set -a
# shellcheck disable=SC1090
. "$BASE_ENV"
# shellcheck disable=SC1090
. "$GEN_ENV"
# Keep local overrides last so manual tuning wins over generated defaults.
if [[ -f "$LOCAL_ENV" ]]; then
  # shellcheck disable=SC1090
  . "$LOCAL_ENV"
fi
set +a

export S2E_FEEDBACK_PROFILE="$PROFILE"
export S2E_FEEDBACK_LOCAL_ENV="$LOCAL_ENV"
export S2E_FEEDBACK_BASELINE_ENV="$BASE_ENV"

cd "$ROOT_DIR"
cat > "$ROOT_DIR/guest-init.txt" <<EOF
RUN_TARGET_INIT=${RUN_TARGET_INIT:-1}
S2E_DISABLE_DEFENDER=${S2E_DISABLE_DEFENDER:-0}
EOF
trap 'rm -f "$ROOT_DIR/guest-init.txt" "$ROOT_DIR/dll-run.txt"' EXIT
./c2pid/run_solver_loop.sh "$(readlink -f "$LATEST_LOG")"
    
