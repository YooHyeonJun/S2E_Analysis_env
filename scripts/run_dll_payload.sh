#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DLL_NAME="${1:-}"
DEFAULT_EXPORTS="${S2E_DEFAULT_DLL_EXPORTS:-Install}"
EXPORT_ARG="${2:-$DEFAULT_EXPORTS}"

if [ -z "$DLL_NAME" ]; then
  echo "usage: $0 <dll_filename_in_project_dir> [export_name|all|csv_list]" >&2
  echo "example: $0 payload.dll Install" >&2
  echo "example: $0 payload.dll all" >&2
  echo "example: $0 payload.dll Install,Run,ServiceMain" >&2
  exit 1
fi

if [ ! -f "$ROOT_DIR/$DLL_NAME" ]; then
  echo "DLL not found: $ROOT_DIR/$DLL_NAME" >&2
  exit 1
fi

cd "$ROOT_DIR"
mkdir -p "$ROOT_DIR/logs"
mkdir -p "$ROOT_DIR/logs/history"
echo c2pid > input-mode.txt

EXPORT_CSV="$EXPORT_ARG"
if [ "$EXPORT_ARG" = "all" ]; then
  EXPORT_CSV="$DEFAULT_EXPORTS"
fi

printf '%s\n%s\n' "$DLL_NAME" "$EXPORT_CSV" > "$ROOT_DIR/dll-run.txt"
RUN_TARGET_INIT_VALUE="${RUN_TARGET_INIT:-1}"
S2E_DISABLE_DEFENDER_VALUE="${S2E_DISABLE_DEFENDER:-0}"
cat > "$ROOT_DIR/guest-init.txt" <<EOF
RUN_TARGET_INIT=${RUN_TARGET_INIT_VALUE}
S2E_DISABLE_DEFENDER=${S2E_DISABLE_DEFENDER_VALUE}
EOF
trap 'rm -f "$ROOT_DIR/dll-run.txt" "$ROOT_DIR/guest-init.txt"' EXIT

KILL_ON_EXIT_DEFAULT="${S2E_C2_KILL_ON_TARGET_EXIT:-}"
if [ -z "$KILL_ON_EXIT_DEFAULT" ]; then
  KILL_ON_EXIT_DEFAULT=0
fi

sanitize() {
  echo "$1" | sed 's/[^A-Za-z0-9._-]/_/g'
}

RUN_TS="$(date +%Y%m%d_%H%M%S)"
RUN_ID="${RUN_TS}_$$"
DLL_SAFE="$(sanitize "$DLL_NAME")"
EXPORT_SAFE="$(sanitize "$EXPORT_ARG")"
LOG_PATH="$ROOT_DIR/logs/history/dll_${DLL_SAFE}_${EXPORT_SAFE}_${RUN_ID}.log"
LATEST_LINK="$ROOT_DIR/logs/dll_${DLL_SAFE}_${EXPORT_SAFE}.latest.log"
INDEX_CSV="$ROOT_DIR/logs/history/index.csv"

RUN_DLL=1 \
S2E_DLL_NAME="$DLL_NAME" \
S2E_DLL_EXPORT="$EXPORT_ARG" \
S2E_DLL_HOOK_EXPORTS="$EXPORT_CSV" \
S2E_C2_KILL_ON_TARGET_EXIT="$KILL_ON_EXIT_DEFAULT" \
S2E_C2_SUPPRESS_TARGET_EXIT="${S2E_C2_SUPPRESS_TARGET_EXIT:-1}" \
S2E_C2_GLOBAL_TRACE="${S2E_C2_GLOBAL_TRACE:-1}" \
./launch-s2e.sh 2>&1 | tee "$LOG_PATH"

ln -sfn "history/$(basename "$LOG_PATH")" "$LATEST_LINK"

if [ ! -f "$INDEX_CSV" ]; then
  echo "run_id,timestamp,dll,export,log_path" > "$INDEX_CSV"
fi
echo "${RUN_ID},${RUN_TS},${DLL_NAME},${EXPORT_ARG},${LOG_PATH}" >> "$INDEX_CSV"

echo "log      : $LOG_PATH"
echo "latest   : $LATEST_LINK"
echo "history  : $INDEX_CSV"
