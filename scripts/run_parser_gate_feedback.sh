#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-rat_staged}"
ROUNDS="${2:-5}"
CHUNK_IDX="${3:-0}"
CHUNK_SIZE="${4:-4}"

LOG_DIR="$ROOT_DIR/logs/profiles/$PROFILE"
GEN_DIR="$ROOT_DIR/profiles/$PROFILE/generated"
LEARN_ENV="$GEN_DIR/learned_gate_values.env"
TABLE_CSV="$LOG_DIR/sweeps/parser_gate_feedback_$(date +%Y%m%d_%H%M%S).csv"
GATE989="${S2E_C2_GATE_TAG_4989:-0x404989}"
GATE995="${S2E_C2_GATE_TAG_4995:-0x404995}"
GATE9A4="${S2E_C2_GATE_TAG_49A4:-0x4049a4}"

mkdir -p "$GEN_DIR" "$LOG_DIR/sweeps"
echo "round,log,ctx_force,ecx_force,gate989_taken0,gate989_taken1,gate995_taken0,gate995_taken1,gate9a4_taken0,gate9a4_taken1,deep_enter" > "$TABLE_CSV"

count_or_zero() {
  local pat="$1"
  local logp="$2"
  local v
  v="$(rg -c "$pat" "$logp" 2>/dev/null || true)"
  if [[ -z "$v" ]]; then
    echo "0"
  else
    echo "$v"
  fi
}

for ((r=1; r<=ROUNDS; r++)); do
  echo "[round $r/$ROUNDS]"
  (
    cd "$ROOT_DIR"
    export S2E_C2_FORCE_HANDSHAKE=1
    export S2E_C2_FORCE_HANDSHAKE_SYMBOLIC=1
    export S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX="$CHUNK_IDX"
    export S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE="$CHUNK_SIZE"
    if [[ -f "$LEARN_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$LEARN_ENV"
      echo "  using learned env: $LEARN_ENV"
    fi
    ./scripts/run_rat_staged.sh "$PROFILE" >/dev/null
  )

  LOG_PATH="$(readlink -f "$LOG_DIR/latest.log")"
  python3 "$ROOT_DIR/scripts/learn_parser_gate_values.py" --log "$LOG_PATH" --out-env "$LEARN_ENV" >/tmp/learn_gate_values.out
  cat /tmp/learn_gate_values.out

  ctx_force="$(rg -n 'S2E_C2_FORCE_CTX_FD=' "$LEARN_ENV" | tail -n1 | sed 's/.*=//')"
  ecx_force="$(rg -n 'S2E_C2_FORCE_GATE_ECX=' "$LEARN_ENV" | tail -n1 | sed 's/.*=//')"
  g989_0="$(count_or_zero "gate=${GATE989}.*taken=0" "$LOG_PATH")"
  g989_1="$(count_or_zero "gate=${GATE989}.*taken=1" "$LOG_PATH")"
  g995_0="$(count_or_zero "gate=${GATE995}.*taken=0" "$LOG_PATH")"
  g995_1="$(count_or_zero "gate=${GATE995}.*taken=1" "$LOG_PATH")"
  g9a4_0="$(count_or_zero "gate=${GATE9A4}.*taken=0" "$LOG_PATH")"
  g9a4_1="$(count_or_zero "gate=${GATE9A4}.*taken=1" "$LOG_PATH")"
  deep="$(count_or_zero "api=deep_enter phase=entered" "$LOG_PATH")"
  echo "$r,$LOG_PATH,$ctx_force,$ecx_force,$g989_0,$g989_1,$g995_0,$g995_1,$g9a4_0,$g9a4_1,$deep" >> "$TABLE_CSV"
done

echo
echo "[done] table=$TABLE_CSV"
echo "[done] learned_env=$LEARN_ENV"
