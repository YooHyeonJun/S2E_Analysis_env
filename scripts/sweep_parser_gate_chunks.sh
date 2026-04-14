#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-rat_staged}"
START_IDX="${2:-0}"
END_IDX="${3:-11}"
CHUNK_SIZE="${4:-4}"
FORCE_CTX_FD="${5:-0x280}"
GATE989="${S2E_C2_GATE_TAG_4989:-0x404989}"
GATE995="${S2E_C2_GATE_TAG_4995:-0x404995}"
GATE9A4="${S2E_C2_GATE_TAG_49A4:-0x4049a4}"

LOG_DIR="$ROOT_DIR/logs/profiles/$PROFILE"
OUT_DIR="$LOG_DIR/sweeps"
OUT_CSV="$OUT_DIR/parser_gate_chunk_sweep_$(date +%Y%m%d_%H%M%S).csv"

mkdir -p "$OUT_DIR"

echo "profile=$PROFILE start=$START_IDX end=$END_IDX chunk_size=$CHUNK_SIZE force_ctx_fd=$FORCE_CTX_FD"
echo "out_csv=$OUT_CSV"
echo "chunk_idx,log,parser_gate,gate989_taken0,gate989_taken1,gate995_taken0,gate995_taken1,gate9a4_taken0,gate9a4_taken1,deep_enter,ctx_force" > "$OUT_CSV"

for ((idx=START_IDX; idx<=END_IDX; idx++)); do
  echo "[run] chunk_idx=$idx"
  (
    cd "$ROOT_DIR"
    export S2E_C2_FORCE_HANDSHAKE=1
    export S2E_C2_FORCE_HANDSHAKE_SYMBOLIC=1
    export S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX="$idx"
    export S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE="$CHUNK_SIZE"
    export S2E_C2_FORCE_CTX_FD="$FORCE_CTX_FD"
    ./scripts/run_rat_staged.sh "$PROFILE" >/dev/null
  )

  LOG_PATH="$(readlink -f "$LOG_DIR/latest.log")"
  parser_gate="$(rg -c "api=parser_gate phase=eval" "$LOG_PATH" || true)"
  gate989_taken0="$(rg -c "gate=${GATE989}.*taken=0" "$LOG_PATH" || true)"
  gate989_taken1="$(rg -c "gate=${GATE989}.*taken=1" "$LOG_PATH" || true)"
  gate995_taken0="$(rg -c "gate=${GATE995}.*taken=0" "$LOG_PATH" || true)"
  gate995_taken1="$(rg -c "gate=${GATE995}.*taken=1" "$LOG_PATH" || true)"
  gate9a4_taken0="$(rg -c "gate=${GATE9A4}.*taken=0" "$LOG_PATH" || true)"
  gate9a4_taken1="$(rg -c "gate=${GATE9A4}.*taken=1" "$LOG_PATH" || true)"
  deep_enter="$(rg -c "api=deep_enter phase=entered" "$LOG_PATH" || true)"
  ctx_force="$(rg -c "api=ctx_force phase=apply" "$LOG_PATH" || true)"

  echo "$idx,$LOG_PATH,$parser_gate,$gate989_taken0,$gate989_taken1,$gate995_taken0,$gate995_taken1,$gate9a4_taken0,$gate9a4_taken1,$deep_enter,$ctx_force" >> "$OUT_CSV"
  echo "  -> log=$(basename "$LOG_PATH") deep_enter=$deep_enter gate989_taken1=$gate989_taken1 gate9a4_taken1=$gate9a4_taken1"
done

echo
echo "[done] $OUT_CSV"
echo "[hint] python3 scripts/summarize_parser_gate_expectations.py --log-dir \"$LOG_DIR\" --glob '20260330_*.log'"
