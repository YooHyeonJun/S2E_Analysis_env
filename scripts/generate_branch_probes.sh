#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

TARGET_BIN="${1:-target.exe}"
OUT_FILE="${2:-profiles/rat_staged/generated/branch_probes_target.txt}"
MODULE_NAME="${3:-target.exe}"

mkdir -p "$(dirname "$OUT_FILE")"
{
  echo "# Auto-generated branch probe points for ${MODULE_NAME}"
  echo "# Source binary: ${TARGET_BIN}"
  echo "# Format: module!0xADDR"
  objdump -d "$TARGET_BIN" | awk -v mod="$MODULE_NAME" '
    {
      if (match($0, /^[[:space:]]*([0-9a-fA-F]+):[[:space:]]/, m)) {
        addr = m[1]
        line = tolower($0)
        is_cond = (line ~ /[[:space:]]j(a|ae|b|be|c|cxz|e|ecxz|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)[[:space:]]/)
        is_loop = (line ~ /[[:space:]]loop(e|ne)?[[:space:]]/)
        is_ind_jmp = (line ~ /[[:space:]]jmp[[:space:]]+\*/)
        if (is_cond || is_loop || is_ind_jmp) {
          print mod "!0x" addr
        }
      }
    }
  ' | sort -u
} > "$OUT_FILE"

echo "Generated $(wc -l < "$OUT_FILE") branch probe points -> $OUT_FILE"
