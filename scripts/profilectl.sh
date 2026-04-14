#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CMD="${1:-}"
PROFILE_NAME="${2:-default}"
PROFILE_DIR="${ROOT_DIR}/profiles/${PROFILE_NAME}"
PROFILE_ENV="${PROFILE_DIR}/profile.env"
PROFILE_LOCAL_ENV="${PROFILE_DIR}/profile.local.env"
STATE_DIR="${ROOT_DIR}/logs/profiles/${PROFILE_NAME}"
LATEST_LOG="${STATE_DIR}/latest.log"
LATEST_META="${STATE_DIR}/latest.meta"

usage() {
  cat <<'EOF'
usage: ./scripts/profilectl.sh <run|rerun|tail|status> <profile>

examples:
  ./scripts/profilectl.sh run template
  ./scripts/profilectl.sh tail template
  ./scripts/profilectl.sh status template
EOF
}

require_profile() {
  if [ ! -f "${PROFILE_ENV}" ]; then
    echo "profile not found: ${PROFILE_ENV}" >&2
    exit 1
  fi
}

load_profile() {
  require_profile
  set -a
  # shellcheck disable=SC1090
  . "${PROFILE_ENV}"
  if [ -f "${PROFILE_LOCAL_ENV}" ]; then
    # shellcheck disable=SC1090
    . "${PROFILE_LOCAL_ENV}"
  fi
  set +a

  export S2E_PROFILE="${PROFILE_NAME}"
  export S2E_PROFILE_DIR="${PROFILE_DIR}"
  export S2E_PROFILE_ENV="${PROFILE_ENV}"
}

sanitize() {
  echo "$1" | sed 's/[^A-Za-z0-9._-]/_/g'
}

write_guest_init() {
  cat > "${ROOT_DIR}/guest-init.txt" <<EOF
RUN_TARGET_INIT=${RUN_TARGET_INIT:-1}
S2E_DISABLE_DEFENDER=${S2E_DISABLE_DEFENDER:-0}
EOF
}

clear_control_files() {
  rm -f "${ROOT_DIR}/guest-init.txt" "${ROOT_DIR}/dll-run.txt"
}

run_profile() {
  local kind
  local run_ts
  local run_id
  local log_path
  local export_csv
  local status

  load_profile
  mkdir -p "${STATE_DIR}"
  echo "${S2E_INPUT_MODE:-c2pid}" > "${ROOT_DIR}/input-mode.txt"

  kind="${S2E_C2_TARGET_KIND:-exe}"
  run_ts="$(date +%Y%m%d_%H%M%S)"
  run_id="${run_ts}_$$"
  log_path="${STATE_DIR}/${run_ts}.log"

  write_guest_init
  trap clear_control_files EXIT

  if [ "${kind}" = "dll" ]; then
    if [ -z "${S2E_DLL_NAME:-}" ]; then
      echo "S2E_DLL_NAME is required for dll profiles" >&2
      exit 1
    fi
    export_csv="${S2E_DLL_HOOK_EXPORTS:-${S2E_DLL_EXPORT:-Install}}"
    printf '%s\n%s\n' "${S2E_DLL_NAME}" "${export_csv}" > "${ROOT_DIR}/dll-run.txt"
    export RUN_DLL=1
    export S2E_DLL_EXPORT="${S2E_DLL_EXPORT:-Install}"
    export S2E_DLL_HOOK_EXPORTS="${export_csv}"
  else
    export RUN_DLL=0
  fi

  export S2E_C2_EXTRACT_RUN_ID="${PROFILE_NAME}_${run_id}"

  set +e
  (
    cd "${ROOT_DIR}"
    ./launch-s2e.sh "$@"
  ) 2>&1 | tee "${log_path}"
  status=${PIPESTATUS[0]}
  set -e

  ln -sfn "$(basename "${log_path}")" "${LATEST_LOG}"
  {
    echo "profile=${PROFILE_NAME}"
    echo "run_id=${run_id}"
    echo "kind=${kind}"
    echo "status=${status}"
    echo "log=${log_path}"
  } > "${LATEST_META}"

  echo "profile : ${PROFILE_NAME}"
  echo "kind    : ${kind}"
  echo "status  : ${status}"
  echo "log     : ${log_path}"
  echo "latest  : ${LATEST_LOG}"

  return "${status}"
}

tail_profile() {
  require_profile
  if [ ! -f "${LATEST_LOG}" ]; then
    echo "no latest log for profile ${PROFILE_NAME}" >&2
    exit 1
  fi
  tail -n "${TAIL_LINES:-80}" "${LATEST_LOG}"
}

status_profile() {
  local log_path
  require_profile
  if [ ! -f "${LATEST_LOG}" ]; then
    echo "no latest log for profile ${PROFILE_NAME}" >&2
    exit 1
  fi
  log_path="${LATEST_LOG}"
  echo "profile : ${PROFILE_NAME}"
  echo "log     : $(readlink -f "${log_path}")"
  grep -E "hooks registered|tracking pid|entry-hook|kill state|Could not fetch|could not open|Exception record|BSOD|Archived live log" "${log_path}" | tail -n 40 || true
}

case "${CMD}" in
  run|rerun)
    shift 2 || true
    run_profile "$@"
    ;;
  tail)
    tail_profile
    ;;
  status)
    status_profile
    ;;
  *)
    usage
    exit 1
    ;;
esac
