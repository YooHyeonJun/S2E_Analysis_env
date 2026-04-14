#!/usr/bin/env python3
import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class CallsiteBlock:
    callsite: int
    apis: List[str]
    events: int
    nearby: int
    exec_n: int
    miss_n: int
    exec_addrs: List[int]
    miss_addrs: List[int]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Build file-specific focus artifacts from network branch report + run log"
    )
    ap.add_argument("--project-root", default=".", help="project root")
    ap.add_argument("--profile", default="rat_staged", help="profile name")
    ap.add_argument("--report", default="", help="network branch report path override")
    ap.add_argument("--log", default="", help="run log path override")
    ap.add_argument("--focus-api", default="socket", help="focus API for miss-branch targeting")
    ap.add_argument("--top-miss", type=int, default=12, help="top miss branches to prioritize")
    return ap.parse_args()


def parse_addr_csv(text: str) -> List[int]:
    out: List[int] = []
    if text.strip() == "-" or not text.strip():
        return out
    for tok in text.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(int(tok, 16) if tok.startswith("0x") else int(tok, 10))
        except ValueError:
            continue
    return out


def parse_network_report(path: Path) -> List[CallsiteBlock]:
    lines = path.read_text(errors="ignore").splitlines()
    blocks: List[CallsiteBlock] = []

    head_re = re.compile(
        r"^- callsite=(0x[0-9a-fA-F]+)\s+apis=([^\s]+)\s+events=(\d+)\s+nearby=(\d+)\s+exec=(\d+)\s+miss=(\d+)"
    )
    exec_re = re.compile(r"^\s*exec_addrs=(.*)$")
    miss_re = re.compile(r"^\s*miss_addrs=(.*)$")

    i = 0
    while i < len(lines):
        m = head_re.match(lines[i].strip())
        if not m:
            i += 1
            continue

        callsite = int(m.group(1), 16)
        apis = [a for a in m.group(2).split(",") if a]
        events = int(m.group(3))
        nearby = int(m.group(4))
        exec_n = int(m.group(5))
        miss_n = int(m.group(6))

        exec_addrs: List[int] = []
        miss_addrs: List[int] = []
        if i + 1 < len(lines):
            me = exec_re.match(lines[i + 1])
            if me:
                exec_addrs = parse_addr_csv(me.group(1).strip())
        if i + 2 < len(lines):
            mm = miss_re.match(lines[i + 2])
            if mm:
                miss_addrs = parse_addr_csv(mm.group(1).strip())

        blocks.append(
            CallsiteBlock(
                callsite=callsite,
                apis=apis,
                events=events,
                nearby=nearby,
                exec_n=exec_n,
                miss_n=miss_n,
                exec_addrs=exec_addrs,
                miss_addrs=miss_addrs,
            )
        )
        i += 3

    return blocks


def parse_symbolic_retaddrs(log_path: Path) -> Dict[str, List[int]]:
    api_to_env = {
        "recv": "S2E_C2_SYMBOLIC_RECV_RETADDRS",
        "WSARecv": "S2E_C2_SYMBOLIC_WSARECV_RETADDRS",
        "recvfrom": "S2E_C2_SYMBOLIC_RECVFROM_RETADDRS",
        "InternetReadFile": "S2E_C2_SYMBOLIC_INTERNETREADFILE_RETADDRS",
        "WinHttpReadData": "S2E_C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS",
    }
    out: Dict[str, List[int]] = {v: [] for v in api_to_env.values()}

    api_re = re.compile(r"\bapi=([A-Za-z0-9_]+)\b")
    ret_re = re.compile(r"\bretaddr=(0x[0-9a-fA-F]+|\d+)\b")
    for line in log_path.read_text(errors="ignore").splitlines():
        if "[c2trace] kind=interesting_api" not in line:
            continue
        ma = api_re.search(line)
        mr = ret_re.search(line)
        if not ma or not mr:
            continue
        api = ma.group(1)
        env_key = api_to_env.get(api)
        if not env_key:
            continue
        ret = int(mr.group(1), 16) if mr.group(1).startswith("0x") else int(mr.group(1), 10)
        out[env_key].append(ret)

    for k in out:
        out[k] = sorted(set(out[k]))
    return out


def to_hex_csv(values: List[int]) -> str:
    return ",".join(f"0x{x:x}" for x in values)


def main() -> int:
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    profile = args.profile

    report_path = (
        Path(args.report).resolve()
        if args.report
        else project_root / "logs" / "profiles" / profile / "network_branch_report.txt"
    )
    log_path = (
        Path(args.log).resolve()
        if args.log
        else project_root / "logs" / "profiles" / profile / "latest.log"
    )

    if not report_path.exists():
        print(f"report not found: {report_path}")
        return 1
    if not log_path.exists():
        print(f"log not found: {log_path}")
        return 2

    blocks = parse_network_report(report_path)
    if not blocks:
        print(f"no callsite blocks parsed from report: {report_path}")
        return 3

    focus = [
        b
        for b in blocks
        if any(api.lower() == args.focus_api.lower() for api in b.apis)
    ]
    if not focus:
        focus = sorted(blocks, key=lambda b: b.miss_n, reverse=True)[:1]

    focus_block = sorted(focus, key=lambda b: b.miss_n, reverse=True)[0]
    ranked_miss = sorted(
        focus_block.miss_addrs, key=lambda a: (abs(a - focus_block.callsite), a)
    )
    top_miss = ranked_miss[: max(0, args.top_miss)]
    ranked_exec = sorted(
        focus_block.exec_addrs, key=lambda a: (abs(a - focus_block.callsite), a)
    )
    top_exec = ranked_exec[: max(0, args.top_miss)]

    sym_sites = parse_symbolic_retaddrs(log_path)

    gen_dir = project_root / "profiles" / profile / "generated"
    gen_dir.mkdir(parents=True, exist_ok=True)

    miss_all_path = gen_dir / "socket_focus_miss_all.txt"
    miss_top_path = gen_dir / "socket_focus_miss_top.txt"
    exec_all_path = gen_dir / "socket_focus_exec_all.txt"
    exec_top_path = gen_dir / "socket_focus_exec_top.txt"
    env_path = gen_dir / "file_specific_next.env"
    strategy_env_path = project_root / "profiles" / profile / "feedback_strategies" / "15_socket_symbolic_focus.env"
    lua_path = gen_dir / "c2-symbolic-sites.next.lua"
    summary_path = gen_dir / "file_specific_focus.md"
    run_script_path = project_root / "scripts" / "run_socket_symbolic_focus.sh"

    miss_all_path.write_text("\n".join(f"0x{x:x}" for x in ranked_miss) + ("\n" if ranked_miss else ""))
    miss_top_path.write_text("\n".join(f"0x{x:x}" for x in top_miss) + ("\n" if top_miss else ""))
    exec_all_path.write_text("\n".join(f"0x{x:x}" for x in ranked_exec) + ("\n" if ranked_exec else ""))
    exec_top_path.write_text("\n".join(f"0x{x:x}" for x in top_exec) + ("\n" if top_exec else ""))
    branch_focus_path = exec_top_path if top_exec else miss_top_path

    env_lines: List[str] = []
    env_lines.append(f"# Auto-generated from {report_path.name} + {log_path.name}")
    env_lines.append(f"# focus_api={args.focus_api} callsite=0x{focus_block.callsite:x}")
    env_lines.append(f"# prioritized_socket_exec_file={exec_top_path}")
    env_lines.append(f"# fallback_socket_miss_file={miss_top_path}")
    env_lines.append("# Symbolic-focused knobs (file-specific overlay)")
    env_lines.append("export S2E_C2_GUIDE_COMPARE=1")
    env_lines.append("export S2E_C2_FORCE_COMPARE_PASS=0")
    env_lines.append("export S2E_C2_COMPARE_BYPASS_PID=1")
    env_lines.append("export S2E_C2_FORCE_CONNECT_CALL=1")
    env_lines.append("export S2E_C2_FORCE_CONNECT_CALL_LIMIT=8")
    env_lines.append("export S2E_C2_FORCE_NET_PROGRESS=1")
    env_lines.append("export S2E_C2_FORCE_SELECT_READY=1")
    env_lines.append("export S2E_C2_FORCE_RECV_PHASED=1")
    env_lines.append("export S2E_C2_FORCE_FULL_SYMBOLIC_RECV=1")
    env_lines.append("export S2E_C2_MAIN_RECV_RVA_START=0x30800")
    env_lines.append("export S2E_C2_MAIN_RECV_RVA_END=0x30c00")
    env_lines.append("export S2E_C2_MAIN_PKT_LEN=0x40")
    env_lines.append("export S2E_C2_MAIN_PKT_SYM_PREFIX=16")
    env_lines.append("export S2E_C2_MAX_SYMBOLIC_BYTES=16")
    env_lines.append("export S2E_C2_DISABLE_INJECT=1")
    env_lines.append(f'export S2E_C2_BRANCH_SYMBOLIC_FILE="{branch_focus_path}"')
    env_lines.append("export S2E_C2_BRANCH_SYMBOLIC_BYTES=8")
    env_lines.append("export S2E_C2_BRANCH_SYMBOLIC_MAX_HITS_PER_PC=1")
    env_lines.append(f'export S2E_C2_SYMBOLIC_SITES_FILE="{lua_path}"')
    for key in [
        "S2E_C2_SYMBOLIC_RECV_RETADDRS",
        "S2E_C2_SYMBOLIC_WSARECV_RETADDRS",
        "S2E_C2_SYMBOLIC_RECVFROM_RETADDRS",
        "S2E_C2_SYMBOLIC_INTERNETREADFILE_RETADDRS",
        "S2E_C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS",
    ]:
        vals = sym_sites.get(key, [])
        if vals:
            env_lines.append(f'export {key}="{to_hex_csv(vals)}"')
        else:
            env_lines.append(f"# export {key}=\"\"")
    env_lines.append("# Optional: keep recv symbolic small to avoid explosion")
    env_lines.append("# export S2E_C2_MAX_SYMBOLIC_BYTES=16")
    env_path.write_text("\n".join(env_lines) + "\n")
    strategy_env_path.write_text("\n".join(env_lines) + "\n")

    lua_lines: List[str] = []
    lua_lines.append("return {")
    map_keys: List[Tuple[str, str]] = [
        ("recv", "S2E_C2_SYMBOLIC_RECV_RETADDRS"),
        ("wsarecv", "S2E_C2_SYMBOLIC_WSARECV_RETADDRS"),
        ("recvfrom", "S2E_C2_SYMBOLIC_RECVFROM_RETADDRS"),
        ("internetreadfile", "S2E_C2_SYMBOLIC_INTERNETREADFILE_RETADDRS"),
        ("winhttpreaddata", "S2E_C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS"),
    ]
    for lua_key, env_key in map_keys:
        vals = sym_sites.get(env_key, [])
        if vals:
            lua_lines.append(f"    {lua_key} = {{ {', '.join(f'0x{x:x}' for x in vals)} }},")
        else:
            lua_lines.append(f"    {lua_key} = {{}},")
    lua_lines.append("}")
    lua_path.write_text("\n".join(lua_lines) + "\n")

    md: List[str] = []
    md.append("# File-Specific Focus (Auto)")
    md.append("")
    md.append(f"- report: `{report_path}`")
    md.append(f"- log: `{log_path}`")
    md.append(
        f"- focus callsite: `0x{focus_block.callsite:x}` (apis={','.join(focus_block.apis)} miss={focus_block.miss_n})"
    )
    md.append(f"- prioritized exec branches: `{len(top_exec)}` / `{len(ranked_exec)}`")
    md.append(f"- prioritized miss branches: `{len(top_miss)}` / `{len(ranked_miss)}`")
    md.append(f"- branch-symbolic file: `{branch_focus_path}`")
    md.append("")
    md.append("## Prioritized exec branches (near callsite first)")
    for a in top_exec:
        md.append(f"- `0x{a:x}`")
    if not top_exec:
        md.append("- none")
    md.append("")
    md.append("## Prioritized miss branches (near callsite first)")
    for a in top_miss:
        md.append(f"- `0x{a:x}`")
    if not top_miss:
        md.append("- none")
    md.append("")
    md.append("## Generated artifacts")
    md.append(f"- `{miss_all_path}`")
    md.append(f"- `{miss_top_path}`")
    md.append(f"- `{exec_all_path}`")
    md.append(f"- `{exec_top_path}`")
    md.append(f"- `{env_path}`")
    md.append(f"- `{strategy_env_path}`")
    md.append(f"- `{lua_path}`")
    md.append("")
    md.append("## Run (symbolic focus)")
    md.append(f"- `./scripts/run_socket_symbolic_focus.sh {profile}`")
    summary_path.write_text("\n".join(md) + "\n")

    run_script = f"""#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${{1:-{profile}}}"
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
if [[ -f "$LOCAL_ENV" ]]; then
  # shellcheck disable=SC1090
  . "$LOCAL_ENV"
fi
# shellcheck disable=SC1090
. "$GEN_ENV"
set +a

export S2E_FEEDBACK_PROFILE="$PROFILE"
export S2E_FEEDBACK_LOCAL_ENV="$LOCAL_ENV"
export S2E_FEEDBACK_BASELINE_ENV="$BASE_ENV"

cd "$ROOT_DIR"
cat > "$ROOT_DIR/guest-init.txt" <<EOF
RUN_TARGET_INIT=${{RUN_TARGET_INIT:-1}}
S2E_DISABLE_DEFENDER=${{S2E_DISABLE_DEFENDER:-0}}
EOF
trap 'rm -f "$ROOT_DIR/guest-init.txt" "$ROOT_DIR/dll-run.txt"' EXIT
./c2pid/run_solver_loop.sh "$(readlink -f "$LATEST_LOG")"
    """
    run_script_path.write_text(run_script)
    run_script_path.chmod(0o755)

    print(f"Generated: {summary_path}")
    print(f"Generated: {exec_top_path}")
    print(f"Generated: {miss_top_path}")
    print(f"Generated: {env_path}")
    print(f"Generated: {strategy_env_path}")
    print(f"Generated: {lua_path}")
    print(f"Generated: {run_script_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
