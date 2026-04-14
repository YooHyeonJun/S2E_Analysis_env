#!/usr/bin/env python3
import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


DEFAULT_APIS = [
    "socket",
    "connect",
    "select",
    "recv",
    "WSARecv",
    "send",
    "WSASend",
    "sendto",
    "gethostbyname",
    "InternetConnectA",
    "InternetReadFile",
    "InternetWriteFile",
    "WinHttpReadData",
    "HttpSendRequestA",
    "HttpSendRequestW",
]


@dataclass(frozen=True)
class ApiEvent:
    line: int
    api: str
    retaddr: int
    raw: str


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Offline analysis of branch execution around network API callsites"
    )
    ap.add_argument("--project-root", default=".", help="project root")
    ap.add_argument("--profile", default="rat_staged", help="profile name")
    ap.add_argument("--log", default="", help="override log path (default: profile latest.log)")
    ap.add_argument("--target-module", default="target.exe", help="target module basename")
    ap.add_argument(
        "--probe-file",
        default="",
        help="override probe file path (default: profiles/<profile>/generated/branch_probes_target.txt)",
    )
    ap.add_argument("--apis", default=",".join(DEFAULT_APIS), help="comma-separated API names")
    ap.add_argument("--window", default="0x200", help="nearby range around retaddr, e.g. 0x200")
    ap.add_argument(
        "--top-callsite", type=int, default=30, help="max callsites to print in detail"
    )
    ap.add_argument(
        "--max-nearby-addrs",
        type=int,
        default=0,
        help="max addresses to print per exec/miss list (0 means no truncation)",
    )
    ap.add_argument("--out", default="", help="optional output file")
    return ap.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(errors="ignore")


def parse_s2e_out_dir(log_text: str, project_root: Path) -> Optional[Path]:
    m = re.search(r'S2E: output directory = "\./(s2e-out-\d+)"', log_text)
    if not m:
        return None
    return project_root / m.group(1)


def parse_runtime_base(log_text: str) -> Optional[int]:
    m = re.search(r"target-module-base .* base=0x([0-9a-fA-F]+)", log_text)
    if not m:
        return None
    return int(m.group(1), 16)


def parse_u64(s: str) -> Optional[int]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except ValueError:
        return None


def parse_probe_file(path: Path, target_module: str) -> List[int]:
    probes = []
    tm = target_module.lower()
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "!" not in line:
            continue
        mod, addr_s = line.split("!", 1)
        if mod.strip().lower() != tm:
            continue
        addr = parse_u64(addr_s.strip())
        if addr is None:
            continue
        probes.append(addr)
    return sorted(set(probes))


def load_tb_ranges(tb_file: Path, target_module: str) -> List[Tuple[int, int, int]]:
    data = json.loads(tb_file.read_text(errors="ignore"))
    t = target_module.lower()
    out = []
    for k, ranges in data.items():
        k_l = str(k).lower().replace("\\", "/")
        if not (k_l.endswith("/" + t) or k_l == t):
            continue
        for ent in ranges:
            if not isinstance(ent, list) or len(ent) < 2:
                continue
            s, e = int(ent[0]), int(ent[1])
            c = int(ent[2]) if len(ent) > 2 else 0
            if e < s:
                s, e = e, s
            out.append((s, e, c))
    return out


def in_ranges(addr: int, ranges: Iterable[Tuple[int, int, int]]) -> bool:
    for s, e, _ in ranges:
        if s <= addr <= e:
            return True
    return False


def candidate_addrs(addr: int, runtime_base: int, base_guess: int) -> Set[int]:
    out = {addr}
    if addr >= base_guess:
        rva = addr - base_guess
        out.add(rva)
        out.add(runtime_base + rva)
    else:
        out.add(runtime_base + addr)
        out.add(base_guess + addr)
    return out


def executed_probe_set(
    probes: List[int], ranges: List[Tuple[int, int, int]], runtime_base: int, base_guess: int
) -> Set[int]:
    out = set()
    for a in probes:
        for c in candidate_addrs(a, runtime_base, base_guess):
            if in_ranges(c, ranges):
                out.add(a)
                break
    return out


def parse_network_events(log_path: Path, api_filter: Set[str]) -> List[ApiEvent]:
    events: List[ApiEvent] = []
    api_re = re.compile(r"\bapi=([A-Za-z0-9_]+)\b")
    ret_re = re.compile(r"\bretaddr=(0x[0-9a-fA-F]+|\d+)\b")

    for lineno, raw in enumerate(log_path.read_text(errors="ignore").splitlines(), 1):
        if "[c2trace] kind=interesting_api" not in raw:
            continue
        m_api = api_re.search(raw)
        if not m_api:
            continue
        api = m_api.group(1)
        if api not in api_filter:
            continue
        m_ret = ret_re.search(raw)
        if not m_ret:
            continue
        retaddr = parse_u64(m_ret.group(1))
        if retaddr is None:
            continue
        events.append(ApiEvent(line=lineno, api=api, retaddr=retaddr, raw=raw.strip()))
    return events


def make_report(
    log_path: Path,
    s2e_out: Path,
    target_module: str,
    runtime_base: int,
    window: int,
    probes: List[int],
    executed: Set[int],
    events: List[ApiEvent],
    top_callsite: int,
    max_nearby_addrs: int,
) -> str:
    missed = set(probes) - executed

    per_api = Counter(ev.api for ev in events)
    unique_callsites = sorted({ev.retaddr for ev in events})
    by_callsite: Dict[int, List[ApiEvent]] = defaultdict(list)
    for ev in events:
        by_callsite[ev.retaddr].append(ev)

    lines: List[str] = []
    lines.append("Network-Adjacent Branch Analysis")
    lines.append("")
    lines.append("Inputs")
    lines.append(f"- log={log_path}")
    lines.append(f"- s2e_out={s2e_out}")
    lines.append(f"- module={target_module}")
    lines.append(f"- runtime_base=0x{runtime_base:x}")
    lines.append(f"- window=0x{window:x} (+/-)")
    lines.append("")
    lines.append("Coverage Base")
    lines.append(f"- configured_probes={len(probes)}")
    lines.append(f"- executed_probes={len(executed)}")
    lines.append(f"- missed_probes={len(missed)}")
    ratio = (len(executed) / len(probes) * 100.0) if probes else 0.0
    lines.append(f"- execution_ratio={ratio:.2f}%")
    lines.append("")
    lines.append("Network API Events")
    lines.append(f"- total_events={len(events)}")
    lines.append(f"- unique_callsites={len(unique_callsites)}")
    if per_api:
        for api, cnt in per_api.most_common():
            lines.append(f"- api.{api}={cnt}")
    lines.append("")

    lines.append("Per-Callsite Nearby Branches")
    detail_count = 0
    for callsite in unique_callsites:
        nearby = [p for p in probes if abs(p - callsite) <= window]
        if not nearby:
            continue
        detail_count += 1
        if detail_count > top_callsite:
            break
        near_exec = sorted([p for p in nearby if p in executed])
        near_miss = sorted([p for p in nearby if p not in executed])
        apis = sorted({ev.api for ev in by_callsite[callsite]})
        lines.append(
            f"- callsite=0x{callsite:x} apis={','.join(apis)} events={len(by_callsite[callsite])} "
            f"nearby={len(nearby)} exec={len(near_exec)} miss={len(near_miss)}"
        )
        if max_nearby_addrs > 0:
            exec_show = near_exec[:max_nearby_addrs]
            miss_show = near_miss[:max_nearby_addrs]
            exec_suffix = ",..." if len(near_exec) > max_nearby_addrs else ""
            miss_suffix = ",..." if len(near_miss) > max_nearby_addrs else ""
        else:
            exec_show = near_exec
            miss_show = near_miss
            exec_suffix = ""
            miss_suffix = ""

        lines.append(
            f"  exec_addrs={','.join(f'0x{x:x}' for x in exec_show) or '-'}{exec_suffix}"
        )
        lines.append(
            f"  miss_addrs={','.join(f'0x{x:x}' for x in miss_show) or '-'}{miss_suffix}"
        )
    if detail_count == 0:
        lines.append("- no callsite had nearby configured probes in this window")
    elif len(unique_callsites) > top_callsite:
        lines.append(f"- ... truncated to top {top_callsite} callsites")
    lines.append("")

    lines.append("Raw Event Samples")
    for ev in events[:30]:
        lines.append(f"- L{ev.line} api={ev.api} retaddr=0x{ev.retaddr:x}")
    if len(events) > 30:
        lines.append(f"- ... {len(events) - 30} more events")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    profile_dir = project_root / "logs" / "profiles" / args.profile

    log_path = Path(args.log).resolve() if args.log else profile_dir / "latest.log"
    probe_file = (
        Path(args.probe_file).resolve()
        if args.probe_file
        else project_root / "profiles" / args.profile / "generated" / "branch_probes_target.txt"
    )

    if not log_path.exists():
        print(f"log not found: {log_path}")
        return 1
    if not probe_file.exists():
        print(f"probe file not found: {probe_file}")
        return 2

    log_text = read_text(log_path)
    s2e_out = parse_s2e_out_dir(log_text, project_root)
    if s2e_out is None or not s2e_out.exists():
        print("could not resolve s2e-out directory from log")
        return 3

    tb_files = sorted(s2e_out.glob("tbcoverage-*.json"))
    if not tb_files:
        print(f"no tbcoverage-*.json under {s2e_out}")
        return 4

    ranges: List[Tuple[int, int, int]] = []
    for tf in tb_files:
        try:
            ranges.extend(load_tb_ranges(tf, args.target_module))
        except Exception:
            continue
    if not ranges:
        print(f"no module coverage ranges for {args.target_module}")
        return 5

    runtime_base = parse_runtime_base(log_text) or 0x400000
    base_guess = 0x400000
    window = parse_u64(args.window)
    if window is None or window < 0:
        print(f"invalid window: {args.window}")
        return 6

    probes = parse_probe_file(probe_file, args.target_module)
    if not probes:
        print(f"no probes parsed for module={args.target_module}")
        return 7

    executed = executed_probe_set(probes, ranges, runtime_base, base_guess)

    api_filter = {x.strip() for x in args.apis.split(",") if x.strip()}
    events = parse_network_events(log_path, api_filter)

    report = make_report(
        log_path=log_path,
        s2e_out=s2e_out,
        target_module=args.target_module,
        runtime_base=runtime_base,
        window=window,
        probes=probes,
        executed=executed,
        events=events,
        top_callsite=args.top_callsite,
        max_nearby_addrs=args.max_nearby_addrs,
    )

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report + "\n")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
