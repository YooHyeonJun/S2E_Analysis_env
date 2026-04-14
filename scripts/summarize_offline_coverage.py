#!/usr/bin/env python3
import argparse
from collections import Counter
from pathlib import Path
from typing import Dict, List, Set, Tuple


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Readable offline summary for branch/probe execution reports"
    )
    ap.add_argument("--project-root", default=".", help="project root")
    ap.add_argument("--profile", default="rat_staged", help="profile name")
    ap.add_argument("--probe-report", default="", help="override probe report path")
    ap.add_argument("--branch-report", default="", help="override branch report path")
    ap.add_argument("--top", type=int, default=12, help="top N rows for hotspot lists")
    ap.add_argument(
        "--page-size",
        default="0x1000",
        help="page size for hotspot grouping (e.g. 0x1000, 4096)",
    )
    return ap.parse_args()


def parse_u64(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def parse_report(path: Path) -> Tuple[Dict[str, str], Dict[str, List[int]], Set[str]]:
    meta: Dict[str, str] = {}
    sections: Dict[str, List[int]] = {}
    truncated: Set[str] = set()
    current = ""

    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections[current] = []
            continue
        if line.startswith("0x"):
            if current:
                try:
                    sections[current].append(int(line, 16))
                except ValueError:
                    pass
            continue
        if line.startswith("... (") and current:
            truncated.add(current)
            continue
        if "=" in line and not current:
            k, v = line.split("=", 1)
            meta[k.strip()] = v.strip()

    return meta, sections, truncated


def ratio_str(n: int, d: int) -> str:
    if d <= 0:
        return "n/a"
    return f"{(n / d) * 100:.2f}%"


def spark_ratio(n: int, d: int, width: int = 24) -> str:
    if d <= 0:
        return "[no-data]"
    p = max(0.0, min(1.0, n / d))
    fill = int(round(p * width))
    return "[" + ("#" * fill) + ("-" * (width - fill)) + f"] {p * 100:.2f}%"


def top_pages(addrs: List[int], page_size: int, limit: int) -> List[Tuple[int, int]]:
    c = Counter()
    mask = ~(page_size - 1)
    for a in addrs:
        c[a & mask] += 1
    return c.most_common(limit)


def addr_span(addrs: List[int]) -> str:
    if not addrs:
        return "n/a"
    return f"0x{min(addrs):x} .. 0x{max(addrs):x}"


def render(
    probe_meta: Dict[str, str],
    probe_sec: Dict[str, List[int]],
    probe_truncated: Set[str],
    branch_meta: Dict[str, str],
    branch_sec: Dict[str, List[int]],
    branch_truncated: Set[str],
    page_size: int,
    top_n: int,
) -> str:
    executed_probe = probe_sec.get("executed_probe_addrs", [])
    missed_probe = probe_sec.get("missed_probe_addrs", [])
    executed_branch = branch_sec.get("executed_branch_addresses_va", [])

    cfg_probes = int(probe_meta.get("configured_probes", len(executed_probe) + len(missed_probe)))
    exec_probes = int(probe_meta.get("executed_probes", len(executed_probe)))
    miss_probes = int(probe_meta.get("missed_probes", len(missed_probe)))

    branch_candidates = int(branch_meta.get("branch_candidates", "0") or 0)
    branch_exec = int(branch_meta.get("executed_branch_candidates", len(executed_branch)))

    can_overlap = (
        "executed_probe_addrs" not in probe_truncated
        and "executed_branch_addresses_va" not in branch_truncated
    )
    overlap = len(set(executed_probe) & set(executed_branch)) if can_overlap else -1

    lines: List[str] = []
    lines.append("Offline Coverage Summary")
    lines.append("")
    lines.append("Inputs")
    lines.append(f"- log: {probe_meta.get('log', branch_meta.get('log', 'n/a'))}")
    lines.append(f"- s2e_out: {probe_meta.get('s2e_out', branch_meta.get('s2e_out', 'n/a'))}")
    lines.append(f"- module: {probe_meta.get('target_module', branch_meta.get('target_module', 'n/a'))}")
    lines.append("")
    lines.append("Probe Coverage")
    lines.append(f"- configured: {cfg_probes}")
    lines.append(f"- executed: {exec_probes}")
    lines.append(f"- missed: {miss_probes}")
    lines.append(f"- ratio: {spark_ratio(exec_probes, cfg_probes)}")
    lines.append(f"- executed span: {addr_span(executed_probe)}")
    lines.append(f"- missed span: {addr_span(missed_probe)}")
    lines.append("")
    lines.append("Branch Coverage")
    lines.append(f"- candidates: {branch_candidates}")
    lines.append(f"- executed: {branch_exec}")
    lines.append(f"- ratio: {spark_ratio(branch_exec, branch_candidates)}")
    lines.append(f"- executed span: {addr_span(executed_branch)}")
    lines.append("")
    lines.append("Cross-check")
    if can_overlap:
        lines.append(f"- executed(probe) ∩ executed(branch): {overlap}")
        lines.append(f"- probe-executed coverage of branch-executed: {ratio_str(overlap, max(branch_exec, 1))}")
    else:
        lines.append("- overlap: n/a (report section truncated by sample limit)")
    lines.append("")

    lines.append(f"Top Executed Pages (page_size=0x{page_size:x})")
    for base, cnt in top_pages(executed_probe, page_size, top_n):
        lines.append(f"- 0x{base:x}: {cnt}")
    if not executed_probe:
        lines.append("- n/a")
    lines.append("")

    lines.append(f"Top Missed Pages (page_size=0x{page_size:x})")
    for base, cnt in top_pages(missed_probe, page_size, top_n):
        lines.append(f"- 0x{base:x}: {cnt}")
    if not missed_probe:
        lines.append("- n/a")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    state_dir = project_root / "logs" / "profiles" / args.profile
    probe_path = Path(args.probe_report).resolve() if args.probe_report else state_dir / "probe_exec_report.txt"
    branch_path = Path(args.branch_report).resolve() if args.branch_report else state_dir / "branch_exec_report.txt"

    if not probe_path.exists():
        print(f"probe report not found: {probe_path}")
        return 1
    if not branch_path.exists():
        print(f"branch report not found: {branch_path}")
        return 2

    page_size = parse_u64(args.page_size)
    if page_size <= 0 or (page_size & (page_size - 1)) != 0:
        print(f"invalid page-size (must be power-of-two): {args.page_size}")
        return 3

    probe_meta, probe_sec, probe_truncated = parse_report(probe_path)
    branch_meta, branch_sec, branch_truncated = parse_report(branch_path)
    print(
        render(
            probe_meta,
            probe_sec,
            probe_truncated,
            branch_meta,
            branch_sec,
            branch_truncated,
            page_size,
            args.top,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
