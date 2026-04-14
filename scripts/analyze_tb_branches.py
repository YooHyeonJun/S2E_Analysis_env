#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from pathlib import Path


def parse_args():
    ap = argparse.ArgumentParser(description="Extract executed branch PCs from S2E tbcoverage")
    ap.add_argument("--project-root", default=".", help="project root")
    ap.add_argument("--log", required=True, help="run log path")
    ap.add_argument("--target-bin", default="target.exe", help="target binary path")
    ap.add_argument("--target-module", default="target.exe", help="target module basename")
    ap.add_argument("--out", required=True, help="output report path")
    return ap.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(errors="ignore")


def parse_s2e_out_dir(log_text: str, project_root: Path) -> Path | None:
    m = re.search(r'S2E: output directory = "\./(s2e-out-\d+)"', log_text)
    if not m:
        return None
    return project_root / m.group(1)


def parse_runtime_base(log_text: str) -> int | None:
    m = re.search(r"target-module-base .* base=0x([0-9a-fA-F]+)", log_text)
    if not m:
        return None
    return int(m.group(1), 16)


def load_tb_ranges(tb_file: Path, target_module: str):
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


def parse_branch_addrs(target_bin: Path):
    cmd = ["objdump", "-d", str(target_bin)]
    cp = subprocess.run(cmd, capture_output=True, text=True, check=True)
    out = set()
    # include conditional jumps, loop*, and indirect jmp (switch-ish)
    patt = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+.*\b("
        r"j(?:a|ae|b|be|c|cxz|e|ecxz|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)"
        r"|loop|loope|loopne"
        r")\b|\s*([0-9a-fA-F]+):\s+.*\bjmp\s+\*",
        re.IGNORECASE,
    )
    for line in cp.stdout.splitlines():
        m = patt.search(line)
        if not m:
            continue
        a = m.group(1) or m.group(3)
        if a:
            out.add(int(a, 16))
    return sorted(out)


def in_ranges(addr: int, ranges):
    for s, e, _ in ranges:
        if s <= addr <= e:
            return True
    return False


def main():
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    log_path = Path(args.log).resolve()
    target_bin = (project_root / args.target_bin).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    log_text = read_text(log_path)
    s2e_out = parse_s2e_out_dir(log_text, project_root)
    if s2e_out is None or not s2e_out.exists():
        out_path.write_text("tbcoverage analysis failed: s2e-out directory not found\n")
        return 1

    tb_files = sorted(s2e_out.glob("tbcoverage-*.json"))
    if not tb_files:
        out_path.write_text(f"tbcoverage analysis failed: no tbcoverage-*.json in {s2e_out}\n")
        return 2

    all_ranges = []
    for tf in tb_files:
        try:
            all_ranges.extend(load_tb_ranges(tf, args.target_module))
        except Exception:
            continue
    if not all_ranges:
        out_path.write_text(
            f"tbcoverage analysis: no module ranges for {args.target_module} in {len(tb_files)} files\n"
        )
        return 3

    runtime_base = parse_runtime_base(log_text) or 0x400000
    branch_addrs = parse_branch_addrs(target_bin)
    # Try both VA and RVA+runtime_base to accommodate format mismatch.
    hit = []
    for a in branch_addrs:
        if in_ranges(a, all_ranges) or in_ranges(runtime_base + (a - 0x400000), all_ranges):
            hit.append(a)

    lines = []
    lines.append(f"log={log_path}")
    lines.append(f"s2e_out={s2e_out}")
    lines.append(f"tbcoverage_files={len(tb_files)}")
    lines.append(f"target_module={args.target_module}")
    lines.append(f"runtime_base=0x{runtime_base:x}")
    lines.append(f"covered_ranges={len(all_ranges)}")
    lines.append(f"branch_candidates={len(branch_addrs)}")
    lines.append(f"executed_branch_candidates={len(hit)}")
    lines.append("")
    lines.append("[executed_branch_addresses_va]")
    for a in hit[:5000]:
        lines.append(f"0x{a:x}")
    out_path.write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

