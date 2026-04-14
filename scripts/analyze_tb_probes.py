#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


def parse_args():
    ap = argparse.ArgumentParser(description="Compare configured instruction probes against executed TB coverage")
    ap.add_argument("--project-root", default=".", help="project root")
    ap.add_argument("--log", required=True, help="run log path")
    ap.add_argument("--target-module", default="target.exe", help="target module basename")
    ap.add_argument("--probe-file", required=True, help="probe list file (module!0xADDR per line)")
    ap.add_argument("--out", required=True, help="output report path")
    ap.add_argument("--base-guess", default="0x400000", help="native image base guess for VA<->RVA mapping")
    ap.add_argument("--sample", type=int, default=200, help="max entries per section in output")
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


def parse_u64(s: str) -> int | None:
    s = (s or "").strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None
    try:
        return int(s, 10)
    except ValueError:
        return None


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


def in_ranges(addr: int, ranges) -> bool:
    for s, e, _ in ranges:
        if s <= addr <= e:
            return True
    return False


def parse_probe_file(path: Path, target_module: str):
    probes = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "!" not in line:
            continue
        mod, addr_s = line.split("!", 1)
        mod_l = mod.strip().lower()
        if mod_l != target_module.lower():
            continue
        addr = parse_u64(addr_s.strip())
        if addr is None:
            continue
        probes.append(addr)
    return sorted(set(probes))


def candidate_addrs(addr: int, runtime_base: int, base_guess: int):
    # Try native VA, runtime VA, and RVA forms to tolerate format mismatch.
    out = {addr}
    if addr >= base_guess:
        rva = addr - base_guess
        out.add(rva)
        out.add(runtime_base + rva)
    else:
        out.add(runtime_base + addr)
        out.add(base_guess + addr)
    return out


def main():
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    log_path = Path(args.log).resolve()
    probe_file = Path(args.probe_file).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not probe_file.exists():
        out_path.write_text(f"probe coverage failed: probe file not found: {probe_file}\n")
        return 1

    log_text = read_text(log_path)
    s2e_out = parse_s2e_out_dir(log_text, project_root)
    if s2e_out is None or not s2e_out.exists():
        out_path.write_text("probe coverage failed: s2e-out directory not found from log\n")
        return 2

    tb_files = sorted(s2e_out.glob("tbcoverage-*.json"))
    if not tb_files:
        out_path.write_text(f"probe coverage failed: no tbcoverage-*.json in {s2e_out}\n")
        return 3

    all_ranges = []
    for tf in tb_files:
        try:
            all_ranges.extend(load_tb_ranges(tf, args.target_module))
        except Exception:
            continue
    if not all_ranges:
        out_path.write_text(
            f"probe coverage: no module ranges for {args.target_module} in {len(tb_files)} files\n"
        )
        return 4

    runtime_base = parse_runtime_base(log_text) or 0x400000
    base_guess = parse_u64(args.base_guess) or 0x400000
    probes = parse_probe_file(probe_file, args.target_module)
    if not probes:
        out_path.write_text(
            f"probe coverage: no probes for module={args.target_module} in file={probe_file}\n"
        )
        return 5

    hit = []
    miss = []
    for a in probes:
        matched = False
        for c in candidate_addrs(a, runtime_base, base_guess):
            if in_ranges(c, all_ranges):
                matched = True
                break
        if matched:
            hit.append(a)
        else:
            miss.append(a)

    lines = []
    lines.append(f"log={log_path}")
    lines.append(f"s2e_out={s2e_out}")
    lines.append(f"tbcoverage_files={len(tb_files)}")
    lines.append(f"target_module={args.target_module}")
    lines.append(f"probe_file={probe_file}")
    lines.append(f"runtime_base=0x{runtime_base:x}")
    lines.append(f"base_guess=0x{base_guess:x}")
    lines.append(f"covered_ranges={len(all_ranges)}")
    lines.append(f"configured_probes={len(probes)}")
    lines.append(f"executed_probes={len(hit)}")
    lines.append(f"missed_probes={len(miss)}")
    lines.append(f"execution_ratio={(len(hit) / len(probes)):.4f}")
    lines.append("")

    lines.append("[executed_probe_addrs]")
    for a in hit[: args.sample]:
        lines.append(f"0x{a:x}")
    if len(hit) > args.sample:
        lines.append(f"... ({len(hit) - args.sample} more)")
    lines.append("")

    lines.append("[missed_probe_addrs]")
    for a in miss[: args.sample]:
        lines.append(f"0x{a:x}")
    if len(miss) > args.sample:
        lines.append(f"... ({len(miss) - args.sample} more)")
    lines.append("")

    out_path.write_text("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
