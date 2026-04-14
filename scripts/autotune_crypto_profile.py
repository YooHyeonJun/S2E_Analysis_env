#!/usr/bin/env python3
import argparse
import re
from collections import Counter
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
KV_RE = re.compile(r"([A-Za-z0-9_]+)=([^ ]+)")


def clean_line(line: str) -> str:
    return ANSI_RE.sub("", line.rstrip("\n"))


def parse_kv(payload: str) -> dict:
    out = {}
    for m in KV_RE.finditer(payload):
        out[m.group(1)] = m.group(2)
    return out


def parse_log(path: Path):
    stats = {
        "api_counts": Counter(),
        "forced_counts": Counter(),
        "hosts": Counter(),
        "compare_callers": Counter(),
        "compare_retaddrs": Counter(),
    }

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = clean_line(raw)

            if "[c2trace]" in line:
                payload = line.split("[c2trace]", 1)[1].strip()
                kv = parse_kv(payload)
                kind = kv.get("kind", "").lower()
                api = kv.get("api", "").lower()
                phase = kv.get("phase", "").lower()

                if api:
                    stats["api_counts"][api] += 1
                    if phase.startswith("forced"):
                        stats["forced_counts"][api] += 1

                if api == "gethostbyname" and "host" in kv:
                    stats["hosts"][kv["host"]] += 1

                if kind == "compare":
                    caller = kv.get("caller", "")
                    retaddr = kv.get("retaddr", "")
                    if caller:
                        stats["compare_callers"][caller] += 1
                    if retaddr:
                        stats["compare_retaddrs"][retaddr.lower()] += 1

            if "[c2pid]" in line and "guide caller=" in line:
                m_caller = re.search(r"caller=([^ ]+)", line)
                m_ret = re.search(r"retaddr=(0x[0-9a-fA-F]+)", line)
                if m_caller:
                    stats["compare_callers"][m_caller.group(1)] += 1
                if m_ret:
                    stats["compare_retaddrs"][m_ret.group(1).lower()] += 1

    return stats


def csv_from_counter(counter: Counter, limit: int) -> str:
    items = [k for k, _ in counter.most_common(limit)]
    return ",".join(items)


def write_profile_overlay(path: Path, source_log: Path, stats: dict, compare_limit: int):
    compare_callers = stats["compare_callers"]
    compare_retaddrs = stats["compare_retaddrs"]
    forced_counts = stats["forced_counts"]
    api_counts = stats["api_counts"]
    hosts = stats["hosts"]

    forced_total = sum(forced_counts.values())
    io_total = sum(api_counts[a] for a in ("recv", "wsarecv", "recvfrom", "internetreadfile", "winhttpreaddata", "select"))

    lines = []
    lines.append("# Auto-generated crypto/gate tuning overlay")
    lines.append(f"# Source log: {source_log}")
    lines.append("# Usage: source this file before running, or copy needed lines to profile.local.env")
    lines.append("")
    lines.append("export S2E_C2_TRACE_COMPARE=1")
    lines.append("export S2E_C2_GUIDE_COMPARE=1")
    lines.append("export S2E_C2_COMPARE_MAX_PREFIX=${S2E_C2_COMPARE_MAX_PREFIX:-32}")
    lines.append("export S2E_C2_FORCE_COMPARE_PASS=${S2E_C2_FORCE_COMPARE_PASS:-1}")
    lines.append("")

    callers_csv = csv_from_counter(compare_callers, compare_limit)
    retaddrs_csv = csv_from_counter(compare_retaddrs, compare_limit)

    if callers_csv:
        lines.append(f'export S2E_C2_COMPARE_CALLSITE_WHITELIST="{callers_csv}"')
    else:
        lines.append("# No compare caller candidates found in this log.")
        lines.append('# export S2E_C2_COMPARE_CALLSITE_WHITELIST="target_module+0x1234,msvcrt.dll+0x5678"')

    if retaddrs_csv:
        lines.append(f'export S2E_C2_COMPARE_RETADDR_WHITELIST="{retaddrs_csv}"')
    else:
        lines.append("# No compare retaddr candidates found in this log.")
        lines.append('# export S2E_C2_COMPARE_RETADDR_WHITELIST="0x7ff7deadbeef"')

    lines.append("")
    if hosts:
        host, _ = hosts.most_common(1)[0]
        lines.append(f"# Observed frequent DNS host: {host}")
        lines.append("# Host hint only. Runtime uses S2E_C2_FORCE_DNS_IP for DNS emulation.")
    else:
        lines.append("# No gethostbyname host field observed in log.")

    lines.append(f"# Forced I/O events: {forced_total}")
    lines.append(f"# Total I/O-ish events: {io_total}")
    if io_total > 0 and forced_total / io_total > 0.7:
        lines.append("# High forced I/O ratio suggests gate/decrypt check still blocking normal flow.")
        lines.append("# Next run: keep compare guide on, add sample-specific gate offsets via S2E_C2_GATE_*.")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_report(path: Path, stats: dict):
    api_counts = stats["api_counts"]
    forced_counts = stats["forced_counts"]
    compare_callers = stats["compare_callers"]
    compare_retaddrs = stats["compare_retaddrs"]
    hosts = stats["hosts"]

    lines = []
    lines.append("AutoTune Report")
    lines.append("")
    lines.append("Top APIs")
    for api, n in api_counts.most_common(20):
        lines.append(f"- {api}: {n}")
    lines.append("")
    lines.append("Forced APIs")
    for api, n in forced_counts.most_common(20):
        lines.append(f"- {api}: {n}")
    lines.append("")
    lines.append("Compare Caller Candidates")
    if compare_callers:
        for c, n in compare_callers.most_common(20):
            lines.append(f"- {c}: {n}")
    else:
        lines.append("- none found")
    lines.append("")
    lines.append("Compare Retaddr Candidates")
    if compare_retaddrs:
        for r, n in compare_retaddrs.most_common(20):
            lines.append(f"- {r}: {n}")
    else:
        lines.append("- none found")
    lines.append("")
    lines.append("DNS Hosts")
    if hosts:
        for h, n in hosts.most_common(20):
            lines.append(f"- {h}: {n}")
    else:
        lines.append("- none found")
    lines.append("")
    lines.append("Next")
    lines.append("- If compare candidates are empty, this run did not expose compare hooks.")
    lines.append("- Add sample-specific probes via S2E_C2_EXTRA_HOOKS and rerun.")
    lines.append("- Merge confirmed whitelist entries into profiles/<sample>/profile.env.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description="Generate sample-specific crypto gate tuning overlay from log")
    p.add_argument("--log", required=True, help="Input run log")
    p.add_argument("--profile", required=True, help="Profile name (under profiles/)")
    p.add_argument("--project-dir", default="", help="Project root (default: inferred)")
    p.add_argument("--compare-limit", type=int, default=32, help="Max compare candidates to keep")
    args = p.parse_args()

    log_path = Path(args.log).resolve()
    if not log_path.exists():
        raise SystemExit(f"log not found: {log_path}")

    if args.project_dir:
        root = Path(args.project_dir).resolve()
    else:
        root = Path(__file__).resolve().parent.parent

    profile_dir = root / "profiles" / args.profile
    if not profile_dir.exists():
        raise SystemExit(f"profile dir not found: {profile_dir}")

    stats = parse_log(log_path)
    overlay = profile_dir / "profile.autotune.env"
    report = profile_dir / "autotune.report.txt"
    write_profile_overlay(overlay, log_path, stats, args.compare_limit)
    write_report(report, stats)

    print(f"overlay={overlay}")
    print(f"report={report}")


if __name__ == "__main__":
    main()
