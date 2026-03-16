#!/usr/bin/env python3
import argparse
import re
from collections import Counter
from pathlib import Path


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
PID_RE = re.compile(r"pid:\s*(\d+)")


def clean_line(line: str) -> str:
    return ANSI_RE.sub("", line.rstrip("\n"))


def parse_kv_payload(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tok in text.split():
        if "=" not in tok:
            continue
        key, value = tok.split("=", 1)
        out[key] = value
    return out


def format_event(ev: dict[str, object]) -> str:
    line = ev["line"]
    kind = ev["type"]
    if kind == "trace":
        api = ev.get("api", "?")
        payload = ev.get("payload", "")
        return f"L{line}: trace {api} {payload}".rstrip()
    if kind == "pid":
        return f"L{line}: pid {ev.get('message', '')}".rstrip()
    if kind == "exception":
        pid = ev.get("pid", "?")
        return f"L{line}: exception pid={pid}"
    if kind == "hook":
        return f"L{line}: hook {ev.get('message', '')}".rstrip()
    return f"L{line}: {ev.get('raw', '')}".rstrip()


def parse_log(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    summary: dict[str, object] = {
        "path": str(path),
        "hook_modules": [],
        "hooks_registered": None,
        "tracked_pid": None,
        "tracked_by": None,
        "interesting_api": Counter(),
        "net_read_total": 0,
        "net_read_bytes": 0,
        "recv_bytes": 0,
        "send_bytes": 0,
        "exceptions": [],
        "forced_connect": 0,
        "forced_select": 0,
        "forced_exit": 0,
        "stages": [],
    }
    timeline: list[dict[str, object]] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            line = clean_line(raw)
            if not line:
                continue

            idx = line.find("[c2trace]")
            if idx >= 0:
                payload = line[idx + len("[c2trace]"):].strip()
                fields = parse_kv_payload(payload)
                api = fields.get("api", "")
                kind = fields.get("kind", "")
                ev = {
                    "type": "trace",
                    "line": lineno,
                    "raw": line,
                    "api": api,
                    "kind": kind,
                    "payload": payload,
                }
                timeline.append(ev)

                if api:
                    summary["interesting_api"][api] += 1
                if kind == "net_read":
                    summary["net_read_total"] += 1
                    n = int(fields.get("n", "0"), 10)
                    summary["net_read_bytes"] += n
                    if api.lower() == "recv":
                        summary["recv_bytes"] += n
                if api.lower() in {"send", "wsasend", "sendto", "internetwritefile"}:
                    n = int(fields.get("n", "0"), 10)
                    summary["send_bytes"] += n
                if "phase=forced_call" in payload and api.lower() == "connect":
                    summary["forced_connect"] += 1
                if "phase=forced" in payload and api.lower() == "select":
                    summary["forced_select"] += 1
                if "phase=forced" in payload and api in {"ExitProcess", "TerminateProcess", "exit"}:
                    summary["forced_exit"] += 1
                continue

            idx = line.find("[c2pid]")
            if idx >= 0:
                payload = line[idx + len("[c2pid]"):].strip()
                if "export-hooks=" in payload:
                    summary["hook_modules"].append(payload)
                    timeline.append({"type": "hook", "line": lineno, "message": payload, "raw": line})
                elif payload.startswith("hooks registered="):
                    summary["hooks_registered"] = payload
                    timeline.append({"type": "hook", "line": lineno, "message": payload, "raw": line})
                elif payload.startswith("tracking pid="):
                    summary["tracked_pid"] = payload
                    summary["tracked_by"] = payload
                    timeline.append({"type": "pid", "line": lineno, "message": payload, "raw": line})
                elif payload.startswith("stage-advance"):
                    summary["stages"].append((lineno, payload))
                    timeline.append({"type": "pid", "line": lineno, "message": payload, "raw": line})
                elif payload.startswith("inject stage="):
                    timeline.append({"type": "pid", "line": lineno, "message": payload, "raw": line})
                elif payload.startswith("force select ready"):
                    timeline.append({"type": "pid", "line": lineno, "message": payload, "raw": line})
                elif payload.startswith("enter recv") or payload.startswith("enter send") or payload.startswith("enter connect"):
                    timeline.append({"type": "pid", "line": lineno, "message": payload, "raw": line})
                continue

            if "Exception record for rundll32.exe" in line:
                m = PID_RE.search(line)
                pid = m.group(1) if m else "?"
                summary["exceptions"].append((lineno, pid))
                timeline.append({"type": "exception", "line": lineno, "pid": pid, "raw": line})

    return summary, timeline


def build_timeline(summary: dict[str, object], timeline: list[dict[str, object]]) -> list[str]:
    selected: list[str] = []
    interesting_api = {
        "WSAStartup", "socket", "closesocket", "gethostbyname", "connect",
        "select", "recv", "WSARecv", "send", "WSASend", "sendto",
        "InternetConnectA", "InternetReadFile", "InternetWriteFile",
        "WinHttpReadData", "CreateMutexA", "ExitProcess", "TerminateProcess",
    }

    for ev in timeline:
        if ev["type"] in {"pid", "exception", "hook"}:
            selected.append(format_event(ev))
            continue
        if ev["type"] == "trace":
            api = ev.get("api", "")
            payload = ev.get("payload", "")
            if api in interesting_api:
                selected.append(format_event(ev))
                continue
            if "phase=forced" in payload or "phase=ret" in payload:
                selected.append(format_event(ev))

    return selected


def render_summary(summary: dict[str, object], timeline_lines: list[str], timeline_limit: int) -> str:
    api_counts: Counter = summary["interesting_api"]
    lines: list[str] = []
    lines.append(f"Log: {summary['path']}")
    lines.append("")
    lines.append("Summary")
    lines.append(f"- hooks: {summary['hooks_registered'] or 'unknown'}")
    lines.append(f"- tracked: {summary['tracked_by'] or 'not tracked'}")
    lines.append(f"- forced connect: {summary['forced_connect']}")
    lines.append(f"- forced select: {summary['forced_select']}")
    lines.append(f"- forced exit: {summary['forced_exit']}")
    lines.append(f"- net reads: {summary['net_read_total']} calls, {summary['net_read_bytes']} bytes")
    lines.append(f"- recv bytes: {summary['recv_bytes']}")
    lines.append(f"- send bytes: {summary['send_bytes']}")
    lines.append(f"- exceptions: {len(summary['exceptions'])}")
    lines.append("")

    if summary["hook_modules"]:
        lines.append("Hook Modules")
        for item in summary["hook_modules"]:
            lines.append(f"- {item}")
        lines.append("")

    if api_counts:
        lines.append("Top APIs")
        for api, count in api_counts.most_common(15):
            lines.append(f"- {api}: {count}")
        lines.append("")

    if summary["stages"]:
        lines.append("Stages")
        for lineno, payload in summary["stages"]:
            lines.append(f"- L{lineno}: {payload}")
        lines.append("")

    if summary["exceptions"]:
        lines.append("Exceptions")
        for lineno, pid in summary["exceptions"]:
            lines.append(f"- L{lineno}: rundll32.exe pid={pid}")
        lines.append("")

    lines.append("Timeline")
    if not timeline_lines:
        lines.append("- no selected events")
    else:
        for item in timeline_lines[:timeline_limit]:
            lines.append(f"- {item}")
        if len(timeline_lines) > timeline_limit:
            lines.append(f"- ... {len(timeline_lines) - timeline_limit} more")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize S2E DLL C2 logs into a readable report")
    ap.add_argument("log", help="Input .log file")
    ap.add_argument("--timeline-limit", type=int, default=60, help="Max timeline lines to print")
    ap.add_argument("--write-timeline", default="", help="Optional path to write full selected timeline")
    args = ap.parse_args()

    log_path = Path(args.log)
    summary, timeline = parse_log(log_path)
    timeline_lines = build_timeline(summary, timeline)
    print(render_summary(summary, timeline_lines, args.timeline_limit))

    if args.write_timeline:
        out = Path(args.write_timeline)
        out.write_text("\n".join(timeline_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
