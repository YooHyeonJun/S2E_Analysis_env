#!/usr/bin/env python3
import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def clean_line(line: str) -> str:
    return ANSI_RE.sub("", line).strip("\n")


def unescape_value(v: str) -> str:
    return v.replace("\\s", " ").replace("\\\\", "\\")


def normalize_caller(caller: str) -> str:
    c = caller.lower()
    if re.fullmatch(r"0x[0-9a-f]+", c):
        return "<addr>"
    return c


def parse_c2trace_line(line: str):
    raw = clean_line(line)
    idx = raw.find("[c2trace]")
    if idx < 0:
        return None
    payload = raw[idx + len("[c2trace]"):].strip()
    if not payload.startswith("kind="):
        return None

    event = {}
    for tok in payload.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        event[k] = unescape_value(v)

    if "kind" not in event:
        return None

    event["caller_norm"] = normalize_caller(event.get("caller", ""))
    event["module_norm"] = event.get("module", "").lower()
    event["api_norm"] = event.get("api", "").lower()
    return event


def parse_log(path: Path, run_id: str):
    events = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            ev = parse_c2trace_line(line)
            if ev is None:
                continue
            ev["run_id"] = run_id
            ev["source_log"] = str(path)
            ev["line"] = lineno
            events.append(ev)
    return events


def write_jsonl(path: Path, events):
    with path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=True) + "\n")


def summarize(events, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    kind_counter = Counter()
    api_counter = Counter()

    compare_sites = {}
    last_net_by_state = {}

    for ev in events:
        kind = ev.get("kind", "")
        kind_counter[kind] += 1
        api = ev.get("api", "")
        if api:
            api_counter[api] += 1

        state_key = (ev.get("run_id", ""), ev.get("sid", ""))
        if kind == "net_read":
            last_net_by_state[state_key] = ev

        if kind == "compare":
            key = (
                ev.get("caller_norm", ""),
                ev.get("module_norm", ""),
                ev.get("api_norm", ""),
            )
            slot = compare_sites.setdefault(
                key,
                {
                    "hits": 0,
                    "after_net_hits": 0,
                    "rhs": Counter(),
                    "retaddrs": Counter(),
                    "lens": Counter(),
                },
            )
            slot["hits"] += 1
            slot["rhs"][ev.get("rhs", "")] += 1
            slot["retaddrs"][ev.get("retaddr", "")] += 1
            slot["lens"][ev.get("len", "")] += 1

            net_ev = last_net_by_state.get(state_key)
            if net_ev is not None:
                slot["after_net_hits"] += 1

    with (out_dir / "summary.txt").open("w", encoding="utf-8") as f:
        f.write("[counts by kind]\n")
        for k, v in kind_counter.most_common():
            f.write(f"{k}\t{v}\n")
        f.write("\n[top api]\n")
        for k, v in api_counter.most_common(100):
            f.write(f"{k}\t{v}\n")

    with (out_dir / "compare_candidates.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "rank",
            "caller_norm",
            "module_norm",
            "api",
            "hits",
            "after_net_hits",
            "distinct_rhs",
            "top_rhs",
            "top_len",
            "top_retaddr",
            "patch_hint",
        ])
        ranked = sorted(
            compare_sites.items(),
            key=lambda kv: (
                kv[1]["after_net_hits"],
                kv[1]["hits"],
                len(kv[1]["rhs"]),
            ),
            reverse=True,
        )

        for idx, (key, data) in enumerate(ranked, 1):
            caller_norm, module_norm, api_norm = key
            top_rhs = data["rhs"].most_common(1)[0][0] if data["rhs"] else ""
            top_len = data["lens"].most_common(1)[0][0] if data["lens"] else ""
            top_ret = data["retaddrs"].most_common(1)[0][0] if data["retaddrs"] else ""
            hint = "overwrite lhs with rhs at this compare site"
            writer.writerow([
                idx,
                caller_norm,
                module_norm,
                api_norm,
                data["hits"],
                data["after_net_hits"],
                len(data["rhs"]),
                top_rhs,
                top_len,
                top_ret,
                hint,
            ])


def main():
    p = argparse.ArgumentParser(description="Normalize [c2trace] logs and extract compare candidates")
    p.add_argument("--log", action="append", default=[], help="Input log path (repeatable)")
    p.add_argument("--log-dir", default="", help="Input directory with *.log")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--run-id", default="", help="Run id tag for --log mode")
    p.add_argument("--jsonl", default="events.jsonl", help="Output jsonl filename")
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logs = [Path(x) for x in args.log]
    if args.log_dir:
        logs.extend(sorted(Path(args.log_dir).glob("*.log")))

    if not logs:
        raise SystemExit("no input logs")

    all_events = []
    for i, logp in enumerate(logs, 1):
        run_id = args.run_id or logp.stem or f"run{i:03d}"
        all_events.extend(parse_log(logp, run_id))

    write_jsonl(out_dir / args.jsonl, all_events)
    summarize(all_events, out_dir)


if __name__ == "__main__":
    main()
