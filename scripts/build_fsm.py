#!/usr/bin/env python3
import argparse
import csv
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

STATE_LABELS = {
    "BOOT": "S0_BOOT",
    "TRACKED": "S1_TRACKED",
    "NET_SETUP": "S2_NET_SETUP",
    "DNS": "S3_DNS",
    "C2_IO": "S4_C2_IO",
    "FORCED_IO": "S5_FORCED_IO",
    "ACTION": "S6_ACTION",
    "PERSISTENCE": "S7_PERSISTENCE",
    "RECONNECT": "S8_RECONNECT",
    "INJECT": "S9_INJECT",
    "EXIT": "S10_EXIT",
    "ERROR": "S11_ERROR",
}

API_NET_SETUP = {
    "wsastartup",
    "socket",
    "connect",
    "wsaconnect",
    "gethostbyname",
    "internetconnecta",
    "internetopena",
    "internetopenurla",
}

API_DNS = {
    "gethostbyname",
    "gethostbyaddr",
    "gethostname",
}

API_C2_IO = {
    "recv",
    "wsarecv",
    "recvfrom",
    "internetreadfile",
    "winhttpreaddata",
    "send",
    "wsasend",
    "sendto",
    "internetwritefile",
    "select",
    "wsapoll",
    "wsawaitformultipleevents",
}

API_ACTION = {
    "createfilea",
    "createfilew",
    "writefile",
    "readfile",
    "loadlibrarya",
    "loadlibraryw",
    "loadlibraryexa",
    "loadlibraryexw",
    "getprocaddress",
    "createthread",
    "createremotethread",
    "virtualallocex",
    "writeprocessmemory",
    "createprocessa",
    "createprocessw",
    "shellexecutea",
    "shellexecutew",
}

API_PERSISTENCE = {
    "createmutexa",
    "createmutexw",
}

API_EXIT = {
    "exitprocess",
    "terminateprocess",
    "ntterminateprocess",
    "rtlexituserprocess",
    "exit",
    "_exit",
    "abort",
}


def clean_line(line: str) -> str:
    return ANSI_RE.sub("", line.rstrip("\n"))


def parse_kv(payload: str) -> dict:
    out = {}
    for tok in payload.split():
        if "=" not in tok:
            continue
        key, value = tok.split("=", 1)
        out[key] = value
    return out


def classify_event(raw: str, current_state: str) -> tuple[str, dict]:
    if "[c2trace]" in raw:
        payload = raw.split("[c2trace]", 1)[1].strip()
        kv = parse_kv(payload)
        api = kv.get("api", "").lower()
        phase = kv.get("phase", "").lower()
        kind = kv.get("kind", "").lower()

        if api in API_EXIT or "forced_exit" in phase:
            return "EXIT", kv
        if kind == "exception":
            return "ERROR", kv
        if api in API_PERSISTENCE:
            return "PERSISTENCE", kv
        if api in API_DNS:
            return "DNS", kv
        if phase.startswith("forced") and (api in API_C2_IO or api in API_NET_SETUP):
            return "FORCED_IO", kv
        if api in API_ACTION:
            return "ACTION", kv
        if api in API_C2_IO or kind in {"net_read", "net_write"}:
            return "C2_IO", kv
        if api in API_NET_SETUP:
            if current_state in {"C2_IO", "FORCED_IO", "DNS"}:
                return "RECONNECT", kv
            return "NET_SETUP", kv
        return "", kv

    if "[c2pid]" in raw:
        payload = raw.split("[c2pid]", 1)[1].strip().lower()
        if payload.startswith("tracking pid="):
            return "TRACKED", {"message": payload}
        if payload.startswith("hooks registered="):
            return "BOOT", {"message": payload}
        if payload.startswith("inject stage="):
            return "INJECT", {"message": payload}
        return "", {"message": payload}

    lowered = raw.lower()
    # Ignore "S2EBSODHook is at ..." bootstrap info line.
    if "s2ebsodhook is at" in lowered:
        return "", {}
    if "exception record" in lowered or "bsod" in lowered:
        return "ERROR", {}
    if "kill state" in lowered:
        return "EXIT", {}
    return "", {}


def iter_log_events(log_path: Path):
    current = "BOOT"
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            raw = clean_line(line)
            if not raw:
                continue
            bucket, kv = classify_event(raw, current)
            if not bucket:
                continue
            current = bucket
            yield lineno, bucket, kv, raw


def build_fsm(log_path: Path):
    current = "BOOT"
    transitions = Counter()
    node_hits = Counter()
    details = []
    node_hits[current] += 1

    for lineno, bucket, kv, raw in iter_log_events(log_path):
        nxt = bucket
        if nxt == current:
            node_hits[nxt] += 1
            continue
        transitions[(current, nxt)] += 1
        node_hits[nxt] += 1
        details.append(
            {
                "line": lineno,
                "from": current,
                "to": nxt,
                "raw": raw,
                "api": kv.get("api", ""),
                "phase": kv.get("phase", ""),
            }
        )
        current = nxt

    return node_hits, transitions, details


def build_tree(log_path: Path):
    events = list(iter_log_events(log_path))
    nodes = [{"id": 0, "name": "ROOT", "line": 0}]
    edges = []
    by_parent_sig = defaultdict(dict)

    cur = 0
    for lineno, bucket, kv, raw in events:
        label = STATE_LABELS[bucket]
        key = (cur, label)
        if key in by_parent_sig[cur]:
            nxt = by_parent_sig[cur][key]
        else:
            nxt = len(nodes)
            nodes.append({"id": nxt, "name": label, "line": lineno})
            edges.append((cur, nxt, kv.get("api", "") or kv.get("message", "")))
            by_parent_sig[cur][key] = nxt
        cur = nxt
    return nodes, edges


def write_fsm_dot(path: Path, node_hits: Counter, transitions: Counter):
    lines = ["digraph FSM {", "  rankdir=LR;", '  node [shape=box, style="rounded,filled", fillcolor="#eef5ff"];']
    for node, count in sorted(node_hits.items()):
        label = STATE_LABELS[node]
        lines.append(f'  "{label}" [label="{label}\\nhits={count}"];')
    for (a, b), count in sorted(transitions.items()):
        lines.append(f'  "{STATE_LABELS[a]}" -> "{STATE_LABELS[b]}" [label="n={count}"];')
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_tree_dot(path: Path, nodes: list, edges: list):
    lines = ["digraph TREE {", "  rankdir=TB;", '  node [shape=ellipse, style="filled", fillcolor="#f8fbff"];']
    for n in nodes:
        lines.append(f'  n{n["id"]} [label="{n["name"]}\\nL{n["line"]}"];')
    for src, dst, lbl in edges:
        safe = (lbl or "").replace('"', '\\"')
        lines.append(f'  n{src} -> n{dst} [label="{safe}"];')
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def maybe_render_png(dot_path: Path):
    try:
        subprocess.run(
            ["dot", "-Tpng", str(dot_path), "-o", str(dot_path.with_suffix(".png"))],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def write_transition_csv(path: Path, transitions: Counter):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["from_state", "to_state", "count"])
        for (src, dst), count in sorted(transitions.items()):
            w.writerow([STATE_LABELS[src], STATE_LABELS[dst], count])


def main():
    p = argparse.ArgumentParser(description="Build FSM/tree graphs from S2E c2 logs")
    p.add_argument("--log", required=True, help="Input log path")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--prefix", default="", help="Output file prefix")
    args = p.parse_args()

    log_path = Path(args.log)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = args.prefix or log_path.stem

    node_hits, transitions, details = build_fsm(log_path)
    tree_nodes, tree_edges = build_tree(log_path)

    fsm_dot = out_dir / f"{prefix}.fsm.dot"
    tree_dot = out_dir / f"{prefix}.tree.dot"
    trans_csv = out_dir / f"{prefix}.transitions.csv"
    detail_jsonl = out_dir / f"{prefix}.transitions.jsonl"
    summary_json = out_dir / f"{prefix}.summary.json"

    write_fsm_dot(fsm_dot, node_hits, transitions)
    write_tree_dot(tree_dot, tree_nodes, tree_edges)
    write_transition_csv(trans_csv, transitions)

    with detail_jsonl.open("w", encoding="utf-8") as f:
        for item in details:
            f.write(json.dumps(item, ensure_ascii=True) + "\n")

    summary = {
        "log": str(log_path),
        "states": {STATE_LABELS[k]: v for k, v in node_hits.items()},
        "transition_count": sum(transitions.values()),
        "unique_transitions": len(transitions),
        "tree_nodes": len(tree_nodes),
        "tree_edges": len(tree_edges),
        "fsm_dot": str(fsm_dot),
        "tree_dot": str(tree_dot),
        "transitions_csv": str(trans_csv),
    }
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    fsm_png = maybe_render_png(fsm_dot)
    tree_png = maybe_render_png(tree_dot)

    print(f"fsm_dot={fsm_dot}")
    print(f"tree_dot={tree_dot}")
    print(f"transitions_csv={trans_csv}")
    print(f"transitions_jsonl={detail_jsonl}")
    print(f"summary_json={summary_json}")
    print(f"fsm_png={'yes' if fsm_png else 'no'}")
    print(f"tree_png={'yes' if tree_png else 'no'}")


if __name__ == "__main__":
    main()
