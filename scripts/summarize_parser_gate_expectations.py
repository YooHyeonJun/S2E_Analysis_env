#!/usr/bin/env python3
import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path


PARSER_PAT = re.compile(r"api=parser_gate phase=eval .*")


def parse_kv(payload: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tok in payload.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        out[k] = v
    return out


def to_int(v: str | None) -> int | None:
    if not v or v == "na":
        return None
    try:
        if v.startswith("0x") or v.startswith("0X"):
            return int(v, 16)
        return int(v, 10)
    except ValueError:
        return None


def gate_hint(gate: str, gate_989: str, gate_995: str, gate_9a4: str, gate_97d: str, ecx_expect: str) -> str:
    if gate == gate_989:
        return "expect ecx != 0"
    if gate == gate_995:
        return "expect eax == [ctx]"
    if gate == gate_9a4:
        return f"expect ecx == {ecx_expect}"
    if gate == gate_97d:
        return "expect al != 0"
    return "-"


def collect(paths: list[Path]) -> dict[str, dict]:
    stats: dict[str, dict] = {}
    for p in paths:
        for lineno, raw in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            m = PARSER_PAT.search(raw)
            if not m:
                continue
            kv = parse_kv(m.group(0))
            gate = kv.get("gate", "unknown")
            st = stats.setdefault(
                gate,
                {
                    "count": 0,
                    "taken": Counter(),
                    "context": Counter(),
                    "lhs": Counter(),
                    "rhs": Counter(),
                    "cmd": Counter(),
                    "recv_seq": Counter(),
                    "ecx": Counter(),
                    "eax": Counter(),
                    "ctx": Counter(),
                    "sources": defaultdict(int),
                },
            )
            st["count"] += 1
            st["taken"][kv.get("taken", "na")] += 1
            st["context"][kv.get("context", "na")] += 1
            st["lhs"][kv.get("lhs", "na")] += 1
            st["rhs"][kv.get("rhs", "na")] += 1
            st["cmd"][kv.get("cmd", "na")] += 1
            st["recv_seq"][kv.get("recv_seq", "na")] += 1
            st["ecx"][kv.get("ecx", "na")] += 1
            st["eax"][kv.get("eax", "na")] += 1
            st["ctx"][kv.get("ctx", "na")] += 1
            st["sources"][f"{p.name}:{lineno}"] += 1
    return stats


def fmt_counter(c: Counter, n: int = 4) -> str:
    if not c:
        return "-"
    return ", ".join(f"{k}({v})" for k, v in c.most_common(n))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Summarize parser gate observations and infer expected conditions."
    )
    ap.add_argument("--log", action="append", default=[], help="log path (repeatable)")
    ap.add_argument("--log-dir", default="", help="directory containing logs")
    ap.add_argument("--glob", default="20260330_*.log", help="glob for --log-dir")
    ap.add_argument("--top", type=int, default=4, help="top-k values per field")
    ap.add_argument("--gate-97d", default="0x40497d", help="gate tag for al!=0")
    ap.add_argument("--gate-989", default="0x404989", help="gate tag for ecx!=0")
    ap.add_argument("--gate-995", default="0x404995", help="gate tag for eax==ctx")
    ap.add_argument("--gate-9a4", default="0x4049a4", help="gate tag for ecx==const")
    ap.add_argument("--ecx-expect", default="0x3f", help="expected ecx constant at gate-9a4")
    args = ap.parse_args()

    paths: list[Path] = [Path(x).resolve() for x in args.log]
    if args.log_dir:
        paths.extend(sorted(Path(args.log_dir).resolve().glob(args.glob)))
    paths = [p for p in paths if p.exists() and p.is_file()]
    # Keep order but unique
    seen = set()
    uniq: list[Path] = []
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    paths = uniq

    if not paths:
        print("no logs")
        return 2

    stats = collect(paths)
    print(f"logs={len(paths)}")
    for p in paths:
        print(f"- {p}")
    print()

    for gate in sorted(stats.keys()):
        st = stats[gate]
        print(f"[{gate}] hint={gate_hint(gate, args.gate_989, args.gate_995, args.gate_9a4, args.gate_97d, args.ecx_expect)}")
        print(f"count={st['count']} taken={fmt_counter(st['taken'], args.top)} context={fmt_counter(st['context'], args.top)}")
        print(f"lhs={fmt_counter(st['lhs'], args.top)} rhs={fmt_counter(st['rhs'], args.top)} cmd={fmt_counter(st['cmd'], args.top)}")
        print(f"ecx={fmt_counter(st['ecx'], args.top)} eax={fmt_counter(st['eax'], args.top)} ctx={fmt_counter(st['ctx'], args.top)}")
        print(f"recv_seq={fmt_counter(st['recv_seq'], args.top)}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
