#!/usr/bin/env python3
import argparse
import re
from collections import Counter
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


def parse_u32(s: str | None) -> int | None:
    if not s or s == "na":
        return None
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Learn parser-gate force values from a log.")
    ap.add_argument("--log", required=True, help="input log")
    ap.add_argument("--out-env", required=True, help="output env file")
    ap.add_argument("--prefer-ecx", default="0x3f", help="preferred ecx force value (default 0x3f)")
    ap.add_argument("--gate-989", default="0x404989", help="gate tag for ecx!=0 check")
    ap.add_argument("--gate-995", default="0x404995", help="gate tag for eax==ctx check")
    ap.add_argument("--gate-9a4", default="0x4049a4", help="gate tag for ecx==const check")
    args = ap.parse_args()

    log_path = Path(args.log).resolve()
    lines = log_path.read_text(errors="ignore").splitlines()

    eax_4995 = Counter()
    ecx_4989 = Counter()
    ecx_49a4 = Counter()
    for raw in lines:
        m = PARSER_PAT.search(raw)
        if not m:
            continue
        kv = parse_kv(m.group(0))
        gate = kv.get("gate", "")
        if gate == args.gate_995:
            v = parse_u32(kv.get("eax"))
            if v is not None:
                eax_4995[v] += 1
        elif gate == args.gate_989:
            v = parse_u32(kv.get("ecx"))
            if v is not None:
                ecx_4989[v] += 1
        elif gate == args.gate_9a4:
            v = parse_u32(kv.get("ecx"))
            if v is not None:
                ecx_49a4[v] += 1

    # ctx 후보: 0x4995에서 가장 자주 본 eax
    force_ctx = eax_4995.most_common(1)[0][0] if eax_4995 else 0x280

    # ecx 후보: 0x49a4 목표 상수(기본 0x3f) 우선
    force_ecx = parse_u32(args.prefer_ecx)
    if force_ecx is None:
        force_ecx = 0x3F

    out_env = Path(args.out_env).resolve()
    out_env.parent.mkdir(parents=True, exist_ok=True)
    content = [
        f"# auto-generated from {log_path.name}",
        f"export S2E_C2_FORCE_CTX_FD=0x{force_ctx:x}",
        f"export S2E_C2_FORCE_GATE_ECX=0x{force_ecx:x}",
    ]
    out_env.write_text("\n".join(content) + "\n")

    print(f"log={log_path}")
    print(f"out_env={out_env}")
    print(f"suggest_ctx_fd=0x{force_ctx:x}")
    print(f"suggest_gate_ecx=0x{force_ecx:x}")
    print(
        "seen:"
        f" gate4995_eax_top={','.join([f'0x{k:x}:{v}' for k,v in eax_4995.most_common(3)]) or '-'}"
        f" gate4989_ecx_top={','.join([f'0x{k:x}:{v}' for k,v in ecx_4989.most_common(3)]) or '-'}"
        f" gate49a4_ecx_top={','.join([f'0x{k:x}:{v}' for k,v in ecx_49a4.most_common(3)]) or '-'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
