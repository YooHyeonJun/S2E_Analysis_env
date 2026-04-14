#!/usr/bin/env python3
import argparse
import re
from collections import Counter
from pathlib import Path


SEND_PAT = re.compile(r"api=send\s+sock=0x([0-9a-fA-F]+)\s+n=(\d+)")
RECV_PAT = re.compile(r"kind=net_read .*api=recv .*seq=(\d+)")
STEP_PAT = re.compile(
    r"kind=branch_window .*phase=step .*pc=0x([0-9a-fA-F]+).*off=0x([0-9a-fA-F]+).*opcode=([^ ]+)"
)
CMP_PAT = re.compile(
    r"kind=branch_cmp .*pc=0x([0-9a-fA-F]+).*off=0x([0-9a-fA-F]+).*lhs=([^ ]+)\s+rhs=([^ ]+).*recv_seq=(\d+)"
)


def load_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def find_window(lines, recv_seq_target):
    send_idx = -1
    recv_idx = -1
    send_info = None
    recv_info = None

    for i, line in enumerate(lines):
        m = SEND_PAT.search(line)
        if m:
            send_idx = i
            send_info = {"sock": m.group(1), "n": int(m.group(2))}
            break

    if send_idx < 0:
        return None

    for i in range(send_idx + 1, len(lines)):
        m = RECV_PAT.search(lines[i])
        if m and int(m.group(1)) == recv_seq_target:
            recv_idx = i
            recv_info = {"seq": int(m.group(1))}
            break

    if recv_idx < 0:
        return None

    return send_idx, recv_idx, send_info, recv_info


def summarize(lines, start, end):
    steps = []
    cmps = []
    step_pc = Counter()

    for i in range(start, end + 1):
        line = lines[i]
        m = STEP_PAT.search(line)
        if m:
            pc = m.group(1).lower()
            off = m.group(2).lower()
            op = m.group(3)
            steps.append((i + 1, pc, off, op))
            step_pc[f"0x{pc}"] += 1
            continue

        m = CMP_PAT.search(line)
        if m:
            cmps.append(
                {
                    "line": i + 1,
                    "pc": "0x" + m.group(1).lower(),
                    "off": "0x" + m.group(2).lower(),
                    "lhs": m.group(3),
                    "rhs": m.group(4),
                    "recv_seq": int(m.group(5)),
                }
            )

    return steps, cmps, step_pc


def main():
    ap = argparse.ArgumentParser(
        description="Summarize branch flow from first send to recv(seq=N) in c2trace log."
    )
    ap.add_argument("--log", required=True, help="Path to log file")
    ap.add_argument(
        "--top",
        type=int,
        default=15,
        help="Top-N branch step PCs to print (default: 15)",
    )
    ap.add_argument(
        "--recv-seq-target",
        type=int,
        default=1,
        help="End window at first net_read recv with this seq (default: 1)",
    )
    ap.add_argument(
        "--post-lines",
        type=int,
        default=0,
        help="Include extra lines after window end (default: 0)",
    )
    args = ap.parse_args()

    log_path = Path(args.log)
    lines = load_lines(log_path)
    window = find_window(lines, args.recv_seq_target)
    if not window:
        print(
            f"window_not_found: could not locate first send -> first recv(seq={args.recv_seq_target})"
        )
        return 2

    send_idx, recv_idx, send_info, recv_info = window
    end_idx = min(len(lines) - 1, recv_idx + max(0, args.post_lines))
    steps, cmps, step_pc = summarize(lines, send_idx, end_idx)

    print(f"log: {log_path}")
    print(f"window: lines {send_idx + 1}..{recv_idx + 1} (+post {max(0, args.post_lines)})")
    print(f"first_send: line={send_idx + 1} sock=0x{send_info['sock']} n={send_info['n']}")
    print(f"first_recv: line={recv_idx + 1} seq={recv_info['seq']}")
    print(f"branch_window_steps: {len(steps)}")
    print(f"branch_cmp_count: {len(cmps)}")

    print("\n[top branch step PCs]")
    for pc, cnt in step_pc.most_common(args.top):
        print(f"{pc}\t{cnt}")

    print("\n[branch_cmp lhs/rhs in window]")
    if not cmps:
        print("(none)")
    else:
        for c in cmps:
            print(
                f"line={c['line']} pc={c['pc']} off={c['off']} "
                f"lhs={c['lhs']} rhs={c['rhs']} recv_seq={c['recv_seq']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
