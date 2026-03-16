#!/usr/bin/env python3
import argparse
from pathlib import Path

IMAGE_FILE_DLL = 0x2000


def detect_pe_kind(path: Path):
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if len(data) < 0x100:
        return None
    if data[:2] != b"MZ":
        return None

    e_lfanew = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    if e_lfanew + 0x18 >= len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None

    coff_off = e_lfanew + 4
    characteristics = int.from_bytes(data[coff_off + 18:coff_off + 20], "little", signed=False)
    if characteristics & IMAGE_FILE_DLL:
        return "dll"
    return "exe"


def target_name(path: Path, new_ext: str):
    # Normalize noisy chained suffixes from extracted names:
    # e.g. foo.jpg.bin -> foo.dll (or foo.exe)
    p = path
    noisy = {".bin", ".jpg", ".jpeg", ".tmp", ".dat", ".raw", ".payload", ".dll", ".exe"}
    while p.suffix.lower() in noisy:
        p = p.with_suffix("")
    return p.with_suffix(f".{new_ext}")


def main():
    ap = argparse.ArgumentParser(description="Classify extracted payload files as exe/dll by PE header and rename")
    ap.add_argument("--root", default="/home/tako/hjyoo/s2e/projects/trace_harvest/extracted", help="Root dir to scan")
    ap.add_argument("--dry-run", action="store_true", help="Print planned changes only")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"root not found: {root}")

    changed = 0
    scanned = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        scanned += 1
        kind = detect_pe_kind(p)
        if kind is None:
            continue

        dst = target_name(p, kind)
        if dst == p:
            continue

        print(f"{p} -> {dst}")
        if not args.dry_run:
            try:
                p.rename(dst)
                changed += 1
            except OSError as e:
                print(f"rename failed: {p}: {e}")

    print(f"scanned={scanned} renamed={changed} dry_run={args.dry_run}")


if __name__ == "__main__":
    main()
