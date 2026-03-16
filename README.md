# payload_replay_runtime

Unified S2E project for payload replay and C2-driven analysis across both EXE and DLL targets.

This project consolidates the runtime behavior that previously lived across:
- `payload_replay`
- `payload_replay_exe`
- `payload_replay_dll`

## What Is Included

- Shared `c2pid` runtime for API/network/file/compare hooks
- Target-aware split for EXE and DLL behavior
- PID tracking and compare-guidance logic
- `WriteFile`-based payload extraction
- DLL export hook support
- Trace normalization helpers in [`scripts/`](./scripts)

## Runtime Layout

- [`c2pid/core/`](./c2pid/core): shared state, resolver, profile selection, hook assembly
- [`c2pid/hooks/`](./c2pid/hooks): common hook implementations
- [`c2pid/targets/dll/`](./c2pid/targets/dll): DLL-only hooks
- [`c2pid/targets/exe/`](./c2pid/targets/exe): EXE-only hooks
- [`legacy/`](./legacy): old non-runtime entrypoints kept for reference

## Basic Usage

Default hook mode:

```bash
echo c2pid > input-mode.txt
```

EXE target:

```bash
S2E_C2_TARGET_KIND=exe \
S2E_TARGET_MODULE=test.exe \
S2E_INPUT_MODE=c2pid \
./launch-s2e.sh
```

DLL target:

```bash
S2E_C2_TARGET_KIND=dll \
S2E_TARGET_MODULE=rundll32.exe \
S2E_INPUT_MODE=c2pid \
./scripts/run_dll_payload.sh payload.dll Install
```

## Important Environment Variables

- `S2E_C2_TARGET_KIND=exe|dll`
- `S2E_TARGET_MODULE=<target module name>`
- `S2E_DLL_NAME=<dll name>` for DLL runs
- `S2E_DLL_EXPORT=<export name>` or `S2E_DLL_HOOK_EXPORTS=<csv>`
- `S2E_C2_EXTRACT_PAYLOADS=1` to enable payload dumping
- `S2E_C2_EXTRA_HOOKS=<module!offset:handler,...>` for explicit probe sites

## Notes

- Old `c2-hooks.lua` and `input-hooks.lua` are preserved under [`legacy/`](./legacy).
- Multi-run collection and some experimental helper scripts are not yet folded into this repo root.
- Local run outputs such as `s2e-out-*`, `logs/`, `extracted/`, and symlinked samples are ignored by git.
