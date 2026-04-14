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
- [`profiles/`](./profiles): malware-family or sample-specific settings
- [`scripts/profilectl.sh`](./scripts/profilectl.sh): run/tail/status wrapper around a named profile
- [`legacy/`](./legacy): old non-runtime entrypoints kept for reference

## Basic Usage

Default hook mode:

```bash
echo c2pid > input-mode.txt
```

EXE target:

```bash
S2E_C2_TARGET_KIND=exe \
S2E_TARGET_MODULE=target.exe \
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

Profile-driven runs:

```bash
cp -r profiles/template profiles/my_sample
$EDITOR profiles/my_sample/profile.env
./scripts/profilectl.sh run my_sample
./scripts/profilectl.sh status my_sample
./scripts/profilectl.sh tail my_sample
```

RAT staged workflow:

```bash
./scripts/run_rat_staged.sh rat_staged
# stage1 only (default, single run)

./scripts/run_rat_staged.sh rat_staged --feedback
# stage1 + stage2/3 feedback reruns
```

## Feedback Loop (Baseline + Editable Strategies)

To separate a stable baseline from tunable parts, use the feedback controller:

```bash
./c2pid/run_feedback_loop.sh run_live.log
```

What it does:
- loads fixed baseline env (`profiles/<name>/profile.env`)
- optionally loads local overrides (`profiles/<name>/profile.local.env`)
- applies one strategy file at a time from `profiles/<name>/feedback_strategies/*.env`
- runs `c2pid/run_solver_loop.sh`
- builds FSM from each iteration log and computes `S5_FORCED_IO / total_states`
- if forced-I/O lock persists, escapes and tries the next strategy automatically

Default strategy examples live in:
- `profiles/default/feedback_strategies/00_compare_guide.env`
- `profiles/default/feedback_strategies/10_short_symbolic.env`
- `profiles/default/feedback_strategies/20_gate_len_header.env`

RAT-oriented staged profile (baseline unchanged, tuning outside baseline):
- `profiles/rat_staged/profile.env`: Stage 1 forced-concrete baseline
- `profiles/rat_staged/profile.local.env`: sample-only overrides (target file, main recv RVA range)
- `profiles/rat_staged/feedback_strategies/10_min_symbolic_ingress.env`: Stage 2 narrow ingress symbolic
- `profiles/rat_staged/feedback_strategies/20_compare_driven_expand.env`: Stage 3 compare-driven expansion

Useful knobs:
- `S2E_FEEDBACK_FORCED_RATIO_MAX` (default `0.98`)
- `S2E_FEEDBACK_MIN_RECV_DECLS` (default `1`)
- `S2E_FEEDBACK_MIN_GUIDE_HITS` (default `1`)
- `S2E_FEEDBACK_MAX_ITERS` (default `6`)
- `S2E_FEEDBACK_NEXT_INPUT_HOOK=/path/to/hook.sh` (optional custom next-input logic)

## Important Environment Variables

- `S2E_C2_TARGET_KIND=exe|dll`
- `S2E_TARGET_MODULE=<target module name>`
- `S2E_TARGET_FILE=<host file to fetch into guest>`
- `S2E_PROFILE=<profile name>` to auto-load `profiles/<name>/profile.env`
- `S2E_DLL_NAME=<dll name>` for DLL runs
- `S2E_DLL_EXPORT=<export name>` or `S2E_DLL_HOOK_EXPORTS=<csv>`
- `S2E_C2_EXTRACT_PAYLOADS=1` to enable payload dumping
- `S2E_C2_EXTRA_HOOKS=<module!offset:handler,...>` for explicit probe sites

## Notes

- Baseline runtime files should stay stable; put per-malware tuning in `profiles/<name>/`.
- Old `c2-hooks.lua` and `input-hooks.lua` are preserved under [`legacy/`](./legacy).
- Multi-run collection and some experimental helper scripts are not yet folded into this repo root.
- Local run outputs such as `s2e-out-*`, `logs/`, `extracted/`, and symlinked samples are ignored by git.

## FSM/Tree From Logs

Build a coarse behavior FSM and a path-preserving tree from any run log:

```bash
python3 scripts/build_fsm.py \
  --log run_live.log \
  --out-dir logs/fsm \
  --prefix run_live
```

Outputs:
- `logs/fsm/<prefix>.fsm.dot`: merged finite-state machine
- `logs/fsm/<prefix>.tree.dot`: path tree from ordered events
- `logs/fsm/<prefix>.transitions.csv`: aggregated transition counts
- `logs/fsm/<prefix>.transitions.jsonl`: transition event details
- `logs/fsm/<prefix>.summary.json`: quick stats

If Graphviz `dot` is available, PNG files are generated next to each `.dot`.
