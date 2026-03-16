This folder is a genericized copy of `payload_replay_dll`.

What was removed from the default path:
- hardcoded target DLL fallback (`sid1_h294_2110453.dll`)
- default explicit internal probe offsets for one sample
- default worker/cleanup field decoding based on sample-specific object layout
- default export set tied to one family of exports

Generic defaults:
- target DLL fallback: `target.dll`
- target export hooks: `S2E_DLL_HOOK_EXPORTS`, else `S2E_DLL_EXPORT`, else `Install`
- explicit internal probes: disabled unless `S2E_C2_EXTRA_HOOKS` is set

Example:
- `./scripts/run_dll_payload.sh payload.dll Install`
- `S2E_C2_EXTRA_HOOKS="payload.dll!0x1234:hook_cleanup_probe" ./scripts/run_dll_payload.sh payload.dll Run`
