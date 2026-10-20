# Changelog

All notable changes to this project are recorded here. There are no tagged
releases yet, so entries are grouped by change set, newest first.

## Scan cost and hook lifecycle

Reduced the cost of the dynamic scan and made cleanup complete and uniform, in
the `v4` agent and the controller.

### Changed

- **Scan scope:** only `UnityFramework` is instrumented
  (`--scan-scope module`, the default). Previously every module was
  instrumented. `--scan-range START:END` narrows the scan to a routine you
  have already located (module-relative, hex, end exclusive);
  `--scan-scope all` restores the previous behaviour.
- **Scan granularity:** one callout per *basic block* instead of one per
  instruction (`--scan-mode block`, the default). `--scan-mode instruction`
  keeps the exhaustive per-instruction scan, e.g. as a baseline.
- **Registers checked:** in block mode only the registers a block actually
  *reads* are checked (from Frida's `Instruction.regsRead`; `w` registers map
  to `x`). If that information is unavailable, or in instruction mode, all of
  `x0-x28` are checked. Previously only ten registers (`x0-x3`, `x19-x24`)
  were looked at, so a pointer in, say, `x27` could be missed.
- The pointer prefilter no longer allocates a `NativePointer` per check.
- **Agent cleanup:** the agent now has explicit, forward-only phases
  (`idle -> waiting-module -> armed -> scanning -> done`). Every way of
  finishing — captured, failed, timeout, cancelled — goes through a single
  `complete()` function that first marks the run done (so callbacks still in
  flight do nothing) and then releases everything in one place: the
  `il2cpp_init` and offset hooks, the module observer, the timeout timer, the
  Stalker threads and the deferred Stalker GC. Previously cleanup was spread
  across several places and was incomplete.
- **Failures fail with a reason** instead of waiting for the timeout: an
  offset that cannot be hooked falls back to the scan at `il2cpp_init` entry;
  `Stalker.follow` failing, an exception inside a callback, or a rejected
  configuration end the run immediately. A timeout now says where it got
  stuck (e.g. "UnityFramework was never loaded").
- **The controller owns the spawned process.** After a failed run, crash,
  Ctrl+C, a script that fails to load or a rejected configuration, it cancels
  the agent, unloads the script, detaches and kills the app it spawned.
  Previously a failure after `spawn()` could leave a suspended app behind.
  Only a run that produced a header leaves the app running. Errors from
  attach/load/configure are reported as one line instead of a traceback.

### Added

- `cancel()` and `dispose()` RPC exports on the agent, both ending in
  `complete()` (`dispose` is called by Frida when the script is unloaded).
- Scan cost reporting: `getStatus()` (printed by the controller as "Scan
  cost") gives blocks compiled/instrumented, callouts run, register checks
  made, scan duration and the time from `il2cpp_init` entry to the header.
- A synthetic cost model in `tests/test_agent.js` comparing callout and
  register-check counts for the same trace under both scan configurations.

### Fixed

- A late load of `UnityFramework` can no longer arm hooks after a timeout.

## Fallback timing and header validation

Two weaknesses of the first `v4` were fixed.

### Fixed

- **The fallback was armed too late.** The dynamic scan used to be installed
  only after a 6 s timer, or from inside the offset hook (already past
  `il2cpp_init` entry), so it could miss the only moment it was needed. Now
  every hook — the offset hook *and* an `il2cpp_init` observer — is installed
  synchronously inside `configure()`, before the controller resumes the app,
  and nothing waits on a timer to get armed.
- **The magic alone no longer proves a header.** A pointer is accepted only
  after `validateHeader()` passes on the exact bytes that are returned: the
  whole `--header-size` window must be readable (checked against the process's
  mappings before reading, with a clear error otherwise), the version must be
  plausible, and the offset/size pairs must be consistent with the
  `Il2CppGlobalMetadataHeader` layout for that version. A candidate that fails
  is remembered and re-checked later, because the buffer may still be getting
  written.

### Notes

- With `--offset`, Stalker stays off until the fast path has failed. A Stalker
  scan that starts in the middle of `il2cpp_init` cannot be made complete, so
  after a failed offset the agent only does a best-effort late scan and the
  controller then relaunches with a full scan from `il2cpp_init` entry. Use
  `--eager-scan` for a single launch at the cost of the slow scan.

## `v4` agent

Introduced a third agent that merges the two earlier ones. The original tool
had two separate agents with opposite trade-offs: a hardcoded-offset hook
(fast, but it breaks on every app update until the offset is re-derived) and a
dynamic Stalker scan (update-proof, but slower).

### Added

- `agents/dump_clean_header_v4.js`, now the default agent:
  - With `--offset` it tries the fast hook first, with no Stalker overhead.
  - If that offset fires but `x21` doesn't hold a valid header, or
    `il2cpp_init` returns without any validated header, the agent notices
    **by event, not by timer**, and the controller relaunches the app once
    with the full dynamic scan. `--no-retry` disables the relaunch;
    `--eager-scan` arms the full scan in the first run instead.
  - Without an offset it skips straight to the dynamic scan.
- The offset is passed in at run time via `--offset` / an RPC call into the
  agent, instead of requiring you to hand-edit the `HOOK_OFFSET` constant in
  the script. The offset is now an optional speed optimization.
- The controller verifies the dumped header's magic and prints the raw
  version field before writing the output file.
- Ctrl+C cancels the agent, detaches and kills the app the tool spawned
  instead of dumping a Python traceback.

### Changed

- The default dump size (`--header-size`) was raised from 512 to 1024 bytes,
  for headroom on newer IL2CPP metadata layouts.
- The older `v2` (scan-only) and `v3` (offset-only) agents moved to
  `agents/legacy/`, so `agents/` only shows the one you should use.
