# il2cpp-re

A Frida-based tool that dumps a clean (deobfuscated) **global-metadata
header** from a running Unity/IL2CPP app on iOS, for analysis with
[Il2CppDumper](https://github.com/Perfare/Il2CppDumper) or similar tools.
The target app is **never hardcoded** — pass it via `--target` or an
environment variable at run time.

> **Purpose:** a personal research/reverse-engineering tool (understanding
> IL2CPP internals, metadata layout, etc). This is not a cheat/hack tool and
> ships with no feature that modifies app state. Only use it on apps you
> have the legal right to analyze (your own builds, or apps you've been
> explicitly authorized to test) — running it against a third-party app may
> violate that app's Terms of Service; that's on you.

> **Status:** research prototype. The code was written for research and
> testing and has not been validated experimentally against real-world
> targets yet — expect rough edges.

## Requirements

- A jailbroken iOS device
- `frida-server` running on the device
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) to forward
  the USB port, e.g.:
  ```
  pymobiledevice3 usbmux forward 45861 45861
  ```
- Python 3 + `pip install -r requirements.txt` (installs `frida` ≥ 16.7, which
  the agents need for `Process.attachModuleObserver`). The Python `frida`
  major version must match the `frida-server` on the device.

## Usage

```bash
# Recommended: adaptive agent, no offset needed (goes straight to the dynamic scan)
python dump_clean_header.py --target com.example.unityapp
# or
TARGET_BUNDLE_ID=com.example.unityapp python dump_clean_header.py

# With a known offset for the fast path (falls back automatically if it's stale)
python dump_clean_header.py --target com.example.unityapp --offset 0xab6ad08

# Single launch: full scan armed from il2cpp_init entry even though an offset is given
python dump_clean_header.py --target com.example.unityapp --offset 0xab6ad08 --eager-scan

# Narrow the scan to a routine you already located (module-relative, hex, end exclusive)
python dump_clean_header.py --target com.example.unityapp --scan-range 0xa00000:0xa40000

# Exhaustive baseline for comparison: a callout after every instruction, in every module
python dump_clean_header.py --target com.example.unityapp --scan-mode instruction --scan-scope all

# A real header is rejected by the structural checks (e.g. a metadata version newer than the
# known layouts)? Downgrade those checks to warnings (magic + version are still required)
python dump_clean_header.py --target com.example.unityapp --lenient

# Force the legacy scan-only or offset-only agents
python dump_clean_header.py --target com.example.unityapp --agent agents/legacy/dump_clean_header_v2.js
python dump_clean_header.py --target com.example.unityapp --agent agents/legacy/dump_clean_header_v3.js
```

The script spawns the target app, injects the agent, resumes the process,
and waits up to 45 s (`--timeout`, in milliseconds) for `il2cpp_init` to reach
the point where the header has been fully deobfuscated. The result is
validated again by the controller (so output from the legacy agents is checked
too) and written to `clean_header.bin` (adjustable with `--out`) only if it
passes; otherwise the raw bytes go to `clean_header.rejected.bin` and the
script exits with status 2. When a scan finds the header, the controller prints
where (`foundAt`: the register and the module-relative address of the block) —
a starting point for `--scan-range`.

### Options

| Option | Default | Applies to | Description |
| --- | --- | --- | --- |
| `--target`, `-t` | `$TARGET_BUNDLE_ID` | all | Bundle ID of the app to spawn. Required (either the flag or the variable). |
| `--agent`, `-a` | `agents/dump_clean_header_v4.js` | — | Agent script to inject. |
| `--offset` | `$HOOK_OFFSET` | v4 | Optional hex offset into `UnityFramework` for the fast-path hook. |
| `--header-size` | `1024` | v4 | Bytes to dump from the clean header pointer. Between 272 (0x110, the largest known header) and 0x100000. The legacy agents always dump 512 bytes. |
| `--lenient` | off | v4 + controller | Downgrade the structural header checks to warnings (magic + version stay fatal). |
| `--eager-scan` | off | v4 | With `--offset`, arm the full scan at `il2cpp_init` entry in the first run. |
| `--no-retry` | off | v4 | Don't relaunch with a full scan when the offset fast path fails. |
| `--scan-scope` | `module` | v4 | `module` = only `UnityFramework`; `all` = every module. |
| `--scan-mode` | `block` | v4 | `block` = one callout per basic block; `instruction` = one per instruction. |
| `--scan-range` | none | v4 | Limit the scan to `START:END` (module-relative, hex, end exclusive). |
| `--out`, `-o` | `clean_header.bin` | all | Where to write the validated header. |
| `--remote` | `$FRIDA_REMOTE`, else `127.0.0.1:45861` | all | frida-server address (matches the port forwarded above). |
| `--timeout` | `45000` | all | Milliseconds to wait for the header. |

"v4" in the *Applies to* column means the option is only honoured by the v4
agent; the legacy agents ignore it (v3 uses its hardcoded `HOOK_OFFSET`
instead). Exit status: `0` header written, `1` run failed or no header
captured, `2` captured bytes failed validation (also used for command-line
usage errors), `130` interrupted with Ctrl+C.

## Layout

```
il2cpp-re/
├── LICENSE                          # GNU AGPL v3.0
├── README.md
├── requirements.txt
├── .gitignore
├── dump_clean_header.py             # controller: spawn app, load agent, wait for the RPC, validate and write the header;
│                                    #   owns the spawned process (cancel/unload/detach/kill on every failure path)
├── tests/                           # validator, agent-logic, controller-lifecycle and opt-in device tests (see "Tests")
└── agents/
    ├── dump_clean_header_v4.js      # RECOMMENDED. Adaptive: fast offset hook, event-driven
    │                                #   fallback to a scoped, block-level dynamic scan, structural
    │                                #   header validation, one central cleanup path. Takes its
    │                                #   config at runtime via `configure()`.
    └── legacy/                      # Superseded by v4 — kept for manual use / reference only
        ├── dump_clean_header_v2.js  # Dynamic-scan only (Stalker over il2cpp_init, checks every
        │                            #   register against the magic at every instruction) — never
        │                            #   goes stale, just slower.
        └── dump_clean_header_v3.js  # Hardcoded-offset only, no fallback — hooks straight into
                                     #   the point where the header has just been deobfuscated
                                     #   (x21 holds the clean pointer). Fastest option when you
                                     #   already trust the offset, but the offset needs to be
                                     #   re-derived every time the module changes.
```

## How it works

### Two strategies, one agent

The `v4` agent combines a fast hardcoded-offset hook (quick, but the offset
goes stale on every app update) with a dynamic Stalker scan (update-proof, but
slower):

- With `--offset`, it tries the fast hook first, with no Stalker overhead.
- If that offset fires but `x21` doesn't hold a valid header, or `il2cpp_init`
  returns without any validated header, the agent notices **by event, not by
  timer**, and the controller relaunches the app once with the full dynamic
  scan (`--no-retry` disables this, `--eager-scan` arms the full scan in the
  first run instead).
- Without an offset it goes straight to the dynamic scan.

The offset is a speed optimization, not a requirement, and it is passed in at
run time (`--offset`, delivered to the agent through its `configure()` RPC)
rather than edited into the script.

One trade-off to know about: with `--offset`, Stalker stays off until the fast
path has failed. A Stalker scan that starts in the middle of `il2cpp_init`
cannot be made complete, so after a failed offset the agent only does a
best-effort late scan and the controller then relaunches with a full scan from
`il2cpp_init` entry. If you'd rather have one launch and accept the slow scan,
use `--eager-scan`.

### Hook timing and header validation

- **Everything is armed up front.** Every hook — the offset hook *and* an
  `il2cpp_init` observer — is installed synchronously inside `configure()`,
  before the controller resumes the app, and nothing waits on a timer to get
  armed. The dynamic scan therefore starts from `il2cpp_init` entry and
  cannot miss the only moment it is needed.
- **The magic alone does not prove a header.** A pointer is accepted only
  after `validateHeader()` passes on the exact bytes that are returned: the
  whole `--header-size` window must be readable (checked against the process's
  mappings before reading, with a clear error otherwise), the version must be
  plausible, and the offset/size pairs must be consistent with the
  `Il2CppGlobalMetadataHeader` layout for that version (see *Technical notes*).
  A candidate that fails is remembered and re-checked later, because the
  buffer may still be getting written.
- **The controller validates again.** It checks the magic, prints the raw
  version field and runs the same structural checks before writing the output
  file, so what the legacy agents return is verified too.

### The dynamic scan

- **Scope** — only `UnityFramework` is instrumented (`--scan-scope module`,
  the default). `--scan-range START:END` narrows that to a routine you have
  already located (module-relative, hex, end exclusive); `--scan-scope all`
  instruments every module.
- **Granularity** — one callout per *basic block* (`--scan-mode block`, the
  default). `--scan-mode instruction` is the exhaustive per-instruction scan,
  e.g. as a baseline.
- **Registers** — in block mode only the registers a block actually *reads*
  are checked (from Frida's `Instruction.regsRead`; `w` registers map to `x`).
  If that information is unavailable, or in instruction mode, all of `x0-x28`
  are checked. The pointer prefilter does not allocate `NativePointer`s per
  check.

The limits of the scan: a pointer that is never held in a general-purpose
register while in-scope code runs (only in memory or a SIMD register) is
invisible to every mode; and in block mode a register the current block does
not read is not looked at until a later block reads it.

### Lifecycle and cleanup

- **One ending for every run.** The agent moves through explicit, forward-only
  phases (`idle -> waiting-module -> armed -> scanning -> done`). Every way of
  finishing — captured, failed, timeout, cancelled — goes through one
  `complete()` function that first marks the run done (so callbacks still in
  flight do nothing) and then releases **everything** in one place: the
  `il2cpp_init` and offset hooks, the module observer (a late load of
  `UnityFramework` cannot arm hooks after a timeout), the timeout timer, the
  Stalker threads and the deferred Stalker GC. The `cancel()` and `dispose()`
  RPC exports end in the same place (`dispose` is called by Frida when the
  script is unloaded).
- **Failures carry a reason.** An offset that cannot be hooked falls back to
  the scan at `il2cpp_init` entry; `Stalker.follow` failing, an exception
  inside a callback, or a rejected configuration end the run immediately; a
  timeout says where it got stuck (e.g. "UnityFramework was never loaded").
- **The controller owns the spawned process.** Whatever happens — failed run,
  crash, Ctrl+C, a script that fails to load, a rejected configuration — it
  cancels the agent, unloads the script, detaches and **kills the app it
  spawned**. Only a run that produced a header leaves the app running. Errors
  from attach/load/configure are reported as one line instead of a traceback,
  and Ctrl+C exits with status 130.

### Measuring the scan

`getStatus()` (printed by the controller as "Scan cost") reports how many
blocks were compiled/instrumented, how many callouts ran, how many register
checks they made, the scan duration and the time from `il2cpp_init` entry to the
header. To compare configurations on your own device, run the same target twice:

```bash
python dump_clean_header.py --target com.example.unityapp                                      # block / module
python dump_clean_header.py --target com.example.unityapp --scan-mode instruction --scan-scope all   # exhaustive baseline
```

`tests/test_agent.js` contains a synthetic cost model (counts of callouts and
register checks for the same trace under both configurations). It shows the
*shape* of the saving - callouts and register checks drop by well over an order
of magnitude in that model - but it is counts, not wall-clock time: the real
saving has to be measured on a device.

## Technical notes

- Standard post-deobfuscation magic: `0xFAB11BAF` (per the standard
  `Il2CppGlobalMetadataHeader` layout used by Il2CppDumper).
- What `validateHeader()` checks. The field table is taken from Il2CppDumper's
  `Il2CppGlobalMetadataHeader` (versions 16-31); the header size per version is
  derived from it (e.g. 264 bytes for v24.2, 256 for v27-v31).
  - Always fatal: fewer than 272 bytes, wrong magic, version outside 16-1000.
  - Fatal unless `--lenient`: a negative or int32-overflowing offset/size; the
    first table starting inside the header; a non-empty table pointing into the
    header; an empty strings / type definitions / methods / images /
    assemblies table; overlapping non-empty byte-range tables.
  - Warnings only: first table offset != header size, table offsets not
    ascending in struct order, gaps over 256 bytes between tables, a version
    newer than 31 (validated with the v31 layout).
  These are heuristics derived from the layout and from how Il2CppDumper reads
  the file, not a proof; they have only been exercised on synthetic headers.
- `v4`'s offset (whether from `--offset` or, in `v3`, the hardcoded
  `HOOK_OFFSET`) is a fixed location inside the current build's IL2CPP
  module — it needs to be re-derived (e.g. via ADRP cross-reference tracing
  in a disassembler) after an app update shifts it. With `v4` this is
  optional: without it, or when it's stale, the tool just falls back to the
  slower dynamic scan instead of failing outright.

## Tests

```bash
python -m unittest discover -s tests -v   # validator (Python + JS parity), controller flow + lifecycle; no frida needed
node --test tests/test_agent.js           # agent logic against a fake Frida runtime
```

The node tests use a small fake of `Process` / `Interceptor` / `Stalker` (with
a translation cache like Stalker's, so `transform()` runs once per block) and
check hook ordering, fallback decisions, scan scope/granularity/registers,
validation, and every ending of a run - captured, failed, timeout, cancel,
dispose - including that nothing (listener, observer, timer, followed thread)
is left behind. The Python tests drive `main()` against a fake `frida` module
and check what happens to the spawned process on success, failure, crash,
Ctrl+C, a script that fails to load and a rejected configuration, and that an
invalid header is never written as a result.

They do not tell you how a real device behaves; the real-target caveat in
**Status** still applies. For that there are opt-in end-to-end tests that run
the real tool against a real app you are allowed to test, and are skipped
unless you set `IL2CPP_RE_TARGET`:

```bash
IL2CPP_RE_TARGET=com.example.unityapp python -m unittest tests.test_device_integration -v
# optional: IL2CPP_RE_REMOTE, IL2CPP_RE_OFFSET (a good offset), IL2CPP_RE_STALE_OFFSET (a wrong one)
```

They check that a full scan writes a header that passes validation, that the
default (block/module) scan captures the same header as the exhaustive
(instruction/all) baseline and prints both cost lines, that a stale offset falls
back, and that a timeout fails cleanly without writing a file.

## License

Copyright (C) 2026 [ndhn27](https://github.com/ndhn27).

Licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`) — see [`LICENSE`](LICENSE) for the full text. In short: you
are free to use, study, modify and redistribute this project, but if you
distribute a modified version — or let users interact with one over a
network — you must make the complete corresponding source available under the
same license, and keep the copyright and license notices intact.

This software is provided without any warranty.
