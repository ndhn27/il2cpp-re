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

## What's new in this version

The original tool had two separate agents with opposite trade-offs: a
hardcoded-offset hook (fast, but breaks on every app update until the offset
is re-derived) and a dynamic Stalker scan (update-proof, but slower). This
version adds a third agent, **v4**, that merges the two:

- If you give it an offset (`--offset`), it tries the fast hook first.
- If that offset fires but the captured pointer's magic doesn't match, or it
  never fires within a few seconds, it **automatically falls back** to the
  dynamic scan — no manual intervention, no re-running with a different
  agent.
- If you don't give it an offset at all, it skips straight to the dynamic
  scan.

`v4` is now the default agent. The offset is a nice-to-have speed
optimization, not a requirement. The older `v2` and `v3` agents have moved to
`agents/legacy/` so `agents/` only shows the one you should use.

Also new: the offset is passed in at run time via `--offset` / an RPC call
into the agent, instead of requiring you to hand-edit the `HOOK_OFFSET`
constant in the script; the controller verifies the dumped header's magic
(and prints the raw version field) before writing the output file; the
default dump size was bumped from 512 to 1024 bytes for headroom on newer
IL2CPP metadata layouts; and Ctrl+C now detaches cleanly instead of dumping
a Python traceback.

## Layout

```
il2cpp-re/
├── LICENSE                          # GNU AGPL v3.0
├── README.md
├── requirements.txt
├── .gitignore
├── dump_clean_header.py             # controller: spawn app, load agent, wait for the RPC to return the header
└── agents/
    ├── dump_clean_header_v4.js      # RECOMMENDED. Adaptive: fast offset hook with automatic
    │                                #   fallback to the dynamic scan. Takes its offset at
    │                                #   runtime via `configure()`.
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

# Force the legacy scan-only or offset-only agents
python dump_clean_header.py --target com.example.unityapp --agent agents/legacy/dump_clean_header_v2.js
python dump_clean_header.py --target com.example.unityapp --agent agents/legacy/dump_clean_header_v3.js
```

The script spawns the target app, injects the agent, resumes the process,
and waits up to 45s (adjustable with `--timeout`) for `il2cpp_init` to reach
the point where the header has been fully deobfuscated. The result is
written to `clean_header.bin` (adjustable with `--out`) and its magic is
verified before writing.

## Technical notes

- Standard post-deobfuscation magic: `0xFAB11BAF` (per the standard
  `Il2CppGlobalMetadataHeader` layout used by Il2CppDumper).
- `v4`'s offset (whether from `--offset` or, in `v3`, the hardcoded
  `HOOK_OFFSET`) is a fixed location inside the current build's IL2CPP
  module — it needs to be re-derived (e.g. via ADRP cross-reference tracing
  in a disassembler) after an app update shifts it. With `v4` this is now
  optional: without it, or when it's stale, the tool just falls back to the
  slower dynamic scan instead of failing outright.

## License

Copyright (C) 2026 [ndhn27](https://github.com/ndhn27).

Licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`) — see [`LICENSE`](LICENSE) for the full text. In short: you
are free to use, study, modify and redistribute this project, but if you
distribute a modified version — or let users interact with one over a
network — you must make the complete corresponding source available under the
same license, and keep the copyright and license notices intact.

This software is provided without any warranty.
