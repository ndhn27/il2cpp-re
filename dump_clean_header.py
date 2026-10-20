# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ndhn27

"""
dump_clean_header.py
Spawns a target iOS app, loads a Frida agent, and makes a single blocking RPC
call that resolves the moment il2cpp_init finishes deobfuscating the shuffled
global-metadata header (or fails/times out). Writes the clean, standard-layout
header bytes to a local file - but only after the dump passes a structural
check (magic, version and the offset/size table), not just the 4-byte magic.

The app to target is NOT hardcoded - pass it via --target or the
TARGET_BUNDLE_ID env var. Nothing in this repo names or is specific to any
particular app/game; it works against any IL2CPP-based iOS app whose
metadata header you have the legal right to inspect (e.g. your own builds,
or apps you have explicit permission to analyze).

By default this uses agents/dump_clean_header_v4.js. Without --offset it runs a
Stalker scan from il2cpp_init entry. With --offset it first tries a fast hook
(no Stalker); if that fails the run is retried once from scratch with the full
scan, unless --no-retry is given. --eager-scan arms the full scan in the very
first run instead (single launch, slower).

The scan only instruments UnityFramework, one callout per basic block
(--scan-scope / --scan-mode / --scan-range change that; see the README).

Whatever happens, the spawned process is not left behind: on a failed run, an
error, Ctrl+C or a crash the script cancels the agent, unloads it, detaches and
kills the app it spawned. Only after a validated header is the app left running.

Usage:
    python dump_clean_header.py --target com.example.unityapp
    # or
    TARGET_BUNDLE_ID=com.example.unityapp python dump_clean_header.py

    # with a known offset for the fast path (retries with a full scan if it fails)
    python dump_clean_header.py --target com.example.unityapp --offset 0xab6ad08
"""
import argparse
import os
import re
import struct
import sys
import time
from typing import List, NamedTuple, Optional

REAL_MAGIC = 0xFAB11BAF  # standard post-deobfuscation magic (Il2CppDumper layout)
MIN_HEADER_SIZE = 0x110  # largest known header layout (v24 / v24.1) = 272 bytes
MAX_HEADER_SIZE = 0x100000
VERSION_MIN = 16         # oldest layout Il2CppDumper supports
VERSION_MAX = 1000       # Il2CppDumper's own "not a metadata file" bound
KNOWN_VERSION_MAX = 31   # newest layout in HEADER_FIELDS
INT32_MAX = 0x7FFFFFFF
MAX_GAP_BYTES = 256      # padding between tables above this is suspicious (warning only)
KEY_TABLES = ("stringSize", "typeDefinitionsSize", "methodsSize", "imagesSize", "assembliesSize")

# (field name, min version, max version) in struct order; None = unbounded.
# Generated from Il2CppDumper's Il2CppGlobalMetadataHeader (MetadataClass.cs). After "sanity" and
# "version" every field comes as an (xOffset, xSize|xCount) pair. Keep identical to HEADER_FIELDS in
# agents/dump_clean_header_v4.js (tests/test_validate_header.py compares the two).
HEADER_FIELDS = [
    ('sanity', None, None),
    ('version', None, None),
    ('stringLiteralOffset', None, None),
    ('stringLiteralSize', None, None),
    ('stringLiteralDataOffset', None, None),
    ('stringLiteralDataSize', None, None),
    ('stringOffset', None, None),
    ('stringSize', None, None),
    ('eventsOffset', None, None),
    ('eventsSize', None, None),
    ('propertiesOffset', None, None),
    ('propertiesSize', None, None),
    ('methodsOffset', None, None),
    ('methodsSize', None, None),
    ('parameterDefaultValuesOffset', None, None),
    ('parameterDefaultValuesSize', None, None),
    ('fieldDefaultValuesOffset', None, None),
    ('fieldDefaultValuesSize', None, None),
    ('fieldAndParameterDefaultValueDataOffset', None, None),
    ('fieldAndParameterDefaultValueDataSize', None, None),
    ('fieldMarshaledSizesOffset', None, None),
    ('fieldMarshaledSizesSize', None, None),
    ('parametersOffset', None, None),
    ('parametersSize', None, None),
    ('fieldsOffset', None, None),
    ('fieldsSize', None, None),
    ('genericParametersOffset', None, None),
    ('genericParametersSize', None, None),
    ('genericParameterConstraintsOffset', None, None),
    ('genericParameterConstraintsSize', None, None),
    ('genericContainersOffset', None, None),
    ('genericContainersSize', None, None),
    ('nestedTypesOffset', None, None),
    ('nestedTypesSize', None, None),
    ('interfacesOffset', None, None),
    ('interfacesSize', None, None),
    ('vtableMethodsOffset', None, None),
    ('vtableMethodsSize', None, None),
    ('interfaceOffsetsOffset', None, None),
    ('interfaceOffsetsSize', None, None),
    ('typeDefinitionsOffset', None, None),
    ('typeDefinitionsSize', None, None),
    ('rgctxEntriesOffset', None, 24.1),
    ('rgctxEntriesCount', None, 24.1),
    ('imagesOffset', None, None),
    ('imagesSize', None, None),
    ('assembliesOffset', None, None),
    ('assembliesSize', None, None),
    ('metadataUsageListsOffset', 19.0, 24.5),
    ('metadataUsageListsCount', 19.0, 24.5),
    ('metadataUsagePairsOffset', 19.0, 24.5),
    ('metadataUsagePairsCount', 19.0, 24.5),
    ('fieldRefsOffset', 19.0, None),
    ('fieldRefsSize', 19.0, None),
    ('referencedAssembliesOffset', 20.0, None),
    ('referencedAssembliesSize', 20.0, None),
    ('attributesInfoOffset', 21.0, 27.2),
    ('attributesInfoCount', 21.0, 27.2),
    ('attributeTypesOffset', 21.0, 27.2),
    ('attributeTypesCount', 21.0, 27.2),
    ('attributeDataOffset', 29.0, None),
    ('attributeDataSize', 29.0, None),
    ('attributeDataRangeOffset', 29.0, None),
    ('attributeDataRangeSize', 29.0, None),
    ('unresolvedVirtualCallParameterTypesOffset', 22.0, None),
    ('unresolvedVirtualCallParameterTypesSize', 22.0, None),
    ('unresolvedVirtualCallParameterRangesOffset', 22.0, None),
    ('unresolvedVirtualCallParameterRangesSize', 22.0, None),
    ('windowsRuntimeTypeNamesOffset', 23.0, None),
    ('windowsRuntimeTypeNamesSize', 23.0, None),
    ('windowsRuntimeStringsOffset', 27.0, None),
    ('windowsRuntimeStringsSize', 27.0, None),
    ('exportedTypeDefinitionsOffset', 24.0, None),
    ('exportedTypeDefinitionsSize', 24.0, None),
]


class HeaderCheck(NamedTuple):
    ok: bool
    version: Optional[int]
    layout: Optional[float]
    header_bytes: Optional[int]
    errors: List[str]
    warnings: List[str]


def _layout_for(version, string_literal_offset):
    if version > KNOWN_VERSION_MAX:
        return float(KNOWN_VERSION_MAX)
    # Same disambiguation Il2CppDumper uses: v24 headers with the first table at 264 are v24.2+.
    if version == 24 and string_literal_offset == 264:
        return 24.2
    return float(version)


def _fields_for(layout):
    return [f for f in HEADER_FIELDS
            if (f[1] is None or layout >= f[1]) and (f[2] is None or layout <= f[2])]


def validate_header(data, lenient=False):
    """Structural check of a dumped Il2CppGlobalMetadataHeader (mirrors validateHeader() in the agent).

    Always fatal: buffer too short, wrong magic, implausible version.
    Structural problems are fatal unless `lenient`, in which case they become warnings:
      - a field pair is negative or its range overflows int32
      - the first table starts before the end of the header, or a non-empty table points into it
      - a table every real app has (strings, type definitions, methods, images, assemblies) is empty
      - two non-empty byte-range tables overlap
    Warnings only: first table offset != header size, table offsets not ascending in struct order,
    large gaps between tables, version newer than the known layouts.
    """
    errors: List[str] = []
    warnings: List[str] = []

    def fail():
        return HeaderCheck(False, None, None, None, errors, warnings)

    if data is None or len(data) < MIN_HEADER_SIZE:
        errors.append(f"need at least {MIN_HEADER_SIZE} bytes to validate, got {0 if data is None else len(data)}")
        return fail()

    words = struct.unpack_from("<" + "i" * (MIN_HEADER_SIZE // 4), data, 0)
    magic = words[0] & 0xFFFFFFFF
    if magic != REAL_MAGIC:
        errors.append(f"magic is 0x{magic:08x}, expected 0x{REAL_MAGIC:08x}")
        return fail()
    version = words[1]
    if version < VERSION_MIN or version > VERSION_MAX:
        errors.append(f"version {version} is outside the plausible range {VERSION_MIN}..{VERSION_MAX}")
        return fail()
    if version > KNOWN_VERSION_MAX:
        warnings.append(f"version {version} is newer than the known layouts ({VERSION_MIN}..{KNOWN_VERSION_MAX}); "
                        f"validating with the v{KNOWN_VERSION_MAX} layout")

    string_literal_offset = words[2] & 0xFFFFFFFF
    layout = _layout_for(version, string_literal_offset)
    fields = _fields_for(layout)
    header_bytes = len(fields) * 4
    layout_label = f"{layout:g}"
    structural: List[str] = []

    tables = []
    for i in range(2, len(fields) - 1, 2):
        off_name, size_name = fields[i][0], fields[i + 1][0]
        off, size = words[i], words[i + 1]
        is_bytes = size_name.endswith("Size")
        if off < 0 or size < 0:
            structural.append(f"{off_name}/{size_name} is negative (offset={off}, {'size' if is_bytes else 'count'}={size})")
        elif is_bytes and off + size > INT32_MAX:
            structural.append(f"{off_name}+{size_name} overflows int32 (offset={off}, size={size})")
        tables.append((off_name, size_name, off, size, is_bytes))

    if string_literal_offset < header_bytes:
        structural.append(f"stringLiteralOffset ({string_literal_offset}) is inside the {header_bytes}-byte v{layout_label} header")
    elif string_literal_offset != header_bytes:
        warnings.append(f"stringLiteralOffset ({string_literal_offset}) != expected v{layout_label} header size ({header_bytes})")

    for off_name, _, off, size, _ in tables:
        if size > 0 and 0 <= off < header_bytes:
            structural.append(f"{off_name} ({off}) points inside the {header_bytes}-byte header")

    for name in KEY_TABLES:
        for _, size_name, _, size, _ in tables:
            if size_name == name and size <= 0:
                structural.append(f"{name} is {size}; every real app has this table")

    ranges = sorted(
        (t for t in tables if t[4] and t[3] > 0 and t[2] >= 0 and t[2] + t[3] <= INT32_MAX),
        key=lambda t: t[2],
    )
    largest_gap = None
    for prev, cur in zip(ranges, ranges[1:]):
        gap = cur[2] - (prev[2] + prev[3])
        if gap < 0:
            structural.append(f"{prev[0]} [{prev[2]}, {prev[2] + prev[3]}) overlaps {cur[0]} at {cur[2]}")
        elif gap > MAX_GAP_BYTES and (largest_gap is None or gap > largest_gap[0]):
            largest_gap = (gap, prev, cur)
    if largest_gap:
        warnings.append(f"{largest_gap[0]}-byte gap between {largest_gap[1][0]} and {largest_gap[2][0]}")

    prev_off = -1
    for off_name, _, off, size, _ in tables:
        if size > 0 and off >= 0:
            if off < prev_off:
                warnings.append(f"table offsets are not ascending in struct order (first at {off_name})")
                break
            prev_off = off

    if structural:
        if lenient:
            warnings.extend(f"(lenient) {s}" for s in structural)
        else:
            errors.extend(structural)
    return HeaderCheck(not errors, version, layout, header_bytes, errors, warnings)


def parse_scan_range(text):
    """'0xa00000:0xa40000' -> (0xa00000, 0xa40000): module-relative byte offsets, end exclusive."""
    try:
        start_text, end_text = text.split(":")
        start, end = int(start_text, 0), int(end_text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected START:END as hex offsets, e.g. 0xa00000:0xa40000 (got {text!r})")
    if start < 0 or end <= start:
        raise argparse.ArgumentTypeError(f"need 0 <= START < END (got {text!r})")
    return start, end


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--target", "-t",
        default=os.environ.get("TARGET_BUNDLE_ID"),
        help="Bundle ID of the app to spawn (or set TARGET_BUNDLE_ID). Required.",
    )
    parser.add_argument(
        "--agent", "-a",
        default="agents/dump_clean_header_v4.js",
        help="Path to the Frida agent script to inject "
             "(default: agents/dump_clean_header_v4.js, the adaptive agent). "
             "Use agents/legacy/dump_clean_header_v2.js for scan-only, or "
             "agents/legacy/dump_clean_header_v3.js for offset-only with no fallback. "
             "The legacy agents only check the magic themselves; this script still validates what they return.",
    )
    parser.add_argument(
        "--offset",
        default=os.environ.get("HOOK_OFFSET"),
        help="Optional hex offset (e.g. 0xab6ad08) into UnityFramework for the fast-path hook. "
             "Only used by dump_clean_header_v4.js; ignored by v2/v3, which don't accept runtime "
             "config. If omitted, v4 goes straight to the dynamic scan.",
    )
    parser.add_argument(
        "--header-size", type=int, default=1024,
        help=f"Number of bytes to dump starting at the clean header pointer (default: 1024, "
             f"minimum {MIN_HEADER_SIZE}: generous headroom over the actual struct size - trim it however you "
             f"parse the dump). The whole range must be readable, otherwise the candidate is rejected.",
    )
    parser.add_argument(
        "--lenient", action="store_true",
        help="Accept a header that passes the magic/version checks but fails the structural checks "
             "(they are reported as warnings instead). Use it if a real header is rejected - e.g. a "
             "metadata version newer than the known layouts.",
    )
    parser.add_argument(
        "--eager-scan", action="store_true",
        help="With --offset, arm the full Stalker scan at il2cpp_init entry in the first run instead of "
             "only after the offset fails. Single launch, but il2cpp_init runs under Stalker until the "
             "header is found, so the offset no longer buys much speed.",
    )
    parser.add_argument(
        "--no-retry", action="store_true",
        help="Don't relaunch the app with a full scan when the offset fast path fails.",
    )
    parser.add_argument(
        "--scan-scope", choices=("module", "all"), default="module",
        help="Which code the Stalker scan instruments: 'module' (default) = only UnityFramework, "
             "'all' = every module (the old behaviour, much slower).",
    )
    parser.add_argument(
        "--scan-mode", choices=("block", "instruction"), default="block",
        help="'block' (default) = one callout per basic block, checking only the registers that block "
             "reads; 'instruction' = a callout after every instruction checking x0-x28 (exhaustive, slow; "
             "useful as a baseline when measuring).",
    )
    parser.add_argument(
        "--scan-range", type=parse_scan_range, default=None, metavar="START:END",
        help="Limit the scan to this module-relative range (hex, end exclusive), e.g. 0xa00000:0xa40000 - "
             "a routine you already located, for instance around 'foundAt' printed by an earlier run. "
             "Only with --scan-scope module.",
    )
    parser.add_argument(
        "--out", "-o",
        default="clean_header.bin",
        help="Where to write the dumped header bytes (default: clean_header.bin)",
    )
    parser.add_argument(
        "--remote",
        default=os.environ.get("FRIDA_REMOTE", "127.0.0.1:45861"),
        help="Remote frida-server address, e.g. after "
             "`pymobiledevice3 usbmux forward 45861 45861` (default: 127.0.0.1:45861)",
    )
    parser.add_argument(
        "--timeout", type=int, default=45000,
        help="Milliseconds to wait for the header before giving up (default: 45000)",
    )
    args = parser.parse_args()
    if not args.target:
        parser.error("no target specified - pass --target <bundle-id> or set TARGET_BUNDLE_ID")
    if not MIN_HEADER_SIZE <= args.header_size <= MAX_HEADER_SIZE:
        parser.error(f"--header-size must be between {MIN_HEADER_SIZE} and {MAX_HEADER_SIZE}")
    if args.scan_range is not None and args.scan_scope == "all":
        parser.error("--scan-range only applies with --scan-scope module")
    return args


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print("[agent]", message.get("payload"))


class CaptureError(Exception):
    """A run could not start or be set up (spawn/attach/load/configure/resume failed, or the v4 agent rejected
    its configuration). Not retried: another launch would fail the same way."""


CONFIGURE_RE = re.compile(r"\bconfigure\s*[:(]")


def build_config(args, offset):
    config = {
        "offset": offset,
        "headerSize": args.header_size,
        "lenient": args.lenient,
        "eagerScan": args.eager_scan,
        "scanMode": args.scan_mode,
        "scanScope": args.scan_scope,
    }
    if args.scan_range is not None:
        config["scanRange"] = [hex(args.scan_range[0]), hex(args.scan_range[1])]
    return config


def configure_agent(script, config, source):
    """Pushes the runtime config into the agent. Returns False for a legacy agent that has no configure().

    v4 installs ALL of its hooks inside this call, so they are in place before the process is resumed.
    The legacy v2/v3 agents self-start at load time and don't export `configure`; a v4 agent that REJECTS
    its configuration is an error, not a legacy agent, and aborts the run.
    """
    try:
        script.exports_sync.configure(config)
        return True
    except Exception as exc:
        if "unable to find method" in str(exc) or not CONFIGURE_RE.search(source):
            print(f"[i] configure() RPC not applied: {exc} (expected for the legacy v2/v3 agents)")
            return False
        raise CaptureError(f"the agent rejected its configuration: {exc}") from exc


def fetch_status(script):
    try:
        return script.exports_sync.get_status()
    except Exception:
        return None  # legacy agents don't export getStatus, or the script is already gone


def release(device, pid, session, script, kill):
    """Best-effort teardown, in the order that leaves nothing behind. Never raises."""
    if script is not None:
        if kill:
            try:
                script.exports_sync.cancel("controller is giving up")  # lets the agent free hooks/Stalker itself
            except Exception:
                pass
        try:
            script.unload()
        except Exception:
            pass
    if session is not None:
        try:
            session.detach()
        except Exception:
            pass
    if kill:
        try:
            device.kill(pid)
        except Exception:
            pass


def capture(device, source, args, offset):
    """One spawn -> inject -> wait cycle. Returns (pid, header_bytes or None, status dict or None, configured).

    This function owns the lifecycle of the spawned process: whatever goes wrong (agent error, crash,
    Ctrl+C, bad config), the agent is cancelled and unloaded, the session detached and the app we spawned
    is killed. Only a run that produced a header leaves the app running.
    """
    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")
        if reason != "application-requested":
            print("    (target process crashed, was killed, or the connection was lost)")

    print(f"[*] Spawning {args.target}...")
    try:
        pid = device.spawn([args.target])
    except Exception as exc:
        raise CaptureError(f"could not spawn {args.target}: {exc}") from exc
    session = script = None
    header_bytes = status = None
    configured = False
    try:
        session = device.attach(pid)
        session.on("detached", on_detached)

        script = session.create_script(source)
        script.on("message", on_message)
        script.load()

        configured = configure_agent(script, build_config(args, offset), source)

        device.resume(pid)
        print(f"[*] Spawned and resumed, pid={pid}")
        print(f"[*] Waiting for il2cpp_init to reach the header-deobfuscation point (up to {args.timeout}ms)...")

        try:
            header_bytes = script.exports_sync.wait_for_header(args.timeout)
        except KeyboardInterrupt:
            print("\n[!] Interrupted - cancelling the agent and cleaning up...")
            raise
        except Exception as exc:
            print(f"[!] wait_for_header() failed: {exc}")
            print("    (target process crashed, was killed, or the connection was lost)")
            header_bytes = None

        status = fetch_status(script)
    except CaptureError:
        raise
    except Exception as exc:  # attach / load / resume failed: report it cleanly (the finally still cleans up)
        raise CaptureError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        release(device, pid, session, script, kill=not header_bytes)
    return pid, header_bytes, status, configured


def print_status(status):
    if not status:
        return
    print(f"[*] Agent status: phase={status.get('phase')}, outcome={status.get('outcome')}, method={status.get('method')}, "
          f"reason={status.get('reason')}, offsetFired={status.get('offsetFired')}, il2cpp_init entered/returned="
          f"{status.get('initEntered')}/{status.get('initReturned')}")
    for warning in status.get("warnings") or []:
        print(f"[~] validation warning (agent): {warning}")
    stats = status.get("stats") or {}
    if stats.get("blocksCompiled") or stats.get("calloutRuns"):
        scan = status.get("scan") or {}
        print(f"[*] Scan cost: mode={scan.get('mode')}, scope={scan.get('scope')}, "
              f"blocks instrumented/compiled={stats.get('blocksInstrumented')}/{stats.get('blocksCompiled')}, "
              f"callouts={stats.get('calloutRuns')}, register checks={stats.get('regChecks')}, "
              f"scan time={stats.get('scanMs')} ms, il2cpp_init entry -> done={stats.get('msFromInitEntry')} ms")
    found = status.get("foundAt")
    if found:
        print(f"[i] The header pointer was seen in {found.get('reg')} at UnityFramework+{found.get('pcOffset')}. "
              f"A later scan can be limited to that routine with --scan-range (a few KB around it); "
              f"if the register is x21 the offset may also work with --offset (verify it first).")


def run_capture(device, source, args, offset):
    try:
        return capture(device, source, args, offset)
    except CaptureError as exc:
        print(f"[!] {exc}")
        sys.exit(1)


def main():
    try:
        run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)


def run():
    args = parse_args()
    import frida  # imported here so the validator above can be used (and tested) without frida installed

    with open(args.agent, "r", encoding="utf-8") as f:
        source = f.read()

    device = frida.get_device_manager().add_remote_device(args.remote)

    pid, header_bytes, status, configured = run_capture(device, source, args, args.offset)
    print_status(status)

    can_retry = bool(args.offset) and configured and not args.eager_scan and not args.no_retry
    if not header_bytes and can_retry:
        # capture() already killed the failed run's process.
        print("[!] Offset fast path did not produce a validated header - relaunching with the full dynamic scan.")
        time.sleep(1.0)
        pid, header_bytes, status, configured = run_capture(device, source, args, None)
        print_status(status)

    if not header_bytes:
        print("[!] Did not capture the header - see agent log above for details.")
        sys.exit(1)

    check = validate_header(header_bytes, lenient=args.lenient)
    for warning in check.warnings:
        print(f"[~] validation warning: {warning}")
    if not check.ok:
        rejected = os.path.splitext(args.out)[0] + ".rejected.bin"
        with open(rejected, "wb") as out:
            out.write(header_bytes)
        print("[!] The captured bytes failed validation, so they were NOT written to " + args.out + ":")
        for error in check.errors:
            print("    -", error)
        print(f"    Raw bytes kept in {rejected} for inspection. If this really is the header "
              f"(e.g. a metadata version newer than the known layouts), re-run with --lenient.")
        sys.exit(2)

    print(f"[+] Header OK: version {check.version}, layout v{check.layout:g} ({check.header_bytes}-byte struct), "
          f"magic 0x{REAL_MAGIC:08X}.")
    with open(args.out, "wb") as out:
        out.write(header_bytes)
    print(f"[+] Wrote {len(header_bytes)} bytes to {args.out}")


if __name__ == "__main__":
    main()
