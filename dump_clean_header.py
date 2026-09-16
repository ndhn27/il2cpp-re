"""
dump_clean_header.py
Spawns a target iOS app, loads a Frida agent, and makes a single blocking RPC
call that resolves the moment il2cpp_init finishes deobfuscating the shuffled
global-metadata header (or times out). Writes the clean, standard-layout
header bytes to a local file.

The app to target is NOT hardcoded - pass it via --target or the
TARGET_BUNDLE_ID env var. Nothing in this repo names or is specific to any
particular app/game; it works against any IL2CPP-based iOS app whose
metadata header you have the legal right to inspect (e.g. your own builds,
or apps you have explicit permission to analyze).

By default this uses agents/dump_clean_header_v4.js, which tries a fast
hardcoded-offset hook (if you pass --offset) and automatically falls back to
a slower but update-proof dynamic Stalker scan if the offset is missing,
stale, or never fires. You don't need a correct offset for this to work -
it's purely a speed optimization now.

Usage:
    python dump_clean_header.py --target com.example.unityapp
    # or
    TARGET_BUNDLE_ID=com.example.unityapp python dump_clean_header.py

    # with a known offset for the fast path (falls back automatically if stale)
    python dump_clean_header.py --target com.example.unityapp --offset 0xab6ad08
"""
import argparse
import os
import struct
import sys

import frida

REAL_MAGIC = 0xFAB11BAF  # standard post-deobfuscation magic (Il2CppDumper layout)


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
             "Use agents/dump_clean_header_v2.js for scan-only, or "
             "agents/dump_clean_header_v3.js for offset-only with no fallback.",
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
        help="Number of bytes to dump starting at the clean header pointer (default: 1024, "
             "generous headroom over the actual struct size - trim it however you parse the dump).",
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
    return args


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print("[agent]", message.get("payload"))


def verify_magic(header_bytes):
    """Sanity-check the dump: the first 4 bytes should be the standard
    post-deobfuscation magic. Also prints the raw version field (next 4
    bytes) for cross-referencing against Il2CppDumper's known version list -
    no version is inferred here to avoid guessing wrong."""
    if len(header_bytes) < 8:
        print("[!] Dump is too short to verify (<8 bytes) - can't check the magic.")
        return False
    magic, version = struct.unpack_from("<II", header_bytes, 0)
    if magic == REAL_MAGIC:
        print(f"[+] Magic OK (0x{magic:08X}). Raw version field: {version} (0x{version:08X}).")
        return True
    print(f"[!] Magic mismatch: got 0x{magic:08X}, expected 0x{REAL_MAGIC:08X}. "
          "The dump may be garbage - double check the offset/agent used.")
    return False


def main():
    args = parse_args()

    with open(args.agent, "r", encoding="utf-8") as f:
        source = f.read()

    device = frida.get_device_manager().add_remote_device(args.remote)

    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")
        if reason != "application-requested":
            print("    (target process crashed, was killed, or the connection was lost)")

    print(f"[*] Spawning {args.target}...")
    pid = device.spawn([args.target])
    session = device.attach(pid)
    session.on("detached", on_detached)

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    # Push runtime config into the agent, if it supports it (v4 does; v2/v3
    # self-start at load time and don't export `configure`, so this is a
    # no-op for them).
    try:
        script.exports_sync.configure({
            "offset": args.offset,
            "headerSize": args.header_size,
        })
    except Exception:
        pass

    device.resume(pid)
    print(f"[*] Spawned and resumed, pid={pid}")
    print(f"[*] Waiting for il2cpp_init to reach the header-deobfuscation point (up to {args.timeout}ms)...")

    try:
        header_bytes = script.exports_sync.wait_for_header(args.timeout)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - detaching...")
        session.detach()
        sys.exit(130)

    if not header_bytes:
        print("[!] Did not capture the header - see agent log above for details.")
        session.detach()
        sys.exit(1)

    verify_magic(header_bytes)

    with open(args.out, "wb") as out:
        out.write(header_bytes)
    print(f"[+] Wrote {len(header_bytes)} bytes to {args.out}")
    session.detach()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
