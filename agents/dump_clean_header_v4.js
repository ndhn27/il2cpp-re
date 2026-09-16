// dump_clean_header_v4.js
// Adaptive agent that merges v2 (dynamic Stalker scan) and v3 (hardcoded
// offset hook) into a single strategy:
//
//   1. If a hook offset was supplied via configure(), attach directly to it
//      (fast path, same technique as v3). The moment it fires, the captured
//      pointer's first 4 bytes are checked against the real
//      Il2CppGlobalMetadataHeader magic (0xFAB11BAF). If it matches, we're
//      done - this is the cheapest and quickest route.
//   2. If the offset hook fires but the magic DOESN'T match (stale offset
//      after a game update), or if it simply never fires within
//      OFFSET_FALLBACK_MS, the agent automatically falls back to the
//      Stalker-based dynamic scan from v2: it single-steps through
//      il2cpp_init and callouts at every instruction, checking every
//      general-purpose register for a pointer whose first 4 bytes match the
//      magic. This never goes stale, it just costs more time.
//   3. If no offset is supplied at all, the agent skips straight to the
//      dynamic scan.
//
// This means the offset in agents/dump_clean_header_v3.js (or --offset on
// the CLI) is now an optional speed optimization, not a hard requirement -
// the tool keeps working across app updates without needing the offset
// re-derived every time, it just gets slower until someone re-derives it.
//
// Configuration is pushed in at runtime via the `configure` RPC export
// (called by dump_clean_header.py right after the script loads and before
// the target process is resumed), so nothing here is hardcoded to a
// specific app, offset, or build.

const REAL_MAGIC = 0xFAB11BAF;      // standard post-deobfuscation magic (Il2CppDumper layout)
const DEFAULT_HEADER_SIZE = 1024;   // generous upper bound; trimmed by whoever parses the dump
const OFFSET_FALLBACK_MS = 6000;    // grace period for the fast path before we also start scanning
const SCAN_TIMEOUT_MS = 20000;      // hard timeout for the dynamic scan itself

const CONFIG = {
    offset: null,             // NativePointer offset into the module, or null
    headerSize: DEFAULT_HEADER_SIZE,
};

let started = false;
let resolved = false;
let scanInstalled = false;
let resolveHeader = null;
const headerPromise = new Promise((resolve) => {
    resolveHeader = resolve;
});

function finish(bytes, method) {
    if (resolved) return;
    resolved = true;
    if (bytes) {
        console.log(`[+] Clean header captured via the ${method} path (${bytes.byteLength} bytes).`);
    } else {
        console.log(`[!] ${method} path ended without a header.`);
    }
    resolveHeader(bytes);
}

function looksLikeHeader(ptr) {
    try {
        return ptr.readU32() === REAL_MAGIC;
    } catch (e) {
        return false; // unreadable -> definitely not a valid pointer here
    }
}

function main() {
    let mod;
    try {
        mod = Process.getModuleByName("UnityFramework");
        installHooks(mod);
    } catch (e) {
        console.log("[i] UnityFramework not loaded yet - waiting on the module observer...");
        const observer = Process.attachModuleObserver({
            onAdded(m) {
                if (m.name === "UnityFramework") {
                    observer.detach();
                    installHooks(m);
                }
            },
        });
    }
}

function installHooks(mod) {
    if (CONFIG.offset) {
        installOffsetHook(mod);
    } else {
        console.log("[i] No offset configured - going straight to the dynamic Stalker scan.");
        installScanHook(mod);
    }
}

function installOffsetHook(mod) {
    const hookAddr = mod.base.add(CONFIG.offset);
    console.log("[+] Fast path: hooking hardcoded offset at", hookAddr);

    const listener = Interceptor.attach(hookAddr, {
        onEnter() {
            try {
                const cleanPtr = this.context.x21; // holds the clean header pointer right after deobfuscation
                if (looksLikeHeader(cleanPtr)) {
                    const bytes = cleanPtr.readByteArray(CONFIG.headerSize);
                    listener.detach();
                    finish(bytes, "fast-offset");
                } else {
                    console.log("[!] Offset fired but the magic didn't match (stale offset after an app update?) - falling back to the dynamic scan.");
                    listener.detach();
                    installScanHook(mod);
                }
            } catch (e) {
                console.log("[!] Offset hook threw:", e.message, "- falling back to the dynamic scan.");
                listener.detach();
                installScanHook(mod);
            }
        },
    });

    // Safety net: the offset hook might simply never fire (wrong address,
    // code path not taken on this run, etc). If nothing has resolved after
    // OFFSET_FALLBACK_MS, start the dynamic scan alongside it.
    setTimeout(() => {
        if (!resolved) {
            console.log(`[!] No hit on the hardcoded offset after ${OFFSET_FALLBACK_MS}ms - starting the dynamic scan as a fallback (offset hook stays active too).`);
            installScanHook(mod);
        }
    }, OFFSET_FALLBACK_MS);
}

function installScanHook(mod) {
    if (scanInstalled) return;
    scanInstalled = true;

    let initAddr;
    try {
        initAddr = mod.getExportByName("il2cpp_init");
    } catch (e) {
        console.log("[!] Could not find the il2cpp_init export - need a different hook point for this build.");
        finish(null, "dynamic-scan");
        return;
    }
    console.log("[+] il2cpp_init @", initAddr);

    const timer = setTimeout(() => {
        if (!resolved) {
            console.log(`[!] Dynamic scan timed out after ${SCAN_TIMEOUT_MS}ms without finding a header.`);
            finish(null, "dynamic-scan");
        }
    }, SCAN_TIMEOUT_MS);

    Interceptor.attach(initAddr, {
        onEnter() {
            const tid = Process.getCurrentThreadId();
            console.log("[+] Entered il2cpp_init, starting Stalker scan on thread", tid);

            Stalker.follow(tid, {
                transform(iterator) {
                    let instr;
                    while ((instr = iterator.next()) !== null) {
                        iterator.keep();
                        if (resolved) continue;

                        iterator.putCallout((context) => {
                            if (resolved) return;
                            const regs = [
                                "x0", "x1", "x2", "x3",
                                "x19", "x20", "x21", "x22", "x23", "x24",
                            ];
                            for (const r of regs) {
                                const v = context[r];
                                if (v && !v.isNull() && looksLikeHeader(v)) {
                                    clearTimeout(timer);
                                    console.log(`[+] Clean header found in ${r} =`, v);
                                    const bytes = v.readByteArray(CONFIG.headerSize);
                                    finish(bytes, "dynamic-scan");
                                    Stalker.unfollow(tid);
                                    return;
                                }
                            }
                        });
                    }
                },
            });
        },
    });

    console.log("[+] Hook + Stalker installed. Waiting for il2cpp_init to reach the deobfuscated header...");
}

rpc.exports = {
    // Called by the controller right after script.load() and before the
    // target process is resumed, so this always runs before il2cpp_init
    // executes.
    configure: function (cfg) {
        if (cfg) {
            if (cfg.offset !== undefined && cfg.offset !== null && cfg.offset !== "") {
                CONFIG.offset = ptr(cfg.offset);
            }
            if (cfg.headerSize) {
                CONFIG.headerSize = cfg.headerSize;
            }
        }
        console.log(
            "[i] Config received: offset=" + (CONFIG.offset ? CONFIG.offset : "none (dynamic scan only)") +
            ", headerSize=" + CONFIG.headerSize
        );
        if (!started) {
            started = true;
            main();
        }
    },

    waitForHeader: function (timeoutMs) {
        timeoutMs = timeoutMs || 30000;
        // If the controller never calls configure() (e.g. an older
        // controller script), start with the dynamic-scan-only path so the
        // agent still works standalone.
        if (!started) {
            started = true;
            main();
        }
        return new Promise((resolve) => {
            const timer = setTimeout(() => {
                console.log("[!] Timed out waiting for header");
                resolve(null);
            }, timeoutMs);
            headerPromise.then((bytes) => {
                clearTimeout(timer);
                resolve(bytes);
            });
        });
    },
};
