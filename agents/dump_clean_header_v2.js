// dump_clean_header_v2.js
// No hardcoded offset. Instead: hook il2cpp_init, use Stalker to single-step
// through every instruction in the function, and at each instruction check
// whether any register currently points to memory whose first 4 bytes match
// the standard post-deobfuscation Il2CppGlobalMetadataHeader magic
// (0xFAB11BAF). On a match -> that's the clean header, regardless of what
// offset it happens to live at in the current build.
//
// Trade-off vs. the hardcoded-offset version: this never goes stale when the
// game updates (as long as the deobfuscation algorithm itself doesn't
// change, only where the code for it lives), but it's slower because it has
// to "call out" to JS on every instruction inside il2cpp_init. That only
// happens once at app startup, so the cost is acceptable.
//
// NOTE: dump_clean_header_v4.js merges this scan with the offset-hook
// approach (falling back to this automatically when the offset is stale or
// missing) and is the recommended default agent. This file is kept for
// scan-only / manual use.

const REAL_MAGIC = 0xFAB11BAF; // standard post-deobfuscation magic (per Il2CppDumper)
const HEADER_SIZE = 512;       // kept from the original version, wide enough for the header
const SCAN_TIMEOUT_MS = 15000; // avoid hanging forever if nothing is found

let resolveHeader = null;
const headerPromise = new Promise((resolve) => {
    resolveHeader = resolve;
});

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
        installStalkerScan(mod);
    } catch (e) {
        console.log("[i] UnityFramework not loaded yet - waiting on the module observer...");
        const observer = Process.attachModuleObserver({
            onAdded(m) {
                if (m.name === "UnityFramework") {
                    observer.detach();
                    installStalkerScan(m);
                }
            },
        });
    }
}

function installStalkerScan(mod) {
    let initAddr;
    try {
        initAddr = mod.getExportByName("il2cpp_init");
    } catch (e) {
        console.log("[!] Could not find the il2cpp_init export - report this, a different hook point is needed for this build.");
        resolveHeader(null);
        return;
    }
    console.log("[+] il2cpp_init @", initAddr);

    let found = false;
    const timer = setTimeout(() => {
        if (!found) {
            console.log("[!] Timed out (" + SCAN_TIMEOUT_MS + "ms) without finding the header.");
            resolveHeader(null);
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
                        if (found) continue;

                        iterator.putCallout((context) => {
                            if (found) return;
                            const regs = [
                                "x0", "x1", "x2", "x3",
                                "x19", "x20", "x21", "x22", "x23", "x24",
                            ];
                            for (const r of regs) {
                                const v = context[r];
                                if (v && !v.isNull() && looksLikeHeader(v)) {
                                    found = true;
                                    clearTimeout(timer);
                                    console.log(`[+] Clean header found in ${r} =`, v);
                                    const bytes = v.readByteArray(HEADER_SIZE);
                                    resolveHeader(bytes);
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
    waitForHeader: function (timeoutMs) {
        timeoutMs = timeoutMs || 30000;
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

main();
