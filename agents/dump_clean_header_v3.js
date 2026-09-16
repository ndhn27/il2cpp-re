// dump_clean_header_v3.js
// Same idea as the original version, just with HOOK_OFFSET pointed at the
// location re-derived with relocate_offset.py for the current
// UnityFramework build.
//
// NOTE: dump_clean_header_v4.js does everything this file does, but adds an
// automatic fallback to the dynamic Stalker scan (from v2) when the offset
// is stale or wrong, and takes the offset at runtime via the `configure` RPC
// call instead of requiring a source edit. It's the recommended default
// agent. This file is kept for offset-only / manual use, or when you want
// the absolute fastest single-shot hook with no fallback logic at all.

const HOOK_OFFSET = 0xab6ad08;  // right after "mov x21, x0" - x21 holds the clean header pointer
const HEADER_SIZE = 512;

let resolveHeader = null;
const headerPromise = new Promise((resolve) => {
    resolveHeader = resolve;
});

function main() {
    let mod;
    try {
        mod = Process.getModuleByName("UnityFramework");
        installHook(mod);
    } catch (e) {
        console.log("[i] UnityFramework not loaded yet - waiting on the module observer...");
        const observer = Process.attachModuleObserver({
            onAdded(m) {
                if (m.name === "UnityFramework") {
                    observer.detach();
                    installHook(m);
                }
            },
        });
    }
}

function installHook(mod) {
    const hookAddr = mod.base.add(HOOK_OFFSET);
    console.log("[+] Hooking deobfuscation completion point at", hookAddr);

    const listener = Interceptor.attach(hookAddr, {
        onEnter(args) {
            try {
                const cleanPtr = this.context.x21;
                console.log("[+] Clean deobfuscated header buffer captured at", cleanPtr);
                const bytes = cleanPtr.readByteArray(HEADER_SIZE);
                resolveHeader(bytes);
            } catch (e) {
                console.log("[!] Error capturing header:", e.message);
                resolveHeader(null);
            }
            listener.detach();
        },
    });

    console.log("[+] Hook installed. Waiting for il2cpp_init to reach the deobfuscation point...");
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
