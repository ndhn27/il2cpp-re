// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ndhn27

// dump_clean_header_v4.js
// Adaptive agent that merges v2 (dynamic Stalker scan) and v3 (hardcoded
// offset hook) into a single strategy.
//
// Everything that can observe il2cpp_init is installed synchronously from
// configure(), i.e. BEFORE the controller resumes the target - nothing here
// depends on a timer to get armed, so the fallback can never be installed
// after il2cpp_init has already run.
//
//   * No offset (or eagerScan): the il2cpp_init hook starts a Stalker scan on
//     entry.
//   * Offset given (default): the offset hook gets the first shot with no
//     Stalker overhead. The il2cpp_init hook is still installed up front and
//     drives the fallback by EVENTS, not timers:
//       - offset fires but x21 does not hold a valid header  -> a late
//         Stalker scan starts on that same thread (best effort: it only sees
//         the rest of il2cpp_init), and
//       - il2cpp_init returns without a validated header      -> the agent
//         re-checks every candidate it has seen and then fails immediately,
//         so the controller can respawn with a full scan from il2cpp_init
//         entry (a scan that starts mid-init cannot be made complete).
//     eagerScan:true trades speed for a single run: the full scan is armed at
//     il2cpp_init entry even when an offset is configured.
//
// What the Stalker scan costs, and how it is kept down
// ----------------------------------------------------
// The expensive part of a scan is not Stalker itself but the JS callout that
// runs for every instrumented spot. Three knobs shrink that cost:
//   scanScope  "module" (default) only instruments code inside UnityFramework;
//              "all" instruments every module (the old behaviour). `scanRange`
//              [lo, hi) (module-relative) narrows "module" further to a routine
//              you already located - e.g. around `foundAt` from an earlier run.
//   scanMode   "block" (default) puts ONE callout at the entry of each basic
//              block; "instruction" puts one after every instruction (the old
//              behaviour, kept for A/B measurements and as an exhaustive mode).
//   registers  in block mode only the registers a block actually READS are
//              checked (from Instruction.regsRead, x0-x28); if Frida does not
//              provide that, all of x0-x28 are checked. Instruction mode always
//              checks x0-x28. The old scan only looked at x0-x3 and x19-x24.
// A pointer that is never held in a general-purpose register while in-scope code
// runs (only in memory or a SIMD register) cannot be seen by any of these modes.
// getStatus().stats exposes counters (blocks, callouts, register checks, time) so
// the before/after cost can be measured on a real device.
//
// A pointer is only accepted as "the clean header" after validateHeader()
// passes on the exact bytes that are returned (not just the 4-byte magic):
// the whole requested window must be readable, the version must be plausible
// and the (offset, size) pairs must be consistent with the
// Il2CppGlobalMetadataHeader layout. See validateHeader() for the checks.
//
// Lifecycle
// ---------
// The agent moves through explicit, forward-only phases:
//     idle -> waiting-module -> armed -> scanning -> done
// and every way of finishing (captured, failed, timeout, cancelled) goes through
// the single complete() function, which first marks the run done (so every
// callback bails out), then releases EVERYTHING in one place: Interceptor
// listeners, the module observer, the timeout timer, Stalker threads and the
// deferred Stalker GC. rpc.exports.cancel() and rpc.exports.dispose() (called by
// Frida when the script is unloaded) end in the same place.
//
// Configuration is pushed in at runtime via the `configure` RPC export.

const TARGET_MODULE = "UnityFramework";
const REAL_MAGIC = 0xFAB11BAF;      // standard post-deobfuscation magic (Il2CppDumper layout)
const DEFAULT_HEADER_SIZE = 1024;   // generous upper bound; trimmed by whoever parses the dump
const MIN_HEADER_SIZE = 0x110;      // largest known header layout (v24 / v24.1) = 272 bytes
const MAX_HEADER_SIZE = 0x100000;
const VERSION_MIN = 16;             // oldest layout Il2CppDumper supports
const VERSION_MAX = 1000;           // Il2CppDumper's own "not a metadata file" bound
const KNOWN_VERSION_MAX = 31;       // newest layout in the table below
const INT32_MAX = 0x7FFFFFFF;
const MAX_GAP_BYTES = 256;          // padding between tables above this is suspicious (warning only)
const KEY_TABLES = ["stringSize", "typeDefinitionsSize", "methodsSize", "imagesSize", "assembliesSize"];

const RECHECK_EVERY = 4096;         // scan callouts before a rejected candidate is validated again
const MAX_CANDIDATES = 32;
const MAX_LOGGED_REJECTIONS = 20;
const GC_DELAY_MS = 200;

// x0..x28. x29 (fp), x30 (lr) and sp never hold the metadata buffer in practice.
const ALL_REGS = Array.from({ length: 29 }, (_, i) => "x" + i);
const MIN_PTR = ptr(0x10000);
const MAX_PTR = ptr("0x7fffffffffff");
const SCAN_MODES = ["block", "instruction"];
const SCAN_SCOPES = ["module", "all"];
const PHASES = ["idle", "waiting-module", "armed", "scanning", "done"];

// [fieldName, minVersion, maxVersion] in struct order (null = unbounded).
// Generated from Il2CppDumper's Il2CppGlobalMetadataHeader (MetadataClass.cs).
// After "sanity" and "version" every field comes as an (xOffset, xSize|xCount) pair.
// The table must stay valid JSON - the Python controller carries the same table
// and tests/ checks that both copies match.
const HEADER_FIELDS = [
    ["sanity", null, null],
    ["version", null, null],
    ["stringLiteralOffset", null, null],
    ["stringLiteralSize", null, null],
    ["stringLiteralDataOffset", null, null],
    ["stringLiteralDataSize", null, null],
    ["stringOffset", null, null],
    ["stringSize", null, null],
    ["eventsOffset", null, null],
    ["eventsSize", null, null],
    ["propertiesOffset", null, null],
    ["propertiesSize", null, null],
    ["methodsOffset", null, null],
    ["methodsSize", null, null],
    ["parameterDefaultValuesOffset", null, null],
    ["parameterDefaultValuesSize", null, null],
    ["fieldDefaultValuesOffset", null, null],
    ["fieldDefaultValuesSize", null, null],
    ["fieldAndParameterDefaultValueDataOffset", null, null],
    ["fieldAndParameterDefaultValueDataSize", null, null],
    ["fieldMarshaledSizesOffset", null, null],
    ["fieldMarshaledSizesSize", null, null],
    ["parametersOffset", null, null],
    ["parametersSize", null, null],
    ["fieldsOffset", null, null],
    ["fieldsSize", null, null],
    ["genericParametersOffset", null, null],
    ["genericParametersSize", null, null],
    ["genericParameterConstraintsOffset", null, null],
    ["genericParameterConstraintsSize", null, null],
    ["genericContainersOffset", null, null],
    ["genericContainersSize", null, null],
    ["nestedTypesOffset", null, null],
    ["nestedTypesSize", null, null],
    ["interfacesOffset", null, null],
    ["interfacesSize", null, null],
    ["vtableMethodsOffset", null, null],
    ["vtableMethodsSize", null, null],
    ["interfaceOffsetsOffset", null, null],
    ["interfaceOffsetsSize", null, null],
    ["typeDefinitionsOffset", null, null],
    ["typeDefinitionsSize", null, null],
    ["rgctxEntriesOffset", null, 24.1],
    ["rgctxEntriesCount", null, 24.1],
    ["imagesOffset", null, null],
    ["imagesSize", null, null],
    ["assembliesOffset", null, null],
    ["assembliesSize", null, null],
    ["metadataUsageListsOffset", 19.0, 24.5],
    ["metadataUsageListsCount", 19.0, 24.5],
    ["metadataUsagePairsOffset", 19.0, 24.5],
    ["metadataUsagePairsCount", 19.0, 24.5],
    ["fieldRefsOffset", 19.0, null],
    ["fieldRefsSize", 19.0, null],
    ["referencedAssembliesOffset", 20.0, null],
    ["referencedAssembliesSize", 20.0, null],
    ["attributesInfoOffset", 21.0, 27.2],
    ["attributesInfoCount", 21.0, 27.2],
    ["attributeTypesOffset", 21.0, 27.2],
    ["attributeTypesCount", 21.0, 27.2],
    ["attributeDataOffset", 29.0, null],
    ["attributeDataSize", 29.0, null],
    ["attributeDataRangeOffset", 29.0, null],
    ["attributeDataRangeSize", 29.0, null],
    ["unresolvedVirtualCallParameterTypesOffset", 22.0, null],
    ["unresolvedVirtualCallParameterTypesSize", 22.0, null],
    ["unresolvedVirtualCallParameterRangesOffset", 22.0, null],
    ["unresolvedVirtualCallParameterRangesSize", 22.0, null],
    ["windowsRuntimeTypeNamesOffset", 23.0, null],
    ["windowsRuntimeTypeNamesSize", 23.0, null],
    ["windowsRuntimeStringsOffset", 27.0, null],
    ["windowsRuntimeStringsSize", 27.0, null],
    ["exportedTypeDefinitionsOffset", 24.0, null],
    ["exportedTypeDefinitionsSize", 24.0, null]
];

// ---------------------------------------------------------------------------
// Header validation (pure: only needs an ArrayBuffer, no Frida APIs)
// ---------------------------------------------------------------------------

function hex(n) {
    return "0x" + (n >>> 0).toString(16);
}

function layoutFor(version, stringLiteralOffset) {
    if (version > KNOWN_VERSION_MAX) return KNOWN_VERSION_MAX;
    // Same disambiguation Il2CppDumper uses: v24 headers with the first table at 264 are v24.2+.
    if (version === 24 && stringLiteralOffset === 264) return 24.2;
    return version;
}

function fieldsFor(layout) {
    return HEADER_FIELDS.filter((f) => (f[1] === null || layout >= f[1]) && (f[2] === null || layout <= f[2]));
}

// Returns { ok, version, layout, headerBytes, errors[], warnings[] }.
//
// Always fatal: buffer too short, wrong magic, implausible version.
// Structural problems are fatal unless `lenient` is set, in which case they are
// reported as warnings:
//   - a field pair is negative or its range overflows int32
//   - the first table starts before the end of the header, or a non-empty table points into it
//   - a table every real app has (strings, type definitions, methods, images, assemblies) is empty
//   - two non-empty byte-range tables overlap
// Warnings only (never fatal): first table offset != header size, table offsets not ascending
// in struct order, large gaps between tables, version newer than the known layouts.
function validateHeader(buf, lenient) {
    const errors = [];
    const warnings = [];
    const fail = () => ({ ok: false, version: null, layout: null, headerBytes: null, errors, warnings });

    if (buf === null || buf === undefined || buf.byteLength < MIN_HEADER_SIZE) {
        errors.push(`need at least ${MIN_HEADER_SIZE} bytes to validate, got ${buf ? buf.byteLength : 0}`);
        return fail();
    }
    const dv = new DataView(buf);
    const u32 = (i) => dv.getUint32(i * 4, true);
    const i32 = (i) => dv.getInt32(i * 4, true);

    if (u32(0) !== REAL_MAGIC) {
        errors.push(`magic is ${hex(u32(0))}, expected ${hex(REAL_MAGIC)}`);
        return fail();
    }
    const version = i32(1);
    if (version < VERSION_MIN || version > VERSION_MAX) {
        errors.push(`version ${version} is outside the plausible range ${VERSION_MIN}..${VERSION_MAX}`);
        return fail();
    }
    if (version > KNOWN_VERSION_MAX) {
        warnings.push(`version ${version} is newer than the known layouts (${VERSION_MIN}..${KNOWN_VERSION_MAX}); validating with the v${KNOWN_VERSION_MAX} layout`);
    }

    const stringLiteralOffset = u32(2);
    const layout = layoutFor(version, stringLiteralOffset);
    const fields = fieldsFor(layout);
    const headerBytes = fields.length * 4;
    const structural = [];

    const tables = [];
    for (let i = 2; i + 1 < fields.length; i += 2) {
        const offName = fields[i][0];
        const sizeName = fields[i + 1][0];
        const off = i32(i);
        const size = i32(i + 1);
        const isBytes = sizeName.endsWith("Size");
        if (off < 0 || size < 0) {
            structural.push(`${offName}/${sizeName} is negative (offset=${off}, ${isBytes ? "size" : "count"}=${size})`);
        } else if (isBytes && off + size > INT32_MAX) {
            structural.push(`${offName}+${sizeName} overflows int32 (offset=${off}, size=${size})`);
        }
        tables.push({ offName, sizeName, off, size, isBytes });
    }

    if (stringLiteralOffset < headerBytes) {
        structural.push(`stringLiteralOffset (${stringLiteralOffset}) is inside the ${headerBytes}-byte v${layout} header`);
    } else if (stringLiteralOffset !== headerBytes) {
        warnings.push(`stringLiteralOffset (${stringLiteralOffset}) != expected v${layout} header size (${headerBytes})`);
    }

    for (const t of tables) {
        if (t.size > 0 && t.off >= 0 && t.off < headerBytes) {
            structural.push(`${t.offName} (${t.off}) points inside the ${headerBytes}-byte header`);
        }
    }

    for (const name of KEY_TABLES) {
        const t = tables.find((x) => x.sizeName === name);
        if (t && t.size <= 0) {
            structural.push(`${name} is ${t.size}; every real app has this table`);
        }
    }

    const ranges = tables
        .filter((t) => t.isBytes && t.size > 0 && t.off >= 0 && t.off + t.size <= INT32_MAX)
        .sort((a, b) => a.off - b.off);
    let largestGap = null;
    for (let k = 1; k < ranges.length; k++) {
        const prev = ranges[k - 1];
        const cur = ranges[k];
        const gap = cur.off - (prev.off + prev.size);
        if (gap < 0) {
            structural.push(`${prev.offName} [${prev.off}, ${prev.off + prev.size}) overlaps ${cur.offName} at ${cur.off}`);
        } else if (gap > MAX_GAP_BYTES && (largestGap === null || gap > largestGap.gap)) {
            largestGap = { gap, prev, cur };
        }
    }
    if (largestGap) {
        warnings.push(`${largestGap.gap}-byte gap between ${largestGap.prev.offName} and ${largestGap.cur.offName}`);
    }

    let prevOff = -1;
    for (const t of tables) {
        if (t.size > 0 && t.off >= 0) {
            if (t.off < prevOff) {
                warnings.push(`table offsets are not ascending in struct order (first at ${t.offName})`);
                break;
            }
            prevOff = t.off;
        }
    }

    if (structural.length > 0) {
        if (lenient) {
            for (const s of structural) warnings.push(`(lenient) ${s}`);
        } else {
            for (const s of structural) errors.push(s);
        }
    }
    return { ok: errors.length === 0, version, layout, headerBytes, errors, warnings };
}

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

const CONFIG = {
    offset: null,                   // NativePointer offset into the module, or null
    headerSize: DEFAULT_HEADER_SIZE,
    lenient: false,                 // downgrade structural validation failures to warnings
    eagerScan: false,               // arm the full Stalker scan at il2cpp_init entry even with an offset
    scanMode: "block",              // "block" | "instruction"
    scanScope: "module",            // "module" | "all"
    scanRange: null,                // [lo, hi) module-relative byte offsets, or null
};

const state = {
    phase: "idle",
    outcome: null,                  // null | "captured" | "failed" | "timeout" | "cancelled"
    started: false,
    resolved: false,
    method: null,
    reason: null,
    warnings: [],
    foundAt: null,                  // { reg, pcOffset } of the pointer that was accepted
    hasInitHook: false,
    initEntered: false,
    initReturned: false,
    initThreadId: null,
    initEnteredAt: null,
    offsetFired: false,
    fastPathFailed: false,
    scanError: null,
};

// Where the scan is allowed to instrument code; filled in by installHooks().
const scope = { all: false, base: null, lo: null, hi: null };

// Cost counters, exposed through getStatus() so before/after can be measured on a device.
const stats = {
    blocksCompiled: 0,              // blocks Stalker handed to transform()
    blocksInstrumented: 0,          // ...of which got a callout
    calloutRuns: 0,                 // times a scan callout actually ran
    regChecks: 0,                   // registers examined by those callouts
    magicHits: 0,                   // register values that pointed at the magic
    scanStartedAt: null,
    scanMs: null,                   // first Stalker.follow -> completion
    msFromInitEntry: null,          // il2cpp_init entry -> completion
};

// Everything that must be released when the run ends, in one place.
const resources = {
    listeners: [],                  // Interceptor listeners
    moduleObserver: null,
    timeoutTimer: null,
    gcTimer: null,
};

const candidates = new Map();       // address string -> { ptr, lastTick, lastReason, where }
const followed = new Set();         // thread ids currently followed by Stalker
let scanTick = 0;
let rejectionLogs = 0;
let resolveHeader = null;
const headerPromise = new Promise((resolve) => {
    resolveHeader = resolve;
});

function setPhase(next) {
    // Forward-only: "done" is terminal and nothing ever moves back.
    if (PHASES.indexOf(next) <= PHASES.indexOf(state.phase)) return false;
    state.phase = next;
    return true;
}

function safely(fn) {
    try {
        fn();
    } catch (e) { /* already detached / thread already gone */ }
}

// The ONLY way a run ends. Marks the run done first, so every callback that is still
// in flight (hooks, Stalker callouts, timers) bails out, then releases every resource.
function complete(outcome, method, opts) {
    if (state.resolved) return;
    const o = opts || {};
    const bytes = o.bytes || null;
    state.resolved = true;
    setPhase("done");
    state.outcome = outcome;
    state.method = method;
    state.reason = bytes ? null : (o.reason || "unknown");
    state.warnings = o.warnings || [];
    state.foundAt = o.foundAt || null;

    const now = Date.now();
    if (state.initEnteredAt !== null) stats.msFromInitEntry = now - state.initEnteredAt;
    if (stats.scanStartedAt !== null) stats.scanMs = now - stats.scanStartedAt;

    releaseResources();

    if (bytes) {
        console.log(`[+] Clean header captured via the ${method} path (${bytes.byteLength} bytes).`);
        if (state.foundAt) console.log(`[i] Header pointer seen in ${state.foundAt.reg} at ${TARGET_MODULE}+${state.foundAt.pcOffset}`);
        for (const w of state.warnings) console.log("[~] validation warning:", w);
    } else {
        console.log(`[!] No header captured (${method}, ${outcome}): ${state.reason}`);
    }
    if (stats.blocksCompiled > 0 || stats.calloutRuns > 0) {
        console.log(`[i] Scan stats: mode=${CONFIG.scanMode}, scope=${scopeLabel()}, blocks=${stats.blocksInstrumented}/${stats.blocksCompiled}` +
            `, callouts=${stats.calloutRuns}, regChecks=${stats.regChecks}, scanMs=${stats.scanMs}`);
    }
    resolveHeader(bytes);
}

function releaseResources() {
    for (const listener of resources.listeners.splice(0)) safely(() => listener.detach());
    if (resources.moduleObserver !== null) {
        const observer = resources.moduleObserver;
        resources.moduleObserver = null;
        safely(() => observer.detach());
    }
    if (resources.timeoutTimer !== null) {
        clearTimeout(resources.timeoutTimer);
        resources.timeoutTimer = null;
    }
    stopScan();
}

function stopScan() {
    const hadThreads = followed.size > 0;
    for (const tid of followed) safely(() => Stalker.unfollow(tid));
    followed.clear();
    if (hadThreads && resources.gcTimer === null) {
        // Stalker can only free the translated code once the threads are really gone.
        resources.gcTimer = setTimeout(() => {
            resources.gcTimer = null;
            safely(() => Stalker.garbageCollect());
        }, GC_DELAY_MS);
    }
}

function internalError(label, e) {
    const msg = e && e.message ? e.message : String(e);
    console.log(`[!] Internal error in ${label}: ${e && e.stack ? e.stack : msg}`);
    complete("failed", "internal-error", { reason: `internal error in ${label}: ${msg}` });
}

// Safety net for every callback Frida invokes: an exception must end the run with a clear
// reason, not leave the controller waiting for the timeout.
function guarded(label, fn) {
    return function () {
        try {
            return fn.apply(this, arguments);
        } catch (e) {
            internalError(label, e);
        }
    };
}

function attachTracked(address, callbacks) {
    const listener = Interceptor.attach(address, callbacks);
    resources.listeners.push(listener);
    return listener;
}

function progress() {
    if (state.phase === "waiting-module") {
        return `phase=waiting-module, ${TARGET_MODULE} was never loaded`;
    }
    return `phase=${state.phase}, il2cpp_init entered=${state.initEntered}, returned=${state.initReturned}, ` +
        `offsetFired=${state.offsetFired}`;
}

function scopeLabel() {
    if (CONFIG.scanScope === "all" || scope.all) return "all";
    if (CONFIG.scanRange) return `range ${hex(CONFIG.scanRange[0])}-${hex(CONFIG.scanRange[1])}`;
    return "module";
}

// ---------------------------------------------------------------------------
// Candidate inspection
// ---------------------------------------------------------------------------

function plausiblePointer(v) {
    // Cheap, allocation-free filter so we don't pay for an access-violation exception on every
    // small integer or hash-like value that passes through a register during the deobfuscation loop.
    return !!v && v.compare(MIN_PTR) >= 0 && v.compare(MAX_PTR) <= 0;
}

function hasMagic(p) {
    try {
        return p.readU32() === REAL_MAGIC;
    } catch (e) {
        return false; // unreadable -> definitely not a valid pointer here
    }
}

// Walks the mappings that cover [p, p+size) and reports how much is really readable.
function checkReadable(p, size) {
    let cur = p;
    let got = 0;
    while (got < size) {
        const range = Process.findRangeByAddress(cur);
        if (range === null || range === undefined) {
            return { ok: false, reason: `only ${got} of ${size} bytes are readable at ${p}: ${cur} is not mapped (lower --header-size if the buffer is smaller)` };
        }
        if (range.protection.charAt(0) !== "r") {
            return { ok: false, reason: `only ${got} of ${size} bytes are readable at ${p}: ${cur} is in a ${range.protection} mapping` };
        }
        const left = range.size - parseInt(cur.sub(range.base).toString(), 16);
        if (left <= 0) {
            return { ok: false, reason: `inconsistent mapping data for ${cur}` };
        }
        const take = Math.min(left, size - got);
        got += take;
        cur = cur.add(take);
    }
    return { ok: true };
}

// Validates the exact bytes that would be returned, so the verdict and the dump can't diverge.
function inspectCandidate(p) {
    const size = CONFIG.headerSize;
    const readable = checkReadable(p, size);
    if (!readable.ok) {
        return { ok: false, errors: [readable.reason], warnings: [] };
    }
    let buf;
    try {
        buf = p.readByteArray(size);
    } catch (e) {
        return { ok: false, errors: [`readByteArray(${size}) at ${p} failed: ${e.message}`], warnings: [] };
    }
    const result = validateHeader(buf, CONFIG.lenient);
    result.bytes = buf;
    return result;
}

function logRejection(p, source, errors) {
    if (rejectionLogs >= MAX_LOGGED_REJECTIONS) return;
    rejectionLogs++;
    console.log(`[!] Rejected candidate ${p} (${source}): ${errors.join("; ")}`);
    if (rejectionLogs === MAX_LOGGED_REJECTIONS) console.log("[i] Further rejections will not be logged.");
}

function whereSeen(reg, pc) {
    if (!pc || !scope.base) return null;
    try {
        return { reg, pcOffset: pc.sub(scope.base).toString() };
    } catch (e) {
        return null;
    }
}

// Validates a magic-matching pointer seen during the scan. A candidate that fails is remembered:
// it is re-validated every RECHECK_EVERY callouts (the buffer may still be being written) and
// once more when il2cpp_init returns.
function considerCandidate(p, source, force, where) {
    const key = p.toString();
    let entry = candidates.get(key);
    if (entry !== undefined && !force && scanTick - entry.lastTick < RECHECK_EVERY) return false;

    const result = inspectCandidate(p);
    if (result.ok) {
        complete("captured", "dynamic-scan", {
            bytes: result.bytes,
            warnings: result.warnings,
            foundAt: where || (entry !== undefined ? entry.where : null),
        });
        return true;
    }
    if (entry === undefined) {
        if (candidates.size >= MAX_CANDIDATES) candidates.delete(candidates.keys().next().value);
        entry = { ptr: p, lastTick: scanTick, lastReason: null, where: where || null };
        candidates.set(key, entry);
    }
    entry.lastTick = scanTick;
    const reason = result.errors.join(" | ");
    if (entry.lastReason !== reason) {
        entry.lastReason = reason;
        logRejection(p, source, result.errors);
    }
    return false;
}

function rescanCandidates() {
    for (const entry of Array.from(candidates.values())) {
        if (considerCandidate(entry.ptr, "re-check at il2cpp_init return", true, null)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Stalker scan
// ---------------------------------------------------------------------------

function inScope(address) {
    return scope.all || (address.compare(scope.lo) >= 0 && address.compare(scope.hi) < 0);
}

// Looks at the given registers of one execution context. `regs` is a plain array of names.
function scanRegisters(context, regs) {
    scanTick++;
    stats.calloutRuns++;
    stats.regChecks += regs.length;
    for (let i = 0; i < regs.length; i++) {
        const reg = regs[i];
        const v = context[reg];
        if (!plausiblePointer(v) || !hasMagic(v)) continue;
        stats.magicHits++;
        if (considerCandidate(v, reg, false, whereSeen(reg, context.pc))) return;
    }
}

// Adds the general-purpose registers an instruction reads to `out` (as x0..x28). Returns false
// when this Frida build does not expose that information, so the caller can fall back to all of them.
function collectRegsRead(instr, out) {
    const read = instr.regsRead;
    if (!Array.isArray(read)) return false;
    for (const name of read) {
        const m = /^[xw](\d+)$/.exec(name);
        if (m !== null && Number(m[1]) <= 28) out.add("x" + Number(m[1]));
    }
    return true;
}

const instructionCallout = guarded("scan callout", function (context) {
    if (state.resolved) return;
    scanRegisters(context, ALL_REGS);
});

function makeBlockCallout(holder) {
    return guarded("scan callout", function (context) {
        if (state.resolved) return;
        scanRegisters(context, holder.regs || ALL_REGS);
    });
}

function transformBlock(iterator) {
    let instr = iterator.next();
    if (instr === null) return;
    stats.blocksCompiled++;

    if (state.resolved || !inScope(instr.address)) {
        do {
            iterator.keep();
        } while ((instr = iterator.next()) !== null);
        return;
    }
    stats.blocksInstrumented++;

    if (CONFIG.scanMode === "instruction") {
        do {
            iterator.keep();
            iterator.putCallout(instructionCallout);
        } while ((instr = iterator.next()) !== null);
        return;
    }

    // Block mode: one callout at block entry. The register list is only complete once the whole
    // block has been walked below, which is fine - the callout runs long after transform() returns.
    const holder = { regs: null };
    const touched = new Set();
    let known = true;
    iterator.putCallout(makeBlockCallout(holder));
    do {
        if (known) known = collectRegsRead(instr, touched);
        iterator.keep();
    } while ((instr = iterator.next()) !== null);
    holder.regs = known ? Array.from(touched) : ALL_REGS;
}

function startScan(tid) {
    if (state.resolved || followed.has(tid)) return;
    followed.add(tid);
    try {
        Stalker.follow(tid, { transform: guarded("Stalker transform", transformBlock) });
    } catch (e) {
        followed.delete(tid);
        state.scanError = `Stalker.follow failed: ${e.message}`;
        console.log(`[!] ${state.scanError}`);
        // Without the scan the only remaining path is a fast path that has not failed (yet).
        if (!CONFIG.offset || state.fastPathFailed) {
            complete("failed", "dynamic-scan", { reason: state.scanError });
        }
        return;
    }
    setPhase("scanning");
    if (stats.scanStartedAt === null) stats.scanStartedAt = Date.now();
    console.log(`[+] Starting Stalker scan on thread ${tid} (mode=${CONFIG.scanMode}, scope=${scopeLabel()})`);
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

function main() {
    let mod = null;
    try {
        mod = Process.getModuleByName(TARGET_MODULE);
    } catch (e) {
        mod = null;
    }
    if (mod !== null) {
        installHooks(mod);
        return;
    }
    console.log(`[i] ${TARGET_MODULE} not loaded yet - waiting on the module observer...`);
    setPhase("waiting-module");
    resources.moduleObserver = Process.attachModuleObserver({
        onAdded: guarded("module observer", function (m) {
            if (m.name !== TARGET_MODULE || state.resolved) return;
            if (resources.moduleObserver !== null) {
                const observer = resources.moduleObserver;
                resources.moduleObserver = null;
                safely(() => observer.detach());
            }
            installHooks(m);
        }),
    });
}

function computeScope(mod) {
    scope.base = mod.base;
    scope.all = CONFIG.scanScope === "all";
    if (scope.all) return;
    const size = mod.size || 0;
    if (!size) {
        console.log(`[~] Size of ${TARGET_MODULE} unknown - the scan will cover every module.`);
        scope.all = true;
        return;
    }
    if (CONFIG.scanRange) {
        if (CONFIG.scanRange[1] > size) {
            console.log(`[~] --scan-range end ${hex(CONFIG.scanRange[1])} is past the end of ${TARGET_MODULE} (${hex(size)}).`);
        }
        scope.lo = mod.base.add(CONFIG.scanRange[0]);
        scope.hi = mod.base.add(CONFIG.scanRange[1]);
    } else {
        scope.lo = mod.base;
        scope.hi = mod.base.add(size);
    }
}

function installHooks(mod) {
    if (state.resolved) return; // the run ended (timeout / cancel) before the module showed up
    try {
        computeScope(mod);

        // The il2cpp_init observer goes in first and unconditionally: it is what lets the fallback
        // react to the real events instead of guessing with a timer.
        let initAddr = null;
        try {
            initAddr = mod.getExportByName("il2cpp_init");
        } catch (e) {
            initAddr = null;
        }
        if (initAddr !== null) {
            console.log("[+] il2cpp_init @", initAddr);
            installInitObserver(initAddr);
        } else if (!CONFIG.offset) {
            complete("failed", "dynamic-scan", { reason: "could not find the il2cpp_init export - need a different hook point for this build" });
            return;
        } else {
            console.log("[!] Could not find the il2cpp_init export - the offset hook is the only path for this build.");
        }

        if (CONFIG.offset) {
            try {
                installOffsetHook(mod);
            } catch (e) {
                // e.g. the offset is not a valid code address in this build: same as a stale offset.
                state.fastPathFailed = true;
                console.log(`[!] Could not hook the configured offset (${e.message}).`);
                if (!state.hasInitHook) {
                    complete("failed", "fast-offset", { reason: `could not hook the offset (${e.message}) and there is no il2cpp_init hook to fall back on` });
                    return;
                }
                console.log("[i] The full scan will start at il2cpp_init entry instead.");
            }
        } else {
            console.log("[i] No offset configured - the dynamic Stalker scan starts when il2cpp_init is entered.");
        }
        setPhase("armed");
    } catch (e) {
        internalError("hook installation", e);
    }
}

function installInitObserver(initAddr) {
    state.hasInitHook = true;
    attachTracked(initAddr, {
        onEnter: guarded("il2cpp_init onEnter", function () {
            state.initEntered = true;
            state.initEnteredAt = Date.now();
            state.initThreadId = this.threadId;
            console.log("[+] Entered il2cpp_init on thread", this.threadId);
            if (state.resolved) return;
            if (!CONFIG.offset || CONFIG.eagerScan || state.fastPathFailed) {
                startScan(this.threadId);
            } else {
                console.log("[i] Offset fast path has priority - Stalker stays off unless it fails.");
            }
        }),
        onLeave: guarded("il2cpp_init onLeave", function () {
            state.initReturned = true;
            if (state.resolved) return;
            console.log("[i] il2cpp_init returned - re-checking the candidates seen so far.");
            if (rescanCandidates()) return;
            const hint = CONFIG.offset && !CONFIG.eagerScan
                ? " (the offset never produced a header; re-run without --offset for a full scan from il2cpp_init entry)"
                : "";
            complete("failed", "il2cpp_init", { reason: `il2cpp_init returned without a validated header${hint}` });
        }),
    });
}

function installOffsetHook(mod) {
    const hookAddr = mod.base.add(CONFIG.offset);
    console.log("[+] Fast path: hooking hardcoded offset at", hookAddr);

    const listener = attachTracked(hookAddr, {
        onEnter: guarded("offset hook", function () {
            if (state.resolved) {
                safely(() => listener.detach());
                return;
            }
            state.offsetFired = true;
            let cleanPtr = null;
            let result;
            try {
                cleanPtr = this.context.x21; // holds the clean header pointer right after deobfuscation
                result = inspectCandidate(cleanPtr);
            } catch (e) {
                result = { ok: false, errors: [`offset hook threw: ${e.message}`], warnings: [] };
            }
            safely(() => listener.detach());

            if (result.ok) {
                complete("captured", "fast-offset", {
                    bytes: result.bytes,
                    warnings: result.warnings,
                    foundAt: { reg: "x21", pcOffset: CONFIG.offset.toString() },
                });
                return;
            }

            state.fastPathFailed = true;
            console.log(`[!] Offset fired but x21 (${cleanPtr}) is not a valid header (stale offset after an app update?): ${result.errors.join("; ")}`);
            if (!state.hasInitHook) {
                complete("failed", "fast-offset", { reason: "offset did not yield a valid header and there is no il2cpp_init hook to fall back on" });
            } else if (state.initEntered && !state.initReturned && this.threadId === state.initThreadId) {
                console.log("[i] Falling back to a late Stalker scan on the il2cpp_init thread (it only covers the rest of the function).");
                startScan(this.threadId);
            } else if (!state.initEntered) {
                console.log("[i] Offset fired before il2cpp_init - the full scan will start at il2cpp_init entry.");
            }
        }),
    });
}

// ---------------------------------------------------------------------------
// RPC
// ---------------------------------------------------------------------------

function parseScanRange(range) {
    if (!Array.isArray(range) || range.length !== 2) {
        throw new Error("scanRange must be [start, end]");
    }
    const lo = Number(range[0]);
    const hi = Number(range[1]);
    if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 0 || hi <= lo) {
        throw new Error(`scanRange must be integers with 0 <= start < end, got ${range[0]}, ${range[1]}`);
    }
    return [lo, hi];
}

rpc.exports = {
    // Called by the controller right after script.load() and before the target process is
    // resumed. Installs every hook synchronously, so it all happens before il2cpp_init can run.
    configure: function (cfg) {
        if (state.started) {
            console.log("[~] configure() ignored: the agent is already running.");
            return;
        }
        cfg = cfg || {};
        // Validate everything first so a bad value cannot leave a half-applied configuration.
        const next = Object.assign({}, CONFIG);
        if (cfg.offset !== undefined && cfg.offset !== null && cfg.offset !== "") {
            next.offset = ptr(cfg.offset);
        }
        if (cfg.headerSize !== undefined && cfg.headerSize !== null) {
            const n = Number(cfg.headerSize);
            if (!Number.isInteger(n) || n < MIN_HEADER_SIZE || n > MAX_HEADER_SIZE) {
                throw new Error(`headerSize must be an integer between ${MIN_HEADER_SIZE} and ${MAX_HEADER_SIZE}, got ${cfg.headerSize}`);
            }
            next.headerSize = n;
        }
        if (cfg.scanMode !== undefined && cfg.scanMode !== null) {
            if (SCAN_MODES.indexOf(cfg.scanMode) < 0) throw new Error(`scanMode must be one of ${SCAN_MODES.join(", ")}, got ${cfg.scanMode}`);
            next.scanMode = cfg.scanMode;
        }
        if (cfg.scanScope !== undefined && cfg.scanScope !== null) {
            if (SCAN_SCOPES.indexOf(cfg.scanScope) < 0) throw new Error(`scanScope must be one of ${SCAN_SCOPES.join(", ")}, got ${cfg.scanScope}`);
            next.scanScope = cfg.scanScope;
        }
        if (cfg.scanRange !== undefined && cfg.scanRange !== null) {
            next.scanRange = parseScanRange(cfg.scanRange);
            if (next.scanScope === "all") throw new Error("scanRange only applies to scanScope \"module\"");
        }
        next.lenient = !!cfg.lenient;
        next.eagerScan = !!cfg.eagerScan;
        Object.assign(CONFIG, next);

        console.log(
            "[i] Config received: offset=" + (CONFIG.offset ? CONFIG.offset : "none (dynamic scan only)") +
            ", headerSize=" + CONFIG.headerSize +
            ", lenient=" + CONFIG.lenient +
            ", eagerScan=" + CONFIG.eagerScan +
            ", scanMode=" + CONFIG.scanMode +
            ", scanScope=" + scopeLabel()
        );
        start();
    },

    waitForHeader: function (timeoutMs) {
        const timeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : 30000;
        // If the controller never calls configure() (e.g. an older controller script), start with
        // the dynamic-scan-only path so the agent still works standalone.
        start();
        if (!state.resolved) {
            // One timer for the whole run; a later call re-arms it. complete() clears it.
            if (resources.timeoutTimer !== null) clearTimeout(resources.timeoutTimer);
            resources.timeoutTimer = setTimeout(() => {
                resources.timeoutTimer = null;
                console.log("[!] Timed out waiting for header");
                complete("timeout", "timeout", { reason: `no validated header within ${timeout}ms (${progress()})` });
            }, timeout);
        }
        return headerPromise;
    },

    // Ends the run on the controller's request (Ctrl+C, giving up) and releases everything.
    cancel: function (why) {
        complete("cancelled", "cancelled", { reason: why ? String(why) : "cancelled by the controller" });
        return state.outcome;
    },

    // Frida calls this when the script is unloaded or the session goes away.
    dispose: function () {
        complete("cancelled", "cancelled", { reason: "script unloaded before a header was captured" });
        if (resources.gcTimer !== null) {
            clearTimeout(resources.gcTimer);
            resources.gcTimer = null;
        }
    },

    // Diagnostics for the controller (JSON only; the header itself is returned by waitForHeader).
    getStatus: function () {
        return {
            resolved: state.resolved,
            phase: state.phase,
            outcome: state.outcome,
            method: state.method,
            reason: state.reason,
            warnings: state.warnings,
            foundAt: state.foundAt,
            initEntered: state.initEntered,
            initReturned: state.initReturned,
            offsetFired: state.offsetFired,
            fastPathFailed: state.fastPathFailed,
            scanError: state.scanError,
            candidatesSeen: candidates.size,
            scan: { mode: CONFIG.scanMode, scope: scopeLabel() },
            stats: Object.assign({}, stats),
        };
    },
};

function start() {
    if (state.started) return;
    state.started = true;
    main();
}
