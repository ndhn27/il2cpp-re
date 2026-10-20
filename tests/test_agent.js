// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ndhn27

// Logic tests for agents/dump_clean_header_v4.js against a fake Frida runtime (see agent_harness.js).
// Run from the repo root:  node --test tests/test_agent.js
// They verify hook ordering, fallback decisions and header validation - NOT behaviour on a device.
const test = require("node:test");
const assert = require("node:assert/strict");
const { loadAgent, FakeMemory } = require("./agent_harness");

const MAGIC = 0xFAB11BAF;
const BASE = 0x100000000;          // fake UnityFramework base
const INIT_OFF = 0x5000;           // il2cpp_init export
const HOOK_OFF = 0x9000;           // configured offset
const HEAP = 0x200000000;
const SIZE = 1024;

function buildHeader(agent, layout = 29, version = 29) {
    const fields = agent.headerFields().filter((f) => (f[1] === null || layout >= f[1]) && (f[2] === null || layout <= f[2]));
    const buf = new Uint8Array(SIZE);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MAGIC, true);
    dv.setInt32(4, version, true);
    let off = fields.length * 4;
    for (let i = 2; i + 1 < fields.length; i += 2) {
        if (fields[i + 1][0].endsWith("Size")) {
            dv.setInt32(i * 4, off, true);
            dv.setInt32((i + 1) * 4, 1000 + i * 8, true);
            off += 1000 + i * 8;
        } else {
            dv.setInt32(i * 4, off, true);
            dv.setInt32((i + 1) * 4, 10, true);
            off += 80;
        }
    }
    return buf;
}

function magicOnly() {
    const buf = new Uint8Array(SIZE);
    new DataView(buf.buffer).setUint32(0, MAGIC, true);
    new DataView(buf.buffer).setInt32(4, 29, true);
    return buf;
}

// Loads the agent with a UnityFramework module present (unless withModule is false).
function setup({ withModule = true, exportInit = true } = {}) {
    const agent = loadAgent();
    const exports = exportInit ? { il2cpp_init: INIT_OFF } : {};
    const mod = agent.makeModule("UnityFramework", BASE, exports);
    if (withModule) agent.addModule("UnityFramework", mod);
    agent.mod = mod;
    agent.initHook = () => agent.hookAt(BASE + INIT_OFF);
    agent.offsetHook = () => agent.hookAt(BASE + HOOK_OFF);
    agent.ctx = (regs) => regs; // registers are plain objects
    return agent;
}

const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

// ---------------------------------------------------------------- P0: fallback armed from the start

test("every hook is installed synchronously in configure(), with no timer involved", () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    assert.equal(a.hooks.length, 2);
    assert.ok(a.initHook(), "il2cpp_init observer missing");
    assert.ok(a.offsetHook(), "offset hook missing");
    assert.equal(a.timers.length, 0, "nothing may be scheduled to arm the fallback later");
});

test("without an offset only the il2cpp_init observer is installed, still synchronously", () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    assert.equal(a.hooks.length, 1);
    assert.ok(a.initHook());
    assert.equal(a.timers.length, 0);
});

test("if UnityFramework loads after configure(), the hooks go in the moment it is added", () => {
    const a = setup({ withModule: false });
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    assert.equal(a.hooks.length, 0);
    assert.ok(a.moduleObserver());
    a.fireModuleAdded(a.mod);
    assert.equal(a.hooks.length, 2);
    assert.ok(a.moduleObserver().detached);
});

test("a stale offset is reported as soon as il2cpp_init returns - no 6s/20s timer needed", async () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    assert.equal(a.stalker.followed.size, 0, "fast path has priority: no Stalker yet");
    a.leave(a.initHook(), 1);              // the offset hook never fired
    assert.equal(await wait, null);
    const status = a.exports.getStatus();
    assert.equal(status.resolved, true);
    assert.match(status.reason, /il2cpp_init returned without a validated header/);
    assert.match(status.reason, /without --offset/);
});

test("offset firing inside il2cpp_init with a bad pointer starts a late scan on that thread", async () => {
    const a = setup();
    a.memory.map(HEAP, magicOnly());                       // decoy: right magic, nothing else
    const good = buildHeader(a);
    a.memory.map(HEAP + 0x10000, good);
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);

    a.enter(a.initHook(), {}, 7);
    a.enter(a.offsetHook(), { x21: new a.NP(HEAP) }, 7);   // fires with the decoy
    assert.ok(a.offsetHook().detached);
    assert.ok(a.stalker.followed.has(7), "late Stalker scan expected");
    assert.equal(a.exports.getStatus().resolved, false, "a magic-only buffer must not be accepted");

    a.execute(7, [{ x0: new a.NP(5) }, { x21: new a.NP(HEAP) }, { x22: new a.NP(HEAP + 0x10000) }]);
    const bytes = await wait;
    assert.ok(bytes && same(bytes, good), "must return the validated buffer, not the decoy");
    assert.equal(a.exports.getStatus().method, "dynamic-scan");
    assert.deepEqual(a.stalker.unfollowed, [7]);
});

test("offset firing BEFORE il2cpp_init arms the full scan at il2cpp_init entry", () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    a.enter(a.offsetHook(), { x21: new a.NP(0) }, 3);
    assert.equal(a.stalker.followed.size, 0);
    a.enter(a.initHook(), {}, 3);
    assert.ok(a.stalker.followed.has(3));
});

test("eagerScan arms the full scan at il2cpp_init entry even when an offset is configured", () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE, eagerScan: true });
    a.enter(a.initHook(), {}, 1);
    assert.ok(a.stalker.followed.has(1));
});

test("no offset: the scan starts at il2cpp_init entry and skips decoys", async () => {
    const a = setup();
    a.memory.map(HEAP, magicOnly());
    const good = buildHeader(a);
    a.memory.map(HEAP + 0x10000, good);
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    assert.ok(a.stalker.followed.has(1));
    a.execute(1, [{ x21: new a.NP(HEAP) }, { x21: new a.NP(HEAP + 0x10000) }]);
    assert.ok(same(await wait, good));
});

// ---------------------------------------------------------------- P0: validation beyond the magic

test("fast path accepts a structurally valid header and never starts Stalker", async () => {
    const a = setup();
    const good = buildHeader(a);
    a.memory.map(HEAP, good);
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    a.enter(a.offsetHook(), { x21: new a.NP(HEAP) }, 1);
    assert.ok(same(await wait, good));
    assert.equal(a.exports.getStatus().method, "fast-offset");
    assert.equal(a.stalker.followed.size, 0);
    assert.equal(a.stalker.unfollowed.length, 0);
});

test("a candidate that is completed later is picked up when il2cpp_init returns", async () => {
    const a = setup();
    const region = magicOnly();                            // header still being written
    a.memory.map(HEAP, region);
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    a.execute(1, [{ x21: new a.NP(HEAP) }]);
    assert.equal(a.exports.getStatus().resolved, false);
    region.set(buildHeader(a));                            // the rest of the header lands
    a.leave(a.initHook(), 1);
    const bytes = await wait;
    assert.ok(bytes && same(bytes, region));
    assert.equal(a.exports.getStatus().method, "dynamic-scan");
});

test("a rejected candidate is re-validated periodically while scanning", async () => {
    const a = setup();
    const region = magicOnly();
    a.memory.map(HEAP, region);
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    const filler = Array.from({ length: 5000 }, () => ({ x0: new a.NP(1) }));
    a.execute(1, [{ x21: new a.NP(HEAP) }]);
    region.set(buildHeader(a));
    a.execute(1, [...filler, { x21: new a.NP(HEAP) }]);
    assert.ok(await wait);
});

test("a buffer that is not readable for the whole window is rejected with a clear message", async () => {
    const a = setup();
    const full = buildHeader(a);
    a.memory.map(HEAP, full.slice(0, 600));                // mapping ends 600 bytes in
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    assert.doesNotThrow(() => a.execute(1, [{ x21: new a.NP(HEAP) }]));
    assert.ok(a.logs.some((l) => /only 600 of 1024 bytes are readable/.test(l)), a.logs.join("\n"));
    a.leave(a.initHook(), 1);
    assert.equal(await wait, null);
});

test("a header spanning adjacent readable mappings is fine; a non-readable neighbour is not", () => {
    for (const [prot, expectOk] of [["r--", true], ["---", false]]) {
        const a = setup();
        const full = buildHeader(a);
        a.memory.map(HEAP, full.slice(0, 700));
        a.memory.map(HEAP + 700, full.slice(700), prot);
        a.exports.configure({ headerSize: SIZE });
        a.enter(a.initHook(), {}, 1);
        a.execute(1, [{ x21: new a.NP(HEAP) }]);
        assert.equal(a.exports.getStatus().resolved, expectOk, `neighbour ${prot}`);
        if (!expectOk) assert.ok(a.logs.some((l) => /--- mapping/.test(l)), a.logs.join("\n"));
    }
});

test("junk register values never throw inside the scan", () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    a.enter(a.initHook(), {}, 1);
    assert.doesNotThrow(() => a.execute(1, [
        {},
        { x0: new a.NP(0), x1: new a.NP(5), x2: new a.NP(0xdeadbeefcafe), x3: new a.NP(0xffffffffffffffffn) },
        { x19: undefined, x20: null },
    ]));
    assert.equal(a.exports.getStatus().candidatesSeen, 0);
});

test("lenient mode accepts a structurally broken header that strict mode rejects", async () => {
    for (const lenient of [false, true]) {
        const a = setup();
        const hdr = buildHeader(a);
        const dv = new DataView(hdr.buffer);
        const idx = a.headerFields().filter((f) => f[1] === null || 29 >= f[1]).map((f) => f[0]).indexOf("typeDefinitionsSize");
        dv.setInt32(idx * 4, 0, true);
        a.memory.map(HEAP, hdr);
        a.exports.configure({ offset: "0x9000", headerSize: SIZE, lenient });
        const wait = a.exports.waitForHeader(45000);
        a.enter(a.initHook(), {}, 1);
        a.enter(a.offsetHook(), { x21: new a.NP(HEAP) }, 1);
        if (lenient) {
            assert.ok(await wait);
            assert.ok(a.exports.getStatus().warnings.some((w) => w.startsWith("(lenient)")));
        } else {
            a.leave(a.initHook(), 1);
            assert.equal(await wait, null);
        }
    }
});

// ---------------------------------------------------------------- housekeeping

test("timeout fails the wait and stops Stalker", async () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(1000);
    a.enter(a.initHook(), {}, 1);
    assert.ok(a.stalker.followed.has(1));
    a.timers.find((t) => t.ms === 1000 && t.live).fn();
    assert.equal(await wait, null);
    assert.equal(a.exports.getStatus().reason.startsWith("no validated header within 1000ms"), true);
    assert.equal(a.stalker.followed.size, 0, "Stalker must not keep following after a timeout");
});

test("configure() rejects an unusable headerSize", () => {
    const a = setup();
    assert.throws(() => a.exports.configure({ headerSize: 100 }), /headerSize/);
});

test("an exception while reading x21 is treated as a failed fast path", () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    a.enter(a.initHook(), {}, 1);
    const ctx = { get x21() { throw new Error("boom"); } };
    assert.doesNotThrow(() => a.enter(a.offsetHook(), ctx, 1));
    assert.ok(a.stalker.followed.has(1));
});

test("offset with no il2cpp_init export has no fallback and fails right away", async () => {
    const a = setup({ exportInit: false });
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    assert.equal(a.hooks.length, 1);
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.offsetHook(), { x21: new a.NP(0) }, 1);
    assert.equal(await wait, null);
    assert.match(a.exports.getStatus().reason, /no il2cpp_init hook/);
});

test("no offset and no il2cpp_init export fails at configure()", async () => {
    const a = setup({ exportInit: false });
    a.exports.configure({ headerSize: SIZE });
    assert.equal(await a.exports.waitForHeader(45000), null);
    assert.match(a.exports.getStatus().reason, /il2cpp_init export/);
});

test("validateHeader reports why a magic-only buffer is not a header", () => {
    const a = setup();
    const buf = magicOnly();
    const r = a.validateHeader(buf.buffer, false);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /every real app has this table/.test(e)));
});

// ================================================================ P1: scan scope, granularity, registers

const OUTSIDE = 0x300000000;       // an address outside the fake UnityFramework [BASE, BASE + 0x1000000)
const fire = (timer) => { timer.live = false; timer.fn(); };
// getStatus() is plain JSON for the controller; compare it that way (objects made inside the agent's vm
// context have a different Object.prototype, which deepStrictEqual would trip over).
const json = (x) => JSON.parse(JSON.stringify(x));

// Starts a scan on thread 1 (no offset => the scan starts at il2cpp_init entry).
function scanning(cfg = {}) {
    const a = setup();
    a.exports.configure({ headerSize: SIZE, ...cfg });
    a.enter(a.initHook(), {}, 1);
    return a;
}

test("scope=module: code outside UnityFramework is never instrumented, code inside is", () => {
    const a = scanning();
    a.runBlock(1, { address: OUTSIDE, instrs: 6 }, { x0: new a.NP(1) });
    a.runBlock(1, { address: BASE + 0x2000, instrs: 6 }, { x0: new a.NP(1) });
    const { stats } = a.exports.getStatus();
    assert.equal(stats.blocksCompiled, 2);
    assert.equal(stats.blocksInstrumented, 1);
    assert.equal(a.stalker.calloutRuns, 1);
});

test("scope=all instruments every module (the old behaviour)", () => {
    const a = scanning({ scanScope: "all" });
    a.runBlock(1, { address: OUTSIDE, instrs: 6 }, { x0: new a.NP(1) });
    assert.equal(a.exports.getStatus().stats.blocksInstrumented, 1);
});

test("scanRange narrows the scan to a routine that is already known", () => {
    const a = scanning({ scanRange: ["0x4000", "0x5000"] });
    a.runBlock(1, { address: BASE + 0x3ffc, instrs: 1 }, {});   // just below the range
    a.runBlock(1, { address: BASE + 0x4000, instrs: 2 }, {});   // first instruction of the range
    a.runBlock(1, { address: BASE + 0x5000, instrs: 1 }, {});   // end is exclusive
    const { stats, scan } = a.exports.getStatus();
    assert.equal(stats.blocksCompiled, 3);
    assert.equal(stats.blocksInstrumented, 1);
    assert.equal(scan.scope, "range 0x4000-0x5000");
});

test("a scanRange past the end of the module is reported", () => {
    const a = scanning({ scanRange: [0, 0x2000000] });
    assert.ok(a.logs.some((l) => /past the end of UnityFramework/.test(l)), a.logs.join("\n"));
});

test("block mode puts ONE callout per block, instruction mode one per instruction", () => {
    const block = scanning();
    block.runBlock(1, { address: BASE + 0x2000, instrs: 6 }, {});
    assert.equal(block.stalker.calloutRuns, 1);

    const insn = scanning({ scanMode: "instruction" });
    insn.runBlock(1, { address: BASE + 0x2000, instrs: 6 }, {});
    assert.equal(insn.stalker.calloutRuns, 6);
});

test("block mode only checks the registers the block reads (w-registers map to x, x29+ are ignored)", () => {
    const a = scanning();
    // reads w21 (=> x21), x29, sp and xzr in the second instruction: only x21 is a candidate register
    a.runBlock(1, { address: BASE + 0x2000, instrs: 2, regsRead: [["w21"], ["x29", "sp", "xzr", "x30"]] }, {});
    const { stats } = a.exports.getStatus();
    assert.equal(stats.calloutRuns, 1);
    assert.equal(stats.regChecks, 1);
});

test("block mode finds a header in a register the block reads, and reports where", async () => {
    const a = setup();
    const good = buildHeader(a);
    a.memory.map(HEAP, good);
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    a.runBlock(1, { address: BASE + 0x1000, instrs: 3, regsRead: [["x22"], [], []] }, { x22: new a.NP(HEAP) });
    assert.ok(same(await wait, good));
    const status = a.exports.getStatus();
    assert.deepEqual(json(status.foundAt), { reg: "x22", pcOffset: "0x1000" });
    assert.equal(status.stats.magicHits, 1);
    assert.deepEqual(a.stalker.unfollowed, [1]);
});

test("a register the block never reads is not looked at (documented limit of block mode)", () => {
    const a = setup();
    a.memory.map(HEAP, buildHeader(a));
    a.exports.configure({ headerSize: SIZE });
    a.enter(a.initHook(), {}, 1);
    a.runBlock(1, { address: BASE + 0x1000, instrs: 1, regsRead: [["x1"]] }, { x5: new a.NP(HEAP) });
    assert.equal(a.exports.getStatus().resolved, false);
});

test("registers beyond the old x0-x3/x19-x24 set are covered (fallback list and instruction mode)", async () => {
    for (const [cfg, reg] of [[{}, "x27"], [{}, "x5"], [{ scanMode: "instruction" }, "x12"], [{ scanMode: "instruction" }, "x28"]]) {
        const a = setup();
        const good = buildHeader(a);
        a.memory.map(HEAP, good);
        a.exports.configure({ headerSize: SIZE, ...cfg });
        const wait = a.exports.waitForHeader(45000);
        a.enter(a.initHook(), {}, 1);
        a.runBlock(1, { address: BASE + 0x1000, instrs: 2 }, { [reg]: new a.NP(HEAP) });   // no regsRead => all of x0-x28
        assert.ok(same(await wait, good), `${JSON.stringify(cfg)} ${reg}`);
        assert.equal(a.exports.getStatus().foundAt.reg, reg);
    }
});

test("a header found by the il2cpp_init re-check is reported with where it was first seen", async () => {
    const a = setup();
    const region = magicOnly();
    a.memory.map(HEAP, region);
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    a.runBlock(1, { address: BASE + 0x1000, instrs: 1 }, { x9: new a.NP(HEAP) });
    region.set(buildHeader(a));
    a.leave(a.initHook(), 1);
    assert.ok(await wait);
    assert.deepEqual(json(a.exports.getStatus().foundAt), { reg: "x9", pcOffset: "0x1000" });
});

test("cost model: the default scan runs far fewer callouts and register checks than the old per-instruction scan", (t) => {
    // 200 in-module blocks and 800 elsewhere, 6 instructions each, each block executed 10 times; every
    // block reads two registers. Counts, not wall-clock: the real saving has to be measured on a device
    // via getStatus().stats (see README, "Measuring the scan").
    const run = (cfg) => {
        const a = scanning(cfg);
        for (let b = 0; b < 1000; b++) {
            const address = b < 200 ? BASE + 0x10000 + b * 0x40 : OUTSIDE + b * 0x40;
            const regsRead = Array.from({ length: 6 }, (_, i) => (i === 0 ? ["x8", "w9"] : []));
            for (let rep = 0; rep < 10; rep++) a.runBlock(1, { address, instrs: 6, regsRead }, { x8: new a.NP(1), x9: new a.NP(2) });
        }
        return a.exports.getStatus().stats;
    };
    const before = run({ scanMode: "instruction", scanScope: "all" });
    const after = run({});
    t.diagnostic(`old (instruction/all): callouts=${before.calloutRuns} regChecks=${before.regChecks}`);
    t.diagnostic(`new (block/module):    callouts=${after.calloutRuns} regChecks=${after.regChecks}`);
    assert.equal(before.calloutRuns, 60000);
    assert.equal(after.calloutRuns, 2000);
    assert.ok(after.calloutRuns * 10 <= before.calloutRuns);
    assert.ok(after.regChecks * 100 <= before.regChecks);
});

test("an exception inside the Stalker transform ends the run with a clear reason and unfollows", async () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    const opts = a.stalker.followed.get(1);
    assert.doesNotThrow(() => opts.transform({ next: () => ({ address: undefined }), keep() {}, putCallout() {} }));
    assert.equal(await wait, null);
    assert.match(a.exports.getStatus().reason, /internal error in Stalker transform/);
    assert.equal(a.stalker.followed.size, 0);
});

// ================================================================ P1: phases and lifecycle

test("phases only move forward: idle -> armed -> scanning -> done", async () => {
    const a = setup();
    assert.equal(a.exports.getStatus().phase, "idle");
    a.exports.configure({ headerSize: SIZE });
    assert.equal(a.exports.getStatus().phase, "armed");
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    assert.equal(a.exports.getStatus().phase, "scanning");
    a.leave(a.initHook(), 1);
    await wait;
    const s = a.exports.getStatus();
    assert.equal(s.phase, "done");
    assert.equal(s.outcome, "failed");
});

test("phase is waiting-module until UnityFramework shows up", () => {
    const a = setup({ withModule: false });
    a.exports.configure({ headerSize: SIZE });
    assert.equal(a.exports.getStatus().phase, "waiting-module");
    a.fireModuleAdded(a.mod);
    assert.equal(a.exports.getStatus().phase, "armed");
});

test("timeout while UnityFramework never loaded: says so, detaches the observer, and later loads do nothing", async () => {
    const a = setup({ withModule: false });
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    const wait = a.exports.waitForHeader(2000);
    fire(a.timers.find((t) => t.ms === 2000 && t.live));
    assert.equal(await wait, null);
    const s = a.exports.getStatus();
    assert.equal(s.outcome, "timeout");
    assert.match(s.reason, /^no validated header within 2000ms/);
    assert.match(s.reason, /UnityFramework was never loaded/);
    assert.ok(a.moduleObserver().detached, "module observer must be detached");
    a.fireModuleAdded(a.mod);                        // a late load must not arm anything
    assert.equal(a.hooks.length, 0);
});

test("timeout after il2cpp_init was entered: reason carries the progress, everything is released", async () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE, eagerScan: true });
    const wait = a.exports.waitForHeader(1500);
    a.enter(a.initHook(), {}, 4);
    assert.ok(a.stalker.followed.has(4));
    fire(a.timers.find((t) => t.ms === 1500 && t.live));
    assert.equal(await wait, null);
    const s = a.exports.getStatus();
    assert.match(s.reason, /il2cpp_init entered=true, returned=false, offsetFired=false/);
    assert.equal(a.liveHooks().length, 0, "every Interceptor listener must be detached");
    assert.equal(a.stalker.followed.size, 0);
    assert.deepEqual(a.stalker.unfollowed, [4]);
    const gc = a.timers.find((t) => t.ms === 200 && t.live);
    assert.ok(gc, "a deferred Stalker GC must be scheduled");
    fire(gc);
    assert.equal(a.stalker.gcCalls, 1);
});

test("a captured header releases hooks and the timeout timer too (fast path)", async () => {
    const a = setup();
    a.memory.map(HEAP, buildHeader(a));
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    a.enter(a.offsetHook(), { x21: new a.NP(HEAP) }, 1);
    assert.ok(await wait);
    assert.equal(a.exports.getStatus().outcome, "captured");
    assert.equal(a.liveHooks().length, 0, "the il2cpp_init observer must be gone as well");
    assert.equal(a.liveTimers().length, 0, "the timeout timer must be cleared");
});

test("after the run is over, hooks that are still in flight do nothing", async () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.exports.cancel("test");
    await wait;
    a.enter(a.initHook(), {}, 9);                    // a call that was already running when we detached
    assert.equal(a.stalker.followed.size, 0);
    assert.doesNotThrow(() => a.leave(a.initHook(), 9));
});

test("cancel() ends a pending wait, stops Stalker and detaches everything", async () => {
    const a = setup();
    a.exports.configure({ offset: "0x9000", headerSize: SIZE, eagerScan: true });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 2);
    assert.equal(a.exports.cancel("user pressed Ctrl+C"), "cancelled");
    assert.equal(await wait, null);
    const s = a.exports.getStatus();
    assert.equal(s.outcome, "cancelled");
    assert.equal(s.reason, "user pressed Ctrl+C");
    assert.equal(a.liveHooks().length, 0);
    assert.deepEqual(a.stalker.unfollowed, [2]);
    assert.equal(a.liveTimers().filter((t) => t.ms === 45000).length, 0);
});

test("cancel() after a capture changes nothing", async () => {
    const a = setup();
    a.memory.map(HEAP, buildHeader(a));
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.offsetHook(), { x21: new a.NP(HEAP) }, 1);
    assert.ok(await wait);
    a.exports.cancel("late");
    assert.equal(a.exports.getStatus().outcome, "captured");
    assert.equal(a.exports.getStatus().reason, null);
});

test("dispose() (script unload) cancels an unfinished run and drops the pending GC timer", async () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    a.exports.dispose();
    assert.equal(await wait, null);
    assert.equal(a.exports.getStatus().outcome, "cancelled");
    assert.equal(a.liveTimers().length, 0, "no timer may outlive the script");
    assert.equal(a.stalker.followed.size, 0);
});

test("calling waitForHeader() twice keeps a single live timeout timer", () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    a.exports.waitForHeader(1000);
    a.exports.waitForHeader(2000);
    assert.deepEqual(a.liveTimers().map((t) => t.ms), [2000]);
});

test("an offset that cannot be hooked falls back to the full scan at il2cpp_init entry", () => {
    const a = setup();
    a.failAttach(BASE + HOOK_OFF);
    assert.doesNotThrow(() => a.exports.configure({ offset: "0x9000", headerSize: SIZE }));
    assert.equal(a.exports.getStatus().fastPathFailed, true);
    assert.equal(a.exports.getStatus().resolved, false);
    a.enter(a.initHook(), {}, 1);
    assert.ok(a.stalker.followed.has(1), "the scan must start at il2cpp_init entry");
});

test("an offset that cannot be hooked and no il2cpp_init export fails right away", async () => {
    const a = setup({ exportInit: false });
    a.failAttach(BASE + HOOK_OFF);
    a.exports.configure({ offset: "0x9000", headerSize: SIZE });
    assert.equal(await a.exports.waitForHeader(45000), null);
    assert.match(a.exports.getStatus().reason, /could not hook the offset/);
});

test("Stalker.follow failing without an offset fails immediately, without waiting for the timeout", async () => {
    const a = setup();
    a.stalker.failFollow = "Stalker is not available";
    a.exports.configure({ headerSize: SIZE });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    assert.equal(await wait, null);
    assert.match(a.exports.getStatus().reason, /Stalker\.follow failed: Stalker is not available/);
    assert.equal(a.exports.getStatus().scanError, "Stalker.follow failed: Stalker is not available");
});

test("Stalker.follow failing while the fast path is still pending does not end the run", async () => {
    const a = setup();
    const good = buildHeader(a);
    a.memory.map(HEAP, good);
    a.stalker.failFollow = "nope";
    a.exports.configure({ offset: "0x9000", headerSize: SIZE, eagerScan: true });
    const wait = a.exports.waitForHeader(45000);
    a.enter(a.initHook(), {}, 1);
    assert.equal(a.exports.getStatus().resolved, false);
    a.enter(a.offsetHook(), { x21: new a.NP(HEAP) }, 1);
    assert.ok(same(await wait, good));
});

test("configure() validates the new options and applies nothing when one is bad", () => {
    const a = setup();
    assert.throws(() => a.exports.configure({ headerSize: 512, scanMode: "bogus" }), /scanMode/);
    assert.throws(() => a.exports.configure({ scanScope: "everything" }), /scanScope/);
    assert.throws(() => a.exports.configure({ scanRange: ["0x10"] }), /scanRange/);
    assert.throws(() => a.exports.configure({ scanRange: ["0x20", "0x10"] }), /scanRange/);
    assert.throws(() => a.exports.configure({ scanRange: ["0x10", "0x20"], scanScope: "all" }), /only applies/);
    assert.equal(a.hooks.length, 0, "a rejected configure() must not start the agent");
    a.exports.configure({});
    assert.ok(a.logs.some((l) => /headerSize=1024/.test(l)), "the rejected headerSize=512 must not have leaked in");
});

test("configure() called a second time is ignored", () => {
    const a = setup();
    a.exports.configure({ headerSize: SIZE });
    a.exports.configure({ headerSize: 512, offset: "0x9000" });
    assert.equal(a.hooks.length, 1);
    assert.ok(a.logs.some((l) => /configure\(\) ignored/.test(l)));
});
