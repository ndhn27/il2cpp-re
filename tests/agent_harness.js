// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ndhn27

// A tiny fake of the Frida runtime, just enough to load agents/dump_clean_header_v4.js in Node and
// drive its hooks by hand. It checks the agent's LOGIC (hook ordering, fallback decisions, scan scope,
// cleanup, validation); it says nothing about how real Frida / a real device behaves.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const AGENT_PATH = process.env.AGENT_PATH || path.join(__dirname, "..", "agents", "dump_clean_header_v4.js");

class FakeMemory {
    constructor() {
        this.regions = []; // { base: BigInt, data: Uint8Array, prot: "r--" }
    }
    map(base, data, prot = "r--") {
        this.regions.push({ base: BigInt(base), data, prot });
    }
    find(addr) {
        return this.regions.find((r) => addr >= r.base && addr < r.base + BigInt(r.data.length));
    }
    read(addr, n) {
        const out = new Uint8Array(n);
        let got = 0;
        while (got < n) {
            const cur = addr + BigInt(got);
            const r = this.find(cur);
            if (!r || r.prot[0] !== "r") throw new Error(`access violation accessing 0x${cur.toString(16)}`);
            const off = Number(cur - r.base);
            const take = Math.min(r.data.length - off, n - got);
            out.set(r.data.subarray(off, off + take), got);
            got += take;
        }
        return out.buffer;
    }
}

function loadAgent({ memory = new FakeMemory(), modules = {} } = {}) {
    class NP {
        constructor(v) { this.v = BigInt(v); }
        static of(x) { return x instanceof NP ? x.v : BigInt(x); }
        add(n) { return new NP(this.v + NP.of(n)); }
        sub(n) { return new NP(this.v - NP.of(n)); }
        shr(n) { return new NP(this.v >> BigInt(n)); }
        isNull() { return this.v === 0n; }
        compare(o) { const b = NP.of(o); return this.v < b ? -1 : this.v > b ? 1 : 0; }
        toString() { return "0x" + this.v.toString(16); }
        readU32() { return new DataView(memory.read(this.v, 4)).getUint32(0, true); }
        readByteArray(n) { return memory.read(this.v, n); }
    }

    const logs = [];
    const timers = [];
    const hooks = []; // { addr, cbs, detached }
    const attachFailures = new Set();
    const stalker = {
        followed: new Map(),
        unfollowed: [],
        gcCalls: 0,
        failFollow: null,       // a message: makes Stalker.follow() throw
        compiled: new Map(),    // "tid:address" -> compiled block (like Stalker's translation cache)
        transforms: 0,          // times transform() ran (once per compiled block)
        calloutRuns: 0,         // times any callout ran
    };
    let moduleObserver = null;

    const sandbox = {
        console: { log: (...a) => logs.push(a.map(String).join(" ")) },
        ptr: (x) => new NP(x),
        rpc: {},
        setTimeout: (fn, ms) => { timers.push({ fn, ms, live: true }); return timers.length - 1; },
        clearTimeout: (id) => { if (timers[id]) timers[id].live = false; },
        Process: {
            getModuleByName: (name) => {
                if (!modules[name]) throw new Error(`unable to find module '${name}'`);
                return modules[name];
            },
            attachModuleObserver: (cbs) => {
                moduleObserver = { cbs, detached: false, detach() { this.detached = true; } };
                return moduleObserver;
            },
            findRangeByAddress: (p) => {
                const r = memory.find(p.v);
                return r ? { base: new NP(r.base), size: r.data.length, protection: r.prot } : null;
            },
        },
        Interceptor: {
            attach: (addr, cbs) => {
                if (attachFailures.has(addr.toString())) throw new Error(`unable to intercept function at ${addr}`);
                const rec = { addr: addr.toString(), cbs, detached: false };
                hooks.push(rec);
                return { detach: () => { rec.detached = true; } };
            },
        },
        Stalker: {
            follow: (tid, opts) => {
                if (stalker.failFollow) throw new Error(stalker.failFollow);
                stalker.followed.set(tid, opts);
            },
            unfollow: (tid) => { stalker.followed.delete(tid); stalker.unfollowed.push(tid); },
            garbageCollect: () => { stalker.gcCalls++; },
        },
    };
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(AGENT_PATH, "utf8"), ctx, { filename: AGENT_PATH });
    const evalIn = (code) => vm.runInContext(code, ctx);

    // A fake module: exports is { name: offset-number }.
    const makeModule = (name, base, exports, size = 0x1000000) => ({
        name,
        base: new NP(base),
        size,
        getExportByName(n) {
            if (!(n in exports)) throw new Error(`unable to find export '${n}'`);
            return new NP(base + exports[n]);
        },
    });

    // Runs one execution of one basic block under Stalker, the way Frida does:
    //   * transform() runs ONCE per (thread, block address) - later executions reuse the translation;
    //   * a callout put before the Nth keep() runs before the Nth instruction;
    //   * callouts see `context` plus `pc` (address of the instruction they precede).
    // block = { address, instrs: n, regsRead?: [[names for instr 0], [names for instr 1], ...] }
    function runBlock(tid, block, context = {}) {
        const opts = stalker.followed.get(tid);
        if (!opts) return false;
        const base = BigInt(block.address);
        const key = `${tid}:${base}`;
        let compiled = stalker.compiled.get(key);
        if (!compiled) {
            compiled = [];                      // [{ before: instructionIndex, fn }]
            let next = 0;
            let kept = 0;
            const instrAt = (i) => ({
                address: new NP(base + BigInt(4 * i)),
                regsRead: block.regsRead ? block.regsRead[i] || [] : undefined,
            });
            opts.transform({
                next: () => (next < block.instrs ? instrAt(next++) : null),
                keep: () => { kept++; },
                putCallout: (fn) => compiled.push({ before: kept, fn }),
            });
            stalker.compiled.set(key, compiled);
            stalker.transforms++;
        }
        for (let i = 0; i <= block.instrs; i++) {
            for (const c of compiled.filter((x) => x.before === i)) {
                if (!stalker.followed.has(tid)) return true; // unfollowed meanwhile (e.g. header found)
                const view = Object.create(context);
                view.pc = new NP(base + BigInt(4 * Math.min(i, block.instrs - 1)));
                stalker.calloutRuns++;
                c.fn(view);
            }
        }
        return true;
    }

    const firstModule = () => Object.values(modules)[0];

    return {
        NP, memory, logs, timers, hooks, stalker, makeModule, runBlock,
        exports: sandbox.rpc.exports,
        validateHeader: (buf, lenient) => evalIn("validateHeader")(buf, lenient),
        headerFields: () => evalIn("HEADER_FIELDS"),
        liveHooks: () => hooks.filter((h) => !h.detached),
        liveTimers: () => timers.filter((t) => t.live),
        hookAt: (addr) => hooks.find((h) => h.addr === (addr instanceof NP ? addr.toString() : "0x" + BigInt(addr).toString(16))),
        failAttach: (addr) => attachFailures.add("0x" + BigInt(addr).toString(16)),
        enter(hook, regs = {}, tid = 1) { hook.cbs.onEnter.call({ context: regs, threadId: tid }); },
        leave(hook, tid = 1) { if (hook.cbs.onLeave) hook.cbs.onLeave.call({ threadId: tid }); },
        addModule(name, mod) { modules[name] = mod; },
        fireModuleAdded(mod) { moduleObserver.cbs.onAdded(mod); },
        moduleObserver: () => moduleObserver,
        // Convenience: executes ONE in-module 3-instruction block once per context.
        execute(tid, contexts, address) {
            const mod = firstModule();
            const addr = address !== undefined ? address : (mod ? mod.base.v + 0x1000n : 0x1000n);
            if (!stalker.followed.has(tid)) return false;
            for (const c of contexts) {
                if (!runBlock(tid, { address: addr, instrs: 3 }, c)) break;
            }
            return true;
        },
    };
}

module.exports = { loadAgent, FakeMemory, AGENT_PATH };
