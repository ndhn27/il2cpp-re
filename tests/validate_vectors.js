// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ndhn27

// Reads [{hex, lenient}] from stdin, runs the agent's validateHeader() on each and prints the verdicts
// as JSON. Used by test_validate_header.py to compare the JS and Python validators.
const { loadAgent } = require("./agent_harness");

const agent = loadAgent();
let input = "";
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
    const results = JSON.parse(input).map(({ hex, lenient }) => {
        const bytes = Buffer.from(hex, "hex");
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length);
        const r = agent.validateHeader(ab, lenient);
        return { ok: r.ok, layout: r.layout, errors: r.errors, warnings: r.warnings };
    });
    process.stdout.write(JSON.stringify(results));
});
