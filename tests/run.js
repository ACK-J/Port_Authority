#!/usr/bin/env node
/**
 * Runs every Node-based unit test for Port Authority.
 *
 * Usage:
 *   node tests/run.js
 *   npm test
 */
import { summary, getCounters } from "./harness.js";

const suites = [
    "./privateAddress.test.js",
    "./requestFilter.test.js",
    "./constants.test.js",
    "./allowlist.test.js",
    "./domUtils.test.js",
    "./browserActions.test.js",
    "./BrowserStorageManager.test.js",
    "./manifest.test.js",
];

console.log("Port Authority test suite\n=========================");

for (const path of suites) {
    const mod = await import(path);
    if (typeof mod.run !== "function") {
        console.error(`No run() export in ${path}`);
        process.exit(2);
    }
    try {
        await mod.run();
    } catch (error) {
        console.error(`\nSuite crashed: ${path}`);
        console.error(error);
        process.exit(2);
    }
}

const { failed } = summary();
const { passed } = getCounters();
if (failed > 0) {
    process.exit(1);
}
if (passed === 0) {
    console.error("No assertions ran.");
    process.exit(2);
}
