/**
 * Back-compat entry point.
 * Prefer: node tests/run.js
 */
import { run } from "../tests/privateAddress.test.js";
import { summary } from "../tests/harness.js";

await run();
const { failed } = summary();
if (failed > 0) process.exit(1);
