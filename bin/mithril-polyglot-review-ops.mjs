#!/usr/bin/env node
/**
 * mithril-polyglot-review-ops — fixed entrypoint wrapper.
 *
 * Registry workflow contract: node fixed entrypoint (bin/<id>.mjs,
 * json-stdin). Forwards to the owning profile's Python tick
 * (scripts/polyglot_review_tick.py) which carries all test,
 * measurement, git-sync and R2/Drive archive logic.
 *
 * The json-stdin object is ignored by the tick (targets come from the
 * profile's data/canonical/targets.json); the wrapper validates that it
 * is a JSON object and reports the tick's stdout/exit code verbatim.
 */
"use strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

let stdin = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (stdin += d));
process.stdin.on("end", () => {
  if (stdin.trim()) {
    let obj;
    try { obj = JSON.parse(stdin); } catch {
      console.error("POLYGLOT-STDFIN\tFAILED not json");
      process.exit(2);
    }
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
      console.error("POLYGLOT-STDFIN\tFAILED not object");
      process.exit(2);
    }
  }
  const tick =
    process.env.POLYGLOT_TICK ||
    fileURLToPath(
      new URL("../skills/security/mithril-polyglot-review-ops/scripts/polyglot_review_tick.py", import.meta.url));
  const child = spawn("python3", [tick],
    { stdio: ["inherit", "inherit", "inherit"], env: process.env });
  child.on("error", (err) => {
    console.error(`POLYGLOT-TICK\tFAILED spawn ${err.message}`);
    process.exit(2);
  });
  child.on("close", (code) => process.exit(code ?? 1));
});
