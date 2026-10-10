#!/usr/bin/env node
/**
 * mithril-bounty-vrf-ops — fixed entrypoint wrapper.
 *
 * The registry workflow contract requires a node fixed entrypoint
 * (bin/<id>.mjs, json-stdin). This wrapper binds that contract to the
 * owning profile's Python tick, which carries all review, R2, Drive and
 * Drive-API sheet write-back logic (skills/security/mithril-bounty-vrf/
 * scripts/bounty_vrf_tick.py, deployed into <profile>/scripts/).
 *
 * stdin (json-stdin): the tick's own arguments are taken from the
 * process environment (BBOPS_CASE, BBOPS_PROFILE_DIR, ...); the wrapper
 * only forwards the environment and reports the tick's stdout/exit code.
 * A json-stdin object may optionally carry {"case":"BB-XXXX"} to force
 * the case binding for this run; it is otherwise ignored.
 */
"use strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2).filter((a) => a !== "--stdin");
let stdin = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (stdin += d));
process.stdin.on("end", () => {
  if (stdin.trim()) {
    let obj;
    try {
      obj = JSON.parse(stdin);
    } catch {
      console.error("BOUNTY-VRF-STDFIN\tFAILED not json");
      process.exit(2);
    }
    if (obj && typeof obj === "object" && typeof obj.case === "string") {
      process.env.BBOPS_CASE = obj.case;
    }
  }
  const tick =
    process.env.BBOPS_TICK ||
    [
      fileURLToPath(new URL("../skills/security/mithril-bounty-vrf/scripts/bounty_vrf_tick.py", import.meta.url)),
    ].join("");
  const child = spawn("python3", [tick, ...args],
    { stdio: ["inherit", "inherit", "inherit"], env: process.env });
  child.on("error", (err) => {
    console.error(`BOUNTY-VRF-TICK\tFAILED spawn ${err.message}`);
    process.exit(2);
  });
  child.on("close", (code) => process.exit(code ?? 1));
});
