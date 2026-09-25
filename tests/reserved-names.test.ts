// Every name the harness writes into the trace is one a forged tool may not
// take. A forged tool's calls are recorded under its own name, so a tool
// called `hub_call` or `vm_finish` would have its lines read as the hub's.
// The list is kept by hand; this test is what keeps it whole.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { TOOL_RESERVED_NAMES } from "../extensions/protocol.ts";

const ROOT = join(import.meta.dirname, "..");

async function sources(): Promise<Array<{ file: string; text: string }>> {
  const out: Array<{ file: string; text: string }> = [];
  for (const dir of ["extensions", "scripts"]) {
    for (const name of await readdir(join(ROOT, dir))) {
      if (!/\.(ts|mjs|sh)$/.test(name)) continue;
      out.push({ file: `${dir}/${name}`, text: await readFile(join(ROOT, dir, name), "utf8") });
    }
  }
  return out;
}

test("every event name the harness writes is reserved against forged tools", async () => {
  const patterns = [
    // the extension: logEvent(cwd, agent, "name", ...)
    /logEvent\([^,()]+,\s*[^,()]+,\s*"([a-z_]+)"/g,
    // the hub: this.event("name", ...) and a two-way choice of names
    /\bevent\(\s*"([a-z_]+)"/g,
    /event\(\s*[^"()]+\?\s*"([a-z_]+)"\s*:\s*"([a-z_]+)"/g,
    // the shell watchdogs: jq -n '{..., tool: "name", ...}'
    /\btool:\s*"([a-z_]+)"/g,
  ];
  const missing = new Map<string, string>();
  for (const { file, text } of await sources()) {
    for (const re of patterns) {
      for (const m of text.matchAll(re)) {
        for (const name of m.slice(1)) {
          if (name && !TOOL_RESERVED_NAMES.has(name)) missing.set(name, file);
        }
      }
    }
  }
  assert.deepEqual(
    [...missing].map(([n, f]) => `${n} (${f})`),
    [],
    "a harness event name a forged tool could also take: add it to TOOL_RESERVED_NAMES",
  );
});
