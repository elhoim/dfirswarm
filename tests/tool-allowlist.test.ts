/**
 * Pi's --tools is an allowlist by name (and with forging on the extension
 * enforces the same list), so a tool the extension registers and swarm.sh
 * does not name is invisible to every agent. publish_file was: in a VM it is
 * the only way a shared file is written, and in run se064eb an agent wrote its
 * report under its own directory, found no way to publish it, and abandoned
 * the run at minute 21 with 2 of 9 finish checks passing.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

async function registeredTools(): Promise<string[]> {
  const dir = join(ROOT, "extensions");
  const names = new Set<string>();
  for (const f of (await readdir(dir)).filter((n) => n.endsWith(".ts"))) {
    const src = await readFile(join(dir, f), "utf8");
    const constants = new Map([...src.matchAll(/export const ([A-Z_]+) = "([a-z_]+)";/g)].map((m) => [m[1], m[2]]));
    for (const m of src.matchAll(/registerTool\(\{\s*name:\s*(?:"([a-z_]+)"|([A-Z_]+))/g)) {
      const name = m[1] ?? constants.get(m[2]);
      assert.ok(name, `${f}: a tool registered under ${m[2]}, a name this test cannot read`);
      names.add(name);
    }
  }
  return [...names].sort();
}

test("every tool the extension registers is one swarm.sh names for Pi", async () => {
  const sh = await readFile(join(ROOT, "scripts", "swarm.sh"), "utf8");
  const base = sh.match(/local PI_TOOLS="([a-z_,]+)"/)?.[1];
  assert.ok(base, "swarm.sh sets no PI_TOOLS");
  const named = new Set(base.split(","));
  for (const m of sh.matchAll(/PI_TOOLS\+=",([a-z_,]+)"/g)) for (const t of m[1].split(",")) named.add(t);
  // With forging on, the extension adds these two to the list it enforces.
  const src = await readFile(join(ROOT, "extensions", "agent-swarm.ts"), "utf8");
  assert.match(src, /\[\.\.\.baseTools, "make_tool", "tools"/);
  named.add("make_tool");
  named.add("tools");
  const tools = await registeredTools();
  assert.ok(tools.includes("publish_file") && tools.includes("self_compact"), `the scan found too little: ${tools.join(", ")}`);
  const missing = tools.filter((t) => !named.has(t));
  assert.deepEqual(missing, [], `registered but never given to Pi: ${missing.join(", ")}`);
});
