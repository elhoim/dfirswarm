/**
 * The extension is the one file tsc cannot see: it imports Pi's own package,
 * which is not a dependency of this repository, so `npm run typecheck` leaves
 * it out. That blind spot shipped a real bug — `nameOf` and `claimName` were
 * called without being imported, the extension threw "nameOf is not defined"
 * while building every system prompt, and a live forensic run lost its naming
 * tool without anything failing loudly.
 *
 * This is the cheap version of the check tsc would do: every protocol function
 * the extension calls has to be in the import list it reads from.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("the extension imports every protocol function it calls", async () => {
  const protocol = await readFile(join(root, "extensions/protocol.ts"), "utf8");
  const extension = await readFile(join(root, "extensions/agent-swarm.ts"), "utf8");

  const exported = new Set<string>();
  for (const m of protocol.matchAll(/^export (?:async )?function ([A-Za-z_][A-Za-z0-9_]*)/gm)) {
    exported.add(m[1]);
  }
  assert.ok(exported.size > 20, "the protocol should export plenty of functions");

  const importBlock = extension.match(/import \{([^}]*)\} from "\.\/protocol\.ts";/s);
  assert.ok(importBlock, "the extension imports from the protocol");
  const imported = new Set(
    importBlock[1]
      .split(",")
      .map((s) => s.replace(/^\s*type\s+/, "").trim())
      .filter(Boolean),
  );

  // Anything the extension declares itself is its own, not the protocol's.
  const declared = new Set<string>();
  for (const m of extension.matchAll(/(?:function|const|let)\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
    declared.add(m[1]);
  }

  const missing = new Set<string>();
  for (const m of extension.matchAll(/(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)) {
    const name = m[1];
    if (!exported.has(name) || imported.has(name) || declared.has(name)) continue;
    missing.add(name);
  }

  assert.deepEqual(
    [...missing].sort(),
    [],
    `the extension calls these protocol functions without importing them: ${[...missing].sort().join(", ")}`,
  );
});

test("the 15s cap timer and the cheap stop check also enforce the per-agent cap", async () => {
  const extension = await readFile(join(root, "extensions/agent-swarm.ts"), "utf8");
  const maybe = extension.match(/async function maybeEnforceStops[\s\S]*?\n  \}/);
  assert.ok(maybe, "maybeEnforceStops should be in the extension");
  assert.match(maybe[0], /enforceAllCaps|enforceAgentCap/, "a long bash must still hit the per-agent cap");
  const watch = extension.match(/function watchCaps[\s\S]*?\n  \}/);
  assert.ok(watch, "watchCaps should be in the extension");
  assert.match(watch[0], /enforceAllCaps|enforceAgentCap/, "the 15s timer must still hit the per-agent cap");
});
