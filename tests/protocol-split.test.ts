/**
 * extensions/protocol.ts is an index over four modules: the core, the rules
 * over the ledger, the sensitive words and the finish line. The split keeps
 * three things true:
 * - the dependency direction: a lower module never imports a higher one
 *   statically. The core reaches the rules and the sensitive words by a
 *   dynamic import, so no static cycle forms;
 * - every name replay reads from a checkout's extensions/protocol.ts by name
 *   is still there;
 * - each module loads first in a fresh process.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";

const ROOT = join(import.meta.dirname, "..");
const ORDER = ["protocol-core", "ledger-rules", "sensitive", "finish-line"] as const;

/** The modules a file imports at runtime (never `import type`), by their names under extensions/. */
function runtimeImports(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/^import\s+(?!type\s)[^;]*?from\s+"\.\/([\w-]+)\.ts";/gms)) out.push(m[1]!);
  return out;
}

test("the index re-exports the four modules and holds nothing else", async () => {
  const index = await readFile(join(ROOT, "extensions", "protocol.ts"), "utf8");
  const code = index.replace(/\/\*[\s\S]*?\*\//g, "").split("\n").map((l) => l.trim()).filter(Boolean);
  assert.deepEqual(code, ORDER.map((m) => `export * from "./${m}.ts";`));
});

test("a lower module never imports a higher one statically", async () => {
  for (const [i, m] of ORDER.entries()) {
    const higher = new Set<string>(ORDER.slice(i + 1));
    const imports = runtimeImports(await readFile(join(ROOT, "extensions", `${m}.ts`), "utf8"));
    const up = imports.filter((x) => higher.has(x) || x === "protocol");
    assert.deepEqual(up, [], `${m}.ts imports ${up.join(", ")} statically: reach a higher module by a dynamic import`);
  }
});

test("every function replay reads from a checkout's protocol.ts by name is exported there", async () => {
  const replay = await readFile(join(ROOT, "scripts", "replay.ts"), "utf8");
  const names = [...new Set([...replay.matchAll(/fn\(Pm?, "([A-Za-z_$][\w$]*)"\)/g)].map((m) => m[1]!))].sort();
  assert.ok(names.length >= 10, `replay reads ${names.length} names`);
  const missing = names.filter((n) => typeof (P as Record<string, unknown>)[n] !== "function");
  assert.deepEqual(missing, [], `replay reads ${missing.join(", ")} from protocol.ts, which no longer exports them`);
});

test("each module, and the index, loads first in a fresh process", () => {
  for (const m of [...ORDER, "protocol"]) {
    const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "-e", `import(${JSON.stringify(join(ROOT, "extensions", `${m}.ts`))}).then((x) => { if (!Object.keys(x).length) process.exit(3); })`], { encoding: "utf8" });
    assert.equal(r.status, 0, `${m}.ts did not load first: ${r.stderr}`);
  }
});
