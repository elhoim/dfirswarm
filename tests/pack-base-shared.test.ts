/**
 * computer-forensics-base: the new tools carry blocks of code that other packs' tools carry too, so that every pack
 * withholds the same strings and ends a program the same way. The base pack ships on its own, so it cannot import them;
 * each copy is the same text, and this suite holds the base copies equal to the network pack's, which holds the block to a
 * table of strings in tests/pack-network-withholding.test.ts.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const ROOT = join(import.meta.dirname, "..", "packs");
const BASE = (name: string) => join(ROOT, "computer-forensics-base", "tools", name, "run.py");
const NETWORK = join(ROOT, "network-forensics", "tools", "pcap_extract", "run.py");

async function block(path: string, name: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const begin = `# BEGIN SHARED ${name}`;
  const end = `# END SHARED ${name}`;
  const start = text.indexOf(begin);
  const stop = text.indexOf(end);
  assert.ok(start >= 0 && stop > start, `${path} carries the ${name} block`);
  assert.equal(text.indexOf(begin, start + 1), -1, `${path} carries it once`);
  return text.slice(start, stop + end.length);
}

test("archive_extract withholds what the network pack's tools withhold: the block is the same text", async () => {
  const network = await block(NETWORK, "WITHHOLDING");
  assert.ok(network.length > 5000);
  assert.equal(await block(BASE("archive_extract"), "WITHHOLDING"), network);
});

test("archive_extract ends a program the way the network pack's engine tools do: the process block is the same text and nothing starts a session", async () => {
  const network = await block(NETWORK, "PROCESS");
  assert.equal(await block(BASE("archive_extract"), "PROCESS"), network);
  const text = await readFile(BASE("archive_extract"), "utf8");
  const code = text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
  assert.doesNotMatch(code, /start_new_session|setsid|process_group/, "archive_extract starts a program outside the tool's process group");
});
