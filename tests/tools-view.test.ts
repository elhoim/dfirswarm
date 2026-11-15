/**
 * The `tools` answer: one line a tool by default, one tool whole by name.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ABOUT_MAX, aboutLine, toolsListing, type ToolRow } from "../extensions/tools-view.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Every tool of every pack in the checkout, as a run with all packs would hold them. */
function everyPackTool(): ToolRow[] {
  const out: ToolRow[] = [];
  for (const pack of readdirSync(join(ROOT, "packs"))) {
    let tools: string[] = [];
    try { tools = readdirSync(join(ROOT, "packs", pack, "tools")); } catch { continue; }
    for (const t of tools) {
      try {
        const m = JSON.parse(readFileSync(join(ROOT, "packs", pack, "tools", t, "manifest.json"), "utf8")) as { name?: string; description?: string; example?: string };
        out.push({ name: m.name ?? t, description: m.description, example: m.example, pack, params: { path: "string" } });
      } catch { /* a directory that is not a tool */ }
    }
  }
  return out;
}

test("the list is one line a tool, grouped by pack, and is about 8,000 characters with every pack's tools in it", () => {
  const all = [...everyPackTool(), { name: "azr_try", description: "Tries a key on a file. And more.", by: "a1", pack: null }];
  assert.ok(all.length > 80, `the checkout's packs hold ${all.length} tools`);
  const whole = JSON.stringify(all).length;
  const l = toolsListing(all);
  assert.ok(l.ok && "packs" in l);
  if (!l.ok || !("packs" in l)) return;
  // What the model reads: the answer pretty-printed (protocol-core.ts toolText). It was 18,367 characters for 153 tools.
  const seen = `${JSON.stringify(l, null, 2)}\n`.length;
  assert.ok(seen <= 300 + 55 * all.length, `the list is ${seen} characters for ${all.length} tools (the tools whole are ${whole})`);
  if (all.length <= 160) assert.ok(seen < 9_000, `the list is ${seen} characters`);
  assert.equal(l.forged, "azr_try: Tries a key on a file (by a1)");
  assert.ok(Object.keys(l.packs).includes("computer-forensics-base"));
  assert.deepEqual(Object.keys(l.packs), [...Object.keys(l.packs)].sort(), "the packs in name order");
  assert.equal(l.count, all.length);
  const lines = Object.values(l.packs).flatMap((p) => p.split("\n"));
  assert.equal(lines.length, all.length - 1, "every pack tool has its line");
  assert.ok(lines.every((line) => line.length <= 80), lines.find((line) => line.length > 80));
});

test("a name gives that tool whole; a name nobody has gives the nearest", () => {
  const all: ToolRow[] = [{ name: "regkv", description: "Reads a key.", pack: "windows-forensics", example: "{}", params: { hive: "string" } }, { name: "registry_recover", description: "Replays logs.", pack: "windows-forensics" }];
  const one = toolsListing(all, "regkv");
  assert.deepEqual(one, { ok: true, tool: all[0] });
  assert.deepEqual(toolsListing(all, "REGKV"), { ok: true, tool: all[0] });
  const none = toolsListing(all, "reg");
  assert.equal(none.ok, false);
  if (!none.ok) assert.deepEqual(none.nearest, ["regkv", "registry_recover"]);
  assert.equal(toolsListing([]).ok, true);
});

test("a tool's line is what its description says first, in a few words, its asides left out and a capital label kept", () => {
  assert.equal(aboutLine("Reads a hive. Then more."), "Reads a hive");
  assert.equal(aboutLine("Read an export (JSON, CSV or a directory of them) offline; and more."), "Read an export offline");
  assert.equal(aboutLine("Scan a local file, or one inode streamed from an image through icat, for needles."), "Scan a local file, or one inode…");
  assert.equal(aboutLine("SENSITIVE: decrypt the logins a browser saved from a profile."), "sensitive: decrypt the logins a…");
  assert.ok(aboutLine("x".repeat(500)).length <= ABOUT_MAX);
  assert.ok(aboutLine("word ".repeat(100)).length <= ABOUT_MAX);
  assert.equal(aboutLine(undefined), "");
});
