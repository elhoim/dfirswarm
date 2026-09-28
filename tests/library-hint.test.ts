/**
 * Library visibility (B20, docs/adr/0016): at a command job's admission the
 * hub names the run's library tools whose manifest `use` (extension, first
 * bytes, name) or, failing a `use`, description matches what the job
 * declared; a hint only. The library's own manifests say what they read.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { commandNames, extensionOf, libraryHint, matchTool } from "../scripts/library-hint.ts";
import { resolveScope } from "../scripts/job-scope.ts";
import { boardTable } from "../scripts/vm-hub.ts";
import { JobService } from "../scripts/job-service.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const SQLITE_HEAD = Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(84)]);

function tool(S: string, name: string, manifest: Record<string, unknown>): void {
  mkdirSync(join(S, "tools", name), { recursive: true });
  const body = "print('x')\n";
  writeFileSync(join(S, "tools", name, "run.py"), body);
  writeFileSync(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, params: {}, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex"), ...manifest }));
}

function rig() {
  const S = join(mkdtempSync(join(tmpdir(), "libhint-")), "run");
  for (const d of ["inputs/phone", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "phone", "sms.db"), SQLITE_HEAD);
  writeFileSync(join(S, "inputs", "phone", "unnamed"), SQLITE_HEAD);
  writeFileSync(join(S, "inputs", "phone", "History"), SQLITE_HEAD);
  writeFileSync(join(S, "inputs", "Security.evtx"), Buffer.from("ElfFile\0rest"));
  writeFileSync(join(S, "inputs", "notes.txt"), "plain\n");
  listInputs(S);
  tool(S, "sqlite_reader", { description: "Read a database.", use: { extensions: [".db", ".sqlite"], magic: [{ offset: 0, hex: "53514c69746520666f726d6174203300" }] } });
  tool(S, "browser_reader", { description: "Read a browser's history.", use: { names: ["History", "places.sqlite"] } });
  tool(S, "evtx_reader", { description: "Parse an EVTX file and list its events." });
  tool(S, "grepper", { description: "Grep catalog/x/filelist.txt for a pattern." });
  return S;
}

test("a manifest's use matches by extension, first bytes and name; without one, the description must name the extension as a word", () => {
  const sqlite = { name: "s", description: "d", use: { extensions: [".DB"], magic: [{ offset: 0, hex: "53514c697465" }] } };
  assert.deepEqual(matchTool(sqlite, { input: "input:a.db", path: "inputs/a.db", head: null }).map((m) => m.by), ["extension"]);
  assert.deepEqual(matchTool(sqlite, { input: "input:x", path: "inputs/x", head: SQLITE_HEAD }).map((m) => `${m.by} ${m.what}`), ["magic 53514c697465 at offset 0"]);
  assert.deepEqual(matchTool(sqlite, { input: "input:x", path: "inputs/x", head: Buffer.from("not it") }), []);
  assert.deepEqual(matchTool({ name: "u", use: { names: ["$I*"] } }, { input: "i", path: "inputs/$Recycle.Bin/$IABC123.txt", head: null }).map((m) => m.by), ["name"]);
  assert.deepEqual(matchTool({ name: "e", description: "Parse an EVTX file" }, { input: "i", path: "inputs/Security.evtx", head: null }).map((m) => m.what), ["its description names EVTX"]);
  assert.deepEqual(matchTool({ name: "g", description: "Grep catalog/x/filelist.txt" }, { input: "i", path: "inputs/notes.txt", head: null }), [], "a word inside a path is not the file's kind");
  assert.deepEqual(matchTool({ name: "e", description: "Parse an EVTX file", use: {} }, { input: "i", path: "inputs/Security.evtx", head: null }), [], "a manifest that says what it reads is held to it");
  assert.equal(extensionOf("inputs/disk.E01"), "e01");
  assert.equal(extensionOf("inputs/.hidden"), null);
  assert.equal(extensionOf("inputs/History"), null);
  assert.equal(commandNames("python3 tools/sqlite_reader/run.py", "sqlite_reader"), true);
  assert.equal(commandNames("sqlite3 x.db", "sqlite_reader"), false);
});

test("the hint for a job's declared objects: each tool with what it matched, a directory's files from its record", async () => {
  const S = rig();
  const r = await resolveScope(S, ["input:phone/", "input:Security.evtx", "input:notes.txt"]);
  assert.ok(r.ok);
  const hint = await libraryHint(S, r.ok ? r.objects : []);
  assert.ok(hint);
  const by = new Map(hint!.tools.map((t) => [t.tool, t.matched.map((m) => `${m.input} ${m.by}`).sort()]));
  assert.deepEqual(by.get("sqlite_reader"), ["input:phone/History magic", "input:phone/sms.db extension", "input:phone/sms.db magic", "input:phone/unnamed magic"]);
  assert.deepEqual(by.get("browser_reader"), ["input:phone/History name"]);
  assert.deepEqual(by.get("evtx_reader"), ["input:Security.evtx description"]);
  assert.equal(by.has("grepper"), false);
  assert.equal(hint!.examined, 5);
  assert.match(hint!.note, /A hint, not a rule/);
  const skipped = await libraryHint(S, r.ok ? r.objects : [], { skip: (t) => t === "sqlite_reader" });
  assert.ok(!skipped!.tools.some((t) => t.tool === "sqlite_reader"), "a tool the job already runs is not offered to it");
  assert.equal(await libraryHint(S, []), null);
});

test("the hub's admission answer carries the hint for a command job that declared its inputs, and none otherwise", async () => {
  const S = rig();
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  const table = boardTable({ sandbox: S, settle: async () => undefined, wrote: () => undefined, ids: ["a1"], jobs: () => svc });
  const call = (fn: string, arg: unknown) => (table as Record<string, (w: string, a: unknown[], s: AbortSignal) => Promise<unknown>>)[fn]("a1", [S, arg], new AbortController().signal) as Promise<Record<string, any>>;
  await svc.start();
  const declared = await call("jobSubmit", { command: "sqlite3 inputs/phone/sms.db .tables > \"$OUT/t.txt\"", inputs: ["input:phone/sms.db"] });
  assert.equal(declared.ok, true, JSON.stringify(declared));
  assert.deepEqual(declared.library.tools.map((t: { tool: string }) => t.tool), ["sqlite_reader"]);
  assert.match(declared.library.note, /A hint, not a rule/);
  const all = await call("jobSubmit", { command: "ls inputs", inputs: ["all"] });
  assert.equal(all.ok, true);
  assert.equal(all.library, undefined, "a job that could read everything gets no hint: what it reads is not declared");
  const runs = await call("jobSubmit", { command: "python3 tools/sqlite_reader/run.py", inputs: ["input:phone/sms.db"] });
  assert.equal(runs.library, undefined, "the tool it runs is not offered again");
  await svc.stop("test over");
});

test("the library's manifests say what they read, in a form the hint can use", () => {
  const LIB = join(ROOT, "tool-library");
  const withUse = [];
  for (const name of readdirSync(LIB)) {
    let m: { use?: { extensions?: unknown; magic?: unknown; names?: unknown } };
    try {
      m = JSON.parse(readFileSync(join(LIB, name, "manifest.json"), "utf8"));
    } catch {
      continue;
    }
    if (!m.use) continue;
    withUse.push(name);
    for (const e of (m.use.extensions as string[] | undefined) ?? []) assert.match(e, /^\.[a-z0-9]+$/, `${name}: ${e}`);
    for (const g of (m.use.magic as Array<{ offset: number; hex: string }> | undefined) ?? []) {
      assert.ok(Number.isInteger(g.offset) && g.offset >= 0, `${name}: offset`);
      assert.match(g.hex, /^([0-9a-f]{2})+$/, `${name}: hex`);
    }
    for (const n of (m.use.names as string[] | undefined) ?? []) assert.ok(typeof n === "string" && n.length > 0, `${name}: name`);
  }
  assert.ok(withUse.length >= 15, `the library says what its readers read: ${withUse.join(", ")}`);
  const sqlite = JSON.parse(readFileSync(join(LIB, "sqlite_query", "manifest.json"), "utf8"));
  assert.equal(matchTool(sqlite, { input: "input:x", path: "inputs/x", head: SQLITE_HEAD })[0]?.by, "magic");
  const evtx = JSON.parse(readFileSync(join(LIB, "evtx_query", "manifest.json"), "utf8"));
  assert.equal(matchTool(evtx, { input: "input:Security.evtx", path: "inputs/Security.evtx", head: null })[0]?.by, "extension");
});
