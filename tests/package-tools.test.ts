/**
 * A package made with --redact holds none of what a sensitive ledger entry
 * says, nor the objects it cites, and every chain it carries still walks:
 * a redacted line keeps its own hash, which the next line names. The
 * package's verify re-walks the trace, the ledger, its attestations and the
 * journal against the custody verdict's seal, recomputing every entry's core
 * a redaction left readable; holds every packaged work/ file to the index
 * custody sealed; walks the examiner's review; and fails on a part that is
 * missing and not declared absent.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { disputeEntry, initSandbox, recordEntry } from "../extensions/protocol.ts";
import { ledgerChain, redactPackage, verifyPackage, writeComponents } from "../scripts/package-tools.ts";
import { takeCustody } from "../scripts/custody.ts";
import { appendReview } from "../scripts/review.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const SECRET = "123456-654321-111222-333444-555666-777888-999000-121212";

function chained(objs: unknown[]): string {
  let prev = "";
  let out = "";
  for (const o of objs) {
    const line = JSON.stringify({ ...(o as Record<string, unknown>), prev });
    out += `${line}\n`;
    prev = sha(line);
  }
  return out;
}

async function packaged(): Promise<{ root: string; pkg: string }> {
  const root = await mkdtemp(join(tmpdir(), "pkg-tools-"));
  dirs.push(root);
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  const a0 = { sandboxRoot: root, agentId: "a0" };
  await recordEntry(a0, { kind: "finding", value: "The laptop was imaged on 2024-04-05", source: "E01 header", evidence: "ewfinfo", basis: "observed", confidence: "high", indicates: "The acquisition is dated.", confidence_why: "The E01 header records it." });
  await recordEntry(a0, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  await recordEntry({ sandboxRoot: root, agentId: "a1" }, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  await recordEntry(a0, { kind: "event", ts: "2024-04-05T10:00:00Z", value: "The volume was unlocked", source: "System.evtx", evidence: "event 24577" });
  const pkg = join(root, "package");
  await mkdir(join(pkg, "trace"), { recursive: true });
  await mkdir(join(pkg, "board"), { recursive: true });
  await mkdir(join(pkg, "store", "jobs", "j000001"), { recursive: true });
  await cp(join(root, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  await cp(join(root, "ledger", "attestations.jsonl"), join(pkg, "ledger-attestations.jsonl"));
  await cp(join(root, "ledger", "ledger.md"), join(pkg, "ledger.md"));
  const trace = chained([
    { ts: "t", agent: "a0", tool: "bash", args: { command: "sqlite3 NoteStore.sqlite" }, result: { ok: true } },
    { ts: "t", agent: "a0", tool: "record", args: { kind: "ioc", value: `BitLocker recovery key ${SECRET}` }, result: { ok: true } },
    { ts: "t", agent: "a1", tool: "post", args: { body: "the vault opens" }, result: { ok: true } },
  ]);
  await writeFile(join(pkg, "trace", "events.jsonl"), trace);
  await writeFile(join(pkg, "board", "main.md"), `a0: the key is ${SECRET}\n`);
  await writeFile(join(pkg, "store", "jobs", "j000001", "stdout.log"), `recovery key: ${SECRET}\n`);
  // The store's journal, chained: one line's command carries the key.
  let prev: string | null = null;
  let journal = "";
  for (const [i, l] of [{ type: "store_opened" }, { type: "job_accepted", job: "j000001", spec: { kind: "command", command: `pybde --key ${SECRET}` } }, { type: "job_committed", job: "j000001" }].entries()) {
    const raw = JSON.stringify({ v: 1, seq: i, at: "t", ...l, prev });
    journal += `${raw}\n`;
    prev = sha(raw);
  }
  await writeFile(join(pkg, "store", "journal.jsonl"), journal);
  const lines = trace.trim().split("\n");
  await writeFile(join(pkg, "custody.json"), JSON.stringify({ seal: { trace: { lines: 3, last_line_sha256: sha(lines[2]) } } }));
  writeComponents(root, pkg);
  return { root, pkg };
}

test("a redacted package holds none of a sensitive entry's words, and its chains still walk", async () => {
  const { root, pkg } = await packaged();
  // The job log is cited by the sensitive entry through its refs in a real run; here it carries the words.
  const r = await redactPackage(root, pkg);
  assert.equal(r.entries, 1, "a1 recorded the same entry word for word: an attestation, not a second entry");
  assert.equal(r.lines, 4, "one ledger entry, the attestation of it (an act on a sensitive entry), one trace line and one journal line");
  assert.deepEqual(r.leaks, [], "nothing of it is left anywhere in the package");
  for (const f of ["ledger.jsonl", "trace/events.jsonl", "board/main.md", "store/jobs/j000001/stdout.log", "ledger.md", "store/journal.jsonl"]) {
    assert.doesNotMatch(await readFile(join(pkg, f), "utf8"), new RegExp(SECRET), `${f} holds no secret`);
  }
  const log = await readFile(join(pkg, "REDACTIONS.txt"), "utf8");
  assert.match(log, /1 ledger entry was marked sensitive \(seq 2\)/);
  assert.match(log, /[0-9a-f]{64}  [0-9a-f]{64}  trace\/events\.jsonl  1 line\(s\)/);
  const v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Trace:        3 lines, chain intact, 1 redacted \(their hashes kept\); the 3 lines the verdict sealed are there, 0 after/);
  assert.match(v.lines.join("\n"), /Ledger:       3 entries, chain intact, 1 redacted/);
  assert.match(v.lines.join("\n"), /Attestations: 1 lines, chain intact, 1 redacted \(their hashes kept\)/);
  assert.match(v.lines.join("\n"), /Journal:      3 lines, chain intact, 1 redacted/);
  assert.match(v.lines.join("\n"), /Redacted:     this package was made with --redact \(REDACTIONS\.txt\); REDACTIONS\.json records what \d+ redaction\(s\) replaced \(the sha256 of each original, why, which entry\); the leak scan after it found nothing over \d+ file\(s\)/);
});

test("the package's verify finds a chain edited after it was packaged, and a trace that is not the one sealed", async () => {
  const { pkg } = await packaged();
  assert.equal(verifyPackage(pkg).ok, true);
  const ledger = await readFile(join(pkg, "ledger.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger.jsonl"), ledger.replace("imaged on 2024-04-05", "imaged on 2024-04-06"));
  const v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Ledger:       broken at entry 1/);
  await writeFile(join(pkg, "ledger.jsonl"), ledger);
  const trace = await readFile(join(pkg, "trace", "events.jsonl"), "utf8");
  await writeFile(join(pkg, "trace", "events.jsonl"), trace.split("\n").slice(0, 2).join("\n") + "\n");
  const w = verifyPackage(pkg);
  assert.equal(w.ok, false);
  assert.match(w.lines.join("\n"), /THE SEALED LINE IS NOT THE ONE THE VERDICT NAMES/);
  assert.ok((await readdir(pkg)).length > 0);
});

test("after a redaction every readable entry's core is recomputed: one rewritten after the redacted entry is found", async () => {
  const { root, pkg } = await packaged();
  await redactPackage(root, pkg);
  assert.equal(verifyPackage(pkg).ok, true);
  // Entry 3 comes after the redacted entry 2: its prev and hash kept, its words changed.
  const ledger = await readFile(join(pkg, "ledger.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger.jsonl"), ledger.replace("The volume was unlocked", "The volume was never unlocked"));
  const v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Ledger:       broken at entry 3 \(the entry's core was rewritten\)/);
  assert.equal(ledgerChain(ledger).ok, true);
});

test("a part the verdict sealed, or one the package lists as present, cannot be taken out: missing and not declared absent fails", async () => {
  const { pkg } = await packaged();
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean; reason?: string }> };
  assert.deepEqual(components.components.find((c) => c.path === "trace/custody-anchor.json"), { path: "trace/custody-anchor.json", what: "the verdict's anchor, kept outside the run", present: false, reason: "the kickoff wrote no custody anchor for this run" });
  assert.match(verifyPackage(pkg).lines.join("\n"), /Absent:       .*trace\/custody-anchor\.json: the kickoff wrote no custody anchor for this run/);
  // The verdict taken out: the list says it is there.
  const custody = await readFile(join(pkg, "custody.json"), "utf8");
  await rm(join(pkg, "custody.json"));
  let v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Components:   MISSING, AND NOT DECLARED ABSENT OR AGAINST THE SEAL: custody\.json \(declared present\)/);
  // With no list at all (an older package), a core part missing is not declared absent.
  await rm(join(pkg, "COMPONENTS.json"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /custody\.json \(not declared absent\)/);
  // The trace taken out of a package whose verdict sealed it, and declared absent: against the seal, it fails.
  await writeFile(join(pkg, "custody.json"), custody);
  await rm(join(pkg, "trace", "events.jsonl"));
  writeComponents(join(pkg, "no-such-run"), pkg);
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /trace\/events\.jsonl \(the verdict sealed 3 trace lines; declared absent: the run has no trace\)/);
});

/** A run with custody taken and an examiner's sign-off, packaged as swarm.sh package lays it out. */
async function sealedPackage(o: { dispute?: boolean; leads?: boolean; questions?: boolean } = {}): Promise<{ root: string; runs: string; pkg: string }> {
  const runs = await mkdtemp(join(tmpdir(), "pkg-sealed-"));
  dirs.push(runs);
  const root = join(runs, "sp001");
  await initSandbox(root, { reset: true, swarmId: "sp001", agentIds: ["a0"] });
  // A finding as ledger version 4 takes one; refused, the ledger stays empty and there is nothing to sign.
  const r = await recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "finding", value: "The laptop was imaged on 2024-04-05", source: "E01 header", evidence: "ewfinfo", basis: "observed", confidence: "high", indicates: "The image is of the laptop as it stood that day.", confidence_why: "The acquisition header, read directly." });
  if (!r.ok) throw new Error(r.reason);
  await mkdir(join(root, "work", "a0"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "# Report\n\nImaged on 2024-04-05 [#1].\n");
  await writeFile(join(root, "work", "a0", "big.bin"), Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 1)]));
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "sp001", sandbox: root }] }));
  if (o.dispute) {
    const d = await disputeEntry({ sandboxRoot: root, agentId: "a1" }, { seq: 1, why: "the header date is the imager's clock, not checked" });
    assert.equal(d.ok, true, JSON.stringify(d));
  }
  if (o.leads) {
    const L = await import("../extensions/leads.ts");
    const opened = await L.openLead({ sandboxRoot: root, agentId: "a0" }, { title: "Check the imager's clock", why: "The date rests on it", take: true });
    assert.equal(opened.ok, true, JSON.stringify(opened));
    const closed = await L.closeLead({ sandboxRoot: root, agentId: "a0" }, "L-1", { disposition: "resolved", ref: "E-1" });
    assert.equal(closed.ok, true, JSON.stringify(closed));
  }
  if (o.questions) {
    const Q = await import("../extensions/questions.ts");
    const asked = await Q.act(root, { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" }, "open", { text: "Was the imager's clock checked against a reference?", why: "The date rests on it" });
    assert.equal(asked.ok, true, JSON.stringify(asked));
  }
  await takeCustody(root, { runsDir: runs });
  await appendReview(runs, "sp001", root, { action: "sign", examiner: "H. Examiner" });
  const pkg = join(root, "package");
  await mkdir(join(pkg, "work"), { recursive: true });
  await mkdir(join(pkg, "trace"), { recursive: true });
  await cp(join(root, "work", "report.md"), join(pkg, "work", "report.md"));
  // The binary is left in the sandbox, named with its sha256, as package leaves a large one.
  await writeFile(join(pkg, "LEFT-BEHIND.txt"), `Left in the sandbox\n\n${sha(await readFile(join(root, "work", "a0", "big.bin")))}            17  work/a0/big.bin\n`);
  await cp(join(root, "custody.json"), join(pkg, "custody.json"));
  await cp(`${root}.custody-anchor.json`, join(pkg, "trace", "custody-anchor.json"));
  await cp(join(root, "artifacts.json"), join(pkg, "artifacts.sealed.json"));
  await cp(join(root, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  await cp(join(root, "traces", "events.jsonl"), join(pkg, "trace", "events.jsonl"));
  await cp(join(runs, "reviews", "sp001.jsonl"), join(pkg, "review.jsonl"));
  if (o.dispute) await cp(join(root, "ledger", "disputes.jsonl"), join(pkg, "ledger-disputes.jsonl"));
  if (o.leads) {
    await cp(join(root, "leads", "leads.jsonl"), join(pkg, "leads.jsonl"));
    await cp(join(root, "leads", "leads.md"), join(pkg, "leads.md"));
  }
  if (o.questions) {
    await cp(join(root, "questions", "questions.jsonl"), join(pkg, "questions.jsonl"));
    await cp(join(root, "questions", "questions.md"), join(pkg, "questions.md"));
  }
  writeComponents(root, pkg);
  return { root, runs, pkg };
}

test("every packaged work/ file is held to the index custody sealed, and that index to the verdict and its anchor", async () => {
  const { pkg } = await sealedPackage();
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Work files:   every packaged work\/ file is the one custody sealed: 1 as sealed, 1 left in the sandbox with the sealed sha256 \(LEFT-BEHIND\.txt\); the index is the one the verdict and the anchor name/);
  // A packaged report edited after the stop, and a file that was never sealed.
  const report = await readFile(join(pkg, "work", "report.md"), "utf8");
  await writeFile(join(pkg, "work", "report.md"), `${report}Added later.\n`);
  await writeFile(join(pkg, "work", "late.md"), "late\n");
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Work files:   NOT AS SEALED: 1 CHANGED \(work\/report\.md\); 1 NOT IN THE SEALED INDEX \(work\/late\.md\)/);
  await writeFile(join(pkg, "work", "report.md"), report);
  await rm(join(pkg, "work", "late.md"));
  // The sealed index replaced by one that fits the files: it is not the one the verdict names.
  const index = await readFile(join(pkg, "artifacts.sealed.json"), "utf8");
  await writeFile(join(pkg, "artifacts.sealed.json"), index.replace(/"generated_at": "[^"]+"/, '"generated_at": "2030-01-01T00:00:00.000Z"'));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Sealed index: artifacts\.sealed\.json IS NOT THE INDEX THE VERDICT NAMES/);
});

test("the examiner's review travels with the package: its chain is walked and its sign-off said against the ledger and the report there", async () => {
  const { pkg } = await sealedPackage();
  let v = verifyPackage(pkg);
  assert.match(v.lines.join("\n"), /Review:       1 act\(s\), chain intact; signed by H\. Examiner at \S+ over this ledger and this work\/report\.md/);
  // A line put in that does not follow the one before it.
  const review = await readFile(join(pkg, "review.jsonl"), "utf8");
  await writeFile(join(pkg, "review.jsonl"), `${review}${JSON.stringify({ v: 1, seq: 2, action: "accept", entry_seq: 1, prev: "0".repeat(64) })}\n`);
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Review:       CHAIN BROKEN \(line 2 does not follow the line before it\)/);
});

test("the agents' disputes travel with the package: their chain is walked and held to the head the verdict sealed", async () => {
  const { pkg } = await sealedPackage({ dispute: true });
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Disputes:     1 lines, chain intact; head sealed/);
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean }> };
  assert.equal(components.components.find((c) => c.path === "ledger-disputes.jsonl")?.present, true);
  // A dispute's words rewritten: the chain breaks.
  const text = await readFile(join(pkg, "ledger-disputes.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger-disputes.jsonl"), text.replace("not checked", "checked"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Disputes:     CHAIN BROKEN at line 1 \(the line was rewritten\)/);
  // Taken out, and still declared present: named.
  await rm(join(pkg, "ledger-disputes.jsonl"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /ledger-disputes\.jsonl \(declared present\)/);
});

test("the lead register travels with the package, unsigned: its chain is walked and held to the head the verdict sealed", async () => {
  const { pkg } = await sealedPackage({ leads: true });
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Leads:        2 events, chain intact; head sealed/);
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean }> };
  assert.equal(components.components.find((c) => c.path === "leads.jsonl")?.present, true);
  assert.equal(components.components.find((c) => c.path === "leads.md")?.present, true);
  // An event's words rewritten: the chain breaks.
  const text = await readFile(join(pkg, "leads.jsonl"), "utf8");
  await writeFile(join(pkg, "leads.jsonl"), text.replace("imager's clock", "imager's name"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Leads:        CHAIN BROKEN at line 1 \(the line was rewritten\)/);
  // Taken out, and the verdict sealed it: named.
  await rm(join(pkg, "leads.jsonl"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /leads\.jsonl \(declared present\)/);
});

test("the question register travels with the package: its chain is walked and held to the head the verdict sealed", async () => {
  const { pkg } = await sealedPackage({ questions: true });
  let v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Questions:    \d+ events, chain intact; head sealed/);
  const components = JSON.parse(await readFile(join(pkg, "COMPONENTS.json"), "utf8")) as { components: Array<{ path: string; present: boolean }> };
  assert.equal(components.components.find((c) => c.path === "questions.jsonl")?.present, true);
  assert.equal(components.components.find((c) => c.path === "questions.md")?.present, true);
  const text = await readFile(join(pkg, "questions.jsonl"), "utf8");
  await writeFile(join(pkg, "questions.jsonl"), text.replace("against a reference", "against the wall clock"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Questions:    CHAIN BROKEN at line \d+ \(the line was rewritten\)/);
  await rm(join(pkg, "questions.jsonl"));
  v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /questions\.jsonl \(declared present\)/);
});
