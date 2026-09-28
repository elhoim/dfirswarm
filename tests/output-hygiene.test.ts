/**
 * Output hygiene (docs/adr/0016): a job run with secret_output seals every
 * output sensitive; a job that reads one (by path, or with no scope and its
 * command naming the job) seals sensitive output too, as derived; an entry
 * citing one is recorded sensitive; a redacted package withholds them whole,
 * names what it withheld and scans every file for what should not be there
 * (a small output's own text included); a package made without --redact
 * names what in it is sensitive; the export treats an unmarked entry citing
 * one as sensitive; and the kept output of a cancelled job cited later is a
 * defect until the citing entry says how it treats it.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { exportLedger } from "../scripts/export.ts";
import { describe, JobService } from "../scripts/job-service.ts";
import { derivedFrom, secretShaped, sensitiveEntries, sensitiveIndex, sensitiveRefs } from "../scripts/output-hygiene.ts";
import { hygieneReport, redactPackage } from "../scripts/package-tools.ts";
import { localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const F = { basis: "observed", confidence: "medium", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
/** A value a job writes and the run treats as secret: a placeholder, never a real credential. */
const VALUE = "TOKEN-sample-7f3a91";

async function run() {
  const base = await mkdtemp(join(tmpdir(), "hygiene-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "shyg", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const svc = new JobService({
    sandbox: S, run: "shyg", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { S, base, svc, a1: { sandboxRoot: S, agentId: "a1" } };
}

async function until(svc: JobService, id: string) {
  // A minute: under a whole suite's load a worker stand-in can be slow to start.
  for (let i = 0; i < 1200; i += 1) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} did not finish`);
}

async function submitted(svc: JobService, who: string, spec: Record<string, unknown>) {
  const r = await svc.submit(who, { kind: "command", timeout_seconds: 60, network: "off", ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  return until(svc, r.job.id);
}

test("secret_output seals every output sensitive; a job reading one is derived; an entry citing one is recorded sensitive", async () => {
  const { S, svc, a1 } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"; echo read one configuration file`, inputs: [], secret_output: true });
  assert.equal(secret.status, "ok");
  assert.equal(secret.sensitive?.why, "secret_output");
  // On the journal (the record) and in the job's projection.
  const journal = await readFile(storePaths(S).journal, "utf8");
  const committed = journal.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.type === "job_committed" && l.job === secret.id);
  assert.equal(committed.sensitive.why, "secret_output");
  assert.equal(JSON.parse(await readFile(join(storePaths(S).jobs, secret.id, "job.json"), "utf8")).sensitive.why, "secret_output");
  assert.match(describe(secret), /Its outputs are sensitive \(it ran with secret_output\)/);
  assert.equal((await svc.submit("a1", { kind: "command", command: "true", inputs: [], secret_output: "yes" } as never)).ok, false, "secret_output is true or false");

  // Declared by path: derived from it.
  const byPath = await submitted(svc, "a2", { command: `echo derived > "$OUT/d.txt"`, inputs: [`job:${secret.id}/value.txt`] });
  assert.deepEqual([byPath.sensitive?.why, byPath.sensitive?.from], ["derived", [secret.id]]);
  // No scope declared: held to what its command names.
  const naming = await submitted(svc, "a2", { command: `wc -c store/jobs/${secret.id}/out/value.txt > "$OUT/count.txt"`, inputs: ["all"] });
  assert.deepEqual(naming.sensitive?.from, [secret.id]);
  const unrelated = await submitted(svc, "a2", { command: `echo unrelated > "$OUT/u.txt"`, inputs: ["all"] });
  assert.equal(unrelated.sensitive, undefined, "a job that names nothing sensitive is not");
  // Derived from derived: the chain carries.
  const second = await submitted(svc, "a1", { command: `echo again > "$OUT/a.txt"`, inputs: [`job:${byPath.id}`] });
  assert.deepEqual(second.sensitive?.from, [byPath.id]);

  // The entry citing it is recorded sensitive, and says why.
  const rec = await P.recordEntry(a1, { kind: "finding", ...F, value: "The configuration held an access token", source: "the job's output", evidence: "the job's command", refs: [`job:${secret.id}/value.txt`] });
  assert.ok(rec.ok, (rec as { reason?: string }).reason);
  assert.equal((rec as { entry: P.LedgerEntry }).entry.sensitive, true);
  assert.match(String((rec as { note?: string }).note), /recorded sensitive: it cites sensitive output \(job:j\d+\/value\.txt, job j\d+ ran with secret_output\)/);
  assert.deepEqual(await sensitiveRefs(S, [`job:${unrelated.id}/u.txt`]), [], "an unrelated output is not sensitive");
  // An entry that cites nothing sensitive is left as its author said.
  const plain = await P.recordEntry(a1, { kind: "finding", ...F, value: "Nothing of note in the unrelated output", source: "the job's output", evidence: "cat", refs: [`job:${unrelated.id}/u.txt`] });
  assert.equal((plain as { entry: P.LedgerEntry }).entry.sensitive, undefined);
  await svc.stop("test over");
});

test("identical bytes of a sensitive output are sensitive at commit, while the same_as index (ADR 0017) is still being built", async () => {
  const { S, svc } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  assert.equal(secret.sensitive?.why, "secret_output");
  // The same_as index as a restarted service has it while it reads the manifests: not built yet.
  const inner = svc as unknown as { outputIndex: unknown };
  inner.outputIndex = null;
  // Another job writes the same bytes from nothing it declared as sensitive (it made them itself).
  const again = await submitted(svc, "a2", { command: `printf '%s' '${VALUE}' > "$OUT/copy.txt"`, inputs: [] });
  assert.deepEqual([again.sensitive?.why, again.sensitive?.from], ["derived", [secret.id]], "decided before job_committed, from the sensitive jobs' manifests, not from the index");
  const journal = await readFile(storePaths(S).journal, "utf8");
  const committed = journal.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.type === "job_committed" && l.job === again.id);
  assert.equal(committed.sensitive?.why, "derived", "the job_committed line says so");
  assert.equal(again.same_as, undefined, "the hint waits for the index; the sensitivity did not");
  await svc.stop("test over");
});

test("the derivation is by path, digest and generation for a declared scope, and by id for none; a small output is a scan word only when it is shaped like a secret", () => {
  const sensitive = new Set(["j000003"]);
  const at = (objects: Array<{ path: string; sha256?: string }> | null, text = "") => derivedFrom({ objects, text, sensitive, digestJob: (s) => (s === "a".repeat(64) ? "j000003" : null), generationJob: (g) => (g === "g000002" ? "j000003" : null) });
  assert.deepEqual(at([{ path: "store/jobs/j000003/out/x" }]), ["j000003"]);
  assert.deepEqual(at([{ path: `store/blobs/${"a".repeat(64)}` }]), ["j000003"]);
  assert.deepEqual(at([{ path: "inputs/disk.E01", sha256: "a".repeat(64) }]), ["j000003"], "the same bytes by digest, wherever they are");
  assert.deepEqual(at([{ path: "catalog/gen/g000002/members.tsv" }]), ["j000003"]);
  assert.deepEqual(at([{ path: "store/jobs/j000004/out/x" }]), []);
  assert.deepEqual(at(null, "python3 read.py store/jobs/j000003/out/key"), ["j000003"]);
  assert.deepEqual(at(null, "echo j0000031"), [], "an id inside a longer word is not the job");
  assert.deepEqual(at([{ path: "inputs/x" }], "echo j000003"), [], "a declared scope is held to what it declared, not to its words");
  assert.equal(secretShaped("none"), false);
  assert.equal(secretShaped("success"), false);
  assert.equal(secretShaped("abc123"), true);
  assert.equal(secretShaped("a-long-plain-phrase"), true);
  assert.equal(secretShaped("two\nlines here"), false);
});

test("a redacted package withholds sensitive outputs whole, names them, and scans every file for their text; one made without --redact names them", async () => {
  const { S, svc, a1, base } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"; echo "read the configuration"`, inputs: [], secret_output: true });
  const other = await submitted(svc, "a1", { command: `echo "nothing sensitive" > "$OUT/p.txt"`, inputs: [] });
  await svc.stop("test over");
  // An entry that cites the output without being marked (as one recorded before the harness marked them would be).
  const ledgerLine = { v: 4, seq: 1, kind: "finding", value: "Unmarked entry about the configuration", source: "s", evidence: "e", refs: [`job:${secret.id}/value.txt`], by: "a1", authors: ["a1"], at: new Date().toISOString() };
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), `${JSON.stringify(ledgerLine)}\n`);
  assert.deepEqual([...(await sensitiveEntries(S, [ledgerLine as never])).keys()], [1], "an unmarked entry citing a sensitive output is sensitive");
  // A package laid out as swarm.sh package --with-outputs lays it out.
  const make = async (name: string) => {
    const pkg = join(base, name);
    for (const id of [secret.id, other.id]) {
      await mkdir(join(pkg, "store", "jobs", id, "out"), { recursive: true });
      for (const f of ["job.json", "manifest.json", "stdout.log"]) await writeFile(join(pkg, "store", "jobs", id, f), await readFile(join(storePaths(S).jobs, id, f)));
    }
    await writeFile(join(pkg, "store", "jobs", secret.id, "out", "value.txt"), VALUE);
    await writeFile(join(pkg, "store", "jobs", other.id, "out", "p.txt"), "nothing sensitive\n");
    await mkdir(join(pkg, "board"), { recursive: true });
    // The value repeated where no ledger entry says it: a post and a work file.
    await writeFile(join(pkg, "board", "main.md"), `a post quoting ${VALUE} in passing\n`);
    await mkdir(join(pkg, "work"), { recursive: true });
    await writeFile(join(pkg, "work", "notes.md"), `notes: ${VALUE}\n`);
    await writeFile(join(pkg, "ledger.jsonl"), `${JSON.stringify(ledgerLine)}\n`);
    return pkg;
  };
  const plain = await make("pkg-plain");
  const h = await hygieneReport(S, plain);
  assert.equal(h.outputs, 1);
  assert.deepEqual(h.carried, [`store/jobs/${secret.id}/out/value.txt`, `store/jobs/${secret.id}/stdout.log`]);
  assert.ok(h.hits.some((x) => x.path === "board/main.md" && x.output), "the scan finds the output's text in a post");
  const hyg = JSON.parse(await readFile(join(plain, "HYGIENE.json"), "utf8"));
  assert.deepEqual(hyg.entries.map((e: { seq: number }) => e.seq), [1]);
  assert.equal(await readFile(join(plain, "board", "main.md"), "utf8"), `a post quoting ${VALUE} in passing\n`, "without --redact nothing is taken out");

  const pkg = await make("pkg-redacted");
  const r = await redactPackage(S, pkg, { leaks: "list" });
  assert.deepEqual(r.withheld.map((w) => w.path).sort(), [`store/jobs/${secret.id}/out/value.txt`, `store/jobs/${secret.id}/stdout.log`]);
  assert.match(await readFile(join(pkg, "store", "jobs", secret.id, "out", "value.txt"), "utf8"), /^\[withheld: a sensitive output \(job j\d+ ran with secret_output\); its sha256 before it was withheld is [0-9a-f]{64}\]/);
  assert.equal(await readFile(join(pkg, "store", "jobs", other.id, "out", "p.txt"), "utf8"), "nothing sensitive\n", "another job's output is kept");
  assert.doesNotMatch(await readFile(join(pkg, "board", "main.md"), "utf8"), new RegExp(VALUE), "the output's text is taken out of a post");
  assert.doesNotMatch(await readFile(join(pkg, "work", "notes.md"), "utf8"), new RegExp(VALUE));
  assert.deepEqual(r.leaks, [], "the scan after redaction finds nothing");
  const red = JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8"));
  assert.equal(red.sensitive_outputs[0].job, secret.id);
  assert.deepEqual(red.withheld.map((w: { path: string }) => w.path).sort(), r.withheld.map((w) => w.path).sort());
  assert.equal(red.entries[0].seq, 1);
  assert.match(red.entries[0].why, /cites sensitive output/);
  const txt = await readFile(join(pkg, "REDACTIONS.txt"), "utf8");
  assert.match(txt, /Withheld whole: \n[0-9a-f]{64}\s+\d+\s+store\/jobs\/j\d+\/(out\/value\.txt|stdout\.log)/);
  // A copy in a form the redaction cannot rewrite (a binary file) is a hit the scan names.
  const leaky = await make("pkg-leaky");
  await writeFile(join(leaky, "work", "blob.bin"), Buffer.concat([Buffer.alloc(16), Buffer.from(VALUE, "utf16le")]));
  const again = await redactPackage(S, leaky, { leaks: "list" });
  assert.ok(again.leaks.some((x) => x.path === "work/blob.bin" && x.output && x.as === "bytes"), JSON.stringify(again.leaks));
});

test("the export's redaction treats an unmarked entry citing a sensitive output as sensitive", async () => {
  const { S, svc } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  await svc.stop("test over");
  const line = { v: 4, seq: 1, kind: "finding", value: "Unmarked words about the configuration", source: "s", evidence: "e", refs: [`job:${secret.id}/value.txt`], by: "a1", authors: ["a1"], at: new Date().toISOString() };
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), `${JSON.stringify(line)}\n`);
  const csv = await exportLedger(S, "csv", { redact: true, review: new Map(), grounding: {} });
  assert.doesNotMatch(csv, /Unmarked words about the configuration/);
  assert.match(csv, /\[redacted: marked sensitive\]/);
  const open = await exportLedger(S, "csv", { review: new Map(), grounding: {} });
  assert.match(open, /Unmarked words about the configuration/, "an export not for handing over is the ledger as it is");
});

test("a cancelled job's kept output cited later is a defect until the citing entry says how it treats it", async () => {
  const base = await mkdtemp(join(tmpdir(), "hygiene-partial-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "spart", agentIds: ["a1", "a2"] });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  // A job an agent cancelled half way: what it wrote is sealed, with its status.
  const staging = join(base, "staging");
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "rows.csv"), "t,what\n1,first half\n");
  await sealTree(S, staging, join(storePaths(S).jobs, "j000007", "out"), "j000007", 1);
  await writeFile(join(storePaths(S).jobs, "j000007", "job.json"), JSON.stringify({ id: "j000007", state: "committed", status: "cancelled", spec: { kind: "command", command: "x", inputs: [] }, requester: { agent: "a1" } }));
  const a1 = { sandboxRoot: S, agentId: "a1" };
  const ev = await P.recordEntry(a1, { kind: "event", ts: "2026-01-01T10:00:00Z", value: "The first half of the rows starts here", source: "rows.csv", evidence: "the job's output", refs: ["job:j000007/rows.csv"] });
  assert.ok(ev.ok, (ev as { reason?: string }).reason);
  const seq = (ev as { entry: P.LedgerEntry }).entry.seq;
  // The gate, pure: the citing entry is the defect.
  const partial = P.partialOutputCites(await P.readLedger(S), (id) => (id === "j000007" ? "cancelled" : "ok"));
  assert.deepEqual([...partial.keys()], [seq]);
  const check = await checkLedgerAnswers(S, ["summary"]);
  const d = check.defects.find((x) => x.code === "partial_output");
  assert.ok(d, check.lines.join("\n"));
  assert.deepEqual(d.seqs, [seq]);
  assert.equal(d.named_by.length, 0, "never named away by a limitation");
  assert.match(check.lines.join("\n"), /DEFECT: #\d+ cites the kept output of job j000007 \(cancelled\)/);
  // A limitation does not resolve it; the entry saying how it treats the output does.
  await P.recordEntry(a1, { kind: "limitation", value: `E-${seq} rests on a cancelled job`, source: "s", evidence: "e", reason: "partial" });
  assert.ok((await checkLedgerAnswers(S, ["summary"])).defects.some((x) => x.code === "partial_output"));
  const fixed = await P.recordEntry(a1, { kind: "event", ts: "2026-01-01T10:00:00Z", value: "The first half of the rows starts here (from a job stopped half way)", source: "rows.csv", evidence: "the job's output", refs: ["job:j000007/rows.csv"], qualifies: [{ ref: "job:j000007/rows.csv", why: "the rows it wrote before it was stopped are whole lines; nothing after them is claimed" }], supersedes: seq });
  assert.ok(fixed.ok, (fixed as { reason?: string }).reason);
  assert.ok(!(await checkLedgerAnswers(S, ["summary"])).defects.some((x) => x.code === "partial_output"), "the correction says how it treats it");
  // A search recorded partial is its own disposition.
  assert.deepEqual([...P.partialOutputCites([{ v: 4, seq: 1, kind: "absence", value: "v", completion: "partial", refs: ["job:j000007/rows.csv"], by: "a", authors: ["a"], at: "t" } as P.LedgerEntry], () => "cancelled").keys()], []);
});
