/**
 * A brain's own output a finding cites: `tool:<seat>/<file>` (a whole output
 * the harness kept under tool-output/<seat>/) and `trace:<sha256>` (one line
 * of the trace), found on the chained trace, attributed by the collector,
 * sealed by an import job over the hub's snapshot held to the trace's digest,
 * published as an import with its trace provenance, and refused — with the
 * way on — when the capture does not hold (no line, another seat, an edited
 * line, bytes that changed since).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSandbox, readLedger } from "../extensions/protocol.ts";
import { checkStore, resolveRef, storePaths, traceOrigin, verifyJournalText } from "../scripts/evidence-store.ts";
import { JobService, type JobServiceOptions } from "../scripts/job-service.ts";
import { boardTable } from "../scripts/vm-hub.ts";
import { listInputs, mountedWorker } from "./job-service-worker.ts";

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const KEPT = "tool-output/a1/20260927120000000-bash-ab12.out.log";
const OUTPUT = "whole output of a long command\n".repeat(200);

/** A trace as the collector writes it: each line chained to the one before by its sha256. */
function writeTrace(S: string, records: Array<Record<string, unknown>>): string[] {
  const lines: string[] = [];
  let prev: string | null = null;
  for (const r of records) {
    const line = JSON.stringify({ ts: "2026-09-27T12:00:00.000Z", sid: "abc123", ...r, recv_ts: "2026-09-27T12:00:00.100Z", prev });
    lines.push(line);
    prev = sha(line);
  }
  mkdirSync(join(S, "traces"), { recursive: true });
  writeFileSync(join(S, "traces", "events.jsonl"), lines.map((l) => `${l}\n`).join(""));
  return lines;
}

const bashLine = (agent = "a1", extra: Record<string, unknown> = {}) => ({
  agent,
  tool: "bash",
  seq: 7,
  args: { command: "strings -a big.bin" },
  result: { ok: true, output: "(prefix)", full_output: { path: KEPT, bytes: Buffer.byteLength(OUTPUT), lines: 200, sha256: sha(OUTPUT) }, duration_ms: 12000 },
  ...extra,
});

async function rig(o: { jobs?: boolean; extra?: Partial<JobServiceOptions> } = {}) {
  const S = join(mkdtempSync(join(tmpdir(), "seal-")), "run");
  await initSandbox(S, { reset: true, agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "tool-output/a1"]) mkdirSync(join(S, d), { recursive: true });
  listInputs(S);
  writeFileSync(join(S, KEPT), OUTPUT);
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [], forging: false, minFreeMb: 1, runWorker: mountedWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined, identity: async (a) => ({ name: a }),
    ...(o.extra ?? {}),
  });
  const table = boardTable({ sandbox: S, settle: async () => undefined, wrote: () => undefined, ids: ["a1", "a2"], ...(o.jobs === false ? {} : { jobs: () => svc }) });
  const call = (who: string, fn: string, arg: unknown) => (table as Record<string, (w: string, a: unknown[], s: AbortSignal) => Promise<unknown>>)[fn](who, [S, arg], new AbortController().signal) as Promise<Record<string, any>>;
  return { S, svc, call };
}

test("tool: resolves against the trace line that kept the file, attributed to its seat and on the chain", async () => {
  const { S } = await rig();
  const lines = writeTrace(S, [{ agent: "a2", tool: "read", args: {}, result: { ok: true } }, bashLine(), { agent: "a1", tool: "ls", args: {}, result: { ok: true } }]);
  const got = await traceOrigin(S, `tool:a1/${KEPT.slice("tool-output/a1/".length)}`);
  assert.ok(got.ok, !got.ok ? got.reason : "");
  const o = got.ok ? got.origin : null!;
  assert.equal(o.line_sha256, sha(lines[1]));
  assert.equal(o.digest, sha(OUTPUT));
  assert.equal(o.bytes, Buffer.byteLength(OUTPUT));
  assert.deepEqual([o.seat, o.tool, o.path, o.field, o.seq, o.ts, o.recv_ts], ["a1", "bash", KEPT, "result.full_output", 7, "2026-09-27T12:00:00.000Z", "2026-09-27T12:00:00.100Z"]);
  assert.deepEqual(o.args, { command: "strings -a big.bin" });
  assert.equal(o.tool_sha256, null, "a built-in tool has none, and none is invented");
  // Not sealed yet: resolveRef says so and how.
  const r = await resolveRef(S, `tool:a1/${KEPT.slice(15)}`);
  assert.equal(r.ok, false);
  assert.match(!r.ok ? r.reason : "", /not sealed: the hub seals it as an import when a record/);
});

test("the capture must hold: another seat's line, an edited line, the last line with no anchor, or no line at all are refused, with the way on", async () => {
  const { S } = await rig();
  const ref = `tool:a1/${KEPT.slice(15)}`;
  writeTrace(S, [bashLine("a2"), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  assert.match(String((await traceOrigin(S, ref) as { reason: string }).reason), /not attributed to a1 by the collector/);
  writeTrace(S, [bashLine("a1", { claimed_agent: "a2" }), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  assert.match(String((await traceOrigin(S, ref) as { reason: string }).reason), /not attributed to a1/);
  // An edited line: the next line no longer names it.
  const lines = writeTrace(S, [bashLine(), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  writeFileSync(join(S, "traces", "events.jsonl"), `${lines[0].replace("strings -a", "strings -n")}\n${lines[1]}\n`);
  assert.match(String((await traceOrigin(S, ref) as { reason: string }).reason), /not what the next line names as its parent/);
  // The last line: held by the anchor, or not at all.
  const last = writeTrace(S, [{ agent: "a2", tool: "ls", args: {}, result: {} }, bashLine()]);
  assert.match(String((await traceOrigin(S, ref) as { reason: string }).reason), /no trace anchor to hold it to/);
  writeFileSync(`${S}.trace-anchor.json`, JSON.stringify({ head: sha(last[1]), prev_head: sha(last[0]) }));
  assert.ok((await traceOrigin(S, ref)).ok);
  const none = await traceOrigin(S, "tool:a1/nothing.log");
  assert.match(!none.ok ? none.reason : "", /no line of the trace, attributed to a1, records tool-output\/a1\/nothing\.log .* run the work again as a job/);
  assert.match(String((await traceOrigin(S, "tool:a1/../x") as { reason: string }).reason), /tool:<seat>\/<file/);
});

test("a cited tool: output is sealed as an import: the hub's snapshot held to the trace's digest, the provenance kept, the same ref sealed once", async () => {
  const { S, svc } = await rig();
  const lines = writeTrace(S, [bashLine(), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  await svc.start();
  const ref = `tool:a1/${KEPT.slice(15)}`;
  const r = await svc.sealCited("a1", ref, { wait: 20 });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const { import_ref, job } = r.ok ? r : { import_ref: "", job: "" };
  assert.equal(import_ref, `import:${job}/${KEPT.slice(15)}`);
  const imp = await resolveRef(S, import_ref, { verify: true });
  assert.ok(imp.ok && imp.sha256 === sha(OUTPUT), JSON.stringify(imp));
  const viaTool = await resolveRef(S, ref);
  assert.ok(viaTool.ok && viaTool.import_ref === import_ref && viaTool.trace_line === sha(lines[0]), JSON.stringify(viaTool));
  const record = JSON.parse(readFileSync(join(storePaths(S).imports, job, "import.json"), "utf8"));
  assert.deepEqual([record.ref, record.import, record.digest, record.trace_line, record.trace.seat, record.trace.tool], [ref, import_ref, sha(OUTPUT), sha(lines[0]), "a1", "bash"]);
  assert.deepEqual(record.trace.args, { command: "strings -a big.bin" });
  const journal = verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
  const sealed = journal.filter((l) => l.type === "brain_output_sealed");
  assert.equal(sealed.length, 1);
  assert.equal(sealed[0].import_json_sha256, sha(readFileSync(join(storePaths(S).imports, job, "import.json"))));
  // The job's own record: an import whose scope was the kept file, snapshotted.
  const accepted = journal.find((l) => l.type === "job_accepted" && l.job === job)!;
  assert.equal((accepted.spec as { seal: { digest: string } }).seal.digest, sha(OUTPUT), "the digest it was held to, on the journal before it ran");
  // Once: a second record gets the same import, and no second job.
  const again = await svc.sealCited("a2", ref, { wait: 5 });
  assert.ok(again.ok && again.import_ref === import_ref);
  assert.equal(journal.filter((l) => l.type === "job_accepted").length, 1);
  const st = await checkStore(S);
  assert.deepEqual(st?.imports, { sealed: 1, verified: 1, mismatched: [] });
  await svc.stop("over");
});

test("bytes that changed since the trace are refused at once; bytes that change before the job starts fail its start; neither is sealed", async () => {
  let allow = false;
  const { S, svc } = await rig({ extra: { hostRoom: async () => ({ ok: allow, available_mib: 1, needed_mib: 1 }) } });
  writeTrace(S, [bashLine(), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  await svc.start();
  const ref = `tool:a1/${KEPT.slice(15)}`;
  writeFileSync(join(S, KEPT), "rewritten since");
  const now = await svc.sealCited("a1", ref, { wait: 2 });
  assert.equal(now.ok, false);
  assert.match(!now.ok ? now.reason : "", /reads now as sha256 .* not the .* the trace recorded .* run the work again as a job/);
  // The same bytes when asked, other bytes by the time the job starts.
  writeFileSync(join(S, KEPT), OUTPUT);
  const waiting = svc.sealCited("a1", ref, { wait: 20 });
  await new Promise((r) => setTimeout(r, 300));
  writeFileSync(join(S, KEPT), "changed while the seal waited for a worker");
  allow = true;
  const late = await waiting;
  assert.equal(late.ok, false);
  assert.match(!late.ok ? late.reason : "", /could not be sealed: job j\d+ failed \(not run: .* not the .* the trace recorded/);
  const journal = verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
  assert.equal(journal.filter((l) => l.type === "brain_output_sealed").length, 0);
  await svc.stop("over");
});

test("trace: seals the line itself: the import's bytes hash to the ref", async () => {
  const { S, svc } = await rig();
  const lines = writeTrace(S, [{ agent: "a1", tool: "grep", args: { pattern: "key" }, result: { ok: true, output: "key=1234" } }, { agent: "a1", tool: "ls", args: {}, result: {} }]);
  await svc.start();
  const ref = `trace:${sha(lines[0])}`;
  const r = await svc.sealCited("a1", ref, { wait: 20 });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const imp = await resolveRef(S, r.ok ? r.import_ref : "", { verify: true });
  assert.ok(imp.ok);
  assert.equal(imp.ok ? imp.sha256 : "", sha(lines[0]), "the sealed file is the line, byte for byte");
  assert.equal(readFileSync(join(S, imp.ok ? String(imp.path) : ""), "utf8"), lines[0]);
  await svc.stop("over");
});

test("a record citing tool: cites the import it became, and without a job service it is refused", async () => {
  const { S, svc, call } = await rig();
  writeTrace(S, [bashLine(), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  await svc.start();
  const ref = `tool:a1/${KEPT.slice(15)}`;
  const res = await call("a1", "recordEntry", { kind: "finding", value: "The binary holds the string", source: "strings over big.bin", evidence: "strings -a big.bin", refs: [ref], confidence: "medium", basis: "observed" });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.match(String(res.note), /sealed as import:j\d{6}\/.* which the entry cites/);
  const entries = await readLedger(S);
  assert.match(String(entries.at(-1)?.refs?.[0]), /^import:j\d{6}\/20260927120000000-bash-ab12\.out\.log$/);
  await svc.stop("over");
  const bare = await rig({ jobs: false });
  writeTrace(bare.S, [bashLine(), { agent: "a1", tool: "ls", args: {}, result: {} }]);
  const refused = await bare.call("a1", "recordEntry", { kind: "finding", value: "x", source: "s", evidence: "e", refs: [ref] });
  assert.equal(refused.ok, false);
  assert.match(String(refused.reason), /sealed by the job service .* run the work as a job/);
});
