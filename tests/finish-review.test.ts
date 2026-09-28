/**
 * The finish under review (Plan 3, WP4; docs/adr/0015; the independent
 * review of 2026-09-28): what a coordinator's done checks is checked again
 * in the transaction that writes the sentinel, never only before its checks
 * ran. An objection that lands while the checks run holds the sentinel; a
 * report published again keeps what landed against the earlier one as an
 * obligation until it is resolved; a coordinator taken over between its
 * done marker and its sentinel does not end the run; a job's stdout read
 * after a check moves the revision that check was recorded at; and
 * readiness is never cached for a revision its snapshot was not read at.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const F4 = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;

async function run() {
  const base = await mkdtemp(join(tmpdir(), "finish-review-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "f2", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30 });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  for (const a of ["a0", "a1", "a2"]) await traceRow(S, a, "bash");
  return { S, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

async function traceRow(S: string, agent: string, tool: string, at: Date = new Date()): Promise<void> {
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at.toISOString(), recv_ts: at.toISOString(), agent, tool, args: {}, result: { ok: true } })}\n`);
}

async function publish(S: string, agent: string, text: string): Promise<void> {
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, "work", "report.md"), text);
  await P.recordFileVersion(S, "work/report.md", agent);
}

const tick = () => new Promise((r) => setTimeout(r, 20));
const done = (finish?: { holder: string; generation: number }) => ({ reason: "finished", outputFile: "work/report.md", ...(finish ? { finish } : {}) }) as Parameters<typeof P.markDone>[1];

test("an objection that lands while the checks run holds the sentinel: the final transaction reads what is late, and a resolution lets it through", async () => {
  const { S, a0, a2 } = await run();
  await publish(S, "a0", "# report\n");
  const turn = await F.finishTurn(a0, { output_file: "work/report.md" });
  assert.deepEqual([turn.mine, turn.generation], [true, 1]);
  assert.deepEqual(await F.lateItems(S, "a0", "work/report.md"), [], "nothing late when the done began");
  // The checks run; meanwhile a reviewer objects.
  const obj = await F.ackReport(a2, { verdict: "objection", why: "section 2 calls a best candidate established" });
  assert.ok(obj.ok);
  await assert.rejects(P.markDone(a0, done({ holder: "a0", generation: 1 })), /late against the report: .*objection .* by a2/);
  assert.equal(await P.swarmDoneExists(S), false, "no sentinel over an objection nobody answered");
  assert.ok((await F.resolveLate(a0, { ack: (obj as { seq: number }).seq, how: "folded", why: "section 2 says best candidate now" })).ok);
  const r = await P.markDone(a0, done({ holder: "a0", generation: 1 }));
  assert.equal("created_sentinel" in r && r.created_sentinel, true);
});

test("a report published again keeps what landed against the earlier one: the late result and the objection stay until resolved, and resolve after publish finds them", async () => {
  const { S, a0, a1, a2 } = await run();
  await publish(S, "a0", "# report v1\n");
  await F.finishTurn(a0, { output_file: "work/report.md" });
  await tick();
  const post = await P.postMessage(a1, { tag: "result", body: "the timeline misses the second logon" });
  const obj = await F.ackReport(a2, { verdict: "objection", why: "question 2's answer is a best candidate" });
  assert.ok(obj.ok);
  assert.deepEqual((await F.lateItems(S, "a0", "work/report.md")).map((x) => x.kind).sort(), ["objection", "post"]);
  // Published again before anything was resolved: nothing is silently dropped.
  await tick();
  await publish(S, "a0", "# report v2\n\nThe second logon, and question 2 as a best candidate.\n");
  const late = await F.lateItems(S, "a0", "work/report.md");
  assert.deepEqual(late.map((x) => [x.kind, x.id]).sort(), [["objection", (obj as { seq: number }).seq], ["post", post.id]].sort());
  await assert.rejects(P.markDone(a0, done({ holder: "a0", generation: 1 })), /late against the report/);
  // Publish, then resolve: the instructed order works.
  assert.ok((await F.resolveLate(a0, { post: post.id, how: "folded", why: "the timeline has the second logon now" })).ok);
  assert.ok((await F.resolveLate(a0, { ack: (obj as { seq: number }).seq, how: "folded", why: "section 2 says best candidate" })).ok);
  assert.deepEqual(await F.lateItems(S, "a0", "work/report.md"), []);
  // A folded resolution names the report's digest it was folded into.
  const digest = await F.reportDigest(S, "work/report.md");
  assert.deepEqual((await F.readFinish(S)).resolutions.map((r) => r.digest), [digest, digest]);
  // An objector who reads the new version and acks it with no objection answers its own objection.
  const obj2 = await F.ackReport(a2, { verdict: "objection", why: "the summary still says established" });
  assert.ok(obj2.ok);
  await tick();
  await publish(S, "a0", "# report v3\n");
  assert.equal((await F.lateItems(S, "a0", "work/report.md")).length, 1);
  assert.ok((await F.ackReport(a2, { verdict: "no_objection" })).ok);
  assert.deepEqual(await F.lateItems(S, "a0", "work/report.md"), []);
});

test("a coordinator taken over does not end the run: the lease is checked with the sentinel, by holder and generation, and nobody takes over once the sentinel is written", async () => {
  const { S, a0, a1 } = await run();
  await publish(S, "a0", "# report\n");
  assert.equal((await F.finishTurn(a0, { output_file: "work/report.md" })).generation, 1);
  // a0 compacts; a1's done takes the lease over at generation 2; a1 compacts in turn.
  await traceRow(S, "a0", "compact_start");
  const took = await F.finishTurn(a1, { output_file: "work/report.md" });
  assert.deepEqual([took.mine, took.generation], [true, 2]);
  await traceRow(S, "a0", "compact_done");
  await traceRow(S, "a0", "bash");
  await traceRow(S, "a1", "compact_start");
  // a0's done, begun at generation 1, reaches the sentinel: not its finish any more.
  await assert.rejects(P.markDone(a0, done({ holder: "a0", generation: 1 })), new RegExp(`${F.NOT_YOURS}.*a1 holds it at generation 2`));
  assert.equal(await P.swarmDoneExists(S), false);
  assert.equal(await readFile(join(S, "done", "agents", "a0.done"), "utf8").catch(() => null), null, "its done marker is not left behind");
  // Taking it over again is how a0 finishes now.
  const back = await F.finishTurn(a0, { output_file: "work/report.md" });
  assert.deepEqual([back.mine, back.generation], [true, 3]);
  const r = await P.markDone(a0, done({ holder: "a0", generation: 3 }));
  assert.equal("created_sentinel" in r && r.created_sentinel, true);
  // Once the sentinel is written, a done marker makes a0 unavailable, but nobody takes the finish over.
  const late = await F.finishTurn(a1, { output_file: "work/report.md" });
  assert.equal(late.mine, false);
  assert.deepEqual([(await F.readFinish(S)).lease?.holder, (await F.readFinish(S)).lease?.generation], ["a0", 3]);
});

test("a coordinator's done and a takeover racing: the sentinel is never written by a seat that does not hold the lease", async () => {
  for (let i = 0; i < 12; i++) {
    const { S, a0, a1 } = await run();
    await publish(S, "a0", "# report\n");
    await F.finishTurn(a0, { output_file: "work/report.md" });
    const [d] = await Promise.allSettled([P.markDone(a0, done({ holder: "a0", generation: 1 })), F.finishTurn(a1, { output_file: "work/report.md" })]);
    const lease = (await F.readFinish(S)).lease!;
    if (await P.swarmDoneExists(S)) {
      assert.equal(d.status, "fulfilled");
      assert.deepEqual([lease.holder, lease.generation], ["a0", 1], `round ${i}: the sentinel is a0's, and so is the lease`);
    } else {
      assert.equal(d.status, "rejected");
    }
  }
});

test("a job's stdout read after a check moves the revision that check was recorded at: a cached check never hides a new unread-output defect, nor outlives its fix", async () => {
  const { S, a1 } = await run();
  const lead = await L.openLead(a1, { title: "Read the notes", why: "q1", take: true });
  assert.ok(lead.ok);
  const dir = join(S, "store", "jobs", "j000001");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "job.json"), JSON.stringify({ id: "j000001", state: "committed", status: "ok", requester: { agent: "a1" }, spec: { kind: "command", command: "strings" } }));
  await writeFile(join(dir, "stdout.log"), "x".repeat(18_206));
  assert.ok((await L.attachJob(S, "a1", "j000001", "L-1")).ok);
  const f = await P.recordEntry(a1, { kind: "finding", ...F4, value: "The notes list six titles", source: "notes", evidence: "the output" } as P.LedgerInput);
  assert.ok(f.ok);
  assert.ok((await L.recordInterpretations(S, "a1", 1, ["j000001"])).ok);
  const rev = async () => (await P.stateRevision(S)).revision;
  const gate = async () => (await L.leadDefects(S)).defects.filter((d) => d.code === "uninterpreted_job").map((d) => d.job);
  const r0 = await rev();
  assert.deepEqual(await gate(), []);
  await F.recordCheck(S, "a1", r0, { proceed: true, outcome: "completed" }, { total: 1, passed: 1, checks: [] });
  // The first page is handed over: an unread-output defect appears, and the revision moves with it.
  await appendFile(join(S, "store", "journal.jsonl"), `${JSON.stringify({ v: 1, type: "job_returned", job: "j000001", to: "a1", stdout_offset: 0, stdout_bytes: 8192 })}\n`);
  assert.deepEqual(await gate(), ["j000001"]);
  const r1 = await rev();
  assert.notEqual(r1, r0, "a delivery that changes the gate changes the revision");
  assert.equal(await F.checkAt(S, r1), null, "the passing check is not taken for it");
  await F.recordCheck(S, "a1", r1, { proceed: false, reason: "j000001 has 10014 bytes unread" }, { total: 1, passed: 0, checks: [] });
  // The rest is read: the defect goes, and so does the refusal recorded for it.
  await appendFile(join(S, "store", "journal.jsonl"), `${JSON.stringify({ v: 1, type: "job_returned", job: "j000001", to: "a1", stdout_offset: 8192, stdout_bytes: 10014 })}\n`);
  assert.deepEqual(await gate(), []);
  const r2 = await rev();
  assert.notEqual(r2, r1);
  assert.equal(await F.checkAt(S, r2), null, "the refusal is not taken for the state that fixed it");
  // The same bytes handed over again change nothing.
  await appendFile(join(S, "store", "journal.jsonl"), `${JSON.stringify({ v: 1, type: "job_returned", job: "j000001", to: "a1", stdout_offset: 0, stdout_bytes: 8192 })}\n`);
  assert.equal(await rev(), r2);
});

test("readiness is never cached for a revision its snapshot was not read at: a lead opened between a caller's snapshot and the revision is seen", async () => {
  const { S, a1 } = await run();
  let r = await F.readiness(S);
  assert.equal(r.ready, true);
  // A caller read its snapshot; a material lead is admitted; the caller asks for readiness with its snapshot.
  const stale = await L.leadsSnapshot(S);
  assert.ok((await L.openLead(a1, { title: "A late avenue", why: "found", take: true })).ok);
  r = await (F.readiness as (s: string, snap?: unknown) => Promise<F.Readiness>)(S, stale);
  assert.equal(r.ready, false, "the lead admitted since is read");
  r = await F.readiness(S);
  assert.equal(r.ready, false);
  assert.ok(r.items.some((i) => /L-1 "A late avenue"/.test(i)), r.items.join("\n"));
});

test("the finish register is written where the metrics and the report read it: the first readiness is recorded (never posted when not ready), and a review before the coordinator's done names the report and holds its done (the c10 pilot)", async () => {
  const { S, a0, a2 } = await run();
  const lead = await L.openLead(a2, { title: "A late avenue", why: "found", take: true });
  assert.ok(lead.ok);
  const finishLog = join(S, "leads", "finish.jsonl");
  assert.equal(await readFile(finishLog, "utf8").catch(() => null), null, "nothing yet");
  // The first header: readiness recorded (not ready), nothing posted.
  const posts = async () => (await P.readInbox({ sandboxRoot: S, agentId: "a0" }, { markSeen: false })).posts.filter((p) => /FINISH/.test(p.body)).length;
  await F.finishHeader(S, "a0");
  assert.deepEqual((await F.readFinish(S)).events.map((e) => [e.ev, e.ready]), [["readiness", false]]);
  assert.equal(await posts(), 0, "not ready from the start is recorded, not posted");
  await F.finishHeader(S, "a1");
  assert.equal((await F.readFinish(S)).events.length, 1, "recorded once");
  // A reviewer objects before any done: it names the report, and the objection is kept.
  await publish(S, "a0", "# report\n\nL-28 and L-29 remain active.\n");
  const refusedNoReport = await F.ackReport(a2, { verdict: "objection", why: "L-29 was closed duplicate" });
  assert.equal(refusedNoReport.ok, false);
  assert.match((refusedNoReport as { reason: string }).reason, /name the report you reviewed \(report, e\.g\. work\/report\.md\)/);
  const obj = await F.ackReport(a2, { verdict: "objection", why: "L-29 was closed duplicate; only L-28 is active", report: "work/report.md" });
  assert.ok(obj.ok, (obj as { reason?: string }).reason);
  // The coordinator's done names the same report: the objection holds it until resolved.
  await F.finishTurn(a0, { output_file: "work/report.md" });
  assert.deepEqual((await F.lateItems(S, "a0", "work/report.md")).map((x) => [x.kind, x.by]), [["objection", "a2"]]);
  // The metrics and the report read the same file.
  const { measureRun } = await import("../scripts/metrics.ts");
  const m = await measureRun(S);
  assert.equal(m.tail.ready_source, null, "readiness is recorded, and it never turned ready");
  assert.equal(F.FINISH_LOG, "leads/finish.jsonl");
  assert.ok((await readFile(finishLog, "utf8")).includes('"ev":"ack"'));
  const { renderReportBodyMarkdown } = await import("../scripts/report-body.ts");
  assert.match(await renderReportBodyMarkdown(S), /\d+ events? in leads\/finish\.jsonl; chain intact/);
});

test("the finish phase: once the coordinator holds the lease and the registers are met but for what is late, another seat's answer revision needs material: why; a wording-only one is refused quietly; the coordinator's is free; nothing is refused outside the phase (the c10 pilot's tail)", async () => {
  const { S, a0, a1, a2 } = await run();
  const f = await P.recordEntry(a2, { kind: "finding", ...F4, value: "The logon was interactive", source: "log", evidence: "line 1" } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  const s1 = await P.recordEntry(a1, { kind: "answer", section: "summary", value: "An interactive logon.", reasoning: `E-${f.entry.seq}` } as P.LedgerInput);
  assert.ok(s1.ok);
  if (!s1.ok) return;
  // Outside the phase (no coordinator yet): a wording revision is admitted as ever.
  const s2 = await P.recordEntry(a1, { kind: "answer", section: "summary", value: "The logon was interactive.", reasoning: `E-${f.entry.seq}`, supersedes: s1.entry.seq } as P.LedgerInput);
  assert.ok(s2.ok, (s2 as { reason?: string }).reason);
  if (!s2.ok) return;
  // The coordinator takes the lease; the registers are met: the finish is being assembled.
  await publish(S, "a0", "# report\n");
  await F.finishTurn(a0, { output_file: "work/report.md" });
  assert.equal((await F.finishPhase(S)).assembling, true);
  assert.match((await F.finishHeader(S, "a1")) ?? "", /ASSEMBLING by a0: an answer revision from another seat is admitted only with material/);
  assert.ok((await F.readFinish(S)).events.some((e) => e.ev === "phase" && e.phase === "assembling"), "recorded in the finish register");
  const { finishText } = await import("../scripts/leads-cli.ts");
  assert.match(await finishText(S), /phase: assembling by a0/);
  // A wording-only revision from another seat: refused quietly, nothing recorded, not a refusal to count.
  const n = (await P.readLedger(S)).length;
  const quiet = await P.recordEntry(a1, { kind: "answer", section: "summary", value: "The logon was an interactive one.", reasoning: `E-${f.entry.seq}`, supersedes: s2.entry.seq } as P.LedgerInput);
  assert.equal(quiet.ok, false);
  assert.equal((quiet as { quiet?: boolean }).quiet, true);
  assert.match((quiet as { reason: string }).reason, /the finish is being assembled by a0; revise only with material: why/);
  assert.equal((await P.readLedger(S)).length, n, "nothing recorded");
  // A material revision is admitted, with its why on the entry.
  const mat = await P.recordEntry(a1, { kind: "answer", section: "summary", value: "The logon was remote.", reasoning: `E-${f.entry.seq}`, supersedes: s2.entry.seq, material: "the log's logon type is 10, remote: the conclusion changes" } as P.LedgerInput);
  assert.ok(mat.ok, (mat as { reason?: string }).reason);
  if (!mat.ok) return;
  assert.equal(mat.entry.finish_material, "the log's logon type is 10, remote: the conclusion changes");
  // The coordinator's own folding stays free.
  const own = await P.recordEntry(a0, { kind: "answer", section: "summary", value: "The logon was remote (type 10).", reasoning: `E-${f.entry.seq}`, supersedes: mat.entry.seq } as P.LedgerInput);
  assert.ok(own.ok, (own as { reason?: string }).reason);
});

test("a result post that only restates an answer's own revision is covered by that revision: it needs no typed resolution; one with another ref still does", async () => {
  const { S, a0, a1, a2 } = await run();
  const f = await P.recordEntry(a2, { kind: "finding", ...F4, value: "The logon was interactive", source: "log", evidence: "line 1" } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  const s1 = await P.recordEntry(a1, { kind: "answer", section: "summary", value: "An interactive logon.", reasoning: `E-${f.entry.seq}` } as P.LedgerInput);
  assert.ok(s1.ok);
  if (!s1.ok) return;
  await publish(S, "a0", "# report\n");
  await F.finishTurn(a0, { output_file: "work/report.md" });
  await tick();
  const s2 = await P.recordEntry(a1, { kind: "answer", section: "summary", value: "An interactive logon at the console.", reasoning: `E-${f.entry.seq}`, supersedes: s1.entry.seq, material: "the console is where" } as P.LedgerInput);
  assert.ok(s2.ok, (s2 as { reason?: string }).reason);
  if (!s2.ok) return;
  const restating = await P.postMessage(a1, { tag: "result", body: `Summary revised: E-${s2.entry.seq} (it supersedes E-${s1.entry.seq}).` });
  const adding = await P.postMessage(a2, { tag: "result", body: `E-${s2.entry.seq} misses job:j000001/hits.txt, which shows a second logon.` });
  const late = await F.lateItems(S, "a0", "work/report.md");
  assert.deepEqual(late.map((x) => x.id), [adding.id], `the restating post #${restating.id} is covered by its revision`);
});

test("an answer's fingerprint is computed as an earlier harness recorded it: the same keys in the same order, so a summary's symbolic citation recorded before still stands (a reordering took down every summary of the finished c10 pilot)", () => {
  const e = {
    v: 4,
    seq: 12,
    kind: "answer",
    section: "question:3",
    result: "not_determinable",
    question_rev: 2,
    support: [{ seq: 4, hash: "b".repeat(64) }, { seq: 3, hash: "a".repeat(64) }],
    contrary: [{ seq: 5, hash: "c".repeat(64) }],
    limitations: [],
    inconclusive: false,
    asserts_absence: false,
  } as unknown as P.LedgerEntry;
  const earlier = P.sha256Hex(JSON.stringify({ result: "not_determinable", question_rev: 2, support: ["a".repeat(64), "b".repeat(64)], contrary: ["c".repeat(64)], limitations: [], inconclusive: false, asserts_absence: false }));
  assert.equal(P.answerFingerprint(e), earlier);
});
