/**
 * The finish (Plan 3, WP4, A4; docs/adr/0015): one coordinator lease with a
 * generation and a takeover that knows about compaction; any other seat's
 * done is "not yours"; readiness computed per revision and posted once per
 * turn; one check result per revision; typed acks that are not late posts,
 * and late objections and results answered by typed resolutions; the
 * revision over the report, the jobs, the policy and the operator's
 * decisions; a summary that cites questions symbolically and is
 * revalidated when their support, scope or contrary evidence changes.
 * Concurrency: two seats asking for the finish at once, a restart, and a
 * coordinator that compacts in the middle of it.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { finishGate } from "../scripts/finish-gate.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const F4 = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const A = { result: "established", confidence: "high", confidence_why: "direct", alternatives_open: "none", would_change: "a second source" } as const;
const GOAL = ["## Goal", "", "Examine it.", "", "### Questions", "", "1. Who?", "2. What?", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary`', ""].join("\n");

async function run(goal?: string) {
  const base = await mkdtemp(join(tmpdir(), "finish-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "f1", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, ...(goal ? { goal } : {}) });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

async function traceRow(S: string, agent: string, tool: string, at: Date = new Date()): Promise<void> {
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at.toISOString(), recv_ts: at.toISOString(), agent, tool, args: {}, result: { ok: true } })}\n`);
}

/** `agent` publishes the report: a revision of work/report.md in its name. */
async function publish(S: string, agent: string, text: string): Promise<void> {
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, "work", "report.md"), text);
  await P.recordFileVersion(S, "work/report.md", agent);
}

const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

test("one coordinator: the report's publisher holds the finish; any other seat's done is not its own, and the sentinel refuses it", async () => {
  const { S, a0, a1, a2 } = await run();
  for (const a of ["a0", "a1", "a2"]) await traceRow(S, a, "bash");
  await publish(S, "a1", "# report\n");
  const t0 = await F.finishTurn(a0, { output_file: "work/report.md" });
  assert.deepEqual([t0.mine, t0.holder, t0.generation], [false, "a1", 1]);
  assert.match(t0.why, /a1 published work\/report\.md last/);
  const t1 = await F.finishTurn(a1, { output_file: "work/report.md" });
  assert.deepEqual([t1.mine, t1.holder, t1.generation], [true, "a1", 1]);
  // The sentinel is the coordinator's: another seat's markDone is refused, quietly worded.
  await assert.rejects(P.markDone(a2, { reason: "finished", outputFile: "work/report.md" }), new RegExp(`^Error: ${F.NOT_YOURS}a1 coordinates the finish \\(generation 1\\)`));
  assert.equal((await F.mayFinish(S, "a1")).ok, true);
  // A seat leaving on its own cap is not the finish.
  const cap = await P.markDone(a2, { reason: "agent_cap", outputFile: "work/report.md", createSentinel: false });
  assert.equal("created_sentinel" in cap && cap.created_sentinel, false);
});

test("two seats asking for the finish at once make one lease; a compacting or silent coordinator is taken over at the next generation, and the lease survives a restart", async () => {
  const { S, a0, a1, a2 } = await run();
  for (const a of ["a0", "a1", "a2"]) await traceRow(S, a, "bash");
  const [x, y] = await Promise.all([F.finishTurn(a0, { output_file: "work/report.md" }), F.finishTurn(a2, { output_file: "work/report.md" })]);
  assert.equal(x.holder, y.holder, "one lease, whoever asked first");
  assert.equal((await F.readFinish(S)).events.filter((e) => e.ev === "lease").length, 1);
  const holder = x.holder;
  const other = holder === "a0" ? a2 : a0;
  // The coordinator compacts: unavailable for the whole compaction.
  await traceRow(S, holder, "compact_start");
  const take = await F.finishTurn(other, { output_file: "work/report.md" });
  assert.deepEqual([take.mine, take.took_over, take.generation], [true, holder, 2]);
  assert.match(take.why, new RegExp(`${holder} is unavailable \\(${holder} is compacting its context\\): taken over by ${other.agentId}`));
  // Its compaction over, the old coordinator's done is no longer the finish.
  await traceRow(S, holder, "compact_done");
  await traceRow(S, holder, "bash");
  const back = await F.finishTurn({ sandboxRoot: S, agentId: holder }, { output_file: "work/report.md" });
  assert.deepEqual([back.mine, back.holder, back.generation], [false, other.agentId, 2]);
  // A fresh process reads the same lease.
  const fresh = (await import(`../extensions/finish.ts?restart=${Date.now()}`)) as typeof F;
  assert.deepEqual([(await fresh.readFinish(S)).lease?.holder, (await fresh.readFinish(S)).lease?.generation], [other.agentId, 2]);
  assert.equal((await fresh.readFinish(S)).chain.ok, true);
  // A dead coordinator: taken over too.
  await mkdir(join(S, "done", "agents"), { recursive: true });
  await writeFile(join(S, "done", "agents", `${other.agentId}.dead`), "x");
  const third = [a0, a1, a2].find((c) => c.agentId !== other.agentId)!;
  const t3 = await F.finishTurn(third, { output_file: "work/report.md" });
  assert.deepEqual([t3.mine, t3.generation], [true, 3]);
});

test("late against the report: a result posted after it needs the coordinator's typed resolution; a typed ack of no objection does not; an objection does", async () => {
  const { S, a0, a1, a2 } = await run();
  for (const a of ["a0", "a1", "a2"]) await traceRow(S, a, "bash");
  await publish(S, "a0", "# report v1\n");
  await F.finishTurn(a0, { output_file: "work/report.md" });
  await new Promise((r) => setTimeout(r, 20));
  const post = await P.postMessage(a1, { tag: "result", body: "the timeline misses the second logon" });
  let late = await F.lateItems(S, "a0", "work/report.md");
  assert.deepEqual(late.map((x) => [x.kind, x.id, x.by]), [["post", post.id, "a1"]]);
  // An ack is typed: no late post, whatever it says.
  refused(await F.ackReport(a0, { verdict: "no_objection" }), /you coordinate the finish/);
  refused(await F.ackReport(a2, { verdict: "objection" }), /an objection says why/);
  refused(await F.ackReport(a2, { verdict: "no_objection", digest: "0".repeat(64) }), /read it again, then ack what you read/);
  const ack = await F.ackReport(a2, { verdict: "no_objection" });
  assert.ok(ack.ok);
  assert.deepEqual((await F.lateItems(S, "a0", "work/report.md")).map((x) => x.kind), ["post"]);
  const obj = await F.ackReport(a1, { verdict: "objection", why: "question 2's answer is a best candidate, the report calls it established" });
  assert.ok(obj.ok);
  late = await F.lateItems(S, "a0", "work/report.md");
  assert.deepEqual(late.map((x) => x.kind).sort(), ["objection", "post"]);
  // Resolutions are the coordinator's, typed, each naming what it answers.
  refused(await F.resolveLate(a1, { post: post.id, how: "not_material", why: "x" }), /resolutions are the coordinator's \(a0\)/);
  refused(await F.resolveLate(a0, { post: post.id, how: "ignored", why: "x" }), /how is folded .* or not_material/);
  refused(await F.resolveLate(a0, { post: post.id, how: "not_material" }), /why is required/);
  refused(await F.resolveLate(a0, { post: 999, how: "not_material", why: "x" }), /post #999 is not open against the report/);
  assert.ok((await F.resolveLate(a0, { post: post.id, how: "not_material", why: "the second logon is the same session, already in the timeline" })).ok);
  assert.ok((await F.resolveLate(a0, { ack: (obj as { seq: number }).seq, how: "folded", why: "section 2 now says best candidate" })).ok);
  assert.deepEqual(await F.lateItems(S, "a0", "work/report.md"), []);
  // A new version of the report: an old objection is of another digest; a new one needs a new resolution.
  await publish(S, "a0", "# report v2\n");
  assert.deepEqual(await F.lateItems(S, "a0", "work/report.md"), [], "the post is older than the report now");
  const status = await F.finishStatus(a2);
  assert.equal((status.coordinator as { holder: string }).holder, "a0");
});

test("readiness per revision: not ready with what holds it, ready once it is not, posted once each time it turns; the header says whose the finish is", async () => {
  const { S, a0, a1 } = await run();
  for (const a of ["a0", "a1"]) await traceRow(S, a, "bash");
  const open = await L.openLead(a1, { title: "Walk the registry", why: "background", take: true });
  assert.ok(open.ok);
  let r = await F.readiness(S);
  assert.equal(r.ready, false);
  assert.ok(r.items.some((i) => /L-1 "Walk the registry" is active \(held by a1\) with no disposition/.test(i)), r.items.join("\n"));
  assert.equal(await F.syncReadiness(S, r), false, "not ready from the start is nothing to post");
  const f = await P.recordEntry(a1, { kind: "finding", ...F4, value: "The registry holds nothing of note", source: "hives", evidence: "a listing" } as P.LedgerInput);
  assert.ok(f.ok);
  assert.ok((await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-1" })).ok);
  r = await F.readiness(S);
  assert.deepEqual([r.ready, r.items], [true, []]);
  assert.equal(await F.syncReadiness(S, r), true);
  assert.equal(await F.syncReadiness(S, r), false, "posted once");
  const posts = async () => (await P.readInbox({ sandboxRoot: S, agentId: "a0" }, { markSeen: false })).posts.map((p) => p.body);
  assert.ok((await posts()).some((b) => /^FINISH READY by the registers/.test(b)));
  const header = await F.finishHeader(S, "a0");
  assert.match(header ?? "", /^Finish: READY by the registers; nobody coordinates it yet: the first done takes it/);
  // Back to not ready: said once.
  assert.ok((await L.openLead(a0, { title: "A late avenue", why: "found", take: true })).ok);
  r = await F.readiness(S);
  assert.equal(r.ready, false);
  assert.equal(await F.syncReadiness(S, r), true);
  assert.ok((await posts()).some((b) => /^FINISH NOT READY again .*: L-2 "A late avenue"/.test(b)));
  // The coordinator's header says what is late and what to do; another seat's says it is not theirs.
  await publish(S, "a0", "# report\n");
  await F.finishTurn(a0, { output_file: "work/report.md" });
  assert.match((await F.finishHeader(S, "a1")) ?? "", /a0 coordinates it \(generation 1\)\. Your done is not the finish/);
  assert.match((await F.finishHeader(S, "a0")) ?? "", /a0 \(you\) coordinates it/);
});

test("one check result per revision, and the revision moves with the report, a job, the policy and the operator's decisions", async () => {
  const { S, a0 } = await run();
  await traceRow(S, "a0", "bash");
  await publish(S, "a0", "# report\n");
  await F.finishTurn(a0, { output_file: "work/report.md" });
  const rev = async () => (await P.stateRevision(S)).revision;
  const r0 = await rev();
  assert.equal(await F.checkAt(S, r0), null);
  await F.recordCheck(S, "a0", r0, { proceed: false, reason: "the report has no section 2" }, { total: 1, passed: 0, checks: [] });
  await F.recordCheck(S, "a0", r0, { proceed: true, outcome: "completed" }, { total: 1, passed: 1, checks: [] });
  const c = await F.checkAt(S, r0);
  assert.deepEqual([c?.proceed, c?.reason], [false, "the report has no section 2"], "one result per revision: the first stands");
  // An ack does not move it.
  await traceRow(S, "a1", "bash");
  assert.ok((await F.ackReport({ sandboxRoot: S, agentId: "a1" }, { verdict: "no_objection" })).ok);
  assert.equal(await rev(), r0, "a typed ack is not a change of state");
  // The report does.
  await publish(S, "a0", "# report\n\n## 2.\n");
  const r1 = await rev();
  assert.notEqual(r1, r0);
  assert.equal(await F.checkAt(S, r1), null);
  // A job's state does.
  await mkdir(join(S, "store", "jobs", "j000001"), { recursive: true });
  await writeFile(join(S, "store", "jobs", "j000001", "job.json"), JSON.stringify({ id: "j000001", state: "running", requester: { agent: "a0" }, spec: { kind: "command" } }));
  const r2 = await rev();
  assert.notEqual(r2, r1);
  // The policy does (a pause).
  const b = await P.readBudget(S);
  await P.writeBudget(S, { ...b, paused: { at: new Date().toISOString(), reason: "cap", detail: "the token cap" } });
  const r3 = await rev();
  assert.notEqual(r3, r2);
  // The operator's decisions do.
  await appendFile(join(S, L.OPERATOR_HOSTS), `${JSON.stringify({ at: new Date().toISOString(), host: "example.org", lead: "L-1", by: "operator" })}\n`);
  assert.notEqual(await rev(), r3);
});

test("an offer made, delivered or declined does not move the revision the finish is checked at; a closure offered to its closer to confirm does", async () => {
  const { S, a0, a1 } = await run(GOAL);
  for (const a of ["a0", "a1"]) await traceRow(S, a, "bash");
  const rev = async () => (await P.stateRevision(S)).revision;
  // a1 waits: an unheld lead is offered to it in the open's own act.
  const since = new Date(Date.now() - 5 * 60_000).toISOString();
  await mkdir(join(S, "inbox", "a1"), { recursive: true });
  await writeFile(join(S, "inbox", "a1", "waiting.json"), JSON.stringify({ since, started_at: since }));
  const opened = await L.openLead(a0, { title: "Read the prefetch folder", why: "background", material: false });
  assert.ok(opened.ok && opened.offered_to === "a1", JSON.stringify(opened));
  const r0 = await rev();
  const offer = (await L.leadsSnapshot(S)).state.leads.get("L-1")!.offers.at(-1)!;
  await L.markOffersSeen(S, "a1", [{ lead: "L-1", offer: offer.seq }]);
  assert.ok((await L.leadsSnapshot(S)).state.leads.get("L-1")!.offers.at(-1)!.seen_at, "delivered");
  assert.equal(await rev(), r0, "a delivery is bookkeeping");
  assert.ok((await L.answerLeadOffer(a1, "L-1", { action: "decline", why: "I hold the registry work" })).ok);
  assert.equal(await rev(), r0, "a decline is bookkeeping");
  await F.recordCheck(S, "a0", r0, { proceed: true, outcome: "completed" }, { total: 1, passed: 1, checks: [] });
  assert.equal((await F.checkAt(S, await rev()))?.proceed, true, "the check at that revision still stands for the next done");
  // A claim is not bookkeeping.
  assert.ok((await L.claimLead(a0, "L-1")).ok);
  assert.notEqual(await rev(), r0);
  // A closure offered to its closer to confirm holds the finish, so it moves the revision.
  const f = await P.recordEntry(a0, { kind: "finding", ...F4, value: "Nothing ran from the temp folder", source: "prefetch", evidence: "the listing" } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  assert.ok((await L.closeLead(a0, "L-1", { disposition: "resolved", ref: `E-${f.entry.seq}` })).ok);
  const g = await P.recordEntry(a1, { kind: "finding", ...F4, value: "Nothing ran from the temp folder after ten", source: "prefetch", evidence: "the listing, sorted", supersedes: f.entry.seq, because: "the listing was unsorted" } as P.LedgerInput);
  assert.ok(g.ok, (g as { reason?: string }).reason);
  const before = await rev();
  await L.reopenOnLedger(S);
  assert.ok((await L.leadsSnapshot(S)).state.leads.get("L-1")!.confirm, "offered to its closer to confirm");
  assert.notEqual(await rev(), before, "a closure to confirm moves it");
  // The line test itself: only the registers' offer bookkeeping.
  assert.equal(P.offerBookkeeping('{"v":1,"seq":4,"at":"x","by":"a1","ev":"offer_seen","lead":"L-1","offer":3}'), true);
  assert.equal(P.offerBookkeeping('{"v":1,"seq":3,"at":"x","by":"system","ev":"offer","lead":"L-1","to":"a1","reason":"wake"}'), true);
  assert.equal(P.offerBookkeeping('{"v":1,"seq":3,"at":"x","by":"system","ev":"offer","lead":"L-1","to":"a1","reason":"confirm"}'), false);
  assert.equal(P.offerBookkeeping('{"v":1,"seq":5,"at":"x","by":"a1","ev":"open","lead":"L-2","title":"say \\"ev\\":\\"offer\\" here"}'), false);
});

test("a summary cites questions symbolically: a reworded correction of an answer keeps it standing; a changed support, or a question withdrawn, makes it be recorded again", async () => {
  const { S, a0, a1, a2 } = await run(GOAL);
  const f1 = await P.recordEntry(a0, { kind: "finding", ...F4, value: "Bob", source: "log", evidence: "line 1", refs: ["unresolved:fixture"], answers: ["1"] } as P.LedgerInput);
  assert.ok(f1.ok);
  if (!f1.ok) return;
  const q1 = await P.recordEntry(a1, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${f1.entry.seq}`, ...A } as P.LedgerInput);
  assert.ok(q1.ok);
  if (!q1.ok) return;
  const sum = await P.recordEntry(a2, { kind: "answer", section: "summary", value: "Bob did it (Q-1).", reasoning: `Q-1 says who: E-${q1.entry.seq}.` } as P.LedgerInput);
  assert.ok(sum.ok, (sum as { reason?: string }).reason);
  if (!sum.ok) return;
  assert.deepEqual(sum.entry.question_refs?.map((r) => [r.q, r.section, r.answer]), [["Q-1", "question:1", q1.entry.seq]]);
  assert.deepEqual(sum.entry.support ?? [], [], "the answer cited by seq too is held by the symbolic cite, not by its seq");
  const problems = async () => P.answerProblems(await P.readLedger(S), await P.readDisputes(S));
  assert.equal((await problems()).size, 0);
  // Reworded, the same support: the summary stands.
  const q1b = await P.recordEntry(a1, { kind: "answer", section: "question:1", value: "It was Bob", reasoning: `E-${f1.entry.seq} names him`, ...A, supersedes: q1.entry.seq } as P.LedgerInput);
  assert.ok(q1b.ok);
  assert.equal((await problems()).has(sum.entry.seq), false, "a wording change does not take the summary down");
  // A changed support: recorded again.
  const f2 = await P.recordEntry(a0, { kind: "finding", ...F4, value: "Bob, from the console", source: "log", evidence: "line 2", refs: ["unresolved:fixture"], answers: ["1"] } as P.LedgerInput);
  assert.ok(f2.ok && q1b.ok);
  if (!f2.ok || !q1b.ok) return;
  const q1c = await P.recordEntry(a1, { kind: "answer", section: "question:1", value: "It was Bob", reasoning: `E-${f2.entry.seq} names him`, ...A, supersedes: q1b.entry.seq } as P.LedgerInput);
  assert.ok(q1c.ok);
  const p = (await problems()).get(sum.entry.seq);
  assert.ok(p?.some((x) => /it cites Q-1 \(question:1\), whose answer changed its support, scope or contrary evidence since it was cited/.test(x)), JSON.stringify(p));
  // A summary citing a question with no answer is refused.
  const bad = await P.recordEntry(a2, { kind: "answer", section: "narrative", value: "Q-2 happened.", reasoning: "Q-2" } as P.LedgerInput);
  assert.equal(bad.ok, false);
  assert.match((bad as { reason: string }).reason, /Q-2 \(question:2\) has no standing answer yet/);
  // The question withdrawn since: the gate says the summary is to be recorded again.
  const again = await P.recordEntry(a2, { kind: "answer", section: "summary", value: "Bob did it (Q-1).", reasoning: "Q-1 says who.", supersedes: sum.entry.seq } as P.LedgerInput);
  assert.ok(again.ok, (again as { reason?: string }).reason);
  const operator: Q.Actor = { kind: "human", role: "examiner", person: "ex@lab", enrolled: false, os_user: "ex", host: "lab", via: "cli", identity: "claimed" };
  const w = await Q.act(S, operator, "withdraw", { q: "Q-1", why: "not needed after all" });
  assert.ok(w.ok, (w as { reason?: string }).reason);
  const gate = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.ok(gate.defects.some((d) => /the summary E-\d+ cites Q-1 \(question:1\), withdrawn by ex@lab/.test(d.what)), JSON.stringify(gate.defects));
});
