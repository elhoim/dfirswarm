/**
 * The operator requests' outbox (extensions/requests.ts, docs/adr/0014):
 * durable ids for every kind (a lead's needs_operator, an acquisition, a
 * clarification, a network item, a stop proposed), the lifecycle pending →
 * notified → acknowledged → answered | declined | withdrawn, the
 * acquisition's stages, the case policy's more_evidence answered at once
 * with its exact words, a crash between the commit and the notification
 * made good once, notifications that carry ids only, a failed write that is
 * said and never swallowed, and a run from before the chain kept whole.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import { resolveCasePolicy } from "../scripts/case-policy.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const GOAL = ["## Goal", "", "Examine the mailbox.", "", "### Questions", "", "1. Which message changed the bank details?", "2. What was paid, and when?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`', ""].join("\n");

async function run(o: { more?: "no" | "ask" | "yes" } = {}) {
  const base = await mkdtemp(join(tmpdir(), "requests-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "r1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  if (o.more) {
    const r = resolveCasePolicy({ flags: { more_evidence: o.more }, isolation: "microvm" });
    assert.ok(r.ok);
    await mkdir(join(S, "network"), { recursive: true });
    await writeFile(join(S, "network", "policy.json"), JSON.stringify((r as { policy: unknown }).policy));
  }
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, a0: ctx("a0"), a1: ctx("a1") };
}

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

const ASK = { kind: "acquisition", source: "the finance system's export of the payment run", where: "the ERP, held by finance", expected_value: "what was paid to the new account, and when", urgency: "normal" };

/** A notifier that records what it was handed, as notify.sh would be. */
function recorder(targets = ["command"]) {
  const got: Array<{ event: string; notice: Record<string, unknown> }> = [];
  const notifier: R.Notifier = async (_S, event, notice) => {
    got.push({ event, notice });
    return { targets };
  };
  return { got, notifier };
}

test("a lead closed needs_operator is a request with a durable id: committed on the close, written once by its key, rendered where it always was, chained", async () => {
  const { S, a1 } = await run();
  ok(await L.openLead(a1, { title: "The key is outside", why: "part 3", take: true }));
  const closed = ok(await L.closeLead(a1, "L-1", { disposition: "needs_operator", ref: "The key is on a paste site; allow its host so a job can fetch it" }));
  assert.equal(closed.request?.id, "R-1");
  assert.equal(closed.request?.kind, "lead");
  assert.equal(closed.request?.state, "pending");
  assert.match(closed.operator_request ?? "", /^swarm\.sh lead r1 note L-1/);
  // Reconciling again writes nothing twice.
  await R.reconcileRequests(S);
  const s = await R.requestsSnapshot(S);
  assert.equal(s.requests.size, 1);
  assert.equal(s.byKey.get(`lead:L-1:${(await L.readLeadEvents(S)).events.find((e) => e.ev === "close")!.seq}`), "R-1");
  // The chain is the lead register's: custody checks it with the same code.
  assert.ok(L.verifyLeadChain(await readFile(join(S, R.REQUESTS_LOG), "utf8")).ok);
  const view = (await readFile(join(S, L.OPERATOR_REQUESTS), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(view.length, 1);
  assert.deepEqual([view[0].rid, view[0].lead, view[0].by, view[0].run, view[0].state], ["R-1", "L-1", "a1", "r1", "pending"]);
  // The operator's note answers it (and reopens the lead).
  ok(await L.noteLead(S, "L-1", "Allowed; fetch it with a job"));
  await R.reconcileRequests(S);
  const after = (await R.requestsSnapshot(S)).requests.get("R-1")!;
  assert.equal(after.state, "answered");
  assert.equal(after.closed?.cause, "lead_note");
});

test("an acquisition is asked on the close: checked, with its questions; its lifecycle requested → authorised → collecting → received → validated, and a stage out of order is refused", async () => {
  const { S, a0 } = await run();
  ok(await L.openLead(a0, { title: "What was paid", why: "Q2", answers: ["2"], take: true }));
  refused(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: { kind: "acquisition", where: "x", expected_value: "y" } }), /source/);
  refused(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: { ...ASK, urgency: "soon" } }), /urgency is one of normal, urgent, volatile/);
  refused(await L.closeLead(a0, "L-1", { disposition: "deferred", ref: "E-1", ask: ASK }), /ask goes with needs_operator/);
  const closed = ok(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: ASK }));
  assert.equal(closed.request?.kind, "acquisition");
  assert.equal(closed.request?.stage, "requested");
  const r = (await R.requestsSnapshot(S)).requests.get("R-1")!;
  assert.deepEqual(r.questions, ["Q-2"], "the lead's questions, when the ask names none");
  assert.equal(r.ask?.source, ASK.source);
  refused(await R.requestAct(S, "R-1", { ev: "stage", by: "operator", stage: "validated" }), /is requested: it can go to authorised, declined, unavailable, received, not validated/);
  ok(await R.requestAct(S, "R-1", { ev: "stage", by: "operator", stage: "authorised", why: "the client consents" }));
  assert.equal((await R.requestsSnapshot(S)).requests.get("R-1")!.state, "acknowledged");
  ok(await R.requestAct(S, "R-1", { ev: "stage", by: "operator", stage: "collecting" }));
  refused(await R.requestAct(S, "R-1", { ev: "stage", by: "operator", stage: "unavailable" }), /says why/);
  ok(await R.requestAct(S, "R-1", { ev: "stage", by: "operator", stage: "received", import: "ev-0001", sha256: ["a".repeat(64)] }));
  const done = ok(await R.requestAct(S, "R-1", { ev: "stage", by: "harness", stage: "validated", import: "ev-0001" }));
  assert.equal(done.request.state, "answered");
  assert.deepEqual(done.request.stages.map((x) => x.stage), ["requested", "authorised", "collecting", "received", "validated"]);
  refused(await R.requestAct(S, "R-1", { ev: "declined", by: "operator", why: "late" }), /answered already/);
});

test("under more_evidence: no the hub answers an acquisition at once, with exactly 'no additional input under this case policy', never that the fact is absent", async () => {
  const { S, a0 } = await run({ more: "no" });
  ok(await L.openLead(a0, { title: "What was paid", why: "Q2", answers: ["2"], take: true }));
  const closed = ok(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: ASK }));
  assert.equal(closed.request?.state, "declined");
  assert.equal(closed.request?.stage, "declined");
  assert.equal(closed.request?.answer, "no additional input under this case policy");
  assert.equal(R.NO_MORE_EVIDENCE, "no additional input under this case policy");
  const r = (await R.requestsSnapshot(S)).requests.get("R-1")!;
  assert.equal(r.closed?.by, "case policy");
  assert.equal(r.closed?.cause, "case_policy");
  assert.equal(r.closed?.text, "no additional input under this case policy");
  assert.doesNotMatch(r.closed?.text ?? "", /absent|not exist|does not|was not found/i, "the answer is a constraint of the case, never a statement about the fact");
  // A lead request that is not an acquisition is left to the operator whatever the policy.
  ok(await L.openLead(a0, { title: "A host", why: "w", take: true }));
  const other = ok(await L.closeLead(a0, "L-2", { disposition: "needs_operator", ref: "allow the host example.org for a job" }));
  assert.equal(other.request?.state, "pending");
});

test("under more_evidence: yes an acquisition is authorised by the policy; under ask it waits for the operator", async () => {
  const yes = await run({ more: "yes" });
  ok(await L.openLead(yes.a0, { title: "What was paid", why: "Q2", answers: ["2"], take: true }));
  const c = ok(await L.closeLead(yes.a0, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: ASK }));
  assert.equal(c.request?.stage, "authorised");
  assert.equal(c.request?.state, "acknowledged");
  const ask = await run({ more: "ask" });
  ok(await L.openLead(ask.a0, { title: "What was paid", why: "Q2", answers: ["2"], take: true }));
  const d = ok(await L.closeLead(ask.a0, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: ASK }));
  assert.equal(d.request?.stage, "requested");
  assert.equal(d.request?.state, "pending");
});

test("a clarification, a network item and a stop proposal are requests too, each by its own key, each closed by what answers it", async () => {
  const { S, a0 } = await run();
  await Q.seedRegister(S);
  const asked = ok(await Q.questionAsk(a0, "Q-1", "the bank details: the supplier's or the clerk's own?"));
  assert.equal(asked.request_id, "R-1");
  // A network item committed on the grants chain.
  await mkdir(join(S, "network"), { recursive: true });
  await appendFile(join(S, "network", "grants.jsonl"), `${JSON.stringify({ seq: 1, at: new Date().toISOString(), by: "policy", ev: "item", item: "NI-1", host: "maps.example.org", lead: null, request: "NR-1" })}\n`);
  const opened = await R.openHarnessRequest(S, { kind: "decision", key: "decision:D-1", by: "harness", line: { at: new Date().toISOString(), run: "r1", kind: "decision", id: "D-1", title: "A stop is proposed", request: "nothing yielded", answer: "swarm.sh stop r1" } });
  assert.deepEqual(opened, { rid: "R-2", created: true });
  assert.deepEqual(await R.openHarnessRequest(S, { kind: "decision", key: "decision:D-1", by: "harness", line: {} }), { rid: "R-2", created: false });
  await R.reconcileRequests(S);
  let s = await R.requestsSnapshot(S);
  assert.deepEqual([...s.requests.values()].map((r) => `${r.rid} ${r.kind}`), ["R-1 clarification", "R-2 decision", "R-3 network"]);
  assert.equal(await R.countKind(S, "decision"), 1);
  // The clarification's reply answers it; the item's close denies it; the operator's stop answers the proposal.
  ok(await Q.act(S, { kind: "human", role: "operator", person: "t@lab", enrolled: false, os_user: "t", host: "lab", via: "cli", identity: "claimed" }, "clarify_answer", { q: "Q-1", clarify: "C-1", answer: "the supplier's" }));
  await appendFile(join(S, "network", "grants.jsonl"), `${JSON.stringify({ seq: 2, at: new Date().toISOString(), by: "operator", ev: "item_close", item: "NI-1", how: "denied", why: "not needed" })}\n`);
  await P.markStopped(S, "operator", "swarm.sh stop");
  await R.reconcileRequests(S);
  s = await R.requestsSnapshot(S);
  assert.deepEqual([...s.requests.values()].map((r) => `${r.rid} ${r.state}`), ["R-1 answered", "R-2 answered", "R-3 declined"]);
});

test("the outbox: a crash between the commit and the notification loses nothing and notifies once; with no target it stays pending", async () => {
  const { S, a0 } = await run();
  ok(await L.openLead(a0, { title: "What was paid", why: "Q2", answers: ["2"], take: true }));
  // The close committed, and the process died before the request was written: the close event alone.
  await L.withRegisters(S, async (held) => {
    await L.appendLeadEventsHeld(S, [{ by: "a0", ev: "close", lead: "L-1", generation: 1, disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: { kind: "acquisition", source: ASK.source, where: ASK.where, questions: ["Q-2"], expected_value: ASK.expected_value, urgency: "urgent", owner: "", authority_needed: "" } }], held);
  });
  assert.equal((await R.requestsSnapshot(S)).requests.size, 0, "nothing was written before the crash");
  // No target configured: nothing is sent, and it stays pending.
  const none = recorder([]);
  await R.fireRequests(S, { notifier: none.notifier });
  assert.equal((await R.requestsSnapshot(S)).requests.get("R-1")?.state, "pending");
  assert.equal(none.got.length, 1, "handed to the notifier, which had no target");
  // A target: notified once, recorded after the hand-over; a second round sends nothing.
  const one = recorder();
  const fired = await R.fireRequests(S, { notifier: one.notifier });
  assert.deepEqual(fired.notified, ["R-1"]);
  await R.fireRequests(S, { notifier: one.notifier });
  assert.equal(one.got.length, 1, "notified once");
  const r = (await R.requestsSnapshot(S)).requests.get("R-1")!;
  assert.equal(r.state, "notified");
  assert.deepEqual(r.notified.map((x) => x.targets), [["command"]]);
  // A notifier that fails leaves it pending, and the next round sends it.
  ok(await L.openLead(a0, { title: "t2", why: "w", take: true }));
  ok(await L.closeLead(a0, "L-2", { disposition: "needs_operator", ref: "allow the host example.org for a job" }));
  await R.dispatchRequests(S, { notifier: async () => { throw new Error("the hook is down"); } });
  assert.equal((await R.requestsSnapshot(S)).requests.get("R-2")?.state, "pending");
  const again = recorder();
  await R.dispatchRequests(S, { notifier: again.notifier });
  assert.deepEqual(again.got.map((g) => g.notice.request), ["R-2"]);
});

test("a notification carries ids only: the request's id and kind, the lead's or question's id, never what was asked", async () => {
  const { S, a0 } = await run();
  await Q.seedRegister(S);
  const secretWords = "the supplier's IBAN GB33BUKB20201555555555 in the second mail";
  ok(await L.openLead(a0, { title: `Find ${secretWords}`, why: "Q2", answers: ["2"], take: true }));
  ok(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: `Need the export: ${secretWords}`, ask: { ...ASK, source: `export naming ${secretWords}`, urgency: "volatile" } }));
  ok(await Q.questionAsk(a0, "Q-1", `is ${secretWords} the supplier's?`));
  const rec = recorder();
  await R.dispatchRequests(S, { notifier: rec.notifier });
  assert.equal(rec.got.length, 2);
  for (const g of rec.got) {
    assert.equal(g.event, "operator_request");
    const text = JSON.stringify(g.notice);
    assert.ok(!text.includes("GB33BUKB"), `a notification carried case content: ${text}`);
    assert.ok(!/supplier|export|IBAN/i.test(text), `a notification carried words of the request: ${text}`);
    for (const k of Object.keys(g.notice)) assert.ok(["request", "kind", "run", "lead", "question", "id", "item", "questions", "urgency", "show"].includes(k), `unexpected key ${k}`);
  }
  assert.deepEqual(rec.got.map((g) => [g.notice.request, g.notice.kind, g.notice.lead ?? g.notice.question]), [["R-1", "acquisition", "L-1"], ["R-2", "clarification", "Q-1"]]);
  assert.equal(rec.got[0].notice.urgency, "volatile");
});

test("a request that cannot be written is said, never swallowed, and written at the next reconciliation", async () => {
  const { S, a0 } = await run();
  ok(await L.openLead(a0, { title: "t", why: "w", take: true }));
  // A broken requests chain: the write fails.
  await mkdir(join(S, R.REQUESTS_DIR), { recursive: true });
  await writeFile(join(S, R.REQUESTS_LOG), "not json\n");
  const closed = ok(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "allow the host example.org for a job" }));
  assert.equal(closed.request, undefined);
  assert.match(closed.request_pending ?? "", /committed on L-1's close.*could not be written.*next reconciliation/);
  // The operator looks, the chain is put right: the next reconciliation writes it from the close.
  await rm(join(S, R.REQUESTS_LOG));
  await R.reconcileRequests(S);
  assert.equal((await R.requestsSnapshot(S)).requests.get("R-1")?.lead, "L-1");
});

test("a run from before the chain keeps its request lines: the first write imports each one whole", async () => {
  const { S, a0 } = await run();
  const legacy = [
    { at: "2026-09-27T21:00:10.198Z", run: "r1", lead: "L-9", by: "a1", title: "Derive the venue", request: "old words", answer: "swarm.sh lead r1 note L-9 ..." },
    { at: "2026-09-27T22:00:00.000Z", run: "r1", kind: "decision", id: "D-1", by: "harness", title: "A stop is proposed", request: "nothing yielded", answer: "swarm.sh stop r1" },
  ];
  await writeFile(join(S, L.OPERATOR_REQUESTS), legacy.map((l) => JSON.stringify(l)).join("\n") + "\n");
  ok(await L.openLead(a0, { title: "t", why: "w", take: true }));
  ok(await L.closeLead(a0, "L-1", { disposition: "needs_operator", ref: "allow the host example.org for a job" }));
  const view = (await readFile(join(S, L.OPERATOR_REQUESTS), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(view.map((v) => [v.rid, v.kind, v.request]), [["R-1", "lead", "old words"], ["R-2", "decision", "nothing yielded"], ["R-3", "lead", "allow the host example.org for a job"]]);
  const s = await R.requestsSnapshot(S);
  assert.ok(s.requests.get("R-1")?.imported);
  // An imported request is not notified again.
  const rec = recorder();
  await R.dispatchRequests(S, { notifier: rec.notifier });
  assert.deepEqual(rec.got.map((g) => g.notice.request), ["R-3"]);
});
