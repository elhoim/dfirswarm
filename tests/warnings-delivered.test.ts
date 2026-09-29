/**
 * The answers check's warnings delivered where the decision is made
 * (docs/adr/0013, "Warnings where the decision is made"): in the reply to
 * the record that writes the answer, in the review offered for it and the
 * reply to an attest on it, and in finish status, each in the same words,
 * none holding. lead_findings_uncited covers what two seats hold for a
 * question outside its leads too: a finding or an event that names the
 * question, or whose rel links it to an entry the answer cites. And the
 * request guidance: a question put to the operator says what would settle
 * it, a value read from an image comes from a job that read it, and under
 * more_evidence: no nothing suggests an ask. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { A, coverage, ESTABLISHED, F, ok, okq, planned, rec, REVIEW, run } from "./negative-bar-fixture.ts";

const ROOT = resolve(import.meta.dirname, "..");

const GOAL = (n: number) =>
  [
    "## Goal",
    "",
    "Examine the host.",
    "",
    "### Questions",
    "",
    ...["Which methods hid the data?", "Which account was used?", "What was deleted?"].slice(0, n).map((q, i) => `${i + 1}. ${q}`),
    "",
    "## Definition of done",
    "",
    "d",
    "",
    "## Checks",
    "",
    `- \`node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections ${Array.from({ length: n }, (_, i) => i + 1).join(",")}\``,
    "",
  ].join("\n");

type Ctx = { sandboxRoot: string; agentId: string };

const finding = (value: string, answers: string[], o: Record<string, unknown> = {}) => ({ kind: "finding", ...F, value, source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers, ...o });

async function attest(c: Ctx, input: Record<string, unknown>) {
  const r = await P.attestEntry(c, input as unknown as P.LedgerActInput);
  assert.ok(r.ok && r.line, JSON.stringify(r));
  return r as Extract<P.AttestResult, { ok: true; line: P.LedgerAttestation }>;
}

const answer = (c: Ctx, section: string, cites: number[], o: Record<string, unknown> = {}) => rec(c, { kind: "answer", section, value: `the answer, on ${cites.map((n) => `E-${n}`).join(", ")}`, reasoning: cites.map((n) => `E-${n}`).join("; "), ...A, confidence: "high", result: "established", ...o });

test("lead_findings_uncited reaches past the question's leads: a finding under another question's lead that names the question, one seat's that names it, and one whose rel links it to an entry the answer cites; never one tied by nothing, one seat's tied only by rel, disputed, superseded or reached", async () => {
  const r = await run({ goal: GOAL(2) });
  const L1 = await planned(r.a0, "1");
  // Reached through a rel of the entry the answer cites: never warned of.
  const reached = ok(await rec(r.a0, finding("the archive tool's own log", ["1"]))).entry;
  const cited = ok(await rec(r.a0, finding("the first hiding method", ["1"], { rel: [{ to: reached.seq, kind: "derived_from" }] }))).entry;
  assert.ok((await L.closeLead(r.a0, L1, { disposition: "resolved", ref: `E-${cited.seq}` })).ok);
  // Question 2's lead: what it established.
  const L2 = await planned(r.a2, "2");
  assert.ok((await L.attachJob(r.S, "a2", "j000001", L2)).ok);
  const names = ok(await rec(r.a2, finding("the second hiding method", ["2", "Q-1"]))).entry;
  const linked = ok(await rec(r.a2, finding("the first method was used twice", ["2"], { rel: [{ to: cited.seq, kind: "supports" }] }))).entry;
  const apart = ok(await rec(r.a2, finding("the account was svc_backup", ["2"]))).entry;
  for (const e of [names, linked, apart]) assert.ok((await L.recordInterpretations(r.S, "a2", e.seq, ["j000001"])).ok);
  assert.ok((await L.closeLead(r.a2, L2, { disposition: "resolved", ref: `E-${apart.seq}` })).ok);
  // One seat's, linked by rel to the cited finding, naming question 2 only: rel alone asks for two seats.
  const oneLinked = ok(await rec(r.a0, finding("the first method left a log", ["2"], { rel: [{ to: cited.seq, kind: "supports" }] }))).entry;
  // Tied to question 1 by name: one seat's (warned of: its author tied it), and a disputed and a superseded one (not; the correction is).
  const alone = ok(await rec(r.a0, finding("a third method, seen once", ["1"]))).entry;
  const disputed = ok(await rec(r.a0, finding("a fourth method", ["1"]))).entry;
  const old = ok(await rec(r.a0, finding("a fifth method, in 2023", ["1"]))).entry;
  const event = { kind: "event", ts: "2024-01-01T09:14:00Z", value: "the hidden volume was mounted", source: "the disk", evidence: "the mount history", refs: ["job:j000001/hits.txt"], answers: ["1"] };
  const twice = ok(await rec(r.a0, event)).entry;
  assert.equal(ok(await rec(r.a3, event)).merged, true, "the same event from another seat is a second author");
  for (const e of [reached, cited, names, linked, apart, disputed, old]) await attest(r.a3, { seq: e.seq, how: "re-read the record from job:j000001/hits.txt" });
  assert.ok((await P.disputeEntry(r.a1, { seq: disputed.seq, why: "the record shows another volume" })).ok);
  const correction = ok(await rec(r.a0, finding("a fifth method, in 2024", ["1"], { supersedes: old.seq }))).entry;
  await attest(r.a3, { seq: correction.seq, how: "re-read the record from job:j000001/hits.txt" });
  const a2 = ok(await answer(r.a1, "question:2", [names.seq, linked.seq, apart.seq, oneLinked.seq]));
  assert.equal(a2.warnings, undefined, "question 2's answer reaches what its leads hold");

  // The record's reply says it, in the words finish status says it with.
  const a1 = await answer(r.a1, "question:1", [cited.seq]);
  assert.ok(a1.ok);
  const seq = a1.entry.seq;
  const want = `answer #${seq} (question:1) leaves out what the record ties to Q-1: E-${names.seq} (a finding that names Q-1), E-${linked.seq} (a finding whose rel supports E-${cited.seq}, which the answer cites), E-${alone.seq} (a finding that names Q-1, held by one seat), E-${twice.seq} (an event that names Q-1), E-${correction.seq} (a finding that names Q-1): cite them or say why they do not bear on it. record the answer again with supersedes=${seq}, citing each as E-<seq> in its reasoning (or among its contrary or limitations), or saying there why each does not bear on Q-1; an entry the answer cites that names one (rel, a coverage record's result_refs) counts`;
  assert.deepEqual(a1.warnings, [want]);
  assert.deepEqual(a1.warned, ["lead_findings_uncited"]);
  const check = await checkLedgerAnswers(r.S, ["1", "2"]);
  assert.deepEqual(check.warnings, [want], "the answers check says the same, for question 1 alone");
  assert.ok(![apart, oneLinked, disputed, old, reached].some((e) => want.includes(`E-${e.seq} (`)), "tied by nothing, one seat's by rel alone, disputed, superseded, reached: none is named");
  // The reply to the attest on it; the review of question 2's answer carries nothing.
  const at = await attest(r.a2, { seq, how: "re-derived the cited finding", ...ESTABLISHED });
  assert.deepEqual(at.warnings, [want]);
  assert.equal((await attest(r.a3, { seq: a2.entry.seq, how: "re-derived the cited findings", ...ESTABLISHED })).warnings, undefined);
  // Nothing holds: the check passes, ready, the done proceeds.
  const reviewed = await checkLedgerAnswers(r.S, ["1", "2"]);
  assert.equal(reviewed.ok, true, reviewed.lines.join("\n"));
  assert.deepEqual(reviewed.warnings, [want]);
  const run1 = { total: 1, passed: 1, source: "registry", checks: [{ cmd: "check-answers --sections 1,2", ok: true, answers: { outcomes: reviewed.outcomes, results: reviewed.results, dispositions: reviewed.dispositions, best_candidate: reviewed.best_candidate, warnings: reviewed.warnings, named: [] } }] };
  const gate = await finishGate(r.S, run1);
  const verdict = P.finishLineVerdict({ ...run1, gate }, false);
  assert.equal(verdict.proceed, true, JSON.stringify(verdict));
  const ready = await FIN.readiness(r.S);
  assert.equal(ready.ready, true, ready.items.join("; "));
  assert.deepEqual(ready.warnings, [want]);
  // Citing them clears it.
  const again = ok(await answer(r.a1, "question:1", [cited.seq, names.seq, linked.seq, alone.seq, twice.seq, correction.seq], { supersedes: seq }));
  assert.equal(again.warnings, undefined);
  assert.deepEqual((await checkLedgerAnswers(r.S, ["1", "2"])).warnings, []);
});

test("each point delivers the warnings of its moment in the words finish status says them with: the record's reply, a negative's review offer, the reply to an attest on the answer, on the coverage it rests on and on an entry it leaves out; none holds", async () => {
  const r = await run({ goal: GOAL(3) });
  // Question 1: not determinable, no ask and no reason for none.
  const L1 = await planned(r.a0, "1");
  const abs = ok(await rec(r.a0, { kind: "absence", value: "a hidden volume", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const cov = ok(await rec(r.a0, coverage("1", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"]))).entry;
  const a1 = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of a hidden volume was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" }));
  assert.deepEqual(a1.warned, ["no_acquisition_ask"]);
  assert.match(a1.warnings![0]!, new RegExp(`^answer #${a1.entry.seq} \\(question:1\\) is not determinable, and its coverage record E-${cov.seq} names no acquisition ask`));
  assert.ok((await L.closeLead(r.a0, L1, { disposition: "negative", ref: `E-${abs.seq}` })).ok);
  // Its review is offered to one seat; the offer, delivered, says the warning.
  assert.equal(await L.offerReviews(r.S), 1);
  const to = (await L.leadsSnapshot(r.S)).state.reviewOffers.get(`E-${a1.entry.seq}`)![0]!.to;
  const seat = { sandboxRoot: r.S, agentId: to };
  const digest = await L.leadsDigest(seat, { mark: true });
  const offer = digest.notices.find((n) => n.kind === "review_offer");
  assert.ok(offer, digest.text);
  assert.ok(offer.text.endsWith(`The finish line warns of this answer, holding nothing on it; weigh each in your review: ${a1.warnings![0]}`), offer.text);
  // Delivered once: the next header does not say the offer again.
  assert.equal((await L.leadsDigest(seat, { mark: true })).notices.filter((n) => n.kind === "review_offer").length, 0);
  // The review, on the coverage record the answer rests on.
  const review = await attest(seat, { seq: cov.seq, how: "ran the search again from job:j000001", review: REVIEW });
  assert.deepEqual(review.warnings, a1.warnings);
  // Question 2: partial, nothing to warn of until a review holds every part established.
  const L2 = await planned(r.a0, "2");
  const f2 = ok(await rec(r.a0, finding("the account was svc_backup", ["2"]))).entry;
  const a2 = ok(await rec(r.a1, { kind: "answer", section: "question:2", value: "svc_backup", reasoning: `E-${f2.seq}`, ...A, result: "partial" }));
  assert.equal(a2.warnings, undefined, "no review yet: nothing to say");
  assert.ok((await L.closeLead(r.a0, L2, { disposition: "resolved", ref: `E-${f2.seq}` })).ok);
  const whole = await attest(r.a3, { seq: a2.entry.seq, how: "re-read the account record", ...ESTABLISHED });
  assert.deepEqual(whole.warned, ["partial_all_parts_established"]);
  assert.match(whole.warnings![0]!, new RegExp(`^answer #${a2.entry.seq} \\(question:2\\) is partial, and every review holds every part it weighed established`));
  // Question 3: established, leaving out a finding two seats hold under its lead.
  const L3 = await planned(r.a0, "3");
  assert.ok((await L.attachJob(r.S, "a0", "j000001", L3)).ok);
  const cited = ok(await rec(r.a0, finding("a folder was deleted", ["3"]))).entry;
  const left = ok(await rec(r.a0, finding("a second folder was deleted", ["3"]))).entry;
  const onCited = await attest(r.a3, { seq: cited.seq, how: "re-read the journal" });
  assert.equal(onCited.warnings, undefined, "an attest on a finding no warning names carries none, whatever other answers are warned of");
  await attest(r.a3, { seq: left.seq, how: "re-read the journal" });
  assert.ok((await L.recordInterpretations(r.S, "a0", left.seq, ["j000001"])).ok);
  assert.ok((await L.closeLead(r.a0, L3, { disposition: "resolved", ref: `E-${cited.seq}` })).ok);
  const a3 = ok(await answer(r.a1, "question:3", [cited.seq]));
  assert.deepEqual(a3.warned, ["lead_findings_uncited"]);
  assert.match(a3.warnings![0]!, new RegExp(`E-${left.seq} \\(a finding under ${L3}\\): cite it`));
  assert.deepEqual((await attest(r.a2, { seq: a3.entry.seq, how: "re-derived the cited finding", ...ESTABLISHED })).warnings, a3.warnings);
  // A later finding for question 3, attested: the attest's reply names the warning it now joins.
  const late = ok(await rec(r.a0, finding("a third folder was deleted", ["3"])));
  assert.equal(late.warnings, undefined, "a finding's record is not where an answer's warning is said");
  const onLate = await attest(r.a3, { seq: late.entry.seq, how: "re-read the journal" });
  assert.deepEqual(onLate.warned, ["lead_findings_uncited"]);
  assert.match(onLate.warnings![0]!, new RegExp(`E-${left.seq} \\(a finding under ${L3}\\), E-${late.entry.seq} \\(a finding that names Q-3\\): cite them`));

  // Finish status: every warning, in the same words each reply used; ready, nothing held.
  const status = (await FIN.finishStatus(r.a1)) as { ready: boolean; warnings?: string[]; items: string[] };
  assert.equal(status.ready, true, status.items.join("; "));
  assert.deepEqual(status.warnings, [a1.warnings![0], whole.warnings![0], onLate.warnings![0]]);
  assert.deepEqual((await FIN.warningsAt(r.S, { point: "finish_status" })).map(P.warningWords), status.warnings);
  const check = await checkLedgerAnswers(r.S, ["1", "2", "3"]);
  assert.deepEqual(check.warnings, status.warnings, "the answers check and finish status say the same");
  assert.deepEqual(check.dispositions, { "question:1": "not_determinable", "question:2": "partial", "question:3": "established" });
});

test("a question put to the operator is told what it says: the observation that would settle the lead's question and what each answer changes; an acquisition ask, and a lead that serves no question, are not", async () => {
  const r = await run({ goal: GOAL(2) });
  const L2 = await planned(r.a0, "2");
  const asked = okq(await L.closeLead(r.a0, L2, { disposition: "needs_operator", ref: "Which of the two accounts did the client issue to the contractor?" }));
  assert.equal(asked.guidance, L.operatorQuestionGuidance(["2"]));
  assert.match(asked.guidance!, /^a question put to the operator says what observation would settle Q-2, and what each possible answer changes \(which answer, and to which result\)/);
  const L1 = await planned(r.a0, "1");
  const acq = okq(await L.closeLead(r.a0, L1, { disposition: "needs_operator", ref: "the proxy's logs for the day", ask: { kind: "acquisition", source: "the proxy's logs", where: "the network team", expected_value: "whether the data left over HTTP, for Q-1", urgency: "normal" } }));
  assert.equal(acq.guidance, undefined, "an acquisition says what it would establish in expected_value");
  assert.equal(L.operatorQuestionGuidance([]), null);
});

test("under more_evidence: no nothing suggests an ask: the record's reply and the warning name the policy as the reason, never an ask", async () => {
  const r = await run({ goal: GOAL(1) });
  const { mkdir, writeFile } = await import("node:fs/promises");
  await mkdir(join(r.S, "network"), { recursive: true });
  await writeFile(join(r.S, "network", "policy.json"), JSON.stringify({ policy: "ctf", more_evidence: "no" }));
  await planned(r.a0, "1");
  const abs = ok(await rec(r.a0, { kind: "absence", value: "a hidden volume", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const cov = ok(await rec(r.a0, coverage("1", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"]))).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of a hidden volume was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" }));
  for (const words of [a.note ?? "", ...(a.warnings ?? [])]) {
    assert.match(words, /this case admits no further evidence \(more_evidence: no\), so open no acquisition ask/);
    assert.doesNotMatch(words, /lead_close needs_operator|open an acquisition ask|Ask for it first/);
  }
  assert.equal(a.warnings?.length, 1);
  // The policy's words as the reason: nothing to warn of.
  const cov2 = ok(await rec(r.a0, coverage("1", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { supersedes: cov.seq, acquisition_none_why: P.NO_MORE_EVIDENCE_NONE_WHY }))).entry;
  const b = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of a hidden volume was found on the disk", reasoning: `E-${cov2.seq}`, ...A, result: "not_determinable", supersedes: a.entry.seq }));
  assert.equal(b.warnings, undefined);
});

test("the request guidance is said in the prompt and the tools: warnings at the point of decision, the operator question, a value read from an image, no ask under no more evidence; the net refusal says the image rule", async () => {
  const flat = (t: string) => t.replace(/\s+/g, " ");
  const prompt = flat(await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8"));
  for (const must of [
    "A warning is said where the decision is made: in the reply to the record that writes the answer, in its review offer and the reply to an attest on it, and in `finish` status.",
    "one that names the question in `answers`, or one whose `rel` links it to an entry the answer cites",
    "A question put to the operator says what observation would settle its question (Q-<n>) and what each possible answer changes (which answer, and to which result)",
    "A value read from an image (a photo, a scan, a screenshot) is cited from the output of a job that read the image (an OCR tool run over the input), never from a transcription typed into a command",
    'Under "no more evidence" open no ask for that: `acquisition_none_why` naming the case policy (more_evidence: no, so an ask would be declined at once) satisfies it.',
  ]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
  const tools = flat(await readFile(join(ROOT, "extensions", "agent-swarm.ts"), "utf8"));
  for (const must of [
    "The reply to an answer carries the finish line's warnings on its question (warnings)",
    "The reply carries the finish line's warnings on what you attested (warnings)",
    "A question put to the operator (needs_operator) says what observation would settle the lead's question (Q-<n>) and what each possible answer changes",
    "A value read from an image (a photo, a scan, a screenshot) is cited from the output of a job that read the image (an OCR tool run over the input), never from a transcription typed into a command",
  ]) assert.ok(tools.includes(must), `extensions/agent-swarm.ts does not say: ${must}`);
  const refusal = flat(await readFile(join(ROOT, "scripts", "net-policy.ts"), "utf8"));
  assert.ok(refusal.includes("a value read from an image (a photo, a scan, a screenshot) is cited from the output of a job that read the image (an OCR tool run over the input), never from a transcription typed into a command"));
});
