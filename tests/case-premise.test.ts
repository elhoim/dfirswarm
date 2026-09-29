/**
 * A case premise is not a reason to hold an answer partial (the run
 * s993d40, a CTF case of six questions: every answer stood partial, and two
 * were complete answers whose only hedge was whether the person the case
 * brief names did it personally, which the brief states as given; both were
 * attested established by two reviewers while still labelled partial). The
 * worker prompt and the record tool say what a premise is; the gate warns,
 * and never holds, when a partial answer's every review holds every part it
 * weighed established and one attests it established. Synthetic runs only.
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
import { A, ESTABLISHED, F, ok, planned, rec, run } from "./negative-bar-fixture.ts";

const ROOT = resolve(import.meta.dirname, "..");

const GOAL = [
  "## Goal",
  "",
  "Examine the laptop of the employee the brief names.",
  "",
  "### Questions",
  "",
  "1. How was the file taken off the laptop?",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1`',
  "",
].join("\n");

const WARN = /is partial, and every review holds every part it weighed established/;

/** A review part by part: `parts` as given, everything else as an established review words it. */
const review = (strength: "established" | "best_candidate", parts: P.AnswerReview["parts"]) => ({ strength, answer_review: { ...ESTABLISHED.answer_review, parts } });

/** The finish line as the harness runs it: the goal's answers check, then the gate, then the verdict. */
async function finish(S: string) {
  const r = await checkLedgerAnswers(S, ["1"]);
  const checks = { total: 1, passed: r.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1", ok: r.ok, out: r.lines.join("\n"), answers: { outcomes: r.outcomes, results: r.results, dispositions: r.dispositions, best_candidate: r.best_candidate, warnings: r.warnings, named: [] } }] };
  const gate = await finishGate(S, checks);
  return { check: r, gate, verdict: P.finishLineVerdict({ ...checks, gate }, false) };
}

/** Question 1 answered partial on a finding, the "who did it" part held open by a limitation, its lead closed on the finding. */
async function hedged(r: Awaited<ReturnType<typeof run>>) {
  const lead = await planned(r.a0, "1", [{ source: "input:disk.E01", method: "read the USB history" }]);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "the file was copied to a USB stick at 09:14", source: "the disk", evidence: "the USB history", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const lim = ok(await rec(r.a0, { kind: "limitation", value: "Nothing on the laptop shows who sat at it at 09:14", source: "the disk", evidence: "no camera, no badge log", reason: "unavailable", answers: ["1"] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "Copied to a USB stick at 09:14; whether the employee did it personally is not established", reasoning: `E-${f.seq} shows the copy; who did it is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial" })).entry;
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
  return { f, lim, a };
}

test("a partial answer every review holds whole, one attesting it established, is warned of in the answers check, the finish line's note and finish status, and holds nothing", async () => {
  const r = await run({ goal: GOAL });
  const q = await hedged(r);
  for (const [who, parts] of [
    ["a2", [{ part: "how it was taken", established: true, why: "E-1 shows the copy" }, { part: "who took it", established: true, why: "the brief names the employee, and the laptop is theirs" }]],
    ["a3", [{ part: "how and when", established: true, why: "the USB history" }]],
  ] as const) {
    const att = await P.attestEntry({ sandboxRoot: r.S, agentId: who }, { seq: q.a.seq, how: "re-read the USB history from job:j000001", ...review(who === "a2" ? "established" : "best_candidate", [...parts]) });
    assert.ok(att.ok, (att as { reason?: string }).reason);
  }
  const f = await finish(r.S);
  // The answers check: still partial, passing, and one warning that names the answer, its reviewers and the way out.
  assert.equal(f.check.ok, true, f.check.lines.join("\n"));
  assert.equal(f.check.dispositions["question:1"], "partial");
  const w = f.check.warnings.filter((x) => WARN.test(x));
  assert.equal(w.length, 1, f.check.warnings.join("\n"));
  assert.match(w[0], new RegExp(`^answer #${q.a.seq} \\(question:1\\) is partial, and every review holds every part it weighed established \\(a2, a3; attested established by a2\\)\\. an answer is partial only for a part of the question the evidence could not establish: say which part is open \\(in its reasoning or limitations, citing what bounds it\\), or record the answer again with supersedes=${q.a.seq} and result established; what the case brief or the goal states as given`));
  assert.match(w[0], /name it \("rests on the case premise that …"\) and answer on the evidence for the rest/);
  assert.ok(f.check.lines.some((l) => l.startsWith("WARN: ") && WARN.test(l)), "printed as a WARN: line");
  // The finish line: the done proceeds, examination-limited, the warning in its note.
  assert.deepEqual(f.gate.questions.map((x) => [x.id, x.disposition]), [["1", "partial"]]);
  assert.ok(f.gate.warnings?.some((x) => WARN.test(x)), JSON.stringify(f.gate.warnings));
  assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", JSON.stringify(f.verdict));
  assert.match((f.verdict as { note?: string }).note ?? "", /warnings \(not held on\): answer #\d+ \(question:1\) is partial, and every review holds every part it weighed established/);
  // Readiness: ready, the warning listed apart from the items; finish status shows it.
  const ready = await FIN.readiness(r.S);
  assert.deepEqual([ready.ready, ready.items], [true, []], JSON.stringify(ready));
  assert.ok(ready.warnings.some((x) => WARN.test(x)), JSON.stringify(ready.warnings));
  const status = await FIN.finishStatus({ sandboxRoot: r.S, agentId: "a0" });
  assert.equal(status.ready, true);
  assert.ok((status.warnings as string[] | undefined)?.some((x) => WARN.test(x)), JSON.stringify(status));
});

test("no warning where a review holds a part open, as s993d40's reviewers did, nor where no review attests it established", async () => {
  const r = await run({ goal: GOAL });
  const q = await hedged(r);
  // Every part held established, but only as a best candidate: no established attest, no warning.
  const bc = await P.attestEntry(r.a3, { seq: q.a.seq, how: "re-read the USB history", ...review("best_candidate", [{ part: "how", established: true, why: "the USB history" }]) });
  assert.ok(bc.ok, (bc as { reason?: string }).reason);
  let c = await checkLedgerAnswers(r.S, ["1"]);
  assert.ok(!c.warnings.some((x) => WARN.test(x)), c.warnings.join("\n"));
  // An established attest that holds the part the answer declares open as open: the answer is partial on its reviews' word.
  const est = await P.attestEntry(r.a2, { seq: q.a.seq, how: "re-read the USB history", ...review("established", [{ part: "how", established: true, why: "the USB history" }, { part: "who took it", established: false, why: "nothing shows who sat at it", declared_open: `E-${q.lim.seq}` }]) });
  assert.ok(est.ok, (est as { reason?: string }).reason);
  c = await checkLedgerAnswers(r.S, ["1"]);
  assert.equal(c.ok, true, c.lines.join("\n"));
  assert.ok(!c.warnings.some((x) => WARN.test(x)), c.warnings.join("\n"));
  assert.ok(!(await FIN.readiness(r.S)).warnings.some((x) => WARN.test(x)));
  // An established answer is never warned of so.
  const whole = ok(await rec(r.a1, { kind: "answer", section: "question:1", supersedes: q.a.seq, value: "Copied to a USB stick at 09:14, on the employee's laptop (the case premise)", reasoning: `E-${q.f.seq} shows the copy; it rests on the case premise that the laptop is the employee's`, ...A, confidence: "high", result: "established" })).entry;
  const att = await P.attestEntry(r.a2, { seq: whole.seq, how: "re-read the USB history", ...ESTABLISHED });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  c = await checkLedgerAnswers(r.S, ["1"]);
  assert.ok(!c.warnings.some((x) => WARN.test(x)), c.warnings.join("\n"));
});

test("the worker prompt and the record and attest tools say what a case premise is", async () => {
  const flat = (t: string) => t.replace(/\s+/g, " ");
  const prompt = flat(await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8"));
  for (const must of [
    "What the case brief or the goal states as given (who the subject is, whose device it is, the scenario's facts) is a premise of the examination, not a part the answer must prove again",
    'names the premise it relies on in its reasoning or limitations ("rests on the case premise that …") and is established on the evidence for the rest',
    "An answer is partial only for a part of the question it could not establish",
    "When the evidence contradicts a premise, that is premise_not_supported or a finding, never a silent hedge",
  ]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
  const src = flat(await readFile(join(ROOT, "extensions", "agent-swarm.ts"), "utf8"));
  for (const must of [
    // The record tool's description of an answer, and its result field.
    'is named in reasoning or limitations, \\"rests on the case premise that …\\", and is no reason to answer partial: partial is only for a part the evidence could not establish, and evidence against a premise is premise_not_supported or a finding',
    "What the case brief or the goal states as given (who the subject is, whose device it is, the scenario's facts) is a premise, not a part to prove again",
    "Partial is only for a part the evidence could not establish; evidence against a premise is premise_not_supported or a finding, never a silent hedge.",
    // The attest tool's parts.
    "What the case brief or the goal states as given (who the subject is, whose device it is) is a premise, not a part to hold open",
  ]) assert.ok(src.includes(must), `extensions/agent-swarm.ts does not say: ${must}`);
});
