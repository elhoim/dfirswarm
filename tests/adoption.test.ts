/**
 * The examiner's disposition of each conclusion (scripts/review.ts,
 * scripts/adoption.ts), on track P's ledger version 4 fixture: adopt,
 * qualify, withdraw (reject) or render inconclusive, by seq and hash, by an
 * enrolled examiner; an unsupported conclusion refused adoption and never
 * waived; a superseded answer refused (its correction is what stands); a
 * technical reviewer's record; the same acts on any entry; and the state the
 * report body takes (scripts/report-body.ts HumanReview, structurally).
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { dispositionWords, dispositionsOf, supportDefects } from "../scripts/adoption.ts";
import { adoptionState, appendReview, failedJobRefs, readDisputeLines, readReviews } from "../scripts/review.ts";
import { cleanUp, FIXTURE, stoppedRun } from "./release-fixture.ts";
import type { LedgerEntry } from "../extensions/protocol.ts";

after(cleanUp);

const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "SHA256:test" };

async function fixtureLedger(): Promise<LedgerEntry[]> {
  return (await readFile(join(FIXTURE, "ledger", "entries.jsonl"), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as LedgerEntry);
}

test("the support defects of the fixture's answers are the ledger gate's, with the tokens no cited entry holds beside them", async () => {
  const entries = await fixtureLedger();
  const disputes = await readDisputeLines(FIXTURE);
  const failed = await failedJobRefs(FIXTURE, entries);
  const d = supportDefects(entries, disputes, failed);
  // P's gate.json: the summary rests on a superseded answer; answer 16 states a hash no entry holds.
  const gate = JSON.parse(await readFile(join(FIXTURE, "gate.json"), "utf8")) as { defects: Array<{ seqs: number[] }>; unsupported: Record<string, string[]> };
  for (const g of gate.defects) for (const seq of g.seqs) assert.ok(d.get(seq)?.some((x) => x.code === "support"), `E-${seq} has the gate's defect`);
  for (const seq of Object.keys(gate.unsupported)) assert.ok(d.get(Number(seq))?.some((x) => x.code === "unsupported_tokens" && x.what.includes(gate.unsupported[seq][0])), `E-${seq}'s tokens`);
  assert.match(d.get(17)?.map((x) => x.what).join(" ") ?? "", /rests on E-15, superseded by #19, and does not cite the correction/);
  // The corrected answers, and the ones that qualify a disputed or failed-job entry, stand.
  for (const seq of [14, 19, 20]) assert.equal(d.get(seq), undefined, `E-${seq} stands`);
  // A superseded answer is not reviewed: its correction is.
  assert.equal(d.get(15), undefined);
  assert.equal(d.get(18), undefined);
  // E-7 rests on a job that timed out and says why its bytes hold: no defect of its own.
  assert.equal(failed.get(7), undefined);
  // A finding disputed and not withdrawn is a defect of its own.
  assert.ok(d.get(6)?.some((x) => x.code === "disputed"));
});

test("an unsupported conclusion cannot be adopted or qualified; it is withdrawn or rendered inconclusive, and repairing it is a new examination", async () => {
  const r = await stoppedRun();
  const add = (input: Omit<Parameters<typeof appendReview>[3], "examiner"> & { examiner?: string }) => appendReview(r.runs, r.id, r.root, { ...ADA, ...input });
  await assert.rejects(add({ action: "adopt", entry_seq: 16 }), /E-16 cannot be adopted: its support is not sound as it stands \(answer E-16 states a specific found in none of the entries it cites: 0123456789abcdef0123456789abcdef\)\. An unsupported conclusion is not waived: withdraw it \(--reject 16 --note\), or render it inconclusive \(--inconclusive 16 --note\)\. Repairing its support is further examination: a new run, whose evidence cutoff is reopened\./);
  await assert.rejects(add({ action: "qualify", entry_seq: 17, note: "the wording holds for the correction" }), /E-17 cannot be qualified/);
  await assert.rejects(add({ action: "adopt", entry_seq: 15 }), /E-15 is superseded by E-19: the correction is what stands/);
  await assert.rejects(add({ action: "qualify", entry_seq: 19 }), /qualify needs a note/);
  await assert.rejects(add({ action: "inconclusive", entry_seq: 16 }), /inconclusive needs a note/);
  // Adoption is an enrolled examiner's act; so is withdrawing an answer. Accepting a finding need not be.
  await assert.rejects(appendReview(r.runs, r.id, r.root, { action: "adopt", examiner: "Someone", entry_seq: 14 }), /adopt is an enrolled examiner's act/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { action: "reject", examiner: "Someone", entry_seq: 17, note: "no" }), /withdrawing an answer is an enrolled examiner's disposition/);
  const free = await appendReview(r.runs, r.id, r.root, { action: "accept", examiner: "Someone", entry_seq: 4 });
  assert.equal(free.examiner_id, undefined, "a name given free is recorded as that, with no id");
  const a = await add({ action: "adopt", entry_seq: 14 });
  assert.equal(a.entry_hash, "13a00600d4208c9f2e2d49115ba5467e9773e6f6ef37ab1478319363494e6333");
  assert.equal(a.entry_kind, "answer");
  assert.equal(a.section, "question:1");
  assert.equal(a.examiner_id, "ada-examiner");
  await add({ action: "qualify", entry_seq: 19, note: "one command is proven; the others are likely" });
  await add({ action: "inconclusive", entry_seq: 16, note: "the archive's hash is stated in no entry it rests on" });
  await add({ action: "reject", entry_seq: 17, note: "it rests on the superseded answer to question 2" });
  // The same acts on any entry by seq and hash: a finding adopted as it stands.
  const f = await add({ action: "adopt", entry_seq: 5 });
  assert.equal(f.entry_kind, "finding");
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  const by = new Map(st.answers.map((x) => [x.seq, x]));
  assert.equal(by.get(14)?.standing, "adopted");
  assert.equal(by.get(19)?.standing, "qualified");
  assert.equal(by.get(16)?.standing, "inconclusive");
  assert.equal(by.get(17)?.standing, "withdrawn");
  assert.equal(by.get(20)?.standing, "not adopted");
  assert.equal(by.get(20)?.words, "the agents' conclusion, not adopted");
  assert.equal(by.get(15)?.superseded_by, 19);
  assert.deepEqual(st.blocked, [], "every defective conclusion is withdrawn or inconclusive");
  assert.equal(st.scope, "answers");
});

test("a defective conclusion with no disposition blocks a release; one rendered inconclusive does not", async () => {
  const r = await stoppedRun();
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.deepEqual(st.blocked.map((a) => a.seq), [16, 17]);
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "hash unsupported" });
  const after = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.deepEqual(after.blocked.map((a) => a.seq), [17]);
});

test("a technical reviewer's record: who, on what competence, which methods were checked, over which entries by hash", async () => {
  const r = await stoppedRun();
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "", competence: "EnCE" }, methodsChecked: "x" }), /names who did it/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo", competence: "" }, methodsChecked: "x" }), /what qualifies the reviewer/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo", competence: "EnCE" }, methodsChecked: " " }), /which methods were checked/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo", competence: "EnCE" }, methodsChecked: "fls" }), /says its outcome \(--outcome agreed\|issues-resolved\|disagreement\)/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo", competence: "EnCE" }, methodsChecked: "fls", outcome: "disagreement" }), /a disagreement says what it is/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo", competence: "EnCE" }, methodsChecked: "fls", outcome: "agreed", entries: [99] }), /no ledger entry 99/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { action: "technical_review", examiner: "Someone", reviewer: { name: "Bo", competence: "EnCE" }, methodsChecked: "fls", outcome: "agreed" }), /technical review is an enrolled examiner's act/);
  // The examiner is not their own technical reviewer, whatever the case or spacing of the name.
  await assert.rejects(appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "ada  EXAMINER", competence: "EnCE" }, methodsChecked: "fls", outcome: "agreed" }), /has the examiner's own name .*: a technical review is a second person's/);
  const l = await appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE" }, methodsChecked: "re-ran fls on the image and the proxy-log search", entries: [4, 10], outcome: "issues-resolved", disagreements: ["E-16's hash: rendered inconclusive by the examiner"], reviewedAt: "2026-09-27T09:00:00Z" });
  assert.deepEqual(l.reviewer, { name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE" });
  assert.equal(l.outcome, "issues-resolved");
  assert.equal(l.reviewed_at, "2026-09-27T09:00:00.000Z");
  assert.equal(l.scope, "entries");
  assert.equal(l.recorded_as, "examiner");
  assert.deepEqual(l.disagreements, ["E-16's hash: rendered inconclusive by the examiner"]);
  assert.match(String(l.report_sha256), /^[0-9a-f]{64}$/, "it names the report it was over");
  assert.match(String(l.custody_sha256), /^[0-9a-f]{64}$/);
  assert.match(String(l.dispositions_head), /^[0-9a-f]{64}$/);
  assert.equal(l.ledger_head, "bf4dc7313c230c253afe8d8aa0fe6feab01787e3b9b00438433573923ad48eac");
  assert.deepEqual(l.entries?.map((e) => e.seq), [4, 10]);
  assert.equal(l.entries?.[0].hash, "dc310a6ef390874293d05c60cfa26246b279c4609891544beb7c28c80e2ef5c4");
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.equal(st.technical.length, 1);
  assert.equal(st.technical[0].reviewer.name, "Bo Reviewer");
  assert.match(st.technical[0].recorded_by, /^Ada Examiner \(/);
  assert.equal(st.technical[0].status, "recorded");
  assert.equal(st.technical[0].words, "recorded by the examiner; not signed by the reviewer");
  // A disposition changed after it: the review is over an earlier state.
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  const moved = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.equal(moved.technical[0].status, "stale");
  assert.equal(moved.technical[0].words, "recorded over an earlier state, not current");
});

test("the state the report body takes: the enrolled examiner, the technical reviewer, each entry's latest act by hash, the sign-off", async () => {
  const r = await stoppedRun();
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "technical_review", reviewer: { name: "Bo Reviewer", competence: "EnCE" }, methodsChecked: "fls", outcome: "agreed" });
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root, examiner: { name: "Ada Examiner", organisation: "Lab One", competence: "GCFA" } });
  assert.deepEqual(st.review?.examiner, { name: "Ada Examiner", organisation: "Lab One", competence: "GCFA" });
  assert.deepEqual(st.review?.technicalReviewer, { name: "Bo Reviewer", competence: "EnCE", checked: "fls" });
  const e = st.review?.entries?.get(14);
  assert.equal(e?.action, "adopt");
  assert.equal(e?.by, "Ada Examiner");
  assert.equal(e?.entry_hash, "13a00600d4208c9f2e2d49115ba5467e9773e6f6ef37ab1478319363494e6333");
  assert.equal(st.review?.signed, null);
  // What a release binds: the review's first lines only.
  const early = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root, upTo: 1 });
  assert.equal(early.lines, 1);
  assert.equal(early.technical.length, 0);
  assert.equal(early.head, (await readReviews(r.runs, r.id)).length ? early.head : null);
});

test("a disposition made on another hash than the entry's does not apply, and says so", () => {
  const acts = dispositionsOf([{ seq: 1, action: "adopt", entry_seq: 14, entry_hash: "0".repeat(64), examiner: "Ada", at: "t" }, { seq: 2, action: "accept", entry_seq: 3, examiner: "Ada", at: "t" }]);
  assert.deepEqual([...acts.keys()], [14], "accept is an entry review, not a disposition");
  assert.match(dispositionWords(acts.get(14) ?? null, { hash: "1".repeat(64) }), /made on entry hash 0{64}, which is not this entry's: it does not apply/);
  assert.equal(dispositionWords(null, null), "the agents' conclusion, not adopted");
});
