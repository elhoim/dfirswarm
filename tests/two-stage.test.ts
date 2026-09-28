/**
 * Two-stage signing (scripts/technical-review.ts, scripts/review.ts,
 * scripts/release.ts): a technical reviewer enrolled on purpose records what
 * they checked, with the outcome and the state it was over, and signs their
 * own record (a countersign line, SSHSIG in the dfirswarm-review namespace);
 * the examiner's release binds it. A review whose hashes no longer match is
 * over an earlier state; a countersign after release names it; a reviewer
 * who is the examiner is refused; --require-technical-review makes the seal
 * wait for a current, signed review that is not a disagreement; a reviewer
 * elsewhere works from the package and the examiner imports what they made,
 * checked against the register. The report and verify say each in one of
 * five wordings. Keys are made in each run's temporary home.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { prepareRelease, runContext, signRelease } from "../scripts/release.ts";
import { runLayout, verifyReleases } from "../scripts/release-record.ts";
import { enrollPerson, allowedSignersLine, type Person } from "../scripts/signers.ts";
import { adoptionState, appendReview, readReviews, reviewsPath } from "../scripts/review.ts";
import { countersignRecord, importReview, makeSignedRecord, packagePlace, recordSigned } from "../scripts/technical-review.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { cleanUp, stoppedRun, type StoppedRun } from "./release-fixture.ts";

after(cleanUp);
const quiet = () => undefined;
const PASS = "reviewer's own passphrase";
const pass = () => Buffer.from(PASS);

function ctxOf(r: StoppedRun) {
  return runContext(r.root, { run: r.id, runsDir: r.runs });
}
function layout(r: StoppedRun) {
  return runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));
}
function enrol(r: StoppedRun, name: string, role: "examiner" | "reviewer", o: { secret?: boolean; id?: string } = {}): Person {
  const e = enrollPerson({ name, id: o.id, organisation: role === "reviewer" ? "Lab Two" : "Lab One", competence: role === "reviewer" ? "EnCE; peer reviewer" : "GCFA", generateKey: true, noPassphrase: !o.secret, role }, r.home, o.secret ? pass() : null);
  assert.ok(!("why" in e), JSON.stringify(e));
  return (e as { person: Person }).person;
}
async function dispose(r: StoppedRun) {
  const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k" };
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
}
const input = { outcome: "agreed", checked: "re-ran fls on the image and the proxy-log search", entries: [4, 10] };

test("a reviewer signs their own record: the countersign is over the record line's bytes, the release binds it, and the report and verify say it is signed", async () => {
  const r = await stoppedRun();
  enrol(r, "Ada Examiner", "examiner");
  const bo = enrol(r, "Bo Reviewer", "reviewer", { secret: true });
  await dispose(r);
  // A wrong passphrase writes nothing at all: the record and its countersign are appended together.
  const before = (await readReviews(r.runs, r.id)).length;
  await assert.rejects(recordSigned(r.runs, r.id, r.root, bo.id, input, Buffer.from("wrong one here"), { home: r.home }), /nothing was written: .*incorrect passphrase/);
  assert.equal((await readReviews(r.runs, r.id)).length, before);
  const made = await recordSigned(r.runs, r.id, r.root, bo.id, input, pass(), { home: r.home });
  const lines = await readReviews(r.runs, r.id);
  const rec = lines[made.seq - 1];
  const cs = lines[made.countersign_seq - 1];
  assert.equal(rec.action, "technical_review");
  assert.equal(rec.recorded_as, "reviewer");
  assert.equal(rec.reviewer?.id, "bo-reviewer");
  assert.equal(rec.outcome, "agreed");
  assert.equal(cs.action, "countersign");
  assert.equal(cs.over_seq, rec.seq);
  assert.equal(cs.signature?.namespace, "dfirswarm-review");
  assert.match(String(cs.signature?.data), /^-----BEGIN SSH SIGNATURE-----/);
  assert.equal(cs.signer?.fingerprint, bo.key.fingerprint);
  assert.equal(cs.after_release, null, "no release was adopted before it");
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.equal(st.technical[0].status, "signed");
  assert.match(String(st.technical[0].words), /^signed by the reviewer \(Bo Reviewer, SHA256:/);
  const w = await signRelease(ctxOf(r), { home: r.home, examiner: "ada-examiner", say: quiet });
  assert.equal(w.record.adoption?.technical_review[0].status, "signed");
  const html = readFileSync(join(w.dir, "report.html"), "utf8");
  assert.match(html, /Bo Reviewer .*: signed by the reviewer/);
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines[1], /technical review by Bo Reviewer \(agreed\): signed by the reviewer/);
  assert.match(v.lines.join("\n"), /Technical: {4}review line \d+, by Bo Reviewer, agreed: signed by the reviewer/);
  // A countersign whose signature is not over the record: said, and it fails verify and the gate.
  const file = reviewsPath(r.runs, r.id);
  const text = readFileSync(file, "utf8");
  writeFileSync(file, text.replace(`"outcome":"agreed"`, `"outcome":"issues-resolved"`));
  const again = await verifyReleases(layout(r));
  assert.equal(again.ok, false);
  writeFileSync(file, text);
});

test("the independence rule: a reviewer who is the run's examiner by name, id or key is refused; the examiner who recorded a free-named reviewer is too", async () => {
  const r = await stoppedRun();
  const ada = enrol(r, "Ada Examiner", "examiner");
  await dispose(r);
  const twin = enrol(r, "ADA  Examiner", "reviewer", { secret: true, id: "ada-twin" });
  await assert.rejects(recordSigned(r.runs, r.id, r.root, twin.id, input, pass(), { home: r.home }), /has the examiner Ada Examiner's own name .*one person is never examiner and reviewer on one run/);
  await assert.rejects(recordSigned(r.runs, r.id, r.root, ada.id, input, null, { home: r.home }), /enrolled as an examiner: a technical review is signed by an enrolled reviewer/);
  await assert.rejects(appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", key: ada.key.fingerprint, action: "technical_review", reviewer: { name: "Ada Examiner", competence: "x" }, methodsChecked: "x", outcome: "agreed" }), /has the examiner's own name/);
});

test("--require-technical-review: the seal waits for a current review signed by its reviewer whose outcome is not a disagreement", async () => {
  const r = await stoppedRun({ registry: { require_technical_review: true } });
  enrol(r, "Ada Examiner", "examiner");
  const bo = enrol(r, "Bo Reviewer", "reviewer", { secret: true });
  await dispose(r);
  await assert.rejects(prepareRelease(ctxOf(r), { home: r.home, say: quiet }), /the run's kickoff \(--require-technical-review\) requires a technical review signed by its reviewer.*no technical review/);
  // A review the examiner recorded is not signed by the reviewer: not enough.
  await appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k", action: "technical_review", reviewer: { name: "Cy Colleague", competence: "EnCE" }, methodsChecked: "fls", outcome: "agreed" });
  await assert.rejects(prepareRelease(ctxOf(r), { home: r.home, say: quiet }), /Cy Colleague is agreed, recorded by the examiner; not signed by the reviewer/);
  // A disagreement, signed: not enough either.
  await recordSigned(r.runs, r.id, r.root, bo.id, { ...input, outcome: "disagreement", disagreements: ["E-19's one command is not in the trace; unresolved"] }, pass(), { home: r.home });
  await assert.rejects(prepareRelease(ctxOf(r), { home: r.home, say: quiet }), /Bo Reviewer is disagreement, signed by the reviewer/);
  // The examiner resolves it (a new disposition), so the signed disagreement is over an earlier state, and the reviewer signs again.
  await appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k", action: "inconclusive", entry_seq: 19, note: "one command only" });
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.equal(st.technical.find((t) => t.reviewer.name === "Bo Reviewer")?.status, "stale");
  assert.equal(st.technical.find((t) => t.reviewer.name === "Bo Reviewer")?.words, "signed over an earlier state, not current");
  await recordSigned(r.runs, r.id, r.root, bo.id, { ...input, outcome: "issues-resolved", disagreements: ["E-19: rendered inconclusive by the examiner"] }, pass(), { home: r.home });
  const w = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.deepEqual(w.record.policy, { require_technical_review: true, source: "the run's kickoff (--require-technical-review)" });
  assert.deepEqual(w.record.adoption?.technical_review.map((t) => t.status), ["stale", "stale", "signed"], "the earlier records stay in the chain, each said as it stands");
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  // SWARM_REQUIRE_TECHNICAL_REVIEW=1 does the same for a run whose kickoff did not ask.
  const r2 = await stoppedRun();
  enrol(r2, "Ada Examiner", "examiner");
  await dispose(r2);
  process.env.SWARM_REQUIRE_TECHNICAL_REVIEW = "1";
  try {
    await assert.rejects(prepareRelease(ctxOf(r2), { home: r2.home, say: quiet }), /SWARM_REQUIRE_TECHNICAL_REVIEW=1 requires/);
  } finally {
    delete process.env.SWARM_REQUIRE_TECHNICAL_REVIEW;
  }
});

test("a countersign after release names the release, and the next amendment binds it", async () => {
  const r = await stoppedRun();
  enrol(r, "Ada Examiner", "examiner");
  const bo = enrol(r, "Bo Reviewer", "reviewer", { secret: true });
  await dispose(r);
  // The examiner records the review, naming the reviewer; the release binds it unsigned.
  const tr = await appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k", action: "technical_review", reviewer: { name: "Bo Reviewer", competence: "EnCE" }, methodsChecked: "fls", outcome: "agreed" });
  const v1 = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v1.record.adoption?.technical_review[0].words, "recorded by the examiner; not signed by the reviewer");
  // The reviewer countersigns it afterwards.
  const cs = await countersignRecord(r.runs, r.id, r.root, bo.id, tr.seq, pass(), { home: r.home });
  assert.deepEqual(cs.after_release, { version: 1, sha256: v1.sha256 });
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.equal(st.technical[0].status, "countersigned-after-release");
  assert.equal(st.technical[0].words, "countersigned by the reviewer (Bo Reviewer) after release v1; the next amendment binds it");
  // Another reviewer cannot countersign it.
  const cy = enrol(r, "Cy Other", "reviewer", { secret: true });
  await assert.rejects(countersignRecord(r.runs, r.id, r.root, cy.id, tr.seq, pass(), { home: r.home }), /names Bo Reviewer, not Cy Other: only its reviewer countersigns it/);
  const v2 = await signRelease(ctxOf(r), { home: r.home, amendReason: "binds the reviewer's countersign", say: quiet });
  assert.equal(v2.record.adoption?.technical_review[0].status, "countersigned-after-release");
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines[2], /technical review by Bo Reviewer \(agreed\): countersigned by the reviewer \(Bo Reviewer\) after release v1/);
});

test("a reviewer elsewhere works from the package: review-import.jsonl is checked against the run's head, hashes, signature and register, and appended as made", async () => {
  const r = await stoppedRun();
  enrol(r, "Ada Examiner", "examiner");
  await dispose(r);
  // The package, as swarm.sh package lays out the parts a review is over.
  const pkg = join(r.root, "..", "pkg");
  mkdirSync(join(pkg, "work"), { recursive: true });
  writeFileSync(join(pkg, "MANIFEST.txt"), "a package\n");
  cpSync(reviewsPath(r.runs, r.id), join(pkg, "review.jsonl"));
  cpSync(join(r.root, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  cpSync(join(r.root, "custody.json"), join(pkg, "custody.json"));
  cpSync(join(r.root, "work", "report.md"), join(pkg, "work", "report.md"));
  // The reviewer's own install, elsewhere.
  const remoteHome = join(r.root, "..", "remote-home");
  const rev = enrollPerson({ name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE", generateKey: true, role: "reviewer" }, remoteHome, pass());
  assert.ok(!("why" in rev));
  if ("why" in rev) return;
  const made = makeSignedRecord(packagePlace(pkg), rev.person, input, pass(), { dropAgent: false, home: remoteHome });
  const file = join(pkg, "review-import.jsonl");
  writeFileSync(file, `${made.texts.join("\n")}\n`);
  // Without a register the key is tied to no one: refused.
  await assert.rejects(importReview(r.runs, r.id, r.root, file, { home: r.home }), /the reviewer's key is not checked against anything/);
  const register = join(r.home, "register");
  writeFileSync(register, `${allowedSignersLine(rev.person)}\n`);
  assert.match(readFileSync(register, "utf8"), /namespaces="dfirswarm-review"/);
  // A register for the release namespace only does not vouch for a review.
  writeFileSync(join(r.home, "wrong-register"), `${allowedSignersLine({ ...rev.person, role: "examiner" })}\n`);
  await assert.rejects(importReview(r.runs, r.id, r.root, file, { allowedSigners: join(r.home, "wrong-register"), home: r.home }), /does not vouch for the reviewer's key/);
  const ok = await importReview(r.runs, r.id, r.root, file, { allowedSigners: register, home: r.home });
  assert.equal(ok.reviewer, "Bo Reviewer");
  const lines = await readReviews(r.runs, r.id);
  assert.equal(lines.at(-2)?.text, made.texts[0], "appended as it was made, byte for byte");
  const st = await adoptionState({ runsDir: r.runs, run: r.id, sandbox: r.root });
  assert.equal(st.technical[0].status, "signed");
  // The same file again: made over a head that is no longer this run's.
  await assert.rejects(importReview(r.runs, r.id, r.root, file, { allowedSigners: register, home: r.home }), /a stale review head/);
});
