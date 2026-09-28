/**
 * Resuming a run (scripts/resume.ts, docs/adr/0013): after a stop, what
 * marked the end is moved aside whole, the wall clock counts on from the
 * stop, a resume that would leave the run over a cap is refused with nothing
 * changed, each seat starts from its last hand-off, the first segment's VM
 * records and kept disks are set aside, and a question asked for the
 * continuation is admitted and delivered like any analyst question. After a
 * seal, the continuation appends to the same chains: custody seals it anew,
 * the earlier verdict still holds as a prefix (custody-verify shows both), a
 * v0 draft and a signed v1 still verify, and the continuation is adopted by
 * a later version. Without a resume on the anchor, a longer ledger is a
 * change, not a prefix.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { lastHandoff, prepareResume } from "../scripts/resume.ts";
import { custodyAnchorPath, takeCustody, verifyCustody } from "../scripts/custody.ts";
import { draftRelease, signRelease } from "../scripts/release.ts";
import { verifyReleases } from "../scripts/release-record.ts";
import { appendReview } from "../scripts/review.ts";
import { enrollExaminer } from "../scripts/signers.ts";
import { cleanUp, stoppedRun } from "./release-fixture.ts";
import { asEnded, asTeam, continueWith, ctxOf, layout, quiet } from "./resume-fixture.ts";

after(cleanUp);
test("resume after a stop: the end moved aside whole, the wall clock counted on, a resume still over a cap refused with nothing changed", async () => {
  const r = await stoppedRun({ id: "sres1" });
  await asEnded(r, { minutesAgo: 90, wall: 30 });
  await P.writeBudget(r.root, { ...(await P.readBudget(r.root)), paused: { at: new Date(Date.now() - 50 * 60_000).toISOString(), reason: "wall_clock", detail: "the wall clock passed" } });
  await (await import("node:fs/promises")).rm(join(r.root, P.SENTINEL_REL));
  await P.markStopped(r.root, "operator", "swarm.sh stop");
  // The first segment's VM record and kept disk, and a seat's sessions with a summary and, later, its own note.
  await mkdir(join(r.root, "vm"), { recursive: true });
  await writeFile(join(r.root, "vm", "a0.json"), "{}");
  await mkdir(`${r.root}.vm-snapshots`, { recursive: true });
  await writeFile(join(`${r.root}.vm-snapshots`, "a0.msb"), "disk");
  await mkdir(join(r.root, ".pi-sessions", "a0"), { recursive: true });
  const note = `name a0, slice: the web logs\nDONE: E-4, E-9\nNEXT ACTION: read access.log from line 5000\n${"x".repeat(30_000)}`;
  await writeFile(
    join(r.root, ".pi-sessions", "a0", "s1.jsonl"),
    [
      JSON.stringify({ type: "compaction", id: "c1", parentId: null, timestamp: "2026-02-03T10:00:00.000Z", summary: "an older summary", firstKeptEntryId: "x", tokensBefore: 1 }),
      JSON.stringify({ type: "custom_message", id: "h1", parentId: "c1", timestamp: "2026-02-03T10:30:00.000Z", customType: "self-compact-handoff", content: "…", details: { note }, display: true }),
    ].join("\n") + "\n",
  );
  // Still over the wall clock: refused, and nothing moves.
  await assert.rejects(prepareResume(r.root, { run: r.id, by: "operator" }), /would resume over its wall clock \(40 of 30 minutes used\): give --minutes N; nothing was changed/);
  assert.ok(existsSync(join(r.root, P.STOPPED_REL)), "nothing moved on a refusal");
  const out = await prepareResume(r.root, { run: r.id, by: "operator", minutes: 30 });
  assert.equal(out.ok, true);
  assert.equal(out.from, "stopped");
  assert.equal(out.segment, 1);
  assert.ok(!existsSync(join(r.root, P.STOPPED_REL)));
  assert.ok(existsSync(join(r.root, "done", "history", "1", "STOPPED")), "the stop is kept, whole, in done/history/1");
  assert.ok(existsSync(join(r.root, "vm", "earlier-1", "a0.json")), "the first segment's VM record is set aside");
  assert.ok(existsSync(join(`${r.root}.vm-snapshots`, "earlier-1", "a0.msb")), "and its kept disk");
  const b = await P.readBudget(r.root);
  assert.equal(b.paused, undefined, "the pause is lifted by the resume");
  assert.equal(b.pauses?.at(-1)?.resumed_by, "operator (resume)");
  assert.equal(Math.round((b.wall_used_ms ?? 0) / 60_000), 40, "the wall clock stood where the pause froze it");
  assert.equal(b.wall_clock_minutes, 60);
  assert.equal(P.budgetPressure(b).reason, null);
  assert.deepEqual(b.resumes?.map((x) => [x.by, x.from]), [["operator", "stopped"]]);
  assert.equal((await P.runOutcome(r.root)).outcome, null, "the run is no longer ended");
  // Each seat starts from its last hand-off, whole; one that left none from the registers.
  const handoff = await readFile(join(r.root, "inbox", "a0", "resume.md"), "utf8");
  assert.ok(handoff.includes(note), "the note, whole: nothing is cut");
  assert.match(handoff, /Your last hand-off note, written at 2026-02-03T10:30:00.000Z/);
  assert.deepEqual((await lastHandoff(r.root, "a0")).kind, "hand-off note");
  assert.match(await readFile(join(r.root, "inbox", "a1", "resume.md"), "utf8"), /You left no hand-off note and no compaction summary/);
  // The resume is anchored beside the run.
  const anchor = JSON.parse(readFileSync(custodyAnchorPath(r.root), "utf8")) as { resumes: Array<{ by: string; from: string; segment: number; heads: { ledger: { lines: number } } }> };
  assert.deepEqual(anchor.resumes.map((x) => [x.by, x.from, x.segment]), [["operator", "stopped", 1]]);
  assert.equal(anchor.resumes[0].heads.ledger.lines, 21);
});

test("a question asked for the continuation is admitted as an analyst question, not a follow-up, and delivered", async () => {
  const r = await stoppedRun({ id: "sres2" });
  await asEnded(r);
  await mkdir(join(r.root, "threads", "main"), { recursive: true });
  await prepareResume(r.root, { run: r.id, by: "operator" });
  const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
  const q = await Q.act(r.root, operator, "open", { text: "Was the web shell used again after the first day?", why: "asked when the run was resumed" });
  assert.ok(q.ok, (q as { reason?: string }).reason);
  if (!q.ok) return;
  assert.equal(q.scope, "in_scope");
  assert.equal(q.after_done, undefined, "the run is no longer ended: it is this run's work");
  const delivered = await Q.deliverPending(r.root);
  assert.deepEqual(delivered.map((d) => d.q), [q.q]);
});

test("a resume takes up the follow-ups: a question admitted after the done is the continuation's work, named on one event", async () => {
  const r = await stoppedRun({ id: "sres3" });
  await asEnded(r);
  await mkdir(join(r.root, "threads", "main"), { recursive: true });
  const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
  const late = await Q.act(r.root, operator, "open", { text: "Was the web shell reached from a second address?", why: "asked after the run finished" });
  assert.ok(late.ok, (late as { reason?: string }).reason);
  if (!late.ok) return;
  assert.equal(late.after_done, true, "a follow-up of the ended run");
  const out = await prepareResume(r.root, { run: r.id, by: "operator" });
  assert.deepEqual(out.follow_ups, [late.q]);
  const snap = await Q.questionsSnapshot(r.root);
  const q = snap.state.questions.get(late.q!)!;
  assert.equal(q.after_done, false, "this run's work now");
  assert.equal(q.continued?.segment, out.segment);
  assert.deepEqual(snap.state.events.filter((e) => e.ev === "continue").map((e) => e.questions), [[late.q]]);
  assert.deepEqual((await Q.deliverPending(r.root)).map((d) => d.q), [late.q], "and delivered to the seats");
  // Resumed again with nothing left to take up: no event.
  await writeFile(join(r.root, P.SENTINEL_REL), `---\nby: a0\noutput: work/report.md\nreason: finished\noutcome: completed\nat: ${new Date().toISOString()}\n---\n`);
  assert.deepEqual((await prepareResume(r.root, { run: r.id, by: "operator" })).follow_ups, []);
  assert.equal((await Q.questionsSnapshot(r.root)).state.events.filter((e) => e.ev === "continue").length, 1);
});

test("resume after a v0 seal: the continuation is sealed anew, the earlier verdict and the v0 draft verify as prefixes, and custody-verify shows both", async () => {
  const r = await stoppedRun({ id: "sres3" });
  const v0 = await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v0.written?.version, 0);
  await asEnded(r);
  // Before a resume, a longer ledger is a change, not a prefix.
  const probe = await stoppedRun({ id: "sres3b" });
  await draftRelease(ctxOf(probe), { home: probe.home, say: quiet });
  await asTeam(probe);
  await continueWith(probe, "10.9.9.9");
  const unresumed = await verifyReleases(layout(probe));
  assert.equal(unresumed.ok, false);
  assert.ok(unresumed.lines.some((l) => /the ledger here is not the one it binds/.test(l)), unresumed.lines.join("\n"));
  // Resumed: the same chains go on.
  await prepareResume(r.root, { run: r.id, by: "operator" });
  await continueWith(r, "10.1.2.3");
  await takeCustody(r.root, { runsDir: r.runs });
  const custodyFiles = (await readdir(r.root)).filter((n) => /^custody\.[0-9A-Za-z]+\.json$/.test(n));
  assert.equal(custodyFiles.length, 1, "the earlier verdict is kept beside the new one");
  const v1 = await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v1.written?.version, 1, "the next stop seals a new draft covering the continuation");
  assert.equal(v1.written?.record.chains.ledger.entries, 22);
  const report = await verifyCustody(r.root, { runsDir: r.runs });
  assert.equal(report.earlier.length, 1);
  assert.equal(report.earlier[0].ok, true, report.earlier[0].broken.join("; "));
  assert.equal(report.earlier[0].resumed_after, true);
  assert.ok(report.earlier[0].held.includes("the ledger (21)"), report.earlier[0].held.join(", "));
  assert.ok(report.earlier[0].held.includes("the trace (21)"), report.earlier[0].held.join(", "));
  assert.equal(report.prefix.intact, true);
  assert.equal(report.seal_drift.length, 0, JSON.stringify(report.seal_drift));
  const releases = await verifyReleases(layout(r));
  assert.equal(releases.ok, true, releases.lines.join("\n"));
  assert.match(releases.lines.find((l) => l.startsWith("Release v0:")) ?? "", /binds an earlier custody verdict.*the ledger it binds is a prefix of the ledger here \(21 of 22\): the run was resumed after it/);
  assert.match(releases.lines.find((l) => l.startsWith("Release v1:")) ?? "", /binds this custody verdict/);
  // A rewrite of what the first seal holds is not a prefix: both say so.
  const entries = await readFile(join(r.root, P.LEDGER_ENTRIES), "utf8");
  await writeFile(join(r.root, P.LEDGER_ENTRIES), entries.replace('"line 4411"', '"line 4412"'));
  const broken = await verifyCustody(r.root, { runsDir: r.runs });
  assert.equal(broken.ok, false);
  assert.equal(broken.earlier[0].ok, false);
  assert.ok(broken.earlier[0].broken.some((b) => /the ledger/.test(b)), broken.earlier[0].broken.join("; "));
});

test("a signed v1 stays as it is after the continuation, and the continuation's answers are adopted through a vN", async () => {
  const r = await stoppedRun({ id: "sres4" });
  const e = enrollExaminer({ name: "Ada Examiner", organisation: "Lab One", competence: "GCFA; ten years of casework", generateKey: true, noPassphrase: true }, r.home);
  assert.ok(!("why" in e), JSON.stringify(e));
  const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k" };
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "qualify", entry_seq: 19, note: "one command proven" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
  const v1 = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v1.version, 1);
  assert.equal(v1.record.state, "adopted");
  const v1Bytes = readFileSync(join(r.root, "release", "v1", "release.json"));
  await asEnded(r);
  await prepareResume(r.root, { run: r.id, by: "operator" });
  await continueWith(r, "10.4.4.4");
  await takeCustody(r.root, { runsDir: r.runs });
  const v2 = await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v2.written?.version, 2);
  assert.deepEqual(readFileSync(join(r.root, "release", "v1", "release.json")), v1Bytes, "v1 is untouched");
  let check = await verifyReleases(layout(r));
  assert.equal(check.ok, true, check.lines.join("\n"));
  assert.match(check.lines.find((l) => l.startsWith("Release v1:")) ?? "", /^Release v1:\s+ADOPTED.*the ledger it binds is a prefix of the ledger here \(21 of 22\): the run was resumed after it/);
  // The continuation's content is adopted through a later version, which names why.
  const vN = await signRelease(ctxOf(r), { home: r.home, say: quiet, amendReason: "adopting the continuation after the resume" });
  assert.equal(vN.version, 3);
  assert.equal(vN.record.state, "adopted");
  assert.equal(vN.record.chains.ledger.entries, 22);
  assert.equal(vN.record.prev?.version, 2);
  check = await verifyReleases(layout(r));
  assert.equal(check.ok, true, check.lines.join("\n"));
  assert.deepEqual(check.signatures.map((s) => [s.version, s.kind, s.adopted]), [[0, "machine", false], [1, "examiner", true], [2, "machine", false], [3, "examiner", true]]);
});
