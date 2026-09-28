/**
 * Resume and the releases under review (Astra's review of WP2): each case
 * below failed on the code before its fix.
 *
 * - A release's chains are verified, not read by their hash fields: an
 *   entry rewritten with its old hash kept breaks the release that binds it.
 * - Only a resume the anchor records at a real point of the verified chains
 *   lets a release bind a prefix; a bare timestamp does not.
 * - The report bytes a release binds are kept when the run is resumed, and
 *   an earlier release verifies against them after the continuation writes
 *   its own report.
 * - An earlier seal of the model gateway's log is broken when the log is
 *   gone, never skipped.
 * - A resume that cannot be anchored changes nothing.
 */
import assert from "node:assert/strict";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { prepareResume } from "../scripts/resume.ts";
import { custodyAnchorPath, sealPrefix, takeCustody } from "../scripts/custody.ts";
import { draftRelease, signRelease } from "../scripts/release.ts";
import { verifyReleases } from "../scripts/release-record.ts";
import { appendReview } from "../scripts/review.ts";
import { enrollExaminer } from "../scripts/signers.ts";
import { cleanUp, stoppedRun } from "./release-fixture.ts";
import { asEnded, asTeam, continueWith, ctxOf, layout, quiet } from "./resume-fixture.ts";

after(cleanUp);

test("a release's chains are verified, not read by their hash fields: an entry rewritten with its hash kept breaks every release that binds it", async () => {
  const r = await stoppedRun({ id: "srv1" });
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  await asEnded(r);
  await prepareResume(r.root, { run: r.id, by: "operator" });
  await continueWith(r, "10.2.2.2");
  await takeCustody(r.root, { runsDir: r.runs });
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal((await verifyReleases(layout(r))).ok, true);
  // Entry 3's words changed, its hash field kept: every line after it still names the hash before.
  const file = join(r.root, P.LEDGER_ENTRIES);
  const text = await readFile(file, "utf8");
  const lines = text.split("\n");
  const third = JSON.parse(lines[2]) as { value: string };
  lines[2] = JSON.stringify({ ...third, value: `${third.value} (rewritten)` });
  await writeFile(file, lines.join("\n"));
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, false, v.lines.join("\n"));
  assert.match(v.lines.find((l) => l.startsWith("Release v0:")) ?? "", /the ledger it binds does not verify: its chain is broken at line 3/);
  assert.match(v.lines.find((l) => l.startsWith("Release v1:")) ?? "", /the ledger it binds does not verify: its chain is broken at line 3/);
});

test("only a resume the anchor records at a real point of the verified chains lets a release bind a prefix; a bare timestamp does not", async () => {
  const r = await stoppedRun({ id: "srv2" });
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  await asTeam(r);
  await continueWith(r, "10.3.3.3");
  const anchor = custodyAnchorPath(r.root);
  const write = (o: Record<string, unknown>) => {
    chmodSync(anchor, 0o644);
    writeFileSync(anchor, JSON.stringify({ ...(JSON.parse(readFileSync(anchor, "utf8")) as Record<string, unknown>), ...o }));
  };
  write({ resumes: [{ at: "z" }] });
  let v = await verifyReleases(layout(r));
  assert.equal(v.ok, false, "a timestamp is not a resume");
  assert.match(v.lines.find((l) => l.startsWith("Release v0:")) ?? "", /the ledger here is not the one it binds/);
  // A resume whose boundary is not a point of the chain: refused too.
  write({ resumes: [{ at: new Date(Date.now() + 60_000).toISOString(), by: "operator", segment: 1, heads: { ledger: { lines: 21, head: "f".repeat(64) } } }] });
  v = await verifyReleases(layout(r));
  assert.equal(v.ok, false, "a boundary that is not the chain's");
  // The boundary the chain holds, after the release: a resume.
  const head = (JSON.parse((await readFile(join(r.root, P.LEDGER_ENTRIES), "utf8")).split("\n")[20]) as { hash: string }).hash;
  write({ resumes: [{ at: new Date(Date.now() + 60_000).toISOString(), by: "operator", segment: 1, heads: { ledger: { lines: 21, head } } }] });
  v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
});

test("the report bytes a release binds are kept at a resume, and a signed v1 verifies against them after the continuation writes its own report", async () => {
  const r = await stoppedRun({ id: "srv3" });
  const e = enrollExaminer({ name: "Ada Examiner", organisation: "Lab One", competence: "GCFA", generateKey: true, noPassphrase: true }, r.home);
  assert.ok(!("why" in e), JSON.stringify(e));
  const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k" };
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "qualify", entry_seq: 19, note: "one command proven" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
  const v1 = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v1.version, 1);
  const bound = v1.record.report.markdown?.sha256;
  assert.ok(bound);
  await asEnded(r);
  const prep = await prepareResume(r.root, { run: r.id, by: "operator" });
  assert.deepEqual(prep.kept, [`release/bound/${bound}`], "the bound report is kept, by its digest");
  // The continuation writes its own report.
  await writeFile(join(r.root, "work", "report.md"), "# Report\n\nThe continuation found more [#22].\n");
  await continueWith(r, "10.4.4.4");
  await takeCustody(r.root, { runsDir: r.runs });
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.find((l) => l.startsWith("Release v1:")) ?? "", new RegExp(`work/report\\.md as bound, kept at release/bound/${bound} when the run was resumed`));
  assert.match(v.lines.find((l) => l.startsWith("Release v2:")) ?? "", /work\/report\.md as bound[;,]/);
  // The kept bytes are held to their digest.
  const kept = join(r.root, "release", "bound", bound!);
  chmodSync(kept, 0o644);
  writeFileSync(kept, "not the report");
  assert.equal((await verifyReleases(layout(r))).ok, false);
});

test("an earlier seal of the model gateway's log is broken when the log is gone, never skipped", () => {
  const empty = { trace: "", ledger: "", attestations: "", disputes: "", leads: "", questions: "", grants: "", fetches: "", journal: null, gateway: null };
  const p = sealPrefix({ model_gateway: { lines: 2, sha256: "a".repeat(64) } } as never, empty);
  assert.equal(p.ok, false);
  assert.match(p.broken.join("; "), /the model gateway log it sealed \(2 lines\) is not here/);
  assert.equal(sealPrefix({ model_gateway: { lines: 0, sha256: null } } as never, empty).ok, true, "a log it sealed empty is not missed");
});

test("a resume that cannot be anchored changes nothing", async () => {
  const r = await stoppedRun({ id: "srv5" });
  await asEnded(r);
  const anchor = custodyAnchorPath(r.root);
  await rm(anchor, { force: true });
  await mkdir(anchor);
  await assert.rejects(prepareResume(r.root, { run: r.id, by: "operator" }), /the resume could not be anchored beside the run.*nothing was changed/);
  assert.ok(existsSync(join(r.root, P.SENTINEL_REL)), "the end is where it was");
  assert.ok(!existsSync(join(r.root, "done", "history")), "nothing was moved");
  assert.equal((await P.readBudget(r.root)).resumes, undefined, "the budget was not written");
});
