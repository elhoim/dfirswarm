/**
 * A run's releases (scripts/release.ts, scripts/release-record.ts): the
 * machine's draft when custody is taken, sealed by the install's machine
 * key and binding the report, a rendering of it generated at the release's
 * own time, the verdict, the sealed index and every chain; an enrolled
 * examiner's adoption, gated on every defective conclusion's disposition,
 * rendering its own final bytes without the DRAFT mark and printed when
 * asked; amendments that name what they amend and why; and a verify that
 * walks the chain and names what does not hold. Old runs say what they
 * lack. Keys are made in each run's temporary home.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { appendFile, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { draftRelease, printRelease, runContext, signRelease } from "../scripts/release.ts";
import { lineHashes, readReleases, runLayout, verifyReleases, type ReleaseRecord } from "../scripts/release-record.ts";
import { enrollExaminer } from "../scripts/signers.ts";
import { appendReview, readReviews, reviewsPath } from "../scripts/review.ts";
import { renderReport } from "../scripts/report.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { cleanUp, fakeChrome, stoppedRun, type StoppedRun } from "./release-fixture.ts";

after(cleanUp);
const sha = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const quiet = () => undefined;

function ctxOf(r: StoppedRun) {
  return runContext(r.root, { run: r.id, runsDir: r.runs });
}
function layout(r: StoppedRun) {
  return runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));
}
function enrol(r: StoppedRun) {
  const e = enrollExaminer({ name: "Ada Examiner", organisation: "Lab One", competence: "GCFA; ten years of casework", generateKey: true, noPassphrase: true }, r.home);
  assert.ok(!("why" in e), JSON.stringify(e));
  return e as Exclude<typeof e, { why: string }>;
}
/** The dispositions the fixture's defective answers need before a release, and two adoptions. */
async function dispose(r: StoppedRun) {
  const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k" };
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "qualify", entry_seq: 19, note: "one command proven" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
}

test("the machine's draft binds the report, a rendering of it at the release's own time, the verdict, the sealed index and every chain, sealed by the machine key", async () => {
  const r = await stoppedRun();
  const d = await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.ok(d.written, d.skipped ?? "");
  const w = d.written;
  if (!w) return;
  assert.equal(w.version, 0);
  const dir = join(r.root, "release", "v0");
  assert.deepEqual(readdirSync(dir).sort(), ["release.json", "release.json.sig", "report.html"]);
  for (const f of readdirSync(dir)) assert.equal(statSync(join(dir, f)).mode & 0o222, 0, `${f} is read-only`);
  const rec = JSON.parse(readFileSync(join(dir, "release.json"), "utf8")) as ReleaseRecord;
  assert.equal(rec.state, "draft");
  assert.equal(rec.signer.kind, "machine");
  assert.match(rec.signer.machine?.label ?? "", /It is not an examiner and adopts nothing/);
  assert.match(rec.statement, /The machine key is not an examiner\. No one has adopted this release/);
  assert.equal(rec.prev, null);
  assert.equal(rec.reason, "custody taken at stop");
  assert.equal(rec.report.markdown?.sha256, sha(readFileSync(join(r.root, "work", "report.md"))));
  assert.equal(rec.report.markdown?.sealed, true, "the report is the one custody sealed");
  assert.equal(rec.report.html.sha256, sha(readFileSync(join(dir, "report.html"))));
  assert.equal(rec.report.html.generated_at, rec.at);
  assert.equal(rec.report.html.watermark, "DRAFT");
  assert.equal(rec.custody?.sha256, sha(readFileSync(join(r.root, "custody.json"))));
  assert.equal(rec.sealed_index?.sha256, sha(readFileSync(join(r.root, "artifacts.json"))));
  assert.deepEqual(rec.chains.ledger, { entries: 21, head: "bf4dc7313c230c253afe8d8aa0fe6feab01787e3b9b00438433573923ad48eac" });
  assert.equal(rec.chains.disputes.lines, 3);
  assert.equal(rec.chains.attestations.lines, 8);
  assert.equal(rec.chains.trace.lines, 21);
  assert.deepEqual(rec.chains.ledger_versions, [3, 4]);
  assert.equal(rec.versions.harness_commit_at_kickoff, "0123abcd");
  assert.match(rec.versions.renderer_sha256, /^[0-9a-f]{64}$/);
  assert.match(rec.evidence_cutoff.note, /Further examination reopens the cutoff: the run resumed \(swarm\.sh resume\).*or a new run/);
  // The rendering says DRAFT, and whose seal it is.
  const html = readFileSync(join(dir, "report.html"), "utf8");
  assert.match(html, /<div class="watermark" aria-hidden="true">DRAFT<\/div>/);
  assert.match(html, /DRAFT: release v0, sealed at .* by this install's machine key .* The machine key is not an examiner: no one has adopted this report/);
  assert.match(html, /<dt>Examiner<\/dt><dd>none: no enrolled examiner has adopted this report<\/dd>/);
  assert.match(html, /<dt>Run by<\/dt><dd>Claude \(CTF round 5, macOS\) \(as the kickoff recorded who ran it; not an enrolled examiner, and not a signature\)<\/dd>/);
  // Deterministic: rendered again for the same release at the same time, the same bytes.
  const again = await renderReport(r.root, { runsDir: r.runs, now: rec.at, release: { version: 0, state: "draft", at: rec.at, machine: { fingerprint: rec.signer.fingerprint } }, review: null });
  assert.equal(sha(again), rec.report.html.sha256);
  // The anchor beside the run names it; the machine key lives in the install's home.
  const anchor = JSON.parse(readFileSync(custodyAnchorPath(r.root), "utf8")) as { releases: Array<{ version: number; sha256: string; line: string }> };
  assert.equal(anchor.releases[0].sha256, w.sha256);
  assert.match(anchor.releases[0].line, /^dfirswarm-release run=s4v4 v=0 state=draft sha256=[0-9a-f]{64} sig=[0-9a-f]{64} signer=SHA256:\S+ at=\S+$/);
  assert.ok(existsSync(join(r.home, "machine", "release_ed25519")));
  // Once per verdict: asked again, nothing is written.
  const twice = await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(twice.written, null);
  assert.match(String(twice.skipped), /release v0 already binds this custody verdict/);
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines[0], /^Release v0:   DRAFT, .*sealed by this install's machine key \(SHA256:\S+\), not an examiner: machine seal, self-checked \(sound under the machine key it names: it shows the install's machine key sealed these bytes, no more\); report\.html as bound; work\/report\.md as bound; binds this custody verdict; every chain it binds is as bound; anchored beside the run; not timestamped; the host: the agents ran on the host \(host mode\), and the kickoff did not record whether the signers' keys were hidden from their panes: unknown$/);
  assert.doesNotMatch(v.lines[0], /verified/, "the machine's seal is never called verified");
  assert.deepEqual(rec.host, { isolation: "host", signer_keys_hidden: null, note: "the agents ran on the host (host mode), and the kickoff did not record whether the signers' keys were hidden from their panes: unknown" });
});

test("a draft is refused when the run is not as custody sealed it: the report edited, an entry appended, the verdict rewritten", async () => {
  const r = await stoppedRun();
  const report = await readFile(join(r.root, "work", "report.md"), "utf8");
  await writeFile(join(r.root, "work", "report.md"), `${report}Added after the stop.\n`);
  await assert.rejects(draftRelease(ctxOf(r), { home: r.home, say: quiet }), /the run is not as custody sealed it: work\/report\.md \(custody sealed [0-9a-f]{64}; it is [0-9a-f]{64} now\)/);
  await writeFile(join(r.root, "work", "report.md"), report);
  const ledger = await readFile(join(r.root, "ledger", "entries.jsonl"), "utf8");
  await appendFile(join(r.root, "ledger", "entries.jsonl"), `${JSON.stringify({ v: 4, seq: 22, kind: "limitation", value: "late", prev: "bf4dc7313c230c253afe8d8aa0fe6feab01787e3b9b00438433573923ad48eac", hash: "f".repeat(64) })}\n`);
  await assert.rejects(draftRelease(ctxOf(r), { home: r.home, say: quiet }), /the run is not as custody sealed it: the ledger/);
  await writeFile(join(r.root, "ledger", "entries.jsonl"), ledger);
  const custody = await readFile(join(r.root, "custody.json"), "utf8");
  await writeFile(join(r.root, "custody.json"), custody.replace('"run": "s4v4"', '"run": "s4v5"'));
  await assert.rejects(draftRelease(ctxOf(r), { home: r.home, say: quiet }), /custody\.json is not the verdict anchored beside the run/);
  await writeFile(join(r.root, "custody.json"), custody);
  assert.ok((await draftRelease(ctxOf(r), { home: r.home, say: quiet })).written);
  assert.equal(readReleases(r.root).length, 1, "the refused attempts left nothing behind");
  assert.deepEqual(readdirSync(join(r.root, "release")), ["v0"]);
});

test("an enrolled examiner's adoption: refused while a defective conclusion has no disposition, then v1 names v0, binds the dispositions and renders its own final bytes", async () => {
  const r = await stoppedRun();
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  await assert.rejects(signRelease(ctxOf(r), { home: r.home, say: quiet }), /a release is signed by an enrolled examiner: no examiner is enrolled on this install/);
  const e = enrol(r);
  await assert.rejects(signRelease(ctxOf(r), { home: r.home, say: quiet }), /the release is refused:\n {2}- E-16 \(question:3\) is not supported as it stands .*\n {2}- E-17 \(summary\) is not supported as it stands/);
  assert.equal(readReleases(r.root).length, 1, "a refused adoption writes no release");
  await dispose(r);
  await appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", action: "technical_review", reviewer: { name: "Bo Reviewer", competence: "EnCE" }, methodsChecked: "re-ran fls", outcome: "agreed" });
  const before = (await readReviews(r.runs, r.id)).length;
  const w = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(w.version, 1);
  const rec = w.record;
  assert.equal(rec.state, "adopted");
  assert.equal(rec.signer.kind, "examiner");
  assert.equal(rec.signer.examiner?.name, "Ada Examiner");
  assert.equal(rec.signer.fingerprint, e.examiner.key.fingerprint);
  assert.equal(rec.signer.examiner?.enrolment_sha256, sha(readFileSync(e.file, "utf8")));
  assert.deepEqual(rec.prev, { version: 0, sha256: readReleases(r.root)[0].sha256, signature_sha256: sha(readFileSync(join(r.root, "release", "v0", "release.json.sig"))) });
  assert.equal(rec.report.html.watermark, null);
  assert.deepEqual(rec.adoption?.dispositions.map((d) => [d.seq, d.disposition]), [[14, "adopt"], [16, "inconclusive"], [17, "reject"], [19, "qualify"]]);
  assert.deepEqual(rec.adoption?.not_adopted.map((a) => a.seq), [20]);
  assert.deepEqual(rec.adoption?.defects.map((d) => [d.seq, d.disposition]), [[16, "inconclusive"], [17, "withdrawn"]]);
  assert.equal(rec.adoption?.technical_review[0].reviewer.name, "Bo Reviewer");
  assert.deepEqual(rec.adoption?.review, { lines: before, head: lineHashes((await readReviews(r.runs, r.id)).slice(0, before).map((l) => l.text).join("\n")).at(-1) });
  assert.match(rec.statement, /Adopted by Ada Examiner \(Lab One\), an examiner enrolled on this install/);
  // The final bytes: no DRAFT mark, the examiner on the cover, the kickoff's string kept apart.
  const html = readFileSync(join(r.root, "release", "v1", "report.html"), "utf8");
  assert.doesNotMatch(html, /class="watermark"/);
  assert.match(html, /<p class="release-banner adopted">Release v1, adopted by Ada Examiner \(Lab One\)/);
  assert.match(html, /<dt>Examiner<\/dt><dd>Ada Examiner, Lab One: GCFA; ten years of casework \(enrolled on this install; key SHA256:/);
  assert.match(html, /<dt>Release<\/dt><dd>v1, adopted \S+: 1 conclusion\(s\) adopted, 1 qualified, 1 withdrawn, 1 rendered inconclusive, 1 not adopted \(the agents'\); methods checked by Bo Reviewer \(EnCE\), agreed: re-ran fls; recorded by the examiner; not signed by the reviewer<\/dd>/);
  // The review's sign-off, written after the signature, names the release.
  const lines = await readReviews(r.runs, r.id);
  const sign = lines.at(-1);
  assert.equal(sign?.action, "sign");
  assert.equal(sign?.examiner_id, "ada-examiner");
  assert.deepEqual(sign?.release, { version: 1, sha256: w.sha256, signature_sha256: w.sigSha });
  assert.deepEqual(sign?.open_rejections, [], "a withdrawn answer is a disposition, not a rejection left standing");
  // Verified: against the key the release names, and against the organisation's register.
  let v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines[1], /^Release v1:   ADOPTED, .*, adopted by the examiner: follows v0; sealed by the examiner Ada Examiner \(key SHA256:\S+\): signature sound under the key the record names .*; signed on the command line, the consent presented and its confirmation skipped \(--yes\) at \S+ over report\.html as shown; .*; the review's sign-off names it; anchored beside the run; not timestamped; technical review by Bo Reviewer \(agreed\): recorded by the examiner; not signed by the reviewer; the host: .*$/);
  assert.equal(v.signatures.find((s) => s.version === 1)?.state, "unchecked");
  const register = join(r.home, "register");
  writeFileSync(register, `${e.register}\n`);
  v = await verifyReleases(layout(r), { allowedSigners: register });
  assert.equal(v.signatures.find((s) => s.version === 1)?.state, "verified");
  assert.equal(v.signatures.find((s) => s.version === 0)?.state, "self-checked", "the machine's seal is checked against its own key, never against an examiner register");
  // A register that lists the examiner's key for someone else: not a verification.
  writeFileSync(register, `${e.register.replace(/^ada-examiner /, "mallory ")}\n`);
  v = await verifyReleases(layout(r), { allowedSigners: register });
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /lists for mallory, NOT for ada-examiner, the signer the record names/);
});

test("after an adoption, another is an amendment: refused without a reason, then v2 names v1 and why", async () => {
  const r = await stoppedRun();
  enrol(r);
  await dispose(r);
  const v1 = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(v1.version, 1, "a run with no release gets the machine's draft first, then the adoption");
  assert.equal(readReleases(r.root)[0].record?.reason, "the machine's draft, written before the first adoption: none was written when custody was taken");
  await assert.rejects(signRelease(ctxOf(r), { home: r.home, say: quiet }), /release v1 is adopted already: a later adoption is an amendment and says why \(--amend-reason TEXT\)\. A new examination is a new run\./);
  await appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", action: "adopt", entry_seq: 20 });
  const v2 = await signRelease(ctxOf(r), { home: r.home, amendReason: "the narrative adopted after re-reading E-6", say: quiet });
  assert.equal(v2.version, 2);
  assert.equal(v2.record.reason, "amendment of v1: the narrative adopted after re-reading E-6");
  assert.equal(v2.record.prev?.sha256, v1.sha256);
  assert.deepEqual(v2.record.adoption?.not_adopted, []);
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.at(-1) ?? "", /Releases: {5}3 \(v0\.\.v2\); the latest adoption is v2 by Ada Examiner/);
});

test("verify names what does not hold: a release's bytes changed, its record rewritten, a version taken out, a release the anchor does not name", async () => {
  const r = await stoppedRun();
  enrol(r);
  await dispose(r);
  await signRelease(ctxOf(r), { home: r.home, say: quiet });
  const html = join(r.root, "release", "v1", "report.html");
  const bytes = readFileSync(html);
  chmodSync(html, 0o644);
  writeFileSync(html, Buffer.concat([bytes, Buffer.from("<!-- edited -->\n")]));
  let v = await verifyReleases(layout(r));
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Release v1:   ADOPTED, .*NOT AS SEALED: report\.html NOT THE BOUND BYTES/);
  writeFileSync(html, bytes);
  const rec = join(r.root, "release", "v1", "release.json");
  const text = readFileSync(rec, "utf8");
  chmodSync(rec, 0o644);
  writeFileSync(rec, text.replace('"reason": "adopted by the examiner"', '"reason": "adopted twice"'));
  v = await verifyReleases(layout(r));
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /SIGNATURE: DOES NOT VERIFY under the key the record names/);
  assert.match(v.lines.join("\n"), /the anchor names another v1/);
  writeFileSync(rec, text);
  assert.equal((await verifyReleases(layout(r))).ok, true);
  // The examiner's review changed under the release it bound.
  const review = reviewsPath(r.runs, r.id);
  const reviewText = readFileSync(review, "utf8");
  writeFileSync(review, reviewText.replace('"one command proven"', '"two commands proven"'));
  v = await verifyReleases(layout(r));
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Release v1:   ADOPTED, .*NOT AS SEALED: review line 3 does not name the line before it: the examiner's review changed under it/);
  writeFileSync(review, reviewText);
  // A release the anchor beside the run does not name (a directory put in by hand).
  const anchor = custodyAnchorPath(r.root);
  const anchorText = readFileSync(anchor, "utf8");
  const a = JSON.parse(anchorText) as { releases: unknown[] };
  chmodSync(anchor, 0o644);
  writeFileSync(anchor, JSON.stringify({ ...a, releases: a.releases.slice(0, 1) }));
  v = await verifyReleases(layout(r));
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Release v1:   ADOPTED, .*the anchor beside the run does not name it/);
  writeFileSync(anchor, anchorText);
  // v0 taken out: v1 names a release that is not there.
  spawnSync("chmod", ["-R", "u+w", join(r.root, "release")]);
  await rm(join(r.root, "release", "v0"), { recursive: true });
  v = await verifyReleases(layout(r));
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Release v1:   VERSION 0 IS MISSING before it/);
});

test("printed: a PDF of a release's HTML after it was sealed is a print record the next release binds; --pdf binds the PDF in the release itself", async () => {
  const r = await stoppedRun();
  const was = process.env.SWARM_CHROME;
  process.env.SWARM_CHROME = await fakeChrome();
  try {
    await draftRelease(ctxOf(r), { home: r.home, say: quiet });
    const p = printRelease(r.root, 0);
    assert.ok(existsSync(p.pdf));
    const rec = JSON.parse(readFileSync(p.record, "utf8")) as { release: number; html_is_the_release: boolean; pdf: { sha256: string } };
    assert.equal(rec.release, 0);
    assert.equal(rec.html_is_the_release, true);
    assert.equal(rec.pdf.sha256, sha(readFileSync(p.pdf)));
    enrol(r);
    await dispose(r);
    const w = await signRelease(ctxOf(r), { home: r.home, pdf: true, say: quiet });
    assert.equal(w.record.report.pdf?.sha256, sha(readFileSync(join(r.root, "release", "v1", "report.pdf"))));
    assert.deepEqual(w.record.report.prints.map((x) => [x.path, x.release]), [["release/v0/print-1.json", 0]]);
    assert.equal(w.record.report.prints[0].pdf_sha256, rec.pdf.sha256);
    const v = await verifyReleases(layout(r));
    assert.equal(v.ok, true, v.lines.join("\n"));
    assert.match(v.lines[1], /report\.pdf as bound; the print record release\/v0\/print-1\.json as bound/);
  } finally {
    if (was === undefined) delete process.env.SWARM_CHROME;
    else process.env.SWARM_CHROME = was;
  }
});

test("an older run says what it lacks: no release at all, or a custody that sealed no index and no chain", async () => {
  const r = await stoppedRun();
  const none = await verifyReleases(layout(r));
  assert.equal(none.ok, true);
  assert.match(none.lines[0], /^Releases: {5}none/);
  // A verdict from before the seal and the index: bound as it is, and said.
  const custody = JSON.parse(await readFile(join(r.root, "custody.json"), "utf8")) as Record<string, unknown>;
  delete custody.seal;
  delete custody.artifacts;
  const text = `${JSON.stringify(custody, null, 2)}\n`;
  await writeFile(join(r.root, "custody.json"), text);
  const anchor = JSON.parse(await readFile(custodyAnchorPath(r.root), "utf8")) as { custody: Array<{ sha256: string }> };
  anchor.custody.at(-1)!.sha256 = sha(text);
  chmodSync(custodyAnchorPath(r.root), 0o644);
  await writeFile(custodyAnchorPath(r.root), JSON.stringify(anchor));
  const d = await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.match(d.written?.record.missing.join("\n") ?? "", /the verdict seals no chain's head .*\n.*the verdict sealed no index of work\//);
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines[0], /could not bind: the verdict seals no chain's head/);
});

test("the release CLI's verify exits 3 when an adoption's key was not checked against a register, 0 when it was, 4 when a release does not hold", async () => {
  const r = await stoppedRun();
  const e = enrol(r);
  await dispose(r);
  await signRelease(ctxOf(r), { home: r.home, say: quiet });
  const cli = (...args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "release.ts"), "verify", r.root, "--run", r.id, "--runs", r.runs, ...args], { encoding: "utf8", env: { ...process.env, DFIRSWARM_HOME: r.home } });
  assert.equal(cli().status, 3);
  const register = join(r.home, "register");
  writeFileSync(register, `${e.register}\n`);
  const ok = cli("--allowed-signers", register);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /RELEASES VERIFIED\./);
  const html = join(r.root, "release", "v1", "report.html");
  chmodSync(html, 0o644);
  writeFileSync(html, "tampered\n");
  assert.equal(cli("--allowed-signers", register).status, 4);
  void execFileSync;
});
