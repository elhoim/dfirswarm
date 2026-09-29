/**
 * Late evidence (docs/adr/0013, "Late evidence: the reverse sweep and the
 * delta"): at the addition the new import's files, and only they, are
 * searched for every standing coverage record's looked_for strings, each hit
 * bound to the records whose strings it holds, on the sweeps' chain; the
 * hits are delivered to the re-examination of the questions they bear on
 * (the addition's board post, the stale answer's words, a warning) and hold
 * nothing by themselves. evidence_stale clears only when the answer, or its
 * new coverage, cites an entry that interprets the import with a delta; the
 * operator's acceptance after the addition still clears it.
 */
import assert from "node:assert/strict";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import * as SW from "../extensions/store-sweep.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { admitMaterial, reconcileAdditions } from "../scripts/material.ts";
import { A, coverage, ESTABLISHED, F, ok, okq, planned, rec, refused, REVIEW, run } from "./negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;
const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };

async function lateDir(S: string, files: Record<string, Buffer | string>): Promise<string> {
  const dir = join(S, "..", `late-${Math.random().toString(16).slice(2)}`);
  await mkdir(dir, { recursive: true });
  for (const [name, body] of Object.entries(files)) await writeFile(join(dir, name), body);
  return dir;
}
const attested = async (c: { sandboxRoot: string; agentId: string }, input: Record<string, unknown>) => {
  const r = await P.attestEntry(c, input as unknown as P.LedgerActInput);
  assert.ok(r.ok && (r as { line?: unknown }).line, JSON.stringify(r));
};
const defectsOf = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string, code: string) => r.defects.filter((d) => d.section === section && d.code === code);

/**
 * Question 2 a reviewed bounded negative whose coverage looked for "alice";
 * question 1 established on a finding, its question's coverage looking for
 * "bob-laptop" (UTF-16LE in the import) and "carol"; a record for question
 * 4 looked for "dave" and was corrected before the addition by one that
 * looks for nothing.
 */
async function before() {
  const c = await run();
  const lead2 = await planned(c.a0, "2");
  const abs2 = ok(await rec(c.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov2 = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${abs2.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  const ans2 = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative" })).entry;
  await attested(c.a2, { seq: cov2.seq, how: "ran the search again from job:j000001", review: REVIEW });
  await planned(c.a0, "1");
  const f1 = ok(await rec(c.a0, { kind: "finding", ...F, value: "the account ran the tool at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const cov1 = ok(await rec(c.a0, coverage("1", ["input:logs/a.log"], [`E-${f1.seq}`, "job:j000002/hits.txt"], { looked_for: ["bob-laptop", "carol"] }))).entry;
  const ans1 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "The first account, at 09:14", reasoning: `E-${f1.seq}, searched as E-${cov1.seq}`, ...HIGH, result: "established" })).entry;
  await attested(c.a2, { seq: ans1.seq, how: "re-read line 12", ...ESTABLISHED });
  await planned(c.a3, "4");
  const abs4 = ok(await rec(c.a3, { kind: "absence", value: "a start time", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["4"] })).entry;
  const cov4 = ok(await rec(c.a3, coverage("4", ["input:logs/a.log"], [`E-${abs4.seq}`], { looked_for: ["dave"], acquisition_none_why: "no source records it" }))).entry;
  const cov4b = ok(await rec(c.a3, coverage("4", ["input:logs/a.log"], [`E-${abs4.seq}`], { supersedes: cov4.seq, acquisition_none_why: "no source records it" }))).entry;
  await SW.awaitSweeps(c.S);
  return { ...c, lead2, abs2, cov2, ans2, f1, cov1, ans1, cov4b };
}

test("the reverse sweep at evidence add: the import's files, and only they, searched for every standing record's strings, each hit bound to its records, on the sweeps' chain, and said by question in the board post", async () => {
  const c = await before();
  const dir = await lateDir(c.S, { "proxy.csv": "time,user\n09:58,alice\n10:02,ALICE\n", "strings.bin": Buffer.concat([Buffer.from([0, 1]), Buffer.from("bob-laptop", "utf16le")]), "dave.txt": "dave was here\n" });
  const added = await admitMaterial(c.S, { mode: "evidence", path: dir, why: "the proxy export and a binary", supplied_by: "t", via: "cli", sweepBudget: {} } as never);
  assert.equal(added.ok, true, String(added.reason ?? ""));
  const lines = await SW.readImportSweeps(c.S);
  assert.equal(lines.length, 1);
  const s = lines[0]!;
  const ext = (await P.readLedger(c.S)).find((e) => e.seq === added.entry)!;
  assert.equal(s.target, ext.hash, "bound to the addition's external entry");
  assert.equal(s.import, "ev-0001");
  // The records standing at the addition: question 2's and question 1's; question 4's was corrected before it by one that looks for nothing.
  assert.deepEqual(s.records.map((r) => r.seq), [c.cov2.seq, c.cov1.seq]);
  assert.deepEqual(s.terms, ["alice", "bob-laptop", "carol"]);
  assert.equal(s.state, "hits");
  assert.deepEqual(s.hits.map((h) => ({ ref: h.ref, term: h.term, count: h.count, encodings: h.encodings, bears_on: h.bears_on })), [
    { ref: "import:ev-0001/proxy.csv", term: "alice", count: 2, encodings: ["utf-8"], bears_on: [c.cov2.seq] },
    { ref: "import:ev-0001/strings.bin", term: "bob-laptop", count: 1, encodings: ["utf-16le"], bears_on: [c.cov1.seq] },
  ]);
  assert.equal(s.searched.objects, 3, "every file of the import, none other");
  assert.equal(SW.verifySweepChain(await readFile(join(c.S, SW.LEDGER_SWEEPS), "utf8")).ok, true, "one chain with the coverage records' sweeps");
  assert.deepEqual((await SW.readSweeps(c.S)).map((x) => x.v), [1, 1, 1], "the coverage records' sweeps (those that looked for something) read as they were");
  assert.deepEqual(added.reverse_sweep, { state: "hits", records: 2, terms: 3, searched: s.searched, hits: 2, questions: ["1", "2"], unsearched: 0 });
  const posts = await Promise.all((await readdir(join(c.S, "threads", "main"))).filter((n) => n.endsWith("-system.md")).map((n) => readFile(join(c.S, "threads", "main", n), "utf8")));
  const post = posts.find((p) => /EVIDENCE ADDED/.test(p))!;
  assert.match(post, /The reverse sweep: import:ev-0001 searched for the 3 string\(s\) of 2 standing coverage record\(s\): 3 object\(s\), \d+ bytes; found: Q-2: "alice" in import:ev-0001\/proxy\.csv, 2 times, first at byte 16 \(E-\d+'s looked_for\) \| Q-1: "bob-laptop" in import:ev-0001\/strings\.bin, 1 time, first at byte 2 \(utf-16le\)/);
  assert.match(post, /it holds nothing by itself/);
  assert.match(post, /with a delta, rel \[\{to: <the answer's seq>, kind: supports \| contradicts \| adds_part \| irrelevant \| inconclusive\}\]/);
  // Once per addition: applied again, nothing more is written.
  await reconcileAdditions(c.S);
  const again = await SW.startImportSweep(c.S, { seq: ext.seq, hash: ext.hash!, import: "ev-0001" }, await P.readLedger(c.S));
  assert.equal(again.hash, s.hash);
  assert.equal((await SW.readImportSweeps(c.S)).length, 1);
});

test("the hits go to the re-examination of their questions and hold nothing: said with the stale answer, warned of on the established one at each delivery point, and gone once an entry the answer reaches names the object", async () => {
  const c = await before();
  const dir = await lateDir(c.S, { "proxy.csv": "time,user\n09:58,alice\n", "strings.bin": Buffer.concat([Buffer.from([0, 1]), Buffer.from("bob-laptop", "utf16le")]) });
  const added = await admitMaterial(c.S, { mode: "evidence", path: dir, why: "the proxy export and a binary", supplied_by: "t", via: "cli" });
  assert.equal(added.ok, true);
  const r = await checkLedgerAnswers(c.S, ["1", "2"], ["2"]);
  // Question 2 is stale by the addition: the hit is in its defect's words, and in its fix.
  const d2 = defectsOf(r, "question:2", "evidence_stale")[0]!;
  assert.match(d2.what, new RegExp(`The reverse sweep found what this question's coverage looked for in it: "alice" in import:ev-0001/proxy\\.csv, 1 time, first at byte 16 \\(E-${c.cov2.seq}'s looked_for\\)`));
  assert.match(d2.fix, /each object the reverse sweep names first/);
  assert.ok(!r.warnings.some((w) => w.includes("question:2")), "the stale answer carries it: no warning beside it");
  // Question 1 is established and not staled: warned of, disposed, never held.
  assert.equal(r.dispositions["question:1"], "established", r.lines.join("\n"));
  assert.deepEqual(r.defects.filter((d) => d.section === "question:1"), []);
  const w1 = r.warnings.filter((w) => w.includes("(question:1)"));
  assert.equal(w1.length, 1, r.warnings.join("\n"));
  assert.match(w1[0]!, new RegExp(`answer #${c.ans1.seq} \\(question:1\\) does not reach what the reverse sweep of evidence added late found for Q-1: import:ev-0001 \\(E-${added.entry}\\): "bob-laptop" in import:ev-0001/strings\\.bin, 1 time, first at byte 2 \\(utf-16le\\) \\(E-${c.cov1.seq}'s looked_for\\)`));
  assert.match(w1[0]!, /A hit is a string found, not a fact/);
  // Where the decision is made: finish status, the reply to a record of the answer, the reply to an attest on it.
  const status = await FIN.warningsAt(c.S, { point: "finish_status" });
  assert.deepEqual(status.filter((w) => w.code === "late_evidence_hits").map((w) => [w.section, w.seqs]), [["question:1", [c.ans1.seq, c.cov1.seq]]]);
  const ready = await FIN.readiness(c.S);
  assert.ok(!ready.items.some((i) => i.includes("(question:1)")), `readiness holds nothing on question 1: ${ready.items.join("; ")}`);
  const again = await P.recordEntry(c.a1, { kind: "answer", section: "question:1", value: "The first account, at 09:14, as the log shows", reasoning: `E-${c.f1.seq}, searched as E-${c.cov1.seq}`, ...HIGH, result: "established", supersedes: c.ans1.seq } as unknown as P.LedgerInput);
  assert.ok(again.ok);
  assert.deepEqual(again.warned, ["late_evidence_hits"]);
  const ans1b = (again as { entry: P.LedgerEntry }).entry;
  const att = await P.attestEntry(c.a3, { seq: ans1b.seq, how: "re-read line 12", ...ESTABLISHED } as unknown as P.LedgerActInput);
  assert.deepEqual((att as { warned?: string[] }).warned, ["late_evidence_hits"]);
  // What the object shows, with its delta, reached by the answer: nothing left to say.
  const seen = ok(await rec(c.a0, { kind: "finding", ...F, value: "the binary names bob-laptop as its build host, not a host of the case", source: "the binary", evidence: "its strings", refs: ["import:ev-0001/strings.bin"], answers: ["1"], rel: [{ to: ans1b.seq, kind: "irrelevant" }] })).entry;
  const ans1c = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "The first account, at 09:14; the binary's host is not the case's", reasoning: `E-${c.f1.seq} and E-${seen.seq}, searched as E-${c.cov1.seq}`, ...HIGH, result: "established", supersedes: ans1b.seq }));
  assert.equal(ans1c.warned, undefined, JSON.stringify(ans1c.warnings));
});

test("evidence_stale clears only on a delta: an entry that interprets the import with a rel to the question's answer; one with no delta, one weighed against another question's answer, one that names no object of the import clear nothing; the operator's acceptance after the addition still clears it", async () => {
  const c = await before();
  const dir = await lateDir(c.S, { "proxy.csv": "time,user\n09:58,ws\n" });
  const added = await admitMaterial(c.S, { mode: "evidence", path: dir, why: "the proxy export", supplied_by: "t", via: "cli" });
  assert.equal(added.ok, true);
  const imp = `import:ev-0001/${(await readdir(join(c.S, "store", "imports", "ev-0001", "out")))[0]}`;
  // A delta names an answer: adds_part, irrelevant and inconclusive to anything else are refused, with how to fix it.
  refused(await rec(c.a0, { kind: "absence", value: "a tool in the export", source: "the export", evidence: "read whole", refs: [imp], answers: ["2"], rel: [{ to: c.abs2.seq, kind: "irrelevant" }] }), /rel irrelevant weighs evidence added late against a question's conclusion: its to names that question's answer/);
  const tries: Array<[string, Record<string, unknown>]> = [
    ["no delta", { refs: [imp] }],
    ["a delta on another question's answer", { refs: [imp], rel: [{ to: c.ans1.seq, kind: "irrelevant" }] }],
    ["a delta on an entry that names no object of the import", { refs: ["job:j000001/hits.txt"], rel: [{ to: c.ans2.seq, kind: "irrelevant" }] }],
  ];
  let prev = c.ans2;
  let cov = c.cov2;
  for (const [what, o] of tries) {
    const d = ok(await rec(c.a0, { kind: "absence", value: `a tool in the export (${what})`, source: "the export", evidence: "read whole", answers: ["2"], ...o })).entry;
    cov = ok(await rec(c.a0, coverage("2", ["input:disk.E01", imp], [`E-${c.abs2.seq}`, `E-${d.seq}`], { looked_for: ["alice"], supersedes: cov.seq }))).entry;
    prev = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: `No evidence of a remote tool was found on the disk or the export (${what})`, reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative", supersedes: prev.seq })).entry;
    await attested(c.a2, { seq: cov.seq, how: "ran the search again over both", review: REVIEW, second_review_why: `the export (${what})` });
    const r = await checkLedgerAnswers(c.S, ["2"], ["2"]);
    const st = defectsOf(r, "question:2", "evidence_stale")[0];
    assert.ok(st, `${what}: still stale\n${r.lines.join("\n")}`);
    assert.match(st.what, /it was examined and reviewed, and nothing it cites says how the new evidence bears on the answer \(a delta\)/, what);
    assert.deepEqual(st.additions, [added.entry]);
  }
  // The operator's acceptance after the addition clears it, as before the delta (once the question's leads are closed).
  assert.ok((await L.closeLead(c.a0, c.lead2, { disposition: "resolved", ref: `E-${cov.seq}` })).ok);
  okq(await Q.act(c.S, OPERATOR, "accept", { q: "Q-2", as: "bounded", why: "the export does not bear on the disk's tools", expected_rev: 1 }));
  const accepted = await checkLedgerAnswers(c.S, ["2"], ["2"]);
  assert.deepEqual(defectsOf(accepted, "question:2", "evidence_stale"), [], accepted.lines.join("\n"));
  // And a delta clears it on the record: contradicts, cited as contrary evidence by the answer.
  const c2 = await before();
  const dir2 = await lateDir(c2.S, { "proxy.csv": "time,user\n09:58,ws\n" });
  assert.equal((await admitMaterial(c2.S, { mode: "evidence", path: dir2, why: "the proxy export", supplied_by: "t", via: "cli" })).ok, true);
  const imp2 = `import:ev-0001/${(await readdir(join(c2.S, "store", "imports", "ev-0001", "out")))[0]}`;
  const seen = ok(await rec(c2.a0, { kind: "finding", ...F, value: "the export shows a tool's beacon at 09:58", source: "the export", evidence: "row 2", refs: [imp2], answers: ["2"], rel: [{ to: c2.ans2.seq, kind: "contradicts" }] })).entry;
  const covN = ok(await rec(c2.a0, coverage("2", ["input:disk.E01", imp2], [`E-${c2.abs2.seq}`, `E-${seen.seq}`], { looked_for: ["alice"], supersedes: c2.cov2.seq }))).entry;
  const ansN = ok(await rec(c2.a1, { kind: "answer", section: "question:2", value: "No evidence of the tool's install was found on the disk; the export shows its beacon", reasoning: `E-${covN.seq}; E-${seen.seq} says otherwise`, ...A, contrary: [seen.seq], result: "bounded_negative", supersedes: c2.ans2.seq })).entry;
  await attested(c2.a2, { seq: covN.seq, how: "ran the search again over both", review: REVIEW, second_review_why: "the export is new" });
  assert.equal(P.evidenceStale(ansN, await P.readLedger(c2.S), await P.readAttestations(c2.S)), null);
});
