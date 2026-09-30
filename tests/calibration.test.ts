/**
 * The calibration cases (calibration/generate.py) and their scorer
 * (scripts/calibrate.ts).
 *
 * The generator gives the same bytes for the same seed, refuses a truth path
 * inside a checkout, inside the cases directory or inside a run, holds every
 * planted fact to the bytes before it writes, and writes goals that name no
 * planted fact. The scorer reads a hand-made ledger as today's runs write it
 * (answers by question:N, absences, limitations, attestations, leads) and as
 * Plan 3's will (a result on each answer, coverage records, the question
 * register), and keeps the truth and its own output out of the run and the
 * repository.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { citedSeqs, normaliseResult, parseTruth, questionKey, resultOf, scoreRun, scoreText, type Truth } from "../scripts/calibrate.ts";
import { patternOf } from "../scripts/score.ts";
import { ledgerHash, type LedgerEntry } from "../extensions/protocol.ts";
import { goalPremises, goalPresumes } from "../extensions/questions.ts";

const ROOT = join(import.meta.dirname, "..");
const GEN = join(ROOT, "calibration", "generate.py");
const CALIBRATE = join(ROOT, "scripts", "calibrate.ts");
const HAVE_PYTHON = spawnSync("python3", ["--version"]).status === 0;

function gen(args: string[]) {
  return spawnSync("python3", [GEN, ...args], { encoding: "utf8" });
}

async function digests(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const walk = async (d: string) => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else out[relative(dir, p)] = createHash("sha256").update(await readFile(p)).digest("hex");
    }
  };
  await walk(dir);
  return out;
}

/** A generated goal's front-matter presumes, as the kickoff carries them into a Presumptions section and the register reads them: the question's number and what it takes as happened. */
function presumesOf(goal: string): Array<{ section: string; text: string; bad?: string }> {
  const front = /^---\n([\s\S]*?)\n---\n/.exec(goal)?.[1] ?? "";
  const items = [...(/^presumes:\n((?:[ \t]+-[^\n]*\n?)*)/m.exec(`${front}\n`)?.[1] ?? "").matchAll(/^[ \t]+-[ \t]*(.*?)[ \t]*$/gm)].map((m) => m[1]);
  return goalPresumes(`## Presumptions\n\n${items.map((x) => `- ${x}`).join("\n")}\n`);
}

async function truthOf(dir: string, c: string): Promise<Truth & { case: { dir?: string }; seed: string; probes: Array<{ ok: boolean }> }> {
  return JSON.parse(await readFile(join(dir, `${c}.truth.json`), "utf8"));
}

const CASES = ["usb-departure", "web-intrusion", "invoice-fraud"];

test("the generator: the same seed gives the same cases and truth, another seed other bytes", { skip: !HAVE_PYTHON && "python3 is not on this host" }, async () => {
  const T = await mkdtemp(join(tmpdir(), "calgen-"));
  try {
    for (const k of ["1", "2"]) {
      const r = gen(["--out", join(T, `cases${k}`), "--truth-dir", join(T, `truth${k}`), "--seed", "determinism"]);
      assert.equal(r.status, 0, r.stderr);
    }
    assert.deepEqual(await digests(join(T, "cases1")), await digests(join(T, "cases2")));
    for (const c of CASES) {
      const [a, b] = [await truthOf(join(T, "truth1"), c), await truthOf(join(T, "truth2"), c)];
      delete a.case.dir;
      delete b.case.dir;
      assert.deepEqual(a, b, `${c}: the truth differs between two runs of one seed`);
      assert.equal(a.seed, "determinism");
    }
    const r = gen(["--out", join(T, "cases3"), "--truth-dir", join(T, "truth3"), "--seed", "another", "--cases", "usb-departure"]);
    assert.equal(r.status, 0, r.stderr);
    const one = await digests(join(T, "cases1", "usb-departure"));
    const three = await digests(join(T, "cases3", "usb-departure"));
    assert.notEqual(one["inputs/usb.dd"], three["inputs/usb.dd"]);
    // Nothing of the truth is in a case directory: no seed, no truth file.
    const caseJson = await readFile(join(T, "cases1", "usb-departure", "case.json"), "utf8");
    assert.doesNotMatch(caseJson, /determinism/);
    assert.ok(!Object.keys(one).some((p) => p.includes("truth")));
    // What each question presumes is framed from its words alone: the same questions presume, whatever the seed.
    const presumed = async (dir: string, c: string) => presumesOf(await readFile(join(T, dir, c, "goal.md"), "utf8")).map((x) => x.section);
    assert.deepEqual(await presumed("cases3", "usb-departure"), await presumed("cases1", "usb-departure"), "the presumed questions do not depend on the seed");
    // Refused without --force, replaced with it.
    assert.equal(gen(["--out", join(T, "cases1"), "--truth-dir", join(T, "truth1"), "--seed", "determinism"]).status, 2);
    assert.equal(gen(["--out", join(T, "cases1"), "--truth-dir", join(T, "truth1"), "--seed", "determinism", "--force"]).status, 0);
  } finally {
    await rm(T, { recursive: true, force: true });
  }
});

test("the generator refuses a truth path in a checkout, in the cases directory or in a run, and writes nothing", { skip: !HAVE_PYTHON && "python3 is not on this host" }, async () => {
  const T = await mkdtemp(join(tmpdir(), "calgen-refuse-"));
  try {
    const inRepo = join(ROOT, "calibration", `truth-${process.pid}`);
    let r = gen(["--out", join(T, "cases"), "--truth-dir", inRepo, "--seed", "x"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /inside the dfirswarm checkout/);
    assert.ok(!existsSync(inRepo) && !existsSync(join(T, "cases")), "a refusal writes nothing");

    // Another checkout of the product (a clone, or the checkout a worktree lives in) is a checkout too.
    const other = join(T, "other-clone");
    await mkdir(join(other, "scripts"), { recursive: true });
    await mkdir(join(other, "extensions"), { recursive: true });
    await writeFile(join(other, "scripts", "swarm.sh"), "#!/usr/bin/env bash\n");
    r = gen(["--out", join(T, "cases"), "--truth-dir", join(other, "notes", "truth"), "--seed", "x"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /inside the dfirswarm checkout/);

    r = gen(["--out", join(T, "cases"), "--truth-dir", join(T, "cases", "truth"), "--seed", "x"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /overlap/);

    const run = join(T, "runs", "s000001");
    await mkdir(run, { recursive: true });
    await writeFile(join(run, "SWARM.md"), "# contract\n");
    await writeFile(join(run, "team.json"), "{}\n");
    r = gen(["--out", join(T, "cases"), "--truth-dir", join(run, "work", "t"), "--seed", "x"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /inside the run/);

    r = gen(["--out", join(ROOT, `cases-${process.pid}`), "--truth-dir", join(T, "truth"), "--seed", "x"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /cases directory .* inside the dfirswarm checkout/);
    assert.ok(!existsSync(join(T, "truth")));
  } finally {
    await rm(T, { recursive: true, force: true });
  }
});

test("every case plants each kind of fact, holds it to the bytes, and its goal names none of them", { skip: !HAVE_PYTHON && "python3 is not on this host" }, async () => {
  const T = await mkdtemp(join(tmpdir(), "calgen-kinds-"));
  try {
    const r = gen(["--out", join(T, "cases"), "--truth-dir", join(T, "truth"), "--seed", "s33d-q9x"]);
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stdout, /s33d-q9x/, "the seed is never printed");
    const categories = new Set<string>();
    const subkinds = new Set<string>();
    const results = new Set<string>();
    for (const c of CASES) {
      const t = await truthOf(join(T, "truth"), c);
      assert.equal(t.format, "dfirswarm-calibration-truth/1");
      assert.ok(t.probes.length > 0 && t.probes.every((p) => p.ok));
      const goal = await readFile(join(T, "cases", c, "goal.md"), "utf8");
      assert.match(goal, /^## Definition of done$/m);
      assert.match(goal, /^## Checks$/m);
      assert.match(goal, /^## Objectives$/m);
      // The brief's givens are designated as premises in the front matter, each with its scope, from the brief alone (the loop below holds them, with the rest of the goal, to naming no planted fact).
      const front = /^---\n([\s\S]*?)\n---\n/.exec(goal)?.[1] ?? "";
      const premises = [...(/^premises:\n((?:[ \t]+-[^\n]*\n?)*)/m.exec(`${front}\n`)?.[1] ?? "").matchAll(/^[ \t]+-[ \t]*(.*?)[ \t]*$/gm)].map((m) => m[1]);
      assert.ok(premises.length >= 2, `${c}: the goal designates no premises`);
      const parsed = goalPremises(`## Premises\n\n${premises.map((x) => `- ${x}`).join("\n")}\n`);
      assert.deepEqual(parsed.filter((x) => x.bad || !x.scope.entities?.length).map((x) => x.text), [], `${c}: every premise names its entities and parses`);
      const numbered = goal.split("\n").filter((l) => /^\d+\. /.test(l)).length;
      assert.equal(numbered, t.questions.length, `${c}: the goal numbers every question of the truth`);
      // What the questions presume (docs/adr/0011, "What a question presumes"), framed neutrally: every premise-false
      // question presumes its event, and so do others whose premise holds, so a presumption says nothing of the truth.
      const presumes = presumesOf(goal);
      assert.deepEqual(presumes.filter((x) => x.bad), [], `${c}: every presumes item names a question`);
      assert.ok(presumes.every((x) => Number(x.section) >= 1 && Number(x.section) <= t.questions.length), `${c}: every presumes item names a question the goal numbers`);
      const presumedIds = new Set(presumes.map((x) => x.section));
      const premiseFalse = t.questions.filter((q) => q.expected.result === "premise_not_supported").map((q) => q.id);
      assert.ok(premiseFalse.length && premiseFalse.every((q) => presumedIds.has(q)), `${c}: a premise-false question presumes its event`);
      assert.ok(presumedIds.size > premiseFalse.length, `${c}: questions whose premise holds presume theirs too`);
      assert.ok(t.questions.some((q) => q.expected.result !== "premise_not_supported" && presumedIds.has(q.id)), `${c}: a presumption is not a mark of a false premise`);
      assert.ok(t.late.length >= 1 && t.late.every((l) => existsSync(join(T, "cases", c, l.path)) && !existsSync(join(T, "cases", c, "inputs", l.path))));
      for (const q of t.questions) {
        results.add(q.expected.result);
        if (q.late) results.add(q.late.expected.result);
        for (const f of [...q.facts, ...(q.late?.facts ?? [])]) {
          categories.add(f.category);
          if (f.category === "hard_present" && f.subkind) subkinds.add(f.subkind);
          if (["hard_present", "present", "late"].includes(f.category)) {
            for (const p of f.accept ?? []) assert.ok(!patternOf(p).test(goal), `${c} ${f.id}: the goal names a planted fact (${p})`);
          }
        }
      }
    }
    for (const k of ["present", "hard_present", "absent", "decoy", "missing", "late"]) assert.ok(categories.has(k), `no ${k} fact`);
    for (const k of ["deleted", "unallocated", "slack", "secondary", "correlation", "encoded"]) assert.ok(subkinds.has(k), `no hard ${k} fact`);
    for (const k of ["established", "bounded_negative", "not_determinable", "premise_not_supported"]) assert.ok(results.has(k), `no ${k} question`);
    // Well under the size a case may have.
    const usb = await digests(join(T, "cases", "usb-departure", "inputs"));
    assert.ok(Object.keys(usb).includes("usb.dd"));
  } finally {
    await rm(T, { recursive: true, force: true });
  }
});

// --- the scorer, on a hand-made ledger ---------------------------------------------------------

const LATE_SHA = "c".repeat(64);

function miniTruth(): Truth {
  return parseTruth(JSON.stringify({
    format: "dfirswarm-calibration-truth/1",
    case: { id: "mini" },
    inputs: [{ path: "disk.dd", sha256: "a".repeat(64) }],
    late: [{ id: "proxy.csv", path: "late/proxy.csv", sha256: LATE_SHA, questions: ["4"] }],
    questions: [
      { id: "1", text: "Which files were deleted?", scored: true, kind: "present",
        expected: { result: "established", accept_results: ["established", "partial"] },
        facts: [
          { id: "F1.1", category: "hard_present", subkind: "deleted", summary: "the deleted export", accept: ["/secret_plans\\.csv/i"] },
          { id: "F1.2", category: "present", summary: "the notes", accept: ["notes.txt"] },
          { id: "F1.3", category: "decoy", summary: "an old file", accept: ["old_plans"] },
        ] },
      { id: "2", text: "Who was it for?", scored: true, kind: "present",
        expected: { result: "established", accept_results: ["established", "partial"] },
        facts: [{ id: "F2.1", category: "hard_present", subkind: "slack", summary: "the recipient", accept: ["/\\bRoe\\b/"] }] },
      { id: "3", text: "Which password?", scored: true, kind: "absent",
        expected: { result: "not_determinable", accept_results: ["not_determinable"] },
        facts: [{ id: "F3.1", category: "absent", summary: "nowhere" }, { id: "F3.2", category: "decoy", summary: "the helpdesk's", accept: ["Password123"] }] },
      { id: "4", text: "Where was it sent?", scored: true, kind: "missing",
        expected: { result: "not_determinable", accept_results: ["not_determinable"] },
        facts: [{ id: "F4.1", category: "missing", summary: "needs the proxy" }],
        acquisition: { accept: ["/proxy/i"] },
        late: { item: "late/proxy.csv", expected: { result: "established", accept_results: ["established", "partial"] },
          facts: [{ id: "F4.2", category: "late", summary: "the host", accept: ["upload.example"] }] } },
      { id: "5", text: "Did anyone log in over SSH?", scored: true, kind: "absent",
        expected: { result: "bounded_negative", accept_results: ["bounded_negative"] },
        facts: [{ id: "F5.1", category: "absent", summary: "no login" }] },
      { id: "6", text: "Timeline.", scored: false, kind: "present", expected: { result: "established", accept_results: ["established"] }, facts: [] },
    ],
  }));
}

const E = (seq: number, kind: string, value: string, more: Record<string, unknown> = {}) =>
  JSON.stringify({ v: 4, seq, kind, value, source: "src", evidence: "ev", by: "a1", authors: ["a1"], at: "2026-01-01T00:00:00Z", ...more });

async function miniRun(opts: { wp2?: boolean; late?: boolean } = {}): Promise<string> {
  const S = await mkdtemp(join(tmpdir(), "calrun-"));
  await mkdir(join(S, "ledger"), { recursive: true });
  await mkdir(join(S, "leads"), { recursive: true });
  const lines = [
    E(1, "finding", "secret_plans.csv was deleted from the drive (inode 7)", { confidence: "high" }),
    E(2, "finding", "The slack of notes.txt names Jane Roe as the recipient", { confidence: "medium" }),
    E(3, "finding", "A helpdesk mail gives Password123 as a temporary password", { confidence: "medium" }),
    E(4, "limitation", "The proxy logs were not collected", { reason: "unavailable", answers: ["4"] }),
    E(5, "absence", "No accepted SSH login from an outside address", { completion: "complete", refs: ["input:auth.log"] }),
    E(6, "answer", "notes.txt and secret_plans.csv, the latter deleted (E-1)", { section: "question:1", confidence: "high", reasoning: "E-1 shows it.", support: [{ seq: 1, hash: "x" }], by: "author", authors: ["author"] }),
    E(7, "answer", "No recipient was found on the drive", { section: "question:2", confidence: "medium", reasoning: "Searched the live files.", by: "author", authors: ["author"] }),
    E(8, "answer", "The password was Password123 (E-3)", { section: "question:3", confidence: "high", reasoning: "E-3.", by: "author", authors: ["author"] }),
    E(9, "answer", "Not determinable: the proxy logs were not collected (E-4)", { section: "question:4", confidence: "high", reasoning: "E-4.", limitations: [{ seq: 4, hash: "y" }], by: "author", authors: ["author"] }),
    E(10, "answer", "No evidence of an SSH login by the attacker in auth.log (E-5)", { section: "question:5", confidence: "medium", reasoning: "E-5.", by: "author", authors: ["author"] }),
  ];
  if (opts.wp2) {
    lines.push(E(11, "coverage", "SSH logins over the whole window", { proposition: "an SSH login by the attacker", coverage: "complete", objects: ["input:auth.log"] }));
    lines.push(E(12, "answer", "No evidence of an SSH login by the attacker in auth.log (E-11)", { section: "question:5", result: "bounded_negative", confidence: "high", reasoning: "E-11.", supersedes: 10, by: "author", authors: ["author"] }));
    lines.push(E(13, "answer", "The password could be Password123 (E-3)", { section: "Q-3", result: "not_determinable", confidence: "low", reasoning: "E-3 only.", supersedes: 8, by: "author", authors: ["author"] }));
    await mkdir(join(S, "questions"), { recursive: true });
    // The register's own events (extensions/questions.ts): the harness's dispose,
    // with what it decided; an operator's accept, then the dispose that follows it;
    // a disposition the register withdrew clears the question.
    const Q = (seq: number, ev: string, q: string, more: Record<string, unknown>) => JSON.stringify({ v: 1, seq, at: "2026-01-01T00:00:00Z", by: "system", ev, q, rev: 1, ...more, prev: String(seq - 1), hash: String(seq) });
    await writeFile(join(S, "questions", "questions.jsonl"), [
      Q(1, "dispose", "Q-1", { decided: { answer: "E-6", result: "partial", stale: false } }),
      Q(2, "accept", "Q-2", { by: "operator", act: { as: "bounded", why: "the drive is all there is", expected_rev: 1 }, decided: { rev: 1, outcome: "examination_limited", answer: "E-7" } }),
      Q(3, "dispose", "Q-2", { decided: { answer: "E-7", result: null, stale: false, accepted: "bounded" } }),
      Q(4, "dispose", "Q-4", { decided: { answer: "E-9", result: "not_determinable", stale: false } }),
      Q(5, "dispose", "Q-4", { decided: { answer: null, result: null, withdrawn_answer: true } }),
    ].join("\n") + "\n");
  }
  await writeFile(join(S, "ledger", "entries.jsonl"), `${lines.join("\n")}\n`);
  await writeFile(join(S, "ledger", "attestations.jsonl"), [
    JSON.stringify({ v: 2, act: "attest", seq: 9, target: "h", by: "critic", at: "2026-01-01T00:00:00Z", how: "re-read" }),
    JSON.stringify({ v: 2, act: "attest", seq: 11, target: "h", by: "critic", at: "2026-01-01T00:00:00Z", how: "re-ran" }),
    JSON.stringify({ v: 2, act: "attest", seq: 10, target: "h", by: "author", at: "2026-01-01T00:00:00Z", how: "my own" }),
  ].join("\n") + "\n");
  await writeFile(join(S, "leads", "leads.jsonl"), [
    JSON.stringify({ v: 1, seq: 1, at: "t", by: "a1", ev: "open", lead: "L-1", title: "Where did it go", answers: ["question:4"], prev: "genesis", hash: "1" }),
    JSON.stringify({ v: 1, seq: 2, at: "t", by: "a1", ev: "close", lead: "L-1", disposition: "needs_operator", ref: "Collect the web proxy's logs for the workstation", prev: "1", hash: "2" }),
  ].join("\n") + "\n");
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.dd", sha256: "a".repeat(64) }, ...(opts.late ? [{ path: "inputs/late/proxy.csv", sha256: LATE_SHA }] : [])] }));
  return S;
}

test("the scorer reads today's ledger: misses, false negatives, forced answers, decoys, negatives, acquisition, confidence", async () => {
  const S = await miniRun();
  try {
    const r = await scoreRun(S, miniTruth());
    const q = (id: string) => r.questions.find((x) => x.id === id)!;
    assert.equal(q("1").verdict, "found");
    assert.equal(q("1").answer?.result, "established");
    assert.equal(q("1").answer?.result_source, "structure");
    assert.equal(q("2").verdict, "false negative");
    assert.equal(q("2").answer?.result, "bounded_negative", "'No recipient was found' reads as a negative by its wording");
    assert.equal(q("2").answer?.result_source, "wording");
    assert.deepEqual(q("2").facts.map((f) => [f.id, f.where]), [["F2.1", "ledger"]]);
    assert.equal(q("3").verdict, "decoy adopted");
    assert.equal(q("3").forced, true);
    assert.equal(q("4").verdict, "held");
    assert.equal(q("4").acquisition?.requested, true);
    assert.equal(q("4").acquisition?.gap_named, true);
    assert.deepEqual(q("4").negative_support && [q("4").negative_support!.covered, q("4").negative_support!.reviewed], [true, true]);
    assert.equal(q("5").verdict, "held");
    assert.equal(q("5").answer?.result, "bounded_negative");
    assert.equal(q("5").negative_support?.covered, true, "a complete absence cited is today's coverage");
    assert.equal(q("5").negative_support?.reviewed, false, "the author's own attestation is not a review");
    assert.equal(q("6").verdict, "not scored");
    const s = r.summary;
    assert.deepEqual([s.hard_facts.total, s.hard_facts.found, s.hard_facts.miss_rate], [2, 1, 0.5]);
    assert.deepEqual([s.present_facts.total, s.present_facts.missed_in_ledger], [3, 1]);
    assert.deepEqual([s.false_negatives.questions, s.false_negatives.answered_negative], [2, 1]);
    assert.deepEqual([s.forced.questions, s.forced.forced], [3, 1]);
    assert.deepEqual([s.decoys.total, s.decoys.adopted], [2, 1]);
    assert.deepEqual([s.negatives.total, s.negatives.without_coverage, s.negatives.without_review, s.negatives.unsupported], [3, 1, 2, 2]);
    assert.deepEqual([s.acquisition.questions, s.acquisition.requested], [1, 1]);
    assert.equal(s.unanswered, 0);
    // These hand-written answers carry no confidence_rule: recorded before the run recorded confidence, they keep what their authors declared (recordedConfidence, legacy).
    assert.equal(s.calibration.overconfident, 1);
    assert.equal(s.calibration.levels.high.n, 3);
    assert.equal(s.calibration.stated_high_lowered, 0);
    assert.deepEqual([q("3").answer?.stated_confidence, q("3").answer?.confidence], ["high", "high"]);
    assert.equal(r.ledger.coverage_model, "absence");
    assert.equal(r.ledger.entries, 10);
    assert.equal(r.ledger.chain_ok, true, "hand-written lines carry no hash, as a version 1 ledger's do");
    assert.deepEqual(r.late, [{ id: "proxy.csv", added: false, how: "its sha256 is in no manifest or inventory record of the run" }]);
    const text = scoreText(r);
    assert.match(text, /Forced answers: +1 of 3/);
    assert.match(text, /Q2 F2\.1 hard_present\/slack: missed \(the ledger has it: E-2; the answer does not\)/);
  } finally {
    await rm(S, { recursive: true, force: true });
  }
});

test("the scorer takes Plan 3's fields when they are there: result, coverage records, the question register", async () => {
  const S = await miniRun({ wp2: true });
  try {
    const r = await scoreRun(S, miniTruth());
    const q = (id: string) => r.questions.find((x) => x.id === id)!;
    assert.equal(r.ledger.coverage_model, "wp2");
    assert.equal(q("1").answer?.result, "partial");
    assert.equal(q("1").answer?.result_source, "register");
    assert.deepEqual([q("2").answer?.result, q("2").answer?.result_source], ["bounded_negative", "register"], "accepted as bounded, by the operator");
    assert.notEqual(q("4").answer?.result_source, "register", "a disposition the register withdrew no longer speaks for the question");
    assert.equal(q("3").answer?.seq, 13, "Q-3 is question 3, and the correction stands");
    assert.equal(q("3").answer?.result_source, "field");
    assert.equal(q("3").verdict, "held", "a decoy named under a not-determinable result is mentioned, not adopted");
    assert.equal(q("3").decoys[0].in_value, true);
    assert.equal(q("5").answer?.seq, 12);
    assert.deepEqual(q("5").negative_support, { covered: true, complete: true, reviewed: true, reviewers: ["critic"], by: ["E-11"] });
    // Under-claimed, on the truth: question 1 is partial by the register and finds both its present facts; question 2 is a negative.
    assert.deepEqual(r.summary.under_claimed, { questions: 2, under_claimed: 1, rate: 0.5, items: [{ id: "1", label: "partial", confidence: "high", stated_confidence: "high" }] });
    assert.match(scoreText(r), /^Under-claimed: +1 of 2 present questions answered partial with every present fact found \(Q1 partial, high\)$/m);
    assert.deepEqual(r.summary.premise, [], "no question here expects premise_not_supported");
  } finally {
    await rm(S, { recursive: true, force: true });
  }
});

test("the premise-false question: what its answer recorded, and whether the answer and its reviews tested the premise, in codes; under-claiming counts only a partial answer that finds every present fact", async () => {
  const truth = miniTruth();
  truth.questions.push({ id: "7", text: "Which wiping tool was used?", scored: true, kind: "absent", expected: { result: "premise_not_supported", accept_results: ["premise_not_supported", "bounded_negative"] }, facts: [{ id: "F7.1", category: "absent", summary: "none was" }, { id: "F7.2", category: "decoy", summary: "a shredder's archive", accept: ["shredder"] }] });
  const S = await miniRun();
  try {
    const add = async (lines: string[]) => writeFile(join(S, "ledger", "entries.jsonl"), `${(await readFile(join(S, "ledger", "entries.jsonl"), "utf8")).trimEnd()}\n${lines.join("\n")}\n`);
    // Question 7 answered partial on the decoy, no premise test anywhere; question 2 partial, finding its fact.
    await add([
      E(20, "finding", "A shredder archive sits in the downloads", { confidence: "medium", answers: ["7"] }),
      E(21, "answer", "A shredder tool, apparently (E-20)", { section: "question:7", result: "partial", confidence: "medium", reasoning: "E-20.", by: "author", authors: ["author"] }),
      E(22, "answer", "Jane Roe, named in the slack of notes.txt (E-2)", { section: "question:2", result: "partial", confidence: "medium", reasoning: "E-2.", supersedes: 7, by: "author", authors: ["author"] }),
    ]);
    let r = await scoreRun(S, truth);
    assert.deepEqual(r.summary.premise, [{ id: "7", result: "partial", class_ok: false, verdict: "decoy adopted", tested_on_answer: false, tested_in_reviews: 0 }]);
    assert.deepEqual(r.questions.find((x) => x.id === "7")?.premise_test, { answer: false, reviews: [] });
    assert.equal(r.questions.find((x) => x.id === "1")?.premise_test, null, "only a question expecting premise_not_supported");
    assert.deepEqual(r.summary.under_claimed.items.map((x) => [x.id, x.label, x.confidence]), [["2", "partial", "medium"]]);
    let text = scoreText(r);
    assert.match(text, /^Premise tested: +Q7 expects premise_not_supported; answered partial \(not accepted\), decoy adopted; premise_tested on the answer no, in 0 review\(s\)$/m);
    assert.match(text, /^Under-claimed: +1 of 2 present questions answered partial with every present fact found \(Q2 partial, medium\)$/m);
    // Recorded again premise_not_supported with its own test, and a review by another seat that tests it too (and one by the author, which is not a review).
    await add([E(23, "answer", "The question's premise is not supported: no wiping tool ran (E-20)", { section: "question:7", result: "premise_not_supported", confidence: "medium", reasoning: "E-20 is an archive never unpacked.", supersedes: 21, premise_tested: { outcome: "an outcome's words, never printed", refs: ["E-20"] }, by: "author", authors: ["author"] })]);
    await writeFile(join(S, "ledger", "attestations.jsonl"), `${(await readFile(join(S, "ledger", "attestations.jsonl"), "utf8")).trimEnd()}\n${[
      JSON.stringify({ v: 2, act: "attest", seq: 23, target: "h", by: "critic", at: "2026-01-01T00:00:00Z", how: "re-read", answer_review: { premise_tested: { outcome: "words", refs: ["job:j1/x"] } } }),
      JSON.stringify({ v: 2, act: "attest", seq: 23, target: "h", by: "author", at: "2026-01-01T00:00:00Z", how: "mine", answer_review: { premise_tested: { outcome: "words", refs: ["E-20"] } } }),
    ].join("\n")}\n`);
    r = await scoreRun(S, truth);
    assert.deepEqual(r.summary.premise, [{ id: "7", result: "premise_not_supported", class_ok: true, verdict: "held", tested_on_answer: true, tested_in_reviews: 1 }]);
    text = scoreText(r);
    assert.match(text, /Q7 expects premise_not_supported; answered premise_not_supported \(accepted\), held; premise_tested on the answer yes, in 1 review\(s\)/);
    assert.ok(!text.includes("never printed") && !JSON.stringify(r.summary).includes("never printed"), "the test's words are not in the summary");
  } finally {
    await rm(S, { recursive: true, force: true });
  }
});

test("the late item, found by its digest, turns a missing question into one its answer must settle", async () => {
  const S = await miniRun({ late: true });
  try {
    const r = await scoreRun(S, miniTruth());
    const q4 = r.questions.find((x) => x.id === "4")!;
    assert.equal(r.late[0].added, true);
    assert.match(r.late[0].how, /inputs\.json/);
    assert.equal(q4.late_applies, true);
    assert.equal(q4.scored_as, "present");
    assert.equal(q4.verdict, "false negative", "an answer left at not determinable after the evidence came is stale");
    // Counted by its state at the start: missing then, it is a missing-evidence question, and the run asked for the evidence.
    assert.equal(q4.acquisition?.requested, true);
    assert.deepEqual([r.summary.acquisition.questions, r.summary.acquisition.requested], [1, 1]);
    assert.match(scoreText(r), /Acquisition: +1 of 1 missing-evidence questions requested the evidence/);
    assert.deepEqual([r.summary.late.questions, r.summary.late.reflected], [1, 0]);
    const forced = (await scoreRun(S, miniTruth(), { late: "absent" })).questions.find((x) => x.id === "4")!;
    assert.equal(forced.scored_as, "missing", "--late absent overrides the digest");
  } finally {
    await rm(S, { recursive: true, force: true });
  }
});

test("the scorer's reading helpers", () => {
  assert.equal(questionKey("question:3"), "3");
  assert.equal(questionKey("Q-12"), "12");
  assert.equal(questionKey("q7"), "7");
  assert.equal(normaliseResult("Bounded negative"), "bounded_negative");
  assert.equal(normaliseResult("inconclusive"), "not_determinable");
  assert.equal(normaliseResult("nonsense"), null);
  assert.deepEqual(citedSeqs({ value: "E-3 and E-5–E-7", reasoning: "E-9", support: [{ seq: 1 }] }), [1, 3, 5, 6, 7, 9]);
  assert.equal(resultOf({ value: "It could not be determined which host" }, [], null).result, "not_determinable");
  assert.equal(resultOf({ value: "The premise is not supported: nothing was wiped" }, [], null).result, "premise_not_supported");
  assert.equal(resultOf({ value: "X", inconclusive: true }, [], null).source, "structure");
  assert.equal(resultOf({ value: "X" }, [{ kind: "finding" }, { kind: "limitation" }], null).result, "partial");
  assert.equal(resultOf({ value: "X", result: "established" }, [], "not_determinable").source, "field");
});

test("the command refuses a truth or an output inside the run or a checkout, and writes its JSON beside the truth", async () => {
  const S = await miniRun();
  const T = await mkdtemp(join(tmpdir(), "caltruth-"));
  try {
    const truth = JSON.stringify(miniTruth());
    const node = (args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", CALIBRATE, ...args], { encoding: "utf8" });
    await writeFile(join(S, "truth.json"), truth);
    let r = node([S, "--truth", join(S, "truth.json")]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /inside the run/);
    const clone = join(T, "clone");
    await mkdir(join(clone, "scripts"), { recursive: true });
    await mkdir(join(clone, "extensions"), { recursive: true });
    await writeFile(join(clone, "scripts", "swarm.sh"), "#\n");
    await writeFile(join(clone, "truth.json"), truth);
    r = node([S, "--truth", join(clone, "truth.json")]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /inside the dfirswarm checkout/);
    await writeFile(join(T, "mini.truth.json"), truth);
    r = node([S, "--truth", join(T, "mini.truth.json"), "--out", join(S, "score.json")]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /output .* inside the run/);
    assert.ok(!existsSync(join(S, "score.json")));
    r = node([S, "--truth", join(T, "mini.truth.json")]);
    assert.equal(r.status, 0, r.stderr);
    const out = join(T, `mini.${relative(join(S, ".."), S)}.score.json`);
    assert.match(r.stdout, /Hard present facts: +1 of 2 found/);
    const report = JSON.parse(await readFile(out, "utf8"));
    assert.equal(report.format, "dfirswarm-calibration-score/1");
    assert.equal(report.questions.length, 6);
    assert.equal(report.questions[1].answer.value, "No recipient was found on the drive", "nothing is cut");
  } finally {
    await rm(S, { recursive: true, force: true });
    await rm(T, { recursive: true, force: true });
  }
});

test("a generated case scored against an empty run: every question unanswered, nothing forced", { skip: !HAVE_PYTHON && "python3 is not on this host" }, async () => {
  const T = await mkdtemp(join(tmpdir(), "calempty-"));
  try {
    assert.equal(gen(["--out", join(T, "cases"), "--truth-dir", join(T, "truth"), "--seed", "empty", "--cases", "web-intrusion"]).status, 0);
    const truth = parseTruth(await readFile(join(T, "truth", "web-intrusion.truth.json"), "utf8"));
    const run = join(T, "run");
    await mkdir(run);
    const r = await scoreRun(run, truth);
    const scored = truth.questions.filter((q) => q.scored).length;
    assert.equal(r.summary.unanswered, scored);
    assert.equal(r.summary.forced.forced, 0);
    assert.equal(r.summary.hard_facts.found, 0);
    assert.equal(r.summary.under_claimed.under_claimed, 0);
    assert.deepEqual(r.summary.premise.map((x) => [x.result, x.tested_on_answer, x.tested_in_reviews]), [[null, false, 0]], "the premise-false question, unanswered");
    assert.ok(r.notes.some((n) => /no ledger/.test(n)));
  } finally {
    await rm(T, { recursive: true, force: true });
  }
});

/** A run whose every answer says what the truth expects, with its negatives covered and reviewed. */
async function faithfulRun(truth: Truth, withLate: boolean): Promise<string> {
  const S = await mkdtemp(join(tmpdir(), "calfaithful-"));
  await mkdir(join(S, "ledger"), { recursive: true });
  const lines: string[] = [];
  const attests: string[] = [];
  const requests: string[] = [];
  let seq = 0;
  for (const q of truth.questions.filter((x) => x.scored)) {
    const late = withLate && q.late ? q.late : null;
    const expected = late ? late.expected : q.expected;
    const basis = ++seq;
    const negative = ["bounded_negative", "not_determinable", "premise_not_supported"].includes(expected.result);
    lines.push(E(basis, negative ? "coverage" : "finding", expected.summary ?? "", { proposition: q.text, coverage: "complete" }));
    const answer = ++seq;
    // Recorded under the recorded-confidence rule (confidence_rule 1): its high stands only as recordedConfidence says.
    const line = E(answer, "answer", expected.summary ?? "", { section: `question:${q.id}`, result: expected.result, confidence: "high", confidence_rule: 1, reasoning: `E-${basis}.`, by: "author", authors: ["author"] });
    lines.push(line);
    if (negative) attests.push(JSON.stringify({ v: 2, act: "attest", seq: answer, target: "h", by: "critic", at: "t", how: "re-derived" }));
    // An established answer attested established by another seat, naming the alternative it weighed: its high is recorded high.
    if (expected.result === "established") attests.push(JSON.stringify({ v: 2, act: "attest", seq: answer, target: ledgerHash(JSON.parse(line) as LedgerEntry, "genesis"), by: "critic", at: "t", how: "re-derived", strength: "established", answer_review: { reproduced: "the finding", read: "nothing else", parts: [{ part: "all", established: true, why: "the finding" }], inference: "direct", alternatives: [{ explanation: "a decoy that looks like the answer", why: "the finding rules it out by its own record", evidence: [`E-${basis}`] }], other_family: { checked: false, text: "one family" } } }));
    // A faithful run asks for a missing question's evidence at the start, whether or not a late item brings it.
    if (q.kind === "missing") requests.push(JSON.stringify({ lead: `L-${q.id}`, questions: [q.id], request: "the evidence that would settle it" }));
  }
  await writeFile(join(S, "ledger", "entries.jsonl"), `${lines.join("\n")}\n`);
  await writeFile(join(S, "ledger", "attestations.jsonl"), attests.length ? `${attests.join("\n")}\n` : "");
  await writeFile(join(S, "operator-requests.jsonl"), requests.length ? `${requests.join("\n")}\n` : "");
  const files = [...truth.inputs, ...(withLate ? truth.late : [])].map((f) => ({ path: `inputs/${f.path}`, sha256: f.sha256 }));
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files }));
  return S;
}

test("a run that answers as the truth does scores clean, before and after the late item, for every case and seed", { skip: !HAVE_PYTHON && "python3 is not on this host" }, async () => {
  const T = await mkdtemp(join(tmpdir(), "calfaithful-cases-"));
  try {
    for (const seed of ["faithful-1", "faithful-2"]) {
      assert.equal(gen(["--out", join(T, seed), "--truth-dir", join(T, `${seed}-truth`), "--seed", seed]).status, 0);
      for (const c of CASES) {
        const truth = parseTruth(await readFile(join(T, `${seed}-truth`, `${c}.truth.json`), "utf8"));
        for (const withLate of [false, true]) {
          const S = await faithfulRun(truth, withLate);
          try {
            const r = await scoreRun(S, truth);
            const where = `${seed} ${c}${withLate ? " with the late item" : ""}`;
            const s = r.summary;
            assert.equal(s.present_facts.missed, 0, `${where}: ${JSON.stringify(r.questions.flatMap((q) => q.facts.filter((f) => !f.found).map((f) => f.id)))}`);
            assert.equal(s.forced.forced, 0, where);
            assert.equal(s.decoys.adopted, 0, `${where}: ${JSON.stringify(r.questions.flatMap((q) => q.decoys.filter((d) => d.adopted).map((d) => d.id)))}`);
            assert.equal(s.false_negatives.answered_negative, 0, where);
            assert.equal(s.negatives.unsupported, 0, where);
            assert.equal(s.under_claimed.questions, s.false_negatives.questions, where);
            assert.equal(s.premise.length, 1, `${where}: one premise-false question per case`);
            assert.ok(s.premise.every((x) => x.class_ok === true), where);
            assert.equal(s.acquisition.requested, s.acquisition.questions, where);
            assert.equal(r.late.every((l) => l.added === withLate), true, where);
            assert.ok(r.questions.filter((q) => q.scored).every((q) => q.correct), `${where}: ${JSON.stringify(r.questions.filter((q) => q.scored && !q.correct).map((q) => [q.id, q.verdict]))}`);
            // High is recorded only on the established answers (attested established, naming an alternative); every other stated high is recorded medium.
            const answered = r.questions.filter((q) => q.scored && q.answer);
            const est = answered.filter((q) => q.answer!.result === "established").length;
            assert.equal(s.calibration.levels.high?.n ?? 0, est, where);
            assert.equal(s.calibration.stated_high_lowered, answered.length - est, where);
            assert.equal(s.calibration.brier, Math.round(((est * 0.01 + (answered.length - est) * 0.09) / answered.length) * 1000) / 1000, where);
          } finally {
            await rm(S, { recursive: true, force: true });
          }
        }
      }
    }
  } finally {
    await rm(T, { recursive: true, force: true });
  }
});
