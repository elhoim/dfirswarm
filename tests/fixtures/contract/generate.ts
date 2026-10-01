/**
 * Writes the register histories under tests/fixtures/contract/<case>/run/:
 * synthetic runs, each made through the harness's own acts (record, attest,
 * leads, the finish, evidence add, custody), for scripts/replay.ts to read
 * again under any harness version (docs/adr/0017, "Measuring a rule
 * change"). Each case's expect.json beside it is written by hand from the
 * ADRs, never by this script and never from the code's output.
 *
 * No case, no tool, no truth: generic questions, one disk and one log named
 * in inputs.json, two jobs whose outputs are a line of text.
 *
 *   node --experimental-strip-types --no-warnings tests/fixtures/contract/generate.ts [case…]
 *
 * The histories are written once and committed: running this again makes
 * new ones (new times, new hashes), which the tests read the same way.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, rename, rm, rmdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as FIN from "../../../extensions/finish.ts";
import * as L from "../../../extensions/leads.ts";
import * as P from "../../../extensions/protocol.ts";
import * as Q from "../../../extensions/questions.ts";
import * as SW from "../../../extensions/store-sweep.ts";
import { checkLedgerAnswers } from "../../../scripts/check-answers.ts";
import { custodyAnchorPath, takeCustody } from "../../../scripts/custody.ts";
import { prepareResume } from "../../../scripts/resume.ts";
import { Journal, sealTree, storePaths } from "../../../scripts/evidence-store.ts";
import { finishGate } from "../../../scripts/finish-gate.ts";
import { admitMaterial } from "../../../scripts/material.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

type Ctx = { sandboxRoot: string; agentId: string };
type Run = { S: string; runs: string; a0: Ctx; a1: Ctx; a2: Ctx; a3: Ctx };

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const A = { confidence: "medium", confidence_why: "The cited entries are direct.", alternatives_open: "none open", would_change: "a second source that disagrees" } as const;
const HIGH = { ...A, confidence: "high" } as const;
/**
 * The source-first part of an established review (docs/adr/0015): the
 * strongest rival and its test, resting on the job output the test read
 * (never the answer, nor only the entries it cites), and the job that
 * derived the value (j000001, over the disk).
 */
const SOURCE_FIRST = {
  discriminator: { rival: "a copy of the record written later by a backup process", test: "read the record's own write time against the backup's run times", favours_if: "the answer if the write time falls outside every backup run; the rival if it falls inside one", outcome: "the write time falls outside every backup run", refs: ["job:j000001/hits.txt"] },
  derivation: { job: "j000001", inputs: ["input:disk.E01"] },
} as const;
const REVIEWED = {
  reproduced: "re-derived the cited finding from its sealed ref",
  read: "nothing beyond the cited entries",
  parts: [{ part: "the question as asked", established: true, why: "the cited finding shows it" }],
  inference: "the finding is the answer",
  alternatives: [{ explanation: "a copy of the record left by another process", why: "the cited record's own metadata ties it to the event, and no copy exists in the objects searched", evidence: ["E-1"] }],
  other_family: { checked: false, text: "no other source family holds it in this fixture" },
} as const;
/** How a critic attests an answer established (a history written before the source-first rule has the review without SOURCE_FIRST). */
const ESTABLISHED = { strength: "established", answer_review: { ...REVIEWED, ...SOURCE_FIRST } } as const;
const REVIEW = {
  detection: { done: true, text: "the event writes to the objects searched, and they keep it for their whole range" },
  reproduced: { done: true, text: "ran the decisive search again over the same objects: nothing" },
  other_route: { done: false, text: "no second source for the event in the case" },
} as const;

/** A partial answer's rows (docs/adr/0013): how the tool was installed, on the finding; who installed it, open on the lead's route. */
const TOOL_PARTS = (finding: number, lead: string) => [
  { id: "how", part: "how the remote tool was installed", status: "established", refs: [`E-${finding}`] },
  { id: "who", part: "which account installed it", status: "open", open_by: lead },
];
/** A review that holds both of those rows established: the partial label a hedge (partial_all_parts_established). */
const TOOL_PARTS_HELD = [
  { id: "how", part: "how the remote tool was installed", established: true, why: "the service entry shows it" },
  { id: "who", part: "which account installed it", established: true, why: "the service entry names its account" },
];

const QUESTIONS = ["Who logged on, and when?", "Was a remote tool installed?", "What was deleted?", "When did it start?", "Which account ran the tool?", "What left the network?"];

function goal(n: number, existence: string[] = [], premises: string[] = [], presumes: string[] = [], must: string[] = []): string {
  return [
    "## Goal",
    "",
    "Examine the host.",
    "",
    "### Questions",
    "",
    ...QUESTIONS.slice(0, n).map((q, i) => `${i + 1}. ${q}`),
    "",
    // The goal's premises (docs/adr/0011, "Premises"): each a given of the premise register.
    ...(premises.length ? ["## Premises", "", ...premises.map((p) => `- ${p}`), ""] : []),
    // What the goal's questions presume (docs/adr/0011, "What a question presumes"): "<n>: <what it takes as happened>".
    ...(presumes.length ? ["## Presumptions", "", ...presumes.map((p) => `- ${p}`), ""] : []),
    // The goal's questions that must be established (docs/adr/0013, "A question that must be established"): "<n>[: why]".
    ...(must.length ? ["## Must establish", "", ...must.map((m) => `- ${m}`), ""] : []),
    "## Definition of done",
    "",
    "Every question has a disposition under the bar.",
    "",
    "## Checks",
    "",
    `- \`node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections ${Array.from({ length: n }, (_, i) => i + 1).join(",")}${existence.length ? ` --existence ${existence.join(",")}` : ""}\``,
    "",
  ].join("\n");
}

async function job(S: string, id: string, file: string, body: string, inputs: string[]): Promise<void> {
  const staging = join(S, "..", `staging-${id}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), body);
  await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(S).jobs, id, "job.json"), `${JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs, command: "search" } })}\n`);
  await rm(staging, { recursive: true, force: true });
}

async function newRun(base: string, id: string, questions: number, existence: string[] = [], premises: string[] = [], presumes: string[] = [], must: string[] = []): Promise<Run> {
  const runs = join(base, "runs");
  const S = join(runs, id);
  await P.initSandbox(S, { swarmId: id, agentIds: ["a0", "a1", "a2", "a3"], capUsd: 5, wallClockMinutes: 30, goal: goal(questions, existence, premises, presumes, must) });
  await writeFile(join(S, "inputs.json"), `${JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: sha("disk"), bytes: 10 }, { path: "inputs/logs/a.log", sha256: sha("a"), bytes: 10 }] })}\n`);
  await job(S, "j000001", "hits.txt", "j000001\n", ["input:disk.E01"]);
  await job(S, "j000002", "hits.txt", "j000002\n", ["input:logs/a.log"]);
  const ctx = (agentId: string) => ({ sandboxRoot: S, agentId });
  return { S, runs, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2"), a3: ctx("a3") };
}

const ok = async (p: Promise<{ ok: boolean }>) => {
  const r = await p;
  assert.ok(r.ok, (r as unknown as { reason?: string }).reason ?? JSON.stringify(r));
  return r as unknown as { ok: true; entry: P.LedgerEntry; note?: string };
};
const rec = (c: Ctx, input: Record<string, unknown>) => ok(P.recordEntry(c, input as unknown as P.LedgerInput));
const attest = async (c: Ctx, input: Record<string, unknown>) => {
  const r = await P.attestEntry(c, input as unknown as P.LedgerActInput);
  assert.ok(r.ok && (r as { line?: unknown }).line, JSON.stringify(r));
};

async function lead(c: Ctx, q: string, routes = [{ source: "input:logs/a.log", method: "read the log" }]): Promise<string> {
  const r = await L.openLead(c, { title: `Work question ${q}`, why: "it is asked", answers: [q], take: true, routes });
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return (r as { lead: { id: string } }).lead.id;
}
const close = async (c: Ctx, id: string, ref: string) => assert.ok((await L.closeLead(c, id, { disposition: "resolved", ref })).ok);

/** A coverage record for question `q` over `refs`, resting on `results`. */
const coverage = (q: string, refs: string[], results: string[], o: Record<string, unknown> = {}) => ({
  kind: "coverage",
  proposition: `The event question ${q} asks about happened`,
  refs,
  answers: [q],
  time_range: "the whole of each object, no time bound",
  search_method: "a keyword search",
  settings: "case-insensitive, every encoding the tool offers",
  coverage_actual: "every byte of the objects named",
  skipped: "none: the search ran to its end",
  failures: "none",
  result_refs: results,
  alternatives: "the event may have left its trace only in memory, which the case does not hold",
  detection_opportunity: { trace_expected: "yes", why: "the event writes to the objects searched, and they keep it" },
  ...(o.looked_for === undefined ? { looked_for_none_why: "the fixture's event has no literal form a byte search could find" } : {}),
  ...o,
});

/** Question `q` established on a finding, attested established by another seat, its lead closed. */
async function established(r: Run, q: string, by: Ctx = r.a1, critic: Ctx = r.a2): Promise<number> {
  const id = await lead(r.a0, q, [{ source: "input:disk.E01", method: "read the disk" }]);
  const f = (await rec(r.a0, { kind: "finding", ...F, value: `the record question ${q} asks for`, source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
  const a = (await rec(by, { kind: "answer", section: `question:${q}`, value: `Established: the record question ${q} asks for`, reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
  await attest(critic, { seq: a.seq, how: "re-read the key from job:j000001", ...ESTABLISHED });
  await close(r.a0, id, `E-${f.seq}`);
  return a.seq;
}

/**
 * Question `q` answered partial, medium confidence, on a finding, with the
 * limitation that bounds the part it leaves open; its lead closed. Its rows
 * (docs/adr/0013, "Claim and open-part rows"): "when" established on the
 * finding, "who" open by the limitation. The histories committed before the
 * rows were recorded without them, and are kept as they were.
 */
async function partial(r: Run, q: string) {
  const id = await lead(r.a0, q);
  const f = (await rec(r.a0, { kind: "finding", ...F, value: `a logon at 09:14 for question ${q}`, source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: [q] })).entry;
  const lim = (await rec(r.a0, { kind: "limitation", value: `The log keeps no account name for question ${q}`, source: "the log", evidence: "its field list", reason: "unavailable", answers: [q] })).entry;
  const a = (await rec(r.a1, { kind: "answer", section: `question:${q}`, value: "A logon at 09:14; the account is not established", reasoning: `E-${f.seq} shows the logon and its time; the account is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial", parts: [{ id: "when", part: "when the logon happened", status: "established", refs: [`E-${f.seq}`] }, { id: "who", part: "which account logged on", status: "open", open_by: `E-${lim.seq}` }] })).entry;
  await close(r.a0, id, `E-${f.seq}`);
  return { f, lim, a };
}

async function setPolicy(S: string, policy: "operator" | "cap-pause" | "cap-stop"): Promise<void> {
  const b = await P.readBudget(S);
  await P.writeBudget(S, policy === "operator" ? { ...b, stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 } : { ...b, stop_policy: policy, until_solved: false, wall_clock_minutes: 60 });
}

/** `agent` publishes the report: a revision of work/report.md in its name. */
async function publish(S: string, agent: string, text: string): Promise<void> {
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, "work", "report.md"), text);
  await P.recordFileVersion(S, "work/report.md", agent);
}

async function traceRow(S: string, agent: string, tool: string): Promise<void> {
  const at = new Date().toISOString();
  await writeFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at, recv_ts: at, agent, tool, args: {}, result: { ok: true } })}\n`, { flag: "a" });
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A receipt of the disk's broad extraction on the store journal, as the hub writes one (scripts/preparation.ts). */
async function diskReceipt(S: string, state: string, o: Record<string, unknown> = {}): Promise<void> {
  const j = await Journal.open(S);
  await j.append({ type: "preparation", state, source: { sha256: sha("disk"), ref: "input:disk.E01", name: "inputs/disk.E01", bytes: 10 }, recipe: "computer-forensics-base/disk-timeline", recipe_version: "1.0.0", recipe_sha256: sha("disk-timeline"), capability: "disk-super-timeline", job: "j000009", manifest: null, exclusions: ["volume shadow copies", "unallocated space: nothing is carved"], by: "harness", ...o });
}

/**
 * Three negatives over the disk while its broad extraction is under way:
 * question 1 not determinable on coverage complete over the disk, question
 * 2 (it asks whether something exists) a bounded negative that says the
 * event did not happen, question 3 not determinable on coverage that names
 * the disk but is partial (its job read the log). Each reviewed by another
 * seat; the disk's extraction planned, then attempted.
 */
async function preparationNegatives(base: string, id: string): Promise<Run> {
  const r = await newRun(base, id, 3, ["2"]);
  await diskReceipt(r.S, "planned");
  const negative = async (q: string, refs: string[], results: string[], answer: Record<string, unknown>) => {
    const lid = await lead(r.a0, q, [{ source: "input:disk.E01", method: "search the disk" }]);
    const abs = (await rec(r.a0, { kind: "absence", value: `the event of question ${q}`, source: "the disk", evidence: "a search", refs: [results[0]!], answers: [q] })).entry;
    const cov = (await rec(r.a0, coverage(q, refs, [`E-${abs.seq}`, ...results], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
    await rec(r.a1, { kind: "answer", section: `question:${q}`, reasoning: `E-${cov.seq}`, ...A, ...answer });
    await attest(r.a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
    await close(r.a0, lid, `E-${cov.seq}`);
  };
  await negative("1", ["input:disk.E01"], ["job:j000001/hits.txt"], { value: "When it happened cannot be determined from the disk", result: "not_determinable" });
  await negative("2", ["input:disk.E01"], ["job:j000001/hits.txt"], { value: "No remote tool was installed on the disk: the installation did not happen", result: "bounded_negative", asserts_absence: true });
  await negative("3", ["input:disk.E01", "input:logs/a.log"], ["job:j000002/hits.txt"], { value: "What was deleted cannot be determined from the log", result: "not_determinable" });
  await diskReceipt(r.S, "attempted", { when: new Date().toISOString() });
  return r;
}

/** The operator on the host, not enrolled: who designates and admits premises in the fixtures. */
const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };

/** The goal's one premise in the premise cases: the laptop is the employee's, for the whole of 2024 (a given, P-1). */
const LAPTOP_PREMISE = "The disk image disk.E01 is of the laptop issued to the employee the brief names, who alone used it [scope: entities disk.E01; times 2024-01-01..2024-12-31]";

/**
 * Question `q` established on a finding, citing `premises`, attested
 * established by another seat, its lead closed; the finding's words given.
 */
async function citing(r: Run, q: string, value: string, premises: unknown[], o: { by?: Ctx; critic?: Ctx; supersedes?: number; finding?: number } = {}): Promise<{ f: number; a: number }> {
  const id = await lead(r.a0, q, [{ source: "input:disk.E01", method: "read the disk" }]);
  const f = o.finding ?? (await rec(r.a0, { kind: "finding", ...F, value, source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: [q] })).entry.seq;
  const a = (await rec(o.by ?? r.a1, { kind: "answer", section: `question:${q}`, value: `Established: ${value}`, reasoning: `E-${f}`, ...HIGH, result: "established", premises, ...(o.supersedes ? { supersedes: o.supersedes } : {}) })).entry;
  await attest(o.critic ?? r.a2, { seq: a.seq, how: "re-read the key from job:j000001", ...ESTABLISHED });
  await close(r.a0, id, `E-${f}`);
  return { f, a: a.seq };
}

/** The premise acts through the register's own admission, as the CLI's are when no hub runs. */
async function operatorAct(S: string, ev: Q.ActKind, input: Q.ActInput): Promise<void> {
  const r = await Q.act(S, OPERATOR, ev, input);
  assert.ok(r.ok, (r as { reason?: string }).reason);
}

// ---------------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------------

/** Evidence added after the kickoff, from a neutral path outside the run (the addition records where it came from). */
async function addLate(S: string, name: string, body: string, why: string): Promise<void> {
  const late = "/tmp/dfirswarm-contract-late";
  await rm(late, { recursive: true, force: true });
  await mkdir(late, { recursive: true });
  await writeFile(join(late, name), body);
  const added = await admitMaterial(S, { mode: "evidence", path: join(late, name), why, supplied_by: "operator", via: "cli" });
  await rm(late, { recursive: true, force: true });
  assert.equal(added.ok, true, String((added as { reason?: string }).reason ?? ""));
  // Its reverse sweep runs once the addition is committed, in the background: settled before the history goes on.
  await SW.awaitSweeps(S);
}

const CASES: Record<string, (base: string) => Promise<string>> = {
  /**
   * The run s9722fa (a CTF case, c10), reconstructed: six goal questions
   * under --stop operator, every one a partial answer with medium
   * confidence resting on a finding and citing the limitation that bounds
   * its open part, each reviewed best_candidate by another seat that held
   * the open part not established (the harness's cap of that time).
   */
  "c10-partial-cascade": async (base) => {
    const r = await newRun(base, "c10pc", 6);
    await setPolicy(r.S, "operator");
    for (const q of ["1", "2", "3", "4", "5", "6"]) {
      const p = await partial(r, q);
      await attest(r.a3, {
        seq: p.a.seq,
        how: "re-read line 12 from job:j000002",
        strength: "best_candidate",
        answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when", established: true, why: "line 12" }, { id: "who", part: "which account", established: false, why: "no account field" }] },
      });
    }
    return r.S;
  },

  /** A partial answer, its review holding the parts it claims and the open part as it declares it; the other question established. */
  "partial-every-policy": async (base) => {
    const r = await newRun(base, "pep", 2);
    await established(r, "2");
    const p = await partial(r, "1");
    await attest(r.a3, {
      seq: p.a.seq,
      how: "re-read line 12 from job:j000002; no account field in the log",
      ...ESTABLISHED,
      answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when, and from where", established: true, why: "line 12" }, { id: "who", part: "which account", established: false, why: "the log keeps none", declared_open: `E-${p.lim.seq}` }] },
    });
    return r.S;
  },

  /** An answer that claims established, medium confidence, its one review a best candidate. */
  "established-best-candidate": async (base) => {
    const r = await newRun(base, "ebc", 2);
    await established(r, "2");
    const id = await lead(r.a0, "1");
    const f = (await rec(r.a0, { kind: "finding", ...F, value: "a logon at 09:14 by the first account", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const a = (await rec(r.a1, { kind: "answer", section: "question:1", value: "The first account, at 09:14", reasoning: `E-${f.seq}`, ...A, result: "established" })).entry;
    await close(r.a0, id, `E-${f.seq}`);
    await attest(r.a3, { seq: a.seq, how: "re-read line 12", ...ESTABLISHED, strength: "best_candidate" });
    return r.S;
  },

  /** A material bounded negative on its coverage record, which nobody else has reviewed. */
  "negative-unreviewed": async (base) => {
    const r = await newRun(base, "nur", 2, ["2"]);
    await established(r, "1");
    const id = await lead(r.a0, "2", [{ source: "input:disk.E01", method: "search the disk" }]);
    const abs = (await rec(r.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
    const cov = (await rec(r.a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"]))).entry;
    await rec(r.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" });
    await close(r.a0, id, `E-${cov.seq}`);
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * Two reviewed negatives; then evidence added. Question 1 is left on its
   * older coverage (stale); question 2 is examined again against the new
   * import: what it shows is recorded with its delta (irrelevant to the
   * answer), among the results of a coverage record naming the import,
   * which another seat reviews (cleared).
   */
  "evidence-stale-cleared": async (base) => {
    const r = await newRun(base, "esc", 2);
    for (const q of ["1", "2"]) {
      const id = await lead(r.a0, q, [{ source: "input:disk.E01", method: "search the disk" }]);
      const abs = (await rec(r.a0, { kind: "absence", value: `the event of question ${q}`, source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
      const cov = (await rec(r.a0, coverage(q, ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
      await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `No evidence of the event of question ${q} was found on the disk`, reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" });
      await attest(r.a2, { seq: cov.seq, how: "ran the search again from job:j000001", review: REVIEW });
      await close(r.a0, id, `E-${cov.seq}`);
    }
    await SW.awaitSweeps(r.S);
    await addLate(r.S, "proxy.csv", "time,host\n09:58,ws\n", "the proxy export the network team kept");
    // Question 2 examined against it: what the export shows, with its delta, reviewed by another seat.
    const prev = (await P.readLedger(r.S)).filter((e) => e.kind === "answer" && e.section === "question:2").at(-1)!;
    const abs2 = (await rec(r.a0, { kind: "absence", value: "the event of question 2 in the proxy export", source: "the proxy export", evidence: "read whole", refs: ["import:ev-0001/proxy.csv"], answers: ["2"], rel: [{ to: prev.seq, kind: "irrelevant" }] })).entry;
    const cov2 = (await rec(r.a0, coverage("2", ["input:disk.E01", "import:ev-0001/proxy.csv"], [`E-${abs2.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
    await rec(r.a1, { kind: "answer", section: "question:2", value: "No evidence of the event of question 2 was found on the disk or in the proxy export", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative", supersedes: prev.seq });
    await attest(r.a2, { seq: cov2.seq, how: "ran the search again over the disk and the export", review: REVIEW, second_review_why: "the export is new" });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * The history evidence-stale-cleared held before the delta rule, kept as
   * it was recorded (by the harness at c34c6cb): question 2 examined
   * against the new import on a coverage record naming it, which another
   * seat reviews, and nothing it cites says how the export bears on the
   * answer. Replayed under the rule before the delta it is cleared; under
   * this checkout it is held (docs/adr/0013, "Late evidence: the reverse
   * sweep and the delta"). Run again, this case makes the same history.
   */
  "evidence-stale-without-delta": async (base) => {
    const r = await newRun(base, "esc", 2);
    const covs: number[] = [];
    for (const q of ["1", "2"]) {
      const id = await lead(r.a0, q, [{ source: "input:disk.E01", method: "search the disk" }]);
      const abs = (await rec(r.a0, { kind: "absence", value: `the event of question ${q}`, source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
      const cov = (await rec(r.a0, coverage(q, ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
      await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `No evidence of the event of question ${q} was found on the disk`, reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" });
      await attest(r.a2, { seq: cov.seq, how: "ran the search again from job:j000001", review: REVIEW });
      await close(r.a0, id, `E-${cov.seq}`);
      covs.push(cov.seq);
    }
    await SW.awaitSweeps(r.S);
    // Outside the directory the run is made in, at a neutral path: the addition records where it came from.
    const late = "/tmp/dfirswarm-contract-late";
    await rm(late, { recursive: true, force: true });
    await mkdir(late, { recursive: true });
    await writeFile(join(late, "proxy.csv"), "time,host\n09:58,ws\n");
    const added = await admitMaterial(r.S, { mode: "evidence", path: join(late, "proxy.csv"), why: "the proxy export the network team kept", supplied_by: "operator", via: "cli" });
    await rm(late, { recursive: true, force: true });
    assert.equal(added.ok, true, String((added as { reason?: string }).reason ?? ""));
    // Question 2 examined against it, and reviewed by another seat.
    const abs2 = (await rec(r.a0, { kind: "absence", value: "the event of question 2 in the proxy export", source: "the proxy export", evidence: "read whole", refs: ["import:ev-0001/proxy.csv"], answers: ["2"] })).entry;
    const cov2 = (await rec(r.a0, coverage("2", ["input:disk.E01", "import:ev-0001/proxy.csv"], [`E-${abs2.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
    const prev = (await P.readLedger(r.S)).filter((e) => e.kind === "answer" && e.section === "question:2").at(-1)!;
    await rec(r.a1, { kind: "answer", section: "question:2", value: "No evidence of the event of question 2 was found on the disk or in the proxy export", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative", supersedes: prev.seq });
    await attest(r.a2, { seq: cov2.seq, how: "ran the search again over the disk and the export", review: REVIEW, second_review_why: "the export is new" });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * The store sweep: question 1's record names the object its sweep found a
   * hit in and says nothing of what it showed (held); question 2's names it
   * with a finding written after the sweep that examines it (released).
   */
  "sweep-hits-examined": async (base) => {
    const r = await newRun(base, "she", 2);
    await job(r.S, "j000007", "export.csv", "time,user\n09:58,alice\n", ["input:disk.E01"]);
    await job(r.S, "j000008", "notes.txt", "bob-laptop was seen\n", ["input:disk.E01"]);
    for (const [q, term, obj] of [["1", "alice", "j000007"], ["2", "bob-laptop", "j000008"]] as const) {
      const id = await lead(r.a0, q, [{ source: "input:disk.E01", method: "search the disk" }]);
      const abs = (await rec(r.a0, { kind: "absence", value: `the event of question ${q}`, source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
      const cov = (await rec(r.a0, coverage(q, ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: [term], acquisition_none_why: "no source outside the evidence records it" }))).entry;
      let ans = (await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `No evidence of the event of question ${q} was found on the disk`, reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
      await SW.awaitSweeps(r.S);
      const file = obj === "j000007" ? "export.csv" : "notes.txt";
      // Question 2: what the hit object showed, recorded after the sweep.
      const seen = q === "2" ? (await rec(r.a3, { kind: "finding", ...F, value: "the notes name another host's laptop, not a tool", source: "the notes", evidence: "line 1", refs: [`job:${obj}/${file}`], answers: [q] })).entry : null;
      const cov2 = (await rec(r.a0, coverage(q, ["input:disk.E01", `job:${obj}`], [`E-${abs.seq}`, "job:j000001/hits.txt", ...(seen ? [`E-${seen.seq}`] : [])], { looked_for: [term], supersedes: cov.seq, acquisition_none_why: "no source outside the evidence records it" }))).entry;
      ans = (await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `No evidence of the event of question ${q} was found on the disk or the outputs`, reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative", supersedes: ans.seq })).entry;
      await SW.awaitSweeps(r.S);
      await attest(r.a2, { seq: cov2.seq, how: "ran the search again", review: REVIEW });
      await close(r.a0, id, `E-${cov2.seq}`);
    }
    return r.S;
  },

  /** Every question disposed; a result posted by another seat after the report was written as the finish began, with no resolution. */
  "late-post-after-report": async (base) => {
    const r = await newRun(base, "lpr", 1);
    await established(r, "1");
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report\n\n## 1. Who logged on, and when?\n\nSee E-3.\n");
    const t = await FIN.finishTurn(r.a0, { output_file: "work/report.md" });
    assert.equal(t.mine, true);
    await pause(30);
    await P.postMessage(r.a1, { tag: "result", body: "the timeline misses the second logon at 09:20" });
    return r.S;
  },

  /** The coordinator's finish line passed and was recorded at a revision; then another seat objected to the report (an ack, which moves no revision). */
  "racing-objection": async (base) => {
    const r = await newRun(base, "rob", 1);
    await established(r, "1");
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report\n\n## 1. Who logged on, and when?\n\nSee E-3.\n");
    const t = await FIN.finishTurn(r.a0, { output_file: "work/report.md" });
    assert.equal(t.mine, true);
    const c = await checkLedgerAnswers(r.S, ["1"]);
    const run = { total: 1, passed: c.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1", ok: c.ok, answers: { outcomes: c.outcomes, results: c.results, dispositions: c.dispositions, best_candidate: c.best_candidate, named: [] } }] };
    const gate = await finishGate(r.S, run);
    const verdict = P.finishLineVerdict({ ...run, gate }, false);
    assert.equal(verdict.proceed, true, JSON.stringify(verdict));
    const { revision } = await P.stateRevision(r.S);
    await FIN.recordCheck(r.S, "a0", revision, { proceed: true, outcome: (verdict as { outcome: string }).outcome }, { ...run, gate });
    const obj = await FIN.ackReport(r.a2, { verdict: "objection", why: "section 1 names the wrong logon" });
    assert.ok(obj.ok, JSON.stringify(obj));
    return r.S;
  },

  /**
   * The finish prepared and resolved in one batch (docs/adr/0015, "Preparing
   * the finish"): the report published, a result and a veto posted after it
   * by two other seats, the coordinator's prepare listing both, one batch
   * resolving both, and the same batch sent again with its key, as a retry
   * after an interruption does.
   */
  "prepared-batch-resolved": async (base) => {
    const r = await newRun(base, "pbr", 1);
    await established(r, "1");
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report\n\n## 1. Who logged on, and when?\n\nSee E-3.\n");
    await pause(30);
    const p1 = await P.postMessage(r.a1, { tag: "result", body: "the second logon at 09:20 is the same session" });
    const p2 = await P.postMessage(r.a2, { tag: "veto", body: "the logon came over the VPN" });
    const prep = await FIN.prepareFinish(r.a0, { report: "work/report.md" });
    assert.ok(prep.ok && prep.mine, JSON.stringify(prep));
    const batch = { items: [{ post: p1.id, how: "not_material", why: "the same session, in section 1 already" }, { post: p2.id, how: "folded", where: "section 1 says the logon came over the VPN" }], generation: prep.generation, digest: prep.digest as string, key: "finish-batch-1" };
    const b = await FIN.resolveLate(r.a0, batch);
    assert.ok(b.ok && b.resolved === 2, JSON.stringify(b));
    const again = await FIN.resolveLate(r.a0, batch);
    assert.ok(again.ok && again.replayed, JSON.stringify(again));
    return r.S;
  },

  /** As prepared-batch-resolved, then a veto posted after the batch, racing the done: it is late, and holds it. */
  "prepared-racing-veto": async (base) => {
    const r = await newRun(base, "prv", 1);
    await established(r, "1");
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report\n\n## 1. Who logged on, and when?\n\nSee E-3.\n");
    await pause(30);
    const p1 = await P.postMessage(r.a1, { tag: "result", body: "the second logon at 09:20 is the same session" });
    const p2 = await P.postMessage(r.a2, { tag: "veto", body: "the logon came over the VPN" });
    const prep = await FIN.prepareFinish(r.a0, { report: "work/report.md" });
    assert.ok(prep.ok && prep.mine, JSON.stringify(prep));
    const b = await FIN.resolveLate(r.a0, { items: [{ post: p1.id, how: "not_material", why: "the same session" }, { post: p2.id, how: "folded", where: "section 1" }], generation: prep.generation, digest: prep.digest as string, key: "finish-batch-1" });
    assert.ok(b.ok, JSON.stringify(b));
    await pause(30);
    await P.postMessage(r.a3, { tag: "veto", body: "the account in section 1 is a service account" });
    return r.S;
  },

  /**
   * A takeover after a prepare: the coordinator prepared, a result was
   * posted after the report, the coordinator began compacting, and another
   * seat's prepare took the finish over at the next generation with the
   * boundary kept, and resolved the result in one batch.
   */
  "prepared-takeover": async (base) => {
    const r = await newRun(base, "ptk", 1);
    await established(r, "1");
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report\n\n## 1. Who logged on, and when?\n\nSee E-3.\n");
    const first = await FIN.prepareFinish(r.a0, { report: "work/report.md" });
    assert.ok(first.ok && first.mine, JSON.stringify(first));
    await pause(30);
    const p1 = await P.postMessage(r.a1, { tag: "result", body: "the second logon at 09:20 is the same session" });
    await traceRow(r.S, "a0", "compact_start");
    const took = await FIN.prepareFinish(r.a2, { report: "work/report.md" });
    assert.ok(took.ok && took.mine && took.took_over === "a0" && took.generation === 2, JSON.stringify(took));
    const b = await FIN.resolveLate(r.a2, { items: [{ post: p1.id, how: "not_material", why: "the same session" }], generation: 2, digest: took.digest as string, key: "takeover-1" });
    assert.ok(b.ok, JSON.stringify(b));
    return r.S;
  },

  /**
   * A resume after a prepare: in the first segment the report was
   * published and prepared on, two results were posted after it and one of
   * them resolved, and another seat objected to the report; the operator
   * stopped the run and resumed it. In the continuation the report was
   * published again, and the coordinator's prepare opened the new segment.
   * (A post of the continuation's made before its report is not late: that
   * rests on the files' times, which a checkout does not keep, so it is
   * held in tests/finish-prepare.test.ts, not here.)
   */
  "resume-carried": async (base) => {
    const r = await newRun(base, "rcd", 1);
    await established(r, "1");
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report v1\n\n## 1. Who logged on, and when?\n\nSee E-3.\n");
    const s1 = await FIN.prepareFinish(r.a0, { report: "work/report.md" });
    assert.ok(s1.ok && s1.mine, JSON.stringify(s1));
    await pause(30);
    await P.postMessage(r.a1, { tag: "result", body: "the first logon was remote" });
    const p2 = await P.postMessage(r.a2, { tag: "result", body: "a second account logged on too" });
    assert.ok((await FIN.resolveLate(r.a0, { post: p2.id, how: "folded", why: "section 1 names both accounts" })).ok);
    assert.ok((await FIN.ackReport(r.a3, { verdict: "objection", why: "section 1 misses the remote logon" })).ok);
    await P.markStopped(r.S, "operator", "swarm.sh stop");
    await writeFile(custodyAnchorPath(r.S), JSON.stringify({ run: "rcd", started_at: new Date().toISOString() }));
    const res = await prepareResume(r.S, { run: "rcd", by: "operator", minutes: 30 });
    assert.equal(res.ok, true, JSON.stringify(res));
    await pause(30);
    for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(r.S, a, "bash");
    await publish(r.S, "a0", "# Report v2\n\n## 1. Who logged on, and when?\n\nSee E-3; three logons.\n");
    const s2 = await FIN.prepareFinish(r.a0, { report: "work/report.md" });
    assert.ok(s2.ok && s2.mine && s2.generation === 2, JSON.stringify(s2));
    return r.S;
  },

  /**
   * A run sealed by custody, resumed, and sealed again: the first verdict
   * kept as custody.<time>.json, as a resume sets it aside, the second as
   * custody.json. The continuation revises question 2 from partial to
   * established on a new finding.
   */
  "resume-prefix": async (base) => {
    const r = await newRun(base, "rpx", 2);
    await established(r, "1");
    const p = await partial(r, "2");
    await attest(r.a3, {
      seq: p.a.seq,
      how: "re-read line 12 from job:j000002; no account field in the log",
      ...ESTABLISHED,
      answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when", established: true, why: "line 12" }, { id: "who", part: "which account", established: false, why: "the log keeps none", declared_open: `E-${p.lim.seq}` }] },
    });
    await SW.awaitSweeps(r.S);
    const first = await takeCustody(r.S, { runsDir: r.runs, readOnly: true });
    await writeFile(join(r.S, "custody.20260929T000000000Z.json"), `${JSON.stringify(first, null, 2)}\n`);
    // The continuation.
    const id = await lead(r.a0, "2", [{ source: "input:disk.E01", method: "read the disk's account records" }]);
    const f2 = (await rec(r.a0, { kind: "finding", ...F, value: "the logon at 09:14 was the second account", source: "the disk", evidence: "an account record", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
    const a2 = (await rec(r.a1, { kind: "answer", section: "question:2", value: "The second account, at 09:14", reasoning: `E-${p.f.seq} and E-${f2.seq}`, ...HIGH, result: "established", supersedes: p.a.seq })).entry;
    await attest(r.a2, { seq: a2.seq, how: "re-read the account record from job:j000001", ...ESTABLISHED });
    await close(r.a0, id, `E-${f2.seq}`);
    const second = await takeCustody(r.S, { runsDir: r.runs, readOnly: true });
    await writeFile(join(r.S, "custody.json"), `${JSON.stringify(second, null, 2)}\n`);
    return r.S;
  },

  /**
   * Three warnings and nothing else: a not-determinable answer whose
   * reviewed coverage names no acquisition ask and no reason for none; a
   * partial answer every review holds whole, attested established; an
   * established answer that leaves out a finding another seat attested
   * under its question's lead.
   */
  "warnings-only": async (base) => {
    const r = await newRun(base, "wno", 3);
    // Question 1: not determinable, no acquisition ask.
    const id1 = await lead(r.a0, "1", [{ source: "input:logs/a.log", method: "search the log" }]);
    const abs = (await rec(r.a0, { kind: "absence", value: "a logon", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const cov = (await rec(r.a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`, "job:j000002/hits.txt"]))).entry;
    await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of who logged on was found in the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" });
    await attest(r.a2, { seq: cov.seq, how: "ran the search again from job:j000002", review: REVIEW });
    await close(r.a0, id1, `E-${cov.seq}`);
    // Question 2: partial, every part held established, attested established.
    const id2 = await lead(r.a0, "2", [{ source: "input:disk.E01", method: "read the disk" }]);
    const f2 = (await rec(r.a0, { kind: "finding", ...F, value: "a remote tool's service entry", source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
    const a2 = (await rec(r.a1, { kind: "answer", section: "question:2", value: "A remote tool was installed as a service", reasoning: `E-${f2.seq}`, ...HIGH, result: "partial", parts: TOOL_PARTS(f2.seq, id2) })).entry;
    await attest(r.a3, { seq: a2.seq, how: "re-read the key from job:j000001", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: TOOL_PARTS_HELD } });
    await close(r.a0, id2, `E-${f2.seq}`);
    // Question 3: established, leaving out a finding another seat attested under its lead.
    const id3 = await lead(r.a0, "3", [{ source: "input:disk.E01", method: "read the disk" }]);
    assert.ok((await L.attachJob(r.S, "a0", "j000001", id3)).ok);
    const cited = (await rec(r.a0, { kind: "finding", ...F, value: "a folder was deleted", source: "the disk", evidence: "the journal", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
    const left = (await rec(r.a0, { kind: "finding", ...F, value: "a second folder was deleted", source: "the disk", evidence: "the journal", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
    for (const seq of [cited.seq, left.seq]) await attest(r.a3, { seq, how: "re-read the journal from job:j000001/hits.txt" });
    assert.ok((await L.recordInterpretations(r.S, "a0", left.seq, ["j000001"])).ok);
    await close(r.a0, id3, `E-${cited.seq}`);
    const a3 = (await rec(r.a1, { kind: "answer", section: "question:3", value: "A folder was deleted", reasoning: `E-${cited.seq}`, ...HIGH, result: "established" })).entry;
    await attest(r.a2, { seq: a3.seq, how: "re-derived the cited finding", ...ESTABLISHED });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * The three warnings, each where its decision is made: question 1's
   * not-determinable answer (no ask, no reason for none) at its record, in
   * its review's offer, delivered to the seat it went to, and in the reply
   * to that seat's review of its coverage; question 2's partial answer,
   * recorded with nothing to warn of, then attested established with every
   * part held, in the reply to that attest; question 3's established answer,
   * recorded after another seat attested a finding under its lead that it
   * leaves out, at its record and in the reply to its review, and again when
   * a later finding for it is attested.
   */
  "warnings-delivered": async (base) => {
    const r = await newRun(base, "wdl", 3);
    // Question 1.
    const id1 = await lead(r.a0, "1", [{ source: "input:logs/a.log", method: "search the log" }]);
    const abs = (await rec(r.a0, { kind: "absence", value: "a logon", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const cov = (await rec(r.a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`, "job:j000002/hits.txt"]))).entry;
    const a1 = (await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of who logged on was found in the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" })).entry;
    await close(r.a0, id1, `E-${cov.seq}`);
    assert.equal(await L.offerReviews(r.S), 1);
    const to = (await L.leadsSnapshot(r.S)).state.reviewOffers.get(`E-${a1.seq}`)![0]!.to;
    const seat = [r.a2, r.a3].find((c) => c.agentId === to)!;
    assert.match((await L.leadsDigest(seat, { mark: true })).text, /is offered to you for its review.*The finish line warns of this answer/);
    await attest(seat, { seq: cov.seq, how: "ran the search again from job:j000002", review: REVIEW });
    // Question 2.
    const id2 = await lead(r.a0, "2", [{ source: "input:disk.E01", method: "read the disk" }]);
    const f2 = (await rec(r.a0, { kind: "finding", ...F, value: "a remote tool's service entry", source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
    const a2 = (await rec(r.a1, { kind: "answer", section: "question:2", value: "A remote tool was installed as a service", reasoning: `E-${f2.seq}`, ...HIGH, result: "partial", parts: TOOL_PARTS(f2.seq, id2) })).entry;
    await close(r.a0, id2, `E-${f2.seq}`);
    await attest(r.a3, { seq: a2.seq, how: "re-read the key from job:j000001", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: TOOL_PARTS_HELD } });
    // Question 3.
    const id3 = await lead(r.a0, "3", [{ source: "input:disk.E01", method: "read the disk" }]);
    assert.ok((await L.attachJob(r.S, "a0", "j000001", id3)).ok);
    const cited = (await rec(r.a0, { kind: "finding", ...F, value: "a folder was deleted", source: "the disk", evidence: "the journal", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
    const left = (await rec(r.a0, { kind: "finding", ...F, value: "a second folder was deleted", source: "the disk", evidence: "the journal", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
    for (const seq of [cited.seq, left.seq]) await attest(r.a3, { seq, how: "re-read the journal from job:j000001/hits.txt" });
    assert.ok((await L.recordInterpretations(r.S, "a0", left.seq, ["j000001"])).ok);
    await close(r.a0, id3, `E-${cited.seq}`);
    const a3 = (await rec(r.a1, { kind: "answer", section: "question:3", value: "A folder was deleted", reasoning: `E-${cited.seq}`, ...HIGH, result: "established" })).entry;
    await attest(r.a2, { seq: a3.seq, how: "re-derived the cited finding", ...ESTABLISHED });
    const late = (await rec(r.a0, { kind: "finding", ...F, value: "a third folder was deleted", source: "the disk", evidence: "the journal", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
    await attest(r.a3, { seq: late.seq, how: "re-read the journal from job:j000001/hits.txt" });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * The run s993d40's second shape: a method established under another
   * question's lead. Question 2's lead holds three findings two seats hold:
   * one names question 1 too, one is linked by rel to the finding question
   * 1's answer cites, and one is tied to question 1 by nothing; and one
   * seat's finding naming question 1 too. Question 2's answer cites all
   * four. One seat's finding naming question 1 alone, which no answer
   * cites, stands beside them. Question 1's answer, recorded after them,
   * cites only its own finding.
   */
  "lead-findings-tied": async (base) => {
    const r = await newRun(base, "lft", 2);
    const id1 = await lead(r.a0, "1", [{ source: "input:disk.E01", method: "read the disk" }]);
    const m1 = (await rec(r.a0, { kind: "finding", ...F, value: "the first method", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
    await attest(r.a3, { seq: m1.seq, how: "re-read the record from job:j000001/hits.txt" });
    await close(r.a0, id1, `E-${m1.seq}`);
    const id2 = await lead(r.a2, "2", [{ source: "input:disk.E01", method: "read the disk" }]);
    assert.ok((await L.attachJob(r.S, "a2", "j000001", id2)).ok);
    const names = (await rec(r.a2, { kind: "finding", ...F, value: "the second method", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["2", "1"] })).entry;
    const linked = (await rec(r.a2, { kind: "finding", ...F, value: "the first method was run twice", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["2"], rel: [{ to: m1.seq, kind: "supports" }] })).entry;
    const apart = (await rec(r.a2, { kind: "finding", ...F, value: "the account used", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
    for (const seq of [names.seq, linked.seq, apart.seq]) {
      await attest(r.a3, { seq, how: "re-read the record from job:j000001/hits.txt" });
      assert.ok((await L.recordInterpretations(r.S, "a2", seq, ["j000001"])).ok);
    }
    const relied = (await rec(r.a2, { kind: "finding", ...F, value: "the third method", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["2", "1"] })).entry;
    assert.ok((await L.recordInterpretations(r.S, "a2", relied.seq, ["j000001"])).ok);
    await rec(r.a0, { kind: "finding", ...F, value: "a fourth method, seen once", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["1"] });
    await close(r.a2, id2, `E-${apart.seq}`);
    const a2 = (await rec(r.a1, { kind: "answer", section: "question:2", value: "The account, and three methods", reasoning: `E-${names.seq}, E-${linked.seq}, E-${relied.seq} and E-${apart.seq}`, ...HIGH, result: "established" })).entry;
    await attest(r.a3, { seq: a2.seq, how: "re-derived the cited findings", ...ESTABLISHED });
    const a1 = (await rec(r.a1, { kind: "answer", section: "question:1", value: "The first method", reasoning: `E-${m1.seq}`, ...HIGH, result: "established" })).entry;
    await attest(r.a2, { seq: a1.seq, how: "re-derived the cited finding", ...ESTABLISHED });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * A lead's close and a confirmation, each tying to the question an entry
   * its answer does not reach. Question 1 is answered on its first lead's
   * finding and reviewed. A second lead of question 1 is closed on a finding
   * two seats hold that names no question. A third is closed on one seat's
   * finding that names none (nothing changes); the finding is corrected,
   * another seat attests the correction, and the closer confirms the
   * closure on it.
   */
  "lead-close-delivered": async (base) => {
    const r = await newRun(base, "lcd", 1);
    await traceRow(r.S, "a0", "bash");
    const id1 = await lead(r.a0, "1", [{ source: "input:disk.E01", method: "read the disk" }]);
    const c = (await rec(r.a0, { kind: "finding", ...F, value: "the first method", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
    await attest(r.a3, { seq: c.seq, how: "re-read the record from job:j000001/hits.txt" });
    await close(r.a0, id1, `E-${c.seq}`);
    const a1 = (await rec(r.a1, { kind: "answer", section: "question:1", value: "The first method", reasoning: `E-${c.seq}`, ...HIGH, result: "established" })).entry;
    await attest(r.a2, { seq: a1.seq, how: "re-derived the cited finding", ...ESTABLISHED });
    const id2 = await lead(r.a2, "1", [{ source: "input:logs/a.log", method: "read the log" }]);
    const x = (await rec(r.a2, { kind: "finding", ...F, value: "the second method", source: "the log", evidence: "line 3", refs: ["job:j000002/hits.txt"] })).entry;
    await attest(r.a3, { seq: x.seq, how: "re-read line 3 from job:j000002/hits.txt" });
    await close(r.a2, id2, `E-${x.seq}`);
    const id3 = await lead(r.a0, "1", [{ source: "input:logs/a.log", method: "read the log again" }]);
    const w = (await rec(r.a0, { kind: "finding", ...F, value: "the third method, as first read", source: "the log", evidence: "line 9", refs: ["job:j000002/hits.txt"] })).entry;
    await close(r.a0, id3, `E-${w.seq}`);
    const w2 = (await rec(r.a0, { kind: "finding", ...F, value: "the third method, read again", source: "the log", evidence: "line 9 and its date", refs: ["job:j000002/hits.txt"], supersedes: w.seq, because: "the second read has the date" })).entry;
    await attest(r.a3, { seq: w2.seq, how: "re-read line 9 from job:j000002/hits.txt" });
    await L.reopenOnLedger(r.S);
    const lv = (await L.leadsSnapshot(r.S)).state.leads.get(id3)!;
    assert.ok(lv.confirm, "the closure waits for its closer");
    assert.ok((await L.confirmLead(r.a0, id3, { expected_revision: lv.rev, why: "the correction adds the date; the method is the same" })).ok);
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * Under the case policy's more_evidence: no, two not-determinable answers,
   * each resting on a coverage record another seat reviewed: question 1's
   * says why no ask in the policy's words, question 2's says nothing of an
   * ask. Nobody opens one.
   */
  /** The disk's broad extraction attempted: the absence negative and the one complete over the disk held, the plain one warned. */
  "preparation-pending": async (base) => {
    const r = await preparationNegatives(base, "ppd");
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /** Then the extraction failed, with why: nothing held, every negative over the disk warned. */
  "preparation-failed-released": async (base) => {
    const r = await preparationNegatives(base, "pfr");
    await diskReceipt(r.S, "failed", { why: "log2timeline and psort not on PATH in this job image" });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  "no-ceremonial-ask": async (base) => {
    const r = await newRun(base, "nca", 2);
    await mkdir(join(r.S, "network"), { recursive: true });
    await writeFile(join(r.S, "network", "policy.json"), `${JSON.stringify({ policy: "ctf", more_evidence: "no" })}\n`);
    for (const q of ["1", "2"]) {
      const id = await lead(r.a0, q, [{ source: "input:logs/a.log", method: "search the log" }]);
      const abs = (await rec(r.a0, { kind: "absence", value: `the event of question ${q}`, source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: [q] })).entry;
      const cov = (await rec(r.a0, coverage(q, ["input:logs/a.log"], [`E-${abs.seq}`, "job:j000002/hits.txt"], q === "1" ? { acquisition_none_why: P.NO_MORE_EVIDENCE_NONE_WHY } : {}))).entry;
      await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `No evidence of the event of question ${q} was found in the log`, reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" });
      await attest(r.a2, { seq: cov.seq, how: "ran the search again from job:j000002", review: REVIEW });
      await close(r.a0, id, `E-${cov.seq}`);
    }
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * Evidence added late, and the reverse sweep of its files for every
   * standing coverage record's looked_for strings. Question 1, a reviewed
   * bounded negative whose coverage looked for "alice": the addition stales
   * it and the sweep finds the string in the export; it is examined again,
   * the hit object read with its delta, reviewed, and recorded again
   * (cleared, nothing warned). Question 2, established, whose question's
   * coverage looked for "bob-laptop": not staled; the sweep's hit is
   * warned of at the record and the review of its answer written after the
   * addition, and in finish status, and holds nothing.
   */
  "late-evidence-hits": async (base) => {
    const r = await newRun(base, "leh", 2);
    const id1 = await lead(r.a0, "1", [{ source: "input:disk.E01", method: "search the disk" }]);
    const abs1 = (await rec(r.a0, { kind: "absence", value: "the event of question 1", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
    const cov1 = (await rec(r.a0, coverage("1", ["input:disk.E01"], [`E-${abs1.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"], acquisition_none_why: "no source outside the evidence records it" }))).entry;
    const ans1 = (await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of the event of question 1 was found on the disk", reasoning: `E-${cov1.seq}`, ...A, result: "bounded_negative" })).entry;
    await SW.awaitSweeps(r.S);
    await attest(r.a2, { seq: cov1.seq, how: "ran the search again from job:j000001", review: REVIEW });
    const id2 = await lead(r.a0, "2");
    const f2 = (await rec(r.a0, { kind: "finding", ...F, value: "a remote tool installed at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["2"] })).entry;
    const cov2 = (await rec(r.a0, coverage("2", ["input:logs/a.log"], [`E-${f2.seq}`, "job:j000002/hits.txt"], { looked_for: ["bob-laptop"], acquisition_none_why: "no source outside the evidence records it" }))).entry;
    const ans2 = (await rec(r.a1, { kind: "answer", section: "question:2", value: "A remote tool, installed at 09:14", reasoning: `E-${f2.seq}, searched as E-${cov2.seq}`, ...HIGH, result: "established" })).entry;
    await SW.awaitSweeps(r.S);
    await attest(r.a3, { seq: ans2.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED });
    await close(r.a0, id2, `E-${f2.seq}`);
    await addLate(r.S, "proxy.csv", "time,user,host\n09:58,alice,bob-laptop\n", "the proxy export the network team kept");
    // Question 1: the hit object read, with its delta, among the results of the coverage recorded again, reviewed; the answer recorded again.
    const d1 = (await rec(r.a0, { kind: "absence", value: "the event of question 1 in the proxy export: alice is a proxy user there, not the event", source: "the proxy export", evidence: "read whole", refs: ["import:ev-0001/proxy.csv"], answers: ["1"], rel: [{ to: ans1.seq, kind: "irrelevant" }] })).entry;
    const cov1b = (await rec(r.a0, coverage("1", ["input:disk.E01", "import:ev-0001/proxy.csv"], [`E-${abs1.seq}`, `E-${d1.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"], supersedes: cov1.seq, acquisition_none_why: "no source outside the evidence records it" }))).entry;
    await rec(r.a1, { kind: "answer", section: "question:1", value: "No evidence of the event of question 1 was found on the disk or in the proxy export", reasoning: `E-${cov1b.seq}`, ...A, result: "bounded_negative", supersedes: ans1.seq });
    await SW.awaitSweeps(r.S);
    await attest(r.a2, { seq: cov1b.seq, how: "ran the search again over the disk and the export", review: REVIEW, second_review_why: "the export is new" });
    await close(r.a0, id1, `E-${cov1b.seq}`);
    // Question 2: its answer recorded again, reworded, and reviewed again: the hit is said at each, and holds nothing.
    const ans2b = (await rec(r.a1, { kind: "answer", section: "question:2", value: "A remote tool, installed at 09:14, as the log shows", reasoning: `E-${f2.seq}, searched as E-${cov2.seq}`, ...HIGH, result: "established", supersedes: ans2.seq })).entry;
    await attest(r.a3, { seq: ans2b.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED });
    return r.S;
  },

  /**
   * A source-first review (docs/adr/0015): question 1 established, its one
   * review established with no discriminator and no locator or derivation
   * (recorded best_candidate, the reasons in capped); question 2
   * established, reviewed with a discriminator and a locator the hub finds
   * at its offset (established); question 3 established, reviewed first
   * with a locator one byte off (recorded best_candidate), then again at
   * the right offset by the same seat (established: its later review).
   */
  "review-source-first": async (base) => {
    const r = await newRun(base, "rsf", 3);
    const answer = async (q: string, ref: string) => {
      const id = await lead(r.a0, q);
      const f = (await rec(r.a0, { kind: "finding", ...F, value: `the record question ${q} asks for`, source: "the log", evidence: "line 1", refs: [ref], answers: [q] })).entry;
      // The answer states the value its reviews locate (the job's record, as the job wrote it): a locator vouches for what the answer says.
      const a = (await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `Established: the record question ${q} asks for, ${ref.slice("job:".length, ref.indexOf("/"))}`, reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
      await close(r.a0, id, `E-${f.seq}`);
      return a;
    };
    const a1 = await answer("1", "job:j000001/hits.txt");
    await attest(r.a2, { seq: a1.seq, how: "re-read the record from job:j000001", strength: "established", answer_review: REVIEWED });
    const a2 = await answer("2", "job:j000002/hits.txt");
    await attest(r.a3, { seq: a2.seq, how: "re-read the record from job:j000002", strength: "established", answer_review: { ...REVIEWED, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000002/hits.txt", offset: 0, value: "j000002" }] } });
    const a3 = await answer("3", "job:j000001/hits.txt");
    await attest(r.a2, { seq: a3.seq, how: "re-read the record from job:j000001", strength: "established", answer_review: { ...REVIEWED, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000001/hits.txt", offset: 1, value: "j000001" }] } });
    await attest(r.a2, { seq: a3.seq, how: "re-read the record from job:j000001, at its offset", strength: "established", answer_review: { ...REVIEWED, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref: "job:j000001/hits.txt", offset: 0, value: "j000001" }] } });
    return r.S;
  },


  /**
   * A part at the limit of the evidence (docs/adr/0013, amended): two answers
   * each hold "which account" limited, by a limitation that says the
   * directory's log was not retained, and each is recorded partial: a limited
   * part never lifts the label. Question 1's bound no other seat has
   * reviewed; question 2's a seat that wrote neither it nor the answer
   * reviewed as a negative is reviewed. Each answer's review agrees the part
   * is at the limit (at_limit). Both stand partial; nothing holds.
   */
  "limited-part-partial": async (base) => {
    const r = await newRun(base, "lpp", 2);
    for (const q of ["1", "2"]) {
      const id = await lead(r.a0, q);
      const f = (await rec(r.a0, { kind: "finding", ...F, value: `a logon at 09:14 for question ${q}`, source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: [q] })).entry;
      const lim = (await rec(r.a0, { kind: "limitation", value: `The log keeps no account name for question ${q}, and the directory's own log was not retained`, source: "the log", evidence: "its field list; the retention setting", reason: "unavailable", answers: [q] })).entry;
      const a = (await rec(r.a1, { kind: "answer", section: `question:${q}`, value: "A logon at 09:14 from the office host; which account is at the limit of the evidence", reasoning: `E-${f.seq}; E-${lim.seq}`, ...A, result: "partial", parts: [{ id: "when", part: "when the logon happened", status: "established", refs: [`E-${f.seq}`] }, { id: "who", part: "which account logged on", status: "limited", limited_by: `E-${lim.seq}` }] })).entry;
      await close(r.a0, id, `E-${f.seq}`);
      if (q === "2") await attest(r.a3, { seq: lim.seq, how: "checked the retention setting and the directory", review: REVIEW });
      await attest(r.a2, { seq: a.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when the logon happened", established: true, why: "line 12" }, { id: "who", part: "which account logged on", established: false, at_limit: true, why: "the log keeps none, and the directory's log is gone" }] } });
    }
    return r.S;
  },

  /**
   * A locator is not coverage (docs/adr/0013): two established answers whose
   * reviews locate the value in a job's output over an input. Question 1's
   * first review is recorded best_candidate (rival_area_uncovered); then a
   * coverage record for it names the disk, says every area searched or not
   * applicable and cites the job over the disk, and the same seat's later
   * review stands established. Question 2's log no coverage record covers:
   * its review stays a best candidate.
   */
  "rival-area-uncovered": async (base) => {
    const r = await newRun(base, "rau", 2);
    const answer = async (q: string, ref: string) => {
      const id = await lead(r.a0, q);
      const f = (await rec(r.a0, { kind: "finding", ...F, value: `the record question ${q} asks for`, source: "the evidence", evidence: "line 1", refs: [ref], answers: [q] })).entry;
      const a = (await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `Established: the record question ${q} asks for, ${ref.slice("job:".length, ref.indexOf("/"))}`, reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
      await close(r.a0, id, `E-${f.seq}`);
      return a;
    };
    const located = (ref: string, inference: string) => ({ ...REVIEWED, inference, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref, offset: 0, value: ref.slice("job:".length, ref.indexOf("/")) }] });
    const a1 = await answer("1", "job:j000001/hits.txt");
    const first = await P.attestEntry(r.a2, { seq: a1.seq, how: "re-read the record from job:j000001", strength: "established", answer_review: located("job:j000001/hits.txt", "the record is the answer") } as unknown as P.LedgerActInput);
    assert.ok(first.ok && first.line?.strength === "best_candidate" && first.line.capped?.some((x) => /a locator is not coverage/.test(x)), JSON.stringify(first));
    await rec(r.a0, coverage("1", ["input:disk.E01"], ["job:j000001/hits.txt"], { areas: { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "not_applicable" } }));
    const later = await P.attestEntry(r.a2, { seq: a1.seq, how: "re-read the record, and the disk's other areas", strength: "established", answer_review: located("job:j000001/hits.txt", "the record is the answer, and the disk's other areas hold no other") } as unknown as P.LedgerActInput);
    assert.ok(later.ok && later.line?.strength === "established", JSON.stringify(later));
    const a2 = await answer("2", "job:j000002/hits.txt");
    const held = await P.attestEntry(r.a3, { seq: a2.seq, how: "re-read the record from job:j000002", strength: "established", answer_review: located("job:j000002/hits.txt", "the record is the answer") } as unknown as P.LedgerActInput);
    assert.ok(held.ok && held.line?.strength === "best_candidate", JSON.stringify(held));
    return r.S;
  },

  /**
   * A given (docs/adr/0011, "Premises"): the goal's premise, seeded as P-1
   * at the kickoff, assumed by both questions' established answers. It is
   * not proved again and holds nothing.
   */
  "premise-given": async (base) => {
    const r = await newRun(base, "pgv", 2, [], [LAPTOP_PREMISE]);
    await Q.seedRegister(r.S);
    await citing(r, "1", "the employee's account logged on at 09:14", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    await citing(r, "2", "a remote tool was installed as a service", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    return r.S;
  },

  /**
   * A proposition under test, later admitted: a seat proposes P-1 (the
   * laptop's clock kept UTC); question 1's answer assumes it only
   * conditionally ("assuming P-1"); the operator admits it as a given; then
   * question 2's answer assumes it outright.
   */
  "premise-admitted": async (base) => {
    const r = await newRun(base, "pad", 2);
    await Q.seedRegister(r.S);
    const proposed = await Q.premisePropose(r.a0, { text: "The laptop's clock kept UTC for the whole examined period", locator: "input:logs/a.log, its header line", why: "every time the answers give is read off that clock" });
    assert.ok(proposed.ok && proposed.p === "P-1", JSON.stringify(proposed));
    await citing(r, "1", "the employee's account logged on at 09:14 UTC", [{ id: "P-1", rev: 1, stance: "assumed", conditional: true }]);
    await operatorAct(r.S, "premise_admit", { p: "P-1", as: "given", why: "the lab's intake notes record the clock on UTC" });
    await citing(r, "2", "a remote tool was installed as a service at 10:02 UTC", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    return r.S;
  },

  /**
   * Two scopes that do not conflict: question 1's answer assumes P-1 for
   * January to March; question 2's answer contradicts it for July to
   * December, on a finding (the laptop was reissued in July), which takes
   * the premise to the operator as a dispute. The two scopes never meet:
   * nothing holds, and nothing is warned.
   */
  "premise-scopes": async (base) => {
    const r = await newRun(base, "psc", 2, [], [LAPTOP_PREMISE]);
    await Q.seedRegister(r.S);
    await citing(r, "1", "the employee's account logged on on 2024-02-12", [{ id: "P-1", rev: 1, stance: "assumed", scope: { times: [{ from: "2024-01-01", to: "2024-03-31" }] } }]);
    const f2 = (await rec(r.a0, { kind: "finding", ...F, value: "the laptop was reissued to a contractor on 2024-07-01", source: "the disk", evidence: "the asset tag's history", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
    await citing(r, "2", "the remote tool was installed on 2024-08-03, after the laptop was reissued", [{ id: "P-1", rev: 1, stance: "contradicted", refs: [`E-${f2}`], scope: { times: [{ from: "2024-07-01", to: "2024-12-31" }] } }], { finding: f2 });
    return r.S;
  },

  /**
   * A contradiction on the record: question 1's answer assumes P-1;
   * question 2's contradicts it over the same scope and names no finding
   * that rebuts it. Both questions are held (premise_inconsistent): neither
   * side is forced, and the fix says the four ways out.
   */
  "premise-held": async (base) => {
    const r = await newRun(base, "phd", 2, [], [LAPTOP_PREMISE]);
    await Q.seedRegister(r.S);
    await citing(r, "1", "the employee's account logged on at 09:14", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    await citing(r, "2", "the remote tool was installed from a second user's session", [{ id: "P-1", rev: 1, stance: "contradicted" }]);
    return r.S;
  },

  /**
   * The same contradiction, reconciled without forcing either answer: a
   * custody seal is taken while it holds; then question 2's answer is
   * recorded again naming the finding that rebuts P-1, which takes the
   * premise to the operator as a dispute (a request of kind premise).
   * Question 1's answer still assumes P-1, and is warned
   * (premise_disputed); nothing holds, and the earlier seal verifies as a
   * prefix.
   */
  "premise-rebutted": async (base) => {
    const r = await newRun(base, "prb", 2, [], [LAPTOP_PREMISE]);
    await Q.seedRegister(r.S);
    await citing(r, "1", "the employee's account logged on at 09:14", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    const q2 = await citing(r, "2", "the remote tool was installed from a second user's session", [{ id: "P-1", rev: 1, stance: "contradicted" }]);
    await SW.awaitSweeps(r.S);
    const seal = await takeCustody(r.S, { runsDir: r.runs, readOnly: true });
    await writeFile(join(r.S, "custody.20260929T120000000Z.json"), `${JSON.stringify(seal, null, 2)}\n`);
    const second = (await rec(r.a0, { kind: "finding", ...F, value: "a second user's profile on the laptop, created 2024-05-02", source: "the disk", evidence: "the profile list", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
    const again = (await rec(r.a1, { kind: "answer", section: "question:2", value: "Established: the remote tool was installed from a second user's session", reasoning: `E-${q2.f}, and E-${second} shows the second user`, ...HIGH, result: "established", premises: [{ id: "P-1", rev: 1, stance: "contradicted", refs: [`E-${second}`] }], supersedes: q2.a })).entry;
    await attest(r.a2, { seq: again.seq, how: "re-read the profile list from job:j000001", ...ESTABLISHED });
    return r.S;
  },

  /**
   * The same contradiction, reconciled by a conditional answer: question
   * 1's answer is recorded again assuming P-1 only conditionally
   * ("assuming P-1"). Nothing holds, nothing is warned; both stand.
   */
  "premise-conditional": async (base) => {
    const r = await newRun(base, "pcd", 2, [], [LAPTOP_PREMISE]);
    await Q.seedRegister(r.S);
    const q1 = await citing(r, "1", "the employee's account logged on at 09:14", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    await citing(r, "2", "the remote tool was installed from a second user's session", [{ id: "P-1", rev: 1, stance: "contradicted" }]);
    const again = (await rec(r.a1, { kind: "answer", section: "question:1", value: "Established, assuming P-1: the employee's account logged on at 09:14", reasoning: `E-${q1.f}`, ...HIGH, result: "established", premises: [{ id: "P-1", rev: 1, stance: "assumed", conditional: true }], supersedes: q1.a })).entry;
    await attest(r.a2, { seq: again.seq, how: "re-read the key from job:j000001", ...ESTABLISHED });
    return r.S;
  },

  /**
   * Only a part the question asks is open (docs/adr/0013, "Claim and
   * open-part rows"; the c10 run s704e4b): question 1's partial answer
   * establishes who logged on and when, and holds open which terminal the
   * session used, which the question does not ask; its review holds the two
   * parts established and marks the third not asked. Question 2's partial
   * answer holds open the account, which the question asks; its review
   * holds that part open, as the answer declares it.
   */
  "parts-not-asked": async (base) => {
    const r = await newRun(base, "pna", 2);
    const id1 = await lead(r.a0, "1");
    const f1 = (await rec(r.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const lim1 = (await rec(r.a0, { kind: "limitation", value: "The log keeps no other session detail", source: "the log", evidence: "its field list", reason: "unavailable", answers: ["1"] })).entry;
    const a1 = (await rec(r.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14; the terminal is not established", reasoning: `E-${f1.seq}; the terminal is open (E-${lim1.seq})`, ...A, limitations: [lim1.seq], result: "partial", parts: [{ id: "who", part: "who logged on", status: "established", refs: [`E-${f1.seq}`] }, { id: "when", part: "when", status: "established", refs: [`E-${f1.seq}`] }, { id: "tty", part: "which terminal the session used", status: "open", open_by: `E-${lim1.seq}` }] })).entry;
    await close(r.a0, id1, `E-${f1.seq}`);
    await attest(r.a3, { seq: a1.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "who", part: "who logged on", established: true, why: "line 12 names alice" }, { id: "when", part: "when", established: true, why: "line 12's time" }, { id: "tty", part: "which terminal the session used", established: false, why: "the question asks who logged on and when, not the terminal", not_asked: true }] } });
    const p = await partial(r, "2");
    await attest(r.a3, { seq: p.a.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when the logon happened", established: true, why: "line 12" }, { id: "who", part: "which account logged on", established: false, why: "the log keeps none" }] } });
    return r.S;
  },

  /**
   * A question's premise, tested first (docs/adr/0011, "What a question
   * presumes"): the goal says question 1 presumes someone logged on. Its
   * established answer is attested established by another seat on a
   * source-first review that tests no premise: recorded best_candidate,
   * capped. Question 2 presumes nothing, and its established answer stands.
   */
  "premise-untested-capped": async (base) => {
    const r = await newRun(base, "puc", 2, [], [], ["1: Someone logged on to the host."]);
    await Q.seedRegister(r.S);
    await established(r, "2");
    const id = await lead(r.a0, "1", [{ source: "input:disk.E01", method: "read the disk" }]);
    const f = (await rec(r.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the disk", evidence: "a logon record", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
    const a = (await rec(r.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
    await close(r.a0, id, `E-${f.seq}`);
    const got = await P.attestEntry(r.a2, { seq: a.seq, how: "re-read the logon record from job:j000001", ...ESTABLISHED } as unknown as P.LedgerActInput);
    assert.ok(got.ok && got.line?.strength === "best_candidate" && got.line.capped?.some((x) => /presumes/.test(x)), JSON.stringify(got));
    return r.S;
  },

  /**
   * The same premise on a partial answer (docs/adr/0011, "What a question
   * presumes"): question 1's partial answer, and its review, test no
   * premise: warned (premise_untested) at the answer's record, the reply to
   * its attest and finish status, never held. Question 2 presumes nothing.
   */
  "premise-untested-warned": async (base) => {
    const r = await newRun(base, "puw", 2, [], [], ["1: Someone logged on to the host."]);
    await Q.seedRegister(r.S);
    await established(r, "2");
    const p = await partial(r, "1");
    await attest(r.a3, { seq: p.a.seq, how: "re-read line 12 from job:j000002; no account field in the log", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when the logon happened", established: true, why: "line 12" }, { id: "who", part: "which account logged on", established: false, why: "the log keeps none" }] } });
    return r.S;
  },

  /**
   * The premise tested and found unsupported (docs/adr/0011, "What a
   * question presumes"): question 1 presumes someone logged on; a finding
   * shows every logon in the log's range failed; the answer tests the
   * premise on it and records premise_not_supported, and another seat's
   * review tests it too. Disposed; question 2 established.
   */
  "premise-tested-not-supported": async (base) => {
    const r = await newRun(base, "pns", 2, [], [], ["1: Someone logged on to the host."]);
    await Q.seedRegister(r.S);
    await established(r, "2");
    const id = await lead(r.a0, "1");
    const f = (await rec(r.a0, { kind: "finding", ...F, value: "every logon attempt in the log's range failed; none succeeded", source: "the log", evidence: "lines 1 to 40", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const a = (await rec(r.a1, { kind: "answer", section: "question:1", value: "The question's premise is not supported: nobody logged on to the host in the log's range", reasoning: `E-${f.seq}`, ...HIGH, result: "premise_not_supported", premise_tested: { outcome: "every logon attempt in the log's whole range failed", refs: [`E-${f.seq}`] } })).entry;
    await close(r.a0, id, `E-${f.seq}`);
    await attest(r.a2, { seq: a.seq, how: "re-read the log from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, premise_tested: { outcome: "the log holds only failed attempts over its whole range", refs: ["job:j000002/hits.txt"] } } });
    return r.S;
  },

  /**
   * The operator's acceptance excuses what it excuses in every reader
   * (docs/adr/0011, "Premises"; the Fable review of the limits branch,
   * P1-1): P-1, a given; question 1's answer assumes it and question 2's
   * contradicts it with no rebutting finding, both held
   * (premise_inconsistent); question 3's partial answer has no critic act.
   * The operator accepts all three questions' limits.
   */
  "accepted-excused": async (base) => {
    const r = await newRun(base, "aex", 3, [], [LAPTOP_PREMISE]);
    await Q.seedRegister(r.S);
    await citing(r, "1", "the employee's account logged on at 09:14", [{ id: "P-1", rev: 1, stance: "assumed" }]);
    await citing(r, "2", "the remote tool was installed from a second user's session", [{ id: "P-1", rev: 1, stance: "contradicted" }]);
    await partial(r, "3");
    await SW.awaitSweeps(r.S);
    await operatorAct(r.S, "accept", { q: "Q-1", as: "bounded", why: "the brief's premise and the second session are for the client to weigh; the examination went as far as the disk allows", expected_rev: 1 });
    await operatorAct(r.S, "accept", { q: "Q-2", as: "bounded", why: "the brief's premise and the second session are for the client to weigh; the examination went as far as the disk allows", expected_rev: 1 });
    await operatorAct(r.S, "accept", { q: "Q-3", as: "bounded", why: "the log keeps no account names; nobody else is free to review it before the deadline", expected_rev: 1 });
    return r.S;
  },

  /**
   * An acceptance never excuses the negative bar (docs/adr/0013): question
   * 1's not-determinable answer rests on a reviewed coverage record; the
   * operator accepts its limits; then the search's result is corrected, so
   * the coverage record no longer says what its search found
   * (coverage_stale). Question 2 is established.
   */
  "accepted-negative-held": async (base) => {
    const r = await newRun(base, "anh", 2);
    await Q.seedRegister(r.S);
    await established(r, "2");
    const lid = await lead(r.a0, "1", [{ source: "input:logs/a.log", method: "search the log" }]);
    const abs = (await rec(r.a0, { kind: "absence", value: "an account name for the logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const cov = (await rec(r.a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`, "job:j000002/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
    await rec(r.a1, { kind: "answer", section: "question:1", value: "Who logged on cannot be determined from the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" });
    await attest(r.a2, { seq: cov.seq, how: "ran the search again from job:j000002", review: REVIEW });
    await close(r.a0, lid, `E-${cov.seq}`);
    await SW.awaitSweeps(r.S);
    await operatorAct(r.S, "accept", { q: "Q-1", as: "not_determinable", why: "the log keeps no account names", expected_rev: 1 });
    await rec(r.a0, { kind: "absence", value: "an account name for the logon, searched again in every encoding", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["1"], supersedes: abs.seq });
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /**
   * Claim and open-part rows (docs/adr/0013): question 1's established
   * answer carries two parts; its review weighs both and names a third the
   * question asks that the answer leaves out (missing), which allows only
   * best_candidate: the question is held as a best candidate, and the
   * omitted part stays visible (part_omitted). Question 2's partial answer
   * names its open part by the limitation that bounds it; its review holds
   * that part open, as the answer declares it: disposed partial.
   */
  "parts-omitted": async (base) => {
    const r = await newRun(base, "pom", 2);
    const id1 = await lead(r.a0, "1", [{ source: "input:logs/a.log", method: "read the logons" }]);
    const f1 = (await rec(r.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const a1 = (await rec(r.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f1.seq}`, ...HIGH, result: "established", parts: [{ id: "who", part: "who logged on", status: "established", refs: [`E-${f1.seq}`] }, { id: "when", part: "when", status: "established", refs: [`E-${f1.seq}`] }] })).entry;
    await close(r.a0, id1, `E-${f1.seq}`);
    const omitted = { ...ESTABLISHED.answer_review, parts: [{ id: "who", part: "who logged on", established: true, why: "line 12 names alice" }, { id: "when", part: "when", established: true, why: "line 12's time" }, { part: "from which host", established: false, why: "the question asks where from; the log's line 12 has a source address the answer does not give", missing: true }] };
    const refusedEstablished = await P.attestEntry(r.a2, { seq: a1.seq, how: "re-read line 12 from job:j000002", strength: "established", answer_review: omitted });
    assert.ok(!refusedEstablished.ok, "a part the answer leaves out allows only best_candidate");
    await attest(r.a2, { seq: a1.seq, how: "re-read line 12 from job:j000002", strength: "best_candidate", answer_review: omitted });
    const p = await partial(r, "2");
    await attest(r.a3, { seq: p.a.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when the logon happened", established: true, why: "line 12" }, { id: "who", part: "which account logged on", established: false, why: "the log keeps none" }] } });
    return r.S;
  },
};

/**
 * Question 1 partial on a finding, the part it leaves open bounded by a
 * limitation, reviewed by another seat that holds that part open as the
 * answer declares it (partial-every-policy's review): a disposition under the
 * ordinary bar.
 */
async function reviewedPartial(r: Run): Promise<void> {
  const p = await partial(r, "1");
  await attest(r.a3, {
    seq: p.a.seq,
    how: "re-read line 12 from job:j000002; no account field in the log",
    ...ESTABLISHED,
    answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when the logon happened", established: true, why: "line 12" }, { id: "who", part: "which account logged on", established: false, why: "the log keeps none", declared_open: `E-${p.lim.seq}` }] },
  });
}

/**
 * A question that must be established (docs/adr/0013): the Breadcrumbs run
 * ended a flag-only challenge on a partial answer, a disposition under the
 * ordinary bar. These histories are the rule's contract.
 */
const MUST_ESTABLISH_CASES: Record<string, (base: string) => Promise<string>> = {
  /** The goal's Must establish section names question 1; its answer is partial on a reviewed finding; question 2 is established. */
  "must-establish-partial": async (base) => {
    const r = await newRun(base, "mep", 2, [], [], [], ["1"]);
    await Q.seedRegister(r.S);
    await established(r, "2");
    await reviewedPartial(r);
    return r.S;
  },

  /** The operator requires question 1 to be established (amend --must-establish); its answer is not determinable on a coverage record another seat reviewed; question 2 is established. */
  "must-establish-not-determinable": async (base) => {
    const r = await newRun(base, "mnd", 2);
    await Q.seedRegister(r.S);
    await established(r, "2");
    await operatorAct(r.S, "amend", { q: "Q-1", expected_rev: 1, must_establish: true, why: "the account is what the client needs" });
    const lid = await lead(r.a0, "1", [{ source: "input:logs/a.log", method: "search the log" }]);
    const abs = (await rec(r.a0, { kind: "absence", value: "an account name for the logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
    const cov = (await rec(r.a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`, "job:j000002/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
    await rec(r.a1, { kind: "answer", section: "question:1", value: "Who logged on cannot be determined from the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" });
    await attest(r.a2, { seq: cov.seq, how: "ran the search again from job:j000002", review: REVIEW });
    await close(r.a0, lid, `E-${cov.seq}`);
    await SW.awaitSweeps(r.S);
    return r.S;
  },

  /** The operator requires question 1 to be established after its partial answer was reviewed, then accepts its limits for that revision and answer; question 2 is established. */
  "must-establish-accepted": async (base) => {
    const r = await newRun(base, "mea", 2);
    await Q.seedRegister(r.S);
    await established(r, "2");
    await reviewedPartial(r);
    await operatorAct(r.S, "amend", { q: "Q-1", expected_rev: 1, must_establish: true, why: "the account is what the client needs" });
    await SW.awaitSweeps(r.S);
    await operatorAct(r.S, "accept", { q: "Q-1", as: "bounded", why: "the log keeps no account names, and no other source is in the case", expected_rev: 1 });
    return r.S;
  },

  /** The goal requires question 1; its answer is partial on a reviewed finding; the operator releases the requirement, with why. Question 2 is established. */
  "must-establish-released": async (base) => {
    const r = await newRun(base, "mer", 2, [], [], [], ["1"]);
    await Q.seedRegister(r.S);
    await established(r, "2");
    await reviewedPartial(r);
    await SW.awaitSweeps(r.S);
    await operatorAct(r.S, "amend", { q: "Q-1", expected_rev: 1, must_establish: false, why: "the client takes what the log holds" });
    return r.S;
  },

  /** The goal requires question 1, and it is established on a finding another seat attests established; question 2 too. */
  "must-establish-established": async (base) => {
    const r = await newRun(base, "mes", 2, [], [], [], ["1"]);
    await Q.seedRegister(r.S);
    await established(r, "1");
    await established(r, "2");
    return r.S;
  },
};
Object.assign(CASES, MUST_ESTABLISH_CASES);

// ---------------------------------------------------------------------------------------------
// Writing the fixture
// ---------------------------------------------------------------------------------------------

/** What a run keeps that is not its history: locks, spills, the kickoff's leftovers. */
const DROP = new Set(["locks"]);

/** Prunes `dir` of what DROP names, links, locks and logs, and of empty directories; true when anything is left. */
async function prune(dir: string): Promise<boolean> {
  let kept = false;
  for (const d of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, d.name);
    if (d.isDirectory()) {
      if (DROP.has(d.name)) await rm(p, { recursive: true, force: true });
      else if (await prune(p)) kept = true;
      else await rmdir(p);
    } else if (d.isSymbolicLink() || d.name.endsWith(".lock") || d.name.endsWith(".log")) await rm(p, { force: true });
    else kept = true;
  }
  return kept;
}

async function writeCase(name: string, build: (base: string) => Promise<string>): Promise<void> {
  const base = await mkdtemp(join(tmpdir(), `contract-${name}-`));
  try {
    const S = await build(base);
    const dest = join(HERE, name, "run");
    await rm(dest, { recursive: true, force: true });
    await mkdir(join(HERE, name), { recursive: true });
    spawnSync("chmod", ["-R", "u+w", S]);
    await rename(S, dest).catch(async () => {
      const cp = spawnSync("cp", ["-Rp", S, dest]);
      assert.equal(cp.status, 0, String(cp.stderr));
    });
    await prune(dest);
    // A history is relocatable: nothing in it names where it was made.
    const leaks = spawnSync("grep", ["-rl", base, dest], { encoding: "utf8" }).stdout.trim();
    assert.equal(leaks, "", `${name}: these files name the directory the run was made in: ${leaks}`);
    const bytes = spawnSync("du", ["-sk", dest], { encoding: "utf8" }).stdout.split("\t")[0];
    process.stdout.write(`${name}: ${bytes} KiB${existsSync(join(HERE, name, "expect.json")) ? "" : " (no expect.json yet: write it from the ADRs)"}\n`);
  } finally {
    spawnSync("chmod", ["-R", "u+w", base]);
    await rm(base, { recursive: true, force: true });
  }
}

const wanted = process.argv.slice(2);
for (const [name, build] of Object.entries(CASES)) {
  if (wanted.length && !wanted.includes(name)) continue;
  await writeCase(name, build);
}
