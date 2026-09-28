/**
 * Score a finished run of a calibration case against the case's truth.
 *
 *   node --experimental-strip-types scripts/calibrate.ts <run-dir> --truth FILE
 *     [--out FILE] [--late auto|added|absent] [--json]
 *
 * The truth is what calibration/generate.py wrote, and it stays outside the
 * repository and every run: a truth file inside the run or inside a dfirswarm
 * checkout is refused, and so is an output there. The output defaults to
 * `<truth dir>/<case>.<run id>.score.json`; the table goes to the terminal.
 *
 * What is read is the run's register, never a tool's output: the ledger's
 * `answer` entries (one per `question:<n>`, the standing one), the entries
 * they cite, the attestations, the lead register and the operator requests,
 * and, when they exist, the question register (`questions/questions.jsonl`)
 * and the Plan 3 fields (`result` on an answer, `coverage` records). Where an
 * answer carries no `result`, its class is read from its structure (what it
 * cites, `inconclusive`) and, before that, its headline's wording; the JSON
 * says which (`result_source`).
 *
 * What is measured, per case:
 * - the miss rate on facts known to be present (the hard ones apart), with
 *   the facts the ledger holds but the answer does not;
 * - false "not found": a question whose answer is in the evidence answered
 *   with a negative;
 * - the forced-answer rate on questions the evidence cannot answer (absent,
 *   and missing before the late item arrives): an established answer, or a
 *   decoy adopted;
 * - decoy adoption: a planted near miss in an answer's headline that matches
 *   none of the question's own facts;
 * - unsupported negatives: a negative answer without coverage (a coverage
 *   record, or today a complete absence or a limitation it cites) or without
 *   another seat's attestation;
 * - acquisition: a missing question answered with a request for the evidence
 *   that would settle it;
 * - the late item: whether the run was given it (by digest), and whether the
 *   answer it settles moved;
 * - confidence calibration: accuracy per recorded confidence and a Brier score
 *   (high 0.9, medium 0.7, low 0.4). The recorded confidence is the run's
 *   (protocol.ts recordedConfidence: high only on an established answer
 *   another seat attested established naming the alternatives it weighed);
 *   the stated one is kept beside it.
 *
 * Exit 0 when scored; 2 on a usage error or a refusal.
 */
import { existsSync, statSync } from "node:fs";
import { mkdir, readdir, readFile, realpath, rename, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { type LedgerAttestation, type LedgerEntry, recordedConfidence, verifyLedgerChain } from "../extensions/protocol.ts";
import { patternOf } from "./score.ts";

export const TRUTH_FORMAT = "dfirswarm-calibration-truth/1";
export const RESULTS = ["established", "partial", "bounded_negative", "not_determinable", "out_of_scope", "premise_not_supported"] as const;
export type ResultClass = (typeof RESULTS)[number];
const NEGATIVE: ReadonlySet<string> = new Set(["bounded_negative", "not_determinable", "premise_not_supported"]);
const ASSERTED: ReadonlySet<string> = new Set(["established", "partial"]);
/** The probability a stated confidence stands for, for the Brier score. */
export const CONFIDENCE_P: Record<string, number> = { high: 0.9, medium: 0.7, low: 0.4 };

export type Expected = { result: ResultClass; accept_results: ResultClass[]; summary?: string };
export type TruthFact = { id: string; category: string; summary: string; subkind?: string; where?: string; accept?: string[] };
export type TruthQuestion = {
  id: string;
  text: string;
  scored: boolean;
  kind: "present" | "absent" | "missing";
  expected: Expected;
  facts: TruthFact[];
  acquisition?: { accept: string[] };
  late?: { item: string; expected: Expected; facts: TruthFact[] };
};
export type Truth = {
  format: string;
  case: { id: string; title?: string; dir?: string };
  inputs: Array<{ path: string; sha256: string; bytes?: number }>;
  late: Array<{ id: string; path: string; sha256: string; questions?: string[] }>;
  questions: TruthQuestion[];
};

type Rec = Record<string, unknown>;

export type Where = "answer" | "cited" | "ledger" | "none";
export type FactScore = { id: string; category: string; subkind?: string; summary: string; found: boolean; where: Where; entries: number[] };
export type DecoyScore = { id: string; summary: string; in_value: boolean; in_answer: boolean; adopted: boolean };
export type AnswerView = {
  seq: number;
  section: string;
  by: string;
  value: string;
  reasoning: string;
  /** The confidence the run records (recordedConfidence), which the calibration scores. */
  confidence: string | null;
  /** The confidence its author stated, and why the run records another when it does. */
  stated_confidence: string | null;
  confidence_why?: string;
  result: ResultClass;
  result_source: "field" | "register" | "structure" | "wording" | "default";
  cited: number[];
  entry: Rec;
};
export type QuestionScore = {
  id: string;
  kind: "present" | "absent" | "missing";
  scored_as: "present" | "absent" | "missing";
  scored: boolean;
  text: string;
  late_applies: boolean;
  expected: Expected;
  answer: AnswerView | null;
  class_ok: boolean | null;
  facts: FactScore[];
  decoys: DecoyScore[];
  false_negative: boolean | null;
  forced: boolean | null;
  acquisition: { requested: boolean; gap_named: boolean; where: string[] } | null;
  negative_support: { covered: boolean; complete: boolean | null; reviewed: boolean; reviewers: string[]; by: string[] } | null;
  correct: boolean | null;
  verdict: string;
};
export type ScoreReport = {
  format: "dfirswarm-calibration-score/1";
  case: string;
  run: string;
  run_dir: string;
  truth: string;
  scored_at: string;
  ledger: { entries: number; chain_ok: boolean; chain_reason: string | null; answers: number; coverage_model: "wp2" | "absence" };
  inputs_match: { expected: number; matched: number; run_files: number };
  late: Array<{ id: string; added: boolean; how: string }>;
  questions: QuestionScore[];
  summary: {
    present_facts: { total: number; found: number; missed: number; missed_in_ledger: number; miss_rate: number | null };
    hard_facts: { total: number; found: number; missed: number; miss_rate: number | null; by_subkind: Record<string, { total: number; found: number }> };
    false_negatives: { questions: number; answered_negative: number; rate: number | null };
    forced: { questions: number; forced: number; rate: number | null };
    decoys: { total: number; adopted: number; mentioned: number; rate: number | null };
    negatives: { total: number; without_coverage: number; without_review: number; unsupported: number; rate: number | null };
    acquisition: { questions: number; requested: number; gap_named: number };
    late: { questions: number; reflected: number };
    unanswered: number;
    /** By the recorded confidence; `stated_high_lowered`: answers stated high that the run records medium. */
    calibration: { levels: Record<string, { n: number; correct: number }>; brier: number | null; overconfident: number; stated_high_lowered: number };
  };
  notes: string[];
};

// --- where things may live -------------------------------------------------------------------

/** A dfirswarm checkout, of any version: the kickoff script and the extensions beside it. */
function isCheckout(dir: string): boolean {
  try {
    return statSync(join(dir, "scripts", "swarm.sh")).isFile() && statSync(join(dir, "extensions")).isDirectory();
  } catch {
    return false;
  }
}

/** The nearest existing ancestor, resolved through links, with the rest appended. */
async function realish(p: string): Promise<string> {
  let cur = resolve(p);
  const tail: string[] = [];
  while (!existsSync(cur) && dirname(cur) !== cur) {
    tail.unshift(basename(cur));
    cur = dirname(cur);
  }
  return join(await realpath(cur), ...tail);
}

function within(child: string, parent: string): boolean {
  const r = relative(parent, child);
  return r === "" || (!r.startsWith("..") && !r.startsWith(sep) && !/^[A-Za-z]:/.test(r));
}

function checkoutAbove(p: string): string | null {
  let cur = p;
  for (;;) {
    if (isCheckout(cur)) return cur;
    const up = dirname(cur);
    if (up === cur) return null;
    cur = up;
  }
}

/** Why a truth or an output path may not be used, or null. */
export async function placeProblem(path: string, runDir: string, what: "truth" | "output"): Promise<string | null> {
  const p = await realish(path);
  const run = await realish(runDir);
  if (within(p, run)) return `the ${what} ${path} is inside the run ${runDir}; the truth, and anything derived from it, stays outside every run`;
  const own = await realish(join(dirname(fileURLToPath(import.meta.url)), ".."));
  const repo = isCheckout(own) && within(p, own) ? own : checkoutAbove(p);
  if (repo) return `the ${what} ${path} is inside the dfirswarm checkout ${repo}; the truth, and anything derived from it, stays outside the repository`;
  return null;
}

// --- reading the run -------------------------------------------------------------------------

async function jsonl(path: string): Promise<Rec[]> {
  const text = await readFile(path, "utf8").catch(() => "");
  const out: Rec[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const v = JSON.parse(line) as unknown;
      if (v && typeof v === "object" && !Array.isArray(v)) out.push(v as Rec);
    } catch {
      // a torn line is skipped; the chain check says whether the ledger holds
    }
  }
  return out;
}

const str = (v: unknown): string => (typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v));
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** A section or question id as the goal numbers it: "question:3", "Q-3", "q3" and "3" are 3. */
export function questionKey(raw: unknown): string {
  return str(raw).trim().replace(/^question:/i, "").replace(/^q-?(?=\d)/i, "");
}

/** Aliases a result may be written in, before and after Plan 3. */
export function normaliseResult(raw: unknown): ResultClass | null {
  const s = str(raw).trim().toLowerCase().replace(/[\s-]+/g, "_");
  const alias: Record<string, ResultClass> = {
    partially_established: "partial",
    inconclusive: "not_determinable",
    insufficient_evidence: "not_determinable",
    not_determined: "not_determinable",
    limited: "not_determinable",
    bounded: "bounded_negative",
    negative: "bounded_negative",
    not_established: "bounded_negative",
    premise_not_supported: "premise_not_supported",
  };
  if ((RESULTS as readonly string[]).includes(s)) return s as ResultClass;
  return alias[s] ?? null;
}

const CUE_PREMISE = /\bpremise\b|\bnot supported by (?:the )?evidence\b|\bevidence does not support\b/i;
const CUE_UNDETERMINED =
  /\b(?:cannot|can ?not|could not|can't|couldn't) be (?:determined|established|answered|identified|confirmed|recovered)\b|\bnot (?:determinable|determined|established|identifiable|answerable)\b|\bundetermined\b|\bindeterminate\b|\binsufficient evidence\b|\bnot in the (?:collected |available )?evidence\b|\b(?:was|were) not (?:collected|provided|available)\b/i;
const CUE_NEGATIVE =
  /\bno evidence\b|\bnot found\b|\bno (?:sign|trace|indication|record)s? of\b|\bnothing (?:was )?found\b|\bno (?:[\w-]+ ){1,3}(?:was|were) (?:found|seen|recorded|identified)\b|\bno successful\b|\bdid not (?:happen|occur|log in)\b/i;

/** An answer's result class: its own field, the register, its wording, then what it cites. */
export function resultOf(entry: Rec, cited: Rec[], register: ResultClass | null): { result: ResultClass; source: AnswerView["result_source"] } {
  const field = normaliseResult(entry.result);
  if (field) return { result: field, source: "field" };
  if (register) return { result: register, source: "register" };
  if (entry.inconclusive === true) return { result: "not_determinable", source: "structure" };
  const headline = str(entry.value);
  if (CUE_PREMISE.test(headline)) return { result: "premise_not_supported", source: "wording" };
  if (CUE_UNDETERMINED.test(headline)) return { result: "not_determinable", source: "wording" };
  if (CUE_NEGATIVE.test(headline)) return { result: "bounded_negative", source: "wording" };
  const kinds = new Set(cited.map((e) => str(e.kind)));
  const limits = Array.isArray(entry.limitations) && entry.limitations.length > 0;
  const positive = ["finding", "event", "ioc"].some((k) => kinds.has(k));
  if (positive) return { result: limits || kinds.has("limitation") ? "partial" : "established", source: "structure" };
  if (kinds.has("absence") || kinds.has("coverage")) return { result: "bounded_negative", source: "structure" };
  if (kinds.has("limitation") || limits) return { result: "not_determinable", source: "structure" };
  return { result: "established", source: "default" };
}

/** The seqs an answer cites: its support, contrary and limitation edges, and every E-<seq> in its text. */
export function citedSeqs(entry: Rec): number[] {
  const out = new Set<number>();
  for (const k of ["support", "limitations", "contrary"]) {
    const edges = entry[k];
    if (Array.isArray(edges)) for (const e of edges) if (e && typeof e === "object" && num((e as Rec).seq) !== null) out.add((e as Rec).seq as number);
  }
  const text = `${str(entry.value)}\n${str(entry.reasoning)}`;
  for (const m of text.matchAll(/\bE-(\d{1,6})(?:\s*[–-]\s*E-?(\d{1,6}))?\b/g)) {
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    if (b >= a && b - a <= 50) for (let n = a; n <= b; n += 1) out.add(n);
    else out.add(a);
  }
  return [...out].filter((n) => n > 0).sort((x, y) => x - y);
}

function entryText(e: Rec): string {
  return ["value", "source", "evidence", "indicates", "significance", "reasoning", "because", "proposition"].map((k) => str(e[k])).filter(Boolean).join("\n");
}

function matches(patterns: string[] | undefined, text: string): boolean {
  for (const p of patterns ?? []) {
    try {
      if (patternOf(p).test(text)) return true;
    } catch {
      // a pattern that does not read matches nothing; the truth's own check should have caught it
    }
  }
  return false;
}

/**
 * The last disposition the question register gives each question, when there
 * is a register (extensions/questions.ts). The harness writes a `dispose`
 * event whenever a question's standing changes, its `decided` holding the
 * answer's result and, once the operator accepted the question, what it was
 * accepted as; an `accept` event carries the operator's `act.as` (bounded or
 * not_determinable). A disposition the register withdrew (its answer
 * superseded or gone) clears the question. Goal questions are `Q-n`, which
 * is `question:n`.
 */
async function registerResults(runDir: string): Promise<Map<string, ResultClass>> {
  const out = new Map<string, ResultClass>();
  for (const r of await jsonl(join(runDir, "questions", "questions.jsonl"))) {
    const id = questionKey(r.q ?? r.id ?? r.question);
    if (!/^\d+$/.test(id)) continue;
    const decided = r.decided && typeof r.decided === "object" ? (r.decided as Rec) : null;
    const act = r.act && typeof r.act === "object" ? (r.act as Rec) : null;
    if (r.ev === "dispose" && decided) {
      const res = normaliseResult(decided.result) ?? normaliseResult(decided.accepted);
      if (res) out.set(id, res);
      else out.delete(id);
      continue;
    }
    if (r.ev === "accept" && act) {
      const res = normaliseResult(act.as);
      if (res) out.set(id, res);
      continue;
    }
    const disp = r.disposition && typeof r.disposition === "object" ? (r.disposition as Rec) : null;
    const res = normaliseResult(r.result) ?? normaliseResult(disp?.result) ?? normaliseResult(r.as) ?? normaliseResult(r.accepted_as) ?? (typeof r.disposition === "string" ? normaliseResult(r.disposition) : null);
    if (res) out.set(id, res);
  }
  return out;
}

async function filesUnder(dir: string, depth = 4): Promise<string[]> {
  if (depth < 0) return [];
  const ents = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const out: string[] = [];
  for (const e of ents) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await filesUnder(p, depth - 1)));
    else if (e.isFile() && /\.(json|jsonl)$/.test(e.name)) out.push(p);
  }
  return out;
}

/**
 * Whether the run holds each late item, by its digest: first as evidence
 * added after the kickoff (the store journal's evidence_added lines, which
 * `swarm.sh evidence add` writes with every file's sha256, its import and
 * its acquisition request), then in the manifest (a second set given at
 * kickoff) or any other inventory record.
 */
async function lateAdded(runDir: string, truth: Truth, mode: "auto" | "added" | "absent"): Promise<Array<{ id: string; added: boolean; how: string }>> {
  if (mode !== "auto") return truth.late.map((l) => ({ id: l.id, added: mode === "added", how: `--late ${mode}` }));
  const added = new Map<string, string>();
  for (const l of await jsonl(join(runDir, "store", "journal.jsonl"))) {
    if (l.type !== "evidence_added" || !Array.isArray(l.files)) continue;
    for (const f of l.files as Rec[]) {
      const sha = str(f.sha256);
      if (/^[0-9a-f]{64}$/.test(sha) && !added.has(sha)) added.set(sha, `evidence added as import:${str(l.import)}/${str(f.path)} (inventory revision ${str(l.inventory_rev) || "?"}${l.request ? `, for ${str(l.request)}` : ""})`);
    }
  }
  const places = [join(runDir, "inputs.json"), join(runDir, "store", "journal.jsonl")];
  for (const d of ["inventory", "evidence", "acquisitions", "requests"]) places.push(...(await filesUnder(join(runDir, d))));
  const texts: Array<{ where: string; text: string }> = [];
  for (const p of places) {
    const t = await readFile(p, "utf8").catch(() => null);
    if (t !== null) texts.push({ where: relative(runDir, p), text: t });
  }
  return truth.late.map((l) => {
    const by = added.get(l.sha256);
    if (by) return { id: l.id, added: true, how: `its sha256 is ${by}` };
    const hit = texts.find((t) => t.text.includes(l.sha256));
    return { id: l.id, added: Boolean(hit), how: hit ? `its sha256 is in ${hit.where}` : "its sha256 is in no manifest or inventory record of the run" };
  });
}

type Request = { text: string; questions: string[]; where: string };

/** What the swarm asked of the operator: requests, leads closed needs_operator, acquisition asks. */
async function operatorRequests(runDir: string): Promise<Request[]> {
  const out: Request[] = [];
  const leads = await jsonl(join(runDir, "leads", "leads.jsonl"));
  const answersOf = new Map<string, string[]>();
  for (const ev of leads) {
    const id = str(ev.lead);
    if (ev.ev === "open" && Array.isArray(ev.answers)) answersOf.set(id, (ev.answers as unknown[]).map(questionKey));
  }
  for (const ev of leads) {
    if (ev.ev === "close" && ev.disposition === "needs_operator") {
      out.push({ text: `${str(ev.title)}\n${str(ev.ref)}`, questions: answersOf.get(str(ev.lead)) ?? [], where: `leads ${str(ev.lead)}` });
    }
  }
  // The requests' chain (requests/requests.jsonl) is rendered into operator-requests.jsonl, one line per request: read once.
  const files = [join(runDir, "operator-requests.jsonl"), ...(await filesUnder(join(runDir, "requests"))).filter((f) => !f.endsWith(join("requests", "requests.jsonl"))), ...(await filesUnder(join(runDir, "operator")))];
  for (const f of files) {
    for (const r of await jsonl(f)) {
      const ask = r.ask && typeof r.ask === "object" ? (r.ask as Rec) : {};
      const qs = [r.questions, ask.questions, r.answers].flatMap((v) => (Array.isArray(v) ? v.map(questionKey) : []));
      const lead = str(r.lead);
      out.push({ text: JSON.stringify(r), questions: qs.length ? qs : (answersOf.get(lead) ?? []), where: `${relative(runDir, f)}${lead ? ` ${lead}` : ""}` });
    }
  }
  return out;
}

// --- scoring ---------------------------------------------------------------------------------

export async function scoreRun(runDirArg: string, truth: Truth, opts: { truthPath?: string; late?: "auto" | "added" | "absent" } = {}): Promise<ScoreReport> {
  const runDir = resolve(runDirArg);
  const notes: string[] = [];
  const ledgerText = await readFile(join(runDir, "ledger", "entries.jsonl"), "utf8").catch(() => "");
  const chain = verifyLedgerChain(ledgerText);
  if (!ledgerText) notes.push("the run has no ledger/entries.jsonl: every question is unanswered");
  else if (!chain.ok) notes.push(`the ledger's chain does not verify (${chain.reason ?? "broken"} at line ${chain.broken_at}); scored as written`);
  const entries = await jsonl(join(runDir, "ledger", "entries.jsonl"));
  const bySeq = new Map<number, Rec>();
  for (const e of entries) if (num(e.seq) !== null) bySeq.set(e.seq as number, e);
  const superseded = new Set<number>();
  for (const e of entries) if (num(e.supersedes) !== null) superseded.add(e.supersedes as number);
  const standing = entries.filter((e) => num(e.seq) !== null && !superseded.has(e.seq as number));
  const coverageModel: "wp2" | "absence" = entries.some((e) => e.kind === "coverage") ? "wp2" : "absence";
  const attests = (await jsonl(join(runDir, "ledger", "attestations.jsonl"))).filter((a) => a.v === 2 && a.act === "attest");
  const register = await registerResults(runDir);
  const requests = await operatorRequests(runDir);
  const late = await lateAdded(runDir, truth, opts.late ?? "auto");
  const lateById = new Map(late.map((l) => [truth.late.find((x) => x.id === l.id)?.path ?? l.id, l.added]));

  let manifest: { files?: Array<{ sha256?: string }> } = {};
  try {
    manifest = JSON.parse((await readFile(join(runDir, "inputs.json"), "utf8").catch(() => "")) || "{}") as typeof manifest;
  } catch {
    notes.push("the run's inputs.json does not parse; the inputs were not matched to the case");
  }
  const runDigests = new Set((manifest.files ?? []).map((f) => f.sha256).filter(Boolean));
  const matched = truth.inputs.filter((f) => runDigests.has(f.sha256)).length;
  if (runDigests.size && !matched) notes.push("none of the run's inputs has a digest the truth lists: this run was not given this case's evidence");

  const answers = entries.filter((e) => e.kind === "answer");
  const answerFor = (qid: string): Rec | null => {
    const mine = answers.filter((e) => questionKey(e.section) === qid && !superseded.has(e.seq as number));
    if (!mine.length) return null;
    return mine.reduce((a, b) => ((a.seq as number) > (b.seq as number) ? a : b));
  };

  const questions: QuestionScore[] = [];
  for (const q of truth.questions) {
    const lateApplies = Boolean(q.late && lateById.get(q.late.item));
    const scoredAs: QuestionScore["scored_as"] = lateApplies ? "present" : q.kind;
    const expected = lateApplies && q.late ? q.late.expected : q.expected;
    const e = answerFor(q.id);
    let answer: AnswerView | null = null;
    let cited: Rec[] = [];
    if (e) {
      const seqs = citedSeqs(e);
      cited = seqs.map((n) => bySeq.get(n)).filter((x): x is Rec => Boolean(x));
      const r = resultOf(e, cited, register.get(q.id) ?? null);
      const conf = str(e.confidence).toLowerCase();
      const stated = conf && conf in CONFIDENCE_P ? conf : null;
      const rc = recordedConfidence({ ...(e as unknown as LedgerEntry), confidence: (stated ?? undefined) as LedgerEntry["confidence"], authors: Array.isArray(e.authors) ? (e.authors as string[]) : [str(e.by)] }, attests as unknown as LedgerAttestation[]);
      answer = {
        seq: e.seq as number, section: str(e.section), by: str(e.by), value: str(e.value), reasoning: str(e.reasoning),
        confidence: rc.recorded, stated_confidence: stated, ...(rc.why ? { confidence_why: rc.why } : {}), result: r.result, result_source: r.source, cited: seqs, entry: e,
      };
    }
    const answerText = answer ? `${answer.value}\n${answer.reasoning}` : "";
    const citedText = cited.map(entryText).join("\n");
    const own = [...q.facts.filter((f) => f.category === "present" || f.category === "hard_present"), ...(lateApplies && q.late ? q.late.facts : [])];
    const facts: FactScore[] = own.map((f) => {
      const inLedger = standing.filter((x) => x.kind !== "answer" && matches(f.accept, entryText(x))).map((x) => x.seq as number);
      const where: Where = matches(f.accept, answerText) ? "answer" : matches(f.accept, citedText) ? "cited" : inLedger.length ? "ledger" : "none";
      return { id: f.id, category: f.category, ...(f.subkind ? { subkind: f.subkind } : {}), summary: f.summary, found: where === "answer" || where === "cited", where, entries: inLedger };
    });
    const ownPatterns = own.flatMap((f) => f.accept ?? []);
    const decoys: DecoyScore[] = q.facts.filter((f) => f.category === "decoy").map((f) => {
      const inValue = answer ? matches(f.accept, answer.value) : false;
      const inAnswer = answer ? matches(f.accept, answerText) : false;
      const adopted = Boolean(answer) && inValue && (scoredAs === "present" ? !matches(ownPatterns, answer!.value) : ASSERTED.has(answer!.result));
      return { id: f.id, summary: f.summary, in_value: inValue, in_answer: inAnswer, adopted };
    });
    const adopted = decoys.some((d) => d.adopted);
    const classOk = answer ? expected.accept_results.includes(answer.result) : null;
    const negative = answer ? NEGATIVE.has(answer.result) : false;
    const falseNegative = scoredAs === "present" && answer ? negative : null;
    const forced = scoredAs !== "present" && answer ? answer.result === "established" || adopted : scoredAs !== "present" ? false : null;

    let acquisition: QuestionScore["acquisition"] = null;
    if (q.kind === "missing" && !lateApplies) {
      const pats = q.acquisition?.accept ?? [];
      const hits = requests.filter((r) => r.questions.includes(q.id) || (pats.length > 0 && matches(pats, r.text) && r.questions.length === 0));
      const gap = standing.filter((x) => x.kind === "limitation" && (Array.isArray(x.answers) ? (x.answers as unknown[]).map(questionKey).includes(q.id) : false) && (!pats.length || matches(pats, entryText(x))));
      acquisition = { requested: hits.length > 0, gap_named: gap.length > 0 || (answer ? matches(pats, answerText) : false), where: [...hits.map((h) => h.where), ...gap.map((g) => `ledger E-${g.seq}`)] };
    }

    let support: QuestionScore["negative_support"] = null;
    if (answer && negative) {
      const covering = cited.filter((c) => {
        if (coverageModel === "wp2") return c.kind === "coverage" || (c.kind === "absence" && (c.coverage !== undefined || c.proposition !== undefined));
        if (answer!.result === "not_determinable") return c.kind === "absence" || c.kind === "limitation";
        return c.kind === "absence" && c.completion === "complete";
      });
      const ownCoverage = answer.entry.coverage !== undefined && answer.entry.coverage !== null;
      const complete = coverageModel === "wp2"
        ? covering.length || ownCoverage ? [...covering.map((c) => c.coverage), answer.entry.coverage].some((v) => v === "complete" || (v && typeof v === "object" && (v as Rec).coverage === "complete")) : null
        : null;
      const authors = new Set([answer.by, ...((Array.isArray(answer.entry.authors) ? answer.entry.authors : []) as string[])]);
      const reviewed = attests.filter((a) => [answer!.seq, ...covering.map((c) => c.seq as number)].includes(a.seq as number) && !authors.has(str(a.by)));
      support = { covered: covering.length > 0 || ownCoverage, complete, reviewed: reviewed.length > 0, reviewers: [...new Set(reviewed.map((a) => str(a.by)))], by: covering.map((c) => `E-${c.seq}`) };
    }

    let correct: boolean | null = null;
    let verdict = "unanswered";
    if (!q.scored) verdict = "not scored";
    else if (answer) {
      if (scoredAs === "present") {
        const all = facts.every((f) => f.found);
        const some = facts.some((f) => f.found);
        correct = Boolean(classOk) && all && !adopted;
        verdict = negative ? "false negative" : adopted ? "decoy adopted" : all ? (classOk ? "found" : "found, wrong class") : some ? "partly missed" : "missed";
      } else {
        correct = Boolean(classOk) && !forced;
        verdict = forced ? (adopted ? "decoy adopted" : "forced") : classOk ? "held" : "wrong class";
      }
    }
    questions.push({
      id: q.id, kind: q.kind, scored_as: scoredAs, scored: q.scored, text: q.text, late_applies: lateApplies, expected, answer,
      class_ok: classOk, facts, decoys, false_negative: q.scored ? falseNegative : null, forced: q.scored ? forced : null,
      acquisition: q.scored ? acquisition : null, negative_support: support, correct: q.scored ? correct : null, verdict,
    });
  }

  const scored = questions.filter((q) => q.scored);
  const facts = scored.flatMap((q) => q.facts);
  const hard = facts.filter((f) => f.category === "hard_present");
  const bySub: Record<string, { total: number; found: number }> = {};
  for (const f of hard) {
    const k = f.subkind ?? "other";
    bySub[k] ??= { total: 0, found: 0 };
    bySub[k].total += 1;
    if (f.found) bySub[k].found += 1;
  }
  const rate = (a: number, b: number): number | null => (b ? Math.round((a / b) * 1000) / 1000 : null);
  const presentQs = scored.filter((q) => q.scored_as === "present");
  const heldQs = scored.filter((q) => q.scored_as !== "present");
  const decoys = scored.flatMap((q) => q.decoys);
  const negs = scored.filter((q) => q.negative_support);
  const levels: Record<string, { n: number; correct: number }> = {};
  let brierSum = 0;
  let brierN = 0;
  let overconfident = 0;
  for (const q of scored) {
    if (!q.answer || q.correct === null) continue;
    const level = q.answer.confidence ?? "none";
    levels[level] ??= { n: 0, correct: 0 };
    levels[level].n += 1;
    if (q.correct) levels[level].correct += 1;
    if (q.answer.confidence) {
      brierSum += (CONFIDENCE_P[q.answer.confidence] - (q.correct ? 1 : 0)) ** 2;
      brierN += 1;
      if (q.answer.confidence === "high" && !q.correct) overconfident += 1;
    }
  }
  const missingQs = scored.filter((q) => q.acquisition);
  const lateQs = scored.filter((q) => q.late_applies);
  const summary: ScoreReport["summary"] = {
    present_facts: { total: facts.length, found: facts.filter((f) => f.found).length, missed: facts.filter((f) => !f.found).length, missed_in_ledger: facts.filter((f) => f.where === "ledger").length, miss_rate: rate(facts.filter((f) => !f.found).length, facts.length) },
    hard_facts: { total: hard.length, found: hard.filter((f) => f.found).length, missed: hard.filter((f) => !f.found).length, miss_rate: rate(hard.filter((f) => !f.found).length, hard.length), by_subkind: bySub },
    false_negatives: { questions: presentQs.length, answered_negative: presentQs.filter((q) => q.false_negative).length, rate: rate(presentQs.filter((q) => q.false_negative).length, presentQs.length) },
    forced: { questions: heldQs.length, forced: heldQs.filter((q) => q.forced).length, rate: rate(heldQs.filter((q) => q.forced).length, heldQs.length) },
    decoys: { total: decoys.length, adopted: decoys.filter((d) => d.adopted).length, mentioned: decoys.filter((d) => d.in_answer && !d.adopted).length, rate: rate(decoys.filter((d) => d.adopted).length, decoys.length) },
    negatives: {
      total: negs.length,
      without_coverage: negs.filter((q) => !q.negative_support!.covered).length,
      without_review: negs.filter((q) => !q.negative_support!.reviewed).length,
      unsupported: negs.filter((q) => !q.negative_support!.covered || !q.negative_support!.reviewed).length,
      rate: rate(negs.filter((q) => !q.negative_support!.covered || !q.negative_support!.reviewed).length, negs.length),
    },
    acquisition: { questions: missingQs.length, requested: missingQs.filter((q) => q.acquisition!.requested).length, gap_named: missingQs.filter((q) => q.acquisition!.gap_named).length },
    late: { questions: lateQs.length, reflected: lateQs.filter((q) => q.correct).length },
    unanswered: scored.filter((q) => !q.answer).length,
    calibration: { levels, brier: brierN ? Math.round((brierSum / brierN) * 1000) / 1000 : null, overconfident, stated_high_lowered: scored.filter((q) => q.answer?.stated_confidence === "high" && q.answer.confidence !== "high").length },
  };
  return {
    format: "dfirswarm-calibration-score/1",
    case: truth.case.id,
    run: basename(runDir),
    run_dir: runDir,
    truth: opts.truthPath ? resolve(opts.truthPath) : "",
    scored_at: new Date().toISOString(),
    ledger: { entries: entries.length, chain_ok: chain.ok, chain_reason: chain.reason, answers: answers.length, coverage_model: coverageModel },
    inputs_match: { expected: truth.inputs.length, matched, run_files: runDigests.size },
    late,
    questions,
    summary,
    notes,
  };
}

// --- the table -------------------------------------------------------------------------------

function pct(r: number | null): string {
  return r === null ? "-" : `${(r * 100).toFixed(1)}%`;
}

function table(rows: string[][]): string[] {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]))).join("  ").trimEnd());
}

export function scoreText(r: ScoreReport, outPath?: string): string {
  const lines: string[] = [`Calibration: ${r.case}, run ${r.run}`];
  for (const l of r.late) lines.push(`Late item ${l.id}: ${l.added ? "added" : "not added"} (${l.how})`);
  lines.push("");
  const rows: string[][] = [["Q", "kind", "expected", "answer", "facts", "decoy", "conf", "verdict"]];
  for (const q of r.questions) {
    const facts = q.facts.length ? `${q.facts.filter((f) => f.found).length}/${q.facts.length}` : "-";
    const decoy = q.decoys.length ? (q.decoys.some((d) => d.adopted) ? "ADOPTED" : q.decoys.some((d) => d.in_answer) ? "mentioned" : "no") : "-";
    const got = q.answer ? `${q.answer.result} (${q.answer.result_source}, E-${q.answer.seq})` : "none";
    rows.push([q.id, q.scored_as === q.kind ? q.kind : `${q.kind}>${q.scored_as}`, q.expected.result, got, facts, decoy, q.answer?.confidence ?? "-", q.verdict]);
  }
  lines.push(...table(rows));
  const detail: string[] = [];
  for (const q of r.questions) {
    for (const f of q.facts.filter((x) => !x.found)) {
      detail.push(`  Q${q.id} ${f.id} ${f.category}${f.subkind ? `/${f.subkind}` : ""}: missed${f.where === "ledger" ? ` (the ledger has it: ${f.entries.map((n) => `E-${n}`).join(", ")}; the answer does not)` : ""}`);
    }
    for (const d of q.decoys.filter((x) => x.adopted)) detail.push(`  Q${q.id} ${d.id} decoy adopted in the answer's headline`);
    if (q.negative_support && (!q.negative_support.covered || !q.negative_support.reviewed)) {
      detail.push(`  Q${q.id} negative ${[!q.negative_support.covered ? "without coverage" : "", !q.negative_support.reviewed ? "without another seat's attestation" : ""].filter(Boolean).join(" and ")}`);
    }
    if (q.acquisition) detail.push(`  Q${q.id} missing evidence: ${q.acquisition.requested ? `requested (${q.acquisition.where.join(", ")})` : "no request to the operator"}${q.acquisition.gap_named ? "; the gap is named" : ""}`);
  }
  if (detail.length) lines.push("", ...detail);
  const s = r.summary;
  lines.push(
    "",
    `Hard present facts:   ${s.hard_facts.found} of ${s.hard_facts.total} found, miss rate ${pct(s.hard_facts.miss_rate)} (${Object.entries(s.hard_facts.by_subkind).map(([k, v]) => `${k} ${v.found}/${v.total}`).join(", ") || "none"})`,
    `All present facts:    ${s.present_facts.found} of ${s.present_facts.total} found, miss rate ${pct(s.present_facts.miss_rate)}; ${s.present_facts.missed_in_ledger} in the ledger but not in the answer`,
    `False "not found":    ${s.false_negatives.answered_negative} of ${s.false_negatives.questions} answerable questions answered with a negative (${pct(s.false_negatives.rate)})`,
    `Forced answers:       ${s.forced.forced} of ${s.forced.questions} unanswerable questions (${pct(s.forced.rate)})`,
    `Decoys adopted:       ${s.decoys.adopted} of ${s.decoys.total} (${pct(s.decoys.rate)}); ${s.decoys.mentioned} mentioned and not adopted`,
    `Negatives:            ${s.negatives.total}; ${s.negatives.without_coverage} without coverage, ${s.negatives.without_review} without review, ${s.negatives.unsupported} unsupported (${pct(s.negatives.rate)}; coverage read as ${r.ledger.coverage_model === "wp2" ? "coverage records" : "a complete absence or a limitation cited"})`,
    `Acquisition:          ${s.acquisition.requested} of ${s.acquisition.questions} missing-evidence questions requested the evidence; ${s.acquisition.gap_named} named the gap`,
    `Late item:            ${s.late.questions ? `${s.late.reflected} of ${s.late.questions} questions it settles answered as it settles them` : "not added: those questions are scored as missing evidence"}`,
    `Unanswered:           ${s.unanswered}`,
    `Confidence (recorded): ${Object.entries(s.calibration.levels).map(([k, v]) => `${k} ${v.correct}/${v.n}`).join(", ") || "none stated"}; Brier ${s.calibration.brier ?? "-"}; ${s.calibration.overconfident} wrong at high confidence; ${s.calibration.stated_high_lowered} stated high and recorded medium`,
  );
  if (r.inputs_match.run_files && r.inputs_match.matched < r.inputs_match.expected) lines.push(`Inputs:               ${r.inputs_match.matched} of the case's ${r.inputs_match.expected} files are in the run's manifest`);
  if (r.notes.length) lines.push("", ...r.notes.map((n) => `Note: ${n}`));
  if (outPath) lines.push("", `Written: ${outPath}`);
  return `${lines.join("\n")}\n`;
}

// --- the command -----------------------------------------------------------------------------

export function parseTruth(text: string): Truth {
  const t = JSON.parse(text) as Truth;
  if (!t || t.format !== TRUTH_FORMAT) throw new Error(`not a calibration truth file (format ${JSON.stringify((t as Partial<Truth>)?.format)}; expected ${TRUTH_FORMAT})`);
  if (!Array.isArray(t.questions) || !t.case?.id) throw new Error("the truth file has no case or no questions");
  t.late ??= [];
  t.inputs ??= [];
  return t;
}

async function main(argv: string[]): Promise<number> {
  const opt = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const truthPath = opt("--truth");
  const outArg = opt("--out");
  const lateArg = opt("--late") ?? "auto";
  const valued = new Set(["--truth", "--out", "--late"]);
  const runDir = argv.find((a, k) => !a.startsWith("--") && !valued.has(argv[k - 1] ?? ""));
  if (!runDir || !truthPath || !["auto", "added", "absent"].includes(lateArg)) {
    process.stderr.write("usage: calibrate.ts <run-dir> --truth FILE [--out FILE] [--late auto|added|absent] [--json]\n");
    return 2;
  }
  if (!existsSync(runDir) || !statSync(runDir).isDirectory()) {
    process.stderr.write(`calibrate.ts: ${runDir} is not a run directory\n`);
    return 2;
  }
  const truthProblem = await placeProblem(truthPath, runDir, "truth");
  if (truthProblem) {
    process.stderr.write(`calibrate.ts: refused: ${truthProblem}\n`);
    return 2;
  }
  let truth: Truth;
  try {
    truth = parseTruth(await readFile(truthPath, "utf8"));
  } catch (err) {
    process.stderr.write(`calibrate.ts: ${(err as Error).message}\n`);
    return 2;
  }
  const out = outArg ?? join(dirname(resolve(truthPath)), `${truth.case.id}.${basename(resolve(runDir))}.score.json`);
  const outProblem = await placeProblem(out, runDir, "output");
  if (outProblem) {
    process.stderr.write(`calibrate.ts: refused: ${outProblem}\n`);
    return 2;
  }
  const report = await scoreRun(runDir, truth, { truthPath, late: lateArg as "auto" | "added" | "absent" });
  await mkdir(dirname(resolve(out)), { recursive: true });
  const tmp = `${resolve(out)}.tmp-${process.pid}`;
  await writeFile(tmp, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, resolve(out));
  process.stdout.write(argv.includes("--json") ? `${JSON.stringify(report, null, 2)}\n` : scoreText(report, resolve(out)));
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(await main(process.argv.slice(2)));
}
