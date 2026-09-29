#!/usr/bin/env node
/**
 * Replay: a finished run's registers read again by a given harness's finish
 * machinery, to measure a rule change on recorded histories (docs/adr/0017,
 * "Measuring a rule change").
 *
 *   node --experimental-strip-types scripts/replay.ts <run-dir | run-id> [--registry FILE]
 *        [--checkout PATH] [--compare [A [B]]] [--stop-policy P[,P…]] [--json] [--show-text]
 *   swarm.sh replay <run> [--checkout PATH] [--compare [A [B]]] [--stop-policy P] [--json]
 *
 * The run is never written. Its directory is copied to a temporary one (a
 * clone where the file system makes one, APFS or a reflink), less what no
 * projection reads: the evidence (`inputs/`, whose hashes `inputs.json`
 * keeps), the VMs' records and images, the seats' Pi sessions and the
 * kickoff's options; a link inside the copy is removed, never followed. The
 * run's registers are hashed before and after, and a change is an error.
 * One copy per checkout and stop policy, so what one evaluation writes (the
 * finish gate reopens leads on the ledger and runs a sweep lost with its
 * process, as it does at a done) never reaches another.
 *
 * Each checkout is evaluated in a process of its own, with no model call,
 * no job and no VM: its answers check (each `check-answers.ts` line of the
 * goal's checks, read as await-done.sh reads them, run as its own function,
 * not as a shell command), its finish gate over that check, the finish
 * line's verdict, readiness, the finish register (the coordinator, what is
 * late against the report, the last check), the report's per-question
 * standing, and each custody verdict the run holds, verified as a prefix of
 * the registers with the checkout's own chain code. The goal's other checks
 * are its own commands, which no harness version changes: they are not run,
 * and the verdict reads them as passing (said in the output).
 *
 * What it prints is values-free by default: per question its declared
 * result, the check's outcome and disposition, whether it is held as a best
 * candidate, the codes of the defects, warnings and readiness items on it,
 * the gate's disposition and the report's standing; readiness, the gate's
 * defect codes, the verdict and the finish. Codes, ids, counts and the
 * harness's own fixed words, never a record's text: no answer, finding,
 * lead title or reason. `--show-text` adds the harness's lines whole (they
 * quote records), and is off unless asked for.
 *
 * `--checkout PATH` evaluates another checkout (a worktree at a commit,
 * `git worktree add --detach /tmp/x <commit>`) instead of this one.
 * `--compare` evaluates two and names every difference: with no argument,
 * the run's own frozen harness against this checkout (or --checkout); with
 * one, that checkout against this one; with two, the first against the
 * second. `frozen` names the run's own harness: the hub directory's frozen
 * host copy when it is still there, else the commit its registry record
 * names (provenance.harness_commit), extracted from this repository with
 * `git archive` into the temporary directory. `--stop-policy` evaluates the
 * copy as though the run's stop policy were each one given (operator,
 * cap-pause, cap-stop; the copy's budget.json only).
 *
 * Replay measures decisions on recorded histories. It cannot show what the
 * agents would have done under the other rule: a rule that changes their
 * behaviour is measured by paired runs, not here.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const STOP_POLICIES = ["operator", "cap-pause", "cap-stop"] as const;
export type StopPolicy = (typeof STOP_POLICIES)[number];

/**
 * What the copy leaves out, each with why: nothing any projection reads.
 * Everything else under the run is copied, whatever its name.
 */
export const LEFT_OUT: Readonly<Record<string, string>> = {
  inputs: "the evidence (inputs.json keeps each file's hash, which is what a ref resolves against)",
  images: "the evidence images a VM mounted",
  vm: "the VMs' records and disks",
  ".pi": "the seats' Pi settings",
  ".pi-sessions": "the seats' Pi sessions",
  ".runtime-cache": "the seats' runtime caches",
  ".kickoff": "the kickoff's options",
  "hub.dir": "the hub's directory, outside the run",
  "hub.pid": "the hub's process",
};

/** The phrase every report version prints in a question's chain when its answer is held a best candidate. */
const REPORT_BEST_CANDIDATE = "A best candidate, not established";

// ---------------------------------------------------------------------------------------------
// The projection: what one checkout's finish machinery says of one copy
// ---------------------------------------------------------------------------------------------

/** One question as a checkout's finish machinery sees it: codes, ids and the harness's own words. */
export type QuestionProjection = {
  section: string;
  /** The standing answer's declared result (the answers check's `results`), or null. */
  result: string | null;
  /** The answers check on it, when a check-answers line of the goal names it. */
  check: { outcome: string | null; disposition: string | null; best_candidate: boolean; defects: string[]; named: string[] } | null;
  /** The finish gate on it. */
  gate: { outcome: string; disposition: string | null; blocks: number } | null;
  /** The codes of the readiness items on it. */
  readiness: string[];
  /** The codes of the answers check's warnings on it. */
  warnings: string[];
  /** The report's standing for it: its status chip, and whether its chain says a best candidate. */
  report: { status: string; best_candidate: boolean } | null;
};

export type Projection = {
  harness: { path: string; commit: string | null };
  goal: { source: string | null; checks: number; answers_checks: number; not_replayed: number };
  stop_policy: string;
  questions: QuestionProjection[];
  /** Readiness: each item by its code and the questions it holds (a lead's item holds every question the lead serves). */
  readiness: { ready: boolean; items: Array<{ code: string; sections: string[] }>; limited: number; warnings: number } | null;
  gate: { defects: Array<{ code: string; sections: string[] }>; holding: number; error: string | null } | null;
  /** The finish line's verdict (proceeds, and how the run would end; or held, and on what: a question, a defect code or a check). */
  verdict: { proceed: boolean; outcome: string | null; failing: string | null } | null;
  finish: {
    lease: { holder: string; generation: number } | null;
    late: Array<{ kind: string; id: number; by: string; tag: string | null }>;
    last_check: { proceed: boolean; outcome: string | null; current: boolean } | null;
    /** Whether the coordinator's done would write the sentinel now: the verdict proceeds and nothing is late against the report. */
    done: "proceeds" | "held";
    held_by: string[];
  } | null;
  /** Where readiness, the answers check and the gate disagree on a question's disposition. */
  agreement: Array<{ section: string; kind: string }>;
  /** Warning codes that also appear as something that holds: readiness, the gate or the verdict. */
  warnings_hold: string[];
  seals: { verdicts: number; hold: number; broken: Array<{ verdict: string; broken: string[] }> };
  /** What could not be evaluated, in the harness's or node's words. */
  errors: string[];
  /** The harness's lines whole (they quote records): only with --show-text. */
  text?: { check: string[]; readiness: string[]; limited: string[]; gate: string[]; verdict: string | null; warnings: string[] };
};

type Mod = Record<string, unknown>;
// A module of the checkout under evaluation: its exports are read by name, and one that is missing is an error in the projection, never a crash.
type AnyFn = (...a: unknown[]) => Promise<unknown> | unknown;

const questionKey = (id: string) => {
  const s = String(id).trim();
  if (s.startsWith("question:") || s === "summary" || s === "narrative") return s;
  return `question:${s.replace(/^q-?(?=\d)/i, "")}`;
};

/** The goal's checks: code spans on bullet lines under every `## Checks` heading (await-done.sh's rule). */
export function goalChecks(text: string): string[] {
  const out: string[] = [];
  const sections = [...text.matchAll(/^##[ \t]*Checks[ \t]*$([\s\S]*?)(?=^#{1,6}[ \t]|(?![\s\S]))/gm)].map((m) => m[1]);
  for (const body of sections) {
    for (const line of body.split("\n")) {
      if (!/^\s*[-*]/.test(line)) continue;
      for (const m of line.matchAll(/`+([^`]+)`+/g)) if (m[1].trim()) out.push(m[1].trim());
    }
  }
  return out;
}

/** A shell line's words, quotes and backslashes taken as the shell takes them (no expansion). */
export function shellWords(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let has = false;
  let q: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === q) q = null;
      else if (c === "\\" && q === '"' && i + 1 < line.length) cur += line[++i];
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") {
      q = c;
      has = true;
    } else if (c === "\\" && i + 1 < line.length) {
      cur += line[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += c;
      has = true;
    }
  }
  if (has || cur) out.push(cur);
  return out;
}

/** An answers check line of the goal, read into what check-answers.ts takes. */
export type AnswersCheck = { cmd: string; sections: string[]; existence: string[]; sectionsIn: string | null; report: string | null };

export function answersChecks(checks: string[]): AnswersCheck[] {
  const out: AnswersCheck[] = [];
  for (const cmd of checks) {
    if (!/scripts\/check-answers\.ts\b/.test(cmd)) continue;
    const w = shellWords(cmd);
    const opt = (name: string) => {
      const i = w.indexOf(name);
      return i >= 0 ? (w[i + 1] ?? null) : null;
    };
    const list = (s: string | null) => (s ?? "").split(",").map((x) => x.trim()).filter(Boolean);
    out.push({ cmd, sections: list(opt("--sections")), existence: list(opt("--existence")), sectionsIn: opt("--sections-in"), report: opt("--report") });
  }
  return out;
}

const WARNING_CODES: ReadonlyArray<[string, RegExp]> = [
  ["no_acquisition_ask", /is not determinable, and .*no acquisition ask/],
  ["partial_all_parts_established", /is partial, and every review holds every part it weighed established/],
  ["lead_findings_uncited", /established under \S+'s leads and not in its answer/],
];

/** A warning line's code and section, by the harness's own words for it. */
export function warningCode(w: string): { code: string; section: string | null } {
  const code = WARNING_CODES.find(([, re]) => re.test(w))?.[0] ?? "warning";
  const m = /\((question:[^)\s]+|summary|narrative)\)/.exec(w);
  return { code, section: m ? m[1] : null };
}

/** A readiness item's code and section: by the defect it repeats, else by the harness's own words for it. */
export function readinessCode(item: string, known: Map<string, { code: string; section: string | null }>): { code: string; section: string | null } {
  const hit = known.get(item);
  if (hit) return hit;
  const lead = /^(question:\S+?|summary|narrative)\b/.exec(item)?.[1] ?? /\((question:[^)\s,;]+|summary|narrative)\)/.exec(item)?.[1] ?? null;
  if (/^\S+ is a best candidate, not established/.test(item)) return { code: "best_candidate", section: lead };
  if (/'s answer E-\d+ predates revision/.test(item)) return { code: "answer_predates_revision", section: lead };
  if (/'s answer E-\d+ predates new evidence/.test(item)) return { code: "answer_predates_evidence", section: lead };
  if (/^import:\S+ \((evidence|material) added/.test(item)) return { code: "addition_incomplete", section: null };
  if (/^L-\d+ was closed \w+/.test(item)) return { code: "route_limitation", section: null };
  return { code: "gate_item", section: lead };
}

async function importFrom(harness: string, rel: string): Promise<Mod | null> {
  const file = join(harness, rel);
  if (!existsSync(file)) return null;
  return (await import(pathToFileURL(file).href)) as Mod;
}

const fn = (m: Mod | null, name: string): AnyFn | null => (m && typeof m[name] === "function" ? (m[name] as AnyFn) : null);

/** The stop policy a run's budget.json says. */
async function stopPolicyIn(S: string): Promise<string> {
  try {
    const b = JSON.parse(await readFile(join(S, "budget.json"), "utf8")) as { stop_policy?: string; until_solved?: boolean };
    return b.until_solved === true ? "operator" : (b.stop_policy ?? "cap-pause");
  } catch {
    return "unknown";
  }
}

/** The commit a harness directory is at: its COMMIT file (a frozen copy), else git's HEAD. */
function harnessCommit(harness: string): string | null {
  for (const f of [join(harness, "COMMIT"), join(harness, "scripts", "HARNESS_COMMIT")]) {
    const t = existsSync(f) ? readFileSync(f, "utf8").trim() : "";
    if (/^[0-9a-f]{7,40}\b/.test(t)) return t.split(/\s/)[0];
  }
  const g = spawnSync("git", ["-C", harness, "rev-parse", "HEAD"], { encoding: "utf8" });
  return g.status === 0 ? g.stdout.trim() : null;
}

/**
 * One copy, as one checkout's finish machinery reads it. Every part is read
 * in the order a done reads it (the answers check, the gate over it, the
 * verdict), then readiness and the finish register at the state that
 * leaves, then the report and the seals. A part the checkout cannot
 * evaluate is named in `errors`.
 */
export async function project(harness: string, S: string, o: { showText?: boolean } = {}): Promise<Projection> {
  const errors: string[] = [];
  const guard = async <T>(what: string, f: () => Promise<T>): Promise<T | null> => {
    try {
      return await f();
    } catch (e) {
      const err = e as Error & { code?: string };
      // A package the checkout imports that its tree does not hold: a worktree made without node_modules.
      const pkg = err.code === "ERR_MODULE_NOT_FOUND" ? /Cannot find package '([^']+)'/.exec(err.message)?.[1] : undefined;
      errors.push(`${what}: ${err.message}${pkg ? `. The checkout has no ${pkg}: link a checkout's packages into it (ln -s ${join(ROOT, "node_modules")} ${join(harness, "node_modules")}) and replay again` : ""}`);
      return null;
    }
  };
  const CA = await guard("scripts/check-answers.ts", () => importFrom(harness, "scripts/check-answers.ts"));
  const FG = await guard("scripts/finish-gate.ts", () => importFrom(harness, "scripts/finish-gate.ts"));
  const FIN = await guard("extensions/finish.ts", () => importFrom(harness, "extensions/finish.ts"));
  const P = await guard("extensions/protocol.ts", () => importFrom(harness, "extensions/protocol.ts"));
  const L = await guard("extensions/leads.ts", () => importFrom(harness, "extensions/leads.ts"));
  const SW = await guard("extensions/store-sweep.ts", () => importFrom(harness, "extensions/store-sweep.ts"));

  // The goal as the finish line reads it: the registry's record (the replay's own, beside the copy), else the copy's SWARM.md.
  const doc = ((await guard("the goal", async () => (fn(L, "goalDocument") ? await fn(L, "goalDocument")!(S) : null))) ?? null) as { text: string; source: string } | null;
  const goalText = doc?.text ?? (await readFile(join(S, "SWARM.md"), "utf8").catch(() => ""));
  const checks = goalChecks(goalText);
  const answers = answersChecks(checks);

  // The answers check, as its CLI runs it: a sweep lost with its process first, then the check.
  type CheckResult = { ok: boolean; lines: string[]; outcomes: Record<string, string>; results?: Record<string, string>; defects?: Array<{ code: string; section?: string; what: string; named_by: number[] }>; best_candidate?: string[]; dispositions?: Record<string, string>; warnings?: string[] };
  const rows: Array<{ cmd: string; ok: boolean; answers: Record<string, unknown> }> = [];
  const perCheck: CheckResult[] = [];
  for (const c of answers) {
    const r = (await guard(`the answers check (${c.cmd.includes("--report") ? "report mode" : "ledger mode"})`, async () => {
      const wanted = [...c.sections];
      if (c.sectionsIn) {
        const brief = await readFile(join(S, c.sectionsIn), "utf8").catch(() => null);
        if (brief !== null && fn(CA, "briefQuestions")) wanted.unshift(...((await fn(CA, "briefQuestions")!(brief)) as string[]));
      }
      if (c.report) return (await fn(CA, "checkAnswers")!(S, c.report, wanted, c.existence)) as CheckResult;
      if (fn(SW, "reconcileSweeps")) await Promise.resolve(fn(SW, "reconcileSweeps")!(S)).catch(() => 0);
      return (await fn(CA, "checkLedgerAnswers")!(S, wanted, c.existence)) as CheckResult;
    })) as CheckResult | null;
    if (!r) continue;
    perCheck.push(r);
    const named = (r.defects ?? []).filter((d) => d.named_by.length).map((d) => `${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`);
    rows.push({ cmd: c.cmd, ok: r.ok, answers: { outcomes: r.outcomes, ...(r.results ? { results: r.results } : {}), ...(r.best_candidate?.length ? { best_candidate: r.best_candidate } : {}), ...(r.dispositions ? { dispositions: r.dispositions } : {}), ...(r.warnings?.length ? { warnings: r.warnings } : {}), named, existence: c.existence, mode: c.report ? "report" : "ledger" } });
  }
  // The goal's other checks are its own commands: not run, read as passing.
  const others = checks.length - answers.length;
  const run = { total: rows.length + others, passed: rows.filter((r) => r.ok).length + others, checks: rows.map((r) => ({ cmd: r.cmd, ok: r.ok, answers: r.answers })), source: "registry" };

  type Gate = { defects: Array<{ code: string; lead?: string; question?: string; what: string }>; limited: string[]; questions: Array<{ id: string; outcome: string; blocks: string[]; disposition?: string }>; holding?: string[]; warnings?: string[]; error?: string };
  const gate = (await guard("the finish gate", async () => (await fn(FG, "finishGate")!(S, run)) as Gate)) as Gate | null;
  const verdictRaw = gate ? ((await guard("the verdict", async () => fn(P, "finishLineVerdict")!({ ...run, gate }, false))) as { proceed: boolean; outcome?: string; failing?: string; reason?: string; note?: string } | null) : null;
  type Ready = { ready: boolean; revision: string; items: string[]; limited: string[]; warnings?: string[] };
  const ready = (await guard("readiness", async () => (await fn(FIN, "readiness")!(S)) as Ready)) as Ready | null;
  type FinState = { lease: { holder: string; generation: number; report: string | null } | null; checks: Array<{ revision: string; proceed: boolean; outcome?: string }> };
  const fin = (await guard("the finish register", async () => (await fn(FIN, "readFinish")!(S)) as FinState)) as FinState | null;
  const late = fin?.lease ? (((await guard("what is late against the report", async () => fn(FIN, "lateItems")!(S, fin.lease!.holder, fin.lease!.report))) as Array<{ kind: string; id: number; by: string; tag?: string }> | null) ?? []) : [];

  // Which questions each lead serves: a lead's defect or limitation holds every one of them.
  const leadQuestions = new Map<string, string[]>();
  const snap = (await guard("the lead register", async () => (fn(L, "leadsSnapshot") ? await fn(L, "leadsSnapshot")!(S) : null))) as { state: { leads: Map<string, { answers: string[] }> } } | null;
  for (const [id, l] of snap?.state.leads ?? []) leadQuestions.set(id, (l.answers ?? []).map(questionKey));
  const gateSections = (d: { question?: string; lead?: string }) => (d.question ? [questionKey(d.question)] : d.lead ? (leadQuestions.get(d.lead) ?? []) : []);

  // Every defect by its words: readiness repeats the gate's and the answers check's.
  const known = new Map<string, { code: string; section: string | null }>();
  for (const r of perCheck) for (const d of r.defects ?? []) known.set(d.what, { code: d.code, section: d.section ?? null });
  const gateKnown = new Map<string, string[]>();
  for (const d of gate?.defects ?? []) {
    known.set(d.what, { code: d.code, section: null });
    gateKnown.set(d.what, gateSections(d));
  }
  const items = (ready?.items ?? []).map((i) => {
    const c = readinessCode(i, known);
    if (c.section) return { code: c.code, sections: [questionKey(c.section)] };
    if (gateKnown.get(i)?.length) return { code: c.code, sections: gateKnown.get(i)! };
    // A lead's item (a route limitation, an open lead) holds what the lead serves.
    const lead = [...i.matchAll(/\b(L-\d+)\b/g)].map((m) => m[1])[0];
    return { code: c.code, sections: lead ? (leadQuestions.get(lead) ?? []) : [] };
  });

  // The report's standing, per question.
  const RB = await guard("scripts/report-body.ts", () => importFrom(harness, "scripts/report-body.ts"));
  const body = (await guard("the report", async () => (fn(RB, "renderReportBody") ? await fn(RB, "renderReportBody")!(S) : null))) as { html: string; facts: { questionStatus: Array<{ id: string; status: string }> } } | null;
  const reportBest = new Set<string>();
  if (body) {
    for (const chunk of body.html.split('<div class="answer chain" id="qc-').slice(1)) {
      const id = chunk.slice(0, chunk.indexOf('"'));
      const end = chunk.indexOf('<div class="answer chain"');
      if ((end < 0 ? chunk : chunk.slice(0, end)).includes(REPORT_BEST_CANDIDATE)) reportBest.add(questionKey(id));
    }
  }

  // Every question the gate, the check or readiness names.
  const sections: string[] = [];
  const add = (s: string | null | undefined) => {
    if (s && !sections.includes(s)) sections.push(s);
  };
  for (const q of gate?.questions ?? []) add(questionKey(q.id));
  for (const r of perCheck) for (const k of Object.keys(r.outcomes ?? {})) add(questionKey(k));
  for (const i of items) for (const s of i.sections) add(s);
  const warningLines = [...new Set([...perCheck.flatMap((r) => r.warnings ?? []), ...(gate?.warnings ?? []), ...(ready?.warnings ?? [])])];
  const warnings = warningLines.map(warningCode);
  const questions: QuestionProjection[] = sections.map((section) => {
    const covered = perCheck.filter((r) => Object.keys(r.outcomes ?? {}).map(questionKey).includes(section));
    const check = covered.length
      ? {
          outcome: covered.map((r) => Object.entries(r.outcomes).find(([k]) => questionKey(k) === section)?.[1] ?? null).find((x) => x !== null) ?? null,
          disposition: covered.map((r) => Object.entries(r.dispositions ?? {}).find(([k]) => questionKey(k) === section)?.[1] ?? null).find((x) => x !== null) ?? null,
          best_candidate: covered.some((r) => (r.best_candidate ?? []).map(questionKey).includes(section)),
          defects: [...new Set(covered.flatMap((r) => (r.defects ?? []).filter((d) => d.section && questionKey(d.section) === section && !d.named_by.length).map((d) => d.code)))].sort(),
          named: [...new Set(covered.flatMap((r) => (r.defects ?? []).filter((d) => d.section && questionKey(d.section) === section && d.named_by.length).map((d) => d.code)))].sort(),
        }
      : null;
    const g = gate?.questions.find((q) => questionKey(q.id) === section);
    const status = body?.facts.questionStatus.find((q) => questionKey(q.id) === section);
    return {
      section,
      result: covered.map((r) => Object.entries(r.results ?? {}).find(([k]) => questionKey(k) === section)?.[1] ?? null).find((x) => x !== null) ?? null,
      check,
      gate: g ? { outcome: g.outcome, disposition: g.disposition ?? null, blocks: g.blocks.length } : null,
      readiness: items.filter((i) => i.sections.includes(section)).map((i) => i.code).sort(),
      warnings: warnings.filter((w) => w.section === section).map((w) => w.code).sort(),
      report: status ? { status: status.status, best_candidate: reportBest.has(section) } : null,
    };
  });

  // Readiness, the answers check and the gate on each question. The gate
  // holds a question it gives no disposition, or one a defect of its own
  // names (a lead serving it still open, a question defect on it); readiness
  // holds it by an item on it. Under the operator's stop policy readiness
  // holds a route limitation too, which only limits the done (docs/adr/0015,
  // 7 and 8): by design, never counted as a disagreement.
  const agreement: Array<{ section: string; kind: string }> = [];
  const finalOutcome = (o: string) => ["answered", "accepted", "withdrawn"].includes(o);
  for (const q of questions) {
    if (!q.gate || !q.section.startsWith("question:")) continue;
    const disposed = Boolean(q.gate.disposition) || finalOutcome(q.gate.outcome);
    const gateHolds = !disposed || (gate?.defects ?? []).some((d) => gateSections(d).includes(q.section));
    const readyHolds = q.readiness.some((c) => c !== "route_limitation");
    if (ready && readyHolds && !gateHolds) agreement.push({ section: q.section, kind: "readiness_holds_disposed" });
    if (ready && !readyHolds && gateHolds) agreement.push({ section: q.section, kind: "readiness_clear_held" });
    if (q.check?.disposition && q.gate.disposition && q.check.disposition !== q.gate.disposition) agreement.push({ section: q.section, kind: "check_gate_disposition" });
    if (q.check?.disposition && !q.gate.disposition && !finalOutcome(q.gate.outcome)) agreement.push({ section: q.section, kind: "gate_holds_check_disposed" });
    if (q.check?.best_candidate && q.gate.disposition) agreement.push({ section: q.section, kind: "gate_disposes_best_candidate" });
  }
  if (ready && gate && !gate.error) {
    const gateClear = !gate.defects.length && !(gate.holding ?? []).length && gate.questions.every((q) => q.disposition || finalOutcome(q.outcome));
    const readyHeld = items.some((i) => i.code !== "route_limitation");
    if (!ready.ready && readyHeld && gateClear) agreement.push({ section: "run", kind: "readiness_not_ready_gate_clear" });
    if (ready.ready && !gateClear) agreement.push({ section: "run", kind: "readiness_ready_gate_holds" });
  }
  // A warning never holds: none of its lines is also what readiness, the gate or the verdict holds on.
  const holdingWords = [...(ready?.items ?? []), ...(gate?.defects ?? []).map((d) => d.what), ...(gate?.holding ?? []), ...(gate?.questions ?? []).flatMap((q) => q.blocks)];
  const warningsHold = [...new Set(warningLines.filter((w) => holdingWords.some((h) => h && (w.startsWith(h) || h.includes(w)))).map((w) => warningCode(w).code))].sort();

  const failing = verdictRaw && !verdictRaw.proceed ? (verdictRaw.failing ?? null) : null;
  // What it holds on: a question, a gate defect's code and id, or a check, named by what it is and never by its command.
  const failingCheck = failing !== null && run.checks.some((c) => c.cmd === failing);
  const verdict = verdictRaw ? { proceed: verdictRaw.proceed, outcome: verdictRaw.proceed ? (verdictRaw.outcome ?? null) : null, failing: failing === null ? null : failingCheck ? (/check-answers\.ts/.test(failing) ? "check:check-answers" : "check") : failing } : null;
  const heldBy = [...(verdict && !verdict.proceed ? [`verdict:${verdict.failing ?? "held"}`] : []), ...late.map((x) => `late_${x.kind}`)];
  const last = fin?.checks.at(-1);

  const seals = await sealCheck(harness, S, errors);
  const projection: Projection = {
    harness: { path: harness, commit: harnessCommit(harness) },
    goal: { source: doc?.source ?? (goalText ? "sandbox contract" : null), checks: checks.length, answers_checks: rows.length, not_replayed: others },
    stop_policy: await stopPolicyIn(S),
    questions,
    readiness: ready ? { ready: ready.ready, items, limited: ready.limited.length, warnings: (ready.warnings ?? []).length } : null,
    gate: gate ? { defects: gate.defects.map((d) => ({ code: d.code, sections: gateSections(d) })), holding: (gate.holding ?? []).length, error: gate.error ?? null } : null,
    verdict,
    finish: fin
      ? {
          lease: fin.lease ? { holder: fin.lease.holder, generation: fin.lease.generation } : null,
          late: late.map((x) => ({ kind: x.kind, id: x.id, by: x.by, tag: x.tag ?? null })),
          last_check: last ? { proceed: last.proceed, outcome: last.outcome ?? null, current: Boolean(ready && last.revision === ready.revision) } : null,
          done: heldBy.length ? "held" : "proceeds",
          held_by: heldBy,
        }
      : null,
    agreement,
    warnings_hold: warningsHold,
    seals,
    errors,
  };
  if (o.showText) {
    projection.text = {
      check: perCheck.flatMap((r) => r.lines),
      readiness: ready?.items ?? [],
      limited: [...(ready?.limited ?? []), ...(gate?.limited ?? [])],
      gate: (gate?.defects ?? []).map((d) => d.what),
      verdict: verdictRaw ? (verdictRaw.proceed ? (verdictRaw.note ?? null) : (verdictRaw.reason ?? null)) : null,
      warnings: warningLines,
    };
  }
  return projection;
}

/**
 * Each custody verdict the run holds (custody.json, a verdict a resume set
 * aside as custody.<time>.json, and every one the anchor beside the run
 * names), held to the copy's registers as a prefix with the checkout's own
 * chain code (custody.ts sealPrefix): a seal an older version made must
 * still verify under the newer one.
 */
async function sealCheck(harness: string, S: string, errors: string[]): Promise<Projection["seals"]> {
  const out: Projection["seals"] = { verdicts: 0, hold: 0, broken: [] };
  let CU: Mod | null = null;
  try {
    CU = await importFrom(harness, "scripts/custody.ts");
  } catch (e) {
    errors.push(`scripts/custody.ts: ${(e as Error).message}`);
    return out;
  }
  const sealPrefix = fn(CU, "sealPrefix");
  const verdicts: Array<{ name: string; seal: unknown }> = [];
  const seen = new Set<string>();
  const take = (name: string, seal: unknown) => {
    if (!seal || typeof seal !== "object") return;
    const k = JSON.stringify(seal);
    if (seen.has(k)) return;
    seen.add(k);
    verdicts.push({ name, seal });
  };
  for (const f of (await readdir(S).catch(() => [] as string[])).filter((n) => /^custody(\.[0-9TZ]+)?\.json$/.test(n)).sort()) {
    try {
      take(f, (JSON.parse(await readFile(join(S, f), "utf8")) as { seal?: unknown }).seal);
    } catch {
      errors.push(`${f} cannot be read as a verdict`);
    }
  }
  try {
    const anchor = JSON.parse(await readFile(join(dirname(S), `${basename(S)}.custody-anchor.json`), "utf8")) as { custody?: Array<{ at?: string; seal?: unknown }> };
    for (const [i, v] of (anchor.custody ?? []).entries()) take(`the anchor's verdict ${i + 1}${v.at ? ` (${v.at})` : ""}`, v.seal);
  } catch {
    // No anchor beside the run: the verdicts it holds are all there is.
  }
  if (!verdicts.length) return out;
  if (!sealPrefix) {
    errors.push("this checkout has no sealPrefix (scripts/custody.ts): the seals are not checked");
    return out;
  }
  const read = (rel: string) => readFile(join(S, rel), "utf8").catch(() => "");
  const now = {
    trace: await read("traces/events.jsonl"),
    ledger: await read("ledger/entries.jsonl"),
    attestations: await read("ledger/attestations.jsonl"),
    disputes: await read("ledger/disputes.jsonl"),
    leads: await read("leads/leads.jsonl"),
    questions: await read("questions/questions.jsonl"),
    grants: await read("network/grants.jsonl"),
    fetches: await read("network/fetches.jsonl"),
    requests: await read("requests/requests.jsonl"),
    sweeps: await read("ledger/sweeps.jsonl"),
    finish: await read("leads/finish.jsonl"),
    journal: await readFile(join(S, "store", "journal.jsonl"), "utf8").catch(() => null),
    gateway: await readFile(join(S, "traces", "model-gateway.jsonl"), "utf8").catch(() => null),
  };
  for (const v of verdicts) {
    out.verdicts += 1;
    const r = (await sealPrefix(v.seal, now)) as { ok: boolean; broken: string[] };
    if (r.ok) out.hold += 1;
    else out.broken.push({ verdict: v.name, broken: r.broken });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The run, its copies, the checkouts
// ---------------------------------------------------------------------------------------------

export type RunRef = { id: string; sandbox: string; entry: Record<string, unknown> | null; registry: string | null };

/** The run: a directory, or an id in the registry. */
export async function resolveRun(run: string, registry?: string | null): Promise<RunRef> {
  const readRegistry = async (file: string) => {
    try {
      const r = JSON.parse(await readFile(file, "utf8")) as { runs?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>;
      return Array.isArray(r) ? r : (r.runs ?? []);
    } catch {
      return null;
    }
  };
  if (existsSync(run) && (existsSync(join(run, "ledger")) || existsSync(join(run, "SWARM.md")))) {
    const sandbox = realpathSync(resolve(run));
    const file = registry ?? join(dirname(sandbox), "registry.json");
    const runs = (await readRegistry(file)) ?? [];
    const entry = [...runs].reverse().find((r) => typeof r.sandbox === "string" && existsSync(r.sandbox) && realpathSync(r.sandbox) === sandbox) ?? null;
    const team = await readFile(join(sandbox, "team.json"), "utf8").then((t) => (JSON.parse(t) as { swarm_id?: string }).swarm_id ?? null).catch(() => null);
    return { id: (entry?.id as string | undefined) ?? team ?? basename(sandbox), sandbox, entry, registry: entry ? file : null };
  }
  if (!registry) throw new Error(`${run} is not a run directory, and no registry was given to find it in: name the run's directory, or its id with --registry <runs dir>/registry.json (swarm.sh replay passes it)`);
  const runs = await readRegistry(registry);
  if (!runs) throw new Error(`${registry} cannot be read as the run registry`);
  const entry = [...runs].reverse().find((r) => r.id === run);
  if (!entry || typeof entry.sandbox !== "string") throw new Error(`no run ${run} in ${registry}: swarm.sh list names the runs`);
  if (!existsSync(entry.sandbox)) throw new Error(`run ${run}'s directory ${entry.sandbox} is not there`);
  return { id: run, sandbox: realpathSync(entry.sandbox), entry, registry };
}

export type Target = { label: string; harness: string; how: string; commit: string | null };

/** Whether a directory is a harness this replay can evaluate, and if not, what to do. */
export function checkoutProblem(path: string): string | null {
  const need = ["scripts/check-answers.ts", "scripts/finish-gate.ts", "extensions/finish.ts", "extensions/protocol.ts"];
  const missing = need.filter((f) => !existsSync(join(path, f)));
  if (!missing.length) return null;
  return `${path} is not a harness checkout (no ${missing.join(", ")}): name the root of a checkout or worktree, e.g. git worktree add --detach /tmp/dfs-<commit> <commit>`;
}

/**
 * The run's own harness: the hub directory's frozen host copy while it is
 * there (swarm.sh freeze_harness), else the commit its registry record
 * names, extracted from this repository with git archive into `scratch`.
 */
export async function frozenHarness(run: RunRef, scratch: string): Promise<Target> {
  const hubDir = await readFile(join(run.sandbox, "hub.dir"), "utf8").then((t) => t.trim()).catch(() => "");
  if (hubDir && !checkoutProblem(join(hubDir, "host"))) {
    const commit = await readFile(join(hubDir, "host", "COMMIT"), "utf8").then((t) => t.trim()).catch(() => null);
    return { label: "frozen", harness: join(hubDir, "host"), how: `the run's frozen host copy (${join(hubDir, "host")})`, commit };
  }
  const prov = (run.entry?.provenance ?? null) as { harness_commit?: string; harness_dirty?: boolean } | null;
  const commit = prov?.harness_commit ?? "";
  if (!/^[0-9a-f]{7,40}$/.test(commit)) {
    throw new Error(`run ${run.id} names no harness commit (its registry record has no provenance.harness_commit) and its hub's frozen copy is gone: give the harness it ran with as --compare <path>`);
  }
  const has = spawnSync("git", ["-C", ROOT, "cat-file", "-e", `${commit}^{commit}`]);
  if (has.status !== 0) {
    throw new Error(`run ${run.id} ran harness ${commit}, and its hub's frozen copy is gone; ${commit} is not in this repository's history (${ROOT}): fetch it (git fetch origin), or make a worktree of it elsewhere and give --compare <path>`);
  }
  const dest = join(scratch, `harness-${commit.slice(0, 12)}`);
  await extractCommit(commit, dest);
  return { label: "frozen", harness: dest, how: `the run's own harness, extracted from git at ${commit.slice(0, 12)}${prov?.harness_dirty ? " (the run's checkout had local changes: the commit alone is replayed)" : ""}`, commit };
}

/** The parts of the harness a replay reads, at `commit`, written under `dest` (git archive; the repository's worktrees are not touched). */
export async function extractCommit(commit: string, dest: string): Promise<void> {
  await mkdir(dest, { recursive: true });
  const paths = ["extensions", "scripts", "prompts", "network", "ui/src/lib", "package.json"].filter((p) => spawnSync("git", ["-C", ROOT, "cat-file", "-e", `${commit}:${p}`]).status === 0);
  const archive = spawnSync("git", ["-C", ROOT, "archive", "--format=tar", commit, ...paths], { maxBuffer: 1 << 30 });
  if (archive.status !== 0) throw new Error(`git archive ${commit} failed: ${String(archive.stderr)}`);
  const untar = spawnSync("tar", ["-x", "-C", dest], { input: archive.stdout, maxBuffer: 1 << 30 });
  if (untar.status !== 0) throw new Error(`the archive of ${commit} could not be unpacked: ${String(untar.stderr)}`);
  await writeFile(join(dest, "COMMIT"), `${commit}\n`);
}

/** The run's registers and custody, by size and sha256: taken before and after, so a replay that wrote the run says so. */
async function registerDigest(sandbox: string): Promise<string> {
  const rels = ["ledger/entries.jsonl", "ledger/attestations.jsonl", "ledger/disputes.jsonl", "ledger/sweeps.jsonl", "leads/leads.jsonl", "leads/finish.jsonl", "questions/questions.jsonl", "requests/requests.jsonl", "network/grants.jsonl", "network/fetches.jsonl", "store/journal.jsonl", "traces/events.jsonl", "budget.json", "custody.json"];
  const h = createHash("sha256");
  for (const rel of rels) {
    const b = await readFile(join(sandbox, rel)).catch(() => null);
    h.update(`${rel}\0${b ? `${b.length}:${createHash("sha256").update(b).digest("hex")}` : "none"}\n`);
  }
  return h.digest("hex");
}

/**
 * The run copied under `dest`, less LEFT_OUT: each top-level entry cloned
 * where the file system can (cp -c on macOS, --reflink=auto on Linux), times
 * kept (the state revision reads the deliverables' times), then every link
 * in the copy removed and the copy made writable for the checkout's own
 * writes.
 */
export async function copyRun(sandbox: string, dest: string): Promise<{ left_out: string[]; links_removed: number }> {
  await mkdir(dest, { recursive: true });
  const left: string[] = [];
  for (const d of await readdir(sandbox, { withFileTypes: true })) {
    if (d.name in LEFT_OUT || d.isSymbolicLink() || d.isSocket() || d.isFIFO()) {
      left.push(d.name);
      continue;
    }
    const src = join(sandbox, d.name);
    const mac = process.platform === "darwin";
    let r = spawnSync("cp", mac ? ["-cRp", src, dest] : ["-a", "--reflink=auto", src, dest], { encoding: "utf8" });
    if (r.status !== 0) r = spawnSync("cp", mac ? ["-Rp", src, dest] : ["-a", src, dest], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`${d.name} could not be copied: ${r.stderr.trim()}`);
  }
  const links = spawnSync("find", [dest, "-type", "l", "-print", "-delete"], { encoding: "utf8", maxBuffer: 1 << 28 });
  const removed = String(links.stdout ?? "").split("\n").filter(Boolean).length;
  spawnSync("find", [dest, "(", "-type", "p", "-o", "-type", "s", ")", "-delete"]);
  spawnSync("chmod", ["-R", "u+w", dest]);
  return { left_out: left.sort(), links_removed: removed };
}

/** The copy's budget.json, as though the run's stop policy were `policy` (the stop-policy tests' own reading of it). */
async function applyPolicy(copy: string, policy: StopPolicy): Promise<void> {
  const file = join(copy, "budget.json");
  const b = JSON.parse(await readFile(file, "utf8").catch(() => "{}")) as Record<string, unknown>;
  const next = policy === "operator" ? { ...b, stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 } : { ...b, stop_policy: policy, until_solved: false, wall_clock_minutes: typeof b.wall_clock_minutes === "number" && b.wall_clock_minutes > 0 ? b.wall_clock_minutes : 60 };
  await writeFile(file, `${JSON.stringify(next, null, 2)}\n`);
}

export type Evaluation = { target: Target; policy: string; projection: Projection | null; error: string | null };
export type Difference = { policy: string; section: string | null; field: string; a: string; b: string };
export type Replay = {
  run: { id: string; case_id: string | null; stop_policy: string | null; harness_commit: string | null };
  copy: { left_out: string[]; links_removed: number };
  targets: Target[];
  evaluations: Evaluation[];
  differences: Difference[] | null;
  unchanged: boolean;
};

/** Evaluate each copy in `copies` with `harness`, in a process of its own; one projection per copy, in order. */
async function evaluateIn(harness: string, copies: string[], showText: boolean): Promise<Array<Projection | { error: string }>> {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^(SWARM_|DFIRSWARM_)/.test(k)) env[k] = v;
  const args = ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "replay.ts"), "--evaluate", "--harness", harness, ...(showText ? ["--show-text"] : []), ...copies.flatMap((c) => ["--sandbox", c])];
  return new Promise((done) => {
    const child = spawn(process.execPath, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => out.push(b));
    child.stderr.on("data", (b: Buffer) => err.push(b));
    child.on("close", (code) => {
      const text = Buffer.concat(out).toString("utf8").trim().split("\n").pop() ?? "";
      try {
        const parsed = JSON.parse(text) as Array<Projection | { error: string }>;
        if (Array.isArray(parsed)) return done(parsed);
      } catch {
        // below
      }
      const why = `the evaluation of ${harness} ended with exit ${code}: ${Buffer.concat(err).toString("utf8").trim().split("\n").slice(-5).join(" | ") || "no output"}`;
      done(copies.map(() => ({ error: why })));
    });
  });
}

/**
 * The replay: the run copied once per checkout and stop policy, each copy
 * evaluated, the run's registers checked unchanged, and, for two
 * checkouts, every difference named.
 */
export async function replay(o: { run: RunRef; targets: Target[]; policies?: StopPolicy[] | null; showText?: boolean; scratch: string }): Promise<Replay> {
  const before = await registerDigest(o.run.sandbox);
  const goal = typeof o.run.entry?.goal === "string" ? (o.run.entry.goal as string) : await readFile(join(o.run.sandbox, "SWARM.md"), "utf8").catch(() => "");
  const briefs = answersChecks(goalChecks(goal)).map((c) => c.sectionsIn).filter((x): x is string => Boolean(x));
  const policies: Array<StopPolicy | null> = o.policies?.length ? o.policies : [null];
  let copyInfo = { left_out: [] as string[], links_removed: 0 };
  const evaluations: Evaluation[] = [];
  for (const [ti, target] of o.targets.entries()) {
    const copies: string[] = [];
    for (const policy of policies) {
      const runs = join(o.scratch, `${ti + 1}-${policy ?? "as-run"}`, "runs");
      const copy = join(runs, o.run.id);
      copyInfo = await copyRun(o.run.sandbox, copy);
      // The goal's brief a check reads its questions from (--sections-in), when it is under the evidence the copy leaves out: that file alone.
      for (const rel of briefs) {
        if (isAbsolute(rel) || relative(o.run.sandbox, resolve(o.run.sandbox, rel)).startsWith("..")) continue;
        if (existsSync(join(copy, rel))) continue;
        await mkdir(dirname(join(copy, rel)), { recursive: true });
        await copyFile(join(o.run.sandbox, rel), join(copy, rel)).catch(() => undefined);
      }
      // The registry the finish line reads the goal from: this run's record alone, pointing at the copy (as the VM hub gives a VM).
      if (o.run.entry) await writeFile(join(runs, "registry.json"), `${JSON.stringify({ runs: [{ ...o.run.entry, sandbox: copy }] }, null, 2)}\n`);
      const anchor = join(dirname(o.run.sandbox), `${basename(o.run.sandbox)}.custody-anchor.json`);
      if (existsSync(anchor)) await copyFile(anchor, join(runs, `${o.run.id}.custody-anchor.json`)).catch(() => undefined);
      if (policy) await applyPolicy(copy, policy);
      copies.push(copy);
    }
    const results = await evaluateIn(target.harness, copies, o.showText === true);
    for (const [i, r] of results.entries()) evaluations.push({ target, policy: policies[i] ?? "as run", projection: "error" in r ? null : r, error: "error" in r ? r.error : null });
  }
  const after = await registerDigest(o.run.sandbox);
  let differences: Difference[] | null = null;
  if (o.targets.length === 2) {
    differences = [];
    for (const policy of policies) {
      const a = evaluations.find((e) => e.target === o.targets[0] && e.policy === (policy ?? "as run"))?.projection;
      const b = evaluations.find((e) => e.target === o.targets[1] && e.policy === (policy ?? "as run"))?.projection;
      if (a && b) differences.push(...diffProjections(a, b).map((d) => ({ ...d, policy: policy ?? "as run" })));
    }
  }
  const prov = (o.run.entry?.provenance ?? null) as { harness_commit?: string } | null;
  return {
    run: { id: o.run.id, case_id: typeof o.run.entry?.case_id === "string" ? (o.run.entry.case_id as string) : null, stop_policy: await stopPolicyIn(o.run.sandbox), harness_commit: prov?.harness_commit ?? null },
    copy: copyInfo,
    targets: o.targets,
    evaluations,
    differences,
    unchanged: before === after,
  };
}

const listWords = (xs: string[]) => (xs.length ? xs.join(", ") : "none");

/** Every difference between two projections of the same run, field by field. */
export function diffProjections(a: Projection, b: Projection): Array<Omit<Difference, "policy">> {
  const out: Array<Omit<Difference, "policy">> = [];
  const put = (section: string | null, field: string, x: string, y: string) => {
    if (x !== y) out.push({ section, field, a: x, b: y });
  };
  const sections = [...new Set([...a.questions, ...b.questions].map((q) => q.section))];
  for (const s of sections) {
    const x = a.questions.find((q) => q.section === s);
    const y = b.questions.find((q) => q.section === s);
    put(s, "result", x?.result ?? "none", y?.result ?? "none");
    put(s, "check outcome", x?.check?.outcome ?? "none", y?.check?.outcome ?? "none");
    put(s, "check disposition", x?.check?.disposition ?? "none", y?.check?.disposition ?? "none");
    put(s, "held a best candidate", String(x?.check?.best_candidate ?? false), String(y?.check?.best_candidate ?? false));
    put(s, "defects", listWords(x?.check?.defects ?? []), listWords(y?.check?.defects ?? []));
    put(s, "named defects", listWords(x?.check?.named ?? []), listWords(y?.check?.named ?? []));
    put(s, "gate outcome", x?.gate?.outcome ?? "none", y?.gate?.outcome ?? "none");
    put(s, "gate disposition", x?.gate?.disposition ?? "none", y?.gate?.disposition ?? "none");
    put(s, "readiness holds", listWords(x?.readiness ?? []), listWords(y?.readiness ?? []));
    put(s, "warnings", listWords(x?.warnings ?? []), listWords(y?.warnings ?? []));
    put(s, "report status", x?.report?.status ?? "none", y?.report?.status ?? "none");
    put(s, "report says best candidate", String(x?.report?.best_candidate ?? false), String(y?.report?.best_candidate ?? false));
  }
  put(null, "ready", String(a.readiness?.ready ?? "unknown"), String(b.readiness?.ready ?? "unknown"));
  put(null, "readiness items", listWords(countWords((a.readiness?.items ?? []).map((i) => i.code))), listWords(countWords((b.readiness?.items ?? []).map((i) => i.code))));
  put(null, "gate defects", listWords(countWords((a.gate?.defects ?? []).map((d) => d.code))), listWords(countWords((b.gate?.defects ?? []).map((d) => d.code))));
  put(null, "verdict", verdictWords(a.verdict), verdictWords(b.verdict));
  put(null, "done", a.finish ? `${a.finish.done}${a.finish.held_by.length ? ` (${a.finish.held_by.join(", ")})` : ""}` : "none", b.finish ? `${b.finish.done}${b.finish.held_by.length ? ` (${b.finish.held_by.join(", ")})` : ""}` : "none");
  put(null, "disagreements", listWords(a.agreement.map((g) => `${g.section} ${g.kind}`)), listWords(b.agreement.map((g) => `${g.section} ${g.kind}`)));
  put(null, "seals", `${a.seals.hold} of ${a.seals.verdicts} hold`, `${b.seals.hold} of ${b.seals.verdicts} hold`);
  return out;
}

function countWords(codes: string[]): string[] {
  const m = new Map<string, number>();
  for (const c of codes) m.set(c, (m.get(c) ?? 0) + 1);
  return [...m].sort(([x], [y]) => x.localeCompare(y)).map(([c, n]) => (n > 1 ? `${c} ×${n}` : c));
}

function verdictWords(v: Projection["verdict"]): string {
  if (!v) return "not evaluated";
  return v.proceed ? `proceeds, ${v.outcome}` : `held on ${v.failing ?? "?"}`;
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

const pad = (s: string, n: number) => (s.length >= n ? `${s} ` : s + " ".repeat(n - s.length));

/** The replay in words, values-free: codes, ids, counts and the harness's own fixed words. */
export function replayWords(r: Replay): string {
  const out: string[] = [];
  out.push(`Replay of ${r.run.id}${r.run.case_id ? ` (case ${r.run.case_id})` : ""}: its registers read again from a copy; the run is not written${r.unchanged ? " (its registers hashed the same before and after)" : ". ITS REGISTERS CHANGED WHILE THIS RAN: another process wrote the run, or this replay did; do not trust this reading"}.`);
  out.push(`The run's stop policy: ${r.run.stop_policy ?? "unknown"}; its harness: ${r.run.harness_commit ?? "not recorded"}. Left out of the copy: ${r.copy.left_out.join(", ") || "nothing"}${r.copy.links_removed ? `; ${r.copy.links_removed} link(s) removed, not followed` : ""}.`);
  const letters = "AB";
  for (const [i, t] of r.targets.entries()) out.push(`${r.targets.length > 1 ? `${letters[i]}: ` : "Checkout: "}${t.commit ? t.commit.slice(0, 12) : "unknown commit"}, ${t.how}`);
  for (const e of r.evaluations) {
    const who = r.targets.length > 1 ? `${letters[r.targets.indexOf(e.target)]} (${e.target.commit?.slice(0, 12) ?? e.target.label})` : (e.target.commit?.slice(0, 12) ?? e.target.label);
    out.push("");
    out.push(`== ${who}, stop policy ${e.projection?.stop_policy ?? e.policy}${e.policy !== "as run" ? " (set for this replay)" : ""}`);
    if (!e.projection) {
      out.push(`  not evaluated: ${e.error}`);
      continue;
    }
    const p = e.projection;
    out.push(`  goal: from the ${p.goal.source ?? "nowhere"}; ${p.goal.checks} check(s), ${p.goal.answers_checks} answers check(s) replayed, ${p.goal.not_replayed} of the goal's own commands not run (read as passing)`);
    out.push(`  ${pad("question", 14)}${pad("result", 22)}${pad("check", 14)}${pad("disposition", 22)}${pad("readiness holds", 26)}${pad("defects", 24)}${pad("warnings", 30)}report`);
    for (const q of p.questions) {
      // A summary or a narrative has no disposition under the bar: only its outcome.
      const disp = q.check?.best_candidate ? "best candidate" : (q.gate?.disposition ?? q.check?.disposition ?? (q.gate ? `none (${q.gate.outcome})` : q.section.startsWith("question:") ? "none" : "-"));
      const report = q.report ? `${q.report.status}${q.report.best_candidate ? "; says best candidate" : ""}` : "-";
      out.push(`  ${pad(q.section, 14)}${pad(q.result ?? "-", 22)}${pad(q.check?.outcome ?? "-", 14)}${pad(disp, 22)}${pad(countWords(q.readiness).join(", ") || "-", 26)}${pad([...(q.check?.defects ?? []), ...(q.check?.named ?? []).map((c) => `${c} (named)`)].join(", ") || "-", 24)}${pad(countWords(q.warnings).join(", ") || "-", 30)}${report}`);
    }
    if (p.readiness) out.push(`  readiness: ${p.readiness.ready ? "ready" : `not ready, ${p.readiness.items.length} item(s): ${countWords(p.readiness.items.map((i) => i.code)).join(", ")}`}; ${p.readiness.limited} line(s) limit the run; ${p.readiness.warnings} warning(s)`);
    if (p.gate) out.push(`  gate: ${p.gate.error ? `unavailable (${p.gate.error})` : `${p.gate.defects.length ? countWords(p.gate.defects.map((d) => d.code)).join(", ") : "no defect"}; ${p.gate.holding} holding`}`);
    out.push(`  verdict: ${verdictWords(p.verdict)}`);
    if (p.finish) out.push(`  finish: ${p.finish.lease ? `${p.finish.lease.holder} coordinates at generation ${p.finish.lease.generation}` : "no coordinator yet"}; ${p.finish.late.length ? `late against the report: ${p.finish.late.map((x) => `${x.kind} ${x.id} by ${x.by}${x.tag ? ` (${x.tag})` : ""}`).join("; ")}` : "nothing late"}; ${p.finish.last_check ? `the last check ${p.finish.last_check.proceed ? `proceeded (${p.finish.last_check.outcome})` : "held"}${p.finish.last_check.current ? " at this revision" : ""}; ` : ""}the done ${p.finish.done}${p.finish.held_by.length ? ` (${p.finish.held_by.join(", ")})` : ""}`);
    out.push(`  seals: ${p.seals.verdicts ? `${p.seals.hold} of ${p.seals.verdicts} custody verdict(s) hold as a prefix${p.seals.broken.map((b) => `; ${b.verdict} does not: ${b.broken.join("; ")}`).join("")}` : "no custody verdict in the run"}`);
    out.push(`  agreement: ${p.agreement.length ? `readiness, the answers check and the gate disagree: ${p.agreement.map((g) => `${g.section} ${g.kind}`).join("; ")}` : "readiness, the answers check and the gate agree on every question"}${p.warnings_hold.length ? `; a warning holds: ${p.warnings_hold.join(", ")}` : ""}`);
    for (const x of p.errors) out.push(`  not evaluated: ${x}`);
    if (p.text) {
      out.push("  --show-text: the harness's lines, whole (they quote records):");
      for (const [k, lines] of Object.entries(p.text)) for (const l of ([] as Array<string | null>).concat(lines as never)) if (l) out.push(`    [${k}] ${l}`);
    }
  }
  if (r.differences) {
    out.push("");
    const letters2 = `${letters[0]} → ${letters[1]}`;
    out.push(r.differences.length ? `== Differences, ${letters2}` : `== No difference, ${letters2}`);
    for (const d of r.differences) out.push(`  ${d.policy !== "as run" ? `[${d.policy}] ` : ""}${d.section ? `${d.section} ` : ""}${d.field}: ${d.a} → ${d.b}`);
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------------------------

const USAGE = "usage: replay.ts <run-dir | run-id> [--registry FILE] [--checkout PATH] [--compare [A [B]]] [--stop-policy P[,P…]] [--json] [--show-text]";

async function evaluateMain(args: string[]): Promise<void> {
  const harness = args[args.indexOf("--harness") + 1];
  const showText = args.includes("--show-text");
  const copies = args.flatMap((a, i) => (a === "--sandbox" ? [args[i + 1]] : []));
  const out: Array<Projection | { error: string }> = [];
  for (const S of copies) {
    // The registry the goal is read from is the replay's own, beside the copy.
    process.env.SWARM_RUNS_DIR = dirname(S);
    try {
      out.push(await project(harness, S, { showText }));
    } catch (e) {
      out.push({ error: (e as Error).message });
    }
  }
  process.stdout.write(`${JSON.stringify(out)}\n`);
}

async function main(argv: string[]): Promise<number> {
  if (argv.includes("--evaluate")) {
    await evaluateMain(argv);
    return 0;
  }
  let runArg: string | null = null;
  let registry: string | null = null;
  let checkout: string | null = null;
  let compare: string[] | null = null;
  let policies: StopPolicy[] | null = null;
  let json = false;
  let showText = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--registry") registry = argv[++i] ?? null;
    else if (a === "--checkout") checkout = argv[++i] ?? null;
    else if (a === "--compare") {
      compare = [];
      while (compare.length < 2 && argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) {
        // The run is named first; after it, what follows --compare are checkouts.
        if (runArg === null) break;
        compare.push(argv[++i]);
      }
    } else if (a === "--stop-policy") {
      const list = (argv[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
      const bad = list.filter((p) => !(STOP_POLICIES as readonly string[]).includes(p));
      if (!list.length || bad.length) {
        process.stderr.write(`--stop-policy takes ${STOP_POLICIES.join(", ")} (one, or several with commas)${bad.length ? `, not ${bad.join(", ")}` : ""}\n`);
        return 2;
      }
      policies = list as StopPolicy[];
    } else if (a === "--json") json = true;
    else if (a === "--show-text") showText = true;
    else if (a === "-h" || a === "--help") {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    } else if (a.startsWith("--")) {
      process.stderr.write(`unknown option ${a}\n${USAGE}\n`);
      return 2;
    } else if (runArg === null) runArg = a;
    else {
      process.stderr.write(`one run at a time (${runArg}, then ${a}); a checkout is given with --checkout or --compare\n${USAGE}\n`);
      return 2;
    }
  }
  if (!runArg) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const scratch = await mkdtemp(join(tmpdir(), "dfs-replay-"));
  try {
    const run = await resolveRun(runArg, registry);
    const current = checkout ? resolve(checkout) : ROOT;
    const named = async (p: string): Promise<Target> => {
      if (p === "frozen") return frozenHarness(run, scratch);
      const path = resolve(p);
      const problem = checkoutProblem(path);
      if (problem) throw new Error(problem);
      return { label: p, harness: path, how: path === ROOT ? `this checkout (${path})` : `the checkout at ${path}`, commit: harnessCommit(path) };
    };
    const targets: Target[] = compare === null ? [await named(current)] : compare.length === 0 ? [await named("frozen"), await named(current)] : compare.length === 1 ? [await named(compare[0]), await named(current)] : [await named(compare[0]), await named(compare[1])];
    const r = await replay({ run, targets, policies, showText, scratch });
    process.stdout.write(json ? `${JSON.stringify(r, null, 2)}\n` : `${replayWords(r)}\n`);
    return r.unchanged && r.evaluations.every((e) => e.projection) ? 0 : 1;
  } catch (e) {
    process.stderr.write(`replay: ${(e as Error).message}\n`);
    return 1;
  } finally {
    spawnSync("chmod", ["-R", "u+w", scratch]);
    await rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
