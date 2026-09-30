#!/usr/bin/env node
/**
 * Replay: a finished run's registers read again by a given harness's finish
 * machinery, to measure a rule change on recorded histories (docs/adr/0017,
 * "Measuring a rule change").
 *
 *   node --experimental-strip-types scripts/replay.ts <run-dir | run-id> [--registry FILE]
 *        [--checkout PATH] [--compare [A [B]]] [--stop-policy P[,P…]] [--deliveries] [--prepare-as STATE] [--reverse-sweep] [--resweep] [--presumes Q[,Q…]] [--json] [--show-text]
 *   swarm.sh replay <run> [--checkout PATH] [--compare [A [B]]] [--stop-policy P] [--deliveries] [--prepare-as STATE] [--reverse-sweep] [--resweep] [--presumes Q[,Q…]] [--json]
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
 * line's verdict, readiness, the finish register (the coordinator, its
 * resume segment and what it carries, what is late against the report, the
 * coordinator's prepares, the resolutions and their batches, the last
 * check), the report's per-question
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
 * Where the checkout reads the sources' broad extractions (the store
 * journal's preparation receipts, extensions/preparation.ts), the
 * projection shows each source's state, capability by capability, and the
 * questions held or warned on it (docs/adr/0013, "A source's broad
 * extraction before a negative on it"). `--prepare-as STATE` asks what a
 * run from before the receipts would have met: this checkout's census asks
 * its packs' broad extractions about the run's own evidence (read, never
 * written; the run's packs, by id, as this checkout ships them), and each
 * copy gets a synthetic receipt per source and capability that applies, in
 * STATE (planned, attempted, produced, partial, failed or declined; one its
 * pack declares the images cannot run is declined, as the hub would record
 * it), by "replay", before it is evaluated.
 *
 * The source-first review rule (docs/adr/0015): where the checkout has it,
 * the projection counts the recorded established attests of answers that
 * claim established and names each the rule would cap, with its codes
 * (no_discriminator, locator_unverified, derivation_unverified; a checkout
 * before the Fable review of the limits branch capped
 * no_locator_or_derivation too), and each it would warn and not cap
 * (no_locator_or_derivation, `warned`). The recorded strengths are the
 * run's and stay as they were: this says what the rule would have done at
 * each attest.
 * Each evidence addition's reverse sweep (docs/adr/0013), counted per
 * question; `--reverse-sweep` gives an addition that has none (a run from
 * before it) the line this checkout's store sweep computes over the copy's
 * import, from the coverage records standing at the addition.
 *
 * Each coverage record's store sweep as the checkout reads it (the latest
 * line for it), after the checkout's answers check ran (which, from the
 * harness that records the sweep's rules version on each line, reads a
 * line recorded under older rules again under its own, a line of its own
 * in the copy, as a hub that starts does: store-sweep.ts rereadSweeps):
 * how many hits, named hits and echoes. `--resweep` reads the
 * copy's recorded sweeps again with this checkout's store sweep
 * (store-sweep.ts resplitSweep): each recorded hit whose object the record
 * names under another name of the same bytes, or whose makers make it an
 * echo or a reading of what the record names (docs/adr/0013, "Echoes:
 * authored, not derived"), is moved, and the record gets a synthetic line on
 * the copy's chain; nothing is searched again, and a line that moves
 * nothing is not added.
 *
 * `--presumes Q[,Q…]` asks what the premise rule (docs/adr/0011, "What a
 * question presumes") would have asked of a run from before it: each
 * question named is amended in every copy, by this checkout's register, as
 * the operator would amend it with `--presumes`, to presume "the event
 * question <n> asks about happened" (synthetic words; the run untouched).
 * The projection then shows the partial answers warned (premise_untested),
 * and the review rule's caps name each established attest it would cap
 * (premise_untested); the recorded strengths stay the run's. A checkout
 * before the rule reads the amendment as nothing.
 *
 * `--deliveries` reads where the checkout delivers the answers check's
 * warnings (docs/adr/0013, "Warnings where the decision is made"), act by
 * act: each act's registers cut to the moment of the act in a scratch
 * directory (a chain cut at a line is a prefix of it), and the checkout's
 * own warningsAt asked what the reply to each answer's record, each review
 * offered for an answer, the reply to each attest and the reply to each
 * seat's close or confirmation of a lead would carry then; and finish
 * status at the end (deliveriesOf).
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
  /** Each warning on it with the entries it names beside the answer (ids only), when the checkout's readiness gives its warnings whole. */
  warned?: Array<{ code: string; entries: number[] }>;
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
    /** The coordinator's lease; `segment` and `carried` (how many posts it carries from before a resume) where the checkout's register reads them and they are set. */
    lease: { holder: string; generation: number; segment?: number; carried?: number } | null;
    late: Array<{ kind: string; id: number; by: string; tag: string | null }>;
    /**
     * The coordinator's prepares (docs/adr/0015, "Preparing the finish"), as
     * the checkout's finish register reads them: how many, and the last (by
     * whom, at which generation, how many items it was given as late, and
     * whether the lease and the report still stand as it prepared them);
     * null for a checkout that does not read them.
     */
    prepared: { count: number; last: { by: string; generation: number; late: number; current: boolean } | null } | null;
    /** The typed resolutions in the register, and how many batches (finish resolve with items) they came in; batches null for a checkout that does not read them. */
    resolutions: { count: number; batches: number | null };
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
  /** With --deliveries: where the checkout delivers the warnings, act by act (deliveriesOf). */
  deliveries?: Deliveries;
  /**
   * The sources' broad extractions, as the checkout reads the store
   * journal's receipts (extensions/preparation.ts): each source with each
   * capability's newest state and the outcome a negative is weighed
   * against, and the questions a preparation holds (preparation_pending) or
   * warns (preparation_missing), each with the sources. Null for a checkout
   * that does not read them.
   */
  preparation?: PreparationProjection | null;
  /**
   * The established attests of answers that claim established, as the
   * checkout's source-first rule reads each recorded review
   * (protocol.ts reviewEvidenceCaps, docs/adr/0015): how many there are,
   * and each the rule would cap, by the answer's section and seq, the
   * attesting seat, whether the answer still stands, whether the question
   * is material, and the codes. The recorded strengths are the run's own
   * and are not changed: this says what the rule would have done at each
   * attest. Null for a checkout without the rule.
   */
  review_caps?: { established: number; capped: Array<{ section: string; answer: number; by: string; standing: boolean; material: boolean; codes: string[] }>; warned?: Array<{ section: string; answer: number; by: string; standing: boolean; material: boolean; codes: string[] }> } | null;
  /**
   * Each evidence addition's reverse sweep, as the checkout reads the
   * copy's sweeps (store-sweep.ts readImportSweeps, docs/adr/0013): the
   * addition's entry and import, whether replay synthesised the line
   * (--reverse-sweep), its state, how many standing coverage records and
   * strings it searched for, how many objects it read, and per question
   * the hit objects and occurrences. Counts only, never a string. Null for
   * a checkout that reads none.
   */
  late_evidence?: Array<{ addition: number; import: string; synthetic: boolean; state: string; records: number; terms: number; objects: number; questions: Array<{ section: string; objects: number; occurrences: number }> }> | null;
  /**
   * Each coverage record's store sweep as the checkout reads the copy's
   * sweeps (store-sweep.ts readSweeps, the latest line for each record),
   * after its answers check ran: how many records named looked_for, how
   * many are swept, how many of those lines replay synthesised
   * (--resweep), how many the checkout's own answers check read again
   * under its rules because they were recorded under older ones
   * (`reread`, reconcileSweeps; absent for a checkout that does not), and
   * over the latest lines the hits, the named hits and the echoes, and the
   * records with hits. Counts only. Null for a checkout that reads none.
   */
  store_sweeps?: { records: number; swept: number; resplit: number; reread?: number; hits: number; named: number; echoes: number; with_hits: number } | null;
  /** The report's reviews replayed under the checkout's carry rule (reviewsOf): null for a checkout without it, or a run with no review of a report in history. */
  reviews?: ReviewReplay | null;
  /** What could not be evaluated, in the harness's or node's words. */
  errors: string[];
  /** The harness's lines whole (they quote records): only with --show-text. */
  text?: { check: string[]; readiness: string[]; limited: string[]; gate: string[]; verdict: string | null; warnings: string[] };
};

/**
 * Where a checkout delivers the answers check's warnings (docs/adr/0013,
 * "Warnings where the decision is made"), read act by act on the registers
 * as they stood at each act: the reply to every record of a question's
 * answer, every review offered for an answer, the reply to every attest,
 * the reply to every seat's close or confirmation of a lead, and finish
 * status at the end. Only the acts that carry a warning are
 * listed; `acts` counts every act read. Ids, codes and sections only.
 */
export type Delivery = { point: "record" | "review_offer" | "attest" | "lead_close" | "finish_status"; entry: number | null; lead?: string; on: string | null; by: string | null; at: string | null; sections: string[]; warnings: string[] };
export type Deliveries = { acts: { record: number; review_offer: number; attest: number; lead_close: number }; delivered: Delivery[]; error: string | null };

/**
 * The report's reviews under the carry rule (docs/adr/0015, "A review
 * carries over"), counts and seats only. `whole`: each recorded ack read as
 * the review a seat gives by naming no sections (the whole report at its
 * version); `scoped`: the what-if in which each seat's ack named only the
 * sections numbered by the questions it answered (a seat that answered
 * none reviews the whole report).
 */
export type ReviewReplay = {
  /** The report's versions in history/, and how many of them were reviewed (an ack of their digest). */
  versions: number;
  reviewed: number;
  acks: { total: number; no_objection: number; objection: number; unmapped: number };
  /** No-objection acks by a seat that had given one on an earlier version, and of those, the ones the rule finds standing already (their sections unchanged: not asked again). */
  reacks: { recorded: number; standing_whole: number; standing_scoped: number };
  /** Sections the recorded re-reviews covered (the whole report each time) against those the rule asks for (only what changed). */
  section_reviews: { recorded: number; asked_whole: number };
  /** Each reviewed version after the first: its sections, how many changed from the version reviewed before it, the re-reviews recorded on it, and the seats the rule asks again. */
  rounds: Array<{ version: number; sections: number; changed: number; reacks: number; asked_whole: number; asked_scoped: number }>;
  /** Result posts resolved as late items that their author made within two minutes after its own ack: an ack announced on the board. */
  echoes: number;
};

/** The sources' broad extractions, per source and capability, and the questions held or warned on them (ids and states only). */
export type PreparationProjection = {
  sources: Array<{ source: string; pending: boolean; produced: boolean; capabilities: Array<{ capability: string; recipe: string; state: string; outcome: string; released: boolean; by: string; synthetic: boolean }> }>;
  held: Array<{ section: string; sources: string[] }>;
  warned: Array<{ section: string; sources: string[] }>;
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

/** Each warning's words, as every harness version since it was added says it (a later wording beside the earlier). */
const WARNING_CODES: ReadonlyArray<[string, RegExp]> = [
  ["no_acquisition_ask", /is not determinable, and .*no acquisition ask/],
  ["partial_all_parts_established", /is partial, and every review holds every part it weighed established/],
  ["partial_all_parts_established", /is partial, and every part of the question its reviews weighed is established/],
  ["lead_findings_uncited", /established under \S+'s leads and not in its answer/],
  ["lead_findings_uncited", /\) leaves out what two seats hold for \S+:/],
  ["lead_findings_uncited", /\) leaves out what the record ties to \S+:/],
  ["preparation_missing", /weighed without a produced broad extraction of what it rests on/],
  ["late_evidence_hits", /does not reach what the reverse sweep of evidence added late found for/],
  ["premise_disputed", /\) assumes P-\d+ .*: the premise is disputed before the operator/],
  ["premise_revised", /\) cites P-\d+ at revision \d+, revised to \d+ since/],
  ["premise_withdrawn", /\) cites P-\d+, withdrawn at /],
  ["premise_inconsistent", /\) (?:assumes|contradicts) P-\d+ \(revision \d+\), which #\d+ .*over scopes that overlap \(a question not material: warned, never held\)/],
  ["part_omitted", /\) leaves out (?:a part|parts) of the question its reviews? names?:/],
  ["no_locator_or_derivation", /\) is held established by .* on a review that vouches for no value by bytes or by derivation/],
  ["premise_untested", /\) is partial on a question that presumes .*, and neither it nor a review of it tests that premise/],
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
export async function project(harness: string, S: string, o: { showText?: boolean; deliveries?: boolean } = {}): Promise<Projection> {
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
  type Ready = { ready: boolean; revision: string; items: string[]; limited: string[]; warnings?: string[]; warned?: Array<{ code: string; section: string; seqs: number[] }> };
  const ready = (await guard("readiness", async () => (await fn(FIN, "readiness")!(S)) as Ready)) as Ready | null;
  type FinState = { lease: { holder: string; generation: number; report: string | null; segment?: number; carried?: unknown[] } | null; checks: Array<{ revision: string; proceed: boolean; outcome?: string }>; resolutions?: Array<{ batch?: string }>; prepares?: Array<{ by: string; generation: number; digest: string | null; late: unknown[] }> };
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
      ...(ready?.warned ? { warned: ready.warned.filter((w) => questionKey(w.section) === section).map((w) => ({ code: w.code, entries: w.seqs.slice(1) })) } : {}),
      report: status ? { status: status.status, best_candidate: reportBest.has(section) } : null,
    };
  });

  // Readiness, the answers check and the gate on each question. The gate
  // holds a question it gives no disposition, or one a defect of its own
  // names (a lead serving it still open, a question defect on it); readiness
  // holds it by an item on it. Under the operator's stop policy readiness
  // holds a route limitation too, which only limits the done (docs/adr/0015,
  // 7 and 8): by design, never counted as a disagreement. An answer the
  // check reads as answered while one of its own defects holds it (a
  // bounded negative that says the event did not happen, held on its
  // source's broad extraction) has no disposition in the check: the gate
  // reads the outcome, and the finish line holds it through the check's
  // verdict. The finish line holds it, as readiness does. So does a
  // question the operator accepted while the check still holds a defect on
  // it: the gate reads it accepted, and the check's verdict refuses the
  // done (the class the Fable review of the limits branch found, P1-1).
  const agreement: Array<{ section: string; kind: string }> = [];
  const finalOutcome = (o: string) => ["answered", "accepted", "withdrawn"].includes(o);
  const heldThrough = (o: string) => o === "answered" || o === "accepted";
  for (const q of questions) {
    if (!q.gate || !q.section.startsWith("question:")) continue;
    const disposed = Boolean(q.gate.disposition) || finalOutcome(q.gate.outcome);
    const heldByCheck = heldThrough(q.gate.outcome) && (q.check?.defects.length ?? 0) > 0;
    const gateHolds = !disposed || heldByCheck || (gate?.defects ?? []).some((d) => gateSections(d).includes(q.section));
    const readyHolds = q.readiness.some((c) => c !== "route_limitation");
    if (ready && readyHolds && !gateHolds) agreement.push({ section: q.section, kind: "readiness_holds_disposed" });
    if (ready && !readyHolds && gateHolds) agreement.push({ section: q.section, kind: "readiness_clear_held" });
    if (q.check?.disposition && q.gate.disposition && q.check.disposition !== q.gate.disposition) agreement.push({ section: q.section, kind: "check_gate_disposition" });
    if (q.check?.disposition && !q.gate.disposition && !finalOutcome(q.gate.outcome)) agreement.push({ section: q.section, kind: "gate_holds_check_disposed" });
    if (q.check?.best_candidate && q.gate.disposition) agreement.push({ section: q.section, kind: "gate_disposes_best_candidate" });
  }
  if (ready && gate && !gate.error) {
    // A question the check reads as answered while one of its own defects holds it is held through the check's verdict, as above (two answers that assume and contradict one premise revision: premise_inconsistent).
    const heldThroughCheck = questions.some((q) => q.gate && heldThrough(q.gate.outcome) && (q.check?.defects.length ?? 0) > 0);
    const gateClear = !gate.defects.length && !(gate.holding ?? []).length && gate.questions.every((q) => q.disposition || finalOutcome(q.outcome)) && !heldThroughCheck;
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

  // The coordinator's prepares and the batches of resolutions, where the checkout's finish register reads them.
  const lastPrepare = fin?.prepares?.at(-1);
  const reportNow = fin?.lease?.report && fn(FIN, "reportDigest") ? ((await guard("the report's digest", async () => fn(FIN, "reportDigest")!(S, fin.lease!.report))) as string | null) : null;
  const prepared = fin && Array.isArray(fin.prepares) ? { count: fin.prepares.length, last: lastPrepare ? { by: lastPrepare.by, generation: lastPrepare.generation, late: lastPrepare.late.length, current: lastPrepare.generation === fin.lease?.generation && lastPrepare.digest !== null && lastPrepare.digest === reportNow } : null } : null;
  const resolutions = { count: fin?.resolutions?.length ?? 0, batches: fin && Array.isArray(fin.prepares) ? new Set((fin.resolutions ?? []).map((r) => r.batch).filter(Boolean)).size : null };

  const seals = await sealCheck(harness, S, errors);
  const delivered = o.deliveries ? await deliveriesOf(S, FIN, ready) : undefined;
  const preparation = await guard("the preparations", () => preparationOf(harness, S));
  const reviewCaps = await guard("the review rule", () => reviewCapsOf(P, S));
  const lateEvidence = await guard("the reverse sweeps", () => lateEvidenceOf(SW, S));
  const storeSweeps = await guard("the store sweeps", () => storeSweepsOf(SW, P, S));
  const reviews = await guard("the report's reviews", () => reviewsOf(FIN, P, S));
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
          lease: fin.lease ? { holder: fin.lease.holder, generation: fin.lease.generation, ...(fin.lease.segment ? { segment: fin.lease.segment } : {}), ...(Array.isArray(fin.lease.carried) && fin.lease.carried.length ? { carried: fin.lease.carried.length } : {}) } : null,
          late: late.map((x) => ({ kind: x.kind, id: x.id, by: x.by, tag: x.tag ?? null })),
          prepared,
          resolutions,
          last_check: last ? { proceed: last.proceed, outcome: last.outcome ?? null, current: Boolean(ready && last.revision === ready.revision) } : null,
          done: heldBy.length ? "held" : "proceeds",
          held_by: heldBy,
        }
      : null,
    agreement,
    warnings_hold: warningsHold,
    seals,
    ...(delivered ? { deliveries: delivered } : {}),
    preparation,
    review_caps: reviewCaps,
    late_evidence: lateEvidence,
    store_sweeps: storeSweeps,
    reviews,
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
 * The sources' broad extractions as the checkout reads the copy's store
 * journal (extensions/preparation.ts): every source and capability, and,
 * for each standing answer to a question the checkout's gate holds or warns
 * on a preparation, the sources it does so for. Null for a checkout that
 * reads no receipts. Refs and states only.
 */
async function preparationOf(harness: string, S: string): Promise<PreparationProjection | null> {
  const PRm = await importFrom(harness, "extensions/preparation.ts");
  const Pm = await importFrom(harness, "extensions/protocol.ts");
  const need = ["readReceipts", "foldPreparation", "preparationFacts", "preparationFindings"];
  if (!PRm || !Pm || need.some((n) => !fn(PRm, n)) || !fn(Pm, "readLedger") || !fn(Pm, "citedForQuestion") || !fn(Pm, "supersededBy")) return null;
  type Src = { source: { ref: string; name: string; sha256: string }; pending: boolean; produced: boolean; capabilities: Array<{ capability: string; recipe: string; state: string; outcome: string; released: boolean; latest: { by: string }; decisive: { by: string } }> };
  const receipts = (await fn(PRm, "readReceipts")!(S)) as unknown[];
  const sources = (await fn(PRm, "foldPreparation")!(receipts)) as Map<string, Src>;
  const entries = (await fn(Pm, "readLedger")!(S)) as Array<{ seq: number; kind: string; section?: string; hash?: string; support?: unknown }>;
  const facts = (await fn(PRm, "preparationFacts")!(S, entries)) as { sources: Map<string, Src> };
  const replaced = (await fn(Pm, "supersededBy")!(entries)) as Map<number, number>;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const held: PreparationProjection["held"] = [];
  const warned: PreparationProjection["warned"] = [];
  const name = (x: Src) => x.source.ref || `sha256:${x.source.sha256}`;
  for (const a of entries) {
    if (a.kind !== "answer" || replaced.has(a.seq) || !a.section?.startsWith("question:")) continue;
    const raw = a.section.slice("question:".length);
    const id = fn(Pm, "sectionKey") ? String(fn(Pm, "sectionKey")!(raw)) : raw;
    const cited = (await fn(Pm, "citedForQuestion")!(a, bySeq, replaced, id)) as Array<{ kind: string }>;
    const found = (await fn(PRm, "preparationFindings")!(a, cited.filter((c) => c.kind === "coverage"), facts)) as { hold: Array<{ source: Src }>; warn: Array<{ source: Src }> };
    if (found.hold.length) held.push({ section: a.section, sources: found.hold.map((h) => name(h.source)) });
    if (found.warn.length) warned.push({ section: a.section, sources: found.warn.map((w) => name(w.source)) });
  }
  return {
    sources: [...sources.values()]
      .map((x) => ({ source: name(x), pending: x.pending, produced: x.produced, capabilities: x.capabilities.map((c) => ({ capability: c.capability, recipe: c.recipe, state: c.state, outcome: c.outcome, released: c.released, by: c.decisive.by, synthetic: c.latest.by === "replay" })) }))
      .sort((a, b) => a.source.localeCompare(b.source)),
    held,
    warned,
  };
}

/**
 * The checkout's source-first review rule over each recorded established
 * attest of an answer that claims established (reviewEvidenceCaps): the
 * codes it would cap each for. Locators are read against the copy, which
 * leaves the evidence out: a locator into an input cannot be read there,
 * and says so. Ids and codes only. Null for a checkout without the rule.
 */
async function reviewCapsOf(Pm: Mod | null, S: string): Promise<Projection["review_caps"]> {
  const rule = fn(Pm, "reviewEvidenceCaps");
  if (!rule || !fn(Pm, "readLedger") || !fn(Pm, "readAttestations") || !fn(Pm, "claimsEstablished")) return null;
  type E = { seq: number; kind: string; section?: string; hash?: string; by: string; authors: string[] };
  type A = { v?: number; act?: string; target?: string; by: string; strength?: string; answer_review?: unknown };
  const entries = (await fn(Pm, "readLedger")!(S)) as E[];
  const atts = (await fn(Pm, "readAttestations")!(S)) as A[];
  const replaced = (await fn(Pm, "supersededBy")!(entries)) as Map<number, number>;
  const byHash = new Map(entries.filter((e) => e.hash).map((e) => [e.hash!, e]));
  const material = new Map<string, boolean>();
  const out: NonNullable<Projection["review_caps"]> = { established: 0, capped: [] };
  for (const a of atts) {
    if (a.v !== 2 || a.act !== "attest" || a.strength !== "established" || !a.answer_review || !a.target) continue;
    const e = byHash.get(a.target);
    if (!e || e.kind !== "answer" || !e.section?.startsWith("question:") || !fn(Pm, "claimsEstablished")!(e)) continue;
    out.established += 1;
    if (!material.has(e.section)) {
      const id = fn(Pm, "sectionAnswersId") ? String(fn(Pm, "sectionAnswersId")!(e.section)) : e.section.slice("question:".length);
      const bar = fn(Pm, "questionBar") ? ((await Promise.resolve(fn(Pm, "questionBar")!(S, id)).catch(() => null)) as { material: boolean } | null) : null;
      material.set(e.section, bar?.material ?? true);
    }
    const r = (await rule(S, e, a.answer_review, { material: material.get(e.section)!, entries })) as { caps: Array<{ code: string }>; unlocated?: { code: string } | null };
    const codes = [...new Set(r.caps.map((c) => c.code))].sort();
    const row = { section: e.section, answer: e.seq, by: a.by, standing: !replaced.has(e.seq), material: material.get(e.section)! };
    if (codes.length) out.capped.push({ ...row, codes });
    // What the checkout warns of and does not cap (a review with neither a locator nor a derivation): a checkout whose rule capped it has no `unlocated`.
    if (r.unlocated) (out.warned ??= []).push({ ...row, codes: [r.unlocated.code] });
  }
  return out;
}

/**
 * The report's reviews replayed under the checkout's carry rule
 * (docs/adr/0015, "A review carries over"; its reportSections and
 * reviewStanding): the run's acks in order, each mapped by its digest to a
 * version of the report in history/ and read as the rule reads it, an ack
 * from before per-section reviews as the whole report at its version (and,
 * as the scoped what-if, as the sections numbered by the questions its seat
 * answered). Before each no-objection ack by a seat that had given one on an
 * earlier version, the rule is asked whether that seat's review stood
 * already (it would not have been asked again) and, when it did not, on how
 * many sections it is asked again. Each reviewed version after the first is
 * a review round the rule needs when it asks anyone again over the acks
 * before it. A late post resolved that its author made within two minutes
 * after its own ack is an echo. Counts and seats only, never a section's
 * words. Null for a checkout without the rule, or a run with no ack of a
 * report version in history.
 */
export async function reviewsOf(FIN: Mod | null, Pm: Mod | null, S: string): Promise<ReviewReplay | null> {
  const sectionsOf = fn(FIN, "reportSections");
  const standing = fn(FIN, "reviewStanding");
  if (!sectionsOf || !standing || !fn(FIN, "readFinish") || !fn(Pm, "listFileHistory") || !fn(Pm, "readFileVersion")) return null;
  type Ack = { seq: number; at: string; by: string; digest: string; verdict: string; why: string; report?: string; sections?: Record<string, string>; whole?: boolean };
  type Sec = { key: string; title: string; digest: string };
  type Seat = { by: string; standing: string; changed: string[]; removed: string[] };
  const st = (await fn(FIN, "readFinish")!(S)) as { lease: { report: string | null } | null; acks: Ack[]; resolutions: Array<{ post?: number }> };
  const report = st.lease?.report ?? st.acks.find((a) => a.report)?.report ?? null;
  if (!report || !st.acks.length) return null;
  const history = (await fn(Pm, "listFileHistory")!(S, report)) as Array<{ rev: number; sha256?: string; stored?: boolean }>;
  const versions: Array<{ i: number; digest: string; sections: Sec[] }> = [];
  for (const v of history) {
    if (v.stored === false || !v.sha256) continue;
    const got = (await Promise.resolve(fn(Pm, "readFileVersion")!(S, report, v.rev)).catch(() => null)) as { text: string } | null;
    if (got) versions.push({ i: versions.length, digest: v.sha256, sections: sectionsOf(got.text) as Sec[] });
  }
  const byDigest = new Map(versions.map((v) => [v.digest, v]));
  // The what-if's scope: the sections numbered by the questions each seat answered.
  const scope = new Map<string, Set<string>>();
  for (const e of fn(Pm, "readLedger") ? ((await fn(Pm, "readLedger")!(S)) as Array<{ kind: string; by: string; section?: string }>) : []) {
    const n = e.kind === "answer" ? /^question:(\d+)$/.exec(e.section ?? "")?.[1] : undefined;
    if (n) scope.set(e.by, new Set([...(scope.get(e.by) ?? []), n]));
  }
  const acks = [...st.acks].filter((a) => !a.report || a.report === report).sort((a, b) => a.seq - b.seq);
  const out: ReviewReplay = { versions: versions.length, reviewed: 0, acks: { total: acks.length, no_objection: 0, objection: 0, unmapped: 0 }, reacks: { recorded: 0, standing_whole: 0, standing_scoped: 0 }, section_reviews: { recorded: 0, asked_whole: 0 }, rounds: [], echoes: 0 };
  const whole: Array<Ack & { v: number }> = [];
  const scoped: Array<Ack & { v: number }> = [];
  const reviewedBefore = new Set<string>();
  const seatOf = (list: Ack[], v: { digest: string; sections: Sec[] }, by: string) => ((standing(list, report, { digest: v.digest, sections: v.sections }) as { seats: Seat[] }).seats.find((x) => x.by === by) ?? null);
  const acked = new Set<number>();
  for (const a of acks) {
    if (a.verdict === "objection") out.acks.objection += 1;
    else out.acks.no_objection += 1;
    const v = byDigest.get(a.digest);
    if (!v) {
      out.acks.unmapped += 1;
      continue;
    }
    // A reviewed version after the first: the round the rule needs, over the acks before it.
    if (!acked.has(v.i) && acked.size) {
      const before = (xs: Array<Ack & { v: number }>) => xs.filter((x) => x.v < v.i);
      const prev = versions[Math.max(...[...acked].filter((i) => i < v.i), -1)];
      const reasked = (xs: Array<Ack & { v: number }>) => (standing(before(xs), report, { digest: v.digest, sections: v.sections }) as { seats: Seat[] }).seats.filter((x) => x.standing === "reasked").length;
      const was = new Map((prev?.sections ?? []).map((x) => [x.key, x.digest]));
      out.rounds.push({ version: v.i + 1, sections: v.sections.length, changed: v.sections.filter((x) => was.get(x.key) !== x.digest).length + [...was.keys()].filter((k) => !v.sections.some((x) => x.key === k)).length, reacks: 0, asked_whole: reasked(whole), asked_scoped: reasked(scoped) });
    }
    acked.add(v.i);
    const all = Object.fromEntries(v.sections.map((x) => [x.key, x.digest]));
    const asWhole = a.sections ? a : { ...a, sections: all, whole: true };
    const keys = [...(scope.get(a.by) ?? [])].filter((k) => k in all);
    const asScoped = a.sections ? a : keys.length ? { ...a, sections: Object.fromEntries(keys.map((k) => [k, all[k]])) } : asWhole;
    if (a.verdict === "no_objection" && reviewedBefore.has(a.by)) {
      out.reacks.recorded += 1;
      const w = seatOf(whole, v, a.by);
      if (w && w.standing !== "reasked") out.reacks.standing_whole += 1;
      const sc = seatOf(scoped, v, a.by);
      if (sc && sc.standing !== "reasked") out.reacks.standing_scoped += 1;
      out.section_reviews.recorded += Object.keys(asWhole.sections!).length;
      out.section_reviews.asked_whole += !w ? v.sections.length : w.standing === "reasked" ? w.changed.length + w.removed.length : 0;
      const round = out.rounds.find((r) => r.version === v.i + 1);
      if (round) round.reacks += 1;
    }
    if (a.verdict === "no_objection") reviewedBefore.add(a.by);
    whole.push({ ...asWhole, v: v.i });
    scoped.push({ ...asScoped, v: v.i });
  }
  out.reviewed = acked.size;
  // Echoes: a resolved late post its author made within two minutes after its own ack (the trace's post rows give each post's time).
  const resolved = new Set(st.resolutions.map((r) => r.post).filter((x): x is number => typeof x === "number"));
  if (resolved.size) {
    const trace = await readFile(join(S, "traces", "events.jsonl"), "utf8").catch(() => "");
    for (const line of trace.split("\n")) {
      if (!line.includes('"tool":"post"')) continue;
      let row: { ts?: string; agent?: string; tool?: string; result?: { ok?: boolean; id?: unknown } };
      try {
        row = JSON.parse(line);
      } catch {
        continue;
      }
      const id = Number(row.result?.id);
      if (row.tool !== "post" || row.result?.ok !== true || !resolved.has(id)) continue;
      const t = Date.parse(row.ts ?? "");
      if (acks.some((a) => a.by === row.agent && t - Date.parse(a.at) >= 0 && t - Date.parse(a.at) <= 120_000)) {
        out.echoes += 1;
        resolved.delete(id);
      }
    }
  }
  return out;
}

/** The report's reviews under the carry rule, values-free: counts and seats. */
function reviewWords(r: ReviewReplay): string[] {
  const out = [`  reviews (the carry rule over the recorded acks): ${r.acks.total} ack(s) (${r.acks.no_objection} no objection, ${r.acks.objection} objection${r.acks.unmapped ? `, ${r.acks.unmapped} of a version not in history` : ""}) over ${r.reviewed} reviewed version(s) of ${r.versions}; ${r.reacks.recorded} re-review(s) of a later version, of which the rule finds ${r.reacks.standing_whole} standing already as recorded (whole report) and ${r.reacks.standing_scoped} had each seat named its own questions' sections; ${r.section_reviews.recorded} section review(s) in the re-reviews, ${r.section_reviews.asked_whole} asked again by the rule; ${r.echoes} resolved late post(s) announcing their author's ack`];
  for (const x of r.rounds) out.push(`    version ${x.version}: ${x.changed} of ${x.sections} section(s) changed since the version reviewed before; ${x.reacks} re-review(s) recorded; the rule asks ${x.asked_whole} seat(s) again (${x.asked_scoped} scoped)`);
  return out;
}

/** Each addition's reverse sweep as the checkout reads the copy's sweeps: counts per question, never a string. Null for a checkout that reads none. */
async function lateEvidenceOf(SWm: Mod | null, S: string): Promise<Projection["late_evidence"]> {
  const read = fn(SWm, "readImportSweeps");
  if (!read) return null;
  type Line = { seq: number; import: string; synthetic?: boolean; state: string; terms: string[]; records: Array<{ seq: number; questions: string[] }>; searched: { objects: number }; hits: Array<{ ref: string; count: number; bears_on: number[] }>; unsearched?: unknown[] };
  // An addition's sweep may be recorded in passes (each continuing the last): read as one, its hits and objects every pass's, its state what the passes found and what the last left.
  const passes = new Map<number, Line[]>();
  for (const l of (await read(S)) as Line[]) passes.set(l.seq, [...(passes.get(l.seq) ?? []), l]);
  return [...passes.values()].map((ps) => {
    const last = ps.at(-1)!;
    const hits = ps.flatMap((x) => x.hits);
    const l: Line = { ...last, hits, searched: { objects: ps.reduce((n, x) => n + x.searched.objects, 0) }, state: ps.length === 1 ? last.state : hits.length ? "hits" : last.unsearched?.length ? "partial" : "clean" };
    const questions = [...new Set(l.records.flatMap((r) => r.questions))].sort();
    return {
      addition: l.seq,
      import: l.import,
      synthetic: l.synthetic === true,
      state: l.state,
      records: l.records.length,
      terms: l.terms.length,
      objects: l.searched.objects,
      questions: questions.map((q) => {
        const mine = new Set(l.records.filter((r) => r.questions.includes(q)).map((r) => r.seq));
        const hits = l.hits.filter((h) => h.bears_on.some((n) => mine.has(n)));
        return { section: questionKey(q), objects: new Set(hits.map((h) => h.ref)).size, occurrences: hits.reduce((n, h) => n + h.count, 0) };
      }),
    };
  });
}

/** Each coverage record's store sweep as the checkout reads the copy's sweeps: counts, never a string. Null for a checkout that reads none. */
async function storeSweepsOf(SWm: Mod | null, Pm: Mod | null, S: string): Promise<Projection["store_sweeps"]> {
  const read = fn(SWm, "readSweeps");
  const ledger = fn(Pm, "readLedger");
  if (!read || !ledger) return null;
  type Line = { target: string; synthetic?: boolean; reread?: unknown; hits: unknown[]; named_hits: unknown[]; echoes?: unknown[] };
  const lines = (await read(S)) as Line[];
  const records = ((await ledger(S)) as Array<{ kind: string; hash?: string; looked_for?: string[] }>).filter((e) => e.kind === "coverage" && e.looked_for?.length);
  const latest = records.map((e) => lines.filter((l) => l.target === e.hash).at(-1)).filter((l): l is Line => Boolean(l));
  return {
    records: records.length,
    swept: latest.length,
    resplit: latest.filter((l) => l.synthetic).length,
    ...(fn(SWm, "rereadSweeps") ? { reread: latest.filter((l) => l.reread && !l.synthetic).length } : {}),
    hits: latest.reduce((n, l) => n + l.hits.length, 0),
    named: latest.reduce((n, l) => n + l.named_hits.length, 0),
    echoes: latest.reduce((n, l) => n + (l.echoes?.length ?? 0), 0),
    with_hits: latest.filter((l) => l.hits.length).length,
  };
}

/**
 * --resweep: each coverage record's latest store sweep line in a copy read
 * again by this checkout's store sweep (resplitSweep): its hits moved where
 * this checkout would have put them (named under another name of the same
 * bytes, an echo, a reading of what the record names), appended to the
 * copy's chain as a synthetic line when anything moved. Nothing is searched
 * again. Returns what moved, counted.
 */
async function addResplitSweeps(copy: string): Promise<{ records: number; moved: number; to_named: number; to_echoes: number; hits_before: number; hits_after: number }> {
  const SWm = await import("../extensions/store-sweep.ts");
  const Pm = await import("../extensions/protocol.ts");
  const entries = await Pm.readLedger(copy);
  const lines = await SWm.readSweeps(copy);
  const out = { records: 0, moved: 0, to_named: 0, to_echoes: 0, hits_before: 0, hits_after: 0 };
  for (const e of entries) {
    if (e.kind !== "coverage" || !e.hash) continue;
    const line = SWm.sweepOf(e, lines);
    if (!line) continue;
    out.records += 1;
    const r = await SWm.resplitSweep(copy, e, line);
    out.hits_before += line.hits.length;
    out.hits_after += r.hits.length;
    if (r.hits.length === line.hits.length && r.named_hits.length === line.named_hits.length && (r.echoes?.length ?? 0) === (line.echoes?.length ?? 0)) continue;
    out.moved += 1;
    out.to_named += r.named_hits.length - line.named_hits.length;
    out.to_echoes += (r.echoes?.length ?? 0) - (line.echoes?.length ?? 0);
    const file = join(copy, SWm.LEDGER_SWEEPS);
    const text = (await readFile(file, "utf8").catch(() => "")).split("\n").filter((l) => l.trim());
    const prev = text.length ? ((JSON.parse(text.at(-1)!) as { hash?: string }).hash ?? "genesis") : "genesis";
    const next: Record<string, unknown> & { hash?: string } = { ...r, synthetic: true, prev };
    next.hash = SWm.sweepHash(next as unknown as Parameters<typeof SWm.sweepHash>[0], prev);
    await writeFile(file, `${[...text, JSON.stringify(next)].join("\n")}\n`);
  }
  return out;
}

/**
 * --reverse-sweep: each evidence addition in a copy that has no reverse
 * sweep line gets one, computed by this checkout's store sweep over the
 * copy's import as the hub would have at the addition (the coverage records
 * standing at its entry, recordsStandingAt), marked synthetic, appended to
 * the copy's chain. Only for a checkout that reads version 2 sweep lines
 * (one that does not would read the chain as broken): its copy is left as
 * it is, and the note says so. The run is never written.
 */
async function addSyntheticReverseSweeps(copy: string, harness: string): Promise<string | null> {
  const target = await importFrom(harness, "extensions/store-sweep.ts").catch(() => null);
  if (!fn(target, "readImportSweeps")) return `${harness} reads no reverse sweep: its copy has none added`;
  const SWm = await import("../extensions/store-sweep.ts");
  const Pm = await import("../extensions/protocol.ts");
  const entries = await Pm.readLedger(copy);
  const have = await SWm.readImportSweeps(copy);
  for (const x of Pm.evidenceAdditions(entries)) {
    const e = entries.find((y) => y.seq === x.seq);
    if (!e?.hash || SWm.importSweepOf(e.hash, have)) continue;
    const r = await SWm.computeImportSweep(copy, { seq: e.seq, hash: e.hash, import: x.import }, SWm.recordsStandingAt(entries, e.seq));
    const file = join(copy, SWm.LEDGER_SWEEPS);
    const lines = (await readFile(file, "utf8").catch(() => "")).split("\n").filter((l) => l.trim());
    const prev = lines.length ? ((JSON.parse(lines.at(-1)!) as { hash?: string }).hash ?? "genesis") : "genesis";
    const line: Record<string, unknown> & { hash?: string } = { ...r, synthetic: true, prev };
    line.hash = SWm.sweepHash(line as unknown as Parameters<typeof SWm.sweepHash>[0], prev);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, `${[...lines, JSON.stringify(line)].join("\n")}\n`);
  }
  return null;
}

/** A broad extraction this checkout's census finds applies to a run's input, for a synthetic receipt (--prepare-as). */
export type SyntheticPreparation = { source: { sha256: string; ref: string; name: string; bytes?: number }; recipe: string; version: string; recipe_sha256: string; capability: string; exclusions: string[]; unavailable?: string };

/**
 * What this checkout's census finds applies to the run's own evidence: its
 * packs' broad extractions (the run's packs by id, as this checkout ships
 * them; every pack here when the run names none), each asked about each
 * input, read in place and never written, in a scratch sandbox whose inputs/
 * is a link to the run's. Nothing when the run's evidence is not there.
 */
export async function syntheticPreparations(run: RunRef, scratch: string): Promise<{ items: SyntheticPreparation[]; notes: string[] }> {
  const notes: string[] = [];
  const inputs = join(run.sandbox, "inputs");
  if (!existsSync(inputs)) return { items: [], notes: [`${run.id} holds no evidence under inputs/ here: no broad extraction can be asked about it`] };
  const ids = Array.isArray(run.entry?.packs) ? (run.entry!.packs as Array<{ id?: string }>).map((p) => String(p.id ?? "")).filter(Boolean) : [];
  const packs = (ids.length ? ids : await readdir(join(ROOT, "packs")).catch(() => [] as string[])).map((id) => join(ROOT, "packs", id)).filter((d) => existsSync(join(d, "pack.json")));
  for (const id of ids) if (!existsSync(join(ROOT, "packs", id, "pack.json"))) notes.push(`the run's pack ${id} is not in this checkout: its recipes are not asked`);
  const S = join(scratch, "census", "run");
  await mkdir(join(S, "catalog"), { recursive: true });
  const { symlinkSync } = await import("node:fs");
  symlinkSync(realpathSync(inputs), join(S, "inputs"));
  const census = spawnSync("python3", [join(ROOT, "scripts", "evidence_catalog.py"), S, "--plan-only", ...packs.flatMap((d) => ["--recipes-from", d])], { encoding: "utf8", maxBuffer: 1 << 26 });
  if (census.status !== 0) return { items: [], notes: [...notes, `the census did not run: ${String(census.stderr).trim().split("\n").slice(-2).join(" ")}`] };
  const plan = JSON.parse(await readFile(join(S, "catalog", "plan.json"), "utf8")) as { preparations?: Array<{ input: string; recipe: string; target: { ref?: string } }> };
  const files = (JSON.parse(await readFile(join(run.sandbox, "inputs.json"), "utf8").catch(() => "{}")) as { files?: Array<{ path: string; sha256?: string; bytes?: number }> }).files ?? [];
  const items: SyntheticPreparation[] = [];
  for (const p of plan.preparations ?? []) {
    const f = files.find((x) => x.path === p.input);
    if (!f?.sha256) {
      notes.push(`${p.input} has no digest in the run's inputs.json: ${p.recipe} over it is not keyed`);
      continue;
    }
    const [pack, name] = p.recipe.split("/");
    const r = JSON.parse(await readFile(join(ROOT, "packs", pack!, "recipes", name!, "recipe.json"), "utf8")) as { version?: string; sha256?: string; capability?: string; exclusions?: string[]; unavailable?: string };
    items.push({ source: { sha256: f.sha256, ref: p.target.ref ?? `input:${p.input.replace(/^inputs\//, "")}`, name: p.input, ...(typeof f.bytes === "number" ? { bytes: f.bytes } : {}) }, recipe: p.recipe, version: r.version ?? "", recipe_sha256: r.sha256 ?? "", capability: r.capability ?? p.recipe, exclusions: r.exclusions ?? [], ...(r.unavailable ? { unavailable: r.unavailable } : {}) });
  }
  return { items, notes };
}

/** The synthetic receipts on a copy's store journal: planned, then `state` (one the images cannot run, declined), each by "replay". */
async function addSyntheticReceipts(copy: string, items: SyntheticPreparation[], state: string): Promise<void> {
  if (!items.length) return;
  const { Journal } = await import("./evidence-store.ts");
  const j = await Journal.open(copy);
  for (const x of items) {
    const base = { type: "preparation", source: x.source, recipe: x.recipe, recipe_version: x.version, recipe_sha256: x.recipe_sha256, capability: x.capability, manifest: null, exclusions: x.exclusions, by: "replay", why: `synthetic: replay --prepare-as ${state}` };
    if (x.unavailable) {
      await j.append({ ...base, state: "declined", why: `synthetic: its pack declares it, and it cannot run in the job images: ${x.unavailable}` });
      continue;
    }
    await j.append({ ...base, state: "planned" });
    if (state !== "planned") await j.append({ ...base, state });
  }
}

/**
 * --presumes: each question named amended in the copy to presume its event,
 * as the operator would (`question amend Q-n --presumes …`), by this
 * checkout's register, in synthetic words that say so; the run untouched.
 * What could not be done is said, never guessed.
 */
async function addSyntheticPresumptions(copy: string, ids: string[]): Promise<string[]> {
  const Q = await import("../extensions/questions.ts");
  const notes: string[] = [];
  const actor = { kind: "human", role: "operator", person: "replay", enrolled: false, os_user: "replay", host: "replay", via: "cli", identity: "claimed" } as const;
  for (const raw of ids) {
    const snap = await Q.questionsSnapshot(copy);
    const q = Q.findQuestion(snap, raw);
    if (!q) {
      notes.push(`${raw} is not in the run's question register: not presumed`);
      continue;
    }
    const r = await Q.act(copy, actor, "amend", { q: q.id, expected_rev: q.rev, presumes: `the event question ${q.section} asks about happened (synthetic: replay --presumes)`, why: "synthetic: replay --presumes" });
    if (!r.ok) notes.push(`${q.id} could not be presumed in the copy: ${r.reason}`);
  }
  return notes;
}

/** The registers a delivery point reads, each cut to the act: a chain cut at a line is a prefix of it, which verifies. */
const CUT_REGISTERS = ["ledger/entries.jsonl", "ledger/attestations.jsonl", "ledger/disputes.jsonl", "ledger/sweeps.jsonl", "leads/leads.jsonl", "questions/questions.jsonl"] as const;
/** What else they read, whole: the contract, the budget, the team, the inputs, the case policy. */
const WHOLE_FILES = ["SWARM.md", "budget.json", "team.json", "inputs.json", "network/policy.json"] as const;

type Row = Record<string, unknown>;
const rowsOf = (text: string): Array<{ line: string; row: Row | null }> =>
  text
    .split("\n")
    .filter((l) => l.trim())
    .map((line) => {
      try {
        return { line, row: JSON.parse(line) as Row };
      } catch {
        return { line, row: null };
      }
    });
/** When a line was written: its `at`, or, for a sweep line that read an earlier one again (whose `at` stays the search's), when it read it (`reread.at`). */
const timeOf = (row: Row | null): number => {
  const reread = row?.reread as { at?: unknown } | undefined;
  if (typeof reread?.at === "string") return Date.parse(reread.at);
  return row && typeof row.at === "string" ? Date.parse(row.at) : Number.NaN;
};

/** A register's lines up to the first one `keep` refuses: a prefix, never a selection. */
function prefixOf(rows: Array<{ line: string; row: Row | null }>, keep: (row: Row | null, i: number) => boolean): string {
  const out: string[] = [];
  for (const [i, r] of rows.entries()) {
    if (!keep(r.row, i)) break;
    out.push(r.line);
  }
  return out.length ? `${out.join("\n")}\n` : "";
}

/**
 * Where the checkout delivers the warnings, act by act (Deliveries): each
 * act's registers cut to the moment of the act in a scratch directory beside
 * the copy (the ledger to the answer's own seq for its record, the
 * attestations to the attest's own line, the lead register to a seat's
 * close's or confirmation's own lines, every other register to the act's
 * time), and the checkout's own warningsAt asked what that point carries then;
 * finish status from readiness at the end. A checkout without warningsAt
 * delivered them in finish status only, and says so. The copy is not
 * written; the scratch directory is removed.
 */
export async function deliveriesOf(S: string, FIN: Mod | null, ready: { warnings?: string[]; warned?: Array<{ code: string; section: string; seqs: number[] }> } | null): Promise<Deliveries> {
  const acts = { record: 0, review_offer: 0, attest: 0, lead_close: 0 };
  const delivered: Delivery[] = [];
  // Finish status, at the end: every warning readiness carries, question by question.
  const finishStatus = (): Delivery[] => {
    const bySection = new Map<string, Set<string>>();
    const put = (section: string | null, code: string) => {
      if (!section) return;
      bySection.set(questionKey(section), (bySection.get(questionKey(section)) ?? new Set()).add(code));
    };
    if (ready?.warned) for (const w of ready.warned) put(w.section, w.code);
    else for (const w of ready?.warnings ?? []) put(warningCode(w).section, warningCode(w).code);
    return [...bySection].sort(([x], [y]) => x.localeCompare(y, undefined, { numeric: true })).map(([section, codes]) => ({ point: "finish_status" as const, entry: null, on: null, by: null, at: null, sections: [section], warnings: [...codes].sort() }));
  };
  const warningsAt = fn(FIN, "warningsAt");
  if (!warningsAt) return { acts, delivered: finishStatus(), error: "this checkout delivers the warnings in finish status only (it has no warningsAt)" };
  const registers = new Map<string, Array<{ line: string; row: Row | null }>>();
  for (const rel of CUT_REGISTERS) registers.set(rel, rowsOf(await readFile(join(S, rel), "utf8").catch(() => "")));
  const bySeq = new Map<number, Row>();
  for (const { row } of registers.get("ledger/entries.jsonl")!) if (row && typeof row.seq === "number") bySeq.set(row.seq, row);
  type Act = { point: Delivery["point"]; at: number; when: string; entry: number | null; lead?: string; on: string; by: string; ledgerSeq?: number; attestations?: number; leads?: number; wp: Record<string, unknown> };
  const list: Act[] = [];
  for (const { row } of registers.get("ledger/entries.jsonl")!) {
    if (!row || row.kind !== "answer" || typeof row.section !== "string" || !row.section.startsWith("question:")) continue;
    list.push({ point: "record", at: timeOf(row), when: String(row.at), entry: Number(row.seq), on: "answer", by: String(row.by ?? ""), ledgerSeq: Number(row.seq), wp: { point: "record", section: row.section } });
  }
  for (const [i, { row }] of registers.get("ledger/attestations.jsonl")!.entries()) {
    if (!row || row.act === "same_content" || typeof row.seq !== "number") continue;
    list.push({ point: "attest", at: timeOf(row), when: String(row.at), entry: row.seq, on: String(bySeq.get(row.seq)?.kind ?? "entry"), by: String(row.by ?? ""), attestations: i + 1, wp: { point: "attest", entry: row.seq } });
  }
  // A review offered for an answer: read when it reached its seat (offer_seen), else when it was made.
  const leads = registers.get("leads/leads.jsonl")!.map((x) => x.row).filter((r): r is Row => r !== null);
  for (const r of leads) {
    if (r.ev !== "offer" || typeof r.entry !== "number") continue;
    const seen = leads.find((x) => x.ev === "offer_seen" && x.entry === r.entry && x.offer === r.seq);
    const when = String((seen ?? r).at);
    list.push({ point: "review_offer", at: Date.parse(when), when, entry: r.entry, on: String(bySeq.get(r.entry)?.kind ?? "entry"), by: String(r.to ?? ""), wp: { point: "review_offer", entry: r.entry } });
  }
  // A seat's close of a lead, or its confirmation of one (a batch's confirmations are one act): read right after its own lines.
  const leadRows = registers.get("leads/leads.jsonl")!;
  for (let i = 0; i < leadRows.length; i++) {
    const r = leadRows[i]!.row;
    if (!r || (r.ev !== "close" && r.ev !== "confirm") || typeof r.lead !== "string" || r.by === "system") continue;
    const seqs = [Number(r.seq)];
    const leadIds = [r.lead];
    while (r.ev === "confirm" && r.batch && leadRows[i + 1]?.row?.ev === "confirm" && leadRows[i + 1]!.row!.batch === r.batch && leadRows[i + 1]!.row!.by === r.by && leadRows[i + 1]!.row!.at === r.at) {
      i += 1;
      seqs.push(Number(leadRows[i]!.row!.seq));
      leadIds.push(String(leadRows[i]!.row!.lead));
    }
    list.push({ point: "lead_close", at: timeOf(r), when: String(r.at), entry: null, lead: leadIds.join(", "), on: String(r.ev), by: String(r.by ?? ""), leads: i + 1, wp: { point: "lead_close", events: seqs } });
  }
  list.sort((x, y) => x.at - y.at);
  // The scratch run the acts are read in, with a registry of its own that points at it (the goal is read from there).
  const base = await mkdtemp(join(dirname(dirname(S)), "deliveries-"));
  const runs = join(base, "runs");
  const cut = join(runs, basename(S));
  const was = process.env.SWARM_RUNS_DIR;
  try {
    await mkdir(cut, { recursive: true });
    for (const rel of WHOLE_FILES) {
      if (!existsSync(join(S, rel))) continue;
      await mkdir(dirname(join(cut, rel)), { recursive: true });
      await copyFile(join(S, rel), join(cut, rel));
    }
    const reg = JSON.parse(await readFile(join(dirname(S), "registry.json"), "utf8").catch(() => "{}")) as { runs?: Array<Record<string, unknown>> };
    const entry = (reg.runs ?? []).find((r) => typeof r.sandbox === "string" && resolve(r.sandbox) === resolve(S));
    if (entry) await writeFile(join(runs, "registry.json"), `${JSON.stringify({ runs: [{ ...entry, sandbox: cut }] })}\n`);
    process.env.SWARM_RUNS_DIR = runs;
    for (const act of list) {
      for (const rel of CUT_REGISTERS) {
        const rows = registers.get(rel)!;
        const body =
          rel === "ledger/entries.jsonl" && act.ledgerSeq !== undefined
            ? prefixOf(rows, (r) => r !== null && Number(r.seq) <= act.ledgerSeq!)
            : rel === "ledger/attestations.jsonl" && act.attestations !== undefined
              ? prefixOf(rows, (_r, i) => i < act.attestations!)
              : rel === "leads/leads.jsonl" && act.leads !== undefined
                ? prefixOf(rows, (_r, i) => i < act.leads!)
                : prefixOf(rows, (r) => !(timeOf(r) > act.at));
        await mkdir(dirname(join(cut, rel)), { recursive: true });
        await writeFile(join(cut, rel), body);
      }
      acts[act.point as keyof typeof acts] += 1;
      const ws = (await warningsAt(cut, act.wp)) as Array<{ code: string; section: string }>;
      if (ws.length) delivered.push({ point: act.point, entry: act.entry, ...(act.lead ? { lead: act.lead } : {}), on: act.on, by: act.by, at: act.when, sections: [...new Set(ws.map((w) => questionKey(w.section)))], warnings: [...new Set(ws.map((w) => w.code))].sort() });
    }
  } catch (e) {
    return { acts, delivered: [...delivered, ...finishStatus()], error: `the acts could not all be read again: ${(e as Error).message}` };
  } finally {
    if (was === undefined) delete process.env.SWARM_RUNS_DIR;
    else process.env.SWARM_RUNS_DIR = was;
    await rm(base, { recursive: true, force: true });
  }
  return { acts, delivered: [...delivered, ...finishStatus()], error: null };
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
export async function registerDigest(sandbox: string): Promise<string> {
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
  /** With --prepare-as: the state given, the broad extractions this checkout's census found apply to the run's evidence, and what could not be asked. */
  prepared_as?: { state: string; items: Array<{ source: string; recipe: string; capability: string; unavailable: boolean }>; notes: string[] };
  /** With --reverse-sweep: each addition without a reverse sweep got one in every copy a checkout can read it in (late_evidence says what it found); the notes name the checkouts that could not. */
  reverse_swept?: { notes: string[] };
  /** With --resweep: what moved in each copy's recorded store sweeps, read again by this checkout (the first copy's counts; every copy gets the same). */
  resplit?: { records: number; moved: number; to_named: number; to_echoes: number; hits_before: number; hits_after: number };
  /** With --presumes: the questions amended in each copy to presume their event (synthetic), and what could not be. */
  presumed?: { questions: string[]; notes: string[] };
  copy: { left_out: string[]; links_removed: number };
  targets: Target[];
  evaluations: Evaluation[];
  differences: Difference[] | null;
  unchanged: boolean;
};

/** Evaluate each copy in `copies` with `harness`, in a process of its own; one projection per copy, in order. */
export async function evaluateIn(harness: string, copies: string[], showText: boolean, deliveries = false): Promise<Array<Projection | { error: string }>> {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^(SWARM_|DFIRSWARM_)/.test(k)) env[k] = v;
  const args = ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "replay.ts"), "--evaluate", "--harness", harness, ...(showText ? ["--show-text"] : []), ...(deliveries ? ["--deliveries"] : []), ...copies.flatMap((c) => ["--sandbox", c])];
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
export async function replay(o: { run: RunRef; targets: Target[]; policies?: StopPolicy[] | null; showText?: boolean; deliveries?: boolean; prepareAs?: string | null; reverseSweep?: boolean; resweep?: boolean; presumes?: string[] | null; scratch: string }): Promise<Replay> {
  const before = await registerDigest(o.run.sandbox);
  // --prepare-as: what this checkout's census finds applies to the run's evidence, asked once.
  const synthetic = o.prepareAs ? await syntheticPreparations(o.run, o.scratch) : null;
  const goal = typeof o.run.entry?.goal === "string" ? (o.run.entry.goal as string) : await readFile(join(o.run.sandbox, "SWARM.md"), "utf8").catch(() => "");
  const briefs = answersChecks(goalChecks(goal)).map((c) => c.sectionsIn).filter((x): x is string => Boolean(x));
  const policies: Array<StopPolicy | null> = o.policies?.length ? o.policies : [null];
  let copyInfo = { left_out: [] as string[], links_removed: 0 };
  const evaluations: Evaluation[] = [];
  const reverseNotes: string[] = [];
  const presumeNotes: string[] = [];
  let resplit: Replay["resplit"];
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
      if (synthetic && o.prepareAs) await addSyntheticReceipts(copy, synthetic.items, o.prepareAs);
      if (o.reverseSweep) {
        const note = await addSyntheticReverseSweeps(copy, target.harness);
        if (note && !reverseNotes.includes(note)) reverseNotes.push(note);
      }
      if (o.resweep) {
        const moved = await addResplitSweeps(copy);
        resplit ??= moved;
      }
      if (o.presumes?.length) for (const n of await addSyntheticPresumptions(copy, o.presumes)) if (!presumeNotes.includes(n)) presumeNotes.push(n);
      copies.push(copy);
    }
    const results = await evaluateIn(target.harness, copies, o.showText === true, o.deliveries === true);
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
    ...(synthetic && o.prepareAs ? { prepared_as: { state: o.prepareAs, items: synthetic.items.map((x) => ({ source: x.source.ref, recipe: x.recipe, capability: x.capability, unavailable: Boolean(x.unavailable) })), notes: synthetic.notes } } : {}),
    ...(o.reverseSweep ? { reverse_swept: { notes: reverseNotes } } : {}),
    ...(o.resweep && resplit ? { resplit } : {}),
    ...(o.presumes?.length ? { presumed: { questions: o.presumes, notes: presumeNotes } } : {}),
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
  const preparedWords = (p: Projection) => (!p.finish ? "none" : !p.finish.prepared ? "not read" : `${p.finish.prepared.count}${p.finish.prepared.last ? `, the last with ${p.finish.prepared.last.late} late` : ""}`);
  // Only where both read them: a checkout from before the rule has none, which is no rule's difference.
  if (a.review_caps && b.review_caps) put(null, "established attests the review rule caps", `${a.review_caps.capped.length} of ${a.review_caps.established}`, `${b.review_caps.capped.length} of ${b.review_caps.established}`);
  // Only where both read the prepares: a checkout from before them reads the register without them, which is no rule's difference.
  if (a.finish?.prepared && b.finish?.prepared) put(null, "prepared", preparedWords(a), preparedWords(b));
  // Only where both have the carry rule: one from before it reads no review as standing past its version.
  if (a.reviews && b.reviews) put(null, "re-reviews the rule finds standing", `${a.reviews.reacks.standing_whole} of ${a.reviews.reacks.recorded}`, `${b.reviews.reacks.standing_whole} of ${b.reviews.reacks.recorded}`);
  put(null, "done", a.finish ? `${a.finish.done}${a.finish.held_by.length ? ` (${a.finish.held_by.join(", ")})` : ""}` : "none", b.finish ? `${b.finish.done}${b.finish.held_by.length ? ` (${b.finish.held_by.join(", ")})` : ""}` : "none");
  put(null, "disagreements", listWords(a.agreement.map((g) => `${g.section} ${g.kind}`)), listWords(b.agreement.map((g) => `${g.section} ${g.kind}`)));
  put(null, "seals", `${a.seals.hold} of ${a.seals.verdicts} hold`, `${b.seals.hold} of ${b.seals.verdicts} hold`);
  if (a.deliveries && b.deliveries) {
    for (const point of ["record", "review_offer", "attest", "lead_close", "finish_status"] as const) {
      const at = (d: Deliveries) => listWords(countWords(d.delivered.filter((x) => x.point === point).flatMap((x) => x.warnings)));
      put(null, `delivered at ${point.replace("_", " ")}`, at(a.deliveries), at(b.deliveries));
    }
  }
  return out;
}

/** Where the warnings were delivered, act by act, values-free: the point, the act's entry and seat, the questions and codes. */
function deliveryWords(d: Deliveries): string[] {
  const out = [`  deliveries: ${d.acts.record} answer record(s), ${d.acts.review_offer} review offer(s) for an answer, ${d.acts.attest} attest(s) and ${d.acts.lead_close ?? 0} lead close(s) or confirmation(s) read again as the registers stood at each${d.error ? ` (${d.error})` : ""}`];
  const acts = d.delivered.filter((x) => x.point !== "finish_status");
  if (!acts.length) out.push("    no act carries a warning");
  for (const x of acts) out.push(`    ${x.point === "record" ? `record E-${x.entry} by ${x.by}` : x.point === "review_offer" ? `review offer of E-${x.entry} to ${x.by}` : x.point === "lead_close" ? `${x.on} of ${x.lead} by ${x.by}` : `attest by ${x.by} of E-${x.entry} (${x.on})`}: ${x.sections.join(", ")} ${x.warnings.join(", ")}`);
  const fs = d.delivered.filter((x) => x.point === "finish_status");
  out.push(`    finish status: ${fs.length ? fs.map((x) => `${x.sections.join(", ")} ${x.warnings.join(", ")}`).join("; ") : "no warning"}`);
  return out;
}

/** The sources' broad extractions, values-free: each source's ref, each capability's recipe and state, and the questions held or warned on them. */
function preparationWords(p: PreparationProjection): string[] {
  if (!p.sources.length) return ["  preparation: no receipt on the store journal"];
  const out = ["  preparation (each source's broad extraction, by the store journal's receipts):"];
  for (const s of p.sources) out.push(`    ${s.source}: ${s.capabilities.map((c) => `${c.recipe} ${c.outcome}${c.state !== c.outcome ? ` (now ${c.state})` : ""}${c.synthetic ? ", synthetic" : ""}`).join("; ")}${s.pending ? " — pending" : ""}`);
  out.push(`    held (preparation_pending): ${p.held.length ? p.held.map((h) => `${h.section} on ${h.sources.join(", ")}`).join("; ") : "none"}`);
  out.push(`    warned (preparation_missing): ${p.warned.length ? p.warned.map((w) => `${w.section} on ${w.sources.join(", ")}`).join("; ") : "none"}`);
  return out;
}

/** The source-first review rule over the recorded established attests, values-free: how many, and each it would cap, with its codes. */
function reviewCapWords(r: NonNullable<Projection["review_caps"]>): string[] {
  const out = [`  review rule (source-first): ${r.established} established attest(s) of answers that claim established; ${r.capped.length} would be capped${r.warned ? `; ${r.warned.length} would be warned and not capped` : ""}`];
  for (const c of r.capped) out.push(`    ${c.section} E-${c.answer} by ${c.by}${c.standing ? "" : " (superseded since)"}${c.material ? "" : " (not material)"}: ${c.codes.join(", ")}`);
  for (const c of r.warned ?? []) out.push(`    ${c.section} E-${c.answer} by ${c.by}${c.standing ? "" : " (superseded since)"}${c.material ? "" : " (not material)"}: warned ${c.codes.join(", ")}`);
  return out;
}

/** Each addition's reverse sweep, values-free: counts per question. */
function lateEvidenceWords(xs: NonNullable<Projection["late_evidence"]>): string[] {
  if (!xs.length) return ["  reverse sweeps: none (no evidence addition has one)"];
  const out = ["  reverse sweeps (each evidence addition's files searched for the standing looked_for strings):"];
  for (const x of xs) out.push(`    E-${x.addition} import:${x.import}${x.synthetic ? " (synthetic, --reverse-sweep)" : ""}: ${x.state}; ${x.records} standing coverage record(s) with looked_for, ${x.terms} string(s), ${x.objects} object(s) read${x.questions.length ? `; ${x.questions.map((q) => `${q.section} ${q.objects} object(s), ${q.occurrences} occurrence(s)`).join("; ")}` : ""}`);
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
  if (r.presumed) out.push(`Presumed (synthetic, --presumes): ${r.presumed.questions.join(", ")}, each amended in every copy to presume its event, by this checkout's register (the run untouched)${r.presumed.notes.length ? `; ${r.presumed.notes.join("; ")}` : ""}.`);
  if (r.resplit) out.push(`Store sweeps read again (--resweep, this checkout's store sweep, nothing searched again, the run untouched): ${r.resplit.records} recorded sweep(s), ${r.resplit.moved} with hits moved: ${r.resplit.hits_before} hit(s) became ${r.resplit.hits_after}, ${r.resplit.to_named} to the named hits, ${r.resplit.to_echoes} to the echoes; each such record's sweep is a synthetic line on each copy's chain.`);
  if (r.reverse_swept) out.push(`Reverse sweeps: each evidence addition without one got one in each copy, by this checkout's store sweep as the hub would have run it at the addition (the run untouched)${r.reverse_swept.notes.length ? `; ${r.reverse_swept.notes.join("; ")}` : ""}.`);
  if (r.prepared_as) {
    out.push(`Prepared as ${r.prepared_as.state} (synthetic receipts on each copy's store journal, the run untouched): ${r.prepared_as.items.length ? r.prepared_as.items.map((x) => `${x.recipe} over ${x.source}${x.unavailable ? " (declared, cannot run: declined)" : ""}`).join("; ") : "no broad extraction applies to the run's evidence"}.`);
    for (const n of r.prepared_as.notes) out.push(`  ${n}`);
  }
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
    if (p.finish) out.push(`  finish: ${p.finish.lease ? `${p.finish.lease.holder} coordinates at generation ${p.finish.lease.generation}${p.finish.lease.segment ? ` (segment ${p.finish.lease.segment}${p.finish.lease.carried ? `, ${p.finish.lease.carried} post(s) carried from before the resume` : ""})` : ""}` : "no coordinator yet"}; ${!p.finish.prepared ? "prepares not read by this checkout" : p.finish.prepared.count ? `prepared ${p.finish.prepared.count} time(s), the last by ${p.finish.prepared.last!.by} at generation ${p.finish.prepared.last!.generation} with ${p.finish.prepared.last!.late} item(s) late${p.finish.prepared.last!.current ? "" : " (the lease or the report has moved since)"}` : "never prepared"}; ${p.finish.resolutions.count} resolution(s)${p.finish.resolutions.batches ? ` (${p.finish.resolutions.batches} batch(es))` : ""}; ${p.finish.late.length ? `late against the report: ${p.finish.late.map((x) => `${x.kind} ${x.id} by ${x.by}${x.tag ? ` (${x.tag})` : ""}`).join("; ")}` : "nothing late"}; ${p.finish.last_check ? `the last check ${p.finish.last_check.proceed ? `proceeded (${p.finish.last_check.outcome})` : "held"}${p.finish.last_check.current ? " at this revision" : ""}; ` : ""}the done ${p.finish.done}${p.finish.held_by.length ? ` (${p.finish.held_by.join(", ")})` : ""}`);
    out.push(`  seals: ${p.seals.verdicts ? `${p.seals.hold} of ${p.seals.verdicts} custody verdict(s) hold as a prefix${p.seals.broken.map((b) => `; ${b.verdict} does not: ${b.broken.join("; ")}`).join("")}` : "no custody verdict in the run"}`);
    out.push(`  agreement: ${p.agreement.length ? `readiness, the answers check and the gate disagree: ${p.agreement.map((g) => `${g.section} ${g.kind}`).join("; ")}` : "readiness, the answers check and the gate agree on every question"}${p.warnings_hold.length ? `; a warning holds: ${p.warnings_hold.join(", ")}` : ""}`);
    if (p.preparation) out.push(...preparationWords(p.preparation));
    if (p.review_caps) out.push(...reviewCapWords(p.review_caps));
    if (p.late_evidence) out.push(...lateEvidenceWords(p.late_evidence));
    if (p.store_sweeps) out.push(`  store sweeps (the latest line of each coverage record's): ${p.store_sweeps.swept} of ${p.store_sweeps.records} record(s) with looked_for swept${p.store_sweeps.resplit ? ` (${p.store_sweeps.resplit} read again, --resweep)` : ""}${p.store_sweeps.reread ? ` (${p.store_sweeps.reread} recorded under older rules, read again by the answers check)` : ""}; ${p.store_sweeps.hits} hit(s) in ${p.store_sweeps.with_hits} record(s), ${p.store_sweeps.named} named hit(s), ${p.store_sweeps.echoes} echo(es)`);
    if (p.reviews) out.push(...reviewWords(p.reviews));
    if (p.deliveries) out.push(...deliveryWords(p.deliveries));
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

const USAGE = "usage: replay.ts <run-dir | run-id> [--registry FILE] [--checkout PATH] [--compare [A [B]]] [--stop-policy P[,P…]] [--deliveries] [--prepare-as STATE] [--reverse-sweep] [--resweep] [--presumes Q[,Q…]] [--json] [--show-text]";

/** The states --prepare-as takes: a receipt's. */
const PREPARE_STATES = ["planned", "attempted", "produced", "partial", "failed", "declined"] as const;

async function evaluateMain(args: string[]): Promise<void> {
  const harness = args[args.indexOf("--harness") + 1];
  const showText = args.includes("--show-text");
  const deliveries = args.includes("--deliveries");
  const copies = args.flatMap((a, i) => (a === "--sandbox" ? [args[i + 1]] : []));
  const out: Array<Projection | { error: string }> = [];
  for (const S of copies) {
    // The registry the goal is read from is the replay's own, beside the copy.
    process.env.SWARM_RUNS_DIR = dirname(S);
    try {
      out.push(await project(harness, S, { showText, deliveries }));
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
  let deliveries = false;
  let prepareAs: string | null = null;
  let reverseSweep = false;
  let resweep = false;
  let presumes: string[] | null = null;
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
    else if (a === "--deliveries") deliveries = true;
    else if (a === "--reverse-sweep") reverseSweep = true;
    else if (a === "--resweep") resweep = true;
    else if (a === "--presumes") {
      presumes = (argv[++i] ?? "").split(",").map((x) => x.trim()).filter(Boolean);
      if (!presumes.length || presumes.some((x) => !/^(?:Q-?|question:)?[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/i.test(x))) {
        process.stderr.write("--presumes takes the questions to presume their event, by id (Q-7, 7, question:7), several with commas\n");
        return 2;
      }
    } else if (a === "--prepare-as") {
      prepareAs = argv[++i] ?? "";
      if (!(PREPARE_STATES as readonly string[]).includes(prepareAs)) {
        process.stderr.write(`--prepare-as takes a receipt's state: ${PREPARE_STATES.join(", ")}${prepareAs ? `, not ${prepareAs}` : ""}\n`);
        return 2;
      }
    } else if (a === "-h" || a === "--help") {
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
    const r = await replay({ run, targets, policies, showText, deliveries, prepareAs, reverseSweep, resweep, presumes, scratch });
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
