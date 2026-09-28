/**
 * The negative bar: what a "not found" has to show before it stands.
 *
 * A run used to end on answers alone, and an answer resting on a search
 * that found nothing read as well as one resting on a finding. The ctf12
 * runs showed what that let through: c09 closed 60 leads negative, 33 of
 * them held under two minutes with at most one job and 19 reviewed by
 * another seat; Belka closed 32, 21 of them on an absence whose own
 * completion was partial, and 10 reviewed. The gate accepted every one.
 *
 * Here a material negative (an answer bounded_negative, or not_determinable)
 * rests on a coverage record: the proposition searched, the inventory
 * revision, the objects, the time range, the method and its settings, what
 * was actually covered, what was skipped, what failed, the results, the
 * alternatives left open, and whether the event would have left a trace
 * here at all (the detection opportunity). The hub computes, beside what the
 * searcher said, whether the jobs behind the record declared every object
 * the record names and every catalogued object inside them, by digest where
 * the run has one: coverage complete or partial. It never judges relevance:
 * the record's objects say what the search was about, the jobs' declared
 * inputs say what they were given, and the hub only refuses to call a
 * partial search complete. Another seat reviews the negative and says what
 * it challenged, reproduced or tried; a negative nobody reviewed shows as
 * "negative (unreviewed)" and holds the finish line.
 *
 * Nothing here reads a tool's output or knows a format: refs, digests, the
 * jobs' declared inputs, the catalogue's generations and the lead register.
 * The only words read are a short list of absolute forms of absence ("did
 * not happen"), which an answer may use only when the bar for saying so is
 * met, the way a person's question's leading forms are flagged.
 */

import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

// --- the vocabulary ---------------------------------------------------------------------------

/**
 * What an answer establishes. established: the question is answered on
 * findings. partial: part of it is. bounded_negative: no evidence of it was
 * found in a named scope (the coverage record's). not_determinable: the
 * evidence cannot settle it (the old `inconclusive`). out_of_scope: the
 * question falls outside what the case's evidence can bear on.
 * premise_not_supported: what the question takes for granted does not hold.
 */
export const ANSWER_RESULTS = ["established", "partial", "bounded_negative", "not_determinable", "out_of_scope", "premise_not_supported"] as const;
export type AnswerResult = (typeof ANSWER_RESULTS)[number];
/** The results the negative bar holds: a coverage record, and another seat's review, on a material question. */
export const NEGATIVE_RESULTS: ReadonlySet<string> = new Set(["bounded_negative", "not_determinable"]);
/** Whether the sought event would have left a trace in these sources, given collection and retention. */
export const TRACE_EXPECTED = ["yes", "no", "unknown"] as const;
export type TraceExpected = (typeof TRACE_EXPECTED)[number];
/** Held this long or less, one job, one object: a quick negative, shown as a review cue. */
export const QUICK_NEGATIVE_HELD_MS = 2 * 60_000;
/** A coverage record's free-text fields: each bounded, refused past it, never cut. */
export const COVERAGE_TEXT_MAX = 2000;
/** A route plan names at most this many routes on one lead. */
export const MAX_ROUTES = 20;

/**
 * The absolute forms of absence: an answer that says the event did not
 * happen, rather than that no evidence of it was found in a scope. Allowed
 * only on an existence question whose coverage record is complete and says
 * the event would have left a trace there; otherwise the answer is worded
 * "No evidence of … was found in …". The worker prompt carries the list.
 */
export const ABSOLUTE_ABSENCE_FORMS: ReadonlyArray<{ phrase: string; re: RegExp }> = [
  { phrase: "did not happen", re: /\bdid(?: not|n't) happen\b/i },
  { phrase: "never happened", re: /\bnever happened\b/i },
  { phrase: "did not occur", re: /\bdid(?: not|n't) occur\b/i },
  { phrase: "never occurred", re: /\bnever occurred\b/i },
  { phrase: "did not take place", re: /\bdid(?: not|n't) take place\b/i },
  { phrase: "never took place", re: /\bnever took place\b/i },
  { phrase: "is proven absent", re: /\b(?:is|was) proven (?:absent|not to have)\b/i },
];

export function absoluteAbsenceForms(text: string): string[] {
  return ABSOLUTE_ABSENCE_FORMS.filter((f) => f.re.test(text)).map((f) => f.phrase);
}

/** An answer's result: its own, or read from the older fields (inconclusive is not_determinable). Null for a summary, a narrative, or an answer from before results. */
export function answerResult(e: { kind?: string; result?: string; inconclusive?: boolean; section?: string }): AnswerResult | null {
  if (e.kind !== "answer") return null;
  if (e.result && (ANSWER_RESULTS as readonly string[]).includes(e.result)) return e.result as AnswerResult;
  if (e.inconclusive === true) return "not_determinable";
  return null;
}

/** How a result reads, for a person. */
export function resultWords(r: string | null | undefined): string {
  switch (r) {
    case "established":
      return "established";
    case "partial":
      return "partially established";
    case "bounded_negative":
      return "bounded negative";
    case "not_determinable":
      return "not determinable";
    case "out_of_scope":
      return "out of scope";
    case "premise_not_supported":
      return "premise not supported";
    default:
      return r ?? "no result stated";
  }
}

// --- the inventory ------------------------------------------------------------------------------

/**
 * The inventory revision a coverage record is written against: the sha256
 * of inputs.json and of every catalogue generation's record, in order. A new
 * input or a new generation is a new revision; the record says which one
 * its search saw.
 */
export async function inventoryRevision(sandboxRoot: string): Promise<string> {
  const h = createHash("sha256");
  const inputs = await readFile(join(sandboxRoot, "inputs.json")).catch(() => null);
  h.update(`inputs.json ${inputs ? createHash("sha256").update(inputs).digest("hex") : "none"}\n`);
  const gens = (await readdir(join(sandboxRoot, "catalog", "gen")).catch(() => [] as string[])).sort();
  for (const g of gens) {
    const rec = await readFile(join(sandboxRoot, "catalog", "gen", g, "generation.json")).catch(() => null);
    if (rec) h.update(`gen ${g} ${createHash("sha256").update(rec).digest("hex")}\n`);
  }
  return h.digest("hex");
}

// --- objects, as the hub compares them ------------------------------------------------------------

/** An object as the hub compares it: where it is in the run, whether it is a directory, and its digest when the run has one. */
type Obj = { ref: string; path: string; dir: boolean; sha?: string; member?: { gen: string; n: string } };

type GenRecord = { id: string; job?: string; target?: { ref?: string; sha256?: string; name?: string } };

async function generations(sandboxRoot: string): Promise<GenRecord[]> {
  const out: GenRecord[] = [];
  for (const g of (await readdir(join(sandboxRoot, "catalog", "gen")).catch(() => [] as string[])).sort()) {
    const raw = await readFile(join(sandboxRoot, "catalog", "gen", g, "generation.json"), "utf8").catch(() => null);
    if (!raw) continue;
    try {
      const j = JSON.parse(raw) as GenRecord;
      out.push({ ...j, id: j.id ?? g });
    } catch {
      // not a record: skipped
    }
  }
  return out;
}

/** A ref or a run path as the hub compares it: located, with its digest when inputs.json or the store's manifest has one. */
async function objectOf(sandboxRoot: string, ref: string): Promise<Obj | { reason: string }> {
  const { locate } = await import("../scripts/job-scope.ts");
  const text = ref.trim();
  const mem = /^member:([a-z0-9-]+)#(\d+)$/.exec(text);
  if (mem) return { ref: text, path: `catalog/gen/${mem[1]}#${mem[2]}`, dir: false, member: { gen: mem[1], n: mem[2] } };
  const at = locate(text);
  if ("reason" in at) return { reason: at.reason };
  const obj: Obj = { ref: text, path: at.path, dir: at.dir, ...(at.sha ? { sha: at.sha } : {}) };
  if (!obj.dir && !obj.sha && /^(input|job|import):/.test(text)) {
    const { resolveRef } = await import("../scripts/evidence-store.ts");
    const r = await resolveRef(sandboxRoot, text).catch(() => null);
    if (r?.ok && "sha256" in r && typeof r.sha256 === "string") obj.sha = r.sha256;
    // A job's whole output, named without a trailing slash, is a directory.
    if (r?.ok && /^(job|import):[a-z0-9-]+$/.test(text)) obj.dir = true;
  }
  if (!obj.dir && at.area === "inputs" && !obj.sha) {
    // inputs/<dir> named without its slash: every input under it.
    const files = await inputFiles(sandboxRoot);
    if (files.some((f) => f.path.startsWith(`${obj.path}/`))) obj.dir = true;
  }
  if (!obj.sha && at.area === "inputs" && !obj.dir) {
    const f = (await inputFiles(sandboxRoot)).find((x) => x.path === obj.path);
    if (f?.sha256) obj.sha = f.sha256;
  }
  return obj;
}

let inputsCache: { key: string; files: Array<{ path: string; sha256?: string }> } | null = null;

async function inputFiles(sandboxRoot: string): Promise<Array<{ path: string; sha256?: string }>> {
  const raw = await readFile(join(sandboxRoot, "inputs.json"), "utf8").catch(() => null);
  const key = `${sandboxRoot}:${raw?.length ?? -1}:${raw ? createHash("sha256").update(raw).digest("hex") : ""}`;
  if (inputsCache?.key === key) return inputsCache.files;
  let files: Array<{ path: string; sha256?: string }> = [];
  try {
    files = raw ? ((JSON.parse(raw) as { files?: Array<{ path: string; sha256?: string }> }).files ?? []) : [];
  } catch {
    files = [];
  }
  inputsCache = { key, files };
  return files;
}

/** Whether `inner` is `outer` or inside it, by place or by digest. */
function contains(outer: Obj, inner: Obj): boolean {
  if (outer.path === inner.path) return true;
  if (outer.dir && inner.path.startsWith(`${outer.path}/`)) return true;
  if (outer.dir && outer.path === "inputs" && inner.path.startsWith("inputs/")) return true;
  if (outer.sha && inner.sha && outer.sha === inner.sha) return true;
  if (outer.member && inner.member) return outer.member.gen === inner.member.gen && outer.member.n === inner.member.n;
  return false;
}

// --- the jobs behind a record ---------------------------------------------------------------------

export type JobDeclared = { id: string; scope: string; inputs: string[]; status: string | null; state: string | null };

/** What a job declared it reads, how it ended: its record in store/jobs/<id>/job.json. */
export async function jobDeclared(sandboxRoot: string, id: string): Promise<JobDeclared | null> {
  const raw = await readFile(join(sandboxRoot, "store", "jobs", id, "job.json"), "utf8").catch(() => null);
  if (!raw) return null;
  try {
    const j = JSON.parse(raw) as { state?: string; status?: string; spec?: { inputs?: string[]; scope?: string } };
    const scope = j.spec?.scope === "declared" || j.spec?.scope === "all" ? j.spec.scope : "default-all";
    return { id, scope, inputs: Array.isArray(j.spec?.inputs) ? j.spec!.inputs!.map(String) : [], status: j.status ?? null, state: j.state ?? null };
  } catch {
    return null;
  }
}

/** A job's id from a ref that names its output (job:<id>, job:<id>/<path>), or null. */
export function jobOfRef(ref: string): string | null {
  return /^job:(j\d{6,})(?:\/|$)/.exec(ref.trim())?.[1] ?? null;
}

// --- hub-computed object coverage -----------------------------------------------------------------

export type CoverageUnit = { what: string; covered: boolean; how: string };

export type ObjectCoverage = {
  coverage: "complete" | "partial";
  /** The objects the record names and the catalogued objects inside them, each covered or not, and how. */
  units: CoverageUnit[];
  /** The jobs behind the record: named in its results, cited by an entry it names, or interpreted by one. */
  jobs: string[];
  /** Why it is partial, each in words; empty when complete. */
  why: string[];
};

/** The minimal shape of a ledger entry the hub reads here. */
type EntryLike = { seq: number; kind: string; refs?: string[]; completion?: string };

/**
 * Whether the jobs behind a coverage record were given every object it
 * names. The objects are the record's `refs`; the catalogue objects relevant
 * to them are the generations whose target is one of them (a disk's volumes,
 * an archive's members). The jobs are the ones its results name (job:<id>),
 * the ones an entry it cites (E-<seq>) rests on or interprets. Each unit is
 * covered when a job declared it, or a container of it, by place or by
 * digest; a job that read everything (scope all, or none said) covers all of
 * it, and is said to. The record is partial when any unit is not covered,
 * when an absence it cites was partial or failed, when a job behind it did
 * not succeed, or when no job is behind it at all: the hub cannot then say
 * what was read.
 */
export async function computeObjectCoverage(
  sandboxRoot: string,
  o: { objects: string[]; resultRefs: string[]; entries: EntryLike[]; interpretations?: Map<string, Array<{ entry: number }>> },
): Promise<ObjectCoverage> {
  const why: string[] = [];
  const bySeq = new Map(o.entries.map((e) => [e.seq, e]));
  // The jobs behind it.
  const jobIds = new Set<string>();
  const cited: EntryLike[] = [];
  for (const r of o.resultRefs) {
    const j = jobOfRef(r);
    if (j) jobIds.add(j);
    const m = /^E-(\d+)$/i.exec(r.trim());
    if (m) {
      const e = bySeq.get(Number(m[1]));
      if (e) cited.push(e);
    }
  }
  for (const e of cited) {
    for (const r of e.refs ?? []) {
      const j = jobOfRef(r);
      if (j) jobIds.add(j);
    }
    for (const [job, list] of o.interpretations ?? new Map<string, Array<{ entry: number }>>()) if (list.some((i) => i.entry === e.seq)) jobIds.add(job);
    if (e.kind === "absence" && e.completion && e.completion !== "complete") why.push(`E-${e.seq}, a search it rests on, was ${e.completion}`);
  }
  const jobs: JobDeclared[] = [];
  for (const id of [...jobIds].sort()) {
    const j = await jobDeclared(sandboxRoot, id);
    if (!j) {
      why.push(`job ${id} has no record in the store`);
      continue;
    }
    jobs.push(j);
    if (j.status && j.status !== "ok") why.push(`job ${id} did not succeed (${j.status})`);
  }
  if (!jobs.length) why.push("no job is behind it: its results name none, and no entry it cites rests on or interprets one, so the hub cannot say what was read");
  const everything = jobs.filter((j) => j.scope !== "declared");
  // What the jobs were given.
  const declared: Obj[] = [];
  for (const j of jobs) {
    if (j.scope !== "declared") continue;
    for (const d of j.inputs) {
      const obj = await objectOf(sandboxRoot, d);
      if (!("reason" in obj)) declared.push(obj);
    }
  }
  const gens = await generations(sandboxRoot);
  const units: CoverageUnit[] = [];
  const coveredBy = (unit: Obj): string | null => {
    if (everything.length) return `${everything.map((j) => j.id).join(", ")} read every object of the run (scope ${everything[0].scope}: said, not measured)`;
    const hit = declared.find((d) => contains(d, unit));
    if (hit) return `declared as ${hit.ref}`;
    return null;
  };
  for (const ref of o.objects) {
    if (/^unresolved:/.test(ref)) {
      units.push({ what: ref, covered: false, how: "an object the run cannot name: no job can be shown to have read it" });
      continue;
    }
    const obj = await objectOf(sandboxRoot, ref);
    if ("reason" in obj) {
      units.push({ what: ref, covered: false, how: obj.reason });
      continue;
    }
    if (obj.member) {
      const g = gens.find((x) => x.id === obj.member!.gen);
      let how = coveredBy(obj);
      if (!how && g?.target?.ref) {
        const container = await objectOf(sandboxRoot, g.target.ref);
        if (!("reason" in container)) {
          const c = declared.find((d) => contains(d, container));
          if (c) how = `its container ${g.target.ref} was declared (${c.ref})`;
        }
      }
      if (!how && g?.job && declared.some((d) => d.path === `store/jobs/${g.job}/out` && d.dir)) how = `the output of ${g.job}, which made its generation, was declared`;
      units.push({ what: ref, covered: Boolean(how), how: how ?? "no job behind the record declared it or its container" });
      continue;
    }
    // A directory of the evidence: each file in it.
    if (obj.dir && obj.path.startsWith("inputs")) {
      const files = (await inputFiles(sandboxRoot)).filter((f) => obj.path === "inputs" || f.path.startsWith(`${obj.path}/`));
      const whole = coveredBy(obj);
      if (whole) units.push({ what: ref, covered: true, how: whole });
      else {
        for (const f of files) {
          const fo: Obj = { ref: `input:${f.path.replace(/^inputs\//, "")}`, path: f.path, dir: false, ...(f.sha256 ? { sha: f.sha256 } : {}) };
          const how = coveredBy(fo);
          units.push({ what: fo.ref, covered: Boolean(how), how: how ?? "no job behind the record declared it" });
        }
        if (!files.length) units.push({ what: ref, covered: false, how: "no job behind the record declared it, and inputs.json lists nothing under it" });
      }
    } else {
      const how = coveredBy(obj);
      units.push({ what: ref, covered: Boolean(how), how: how ?? "no job behind the record declared it, or a directory holding it, or an object with its digest" });
    }
    // The catalogued objects inside it: each generation whose target it is.
    for (const g of gens) {
      if (!g.target?.ref) continue;
      const target = await objectOf(sandboxRoot, g.target.ref);
      if ("reason" in target) continue;
      const same = target.path === obj.path || (target.sha && obj.sha && target.sha === obj.sha) || (obj.dir && target.path.startsWith(`${obj.path}/`));
      if (!same) continue;
      const whole = coveredBy(target) ?? coveredBy(obj);
      const members = declared.filter((d) => d.member?.gen === g.id);
      const genOut = g.job ? declared.find((d) => d.dir && d.path === `store/jobs/${g.job}/out`) : undefined;
      const what = `catalogue generation ${g.id} of ${g.target.ref}${g.target.name ? ` (${g.target.name})` : ""}`;
      if (whole) units.push({ what, covered: true, how: `its container was ${whole.startsWith("declared") ? whole : `covered: ${whole}`}` });
      else if (genOut) units.push({ what, covered: true, how: `the output of ${g.job}, which made it, was declared` });
      else units.push({ what, covered: false, how: members.length ? `only ${members.map((m) => m.ref).join(", ")} of it were declared, not the whole` : "no job behind the record declared its container or any object in it" });
    }
  }
  if (!o.objects.length) why.push("the record names no object");
  const missing = units.filter((u) => !u.covered);
  if (missing.length) why.push(`not covered: ${missing.map((u) => `${u.what} (${u.how})`).join("; ")}`);
  return { coverage: why.length ? "partial" : "complete", units, jobs: jobs.map((j) => j.id), why };
}

// --- route plans ------------------------------------------------------------------------------

/** A planned route: the source to examine (a ref or a path of the run, or words) and the method. */
export type Route = { source: string; method: string };

/** Whether a route's source is something the hub can follow (an object ref or a run path), not only words. */
export function routeTrackable(source: string): boolean {
  return /^(input|job|import|member|sha256):/.test(source.trim()) || /^(inputs|store|catalog)\//.test(source.trim());
}

/**
 * Whether a route was examined: a job under the question's leads declared its
 * source or a container of it (a job that read everything counts, and is
 * said to), or a coverage record for the question names it among its
 * objects. A route named in words only is not something the hub can follow:
 * it stays not examined, and says why.
 */
export async function routeExamined(sandboxRoot: string, route: Route, o: { jobs: string[]; objects: string[] }): Promise<{ examined: boolean; how: string }> {
  if (!routeTrackable(route.source)) return { examined: false, how: "named in words, not as an object of the run: the hub cannot follow it" };
  const src = await objectOf(sandboxRoot, route.source);
  if ("reason" in src) return { examined: false, how: src.reason };
  for (const ref of o.objects) {
    const obj = await objectOf(sandboxRoot, ref);
    if (!("reason" in obj) && (contains(obj, src) || contains(src, obj))) return { examined: true, how: `a coverage record names ${ref}` };
  }
  for (const id of o.jobs) {
    const j = await jobDeclared(sandboxRoot, id);
    if (!j) continue;
    if (j.scope !== "declared") return { examined: true, how: `${id} read every object of the run (scope ${j.scope}: said, not measured)` };
    for (const d of j.inputs) {
      const obj = await objectOf(sandboxRoot, d);
      if (!("reason" in obj) && (contains(obj, src) || contains(src, obj))) return { examined: true, how: `${id} declared ${d}` };
    }
  }
  return { examined: false, how: "no job under the question's leads declared it, and no coverage record names it" };
}

export function routeWords(r: Route): string {
  return `${r.source} (${r.method})`;
}

// --- review of a negative -----------------------------------------------------------------------

/** What a reviewer of a negative says it did: each of three checks, done with what, or not done and why. */
export type ReviewCheck = { done: boolean; text: string };
export type NegativeReview = { detection: ReviewCheck; reproduced: ReviewCheck; other_route: ReviewCheck };
export const REVIEW_CHECKS: ReadonlyArray<{ key: keyof NegativeReview; words: string }> = [
  { key: "detection", words: "challenged the detection assumptions (would the event have left a trace in these sources, given collection and retention)" },
  { key: "reproduced", words: "reproduced a decisive check" },
  { key: "other_route", words: "tried a materially different route" },
];

/** A review as given, checked: each check {done, text}, the text saying what was done, or why not. */
export function checkReview(raw: unknown): { ok: true; review: NegativeReview } | { ok: false; reason: string } {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const out: Partial<NegativeReview> = {};
  for (const c of REVIEW_CHECKS) {
    const v = (r[c.key] && typeof r[c.key] === "object" ? r[c.key] : null) as { done?: unknown; text?: unknown } | null;
    if (!v || typeof v.done !== "boolean") return { ok: false, reason: `review.${c.key} is {done: true|false, text}: whether you ${c.words}, and what you did, or why not` };
    const text = String(v.text ?? "").trim();
    if (!text) return { ok: false, reason: `review.${c.key}.text is required: ${v.done ? "what you did" : "why not"}` };
    if (text.length > COVERAGE_TEXT_MAX) return { ok: false, reason: `review.${c.key}.text is over ${COVERAGE_TEXT_MAX} characters: say it in fewer; nothing is cut, so a longer text is refused` };
    out[c.key] = { done: v.done, text };
  }
  return { ok: true, review: out as NegativeReview };
}

/** A review in words, for the ledger's rendering and the report. */
export function reviewWords(r: NegativeReview): string {
  return REVIEW_CHECKS.map((c) => `${r[c.key].done ? "" : "not "}${c.key === "detection" ? "challenged the detection assumptions" : c.key === "reproduced" ? "reproduced a decisive check" : "tried another route"}: ${r[c.key].text}`).join("; ");
}
