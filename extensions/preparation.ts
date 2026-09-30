/**
 * Preparation: a source's broad extraction, before a negative is weighed on it.
 *
 * On the Belka runs four of five false negatives rested on a row no job had
 * ever produced: the iPhone's tar had been inventoried (the mobile pack's
 * kickoff recipe lists structures and "parses no artifact content") and read
 * narrowly, and the whole-source parse the pack's own tools can do was an
 * agent's choice that nobody made. Here a pack says which of its recipes is
 * a broad extraction (recipe.json `purpose: broad_extraction`, with the
 * capability it prepares and what it excludes); the hub offers one per
 * source digest and capability, runs the ones the pack marks `auto` without
 * an agent, and records each step on the store journal as a receipt:
 * planned, attempted, produced, partial, failed or declined. A receipt names
 * the source snapshot, the recipe and its version, the output manifest and
 * the exclusions. "Produced" never means complete: the exclusions say what
 * the extraction does not hold.
 *
 * The gate reads the receipts (docs/adr/0013, "A source's broad extraction
 * before a negative on it"): a negative that says the event did not happen,
 * or whose coverage is complete over a source, holds (`preparation_pending`)
 * while that source's broad extraction is planned or attempted; produced,
 * partial, failed or declined releases it, and so does the operator's
 * acceptance. Every other material negative on a source whose extraction
 * has not produced is warned (`preparation_missing`), and a negative's review
 * offer leads with the state of each source it rests on.
 *
 * Nothing here knows a tool or a format: receipts, refs, digests, the jobs'
 * declared inputs and the catalogue's generations. Which recipe is a broad
 * extraction of what is the pack's word.
 */

import { readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import * as NB from "./negative-bar.ts";
import type { LedgerEntry } from "./protocol.ts";

/** A receipt's states, in the order a preparation goes through them. */
export const PREPARATION_STATES = ["planned", "attempted", "produced", "partial", "failed", "declined"] as const;
export type PreparationState = (typeof PREPARATION_STATES)[number];
/** The states a broad extraction is still under way in: a negative that claims absence on its source is held. */
export const PREPARATION_PENDING: ReadonlySet<string> = new Set(["planned", "attempted"]);
/** The states that release the hold, once any receipt of a capability reaches one. */
export const PREPARATION_RELEASING: ReadonlySet<string> = new Set(["produced", "partial", "failed", "declined"]);
/** A recipe's purpose (recipe.json): an inventory lists what a source holds; a broad extraction parses it into a searchable form. */
export const RECIPE_PURPOSES = ["inventory", "broad_extraction"] as const;
export type RecipePurpose = (typeof RECIPE_PURPOSES)[number];

/** The source a receipt is of: the snapshot the recipe was given, by digest, and how the run names it. */
export type PreparationSource = { sha256: string; ref: string; name: string; bytes?: number };

/** A receipt as the store journal holds it (`type: "preparation"`). */
export type PreparationReceipt = {
  /** The journal line's seq and time. */
  seq: number;
  at: string;
  state: PreparationState;
  source: PreparationSource;
  recipe: string;
  recipe_version: string;
  recipe_sha256: string;
  capability: string;
  /** The job that runs or ran it, the lead that offers it, the generation it made. */
  job?: string;
  lead?: string;
  generation?: string;
  /** The output manifest: the job's sealed manifest's digest, its files and bytes; null before there is one. */
  manifest?: { sha256: string; files: number; bytes: number } | null;
  /** What the extraction does not hold: the recipe's declared exclusions, then what this run of it did not cover. */
  exclusions: string[];
  /** Why it failed or was declined, or what a partial one left out. */
  why?: string;
  /** Who wrote it down: the harness, a seat that declined it, the operator. */
  by: string;
  /** When the job's own step happened (accepted, started, finished), where it is not the receipt's own time. */
  when?: string;
};

/** One capability of one source: every receipt, the newest, and whether the hold is released. */
export type CapabilityPreparation = {
  capability: string;
  recipe: string;
  version: string;
  /** The newest receipt's state. */
  state: PreparationState;
  /** Released once any receipt reached produced, partial, failed or declined: a later run of it does not hold again. */
  released: boolean;
  /** The state a negative is weighed against: the newest releasing one once released, else the newest. */
  outcome: PreparationState;
  receipts: PreparationReceipt[];
  latest: PreparationReceipt;
  /** The receipt `outcome` is read from. */
  decisive: PreparationReceipt;
};

/** A source and its preparations, one per capability. */
export type SourcePreparation = {
  source: PreparationSource;
  capabilities: CapabilityPreparation[];
  /** Some capability is still planned or attempted and was never released. */
  pending: boolean;
  /** Every capability produced. */
  produced: boolean;
};

/** The key of a preparation: a source digest and a capability. */
export function preparationKey(sha256: string, capability: string): string {
  return `${sha256}\u0000${capability}`;
}

/** A journal line read as a receipt, or null when it is not one. */
export function receiptOf(line: Record<string, unknown>): PreparationReceipt | null {
  if (line.type !== "preparation") return null;
  const state = String(line.state ?? "");
  const src = (line.source ?? null) as PreparationSource | null;
  if (!(PREPARATION_STATES as readonly string[]).includes(state) || !src || typeof src.sha256 !== "string" || !src.sha256) return null;
  return {
    seq: Number(line.seq ?? 0),
    at: String(line.at ?? ""),
    state: state as PreparationState,
    source: { sha256: src.sha256, ref: String(src.ref ?? ""), name: String(src.name ?? src.ref ?? ""), ...(typeof src.bytes === "number" ? { bytes: src.bytes } : {}) },
    recipe: String(line.recipe ?? ""),
    recipe_version: String(line.recipe_version ?? ""),
    recipe_sha256: String(line.recipe_sha256 ?? ""),
    capability: String(line.capability ?? line.recipe ?? ""),
    ...(typeof line.job === "string" ? { job: line.job } : {}),
    ...(typeof line.lead === "string" ? { lead: line.lead } : {}),
    ...(typeof line.generation === "string" ? { generation: line.generation } : {}),
    ...(line.manifest && typeof line.manifest === "object" ? { manifest: line.manifest as PreparationReceipt["manifest"] } : line.manifest === null ? { manifest: null } : {}),
    exclusions: Array.isArray(line.exclusions) ? (line.exclusions as unknown[]).map(String) : [],
    ...(typeof line.why === "string" ? { why: line.why } : {}),
    by: String(line.by ?? "harness"),
    ...(typeof line.when === "string" ? { when: line.when } : {}),
  };
}

/**
 * The receipts folded by source and capability, in journal order: each
 * capability's newest state, whether any receipt released it, and the state
 * a negative is weighed against. Pure.
 */
export function foldPreparation(receipts: readonly PreparationReceipt[]): Map<string, SourcePreparation> {
  const byKey = new Map<string, PreparationReceipt[]>();
  for (const r of [...receipts].sort((a, b) => a.seq - b.seq)) {
    const k = preparationKey(r.source.sha256, r.capability);
    byKey.set(k, [...(byKey.get(k) ?? []), r]);
  }
  const out = new Map<string, SourcePreparation>();
  for (const list of byKey.values()) {
    const latest = list.at(-1)!;
    const releasing = [...list].reverse().find((r) => PREPARATION_RELEASING.has(r.state));
    const cap: CapabilityPreparation = {
      capability: latest.capability,
      recipe: latest.recipe,
      version: latest.recipe_version,
      state: latest.state,
      released: Boolean(releasing),
      outcome: releasing?.state ?? latest.state,
      receipts: list,
      latest,
      decisive: releasing ?? latest,
    };
    const sha = latest.source.sha256;
    const s = out.get(sha) ?? { source: latest.source, capabilities: [], pending: false, produced: true };
    s.capabilities.push(cap);
    out.set(sha, s);
  }
  for (const s of out.values()) {
    s.capabilities.sort((a, b) => a.capability.localeCompare(b.capability));
    s.pending = s.capabilities.some((c) => !c.released);
    s.produced = s.capabilities.every((c) => c.outcome === "produced");
  }
  return out;
}

let receiptsCache: { key: string; receipts: PreparationReceipt[] } | null = null;

/** Every receipt on a run's store journal, in order (none when it has no journal). */
export async function readReceipts(sandboxRoot: string): Promise<PreparationReceipt[]> {
  const path = join(sandboxRoot, "store", "journal.jsonl");
  const st = await stat(path).catch(() => null);
  if (!st) return [];
  const key = `${resolve(path)}:${st.size}:${st.mtimeMs}`;
  if (receiptsCache?.key === key) return receiptsCache.receipts;
  const text = await readFile(path, "utf8").catch(() => "");
  const out: PreparationReceipt[] = [];
  for (const line of text.split("\n")) {
    if (!line.includes('"type":"preparation"')) continue;
    try {
      const r = receiptOf(JSON.parse(line) as Record<string, unknown>);
      if (r) out.push(r);
    } catch {
      // A torn last line: the journal's own check names it.
    }
  }
  receiptsCache = { key, receipts: out };
  return out;
}

// --- a negative's reach into the sources ------------------------------------------------------

/**
 * How a coverage record reaches a source a preparation is of: it names the
 * source, or a directory holding it (`named`); it names a member of the
 * source's catalogue (`member`); or it names an output of a job whose
 * declared inputs lead back to the source (`derived`, through as many jobs
 * as it takes). `via` is the ref of the record that does it.
 */
export type SourceReach = { sha256: string; how: "named" | "member" | "derived"; via: string };

/** A preparation lead a seat or the operator closed, by its id: how, on what, and by whom. */
export type ClosedPreparationLead = { disposition: string; ref: string; by: string };

/** What the gate reads of the preparations: each source's state, each coverage record's reach into them, by the record's seq, and the preparation leads closed (a hold's fix never points at one). */
export type PreparationFacts = {
  sources: ReadonlyMap<string, SourcePreparation>;
  reach: ReadonlyMap<number, readonly SourceReach[]>;
  closed?: ReadonlyMap<string, ClosedPreparationLead>;
};

export const NO_PREPARATION: PreparationFacts = { sources: new Map(), reach: new Map() };

/** How many jobs back a derived object is followed to the source it came from. */
const DERIVATION_DEPTH = 12;

/** The job whose output a run path is, or null. */
function producingJob(path: string): string | null {
  return /^store\/jobs\/(j\d{6,})(?:\/|$)/.exec(path)?.[1] ?? null;
}

/**
 * Each standing coverage record's reach into the sources the preparations
 * are of (reachOf). Refs, digests, the catalogue's generations and the jobs'
 * declared inputs only. Nothing when the run holds no receipt.
 */
export async function preparationFacts(sandboxRoot: string, entries: readonly LedgerEntry[], leads?: Iterable<{ id: string; preparation?: unknown; closed?: { disposition: string; ref: string; by: string } | null }>): Promise<PreparationFacts> {
  const facts = await sourceFacts(sandboxRoot, entries);
  if (!leads || !facts.sources.size) return facts;
  const closed = new Map<string, ClosedPreparationLead>();
  for (const l of leads) if (l.preparation && l.closed) closed.set(l.id, { disposition: l.closed.disposition, ref: l.closed.ref, by: l.closed.by });
  return closed.size ? { ...facts, closed } : facts;
}

async function sourceFacts(sandboxRoot: string, entries: readonly LedgerEntry[]): Promise<PreparationFacts> {
  const receipts = await readReceipts(sandboxRoot);
  if (!receipts.length) return NO_PREPARATION;
  // Read once per state of the two records it rests on: the receipts and the ledger (what a ref names, a job's declared inputs and a generation's target do not change once written).
  const last = entries.at(-1);
  const key = `${resolve(sandboxRoot)}\u0000${receipts.length}:${receipts.at(-1)!.seq}\u0000${entries.length}:${last?.seq ?? 0}:${last?.hash ?? ""}:${entries.filter((e) => e.kind === "coverage").length}`;
  const hit = factsCache.get(key);
  if (hit) return hit;
  const facts = await computeFacts(sandboxRoot, receipts, entries);
  factsCache.set(key, facts);
  if (factsCache.size > 32) factsCache.delete(factsCache.keys().next().value!);
  return facts;
}

const factsCache = new Map<string, PreparationFacts>();

async function computeFacts(sandboxRoot: string, receipts: readonly PreparationReceipt[], entries: readonly LedgerEntry[]): Promise<PreparationFacts> {
  const sources = foldPreparation(receipts);
  const replaced = new Set<number>();
  for (const e of entries) if (typeof e.supersedes === "number") replaced.add(e.supersedes);
  const reach = new Map<number, SourceReach[]>();
  const ctx = await reachContext(sandboxRoot, sources);
  for (const e of entries) {
    if (e.kind !== "coverage" || replaced.has(e.seq)) continue;
    const r = await reachOf(ctx, e.refs ?? []);
    if (r.length) reach.set(e.seq, r);
  }
  return { sources, reach };
}

type ReachContext = {
  S: string;
  sources: Array<{ sha256: string; obj: NB.Obj | null }>;
  gens: NB.GenRecord[];
  jobInputs: Map<string, string[] | null>;
  objects: Map<string, NB.Obj | { reason: string }>;
};

async function reachContext(sandboxRoot: string, sources: ReadonlyMap<string, SourcePreparation>): Promise<ReachContext> {
  const ctx: ReachContext = { S: sandboxRoot, sources: [], gens: await NB.generations(sandboxRoot), jobInputs: new Map(), objects: new Map() };
  for (const [sha, s] of sources) {
    const o = s.source.ref ? await objectAt(ctx, s.source.ref) : null;
    ctx.sources.push({ sha256: sha, obj: o && !("reason" in o) ? { ...o, sha: o.sha ?? sha } : { ref: `sha256:${sha}`, path: `store/blobs/${sha}`, dir: false, sha } });
  }
  return ctx;
}

async function objectAt(ctx: ReachContext, ref: string): Promise<NB.Obj | { reason: string }> {
  const hit = ctx.objects.get(ref);
  if (hit) return hit;
  const o = await NB.objectOf(ctx.S, ref).catch((err: Error) => ({ reason: err.message }));
  ctx.objects.set(ref, o);
  return o;
}

/** The sources an object is, or holds (a directory holding one, the same digest). */
function sourcesIn(ctx: ReachContext, o: NB.Obj): string[] {
  return ctx.sources.filter((s) => s.obj && NB.contains(o, s.obj)).map((s) => s.sha256);
}

/** A job's declared inputs, from its record (null when it declared none: a job over everything is not traced to one source). */
async function declaredInputs(ctx: ReachContext, job: string): Promise<string[] | null> {
  if (ctx.jobInputs.has(job)) return ctx.jobInputs.get(job) ?? null;
  const j = await NB.jobDeclared(ctx.S, job).catch(() => null);
  const inputs = j && j.scope === "declared" ? j.inputs : null;
  ctx.jobInputs.set(job, inputs);
  return inputs;
}

/** The sources a job's output was made from: its declared inputs, followed back through the jobs that made them. */
async function derivedSources(ctx: ReachContext, job: string, seen: Set<string>, depth: number): Promise<string[]> {
  if (seen.has(job) || depth > DERIVATION_DEPTH) return [];
  seen.add(job);
  const out = new Set<string>();
  for (const ref of (await declaredInputs(ctx, job)) ?? []) {
    const o = await objectAt(ctx, ref);
    if ("reason" in o) continue;
    for (const sha of sourcesIn(ctx, o)) out.add(sha);
    for (const sha of await objectSources(ctx, o, seen, depth + 1).then((xs) => xs.map((x) => x.sha256))) out.add(sha);
  }
  return [...out];
}

/** Where an object leads, other than being a source itself: a member of a source's catalogue, a catalogue file, or a job's output. */
async function objectSources(ctx: ReachContext, o: NB.Obj, seen: Set<string>, depth: number): Promise<Array<{ sha256: string; how: "member" | "derived" }>> {
  const out: Array<{ sha256: string; how: "member" | "derived" }> = [];
  const gen = o.member?.gen ?? /^catalog\/gen\/([a-z0-9-]+)(?:\/|$)/.exec(o.path)?.[1];
  if (gen) {
    const g = ctx.gens.find((x) => x.id === gen);
    const target = g?.target?.sha256 ? ctx.sources.find((s) => s.sha256 === g.target!.sha256)?.sha256 : undefined;
    const t = !target && g?.target?.ref ? await objectAt(ctx, g.target.ref) : null;
    for (const sha of target ? [target] : t && !("reason" in t) ? sourcesIn(ctx, t) : []) out.push({ sha256: sha, how: o.member ? "member" : "derived" });
    if (!o.member && g?.job) for (const sha of await derivedSources(ctx, g.job, seen, depth)) out.push({ sha256: sha, how: "derived" });
  }
  const job = producingJob(o.path);
  if (job) for (const sha of await derivedSources(ctx, job, seen, depth)) out.push({ sha256: sha, how: "derived" });
  return out;
}

/** What a coverage record's refs reach, each source once, by the closest way (named, then member, then derived). */
export async function reachOfRefs(sandboxRoot: string, sources: ReadonlyMap<string, SourcePreparation>, refs: readonly string[]): Promise<SourceReach[]> {
  return reachOf(await reachContext(sandboxRoot, sources), refs);
}

async function reachOf(ctx: ReachContext, refs: readonly string[]): Promise<SourceReach[]> {
  const rank = { named: 0, member: 1, derived: 2 } as const;
  const best = new Map<string, SourceReach>();
  const put = (x: SourceReach) => {
    const had = best.get(x.sha256);
    if (!had || rank[x.how] < rank[had.how]) best.set(x.sha256, x);
  };
  for (const ref of refs) {
    if (/^unresolved:/.test(ref)) continue;
    const o = await objectAt(ctx, ref);
    if ("reason" in o) continue;
    for (const sha of sourcesIn(ctx, o)) put({ sha256: sha, how: "named", via: ref });
    for (const x of await objectSources(ctx, o, new Set(), 0)) put({ ...x, via: ref });
  }
  return [...best.values()].sort((a, b) => rank[a.how] - rank[b.how] || a.sha256.localeCompare(b.sha256));
}

// --- the gate's reading ---------------------------------------------------------------------------

/** A source a negative is held on: the pending preparation, and the coverage records whose claim makes it hold (absence, or complete coverage over the source). */
export type PreparationHold = { source: SourcePreparation; coverage: number[]; claim: "absence" | "complete" };
/** A source a negative is warned of: its preparation has not produced, and the coverage records that reach it. */
export type PreparationWarn = { source: SourcePreparation; coverage: number[]; how: SourceReach["how"] };

/**
 * What the preparations say of one negative answer, given the standing
 * coverage records it cites for its question (`coverage`): the sources it
 * is held on (preparation_pending), and those it is warned of
 * (preparation_missing). Held: the answer says the event did not happen
 * (asserts_absence), or a record it cites is complete (the hub's object
 * coverage), and that record names the source (itself or a directory
 * holding it) whose broad extraction is planned or attempted and was never
 * released. Warned: every other source a record reaches (named, a member of
 * its catalogue, or an output made from it) whose preparation has not
 * produced. A held source is not also warned. Pure.
 */
export function preparationFindings(answer: Pick<LedgerEntry, "asserts_absence">, coverage: readonly LedgerEntry[], facts: PreparationFacts): { hold: PreparationHold[]; warn: PreparationWarn[] } {
  if (!facts.sources.size) return { hold: [], warn: [] };
  const hold = new Map<string, PreparationHold>();
  const warn = new Map<string, PreparationWarn>();
  const rank = { named: 0, member: 1, derived: 2 } as const;
  for (const c of coverage) {
    for (const r of facts.reach.get(c.seq) ?? []) {
      const s = facts.sources.get(r.sha256);
      if (!s) continue;
      const claim: PreparationHold["claim"] | null = r.how === "named" ? (answer.asserts_absence === true ? "absence" : c.coverage === "complete" ? "complete" : null) : null;
      if (s.pending && claim) {
        const h = hold.get(r.sha256) ?? { source: s, coverage: [], claim };
        if (!h.coverage.includes(c.seq)) h.coverage.push(c.seq);
        if (claim === "absence") h.claim = "absence";
        hold.set(r.sha256, h);
        continue;
      }
      if (s.produced) continue;
      const w = warn.get(r.sha256) ?? { source: s, coverage: [], how: r.how };
      if (!w.coverage.includes(c.seq)) w.coverage.push(c.seq);
      if (rank[r.how] < rank[w.how]) w.how = r.how;
      warn.set(r.sha256, w);
    }
  }
  for (const sha of hold.keys()) warn.delete(sha);
  const bySource = <T extends { source: SourcePreparation }>(xs: Iterable<T>) => [...xs].sort((a, b) => a.source.source.name.localeCompare(b.source.source.name));
  return { hold: bySource(hold.values()), warn: bySource(warn.values()) };
}

// --- words ----------------------------------------------------------------------------------------

/** One capability's state in words: what it is, where it stands, and what it leaves out. */
export function capabilityWords(c: CapabilityPreparation): string {
  const r = c.decisive;
  const where = r.job ? `job ${r.job}` : r.lead ? `offered as ${r.lead}` : "";
  const said: Record<PreparationState, string> = {
    planned: `planned (${r.job ? `queued as job ${r.job}` : r.lead ? `offered as ${r.lead}, nobody has run it yet` : "not queued yet"})`,
    attempted: `attempted (${where || "running"}${r.when ? `, since ${r.when}` : ""})`,
    produced: `produced (${where}${r.generation ? `, generation ${r.generation} at catalog/gen/${r.generation}/` : ""}${r.manifest ? `, ${r.manifest.files} file(s), ${r.manifest.bytes} bytes` : ""})`,
    partial: `partial (${where}${r.generation ? `, generation ${r.generation} at catalog/gen/${r.generation}/` : ""}${r.why ? `: ${r.why}` : ""})`,
    failed: `failed (${where}${r.why ? `: ${r.why}` : ""})`,
    declined: `declined (by ${r.by}${r.lead ? ` on ${r.lead}` : ""}${r.why ? `: ${r.why}` : ""})`,
  };
  const again = c.released && PREPARATION_PENDING.has(c.state) ? `; run again since, now ${c.state}${c.latest.job ? ` (job ${c.latest.job})` : ""}` : "";
  return `${c.recipe} ${c.version} ${said[c.outcome]}${again}${c.decisive.exclusions.length ? `; it does not hold: ${c.decisive.exclusions.join("; ")}` : ""}`;
}

/** A source's preparation in words: its name, then each capability. */
export function sourceWords(s: SourcePreparation): string {
  return `${s.source.name}: broad extraction ${s.capabilities.map(capabilityWords).join(" / ")}`;
}

/**
 * What a hold asks: wait for the job, run or decline the offered lead, or
 * the operator accepts. A lead already closed (`closed`, by id) is never
 * pointed at as something to claim or close: its close is recorded as the
 * decline at the hub's next round, or the extraction is run directly.
 */
export function holdFix(s: SourcePreparation, closed?: ReadonlyMap<string, ClosedPreparationLead>): string {
  const pending = s.capabilities.filter((c) => !c.released);
  const target = s.source.ref || `sha256:${s.source.sha256}`;
  const steps = pending.map((c) => {
    const r = c.latest;
    if (r.job) return `wait for job ${r.job} (${c.recipe} over ${s.source.ref || s.source.name}; job_status ${r.job})`;
    const shut = r.lead ? closed?.get(r.lead) : undefined;
    if (r.lead && shut) return `${r.lead}, the offered ${c.recipe} over ${s.source.ref || s.source.name}, was closed ${shut.disposition} by ${shut.by} (${shut.ref}) and nothing ran it: the hub records that close as its decline at its next round, which releases the hold; or run it now: catalog_request target=${target} recipe=${c.recipe}`;
    if (r.lead) return `run or decline ${r.lead}, the offered ${c.recipe} over ${s.source.ref || s.source.name}: lead_claim ${r.lead}, then catalog_request target=${target} recipe=${c.recipe}; or close ${r.lead} deferred or infeasible citing a limitation that says why it is not run (its receipt is then declined)`;
    return `wait for ${c.recipe} over ${s.source.ref || s.source.name} to be queued`;
  });
  return steps.join("; ");
}

/** The state of each source a negative rests on, for its review offer: what the reviewer reads first. */
export function reviewPreparationWords(findings: { hold: PreparationHold[]; warn: PreparationWarn[] }, others: readonly SourcePreparation[] = []): string | null {
  const lines: string[] = [];
  for (const h of findings.hold) lines.push(`${sourceWords(h.source)} — this negative is held (preparation_pending) until it is produced, partial, failed or declined: review it against what the extraction holds once it is in`);
  for (const w of findings.warn) lines.push(`${sourceWords(w.source)} — the negative ${w.how === "named" ? "names this source" : w.how === "member" ? "names members of this source's catalogue" : "rests on outputs made from this source"} and was weighed without a produced broad extraction of it`);
  for (const s of others) lines.push(sourceWords(s));
  return lines.length ? `Preparation of the sources it rests on: ${lines.join(" | ")}.` : null;
}
