/**
 * The hub's side of preparation (extensions/preparation.ts, docs/adr/0013 "A
 * source's broad extraction before a negative on it"): the offers and the
 * receipts, reconciled from what the run's records already say, once a
 * round, so a restart loses nothing and writes nothing twice.
 *
 * What applies to what is the census's (catalog/plan.json `preparations`,
 * each input a pack's broad-extraction recipe answered yes for) and, for
 * evidence added later, the system's own detect passes over each added file
 * (their detect.tsv). Then, per source digest and capability:
 *
 *   - a recipe its pack marks `auto` was queued by the kickoff (or by the
 *     evidence's detect pass, or the derived catalogue) and runs without an
 *     agent: its receipts follow its job;
 *   - any other is offered as a lead (leads.ts openPreparationLead), once,
 *     unless the same capability over the same bytes is queued, running or
 *     sealed already, or on the record in any state;
 *   - one the pack declares but the job images cannot run (`unavailable`) is
 *     declined, with the pack's why; so is one the kickoff's queue refused.
 *
 * Receipts, on the store journal (`type: "preparation"`): planned (queued as
 * a job, or offered as a lead), attempted (its job started), produced,
 * partial or failed (its job ended, with the generation, the output
 * manifest and what this run of it did not cover), declined (unavailable,
 * refused, or a seat closed its lead deferred, infeasible or needs_operator
 * citing why). Every recipe job whose recipe is a broad extraction has its
 * receipts, whoever asked for it. A preparation lead whose extraction
 * reached an outcome by any route is closed by the harness.
 *
 * Nothing here parses a format or names a tool: recipe declarations, job
 * records, refs, digests and the two registers.
 */
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import * as L from "../extensions/leads.ts";
import * as PR from "../extensions/preparation.ts";
import { resolveRef, type Journal } from "./evidence-store.ts";
import type { JobRecord, RecipeInfo, Target } from "./job-service.ts";

/** What the reconciliation reads of the job service: its journal, its jobs, its recipes. */
export type PreparationService = {
  journal: Journal;
  jobs: ReadonlyMap<string, JobRecord>;
  recipe(id: string): Promise<RecipeInfo | null>;
};

/** A broad extraction the census found applies to an input (catalog/plan.json `preparations`). */
export type PlannedPreparation = {
  input: string;
  recipe: string;
  capability?: string;
  auto?: boolean;
  unavailable?: string;
  target: Target;
};

/** What a round of reconciliation did. */
export type PreparationRound = { receipts: number; opened: string[]; closed: string[]; notes: string[] };

/** The receipt a line would be, less what the journal adds. */
type Draft = Omit<PR.PreparationReceipt, "seq" | "at">;

/** A receipt's identity: the same source, capability, job or lead, and state is written once. */
function tag(r: Pick<PR.PreparationReceipt, "source" | "capability" | "job" | "lead" | "state">): string {
  return `${r.source.sha256}|${r.capability}|${r.job ?? ""}|${r.lead ?? ""}|${r.state}`;
}

/** The limiting dispositions a seat declines a preparation lead with. */
const DECLINING: ReadonlySet<string> = new Set(["deferred", "infeasible", "needs_operator"]);
/** A job's states once it will run no more. */
const ENDED: ReadonlySet<string> = new Set(["committed", "failed", "cancelled"]);

/**
 * The source a recipe's target is, by digest: its own sha256 (a derived or
 * requested object), or the digest inputs.json or the store holds for its
 * ref. Null when the run has no digest for it (it cannot be keyed).
 */
export async function sourceOf(sandbox: string, t: Target | undefined): Promise<PR.PreparationSource | null> {
  if (!t) return null;
  const ref = t.ref ?? "";
  let sha = t.sha256 && /^[0-9a-f]{64}$/.test(t.sha256) ? t.sha256 : "";
  let bytes: number | undefined;
  if (ref) {
    const r = await resolveRef(sandbox, ref).catch(() => null);
    if (r?.ok && "sha256" in r && typeof r.sha256 === "string" && /^[0-9a-f]{64}$/.test(r.sha256)) sha ||= r.sha256;
    if (r?.ok && "bytes" in r && typeof r.bytes === "number") bytes = r.bytes;
  }
  if (!sha) return null;
  return { sha256: sha, ref: ref || `sha256:${sha}`, name: t.name ?? ref ?? `sha256:${sha}`, ...(bytes !== undefined ? { bytes } : {}) };
}

/** The census's list of broad extractions that apply (none for a run from before it). */
export async function plannedPreparations(sandbox: string): Promise<PlannedPreparation[]> {
  try {
    const plan = JSON.parse(await readFile(join(sandbox, "catalog", "plan.json"), "utf8")) as { preparations?: PlannedPreparation[] };
    return Array.isArray(plan.preparations) ? plan.preparations.filter((p) => p && typeof p.recipe === "string" && p.target && Array.isArray(p.target.paths)) : [];
  } catch {
    return [];
  }
}

/** The broad extractions a system detect pass (evidence added after the kickoff) found apply and did not run: offered, or declined. */
async function detectedPreparations(sandbox: string, svc: PreparationService, recipeOf: (id: string) => Promise<RecipeInfo | null>): Promise<PlannedPreparation[]> {
  const out: PlannedPreparation[] = [];
  for (const j of svc.jobs.values()) {
    if (j.spec.kind !== "detect" || j.requester.agent !== "system" || j.spec.trigger === "derived" || j.state !== "committed") continue;
    const text = await readFile(join(sandbox, "store", "jobs", j.id, "out", "detect.tsv"), "utf8").catch(() => "");
    for (const line of text.split("\n")) {
      const [i, rid, rc] = line.split("\t");
      const t = j.spec.targets?.[Number(i)];
      if (!rid || rc !== "0" || !t) continue;
      const r = await recipeOf(rid);
      if (!r || r.purpose !== "broad_extraction") continue;
      // An auto one was submitted by the pass itself (job-service fromDetect): its receipts follow its job.
      if (!r.unavailable && r.auto.length) continue;
      out.push({ input: t.name ?? t.ref ?? "", recipe: rid, target: t, ...(r.unavailable ? { unavailable: r.unavailable } : {}) });
    }
  }
  return out;
}

/** What a recipe's generation says this run of it did not cover: the recipe's own words, whole. */
async function runExclusions(sandbox: string, generation: string | undefined): Promise<{ status: string; left: string[] }> {
  if (!generation) return { status: "unknown", left: [] };
  try {
    const g = JSON.parse(await readFile(join(sandbox, "catalog", "gen", generation, "generation.json"), "utf8")) as { status?: string; coverage?: { not_covered?: unknown; limits_hit?: unknown[]; errors?: unknown[]; withheld?: unknown } | null };
    const c = g.coverage ?? null;
    const left = [
      ...(c?.withheld ? [String(c.withheld)] : []),
      ...(c?.not_covered ? [`not covered in this run: ${String(c.not_covered)}`] : []),
      ...(c?.limits_hit ?? []).map((x) => `a limit hit: ${String(x)}`),
      ...(c?.errors ?? []).map((x) => `an error: ${String(x)}`),
    ];
    return { status: String(g.status ?? "unknown"), left };
  } catch {
    return { status: "unknown", left: [] };
  }
}

/**
 * One round: every receipt the records call for and the journal does not
 * hold, appended in order; every offer due, made; every preparation lead
 * whose extraction reached an outcome, closed. Idempotent: a second round
 * over the same records writes nothing.
 */
export async function reconcilePreparation(svc: PreparationService, sandbox: string, o: { now?: number } = {}): Promise<PreparationRound> {
  const S = resolve(sandbox);
  const round: PreparationRound = { receipts: 0, opened: [], closed: [], notes: [] };
  const written = new Set<string>();
  const byKey = new Map<string, PR.PreparationReceipt[]>();
  const note = (r: PR.PreparationReceipt) => {
    written.add(tag(r));
    const k = PR.preparationKey(r.source.sha256, r.capability);
    byKey.set(k, [...(byKey.get(k) ?? []), r]);
  };
  for (const l of svc.journal.of("preparation")) {
    const r = PR.receiptOf(l as unknown as Record<string, unknown>);
    if (r) note(r);
  }
  const put = async (d: Draft): Promise<void> => {
    if (written.has(tag(d))) return;
    const line = await svc.journal.append({ type: "preparation", ...d });
    const r = PR.receiptOf(line as unknown as Record<string, unknown>);
    if (r) note(r);
    round.receipts += 1;
  };
  const recipes = new Map<string, RecipeInfo | null>();
  const recipeOf = async (id: string): Promise<RecipeInfo | null> => {
    if (!recipes.has(id)) recipes.set(id, await svc.recipe(id).catch(() => null));
    return recipes.get(id) ?? null;
  };
  const released = (k: string) => (byKey.get(k) ?? []).some((r) => PR.PREPARATION_RELEASING.has(r.state));
  const base = (r: RecipeInfo, src: PR.PreparationSource) => ({ source: src, recipe: r.id, recipe_version: r.version ?? "", recipe_sha256: r.sha256, capability: r.capability ?? r.id, exclusions: r.exclusions ?? [], by: "harness" });

  // 1. Every broad-extraction recipe job, whoever asked for it: planned, attempted, and how it ended.
  const jobsByKey = new Map<string, JobRecord[]>();
  for (const j of [...svc.jobs.values()].sort((a, b) => a.id.localeCompare(b.id))) {
    if (j.spec.kind !== "recipe" || !j.spec.recipe) continue;
    const r = await recipeOf(j.spec.recipe);
    if (!r || r.purpose !== "broad_extraction") continue;
    const src = await sourceOf(S, j.spec.target);
    if (!src) {
      round.notes.push(`${j.id} (${r.id}) has no digest for its target ${j.spec.target?.ref ?? "?"}: no receipt can name its source`);
      continue;
    }
    const k = PR.preparationKey(src.sha256, r.capability ?? r.id);
    jobsByKey.set(k, [...(jobsByKey.get(k) ?? []), j]);
    const b = { ...base(r, src), recipe_sha256: j.tool_sha256 ?? r.sha256, job: j.id };
    await put({ ...b, state: "planned", manifest: null, when: j.accepted_at });
    if (j.started_at) await put({ ...b, state: "attempted", manifest: null, when: j.started_at });
    if (j.state === "committed") {
      // A committed recipe gets its generation just after (job-service afterCommit): its outcome is read from it.
      if (!j.generation && (j.status === "ok" || j.status === "failed" || j.status === "timed_out")) continue;
      const run = await runExclusions(S, j.generation);
      const manifest = j.outputs ? { sha256: j.outputs.manifest_sha256, files: j.outputs.files, bytes: j.outputs.bytes } : null;
      const common = { ...b, manifest, ...(j.generation ? { generation: j.generation } : {}), exclusions: [...b.exclusions, ...run.left], when: j.finished_at ?? j.accepted_at };
      if (j.status === "ok" && run.status === "complete") await put({ ...common, state: "produced" });
      else if (j.status === "timed_out" || (j.status === "ok" && run.status === "partial")) await put({ ...common, state: "partial", why: j.status === "timed_out" ? `stopped at its time limit${j.reason ? ` (${j.reason})` : ""}: what it wrote before is kept` : run.left.join("; ") || "the recipe said partial" });
      else await put({ ...common, state: "failed", why: [j.program_missing ? `a program it runs is not in its image (${j.program_missing.program ?? "?"} in ${j.program_missing.image})` : "", j.reason ?? "", j.status && j.status !== "ok" ? `status ${j.status}` : `the recipe's own status ${run.status}`, ...run.left].filter(Boolean).join("; ") });
    } else if (j.state === "failed" || j.state === "cancelled") {
      await put({ ...b, state: "failed", manifest: null, why: `${j.state === "cancelled" ? "cancelled" : "it could not run"}${j.reason ? `: ${j.reason}` : ""}`, when: j.finished_at ?? j.accepted_at });
    }
  }

  // 2. What applies and did not run by itself: offered once, or declined with why.
  const kickoff = svc.journal.of("kickoff_queued").at(-1) as (Record<string, unknown> & { refused?: Array<{ recipe: string; input: string; reason: string }> }) | undefined;
  const items = [...(await plannedPreparations(S)), ...(await detectedPreparations(S, svc, recipeOf))];
  // The lead register as its chain says it (the fold alone: no ledger or jobs read for this).
  const leadState = async () => L.foldLeads((await L.readLeadEvents(S).catch(() => ({ events: [] as L.LeadEvent[] }))).events);
  const leads = items.length ? await leadState() : null;
  for (const p of items) {
    const r = await recipeOf(p.recipe);
    if (!r || r.purpose !== "broad_extraction") continue;
    const src = await sourceOf(S, p.target);
    if (!src) {
      round.notes.push(`${p.recipe} over ${p.input}: the run has no digest for it, so it is not offered`);
      continue;
    }
    const cap = r.capability ?? r.id;
    const k = PR.preparationKey(src.sha256, cap);
    const b = base(r, src);
    // Dedup: the same capability over the same bytes queued, running or sealed, or on the record in any state, is not offered again.
    if (jobsByKey.get(k)?.length) continue;
    if (byKey.get(k)?.length) continue;
    const why = r.unavailable ?? p.unavailable;
    if (why) {
      await put({ ...b, state: "declined", manifest: null, why: `its pack declares it, and it cannot run in this run's job images: ${why}` });
      continue;
    }
    if (p.auto) {
      const refused = kickoff?.refused?.find((x) => x.recipe === p.recipe && x.input === p.input);
      if (refused) await put({ ...b, state: "declined", manifest: null, why: `the kickoff's queue refused it: ${refused.reason}` });
      continue;
    }
    const lead = leads ? [...leads.leads.values()].find((l) => l.preparation?.sha256 === src.sha256 && l.preparation.capability === cap) : undefined;
    const opened = lead ? { ok: true as const, id: lead.id } : await L.openPreparationLead(S, { sha256: src.sha256, ref: src.ref, name: src.name, capability: cap, recipe: r.id, version: r.version ?? "", description: r.description ?? "", exclusions: r.exclusions ?? [] }, o.now);
    if (!opened.ok) {
      round.notes.push(`${r.id} over ${src.name} could not be offered: ${opened.reason}`);
      continue;
    }
    if (!lead) round.opened.push(opened.id);
    await put({ ...b, state: "planned", manifest: null, lead: opened.id });
  }

  // 3. The preparation leads: a seat's decline, a planned receipt a crash left out, and a lead whose extraction reached an outcome closed.
  for (const l of (await leadState()).leads.values()) {
    const p = l.preparation;
    if (!p) continue;
    const r = await recipeOf(p.recipe);
    const k = PR.preparationKey(p.sha256, p.capability);
    const known = byKey.get(k)?.at(-1)?.source;
    const src: PR.PreparationSource = known ?? { sha256: p.sha256, ref: p.ref, name: p.ref || `sha256:${p.sha256}` };
    const b = { ...(r ? base(r, src) : { source: src, recipe: p.recipe, recipe_version: "", recipe_sha256: "", capability: p.capability, exclusions: [] as string[], by: "harness" }), lead: l.id };
    if (!(byKey.get(k) ?? []).some((x) => x.lead === l.id)) await put({ ...b, state: "planned", manifest: null });
    if (l.closed && l.closed.by !== "system" && DECLINING.has(l.closed.disposition) && !released(k)) {
      await put({ ...b, state: "declined", manifest: null, by: l.closed.by, why: `${l.id} closed ${l.closed.disposition} on ${l.closed.ref}${l.closed.why ? `: ${l.closed.why}` : ""}` });
    }
    // Closed any other way (resolved, duplicate, negative) with nothing that ran the extraction or runs it now: the seat's decline, and the receipt says so (the Fable review of the limits branch, P3-2).
    else if (l.closed && l.closed.by !== "system" && !released(k) && !(jobsByKey.get(k) ?? []).some((j) => !ENDED.has(j.state))) {
      await put({ ...b, state: "declined", manifest: null, by: l.closed.by, why: `${l.id} closed ${l.closed.disposition} on ${l.closed.ref}${l.closed.why ? `: ${l.closed.why}` : ""}, and nothing ran the extraction it offered: its close is its decline` });
    }
    // Closed by the harness only while no seat holds it: a held lead is its holder's to close (P3-3).
    if (!l.closed && !l.holder && released(k)) {
      const last = [...(byKey.get(k) ?? [])].reverse().find((x) => PR.PREPARATION_RELEASING.has(x.state))!;
      const ref = `${last.state}${last.job ? ` by job ${last.job}` : ""}${last.generation ? `, generation ${last.generation}` : ""} (store journal line ${last.seq})`;
      const c = await L.closePreparationLead(S, l.id, ref, `the broad extraction it offered is ${last.state}${last.why ? `: ${last.why}` : ""}; its receipt is on the store journal, and nothing more is asked of this lead`);
      if (c.ok && c.closed) round.closed.push(l.id);
    }
  }
  return round;
}
