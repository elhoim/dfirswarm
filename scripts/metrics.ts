#!/usr/bin/env node
/**
 * Process metrics of a run, read from its own registers: no truth, no case,
 * no tool's output (docs/adr/0017, the definitions in docs/usage.md).
 *
 *   node --experimental-strip-types scripts/metrics.ts <run-dir> [--json]
 *   node --experimental-strip-types scripts/metrics.ts --compare <run-dir-A> <run-dir-B> [--json]
 *   swarm.sh metrics <id> [--json]
 *   swarm.sh metrics --compare <id-A> <id-B> [--json]
 *
 * What is read, and nothing else: the lead register (leads/leads.jsonl, and
 * the finish register leads/finish.jsonl where the run has one), the question
 * register, the ledger with its attestations and disputes, the operator
 * requests, the store's journal (jobs, reuse hints, evidence added), the
 * network's grants and fetches, the trace (done calls, the hub's refusals),
 * the run's end (done/SWARM_DONE, done/STOPPED) and the seats' token records
 * (the model gateway's log, else the Pi sessions). A register a run does not
 * have is said to be absent, never read as zero: a run from before offers
 * has no offer events, one from before the reuse hints no job_similar lines.
 *
 * Each figure is a count of named records, and the JSON lists them (ids,
 * sections, seats, times), so a figure can be checked against the register
 * it came from. No answer value, no finding's text and no command is printed:
 * a metric says what the process did, never what the case holds.
 *
 * `--compare` sets two runs of the same goal side by side, question by
 * question: each one's standing result, whether it was reviewed, its
 * coverage and acceptance, and where they agree or disagree. A negative in
 * one run that the other established is flagged; so is agreement on a
 * negative resting on partial coverage in both, which may be a shared blind
 * spot rather than a confirmation. Neither run's conclusions are shown to the
 * other: this is read after both ended.
 */
import { existsSync, statSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import * as NB from "../extensions/negative-bar.ts";
import { readNetState, grantStatus } from "./net-grants.ts";
import { storePaths } from "./evidence-store.ts";

type Rec = Record<string, unknown>;

export const METRICS_FORMAT = "dfirswarm-metrics/1";
export const COMPARE_FORMAT = "dfirswarm-metrics-compare/1";

const str = (v: unknown): string => (typeof v === "string" ? v : v === undefined || v === null ? "" : String(v));
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const ms = (iso: unknown): number | null => {
  const t = Date.parse(str(iso));
  return Number.isFinite(t) ? t : null;
};
const minutes = (from: number | null, to: number | null): number | null => (from === null || to === null ? null : Math.round(((to - from) / 60000) * 10) / 10);
const iso = (t: number | null): string | null => (t === null ? null : new Date(t).toISOString());

async function jsonl(path: string): Promise<Rec[]> {
  const text = await readFile(path, "utf8").catch(() => "");
  const out: Rec[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const v = JSON.parse(line) as unknown;
      if (v && typeof v === "object" && !Array.isArray(v)) out.push(v as Rec);
    } catch {
      // a torn line is skipped; the register's own chain check names it
    }
  }
  return out;
}

/** A question's section key, however it is written: question:3, Q-3 (through the register), 3, or a goal's own id. */
function sectionOf(raw: string, qs: Q.QuestionsSnapshot | null): string {
  const t = raw.trim();
  if (qs && /^Q-\d+$/i.test(t)) {
    const q = Q.findQuestion(qs, t);
    if (q) return q.section;
  }
  return P.sectionKey(t.replace(/^question:/i, ""));
}

// --- the shape ------------------------------------------------------------------------------------

export type QuestionRef = { section: string; id: string | null };

export type RunMetrics = {
  format: typeof METRICS_FORMAT;
  run: string;
  run_dir: string;
  measured_at: string;
  outcome: { outcome: string | null; by: string | null; at: string | null; why: string | null };
  registers: Record<string, boolean>;
  questions: { in_scope: QuestionRef[]; source: "register" | "goal" | "ledger" };
  negatives: {
    closes: number;
    quick: { count: number; items: Array<{ lead: string; seq: number; questions: string[]; held_seconds: number; jobs: number; objects: number }> };
    answers: number;
    reviewed: number;
    unreviewed_material: Array<{ section: string; id: string | null; answer: string; result: string }>;
    unreviewed_background: Array<{ section: string; id: string | null; answer: string; result: string }>;
  };
  coverage: {
    records: number;
    reviewed: number;
    complete: number;
    partial: number;
    not_computed: number;
    stale: Array<{ record: string; problems: string[] }>;
    negatives_on_partial: Array<{ section: string; id: string | null; answer: string; coverage: string[] }>;
    negatives_without_coverage: Array<{ section: string; id: string | null; answer: string }>;
  };
  offers: {
    recorded: boolean;
    leads: OfferCounts & { by_reason: Record<string, OfferCounts> };
    questions: { made: number; accepted: number; declined: number; not_taken_up: number };
    wakes_before_offers: { made: number; taken_by_woken: number; taken_by_another: number; not_taken: number };
  };
  done: {
    calls: number;
    accepted: number;
    created_sentinel: number;
    refused: number;
    refused_by: Record<string, number>;
    hub_refused: number;
    not_yours: number;
    items: Array<{ at: string; agent: string; how: string; reason?: string }>;
  };
  tail: {
    end_at: string | null;
    end: "sentinel" | "stopped" | "paused" | null;
    ready_at: string | null;
    ready_source: "readiness" | "first answers" | null;
    all_first_answered_at: string | null;
    all_final_answered_at: string | null;
    minutes_from_ready: number | null;
    minutes_from_first_answers: number | null;
    minutes_from_final_answers: number | null;
    unanswered: string[];
  };
  acquisition: {
    requests: number;
    by_stage: Record<string, number>;
    declined_by_policy: number;
    gaps: Array<{ rid: string; stage: string | null; state: string; questions: string[]; cause: string | null }>;
    questions_with_gap: string[];
    evidence_added: number;
    evidence_added_for_request: number;
  };
  interpretations: {
    total: number;
    valid: number;
    superseded: number;
    disputed: number;
    missing: number;
    jobs_under_leads: number;
    jobs_uninterpreted: string[];
    jobs_without_valid: string[];
  };
  reversals: {
    answer_supersessions: number;
    corrections: number;
    result_changes: Array<{ section: string; from: string; to: string; from_result: string | null; to_result: string | null; cause: "new_evidence" | "discoverable" }>;
    negative_reopens: Array<{ lead: string; closed_seq: number; reopened_at: string; reopen_cause: string; cause: "new_evidence" | "discoverable" }>;
    new_evidence: number;
    discoverable: number;
  };
  cost: {
    source: "model-gateway" | "pi-sessions" | null;
    tokens: number;
    usd: number;
    per_question: Array<{ section: string; id: string | null; tokens: number; usd: number; leads: string[] }>;
    unheld: { tokens: number; usd: number };
    leads_without_question: { tokens: number; usd: number; leads: string[] };
  };
  duplicates: {
    recorded: boolean;
    jobs_with_similar: string[];
    exact_repeats: string[];
    independent: string[];
    independent_with_similar: string[];
    same_as: { jobs: string[]; files: number; bytes: number; whole: string[] };
    recipe_merged: number;
    shadow_would_merge: number;
  };
  network: {
    recorded: boolean;
    requests: number;
    granted: number;
    denied: number;
    denied_by_code: Record<string, number>;
    operator_items: number;
    operator_items_open: number;
    grants: number;
    grants_by_status: Record<string, number>;
    fetches: number;
    captures: number;
    captures_complete: number;
    fetch_refusals: number;
    contamination: number;
  };
  notes: string[];
};

type OfferCounts = { made: number; accepted: number; declined: number; taken_by_another: number; lapsed: number; open: number };

// --- reading ---------------------------------------------------------------------------------------

type Context = {
  S: string;
  entries: P.LedgerEntry[];
  attestations: P.LedgerAttestation[];
  disputes: P.LedgerDispute[];
  replaced: Map<number, number>;
  leadEvents: L.LeadEvent[];
  leads: L.LeadsState;
  qs: Q.QuestionsSnapshot | null;
  journal: Rec[];
  evidenceTimes: number[];
  notes: string[];
};

async function readContext(S: string): Promise<Context> {
  const notes: string[] = [];
  const entries = await P.readLedger(S).catch(() => [] as P.LedgerEntry[]);
  const attestations = await P.readAttestations(S).catch(() => [] as P.LedgerAttestation[]);
  const disputes = await P.readDisputes(S).catch(() => [] as P.LedgerDispute[]);
  const { events: leadEvents, text: leadText } = await L.readLeadEvents(S);
  const chain = L.verifyLeadChain(leadText);
  if (!chain.ok) notes.push(`the lead register's chain does not verify (${chain.reason} at line ${chain.broken_at}): read as written`);
  const leads = L.foldLeads(leadEvents, chain);
  let qs: Q.QuestionsSnapshot | null = null;
  try {
    qs = await Q.questionsSnapshot(S);
    if (!qs.state.questions.size) qs = null;
  } catch (err) {
    notes.push(`the question register could not be read (${(err as Error).message})`);
  }
  const journal = await jsonl(storePaths(S).journal);
  const evidenceTimes = journal.filter((l) => l.type === "evidence_added").map((l) => ms(l.at)).filter((t): t is number => t !== null).sort((a, b) => a - b);
  return { S, entries, attestations, disputes, replaced: P.supersededBy(entries), leadEvents, leads, qs, journal, evidenceTimes, notes };
}

/** The questions in scope at the end of the run: the register's (not withdrawn), else the goal's, else those the ledger answers. */
function inScope(c: Context): RunMetrics["questions"] {
  if (c.qs) {
    const list = [...c.qs.state.questions.values()].filter((q) => q.scope === "in_scope" && !q.withdrawn).sort((a, b) => a.n - b.n);
    return { in_scope: list.map((q) => ({ section: q.section, id: q.id })), source: c.qs.seeded ? "register" : "goal" };
  }
  const sections = [...new Set(c.entries.filter((e) => e.kind === "answer" && str(e.section).startsWith("question:")).map((e) => sectionOf(str(e.section), null)))].sort();
  return { in_scope: sections.map((section) => ({ section, id: null })), source: "ledger" };
}

function isMaterial(section: string, c: Context): boolean {
  const q = c.qs?.bySection.get(section);
  return !q || q.materiality === "material";
}

/** The standing answer of each question section at the end of the run. */
function standingAnswers(c: Context): Map<string, P.LedgerEntry> {
  const out = new Map<string, P.LedgerEntry>();
  for (const e of c.entries) {
    if (e.kind !== "answer" || !str(e.section).startsWith("question:") || c.replaced.has(e.seq)) continue;
    const k = sectionOf(str(e.section), c.qs);
    const had = out.get(k);
    if (!had || e.seq > had.seq) out.set(k, e);
  }
  return out;
}

// --- the metrics ---------------------------------------------------------------------------------

function negativesAndCoverage(c: Context): Pick<RunMetrics, "negatives" | "coverage"> {
  const closes = c.leadEvents.filter((e) => e.ev === "close" && e.disposition === "negative");
  const quick = closes.filter((e) => e.quick_negative).map((e) => ({
    lead: str(e.lead),
    seq: e.seq,
    questions: [...(c.leads.leads.get(str(e.lead))?.answers ?? [])],
    held_seconds: Math.round(num(e.quick_negative?.held_ms) / 1000),
    jobs: num(e.quick_negative?.jobs),
    objects: num(e.quick_negative?.objects),
  }));
  const bySeq = new Map(c.entries.map((e) => [e.seq, e]));
  const answers = standingAnswers(c);
  const negatives = [...answers.entries()].filter(([, e]) => NB.NEGATIVE_RESULTS.has(NB.answerResult(e) ?? ""));
  let reviewed = 0;
  const unreviewedMaterial: RunMetrics["negatives"]["unreviewed_material"] = [];
  const unreviewedBackground: RunMetrics["negatives"]["unreviewed_background"] = [];
  const onPartial: RunMetrics["coverage"]["negatives_on_partial"] = [];
  const without: RunMetrics["coverage"]["negatives_without_coverage"] = [];
  for (const [section, e] of negatives) {
    const r = P.negativeReview(e, c.entries, c.attestations, c.disputes);
    const id = c.qs?.bySection.get(section)?.id ?? null;
    const row = { section, id, answer: `E-${e.seq}`, result: NB.answerResult(e) ?? "" };
    if (r.reviewed) reviewed += 1;
    else if (isMaterial(section, c)) unreviewedMaterial.push(row);
    else unreviewedBackground.push(row);
    const cov = (e.support ?? []).map((x) => bySeq.get(x.seq)).filter((x): x is P.LedgerEntry => x?.kind === "coverage" && !c.replaced.has(x.seq));
    if (!cov.length) without.push({ section, id, answer: `E-${e.seq}` });
    else if (cov.every((x) => x.coverage !== "complete")) onPartial.push({ section, id, answer: `E-${e.seq}`, coverage: cov.map((x) => `E-${x.seq} ${str(x.coverage) || "not computed"}`) });
  }
  const records = c.entries.filter((e) => e.kind === "coverage" && !c.replaced.has(e.seq));
  const stale = records.map((x) => ({ record: `E-${x.seq}`, problems: P.coverageProblems(x, c.entries, c.disputes) })).filter((x) => x.problems.length);
  return {
    negatives: { closes: closes.length, quick: { count: quick.length, items: quick }, answers: negatives.length, reviewed, unreviewed_material: unreviewedMaterial, unreviewed_background: unreviewedBackground },
    coverage: {
      records: records.length,
      reviewed: records.filter((x) => P.negativeReview(x, c.entries, c.attestations, c.disputes).reviewed).length,
      complete: records.filter((x) => x.coverage === "complete").length,
      partial: records.filter((x) => x.coverage === "partial").length,
      not_computed: records.filter((x) => x.coverage !== "complete" && x.coverage !== "partial").length,
      stale,
      negatives_on_partial: onPartial,
      negatives_without_coverage: without,
    },
  };
}

/**
 * Offers, from the registers' events: a lead offer is accepted by the claim
 * or confirm that names it, declined or lapsed by its own event, taken by
 * another seat when another seat claimed the lead after it was made and
 * before it was answered; one outcome each, in that order. Wakes from
 * before offers are counted apart.
 */
function offers(c: Context): RunMetrics["offers"] {
  const blank = (): OfferCounts => ({ made: 0, accepted: 0, declined: 0, taken_by_another: 0, lapsed: 0, open: 0 });
  const leads = { ...blank(), by_reason: {} as Record<string, OfferCounts> };
  const wakes = { made: 0, taken_by_woken: 0, taken_by_another: 0, not_taken: 0 };
  // Read by name: a register from before offers has none of these kinds, and one from after has more.
  const ev = c.leadEvents as unknown as Array<Rec & { seq: number; ev: string; lead?: string; to?: string; holder?: string; by: string }>;
  const recorded = ev.some((e) => e.ev.startsWith("offer"));
  for (let i = 0; i < ev.length; i += 1) {
    const e = ev[i];
    if (e.ev !== "offer" && e.ev !== "wake") continue;
    const lead = str(e.lead);
    const to = str(e.to);
    // What happened to it while it stood: until the lead's next claim (or a confirm), release, close or reopen.
    const seen = new Set<string>();
    for (let k = i + 1; k < ev.length; k += 1) {
      const x = ev[k];
      if (x.lead !== lead) continue;
      if (x.ev === "claim" || x.ev === "confirm") {
        if (x.offer === e.seq) seen.add("accepted");
        else if (x.ev === "claim") seen.add(str(x.holder ?? x.by) === to ? "woken" : "another");
        break;
      }
      if (x.ev === "offer_decline" && x.offer === e.seq) seen.add("declined");
      if (x.ev === "offer_lapse" && x.offer === e.seq) seen.add("lapsed");
      if (x.ev === "release" || x.ev === "reopen" || x.ev === "close") break;
    }
    const outcome = e.ev === "wake" ? (seen.has("woken") || seen.has("accepted") ? "woken" : seen.has("another") ? "another" : "none") : seen.has("accepted") ? "accepted" : seen.has("declined") ? "declined" : seen.has("another") ? "taken_by_another" : seen.has("lapsed") ? "lapsed" : "open";
    if (e.ev === "wake") {
      wakes.made += 1;
      if (outcome === "woken") wakes.taken_by_woken += 1;
      else if (outcome === "another") wakes.taken_by_another += 1;
      else wakes.not_taken += 1;
      continue;
    }
    const reason = str(e.reason) || "wake";
    const r = (leads.by_reason[reason] ??= blank());
    const key = outcome as keyof OfferCounts;
    for (const t of [leads, r]) {
      t.made += 1;
      t[key] += 1;
    }
  }
  const qev = c.qs?.state.events ?? [];
  const qOffers = qev.filter((e) => e.ev === "offer");
  const answeredQ = (seq: number, what: string) => qev.some((x) => x.ev === what && (x as Rec).offer === seq);
  const questions = { made: qOffers.length, accepted: qOffers.filter((o) => answeredQ(o.seq, "offer_accept")).length, declined: qOffers.filter((o) => answeredQ(o.seq, "offer_decline")).length, not_taken_up: 0 };
  questions.not_taken_up = questions.made - questions.accepted - questions.declined;
  return { recorded: recorded || qOffers.length > 0, leads, questions, wakes_before_offers: wakes };
}

/** done calls, from the trace: each seat's own line, the hub's refusals of markDone, and a finish that was not the seat's (done_deferred). */
function doneCalls(events: readonly P.SwarmEvent[]): RunMetrics["done"] {
  const out: RunMetrics["done"] = { calls: 0, accepted: 0, created_sentinel: 0, refused: 0, refused_by: {}, hub_refused: 0, not_yours: 0, items: [] };
  const why = (reason: string, r: Rec): string => {
    if (r.late !== undefined || /landed (?:after|against)/i.test(reason)) return "late posts";
    if (r.abandon !== undefined) return "abandon vote";
    if (/changed while the finish line ran/i.test(reason)) return "finish line unsettled";
    if (/finish line is not met/i.test(reason)) return "finish line not met";
    return "other";
  };
  for (const e of events) {
    const r = (e.result && typeof e.result === "object" ? e.result : {}) as Rec;
    const at = P.hostTime(e);
    if (e.tool === "done") {
      out.calls += 1;
      if (r.ok === false) {
        const reason = str(r.reason);
        const k = why(reason, r);
        out.refused += 1;
        out.refused_by[k] = (out.refused_by[k] ?? 0) + 1;
        out.items.push({ at, agent: e.agent, how: `refused: ${k}` });
      } else {
        out.accepted += 1;
        if (r.created_sentinel === true) out.created_sentinel += 1;
        out.items.push({ at, agent: e.agent, how: r.created_sentinel === true ? "accepted: wrote the sentinel" : "accepted" });
      }
    } else if (e.tool === "done_deferred") {
      out.calls += 1;
      out.not_yours += 1;
      out.items.push({ at, agent: e.agent, how: "not yours" });
    } else if (e.tool === "hub_call" && str((e.args as Rec)?.fn) === "markDone" && r.ok === false) {
      // A refusal the hub counted and wrote once (repeated_before, or the flush's repeated) is that many calls.
      const n = r.repeated !== undefined ? num(r.repeated) : 1 + num(r.repeated_before);
      if (!n) continue;
      out.calls += n;
      out.hub_refused += n;
      out.items.push({ at, agent: str((e.args as Rec)?.agent), how: `refused by the hub${n > 1 ? ` (${n})` : ""}` });
    }
  }
  // A refusal on the hub reached its seat as a thrown error, never as a done line of its own: its hub_call line is the call.
  return out;
}

async function tail(c: Context, scope: RunMetrics["questions"], outcome: RunMetrics["outcome"]): Promise<RunMetrics["tail"]> {
  const endAt = ms(outcome.at);
  const end: RunMetrics["tail"]["end"] = outcome.outcome === "stopped" && existsSync(join(c.S, P.STOPPED_REL)) ? "stopped" : outcome.outcome === "paused" ? "paused" : existsSync(join(c.S, P.SENTINEL_REL)) ? "sentinel" : null;
  // Readiness where the finish register records it (docs/adr/0015): the last turn to ready before the end, not undone before it.
  let readyAt: number | null = null;
  const finish = await jsonl(join(c.S, "leads", "finish.jsonl"));
  for (const f of finish) {
    if (f.ev !== "readiness") continue;
    const t = ms(f.at);
    if (t === null || (endAt !== null && t > endAt)) continue;
    if (f.ready === true && readyAt === null) readyAt = t;
    if (f.ready === false) readyAt = null;
  }
  const first = new Map<string, number>();
  for (const e of c.entries) {
    if (e.kind !== "answer" || !str(e.section).startsWith("question:")) continue;
    const t = ms(e.at);
    if (t === null) continue;
    const k = sectionOf(str(e.section), c.qs);
    if (!first.has(k) || t < first.get(k)!) first.set(k, t);
  }
  const standing = standingAnswers(c);
  const unanswered = scope.in_scope.filter((q) => !standing.has(q.section)).map((q) => q.id ?? `question:${q.section}`);
  const allFirst = scope.in_scope.length && !unanswered.length ? Math.max(...scope.in_scope.map((q) => first.get(q.section) ?? 0)) : null;
  const allFinal = scope.in_scope.length && !unanswered.length ? Math.max(...scope.in_scope.map((q) => ms(standing.get(q.section)!.at) ?? 0)) : null;
  const hasReadiness = finish.some((f) => f.ev === "readiness");
  const ready = hasReadiness ? readyAt : allFirst;
  return {
    end_at: iso(endAt),
    end,
    ready_at: iso(ready),
    ready_source: hasReadiness ? (readyAt !== null ? "readiness" : null) : allFirst !== null ? "first answers" : null,
    all_first_answered_at: iso(allFirst),
    all_final_answered_at: iso(allFinal),
    minutes_from_ready: minutes(ready, endAt),
    minutes_from_first_answers: minutes(allFirst, endAt),
    minutes_from_final_answers: minutes(allFinal, endAt),
    unanswered,
  };
}

async function acquisition(c: Context): Promise<RunMetrics["acquisition"]> {
  const snap = await R.requestsSnapshot(c.S).catch(() => null);
  const list = snap ? [...snap.requests.values()].filter((r) => r.kind === "acquisition") : [];
  const byStage: Record<string, number> = {};
  const gaps: RunMetrics["acquisition"]["gaps"] = [];
  let byPolicy = 0;
  for (const r of list) {
    const stage = r.stage ?? "requested";
    byStage[stage] = (byStage[stage] ?? 0) + 1;
    if (r.closed?.cause === "case_policy" || r.stages.some((s) => s.by === "case policy" && s.stage === "declined")) byPolicy += 1;
    if (stage !== "validated") gaps.push({ rid: r.rid, stage: r.stage, state: r.state, questions: [...r.questions], cause: r.closed?.cause ?? null });
  }
  const added = c.journal.filter((l) => l.type === "evidence_added");
  return {
    requests: list.length,
    by_stage: byStage,
    declined_by_policy: byPolicy,
    gaps,
    questions_with_gap: [...new Set(gaps.flatMap((g) => g.questions))].sort(),
    evidence_added: added.length,
    evidence_added_for_request: added.filter((l) => str(l.request)).length,
  };
}

function interpretations(c: Context): RunMetrics["interpretations"] {
  const view = L.ledgerView(c.entries, c.disputes);
  let total = 0;
  let valid = 0;
  let superseded = 0;
  let disputed = 0;
  let missing = 0;
  const withoutValid: string[] = [];
  for (const [job, list] of c.leads.interpretations) {
    let any = false;
    for (const it of list) {
      total += 1;
      const s = L.entryStands(view, it.entry);
      if (s.ok) {
        valid += 1;
        any = true;
      } else if (!view.bySeq.has(it.entry)) missing += 1;
      else if (view.replaced.has(it.entry)) superseded += 1;
      else disputed += 1;
    }
    if (!any) withoutValid.push(job);
  }
  const underLeads = [...c.leads.jobLead.keys()];
  return {
    total,
    valid,
    superseded,
    disputed,
    missing,
    jobs_under_leads: underLeads.length,
    jobs_uninterpreted: underLeads.filter((j) => !c.leads.interpretations.has(j)).sort(),
    jobs_without_valid: withoutValid.sort(),
  };
}

/** New evidence arrived between two instants (an evidence_added line of the store's journal). */
function evidenceBetween(c: Context, from: number | null, to: number | null): boolean {
  if (from === null || to === null) return false;
  return c.evidenceTimes.some((t) => t > from && t <= to);
}

function reversals(c: Context): RunMetrics["reversals"] {
  const bySeq = new Map(c.entries.map((e) => [e.seq, e]));
  let supersessions = 0;
  let corrections = 0;
  const changes: RunMetrics["reversals"]["result_changes"] = [];
  for (const e of c.entries) {
    if (e.kind !== "answer" || e.supersedes === undefined) continue;
    const old = bySeq.get(e.supersedes);
    if (!old || old.kind !== "answer") continue;
    supersessions += 1;
    const a = NB.answerResult(old);
    const b = NB.answerResult(e);
    if (a === b) {
      corrections += 1;
      continue;
    }
    changes.push({ section: sectionOf(str(e.section), c.qs), from: `E-${old.seq}`, to: `E-${e.seq}`, from_result: a, to_result: b, cause: evidenceBetween(c, ms(old.at), ms(e.at)) ? "new_evidence" : "discoverable" });
  }
  const reopens: RunMetrics["reversals"]["negative_reopens"] = [];
  const lastNegative = new Map<string, { seq: number; at: number | null }>();
  for (const e of c.leadEvents) {
    const lead = str(e.lead);
    if (e.ev === "close") {
      if (e.disposition === "negative") lastNegative.set(lead, { seq: e.seq, at: ms(e.at) });
      else lastNegative.delete(lead);
    } else if (e.ev === "reopen" && lastNegative.has(lead)) {
      const closed = lastNegative.get(lead)!;
      const cause = e.cause === "evidence_added" || evidenceBetween(c, closed.at, ms(e.at)) ? "new_evidence" : "discoverable";
      reopens.push({ lead, closed_seq: closed.seq, reopened_at: e.at, reopen_cause: str(e.cause) || "agent", cause });
      lastNegative.delete(lead);
    }
  }
  const all = [...changes.map((x) => x.cause), ...reopens.map((x) => x.cause)];
  return {
    answer_supersessions: supersessions,
    corrections,
    result_changes: changes,
    negative_reopens: reopens,
    new_evidence: all.filter((x) => x === "new_evidence").length,
    discoverable: all.filter((x) => x === "discoverable").length,
  };
}

type Spend = { seat: string; at: number; tokens: number; usd: number };

async function filesUnder(dir: string, depth = 5): Promise<string[]> {
  if (depth < 0) return [];
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await filesUnder(p, depth - 1)));
    else if (e.isFile() && e.name.endsWith(".jsonl")) out.push(p);
  }
  return out.sort();
}

/** Each seat's spend, call by call: the model gateway's log where the run has one, else the seats' Pi sessions. */
async function spendSeries(S: string): Promise<{ source: RunMetrics["cost"]["source"]; rows: Spend[] }> {
  const gateway = (await jsonl(join(S, "traces", "model-gateway.jsonl"))).filter((l) => l.seat && l.input !== undefined);
  if (gateway.length) {
    return {
      source: "model-gateway",
      rows: gateway.map((l) => ({ seat: str(l.seat), at: ms(l.at) ?? 0, tokens: num(l.input) + num(l.output) + num(l.cache_read) + num(l.cache_write), usd: num(l.cost_usd) })),
    };
  }
  const rows: Spend[] = [];
  for (const seat of await readdir(join(S, ".pi-sessions")).catch(() => [] as string[])) {
    for (const f of await filesUnder(join(S, ".pi-sessions", seat))) {
      for (const e of await jsonl(f)) {
        const m = e.message as Rec | undefined;
        const usage = (e.type === "message" && m && (m.role === "assistant" || m.role === "toolResult") ? m.usage : e.type === "compaction" || e.type === "branch_summary" ? e.usage : undefined) as Rec | undefined;
        if (!usage) continue;
        const cost = usage.cost && typeof usage.cost === "object" ? num((usage.cost as Rec).total) : 0;
        rows.push({ seat, at: ms(e.timestamp) ?? 0, tokens: num(usage.input) + num(usage.output) + num(usage.cacheRead) + num(usage.cacheWrite), usd: cost });
      }
    }
  }
  return { source: rows.length ? "pi-sessions" : null, rows };
}

/** Who held which lead when: spells from a take to its end (a release, a close, a reopen, another's claim, a hand-off). */
function heldSpells(events: L.LeadEvent[]): Array<{ seat: string; lead: string; from: number; to: number }> {
  const open = new Map<string, { seat: string; from: number }>();
  const out: Array<{ seat: string; lead: string; from: number; to: number }> = [];
  const end = (lead: string, at: number) => {
    const h = open.get(lead);
    if (h) out.push({ seat: h.seat, lead, from: h.from, to: at });
    open.delete(lead);
  };
  for (const e of events) {
    const lead = str(e.lead);
    const at = ms(e.at);
    if (!lead || at === null) continue;
    if (e.ev === "open" && e.holder) open.set(lead, { seat: e.holder, from: at });
    else if (e.ev === "claim") {
      const holder = str(e.holder ?? e.by);
      if (open.get(lead)?.seat === holder) continue;
      end(lead, at);
      open.set(lead, { seat: holder, from: at });
    } else if (e.ev === "release" || e.ev === "close" || e.ev === "reopen" || (e.ev as string) === "handoff") end(lead, at);
  }
  for (const [lead, h] of open) out.push({ seat: h.seat, lead, from: h.from, to: Number.POSITIVE_INFINITY });
  return out;
}

/**
 * Tokens apportioned by lead: each call's tokens go to the leads its seat
 * held when it was made, in equal parts, and a lead's part to the questions
 * it answers, in equal parts. A call made while the seat held no lead is
 * counted as unheld; a lead that answers no question is counted apart.
 */
async function cost(c: Context): Promise<RunMetrics["cost"]> {
  const { source, rows } = await spendSeries(c.S);
  const spells = heldSpells(c.leadEvents);
  const perQ = new Map<string, { tokens: number; usd: number; leads: Set<string> }>();
  const unheld = { tokens: 0, usd: 0 };
  const noQ = { tokens: 0, usd: 0, leads: new Set<string>() };
  let tokens = 0;
  let usd = 0;
  for (const r of rows) {
    tokens += r.tokens;
    usd += r.usd;
    const held = [...new Set(spells.filter((s) => s.seat === r.seat && s.from <= r.at && r.at < s.to).map((s) => s.lead))];
    if (!held.length) {
      unheld.tokens += r.tokens;
      unheld.usd += r.usd;
      continue;
    }
    for (const lead of held) {
      const t = r.tokens / held.length;
      const u = r.usd / held.length;
      const qs = [...new Set((c.leads.leads.get(lead)?.answers ?? []).map((a) => sectionOf(a, c.qs)))];
      if (!qs.length) {
        noQ.tokens += t;
        noQ.usd += u;
        noQ.leads.add(lead);
        continue;
      }
      for (const q of qs) {
        const acc = perQ.get(q) ?? { tokens: 0, usd: 0, leads: new Set<string>() };
        acc.tokens += t / qs.length;
        acc.usd += u / qs.length;
        acc.leads.add(lead);
        perQ.set(q, acc);
      }
    }
  }
  const round = (x: number) => Math.round(x);
  const cents = (x: number) => Math.round(x * 10000) / 10000;
  return {
    source,
    tokens: round(tokens),
    usd: cents(usd),
    per_question: [...perQ.entries()].map(([section, v]) => ({ section, id: c.qs?.bySection.get(section)?.id ?? null, tokens: round(v.tokens), usd: cents(v.usd), leads: [...v.leads].sort() })).sort((a, b) => b.tokens - a.tokens || a.section.localeCompare(b.section)),
    unheld: { tokens: round(unheld.tokens), usd: cents(unheld.usd) },
    leads_without_question: { tokens: round(noQ.tokens), usd: cents(noQ.usd), leads: [...noQ.leads].sort() },
  };
}

async function duplicates(c: Context): Promise<RunMetrics["duplicates"]> {
  const accepted = c.journal.filter((l) => l.type === "job_accepted");
  const recorded = accepted.some((l) => l.reuse !== undefined) || c.journal.some((l) => l.type === "job_similar" || l.type === "job_same_as");
  const independent = accepted.filter((l) => (l.spec as Rec | undefined)?.independent === true).map((l) => str(l.job));
  const similar = c.journal.filter((l) => l.type === "job_similar");
  const exact = similar.filter((l) => ((l.similar as Rec[] | undefined) ?? []).some((s) => (s.match === "same command" || s.match === "same tool and arguments") && s.objects === "same")).map((l) => str(l.job));
  const same = c.journal.filter((l) => l.type === "job_same_as");
  let files = 0;
  let bytes = 0;
  const whole: string[] = [];
  for (const l of same) {
    const list = (l.same_as as Rec[] | undefined) ?? [];
    files += list.length;
    bytes += list.reduce((a, s) => a + num(s.bytes), 0);
    const m = await readFile(join(storePaths(c.S).jobs, str(l.job), "manifest.json"), "utf8").then((t) => JSON.parse(t) as { files?: Array<{ bytes?: number }> }).catch(() => null);
    const nonEmpty = (m?.files ?? []).filter((f) => num(f.bytes) > 0).length;
    if (m && nonEmpty > 0 && list.length >= nonEmpty) whole.push(str(l.job));
  }
  const withSimilar = similar.map((l) => str(l.job));
  return {
    recorded,
    jobs_with_similar: withSimilar.filter((j) => !independent.includes(j)),
    exact_repeats: exact.filter((j) => !independent.includes(j)),
    independent,
    independent_with_similar: withSimilar.filter((j) => independent.includes(j)),
    same_as: { jobs: same.map((l) => str(l.job)), files, bytes, whole },
    recipe_merged: c.journal.filter((l) => l.type === "job_deduplicated").length,
    shadow_would_merge: c.journal.filter((l) => l.type === "job_would_merge").length,
  };
}

async function network(S: string): Promise<RunMetrics["network"]> {
  const st = await readNetState(S).catch(() => null);
  const recorded = Boolean(st && (st.events.length || st.fetchEvents.length));
  const out: RunMetrics["network"] = { recorded, requests: 0, granted: 0, denied: 0, denied_by_code: {}, operator_items: 0, operator_items_open: 0, grants: 0, grants_by_status: {}, fetches: 0, captures: 0, captures_complete: 0, fetch_refusals: 0, contamination: 0 };
  if (!st || !recorded) return out;
  const reqs = [...st.requests.values()];
  out.requests = reqs.length;
  out.granted = reqs.filter((r) => r.decision?.decision === "granted").length;
  out.denied = reqs.filter((r) => r.decision?.decision === "denied").length;
  for (const r of reqs) if (r.decision?.decision === "denied") for (const reason of r.decision.reasons.length ? r.decision.reasons : [{ code: "unstated" }]) out.denied_by_code[reason.code] = (out.denied_by_code[reason.code] ?? 0) + 1;
  out.operator_items = st.items.size;
  out.operator_items_open = [...st.items.values()].filter((i) => !i.closed).length;
  out.grants = st.grants.size;
  for (const g of st.grants.values()) {
    const s = grantStatus(g, st).status;
    out.grants_by_status[s] = (out.grants_by_status[s] ?? 0) + 1;
  }
  const fetches = [...st.fetches.values()].flat();
  out.fetches = fetches.length;
  out.captures = fetches.filter((f) => f.result?.delivered).length;
  out.captures_complete = fetches.filter((f) => f.result?.delivered && f.result.complete).length;
  out.fetch_refusals = st.refusals.length + fetches.filter((f) => f.result?.refused).length;
  out.contamination = st.contamination.length;
  return out;
}

// --- one run --------------------------------------------------------------------------------------

export async function measureRun(runDirArg: string): Promise<RunMetrics> {
  const S = resolve(runDirArg);
  const c = await readContext(S);
  const outcome = await P.runOutcome(S).catch(() => ({ outcome: null, by: null, at: null, why: null }));
  const { events, unreadable } = await P.readEventLogChecked(S);
  if (unreadable) c.notes.push(`the trace is ${unreadable}: done calls are not counted`);
  const scope = inScope(c);
  const registers: Record<string, boolean> = {
    leads: existsSync(join(S, L.LEADS_LOG)),
    finish: existsSync(join(S, "leads", "finish.jsonl")),
    questions: existsSync(join(S, Q.QUESTIONS_LOG)),
    ledger: existsSync(join(S, "ledger", "entries.jsonl")),
    requests: existsSync(join(S, R.REQUESTS_LOG)),
    journal: existsSync(storePaths(S).journal),
    network: existsSync(join(S, "network", "grants.jsonl")),
    trace: existsSync(join(S, P.EVENTS_REL)),
  };
  const nc = negativesAndCoverage(c);
  const off = offers(c);
  if (!off.recorded) c.notes.push("no offer events in the registers (a run from before offers): offers are not counted; its wakes are");
  const dup = await duplicates(c);
  if (!dup.recorded && c.journal.some((l) => l.type === "job_accepted")) c.notes.push("no reuse hints on the journal (a run from before them): duplicates are not counted");
  const t = await tail(c, scope, outcome);
  if (!registers.finish) c.notes.push("no finish register (a run from before readiness was recorded): the tail is measured from the first answers");
  const m: RunMetrics = {
    format: METRICS_FORMAT,
    run: basename(S),
    run_dir: S,
    measured_at: new Date().toISOString(),
    outcome,
    registers,
    questions: scope,
    ...nc,
    offers: off,
    done: doneCalls(events),
    tail: t,
    acquisition: await acquisition(c),
    interpretations: interpretations(c),
    reversals: reversals(c),
    cost: await cost(c),
    duplicates: dup,
    network: await network(S),
    notes: c.notes,
  };
  if (!m.cost.source) m.notes.push("no per-call token record (no model gateway log, no Pi sessions): cost per question is not measured");
  return m;
}

// --- two runs --------------------------------------------------------------------------------------

export type QuestionSide = { answer: string | null; result: string | null; reviewed: boolean | null; coverage: string[]; accepted: string | null };
export type Comparison = {
  format: typeof COMPARE_FORMAT;
  a: { run: string; run_dir: string };
  b: { run: string; run_dir: string };
  compared_at: string;
  same_questions: boolean;
  questions: Array<{ section: string; id: string | null; a: QuestionSide; b: QuestionSide; verdict: "agree" | "class_differs" | "disagree" | "only_a" | "only_b" | "neither"; flags: string[] }>;
  summary: { questions: number; agree: number; class_differs: number; disagree: number; one_sided: number; neither: number; negative_disagreements: number; shared_partial_negatives: number };
  notes: string[];
};

const sideOf = (c: Context, section: string, standing: Map<string, P.LedgerEntry>): QuestionSide => {
  const e = standing.get(section);
  const q = c.qs?.bySection.get(section);
  const accepted = q?.accepted ? q.accepted.as : null;
  if (!e) return { answer: null, result: null, reviewed: null, coverage: [], accepted };
  const result = NB.answerResult(e);
  const bySeq = new Map(c.entries.map((x) => [x.seq, x]));
  const cov = (e.support ?? []).map((x) => bySeq.get(x.seq)).filter((x): x is P.LedgerEntry => x?.kind === "coverage" && !c.replaced.has(x.seq)).map((x) => str(x.coverage) || "not computed");
  return { answer: `E-${e.seq}`, result, reviewed: NB.NEGATIVE_RESULTS.has(result ?? "") ? P.negativeReview(e, c.entries, c.attestations, c.disputes).reviewed : null, coverage: cov, accepted };
};

/** Results of one kind: established and partial both assert; the negatives (a bounded negative, not determinable, a premise not supported) do not. */
const family = (r: string | null): string => (r === "established" || r === "partial" ? "positive" : r === "bounded_negative" || r === "not_determinable" || r === "premise_not_supported" ? "negative" : r ?? "none");

export async function compareRuns(aDir: string, bDir: string): Promise<Comparison> {
  const A = await readContext(resolve(aDir));
  const B = await readContext(resolve(bDir));
  const notes = [...A.notes.map((n) => `A: ${n}`), ...B.notes.map((n) => `B: ${n}`)];
  const sa = inScope(A);
  const sb = inScope(B);
  const text = (c: Context, s: string) => c.qs?.bySection.get(s)?.text ?? null;
  const sections = [...new Set([...sa.in_scope, ...sb.in_scope].map((q) => q.section))].sort((x, y) => (/^\d+$/.test(x) && /^\d+$/.test(y) ? Number(x) - Number(y) : x.localeCompare(y)));
  const sameQuestions = sa.in_scope.length === sb.in_scope.length && sa.in_scope.every((q) => sb.in_scope.some((r) => r.section === q.section && text(A, q.section) === text(B, q.section)));
  if (!sameQuestions) notes.push("the two runs' questions differ (in number, or in their text): compared by section, and a question one run has alone is one-sided");
  const standA = standingAnswers(A);
  const standB = standingAnswers(B);
  const rows: Comparison["questions"] = [];
  for (const section of sections) {
    const a = sideOf(A, section, standA);
    const b = sideOf(B, section, standB);
    const flags: string[] = [];
    const fa = family(a.result);
    const fb = family(b.result);
    let verdict: Comparison["questions"][number]["verdict"];
    if (!a.answer && !b.answer) verdict = "neither";
    else if (!b.answer) verdict = "only_a";
    else if (!a.answer) verdict = "only_b";
    else verdict = a.result === b.result ? "agree" : fa === fb ? "class_differs" : "disagree";
    if (a.answer && b.answer && fa !== fb && (fa === "negative" || fb === "negative")) flags.push(`a negative in ${fa === "negative" ? "A" : "B"} (${fa === "negative" ? a.result : b.result}) is established in the other: re-examine the negative's coverage and detection assumptions`);
    if (fa === "negative" && fb === "negative") {
      const partial = (s: QuestionSide) => !s.coverage.length || s.coverage.every((x) => x !== "complete");
      if (partial(a) && partial(b)) flags.push("both runs are negative and neither rests on complete coverage: agreement may be a shared blind spot");
      if (a.reviewed === false || b.reviewed === false) flags.push(`a negative not reviewed by another seat in ${[a.reviewed === false ? "A" : "", b.reviewed === false ? "B" : ""].filter(Boolean).join(" and ")}`);
    }
    if (verdict === "agree" && fa === "positive" && (a.accepted || b.accepted)) flags.push("agreement where one run's question was accepted by the operator as limited");
    rows.push({ section, id: A.qs?.bySection.get(section)?.id ?? B.qs?.bySection.get(section)?.id ?? null, a, b, verdict, flags });
  }
  const count = (v: string) => rows.filter((r) => r.verdict === v).length;
  return {
    format: COMPARE_FORMAT,
    a: { run: basename(resolve(aDir)), run_dir: resolve(aDir) },
    b: { run: basename(resolve(bDir)), run_dir: resolve(bDir) },
    compared_at: new Date().toISOString(),
    same_questions: sameQuestions,
    questions: rows,
    summary: {
      questions: rows.length,
      agree: count("agree"),
      class_differs: count("class_differs"),
      disagree: count("disagree"),
      one_sided: count("only_a") + count("only_b"),
      neither: count("neither"),
      negative_disagreements: rows.filter((r) => r.flags.some((f) => f.startsWith("a negative in"))).length,
      shared_partial_negatives: rows.filter((r) => r.flags.some((f) => f.includes("shared blind spot"))).length,
    },
    notes,
  };
}

// --- the tables -------------------------------------------------------------------------------------

function table(rows: string[][]): string[] {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]))).join("  ").trimEnd());
}

const list = (xs: string[]): string => (xs.length ? xs.join(", ") : "none");
const counts = (o: Record<string, number>): string => (Object.keys(o).length ? Object.entries(o).sort().map(([k, v]) => `${k} ${v}`).join(", ") : "none");
const mins = (m: number | null): string => (m === null ? "-" : `${m} min`);
const qname = (x: { section: string; id: string | null }): string => x.id ?? `question:${x.section}`;

export function metricsText(m: RunMetrics): string {
  const lines: string[] = [`Metrics: run ${m.run}${m.outcome.outcome ? ` (${m.outcome.outcome})` : ""}`, `Questions in scope: ${m.questions.in_scope.length} (from the ${m.questions.source})`, ""];
  const o = m.offers;
  const d = m.done;
  const a = m.acquisition;
  const i = m.interpretations;
  const r = m.reversals;
  const n = m.network;
  const rows: string[][] = [
    ["Metric", "Value"],
    ["Quick negatives", `${m.negatives.quick.count} of ${m.negatives.closes} negative closes${m.negatives.quick.count ? `: ${m.negatives.quick.items.map((x) => `${x.lead} (${x.held_seconds} s, ${x.jobs} job, ${x.objects} object)`).join(", ")}` : ""}`],
    ["Negative answers", `${m.negatives.answers} standing; ${m.negatives.reviewed} reviewed`],
    ["Unreviewed negatives", `${m.negatives.unreviewed_material.length} material (${list(m.negatives.unreviewed_material.map((x) => `${qname(x)} ${x.answer}`))}), ${m.negatives.unreviewed_background.length} background`],
    ["Coverage records", `${m.coverage.records} standing: ${m.coverage.complete} complete, ${m.coverage.partial} partial, ${m.coverage.not_computed} not computed; ${m.coverage.reviewed} reviewed by another seat; ${m.coverage.stale.length} stale`],
    ["Negatives on partial coverage", `${m.coverage.negatives_on_partial.length} (${list(m.coverage.negatives_on_partial.map((x) => `${qname(x)} ${x.answer}`))}); ${m.coverage.negatives_without_coverage.length} cite no coverage record`],
    ["Offers (leads)", o.recorded ? `${o.leads.made} made: ${o.leads.accepted} accepted, ${o.leads.declined} declined, ${o.leads.taken_by_another} taken by another seat, ${o.leads.lapsed} lapsed, ${o.leads.open} with no outcome` : "not recorded"],
    ["Offers (questions)", o.recorded ? `${o.questions.made} made: ${o.questions.accepted} accepted, ${o.questions.declined} declined, ${o.questions.not_taken_up} not taken up` : "not recorded"],
    ["Wakes (before offers)", `${o.wakes_before_offers.made}: ${o.wakes_before_offers.taken_by_woken} taken by the woken seat, ${o.wakes_before_offers.taken_by_another} by another, ${o.wakes_before_offers.not_taken} not taken`],
    ["done calls", `${d.calls}: ${d.accepted} accepted (${d.created_sentinel} wrote the sentinel), ${d.refused} refused by the seat's checks (${counts(d.refused_by)}), ${d.hub_refused} refused by the hub, ${d.not_yours} not the seat's finish`],
    ["Tail to the end", `${mins(m.tail.minutes_from_ready)} from ready (${m.tail.ready_source ?? "never ready"}); ${mins(m.tail.minutes_from_first_answers)} from the first answers, ${mins(m.tail.minutes_from_final_answers)} from the final ones${m.tail.unanswered.length ? `; unanswered: ${list(m.tail.unanswered)}` : ""}`],
    ["Acquisition", `${a.requests} request(s) (${counts(a.by_stage)}; ${a.declined_by_policy} declined by the case policy); ${a.gaps.length} gap(s)${a.questions_with_gap.length ? ` on ${list(a.questions_with_gap)}` : ""}; evidence added ${a.evidence_added} time(s), ${a.evidence_added_for_request} for a request`],
    ["Interpretations", `${i.total}: ${i.valid} valid, ${i.superseded} on a superseded entry, ${i.disputed} on a disputed one${i.missing ? `, ${i.missing} on no entry` : ""}; ${i.jobs_uninterpreted.length} of ${i.jobs_under_leads} lead jobs uninterpreted, ${i.jobs_without_valid.length} with no valid interpretation`],
    ["Reversals", `${r.result_changes.length + r.negative_reopens.length}: ${r.new_evidence} after new evidence, ${r.discoverable} discoverable in the original evidence (${r.result_changes.length} answer result changes, ${r.negative_reopens.length} negative leads reopened); ${r.corrections} corrections kept the result`],
    ["Cost", m.cost.source ? `${m.cost.tokens} tokens, $${m.cost.usd} (from ${m.cost.source === "model-gateway" ? "the model gateway's log" : "the seats' Pi sessions"}); ${m.cost.unheld.tokens} spent holding no lead, ${m.cost.leads_without_question.tokens} on leads that answer no question` : "not measured"],
    ["Duplicates", m.duplicates.recorded ? `${m.duplicates.jobs_with_similar.length} jobs with similar work by another seat (${m.duplicates.exact_repeats.length} exact repeats); ${m.duplicates.independent.length} independent reproductions; same_as ${m.duplicates.same_as.files} file(s), ${m.duplicates.same_as.bytes} bytes in ${m.duplicates.same_as.jobs.length} job(s), ${m.duplicates.same_as.whole.length} wholly; recipes merged ${m.duplicates.recipe_merged}` : `not recorded${m.duplicates.shadow_would_merge ? ` (the retired shadow merge said ${m.duplicates.shadow_would_merge})` : ""}`],
    ["Network", n.recorded ? `${n.requests} request(s): ${n.granted} granted, ${n.denied} denied (${counts(n.denied_by_code)}); ${n.operator_items} operator item(s), ${n.operator_items_open} open; ${n.grants} grant(s) (${counts(n.grants_by_status)}); ${n.fetches} fetch(es), ${n.captures} capture(s), ${n.fetch_refusals} refused by the fetch service${n.contamination ? `; contamination ${n.contamination}` : ""}` : "not used"],
  ];
  lines.push(...table(rows));
  if (m.cost.per_question.length) {
    lines.push("", "Cost per question (tokens apportioned by lead):");
    lines.push(...table([["Question", "Tokens", "USD", "Leads"], ...m.cost.per_question.map((q) => [qname(q), String(q.tokens), String(q.usd), q.leads.join(" ")])]));
  }
  if (m.notes.length) lines.push("", ...m.notes.map((x) => `Note: ${x}`));
  return `${lines.join("\n")}\n`;
}

export function compareText(c: Comparison): string {
  const side = (s: QuestionSide) => (s.answer ? `${s.result ?? "?"}${s.reviewed === false ? " (unreviewed)" : ""}${s.coverage.length ? ` [${s.coverage.join(", ")}]` : ""}${s.accepted ? ` accepted ${s.accepted}` : ""}` : "no answer");
  const lines = [`Compare: A ${c.a.run}, B ${c.b.run}${c.same_questions ? "" : " (their questions differ)"}`, ""];
  lines.push(...table([["Question", "A", "B", "Verdict"], ...c.questions.map((q) => [q.id ?? `question:${q.section}`, side(q.a), side(q.b), q.verdict])]));
  const flagged = c.questions.filter((q) => q.flags.length);
  if (flagged.length) {
    lines.push("");
    for (const q of flagged) for (const f of q.flags) lines.push(`Flag ${q.id ?? `question:${q.section}`}: ${f}`);
  }
  const s = c.summary;
  lines.push("", `${s.questions} question(s): ${s.agree} agree, ${s.class_differs} of the same kind in another class, ${s.disagree} disagree, ${s.one_sided} answered in one run only, ${s.neither} in neither; ${s.negative_disagreements} negative(s) the other run established, ${s.shared_partial_negatives} shared negative(s) on partial coverage.`);
  lines.push("Agreement is not confirmation: two runs of one harness can share a blind spot.");
  if (c.notes.length) lines.push("", ...c.notes.map((x) => `Note: ${x}`));
  return `${lines.join("\n")}\n`;
}

// --- the command --------------------------------------------------------------------------------------

function isRunDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

async function main(argv: string[]): Promise<number> {
  const json = argv.includes("--json");
  const args = argv.filter((a) => a !== "--json");
  const usage = "usage: metrics.ts <run-dir> [--json] | metrics.ts --compare <run-dir-A> <run-dir-B> [--json]\n";
  if (args[0] === "--compare") {
    const [a, b] = args.slice(1);
    if (!a || !b || args.length !== 3) {
      process.stderr.write(usage);
      return 2;
    }
    for (const d of [a, b]) {
      if (!isRunDir(d)) {
        process.stderr.write(`metrics.ts: ${d} is not a run directory\n`);
        return 2;
      }
    }
    const c = await compareRuns(a, b);
    process.stdout.write(json ? `${JSON.stringify(c, null, 2)}\n` : compareText(c));
    return 0;
  }
  if (args.length !== 1 || args[0].startsWith("--")) {
    process.stderr.write(usage);
    return 2;
  }
  if (!isRunDir(args[0])) {
    process.stderr.write(`metrics.ts: ${args[0]} is not a run directory\n`);
    return 2;
  }
  const m = await measureRun(args[0]);
  process.stdout.write(json ? `${JSON.stringify(m, null, 2)}\n` : metricsText(m));
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(await main(process.argv.slice(2)));
}
