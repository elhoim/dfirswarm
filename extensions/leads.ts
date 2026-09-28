/**
 * The lead register: the swarm's open investigative work, kept by the harness.
 *
 * A lead is a piece of material work somebody found: a container to open, a
 * key to find, a note to read to its end. Before this register a lead lived
 * only in prose: a post addressed to the peer the writer guessed owned the
 * next step, a `name(doing)` nobody checked, a job whose output nobody
 * interpreted. On the Belka run s94e373 a recovery key sat in a job's unread
 * page for 51 minutes while three agents searched for it; on c10 s6895a8 a
 * late recovery avenue was being interpreted when the run ended and no record
 * said it was open; on c09 the pointer to the third part's key was found in
 * every run and followed in none, and the finish line took "a limitation is
 * recorded" for an answer. The register makes that work durable, owned,
 * visible and part of the finish line, and nothing more: agents open, claim,
 * link and close leads themselves; the harness assigns nothing and never
 * judges what a lead is worth (the creator says whether it is material).
 *
 * Hub-owned state. `leads/leads.jsonl` is an append-only chain of events (each
 * line hashed over the one before, as the ledger's are); `leads/leads.md` is
 * derived from it after every write. On the host every pane writes it under
 * one named lock; in a microVM run the hub is its only writer (board.ts), and
 * the operator's CLI writes it on the host under the same lock. It sits
 * beside the ledger, not in it: a lead is work, not a finding, and custody
 * seals it and the package carries it, unsigned.
 *
 * What is derived, never stored: whether a lead is blocked (a need not met),
 * its priority (how many leads and unanswered questions wait on it, then its
 * age), whether its holder is stale, which questions nobody covers, which jobs
 * wait for an interpretation, and what each agent has not yet been told.
 * Everything derived is computed from the files on every read, so a hub that
 * restarts between a transition and its notice loses neither.
 *
 * Nothing here knows a tool or a case: a need names a lead's disposition or a
 * ledger entry, never a program, and a job's exit status never satisfies one.
 */

import { existsSync, readFileSync } from "node:fs";
import { appendFile, mkdir, open, readdir, readFile, realpath, rename, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import * as P from "./protocol.ts";

// --- the files --------------------------------------------------------------------------------

export const LEADS_DIR = "leads";
export const LEADS_LOG = "leads/leads.jsonl";
export const LEADS_MD = "leads/leads.md";
/** Every request an agent made of the operator (a lead closed needs_operator), one JSON line each. */
export const OPERATOR_REQUESTS = "operator-requests.jsonl";
/** Hosts the operator allowed while the run went on, for jobs run with network=allowlist. */
export const OPERATOR_HOSTS = "operator-hosts.jsonl";
/**
 * The one lock both registers are written under: the leads and the questions
 * (extensions/questions.ts). A withdrawn question closes its leads in the
 * same act, and a done's sentinel is written under it too (protocol.ts
 * markDone), so an admission and a terminal done are never interleaved.
 */
export const REGISTER_LOCK = P.REGISTER_LOCK;
const LOCK = REGISTER_LOCK;

// --- the vocabulary ---------------------------------------------------------------------------

/**
 * How a lead ends, and what each must cite. resolved: the standing entry that
 * settles it (E-<seq>). negative: the search that found nothing (an absence,
 * E-<seq>). duplicate: the lead it repeats (L-<n>). deferred: the limitation
 * that says why it waits (E-<seq>). infeasible: the limitation naming the
 * methods tried and why none worked (E-<seq>). needs_operator: what only the
 * operator can do (allow a host, add a file, answer a question), in words.
 * withdrawn: the harness's alone, when every question the lead served was
 * withdrawn (extensions/questions.ts); it cites the question.
 */
export const LEAD_DISPOSITIONS = ["resolved", "negative", "duplicate", "deferred", "infeasible", "needs_operator", "withdrawn"] as const;
export type LeadDisposition = (typeof LEAD_DISPOSITIONS)[number];
/** The dispositions that leave the question behind them open: an examination-limited outcome, never an answered one. */
export const LIMITING_DISPOSITIONS: ReadonlySet<LeadDisposition> = new Set(["deferred", "infeasible", "needs_operator"]);
export const LEAD_ID = /^L-([1-9]\d{0,5})$/;
export const LEAD_TITLE_MAX = 200;
export const LEAD_WHY_MAX = 2000;
export const LEAD_REF_MAX = 2000;
export const LEAD_NOTE_MAX = 4000;
export const LEAD_MAX_NEEDS = 20;
export const LEAD_MAX_ANSWERS = 8;
export const LEAD_MAX_OPENS = 10;
/** Whole seconds from the environment, in milliseconds, or the default when unset or not a number. */
function envMs(name: string, dfltSec: number): number {
  const raw = process.env[name]?.trim();
  const n = raw && /^\d+$/.test(raw) ? Number(raw) : dfltSec;
  return n * 1000;
}
/** A holder silent this long, with no job running and no compaction under way, shows as stale (SWARM_LEAD_STALE_SEC, 600). */
export function leadStaleMs(): number {
  return envMs("SWARM_LEAD_STALE_SEC", 600);
}
/** How long a stale mark stands before the lead may be reclaimed: the holder is told first (SWARM_LEAD_RECLAIM_GRACE_SEC, 60). */
export function reclaimGraceMs(): number {
  return envMs("SWARM_LEAD_RECLAIM_GRACE_SEC", 60);
}
/** A compaction this long keeps its seat's leases; past it, the seat may have lost its turn for good. */
export const LEAD_COMPACTION_BOUND_MS = 20 * 60_000;
/** An idle seat is one that has waited at least this long, holding no active lead and no job. */
export const IDLE_SEAT_MS = 60_000;

export type LeadEventKind = "open" | "claim" | "release" | "close" | "link" | "reopen" | "stale" | "job" | "interpret" | "wake" | "note";

export type LeadEvent = {
  v: 1;
  seq: number;
  at: string;
  /** An agent's id, "system" for the harness, "operator" for the examiner. */
  by: string;
  ev: LeadEventKind;
  lead?: string;
  title?: string;
  why?: string;
  origin?: string;
  needs?: string[];
  answers?: string[];
  material?: boolean;
  holder?: string;
  generation?: number;
  /** A claim that took the lead from a stale holder: whom from. */
  from?: string;
  disposition?: LeadDisposition;
  ref?: string;
  add?: string[];
  remove?: string[];
  /** A reopen's cause: superseded, disputed, operator, agent. */
  cause?: string;
  job?: string;
  /** An interpretation: the ledger entry that is it, and that entry's kind. */
  entry?: number;
  kind?: string;
  /** An interpretation: how the rest of a job's output was read, or why it was not. */
  rest?: string;
  /** A wake: the seat woken, and which open spell of the lead it was for. */
  to?: string;
  cycle?: number;
  text?: string;
  allow_host?: string;
  last_activity?: string | null;
  idle_seconds?: number;
  /**
   * An open under an analyst's question (extensions/questions.ts): the
   * proposition the lead tests and its negation, so the question is worked as
   * a hypothesis, never as a conclusion to confirm.
   */
  proposition?: string;
  negation?: string;
  /** A directive (the operator's lead under a question): what it is to produce, and what makes that product acceptable. */
  product?: string;
  acceptance?: string;
  prev: string;
  hash: string;
};

export type Lead = {
  id: string;
  n: number;
  title: string;
  why: string;
  origin: string;
  needs: string[];
  answers: string[];
  material: boolean;
  opened_by: string;
  opened_at: string;
  holder: string | null;
  generation: number;
  /** When the current holder took it. */
  held_since: string | null;
  closed: { disposition: LeadDisposition; ref: string; by: string; at: string; why?: string } | null;
  reopened: Array<{ at: string; by: string; why: string; cause: string }>;
  /** The newest stale mark on the current holder, until the holder acts on the lead or loses it. */
  stale: { at: string; holder: string; generation: number; idle_seconds: number; last_activity: string | null } | null;
  jobs: string[];
  notes: Array<{ at: string; by: string; text: string; allow_host?: string }>;
  /** How many times it went back to open (released or reopened): one wake per open spell. */
  cycle: number;
  last_seq: number;
  proposition?: string;
  negation?: string;
  product?: string;
  acceptance?: string;
};

export type LeadsState = {
  events: LeadEvent[];
  leads: Map<string, Lead>;
  /** The lead each job was run under. */
  jobLead: Map<string, string>;
  /** Each job's interpretations, in order. */
  interpretations: Map<string, Array<{ by: string; at: string; entry: number; kind: string; rest?: string }>>;
  /** Wakes, by lead and open spell. */
  wakes: Map<string, string>;
  chain: { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };
};

// --- the chain ----------------------------------------------------------------------------------

function core(e: Omit<LeadEvent, "prev" | "hash"> | LeadEvent): string {
  const { prev: _p, hash: _h, ...rest } = e as LeadEvent;
  return JSON.stringify(P.canonicalValue(rest));
}

export function leadEventHash(e: Omit<LeadEvent, "hash"> | LeadEvent, prev: string): string {
  return P.sha256Hex(`${prev}\n${core(e)}`);
}

/** Whether leads.jsonl chains from its first line to its last: a rewritten or removed line breaks it. */
export function verifyLeadChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let prev = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let e: LeadEvent;
    try {
      e = JSON.parse(line) as LeadEvent;
    } catch {
      return { ok: false, total, broken_at: total, reason: "the line is not JSON", head: null };
    }
    if (e.seq !== total) return { ok: false, total, broken_at: total, reason: `the line has seq ${e.seq}, not ${total}`, head: null };
    if (e.prev !== prev) return { ok: false, total, broken_at: total, reason: "the line does not chain to the one before", head: null };
    if (e.hash !== leadEventHash(e, prev)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    prev = e.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? prev : null };
}

// --- reading ------------------------------------------------------------------------------------

export async function readLeadEvents(sandboxRoot: string): Promise<{ events: LeadEvent[]; text: string }> {
  const text = await readFile(join(sandboxRoot, LEADS_LOG), "utf8").catch(() => "");
  const events: LeadEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as LeadEvent);
    } catch {
      // The chain check names it.
    }
  }
  return { events, text };
}

/** The register's state, folded from its events in order. */
export function foldLeads(events: LeadEvent[], chain: LeadsState["chain"] = { ok: true, broken_at: null, reason: null, head: events.at(-1)?.hash ?? null }): LeadsState {
  const leads = new Map<string, Lead>();
  const jobLead = new Map<string, string>();
  const interpretations: LeadsState["interpretations"] = new Map();
  const wakes = new Map<string, string>();
  for (const e of events) {
    const l = e.lead ? leads.get(e.lead) : undefined;
    switch (e.ev) {
      case "open": {
        if (!e.lead) break;
        leads.set(e.lead, {
          id: e.lead,
          n: Number(LEAD_ID.exec(e.lead)?.[1] ?? 0),
          title: e.title ?? "",
          why: e.why ?? "",
          origin: e.origin ?? "",
          needs: [...(e.needs ?? [])],
          answers: [...(e.answers ?? [])],
          material: e.material !== false,
          opened_by: e.by,
          opened_at: e.at,
          holder: e.holder ?? null,
          generation: e.generation ?? 0,
          held_since: e.holder ? e.at : null,
          closed: null,
          reopened: [],
          stale: null,
          jobs: [],
          notes: [],
          cycle: 0,
          last_seq: e.seq,
          ...(e.proposition ? { proposition: e.proposition } : {}),
          ...(e.negation ? { negation: e.negation } : {}),
          ...(e.product ? { product: e.product } : {}),
          ...(e.acceptance ? { acceptance: e.acceptance } : {}),
        });
        break;
      }
      case "claim":
        if (!l) break;
        l.holder = e.holder ?? e.by;
        l.generation = e.generation ?? l.generation + 1;
        l.held_since = e.at;
        l.stale = null;
        l.last_seq = e.seq;
        break;
      case "release":
        if (!l) break;
        l.holder = null;
        l.held_since = null;
        l.stale = null;
        l.cycle += 1;
        l.last_seq = e.seq;
        break;
      case "close":
        if (!l || !e.disposition) break;
        l.closed = { disposition: e.disposition, ref: e.ref ?? "", by: e.by, at: e.at, ...(e.why ? { why: e.why } : {}) };
        l.stale = null;
        l.last_seq = e.seq;
        break;
      case "reopen":
        if (!l) break;
        l.closed = null;
        l.holder = null;
        l.held_since = null;
        l.stale = null;
        l.cycle += 1;
        l.reopened.push({ at: e.at, by: e.by, why: e.why ?? "", cause: e.cause ?? "agent" });
        l.last_seq = e.seq;
        break;
      case "link":
        if (!l) break;
        l.needs = [...l.needs.filter((n) => !(e.remove ?? []).includes(n)), ...(e.add ?? []).filter((n) => !l.needs.includes(n))];
        l.last_seq = e.seq;
        break;
      case "stale":
        if (!l) break;
        l.stale = { at: e.at, holder: e.holder ?? "", generation: e.generation ?? l.generation, idle_seconds: e.idle_seconds ?? 0, last_activity: e.last_activity ?? null };
        l.last_seq = e.seq;
        break;
      case "job":
        if (!l || !e.job) break;
        if (!l.jobs.includes(e.job)) l.jobs.push(e.job);
        jobLead.set(e.job, l.id);
        l.last_seq = e.seq;
        break;
      case "interpret":
        if (!e.job || typeof e.entry !== "number") break;
        interpretations.set(e.job, [...(interpretations.get(e.job) ?? []), { by: e.by, at: e.at, entry: e.entry, kind: e.kind ?? "", ...(e.rest ? { rest: e.rest } : {}) }]);
        break;
      case "wake":
        if (!e.lead || !e.to) break;
        wakes.set(`${e.lead}#${e.cycle ?? 0}`, e.to);
        break;
      case "note":
        if (!l) break;
        l.notes.push({ at: e.at, by: e.by, text: e.text ?? "", ...(e.allow_host ? { allow_host: e.allow_host } : {}) });
        l.last_seq = e.seq;
        break;
    }
  }
  return { events, leads, jobLead, interpretations, wakes, chain };
}

// --- needs --------------------------------------------------------------------------------------

/** A need, as agents write it: L-3 (resolved), L-3:negative, or E-12 (a standing ledger entry). */
export function parseNeed(raw: string): { ok: true; need: string; lead?: string; disposition?: LeadDisposition; entry?: number } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim();
  const e = /^E-([1-9]\d{0,5})$/i.exec(text);
  if (e) return { ok: true, need: `E-${Number(e[1])}`, entry: Number(e[1]) };
  const m = /^(L-[1-9]\d{0,5})(?::([a-z_]+))?$/i.exec(text);
  if (m) {
    const disposition = (m[2] ?? "resolved").toLowerCase() as LeadDisposition;
    if (!(LEAD_DISPOSITIONS as readonly string[]).includes(disposition)) return { ok: false, reason: `a need's disposition is one of ${LEAD_DISPOSITIONS.join(", ")} (got ${JSON.stringify(m[2])})` };
    if (disposition === "duplicate" || disposition === "needs_operator" || disposition === "withdrawn") return { ok: false, reason: `${text}: a lead closed ${disposition} produced nothing a lead can use; need the lead it duplicates, or the answer the operator gives, instead` };
    const lead = `L-${Number(m[1].slice(2))}`;
    return { ok: true, need: `${lead}:${disposition}`, lead, disposition };
  }
  return { ok: false, reason: `a need is a lead with the outcome it must reach (L-3, L-3:negative) or a standing ledger entry (E-12); a job's exit is never one (got ${JSON.stringify(text)})` };
}

/** What the ledger says, as a need reads it. */
export type LedgerView = {
  entries: P.LedgerEntry[];
  bySeq: Map<number, P.LedgerEntry>;
  replaced: Map<number, number>;
  disputed: Set<string>;
};

export function ledgerView(entries: P.LedgerEntry[], disputes: P.LedgerDispute[]): LedgerView {
  return {
    entries,
    bySeq: new Map(entries.map((e) => [e.seq, e])),
    replaced: P.supersededBy(entries),
    disputed: new Set(P.standingDisputes(disputes).map((d) => d.target)),
  };
}

/** Whether a ledger entry stands: recorded, not corrected since, not disputed. */
export function entryStands(v: LedgerView, seq: number): { ok: true; kind: string } | { ok: false; why: string } {
  const e = v.bySeq.get(seq);
  if (!e) return { ok: false, why: `E-${seq} is not in the ledger` };
  const by = v.replaced.get(seq);
  if (by !== undefined) return { ok: false, why: `E-${seq} was superseded by E-${P.standingSeq(seq, v.replaced)}` };
  if (v.disputed.has(e.hash ?? P.ledgerHash(e, "genesis"))) return { ok: false, why: `E-${seq} is disputed` };
  return { ok: true, kind: e.kind };
}

/** Whether one need is met now, and when it is not, why and whether it still can be. */
export function needState(need: string, s: LeadsState, v: LedgerView): { met: boolean; why?: string; dead?: boolean } {
  const p = parseNeed(need);
  if (!p.ok) return { met: false, why: p.reason, dead: true };
  if (p.entry !== undefined) {
    const st = entryStands(v, p.entry);
    return st.ok ? { met: true } : { met: false, why: st.why, dead: v.bySeq.has(p.entry) };
  }
  const l = s.leads.get(p.lead!);
  if (!l) return { met: false, why: `${p.lead} does not exist`, dead: true };
  if (!l.closed) return { met: false, why: `${l.id} is ${l.holder ? `held by ${l.holder}` : "open, unheld"}` };
  if (l.closed.disposition === p.disposition) return { met: true };
  return { met: false, why: `${l.id} was closed ${l.closed.disposition}${l.closed.ref ? ` (${l.closed.ref})` : ""}, not ${p.disposition}: revise the need (lead_link)`, dead: true };
}

export type LeadStatus = "open" | "active" | "blocked" | "closed";

export function leadStatus(l: Lead, s: LeadsState, v: LedgerView): LeadStatus {
  if (l.closed) return "closed";
  if (l.needs.some((n) => !needState(n, s, v).met)) return "blocked";
  return l.holder ? "active" : "open";
}

/** The leads that need `id`, directly or through one another, still open or held. */
export function dependentsOf(id: string, s: LeadsState): string[] {
  const out = new Set<string>();
  const queue = [id];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const l of s.leads.values()) {
      if (l.closed || out.has(l.id) || l.id === id) continue;
      if (l.needs.some((n) => n.split(":")[0] === cur)) {
        out.add(l.id);
        queue.push(l.id);
      }
    }
  }
  return [...out];
}

/** Whether adding `need` to lead `id` would close a loop of needs. */
export function wouldCycle(id: string, need: string, s: LeadsState): boolean {
  const target = need.split(":")[0];
  if (!LEAD_ID.test(target)) return false;
  if (target === id) return true;
  // The target needs id, directly or through others: a loop.
  const seen = new Set<string>();
  const queue = [target];
  while (queue.length) {
    const cur = queue.shift()!;
    if (cur === id) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const n of s.leads.get(cur)?.needs ?? []) {
      const t = n.split(":")[0];
      if (LEAD_ID.test(t)) queue.push(t);
    }
  }
  return false;
}

// --- the goal's questions ----------------------------------------------------------------------

export type GoalQuestions = { questions: string[]; existence: string[]; source: string | null };

/** Split a shell line into words: enough for a goal's check line (quotes, no expansion). */
export function shellWords(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let any = false;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      any = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (cur || any) out.push(cur);
      cur = "";
      any = false;
      continue;
    }
    cur += ch;
  }
  if (cur || any) out.push(cur);
  return out;
}

/** The goal document the operator gave, from the registry; the contract when the registry has none. */
export async function goalDocument(sandboxRoot: string, runsDir = process.env.SWARM_RUNS_DIR || dirname(resolve(sandboxRoot))): Promise<{ text: string; source: "registry" | "sandbox contract" } | null> {
  try {
    const reg = JSON.parse(await readFile(join(runsDir, "registry.json"), "utf8")) as { runs?: Array<{ sandbox?: string; goal?: string }> };
    const real = await realpath(sandboxRoot).catch(() => resolve(sandboxRoot));
    for (const run of [...(reg.runs ?? [])].reverse()) {
      if (!run.sandbox) continue;
      const rec = await realpath(run.sandbox).catch(() => resolve(run.sandbox!));
      if (rec === real && run.goal) return { text: run.goal, source: "registry" };
    }
  } catch {
    // No registry: the contract below.
  }
  const text = await readFile(join(sandboxRoot, "SWARM.md"), "utf8").catch(() => null);
  return text ? { text, source: "sandbox contract" } : null;
}

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

/**
 * The goal's questions, as its answers check names them (--sections, and a
 * brief's numbered questions with --sections-in), and those it says ask
 * whether something exists (--existence). The check line is the goal's own:
 * nothing here reads a question's words.
 */
export async function goalQuestions(sandboxRoot: string): Promise<GoalQuestions> {
  const doc = await goalDocument(sandboxRoot);
  if (!doc) return { questions: [], existence: [], source: null };
  const questions: string[] = [];
  const existence: string[] = [];
  for (const check of goalChecks(doc.text)) {
    if (!check.includes("check-answers.ts")) continue;
    const words = shellWords(check);
    const opt = (name: string) => {
      const i = words.indexOf(name);
      return i >= 0 ? words[i + 1] : undefined;
    };
    const briefPath = opt("--sections-in");
    if (briefPath) {
      const brief = await readFile(join(sandboxRoot, briefPath), "utf8").catch(() => "");
      for (const q of P.briefQuestions(brief)) if (!questions.includes(q)) questions.push(q);
    }
    for (const raw of (opt("--sections") ?? "").split(",")) {
      const sec = P.answerSection(raw.trim());
      if (!sec.ok || !sec.section.startsWith("question:")) continue;
      if (!questions.includes(sec.id)) questions.push(sec.id);
    }
    for (const raw of (opt("--existence") ?? "").split(",")) {
      const id = P.sectionKey(raw.trim());
      if (id && !existence.includes(id)) existence.push(id);
    }
  }
  return { questions, existence, source: doc.source };
}

// --- jobs ---------------------------------------------------------------------------------------

export type JobFacts = { id: string; agent: string; kind: string; state: string; status?: string; command?: string; tool?: string; finished_at?: string };

const terminalJobs = new Map<string, JobFacts>();

/** The run's jobs, from their projected records in store/jobs/ (a terminal one is read once). */
export async function readJobs(sandboxRoot: string): Promise<JobFacts[]> {
  const dir = join(sandboxRoot, "store", "jobs");
  const names = await readdir(dir).catch(() => [] as string[]);
  const out: JobFacts[] = [];
  for (const id of names.sort()) {
    if (!/^j\d{6,}$/.test(id)) continue;
    const key = `${resolve(sandboxRoot)}\u0000${id}`;
    const known = terminalJobs.get(key);
    if (known) {
      out.push(known);
      continue;
    }
    const raw = await readFile(join(dir, id, "job.json"), "utf8").catch(() => null);
    if (!raw) continue;
    try {
      const j = JSON.parse(raw) as { id?: string; state?: string; status?: string; requester?: { agent?: string }; spec?: { kind?: string; command?: string; tool?: string }; finished_at?: string };
      const facts: JobFacts = {
        id,
        agent: j.requester?.agent ?? "",
        kind: j.spec?.kind ?? "",
        state: j.state ?? "",
        ...(j.status ? { status: j.status } : {}),
        ...(j.spec?.command ? { command: j.spec.command } : {}),
        ...(j.spec?.tool ? { tool: j.spec.tool } : {}),
        ...(j.finished_at ? { finished_at: j.finished_at } : {}),
      };
      if (facts.state === "committed" || facts.state === "failed" || facts.state === "cancelled") terminalJobs.set(key, facts);
      out.push(facts);
    } catch {
      // Not a record: skipped.
    }
  }
  return out;
}

/** Whether a job's output is the agent's to interpret: a command or a tool it asked for, that ran and was committed. */
export function needsInterpretation(j: JobFacts): boolean {
  return (j.kind === "command" || j.kind === "tool") && j.state === "committed" && j.status !== "cancelled";
}

/** Whether a job is still to finish: queued, running, or between its end and its commit. */
export function jobOpen(j: JobFacts): boolean {
  return ["accepted", "running", "finished", "fenced"].includes(j.state);
}

type Reads = { offset: number; returned: Map<string, Map<string, Array<[number, number]>>> };
const readsCache = new Map<string, Reads>();

/**
 * Which bytes of each job's stdout each agent was handed (the store journal's
 * job_returned lines), read incrementally.
 */
export async function stdoutReads(sandboxRoot: string): Promise<Map<string, Map<string, Array<[number, number]>>>> {
  const path = join(sandboxRoot, "store", "journal.jsonl");
  const key = resolve(sandboxRoot);
  let c = readsCache.get(key);
  const size = await stat(path).then((s) => s.size).catch(() => 0);
  if (!c || size < c.offset) {
    c = { offset: 0, returned: new Map() };
    readsCache.set(key, c);
  }
  if (size > c.offset) {
    const fh = await open(path, "r").catch(() => null);
    if (fh) {
      try {
        const buf = Buffer.alloc(size - c.offset);
        await fh.read(buf, 0, buf.length, c.offset);
        const text = buf.toString("utf8");
        const end = text.lastIndexOf("\n");
        if (end >= 0) {
          for (const line of text.slice(0, end).split("\n")) {
            if (!line.includes('"job_returned"')) continue;
            try {
              const l = JSON.parse(line) as { type?: string; job?: string; to?: string; stdout_offset?: number; stdout_bytes?: number };
              if (l.type !== "job_returned" || !l.job || !l.to) continue;
              const byAgent = c.returned.get(l.job) ?? new Map<string, Array<[number, number]>>();
              const spans = byAgent.get(l.to) ?? [];
              spans.push([Number(l.stdout_offset ?? 0), Number(l.stdout_offset ?? 0) + Number(l.stdout_bytes ?? 0)]);
              byAgent.set(l.to, spans);
              c.returned.set(l.job, byAgent);
            } catch {
              // A torn line: the journal's own check names it.
            }
          }
          c.offset += Buffer.byteLength(text.slice(0, end + 1));
        }
      } finally {
        await fh.close();
      }
    }
  }
  return c.returned;
}

/** How many bytes of a job's stdout an agent was not handed, of `total`. */
export function unreadBytes(spans: Array<[number, number]> | undefined, total: number): number {
  if (!spans?.length) return total;
  const sorted = [...spans].sort((a, b) => a[0] - b[0]);
  let covered = 0;
  let at = 0;
  for (const [a, b] of sorted) {
    const lo = Math.max(a, at);
    const hi = Math.min(b, total);
    if (hi > lo) covered += hi - lo;
    at = Math.max(at, b);
  }
  return Math.max(0, total - covered);
}

export type AwaitingJob = { job: string; agent: string; lead: string | null; why: string; unread_bytes?: number; total_bytes?: number; next_offset?: number };

/**
 * The jobs whose output waits for an interpretation: a command or tool job,
 * committed, that no interpretation names; or one whose stdout its requester
 * was handed only in part, until the rest is read or the interpretation says
 * how it was read or why not. A bare ledger citation does not count: an
 * interpretation is an entry recorded with `interprets` naming the job.
 */
export async function awaitingInterpretation(sandboxRoot: string, s: LeadsState, jobs?: JobFacts[]): Promise<AwaitingJob[]> {
  const all = jobs ?? (await readJobs(sandboxRoot));
  const reads = await stdoutReads(sandboxRoot);
  const out: AwaitingJob[] = [];
  for (const j of all) {
    if (!needsInterpretation(j) || !j.agent || j.agent === "system" || j.agent === "derived") continue;
    const lead = s.jobLead.get(j.id) ?? null;
    const interps = s.interpretations.get(j.id) ?? [];
    const spans = reads.get(j.id)?.get(j.agent);
    let unread: { unread: number; total: number; next: number } | null = null;
    if (spans?.length) {
      const total = await stat(join(sandboxRoot, "store", "jobs", j.id, "stdout.log")).then((st) => st.size).catch(() => 0);
      const left = unreadBytes(spans, total);
      if (left > 0) {
        const next = Math.max(...spans.map(([, b]) => b));
        unread = { unread: left, total, next: Math.min(next, total) };
      }
    }
    const restSaid = interps.some((i) => i.rest);
    if (!interps.length) {
      out.push({ job: j.id, agent: j.agent, lead, why: unread ? `no interpretation yet, and ${unread.unread} of ${unread.total} stdout bytes unread` : "no interpretation yet", ...(unread ? { unread_bytes: unread.unread, total_bytes: unread.total, next_offset: unread.next } : {}) });
    } else if (unread && !restSaid) {
      out.push({ job: j.id, agent: j.agent, lead, why: `interpreted, but ${unread.unread} of ${unread.total} stdout bytes unread: read them, or record why not (interprets with rest)`, unread_bytes: unread.unread, total_bytes: unread.total, next_offset: unread.next });
    }
  }
  return out;
}

// --- liveness -----------------------------------------------------------------------------------

/** Rows a seat's harness writes without the seat doing anything, and its waiting: none of it works a lead. */
const NOT_WORK = new Set([
  "hub_prompt", "context", "thinking", "tool_loaded", "agent_start", "inputs_guard", "budget_precall_stop",
  "self_compact", "compact_config", "compact_notice", "compact_warning", "compact_forced", "compact_hold",
  "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled", "wait", "inbox", "agent_error",
]);

/**
 * Each agent's last working row on the trace within `windowMs`, and whether a
 * compaction is under way (started, not ended). Read from the end of the
 * trace backwards, a chunk at a time, only as far as the window reaches.
 */
export async function recentActivity(sandboxRoot: string, windowMs: number, now = Date.now()): Promise<Map<string, { last: number; compacting: number | null }>> {
  const out = new Map<string, { last: number; compacting: number | null }>();
  const path = join(sandboxRoot, P.EVENTS_REL);
  const size = await stat(path).then((s) => s.size).catch(() => 0);
  if (!size) return out;
  const fh = await open(path, "r").catch(() => null);
  if (!fh) return out;
  const cutoff = now - windowMs;
  const compactEnded = new Set<string>();
  try {
    let pos = size;
    let carry = "";
    const CHUNK = 256 * 1024;
    let done = false;
    while (pos > 0 && !done) {
      const len = Math.min(CHUNK, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, pos);
      const text = buf.toString("utf8") + carry;
      const lines = text.split("\n");
      carry = pos > 0 ? (lines.shift() ?? "") : "";
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i];
        if (!line.trim()) continue;
        let e: { agent?: string; tool?: string; ts?: string; recv_ts?: string; args?: { stage?: string } };
        try {
          e = JSON.parse(line);
        } catch {
          continue;
        }
        const at = Date.parse(e.recv_ts || e.ts || "");
        if (!Number.isFinite(at)) continue;
        if (at < cutoff) {
          done = true;
          break;
        }
        const agent = e.agent ?? "";
        if (!agent || agent === "system") continue;
        const row = out.get(agent) ?? { last: 0, compacting: null };
        if (e.tool === "compact_done" || (e.tool === "compact_failed" && (e.args?.stage === "compaction" || e.args?.stage === "pi"))) compactEnded.add(agent);
        if (e.tool === "compact_start" && !compactEnded.has(agent) && row.compacting === null) row.compacting = at;
        if (e.tool && !NOT_WORK.has(e.tool)) row.last = Math.max(row.last, at);
        out.set(agent, row);
      }
    }
  } finally {
    await fh.close();
  }
  return out;
}

export type HolderLiveness = { stale: boolean; why: string; last_activity: string | null; idle_seconds: number };

/**
 * Whether a lead's holder has gone quiet: marked done or dead, or silent past
 * LEAD_STALE_MS with no job of its own still to finish and no compaction
 * under way within its bound. A turn that ended in an error is not quiet by
 * itself: the holder keeps the lead until it is also silent that long.
 */
export async function holderLiveness(sandboxRoot: string, holder: string, jobs: JobFacts[], activity?: Map<string, { last: number; compacting: number | null }>, now = Date.now(), floor = 0): Promise<HolderLiveness> {
  for (const m of ["done", "dead"] as const) {
    if (existsSync(join(sandboxRoot, "done", "agents", `${holder}.${m}`))) return { stale: true, why: `${holder} is ${m === "done" ? "done" : "marked dead"}`, last_activity: null, idle_seconds: 0 };
  }
  const act = activity ?? (await recentActivity(sandboxRoot, Math.max(leadStaleMs(), LEAD_COMPACTION_BOUND_MS), now));
  const row = act.get(holder);
  // The holder's own last act on the register counts too: a claim a moment
  // ago is work, whether or not its trace line has reached the host yet.
  const last = Math.max(row?.last ?? 0, floor);
  const idle = last ? Math.round((now - last) / 1000) : Math.round(leadStaleMs() / 1000);
  const lastIso = last ? new Date(last).toISOString() : null;
  if (jobs.some((j) => j.agent === holder && jobOpen(j))) return { stale: false, why: `${holder} has a job still running`, last_activity: lastIso, idle_seconds: idle };
  if (row?.compacting && now - row.compacting < LEAD_COMPACTION_BOUND_MS) return { stale: false, why: `${holder} is compacting its context`, last_activity: lastIso, idle_seconds: idle };
  if (last && now - last < leadStaleMs()) return { stale: false, why: `${holder} worked ${idle} s ago`, last_activity: lastIso, idle_seconds: idle };
  return { stale: true, why: last ? `${holder} has done nothing for ${Math.round(idle / 60)} min, with no job running and no compaction under way` : `${holder} has done nothing in the last ${Math.round(leadStaleMs() / 60_000)} min`, last_activity: lastIso, idle_seconds: idle };
}

// --- idle seats ---------------------------------------------------------------------------------

/** When each seat began waiting, if it is waiting now (protocol.ts marks it). */
export async function idleSeats(sandboxRoot: string, s: LeadsState, v: LedgerView, jobs: JobFacts[], now = Date.now()): Promise<Array<{ agent: string; since: number }>> {
  const ids = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
  const out: Array<{ agent: string; since: number }> = [];
  for (const agent of ids) {
    if (existsSync(join(sandboxRoot, "done", "agents", `${agent}.done`)) || existsSync(join(sandboxRoot, "done", "agents", `${agent}.dead`))) continue;
    const mark = await P.readWaiting(sandboxRoot, agent);
    const since = P.waitingSince(mark, now);
    if (since === null || now - since < IDLE_SEAT_MS) continue;
    const holds = [...s.leads.values()].some((l) => l.holder === agent && !l.closed);
    if (holds) continue;
    if (jobs.some((j) => j.agent === agent && jobOpen(j))) continue;
    out.push({ agent, since });
  }
  return out.sort((a, b) => a.since - b.since || a.agent.localeCompare(b.agent));
}

// --- the snapshot -------------------------------------------------------------------------------

export type LeadsSnapshot = {
  state: LeadsState;
  ledger: LedgerView;
  goal: GoalQuestions;
  /** Question ids with a standing answer entry. */
  answered: Set<string>;
  jobs: JobFacts[];
  at: number;
  /** The question register (extensions/questions.ts), read beside the leads; null when it could not be read. */
  questions: import("./questions.ts").QuestionsSnapshot | null;
};

export async function leadsSnapshot(sandboxRoot: string): Promise<LeadsSnapshot> {
  const { events, text } = await readLeadEvents(sandboxRoot);
  const chain = verifyLeadChain(text);
  const state = foldLeads(events, chain);
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as P.LedgerEntry[]);
  const disputes = await P.readDisputes(sandboxRoot).catch(() => [] as P.LedgerDispute[]);
  const ledger = ledgerView(entries, disputes);
  const goal = await goalQuestions(sandboxRoot);
  const answered = new Set<string>();
  for (const e of entries) {
    if (e.kind !== "answer" || !e.section?.startsWith("question:") || ledger.replaced.has(e.seq)) continue;
    answered.add(P.sectionKey(e.section.slice("question:".length)));
  }
  const jobs = await readJobs(sandboxRoot);
  const questions = await import("./questions.ts").then((Q) => Q.questionsSnapshot(sandboxRoot, { goal })).catch(() => null);
  return { state, ledger, goal, answered, jobs, at: Date.now(), questions };
}

/** A lead as a reader is shown it: its record, with everything derived beside it. */
export type LeadView = {
  id: string;
  title: string;
  why: string;
  origin: string;
  status: LeadStatus;
  material: boolean;
  holder: string | null;
  generation: number;
  needs: Array<{ need: string; met: boolean; why?: string }>;
  answers: string[];
  disposition?: LeadDisposition;
  ref?: string;
  closed_by?: string;
  closed_at?: string;
  close_why?: string;
  opened_by: string;
  opened_at: string;
  held_since: string | null;
  priority: number;
  waiting_on_it: { leads: string[]; questions: string[] };
  stale: Lead["stale"];
  jobs: string[];
  notes: Lead["notes"];
  reopened: Lead["reopened"];
  proposition?: string;
  negation?: string;
  product?: string;
  acceptance?: string;
};

export function viewLead(l: Lead, snap: LeadsSnapshot): LeadView {
  const { state: s, ledger: v } = snap;
  const status = leadStatus(l, s, v);
  const deps = dependentsOf(l.id, s);
  const qs = new Set<string>();
  for (const id of [l.id, ...deps]) for (const a of s.leads.get(id)?.answers ?? []) if (!snap.answered.has(P.sectionKey(a))) qs.add(P.sectionKey(a));
  return {
    id: l.id,
    title: l.title,
    why: l.why,
    origin: l.origin,
    status,
    material: l.material,
    holder: l.holder,
    generation: l.generation,
    needs: l.needs.map((n) => ({ need: n, ...needState(n, s, v) })).map(({ dead: _d, ...x }) => x),
    answers: l.answers,
    ...(l.closed ? { disposition: l.closed.disposition, ref: l.closed.ref, closed_by: l.closed.by, closed_at: l.closed.at, ...(l.closed.why ? { close_why: l.closed.why } : {}) } : {}),
    opened_by: l.opened_by,
    opened_at: l.opened_at,
    held_since: l.held_since,
    priority: l.closed ? 0 : deps.length + qs.size,
    waiting_on_it: { leads: deps, questions: [...qs].sort() },
    stale: l.stale,
    jobs: l.jobs,
    notes: l.notes,
    reopened: l.reopened,
    ...(l.proposition ? { proposition: l.proposition } : {}),
    ...(l.negation ? { negation: l.negation } : {}),
    ...(l.product ? { product: l.product } : {}),
    ...(l.acceptance ? { acceptance: l.acceptance } : {}),
  };
}

/** Every lead's view, the live ones by priority then age, the closed ones after them by when they closed. */
export function rankedLeads(snap: LeadsSnapshot): LeadView[] {
  const views = [...snap.state.leads.values()].map((l) => viewLead(l, snap));
  const live = views.filter((x) => x.status !== "closed").sort((a, b) => b.priority - a.priority || a.opened_at.localeCompare(b.opened_at) || a.id.localeCompare(b.id));
  const closed = views.filter((x) => x.status === "closed").sort((a, b) => (a.closed_at ?? "").localeCompare(b.closed_at ?? "") || a.id.localeCompare(b.id));
  return [...live, ...closed];
}

/**
 * The questions the run is to answer: the goal's, then every other question
 * the register holds in scope (a person's, an agent's), by their sections.
 */
export function caseQuestions(snap: LeadsSnapshot): string[] {
  const out = [...snap.goal.questions];
  for (const q of snap.questions?.state.questions.values() ?? []) {
    if (q.origin.kind === "goal" || q.scope !== "in_scope" || q.withdrawn || q.after_done) continue;
    if (!out.includes(q.section)) out.push(q.section);
  }
  return out;
}

/** The case's questions with no standing answer, and of those, the ones no held lead covers. */
export function questionCoverage(snap: LeadsSnapshot): { unanswered: string[]; uncovered: string[]; open_leads_for: Record<string, string[]> } {
  const unanswered = caseQuestions(snap).filter((q) => !snap.answered.has(P.sectionKey(q)));
  const uncovered: string[] = [];
  const openFor: Record<string, string[]> = {};
  for (const q of unanswered) {
    const naming = [...snap.state.leads.values()].filter((l) => !l.closed && l.answers.some((a) => P.sectionKey(a) === P.sectionKey(q)));
    if (!naming.some((l) => l.holder)) uncovered.push(q);
    const unheld = naming.filter((l) => !l.holder).map((l) => l.id);
    if (unheld.length) openFor[q] = unheld;
  }
  return { unanswered, uncovered, open_leads_for: openFor };
}

// --- writing ------------------------------------------------------------------------------------

async function appendLeadEvents(sandboxRoot: string, events: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash"> & { at?: string }>, held: P.HeldLock): Promise<LeadEvent[]> {
  const { events: existing, text } = await readLeadEvents(sandboxRoot);
  const chain = verifyLeadChain(text);
  if (!chain.ok) throw new Error(`leads/leads.jsonl's chain is broken at line ${chain.broken_at} (${chain.reason}); the register takes no new event until the operator looks`);
  let prev = chain.head ?? "genesis";
  let seq = existing.length;
  const out: LeadEvent[] = [];
  for (const raw of events) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: raw.at ?? new Date().toISOString(), ...Object.fromEntries(Object.entries(raw).filter(([k, x]) => k !== "at" && x !== undefined)) } as Omit<LeadEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<LeadEvent, "hash">;
    const e = { ...withPrev, hash: leadEventHash(withPrev, prev) } as LeadEvent;
    out.push(e);
    prev = e.hash;
  }
  await mkdir(join(sandboxRoot, LEADS_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(sandboxRoot, LEADS_LOG), out.map((e) => `${JSON.stringify(e)}\n`).join(""), "utf8");
  return out;
}

/** A lead event as a writer drafts it: the chain fields are the append's. */
export type LeadDraft = Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">;

/** Run `fn` under the lock both registers share (the question register's writes take it through here). */
export async function withRegisters<T>(sandboxRoot: string, fn: (held: P.HeldLock) => Promise<T>): Promise<T> {
  return P.withNamedLock(sandboxRoot, LOCK, fn);
}

/** Append lead events under a lock the caller holds (withRegisters), and render leads.md. */
export async function appendLeadEventsHeld(sandboxRoot: string, events: LeadDraft[], held: P.HeldLock): Promise<LeadEvent[]> {
  const out = events.length ? await appendLeadEvents(sandboxRoot, events, held) : [];
  if (out.length) await writeLeadsMd(sandboxRoot).catch(() => undefined);
  return out;
}

/** Run `fn` under the register's lock, with its state read inside the lock; what it returns to append is appended, and leads.md rendered. */
async function transact<T>(sandboxRoot: string, fn: (snap: LeadsSnapshot) => Promise<{ append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">>; result: T }>): Promise<T & { events: LeadEvent[] }> {
  return P.withNamedLock(sandboxRoot, LOCK, async (held) => {
    const snap = await leadsSnapshot(sandboxRoot);
    const { append, result } = await fn(snap);
    const events = append.length ? await appendLeadEvents(sandboxRoot, append, held) : [];
    if (events.length) await writeLeadsMd(sandboxRoot).catch(() => undefined);
    return { ...result, events };
  });
}

function bounded(name: string, raw: unknown, max: number, required: boolean): { ok: true; value: string } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim();
  if (required && !text) return { ok: false, reason: `${name} is required` };
  if (text.length > max) return { ok: false, reason: `${name} is over ${max} characters: say it in fewer; nothing is cut, so a longer text is refused, not shortened` };
  return { ok: true, value: text };
}

function listOf(v: unknown): string[] {
  const raw = Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[\s,]+/) : [];
  return [...new Set(raw.map((x) => x.trim()).filter(Boolean))];
}

export type LeadResult<T = Record<string, unknown>> = ({ ok: true } & T) | { ok: false; reason: string };
type Fail = { ok: false; reason: string };

export type LeadOpenInput = {
  title?: string;
  why?: string;
  needs?: string[] | string;
  answers?: string[] | string;
  material?: boolean;
  take?: boolean;
  origin?: string;
  /** Under an analyst's question: the proposition this lead tests, and its negation (required on the first agent lead under one). */
  proposition?: string;
  negation?: string;
  /** A directive's product and acceptance (the operator's lead under a question). */
  product?: string;
  acceptance?: string;
};

function checkNeeds(raw: unknown, s: LeadsState, v: LedgerView, self?: string): { ok: true; needs: string[] } | { ok: false; reason: string } {
  const needs: string[] = [];
  for (const n of listOf(raw)) {
    const p = parseNeed(n);
    if (!p.ok) return p;
    if (p.lead && !s.leads.has(p.lead)) return { ok: false, reason: `${p.lead} does not exist: open it first, or need an entry (E-<seq>)` };
    if (p.entry !== undefined && !v.bySeq.has(p.entry)) return { ok: false, reason: `E-${p.entry} is not in the ledger` };
    if (self && wouldCycle(self, p.need, s)) return { ok: false, reason: `${self} needing ${p.need} closes a loop: ${p.lead} already needs ${self}, directly or through other leads` };
    if (!needs.includes(p.need)) needs.push(p.need);
  }
  if (needs.length > LEAD_MAX_NEEDS) return { ok: false, reason: `a lead names at most ${LEAD_MAX_NEEDS} needs` };
  return { ok: true, needs };
}

function checkAnswers(raw: unknown): { ok: true; answers: string[]; registered: string[] } | { ok: false; reason: string } {
  const answers: string[] = [];
  // A register id (Q-19) is resolved against the question register inside the
  // lock (resolveAnswers); the goal's own forms (3, Q3, question:3) are the
  // section they always were.
  const registered: string[] = [];
  for (const a of listOf(raw)) {
    const reg = /^Q-([1-9]\d{0,5})$/i.exec(a);
    if (reg) {
      const id = `Q-${Number(reg[1])}`;
      if (!registered.includes(id)) registered.push(id);
      continue;
    }
    const key = P.sectionKey(a.replace(/^question:/i, ""));
    if (!answers.includes(key)) answers.push(key);
  }
  if (answers.length + registered.length > LEAD_MAX_ANSWERS) return { ok: false, reason: `a lead names at most ${LEAD_MAX_ANSWERS} questions` };
  const bad = answers.find((a) => !P.LEDGER_ANSWER_ID.test(a));
  if (bad) return { ok: false, reason: `answers takes question ids: Q-19 from the question register, or the goal's own ("3", "Q3", "question:3"; got ${JSON.stringify(bad)})` };
  return { ok: true, answers, registered };
}

/**
 * The questions a lead names, as the ledger's sections: a register id (Q-19)
 * must name a question in scope, and becomes its section (19, or a goal's own
 * id such as "bonus"); the goal's forms pass as they are. Also says which of
 * them an analyst, a reviewer or an observer asked (a human's question is a
 * hypothesis to test: its first agent lead states the proposition and its
 * negation). Read inside the register's lock.
 */
async function resolveAnswers(sandboxRoot: string, checked: { answers: string[]; registered: string[] }): Promise<{ ok: true; answers: string[]; human: Array<{ id: string; section: string }> } | { ok: false; reason: string }> {
  const Q = await import("./questions.ts");
  const qs = await Q.questionsSnapshot(sandboxRoot);
  const out = [...checked.answers];
  const human: Array<{ id: string; section: string }> = [];
  for (const id of checked.registered) {
    const q = qs.state.questions.get(id);
    if (!q) return { ok: false, reason: `${id} is not in the question register (questions view=list names every question)` };
    if (q.withdrawn) return { ok: false, reason: `${id} was withdrawn by ${Q.originWords(q.withdrawn.origin)}: ${q.withdrawn.why}` };
    if (q.scope === "excluded") return { ok: false, reason: `${id} is excluded from the case (${q.scope_why}); it is no lead's work` };
    if (q.scope === "proposed") return { ok: false, reason: `${id} is proposed and waits for the operator's triage: it is not the case's work until it is admitted` };
    if (!out.includes(q.section)) out.push(q.section);
  }
  for (const section of out) {
    const q = qs.bySection.get(section);
    if (q && Q.HUMAN_ORIGINS.has(q.origin.kind)) human.push({ id: q.id, section });
  }
  return { ok: true, answers: out, human };
}

/**
 * Open a lead. With take, the opener holds it at once (create and claim in
 * one step: the discoverer's first refusal, so nobody takes the natural next
 * step of its own work from under it). Without, it is open to everyone, and
 * when it is ready (no unmet need) the seat idle longest is woken for it.
 */
export async function openLead(ctx: P.SwarmContext, input: LeadOpenInput): Promise<LeadResult<{ lead: LeadView; woke?: string }>> {
  const title = bounded("title", input.title, LEAD_TITLE_MAX, true);
  if (!title.ok) return title;
  const why = bounded("why", input.why, LEAD_WHY_MAX, true);
  if (!why.ok) return why;
  const origin = bounded("origin", input.origin, 200, false);
  if (!origin.ok) return origin;
  if (input.material !== undefined && typeof input.material !== "boolean") return { ok: false, reason: "material is true or false" };
  if (input.take !== undefined && typeof input.take !== "boolean") return { ok: false, reason: "take is true or false" };
  const checked = checkAnswers(input.answers);
  if (!checked.ok) return checked;
  const proposition = bounded("proposition", input.proposition, LEAD_WHY_MAX, false);
  if (!proposition.ok) return proposition;
  const negation = bounded("negation", input.negation, LEAD_WHY_MAX, false);
  if (!negation.ok) return negation;
  if (Boolean(proposition.value) !== Boolean(negation.value)) return { ok: false, reason: "proposition and negation come together: the proposition this lead tests, and what would hold if it is false" };
  const product = bounded("product", input.product, LEAD_WHY_MAX, false);
  if (!product.ok) return product;
  const acceptance = bounded("acceptance", input.acceptance, LEAD_WHY_MAX, false);
  if (!acceptance.ok) return acceptance;
  try {
    const r = await transact<Fail | { ok: true; id: string; woke: string | undefined }>(ctx.sandboxRoot, async (snap) => {
      const needs = checkNeeds(input.needs, snap.state, snap.ledger);
      if (!needs.ok) return { append: [], result: { ok: false as const, reason: needs.reason } };
      const answers = checked.registered.length || checked.answers.length ? await resolveAnswers(ctx.sandboxRoot, checked) : { ok: true as const, answers: [] as string[], human: [] as Array<{ id: string; section: string }> };
      if (!answers.ok) return { append: [], result: { ok: false as const, reason: answers.reason } };
      // The first agent lead under a human's question tests it: the
      // proposition and its negation, stated before the search (a directive
      // is the operator's own, and carries its product instead).
      if (ctx.agentId !== "operator" && !proposition.value) {
        for (const h of answers.human) {
          const earlier = [...snap.state.leads.values()].some((l) => l.opened_by !== "operator" && l.answers.includes(h.section));
          if (!earlier) {
            return {
              append: [],
              result: {
                ok: false as const,
                reason: `${h.id} is a person's question and this is the first lead under it: it is a proposition to test, never a conclusion to confirm. Give proposition (what this lead tests) and negation (what would hold if it is false), and plan a route that could disconfirm it`,
              },
            };
          }
        }
      }
      const id = `L-${snap.state.leads.size + 1}`;
      const take = input.take === true;
      const open = {
        by: ctx.agentId,
        ev: "open" as const,
        lead: id,
        title: title.value,
        why: why.value,
        origin: origin.value || `lead_open by ${ctx.agentId}`,
        needs: needs.needs,
        answers: answers.answers,
        material: input.material !== false,
        ...(take ? { holder: ctx.agentId, generation: 1 } : { generation: 0 }),
        ...(proposition.value ? { proposition: proposition.value, negation: negation.value } : {}),
        ...(product.value ? { product: product.value } : {}),
        ...(acceptance.value ? { acceptance: acceptance.value } : {}),
      };
      const append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">> = [open];
      // Ready and unheld: the seat idle longest is woken for it, once.
      let woke: string | undefined;
      if (!take && !needs.needs.some((n) => !needState(n, snap.state, snap.ledger).met)) {
        const idle = await idleSeats(ctx.sandboxRoot, snap.state, snap.ledger, snap.jobs);
        const pick = idle.find((x) => x.agent !== ctx.agentId);
        if (pick) {
          woke = pick.agent;
          append.push({ by: "system", ev: "wake", lead: id, to: pick.agent, cycle: 0 });
        }
      }
      return { append, result: { ok: true as const, id, woke } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(r.id)!, snap), ...(r.woke ? { woke: r.woke } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

function leadRef(raw: unknown): { ok: true; id: string } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim().toUpperCase();
  const m = LEAD_ID.exec(text);
  if (!m) return { ok: false, reason: `a lead is named L-<n> (got ${JSON.stringify(raw)})` };
  return { ok: true, id: `L-${Number(m[1])}` };
}

/**
 * Claim a lead: atomically, with a new generation. A lead someone else holds
 * is theirs until they release it or show as stale; a stale holder is marked
 * first (and told, through their header and wait), and the lead may be taken
 * only once that mark has stood reclaimGraceMs(). A turn error frees
 * nothing by itself.
 */
export async function claimLead(ctx: P.SwarmContext, rawId: unknown, now = Date.now()): Promise<LeadResult<{ lead: LeadView; reclaimed_from?: string; already?: true }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  try {
    const r = await transact<Fail | { ok: true; already?: true; from?: string }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed (${l.closed.disposition}${l.closed.ref ? `, ${l.closed.ref}` : ""}, by ${l.closed.by}); open a new lead for new work, or ask the operator to reopen it` } };
      if (l.holder === ctx.agentId) return { append: [], result: { ok: true as const, already: true as const } };
      if (!l.holder) return { append: [{ by: ctx.agentId, ev: "claim", lead: l.id, holder: ctx.agentId, generation: l.generation + 1 }], result: { ok: true as const } };
      // Held by a peer: only a stale holder gives it up, and only after being marked.
      const lastAct = Math.max(0, ...snap.state.events.filter((e) => e.by === l.holder && e.ev !== "stale").map((e) => Date.parse(e.at)).filter(Number.isFinite));
      const live = await holderLiveness(ctx.sandboxRoot, l.holder, snap.jobs, undefined, now, lastAct);
      if (!live.stale) {
        return { append: [], result: { ok: false as const, reason: `${l.id} is held by ${l.holder} (generation ${l.generation}, since ${l.held_since}): ${live.why}. Post to ${l.holder}, or open a lead for your own part of it` } };
      }
      if (!l.stale || l.stale.holder !== l.holder || l.stale.generation !== l.generation) {
        const mark = { by: ctx.agentId, ev: "stale" as const, lead: l.id, holder: l.holder, generation: l.generation, idle_seconds: live.idle_seconds, last_activity: live.last_activity };
        return { append: [mark], result: { ok: false as const, reason: `${l.id}'s holder ${l.holder} shows as stale (${live.why}). It is marked stale now and ${l.holder} is told; claim it again in ${Math.round(reclaimGraceMs() / 1000)} s to take it over if ${l.holder} has not answered` } };
      }
      const since = now - Date.parse(l.stale.at);
      if (since < reclaimGraceMs()) {
        return { append: [], result: { ok: false as const, reason: `${l.id} was marked stale ${Math.round(since / 1000)} s ago; ${l.holder} has ${Math.round((reclaimGraceMs() - since) / 1000)} s more to answer before it can be taken over` } };
      }
      return { append: [{ by: ctx.agentId, ev: "claim", lead: l.id, holder: ctx.agentId, generation: l.generation + 1, from: l.holder }], result: { ok: true as const, from: l.holder } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), ...("from" in r && r.from ? { reclaimed_from: r.from } : {}), ...("already" in r && r.already ? { already: true as const } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

function holderOnly(l: Lead, ctx: P.SwarmContext, generation: unknown, verb: string): string | null {
  if (l.holder !== ctx.agentId) return l.holder ? `${l.id} is held by ${l.holder} (generation ${l.generation}); only its holder can ${verb} it` : `${l.id} is not held by you (nobody holds it); claim it first`;
  if (generation !== undefined && generation !== null && Number(generation) !== l.generation) return `${l.id} is at generation ${l.generation}, not ${generation}: it changed hands since you last held it`;
  return null;
}

export async function releaseLead(ctx: P.SwarmContext, rawId: unknown, input: { why?: string; generation?: number } = {}): Promise<LeadResult<{ lead: LeadView }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const why = bounded("why", input.why, LEAD_WHY_MAX, false);
  if (!why.ok) return why;
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed; there is nothing to release` } };
      const refused = holderOnly(l, ctx, input.generation, "release");
      if (refused) return { append: [], result: { ok: false as const, reason: refused } };
      return { append: [{ by: ctx.agentId, ev: "release", lead: l.id, generation: l.generation, ...(why.value ? { why: why.value } : {}) }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** What a disposition's ref must be, checked against the ledger and the register. */
function checkRef(disposition: LeadDisposition, raw: string, l: Lead, snap: LeadsSnapshot): { ok: true; ref: string } | { ok: false; reason: string } {
  const text = raw.trim();
  if (disposition === "needs_operator") {
    if (text.length < 10) return { ok: false, reason: "needs_operator says in ref what only the operator can do: the host to allow, the file to add, or the question to answer, and why" };
    return { ok: true, ref: text };
  }
  if (disposition === "duplicate") {
    const d = leadRef(text);
    if (!d.ok) return { ok: false, reason: "duplicate cites the lead it repeats: ref L-<n>" };
    if (d.id === l.id) return { ok: false, reason: "a lead is not a duplicate of itself" };
    const other = snap.state.leads.get(d.id);
    if (!other) return { ok: false, reason: `${d.id} does not exist` };
    if (other.closed?.disposition === "duplicate" && other.closed.ref === l.id) return { ok: false, reason: `${d.id} is already closed as a duplicate of ${l.id}: one of the two carries the work` };
    return { ok: true, ref: d.id };
  }
  const m = /^E-([1-9]\d{0,5})$/i.exec(text);
  if (!m) return { ok: false, reason: `${disposition} cites a ledger entry: ref E-<seq> (${disposition === "resolved" ? "the entry that settles it" : disposition === "negative" ? "the absence: the search that found nothing" : disposition === "deferred" ? "the limitation that says why it waits" : "the limitation naming the methods tried and why none worked"})` };
  const seq = Number(m[1]);
  const st = entryStands(snap.ledger, seq);
  if (!st.ok) return { ok: false, reason: `${st.why}: cite an entry that stands` };
  const want: Record<string, string[]> = { negative: ["absence"], deferred: ["limitation"], infeasible: ["limitation"] };
  if (want[disposition] && !want[disposition].includes(st.kind)) return { ok: false, reason: `${disposition} cites ${want[disposition].join(" or ")} (E-${seq} is ${st.kind})` };
  if (disposition === "resolved" && st.kind === "limitation") return { ok: false, reason: `a limitation does not resolve a lead: close it deferred or infeasible citing E-${seq}` };
  if (disposition === "resolved" && st.kind === "hypothesis") return { ok: false, reason: `a hypothesis does not resolve a lead: record what settled it, and cite that` };
  return { ok: true, ref: `E-${seq}` };
}

/**
 * Close a lead with its disposition and what it cites. The holder closes its
 * own; an unheld lead can be closed by anyone (a duplicate found, a search
 * already recorded), and the record says who. A lead closed needs_operator
 * also writes its request to operator-requests.jsonl.
 */
export async function closeLead(ctx: P.SwarmContext, rawId: unknown, input: { disposition?: string; ref?: string; why?: string; generation?: number }): Promise<LeadResult<{ lead: LeadView; operator_request?: string }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const disposition = String(input.disposition ?? "").trim().toLowerCase() as LeadDisposition;
  if (!(LEAD_DISPOSITIONS as readonly string[]).includes(disposition)) return { ok: false, reason: `disposition is one of ${LEAD_DISPOSITIONS.filter((d) => d !== "withdrawn").join(", ")}` };
  if (disposition === "withdrawn") return { ok: false, reason: "withdrawn is the harness's: a lead closes withdrawn when every question it serves is withdrawn by whoever asked it" };
  const refText = bounded("ref", input.ref, LEAD_REF_MAX, true);
  if (!refText.ok) return refText;
  const why = bounded("why", input.why, LEAD_WHY_MAX, false);
  if (!why.ok) return why;
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is already closed (${l.closed.disposition}, by ${l.closed.by})` } };
      if (l.holder) {
        const refused = holderOnly(l, ctx, input.generation, "close");
        if (refused) return { append: [], result: { ok: false as const, reason: refused } };
      }
      const checked = checkRef(disposition, refText.value, l, snap);
      if (!checked.ok) return { append: [], result: { ok: false as const, reason: checked.reason } };
      return { append: [{ by: ctx.agentId, ev: "close", lead: l.id, generation: l.generation, disposition, ref: checked.ref, ...(why.value ? { why: why.value } : {}) }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    const view = viewLead(snap.state.leads.get(ref.id)!, snap);
    let request: string | undefined;
    if (disposition === "needs_operator") request = await writeOperatorRequest(ctx.sandboxRoot, view, ctx.agentId).catch(() => undefined);
    return { ok: true, lead: view, ...(request ? { operator_request: request } : {}) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** One line in operator-requests.jsonl, for the console and the CLI; the command that answers it. */
async function writeOperatorRequest(sandboxRoot: string, lead: LeadView, by: string): Promise<string> {
  const run = (await P.readTeam(sandboxRoot).catch(() => null))?.swarm_id ?? "";
  const answer = `swarm.sh lead ${run || "<run>"} note ${lead.id} "<your answer>" [--allow-host HOST]`;
  const line = { at: new Date().toISOString(), run, lead: lead.id, by, title: lead.title, request: lead.ref ?? "", answer };
  await appendFile(join(sandboxRoot, OPERATOR_REQUESTS), `${JSON.stringify(line)}\n`, "utf8");
  return answer;
}

/**
 * Revise a lead's needs: add a route, or drop one that will not come, so an
 * alternative stays open. The holder revises its own lead; an unheld one,
 * anyone. A loop is refused.
 */
export async function linkLead(ctx: P.SwarmContext, rawId: unknown, input: { add?: string[] | string; remove?: string[] | string }): Promise<LeadResult<{ lead: LeadView }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  try {
    const r = await transact<Fail | { ok: true }>(ctx.sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is closed` } };
      if (l.holder && l.holder !== ctx.agentId) return { append: [], result: { ok: false as const, reason: `${l.id} is held by ${l.holder}; its needs are its holder's to revise` } };
      const add = checkNeeds(input.add, snap.state, snap.ledger, l.id);
      if (!add.ok) return { append: [], result: { ok: false as const, reason: add.reason } };
      const remove: string[] = [];
      for (const n of listOf(input.remove)) {
        const p = parseNeed(n);
        if (!p.ok) return { append: [], result: { ok: false as const, reason: p.reason } };
        if (!l.needs.includes(p.need)) return { append: [], result: { ok: false as const, reason: `${l.id} does not need ${p.need} (its needs: ${l.needs.join(", ") || "none"})` } };
        remove.push(p.need);
      }
      const fresh = add.needs.filter((n) => !l.needs.includes(n));
      if (!fresh.length && !remove.length) return { append: [], result: { ok: false as const, reason: "give add, remove, or both: a need to add that it does not have, or one it has to drop" } };
      if (l.needs.length - remove.length + fresh.length > LEAD_MAX_NEEDS) return { append: [], result: { ok: false as const, reason: `a lead names at most ${LEAD_MAX_NEEDS} needs` } };
      return { append: [{ by: ctx.agentId, ev: "link", lead: l.id, ...(fresh.length ? { add: fresh } : {}), ...(remove.length ? { remove } : {}) }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * Reopen a closed lead. The operator does it after answering a request; the
 * harness does it when the entry a lead was closed on is superseded or
 * disputed (reopenOnLedger), since the closure no longer stands.
 */
export async function reopenLead(sandboxRoot: string, rawId: unknown, by: string, why: string, cause: string): Promise<LeadResult<{ lead: LeadView }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const text = bounded("why", why, LEAD_WHY_MAX, true);
  if (!text.ok) return text;
  try {
    const r = await transact<Fail | { ok: true }>(sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      if (!l.closed) return { append: [], result: { ok: false as const, reason: `${l.id} is not closed` } };
      return { append: [{ by, ev: "reopen", lead: l.id, why: text.value, cause }], result: { ok: true as const } };
    });
    if (!r.ok) return r;
    const snap = await leadsSnapshot(sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * The operator's answer to a lead: recorded on it, and the lead reopened when
 * it was closed, so the work goes on with what the operator gave. A host the
 * operator allows goes into operator-hosts.jsonl, which the job service reads
 * for each job run with network=allowlist from then on.
 */
export async function noteLead(sandboxRoot: string, rawId: unknown, text: string, o: { allowHost?: string; reopen?: boolean } = {}): Promise<LeadResult<{ lead: LeadView; reopened: boolean }>> {
  const ref = leadRef(rawId);
  if (!ref.ok) return ref;
  const note = bounded("the note", text, LEAD_NOTE_MAX, true);
  if (!note.ok) return note;
  const host = String(o.allowHost ?? "").trim();
  if (host && !/^(\*\.)?[A-Za-z0-9.-]{1,253}(:\d{1,5})?$/.test(host)) return { ok: false, reason: `--allow-host takes a host name (example.org, *.example.org, example.org:8443), got ${JSON.stringify(host)}` };
  try {
    const r = await transact<Fail | { ok: true; reopened: boolean }>(sandboxRoot, async (snap) => {
      const l = snap.state.leads.get(ref.id);
      if (!l) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
      const append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">> = [{ by: "operator", ev: "note", lead: l.id, text: note.value, ...(host ? { allow_host: host } : {}) }];
      const reopen = Boolean(l.closed) && o.reopen !== false;
      if (reopen) append.push({ by: "operator", ev: "reopen", lead: l.id, why: `the operator answered: ${note.value}`, cause: "operator" });
      return { append, result: { ok: true as const, reopened: reopen } };
    });
    if (!r.ok) return r;
    if (host) await appendFile(join(sandboxRoot, OPERATOR_HOSTS), `${JSON.stringify({ at: new Date().toISOString(), host, lead: ref.id, by: "operator" })}\n`, "utf8");
    const snap = await leadsSnapshot(sandboxRoot);
    return { ok: true, lead: viewLead(snap.state.leads.get(ref.id)!, snap), reopened: r.reopened };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** The hosts the operator allowed while the run went on. */
export async function operatorHosts(sandboxRoot: string): Promise<string[]> {
  return operatorHostsSync(sandboxRoot);
}

/** The same, read at once: the job service reads it as it places each job that asks for the network. */
export function operatorHostsSync(sandboxRoot: string): string[] {
  let text = "";
  try {
    text = readFileSync(join(sandboxRoot, OPERATOR_HOSTS), "utf8");
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const h = String((JSON.parse(line) as { host?: string }).host ?? "");
      if (h && !out.includes(h)) out.push(h);
    } catch {
      // skipped
    }
  }
  return out;
}

/**
 * A job an agent ran, under the lead it named or, when it named none, the one
 * active lead it holds. A lead's jobs wait for an interpretation before the
 * run may end (the gate); an agent's other jobs are shown, never gated.
 */
export async function attachJob(sandboxRoot: string, agent: string, job: string, named?: unknown): Promise<LeadResult<{ lead: string | null }>> {
  try {
    const r = await transact<Fail | { ok: true; lead: string | null }>(sandboxRoot, async (snap) => {
      let lead: Lead | undefined;
      if (named !== undefined && named !== null && String(named).trim()) {
        const ref = leadRef(named);
        if (!ref.ok) return { append: [], result: { ok: false as const, reason: ref.reason } };
        lead = snap.state.leads.get(ref.id);
        if (!lead) return { append: [], result: { ok: false as const, reason: `${ref.id} does not exist` } };
        if (lead.closed) return { append: [], result: { ok: false as const, reason: `${lead.id} is closed` } };
        if (lead.holder !== agent) return { append: [], result: { ok: false as const, reason: `${lead.id} is ${lead.holder ? `held by ${lead.holder}` : "not held"}: claim it before running its jobs` } };
      } else {
        const mine = [...snap.state.leads.values()].filter((l) => l.holder === agent && !l.closed);
        if (mine.length !== 1) return { append: [], result: { ok: true as const, lead: null } };
        lead = mine[0];
      }
      if (snap.state.jobLead.has(job)) return { append: [], result: { ok: true as const, lead: snap.state.jobLead.get(job)! } };
      return { append: [{ by: agent, ev: "job", lead: lead.id, job }], result: { ok: true as const, lead: lead.id } };
    });
    return r.ok ? { ok: true, lead: r.lead } : r;
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** Whether a lead the agent names may run a job now (checked before the job is accepted). */
export async function jobLeadAllowed(sandboxRoot: string, agent: string, named: unknown): Promise<string | null> {
  if (named === undefined || named === null || !String(named).trim()) return null;
  const ref = leadRef(named);
  if (!ref.ok) return ref.reason;
  const snap = await leadsSnapshot(sandboxRoot);
  const l = snap.state.leads.get(ref.id);
  if (!l) return `${ref.id} does not exist`;
  if (l.closed) return `${l.id} is closed`;
  if (l.holder !== agent) return `${l.id} is ${l.holder ? `held by ${l.holder}` : "not held"}: claim it before running its jobs`;
  return null;
}

export type InterpretInput = { job?: string; rest?: string } | string;

/**
 * Record that a ledger entry is the interpretation of jobs' output: what the
 * output shows, as the entry says it, and its kind as the disposition (a
 * finding: it shows something; an absence: it shows nothing; a limitation:
 * it could not be used). `rest`, per job, says how the rest of an output
 * handed over only in part was read, or why it was not.
 */
export async function recordInterpretations(sandboxRoot: string, agent: string, entrySeq: number, items: InterpretInput[]): Promise<LeadResult<{ interprets: string[] }>> {
  const list: Array<{ job: string; rest?: string }> = [];
  for (const it of items) {
    const job = String(typeof it === "string" ? it : (it?.job ?? "")).trim();
    if (!/^j\d{6,}$/.test(job)) return { ok: false, reason: `interprets names jobs as j000123 (got ${JSON.stringify(job)})` };
    const rest = bounded("rest", typeof it === "string" ? "" : it?.rest, LEAD_WHY_MAX, false);
    if (!rest.ok) return rest;
    if (!list.some((x) => x.job === job)) list.push({ job, ...(rest.value ? { rest: rest.value } : {}) });
  }
  if (!list.length) return { ok: true, interprets: [] };
  try {
    const r = await transact<Fail | { ok: true }>(sandboxRoot, async (snap) => {
      const e = snap.ledger.bySeq.get(entrySeq);
      if (!e) return { append: [], result: { ok: false as const, reason: `E-${entrySeq} is not in the ledger` } };
      if (e.kind === "answer") return { append: [], result: { ok: false as const, reason: "an answer cites entries, not jobs: interpret a job in the finding, absence or limitation it rests on" } };
      const known = new Map(snap.jobs.map((j) => [j.id, j]));
      for (const x of list) {
        const j = known.get(x.job);
        if (!j) return { append: [], result: { ok: false as const, reason: `${x.job} is not a job of this run` } };
        if (j.state !== "committed") return { append: [], result: { ok: false as const, reason: `${x.job} is ${j.state}: interpret it once it is committed` } };
      }
      return { append: list.map((x) => ({ by: agent, ev: "interpret" as const, job: x.job, entry: entrySeq, kind: e.kind, ...(x.rest ? { rest: x.rest } : {}) })), result: { ok: true as const } };
    });
    return r.ok ? { ok: true, interprets: list.map((x) => x.job) } : r;
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/**
 * A lead closed on an entry that no longer stands (superseded, or disputed)
 * goes back to open: its closure rested on it. Called after every change to
 * the ledger, and before the gate and every header, so a crash between the
 * ledger's change and this cannot leave a closure standing on nothing.
 */
export async function reopenOnLedger(sandboxRoot: string): Promise<string[]> {
  const snap = await leadsSnapshot(sandboxRoot);
  const due = [...snap.state.leads.values()].filter((l) => {
    const m = l.closed ? /^E-(\d+)$/.exec(l.closed.ref) : null;
    return m ? !entryStands(snap.ledger, Number(m[1])).ok : false;
  });
  if (!due.length) return [];
  const r = await transact<{ ok: true }>(sandboxRoot, async (inner) => {
    const append: Array<Omit<LeadEvent, "v" | "seq" | "at" | "prev" | "hash">> = [];
    for (const l of inner.state.leads.values()) {
      const m = l.closed ? /^E-(\d+)$/.exec(l.closed.ref) : null;
      if (!m) continue;
      const st = entryStands(inner.ledger, Number(m[1]));
      if (st.ok) continue;
      append.push({ by: "system", ev: "reopen", lead: l.id, why: `${l.id} was closed ${l.closed!.disposition} on ${l.closed!.ref}, and ${st.why}`, cause: /superseded/.test(st.why) ? "superseded" : "disputed" });
    }
    return { append, result: { ok: true as const } };
  });
  return r.events.map((e) => e.lead!).filter(Boolean);
}

// --- what each agent is told ---------------------------------------------------------------------

/** What an agent was last shown of the leads it holds and the ones they need (inbox/<id>/leads.json). */
type Told = { seq: number; held: Record<string, { status: LeadStatus; unmet: string[]; dead: string[]; stale: boolean; closed?: string; notes: number }>; deps: Record<string, { status: LeadStatus; holder: string | null; disposition?: string }>; wakes: string[] };

function toldPath(sandboxRoot: string, agent: string): string {
  return join(sandboxRoot, "inbox", agent, "leads.json");
}

async function readTold(sandboxRoot: string, agent: string): Promise<Told> {
  try {
    const t = JSON.parse(await readFile(toldPath(sandboxRoot, agent), "utf8")) as Told;
    return { seq: t.seq ?? 0, held: t.held ?? {}, deps: t.deps ?? {}, wakes: t.wakes ?? [] };
  } catch {
    return { seq: 0, held: {}, deps: {}, wakes: [] };
  }
}

function toldNow(agent: string, snap: LeadsSnapshot, previouslyHeld: string[]): Told {
  const { state: s, ledger: v } = snap;
  const held: Told["held"] = {};
  const deps: Told["deps"] = {};
  for (const l of s.leads.values()) {
    // The leads it holds, and the ones it held when last told that nobody
    // holds now (released, reopened): what happens to those is still its news.
    if (l.holder !== agent && !(previouslyHeld.includes(l.id) && l.holder === null)) continue;
    const unmet = l.needs.filter((n) => !needState(n, s, v).met);
    held[l.id] = { status: leadStatus(l, s, v), unmet, dead: unmet.filter((n) => needState(n, s, v).dead), stale: Boolean(l.stale && l.stale.holder === agent), ...(l.closed ? { closed: l.closed.disposition } : {}), notes: l.notes.length };
    for (const n of l.needs) {
      const id = n.split(":")[0];
      const d = s.leads.get(id);
      if (d) deps[id] = { status: leadStatus(d, s, v), holder: d.holder, ...(d.closed ? { disposition: d.closed.disposition } : {}) };
    }
  }
  const wakes = [...s.wakes.entries()].filter(([, to]) => to === agent).map(([k]) => k);
  return { seq: s.events.length, held, deps, wakes };
}

export type LeadNotice = {
  kind: "lead_ready" | "lead_blocked" | "need_dead" | "dependency_changed" | "stale_marked" | "reclaimed" | "reopened" | "operator_note" | "wake" | `question_${import("./questions.ts").QuestionNotice["kind"]}`;
  /** The lead the notice is about, or the question (Q-<n>) for the register's. */
  lead: string;
  text: string;
  wakes: boolean;
};

/** What changed for this agent since it was last told: derived from the state, never stored, so none is lost to a restart. */
export function noticesFor(agent: string, before: Told, snap: LeadsSnapshot): LeadNotice[] {
  const { state: s, ledger: v } = snap;
  const out: LeadNotice[] = [];
  const now = toldNow(agent, snap, Object.keys(before.held));
  for (const [id, was] of Object.entries(before.held)) {
    const l = s.leads.get(id);
    if (!l) continue;
    const cur = now.held[id];
    if (l.holder && l.holder !== agent && !l.closed) {
      const took = [...s.events].reverse().find((e) => e.ev === "claim" && e.lead === id && e.seq > before.seq);
      if (took) out.push({ kind: "reclaimed", lead: id, text: `${id} was taken over by ${l.holder} (generation ${l.generation}) after it showed as stale in your hands: post to ${l.holder} with what you have`, wakes: true });
      continue;
    }
    if (!cur) continue;
    if (was.status === "blocked" && (cur.status === "active" || cur.status === "open")) out.push({ kind: "lead_ready", lead: id, text: `lead_ready: every need of ${id} (${l.title}) is met now; go on with it`, wakes: true });
    if (was.status !== "blocked" && cur.status === "blocked") out.push({ kind: "lead_blocked", lead: id, text: `${id} is blocked again: ${cur.unmet.map((n) => `${n} (${needState(n, s, v).why ?? "unmet"})`).join("; ")}`, wakes: false });
    for (const n of cur.dead) {
      if ((was.dead ?? []).includes(n)) continue;
      out.push({ kind: "need_dead", lead: id, text: `${id}'s need ${n} will not be met as it stands: ${needState(n, s, v).why}. Revise it with lead_link, or find another route`, wakes: true });
    }
    if (cur.stale && !was.stale) out.push({ kind: "stale_marked", lead: id, text: `${id} is marked stale in your hands: a peer found you silent with no job running. Act on it (a post, a job, lead_release) or it will be taken over`, wakes: true });
    if (was.closed && !cur.closed) {
      const r = l.reopened.at(-1);
      out.push({ kind: "reopened", lead: id, text: `${id} was reopened (${r?.cause ?? "?"}): ${r?.why ?? ""}. It is open again; claim it to go on`, wakes: true });
    }
    if (cur.notes > was.notes) {
      for (const n of l.notes.slice(was.notes)) out.push({ kind: "operator_note", lead: id, text: `The operator on ${id}: ${n.text}${n.allow_host ? ` (allowed host for jobs with network=allowlist: ${n.allow_host})` : ""}`, wakes: true });
    }
  }
  for (const [id, cur] of Object.entries(now.deps)) {
    const was = before.deps[id];
    if (!was) continue;
    if (was.status !== cur.status || was.holder !== cur.holder || was.disposition !== cur.disposition) {
      out.push({ kind: "dependency_changed", lead: id, text: `${id}, which your lead needs, is now ${cur.status}${cur.holder ? ` (held by ${cur.holder})` : ""}${cur.disposition ? `, closed ${cur.disposition}` : ""}`, wakes: false });
    }
  }
  for (const w of now.wakes) {
    if (before.wakes.includes(w)) continue;
    const id = w.split("#")[0];
    const l = s.leads.get(id);
    if (l && !l.closed && !l.holder) out.push({ kind: "wake", lead: id, text: `${id} is open, ready and nobody holds it, and you have been idle: "${l.title}". lead_claim ${id} if you can take it`, wakes: true });
  }
  return out;
}

export type LeadsDigest = {
  text: string;
  notices: LeadNotice[];
  counts: { open: number; active: number; blocked: number; closed: number; mine: number; awaiting: number; uncovered: number; questions?: { analyst: number; proposed: number; clarifications: number; triage: number } };
};

function lineOf(x: LeadView): string {
  return `${x.id} "${x.title}"${x.priority ? ` (priority ${x.priority})` : ""}`;
}

/**
 * The header on every inbox and wait delivery, and the notices since the last
 * one. Whole: every lead it lists is named; a list is never cut to fit.
 */
export async function leadsDigest(ctx: P.SwarmContext, o: { mark?: boolean } = {}): Promise<LeadsDigest> {
  await reopenOnLedger(ctx.sandboxRoot).catch(() => undefined);
  // What the question register committed and has not yet published goes out
  // first (a crash between an act and its post is made good here).
  const Q = await import("./questions.ts");
  await Q.deliverPending(ctx.sandboxRoot).catch(() => undefined);
  const snap = await leadsSnapshot(ctx.sandboxRoot);
  const me = ctx.agentId;
  const ranked = rankedLeads(snap);
  const open = ranked.filter((x) => x.status === "open");
  const mine = ranked.filter((x) => x.holder === me && x.status !== "closed");
  const blockedOnMe = ranked.filter((x) => x.status === "blocked" && x.holder !== me && x.needs.some((n) => !n.met && mine.some((m) => m.id === n.need.split(":")[0])));
  const awaiting = (await awaitingInterpretation(ctx.sandboxRoot, snap.state, snap.jobs)).filter((a) => a.agent === me);
  const cov = questionCoverage(snap);
  const before = await readTold(ctx.sandboxRoot, me);
  const notices = noticesFor(me, before, snap);
  // The register's part comes first: a person's question outranks the rest.
  const qTold = await Q.readTold(ctx.sandboxRoot, me);
  const qd = snap.questions ? Q.questionsDigest(me, { questions: snap.questions, leads: snap.state, ledger: snap.ledger }, qTold) : null;
  const lines: string[] = [...(qd?.lines ?? [])];
  const counts = {
    open: open.length,
    active: ranked.filter((x) => x.status === "active").length,
    blocked: ranked.filter((x) => x.status === "blocked").length,
    closed: ranked.filter((x) => x.status === "closed").length,
    mine: mine.length,
    awaiting: awaiting.length,
    uncovered: cov.uncovered.length,
  };
  lines.push(`Leads: ${counts.open} open, ${counts.active} active, ${counts.blocked} blocked, ${counts.closed} closed (leads for the whole register).`);
  for (const n of qd?.notices ?? []) lines.push(`NOTICE ${n.text}`);
  for (const n of notices) lines.push(`NOTICE ${n.text}`);
  lines.push(`Open, unheld, by priority: ${open.length ? open.map(lineOf).join("; ") : "none"}.`);
  lines.push(`Yours: ${mine.length ? mine.map((x) => `${x.id} ${x.status}${x.status === "blocked" ? ` on ${x.needs.filter((n) => !n.met).map((n) => n.need).join(", ")}` : ""}${x.stale ? " (MARKED STALE: act on it)" : ""}`).join("; ") : "none"}.`);
  lines.push(`Blocked on you: ${blockedOnMe.length ? blockedOnMe.map((x) => `${x.id} (${x.holder ?? "unheld"}) needs ${x.needs.filter((n) => !n.met).map((n) => n.need).join(", ")}`).join("; ") : "none"}.`);
  lines.push(`Awaiting your interpretation: ${awaiting.length ? awaiting.map((a) => `${a.job}${a.lead ? ` (${a.lead})` : ""}${a.unread_bytes ? `: ${a.unread_bytes} of ${a.total_bytes} stdout bytes unread, job_status offset ${a.next_offset}` : ""}`).join("; ") : "none"}.`);
  lines.push(`Questions nobody holds a lead for, with no answer yet: ${cov.uncovered.length ? cov.uncovered.map((q) => `question:${q}${cov.open_leads_for[q] ? ` (open: ${cov.open_leads_for[q].join(", ")})` : ""}`).join(", ") : "none"}.`);
  if (o.mark) {
    await writeTold(ctx.sandboxRoot, me, toldNow(me, snap, Object.keys(before.held)));
    if (snap.questions) await Q.markTold(ctx.sandboxRoot, me, snap.questions);
  }
  return { text: lines.join("\n"), notices: [...notices, ...(qd?.notices ?? []).map((n) => ({ kind: `question_${n.kind}` as LeadNotice["kind"], lead: n.q, text: n.text, wakes: n.wakes }))], counts: { ...counts, ...(qd ? { questions: qd.counts } : {}) } };
}

async function writeTold(sandboxRoot: string, agent: string, told: Told): Promise<void> {
  const path = toldPath(sandboxRoot, agent);
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(told)}\n`, "utf8");
  await rename(tmp, path);
}

/** Cheap signature of the files the register's derived views read, so a waiting poll recomputes only when one changed. */
async function filesSignature(sandboxRoot: string): Promise<string> {
  const parts: string[] = [];
  for (const rel of [LEADS_LOG, P.LEDGER_ENTRIES, P.LEDGER_DISPUTES, "store/journal.jsonl", "questions/questions.jsonl"]) {
    const st = await stat(join(sandboxRoot, rel)).catch(() => null);
    parts.push(st ? `${st.size}:${st.mtimeMs}` : "-");
  }
  return parts.join("|");
}

/**
 * The check a waiting agent's wait makes each poll: a notice that wakes it
 * (its lead ready, a need that will not come, its lead marked stale or taken
 * over or reopened, the operator's note, a wake for an open lead), and, when
 * it is the seat idle longest, the wake for a ready lead nobody holds and no
 * seat was woken for (so a wake a crashed hub never wrote is still made).
 * Returns the words that wake it, or null.
 */
export function leadsWaitCheck(ctx: P.SwarmContext): () => Promise<string | null> {
  let sig = "";
  let lastElection = 0;
  return async () => {
    const now = Date.now();
    const next = await filesSignature(ctx.sandboxRoot);
    const due = now - lastElection > 5_000;
    if (next === sig && !due) return null;
    sig = next;
    const snap = await leadsSnapshot(ctx.sandboxRoot);
    const before = await readTold(ctx.sandboxRoot, ctx.agentId);
    const waking = noticesFor(ctx.agentId, before, snap).filter((n) => n.wakes);
    // The question register's news for this seat: an offer, a clarification answered, its question amended or withdrawn.
    const Q = await import("./questions.ts");
    const qWaking = snap.questions ? Q.questionNotices(ctx.agentId, await Q.readTold(ctx.sandboxRoot, ctx.agentId), { questions: snap.questions, leads: snap.state, ledger: snap.ledger }).filter((n) => n.wakes) : [];
    if (waking.length || qWaking.length) return [...qWaking, ...waking].map((n) => n.text).join(" ");
    if (!due) return null;
    lastElection = now;
    // A person's question nobody has taken, past its suggested seat's minute, goes to the most suited idle seat.
    await Q.deliverPending(ctx.sandboxRoot).catch(() => undefined);
    const offered = await Q.electQuestionOffer(ctx, now, snap.questions ? { questions: snap.questions, leads: snap.state, ledger: snap.ledger } : undefined).catch(() => null);
    if (offered) return `${offered.id} is offered to you (you are idle and the most suited): "${offered.text}" (${Q.originWords(offered.origin)}). Take it with lead_open(answers: ["${offered.id}"], take: true, proposition, negation), or say on the board why not; nobody owns it.`;
    const woke = await electWake(ctx, snap);
    return woke ? `${woke} is open, ready and nobody holds it, and you have been idle: lead_claim ${woke} if you can take it (leads ${woke} for the whole of it).` : null;
  };
}

/** One wake per lead and open spell, to the seat idle longest: taken under the lock, so two waits never both take it. */
async function electWake(ctx: P.SwarmContext, outer: LeadsSnapshot): Promise<string | null> {
  const ready = [...outer.state.leads.values()].filter((l) => !l.closed && !l.holder && leadStatus(l, outer.state, outer.ledger) === "open" && !outer.state.wakes.has(`${l.id}#${l.cycle}`));
  if (!ready.length) return null;
  const idle = await idleSeats(ctx.sandboxRoot, outer.state, outer.ledger, outer.jobs);
  if (idle[0]?.agent !== ctx.agentId) return null;
  const r = await transact<{ ok: true; lead: string | null }>(ctx.sandboxRoot, async (snap) => {
    const still = [...snap.state.leads.values()]
      .filter((l) => !l.closed && !l.holder && leadStatus(l, snap.state, snap.ledger) === "open" && !snap.state.wakes.has(`${l.id}#${l.cycle}`))
      .map((l) => viewLead(l, snap))
      .sort((a, b) => b.priority - a.priority || a.opened_at.localeCompare(b.opened_at));
    const pick = still[0];
    if (!pick) return { append: [], result: { ok: true as const, lead: null as string | null } };
    const l = snap.state.leads.get(pick.id)!;
    return { append: [{ by: "system", ev: "wake" as const, lead: l.id, to: ctx.agentId, cycle: l.cycle }], result: { ok: true as const, lead: l.id } };
  }).catch(() => null);
  return r?.lead ?? null;
}

// --- the views an agent asks for ----------------------------------------------------------------

export const LEADS_VIEWS = ["summary", "open", "mine", "blocked", "active", "closed", "all", "jobs", "questions"] as const;

/**
 * The register as an agent reads it: a view (or one lead by id), whole leads
 * a page at a time. `next` names where the next page starts; nothing is cut.
 */
export async function leadsView(ctx: P.SwarmContext, o: { view?: string; from?: string; pageChars?: number } = {}): Promise<Record<string, unknown>> {
  await reopenOnLedger(ctx.sandboxRoot).catch(() => undefined);
  const snap = await leadsSnapshot(ctx.sandboxRoot);
  const view = String(o.view ?? "summary").trim();
  const one = leadRef(view);
  if (one.ok) {
    const l = snap.state.leads.get(one.id);
    if (!l) return { ok: false, reason: `${one.id} does not exist` };
    const history = snap.state.events.filter((e) => e.lead === one.id || (e.job && l.jobs.includes(e.job) && e.ev === "interpret")).map(({ prev: _p, hash: _h, v: _v, ...e }) => e);
    const awaiting = (await awaitingInterpretation(ctx.sandboxRoot, snap.state, snap.jobs)).filter((a) => a.lead === one.id);
    return { ok: true, lead: viewLead(l, snap), history, awaiting_interpretation: awaiting };
  }
  if (!(LEADS_VIEWS as readonly string[]).includes(view)) return { ok: false, reason: `view is one of ${LEADS_VIEWS.join(", ")}, or a lead's id (L-3)` };
  if (view === "summary") {
    const digest = await leadsDigest(ctx, { mark: false });
    return { ok: true, view, summary: digest.text, counts: digest.counts, chain: snap.state.chain.ok ? "intact" : `BROKEN at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})` };
  }
  if (view === "jobs") {
    const awaiting = await awaitingInterpretation(ctx.sandboxRoot, snap.state, snap.jobs);
    return { ok: true, view, awaiting_interpretation: awaiting, note: "A job waits for an interpretation until an entry is recorded with interprets naming it (and, when its stdout was handed over in part, rest saying how the rest was read or why not). A lead's jobs hold the finish line; an agent's others are only shown." };
  }
  if (view === "questions") {
    const cov = questionCoverage(snap);
    // The register beside the goal's list: every question with its origin (a person's first), scope and state.
    const Q = await import("./questions.ts");
    const register = snap.questions
      ? Q.questionViews({ questions: snap.questions, leads: snap.state, ledger: snap.ledger }).map((v) => ({
          id: v.id,
          section: `question:${v.section}`,
          origin: v.origin.kind,
          author: v.author,
          text: v.text,
          rev: v.rev,
          scope: v.scope,
          work: v.work,
          answered: v.answer ? `E-${v.answer.seq}${v.answer.stale ? " (stale)" : ""}` : null,
          leads: v.leads.map((l) => l.id),
          ...(v.withdrawn ? { withdrawn: true } : {}),
        }))
      : [];
    return { ok: true, view, questions: caseQuestions(snap), existence: snap.goal.existence, answered: [...snap.answered].sort(), unanswered: cov.unanswered, uncovered: cov.uncovered, open_leads_for: cov.open_leads_for, source: snap.goal.source, register };
  }
  const ranked = rankedLeads(snap);
  const pick = ranked.filter((x) =>
    view === "all" ? true : view === "mine" ? x.holder === ctx.agentId && x.status !== "closed" : x.status === view,
  );
  const start = o.from ? Math.max(0, pick.findIndex((x) => x.id === o.from)) : 0;
  const pageChars = o.pageChars && o.pageChars > 0 ? o.pageChars : P.inboxPageChars();
  const page: LeadView[] = [];
  let chars = 0;
  for (const x of pick.slice(start)) {
    const size = JSON.stringify(x).length;
    if (page.length && chars + size > pageChars) break;
    page.push(x);
    chars += size;
  }
  const rest = pick.length - start - page.length;
  return { ok: true, view, n: pick.length, leads: page, remaining: rest, ...(rest > 0 ? { next: pick[start + page.length].id, note: `${rest} more lead(s) in this view, held back to keep this page under ${pageChars} characters; nothing was cut. Call leads again with from: "${pick[start + page.length].id}".` } : {}) };
}

// --- the finish line ---------------------------------------------------------------------------

export type LeadDefect = { code: "open_lead" | "uninterpreted_job"; lead?: string; job?: string; what: string; fix: string };

/**
 * What the register holds against a done: a material lead with no
 * disposition (open_lead), and a material lead's job with no interpretation
 * or with output unread and unexplained (uninterpreted_job). An agent's own
 * jobs outside a lead are never a defect.
 */
export async function leadDefects(sandboxRoot: string, snap?: LeadsSnapshot): Promise<{ defects: LeadDefect[]; limiting: Array<{ lead: string; disposition: LeadDisposition; ref: string }>; chain: LeadsState["chain"] }> {
  const s = snap ?? (await leadsSnapshot(sandboxRoot));
  const defects: LeadDefect[] = [];
  for (const l of s.state.leads.values()) {
    if (!l.material || l.closed) continue;
    const st = leadStatus(l, s.state, s.ledger);
    defects.push({
      code: "open_lead",
      lead: l.id,
      what: `${l.id} "${l.title}" is ${st}${l.holder ? ` (held by ${l.holder})` : ""} with no disposition`,
      fix: `close it with lead_close ${l.id}: resolved citing the entry that settles it (E-<seq>), negative citing the absence, duplicate citing the lead it repeats, deferred or infeasible citing the limitation, or needs_operator saying what the operator must do`,
    });
  }
  const awaiting = await awaitingInterpretation(sandboxRoot, s.state, s.jobs);
  for (const a of awaiting) {
    if (!a.lead) continue;
    const l = s.state.leads.get(a.lead);
    if (!l?.material) continue;
    defects.push({
      code: "uninterpreted_job",
      lead: a.lead,
      job: a.job,
      what: `${a.job}, run under ${a.lead}, ${a.why}`,
      fix: a.unread_bytes
        ? `read the rest (job_status ${a.job} offset ${a.next_offset}) and record what it shows with interprets: ["${a.job}"], or record with interprets: [{job: "${a.job}", rest: "how the rest was read, or why not"}]`
        : `record what its output shows (a finding, an absence or a limitation) with interprets: ["${a.job}"]`,
    });
  }
  const limiting = [...s.state.leads.values()]
    .filter((l) => l.material && l.closed && LIMITING_DISPOSITIONS.has(l.closed.disposition))
    .map((l) => ({ lead: l.id, disposition: l.closed!.disposition, ref: l.closed!.ref }));
  return { defects, limiting, chain: s.state.chain };
}

// --- the rendered register ----------------------------------------------------------------------

export function renderLeadsMd(snap: LeadsSnapshot): string {
  const ranked = rankedLeads(snap);
  const lines: string[] = ["# Leads", "", "The swarm's investigative work: what was found to follow, who holds it, what it needs, and how it ended. Rendered by the harness from `leads/leads.jsonl` after every change; do not edit.", ""];
  lines.push(`Chain: ${snap.state.chain.ok ? `intact, ${snap.state.events.length} events` : `BROKEN at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})`}.`, "");
  const groups: Array<[string, LeadView[]]> = [
    ["Active", ranked.filter((x) => x.status === "active")],
    ["Blocked", ranked.filter((x) => x.status === "blocked")],
    ["Open", ranked.filter((x) => x.status === "open")],
    ["Closed", ranked.filter((x) => x.status === "closed")],
  ];
  for (const [name, list] of groups) {
    lines.push(`## ${name} (${list.length})`, "");
    if (!list.length) lines.push("None.", "");
    for (const x of list) {
      lines.push(`### ${x.id}: ${x.title}`, "");
      lines.push(`- Why: ${x.why}`);
      lines.push(`- Origin: ${x.origin}; opened by ${x.opened_by} at ${x.opened_at}${x.material ? "" : "; not material"}`);
      if (x.holder) lines.push(`- Held by ${x.holder}, generation ${x.generation}, since ${x.held_since}${x.stale ? `; MARKED STALE at ${x.stale.at}` : ""}`);
      if (x.needs.length) lines.push(`- Needs: ${x.needs.map((n) => `${n.need} (${n.met ? "met" : `unmet: ${n.why}`})`).join("; ")}`);
      if (x.answers.length) lines.push(`- Answers: ${x.answers.map((a) => `question:${a}`).join(", ")}`);
      if (x.proposition) lines.push(`- Tests: ${x.proposition}; against: ${x.negation ?? ""}`);
      if (x.product) lines.push(`- Directive's product: ${x.product}; accepted when: ${x.acceptance ?? ""}`);
      if (x.priority) lines.push(`- Waiting on it: ${x.waiting_on_it.leads.length} lead(s)${x.waiting_on_it.leads.length ? ` (${x.waiting_on_it.leads.join(", ")})` : ""}, ${x.waiting_on_it.questions.length} unanswered question(s)${x.waiting_on_it.questions.length ? ` (${x.waiting_on_it.questions.map((q) => `question:${q}`).join(", ")})` : ""}`);
      if (x.jobs.length) lines.push(`- Jobs: ${x.jobs.join(", ")}`);
      if (x.disposition) lines.push(`- Closed ${x.disposition} by ${x.closed_by} at ${x.closed_at}: ${x.ref}${x.close_why ? ` (${x.close_why})` : ""}`);
      for (const r of x.reopened) lines.push(`- Reopened at ${r.at} by ${r.by} (${r.cause}): ${r.why}`);
      for (const n of x.notes) lines.push(`- Operator note at ${n.at}: ${n.text}${n.allow_host ? ` (allowed host: ${n.allow_host})` : ""}`);
      lines.push("");
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export async function writeLeadsMd(sandboxRoot: string): Promise<void> {
  const snap = await leadsSnapshot(sandboxRoot);
  await mkdir(join(sandboxRoot, LEADS_DIR), { recursive: true });
  await P.writeFileAtomic(join(sandboxRoot, LEADS_MD), renderLeadsMd(snap));
}

// --- until solved: the regroup ------------------------------------------------------------------

/** The last moment the run moved: a standing entry recorded, a lead closed, a job committed. */
export async function lastProgress(sandboxRoot: string, snap: LeadsSnapshot, startedAt: string): Promise<{ at: number; what: string }> {
  let best = { at: Date.parse(startedAt) || 0, what: "the run's start" };
  const take = (iso: string | undefined, what: string) => {
    const t = iso ? Date.parse(iso) : NaN;
    if (Number.isFinite(t) && t > best.at) best = { at: t, what };
  };
  for (const e of snap.ledger.entries) if (!snap.ledger.replaced.has(e.seq)) take(e.at, `E-${e.seq} (${e.kind})`);
  for (const e of snap.state.events) if (e.ev === "close") take(e.at, `${e.lead} closed ${e.disposition}`);
  for (const j of snap.jobs) if (j.state === "committed") take(j.finished_at, `${j.id} committed`);
  return best;
}

/**
 * The evidence the catalogue knows that no standing entry cites: an input
 * file no ref names (directly, or through a catalogued member of it), and a
 * catalogued object (an archive's members, a disk's volumes) no ref reaches.
 * Generic: the catalogue says what it holds; nothing here reads a format.
 */
export async function uncitedEvidence(sandboxRoot: string, snap: LeadsSnapshot): Promise<string[]> {
  const refs = new Set<string>();
  for (const e of snap.ledger.entries) if (!snap.ledger.replaced.has(e.seq)) for (const r of e.refs ?? []) refs.add(r);
  const gens: Array<{ id: string; ref: string; name: string; what: string }> = [];
  for (const g of await readdir(join(sandboxRoot, "catalog", "gen")).catch(() => [] as string[])) {
    const raw = await readFile(join(sandboxRoot, "catalog", "gen", g, "generation.json"), "utf8").catch(() => null);
    if (!raw) continue;
    try {
      const j = JSON.parse(raw) as { id?: string; target?: { ref?: string; name?: string }; coverage?: { covered?: string; members?: number }; recipe?: string };
      gens.push({ id: j.id ?? g, ref: j.target?.ref ?? "", name: j.target?.name ?? j.target?.ref ?? g, what: [j.coverage?.covered, j.coverage?.members !== undefined ? `${j.coverage.members} listed` : ""].filter(Boolean).join(", ") || (j.recipe ?? "") });
    } catch {
      // skipped
    }
  }
  const cited = (ref: string) => [...refs].some((r) => r === ref || r.startsWith(`${ref}/`));
  const genCited = (g: { id: string; ref: string }) => [...refs].some((r) => r.startsWith(`member:${g.id}#`)) || (g.ref ? cited(g.ref) : false);
  const out: string[] = [];
  const manifest = await P.readInputsManifest(sandboxRoot).catch(() => null);
  for (const f of manifest?.files ?? []) {
    const ref = `input:${f.path.replace(/^inputs\//, "")}`;
    const viaGen = gens.some((g) => g.ref === ref && genCited(g));
    if (!cited(ref) && !viaGen) out.push(`${f.path} (${f.bytes} bytes)`);
  }
  // A catalogued object made from a job's output (an extracted archive, a
  // decrypted volume) that no ref reaches; one made from an input is said
  // with its input above.
  for (const g of gens) if (!genCited(g) && !g.ref.startsWith("input:")) out.push(`catalogue ${g.id}: ${g.name}${g.what ? ` (${g.what})` : ""}`);
  return out;
}

/** How each goal question stands for the regroup: no answer, or an answer that does not settle it. */
export function questionStanding(snap: LeadsSnapshot): Array<{ id: string; why: string; blocks: string[] }> {
  const out: Array<{ id: string; why: string; blocks: string[] }> = [];
  for (const q of snap.goal.questions) {
    const a = snap.ledger.entries.find((e) => e.kind === "answer" && e.section === `question:${q}` && !snap.ledger.replaced.has(e.seq));
    let why = "";
    if (!a) why = "no answer";
    else if (a.inconclusive) why = `answer E-${a.seq} is inconclusive`;
    else if (!(a.support ?? []).length && (a.limitations ?? []).length) why = `answer E-${a.seq} rests on limitations only`;
    else if (snap.goal.existence.length && !snap.goal.existence.includes(q)) {
      const kinds = (a.support ?? []).map((x) => snap.ledger.bySeq.get(x.seq)?.kind);
      if (kinds.length && kinds.every((k) => k === "absence")) why = `answer E-${a.seq} rests on a search that found nothing, and the question asks for more than whether it exists`;
    }
    if (!why) continue;
    const blocks: string[] = [];
    for (const l of snap.state.leads.values()) {
      if (!l.answers.includes(q)) continue;
      const st = leadStatus(l, snap.state, snap.ledger);
      if (st === "closed") {
        if (LIMITING_DISPOSITIONS.has(l.closed!.disposition)) blocks.push(`${l.id} closed ${l.closed!.disposition}: ${l.closed!.ref}`);
        continue;
      }
      blocks.push(`${l.id} ${st}${l.holder ? ` (${l.holder})` : " (nobody holds it)"}${st === "blocked" ? ` on ${l.needs.filter((n) => !needState(n, snap.state, snap.ledger).met).join(", ")}` : ""}`);
    }
    out.push({ id: q, why, blocks });
  }
  return out;
}

/** The regroup post: what is open, what is blocked, what waits on the operator, and what nobody has cited. */
export async function regroupMessage(sandboxRoot: string, snap: LeadsSnapshot, o: { minutes: number; since: { at: number; what: string }; count: number; nextMinutes: number }): Promise<string> {
  const ranked = rankedLeads(snap);
  const qs = questionStanding(snap);
  const open = ranked.filter((v) => v.status === "open");
  const blocked = ranked.filter((v) => v.status === "blocked");
  const operator = ranked.filter((v) => v.disposition === "needs_operator");
  const uncited = await uncitedEvidence(sandboxRoot, snap);
  const lines: string[] = [];
  lines.push(`REGROUP ${o.count}: nothing has moved for ${o.minutes} minutes: no new standing entry, no lead closed and no job committed since ${new Date(o.since.at).toISOString()} (${o.since.what}). This run is until solved, so it goes on until every question is answered; find another route.`);
  lines.push("", `Questions not answered (${qs.length}):`);
  for (const q of qs) lines.push(`- question:${q.id}: ${q.why}${q.blocks.length ? `; ${q.blocks.join("; ")}` : "; no lead names it"}`);
  if (!qs.length) lines.push("- none by the ledger: the finish line says what still holds done (call done, and read its refusal).");
  lines.push("", `Leads open, held by nobody (${open.length}):`);
  for (const v of open) lines.push(`- ${v.id} "${v.title}"${v.priority ? ` (${v.priority} waiting on it)` : ""}`);
  if (!open.length) lines.push("- none");
  lines.push("", `Leads blocked (${blocked.length}):`);
  for (const v of blocked) lines.push(`- ${v.id} "${v.title}"${v.holder ? ` (${v.holder})` : ""} waiting on ${v.needs.filter((n) => !n.met).map((n) => `${n.need}: ${n.why}`).join("; ")}`);
  if (!blocked.length) lines.push("- none");
  lines.push("", `Waiting on the operator (${operator.length}):`);
  for (const v of operator) lines.push(`- ${v.id} "${v.title}": ${v.ref}`);
  if (!operator.length) lines.push("- none");
  lines.push("", `Evidence no standing entry cites (${uncited.length}):`);
  for (const u of uncited) lines.push(`- ${u}`);
  if (!uncited.length) lines.push("- none");
  lines.push(
    "",
    "Each of you: say on the board which route you take next. An artefact above that no entry cites, a lead nobody holds (lead_claim), a need that can be met another way (lead_link), a question with no lead (lead_open), a job whose output nobody read to its end, or what only the operator can give (lead_close needs_operator, saying what). " +
      `If nothing moves, the next regroup comes in ${o.nextMinutes} minutes.`,
  );
  return lines.join("\n");
}
