/**
 * What each question cost, in model tokens and dollars (docs/adr/0016, and
 * the metrics of docs/adr/0017, which read the same figures).
 *
 * Nothing in a model call says which question it served: a seat reasons
 * about the board, its lead and its peers' posts in one context. The only
 * attribution the record allows is by what the seat held when the call was
 * made, and this module makes exactly that one, for the report and for
 * `swarm.sh metrics` alike, and says so wherever it is shown:
 *
 * - every model call is taken from the model gateway's log
 *   (traces/model-gateway.jsonl: the seat, the time, the input, output and
 *   cache tokens, the dollars), which every microVM run keeps; a refused
 *   call carried no usage and is not one;
 * - a run without the gateway takes each call from the seats' Pi sessions
 *   (.pi-sessions/<seat>/: each assistant message's and compaction's usage,
 *   with its time);
 * - a run with neither has only each seat's total (budget.json); it is
 *   spread evenly over the seat's tool calls on the trace, which is an
 *   estimate and is called one, and a seat with no trace row to spread it
 *   over keeps its tokens in an explicit no-trace bucket, never dropped;
 * - a call is given to the leads its seat held at that moment (the lead
 *   register: from an open with a holder or a claim, to a release, a
 *   hand-off, a close, a reopen or another seat's claim; a seat claiming a
 *   lead it already holds keeps holding it), split evenly among them, and a
 *   lead's share to the questions it names, split evenly;
 * - a call made while the seat held no lead goes to what the call itself
 *   named, when it named one (the c10 pilot, s6be12f: 12 % of its tokens
 *   were reviews, records and lead acts made holding nothing, counted as
 *   no question's): an attest or a dispute to the question of the entry it
 *   names, a route review, a confirmation or a lead act to its lead, a
 *   record to the questions it answers, a job's status to its lead; the
 *   finish and the report's writing to a line of their own;
 * - a call that named nothing, or with no time, goes to no question: it is
 *   the seat's waiting, compaction, coordination and reading, each shown on
 *   its own line, so the question figures, the leads that name no question,
 *   the finish and those lines add up to the run's total.
 *
 * Pure over what it reads; the figures are fractions until they are shown,
 * and shown rounded so that they still add up to the total (roundParts).
 */
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { LeadEvent } from "../extensions/leads.ts";

/** What a call did, when the record says: the tools it called, with their arguments (a Pi session's reply), or the trace rows it made. */
export type CallTool = { name: string; args?: Record<string, unknown> };

/** One call's tokens and dollars, by seat and time (ms; NaN when the record gives none), and the tools it called when known. */
export type TokenCall = { seat: string; at: number; tokens: number; usd?: number; tools?: CallTool[]; compaction?: boolean };

/** What a call named, resolved to leads and questions (the caller's question keys), or the run's finish. */
export type Named = { leads: string[]; questions: string[]; run: boolean };

/** Where a call made holding no lead and naming nothing went: its kind, from the tools it called. */
export const UNHELD_KINDS = ["waiting", "compaction", "coordination", "reading", "other"] as const;
export type UnheldKind = (typeof UNHELD_KINDS)[number];

const WAITING = new Set(["wait", "inbox"]);
const COORDINATION = new Set(["post", "list_team", "name", "thread_open", "thread_join", "claims", "budget", "claim_file", "release_file", "tools"]);
const READING = new Set(["read", "bash", "grep", "find", "ls", "ledger", "leads", "questions", "inputs", "file_history", "file_diff", "job_status", "requests", "catalog_request"]);

/** The kind of a call that named nothing: waiting, compaction, coordination, reading or other (by its first tool). */
export function unheldKind(c: TokenCall): UnheldKind {
  if (c.compaction || c.tools?.some((t) => t.name === "self_compact")) return "compaction";
  const first = c.tools?.[0]?.name;
  if (!first) return "other";
  if (WAITING.has(first)) return "waiting";
  if (COORDINATION.has(first)) return "coordination";
  if (READING.has(first)) return "reading";
  return "other";
}

/** What a call's tools name, raw: lead ids, question names (Q-n, question:n, n), ledger seqs, job ids, and whether it is the finish's work. */
export type RawNames = { leads: string[]; questions: string[]; entries: number[]; jobs: string[]; run: boolean };

const LEAD_ID_RE = /^L-[1-9]\d*$/;
const Q_ID_RE = /^Q-[1-9]\d*$/i;
const JOB_ID_RE = /^j\d{6,}$/;
/** The tools that act on a lead by its id. */
const LEAD_TOOLS = new Set(["lead_claim", "lead_release", "lead_close", "lead_link", "lead_reopen", "lead_handoff", "lead_confirm", "route_review", "offer", "leads"]);
/** The tools that write a file: the finish's work when the file is the report. */
const WRITE_TOOLS = new Set(["write", "edit", "publish_file", "claim_file", "release_file"]);

/** What one call's tools name. Pure over the arguments; nothing but ids is read from them. */
export function rawNames(tools: readonly CallTool[] | undefined, reportPaths: ReadonlySet<string> = new Set(["work/report.md"])): RawNames {
  const out: RawNames = { leads: [], questions: [], entries: [], jobs: [], run: false };
  const push = <T>(list: T[], v: T) => {
    if (!list.includes(v)) list.push(v);
  };
  const str = (v: unknown) => (typeof v === "string" ? v.trim() : typeof v === "number" ? String(v) : "");
  for (const t of tools ?? []) {
    const a = t.args ?? {};
    const id = str(a.id);
    if (LEAD_TOOLS.has(t.name) && LEAD_ID_RE.test(id)) push(out.leads, id);
    if ((t.name === "offer" || t.name === "questions" || t.name === "question_ask") && Q_ID_RE.test(id)) push(out.questions, id.toUpperCase());
    for (const k of ["lead", "consumer"]) if (LEAD_ID_RE.test(str(a[k]))) push(out.leads, str(a[k]));
    if (Array.isArray(a.answers)) for (const q of a.answers) if (str(q)) push(out.questions, str(q));
    const section = str(a.section);
    if (section.startsWith("question:")) push(out.questions, section);
    if ((t.name === "attest" || t.name === "dispute") && /^\d+$/.test(str(a.seq))) push(out.entries, Number(str(a.seq)));
    if (t.name === "record" && /^\d+$/.test(str(a.supersedes))) push(out.entries, Number(str(a.supersedes)));
    if (t.name === "record" && Array.isArray(a.interprets)) for (const x of a.interprets) {
      const j = typeof x === "string" ? x : str((x as { job?: unknown } | null)?.job);
      if (JOB_ID_RE.test(j)) push(out.jobs, j);
    }
    for (const k of ["job_id", "job"]) if (JOB_ID_RE.test(str(a[k]))) push(out.jobs, str(a[k]));
    if (t.name === "job_status" && JOB_ID_RE.test(id)) push(out.jobs, id);
    if (t.name === "finish") out.run = true;
    if (WRITE_TOOLS.has(t.name) && reportPaths.has(str(a.path).replace(/^\.\//, ""))) out.run = true;
  }
  return out;
}

export type CostSource = "gateway" | "sessions" | "trace" | "none";

export type QuestionCost = {
  source: CostSource;
  /** How the tokens were apportioned, in words, for the report to print whole. */
  method: string;
  total: number;
  totalUsd: number;
  /** By the question's key (what the caller's questionsOf names: a register id, Q-n, or a section). */
  byQuestion: Map<string, number>;
  byQuestionUsd: Map<string, number>;
  /** The leads each question's share came through. */
  byQuestionLeads: Map<string, Set<string>>;
  byLead: Map<string, number>;
  /** Calls made while the seat held no lead and naming nothing, by seat. */
  unheld: Map<string, number>;
  unheldUsd: number;
  /** The same by what the calls were (waiting, compaction, coordination, reading, other). */
  unheldByKind: Map<UnheldKind, number>;
  /** Calls made holding no lead that were given to what they named (a lead, a question): in byQuestion and byLead, and counted here too. */
  named: number;
  /** The finish's and the report's work (a `finish` call, a write of the report) made holding no lead: a line of its own. */
  run: number;
  runUsd: number;
  /** A seat's budget the trace could not place (no trace rows to spread it over): an explicit unattributed bucket, by seat. */
  noTrace: Map<string, number>;
  /** Tokens given to leads that name no question, and those leads. */
  noQuestion: number;
  noQuestionUsd: number;
  noQuestionLeads: Set<string>;
  /**
   * The same in whole tokens as a reader is shown them, rounded so the parts
   * still add up (roundParts): the questions, the leads that name none and
   * the unheld calls to the total; the leads to what the leads were given.
   */
  shown: { total: number; byQuestion: Map<string, number>; byLead: Map<string, number>; unheld: Map<string, number>; unheldByKind: Map<UnheldKind, number>; noTrace: Map<string, number>; noQuestion: number; named: number; run: number };
};

type Interval = { seat: string; from: number; to: number };

/** Who held each lead when, from the register's events. Pure. */
export function holdingIntervals(events: readonly LeadEvent[]): Map<string, Interval[]> {
  const out = new Map<string, Interval[]>();
  const open = new Map<string, { seat: string; from: number }>();
  const end = (lead: string, at: number) => {
    const o = open.get(lead);
    if (!o) return;
    out.set(lead, [...(out.get(lead) ?? []), { seat: o.seat, from: o.from, to: at }]);
    open.delete(lead);
  };
  for (const e of events) {
    if (!e.lead) continue;
    const at = Date.parse(e.at);
    if (!Number.isFinite(at)) continue;
    const ev = e.ev as string;
    if (ev === "open") {
      if (e.holder) open.set(e.lead, { seat: e.holder, from: at });
    } else if (ev === "claim") {
      const holder = e.holder ?? e.by;
      // A seat claiming what it already holds (a reclaim at the next generation) keeps holding it.
      if (open.get(e.lead)?.seat === holder) continue;
      end(e.lead, at);
      open.set(e.lead, { seat: holder, from: at });
    } else if (ev === "release" || ev === "handoff" || ev === "close" || ev === "reopen") end(e.lead, at);
  }
  for (const [lead, o] of open) out.set(lead, [...(out.get(lead) ?? []), { seat: o.seat, from: o.from, to: Number.POSITIVE_INFINITY }]);
  return out;
}

const HOW =
  "each call is given to the leads its seat held when it was made, split evenly among them, and each lead's share to the questions it names, split evenly. A call made while the seat held no lead is given to what it named, split evenly: an attest or a dispute to the question of the entry it names, a route review, a confirmation or another act on a lead to that lead, a record to the questions it answers, a job's status to the job's lead; a finish call or a write of the report goes to the finish's own line. A call that named nothing is given to no question: the seat's waiting, compaction, coordination and reading, each on its own line. The figures are an attribution by holding, not a measure of what each question needed: a seat reasons about everything in its context at once. Shown rounded, the parts still add up to the run's total.";
export const METHOD_GATEWAY = `Each model call the gateway recorded (its input, output and cache tokens, and its dollars): ${HOW}`;
export const METHOD_SESSIONS = `This run has no gateway log: each model call is read from the seats' Pi sessions (each reply's and compaction's usage, with its time), and ${HOW}`;
export const METHOD_TRACE = `This run has no gateway log and no Pi sessions: each seat's total tokens (budget.json) are spread evenly over its tool calls on the trace, an estimate (a seat with no trace row keeps its tokens in a no-trace bucket, counted in the total), and ${HOW}`;
export const METHOD_NONE = "No token record was found (no gateway log, no Pi sessions, and no seat total in budget.json): no cost can be given to a question.";

/**
 * Apportion calls to leads and questions. Pure. `questionsOf` maps a lead to
 * the question keys it names (empty for none); `named` resolves what a call
 * made holding no lead named (null or empty when nothing, and then the call
 * is unheld, by its kind).
 */
export function apportion(calls: readonly TokenCall[], intervals: Map<string, Interval[]>, questionsOf: (lead: string) => string[], source: CostSource, noTrace: Map<string, number> = new Map(), named: (c: TokenCall) => Named | null = () => null): QuestionCost {
  const byQuestion = new Map<string, number>();
  const byQuestionUsd = new Map<string, number>();
  const byQuestionLeads = new Map<string, Set<string>>();
  const byLead = new Map<string, number>();
  const unheld = new Map<string, number>();
  const unheldByKind = new Map<UnheldKind, number>();
  const noQuestionLeads = new Set<string>();
  let unheldUsd = 0;
  let noQuestion = 0;
  let noQuestionUsd = 0;
  let namedTokens = 0;
  let run = 0;
  let runUsd = 0;
  // A seat's budget the trace could not place is the run's too: counted in the total, in its own bucket.
  let total = [...noTrace.values()].reduce((a, b) => a + b, 0);
  let totalUsd = 0;
  const add = <K>(m: Map<K, number>, k: K, v: number) => m.set(k, (m.get(k) ?? 0) + v);
  const bySeat = new Map<string, Array<{ lead: string; from: number; to: number }>>();
  for (const [lead, list] of intervals) for (const i of list) bySeat.set(i.seat, [...(bySeat.get(i.seat) ?? []), { lead, from: i.from, to: i.to }]);
  // A lead's share: to its questions, or to the leads that name none.
  const toLead = (lead: string, share: number, shareUsd: number) => {
    add(byLead, lead, share);
    const qs = [...new Set(questionsOf(lead))];
    if (!qs.length) {
      noQuestion += share;
      noQuestionUsd += shareUsd;
      noQuestionLeads.add(lead);
      return;
    }
    for (const q of qs) {
      add(byQuestion, q, share / qs.length);
      add(byQuestionUsd, q, shareUsd / qs.length);
      byQuestionLeads.set(q, (byQuestionLeads.get(q) ?? new Set<string>()).add(lead));
    }
  };
  for (const c of calls) {
    const usd = c.usd ?? 0;
    total += c.tokens;
    totalUsd += usd;
    const held = [...new Set((bySeat.get(c.seat) ?? []).filter((i) => i.from <= c.at && c.at < i.to).map((i) => i.lead))];
    if (held.length) {
      for (const lead of held) toLead(lead, c.tokens / held.length, usd / held.length);
      continue;
    }
    // Holding nothing: what the call named, split evenly over its leads and its questions.
    const n = named(c);
    const leads = [...new Set(n?.leads ?? [])];
    const questions = [...new Set(n?.questions ?? [])].filter((q) => !leads.some((l) => questionsOf(l).includes(q)));
    const parts = leads.length + questions.length;
    if (parts) {
      namedTokens += c.tokens;
      for (const lead of leads) toLead(lead, c.tokens / parts, usd / parts);
      for (const q of questions) {
        add(byQuestion, q, c.tokens / parts);
        add(byQuestionUsd, q, usd / parts);
      }
      continue;
    }
    if (n?.run) {
      run += c.tokens;
      runUsd += usd;
      continue;
    }
    add(unheld, c.seat, c.tokens);
    add(unheldByKind, unheldKind(c), c.tokens);
    unheldUsd += usd;
  }
  const method = source === "gateway" ? METHOD_GATEWAY : source === "sessions" ? METHOD_SESSIONS : source === "trace" ? METHOD_TRACE : METHOD_NONE;
  // Shown in whole tokens, the parts rounded together so they still make the total (the no-trace bucket included).
  const parts = roundParts<string>([
    ...[...byQuestion].map(([k, v]) => [`q\u0000${k}`, v] as const),
    ...[...unheld].map(([k, v]) => [`u\u0000${k}`, v] as const),
    ...[...noTrace].map(([k, v]) => [`t\u0000${k}`, v] as const),
    ["n", noQuestion] as const,
    ["r", run] as const,
  ]);
  const pick = (prefix: string) => new Map([...parts].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length), v]));
  const shownUnheld = pick("u\u0000");
  const unheldTotal = [...shownUnheld.values()].reduce((a, b) => a + b, 0);
  const shownKinds = roundParts<UnheldKind>(UNHELD_KINDS.filter((k) => unheldByKind.has(k)).map((k) => [k, unheldByKind.get(k)!] as const), 1, unheldTotal);
  const shown = { total: [...parts.values()].reduce((a, b) => a + b, 0), byQuestion: pick("q\u0000"), byLead: roundParts<string>([...byLead]), unheld: shownUnheld, unheldByKind: shownKinds, noTrace: pick("t\u0000"), noQuestion: parts.get("n") ?? 0, named: Math.round(namedTokens), run: parts.get("r") ?? 0 };
  return { source, method, total, totalUsd, byQuestion, byQuestionUsd, byQuestionLeads, byLead, unheld, unheldUsd, unheldByKind, named: namedTokens, run, runUsd, noTrace, noQuestion, noQuestionUsd, noQuestionLeads, shown };
}

/**
 * Round the parts of a total so that they still add up to it (the largest
 * remainder: each part rounded down, and the units left over given one at a
 * time to the parts that lost the most, ties by the parts' order). `step` is
 * the unit (1 for tokens, 0.000001 for dollars); `total`, in units, is the
 * whole to share when the caller has it exactly, else the parts' own sum
 * rounded. Rounded one by one, parts of 1/3 each shown as 0 add up to
 * nothing: the run total would no longer be the sum of its parts. The one
 * rounding the report and the metrics use.
 */
export function roundParts<K>(parts: ReadonlyArray<readonly [K, number]>, step = 1, total?: number): Map<K, number> {
  const units = parts.map(([k, v], i) => ({ k, v: v / step, i }));
  const target = total ?? Math.round(units.reduce((a, x) => a + x.v, 0));
  const floor = units.map((x) => ({ k: x.k, n: Math.floor(x.v + 1e-9), r: x.v - Math.floor(x.v + 1e-9), i: x.i }));
  let left = target - floor.reduce((a, x) => a + x.n, 0);
  const order = [...floor].sort((a, b) => b.r - a.r || a.i - b.i);
  for (let j = 0; left > 0 && order.length; j = (j + 1) % order.length, left -= 1) order[j].n += 1;
  const decimals = step < 1 ? Math.round(-Math.log10(step)) : 0;
  return new Map(floor.map((x) => [x.k, Number((x.n * step).toFixed(decimals))]));
}

/** The gateway's calls: each billed line with its seat, time, tokens and dollars; a refused call carried no usage. */
export function gatewayCalls(text: string): TokenCall[] {
  const out: TokenCall[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let l: { at?: string; seat?: string; input?: number; output?: number; cache_read?: number; cache_write?: number; cost_usd?: number; refused?: string };
    try {
      l = JSON.parse(line) as typeof l;
    } catch {
      continue;
    }
    if (l.refused || !l.seat || l.input === undefined) continue;
    const tokens = (Number(l.input) || 0) + (Number(l.output) || 0) + (Number(l.cache_read) || 0) + (Number(l.cache_write) || 0);
    const usd = Number(l.cost_usd) || 0;
    if (tokens > 0 || usd > 0) out.push({ seat: l.seat, at: Date.parse(String(l.at ?? "")), tokens, usd });
  }
  return out;
}

/** Every .jsonl file under a directory, a few levels deep, in order. */
async function jsonlFiles(dir: string, depth = 5): Promise<string[]> {
  if (depth < 0) return [];
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await jsonlFiles(p, depth - 1)));
    else if (e.isFile() && e.name.endsWith(".jsonl")) out.push(p);
  }
  return out.sort();
}

/** The seats' Pi sessions' calls: each reply's (and compaction's) usage, with its time and cost. */
export async function sessionCalls(sandbox: string): Promise<TokenCall[]> {
  const out: TokenCall[] = [];
  const root = join(resolve(sandbox), ".pi-sessions");
  for (const seat of (await readdir(root).catch(() => [] as string[])).sort()) {
    for (const f of await jsonlFiles(join(root, seat))) {
      const text = await readFile(f, "utf8").catch(() => "");
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        let e: { type?: string; timestamp?: string; message?: { role?: string; usage?: Record<string, unknown>; content?: unknown }; usage?: Record<string, unknown> };
        try {
          e = JSON.parse(line) as typeof e;
        } catch {
          continue;
        }
        const m = e.message;
        const usage = e.type === "message" && m && (m.role === "assistant" || m.role === "toolResult") ? m.usage : e.type === "compaction" || e.type === "branch_summary" ? e.usage : undefined;
        if (!usage) continue;
        const n = (k: string) => Number(usage[k]) || 0;
        const tokens = n("input") + n("output") + n("cacheRead") + n("cacheWrite");
        const cost = usage.cost && typeof usage.cost === "object" ? Number((usage.cost as { total?: unknown }).total) || 0 : 0;
        // The tools the reply called, with their arguments (only ids are read from them), and whether it was a compaction.
        const tools: CallTool[] = [];
        if (m && Array.isArray(m.content)) {
          for (const x of m.content as Array<{ type?: string; name?: string; arguments?: unknown }>) {
            if (x?.type === "toolCall" && typeof x.name === "string") tools.push({ name: x.name, ...(x.arguments && typeof x.arguments === "object" ? { args: x.arguments as Record<string, unknown> } : {}) });
          }
        }
        const compaction = e.type === "compaction" || e.type === "branch_summary";
        if (tokens > 0 || cost > 0) out.push({ seat, at: Date.parse(String(e.timestamp ?? "")), tokens, usd: cost, ...(tools.length ? { tools } : {}), ...(compaction ? { compaction } : {}) });
      }
    }
  }
  return out;
}

/**
 * The tools a gateway's calls made, from the trace: each trace row (a seat's
 * tool call, with its arguments) belongs to that seat's last model call
 * before it. The gateway's log holds no request body; the trace does.
 */
export function attachTraceTools(calls: TokenCall[], traceText: string): void {
  const bySeat = new Map<string, TokenCall[]>();
  for (const c of calls) if (Number.isFinite(c.at)) bySeat.set(c.seat, [...(bySeat.get(c.seat) ?? []), c]);
  for (const list of bySeat.values()) list.sort((a, b) => a.at - b.at);
  for (const line of traceText.split("\n")) {
    if (!line.trim()) continue;
    let r: { ts?: string; agent?: string; tool?: string; args?: unknown };
    try {
      r = JSON.parse(line) as typeof r;
    } catch {
      continue;
    }
    const list = r.agent ? bySeat.get(r.agent) : undefined;
    const at = Date.parse(String(r.ts ?? ""));
    if (!list || !r.tool || !Number.isFinite(at)) continue;
    let lo = 0;
    let hi = list.length - 1;
    let hit = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (list[mid]!.at <= at) {
        hit = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    if (hit < 0) continue;
    const c = list[hit]!;
    c.tools = [...(c.tools ?? []), { name: r.tool, ...(r.args && typeof r.args === "object" ? { args: r.args as Record<string, unknown> } : {}) }];
  }
}

/** Each seat's total spread evenly over its rows on the trace: an estimate for a run with no gateway and no sessions. */
export function traceCalls(traceText: string, totals: Record<string, number>): TokenCall[] {
  const rows = new Map<string, Array<{ at: number; tool?: CallTool }>>();
  for (const line of traceText.split("\n")) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as { ts?: string; agent?: string; tool?: string; args?: unknown };
      const at = Date.parse(String(r.ts ?? ""));
      if (r.agent && Number.isFinite(at) && totals[r.agent] !== undefined) rows.set(r.agent, [...(rows.get(r.agent) ?? []), { at, ...(r.tool ? { tool: { name: r.tool, ...(r.args && typeof r.args === "object" ? { args: r.args as Record<string, unknown> } : {}) } } : {}) }]);
    } catch {
      // a line that does not parse is the trace check's
    }
  }
  const out: TokenCall[] = [];
  for (const [seat, list] of rows) {
    const each = (totals[seat] ?? 0) / list.length;
    if (each > 0) for (const x of list) out.push({ seat, at: x.at, tokens: each, ...(x.tool ? { tools: [x.tool] } : {}) });
  }
  return out;
}

/** The run's calls and where they came from: the gateway, else the Pi sessions, else the seats' totals spread over the trace. */
export async function runCalls(sandbox: string): Promise<{ source: CostSource; calls: TokenCall[]; noTrace: Map<string, number> }> {
  const S = resolve(sandbox);
  const gateway = gatewayCalls(await readFile(join(S, "traces", "model-gateway.jsonl"), "utf8").catch(() => ""));
  if (gateway.length) {
    attachTraceTools(gateway, await readFile(join(S, "traces", "events.jsonl"), "utf8").catch(() => ""));
    return { source: "gateway", calls: gateway, noTrace: new Map() };
  }
  const sessions = await sessionCalls(S);
  if (sessions.length) return { source: "sessions", calls: sessions, noTrace: new Map() };
  const budget = await readFile(join(S, "budget.json"), "utf8").then((t) => JSON.parse(t) as { agents?: Record<string, { tokens?: number }> }).catch(() => null);
  const totals = Object.fromEntries(Object.entries(budget?.agents ?? {}).map(([k, v]) => [k, Number(v?.tokens) || 0]).filter(([, v]) => (v as number) > 0));
  if (Object.keys(totals).length) {
    const calls = traceCalls(await readFile(join(S, "traces", "events.jsonl"), "utf8").catch(() => ""), totals as Record<string, number>);
    // A seat with a budget but no trace rows to spread it over: its tokens
    // are the run's, and go in an explicit bucket, never dropped (docs/adr/0016).
    const spread = new Map<string, number>();
    for (const c of calls) spread.set(c.seat, (spread.get(c.seat) ?? 0) + c.tokens);
    const noTrace = new Map<string, number>();
    for (const [seat, tok] of Object.entries(totals as Record<string, number>)) {
      const placed = spread.get(seat) ?? 0;
      if (tok - placed > 0.5) noTrace.set(seat, tok - placed);
    }
    if (calls.length || noTrace.size) return { source: "trace", calls, noTrace };
  }
  return { source: "none", calls: [], noTrace: new Map() };
}

/**
 * How the caller keys a question it is named by (a register id, Q-n, a
 * section): null for one it does not know. Without it, a call's named
 * questions are not given to any question (its named leads still are).
 */
export type QuestionKeyOf = (raw: string) => string | null;

/** The run's cost by question, apportioned by the leads held, and by what a call made holding none named. */
export async function questionCost(sandbox: string, events: readonly LeadEvent[], questionsOf: (lead: string) => string[], o: { questionKey?: QuestionKeyOf } = {}): Promise<QuestionCost> {
  const { source, calls, noTrace } = await runCalls(sandbox);
  const S = resolve(sandbox);
  // What resolves a name: the ledger's entries (the questions an entry answers), the jobs' leads, the report's path.
  const entries = new Map<number, { section?: string; answers?: string[] }>();
  for (const line of (await readFile(join(S, "ledger", "entries.jsonl"), "utf8").catch(() => "")).split("\n")) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line) as { seq?: number; section?: string; answers?: string[] };
      if (typeof e.seq === "number") entries.set(e.seq, { ...(e.section ? { section: e.section } : {}), ...(Array.isArray(e.answers) ? { answers: e.answers } : {}) });
    } catch {
      // a torn line is the ledger check's
    }
  }
  const jobLead = new Map<string, string>();
  for (const e of events) if ((e.ev as string) === "job" && e.job && e.lead) jobLead.set(e.job, e.lead);
  const reportPaths = new Set<string>(["work/report.md"]);
  for (const line of (await readFile(join(S, "leads", "finish.jsonl"), "utf8").catch(() => "")).split("\n")) {
    try {
      const f = JSON.parse(line) as { ev?: string; report?: string };
      if (f.ev === "lease" && f.report) reportPaths.add(f.report.replace(/^\.\//, ""));
    } catch {
      // not a line
    }
  }
  const key = o.questionKey;
  const named = (c: TokenCall): Named | null => {
    if (!c.tools?.length) return null;
    const raw = rawNames(c.tools, reportPaths);
    const leads = [...raw.leads];
    const questions: string[] = [];
    const addQ = (name: string) => {
      const k = key ? key(name) : null;
      if (k && !questions.includes(k)) questions.push(k);
    };
    for (const q of raw.questions) addQ(q);
    for (const seq of raw.entries) {
      const e = entries.get(seq);
      if (e?.section?.startsWith("question:")) addQ(e.section);
      for (const a of e?.answers ?? []) addQ(a);
    }
    for (const j of raw.jobs) {
      const l = jobLead.get(j);
      if (l && !leads.includes(l)) leads.push(l);
    }
    return { leads, questions, run: raw.run };
  };
  return apportion(calls, holdingIntervals(events), questionsOf, source, noTrace, named);
}

/**
 * Whole shares of fractional values that sum to their rounded total (the
 * largest-remainder method): roundParts, over a plain list. The displayed
 * per-question figures then add up to the displayed run total (docs/adr/0016).
 */
export function conserveRound(values: number[]): number[] {
  return [...roundParts(values.map((v, i) => [i, v] as const)).values()];
}

/** A token figure as a reader is shown it: a whole number with separators. */
export function tokensWords(n: number): string {
  return `${Math.round(n).toLocaleString("en-US")} tokens`;
}
