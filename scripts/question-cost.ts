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
 *   estimate and is called one;
 * - a call is given to the leads its seat held at that moment (the lead
 *   register: from an open with a holder or a claim, to a release, a
 *   hand-off, a close, a reopen or another seat's claim; a seat claiming a
 *   lead it already holds keeps holding it), split evenly among them, and a
 *   lead's share to the questions it names, split evenly;
 * - a call made while the seat held no lead, or with no time, goes to no
 *   question: it is the seat's coordination, reading and board work, shown
 *   on its own line, so the question figures, the leads that name no
 *   question and that line add up to the run's total.
 *
 * Pure over what it reads; the figures are fractions until they are shown,
 * and shown rounded so that they still add up to the total (roundParts).
 */
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { LeadEvent } from "../extensions/leads.ts";

/** One call's tokens and dollars, by seat and time (ms; NaN when the record gives none). */
export type TokenCall = { seat: string; at: number; tokens: number; usd?: number };

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
  /** Calls made while the seat held no lead, by seat. */
  unheld: Map<string, number>;
  unheldUsd: number;
  /** Tokens given to leads that name no question, and those leads. */
  noQuestion: number;
  noQuestionUsd: number;
  noQuestionLeads: Set<string>;
  /**
   * The same in whole tokens as a reader is shown them, rounded so the parts
   * still add up (roundParts): the questions, the leads that name none and
   * the unheld calls to the total; the leads to what the leads were given.
   */
  shown: { total: number; byQuestion: Map<string, number>; byLead: Map<string, number>; unheld: Map<string, number>; noQuestion: number };
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
  "each call is given to the leads its seat held when it was made, split evenly among them, and each lead's share to the questions it names, split evenly. A call made while the seat held no lead is given to no question: it is the seat's reading, coordination and board work, on its own line. The figures are an attribution by holding, not a measure of what each question needed: a seat reasons about everything in its context at once. Shown rounded, the parts still add up to the run's total.";
export const METHOD_GATEWAY = `Each model call the gateway recorded (its input, output and cache tokens, and its dollars): ${HOW}`;
export const METHOD_SESSIONS = `This run has no gateway log: each model call is read from the seats' Pi sessions (each reply's and compaction's usage, with its time), and ${HOW}`;
export const METHOD_TRACE = `This run has no gateway log and no Pi sessions: each seat's total tokens (budget.json) are spread evenly over its tool calls on the trace, an estimate, and ${HOW}`;
export const METHOD_NONE = "No token record was found (no gateway log, no Pi sessions, and no seat total with calls on the trace): no cost can be given to a question.";

/**
 * Apportion calls to leads and questions. Pure. `questionsOf` maps a lead to
 * the question keys it names (empty for none).
 */
export function apportion(calls: readonly TokenCall[], intervals: Map<string, Interval[]>, questionsOf: (lead: string) => string[], source: CostSource): QuestionCost {
  const byQuestion = new Map<string, number>();
  const byQuestionUsd = new Map<string, number>();
  const byQuestionLeads = new Map<string, Set<string>>();
  const byLead = new Map<string, number>();
  const unheld = new Map<string, number>();
  const noQuestionLeads = new Set<string>();
  let unheldUsd = 0;
  let noQuestion = 0;
  let noQuestionUsd = 0;
  let total = 0;
  let totalUsd = 0;
  const add = (m: Map<string, number>, k: string, v: number) => m.set(k, (m.get(k) ?? 0) + v);
  const bySeat = new Map<string, Array<{ lead: string; from: number; to: number }>>();
  for (const [lead, list] of intervals) for (const i of list) bySeat.set(i.seat, [...(bySeat.get(i.seat) ?? []), { lead, from: i.from, to: i.to }]);
  for (const c of calls) {
    const usd = c.usd ?? 0;
    total += c.tokens;
    totalUsd += usd;
    const held = [...new Set((bySeat.get(c.seat) ?? []).filter((i) => i.from <= c.at && c.at < i.to).map((i) => i.lead))];
    if (!held.length) {
      add(unheld, c.seat, c.tokens);
      unheldUsd += usd;
      continue;
    }
    const share = c.tokens / held.length;
    const shareUsd = usd / held.length;
    for (const lead of held) {
      add(byLead, lead, share);
      const qs = [...new Set(questionsOf(lead))];
      if (!qs.length) {
        noQuestion += share;
        noQuestionUsd += shareUsd;
        noQuestionLeads.add(lead);
        continue;
      }
      for (const q of qs) {
        add(byQuestion, q, share / qs.length);
        add(byQuestionUsd, q, shareUsd / qs.length);
        byQuestionLeads.set(q, (byQuestionLeads.get(q) ?? new Set<string>()).add(lead));
      }
    }
  }
  const method = source === "gateway" ? METHOD_GATEWAY : source === "sessions" ? METHOD_SESSIONS : source === "trace" ? METHOD_TRACE : METHOD_NONE;
  // Shown in whole tokens, the parts rounded together so they still make the total.
  const parts = roundParts<string>([...[...byQuestion].map(([k, v]) => [`q\u0000${k}`, v] as const), ...[...unheld].map(([k, v]) => [`u\u0000${k}`, v] as const), ["n", noQuestion] as const]);
  const pick = (prefix: string) => new Map([...parts].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length), v]));
  const shown = { total: [...parts.values()].reduce((a, b) => a + b, 0), byQuestion: pick("q\u0000"), byLead: roundParts<string>([...byLead]), unheld: pick("u\u0000"), noQuestion: parts.get("n") ?? 0 };
  return { source, method, total, totalUsd, byQuestion, byQuestionUsd, byQuestionLeads, byLead, unheld, unheldUsd, noQuestion, noQuestionUsd, noQuestionLeads, shown };
}

/**
 * Round the parts of a total so that they still add up to it (the largest
 * remainder: each part rounded down, and the units left over given to the
 * parts that lost the most). `step` is the unit (1 for tokens, 0.0001 for
 * dollars). Rounded one by one, parts of 1/3 each shown as 0 add up to
 * nothing: the run total would no longer be the sum of its parts.
 */
export function roundParts<K>(parts: ReadonlyArray<readonly [K, number]>, step = 1): Map<K, number> {
  const units = parts.map(([k, v]) => ({ k, v: v / step }));
  const target = Math.round(units.reduce((a, x) => a + x.v, 0));
  const floor = units.map((x) => ({ k: x.k, n: Math.floor(x.v + 1e-9), r: x.v - Math.floor(x.v + 1e-9) }));
  let left = target - floor.reduce((a, x) => a + x.n, 0);
  for (const x of [...floor].sort((a, b) => b.r - a.r)) {
    if (left <= 0) break;
    x.n += 1;
    left -= 1;
  }
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
        let e: { type?: string; timestamp?: string; message?: { role?: string; usage?: Record<string, unknown> }; usage?: Record<string, unknown> };
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
        if (tokens > 0 || cost > 0) out.push({ seat, at: Date.parse(String(e.timestamp ?? "")), tokens, usd: cost });
      }
    }
  }
  return out;
}

/** Each seat's total spread evenly over its rows on the trace: an estimate for a run with no gateway and no sessions. */
export function traceCalls(traceText: string, totals: Record<string, number>): TokenCall[] {
  const rows = new Map<string, number[]>();
  for (const line of traceText.split("\n")) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as { ts?: string; agent?: string };
      const at = Date.parse(String(r.ts ?? ""));
      if (r.agent && Number.isFinite(at) && totals[r.agent] !== undefined) rows.set(r.agent, [...(rows.get(r.agent) ?? []), at]);
    } catch {
      // a line that does not parse is the trace check's
    }
  }
  const out: TokenCall[] = [];
  for (const [seat, times] of rows) {
    const each = (totals[seat] ?? 0) / times.length;
    if (each > 0) for (const at of times) out.push({ seat, at, tokens: each });
  }
  return out;
}

/** The run's calls and where they came from: the gateway, else the Pi sessions, else the seats' totals spread over the trace. */
export async function runCalls(sandbox: string): Promise<{ source: CostSource; calls: TokenCall[] }> {
  const S = resolve(sandbox);
  const gateway = gatewayCalls(await readFile(join(S, "traces", "model-gateway.jsonl"), "utf8").catch(() => ""));
  if (gateway.length) return { source: "gateway", calls: gateway };
  const sessions = await sessionCalls(S);
  if (sessions.length) return { source: "sessions", calls: sessions };
  const budget = await readFile(join(S, "budget.json"), "utf8").then((t) => JSON.parse(t) as { agents?: Record<string, { tokens?: number }> }).catch(() => null);
  const totals = Object.fromEntries(Object.entries(budget?.agents ?? {}).map(([k, v]) => [k, Number(v?.tokens) || 0]).filter(([, v]) => (v as number) > 0));
  if (Object.keys(totals).length) {
    const calls = traceCalls(await readFile(join(S, "traces", "events.jsonl"), "utf8").catch(() => ""), totals as Record<string, number>);
    if (calls.length) return { source: "trace", calls };
  }
  return { source: "none", calls: [] };
}

/** The run's cost by question, apportioned by the leads held. */
export async function questionCost(sandbox: string, events: readonly LeadEvent[], questionsOf: (lead: string) => string[]): Promise<QuestionCost> {
  const { source, calls } = await runCalls(sandbox);
  return apportion(calls, holdingIntervals(events), questionsOf, source);
}

/** A token figure as a reader is shown it: a whole number with separators. */
export function tokensWords(n: number): string {
  return `${Math.round(n).toLocaleString("en-US")} tokens`;
}
