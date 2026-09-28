/**
 * What each question cost, in model tokens (docs/adr/0016).
 *
 * Nothing in a model call says which question it served: a seat reasons
 * about the board, its lead and its peers' posts in one context. The only
 * attribution the record allows is by what the seat held when the call was
 * made, and this module makes exactly that one, and says so wherever it is
 * shown:
 *
 * - every model call is taken from the model gateway's log
 *   (traces/model-gateway.jsonl: the seat, the time, the input, output and
 *   cache tokens), which every microVM run keeps;
 * - a run without the gateway (a host run) has only each seat's total
 *   (budget.json); it is spread evenly over the seat's tool calls on the
 *   trace, which is an estimate and is called one;
 * - a call is given to the leads its seat held at that moment (the lead
 *   register: from an open with a holder or a claim, to a release, a close,
 *   a reopen or another seat's claim), split evenly among them, and a lead's
 *   share to the questions it names, split evenly;
 * - a call made while the seat held no lead goes to no question: it is the
 *   seat's coordination, reading and board work, shown on its own line, so
 *   the question figures and that line add up to the run's total.
 *
 * Pure over what it reads; the figures are fractions until they are shown.
 */
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { LeadEvent } from "../extensions/leads.ts";

/** One call's tokens, by seat and time (ms). */
export type TokenCall = { seat: string; at: number; tokens: number };

export type CostSource = "gateway" | "trace" | "none";

export type QuestionCost = {
  source: CostSource;
  /** How the tokens were apportioned, in words, for the report to print whole. */
  method: string;
  total: number;
  /** By the question's key (a register id, Q-n, or the section a lead names when the register has no question for it). */
  byQuestion: Map<string, number>;
  byLead: Map<string, number>;
  /** Calls made while the seat held no lead, by seat. */
  unheld: Map<string, number>;
  /** Tokens given to leads that name no question. */
  noQuestion: number;
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
    if (e.ev === "open") {
      if (e.holder) open.set(e.lead, { seat: e.holder, from: at });
    } else if (e.ev === "claim") {
      end(e.lead, at);
      open.set(e.lead, { seat: e.holder ?? e.by, from: at });
    } else if (e.ev === "release" || e.ev === "close" || e.ev === "reopen") end(e.lead, at);
  }
  for (const [lead, o] of open) out.set(lead, [...(out.get(lead) ?? []), { seat: o.seat, from: o.from, to: Number.POSITIVE_INFINITY }]);
  return out;
}

export const METHOD_GATEWAY =
  "Each model call the gateway recorded (its input, output and cache tokens) is given to the leads its seat held when the call was made, split evenly among them, and each lead's share to the questions it names, split evenly. A call made while the seat held no lead is given to no question: it is the seat's reading, coordination and board work, on its own line. The figures are an attribution by holding, not a measure of what each question needed: a seat reasons about everything in its context at once.";
export const METHOD_TRACE =
  "This run has no gateway log (a host run): each seat's total tokens (budget.json) are spread evenly over its tool calls on the trace, an estimate, and each call is then given to the leads its seat held at that moment, split evenly, and each lead's share to the questions it names, split evenly. A call made while the seat held no lead is given to no question.";
export const METHOD_NONE = "No token record was found (no gateway log, and no seat total with calls on the trace): no cost can be given to a question.";

/**
 * Apportion calls to leads and questions. Pure. `questionsOf` maps a lead to
 * the question keys it names (empty for none).
 */
export function apportion(calls: readonly TokenCall[], intervals: Map<string, Interval[]>, questionsOf: (lead: string) => string[], source: CostSource): QuestionCost {
  const byQuestion = new Map<string, number>();
  const byLead = new Map<string, number>();
  const unheld = new Map<string, number>();
  let noQuestion = 0;
  let total = 0;
  const bySeat = new Map<string, Array<{ lead: string; from: number; to: number }>>();
  for (const [lead, list] of intervals) for (const i of list) bySeat.set(i.seat, [...(bySeat.get(i.seat) ?? []), { lead, from: i.from, to: i.to }]);
  for (const c of calls) {
    total += c.tokens;
    const held = [...new Set((bySeat.get(c.seat) ?? []).filter((i) => i.from <= c.at && c.at < i.to).map((i) => i.lead))];
    if (!held.length) {
      unheld.set(c.seat, (unheld.get(c.seat) ?? 0) + c.tokens);
      continue;
    }
    const share = c.tokens / held.length;
    for (const lead of held) {
      byLead.set(lead, (byLead.get(lead) ?? 0) + share);
      const qs = [...new Set(questionsOf(lead))];
      if (!qs.length) {
        noQuestion += share;
        continue;
      }
      for (const q of qs) byQuestion.set(q, (byQuestion.get(q) ?? 0) + share / qs.length);
    }
  }
  return { source, method: source === "gateway" ? METHOD_GATEWAY : source === "trace" ? METHOD_TRACE : METHOD_NONE, total, byQuestion, byLead, unheld, noQuestion };
}

/** The gateway's calls: each billed line with its seat, time and tokens. */
export function gatewayCalls(text: string): TokenCall[] {
  const out: TokenCall[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let l: { at?: string; seat?: string; input?: number; output?: number; cache_read?: number; cache_write?: number; refused?: string };
    try {
      l = JSON.parse(line) as typeof l;
    } catch {
      continue;
    }
    if (l.refused || !l.seat || !l.at) continue;
    const tokens = (Number(l.input) || 0) + (Number(l.output) || 0) + (Number(l.cache_read) || 0) + (Number(l.cache_write) || 0);
    const at = Date.parse(l.at);
    if (tokens > 0 && Number.isFinite(at)) out.push({ seat: l.seat, at, tokens });
  }
  return out;
}

/** Each seat's total spread evenly over its rows on the trace: an estimate for a run with no gateway. */
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

/**
 * The run's cost by question: the gateway's calls when the run kept them,
 * else the seats' totals spread over the trace, apportioned by the leads held.
 */
export async function questionCost(sandbox: string, events: readonly LeadEvent[], questionsOf: (lead: string) => string[]): Promise<QuestionCost> {
  const S = resolve(sandbox);
  const gateway = await readFile(join(S, "traces", "model-gateway.jsonl"), "utf8").catch(() => "");
  let calls = gatewayCalls(gateway);
  let source: CostSource = calls.length ? "gateway" : "none";
  if (!calls.length) {
    const budget = await readFile(join(S, "budget.json"), "utf8").then((t) => JSON.parse(t) as { agents?: Record<string, { tokens?: number }> }).catch(() => null);
    const totals = Object.fromEntries(Object.entries(budget?.agents ?? {}).map(([k, v]) => [k, Number(v?.tokens) || 0]).filter(([, v]) => (v as number) > 0));
    if (Object.keys(totals).length) {
      calls = traceCalls(await readFile(join(S, "traces", "events.jsonl"), "utf8").catch(() => ""), totals as Record<string, number>);
      if (calls.length) source = "trace";
    }
  }
  return apportion(calls, holdingIntervals(events), questionsOf, source);
}

/** A token figure as a reader is shown it: a whole number with separators. */
export function tokensWords(n: number): string {
  return `${Math.round(n).toLocaleString("en-US")} tokens`;
}
