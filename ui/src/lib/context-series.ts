/**
 * One agent's context window over its run, read from the trace.
 *
 * Kept out of the component so it can be tested without a DOM. The harness
 * writes a `context` row at every turn end and a `compact_*` row for every
 * crossing, hold, note, compaction and failure, so the whole story of an
 * agent's context is on the trace and nowhere else. An old run has none of
 * these rows, and the panel has to say so rather than draw an empty chart.
 */
import type { SwarmEvent } from "./types.ts";

export type ContextPoint = { t: number; tokens: number; level: string; cycle: number };

/** The three lines, in tokens. */
export type ContextThresholds = { notice: number; warning: number; compact: number };

export type Compaction = {
  t: number;
  tokensBefore: number | null;
  tokensAfter: number | null;
  /** self: a hand-off with a note. pi: Pi's own fallback, no note. */
  via: "self" | "pi";
  reason: string;
  cycle: number;
};

export type ContextSeries = {
  points: ContextPoint[];
  /** The ceiling the lines are fractions of; 0 when the trace never said. */
  ceiling: number;
  /** The resolved lines from `compact_config`, or null when the run had none and the defaults apply. */
  thresholds: ContextThresholds | null;
  compactions: Compaction[];
  /** Tool calls refused at the compact line. */
  holds: number;
  /** Notes to self the harness accepted. */
  notes: number;
  failures: number;
};

/** The default lines as fractions of the ceiling, matching extensions/self-compact.ts. */
export const DEFAULT_LINES = { notice: 0.4, warning: 0.5, compact: 0.6 } as const;

export function defaultThresholds(ceiling: number): ContextThresholds {
  return {
    notice: Math.round(ceiling * DEFAULT_LINES.notice),
    warning: Math.round(ceiling * DEFAULT_LINES.warning),
    compact: Math.round(ceiling * DEFAULT_LINES.compact),
  };
}

/** True for every row the self-compaction extension writes, the per-turn context row included. */
export function isContextEvent(e: SwarmEvent): boolean {
  return e.tool === "context" || e.tool.startsWith("compact_");
}

function bag(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export function contextSeries(events: SwarmEvent[], agentId: string): ContextSeries {
  const points: ContextPoint[] = [];
  const compactions: Compaction[] = [];
  let ceiling = 0;
  let thresholds: ContextThresholds | null = null;
  let holds = 0;
  let notes = 0;
  let failures = 0;
  for (const e of events) {
    if (e.agent !== agentId) continue;
    const result = bag(e.result);
    const args = bag(e.args);
    switch (e.tool) {
      case "context": {
        const t = Date.parse(e.ts);
        const tokens = num(result.tokens);
        if (!Number.isFinite(t) || tokens === null) break;
        points.push({ t, tokens, level: str(result.level), cycle: num(result.cycle) ?? 0 });
        // The row carries the ceiling it was measured against, so a run with no
        // compact_config still has one.
        ceiling = num(result.ceiling) ?? ceiling;
        break;
      }
      case "compact_config": {
        if (result.ok === false) break;
        const c = num(result.ceiling);
        if (c !== null) ceiling = c;
        const notice = num(result.notice);
        const warning = num(result.warning);
        const compact = num(result.compact);
        if (notice !== null && warning !== null && compact !== null) thresholds = { notice, warning, compact };
        break;
      }
      case "compact_done": {
        const t = Date.parse(e.ts);
        if (!Number.isFinite(t)) break;
        compactions.push({
          t,
          tokensBefore: num(result.tokens_before),
          tokensAfter: num(result.tokens_after),
          via: args.via === "self" ? "self" : "pi",
          reason: str(args.reason),
          cycle: num(result.cycle) ?? 0,
        });
        break;
      }
      case "compact_hold":
        holds += 1;
        break;
      case "compact_note":
        if (result.ok !== false) notes += 1;
        break;
      case "compact_failed":
        failures += 1;
        break;
    }
  }
  // The trace route can answer newest first; the chart wants time to run left to right.
  points.sort((a, b) => a.t - b.t);
  compactions.sort((a, b) => a.t - b.t);
  // `compact_done` is written before the next model call, when Pi has no
  // measurement of the new context yet, so its `tokens_after` is null on a
  // real run; the first `context` row after the compaction is that measurement.
  for (const c of compactions) {
    if (c.tokensAfter !== null) continue;
    const next = points.find((p) => p.t > c.t);
    if (next) c.tokensAfter = next.tokens;
  }
  return { points, ceiling, thresholds, compactions, holds, notes, failures };
}

/**
 * One entry per thing that happened to the context, for the timeline under
 * the chart. Holds are not moments: twelve refused calls in a row are one
 * count, which the caller reads from `contextSeries`.
 */
export type CompactionMoment =
  | { kind: "crossing"; ts: string; level: "notice" | "warning" | "forced"; tokens: number | null; percent: number | null; cycle: number | null }
  | { kind: "note"; ts: string; ok: boolean; chars: number; reason: string; retry: boolean; tokens: number | null; percent: number | null }
  | { kind: "compaction"; ts: string; via: "self" | "pi"; reason: string; tokensBefore: number | null; tokensAfter: number | null; summaryUsd: number | null; summaryTokens: number | null; cycle: number | null }
  | { kind: "failure"; ts: string; stage: string; reason: string; retrying: boolean; lockReleased: boolean; fallback: string; aborted: boolean };

export function compactionHistory(events: SwarmEvent[], agentId: string): CompactionMoment[] {
  const out: CompactionMoment[] = [];
  for (const e of events) {
    if (e.agent !== agentId) continue;
    const result = bag(e.result);
    const args = bag(e.args);
    switch (e.tool) {
      case "compact_notice":
      case "compact_warning":
      case "compact_forced":
        out.push({
          kind: "crossing",
          ts: e.ts,
          level: e.tool === "compact_notice" ? "notice" : e.tool === "compact_warning" ? "warning" : "forced",
          tokens: num(result.tokens),
          percent: num(result.percent),
          cycle: num(result.cycle),
        });
        break;
      case "compact_note":
        out.push({
          kind: "note",
          ts: e.ts,
          ok: result.ok !== false,
          chars: num(args.chars) ?? 0,
          reason: str(result.reason),
          retry: result.retry === true,
          tokens: num(result.tokens),
          percent: num(result.percent),
        });
        break;
      case "compact_done":
        out.push({
          kind: "compaction",
          ts: e.ts,
          via: args.via === "self" ? "self" : "pi",
          reason: str(args.reason),
          tokensBefore: num(result.tokens_before),
          tokensAfter: num(result.tokens_after),
          summaryUsd: num(result.summary_usd),
          summaryTokens: num(result.summary_tokens),
          cycle: num(result.cycle),
        });
        break;
      case "compact_failed":
        out.push({
          kind: "failure",
          ts: e.ts,
          stage: str(args.stage),
          reason: str(result.reason) || str(args.reason),
          retrying: result.retrying === true,
          lockReleased: result.lock_released === true,
          fallback: str(result.fallback),
          aborted: result.aborted === true,
        });
        break;
    }
  }
  out.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  // The same measurement the series uses: the first context row after a
  // compaction says what the compaction left behind.
  const after = contextSeries(events, agentId).points;
  for (const moment of out) {
    if (moment.kind !== "compaction" || moment.tokensAfter !== null) continue;
    const t = Date.parse(moment.ts);
    const next = after.find((p) => p.t > t);
    if (next) moment.tokensAfter = next.tokens;
  }
  return out;
}
