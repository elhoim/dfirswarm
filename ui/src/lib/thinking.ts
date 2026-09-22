/**
 * Reading a reasoning event, and deciding what its absence means.
 *
 * Kept out of the component so it can be tested without a DOM: the field the
 * text lives in was wrong for the whole life of the THINKING tab, and a test
 * is the only thing that would have said so.
 */
import type { SwarmEvent } from "./types.ts";

/**
 * The text of one reasoning event.
 *
 * The harness writes it as `logEvent(cwd, agent, "thinking", {}, { text,
 * chars })` — empty args, the text in the **result**. The console asked for
 * `args.text`, got nothing, and printed an empty line for every reasoning
 * event in every run. Both shapes are read here so archived traces keep
 * rendering.
 */
export function thinkingText(e: SwarmEvent): string {
  for (const bag of [e.result, e.args] as unknown[]) {
    if (!bag || typeof bag !== "object") continue;
    const r = bag as Record<string, unknown>;
    for (const key of ["text", "thinking", "thought", "reasoning", "content"]) {
      const v = r[key];
      if (typeof v === "string" && v.trim()) return v;
    }
  }
  return "";
}

/** How long the reasoning was, when the stored text is only its opening. */
export function thinkingChars(e: SwarmEvent): number | null {
  const r = e.result as Record<string, unknown> | null;
  const n = r && typeof r === "object" ? r.chars : undefined;
  return typeof n === "number" && Number.isFinite(n) ? n : null;
}

/**
 * True when the harness kept an opening rather than the whole thing.
 *
 * How much it keeps has changed (240 characters once, 2,000 now), so this
 * measures the text in hand instead of trusting a constant that was not in
 * force when the run happened.
 */
export function thinkingTruncated(e: SwarmEvent): boolean {
  const chars = thinkingChars(e);
  return chars !== null && chars > thinkingText(e).length;
}

export type ThinkingCensus = {
  /** Which of the three empty cases this is. */
  verdict: "model-silent" | "agent-silent" | "run-silent";
  /** The agent's model, as the team roster records it. */
  model: string;
  /** Reasoning lines and agent count for that model. */
  mine: { lines: number; agents: number };
  /** Other models that did reason, most talkative first. */
  others: Array<{ model: string; lines: number }>;
  /** Reasoning lines in the whole run. */
  total: number;
};

/**
 * Who else was quiet — the one question an empty THINKING tab has to answer.
 *
 * `counts` is `matched_by_agent` from a `tool=thinking` trace query, which
 * carries the per-agent count over the whole run for the price of one event.
 */
export function thinkingCensus(
  agentId: string,
  team: Array<{ id: string; model?: string }>,
  counts: Record<string, number>,
  fallbackModel = "its model",
): ThinkingCensus {
  const model = team.find((a) => a.id === agentId)?.model || fallbackModel;
  const byModel = new Map<string, { lines: number; agents: number }>();
  for (const member of team) {
    const m = member.model || fallbackModel;
    const row = byModel.get(m) ?? { lines: 0, agents: 0 };
    row.lines += counts[member.id] ?? 0;
    row.agents += 1;
    byModel.set(m, row);
  }
  const mine = byModel.get(model) ?? { lines: 0, agents: 1 };
  const others = [...byModel.entries()]
    .filter(([m, row]) => m !== model && row.lines > 0)
    .map(([m, row]) => ({ model: m, lines: row.lines }))
    .sort((a, b) => b.lines - a.lines);
  const total = [...byModel.values()].reduce((sum, row) => sum + row.lines, 0);
  const verdict = total === 0 ? "run-silent" : mine.lines === 0 ? "model-silent" : "agent-silent";
  return { verdict, model, mine, others, total };
}

/** `azure-foundry/grok-4.6` → `grok-4.6`, which is what a reader says out loud. */
export function shortModel(model: string): string {
  const parts = model.split("/");
  return parts.length > 1 ? parts.slice(1).join("/") : model;
}
