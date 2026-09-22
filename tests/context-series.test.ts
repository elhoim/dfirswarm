import assert from "node:assert/strict";
import { test } from "node:test";
import { compactionHistory, contextSeries, defaultThresholds, isContextEvent } from "../ui/src/lib/context-series.ts";
import type { SwarmEvent } from "../ui/src/lib/types.ts";

const AGENT = "s309602";

function event(tool: string, ts: string, args: Record<string, unknown>, result: unknown, agent = AGENT): SwarmEvent {
  return { ts, agent, tool, args, result } as SwarmEvent;
}

function contextRow(ts: string, tokens: number, level: string, cycle = 0, agent = AGENT): SwarmEvent {
  // extensions/self-compact.ts onTurnEnd: the ceiling rides on every row.
  return event("context", ts, {}, { ok: true, tokens, cached: 0, window: 272_000, ceiling: 272_000, percent: (tokens / 272_000) * 100, level, cycle, locked: level === "forced" }, agent);
}

test("an empty trace is an empty series, with nothing to draw and nothing to count", () => {
  const s = contextSeries([], AGENT);
  assert.deepEqual(s.points, []);
  assert.equal(s.ceiling, 0);
  assert.equal(s.thresholds, null);
  assert.deepEqual(s.compactions, []);
  assert.deepEqual([s.holds, s.notes, s.failures], [0, 0, 0]);
  assert.deepEqual(compactionHistory([], AGENT), []);
});

test("a climbing series with one hand-off: the points, the lines, the drop", () => {
  const trace: SwarmEvent[] = [
    event("agent_start", "2026-09-22T10:00:00.000Z", {}, { ok: true }),
    event("compact_config", "2026-09-22T10:00:00.100Z", { notice_at: "40%", warn_at: "50%", compact_at: "60%", defaults: true }, {
      ok: true,
      model: "openai/gpt-5.4",
      window: 272_000,
      ceiling: 272_000,
      ceiling_reason: "price doubles above it",
      notice: 108_800,
      warning: 136_000,
      compact: 163_200,
      cap: 223_616,
      clamped: false,
      notes: [],
    }),
    contextRow("2026-09-22T10:01:00.000Z", 40_000, "idle"),
    contextRow("2026-09-22T10:05:00.000Z", 120_000, "notice"),
    event("compact_notice", "2026-09-22T10:05:00.001Z", { level: "notice" }, { ok: true, tokens: 120_000, percent: 44.1, ceiling: 272_000, threshold: 108_800, cycle: 0, locked: false }),
    contextRow("2026-09-22T10:09:00.000Z", 170_000, "forced"),
    event("compact_forced", "2026-09-22T10:09:00.001Z", { level: "forced" }, { ok: true, tokens: 170_000, percent: 62.5, ceiling: 272_000, threshold: 163_200, cycle: 0, locked: true }),
    event("compact_hold", "2026-09-22T10:09:10.000Z", { tool: "bash" }, { ok: true, tokens: 170_000, level: "forced", cycle: 0, handoff: "none" }),
    event("compact_hold", "2026-09-22T10:09:12.000Z", { tool: "read" }, { ok: true, tokens: 170_000, level: "forced", cycle: 0, handoff: "none" }),
    event("compact_note", "2026-09-22T10:09:20.000Z", { chars: 1_900 }, { ok: true, tokens: 170_000, percent: 62.5, level: "forced", cycle: 1, retry: false }),
    event("compact_start", "2026-09-22T10:09:21.000Z", { trigger: "self_compact" }, { ok: true, tokens: 170_000, note_chars: 1_900, cycle: 1, attempt: 1 }),
    event("compact_done", "2026-09-22T10:09:40.000Z", { reason: "manual", via: "self" }, {
      ok: true,
      tokens_before: 170_000,
      tokens_after: 31_000,
      summary_chars: 6_200,
      summary_tokens: 4_100,
      summary_usd: 0.0123,
      from_extension: true,
      cycle: 1,
      note_chars: 1_900,
    }),
    contextRow("2026-09-22T10:10:00.000Z", 31_000, "idle", 1),
    // A peer's row on the same trace belongs to the peer.
    contextRow("2026-09-22T10:10:30.000Z", 200_000, "forced", 0, "s309601"),
  ];
  const s = contextSeries(trace, AGENT);
  assert.deepEqual(
    s.points.map((p) => [p.tokens, p.level, p.cycle]),
    [
      [40_000, "idle", 0],
      [120_000, "notice", 0],
      [170_000, "forced", 0],
      [31_000, "idle", 1],
    ],
  );
  assert.equal(s.ceiling, 272_000);
  assert.deepEqual(s.thresholds, { notice: 108_800, warning: 136_000, compact: 163_200 });
  assert.equal(s.compactions.length, 1);
  assert.equal(s.compactions[0].via, "self");
  assert.equal(s.compactions[0].reason, "manual");
  assert.equal(s.compactions[0].tokensBefore, 170_000);
  assert.equal(s.compactions[0].tokensAfter, 31_000);
  assert.equal(s.compactions[0].cycle, 1);
  assert.deepEqual([s.holds, s.notes, s.failures], [2, 1, 0]);

  const history = compactionHistory(trace, AGENT);
  assert.deepEqual(
    history.map((m) => m.kind),
    ["crossing", "crossing", "note", "compaction"],
    "holds and the start row go into the counts rather than the list",
  );
  const forced = history[1];
  assert.equal(forced.kind === "crossing" && forced.level, "forced");
  const done = history[3];
  assert.ok(done.kind === "compaction" && done.summaryUsd === 0.0123 && done.tokensAfter === 31_000);
});

test("the series reads newest-first pages too, and a refused note is a moment of its own", () => {
  const trace: SwarmEvent[] = [
    contextRow("2026-09-22T10:05:00.000Z", 90_000, "idle"),
    event("compact_note", "2026-09-22T10:04:00.000Z", { chars: 0 }, { ok: false, reason: "note_to_self must be 1 to 24000 characters" }),
    contextRow("2026-09-22T10:01:00.000Z", 40_000, "idle"),
    event("compact_failed", "2026-09-22T10:03:00.000Z", { stage: "summary", attempts: 3 }, { ok: false, reason: "summary call timed out", fallback: "pi-summary" }),
  ];
  const s = contextSeries(trace, AGENT);
  assert.deepEqual(s.points.map((p) => p.tokens), [40_000, 90_000], "time runs left to right whatever order the page came in");
  assert.equal(s.notes, 0, "a refused note is not a saved one");
  assert.equal(s.failures, 1);
  const history = compactionHistory(trace, AGENT);
  assert.deepEqual(history.map((m) => m.kind), ["failure", "note"]);
  assert.ok(history[1].kind === "note" && !history[1].ok && history[1].reason.includes("24000"));
  assert.ok(history[0].kind === "failure" && history[0].fallback === "pi-summary" && !history[0].retrying);
});

test("an old run has no context rows, and the defaults are fractions of whatever ceiling the card knows", () => {
  const trace: SwarmEvent[] = [
    event("agent_start", "2026-09-20T18:52:01.869Z", {}, { ok: true }),
    event("post", "2026-09-20T18:53:01.869Z", { thread: "main", body: "hello" }, { ok: true, seq: 1 }),
    event("bash", "2026-09-20T18:54:01.869Z", { command: "ls" }, { ok: true, stdout: "" }),
  ];
  const s = contextSeries(trace, AGENT);
  assert.deepEqual(s.points, []);
  assert.equal(s.ceiling, 0, "nothing on the trace named a ceiling");
  assert.equal(s.thresholds, null);
  assert.deepEqual(compactionHistory(trace, AGENT), []);
  assert.deepEqual(defaultThresholds(272_000), { notice: 108_800, warning: 136_000, compact: 163_200 });
  assert.equal(trace.some(isContextEvent), false);
  assert.equal(isContextEvent(contextRow("2026-09-22T10:01:00.000Z", 1, "idle")), true);
  assert.equal(isContextEvent(event("compact_hold", "2026-09-22T10:01:00.000Z", { tool: "bash" }, { ok: true })), true);
});
