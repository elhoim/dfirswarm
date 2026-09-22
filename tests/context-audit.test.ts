/**
 * The context audit reads a run's trace and says what each agent's context
 * did: the record of run 5 on the Linux host (three hand-offs, no fallback)
 * is the fixture, and a hand-made trace covers the findings the run did not
 * produce (an overflow fallback, a hold at the line, a slice with no rows).
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { audit, findings, readRows, renderMarkdown } from "../scripts/context-audit.ts";

const REPO = resolve(import.meta.dirname, "..");
const RUN5 = join(REPO, "docs", "use-cases", "dfir-web-server-case", "run-5-self-compact");

test("run 5: the audit reads the record and reports what the run did", () => {
  const { rows, bad, file } = readRows(RUN5);
  assert.equal(bad, 0);
  assert.ok(file.endsWith("trace/events.jsonl"), "a record directory keeps the trace under trace/");
  const run = audit(rows, file, bad);
  assert.equal(run.agents.length, 4);
  const one = run.agents.find((a) => a.agent === "sd8ee01")!;
  assert.equal(one.model, "openai/gpt-5.4-mini");
  assert.equal(one.ceiling, 272_000);
  assert.deepEqual(one.lines, { notice: 108_800, warning: 136_000, compact: 163_200 });
  assert.equal(one.defaults, true);
  assert.equal(one.turns, 140);
  assert.equal(one.peak?.tokens, 168_424);
  assert.deepEqual(one.crossings.map((c) => c.level), ["notice", "warning", "notice", "warning", "forced"]);
  assert.equal(one.compactions.length, 2);
  assert.deepEqual(one.compactions.map((c) => [c.via, c.tokens_before, c.tokens_after]), [["self", 144_349, 35_165], ["self", 168_424, 14_122]], "tokens_after comes from the first context row after each compaction");
  assert.ok(one.compactions.every((c) => c.summary_usd !== null && c.summary_usd > 0));
  const three = run.agents.find((a) => a.agent === "sd8ee03")!;
  assert.equal(three.crossings.length, 0);
  assert.equal(three.compactions.length, 1);
  assert.equal(run.totals.compactions, 3);
  assert.equal(run.totals.hand_offs, 3);
  assert.equal(run.totals.pi_fallbacks, 0);
  assert.ok(run.totals.summary_usd > 0.11 && run.totals.summary_usd < 0.13, String(run.totals.summary_usd));
  assert.ok(run.findings.some((f) => /sd8ee03: handed off below the notice line, at 98,095 tokens/.test(f)), run.findings.join("\n"));
  assert.ok(run.findings.some((f) => /^Summaries: 3 \(3 hand-offs, 0 by Pi's own recovery\)/.test(f)));
  const md = renderMarkdown(run);
  assert.match(md, /^# Context history/);
  assert.match(md, /\| sd8ee01 \| openai\/gpt-5\.4-mini \| 272,000 \| 108,800 \/ 136,000 \/ 163,200 \| 140 \| 168,424 \(61\.9%\) \| notice, warning, forced \| 0 \| 2 \| 0 \| \$0\.08 \|/);
  assert.match(md, /hand-off \(cycle 2\): 168,424 → 14,122 tokens; summary 33,969 tokens \(\$0\.036\)/);
  assert.match(md, /## What the record says/);
});

test("the CLI prints the same audit as Markdown or JSON", () => {
  const md = execFileSync("node", ["--experimental-strip-types", join(REPO, "scripts", "context-audit.ts"), RUN5], { encoding: "utf8" });
  assert.match(md, /^# Context history/);
  const json = JSON.parse(execFileSync("node", ["--experimental-strip-types", join(REPO, "scripts", "context-audit.ts"), RUN5, "--json"], { encoding: "utf8" })) as { totals: { hand_offs: number } };
  assert.equal(json.totals.hand_offs, 3);
});

test("the findings name what the run did not produce: a fallback, a hold, a rejected seat, a quiet run", () => {
  const dir = mkdtempSync(join(tmpdir(), "context-audit-"));
  const file = join(dir, "events.jsonl");
  const row = (agent: string, tool: string, args: Record<string, unknown>, result: Record<string, unknown>, ts: string) => JSON.stringify({ ts, agent, tool, args, result });
  writeFileSync(
    file,
    [
      row("a0", "compact_config", { defaults: true }, { ok: true, model: "x/big", window: 200_000, ceiling: 200_000, notice: 80_000, warning: 100_000, compact: 120_000, summary_model: "x/small", summary_model_source: "compact-model" }, "2026-01-01T00:00:00Z"),
      row("a0", "context", {}, { ok: true, tokens: 50_000, ceiling: 200_000 }, "2026-01-01T00:00:01Z"),
      row("a0", "context", {}, { ok: true, tokens: 140_000, ceiling: 200_000 }, "2026-01-01T00:00:02Z"),
      row("a0", "compact_forced", { level: "forced" }, { ok: true, tokens: 140_000, threshold: 120_000, cycle: 0 }, "2026-01-01T00:00:02Z"),
      row("a0", "compact_hold", { tool: "bash" }, { ok: true, tokens: 140_000 }, "2026-01-01T00:00:03Z"),
      row("a0", "compact_done", { reason: "overflow", via: "pi" }, { ok: true, tokens_before: 205_000, tokens_after: null, summary_tokens: 50_000, summary_usd: 0.5, summary_chars: 9_000, summary_model: "x/small", note_chars: 0, cycle: 0 }, "2026-01-01T00:00:04Z"),
      row("a0", "context", {}, { ok: true, tokens: 70_000, ceiling: 200_000 }, "2026-01-01T00:00:05Z"),
      row("a0", "bash", { command: "cat big" }, { ok: true, output: "x", full_output: { path: "tool-output/a0/x.out.log", bytes: 500_000, lines: 10, sha256: "0" } }, "2026-01-01T00:00:06Z"),
      row("a0", "wait", {}, { reason: "post", n: 3, remaining: 7 }, "2026-01-01T00:00:07Z"),
      row("a1", "compact_config", { defaults: false }, { ok: false, model: "x/big", reason: "the compact threshold 95% is above what the window can hold" }, "2026-01-01T00:00:00Z"),
      row("a1", "context", {}, { ok: true, tokens: 10_000, ceiling: 200_000 }, "2026-01-01T00:00:01Z"),
      "not json at all",
      "",
    ].join("\n"),
  );
  const read = readRows(file);
  assert.equal(read.bad, 1);
  const run = audit(read.rows, file, read.bad);
  const a0 = run.agents.find((a) => a.agent === "a0")!;
  assert.equal(a0.summary_model, "x/small");
  assert.equal(a0.largest_jump?.tokens, 90_000);
  assert.equal(a0.compactions[0]!.tokens_after, 70_000);
  assert.deepEqual(a0.spilled, { calls: 1, bytes: 500_000 });
  assert.equal(a0.pages_held, 1);
  const a1 = run.agents.find((a) => a.agent === "a1")!;
  assert.match(a1.config_error ?? "", /above what the window can hold/);
  const f = run.findings;
  assert.ok(f.some((x) => /a1: the lines were rejected/.test(x)), f.join("\n"));
  assert.ok(f.some((x) => /a0: the provider refused a request at 205,000 tokens and Pi's overflow recovery ran/.test(x)), f.join("\n"));
  assert.ok(f.some((x) => /a0: reached the compact line and was held 1 time before handing off/.test(x)), f.join("\n"));
  assert.ok(f.some((x) => /a0: one turn added 90,000 tokens, more than the room between the compact line and the ceiling/.test(x)), f.join("\n"));
  assert.ok(f.some((x) => /1 tool call produced more than the model received; the whole output, 488\.3 KB, is under tool-output\//.test(x)), f.join("\n"));
  assert.ok(f.some((x) => /1 inbox\/wait delivery held posts back/.test(x)), f.join("\n"));
  assert.ok(renderMarkdown(run).includes(", 1 unreadable)"), "the Markdown says how many lines could not be read");
  // A run with no context rows says it is not measured, nothing else.
  assert.deepEqual(findings([{ ...a1, turns: 0 }], run.totals).slice(0, 1), ["No `context` rows: self-compaction was off for this run, or the run predates the feature; nothing here is measured."]);
  // A quiet run: nobody reached a line.
  const quiet = findings([{ ...a1, config_error: null, turns: 3, peak: { tokens: 20_000, ts: "", percent: 10 } }], { ...run.totals, summary_usd: 0, compactions: 0, spilled_calls: 0, pages_held: 0 });
  assert.ok(quiet.some((x) => /No agent reached the notice line; the highest context was 10\.0% of the ceiling/.test(x)), quiet.join("\n"));
});
