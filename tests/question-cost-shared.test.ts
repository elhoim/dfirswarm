/**
 * One cost method for the report and the metrics (scripts/question-cost.ts;
 * docs/adr/0016 and 0017): a call's tokens go to the leads its seat held
 * then, and a hold ends at a hand-off as at a release. Rounded for a reader,
 * the parts still add up to the run's total, and `swarm.sh metrics` shows the
 * report's own figures.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { measureRun } from "../scripts/metrics.ts";
import { apportion, questionCost, roundParts } from "../scripts/question-cost.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

test("rounded, the parts of a total still add up to it", () => {
  const thirds = roundParts([["a", 100 / 3], ["b", 100 / 3], ["c", 100 / 3]] as const);
  assert.equal([...thirds.values()].reduce((x, y) => x + y, 0), 100, JSON.stringify([...thirds]));
  assert.deepEqual([...thirds.values()].sort(), [33, 33, 34]);
  const dollars = roundParts([["a", 0.01 / 3], ["b", 0.01 / 3], ["c", 0.01 / 3]] as const, 0.0001);
  assert.equal(Number([...dollars.values()].reduce((x, y) => x + y, 0).toFixed(4)), 0.01);
  // Three leads held at once, one call: each question a third, shown so they make the call.
  const iv = new Map([["L-1", [{ seat: "a1", from: 0, to: 100 }]], ["L-2", [{ seat: "a1", from: 0, to: 100 }]], ["L-3", [{ seat: "a1", from: 0, to: 100 }]]]);
  const cost = apportion([{ seat: "a1", at: 50, tokens: 100 }], iv, (lead) => [lead.replace("L", "Q")], "gateway");
  assert.equal([...cost.shown.byQuestion.values()].reduce((x, y) => x + y, 0), 100, "each rounded alone, three thirds would have made 99");
  assert.equal(cost.shown.total, 100);
});

const GOAL = ["## Goal", "", "Examine the mailbox.", "", "### Questions", "", "1. Which message changed the bank details?", "2. Who sent it?", "3. When was it read?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3`', ""].join("\n");

test("the report's cost and the metrics' are one computation: a hand-off ends a hold, and the figures agree and add up", async () => {
  const base = await mkdtemp(join(tmpdir(), "qcost-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "qc1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await Q.seedRegister(S);
  const a0 = { sandboxRoot: S, agentId: "a0" };
  const ids: string[] = [];
  for (const [i, q] of ["1", "2", "3"].entries()) {
    const r = await L.openLead(a0, { title: `Route ${i + 1} through the mailbox`, why: "it bears on the question", answers: [q], take: true });
    assert.ok(r.ok, (r as { reason?: string }).reason);
    ids.push((r as { lead: { id: string } }).lead.id);
  }
  const tick = () => new Promise((r) => setTimeout(r, 15));
  await tick();
  const t1 = new Date().toISOString();
  await tick();
  const h = await L.handoffLead(a0, ids[0], { why: "the rules are a1's now", to: "a1" });
  assert.ok(h.ok, (h as { reason?: string }).reason);
  await tick();
  const t2 = new Date().toISOString();
  // The gateway's calls: a0 while it held all three, a0 after the hand-off (two left), a refused one.
  await mkdir(join(S, "traces"), { recursive: true });
  await writeFile(
    join(S, "traces", "model-gateway.jsonl"),
    [
      { at: t1, seat: "a0", input: 100, output: 0, cache_read: 0, cache_write: 0, cost_usd: 0.01 },
      { at: t2, seat: "a0", input: 90, output: 0, cache_read: 0, cache_write: 0, cost_usd: 0.003 },
      { at: t2, seat: "a1", refused: "run_paused" },
    ]
      .map((l) => JSON.stringify(l))
      .join("\n") + "\n",
  );
  const ls = await L.leadsSnapshot(S);
  const report = await questionCost(S, ls.state.events, (lead) => (ls.state.leads.get(lead)?.answers ?? []).map((a) => `question:${P.sectionKey(a)}`));
  assert.equal(report.source, "gateway");
  assert.equal(report.total, 190, "the refused call carried no usage");
  // After the hand-off a0 held two leads: 45 each, never a third to the lead it gave away.
  assert.ok(Math.abs((report.byQuestion.get("question:1") ?? 0) - 100 / 3) < 1e-9, JSON.stringify([...report.byQuestion]));
  assert.ok(Math.abs((report.byQuestion.get("question:2") ?? 0) - (100 / 3 + 45)) < 1e-9, JSON.stringify([...report.byQuestion]));
  const shown = report.shown;
  assert.equal([...shown.byQuestion.values()].reduce((a, b) => a + b, 0) + shown.noQuestion + [...shown.unheld.values()].reduce((a, b) => a + b, 0), shown.total);
  assert.equal(shown.total, 190);
  const m = await measureRun(S);
  assert.equal(m.cost.source, "model-gateway");
  assert.equal(m.cost.tokens, shown.total);
  for (const q of m.cost.per_question) assert.equal(q.tokens, shown.byQuestion.get(`question:${q.section}`), `${q.section}: the metrics show the report's figure`);
  assert.equal(m.cost.per_question.reduce((a, q) => a + q.tokens, 0) + m.cost.unheld.tokens + m.cost.leads_without_question.tokens, m.cost.tokens, "the metrics' parts add up to their total");
  assert.equal(Number((m.cost.per_question.reduce((a, q) => a + q.usd, 0) + m.cost.unheld.usd + m.cost.leads_without_question.usd).toFixed(4)), m.cost.usd, "and the dollars too");
  assert.equal(m.cost.usd, 0.013);
});
