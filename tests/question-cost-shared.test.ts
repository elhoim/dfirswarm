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

test("a host run's seat with a budget and no trace row: its tokens are in the no-trace bucket, in the report's total and in the metrics' parts", async () => {
  const base = await mkdtemp(join(tmpdir(), "qcost-host-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "qc2", agentIds: ["a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await mkdir(join(S, "traces"), { recursive: true });
  const budget = JSON.parse(await (await import("node:fs/promises")).readFile(join(S, "budget.json"), "utf8"));
  budget.agents = { ...(budget.agents ?? {}), a1: { ...(budget.agents?.a1 ?? {}), tokens: 1001 }, a2: { ...(budget.agents?.a2 ?? {}), tokens: 900 } };
  await writeFile(join(S, "budget.json"), JSON.stringify(budget));
  await writeFile(join(S, "traces", "events.jsonl"), [{ ts: "2026-01-01T00:00:01Z", agent: "a1" }, { ts: "2026-01-01T00:00:02Z", agent: "a1" }, { ts: "2026-01-01T00:00:03Z", agent: "a1" }].map((r) => JSON.stringify(r)).join("\n") + "\n");
  const report = await questionCost(S, [], () => []);
  assert.equal(report.source, "trace");
  assert.ok(Math.abs(report.total - 1901) < 1e-6, "exact until shown");
  assert.equal(report.shown.total, 1901);
  assert.deepEqual(Object.fromEntries(report.shown.noTrace), { a2: 900 });
  const m = await measureRun(S);
  assert.equal(m.cost.source, "trace-estimate");
  assert.equal(m.cost.tokens, 1901);
  assert.deepEqual(m.cost.no_trace, { tokens: 900, seats: ["a2"] });
  assert.equal(m.cost.per_question.reduce((a, q) => a + q.tokens, 0) + m.cost.unheld.tokens + m.cost.leads_without_question.tokens + m.cost.no_trace.tokens, m.cost.tokens, "every part, the no-trace bucket too, adds up to the total");
});

test("a call made holding no lead is given to what it named: an attest to its entry's question, a route review to its lead, a record to its questions, a job's status to its lead; the finish to its own line; the rest by kind (the c10 pilot)", async () => {
  const base = await mkdtemp(join(tmpdir(), "qcost-named-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "qc3", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await Q.seedRegister(S);
  const a0 = { sandboxRoot: S, agentId: "a0" };
  // L-1 under question 1 (held by a0), L-2 under question 2, closed; a finding answering question 3; a job under L-1.
  const l1 = await L.openLead(a0, { title: "Read the rules", why: "q1", answers: ["1"], take: true });
  assert.ok(l1.ok);
  const l2 = await L.openLead(a0, { title: "Trace the sender", why: "q2", answers: ["2"] });
  assert.ok(l2.ok);
  const f = await P.recordEntry(a0, { kind: "finding", basis: "observed", confidence: "high", indicates: "shows it", confidence_why: "direct", value: "Read at ten", source: "the store", evidence: "flag", answers: ["3"] } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  assert.ok((await L.attachJob(S, "a0", "j000001", "L-1")).ok);
  assert.ok((await L.releaseLead(a0, "L-1", { why: "done with it" })).ok);
  const later = Date.now() + 60_000;
  // a1 holds nothing all along; a0 holds nothing after its release.
  const at = (s: number) => new Date(later + s * 1000).toISOString();
  const line = (seat: string, s: number, name: string, args: Record<string, unknown>, usage = 100) => JSON.stringify({ type: "message", timestamp: at(s), message: { role: "assistant", usage: { input: usage, output: 0, cacheRead: 0, cacheWrite: 0, cost: { total: 0 } }, content: [{ type: "toolCall", name, arguments: args }] } });
  await mkdir(join(S, ".pi-sessions", "a1"), { recursive: true });
  await writeFile(join(S, ".pi-sessions", "a1", "s.jsonl"), [
    line("a1", 1, "attest", { seq: f.entry.seq, how: "re-derived it" }),
    line("a1", 2, "route_review", { id: "L-2", material: false, why: "answered" }),
    line("a1", 3, "record", { kind: "answer", section: "question:2", value: "x" }),
    line("a1", 4, "job_status", { job_id: "j000001" }),
    line("a1", 5, "finish", { action: "status" }),
    line("a1", 6, "write", { path: "work/report.md", content: "x" }),
    line("a1", 7, "wait", { seconds: 60 }),
    line("a1", 8, "post", { body: "hello" }),
    line("a1", 9, "bash", { command: "ls" }),
    JSON.stringify({ type: "compaction", timestamp: at(10), usage: { input: 100, output: 0, cacheRead: 0, cacheWrite: 0 } }),
  ].join("\n") + "\n");
  const ls = await L.leadsSnapshot(S);
  const cost = await questionCost(S, ls.state.events, (lead) => (ls.state.leads.get(lead)?.answers ?? []).map((a) => `question:${P.sectionKey(a)}`), { questionKey: (raw) => `question:${P.sectionKey(raw.replace(/^question:/, ""))}` });
  assert.equal(cost.source, "sessions");
  // attest -> question 3 (its entry's), route review -> L-2 -> question 2, record -> question 2, job status -> L-1 -> question 1.
  assert.deepEqual([...cost.shown.byQuestion].sort(), [["question:1", 100], ["question:2", 200], ["question:3", 100]]);
  assert.equal(cost.shown.named, 400);
  assert.equal(cost.shown.run, 200, "the finish and the report's writing, on their own line");
  assert.deepEqual([...cost.shown.unheldByKind], [["waiting", 100], ["compaction", 100], ["coordination", 100], ["reading", 100]]);
  assert.equal(cost.shown.total, 1000, "the parts still add up");
  assert.equal([...cost.shown.byQuestion.values()].reduce((a, b) => a + b, 0) + cost.shown.noQuestion + cost.shown.run + [...cost.shown.unheld.values()].reduce((a, b) => a + b, 0), 1000);
});

test("a gateway's calls are told what they did by the trace: each tool row belongs to its seat's last call before it", async () => {
  const { attachTraceTools } = await import("../scripts/question-cost.ts");
  const calls = [{ seat: "a1", at: 1000, tokens: 10 }, { seat: "a1", at: 2000, tokens: 10 }, { seat: "a2", at: 1500, tokens: 10 }] as Array<{ seat: string; at: number; tokens: number; tools?: Array<{ name: string }> }>;
  const row = (agent: string, ms: number, tool: string) => JSON.stringify({ ts: new Date(ms).toISOString(), agent, tool, args: {} });
  attachTraceTools(calls, [row("a1", 1040, "attest"), row("a1", 2030, "wait"), row("a2", 1510, "route_review"), row("a1", 500, "read")].join("\n"));
  assert.deepEqual(calls.map((c) => (c.tools ?? []).map((t) => t.name)), [["attest"], ["wait"], ["route_review"]], "a row before a seat's first call belongs to none");
});

test("a seat holding no lead is told, in its header, to hold one for sustained work before it waits", async () => {
  const base = await mkdtemp(join(tmpdir(), "qcost-nudge-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "qc4", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  const text = (await L.leadsDigest({ sandboxRoot: S, agentId: "a1" }, { mark: false })).text;
  assert.match(text, /Yours: none\. Sustained work \(a review pass, a synthesis, a timeline, the report\) is held: open or claim a lead for it/);
  const held = await L.openLead({ sandboxRoot: S, agentId: "a1" }, { title: "Review the answers", why: "the critic's pass", answers: ["1"], take: true });
  assert.ok(held.ok);
  assert.doesNotMatch((await L.leadsDigest({ sandboxRoot: S, agentId: "a1" }, { mark: false })).text, /Sustained work/);
});
