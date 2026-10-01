/**
 * The stop policy (docs/adr/0013) at the protocol level: what a cap does
 * under each policy (cap-pause pauses, cap-stop stops, operator does
 * nothing), the pause (the wall clock frozen, every brake holding, a question
 * paused), the operator's extension (refused while still over, the pause
 * lifted with room, the wall clock started again where it stopped), the
 * operator's stop (stopped, never completed), --until-solved as --stop
 * operator, and the diminishing-returns proposal (an operator request of kind
 * decision, once per window, never while paused, and nothing stopped).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { refusalFor } from "../scripts/model-gateway.ts";
import { untilSolved } from "../scripts/finish-gate.ts";
import { yieldCheck, lastYield, yieldWindow } from "../scripts/stop-policy.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const GOAL = ["## Goal", "", "g", "", "### Questions", "", "1. Who?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1`', ""].join("\n");

async function run(o: Partial<P.BudgetRecord> = {}) {
  const base = await mkdtemp(join(tmpdir(), "stop-policy-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "sp1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  const b = await P.readBudget(S);
  await P.writeBudget(S, { ...b, ...o });
  return { S, a0: { sandboxRoot: S, agentId: "a0" } };
}
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

test("the policy: cap-pause, cap-stop, operator; --until-solved is --stop operator; a run from before the policy stopped at its caps", async () => {
  assert.deepEqual([...P.STOP_POLICIES], ["cap-pause", "cap-stop", "operator"]);
  assert.equal(P.DEFAULT_STOP_POLICY, "cap-pause");
  assert.equal(P.stopPolicyOf({ stop_policy: "cap-pause" }), "cap-pause");
  assert.equal(P.stopPolicyOf({ stop_policy: "cap-stop" }), "cap-stop");
  assert.equal(P.stopPolicyOf({ stop_policy: "operator" }), "operator");
  assert.equal(P.stopPolicyOf({ until_solved: true }), "operator", "--until-solved is the operator's policy");
  assert.equal(P.stopPolicyOf({}), "cap-stop", "a run from before the policy stopped at its caps");
  // The field survives every fold of usage, as the caps do.
  const kept = P.normalizeBudget({ cap_usd: 1, stop_policy: "cap-pause", paused: { at: "2026-01-01T00:00:00Z", reason: "cap", detail: "d" }, wall_used_ms: 5000, wall_base_at: "2026-01-01T00:00:00Z" } as never);
  assert.deepEqual([kept.stop_policy, kept.paused?.reason, kept.wall_used_ms, kept.wall_base_at], ["cap-pause", "cap", 5000, "2026-01-01T00:00:00Z"]);
  const { S } = await run({ stop_policy: "operator" });
  assert.equal(await untilSolved(S), true, "the finish gate reads --stop operator as until solved");
});

test("the wall clock across pauses and resumes: frozen at a pause, counted from where it stopped", () => {
  const started = Date.parse("2026-01-01T00:00:00Z");
  const b = P.normalizeBudget({ cap_usd: 5, wall_clock_minutes: 30, started_at: "2026-01-01T00:00:00Z" });
  assert.equal(P.wallElapsedMs(b, started + 10 * 60_000), 10 * 60_000);
  const paused = { ...b, paused: { at: "2026-01-01T00:20:00Z", reason: "cap" as const, detail: "d" } };
  assert.equal(P.wallElapsedMs(paused, started + 90 * 60_000), 20 * 60_000, "a pause freezes the clock");
  const resumed = { ...b, wall_used_ms: 20 * 60_000, wall_base_at: "2026-01-01T02:00:00Z" };
  assert.equal(P.wallElapsedMs(resumed, Date.parse("2026-01-01T02:05:00Z")), 25 * 60_000, "a resume counts on from where it stopped");
  assert.equal(P.budgetPressure(resumed, Date.parse("2026-01-01T02:05:00Z")).reason, null);
  assert.equal(P.budgetPressure(resumed, Date.parse("2026-01-01T02:11:00Z")).reason, "wall_clock");
});

test("cap-pause: the steer says a pause, the grace passes, the run pauses; every brake holds; a question is paused; the gateway refuses", async () => {
  const { S } = await run({ stop_policy: "cap-pause", cap_tokens: 1000, tokens: 5000, metered: true });
  const b = await P.readBudget(S);
  const pressure = P.budgetPressure(b);
  assert.equal(pressure.reason, "cap");
  assert.match(P.capSteerText(b, pressure), /The run's token cap \(5,000 of 1,000\) is reached: it pauses in 2 minutes, for the operator to extend it or stop it/);
  assert.doesNotMatch(P.capSteerText(b, pressure), /cannot_complete/, "a pause is not a stop: nobody is told to give up");
  const acted = await P.capAct(S, "cap", "the token cap passed");
  assert.deepEqual(acted, { kind: "paused", created: true });
  const paused = await P.readBudget(S);
  assert.equal(paused.paused?.reason, "cap");
  assert.equal(P.isPaused(paused), true);
  assert.equal(await P.swarmDoneExists(S), false, "a pause writes no sentinel: the partial result stays as it is");
  assert.deepEqual(await P.capAct(S, "cap", "again"), { kind: "paused", created: false }, "idempotent");
  assert.equal((await P.runOutcome(S)).outcome, "paused");
  // The gateway refuses every call of a paused run.
  const seat = { token: "t", model: "m/x", providers: [] } as never;
  assert.equal(refusalFor(S, "a0", seat, { seats: {}, spent_usd: 0 } as never)?.code, "run_paused");
  // The questions in scope are paused with it.
  const ctx = await Q.viewContext(S);
  assert.equal(ctx.paused, true);
  const v = Q.questionViews(ctx).find((x) => x.id === "Q-1")!;
  assert.equal(v.work, "paused");
});

test("the operator's extension: refused while it would leave the run over a cap, the pause lifted with room, the wall clock started again", async () => {
  const { S } = await run({ stop_policy: "cap-pause", cap_tokens: 1000, tokens: 5000, wall_clock_minutes: 30, started_at: ago(10 * 60_000) });
  await P.capAct(S, "cap", "the token cap passed");
  const at = (await P.readBudget(S)).paused!.at;
  await assert.rejects(P.extendRun(S, {}, "operator"), /nothing to extend by/);
  await assert.rejects(P.extendRun(S, { tokens: -5 }, "operator"), /--tokens takes a number above zero/);
  await assert.rejects(P.extendRun(S, { minutes: 30 }, "operator"), /would still be over the token cap \(5000 of 1000\)/);
  assert.equal((await P.readBudget(S)).paused?.at, at, "nothing was changed");
  await assert.rejects(P.extendRun(S, { usd: 1 }, "operator"), /would still be over/);
  const r = await P.extendRun(S, { tokens: 10_000 }, "operator");
  assert.equal(r.set.cap_tokens, 15_000, "added to the larger of the cap and what was used");
  assert.equal(r.resumed?.reason, "cap");
  assert.equal(r.resumed?.resumed_by, "operator");
  const b = await P.readBudget(S);
  assert.equal(b.paused, undefined);
  assert.equal(b.pauses?.length, 1);
  assert.ok((b.wall_used_ms ?? 0) >= 9 * 60_000 && (b.wall_used_ms ?? 0) < 12 * 60_000, `the wall used up to the pause is kept (${b.wall_used_ms})`);
  assert.ok(b.wall_base_at && Date.parse(b.wall_base_at) > Date.parse(at));
  assert.equal(b.stop_steer_at, undefined, "the steer that announced it is withdrawn");
  assert.ok(b.cap_changes?.some((c) => c.by === "operator" && c.set.cap_tokens === 15_000));
  assert.equal((await P.runOutcome(S)).outcome, null, "running again");
  // swarm.sh cap lifts a pause too, when it leaves room.
  await P.writeBudget(S, { ...(await P.readBudget(S)), tokens: 20_000 });
  await P.capAct(S, "cap", "again");
  const lifted = await P.setCaps(S, { cap_tokens: 50_000 }, "operator");
  assert.equal(lifted.resumed?.reason, "cap");
  // An operator's run has nothing to extend; a finished one is resumed, not extended.
  const op = await run({ stop_policy: "operator", until_solved: true });
  await assert.rejects(P.extendRun(op.S, { minutes: 5 }, "operator"), /stop is the operator's/);
  await writeFile(join(S, P.SENTINEL_REL), "---\nby: a0\n---\n");
  await assert.rejects(P.extendRun(S, { minutes: 5 }, "operator"), /swarm\.sh resume continues it/);
});

test("cap-stop: the harness writes the sentinel, and the run is stopped, never completed; the operator's policy does nothing", async () => {
  const { S } = await run({ stop_policy: "cap-stop", cap_usd: 1, spent_usd: 3 });
  const b = await P.readBudget(S);
  assert.match(P.capSteerText(b, P.budgetPressure(b)), /Call done with reason cannot_complete/);
  assert.deepEqual(await P.capAct(S, "cap", "the spend cap passed"), { kind: "stopped", created: true });
  const sentinel = await readFile(join(S, P.SENTINEL_REL), "utf8");
  assert.match(sentinel, /^outcome: stopped$/m);
  assert.deepEqual((await P.runOutcome(S)).outcome, "stopped");
  const op = await run({ stop_policy: "operator", until_solved: true, cap_usd: 1, spent_usd: 3 });
  assert.deepEqual(await P.capAct(op.S, "cap", "x"), { kind: "none", created: false });
});

test("the operator's stop of a run with no sentinel is stopped, once, and never completed", async () => {
  const { S } = await run({ stop_policy: "cap-pause" });
  assert.equal((await P.runOutcome(S)).outcome, null);
  assert.deepEqual(await P.markStopped(S, "operator", "swarm.sh stop"), { written: true });
  assert.deepEqual(await P.markStopped(S, "operator", "again"), { written: false });
  const o = await P.runOutcome(S);
  assert.deepEqual([o.outcome, o.by, o.why], ["stopped", "operator", "swarm.sh stop"]);
  assert.ok(!(P.FINISH_OUTCOMES as readonly string[]).includes("stopped"), "a done never says stopped");
  assert.deepEqual([...P.RUN_OUTCOMES], ["completed", "examination_limited", "paused", "stopped", "abandoned", "verification_unavailable"]);
});

test("diminishing returns: a stop proposed to the operator after a window with nothing yielded, once per window, never while paused", async () => {
  const { S, a0 } = await run({ stop_policy: "cap-pause", started_at: ago(60 * 60_000) });
  // Nothing yielded in the hour: a proposal (the window is 30 minutes by default).
  const first = await yieldCheck(S, { jobs: 20, minutes: 30 });
  assert.equal(first.proposed, true);
  assert.equal(first.id, "D-1");
  const requests = (await readFile(join(S, "operator-requests.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(requests[0].kind, "decision");
  assert.match(requests[0].request, /No new finding, question disposition or coverage record since .*The harness proposes that you stop the run\. It is never the agents' vote/);
  assert.match(requests[0].answer, /silence is not approval of the stop/);
  assert.equal(await P.swarmDoneExists(S), false, "nothing is stopped");
  // Not again in the same window.
  assert.equal((await yieldCheck(S, { jobs: 20, minutes: 30 })).proposed, false);
  // Again after another window with nothing yielded.
  assert.equal((await yieldCheck(S, { jobs: 20, minutes: 30, now: Date.now() + 31 * 60_000 })).proposed, true);
  // A finding yields: the window starts from it.
  const f = await P.recordEntry(a0, { kind: "finding", basis: "observed", confidence: "high", indicates: "i", confidence_why: "c", value: "a fact", source: "s", evidence: "e" } as P.LedgerInput);
  assert.ok(f.ok);
  assert.match((await lastYield(S)).what, /a finding/);
  assert.equal((await yieldCheck(S, { jobs: 20, minutes: 30, now: Date.now() + 5 * 60_000 })).proposed, false);
  // Committed jobs count too: K jobs without a yield.
  for (let i = 1; i <= 3; i++) {
    const id = `j00000${i}`;
    await mkdir(join(S, "store", "jobs", id), { recursive: true });
    await writeFile(join(S, "store", "jobs", id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a1" }, spec: { kind: "command" }, status: "ok", finished_at: new Date(Date.now() + i * 1000).toISOString() }));
  }
  assert.equal((await yieldCheck(S, { jobs: 3, minutes: 600, now: Date.now() + 10_000 })).proposed, true);
  // A paused run proposes nothing: the operator is asked already.
  await P.writeBudget(S, { ...(await P.readBudget(S)), paused: { at: new Date().toISOString(), reason: "cap", detail: "d" } });
  assert.match(String((await yieldCheck(S, { jobs: 1, minutes: 1, now: Date.now() + 10 * 60 * 60_000 })).why), /paused/);
});

test("the stop proposal's window is time: a burst of committed jobs with nothing yielded yet proposes nothing by default (the Breadcrumbs run's D-1 came 20 jobs and 8 minutes after its last finding, minutes before the next); SWARM_YIELD_JOBS puts the job count back beside it", async () => {
  assert.deepEqual(yieldWindow({}), { jobs: 0, minutes: 30 }, "by default only the minutes propose");
  assert.deepEqual(yieldWindow({ SWARM_YIELD_JOBS: "20", SWARM_YIELD_MINUTES: "45" }), { jobs: 20, minutes: 45 });
  assert.deepEqual(yieldWindow({ SWARM_YIELD_JOBS: "0" }), { jobs: 0, minutes: 30 }, "zero is off, as unset is");
  const { S } = await run({ stop_policy: "operator", started_at: ago(8 * 60_000) });
  // 20 committed jobs in the 8 minutes since the start, nothing yielded.
  for (let i = 1; i <= 20; i++) {
    const id = `j${String(i).padStart(6, "0")}`;
    await mkdir(join(S, "store", "jobs", id), { recursive: true });
    await writeFile(join(S, "store", "jobs", id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a1" }, spec: { kind: "command" }, status: "ok", finished_at: ago((20 - i) * 20_000) }));
  }
  const quiet = await yieldCheck(S, {});
  assert.equal(quiet.proposed, false, JSON.stringify(quiet));
  assert.deepEqual([quiet.jobs, quiet.minutes], [20, 8]);
  assert.deepEqual(quiet.window, { jobs: 0, minutes: 30 });
  // The operator who wants the count asks for it.
  const counted = await yieldCheck(S, { jobs: 20 });
  assert.equal(counted.proposed, true);
  const req = (await readFile(join(S, "operator-requests.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l)).at(-1);
  assert.match(req.request, /the window being 30 minutes or 20 committed jobs/);
  // Past the minutes with nothing yielded since the proposal, the time proposes by itself; its words name the minutes alone.
  const timed = await yieldCheck(S, { now: Date.now() + 31 * 60_000 });
  assert.equal(timed.proposed, true, JSON.stringify(timed));
  const last = (await readFile(join(S, "operator-requests.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l)).at(-1);
  assert.match(last.request, /the window being 30 minutes\. /);
});
