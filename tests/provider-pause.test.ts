/**
 * The pause for the model provider's limit (docs/adr/0013, "The provider's
 * limit"), and the operator's own pause and unpause. A real until-solved run
 * hit a subscription's usage limit on every seat at once; the watchdog
 * prompted each seat again, half an hour apart, for days, every VM up, and
 * the operator was never told. What must hold: the wait a provider's words
 * state is read (and nothing is read when they state none); the run pauses
 * only when every live seat is refused and the limit is plainly not a
 * passing one, never for one seat's error; it pauses under every stop
 * policy; the harness tries again at the named end, or every half hour, and
 * the same rule pauses it again; the operator is told once per spell, with
 * the advice; the operator can hold a run and lift a pause whose cause is
 * gone, and a cap's pause still over its cap is refused.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { refusalFor } from "../scripts/model-gateway.ts";
import { liveSeats, parseProviderWait, providerLimitTick, providerLimitVerdict, readSeatRows, type TraceRow } from "../scripts/provider-limit.ts";

const ROOT = join(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const T0 = Date.parse("2026-09-28T10:00:00.000Z");
const MIN = 60_000;
const iso = (t: number) => new Date(t).toISOString();
const LONG = "You have hit your ChatGPT usage limit (pro plan). Try again in ~6904 min.";
const PLAIN = "Codex error: The usage limit has been reached";

async function run(o: Partial<P.BudgetRecord> = {}, agents = ["a0", "a1"]) {
  const base = await mkdtemp(join(tmpdir(), "provider-pause-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "pp1", agentIds: agents, capUsd: 5, wallClockMinutes: 60 });
  const b = await P.readBudget(S);
  await P.writeBudget(S, { ...b, started_at: iso(T0), ...o });
  return S;
}

/** One trace line, stamped by the host's clock as the collector does. */
function line(agent: string, tool: string, at: number, args: Record<string, unknown> = {}, result: Record<string, unknown> = { ok: true }): string {
  return `${JSON.stringify({ ts: iso(at), recv_ts: iso(at), agent, tool, args, result })}\n`;
}
const err = (agent: string, at: number, reason: string, model = "openai-codex/gpt-6-sol") => line(agent, "agent_error", at, { model }, { ok: false, reason });
const nudge = (agent: string, at: number) => line("system", "idle_nudge", at, { agent, idle_seconds: 200, why: "provider_error" }, { ok: true, nudges: 1 });
async function trace(S: string, ...lines: string[]) {
  await appendFile(join(S, P.EVENTS_REL), lines.join(""), "utf8");
}
function rows(...lines: string[]): TraceRow[] {
  return lines.map((l) => {
    const e = JSON.parse(l);
    return { agent: e.agent, tool: e.tool, at: Date.parse(e.recv_ts), args: e.args, result: e.result };
  });
}
async function board(S: string): Promise<string> {
  const dir = join(S, "threads", "main");
  const out: string[] = [];
  for (const f of (await readdir(dir)).sort()) out.push(await readFile(join(dir, f), "utf8"));
  return out.join("\n");
}

test("the wait a provider's words state: try again in, in N minutes or hours, retry after, a Retry-After number, a time with its zone; none when none is said", () => {
  const at = Date.parse("2026-09-29T12:00:00Z");
  const w = (t: string) => parseProviderWait(t, at);
  assert.equal(w(LONG)?.wait_ms, 6904 * MIN);
  assert.equal(w(LONG)?.until, at + 6904 * MIN);
  assert.equal(w(PLAIN), null, "no wait is said, none is read");
  assert.equal(w("overloaded_error: Overloaded"), null);
  assert.equal(w("quota exhausted; available again in 2 hours and 15 minutes")?.wait_ms, 135 * MIN);
  assert.equal(w("limit hit, back in 3 hours")?.wait_ms, 180 * MIN, "in N hours, with nothing before it");
  assert.equal(w("rate limited, please wait: resets in 45 minutes")?.wait_ms, 45 * MIN);
  assert.equal(w("Rate limit reached. Please try again in 6m0s.")?.wait_ms, 6 * MIN, "a compound duration");
  assert.equal(w("Please try again in 1.5s")?.wait_ms, 1500);
  assert.equal(w("429 Too Many Requests: retry after 30 seconds")?.wait_ms, 30_000);
  assert.equal(w("Retry-After: 120")?.wait_ms, 120_000, "a Retry-After number is seconds");
  assert.equal(w('{"error":{"retry_after": 45}}')?.wait_ms, 45_000);
  assert.equal(w("Your limit resets at 2026-09-30T12:00:00Z")?.until, Date.parse("2026-09-30T12:00:00Z"));
  assert.equal(w("resets 2026-09-30 15:00 +0300")?.until, Date.parse("2026-09-30T12:00:00Z"), "an offset without its colon");
  assert.equal(w("resets 2026-09-30 12:00 UTC")?.until, Date.parse("2026-09-30T12:00:00Z"));
  assert.equal(w("the window reset at 2026-09-29T11:00:00Z"), null, "a time already past is no wait");
  assert.equal(w("Try again in ~5 mo"), null, "an unknown unit is not guessed");
});

test("the rule: every live seat refused with a long stated wait pauses; one seat's error does not; a done or dead seat is not counted", async () => {
  const at = T0 + 10 * MIN;
  const all = rows(line("a0", "bash", T0), line("a1", "bash", T0), err("a0", T0 + MIN, LONG), err("a1", T0 + 2 * MIN, PLAIN));
  const v = providerLimitVerdict(all, ["a0", "a1"], { since: 0, now: at });
  assert.equal(v.pause, true, v.why);
  assert.match(v.why, /a0 was told to wait 6904 minutes/);
  assert.deepEqual(v.models, ["openai-codex/gpt-6-sol"]);
  assert.equal(v.detail, `${LONG}\n${PLAIN}`, "the distinct texts, whole");
  assert.equal(v.until, null, "a1 was told no time: none is known for the run");
  // One seat's error, the other working: never.
  const one = rows(line("a0", "bash", T0), err("a0", T0 + MIN, LONG), line("a1", "bash", T0 + 3 * MIN));
  const v1 = providerLimitVerdict(one, ["a0", "a1"], { since: 0, now: at });
  assert.equal(v1.pause, false);
  assert.match(v1.why, /a1 has no provider error/);
  // A single seat's transient error, with no wait, alone on its team, is not a pause either until it fails again after a prompt.
  assert.equal(providerLimitVerdict(rows(err("a0", T0, "429 rate limited")), ["a0"], { since: 0, now: at }).pause, false);
  // The seat that is done (or dead) is left out: the one live seat decides.
  const withDone = rows(err("a0", T0 + MIN, LONG), line("a1", "done", T0 + 2 * MIN));
  assert.equal(providerLimitVerdict(withDone, ["a0", "a1"], { since: 0, now: at }).pause, false, "a1's last row is its done");
  assert.equal(providerLimitVerdict(withDone, ["a0"], { since: 0, now: at }).pause, true, "with a1 out of the live seats");
  const S = await run();
  await writeFile(P.agentDonePath(S, "a1"), "done\n");
  assert.deepEqual(await liveSeats(S), ["a0"]);
  await writeFile(P.agentDeadPath(S, "a0"), "dead\n");
  assert.deepEqual(await liveSeats(S), []);
  assert.equal(providerLimitVerdict([], [], { since: 0, now: at }).pause, false, "no live seat, nothing to pause");
  // Every seat told a time: the earliest is the run's.
  const both = rows(err("a0", T0, "Try again in 90 minutes"), err("a1", T0, "Try again in 60 minutes"));
  assert.equal(providerLimitVerdict(both, ["a0", "a1"], { since: 0, now: T0 + MIN }).until, iso(T0 + 60 * MIN));
  // A wait already over is not a long one.
  assert.equal(providerLimitVerdict(both, ["a0", "a1"], { since: 0, now: T0 + 120 * MIN }).pause, false);
});

test("the rule: refused without a stated wait, the run pauses only after every seat was prompted again and refused again", () => {
  const at = T0 + 30 * MIN;
  const first = [err("a0", T0 + MIN, PLAIN), err("a1", T0 + MIN, PLAIN)];
  assert.equal(providerLimitVerdict(rows(...first), ["a0", "a1"], { since: 0, now: at }).pause, false, "each refused once");
  // a0 prompted and refused again; a1 prompted, not yet answered.
  const partly = [...first, nudge("a0", T0 + 5 * MIN), nudge("a1", T0 + 5 * MIN), line("a0", "hub_prompt", T0 + 5 * MIN + 100, { kind: "idle_nudge" }), err("a0", T0 + 6 * MIN, PLAIN)];
  const v = providerLimitVerdict(rows(...partly), ["a0", "a1"], { since: 0, now: at });
  assert.equal(v.pause, false);
  assert.match(v.why, /a1 has not been refused again after a prompt/);
  // Two errors in a row with no prompt between them (the provider's own retries) are not a retry of the seat.
  const noPrompt = [...first, err("a0", T0 + 2 * MIN, PLAIN), err("a1", T0 + 2 * MIN, PLAIN)];
  assert.equal(providerLimitVerdict(rows(...noPrompt), ["a0", "a1"], { since: 0, now: at }).pause, false);
  // Both refused again after a prompt: the limit persists across a retry.
  const both = [...partly, err("a1", T0 + 7 * MIN, PLAIN)];
  const v2 = providerLimitVerdict(rows(...both), ["a0", "a1"], { since: 0, now: at });
  assert.equal(v2.pause, true, v2.why);
  assert.match(v2.why, /each was refused again after it was prompted again/);
  assert.equal(v2.detail, PLAIN, "one text, said once");
  // Bookkeeping between the errors does not break the run of errors; work does.
  const worked = [...both.slice(0, -1), line("a1", "bash", T0 + 6 * MIN + 500), err("a1", T0 + 7 * MIN, PLAIN)];
  assert.equal(providerLimitVerdict(rows(...worked), ["a0", "a1"], { since: 0, now: at }).pause, false, "a1 worked between its errors");
  // Errors before the last lift count for the retry, not as a refusal now.
  assert.equal(providerLimitVerdict(rows(...both), ["a0", "a1"], { since: T0 + 10 * MIN, now: at }).pause, false);
});

test("pauseRun: the provider's limit pauses a run under every stop policy, a cap's pause still needs its cap, a stopped run is not paused, and the rule is read again under the lock", async () => {
  for (const policy of ["cap-pause", "cap-stop", "operator"] as const) {
    const S = await run({ stop_policy: policy, ...(policy === "operator" ? { until_solved: true, wall_clock_minutes: 0 } : {}) });
    assert.equal(P.budgetPressure(await P.readBudget(S), T0 + MIN).reason, null, "no cap is reached");
    const p = await P.pauseRun(S, "provider_limit", LONG, T0 + MIN, { by: "harness", models: ["openai-codex/gpt-6-sol"], until: iso(T0 + 6905 * MIN) });
    assert.equal(p.paused, true, `paused under ${policy}`);
    const b = await P.readBudget(S);
    assert.deepEqual(b.paused, { at: iso(T0 + MIN), reason: "provider_limit", detail: LONG, by: "harness", models: ["openai-codex/gpt-6-sol"], until: iso(T0 + 6905 * MIN) });
    assert.equal((await P.pauseRun(S, "provider_limit", LONG, T0 + 2 * MIN)).already, true, "idempotent");
    assert.equal((await P.runOutcome(S)).outcome, "paused");
    assert.equal(P.wallElapsedMs(b, T0 + 500 * MIN), MIN, "the wall clock stands at the pause");
  }
  const cap = await run({ stop_policy: "cap-pause" });
  assert.equal((await P.pauseRun(cap, "cap", "no cap reached", T0 + MIN)).stale, true, "a cap's pause still needs its cap");
  const stopped = await run();
  await P.markStopped(stopped, "operator", "stopped");
  assert.equal((await P.pauseRun(stopped, "provider_limit", LONG)).stale, true, "a stopped run is not paused");
  const came = await run();
  assert.equal((await P.pauseRun(came, "provider_limit", LONG, Date.now(), { recheck: async () => false })).stale, true, "a seat came back before the lock");
  assert.equal((await P.readBudget(came)).paused, undefined);
});

test("the watchdog's pass: pauses on the rule, says it once on the board, and the model gateway, the notice and the words name the provider's limit", async () => {
  const S = await run({ stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 });
  const now = Date.now();
  await trace(S, line("a0", "bash", now - 20 * MIN), line("a1", "bash", now - 20 * MIN), err("a0", now - 10 * MIN, LONG), err("a1", now - 9 * MIN, PLAIN));
  // The rows read from the end stop where each seat's errors begin.
  const read = await readSeatRows(S, ["a0", "a1"], 0);
  assert.deepEqual(read.map((r) => `${r.agent}:${r.tool}`), ["a0:bash", "a1:bash", "a0:agent_error", "a1:agent_error"]);
  const t = await providerLimitTick(S, now);
  assert.equal(t.action, "paused");
  if (t.action !== "paused") return;
  assert.equal(t.spell, "new");
  const b = await P.readBudget(S);
  assert.equal(b.paused?.reason, "provider_limit");
  assert.equal(b.paused?.by, "harness");
  assert.equal(b.paused?.until, undefined, "a1 was told no time");
  assert.equal(t.retry_at, iso(now + P.PROVIDER_LIMIT_RETRY_MS));
  assert.match(await board(S), /The run is paused: the model provider refused every live seat \(openai-codex\/gpt-6-sol\)\. No model call goes out and nobody is prompted; the harness tries again at /);
  // Every brake holds: the gateway refuses, naming it.
  const seat = { token: "t", model: "openai-codex/gpt-6-sol", providers: [] } as never;
  const refused = refusalFor(S, "a0", seat, { seats: {}, spent_usd: 0 } as never);
  assert.equal(refused?.code, "run_paused");
  assert.match(refused!.message, /for the model provider's limit: no model call goes out until the harness tries again, the operator lifts it \(swarm\.sh unpause\) or stops it/);
  // The summary and the outcome say what lifts it.
  assert.equal(P.pauseWayOn(b.paused!), `the harness tries again at ${iso(now + P.PROVIDER_LIMIT_RETRY_MS)}, or the operator lifts it (swarm.sh unpause) or stops it (swarm.sh stop)`);
  assert.equal((await P.runOutcome(S)).why, LONG + "\n" + PLAIN, "the provider's words are why");
  // A second pass while paused does nothing before the try is due.
  const again = await providerLimitTick(S, now + MIN);
  assert.equal(again.action, "none");
  // The operator's notice: once, with the reason, the models, the try and the advice.
  const notice = P.pauseNotice(b.paused!)!;
  assert.equal(notice.reason, "provider_limit");
  assert.deepEqual(notice.models, ["openai-codex/gpt-6-sol"]);
  assert.equal(notice.retry_at, iso(now + P.PROVIDER_LIMIT_RETRY_MS));
  assert.equal(notice.until, undefined);
  assert.match(String(notice.advice), /A long wait holds every VM: to free the machine, stop the run now \(swarm\.sh stop <run>; custody seals it\) and continue it after the limit lifts \(swarm\.sh resume <run>\)\./);
  assert.match(String(notice.advice), /it named no time the limit lifts\. The harness tries again at .*, and every half hour after while the limit holds/);
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(b.paused!)), true);
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(b.paused!)), false, "told once");
});

test("the harness's try: lifted at the named end and its margin (or half an hour on), the wall clock kept; refused again, the run pauses again in the same spell, told once", async () => {
  const S = await run({ stop_policy: "cap-pause", wall_clock_minutes: 600 });
  const now = Date.now();
  // Paused ten minutes into the run, the provider naming an end forty minutes on.
  const at = now - 50 * MIN;
  await P.writeBudget(S, { ...(await P.readBudget(S)), started_at: iso(at - 10 * MIN) });
  await trace(S, line("a0", "bash", at - 5 * MIN), line("a1", "bash", at - 5 * MIN), err("a0", at - MIN, "Try again in 40 minutes."), err("a1", at - MIN, "Try again in 41 minutes."));
  const t = await providerLimitTick(S, at);
  assert.equal(t.action, "paused");
  const paused = (await P.readBudget(S)).paused!;
  assert.equal(paused.until, iso(at + 39 * MIN), "every seat named an end: the earliest");
  assert.equal(await P.liftProviderLimit(S, at + 39 * MIN), null, "not before the margin");
  const lifted = await P.liftProviderLimit(S, at + 39 * MIN + P.PROVIDER_LIMIT_MARGIN_MS);
  assert.equal(lifted?.resumed_by, "harness");
  assert.equal(lifted?.reason, "provider_limit");
  const b = await P.readBudget(S);
  assert.equal(b.paused, undefined);
  assert.equal(b.wall_used_ms, 10 * MIN, "the stretch before the pause is kept, the pause does not count");
  assert.match(P.pauseLiftedText(b.pauses!.at(-1)!), /^The harness lifted the pause for the model provider's limit at .*, to try again\. Pick up where you were: .* If the provider refuses every seat again, the run pauses again by itself\.$/);
  const lift = Date.parse(b.pauses!.at(-1)!.resumed_at!);
  // Right after the lift the old errors do not pause it again.
  assert.equal((await providerLimitTick(S, lift + 1000)).action, "none");
  // The wake reaches each seat and each is refused again: paused again, the same spell.
  await trace(
    S,
    line("system", "resume_wake", lift + 2000, { agent: "a0", resumed_at: iso(lift) }),
    line("system", "resume_wake", lift + 2000, { agent: "a1", resumed_at: iso(lift) }),
    err("a0", lift + 5000, "Codex error: The usage limit has been reached"),
    err("a1", lift + 6000, "Codex error: The usage limit has been reached"),
  );
  const again = await providerLimitTick(S, lift + 10_000);
  assert.equal(again.action, "paused");
  if (again.action !== "paused") return;
  assert.equal(again.spell, "continued");
  const re = (await P.readBudget(S)).paused!;
  assert.equal(re.since, paused.at, "the spell began at the first pause");
  assert.equal(re.until, undefined, "no end named this time");
  assert.equal(P.providerLimitRetryAt(re), Date.parse(re.at) + P.PROVIDER_LIMIT_RETRY_MS, "half an hour on");
  assert.equal(P.pauseNoticeKey(re), P.pauseNoticeKey(paused));
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(paused)), true);
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(re)), false, "the operator is told once per spell");
  assert.equal((await board(S)).match(/The run is paused: the model provider refused every live seat/g)?.length, 1, "said on the board once per spell");
  // Half an hour on, the harness tries again.
  const second = await providerLimitTick(S, Date.parse(re.at) + P.PROVIDER_LIMIT_RETRY_MS);
  assert.equal(second.action, "lifted");
  // A seat that works after the try ends the spell: the next pause is a new one, told again.
  const lift2 = Date.parse((await P.readBudget(S)).pauses!.at(-1)!.resumed_at!);
  await trace(S, line("a0", "bash", lift2 + 1000), err("a0", lift2 + 60_000, LONG), err("a1", lift2 + 60_000, LONG));
  const fresh = await providerLimitTick(S, lift2 + 70_000);
  assert.equal(fresh.action === "paused" && fresh.spell, "new");
  assert.equal((await P.readBudget(S)).paused?.since, undefined);
});

test("the operator's pause and unpause: a hold under any policy, lifted always; the provider's limit lifted at once; a cap's pause lifted only with room, refused while still over it; extend leaves a pause that is not a cap's", async () => {
  for (const policy of ["cap-pause", "cap-stop", "operator"] as const) {
    const S = await run({ stop_policy: policy, ...(policy === "operator" ? { until_solved: true, wall_clock_minutes: 0 } : {}) });
    assert.equal((await P.pauseRun(S, "operator", "the operator paused the run", T0 + 5 * MIN, { by: "operator" })).paused, true);
    assert.equal((await P.runOutcome(S)).by, "operator");
    assert.equal(P.pauseNotice((await P.readBudget(S)).paused!), null, "the operator is not told of their own hold");
    const r = await P.unpauseRun(S, "operator", T0 + 65 * MIN);
    assert.equal(r.resumed.reason, "operator");
    assert.equal(r.resumed.resumed_by, "operator");
    assert.equal(r.resumed.set, undefined);
    assert.equal(r.budget.wall_used_ms, 5 * MIN, "the hold did not count against the wall clock");
    assert.match(P.pauseLiftedText(r.resumed), /^The operator lifted the pause for the operator's hold at /);
    await assert.rejects(P.unpauseRun(S, "operator"), /the run is not paused/);
  }
  // The provider's limit: lifted by the operator at once.
  const pl = await run();
  await P.pauseRun(pl, "provider_limit", LONG, T0 + MIN, { by: "harness", until: iso(T0 + 6905 * MIN) });
  // An extension of a cap-pause run under it changes the caps and leaves the pause.
  await P.writeBudget(pl, { ...(await P.readBudget(pl)), stop_policy: "cap-pause" });
  const ext = await P.extendRun(pl, { minutes: 30 }, "operator", T0 + 2 * MIN);
  assert.equal(ext.resumed, null);
  assert.equal(ext.budget.paused?.reason, "provider_limit", "the pause is not a cap's: an extension does not lift it");
  assert.equal(ext.budget.wall_clock_minutes, 90);
  const up = await P.unpauseRun(pl, "operator", T0 + 3 * MIN);
  assert.equal(up.resumed.reason, "provider_limit");
  assert.match(P.pauseLiftedText(up.resumed), /^The operator lifted the pause for the model provider's limit at /);
  // A cap's pause still over its cap: refused, nothing changed.
  const cap = await run({ stop_policy: "cap-pause", cap_tokens: 1000, tokens: 5000, started_at: iso(Date.now()) });
  await P.capAct(cap, "cap", "the token cap passed");
  const before = await readFile(join(cap, "budget.json"), "utf8");
  await assert.rejects(P.unpauseRun(cap, "operator"), /paused at a cap and is still over the token cap \(5000 of 1000\): swarm\.sh extend gives it room/);
  assert.equal(await readFile(join(cap, "budget.json"), "utf8"), before, "nothing was changed");
  // With room (the caps changed some other way), it is lifted, and the steer withdrawn.
  await P.writeBudget(cap, { ...(await P.readBudget(cap)), cap_tokens: 50_000 });
  const lifted = await P.unpauseRun(cap, "operator");
  assert.equal(lifted.resumed.reason, "cap");
  assert.equal(lifted.budget.stop_steer_at, undefined);
  // A finished run has no pause to lift.
  const fin = await run();
  await P.pauseRun(fin, "operator", "hold");
  await P.markStopped(fin, "operator", "stopped");
  await assert.rejects(P.unpauseRun(fin, "operator"), /the run was stopped/);
});

test("the notify payload: the reason and the named end leave the host in the envelope; the advice and the texts stay in the run", async () => {
  const S = await run();
  await P.pauseRun(S, "provider_limit", LONG, Date.now(), { by: "harness", models: ["openai-codex/gpt-6-sol"], until: "2026-10-04T07:04:00.000Z" });
  const paused = (await P.readBudget(S)).paused!;
  const notice = P.pauseNotice(paused)!;
  assert.deepEqual(Object.keys(notice).sort(), ["advice", "models", "paused", "reason", "resume", "retry_at", "scope", "stop", "unpause", "until"]);
  assert.match(String(notice.advice), /and said its limit lifts at 2026-10-04T07:04:00\.000Z\. The harness tries again at 2026-10-04T07:05:00\.000Z; until then no model call goes out/);
  const capNotice = P.pauseNotice({ at: iso(T0), reason: "cap", detail: "d" })!;
  assert.equal(capNotice.extend, "swarm.sh extend <run> --minutes N | --tokens N | --usd N", "a cap's pause is told as before");
  // Through notify.sh: the operator's command gets the envelope, the run keeps the whole detail.
  const runs = join(S, "..", "runs");
  await mkdir(join(runs, "notify"), { recursive: true });
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "pp1", sandbox: S }] }));
  const got = join(runs, "got.json");
  await writeFile(join(runs, "notify", "pp1.cmd"), `cat > '${got}'\n`, { mode: 0o600 });
  await new Promise<void>((res, rej) => {
    const c = spawn("bash", [join(ROOT, "scripts", "notify.sh"), S, "paused", JSON.stringify(notice)], { env: { ...process.env, SWARM_RUNS_DIR: runs }, stdio: "ignore" });
    c.on("error", rej);
    c.on("exit", () => res());
  });
  let envelope: { event?: string; detail?: Record<string, unknown> } = {};
  for (let i = 0; i < 80; i++) {
    const text = await readFile(got, "utf8").catch(() => "");
    if (text.trim()) {
      envelope = JSON.parse(text);
      break;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.equal(envelope.event, "paused");
  assert.equal(envelope.detail?.reason, "provider_limit");
  assert.equal(envelope.detail?.until, "2026-10-04T07:04:00.000Z");
  assert.equal(envelope.detail?.models_count, 1);
  assert.equal(envelope.detail?.advice, undefined, "words stay in the run");
  const kept = (await readFile(join(S, "traces", "notify-events.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(kept.at(-1).detail.paused.detail, LONG, "the provider's words, whole, in the run");
});
