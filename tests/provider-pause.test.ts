/**
 * The pause for the model provider's limit (docs/adr/0013, "The provider's
 * limit"), and the operator's own pause and unpause. A real until-solved run
 * hit a subscription's usage limit on every seat at once; the watchdog
 * prompted each seat again, half an hour apart, for days, every VM up, and
 * the operator was never told. What must hold: the wait a provider's words
 * state is read (and nothing is read when they state none, or when it is past
 * belief); the run pauses only when every live seat is refused and each is
 * itself limited (a long stated wait, or refused again after a prompt), never
 * for one seat's error or one seat's wait; it pauses under every stop policy;
 * the pause holds to the end the provider named, read by a rule that can be
 * said, or the harness tries every half hour, and the same rule pauses it
 * again without charging the try to the wall clock; the operator is told once
 * per spell, the board once per seat per spell; the operator can hold a run
 * and lift a pause whose cause is gone, and a cap's pause still over its cap
 * is refused; a stop and a resume in a pause wake nobody with words about a
 * lift, and a run whose seats all died in a pause is not read as paused.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { access, appendFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { refusalFor } from "../scripts/model-gateway.ts";
import { liveSeats, parseProviderWait, pauseUntil, PROVIDER_WAIT_MAX_MS, providerLimitTick, providerLimitVerdict, readSeatRows, SEAT_HARNESS_ROWS, type TraceRow } from "../scripts/provider-limit.ts";
import { prepareResume } from "../scripts/resume.ts";
import { listSwarmRows } from "../scripts/ui/model.ts";
import { cleanUp, stoppedRun } from "./release-fixture.ts";
import { asEnded } from "./resume-fixture.ts";

const ROOT = resolve(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    execFileSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
  await cleanUp();
});

const T0 = Date.parse("2026-09-28T10:00:00.000Z");
const MIN = 60_000;
const iso = (t: number) => new Date(t).toISOString();
const LONG = "You have hit your ChatGPT usage limit (pro plan). Try again in ~6904 min.";
const PLAIN = "Codex error: The usage limit has been reached";
const CODEX = "openai-codex/gpt-6-sol";

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
const err = (agent: string, at: number, reason: string, model = CODEX) => line(agent, "agent_error", at, { model }, { ok: false, reason });
const nudge = (agent: string, at: number) => line("system", "idle_nudge", at, { agent, idle_seconds: 200, why: "provider_error" }, { ok: true, nudges: 1 });
const wake = (agent: string, at: number, ok: boolean) => line("system", "resume_wake", at, { agent, resumed_at: iso(at) }, { ok });
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

test("the wait a provider's words state: try again in, in N minutes or hours, retry after, a Retry-After number, the first time with its zone that is ahead; none when none is said or it is past belief", () => {
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
  assert.equal(w("Rate limited at 2026-09-29T10:00:00Z; window resets at 2026-09-29T13:00:00Z")?.until, Date.parse("2026-09-29T13:00:00Z"), "the first time ahead, past a time behind");
  assert.equal(w("Try again in ~5 mo"), null, "an unknown unit is not guessed");
  assert.equal(w("try again at 3:45 PM"), null, "a clock time with no date and no zone is not guessed");
  // Past belief: an epoch sent where seconds were meant, or a wait of more than thirty days.
  assert.equal(w('{"retry_after": 1727600000}'), null, "an epoch is not fifty years of waiting");
  assert.equal(w("Try again in 40 days"), null);
  assert.equal(w(`retry after ${PROVIDER_WAIT_MAX_MS / 1000} seconds`)?.wait_ms, PROVIDER_WAIT_MAX_MS, "thirty days is still a wait");
  assert.equal(w("Retry-After: 99999999999. Please try again in 20 minutes")?.wait_ms, 20 * MIN, "a form past belief gives way to the next");
});

test("the board's dedupe masks numbers and times: a countdown is one error, and the words differ where the error does", () => {
  const n = P.normalizeProviderError;
  assert.equal(n("You have hit your ChatGPT usage limit (pro plan). Try again in ~6904 min."), n("You have hit your ChatGPT usage limit (pro plan). Try again in ~6874 min."));
  assert.equal(n("resets at 2026-09-30T12:00:00Z"), n("resets at 2026-10-01 08:30 UTC"));
  assert.notEqual(n("402 Insufficient Balance"), n("429 Too Many Requests"));
  assert.equal(n(PLAIN), PLAIN, "a text with no number is itself");
});

test("the rule: every live seat refused and each limited pauses; one seat's error does not, nor one seat's long wait beside the others' passing errors; a done or dead seat is not counted", async () => {
  const at = T0 + 10 * MIN;
  // The incident: every seat told ~6904 minutes.
  const both = rows(line("a0", "bash", T0), line("a1", "bash", T0), err("a0", T0 + MIN, LONG), err("a1", T0 + 2 * MIN, LONG));
  const v = providerLimitVerdict(both, ["a0", "a1"], { since: 0, now: at });
  assert.equal(v.pause, true, v.why);
  assert.match(v.why, /a0 was told to wait 6904 minutes; a1 was told to wait 6904 minutes/);
  assert.deepEqual(v.models, [CODEX]);
  assert.equal(v.detail, LONG, "one text, said once");
  assert.equal(v.until, iso(T0 + 2 * MIN + 6904 * MIN), "one provider: the longest end any seat was told");
  // The incident's other text, on a seat refused once: not limited yet.
  const mixed = [line("a0", "bash", T0), line("a1", "bash", T0), err("a0", T0 + MIN, LONG), err("a1", T0 + 2 * MIN, PLAIN)];
  const vm = providerLimitVerdict(rows(...mixed), ["a0", "a1"], { since: 0, now: at });
  assert.equal(vm.pause, false);
  assert.match(vm.why, /but a1 was neither told to wait 30 minutes or more nor refused again after a prompt/);
  // Refused again after a prompt: limited; the pause holds to the end a0 was told, the provider being one.
  const retried = providerLimitVerdict(rows(...mixed, nudge("a1", T0 + 5 * MIN), err("a1", T0 + 6 * MIN, PLAIN)), ["a0", "a1"], { since: 0, now: at });
  assert.equal(retried.pause, true, retried.why);
  assert.equal(retried.detail, `${LONG}\n${PLAIN}`, "the distinct texts, whole");
  assert.equal(retried.until, iso(T0 + MIN + 6904 * MIN), "the one provider's end, from the seat that was told it");
  // One seat's long wait, and the others' momentary errors: not a run-wide limit.
  const three = [err("a0", T0 + MIN, "Rate limit on tokens per minute. Please try again in 45 minutes."), err("a1", T0 + MIN, "500 Internal Server Error"), err("a2", T0 + MIN, "overloaded_error: Overloaded")];
  const v3 = providerLimitVerdict(rows(...three), ["a0", "a1", "a2"], { since: 0, now: at });
  assert.equal(v3.pause, false);
  assert.match(v3.why, /but a1, a2 were neither told/);
  // Its mirror: a1 and a2 prompted again and refused again.
  const mirror = [...three, nudge("a1", T0 + 5 * MIN), nudge("a2", T0 + 5 * MIN), err("a1", T0 + 6 * MIN, "500 Internal Server Error"), err("a2", T0 + 6 * MIN, "overloaded_error: Overloaded")];
  assert.equal(providerLimitVerdict(rows(...mirror), ["a0", "a1", "a2"], { since: 0, now: at }).pause, true);
  // One seat's error, the other working: never.
  const one = rows(line("a0", "bash", T0), err("a0", T0 + MIN, LONG), line("a1", "bash", T0 + 3 * MIN));
  const v1 = providerLimitVerdict(one, ["a0", "a1"], { since: 0, now: at });
  assert.equal(v1.pause, false);
  assert.match(v1.why, /a1 has no provider error/);
  // A single seat's passing error, alone on its team, is not a pause until it fails again after a prompt.
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
  // A wait already over is not a long one.
  const over = rows(err("a0", T0, "Try again in 90 minutes"), err("a1", T0, "Try again in 60 minutes"));
  assert.equal(providerLimitVerdict(over, ["a0", "a1"], { since: 0, now: T0 + 120 * MIN }).pause, false);
});

test("the end the pause holds to: one provider, the longest end any seat was told; several, the earliest when each was told one, else none", () => {
  const a0 = err("a0", T0, "Try again in 90 minutes");
  const a1 = err("a1", T0, "Try again in 60 minutes");
  const at = T0 + MIN;
  assert.equal(providerLimitVerdict(rows(a0, a1), ["a0", "a1"], { since: 0, now: at }).until, iso(T0 + 90 * MIN), "one provider: its limit is one, and the longest end is when it has lifted");
  const other = err("a1", T0, "Try again in 60 minutes", "anthropic/claude-x");
  assert.equal(providerLimitVerdict(rows(a0, other), ["a0", "a1"], { since: 0, now: at }).until, iso(T0 + 60 * MIN), "two providers, each told an end: the first time any seat can go on");
  const unstated = [err("a1", T0, PLAIN, "anthropic/claude-x"), nudge("a1", T0 + 2 * MIN), err("a1", T0 + 3 * MIN, PLAIN, "anthropic/claude-x")];
  assert.equal(providerLimitVerdict(rows(a0, ...unstated), ["a0", "a1"], { since: 0, now: T0 + 5 * MIN }).until, null, "two providers, one told nothing: the half-hour try");
  assert.equal(pauseUntil([{ model: null, until: T0 }, { model: CODEX, until: T0 + MIN }]), T0, "a seat with no model known is not assumed to share a provider");
  assert.equal(pauseUntil([{ model: CODEX, until: null }, { model: CODEX, until: null }]), null, "one provider that named no end: none");
});

test("the rule: refused without a stated wait, the run pauses only after every seat was prompted again and refused again; a prompt's row may land just after the error it caused", () => {
  const at = T0 + 30 * MIN;
  const first = [err("a0", T0 + MIN, PLAIN), err("a1", T0 + MIN, PLAIN)];
  assert.equal(providerLimitVerdict(rows(...first), ["a0", "a1"], { since: 0, now: at }).pause, false, "each refused once");
  // a0 prompted and refused again; a1 prompted, not yet answered.
  const partly = [...first, nudge("a0", T0 + 5 * MIN), nudge("a1", T0 + 5 * MIN), line("a0", "hub_prompt", T0 + 5 * MIN + 100, { kind: "idle_nudge" }), err("a0", T0 + 6 * MIN, PLAIN)];
  const v = providerLimitVerdict(rows(...partly), ["a0", "a1"], { since: 0, now: at });
  assert.equal(v.pause, false);
  assert.match(v.why, /but a1 was neither told to wait 30 minutes or more nor refused again after a prompt/);
  // Two errors in a row with no prompt between them (Pi's own retries) are not a retry of the seat.
  const noPrompt = [...first, err("a0", T0 + 2 * MIN, PLAIN), err("a1", T0 + 2 * MIN, PLAIN)];
  assert.equal(providerLimitVerdict(rows(...noPrompt), ["a0", "a1"], { since: 0, now: at }).pause, false);
  // Both refused again after a prompt: the limit persists across a retry.
  const both = [...partly, err("a1", T0 + 7 * MIN, PLAIN)];
  const v2 = providerLimitVerdict(rows(...both), ["a0", "a1"], { since: 0, now: at });
  assert.equal(v2.pause, true, v2.why);
  assert.match(v2.why, /a0, a1 were refused again after a prompt/);
  assert.equal(v2.detail, PLAIN, "one text, said once");
  // A host run's nudge row written after the delivery returned lands after the refusal it caused: still a retry.
  const late = [...first, err("a0", T0 + 5 * MIN, PLAIN), nudge("a0", T0 + 5 * MIN + 300), err("a1", T0 + 5 * MIN, PLAIN), nudge("a1", T0 + 5 * MIN + 300)];
  assert.equal(providerLimitVerdict(rows(...late), ["a0", "a1"], { since: 0, now: at }).pause, true, "within the lag a prompt row may take");
  const tooLate = [...first, err("a0", T0 + 5 * MIN, PLAIN), nudge("a0", T0 + 5 * MIN + 10_000), err("a1", T0 + 5 * MIN, PLAIN), nudge("a1", T0 + 5 * MIN + 10_000)];
  assert.equal(providerLimitVerdict(rows(...tooLate), ["a0", "a1"], { since: 0, now: at }).pause, false, "a prompt well after the error is the next try, not this one");
  // Bookkeeping between the errors does not break the run of errors, nor do the harness's own rows after it; work does.
  const worked = [...both.slice(0, -1), line("a1", "bash", T0 + 6 * MIN + 500), err("a1", T0 + 7 * MIN, PLAIN)];
  assert.equal(providerLimitVerdict(rows(...worked), ["a0", "a1"], { since: 0, now: at }).pause, false, "a1 worked between its errors");
  const harness = [...both, line("a0", "hub_lost", T0 + 8 * MIN), line("a1", "extension_error", T0 + 8 * MIN), line("a1", "agent_stop", T0 + 9 * MIN)];
  assert.equal(providerLimitVerdict(rows(...harness), ["a0", "a1"], { since: 0, now: at }).pause, true, "a lost hub link, an extension's error or a stop is not a turn");
  // Errors before the last lift count for the retry, not as a refusal now.
  assert.equal(providerLimitVerdict(rows(...both), ["a0", "a1"], { since: T0 + 10 * MIN, now: at }).pause, false);
});

test("the harness's rows under a seat's id are one list, here and in the watchdog, and every row the extension writes is that, a tool the seat calls, or a row inside such a call", async () => {
  const sh = await readFile(join(ROOT, "scripts", "idle-nudge.sh"), "utf8");
  const listed = sh.match(/^SEAT_HARNESS_ROWS='([^']*)'/m)?.[1].split(/\s+/).filter(Boolean) ?? [];
  assert.deepEqual([...listed].sort(), [...SEAT_HARNESS_ROWS].sort(), "scripts/idle-nudge.sh SEAT_HARNESS_ROWS and scripts/provider-limit.ts are the same list");
  const tools = new Set<string>();
  const written = new Set<string>();
  for (const name of await readdir(join(ROOT, "extensions"))) {
    if (!name.endsWith(".ts")) continue;
    const text = await readFile(join(ROOT, "extensions", name), "utf8");
    for (const m of text.matchAll(/registerTool\(\{\s*name:\s*"([a-z_]+)"/g)) tools.add(m[1]);
    for (const m of text.matchAll(/logEvent\([^,()]+,\s*agentId,\s*"([a-z_]+)"/g)) written.add(m[1]);
    for (const m of text.matchAll(/\btrace\((?:ctx\.)?cwd,\s*"([a-z_]+)"/g)) written.add(m[1]);
  }
  assert.ok(tools.size > 20 && written.size > 20, `read the extension (${tools.size} tools, ${written.size} rows)`);
  // Written inside a tool call the seat made: its model answered.
  const inCall = new Set(["claim_violation", "done_deferred", "finish_line", "inputs_check", "inputs_violation", "ledger_superseded", "record_deferred", "record_leads", "record_violation", "review_deferred"]);
  const unclassified = [...written].filter((n) => n !== "agent_error" && !tools.has(n) && !SEAT_HARNESS_ROWS.has(n) && !inCall.has(n));
  assert.deepEqual(unclassified, [], "a new row under a seat's id is a harness row (SEAT_HARNESS_ROWS) or one written inside a call");
});

test("readSeatRows: the same rows at every chunk size, a line cut short passed over, a seat's start ends the read, and a seat not yet at work leaves the run going at once", async () => {
  const S = await run({}, ["a0", "a1", "a2"]);
  const padding = Array.from({ length: 200 }, (_x, i) => line("a0", "bash", T0 - 300 * MIN + i * 1000, { command: `step ${i} ${"x".repeat(i % 37)}` }));
  await trace(S, ...padding, line("a0", "agent_start", T0), line("a1", "agent_start", T0), line("a0", "bash", T0 + MIN), line("a1", "bash", T0 + MIN), err("a0", T0 + 2 * MIN, LONG), err("a1", T0 + 2 * MIN, LONG));
  const big = await readSeatRows(S, ["a0", "a1"], 0);
  assert.deepEqual(big.map((r) => `${r.agent}:${r.tool}`), ["a0:bash", "a1:bash", "a0:agent_error", "a1:agent_error"], "read back only to each seat's last work");
  for (const chunk of [1, 7, 64, 1000]) assert.deepEqual(await readSeatRows(S, ["a0", "a1"], 0, { chunk }), big, `chunk ${chunk}`);
  // A last line still being written is passed over; a whole one with no newline yet is read.
  const cut = err("a0", T0 + 3 * MIN, PLAIN);
  await appendFile(join(S, P.EVENTS_REL), cut.slice(0, 40), "utf8");
  assert.deepEqual(await readSeatRows(S, ["a0", "a1"], 0, { chunk: 64 }), big);
  await writeFile(join(S, P.EVENTS_REL), (await readFile(join(S, P.EVENTS_REL), "utf8")).slice(0, -40) + cut.trimEnd(), "utf8");
  assert.equal((await readSeatRows(S, ["a0", "a1"], 0)).at(-1)?.at, T0 + 3 * MIN);
  // a2 is still loading its first turn: the read stops at its start, and the run is not paused.
  await trace(S, "\n", line("a2", "agent_start", T0 + 4 * MIN), line("a2", "tool_loaded", T0 + 4 * MIN), line("a2", "context", T0 + 5 * MIN));
  const loading = await readSeatRows(S, ["a0", "a1", "a2"], 0, { chunk: 64 });
  assert.ok(loading.length <= 6, `stopped at a2's start (${loading.length} rows)`);
  assert.equal(providerLimitVerdict(loading, ["a0", "a1", "a2"], { since: 0, now: T0 + 6 * MIN }).pause, false);
});

test("a seat the lift's wake did not reach is left out of the rule, and the others' refusal pauses the run again", async () => {
  const S = await run({ stop_policy: "cap-pause", wall_clock_minutes: 600, started_at: iso(Date.now() - 100 * MIN) });
  const t = Date.now() - 60 * MIN;
  await trace(S, line("a0", "bash", t - 5 * MIN), line("a1", "bash", t - 5 * MIN), err("a0", t, LONG), err("a1", t, LONG));
  assert.equal((await providerLimitTick(S, t + 1000)).action, "paused");
  await P.unpauseRun(S, "operator", t + 2 * MIN);
  const lift = Date.parse((await P.readBudget(S)).pauses!.at(-1)!.resumed_at!);
  // a1's process is gone (no .dead yet): its wake fails; a0 is woken and refused again.
  await trace(S, wake("a0", lift + 1000, true), wake("a1", lift + 1000, false), err("a0", lift + 3000, LONG));
  const read = await readSeatRows(S, ["a0", "a1"], lift);
  const v = providerLimitVerdict(read, ["a0", "a1"], { since: lift, now: lift + 5000 });
  assert.equal(v.pause, true, v.why);
  assert.deepEqual(v.unreached, ["a1"]);
  const tick = await providerLimitTick(S, lift + 5000);
  assert.equal(tick.action, "paused");
  assert.deepEqual(tick.action === "paused" && tick.unreached, ["a1"]);
  // Once a wake reaches it, it counts again: nothing of its own since the lift, so the run is not paused on it.
  const reached = rows(...read.map((r) => line(r.agent, r.tool, r.at, r.args ?? {}, r.result ?? {})), wake("a1", lift + 4000, true));
  const v2 = providerLimitVerdict(reached, ["a0", "a1"], { since: lift, now: lift + 5000 });
  assert.equal(v2.pause, false);
  assert.match(v2.why, /a1 has no provider error as the last turn since/);
  // Every live seat unreached: no pause (the reaper's to mark).
  assert.equal(providerLimitVerdict(rows(err("a0", T0, LONG), wake("a0", T0 + 2 * MIN, false)), ["a0"], { since: T0 + MIN, now: T0 + 3 * MIN }).pause, false);
});

test("pauseRun: the provider's limit pauses a run under every stop policy, a cap's pause still needs its cap, a stopped run is not paused, and the rule is read again under the lock", async () => {
  for (const policy of ["cap-pause", "cap-stop", "operator"] as const) {
    const S = await run({ stop_policy: policy, ...(policy === "operator" ? { until_solved: true, wall_clock_minutes: 0 } : {}) });
    assert.equal(P.budgetPressure(await P.readBudget(S), T0 + MIN).reason, null, "no cap is reached");
    const p = await P.pauseRun(S, "provider_limit", LONG, T0 + MIN, { by: "harness", models: [CODEX], until: iso(T0 + 6905 * MIN) });
    assert.equal(p.paused, true, `paused under ${policy}`);
    const b = await P.readBudget(S);
    assert.deepEqual(b.paused, { at: iso(T0 + MIN), reason: "provider_limit", detail: LONG, by: "harness", models: [CODEX], until: iso(T0 + 6905 * MIN) });
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

test("the harness's try is not made on a run stopped in its pause, and a run whose seats all died in a pause is not read as paused", async () => {
  const S = await run();
  await P.pauseRun(S, "provider_limit", PLAIN, T0 + MIN, { by: "harness" });
  await P.markStopped(S, "operator", "swarm.sh stop");
  assert.equal(await P.liftProviderLimit(S, T0 + 120 * MIN), null, "stopped: the pause it was stopped in stays");
  assert.equal((await P.readBudget(S)).paused?.reason, "provider_limit");
  assert.equal((await P.runOutcome(S)).outcome, "stopped");
  const dead = await run();
  await P.pauseRun(dead, "provider_limit", PLAIN, T0 + MIN, { by: "harness" });
  await writeFile(join(dead, P.ALL_DEAD_REL), "---\nby: reaper\nreason: all_agents_dead\n---\n");
  assert.deepEqual(await P.runOutcome(dead), { outcome: null, by: null, at: null, why: null }, "no outcome of its own, as an unpaused run whose seats all died");
  assert.equal((await providerLimitTick(dead, T0 + 120 * MIN)).action, "none");
});

test("the watchdog's pass: pauses on the rule, says it once on the board, and the model gateway, the notice and the words name the provider's limit", async () => {
  const S = await run({ stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 });
  const now = Date.now();
  const RATE = "Rate limit exceeded for this account";
  await trace(
    S,
    line("a0", "bash", now - 20 * MIN),
    line("a1", "bash", now - 20 * MIN),
    err("a0", now - 15 * MIN, PLAIN),
    err("a1", now - 15 * MIN, RATE),
    nudge("a0", now - 12 * MIN),
    nudge("a1", now - 12 * MIN),
    err("a0", now - 11 * MIN, PLAIN),
    err("a1", now - 11 * MIN, RATE),
  );
  // The rows read from the end stop where each seat's errors begin.
  const read = await readSeatRows(S, ["a0", "a1"], 0);
  assert.deepEqual(read.map((r) => `${r.agent}:${r.tool}`), ["a0:bash", "a1:bash", "a0:agent_error", "a1:agent_error", "system:idle_nudge", "system:idle_nudge", "a0:agent_error", "a1:agent_error"]);
  const t = await providerLimitTick(S, now);
  assert.equal(t.action, "paused");
  if (t.action !== "paused") return;
  assert.equal(t.spell, "new");
  const b = await P.readBudget(S);
  assert.equal(b.paused?.reason, "provider_limit");
  assert.equal(b.paused?.by, "harness");
  assert.equal(b.paused?.until, undefined, "no seat was told a time");
  assert.equal(t.retry_at, iso(now + P.PROVIDER_LIMIT_RETRY_MS));
  assert.match(await board(S), /The run is paused: the model provider refused every live seat \(openai-codex\/gpt-6-sol\)\. No model call goes out and nobody is prompted; the harness tries again at /);
  // Every brake holds: the gateway refuses, naming it.
  const seat = { token: "t", model: CODEX, providers: [] } as never;
  const refused = refusalFor(S, "a0", seat, { seats: {}, spent_usd: 0 } as never);
  assert.equal(refused?.code, "run_paused");
  assert.match(refused!.message, /for the model provider's limit: no model call goes out until the harness tries again, the operator lifts it \(swarm\.sh unpause\) or stops it/);
  // The summary and the outcome say what lifts it.
  assert.equal(P.pauseWayOn(b.paused!), `the harness tries again at ${iso(now + P.PROVIDER_LIMIT_RETRY_MS)}, or the operator lifts it (swarm.sh unpause) or stops it (swarm.sh stop)`);
  assert.equal((await P.runOutcome(S)).why, `${PLAIN}\n${RATE}`, "the provider's words are why");
  // A second pass while paused does nothing before the try is due.
  const again = await providerLimitTick(S, now + MIN);
  assert.equal(again.action, "none");
  // The operator's notice: once, with the reason, the models, the try and the advice.
  const notice = P.pauseNotice(b.paused!)!;
  assert.equal(notice.reason, "provider_limit");
  assert.deepEqual(notice.models, [CODEX]);
  assert.equal(notice.retry_at, iso(now + P.PROVIDER_LIMIT_RETRY_MS));
  assert.equal(notice.until, undefined);
  assert.match(String(notice.advice), /A long wait holds every VM: to free the machine, stop the run now \(swarm\.sh stop <run>; custody seals it\) and continue it after the limit lifts \(swarm\.sh resume <run>\)\./);
  assert.match(String(notice.advice), /it named no time the limit lifts\. The harness tries again at .*, and every half hour after while the limit holds/);
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(b.paused!)), true);
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(b.paused!)), false, "told once");
});

test("the harness's try: lifted at the named end and its margin (or half an hour on), the wall clock kept; refused again, the run pauses again in the same spell, told once, and the try costs no wall clock", async () => {
  const S = await run({ stop_policy: "cap-pause", wall_clock_minutes: 600 });
  const now = Date.now();
  // Paused ten minutes into the run, the provider naming an end forty minutes on.
  const at = now - 50 * MIN;
  await P.writeBudget(S, { ...(await P.readBudget(S)), started_at: iso(at - 10 * MIN) });
  await trace(S, line("a0", "bash", at - 5 * MIN), line("a1", "bash", at - 5 * MIN), err("a0", at - MIN, "Try again in 40 minutes."), err("a1", at - MIN, "Try again in 41 minutes."));
  const t = await providerLimitTick(S, at);
  assert.equal(t.action, "paused");
  const paused = (await P.readBudget(S)).paused!;
  assert.equal(paused.until, iso(at + 40 * MIN), "one provider: the longest end named");
  assert.equal(await P.liftProviderLimit(S, at + 40 * MIN), null, "not before the margin");
  const lifted = await P.liftProviderLimit(S, at + 40 * MIN + P.PROVIDER_LIMIT_MARGIN_MS);
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
  await trace(S, wake("a0", lift + 2000, true), wake("a1", lift + 2000, true), err("a0", lift + 5000, PLAIN), err("a1", lift + 6000, PLAIN));
  const again = await providerLimitTick(S, lift + 40_000);
  assert.equal(again.action, "paused");
  if (again.action !== "paused") return;
  assert.equal(again.spell, "continued");
  const re = (await P.readBudget(S)).paused!;
  assert.equal(re.since, paused.at, "the spell began at the first pause");
  assert.equal(re.until, undefined, "no end ahead this time");
  assert.equal(P.providerLimitRetryAt(re), Date.parse(re.at) + P.PROVIDER_LIMIT_RETRY_MS, "half an hour on");
  assert.equal(P.wallElapsedMs(await P.readBudget(S), Date.parse(re.at) + 60 * MIN), 10 * MIN, "the forty seconds of the try are not charged");
  assert.equal(P.pauseNoticeKey(re), P.pauseNoticeKey(paused));
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(paused)), true);
  assert.equal(await P.claimPauseNotice(S, P.pauseNoticeKey(re)), false, "the operator is told once per spell");
  assert.equal((await board(S)).match(/The run is paused: the model provider refused every live seat/g)?.length, 1, "said on the board once per spell");
  // Half an hour on, the harness tries again.
  const second = await providerLimitTick(S, Date.parse(re.at) + P.PROVIDER_LIMIT_RETRY_MS);
  assert.equal(second.action, "lifted");
  // A seat that works after the try ends the spell: the next pause is a new one, told again, and its try window counted.
  const lift2 = Date.parse((await P.readBudget(S)).pauses!.at(-1)!.resumed_at!);
  await trace(S, line("a0", "bash", lift2 + 1000), err("a0", lift2 + 60_000, LONG), err("a1", lift2 + 60_000, LONG));
  const fresh = await providerLimitTick(S, lift2 + 70_000);
  assert.equal(fresh.action === "paused" && fresh.spell, "new");
  assert.equal((await P.readBudget(S)).paused?.since, undefined);
  assert.equal(P.wallElapsedMs(await P.readBudget(S), lift2 + 200 * MIN), 10 * MIN + 70_000, "a spell that ended in work counts its minute");
});

test("a stop and a resume in a pause for the provider's limit: the pause folded as the resume's, the wall clock where the pause froze it, and the next pause a new spell", async () => {
  const r = await stoppedRun({ id: "sppr1" });
  await asEnded(r, { minutesAgo: 90, wall: 600 });
  const started = Date.parse((await P.readBudget(r.root)).started_at);
  await rm(join(r.root, P.SENTINEL_REL));
  await P.writeBudget(r.root, { ...(await P.readBudget(r.root)), paused: { at: iso(started + 20 * MIN), reason: "provider_limit", detail: LONG, by: "harness", models: [CODEX], until: iso(started + 6924 * MIN) } });
  await P.markStopped(r.root, "operator", "swarm.sh stop");
  assert.equal((await P.runOutcome(r.root)).outcome, "stopped");
  const out = await prepareResume(r.root, { run: r.id, by: "operator" });
  assert.equal(out.ok, true);
  const b = await P.readBudget(r.root);
  assert.equal(b.paused, undefined);
  assert.equal(b.pauses?.at(-1)?.reason, "provider_limit");
  assert.equal(b.pauses?.at(-1)?.resumed_by, "operator (resume)", "the watchdog knows this lift from one it should wake the seats for");
  assert.equal(b.wall_used_ms, 20 * MIN, "the wall clock stood from the pause to the resume");
  // The resumed seats are refused again: a new spell, told again.
  const t = Date.now();
  await appendFile(join(r.root, P.EVENTS_REL), [err("a0", t, LONG), err("a1", t, LONG)].join(""), "utf8");
  const tick = await providerLimitTick(r.root, t + 1000);
  assert.equal(tick.action === "paused" && tick.spell, "new");
});

test("the console shows a pause while the run stands paused, with its reason and end, and counts no pause as elapsed", async () => {
  const S = await run({ stop_policy: "cap-pause", wall_clock_minutes: 600, started_at: iso(Date.now() - 100 * MIN) });
  const runs = join(S, "..", "runs");
  await mkdir(runs, { recursive: true });
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "pp1", sandbox: S, state: "running" }] }));
  const pausedAt = Date.now() - 90 * MIN;
  await P.pauseRun(S, "provider_limit", LONG, pausedAt, { by: "harness", until: "2026-10-04T07:04:00.000Z" });
  const [row] = await listSwarmRows(runs);
  assert.deepEqual(row.paused, { at: iso(pausedAt), reason: "provider_limit", detail: LONG, until: "2026-10-04T07:04:00.000Z" });
  assert.ok(Math.abs(row.elapsed_ms - 10 * MIN) < 5_000, `ten minutes went before the pause, the ninety since are not elapsed (${row.elapsed_ms})`);
  await P.markStopped(S, "operator", "swarm.sh stop");
  const [stopped] = await listSwarmRows(runs);
  assert.equal(stopped.paused, null, "a run stopped in a pause is not waiting on it");
  assert.equal(stopped.outcome, "stopped");
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
  await P.pauseRun(S, "provider_limit", LONG, Date.now(), { by: "harness", models: [CODEX], until: "2026-10-04T07:04:00.000Z" });
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

// --- the extension, loaded by Pi's own loader ---------------------------------------------------

async function findLoader(): Promise<string | null> {
  const candidates: string[] = [];
  if (process.env.PI_PACKAGE_DIR) candidates.push(process.env.PI_PACKAGE_DIR);
  candidates.push(join(ROOT, "node_modules", "@earendil-works", "pi-coding-agent"));
  for (const dir of candidates) {
    const loader = join(dir, "dist", "core", "extensions", "loader.js");
    if (await access(loader).then(() => true, () => false)) return loader;
  }
  return null;
}

test("Pi loader: each failed turn is on the trace, whole; the board is told once per seat per spell, a countdown being one error", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) return t.skip("Pi package not found");
  const S = await run({}, ["agent00"]);
  const keys = ["AGENT_ID", "SWARM_BOARD_SOCKET", "SWARM_TRACE_SOCKET", "SWARM_SELF_COMPACT", "SWARM_ISOLATION"];
  const was = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.AGENT_ID = "agent00";
  process.env.SWARM_ISOLATION = "host";
  delete process.env.SWARM_BOARD_SOCKET;
  delete process.env.SWARM_TRACE_SOCKET;
  delete process.env.SWARM_SELF_COMPACT;
  try {
    const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, Array<(e: unknown, c: unknown) => Promise<unknown>>> }>; errors: unknown[] }> };
    const out = await loadExtensions([join(ROOT, "extensions", "agent-swarm.ts")], S);
    assert.deepEqual(out.errors, []);
    const [swarm] = out.extensions;
    const entries: unknown[] = [];
    let n = 0;
    const turn = async (stopReason: "error" | "stop", errorMessage?: string) => {
      n++;
      entries.push({ type: "message", id: `e${n}`, parentId: null, timestamp: iso(Date.now() + n), message: { role: "assistant", stopReason, errorMessage, provider: "openai-codex", model: "gpt-6-sol", content: [], usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } } });
      const ctx = { cwd: S, hasUI: false, ui: {}, abort: () => undefined, shutdown: () => undefined, sessionManager: { getEntries: () => entries, getSessionId: () => "s1" } };
      for (const h of swarm.handlers.get("turn_end") ?? []) await h({ type: "turn_end" }, ctx);
    };
    await turn("error", "You have hit your usage limit. Try again in ~10 min.");
    await turn("error", "You have hit your usage limit. Try again in ~9 min.");
    await turn("error", "You have hit your usage limit. Try again in ~9 min.");
    const errorRows = async () => (await readFile(join(S, P.EVENTS_REL), "utf8")).split("\n").filter((l) => l.includes('"tool":"agent_error"')).map((l) => JSON.parse(l).result.reason as string);
    const vetoes = async () => (await board(S)).match(/PROVIDER ERROR: agent00/g)?.length ?? 0;
    assert.deepEqual(await errorRows(), ["You have hit your usage limit. Try again in ~10 min.", "You have hit your usage limit. Try again in ~9 min.", "You have hit your usage limit. Try again in ~9 min."], "every failed turn, whole, the same words included");
    assert.equal(await vetoes(), 1, "one post for the countdown");
    // Another error in the same spell: on the trace, not on the board.
    await turn("error", "402 Insufficient Balance");
    assert.equal(await vetoes(), 1, "once per spell");
    // A turn that ends well ends the spell; the next spell's error is told, unless it is the one last told.
    await turn("stop");
    await turn("error", "402 Insufficient Balance");
    assert.equal(await vetoes(), 2);
    await turn("stop");
    await turn("error", "402 Insufficient Balance");
    assert.equal(await vetoes(), 2, "the error the board was last told is not told again");
    assert.equal((await errorRows()).length, 6);
  } finally {
    for (const [k, v] of Object.entries(was)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});
