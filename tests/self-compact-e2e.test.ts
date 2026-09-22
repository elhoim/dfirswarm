/**
 * The self-compaction cycle through the real CLI (`pi --mode rpc`), the real
 * swarm extension and a scripted provider whose reported usage climbs every
 * turn: notice -> warning -> the lock refuses bash -> self_compact saves the
 * note and ends the run -> the compaction runs with our summary prompt once
 * the agent is idle -> the note comes back verbatim under the harness's
 * header -> the agent writes its result file. No key, no network, no money.
 *
 * Needs `pi` on PATH (0.87.0, the pinned version; the fake provider also
 * speaks 0.85.1's provider contract). Skips when it is not there.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { EVENTS_REL, initSandbox } from "../extensions/protocol.ts";
import { eventsOfType, messageText, RpcClient, type RpcEvent } from "./harness/rpc-client.ts";

const REPO = resolve(import.meta.dirname, "..");
const EXTENSION = join(REPO, "extensions", "agent-swarm.ts");
const FAKE = join(REPO, "tests", "fixtures", "self-compact-fake-provider.ts");
const HANDOFF = "self-compact-handoff";
const TOOLS = "read,bash,edit,write,post,inbox,wait,claim_file,release_file,claims,list_team,budget,file_history,file_restore,file_diff,thread_open,thread_join,inputs,name,record,ledger,done,self_compact";

/** With SC_KEEP=1 the sandboxes stay behind (rpc.log, fake-trace.jsonl, the session file) for a look. */
async function cleanup(d: Dir): Promise<void> {
  if (process.env.SC_KEEP === "1") {
    console.log(`kept ${d.root}`);
    return;
  }
  await rm(d.root, { recursive: true, force: true }).catch(() => undefined);
}

function haveCli(): boolean {
  try {
    execFileSync("pi", ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

type Dir = { root: string; sessionDir: string; logFile: string; traceFile: string };

async function makeSandbox(name: string): Promise<Dir> {
  const root = await mkdtemp(join(tmpdir(), `sc-e2e-${name}-`));
  await initSandbox(root, { reset: true });
  // Small retained history, so the scripted turns are compactable early.
  mkdirSync(join(root, ".pi"), { recursive: true });
  writeFileSync(join(root, ".pi", "settings.json"), JSON.stringify({ compaction: { enabled: true, reserveTokens: 16384, keepRecentTokens: 1500 } }, null, 2));
  mkdirSync(join(root, "work", "agent00"), { recursive: true });
  const sessionDir = join(root, ".pi-sessions", "agent00");
  mkdirSync(sessionDir, { recursive: true });
  return { root, sessionDir, logFile: join(root, "rpc.log"), traceFile: join(root, "fake-trace.jsonl") };
}

function args(d: Dir, tools = TOOLS): string[] {
  return ["--no-extensions", "--no-skills", "--no-prompt-templates", "--no-context-files", "-a", "-e", EXTENSION, "-e", FAKE, "--model", "fake/scripted", "--session-dir", d.sessionDir, "--tools", tools];
}

/** The note the scripted model handed off, from the fake's own request trace. */
function noteFromFakeTrace(d: Dir): string {
  const turns = readFileSync(d.traceFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { kind: string; plan?: { toolCall?: { name: string; arguments?: { note_to_self?: string } } } });
  return turns.find((r) => r.kind === "turn" && r.plan?.toolCall?.name === "self_compact")?.plan?.toolCall?.arguments?.note_to_self ?? "";
}

/** Notice at 40k, warning at 80k, compact at 100k on the fake's 200k window (no table row: the declared window is the ceiling). */
const ENV = {
  AGENT_ID: "agent00",
  SWARM_SELF_COMPACT: "1",
  SWARM_COMPACT_NOTICE_AT: "20%",
  SWARM_COMPACT_WARN_AT: "40%",
  SWARM_COMPACT_AT: "50%",
  SC_FAKE_WINDOW: "200000",
  SC_FAKE_BASE: "5000",
  SC_FAKE_STEP: "20000",
};

function trace(d: Dir): Array<Record<string, unknown>> {
  return readFileSync(join(d.root, EVENTS_REL), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

function toolEnds(events: RpcEvent[], toolName: string): RpcEvent[] {
  return eventsOfType(events, "tool_execution_end").filter((e) => e.toolName === toolName);
}

function resultText(e: RpcEvent): string {
  return messageText(e.result);
}

async function waitForCompletion(client: RpcClient): Promise<RpcEvent> {
  const handoff = await client.waitFor((e) => e.type === "message_end" && (e.message as { customType?: string })?.customType === HANDOFF, 90_000);
  const after = client.events.indexOf(handoff);
  await client.waitFor((e) => e.type === "tool_execution_end" && e.toolName === "write", 30_000, { since: after });
  await client.waitFor((e) => e.type === "agent_settled", 60_000, { since: after });
  return handoff;
}

test("lifecycle: notice, warning, lock, note, compaction with our prompt, verbatim note under the harness header, work resumes", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("lifecycle");
  const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
  try {
    const accepted = await client.request({ type: "prompt", message: "Start the scripted work." });
    assert.equal(accepted.success, true, JSON.stringify(accepted));
    const handoffEvent = await waitForCompletion(client);
    const events = client.events;

    // 1. The crossings are on the trace, in order, with the numbers.
    const rows = trace(d);
    const crossings = rows.filter((e) => /^compact_(notice|warning|forced)$/.test(String(e.tool))).map((e) => e.tool);
    assert.deepEqual(crossings.slice(0, 3), ["compact_notice", "compact_warning", "compact_forced"], `crossings: ${crossings.join(",")}`);
    const forced = rows.find((e) => e.tool === "compact_forced") as { result: { tokens: number; threshold: number; ceiling: number } };
    assert.equal(forced.result.ceiling, 200_000);
    assert.equal(forced.result.threshold, 100_000);
    assert.ok(forced.result.tokens >= 100_000);
    const config = rows.find((e) => e.tool === "compact_config") as { result: { ok: boolean; notice: number; warning: number; compact: number } };
    assert.deepEqual([config.result.ok, config.result.notice, config.result.warning, config.result.compact], [true, 40_000, 80_000, 100_000]);

    // 2. One context row per turn, climbing, with the level.
    const contexts = rows.filter((e) => e.tool === "context") as Array<{ result: { tokens: number; level: string; cycle: number } }>;
    assert.ok(contexts.length >= 5, `context rows: ${contexts.length}`);
    assert.ok(contexts.some((c) => c.result.level === "forced"));
    assert.ok(contexts.some((c) => c.result.cycle === 1), "a context row after the hand-off carries cycle 1");

    // 3. The lock refused an ordinary tool with a reason naming self_compact, and said so on the trace.
    const blocked = toolEnds(events, "bash").filter((e) => e.isError === true && /blocked by self-compact/.test(resultText(e)));
    assert.ok(blocked.length >= 1, "a bash call was refused by the lock");
    assert.match(resultText(blocked[0]!), /self_compact/);
    assert.ok(rows.some((e) => e.tool === "compact_hold" && (e.args as { tool?: string }).tool === "bash"), "the hold is on the trace");
    assert.ok(toolEnds(events, "bash").filter((e) => e.isError === false).length >= 3, "the scripted steps ran before the lock");

    // 4. The note was saved, the run ended, and the compaction ran once idle with our prompt.
    const saved = toolEnds(events, "self_compact");
    assert.equal(saved.length, 1);
    assert.equal(saved[0]!.isError, false);
    assert.match(resultText(saved[0]!), /Note saved/);
    const note = rows.find((e) => e.tool === "compact_note" && (e.result as { ok?: boolean }).ok === true) as { result: { cycle: number; level: string } };
    assert.equal(note.result.cycle, 1);
    const compactionStart = eventsOfType(events, "compaction_start")[0]!;
    assert.ok(eventsOfType(events, "agent_end").some((e) => events.indexOf(e) < events.indexOf(compactionStart)), "the run ended before the compaction started");
    const compactionEnd = eventsOfType(events, "compaction_end")[0]!;
    assert.equal(compactionEnd.aborted, false);
    const result = compactionEnd.result as { summary?: string; details?: { handoffId?: string; selfCompact?: { promptSource?: string; reason?: string } } };
    // The fake echoes the first 60 characters of the system prompt it was given.
    assert.match(result.summary ?? "", /^FAKE-SUMMARY\[You are the context-compaction summarizer for one agent in a\]/, "the summary call carried our prompt file");
    assert.ok(result.details?.handoffId, "the compaction carries the hand-off id");
    assert.equal(result.details?.selfCompact?.reason, "manual");
    const done = rows.find((e) => e.tool === "compact_done") as { args: { via: string; reason: string }; result: { cycle: number; tokens_after: number; tokens_before: number } };
    assert.deepEqual([done.args.via, done.args.reason, done.result.cycle], ["self", "manual", 1]);

    // 5. The note came back verbatim under the header, once, and the agent continued without a user message.
    const handoffText = messageText(handoffEvent.message);
    const expectedNote = noteFromFakeTrace(d);
    assert.ok(expectedNote.length > 10, "the fake's trace holds the note it handed off");
    assert.ok(handoffText.startsWith("[self-compact · handoff] cycle 1 · you are agent00"), handoffText.slice(0, 120));
    assert.match(handoffText, /Live claims: none\./);
    assert.match(handoffText, /Your note follows verbatim/);
    assert.ok(handoffText.endsWith(`\n---\n${expectedNote}`), "the note is the last thing in the message, byte for byte");
    const details = handoffEvent.message as { details?: { note?: string; cycle?: number } };
    assert.equal(details.details?.note, expectedNote);
    assert.equal(details.details?.cycle, 1);
    const persisted = eventsOfType(events, "message_end").map((e) => `${(e.message as { role?: string }).role}:${(e.message as { customType?: string }).customType ?? ""}`);
    assert.equal(persisted.filter((r) => r.startsWith("custom:")).length, 1, "the only persisted custom message is the hand-off; guidance never lands");
    assert.equal(persisted.filter((r) => r === "user:").length, 1, "the only user message is the prompt");

    // 6. Tools were restored and real work resumed in the agent's own scratch.
    const writes = toolEnds(events, "write");
    assert.ok(writes.length >= 1 && writes[0]!.isError === false, `write ran after the hand-off: ${writes.map((w) => resultText(w)).join(" | ")}`);
    assert.ok(events.indexOf(writes[0]!) > events.indexOf(handoffEvent));
    assert.equal(readFileSync(join(d.root, "work", "agent00", "result.txt"), "utf8").trim(), "done");

    // 7. The budget fold carries the level, the ceiling and the counts.
    const budget = JSON.parse(readFileSync(join(d.root, "budget.json"), "utf8")) as { agents: Record<string, { context_ceiling?: number; context_level?: string; compactions?: number; handoffs?: number; context_locked?: boolean }> };
    const slice = budget.agents.agent00;
    assert.equal(slice.context_ceiling, 200_000);
    assert.equal(slice.compactions, 1);
    assert.equal(slice.handoffs, 1);
    assert.equal(slice.context_locked, false);
    assert.ok(slice.context_level, "a level is recorded");
  } finally {
    await client.close();
    await cleanup(d);
  }
});

test("two cycles: the lines and the lock re-arm after a completed hand-off", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("two-cycles");
  const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SC_FAKE_CYCLES: "2", SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    const first = await client.waitFor((e) => e.type === "message_end" && (e.message as { customType?: string })?.customType === HANDOFF, 90_000);
    const second = await client.waitFor((e) => e.type === "message_end" && (e.message as { customType?: string })?.customType === HANDOFF, 120_000, { since: client.events.indexOf(first) + 1 });
    await client.waitFor((e) => e.type === "tool_execution_end" && e.toolName === "write", 30_000, { since: client.events.indexOf(second) });
    await client.waitFor((e) => e.type === "agent_settled", 60_000, { since: client.events.indexOf(second) });
    const rows = trace(d);
    assert.equal(rows.filter((e) => e.tool === "compact_forced").length, 2, "the compact line was crossed twice");
    assert.equal(rows.filter((e) => e.tool === "compact_done").length, 2);
    const cycles = rows.filter((e) => e.tool === "compact_done").map((e) => (e.result as { cycle: number }).cycle);
    assert.deepEqual(cycles, [1, 2]);
    const ids = [first, second].map((e) => (e.message as { details?: { id?: string } }).details?.id);
    assert.notEqual(ids[0], ids[1], "each cycle has its own hand-off id");
    assert.equal(readFileSync(join(d.root, "work", "agent00", "result.txt"), "utf8").trim(), "done");
    const budget = JSON.parse(readFileSync(join(d.root, "budget.json"), "utf8")) as { agents: Record<string, { handoffs?: number; compactions?: number }> };
    assert.equal(budget.agents.agent00.handoffs, 2);
    assert.equal(budget.agents.agent00.compactions, 2);
  } finally {
    await client.close();
    await cleanup(d);
  }
});

test("a failing summary falls back to Pi's own summarizer and the note still comes back", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("summary-fallback");
  // Two of our attempts fail; Pi's own summary call (the third summary request) succeeds.
  const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SC_FAKE_SUMMARY_FAIL: "2", SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    const handoff = await waitForCompletion(client);
    const rows = trace(d);
    const failed = rows.find((e) => e.tool === "compact_failed") as { args: { stage: string }; result: { fallback?: string } } | undefined;
    assert.ok(failed && failed.args.stage === "summary" && failed.result.fallback === "pi-summary", `our summary failure is on the trace with the fallback named: ${JSON.stringify(failed)}`);
    assert.ok(rows.some((e) => e.tool === "compact_done"), "the compaction still landed");
    assert.match(messageText(handoff.message), /Your note follows verbatim/);
    assert.equal(readFileSync(join(d.root, "work", "agent00", "result.txt"), "utf8").trim(), "done");
  } finally {
    await client.close();
    await cleanup(d);
  }
});

test("with self-compaction off nothing is locked and no self_compact tool exists", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("off");
  const off = { ...ENV, SWARM_SELF_COMPACT: "0", SC_FAKE_SCENARIO: "never-compact", SC_FAKE_TRACE: d.traceFile };
  const client = new RpcClient({ args: args(d, TOOLS.replace(",self_compact", "")), cwd: d.root, env: off, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    // Six scripted steps take the fake to 125k reported tokens; nothing may stop them.
    let seen = 0;
    const since = client.mark();
    for (let i = 0; i < 6; i++) {
      const e = await client.waitFor((ev) => ev.type === "tool_execution_end" && ev.toolName === "bash" && client.events.indexOf(ev) >= since + seen, 30_000, { since });
      seen = client.events.indexOf(e) - since + 1;
      assert.equal(e.isError, false, `step ${i + 1} ran: ${resultText(e).slice(0, 80)}`);
    }
    const rows = trace(d);
    assert.ok(!rows.some((e) => /^compact_/.test(String(e.tool)) || e.tool === "context"), "no self-compaction event of any kind");
    assert.ok(!existsSync(join(d.root, "work", "agent00", "result.txt")));
  } finally {
    await client.close();
    await cleanup(d);
  }
});

/** The fake's own request trace: every summary call, with the model it reached. */
function summaryCallsFromFakeTrace(d: Dir): Array<{ model?: string }> {
  return readFileSync(d.traceFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { kind: string; model?: string }).filter((r) => r.kind === "summary");
}

test("the summary goes to --compact-model when Pi knows it, and the record says which model wrote it", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("compact-model");
  const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SC_FAKE_SCENARIO: "obey-warning", SWARM_COMPACT_MODEL: "fake/summarizer", SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    await waitForCompletion(client);
    const rows = trace(d);
    const config = rows.find((e) => e.tool === "compact_config") as { args: { compact_model?: string }; result: { ok: boolean; summary_model?: string; summary_model_source?: string; summary_model_problem?: string } };
    assert.equal(config.args.compact_model, "fake/summarizer");
    assert.deepEqual([config.result.ok, config.result.summary_model, config.result.summary_model_source, config.result.summary_model_problem], [true, "fake/summarizer", "compact-model", undefined]);
    const done = rows.find((e) => e.tool === "compact_done") as { args: { via: string }; result: { summary_model?: string; summary_model_source?: string } };
    assert.deepEqual([done.args.via, done.result.summary_model, done.result.summary_model_source], ["self", "fake/summarizer", "compact-model"]);
    const calls = summaryCallsFromFakeTrace(d);
    assert.ok(calls.length >= 1 && calls.every((c) => c.model === "summarizer"), `every summary call reached the summarizer model: ${JSON.stringify(calls)}`);
    const compactionEnd = eventsOfType(client.events, "compaction_end")[0]!;
    assert.match(String((compactionEnd.result as { summary?: string }).summary ?? ""), /MODEL: summarizer$/, "the summary in the session is the summarizer's");
    assert.equal(readFileSync(join(d.root, "work", "agent00", "result.txt"), "utf8").trim(), "done", "work resumed after the hand-off");
  } finally {
    await client.close();
    await cleanup(d);
  }
});

test("a summary model Pi does not know falls back to the agent's own, and the config row says so", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("compact-model-missing");
  const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SC_FAKE_SCENARIO: "obey-warning", SWARM_COMPACT_MODEL: "fake/nope", SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    await waitForCompletion(client);
    const rows = trace(d);
    const config = rows.find((e) => e.tool === "compact_config") as { result: { ok: boolean; summary_model?: string; summary_model_source?: string; summary_model_problem?: string } };
    assert.deepEqual([config.result.ok, config.result.summary_model, config.result.summary_model_source], [true, "fake/scripted", "agent-model"]);
    assert.match(config.result.summary_model_problem ?? "", /fake\/nope is not in Pi's registry/);
    const done = rows.find((e) => e.tool === "compact_done") as { result: { summary_model?: string } };
    assert.equal(done.result.summary_model, "fake/scripted", "the compaction still ran, on the agent's own model");
    assert.ok(summaryCallsFromFakeTrace(d).every((c) => c.model === "scripted"));
    assert.equal(readFileSync(join(d.root, "work", "agent00", "result.txt"), "utf8").trim(), "done");
  } finally {
    await client.close();
    await cleanup(d);
  }
});

test("a bash result past Pi's bound: the whole output lands under tool-output/, the trace and the model's trailer name it", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("big-bash");
  const env = { ...ENV, SWARM_SELF_COMPACT: "0", SC_FAKE_SCENARIO: "never-compact", SC_FAKE_BIG_STEP: "1", SC_FAKE_TRACE: d.traceFile };
  const client = new RpcClient({ args: args(d, TOOLS.replace(",self_compact", "")), cwd: d.root, env, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    const first = await client.waitFor((ev) => ev.type === "tool_execution_end" && ev.toolName === "bash", 30_000);
    assert.equal(first.isError, false, resultText(first).slice(0, 200));
    // The trace row lands from the tool_result hook; give it a moment.
    type Ref = { path: string; bytes: number; lines: number; sha256: string };
    let row: { result: { output?: string; full_output?: Ref; view?: { truncated?: boolean; total_lines?: number } } } | undefined;
    for (let i = 0; i < 100 && !row; i++) {
      row = trace(d).find((e) => e.tool === "bash" && Boolean((e.result as { full_output?: unknown }).full_output)) as typeof row;
      if (!row) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(row, "a bash row with full_output is on the trace");
    const ref = row!.result.full_output!;
    assert.ok(ref.path.startsWith("tool-output/agent00/") && ref.path.endsWith(".out.log"), ref.path);
    assert.equal(ref.lines, 20_000);
    assert.equal(ref.bytes, 140_000);
    const onDisk = readFileSync(join(d.root, ref.path));
    assert.equal(onDisk.length, 140_000, "every byte the command printed is in the sandbox");
    assert.equal(onDisk.toString("utf8"), "filler\n".repeat(20_000));
    assert.equal(createHash("sha256").update(onDisk).digest("hex"), ref.sha256);
    assert.deepEqual([row!.result.view?.truncated, row!.result.view?.total_lines], [true, 20_000], "the row says what the model saw was a slice");
    const shown = resultText(first);
    assert.ok(shown.includes(`Full output: ${ref.path}]`), `the model's trailer names the sandbox record: ${shown.slice(-200)}`);
    assert.ok(!/pi-bash-/.test(shown), "the host's temp file is not what the model is told about");
    assert.equal(row!.result.output, shown, "the trace carries exactly what the model received, whole");
  } finally {
    await client.close();
    await cleanup(d);
  }
});
