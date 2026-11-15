/**
 * A shell call in a seat's own VM has a limit (extensions/agent-swarm.ts
 * shellTimeout): one that names no timeout gets the harness's default, one
 * that names more than the most gets the most, and one stopped there is told
 * that longer work is a job. Pi's bash has no limit of its own: a seat of the
 * run s082123 waited 178 minutes on a call that never returned, and the
 * nudger leaves a working seat alone.
 */
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";
import { READY_COMMAND_MAX, readyJobRun, SHELL_TIMEOUT_DEFAULT_S, SHELL_TIMEOUT_MAX_S, shellTimeout, shellTimeoutNote, sleepLoopOverJobs } from "../extensions/agent-swarm.ts";
import extension from "../extensions/agent-swarm.ts";
import { initSandbox, WAIT_MAX_SECONDS } from "../extensions/protocol.ts";

const REPO = resolve(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

test("the limit: the default for a call that names none, the most for one that names more, the call's own otherwise; both can be set", () => {
  assert.deepEqual(shellTimeout(undefined, {}), { seconds: SHELL_TIMEOUT_DEFAULT_S, why: "default" });
  assert.deepEqual(shellTimeout(0, {}), { seconds: SHELL_TIMEOUT_DEFAULT_S, why: "default" });
  assert.deepEqual(shellTimeout("60", {}), { seconds: SHELL_TIMEOUT_DEFAULT_S, why: "default" }, "not a number: the default");
  assert.deepEqual(shellTimeout(60, {}), { seconds: 60, why: null });
  assert.deepEqual(shellTimeout(100000, {}), { seconds: SHELL_TIMEOUT_MAX_S, why: "capped", asked: 100000 });
  assert.deepEqual(shellTimeout(undefined, { SWARM_SHELL_TIMEOUT_S: "120" }), { seconds: 120, why: "default" });
  assert.deepEqual(shellTimeout(undefined, { SWARM_SHELL_TIMEOUT_S: "5000", SWARM_SHELL_TIMEOUT_MAX_S: "600" }), { seconds: 600, why: "default" }, "the default is never over the most");
  assert.match(shellTimeoutNote({ seconds: 900, why: "default" }), /names no timeout has the harness's limit of 900 s\. Run longer work as a job \(job_run/);
  assert.match(shellTimeoutNote({ seconds: 1800, why: "capped", asked: 7200 }), /the 7200 s it asked for is over the harness's limit of 1800 s/);
});

test("the default is two minutes; a shell loop that sleeps to wait on a job is refused and pointed at wait, and at job_status for where it stands", () => {
  assert.equal(SHELL_TIMEOUT_DEFAULT_S, 120);
  assert.match(shellTimeoutNote({ seconds: 120, why: "default" }), /job_run with the same command.*names its own timeout, up to 1800 s/);
  for (const [loop, id] of [
    ["while ! grep -q done store/jobs/j000097/stdout.log; do sleep 30; done", "j000097"],
    ["for i in $(seq 1 20); do ls store/jobs/j000040/out 2>/dev/null && break; sleep 15; done", "j000040"],
    ["until [ -f store/jobs/j000012/manifest.json ]; do\n  sleep 5\ndone", "j000012"],
    ["while true; do echo waiting for j000218; sleep 60; done", "j000218"],
  ] as const) {
    const said = sleepLoopOverJobs(loop) ?? "";
    assert.ok(said.includes(`send wait({"seconds":${WAIT_MAX_SECONDS}}) instead. It sleeps at no cost and wakes on the post tagged result that says a job is done`), loop);
    assert.ok(said.includes(`job_status({"job_id":"${id}"}) says where it stands now`), loop);
    assert.doesNotMatch(said, /wait_seconds|job_status[^.]*waits/, "job_status is never said to wait");
  }
  assert.match(sleepLoopOverJobs("while [ ! -s store/jobs/j000001/out/a ] || [ ! -s store/jobs/j000002/out/b ]; do sleep 10; done") ?? "", /job_status\(\{"job_id":"j000001"\}\) and job_status\(\{"job_id":"j000002"\}\) say where each job stands now/, "each job the loop names");
  assert.match(sleepLoopOverJobs("while ! ls store/jobs/*/out/done; do sleep 5; done") ?? "", /job_status\(\{"job_id":"<the job's id>"\}\)/, "a loop that names no job");
  for (const fine of ["sleep 2; ls work/", "for f in work/*.bin; do xxd $f | head -2; done", "while read l; do echo $l; done < store/jobs/j000001/out/list.txt", "grep -r needle store/jobs/j000003/out | head", 42, undefined]) {
    assert.equal(sleepLoopOverJobs(fine), null, String(fine));
  }
});

/** Each `name({...})` call a text holds: the tool it names and the keys of its argument object. */
function readyCalls(text: string): Array<{ call: string; tool: string; args: Record<string, unknown> }> {
  const calls: Array<{ call: string; tool: string; args: Record<string, unknown> }> = [];
  for (const m of text.matchAll(/\b([a-z_]+)\(\{/g)) {
    const start = m.index! + m[1]!.length + 1;
    let depth = 0;
    let inString = false;
    let escaped = false;
    let end = -1;
    for (let i = start; i < text.length && end < 0; i++) {
      const ch = text[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === '"') inString = false;
      } else if (ch === '"') inString = true;
      else if (ch === "{") depth++;
      else if (ch === "}" && --depth === 0) end = i;
    }
    assert.ok(end > 0, `the call at ${m.index} closes: ${text.slice(m.index!, m.index! + 120)}`);
    const body = text.slice(start, end + 1);
    let args: Record<string, unknown>;
    try {
      args = JSON.parse(body) as Record<string, unknown>;
    } catch {
      // A command too long to repeat is named by its length: the keys are still the call's.
      args = Object.fromEntries([...body.matchAll(/"([a-z_]+)"\s*:/g)].map((k) => [k[1]!, "<named>"]));
    }
    calls.push({ call: `${m[1]}(${body})`, tool: m[1]!, args });
  }
  return calls;
}

type Schema = { properties: Record<string, { maximum?: number }>; required?: string[] };
/** The extension loaded against a stand-in for Pi that only records the tools it registers. */
function registered(): Map<string, Schema> {
  const tools = new Map<string, Schema>();
  const base: Record<string, unknown> = { registerTool: (t: { name: string; parameters: Schema }) => tools.set(t.name, t.parameters) };
  const pi = new Proxy(base, { get: (target, key) => (key in target ? target[key as string] : () => undefined) });
  const saved = process.env.AGENT_ID;
  process.env.AGENT_ID = "agent00";
  try {
    extension(pi as never);
  } finally {
    if (saved === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = saved;
  }
  return tools;
}

test("every ready call the harness prints in a refusal names a registered tool and only parameters its schema declares", () => {
  const tools = registered();
  const texts = [
    ...["while ! grep -q done store/jobs/j000097/stdout.log; do sleep 30; done", "while [ ! -s store/jobs/j000001/out/a ] || [ ! -s store/jobs/j000002/out/b ]; do sleep 10; done", "while ! ls store/jobs/*/out/done; do sleep 5; done"].map((l) => sleepLoopOverJobs(l)!),
    shellTimeoutNote({ seconds: 120, why: "default" }, "python3 tools/x/run.py --in 'a b' > work/a0/out.txt"),
    shellTimeoutNote({ seconds: 1800, why: "capped", asked: 99999 }, "sleep 1"),
    shellTimeoutNote({ seconds: 120, why: "default" }),
    shellTimeoutNote({ seconds: 120, why: "default" }, `echo ${"x".repeat(READY_COMMAND_MAX)}`),
  ];
  const seen = new Set<string>();
  for (const text of texts) {
    const calls = readyCalls(text);
    assert.ok(calls.length > 0, `a ready call in: ${text.slice(0, 120)}`);
    for (const { call, tool, args } of calls) {
      seen.add(tool);
      const schema = tools.get(tool);
      assert.ok(schema, `${call}: ${tool} is a registered tool`);
      for (const key of Object.keys(args)) assert.ok(key in schema!.properties, `${call}: ${tool} declares ${key} (it declares ${Object.keys(schema!.properties).join(", ")})`);
      for (const key of schema!.required ?? []) assert.ok(key in args, `${call}: ${tool} requires ${key}`);
    }
  }
  assert.deepEqual([...seen].sort(), ["job_run", "job_status", "wait"]);
  // The wait the refusal names is one the tool takes whole.
  assert.ok(texts[0]!.includes(`wait({"seconds":${WAIT_MAX_SECONDS}})`));
  assert.match(tools.get("wait")!.properties.seconds ? JSON.stringify(tools.get("wait")!.properties.seconds) : "", new RegExp(`max ${WAIT_MAX_SECONDS}\\b`));
});

test("a call stopped at its limit is told the job_run call that runs it as a job, ready to send", () => {
  const command = "python3 tools/x/run.py --in 'inputs/a b.img' > work/a0/out.txt";
  const note = shellTimeoutNote({ seconds: 120, why: "default" }, command);
  const ready = /Ready to send: (job_run\((.*)\))\. A job runs/.exec(note);
  assert.ok(ready, note);
  assert.deepEqual(JSON.parse(ready![2]!), { command, timeout_seconds: 900 }, "the same command, whole, with a job's default limit");
  assert.match(note, /writes only under \$OUT: point the command's outputs there, and list what it reads in inputs/);
  // A call that asked for more than the shell's most: the job gets what it asked for, up to a job's own most.
  assert.equal(readyJobRun("sleep 1", { seconds: 1800, why: "capped", asked: 7200 }), 'job_run({"command":"sleep 1","timeout_seconds":7200})');
  assert.equal(readyJobRun("sleep 1", { seconds: 1800, why: "capped", asked: 99999 }), 'job_run({"command":"sleep 1","timeout_seconds":14400})');
  const long = `echo ${"x".repeat(READY_COMMAND_MAX)}`;
  assert.equal(readyJobRun(long, { seconds: 120, why: "default" }), `job_run({"command": <the same command, ${long.length} characters>, "timeout_seconds": 900})`);
  assert.match(shellTimeoutNote({ seconds: 120, why: "default" }), /Ready to send: job_run\(\{"command":"<the same command>","timeout_seconds":900\}\)/, "no command at hand: the form");
});

async function findLoader(): Promise<string | null> {
  const loader = join(process.env.PI_PACKAGE_DIR ?? join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"), "dist", "core", "extensions", "loader.js");
  return access(loader).then(() => loader, () => null);
}

test("through the extension: the call's input gets the limit before it runs, and a call stopped at a limit the harness set is told so, on the trace too", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR, or npm install)");
    return;
  }
  const S = await mkdtemp(join(tmpdir(), "shell-timeout-"));
  dirs.push(S);
  await initSandbox(S, { reset: true });
  const keep = process.env.AGENT_ID;
  process.env.AGENT_ID = "agent00";
  try {
    const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, Array<(e: unknown, c: unknown) => Promise<unknown>>> }>; errors: unknown[] }> };
    const out = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], S);
    assert.deepEqual(out.errors, []);
    const handlers = out.extensions[0]!.handlers;
    const ctx = { cwd: S, hasUI: false, ui: {}, abort: () => undefined, shutdown: () => undefined, sessionManager: { getEntries: () => [], buildContextEntries: () => [], getBranch: () => [] } };
    const fire = async (event: string, payload: Record<string, unknown>) => {
      const outs: unknown[] = [];
      for (const h of handlers.get(event) ?? []) outs.push(await h({ type: event, ...payload }, ctx));
      return outs;
    };
    const none: Record<string, unknown> = { command: "sleep 100000" };
    await fire("tool_call", { toolName: "bash", toolCallId: "c1", input: none });
    assert.equal(none.timeout, SHELL_TIMEOUT_DEFAULT_S, "a call that names none is given the default");
    const long: Record<string, unknown> = { command: "sleep 100000", timeout: 100000 };
    await fire("tool_call", { toolName: "bash", toolCallId: "c2", input: long });
    assert.equal(long.timeout, SHELL_TIMEOUT_MAX_S);
    const own: Record<string, unknown> = { command: "ls", timeout: 30 };
    await fire("tool_call", { toolName: "bash", toolCallId: "c3", input: own });
    assert.equal(own.timeout, 30);
    // Stopped at the limit the harness set: the note comes after Pi's own words.
    const outs = await fire("tool_result", { toolName: "bash", toolCallId: "c1", input: none, isError: true, content: [{ type: "text", text: `Command timed out after ${SHELL_TIMEOUT_DEFAULT_S} seconds` }] });
    const content = (outs.find((o) => o && typeof o === "object" && "content" in (o as object)) as { content: Array<{ text: string }> } | undefined)?.content ?? [];
    assert.match(content.map((c) => c.text).join("\n"), /Command timed out after 120 seconds\nThe call was stopped at its limit: a shell call in your VM that names no timeout has the harness's limit of 120 s/);
    assert.ok(content.map((c) => c.text).join("\n").includes('Ready to send: job_run({"command":"sleep 100000","timeout_seconds":900})'), "the call's own command, as a job");
    const rows = (await readFile(join(S, "traces", "events.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as { tool: string; result: Record<string, unknown> });
    assert.ok(rows.some((r) => r.tool === "shell_timeout" && r.result.seconds === 120 && r.result.why === "default"));
    // A call the model gave its own limit, stopped there: nothing added.
    const mine = await fire("tool_result", { toolName: "bash", toolCallId: "c3", input: own, isError: true, content: [{ type: "text", text: "Command timed out after 30 seconds" }] });
    assert.ok(!JSON.stringify(mine).includes("stopped at its limit"));
  } finally {
    if (keep === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = keep;
  }
});
