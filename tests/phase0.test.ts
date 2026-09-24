// Two phase-0 promises no test held: a credential in a trace line is
// replaced before the line is written, and the console listens on this
// machine only unless told otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendEvent, EVENTS_REL, initSandbox } from "../extensions/protocol.ts";

test("a trace line that carries the pane's trace token or the console's token keeps neither", async () => {
  const root = await mkdtemp(join(tmpdir(), "p0-redact-"));
  const saved = { t: process.env.SWARM_TRACE_TOKEN, u: process.env.SWARM_UI_TOKEN, s: process.env.SWARM_TRACE_SOCKET };
  try {
    await initSandbox(root, { swarmId: "s1", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 5 });
    process.env.SWARM_TRACE_TOKEN = "trace-token-0123456789";
    process.env.SWARM_UI_TOKEN = "ui-token-abcdefghij";
    delete process.env.SWARM_TRACE_SOCKET;
    // An `env` a shell printed, whole, into a tool result.
    await appendEvent(root, { agent: "a0", tool: "bash", args: { command: "env" }, result: { output: "SWARM_TRACE_TOKEN=trace-token-0123456789\nSWARM_UI_TOKEN=ui-token-abcdefghij\n" } });
    const text = await readFile(join(root, EVENTS_REL), "utf8");
    assert.doesNotMatch(text, /trace-token-0123456789/);
    assert.doesNotMatch(text, /ui-token-abcdefghij/);
    assert.match(text, /\[secret SWARM_TRACE_TOKEN\]/);
    assert.match(text, /\[secret SWARM_UI_TOKEN\]/);
  } finally {
    for (const [k, v] of [["SWARM_TRACE_TOKEN", saved.t], ["SWARM_UI_TOKEN", saved.u], ["SWARM_TRACE_SOCKET", saved.s]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("the console listens on 127.0.0.1 unless it is told another address", async () => {
  const runs = await mkdtemp(join(tmpdir(), "p0-ui-"));
  const env: NodeJS.ProcessEnv = { ...process.env, SWARM_RUNS_DIR: runs };
  delete env.SWARM_UI_HOST;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "ui-server.ts"), "--port", "0"], { env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    let out = "";
    const url = await new Promise<string>((done, fail) => {
      const timer = setTimeout(() => fail(new Error(`the console printed no address: ${out}`)), 20_000);
      const onData = (d: Buffer) => {
        out += d.toString();
        const m = out.match(/https?:\/\/[^\s]+/);
        if (m) {
          clearTimeout(timer);
          done(m[0]);
        }
      };
      child.stdout.on("data", onData);
      child.stderr.on("data", onData);
    });
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+/, `the console's address: ${url}`);
  } finally {
    child.kill();
    await rm(runs, { recursive: true, force: true });
  }
});

test("the report says what was refused, or that it cannot know, and names where content went", async () => {
  const { egressRefusedLine, providersLine, custodyViolations } = await import("../scripts/report.ts");
  assert.equal(egressRefusedLine([["evil.example", 3], ["x.test", 1]], true, null), "evil.example (3), x.test");
  assert.equal(egressRefusedLine([], true, null), "nothing was refused");
  assert.match(egressRefusedLine([], false, { netguard: false }), /not observable: no egress control was running/);
  assert.match(egressRefusedLine([], false, null), /not observable: no netguard log was kept/);
  const vm = { isolation: { mode: "microvm" } };
  assert.match(egressRefusedLine([], false, vm), /refusal leaves no log; msb stopped no credential placeholder/);
  assert.match(egressRefusedLine([], false, { ...vm, netguard_mode: "microvm-open" }), /network was open/);
  const stopped = custodyViolations({ vms: [{ agent: "a0", secret_violations: [{ env: "OPENAI_API_KEY", host: "evil.example", method: "POST", path: "/x" }] }] });
  assert.deepEqual(stopped, ["a0 OPENAI_API_KEY → evil.example POST /x"]);
  assert.match(egressRefusedLine([], false, vm, stopped), /msb stopped 1 credential placeholder aimed at a host not its own: a0 OPENAI_API_KEY → evil\.example/);
  assert.equal(providersLine(null), "not recorded");
  assert.equal(
    providersLine({ providers: [{ model: "openai/gpt-5", hosts: ["api.openai.com"] }, { model: "ollama/q", local: true }, { model: "deepseek/d", hosts: ["api.deepseek.com"], role: "summary" }] }),
    "openai/gpt-5 → api.openai.com; ollama/q → this machine (local model); deepseek/d (the summary model self-compaction hands contexts to) → api.deepseek.com",
  );
});

test("the evidence check walks every file of a large set, not the first five thousand", async () => {
  const { mkdir, writeFile } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const { verifyInputs } = await import("../extensions/protocol.ts");
  const root = await mkdtemp(join(tmpdir(), "dfs-inputs-"));
  try {
    await initSandbox(root, { swarmId: "big", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 5 });
    const files: Array<{ path: string; bytes: number; sha256: string }> = [];
    for (let d = 0; d < 51; d++) {
      await mkdir(join(root, "inputs", `d${d}`), { recursive: true });
      for (let f = 0; f < 100; f++) {
        const text = `${d}/${f}\n`;
        await writeFile(join(root, "inputs", `d${d}`, `f${f}.txt`), text, { mode: 0o444 });
        files.push({ path: `inputs/d${d}/f${f}.txt`, bytes: text.length, sha256: createHash("sha256").update(text).digest("hex") });
      }
    }
    await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "x", copied_at: "t", files, bytes: 0 }));
    const check = await verifyInputs(root);
    assert.equal(check?.checked, 5100);
    assert.equal(check?.content_ok, true, `${check?.missing.length} missing, ${check?.added.length} added, ${check?.modified.length} modified`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a seat in a VM that loses its hub is told after a minute, once, and stopped after four; the hub's return forgets it", async () => {
  const { hubLostStep, HUB_LOST_STEER_MS, HUB_LOST_STOP_MS } = await import("../extensions/agent-swarm.ts");
  let s = { since: 0, told: false };
  const t0 = 1_000_000;
  let step = hubLostStep(s, false, t0);
  assert.deepEqual([step.steer, step.stop], [false, false]);
  s = step.state;
  step = hubLostStep(s, false, t0 + HUB_LOST_STEER_MS);
  assert.deepEqual([step.steer, step.stop], [true, false], "told at a minute");
  s = step.state;
  step = hubLostStep(s, false, t0 + HUB_LOST_STEER_MS + 1000);
  assert.equal(step.steer, false, "told once");
  s = step.state;
  step = hubLostStep(s, false, t0 + HUB_LOST_STOP_MS);
  assert.equal(step.stop, true, "stopped at four minutes");
  step = hubLostStep(step.state, true, t0 + HUB_LOST_STOP_MS + 1);
  assert.deepEqual(step.state, { since: 0, told: false }, "the hub's return forgets the loss");
});
