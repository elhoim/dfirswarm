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
