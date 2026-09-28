/**
 * The stop policy under review (Astra's review of WP2): each case below
 * failed on the code before its fix.
 *
 * - An extension checks the run's end under the lock a stop takes: a stop,
 *   the harness's or the operator's, that won the race is not undone.
 * - The model call during which the pause is written is held too.
 * - A compaction, which calls the provider itself, is held while the run is
 *   paused: no attempt, no retry and no fallback goes out.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";

const REPO = resolve(import.meta.dirname, "..");

async function findLoader(): Promise<string | null> {
  const candidates: string[] = [];
  if (process.env.PI_PACKAGE_DIR) candidates.push(process.env.PI_PACKAGE_DIR);
  try {
    candidates.push(join(execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim(), "@earendil-works", "pi-coding-agent"));
  } catch {
    // npm missing
  }
  candidates.push(join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"));
  for (const dir of candidates) {
    const loader = join(dir, "dist", "core", "extensions", "loader.js");
    try {
      await access(loader);
      return loader;
    } catch {
      // next
    }
  }
  return null;
}

async function sandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "stop-review-"));
  await P.initSandbox(root, { reset: true, agentIds: ["agent00"], capUsd: 1, wallClockMinutes: 60 });
  return root;
}

async function over(root: string, o: { steerMinutesAgo: number }): Promise<void> {
  const b = await P.readBudget(root);
  await P.writeBudget(root, { ...b, stop_policy: "cap-pause", spent_usd: 2, stop_steer_at: new Date(Date.now() - o.steerMinutesAgo * 60_000).toISOString(), stop_reason: "cap", cap_steer_sent: true });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("an extension checks the run's end under the lock a stop takes: a stop that won the race is not undone", async () => {
  const root = await sandbox();
  try {
    await over(root, { steerMinutesAgo: 5 });
    await P.pauseRun(root, "cap", "the cap passed");
    // A cap-stop takes the lock first and writes the sentinel while the extension waits for it.
    let release: () => void = () => undefined;
    const holding = new Promise<void>((r) => (release = r));
    const stop = P.withTableLock(root, async () => {
      await sleep(150);
      await mkdir(join(root, "done"), { recursive: true });
      await writeFile(join(root, P.SENTINEL_REL), "---\nby: harness\nreason: cap\noutcome: stopped\n---\n");
      await holding;
    });
    await sleep(50);
    const extend = P.extendRun(root, { usd: 5 }, "operator");
    await sleep(200);
    release();
    await stop;
    await assert.rejects(extend, /the run is finished/);
    assert.equal((await P.readBudget(root)).cap_usd, 1, "the caps are as the stop left them");
    // The operator's stop (done/STOPPED) is an end too.
    await rm(join(root, P.SENTINEL_REL));
    await P.markStopped(root, "operator", "swarm.sh stop");
    await assert.rejects(P.extendRun(root, { usd: 5 }, "operator"), /the run was stopped \(done\/STOPPED exists\)/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

type LoadedExtension = { path: string; tools: Map<string, unknown>; handlers: Map<string, Array<(event: unknown, ctx: unknown) => Promise<unknown>>> };

async function loaded(t: { skip: (why: string) => void }, root: string, env: Record<string, string>): Promise<{ fire: (name: string, event: unknown, ctx: unknown) => Promise<unknown>; restore: () => void } | null> {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found");
    return null;
  }
  const keys = ["AGENT_ID", "SWARM_BOARD_SOCKET", "SWARM_TRACE_SOCKET", "SWARM_SELF_COMPACT", ...Object.keys(env)];
  const was = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.AGENT_ID = "agent00";
  delete process.env.SWARM_BOARD_SOCKET;
  delete process.env.SWARM_TRACE_SOCKET;
  delete process.env.SWARM_SELF_COMPACT;
  Object.assign(process.env, env);
  const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }> };
  const out = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
  assert.deepEqual(out.errors, []);
  const [swarm] = out.extensions;
  return {
    fire: async (name, event, ctx) => {
      let r: unknown;
      for (const h of swarm.handlers.get(name) ?? []) r = (await h(event, ctx)) ?? r;
      return r;
    },
    restore: () => {
      for (const [k, v] of Object.entries(was)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    },
  };
}

test("Pi loader: the model call during which the pause is written does not go out", async (t) => {
  const root = await sandbox();
  const pi = await loaded(t, root, {});
  if (!pi) return;
  try {
    await over(root, { steerMinutesAgo: 5 });
    let aborted = 0;
    let shut = 0;
    const ctx = { cwd: root, hasUI: false, ui: {}, abort: () => void aborted++, shutdown: () => void shut++ };
    await pi.fire("context", { type: "context", messages: [] }, ctx);
    assert.ok((await P.readBudget(root)).paused, "this call's check wrote the pause");
    assert.equal(aborted, 1, "and the call that wrote it is held");
    assert.equal(shut, 0, "the seat stays");
  } finally {
    pi.restore();
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi loader: a compaction is held while the run is paused: no attempt, no retry and no fallback calls the provider", async (t) => {
  const root = await sandbox();
  const pi = await loaded(t, root, { SWARM_SELF_COMPACT: "1" });
  if (!pi) return;
  try {
    await over(root, { steerMinutesAgo: 5 });
    assert.equal((await P.pauseRun(root, "cap", "the cap passed")).paused, true);
    let calls = 0;
    const ctx = {
      cwd: root,
      hasUI: false,
      ui: {},
      model: { provider: "p", id: "m", maxTokens: 1000, contextWindow: 100_000 },
      modelRegistry: {
        stream: () => {
          calls++;
          throw new Error("the provider was called");
        },
        find: () => undefined,
      },
    };
    const event = {
      type: "session_before_compact",
      reason: "manual",
      preparation: { messagesToSummarize: [], turnPrefixMessages: [], previousSummary: undefined, fileOps: { read: new Set(), written: new Set(), edited: new Set() }, firstKeptEntryId: "e1", tokensBefore: 1000 },
      signal: new AbortController().signal,
      customInstructions: undefined,
    };
    const out = (await pi.fire("session_before_compact", event, ctx)) as { cancel?: boolean } | undefined;
    assert.equal(calls, 0, "no summary attempt went out");
    assert.equal(out?.cancel, true, "and Pi's own summarizer is not left to run in its place");
    const events = (await readFile(join(root, P.EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as { tool: string; args: Record<string, unknown> });
    assert.ok(events.some((e) => e.tool === "compact_held" && e.args.reason === "cap"), "said on the trace");
    // Extended, the compaction goes on as usual (here, to the stand-in provider).
    await P.extendRun(root, { usd: 5 }, "operator");
    await pi.fire("session_before_compact", event, ctx);
    assert.ok(calls > 0, "the summary is attempted once the pause is lifted");
  } finally {
    pi.restore();
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});
