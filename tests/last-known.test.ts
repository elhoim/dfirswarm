/**
 * A read made before every model call is served within its deadline: a hub
 * that is held for seconds costs a seat the deadline, not the hold.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { lastKnown } from "../extensions/last-known.ts";
import { factsWithin, HANDOFF_FACTS_MS } from "../extensions/self-compact.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("with the hub held ten seconds, a read answers within its deadline on the last value, and the newer value arrives for a later call", async () => {
  const lk = lastKnown<number>(50);
  assert.equal(await lk.read(async () => 1), 1, "a first read is waited for whole");
  let release!: (v: number) => void;
  const held = new Promise<number>((r) => (release = r));
  const t0 = Date.now();
  const gaps: number[] = [];
  for (let i = 0; i < 5; i += 1) {
    const s = Date.now();
    assert.equal(await lk.read(() => held), 1, "the last value the hub gave");
    gaps.push(Date.now() - s);
  }
  assert.ok(Math.max(...gaps) < 300, `each read took at most ${Math.max(...gaps)} ms`);
  assert.ok(Date.now() - t0 < 1500);
  assert.equal(lk.stale(), 5);
  release(2);
  await sleep(10);
  assert.equal(await lk.read(async () => 3), 3, "once the held read has ended, the next one is a new read");
  assert.ok((lk.age() ?? 1e9) < 1000);
});

test("only one read flies at a time; a first read that fails throws, a later failing one gives the last value", async () => {
  const lk = lastKnown<string>(30);
  await assert.rejects(lk.read(async () => { throw new Error("hub down"); }), /hub down/);
  let calls = 0;
  const slow = async () => { calls += 1; await sleep(80); return "a"; };
  const [x, y] = await Promise.all([lk.read(slow), lk.read(slow)]);
  assert.deepEqual([x, y], ["a", "a"]);
  assert.equal(calls, 1, "two callers share the one read");
  assert.equal(await lk.read(async () => { throw new Error("hub down again"); }), "a");
  assert.equal(lk.age() !== null, true);
});

test("a hand-off does not wait for a hub that is held: past its bound the facts are unknown, and a hub that answers in time is used", async () => {
  const known = { claims: [], unread: { main: 2 }, ledgerTotal: 9, ledgerMine: 3, sentinel: false, spentUsd: 0 };
  assert.deepEqual(await factsWithin(async () => known, 50), known);
  const t0 = Date.now();
  const late = await factsWithin(() => new Promise((r) => setTimeout(() => r(known), 2000)), 50);
  assert.ok(Date.now() - t0 < 500, `the hand-off waited ${Date.now() - t0} ms`);
  assert.equal(late.unknown, true);
  assert.equal((await factsWithin(async () => { throw new Error("hub down"); }, 50)).unknown, true);
  assert.ok(HANDOFF_FACTS_MS <= 5000, "a hand-off is at most five seconds behind its compaction");
});

test("reads given what is left of one deadline end together: a held read costs the deadline once, and a late one is not waited on again", async () => {
  const budget = lastKnown<number>(1000);
  const sentinel = lastKnown<boolean>(1000);
  await budget.read(async () => 1);
  await sentinel.read(async () => false);
  const never = () => new Promise<never>(() => undefined);
  const t0 = Date.now();
  const until = Date.now() + 200;
  const left = () => Math.max(0, until - Date.now());
  const s = sentinel.read(never, left());
  assert.equal(await budget.read(never, left()), 1);
  assert.equal(await budget.read(never, left()), 1);
  assert.equal(await s, false);
  const spent = Date.now() - t0;
  assert.ok(spent < 450, `three reads on a held hub took ${spent} ms, one deadline of 200`);
  const t1 = Date.now();
  assert.equal(await budget.read(never), 1, "a read already late gives the last value at once");
  assert.ok(Date.now() - t1 < 50, `${Date.now() - t1} ms`);
});

/**
 * The seat's real `context` hook (extensions/agent-swarm.ts) through Pi's loader, against a stand-in hub on the seat's
 * board socket that answers the budget and the sentinel, and is then held for ten seconds the way a busy hub loop is.
 */
test("Pi loader: with the hub held ten seconds, the model calls' gap before the call has a median under 0.3 s and none waits past one deadline", { timeout: 60_000 }, async (t) => {
  const { access, mkdtemp, rm } = await import("node:fs/promises");
  const { createServer } = await import("node:net");
  const { tmpdir } = await import("node:os");
  const { join, resolve } = await import("node:path");
  const REPO = resolve(import.meta.dirname, "..");
  const loaderPath = join(process.env.PI_PACKAGE_DIR ?? join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"), "dist", "core", "extensions", "loader.js");
  if (!(await access(loaderPath).then(() => true, () => false))) return t.skip("Pi package not found");
  const P = await import("../extensions/protocol.ts");
  const { closeBoardClients } = await import("../extensions/board.ts");
  const { PRECALL_DEADLINE_MS } = await import("../extensions/agent-swarm.ts");
  const root = await mkdtemp(join(tmpdir(), "lk-"));
  const S = join(root, "run");
  await P.initSandbox(S, { reset: true, agentIds: ["agent00"] });
  const record = await P.readBudget(S);
  let held: Promise<void> | null = null;
  let release: () => void = () => undefined;
  const asked: string[] = [];
  const open = new Set<import("node:net").Socket>();
  const server = createServer((socket) => {
    open.add(socket);
    socket.on("close", () => open.delete(socket));
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("error", () => undefined);
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        const msg = JSON.parse(line) as { t?: string; id?: number; fn?: string };
        if (msg.t !== "rpc") continue;
        asked.push(String(msg.fn));
        const result = msg.fn === "readBudget" ? record : msg.fn === "swarmDoneExists" ? false : null;
        const answer = () => socket.write(`${JSON.stringify({ id: msg.id, ok: true, result })}\n`);
        if (held) void held.then(answer);
        else answer();
      }
    });
  });
  const sock = join(root, "h.sock");
  await new Promise<void>((r) => server.listen(sock, r));
  const keys = ["AGENT_ID", "SWARM_BOARD_SOCKET", "SWARM_TRACE_SOCKET", "SWARM_SELF_COMPACT", "SWARM_SEAT_TOKEN"];
  const was = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.AGENT_ID = "agent00";
  process.env.SWARM_BOARD_SOCKET = sock;
  for (const k of ["SWARM_TRACE_SOCKET", "SWARM_SELF_COMPACT", "SWARM_SEAT_TOKEN"]) delete process.env[k];
  try {
    const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, Array<(e: unknown, c: unknown) => Promise<unknown>>> }>; errors: unknown[] }> };
    const out = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], S);
    assert.deepEqual(out.errors, []);
    const hooks = out.extensions[0]!.handlers.get("context") ?? [];
    let aborted = 0;
    const ctx = { cwd: S, hasUI: false, ui: {}, abort: () => void aborted++, shutdown: () => undefined };
    const call = async () => {
      const s = Date.now();
      for (const h of hooks) await h({ type: "context", messages: [] }, ctx);
      return Date.now() - s;
    };
    await call();
    assert.ok(asked.includes("readBudget") && asked.includes("swarmDoneExists"), `the hook read the budget and the sentinel from the hub: ${asked.join(", ")}`);
    // The hub loop is held ten seconds; the seat goes on making model calls, half a second of model time apart.
    held = new Promise<void>((r) => (release = r));
    const holdUntil = Date.now() + 10_000;
    const gaps: number[] = [];
    while (Date.now() < holdUntil - 600) {
      gaps.push(await call());
      await new Promise((r) => setTimeout(r, 500));
    }
    const sorted = [...gaps].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)]!;
    assert.ok(gaps.length >= 8, `${gaps.length} calls in the hold`);
    assert.ok(median < 300, `the median gap was ${median} ms (gaps ${gaps.join(", ")})`);
    assert.ok(Math.max(...gaps) < PRECALL_DEADLINE_MS + 500, `no call waited past one deadline: the longest gap was ${Math.max(...gaps)} ms, the deadline ${PRECALL_DEADLINE_MS}`);
    assert.equal(aborted, 0, "no call was held back");
    held = null;
    release();
    await new Promise((r) => setTimeout(r, 100));
    assert.ok((await call()) < 300, "a free hub again answers in time");
  } finally {
    held = null;
    release();
    closeBoardClients();
    // The extension Pi loaded has its own board client (its own module instance): the hub's end of the link is closed here.
    for (const socket of open) socket.destroy();
    await new Promise<void>((r) => server.close(() => r()));
    for (const [k, v] of Object.entries(was)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    const { execFileSync } = await import("node:child_process");
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});
