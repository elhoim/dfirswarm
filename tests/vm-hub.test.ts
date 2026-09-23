/**
 * The hub is the board's only writer for agents in microVMs, and who is
 * asking is decided by the socket a request arrives on. These tests run the
 * hub in-process against a real sandbox and talk to it the way the
 * extension in a VM does (extensions/board.ts), with a stand-in collector.
 */
import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { connect, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as board from "../extensions/board.ts";
import { emptyAgentBudget, initSandbox, readPost, SENTINEL_REL } from "../extensions/protocol.ts";
import { boardTable, Hub } from "../scripts/vm-hub.ts";

const cleanups: Array<() => Promise<unknown>> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

async function setup(options: { agents?: string[]; settleMs?: number; wall?: number } = {}) {
  const agents = options.agents ?? ["a0", "a1"];
  const sandbox = await mkdtemp(join(tmpdir(), "dfs-hub-sbx-"));
  await initSandbox(sandbox, { swarmId: "t1", agentIds: agents, capUsd: 5, wallClockMinutes: options.wall ?? 30 });
  const dir = await mkdtemp(join(tmpdir(), "dfh-"));
  const lines: Record<string, unknown>[] = [];
  const collectorPath = join(dir, "col.sock");
  const collector: Server = createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        lines.push(JSON.parse(buffer.slice(0, cut)));
        buffer = buffer.slice(cut + 1);
        socket.write('{"ok":true}\n');
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((r) => collector.listen(collectorPath, () => r()));
  const hub = new Hub({
    sandbox,
    dir,
    agents,
    tokens: Object.fromEntries([...agents.map((a) => [a, `token-${a}`]), ["system", "token-system"]]),
    collector: collectorPath,
    backstop: false,
    quiet: true,
    settleMs: options.settleMs ?? 0,
    herdrBin: "/usr/bin/false",
  });
  await hub.start();
  cleanups.push(async () => {
    await hub.stop();
    collector.close();
    await rm(sandbox, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  });
  return { hub, sandbox, dir, lines, agents };
}

/** One raw line to a socket, and the first line back (or the close). */
function exchange(socketPath: string, body: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let answer = "";
    socket.setEncoding("utf8");
    socket.on("error", reject);
    socket.on("data", (chunk: string) => {
      answer += chunk;
      const cut = answer.indexOf("\n");
      if (cut >= 0) {
        socket.destroy();
        resolve(JSON.parse(answer.slice(0, cut)));
      }
    });
    socket.on("close", () => resolve(answer ? JSON.parse(answer.trim()) : {}));
    socket.on("connect", () => socket.write(`${JSON.stringify(body)}\n`));
  });
}

test("the hub answers exactly the functions the extension sends it", () => {
  const table = boardTable({ sandbox: "/nowhere", settle: async () => undefined, wrote: () => undefined });
  assert.deepEqual(Object.keys(table).sort(), [...board.REMOTE_FUNCTIONS].sort());
});

test("a post is the channel's agent's, whatever the context in the request says", async () => {
  const { hub, sandbox } = await setup();
  const forged = { sandboxRoot: "/somewhere/else", agentId: "a1" };
  const post = (await board.callBoard(hub.socketFor("a0"), "postMessage", [forged, { tag: "intro", body: "hello from a0", via: "a1" }])) as {
    from: string;
    path: string;
    via?: string;
  };
  assert.equal(post.from, "a0", "the socket is a0's, so the post is a0's");
  assert.equal(post.via, undefined, "an agent cannot set via on its own post");
  assert.ok(post.path.startsWith(sandbox), "written into the hub's sandbox, not the path the request named");
  const onDisk = await readPost(post.path);
  assert.equal(onDisk.from, "a0");
});

test("a harness post sent from a VM says which agent's harness said it", async () => {
  const { hub } = await setup();
  const post = (await board.callBoard(hub.socketFor("a1"), "systemPost", ["/x", { tag: "veto", body: "CLAIM VIOLATION" }])) as {
    from: string;
    via?: string;
    path: string;
  };
  assert.equal(post.from, "system");
  assert.equal(post.via, "a1");
  assert.equal((await readPost(post.path)).via, "a1", "and the file on the board carries it");
});

test("the extension's board functions go to the hub when SWARM_BOARD_SOCKET is set, and run locally when it is not", async () => {
  const { hub, sandbox } = await setup();
  const previous = process.env.SWARM_BOARD_SOCKET;
  try {
    process.env.SWARM_BOARD_SOCKET = hub.socketFor("a1");
    const viaHub = await board.postMessage({ sandboxRoot: sandbox, agentId: "a0" }, { tag: "ask", body: "through the hub" });
    assert.equal(viaHub.from, "a1", "through the hub the caller is the socket's agent");
    const claim = await board.claimFile({ sandboxRoot: sandbox, agentId: "a0" }, "work/notes.md", { reason: "writing notes" });
    assert.equal(claim.ok, true);
    assert.equal((await board.heldBy({ sandboxRoot: sandbox, agentId: "a0" }, "work/notes.md"))?.owner, "a1");
    delete process.env.SWARM_BOARD_SOCKET;
    const local = await board.postMessage({ sandboxRoot: sandbox, agentId: "a0" }, { tag: "ask", body: "locally" });
    assert.equal(local.from, "a0", "on the host the context decides, as it always has");
  } finally {
    if (previous === undefined) delete process.env.SWARM_BOARD_SOCKET;
    else process.env.SWARM_BOARD_SOCKET = previous;
  }
});

test("a protocol error comes back as the protocol's own message", async () => {
  const { hub } = await setup();
  await assert.rejects(
    board.callBoard(hub.socketFor("a0"), "postMessage", [null, { tag: "nonsense", body: "x" }]),
    /Unknown tag "nonsense"/,
  );
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "healInputs", ["/x"]), /not a board function/);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "constructor", []), /not a board function/);
});

test("usage is folded into the channel's agent's budget, not the one the request names", async () => {
  const { hub, sandbox } = await setup();
  const slice = { ...emptyAgentBudget(), spent_usd: 0.25, tokens: 1000, calls: 3 };
  await board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a1", slice]);
  const budget = JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")) as { agents: Record<string, { spent_usd: number }> };
  assert.equal(budget.agents.a0.spent_usd, 0.25, "a0 sent it, so a0 spent it");
  assert.equal(budget.agents.a1?.spent_usd ?? 0, 0, "a1 was not charged for a0's usage");
});

test("a claim on a file a peer just wrote waits out the cache window; the writer's own does not", async () => {
  const { hub, sandbox } = await setup({ settleMs: 1500 });
  await writeFile(join(sandbox, "work", "shared.md"), "a0 wrote this\n");
  await board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/shared.md", "a0"]);
  await new Promise((r) => setTimeout(r, 20));
  let t = Date.now();
  const own = (await board.callBoard(hub.socketFor("a0"), "claimFile", [null, "work/shared.md", { reason: "more" }])) as { ok: boolean };
  assert.equal(own.ok, true);
  assert.ok(Date.now() - t < 700, `the writer re-claims at once (took ${Date.now() - t}ms)`);
  await board.callBoard(hub.socketFor("a0"), "releaseFile", [null, "work/shared.md"]);
  t = Date.now();
  const peer = (await board.callBoard(hub.socketFor("a1"), "claimFile", [null, "work/shared.md", { reason: "append" }])) as { ok: boolean };
  assert.equal(peer.ok, true);
  assert.ok(Date.now() - t >= 1000, `a peer's claim waits for the window (took ${Date.now() - t}ms)`);
});

test("trace lines are forwarded with the channel's token, and a token in the line is dropped", async () => {
  const { hub, lines } = await setup();
  const answer = await exchange(hub.socketFor("a1"), { ts: new Date().toISOString(), agent: "a0", tool: "bash", args: {}, result: {}, token: "stolen" });
  assert.equal(answer.ok, true);
  assert.equal(lines.length, 1);
  assert.equal(lines[0].token, "token-a1", "the collector sees a1's token, so it writes the line as a1's");
  assert.equal(lines[0].agent, "a0", "the claim is left for the collector to judge");
});

test("a nudge reaches the peer's link as a prompt, once, and only for a kind the run bears out", async () => {
  const { hub, sandbox } = await setup();
  const prompts: string[] = [];
  const link = board.openHubLink(hub.socketFor("a1"), (p) => prompts.push(p.text), { retryMs: 50 });
  cleanups.push(async () => link.close());
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(hub.statusSnapshot().a1.connected, true);
  let answer = await exchange(hub.socketFor("a0"), { kind: "swarm_done", peer: "a1", from: "a1" });
  assert.equal(answer.ok, false, "no sentinel yet: the run does not say that");
  await writeFile(join(sandbox, SENTINEL_REL), "---\nby: a0\n---\n");
  answer = await exchange(hub.socketFor("a0"), { kind: "swarm_done", peer: "a1", from: "a1" });
  assert.equal(answer.ok, true);
  answer = await exchange(hub.socketFor("a0"), { kind: "swarm_done", peer: "a1" });
  assert.equal(answer.repeat, true, "a peer is told once per kind");
  answer = await exchange(hub.socketFor("a0"), { kind: "swarm_done", peer: "a0" });
  assert.equal(answer.ok, false, "the sender is not its own peer, whatever `from` said");
  answer = await exchange(hub.socketFor("a0"), { kind: "anything", peer: "a1" });
  assert.equal(answer.ok, false);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(prompts.length, 1);
  assert.match(prompts[0], /SWARM_DONE/);
});

test("the admin socket prompts an agent, reports who is working, and knows nobody outside the run", async () => {
  const { hub } = await setup();
  const prompts: Array<{ text: string; deliver?: string }> = [];
  const link = board.openHubLink(hub.socketFor("a0"), (p) => prompts.push(p), { retryMs: 50 });
  cleanups.push(async () => link.close());
  await new Promise((r) => setTimeout(r, 100));
  link.state("working");
  await new Promise((r) => setTimeout(r, 100));
  const status = await exchange(hub.adminSocket(), { op: "status" });
  const agents = status.agents as Record<string, { state: string; connected: boolean }>;
  assert.equal(agents.a0.state, "working");
  assert.equal(agents.a0.connected, true);
  assert.equal(agents.a1.connected, false);
  const statusFile = JSON.parse(await readFile(hub.statusFile(), "utf8")) as { agents: Record<string, { state: string }> };
  assert.equal(statusFile.agents.a0.state, "working", "the status file says the same, for the shell scripts");
  let answer = await exchange(hub.adminSocket(), { op: "prompt", agent: "a0", text: "you are idle" });
  assert.equal(answer.delivered, true);
  answer = await exchange(hub.adminSocket(), { op: "prompt", agent: "a1", text: "nobody is listening" });
  assert.equal(answer.delivered, false, "a1 has no link: said, not pretended");
  answer = await exchange(hub.adminSocket(), { op: "prompt", agent: "zz", text: "x" });
  assert.equal(answer.ok, false);
  await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(prompts.map((p) => p.text), ["you are idle"]);
  assert.equal(prompts[0].deliver, "followUp");
});

test("a queued prompt is delivered when the agent's link comes up", async () => {
  const { hub } = await setup();
  const answer = await exchange(hub.adminSocket(), { op: "prompt", agent: "a1", text: "kickoff follow-up", queue: true });
  assert.equal(answer.delivered, false);
  const prompts: string[] = [];
  const link = board.openHubLink(hub.socketFor("a1"), (p) => prompts.push(p.text), { retryMs: 50 });
  cleanups.push(async () => link.close());
  await new Promise((r) => setTimeout(r, 150));
  assert.deepEqual(prompts, ["kickoff follow-up"]);
});

test("wait through the hub returns on a peer's post, and an aborted wait ends the call", async () => {
  const { hub, sandbox } = await setup();
  const previous = process.env.SWARM_BOARD_SOCKET;
  try {
    process.env.SWARM_BOARD_SOCKET = hub.socketFor("a1");
    const ctx = { sandboxRoot: sandbox, agentId: "a1" };
    await board.readInbox(ctx);
    const waiting = board.waitForSwarmChange(ctx, { seconds: 20 });
    await new Promise((r) => setTimeout(r, 300));
    await board.callBoard(hub.socketFor("a0"), "postMessage", [null, { tag: "result", body: "found it" }]);
    const result = await waiting;
    assert.equal(result.reason, "post");
    await board.readInbox(ctx);
    const controller = new AbortController();
    const started = Date.now();
    const aborted = board.waitForSwarmChange(ctx, { seconds: 60, signal: controller.signal });
    setTimeout(() => controller.abort(), 200);
    const r2 = await aborted;
    assert.equal(r2.reason, "timeout");
    assert.ok(Date.now() - started < 5000);
  } finally {
    if (previous === undefined) delete process.env.SWARM_BOARD_SOCKET;
    else process.env.SWARM_BOARD_SOCKET = previous;
  }
});

test("the backstop writes the sentinel past the wall clock and the grace period, and says so as the harness", async () => {
  const { hub, sandbox, lines } = await setup({ wall: 1 });
  const prompts: string[] = [];
  const link = board.openHubLink(hub.socketFor("a0"), (p) => prompts.push(p.text), { retryMs: 50 });
  cleanups.push(async () => link.close());
  await new Promise((r) => setTimeout(r, 100));
  const budgetFile = join(sandbox, "budget.json");
  const budget = JSON.parse(await readFile(budgetFile, "utf8")) as Record<string, unknown>;
  budget.started_at = new Date(Date.now() - 2 * 60_000).toISOString();
  await writeFile(budgetFile, JSON.stringify(budget));
  await hub.backstop();
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(prompts.some((p) => /wall clock/i.test(p)), "the agents are steered first");
  assert.equal(await stat(join(sandbox, SENTINEL_REL)).then(() => true).catch(() => false), false, "not stopped inside the grace period");
  await hub.backstop(Date.now() + 3 * 60_000);
  assert.equal(await stat(join(sandbox, SENTINEL_REL)).then(() => true).catch(() => false), true, "stopped once the grace period passed");
  const stopLine = lines.find((l) => l.tool === "harness_stop");
  assert.ok(stopLine, "the stop is on the trace");
  assert.equal(stopLine.token, "token-system", "as the harness's own line");
  const posts = await readdir(join(sandbox, "threads", "main"));
  assert.ok(posts.some((p) => p.endsWith("-system.md")), "and on the board");
});
