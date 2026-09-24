/**
 * The hub is the board's only writer for agents in microVMs, and who is
 * asking is decided by the socket a request arrives on. These tests run the
 * hub in-process against a real sandbox and talk to it the way the
 * extension in a VM does (extensions/board.ts), with a stand-in collector.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { connect, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as board from "../extensions/board.ts";
import { agentDeadPath, emptyAgentBudget, initSandbox, readPost, SENTINEL_REL } from "../extensions/protocol.ts";
import { boardTable, Hub } from "../scripts/vm-hub.ts";

const cleanups: Array<() => Promise<unknown>> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

async function setup(options: { agents?: string[]; settleMs?: number; wall?: number; collector?: boolean; forging?: boolean } = {}) {
  const agents = options.agents ?? ["a0", "a1"];
  const base = await mkdtemp(join(tmpdir(), "dfs-hub-"));
  const sandbox = join(base, "runs", "t1");
  await mkdir(sandbox, { recursive: true });
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
    collector: options.collector === false ? join(dir, "no-collector.sock") : collectorPath,
    backstop: false,
    quiet: true,
    settleMs: options.settleMs ?? 0,
    herdrBin: "/usr/bin/false",
    forging: options.forging ?? true,
  });
  await hub.start();
  cleanups.push(async () => {
    // A test may have stopped the hub itself; the directories go either way.
    await hub.stop().catch(() => undefined);
    collector.close();
    await rm(base, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  });
  return { hub, sandbox, dir, lines, agents, base };
}

/** The operator's registry for a sandbox, with a goal whose finish line is these checks. */
async function registryWithChecks(base: string, sandbox: string, checks: string[]): Promise<void> {
  const goal = ["## Goal", "", "Do the thing.", "", "## Checks", "", ...checks.map((c) => `- \`${c}\``), ""].join("\n");
  await writeFile(join(base, "runs", "registry.json"), JSON.stringify({ runs: [{ id: "t1", sandbox, goal }] }));
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

test("the harness's own functions are not on the agent channel: a VM cannot stop the swarm or move its clock", async () => {
  const { hub, sandbox } = await setup();
  for (const fn of ["harnessStop", "markStopSteer", "clearStopSteer"]) {
    await assert.rejects(board.callBoard(hub.socketFor("a0"), fn, [sandbox, "cap", "forged", {}]), /not a board function/, fn);
  }
  assert.equal(await stat(join(sandbox, SENTINEL_REL)).then(() => true).catch(() => false), false, "no sentinel was written");
  assert.ok(!board.REMOTE_FUNCTIONS.includes("harnessStop" as never), "and the extension does not send them");
});

test("a link an agent planted in work/ is refused: history, diffs and restores never read or write through it", async () => {
  const { hub, sandbox, dir } = await setup();
  const outside = join(dir, "operator-secret.txt");
  await writeFile(outside, "the operator's own file\n");
  await symlink(outside, join(sandbox, "work", "leak"));
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/leak", "a0"]), /escapes sandbox|link/i, "history does not copy a host file");
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "fileDiff", [sandbox, "work/leak"]), /escapes sandbox|link/i, "a diff does not read a host file");
  assert.deepEqual(await readdir(join(sandbox, "history")).catch(() => []), [], "nothing landed in history/");
  // A link inside the sandbox is a link too: the bytes at the target are the
  // target's, and a restore must not be redirected into another file.
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await writeFile(join(sandbox, "work", "a0", "own.md"), "rev one\n");
  await board.callBoard(hub.socketFor("a0"), "claimFile", [null, "work/a0/own.md", { reason: "mine" }]);
  const rec = (await board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/a0/own.md", "a0"])) as { rev: number };
  assert.equal(rec.rev, 1);
  await writeFile(join(sandbox, "work", "a0", "other.md"), "do not touch\n");
  await rm(join(sandbox, "work", "a0", "own.md"));
  await symlink("other.md", join(sandbox, "work", "a0", "own.md"));
  const restored = (await board.callBoard(hub.socketFor("a0"), "restoreFileVersion", [null, "work/a0/own.md", 1]).catch((e: Error) => ({ ok: false, reason: e.message }))) as { ok: boolean; reason?: string };
  assert.equal(restored.ok, false, `a restore through a link is refused: ${JSON.stringify(restored)}`);
  assert.equal(await readFile(join(sandbox, "work", "a0", "other.md"), "utf8"), "do not touch\n", "the link's target is untouched");
});

test("a seat's spend report may only grow: a smaller, negative or non-numeric report is refused and the row stays", async () => {
  const { hub, sandbox } = await setup();
  const first = { ...emptyAgentBudget(), spent_usd: 0.5, tokens: 2000, calls: 4 };
  await board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", first]);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...first, spent_usd: 0.1 }]), /went backwards/);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...first, tokens: -5 }]), /not a non-negative number|went backwards/);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...first, spent_usd: "lots" }]), /not a non-negative number/);
  const budget = JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")) as { agents: Record<string, { spent_usd: number; tokens: number }> };
  assert.equal(budget.agents.a0.spent_usd, 0.5);
  assert.equal(budget.agents.a0.tokens, 2000);
  await board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...first, spent_usd: 0.75, tokens: 2500 }]);
  assert.equal(JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")).agents.a0.spent_usd, 0.75, "a larger report is taken");
});

test("the sentinel is written only when the operator's finish line passes on the host", async () => {
  const { hub, sandbox, base } = await setup();
  const was = process.env.SWARM_RUNS_DIR;
  process.env.SWARM_RUNS_DIR = join(base, "runs");
  cleanups.push(async () => {
    if (was === undefined) delete process.env.SWARM_RUNS_DIR;
    else process.env.SWARM_RUNS_DIR = was;
  });
  await registryWithChecks(base, sandbox, ["test -f work/report.md"]);
  await assert.rejects(
    board.callBoard(hub.socketFor("a0"), "markDone", [null, { reason: "finished", outputFile: "work/report.md" }]),
    /finish line/,
    "with the check failing, done is refused by the hub itself",
  );
  assert.equal(await stat(join(sandbox, SENTINEL_REL)).then(() => true).catch(() => false), false);
  assert.equal(await stat(join(sandbox, "done", "agents", "a0.done")).then(() => true).catch(() => false), false, "and the seat is not marked done either");
  await writeFile(join(sandbox, "work", "report.md"), "# report\n");
  const done = (await board.callBoard(hub.socketFor("a0"), "markDone", [null, { reason: "finished", outputFile: "work/report.md" }])) as { created_sentinel: boolean };
  assert.equal(done.created_sentinel, true, "with the check passing, the sentinel is written");
});

test("a seat whose link went down mid-turn is 'gone', not 'working', so the watchdogs act on it", async () => {
  const { hub } = await setup();
  const link = board.openHubLink(hub.socketFor("a0"), () => undefined, { retryMs: 60_000 });
  await new Promise((r) => setTimeout(r, 100));
  link.state("working");
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(hub.statusSnapshot().a0.state, "working");
  link.close();
  await new Promise((r) => setTimeout(r, 150));
  const st = hub.statusSnapshot().a0;
  assert.equal(st.state, "gone");
  assert.equal(st.connected, false);
});

test("a seat the run recorded dead is not served", async () => {
  const { hub, sandbox } = await setup();
  await mkdir(join(sandbox, "done", "agents"), { recursive: true });
  await writeFile(agentDeadPath(sandbox, "a1"), "reaped\n");
  await assert.rejects(board.callBoard(hub.socketFor("a1"), "postMessage", [null, { tag: "intro", body: "still here" }]), /recorded dead/);
  const post = (await board.callBoard(hub.socketFor("a0"), "postMessage", [null, { tag: "intro", body: "alive" }])) as { from: string };
  assert.equal(post.from, "a0", "a live seat is served as before");
});

test("the hub's own lines are kept on the host when the collector does not take them", async () => {
  const { hub, dir } = await setup({ collector: false });
  await hub.event("harness_stop", { via: "hub", reason: "cap" }, { created_sentinel: true });
  const spill = await readFile(join(dir, "hub-spill.jsonl"), "utf8");
  const line = JSON.parse(spill.trim()) as { agent: string; tool: string; token?: string };
  assert.equal(line.tool, "harness_stop");
  assert.equal(line.agent, "system");
  assert.equal(line.token, undefined, "no token is written to disk");
  assert.equal(hub.spillFile(), join(dir, "hub-spill.jsonl"));
});

test("tool forging off for the run: the hub refuses a forge whatever the VM asks", async () => {
  const { hub } = await setup({ forging: false });
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "forgeTool", [null, { name: "hello_tool", runtime: "bash", script: "echo hi" }]), /forging is off/);
});

test("the stop clock survives a restart of the hub: a resumed hub does not start the grace period again", async () => {
  const { hub, sandbox, dir, agents, lines } = await setup({ wall: 1 });
  const budgetFile = join(sandbox, "budget.json");
  const budget = JSON.parse(await readFile(budgetFile, "utf8")) as Record<string, unknown>;
  budget.started_at = new Date(Date.now() - 2 * 60_000).toISOString();
  await writeFile(budgetFile, JSON.stringify(budget));
  const t0 = Date.now();
  await hub.backstop(t0);
  assert.ok(lines.some((l) => l.tool === "wall_steer"), "steered");
  await hub.stop();
  const again = new Hub({ sandbox, dir, agents, tokens: hub.cfg.tokens, collector: hub.cfg.collector, backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false" });
  await again.start();
  cleanups.push(async () => again.stop().catch(() => undefined));
  await again.backstop(t0 + 30_000);
  assert.equal(await stat(join(sandbox, SENTINEL_REL)).then(() => true).catch(() => false), false, "inside the grace period still");
  await again.backstop(t0 + 3 * 60_000);
  assert.equal(await stat(join(sandbox, SENTINEL_REL)).then(() => true).catch(() => false), true, "the grace period was measured from the first hub's clock");
  assert.ok(lines.filter((l) => l.tool === "wall_steer").length === 1, "the resumed hub did not steer a second time");
});

test("a burst of calls from one seat queues past the running cap and is refused past the queue", async () => {
  const { hub } = await setup();
  const t = Date.now();
  const burst = Array.from({ length: 70 }, () => board.callBoard(hub.socketFor("a0"), "waitForSwarmChange", [null, { seconds: 2 }]).then(() => "ok", (e: Error) => e.message));
  const results = await Promise.all(burst);
  assert.equal(results.filter((r) => r === "ok").length, 70, "a burst past the running cap is queued, not refused");
  assert.ok(Date.now() - t >= 3500, `the calls past the cap waited for a slot (took ${Date.now() - t}ms)`);
  const flood = Array.from({ length: 300 }, () => board.callBoard(hub.socketFor("a1"), "waitForSwarmChange", [null, { seconds: 1 }]).then(() => "ok", (e: Error) => e.message));
  const answers = await Promise.all(flood);
  const refused = answers.filter((r) => /too many board calls waiting/.test(r)).length;
  assert.ok(refused >= 30 && refused <= 60, `a flood past the queue is refused (${refused} refused)`);
  assert.equal(answers.length - refused, 256, "and the rest were answered");
});
