/**
 * The hub is the board's only writer for agents in microVMs, and who is
 * asking is decided by the socket a request arrives on. These tests run the
 * hub in-process against a real sandbox and talk to it the way the
 * extension in a VM does (extensions/board.ts), with a stand-in collector.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { connect, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as board from "../extensions/board.ts";
import { agentDeadPath, diffWatchedPaths, emptyAgentBudget, initSandbox, postSender, readPost, SENTINEL_REL, watchedPathHashes } from "../extensions/protocol.ts";
import { boardTable, CollectorLink, Hub, isHubProcess, msbDbOutcomes, SocketPathTooLong, takeHubLock, updateRegistryState } from "../scripts/vm-hub.ts";

const cleanups: Array<() => Promise<unknown>> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

/**
 * Run `fn` as the extension in a seat's VM runs: the board's calls go to
 * that seat's hub socket (SWARM_BOARD_SOCKET), so the wrappers that send a
 * file's bytes with the call are the ones exercised.
 */
async function asVm<T>(socket: string, fn: () => Promise<T>): Promise<T> {
  const was = process.env.SWARM_BOARD_SOCKET;
  process.env.SWARM_BOARD_SOCKET = socket;
  try {
    return await fn();
  } finally {
    if (was === undefined) delete process.env.SWARM_BOARD_SOCKET;
    else process.env.SWARM_BOARD_SOCKET = was;
  }
}

/** Poll until the condition holds: a fixed sleep was either too short on a loaded runner or wasted time. */
async function until(cond: () => boolean, what: string, ms = 5000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function setup(options: { agents?: string[]; settleMs?: number; wall?: number; collector?: boolean; forging?: boolean; extra?: Record<string, unknown> } = {}) {
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
    ...(options.extra ?? {}),
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
  // What a peer reads names the seat: a harness post from inside a VM is
  // that seat's harness code, which its guest root controls.
  const box = await asVm(hub.socketFor("a0"), () => board.readInbox({ sandboxRoot: "/x", agentId: "a0" }));
  const seen = box.posts.find((p) => p.id === (post as { id?: number }).id);
  assert.ok(seen, "a0 reads the post");
  assert.equal(postSender(seen), "system via a1");
  const extension = await readFile(join(import.meta.dirname, "..", "extensions", "agent-swarm.ts"), "utf8");
  assert.equal((extension.match(/from: postSender\(p\)/g) ?? []).length, 2, "the inbox and the wait payloads both name the seat");
  assert.doesNotMatch(extension, /from: p\.from,/, "no payload shows a post's bare sender");
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
  // No pause: the hub waits for its own write note before judging a claim.
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
  // And the collector's judgement, on the very line the hub forwarded: the
  // channel's token wins, the claim is kept as a claim.
  const collectorModule = "../scripts/trace-collector.mjs";
  const { attribute } = (await import(collectorModule)) as { attribute: (r: Record<string, unknown>, m: Map<string, string>, k?: string) => Record<string, unknown> };
  const judged = attribute(lines[0], new Map([["token-a0", "a0"], ["token-a1", "a1"]]), "");
  assert.equal(judged.agent, "a1", "written as the channel's agent");
  assert.equal(judged.claimed_agent, "a0", "with what it claimed beside it");
  assert.equal("token" in judged, false, "and no token in the record");
});

test("a nudge reaches the peer's link as a prompt, once, and only for a kind the run bears out", async () => {
  const { hub, sandbox } = await setup();
  const prompts: string[] = [];
  const link = board.openHubLink(hub.socketFor("a1"), (p) => prompts.push(p.text), { retryMs: 50 });
  cleanups.push(async () => link.close());
  await until(() => hub.statusSnapshot().a1?.connected === true, "a1's link comes up");
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
  await until(() => prompts.length >= 1, "the one nudge arrives");
  assert.equal(prompts.length, 1);
  assert.match(prompts[0], /SWARM_DONE/);
});

test("the admin socket prompts an agent, reports who is working, and knows nobody outside the run", async () => {
  const { hub } = await setup();
  const prompts: Array<{ text: string; deliver?: string }> = [];
  const link = board.openHubLink(hub.socketFor("a0"), (p) => prompts.push(p), { retryMs: 50 });
  cleanups.push(async () => link.close());
  await until(() => hub.statusSnapshot().a0?.connected === true, "a0's link comes up");
  link.state("working");
  await until(() => hub.statusSnapshot().a0?.state === "working", "a0's state reaches the hub");
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
  await until(() => prompts.length >= 1, "the prompt arrives");
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
  await until(() => prompts.length >= 1, "the held prompt is delivered on link");
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
  await until(() => hub.statusSnapshot().a0?.connected === true, "a0's link comes up");
  const budgetFile = join(sandbox, "budget.json");
  const budget = JSON.parse(await readFile(budgetFile, "utf8")) as Record<string, unknown>;
  budget.started_at = new Date(Date.now() - 2 * 60_000).toISOString();
  await writeFile(budgetFile, JSON.stringify(budget));
  await hub.backstop();
  await until(() => prompts.some((p) => /wall clock/i.test(p)), "the agents are steered first");
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
  // The hub does not open a file in a seat's own directory: a call without
  // its bytes is refused, and the VM's wrapper sends them.
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/a0/own.md", "a0"]), /its bytes come with the call/);
  const rec = (await asVm(hub.socketFor("a0"), () => board.recordFileVersion(sandbox, "work/a0/own.md", "a0"))) as { rev: number };
  assert.equal(rec.rev, 1);
  await writeFile(join(sandbox, "work", "a0", "other.md"), "do not touch\n");
  await rm(join(sandbox, "work", "a0", "own.md"));
  await symlink("other.md", join(sandbox, "work", "a0", "own.md"));
  const restored = (await board.callBoard(hub.socketFor("a0"), "restoreFileVersion", [null, "work/a0/own.md", 1]).catch((e: Error) => ({ ok: false, reason: e.message }))) as { ok: boolean; reason?: string };
  assert.equal(restored.ok, false, `a restore through a link is refused: ${JSON.stringify(restored)}`);
  const inVm = await asVm(hub.socketFor("a0"), () => board.restoreFileVersion({ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/own.md", 1));
  assert.equal(inVm.ok, false, `nor in the VM: ${JSON.stringify(inVm)}`);
  assert.equal(await readFile(join(sandbox, "work", "a0", "other.md"), "utf8"), "do not touch\n", "the link's target is untouched");
});

test("the hub never opens a file in a seat's own directory: records, diffs and publishes carry the bytes, restores happen in the VM", async () => {
  const { hub, sandbox } = await setup();
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await writeFile(join(sandbox, "work", "a0", "notes.md"), "one\n");
  const vm = (fn: () => Promise<unknown>) => asVm(hub.socketFor("a0"), fn);
  const r1 = (await vm(() => board.recordFileVersion(sandbox, "work/a0/notes.md", "a0"))) as { rev: number; sha256: string };
  assert.equal(r1.rev, 1);
  await writeFile(join(sandbox, "work", "a0", "notes.md"), "one\ntwo\n");
  const r2 = (await vm(() => board.recordFileVersion(sandbox, "work/a0/notes.md", "a0"))) as { rev: number };
  assert.equal(r2.rev, 2);
  // What the hub recorded is what the VM sent, and a diff against the disk
  // uses the VM's own view of it.
  const diff = (await vm(() => board.fileDiff(sandbox, "work/a0/notes.md", 1))) as { added: number };
  assert.equal(diff.added, 1);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "fileDiff", [sandbox, "work/a0/notes.md", 1]), /the bytes on disk come with the call/, "a raw diff against a hole's disk is refused");
  // A restore of one's own file is made in the VM, checked against the hash the hub recorded.
  const restored = (await vm(() => board.restoreFileVersion({ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/notes.md", 1))) as { ok: boolean; sha256?: string; landed_rev?: number | null };
  assert.equal(restored.ok, true, JSON.stringify(restored));
  assert.equal(restored.sha256, r1.sha256);
  assert.equal(await readFile(join(sandbox, "work", "a0", "notes.md"), "utf8"), "one\n");
  assert.equal(restored.landed_rev, 3, "the restore itself is a revision");
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "restoreFileVersion", [null, "work/a0/notes.md", 2]), /restores it in your VM/);
  // A file past the store limit is recorded by its hash only, and cannot be restored.
  const big = (await board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/a0/notes.md", "a0", { hash_only: { sha256: "a".repeat(64), bytes: 40 * 1024 * 1024 } }])) as { rev: number; stored?: boolean };
  assert.equal(big.stored, false);
  const noBytes = (await vm(() => board.restoreFileVersion({ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/notes.md", big.rev))) as { ok: boolean; reason?: string };
  assert.equal(noBytes.ok, false);
  assert.match(noBytes.reason ?? "", /hash only/);
  // Bytes over the limit in a call are refused.
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/a0/notes.md", "a0", { bytes_b64: Buffer.alloc(33 * 1024 * 1024).toString("base64") }]), /hash_only/);
});

test("a seat cannot claim, record, restore or publish into a peer's directory, whatever the letter case", async () => {
  const { hub, sandbox } = await setup();
  await mkdir(join(sandbox, "work", "a1"), { recursive: true });
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await writeFile(join(sandbox, "work", "a1", "findings.md"), "a1's\n");
  await writeFile(join(sandbox, "work", "a0", "evil.md"), "a0's\n");
  const claim = (await board.callBoard(hub.socketFor("a0"), "claimFile", [null, "work/a1/findings.md", { reason: "take it" }])) as { ok: boolean; owner?: string };
  assert.equal(claim.ok, false);
  assert.equal(claim.owner, "a1");
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "work/a1/findings.md", "a0", { bytes_b64: "eA==" }]), /a1's own directory/);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "restoreFileVersion", [null, "work/a1/findings.md", 1]), /a1's own directory/);
  const guard = (await board.callBoard(hub.socketFor("a0"), "guardWrite", [null, "work/a1/findings.md"])) as { ok: boolean; reason?: string };
  assert.equal(guard.ok, false);
  for (const to of ["work/a1/findings.md", "work/A1/findings.md", "work/extracted/a1/x.md", "tool-output/a1/x"]) {
    const res = (await asVm(hub.socketFor("a0"), () => board.publishFile({ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/evil.md", to))) as { ok: boolean; reason?: string };
    assert.equal(res.ok, false, `${to}: ${JSON.stringify(res)}`);
  }
  assert.equal(await readFile(join(sandbox, "work", "a1", "findings.md"), "utf8"), "a1's\n", "the peer's file is untouched");
});

// Linux names the file a descriptor holds, which closes the race; macOS does
// not, and there the hub's answer is never to open such a path at all (the
// tests above). So the race itself is held to zero on Linux only.
test("the harness's reads refuse a directory swapped for a link while they read", { skip: process.platform !== "linux" && "macOS gives no path for an open descriptor; the hub never opens a seat's directory instead" }, async () => {
  const { sandbox, dir } = await setup();
  const { readSandboxFile } = await import("../extensions/protocol.ts");
  const outside = join(dir, "outside");
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, "auth.json"), "SECRET");
  const inside = join(sandbox, "work", "a0", "sub");
  await mkdir(inside, { recursive: true });
  await writeFile(join(inside, "auth.json"), "fine");
  // A second process swaps the directory for a link to the outside one and back, as fast as it can.
  const { spawn } = await import("node:child_process");
  const swapper = spawn(process.execPath, ["-e", `
    const fs = require("node:fs");
    const d = ${JSON.stringify(inside)}, parked = d + ".real", out = ${JSON.stringify(outside)};
    const end = Date.now() + 2500;
    while (Date.now() < end) {
      try { fs.renameSync(d, parked); fs.symlinkSync(out, d); fs.unlinkSync(d); fs.renameSync(parked, d); } catch {}
    }
    try { fs.unlinkSync(d); } catch {}
    try { fs.renameSync(parked, d); } catch {}
  `]);
  let leaks = 0;
  let reads = 0;
  let refused = 0;
  const end = Date.now() + 2500;
  while (Date.now() < end) {
    const got = await readSandboxFile(sandbox, "work/a0/sub/auth.json").catch(() => null);
    reads += 1;
    if (got === null) refused += 1;
    if (got && got.bytes.toString() === "SECRET") leaks += 1;
  }
  await new Promise((r) => swapper.once("exit", r));
  assert.equal(leaks, 0, `${leaks} of ${reads} reads returned the outside file`);
  // The race was run: reads happened, and some met the swapped directory.
  assert.ok(reads > 100, `only ${reads} reads`);
  assert.ok(refused > 0, "no read met the link: the swapper never swapped, and the test proved nothing");
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
  await until(() => hub.statusSnapshot().a0?.connected === true, "a0's link comes up");
  link.state("working");
  await until(() => hub.statusSnapshot().a0?.state === "working", "a0's state reaches the hub");
  link.close();
  await until(() => hub.statusSnapshot().a0?.state === "gone", "the closed link is seen");
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


/** One raw request on its own connection, answered with one line: what a VM's one-shot call is. */
function rawCall(socket: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const s = connect(socket);
    let buf = "";
    s.setEncoding("utf8");
    s.on("connect", () => s.write(`${JSON.stringify(body)}\n`));
    s.on("data", (d: string) => {
      buf += d;
      const cut = buf.indexOf("\n");
      if (cut >= 0) {
        s.destroy();
        resolve(JSON.parse(buf.slice(0, cut)));
      }
    });
    s.on("error", reject);
  });
}

/** A stand-in for scripts/vm.ts: records how it was called; a custody.ts beside it records what it saw. */
async function fakeVmCli(dir: string, sandbox: string): Promise<{ cli: string; log: string; seen: string }> {
  const bin = join(dir, "fake-bin");
  await mkdir(bin, { recursive: true });
  const log = join(bin, "calls.log");
  const seen = join(bin, "custody-saw.txt");
  await writeFile(join(bin, "vm.ts"), `require("node:fs").appendFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2)) + "\\n");\n`);
  await writeFile(
    join(bin, "custody.ts"),
    `const fs = require("node:fs"); fs.writeFileSync(${JSON.stringify(seen)}, fs.existsSync(${JSON.stringify(join(sandbox, "traces", "hub-spill.jsonl"))}) ? "spill copied" : "no spill"); fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify(["custody", ...process.argv.slice(2)]) + "\\n");\n`,
  );
  return { cli: join(bin, "vm.ts"), log, seen };
}

test("a call a seat sends again after a dropped link is run once: the same request id gets the first answer", async () => {
  const { hub, sandbox } = await setup();
  const body = { t: "rpc", fn: "postMessage", rid: "req-1", args: [null, { tag: "intro", body: "said once" }] };
  const first = await rawCall(hub.socketFor("a0"), body);
  const again = await rawCall(hub.socketFor("a0"), body);
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.deepEqual(again.result, first.result, "the repeat gets the first run's answer");
  const posts = (await readdir(join(sandbox, "threads", "main"))).filter((f) => f.endsWith("-a0.md"));
  assert.equal(posts.length, 1, "and the board has the post once");
  // The same id from another seat is another request.
  const other = await rawCall(hub.socketFor("a1"), body);
  assert.notDeepEqual(other.result, first.result);
  // A restarted hub still knows the id (the answers are kept in its own directory).
  const replies = await readFile(join(hub.cfg.dir, "replies.jsonl"), "utf8");
  assert.match(replies, /req-1/);
});

test("a seat that posts in a loop is slowed, its peers are not, and the refusals are counted rather than written each time", async () => {
  const { hub, lines } = await setup();
  const results: string[] = [];
  for (let i = 0; i < 46; i++) {
    results.push(await board.callBoard(hub.socketFor("a0"), "postMessage", [null, { tag: "intro", body: `post ${i}` }]).then(() => "ok", (e: Error) => e.message));
  }
  assert.equal(results.filter((r) => r === "ok").length, 40, "a burst up to the bucket goes through");
  assert.ok(results.slice(40).every((r) => /slow down/.test(r)), results.slice(40).join(" | "));
  assert.equal(await board.callBoard(hub.socketFor("a1"), "postMessage", [null, { tag: "intro", body: "a1 is fine" }]).then(() => "ok"), "ok", "a peer is not slowed");
  await until(() => lines.some((l) => l.tool === "hub_call" && (l.args as { fn?: string }).fn === "postMessage"), "the first refusal is on the trace");
  const refusalLines = lines.filter((l) => l.tool === "hub_call" && (l.args as { fn?: string }).fn === "postMessage" && (l.result as { ok?: boolean }).ok === false);
  assert.equal(refusalLines.length, 1, "six identical refusals in a minute are one line and a count");
  await hub.flushRefusals();
  await until(() => lines.some((l) => (l.result as { repeated?: number }).repeated === 5), "the count is written on the flush");
});

test("one seat cannot hold more connections than its cap, and a peer's calls still answer", async () => {
  const { hub } = await setup();
  const held = Array.from({ length: 24 }, () => connect(hub.socketFor("a0")));
  let closed = 0;
  for (const s of held) {
    s.on("error", () => undefined);
    s.on("close", () => (closed += 1));
  }
  await until(() => closed >= 8, `connections past the cap are closed (${closed} closed)`);
  assert.ok(closed <= 12, `only those past the cap (${closed} closed)`);
  const answer = (await board.callBoard(hub.socketFor("a1"), "listTeam", [null])) as { agents: unknown[] };
  assert.equal(answer.agents.length, 2);
  for (const s of held) s.destroy();
});

test("a seat's usage report carries only a budget row's fields, each of its kind, and never moves the seat's model", async () => {
  const { hub, sandbox } = await setup();
  const budgetFile = join(sandbox, "budget.json");
  const b = JSON.parse(await readFile(budgetFile, "utf8"));
  b.agents.a0 = { ...emptyAgentBudget(), model: "openai/gpt-5" };
  await writeFile(budgetFile, JSON.stringify(b));
  const row = { ...emptyAgentBudget(), spent_usd: 0.2, tokens: 10, junk: "x".repeat(100_000), model: "local/free", context_level: "notice", context_locked: false };
  await board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", row]);
  const after = JSON.parse(await readFile(budgetFile, "utf8")).agents.a0;
  assert.equal(after.junk, undefined, "a field a row does not have is dropped");
  assert.equal(after.model, "openai/gpt-5", "the kickoff's model stays");
  assert.equal(after.context_level, "notice");
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...row, spent_usd: 0.3, context_level: 42 }]), /context_level/);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...row, spent_usd: 0.3, context_locked: "yes" }]), /context_locked/);
  // Reports in flight at once: the check is made under the table lock, so the row ends at the largest.
  const values = Array.from({ length: 30 }, (_, i) => (i % 2 ? 1 + i / 100 : 2 + i / 100));
  await Promise.all(values.map((v) => board.callBoard(hub.socketFor("a0"), "applySessionUsage", [sandbox, "a0", { ...emptyAgentBudget(), spent_usd: v, tokens: 10 }]).catch(() => undefined)));
  const last = JSON.parse(await readFile(budgetFile, "utf8")).agents.a0.spent_usd;
  assert.equal(last, Math.max(...values), `the row never went back (${last})`);
});

test("the hub's own calls are on the trace: a refused forge and a done that ended the swarm", async () => {
  const { hub, lines } = await setup({ forging: false });
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "forgeTool", [null, { name: "x_tool", runtime: "bash", script: "echo" }]), /forging is off/);
  await board.callBoard(hub.socketFor("a1"), "markDone", [null, { reason: "ABANDONED: nothing to do", outputFile: "work/none.md" }]);
  await until(() => lines.filter((l) => l.tool === "hub_call").length >= 2, "two hub_call lines");
  const calls = lines.filter((l) => l.tool === "hub_call") as Array<{ agent: string; args: { agent: string; fn: string }; result: Record<string, unknown>; sid?: string; seq?: number }>;
  const forge = calls.find((c) => c.args.fn === "forgeTool");
  assert.equal(forge?.result.ok, false);
  assert.equal(forge?.args.agent, "a0");
  const done = calls.find((c) => c.args.fn === "markDone");
  assert.equal(done?.result.ok, true);
  assert.equal(done?.result.created_sentinel, true);
  assert.ok(calls.every((c) => typeof c.sid === "string" && typeof c.seq === "number"), "the hub numbers its own lines");
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "markDone", [null, { reason: "done", outputFile: "../../etc/passwd" }]), /escapes sandbox/, "a done's output file is a file in the run");
});

test("the hub puts the VMs away with the run's registry and snapshot choice, and custody sees its own spilled lines", async () => {
  const pre = await mkdtemp(join(tmpdir(), "dfh-fake-"));
  cleanups.push(() => rm(pre, { recursive: true, force: true }));
  const registry = join(pre, "registry.json");
  await writeFile(registry, JSON.stringify({ runs: [{ id: "t1", state: "running" }] }));
  const probe = await setup({ collector: false });
  const fake = await fakeVmCli(pre, probe.sandbox);
  await probe.hub.stop();
  const { hub, sandbox } = await setup({ collector: false, extra: { run: "t1", vmCli: fake.cli, registry, snapshot: false, custodyTimeoutSec: 600 } });
  const fake2 = await fakeVmCli(pre, sandbox);
  (hub.cfg as { vmCli?: string }).vmCli = fake2.cli;
  await writeFile(join(sandbox, SENTINEL_REL), "---\nby: a0\nreason: done\n---\n");
  for (const a of ["a0", "a1"]) await writeFile(join(sandbox, "done", "agents", `${a}.done`), "---\nby: x\n---\n");
  await hub.backstop(Date.now());
  await hub.backstop(Date.now() + 1000);
  const calls = (await readFile(fake2.log, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as string[]);
  const finish = calls.find((c) => c.includes("finish") && !c.includes("--agent"));
  assert.ok(finish, JSON.stringify(calls));
  assert.ok(finish.includes("--no-snapshot"), "the run's --no-vm-snapshot reaches the finish");
  assert.equal(finish[finish.indexOf("--registry") + 1], registry, "only this registry's VMs are put away");
  assert.equal(await readFile(fake2.seen, "utf8"), "spill copied", "the hub's own spilled lines are in the run before custody reads it");
  assert.equal(JSON.parse(await readFile(registry, "utf8")).runs[0].state, "finished");
  const custody = calls.find((c) => c[0] === "custody");
  assert.ok(custody, "custody was taken");
  assert.equal(custody[custody.indexOf("--timeout") + 1], "600", "with the operator's bound, not a fixed one");
});

test("custody's bound at a hub's finish is the operator's SWARM_CUSTODY_TIMEOUT, kept across a restart, else stop's default", async () => {
  const { custodyTimeoutSec } = await import("../scripts/vm-hub.ts");
  assert.equal(custodyTimeoutSec({ SWARM_CUSTODY_TIMEOUT: "900" }), 900);
  assert.equal(custodyTimeoutSec({}), 14400);
  assert.equal(custodyTimeoutSec({ SWARM_CUSTODY_TIMEOUT: "-5" }), 14400);
  assert.equal(custodyTimeoutSec({ SWARM_CUSTODY_TIMEOUT: "soon" }), 14400);
  const source = await readFile(join(import.meta.dirname, "..", "scripts", "vm-hub.ts"), "utf8");
  assert.match(source, /const KEPT_ENV = \[[^\]]*"SWARM_CUSTODY_TIMEOUT"/, "a resumed hub keeps the operator's bound");
});

test("a seat that is done while the swarm goes on has its VM put away a grace period later", async () => {
  const pre = await mkdtemp(join(tmpdir(), "dfh-leave-"));
  cleanups.push(() => rm(pre, { recursive: true, force: true }));
  const probe = await setup();
  const fake = await fakeVmCli(pre, probe.sandbox);
  await probe.hub.stop();
  const { hub } = await setup({ extra: { run: "t1", vmCli: fake.cli, seatLeaveMs: 50 } });
  await board.callBoard(hub.socketFor("a0"), "markDone", [null, { reason: "agent_cap", outputFile: "work/a0.md", createSentinel: false }]);
  await until(() => existsSync(fake.log), "the seat's VM is put away", 5000);
  const calls = (await readFile(fake.log, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as string[]);
  assert.ok(calls.some((c) => c.includes("--agent") && c[c.indexOf("--agent") + 1] === "a0"), JSON.stringify(calls));
  assert.ok(!calls.some((c) => c.includes("--agent") && c[c.indexOf("--agent") + 1] === "a1"), "and no other seat's");
});

test("a hub started from the command line keeps what --resume needs: the runs directory of its registry and the inbox bound", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-main-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const sandbox = join(base, "elsewhere", "case");
  await mkdir(join(sandbox, "traces"), { recursive: true });
  const registry = join(base, "runs", "registry.json");
  await mkdir(join(base, "runs"), { recursive: true });
  await writeFile(registry, JSON.stringify({ runs: [] }));
  const dir = join(base, "hub");
  const { spawn } = await import("node:child_process");
  const env: NodeJS.ProcessEnv = { ...process.env, SWARM_INBOX_PAGE_CHARS: "12345" };
  delete env.SWARM_RUNS_DIR;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "vm-hub.ts"), sandbox, "--dir", dir, "--registry", registry, "--quiet"], { env, stdio: ["pipe", "ignore", "ignore"] });
  child.stdin.end(JSON.stringify({ agents: ["a0"], tokens: {}, collector: join(sandbox, "traces", "none.sock") }));
  cleanups.push(async () => child.kill());
  await until(() => existsSync(join(dir, "admin.sock")), "the hub is up", 10_000);
  const input = JSON.parse(await readFile(join(dir, "hub-input.json"), "utf8")) as { env?: Record<string, string> };
  assert.equal(input.env?.SWARM_RUNS_DIR, join(base, "runs"), "the finish line is found through the registry's directory, wherever the sandbox is");
  assert.equal(input.env?.SWARM_INBOX_PAGE_CHARS, "12345");
  child.kill();
});

test("publish_file: a seat's own file lands in the shared work/ claimed and recorded; a peer's directory and a peer's claim are refused", async () => {
  const { hub, sandbox } = await setup();
  const ctx0 = { sandboxRoot: sandbox, agentId: "a0" };
  const ctx1 = { sandboxRoot: sandbox, agentId: "a1" };
  const pub = (socket: string, ctx: { sandboxRoot: string; agentId: string }, from: string, to: string) => asVm(socket, () => board.publishFile(ctx, from, to));
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "publishFile", [null, "work/a0/report.md", "work/report.md"]), /bytes with the call/, "a publish without its bytes is refused");
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await mkdir(join(sandbox, "work", "a1"), { recursive: true });
  await writeFile(join(sandbox, "work", "a0", "report.md"), "# findings\n");
  const published = (await pub(hub.socketFor("a0"), ctx0, "work/a0/report.md", "work/report.md")) as { ok: boolean; path: string; sha256: string; rev: number | null; reason?: string };
  assert.equal(published.ok, true, published.reason);
  assert.equal(published.path, "work/report.md");
  assert.equal(await readFile(join(sandbox, "work", "report.md"), "utf8"), "# findings\n");
  assert.equal(published.rev, 1, "the revision is recorded");
  const claims = (await board.callBoard(hub.socketFor("a0"), "listClaims", [sandbox])) as Array<{ path: string; owner: string }>;
  assert.ok(claims.some((c) => c.path === "work/report.md" && c.owner === "a0"), "the destination is a0's claim");
  // A peer's own directory is theirs.
  await writeFile(join(sandbox, "work", "a0", "note.md"), "mine\n");
  const intoPeer = (await pub(hub.socketFor("a0"), ctx0, "work/a0/note.md", "work/a1/note.md")) as { ok: boolean; reason?: string };
  assert.equal(intoPeer.ok, false);
  assert.match(intoPeer.reason ?? "", /a1's own directory/);
  // A file that is not one's own cannot be published as one's own.
  await writeFile(join(sandbox, "work", "a1", "theirs.md"), "theirs\n");
  const notMine = (await pub(hub.socketFor("a0"), ctx0, "work/a1/theirs.md", "work/theirs.md")) as { ok: boolean; reason?: string };
  assert.equal(notMine.ok, false);
  assert.match(notMine.reason ?? "", /a file of your own/);
  // While a0 holds work/report.md, a1 cannot publish over it.
  await writeFile(join(sandbox, "work", "a1", "report.md"), "# other\n");
  const over = (await pub(hub.socketFor("a1"), ctx1, "work/a1/report.md", "work/report.md")) as { ok: boolean; reason?: string };
  assert.equal(over.ok, false);
  assert.match(over.reason ?? "", /held by a0/);
  assert.equal(await readFile(join(sandbox, "work", "report.md"), "utf8"), "# findings\n", "and the file is untouched");
  // A planted link as the source is refused.
  await symlink("/etc/hosts", join(sandbox, "work", "a0", "leak.md"));
  const leak = (await pub(hub.socketFor("a0"), ctx0, "work/a0/leak.md", "work/leak.md")) as { ok: boolean; reason?: string };
  assert.equal(leak.ok, false);
  assert.match(leak.reason ?? "", /escapes sandbox|link/i);
  assert.equal(await stat(join(sandbox, "work", "leak.md")).then(() => true).catch(() => false), false, "nothing of the host was published");
});

test("in a VM a seat's shell-write watch is its own directories: a peer's published file is never blamed on its command", async () => {
  const { sandbox } = await setup();
  const was = process.env.SWARM_ISOLATION;
  process.env.SWARM_ISOLATION = "microvm";
  cleanups.push(async () => {
    if (was === undefined) delete process.env.SWARM_ISOLATION;
    else process.env.SWARM_ISOLATION = was;
  });
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await mkdir(join(sandbox, "work", "a1"), { recursive: true });
  await writeFile(join(sandbox, "work", "report.md"), "v1\n");
  const before = await watchedPathHashes(sandbox, "a0");
  assert.ok([...before.hashes.keys()].every((k) => k.startsWith("work/a0/")), "only the seat's own files are watched");
  // During a0's command: a peer publishes into the shared work/, and writes its own scratch.
  await writeFile(join(sandbox, "work", "report.md"), "v2 by a1\n");
  await writeFile(join(sandbox, "work", "a1", "x.txt"), "a1's\n");
  await writeFile(join(sandbox, "work", "a0", "mine.txt"), "a0 wrote this\n");
  const reports = await diffWatchedPaths(sandbox, before, "a0");
  assert.deepEqual(reports.map((r) => r.path), ["work/a0/mine.txt"], "a0's command wrote its own file and nothing else");
  // The history the diff reads is the one it is given: in a VM, the hub's,
  // which has a revision the VM's cached view of history/ does not show yet.
  const { createHash } = await import("node:crypto");
  const sha = createHash("sha256").update("a0 wrote this\n").digest("hex");
  const seen: string[] = [];
  const viaHub = await diffWatchedPaths(sandbox, before, "a0", {
    listClaims: async () => {
      seen.push("claims");
      return [];
    },
    listFileHistory: async (_root, path) => {
      seen.push(`history ${path}`);
      return path === "work/a0/mine.txt" ? [{ rev: 1, sha256: sha, bytes: 14, by: "a0", at: new Date().toISOString(), path } as never] : [];
    },
  });
  assert.deepEqual(viaHub, [], "a write the hub's history already holds is accounted for");
  assert.deepEqual(seen, ["claims", "history work/a0/mine.txt"], "the lookups asked were the ones passed in, not the local files");
});

test("the hub's keeper brings a dead hub back with --resume, and lets it go once the stop has begun", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-keeper-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const sandbox = join(base, "runs", "case");
  await mkdir(join(sandbox, "traces"), { recursive: true });
  const dir = join(base, "hub");
  const { spawn } = await import("node:child_process");
  const script = join(import.meta.dirname, "..", "scripts", "vm-hub.ts");
  const first = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", script, sandbox, "--dir", dir, "--quiet"], { stdio: ["pipe", "ignore", "ignore"] });
  first.stdin.end(JSON.stringify({ agents: ["a0"], tokens: {}, collector: join(sandbox, "traces", "none.sock") }));
  await until(() => existsSync(join(dir, "admin.sock")), "the first hub is up", 10_000);
  const keeper = spawn("bash", [join(import.meta.dirname, "..", "scripts", "hub-supervise.sh"), sandbox, dir, script, String(first.pid)], { stdio: "ignore" });
  cleanups.push(async () => {
    keeper.kill();
    const pid = Number((await readFile(join(sandbox, "hub.pid"), "utf8").catch(() => "0")).trim());
    if (pid) {
      try {
        process.kill(pid);
      } catch {
        // gone
      }
    }
  });
  first.kill("SIGKILL");
  await until(() => existsSync(join(sandbox, "hub.pid")), "the keeper wrote a new hub pid", 15_000);
  const second = Number((await readFile(join(sandbox, "hub.pid"), "utf8")).trim());
  assert.notEqual(second, first.pid);
  await until(() => {
    try {
      process.kill(second, 0);
      return existsSync(join(dir, "admin.sock"));
    } catch {
      return false;
    }
  }, "the resumed hub is up", 15_000);
  // Once the stop has begun, a hub that goes is let go, and the keeper ends.
  await writeFile(join(dir, ".stop"), "");
  process.kill(second, "SIGTERM");
  await new Promise<void>((resolve) => keeper.once("exit", () => resolve()));
  assert.equal(Number((await readFile(join(sandbox, "hub.pid"), "utf8")).trim()), second, "no third hub was started");
});

test("a seat over its own cap is recorded done by the hub once the grace period passes, and is not steered again", async () => {
  const { hub, sandbox, lines } = await setup();
  const budgetFile = join(sandbox, "budget.json");
  const budget = JSON.parse(await readFile(budgetFile, "utf8")) as Record<string, any>;
  budget.cap_per_agent_usd = 1;
  budget.agents = { ...(budget.agents ?? {}), a0: { ...emptyAgentBudget(), spent_usd: 2 } };
  await writeFile(budgetFile, JSON.stringify(budget));
  const t0 = Date.now();
  await hub.backstop(t0);
  assert.equal(lines.filter((l) => l.tool === "agent_cap_steer").length, 1, "the seat is told first");
  assert.equal(existsSync(join(sandbox, "done", "agents", "a0.done")), false, "not stopped inside the grace period");
  await hub.backstop(t0 + 3 * 60_000);
  const marker = await readFile(join(sandbox, "done", "agents", "a0.done"), "utf8");
  assert.match(marker, /reason: agent_cap/);
  assert.match(marker, /output: \(stopped by the per-agent cap\)/);
  const stops = lines.filter((l) => l.tool === "agent_cap_stop");
  assert.equal(stops.length, 1);
  assert.equal((stops[0].result as Record<string, unknown>).ok, true);
  await hub.backstop(t0 + 6 * 60_000);
  assert.equal(lines.filter((l) => l.tool === "agent_cap_steer").length, 1, "a seat that is out is not steered again");
  assert.equal(lines.filter((l) => l.tool === "agent_cap_stop").length, 1, "nor stopped again");
  assert.equal(existsSync(join(sandbox, SENTINEL_REL)), false, "one seat's cap does not end the swarm");
});

test("what a seat holds in the hub stays under its budget: whole lines waiting their turn count too, and its connection is paused, not grown", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-held-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const sandbox = join(base, "sb");
  await mkdir(sandbox, { recursive: true });
  await initSandbox(sandbox, { swarmId: "t1", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30 });
  // A collector that takes the connection and never answers: each line waits.
  const colPath = join(base, "c.sock");
  const silent: Server = createServer(() => undefined);
  await new Promise<void>((r) => silent.listen(colPath, () => r()));
  cleanups.push(async () => silent.close());
  const max = 4_000_000;
  const hub = new Hub({ sandbox, dir: join(base, "hub"), agents: ["a0"], tokens: {}, collector: colPath, backstop: false, quiet: true, herdrBin: "/usr/bin/false", bufferMax: max });
  await hub.start();
  cleanups.push(() => hub.stop());
  const s = connect(hub.socketFor("a0"));
  cleanups.push(async () => s.destroy());
  await new Promise((r) => s.once("connect", r));
  const pad = "x".repeat(500_000);
  let peak = 0;
  const watch = setInterval(() => (peak = Math.max(peak, hub.heldBytes("a0"))), 5);
  for (let i = 0; i < 40; i++) s.write(`${JSON.stringify({ tool: "bash", ts: new Date().toISOString(), agent: "a0", args: { pad } })}\n`);
  await new Promise((r) => setTimeout(r, 1500));
  clearInterval(watch);
  // One chunk past the budget at most: the read that crossed it.
  assert.ok(peak <= max + 1_100_000, `held ${peak} bytes against a budget of ${max}`);
  assert.ok(peak > max / 2, `the flood reached the budget (${peak})`);
  assert.equal(s.destroyed, false, "the seat's connection is paused, not cut");
});

test("a board call that carries no file is refused past its size limit; a file-bearing call is not held to it", async () => {
  const { hub, sandbox } = await setup();
  const big = "y".repeat(8_100_000);
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "postMessage", [{ sandboxRoot: sandbox, agentId: "a0" }, { thread: "main", body: big }]), /limit for a call that carries no file/);
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  const bytes = Buffer.from("z".repeat(8_100_000));
  await writeFile(join(sandbox, "work", "a0", "big.txt"), bytes);
  const recorded = (await asVm(hub.socketFor("a0"), () => board.recordFileVersion(sandbox, "work/a0/big.txt", "a0"))) as { rev?: number } | null;
  assert.ok(recorded && typeof recorded.rev === "number", "a record of an 8 MB file goes through");
});

test("in a VM a peer's extraction of thousands of files does not use up a seat's watch: its own files are still watched", async () => {
  const { sandbox } = await setup();
  const was = process.env.SWARM_ISOLATION;
  process.env.SWARM_ISOLATION = "microvm";
  cleanups.push(async () => {
    if (was === undefined) delete process.env.SWARM_ISOLATION;
    else process.env.SWARM_ISOLATION = was;
  });
  const peer = join(sandbox, "work", "extracted", "a1");
  await mkdir(peer, { recursive: true });
  for (let i = 0; i < 600; i++) await writeFile(join(peer, `f${i}.bin`), String(i));
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await writeFile(join(sandbox, "work", "a0", "mine.txt"), "a0's\n");
  const snap = await watchedPathHashes(sandbox, "a0");
  assert.ok(snap.hashes.has("work/a0/mine.txt"), "the seat's own file is watched");
  assert.equal(snap.truncated, false, "a peer's files are not the seat's budget");
});

test("a VM's wait cannot choose how often the hub polls: a pollMs of 0 is not a tight loop on the hub", async () => {
  const { hub, sandbox } = await setup();
  const cpu = process.cpuUsage();
  const r = (await board.callBoard(hub.socketFor("a0"), "waitForSwarmChange", [{ sandboxRoot: sandbox, agentId: "a0" }, { seconds: 1, pollMs: 0 }])) as { reason?: string };
  const used = process.cpuUsage(cpu);
  assert.equal(r.reason, "timeout");
  const ms = (used.user + used.system) / 1000;
  // Measured: 9 ms at the hub's own poll, 343 ms at a pollMs of 0.
  assert.ok(ms < 150, `the wait used ${ms.toFixed(0)} ms of CPU in one second`);
});

test("a seat that alternates its state in a loop gets one Herdr report at a time, spaced out, with no terminal controls in it", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-state-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const log = join(base, "herdr.log");
  const herdr = join(base, "herdr.sh");
  await writeFile(herdr, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\nsleep 0.2\n`, { mode: 0o755 });
  const { hub } = await setup({ extra: { herdrBin: herdr } });
  const admin = connect(join(hub.cfg.dir, "admin.sock"));
  cleanups.push(async () => admin.destroy());
  await new Promise((r) => admin.once("connect", r));
  admin.write(`${JSON.stringify({ op: "panes", panes: { a0: "p1" } })}\n`);
  await until(() => (hub as unknown as { panes: Map<string, string> }).panes.get("a0") === "p1", "the pane is known");
  const s = connect(hub.socketFor("a0"));
  cleanups.push(async () => s.destroy());
  await new Promise((r) => s.once("connect", r));
  let lines = "";
  for (let i = 0; i < 400; i++) lines += `${JSON.stringify({ t: "state", state: i % 2 ? "working" : "idle" })}\n`;
  lines += `${JSON.stringify({ t: "state", state: "blocked", detail: "waiting\u001b]52;c;cHduZWQ=\u0007 on a1" })}\n`;
  s.write(lines);
  await until(() => hub.statusSnapshot().a0?.state === "blocked", "the last state is taken");
  await new Promise((r) => setTimeout(r, 1500));
  const calls = (await readFile(log, "utf8").catch(() => "")).trim().split("\n").filter(Boolean);
  assert.ok(calls.length >= 1 && calls.length <= 6, `${calls.length} Herdr reports for 401 state lines`);
  assert.equal(hub.statusSnapshot().a0?.detail, "waiting]52;c;cHduZWQ= on a1", "the controls are gone, the text is kept");
  assert.ok(calls.at(-1)?.includes("--state blocked"), "the newest state is the one reported last");
});

test("a collector socket cut on a timeout fails only its own lines: the next socket's answers land on the right lines", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-link-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const path = join(base, "c.sock");
  const written: string[] = [];
  const server = createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        if (line === "A") continue; // never answered
        if (line === "D") {
          setTimeout(() => socket.write('{"ok":false,"error":"refused"}\n'), 60);
          continue;
        }
        written.push(line);
        setTimeout(() => socket.write('{"ok":true}\n'), 30);
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((r) => server.listen(path, () => r()));
  cleanups.push(async () => server.close());
  const link = new CollectorLink(path, 200);
  cleanups.push(async () => link.close());
  const a = link.send("A\n");
  // Sent in the same timers phase as A's timeout, before the cut socket closes.
  const b = new Promise<boolean>((resolve) => setTimeout(() => resolve(link.send("B\n")), 200));
  assert.equal(await a, false, "the unanswered line is lost");
  assert.equal(await b, true, "B was written and is said written");
  assert.ok(written.includes("B"));
  assert.equal(await link.send("D\n"), false, "a line the collector refused is said refused");
});

test("a seat cannot publish over the harness's own files in work/: the trace spill custody reads, the install area, the temp directory", async () => {
  const { hub, sandbox } = await setup();
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await writeFile(join(sandbox, "work", "a0", "lines.jsonl"), '{"agent":"a1","sid":"x","seq":1,"tool":"recordEntry"}\n');
  for (const to of ["work/.trace-spill.jsonl", "work/.TRACE-SPILL.jsonl", "work/.toolchain/lib/site.py", "work/.tmp/x"]) {
    const r = (await asVm(hub.socketFor("a0"), () => board.publishFile({ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/lines.jsonl", to))) as { ok: boolean; reason?: string };
    assert.equal(r.ok, false, `publishing to ${to} was refused`);
    assert.match(r.reason ?? "", /harness's|harness-owned/);
  }
  assert.equal(existsSync(join(sandbox, "work", ".trace-spill.jsonl")), false, "nothing was written there");
  const fine = (await asVm(hub.socketFor("a0"), () => board.publishFile({ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/lines.jsonl", "work/lines.jsonl"))) as { ok: boolean };
  assert.equal(fine.ok, true, "a shared name is still published");
});

test("a hub lock naming a live process that is not a hub is stale and is taken; one naming a live hub for the run is not", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-lock-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const dir = join(base, "dfs-t1.abc123");
  await mkdir(dir, { recursive: true });
  const lock = join(dir, "hub.lock");
  const { spawn } = await import("node:child_process");
  // The dead hub's pid, taken since by an unrelated process of the user's.
  const other = spawn("sleep", ["30"], { stdio: "ignore" });
  cleanups.push(async () => other.kill());
  await writeFile(lock, `${other.pid}\n`);
  assert.equal(isHubProcess(other.pid as number, dir), false);
  assert.equal(takeHubLock(lock, dir), true, "a lock held by a process that is not a hub is taken");
  assert.equal(Number((await readFile(lock, "utf8")).trim()), process.pid);
  // A live hub for this directory holds it.
  const hub = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)", "scripts/vm-hub.ts", "--resume", dir], { stdio: "ignore" });
  cleanups.push(async () => hub.kill());
  await until(() => {
    try {
      process.kill(hub.pid as number, 0);
      return true;
    } catch {
      return false;
    }
  }, "the stand-in hub is up");
  await writeFile(lock, `${hub.pid}\n`);
  assert.equal(isHubProcess(hub.pid as number, dir), true);
  assert.equal(takeHubLock(lock, dir), false, "a second hub for the run does not start");
  assert.equal(Number((await readFile(lock, "utf8")).trim()), hub.pid, "and the live hub's lock is left as it was");
});

test("done from a VM is paced, and calls that arrive together share one run of the operator's finish line on the host", async () => {
  const { hub, sandbox, base } = await setup();
  const was = process.env.SWARM_RUNS_DIR;
  process.env.SWARM_RUNS_DIR = join(base, "runs");
  cleanups.push(async () => {
    if (was === undefined) delete process.env.SWARM_RUNS_DIR;
    else process.env.SWARM_RUNS_DIR = was;
  });
  await registryWithChecks(base, sandbox, ["echo ran >> checks-ran.log; test -f work/never.md"]);
  const calls = Array.from({ length: 6 }, () =>
    board.callBoard(hub.socketFor("a0"), "markDone", [null, { reason: "finished", outputFile: "work/report.md" }]).then(
      () => "ok",
      (err: Error) => err.message,
    ),
  );
  const answers = await Promise.all(calls);
  assert.equal(answers.filter((a) => /slow down: markDone/.test(a)).length, 3, answers.join(" | "));
  assert.equal(answers.filter((a) => /finish line/.test(a)).length, 3, "the three let through were refused on the finish line");
  const ran = (await readFile(join(sandbox, "checks-ran.log"), "utf8")).trim().split("\n").length;
  assert.equal(ran, 1, "one run of the finish line answered the three");
});

test("the hub works from the bytes a VM sends, never its own read: with the seat's directory closed to it, record, diff and publish still answer, from the sent bytes", { skip: process.getuid?.() === 0 && "root reads a mode-000 directory" }, async () => {
  const { hub, sandbox } = await setup();
  const { createHash } = await import("node:crypto");
  const { chmod } = await import("node:fs/promises");
  const own = join(sandbox, "work", "a0");
  await mkdir(own, { recursive: true });
  // What the host disk holds differs from what the VM sends; the hub can read neither.
  await writeFile(join(own, "notes.md"), "HOST\n");
  await chmod(own, 0o000);
  cleanups.push(() => chmod(own, 0o700));
  const b64 = (t: string) => Buffer.from(t).toString("base64");
  const sha = (t: string) => createHash("sha256").update(t).digest("hex");
  const call = (fn: string, args: unknown[]) => board.callBoard(hub.socketFor("a0"), fn, args);
  const r1 = (await call("recordFileVersion", [sandbox, "work/a0/notes.md", "a0", { bytes_b64: b64("VM one\n") }])) as { rev: number; sha256: string };
  assert.equal(r1.sha256, sha("VM one\n"), "the revision is the sent bytes");
  const diff = (await call("fileDiff", [sandbox, "work/a0/notes.md", 1, null, { disk_b64: b64("VM one\nVM two\n") }])) as { added: number; removed: number };
  assert.deepEqual([diff.added, diff.removed], [1, 0], "the disk side of the diff is the sent bytes");
  const pub = (await call("publishFile", [{ sandboxRoot: sandbox, agentId: "a0" }, "work/a0/notes.md", "work/notes.md", { bytes_b64: b64("VM published\n") }])) as { ok: boolean; sha256?: string };
  assert.equal(pub.ok, true, JSON.stringify(pub));
  assert.equal(pub.sha256, sha("VM published\n"));
  assert.equal(await readFile(join(sandbox, "work", "notes.md"), "utf8"), "VM published\n");
});

test("publish tells a peer's directory from a shared one by the hub's roster; with no roster and no team file it publishes nothing", async () => {
  const { sandbox } = await setup();
  const { publishFile } = await import("../extensions/protocol.ts");
  await mkdir(join(sandbox, "work", "a0"), { recursive: true });
  await writeFile(join(sandbox, "work", "a0", "x.md"), "x\n");
  await rm(join(sandbox, "team.json"));
  const ctx = { sandboxRoot: sandbox, agentId: "a0" };
  const peer = await publishFile(ctx, "work/a0/x.md", "work/a1/x.md", { bytes: Buffer.from("x\n"), ids: ["a0", "a1"] });
  assert.equal(peer.ok, false, "the roster names a1's directory");
  assert.match((peer as { reason: string }).reason, /a1's own directory/);
  const blind = await publishFile(ctx, "work/a0/x.md", "work/a1/x.md", { bytes: Buffer.from("x\n") });
  assert.equal(blind.ok, false, "no roster, no team file: refused");
  assert.match((blind as { reason: string }).reason, /team cannot be read/);
  assert.equal(existsSync(join(sandbox, "work", "a1", "x.md")), false);
});

test("the hub records a run's state past a registry lock a dead writer left, and waits on a live one", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-reg-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const registry = join(base, "registry.json");
  await writeFile(registry, JSON.stringify({ runs: [{ id: "t1", state: "running" }] }));
  const { utimes } = await import("node:fs/promises");
  await mkdir(`${registry}.lock`);
  const old = new Date(Date.now() - 5 * 60_000);
  await utimes(`${registry}.lock`, old, old);
  await updateRegistryState(registry, "t1", "finished");
  assert.equal(JSON.parse(await readFile(registry, "utf8")).runs[0].state, "finished", "a lock older than a minute is broken");
  await mkdir(`${registry}.lock`);
  await assert.rejects(updateRegistryState(registry, "t1", "stopped"), /the registry is locked/, "a fresh lock is waited on, not broken");
  assert.equal(JSON.parse(await readFile(registry, "utf8")).runs[0].state, "finished");
});

test("custody's verdicts and the artifact index are the harness's: no seat records, restores or claims them", async () => {
  const { hub, sandbox } = await setup();
  const { isProtectedPath } = await import("../extensions/protocol.ts");
  for (const f of ["custody.json", "custody.20260924T101500Z.json", "custody.previous.json", "custody.previous-20260924.json", "CUSTODY.JSON", "artifacts.json", "work/.trace-spill.jsonl"]) {
    assert.equal(isProtectedPath(f), true, f);
  }
  assert.equal(isProtectedPath("work/custody.json"), false, "a seat's own file of that name under work/ is not the harness's");
  await writeFile(join(sandbox, "custody.json"), '{"verdict":"intact"}\n');
  await assert.rejects(board.callBoard(hub.socketFor("a0"), "recordFileVersion", [sandbox, "custody.json", "a0", null]), /harness-owned path/);
  const restore = (await board.callBoard(hub.socketFor("a0"), "restoreFileVersion", [null, "artifacts.json", 1])) as { ok: boolean; reason?: string };
  assert.equal(restore.ok, false);
  assert.match(restore.reason ?? "", /harness-owned path/);
  const claim = (await board.callBoard(hub.socketFor("a0"), "claimFile", [null, "custody.previous.json", { reason: "edit" }])) as { ok: boolean; protected?: boolean };
  assert.equal(claim.ok, false);
  assert.equal(claim.protected, true);
});

test("a hub socket path past what a Unix socket takes is refused by name, with the path and its length, before anything is bound", async () => {
  const base = await mkdtemp(join(tmpdir(), "dfh-long-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const sandbox = join(base, "sb");
  await mkdir(sandbox, { recursive: true });
  await initSandbox(sandbox, { swarmId: "t1", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30 });
  const dir = join(base, "d".repeat(Math.max(1, 110 - base.length)));
  const hub = new Hub({ sandbox, dir, agents: ["a0"], tokens: {}, collector: join(base, "none.sock"), backstop: false, quiet: true, herdrBin: "/usr/bin/false" });
  const path = hub.socketFor("a0");
  assert.ok(Buffer.byteLength(path) > 103, `the test's path is ${Buffer.byteLength(path)} bytes`);
  await assert.rejects(hub.start(), (err: unknown) => {
    assert.ok(err instanceof SocketPathTooLong);
    assert.equal(err.path, path);
    assert.equal(err.bytes, Buffer.byteLength(path));
    assert.match(err.message, /past the 103 a Unix socket can take/);
    return true;
  });
  assert.equal(existsSync(dir), false, "nothing was created");
});

test("the hub's vm_finish line says what became of msb's database for each VM it removed", async () => {
  assert.deepEqual(msbDbOutcomes('noise\n{"ok":true,"vms":[{"agent":"a0","name":"dfs-t1-a0","msb_db":"scrubbed"},{"agent":"a1","name":"dfs-t1-a1","kept":true}]}\n'), [{ agent: "a0", name: "dfs-t1-a0", msb_db: "scrubbed" }]);
  assert.deepEqual(msbDbOutcomes("not json"), []);
  const pre = await mkdtemp(join(tmpdir(), "dfh-msbdb-"));
  cleanups.push(() => rm(pre, { recursive: true, force: true }));
  const cli = join(pre, "vm.ts");
  await writeFile(
    cli,
    `process.stdout.write(JSON.stringify({ ok: true, vms: [{ agent: "a0", name: "dfs-t1-a0", msb_db: "busy" }, { agent: "a1", name: "dfs-t1-a1", msb_db: "busy" }] }) + "\\n");\n`,
  );
  const { hub, sandbox, lines } = await setup({ extra: { run: "t1", vmCli: cli, snapshot: false } });
  await writeFile(join(sandbox, SENTINEL_REL), "---\nby: a0\nreason: done\n---\n");
  for (const a of ["a0", "a1"]) await writeFile(join(sandbox, "done", "agents", `${a}.done`), "---\nby: x\n---\n");
  await hub.backstop(Date.now());
  await hub.backstop(Date.now() + 1000);
  const finish = lines.find((l) => l.tool === "vm_finish");
  assert.ok(finish, "the finish is on the trace");
  assert.deepEqual((finish.result as { msb_db?: unknown }).msb_db, [
    { agent: "a0", name: "dfs-t1-a0", msb_db: "busy" },
    { agent: "a1", name: "dfs-t1-a1", msb_db: "busy" },
  ]);
});
