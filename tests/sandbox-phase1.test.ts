/**
 * Phase 1 of docs/sandbox-plan.md: the two structural holes.
 *
 * The write guard is a shell test (`tests/write-guard.test.sh`) because it is
 * a kernel profile. This is the other half: the trace's writer lives outside
 * the panes, and every line it writes names the line before it.
 */
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { appendEvent, verifyEventChain, COLLECTOR_SOCKET_REL } from "../extensions/protocol.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const started: ChildProcess[] = [];
/** What each collector started with `collectorWithTokens` said on stderr, by sandbox. */
const collectorLogs = new Map<string, string>();

after(() => {
  for (const proc of started) proc.kill("SIGTERM");
});

async function collectorOn(root: string): Promise<string> {
  await mkdir(join(root, "traces"), { recursive: true });
  const proc = spawn("node", [join(ROOT, "scripts", "trace-collector.mjs"), root, "--quiet"], { stdio: "ignore" });
  started.push(proc);
  const socket = join(root, COLLECTOR_SOCKET_REL);
  return collectorUp(socket);
}

/**
 * The collector's socket once it accepts a connection, not merely once the
 * file exists: the file appears at bind, before listen, and a connect in
 * between is ECONNREFUSED (a CI run of the torn-append test, cb2f0be). The
 * probe sends nothing. A path past the kernel's limit cannot be dialled
 * from here as it is, so there the file is what is waited for.
 */
async function collectorUp(socket: string): Promise<string> {
  const accepts = () =>
    new Promise<boolean>((resolve) => {
      const s = connect(socket);
      s.on("connect", () => {
        s.destroy();
        resolve(true);
      });
      s.on("error", () => resolve(false));
    });
  const dialable = Buffer.byteLength(socket) < 100;
  for (let i = 0; i < 200; i += 1) {
    const there = await stat(socket).then((st) => st.isSocket()).catch(() => false);
    if (there && (!dialable || (await accepts()))) return socket;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("the collector did not come up");
}

async function lines(root: string): Promise<string[]> {
  const text = await readFile(join(root, "traces", "events.jsonl"), "utf8").catch(() => "");
  return text.split("\n").filter(Boolean);
}

test("the collector writes the trace and chains every line to the one before it", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-collector-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    for (let i = 0; i < 6; i += 1) {
      await appendEvent(root, { agent: `a${i % 3}`, tool: "bash", args: { n: i }, result: { ok: true } });
    }
    await new Promise((r) => setTimeout(r, 250));
    const written = await lines(root);
    assert.equal(written.length, 6);
    const text = `${written.join("\n")}\n`;
    const chain = verifyEventChain(text);
    assert.deepEqual({ ok: chain.ok, chained: chain.chained, total: chain.total }, { ok: true, chained: 6, total: 6 });
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a line inserted after the fact breaks the chain and names where", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-chain-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    for (let i = 0; i < 4; i += 1) await appendEvent(root, { agent: "a0", tool: "read", args: { n: i }, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    const written = await lines(root);
    // What an agent editing its own history would produce: a plausible line,
    // with a plausible parent hash, in the middle.
    const forged = JSON.stringify({ ts: "2026-01-01T00:00:00Z", agent: "a0", tool: "read", args: {}, result: { ok: true }, prev: "f".repeat(64) });
    const tampered = `${[...written.slice(0, 2), forged, ...written.slice(2)].join("\n")}\n`;
    const chain = verifyEventChain(tampered);
    assert.equal(chain.ok, false);
    assert.equal(chain.broken_at, 3);
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a malformed message is refused rather than written", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-malformed-"));
  const socket = await collectorOn(root);
  await new Promise<void>((resolve, reject) => {
    const s = connect(socket);
    s.on("error", reject);
    s.on("connect", () => s.end('this is not json\n{"ts":"t","agent":"a0","tool":"post","args":{},"result":{}}\n', () => resolve()));
  });
  await new Promise((r) => setTimeout(r, 250));
  const written = await lines(root);
  assert.equal(written.length, 1, "the good line lands and the bad one does not");
  assert.equal(JSON.parse(written[0]).tool, "post");
});

test("with no collector the harness still writes its own trace, and says it is unchained", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-nocollector-"));
  delete process.env.SWARM_TRACE_SOCKET;
  await appendEvent(root, { agent: "a0", tool: "post", args: {}, result: { ok: true } });
  const written = await lines(root);
  assert.equal(written.length, 1);
  const chain = verifyEventChain(`${written.join("\n")}\n`);
  assert.equal(chain.ok, true, "an unchained file is not a broken one");
  assert.equal(chain.chained, 0, "and it does not claim a chain it does not have");
});

test("a socket that is not there falls back instead of losing the line", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-deadsocket-"));
  process.env.SWARM_TRACE_SOCKET = join(root, "nothing-listening.sock");
  try {
    await appendEvent(root, { agent: "a0", tool: "wait", args: {}, result: { ok: true } });
    assert.equal((await lines(root)).length, 1);
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});


test("a pane that cannot reach the collector or the file spills rather than losing the line", async () => {
  // With a collector running, traces/ is read-only to the pane — the point of
  // the design — so a failed send has nowhere to write. Losing the line in
  // silence is the one outcome a record cannot have.
  const root = await mkdtemp(join(tmpdir(), "swarm-spill-"));
  await mkdir(join(root, "traces"), { recursive: true });
  await mkdir(join(root, "work"), { recursive: true });
  // A directory where the file should be: appendFile fails with EISDIR, which
  // stands in for "the kernel refuses this write".
  await mkdir(join(root, "traces", "events.jsonl"), { recursive: true });
  process.env.SWARM_TRACE_SOCKET = join(root, "nothing-listening.sock");
  try {
    await appendEvent(root, { agent: "a0", tool: "bash", args: { n: 1 }, result: { ok: true } }).catch(() => undefined);
    const spill = await readFile(join(root, "work", ".trace-spill.jsonl"), "utf8").catch(() => "");
    assert.equal(spill.split("\n").filter(Boolean).length, 1, "the line is in the spill, not gone");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a pane that loses the collector mid-run spills rather than appending an unchained line to the chain", async () => {
  // With no write guard, traces/ stays writable to the pane, so the fallback
  // append succeeds — and an unchained line after a chained one is exactly
  // what the verifier reports as "appended": a tamper alarm the harness would
  // raise against itself. The shell watchdogs already spill in this case.
  const root = await mkdtemp(join(tmpdir(), "swarm-lostcollector-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    for (let i = 0; i < 2; i += 1) await appendEvent(root, { agent: "a0", tool: "read", args: { n: i }, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    assert.equal(verifyEventChain(`${(await lines(root)).join("\n")}\n`).chained, 2);
    // The collector stops answering: a socket nothing listens on.
    process.env.SWARM_TRACE_SOCKET = join(root, "nothing-listening.sock");
    await appendEvent(root, { agent: "a0", tool: "bash", args: { prev: "not a chain" }, result: { ok: true } });
    const written = await lines(root);
    assert.equal(written.length, 2, "the chained record is not appended to");
    const chain = verifyEventChain(`${written.join("\n")}\n`);
    assert.equal(chain.ok, true, `the record still verifies (${chain.reason ?? ""} at ${chain.broken_at ?? ""})`);
    const spill = await readFile(join(root, "work", ".trace-spill.jsonl"), "utf8").catch(() => "");
    assert.equal(spill.split("\n").filter(Boolean).length, 1, "the line is in the spill, not gone");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a pane that finds a torn line at the end of the trace spills rather than fusing onto it", async () => {
  // A collector killed mid-append leaves a fragment with no newline after the
  // chained records. A line appended there would join the fragment into one
  // unparseable line, and the record could never verify again.
  const root = await mkdtemp(join(tmpdir(), "swarm-torntail-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    for (let i = 0; i < 2; i += 1) await appendEvent(root, { agent: "a0", tool: "read", args: { n: i }, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    const events = join(root, "traces", "events.jsonl");
    const before = await readFile(events, "utf8");
    await appendFile(events, '{"ts":"2026-01-01T00:00:00Z","agent":"a0","tool":"bash","args":{"cmd":"cut sh', "utf8");
    process.env.SWARM_TRACE_SOCKET = join(root, "nothing-listening.sock");
    await appendEvent(root, { agent: "a0", tool: "bash", args: { n: 3 }, result: { ok: true } });
    const after = await readFile(events, "utf8");
    assert.ok(after.startsWith(before) && !after.slice(before.length).includes("\n"), "nothing is appended onto the fragment");
    const spill = await readFile(join(root, "work", ".trace-spill.jsonl"), "utf8").catch(() => "");
    assert.equal(spill.split("\n").filter(Boolean).length, 1, "the line is in the spill, not gone");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("the socket lives under traces/, which the write guard denies to the panes", () => {
  // A socket in the sandbox root is one an agent can unlink — and then bind
  // its own, becoming the writer of the record of what it did. Measured under
  // a real profile: unlink in the sandbox root succeeds, under traces/ it does
  // not.
  assert.equal(COLLECTOR_SOCKET_REL, "traces/.collector.sock");
});

test("the harness's own watchdogs record through the collector, so their lines are chained too", async () => {
  // idle-nudge.sh and reap.sh append the harness's own events. They used to
  // write the file directly — they run outside every pane, so the read-only
  // guard does not touch them — and their unchained line broke the *next*
  // collector line: with the watchdog on by default, a run reported its own
  // record as edited every three minutes. They send through the socket now,
  // which is also what lets an unchained line mean something.
  const root = await mkdtemp(join(tmpdir(), "swarm-external-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    await appendEvent(root, { agent: "a0", tool: "bash", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 200));

    const emit = spawn("node", [join(ROOT, "scripts", "trace-emit.mjs"), root], { stdio: ["pipe", "ignore", "ignore"] });
    emit.stdin?.end(JSON.stringify({ ts: "t2", agent: "system", tool: "idle_nudge", args: {}, result: { ok: true } }));
    const code = await new Promise<number>((resolve) => emit.on("exit", (c) => resolve(c ?? 1)));
    assert.equal(code, 0, "trace-emit reports whether the collector took the line");

    await appendEvent(root, { agent: "a0", tool: "read", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));

    const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
    assert.equal(chain.ok, true, "every line went through the one writer");
    assert.equal(chain.total, 3);
    assert.equal(chain.chained, 3, "including the watchdog's");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a direct append still cannot corrupt the lines that follow it", async () => {
  // Belt and braces: something that appends anyway — a future writer, a bug —
  // is caught by the verifier, and must not also break the next real line.
  const root = await mkdtemp(join(tmpdir(), "swarm-external2-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    await appendEvent(root, { agent: "a0", tool: "bash", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 200));
    const { appendFile } = await import("node:fs/promises");
    await appendFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "system", tool: "reap", args: {}, result: {} })}\n`, "utf8");
    await appendEvent(root, { agent: "a0", tool: "read", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    const all = await lines(root);
    const last = JSON.parse(all[2]) as { prev: string };
    const { createHash } = await import("node:crypto");
    assert.equal(last.prev, createHash("sha256").update(all[1]).digest("hex"), "the collector picked the chain up from the file");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a socket path past the kernel's limit still works", async () => {
  // ~/Library/CloudStorage/Dropbox/…/runs/<id>/traces/.collector.sock is 110
  // bytes, and a Unix socket path is limited to about 104. Binding and
  // connecting relative to the directory keeps what the kernel sees short —
  // without it the collector silently fails to start and every pane writes
  // its own unchained trace.
  const deep = join(await mkdtemp(join(tmpdir(), `swarm-${"d".repeat(60)}-`)), "runs", "s1234");
  await mkdir(join(deep, "traces"), { recursive: true });
  assert.ok(join(deep, COLLECTOR_SOCKET_REL).length > 104, "the fixture has to be past the limit to test it");
  const socket = await collectorOn(deep);
  const cwd = process.cwd();
  process.chdir(deep);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    await appendEvent(deep, { agent: "a0", tool: "bash", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    assert.equal((await lines(deep)).length, 1);
    assert.equal(verifyEventChain(`${(await lines(deep)).join("\n")}\n`).chained, 1, "and it is chained");
  } finally {
    process.chdir(cwd);
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

/** A collector with a token map and an anchor, the way the kickoff starts one. */
async function collectorWithTokens(root: string, map: Record<string, unknown>, anchor: string, fileLimitKb = 0): Promise<string> {
  await mkdir(join(root, "traces"), { recursive: true });
  const args = [join(ROOT, "scripts", "trace-collector.mjs"), root, "--tokens", "--anchor", anchor, "--quiet"];
  // A file-size limit stands in for a full disk: an append that crosses it
  // writes up to the limit and then fails, as ENOSPC does, with no tmpfs and
  // no root. SIGXFSZ is ignored so the write fails instead of killing it.
  const proc = fileLimitKb
    ? spawn("bash", ["-c", `trap '' XFSZ; ulimit -f ${fileLimitKb}; exec node "$@"`, "bash", ...args], { stdio: ["pipe", "ignore", "ignore"] })
    : spawn("node", args, { stdio: ["pipe", "ignore", "pipe"] });
  started.push(proc);
  proc.stderr?.on("data", (chunk: Buffer) => collectorLogs.set(root, (collectorLogs.get(root) ?? "") + chunk.toString("utf8")));
  // The one line the kickoff writes: `{tokens, gate}`. A bare map here is a
  // token map with no gate; a map that already has the shape is passed as is.
  const line = typeof map.tokens === "object" && map.tokens !== null ? map : { tokens: map, gate: "" };
  proc.stdin?.end(JSON.stringify(line));
  const socket = join(root, COLLECTOR_SOCKET_REL);
  return collectorUp(socket);
}

function sendRaw(socket: string, payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = connect(socket);
    s.on("error", reject);
    s.on("connect", () => s.end(`${JSON.stringify(payload)}\n`, () => resolve()));
  });
}

test("a line is attributed by its token, not by what it claims", async () => {
  // Every pane shares one uid, so nothing in the body can be trusted to say
  // who wrote it. The token can: macOS does not let one process read
  // another's environment, and Herdr's API does not expose a pane's env.
  const root = await mkdtemp(join(tmpdir(), "swarm-token-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { "tok-a0": "a0", "tok-a1": "a1" }, anchor);

  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a0" });
  // a1 trying to put an event on a0's name — the forgery the socket allows.
  await sendRaw(socket, { ts: "t2", agent: "a0", tool: "bash", args: { command: "rm -rf /evidence" }, result: { ok: true }, token: "tok-a1" });
  // and one with no token at all
  await sendRaw(socket, { ts: "t3", agent: "a0", tool: "read", args: {}, result: { ok: true } });
  await new Promise((r) => setTimeout(r, 300));

  const written = (await lines(root)).map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.equal(written.length, 3);
  assert.equal(written[0].agent, "a0");
  assert.equal(written[0].token, undefined, "the token is a secret, never a field in the record");

  assert.equal(written[1].agent, "a1", "the sender, not the claim");
  assert.equal(written[1].claimed_agent, "a0", "and the attempt is on the record");

  assert.equal(written[2].agent_unverified, true, "a line with no token says so");

  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
  assert.equal(chain.ok, true);
  assert.equal(chain.disputed, 1);
  assert.equal(chain.unverified, 1);
});


test("the collector decides the verdict, so a sender cannot stamp its own", async () => {
  // `agent_unverified` and `claimed_agent` are what the collector concluded
  // about a line. A sender that supplies them concludes for it: it can mark
  // its own work unattributable and repudiate it later, or spray the dispute
  // flag until a real forgery is one row among hundreds. They are stripped
  // on the way in, like `prev`.
  const root = await mkdtemp(join(tmpdir(), "swarm-verdict-"));
  const socket = await collectorWithTokens(root, { "tok-a0": "a0" }, join(root, "anchor.json"));

  await sendRaw(socket, {
    ts: "t1",
    agent: "a0",
    tool: "bash",
    args: {},
    result: { ok: true },
    token: "tok-a0",
    agent_unverified: true,
    claimed_agent: "someone-else",
    prev: "0".repeat(64),
  });
  await new Promise((r) => setTimeout(r, 300));

  const written = (await lines(root)).map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.equal(written.length, 1);
  assert.equal(written[0].agent, "a0");
  assert.equal(written[0].agent_unverified, undefined, "a sender cannot mark its own line unattributed");
  assert.equal(written[0].claimed_agent, undefined, "nor invent a dispute");
  assert.notEqual(written[0].prev, "0".repeat(64), "nor choose its own parent");

  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
  assert.equal(chain.unverified, 0);
  assert.equal(chain.disputed, 0);
});

test("with a gate in front, a token attributes only on a line the gate vouched for", async () => {
  // Linux: every pane of one uid can read a peer's environment, so the token
  // is not a secret there. scripts/trace-gate.py decides the sender from
  // SO_PEERCRED and marks each forwarded line with a key the panes never
  // see; the collector counts a token only beside that key.
  const root = await mkdtemp(join(tmpdir(), "swarm-gate-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { tokens: { "tok-a0": "a0", "tok-a1": "a1" }, gate: "k-0123" }, anchor);

  // straight from a pane, with a token it read from /proc
  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a0" });
  // the same line as the gate forwards it
  await sendRaw(socket, { ts: "t2", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a1", gate: "k-0123" });
  // a guessed key
  await sendRaw(socket, { ts: "t3", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a0", gate: "k-9999" });

  // Waited for, not slept on: a fixed 150 ms was short on a loaded CI
  // runner. Three connections may land in any order; each line is found by
  // its own ts.
  let lines: Record<string, unknown>[] = [];
  for (let i = 0; i < 100 && lines.length < 3; i++) {
    await new Promise((r) => setTimeout(r, 50));
    const text = await readFile(join(root, "traces", "events.jsonl"), "utf8").catch(() => "");
    lines = text.trim() ? text.trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>) : [];
  }
  assert.equal(lines.length, 3);
  const written = ["t1", "t2", "t3"].map((ts) => lines.find((l) => l.ts === ts) as Record<string, unknown>);
  assert.equal(written[0].agent_unverified, true, "a token without the gate's key does not attribute");
  assert.equal(written[1].agent, "a1", "the gate's token decides, whatever the body claims");
  assert.equal(written[1].claimed_agent, "a0");
  assert.equal(written[1].agent_unverified, undefined);
  assert.equal(written[2].agent_unverified, true, "a wrong key is no key");
  for (const w of written) {
    assert.equal(w.gate, undefined, "the key never reaches the record");
    assert.equal(w.token, undefined);
  }
});

test("the anchor only ever grows, so truncating the trace cannot reset it", async () => {
  // It used to re-read the line count from the file. Cutting the trace down
  // and letting the collector write one more line moved the anchor to the
  // shorter count, and the record then verified as intact — an anchor that
  // forgets is not an anchor.
  const root = await mkdtemp(join(tmpdir(), "swarm-anchor-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (let i = 1; i <= 4; i += 1) {
    await sendRaw(socket, { ts: `t${i}`, agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  }
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(JSON.parse(await readFile(anchor, "utf8")).lines, 4);

  const { writeFile } = await import("node:fs/promises");
  const kept = (await lines(root)).slice(0, 2);
  await writeFile(join(root, "traces", "events.jsonl"), `${kept.join("\n")}\n`, "utf8");
  await sendRaw(socket, { ts: "t5", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  await new Promise((r) => setTimeout(r, 400));

  const after = JSON.parse(await readFile(anchor, "utf8"));
  assert.equal(after.lines, 5, "the anchor counts what was written, not what survived");
  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`, {
    lines: after.lines,
    head: after.head,
    prev_head: after.prev_head,
  });
  assert.equal(chain.ok, false, "and the shortened record no longer matches it");
});

test("a line the collector refuses is reported as refused, not as written", async () => {
  // `trace-emit` used to exit 0 when the bytes reached the kernel. A line the
  // collector then threw away — over the size limit, missing a field — looked
  // recorded to its caller, whose fallback exists for exactly that case and
  // never ran. An event that disappears quietly is the one failure this file
  // cannot have.
  const root = await mkdtemp(join(tmpdir(), "swarm-refused-"));
  await collectorWithTokens(root, { t: "a0" }, join(root, "anchor.json"));
  const emit = (payload: unknown) =>
    new Promise<number>((resolve) => {
      const proc = spawn("node", [join(ROOT, "scripts", "trace-emit.mjs"), root], {
        stdio: ["pipe", "ignore", "ignore"],
      });
      proc.stdin?.end(JSON.stringify(payload));
      proc.on("exit", (code) => resolve(code ?? -1));
    });

  assert.equal(await emit({ ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true } }), 0);
  // No `tool`, so the collector refuses it.
  assert.equal(await emit({ ts: "t2", agent: "a0", args: {} }), 1, "a refused line must not report success");
  assert.equal((await lines(root)).length, 1, "and it is not in the record");
  // Past the old 1 MB line limit: recorded now. The trace keeps every result
  // whole, a 60,000-character bash output is ordinary, and the collector's
  // own ceiling is 64 MB a line. Only a malformed message is refused.
  assert.equal(await emit({ ts: "t3", agent: "a0", tool: "bash", args: {}, result: { ok: true, output: "x".repeat(1_100_000) } }), 0, "a 1.1 MB line is written whole");
  const recorded = await lines(root);
  assert.equal(recorded.length, 2);
  assert.equal(String((JSON.parse(recorded[1]!) as { result?: { output?: string } }).result?.output).length, 1_100_000, "and nothing of it was cut");
});

test("a line appended after the collector started breaks the chain", async () => {
  // The gap the hash chain did not close: an edit in the middle was caught,
  // an append at the end was not, because an unchained line was simply
  // skipped. Every legitimate writer goes through the collector now, so an
  // unchained line after the first chained one is something else's work.
  const root = await mkdtemp(join(tmpdir(), "swarm-append-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  await new Promise((r) => setTimeout(r, 250));
  const { appendFile } = await import("node:fs/promises");
  await appendFile(
    join(root, "traces", "events.jsonl"),
    `${JSON.stringify({ ts: "t2", agent: "a0", tool: "done", args: {}, result: { ok: true } })}\n`,
    "utf8",
  );
  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
  assert.equal(chain.ok, false);
  assert.equal(chain.reason, "appended");
  assert.equal(chain.broken_at, 2);
});

test("a trace rewritten from the first line no longer matches the anchor", async () => {
  // A chain recomputed over a file somebody rewrote verifies against itself.
  // The anchor is what it cannot reproduce: it lives outside the sandbox,
  // where the write guard keeps a pane from reaching it.
  const root = await mkdtemp(join(tmpdir(), "swarm-anchor-"));
  const anchor = join(root, "..", `anchor-${Date.now()}.json`);
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (const n of [1, 2, 3]) {
    await sendRaw(socket, { ts: `t${n}`, agent: "a0", tool: "bash", args: { n }, result: { ok: true }, token: "t" });
  }
  await new Promise((r) => setTimeout(r, 350));
  const recorded = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string };
  assert.equal(recorded.lines, 3);

  const honest = `${(await lines(root)).join("\n")}\n`;
  assert.equal(verifyEventChain(honest, recorded).ok, true, "the real file matches its anchor");

  // What a rewrite looks like: two of the three lines, chained correctly.
  const { createHash } = await import("node:crypto");
  const kept = (await lines(root)).slice(0, 2);
  const rebuilt: string[] = [];
  let prev = "";
  for (const line of kept) {
    const record = { ...(JSON.parse(line) as Record<string, unknown>), prev };
    const rebuiltLine = JSON.stringify(record);
    rebuilt.push(rebuiltLine);
    prev = createHash("sha256").update(rebuiltLine).digest("hex");
  }
  const forged = `${rebuilt.join("\n")}\n`;
  assert.equal(verifyEventChain(forged).ok, true, "it verifies against itself, which is the problem");
  const caught = verifyEventChain(forged, recorded);
  assert.equal(caught.ok, false, "and against the anchor it does not");
  assert.equal(caught.reason, "shortened");
});

test("a message that is not an event is refused, whatever shape it has", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-shape-"));
  const socket = await collectorWithTokens(root, { t: "a0" }, join(root, "anchor.json"));
  await sendRaw(socket, [1, 2, 3]);
  await sendRaw(socket, { totally: "unrelated", token: "t" });
  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "post", args: {}, result: {}, token: "t" });
  await new Promise((r) => setTimeout(r, 300));
  const written = await lines(root);
  assert.equal(written.length, 1, "only the event lands");
  assert.equal((JSON.parse(written[0]) as { tool: string }).tool, "post");
});

test("a multibyte character split across two socket reads is written whole", async () => {
  // A large event arrives in several reads, and a read boundary can fall
  // inside a UTF-8 sequence. Decoding each read on its own turned both halves
  // into U+FFFD; the line still parsed, so the altered text was hashed into
  // the chain and the trace verified as intact while saying something else.
  const root = await mkdtemp(join(tmpdir(), "swarm-utf8-"));
  const socket = await collectorOn(root);
  const text = "İstanbul 東京 🔍 Москва";
  const bytes = Buffer.from(`${JSON.stringify({ ts: "t1", agent: "a0", tool: "bash", args: {}, result: { output: text } })}\n`, "utf8");
  // Cut inside the four-byte emoji.
  const cut = bytes.indexOf(Buffer.from("🔍", "utf8")) + 2;
  await new Promise<void>((resolve, reject) => {
    const s = connect(socket);
    s.on("error", reject);
    s.on("connect", () => {
      s.write(bytes.subarray(0, cut), () => {
        // Long enough that the collector reads the first half on its own.
        setTimeout(() => s.end(bytes.subarray(cut), () => resolve()), 150);
      });
    });
  });
  await new Promise((r) => setTimeout(r, 250));
  const written = await lines(root);
  assert.equal(written.length, 1);
  assert.equal((JSON.parse(written[0]!) as { result: { output: string } }).result.output, text);
});

test("a line the collector could not append leaves the chain where it was", { skip: process.getuid?.() === 0 && "root ignores file modes" }, async () => {
  // The chain head and the line count used to move before the append. When
  // the append threw — a full disk, a file gone read-only — the sender was
  // told ok:false and spilled the line, but the collector's head now named a
  // line that was never written. The next real line carried that phantom as
  // its parent, and the harness reported its own record as edited.
  const root = await mkdtemp(join(tmpdir(), "swarm-failed-append-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  const send = (payload: unknown) =>
    new Promise<{ ok: boolean }>((resolve, reject) => {
      const s = connect(socket);
      let got = "";
      s.on("error", reject);
      s.on("data", (chunk) => {
        got += chunk.toString("utf8");
        if (got.includes("\n")) {
          s.end();
          resolve(JSON.parse(got.slice(0, got.indexOf("\n"))) as { ok: boolean });
        }
      });
      s.on("connect", () => s.write(`${JSON.stringify(payload)}\n`));
    });
  const events = join(root, "traces", "events.jsonl");
  const { chmod } = await import("node:fs/promises");

  assert.equal((await send({ ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);
  await chmod(events, 0o444);
  try {
    const refused = await send({ ts: "t2", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
    assert.equal(refused.ok, false, "a line that could not be written is not reported as written");
  } finally {
    await chmod(events, 0o644);
  }
  const between = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; pending: boolean };
  assert.deepEqual({ lines: between.lines, pending: between.pending }, { lines: 1, pending: false }, "the anchor still names the last line written");
  assert.equal((await send({ ts: "t3", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);

  const recorded = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string; prev_head: string };
  assert.equal((await lines(root)).length, 2);
  assert.equal(recorded.lines, 2);
  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`, recorded);
  assert.equal(chain.ok, true, `the record verifies after a failed append (${chain.reason ?? ""})`);
});

test("a line cut short by a full disk is taken back out of the trace", async () => {
  // A full disk fails an append partway: part of the line is on disk when it
  // throws. Rolling back only the head left that fragment, with no newline,
  // at the end of the file; the next line was written onto it, the anchor
  // counted a line the file did not have, and the record read as edited.
  const root = await mkdtemp(join(tmpdir(), "swarm-torn-append-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor, 64);
  const send = (payload: unknown) =>
    new Promise<{ ok: boolean }>((resolve, reject) => {
      const s = connect(socket);
      let got = "";
      s.on("error", reject);
      s.on("data", (chunk) => {
        got += chunk.toString("utf8");
        if (got.includes("\n")) {
          s.end();
          resolve(JSON.parse(got.slice(0, got.indexOf("\n"))) as { ok: boolean });
        }
      });
      s.on("connect", () => s.write(`${JSON.stringify(payload)}\n`));
    });
  const events = join(root, "traces", "events.jsonl");

  assert.equal((await send({ ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);
  const before = (await stat(events)).size;
  const big = await send({ ts: "t2", agent: "a0", tool: "bash", args: { out: "x".repeat(200_000) }, result: { ok: true }, token: "t" });
  assert.equal(big.ok, false, "a line that did not fit is not reported as written");
  assert.equal((await stat(events)).size, before, "no fragment of it is left in the file");
  assert.equal((await send({ ts: "t3", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);

  const recorded = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string; prev_head: string };
  const written = await lines(root);
  assert.deepEqual(written.map((l) => (JSON.parse(l) as { ts: string }).ts), ["t1", "t3"]);
  assert.equal(recorded.lines, 2);
  const chain = verifyEventChain(`${written.join("\n")}\n`, recorded);
  assert.equal(chain.ok, true, `the record verifies after a torn append (${chain.reason ?? ""})`);
});

/** Send one event and wait for the collector's verdict on it. */
function sendForReply(socket: string, payload: unknown): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve, reject) => {
    const s = connect(socket);
    let got = "";
    s.on("error", reject);
    s.on("data", (chunk) => {
      got += chunk.toString("utf8");
      if (got.includes("\n")) {
        s.end();
        resolve(JSON.parse(got.slice(0, got.indexOf("\n"))) as { ok: boolean; error?: string });
      }
    });
    s.on("connect", () => s.write(`${JSON.stringify(payload)}\n`));
  });
}

/**
 * Kill the collector started last, as a crash would, and clear the socket it
 * leaves behind, as the kickoff does before it starts the next one.
 */
async function killLastCollector(root: string): Promise<void> {
  const proc = started[started.length - 1];
  const gone = new Promise((r) => proc.once("exit", r));
  proc.kill("SIGKILL");
  await gone;
  await rm(join(root, COLLECTOR_SOCKET_REL), { force: true });
}

test("a restarted collector refuses to append onto a partial line it finds", async () => {
  // A collector killed mid-append leaves a fragment with no newline. The next
  // collector used to take the fragment as the last line, chain onto it and
  // write the next line straight after it: the sender was told `ok`, and the
  // line was fused into the fragment and lost from the record.
  const root = await mkdtemp(join(tmpdir(), "swarm-restart-torn-"));
  const anchor = join(root, "anchor.json");
  let socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (let i = 1; i <= 2; i += 1) {
    assert.equal((await sendForReply(socket, { ts: `t${i}`, agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);
  }
  await killLastCollector(root);
  const events = join(root, "traces", "events.jsonl");
  await appendFile(events, '{"ts":"t3","agent":"a0","tool":"bash","args":{"cmd":"cut sh', "utf8");
  const before = await readFile(events, "utf8");
  // No anchor to say the fragment is the line it promised: it is not this
  // collector's to cut. (One that does is the next test.)
  await rm(anchor);

  socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  const reply = await sendForReply(socket, { ts: "t4", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  assert.equal(reply.ok, false, "the sender is told the line was not written, so it spills it");
  assert.equal(await readFile(events, "utf8"), before, "nothing is appended onto the fragment");
  await new Promise((r) => setTimeout(r, 100));
  assert.match(collectorLogs.get(root) ?? "", /could not write a line: the trace ends in a partial line/, "the refusal is logged under --quiet");
});

test("a restarted collector cuts off the partial line its anchor promised and never acknowledged", async () => {
  // A collector killed mid-append leaves its anchor pending on the line it was
  // writing and a fragment of that line on disk. Nothing else ever cuts a
  // fragment a collector did not write, so it used to refuse every line for
  // the rest of the run.
  const root = await mkdtemp(join(tmpdir(), "swarm-restart-cut-"));
  const anchor = join(root, "anchor.json");
  let socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (let i = 1; i <= 2; i += 1) {
    assert.equal((await sendForReply(socket, { ts: `t${i}`, agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);
  }
  await killLastCollector(root);
  const events = join(root, "traces", "events.jsonl");
  const kept = await lines(root);
  const fragment = '{"ts":"t3","agent":"a0","tool":"bash","args":{"cmd":"cut sh';
  // Exactly what a kill between the anchor write and the end of the append leaves.
  const head2 = createHash("sha256").update(kept[1]).digest("hex");
  await writeFile(anchor, `${JSON.stringify({ lines: 3, head: "never-written", prev_head: head2, pending: true })}\n`, "utf8");
  await appendFile(events, fragment, "utf8");

  socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  const text = await readFile(events, "utf8");
  assert.ok(text.endsWith("\n"), "the fragment is off the end of the trace");
  const now = text.split("\n").filter(Boolean);
  assert.deepEqual(now.slice(0, 2), kept, "the whole lines before it are untouched");
  const cutLine = JSON.parse(now[2]) as { tool: string; prev: string; args: { bytes: number; saved_to: string } };
  assert.equal(cutLine.tool, "trace_fragment_cut", "the cut is itself a line of the record");
  assert.equal(cutLine.prev, head2, "chained onto the last whole line");
  assert.equal(cutLine.args.bytes, Buffer.byteLength(fragment));
  assert.equal(await readFile(join(root, cutLine.args.saved_to), "utf8"), fragment, "the fragment is kept under traces/");
  assert.ok(cutLine.args.saved_to.startsWith("traces/"));

  const reply = await sendForReply(socket, { ts: "t4", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  assert.equal(reply.ok, true, "the collector writes again");
  const recorded = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string; prev_head: string; pending: boolean };
  assert.equal(recorded.lines, 4);
  const chain = verifyEventChain(await readFile(events, "utf8"), recorded);
  assert.equal(chain.ok, true, `the record verifies after the cut (${chain.reason ?? ""})`);
});

test("a collector restarted over a shortened trace keeps the anchor it found", async () => {
  // A restarted collector used to count the file for its anchor. Lines cut
  // from the trace while no collector ran lowered the anchor to match, and
  // the shortened record then verified as intact.
  const root = await mkdtemp(join(tmpdir(), "swarm-restart-anchor-"));
  const anchor = join(root, "anchor.json");
  let socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (let i = 1; i <= 4; i += 1) {
    assert.equal((await sendForReply(socket, { ts: `t${i}`, agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);
  }
  await killLastCollector(root);
  assert.equal(JSON.parse(await readFile(anchor, "utf8")).lines, 4);
  await writeFile(join(root, "traces", "events.jsonl"), `${(await lines(root)).slice(0, 2).join("\n")}\n`, "utf8");

  socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  await new Promise((r) => setTimeout(r, 200));
  const recorded = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string; prev_head: string };
  // Four, and the line that records the mismatch the restart found.
  assert.equal(recorded.lines, 5, "the anchor still says how long the record was");
  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`, recorded);
  assert.equal(chain.ok, false, "and the shortened record does not verify");
  assert.equal(chain.reason, "shortened");
  assert.equal(JSON.parse(await readFile(join(root, "anchor.prev.json"), "utf8")).lines, 4, "the anchor found is kept");
});

test("a collector restarted over a trace rewritten to the same length keeps the anchor it found and records the mismatch", async () => {
  // A restart wrote a fresh anchor naming whatever head the file had. A trace
  // rewritten while no collector ran, with a recomputed chain and the same
  // number of lines, was re-anchored onto and verified as intact.
  const root = await mkdtemp(join(tmpdir(), "swarm-restart-rewrite-"));
  const anchor = join(root, "anchor.json");
  let socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (let i = 1; i <= 4; i += 1) {
    assert.equal((await sendForReply(socket, { ts: `t${i}`, agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" })).ok, true);
  }
  await killLastCollector(root);
  const found = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string };
  assert.equal(found.lines, 4);
  let prev = "";
  const forged = [1, 2, 3, 4].map((i) => {
    const line = JSON.stringify({ ts: `t${i}`, agent: "a0", tool: "bash", args: { cmd: "something else" }, result: { ok: true }, prev });
    prev = createHash("sha256").update(line).digest("hex");
    return line;
  });
  await writeFile(join(root, "traces", "events.jsonl"), `${forged.join("\n")}\n`, "utf8");
  assert.equal(verifyEventChain(`${forged.join("\n")}\n`).ok, true, "the forged chain verifies against itself");

  socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  await new Promise((r) => setTimeout(r, 200));
  const kept = JSON.parse(await readFile(join(root, "anchor.prev.json"), "utf8")) as { lines: number; head: string };
  assert.deepEqual([kept.lines, kept.head], [found.lines, found.head], "the anchor found is kept, not re-anchored over");
  const now = await lines(root);
  assert.deepEqual(now.slice(0, 4), forged, "the collector does not edit the file it found");
  const mismatch = JSON.parse(now[4]) as { tool: string; prev: string; args: { reason: string; anchor_head: string; anchor_lines: number } };
  assert.equal(mismatch.tool, "trace_anchor_mismatch", "the mismatch is a line of the record");
  assert.equal(mismatch.prev, prev, "chained onto the file as found");
  assert.deepEqual([mismatch.args.reason, mismatch.args.anchor_lines, mismatch.args.anchor_head], ["head", 4, found.head]);
  assert.match(collectorLogs.get(root) ?? "", /does not match the anchor it found \(head/, "and it is logged under --quiet");
});
