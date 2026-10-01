/**
 * The harness's own trace lines the collector could not take, chained once
 * it is down (scripts/trace-collector.mjs --gather, which `swarm.sh stop`
 * runs after it stops the run's daemons). On the Breadcrumbs run a reap and
 * a second stop came after the first stop had stopped the collector: their
 * lines went to traces/system-spill.jsonl and custody counted two lines
 * outside the chain. Here a real collector writes a chained trace and is
 * stopped, the harness spills as it would, and the gather:
 *
 * - chains each spilled event, unverified and marked `gathered` with its
 *   spill and its own sha256, the anchor moving with the chain;
 * - keeps the spilled lines whole beside the trace (<name>.gathered.jsonl),
 *   leaves a line that is not an event in the spill, and does not chain twice
 *   a hub line the collector had already taken;
 * - is safe to run again, and refuses while a collector answers;
 * - leaves custody with nothing outside the chain but the line that is not
 *   an event, the gathered lines counted, and each gathered operator line
 *   held to the operator's audit by the time the command ran.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { COLLECTOR_SOCKET_REL, EVENTS_REL, verifyEventChain } from "../extensions/protocol.ts";
import { custodyAnchorPath, takeCustody } from "../scripts/custody.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const COLLECTOR = join(ROOT, "scripts", "trace-collector.mjs");
const dirs: string[] = [];
const procs: ChildProcess[] = [];
after(async () => {
  for (const p of procs) p.kill("SIGTERM");
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** The run's collector as the kickoff starts it; resolves once it answers. */
async function collector(S: string): Promise<ChildProcess> {
  const proc = spawn("node", [COLLECTOR, S, "--tokens", "--anchor", `${S}.trace-anchor.json`, "--quiet"], { stdio: ["pipe", "ignore", "ignore"] });
  procs.push(proc);
  proc.stdin?.end(JSON.stringify({ tokens: { tsys: "system" }, gate: "" }));
  const socket = join(S, COLLECTOR_SOCKET_REL);
  for (let i = 0; i < 200; i += 1) {
    const up = await stat(socket).then((s) => s.isSocket()).catch(() => false);
    if (up && (await new Promise<boolean>((r) => { const c = connect(socket); c.on("connect", () => { c.destroy(); r(true); }); c.on("error", () => r(false)); }))) return proc;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("the collector did not come up");
}

function send(S: string, record: Record<string, unknown>): Promise<void> {
  return new Promise<void>((r) => {
    const c = connect(join(S, COLLECTOR_SOCKET_REL));
    c.on("data", () => {
      c.destroy();
      r();
    });
    c.on("error", () => r());
    c.on("connect", () => c.write(`${JSON.stringify(record)}\n`));
  });
}

async function stopped(p: ChildProcess): Promise<void> {
  if (p.exitCode !== null || p.signalCode !== null) return;
  await new Promise<void>((r) => {
    p.on("exit", () => r());
    p.kill("SIGTERM");
  });
}

function gather(S: string): { code: number | null; out: Record<string, unknown> } {
  const r = spawnSync("node", [COLLECTOR, S, "--gather", "--anchor", `${S}.trace-anchor.json`], { encoding: "utf8" });
  return { code: r.status, out: JSON.parse(r.stdout.trim() || "{}") as Record<string, unknown> };
}

const lines = (S: string) => readFileSync(join(S, EVENTS_REL), "utf8").split("\n").filter(Boolean);
const anchor = (S: string) => JSON.parse(readFileSync(`${S}.trace-anchor.json`, "utf8")) as { lines: number; head: string; pending: boolean };

test("the harness's spilled lines are chained once the collector is down, kept whole beside the trace, and custody finds none outside the chain", async () => {
  const runs = await mkdtemp(join(tmpdir(), "gather-runs-"));
  dirs.push(runs);
  const S = join(runs, "sgth1");
  await mkdir(join(S, "traces"), { recursive: true });
  await mkdir(join(S, "inputs"), { recursive: true });
  await writeFile(join(S, "inputs", "a.txt"), "evidence\n");
  await writeFile(join(S, "inputs.json"), JSON.stringify({ source: "/evidence", bytes: 9, held: "copy", files: [{ path: "inputs/a.txt", bytes: 9, sha256: sha("evidence\n") }] }));
  await writeFile(custodyAnchorPath(S), JSON.stringify({ run: "sgth1", started_at: "2026-10-01T07:45:00Z" }));
  // The run's own lines, through its collector: the hub's numbered one, and the operator's first stop.
  const live = await collector(S);
  await send(S, { ts: new Date().toISOString(), agent: "system", tool: "hub_link", args: { agent: "a0" }, result: { up: false }, sid: "hub-1", seq: 7, token: "tsys" });
  await send(S, { ts: new Date().toISOString(), agent: "system", tool: "hub_link", args: { agent: "a1" }, result: { up: true }, sid: "hub-1", seq: 6, token: "tsys" });
  await stopped(live);
  const before = lines(S).length;
  assert.equal(before, 2);
  // Ten minutes ago, as the operator ran them: the gather chains them later.
  const stopAt = new Date(Date.now() - 10 * 60_000);
  const op = (cmd: string, argv: string[], at: Date) => ({ ts: at.toISOString().replace(/\.\d+Z$/, ".000Z"), agent: "system", tool: "operator_action", args: { command: cmd, argv, os_user: "tester", host: "lab", via: "cli" }, result: { ok: true } });
  // Once it is down: a reap and a second stop spill (the Breadcrumbs order), with a line that is no event;
  // the hub's spill holds the line the collector took after its sender gave up, and one it never took.
  const reapAt = new Date(stopAt.getTime() + 57_000);
  const stop2At = new Date(stopAt.getTime() + 66_000);
  const spilled = [JSON.stringify(op("reap", ["sgth1", "--stop"], reapAt)), JSON.stringify(op("stop", ["sgth1"], stop2At)), "{not an event"];
  await writeFile(join(S, "traces", "system-spill.jsonl"), `${spilled.join("\n")}\n`);
  const hubDup = JSON.stringify({ ts: new Date().toISOString(), agent: "system", tool: "hub_link", args: { agent: "a0" }, result: { up: false }, sid: "hub-1", seq: 7 });
  const hubNew = JSON.stringify({ ts: new Date().toISOString(), agent: "system", tool: "hub_link", args: { agent: "a1" }, result: { up: false }, sid: "hub-1", seq: 8 });
  await writeFile(join(S, "traces", "hub-spill.jsonl"), `${hubDup}\n${hubNew}\n`);
  // The operator's audit, outside the run, as swarm.sh keeps it (each line naming the one before).
  const audit: string[] = [];
  for (const [cmd, argv, at] of [["stop", ["sgth1"], stopAt], ["reap", ["sgth1", "--stop"], reapAt], ["stop", ["sgth1"], stop2At]] as const) {
    audit.push(JSON.stringify({ at: at.toISOString().replace(/\.\d+Z$/, "Z"), command: cmd, argv, cwd: "/", os_user: "tester", host: "lab", via: "cli", prev: audit.length ? sha(audit.at(-1)!) : null }));
  }
  await writeFile(join(runs, "operator-audit.jsonl"), `${audit.join("\n")}\n`);

  const g = gather(S);
  assert.equal(g.code, 0, JSON.stringify(g.out));
  assert.deepEqual([g.out.gathered, g.out.duplicates, g.out.kept], [3, 1, 1]);
  const all = lines(S);
  assert.equal(all.length, before + 3);
  const check = verifyEventChain(`${all.join("\n")}\n`, anchor(S));
  assert.equal(check.ok, true, JSON.stringify(check));
  assert.equal(anchor(S).lines, all.length);
  assert.equal(anchor(S).head, sha(all.at(-1)!), "the anchor moved with the chain");
  const added = all.slice(before).map((l) => JSON.parse(l) as Record<string, unknown> & { gathered: { from: string; sha256: string } });
  assert.deepEqual(added.map((l) => [l.tool, l.gathered.from, l.agent_unverified]), [
    ["operator_action", "traces/system-spill.jsonl", true],
    ["operator_action", "traces/system-spill.jsonl", true],
    ["hub_link", "traces/hub-spill.jsonl", true],
  ]);
  assert.deepEqual(added.map((l) => l.gathered.sha256), [sha(spilled[0]!), sha(spilled[1]!), sha(hubNew)], "each names the spilled line it came from");
  assert.equal(added[0]!.ts, JSON.parse(spilled[0]!).ts, "its own time is kept");
  // Nothing cut: the spilled lines whole beside the trace; the line that is no event stays in the spill.
  assert.equal(readFileSync(join(S, "traces", "system-spill.gathered.jsonl"), "utf8"), `${spilled[0]}\n${spilled[1]}\n`);
  assert.equal(readFileSync(join(S, "traces", "hub-spill.gathered.jsonl"), "utf8"), `${hubDup}\n${hubNew}\n`);
  assert.equal(readFileSync(join(S, "traces", "system-spill.jsonl"), "utf8"), "{not an event\n");
  assert.ok(!existsSync(join(S, "traces", "hub-spill.jsonl")));
  assert.ok(!existsSync(join(S, "traces", "system-spill.jsonl.gathering")));

  // Again: nothing new is chained.
  const again = gather(S);
  assert.equal(again.code, 0);
  assert.deepEqual([again.out.gathered, again.out.kept], [0, 1]);
  assert.equal(lines(S).length, all.length);

  // Custody: one line outside the chain (the one that is no event), the gathered counted, every operator line on the audit.
  const c = await takeCustody(S, { runsDir: runs });
  assert.equal(c.trace.intact, true, c.trace.detail);
  assert.deepEqual(c.trace.spilled.map((s) => [s.path, s.lines]), [["traces/system-spill.jsonl", 1]]);
  assert.equal(c.trace.gathered, 3);
  assert.deepEqual(c.trace.clock, [], "a gathered line's recv_ts is when it was chained, not a clock off the host's");
  assert.equal(c.operator?.trace_actions, 2);
  assert.deepEqual(c.operator?.unmatched, [], "each gathered operator line is held to the audit by when the command ran");
  assert.match(c.summary, /3 lines the harness spilled while the collector was down chained by the stop/);

  // While a collector answers, the gather leaves the lines to it.
  await writeFile(join(S, "traces", "system-spill.jsonl"), `${spilled[0]}\n`, { flag: "a" });
  const up = await collector(S);
  const refused = gather(S);
  assert.equal(refused.code, 4);
  assert.match(String(refused.out.error), /a collector answers/);
  await stopped(up);
});
