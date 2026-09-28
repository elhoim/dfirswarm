/**
 * `done` from a seat in a microVM, through the real extension (Pi's own
 * loader) and a real hub in-process: the operator's finish line is run by
 * the hub on the host, where the trace and the ledger are, and its refusal
 * comes back to the seat word for word, the ledger gate's included. The seat's view of the run is a directory whose
 * traces/ is empty, as the veil leaves it in a VM; run there, the goal's
 * trace check could never pass. No model, no VM, no key.
 *
 * Needs an installed @earendil-works/pi-coding-agent (the pinned
 * devDependency first); skips with a reason when there is none.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";
import { closeBoardClients } from "../extensions/board.ts";
import { finishLineVerdict, initSandbox, runFinishLine, SENTINEL_REL } from "../extensions/protocol.ts";
import { Hub } from "../scripts/vm-hub.ts";

const REPO = resolve(import.meta.dirname, "..");
const cleanups: Array<() => Promise<unknown>> = [];
after(async () => {
  closeBoardClients();
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

type LoadedTool = { definition: { execute: (...args: unknown[]) => Promise<{ details: Record<string, unknown>; isError?: boolean; content?: Array<{ text?: string }> }> } };
type LoadedExtension = { tools: Map<string, LoadedTool> };

async function findLoader(): Promise<string | null> {
  const loader = join(process.env.PI_PACKAGE_DIR ?? join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"), "dist", "core", "extensions", "loader.js");
  return access(loader).then(
    () => loader,
    () => null,
  );
}

/** Set these environment variables for the rest of the test, and put them back after. */
function withEnv(vars: Record<string, string>): void {
  const was = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  cleanups.push(async () => {
    for (const [k, v] of Object.entries(was)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

type Seat = { sandbox: string; view: string; done: LoadedTool["definition"]; ctx: { cwd: string; hasUI: boolean; ui: Record<string, never> } };

/**
 * A run on the host with these checks as its finish line, its hub, and seat
 * a0's extension loaded as it runs in a VM: board calls to its hub socket,
 * its view of the run a directory with an empty traces/ (the veil). Null
 * when there is no Pi package to load it with.
 */
async function vmSeat(t: { skip: (why: string) => void }, checks: string[], prepare: (sandbox: string) => Promise<void> = async () => undefined): Promise<Seat | null> {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR, or npm install)");
    return null;
  }
  const base = await mkdtemp(join(tmpdir(), "vm-done-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const sandbox = join(base, "run");
  await initSandbox(sandbox, { reset: true });
  await writeFile(join(sandbox, "team.json"), JSON.stringify({ swarm_id: "t", n: 1, agents: [{ id: "a0", role: "worker" }] }));
  await prepare(sandbox);
  const goal = ["## Goal", "", "Write the report.", "", "## Definition of done", "", "The report exists.", "", "## Checks", "", ...checks.map((c) => `- \`${c}\``), ""].join("\n");
  await mkdir(join(base, "runs"), { recursive: true });
  await writeFile(join(base, "runs", "registry.json"), JSON.stringify({ runs: [{ id: "t", sandbox, goal }] }));
  // The seat's view: its own tool-output/ and an empty traces/ (the veil).
  const view = join(base, "vm-view");
  await mkdir(join(view, "tool-output", "a0"), { recursive: true });
  await mkdir(join(view, "traces"), { recursive: true });

  const hubDir = await mkdtemp(join("/tmp", "vmd-"));
  cleanups.push(() => rm(hubDir, { recursive: true, force: true }));
  const collectorPath = join(hubDir, "collector.sock");
  const collector = createServer((socket) => {
    socket.on("data", () => socket.write('{"ok":true}\n'));
    socket.on("error", () => undefined);
  });
  await new Promise<void>((r) => collector.listen(collectorPath, () => r()));
  cleanups.push(async () => collector.close());
  const hub = new Hub({ sandbox, dir: hubDir, agents: ["a0"], tokens: { a0: "token-a0", system: "token-system" }, collector: collectorPath, backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false", forging: false });
  await hub.start();
  cleanups.push(() => hub.stop());

  withEnv({ SWARM_RUNS_DIR: join(base, "runs"), AGENT_ID: "a0", SWARM_ISOLATION: "microvm", SWARM_BOARD_SOCKET: hub.socketFor("a0") });
  const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }> };
  const loaded = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], view);
  assert.deepEqual(loaded.errors, []);
  return { sandbox, view, done: loaded.extensions[0]!.tools.get("done")!.definition, ctx: { cwd: view, hasUI: false, ui: {} } };
}

test("done in a VM: the hub runs the finish line on the host, and its refusal reaches the seat word for word", async (t) => {
  // The host's run: the trace holds an inputs_check line, as it does once
  // any seat has called done.
  const seat = await vmSeat(t, [`grep -q '"tool":"inputs_check"' traces/events.jsonl`, "echo ran >> checks-ran.log; test -f work/report.md"], (sandbox) =>
    writeFile(join(sandbox, "traces", "events.jsonl"), `${JSON.stringify({ ts: new Date().toISOString(), agent: "a0", tool: "inputs_check", args: {}, result: { ok: true } })}\n`),
  );
  if (!seat) return;
  const { sandbox, done, ctx } = seat;
  const runs = async () => (await readFile(join(sandbox, "checks-ran.log"), "utf8").catch(() => "")).trim().split("\n").filter(Boolean).length;

  const refused = await done.execute("d1", { reason: "definition_of_done_met", output_file: "work/report.md" }, undefined, undefined, ctx);
  assert.equal(refused.isError, true, "the report is missing: done is refused");
  assert.deepEqual([refused.details.passed, refused.details.total], [1, 2], "the trace check passed: the checks ran where the trace is, not in the seat's view");
  const onHost = finishLineVerdict(await runFinishLine(sandbox), false);
  assert.equal(onHost.proceed, false);
  if (!onHost.proceed) {
    assert.equal(refused.details.reason, onHost.reason, "the refusal is the host's run's, word for word");
    assert.equal(refused.content?.[0]?.text, onHost.reason, "and it is what the model reads");
  }
  assert.match(String(refused.details.reason), /- `echo ran >> checks-ran\.log; test -f work\/report\.md` fails\. Fix: /);
  assert.equal(await readFile(join(sandbox, SENTINEL_REL), "utf8").catch(() => null), null, "no sentinel");

  await writeFile(join(sandbox, "work", "report.md"), "# report\n");
  const before = await runs();
  const ended = await done.execute("d2", { reason: "definition_of_done_met", output_file: "work/report.md" }, undefined, undefined, ctx);
  assert.equal(ended.details.terminate, true, `done goes through once the host's checks pass: ${JSON.stringify(ended.details)}`);
  assert.ok(await readFile(join(sandbox, SENTINEL_REL), "utf8"), "the hub wrote the sentinel on the host");
  assert.equal(await runs(), before + 1, "one done, one run of the checks: markDone took the seat's run");
});

test("done in a VM: the ledger gate's refusal (check-answers) reaches the seat verbatim, each defect and its fix", async (t) => {
  // The answers check reads the ledger on the host and names each defect and
  // its fix in its output; the runner hands that back as `out`, and the
  // refusal the seat reads carries it as check-answers printed it.
  const gate = 'node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,summary';
  const seat = await vmSeat(t, [gate], (sandbox) => mkdir(join(sandbox, "ledger"), { recursive: true }).then(() => undefined));
  if (!seat) return;
  const { sandbox, done, ctx } = seat;
  const printed = spawnSync("bash", ["-c", gate], { cwd: sandbox, encoding: "utf8", env: { ...process.env, SWARM_HARNESS: REPO } });
  assert.equal(printed.status, 1, "the gate refuses an unanswered question");
  assert.match(printed.stdout, /^DEFECT: question:1 has no answer\. Fix: record kind=answer section=question:1/m);

  const refused = await done.execute("g1", { reason: "definition_of_done_met", output_file: "work/report.md" }, undefined, undefined, ctx);
  assert.equal(refused.isError, true);
  const reason = String(refused.details.reason);
  assert.ok(reason.includes(`- \`${gate}\` fails. It says:\n${printed.stdout.trimEnd()}\n`), `the gate's words, whole and in order, in the refusal:\n${reason}`);
  assert.equal(refused.content?.[0]?.text, reason, "and the model reads exactly that");
  assert.equal(await readFile(join(sandbox, SENTINEL_REL), "utf8").catch(() => null), null, "no sentinel");
});
