/**
 * A ledger entry the harness itself authors is on the trace by its own
 * line, and custody holds the ledger to it (extensions/protocol.ts
 * traceHarnessEntry, scripts/custody.ts). No seat's `record` and no hub
 * `recordEntry` call writes the operator's evidence and material, a capture
 * the fetch service sealed, or a person's hint recorded as a hypothesis, so
 * no line carried their hash: custody named each "in the ledger and never
 * on the trace" and the ledger check failed every real run that had one
 * (s26f142, s7f90eb, sabfd76, sb177a7). Here: through the hub (a microVM
 * run) and from the operator's CLI and a pane (a host run), every such
 * entry passes; one written into the file without its line still fails,
 * and a seat's line does not stand in for the harness's; a seal taken
 * before an addition holds as a prefix after it.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import { custodyAnchorPath, takeCustody, verifyCustody, type Custody } from "../scripts/custody.ts";
import { admitMaterial } from "../scripts/material.ts";
import { admitOperatorAct } from "../scripts/questions-cli.ts";
import { Hub } from "../scripts/vm-hub.ts";
import type * as Q from "../extensions/questions.ts";
import { json, setup, skipWithoutTls } from "./net-mock.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const dirs: string[] = [];
const procs: ChildProcess[] = [];
const hubs: Hub[] = [];
after(async () => {
  for (const h of hubs) await h.stop().catch(() => undefined);
  for (const p of procs) p.kill("SIGTERM");
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const TOKENS = { tsys: "system", t0: "a0", t1: "a1", t2: "a2" };
const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
const F = { basis: "observed", confidence: "medium", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const route = (h: string, p: string) => (h === "rdap.org" && p === "/domain/example.org" ? json({ objectClassName: "domain", ldhName: "EXAMPLE.ORG" }) : null);

/** The run's collector, as the kickoff starts it: a token map, the anchor outside the run. */
async function collector(S: string): Promise<string> {
  await mkdir(join(S, "traces"), { recursive: true });
  const proc = spawn("node", [join(ROOT, "scripts", "trace-collector.mjs"), S, "--tokens", "--anchor", `${S}.trace-anchor.json`, "--quiet"], { stdio: ["pipe", "ignore", "ignore"] });
  procs.push(proc);
  dirs.push(`${S}.trace-anchor.json`);
  proc.stdin?.end(JSON.stringify({ tokens: TOKENS, gate: "" }));
  const socket = join(S, P.COLLECTOR_SOCKET_REL);
  for (let i = 0; i < 200; i += 1) {
    const up = await stat(socket).then((s) => s.isSocket()).catch(() => false);
    if (up && (await new Promise<boolean>((r) => { const c = connect(socket); c.on("connect", () => { c.destroy(); r(true); }); c.on("error", () => r(false)); }))) return socket;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("the collector did not come up");
}

/** One line to the collector, as a sender with that token writes it; resolves on its answer. */
function send(socket: string, record: Record<string, unknown>): Promise<void> {
  return new Promise<void>((r) => {
    const c = connect(socket);
    c.on("data", () => {
      c.destroy();
      r();
    });
    c.on("error", () => r());
    c.on("connect", () => c.write(`${JSON.stringify(record)}\n`));
  });
}

/** A seat's own line: the trace a run has before anything is added, so the ledger is held to it. */
const seatLine = (socket: string, agent: string, token: string) => send(socket, { ts: new Date().toISOString(), agent, tool: "bash", args: { command: "ls inputs" }, result: { ok: true }, token });

type Line = Record<string, unknown> & { tool: string; agent: string; args: Record<string, unknown>; result: Record<string, unknown> };
async function trace(S: string): Promise<Line[]> {
  return (await readFile(join(S, P.EVENTS_REL), "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Line);
}
async function until(what: string, cond: () => Promise<boolean>): Promise<void> {
  for (let i = 0; i < 400; i += 1) {
    if (await cond()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`timed out waiting: ${what}`);
}

/** A file outside the run, as the operator adds it. */
async function hostFile(name: string, text: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "hrec-src-"));
  dirs.push(d);
  await writeFile(join(d, name), text);
  return join(d, name);
}

const ledgerCheck = (c: Custody) => c.checks.find((x) => x.name === "ledger");

/** The ledger's harness-authored entries: by the harness, or in a person's name. */
async function harnessEntries(S: string): Promise<P.LedgerEntry[]> {
  return (await P.readLedger(S, { raw: true })).filter((e) => e.by === "system" || e.by.startsWith("analyst:"));
}

/** A person's question whose hint says something: recorded as a hypothesis in the asker's name. */
async function questionWithHint(S: string): Promise<void> {
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, "work", "notes"), "the analyst's notes\n");
  const r = await admitOperatorAct(S, { actor: operator, ev: "open", input: { text: "Was the domain in the proxy log registered for this campaign?", why: "the client's claim", hints: [{ ref: "work/notes", value: "The domain was registered the week before" }] } });
  assert.equal(r.ok, true, String(r.reason ?? ""));
}

test("through the hub (a microVM run): the operator's evidence and material, a network capture and a person's hint each carry their hash on the hub's own line, and custody's ledger check passes", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route });
  dirs.push(custodyAnchorPath(s.S));
  await writeFile(custodyAnchorPath(s.S), JSON.stringify({ run: "n1", started_at: new Date().toISOString(), isolation: "microvm" }));
  const socket = await collector(s.S);
  const hub = new Hub({ sandbox: s.S, dir: s.hubDir, agents: ["a1", "a2"], tokens: { a1: "t1", a2: "t2", system: "tsys" }, collector: socket, backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false", forging: false });
  hubs.push(hub);
  // A seat's own record, through the hub: the hub's recordEntry line.
  const own = await hub.call("a1", "recordEntry", [s.S, { kind: "finding", value: "The proxy log names example.org", source: "inputs/proxy.log", evidence: "line 3", refs: ["unresolved:the proxy log is not in this fixture"], ...F }]);
  assert.equal(own.ok && (own.result as { ok?: boolean }).ok, true, JSON.stringify(own));
  // A capture the fetch service sealed, recorded when the seat fetches.
  const req = await hub.call("a1", "netRequest", [s.S, { lead: "L-1", adapter: "rdap_domain", params: { domain: "example.org" }, purpose: "who registered it" }]);
  assert.equal((req.result as { ok?: boolean }).ok, true, JSON.stringify(req));
  const fetched = await hub.call("a1", "netFetch", [s.S, { grant: "N-1" }]);
  assert.match(String((fetched.result as { entry?: string }).entry), /^E-\d+$/, JSON.stringify(fetched));
  // The operator's evidence and material, admitted while the hub serves the run.
  const ev = await admitMaterial(s.S, { mode: "evidence", path: await hostFile("proxy.csv", "time,host\n09:58,example.org\n"), why: "the proxy export the network team kept", supplied_by: "tester", via: "cli" });
  assert.equal(ev.ok, true, String(ev.reason ?? ""));
  const mat = await admitMaterial(s.S, { mode: "material", path: await hostFile("brief.txt", "the client's brief\n"), why: "the client's own account", supplied_by: "tester", via: "cli" });
  assert.equal(mat.ok, true, String(mat.reason ?? ""));
  await questionWithHint(s.S);
  const authored = await harnessEntries(s.S);
  assert.deepEqual(authored.map((e) => e.source_class ?? e.kind).sort(), ["acquired_evidence", "external_capture", "hypothesis", "operator_supplied"]);
  await until("the hub's lines on the trace", async () => {
    const lines = await trace(s.S);
    return lines.some((l) => l.tool === "hub_call" && l.args.fn === "recordEntry") && authored.every((e) => lines.some((l) => l.tool === P.HARNESS_RECORD_TOOL && l.result.hash === e.hash));
  });
  const lines = await trace(s.S);
  for (const e of authored) {
    const line = lines.find((l) => l.tool === P.HARNESS_RECORD_TOOL && l.result.hash === e.hash)!;
    // The hub's own line: the harness's token, its sid, the entry's seq and hash.
    assert.equal(line.agent, "system");
    assert.equal(line.agent_unverified, undefined, "the hub's line carries the harness's token");
    assert.match(String(line.sid), /^hub-/);
    assert.deepEqual(line.result, { ok: true, seq: e.seq, merged: false, hash: e.hash });
  }
  // A merged duplicate writes nothing new, and no line.
  const before = (await trace(s.S)).filter((l) => l.tool === P.HARNESS_RECORD_TOOL).length;
  const again = await P.recordExternal(s.S, { value: "the same capture again", source: "s", evidence: "e", refs: authored.find((e) => e.source_class === "external_capture")!.refs!, source_class: "external_capture", provenance: { supplied_by: "the fetch service", at: "x", from: "https://rdap.org/domain/example.org", permitted_use: "reference" } });
  assert.equal(again.ok && again.merged, true);
  assert.equal((await trace(s.S)).filter((l) => l.tool === P.HARNESS_RECORD_TOOL).length, before, "a merged duplicate put a line on the trace");
  const c = await takeCustody(s.S);
  assert.equal(c.ledger?.held_to, "the hub's lines");
  assert.deepEqual(c.ledger?.not_on_trace, [], JSON.stringify(c.ledger));
  assert.deepEqual(c.ledger?.missing_from_ledger, []);
  assert.equal(c.ledger?.intact, true, JSON.stringify(c.ledger));
  assert.equal(ledgerCheck(c)?.status, "passed", JSON.stringify(ledgerCheck(c)));

  // An external entry written into the file by hand, chained on, never on the trace: named.
  const all = await P.readLedger(s.S, { raw: true });
  const last = all.at(-1)!;
  const forged: P.LedgerEntry = { v: P.LEDGER_VERSION, seq: last.seq + 1, kind: "external", value: "Material nobody added", source: "swarm.sh material add, by nobody (cli)", evidence: "none", refs: [...(authored.find((e) => e.source_class === "operator_supplied")!.refs ?? [])], source_class: "operator_supplied", provenance: { supplied_by: "nobody", at: new Date().toISOString(), from: "/nowhere", permitted_use: "reference" }, by: "system", authors: ["system"], at: new Date().toISOString() };
  forged.prev = last.hash;
  forged.hash = P.ledgerHash(forged, forged.prev as string);
  await appendFile(join(s.S, P.LEDGER_ENTRIES), `${JSON.stringify(forged)}\n`);
  // A seat's line claiming to be the harness's, carrying its hash: the collector attributes it to the seat, and it is not counted.
  await send(socket, { ts: new Date().toISOString(), agent: "system", tool: P.HARNESS_RECORD_TOOL, args: { kind: "external", by: "system" }, result: { ok: true, seq: forged.seq, merged: false, hash: forged.hash }, token: "t2" });
  await until("the seat's line on the trace", async () => (await trace(s.S)).some((l) => l.claimed_agent === "system"));
  const bad = await takeCustody(s.S);
  assert.deepEqual(bad.ledger?.not_on_trace, [forged.seq], JSON.stringify(bad.ledger));
  assert.deepEqual(bad.ledger?.claimed_by_seat, [forged.hash], "the seat's word is named, not counted");
  assert.equal(ledgerCheck(bad)?.status, "failed");
  assert.match(String(ledgerCheck(bad)?.reason), new RegExp(`never on the trace \\(seq ${forged.seq}\\)`));
});

test("from the operator's CLI with no hub, and from a pane (a host run): each entry's own line carries its hash, and custody's ledger check passes", async () => {
  const base = await mkdtemp(join(tmpdir(), "hrec-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "h1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30 });
  dirs.push(custodyAnchorPath(S));
  await writeFile(custodyAnchorPath(S), JSON.stringify({ run: "h1", started_at: new Date().toISOString(), isolation: "host" }));
  await seatLine(await collector(S), "a1", "t1");
  // The operator's CLI: no hub, no way of its own registered, no token in its shell.
  const ev = await admitMaterial(S, { mode: "evidence", path: await hostFile("dns.log", "09:58 ws query example.org\n"), why: "the DNS log", supplied_by: "tester", via: "cli" });
  assert.equal(ev.ok, true, String(ev.reason ?? ""));
  const mat = await admitMaterial(S, { mode: "material", path: await hostFile("brief.txt", "the brief\n"), why: "the client's brief", supplied_by: "tester", via: "cli" });
  assert.equal(mat.ok, true, String(mat.reason ?? ""));
  // A pane on the host: the hint's hypothesis is recorded while its header is made, and the line is the pane's own (logEvent).
  const env = { SWARM_TRACE_SOCKET: process.env.SWARM_TRACE_SOCKET, SWARM_TRACE_TOKEN: process.env.SWARM_TRACE_TOKEN };
  process.env.SWARM_TRACE_SOCKET = join(S, P.COLLECTOR_SOCKET_REL);
  process.env.SWARM_TRACE_TOKEN = "t0";
  const undo = P.useHarnessTrace(async (root, line) => void (await P.appendEvent(root, { agent: "a0", ...line })));
  try {
    await questionWithHint(S);
  } finally {
    undo();
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const authored = await harnessEntries(S);
  assert.equal(authored.length, 3, JSON.stringify(authored.map((e) => e.kind)));
  const lines = await trace(S);
  const of = (e: P.LedgerEntry) => lines.find((l) => l.tool === P.HARNESS_RECORD_TOOL && l.result.hash === e.hash);
  for (const e of authored.filter((x) => x.kind === "external")) {
    // The operator's shell holds no token: the harness's line, marked unverified by the collector, as an operator action is.
    assert.equal(of(e)?.agent, "system", JSON.stringify(lines));
    assert.equal(of(e)?.agent_unverified, true);
  }
  const hint = authored.find((e) => e.kind === "hypothesis")!;
  assert.equal(of(hint)?.agent, "a0", "the pane's own line");
  assert.equal(of(hint)?.agent_unverified, undefined);
  const c = await takeCustody(S);
  assert.equal(c.ledger?.held_to, "the record tool's lines");
  assert.deepEqual(c.ledger?.not_on_trace, [], JSON.stringify(c.ledger));
  assert.equal(ledgerCheck(c)?.status, "passed", JSON.stringify(ledgerCheck(c)));
});

test("with no collector, the operator's line goes where the shell's trace_emit puts it: the harness's spill on a chained trace, which custody counts", async () => {
  const base = await mkdtemp(join(tmpdir(), "hrec-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "h2", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30 });
  dirs.push(custodyAnchorPath(S));
  await writeFile(custodyAnchorPath(S), JSON.stringify({ run: "h2", started_at: new Date().toISOString(), isolation: "microvm" }));
  // A chained trace whose collector is gone (a stopped run).
  const first = JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true }, prev: "" });
  await writeFile(join(S, P.EVENTS_REL), `${first}\n`);
  const mat = await admitMaterial(S, { mode: "material", path: await hostFile("brief.txt", "the brief\n"), why: "the client's brief", supplied_by: "tester", via: "cli" });
  assert.equal(mat.ok, true, String(mat.reason ?? ""));
  assert.equal((await readFile(join(S, P.EVENTS_REL), "utf8")).trim(), first, "an unchained line appended to a chained trace");
  const spill = (await readFile(join(S, P.SYSTEM_SPILL_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Line);
  const entry = (await harnessEntries(S))[0]!;
  assert.deepEqual(spill.map((l) => [l.agent, l.tool, l.result.hash]), [["system", P.HARNESS_RECORD_TOOL, entry.hash]]);
  const c = await takeCustody(S);
  assert.deepEqual(c.ledger?.not_on_trace, [], JSON.stringify(c.ledger));
  assert.equal(c.ledger?.intact, true);
});

test("an earlier seal still verifies as a prefix after the operator adds evidence, and the ledger check holds on both", async () => {
  const base = await mkdtemp(join(tmpdir(), "hrec-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "h3", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30 });
  dirs.push(custodyAnchorPath(S));
  await writeFile(custodyAnchorPath(S), JSON.stringify({ run: "h3", started_at: new Date().toISOString(), isolation: "host" }));
  await seatLine(await collector(S), "a0", "t0");
  const first = await admitMaterial(S, { mode: "evidence", path: await hostFile("a.log", "first\n"), why: "the first export", supplied_by: "tester", via: "cli" });
  assert.equal(first.ok, true, String(first.reason ?? ""));
  const sealed = await takeCustody(S);
  assert.equal(ledgerCheck(sealed)?.status, "passed", JSON.stringify(sealed.ledger));
  // The run went on: more evidence, custody again.
  const second = await admitMaterial(S, { mode: "evidence", path: await hostFile("b.log", "second\n"), why: "the second export", supplied_by: "tester", via: "cli" });
  assert.equal(second.ok, true, String(second.reason ?? ""));
  const now = await takeCustody(S);
  assert.equal(ledgerCheck(now)?.status, "passed", JSON.stringify(now.ledger));
  assert.equal(now.ledger?.entries, (sealed.ledger?.entries ?? 0) + 1);
  const v = await verifyCustody(S);
  assert.equal(v.earlier.length, 1);
  assert.equal(v.earlier[0].ok, true, v.earlier[0].broken.join("; "));
});
