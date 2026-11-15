/**
 * One run under every pressure the Batman III runs met at once (Plan 2,
 * A15): a store larger than a sweep's budget (synthetic: 20,000 objects by
 * default, 200,000 with SWARM_SCALE_FULL=1), a seal killed midway and
 * resumed, and a seat that died holding a lead and a claim. What is held to
 * a bound: the size of a record and of its sweep's line, the heap a
 * restarted hub adds answering every live seat at once, the largest answer
 * a seat gets, and the time from the resumed seal to the job's output
 * resolving. Each piece has its own test elsewhere; this is them together.
 *
 * The answers are measured twice: as each source makes them (the digest,
 * the finish, the inbox page, the lead register: each bounded where it is
 * made, so none needs the wall here) and as the wall (reply-bound.ts) sends
 * them. One answer is past the wall on purpose (a seat's whole inbox, the
 * dead seat's backlog in it): it is sent cut, within the wall, and the file
 * it names holds the whole. The dead seat's lead is freed for the others as
 * the watchdog frees it (leads-cli.ts seat-stall ... dead).
 * Nothing here reads runs/.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as SW from "../extensions/store-sweep.ts";
import { resealMoved, resolveRef, sealDirOf, storePaths } from "../scripts/evidence-store.ts";
import { coverage, ok, planned, rec, run } from "./negative-bar-fixture.ts";

const FULL = process.env.SWARM_SCALE_FULL === "1";
const OBJECTS = FULL ? 200_000 : 20_000;
const FILES = FULL ? 20_000 : 4_000;
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const ROOT = join(import.meta.dirname, "..");

/** A committed job whose manifest lists `n` files of ten bytes: a store too large for a sweep's budget (only the manifest is written). */
async function hugeJob(S: string, id: string, n: number): Promise<void> {
  const dir = join(S, "store", "jobs", id);
  await mkdir(join(dir, "out"), { recursive: true });
  const files = Array.from({ length: n }, (_, i) => ({ path: `Users/dir${String(i % 400).padStart(3, "0")}/AppData/Local/Packages/file-${String(i).padStart(6, "0")}.dat`, sha256: sha(`f${i}`), bytes: 10 }));
  await writeFile(join(dir, "manifest.json"), JSON.stringify({ files }));
  await writeFile(join(dir, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "extract" } }));
}

/** A job's staging tree of `n` small files in directories of a hundred. */
async function tree(root: string, n: number): Promise<void> {
  for (let i = 0; i < n; i += 1) {
    const d = join(root, `d${String(Math.floor(i / 100)).padStart(3, "0")}`);
    if (i % 100 === 0) await mkdir(d, { recursive: true });
    await writeFile(join(d, `f${i}.bin`), Buffer.concat([Buffer.from(`file ${i}\n`), Buffer.alloc(400, i % 251)]));
  }
}

test(`a store of ${OBJECTS} objects over its sweep's budget, a seal killed midway and resumed, and a dead seat, at once: records, the heap, answers and the job's delivery stay bounded`, { timeout: 900_000 }, async (t) => {
  const { S, a0, a1, a3 } = await run();

  // 1. The store over its budget: a coverage record whose sweep can open none of its objects.
  await hugeJob(S, "j900000", OBJECTS);
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  process.env.SWARM_SWEEP_MAX_BYTES = "5";
  let cov: P.LedgerEntry;
  try {
    cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["mallory"] }))).entry;
    await SW.awaitSweeps(S);
  } finally {
    delete process.env.SWARM_SWEEP_MAX_BYTES;
  }
  const ledgerLines = (await readFile(join(S, P.LEDGER_ENTRIES), "utf8")).split("\n").filter(Boolean);
  const recordBytes = Math.max(...ledgerLines.map((l) => Buffer.byteLength(l)));
  const sweepLines = (await readFile(join(S, SW.LEDGER_SWEEPS), "utf8")).split("\n").filter(Boolean);
  const sweepBytes = Math.max(...sweepLines.map((l) => Buffer.byteLength(l)));
  assert.ok(recordBytes < 16 * 1024, `the largest record is ${recordBytes} bytes`);
  assert.ok(sweepBytes < 64 * 1024, `the sweep's line is ${sweepBytes} bytes`);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.equal(sw.state, "partial", "the sweep ran past its budget");
  assert.ok(SW.unsearchedTotal(sw) >= OBJECTS, "every object is named unsearched, in its file");

  // 2. A seat dies holding a lead and a claim, with a backlog of its posts in every inbox: marked dead as the watchdog marks it, its
  // claims let go, and its lead freed for the others at once (idle-nudge.sh lead_stall_act ... dead).
  const deadLead = await planned(a3, "3");
  assert.equal((await P.claimFile(a3, "work/report.md", { reason: "drafting the timeline" })).ok, true);
  for (let i = 0; i < 120; i++) await P.postMessage(a3, { tag: "result", body: `timeline draft ${i}: ${"t".repeat(3000)}` });
  await mkdir(join(S, "done", "agents"), { recursive: true });
  await writeFile(P.agentDeadPath(S, "a3"), `---\nby: reaper\nagent: a3\nreason: stall\nat: ${new Date().toISOString()}\n---\n`);
  await P.releaseAllOwned(a3);
  assert.ok(!(await P.listClaims(S)).some((c) => c.owner === "a3"), "the dead seat's claim is let go");
  assert.equal((await L.leadsSnapshot(S)).state.leads.get(deadLead)?.holder, "a3", "until the watchdog acts, the dead seat holds its lead");
  const stall = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "leads-cli.ts"), "seat-stall", S, "a3", "dead", "1200"], { encoding: "utf8" });
  assert.equal(stall.status, 0, stall.stderr + stall.stdout);
  assert.deepEqual((JSON.parse(stall.stdout) as { released: string[] }).released, [deadLead], "the watchdog frees the dead seat's lead");
  const freed = (await L.leadsSnapshot(S)).state.leads.get(deadLead)!;
  assert.ok(!freed.holder && !freed.closed, `the lead is open again for any seat (holder ${freed.holder}, closed ${JSON.stringify(freed.closed)})`);
  await P.postMessage(a1, { tag: "result", body: "a3 went silent while drafting the timeline" });

  // 3. A seal killed three quarters of the way, and resumed: the job's output resolves after it.
  const staging = join(S, "..", "staging-j950000");
  await tree(staging, FILES);
  const dest = join(storePaths(S).jobs, "j950000", "out");
  const stopAt = Math.floor(FILES * 0.75);
  const script = `import { sealTree } from ${JSON.stringify(join(ROOT, "scripts", "evidence-store.ts"))}; await sealTree(${JSON.stringify(S)}, ${JSON.stringify(staging)}, ${JSON.stringify(dest)}, "j950000", 1, undefined, { workers: 4 });`;
  const killed = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: `seal:hashed:${stopAt}` } });
  assert.equal(killed.status, 99, killed.stderr);
  assert.ok(existsSync(sealDirOf(dest)), "the seal left its record");
  const t0 = performance.now();
  const again = await resealMoved(S, dest, "j950000", 1, undefined, { workers: 4 });
  await writeFile(join(storePaths(S).jobs, "j950000", "job.json"), JSON.stringify({ id: "j950000", state: "committed", requester: { agent: "a1" }, status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "extract" } }));
  const resolved = await resolveRef(S, `job:j950000/d${String(Math.floor((FILES - 1) / 100)).padStart(3, "0")}/f${FILES - 1}.bin`);
  const deliveryMs = performance.now() - t0;
  assert.ok(resolved.ok, JSON.stringify(resolved));
  assert.ok(again.seal.resumed >= stopAt, `${again.seal.resumed} files taken from the record`);
  assert.ok(again.seal.hashed <= FILES - stopAt + 8, `${again.seal.hashed} files hashed again after the kill`);
  assert.ok(deliveryMs < (FULL ? 300_000 : 60_000), `the resumed seal delivered the job's output in ${deliveryMs.toFixed(0)} ms`);

  // 4. The hub restarted: a fresh process answers every live seat at once, twice over, everything a seat asks between turns.
  const child = `
    const P = await import(${JSON.stringify(join(ROOT, "extensions", "protocol.ts"))});
    const L = await import(${JSON.stringify(join(ROOT, "extensions", "leads.ts"))});
    const F = await import(${JSON.stringify(join(ROOT, "extensions", "finish.ts"))});
    const { boundRpcAnswer } = await import(${JSON.stringify(join(ROOT, "extensions", "reply-bound.ts"))});
    const S = process.argv[1];
    gc();
    const h0 = process.memoryUsage().heapUsed;
    let peak = h0;
    const watch = setInterval(() => { peak = Math.max(peak, process.memoryUsage().heapUsed); }, 2);
    const sizes = {};
    const raws = {};
    const cuts = {};
    const { createHash } = await import("node:crypto");
    const { mkdir, writeFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    let kept = 0;
    // As the hub keeps an answer past the wall: whole, in a file of the seat's own kept outputs, named in the answer.
    const keep = async (text) => {
      const rel = "tool-output/hub/answer-" + (++kept) + ".text.log";
      await mkdir(join(S, "tool-output", "hub"), { recursive: true });
      await writeFile(join(S, rel), text);
      return { path: rel, bytes: Buffer.byteLength(text), sha256: createHash("sha256").update(text).digest("hex") };
    };
    const answer = async (fn, p) => {
      const raw = await p.then((result) => ({ ok: true, result }), (err) => ({ ok: false, error: String(err && err.message || err) }));
      const rawBytes = Buffer.byteLength(JSON.stringify(raw));
      const { answer, cut } = await boundRpcAnswer(fn.split("(")[0], raw, keep);
      const n = Buffer.byteLength(JSON.stringify(answer));
      sizes[fn] = Math.max(sizes[fn] ?? 0, n);
      raws[fn] = Math.max(raws[fn] ?? 0, rawBytes);
      if (cut) cuts[fn] = { raw: rawBytes, sha256: createHash("sha256").update(JSON.stringify(raw)).digest("hex"), kept: cut.kept, answer_cut: answer.result && answer.result.answer_cut };
      return { fn, raw: rawBytes, n };
    };
    const t0 = Date.now();
    const seats = ["a0", "a1", "a2", "a0", "a1", "a2", "a0", "a1"];
    await Promise.all(seats.map(async (a) => {
      const ctx = { sandboxRoot: S, agentId: a };
      await Promise.all([
        answer("waitForSwarmChange", P.waitForSwarmChange(ctx, { seconds: 1 })),
        answer("leadsDigest", L.leadsDigest(ctx, { mark: true })),
        answer("readInbox", P.readInbox(ctx)),
        answer("finishAct", F.finishAct(ctx, { action: "status" })),
        answer("leadsView", L.leadsView(ctx, {})),
        // A seat that asks for its whole inbox, unpaged: the dead seat's backlog makes it past the wall.
        answer("readInbox(whole)", P.readInbox(ctx, { pageChars: 0, markSeen: false })),
      ]);
    }));
    clearInterval(watch);
    peak = Math.max(peak, process.memoryUsage().heapUsed);
    gc();
    const h1 = process.memoryUsage().heapUsed;
    console.log(JSON.stringify({ h0, h1, peak, ms: Date.now() - t0, sizes, raws, cuts }));
  `;
  const out = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--expose-gc", "--input-type=module", "-e", child, S], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(out.status, 0, out.stderr);
  type Cut = { raw: number; sha256: string; kept?: string; answer_cut?: { kept?: string; bytes: number; note: string } };
  const m = JSON.parse(out.stdout.trim().split("\n").at(-1)!) as { h0: number; h1: number; peak: number; ms: number; sizes: Record<string, number>; raws: Record<string, number>; cuts: Record<string, Cut> };
  const WALL = 256 * 1024;
  const largest = Math.max(...Object.values(m.sizes));
  const peakMb = (m.peak - m.h0) / 2 ** 20;
  const keptMb = (m.h1 - m.h0) / 2 ** 20;
  // Each source is bounded where it is made: with 20,000 objects unsearched, a dead seat and its backlog, none of them needs the wall.
  for (const fn of ["waitForSwarmChange", "leadsDigest", "readInbox", "finishAct", "leadsView"]) {
    assert.ok(m.raws[fn]! <= WALL, `${fn} is ${m.raws[fn]} bytes as its source makes it, past the wall: ${JSON.stringify(m.raws)}`);
    assert.equal(m.cuts[fn], undefined, `${fn} was not cut`);
  }
  // An answer past the wall is cut to it, and the file it names keeps the whole.
  const whole = m.cuts["readInbox(whole)"];
  assert.ok(m.raws["readInbox(whole)"]! > WALL && whole, `the whole inbox is ${m.raws["readInbox(whole)"]} bytes before the wall`);
  assert.ok(m.sizes["readInbox(whole)"]! <= WALL);
  assert.ok(whole.kept && whole.answer_cut?.kept === whole.kept && whole.answer_cut.bytes === whole.raw, JSON.stringify(whole.answer_cut));
  const keptText = await readFile(join(S, whole.kept));
  assert.equal(sha(keptText), whole.sha256, "the kept file is the whole answer");
  assert.ok((JSON.parse(keptText.toString("utf8")) as { result: { posts: unknown[] } }).result.posts.length >= 121, "every post of the backlog is in it");
  // What every seat is sent, the cut answer included, is within the wall.
  assert.ok(largest <= WALL, `the largest answer is ${largest} bytes: ${JSON.stringify(m.sizes)}`);
  // The dead seat's lead is offered to the live seats: open and unheld in their digest.
  const digest = (await L.leadsDigest({ sandboxRoot: S, agentId: "a0" }, { mark: false })).text;
  assert.match(digest, new RegExp(`Open, unheld, by priority: [^\\n]*${deadLead}\\b`), digest);
  assert.ok(peakMb < 100, `answering every seat at once took ${peakMb.toFixed(1)} MB more heap at its peak`);
  assert.ok(keptMb < 50, `and left ${keptMb.toFixed(1)} MB more heap`);
  t.diagnostic(`answers as made: ${JSON.stringify(m.raws)}; as sent: ${JSON.stringify(m.sizes)}`);
  process.stdout.write(`# ${OBJECTS} objects over budget, a seal of ${FILES} files killed at ${stopAt} and resumed (${again.seal.hashed} hashed again), a dead seat: largest record ${recordBytes} B, sweep line ${sweepBytes} B; job delivered ${deliveryMs.toFixed(0)} ms after the resume; a restarted hub answered 48 calls in ${m.ms} ms, heap +${peakMb.toFixed(1)} MB at the peak, +${keptMb.toFixed(1)} MB kept; largest answer ${largest} B\n`);
});
