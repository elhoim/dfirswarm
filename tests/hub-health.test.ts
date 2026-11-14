/**
 * The hub's own health row and its early heap snapshot.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { loopMonitor, sampleHealth, snapshotAt, snapshotDue } from "../scripts/hub-health.ts";

test("a health sample names the heap, the loop's delay, the host and what the hub holds", async () => {
  const loop = loopMonitor();
  await new Promise((r) => setTimeout(r, 60));
  const until = Date.now() + 120;
  while (Date.now() < until) { /* hold the loop: a timer due now fires late */ }
  await new Promise((r) => setTimeout(r, 60));
  const h = sampleHealth(loop.read(), { transfers: 3 });
  loop.stop();
  assert.ok(h.heap_used_mb > 0 && h.heap_limit_mb >= h.heap_used_mb);
  assert.ok(h.loop_max_ms >= 50, `the held loop shows in the sample (max ${h.loop_max_ms} ms)`);
  assert.ok(h.host_cpus >= 1 && h.host_total_mb > h.host_free_mb);
  assert.deepEqual(h.holds, { transfers: 3 });
  assert.ok(JSON.stringify(h).length < 600);
});

test("the snapshot is taken once, at 60% of the heap limit by default, while it can still be written", () => {
  assert.equal(snapshotAt({}), 0.6);
  assert.equal(snapshotAt({ SWARM_HUB_SNAPSHOT_AT: "0.4" }), 0.4);
  assert.equal(snapshotAt({ SWARM_HUB_SNAPSHOT_AT: "0" }), 0, "0 turns it off");
  assert.equal(snapshotAt({ SWARM_HUB_SNAPSHOT_AT: "7" }), 0.6);
  assert.equal(snapshotDue({ heap_used_mb: 2400, heap_limit_mb: 4288 }, false), false);
  assert.equal(snapshotDue({ heap_used_mb: 2600, heap_limit_mb: 4288 }, false), true);
  assert.equal(snapshotDue({ heap_used_mb: 4000, heap_limit_mb: 4288 }, true), false, "once");
  assert.equal(snapshotDue({ heap_used_mb: 4000, heap_limit_mb: 4288 }, false, 0), false);
});

test("a supervised hub past its heap line ends for a restart only at a quiet moment", async () => {
  const { recycleAt, recycleDue } = await import("../scripts/hub-health.ts");
  assert.equal(recycleAt({}), 0.85);
  assert.equal(recycleAt({ SWARM_HUB_RECYCLE_AT: "0" }), 0);
  assert.equal(recycleAt({ SWARM_HUB_RECYCLE_AT: "2" }), 0.85);
  const high = { heap_used_mb: 7100, heap_limit_mb: 8192 };
  const quiet = { supervised: true, callsInFlight: 0, jobsBusy: 0 };
  assert.equal(recycleDue({ heap_used_mb: 6000, heap_limit_mb: 8192 }, quiet, 0.85).due, false);
  const due = recycleDue(high, quiet, 0.85);
  assert.equal(due.due, true);
  assert.match(due.why, /heap 7100 of 8192 MB, past 85%, with no call in flight and no job running/);
  assert.match(recycleDue(high, { ...quiet, supervised: false }, 0.85).why, /no keeper would start it again/);
  assert.match(recycleDue(high, { ...quiet, callsInFlight: 2 }, 0.85).why, /2 call\(s\) in flight/);
  assert.match(recycleDue(high, { ...quiet, jobsBusy: 1 }, 0.85).why, /1 job\(s\) running or waiting to be sealed/);
  assert.equal(recycleDue(high, quiet, 0).due, false, "0 turns it off");
});

test("the host's memory pressure is its kernel's own signal, free memory only when there is none; the disk's speed is measured where the hub writes", async () => {
  const { diskSpeed, memoryPressure } = await import("../scripts/hub-health.ts");
  assert.deepEqual(await memoryPressure({ platform: "darwin", sysctl: async () => "4\n" }), { mem_pressure: "critical", mem_pressure_from: "macos" });
  assert.deepEqual(await memoryPressure({ platform: "darwin", sysctl: async () => "1" }), { mem_pressure: "normal", mem_pressure_from: "macos" });
  // macOS without the sysctl: free memory, said so.
  assert.deepEqual(await memoryPressure({ platform: "darwin", sysctl: async () => { throw new Error("no"); }, free: 1, total: 100 }), { mem_pressure: "critical", mem_pressure_from: "freemem" });
  const { mkdtemp, writeFile, rm, readdir } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "hub-health-"));
  try {
    const psi = join(dir, "memory");
    await writeFile(psi, "some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=0.40 avg60=0.10 avg300=0.00 total=45\n");
    assert.deepEqual(await memoryPressure({ platform: "linux", psiFile: psi }), { mem_pressure: "warn", mem_pressure_from: "linux-psi", mem_some_avg10: 12.5, mem_full_avg10: 0.4 });
    await writeFile(psi, "some avg10=40.00 avg60=3.00 avg300=1.00 total=123\nfull avg10=22.00 avg60=0.10 avg300=0.00 total=45\n");
    assert.equal((await memoryPressure({ platform: "linux", psiFile: psi })).mem_pressure, "critical");
    assert.deepEqual(await memoryPressure({ platform: "linux", psiFile: join(dir, "none"), free: 50, total: 100 }), { mem_pressure: "normal", mem_pressure_from: "freemem" });
    // This host, as the hub reads it.
    const here = await memoryPressure();
    assert.ok(["normal", "warn", "critical"].includes(String(here.mem_pressure)), JSON.stringify(here));
    assert.equal(here.mem_pressure_from, process.platform === "darwin" ? "macos" : process.platform === "linux" && (await readFile("/proc/pressure/memory", "utf8").then(() => true, () => false)) ? "linux-psi" : "freemem");
    const d = await diskSpeed(dir, 256 * 1024);
    assert.ok(d.disk_write_mb_s !== null && d.disk_write_mb_s > 0 && d.disk_fsync_ms !== null && d.disk_fsync_ms >= 0, JSON.stringify(d));
    assert.deepEqual((await readdir(dir)).sort(), ["memory"], "the probe's file is removed");
    const gone = await diskSpeed(join(dir, "no-such-dir"));
    assert.equal(gone.disk_write_mb_s, null);
    assert.match(gone.disk_error ?? "", /ENOENT/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a hub filled to 60% of its heap writes a heap snapshot that is not empty and a trace line that names it; its health lines say the host's pressure, the disk's speed and the sizes of what it holds", async () => {
  // The run s17fdfe's snapshot was 0 bytes: the hub died writing it at the limit. Here the real hub runs in a process
  // of its own with a 128 MB heap, filled past 60% by a module loaded before it, sampling itself every 300 ms.
  const { spawn } = await import("node:child_process");
  const { mkdtemp, readFile: read, rm, stat } = await import("node:fs/promises");
  const { realpathSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const P = await import("../extensions/protocol.ts");
  const base = realpathSync(await mkdtemp(join(tmpdir(), "hub-heap-")));
  const S = join(base, "run");
  const dir = await mkdtemp("/tmp/hh-");
  await P.initSandbox(S, { swarmId: "hh1", agentIds: ["a1"], capUsd: 1, wallClockMinutes: 30 });
  // Filled once the hub has loaded: arrays kept alive until the heap is 65% of its limit.
  const fill = `import v8 from "node:v8"; globalThis.__fill = []; setTimeout(() => { const limit = v8.getHeapStatistics().heap_size_limit; while (process.memoryUsage().heapUsed < 0.65 * limit) globalThis.__fill.push(new Array(32768).fill(0.5)); }, 1500).unref();`;
  // A small young generation, so that the heap's limit is its old space's (as with the hub's 8 GB) and 60% of it can be reached.
  const hub = spawn(process.execPath, ["--max-semi-space-size=1", "--max-old-space-size=128", "--experimental-strip-types", "--no-warnings", "--import", `data:text/javascript,${encodeURIComponent(fill)}`, join(import.meta.dirname, "..", "scripts", "vm-hub.ts"), S, "--dir", dir, "--run", "hh1", "--no-snapshot", "--quiet"], { env: { ...process.env, SWARM_HUB_HEALTH_MS: "300" }, stdio: ["pipe", "ignore", "pipe"] });
  let log = "";
  hub.stderr!.on("data", (c) => (log += c));
  hub.stdin!.end(JSON.stringify({ agents: ["a1"], tokens: {} }));
  const spill = join(dir, "hub-spill.jsonl");
  try {
    const end = Date.now() + 60_000;
    let lines: Array<{ tool: string; result: Record<string, unknown> }> = [];
    for (;;) {
      lines = (await read(spill, "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
      if (lines.some((l) => l.tool === "hub_heap_snapshot")) break;
      assert.ok(Date.now() < end && hub.exitCode === null, `no snapshot line in time; the hub said: ${log.slice(-2000)}`);
      await new Promise((r) => setTimeout(r, 200));
    }
    const shot = lines.find((l) => l.tool === "hub_heap_snapshot")!.result as { ok: boolean; file: string; bytes: number; heap_used_mb: number; heap_limit_mb: number };
    assert.equal(shot.ok, true, JSON.stringify(shot));
    assert.ok(shot.heap_used_mb > 0.6 * shot.heap_limit_mb, `taken at ${shot.heap_used_mb} of ${shot.heap_limit_mb} MB`);
    assert.equal(shot.file, join(dir, `Heap.at-60pct.${hub.pid}.heapsnapshot`), "the line names the file");
    const size = (await stat(shot.file)).size;
    assert.ok(size > 1024 * 1024 && size === shot.bytes, `the snapshot is ${size} bytes`);
    const head = Buffer.alloc(64);
    const fh = await (await import("node:fs/promises")).open(shot.file, "r");
    await fh.read(head, 0, 64, 0);
    await fh.close();
    assert.match(head.toString("utf8"), /^\{"snapshot":/, "and it is a heap snapshot");
    const health = lines.filter((l) => l.tool === "hub_health").map((l) => l.result as Record<string, unknown> & { holds: Record<string, number> });
    assert.ok(health.length >= 1);
    const h = health.at(-1)!;
    assert.ok(["normal", "warn", "critical"].includes(String(h.mem_pressure)) && typeof h.mem_pressure_from === "string", JSON.stringify(h));
    assert.ok(typeof h.disk_write_mb_s === "number" && (h.disk_write_mb_s as number) > 0 && typeof h.disk_fsync_ms === "number", JSON.stringify(h));
    for (const k of ["transfers_bytes", "call_args_bytes", "queued_prompts_bytes", "sweeps_bytes", "sweeps_hit_bytes", "ledger_kept_bytes", "replies_kept", "jobs"]) assert.equal(typeof h.holds[k], "number", `holds names ${k}`);
    assert.match(log, /^\d{4}-\d{2}-\d{2}T[\d:.]+Z vm-hub: up/m, "and the hub's own lines say when");
    process.stdout.write(`# a ${shot.heap_limit_mb} MB hub at ${shot.heap_used_mb} MB wrote a ${(size / 2 ** 20).toFixed(1)} MB snapshot; disk ${h.disk_write_mb_s} MB/s, fsync ${h.disk_fsync_ms} ms, pressure ${h.mem_pressure} (${h.mem_pressure_from})\n`);
  } finally {
    hub.kill("SIGKILL");
    await rm(base, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});

test("a disk probe that never ends holds no health sample: it is said slow or hung, the heap snapshot and the restart are still decided, and no second probe starts while it hangs", { timeout: 120_000 }, async () => {
  const { Hub } = await import("../scripts/vm-hub.ts");
  const P = await import("../extensions/protocol.ts");
  const { mkdtemp, rm, stat } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const base = await mkdtemp(join(tmpdir(), "hub-probe-"));
  const dir = await mkdtemp(join(tmpdir(), "hp-"));
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "hp1", agentIds: ["a1"], capUsd: 1, wallClockMinutes: 30 });
  const hub = new Hub({ sandbox: S, dir, agents: ["a1"], tokens: { a1: "t", system: "s" }, collector: join(dir, "none.sock"), backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false" });
  let probes = 0;
  // An fsync that never returns, as on a disk that hung.
  hub.diskProbe = () => (probes++, new Promise(() => undefined));
  hub.healthProbeMs = 200;
  const said: Array<[string, Record<string, unknown>]> = [];
  (hub as unknown as { event: (t: string, a: unknown, r: Record<string, unknown>) => Promise<void> }).event = async (t, _a, r) => void said.push([t, r]);
  const keys = ["SWARM_HUB_SNAPSHOT_AT", "SWARM_HUB_RECYCLE_AT", "SWARM_HUB_SUPERVISED"] as const;
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  // Both heap lines are passed at once, so that the sample has to reach them.
  process.env.SWARM_HUB_SNAPSHOT_AT = "0.0001";
  process.env.SWARM_HUB_RECYCLE_AT = "0.0001";
  process.env.SWARM_HUB_SUPERVISED = "1";
  const exit = process.exit;
  let exited: number | undefined;
  process.exit = ((code?: number) => void (exited = code)) as typeof process.exit;
  try {
    const loop = { read: () => ({ p50: 1, p99: 2, max: 3 }) };
    await hub.healthTick(loop);
    const t1 = performance.now();
    await hub.healthTick(loop);
    const second = performance.now() - t1;
    assert.ok(second < 1500, `the second sample took ${second.toFixed(0)} ms`);
    assert.equal(probes, 1, "no second probe while the first hangs");
    const health = said.filter(([t]) => t === "hub_health").map(([, r]) => r);
    assert.equal(health.length, 2, "both samples are on the trace");
    assert.equal(health[0]!.disk_write_mb_s, null);
    assert.match(String(health[0]!.disk_error), /the disk probe did not end within 200 ms: the disk under .* is slow or hung/);
    assert.match(String(health[1]!.disk_error), /the disk probe started \d+ s ago has not ended/);
    assert.ok(typeof health[0]!.heap_used_mb === "number" && (health[0]!.heap_used_mb as number) > 0, "the heap is read");
    const shot = said.find(([t]) => t === "hub_heap_snapshot")?.[1] as { ok: boolean; file: string; bytes: number } | undefined;
    assert.ok(shot?.ok, `the heap snapshot was taken: ${JSON.stringify(shot)}`);
    assert.ok((await stat(shot!.file)).size > 0);
    for (let i = 0; i < 100 && exited === undefined; i++) await new Promise((r) => setTimeout(r, 20));
    assert.equal(exited, 75, "and the restart past its line was decided");
    assert.ok(said.some(([t]) => t === "hub_recycled"));
  } finally {
    process.exit = exit;
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await hub.stop().catch(() => undefined);
    await rm(base, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});
