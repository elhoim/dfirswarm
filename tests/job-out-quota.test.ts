/**
 * A job's $OUT is given a write quota of its own (scripts/job-service.ts
 * outQuotaMb): microsandbox bounds a bind with none to 4 GiB (measured on
 * msb: a write stops at 4,294,967,296 bytes), which stopped three
 * whole-image AD1 extractions of one run part way through a file.
 *
 * The quota is one budget for the disk: the room free less the service's
 * reserve and less what the jobs that write there now were promised and have
 * not written, this run's and the other live runs' (hostStagingWriters reads
 * the run registry and what each live run's job service writes beside its
 * staging), so that jobs started at different times are never promised
 * together more than the disk holds. A share is never raised to
 * microsandbox's default, which would promise more than the disk holds.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { hostStagingWriters, JobService, MSB_DEFAULT_QUOTA_MB, outQuotaMb, STAGING_WRITERS } from "../scripts/job-service.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { freeMb } from "../scripts/job-scope.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

test("$OUT's quota is the free room less what the service keeps free, shared among the jobs that write, never more than there is; the environment can set it", () => {
  assert.equal(MSB_DEFAULT_QUOTA_MB, 4096);
  assert.equal(outQuotaMb(300_000, 4096, {}), 295_904, "the disk's room, less the service's reserve");
  assert.equal(outQuotaMb(6000, 4096, {}), 1904, "a disk with less room than msb's default is not promised the default");
  assert.equal(outQuotaMb(null, 4096, {}), 4096, "room unknown: the default");
  assert.equal(outQuotaMb(300_000, 4096, {}, 3), 98_634, "three jobs that write at once share the room");
  assert.equal(outQuotaMb(10_000, 4096, {}, 3), 1968, "a share is what there is, never raised to the default");
  assert.equal(outQuotaMb(4096, 4096, {}, 3), 1, "never 0, which would be no quota and msb's 4 GiB");
  assert.equal(outQuotaMb(300_000, 4096, {}, 0), 295_904, "a count that is no count is one");
  assert.equal(outQuotaMb(300_000, 4096, { SWARM_JOB_OUT_QUOTA_MB: "20000" }), 20_000);
  assert.equal(outQuotaMb(300_000, 4096, { SWARM_JOB_OUT_QUOTA_MB: "nope" }), 295_904);
  // However many write, the shares together are never more than the budget.
  for (const n of [1, 2, 3, 7, 16]) assert.ok(outQuotaMb(50_000, 4096, {}, n) * n <= 50_000 - 4096, `${n} sharers`);
  // What is promised and not yet written is not promised again; a slot that may still start a job keeps msb's default, or its share.
  assert.equal(outQuotaMb(300_000, 4096, {}, 1, { promisedMb: 100_000 }), 195_904);
  assert.equal(outQuotaMb(300_000, 4096, {}, 1, { idleSlots: 1 }), 295_904 - 4096);
  assert.equal(outQuotaMb(10_000, 4096, {}, 1, { idleSlots: 1 }), 2952, "a scarce disk: an even share for the slot");
  assert.equal(outQuotaMb(10_000, 4096, {}, 1, { promisedMb: 9000 }), 1, "nothing left: never 0");
});

test("two jobs started at different times are never promised together more than the disk holds: what the first has not written yet is counted when the second starts", () => {
  // Replayed: the free room as the disk has it at each start, the promises as the service keeps them (outQuotaMb), two workers.
  const minFree = 4096;
  for (const free0 of [20_000, 300_000, 2_000_000]) {
    for (const written of [0, 0.1, 0.5, 0.9]) {
      const a = outQuotaMb(free0, minFree, {}, 1, { idleSlots: 1 });
      const wa = Math.floor(a * written);
      const free1 = free0 - wa;
      const b = outQuotaMb(free1, minFree, {}, 1, { promisedMb: a - wa, idleSlots: 0 });
      assert.ok(a - wa + b <= free1 - minFree, `free ${free0}, A wrote ${wa}: A may still write ${a - wa} and B ${b}, over the ${free1 - minFree} there is`);
      assert.ok(b >= Math.min(MSB_DEFAULT_QUOTA_MB, Math.floor((free0 - minFree) / 2)) - 1, `B gets the room its slot kept (${b})`);
      // Without the promise counted, as before: the two together passed the room.
      const before = outQuotaMb(free1, minFree, {}, 2);
      if (written < 0.5) assert.ok(outQuotaMb(free0, minFree, {}, 1) - wa + before > free1 - minFree);
    }
  }
});

/** A run of the registry: its sandbox with a staging directory, a hub.pid, and what its job service said of its writers. */
function otherRun(base: string, id: string, o: { state?: string; hubPid?: number; writers?: { writers: number; pid: number; workers?: number; unused_mb?: number } | "torn"; workers?: number; noStaging?: boolean }): Record<string, unknown> {
  const sb = join(base, id);
  mkdirSync(sb, { recursive: true });
  if (!o.noStaging) mkdirSync(storePaths(sb).staging, { recursive: true });
  if (o.hubPid !== undefined) writeFileSync(join(sb, "hub.pid"), `${o.hubPid}\n`);
  if (o.writers === "torn") writeFileSync(join(storePaths(sb).staging, STAGING_WRITERS), "{\"v\":1,\"wri");
  else if (o.writers) writeFileSync(join(storePaths(sb).staging, STAGING_WRITERS), JSON.stringify({ v: 1, run: id, ...o.writers }));
  return { id, sandbox: sb, state: o.state ?? "running", isolation: { mode: "microvm", jobs: { workers: o.workers ?? 2 } } };
}

test("the jobs of every live run on the host share one staging budget: each run's writers as its job service last said them, or its declared workers; a stopped run, a dead hub and this run are not counted", async () => {
  const base = mkdtempSync(join(tmpdir(), "out-quota-"));
  const dead = 2 ** 22 - 3; // no such process on a test host
  try {
    const self = join(base, "self");
    for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(self, d), { recursive: true });
    writeFileSync(join(self, "inputs", "x.txt"), "x\n");
    listInputs(self);
    mkdirSync(storePaths(self).staging, { recursive: true });
    const runs = [
      { id: "self", sandbox: self, state: "running", isolation: { mode: "microvm", jobs: { workers: 6 } } },
      otherRun(base, "busy", { hubPid: process.pid, writers: { writers: 3, pid: process.pid } }),
      otherRun(base, "older", { hubPid: process.pid, workers: 4 }),
      otherRun(base, "torn", { hubPid: process.pid, writers: "torn", workers: 2 }),
      otherRun(base, "said-by-a-dead-hub", { hubPid: process.pid, writers: { writers: 9, pid: dead }, workers: 1 }),
      otherRun(base, "finished", { state: "finished", hubPid: process.pid, writers: { writers: 5, pid: process.pid } }),
      otherRun(base, "no-hub", { hubPid: dead, writers: { writers: 5, pid: process.pid } }),
      otherRun(base, "not-started", { hubPid: process.pid, noStaging: true, workers: 8 }),
      otherRun(base, "promising", { hubPid: process.pid, writers: { writers: 1, pid: process.pid, workers: 3, unused_mb: 700 } }),
    ];
    const registry = join(base, "registry.json");
    writeFileSync(registry, JSON.stringify({ runs }));
    const counted = hostStagingWriters(registry, self, storePaths(self).staging);
    assert.deepEqual(counted.runs, [
      { run: "busy", writers: 3, from: "writers_file" },
      { run: "older", writers: 4, from: "declared_workers" },
      { run: "torn", writers: 2, from: "declared_workers" },
      { run: "said-by-a-dead-hub", writers: 1, from: "declared_workers" },
      { run: "promising", writers: 1, from: "promises", promised_mb: 700, idle: 2 },
    ]);
    assert.deepEqual([counted.writers, counted.promised_mb, counted.idle], [10, 700, 2], "a run that says its promises is counted by them, not among the writers the rest is shared with");
    assert.deepEqual(hostStagingWriters(undefined, self, storePaths(self).staging), { writers: 0, promised_mb: 0, idle: 0, runs: [] }, "no registry: no other run");
    assert.equal(hostStagingWriters(join(base, "nothing.json"), self, storePaths(self).staging).writers, 0);

    // This run's job service: its job's quota is the budget less what the promising run has not written, with its two idle slots and
    // this run's other one keeping their part, shared with those ten and itself; and it says its own writers and promises.
    const seen: WorkerSpec[] = [];
    const real = localWorker();
    let release: () => void = () => undefined;
    const held = new Promise<void>((r) => (release = r));
    const svc = new JobService({
      sandbox: self, run: "s000001", registry, image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
      packDirs: [], forging: false, minFreeMb: 100,
      runWorker: async (spec: WorkerSpec) => {
        seen.push(spec);
        await held;
        return real(spec);
      },
      destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
    });
    await svc.start();
    const r = await svc.submit("a1", { kind: "command", command: "echo hi > \"$OUT/x.txt\"", inputs: [] });
    assert.ok(r.ok);
    const writersFile = join(storePaths(self).staging, STAGING_WRITERS);
    const said = () => (existsSync(writersFile) ? (JSON.parse(readFileSync(writersFile, "utf8")) as { writers: number; pid: number }) : null);
    for (let i = 0; i < 200 && !(seen.length && said()?.writers === 1); i++) await new Promise((res) => setTimeout(res, 25));
    assert.deepEqual([said()?.writers, said()?.pid], [1, process.pid], "the running job is said beside the staging, for the other runs");
    const mount = (seen[0]!.mounts ?? []).find((m) => typeof (m as { quota_mb?: number }).quota_mb === "number") as { quota_mb: number } | undefined;
    const expected = outQuotaMb(freeMb(storePaths(self).staging), 100, {}, 1 + 10, { promisedMb: 700, idleSlots: 1 + 2 });
    assert.ok(mount && Math.abs(mount.quota_mb - expected) <= Math.max(2, expected * 0.01), `the quota ${mount?.quota_mb} MiB is the room shared by 11 writers (${expected} MiB)`);
    const promise = said() as unknown as { workers: number; unused_mb: number };
    assert.deepEqual([promise.workers, promise.unused_mb], [2, mount!.quota_mb], "and what it promised, not yet written, is said for the other runs");
    release();
    for (let i = 0; i < 400 && svc.jobs.get(r.job.id)?.state !== "committed"; i++) await new Promise((res) => setTimeout(res, 25));
    assert.equal(said()?.writers, 0, "and none once it ended");
    await svc.stop("over");
  } finally {
    spawnSync("chmod", ["-R", "u+w", base]);
    rmSync(base, { recursive: true, force: true });
  }
});

test("in the service, a job started while another writes is promised what the first has not: the two quotas, less what the first wrote, are within the room", { timeout: 120_000 }, async () => {
  const base = mkdtempSync(join(tmpdir(), "out-quota-2-"));
  try {
    const self = join(base, "self");
    for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(self, d), { recursive: true });
    writeFileSync(join(self, "inputs", "x.txt"), "x\n");
    listInputs(self);
    const seen: WorkerSpec[] = [];
    const real = localWorker();
    const gates: Array<() => void> = [];
    const svc = new JobService({
      sandbox: self, run: "s000002", registry: join(base, "no-registry.json"), image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
      packDirs: [], forging: false, minFreeMb: 100,
      runWorker: async (spec: WorkerSpec) => {
        seen.push(spec);
        // The first job writes 64 MiB into its $OUT at once, then both wait to be let go.
        if (seen.length === 1) {
          const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!.host;
          mkdirSync(out, { recursive: true });
          writeFileSync(join(out, "big.bin"), Buffer.alloc(64 * 1024 * 1024, 1));
        }
        await new Promise<void>((r) => gates.push(r));
        return real(spec);
      },
      destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
    });
    await svc.start();
    const quota = (spec: WorkerSpec) => ((spec.mounts ?? []).find((m) => typeof (m as { quota_mb?: number }).quota_mb === "number") as { quota_mb: number }).quota_mb;
    const a = await svc.submit("a1", { kind: "command", command: "echo a > \"$OUT/a.txt\"", inputs: [] });
    assert.ok(a.ok);
    for (let i = 0; i < 400 && seen.length < 1; i++) await new Promise((res) => setTimeout(res, 25));
    const b = await svc.submit("a1", { kind: "command", command: "echo b > \"$OUT/b.txt\"", inputs: [] });
    assert.ok(b.ok);
    for (let i = 0; i < 400 && seen.length < 2; i++) await new Promise((res) => setTimeout(res, 25));
    const freeAtB = freeMb(storePaths(self).staging)!;
    assert.equal(seen.length, 2, "both jobs run at once");
    const [qa, qb] = [quota(seen[0]!), quota(seen[1]!)];
    // A has written 64 MiB of its quota: what it may still write and what B may are together within the room (a few MiB of slack for
    // what else this host wrote between the measures).
    const promised = qa - 64 + qb;
    assert.ok(promised <= freeAtB - 100 + 16, `A may still write ${qa - 64} MiB and B ${qb} MiB: ${promised} MiB promised, ${freeAtB - 100} MiB there`);
    assert.ok(qb >= 1, `A ${qa} MiB, B ${qb} MiB`);
    // On a disk with room past the idle slots' keep (4 GiB each), the first job alone was promised all but that keep, so more than the
    // second; on a small one (a microVM's /tmp) the idle slot keeps its even share and the two come out alike.
    if (freeAtB > 3 * 4096) assert.ok(qa > qb, `A ${qa} MiB, B ${qb} MiB`);
    // As each job was promised before: all the room to the first, half of it to the second, together far past it.
    assert.ok(outQuotaMb(freeAtB + 64, 100, {}, 1) - 64 + outQuotaMb(freeAtB, 100, {}, 2) > freeAtB - 100 + 16);
    for (const g of gates) g();
    for (let i = 0; i < 400 && !["committed", "failed"].includes(String(svc.jobs.get(b.job.id)?.state)); i++) {
      for (const g of gates.splice(0)) g();
      await new Promise((res) => setTimeout(res, 25));
    }
    await svc.stop("over");
  } finally {
    spawnSync("chmod", ["-R", "u+w", base]);
    rmSync(base, { recursive: true, force: true });
  }
});
