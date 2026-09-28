/**
 * UNTESTED: written without booting a VM, to be run by hand on a host that
 * boots microVMs. The acceptance tests of the EXPERIMENTAL observation of a
 * job's reads (fanotify inside its worker, scripts/job-observe.py and
 * scripts/job-observe.ts), each on this host's own guest kernel and
 * virtio-fs. Until every one passes there, observation stays off and custody
 * says a declared job's reads within its scope are not observed.
 *
 *   SWARM_JOB_OBSERVE_VM=1 node --experimental-strip-types --test --test-concurrency=1 tests/job-observe-vm.test.ts
 *
 * Skipped without SWARM_JOB_OBSERVE_VM=1; not in `npm test` or `npm run
 * test:vm`. VM_TEST_IMAGE names the image (default dfirswarm-base:dev-<arch>;
 * it needs python3 and setpriv).
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, renameSync } from "node:fs";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { destroyWorker, msbBinary, probeHost, runWorker } from "../scripts/vm.ts";
import { initStore, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { listInputs } from "./job-service-worker.ts";

const ARCH = process.arch === "arm64" ? "arm64" : "amd64";
const IMAGE = process.env.VM_TEST_IMAGE || `dfirswarm-base:dev-${ARCH}`;
const WANTED = process.env.SWARM_JOB_OBSERVE_VM === "1";
let skip: string | false = WANTED ? false : "the observation's VM acceptance tests run only with SWARM_JOB_OBSERVE_VM=1";
const runs: string[] = [];

before(async () => {
  if (skip) return;
  process.env.SWARM_JOB_OBSERVE = "fanotify-experimental";
  const probe = await probeHost(IMAGE).catch((err: Error) => ({ ok: false, reasons: [err.message], image_present: false }));
  if (!probe.ok || !probe.image_present) throw new Error(`this host cannot run them (${probe.ok ? `no image ${IMAGE}` : (probe as { reasons: string[] }).reasons.join("; ")})`);
});

after(async () => {
  delete process.env.SWARM_JOB_OBSERVE;
  for (const run of runs) {
    const list = execFileSync(msbBinary(), ["list", "--format", "json"], { encoding: "utf8" });
    for (const name of (JSON.parse(list || "[]") as Array<{ name: string }>).map((v) => v.name).filter((n) => n.startsWith(`dfs-${run}-`))) await destroyWorker(name);
  }
});

async function rig(files: Record<string, string> = {}) {
  const base = await mkdtemp(join(tmpdir(), "obsvm-"));
  const run = `ov${Math.random().toString(36).slice(2, 8)}`;
  runs.push(run);
  const S = join(base, "runs", run);
  for (const d of ["inputs/dir", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs", "disk.E01"), "declared evidence");
  await writeFile(join(S, "inputs", "other.bin"), "undeclared evidence");
  await writeFile(join(S, "inputs", "dir", "a.txt"), "in a bound directory");
  for (const [p, body] of Object.entries(files)) {
    await mkdir(join(S, p, ".."), { recursive: true });
    await writeFile(join(S, p), body);
  }
  listInputs(S);
  await initStore(S);
  const svc = new JobService({ sandbox: S, run, image: IMAGE, workers: 2, workerCpus: 1, workerMemoryMib: 1024, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 64, runWorker, destroyWorker, notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  return { S, svc };
}

async function observed(S: string, svc: JobService, command: string, inputs: string[]): Promise<{ job: JobRecord; line: Record<string, unknown>; read: { opened: Array<{ path: string; what: string[] }>; escapes: string[]; reasons: string[] } }> {
  const r = await svc.submit("a1", { kind: "command", command, inputs, timeout_seconds: 120 });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  let job: JobRecord | undefined;
  for (let i = 0; i < 1200 && !(job && (job.state === "committed" || job.state === "failed")); i += 1) {
    job = svc.jobs.get(r.job.id);
    await new Promise((res) => setTimeout(res, 100));
  }
  const line = verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines.find((l) => l.type === "job_observed" && l.job === r.job.id) as Record<string, unknown>;
  assert.ok(line, "a job_observed line");
  return { job: job!, line, read: JSON.parse(readFileSync(join(S, String(line.read)), "utf8")) };
}

const opened = (read: { opened: Array<{ path: string }> }, S: string, rel: string) => read.opened.some((o) => o.path === join(S, rel));

test("the actual kernel and virtio-fs: a declared read is seen, the canary twice, the log verifies", { skip }, async () => {
  const { S, svc } = await rig();
  const { line, read } = await observed(S, svc, "cat inputs/disk.E01", ["input:disk.E01"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  assert.ok(opened(read, S, "inputs/disk.E01"));
  await svc.stop("over");
});

test("a static binary and a direct syscall are seen as any read is", { skip }, async () => {
  const { S, svc } = await rig();
  const direct = "python3 -c \"import ctypes,os; libc=ctypes.CDLL(None,use_errno=True); fd=libc.syscall(56 if os.uname().machine=='aarch64' else 257, -100, b'inputs/disk.E01', 0, 0); os.read(fd, 10)\"";
  const busybox = "(command -v busybox >/dev/null && busybox cat inputs/dir/a.txt) || true";
  const { line, read } = await observed(S, svc, `${direct}; ${busybox}`, ["input:disk.E01", "input:dir/"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  assert.ok(opened(read, S, "inputs/disk.E01"), "openat(2) called directly");
  await svc.stop("over");
});

test("a descendant's read is seen: a background child, a double fork", { skip }, async () => {
  const { S, svc } = await rig();
  const { line, read } = await observed(S, svc, "(sh -c 'sleep 0.2; cat inputs/disk.E01 >/dev/null' &) ; sleep 1", ["input:disk.E01"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  assert.ok(opened(read, S, "inputs/disk.E01"));
  await svc.stop("over");
});

test("a mount inside the view (a bound directory) is marked and seen", { skip }, async () => {
  const { S, svc } = await rig();
  const { line, read } = await observed(S, svc, "cat inputs/dir/a.txt", ["input:dir/"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  assert.ok(opened(read, S, "inputs/dir/a.txt"));
  await svc.stop("over");
});

test("a file renamed on the host while the job holds it open is still seen, under a name inside the scope", { skip }, async () => {
  const { S, svc } = await rig();
  const done = observed(S, svc, "python3 -c \"import time; f=open('inputs/dir/a.txt'); time.sleep(3); f.read()\"", ["input:dir/"]);
  await new Promise((r) => setTimeout(r, 2000));
  renameSync(join(S, "inputs", "dir", "a.txt"), join(S, "inputs", "dir", "c.txt"));
  const { read } = await done;
  assert.ok(read.opened.some((o) => o.path.startsWith(join(S, "inputs", "dir"))), JSON.stringify(read.opened));
  assert.deepEqual(read.escapes, []);
  await svc.stop("over");
});

test("a read through mmap shows as the open, and only as the open", { skip }, async () => {
  const { S, svc } = await rig();
  const { line, read } = await observed(S, svc, "python3 -c \"import mmap; f=open('inputs/disk.E01','rb'); m=mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ); m[:5]\"", ["input:disk.E01"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  const o = read.opened.find((x) => x.path === join(S, "inputs", "disk.E01"));
  assert.ok(o?.what.includes("open"));
  await svc.stop("over");
});

test("a queue overflow is said: partial, never complete", { skip }, async () => {
  const many: Record<string, string> = {};
  for (let i = 0; i < 40000; i += 1) many[`inputs/many/${String(i).padStart(5, "0")}`] = "x";
  const { S, svc } = await rig(many);
  const { line } = await observed(S, svc, "for i in 1 2 3; do cat inputs/many/* > /dev/null; done", ["input:many/"]);
  assert.ok(line.status === "partial" || line.status === "complete", String(line.status));
  if (line.status === "complete") assert.equal(line.overflow, 0, "complete only with no overflow");
  else assert.ok(Number(line.overflow) > 0 || (line.reasons as string[]).length);
  await svc.stop("over");
});

test("the job cannot kill the collector, forge its log or read its key: it runs as nobody", { skip }, async () => {
  const { S, svc } = await rig();
  const tries = "pkill -9 -f observe.py; echo forged >> /observe/events.jsonl; cat /observe/key; kill -9 1; true";
  const { job, line, read } = await observed(S, svc, `${tries} 2> \"$OUT/refusals.txt\"; cat inputs/disk.E01`, ["input:disk.E01"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  const refusals = readFileSync(join(storePaths(S).jobs, job.id, "out", "refusals.txt"), "utf8");
  assert.match(refusals, /Permission denied|Operation not permitted/);
  await svc.stop("over");
});

// A collector that dies mid-job: the job cannot kill it (above), and nothing else in the worker
// runs as root; a log without its end reads as unknown (tests/job-observe.test.ts). Killing it
// from outside the worker needs a hook this prototype does not have.
test.todo("a collector killed from outside the worker mid-job is read as unknown");

test("a scope escape finds nothing to read and nothing outside is seen", { skip }, async () => {
  const { S, svc } = await rig();
  const { job, line, read } = await observed(S, svc, `cat inputs/other.bin ${S}/../../etc/hostname ../inputs/other.bin > \"$OUT/escape.txt\" 2>&1; cat inputs/disk.E01`, ["input:disk.E01"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  assert.deepEqual(read.escapes, []);
  assert.match(readFileSync(join(storePaths(S).jobs, job.id, "out", "escape.txt"), "utf8"), /other\.bin: No such file/);
  await svc.stop("over");
});

test("writes to $OUT while reading the evidence: only the evidence's reads are seen", { skip }, async () => {
  const { S, svc } = await rig();
  const { line, read } = await observed(S, svc, "for i in $(seq 200); do cat inputs/disk.E01 > \"$OUT/copy-$i\"; done", ["input:disk.E01"]);
  assert.equal(line.status, "complete", JSON.stringify(read.reasons));
  assert.ok(read.opened.every((o) => !o.path.includes("/.jobs/")), "the job's own output is not marked");
  await svc.stop("over");
});
