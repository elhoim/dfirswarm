/**
 * The job service's stages apart from each other, held to what the runs of
 * s17fdfe showed (deep-reports/platform.md P-01, P-09, P-11, P-17, P-19,
 * P-20, P-22, P-23), with the worker VM replaced by the stand-in of
 * tests/job-service-worker.ts or by one this file holds open:
 *
 * - a worker slot is free from job_fenced, the seal is a stage of its own
 *   with its own bound, a small commit passes a large seal, and a restart
 *   queues the seals it finds instead of doing them before it takes a job;
 * - whoever asked is told before the job's files are offered to the derived
 *   recipes, no file is opened for an offer at the lane's ceiling, the lane's
 *   order puts a user's programs and documents first and a language's
 *   runtime last, and part of the ceiling is kept for a user's objects;
 * - the identical whole-object tool call is answered with the job under way
 *   or committed, and `independent: true` runs it again;
 * - a job's same_as is a count, the bytes and a side file past a few files;
 * - job_finished says when the command ended, when the worker was gone and
 *   when the service went on, a job is held to its limit from outside its
 *   worker, and a worker not confirmed gone keeps its slot;
 * - a stop cancels what never started on the record, and says nothing of
 *   workers that do not run.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVED, DERIVED_FLOOR, DERIVED_LIMITS, DERIVED_RESERVE, derivedPass, derivedRank, derivedRoom, describe, JobService, jobView, sealIsLarge, sealLeftStaging, SEAL_LARGE_FILES, type JobRecord, type JobServiceOptions } from "../scripts/job-service.ts";
import { buildIndex, writeIndex } from "../scripts/manifest-index.ts";
import { sealTree, storePaths, verifyJournalText, type JournalLine } from "../scripts/evidence-store.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "stages-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "image.bin"), "an image\n".repeat(40));
  listInputs(S);
  return S;
}

function tool(S: string, name: string, body: string, params: Record<string, unknown>): void {
  mkdirSync(join(S, "tools", name), { recursive: true });
  writeFileSync(join(S, "tools", name, "run.py"), body);
  writeFileSync(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, description: "t", params, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex") }));
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const posts: Array<[string, string]> = [];
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [], forging: true, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => { posts.push([to, body]); }, identity: async (a) => ({ name: `${a}-name` }),
    // JOB_TEST_LOG=1 prints the service's own log lines when a test here is being read.
    ...(process.env.JOB_TEST_LOG ? { log: (line: string) => process.stderr.write(`${line}\n`) } : {}),
    ...extra,
  });
  return { svc, posts };
}

const journal = (S: string): JournalLine[] => {
  const checked = verifyJournalText(readFileSync(storePaths(S).journal, "utf8"));
  assert.equal(checked.error, undefined, "the journal chains");
  return checked.lines;
};
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function eventually(ok: () => boolean, what: string, ms = 30000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await sleep(25);
  }
}

async function until(svc: JobService, id: string, states = ["committed", "failed", "cancelled"], ms = 30000): Promise<JobRecord> {
  const end = Date.now() + ms;
  while (!states.includes(svc.jobs.get(id)?.state ?? "")) {
    if (Date.now() > end) throw new Error(`job ${id} is ${svc.jobs.get(id)?.state} after ${ms} ms, not ${states.join(" or ")}`);
    await sleep(25);
  }
  return svc.jobs.get(id)!;
}

function ok<T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> {
  assert.ok(r.ok, JSON.stringify(r));
  return r as Extract<T, { ok: true }>;
}

/** A seal that takes `ms` for the jobs `slow` names, and is evidence-store's own for the rest. */
function slowSeal(slow: (job: string) => boolean, ms: number, seen: string[] = []): typeof sealTree {
  return async (sandboxDir, staging, dest, job, attempt, manifestPath) => {
    seen.push(job);
    if (slow(job)) await sleep(ms);
    return sealTree(sandboxDir, staging, dest, job, attempt, manifestPath);
  };
}

/** Each job's lines in the order every job's must be in. */
function ordered(lines: JournalLine[], id: string): void {
  const mine = lines.filter((l) => l.job === id && ["job_accepted", "job_started", "job_finished", "job_fenced", "job_committed"].includes(l.type)).map((l) => l.type);
  assert.deepEqual(mine, ["job_accepted", "job_started", "job_finished", "job_fenced", "job_committed"], `${id}: ${mine.join(",")}`);
}

// --- A1: the slot is free at job_fenced, the seal is its own stage ------------------------------------

test("a slot is free from job_fenced: with two workers and a seal of three seconds, two later jobs start within two seconds and are committed while it still seals", async () => {
  const S = sandbox();
  const { svc } = service(S, { workers: 2, sealTree: slowSeal((j) => j === "j000001", 3000) });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command: "printf a > \"$OUT/a\"", inputs: [] }));
  await until(svc, a.job.id, ["fenced"]);
  // The record in memory is fenced a moment before job.json is written again: read once it is.
  const projected = () => JSON.parse(readFileSync(join(storePaths(S).jobs, a.job.id, "job.json"), "utf8")).state as string;
  await eventually(() => projected() !== "finished", "job.json written at the fence", 2000);
  assert.equal(projected(), "fenced", "job.json says where it is, not running");
  const asked = Date.now();
  const b = ok(await svc.submit("a2", { kind: "command", command: "printf b > \"$OUT/b\"", inputs: [] }));
  const c = ok(await svc.submit("a3", { kind: "command", command: "printf c > \"$OUT/c\"", inputs: [] }));
  const [bd, cd] = [await until(svc, b.job.id), await until(svc, c.job.id)];
  for (const j of [bd, cd]) assert.ok(Date.parse(j.started_at!) - asked < 2000, `${j.id} started ${Date.parse(j.started_at!) - asked} ms after it was asked for`);
  assert.equal(svc.jobs.get(a.job.id)!.state, "fenced", "both are committed while the first is still being sealed");
  assert.match(svc.waitWords(svc.jobs.get(a.job.id)!) ?? "", /being sealed into the store now/);
  assert.ok(Date.now() - asked < 2800, `committed ${Date.now() - asked} ms after they were asked for, inside the three seconds of the seal`);
  const ad = await until(svc, a.job.id);
  assert.equal(ad.status, "ok");
  assert.equal(readFileSync(join(storePaths(S).jobs, a.job.id, "out", "a"), "utf8"), "a");
  const lines = journal(S);
  for (const j of [a, b, c]) ordered(lines, j.job.id);
  const committed = lines.filter((l) => l.type === "job_committed").map((l) => l.job);
  assert.deepEqual(committed, [b.job.id, c.job.id, a.job.id].sort((x, y) => (x === a.job.id ? 1 : y === a.job.id ? -1 : 0)).filter((x) => committed.includes(x)), "the small commits passed the long seal");
  assert.equal(committed.at(-1), a.job.id);
  assert.equal(lines.filter((l) => l.type === "job_started").length, 3, "nothing started is lost");
  await svc.stop("over");
});

test("a small job's commit has a sealer no large tree holds: two large trees seal one after the other, and a small one beside them", async () => {
  const S = sandbox();
  const seen: string[] = [];
  const { svc } = service(S, { workers: 3, perRequesterRunning: 3, sealers: 2, sealTree: slowSeal((j) => j === "j000001" || j === "j000002", 1500, seen) });
  await svc.start();
  const many = `i=0; while [ $i -le ${SEAL_LARGE_FILES} ]; do : > "$OUT/f$i"; i=$((i+1)); done`;
  const l1 = ok(await svc.submit("a1", { kind: "command", command: many, inputs: [] }));
  const l2 = ok(await svc.submit("a1", { kind: "command", command: many, inputs: [] }));
  await until(svc, l1.job.id, ["fenced", "committed"]);
  await until(svc, l2.job.id, ["fenced", "committed"]);
  await eventually(() => seen.length >= 1, "the first large seal began");
  await sleep(100);
  assert.equal(seen.length, 1, "the second large tree waits: one sealer is kept for small jobs");
  assert.match(svc.waitWords(svc.jobs.get(seen[0] === l1.job.id ? l2.job.id : l1.job.id)!) ?? "", /waiting to be sealed into the store: 0 job\(s\) ahead of it/);
  const small = ok(await svc.submit("a2", { kind: "command", command: "printf s > \"$OUT/s\"", inputs: [] }));
  await until(svc, small.job.id);
  assert.ok([l1, l2].every((l) => svc.jobs.get(l.job.id)!.state === "fenced"), "the small job is committed while both large ones wait or seal");
  assert.equal((await until(svc, l1.job.id)).outputs?.files, SEAL_LARGE_FILES + 1);
  assert.equal((await until(svc, l2.job.id)).outputs?.files, SEAL_LARGE_FILES + 1);
  const P = storePaths(S);
  assert.equal(await sealIsLarge(join(P.jobs, l1.job.id, "out"), join(P.staging, "none")), true);
  assert.equal(await sealIsLarge(join(P.jobs, small.job.id, "out"), join(P.staging, "none")), false);
  await svc.stop("over");
});

test("a restart queues the seals it finds and takes jobs at once: a job asked for after it is committed before the seal a crash left", async () => {
  const S = sandbox();
  const code = `
import { JobService } from ${JSON.stringify(join(ROOT, "scripts", "job-service.ts"))};
import { localWorker } from ${JSON.stringify(join(ROOT, "tests", "job-service-worker.ts"))};
const svc = new JobService({ sandbox: ${JSON.stringify(S)}, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1,
  runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => {}, identity: async () => ({}) });
await svc.start();
await svc.submit("a1", { kind: "command", command: "printf left > \\"$OUT/left\\"", inputs: [] });
await new Promise((r) => setTimeout(r, 20000));
`;
  const child = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", code], { encoding: "utf8", env: { ...process.env, SWARM_JOB_CRASH_AT: "job:fenced" }, timeout: 30000 });
  assert.equal(child.status, 99, child.stderr);
  const { svc } = service(S, { workers: 1, sealTree: slowSeal((j) => j === "j000001", 2500) });
  const before = Date.now();
  await svc.start();
  assert.ok(Date.now() - before < 1500, `start returned after ${Date.now() - before} ms, not after the seal`);
  assert.equal(svc.jobs.get("j000001")!.state, "fenced");
  const next = ok(await svc.submit("a2", { kind: "command", command: "printf next > \"$OUT/next\"", inputs: [] }));
  await until(svc, next.job.id);
  assert.equal(svc.jobs.get("j000001")!.state, "fenced", "the new job is committed while the left one still seals");
  assert.equal((await until(svc, "j000001")).status, "ok");
  assert.equal(readFileSync(join(storePaths(S).jobs, "j000001", "out", "left"), "utf8"), "left");
  ordered(journal(S), "j000001");
  await svc.stop("over");
});

// --- A9: told first, offered behind; the lane's order and its ceiling ------------------------------------

test("a commit of 5,000 files tells its requester before any of them is offered to the derived recipes", async () => {
  const S = sandbox();
  const atNotify: number[] = [];
  const { svc, posts } = service(S, { packDirs: [CFB], derived: true });
  (svc.o as { notify: JobServiceOptions["notify"] }).notify = async (to, body) => {
    atNotify.push(svc.counters.offers_started);
    posts.push([to, body]);
  };
  await svc.start();
  const r = ok(await svc.submit("a1", { kind: "command", command: "python3 -c \"import os\nfor i in range(5000): open(os.environ['OUT']+'/f%04d.bin'%i,'w').write('x%04d-'%i*8)\nopen(os.environ['OUT']+'/named.zip','w').write('not a zip, but named one: its name is the recipe\\'s measure')\"", inputs: [] }));
  const done = await until(svc, r.job.id, undefined, 120000);
  assert.equal(done.outputs?.files, 5001);
  await eventually(() => posts.some(([to, b]) => to === "a1" && b.startsWith(`Job ${r.job.id} `)), "the requester is told");
  assert.deepEqual(atNotify.slice(0, 1), [0], "no offer had begun when the requester was told");
  await eventually(() => journal(S).some((l) => l.type === "derived_offered" && l.job === r.job.id), "its files are offered, behind the commit", 120000);
  const lines = journal(S);
  const told = lines.find((l) => l.type === "job_notified" && l.job === r.job.id)!;
  const offered = lines.find((l) => l.type === "derived_offered" && l.job === r.job.id)!;
  assert.ok(told.seq < offered.seq, "job_notified is on the journal before derived_offered");
  assert.deepEqual([offered.filtered, (offered.offered as Array<{ path: string }>).map((o) => o.path)], [5000, ["named.zip"]], "each was held to the recipes' own measure");
  assert.equal(svc.counters.offer_file_opens, 5000, "below the ceiling the head of each file a name does not settle is read");
  await svc.stop("over");
});

test("at the lane's ceiling an offer opens no file and reads no manifest: the line says it was not read, and the ceiling is said once", async () => {
  const S = sandbox();
  const { svc, posts } = service(S, { packDirs: [CFB], derived: true, derivedLimits: { generationsMax: 0 } });
  await svc.start();
  const r = ok(await svc.submit("a1", { kind: "command", command: "i=0; while [ $i -lt 30 ]; do printf 'forty bytes of nothing a recipe would take %02d' $i > \"$OUT/f$i.bin\"; i=$((i+1)); done", inputs: [] }));
  await until(svc, r.job.id);
  await eventually(() => journal(S).some((l) => l.type === "derived_offered"), "the offer is on the record");
  const line = journal(S).find((l) => l.type === "derived_offered")!;
  assert.deepEqual([line.not_read, line.files, (line.offered as unknown[]).length], ["generations", 30, 0]);
  assert.equal(svc.counters.offer_file_opens, 0, "no file was opened");
  await eventually(() => posts.some(([to, b]) => to === "all" && b.startsWith("The derived catalogue has reached its 0 generations")), "said to all");
  await svc.stop("over");
  // A restarted service does not offer it again.
  const again = service(S, { packDirs: [CFB], derived: true, derivedLimits: { generationsMax: 0 } }).svc;
  await again.start();
  await sleep(300);
  assert.equal(journal(S).filter((l) => l.type === "derived_offered").length, 1);
  assert.equal(again.counters.offer_file_opens, 0);
  await again.stop("over");
});

test("the lane's order: a program in a profile's Temp first, a user's other files next, Program Files and a Python's .pyd last, wherever the Python sits", () => {
  const list = [
    "image/Program Files/Vendor/app.exe",
    "image/Users/x/AppData/Local/Programs/Python/Python311/DLLs/_ssl.pyd",
    "image/Users/x/AppData/Local/Programs/Python/Python311/DLLs/_sqlite3.pyd",
    "image/Users/x/AppData/Local/Temp/setup.exe",
    "image/Users/x/AppData/Roaming/notes/state.dat",
    "image/Users/x/Downloads/invoice.docx",
    "image/Users/x/Downloads/thumb.cache",
    "image/Windows/System32/config/x.cab",
    "image/Users/x/AppData/Local/Temp/pip-unpack/site-packages/pkg/_core.pyd",
    "image/other/blob.zip",
  ];
  const sorted = [...list].sort((a, b) => derivedRank(a) - derivedRank(b) || list.indexOf(a) - list.indexOf(b));
  assert.equal(sorted[0], "image/Users/x/AppData/Local/Temp/setup.exe", "the Temp executable first");
  assert.deepEqual(sorted.slice(0, 2).sort(), ["image/Users/x/AppData/Local/Temp/setup.exe", "image/Users/x/Downloads/invoice.docx"].sort());
  const at = (p: string) => sorted.indexOf(p);
  const user = ["image/Users/x/AppData/Roaming/notes/state.dat", "image/Users/x/Downloads/thumb.cache"];
  const pyd = list.filter((p) => p.endsWith(".pyd"));
  for (const p of pyd) for (const u of user) assert.ok(at(p) > at(u), `${p} after ${u}`);
  for (const p of pyd) assert.equal(derivedRank(p), 2, `${p} is a runtime's`);
  assert.equal(derivedRank("image/Program Files/Vendor/app.exe"), 2);
  assert.ok(at("image/other/blob.zip") < at("image/Program Files/Vendor/app.exe") && at("image/other/blob.zip") > at(user[0]), "what is neither a user's nor a vendor's stands between");
  // The ranks the earlier runs pinned hold (tests/derived-catalog.test.ts).
  assert.deepEqual([derivedRank("C/Users/bob/Documents/a.docx"), derivedRank("extracted/archive.zip"), derivedRank("Users/bob/AppData/Local/Microsoft/Edge/x.zip")], [0, 1, 2]);
  // What a seat picked by name when it extracted it is first whatever its path.
  assert.equal(derivedRank("image/Program Files/Vendor/app.exe", { picked: true }), 0);
});

test("part of the ceiling is kept for what a user made or kept: vendor objects take the rest and no more, and a user's object offered later is still catalogued", async () => {
  const S = sandbox();
  // Five generations, three of them kept (DERIVED_RESERVE, three fifths): the vendor's files get two.
  const kept = Math.floor(5 * DERIVED_RESERVE);
  assert.equal(kept, 3);
  const { svc } = service(S, { packDirs: [CFB], derived: true, derivedLimits: { generationsMax: 5 } });
  await svc.start();
  const tar = (dir: string, names: string[]) => `python3 - <<'PY'\nimport tarfile,io,os\nfor k,n in enumerate(${JSON.stringify(names)}):\n  d=os.path.join(os.environ['OUT'],${JSON.stringify(dir)}); os.makedirs(d,exist_ok=True)\n  with tarfile.open(os.path.join(d,n),'w') as t:\n    i=tarfile.TarInfo('m.txt'); b=(n*400).encode(); i.size=len(b); t.addfile(i,io.BytesIO(b))\nPY`;
  const vendor = ok(await svc.submit("a1", { kind: "command", command: tar("image/Program Files/Vendor", ["v1.tar", "v2.tar", "v3.tar", "v4.tar", "v5.tar", "v6.tar"]), inputs: [] }));
  await until(svc, vendor.job.id);
  const gens = () => journal(S).filter((l) => l.type === "generation_committed" && l.trigger === "derived");
  await eventually(() => journal(S).some((l) => l.type === "derived_not_run" || (l.type === "job_cancelled" && String(l.reason).includes("kept for what a user made"))), "the vendor objects past the unreserved part are not run", 120000);
  await eventually(() => gens().length === 5 - kept && ![...svc.jobs.values()].some((j) => j.requester.agent === DERIVED && ["accepted", "running", "finished", "fenced"].includes(j.state)), "two generations, and the lane idle", 120000);
  assert.equal(gens().length, 5 - kept, "the vendor's files took the two that are not kept back");
  const user = ok(await svc.submit("a1", { kind: "command", command: tar("image/Users/x/Downloads", ["u.tar"]), inputs: [] }));
  await until(svc, user.job.id);
  await eventually(() => gens().length === 5 - kept + 1, "the user's object, offered later, takes one of the kept ones", 120000);
  assert.match(String((gens()[5 - kept].target as { ref?: string }).ref), /Users\/x\/Downloads\/u\.tar$/);
  assert.ok(![...svc.jobs.values()].some((j) => j.requester.agent === DERIVED && j.state === "accepted"), "nothing of the lane is left queued");
  await svc.stop("over");
});

test("in the service, kept room is lent to the next rank's objects down to the floor, and a user's object offered later takes the floor", async () => {
  const S = sandbox();
  // Five generations, three kept, one of them never lent (DERIVED_FLOOR): the next rank's objects get four.
  assert.deepEqual([Math.floor(5 * DERIVED_RESERVE), Math.floor(5 * DERIVED_FLOOR)], [3, 1]);
  const { svc } = service(S, { packDirs: [CFB], derived: true, derivedLimits: { generationsMax: 5 } });
  await svc.start();
  const tar = (dir: string, names: string[]) => `python3 - <<'PY'\nimport tarfile,io,os\nfor k,n in enumerate(${JSON.stringify(names)}):\n  d=os.path.join(os.environ['OUT'],${JSON.stringify(dir)}); os.makedirs(d,exist_ok=True)\n  with tarfile.open(os.path.join(d,n),'w') as t:\n    i=tarfile.TarInfo('m.txt'); b=(n*400).encode(); i.size=len(b); t.addfile(i,io.BytesIO(b))\nPY`;
  const web = ok(await svc.submit("a1", { kind: "command", command: tar("image/inetpub/wwwroot/app", ["w1.tar", "w2.tar", "w3.tar", "w4.tar", "w5.tar", "w6.tar"]), inputs: [] }));
  await until(svc, web.job.id);
  assert.equal(derivedRank("image/inetpub/wwwroot/app/w1.tar"), 1);
  const gens = () => journal(S).filter((l) => l.type === "generation_committed" && l.trigger === "derived");
  await eventually(() => gens().length === 4 && ![...svc.jobs.values()].some((j) => j.requester.agent === DERIVED && ["accepted", "running", "finished", "fenced"].includes(j.state)), "four generations, and the lane idle", 120000);
  assert.ok(gens().every((g) => /inetpub\/wwwroot\/app\/w\d\.tar$/.test(String((g.target as { ref?: string }).ref))), "the next rank's objects, two of them on loan");
  assert.ok(journal(S).some((l) => (l.type === "job_cancelled" && /the last 1 never lent/.test(String(l.reason))) || l.type === "derived_not_run"), "past the floor the rest is not run, and said so");
  const user = ok(await svc.submit("a1", { kind: "command", command: tar("image/Users/x/Downloads", ["u.tar"]), inputs: [] }));
  await until(svc, user.job.id);
  await eventually(() => gens().length === 5, "the user's object, offered later, takes the floor", 120000);
  assert.match(String((gens()[4].target as { ref?: string }).ref), /Users\/x\/Downloads\/u\.tar$/);
  await svc.stop("over");
});

/** A tree of a Windows image, the way extraction jobs commit it: objects a recipe would take, by path and size. */
function windowsTree(): { vendor: string[]; runtime: string[]; profile: string[] } {
  const vendor: string[] = [];
  for (let v = 0; v < 6; v++) for (const f of ["setup.exe", "data1.cab", "data2.cab", "product.msi", "core.dll", "update.exe", "lang.cab", "help.zip"]) vendor.push(`image/Program Files/Vendor${v}/${f}`);
  for (let i = 0; i < 20; i++) vendor.push(`image/Program Files (x86)/Common Files/Shared${i % 4}/component${i}.cab`);
  for (let i = 0; i < 20; i++) vendor.push(`image/Windows/WinSxS/amd64_package_${i}/package.cab`);
  for (let i = 0; i < 12; i++) vendor.push(`image/ProgramData/Package Cache/{${i}}/installer${i}.msi`);
  for (let i = 0; i < 10; i++) vendor.push(`image/Windows/System32/driverstore${i}.zip`);
  const runtime: string[] = [];
  for (let i = 0; i < 20; i++) runtime.push(`image/Users/alex/AppData/Local/Programs/Python/Python311/DLLs/_mod${i}.pyd`);
  for (let i = 0; i < 15; i++) runtime.push(`image/Users/alex/AppData/Local/Programs/Python/Python311/Lib/site-packages/pkg${i}/_core.pyd`);
  for (let i = 0; i < 10; i++) runtime.push(`image/Users/alex/AppData/Roaming/npm/node_modules/mod${i}/prebuilt.zip`);
  for (let i = 0; i < 5; i++) runtime.push(`image/Users/alex/AppData/Local/Microsoft/Edge/User Data/ext${i}.zip`);
  const profile: string[] = [
    ...["setup.exe", "install.ps1", "payload.zip", "helper.msi", "run.bat"].map((f) => `image/Users/alex/AppData/Local/Temp/${f}`),
    ...["invoice.docx", "archive.7z", "tools.zip", "report.pdf", "image.iso", "client.exe", "notes.txt", "data.xlsx", "keys.kdbx", "mail.eml"].map((f) => `image/Users/alex/Downloads/${f}`),
    ...["todo.docm", "budget.xlsm", "shortcut.lnk", "drop.zip"].map((f) => `image/Users/alex/Desktop/${f}`),
    ...["plan.docx", "contract.pdf", "backup.pst", "old.rar"].map((f) => `image/Users/alex/Documents/${f}`),
    ...["album.zip", "scan.pdf"].map((f) => `image/Users/alex/Pictures/${f}`),
    ...["shared.docx", "sync.zip"].map((f) => `image/Users/alex/OneDrive/${f}`),
    ...["memo.docx", "list.xlsx"].map((f) => `image/Users/Public/Documents/${f}`),
    ...["state.db", "cache.dat", "store.sqlite"].map((f) => `image/Users/alex/AppData/Roaming/notesapp/${f}`),
    "image/Users/alex/AppData/Roaming/updater/agent.exe",
    "image/PerfLogs/svc.exe",
  ];
  return { vendor, runtime, profile };
}

/**
 * The derived lane as it runs (job-service.ts maybeDrainDerived and the room check of fromDetect): one pass at a time over what
 * waits, each object taken a generation when there is room for its rank, until the ceiling. `arrivals` are the offers of the jobs
 * in the order they were committed; every pass the lane can make runs before the next job commits (the worst case: a vendor tree
 * committed first is drained whole before the profile is offered).
 */
function replayLane(arrivals: string[][]): { made: string[]; notRun: number } {
  const max = DERIVED_LIMITS.generationsMax;
  const reserve = Math.floor(max * DERIVED_RESERVE);
  const pending: Array<{ path: string; bytes: number; recipes: string[] }> = [];
  const made: string[] = [];
  let notRun = 0;
  for (const offer of arrivals) {
    // Vendor installers are the large objects of an image: largest first would put them first within a rank.
    offer.forEach((path, i) => pending.push({ path, bytes: (derivedRank(path) >= 1 ? 50_000_000 : 1_000_000) - i, recipes: ["computer-forensics-base/archive-members"] }));
    while (pending.length && made.length < max) {
      const { take } = derivedPass(pending, (c) => derivedRank(c.path), { made: made.length, max, reserve, pairsPerPass: DERIVED_LIMITS.pairsPerPass });
      if (!take.length) break;
      // As fromDetect asks: whether a user's object waits, once for the pass's answers.
      const userWaiting = pending.some((c) => derivedRank(c.path) < 1);
      for (const c of take) {
        if (derivedRoom(derivedRank(c.path), made.length, max, reserve, { userWaiting })) made.push(c.path);
        else notRun += 1;
      }
    }
  }
  return { made, notRun };
}

test("replayed on a synthetic Windows image whose vendor trees are committed before the profile, at least 30 of the lane's 50 generations are a user's objects", (t) => {
  const { vendor, runtime, profile } = windowsTree();
  const user = (p: string) => derivedRank(p) < 1;
  assert.ok(vendor.every((p) => !user(p)) && runtime.every((p) => !user(p)), "the vendor's and the runtime's objects are not a user's");
  assert.ok(profile.every(user), `every object of the profile is a user's: ${profile.filter((p) => !user(p)).join(", ")}`);
  // Executables outside the vendors' roots and the runtimes are with what a case turns on, wherever they sit.
  assert.equal(derivedRank("image/PerfLogs/svc.exe"), 0);
  assert.equal(derivedRank("image/Users/alex/AppData/Roaming/updater/agent.exe"), 0);
  assert.ok(profile.length >= 30 && vendor.length + runtime.length > 100);
  // As on the run E0: a prefix of Program Files committed first, a Python under the profile next, the profile last.
  const late = replayLane([vendor, runtime, profile]);
  assert.equal(late.made.length, DERIVED_LIMITS.generationsMax, "the lane reaches its ceiling");
  const userMade = late.made.filter(user).length;
  assert.ok(userMade >= 30, `${userMade} of ${late.made.length} generations went to a user's objects (vendor and runtime first)`);
  t.diagnostic(`vendor and runtime committed first: ${userMade} of ${late.made.length} generations a user's objects`);
  // Whatever the order, the same holds: the whole image at once, and the profile first.
  for (const order of [[[...vendor, ...runtime, ...profile]], [profile, vendor, runtime]]) {
    const r = replayLane(order);
    assert.ok(r.made.filter(user).length >= 30, `${r.made.filter(user).length} user objects of ${r.made.length}`);
  }
  // With a fifth kept, as before, the late profile got ten: the replay fails without the larger reserve.
  assert.ok(DERIVED_RESERVE >= 0.6);
});

test("kept room no user's object waits for is lent to the next rank, all but the floor, and taken back while a user's object waits; a vendor's objects are never lent it", () => {
  const max = DERIVED_LIMITS.generationsMax;
  const reserve = Math.floor(max * DERIVED_RESERVE);
  const floor = Math.floor(max * DERIVED_FLOOR);
  assert.deepEqual([max, reserve, floor], [50, 30, 10]);
  // derivedRoom, rank by rank, once only the kept part is left (made 20 of 50).
  assert.equal(derivedRoom(2, 20, max, reserve), false, "a vendor's object: never");
  assert.equal(derivedRoom(1, 20, max, reserve), true, "the next rank, on loan");
  assert.equal(derivedRoom(1, 20, max, reserve, { userWaiting: true }), false, "taken back while a user's object waits");
  assert.equal(derivedRoom(1, max - floor - 1, max, reserve), true);
  assert.equal(derivedRoom(1, max - floor, max, reserve), false, "the floor is never lent");
  assert.equal(derivedRoom(0, max - 1, max, reserve, { userWaiting: true }), true, "a user's object: up to the ceiling");
  assert.equal(derivedRoom(0, max, max, reserve), false);
  const rank1 = (p: string) => derivedRank(p) === 1;
  const user = (p: string) => derivedRank(p) < 1;
  // The re-review's case: twelve Program Files objects, then 27 under web roots and at the root. Kept room nobody used left 30
  // generations idle (20 made, 8 of them the web roots').
  const vendor = Array.from({ length: 12 }, (_, i) => `image/Program Files/V${i}/setup${i}.cab`);
  const web = [
    ...Array.from({ length: 15 }, (_, i) => `image/inetpub/wwwroot/app/upload/shell${i}.aspx.zip`),
    ...Array.from({ length: 10 }, (_, i) => `image/var/www/html/backup${i}.tar.gz`),
    "image/root/.bash_history.tar",
    "image/etc/cron.d/x.zip",
  ];
  assert.ok(web.every(rank1) && vendor.every((p) => derivedRank(p) === 2));
  const lent = replayLane([vendor, web]);
  assert.equal(lent.made.length, 39, "every object is catalogued: 12 vendor objects and 27 of the next rank");
  assert.equal(lent.made.filter(rank1).length, 27);
  // The next rank first and the profile after: the loan stops at the floor, which the late profile gets.
  const { profile } = windowsTree();
  const many = Array.from({ length: 60 }, (_, i) => `image/inetpub/wwwroot/site${i}/backup${i}.zip`);
  const late = replayLane([many, profile]);
  assert.equal(late.made.filter(rank1).length, max - floor, "the next rank takes all but the floor");
  assert.equal(late.made.filter(user).length, floor, "the late profile takes the floor");
  // Offered together: the user's objects first, and none of the kept part is lent while they wait.
  const together = replayLane([[...many, ...profile, ...vendor]]);
  assert.ok(together.made.filter(user).length >= 30, `${together.made.filter(user).length} user objects`);
  assert.equal(together.made.filter((p) => derivedRank(p) === 2).length, 0, "the vendor's objects come after both, and get nothing kept");
  // derivedPass: once only the kept part is left, a user's object waiting keeps the pass to the user's objects.
  const pending = [...many.slice(0, 5), ...profile.slice(0, 3)].map((path, i) => ({ path, bytes: 1000 - i, recipes: ["r"] }));
  const pass = derivedPass(pending, (c) => derivedRank(c.path), { made: 25, max, reserve, pairsPerPass: 32 });
  assert.deepEqual(pass.take.map((c) => c.path).sort(), profile.slice(0, 3).sort());
  assert.equal(pass.userOnly, true);
  const next = derivedPass(pending, (c) => derivedRank(c.path), { made: 28, max, reserve, pairsPerPass: 32 });
  assert.equal(next.take.length, 5, "with none waiting the next rank is lent the room");
  // The E0 criterion is unchanged by the loan: vendor and runtime first, the profile last, a user's objects get 30 of 50.
  const { vendor: v, runtime } = windowsTree();
  assert.ok(replayLane([v, runtime, profile]).made.filter(user).length >= 30);
});

test("a commit of 200,000 files tells its requester within 2 s, its files are offered from the manifest's index (the manifest itself unreadable), and a job committed meanwhile is told within 2 s", { timeout: 300_000 }, async (t) => {
  const S = sandbox();
  const N = 200_000;
  const sha = (i: number) => createHash("sha256").update(`synthetic ${i}`).digest("hex");
  let large = "";
  const seal: typeof sealTree = async (sandboxDir, staging, dest, job, attempt, given, opts) => {
    const real = await sealTree(sandboxDir, staging, dest, job, attempt, given, opts);
    if (job !== large) return real;
    const manifestPath = given ?? join(dest, "..", "manifest.json");
    // The tree the worker wrote, and 200,000 files of a profile's cache beside it in the manifest (none on disk: a file the
    // offer cannot open is read as empty, as one that vanished would be).
    const files = [...real.manifest.files];
    for (let i = 0; i < N; i++) {
      const path = `image/Users/u${i % 50}/AppData/Local/Cache/d${i % 997}/f${i}.bin`;
      files.push({ path, path_b64: Buffer.from(path).toString("base64"), bytes: 4096, sha256: sha(i), mode: "444" });
    }
    const manifest = { ...real.manifest, files, totals: { files: files.length, bytes: real.manifest.totals.bytes + N * 4096 } };
    const text = `${JSON.stringify(manifest)}\n`;
    chmodSync(manifestPath, 0o644);
    writeFileSync(manifestPath, text);
    const st = statSync(manifestPath);
    const manifestSha256 = createHash("sha256").update(text).digest("hex");
    await writeIndex(manifestPath, buildIndex(manifest, { sha256: manifestSha256, bytes: st.size, mtime_ms: st.mtimeMs }));
    // From here on nothing can read the manifest whole: what the offer reads is the index.
    chmodSync(manifestPath, 0);
    return { ...real, manifest, manifestSha256 };
  };
  const { svc, posts } = service(S, { packDirs: [CFB], derived: true, sealTree: seal });
  await svc.start();
  try {
    const command = "python3 -c \"import os,zipfile\nfor i in range(20): open(os.environ['OUT']+'/real%02d.bin'%i,'w').write('x'*100)\nwith zipfile.ZipFile(os.environ['OUT']+'/kept.zip','w') as z: z.writestr('m.txt','member '*50)\"";
    const a = ok(await svc.submit("a1", { kind: "command", command, inputs: [] }));
    large = a.job.id;
    const done = await until(svc, a.job.id, undefined, 120_000);
    assert.equal(done.outputs?.files, N + 21);
    // Timers in the hub's process while the offer reads 200,000 rows of the index.
    let late = 0;
    let last = performance.now();
    const timer = setInterval(() => {
      const now = performance.now();
      late = Math.max(late, now - last - 20);
      last = now;
    }, 20);
    try {
      await eventually(() => posts.some(([to, b]) => to === "a1" && b.startsWith(`Job ${a.job.id} `)), "the requester of the large job is told");
      const toldIn = (id: string) => {
        const lines = journal(S);
        const committed = lines.find((l) => l.type === "job_committed" && l.job === id)!;
        const told = lines.find((l) => l.type === "job_notified" && l.job === id)!;
        return Date.parse(told.at) - Date.parse(committed.at);
      };
      const aMs = toldIn(a.job.id);
      assert.ok(aMs < 2000, `the requester of ${N} files was told ${aMs} ms after the commit`);
      // A small job committed while the large one's files are being offered is told as soon.
      const b = ok(await svc.submit("a2", { kind: "command", command: "echo small > \"$OUT/small.txt\"", inputs: [] }));
      await until(svc, b.job.id);
      await eventually(() => journal(S).some((l) => l.type === "job_notified" && l.job === b.job.id), "the small job's requester is told");
      const bMs = toldIn(b.job.id);
      assert.ok(bMs < 2000, `the small job's requester was told ${bMs} ms after its commit`);
      await eventually(() => journal(S).some((l) => l.type === "derived_offered" && l.job === a.job.id), "the large job's files are offered, from the index", 240_000);
      const offered = journal(S).find((l) => l.type === "derived_offered" && l.job === a.job.id)!;
      assert.deepEqual((offered.offered as Array<{ path: string }>).map((o) => o.path), ["kept.zip"], "the one archive is offered, read from the index with the manifest unreadable");
      assert.equal(offered.filtered, N + 20, "every other file was held to the recipes' measure");
      t.diagnostic(`${N} files: told ${aMs} ms after the commit; a job committed meanwhile told ${bMs} ms after its own; a 20 ms timer at most ${Math.round(late)} ms late`);
      assert.ok(late < 500, `a 20 ms timer in the hub's process was ${Math.round(late)} ms late while the offer ran`);
    } finally {
      clearInterval(timer);
    }
  } finally {
    await svc.stop("over");
    if (large) spawnSync("chmod", ["-R", "u+rw", join(storePaths(S).jobs, large)]);
  }
});

// --- A11: the identical whole-object tool call is one job --------------------------------------------------

test("two identical whole-object tool calls a second apart are one worker run, both seats are told, and independent: true runs it again", async () => {
  const S = sandbox();
  const body = "import json,sys,os\nd=json.load(sys.stdin)\nopen(os.path.join(d['output'],'tree.txt'),'w').write('the whole image')\n";
  tool(S, "extract_all", body, { output: { type: "string", required: true }, members: { type: "array" } });
  const runs: string[] = [];
  const real = localWorker();
  const { svc, posts } = service(S, {
    runWorker: async (spec: WorkerSpec) => {
      runs.push(spec.job ?? "");
      await sleep(1800);
      return real(spec);
    },
  });
  await svc.start();
  const call = { kind: "tool" as const, tool: "extract_all", args: { output: "{OUT}" }, inputs: ["input:image.bin"] };
  const first = ok(await svc.submit("a2", call));
  assert.equal(first.joined, undefined);
  await sleep(1000);
  const second = ok(await svc.submit("a3", { ...call, timeout_seconds: 900 }));
  assert.equal(second.job.id, first.job.id, "answered with the job under way");
  assert.deepEqual([second.joined?.job, second.joined?.state, second.joined?.requester], [first.job.id, "running", "a2"]);
  assert.match(second.joined?.note ?? "", new RegExp(`^Not run again: a2-name \\(a2\\) asked for the same call .* as job ${first.job.id}, which is running; you are told when it is done`));
  const done = await until(svc, first.job.id);
  assert.equal(done.status, "ok");
  await eventually(() => ["a2", "a3"].every((seat) => posts.some(([to, b]) => to === seat && b.startsWith(`Job ${first.job.id} (tool extract_all) done`))), `both are told: ${JSON.stringify(posts)}`);
  assert.deepEqual(runs, [first.job.id], "one worker run");
  const lines = journal(S);
  assert.equal(lines.filter((l) => l.type === "job_accepted").length, 1);
  const joined = lines.find((l) => l.type === "job_deduplicated")!;
  assert.deepEqual([joined.job, (joined.by as { agent: string }).agent, joined.kind, joined.notify], [first.job.id, "a3", "tool", true]);
  // Once it is committed the same call is answered with it, and nobody waits for a post.
  const third = ok(await svc.submit("a4", call));
  assert.deepEqual([third.job.id, third.joined?.state], [first.job.id, "committed"]);
  assert.match(third.joined?.note ?? "", /which is committed \(1 file\(s\) in store\/jobs\/j000001\/out\/\)/);
  // A second run when that is the point.
  const again = ok(await svc.submit("a3", { ...call, independent: true }));
  assert.notEqual(again.job.id, first.job.id);
  assert.equal(again.joined, undefined);
  assert.ok(again.similar?.some((x) => x.job === first.job.id && x.match === "same tool and arguments"), "the hint is still given");
  // Other arguments, other objects, or members named: its own job.
  const members = ok(await svc.submit("a4", { ...call, args: { output: "{OUT}", members: ["Users/x/a.txt"] } }));
  const membersAgain = ok(await svc.submit("a5", { ...call, args: { output: "{OUT}", members: ["Users/x/a.txt"] } }));
  assert.ok(members.joined === undefined && membersAgain.joined === undefined && members.job.id !== membersAgain.job.id, "a call that names members is its seat's own");
  for (const j of [again, members, membersAgain]) await until(svc, j.job.id);
  assert.equal(runs.length, 4);
  await svc.stop("over");
  // A restart keeps who else is to be told of a job still under way (the job_deduplicated line).
  assert.equal(journal(S).filter((l) => l.type === "job_deduplicated").length, 2);
});

// --- A13: same_as is a count, the bytes and a side file ----------------------------------------------------

test("a commit of 5,000 files an earlier job had written adds under 4 KB to the journal: a count, the bytes and a side file", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const write = "python3 -c \"import os\nfor i in range(5000):\n  d=os.environ['OUT']+'/Users/someone/AppData/Local/a-long-directory-name/%02d'%(i%50); os.makedirs(d,exist_ok=True); open(d+'/file-%05d.dat'%i,'w').write('content %05d'%i)\"";
  const first = ok(await svc.submit("a1", { kind: "command", command: write, inputs: [] }));
  await until(svc, first.job.id, undefined, 120000);
  const sizeBefore = statSync(storePaths(S).journal).size;
  const second = ok(await svc.submit("a2", { kind: "command", command: `${write} ; true`, inputs: [] }));
  const done = await until(svc, second.job.id, undefined, 120000);
  await eventually(() => journal(S).some((l) => l.type === "job_same_as" && l.job === second.job.id), "the job_same_as line");
  await eventually(() => journal(S).some((l) => l.type === "job_notified" && l.job === second.job.id), "the requester told");
  const lines = journal(S);
  const text = readFileSync(storePaths(S).journal, "utf8").split("\n");
  const mine = lines.filter((l) => l.job === second.job.id && l.seq >= lines.find((x) => x.type === "job_committed" && x.job === second.job.id)!.seq);
  const added = mine.reduce((n, l) => n + Buffer.byteLength(text[l.seq]) + 1, 0);
  assert.ok(added < 4096, `its commit, its same_as and its notice are ${added} bytes of journal`);
  assert.ok(statSync(storePaths(S).journal).size - sizeBefore < 8192, "the whole job, accepted to told, under 8 KB");
  const line = lines.find((l) => l.type === "job_same_as" && l.job === second.job.id)!;
  assert.deepEqual([line.files, line.bytes, line.list], [5000, 5000 * 13, `store/jobs/${second.job.id}/same_as.jsonl`]);
  assert.deepEqual(line.jobs, [{ job: first.job.id, files: 5000, bytes: 5000 * 13 }]);
  const side = readFileSync(join(S, String(line.list)), "utf8");
  assert.equal(createHash("sha256").update(side).digest("hex"), line.list_sha256, "the side file is held to the line");
  const rows = side.trim().split("\n").map((x) => JSON.parse(x) as Record<string, unknown>);
  assert.deepEqual(rows[0], { v: 1, job: second.job.id, files: 5000, bytes: 5000 * 13 });
  assert.equal(rows.length, 5001, "every one is in the side file");
  assert.equal(rows[1].job, first.job.id);
  // The record and what a seat is shown carry the first few and the count.
  assert.ok((done.same_as?.length ?? 0) <= 20);
  assert.equal(done.same_as_total?.files, 5000);
  assert.ok(statSync(join(storePaths(S).jobs, second.job.id, "job.json")).size < 16384, "job.json does not grow with the tree");
  const view = await jobView(S, done);
  assert.equal((view.same_as as unknown[]).length, 20);
  assert.equal(view.same_as_more, `4980 more (65000 bytes in all 5000), every one in store/jobs/${second.job.id}/same_as.jsonl`);
  assert.match(describe(done), /5000 of its files are an earlier job's output byte for byte/);
  await svc.stop("over");
  const again = service(S).svc;
  await again.start();
  assert.deepEqual(again.jobs.get(second.job.id)?.same_as_total, done.same_as_total, "read back from the line");
  await again.stop("over");
});

// --- A14: three times, the limit from outside, the slot of a worker not gone --------------------------------

test("job_finished says when the command ended, when the worker was gone and when the service went on", async () => {
  const S = sandbox();
  const real = localWorker();
  const gone = new Date(Date.now() + 1234).toISOString();
  const { svc } = service(S, { runWorker: async (spec) => ({ ...(await real(spec)), gone_at: gone }) });
  await svc.start();
  const before = Date.now();
  const r = ok(await svc.submit("a1", { kind: "command", command: "true", inputs: [] }));
  const done = await until(svc, r.job.id);
  const line = journal(S).find((l) => l.type === "job_finished" && l.job === r.job.id)!;
  const [ended, noticed] = [Date.parse(String(line.command_ended_at)), Date.parse(String(line.noticed_at))];
  assert.ok(ended >= before - 2000 && ended <= noticed + 1000, `the command ended (${line.command_ended_at}) before the service went on (${line.noticed_at})`);
  assert.equal(line.worker_gone_at, gone, "the worker's going as its caller reports it");
  assert.ok(noticed <= Date.parse(line.at), "and the line is written after");
  assert.deepEqual([done.command_ended_at, done.worker_gone_at], [line.command_ended_at, gone]);
  await svc.stop("over");
});

test("a job is held to its limit from outside its worker: one whose command ended and whose worker stays up, and one that reports nothing past its limit", async () => {
  const S = sandbox();
  const asked: string[] = [];
  // A worker that never returns: it writes what the job's script would, when it is told to.
  const hanging = (exit: string | null) => async (spec: WorkerSpec) => {
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!.host;
    writeFileSync(join(out, "made"), "made");
    if (exit !== null) writeFileSync(join(ctl, "exit"), `${exit}\n`);
    return new Promise<never>(() => undefined);
  };
  let how = hanging("0");
  const { svc } = service(S, {
    runWorker: ((spec: WorkerSpec) => how(spec)) as JobServiceOptions["runWorker"],
    destroyWorker: async (w) => {
      asked.push(w);
      return { ok: true };
    },
    timing: { watchMs: 20, exitGraceMs: 300, pastLimitMs: 400, fenceRetryMs: 50 },
  });
  await svc.start();
  // Its command ended at once; the worker never goes by itself.
  const started = Date.now();
  const ended = ok(await svc.submit("a1", { kind: "command", command: "true", inputs: [], timeout_seconds: 600 }));
  const e = await until(svc, ended.job.id);
  assert.ok(Date.now() - started < 3000, `finished and sealed ${Date.now() - started} ms after it began, not at its limit of 600 s`);
  assert.deepEqual([e.status, e.exit], ["ok", 0], "its own exit status stands");
  const lines = () => journal(S);
  const fin = lines().find((l) => l.type === "job_finished" && l.job === ended.job.id)!;
  assert.match(String(fin.overdue), /^its command had ended and its worker was still up \d+s later$/);
  assert.equal(fin.worker_gone_at, null, "not gone when job_finished was written");
  const fences = lines().filter((l) => l.type === "job_fenced" && l.job === ended.job.id);
  assert.deepEqual(fences.map((l) => [l.fenced, l.late ?? false]), [[false, false], [true, true]], "asked to go by the service, and sealed only once it was");
  assert.match(String(fences[0].error), /the job service asked it to go$/);
  assert.equal(asked.length, 1);
  assert.equal(readFileSync(join(storePaths(S).jobs, ended.job.id, "out", "made"), "utf8"), "made");
  // It reports nothing: job_finished comes at its limit plus the service's own margin, whatever the worker does.
  how = hanging(null);
  const t0 = Date.now();
  // Ten seconds is the shortest limit a job may have.
  const silent = ok(await svc.submit("a1", { kind: "command", command: "true", inputs: [], timeout_seconds: 10 }));
  const s = await until(svc, silent.job.id);
  const fin2 = lines().find((l) => l.type === "job_finished" && l.job === silent.job.id)!;
  const took = Date.parse(fin2.at) - t0;
  assert.ok(took >= 10400 && took < 10400 + 1300, `job_finished ${took} ms after it was asked for: its limit of 10 s, the margin of 0.4 s, and no more than the watch`);
  assert.deepEqual([s.status, s.exit], ["timed_out", null]);
  assert.match(s.reason ?? "", /^stopped at its limit of 10s by the job service: its worker had reported nothing \d+s past it$/);
  await svc.stop("over");
});

test("a worker not confirmed gone keeps its slot: the next job starts only once it is, and nothing of the first is read before", async () => {
  const S = sandbox();
  let gone = false;
  let asks = 0;
  const { svc, posts } = service(S, {
    workers: 1,
    runWorker: localWorker([], { fenced: () => false }),
    destroyWorker: async () => {
      asks += 1;
      return gone ? { ok: true } : { ok: false, error: "could not list processes to find the maker of dfs-s000000-job-j000001-1" };
    },
    timing: { fenceRetryMs: 40 },
  });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command: "printf a > \"$OUT/a\"", inputs: [] }));
  const b = ok(await svc.submit("a2", { kind: "command", command: "printf b > \"$OUT/b\"", inputs: [] }));
  await until(svc, a.job.id, ["finished"]);
  await sleep(400);
  assert.equal(svc.jobs.get(a.job.id)!.state, "finished", "not sealed while its worker may be up");
  assert.equal(svc.jobs.get(b.job.id)!.state, "accepted", "and the only slot is not given to the next job");
  assert.ok(asks >= 3, `asked again while it holds the slot (${asks} times)`);
  assert.match(svc.waitWords(svc.jobs.get(a.job.id)!) ?? "", /Its worker VM is not yet confirmed gone/);
  assert.ok(!existsSync(join(storePaths(S).jobs, a.job.id, "out")));
  gone = true;
  assert.equal((await until(svc, a.job.id)).status, "ok");
  assert.equal((await until(svc, b.job.id)).status, "ok");
  const lines = journal(S);
  const lateFence = lines.find((l) => l.type === "job_fenced" && l.job === a.job.id && l.fenced === true)!;
  const startedB = lines.find((l) => l.type === "job_started" && l.job === b.job.id)!;
  assert.ok(lateFence.late === true && lateFence.seq < startedB.seq, "the next job started after the worker was confirmed gone");
  assert.ok(!posts.some(([, body]) => body.startsWith("Tool jobs are not running")));
  await svc.stop("over");
});

// --- G3: a stop -----------------------------------------------------------------------------------------------

test("a stop of the run takes the workers away and nobody is told jobs do not run; what never started is cancelled on the record", async () => {
  const S = sandbox();
  let holding = false;
  const release: Array<() => void> = [];
  const { svc, posts } = service(S, {
    workers: 3,
    perRequesterRunning: 3,
    holding: () => holding,
    // Three workers removed from outside, as swarm.sh stop does: each run ends with no exit status.
    runWorker: async () => {
      await new Promise<void>((res) => release.push(res));
      return { code: null, error: "the worker was removed", fenced: true };
    },
  });
  await svc.start();
  const ids: string[] = [];
  // Short jobs: with three workers one is kept for those, and a longer job takes only the other two.
  for (let i = 0; i < 5; i += 1) ids.push(ok(await svc.submit("a1", { kind: "command", command: "true", inputs: [], timeout_seconds: 60 })).job.id);
  await eventually(() => release.length === 3, "three run");
  holding = true;
  for (const go of release) go();
  for (const id of ids.slice(0, 3)) assert.equal((await until(svc, id)).status, "stopped");
  assert.match(svc.jobs.get(ids[0])!.reason ?? "", /^stopped: the run was stopping and its worker was removed$/);
  await sleep(100);
  assert.ok(!posts.some(([, body]) => body.startsWith("Tool jobs are not running")), `nothing is said of workers during a stop: ${JSON.stringify(posts)}`);
  assert.ok(!journal(S).some((l) => l.type === "jobs_degraded"));
  assert.deepEqual(ids.slice(3).map((id) => svc.jobs.get(id)!.state), ["accepted", "accepted"], "no worker is started behind the stop");
  await svc.stop("the run is stopping");
  const lines = journal(S);
  for (const id of ids.slice(3)) assert.ok(lines.some((l) => l.type === "job_cancelled" && l.job === id && l.reason === "the run is stopping"), `${id} is cancelled on the record`);
  assert.ok(![...svc.jobs.values()].some((j) => j.state === "accepted"), "nothing is left accepted");
});

test("the seal after the run cancels what the hub left queued: a hub that died before its own stop leaves no job accepted for ever", async () => {
  const S = sandbox();
  // No worker at all: everything asked for stays queued, and the service is never stopped (the hub died).
  const { svc } = service(S, { workers: 0 });
  await svc.start();
  const a = ok(await svc.submit("a1", { kind: "command", command: "true", inputs: [] }));
  const b = ok(await svc.submit("a2", { kind: "command", command: "true", inputs: [] }));
  writeFileSync(join(S, "hub.pid"), "999999999\n");
  const out = await sealLeftStaging(S, async () => ({ ok: true }));
  assert.deepEqual(out, { sealed: [], left: [] });
  const lines = journal(S);
  for (const j of [a, b]) {
    const mine = lines.filter((l) => l.job === j.job.id).map((l) => l.type);
    assert.deepEqual(mine, ["job_accepted", "job_cancelled"]);
    assert.equal(JSON.parse(readFileSync(join(storePaths(S).jobs, j.job.id, "job.json"), "utf8")).state, "cancelled");
  }
  assert.equal(lines.find((l) => l.type === "job_cancelled")!.reason, "the run was stopped before it started");
  // Once: a second pass finds nothing accepted.
  await sealLeftStaging(S, async () => ({ ok: true }));
  assert.equal(journal(S).filter((l) => l.type === "job_cancelled").length, 2);
});
