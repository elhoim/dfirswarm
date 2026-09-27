/**
 * A job's declared scope, enforced: the three scopes kept apart (left out,
 * all, a list), a declared job's worker given a view of what it named and
 * nothing beside it (the stand-in worker lays the guest out from the mounts
 * alone), segment sets expanded from the census's record, a work file
 * snapshotted and hashed at the start, links and traversal refused, the
 * binding checked again after the VM is made, and the broad view of a job
 * that declared nothing unchanged.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { JobService, type JobServiceOptions } from "../scripts/job-service.ts";
import { buildView, declaredScope, locate, resolveScope, SCOPE_DECLARED_MAX } from "../scripts/job-scope.ts";
import { checkStore, initStore, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { holdWorkerMounts, recheckWorkerMounts, type WorkerSpec } from "../scripts/vm.ts";
import { listInputs, localWorker, mountedWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "scope-")), "run");
  for (const d of ["inputs/case", "tools", "catalog", "work/a1", "work/a2", "tool-output/a1", "ledger"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "case", "disk.E01"), "E01-segment-one");
  writeFileSync(join(S, "inputs", "case", "disk.E02"), "E02-segment-two");
  writeFileSync(join(S, "inputs", "case", "memory.raw"), "a sibling nobody declared");
  writeFileSync(join(S, "inputs", "notes.txt"), "the operator's notes");
  writeFileSync(join(S, "work", "a1", "parse.py"), "print(open('inputs/case/disk.E01').read())\n");
  writeFileSync(join(S, "work", "a2", "secret.txt"), "a peer's live scratch");
  writeFileSync(join(S, "ledger", "entries.jsonl"), "");
  listInputs(S);
  return S;
}

/** The census's record of the evidence's one segment set, in the store as the kickoff leaves it. */
async function censused(S: string): Promise<void> {
  writeFileSync(join(S, "catalog", "plan.json"), JSON.stringify({ recipes: [], collections: [{ input: "inputs/case/disk.E01", members: ["inputs/case/disk.E01", "inputs/case/disk.E02"] }] }));
  await initStore(S);
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const specs: WorkerSpec[] = [];
  const svc = new JobService({
    sandbox: S,
    run: "s000000",
    image: "img:test",
    workers: 2,
    workerCpus: 1,
    workerMemoryMib: 512,
    allowHosts: [],
    openNet: false,
    packDirs: [CFB],
    forging: true,
    minFreeMb: 1,
    runWorker: mountedWorker(specs),
    destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined,
    identity: async (agent) => ({ name: agent }),
    ...extra,
  });
  return { svc, specs };
}

async function until(svc: JobService, id: string, ms = 20000) {
  const end = Date.now() + ms;
  for (;;) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    if (Date.now() > end) throw new Error(`job ${id} is ${j?.state} after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

function journal(S: string) {
  return verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
}

function stdout(S: string, id: string): string {
  return readFileSync(join(storePaths(S).jobs, id, "stdout.log"), "utf8");
}

test("the three scopes are kept apart: left out, all said, and a list (an empty one too), in the spec and on the journal", async () => {
  assert.deepEqual(declaredScope(undefined), { kind: "default-all", inputs: [] });
  assert.deepEqual(declaredScope(["all"]), { kind: "all", inputs: ["all"] });
  assert.deepEqual(declaredScope([]), { kind: "declared", inputs: [] });
  assert.match(String((declaredScope(["all", "input:x"]) as { reason: string }).reason), /all stands alone/);
  assert.match(String((declaredScope(Array.from({ length: SCOPE_DECLARED_MAX + 1 }, (_, i) => `input:${i}`)) as { reason: string }).reason), /more than 256/, "never cut to fit: refused, with what to do");
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const left = await svc.submit("a1", { kind: "command", command: "true" });
  const all = await svc.submit("a1", { kind: "command", command: "true", inputs: ["all"] });
  const none = await svc.submit("a1", { kind: "command", command: "ls inputs 2>&1; echo end" , inputs: [] });
  assert.ok(left.ok && all.ok && none.ok);
  for (const r of [left, all, none]) await until(svc, r.ok ? r.job.id : "");
  const lines = journal(S);
  const accepted = (id: string) => lines.find((l) => l.type === "job_accepted" && l.job === id)!.spec as { scope: string; inputs: string[] };
  const started = (id: string) => lines.find((l) => l.type === "job_started" && l.job === id)!;
  assert.deepEqual([accepted(left.ok ? left.job.id : "").scope, accepted(all.ok ? all.job.id : "").scope, accepted(none.ok ? none.job.id : "").scope], ["default-all", "all", "declared"]);
  assert.deepEqual([(started(left.ok ? left.job.id : "").scope as { kind: string }).kind, (started(all.ok ? all.job.id : "").scope as { kind: string }).kind, (started(none.ok ? none.job.id : "").scope as { kind: string }).kind], ["default-all", "all", "declared"]);
  // An empty declaration is a scope of nothing: no evidence at all.
  assert.match(stdout(S, none.ok ? none.job.id : ""), /No such file or directory[\s\S]*end/);
  await svc.stop("over");
});

test("a declared job sees what it named and nothing beside it: no undeclared input, no sibling, no peer's scratch, no ledger", async () => {
  const S = sandbox();
  await censused(S);
  const { svc, specs } = service(S);
  await svc.start();
  const r = await svc.submit("a1", {
    kind: "command",
    command: "ls inputs inputs/case; cat inputs/case/disk.E01; echo; cat inputs/case/memory.raw 2>&1; cat inputs/notes.txt 2>&1; cat work/a2/secret.txt 2>&1; ls ledger 2>&1; python3 work/a1/parse.py",
    inputs: ["input:case/disk.E01", "work/a1/parse.py"],
  });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.equal(job.state, "committed", job.reason);
  const out = stdout(S, job.id);
  assert.match(out, /^inputs:\ncase\n\ninputs\/case:\ndisk\.E01\ndisk\.E02\n/, `only the declared file and the rest of its set, as recorded: ${out}`);
  assert.match(out, /E01-segment-one/);
  assert.match(out, /memory\.raw: No such file/, "a sibling in the same directory is not there");
  assert.match(out, /notes\.txt: No such file/, "an undeclared input is not there");
  assert.match(out, /secret\.txt: No such file/, "a peer's scratch is not there");
  assert.match(out, /ledger: No such file/);
  // The worker's mounts: the view at the run's path, nothing of the run's own directories.
  const mounts = specs.at(-1)!.mounts;
  assert.ok(mounts.some((m) => m.guest === S && m.view && m.readonly && m.host.includes(".staging/")), JSON.stringify(mounts));
  for (const bare of ["inputs", "store", "catalog", "work", "tool-output"]) assert.ok(!mounts.some((m) => m.host === join(S, bare)), `no broad mount of ${bare}/`);
  await svc.stop("over");
});

test("a segment set is expanded from the census's record, and declared, expanded and accessible are recorded apart", async () => {
  const S = sandbox();
  await censused(S);
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "ls inputs/case", inputs: ["input:case/disk.E01"] });
  assert.ok(r.ok);
  const job = await until(svc, r.job.id);
  assert.equal(stdout(S, job.id), "disk.E01\ndisk.E02\n");
  const started = journal(S).find((l) => l.type === "job_started" && l.job === job.id)!;
  const scope = started.scope as { kind: string; manifest: string; manifest_sha256: string; objects: number };
  assert.equal(scope.kind, "declared");
  const text = readFileSync(join(S, scope.manifest), "utf8");
  assert.equal(createHash("sha256").update(text).digest("hex"), scope.manifest_sha256, "the manifest is held to its hash on the journal");
  const m = JSON.parse(text);
  assert.deepEqual(m.declared, ["input:case/disk.E01"]);
  const e02 = m.expanded.find((x: { path: string }) => x.path === "inputs/case/disk.E02");
  assert.match(e02.from, /the set of input:case\/disk\.E01, as the census recorded it/);
  assert.equal(e02.sha256, createHash("sha256").update("E02-segment-two").digest("hex"));
  assert.deepEqual(m.accessible.map((a: { path: string }) => a.path).sort(), ["inputs/case/disk.E01", "inputs/case/disk.E02"]);
  assert.equal(m.observed, "not observed: the reads within this scope are not recorded");
  // Custody: the job's scope, its manifest verified.
  const st = await checkStore(S);
  assert.deepEqual(st?.access?.scopes, { declared: 1, all: 0, default_all: 0 });
  assert.equal(st?.access?.manifests?.verified, 1);
  await svc.stop("over");
});

test("the census's record of every segment set reaches the store, and a declaration that does not resolve refuses the job with the reason", async () => {
  const S = sandbox();
  await censused(S);
  const { Journal } = await import("../scripts/evidence-store.ts");
  const j = await Journal.open(S);
  assert.deepEqual(j.of("input_collection").map((l) => l.members), [["inputs/case/disk.E01", "inputs/case/disk.E02"]]);
  const { svc } = service(S);
  await svc.start();
  for (const [bad, why] of [
    ["input:case/nothing.E01", /not in inputs\.json/],
    ["job:j999999", /no sealed output/],
    ["work/a1/missing.py", /does not exist/],
    ["work/../inputs.json", /no empty, \. or \.\. part/],
    ["input:../etc/passwd", /no empty, \. or \.\. part/],
    ["/etc/passwd", /from the run's directory/],
    ["ledger/entries.jsonl", /a job reads/],
  ] as const) {
    const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [bad] });
    assert.equal(r.ok, false, bad);
    assert.match(!r.ok ? r.reason : "", why, bad);
    assert.match(!r.ok ? r.reason : "", /A job reads only what it declares/, "and what to declare instead");
  }
  assert.equal(journal(S).filter((l) => l.type === "job_accepted").length, 0, "no broad fallback: nothing accepted");
  await svc.stop("over");
});

test("a work file is snapshotted and hashed at the start: the job reads what it was, while the live file changes", async () => {
  const S = sandbox();
  const live = join(S, "work", "a1", "notes.txt");
  writeFileSync(live, "as it was when the job started");
  const inner = mountedWorker();
  const { svc } = service(S, {
    runWorker: async (spec) => {
      // The agent goes on writing while the job runs.
      writeFileSync(live, "changed while the job ran");
      return inner(spec);
    },
  });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "cat work/a1/notes.txt", inputs: ["work/a1/notes.txt"] });
  assert.ok(r.ok);
  const job = await until(svc, r.job.id);
  assert.equal(stdout(S, job.id), "as it was when the job started");
  assert.equal(readFileSync(live, "utf8"), "changed while the job ran");
  const m = JSON.parse(readFileSync(join(storePaths(S).jobs, job.id, "scope.1.json"), "utf8"));
  const e = m.accessible.find((x: { path: string }) => x.path === "work/a1/notes.txt");
  assert.equal(e.sha256, createHash("sha256").update("as it was when the job started").digest("hex"));
  assert.equal(e.hashed, "at the job's start");
  assert.ok(e.how === "clone" || e.how === "copy", `a clone or a copy, never a link: ${e.how}`);
  await svc.stop("over");
});

test("links are refused: a declared link, a link on the way, and none is ever followed out of the run", async () => {
  const S = sandbox();
  const outside = mkdtempSync(join(tmpdir(), "outside-"));
  writeFileSync(join(outside, "id_rsa"), "not the run's");
  symlinkSync(join(outside, "id_rsa"), join(S, "work", "a1", "key"));
  symlinkSync(outside, join(S, "work", "a1", "sub"));
  const { svc } = service(S);
  await svc.start();
  const link = await svc.submit("a1", { kind: "command", command: "true", inputs: ["work/a1/key"] });
  assert.equal(link.ok, false);
  assert.match(!link.ok ? link.reason : "", /is a link/);
  const via = await svc.submit("a1", { kind: "command", command: "true", inputs: ["work/a1/sub/id_rsa"] });
  assert.equal(via.ok, false);
  assert.match(!via.ok ? via.reason : "", /a link on the way/);
  // A declared directory: the link inside is named and left out, never followed.
  const dir = await svc.submit("a1", { kind: "command", command: "ls work/a1", inputs: ["work/a1/"] });
  assert.ok(dir.ok);
  const job = await until(svc, dir.job.id);
  assert.equal(stdout(S, job.id), "parse.py\n");
  const m = JSON.parse(readFileSync(join(storePaths(S).jobs, job.id, "scope.1.json"), "utf8"));
  assert.deepEqual(m.accessible.filter((e: { left_out?: string }) => e.left_out).map((e: { path: string; left_out: string }) => `${e.path}: ${e.left_out}`).sort(), ["work/a1/key: a link", "work/a1/sub: a link"]);
  await svc.stop("over");
});

test("a declared directory of the evidence and a job's whole output are bound as they are; a single store file is given alone", async () => {
  const S = sandbox();
  const { svc, specs } = service(S);
  await svc.start();
  const maker = await svc.submit("a1", { kind: "command", command: 'printf one > "$OUT/one.txt"; printf two > "$OUT/two.txt"', inputs: [] });
  assert.ok(maker.ok);
  const made = await until(svc, maker.job.id);
  const whole = await svc.submit("a1", { kind: "command", command: "ls inputs/case; ls store/jobs/*/out", inputs: ["input:case/", `job:${made.id}`] });
  assert.ok(whole.ok, !whole.ok ? whole.reason : "");
  const w = await until(svc, whole.job.id);
  assert.equal(stdout(S, w.id), "disk.E01\ndisk.E02\nmemory.raw\none.txt\ntwo.txt\n");
  const binds = specs.at(-1)!.mounts.filter((m) => m.expect && !m.view);
  assert.deepEqual(binds.map((m) => m.guest).sort(), [join(S, "inputs", "case"), join(S, "store", "jobs", made.id, "out")].sort());
  assert.ok(binds.every((m) => m.readonly), "read-only");
  assert.equal(binds.find((m) => m.guest === join(S, "inputs", "case"))?.noexec, true, "the evidence no-exec");
  assert.equal(binds.find((m) => m.guest === join(S, "inputs", "case"))?.host, realpathSync(join(S, "inputs", "case")));
  const one = await svc.submit("a1", { kind: "command", command: "ls store/jobs/*/out", inputs: [`job:${made.id}/one.txt`] });
  assert.ok(one.ok);
  assert.equal(stdout(S, (await until(svc, one.job.id)).id), "one.txt\n", "its sibling in the same output is not there");
  await svc.stop("over");
});

test("a scope that covers a whole evidence set binds the set as it is: one image and its segments, alone or as one of several sets", async () => {
  // One set: inputs/ holds the image's two segments and nothing else.
  const S = join(mkdtempSync(join(tmpdir(), "scope-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "disk.E01"), "E01-segment-one");
  writeFileSync(join(S, "inputs", "disk.E02"), "E02-segment-two");
  listInputs(S);
  writeFileSync(join(S, "catalog", "plan.json"), JSON.stringify({ recipes: [], collections: [{ input: "inputs/disk.E01", members: ["inputs/disk.E01", "inputs/disk.E02"] }] }));
  await initStore(S);
  const { svc, specs } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "ls inputs; cat inputs/disk.E02", inputs: ["input:disk.E01"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const job = await until(svc, r.job.id);
  assert.equal(stdout(S, job.id), "disk.E01\ndisk.E02\nE02-segment-two");
  const bound = specs.at(-1)!.mounts.find((m) => m.guest === join(S, "inputs"))!;
  assert.equal(bound.host, realpathSync(join(S, "inputs")), "the set's own directory, bound, not a view of copies");
  assert.ok(bound.readonly && bound.noexec && bound.expect && !bound.view);
  const m = JSON.parse(readFileSync(join(storePaths(S).jobs, job.id, "scope.1.json"), "utf8"));
  assert.deepEqual(m.accessible.map((e: { path: string; how: string }) => `${e.path} ${e.how}`), ["inputs/ bound"]);
  assert.match(m.accessible[0].why, /every file of the evidence set inputs\/ is in the scope \(2 file\(s\)\): bound whole/);
  assert.deepEqual(m.expanded.map((x: { path: string }) => x.path), ["inputs/disk.E01", "inputs/disk.E02"], "what the declaration resolved to stays file by file");
  await svc.stop("over");
  // Several sets held in place: the laptop's set is bound where its link leads, the phone's is not given.
  const S2 = join(mkdtempSync(join(tmpdir(), "scope-")), "run");
  const ev = mkdtempSync(join(tmpdir(), "sets-"));
  for (const d of ["laptop", "phone"]) mkdirSync(join(ev, d));
  writeFileSync(join(ev, "laptop", "disk.E01"), "the laptop");
  writeFileSync(join(ev, "phone", "sms.db"), "the phone");
  for (const d of ["inputs", "tools", "catalog"]) mkdirSync(join(S2, d), { recursive: true });
  symlinkSync(join(ev, "laptop"), join(S2, "inputs", "laptop"));
  symlinkSync(join(ev, "phone"), join(S2, "inputs", "phone"));
  const sha = (s: string) => createHash("sha256").update(s).digest("hex");
  writeFileSync(join(S2, "inputs.json"), JSON.stringify({ sets: [{ name: "laptop" }, { name: "phone" }], files: [{ path: "inputs/laptop/disk.E01", bytes: 10, sha256: sha("the laptop") }, { path: "inputs/phone/sms.db", bytes: 9, sha256: sha("the phone") }] }));
  const two = service(S2);
  await two.svc.start();
  const r2 = await two.svc.submit("a1", { kind: "command", command: "ls inputs; cat inputs/laptop/disk.E01; cat inputs/phone/sms.db 2>&1", inputs: ["input:laptop/disk.E01"] });
  assert.ok(r2.ok, !r2.ok ? r2.reason : "");
  const j2 = await until(two.svc, r2.job.id);
  assert.match(stdout(S2, j2.id), /^laptop\nthe laptop.*sms\.db: No such file/s);
  const laptop = two.specs.at(-1)!.mounts.find((m) => m.guest === join(S2, "inputs", "laptop"))!;
  assert.equal(laptop.host, realpathSync(join(ev, "laptop")));
  assert.ok(!two.specs.at(-1)!.mounts.some((m) => m.host === realpathSync(join(ev, "phone"))), "the other set is not given");
  const m2 = JSON.parse(readFileSync(join(storePaths(S2).jobs, j2.id, "scope.1.json"), "utf8"));
  assert.match(m2.accessible[0].why, /every file of the evidence set inputs\/laptop\/ is in the scope/);
  await two.svc.stop("over");
});

test("a scope that covers part of a set is given file by file: nothing beside it is bound, each file cloned or taken from the run's one copy", async () => {
  const S = sandbox();
  await censused(S);
  const { svc, specs } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "ls inputs/case", inputs: ["input:case/disk.E01"] });
  assert.ok(r.ok);
  const job = await until(svc, r.job.id);
  assert.equal(stdout(S, job.id), "disk.E01\ndisk.E02\n", "memory.raw beside them is not shown");
  assert.ok(!specs.at(-1)!.mounts.some((m) => m.host === realpathSync(join(S, "inputs", "case")) || m.host === realpathSync(join(S, "inputs"))), "no evidence directory bound");
  const m = JSON.parse(readFileSync(join(storePaths(S).jobs, job.id, "scope.1.json"), "utf8"));
  for (const e of m.accessible) assert.ok(e.how === "clone" || e.how === "the run's copy, linked", `${e.path}: ${e.how}`);
  await svc.stop("over");
});

test("the kickoff's recipes take the same rule: a set that is all their target is bound, and they run in their target's scope", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "scope-")), "run");
  for (const d of ["inputs", "tools", "catalog"]) mkdirSync(join(S, d), { recursive: true });
  spawnSync("python3", ["-c", "import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1],'w') as z: z.writestr('x.txt','x'*100)", join(S, "inputs", "a.zip")]);
  listInputs(S);
  writeFileSync(join(S, "catalog", "plan.json"), JSON.stringify({ recipes: [{ input: "inputs/a.zip", recipe: "computer-forensics-base/archive-members", target: { paths: [join(S, "inputs", "a.zip")], name: "inputs/a.zip", ref: "input:a.zip" } }] }));
  const { svc, specs } = service(S);
  await svc.start();
  const [id] = [...svc.jobs.keys()];
  const job = await until(svc, id);
  assert.equal(job.status, "ok", job.reason);
  assert.equal(job.scope?.kind, "declared");
  const inputs = specs[0].mounts.find((m) => m.guest === join(S, "inputs"))!;
  assert.equal(inputs.host, realpathSync(join(S, "inputs")), "the whole set, bound");
  // The generation is published just after the commit.
  for (let i = 0; i < 400 && !svc.jobs.get(id)?.generation; i += 1) await new Promise((res) => setTimeout(res, 50));
  assert.ok(existsSync(join(S, "catalog", "gen", "g0001", "members.tsv")), "the recipe read its target through the bound set");
  await svc.stop("over");
});

test("a job that declares nothing keeps the broad view, recorded as the default, and all said is the same view", async () => {
  const S = sandbox();
  const specs: WorkerSpec[] = [];
  const { svc } = service(S, { runWorker: localWorker(specs) });
  await svc.start();
  const left = await svc.submit("a1", { kind: "command", command: "cat inputs/notes.txt" });
  const all = await svc.submit("a1", { kind: "command", command: "cat inputs/notes.txt", inputs: ["all"] });
  assert.ok(left.ok && all.ok);
  for (const r of [left, all]) {
    const j = await until(svc, r.ok ? r.job.id : "");
    assert.equal(stdout(S, j.id), "the operator's notes");
  }
  const [a, b] = specs;
  const broad = (spec: WorkerSpec) => spec.mounts.filter((m) => m.guest !== "/job" && !m.host.includes(".staging/")).map((m) => `${m.guest}:${m.readonly ? "ro" : "rw"}:${m.noexec ? "noexec" : ""}`);
  assert.deepEqual(broad(a), broad(b));
  for (const want of [`${join(S, "inputs")}:ro:noexec`, `${join(S, "store")}:ro:`, `${join(S, "work")}:ro:`, `${join(S, "tool-output")}:ro:`]) {
    if (existsSync(join(S, want.split(":")[0].slice(S.length + 1)))) assert.ok(broad(a).includes(want), `${want} in ${JSON.stringify(broad(a))}`);
  }
  assert.ok(!a.mounts.some((m) => m.view), "no view");
  const st = await checkStore(S);
  assert.deepEqual(st?.access?.scopes, { declared: 0, all: 1, default_all: 1 });
  await svc.stop("over");
});

test("an input the file system cannot clone is given from the run's one checked copy; bytes that differ from inputs.json are refused", async () => {
  const S = sandbox();
  process.env.SWARM_VIEW_NO_CLONE = "1";
  try {
    const { svc } = service(S);
    await svc.start();
    const r = await svc.submit("a1", { kind: "command", command: "cat inputs/notes.txt", inputs: ["input:notes.txt"] });
    assert.ok(r.ok);
    const job = await until(svc, r.job.id);
    assert.equal(stdout(S, job.id), "the operator's notes");
    const m = JSON.parse(readFileSync(join(storePaths(S).jobs, job.id, "scope.1.json"), "utf8"));
    assert.equal(m.accessible[0].how, "the run's copy, linked");
    assert.equal(m.accessible[0].hashed, "inputs.json");
    const sha = createHash("sha256").update("the operator's notes").digest("hex");
    assert.ok(existsSync(join(storePaths(S).staging, ".projected", sha)), "one copy, named by its sha256, beside the jobs' staging");
    const st = await checkStore(S);
    assert.deepEqual(st?.staging_left, [], "the run's copies are not a job left unsealed");
    // The evidence is not what inputs.json says: nothing is given.
    writeFileSync(join(S, "inputs", "case", "memory.raw"), "tampered, same inputs.json");
    const bad = await svc.submit("a1", { kind: "command", command: "true", inputs: ["input:case/memory.raw"] });
    assert.ok(bad.ok);
    const b = await until(svc, bad.job.id);
    assert.equal(b.state, "failed");
    assert.match(String(b.reason), /not run: .*reads now as sha256 .* not the .* inputs\.json records/);
    await svc.stop("over");
    assert.ok(!existsSync(join(storePaths(S).staging, ".projected")), "the run's copies go when the run stops");
  } finally {
    delete process.env.SWARM_VIEW_NO_CLONE;
  }
});

test("workerSpecFor is the same worker from the recorded job and a staging directory: a rerun builds what the job had", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "cat inputs/notes.txt", inputs: ["input:notes.txt"] });
  assert.ok(r.ok);
  const job = await until(svc, r.job.id);
  const base = join(`${S}.staging`, "rerun-1");
  const plan = await svc.workerSpecFor(job, base);
  assert.equal(plan.spec.image, job.image, "the image it ran in");
  assert.equal(plan.spec.name, `dfs-s000000-job-${job.id}-1`);
  assert.deepEqual(plan.spec.command, ["bash", "/job/run.sh"]);
  const view = plan.spec.mounts.find((m) => m.view && m.guest === S)!;
  assert.equal(view.host, join(base, "view"));
  assert.equal(readFileSync(join(base, "view", "inputs", "notes.txt"), "utf8"), "the operator's notes");
  assert.ok(plan.spec.mounts.some((m) => m.guest === "/job" && m.host === join(base, "job")));
  assert.deepEqual((plan.manifest as { declared: string[] }).declared, ["input:notes.txt"]);
  await svc.stop("over");
});

test("the binding is checked: traversal, a link or a special file in a view, and a view swapped after the check are refused", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const view = mkdtempSync(join(tmpdir(), "view-"));
  mkdirSync(join(view, "inputs"));
  writeFileSync(join(view, "inputs", "a"), "a");
  const expect = (p: string) => {
    const st = statSync(p);
    return { dev: st.dev, ino: st.ino };
  };
  assert.throws(() => holdWorkerMounts([{ host: `${view}/../x`, guest: S }]), /not plain and absolute/);
  assert.throws(() => holdWorkerMounts([{ host: view, guest: `${S}/../etc` }]), /not plain and absolute/);
  assert.throws(() => holdWorkerMounts([{ host: view, guest: "relative/path" }]), /not plain and absolute/);
  assert.throws(() => holdWorkerMounts([{ host: join(view, "inputs", "a"), guest: S }]), /not a directory/);
  // The directory the hub built, and no other.
  const held = holdWorkerMounts([{ host: view, guest: S, readonly: true, view: true, expect: expect(realpathSync(view)) }]);
  assert.equal(recheckWorkerMounts(held), null);
  writeFileSync(join(view, "inputs", "planted"), "added after the check");
  assert.match(String(recheckWorkerMounts(held)), /view under .* changed between its check and the VM's start/);
  held.release();
  const swapped = holdWorkerMounts([{ host: view, guest: S, view: true }]);
  renameSync(view, `${view}.old`);
  mkdirSync(view);
  assert.match(String(recheckWorkerMounts(swapped)), /changed between its check and the VM's start/);
  swapped.release();
  assert.throws(() => holdWorkerMounts([{ host: view, guest: S, expect: { dev: 1, ino: 1 } }]), /not the directory the hub built/);
  symlinkSync("/etc/passwd", join(view, "escape"));
  assert.throws(() => holdWorkerMounts([{ host: view, guest: S, view: true }]), /holds a link at escape/);
  const fifoView = mkdtempSync(join(tmpdir(), "view-"));
  spawnSync("mkfifo", [join(fifoView, "pipe")]);
  assert.throws(() => holdWorkerMounts([{ host: fifoView, guest: S, view: true }]), /holds a special file at pipe/);
  await svc.stop("over");
});

test("resolution alone: every kind of declaration and where it points", async () => {
  const S = sandbox();
  assert.deepEqual(locate("input:case/disk.E01"), { ref: "input:case/disk.E01", area: "inputs", path: "inputs/case/disk.E01", dir: false });
  assert.deepEqual(locate("inputs/case/"), { ref: "inputs/case/", area: "inputs", path: "inputs/case", dir: true });
  assert.deepEqual(locate("job:j000001"), { ref: "job:j000001", area: "store", path: "store/jobs/j000001/out", dir: true });
  assert.deepEqual(locate("job:j000001/out/a.txt"), { ref: "job:j000001/out/a.txt", area: "store", path: "store/jobs/j000001/out/a.txt", dir: false });
  assert.deepEqual(locate("member:g0003#12"), { ref: "member:g0003#12", area: "catalog", path: "catalog/gen/g0003", dir: true });
  assert.ok("reason" in locate("work"), "not all of work/");
  const r = await resolveScope(S, ["inputs/"]);
  assert.ok(r.ok);
  assert.deepEqual(r.ok ? r.objects.map((o) => [o.path, o.shape, o.files]) : [], [["inputs", "dir", 4]]);
  const v = await buildView(r.ok ? r.objects : [], { S, root: join(`${S}.staging`, "x", "view"), projected: join(`${S}.staging`, ".projected"), guestOut: join(S, ".jobs", "j000009"), minFreeMb: 1 });
  assert.ok(v.mounts.some((m) => m.guest === join(S, "inputs") && m.host === realpathSync(join(S, "inputs")) && m.noexec), "the whole evidence bound, no-exec");
  assert.ok(existsSync(join(`${S}.staging`, "x", "view", ".jobs", "j000009")), "a mountpoint for $OUT");
});
