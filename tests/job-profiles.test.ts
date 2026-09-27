/**
 * The run's job images: the agents' own VMs boot the base, and the forensic
 * programs are in an image per profile. A job names one with `profile`; a
 * pack tool runs in its pack's, a recipe in its pack's (or the one its
 * recipe.json names); a command that names none in the smallest image whose
 * own record holds every program it runs, when that is sure; anything else in
 * the image that holds every pack. The images are declared on the journal
 * before any job runs, and custody holds each job to them. The worker is the
 * local stand-in, which records the image it was asked to boot; the image
 * records are fakes, with made-up program names.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService, type JobRecord, type JobServiceOptions } from "../scripts/job-service.ts";
import { chooseImage, commandShape, type ImageRecord } from "../scripts/image-choice.ts";
import { checkStore, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");
const IMAGES = { full: "dfirswarm-full:dev", disk: "dfirswarm-disk:dev", memory: "dfirswarm-memory:dev", mobile: "dfirswarm-mobile:dev" };

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "jobprof-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  return S;
}

function service(S: string, extra: Partial<JobServiceOptions> = {}) {
  const booted: string[] = [];
  const worker = localWorker();
  const svc = new JobService({
    sandbox: S, run: "s000000", image: IMAGES.full, images: IMAGES,
    packProfiles: { "computer-forensics-base": "disk", "memory-forensics": "memory", "mobile-forensics": "mobile" },
    workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [CFB], forging: true, minFreeMb: 1, derived: false,
    runWorker: (spec: WorkerSpec) => {
      booted.push(spec.image);
      return worker(spec);
    },
    destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined,
    identity: async (a) => ({ name: `${a}-name` }),
    ...extra,
  });
  return { svc, booted };
}

async function until(svc: JobService, id: string): Promise<JobRecord> {
  const end = Date.now() + 30000;
  while (!["committed", "failed", "cancelled"].includes(svc.jobs.get(id)?.state ?? "")) {
    if (Date.now() > end) throw new Error(`job ${id} not done`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return svc.jobs.get(id)!;
}

const journal = (S: string) => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;

test("a job runs in the image its profile names, a pack tool in its pack's, anything else in the one holding every pack", async () => {
  const S = sandbox();
  // A pack tool, seeded with its pack's name as the kickoff seeds one.
  const body = "import json,sys\nprint(json.dumps({'ok': True}))\n";
  mkdirSync(join(S, "tools", "segb_dump"), { recursive: true });
  writeFileSync(join(S, "tools", "segb_dump", "run.py"), body);
  writeFileSync(join(S, "tools", "segb_dump", "manifest.json"), JSON.stringify({ name: "segb_dump", description: "t", params: {}, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex"), pack: "mobile-forensics" }));
  const { svc, booted } = service(S);
  await svc.start();
  const mem = await svc.submit("a1", { kind: "command", command: "echo vol", inputs: [], profile: "memory" });
  const plain = await svc.submit("a1", { kind: "command", command: "echo hi", inputs: [] });
  const tool = await svc.submit("a1", { kind: "tool", tool: "segb_dump", args: {}, inputs: [] });
  assert.ok(mem.ok && plain.ok && tool.ok);
  for (const r of [mem, plain, tool]) await until(svc, r.ok ? r.job.id : "");
  const started = new Map(journal(S).filter((l) => l.type === "job_started").map((l) => [String(l.job), l]));
  assert.equal(started.get(mem.ok ? mem.job.id : "")?.image, IMAGES.memory);
  assert.equal(started.get(mem.ok ? mem.job.id : "")?.profile, "memory");
  assert.equal(started.get(plain.ok ? plain.job.id : "")?.image, IMAGES.full, "no profile: the image that holds every pack");
  assert.equal(started.get(tool.ok ? tool.job.id : "")?.image, IMAGES.mobile, "a pack tool: its pack's image");
  assert.deepEqual([...booted].sort(), [IMAGES.full, IMAGES.memory, IMAGES.mobile].sort(), "each worker booted the image on its record");
  // The images were on the journal before any job ran.
  const lines = journal(S);
  const declared = lines.findIndex((l) => l.type === "job_images");
  assert.ok(declared >= 0 && declared < lines.findIndex((l) => l.type === "job_started"));
  assert.deepEqual(lines[declared].images, IMAGES);
  // Custody holds each job to them.
  const st = await checkStore(S);
  assert.deepEqual(st?.images?.undeclared, []);
  assert.deepEqual(st?.images?.declared, Object.values(IMAGES).sort());
  await svc.stop("over");
});

test("a profile the run did not declare is refused with the ones it has; with no job images, any profile is", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "true", inputs: [], profile: "network" });
  assert.equal(r.ok, false);
  assert.match(!r.ok ? r.reason : "", /no job image "network" in this run: full; disk \(the packs computer-forensics-base\); memory \(the packs memory-forensics\); mobile \(the packs mobile-forensics\)/);
  // A pack's id picks its pack's image: agents named packs as profiles.
  const byPack = await svc.submit("a1", { kind: "command", command: "true", inputs: [], profile: "mobile-forensics" });
  assert.ok(byPack.ok, !byPack.ok ? byPack.reason : "");
  const done = await until(svc, byPack.ok ? byPack.job.id : "");
  assert.equal(done.spec.profile, "mobile");
  assert.equal(journal(S).find((l) => l.type === "job_started" && l.job === done.id)?.image, IMAGES.mobile);
  await svc.stop("over");
  const S2 = sandbox();
  const { svc: plain } = service(S2, { images: undefined, packProfiles: undefined });
  await plain.start();
  const r2 = await plain.submit("a1", { kind: "command", command: "true", inputs: [], profile: "disk" });
  assert.match(!r2.ok ? r2.reason : "", /declared no job images: leave profile out/);
  assert.equal(journal(S2).some((l) => l.type === "job_images"), false, "nothing declared when there is nothing to declare");
  await plain.stop("over");
});

test("a recipe runs in its pack's image, or in the one its recipe.json names", async () => {
  const S = sandbox();
  const { svc } = service(S);
  await svc.start();
  assert.deepEqual(await svc.imageFor({ kind: "recipe", recipe: "computer-forensics-base/archive-members", inputs: [], timeout_seconds: 60, network: "off" }), { profile: "disk", ref: IMAGES.disk, choice: { how: "pack", why: "the recipe's pack computer-forensics-base runs in disk" } });
  assert.deepEqual(await svc.imageFor({ kind: "detect", inputs: [], timeout_seconds: 60, network: "off" }), { profile: null, ref: IMAGES.full, choice: { how: "default", why: "a detect pass asks the recipes of every pack" } }, "a detect pass asks every recipe: the image that holds every pack");
  await svc.stop("over");
});

/** A job image's record as install.py writes it: its packs, its packs' programs, every program on its PATH. */
function record(S: string, profile: string, packs: string[], binaries: Record<string, string | null>, onPath?: string[]): void {
  mkdirSync(join(S, "images", profile), { recursive: true });
  writeFileSync(join(S, "images", profile, "image.json"), JSON.stringify({ profile, packs, binaries, ...(onPath ? { on_path: onPath } : {}) }));
}

const SHELL = ["/bin/bash", "/usr/bin/head", "/usr/bin/grep", "/usr/bin/sort", "/usr/bin/python3", "/usr/bin/timeout", "/usr/bin/find", "/usr/bin/xargs"];

function fake(profile: string, packs: number, own: string[], ref = `img:${profile}`): ImageRecord {
  const paths = [...SHELL, ...own.map((p) => `/usr/local/bin/${p}`)];
  return { profile, ref, packs, programs: new Set(paths.map((p) => p.split("/").pop()!)), paths: new Set(paths), whole: true };
}

test("a command is read as bash reads it: the words that run, in pipelines, lists, substitutions and quotes, redirections aside", () => {
  assert.deepEqual(commandShape(`FOO=1 partx -o 2048 "in puts/x" 2>/dev/null | head -n 5 && echo "$(lister -a)" > "$OUT/x"; for f in a b; do carver "$f"; done`), {
    commands: [["FOO=1", "partx", "-o", "2048", "in puts/x"], ["head", "-n", "5"], ["lister", "-a"], ["echo", "$(lister -a)"], ["for", "f", "in", "a", "b"], ["do", "carver", "$f"], ["done"]],
    hidden: null,
  });
  assert.equal(commandShape("paths=(\n'a b'\n'c')\nls \"${paths[@]}\"").hidden, null, "an array's elements are not commands");
  assert.match(String(commandShape("python3 - <<'PY'\nprint(1)\nPY").hidden), /heredoc/);
  assert.match(String(commandShape("tool <<< 'x'").hidden), /heredoc or here-string/);
  assert.match(String(commandShape("bash -c 'a; b'").hidden), /quoted script/);
});

test("a command that names no profile runs in the smallest image whose record holds every program it runs, and in the default when that is not sure", () => {
  const records = [fake("disk", 3, ["partx", "carver", "evtxparse"]), fake("linux", 2, ["extdump"]), fake("re", 4, ["lonely"]), fake("full", 12, ["partx", "carver", "evtxparse", "extdump", "memdump"])];
  const dflt = { profile: null, ref: "img:full" };
  const pick = (cmd: string) => chooseImage(cmd, records, dflt, new Set(["echo", "cd", "read", "export", "[", "true"]));
  const smallest = pick("partx -o 2048 inputs/disk.raw | head -50");
  assert.equal(smallest.profile, "disk");
  assert.deepEqual(smallest.choice, { how: "programs", why: "the smallest job image that holds what the command runs: head and partx are in its record (also in full)", programs: ["head", "partx"] });
  assert.equal(pick("grep -c x inputs/a.txt | sort").profile, "linux", "the fewest packs of those that hold it");
  assert.equal(pick("cd \"$OUT\" && echo hi").profile, "linux", "bash's own builtins run anywhere");
  // A program run through another is named, and moves the choice.
  assert.equal(pick("timeout 60 carver -r inputs/x.raw > \"$OUT/c.txt\" 2>&1").profile, "disk");
  assert.equal(pick("find inputs -name '*.evt' -exec evtxparse {} \\;").profile, "disk");
  assert.equal(pick("bash -c 'carver inputs/x | head'").profile, "disk");
  assert.equal(pick("exec carver inputs/x").profile, "disk", "a builtin that runs a program: that program");
  assert.equal(pick("ls inputs | xargs -n1 extdump").ref, "img:full", "ls is on no record here: the default");
  assert.equal(pick("find inputs | xargs -n1 extdump").profile, "linux");
  assert.equal(pick("extdump a && memdump b").profile, "full", "only one image holds both");
  const why = (cmd: string) => {
    const c = pick(cmd);
    assert.equal(c.ref, "img:full", cmd);
    assert.equal(c.choice.how, "default", cmd);
    return c.choice.why;
  };
  assert.match(why("python3 - <<'PY'\nimport os\nPY"), /^the run's default image: a heredoc/);
  assert.match(why("python3 -c 'import libfoo'"), /imports a library/);
  assert.match(why("python3 work/a1/parse.py inputs/x"), /agents' scratch/);
  assert.match(why("cd work/a1 && python3 parse.py"), /agents' scratch/);
  assert.match(why("./parse.sh inputs/x"), /relative path/);
  assert.match(why("$TOOL inputs/x"), /named by an expansion/);
  assert.match(why('eval "$CMD"'), /eval runs text as code/);
  assert.match(why("nosuchprogram inputs/x | head"), /nosuchprogram is in no job image's record/);
  assert.match(why("partx a | lonely b"), /no one job image's record holds lonely and partx/);
  // Records written before they listed every program on PATH: a shell utility is on none.
  const old = records.map((r) => ({ ...r, programs: new Set([...r.programs].filter((p) => !["bash", "head", "grep", "sort", "python3", "timeout", "find", "xargs"].includes(p))), whole: false }));
  const c = chooseImage("partx a | head", old, dflt, new Set());
  assert.equal(c.ref, "img:full");
  assert.match(c.choice.why, /head is in no job image's record \(these records list only their packs' programs/);
  assert.equal(chooseImage("partx -o 2048 inputs/x", old, dflt, new Set()).profile, "disk", "a pack's program alone is still found");
  assert.equal(chooseImage("exec -a x mactime -b body", old, dflt, new Set(["exec"])).ref, "img:full", "a program run by a builtin, on no record: the default");
  assert.match(chooseImage("partx", [], dflt).choice.why, /no job image's record could be read/);
});

test("a job that names no profile goes to the image the records choose, the choice and its reason on job_started", async () => {
  const S = sandbox();
  const shell = ["/usr/bin/head", "/usr/bin/python3"];
  record(S, "disk", ["computer-forensics-base"], { partx: "/usr/bin/partx", gone: null }, [...shell, "/usr/bin/partx"]);
  record(S, "memory", ["memory-forensics"], { memdump: "/usr/local/bin/memdump" }, [...shell, "/usr/local/bin/memdump"]);
  record(S, "full", ["computer-forensics-base", "memory-forensics", "mobile-forensics"], { partx: "/usr/bin/partx", memdump: "/usr/local/bin/memdump" }, [...shell, "/usr/bin/partx", "/usr/local/bin/memdump"]);
  const { svc, booted } = service(S);
  await svc.start();
  const runs = [
    await svc.submit("a1", { kind: "command", command: "partx 2>/dev/null | head -5; true", inputs: [] }),
    await svc.submit("a1", { kind: "command", command: "gone inputs/x || true", inputs: [] }),
    await svc.submit("a1", { kind: "command", command: "python3 - <<'PY'\nprint(1)\nPY", inputs: [] }),
  ];
  assert.ok(runs.every((r) => r.ok));
  for (const r of runs) await until(svc, r.ok ? r.job.id : "");
  const started = new Map(journal(S).filter((l) => l.type === "job_started").map((l) => [String(l.job), l]));
  const [smallest, missing, heredoc] = runs.map((r) => started.get(r.ok ? r.job.id : "")!);
  assert.deepEqual([smallest.image, smallest.profile], [IMAGES.disk, "disk"], "the smallest image whose record holds partx and head (the mobile image has no record)");
  assert.deepEqual(smallest.image_choice, { how: "programs", why: "the smallest job image that holds what the command runs: head and partx are in its record (also in full)", programs: ["head", "partx"] });
  assert.equal(missing.image, IMAGES.full, "a program its pack names that the build left out is not held");
  assert.match(String((missing.image_choice as { why: string }).why), /gone is in no job image's record/);
  assert.equal(heredoc.image, IMAGES.full);
  assert.equal((heredoc.image_choice as { how: string }).how, "default");
  assert.ok(booted.includes(IMAGES.disk));
  // Custody holds the chosen image to the declared ones.
  assert.deepEqual((await checkStore(S))?.images?.undeclared, []);
  // An import copies with python3: the smallest image that has it.
  mkdirSync(join(S, "work", "a1"), { recursive: true });
  writeFileSync(join(S, "work", "a1", "note.txt"), "n\n");
  const imp = await svc.submit("a1", { kind: "import", source: "work/a1/note.txt" });
  assert.ok(imp.ok);
  await until(svc, imp.ok ? imp.job.id : "");
  const impStarted = journal(S).find((l) => l.type === "job_started" && l.job === (imp.ok ? imp.job.id : ""))!;
  assert.equal(impStarted.profile, "disk", "disk and memory both hold python3; disk sorts first by name");
  await svc.stop("over");
});
