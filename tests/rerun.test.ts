/**
 * A sealed job run again (scripts/rerun.ts), through the job service's own
 * worker path with a worker that runs the job's script on this host (no
 * VM): held to the image digest and the tool sha256 the job ran, its
 * outputs in a rerun area beside the run and never in the store, compared
 * by bytes with the sealed manifest. A byte mismatch stays a mismatch; an
 * equivalence under a named, versioned normalisation is said apart, and
 * only when asked. Real-VM reruns are not tested here.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService } from "../scripts/job-service.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { NORMALISATIONS, rerunJob, type RerunDeps } from "../scripts/rerun.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const made: string[] = [];
after(() => {
  for (const d of made) {
    spawnSync("chmod", ["-R", "u+w", d]);
    rmSync(d, { recursive: true, force: true });
  }
});
const DIGEST = `sha256:${"a".repeat(64)}`;
const sha = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** What a worker VM would do, done here: the job's run.sh with its /job and $OUT as the host directories mounted there. */
function hostWorker(digest: string | undefined, seen: WorkerSpec[] = []) {
  return async (spec: WorkerSpec) => {
    seen.push(spec);
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => m.guest === spec.env.OUT)!;
    const local = (text: string) => text.split("/job/").join(`${ctl}/`).split(out.guest!).join(out.host);
    for (const f of readdirSync(ctl)) if (f !== "run.sh" && f.endsWith(".json")) writeFileSync(join(ctl, f), local(readFileSync(join(ctl, f), "utf8")));
    const script = local(readFileSync(join(ctl, "run.sh"), "utf8")).replace(/timeout --kill-after=10 (\d+) /g, "");
    writeFileSync(join(ctl, "run-local.sh"), script);
    const r = spawnSync("bash", [join(ctl, "run-local.sh")], { cwd: spec.workdir, env: { ...process.env, ...spec.env, OUT: out.host }, encoding: "utf8" });
    return { code: r.status, fenced: true, ...(digest ? { digest } : {}) };
  };
}

function sandbox(): string {
  const base = mkdtempSync(join(tmpdir(), "rerun-"));
  made.push(base);
  const S = join(base, "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "notes.txt"), "the evidence\n");
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/notes.txt", bytes: 13, sha256: sha("the evidence\n") }] }));
  return S;
}

async function sealedJob(S: string, raw: Parameters<JobService["submit"]>[1], digest: string | null = DIGEST): Promise<string> {
  const svc = new JobService({ sandbox: S, run: "s1", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: true, minFreeMb: 1, runWorker: hostWorker(digest ?? undefined), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  const r = await svc.submit("a1", raw);
  if (!r.ok) throw new Error(r.reason);
  const end = Date.now() + 20000;
  while (!["committed", "failed", "cancelled"].includes(svc.jobs.get(r.job.id)?.state ?? "")) {
    if (Date.now() > end) throw new Error("the job did not finish");
    await new Promise((res) => setTimeout(res, 50));
  }
  await svc.stop("the test is done");
  return r.job.id;
}

const deps = (digest: string | null = DIGEST, workerDigest: string | undefined = DIGEST, seen: WorkerSpec[] = []): RerunDeps => ({ runWorker: hostWorker(workerDigest, seen), destroyWorker: async () => ({ ok: true }), imageDigest: async () => digest });

test("a rerun runs through the job service's own worker path", () => {
  assert.equal(typeof JobService.prototype.workerSpecFor, "function");
});

test("a job whose outputs come out the same is reproduced byte for byte, in a rerun area beside the run and never in its store", async () => {
  const S = sandbox();
  const id = await sealedJob(S, { kind: "command", command: 'sha256sum inputs/notes.txt 2>/dev/null | cut -c1-64 > "$OUT/hash.txt" || shasum -a 256 inputs/notes.txt | cut -c1-64 > "$OUT/hash.txt"; echo done', inputs: ["input:notes.txt"] });
  const P = storePaths(S);
  const journal = readFileSync(P.journal, "utf8");
  const sealedOut = readFileSync(join(P.jobs, id, "out", "hash.txt"));
  const seen: WorkerSpec[] = [];
  const r = await rerunJob({ sandbox: S, job: id, run: "s1", deps: deps(DIGEST, DIGEST, seen) });
  assert.equal(r.verdict, "reproduced byte for byte: 1 file(s), each with the sealed sha256; stdout and stderr the same too");
  assert.deepEqual(r.compare.identical, ["hash.txt"]);
  assert.equal(r.rerun.status, "ok");
  assert.equal(r.normalised, null);
  // Through the worker path: the same script shape, $OUT in the guest where the job had it, the store read-only, no network.
  assert.equal(seen.length, 1);
  assert.equal(seen[0].image, "img:test");
  assert.equal(seen[0].env.OUT, join(S, ".jobs", id));
  assert.deepEqual(seen[0].network, { mode: "off" });
  assert.deepEqual(seen[0].mounts.filter((m) => !m.readonly).map((m) => m.guest).sort(), ["/job", join(S, ".jobs", id)].sort(), "only $OUT and the job's control directory are writable");
  assert.match(seen[0].name, new RegExp(`^dfs-rerun-s1-${id}-1$`));
  // Nothing in the run's store changed, and the rerun's outputs are beside the run.
  assert.equal(readFileSync(P.journal, "utf8"), journal);
  assert.deepEqual(readFileSync(join(P.jobs, id, "out", "hash.txt")), sealedOut);
  assert.ok(existsSync(join(`${S}.reruns`, id, "1", "out", "hash.txt")));
  const rec = JSON.parse(readFileSync(join(`${S}.reruns`, id, "1", "rerun.json"), "utf8")) as { original: { image_digest: string }; not_reproduced: string[] };
  assert.equal(rec.original.image_digest, DIGEST);
  assert.ok(rec.not_reproduced.some((x) => /which bytes the job read: not measured/.test(x)));
  // A second rerun is a second area.
  await rerunJob({ sandbox: S, job: id, run: "s1", deps: deps() });
  assert.deepEqual(readdirSync(join(`${S}.reruns`, id)).sort(), ["1", "2"]);
});

test("a file that differs stays a mismatch; under timestamps@1, asked for, it is said to be equivalent, apart from the verdict", async () => {
  const S = sandbox();
  const id = await sealedJob(S, { kind: "command", command: 'printf "the notes\\n" > "$OUT/fixed.txt"; printf "made at %s\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUT/stamped.txt"; head -c 16 /dev/urandom > "$OUT/random.bin"', inputs: ["all"] });
  await new Promise((res) => setTimeout(res, 1100));
  const r = await rerunJob({ sandbox: S, job: id, run: "s1", deps: deps() });
  assert.match(r.verdict, /^NOT REPRODUCED: 2 file\(s\) differ \((random\.bin, stamped\.txt|stamped\.txt, random\.bin)\); 1 the same$/);
  assert.deepEqual(r.compare.identical, ["fixed.txt"]);
  assert.equal(r.normalised, null, "no normalisation unless asked");
  const n = await rerunJob({ sandbox: S, job: id, run: "s1", normalise: "timestamps@1", deps: deps() });
  assert.match(n.verdict, /^NOT REPRODUCED: /, "the verdict stands");
  assert.equal(n.normalised?.name, "timestamps@1");
  assert.equal(n.normalised?.definition, NORMALISATIONS["timestamps@1"].definition);
  assert.deepEqual(n.normalised?.equivalent, ["stamped.txt"]);
  assert.deepEqual(n.normalised?.still_differ, ["random.bin"]);
  assert.match(n.normalised?.note ?? "", /This is not a reproduction, and the verdict above stands/);
  await assert.rejects(rerunJob({ sandbox: S, job: id, run: "s1", normalise: "timestamps@2", deps: deps() }), /there is no normalisation timestamps@2: timestamps@1/);
});

test("refused before anything runs: an image whose digest here is not the one recorded, a job with no digest, an unknown job, an import, a tool that changed", async () => {
  const S = sandbox();
  const id = await sealedJob(S, { kind: "command", command: 'echo x > "$OUT/x.txt"', inputs: ["all"] });
  const seen: WorkerSpec[] = [];
  await assert.rejects(rerunJob({ sandbox: S, job: id, run: "s1", deps: deps(`sha256:${"b".repeat(64)}`, DIGEST, seen) }), new RegExp(`the image img:test here is sha256:b{64}, not ${DIGEST}, the digest job ${id} ran in: pull or restore that image; nothing else is run in its place`));
  await assert.rejects(rerunJob({ sandbox: S, job: id, run: "s1", deps: deps(null, DIGEST, seen) }), /here is not present/);
  assert.equal(seen.length, 0, "nothing ran");
  await assert.rejects(rerunJob({ sandbox: S, job: "j999999", run: "s1", deps: deps() }), /the store journal has no job j999999/);
  const bare = await sealedJob(S, { kind: "command", command: 'echo y > "$OUT/y.txt"', inputs: ["all"] }, null);
  await assert.rejects(rerunJob({ sandbox: S, job: bare, run: "s1", deps: deps() }), /no image digest was recorded for job/);
  writeFileSync(join(S, "work", "a1", "copy.txt"), "live\n");
  const imp = await sealedJob(S, { kind: "import", source: "work/a1/copy.txt", inputs: ["all"] });
  await assert.rejects(rerunJob({ sandbox: S, job: imp, run: "s1", deps: deps() }), /is an import: a copy of a live file as it was then/);
  // A forged tool, run, then changed: the tool here is not the one the job ran.
  const body = 'import json, os, sys\nargs = json.load(sys.stdin)\nopen(os.path.join(os.environ["OUT"], "t.txt"), "w").write(args["word"] + "\\n")\n';
  mkdirSync(join(S, "tools", "echo_word"), { recursive: true });
  writeFileSync(join(S, "tools", "echo_word", "run.py"), body);
  writeFileSync(join(S, "tools", "echo_word", "manifest.json"), JSON.stringify({ name: "echo_word", description: "t", params: { word: { type: "string", required: true } }, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256: sha(body) }));
  const t = await sealedJob(S, { kind: "tool", tool: "echo_word", args: { word: "evidence" }, inputs: ["all"] });
  const ok = await rerunJob({ sandbox: S, job: t, run: "s1", deps: deps() });
  assert.match(ok.verdict, /^reproduced byte for byte/);
  const changed = body.replace('"\\n"', '"!\\n"');
  writeFileSync(join(S, "tools", "echo_word", "run.py"), changed);
  writeFileSync(join(S, "tools", "echo_word", "manifest.json"), JSON.stringify({ name: "echo_word", description: "t", params: { word: { type: "string", required: true } }, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 2, sha256: sha(changed) }));
  await assert.rejects(rerunJob({ sandbox: S, job: t, run: "s1", deps: deps() }), /the tool echo_word here \(sha256 [0-9a-f]{64}\) is not the one job j\d{6} ran/);
});
