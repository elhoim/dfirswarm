/**
 * A write a job's worker refused is said in its reason (scripts/job-write-refused.ts).
 * On the Belka run (s7827e1) log2timeline wrote its log to the working
 * directory, the run's, read-only in the worker, and the recipe and two
 * agents' jobs failed with "exit 1" and nothing more. The match is on the
 * error text alone; no program is named.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { describe, JobService, jobView } from "../scripts/job-service.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { isStderrName, pathIn, refusedIn, writeRefused, writeRefusedWords } from "../scripts/job-write-refused.ts";
import { localWorker } from "./job-service-worker.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    // The store seals what a job wrote read-only.
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const RUN = "/runs/s7827e1";
const OUT = `${RUN}/.jobs/j000036`;
const at = { cwd: RUN, writable: [OUT, "/job"] };

test("the path each form of the error names, and only a path", () => {
  // Python's OSError, as log2timeline and psort said it on the Belka run.
  assert.equal(pathIn(`OSError: [Errno 30] Read-only file system: '${RUN}/log2timeline-20260929T162603.log.gz'`, "Read-only file system"), `${RUN}/log2timeline-20260929T162603.log.gz`);
  assert.equal(pathIn(`OSError: Unable to write to storage with error: [Errno 30] Read-only file system: '${RUN}/psort-20260929T171528.log.gz'`, "Read-only file system"), `${RUN}/psort-20260929T171528.log.gz`);
  assert.equal(pathIn(`PermissionError: [Errno 13] Permission denied: "${RUN}/x.db"`, "Permission denied"), `${RUN}/x.db`);
  // coreutils, quoted either way.
  assert.equal(pathIn("touch: cannot touch 'out.txt': Read-only file system", "Read-only file system"), "out.txt");
  assert.equal(pathIn("mkdir: cannot create directory ‘work/tmp’: Permission denied", "Permission denied"), "work/tmp");
  // A shell's redirection, and a program's own "<path>: <error>".
  assert.equal(pathIn(`/job/command.sh: line 3: ${RUN}/notes.txt: Permission denied`, "Permission denied"), `${RUN}/notes.txt`);
  assert.equal(pathIn("tee: capture.log: Read-only file system", "Read-only file system"), "capture.log");
  // Java's form.
  assert.equal(pathIn(`java.io.FileNotFoundException: ${RUN}/a.log (Read-only file system)`, "Read-only file system"), `${RUN}/a.log`);
  // A function's name is not a path; nor is nothing.
  assert.equal(pathIn("fopen: Permission denied", "Permission denied"), null);
  assert.equal(pathIn('Os { code: 30, kind: ReadOnlyFilesystem, message: "Read-only file system" }', "Read-only file system"), null);
});

test("what counts: a read-only file system unless the path is writable, a permission denied only on a path outside what the job may write", () => {
  assert.deepEqual(refusedIn(`OSError: [Errno 30] Read-only file system: '${RUN}/log2timeline-1.log.gz'`, at), { error: "Read-only file system", path: `${RUN}/log2timeline-1.log.gz` });
  // Relative: read from where the job started, the run's directory.
  assert.deepEqual(refusedIn("tee: capture.log: Read-only file system", at), { error: "Read-only file system", path: `${RUN}/capture.log` });
  assert.deepEqual(refusedIn(`PermissionError: [Errno 13] Permission denied: '${RUN}/work/a1/x'`, at), { error: "Permission denied", path: `${RUN}/work/a1/x` });
  // With no path, a read-only file system still counts; a permission denied does not.
  assert.deepEqual(refusedIn('thread main panicked: Os { code: 30, kind: ReadOnlyFilesystem, message: "Read-only file system" }', at), { error: "Read-only file system", path: null });
  assert.equal(refusedIn("fopen: Permission denied", at), null);
  // A path the job may write is not a refused write: $OUT is no-exec, and running a script there is denied.
  assert.equal(refusedIn(`bash: ${OUT}/venv/bin/tool: Permission denied`, at), null);
  assert.equal(refusedIn(`OSError: [Errno 30] Read-only file system: '/job/x'`, at), null);
  assert.equal(refusedIn(`bash: ${OUT}/../j000037/x: Permission denied`, at)?.path, `${RUN}/.jobs/j000037/x`);
  // Any other line.
  assert.equal(refusedIn("KeyError: 'entries'", at), null);
  assert.equal(isStderrName("log2timeline.stderr") && isStderrName("fsstat.txt.stderr") && isStderrName("stderr.log") && isStderrName("tool.err") && isStderrName("run_stderr.txt"), true);
  assert.equal(isStderrName("timeline.csv") || isStderrName("error.html") || isStderrName("stderrs"), false);
});

test("a job's stdout, stderr and every stderr file it kept are read whole; the first refused write is named with where it is, and the rest counted", async () => {
  const base = await mkdtemp(join(tmpdir(), "wr-"));
  dirs.push(base);
  const ctl = join(base, "job");
  const out = join(base, "out");
  await mkdir(join(out, "p2048"), { recursive: true });
  await mkdir(ctl, { recursive: true });
  // Nothing: no hint.
  await writeFile(join(ctl, "stdout.log"), "wc: 0\n");
  await writeFile(join(ctl, "stderr.log"), "Traceback (most recent call last):\nKeyError: 'entries'\n");
  assert.equal(await writeRefused({ ctl, out, cwd: RUN, writable: [OUT, "/job", out, ctl] }), null);
  // A recipe's step kept its stderr in $OUT; far into a long stdout the command printed another.
  const long = `${RUN}/${"deep/".repeat(1000)}log2timeline-20260929T163901.log.gz`;
  await writeFile(join(ctl, "stdout.log"), `${"x".repeat(3 << 20)}\nline\nOSError: [Errno 30] Read-only file system: '${long}'\n`);
  await writeFile(join(out, "log2timeline.stderr"), `Traceback\nOSError: [Errno 30] Read-only file system: '${RUN}/log2timeline-1.log.gz'\nOSError: [Errno 30] Read-only file system: '${RUN}/log2timeline-1.log.gz'\n`);
  await writeFile(join(out, "p2048", "fsstat.txt.stderr"), `bash: ${OUT}/p2048/tool: Permission denied\n`);
  await writeFile(join(out, "timeline.csv"), `a,Read-only file system: '${RUN}/evidence-says-so'\n`);
  const w = await writeRefused({ ctl, out, cwd: RUN, writable: [OUT, "/job", out, ctl] });
  assert.deepEqual(w, { error: "Read-only file system", path: long, file: "stdout.log", line: 3, lines: 3, files: 2 });
  const words = writeRefusedWords(w!, { job: "j000114", out: `${RUN}/.jobs/j000114` });
  // Never cut: the whole path, where it is, $OUT by name and path, and what to do.
  assert.ok(words.includes(long), "the path is whole");
  assert.match(words, /^a write outside \$OUT was refused \("Read-only file system" on \/runs\/s7827e1\/deep\/.*, store\/jobs\/j000114\/stdout\.log line 3; 3 such lines in 2 files\)\./);
  assert.match(words, /the job starts in the run's directory, and it and the whole run are read-only: only this job's output directory, \$OUT \(\/runs\/s7827e1\/\.jobs\/j000114\), is writable\. Point the program's log, temp or output options there, or cd "\$OUT" before running it$/);
  // Only in a kept stderr file: cited as the job's output.
  await writeFile(join(ctl, "stdout.log"), "");
  const kept = await writeRefused({ ctl, out, cwd: RUN, writable: [OUT, "/job", out, ctl] });
  assert.deepEqual(kept, { error: "Read-only file system", path: `${RUN}/log2timeline-1.log.gz`, file: "out/log2timeline.stderr", line: 2, lines: 2, files: 1 });
  assert.match(writeRefusedWords(kept!, { job: "j000036", out: OUT }), /on \/runs\/s7827e1\/log2timeline-1\.log\.gz, job:j000036\/log2timeline\.stderr line 2; 2 such lines in that file\)/);
});

test("through the service: a job that ended non-zero on a refused write has it in its reason, on its record, on the journal and in what its requester is told; one that did not keeps \"exit N\"", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "wr-jobs-")), "run");
  dirs.push(join(S, ".."));
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  const run = async (command: string) => {
    const r = await svc.submit("a1", { kind: "command", command, inputs: ["all"] });
    assert.ok(r.ok, !r.ok ? r.reason : "");
    const end = Date.now() + 20_000;
    let job = svc.jobs.get(r.job.id)!;
    while (!["committed", "failed", "cancelled"].includes(job.state) && Date.now() < end) {
      await new Promise((res) => setTimeout(res, 50));
      job = svc.jobs.get(r.job.id)!;
    }
    return job;
  };
  // The program's own words on stderr, as log2timeline's were; the path is where the job started.
  const refused = await run(`echo "OSError: [Errno 30] Read-only file system: '$PWD/log2timeline-20260929T162603.log.gz'" >&2; exit 1`);
  assert.equal(refused.status, "failed");
  const out = join(S, ".jobs", refused.id);
  assert.equal(refused.reason, `exit 1: a write outside $OUT was refused ("Read-only file system" on ${S}/log2timeline-20260929T162603.log.gz, store/jobs/${refused.id}/stderr.log line 1). In a worker the job starts in the run's directory, and it and the whole run are read-only: only this job's output directory, $OUT (${out}), is writable. Point the program's log, temp or output options there, or cd "$OUT" before running it`);
  assert.deepEqual(refused.write_refused, { error: "Read-only file system", path: `${S}/log2timeline-20260929T162603.log.gz`, file: "stderr.log", line: 1, lines: 1, files: 1 });
  const journal = readFileSync(storePaths(S).journal, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.ok(journal.some((l) => l.type === "job_write_refused" && l.job === refused.id && l.path === `${S}/log2timeline-20260929T162603.log.gz` && l.exit === 1));
  assert.ok(journal.some((l) => l.type === "job_finished" && l.job === refused.id && l.reason === refused.reason), "the journal's job_finished carries the reason whole");
  assert.ok(describe(refused).includes(refused.reason!), "the post its requester gets says it whole");
  assert.equal((await jobView(S, refused)).reason, refused.reason, "and so does job_run's and job_status's answer");
  // A step's stderr kept in $OUT, as a recipe keeps it.
  const kept = await run(`echo "PermissionError: [Errno 13] Permission denied: 'notes.txt'" > "$OUT/step.stderr"; exit 2`);
  assert.match(kept.reason ?? "", new RegExp(`^exit 2: a write outside \\$OUT was refused \\("Permission denied" on ${S}/notes\\.txt, job:${kept.id}/step\\.stderr line 1\\)\\.`));
  // Denied inside $OUT (it is no-exec) is no refused write: it is a program that could not be executed (job-exec-refused.ts).
  const inside = await run(`echo "bash: $OUT/tool: Permission denied" >&2; exit 126`);
  assert.match(inside.reason ?? "", /^exit 126: a program it ran could not be executed \("Permission denied" on /);
  assert.equal(inside.write_refused, undefined);
  // A failure that is not a write: the reason is the exit status.
  const other = await run(`echo "KeyError: 'entries'" >&2; exit 1`);
  assert.equal(other.reason, "exit 1");
  // A job that succeeded is not read for it.
  const ok = await run(`echo "Read-only file system: '/somewhere/else'" >&2; exit 0`);
  assert.equal(ok.status, "ok");
  assert.equal(ok.reason, undefined);
  await svc.stop("test over");
});

test("the worker prompt says a job runs with the run read-only, and where a program's log or temp files go", async () => {
  const prompt = readFileSync(join(import.meta.dirname, "..", "prompts", "worker-system.md"), "utf8").replace(/\s+/g, " ");
  for (const must of [
    "A job starts in the run's directory and runs with the run read-only, so a program that writes its log or temp files to its working directory must be given a path under $OUT (its log, temp or output option), or run after cd \"$OUT\".",
    "A job that failed on such a write says so in its reason.",
  ]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
});
