/**
 * A program a job's worker could not execute is said in its reason
 * (scripts/job-exec-refused.ts). In a worker nothing under store/ (sealed
 * files have no execute bit), work/extracted/, work/quarantine/, inputs/ or
 * the job's own $OUT can run in place; a seat that supplied itself a program
 * found the way (a copy in an executable temporary directory inside the job)
 * only after two failed jobs, each of which said "exit 126" or "exit 127: a
 * program it runs is not in its image". The match is on the shell's exit
 * status and the loader's own words; no program is named.
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
import { execRefused, execRefusedIn, execRefusedWords, LOADER_REFUSAL } from "../scripts/job-exec-refused.ts";
import { localWorker } from "./job-service-worker.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    // The store seals what a job wrote read-only.
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const RUN = "/runs/s3472f0";
const OUT = `${RUN}/.jobs/j000090`;
const at = { cwd: RUN };

test("what counts: the shell's status 126 with its permission denied, the loader's refusal to map a segment at any status; a permission denied at another status is not read", () => {
  // The shell, as it said it for a program unpacked into $OUT (exit 126).
  assert.deepEqual(execRefusedIn(`/job/command.sh: line 29: ${OUT}/root/usr/bin/tool: Permission denied`, { ...at, exit: 126 }), { error: "Permission denied", path: `${OUT}/root/usr/bin/tool` });
  // A sealed file in the store has no execute bit: relative, read from where the job started.
  assert.deepEqual(execRefusedIn("/job/command.sh: line 5: store/imports/mat-0002/out/prog: Permission denied", { ...at, exit: 126 }), { error: "Permission denied", path: `${RUN}/store/imports/mat-0002/out/prog` });
  assert.deepEqual(execRefusedIn(`bash: ${RUN}/work/extracted/s0/x/prog: Permission denied`, { ...at, exit: 126 }), { error: "Permission denied", path: `${RUN}/work/extracted/s0/x/prog` });
  // A bare name the shell found on its path but could not run: counted, with no path.
  assert.deepEqual(execRefusedIn("bash: tool: Permission denied", { ...at, exit: 126 }), { error: "Permission denied", path: null });
  // At any other status the same words are not read: nothing in the line tells a program that could not be executed from a file that could not be written (a read-only directory in $OUT).
  for (const exit of [1, 2, 127, null]) {
    assert.equal(execRefusedIn(`PermissionError: [Errno 13] Permission denied: '${OUT}/root/usr/bin/tool'`, { ...at, exit }), null);
    assert.equal(execRefusedIn(`touch: cannot touch '${OUT}/ro/new': Permission denied`, { ...at, exit }), null);
    assert.equal(execRefusedIn(`PermissionError: [Errno 13] Permission denied: '${RUN}/store/imports/mat-0002/out/prog'`, { ...at, exit }), null);
  }
  // The dynamic loader, for the program or a library it loads from a no-exec mount: at any status, the path it names.
  assert.deepEqual(
    execRefusedIn(`${OUT}/root/usr/bin/tool: error while loading shared libraries: ${OUT}/root/usr/bin/tool: ${LOADER_REFUSAL}`, { ...at, exit: 127 }),
    { error: LOADER_REFUSAL, path: `${OUT}/root/usr/bin/tool` },
  );
  assert.deepEqual(
    execRefusedIn(`/job/x: error while loading shared libraries: ${OUT}/root/usr/lib/aarch64-linux-gnu/libfoo.so.62: ${LOADER_REFUSAL}`, { ...at, exit: 1 }),
    { error: LOADER_REFUSAL, path: `${OUT}/root/usr/lib/aarch64-linux-gnu/libfoo.so.62` },
  );
  assert.deepEqual(execRefusedIn(`error while loading shared libraries: ${LOADER_REFUSAL}`, { ...at, exit: 127 }), { error: LOADER_REFUSAL, path: null });
  // A library that is merely missing is not a refusal to execute (the image does not hold it).
  assert.equal(execRefusedIn("tool: error while loading shared libraries: libfoo.so.1: cannot open shared object file: No such file or directory", { ...at, exit: 127 }), null);
  // Any other line.
  assert.equal(execRefusedIn("KeyError: 'entries'", { ...at, exit: 126 }), null);
  assert.equal(execRefusedIn("bash: tool: command not found", { ...at, exit: 127 }), null);
});

test("a job's stdout, stderr and every stderr file it kept are read whole; the first line is named with where it is, the rest counted; status 126 alone is enough, and says that no line names the program", async () => {
  const base = await mkdtemp(join(tmpdir(), "xr-"));
  dirs.push(base);
  const ctl = join(base, "job");
  const out = join(base, "out");
  await mkdir(join(out, "p1"), { recursive: true });
  await mkdir(ctl, { recursive: true });
  // Nothing refused: no hint, at any status.
  await writeFile(join(ctl, "stdout.log"), "wc: 0\n");
  await writeFile(join(ctl, "stderr.log"), "Traceback (most recent call last):\nKeyError: 'entries'\n");
  assert.equal(await execRefused({ ctl, out, cwd: RUN, exit: 1 }), null);
  assert.equal(await execRefused({ ctl, out, cwd: RUN, exit: 0 }), null);
  // Status 126 and no line anywhere (the shell's words went into a file of the job's own that is not a stderr file).
  await writeFile(join(out, "version.txt"), `/job/command.sh: line 29: ${OUT}/root/usr/bin/tool: Permission denied\n`);
  assert.deepEqual(await execRefused({ ctl, out, cwd: RUN, exit: 126 }), { error: null, path: null, file: null, line: null, lines: 0, files: 0 });
  // A line in a far corner of a long stdout, and in a kept stderr file.
  await writeFile(join(ctl, "stdout.log"), `${"x".repeat(3 << 20)}\nline\n/job/command.sh: line 9: ${RUN}/store/imports/mat-0002/out/prog: Permission denied\n`);
  await writeFile(join(out, "p1", "run.stderr"), `bash: ${OUT}/root/bin/tool: Permission denied\nbash: ${OUT}/root/bin/tool: Permission denied\n`);
  const x = await execRefused({ ctl, out, cwd: RUN, exit: 126 });
  assert.deepEqual(x, { error: "Permission denied", path: `${RUN}/store/imports/mat-0002/out/prog`, file: "stdout.log", line: 3, lines: 3, files: 2 });
  // At another status a permission denied is not read, and the loader's words still are, wherever they are said.
  assert.equal(await execRefused({ ctl, out, cwd: RUN, exit: 1 }), null);
  await writeFile(join(out, "p1", "run.stderr"), `${OUT}/root/bin/tool: error while loading shared libraries: ${OUT}/root/lib/libx.so.1: ${LOADER_REFUSAL}\nbash: ${OUT}/root/bin/tool: Permission denied\n${OUT}/root/bin/tool: error while loading shared libraries: ${OUT}/root/lib/libx.so.1: ${LOADER_REFUSAL}\n`);
  const y = await execRefused({ ctl, out, cwd: RUN, exit: 127 });
  assert.deepEqual(y, { error: LOADER_REFUSAL, path: `${OUT}/root/lib/libx.so.1`, file: "out/p1/run.stderr", line: 1, lines: 2, files: 1 });
  // Words: whole, never cut.
  const words = execRefusedWords(x!, { job: "j000090", out: OUT });
  assert.ok(words.includes(`${RUN}/store/imports/mat-0002/out/prog`), "the path is whole");
  assert.match(words, /^a program it ran could not be executed \("Permission denied" on \/runs\/s3472f0\/store\/imports\/mat-0002\/out\/prog, store\/jobs\/j000090\/stdout\.log line 3; 3 such lines in 2 files\)\./);
  assert.match(words, /Nothing a worker holds in store\/, work\/extracted\/, work\/quarantine\/, inputs\/ or its own \$OUT can be executed where it stands: sealed files have no execute bit and the others are mounted no-exec\./);
  assert.match(words, /Copy the program, and every library it loads, into an executable temporary directory inside the job \(for example one made with mktemp -d under \/tmp, which is the worker VM's own\), make it executable there and run it from that copy; what it writes that you want kept goes to \$OUT \(\/runs\/s3472f0\/\.jobs\/j000090\)$/);
  // Only a kept stderr file: cited as the job's output.
  const kept = execRefusedWords(y!, { job: "j000090", out: OUT });
  assert.match(kept, /\("failed to map segment from shared object" on \/runs\/s3472f0\/\.jobs\/j000090\/root\/lib\/libx\.so\.1, job:j000090\/p1\/run\.stderr line 1; 2 such lines in that file\)/);
  // The status alone: it says no line names the program, and where such a line may be.
  const bare = execRefusedWords({ error: null, path: null, file: null, line: null, lines: 0, files: 0 }, { job: "j000090", out: OUT });
  assert.match(bare, /^a program it ran could not be executed: exit 126 is the shell's status for a program it found and could not run, and no line in stdout\.log, stderr\.log or a stderr file the job kept says which \(if the program's stderr went into a file of the job's own, it is there\)\./);
  assert.match(bare, /Copy the program, and every library it loads, into an executable temporary directory inside the job/);
});

test("through the service: a job that could not execute a program has it in its reason, on its record, on the journal and in what its requester is told; the loader's refusal is no missing program, a missing program still is, and a refused write is still a refused write", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "xr-jobs-")), "run");
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
  const journal = () => readFileSync(storePaths(S).journal, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
  // A real program that cannot be run: a file with no execute bit, run by the shell; exit 126, the shell's own words on stderr.
  const denied = await run(`printf '#!/bin/sh\\necho hi\\n' > "$OUT/prog"; "$OUT/prog"`);
  assert.equal(denied.status, "failed");
  assert.equal(denied.exit, 126);
  const out = join(S, ".jobs", denied.id);
  // The local worker runs the job's script on this host, so the shell names the staging directory $OUT stands for here.
  assert.match(denied.reason ?? "", new RegExp(`^exit 126: a program it ran could not be executed \\("Permission denied" on \\S+/prog, store/jobs/${denied.id}/stderr\\.log line 1\\)\\. Nothing a worker holds in store/`));
  assert.ok((denied.reason ?? "").endsWith(`what it writes that you want kept goes to $OUT (${out})`));
  assert.match(denied.exec_refused?.path ?? "", /\/prog$/);
  assert.equal(denied.exec_refused?.error, "Permission denied");
  assert.equal(denied.program_missing, undefined);
  assert.equal(denied.write_refused, undefined, "an exec of a sealed file is not a refused write");
  assert.ok(journal().some((l) => l.type === "job_exec_refused" && l.job === denied.id && l.exit === 126 && l.path === denied.exec_refused?.path));
  assert.ok(journal().some((l) => l.type === "job_finished" && l.job === denied.id && l.reason === denied.reason), "the journal's job_finished carries the reason whole");
  assert.ok(describe(denied).includes(denied.reason!), "the post its requester gets says it whole");
  assert.equal((await jobView(S, denied)).reason, denied.reason, "and so does job_run's and job_status's answer");
  // The same on a sealed store file named relative to the run: exit 126, and not read as a write.
  mkdirSync(join(S, "store", "imports", "mat-0001", "out"), { recursive: true });
  writeFileSync(join(S, "store", "imports", "mat-0001", "out", "prog"), "#!/bin/sh\necho hi\n", { mode: 0o444 });
  const sealed = await run("store/imports/mat-0001/out/prog");
  assert.equal(sealed.exit, 126);
  assert.match(sealed.reason ?? "", new RegExp(`^exit 126: a program it ran could not be executed \\("Permission denied" on ${S.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/store/imports/mat-0001/out/prog, store/jobs/${sealed.id}/stderr\\.log line 1\\)`));
  assert.equal(sealed.write_refused, undefined);
  // Status 126 with the shell's words sent into a file of the job's own: no line names the program, and the reason says so.
  const hidden = await run(`printf '#!/bin/sh\\n' > "$OUT/prog"; "$OUT/prog" > "$OUT/version.txt" 2>&1`);
  assert.equal(hidden.exit, 126);
  assert.match(hidden.reason ?? "", /^exit 126: a program it ran could not be executed: exit 126 is the shell's status for a program it found and could not run, and no line in stdout\.log, stderr\.log or a stderr file the job kept says which/);
  assert.equal(hidden.exec_refused?.path, null);
  // The loader's refusal to map a segment (exit 127) is no program missing from the image.
  const mapped = await run(`echo "$OUT/root/usr/bin/tool: error while loading shared libraries: $OUT/root/usr/bin/tool: ${LOADER_REFUSAL}" >&2; exit 127`);
  assert.equal(mapped.exit, 127);
  assert.match(mapped.reason ?? "", new RegExp(`^exit 127: a program it ran could not be executed \\("${LOADER_REFUSAL}" on `));
  assert.equal(mapped.program_missing, undefined);
  assert.ok(!journal().some((l) => l.type === "job_program_missing" && l.job === mapped.id));
  // A directory made read-only inside $OUT and written to: a refused write in the job's own space is no program that could not be executed, and its reason is the exit status.
  if (process.getuid?.() !== 0) {
    const ro = await run(`mkdir "$OUT/ro" && chmod 555 "$OUT/ro" && touch "$OUT/ro/new"`);
    assert.equal(ro.exit, 1);
    assert.equal(ro.reason, "exit 1");
    assert.equal(ro.exec_refused, undefined);
  }
  // A program the image does not hold is still that.
  const missing = await run("no-such-program-here-xyz");
  assert.equal(missing.exit, 127);
  assert.match(missing.reason ?? "", /^exit 127: a program it runs is not in its image/);
  assert.equal(missing.exec_refused, undefined);
  // A refused write is still a refused write, and a failure that is neither keeps "exit N".
  const wrote = await run(`echo "OSError: [Errno 30] Read-only file system: '$PWD/notes.log'" >&2; exit 1`);
  assert.match(wrote.reason ?? "", /^exit 1: a write outside \$OUT was refused/);
  assert.equal(wrote.exec_refused, undefined);
  const other = await run(`echo "KeyError: 'entries'" >&2; exit 1`);
  assert.equal(other.reason, "exit 1");
  // A job that succeeded is not read for it, whatever its stderr says.
  const ok = await run(`echo "bash: $OUT/prog: Permission denied" >&2; exit 0`);
  assert.equal(ok.status, "ok");
  assert.equal(ok.exec_refused, undefined);
  await svc.stop("test over");
});

test("the worker prompt says where a program can and cannot be executed in a job", () => {
  const prompt = readFileSync(join(import.meta.dirname, "..", "prompts", "worker-system.md"), "utf8").replace(/\s+/g, " ");
  for (const must of [
    "A job cannot run a program where it stands in store/, work/extracted/, work/quarantine/, inputs/ or $OUT (sealed files have no execute bit and the others are no-exec): copy the program, and every library it loads, into an executable temporary directory inside the job and run it from the copy.",
    "A job that failed on this says so in its reason.",
  ]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
});
