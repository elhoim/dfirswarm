/**
 * A forged tool's arguments are brought to the types its manifest declares,
 * on a direct call and on job_run, and said; make_tool requires a self-test
 * and runs it before the tool is written or shared.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { coerceArgs, coercedWords, selfTestCandidate, selfTestProblem, type CandidateRun } from "../extensions/forged-args.ts";
import { runForgedTool, type ForgedToolManifest } from "../extensions/protocol.ts";
import { describe, JobService, jobView } from "../scripts/job-service.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

test("what a string plainly is under its declared type is taken as that, and said (the runs' 14 crashed calls)", () => {
  const params = { candidates: { type: "array" }, offset: { type: "integer" }, ratio: { type: "number" }, deep: { type: "boolean" }, opts: { type: "object" }, path: { type: "string" }, keys: { type: "array" } };
  const r = coerceArgs(params, { candidates: "[1, 2, 3]", offset: "4096", ratio: "0.5", deep: "TRUE", opts: '{"a": 1}', path: "42", keys: "204724, 204715,abc" });
  assert.deepEqual(r.args, { candidates: [1, 2, 3], offset: 4096, ratio: 0.5, deep: true, opts: { a: 1 }, path: "42", keys: [204724, 204715, "abc"] });
  assert.equal(r.coerced.length, 6, "the string parameter is left alone");
  assert.match(r.coerced.join("; "), /candidates \(a string\) was taken as an array of 3/);
  assert.deepEqual(coerceArgs({ offset: { type: "integer" } }, { offset: "0x10" }).args, { offset: 16 });
});

test("what is not plainly of the type is left as it came; values already of the type are untouched", () => {
  const params = { n: { type: "integer" }, list: { type: "array" }, o: { type: "object" }, flag: { type: "boolean" } };
  const args = { n: "12.5", list: "[1, 2", o: "[1]", flag: "yes", extra: "kept" };
  const r = coerceArgs(params, args);
  assert.deepEqual(r.args, args);
  assert.deepEqual(r.coerced, []);
  assert.deepEqual(coerceArgs(params, { n: 3, list: [1], o: {}, flag: false }).coerced, []);
  assert.deepEqual(coerceArgs(undefined, { a: "1" }), { args: { a: "1" }, coerced: [] });
});

// --- the self-test, run before a tool is written or shared (D6) ----------------------------------------------

test("a self-test is required: what is wrong with one as given is said", () => {
  assert.match(selfTestProblem(undefined) ?? "", /^selftest is required/);
  assert.match(selfTestProblem([]) ?? "", /^selftest is required/);
  assert.match(selfTestProblem({ args: [1], expect: "x" }) ?? "", /selftest\.args is the object/);
  assert.match(selfTestProblem({ args: {}, expect: "  " }) ?? "", /selftest\.expect is text/);
  assert.equal(selfTestProblem({ args: {}, expect: "x" }), null);
  assert.equal(selfTestProblem({ expect: "x" }), null, "a tool with no params is called with none");
  assert.equal(coercedWords([]), "");
  assert.equal(coercedWords(["n (a string) was taken as the integer 4"]), "Arguments taken as their declared types: n (a string) was taken as the integer 4.");
});

test("a tool's self-test runs on its script staged in the author's own directory, from the run's directory, with typed arguments, and leaves nothing behind", async () => {
  const root = await mkdtemp(join(tmpdir(), "selftest-"));
  try {
    await mkdir(join(root, "work", "a1"), { recursive: true });
    await writeFile(join(root, "work", "a1", "data.txt"), "one\ntwo\nthree\n");
    const tool = { name: "count_lines", description: "count", runtime: "python3" as const, params: { path: { type: "string" }, extra: { type: "integer" } }, script: "import json,sys\nd=json.load(sys.stdin)\nassert isinstance(d.get('extra',0), int)\nprint(json.dumps({'lines': sum(1 for _ in open(d['path'])), 'extra': d.get('extra')}))\n" };
    const run: CandidateRun = (r, m, args, o) => runForgedTool(r, m as unknown as ForgedToolManifest, args, o);
    const passed = await selfTestCandidate(root, "a1", tool, { args: { path: "work/a1/data.txt", extra: "7" }, expect: '"lines": 3' }, run);
    assert.deepEqual([passed.passed, passed.exit, passed.coerced], [true, 0, ["extra (a string) was taken as the integer 7"]]);
    assert.match(passed.said, /its self-test passed/);
    const wrong = await selfTestCandidate(root, "a1", tool, { args: { path: "work/a1/data.txt" }, expect: '"lines": 4' }, run);
    assert.equal(wrong.passed, false);
    assert.match(wrong.said, /^its self-test failed \(the output did not hold "\\"lines\\": 4"\)$/);
    const crash = await selfTestCandidate(root, "a1", { ...tool, script: "import sys\nsys.stderr.write('boom\\n')\nsys.exit(3)\n" }, { args: {}, expect: "x" }, run);
    assert.deepEqual([crash.passed, crash.exit], [false, 3]);
    assert.match(crash.said, /^its self-test failed \(exit 3: boom\)$/);
    // Nothing is left: not in tools/, and the staged copy is gone.
    assert.ok(!existsSync(join(root, "tools")), "no tool was written");
    assert.deepEqual(await readdir(join(root, "work", "a1")), ["data.txt"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("job_run takes a tool's arguments as the types its manifest declares, as a direct call does, and says so in the job's answer", async () => {
  const S = join(await mkdtemp(join(tmpdir(), "forged-jobrun-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs", "x.txt"), "x\n");
  listInputs(S);
  const body = "import json,sys,os\nd=json.load(sys.stdin)\nopen(os.path.join(os.environ['OUT'],'sum.txt'),'w').write(str(d['n'] + sum(d['list'])))\nprint(json.dumps({'sum': d['n'] + sum(d['list'])}))\n";
  await mkdir(join(S, "tools", "adder"), { recursive: true });
  await writeFile(join(S, "tools", "adder", "run.py"), body);
  await writeFile(join(S, "tools", "adder", "manifest.json"), JSON.stringify({ name: "adder", description: "adds", params: { n: { type: "integer", required: true }, list: { type: "array", required: true } }, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "a2", at: "t", version: 1, sha256: createHash("sha256").update(body).digest("hex") }));
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: true, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }) });
  await svc.start();
  try {
    const r = await svc.submit("a1", { kind: "tool", tool: "adder", args: { n: "4096", list: "[1, 2, 3]" }, inputs: [] });
    assert.ok(r.ok, JSON.stringify(r));
    if (!r.ok) return;
    assert.deepEqual(r.job.spec.args, { n: 4096, list: [1, 2, 3] });
    assert.deepEqual(r.job.spec.args_coerced, ["n (a string) was taken as the integer 4096", "list (a string) was taken as an array of 3"]);
    for (let i = 0; i < 400 && svc.jobs.get(r.job.id)?.state !== "committed"; i++) await new Promise((res) => setTimeout(res, 25));
    const done = svc.jobs.get(r.job.id)!;
    assert.deepEqual([done.state, done.status], ["committed", "ok"], "the tool did not crash on its first call");
    assert.match(describe(done), /Arguments taken as their declared types: n \(a string\) was taken as the integer 4096; list \(a string\) was taken as an array of 3\./);
    assert.match(String((await jobView(S, done)).args_coerced), /^Arguments taken as their declared types: /);
    // What is not plainly of its type is still refused, by the manifest's own check.
    const bad = await svc.submit("a1", { kind: "tool", tool: "adder", args: { n: "four", list: [1] }, inputs: [] });
    assert.deepEqual(bad, { ok: false, reason: "tool adder: n must be an integer" });
  } finally {
    await svc.stop("over");
    spawnSync("chmod", ["-R", "u+w", join(S, "..")]);
    await rm(join(S, ".."), { recursive: true, force: true });
  }
});

// --- a forged tool's call ends at its limit, whatever its descendants do -----------------------------------------

const EXT = { python3: "py", bash: "sh", node: "mjs" } as const;
/** A tool written under tools/<name>/ and run as runForgedTool runs one, with its seal given. */
async function stagedTool(root: string, name: string, runtime: keyof typeof EXT, script: string, timeout_seconds: number) {
  await mkdir(join(root, "tools", name), { recursive: true });
  const entry = `run.${EXT[runtime]}`;
  await writeFile(join(root, "tools", name, entry), script);
  const sha256 = createHash("sha256").update(script).digest("hex");
  const manifest: ForgedToolManifest = { name, description: "", params: {}, runtime, entry, timeout_seconds, by: "a1", at: "t", version: 1, sha256 };
  return { manifest, sealed: sha256 };
}
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const readPid = async (file: string) => Number((await readFile(file, "utf8").catch(() => "")).trim()) || 0;
/** True once nothing is left in the process group (a killed member may need a moment to be reaped). */
async function groupGone(pgid: number): Promise<boolean> {
  for (let i = 0; i < 40; i++) {
    if (!alive(-pgid)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}
/** A process the tool started in a session of its own: ended by the test, which the harness cannot see. */
async function endEscaped(file: string) {
  for (let i = 0; i < 20; i++) {
    const pid = await readPid(file);
    if (pid) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // already gone
      }
      return;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}
// Waits until the forked child has its own session, so the group kill cannot reach it first.
const SETSID_PY = (tail: string) =>
  `import os, sys, time\nif os.fork() == 0:\n    os.setsid()\n    open('esc.pid', 'w').write(str(os.getpid()))\n    time.sleep(30)\n    os._exit(0)\nwhile not os.path.exists('esc.pid'):\n    time.sleep(0.02)\nopen('grp.pid', 'w').write(str(os.getpgrp()))\nprint('x')\nsys.stdout.flush()\n${tail}`;

test("a tool whose child leaves the group and keeps stdout open returns when the tool ends, with its output, not when the child does", async () => {
  const root = await mkdtemp(join(tmpdir(), "forged-limit-"));
  try {
    const t = await stagedTool(root, "daemon_left", "python3", SETSID_PY(""), 10);
    const started = Date.now();
    const run = await runForgedTool(root, t.manifest, {}, { sealed: t.sealed });
    const took = Date.now() - started;
    assert.deepEqual([run.ok, run.exit_code, run.timed_out, run.stdout.trim()], [true, 0, false, "x"], JSON.stringify(run));
    assert.ok(took < 3000, `returned after ${took} ms, not after the 30 s child`);
    assert.ok(alive(await readPid(join(root, "esc.pid"))), "the child that left the group is the one the call no longer waits on");
    assert.ok(await groupGone(await readPid(join(root, "grp.pid"))), "nothing is left in the tool's group");
  } finally {
    await endEscaped(join(root, "esc.pid"));
    await rm(root, { recursive: true, force: true });
  }
});

test("a tool that hangs while its child holds stdout from a session of its own ends at its limit with what it printed", async () => {
  const root = await mkdtemp(join(tmpdir(), "forged-limit-"));
  try {
    const t = await stagedTool(root, "daemon_hang", "python3", SETSID_PY("time.sleep(30)\n"), 2);
    const started = Date.now();
    const run = await runForgedTool(root, t.manifest, {}, { sealed: t.sealed });
    const took = Date.now() - started;
    assert.deepEqual([run.ok, run.timed_out, run.stdout.trim()], [false, true, "x"], JSON.stringify(run));
    assert.ok(took < 2000 + 2500, `returned ${took} ms after it started, its limit being 2 s`);
    assert.ok(await groupGone(await readPid(join(root, "grp.pid"))), "nothing is left in the tool's group");
  } finally {
    await endEscaped(join(root, "esc.pid"));
    await rm(root, { recursive: true, force: true });
  }
});

test("a tool that ignores SIGTERM ends at its limit; a backgrounded child in its group ends when the tool does", async () => {
  const root = await mkdtemp(join(tmpdir(), "forged-limit-"));
  try {
    const stubborn = await stagedTool(root, "stubborn", "bash", "trap '' TERM\necho $$ > grp.pid\necho started\nwhile :; do sleep 1; done\n", 2);
    let started = Date.now();
    const run = await runForgedTool(root, stubborn.manifest, {}, { sealed: stubborn.sealed });
    let took = Date.now() - started;
    assert.deepEqual([run.ok, run.timed_out, run.stdout.trim()], [false, true, "started"], JSON.stringify(run));
    assert.ok(took < 2000 + 2500, `returned after ${took} ms`);
    assert.ok(await groupGone(await readPid(join(root, "grp.pid"))), "nothing is left in the tool's group");

    // The tool exits at once; its `sleep` holds stdout from the same group. The call used to wait for the limit.
    const bg = await stagedTool(root, "backgrounded", "bash", "echo $$ > grp2.pid\nsleep 30 &\necho x\n", 20);
    started = Date.now();
    const bgRun = await runForgedTool(root, bg.manifest, {}, { sealed: bg.sealed });
    took = Date.now() - started;
    assert.deepEqual([bgRun.ok, bgRun.timed_out, bgRun.stdout.trim()], [true, false, "x"], JSON.stringify(bgRun));
    assert.ok(took < 3000, `returned after ${took} ms, not at its 20 s limit`);
    assert.ok(await groupGone(await readPid(join(root, "grp2.pid"))), "the backgrounded sleep ended with the tool");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("make_tool's self-test (the same runner) ends at the tool's limit when a child left the group", async () => {
  const root = await mkdtemp(join(tmpdir(), "forged-limit-"));
  try {
    await mkdir(join(root, "work", "a1"), { recursive: true });
    const run: CandidateRun = (r, m, args, o) => runForgedTool(r, m as unknown as ForgedToolManifest, args, o);
    let started = Date.now();
    const quick = await selfTestCandidate(root, "a1", { name: "daemon", runtime: "python3", script: SETSID_PY(""), timeout_seconds: 2 }, { args: {}, expect: "x" }, run);
    assert.deepEqual([quick.passed, quick.exit, quick.timed_out], [true, 0, false], quick.said);
    assert.ok(Date.now() - started < 3000, "the self-test passed when the tool ended, not when its child did");
    await endEscaped(join(root, "esc.pid"));
    await rm(join(root, "esc.pid"), { force: true });
    started = Date.now();
    const hung = await selfTestCandidate(root, "a1", { name: "daemon", runtime: "python3", script: SETSID_PY("time.sleep(30)\n"), timeout_seconds: 2 }, { args: {}, expect: "x" }, run);
    assert.deepEqual([hung.passed, hung.timed_out], [false, true], hung.said);
    assert.match(hung.said, /timed out/);
    assert.ok(Date.now() - started < 2000 + 2500, "the self-test failed at its limit");
  } finally {
    await endEscaped(join(root, "esc.pid"));
    await rm(root, { recursive: true, force: true });
  }
});

const HAS_SETSID = process.platform === "linux" && spawnSync("setsid", ["true"]).status === 0;
test("a bash tool that starts `setsid sh -c 'sleep 30' &` holding stdout ends at its limit (Linux)", { skip: HAS_SETSID ? false : "setsid(1) is Linux's" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "forged-limit-"));
  try {
    const t = await stagedTool(root, "setsid_sleep", "bash", "echo $$ > grp.pid\nsetsid sh -c 'echo $$ > esc.pid; exec sleep 30' &\necho started\nsleep 30\n", 2);
    const started = Date.now();
    const run = await runForgedTool(root, t.manifest, {}, { sealed: t.sealed });
    const took = Date.now() - started;
    assert.deepEqual([run.ok, run.timed_out, run.stdout.trim()], [false, true, "started"], JSON.stringify(run));
    assert.ok(took < 2000 + 2500, `returned after ${took} ms, its limit being 2 s`);
    assert.ok(await groupGone(await readPid(join(root, "grp.pid"))), "nothing is left in the tool's group");
  } finally {
    await endEscaped(join(root, "esc.pid"));
    await rm(root, { recursive: true, force: true });
  }
});
