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
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
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
