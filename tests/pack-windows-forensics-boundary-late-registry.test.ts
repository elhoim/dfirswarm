/**
 * regkv, shellbags and amcache_apps past the judging time: the clock of the seal forced to be out (SEAL_BUDGET below zero in a copy of the tool), the answer is still
 * readable (its keys, its status basis, the name of the hive and of the result files are the tool's own words and are not withheld), what the evidence supplied
 * that is not short and plain is still withheld, and a walk that ran out of its own time names a bounded number of the branches it did not open and counts the rest.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { AGENT, WIN } from "./windows-pack-harness.ts";
import { VARIANTS, type Node, type Val } from "./windows-stub-regipy.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const V = VARIANTS.find((v) => v.real && !v.skip) ?? VARIANTS[0];
const PLACEHOLDER = /^<withheld \d+ (?:characters|bytes)/;

/** A copy of a tool with some of its text changed (each change must be found), run on `args`. */
async function runPatched(name: string, cwd: string, edits: Array<[string, string]>, args: unknown, env: Record<string, string>): Promise<{ answer: Answer; stdout: string }> {
  let text = await readFile(join(WIN, name, "run.py"), "utf8");
  for (const [from, to] of edits) {
    assert.ok(text.includes(from), `${name}: ${from}`);
    text = text.replace(from, to);
  }
  const file = join(cwd, "patched", `${name}.py`);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, text, "utf8");
  const run = await runPy(file, cwd, args, undefined, { ...AGENT, ...env });
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  return { answer: JSON.parse(run.stdout) as Answer, stdout: run.stdout };
}

/** Every key, at any depth, that is a placeholder. */
function placeholderKeys(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => placeholderKeys(v, `${path}[${i}]`));
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => (PLACEHOLDER.test(k) ? [`${path}/${k}`] : []).concat(placeholderKeys(v, `${path}/${k}`)));
  }
  return [];
}

const OUT_OF_TIME: [string, string] = ["SEAL_BUDGET = 10.0", "SEAL_BUDGET = -1.0"];
/** The words of an answer that are the tool's own: a reader needs them to find the result and to know why it is partial. */
function ownWordsKept(answer: Answer, hive: string): void {
  assert.deepEqual(placeholderKeys(answer), [], "no key of the answer is withheld");
  assert.equal(answer.hive, hive, "the name of the hive is kept");
  assert.equal(typeof answer.status_basis, "string");
  assert.doesNotMatch(answer.status_basis, PLACEHOLDER, "the reason the answer is partial is readable");
  assert.ok(["complete", "partial"].includes(answer.status), answer.status);
}

test("regkv: past the judging time the answer keeps its keys, its status basis and the names of its result files, and a walk that ran out of time names a bounded number of the branches it did not open", async () => {
  await withCwd(async (cwd) => {
    const leaf = (n: number): Node => ({ name: `d${n}`, values: [{ name: "v", type: "sz" as const, value: "x" }] });
    const wide: Node = {
      name: "Wide",
      values: [{ name: "Note", type: "sz" as const, value: "a value of the root key that is longer than fifteen characters" }],
      children: Array.from({ length: 30 }, (_, i) => ({ name: `c${String(i).padStart(2, "0")}`, children: [leaf(0), leaf(1), leaf(2)] })),
    };
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [wide] });
    const { answer, stdout } = await runPatched(
      "regkv",
      cwd,
      [OUT_OF_TIME, ["        if out_of_time():\n            out_of_time_at = seen", "        if seen >= 8 or out_of_time():\n            out_of_time_at = seen"], ["MAX_UNOPENED_LISTED = 1000", "MAX_UNOPENED_LISTED = 10"]],
      { hive: "work/SOFTWARE", key: "Wide", recurse: true, depth: 5, limit: 5 },
      env,
    );
    ownWordsKept(answer, "work/SOFTWARE");
    assert.equal(answer.status, "partial");
    assert.equal(answer.walk_stopped_by_time_limit, true);
    assert.equal(answer.stopped_branch_count, 30, "every branch left unopened is counted");
    assert.equal(answer.stopped_branches_not_named, 20, "and the ones past the first ten are said not to be named");
    assert.equal(answer.stopped_branches.length, 10, "ten are named");
    assert.equal(typeof answer.tree_complete, "boolean");
    assert.equal(answer.nodes_listed, 30);
    assert.match(answer.status_basis, /30 branch\(es\) were not entered/);
    for (const field of ["all_nodes", "all_subkeys"]) if (answer[field] !== undefined) assert.doesNotMatch(answer[field], PLACEHOLDER, `${field} names a file`);
    assert.ok(!stdout.includes("a value of the root key"), "the value of the root key is not printed");
    assert.match(String(answer.values.Note), PLACEHOLDER, "an evidence string that is not short and plain is still a placeholder");
  });
});

test("regkv: without the late path (the clock untouched) the same fixture is read to its end and nothing is counted as unopened", async () => {
  await withCwd(async (cwd) => {
    const wide: Node = { name: "Wide", children: Array.from({ length: 30 }, (_, i) => ({ name: `c${i}`, children: [{ name: "d0" }, { name: "d1" }] })) };
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [wide] });
    const run = await runPy(join(WIN, "regkv", "run.py"), cwd, { hive: "work/SOFTWARE", key: "Wide", recurse: true, depth: 5, limit: 5 }, undefined, { ...AGENT, ...env });
    const answer = JSON.parse(run.stdout) as Answer;
    assert.equal(answer.stopped_branch_count, 0);
    assert.equal(answer.stopped_branches_not_named, undefined);
    assert.equal(answer.walk_stopped_by_time_limit, false);
    assert.equal(answer.nodes_listed, 90);
  });
});

test("shellbags: past the judging time the answer keeps its keys, its status basis and the name of the hive", async () => {
  await withCwd(async (cwd) => {
    const item = (text: string): Buffer => {
      const content = Buffer.concat([Buffer.from([0x4e, 0x00]), Buffer.from(text, "latin1"), Buffer.from([0])]);
      const size = Buffer.alloc(2);
      size.writeUInt16LE(content.length + 2);
      return Buffer.concat([size, content]);
    };
    const texts = ["Documents", "a folder whose name is longer than fifteen characters"];
    const values: Val[] = texts.map((t, i) => ({ name: String(i), type: "binary" as const, value: item(t) }));
    const bag: Node = { name: "BagMRU", values, children: texts.map((_, i) => ({ name: String(i) })) };
    const env = await V.write(cwd, "work/UsrClass.dat", { name: "HIVE", children: [{ name: "Local Settings", children: [{ name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] }] }] });
    const { answer, stdout } = await runPatched("shellbags", cwd, [OUT_OF_TIME], { hive: "work/UsrClass.dat", limit: 5 }, env);
    ownWordsKept(answer, "work/UsrClass.dat");
    assert.ok(!stdout.includes("whose name is longer"), "the long name is not printed");
    assert.ok(answer.entry_count >= 1);
  });
});

test("amcache_apps: past the judging time the answer keeps its keys, its status basis and the name of the hive", async () => {
  await withCwd(async (cwd) => {
    const rows: Node[] = [0, 1].map((i) => ({ name: `${i}`, values: [{ name: "LowerCaseLongPath", type: "sz" as const, value: `c:\\program files\\a program with a long name ${i}\\tool.exe` }, { name: "Publisher", type: "sz" as const, value: "Example" }] }));
    const env = await V.write(cwd, "work/Amcache.hve", { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] });
    const { answer, stdout } = await runPatched("amcache_apps", cwd, [OUT_OF_TIME], { hive: "work/Amcache.hve", limit: 5 }, env);
    ownWordsKept(answer, "work/Amcache.hve");
    assert.ok(!stdout.includes("a program with a long name"), "the long path is not printed");
    assert.ok(answer.entry_count >= 1);
  });
});
