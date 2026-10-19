/**
 * evtx_query and evtx_carve past the judging time: the clock of the seal forced to be out (SEAL_BUDGET below zero in a copy of the tool), the answer is still
 * readable (its keys, its status basis, the name of the log and of the result file are the tool's own words and are not withheld), and what the evidence
 * supplied that is not short and plain is still withheld.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { AGENT, WIN, stubModule } from "./windows-pack-harness.ts";
import { EVTX_CARVE_STUB, eventXml, evtxChunk, evtxFileHeader } from "./windows-stub-evtx.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PLACEHOLDER = /^<withheld \d+ (?:characters|bytes)/;
const LONG = "a command line that is longer than fifteen characters";

async function put(cwd: string): Promise<Record<string, string>> {
  const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
  const records = [1, 2, 3].map((n) => ({ number: n, xml: eventXml({ eid: 4688, rec: n, time: "2026-09-01 10:00:00.000000", data: [["CommandLine", LONG], ["Payload", "x"]] }) }));
  const chunk = evtxChunk(records);
  await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(1, records.length + 1), chunk]));
  await writeFile(join(cwd, "work", "Security.evtx.inject.json"), "{}");
  await writeFile(join(cwd, "work", "blob.bin"), chunk);
  return stubs;
}

async function runPatched(name: string, cwd: string, args: unknown, env: Record<string, string>): Promise<{ answer: Answer; stdout: string }> {
  const text = (await readFile(join(WIN, name, "run.py"), "utf8")).replace("SEAL_BUDGET = 10.0", "SEAL_BUDGET = -1.0");
  assert.ok(text.includes("SEAL_BUDGET = -1.0"), name);
  const file = join(cwd, "patched", `${name}.py`);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, text, "utf8");
  const run = await runPy(file, cwd, args, undefined, { ...AGENT, ...env });
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  return { answer: JSON.parse(run.stdout) as Answer, stdout: run.stdout };
}

function placeholderKeys(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => placeholderKeys(v, `${path}[${i}]`));
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => (PLACEHOLDER.test(k) ? [`${path}/${k}`] : []).concat(placeholderKeys(v, `${path}/${k}`)));
  }
  return [];
}

for (const [name, file, args] of [["evtx_query", "work/Security.evtx", { path: "work/Security.evtx", limit: 1 }], ["evtx_carve", "work/blob.bin", { path: "work/blob.bin", limit: 1 }]] as const) {
  test(`${name}: past the judging time the answer keeps its keys, its status basis and the name of its result file, and withholds the evidence that is not short and plain`, async () => {
    await withCwd(async (cwd) => {
      const env = await put(cwd);
      const { answer, stdout } = await runPatched(name, cwd, args, env);
      assert.deepEqual(placeholderKeys(answer), [], "no key of the answer is withheld");
      assert.equal(answer.path, file, "the name of the log is kept");
      assert.equal(typeof answer.status_basis, "string");
      assert.doesNotMatch(answer.status_basis, PLACEHOLDER, "the reason the answer is partial is readable");
      assert.equal(answer.status, "partial");
      const resultFile = answer.result_file ?? answer.all_results;
      assert.equal(typeof resultFile, "string", "a result file is named");
      assert.doesNotMatch(resultFile, PLACEHOLDER, "the name of the result file is kept");
      assert.ok(!stdout.includes("longer than fifteen"), "the command line is not printed");
      assert.ok(answer.boundary.strings_replaced_by_the_backstop >= 1);
    });
  });
}

test("evtx_query: a contains filter that matches does not change what the answer counts as withheld, or what the values file holds", async () => {
  const secret = "pass" + "word=" + "Xk7hQ2mP9wZr";
  const count = async (extra: Record<string, unknown>, tag: string): Promise<{ withheld: number; lines: number; by: unknown }> => {
    let out = { withheld: -1, lines: -1, by: {} as unknown };
    await withCwd(async (cwd) => {
      const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
      const records = [1, 2].map((n) => ({ number: n, xml: eventXml({ eid: 4688, rec: n, time: "2026-09-01 10:00:00.000000", data: [["CommandLine", `C:\\Windows\\tool.exe ${secret}${n}`]] }) }));
      const chunk = evtxChunk(records);
      await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(1, records.length + 1), chunk]));
      await writeFile(join(cwd, "work", "Security.evtx.inject.json"), "{}");
      const dir = join(cwd, "job-out", tag);
      await mkdir(dir, { recursive: true });
      const run = await runPy(join(WIN, "evtx_query", "run.py"), cwd, { path: "work/Security.evtx", write_values: true, ...extra }, undefined, { ...AGENT, ...stubs, JOB_ID: "j1", OUT: dir, SECRET_OUTPUT: "1" });
      assert.equal(run.code, 0, run.stderr + run.stdout);
      const answer = JSON.parse(run.stdout) as Answer;
      const values = (await readFile(join(dir, "evtx_query-values.jsonl"), "utf8")).split("\n").filter(Boolean);
      assert.ok(!run.stdout.includes("Xk7hQ2mP9wZr"), "the secret is not printed");
      out = { withheld: answer.boundary.strings_withheld, lines: values.length, by: answer.boundary.withheld_by_reason };
    });
    return out;
  };
  const plain = await count({}, "plain");
  const matching = await count({ contains: "tool.exe" }, "matching");
  const missing = await count({ contains: "no-such-text" }, "missing");
  assert.ok(plain.withheld >= 2 && plain.lines >= 2, JSON.stringify(plain));
  assert.deepEqual(matching, plain, "a matching contains");
  assert.deepEqual(missing, { withheld: 0, lines: 0, by: {} }, "a contains that matches nothing prints no record, so judging them for the filter counts and writes nothing");
});
