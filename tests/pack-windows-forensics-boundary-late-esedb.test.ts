/**
 * esedb_query past the judging time: the clock of the seal forced to be out (SEAL_BUDGET below zero in a copy of the tool), the answer is still readable
 * (its keys, its status basis, the name of the database and of the export are the tool's own words and are not withheld), and what the evidence supplied
 * that is not short and plain is still withheld.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { AGENT, WIN, stub } from "./windows-pack-harness.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PLACEHOLDER = /^<withheld \d+ (?:characters|bytes)/;
const COPY_EXPORTER = `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
mkdir -p "$root.export"
cp "$FIXTURE" "$root.export/T.0"
`;

function placeholderKeys(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => placeholderKeys(v, `${path}[${i}]`));
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => (PLACEHOLDER.test(k) ? [`${path}/${k}`] : []).concat(placeholderKeys(v, `${path}/${k}`)));
  }
  return [];
}

test("esedb_query: past the judging time the answer keeps its keys, its status basis and the names of its export, and withholds the cells that are not short and plain", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", COPY_EXPORTER);
    await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
    await writeFile(join(cwd, "fixture.tsv"), "Id\tData\n1\ta cell that is longer than fifteen characters\n2\tshort\n", "utf8");
    const env = { FIXTURE: join(cwd, "fixture.tsv"), ...AGENT };
    const text = (await readFile(join(WIN, "esedb_query", "run.py"), "utf8")).replace("SEAL_BUDGET = 10.0", "SEAL_BUDGET = -1.0");
    assert.ok(text.includes("SEAL_BUDGET = -1.0"));
    const file = join(cwd, "patched", "esedb_query.py");
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, text, "utf8");
    for (const args of [{ path: "work/x.edb" }, { path: "work/x.edb", table: "T", limit: 1 }]) {
      const run = await runPy(file, cwd, args, bin, env);
      assert.equal(run.code, 0, run.stderr + run.stdout);
      assert.doesNotMatch(run.stderr, /Traceback/);
      const answer = JSON.parse(run.stdout) as Answer;
      assert.deepEqual(placeholderKeys(answer), [], `no key of the answer is withheld: ${JSON.stringify(args)}`);
      assert.equal(answer.path, "work/x.edb");
      assert.equal(typeof answer.status_basis, "string");
      assert.doesNotMatch(answer.status_basis, PLACEHOLDER, "the reason is readable");
      assert.doesNotMatch(String(answer.export_dir), PLACEHOLDER, "the name of the export is kept");
      assert.ok(!run.stdout.includes("longer than fifteen"), "the cell is not printed");
    }
  });
});
