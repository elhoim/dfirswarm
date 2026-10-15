/**
 * The macOS CI job is split in parts that run side by side: one runs the
 * typecheck and every node suite, the others the shell suites, `--shard I/N`
 * each (scripts/test-bash.sh). Splitting must not lose a test, so this suite
 * reads the workflow and the shard assignment and fails if any shell suite is
 * in no shard, in two, or if the node suites are not all run by one part.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { nodeSuites } from "../scripts/test-node.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKFLOW = readFileSync(join(ROOT, ".github/workflows/ci.yml"), "utf8");

/** Every shell suite's stem, as `scripts/test-bash.sh` finds them. */
function allShellSuites(): string[] {
  return readdirSync(join(ROOT, "tests"))
    .filter((f) => f.endsWith(".test.sh"))
    .map((f) => f.slice(0, -".test.sh".length))
    .sort();
}

/** The stems shard `i/n` runs, from the script itself (`--list` runs nothing). */
function shardOf(i: number, n: number): string[] {
  const out = execFileSync("bash", [join(ROOT, "scripts/test-bash.sh"), "--shard", `${i}/${n}`, "--list"], { encoding: "utf8" });
  return out.split("\n").filter(Boolean);
}

/** The text of the `macos:` job in ci.yml, up to the next job. */
function macosJob(): string {
  const m = WORKFLOW.match(/^ {2}macos:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))/m);
  assert.ok(m, "ci.yml has no `macos:` job");
  return m[1];
}

test("any number of shards holds every shell suite exactly once", () => {
  const all = allShellSuites();
  assert.ok(all.length > 0);
  for (const n of [1, 2, 3, 4]) {
    const shards = Array.from({ length: n }, (_, k) => shardOf(k + 1, n));
    const seen = shards.flat();
    assert.deepEqual([...seen].sort(), all, `${n} shards: their union is not the full list, or a suite is in two`);
    if (all.length >= n) for (const [k, s] of shards.entries()) assert.ok(s.length > 0, `${n} shards: shard ${k + 1} is empty`);
  }
});

test("a shard is the same on every call and does not depend on what is named", () => {
  assert.deepEqual(shardOf(1, 2), shardOf(1, 2));
  assert.deepEqual(shardOf(2, 3), shardOf(2, 3));
});

test("a bad shard or a shard with named suites is refused", () => {
  for (const args of [["--shard", "0/2"], ["--shard", "3/2"], ["--shard", "x"], ["--shard", "1/2", "reap"], ["--shard", ""], ["--shard"], ["--shard="], ["--bogus"]]) {
    assert.throws(() => execFileSync("bash", [join(ROOT, "scripts/test-bash.sh"), ...args, "--list"], { stdio: "pipe" }), (e: { status?: number }) => e.status === 2, args.join(" "));
  }
});

test("the weights file names only suites that exist, once each", () => {
  const all = allShellSuites();
  const names = readFileSync(join(ROOT, "tests/shell-suites.weights"), "utf8")
    .split("\n")
    .map((l) => l.replace(/#.*$/, "").trim())
    .filter(Boolean)
    .map((l) => {
      const [stem, secs] = l.split(/\s+/);
      assert.match(secs ?? "", /^[1-9]\d*$/, `weights line '${l}'`);
      return stem;
    });
  assert.deepEqual(names.filter((n) => !all.includes(n)), [], "a weights line names a suite that no longer exists: remove it");
  assert.equal(new Set(names).size, names.length, "a suite is weighed twice");
});

test("the macOS job's parts together run every node suite and every shell suite", () => {
  const job = macosJob();
  // Node: exactly one matrix entry has `node: true`, and its steps run the
  // whole of `npm test` (scripts/test-node.ts finds every suite itself).
  assert.equal((job.match(/^\s+node: true$/gm) ?? []).length, 1, "exactly one part runs the node tests");
  assert.match(job, /- name: Node tests\n\s+if: matrix\.node\n\s+run: npm test\n/, "the node part must run plain `npm test`, with no filter");
  assert.match(job, /if: matrix\.node\n\s+run: npm run typecheck\n/, "the typecheck stays in the node part");
  // Shell: the matrix names every shard 1..N of one N, and the step passes it on.
  const shards = [...job.matchAll(/^\s+shard: "(\d+)\/(\d+)"$/gm)].map((m) => [Number(m[1]), Number(m[2])]);
  assert.ok(shards.length >= 1, "no shell part in the macOS job");
  const n = shards[0][1];
  assert.deepEqual(shards.map(([i]) => i).sort(), Array.from({ length: n }, (_, k) => k + 1), "the shell parts must be shards 1..N, each once");
  assert.ok(shards.every(([, m]) => m === n), "the shell parts name different shard counts");
  assert.match(job, /if: matrix\.shard\n\s+run: npm run test:bash -- --shard \$\{\{ matrix\.shard \}\}\n/, "the shell step must pass the part's own shard on");
  // And that shard count, applied by the script, covers all of them.
  const ran = Array.from({ length: n }, (_, k) => shardOf(k + 1, n)).flat();
  assert.deepEqual([...ran].sort(), allShellSuites());
});

test("the node suites npm test runs are found by scripts/test-node.ts, none lost to a filter", () => {
  const { run, skipped } = nodeSuites(ROOT);
  assert.ok(run.includes("tests/ci-shards.test.ts"), "this suite must be one of them");
  // The only node suites left out are the ones tests/node-tests.skip names.
  const onDisk = (readdirSync(join(ROOT, "tests"), { recursive: true }) as string[]).filter((p) => p.endsWith(".test.ts") && !p.split("/").includes("fixtures")).length;
  assert.equal(run.length + skipped.length, onDisk);
});
