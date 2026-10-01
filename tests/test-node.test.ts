/**
 * `npm test` finds its suites (scripts/test-node.ts): every tests/**\/*.test.ts
 * but the fixtures and the ones tests/node-tests.skip names, and a skip entry
 * that names no suite fails rather than going stale.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { nodeSuites, readSkipList } from "../scripts/test-node.ts";

test("the repository's suites: the VM ones are skipped, this one and the nested rule tests run", () => {
  const { run, skipped } = nodeSuites();
  assert.ok(run.includes("tests/test-node.test.ts"));
  assert.ok(run.some((p) => p.startsWith("tests/rules/")), "a suite one directory down runs too");
  for (const vm of ["tests/vm-integration.test.ts", "tests/vm-jobs.test.ts", "tests/vm-secret-rotation.test.ts", "tests/job-observe-vm.test.ts"]) {
    assert.ok(skipped.includes(vm) && !run.includes(vm), vm);
  }
  assert.deepEqual(run, [...run].sort());
});

test("discovery skips fixtures, and a stale skip entry fails", () => {
  const root = mkdtempSync(join(tmpdir(), "test-node-"));
  try {
    mkdirSync(join(root, "tests", "fixtures", "x"), { recursive: true });
    mkdirSync(join(root, "tests", "deeper"), { recursive: true });
    for (const f of ["tests/a.test.ts", "tests/b.test.ts", "tests/deeper/c.test.ts", "tests/fixtures/x/d.test.ts", "tests/helper.ts"]) writeFileSync(join(root, f), "");
    writeFileSync(join(root, "tests", "node-tests.skip"), "# why\ntests/b.test.ts   # it boots something\n\n");
    assert.deepEqual(nodeSuites(root), { run: ["tests/a.test.ts", "tests/deeper/c.test.ts"], skipped: ["tests/b.test.ts"] });
    writeFileSync(join(root, "tests", "node-tests.skip"), "tests/gone.test.ts # removed long ago\n");
    assert.throws(() => nodeSuites(root), /names tests\/gone\.test\.ts, which no node suite is/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the skip list reads paths and drops comments and blank lines", () => {
  assert.deepEqual(readSkipList("# head\n\ntests/x.test.ts  # why\n  tests/y.test.ts\n"), ["tests/x.test.ts", "tests/y.test.ts"]);
});
