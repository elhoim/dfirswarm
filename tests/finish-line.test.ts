/**
 * done runs the finish line before it writes the sentinel. On run sb36f a nano
 * agent ended a 25 GB case after four minutes by calling done when its own
 * slice was finished: no report, no timeline, three peers stopped. The checks
 * are the operator's and always were; what changed is that they are run at the
 * moment they matter. And the claim ledger stays out of the shared install
 * area, where two agents pip-installing at once read as 442 violations.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { finishLineVerdict, isSharedScratch } from "../extensions/protocol.ts";

const run = (passed: number, cmds: Array<[string, boolean]>) => ({
  total: cmds.length,
  passed,
  checks: cmds.map(([cmd, ok]) => ({ cmd, ok })),
});

test("a finish line that fails refuses done and names the first check that fails", () => {
  const v = finishLineVerdict(run(1, [["test -f work/report.md", false], ["test -f work/timeline.md", false], ["true", true]]), false);
  assert.equal(v.proceed, false);
  if (!v.proceed) {
    assert.equal(v.failing, "test -f work/report.md");
    assert.match(v.reason, /1 of 3 checks pass/);
    assert.match(v.reason, /ends the whole swarm, not your slice/);
    assert.match(v.reason, /abandon: true/);
  }
});

test("a finish line that passes lets done through, with nothing added to the reason", () => {
  const v = finishLineVerdict(run(2, [["true", true], ["true", true]]), false);
  assert.deepEqual(v, { proceed: true });
});

test("abandon writes the sentinel anyway and says so", () => {
  const v = finishLineVerdict(run(0, [["test -f work/report.md", false]]), true);
  assert.equal(v.proceed, true);
  if (v.proceed) {
    assert.equal(v.reasonPrefix, "ABANDONED: ");
    assert.match(v.note ?? "", /abandoned on purpose/);
  }
});

test("a check that timed out is reported as such, and still refuses", () => {
  const v = finishLineVerdict({ total: 1, passed: 0, checks: [{ cmd: "sleep 999", ok: false, timed_out: true }] }, false);
  assert.equal(v.proceed, false);
  if (!v.proceed) assert.match(v.reason, /first that timed out/);
});

test("a run whose checks cannot be run is not held hostage: done proceeds, and the note says why", () => {
  assert.equal(finishLineVerdict(null, false).proceed, true);
  const v = finishLineVerdict({ total: 0, passed: 0, checks: [], error: "no registry" }, false);
  assert.equal(v.proceed, true);
  if (v.proceed) assert.match(v.note ?? "", /no registry/);
  assert.equal(finishLineVerdict(run(0, []), false).proceed, true, "a goal with no checks has nothing to fail");
});

test("the shared install area and the scratch dir are nobody's work product", () => {
  assert.equal(isSharedScratch("work/.toolchain/lib/python/site-packages/pytz/zoneinfo/Africa/Mbabane"), true);
  assert.equal(isSharedScratch("work/.toolchain/.cache/volatility3/identifier.cache"), true);
  assert.equal(isSharedScratch("work/.tmp/pi-bash-1.log"), true);
  assert.equal(isSharedScratch("work/report.md"), false);
  assert.equal(isSharedScratch("work/sb36f02/timeline_rows.md"), false);
  assert.equal(isSharedScratch("tools/carve/manifest.json"), false);
  assert.equal(isSharedScratch("work/.toolchainx/evil"), false, "the prefix is the directory, not a string");
});
