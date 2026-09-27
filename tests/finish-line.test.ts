/**
 * done runs the finish line before it writes the sentinel. On run sb36f a nano
 * agent ended a 25 GB case after four minutes by calling done when its own
 * slice was finished: no report, no timeline, three peers stopped. The checks
 * are the operator's and always were; what changed is that they are run at the
 * moment they matter. And the claim ledger stays out of the shared install
 * area, where two agents pip-installing at once read as 442 violations.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { abandonVotePath, agentDeadPath, agentDonePath, finishLineVerdict, initSandbox, isSharedScratch, markDone, SENTINEL_REL } from "../extensions/protocol.ts";

const run = (passed: number, cmds: Array<[string, boolean]>) => ({
  total: cmds.length,
  passed,
  checks: cmds.map(([cmd, ok]) => ({ cmd, ok })),
});

test("a finish line that fails refuses done and names every check that fails, and what makes it pass", () => {
  const v = finishLineVerdict(run(1, [["test -f work/report.md", false], ["test -f work/timeline.md", false], ["true", true]]), false);
  assert.equal(v.proceed, false);
  if (!v.proceed) {
    assert.equal(v.failing, "test -f work/report.md", "the record's one field is the first");
    assert.match(v.reason, /1 of 3 checks pass/);
    assert.match(v.reason, /The harness ran the goal's checks when you called done/);
    assert.match(v.reason, /^- `test -f work\/report\.md` fails\. Fix: make this command succeed when run from the run's directory$/m);
    assert.match(v.reason, /^- `test -f work\/timeline\.md` fails\. Fix: /m, "the second failing check is named too");
    assert.doesNotMatch(v.reason, /`true`/, "a passing check is not");
    assert.match(v.reason, /ends the whole swarm, not your slice/);
    assert.match(v.reason, /abandon: true/);
  }
});

test("what a check said about itself reaches the agent verbatim", () => {
  // A gate run as a check (check-answers.ts names each defect and its fix)
  // says what to do in its output, which the runner hands back as `out`; the
  // refusal carries its words as they are, for every failing check.
  const said = "DEFECT: question:3 has no answer. Fix: record kind=answer section=question:3\n  second line, kept";
  const v = finishLineVerdict(
    {
      total: 3,
      passed: 0,
      checks: [
        { cmd: "gate one", ok: false, out: `${said}\n` },
        { cmd: "gate two", ok: false, fix: "the fix\n  as given" },
        { cmd: "gate three", ok: false, out_bytes: 70000 },
      ],
    },
    false,
  );
  assert.equal(v.proceed, false);
  if (!v.proceed) {
    assert.ok(v.reason.includes(`- \`gate one\` fails. It says:\n${said}\n`), v.reason);
    assert.ok(v.reason.includes("- `gate two` fails. It says:\nthe fix\n  as given\n"), v.reason);
    assert.ok(v.reason.includes("- `gate three` fails. It printed 70000 bytes; run it from the run's directory to read them.\n"), v.reason);
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
  if (!v.proceed) assert.match(v.reason, /^- `sleep 999` timed out\. Fix: it has to finish within the check's time limit and succeed$/m);
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

test("a finish line read from an agent-writable copy cannot certify a run", () => {
  const passing = { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }], source: "sandbox contract" };
  const v = finishLineVerdict(passing, false);
  assert.equal(v.proceed, false);
  if (!v.proceed) assert.match(v.reason, /agents can edit/);
  const abandon = finishLineVerdict(passing, true);
  assert.equal(abandon.proceed, true, "abandoning claims nothing, so it stays the way out");
  if (abandon.proceed) assert.equal(abandon.reasonPrefix, "ABANDONED: ");
  const failing = finishLineVerdict({ ...passing, passed: 0, checks: [{ cmd: "test -f work/x", ok: false }] }, false);
  assert.equal(failing.proceed, false);
  if (!failing.proceed) assert.equal(failing.failing, "test -f work/x", "a failing check is named whatever the source");
  const emptied = finishLineVerdict({ total: 0, passed: 0, checks: [], source: "sandbox contract" }, false);
  assert.equal(emptied.proceed, false, "checks deleted from an editable copy do not pass vacuously");
  assert.equal(finishLineVerdict({ ...passing, source: "registry" }, false).proceed, true);
});

/**
 * Run sfeeebb: one seat of ten, whose own slice had not come together,
 * abandoned the case after six minutes and the sentinel stopped nine working
 * peers. An abandon is now a vote while others work.
 */
async function team(ids: string[]): Promise<string> {
  const sandbox = await mkdtemp(join(tmpdir(), "dfs-abandon-"));
  await initSandbox(sandbox, { swarmId: "t1", agentIds: ids, capUsd: 5, wallClockMinutes: 30 });
  return sandbox;
}

test("one agent's abandon while peers work is recorded and refused; a second agent's ends the run", async () => {
  const sandbox = await team(["a0", "a1", "a2"]);
  try {
    const first = await markDone({ sandboxRoot: sandbox, agentId: "a0" }, { reason: "ABANDONED: my slice is stuck", outputFile: "work/report.md" });
    assert.equal(first.terminate, false);
    if (!first.terminate) {
      assert.deepEqual(first.abandon.working, ["a1", "a2"]);
      assert.deepEqual(first.abandon.votes, ["a0"]);
      assert.equal(first.abandon.first_vote, true);
      assert.match(first.refused, /2 other agents are still working \(a1, a2\)/);
    }
    assert.ok(existsSync(abandonVotePath(sandbox, "a0")), "the vote is on disk");
    assert.equal(existsSync(agentDonePath(sandbox, "a0")), false, "the seat is not done");
    assert.equal(existsSync(join(sandbox, SENTINEL_REL)), false, "no sentinel");
    const again = await markDone({ sandboxRoot: sandbox, agentId: "a0" }, { reason: "ABANDONED: still stuck", outputFile: "work/report.md" });
    assert.equal(again.terminate, false, "asking twice is still one agent");
    if (!again.terminate) assert.equal(again.abandon.first_vote, false);
    const second = await markDone({ sandboxRoot: sandbox, agentId: "a2" }, { reason: "ABANDONED: the image is not readable", outputFile: "work/report.md" });
    assert.equal(second.terminate, true);
    assert.equal(second.created_sentinel, true);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("an abandon with no other agent working ends the run on one word; a done or dead peer is not working", async () => {
  const sandbox = await team(["a0", "a1", "a2"]);
  try {
    await writeFile(agentDonePath(sandbox, "a1"), "---\nby: a1\n---\n");
    await writeFile(agentDeadPath(sandbox, "a2"), "---\nby: reap\n---\n");
    const only = await markDone({ sandboxRoot: sandbox, agentId: "a0" }, { reason: "ABANDONED: alone and stuck", outputFile: "work/report.md" });
    assert.equal(only.terminate, true);
    assert.equal(only.created_sentinel, true);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("a done that is not an abandon, and a seat leaving on its cap, are not votes", async () => {
  const sandbox = await team(["a0", "a1"]);
  try {
    const cap = await markDone({ sandboxRoot: sandbox, agentId: "a1" }, { reason: "agent_cap", outputFile: "(cap)", createSentinel: false });
    assert.equal(cap.terminate, true);
    assert.equal(existsSync(abandonVotePath(sandbox, "a1")), false);
    const done = await markDone({ sandboxRoot: sandbox, agentId: "a0" }, { reason: "the checks pass", outputFile: "work/report.md" });
    assert.equal(done.terminate, true);
    assert.equal(done.created_sentinel, true);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});
