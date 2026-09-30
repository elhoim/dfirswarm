/**
 * scripts/replay.ts as a command (docs/adr/0017, "Measuring a rule
 * change"): it reads a copy and never the run; what it prints by default
 * carries no record's text; --compare against the run's own harness finds it
 * by the commit the registry records when the hub's frozen copy is gone,
 * and says how to give one when it cannot; a custody verdict verifies as a
 * prefix of what the run appended after it, and not once a sealed line
 * changed. Synthetic histories only (tests/fixtures/contract).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";
import { answersChecks, deliveriesOf, goalChecks, readinessCode, shellWords, warningCode, type Replay } from "../scripts/replay.ts";

const ROOT = resolve(import.meta.dirname, "..");
const FIXTURES = join(ROOT, "tests", "fixtures", "contract");
const SCRIPT = join(ROOT, "scripts", "replay.ts");

const scratch: string[] = [];
after(async () => {
  for (const d of scratch) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const replayCli = (args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", SCRIPT, ...args], { encoding: "utf8", maxBuffer: 1 << 26 });

/** A fixture's history copied into a runs directory of its own, under `id`. */
async function runsWith(fixture: string, id: string): Promise<{ runs: string; S: string }> {
  const runs = await mkdtemp(join(tmpdir(), "replay-runs-"));
  scratch.push(runs);
  const S = join(runs, id);
  const cp = spawnSync("cp", ["-Rp", join(FIXTURES, fixture, "run"), S]);
  assert.equal(cp.status, 0, String(cp.stderr));
  return { runs, S };
}

/** Every text a record of the history carries that a reader could take for the case's: answers, findings, reasons, lead titles, reviews, posts. */
function recordTexts(S: string): string[] {
  const out = new Set<string>();
  const lines = (rel: string) => (existsSync(join(S, rel)) ? readFileSync(join(S, rel), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>) : []);
  for (const e of lines("ledger/entries.jsonl")) for (const k of ["value", "reasoning", "evidence", "source", "indicates"]) if (typeof e[k] === "string") out.add(e[k] as string);
  for (const e of lines("leads/leads.jsonl")) for (const k of ["title", "why"]) if (typeof e[k] === "string") out.add(e[k] as string);
  for (const e of lines("ledger/attestations.jsonl")) if (typeof e.how === "string") out.add(e.how);
  for (const e of lines("leads/finish.jsonl")) if (typeof e.why === "string" && e.ev === "ack") out.add(e.why);
  return [...out].filter((t) => t.length >= 12);
}

test("the goal's checks are read as await-done.sh reads them, and an answers check's options as the shell passes them", () => {
  const goal = ["## Checks", "", "- `test -f work/report.md`", '- `node --experimental-strip-types "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary --existence 2`', "- prose, no code", "* `node x \"$SWARM_HARNESS/scripts/check-answers.ts\" --sections-in 'inputs/CASE.md' --sections narrative`", "", "## After", "- `not a check`"].join("\n");
  const checks = goalChecks(goal);
  assert.equal(checks.length, 3);
  assert.deepEqual(answersChecks(checks).map((c) => [c.sections, c.existence, c.sectionsIn]), [
    [["1", "2", "summary"], ["2"], null],
    [["narrative"], [], "inputs/CASE.md"],
  ]);
  assert.deepEqual(shellWords(`a "b c" 'd e' f\\ g`), ["a", "b c", "d e", "f g"]);
});

test("warnings and readiness items are read by the harness's own words, into codes and sections, and nothing else", () => {
  assert.deepEqual(warningCode("answer #12 (question:3) is partial, and every review holds every part it weighed established (a1; attested established by a1). fix"), { code: "partial_all_parts_established", section: "question:3" });
  assert.deepEqual(warningCode("answer #9 (question:1) is not determinable, and its coverage record E-7 names no acquisition ask and no reason for none. fix"), { code: "no_acquisition_ask", section: "question:1" });
  assert.deepEqual(warningCode("answer #4 (question:2): E-3 (a finding under L-1) established under Q-2's leads and not in its answer: cite it. fix"), { code: "lead_findings_uncited", section: "question:2" }, "the words of the harness before the rule reached past the leads");
  assert.deepEqual(warningCode("answer #4 (question:2) leaves out what two seats hold for Q-2: E-3 (a finding that names Q-2): cite it or say why it does not bear on it. fix"), { code: "lead_findings_uncited", section: "question:2" });
  const known = new Map([["answer #5 (question:2) is negative (unreviewed)", { code: "negative_unreviewed", section: "question:2" }]]);
  assert.deepEqual(readinessCode("answer #5 (question:2) is negative (unreviewed)", known), { code: "negative_unreviewed", section: "question:2" });
  assert.deepEqual(readinessCode("question:4 is a best candidate, not established (E-9)", known), { code: "best_candidate", section: "question:4" });
  assert.deepEqual(readinessCode("question:4's answer E-9 predates new evidence for Q-4 (ev-0001)", known), { code: "answer_predates_evidence", section: "question:4" });
  assert.deepEqual(readinessCode("L-3 was closed deferred (E-12): why", known), { code: "route_limitation", section: null });
});

test("replay never writes the run and never follows a link out of it: the evidence and every link are left out of the copy, the registers hashed the same after", async () => {
  const { runs, S } = await runsWith("negative-unreviewed", "nur");
  const outside = join(runs, "evidence");
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, "disk.E01"), "evidence bytes\n");
  await symlink(outside, join(S, "inputs"));
  await mkdir(join(S, "work"), { recursive: true });
  await symlink(join(outside, "disk.E01"), join(S, "work", "link.bin"));
  const before = spawnSync("find", [S, "-type", "f", "-exec", "shasum", "{}", "+"], { encoding: "utf8" }).stdout;
  const r = replayCli([S, "--json"]);
  assert.equal(r.status, 0, `the replay ran (what it replayed holds the done: an unreviewed negative, which is the history's, not the replay's): ${r.stderr}`);
  const out = JSON.parse(r.stdout) as Replay;
  assert.equal(out.unchanged, true);
  assert.ok(out.copy.left_out.includes("inputs"), JSON.stringify(out.copy));
  assert.equal(out.copy.links_removed, 1, "the link under work/ is removed from the copy, never followed");
  assert.ok(out.evaluations[0].projection, out.evaluations[0].error ?? "");
  assert.equal(spawnSync("find", [S, "-type", "f", "-exec", "shasum", "{}", "+"], { encoding: "utf8" }).stdout, before, "no file of the run changed");
  assert.equal(await readFile(join(outside, "disk.E01"), "utf8"), "evidence bytes\n");
});

test("what replay prints by default carries no record's text, in words or as JSON; --show-text adds the harness's lines, and is off unless asked", async () => {
  for (const fixture of ["warnings-only", "racing-objection", "c10-partial-cascade"]) {
    const S = join(FIXTURES, fixture, "run");
    const texts = recordTexts(S);
    assert.ok(texts.length > 5, `${fixture}: its records carry text to look for`);
    for (const args of [[S], [S, "--json"]]) {
      const r = replayCli(args);
      assert.ok(r.status === 0 || r.status === 1, r.stderr);
      const leaked = texts.filter((t) => r.stdout.includes(t));
      assert.deepEqual(leaked, [], `${fixture} ${args.slice(1).join(" ")}: no record's text in the output`);
      assert.doesNotMatch(r.stdout, /--show-text/);
    }
  }
  const shown = replayCli([join(FIXTURES, "warnings-only", "run"), "--show-text"]);
  assert.match(shown.stdout, /--show-text: the harness's lines, whole \(they quote records\)/);
  assert.match(shown.stdout, /\[warnings\] answer #\d+ \(question:1\) is not determinable/);
});

test("--compare with no checkout reads the run's own harness: the commit its registry record names, extracted from this repository, when the hub's frozen copy is gone", async (t) => {
  const head = spawnSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" });
  if (head.status !== 0) {
    t.skip("not a git checkout: there is no history to extract a commit from");
    return;
  }
  const commit = head.stdout.trim();
  const { runs, S } = await runsWith("partial-every-policy", "pep1");
  const goal = await readFile(join(S, "SWARM.md"), "utf8");
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "pep1", sandbox: S, goal, case_id: "synthetic", stop_policy: "cap-pause", provenance: { harness_commit: commit, harness_dirty: false } }] }));
  const r = replayCli(["pep1", "--registry", join(runs, "registry.json"), "--compare", "--json"]);
  assert.equal(r.status, 0, r.stderr + r.stdout.slice(0, 2000));
  const out = JSON.parse(r.stdout) as Replay;
  assert.equal(out.run.id, "pep1");
  assert.equal(out.run.case_id, "synthetic");
  assert.equal(out.targets[0].commit, commit);
  assert.match(out.targets[0].how, new RegExp(`the run's own harness, extracted from git at ${commit.slice(0, 12)}`));
  assert.equal(out.evaluations.length, 2);
  for (const e of out.evaluations) {
    assert.ok(e.projection, e.error ?? "");
    assert.equal(e.projection.goal.source, "registry", "the goal is the registry record's, as the finish line reads it");
  }
  // The same commit as this checkout's code: no difference, unless the harness has changes not yet committed.
  const clean = spawnSync("git", ["-C", ROOT, "diff", "--quiet", "HEAD", "--", "extensions", "scripts/check-answers.ts", "scripts/finish-gate.ts", "scripts/report-body.ts", "scripts/custody.ts"]).status === 0;
  if (clean) assert.deepEqual(out.differences, []);
  const words = replayCli(["pep1", "--registry", join(runs, "registry.json"), "--compare"]);
  if (clean) assert.match(words.stdout, /== No difference, A → B/);
});

test("replay says how to go on when it cannot: no harness commit recorded, not a checkout, a stop policy it does not know, a run it cannot find", async () => {
  const S = join(FIXTURES, "late-post-after-report", "run");
  const noCommit = replayCli([S, "--compare"]);
  assert.equal(noCommit.status, 1);
  assert.match(noCommit.stderr, /names no harness commit .* give the harness it ran with as --compare <path>/);
  const notCheckout = replayCli([S, "--checkout", tmpdir()]);
  assert.equal(notCheckout.status, 1);
  assert.match(notCheckout.stderr, /is not a harness checkout .* git worktree add --detach/);
  const policy = replayCli([S, "--stop-policy", "until-done"]);
  assert.equal(policy.status, 2);
  assert.match(policy.stderr, /--stop-policy takes operator, cap-pause, cap-stop .*not until-done/);
  const unknown = replayCli(["s000000"]);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /is not a run directory, and no registry was given to find it in/);
});

test("earlier seals: a verdict holds as a prefix of what the run appended after it, and not once a line it sealed changed", async () => {
  const { S } = await runsWith("resume-prefix", "rpx1");
  const first = JSON.parse(await readFile(join(S, "custody.20260929T000000000Z.json"), "utf8")) as { seal: { ledger: { entries: number } } };
  const now = (await readFile(join(S, "ledger", "entries.jsonl"), "utf8")).split("\n").filter(Boolean);
  assert.ok(first.seal.ledger.entries < now.length, "the continuation appended to the ledger after the first seal");
  const intact = JSON.parse(replayCli([S, "--json"]).stdout) as Replay;
  assert.deepEqual(intact.evaluations[0].projection?.seals, { verdicts: 2, hold: 2, broken: [] });
  // A sealed line rewritten, its hash fields left as they were.
  const e = JSON.parse(now[0]) as Record<string, unknown>;
  now[0] = JSON.stringify({ ...e, value: `${String(e.value)} (edited)` });
  await writeFile(join(S, "ledger", "entries.jsonl"), `${now.join("\n")}\n`);
  const edited = JSON.parse(replayCli([S, "--json"]).stdout) as Replay;
  const seals = edited.evaluations[0].projection!.seals;
  assert.equal(seals.verdicts, 2);
  assert.equal(seals.hold, 0);
  // The ledger's chain no longer verifies, so no sealed prefix of it is here.
  for (const b of seals.broken) assert.ok(b.broken.some((w) => /^the ledger: /.test(w)), JSON.stringify(b));
});

test("--deliveries on the command line: each act that carries a warning, values-free; a checkout without warningsAt said to deliver in finish status only", async () => {
  const { S } = await runsWith("warnings-delivered", "wdl");
  const out = replayCli([S, "--deliveries"]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /deliveries: 3 answer record\(s\), 1 review offer\(s\) for an answer, 6 attest\(s\) and 3 lead close\(s\) or confirmation\(s\) read again as the registers stood at each/);
  assert.match(out.stdout, /review offer of E-3 to a2: question:1 no_acquisition_ask/);
  assert.match(out.stdout, /finish status: question:1 no_acquisition_ask; question:2 partial_all_parts_established; question:3 lead_findings_uncited/);
  // Values-free: no record's words.
  for (const words of ["A folder was deleted", "a second folder was deleted", "A remote tool was installed"]) assert.ok(!out.stdout.includes(words), words);
  // A harness from before the delivery: finish status only, and said so.
  const old = await deliveriesOf(S, null, { warnings: ["answer #3 (question:1) is not determinable, and its coverage record E-2 names no acquisition ask and no reason for none. fix"] });
  assert.equal(old.error, "this checkout delivers the warnings in finish status only (it has no warningsAt)");
  assert.deepEqual(old.acts, { record: 0, review_offer: 0, attest: 0, lead_close: 0 });
  assert.deepEqual(old.delivered.map((d) => [d.point, d.sections, d.warnings]), [["finish_status", ["question:1"], ["no_acquisition_ask"]]]);
});

test("--deliveries reads a seat's close and confirmation of a lead as acts, each on the lead register cut to its own lines", async () => {
  const { S } = await runsWith("lead-close-delivered", "lcd");
  const out = replayCli([S, "--deliveries"]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /1 answer record\(s\), 0 review offer\(s\) for an answer, 4 attest\(s\) and 4 lead close\(s\) or confirmation\(s\)/);
  assert.match(out.stdout, /\n    close of L-2 by a2: question:1 lead_findings_uncited\n    confirm of L-3 by a0: question:1 lead_findings_uncited\n    finish status: question:1 lead_findings_uncited/);
});
