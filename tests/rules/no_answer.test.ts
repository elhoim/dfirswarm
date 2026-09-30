/**
 * Rule `no_answer` (a defect; docs/protocol.md, "The codes the answers check
 * names"): a section the goal requires with no standing answer holds the
 * finish line, and an answer recorded for it clears the defect.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { checkLedgerAnswers } from "../../scripts/check-answers.ts";
import { A, F, ok, rec, run } from "../negative-bar-fixture.ts";

const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);

test("no_answer: a required section with no standing answer is a defect until one is recorded", async () => {
  const c = await run();
  let r = await checkLedgerAnswers(c.S, ["1"]);
  assert.ok(codes(r, "question:1").includes("no_answer"), JSON.stringify(r.defects));
  assert.equal(r.ok, false);
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f}`, ...A, result: "established" }));
  r = await checkLedgerAnswers(c.S, ["1"]);
  assert.ok(!codes(r, "question:1").includes("no_answer"), JSON.stringify(r.defects));
});
