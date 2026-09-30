/**
 * Rule `derivation_unverified` (a review cap; docs/adr/0015, "A
 * source-first review"): an established review whose derivation does not
 * resolve (a job that did not declare the input it names, or no such job)
 * is capped to best_candidate, and one that resolves caps nothing for it.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as P from "../../extensions/protocol.ts";
import { A, ESTABLISHED, F, ok, planned, rec, run, SOURCE_FIRST } from "../negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;

test("derivation_unverified: a derivation naming an input its job did not declare, or no job, is a cap; one that resolves is not", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a logon record", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry.seq;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "a logon record", reasoning: `E-${f}`, ...HIGH, result: "established" })).entry;
  const caps = async (derivation: { job: string; inputs: string[] }) =>
    (await P.reviewEvidenceCaps(c.S, a, { ...ESTABLISHED.answer_review, discriminator: SOURCE_FIRST.discriminator, derivation } as unknown as P.AnswerReview, { material: true })).caps.map((x) => x.code);
  assert.ok((await caps({ job: "j000001", inputs: ["input:logs/a.log"] })).includes("derivation_unverified"), "an input the job did not declare");
  assert.ok((await caps({ job: "j999999", inputs: ["input:disk.E01"] })).includes("derivation_unverified"), "no such job");
  assert.ok(!(await caps({ job: "j000001", inputs: ["input:disk.E01"] })).includes("derivation_unverified"), "a derivation that resolves");
});
