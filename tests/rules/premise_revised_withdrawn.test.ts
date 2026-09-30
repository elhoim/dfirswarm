/**
 * Rules `premise_revised` and `premise_withdrawn` (warnings; docs/adr/0011,
 * "Premises"): an answer that cites a premise at a revision the operator has
 * revised since, or a premise the operator withdrew, is warned where the
 * decision is made, and never held or rewritten.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as FIN from "../../extensions/finish.ts";
import * as Q from "../../extensions/questions.ts";
import { A, F, GOAL, ok, rec, run } from "../negative-bar-fixture.ts";

const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
const PREMISED = GOAL.replace("## Definition of done", "## Premises\n\n- The disk image disk.E01 is of the laptop issued to the employee, who alone used it [scope: questions 1, 2; entities disk.E01; times 2024-01-01..2024-12-31]\n\n## Definition of done");
const act = async (S: string, ev: Q.ActKind, input: Q.ActInput) => {
  const r = await Q.act(S, OPERATOR, ev, input);
  assert.ok(r.ok, (r as { reason?: string }).reason);
};
const warnedOn = async (S: string, section: string) => (await FIN.readiness(S)).warned.filter((w) => w.section === section).map((w) => w.code);

test("premise_revised, then premise_withdrawn: an answer citing the premise is warned of each, never held", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "the employee's account logged on at 09:14", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry.seq;
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "the employee", reasoning: `E-${f}`, ...A, result: "established", premises: [{ id: "P-1", rev: 1, stance: "assumed" }] }));
  assert.ok(!(await warnedOn(c.S, "question:1")).some((x) => x.startsWith("premise_")), "nothing to warn of while the premise stands as cited");
  await act(c.S, "premise_revise", { p: "P-1", expected_rev: 1, why: "the laptop was the employee's only until June", premise_scope: { entities: ["disk.E01"], times: ["2024-01-01..2024-06-30"], questions: ["Q-1", "Q-2"] } });
  let w = await warnedOn(c.S, "question:1");
  assert.ok(w.includes("premise_revised"), JSON.stringify(w));
  assert.ok(!(await FIN.readiness(c.S)).items.some((x) => /question:1/.test(x) && /premise/.test(x)), "a warning holds nothing");
  await act(c.S, "premise_withdraw", { p: "P-1", why: "the brief was wrong about the laptop" });
  w = await warnedOn(c.S, "question:1");
  assert.ok(w.includes("premise_withdrawn"), JSON.stringify(w));
  assert.ok(!w.includes("premise_revised"), "a withdrawn premise is warned of as withdrawn, not as revised");
});
