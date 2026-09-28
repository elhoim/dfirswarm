/**
 * A downgrade needs counter-evidence (docs/adr/0013, "After the round-13
 * scoring"): a revision that moves an answer from established or partial to
 * not determinable or a bounded negative names what undermines the earlier
 * chain, or it is refused and pointed to a dispute and a lower strength; a
 * dispute is still how a doubt is said. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, coverage, ESTABLISHED, F, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const attested = async (c: { sandboxRoot: string; agentId: string }, input: P.LedgerActInput) => {
  const r = await P.attestEntry(c, input);
  assert.ok(r.ok && (r as { line: unknown }).line, JSON.stringify(r));
};
const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);

test("a downgrade names its counter-evidence: refused without it, admitted with it, in the chained core and the report; a dispute is still how a doubt is said", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const est = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established" })).entry;
  await attested(a2, { seq: est.seq, how: "read the line again", ...ESTABLISHED });
  // The dispute path is unchanged: a doubt is a dispute, and the answer stays.
  const disp = await P.disputeEntry(a3, { seq: est.seq, why: "the line may record the logon the other way round", refs: ["job:j000001/hits.txt"] });
  assert.ok(disp.ok, (disp as { reason?: string }).reason);
  let r = await checkLedgerAnswers(S, ["1"]);
  assert.deepEqual(codes(r, "question:1"), ["answer_disputed"]);
  // Walked down with no counter-evidence: refused, pointing to the dispute and a lower strength.
  await planned(a0, "1");
  const abs = ok(await rec(a0, { kind: "absence", value: "a logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const cov = ok(await rec(a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`]))).entry;
  const down = { kind: "answer", section: "question:1", value: "Who logged on cannot be determined from the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable", supersedes: est.seq };
  refused(await rec(a1, down), new RegExp(`#${est.seq} answered question:1 established; recording it not determinable is a downgrade, and a downgrade names what undermines the earlier chain: downgrade \\{evidence: .*dispute #${est.seq} \\(why, refs\\), and if the doubt stands attest it best_candidate or record it again with confidence medium; the answer stays`));
  refused(await rec(a1, { ...down, downgrade: { evidence: [`E-${est.seq}`], why: "w" } }), /names E-\d+, the answer being downgraded/);
  refused(await rec(a1, { ...down, downgrade: { evidence: ["E-999"], why: "w" } }), /no entry #999/);
  refused(await rec(a1, { ...down, downgrade: { evidence: ["job:j000009/none.txt"], why: "w" } }), /downgrade\.evidence: /);
  refused(await rec(a1, { ...down, downgrade: { evidence: [], why: "w" } }), /downgrade is \{evidence: \[E-<seq> or objects\], why\}/);
  refused(await rec(a1, { kind: "answer", section: "question:1", value: "alice, as the log says", reasoning: `E-${f.seq}`, ...A, result: "established", supersedes: est.seq, downgrade: { evidence: [`E-${f.seq}`], why: "w" } }), /downgrade is for a revision that moves an answer from established or partial to not_determinable or bounded_negative; #\d+ is established and this is established/);
  // With what undermines the chain: admitted, and kept.
  const counter = ok(await rec(a3, { kind: "finding", ...F, value: "the line records a logon to alice's account from another user's session", source: "a log", evidence: "line 2", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const why = "the line the answer read names the session's owner, not the account logged on to";
  const nd = ok(await rec(a1, { ...down, reasoning: `E-${cov.seq}; E-${counter.seq} undermines E-${f.seq}`, downgrade: { evidence: [`E-${counter.seq}`, "job:j000002/hits.txt"], why } })).entry;
  assert.deepEqual(nd.downgrade, { evidence: [`E-${counter.seq}`, "job:j000002/hits.txt"], why });
  const text = await readFile(join(S, P.LEDGER_ENTRIES), "utf8");
  assert.equal(P.verifyLedgerChain(text).ok, true);
  assert.equal(P.verifyLedgerChain(text.replace(why, "a reason")).ok, false, "the downgrade is in the chained core");
  // The report's chain for the question: the earlier answer, its dispute, the counter-evidence.
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, new RegExp(`\\*\\*Downgraded:\\*\\* E-${nd.seq} moved the answer from established \\(E-${est.seq}\\) to not determinable`));
  assert.match(md, new RegExp(`\\*\\*Counter-evidence:\\*\\* E-${counter.seq}, \`job:j000002/hits.txt\`: ${why}`));
  assert.match(md, /\*\*Disputes of the earlier answer:\*\* a3: the line may record the logon the other way round/);
});
