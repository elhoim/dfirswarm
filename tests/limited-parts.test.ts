/**
 * A part at the limit of the evidence (docs/adr/0013): a part the question
 * asks that the evidence in scope cannot settle is limited, not open. It is
 * shown by the coverage record for the question or by a limitation whose
 * reason is unavailable or excluded; it does not make the answer partial;
 * and claiming it costs what a negative costs: another seat reviews the
 * bound as it reviews a negative, and until then an established attest of
 * the answer is recorded best_candidate (limit_unreviewed), the answers
 * check warns, and the report says so. A review agrees with `at_limit`, or
 * holds the part still to be settled, which caps an established review.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as PM from "../extensions/premises.ts";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { measureRun } from "../scripts/metrics.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, ESTABLISHED, F, REVIEW, coverage, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;
const review = (parts: unknown[]) => ({ ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts } });

/** A run with a finding for question 1, a limitation that says the evidence for the account is gone, and one that says it was not examined. */
async function setting() {
  const c = await run();
  const lead = await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a logon at 09:14 from the office host", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const gone = ok(await rec(c.a0, { kind: "limitation", value: "The log keeps no account name, and the directory's own log was not retained", source: "a log", evidence: "its fields; the retention setting", reason: "unavailable", answers: ["1"] })).entry.seq;
  const unread = ok(await rec(c.a0, { kind: "limitation", value: "The second log was not read", source: "a log", evidence: "time", reason: "not_examined", answers: ["1"] })).entry.seq;
  return { c, lead, f, gone, unread };
}

test("a limited part: its shape and what shows it; it never makes an answer partial, and an established answer holds it among its limitations", async () => {
  const { c, f, gone, unread } = await setting();
  const cov2 = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], ["job:j000001/hits.txt"]))).entry.seq;
  const when = { id: "when", part: "when", status: "established", refs: [`E-${f}`] };
  const base = { kind: "answer", section: "question:1", value: "a logon at 09:14; which account is at the limit of the evidence", reasoning: `E-${f}`, ...A, result: "established" };
  const who = (o: Record<string, unknown>) => ({ ...base, parts: [when, { id: "who", part: "which account", status: "limited", ...o }] });
  refused(await rec(c.a1, who({})), /"who" is limited: name in limited_by what shows the evidence in scope cannot settle it: the coverage record for the question .* or a limitation whose reason is unavailable or excluded .* If a route or an ask could still settle it, it is open/);
  refused(await rec(c.a1, who({ limited_by: `E-${gone}`, open_by: `E-${gone}` })), /"who" is limited: open_by is an open part's \(what could still settle it\); a limited part names in limited_by/);
  refused(await rec(c.a1, { ...base, parts: [{ ...when, limited_by: `E-${gone}` }] }), /"when" is established: limited_by is a limited part's/);
  refused(await rec(c.a1, who({ limited_by: "P-1" })), /"who" is limited by P-1, a premise, and a premise is never a limited part/);
  refused(await rec(c.a1, who({ limited_by: `E-${f}` })), /"who" is limited by E-\d+, a finding: a limited part rests on the coverage record for the question .* or a limitation whose reason is unavailable or excluded/);
  refused(await rec(c.a1, who({ limited_by: `E-${unread}` })), /"who" is limited by E-\d+, a limitation whose reason is not_examined: .* could still be settled: hold the part open \(open_by E-\d+\)/);
  refused(await rec(c.a1, who({ limited_by: `E-${cov2}` })), /"who" is limited by E-\d+, a coverage record not recorded for question:1: a limited part rests on the coverage record for its question \(answers=\["1"\]/);
  // A limited part is not an open one: a partial answer with none open is refused, with the words that say so.
  const partial = await rec(c.a1, { ...who({ limited_by: `E-${gone}` }), result: "partial" });
  refused(partial, /^record it established or name what is open: .* A part the question asks that the evidence in scope cannot settle is limited, not open .* a limited part does not make an answer partial/);
  // An established answer holds it: the limitation joins its limitations, and its words say it.
  const a = ok(await rec(c.a1, who({ limited_by: `E-${gone}` }))).entry;
  assert.deepEqual(a.parts?.map((p) => [p.id, p.status, p.limited_by ?? null]), [["when", "established", null], ["who", "limited", `E-${gone}`]]);
  assert.deepEqual(a.limitations?.map((x) => x.seq), [gone]);
  assert.match(PM.partsWords(a.parts!), new RegExp(`who "which account" at the limit of the evidence, shown by E-${gone}`));
  // The standing reads it: asked 2, established 1, limited 1, open none.
  const s = PM.partsStanding(a.parts!, []);
  assert.deepEqual([s.asked, s.established, s.limited, s.open, s.all_asked_established], [2, 1, 1, 0, false]);
  assert.equal(PM.partsSummaryWords(s), "Asked parts: 1 of 2 established, 1 at the limit of the evidence. Open: none.");
  // A partial answer may hold a limited part beside an open one.
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "a remote tool", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  const cov = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], ["job:j000001/hits.txt"]))).entry.seq;
  const lead2 = await planned(c.a0, "2");
  const p2 = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "a remote tool; how it came is open; its first run is at the limit", reasoning: `E-${f2}`, ...A, result: "partial", support: [cov], parts: [{ id: "what", part: "which tool", status: "established", refs: [`E-${f2}`] }, { id: "how", part: "how it came", status: "open", open_by: lead2 }, { id: "first", part: "its first run", status: "limited", limited_by: `E-${cov}` }] })).entry;
  assert.deepEqual(p2.parts?.map((p) => p.status), ["established", "open", "limited"]);
});

test("the bound is reviewed as a negative is: until then an established attest is recorded best_candidate (limit_unreviewed) and the answers check warns; at_limit agrees, and a review that holds the part still to be settled caps it", async () => {
  const { c, lead, f, gone } = await setting();
  const parts = [{ id: "when", part: "when", status: "established", refs: [`E-${f}`] }, { id: "who", part: "which account", status: "limited", limited_by: `E-${gone}` }];
  const rec1 = await rec(c.a1, { kind: "answer", section: "question:1", value: "a logon at 09:14 from the office host; which account is at the limit of the evidence", reasoning: `E-${f}; E-${gone}`, ...HIGH, result: "established", parts });
  const a = ok(rec1).entry;
  assert.ok((rec1 as P.WarningsDelivered).warned?.includes("limit_unreviewed"), JSON.stringify(rec1));
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  const agreed = review([{ id: "when", part: "when", established: true, why: "line 12" }, { id: "who", part: "which account", established: false, at_limit: true, why: "the log keeps no account, and the directory log is gone" }]);
  // at_limit's shape: by id, established false, never missing or not_asked.
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ id: "when", part: "when", established: true, why: "w" }, { id: "who", part: "which account", established: true, at_limit: true, why: "w" }]) }), /at_limit agrees with a part the answer holds limited, by its id: established false, with id/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ part: "which account", established: false, at_limit: true, why: "w" }]) }), /at_limit agrees with a part the answer holds limited, by its id/);
  // A review that holds the limited part still to be settled: an established attest is refused as the other strength caps are.
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ id: "when", part: "when", established: true, why: "line 12" }, { id: "who", part: "which account", established: false, why: "the domain controller's log could say" }]) }), /best_candidate only: the review holds "which account", which the answer holds at the limit of the evidence, still to be settled \(the domain controller's log could say\): a route or an ask could settle it, so it is open/);
  // Agreed, but the bound is not reviewed: recorded a best candidate, the reason in capped.
  const early = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...agreed });
  assert.ok(early.ok && early.line, JSON.stringify(early));
  assert.equal(early.line!.strength, "best_candidate");
  assert.match(early.line!.capped!.join("\n"), new RegExp(`"who" is held at the limit of the evidence by E-${gone}, and no seat other than a1, a0 has reviewed E-${gone} as a negative is reviewed`));
  assert.match(early.note ?? "", /with review \{detection, reproduced, other_route\}, as it would review a negative/);
  let r = await checkLedgerAnswers(c.S, ["1"]);
  assert.deepEqual(r.best_candidate, ["question:1"]);
  const w = r.warnings.filter((x) => /\(question:1\) is established and holds "who" \(which account\) at the limit of the evidence by E-\d+/.test(x));
  assert.equal(w.length, 1, r.warnings.join("\n"));
  const ready = await FIN.readiness(c.S);
  assert.ok(ready.warned.some((x) => x.code === "limit_unreviewed" && x.section === "question:1"), "said in finish status");
  // The report says it, part by part.
  let body = await renderReportBodyMarkdown(c.S);
  assert.match(body, /Established, at the limit of the evidence on:(\*\*)? which account \(.*E-\d+.*, not yet reviewed by another seat/);
  // The answer's own author cannot review the bound; another seat does, as it reviews a negative.
  const self = await P.attestEntry(c.a1, { seq: gone, how: "re-read", review: REVIEW });
  assert.ok(self.ok, JSON.stringify(self));
  assert.equal(P.limitedBoundReview(a, `E-${gone}`, await P.readLedger(c.S), await P.readAttestations(c.S)).reviewed, false, "the answer's author is not a reviewer of its bound");
  assert.ok((await P.attestEntry(c.a3, { seq: gone, how: "checked the retention setting and the directory", review: REVIEW })).ok);
  assert.deepEqual(P.limitedBoundReview(a, `E-${gone}`, await P.readLedger(c.S), await P.readAttestations(c.S)), { reviewed: true, by: ["a3"] });
  const later = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12, and the bound's review", ...agreed });
  assert.ok(later.ok && later.line, JSON.stringify(later));
  assert.equal(later.line!.strength, "established");
  assert.equal(later.line!.capped, undefined);
  r = await checkLedgerAnswers(c.S, ["1"]);
  assert.equal(r.dispositions["question:1"], "established", r.lines.join("\n"));
  assert.ok(!r.warnings.some((x) => /at the limit of the evidence/.test(x)), r.warnings.join("\n"));
  body = await renderReportBodyMarkdown(c.S);
  assert.match(body, /Established, at the limit of the evidence on:(\*\*)? which account \(.*E-\d+.*, reviewed by a3\)/);
  assert.match(body, /\| who \| which account \| at the limit of the evidence \| .*E-\d+.*, reviewed by a3 \|/);
  // The metrics count it, with its bound reviewed.
  const m = await measureRun(c.S);
  assert.deepEqual(m.claims.limited, [{ section: "1", id: "Q-1", answer: `E-${a.seq}`, part: "who", bound: `E-${gone}`, reviewed: true }]);
});

test("an answer without limited parts reads and hashes as before; a limited row's field is in the core only when present", async () => {
  const { c, f, gone } = await setting();
  const plain = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "a logon at 09:14", reasoning: `E-${f}`, ...A, result: "established", parts: [{ id: "when", part: "when", status: "established", refs: [`E-${f}`] }] })).entry;
  assert.ok(!("limited_by" in plain.parts![0]!));
  assert.equal(PM.partsStanding(plain.parts!, []).limited, 0);
  assert.doesNotMatch(PM.partsSummaryWords(PM.partsStanding(plain.parts!, [])), /limit/);
  const limited = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "a logon at 09:14; the account at the limit", reasoning: `E-${f}`, ...A, result: "established", supersedes: plain.seq, parts: [{ id: "when", part: "when", status: "established", refs: [`E-${f}`] }, { id: "who", part: "which account", status: "limited", limited_by: `E-${gone}` }] })).entry;
  assert.equal(limited.parts![1]!.limited_by, `E-${gone}`);
  const v = P.verifyLedgerChain(await readFile(join(c.S, "ledger", "entries.jsonl"), "utf8"));
  assert.ok(v.ok, JSON.stringify(v));
});
