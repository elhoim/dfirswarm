/**
 * An answer's parts, shown (docs/adr/0013, "What the report shows of an
 * answer's parts"): each part established on what it rests on or open with
 * what bounds it, a review's not_asked mark beside the part it marks, the
 * plain line a partial answer leads with ("Asked parts: 3 of 3
 * established. Open: 1, which a review marks as not asked."), and, when
 * every asked part is established, that said beside the partial label, which
 * is unchanged. In the report (the §1 table, the §2 chain, the §5 answer),
 * the console's question view, questions.md and the metrics' under-claiming
 * count, compared across runs. An answer without parts reads as before.
 */
import assert from "node:assert/strict";
import { appendFileSync, cpSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as PM from "../extensions/premises.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { compareRuns, compareText, measureRun, metricsText } from "../scripts/metrics.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, dirs, ESTABLISHED, F, ok, planned, rec, run } from "./negative-bar-fixture.ts";

test("partsStanding: a mark matches its row by id, else by its words; a part named missing is asked and not established; a mark that names no row is kept apart", () => {
  const rows: PM.AnswerPart[] = [
    { id: "who", part: "who logged on", status: "established", refs: ["E-1"] },
    { id: "when", part: "when", status: "established", refs: ["E-1"] },
    { id: "tty", part: "which terminal the session used", status: "open", open_by: "E-2" },
  ];
  const none = PM.partsStanding(rows, []);
  assert.deepEqual([none.asked, none.established, none.open, none.open_not_asked, none.all_asked_established], [3, 2, 1, 0, false]);
  assert.equal(PM.partsSummaryWords(none), "Asked parts: 2 of 3 established. Open: 1.");
  assert.equal(PM.partialPlainWords("partial", none), null);
  // Marked not asked by id, and again by words by another review: the row carries both reviewers, counted once.
  const marked = PM.partsStanding(rows, [
    { by: "a2", id: "tty", part: "the terminal", why: "the question asks who and when", not_asked: true },
    { by: "a3", part: "Which  terminal the SESSION used", why: "not asked", not_asked: true },
    { by: "a3", id: "nope", part: "a row the answer does not have", why: "w", not_asked: true },
  ]);
  assert.deepEqual([marked.asked, marked.established, marked.open, marked.open_not_asked, marked.all_asked_established], [2, 2, 1, 1, true]);
  assert.deepEqual(marked.rows.find((r) => r.id === "tty")?.not_asked_by.map((x) => x.by), ["a2", "a3"]);
  assert.deepEqual(marked.unmatched.map((m) => m.id), ["nope"], "never dropped");
  assert.equal(PM.partsSummaryWords(marked), "Asked parts: 2 of 2 established. Open: 1, which a review marks as not asked.");
  assert.equal(PM.partialPlainWords("partial", marked), "every part the question asks is established");
  assert.equal(PM.partialPlainWords("established", marked), null, "said beside a partial label only");
  // A part a review names missing: asked, not established, once however many reviews name it.
  const missing = PM.partsStanding(rows, [
    { by: "a2", id: "tty", part: "the terminal", why: "not asked", not_asked: true },
    { by: "a2", part: "from which address", why: "the question asks it", missing: true },
    { by: "a3", part: "From which address", why: "asked", missing: true },
  ]);
  assert.deepEqual([missing.asked, missing.established, missing.all_asked_established, missing.missing.length], [3, 2, false, 1]);
  assert.equal(PM.partsSummaryWords(missing), "Asked parts: 2 of 3 established. Open: 1, which a review marks as not asked. A review names 1 part of the question the answer leaves out.");
  // Several open, some marked.
  const two = PM.partsStanding([...rows, { id: "src", part: "the source address", status: "open", open_by: "E-2" }], [{ by: "a2", id: "tty", part: "t", why: "w", not_asked: true }]);
  assert.equal(PM.partsSummaryWords(two), "Asked parts: 2 of 3 established. Open: 2, of which 1 a review marks as not asked.");
  const both = PM.partsStanding([...rows, { id: "src", part: "the source address", status: "open", open_by: "E-2" }], [{ by: "a2", id: "tty", part: "t", why: "w", not_asked: true }, { by: "a2", id: "src", part: "s", why: "w", not_asked: true }]);
  assert.equal(PM.partsSummaryWords(both), "Asked parts: 2 of 2 established. Open: 2, each of which a review marks as not asked.");
  // Every row marked not asked: nothing is asked, and that is not "every asked part established".
  const nothing = PM.partsStanding([rows[2]!], [{ by: "a2", id: "tty", part: "t", why: "w", not_asked: true }]);
  assert.equal(nothing.all_asked_established, false);
});

/** Question 1 partial, every asked part established and the open one marked not asked by a review; question 2 partial with an asked part open; question 3 established without parts. */
async function underClaimed() {
  const c = await run();
  const lead1 = await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The log keeps no other session detail", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["1"] })).entry.seq;
  const a1 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14; the terminal is not established", reasoning: `E-${f}; the terminal is open (E-${lim})`, ...A, limitations: [lim], result: "partial", parts: [{ id: "who", part: "who logged on", status: "established", refs: [`E-${f}`] }, { id: "when", part: "when", status: "established", refs: [`E-${f}`] }, { id: "tty", part: "which terminal the session used", status: "open", open_by: `E-${lim}` }] })).entry;
  assert.ok((await L.closeLead(c.a0, lead1, { disposition: "resolved", ref: `E-${f}` })).ok);
  const review = (parts: unknown[]) => ({ ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts } });
  const att = await P.attestEntry(c.a2, { seq: a1.seq, how: "re-read line 12", ...review([{ id: "who", part: "who logged on", established: true, why: "line 12" }, { id: "when", part: "when", established: true, why: "line 12" }, { id: "tty", part: "which terminal the session used", established: false, why: "the question asks who and when, not the terminal", not_asked: true }]) });
  assert.ok(att.ok && att.line, JSON.stringify(att));
  // Question 2: the open part is one the question asks.
  const lead2 = await planned(c.a0, "2");
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "a service entry for a remote tool", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  const lim2 = ok(await rec(c.a0, { kind: "limitation", value: "The installer log was not kept", source: "the disk", evidence: "its absence", reason: "unavailable", answers: ["2"] })).entry.seq;
  ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "a remote tool is installed as a service; how it came is open", reasoning: `E-${f2}; how is open (E-${lim2})`, ...A, limitations: [lim2], result: "partial", parts: [{ id: "what", part: "whether a remote tool was installed", status: "established", refs: [`E-${f2}`] }, { id: "how", part: "how it was installed", status: "open", open_by: `E-${lim2}` }] }));
  assert.ok((await L.closeLead(c.a0, lead2, { disposition: "resolved", ref: `E-${f2}` })).ok);
  // Question 3: an answer without parts.
  const lead3 = await planned(c.a0, "3");
  const f3 = ok(await rec(c.a0, { kind: "finding", ...F, value: "notes.txt was deleted", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry.seq;
  ok(await rec(c.a1, { kind: "answer", section: "question:3", value: "notes.txt", reasoning: `E-${f3}`, ...A, result: "established" }));
  assert.ok((await L.closeLead(c.a0, lead3, { disposition: "resolved", ref: `E-${f3}` })).ok);
  return { c, a1 };
}

test("the report shows each answer's parts: a partial answer leads with its plain line, a review's not_asked mark sits beside the part it marks, the §1 table says so beside the partial label, the §2 chain lists the parts; an answer without parts reads as before", async () => {
  const { c } = await underClaimed();
  const md = await renderReportBodyMarkdown(c.S);
  // §5, question 1: the plain line first, then the answer; the label is the recorder's.
  const q1 = md.slice(md.indexOf("### Question 1: Who logged on?"));
  const lead = q1.indexOf("Asked parts: 2 of 2 established. Open: 1, which a review marks as not asked.");
  assert.ok(lead > 0 && lead < q1.indexOf("Answer"), "the plain line leads the answer");
  assert.match(q1, /Partial as recorded, and every part the question asks is established\./);
  // The mark beside the part, in the parts table; not repeated as a note.
  assert.match(md, /\| tty \| which terminal the session used \| open; not asked by the question, as a review marks it: a2 \(the question asks who and when, not the terminal\) \|/);
  assert.doesNotMatch(md, /A review says a part the answer holds is outside what the question asks/);
  // §1: beside the partial label, and the plain line with the answer.
  assert.match(md, /\| Question 1 \| `partially established` every part the question asks is established \|/);
  assert.match(md, /\| E-\d+ partially established\. Asked parts: 2 of 2 established\. Open: 1, which a review marks as not asked\. \|/);
  assert.match(md, /\| Question 2 \| `partially established` \|/, "nothing beside a label whose asked part is open");
  // Question 2: an asked part open, nothing said beside its label.
  assert.match(md, /Asked parts: 1 of 2 established\. Open: 1\./);
  // §2: the chain lists the parts, each established on or bounded by its entry.
  assert.match(md, /\*\*Parts\*\*: Asked parts: 2 of 2 established\. Open: 1, which a review marks as not asked\. Partial as recorded, and every part the question asks is established\./);
  assert.match(md, /`tty` which terminal the session used: open, bounded by E-\d+; not asked by the question, as a review marks it: a2/);
  // Question 3, without parts: no line, no list.
  const q3 = md.slice(md.indexOf("### Question 3: What was deleted?"), md.indexOf("### Question 4"));
  assert.doesNotMatch(q3, /Asked parts|Part by part/);
  // The answers check disposes as it did: the label is unchanged, and the warning holds nothing.
  const r = await checkLedgerAnswers(c.S, ["1", "2", "3"]);
  assert.equal(r.dispositions["question:1"], "partial");
  assert.equal(r.results["question:1"], "partial");
});

test("the console's question view and questions.md say the same: the plain line, the mark beside the part, and the words beside a partial label whose every asked part is established", async () => {
  const { c, a1 } = await underClaimed();
  const ctx = await Q.viewContext(c.S);
  const v = Q.questionViews(ctx).find((x) => x.section === "1")!;
  assert.equal(v.answer?.seq, a1.seq);
  assert.equal(v.answer?.standing?.summary, "Asked parts: 2 of 2 established. Open: 1, which a review marks as not asked.");
  assert.equal(v.answer?.standing?.plain, "every part the question asks is established");
  assert.deepEqual(v.answer?.standing?.rows.find((r) => r.id === "tty")?.not_asked_by, [{ by: "a2", why: "the question asks who and when, not the terminal" }]);
  const v2 = Q.questionViews(ctx).find((x) => x.section === "2")!;
  assert.equal(v2.answer?.standing?.plain, null);
  assert.equal(Q.questionViews(ctx).find((x) => x.section === "3")!.answer?.standing, undefined, "no parts, no standing");
  const md = Q.renderQuestionsMd(ctx);
  assert.match(md, /- Asked parts: 2 of 2 established\. Open: 1, which a review marks as not asked\. Partial as recorded, and every part the question asks is established\./);
  assert.match(md, /- A part the question does not ask, as a2's review marks it: tty "which terminal the session used" \(the question asks who and when, not the terminal\)/);
});

test("the metrics count the under-claimed: partial answers whose asked parts are all established, one without parts named apart; --compare sets each run's count side by side and flags the question", async () => {
  const { c, a1 } = await underClaimed();
  // Question 4 partial without parts, as an answer from before them reads (written by hand: the record tool now refuses a partial answer without an open part).
  const m = await measureRun(c.S);
  assert.equal(m.claims.recorded, true);
  assert.equal(m.claims.partial, 2);
  assert.equal(m.claims.with_parts, 2);
  assert.deepEqual(m.claims.asked_all_established, [{ section: "1", id: "Q-1", answer: `E-${a1.seq}`, asked: 2, established: 2, open: 1, open_not_asked: 1 }]);
  assert.match(metricsText(m), /Under-claiming +1 of 2 partial answer\(s\) with parts have every asked part established \(asked: not marked not_asked by a review\) \(Q-1 E-\d+: 2 of 2 asked established, 1 open, 1 not asked\); 2 partial in scope/);
  // Another run of the goal where question 1's open part is not marked: compared, the flag and the counts.
  const other = await run();
  const lead = await planned(other.a0, "1");
  const f = ok(await rec(other.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const lim = ok(await rec(other.a0, { kind: "limitation", value: "no terminal field", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["1"] })).entry.seq;
  ok(await rec(other.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f}`, ...A, limitations: [lim], result: "partial", parts: [{ id: "who", part: "who logged on", status: "established", refs: [`E-${f}`] }, { id: "tty", part: "which terminal", status: "open", open_by: `E-${lim}` }] }));
  assert.ok((await L.closeLead(other.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  const cmp = await compareRuns(c.S, other.S);
  assert.deepEqual(cmp.summary.under_claimed, { a: 1, b: 0 });
  const row = cmp.questions.find((q) => q.section === "1")!;
  assert.equal(row.a.asked_all_established, true);
  assert.equal(row.b.asked_all_established, false);
  assert.ok(row.flags.includes("partial in A with every asked part established (under-claimed: what is open, a review marks not asked)"), JSON.stringify(row.flags));
  const text = compareText(cmp);
  assert.match(text, /partial \(every asked part established\)/);
  assert.match(text, /Under-claiming: 1 partial answer\(s\) in A and 0 in B with every asked part established/);
  // A partial answer without parts (one recorded before them, written here by hand: the record tool now refuses it) is named apart and counted neither way.
  const old = mkdtempSync(join(tmpdir(), "parts-old-"));
  dirs.push(old);
  cpSync(c.S, join(old, "run"), { recursive: true });
  const S = join(old, "run");
  const entries = await P.readLedger(S);
  const last = entries.at(-1)!;
  const e = { v: 4, seq: last.seq + 1, kind: "answer", value: "an answer from before parts", section: "question:4", reasoning: `E-${last.seq}`, result: "partial", confidence: "medium", by: "a1", authors: ["a1"], at: new Date().toISOString(), prev: last.hash! } as unknown as P.LedgerEntry;
  appendFileSync(join(S, "ledger", "entries.jsonl"), `${JSON.stringify({ ...e, hash: P.ledgerHash(e, last.hash!) })}\n`);
  const legacy = await measureRun(S);
  assert.equal(legacy.claims.partial, 3);
  assert.equal(legacy.claims.with_parts, 2);
  assert.deepEqual(legacy.claims.without_parts.map((x) => x.section), ["4"]);
  assert.equal(legacy.claims.asked_all_established.length, 1);
  assert.match(metricsText(legacy), /3 partial in scope, 1 without parts, not counted \(Q-4 E-\d+\)/);
  // The report reads it as before: no plain line on it.
  const md = await renderReportBodyMarkdown(S);
  const q4 = md.slice(md.indexOf("### Question 4: When did it start?"), md.indexOf("### Question 5"));
  assert.doesNotMatch(q4, /Asked parts|Part by part/);
});
