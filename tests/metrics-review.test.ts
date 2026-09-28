/**
 * The metrics under review (Astra, WP7): no free text a record carries
 * reaches the JSON; a premise rejected on a search alone is a negative, as
 * the gate says; a comparison neither guesses a result class nor calls a
 * result it does not assert "established"; stale coverage is never complete;
 * a follow-up admitted after done and a withdrawn question are not the run's
 * scope; an acceptance that no longer stands is not shown as current; a
 * register a run does not have is "not recorded", never a zero; a grant's
 * status is read at the run's end; and the cost's parts add up to its whole.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as L from "../extensions/leads.ts";
import { apportion, compareRuns, compareText, measureRun, metricsText } from "../scripts/metrics.ts";

const T = (hms: string) => `2026-09-28T${hms}.000Z`;

function chained(events: Array<Record<string, unknown>>): string {
  let prev = "genesis";
  return events
    .map((d, i) => {
      const body = { v: 1, seq: i + 1, ...d, prev };
      const hash = L.leadEventHash(body as never, prev);
      prev = hash;
      return `${JSON.stringify({ ...body, hash })}\n`;
    })
    .join("");
}

const lines = (rows: Array<Record<string, unknown>>) => rows.map((r) => `${JSON.stringify(r)}\n`).join("");

function write(S: string, rel: string, text: string): void {
  mkdirSync(join(S, rel, ".."), { recursive: true });
  writeFileSync(join(S, rel), text);
}

function run(name: string): string {
  const S = join(mkdtempSync(join(tmpdir(), "metrics-review-")), name);
  mkdirSync(S, { recursive: true });
  return S;
}

function entry(seq: number, by: string, kind: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 4, seq, kind, value: `entry ${seq}`, source: "s", evidence: "e", by, authors: [by], at: T(`10:${String(seq).padStart(2, "0")}:00`), hash: `h${seq}`, ...extra };
}

function answer(seq: number, by: string, section: string, result: string | null, support: number[] = [], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return entry(seq, by, "answer", { section: `question:${section}`, ...(result ? { result } : {}), reasoning: "r", support: support.map((s) => ({ seq: s, hash: `h${s}` })), ...extra });
}

const goalQ = (n: number, extra: Record<string, unknown> = {}) => ({ at: T("09:59:00"), by: "system", ev: "open", q: `Q-${n}`, rev: 1, act: { text: `question ${n}`, why: "goal", materiality: "material", priority: "normal" }, origin: { kind: "goal", via: "goal" }, decided: { scope: "in_scope", scope_why: "goal", section: String(n), leading_forms: [], ...extra } });
const seed = (n: number) => ({ at: T("09:59:00"), by: "system", ev: "seed", source: null, questions: Array.from({ length: n }, (_, i) => `Q-${i + 1}`), objectives: [] });
const sentinel = (S: string, at = "2026-09-28T11:00:00.000Z", reason = "done") => write(S, "done/SWARM_DONE", `---\nby: a1\noutput: report.md\nreason: ${reason}\noutcome: completed\nat: ${at}\n---\n\nCollective finished.\n`);

test("no free text a record carries reaches the metrics' JSON or table: a dispute's why and a done's or a stop's reason stay out, codes and ids go in", async () => {
  const S = run("sfree01");
  write(S, "ledger/entries.jsonl", lines([
    entry(1, "a1", "finding", { answers: ["1"] }),
    entry(2, "a1", "coverage", { coverage: "complete", result_refs: ["E-1"], answers: ["1"] }),
    answer(3, "a1", "1", "bounded_negative", [2]),
  ]));
  write(S, "ledger/disputes.jsonl", lines([{ v: 1, act: "dispute", seq: 1, target: "h1", by: "a2", at: T("10:05:00"), why: "MARKER-DISPUTE-WHY the command the finding quotes" }]));
  sentinel(S, "2026-09-28T11:00:00.000Z", "MARKER-DONE-REASON what the report concluded");
  const m = await measureRun(S);
  const json = JSON.stringify(m);
  for (const marker of ["MARKER-DISPUTE-WHY", "MARKER-DONE-REASON"]) {
    assert.ok(!json.includes(marker), `${marker} is in the JSON`);
    assert.ok(!metricsText(m).includes(marker), `${marker} is in the table`);
  }
  assert.deepEqual(m.coverage.stale, [{ record: "E-2", field: "complete", results: [{ result: "E-1", code: "disputed", disputed_by: ["a2"] }] }]);
  assert.deepEqual(m.outcome, { outcome: "completed", by: "a1", at: "2026-09-28T11:00:00.000Z" });
  // A stop's why too.
  write(S, "done/STOPPED", `${JSON.stringify({ outcome: "stopped", by: "operator", at: T("11:30:00"), why: "MARKER-STOP-WHY" })}\n`);
  const stopped = await measureRun(S);
  assert.ok(!JSON.stringify(stopped).includes("MARKER-STOP-WHY"));
  assert.equal(stopped.outcome.outcome, "stopped");
  const cmp = await compareRuns(S, S);
  for (const marker of ["MARKER-DISPUTE-WHY", "MARKER-DONE-REASON", "MARKER-STOP-WHY"]) assert.ok(!JSON.stringify(cmp).includes(marker) && !compareText(cmp).includes(marker), marker);
});

test("a premise rejected on a search alone is a negative, as the gate says; one a finding shows false is not", async () => {
  const S = run("sprem01");
  write(S, "questions/questions.jsonl", chained([goalQ(1), goalQ(2), seed(2)]));
  write(S, "ledger/entries.jsonl", lines([
    entry(1, "a1", "coverage", { coverage: "complete", result_refs: [], answers: ["1"] }),
    answer(2, "a1", "1", "premise_not_supported", [1]),
    entry(3, "a2", "finding", { answers: ["2"] }),
    answer(4, "a2", "2", "premise_not_supported", [3]),
  ]));
  sentinel(S);
  const m = await measureRun(S);
  assert.equal(m.negatives.answers, 1);
  assert.deepEqual(m.negatives.unreviewed_material, [{ section: "1", id: "Q-1", answer: "E-2", result: "premise_not_supported" }]);
  const c = await compareRuns(S, S);
  assert.deepEqual(c.questions.map((q) => [q.id, q.a.kind]), [["Q-1", "negative"], ["Q-2", "premise_rejected"]]);
});

test("a comparison guesses no result class, and calls a negative contradicted only by a result that asserts", async () => {
  const A = run("scmpa01");
  const B = run("scmpb01");
  for (const S of [A, B]) write(S, "questions/questions.jsonl", chained([goalQ(1), goalQ(2), goalQ(3), seed(3)]));
  write(A, "ledger/entries.jsonl", lines([answer(1, "a1", "1", null), answer(2, "a1", "2", "bounded_negative"), answer(3, "a1", "3", "bounded_negative")]));
  write(B, "ledger/entries.jsonl", lines([answer(1, "b1", "1", null), answer(2, "b1", "2", "out_of_scope"), answer(3, "b1", "3", "partial")]));
  const c = await compareRuns(A, B);
  const row = (id: string) => c.questions.find((q) => q.id === id)!;
  assert.equal(row("Q-1").verdict, "unknown", "two answers without a result are not an agreement");
  assert.deepEqual([row("Q-1").a.kind, row("Q-1").b.kind], ["unknown", "unknown"]);
  assert.equal(row("Q-2").verdict, "disagree");
  assert.ok(!row("Q-2").flags.some((f) => /asserted|established/.test(f)), `out of scope is not an assertion: ${row("Q-2").flags.join(" | ")}`);
  assert.equal(row("Q-3").verdict, "disagree");
  assert.ok(row("Q-3").flags.some((f) => /a negative in A \(bounded_negative\) is asserted in B \(partial\)/.test(f)));
  assert.equal(c.summary.negative_disagreements, 1);
  assert.equal(c.summary.unknown, 1);
  assert.equal(c.summary.agree, 0);
});

test("coverage whose results no longer stand is stale, never complete: a shared negative on it is a possible blind spot", async () => {
  const A = run("sstla01");
  const B = run("sstlb01");
  for (const S of [A, B]) write(S, "questions/questions.jsonl", chained([goalQ(1), seed(1)]));
  const base = [entry(1, "x1", "finding", { answers: ["1"] }), entry(2, "x1", "coverage", { coverage: "complete", result_refs: ["E-1"], answers: ["1"] }), answer(3, "x1", "1", "bounded_negative", [2])];
  // A: the result the coverage names was superseded; B: it is disputed.
  write(A, "ledger/entries.jsonl", lines([...base, entry(4, "x2", "finding", { supersedes: 1, answers: ["1"] })]));
  write(B, "ledger/entries.jsonl", lines(base));
  write(B, "ledger/disputes.jsonl", lines([{ v: 1, act: "dispute", seq: 1, target: "h1", by: "x2", at: T("10:05:00"), why: "no" }]));
  const c = await compareRuns(A, B);
  const q = c.questions[0];
  assert.deepEqual([q.a.coverage, q.b.coverage], [["stale"], ["stale"]]);
  assert.ok(q.flags.some((f) => /shared blind spot/.test(f)), q.flags.join(" | "));
  assert.equal(c.summary.shared_partial_negatives, 1);
  const m = await measureRun(A);
  assert.deepEqual([m.coverage.complete, m.coverage.stale.length], [0, 1]);
  assert.deepEqual(m.coverage.negatives_on_partial.map((x) => x.coverage), [["E-2 stale"]]);
});

test("a question admitted after the run's done is a follow-up, not the run's scope: the finished run's tails stand", async () => {
  const S = run("safter01");
  write(S, "questions/questions.jsonl", chained([
    goalQ(1),
    seed(1),
    { at: T("11:05:00"), by: "operator", ev: "open", q: "Q-2", rev: 1, act: { text: "a follow-up", why: "later", materiality: "material", priority: "normal" }, origin: { kind: "analyst", person: "p", role: "examiner" }, decided: { scope: "in_scope", scope_why: "by authority", section: "2", leading_forms: [], after_done: true } },
  ]));
  write(S, "ledger/entries.jsonl", lines([answer(10, "a1", "1", "established")]));
  sentinel(S);
  const m = await measureRun(S);
  assert.deepEqual(m.questions.in_scope.map((q) => q.id), ["Q-1"]);
  assert.deepEqual(m.tail.unanswered, []);
  assert.equal(m.tail.minutes_from_first_answers, 50);
});

test("a withdrawn question's answer is history: not counted as the run's negative, and one-sided in a comparison", async () => {
  const A = run("swda01");
  const B = run("swdb01");
  write(A, "questions/questions.jsonl", chained([goalQ(1), seed(1)]));
  write(B, "questions/questions.jsonl", chained([goalQ(1), seed(1), { at: T("10:30:00"), by: "operator", ev: "withdraw", q: "Q-1", rev: 1, act: { why: "not needed" }, origin: { kind: "analyst", person: "p", role: "examiner" } }]));
  for (const S of [A, B]) write(S, "ledger/entries.jsonl", lines([answer(1, "a1", "1", "bounded_negative")]));
  const mb = await measureRun(B);
  assert.deepEqual([mb.negatives.answers, mb.negatives.unreviewed_material.length], [0, 0]);
  assert.deepEqual(mb.negatives.out_of_scope, [{ section: "1", id: "Q-1", answer: "E-1", result: "bounded_negative" }]);
  const c = await compareRuns(A, B);
  assert.equal(c.questions[0].verdict, "only_a");
  assert.deepEqual([c.questions[0].b.in_scope, c.questions[0].b.answer, c.questions[0].b.history], [false, null, { answer: "E-1", result: "bounded_negative" }]);
});

test("an operator's acceptance that no longer stands (the question amended, or evidence arrived after it) is shown as lapsed, never as current", async () => {
  const accepted = { at: T("10:20:00"), by: "operator", ev: "accept", q: "Q-1", rev: 1, act: { as: "not_determinable", why: "limits" }, origin: { kind: "analyst", person: "p", role: "examiner" }, decided: { rev: 1, outcome: "examination_limited", answer: "E-1", answer_hash: "h1" } };
  const make = (name: string, after: Array<Record<string, unknown>>) => {
    const S = run(name);
    write(S, "questions/questions.jsonl", chained([goalQ(1), seed(1), accepted, ...after]));
    write(S, "ledger/entries.jsonl", lines([answer(1, "a1", "1", "not_determinable")]));
    return S;
  };
  const stands = make("sacc01", []);
  const amended = make("sacc02", [{ at: T("10:25:00"), by: "operator", ev: "amend", q: "Q-1", rev: 2, act: { text: "question 1, reworded" }, origin: { kind: "analyst", person: "p", role: "examiner" }, decided: { revision: true } }]);
  const evidence = make("sacc03", [{ at: T("10:26:00"), by: "operator", ev: "evidence", q: "Q-1", rev: 1, decided: { import: "import:ev-0001", ledger_seq: 1, inventory_rev: 1 } }]);
  const side = async (S: string) => (await compareRuns(S, S)).questions[0].a;
  assert.deepEqual([(await side(stands)).accepted, (await side(stands)).acceptance_lapsed], ["not_determinable", null]);
  for (const S of [amended, evidence]) {
    const s = await side(S);
    assert.deepEqual([s.accepted, s.acceptance_lapsed], [null, "not_determinable"], S);
    assert.ok((await compareRuns(S, S)).questions[0].flags.some((f) => /acceptance \(not_determinable\) no longer stands/.test(f)));
  }
});

test("a register the run does not have is not recorded, never a zero; each register makes its own metrics measured", async () => {
  const S = run("snone01");
  const rowOf = (text: string, name: string) => text.split("\n").find((l) => l.startsWith(name)) ?? "";
  const expectRows = async (measured: string[]) => {
    const m = await measureRun(S);
    const text = metricsText(m);
    const all = ["Quick negatives", "Negative answers", "Unreviewed negatives", "Coverage records", "Negatives on partial coverage", "Offers (leads)", "Wakes (before offers)", "done calls", "Acquisition", "Evidence added", "Interpretations", "Reversals", "Cost", "Duplicates", "Network"];
    for (const name of all) {
      const row = rowOf(text, name);
      assert.ok(row, `no ${name} row`);
      const value = row.slice(name.length).trimStart();
      if (measured.includes(name)) assert.doesNotMatch(value, /^(not recorded|not measured|not used)/, row);
      else assert.match(value, /^(not recorded|not measured|not used)/, row);
    }
    return m;
  };
  const none = await expectRows([]);
  for (const k of ["negatives", "coverage", "done", "acquisition", "interpretations", "reversals"] as const) assert.equal((none[k] as { recorded: boolean }).recorded, false, k);
  write(S, "ledger/entries.jsonl", lines([answer(1, "a1", "1", "established")]));
  const ledgerOnly = await expectRows(["Negative answers", "Unreviewed negatives", "Coverage records", "Negatives on partial coverage", "Reversals"]);
  assert.match(rowOf(metricsText(ledgerOnly), "Reversals"), /negative reopens not recorded \(no leads\/leads\.jsonl\)/, "the part a missing register holds is said, not zero");
  write(S, "leads/leads.jsonl", chained([{ at: T("10:00:00"), by: "a1", ev: "open", lead: "L-1", title: "t", why: "w", origin: "o", needs: [], answers: ["1"], material: true, holder: "a1", generation: 1 }]));
  await expectRows(["Negative answers", "Unreviewed negatives", "Coverage records", "Negatives on partial coverage", "Reversals", "Quick negatives", "Wakes (before offers)", "Interpretations"]);
  write(S, "traces/events.jsonl", "");
  write(S, "requests/requests.jsonl", "");
  write(S, "store/journal.jsonl", "");
  const all = await expectRows(["Negative answers", "Unreviewed negatives", "Coverage records", "Negatives on partial coverage", "Reversals", "Quick negatives", "Wakes (before offers)", "Interpretations", "done calls", "Acquisition", "Evidence added"]);
  assert.deepEqual([all.done.recorded, all.acquisition.recorded, all.acquisition.evidence_recorded], [true, true, true]);
});

test("a grant's status is read at the run's end, so a finished run measures the same whenever it is read", async () => {
  const S = run("sclock01");
  write(S, "done/SWARM_DONE", "---\nby: a1\nreason: done\noutcome: completed\nat: 2025-01-01T10:30:00.000Z\n---\n");
  const terms = { type: "fetch", principal: "seat:a1", lead: "L-1", adapter: "rdap", method: "GET", url: "https://rdap.org/x", scheme: "https", host: "rdap.org", port: 443, path: "/x", redirects: null, response_fields: null, max_requests: 1, max_bytes: 1000, ttl_seconds: 300 };
  write(S, "network/grants.jsonl", chained([
    { at: "2025-01-01T10:00:00.000Z", by: "a1", ev: "request", request: "NR-1", principal: "seat:a1", lead: "L-1", digest: "d", type: "fetch", host: "rdap.org", input: {} },
    { at: "2025-01-01T10:00:01.000Z", by: "policy", ev: "decide", request: "NR-1", decision: "granted", reasons: [], grant: "N-1" },
    // Used once, then expiring a minute after the run ended: at the run's end it was exhausted.
    { at: "2025-01-01T10:00:02.000Z", by: "policy", ev: "grant", grant: "N-1", request: "NR-1", terms: { ...terms, request: "NR-1", expires_at: "2025-01-01T10:31:00.000Z" } },
    // Unused, and still live when the run ended.
    { at: "2025-01-01T10:00:03.000Z", by: "policy", ev: "grant", grant: "N-2", request: "NR-1", terms: { ...terms, request: "NR-1", expires_at: "2025-01-01T10:45:00.000Z" } },
  ]));
  write(S, "network/fetches.jsonl", chained([
    { at: "2025-01-01T10:01:00.000Z", by: "fetch-service", ev: "attempt", grant: "N-1", n: 1, capture: "net:1/1", principal: "seat:a1", method: "GET", url: "https://rdap.org/x" },
    { at: "2025-01-01T10:01:01.000Z", by: "fetch-service", ev: "result", grant: "N-1", n: 1, capture: "net:1/1", status: 200, bytes: 10, complete: true, delivered: true, published: true },
  ]));
  assert.deepEqual((await measureRun(S)).network.grants_by_status, { exhausted: 1, granted: 1 });
  // A run still going is read at the time the caller gives (or now).
  const going = run("sclock02");
  write(going, "network/grants.jsonl", chained([{ at: "2025-01-01T10:00:02.000Z", by: "policy", ev: "grant", grant: "N-1", request: "NR-1", terms: { ...terms, request: "NR-1", expires_at: "2025-01-01T10:31:00.000Z" } }]));
  assert.deepEqual((await measureRun(going, { now: Date.parse("2025-01-01T10:20:00.000Z") })).network.grants_by_status, { granted: 1 });
  assert.deepEqual((await measureRun(going, { now: Date.parse("2025-01-01T10:40:00.000Z") })).network.grants_by_status, { expired: 1 });
});

test("the cost's parts add up to its whole: an indivisible call is shared by the largest remainder, in tokens and in millionths of a dollar", async () => {
  assert.deepEqual([...apportion(101, [["a", 50.5], ["b", 50.5]])], [["a", 51], ["b", 50]]);
  assert.deepEqual([...apportion(100, [["a", 100 / 3], ["b", 100 / 3], ["c", 100 / 3]])], [["a", 34], ["b", 33], ["c", 33]]);
  const S = run("scost01");
  write(S, "questions/questions.jsonl", chained([goalQ(1), goalQ(2), goalQ(3), seed(3)]));
  write(S, "leads/leads.jsonl", chained([{ at: T("10:00:00"), by: "a1", ev: "open", lead: "L-1", title: "t", why: "w", origin: "o", needs: [], answers: ["1", "2", "3"], material: true, holder: "a1", generation: 1 }]));
  write(S, "traces/model-gateway.jsonl", lines([{ at: T("10:01:00"), seat: "a1", input: 100, output: 1, cache_read: 0, cache_write: 0, cost_usd: 0.0001 }]));
  const m = await measureRun(S);
  assert.equal(m.cost.tokens, 101);
  assert.equal(m.cost.per_question.reduce((a, q) => a + q.tokens, 0) + m.cost.unheld.tokens + m.cost.leads_without_question.tokens, 101);
  assert.deepEqual(m.cost.per_question.map((q) => [q.id, q.tokens]), [["Q-1", 34], ["Q-2", 34], ["Q-3", 33]]);
  const micro = (x: number) => Math.round(x * 1e6);
  assert.equal(m.cost.per_question.reduce((a, q) => a + micro(q.usd), 0), micro(m.cost.usd));
  assert.equal(micro(m.cost.usd), 100);
});
