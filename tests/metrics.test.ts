/**
 * Process metrics (scripts/metrics.ts, docs/usage.md "Metrics") over a
 * synthetic run whose registers hold one case of everything each metric
 * counts, so every figure is checked against records written by hand: quick
 * and unreviewed negatives, coverage, offers (and wakes from before them),
 * done calls, the tail, acquisition, interpretations, reversals by cause,
 * cost per question, duplicates and the network. Then two runs compared,
 * and the command's own exits.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as L from "../extensions/leads.ts";
import { compareRuns, compareText, measureRun, metricsText } from "../scripts/metrics.ts";

const ROOT = join(import.meta.dirname, "..");
const T = (hms: string) => `2026-09-28T${hms}.000Z`;

/** A register's lines, chained as the hub writes them (seq from 1, prev, hash). */
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

type Answer = { seq: number; at: string; by: string; section: string; result: string; support?: number[]; supersedes?: number };

function entry(seq: number, at: string, by: string, kind: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 4, seq, kind, value: `entry ${seq}`, source: "s", evidence: "e", by, authors: [by], at: T(at), hash: `h${seq}`, ...extra };
}

function answer(a: Answer): Record<string, unknown> {
  return entry(a.seq, a.at, a.by, "answer", { section: `question:${a.section}`, result: a.result, reasoning: "r", ...(a.support ? { support: a.support.map((s) => ({ seq: s, hash: `h${s}` })) } : {}), ...(a.supersedes ? { supersedes: a.supersedes } : {}) });
}

/** The question register both runs share: Q-1..Q-3 of the goal, Q-4 an analyst's background question, Q-5 proposed; one question offer accepted, one declined, one not taken up. */
function questions(S: string): void {
  const goal = (n: number) => ({ at: T("09:59:00"), by: "system", ev: "open", q: `Q-${n}`, rev: 1, act: { text: `question ${n} of the goal`, why: "goal", materiality: "material", priority: "normal" }, origin: { kind: "goal", via: "goal" }, decided: { scope: "in_scope", scope_why: "goal", section: String(n), leading_forms: [] } });
  write(S, "questions/questions.jsonl", chained([
    goal(1), goal(2), goal(3),
    { at: T("09:59:00"), by: "system", ev: "seed", source: null, questions: ["Q-1", "Q-2", "Q-3"], objectives: [] },
    { at: T("10:02:00"), by: "operator", ev: "open", q: "Q-4", rev: 1, act: { text: "question 4 of the analyst", why: "context", materiality: "background", priority: "normal" }, origin: { kind: "analyst", person: "p", role: "examiner" }, decided: { scope: "in_scope", scope_why: "by authority", section: "4", leading_forms: [] } },
    { at: T("10:03:00"), by: "a1", ev: "open", q: "Q-5", rev: 1, act: { text: "question 5 of an agent", why: "a lead", materiality: "material", priority: "normal" }, origin: { kind: "agent", agent: "a1" }, decided: { scope: "proposed", scope_why: "outside every objective", section: "5", leading_forms: [] } },
    { at: T("10:02:01"), by: "system", ev: "offer", q: "Q-4", rev: 1, to: "a2", first: true, why: "suggested" },
    { at: T("10:02:05"), by: "a2", ev: "offer_accept", q: "Q-4", offer: 7 },
    { at: T("10:03:01"), by: "system", ev: "offer", q: "Q-4", rev: 1, to: "a3", first: false, why: "idle" },
    { at: T("10:03:05"), by: "a3", ev: "offer_decline", q: "Q-4", offer: 9, why: "busy" },
    { at: T("10:04:01"), by: "system", ev: "offer", q: "Q-4", rev: 1, to: "a1", first: false, why: "idle" },
  ]));
}

/** Run A: the registers described in the comments beside each line. */
function runA(): string {
  const S = join(mkdtempSync(join(tmpdir(), "metrics-")), "sa00001");
  questions(S);
  write(S, "leads/leads.jsonl", chained([
    { at: T("10:00:00"), by: "a1", ev: "open", lead: "L-1", title: "t", why: "w", origin: "o", needs: [], answers: ["1"], material: true, holder: "a1", generation: 1 },
    { at: T("10:00:05"), by: "a2", ev: "open", lead: "L-2", title: "t", why: "w", origin: "o", needs: [], answers: ["2"], material: true, holder: "a2", generation: 1 },
    { at: T("10:00:10"), by: "a1", ev: "job", lead: "L-1", job: "j000001" },
    { at: T("10:00:20"), by: "a2", ev: "job", lead: "L-2", job: "j000002" },
    { at: T("10:00:30"), by: "a2", ev: "job", lead: "L-2", job: "j000003" },
    { at: T("10:00:40"), by: "a2", ev: "job", lead: "L-2", job: "j000004" },
    // A quick negative: held a minute, one job, one object.
    { at: T("10:01:00"), by: "a1", ev: "close", lead: "L-1", generation: 1, disposition: "negative", ref: "E-3", quick_negative: { held_ms: 60000, jobs: 1, objects: 1 } },
    { at: T("10:05:00"), by: "a2", ev: "close", lead: "L-2", generation: 1, disposition: "negative", ref: "E-6" },
    { at: T("10:06:00"), by: "a1", ev: "interpret", job: "j000001", entry: 2, kind: "finding" },
    { at: T("10:06:00"), by: "a2", ev: "interpret", job: "j000002", entry: 4, kind: "finding" },
    { at: T("10:06:00"), by: "a2", ev: "interpret", job: "j000003", entry: 5, kind: "finding" },
    // Evidence arrived at 10:08: the negative lead reopens for it.
    { at: T("10:10:00"), by: "system", ev: "reopen", lead: "L-2", why: "evidence added", cause: "evidence_added", import: "ev-0001" },
    { at: T("10:11:00"), by: "a3", ev: "open", lead: "L-3", title: "t", why: "w", origin: "o", needs: [], answers: ["3"], material: true, generation: 0 },
    // A wake from before offers, taken by another seat.
    { at: T("10:11:01"), by: "system", ev: "wake", lead: "L-3", to: "a1", cycle: 0 },
    { at: T("10:11:05"), by: "a2", ev: "claim", lead: "L-3", holder: "a2", generation: 1 },
    // Offers: accepted by the claim naming it, declined, taken by another, lapsed.
    { at: T("10:12:00"), by: "a3", ev: "open", lead: "L-4", title: "t", why: "w", origin: "o", needs: [], answers: ["3"], material: true, generation: 0 },
    { at: T("10:12:01"), by: "system", ev: "offer", lead: "L-4", to: "a1", reason: "wake", rev: 1, cycle: 0 },
    { at: T("10:12:05"), by: "a1", ev: "claim", lead: "L-4", holder: "a1", generation: 1, offer: 17 },
    { at: T("10:12:10"), by: "a1", ev: "open", lead: "L-5", title: "t", why: "w", origin: "o", needs: [], answers: ["4"], material: false, generation: 0 },
    { at: T("10:12:11"), by: "system", ev: "offer", lead: "L-5", to: "a2", reason: "wake", rev: 1, cycle: 0 },
    { at: T("10:12:15"), by: "a2", ev: "offer_decline", lead: "L-5", offer: 20, why: "busy" },
    { at: T("10:12:20"), by: "a1", ev: "open", lead: "L-6", title: "t", why: "w", origin: "o", needs: [], answers: ["4"], material: false, generation: 0 },
    { at: T("10:12:21"), by: "system", ev: "offer", lead: "L-6", to: "a3", reason: "wake", rev: 1, cycle: 0 },
    { at: T("10:12:30"), by: "a1", ev: "claim", lead: "L-6", holder: "a1", generation: 1 },
    { at: T("10:12:40"), by: "a1", ev: "open", lead: "L-7", title: "t", why: "w", origin: "o", needs: [], answers: ["4"], material: false, generation: 0 },
    { at: T("10:12:41"), by: "system", ev: "offer", lead: "L-7", to: "a3", reason: "parked", rev: 1, cycle: 0, from: "a1" },
    { at: T("10:14:00"), by: "system", ev: "offer_lapse", lead: "L-7", offer: 26, to: "a3", why: "not taken" },
    // A wake taken by the woken seat.
    { at: T("10:14:10"), by: "a1", ev: "open", lead: "L-8", title: "t", why: "w", origin: "o", needs: [], answers: ["4"], material: false, generation: 0 },
    { at: T("10:14:11"), by: "system", ev: "wake", lead: "L-8", to: "a1", cycle: 0 },
    { at: T("10:14:15"), by: "a1", ev: "claim", lead: "L-8", holder: "a1", generation: 1 },
    // A lead that answers no question.
    { at: T("10:15:00"), by: "a3", ev: "open", lead: "L-9", title: "t", why: "w", origin: "o", needs: [], answers: [], material: false, holder: "a3", generation: 1 },
    { at: T("10:16:00"), by: "a3", ev: "close", lead: "L-9", generation: 1, disposition: "resolved", ref: "E-2" },
    { at: T("10:20:00"), by: "a2", ev: "close", lead: "L-3", generation: 1, disposition: "resolved", ref: "E-13" },
    // An offer that lapsed, and the lead then claimed by another seat: taken by another.
    { at: T("10:22:00"), by: "a1", ev: "open", lead: "L-10", title: "t", why: "w", origin: "o", needs: [], answers: ["4"], material: false, generation: 0 },
    { at: T("10:22:01"), by: "system", ev: "offer", lead: "L-10", to: "a2", reason: "wake", rev: 1, cycle: 0 },
    { at: T("10:23:10"), by: "system", ev: "offer_lapse", lead: "L-10", offer: 35, to: "a2", why: "not taken" },
    { at: T("10:23:15"), by: "a1", ev: "claim", lead: "L-10", holder: "a1", generation: 1 },
  ]));
  write(S, "ledger/entries.jsonl", lines([
    entry(1, "10:00:15", "a1", "finding"),
    entry(2, "10:00:50", "a1", "finding"),
    entry(3, "10:00:55", "a1", "coverage", { coverage: "complete", result_refs: ["E-2"], answers: ["1"] }),
    entry(4, "10:04:00", "a2", "finding"),
    entry(5, "10:04:30", "a2", "finding"),
    entry(6, "10:04:50", "a2", "coverage", { coverage: "partial", result_refs: ["E-4"], answers: ["2"] }),
    answer({ seq: 7, at: "10:05:30", by: "a1", section: "1", result: "bounded_negative", support: [3] }),
    answer({ seq: 8, at: "10:06:30", by: "a1", section: "4", result: "not_determinable" }),
    entry(9, "10:07:00", "a2", "finding", { supersedes: 4 }),
    answer({ seq: 10, at: "10:07:30", by: "a2", section: "2", result: "bounded_negative", support: [6] }),
    answer({ seq: 11, at: "10:09:00", by: "a2", section: "2", result: "not_determinable", support: [6], supersedes: 10 }),
    answer({ seq: 12, at: "10:09:30", by: "a2", section: "3", result: "bounded_negative" }),
    answer({ seq: 13, at: "10:21:00", by: "a2", section: "3", result: "established", supersedes: 12 }),
    answer({ seq: 14, at: "10:21:10", by: "a1", section: "1", result: "bounded_negative", support: [3], supersedes: 7 }),
  ]));
  // a3 reviewed the coverage record Q-1's negative rests on; a1 disputes E-5.
  write(S, "ledger/attestations.jsonl", lines([{ v: 2, act: "attest", seq: 3, target: "h3", by: "a3", at: T("10:06:00"), how: "re-ran it", review: { detection: { done: true, text: "d" }, reproduced: { done: true, text: "r" }, other_route: { done: false, text: "none" } } }]));
  write(S, "ledger/disputes.jsonl", lines([{ v: 1, act: "dispute", seq: 5, target: "h5", by: "a1", at: T("10:06:30"), why: "does not hold" }]));
  write(S, "leads/finish.jsonl", chained([
    { at: T("10:21:30"), by: "system", ev: "readiness", ready: true, revision: "r1", items: [] },
    { at: T("10:22:00"), by: "system", ev: "readiness", ready: false, revision: "r2", items: ["a late post"] },
    { at: T("10:25:00"), by: "system", ev: "readiness", ready: true, revision: "r3", items: [] },
  ]));
  write(S, "done/SWARM_DONE", "---\nby: a1\noutput: report.md\nreason: done\noutcome: completed\nat: 2026-09-28T10:30:00.000Z\n---\n\nCollective finished.\n");
  write(S, "traces/events.jsonl", lines([
    { ts: T("10:26:00"), agent: "a1", tool: "done", args: {}, result: { ok: false, reason: "The finish line is not met: 1 of 2 checks pass." } },
    { ts: T("10:27:00"), agent: "a2", tool: "done", args: {}, result: { ok: false, reason: "2 post(s) landed after `report.md` was last written", late: 2 } },
    { ts: T("10:27:30"), agent: "a3", tool: "done_deferred", args: {}, result: { ok: true, coordinator: "a1" } },
    { ts: T("10:28:00"), agent: "system", tool: "hub_call", args: { agent: "a2", fn: "markDone" }, result: { ok: false, error: "not met", repeated_before: 2 } },
    { ts: T("10:29:00"), agent: "system", tool: "hub_call", args: { agent: "a2", fn: "markDone" }, result: { ok: false, error: "not met", repeated: 1, repeated_until: T("10:29:00") } },
    { ts: T("10:29:30"), agent: "system", tool: "hub_call", args: { agent: "a3", fn: "markDone" }, result: { ok: true, created_sentinel: false } },
    { ts: T("10:30:00"), agent: "a1", tool: "done", args: {}, result: { reason: "done", output_file: "report.md", created_sentinel: true, outcome: "completed" } },
  ]));
  // Requests: validated, declined by the case policy, still requested; and a clarification, which is not an acquisition.
  const acq = (rid: string, q: string) => ({ at: T("10:02:00"), by: "a2", ev: "open", rid, kind: "acquisition", key: `lead:${rid}`, line: {}, questions: [q], ask: { kind: "acquisition", source: "s", where: "w", questions: [q], expected_value: "v", urgency: "normal", owner: "o", authority_needed: "a" } });
  write(S, "requests/requests.jsonl", chained([
    acq("R-1", "Q-2"),
    { at: T("10:03:00"), by: "operator", ev: "stage", rid: "R-1", stage: "authorised" },
    { at: T("10:07:00"), by: "operator", ev: "stage", rid: "R-1", stage: "received" },
    { at: T("10:08:00"), by: "operator", ev: "stage", rid: "R-1", stage: "validated" },
    { at: T("10:08:00"), by: "operator", ev: "answered", rid: "R-1", cause: "evidence_added" },
    acq("R-2", "Q-4"),
    { at: T("10:02:00"), by: "case policy", ev: "stage", rid: "R-2", stage: "declined" },
    { at: T("10:02:00"), by: "case policy", ev: "declined", rid: "R-2", cause: "case_policy" },
    acq("R-3", "Q-3"),
    { at: T("10:04:00"), by: "a1", ev: "open", rid: "R-4", kind: "clarification", key: "clarification:Q-4#C-1", line: {}, questions: ["Q-4"] },
  ]));
  write(S, "store/journal.jsonl", lines([
    { seq: 0, at: T("10:00:10"), type: "job_accepted", job: "j000001", spec: { kind: "command" }, requester: { agent: "a1" }, reuse: { op: "command:strings", objects: [] } },
    { seq: 1, at: T("10:00:20"), type: "job_accepted", job: "j000002", spec: { kind: "command" }, requester: { agent: "a2" }, reuse: { op: "command:strings", objects: [] } },
    { seq: 2, at: T("10:00:20"), type: "job_similar", job: "j000002", by: { agent: "a2" }, similar: [{ job: "j000001", match: "same command", objects: "same" }] },
    { seq: 3, at: T("10:00:30"), type: "job_accepted", job: "j000003", spec: { kind: "command", independent: true }, requester: { agent: "a2" }, reuse: { op: "command:strings", objects: [] } },
    { seq: 4, at: T("10:00:30"), type: "job_similar", job: "j000003", by: { agent: "a2" }, independent: true, similar: [{ job: "j000001", match: "same leading command", objects: "overlap" }] },
    { seq: 5, at: T("10:00:40"), type: "job_accepted", job: "j000005", spec: { kind: "command" }, requester: { agent: "a3" }, reuse: { op: "command:strings", objects: [] } },
    { seq: 6, at: T("10:00:40"), type: "job_similar", job: "j000005", by: { agent: "a3" }, similar: [{ job: "j000001", match: "same leading command", objects: "same" }] },
    { seq: 7, at: T("10:01:00"), type: "job_same_as", job: "j000002", same_as: [{ path: "a.txt", sha256: "c".repeat(64), bytes: 10, job: "j000001", file: "a.txt" }] },
    { seq: 8, at: T("10:01:10"), type: "job_same_as", job: "j000005", same_as: [{ path: "x", sha256: "d".repeat(64), bytes: 5, job: "j000001", file: "x" }] },
    { seq: 9, at: T("10:01:20"), type: "job_deduplicated", job: "j000006", by: { agent: "a1" }, dedup_key: "k", notify: false },
    { seq: 10, at: T("10:01:30"), type: "job_would_merge", job: "j000007", same_as: "j000001" },
    { seq: 11, at: T("10:08:00"), type: "evidence_added", import: "ev-0001", files: [{ path: "late.bin", sha256: "e".repeat(64), bytes: 3 }], request: "R-1", questions: ["Q-2"], inventory_rev: 1 },
  ]));
  write(S, "store/jobs/j000002/manifest.json", JSON.stringify({ files: [{ path: "a.txt", bytes: 10 }, { path: "empty", bytes: 0 }] }));
  write(S, "store/jobs/j000005/manifest.json", JSON.stringify({ files: [{ path: "x", bytes: 5 }, { path: "y", bytes: 7 }] }));
  // The network: one granted request used once, two denied (one opening an operator item), a revoked and an expired grant, a refused use.
  const grant = (id: string, request: string, extra: Record<string, unknown>) => ({ at: T("10:03:00"), by: "policy", ev: "grant", grant: id, request, terms: { request, type: "fetch", principal: "seat:a2", lead: "L-2", adapter: "rdap", method: "GET", url: "https://rdap.org/x", scheme: "https", host: "rdap.org", port: 443, path: "/x", redirects: null, response_fields: null, max_requests: 1, max_bytes: 1000, ttl_seconds: 300, expires_at: T("23:59:00"), ...extra } });
  write(S, "network/grants.jsonl", chained([
    { at: T("10:02:50"), by: "a2", ev: "request", request: "NR-1", principal: "seat:a2", lead: "L-2", digest: "d1", type: "fetch", host: "rdap.org", input: {} },
    { at: T("10:02:51"), by: "policy", ev: "decide", request: "NR-1", decision: "granted", reasons: [], grant: "N-1" },
    grant("N-1", "NR-1", {}),
    { at: T("10:03:10"), by: "a2", ev: "request", request: "NR-2", principal: "seat:a2", lead: "L-2", digest: "d2", type: "fetch", host: "search.example", input: {} },
    { at: T("10:03:11"), by: "policy", ev: "decide", request: "NR-2", decision: "denied", reasons: [{ step: 4, rule: "hard", code: "search_engine", detail: "x", overridable: false }], item: "NI-1" },
    { at: T("10:03:11"), by: "policy", ev: "item", item: "NI-1", host: "search.example", lead: "L-2", request: "NR-2", reasons: [] },
    { at: T("10:03:20"), by: "a2", ev: "request", request: "NR-3", principal: "seat:a2", lead: "L-2", digest: "d3", type: "fetch", host: "search.example", input: {} },
    { at: T("10:03:21"), by: "policy", ev: "decide", request: "NR-3", decision: "denied", reasons: [{ step: 4, rule: "hard", code: "search_engine", detail: "x", overridable: false }, { step: 8, rule: "quota", code: "quota", detail: "y", overridable: false }] },
    grant("N-2", "NR-1", {}),
    { at: T("10:04:00"), by: "operator", ev: "revoke", grant: "N-2", cause: "operator", why: "no" },
    grant("N-3", "NR-1", { expires_at: T("10:05:00") }),
  ]));
  write(S, "network/fetches.jsonl", chained([
    { at: T("10:03:30"), by: "fetch-service", ev: "attempt", grant: "N-1", n: 1, capture: "net:1/1", principal: "seat:a2", method: "GET", url: "https://rdap.org/x" },
    { at: T("10:03:31"), by: "fetch-service", ev: "result", grant: "N-1", n: 1, capture: "net:1/1", status: 200, bytes: 10, complete: true, delivered: true, published: true },
    { at: T("10:03:40"), by: "fetch-service", ev: "refused", principal: "seat:a3", grant: "N-1", code: "principal_mismatch", detail: "not yours" },
  ]));
  // Spend: a1 on L-1 (Q-1); a2 on L-2 (Q-2); a3 holding nothing; a1 holding L-4 (Q-3) and L-6 (Q-4) at once; a3 on L-9, which answers no question.
  write(S, "traces/model-gateway.jsonl", lines([
    { at: T("10:00:30"), seat: "a1", input: 800, output: 200, cache_read: 0, cache_write: 0, cost_usd: 0.01 },
    { at: T("10:00:30"), seat: "a2", input: 300, output: 100, cache_read: 0, cache_write: 0, cost_usd: 0.004 },
    { at: T("10:11:30"), seat: "a3", input: 200, output: 0, cache_read: 0, cache_write: 0, cost_usd: 0.002 },
    { at: T("10:13:00"), seat: "a1", input: 400, output: 100, cache_read: 100, cache_write: 0, cost_usd: 0.006 },
    { at: T("10:15:30"), seat: "a3", input: 300, output: 0, cache_read: 0, cache_write: 0, cost_usd: 0.003 },
    { at: T("10:16:00"), seat: "a2", refused: "cap", status: 429 },
  ]));
  return S;
}

test("every metric of a run, from its registers", async () => {
  const S = runA();
  const m = await measureRun(S);
  assert.deepEqual(m.questions.in_scope.map((q) => q.id), ["Q-1", "Q-2", "Q-3", "Q-4"], "the proposed Q-5 is not in scope");
  // Negatives and coverage.
  assert.equal(m.negatives.closes, 2);
  assert.deepEqual(m.negatives.quick.items.map((x) => [x.lead, x.held_seconds, x.jobs, x.objects, x.questions]), [["L-1", 60, 1, 1, ["1"]]]);
  assert.equal(m.negatives.answers, 3, "Q-1, Q-2 and Q-4 stand negative; Q-3 was established");
  assert.equal(m.negatives.reviewed, 1, "Q-1's rests on a coverage record a3 reviewed");
  assert.deepEqual(m.negatives.unreviewed_material, [{ section: "2", id: "Q-2", answer: "E-11", result: "not_determinable" }]);
  assert.deepEqual(m.negatives.unreviewed_background, [{ section: "4", id: "Q-4", answer: "E-8", result: "not_determinable" }]);
  assert.deepEqual([m.coverage.records, m.coverage.reviewed, m.coverage.complete, m.coverage.partial, m.coverage.not_computed], [2, 1, 1, 1, 0]);
  assert.deepEqual(m.coverage.stale.map((x) => x.record), ["E-6"], "E-6's result E-4 was superseded");
  assert.deepEqual(m.coverage.negatives_on_partial.map((x) => [x.section, x.answer]), [["2", "E-11"]]);
  assert.deepEqual(m.coverage.negatives_without_coverage, [{ section: "4", id: "Q-4", answer: "E-8" }]);
  // Offers.
  assert.equal(m.offers.recorded, true);
  const { made, accepted, declined, taken_by_another, lapsed, open } = m.offers.leads;
  assert.deepEqual({ made, accepted, declined, taken_by_another, lapsed, open }, { made: 5, accepted: 1, declined: 1, taken_by_another: 2, lapsed: 1, open: 0 });
  assert.equal(m.offers.leads.by_reason.parked.lapsed, 1);
  assert.deepEqual(m.offers.questions, { made: 3, accepted: 1, declined: 1, not_taken_up: 1 });
  assert.deepEqual(m.offers.wakes_before_offers, { made: 2, taken_by_woken: 1, taken_by_another: 1, not_taken: 0 });
  // done calls.
  assert.deepEqual([m.done.calls, m.done.accepted, m.done.created_sentinel, m.done.refused, m.done.hub_refused, m.done.not_yours], [8, 1, 1, 2, 4, 1]);
  assert.deepEqual(m.done.refused_by, { "finish line not met": 1, "late posts": 1 });
  // The tail: ready at 10:25 (the turn at 10:21:30 was undone at 10:22), the end at 10:30.
  assert.equal(m.tail.end, "sentinel");
  assert.deepEqual([m.tail.ready_at, m.tail.ready_source, m.tail.minutes_from_ready], [T("10:25:00"), "readiness", 5]);
  assert.deepEqual([m.tail.all_first_answered_at, m.tail.minutes_from_first_answers], [T("10:09:30"), 20.5]);
  assert.deepEqual([m.tail.all_final_answered_at, m.tail.minutes_from_final_answers], [T("10:21:10"), 8.8]);
  assert.deepEqual(m.tail.unanswered, []);
  // Acquisition.
  assert.equal(m.acquisition.requests, 3, "the clarification is not an acquisition");
  assert.deepEqual(m.acquisition.by_stage, { validated: 1, declined: 1, requested: 1 });
  assert.equal(m.acquisition.declined_by_policy, 1);
  assert.deepEqual(m.acquisition.gaps.map((g) => [g.rid, g.stage]), [["R-2", "declined"], ["R-3", "requested"]]);
  assert.deepEqual(m.acquisition.questions_with_gap, ["Q-3", "Q-4"]);
  assert.deepEqual([m.acquisition.evidence_added, m.acquisition.evidence_added_for_request], [1, 1]);
  // Interpretations.
  const i = m.interpretations;
  assert.deepEqual([i.total, i.valid, i.superseded, i.disputed, i.missing, i.jobs_under_leads], [3, 1, 1, 1, 0, 4]);
  assert.deepEqual(i.jobs_uninterpreted, ["j000004"]);
  assert.deepEqual(i.jobs_without_valid, ["j000002", "j000003"]);
  // Reversals: Q-2 changed after the evidence came, Q-3 without it; L-2 reopened for the evidence; Q-1's correction kept its result.
  assert.deepEqual(m.reversals.result_changes.map((x) => [x.section, x.from, x.to, x.cause]), [["2", "E-10", "E-11", "new_evidence"], ["3", "E-12", "E-13", "discoverable"]]);
  assert.deepEqual(m.reversals.negative_reopens.map((x) => [x.lead, x.reopen_cause, x.cause]), [["L-2", "evidence_added", "new_evidence"]]);
  assert.deepEqual([m.reversals.answer_supersessions, m.reversals.corrections, m.reversals.new_evidence, m.reversals.discoverable], [3, 1, 2, 1]);
  // Cost per question.
  assert.equal(m.cost.source, "model-gateway");
  assert.equal(m.cost.tokens, 2500, "the refused call carried no usage");
  assert.deepEqual(m.cost.per_question.map((q) => [q.id, q.tokens, q.leads]), [["Q-1", 1000, ["L-1"]], ["Q-2", 400, ["L-2"]], ["Q-3", 300, ["L-4"]], ["Q-4", 300, ["L-6"]]]);
  assert.deepEqual(m.cost.unheld, { tokens: 200, usd: 0.002 });
  assert.deepEqual(m.cost.leads_without_question, { tokens: 300, usd: 0.003, leads: ["L-9"] });
  // Duplicates.
  const d = m.duplicates;
  assert.equal(d.recorded, true);
  assert.deepEqual([d.jobs_with_similar, d.exact_repeats, d.independent, d.independent_with_similar], [["j000002", "j000005"], ["j000002"], ["j000003"], ["j000003"]]);
  assert.deepEqual(d.same_as, { jobs: ["j000002", "j000005"], files: 2, bytes: 15, whole: ["j000002"] });
  assert.deepEqual([d.recipe_merged, d.shadow_would_merge], [1, 1]);
  // Network.
  const n = m.network;
  assert.deepEqual([n.recorded, n.requests, n.granted, n.denied, n.operator_items, n.operator_items_open, n.grants], [true, 3, 1, 2, 1, 1, 3]);
  assert.deepEqual(n.denied_by_code, { search_engine: 2, quota: 1 });
  assert.deepEqual(n.grants_by_status, { exhausted: 1, revoked: 1, expired: 1 });
  assert.deepEqual([n.fetches, n.captures, n.captures_complete, n.fetch_refusals, n.contamination], [1, 1, 1, 1, 0]);
  // The table names each metric, and prints no answer's value.
  const text = metricsText(m);
  for (const row of ["Quick negatives", "Unreviewed negatives", "Coverage records", "Offers (leads)", "done calls", "Tail to the end", "Acquisition", "Interpretations", "Reversals", "Cost", "Duplicates", "Network", "Cost per question"]) assert.ok(text.includes(row), row);
  assert.ok(!/entry \d+/.test(text), "no entry's value is printed");
});

test("a run from before offers, readiness and reuse hints says what it cannot count, and reads what it can", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "metrics-old-")), "sold01");
  write(S, "leads/leads.jsonl", chained([
    { at: T("10:00:00"), by: "a1", ev: "open", lead: "L-1", title: "t", why: "w", origin: "o", needs: [], answers: ["1"], material: true, generation: 0 },
    { at: T("10:00:01"), by: "system", ev: "wake", lead: "L-1", to: "a2", cycle: 0 },
  ]));
  write(S, "ledger/entries.jsonl", lines([answer({ seq: 1, at: "10:05:00", by: "a1", section: "1", result: "established" })]));
  write(S, "store/journal.jsonl", lines([{ seq: 0, at: T("10:00:10"), type: "job_accepted", job: "j000001", spec: { kind: "command" }, requester: { agent: "a1" } }]));
  write(S, "done/SWARM_DONE", "---\nby: a1\nat: 2026-09-28T10:15:00.000Z\n---\n");
  const m = await measureRun(S);
  assert.equal(m.questions.source, "ledger");
  assert.equal(m.offers.recorded, false);
  assert.deepEqual(m.offers.wakes_before_offers, { made: 1, taken_by_woken: 0, taken_by_another: 0, not_taken: 1 });
  assert.equal(m.duplicates.recorded, false);
  assert.equal(m.network.recorded, false);
  assert.deepEqual([m.tail.ready_source, m.tail.minutes_from_ready, m.tail.minutes_from_first_answers], ["first answers", 10, 10]);
  assert.equal(m.cost.source, null);
  for (const said of [/before offers/, /before them/, /no finish register/, /no per-call token record/]) assert.ok(m.notes.some((x) => said.test(x)), `${said}: ${m.notes.join(" | ")}`);
  assert.match(metricsText(m), /Offers \(leads\)\s+not recorded/);
});

test("two runs of the same goal compared: agreement, a negative the other established, and a shared negative on partial coverage", async () => {
  const A = runA();
  const B = join(mkdtempSync(join(tmpdir(), "metrics-b-")), "sb00001");
  cpSync(A, B, { recursive: true });
  write(B, "ledger/entries.jsonl", lines([
    entry(1, "10:00:15", "b1", "finding"),
    entry(2, "10:00:50", "b1", "coverage", { coverage: "partial", result_refs: ["E-1"], answers: ["2"] }),
    answer({ seq: 3, at: "10:05:00", by: "b1", section: "1", result: "established" }),
    answer({ seq: 4, at: "10:06:00", by: "b1", section: "2", result: "bounded_negative", support: [2] }),
    answer({ seq: 5, at: "10:07:00", by: "b2", section: "3", result: "established" }),
  ]));
  write(B, "ledger/attestations.jsonl", "");
  write(B, "ledger/disputes.jsonl", "");
  const c = await compareRuns(A, B);
  assert.equal(c.same_questions, true);
  const row = (id: string) => c.questions.find((q) => q.id === id)!;
  assert.deepEqual([row("Q-1").a.result, row("Q-1").b.result, row("Q-1").verdict], ["bounded_negative", "established", "disagree"]);
  assert.ok(row("Q-1").flags.some((f) => /a negative in A .* is established in the other/.test(f)), row("Q-1").flags.join(" | "));
  assert.equal(row("Q-2").verdict, "class_differs", "not_determinable against bounded_negative: both negative");
  assert.ok(row("Q-2").flags.some((f) => /shared blind spot/.test(f)), row("Q-2").flags.join(" | "));
  assert.ok(row("Q-2").flags.some((f) => /not reviewed by another seat in A and B/.test(f)));
  assert.equal(row("Q-3").verdict, "agree");
  assert.equal(row("Q-4").verdict, "only_a");
  assert.deepEqual(c.summary, { questions: 4, agree: 1, class_differs: 1, disagree: 1, one_sided: 1, neither: 0, negative_disagreements: 1, shared_partial_negatives: 1 });
  const text = compareText(c);
  assert.match(text, /Agreement is not confirmation/);
  assert.ok(!/entry \d+/.test(text), "no answer's value is printed");
  // Different questions are said.
  write(B, "questions/questions.jsonl", "");
  const d = await compareRuns(A, B);
  assert.equal(d.same_questions, false);
  assert.ok(d.notes.some((x) => /questions differ/.test(x)));
});

test("the command: a table or JSON for one run, --compare for two, and a usage error otherwise", () => {
  const S = runA();
  const run = (...args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "metrics.ts"), ...args], { encoding: "utf8" });
  const table = run(S);
  assert.equal(table.status, 0, table.stderr);
  assert.match(table.stdout, /^Metrics: run sa00001 \(completed\)/);
  const json = JSON.parse(run(S, "--json").stdout) as { format: string; negatives: { quick: { count: number } } };
  assert.deepEqual([json.format, json.negatives.quick.count], ["dfirswarm-metrics/1", 1]);
  const cmp = run("--compare", S, S, "--json");
  assert.equal(cmp.status, 0, cmp.stderr);
  assert.equal((JSON.parse(cmp.stdout) as { summary: { disagree: number } }).summary.disagree, 0, "a run agrees with itself");
  assert.equal(run().status, 2);
  assert.equal(run("--compare", S).status, 2);
  assert.equal(run(join(S, "nothing")).status, 2);
});
