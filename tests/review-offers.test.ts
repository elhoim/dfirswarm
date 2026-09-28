/**
 * Reviews are offered, one seat at a time (the c10 pilot, run s6be12f): six
 * seats did a route review of one deferred lead (L-27) within minutes, one
 * of them twice, and a material negative's peer reviews could pile up the
 * same way. A route review and a negative's review are offered through the
 * offer mechanism to one eligible seat (never the closer or an author, never
 * a seat compacting, the relevant first); another seat's review of an item
 * already reviewed or offered returns quietly with who has it and records
 * nothing; a further independent review needs its why. And a confirmation
 * offer waits while its closer compacts, bounded, where done or dead
 * reopens it at once (the pilot's L-17 was reopened three times so).
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { A, coverage, F, ok, okq, rec, REVIEW, run } from "./negative-bar-fixture.ts";

const operator: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };

async function traceRow(S: string, agent: string, tool: string, at: Date = new Date()): Promise<void> {
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at.toISOString(), recv_ts: at.toISOString(), agent, tool, args: {}, result: { ok: true } })}\n`);
}

async function idleFor(S: string, agent: string, min: number): Promise<void> {
  const at = new Date(Date.now() - min * 60_000).toISOString();
  await mkdir(join(S, "inbox", agent), { recursive: true });
  await writeFile(join(S, "inbox", agent, "waiting.json"), JSON.stringify({ since: at, started_at: at }));
}

async function withEnv<T>(env: Record<string, string>, fn: () => Promise<T>): Promise<T> {
  const was = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  Object.assign(process.env, env);
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(was)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/** A deferred material lead under question 1, closed by a0, while a1 works the question on another lead. */
async function deferredRoute(c: Awaited<ReturnType<typeof run>>) {
  for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(c.S, a, "bash");
  const other = okq(await L.openLead(c.a1, { title: "Read the logon log", why: "q1", answers: ["1"], take: true, overlap: "second_route", overlap_why: "the log, not the disk", routes: [{ source: "input:logs/a.log", method: "read the log" }] }));
  const route = okq(await L.openLead(c.a0, { title: "Carve the unallocated space", why: "q1", answers: ["1"], take: true, routes: [{ source: "input:disk.E01", method: "carve" }] }));
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The unallocated space is wiped", source: "the disk", evidence: "zeros", reason: "unavailable" })).entry;
  okq(await L.closeLead(c.a0, route.lead.id, { disposition: "deferred", ref: `E-${lim.seq}` }));
  return { lead: route.lead.id, other: other.lead.id };
}

test("a route review is offered to one relevant seat, never its closer; another seat's review returns quietly with who has it and records nothing; a second review needs its why", async () => {
  const c = await run();
  const { lead } = await deferredRoute(c);
  // Its question is not answered yet: nothing to review.
  assert.equal(await L.offerReviews(c.S), 0);
  const f = ok(await rec(c.a1, { kind: "finding", ...F, value: "Bob logged on", source: "the log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  ok(await rec(c.a2, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${f.seq}`, result: "established", ...A, confidence: "high" }));
  // Answered now: one offer, to a1 (it worked the question), not a0 (the closer).
  assert.equal(await L.offerReviews(c.S), 1);
  assert.equal(await L.offerReviews(c.S), 0, "one offer at a time for one item");
  const snap = await L.leadsSnapshot(c.S);
  const offers = snap.state.reviewOffers.get(lead) ?? [];
  assert.deepEqual(offers.map((o) => [o.to, o.reason]), [["a1", "route_review"]]);
  // The offered seat is told in its header.
  assert.match((await L.leadsDigest(c.a1, { mark: true })).text, new RegExp(`${lead} .*is offered to you for its route review`));
  // The stampede: other seats' reviews return quietly, nothing recorded.
  for (const seat of [c.a2, c.a3]) {
    const r = okq(await L.routeReview(seat, lead, { material: true, why: "the carve might hold more" }));
    assert.deepEqual([r.deferred?.to, r.deferred?.by], ["a1", undefined]);
  }
  const reviewsNow = async () => (await L.leadsSnapshot(c.S)).state.leads.get(lead)!.route_reviews.length;
  assert.equal(await reviewsNow(), 0, "a deferred review records nothing");
  // The offered seat reviews: recorded, the offer accepted.
  const done = okq(await L.routeReview(c.a1, lead, { material: false, why: "the log answers question 1 without the carve" }));
  assert.equal(done.deferred, undefined);
  assert.equal(await reviewsNow(), 1);
  const after = await L.leadsSnapshot(c.S);
  assert.ok(after.state.reviewOffers.get(lead)!.at(-1)!.accepted, "the review accepted the offer");
  // Reviewed: a later review is quiet, naming the reviewer; the same seat twice too.
  for (const seat of [c.a2, c.a1]) {
    const again = okq(await L.routeReview(seat, lead, { material: true, why: "again" }));
    assert.deepEqual(again.deferred?.by, ["a1"]);
  }
  assert.equal(await reviewsNow(), 1);
  // A second, independent review, with why: recorded.
  const second = okq(await L.routeReview(c.a3, lead, { material: true, why: "the wipe may be partial", second_review_why: "I read the wipe's extent from the partition table, which a1 did not" }));
  assert.equal(second.deferred, undefined);
  assert.equal(await reviewsNow(), 2);
  assert.equal(await L.offerReviews(c.S), 0, "reviewed: nothing more is offered");
  // The metrics count the review's offer apart from the leads', taken up.
  const { measureRun } = await import("../scripts/metrics.ts");
  const m = await measureRun(c.S);
  assert.deepEqual([m.offers.reviews.made, m.offers.reviews.accepted, m.offers.reviews.by_reason], [1, 1, { route_review: 1 }]);
});

test("a route review is bound to the answers it saw: one made before the question's answer changed does not settle it after; the new review is offered", async () => {
  const c = await run();
  const { lead } = await deferredRoute(c);
  const f = ok(await rec(c.a1, { kind: "finding", ...F, value: "Bob logged on", source: "the log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const q1 = ok(await rec(c.a2, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${f.seq}`, result: "established", ...A, confidence: "high" })).entry;
  okq(await L.routeReview(c.a3, lead, { material: true, why: "the answer rests on one line" }));
  assert.equal(await L.offerReviews(c.S), 0, "reviewed for the answers as they stand");
  // The answer is recorded again on another support: the review saw other answers.
  const g = ok(await rec(c.a1, { kind: "finding", ...F, value: "Bob logged on at the console", source: "the log", evidence: "lines 1 and 2", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  ok(await rec(c.a2, { kind: "answer", section: "question:1", value: "Bob, at the console", reasoning: `E-${f.seq}; E-${g.seq}`, result: "established", ...A, confidence: "high", supersedes: q1.seq }));
  assert.equal(await L.offerReviews(c.S), 1, "offered again");
});

test("a material negative's review is offered to one seat, never an author; another seat's review is quiet; a compacting seat is offered nothing; a decline passes it on", async () => {
  const c = await run();
  for (const a of ["a0", "a1", "a2", "a3"]) await traceRow(c.S, a, "bash");
  const opened = okq(await L.openLead(c.a0, { title: "Search for the remote tool", why: "q2", answers: ["2"], take: true, routes: [{ source: "input:disk.E01", method: "search the disk" }] }));
  const absence = ok(await rec(c.a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  okq(await L.closeLead(c.a0, opened.lead.id, { disposition: "negative", ref: `E-${absence.seq}` }));
  const cov = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`]))).entry;
  const ans = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, contrary_none_why: "nothing points to one", result: "bounded_negative" })).entry;
  // a2 is compacting: offered nothing. a3 is the one.
  await traceRow(c.S, "a2", "compact_start");
  assert.equal(await L.offerReviews(c.S), 1);
  const key = `E-${ans.seq}`;
  let offers = (await L.leadsSnapshot(c.S)).state.reviewOffers.get(key) ?? [];
  assert.deepEqual(offers.map((o) => [o.to, o.reason]), [["a3", "negative_review"]], "not a0 (coverage) or a1 (answer), not a2 (compacting)");
  // a3 declines: passed on at once, to nobody eligible yet (a2 compacting); a2 through, it is offered.
  okq(await L.answerOffer(c.a3, key, { action: "decline", why: "I hold the registry work" }) as { ok: boolean });
  assert.equal(await L.offerReviews(c.S), 0);
  await traceRow(c.S, "a2", "compact_done");
  await traceRow(c.S, "a2", "bash");
  assert.equal(await L.offerReviews(c.S), 1);
  offers = (await L.leadsSnapshot(c.S)).state.reviewOffers.get(key) ?? [];
  assert.equal(offers.at(-1)!.to, "a2");
  // a3's review now: quiet, naming a2.
  const quiet = await P.attestEntry(c.a3, { seq: ans.seq, how: "ran it again", review: REVIEW });
  assert.ok(quiet.ok);
  assert.equal((quiet as { appended: boolean }).appended, false);
  assert.equal((quiet as { deferred?: { to?: string } }).deferred?.to, "a2");
  assert.equal((await P.readAttestations(c.S)).length, 0);
  // a2 reviews: recorded, and its offer is accepted.
  const done = await P.attestEntry(c.a2, { seq: ans.seq, how: "ran the decisive query again", review: REVIEW });
  assert.ok(done.ok && (done as { appended: boolean }).appended);
  assert.ok((await L.leadsSnapshot(c.S)).state.reviewOffers.get(key)!.at(-1)!.accepted);
  // Reviewed: another seat's review of it, or of its coverage record, is quiet.
  for (const seq of [ans.seq, cov.seq]) {
    const again = await P.attestEntry(c.a3, { seq, how: "again", review: REVIEW });
    assert.ok(again.ok);
    assert.deepEqual((again as { deferred?: { by?: string[] } }).deferred?.by, ["a2"]);
  }
  // A second, independent review, with why: recorded.
  const second = await P.attestEntry(c.a3, { seq: ans.seq, how: "a second route: the MFT", review: REVIEW, second_review_why: "I searched the MFT's deleted records, which a2 did not" });
  assert.ok(second.ok && (second as { appended: boolean }).appended);
  assert.equal((await P.readAttestations(c.S)).length, 2);
  assert.equal(await L.offerReviews(c.S), 0);
});

test("a confirmation waits while its closer compacts, bounded; the closer confirms once through; past the bound, or done or dead, it reopens", async () => {
  const setup = async () => {
    const c = await run();
    await traceRow(c.S, "a1", "bash");
    const l = okq(await L.openLead(c.a1, { title: "Which account ran it", why: "q1", answers: ["1"], take: true, routes: [{ source: "input:disk.E01", method: "prefetch" }] })).lead;
    const f = ok(await rec(c.a1, { kind: "finding", ...F, value: "Account bob ran it", source: "prefetch", evidence: "row 1", refs: ["job:j000001/hits.txt"] })).entry;
    okq(await L.closeLead(c.a1, l.id, { disposition: "resolved", ref: `E-${f.seq}` }));
    const fix = ok(await rec(c.a1, { kind: "finding", ...F, value: "Account bob ran it, from the console", source: "prefetch", evidence: "row 1 and the session", refs: ["job:j000001/hits.txt"], supersedes: f.seq, because: "the session says where" })).entry;
    return { c, l, fix };
  };
  await withEnv({ SWARM_OFFER_SEC: "1", SWARM_OFFER_MAX_SEC: "1" }, async () => {
    // The closer compacts right after the offer: held, even past the offer's own window.
    const { c, l, fix } = await setup();
    assert.deepEqual(await L.reopenOnLedger(c.S), []);
    assert.ok((await L.leadsSnapshot(c.S)).state.leads.get(l.id)!.confirm);
    await traceRow(c.S, "a1", "compact_start");
    await new Promise((r) => setTimeout(r, 1_200));
    assert.deepEqual(await L.reopenOnLedger(c.S), [], "compacting: the confirmation waits");
    let lv = (await L.leadsSnapshot(c.S)).state.leads.get(l.id)!;
    assert.ok(lv.closed && lv.confirm, "still closed, still waiting for its closer");
    // Through its compaction, the closer confirms it.
    await traceRow(c.S, "a1", "compact_done");
    await traceRow(c.S, "a1", "bash");
    okq(await L.confirmLead(c.a1, l.id, { expected_revision: lv.rev, ref: `E-${fix.seq}`, why: "who ran it is unchanged" }));
    lv = (await L.leadsSnapshot(c.S)).state.leads.get(l.id)!;
    assert.deepEqual([lv.closed?.ref, lv.confirm], [`E-${fix.seq}`, null]);
  });
  await withEnv({ SWARM_CONFIRM_COMPACTION_HOLD_SEC: "1" }, async () => {
    // Compacting past the bound: reopened.
    const { c, l } = await setup();
    assert.deepEqual(await L.reopenOnLedger(c.S), []);
    await traceRow(c.S, "a1", "compact_start", new Date(Date.now() - 2_000));
    assert.deepEqual(await L.reopenOnLedger(c.S), [l.id]);
    const text = (await L.leadsSnapshot(c.S)).state.events.filter((e) => e.ev === "reopen").at(-1)?.why ?? "";
    assert.match(text, /compacting its context for more than/);
  });
  // Dead after the offer: reopened at once.
  const { c, l } = await setup();
  assert.deepEqual(await L.reopenOnLedger(c.S), []);
  await mkdir(join(c.S, "done", "agents"), { recursive: true });
  await writeFile(join(c.S, "done", "agents", "a1.dead"), "x");
  assert.deepEqual(await L.reopenOnLedger(c.S), [l.id]);
  void operator;
});

test("a correction under several closures of one seat is one confirmation offer: one notice, confirmed with one lead_confirm naming the batch (the c10 pilot's cascade)", async () => {
  const c = await run();
  await traceRow(c.S, "a1", "bash");
  const f = ok(await rec(c.a1, { kind: "finding", ...F, value: "Account bob ran it", source: "prefetch", evidence: "row 1", refs: ["job:j000001/hits.txt"] })).entry;
  const g = ok(await rec(c.a1, { kind: "finding", ...F, value: "It ran at ten", source: "prefetch", evidence: "row 2", refs: ["job:j000001/hits.txt"] })).entry;
  const leads: string[] = [];
  for (const [title, e] of [["Which account ran it", f], ["Who was at the console", f], ["Whose profile holds it", f], ["When did it run", g]] as const) {
    const l = okq(await L.openLead(c.a1, { title, why: "q1", take: true })).lead;
    okq(await L.closeLead(c.a1, l.id, { disposition: "resolved", ref: `E-${e.seq}` }));
    leads.push(l.id);
  }
  // Both entries corrected, each changing what it concludes.
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "Account alice ran it", source: "prefetch", evidence: "row 1, the SID", refs: ["job:j000001/hits.txt"], supersedes: f.seq, because: "the SID is alice's" })).entry;
  const g2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "It ran at eleven", source: "prefetch", evidence: "row 2, UTC", refs: ["job:j000001/hits.txt"], supersedes: g.seq, because: "the clock was local" })).entry;
  assert.deepEqual(await L.reopenOnLedger(c.S), []);
  const snap = await L.leadsSnapshot(c.S);
  const batches = new Set(leads.map((id) => snap.state.leads.get(id)!.offers.find((o) => o.reason === "confirm")?.batch));
  assert.deepEqual([...batches].sort(), [`E-${f2.seq}`, `E-${g2.seq}`].sort(), "one batch per correction chain");
  // One notice per batch, naming every closure in it.
  const notices = (await L.leadsDigest(c.a1, { mark: true })).notices.filter((n) => n.kind === "confirm");
  assert.equal(notices.length, 2, JSON.stringify(notices));
  const big = notices.find((n) => n.text.includes(`E-${f2.seq}`))!;
  for (const id of leads.slice(0, 3)) assert.match(big.text, new RegExp(`\\b${id}\\b`));
  assert.match(big.text, new RegExp(`lead_confirm\\(batch: "E-${f2.seq}"`));
  // One act confirms the batch.
  const done = okq(await L.confirmBatch(c.a1, `E-${f2.seq}`, { why: "alice or bob, the closures hold: they asked which account, and the correction answers it" }));
  assert.deepEqual(done.confirmed, leads.slice(0, 3));
  const after = await L.leadsSnapshot(c.S);
  for (const id of leads.slice(0, 3)) assert.deepEqual([after.state.leads.get(id)!.closed?.ref, after.state.leads.get(id)!.confirm], [`E-${f2.seq}`, null]);
  assert.ok(after.state.leads.get(leads[3])!.confirm, "the other batch still waits");
});

test("a correction that changes no conclusion (only its refs or its wording) holds the closures on it automatically, recorded as a repoint; one that changes the value still asks its closer", async () => {
  const c = await run();
  await traceRow(c.S, "a1", "bash");
  const f = ok(await rec(c.a1, { kind: "finding", ...F, value: "Account bob ran it", source: "prefetch", evidence: "row 1", refs: ["job:j000001/hits.txt"] })).entry;
  const l = okq(await L.openLead(c.a1, { title: "Which account ran it", why: "q1", take: true })).lead;
  okq(await L.closeLead(c.a1, l.id, { disposition: "resolved", ref: `E-${f.seq}` }));
  // A citation refresh: another ref, other evidence words, the same value.
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "Account Bob ran it.", source: "prefetch", evidence: "row 1, and the job that parsed it", refs: ["job:j000001/hits.txt", "job:j000006/hits.txt"], supersedes: f.seq, because: "cite the parse too" })).entry;
  assert.deepEqual(await L.reopenOnLedger(c.S), []);
  let lv = (await L.leadsSnapshot(c.S)).state.leads.get(l.id)!;
  assert.deepEqual([lv.closed?.ref, lv.confirm, lv.offers.filter((o) => o.reason === "confirm").length], [`E-${f2.seq}`, null, 0], "held on the standing entry, nobody asked");
  assert.match(lv.confirmed?.at(-1)?.why ?? "", /^repoint \(conclusion unchanged\)/);
  assert.equal(lv.confirmed?.at(-1)?.by, "system");
  // A correction of the value: confirm or reopen, as ever.
  const f3 = ok(await rec(c.a0, { kind: "finding", ...F, value: "Account alice ran it", source: "prefetch", evidence: "row 1, the SID", refs: ["job:j000001/hits.txt"], supersedes: f2.seq, because: "the SID is alice's" })).entry;
  assert.deepEqual(await L.reopenOnLedger(c.S), []);
  lv = (await L.leadsSnapshot(c.S)).state.leads.get(l.id)!;
  assert.ok(lv.confirm, "offered to its closer");
  assert.equal(lv.confirm?.head, `E-${f3.seq}`);
});
