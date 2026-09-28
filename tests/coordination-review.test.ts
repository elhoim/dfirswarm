/**
 * Coordination under review (Plan 3, WP4; docs/adr/0015; the independent
 * review of 2026-09-28): a question offered to one seat holds against every
 * way of taking its work (open, claim, reopen with take); one offer at a
 * time per seat across both registers, in a batch of deliveries and under
 * the lock; a prerequisite opened with its consumer never closes a loop;
 * a lead is parked only on positive evidence that its holder works
 * elsewhere; and a closure offered to its closer reopens at once when the
 * closer can no longer take it.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as O from "../extensions/offers.ts";
import * as Q from "../extensions/questions.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const GOAL = ["## Goal", "", "Examine it.", "", "### Questions", "", "1. Who?", "2. What?", "3. When?", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3`', ""].join("\n");
const operator: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
const FRAME = { proposition: "it happened", negation: "it did not happen", routes: [{ source: "input:disk.E01", method: "search the disk" }] };

async function run(agents = ["a0", "a1", "a2", "a3"]) {
  const base = await mkdtemp(join(tmpdir(), "coordination-review-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "c2", agentIds: agents, capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, ctx, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2"), a3: ctx("a3") };
}

async function traceRow(S: string, agent: string, tool: string, at: Date = new Date()): Promise<void> {
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at.toISOString(), recv_ts: at.toISOString(), agent, tool, args: {}, result: { ok: true } })}\n`);
}

async function idleFor(S: string, agent: string, min: number): Promise<void> {
  const at = new Date(Date.now() - min * 60_000).toISOString();
  await mkdir(join(S, "inbox", agent), { recursive: true });
  await writeFile(join(S, "inbox", agent, "waiting.json"), JSON.stringify({ since: at, started_at: at }));
}

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

async function withPark<T>(sec: number, fn: () => Promise<T>): Promise<T> {
  const was = process.env.SWARM_LEAD_PARK_SEC;
  process.env.SWARM_LEAD_PARK_SEC = String(sec);
  try {
    return await fn();
  } finally {
    if (was === undefined) delete process.env.SWARM_LEAD_PARK_SEC;
    else process.env.SWARM_LEAD_PARK_SEC = was;
  }
}

/** The seats each register holds an offer for now, and how many each. */
async function reservations(S: string): Promise<Map<string, number>> {
  const now = Date.now();
  const out = new Map<string, number>();
  const snap = await L.leadsSnapshot(S);
  for (const l of snap.state.leads.values()) {
    const o = O.reservingOffer(l.offers, now, l.rev);
    if (o) out.set(o.to, (out.get(o.to) ?? 0) + 1);
  }
  for (const q of (await Q.questionsSnapshot(S)).state.questions.values()) {
    const o = Q.reservingQuestionOffer(q, now);
    if (o) out.set(o.to, (out.get(o.to) ?? 0) + 1);
  }
  return out;
}

/** A person's question, delivered (and offered, when a seat can take it). */
async function ask(S: string, text: string, o: Record<string, unknown> = {}): Promise<string> {
  const q = ok(await Q.act(S, operator, "open", { text, why: "the client asks", ...o })).q!;
  await Q.deliverPending(S);
  return q;
}

test("a question offered to one seat holds against a claim: a peer's lead under it opens unheld and its claim is refused while the offer stands; the offered seat claims it", async () => {
  const { S, a1, a2 } = await run();
  await idleFor(S, "a1", 5);
  const q = await ask(S, "Was the archive mailed?", { suggested_to: "a1" });
  const early = ok(await L.openLead(a2, { title: "Search the mail", why: q, answers: [q], take: true, ...FRAME }));
  assert.equal(early.lead.holder, null);
  refused(await L.claimLead(a2, early.lead.id), new RegExp(`serves ${q}, which is offered to a1`));
  ok(await L.claimLead(a1, early.lead.id));
});

test("a question offered to one seat holds against a reopen with take: the lead is reopened unheld, never taken past the offer", async () => {
  const { S, a1, a2, a3 } = await run();
  await idleFor(S, "a1", 5);
  const q = await ask(S, "Was the archive deleted?", { suggested_to: "a1" });
  const l = ok(await L.openLead(a3, { title: "Look for the deletion", why: q, answers: [q], take: true, ...FRAME })).lead;
  assert.equal(l.holder, null, "offered to a1: opened unheld");
  const lim = ok((await P.recordEntry(a3, { kind: "limitation", value: "The recycle bin is not in the image", source: "the image", evidence: "no $Recycle.Bin", reason: "partial" } as P.LedgerInput)) as never) as unknown as { entry: P.LedgerEntry };
  ok(await L.closeLead(a3, l.id, { disposition: "deferred", ref: `E-${lim.entry.seq}` }));
  const rev = (await L.leadsSnapshot(S)).state.leads.get(l.id)!.rev;
  refused(await L.agentReopenLead(a2, l.id, { expected_revision: rev, why: "the MFT may show it", take: true }), new RegExp(`serves ${q}, which is offered to a1`));
  const reopened = ok(await L.agentReopenLead(a2, l.id, { expected_revision: rev, why: "the MFT may show it" }));
  assert.equal(reopened.lead.holder, null);
});

test("one offer at a time per seat, across both registers: a seat offered a question is not offered a lead, nor a second question in the same delivery, nor a question suggested to it while it holds a lead offer", async () => {
  const { S, a0 } = await run();
  await idleFor(S, "a1", 9);
  await idleFor(S, "a2", 3);
  // question -> lead
  const q1 = await ask(S, "Who sent the mail?", { suggested_to: "a1" });
  assert.equal((await Q.questionsSnapshot(S)).state.questions.get(q1)!.offers.at(-1)!.to, "a1");
  const lead = ok(await L.openLead(a0, { title: "Read the prefetch folder", why: "q3" }));
  assert.equal(lead.offered_to, "a2", "a1 has a question offer standing");
  // question -> question, in one delivery: a1 and a2 both hold an offer now, so a3 (once idle) is the only seat.
  await idleFor(S, "a3", 1.5);
  ok(await Q.act(S, operator, "open", { text: "When was it sent?", why: "the client asks" }));
  ok(await Q.act(S, operator, "open", { text: "Where was it sent from?", why: "the client asks" }));
  await Q.deliverPending(S);
  const res = await reservations(S);
  for (const [seat, n] of res) assert.equal(n, 1, `${seat} holds ${n} offers: ${JSON.stringify([...res])}`);
  // suggested seat with an offer standing: offered to an idle seat instead, or to nobody yet.
  const q4 = await ask(S, "Was it forwarded?", { suggested_to: "a2" });
  const o4 = (await Q.questionsSnapshot(S)).state.questions.get(q4)!.offers.at(-1);
  assert.notEqual(o4?.to, "a2", "a2 holds a lead offer: it is offered nothing more");
  const after = await reservations(S);
  for (const [seat, n] of after) assert.equal(n, 1, `${seat} holds ${n} offers: ${JSON.stringify([...after])}`);
});

test("one offer at a time per seat under concurrent deliveries and opens: two deliveries and an open racing reserve no seat twice", async () => {
  const { S, a0 } = await run(["a0", "a1", "a2", "a3", "a4"]);
  await idleFor(S, "a1", 9);
  await idleFor(S, "a2", 7);
  await idleFor(S, "a3", 5);
  for (const t of ["Who?", "What?", "When?"]) ok(await Q.act(S, operator, "open", { text: `${t} (asked)`, why: "the client asks" }));
  await Promise.all([Q.deliverPending(S), Q.deliverPending(S), L.openLead(a0, { title: "Read the shimcache", why: "q3" }), L.openLead(a0, { title: "Read the amcache", why: "q3" })]);
  const res = await reservations(S);
  for (const [seat, n] of res) assert.equal(n, 1, `${seat} holds ${n} offers: ${JSON.stringify([...res])}`);
});

test("a prerequisite opened with its consumer never closes a loop of needs: direct and indirect loops are refused, and nothing is appended", async () => {
  const { S, a0 } = await run();
  await traceRow(S, "a0", "bash");
  const consumer = ok(await L.openLead(a0, { title: "Decrypt the message", why: "q2", take: true })).lead;
  const events = async () => (await L.leadsSnapshot(S)).state.events.length;
  const n0 = await events();
  refused(await L.openLead(a0, { title: "Find the key", why: "for L-1", consumer: consumer.id, needs: [consumer.id] }), /loop/);
  assert.equal(await events(), n0, "neither the open nor the link was appended");
  // Indirect: L-2 needs L-1; a prerequisite of L-1 that needs L-2 closes L-1 -> new -> L-2 -> L-1.
  const mid = ok(await L.openLead(a0, { title: "Read the vault", why: "q2", needs: [consumer.id] })).lead;
  const n1 = await events();
  refused(await L.openLead(a0, { title: "Find the key's hint", why: "for L-1", consumer: consumer.id, needs: [mid.id] }), /loop/);
  assert.equal(await events(), n1);
  const snap = await L.leadsSnapshot(S);
  assert.deepEqual(snap.state.leads.get(consumer.id)!.needs, [], "the consumer gained no need");
  assert.equal(snap.state.leads.size, 2);
  // A prerequisite with no loop is still one act.
  const pre = ok(await L.openLead(a0, { title: "Find the key", why: "for L-1", consumer: consumer.id }));
  assert.deepEqual((await L.leadsSnapshot(S)).state.leads.get(consumer.id)!.needs, [`${pre.lead.id}:resolved`]);
});

test("a lead is parked only on positive evidence that its holder works elsewhere: a seat analysing its only lead keeps it; acting on another lead parks it", async () => {
  await withPark(1, async () => {
    const { S, a0, a1 } = await run();
    await traceRow(S, "a0", "bash");
    const l = ok(await L.openLead(a0, { title: "Read the browser history", why: "q2", take: true })).lead;
    await new Promise((r) => setTimeout(r, 1_200));
    // a0 reads and analyses the lead's existing output: foreground work, no register event, no job.
    await traceRow(S, "a0", "read");
    await traceRow(S, "a0", "bash");
    assert.deepEqual(await L.parkedLeads(S, await L.leadsSnapshot(S)), [], "its only lead, worked in the foreground: not parked");
    await idleFor(S, "a1", 5);
    assert.equal(await L.leadsWaitCheck(a1)(), null, "nothing is offered away from it");
    refused(await L.claimLead(a1, l.id), /is held by a0/);
    // a0 turns to another lead: now L-1 lies idle in the hands of a seat working elsewhere.
    ok(await L.openLead(a0, { title: "Read the prefetch", why: "q3", take: true }));
    await traceRow(S, "a0", "bash");
    assert.deepEqual((await L.parkedLeads(S, await L.leadsSnapshot(S))).map((p) => p.lead), [l.id]);
  });
});

test("a closure offered to its closer to confirm reopens at once when the closer can no longer take it: compacting or dead after the offer", async () => {
  for (const how of ["compacting", "dead"] as const) {
    const { S, a0, a1 } = await run();
    await traceRow(S, "a1", "bash");
    const l = ok(await L.openLead(a1, { title: "Which account ran it", why: "q1", take: true })).lead;
    const f = ok((await P.recordEntry(a1, { kind: "finding", ...F, value: "Account bob ran it", source: "prefetch", evidence: "row 1", refs: ["unresolved:fixture"] } as P.LedgerInput)) as never) as unknown as { entry: P.LedgerEntry };
    ok(await L.closeLead(a1, l.id, { disposition: "resolved", ref: `E-${f.entry.seq}` }));
    ok((await P.recordEntry(a0, { kind: "finding", ...F, value: "Account bob ran it, from the console", source: "prefetch", evidence: "row 1 and the session", refs: ["unresolved:fixture"], supersedes: f.entry.seq, because: "the session says where" } as P.LedgerInput)) as never);
    assert.deepEqual(await L.reopenOnLedger(S), []);
    assert.ok((await L.leadsSnapshot(S)).state.leads.get(l.id)!.confirm, "offered to a1 to confirm");
    // After the offer, the closer can no longer take it.
    if (how === "compacting") await traceRow(S, "a1", "compact_start");
    else {
      await mkdir(join(S, "done", "agents"), { recursive: true });
      await writeFile(join(S, "done", "agents", "a1.dead"), "x");
    }
    assert.deepEqual(await L.reopenOnLedger(S), [l.id], `${how}: reopened at once, not after the offer's window`);
    const lv = (await L.leadsSnapshot(S)).state.leads.get(l.id)!;
    assert.equal(lv.closed, null);
    assert.ok(lv.offers.find((o) => o.reason === "confirm")?.lapsed_at, "the confirmation offer is ended on the record");
    const text = await readFile(join(S, L.LEADS_LOG), "utf8");
    assert.match(text, new RegExp(`"ev":"reopen".*a1 ${how === "compacting" ? "is compacting its context" : "is marked dead"}`));
  }
});
