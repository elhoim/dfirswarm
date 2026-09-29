/**
 * The lead register (extensions/leads.ts) at the protocol level: the checks
 * the three reviewers agreed to run before any paired CTF run (joint-final
 * C.1). Concurrent claims, create-and-take, a failed producer, a job that
 * succeeds and still misses what the lead needed, a stale owner reclaimed, a
 * compaction that keeps its lease, a hub restart between a transition and its
 * notice, a lead appearing while the finish line runs, supersession reopening
 * a lead, pagination, an uninterpreted job at done, and partial coverage.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

/** A finding's version 4 fields. */
const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;

async function run(agents = ["a0", "a1", "a2", "a3"], goal?: string) {
  const base = await mkdtemp(join(tmpdir(), "leads-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "t1", agentIds: agents, capUsd: 5, wallClockMinutes: 30, ...(goal ? { goal } : {}) });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, base, ctx, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2"), a3: ctx("a3") };
}

/** A trace row for `agent` at `at`, as the collector writes them. */
async function traceRow(S: string, agent: string, tool: string, at: Date, args: Record<string, unknown> = {}): Promise<void> {
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at.toISOString(), recv_ts: at.toISOString(), agent, tool, args, result: { ok: true } })}\n`);
}

/** A committed job of `agent`'s, its stdout, and what of it the agent was handed. */
async function job(S: string, id: string, agent: string, o: { stdout?: string; status?: string; state?: string; returned?: Array<[number, number]>; kind?: string } = {}): Promise<void> {
  const dir = join(S, "store", "jobs", id);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "job.json"), JSON.stringify({ id, state: o.state ?? "committed", status: o.status ?? "ok", requester: { agent }, spec: { kind: o.kind ?? "command", command: "echo" } }));
  await writeFile(join(dir, "stdout.log"), o.stdout ?? "out\n");
  for (const [off, n] of o.returned ?? []) {
    await appendFile(join(S, "store", "journal.jsonl"), `${JSON.stringify({ v: 1, type: "job_returned", job: id, to: agent, stdout_offset: off, stdout_bytes: n })}\n`);
  }
}

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

test("a lead is opened, claimed and closed with a disposition that cites what it rests on; the chain holds and leads.md is rendered", async () => {
  const { S, a0, a1 } = await run();
  const l = ok(await L.openLead(a0, { title: "Open the encrypted container", why: "Five questions rest on its files", answers: ["3", "Q4"] })).lead;
  assert.deepEqual([l.id, l.status, l.holder, l.generation, l.material, l.answers], ["L-1", "open", null, 0, true, ["3", "4"]]);
  const c = ok(await L.claimLead(a1, "L-1")).lead;
  assert.deepEqual([c.status, c.holder, c.generation], ["active", "a1", 1]);
  refused(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-1" }), /E-1 is not in the ledger/);
  refused(await L.closeLead(a1, "L-1", { disposition: "done", ref: "E-1" }), /disposition is one of/);
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "The container opens with the recovery key", source: "a job", evidence: "the unlock" });
  assert.ok(f.ok);
  refused(await L.closeLead(a0, "L-1", { disposition: "resolved", ref: "E-1" }), /held by a1.*only its holder can close it/);
  const closed = ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "e-1" })).lead;
  assert.deepEqual([closed.status, closed.disposition, closed.ref], ["closed", "resolved", "E-1"]);
  const text = await readFile(join(S, L.LEADS_LOG), "utf8");
  const chain = L.verifyLeadChain(text);
  assert.deepEqual([chain.ok, chain.total], [true, 3]);
  // A rewritten line breaks the chain, and the register takes nothing more.
  await writeFile(join(S, L.LEADS_LOG), text.replace("Open the encrypted container", "Open something else"));
  assert.equal(L.verifyLeadChain(await readFile(join(S, L.LEADS_LOG), "utf8")).reason, "the line was rewritten");
  refused(await L.openLead(a0, { title: "t", why: "w" }), /chain is broken/);
  await writeFile(join(S, L.LEADS_LOG), text);
  const md = await readFile(join(S, L.LEADS_MD), "utf8");
  assert.match(md, /### L-1: Open the encrypted container/);
  assert.match(md, /Closed resolved by a1 at .*: E-1/);
});

test("two agents claiming the same lead at once: exactly one holds it, at generation 1, and the other is told who", async () => {
  const { a0, a1, a2 } = await run();
  ok(await L.openLead(a0, { title: "Recover the deleted archive", why: "It may hold the key" }));
  const [r1, r2] = await Promise.all([L.claimLead(a1, "L-1"), L.claimLead(a2, "L-1")]);
  const won = [r1, r2].filter((r) => r.ok);
  const lost = [r1, r2].filter((r) => !r.ok);
  assert.equal(won.length, 1, "one claim wins");
  assert.equal(lost.length, 1);
  const winner = r1.ok ? "a1" : "a2";
  assert.match((lost[0] as { reason: string }).reason, new RegExp(`held by ${winner} \\(generation 1`));
  const snap = await L.leadsSnapshot(a0.sandboxRoot);
  assert.deepEqual([snap.state.leads.get("L-1")?.holder, snap.state.leads.get("L-1")?.generation], [winner, 1]);
  assert.equal(snap.state.events.filter((e) => e.ev === "claim").length, 1, "one claim event, not two");
});

test("create-and-take is one step: the discoverer holds its own follow-up before anyone can take it", async () => {
  const { a0, a1 } = await run();
  await traceRow(a0.sandboxRoot, "a0", "bash", new Date());
  const l = ok(await L.openLead(a0, { title: "Decode the session state", why: "The page's form state ties the message to the meeting", take: true })).lead;
  assert.deepEqual([l.status, l.holder, l.generation], ["active", "a0", 1]);
  refused(await L.claimLead(a1, "L-1"), /held by a0 \(generation 1/);
  const events = (await L.leadsSnapshot(a0.sandboxRoot)).state.events;
  assert.deepEqual(events.map((e) => e.ev), ["open"], "one event: there is no moment when the lead is open to others");
});

test("needs: a blocked lead becomes ready when its producer closes with the outcome it needs, and its holder is told lead_ready; loops are refused", async () => {
  const { S, a0, a1, a2 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  await traceRow(S, "a2", "bash", new Date());
  ok(await L.openLead(a1, { title: "Find the recovery key", why: "The container is locked", take: true }));
  const inside = ok(await L.openLead(a2, { title: "Read the files inside the container", why: "Questions 5 to 9", needs: ["L-1"], answers: ["5"], take: true })).lead;
  assert.equal(inside.status, "blocked");
  assert.deepEqual(inside.needs, [{ need: "L-1:resolved", met: false, why: "L-1 is held by a1", outcome: "pending" }]);
  refused(await L.linkLead(a1, "L-1", { add: ["L-2"] }), /closes a loop/);
  refused(await L.openLead(a0, { title: "x", why: "y", needs: ["job:j000001"] }), /a job's exit is never one/);
  // What a2 has been told so far.
  await L.leadsDigest(a2, { mark: true });
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "The recovery key is in a phone note", source: "notes db", evidence: "row 12" });
  assert.ok(f.ok);
  ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-1" }));
  const digest = await L.leadsDigest(a2, { mark: false });
  assert.ok(digest.notices.some((n) => n.kind === "lead_ready" && n.lead === "L-2" && n.wakes), JSON.stringify(digest.notices));
  assert.match(digest.text, /NOTICE lead_ready: every need of L-2/);
  // The wait of a2 wakes on it.
  const check = L.leadsWaitCheck(a2);
  assert.match((await check()) ?? "", /lead_ready: every need of L-2/);
  // Once told, it is not told again.
  await L.leadsDigest(a2, { mark: true });
  assert.equal(await L.leadsWaitCheck(a2)(), null);
});

test("a failed producer: the lead it feeds stays blocked, its holder is told the need will not come, and a job's exit never satisfies a need", async () => {
  const { S, a1, a2 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  await traceRow(S, "a2", "bash", new Date());
  ok(await L.openLead(a1, { title: "Unlock the volume", why: "Its files answer three questions", take: true }));
  ok(await L.openLead(a2, { title: "Examine the unlocked volume", why: "Three questions", needs: ["L-1"], take: true }));
  await L.leadsDigest(a2, { mark: true });
  // The producer's job ran and exited 0; the need is not met by that.
  await job(S, "j000001", "a1");
  ok(await L.attachJob(S, "a1", "j000001"));
  let snap = await L.leadsSnapshot(S);
  assert.equal(L.leadStatus(snap.state.leads.get("L-2")!, snap.state, snap.ledger), "blocked", "a committed job is not the outcome L-2 needs");
  // The unlock failed: recorded as a limitation, interpreted, and the lead closed infeasible.
  const lim = await P.recordEntry(a1, { kind: "limitation", value: "The volume could not be unlocked: no key fits", source: "the volume", evidence: "every candidate tried", reason: "failed" });
  assert.ok(lim.ok);
  ok(await L.recordInterpretations(S, "a1", 1, ["j000001"]));
  ok(await L.closeLead(a1, "L-1", { disposition: "infeasible", ref: "E-1" }));
  snap = await L.leadsSnapshot(S);
  assert.equal(L.leadStatus(snap.state.leads.get("L-2")!, snap.state, snap.ledger), "blocked");
  const told = await L.leadsDigest(a2, { mark: false });
  const dead = told.notices.find((n) => n.kind === "need_dead");
  assert.ok(dead, JSON.stringify(told.notices));
  assert.match(dead!.text, /L-2's need L-1:resolved will not be met as it stands: L-1 was closed infeasible \(E-1\), not resolved: revise the need/);
  // Needs can be revised: an alternative route keeps the lead open.
  const f = await P.recordEntry(a2, { kind: "finding", ...F, value: "A decrypted copy of the volume's files sits in the backup", source: "backup", evidence: "listing" });
  assert.ok(f.ok);
  // An entry that stands is not a need (it is where the lead comes from); a need dropped says why and is withdrawn, never met.
  refused(await L.linkLead(a2, "L-2", { add: ["E-2"] }), /E-2 stands: it is not a need/);
  refused(await L.linkLead(a2, "L-2", { remove: ["L-1"] }), /why is required with remove/);
  const revised = ok(await L.linkLead(a2, "L-2", { remove: ["L-1"], why: "E-2 holds a decrypted copy: the lead goes on without the unlock" })).lead;
  assert.equal(revised.status, "active");
  assert.deepEqual(revised.dropped?.map((d) => [d.need, d.by]), [["L-1:resolved", "a2"]]);
});

test("a job that succeeds but misses what the lead needed: interpreted as an absence, the lead closes negative, and a lead needing it resolved is not unblocked", async () => {
  const { S, a1, a2 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  await traceRow(S, "a2", "bash", new Date());
  ok(await L.openLead(a1, { title: "Find the key in the pagefile", why: "The vault is locked", take: true }));
  ok(await L.openLead(a2, { title: "Open the vault", why: "q7", needs: ["L-1:resolved"], take: true }));
  await job(S, "j000001", "a1", { stdout: "0 hits\n" });
  ok(await L.attachJob(S, "a1", "j000001"));
  // Before interpretation, the gate holds the job and the lead.
  let gate = await L.leadDefects(S);
  assert.deepEqual(gate.defects.map((d) => [d.code, d.lead, d.job ?? null]), [["open_lead", "L-1", null], ["open_lead", "L-2", null], ["uninterpreted_job", "L-1", "j000001"]]);
  // A bare citation does not interpret it.
  await P.recordEntry(a1, { kind: "event", ts: "2024-01-01T00:00:00Z", value: "pagefile scanned", source: "pagefile", evidence: "scan", refs: [] });
  gate = await L.leadDefects(S);
  assert.ok(gate.defects.some((d) => d.code === "uninterpreted_job"), "an entry that does not name the job in interprets leaves it waiting");
  const none = await P.recordEntry(a1, { kind: "absence", value: "No recovery key in the pagefile", source: "pagefile.sys", evidence: "the job's whole scan, every page" });
  assert.ok(none.ok);
  ok(await L.recordInterpretations(S, "a1", 2, [{ job: "j000001" }]));
  ok(await L.closeLead(a1, "L-1", { disposition: "negative", ref: "E-2" }));
  const snap = await L.leadsSnapshot(S);
  assert.equal(L.leadStatus(snap.state.leads.get("L-2")!, snap.state, snap.ledger), "blocked", "a negative search is not the key");
  gate = await L.leadDefects(S);
  assert.deepEqual(gate.defects.map((d) => [d.code, d.lead]), [["open_lead", "L-2"]], "L-1 is disposed of and its job interpreted");
  refused(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-2" }), /already closed/);
});

test("a stale owner is marked before its lead is reclaimed; the reclaim takes a new generation and the old holder can no longer close it", async () => {
  const { S, a1, a2 } = await run();
  const was = { stale: process.env.SWARM_LEAD_STALE_SEC, grace: process.env.SWARM_LEAD_RECLAIM_GRACE_SEC };
  process.env.SWARM_LEAD_STALE_SEC = "600";
  process.env.SWARM_LEAD_RECLAIM_GRACE_SEC = "0";
  try {
    const long = new Date(Date.now() - 30 * 60_000);
    await traceRow(S, "a1", "bash", long);
    ok(await L.openLead(a1, { title: "Map the guest file's extents", why: "The only route to the recovered file", take: true }));
    // The open is the holder's own act: back-date it, as a holder silent for half an hour.
    const text = await readFile(join(S, L.LEADS_LOG), "utf8");
    const e = JSON.parse(text) as L.LeadEvent;
    const old = { ...e, at: long.toISOString() };
    const { hash: _h, ...rest } = old;
    await writeFile(join(S, L.LEADS_LOG), `${JSON.stringify({ ...rest, hash: L.leadEventHash(rest as L.LeadEvent, "genesis") })}\n`);
    await L.leadsDigest(a1, { mark: true });
    await traceRow(S, "a2", "bash", new Date());
    const first = await L.claimLead(a2, "L-1");
    refused(first, /a1 shows as stale .* marked stale now and a1 is told/);
    const snap = await L.leadsSnapshot(S);
    assert.equal(snap.state.leads.get("L-1")?.stale?.holder, "a1", "the stale mark is on the record before any reclaim");
    // The holder is told, and its wait wakes on it.
    assert.match((await L.leadsWaitCheck(a1)()) ?? "", /L-1 is marked stale in your hands/);
    const second = ok(await L.claimLead(a2, "L-1"));
    assert.equal(second.reclaimed_from, "a1");
    assert.deepEqual([second.lead.holder, second.lead.generation], ["a2", 2]);
    // The old holder comes back: it cannot close or release what it no longer holds.
    refused(await L.closeLead(a1, "L-1", { disposition: "deferred", ref: "E-1" }), /held by a2 \(generation 2\)/);
    refused(await L.releaseLead(a1, "L-1"), /held by a2/);
    refused(await L.releaseLead(a2, "L-1", { generation: 1 }), /generation 2, not 1/);
    const told = await L.leadsDigest(a1, { mark: false });
    assert.ok(told.notices.some((n) => n.kind === "reclaimed" && /taken over by a2/.test(n.text)), JSON.stringify(told.notices));
  } finally {
    for (const [k, v] of [["SWARM_LEAD_STALE_SEC", was.stale], ["SWARM_LEAD_RECLAIM_GRACE_SEC", was.grace]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test("a holder in a bounded compaction, or with a job running, keeps its lead; a turn error by itself frees nothing", async () => {
  const { S, a1, a2 } = await run();
  const long = new Date(Date.now() - 30 * 60_000);
  await traceRow(S, "a1", "bash", long);
  ok(await L.openLead(a1, { title: "Carve the unallocated space", why: "q4", take: true }));
  const facts = await L.readJobs(S);
  // Compacting for five minutes: alive.
  await traceRow(S, "a1", "compact_start", new Date(Date.now() - 5 * 60_000));
  let live = await L.holderLiveness(S, "a1", facts, undefined, Date.now(), 0);
  assert.equal(live.stale, false, live.why);
  assert.match(live.why, /compacting/);
  // A compaction that ended, and a provider error since: stale only by silence, not by the error.
  await traceRow(S, "a1", "compact_done", new Date(Date.now() - 4 * 60_000));
  await traceRow(S, "a1", "agent_error", new Date(Date.now() - 3 * 60_000));
  live = await L.holderLiveness(S, "a1", facts, undefined, Date.now(), Date.now() - 2 * 60_000);
  assert.equal(live.stale, false, "an agent whose turn failed two minutes after its last act is not stale");
  // A job of its own still running keeps the lease however long it is silent.
  await job(S, "j000002", "a1", { state: "running" });
  live = await L.holderLiveness(S, "a1", await L.readJobs(S), undefined, Date.now(), 0);
  assert.equal(live.stale, false);
  assert.match(live.why, /job still running/);
  refused(await L.claimLead(a2, "L-1"), /held by a1/);
});

test("a hub restarting between a transition and its notice loses neither: notices and wakes are derived from the record", async () => {
  const { S, a1, a2, a3 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  await traceRow(S, "a2", "bash", new Date());
  ok(await L.openLead(a1, { title: "Find the passphrase", why: "part 3", take: true }));
  ok(await L.openLead(a2, { title: "Decrypt the message", why: "part 3", needs: ["L-1"], take: true }));
  await L.leadsDigest(a2, { mark: true });
  // The transition lands; the process that made it dies before telling anyone.
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "The passphrase is on the external resource", source: "s", evidence: "e" });
  assert.ok(f.ok);
  ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-1" }));
  // A fresh reader (a restarted hub) still finds the notice owed.
  const fresh = await import(`../extensions/leads.ts?restart=${Date.now()}`);
  assert.match((await fresh.leadsWaitCheck(a2)()) ?? "", /lead_ready: every need of L-2/);
  // An open lead whose wake was never written (the hub died after the open):
  // the seat idle longest takes the wake itself, once.
  const past = new Date(Date.now() - 5 * 60_000).toISOString();
  await writeFile(join(S, "inbox", "a3", "waiting.json"), JSON.stringify({ since: past, started_at: past }));
  const text = await readFile(join(S, L.LEADS_LOG), "utf8");
  const events = text.trim().split("\n").map((l) => JSON.parse(l) as L.LeadEvent);
  const last = events.at(-1)!;
  const draft = { v: 1 as const, seq: last.seq + 1, at: new Date().toISOString(), by: "a1", ev: "open" as const, lead: "L-3", title: "Read the cached page", why: "part 1", origin: "lead_open by a1", needs: [], answers: [], material: true, generation: 0, prev: last.hash };
  await appendFile(join(S, L.LEADS_LOG), `${JSON.stringify({ ...draft, hash: L.leadEventHash(draft as unknown as L.LeadEvent, last.hash) })}\n`);
  const woke = await L.leadsWaitCheck(a3)();
  assert.match(woke ?? "", /L-3 \("Read the cached page"\) is open, ready and nobody holds it, and it is offered to you/);
  const offers = (await L.leadsSnapshot(S)).state.events.filter((e) => e.ev === "offer");
  assert.deepEqual(offers.map((w) => [w.lead, w.to, w.reason]), [["L-3", "a3", "wake"]]);
  assert.equal((await L.leadsSnapshot(S)).state.events.filter((e) => e.ev === "offer_seen").length, 1, "delivered as it was made: its minute runs from now");
  // The wait's delivery tells a3 (the header marks what it was shown): no second offer for the same lead.
  await L.leadsDigest(a3, { mark: true });
  assert.equal(await L.leadsWaitCheck(a3)(), null, "one offer at a time: a second check does not offer it again");
  assert.equal((await L.leadsSnapshot(S)).state.events.filter((e) => e.ev === "offer").length, 1);
});

test("lead_open wakes the seat idle longest, one wake per lead; a seat holding a lead or a job is not idle", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  const at = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
  await writeFile(join(S, "inbox", "a1", "waiting.json"), JSON.stringify({ since: at(3), started_at: at(1) }));
  await writeFile(join(S, "inbox", "a2", "waiting.json"), JSON.stringify({ since: at(9), started_at: at(1) }));
  await writeFile(join(S, "inbox", "a3", "waiting.json"), JSON.stringify({ since: at(20), started_at: at(1) }));
  // a3 has waited longest but has a job running: not idle.
  await job(S, "j000009", "a3", { state: "running" });
  const opened = ok(await L.openLead(a0, { title: "Walk the second browser profile", why: "Nobody has looked at it" }));
  assert.equal(opened.woke, "a2");
  assert.match((await L.leadsWaitCheck(a2)()) ?? "", /L-1 \("Walk the second browser profile"\) is open, ready and nobody holds it, and it is offered to you \(idle\)/);
  assert.equal(await L.leadsWaitCheck(a1)(), null);
  // A blocked lead wakes nobody until it is ready.
  const blocked = ok(await L.openLead(a0, { title: "Read what the profile's cache holds", why: "after L-1", needs: ["L-1"] }));
  assert.equal(blocked.woke, undefined);
});

test("a lead that appears while the finish line runs: the run is taken again, and the gate refuses done on the open lead", async () => {
  const { S, a0 } = await run();
  let runs = 0;
  const runner = async () => {
    runs += 1;
    if (runs === 1) await L.openLead(a0, { title: "A late avenue", why: "found while checking" });
    return { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] };
  };
  const bound = await P.runFinishLineBound(S, runner);
  assert.deepEqual([bound.settled, bound.runs], [true, 2], "the lead moved the state under the first run");
  const gate = await L.leadDefects(S);
  assert.deepEqual(gate.defects.map((d) => [d.code, d.lead]), [["open_lead", "L-1"]]);
  const verdict = P.finishLineVerdict({ ...bound.run!, gate: { defects: gate.defects, limited: [] } }, false);
  assert.equal(verdict.proceed, false);
  if (!verdict.proceed) {
    assert.match(verdict.reason, /L-1 "A late avenue" is open with no disposition/);
    assert.match(verdict.reason, /lead_close L-1/);
  }
});

test("supersession offers the closer to confirm or reopen (never a re-point), and reopens when unconfirmed; a dispute reopens at once; the holder is told", async () => {
  const { S, a1, a2 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  ok(await L.openLead(a1, { title: "Which container holds the originals", why: "decoy or original", take: true }));
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "The decoy volume holds the originals", source: "s", evidence: "e" });
  assert.ok(f.ok);
  ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-1" }));
  await L.leadsDigest(a1, { mark: true });
  const fix = await P.recordEntry(a2, { kind: "finding", ...F, value: "The encrypted original holds them, not the decoy", source: "s", evidence: "e", supersedes: 1, because: "the provenance of the decoy was confused" });
  assert.ok(fix.ok);
  // Its closer, available, is offered to confirm the closure on what stands now: nothing re-points it, and it is not yet reopened.
  assert.deepEqual(await L.reopenOnLedger(S), []);
  let snap = await L.leadsSnapshot(S);
  let l = snap.state.leads.get("L-1")!;
  assert.equal(l.closed?.ref, "E-1", "the closure is not re-pointed");
  assert.deepEqual([l.confirm?.ref_was, l.confirm?.head], ["E-1", "E-2"]);
  assert.equal(L.needState("L-1", snap.state, snap.ledger).met, false, "a closure awaiting confirmation meets no need");
  const told = await L.leadsDigest(a1, { mark: false });
  // One notice per correction (the c10 pilot's batches): it names the closure and the act that confirms the batch.
  assert.ok(told.notices.some((n) => n.kind === "confirm" && n.lead === "L-1" && /L-1 \("Which container holds the originals"/.test(n.text) && /lead_confirm\(batch: "E-2", why\)/.test(n.text)), JSON.stringify(told.notices));
  // Unconfirmed within its window: reopened.
  assert.deepEqual(await L.reopenOnLedger(S, Date.now() + 10 * 60_000), ["L-1"]);
  snap = await L.leadsSnapshot(S);
  l = snap.state.leads.get("L-1")!;
  assert.equal(l.closed, null);
  assert.equal(l.reopened[0].cause, "superseded");
  assert.match(l.reopened[0].why, /E-1 was superseded by E-2, and its closer did not confirm it within its window/);
  assert.ok(snap.state.events.some((e) => e.ev === "offer_lapse" && e.lead === "L-1"), "the lapse is on the record");
  // Closed again on the correction, then disputed: reopened again.
  ok(await L.claimLead(a1, "L-1"));
  ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-2" }));
  const d = await P.disputeEntry({ sandboxRoot: S, agentId: "a0" }, { seq: 2, why: "the header check was never run" });
  assert.ok(d.ok, (d as { reason?: string }).reason);
  assert.deepEqual(await L.reopenOnLedger(S), ["L-1"]);
  assert.equal((await L.leadsSnapshot(S)).state.leads.get("L-1")!.reopened.at(-1)!.cause, "disputed");
});

test("pagination: the views hand whole leads a page at a time, name where the next starts, and together hold every lead", async () => {
  const { a0 } = await run();
  for (let i = 1; i <= 30; i++) ok(await L.openLead(a0, { title: `Lead number ${i} with a title long enough to fill a page`, why: "w".repeat(200) }));
  const seen: string[] = [];
  let from: string | undefined;
  let pages = 0;
  for (;;) {
    const page = (await L.leadsView(a0, { view: "open", pageChars: 2000, ...(from ? { from } : {}) })) as { leads: L.LeadView[]; remaining: number; next?: string; note?: string };
    pages += 1;
    assert.ok(page.leads.length >= 1);
    for (const l of page.leads) assert.equal(l.why.length, 200, "a lead is never cut");
    seen.push(...page.leads.map((l) => l.id));
    if (!page.next) {
      assert.equal(page.remaining, 0);
      break;
    }
    assert.match(page.note ?? "", /nothing was cut/);
    from = page.next;
  }
  assert.ok(pages > 1, "the view paged");
  assert.deepEqual([...seen].sort(), Array.from({ length: 30 }, (_, i) => `L-${i + 1}`).sort());
  assert.equal(new Set(seen).size, 30, "no lead twice");
  const digest = await L.leadsDigest(a0);
  for (let i = 1; i <= 30; i++) assert.ok(digest.text.includes(`L-${i} "`), `the header names L-${i}`);
});

test("an uninterpreted job at done: a material lead's job is a gate defect; an agent's own job is shown, never gated", async () => {
  const { S, a1 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  await job(S, "j000001", "a1");
  ok(await L.openLead(a1, { title: "Parse the event logs", why: "q2", take: true }));
  await job(S, "j000002", "a1");
  ok(await L.attachJob(S, "a1", "j000002"));
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "The logs show the logon", source: "Security.evtx", evidence: "4624" });
  assert.ok(f.ok);
  ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: "E-1" }));
  const gate = await L.leadDefects(S);
  assert.deepEqual(gate.defects.map((d) => [d.code, d.job]), [["uninterpreted_job", "j000002"]]);
  assert.match(gate.defects[0].fix, /interprets: \["j000002"\]/);
  const digest = await L.leadsDigest(a1);
  assert.match(digest.text, /Awaiting your interpretation: j000001; j000002 \(L-1\)\./);
  ok(await L.recordInterpretations(S, "a1", 1, ["j000002"]));
  assert.deepEqual((await L.leadDefects(S)).defects, []);
  refused(await L.recordInterpretations(S, "a1", 1, ["j000077"]), /not a job of this run/);
});

test("partial coverage: a job's output handed over in part waits until the rest is read or the interpretation says why not", async () => {
  const { S, a1 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  ok(await L.openLead(a1, { title: "Read the notes database", why: "a note may hold the key", take: true }));
  await job(S, "j000001", "a1", { stdout: "n".repeat(18206), returned: [[0, 8192]] });
  ok(await L.attachJob(S, "a1", "j000001"));
  let waiting = await L.awaitingInterpretation(S, (await L.leadsSnapshot(S)).state);
  assert.deepEqual(waiting.map((w) => [w.job, w.unread_bytes, w.total_bytes, w.next_offset]), [["j000001", 10014, 18206, 8192]]);
  assert.match((await L.leadsDigest(a1)).text, /j000001 \(L-1\): 10014 of 18206 stdout bytes unread, job_status offset 8192/);
  // Interpreted from the first page alone: still waiting, for the rest.
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "The notes list six titles", source: "notes", evidence: "first page" });
  assert.ok(f.ok);
  ok(await L.recordInterpretations(S, "a1", 1, ["j000001"]));
  waiting = await L.awaitingInterpretation(S, (await L.leadsSnapshot(S)).state);
  assert.match(waiting[0]?.why ?? "", /interpreted, but 10014 of 18206 stdout bytes unread/);
  assert.equal((await L.leadDefects(S)).defects.find((d) => d.code === "uninterpreted_job")?.job, "j000001");
  // Reading the rest clears it.
  await appendFile(join(S, "store", "journal.jsonl"), `${JSON.stringify({ v: 1, type: "job_returned", job: "j000001", to: "a1", stdout_offset: 8192, stdout_bytes: 10014 })}\n`);
  assert.deepEqual(await L.awaitingInterpretation(S, (await L.leadsSnapshot(S)).state), []);
  // Or saying how it was read, for another job.
  await job(S, "j000002", "a1", { stdout: "x".repeat(9000), returned: [[0, 4096]] });
  ok(await L.recordInterpretations(S, "a1", 1, [{ job: "j000002", rest: "read whole with grep over store/jobs/j000002/stdout.log" }]));
  assert.deepEqual(await L.awaitingInterpretation(S, (await L.leadsSnapshot(S)).state), []);
});

test("priority is how much waits on a lead, transitively, then its age; uncovered questions are those with no answer and no held lead", async () => {
  const goal = ["## Goal", "", "g", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,summary,narrative --existence 3`', ""].join("\n");
  const { S, a0, a1 } = await run(["a0", "a1", "a2", "a3"], goal);
  await traceRow(S, "a1", "bash", new Date());
  ok(await L.openLead(a0, { title: "An old side lead", why: "w" }));
  ok(await L.openLead(a0, { title: "The key", why: "w" }));
  ok(await L.openLead(a0, { title: "Open the vault", why: "w", needs: ["L-2"], answers: ["1"] }));
  ok(await L.openLead(a1, { title: "Read inside", why: "w", needs: ["L-3"], answers: ["2"], take: true }));
  const snap = await L.leadsSnapshot(S);
  const ranked = L.rankedLeads(snap);
  assert.deepEqual(ranked.map((x) => [x.id, x.priority]), [["L-2", 4], ["L-3", 3], ["L-4", 1], ["L-1", 0]], "L-2 unblocks two leads and two questions");
  assert.deepEqual(snap.goal, { questions: ["1", "2", "3"], existence: ["3"], source: "sandbox contract" });
  const cov = L.questionCoverage(snap);
  assert.deepEqual(cov.unanswered, ["1", "2", "3"]);
  assert.deepEqual(cov.uncovered, ["1", "3"], "question 2 has a held lead; 1 has only an unheld one");
  assert.deepEqual(cov.open_leads_for, { "1": ["L-3"] });
});

test("a needs_operator close asking the operator to accept dispositions stands, and is told done asks the finish line first; once a done was refused on a question the operator may accept, it is not", async () => {
  const { S, a1 } = await run();
  const F_ = await import("../extensions/finish.ts");
  ok(await L.openLead(a1, { title: "Have the limits ruled on", why: "two answers rest on what could not be examined", take: true }));
  const asked = ok(await L.closeLead(a1, "L-1", { disposition: "needs_operator", ref: "Operator: accept or reject the examination-limited dispositions of Q-1 and Q-2 before we finish" }));
  assert.ok(asked.request?.id, "the close stands, with its request");
  assert.match(asked.hint ?? "", /no done has been refused on anything only the operator can release: whether examination-limited dispositions suffice is what done asks the finish line/);
  assert.match(asked.hint ?? "", /swarm\.sh question <run> accept Q-n/);
  // An ask of what only the operator can do is not hinted.
  ok(await L.openLead(a1, { title: "Reach the paste site", why: "the key is there", take: true }));
  assert.equal(ok(await L.closeLead(a1, "L-2", { disposition: "needs_operator", ref: "allow the host paste.example.org so a job can fetch the key" })).hint, undefined);
  // A done refused on a question with no disposition names what the operator may accept: the ask may be the operator's now.
  await F_.recordCheck(S, "a1", "r1", { proceed: false, reason: `done finishes a run only when ${P.DISPOSITION_WORDS}. No disposition yet: question:2 is limited` }, {});
  ok(await L.openLead(a1, { title: "Have Q-2 accepted", why: "the finish line holds it", take: true }));
  assert.equal(ok(await L.closeLead(a1, "L-3", { disposition: "needs_operator", ref: "The finish line holds Q-2: accept its examination-limited disposition (swarm.sh question accept Q-2)" })).hint, undefined);
});

test("needs_operator writes the request for the operator; the operator's note reopens the lead, allows a host for jobs, and its holder is told", async () => {
  const { S, a1 } = await run();
  await traceRow(S, "a1", "bash", new Date());
  ok(await L.openLead(a1, { title: "Follow the pointer to the outside resource", why: "part 3's key is there", take: true }));
  refused(await L.closeLead(a1, "L-1", { disposition: "needs_operator", ref: "help" }), /what only the operator can do/);
  const closed = ok(await L.closeLead(a1, "L-1", { disposition: "needs_operator", ref: "The key is on a public paste site named in the plaintext; allow its host so a job can fetch it" }));
  assert.match(closed.operator_request ?? "", /^swarm\.sh lead t1 note L-1 "<your answer>" \[--allow-host HOST\]$/);
  const req = JSON.parse((await readFile(join(S, L.OPERATOR_REQUESTS), "utf8")).trim()) as Record<string, string>;
  assert.deepEqual([req.lead, req.by, req.run], ["L-1", "a1", "t1"]);
  await L.leadsDigest(a1, { mark: true });
  refused(await L.noteLead(S, "L-1", "go", { allowHost: "bad host!" }), /takes a host name/);
  const noted = ok(await L.noteLead(S, "L-1", "Allowed; fetch it with a job", { allowHost: "paste.example.org" }));
  assert.equal(noted.reopened, true);
  assert.equal(noted.lead.status, "open");
  assert.deepEqual(await L.operatorHosts(S), ["paste.example.org"]);
  const told = await L.leadsDigest(a1, { mark: false });
  // Reopened after the operator's note, it is offered to its previous holder first.
  assert.ok(told.notices.some((n) => n.kind === "offer" && /was reopened after the operator's note and is offered to you first, its previous holder/.test(n.text)), JSON.stringify(told.notices));
  assert.ok(told.notices.some((n) => n.kind === "operator_note" && /paste\.example\.org/.test(n.text)), JSON.stringify(told.notices));
});
