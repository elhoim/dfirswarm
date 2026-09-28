/**
 * The metrics (docs/adr/0017) against the registers the coordination code
 * writes (docs/adr/0015), not against hand-written lines: a lead handed off
 * and its offer accepted, one declined, readiness recorded by the finish
 * register's own writer, a done answered "not yours", and the sentinel. The
 * offer, done and tail figures come out measured, never "absent"; and a job
 * run under a lead taken by an offer is that lead's in the fold the hub's
 * leadsOf reads for the reuse hints.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { measureRun, metricsText } from "../scripts/metrics.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const GOAL = ["## Goal", "", "Examine the mailbox.", "", "### Questions", "", "1. Which message changed the bank details?", "2. Who sent it?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2`', ""].join("\n");

test("offers, done calls and the tail are measured from what the coordination code writes", async () => {
  const base = await mkdtemp(join(tmpdir(), "metrics-coord-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "mc1", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await Q.seedRegister(S);
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  // A lead handed off to a1, whose offer a1 accepts by claiming it.
  const l1 = await L.openLead(ctx("a0"), { title: "Read the mailbox's rules", why: "a forwarding rule would show the change", answers: ["1"], take: true });
  assert.ok(l1.ok, (l1 as { reason?: string }).reason);
  const id1 = (l1 as { lead: { id: string } }).lead.id;
  const h1 = await L.handoffLead(ctx("a0"), id1, { why: "I take the sender's side; the rules are yours", to: "a1" });
  assert.ok(h1.ok, (h1 as { reason?: string }).reason);
  const acc = await L.answerLeadOffer(ctx("a1"), id1, { action: "accept" });
  assert.ok(acc.ok, (acc as { reason?: string }).reason);
  // A job a1 runs under the lead it took by the offer: the hub's leadsOf (the reuse hints' lead, ADR 0017) reads it from the lead register's fold.
  const att = await L.attachJob(S, "a1", "j000001", id1);
  assert.ok(att.ok && att.lead === id1, JSON.stringify(att));
  const jobLead = L.foldLeads((await L.readLeadEvents(S)).events).jobLead;
  assert.equal(jobLead.get("j000001"), id1, "a job under a handed-off lead is that lead's");
  // A second lead handed off to a2, who declines it.
  const l2 = await L.openLead(ctx("a0"), { title: "Trace the sender's domain", why: "a lookalike domain would say who", answers: ["2"], take: true });
  assert.ok(l2.ok, (l2 as { reason?: string }).reason);
  const id2 = (l2 as { lead: { id: string } }).lead.id;
  const h2 = await L.handoffLead(ctx("a0"), id2, { why: "a second pair of eyes on the headers", to: "a2" });
  assert.ok(h2.ok, (h2 as { reason?: string }).reason);
  const dec = await L.answerLeadOffer(ctx("a2"), id2, { action: "decline", why: "I am on the attachments" });
  assert.ok(dec.ok, (dec as { reason?: string }).reason);
  // Readiness, recorded by the finish register's own writer: ready, then the run ends.
  assert.equal(await F.syncReadiness(S, { ready: true, revision: "r-ready", items: [], limited: [] }), true);
  // A seat's done that was not the finish, as the extension writes it on the trace.
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: new Date().toISOString(), agent: "a2", tool: "done_deferred", args: { output_file: "work/report.md" }, result: { ok: true, coordinator: "a0", generation: 1, ready: true } })}\n`);
  await new Promise((r) => setTimeout(r, 20));
  await mkdir(join(S, "done"), { recursive: true });
  await writeFile(join(S, P.SENTINEL_REL), `---\nby: a0\noutput: work/report.md\nreason: finished\nat: ${new Date().toISOString()}\n---\n\nCollective finished.\n`);

  const m = await measureRun(S);
  assert.equal(m.registers.leads, true);
  assert.equal(m.registers.finish, true, "the finish register exists");
  assert.equal(m.offers.recorded, true, "offers are counted, not said absent");
  assert.ok(!m.notes.some((n) => /no offer events/.test(n)), m.notes.join("; "));
  const handoff = m.offers.leads.by_reason.handoff;
  assert.ok(handoff, JSON.stringify(m.offers.leads));
  assert.ok(handoff.made >= 2, JSON.stringify(handoff));
  assert.equal(handoff.accepted, 1, JSON.stringify(handoff));
  assert.equal(handoff.declined, 1, JSON.stringify(handoff));
  assert.equal(m.done.not_yours, 1, JSON.stringify(m.done));
  assert.equal(m.tail.ready_source, "readiness", JSON.stringify(m.tail));
  assert.ok(m.tail.ready_at && m.tail.end_at && m.tail.ready_at <= m.tail.end_at, JSON.stringify(m.tail));
  assert.equal(typeof m.tail.minutes_from_ready, "number", JSON.stringify(m.tail));
  assert.ok(!m.notes.some((n) => /no finish register/.test(n)), m.notes.join("; "));
  const text = metricsText(m);
  assert.doesNotMatch(text, /absent/i, text);
});
