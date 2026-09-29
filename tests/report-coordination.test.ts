/**
 * The report per question (docs/adr/0016) with coordination and review
 * (docs/adr/0015): a question's chain says how strongly other seats hold its
 * answer (established, or a best candidate) and where a person's question was
 * offered; a lead says its offers, its hand-off, its product and its route
 * review; Appendix F holds the finish register: the coordinator's lease,
 * readiness, the report's review and its resolutions.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, dirs, ESTABLISHED, F as FIND, ok, planned, rec, run } from "./negative-bar-fixture.ts";

after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };

test("the report shows a best candidate, a question's offers, a lead's coordination and the finish register", async () => {
  const c = await run();
  const S = c.S;
  // Question 1 answered, and held a best candidate by the only other seat that reviewed it.
  await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...FIND, value: "What question 1 asks", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "The answer to 1", reasoning: `E-${f.seq} shows it`, result: "established", ...A, confidence: "high" })).entry;
  const att = await P.attestEntry(c.a2, { seq: a.seq, how: "re-derived it", strength: "best_candidate", answer_review: { ...ESTABLISHED.answer_review, parts: [{ part: "the question as asked", established: false, why: "one source only" }] } });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  // A lead handed off by a0 to a3, whose offer a3 accepts, with a product contract.
  const lead = await L.openLead(c.a0, { title: "The logon records", why: "they say what was deleted", answers: ["3"], take: true, product: "a table of logons", acceptance: "every logon in the security log is on it" });
  assert.ok(lead.ok, (lead as { reason?: string }).reason);
  const id = (lead as { lead: { id: string } }).lead.id;
  assert.ok((await L.handoffLead(c.a0, id, { why: "a3 reads the security log", to: "a3" })).ok);
  const accepted = await L.answerLeadOffer(c.a3, id, { action: "accept" });
  assert.ok(accepted.ok, (accepted as { reason?: string }).reason);
  // A person's question, offered to a seat by its delivery.
  const asked = await Q.act(S, operator, "open", { text: "Was the account used after the leave date?", why: "HR asks", suggested_to: "a2" });
  assert.ok(asked.ok, (asked as { reason?: string }).reason);
  await Q.deliverPending(S);
  // The finish: a0 published the report and coordinates; a2 objects; a0 resolves; ready.
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, "work", "report.md"), "# report\n");
  await P.recordFileVersion(S, "work/report.md", "a0");
  const turn = await F.finishTurn(c.a0, { output_file: "work/report.md" });
  assert.equal(turn.mine, true);
  const obj = await F.ackReport(c.a2, { verdict: "objection", why: "question 1 is a best candidate" });
  assert.ok(obj.ok);
  assert.ok((await F.resolveLate(c.a0, { ack: (obj as { seq: number }).seq, how: "folded", why: "the report says best candidate now" })).ok);
  await F.syncReadiness(S, { ready: true, revision: "r-ready", items: [], limited: [], confirming: [] });

  const md = await renderReportBodyMarkdown(S);
  assert.match(md, /Reviewed.*by a2 at .*, a best candidate/, "the answer's review says how strongly it holds");
  assert.match(md, /A best candidate, not established/);
  assert.match(md, new RegExp(`Coordination: handed off by a0 at [^;]* to a3 \\(a3 reads the security log\\); offered to a3 at [^;]* \\(handoff, from a0\\): accepted by a3`), "the lead's hand-off and its offer");
  assert.match(md, /Product: a table of logons; accepted when: every logon in the security log is on it/);
  const q = (await Q.questionsSnapshot(S)).state.questions.get((asked as { q: string }).q)!;
  assert.ok(q.offers.length >= 1, "the delivery offered it to a seat");
  assert.match(md, new RegExp(`Offered.*to ${q.offers[0].to} at`), "a person's question's offer, as the register wrote it");
  assert.match(md, /### The finish/);
  assert.match(md, /The coordinator at the end: a0 \(generation 1/);
  assert.match(md, /ack: objection to the report [0-9a-f]{12}: question 1 is a best candidate/);
  assert.match(md, /resolve: resolved ack \d+ as folded: the report says best candidate now/);
  assert.match(md, /readiness: ready at revision r-ready/);
});
