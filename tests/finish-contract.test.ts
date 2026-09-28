/**
 * The finish and the case contract (docs/adr/0015 with docs/adr/0014): the
 * state revision a finish line is judged at, and the readiness computed for
 * it, cover what the case contract adds to the gate. A request of the
 * operator opened or answered, the case policy the gate reads for
 * material_use, and an addition committed or applied each move the revision;
 * a notifier's delivery bookkeeping does not. An addition committed and not
 * yet applied holds readiness, as the gate holds it (addition_incomplete),
 * and so does an answer recorded before new evidence for its question
 * arrived (stale by evidence, as the gate holds it).
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function run(): Promise<string> {
  const base = await mkdtemp(join(tmpdir(), "finish-contract-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "fc1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30 });
  return S;
}

const rev = async (S: string) => (await P.stateRevision(S)).revision;
const line = (o: Record<string, unknown>) => `${JSON.stringify(o)}\n`;

test("the requests' chain moves the revision by what the operator decides, never by a notifier's delivery bookkeeping", async () => {
  const S = await run();
  await mkdir(join(S, "requests"), { recursive: true });
  const log = join(S, "requests", "requests.jsonl");
  const r0 = await rev(S);
  await appendFile(log, line({ v: 1, seq: 1, at: "2026-09-28T10:00:00Z", by: "harness", ev: "open", rid: "R-1", kind: "acquisition", key: "lead:L-1:4" }));
  const r1 = await rev(S);
  assert.notEqual(r1, r0, "a request opened moves it");
  await appendFile(log, line({ v: 1, seq: 2, at: "2026-09-28T10:00:01Z", by: "harness", ev: "claimed", rid: "R-1", claim: "c1" }));
  await appendFile(log, line({ v: 1, seq: 3, at: "2026-09-28T10:00:02Z", by: "harness", ev: "notified", rid: "R-1", claim: "c1" }));
  await appendFile(log, line({ v: 1, seq: 4, at: "2026-09-28T10:00:03Z", by: "harness", ev: "delivery_failed", rid: "R-1", claim: "c2", why: "no notification target took it" }));
  assert.equal(await rev(S), r1, "a delivery claimed, sent or failed does not move it");
  await appendFile(log, line({ v: 1, seq: 5, at: "2026-09-28T10:01:00Z", by: "operator", ev: "stage", rid: "R-1", stage: "authorised" }));
  const r2 = await rev(S);
  assert.notEqual(r2, r1, "an acquisition's stage moves it");
  await appendFile(log, line({ v: 1, seq: 6, at: "2026-09-28T10:02:00Z", by: "operator", ev: "answered", rid: "R-1", answer: "collected" }));
  assert.notEqual(await rev(S), r2, "an answer moves it");
});

test("the case policy and an addition move the revision, and an addition committed and not applied holds readiness", async () => {
  const S = await run();
  const r0 = await rev(S);
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), JSON.stringify({ v: 2, policy: "standard", network: "closed", more_evidence: "yes", material_use: { operator_supplied: "reference" } }));
  const r1 = await rev(S);
  assert.notEqual(r1, r0, "the case policy the gate reads for material_use is in it");
  const before = await F.readiness(S);
  assert.ok(!before.items.some((x) => /import:ev-0001/.test(x)), before.items.join("; "));
  await mkdir(join(S, "store"), { recursive: true });
  const journal = join(S, "store", "journal.jsonl");
  await appendFile(journal, line({ v: 1, seq: 1, type: "job_started", job: "j000001", declared: [] }));
  assert.equal(await rev(S), r1, "a job's journal line is not an addition (the job's state is read apart)");
  await appendFile(journal, line({ v: 1, seq: 2, type: "evidence_added", import: "ev-0001", by: "t@lab", at: "2026-09-28T10:05:00Z" }));
  const r2 = await rev(S);
  assert.notEqual(r2, r1, "an addition committed moves it");
  const held = await F.readiness(S);
  assert.equal(held.revision, r2);
  assert.equal(held.ready, false);
  assert.ok(held.items.some((x) => /import:ev-0001 \(evidence added at .*\) is committed and not all it implies is recorded yet/.test(x)), held.items.join("; "));
  await appendFile(journal, line({ v: 1, seq: 3, type: "addition_applied", import: "ev-0001", at: "2026-09-28T10:05:01Z" }));
  const r3 = await rev(S);
  assert.notEqual(r3, r2, "the addition applied moves it again");
  const after = await F.readiness(S);
  assert.ok(!after.items.some((x) => /import:ev-0001/.test(x)), "applied, it holds nothing");
});

test("an answer recorded before new evidence for its question arrived holds readiness, as the gate holds it", async () => {
  const base = await mkdtemp(join(tmpdir(), "finish-contract-"));
  dirs.push(base);
  const S = join(base, "run");
  const goal = ["## Goal", "", "Examine the mailbox.", "", "### Questions", "", "1. Which message changed the bank details?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1`', ""].join("\n");
  await P.initSandbox(S, { swarmId: "fc2", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal });
  await Q.seedRegister(S);
  const a0 = { sandboxRoot: S, agentId: "a0" };
  const f = await P.recordEntry(a0, { kind: "finding", value: "The message of 2026-06-14 changed the bank details", source: "mailbox", evidence: "message 42", answers: ["1"], basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as P.LedgerInput);
  assert.ok(f.ok, (f as { reason?: string }).reason);
  if (!f.ok) return;
  const ans = await P.recordEntry(a0, { kind: "answer", section: "question:1", result: "established", value: "The message of 2026-06-14", reasoning: `E-${f.entry.seq} shows it`, confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open", would_change: "a record that disagrees" } as unknown as P.LedgerInput);
  assert.ok(ans.ok, (ans as { reason?: string }).reason);
  if (!ans.ok) return;
  const stale = (r: F.Readiness) => r.items.some((x) => new RegExp(`question:1's answer E-${ans.entry.seq} predates new evidence for Q-1 \\(import:ev-0001\\)`).test(x));
  assert.equal(stale(await F.readiness(S)), false);
  await Q.recordEvidenceArrival(S, ["Q-1"], { import: "import:ev-0001", request: null, inventory_rev: 2 });
  const r = await F.readiness(S);
  assert.equal(stale(r), true, r.items.join("; "));
  assert.equal(r.ready, false);
});
