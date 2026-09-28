/**
 * The case contract (docs/adr/0014), below the operator requests' outbox
 * (tests/requests.test.ts): the case policy's presets, overrides and
 * conflicts, its record read back and preserved on a resume; the services a
 * goal names held to the policy and the adapter catalogue (B16); evidence
 * added after the kickoff as an inventory revision that answers its
 * acquisition and reopens the leads, answers and acceptances resting on the
 * evidence as it was; material supplied as external, flagged where answers
 * are weighed, and held to the policy's material use; the report's evidence
 * gaps; and the sensitivity of names, `doing` labels and question text (B9).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import { inventoryRevision } from "../extensions/negative-bar.ts";
import { defaultPolicy, goalPolicyKeys, goalServiceNotes, parseMaterialUse, policyDifferences, policyLines, PRESET, readCasePolicy, resolveCasePolicy, SOURCE_CLASSES, type CasePolicy } from "../scripts/case-policy.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { admitMaterial } from "../scripts/material.ts";
import { externalLineage } from "../scripts/net-broker.ts";
import { loadCatalogue, loadDeny } from "../scripts/net-adapters.ts";
import { renderReportBody, renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { recordAttachments } from "../scripts/questions-cli.ts";

const dirs: string[] = [];
after(async () => {
  // The store's sealed imports are read-only: made writable again to be removed.
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
/** An addition's answer (scripts/material.ts): a record, its ok said. */
const added_ = (r: Record<string, unknown> & { ok: boolean }): Record<string, unknown> => {
  assert.equal(r.ok, true, String(r.reason ?? ""));
  return r;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};
const policy = (flags: Record<string, string>, goal: Record<string, string> = {}): CasePolicy => {
  const r = resolveCasePolicy({ flags, goal, isolation: "microvm" });
  assert.ok(r.ok, JSON.stringify(r));
  return (r as { policy: CasePolicy }).policy;
};
const conflicts = (flags: Record<string, string>, goal: Record<string, string> = {}): string => {
  const r = resolveCasePolicy({ flags, goal, isolation: "microvm" });
  assert.equal(r.ok, false, `expected a conflict: ${JSON.stringify(r)}`);
  return (r as { conflicts: string[] }).conflicts.join("\n");
};

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const A = { result: "established", confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open", would_change: "a record that disagrees" } as const;
const GOAL = ["## Goal", "", "Examine the mailbox and the payment run. Look the sender's domain up in RDAP if you can.", "", "### Questions", "", "1. Which message changed the bank details?", "2. What was paid, and when?", "", "## Objectives", "", "- O-1: Establish how the details changed.", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`', ""].join("\n");

async function run(o: { flags?: Record<string, string> } = {}) {
  const base = await mkdtemp(join(tmpdir(), "contract-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "c1", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), JSON.stringify(policy(o.flags ?? {})));
  await Q.seedRegister(S);
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, base, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

// --- the case policy ---------------------------------------------------------------------------

test("the case policy: every field recorded, the presets' more evidence and material use, and a version 1 record read as it meant", () => {
  const d = defaultPolicy();
  assert.equal(d.v, 2);
  assert.equal(d.more_evidence, "ask");
  assert.deepEqual(d.material_use, { acquired_evidence: "evidence", case_material: "reference", operator_supplied: "reference", external_capture: "reference" });
  assert.equal(PRESET.ctf.more_evidence, "no");
  assert.equal(PRESET.internal.material_use.external_capture, "none");
  assert.deepEqual([...SOURCE_CLASSES], [...P.LEDGER_SOURCE_CLASSES], "the policy's classes are the ledger's");
  const lines = policyLines(policy({ more_evidence: "no" })).join("\n");
  assert.match(lines, /More evidence during the run: no \(no further evidence during this run: an acquisition ask is answered at once, "no additional input under this case policy"/);
  assert.match(lines, /acquired_evidence evidence, case_material reference, operator_supplied reference, external_capture reference/);
  // The goal's block and the flags set every field; a flag wins, and says so.
  const keys = goalPolicyKeys("---\npolicy: standard\nmore_evidence: yes\nmaterial_use: operator_supplied=none\nlegal: GDPR or similar laws\nprovider_retention: thirty days\n---\n## Goal\n");
  const r = resolveCasePolicy({ goal: keys, flags: { more_evidence: "ask" }, isolation: "microvm" });
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.policy.more_evidence, "ask");
  assert.equal(r.policy.material_use.operator_supplied, "none");
  assert.equal(r.policy.material_use.case_material, "reference", "a class left out keeps the preset's use");
  assert.equal(r.policy.provider_retention, "thirty days");
  assert.equal(r.policy.sources.material_use, "goal");
  assert.ok(r.notes.some((n) => /more_evidence: the kickoff's ask overrides the goal's yes/.test(n)));
  assert.deepEqual(parseMaterialUse("external_capture:none", PRESET.standard.material_use), { ok: true, use: { ...PRESET.standard.material_use, external_capture: "none" } });
});

test("conflicts are refused at kickoff, each with its reason: a capture is never evidence, a published case takes no evidence later, a class with no use cannot be expected", () => {
  assert.match(conflicts({ material_use: "external_capture=evidence" }), /a capture's hash proves its bytes, not their truth/);
  assert.match(conflicts({ policy: "ctf", network: "dynamic", more_evidence: "yes" }), /policy ctf: a published case's evidence is what was published/);
  assert.match(conflicts({ more_evidence: "yes", material_use: "acquired_evidence=none" }), /evidence the run expects could never be cited/);
  assert.match(conflicts({ more_evidence: "maybe" }), /more_evidence: "maybe" is not one of no, ask, yes \(the kickoff's --more-evidence\)/);
  assert.match(conflicts({}, { material_use: "captures are fine" }), /is not class=use.*the goal's metadata block/);
  assert.match(conflicts({ material_use: "screenshots=evidence" }), /screenshots is not a class/);
  assert.match(conflicts({ material_use: "case_material=proof" }), /proof is not a use/);
  // What is not a contradiction is a note.
  const r = resolveCasePolicy({ flags: { policy: "internal", material_use: "external_capture=reference" }, isolation: "microvm" });
  assert.ok(r.ok);
  assert.ok(r.notes.some((n) => /nothing is captured from outside an internal case/.test(n)));
  // ctf with ask is the operator's choice, not a contradiction.
  assert.equal(policy({ policy: "ctf", network: "dynamic", more_evidence: "ask" }).more_evidence, "ask");
});

test("a version 1 record (material use as a text) and a resume: the recorded policy is read as it meant, and a resume's options that differ are named", async () => {
  const base = await mkdtemp(join(tmpdir(), "contract-v1-"));
  dirs.push(base);
  await mkdir(join(base, "network"));
  const v1 = { ...defaultPolicy(), v: 1, material_use: "reference: an examiner records what a capture or supplied material establishes" } as unknown as CasePolicy;
  delete (v1 as Record<string, unknown>).material_note;
  await writeFile(join(base, "network", "policy.json"), JSON.stringify(v1));
  const read = readCasePolicy(base);
  assert.deepEqual(read.material_use, PRESET.standard.material_use);
  assert.match(read.material_note, /an examiner records/);
  const recorded = policy({ policy: "ctf", network: "dynamic" });
  const now = policy({ policy: "standard", more_evidence: "yes" });
  const diff = policyDifferences(recorded, now).join("\n");
  assert.match(diff, /policy: recorded "ctf", these options "standard"/);
  assert.match(diff, /more_evidence: recorded "no", these options "yes"/);
  assert.deepEqual(policyDifferences(recorded, recorded), []);
});

// --- B16 ------------------------------------------------------------------------------------------

test("B16: the services a goal names are held to the policy and the adapter catalogue, as warnings", () => {
  const lists = { adapters: loadCatalogue().adapters, deny: loadDeny(), keys: new Set<string>() };
  const goal = "Use RDAP for the sender's domain, look the place up in Nominatim, check the hash on VirusTotal, search Google for the name, and read https://files.example-case.com/brief.";
  const closed = goalServiceNotes(goal, policy({}), lists);
  const said = (notes: ReturnType<typeof goalServiceNotes>, re: RegExp) => notes.some((n) => re.test(n.text));
  assert.ok(said(closed, /names rdap .*network is closed/), JSON.stringify(closed, null, 1));
  assert.ok(said(closed, /google.*hard denials refuse \(search/), "a denied service named by its own name");
  assert.ok(said(closed, /files\.example-case\.com, which this run's closed network does not reach/));
  const dyn = goalServiceNotes(goal, policy({ network: "dynamic" }), lists);
  assert.ok(dyn.some((n) => n.adapter === "rdap_domain" && n.level === "ok"), "RDAP is reachable under standard, dynamic");
  assert.ok(said(dyn, /virustotal.*needs a host-managed key \(DFIRSWARM_VT_API_KEY\)/i));
  assert.ok(said(dyn, /files\.example-case\.com, which no adapter of the catalogue reaches/));
  const internal = goalServiceNotes(goal, policy({ policy: "internal" }), lists);
  assert.ok(internal.every((n) => n.level === "warn"));
  // No catalogue (WP6 absent): the hosts alone, nothing thrown.
  const bare = goalServiceNotes(goal, policy({}), {});
  assert.ok(bare.some((n) => n.service === "files.example-case.com"));
  assert.deepEqual(goalServiceNotes("## Goal\nExamine the image in inputs/disk.E01 and write report.md.", policy({}), lists), [], "a file name is not a service");
});

// --- evidence added after the kickoff ---------------------------------------------------------------

async function lateFile(base: string, name = "erp-payment-run-export.csv", body = "run,amount\n2026-06-16,48200.00\n") {
  const dir = join(base, "late");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, name), body);
  return join(dir, name);
}

test("evidence add: an inventory revision in the store and the ledger, the acquisition received and validated, the leads, answers and acceptances resting on the evidence as it was reopened", async () => {
  const { S, base, a0, a1, a2 } = await run();
  // An answer to Q-2 before the evidence came, a lead closed on it, and the acquisition asked on another lead.
  ok(await L.openLead(a1, { title: "The payments", why: "Q2", answers: ["2"], take: true, routes: [{ source: "input:mail", method: "read" }] }));
  const f = ok(await P.recordEntry(a1, { kind: "finding", ...F, value: "A payment of 48,200 appears in the clerk's mail", source: "mail", evidence: "the mail", refs: ["unresolved:the fixture has no store object"], answers: ["2"] } as P.LedgerInput));
  const ans = ok(await P.recordEntry(a1, { kind: "answer", ...A, section: "question:2", value: "48,200 was paid", reasoning: `E-${f.entry.seq} shows it` } as unknown as P.LedgerInput));
  ok(await L.closeLead(a1, "L-1", { disposition: "resolved", ref: `E-${f.entry.seq}` }));
  ok(await L.openLead(a0, { title: "The payment run", why: "Q2 wants what was paid", answers: ["2"], take: true }));
  const asked = ok(await L.closeLead(a0, "L-2", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: { kind: "acquisition", source: "the ERP's payment run export", where: "finance", expected_value: "what was paid and when", urgency: "normal" } }));
  assert.equal(asked.request?.id, "R-1");
  const before = await inventoryRevision(S);
  // Refused: a path inside the run; a wrong acquisition hash; a request that is not an acquisition.
  refused(await admitMaterial(S, { mode: "evidence", path: join(S, "SWARM.md"), why: "w", supplied_by: "t", via: "cli" }), /inside the run/);
  const file = await lateFile(base);
  refused(await admitMaterial(S, { mode: "evidence", path: file, why: "the export", for: "R-1", sha256: "0".repeat(64), supplied_by: "t", via: "cli" }), /not the acquisition hash given.*nothing was added/);
  refused(await admitMaterial(S, { mode: "evidence", path: file, why: "", for: "R-1", supplied_by: "t", via: "cli" }), /says why/);
  const added = added_(await admitMaterial(S, { mode: "evidence", path: file, why: "finance supplied the payment run export", for: "R-1", supplied_by: "t@lab (not enrolled)", via: "cli" }));
  assert.equal(added.import, "ev-0001");
  assert.equal(added.inventory_rev, 1);
  // In the store: sealed, read-only, on the journal with every file's sha256.
  const journal = (await readFile(join(S, "store", "journal.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  const line = journal.find((l) => l.type === "evidence_added");
  assert.equal(line.import, "ev-0001");
  assert.equal(line.request, "R-1");
  assert.equal(line.files[0].sha256, (added.files as Array<{ sha256: string }>)[0].sha256);
  assert.equal(await readFile(join(S, "store", "imports", "ev-0001", "out", "erp-payment-run-export.csv"), "utf8"), "run,amount\n2026-06-16,48200.00\n");
  assert.notEqual(await inventoryRevision(S), before, "the inventory revision moved");
  // On the ledger: external, acquired evidence, with its provenance.
  const ext = (await P.readLedger(S)).find((e) => e.kind === "external")!;
  assert.equal(ext.source_class, "acquired_evidence");
  assert.deepEqual(ext.refs, ["import:ev-0001/erp-payment-run-export.csv"]);
  assert.equal(ext.provenance?.supplied_by, "t@lab (not enrolled)");
  assert.equal(ext.provenance?.from, file);
  assert.match(String(ext.provenance?.permitted_use), /^evidence: /);
  // The acquisition: received, then validated; answered.
  const req = (await R.requestsSnapshot(S)).requests.get("R-1")!;
  assert.deepEqual(req.stages.map((s) => s.stage), ["requested", "authorised", "received", "validated"]);
  assert.equal(req.state, "answered");
  // Reopened: the lead closed on the evidence as it was, and the acquisition's own lead.
  const snap = await L.leadsSnapshot(S);
  assert.equal(snap.state.leads.get("L-1")?.closed, null);
  assert.equal(snap.state.leads.get("L-2")?.closed, null);
  assert.equal(snap.state.leads.get("L-1")?.reopened.at(-1)?.cause, "evidence_added");
  // The answer recorded before it is stale, for the evidence, and the finish line says so.
  const v = Q.questionViews(await Q.viewContext(S)).find((x) => x.id === "Q-2")!;
  assert.equal(v.answer?.seq, ans.entry.seq);
  assert.equal(v.answer?.stale, true);
  assert.equal(v.answer?.stale_why, "evidence");
  assert.equal(v.evidence[0].import, "import:ev-0001");
  const gate = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.ok(gate.defects.some((d) => d.code === "stale_answer" && /new evidence for Q-2/.test(d.what)), JSON.stringify(gate.defects));
  // A new answer after it is not stale.
  const f2 = ok(await P.recordEntry(a2, { kind: "finding", ...F, value: "The export shows 48,200.00 paid on 2026-06-16", source: "the export", evidence: "row 2", refs: ["import:ev-0001/erp-payment-run-export.csv"], answers: ["2"] } as P.LedgerInput));
  ok(await P.recordEntry(a2, { kind: "answer", ...A, section: "question:2", value: "48,200.00 was paid on 2026-06-16", reasoning: `E-${f2.entry.seq} shows it`, supersedes: ans.entry.seq } as unknown as P.LedgerInput));
  const v2 = Q.questionViews(await Q.viewContext(S)).find((x) => x.id === "Q-2")!;
  assert.equal(v2.answer?.stale, false);
  // The answer resting on it is named with its class, never failed.
  const check = await checkLedgerAnswers(S, ["question:2"]);
  assert.deepEqual(check.external["question:2"]?.classes, ["acquired_evidence"]);
  assert.ok(check.lines.some((l) => /rests on external material .*question:2 #\d+ \(acquired_evidence\)/.test(l)), check.lines.join("\n"));
});

test("evidence add is refused under more_evidence: no, and an acceptance made before new evidence no longer stands", async () => {
  const no = await run({ flags: { more_evidence: "no" } });
  const file = await lateFile(no.base);
  refused(await admitMaterial(no.S, { mode: "evidence", path: file, why: "late", supplied_by: "t", via: "cli" }), /admits no evidence after its kickoff \(case policy standard, more_evidence: no\)/);
  const { S, base, a0 } = await run();
  const operator: Q.Actor = { kind: "human", role: "operator", person: "t@lab", enrolled: false, os_user: "t", host: "lab", via: "cli", identity: "claimed" };
  ok(await Q.act(S, operator, "accept", { q: "Q-1", as: "not_determinable", why: "no message survives", expected_rev: 1 }));
  assert.equal(Q.acceptanceStands((await Q.questionsSnapshot(S)).state.questions.get("Q-1")!, (await Q.viewContext(S)).ledger), true);
  added_(await admitMaterial(S, { mode: "evidence", path: await lateFile(base, "server.log", "line\n"), why: "the mail server's log", questions: ["Q-1"], supplied_by: "t", via: "cli" }));
  const q1 = (await Q.questionsSnapshot(S)).state.questions.get("Q-1")!;
  assert.equal(Q.acceptanceStands(q1, (await Q.viewContext(S)).ledger), false, "new evidence lifts the acceptance");
  void a0;
});

// --- material supplied, and what rests on it ----------------------------------------------------------

test("material add and a question's attachment: external, operator supplied, with provenance; an answer resting on it is flagged with its class; a class the policy says none cannot be cited", async () => {
  const { S, base, a0 } = await run({ flags: { material_use: "case_material=none" } });
  const memo = join(base, "memo.txt");
  await writeFile(memo, "The clerk says the call came on Monday.\n");
  const m = added_(await admitMaterial(S, { mode: "material", path: memo, why: "the clerk's statement", supplied_by: "ana (analyst, enrolled, claimed)", via: "cli" }));
  assert.equal(m.import, "mat-0001");
  assert.equal(m.class, "operator_supplied");
  const f = ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "The clerk states the call came on Monday", source: "the statement", evidence: "line 1", refs: ["import:mat-0001/memo.txt"], answers: ["1"] } as P.LedgerInput));
  ok(await P.recordEntry(a0, { kind: "answer", ...A, section: "question:1", value: "The call came on Monday, per the clerk", reasoning: `E-${f.entry.seq} is the statement` } as unknown as P.LedgerInput));
  const lin = await externalLineage(S);
  assert.deepEqual(lin.classes.get(f.entry.seq), ["operator_supplied"]);
  const check = await checkLedgerAnswers(S, ["question:1"]);
  assert.deepEqual(check.external["question:1"]?.classes, ["operator_supplied"]);
  // Case material under material_use case_material=none: kept, and never citable.
  const policyDoc = join(base, "policy.pdf");
  await writeFile(policyDoc, "%PDF-1.4 the payment policy\n");
  added_(await admitMaterial(S, { mode: "material", path: policyDoc, why: "the payment policy", cls: "case_material", supplied_by: "t", via: "cli" }));
  refused(await P.recordEntry(a0, { kind: "finding", ...F, value: "The policy needs two approvals", source: "the policy", evidence: "page 1", refs: ["import:mat-0002/policy.pdf"] } as P.LedgerInput), /is case material, which case policy standard does not let a record cite \(material_use case_material=none\)/);
  // A question's attachment already in the run is recorded as supplied material, once; the original evidence is not.
  const r = await recordAttachments(S, "Q-1", ["import:mat-0001/memo.txt", "input:mail.mbox", "job:j000001/out.txt"], "ana");
  assert.equal(r[0].skipped, "recorded as external material already");
  assert.equal(r[1].skipped, "the original evidence, not supplied material");
  assert.ok(r[2].pending, "a ref that does not resolve is said, not recorded");
});

// --- the report's evidence gaps ---------------------------------------------------------------------

test("the report's evidence gaps: never collected, unavailable, inaccessible, unexamined and inconclusive, told apart and generated from the records", async () => {
  const { S, base, a0, a1 } = await run();
  const ask = (source: string) => ({ kind: "acquisition", source, where: "the client", expected_value: "what happened", urgency: "normal" });
  for (const [i, src] of ["the firewall logs", "the phone", "the backup tape"].entries()) {
    ok(await L.openLead(a0, { title: `Need ${src}`, why: "w", answers: ["2"], take: true }));
    ok(await L.closeLead(a0, `L-${i + 1}`, { disposition: "needs_operator", ref: `${src} is not in the evidence`, ask: ask(src) }));
  }
  ok(await R.requestAct(S, "R-1", { ev: "declined", by: "operator", why: "out of scope for the client" }));
  ok(await R.requestAct(S, "R-2", { ev: "stage", by: "operator", stage: "unavailable", why: "the phone was wiped" }));
  // R-3 stays open. Evidence added without a request, and not read by any job.
  added_(await admitMaterial(S, { mode: "evidence", path: await lateFile(base, "extra.log", "x\n"), why: "an extra log", supplied_by: "t", via: "cli" }));
  // Limitations by reason, and an answer not determinable.
  ok(await P.recordEntry(a1, { kind: "limitation", reason: "failed", value: "The encrypted volume could not be opened (R-9 is unrelated)", source: "the volume", evidence: "the tool's error", refs: ["unresolved:the fixture"], answers: ["1"] } as unknown as P.LedgerInput));
  ok(await P.recordEntry(a1, { kind: "limitation", reason: "not_examined", value: "The second mailbox was not examined", source: "the mailbox", evidence: "no job read it", refs: ["unresolved:the fixture"], answers: ["1"] } as unknown as P.LedgerInput));
  const body = await renderReportBody(S);
  const s8 = body.sections.find((s) => s.id === "s8")!.html;
  assert.match(s8, /Evidence gaps and acquisition requests/);
  for (const cls of ["Never collected", "Unavailable", "Inaccessible", "Unexamined"]) assert.match(s8, new RegExp(`${cls} \\(`), cls);
  assert.match(s8, /the firewall logs \(the client\)/);
  assert.match(s8, /R-1, declined by operator/);
  assert.match(s8, /R-3, still requested when this was rendered/);
  assert.match(s8, /R-2: unavailable: the phone was wiped/);
  assert.match(s8, /import:ev-0001 \(an extra log\)/);
  assert.match(s8, /never a finding that something is absent/);
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, /### Evidence gaps and acquisition requests/);
  assert.match(md, /\| R-1 \| the firewall logs \(the client\) \| Q-2 \|/);
  // Evidence added in §3.
  assert.match(body.sections.find((s) => s.id === "s3")!.html, /Evidence added during the run/);
});

// --- B9: names, doing labels and question text ------------------------------------------------------

test("B9: a name, a doing label and a question's text are refused when they hold a value the run marks sensitive, whatever its origin: an answer, supplied material, the goal's own words", async () => {
  const { S, base, a0 } = await run();
  const secret = "Wint3r-Rose-2026!";
  // In the goal's own words too: there is no goal-text exemption.
  await writeFile(join(S, "SWARM.md"), `${await readFile(join(S, "SWARM.md"), "utf8")}\nThe clerk's password may be ${secret}.\n`);
  ok(await P.recordEntry(a0, { kind: "finding", ...F, value: `The clerk entered ${secret} on the phishing page`, source: "the history", evidence: "row 9", refs: ["unresolved:the fixture"], sensitive: true } as P.LedgerInput));
  for (const [name, doing] of [[`Hunting ${secret}`, undefined], ["pw-hunter", `checking where ${secret} was reused`], ["pw-hunter", `CHECKING ${secret.toUpperCase()}`]] as const) {
    const r = await P.claimName(S, "a1", name, doing);
    assert.equal(r.ok, false);
    assert.match((r as { error: string }).error, /holds a value the run marks sensitive \(E-1\).*Nothing was recorded/);
    assert.ok(!(r as { error: string }).error.includes(secret), "the refusal never repeats the value");
  }
  assert.equal((await P.readNames(S)).length, 0);
  ok(await P.claimName(S, "a1", "pw-hunter", "checking where the password (E-1) was reused") as { ok: boolean });
  // An answer marked sensitive is a sensitive value like any other: no answer-value concept.
  const operator: Q.Actor = { kind: "human", role: "operator", person: "t@lab", enrolled: false, os_user: "t", host: "lab", via: "cli", identity: "claimed" };
  refused(await Q.act(S, operator, "open", { text: `Was ${secret.toLowerCase()} used elsewhere?`, why: "reuse" }), /holds a value the run marks sensitive/);
  const answerSecret = "acct-7731-0042-9918";
  const f = ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "The account is recorded", source: "s", evidence: "e", refs: ["unresolved:x"], answers: ["2"] } as P.LedgerInput));
  ok(await P.recordEntry(a0, { kind: "answer", ...A, section: "question:2", value: `Paid to ${answerSecret}`, reasoning: `E-${f.entry.seq}`, sensitive: true } as unknown as P.LedgerInput));
  refused(await Q.act(S, operator, "open", { text: `Who controls ${answerSecret}?`, why: "w" }), /sensitive/);
  const r = await P.claimName(S, "a2", `tracing ${answerSecret}`);
  assert.equal(r.ok, false);
  // Supplied material the operator marks sensitive.
  const note = join(base, "note.txt");
  await writeFile(note, "x\n");
  added_(await admitMaterial(S, { mode: "material", path: note, why: "the informant Kestrel-Nine-44 says so", sensitive: true, supplied_by: "t", via: "cli" }));
  const r2 = await P.claimName(S, "a2", "asking Kestrel-Nine-44");
  assert.equal(r2.ok, false);
});

// --- release.json binds the case contract -----------------------------------------------------------

test("release.json binds the case policy held to its anchor, the answers resting on external material with their classes, and the acquisitions", async () => {
  const { stoppedRun, cleanUp } = await import("./release-fixture.ts");
  const { draftRelease, runContext } = await import("../scripts/release.ts");
  const { custodyAnchorPath, takeCustody } = await import("../scripts/custody.ts");
  try {
    const r = await stoppedRun({ id: "scc1" });
    // The kickoff's policy record and its anchor, as the kickoff writes them.
    await mkdir(join(r.root, "network"), { recursive: true });
    const text = `${JSON.stringify(policy({ more_evidence: "yes" }), null, 2)}\n`;
    await writeFile(join(r.root, "network", "policy.json"), text);
    const { createHash } = await import("node:crypto");
    const anchor = JSON.parse(await readFile(custodyAnchorPath(r.root), "utf8")) as Record<string, unknown>;
    spawnSync("chmod", ["u+w", custodyAnchorPath(r.root)]);
    await writeFile(custodyAnchorPath(r.root), JSON.stringify({ ...anchor, case_policy_sha256: createHash("sha256").update(text).digest("hex") }));
    // Material supplied, a finding and an answer resting on it, and an acquisition.
    const memo = join(r.runs, "memo.txt");
    await writeFile(memo, "the statement\n");
    added_(await admitMaterial(r.root, { mode: "material", path: memo, why: "a statement", supplied_by: "t", via: "cli" }));
    const ctx = { sandboxRoot: r.root, agentId: "a1" };
    const f = ok(await P.recordEntry(ctx, { kind: "finding", ...F, value: "The statement says so", source: "the statement", evidence: "line 1", refs: ["import:mat-0001/memo.txt"], answers: ["9"] } as P.LedgerInput));
    const a = ok(await P.recordEntry(ctx, { kind: "answer", ...A, section: "question:9", value: "So, per the statement", reasoning: `E-${f.entry.seq}` } as unknown as P.LedgerInput));
    ok(await L.openLead(ctx, { title: "The mail server's log", why: "Q9", answers: ["9"], take: true }));
    ok(await L.closeLead(ctx, "L-1", { disposition: "needs_operator", ref: "The mail server's log is not in the evidence", ask: { kind: "acquisition", source: "the mail server's log", where: "the hosting provider", expected_value: "who sent it", urgency: "volatile" } }));
    await takeCustody(r.root, { runsDir: r.runs });
    const d = await draftRelease(runContext(r.root, { run: r.id, runsDir: r.runs }), { home: r.home, say: () => undefined, reason: "the case contract" });
    assert.ok(d.written, d.skipped ?? "");
    const rec = JSON.parse(await readFile(join(d.written!.dir, "release.json"), "utf8")) as import("../scripts/release-record.ts").ReleaseRecord;
    assert.equal(rec.case_policy?.anchored, true);
    assert.equal(rec.case_policy?.more_evidence, "yes");
    assert.equal(rec.case_policy?.material_use.operator_supplied, "reference");
    const ext = rec.external?.answers.find((x) => x.seq === a.entry.seq);
    assert.deepEqual(ext?.classes, ["operator_supplied"]);
    assert.equal(ext?.section, "question:9");
    assert.match(rec.external?.note ?? "", /supplied material proves nothing by itself/);
    assert.deepEqual(rec.acquisitions, [{ id: "R-1", state: "acknowledged", stage: "authorised", source: "the mail server's log", questions: ["Q-9"], import: null }]);
  } finally {
    await cleanUp();
  }
});
