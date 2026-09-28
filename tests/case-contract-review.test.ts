/**
 * The defects an independent review (Astra, over the case contract's
 * 8e53574..c14f27b) found, each reproduced here and held fixed (the shell's
 * are in tests/case-contract.test.sh and tests/notify.test.sh; the fetch
 * service's interval in tests/net-review.test.ts):
 *
 *   3  a reason of 2,000 characters left an addition with no external entry
 *      and its leads closed;
 *   4  material_use none was passed by a digest, a job's output made from
 *      the material, or a coverage record, and answer checking never failed it;
 *   5  a crash after the commit left what rested on the evidence as it was
 *      current, with nothing to replay it;
 *   6  two additions at once shared an id and a staging directory;
 *   7  B9 read the raw name, not the one published, missed a short value
 *      marked sensitive, and Unicode that folds to it;
 *   8  an interrupted migration of a run's request lines lost them;
 *   9  the documents promised agents a frozen view the mounts do not give;
 *   10 a lead under a custom question section (bonus) stayed closed;
 *   11 a job's output attached as material lost its lineage downstream;
 *   12 two dispatchers notified the same request;
 *   13 a request imported from a run before the chain was never notified;
 *   14 a request act bypassed the hub, and its board post was not recovered;
 *   16 B16 missed an adapter named by its whole id.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import { goalServiceNotes, resolveCasePolicy, type CasePolicy } from "../scripts/case-policy.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { Journal } from "../scripts/evidence-store.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import * as M from "../scripts/material.ts";
import { loadCatalogue, loadDeny } from "../scripts/net-adapters.ts";
import { externalLineage } from "../scripts/net-broker.ts";
import { recordAttachments } from "../scripts/questions-cli.ts";
import * as RC from "../scripts/requests-cli.ts";
import { renderReportBody } from "../scripts/report-body.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const added = (r: Record<string, unknown> & { ok: boolean }): Record<string, unknown> => {
  assert.equal(r.ok, true, String(r.reason ?? ""));
  return r;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};
const policy = (flags: Record<string, string>): CasePolicy => {
  const r = resolveCasePolicy({ flags, isolation: "microvm" });
  assert.ok(r.ok, JSON.stringify(r));
  return (r as { policy: CasePolicy }).policy;
};

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const A = { result: "established", confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open", would_change: "a record that disagrees" } as const;
const GOAL = ["## Goal", "", "Examine the mailbox and the payment run.", "", "### Questions", "", "1. Which message changed the bank details?", "2. What was paid, and when?", "Bonus: what else did the clerk send?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,bonus,summary,narrative`', ""].join("\n");
const ASK = { kind: "acquisition", source: "the ERP's payment run export", where: "finance", expected_value: "what was paid and when", urgency: "normal" } as const;

async function run(o: { flags?: Record<string, string> } = {}) {
  const base = await mkdtemp(join(tmpdir(), "contract-review-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "cr1", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), JSON.stringify(policy(o.flags ?? {})));
  await Q.seedRegister(S);
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, base, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

async function hostFile(base: string, name: string, body: string): Promise<string> {
  const dir = join(base, "host", String(Math.random()).slice(2));
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, name), body);
  return join(dir, name);
}

/** A job's sealed output, as the job service leaves it, and its start on the store journal with what it declared. */
async function sealedJob(S: string, id: string, declared: string[], name: string, body: string): Promise<void> {
  const dir = join(S, "store", "jobs", id);
  await mkdir(join(dir, "out"), { recursive: true });
  await writeFile(join(dir, "out", name), body);
  await writeFile(join(dir, "manifest.json"), JSON.stringify({ v: 1, job: id, attempt: 1, sealed_at: new Date().toISOString(), files: [{ path: name, path_b64: Buffer.from(name).toString("base64"), bytes: body.length, sha256: P.sha256Hex(body) }], dirs: [], rejected: [], totals: { files: 1, bytes: body.length } }));
  await writeFile(join(dir, "job.json"), JSON.stringify({ id, attempt: 1, state: "committed", status: "ok", requester: { agent: "a1" }, spec: { kind: "command", command: "read it", inputs: declared, scope: "declared" } }));
  const j = await Journal.open(S);
  await j.append({ type: "job_started", job: id, declared, scope: { kind: "declared" } });
}

// --- 4 ---------------------------------------------------------------------------------------------

test("4: material_use none holds on what a record rests on, however it is cited: by digest, through a job's output, in a coverage record; and answer checking fails an answer resting on it", async () => {
  const { S, base, a0 } = await run({ flags: { material_use: "case_material=none" } });
  const body = "%PDF-1.4 the payment policy: two approvals above 10,000\n";
  added(await M.admitMaterial(S, { mode: "material", path: await hostFile(base, "policy.pdf", body), why: "the payment policy", cls: "case_material", supplied_by: "t", via: "cli" }));
  added(await M.admitMaterial(S, { mode: "material", path: await hostFile(base, "memo.txt", "The clerk's statement.\n"), why: "the clerk's statement", supplied_by: "t", via: "cli" }));
  const finding = (refs: string[]) => ({ kind: "finding", ...F, value: "The policy needs two approvals", source: "the policy", evidence: "page 1", refs, answers: ["2"] }) as unknown as P.LedgerInput;
  // The same bytes by their digest.
  refused(await P.recordEntry(a0, finding([`sha256:${P.sha256Hex(body)}`])), /rests on case material .*import:mat-0001.*material_use case_material=none/);
  // A job that read it, and its output.
  await sealedJob(S, "j000001", ["import:mat-0001/policy.pdf"], "approvals.txt", "two approvals above 10,000\n");
  refused(await P.recordEntry(a0, finding(["job:j000001/approvals.txt"])), /rests on case material \(job:j000001.*material_use case_material=none/);
  // A coverage record whose search produced that output.
  const coverage = { kind: "coverage", proposition: "A second approval of the payment exists", refs: ["import:mat-0002/memo.txt"], answers: ["2"], time_range: "no time bound", search_method: "read the statement and the approvals list", settings: "none", coverage_actual: "the statement and the list", skipped: "none", failures: "none", result_refs: ["job:j000001/approvals.txt"], alternatives: "an approval by mail, not examined", detection_opportunity: { trace_expected: "yes", why: "an approval is a line in the list" } };
  refused(await P.recordEntry(a0, coverage as unknown as P.LedgerInput), /job:j000001\/approvals\.txt rests on case material/);
  // An answer that came to rest on it anyway (recorded under a policy that allowed it) fails the answers check.
  await writeFile(join(S, "network", "policy.json"), JSON.stringify(policy({})));
  const f = ok(await P.recordEntry(a0, finding(["job:j000001/approvals.txt"])));
  ok(await P.recordEntry(a0, { kind: "answer", ...A, section: "question:2", value: "Two approvals were needed", reasoning: `E-${f.entry.seq} shows it` } as unknown as P.LedgerInput));
  assert.equal((await checkLedgerAnswers(S, ["question:2"])).defects.some((d) => d.code === "material_use"), false, "allowed under the policy it was recorded under");
  await writeFile(join(S, "network", "policy.json"), JSON.stringify(policy({ material_use: "case_material=none" })));
  const check = await checkLedgerAnswers(S, ["question:2"]);
  assert.equal(check.ok, false);
  const d = check.defects.find((x) => x.code === "material_use");
  assert.ok(d, JSON.stringify(check.defects));
  assert.match(d!.what, /rests on case_material material .*material_use case_material=none/);
  assert.deepEqual(d!.named_by, [], "never named away by a limitation");
});

// --- 7 ---------------------------------------------------------------------------------------------

test("7: B9 holds the name as it is published, a short value marked sensitive, and Unicode that folds to a sensitive value", async () => {
  const { S, a0 } = await run();
  ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "The vault word and its owner are recorded", source: "Alice", evidence: "Secret77", refs: ["unresolved:the fixture"], sensitive: true } as P.LedgerInput));
  ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "The second word is recorded", source: "the notebook", evidence: "Secret Word", refs: ["unresolved:the fixture"], sensitive: true } as P.LedgerInput));
  for (const name of ["Sec**ret77", "Secret\nWord", "asking Alice", "Ｓｅｃｒｅｔ７７", "Sec​ret77", "`secret`_77"]) {
    const r = await P.claimName(S, "a1", name);
    assert.equal(r.ok, false, `${JSON.stringify(name)} was taken`);
    assert.match((r as { error: string }).error, /holds a value the run marks sensitive/);
  }
  assert.equal((await P.claimName(S, "a1", "Malice hunter")).ok, true, "a short value is matched as a whole word, never inside another");
  const operator: Q.Actor = { kind: "human", role: "operator", person: "t@lab", enrolled: false, os_user: "t", host: "lab", via: "cli", identity: "claimed" };
  refused(await Q.act(S, operator, "open", { text: "Was Secret\nWord used elsewhere?", why: "reuse" }), /holds a value the run marks sensitive/);
  refused(await Q.act(S, operator, "open", { text: "What did alice send?", why: "w" }), /holds a value the run marks sensitive/);
});

// --- 11 --------------------------------------------------------------------------------------------

test("11: a job's output attached as material keeps its lineage: a finding citing it, by name or by its bytes, and the answer resting on it are flagged", async () => {
  const { S, a0 } = await run();
  const memo = "The clerk says the call came on Monday.\n";
  await sealedJob(S, "j000001", [], "memo.txt", memo);
  const att = await recordAttachments(S, "Q-1", ["job:j000001/memo.txt"], "ana");
  assert.equal(typeof att[0].entry, "number", JSON.stringify(att));
  // The same bytes in the store's blobs, as a digest cites them.
  await mkdir(join(S, "store", "blobs"), { recursive: true });
  await copyFile(join(S, "store", "jobs", "j000001", "out", "memo.txt"), join(S, "store", "blobs", P.sha256Hex(memo)));
  const byName = ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "The clerk states the call came on Monday", source: "the memo", evidence: "line 1", refs: ["job:j000001/memo.txt"], answers: ["1"] } as P.LedgerInput));
  const byBytes = ok(await P.recordEntry(a0, { kind: "finding", ...F, value: "The memo dates the call to Monday", source: "the memo", evidence: "line 1", refs: [`sha256:${P.sha256Hex(memo)}`], answers: ["1"] } as P.LedgerInput));
  const answer = ok(await P.recordEntry(a0, { kind: "answer", ...A, section: "question:1", value: "The call came on Monday, per the clerk", reasoning: `E-${byName.entry.seq} is the memo` } as unknown as P.LedgerInput));
  const lin = await externalLineage(S);
  assert.deepEqual(lin.classes.get(byName.entry.seq), ["operator_supplied"]);
  assert.deepEqual(lin.classes.get(byBytes.entry.seq), ["operator_supplied"]);
  assert.deepEqual(lin.classes.get(answer.entry.seq), ["operator_supplied"]);
  const check = await checkLedgerAnswers(S, ["question:1"]);
  assert.deepEqual(check.external["question:1"]?.classes, ["operator_supplied"]);
});

// --- 16 --------------------------------------------------------------------------------------------

test("16: B16 names an adapter the goal names by its whole id, or a tool name built on its service", () => {
  const lists = { adapters: loadCatalogue().adapters, deny: loadDeny() };
  const closed = policy({});
  const notes = (goal: string) => goalServiceNotes(`## Goal\n\n${goal}\n`, closed, lists);
  const domain = notes("Use `rdap_domain` for the sender's domain.");
  assert.equal(domain[0]?.adapter, "rdap_domain", JSON.stringify(domain));
  assert.equal(domain[0]?.level, "warn");
  assert.equal(notes("Look the address up with rdap_ip.")[0]?.adapter, "rdap_ip");
  const vt = notes("Check the hashes with virustotal_hash.");
  assert.equal(vt[0]?.adapter, "virustotal_file", JSON.stringify(vt));
  assert.equal(vt[0]?.level, "warn");
  assert.equal(notes("Pull the CVE from NVD.")[0]?.adapter, "nvd_cve");
  assert.deepEqual(notes("Write the report to report.md."), []);
});
