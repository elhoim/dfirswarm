/**
 * The question register's cases an independent review found open, each held
 * here: a question named by any of its aliases is held to the same standing;
 * a directive is not signed; a signed act carries its signature on its own
 * event, and a signed-labelled act without one fails verification; an act's
 * effects on the lead register are made good after a crash; admission and a
 * new revision after the done are follow-ups; a lead opened from a finding
 * goes to triage on a withdrawal; an answer is bound to the revision it
 * answers; the signer is the person the signed act names, checked against
 * this install's enrolment, and a register naming the key for someone else
 * fails; a signed amendment verifies; a failed publication stays pending;
 * delivery is found by an exact key; clarification requests are derived
 * from the chain; operator acts are admitted by the hub when one runs;
 * a goal question is seeded whole; a directive is framed at its first claim;
 * a withdrawn goal question is not required; a release holds the registers
 * to the verdict it binds; and the console's last post is whole.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import * as QC from "../scripts/questions-cli.ts";
import { allowedSignersLine, enrollPerson } from "../scripts/signers.ts";
import { Hub } from "../scripts/vm-hub.ts";
import { listSwarmRows } from "../scripts/ui/model.ts";
import { draftRelease, runContext } from "../scripts/release.ts";
import { runLayout, verifyReleases } from "../scripts/release-record.ts";
import { reviewsPath } from "../scripts/review.ts";
import { custodyAnchorPath, takeCustody } from "../scripts/custody.ts";
import { cleanUp, stoppedRun } from "./release-fixture.ts";

const dirs: string[] = [];
const closers: Array<() => Promise<unknown>> = [];
after(async () => {
  for (const c of closers.reverse()) await c().catch(() => undefined);
  for (const d of dirs) await rm(d, { recursive: true, force: true });
  await cleanUp();
});

const ROOT = join(import.meta.dirname, "..");
const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const A = { result: "established", confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open: the record is direct", would_change: "a second record that disagrees" } as const;
const ROUTE = [{ source: "input:disk.E01", method: "read what the question names, looking for what would disconfirm it" }];

const GOAL = [
  "## Goal",
  "",
  "Examine the archive.",
  "",
  "### Questions",
  "",
  "1. Which account created the archive?",
  "2. Was the archive opened on another machine?",
  "",
  "## Objectives",
  "",
  "- O-1: Establish how the archive came to be on this machine.",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`',
  "",
].join("\n");

async function run(goal: string = GOAL, agents = ["a0", "a1", "a2"]) {
  const base = await mkdtemp(join(tmpdir(), "qreview-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "q1", agentIds: agents, capUsd: 5, wallClockMinutes: 30, goal });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, base, ctx, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

const person = (role: Q.ActorRole, id: string): Q.Actor => ({ kind: "human", role, person: id, name: id.toUpperCase(), enrolled: true, os_user: "tester", host: "lab", via: "cli", identity: "claimed" });
const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
const agent = (id: string): Q.Actor => ({ kind: "agent", agent: id });

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

async function posts(S: string): Promise<Array<{ file: string; text: string }>> {
  const dir = join(S, "threads", "main");
  const names = (await readdir(dir).catch(() => [] as string[])).filter((n) => /^\d{6}-.+\.md$/.test(n)).sort();
  return Promise.all(names.map(async (n) => ({ file: n, text: await readFile(join(dir, n), "utf8") })));
}

/** Append an event to the question chain as a crash, a forger or a torn run would leave it: hashed, and nothing else done. */
async function appendRaw(S: string, draft: Record<string, unknown>) {
  await L.withRegisters(S, async () => {
    const text = await readFile(join(S, Q.QUESTIONS_LOG), "utf8");
    const head = Q.verifyQuestionChain(text).head!;
    const seq = text.split("\n").filter((l) => l.trim()).length + 1;
    const d = { v: 1 as const, seq, at: new Date().toISOString(), ...draft, prev: head } as unknown as Q.QuestionEvent;
    await appendFile(join(S, Q.QUESTIONS_LOG), `${JSON.stringify({ ...d, hash: Q.questionEventHash(d, head) })}\n`);
  });
}

/** Rewrite the first event `pick` finds with `change`, and chain it and every event after it again: a consistent chain that says something else. */
async function rewriteEvent(S: string, pick: (e: Record<string, unknown>) => boolean, change: (e: Record<string, unknown>) => void) {
  const text = await readFile(join(S, Q.QUESTIONS_LOG), "utf8");
  const events = text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Record<string, unknown>);
  const at = events.findIndex(pick);
  assert.ok(at >= 0, "the event to rewrite");
  change(events[at]);
  let prev = String(events[at].prev);
  for (let i = at; i < events.length; i++) {
    const { hash: _h, ...rest } = events[i];
    const e = { ...rest, prev };
    events[i] = { ...e, hash: Q.questionEventHash(e as unknown as Q.QuestionEvent, prev) };
    prev = String(events[i].hash);
  }
  await writeFile(join(S, Q.QUESTIONS_LOG), `${events.map((e) => JSON.stringify(e)).join("\n")}\n`);
}

/** An enrolled analyst with a passphrase-protected key, in a home of its own. */
async function enrolled(id: string, base: string) {
  const home = join(base, `home-${id}-${Math.random().toString(36).slice(2, 6)}`);
  await mkdir(home, { recursive: true });
  const pass = Buffer.from(`the passphrase of ${id}`);
  const e = enrollPerson({ name: `${id.toUpperCase()} Lyst`, organisation: "Lab", competence: "casework", role: "analyst", id, generateKey: true }, home, Buffer.from(pass));
  assert.ok(!("why" in e), "why" in e ? e.why : "");
  return { home, pass, person: (e as Exclude<typeof e, { why: string }>).person };
}

// --- 1: aliases -------------------------------------------------------------------------------------

test("every alias of a question is held to its standing: a proposed or withdrawn question refuses work named as question:N, N or QN as it does as Q-N", async () => {
  const { S, a0 } = await run();
  const obs = ok(await Q.act(S, person("observer", "oli"), "open", { text: "Is there a second archive?", why: "watching" })).q!;
  const n = obs.slice(2);
  for (const name of [obs, `question:${n}`, n, `Q${n}`]) {
    refused(await L.openLead(a0, { title: "Look for it", why: "w", answers: [name], take: true, proposition: "p", negation: "n", routes: ROUTE }), /is proposed and waits for the operator's triage/);
  }
  // Nor may the operator direct work at it before it is admitted.
  refused(await L.openLead({ sandboxRoot: S, agentId: "operator" }, { title: "List archives", why: "directive", answers: [`question:${n}`], product: "a list", acceptance: "every archive" }), /is proposed/);
  // A withdrawn goal question, by any name.
  ok(await Q.act(S, operator, "withdraw", { q: "Q-2", why: "the client dropped it" }));
  for (const name of ["Q-2", "question:2", "2", "Q2"]) refused(await L.openLead(a0, { title: "t", why: "w", answers: [name] }), /was withdrawn/);
  // An admitted question is work by any name.
  ok(await Q.act(S, operator, "scope", { q: obs, scope: "in_scope", why: "it matters" }));
  ok(await L.openLead(a0, { title: "Look for it", why: "w", answers: [`question:${n}`], take: true, proposition: "there is a second archive", negation: "there is none", routes: ROUTE }));
});

// --- 2: a directive is not signed ---------------------------------------------------------------------

test("a directive with --sign is refused, and nothing is recorded as signed that was not signed", async () => {
  const { S, base } = await run();
  const { home, pass } = await enrolled("ana", base);
  const q = String((await QC.operatorAct(S, "open", { text: "Where did the archive come from?", why: "provenance", objective: "O-1" }, { as: "ana" }, home)).q);
  const before = (await L.leadsSnapshot(S)).state.leads.size;
  const r = await QC.operatorDirective(S, { q, title: "List the mail", why: "directive", product: "a table", acceptance: "every mail" }, { as: "ana", sign: true, secret: Buffer.from(pass) }, home);
  refused(r as { ok: boolean }, /a directive is not signed/);
  assert.equal((await L.leadsSnapshot(S)).state.leads.size, before, "no lead was opened");
  // Unsigned, it is the person's claim.
  const d = await QC.operatorDirective(S, { q, title: "List the mail", why: "directive", product: "a table", acceptance: "every mail" }, { as: "ana" }, home);
  assert.equal(d.ok, true, String(d.reason));
  assert.match((await L.leadsSnapshot(S)).state.leads.get(String(d.lead))!.origin, /claimed/);
  assert.doesNotMatch((await L.leadsSnapshot(S)).state.leads.get(String(d.lead))!.origin, /signed/);
  // And the admission refuses a signed actor whatever calls it.
  const who = QC.actorFor({ as: "ana", sign: true }, home) as { actor: Q.Actor };
  refused((await QC.admitDirective(S, { actor: who.actor, q, title: "t", why: "w", product: "p", acceptance: "a" })) as { ok: boolean }, /not signed/);
});

// --- 3: a signed act and its effects ----------------------------------------------------------------

test("a signed act carries its signature on its own event; a signed-labelled act without one fails verification and is refused at commit", async () => {
  const { S, base } = await run();
  const { home, pass } = await enrolled("ana", base);
  const r = await QC.operatorAct(S, "open", { text: "Was the archive sent twice?", why: "two copies", objective: "O-1" }, { as: "ana", sign: true, secret: Buffer.from(pass) }, home);
  assert.equal(r.ok, true, String(r.reason));
  const { events } = await Q.readQuestionEvents(S);
  const opened = events.find((e) => e.ev === "open" && e.q === r.q)!;
  assert.ok(opened.signature, "the act's own event carries the signature");
  assert.equal(events.filter((e) => e.ev === "sign").length, 0, "no separate sign event to lose in a crash");
  assert.deepEqual((await QC.verifySignedActs(S, { home })).map((x) => [x.q, x.person, x.state]), [[r.q, "ana", "unchecked"]]);
  // A torn write, or a forger: an act that says it is signed, with no signature.
  const who = QC.actorFor({ as: "ana", sign: true }, home) as { actor: Q.Actor };
  const prepared = await Q.prepareAct(S, who.actor, "open", { text: "Was the archive printed?", why: "paper", objective: "O-1" });
  assert.ok(prepared.ok);
  if (!prepared.ok) return;
  refused(await Q.commitAct(S, prepared.prepared), /says it is signed carries its signature/);
  await appendRaw(S, { by: "operator", ev: "open", q: "Q-9", rev: 1, act: prepared.prepared.act, origin: prepared.prepared.origin, decided: { scope: "in_scope", scope_why: "forged", section: "9" } });
  const checked = await QC.verifySignedActs(S, { home });
  const forged = checked.find((x) => x.q === "Q-9");
  assert.equal(forged?.state, "bad");
  assert.match(forged?.detail ?? "", /says it is signed and carries no signature/);
  const cli = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "questions-cli.ts"), "verify", S, "--json"], { encoding: "utf8", env: { ...process.env, DFIRSWARM_HOME: home, SWARM_SIGNERS_HOME: home } });
  assert.equal(cli.status, 1, cli.stdout + cli.stderr);
});

test("a withdrawal whose process died before its leads were closed is made good at the next header", async () => {
  const { S, a0, a1 } = await run();
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Did the user print the archive?", why: "paper", objective: "O-1" })).q!;
  const l = ok(await L.openLead(a1, { title: "Read the spool", why: "printing", answers: [q], take: true, proposition: "it was printed", negation: "it was not", routes: ROUTE })).lead;
  // The withdraw event is on the chain; the process died before anything else.
  const prepared = await Q.prepareAct(S, person("analyst", "ana"), "withdraw", { q, why: "the client withdrew the claim" });
  assert.ok(prepared.ok);
  if (!prepared.ok) return;
  await appendRaw(S, { by: "operator", ev: "withdraw", q, rev: 1, act: prepared.prepared.act, origin: prepared.prepared.origin });
  assert.equal((await L.leadsSnapshot(S)).state.leads.get(l.id)!.closed, null, "the crash left the lead open");
  refused(await Q.act(S, person("analyst", "ana"), "withdraw", { q, why: "again" }), /was withdrawn/);
  await L.leadsDigest(a0, { mark: false });
  const closed = (await L.leadsSnapshot(S)).state.leads.get(l.id)!.closed;
  assert.deepEqual([closed?.disposition, closed?.ref], ["withdrawn", q]);
  // Idempotent: the next header closes nothing twice.
  await L.leadsDigest(a0, { mark: false });
  assert.equal((await L.leadsSnapshot(S)).state.events.filter((e) => e.ev === "close" && e.lead === l.id).length, 1);
});

// --- 4: after the done ------------------------------------------------------------------------------

test("admitting a proposed question after the done, and amending one into new work after it, are follow-ups, not this run's work", async () => {
  const { S, a0 } = await run();
  const obs = ok(await Q.act(S, person("observer", "oli"), "open", { text: "Is there a second archive?", why: "watching", objective: "O-1" })).q!;
  const own = ok(await Q.act(S, operator, "open", { text: "When was the archive made?", why: "timeline" })).q!;
  const now = (await P.stateRevision(S)).revision;
  assert.equal((await P.markDone(a0, { reason: "finished", outputFile: "work/report.md", revision: now })).terminate, true);
  const admitted = ok(await Q.act(S, person("examiner", "eve"), "scope", { q: obs, scope: "in_scope", why: "late, but it matters" }));
  assert.equal(admitted.after_done, true, "a durable follow-up receipt");
  const amended = ok(await Q.act(S, operator, "amend", { q: own, expected_rev: 1, text: "When was the archive made, in UTC?" }));
  assert.equal(amended.after_done, true);
  const snap = await Q.questionsSnapshot(S);
  assert.deepEqual([snap.state.questions.get(obs)!.after_done, snap.state.questions.get(own)!.after_done], [true, true]);
  const g = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.deepEqual([...(g.register?.after_done ?? [])].sort(), [obs, own].sort());
  assert.ok(!g.defects.some((d) => [obs, own].includes((d as { question?: string }).question ?? "")));
  assert.deepEqual(await Q.deliverPending(S), [], "a finished run delivers nothing");
});

// --- 5: a lead opened from a finding ------------------------------------------------------------------

test("a withdrawal sends a lead opened from a finding (origin E-n) to triage, not to a withdrawn close", async () => {
  const { S, a1 } = await run();
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Was the archive mailed?", why: "claim", objective: "O-1" })).q!;
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "A mail names the archive", source: "mail store", evidence: "the header", refs: ["unresolved:the fixture has no store object"], answers: [q] } as P.LedgerInput);
  assert.ok(f.ok, (f as { reason?: string }).reason);
  if (!f.ok) return;
  // record(kind=finding, opens=[…]) opens its follow-up with origin E-<seq>.
  const l = ok(await L.openLead(a1, { title: "Follow the mail", why: "the finding", answers: [q], take: true, origin: `E-${f.entry.seq}`, proposition: "it was mailed", negation: "it was not", routes: ROUTE })).lead;
  const w = ok(await Q.act(S, person("analyst", "ana"), "withdraw", { q, why: "the client withdrew it" }));
  assert.deepEqual(w.triaged, [l.id]);
  assert.deepEqual(w.closed_leads, []);
  assert.equal((await L.leadsSnapshot(S)).state.leads.get(l.id)!.closed, null);
  const item = (await Q.questionsSnapshot(S)).state.triage.find((t) => t.lead === l.id);
  assert.deepEqual(item?.entries, [f.entry.seq]);
});

// --- 6: an answer's revision --------------------------------------------------------------------------

test("an answer is bound to the revision it answers: a revision-1 answer after an amendment is refused, question_rev is hashed, and an unchanged answer is reaffirmed for the new revision", async () => {
  const { S, a0 } = await run();
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Where did the archive come from?", why: "origin", objective: "O-1" })).q!;
  const section = `question:${q.slice(2)}`;
  const f = await P.recordEntry(a0, { kind: "finding", ...F, value: "The archive came by mail", source: "mail store", evidence: "the header", refs: ["unresolved:the fixture has no store object"], answers: [q] } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  const answer = { kind: "answer", section, value: "By mail", reasoning: `E-${f.entry.seq} shows it`, contrary_none_why: "no other route left a trace", ...A } as const;
  const first = await P.recordEntry(a0, { ...answer, question_rev: 1 } as P.LedgerInput);
  assert.ok(first.ok, (first as { reason?: string }).reason);
  if (!first.ok) return;
  assert.equal(first.entry.question_rev, 1);
  // The analyst amends; an agent that read revision 1 answers after.
  ok(await Q.act(S, person("analyst", "ana"), "amend", { q, expected_rev: 1, text: "Where did the archive come from, and when?" }));
  let ctx = await Q.viewContext(S);
  assert.deepEqual([Q.viewQuestion(ctx.questions.state.questions.get(q)!, ctx).answer?.stale, Q.viewQuestion(ctx.questions.state.questions.get(q)!, ctx).answer?.question_rev], [true, 1]);
  refused(await P.recordEntry(a0, { ...answer, value: "By mail, on the first day", supersedes: first.entry.seq, question_rev: 1 } as P.LedgerInput), /is at revision 2, amended since the revision 1 this answers/);
  refused(await P.recordEntry(a0, { ...answer, value: "By mail, on the first day", supersedes: first.entry.seq } as P.LedgerInput), /was amended to revision 2: say which revision this answers/);
  refused(await P.recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", refs: ["unresolved:x"], question_rev: 2 } as P.LedgerInput), /an answer's|question_rev/);
  // The same words, reaffirmed for revision 2: a correction that says which revision it answers.
  const again = await P.recordEntry(a0, { ...answer, supersedes: first.entry.seq, question_rev: 2 } as P.LedgerInput);
  assert.ok(again.ok, (again as { reason?: string }).reason);
  ctx = await Q.viewContext(S);
  assert.equal(Q.viewQuestion(ctx.questions.state.questions.get(q)!, ctx).answer?.stale, false);
  // question_rev is in the chained core.
  const text = await readFile(join(S, P.LEDGER_ENTRIES), "utf8");
  assert.equal(P.verifyLedgerChain(text).ok, true);
  assert.equal(P.verifyLedgerChain(text.replace('"question_rev":2', '"question_rev":1')).ok, false);
});

// --- 8, 9, 10: signatures -----------------------------------------------------------------------------

test("a signature is attributed to the person the signed act names, checked against this install's enrolment; a register naming the key for someone else fails verification", async () => {
  const { S, base } = await run();
  const ana = await enrolled("ana", base);
  const r = await QC.operatorAct(S, "open", { text: "Was the archive copied to a stick?", why: "usb", objective: "O-1" }, { as: "ana", sign: true, secret: Buffer.from(ana.pass) }, ana.home);
  assert.equal(r.ok, true, String(r.reason));
  // Another install where ana is enrolled with another key: the mapping fails.
  const other = await enrolled("ana", base);
  const elsewhere = (await QC.verifySignedActs(S, { home: other.home })).find((x) => x.q === r.q)!;
  assert.equal(elsewhere.state, "wrong-principal");
  assert.match(elsewhere.detail, /enrolled on this install with key/);
  // An allowed-signers register that lists ana's key under eve: the command fails.
  const allowed = join(base, "allowed_signers");
  await writeFile(allowed, `${allowedSignersLine({ ...ana.person, principal: "eve" })}\n`);
  const cli = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "questions-cli.ts"), "verify", S, "--allowed-signers", allowed, "--json"], { encoding: "utf8", env: { ...process.env, DFIRSWARM_HOME: ana.home, SWARM_SIGNERS_HOME: ana.home } });
  const out = JSON.parse(cli.stdout.trim().split("\n").at(-1) ?? "{}") as { ok?: boolean; signed?: Array<{ state: string }> };
  assert.equal(out.signed?.[0]?.state, "wrong-principal");
  assert.equal(out.ok, false);
  assert.equal(cli.status, 1);
  // The envelope's person rewritten to eve, the chain made consistent again: still ana's act, and it fails.
  await rewriteEvent(
    S,
    (e) => Boolean(e.signature),
    (e) => {
      (e.signature as Record<string, unknown>).person = "eve";
    },
  );
  assert.equal(Q.verifyQuestionChain(await readFile(join(S, Q.QUESTIONS_LOG), "utf8")).ok, true);
  const tampered = (await QC.verifySignedActs(S, { home: ana.home })).filter((x) => x.q === r.q);
  assert.deepEqual(tampered.map((x) => [x.person, x.state]), [["ana", "bad"]]);
  assert.match(tampered[0].detail, /the signature names eve/);
  const snap = await Q.questionsSnapshot(S);
  assert.deepEqual(snap.state.questions.get(String(r.q))!.signed.map((s) => s.person), ["ana"], "the register names the signed act's person");
});

test("a signed amendment that repeats the text and changes the neutral formulation verifies: the signed act is kept as it was signed", async () => {
  const { S, base } = await run();
  const ana = await enrolled("ana", base);
  const q = String((await QC.operatorAct(S, "open", { text: "Was the archive altered?", why: "integrity", objective: "O-1" }, { as: "ana" }, ana.home)).q);
  const r = await QC.operatorAct(S, "amend", { q, expected_rev: 1, text: "Was the archive altered?", neutral: "Did the archive's content change after it arrived?" }, { as: "ana", sign: true, secret: Buffer.from(ana.pass) }, ana.home);
  assert.equal(r.ok, true, String(r.reason));
  assert.equal(r.rev, 1, "the same text makes no new revision");
  const checked = (await QC.verifySignedActs(S, { home: ana.home })).filter((x) => x.q === q);
  assert.deepEqual(checked.map((x) => x.state), ["unchecked"]);
  const amend = (await Q.readQuestionEvents(S)).events.find((e) => e.ev === "amend")!;
  assert.equal(amend.act?.text, "Was the archive altered?", "the act as signed, text included");
  assert.equal((amend.decided as { revision?: boolean }).revision, false);
});

// --- 11, 12: delivery -----------------------------------------------------------------------------

test("a board post that failed stays pending with no deliver event, and is made at the next delivery", { skip: process.getuid?.() === 0 ? "root ignores the directory's mode" : false }, async () => {
  const { S } = await run();
  const main = join(S, "threads", "main");
  await mkdir(main, { recursive: true });
  const q = ok(await Q.act(S, operator, "open", { text: "Was the archive opened on the laptop?", why: "second machine", objective: "O-1" })).q!;
  await chmod(main, 0o555);
  let first: Q.Delivery[];
  try {
    first = await Q.deliverPending(S);
  } finally {
    await chmod(main, 0o755);
  }
  assert.equal(first.length, 1);
  assert.equal(first[0].post, null);
  assert.match(first[0].pending ?? "", /the board post was not made/);
  assert.equal((await Q.questionsSnapshot(S)).state.questions.get(q)!.delivered.size, 0, "no deliver event for a post that was not made");
  const second = await Q.deliverPending(S);
  assert.equal(second[0]?.q, q);
  assert.ok(second[0]?.post);
  assert.equal((await Q.questionsSnapshot(S)).state.questions.get(q)!.delivered.get(1)?.post?.id, second[0].post!.id);
});

test("a delivery finds its own post by an exact key, never by words another post happens to contain", async () => {
  const { S } = await run();
  await Q.seedRegister(S);
  const next = `Q-${(await Q.questionsSnapshot(S)).state.questions.size + 1}`;
  // An earlier post by the same person quoting the words a later question's delivery would carry.
  const planted = await P.registerPost(S, { from: "analyst:tester@lab", to: "all", tag: "question", body: `About QUESTION ${next} (revision 1) from the operator: not the question itself.`, key: "note:planted" });
  const q = ok(await Q.act(S, operator, "open", { text: "Was the archive printed?", why: "paper", objective: "O-1" })).q!;
  assert.equal(q, next);
  const d = await Q.deliverPending(S);
  assert.ok(d[0]?.post);
  assert.notEqual(d[0].post!.id, planted.id, "the planted post is not the delivery");
  const all = await posts(S);
  assert.equal(all.length, 2);
  assert.match(all[1].text, new RegExp(`^key: ${Q.postKey(q, 1)}$`, "m"));
  // Found again by its key: no second post.
  const again = await P.registerPost(S, { from: "analyst:tester@lab", to: "a0", tag: "question", body: "x", key: Q.postKey(q, 1) });
  assert.equal(again.id, d[0].post!.id);
  assert.equal((await posts(S)).length, 2);
});

// --- 13: clarification requests ------------------------------------------------------------------

test("a clarification committed without its operator request, or without its answer's post, is published from the chain once", async () => {
  const { S, a0, a2 } = await run();
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Was the archive handled by the admin?", why: "access", objective: "O-1" })).q!;
  // The ask is committed; the process dies before the operator's request is written.
  ok(await Q.act(S, agent("a2"), "clarify_ask", { q, what: "admin: the domain admin, or the local one?" }));
  const requests = async () => (await readFile(join(S, L.OPERATOR_REQUESTS), "utf8").catch(() => "")).split("\n").filter((l) => l.includes('"kind":"clarification"'));
  assert.equal((await requests()).length, 0);
  await L.leadsDigest(a0, { mark: false });
  assert.equal((await requests()).length, 1, "derived from the chain at the next header");
  await L.leadsDigest(a0, { mark: false });
  assert.equal((await requests()).length, 1, "and written once");
  // The answer is committed; its post is not made yet.
  ok(await Q.act(S, person("analyst", "ana"), "clarify_answer", { q, clarify: "C-1", answer: "the local administrator" }));
  const answered = async () => (await posts(S)).filter((p) => p.text.includes("CLARIFICATION C-1"));
  await L.leadsDigest(a0, { mark: false });
  assert.equal((await answered()).length, 1);
  assert.match((await answered())[0].text, /^to: a2$/m);
  await Q.deliverPending(S);
  assert.equal((await answered()).length, 1, "posted once");
  void a2;
});

// --- 14: the hub admits ---------------------------------------------------------------------------

test("with a hub running, an operator's act and a directive are admitted by the hub on its admin socket; with none, by the CLI under the lock", async () => {
  const { S } = await run();
  const dir = await mkdtemp(join(tmpdir(), "dfh-"));
  dirs.push(dir);
  const hub = new Hub({ sandbox: S, dir, agents: ["a0", "a1", "a2"], tokens: { a0: "t0", a1: "t1", a2: "t2", system: "ts" }, collector: join(dir, "no-collector.sock"), backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false", forging: false });
  await hub.start();
  closers.push(() => hub.stop());
  const sock = hub.adminSocket();
  const r = await QC.operatorAct(S, "open", { text: "Was the archive encrypted?", why: "crypto", objective: "O-1" }, {}, undefined, { hubAdmin: sock });
  assert.equal(r.ok, true, String(r.reason));
  assert.equal(r.admitted_by, "hub");
  assert.equal((await Q.questionsSnapshot(S)).state.questions.get(String(r.q))?.text, "Was the archive encrypted?");
  const d = await QC.operatorDirective(S, { q: String(r.q), title: "Test the headers", why: "directive", product: "a table", acceptance: "every file" }, {}, undefined, { hubAdmin: sock });
  assert.equal(d.ok, true, String(d.reason));
  assert.equal(d.admitted_by, "hub");
  // The hub admits only its own run's acts.
  const other = await QC.hubAdmission(sock, { op: "question", sandbox: dir, request: { actor: operator, ev: "open", input: { text: "x", why: "y" } } });
  assert.ok(other.reached);
  if (other.reached) assert.match(String(other.answer.reason), /this hub serves another run/);
  // No hub listening: the CLI admits it itself, and says so.
  const local = await QC.operatorAct(S, "open", { text: "Was the archive signed?", why: "provenance", objective: "O-1" }, {}, undefined, { hubAdmin: join(dir, "gone.sock") });
  assert.equal(local.ok, true, String(local.reason));
  assert.equal(local.admitted_by, "cli, no hub running");
});

// --- 15: seeding ------------------------------------------------------------------------------------

test("a goal question is seeded whole: its later paragraphs, its conditions and its sub-questions, up to the next question or section", async () => {
  const goal = GOAL.replace(
    "1. Which account created the archive?\n2. Was the archive opened on another machine?",
    ["1. Which account created the archive?", "", "   Consider the local accounts only; the domain is out of scope.", "   - which of them was logged on at the time", "   - whether it was an interactive logon", "2. Was the archive opened on another machine?", "", "   Name the machine."].join("\n"),
  );
  const { S } = await run(goal);
  await Q.seedRegister(S);
  const snap = await Q.questionsSnapshot(S);
  const q1 = snap.state.questions.get("Q-1")!.text;
  assert.match(q1, /^Which account created the archive\?\n\n {3}Consider the local accounts only; the domain is out of scope\.\n {3}- which of them was logged on at the time\n {3}- whether it was an interactive logon$/);
  assert.equal(snap.state.questions.get("Q-2")!.text, "Was the archive opened on another machine?\n\n   Name the machine.");
});

// --- 16: a directive is framed at its first claim -------------------------------------------------

test("an unframed directive under a person's question is framed by its first claim: proposition and negation, kept on the lead", async () => {
  const { S, a1, a2 } = await run();
  const q = ok(await Q.act(S, person("examiner", "eve"), "open", { text: "Was the archive copied to a stick?", why: "usb" })).q!;
  const dir = ok(await L.openLead({ sandboxRoot: S, agentId: "operator" }, { title: "List the USB devices", why: "directive", answers: [q], product: "a table of devices", acceptance: "every device" })).lead;
  refused(await L.claimLead(a1, dir.id), new RegExp(`${dir.id} is a directive under ${q}, a person's question no lead has framed yet`));
  refused(await L.claimLead(a1, dir.id, { proposition: "a stick was used" }), /proposition and negation come together/);
  refused(await L.claimLead(a1, dir.id, { proposition: "a stick received the archive", negation: "no removable device received it" }), /no route plan yet/);
  const c = ok(await L.claimLead(a1, dir.id, { proposition: "a stick received the archive", negation: "no removable device received it", routes: ROUTE })).lead;
  assert.deepEqual([c.holder, c.proposition, c.negation], ["a1", "a stick received the archive", "no removable device received it"]);
  const kept = (await L.leadsSnapshot(S)).state.leads.get(dir.id)!;
  assert.equal(kept.proposition, "a stick received the archive", "kept on the lead's chain");
  // Framed: a later claim (after a release) needs nothing more.
  ok(await L.releaseLead(a1, dir.id, { why: "handing over" }));
  ok(await L.claimLead(a2, dir.id));
});

// --- 17: a withdrawn goal question ----------------------------------------------------------------

test("a withdrawn goal question is not required by the answers check or the finish line; the goal keeps it and the register says why", async () => {
  const { S } = await run();
  const before = await checkLedgerAnswers(S, ["question:2"]);
  assert.equal(before.ok, false);
  ok(await Q.act(S, operator, "withdraw", { q: "Q-2", why: "the client dropped the second machine" }));
  const r = await checkLedgerAnswers(S, ["question:2"]);
  assert.equal(r.ok, true, r.lines.join("\n"));
  assert.match(r.withdrawn["question:2"] ?? "", /Q-2 was withdrawn by .*: the client dropped the second machine/);
  assert.equal(r.outcomes["question:2"], undefined);
  const snap = await L.leadsSnapshot(S);
  assert.deepEqual(L.caseQuestions(snap), ["1"]);
  assert.deepEqual(snap.goal.questions, ["1", "2"], "the goal keeps it");
  const g = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.deepEqual(g.questions.find((x) => x.id === "2"), { id: "2", outcome: "withdrawn", blocks: [] });
});

