#!/usr/bin/env node
/**
 * The question register from the operator's side (extensions/questions.ts):
 * the CLI and, through `swarm.sh question`, the console.
 *
 *   questions-cli.ts seed <sandbox>                         put the goal's questions and objectives on the chain
 *   questions-cli.ts add <sandbox> --text T --why W [--presumes P] [...]
 *                                                           a person's question (analyst, reviewer, observer, examiner);
 *                                                           --presumes: what it takes as happened, tested first
 *   questions-cli.ts list <sandbox> [--json]                every question: triage and clarifications first
 *   questions-cli.ts show <sandbox> Q-n [--json]            one question whole, with its history and signatures checked
 *   questions-cli.ts amend <sandbox> Q-n --expect-rev N [--text T] [--why W] [--neutral T] [--presumes P] [...]
 *   questions-cli.ts priority <sandbox> Q-n urgent|normal [--reason R]
 *   questions-cli.ts scope <sandbox> Q-n|L-n in_scope|excluded --why W
 *   questions-cli.ts withdraw <sandbox> Q-n --why W
 *   questions-cli.ts clarify-reply <sandbox> Q-n C-n TEXT
 *   questions-cli.ts accept <sandbox> Q-n --as bounded|not_determinable --why W --expect-rev N
 *                                                           (the person, when named, is a second --as ID)
 *   questions-cli.ts direct <sandbox> (--question Q-n | --new-question T --new-why W) --title T --why W --product P --acceptance A
 *                                                           (never --sign: a directive is not signed)
 *   questions-cli.ts premise <sandbox> add --text T [--locator L] [--class given|supplied_assertion|proposition_under_test]
 *                                    [--entity E …] [--time FROM..TO …] [--for-question Q-n …] [--why W]
 *   questions-cli.ts premise <sandbox> revise P-n --expect-rev N --why W [--text T] [--locator L] [scope flags | --no-scope]
 *   questions-cli.ts premise <sandbox> admit P-n --as given|supplied_assertion --why W
 *   questions-cli.ts premise <sandbox> withdraw P-n --why W
 *   questions-cli.ts premise <sandbox> list [--json] | show P-n [--json]
 *                                                           the premise register (extensions/premises.ts), on the
 *                                                           same chain; the person, when named on admit, is a second --as ID
 *   questions-cli.ts deliver <sandbox>                      publish what was committed and not yet published
 *   questions-cli.ts verify <sandbox> [--json] [--allowed-signers FILE] [--ca FILE]
 *                                                           every signed act, its signature checked; fails on
 *                                                           bad, wrong-principal, or a signed act with none
 *
 * Every act takes [--as ID] (an enrolled person: a claim), [--sign] (the act
 * signed with that person's enrolled key, namespace dfirswarm-question; the
 * passphrase or PIN on the terminal, or on the descriptor --secret-fd N
 * names, never in argv or the environment) and [--via cli|console]. Without
 * --as the act is the OS account's on this host, not enrolled, with the
 * operator's authority, and is never promoted.
 *
 * [--hub-admin SOCKET] names the run's hub admin socket (swarm.sh passes it
 * while the hub is up): the act, prepared and signed here, is admitted by the
 * hub, the register's one writer. With no hub listening there, the act is
 * admitted here under the registers' lock; `admitted_by` says which.
 *
 * An act prints one JSON line once the chain holds it (the acknowledgement
 * comes after the write, never before), then what its delivery did.
 */
import { createHash } from "node:crypto";
import { connect } from "node:net";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { hostname, tmpdir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as PM from "../extensions/premises.ts";
import * as Q from "../extensions/questions.ts";
import { hasTty, readFromTty, readSecretFromFd, wipe } from "./secret-io.ts";
import { fingerprintOf, keyNeeds, loadPerson, signAs, verifyAs, type Person, type PersonKey, type SignatureState } from "./signers.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** How an act is made: who (--as), signed or not, and where the secret comes from (a descriptor, the terminal, or a caller in this process). */
export type Flags = { as?: string; sign?: boolean; secretFd?: number; via?: "cli" | "console"; secret?: Buffer | null };

/** Who acts: the enrolled person named (a claim, or signed), or this host's OS account, not enrolled, as the operator. */
export function actorFor(flags: Flags, home?: string): { actor: Q.Actor; person: Person | null } | { why: string } {
  const os_user = (() => {
    try {
      return userInfo().username;
    } catch {
      return process.env.USER ?? "unknown";
    }
  })();
  const host = hostname();
  const via = flags.via ?? (process.env.SWARM_OPERATOR_VIA === "console" ? "console" : "cli");
  if (!flags.as) {
    if (flags.sign) return { why: "--sign signs with an enrolled person's key: name them with --as ID" };
    return { actor: { kind: "human", role: "operator", person: `${os_user}@${host}`, enrolled: false, os_user, host, via, identity: "claimed" }, person: null };
  }
  const r = loadPerson(flags.as, home);
  if ("why" in r) return { why: `--as ${flags.as}: ${r.why}` };
  const p = r.person;
  return {
    actor: { kind: "human", role: p.role, person: p.id, name: p.name, enrolled: true, os_user, host, via, identity: flags.sign ? "signed" : "claimed", ...(flags.sign ? { fingerprint: p.key.fingerprint } : {}) },
    person: p,
  };
}

/** Sign an act's statement with the person's key: the secret from the descriptor named, or the terminal. */
export async function signStatement(person: Person, statement: string, flags: Flags): Promise<Q.ActSignature | { why: string; wrongSecret?: boolean }> {
  const needs = keyNeeds(person);
  let secret: Buffer | null = null;
  const dir = mkdtempSync(join(tmpdir(), "dfs-question-"));
  try {
    if (flags.secret) secret = Buffer.from(flags.secret);
    else if (flags.secretFd !== undefined) secret = readSecretFromFd(flags.secretFd);
    else if (needs.secret) {
      if (!hasTty()) return { why: `${person.name}'s key needs its ${needs.secret === "passphrase" ? "passphrase" : "PIN"}, and there is no terminal to ask on: run it at a terminal, or --secret-fd N` };
      secret = await readFromTty(needs.secret === "pin" ? "The e-signature token's PIN (not shown): " : needs.secret === "fido-pin" ? "The FIDO key's PIN (not shown): " : "The key's passphrase (not shown): ");
    }
    if (needs.touch) process.stderr.write("Touch your key now, every time it blinks.\n");
    const file = join(dir, "statement.json");
    writeFileSync(file, statement);
    const signed = signAs(person, file, Q.QUESTION_NAMESPACE, secret, { dropAgent: flags.via === "console" });
    if (!signed.ok) return { why: `the act was not signed, so nothing was recorded: ${signed.why}`, ...(signed.wrongSecret ? { wrongSecret: true } : {}) };
    const checked = verifyAs(person, file, signed.sig, Q.QUESTION_NAMESPACE);
    if (checked.state === "bad") return { why: `the signature made does not verify under ${person.name}'s enrolled key: ${checked.detail}` };
    return {
      person: person.id,
      format: signed.format,
      key_kind: person.key.kind,
      fingerprint: person.key.fingerprint,
      principal: person.principal,
      ...(person.key.kind !== "pkcs11" ? { public_key: person.key.public } : {}),
      statement_sha256: sha256(statement),
      sig_b64: readFileSync(signed.sig).toString("base64"),
    };
  } finally {
    wipe(secret);
    rmSync(dir, { recursive: true, force: true });
  }
}

async function runId(sandbox: string): Promise<string> {
  return (await P.readTeam(sandbox).catch(() => null))?.swarm_id ?? "";
}

// --- admission: the hub is the register's writer ------------------------------------------------

/** An operator's act as it is handed to the admission: who acts, what they said, and their signature over its statement when they signed. */
export type AdmissionRequest = { actor: Q.Actor; ev: Q.ActKind; input: Q.ActInput; signature?: Q.ActSignature };

/** A directive as it is handed to the admission: the question it serves (or one to ask first) and the lead's words. */
export type DirectiveRequest = { actor: Q.Actor; q?: string; question?: { text?: string; why?: string }; title?: string; why?: string; product?: string; acceptance?: string };

/**
 * The admission of an operator's act, where the register is written: the act
 * prepared again from what was said (what is committed is what the admission
 * checked, not what a client computed), a signature checked against that
 * statement before anything is written, the act committed under the
 * registers' lock and only then acknowledged, then delivered. The hub runs
 * this for its admin socket, so it is the register's one writer while it
 * runs; the CLI runs it itself, under the same lock, only when no hub is
 * running (docs/adr/0011).
 */
export async function admitOperatorAct(sandbox: string, req: AdmissionRequest, o: { home?: string } = {}): Promise<Record<string, unknown>> {
  if (!req || typeof req !== "object" || req.actor?.kind !== "human") return { ok: false, reason: "the operator's admission takes a person's act; an agent acts through its own tools" };
  const prepared = await Q.prepareAct(sandbox, req.actor, req.ev, req.input ?? {});
  if (!prepared.ok) return prepared;
  const p = prepared.prepared;
  if (req.signature) {
    const statement = Q.statementOf(p, await runId(sandbox));
    const probe = { v: 1, seq: 0, at: "", by: p.by, ev: p.ev, ...(p.q ? { q: p.q } : {}), act: p.act, origin: p.origin, prev: "", hash: "" } as Q.QuestionEvent;
    const check = checkActSignature(probe, req.signature, statement, o);
    if (FAILED_SIGNATURE.has(check.state)) return { ok: false, reason: `the signature was checked before anything was written, and does not hold (${check.state}: ${check.detail}); nothing was recorded` };
  }
  const r = await Q.commitAct(sandbox, p, req.signature ? { signature: req.signature } : {});
  if (!r.ok) return r;
  // Committed: the acknowledgement may be given. What it publishes follows.
  const out: Record<string, unknown> = { ...r, by: Q.originWords(p.origin) };
  // A premise revised or withdrawn closes the disputes on its earlier revision: the operator requests are reconciled now.
  if (req.ev === "premise_revise" || req.ev === "premise_withdraw") await import("../extensions/requests.ts").then((R) => R.reconcileRequests(sandbox)).catch(() => undefined);
  // A question's attachments are supplied material: each on the ledger as external (docs/adr/0014).
  if ((req.ev === "open" || req.ev === "amend") && p.act.attachments?.length && r.q) out.attachments = await recordAttachments(sandbox, r.q, p.act.attachments, Q.originWords(p.origin)).catch((err: Error) => ({ pending: err.message }));
  if (req.ev === "clarify_answer" && r.q && r.clarify) out.post = await Q.publishClarification(sandbox, r.q, r.clarify).catch((err: Error) => ({ pending: err.message }));
  const delivered = await Q.deliverPending(sandbox).catch((err: Error) => ({ error: err.message }));
  out.delivered = delivered;
  // An acceptance changes how the question stands: its disposition goes on the chain now.
  if (req.ev === "accept") {
    const disposed = await Q.syncDispositions(sandbox).catch(() => [] as string[]);
    if (disposed.length) out.disposed = disposed;
    out.outcome = "an acceptance makes the run examination-limited: the report says what was accepted, by whom, for which revision";
  }
  return out;
}

/**
 * A question's attachments on the ledger as external material (class
 * operator_supplied, docs/adr/0014), each with its provenance: who supplied
 * it, when, for which question, its sha256 and what the case policy lets it
 * be used for. The original evidence (input:, member:) is evidence, not
 * supplied material, and is left; an attachment already recorded as
 * external (material add) is not recorded twice.
 */
export async function recordAttachments(sandbox: string, q: string, attachments: string[], suppliedBy: string): Promise<Array<{ ref: string; entry?: number; skipped?: string; pending?: string }>> {
  const { permittedUse, readCasePolicy } = await import("./case-policy.ts");
  const { resolveRef } = await import("./evidence-store.ts");
  const policy = readCasePolicy(sandbox);
  const ledger = await P.readLedger(sandbox, { raw: true }).catch(() => [] as P.LedgerEntry[]);
  const known = new Set<string>();
  for (const e of ledger) {
    if (e.kind !== "external") continue;
    for (const r of e.refs ?? []) {
      known.add(r.trim());
      const imp = /^import:([a-z0-9-]{1,64})/.exec(r.trim());
      if (imp) known.add(`import:${imp[1]}`);
    }
  }
  const out: Array<{ ref: string; entry?: number; skipped?: string; pending?: string }> = [];
  for (const raw of attachments) {
    const ref = raw.trim();
    if (/^(input|member):/.test(ref)) {
      out.push({ ref, skipped: "the original evidence, not supplied material" });
      continue;
    }
    const imp = /^import:([a-z0-9-]{1,64})/.exec(ref);
    if (known.has(ref) || (imp && known.has(`import:${imp[1]}`))) {
      out.push({ ref, skipped: "recorded as external material already" });
      continue;
    }
    if (!/^[a-z0-9]+:/.test(ref)) {
      out.push({ ref, skipped: "a path in the run, not an object: supply it as a file (question add --attach FILE) to seal it" });
      continue;
    }
    const resolved = await resolveRef(sandbox, ref).catch(() => null);
    const sha = resolved && resolved.ok ? resolved.sha256 : undefined;
    const rec = await P.recordExternal(sandbox, {
      value: `Supplied with ${q} as an attachment: ${ref}`,
      source: `an attachment to ${q}, by ${suppliedBy}`,
      evidence: `questions/questions.jsonl (${q}); ${ref}`,
      refs: [ref],
      source_class: "operator_supplied",
      provenance: { supplied_by: suppliedBy, at: new Date().toISOString(), from: `an attachment to ${q}`, ...(sha ? { sha256: sha } : {}), permitted_use: permittedUse(policy, "operator_supplied"), question: q },
    });
    out.push(rec.ok ? { ref, entry: rec.entry.seq } : { ref, pending: rec.reason });
  }
  return out;
}

/**
 * A question's --attach given as a file on this host, outside the run: the
 * file is supplied as material first (scripts/material.ts, class
 * operator_supplied, through the hub when one runs), and the act carries the
 * import it became. A ref or a path in the run is left as it is.
 */
export async function supplyAttachments(sandbox: string, attachments: string[] | undefined, suppliedBy: string, via: string, hubAdmin?: string): Promise<{ ok: true; attachments: string[] | undefined; supplied: string[] } | { ok: false; reason: string }> {
  if (!attachments?.length) return { ok: true, attachments, supplied: [] };
  const { existsSync, statSync } = await import("node:fs");
  const { isAbsolute, relative, resolve: res } = await import("node:path");
  const out: string[] = [];
  const supplied: string[] = [];
  for (const a of attachments) {
    const t = a.trim();
    const abs = res(t);
    const inRun = !relative(res(sandbox), abs).startsWith("..") && !isAbsolute(relative(res(sandbox), abs));
    if (/^[a-z0-9]+:/.test(t) || !existsSync(abs) || inRun || (!isAbsolute(t) && existsSync(res(sandbox, t)))) {
      out.push(t);
      continue;
    }
    const M = await import("./material.ts");
    const req = { mode: "material" as const, path: abs, why: `an attachment to a question, supplied by ${suppliedBy}`, supplied_by: suppliedBy, via };
    const r = await admit(sandbox, hubAdmin, { op: "material", request: req }, () => M.admitMaterial(sandbox, req));
    if (r.ok === false) return { ok: false, reason: `the attachment ${t} could not be supplied: ${String(r.reason ?? "refused")}` };
    const files = (r.files as Array<{ path: string }> | undefined) ?? [];
    const ref = files.length === 1 && statSync(abs).isFile() ? `import:${String(r.import)}/${files[0].path}` : `import:${String(r.import)}`;
    out.push(ref);
    supplied.push(ref);
  }
  return { ok: true, attachments: out, supplied };
}

/**
 * The admission of a directive: an unheld lead under a question, with the
 * product it is to make and what makes it acceptable. Not signed: a directive
 * is the operator's instruction to the team, recorded as the lead register's
 * operator act; a person's signed word goes on the question it serves.
 */
export async function admitDirective(sandbox: string, req: DirectiveRequest, o: { home?: string } = {}): Promise<Record<string, unknown>> {
  if (!req || typeof req !== "object" || req.actor?.kind !== "human") return { ok: false, reason: "a directive is a person's, from the operator's side" };
  if (req.actor.identity === "signed") return { ok: false, reason: "a directive is not signed: sign the question it serves (question add --sign), then direct it without --sign" };
  let q = req.q ? String(req.q) : "";
  let created: Record<string, unknown> | null = null;
  if (!q) {
    if (!req.question?.text) return { ok: false, reason: "a directive is a lead under a question: --question Q-n, or --new-question TEXT --new-why WHY to ask one first" };
  }
  for (const [k, v] of [["--title", req.title], ["--why", req.why], ["--product", req.product], ["--acceptance", req.acceptance]] as const) {
    if (!String(v ?? "").trim()) return { ok: false, reason: `a directive needs ${k} (title and why as a lead has them; product: what it is to produce; acceptance: what makes that product acceptable)` };
  }
  if (!q) {
    created = await admitOperatorAct(sandbox, { actor: req.actor, ev: "open", input: { text: req.question!.text, why: req.question!.why } }, o);
    if (created.ok === false) return created;
    q = String(created.q);
  }
  const origin = Q.originOf(req.actor);
  const r = await L.openLead({ sandboxRoot: sandbox, agentId: "operator" }, { title: req.title, why: req.why, answers: [q], product: req.product, acceptance: req.acceptance, origin: `directive by ${Q.originWords(origin)}` });
  return r.ok ? { ok: true, lead: r.lead.id, q, ...(r.woke ? { woke: r.woke } : {}), ...(created ? { question: created } : {}) } : r;
}

/**
 * One request to the run's hub on its admin socket: `reached` false when no
 * hub listens there (the socket is gone, or nothing accepts on it), so the
 * caller may admit the act itself; once connected, the hub's answer, or a
 * failure that says the act may have been recorded.
 */
export function hubAdmission(socketPath: string, body: Record<string, unknown>, timeoutMs = 60_000): Promise<{ reached: false; why: string } | { reached: true; answer: Record<string, unknown> }> {
  return new Promise((resolveP) => {
    let settled = false;
    let connected = false;
    let answer = "";
    const done = (v: { reached: false; why: string } | { reached: true; answer: Record<string, unknown> }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolveP(v);
    };
    const socket = connect(socketPath);
    socket.setEncoding("utf8");
    socket.setTimeout(timeoutMs, () => done({ reached: true, answer: { ok: false, reason: `the hub took the act and did not answer within ${Math.round(timeoutMs / 1000)} s: questions list shows whether it was recorded` } }));
    socket.on("error", (err: NodeJS.ErrnoException) => {
      if (!connected) done({ reached: false, why: `${err.code ?? "error"}: ${err.message}` });
      else done({ reached: true, answer: { ok: false, reason: `the connection to the hub failed after the act was sent (${err.message}): questions list shows whether it was recorded` } });
    });
    socket.on("connect", () => {
      connected = true;
      socket.write(`${JSON.stringify(body)}\n`);
    });
    socket.on("data", (chunk: string) => {
      answer += chunk;
      const cut = answer.indexOf("\n");
      if (cut < 0) return;
      try {
        done({ reached: true, answer: JSON.parse(answer.slice(0, cut)) as Record<string, unknown> });
      } catch {
        done({ reached: true, answer: { ok: false, reason: "the hub's answer is not JSON" } });
      }
    });
    socket.on("close", () => {
      if (!connected) done({ reached: false, why: "closed before it connected" });
      else done({ reached: true, answer: { ok: false, reason: "the hub closed the connection without an answer: questions list shows whether the act was recorded" } });
    });
  });
}

/**
 * Hand an admission to the run's hub when one runs (its admin socket), or
 * make it here under the registers' lock when none does: `admitted_by` says
 * which.
 */
export async function admit(sandbox: string, hubAdmin: string | undefined, body: Record<string, unknown>, local: () => Promise<Record<string, unknown>>): Promise<Record<string, unknown>> {
  if (hubAdmin) {
    const r = await hubAdmission(hubAdmin, { ...body, sandbox });
    if (r.reached) return { ...r.answer, admitted_by: "hub" };
  }
  return { ...(await local()), admitted_by: "cli, no hub running" };
}

/**
 * One act from the operator's side: prepared here (its words checked before
 * a secret is asked for), signed when asked, then handed to the admission:
 * the run's hub when one runs (`hubAdmin`, its admin socket), else made here
 * under the registers' lock. Acknowledged only once the chain holds it.
 */
export async function operatorAct(sandbox: string, ev: Q.ActKind, input: Q.ActInput, flags: Flags, home?: string, o: { hubAdmin?: string } = {}): Promise<Record<string, unknown>> {
  const who = actorFor(flags, home);
  if ("why" in who) return { ok: false, reason: who.why };
  // An attachment given as a file on this host is supplied as material first; the act carries its import.
  if ((ev === "open" || ev === "amend") && Array.isArray(input.attachments) && input.attachments.length) {
    // The act's other words are checked first: nothing is supplied for an act that would be refused.
    const { attachments: _a, ...rest } = input;
    const first = await Q.prepareAct(sandbox, who.actor, ev, rest);
    if (!first.ok && !(ev === "amend" && /changes something/.test(first.reason))) return first;
    const s = await supplyAttachments(sandbox, input.attachments.map(String), Q.originWords(Q.originOf(who.actor)), who.actor.kind === "human" ? (who.actor.via ?? "cli") : "cli", o.hubAdmin);
    if (!s.ok) return { ok: false, reason: s.reason };
    input = { ...input, attachments: s.attachments };
  }
  const prepared = await Q.prepareAct(sandbox, who.actor, ev, input);
  if (!prepared.ok) return prepared;
  let signature: Q.ActSignature | undefined;
  if (flags.sign) {
    const s = await signStatement(who.person!, Q.statementOf(prepared.prepared, await runId(sandbox)), flags);
    if ("why" in s) return { ok: false, reason: s.why, ...(s.wrongSecret ? { wrong_secret: true } : {}) };
    signature = s;
  }
  const req: AdmissionRequest = { actor: who.actor, ev, input, ...(signature ? { signature } : {}) };
  return admit(sandbox, o.hubAdmin, { op: "question", request: req }, () => admitOperatorAct(sandbox, req, { ...(home ? { home } : {}) }));
}

/** A directive from the operator's side, handed to the admission as an act is (operatorAct). `--sign` is refused: a directive is not signed. */
export async function operatorDirective(sandbox: string, req: Omit<DirectiveRequest, "actor">, flags: Flags, home?: string, o: { hubAdmin?: string } = {}): Promise<Record<string, unknown>> {
  if (flags.sign) return { ok: false, reason: "a directive is not signed: sign the question it serves (question add --sign), then direct it without --sign" };
  const who = actorFor(flags, home);
  if ("why" in who) return { ok: false, reason: who.why };
  const full: DirectiveRequest = { ...req, actor: who.actor };
  return admit(sandbox, o.hubAdmin, { op: "question_direct", request: full }, () => admitDirective(sandbox, full, { ...(home ? { home } : {}) }));
}

// --- signatures --------------------------------------------------------------------------------

export type SignedAct = { q: string | null; act_seq: number; sign_seq: number | null; person: string; fingerprint: string; key_kind: string; state: SignatureState; detail: string };

/** What fails a check of the question register's signatures: a signature that does not verify, or a key a register names for someone else. */
export const FAILED_SIGNATURE: ReadonlySet<string> = new Set(["bad", "wrong-principal"]);

/**
 * One signature over an act on the chain, checked: the act says it is
 * signed; the envelope names the person and key fingerprint the signed act
 * names (the act's origin is inside the statement; the envelope is not); the
 * key it carries has that fingerprint; the person enrolled on this install
 * under that id, when they are, has that key and principal; the statement
 * rebuilt from the chain is the one signed; and the signature verifies.
 */
export function checkActSignature(act: Q.QuestionEvent, s: Q.ActSignature, statement: string, o: { allowedSigners?: string; ca?: string; home?: string } = {}): { state: SignatureState; detail: string } {
  const origin = act.origin ?? { kind: "analyst" as const };
  if (origin.identity !== "signed") return { state: "bad", detail: `the act (event ${act.seq}) does not say it is signed: a signature is carried by the act it signs` };
  if (s.person !== origin.person || s.fingerprint !== origin.fingerprint) {
    return { state: "bad", detail: `the signature names ${s.person} (${s.fingerprint}), the signed act ${origin.person ?? "nobody"} (${origin.fingerprint ?? "no key"}): a signature is attributed to the person the signed act names, with that key` };
  }
  if (sha256(statement) !== s.statement_sha256) return { state: "bad", detail: "the act on the chain is not the statement that was signed" };
  if (s.key_kind !== "pkcs11") {
    const derived = s.public_key ? fingerprintOf(s.public_key) : null;
    if (derived !== s.fingerprint) return { state: "bad", detail: `the key the signature carries has fingerprint ${derived ?? "unread"}, not ${s.fingerprint}, the one the signed act names` };
  }
  // Who that person is on this install: their enrolled key and principal, or none.
  const enrolled = loadPerson(s.person, o.home);
  let key: PersonKey;
  let principal = s.principal;
  let who: string;
  if (!("why" in enrolled)) {
    const p = enrolled.person;
    if (p.key.fingerprint !== s.fingerprint) return { state: "wrong-principal", detail: `${s.person} is enrolled on this install with key ${p.key.fingerprint}, not ${s.fingerprint}, the key this signature carries` };
    if (p.principal !== s.principal) return { state: "wrong-principal", detail: `${s.person} is enrolled on this install as principal ${p.principal}, not ${s.principal}, the one this signature names` };
    key = p.key;
    principal = p.principal;
    who = `the key ${s.person} is enrolled with on this install`;
  } else {
    key = (s.key_kind === "pkcs11"
      ? { kind: "pkcs11", certificate: { sha256: s.fingerprint.replace(/^X509-SHA256:/, "") } }
      : { kind: s.key_kind, public: s.public_key ?? "", path: "", fingerprint: s.fingerprint }) as unknown as PersonKey;
    who = `${s.person} is not enrolled on this install: checked against the key the signature carries`;
  }
  const dir = mkdtempSync(join(tmpdir(), "dfs-question-verify-"));
  try {
    const file = join(dir, "statement.json");
    writeFileSync(file, statement);
    const sig = join(dir, s.format === "cms" ? "statement.json.p7s" : "statement.json.sig");
    writeFileSync(sig, Buffer.from(s.sig_b64, "base64"));
    const v = verifyAs({ key, principal }, file, sig, Q.QUESTION_NAMESPACE, { ...(o.allowedSigners ? { allowedSigners: o.allowedSigners } : {}), ...(o.ca ? { ca: o.ca } : {}) });
    return { state: v.state, detail: `${v.detail}; ${who}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Every signed act on the chain, checked (checkActSignature): each act that
 * carries its signature, each separate sign event (the register's first
 * form), and every act that says it is signed and carries none, which fails.
 */
export async function verifySignedActs(sandbox: string, o: { allowedSigners?: string; ca?: string; home?: string } = {}): Promise<SignedAct[]> {
  const { events } = await Q.readQuestionEvents(sandbox);
  const run = await runId(sandbox);
  const bySeq = new Map(events.map((e) => [e.seq, e]));
  const out: SignedAct[] = [];
  const carried = new Set<number>();
  const row = (act: Q.QuestionEvent | undefined, s: Q.ActSignature | undefined, actSeq: number, signSeq: number | null) => ({
    q: act?.q ?? act?.act?.lead ?? null,
    act_seq: actSeq,
    sign_seq: signSeq,
    // The person the signed act names: never the envelope's word.
    person: act?.origin?.person ?? s?.person ?? "?",
    fingerprint: act?.origin?.fingerprint ?? s?.fingerprint ?? "?",
    key_kind: s?.key_kind ?? "none",
  });
  for (const e of events) {
    if (e.ev === "sign") {
      const target = e.target_seq !== undefined ? bySeq.get(e.target_seq) : undefined;
      if (target && target.hash === e.target_hash) carried.add(target.seq);
      if (!e.signature) {
        out.push({ ...row(target, undefined, e.target_seq ?? 0, e.seq), state: "bad", detail: "a sign event with no signature" });
        continue;
      }
      if (!target || target.hash !== e.target_hash) {
        out.push({ ...row(target, e.signature, e.target_seq ?? 0, e.seq), state: "bad", detail: "the act it names is not on the chain with that hash" });
        continue;
      }
      out.push({ ...row(target, e.signature, target.seq, e.seq), ...checkActSignature(target, e.signature, Q.statementOfEvent(target, run), o) });
    } else if (e.signature) {
      carried.add(e.seq);
      out.push({ ...row(e, e.signature, e.seq, e.seq), ...checkActSignature(e, e.signature, Q.statementOfEvent(e, run), o) });
    }
  }
  for (const e of events) {
    if (e.ev === "sign" || e.origin?.identity !== "signed" || carried.has(e.seq)) continue;
    out.push({ ...row(e, undefined, e.seq, null), state: "bad", detail: "the act says it is signed and carries no signature" });
  }
  return out.sort((a, b) => a.act_seq - b.act_seq || (a.sign_seq ?? 0) - (b.sign_seq ?? 0));
}

// --- reading ----------------------------------------------------------------------------------

function views(ctx: Q.ViewContext): Q.QuestionView[] {
  return Q.questionViews(ctx);
}

function line(v: Q.QuestionView): string {
  const bits = [
    v.scope,
    v.work,
    v.materiality === "background" ? "background" : null,
    v.priority === "urgent" ? `URGENT (${v.priority_reason ?? ""})` : null,
    v.objective ? `objective ${v.objective}` : v.objective_text ? `would add "${v.objective_text}"` : null,
    v.parent ? `follows ${v.parent}` : null,
    v.leading_forms.length ? `leading form ${v.leading_forms.map((f) => `"${f}"`).join(", ")}` : null,
    v.after_done ? "after done: a follow-up" : null,
  ].filter(Boolean);
  const state = v.answer ? `answer E-${v.answer.seq}${v.answer.stale ? ` (STALE: before revision ${v.rev})` : ""}${v.answer.parts?.length ? `; parts: ${PM.partsWords(v.answer.parts)}` : ""}${v.answer.premises?.length ? `; premises: ${PM.citationsWords(v.answer.premises)}` : ""}${v.answer.omitted?.length ? `; a review says it leaves out: ${v.answer.omitted.map((x) => `"${x.part}" (${x.by})`).join(", ")}` : ""}` : "no answer";
  const leads = v.leads.length ? `; leads ${v.leads.map((l) => `${l.id} ${l.status}${l.holder ? ` (${l.holder})` : ""}`).join(", ")}` : "";
  const signed = v.signed.length ? `; ${v.signed.length} signed act(s)` : "";
  return `${v.id} rev ${v.rev} [${bits.join(", ")}] ${v.author}${signed}\n    ${v.text.split("\n").join("\n    ")}\n    why: ${v.why}\n    ${state}${leads}`;
}

/** The premise register in words: each premise whole, with its revisions, class and the answers that cite it. */
export async function premisesText(sandbox: string, id?: string): Promise<string | null> {
  const ctx = await Q.viewContext(sandbox);
  const all = Q.premiseViews(ctx);
  const list = id ? all.filter((p) => p.id === id) : all;
  if (id && !list.length) return null;
  const out: string[] = id ? [] : [`${all.length} premise(s); chain ${ctx.questions.state.chain.ok ? "intact" : `BROKEN at line ${ctx.questions.state.chain.broken_at} (${ctx.questions.state.chain.reason})`}.`];
  for (const p of list) {
    out.push(`${Q.premiseLine(p, p.author)}`);
    for (const r of p.revisions) out.push(`    revision ${r.rev} (${r.origin?.kind === "goal" ? "the goal" : Q.originWords(r.origin)}, ${r.at}): ${r.text}${r.locator ? ` — at ${r.locator}` : ""}; scope ${PM.scopeWords(r.scope)}${r.why && r.rev > 1 ? ` (why revised: ${r.why})` : ""}`);
    if (p.classes.length > 1) out.push(`    class: ${p.classes.map((x) => `${PM.classWords(x.class)} at ${x.at}${x.why ? ` (${x.why})` : ""}`).join(" → ")}`);
    out.push(`    cited by: ${p.cited_by.length ? p.cited_by.map((x) => `E-${x.answer} (${x.section}) ${x.conditional ? "assuming it" : x.stance}${x.refs.length ? ` on ${x.refs.join(", ")}` : ""}${x.current ? "" : ` at revision ${x.rev}`}`).join("; ") : "no standing answer"}`);
    if (p.class === "proposition_under_test" && !p.withdrawn) out.push(`    admit: swarm.sh question <run> premise admit ${p.id} --as given|supplied_assertion --why "…"`);
  }
  return `${out.join("\n")}\n`;
}

/** Every question, what waits on the operator first (the triage, the clarifications), then by origin. */
export async function listText(sandbox: string): Promise<string> {
  const ctx = await Q.viewContext(sandbox);
  const all = views(ctx);
  const s = ctx.questions.state;
  const out: string[] = [];
  out.push(`${all.length} question(s); chain ${s.chain.ok ? `intact, ${s.events.length} events` : `BROKEN at line ${s.chain.broken_at} (${s.chain.reason})`}${ctx.questions.seeded ? "" : "; the goal's questions derived from the goal, not yet on the chain"}.`);
  if (s.objectives.size) out.push("", "OBJECTIVES:", ...[...s.objectives.values()].map((o) => `  ${o.id}: ${o.text}${o.origin && o.origin.kind !== "goal" ? ` (${o.why})` : ""}`));
  if (s.premises.size) {
    const premises = Q.premiseViews(ctx);
    const under = premises.filter((p) => p.class === "proposition_under_test" && !p.withdrawn);
    out.push("", "PREMISES:", ...premises.map((p) => `  ${Q.premiseLine(p, p.author)}`));
    if (under.length) out.push(`  under test until you admit them: ${under.map((p) => `swarm.sh question <run> premise admit ${p.id} --as given|supplied_assertion --why "…"`).join("; ")}`);
  }
  const proposed = all.filter((v) => v.scope === "proposed" && !v.withdrawn);
  const triage = s.triage.filter((t) => !t.resolved);
  if (proposed.length || triage.length) {
    out.push("", "WAITING FOR YOUR TRIAGE:");
    for (const v of proposed) out.push(`  ${line(v)}`, `    admit: swarm.sh question <run> scope ${v.id} in_scope --why "…"   exclude: … scope ${v.id} excluded --why "…"`);
    for (const t of triage) out.push(`  ${t.lead ?? t.q}: ${t.cause}`, `    keep: swarm.sh question <run> scope ${t.lead ?? t.q} in_scope --why "…"   close: … scope ${t.lead ?? t.q} excluded --why "…"`);
  }
  const pending = all.flatMap((v) => v.clarifications.filter((c) => !c.answer).map((c) => ({ v, c })));
  if (pending.length) {
    out.push("", "CLARIFICATIONS WAITING:");
    for (const { v, c } of pending) out.push(`  ${c.id} on ${v.id} from ${c.by} (to ${c.to}): ${c.what}`, `    answer: swarm.sh question <run> clarify-reply ${v.id} ${c.id} "<your answer>"`);
  }
  for (const [name, pick] of [
    ["ASKED BY PEOPLE", (v: Q.QuestionView) => Q.HUMAN_ORIGINS.has(v.origin.kind) && v.scope === "in_scope" && !v.withdrawn],
    ["THE GOAL'S", (v: Q.QuestionView) => v.origin.kind === "goal" && !v.withdrawn],
    ["OPENED BY AGENTS", (v: Q.QuestionView) => v.origin.kind === "agent" && v.scope === "in_scope" && !v.withdrawn],
    ["EXCLUDED", (v: Q.QuestionView) => v.scope === "excluded" && !v.withdrawn],
    ["WITHDRAWN", (v: Q.QuestionView) => Boolean(v.withdrawn)],
  ] as const) {
    const list = all.filter(pick);
    if (!list.length) continue;
    out.push("", `${name}:`);
    for (const v of list) out.push(`  ${line(v)}`);
  }
  return `${out.join("\n")}\n`;
}

export async function showText(sandbox: string, id: string): Promise<string | null> {
  const ctx = await Q.viewContext(sandbox);
  const q = Q.findQuestion(ctx.questions, id);
  if (!q) return null;
  const v = Q.viewQuestion(q, ctx);
  const signed = (await verifySignedActs(sandbox)).filter((x) => x.q === v.id);
  const out: string[] = [line(v)];
  out.push(`    asked by ${v.author} at ${v.opened_at}; scope: ${v.scope} (${v.scope_why})`);
  for (const r of v.revisions) out.push(`    revision ${r.rev} (${Q.originWords(r.origin)}, ${r.at}): ${r.text}${r.why ? ` (why amended: ${r.why})` : ""}`);
  if (v.neutral) out.push(`    neutral formulation (${Q.originWords(v.neutral.origin)}): ${v.neutral.text}`);
  if (v.expects) out.push(`    expects: ${v.expects}`);
  if (v.completeness) out.push(`    asks for a complete set (${v.completeness_by === "asker" ? "the asker says so" : "by its words"}): an established or partial answer rests on a coverage record naming the areas searched`);
  if (v.presumption) out.push(`    presumes ${PM.presumptionWords(v.presumption)}: its answer tests that premise first`);
  if (v.hints.length) out.push(`    hints: ${v.hints.map((h) => `${h.ref}${h.value ? ` (says: ${h.value})` : ""}`).join("; ")}`);
  if (v.attachments.length) out.push(`    attachments: ${v.attachments.join(", ")}`);
  if (v.suggested_to) out.push(`    suggested to: ${v.suggested_to}`);
  if (v.deadline) out.push(`    wanted by: ${v.deadline}`);
  for (const c of v.clarifications) out.push(`    clarification ${c.id} from ${c.by}: ${c.what}${c.answer ? `\n      answered by ${Q.originWords(c.answer.origin)}: ${c.answer.text}` : "\n      not answered yet"}`);
  for (const o of v.offers) out.push(`    offered to ${o.to} at ${o.at}${o.first ? " first" : ""}${o.until ? `, until ${o.until}` : ""} (${o.why})${o.seen_at ? `; reached it at ${o.seen_at}` : ""}${o.accepted ? `; accepted at ${o.accepted.at}` : ""}${o.declined ? `; declined at ${o.declined.at}: ${o.declined.why}` : ""}`);
  for (const d of v.delivered) out.push(`    delivered revision ${d.rev} at ${d.at}${d.post ? ` (post ${d.post.thread}#${d.post.id})` : ""}${d.hypotheses.length ? `; hypotheses ${d.hypotheses.map((n) => `E-${n}`).join(", ")}` : ""}`);
  if (v.accepted) out.push(`    accepted as ${v.accepted.as} by ${Q.originWords(v.accepted.origin)} for revision ${v.accepted.rev}${v.accepted.stands ? "" : " (NO LONGER STANDS: amended, or new evidence arrived, since)"}: ${v.accepted.why}`);
  if (v.withdrawn) out.push(`    withdrawn by ${Q.originWords(v.withdrawn.origin)} at ${v.withdrawn.at}: ${v.withdrawn.why}`);
  for (const g of signed) out.push(`    event ${g.act_seq} signed by ${g.person} (${g.key_kind} ${g.fingerprint}): ${g.state} (${g.detail})`);
  return `${out.join("\n")}\n`;
}

// --- the command line ----------------------------------------------------------------------------

function parseArgs(rest: string[]): { pos: string[]; opts: Map<string, string[]>; flags: Set<string> } {
  const pos: string[] = [];
  const opts = new Map<string, string[]>();
  const flags = new Set<string>();
  const valued = new Set(["--text", "--why", "--neutral", "--presumes", "--objective", "--objective-text", "--parent", "--materiality", "--priority", "--reason", "--expects", "--hint", "--hint-value", "--attach", "--suggest", "--deadline", "--submission", "--expect-rev", "--as", "--secret-fd", "--via", "--title", "--product", "--acceptance", "--question", "--new-question", "--new-why", "--allowed-signers", "--ca", "--hub-admin", "--locator", "--class", "--entity", "--time", "--for-question"]);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (valued.has(a)) {
      opts.set(a, [...(opts.get(a) ?? []), rest[i + 1] ?? ""]);
      i += 1;
    } else if (a.startsWith("--")) flags.add(a);
    else pos.push(a);
  }
  return { pos, opts, flags };
}

/** --hint REF, each optionally followed by --hint-value TEXT for the hint before it. */
function hintsFrom(rest: string[]): Q.QuestionHint[] {
  const out: Q.QuestionHint[] = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--hint") out.push({ ref: rest[i + 1] ?? "" });
    else if (rest[i] === "--hint-value" && out.length) out[out.length - 1].value = rest[i + 1] ?? "";
  }
  return out;
}

function emit(r: Record<string, unknown>): never {
  process.stdout.write(`${JSON.stringify(r)}\n`);
  process.exit(r.ok === false ? 1 : 0);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, sandboxArg, ...rest] = process.argv.slice(2);
  const usage = () => {
    process.stderr.write("usage: questions-cli.ts seed|add|list|show|amend|priority|scope|withdraw|clarify-reply|accept|direct|premise|deliver|verify <sandbox> ...\n");
    process.exit(2);
  };
  if (!cmd || !sandboxArg) usage();
  const sandbox = resolve(sandboxArg);
  const { pos, opts, flags } = parseArgs(rest);
  const one = (k: string) => opts.get(k)?.at(-1);
  const fdRaw = one("--secret-fd");
  const via = one("--via");
  // On accept, --as also takes what is accepted (bounded, not_determinable);
  // the other --as is the person. Everywhere else --as is the person.
  const asValues = opts.get("--as") ?? [];
  const acceptAs =
    cmd === "accept"
      ? asValues.find((v) => (Q.ACCEPT_AS as readonly string[]).includes(v.replace(/-/g, "_")))
      : cmd === "premise" && pos[0] === "admit"
        ? asValues.find((v) => (PM.ADMIT_AS as readonly string[]).includes(v.replace(/-/g, "_")))
        : undefined;
  const person = asValues.filter((v) => v !== acceptAs).at(-1);
  // The run's hub, when one runs: the register's writer (swarm.sh names its admin socket).
  const admission = one("--hub-admin") ? { hubAdmin: one("--hub-admin") } : {};
  const f: Flags = { ...(person ? { as: person } : {}), ...(flags.has("--sign") ? { sign: true } : {}), ...(fdRaw !== undefined ? { secretFd: Number(fdRaw) } : {}), ...(via === "console" || via === "cli" ? { via } : {}) };
  const shared = (): Q.ActInput => ({
    ...(one("--text") !== undefined ? { text: one("--text") } : {}),
    ...(one("--why") !== undefined ? { why: one("--why") } : {}),
    ...(one("--neutral") !== undefined ? { neutral: one("--neutral") } : {}),
    ...(one("--materiality") !== undefined ? { materiality: one("--materiality") } : {}),
    ...(one("--expects") !== undefined ? { expects: one("--expects") } : {}),
    // --presumes: what the question takes as happened; its answer tests that premise first (docs/adr/0011, "What a question presumes").
    ...(one("--presumes") !== undefined ? { presumes: one("--presumes") } : {}),
    // --completeness: the question asks for a complete set (every one, all, each); --no-completeness: it does not, whatever its words.
    ...(flags.has("--completeness") ? { completeness: true } : flags.has("--no-completeness") ? { completeness: false } : {}),
    ...(opts.has("--hint") ? { hints: hintsFrom(rest) } : {}),
    ...(opts.has("--attach") ? { attachments: opts.get("--attach") } : {}),
    ...(one("--suggest") !== undefined ? { suggested_to: one("--suggest") } : {}),
    ...(one("--deadline") !== undefined ? { deadline: one("--deadline") } : {}),
    ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}),
  });
  switch (cmd) {
    case "seed":
      emit({ ok: true, ...(await Q.seedRegister(sandbox)) });
      break;
    case "list":
      if (flags.has("--json")) {
        const ctx = await Q.viewContext(sandbox);
        process.stdout.write(`${JSON.stringify({ questions: Q.questionViews(ctx).map((v) => ({ ...v, delivered: v.delivered })), objectives: [...ctx.questions.state.objectives.values()], triage: ctx.questions.state.triage, chain: ctx.questions.state.chain, seeded: ctx.questions.seeded, ...(ctx.questions.state.premises.size ? { premises: Q.premiseViews(ctx) } : {}) }, null, 2)}\n`);
      } else process.stdout.write(await listText(sandbox));
      break;
    case "show": {
      const id = pos[0];
      if (!id) usage();
      if (flags.has("--json")) {
        const ctx = await Q.viewContext(sandbox);
        const q = Q.findQuestion(ctx.questions, id);
        if (!q) emit({ ok: false, reason: `${id} is not in the question register` });
        const history = ctx.questions.state.events.filter((e) => e.q === q!.id);
        emit({ ok: true, question: Q.viewQuestion(q!, ctx), history, signatures: (await verifySignedActs(sandbox)).filter((x) => x.q === q!.id) });
      }
      const text = await showText(sandbox, id);
      if (!text) {
        process.stderr.write(`${id} is not in the question register\n`);
        process.exit(1);
      }
      process.stdout.write(text);
      break;
    }
    case "add":
      emit(
        await operatorAct(
          sandbox,
          "open",
          {
            ...shared(),
            ...(one("--objective") !== undefined ? { objective: one("--objective") } : {}),
            ...(one("--objective-text") !== undefined ? { objective_text: one("--objective-text") } : {}),
            ...(one("--parent") !== undefined ? { parent: one("--parent") } : {}),
            ...(one("--priority") !== undefined ? { priority: one("--priority") } : {}),
            ...(one("--reason") !== undefined ? { reason: one("--reason") } : {}),
            ...(one("--submission") !== undefined ? { submission: one("--submission") } : {}),
          },
          f,
          undefined,
          admission,
        ),
      );
      break;
    case "amend":
      if (!pos[0]) usage();
      emit(await operatorAct(sandbox, "amend", { q: pos[0], ...shared() }, f, undefined, admission));
      break;
    case "priority":
      if (!pos[0] || !pos[1]) usage();
      emit(await operatorAct(sandbox, "priority", { q: pos[0], priority: pos[1], ...(one("--reason") !== undefined ? { reason: one("--reason") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f, undefined, admission));
      break;
    case "scope": {
      if (!pos[0] || !pos[1]) usage();
      const target = pos[0].toUpperCase();
      emit(await operatorAct(sandbox, "scope", { ...(L.LEAD_ID.test(target) ? { lead: target } : { q: target }), scope: pos[1], ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f, undefined, admission));
      break;
    }
    case "withdraw":
      if (!pos[0]) usage();
      emit(await operatorAct(sandbox, "withdraw", { q: pos[0], ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f, undefined, admission));
      break;
    case "clarify-reply":
      if (!pos[0] || !pos[1] || pos.length < 3) usage();
      emit(await operatorAct(sandbox, "clarify_answer", { q: pos[0], clarify: pos[1], answer: pos.slice(2).join(" ") }, f, undefined, admission));
      break;
    case "accept":
      if (!pos[0]) usage();
      emit(await operatorAct(sandbox, "accept", { q: pos[0], as: acceptAs ?? "", ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f, undefined, admission));
      break;
    case "direct":
      emit(
        await operatorDirective(
          sandbox,
          {
            ...(one("--question") ? { q: one("--question") } : {}),
            ...(one("--new-question") ? { question: { text: one("--new-question"), why: one("--new-why") } } : {}),
            title: one("--title"),
            why: one("--why"),
            product: one("--product"),
            acceptance: one("--acceptance"),
          },
          f,
          undefined,
          admission,
        ),
      );
      break;
    case "premise": {
      // The premise register (extensions/premises.ts): the operator designates what the case takes as given.
      const op = pos[0];
      const id = pos[1];
      // A scope from its flags: --entity, --time FROM..TO, --for-question Q-n (each repeatable); --no-scope clears it on a revision.
      const scope = (): Record<string, unknown> | undefined =>
        flags.has("--no-scope")
          ? {}
          : opts.has("--entity") || opts.has("--time") || opts.has("--for-question")
            ? { ...(opts.has("--entity") ? { entities: opts.get("--entity") } : {}), ...(opts.has("--time") ? { times: opts.get("--time") } : {}), ...(opts.has("--for-question") ? { questions: opts.get("--for-question") } : {}) }
            : undefined;
      const words = (): Q.ActInput => ({
        ...(one("--text") !== undefined ? { text: one("--text") } : {}),
        ...(one("--locator") !== undefined ? { locator: one("--locator") } : {}),
        ...(one("--why") !== undefined ? { why: one("--why") } : {}),
        ...(scope() !== undefined ? { premise_scope: scope() } : {}),
      });
      switch (op) {
        case "list":
        case "show": {
          if (op === "show" && !id) usage();
          const pid = op === "show" ? `P-${Number(/(\d+)$/.exec(id ?? "")?.[1] ?? 0)}` : undefined;
          if (flags.has("--json")) {
            const ctx = await Q.viewContext(sandbox);
            const views = Q.premiseViews(ctx);
            if (!pid) emit({ ok: true, premises: views, chain: ctx.questions.state.chain });
            const p = views.find((x) => x.id === pid);
            if (!p) emit({ ok: false, reason: `${id} is not in the premise register` });
            emit({ ok: true, premise: p, history: ctx.questions.state.events.filter((e) => e.p === pid) });
          }
          const text = await premisesText(sandbox, pid);
          if (text === null) {
            process.stderr.write(`${id} is not in the premise register\n`);
            process.exit(1);
          }
          process.stdout.write(text);
          break;
        }
        case "add":
          emit(await operatorAct(sandbox, "premise_add", { ...words(), ...(one("--class") !== undefined ? { class: one("--class") } : {}) }, f, undefined, admission));
          break;
        case "revise":
          if (!id) usage();
          emit(await operatorAct(sandbox, "premise_revise", { p: id, ...words(), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f, undefined, admission));
          break;
        case "admit":
          if (!id) usage();
          emit(await operatorAct(sandbox, "premise_admit", { p: id, as: acceptAs ?? "", ...(one("--why") !== undefined ? { why: one("--why") } : {}) }, f, undefined, admission));
          break;
        case "withdraw":
          if (!id) usage();
          emit(await operatorAct(sandbox, "premise_withdraw", { p: id, ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f, undefined, admission));
          break;
        default:
          process.stderr.write("usage: questions-cli.ts premise <sandbox> add|revise|admit|withdraw|list|show ...\n");
          process.exit(2);
      }
      break;
    }
    case "deliver":
      emit(await admit(sandbox, admission.hubAdmin, { op: "question_deliver" }, async () => ({ ok: true, delivered: await Q.deliverPending(sandbox) })));
      break;
    case "verify": {
      const r = await verifySignedActs(sandbox, { ...(one("--allowed-signers") ? { allowedSigners: one("--allowed-signers") } : {}), ...(one("--ca") ? { ca: one("--ca") } : {}) });
      const failed = r.some((x) => FAILED_SIGNATURE.has(x.state));
      if (flags.has("--json")) emit({ ok: !failed, signed: r });
      for (const x of r) process.stdout.write(`${x.q ?? "?"} event ${x.act_seq}: signed by ${x.person} (${x.key_kind} ${x.fingerprint}): ${x.state}: ${x.detail}\n`);
      if (!r.length) process.stdout.write("No act in the question register is signed.\n");
      process.exit(failed ? 1 : 0);
      break;
    }
    default:
      usage();
  }
}
