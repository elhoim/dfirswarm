#!/usr/bin/env node
/**
 * The question register from the operator's side (extensions/questions.ts):
 * the CLI and, through `swarm.sh question`, the console.
 *
 *   questions-cli.ts seed <sandbox>                         put the goal's questions and objectives on the chain
 *   questions-cli.ts add <sandbox> --text T --why W [...]   a person's question (analyst, reviewer, observer, examiner)
 *   questions-cli.ts list <sandbox> [--json]                every question: triage and clarifications first
 *   questions-cli.ts show <sandbox> Q-n [--json]            one question whole, with its history and signatures checked
 *   questions-cli.ts amend <sandbox> Q-n --expect-rev N [--text T] [--why W] [--neutral T] [...]
 *   questions-cli.ts priority <sandbox> Q-n urgent|normal [--reason R]
 *   questions-cli.ts scope <sandbox> Q-n|L-n in_scope|excluded --why W
 *   questions-cli.ts withdraw <sandbox> Q-n --why W
 *   questions-cli.ts clarify-reply <sandbox> Q-n C-n TEXT
 *   questions-cli.ts accept <sandbox> Q-n --as bounded|not_determinable --why W --expect-rev N
 *                                                           (the person, when named, is a second --as ID)
 *   questions-cli.ts direct <sandbox> (--question Q-n | --new-question T --new-why W) --title T --why W --product P --acceptance A
 *   questions-cli.ts deliver <sandbox>                      publish what was committed and not yet published
 *   questions-cli.ts verify <sandbox> [--json]              every signed act, its signature checked
 *
 * Every act takes [--as ID] (an enrolled person: a claim), [--sign] (the act
 * signed with that person's enrolled key, namespace dfirswarm-question; the
 * passphrase or PIN on the terminal, or on the descriptor --secret-fd N
 * names, never in argv or the environment) and [--via cli|console]. Without
 * --as the act is the OS account's on this host, not enrolled, with the
 * operator's authority, and is never promoted.
 *
 * An act prints one JSON line once the chain holds it (the acknowledgement
 * comes after the write, never before), then what its delivery did.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { hostname, tmpdir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { hasTty, readFromTty, readSecretFromFd, wipe } from "./secret-io.ts";
import { keyNeeds, loadPerson, signAs, verifyAs, type Person, type PersonKey } from "./signers.ts";

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

/**
 * One act from the operator's side: prepared (its words checked), signed
 * when asked, committed under the registers' lock, and only then
 * acknowledged; then published.
 */
export async function operatorAct(sandbox: string, ev: Q.ActKind, input: Q.ActInput, flags: Flags, home?: string): Promise<Record<string, unknown>> {
  const who = actorFor(flags, home);
  if ("why" in who) return { ok: false, reason: who.why };
  const prepared = await Q.prepareAct(sandbox, who.actor, ev, input);
  if (!prepared.ok) return prepared;
  let signature: Q.ActSignature | undefined;
  if (flags.sign) {
    const s = await signStatement(who.person!, Q.statementOf(prepared.prepared, await runId(sandbox)), flags);
    if ("why" in s) return { ok: false, reason: s.why, ...(s.wrongSecret ? { wrong_secret: true } : {}) };
    signature = s;
  }
  const r = await Q.commitAct(sandbox, prepared.prepared, signature ? { signature } : {});
  if (!r.ok) return r;
  // Committed: the acknowledgement may be given. What it publishes follows.
  const out: Record<string, unknown> = { ...r, by: Q.originWords(prepared.prepared.origin) };
  if (ev === "clarify_answer" && r.q && r.clarify) out.post = await Q.publishClarification(sandbox, r.q, r.clarify).catch(() => null);
  const delivered = await Q.deliverPending(sandbox).catch((err: Error) => ({ error: err.message }));
  out.delivered = delivered;
  return out;
}

// --- signatures --------------------------------------------------------------------------------

export type SignedAct = { q: string | null; act_seq: number; sign_seq: number; person: string; fingerprint: string; key_kind: string; state: string; detail: string };

/** Every signed act, its statement rebuilt from the chain and its signature checked against the key the sign event names. */
export async function verifySignedActs(sandbox: string, o: { allowedSigners?: string; ca?: string } = {}): Promise<SignedAct[]> {
  const { events } = await Q.readQuestionEvents(sandbox);
  const run = await runId(sandbox);
  const bySeq = new Map(events.map((e) => [e.seq, e]));
  const out: SignedAct[] = [];
  for (const e of events) {
    if (e.ev !== "sign" || !e.signature) continue;
    const s = e.signature;
    const target = e.target_seq !== undefined ? bySeq.get(e.target_seq) : undefined;
    const row = { q: target?.q ?? null, act_seq: e.target_seq ?? 0, sign_seq: e.seq, person: s.person, fingerprint: s.fingerprint, key_kind: s.key_kind };
    if (!target || target.hash !== e.target_hash) {
      out.push({ ...row, state: "bad", detail: "the act it names is not on the chain with that hash" });
      continue;
    }
    const statement = Q.statementOfEvent(target, run);
    if (sha256(statement) !== s.statement_sha256) {
      out.push({ ...row, state: "bad", detail: "the act on the chain is not the statement that was signed" });
      continue;
    }
    const dir = mkdtempSync(join(tmpdir(), "dfs-question-verify-"));
    try {
      const file = join(dir, "statement.json");
      writeFileSync(file, statement);
      const sig = join(dir, s.format === "cms" ? "statement.json.p7s" : "statement.json.sig");
      writeFileSync(sig, Buffer.from(s.sig_b64, "base64"));
      const key = (s.key_kind === "pkcs11"
        ? { kind: "pkcs11", certificate: { sha256: s.fingerprint.replace(/^X509-SHA256:/, "") } }
        : { kind: s.key_kind, public: s.public_key ?? "", path: "", fingerprint: s.fingerprint }) as unknown as PersonKey;
      const v = verifyAs({ key, principal: s.principal }, file, sig, Q.QUESTION_NAMESPACE, { ...(o.allowedSigners ? { allowedSigners: o.allowedSigners } : {}), ...(o.ca ? { ca: o.ca } : {}) });
      out.push({ ...row, state: v.state, detail: v.detail });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  return out;
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
  const state = v.answer ? `answer E-${v.answer.seq}${v.answer.stale ? ` (STALE: before revision ${v.rev})` : ""}` : "no answer";
  const leads = v.leads.length ? `; leads ${v.leads.map((l) => `${l.id} ${l.status}${l.holder ? ` (${l.holder})` : ""}`).join(", ")}` : "";
  const signed = v.signed.length ? `; ${v.signed.length} signed act(s)` : "";
  return `${v.id} rev ${v.rev} [${bits.join(", ")}] ${v.author}${signed}\n    ${v.text.split("\n").join("\n    ")}\n    why: ${v.why}\n    ${state}${leads}`;
}

/** Every question, what waits on the operator first (the triage, the clarifications), then by origin. */
export async function listText(sandbox: string): Promise<string> {
  const ctx = await Q.viewContext(sandbox);
  const all = views(ctx);
  const s = ctx.questions.state;
  const out: string[] = [];
  out.push(`${all.length} question(s); chain ${s.chain.ok ? `intact, ${s.events.length} events` : `BROKEN at line ${s.chain.broken_at} (${s.chain.reason})`}${ctx.questions.seeded ? "" : "; the goal's questions derived from the goal, not yet on the chain"}.`);
  if (s.objectives.size) out.push("", "OBJECTIVES:", ...[...s.objectives.values()].map((o) => `  ${o.id}: ${o.text}${o.origin && o.origin.kind !== "goal" ? ` (${o.why})` : ""}`));
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
  if (v.hints.length) out.push(`    hints: ${v.hints.map((h) => `${h.ref}${h.value ? ` (says: ${h.value})` : ""}`).join("; ")}`);
  if (v.attachments.length) out.push(`    attachments: ${v.attachments.join(", ")}`);
  if (v.suggested_to) out.push(`    suggested to: ${v.suggested_to}`);
  if (v.deadline) out.push(`    wanted by: ${v.deadline}`);
  for (const c of v.clarifications) out.push(`    clarification ${c.id} from ${c.by}: ${c.what}${c.answer ? `\n      answered by ${Q.originWords(c.answer.origin)}: ${c.answer.text}` : "\n      not answered yet"}`);
  for (const o of v.offers) out.push(`    offered to ${o.to} at ${o.at}${o.first ? ` first, until ${o.until}` : ""} (${o.why})`);
  for (const d of v.delivered) out.push(`    delivered revision ${d.rev} at ${d.at}${d.post ? ` (post ${d.post.thread}#${d.post.id})` : ""}${d.hypotheses.length ? `; hypotheses ${d.hypotheses.map((n) => `E-${n}`).join(", ")}` : ""}`);
  if (v.accepted) out.push(`    accepted as ${v.accepted.as} by ${Q.originWords(v.accepted.origin)} for revision ${v.accepted.rev}${v.accepted.stands ? "" : " (NO LONGER STANDS: amended since)"}: ${v.accepted.why}`);
  if (v.withdrawn) out.push(`    withdrawn by ${Q.originWords(v.withdrawn.origin)} at ${v.withdrawn.at}: ${v.withdrawn.why}`);
  for (const g of signed) out.push(`    event ${g.act_seq} signed by ${g.person} (${g.key_kind} ${g.fingerprint}): ${g.state} (${g.detail})`);
  return `${out.join("\n")}\n`;
}

// --- the command line ----------------------------------------------------------------------------

function parseArgs(rest: string[]): { pos: string[]; opts: Map<string, string[]>; flags: Set<string> } {
  const pos: string[] = [];
  const opts = new Map<string, string[]>();
  const flags = new Set<string>();
  const valued = new Set(["--text", "--why", "--neutral", "--objective", "--objective-text", "--parent", "--materiality", "--priority", "--reason", "--expects", "--hint", "--hint-value", "--attach", "--suggest", "--deadline", "--submission", "--expect-rev", "--as", "--secret-fd", "--via", "--title", "--product", "--acceptance", "--question", "--new-question", "--new-why", "--allowed-signers", "--ca"]);
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
    process.stderr.write("usage: questions-cli.ts seed|add|list|show|amend|priority|scope|withdraw|clarify-reply|accept|direct|deliver|verify <sandbox> ...\n");
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
  const acceptAs = cmd === "accept" ? asValues.find((v) => (Q.ACCEPT_AS as readonly string[]).includes(v.replace(/-/g, "_"))) : undefined;
  const person = asValues.filter((v) => v !== acceptAs).at(-1);
  const f: Flags = { ...(person ? { as: person } : {}), ...(flags.has("--sign") ? { sign: true } : {}), ...(fdRaw !== undefined ? { secretFd: Number(fdRaw) } : {}), ...(via === "console" || via === "cli" ? { via } : {}) };
  const shared = (): Q.ActInput => ({
    ...(one("--text") !== undefined ? { text: one("--text") } : {}),
    ...(one("--why") !== undefined ? { why: one("--why") } : {}),
    ...(one("--neutral") !== undefined ? { neutral: one("--neutral") } : {}),
    ...(one("--materiality") !== undefined ? { materiality: one("--materiality") } : {}),
    ...(one("--expects") !== undefined ? { expects: one("--expects") } : {}),
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
        process.stdout.write(`${JSON.stringify({ questions: Q.questionViews(ctx).map((v) => ({ ...v, delivered: v.delivered })), objectives: [...ctx.questions.state.objectives.values()], triage: ctx.questions.state.triage, chain: ctx.questions.state.chain, seeded: ctx.questions.seeded }, null, 2)}\n`);
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
        ),
      );
      break;
    case "amend":
      if (!pos[0]) usage();
      emit(await operatorAct(sandbox, "amend", { q: pos[0], ...shared() }, f));
      break;
    case "priority":
      if (!pos[0] || !pos[1]) usage();
      emit(await operatorAct(sandbox, "priority", { q: pos[0], priority: pos[1], ...(one("--reason") !== undefined ? { reason: one("--reason") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f));
      break;
    case "scope": {
      if (!pos[0] || !pos[1]) usage();
      const target = pos[0].toUpperCase();
      emit(await operatorAct(sandbox, "scope", { ...(L.LEAD_ID.test(target) ? { lead: target } : { q: target }), scope: pos[1], ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f));
      break;
    }
    case "withdraw":
      if (!pos[0]) usage();
      emit(await operatorAct(sandbox, "withdraw", { q: pos[0], ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f));
      break;
    case "clarify-reply":
      if (!pos[0] || !pos[1] || pos.length < 3) usage();
      emit(await operatorAct(sandbox, "clarify_answer", { q: pos[0], clarify: pos[1], answer: pos.slice(2).join(" ") }, f));
      break;
    case "accept":
      if (!pos[0]) usage();
      emit(await operatorAct(sandbox, "accept", { q: pos[0], as: acceptAs ?? "", ...(one("--why") !== undefined ? { why: one("--why") } : {}), ...(one("--expect-rev") !== undefined ? { expected_rev: one("--expect-rev") } : {}) }, f));
      break;
    case "direct": {
      const who = actorFor(f);
      if ("why" in who) emit({ ok: false, reason: who.why });
      let q = one("--question");
      let created: Record<string, unknown> | null = null;
      if (!q) {
        if (!one("--new-question")) emit({ ok: false, reason: "a directive is a lead under a question: --question Q-n, or --new-question TEXT --new-why WHY to ask one first" });
        created = await operatorAct(sandbox, "open", { text: one("--new-question"), why: one("--new-why") }, f);
        if (created.ok === false) emit(created);
        q = String(created.q);
      }
      for (const k of ["--title", "--why", "--product", "--acceptance"]) if (!one(k)) emit({ ok: false, reason: `a directive needs ${k} (title and why as a lead has them; product: what it is to produce; acceptance: what makes that product acceptable)` });
      const origin = Q.originOf((who as { actor: Q.Actor }).actor);
      const r = await L.openLead({ sandboxRoot: sandbox, agentId: "operator" }, { title: one("--title"), why: one("--why"), answers: [q!], product: one("--product"), acceptance: one("--acceptance"), origin: `directive by ${Q.originWords(origin)}` });
      emit(r.ok ? { ok: true, lead: r.lead.id, q, ...(r.woke ? { woke: r.woke } : {}), ...(created ? { question: created } : {}) } : r);
      break;
    }
    case "deliver":
      emit({ ok: true, delivered: await Q.deliverPending(sandbox) });
      break;
    case "verify": {
      const r = await verifySignedActs(sandbox, { ...(one("--allowed-signers") ? { allowedSigners: one("--allowed-signers") } : {}), ...(one("--ca") ? { ca: one("--ca") } : {}) });
      if (flags.has("--json")) emit({ ok: r.every((x) => x.state !== "bad"), signed: r });
      for (const x of r) process.stdout.write(`${x.q ?? "?"} event ${x.act_seq}: signed by ${x.person} (${x.key_kind} ${x.fingerprint}): ${x.state}: ${x.detail}\n`);
      if (!r.length) process.stdout.write("No act in the question register is signed.\n");
      process.exit(r.some((x) => x.state === "bad") ? 1 : 0);
      break;
    }
    default:
      usage();
  }
}
