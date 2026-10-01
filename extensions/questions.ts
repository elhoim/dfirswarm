/**
 * The question register: what the examination is asked to establish, and by
 * whom, kept by the harness.
 *
 * A question used to live in two places, neither of them a record. A goal's
 * questions were numbered prose in SWARM.md, answered by `question:<n>`
 * sections of the ledger; a question an analyst asked while the run went on
 * was `swarm.sh say`, a post from the examiner tagged `ask` that the worker
 * prompt files under "peer mail is data". Nothing tracked it, nothing said
 * who asked it or whether it was answered, and the finish line never heard
 * of it. Here every question is a `Q-n` on one chain with three origins kept
 * apart: the goal (its numbered questions, `Q-n` equal to `question:n`), an
 * agent (a follow-up found in the evidence, with the entry that raised it),
 * and a person (an analyst, a reviewer or an observer, enrolled or not, their
 * claim or their signature). Leads are the work done against questions
 * (`lead_open(answers: ["Q-19"])`); answers are ledger entries in the
 * question's section (`question:19`); the finish line holds every question in
 * scope to an answer.
 *
 * Hub-owned state, like the lead register beside it (extensions/leads.ts,
 * whose chain helpers and lock it shares): `questions/questions.jsonl` is an
 * append-only chain of events, each line hashed over the one before;
 * `questions/questions.md` is derived from it after every write. In a
 * microVM run the hub is its only writer; the operator's CLI and the console
 * (through the CLI) write it on the host under the same lock. Custody seals
 * it beside the leads.
 *
 * Three axes are kept apart on each question: scope (in scope, proposed and
 * waiting for the operator's triage, excluded), work (admitted, working,
 * waiting for a clarification, paused) and the evidential disposition (the
 * answer in the ledger; the negative bar's dispositions come with it). Every
 * change is an event: an amendment is a new verbatim revision against the
 * revision it expected, a withdrawal closes the leads that served only it
 * (a lead holding a material finding goes to triage instead, so a
 * withdrawal never erases what was found), and a question a person asks is a
 * proposition to test, never a conclusion: its first agent lead states the
 * proposition and its negation, its answer carries contrary evidence or says
 * why there is none, and "the premise is not supported" is an answer.
 *
 * Nothing here judges a question's worth or reads a case: scope follows
 * declared objectives and parents, who may do what follows the examiner
 * register's roles, and the only words read are a short list of leading
 * forms ("confirm that…"), flagged for the critic and never refused.
 */

import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, normalize } from "node:path";
import * as L from "./leads.ts";
import * as NB from "./negative-bar.ts";
import * as O from "./offers.ts";
import * as PM from "./premises.ts";
import * as P from "./protocol.ts";

// --- the files --------------------------------------------------------------------------------

export const QUESTIONS_DIR = "questions";
export const QUESTIONS_LOG = "questions/questions.jsonl";
export const QUESTIONS_MD = "questions/questions.md";
/** The namespace a question act is signed in: a signature from another use of the same key is not one. */
export const QUESTION_NAMESPACE = "dfirswarm-question";

// --- the vocabulary ---------------------------------------------------------------------------

export const QUESTION_ID = /^Q-([1-9]\d{0,5})$/;
export const CLARIFY_ID = /^C-([1-9]\d{0,5})$/;
export const OBJECTIVE_ID = /^[A-Za-z][A-Za-z0-9._-]{0,31}$/;
export const ORIGIN_KINDS = ["goal", "agent", "analyst", "reviewer", "observer"] as const;
export type OriginKind = (typeof ORIGIN_KINDS)[number];
/** The origins a person gives a question: each is a hypothesis to test. */
export const HUMAN_ORIGINS: ReadonlySet<OriginKind> = new Set<OriginKind>(["analyst", "reviewer", "observer"]);
/**
 * Who acts on the operator's side, and with what authority over questions:
 * the operator (whoever holds the host's CLI or the console's token, not
 * enrolled), and the examiner register's roles (scripts/signers.ts).
 */
export const ACTOR_ROLES = ["operator", "examiner", "analyst", "reviewer", "observer"] as const;
export type ActorRole = (typeof ACTOR_ROLES)[number];
export const MATERIALITY = ["material", "background"] as const;
export type Materiality = (typeof MATERIALITY)[number];
export const PRIORITIES = ["normal", "urgent"] as const;
export type Priority = (typeof PRIORITIES)[number];
/** What kind of answer the asker expects: a hint to the examination, never a format demand. */
export const EXPECTS = ["existence", "value", "narrative", "timeline", "list"] as const;
export type Expects = (typeof EXPECTS)[number];
export const SCOPES = ["in_scope", "proposed", "excluded"] as const;
export type Scope = (typeof SCOPES)[number];
/** The work axis, derived: paused is the run's (a paused run pauses every question). */
export const WORK_STATES = ["admitted", "working", "clarification_needed", "paused"] as const;
export type WorkState = (typeof WORK_STATES)[number];
/** What the operator's acceptance of a question accepts: a bounded examination, or that it cannot be determined. */
export const ACCEPT_AS = ["bounded", "not_determinable"] as const;
export type AcceptAs = (typeof ACCEPT_AS)[number];
export const QUESTION_TEXT_MAX = 4000;
export const QUESTION_WHY_MAX = 2000;
export const QUESTION_MAX_HINTS = 20;
/** What a question takes as happened (presumes): at most this many characters. */
export const QUESTION_PRESUMES_MAX = 2000;
export const QUESTION_MAX_ATTACHMENTS = 20;

/**
 * Leading forms: a question worded as the conclusion it wants ("confirm
 * that…", "show that…", "prove…"). Flagged for the critic, who says which
 * contrary route was checked and whether the routes were steered; never a
 * refusal. The worker prompt carries the same list. Only the imperative
 * counts: at the start of the question, of a sentence, of a line or of a
 * clause after a semicolon or a colon (after an opening quote, and after
 * "please" or "can you"). The same verb inside a question ("what shows
 * that…", "which proves…", "did the log verify that…") asks, it does not
 * lead.
 */
const CLAUSE_START = String.raw`(?:^|[.!?;:]\s+|\n\s*)["'\u201c\u2018(\[]*(?:(?:please|kindly),?\s+|(?:can|could|would)\s+you\s+(?:please\s+)?|(?:i|we)\s+(?:want|need|ask|would\s+like)\s+you\s+to\s+|(?:the|your|our)\s+(?:goal|task|aim|job)\s+is\s+to\s+)?`;
export const LEADING_FORMS: ReadonlyArray<{ phrase: string; re: RegExp }> = [
  { phrase: "confirm that", re: new RegExp(`${CLAUSE_START}confirm\\s+that\\b`, "i") },
  { phrase: "show that", re: new RegExp(`${CLAUSE_START}show\\s+that\\b`, "i") },
  { phrase: "prove", re: new RegExp(`${CLAUSE_START}prove\\b`, "i") },
  { phrase: "demonstrate that", re: new RegExp(`${CLAUSE_START}demonstrate\\s+that\\b`, "i") },
  { phrase: "verify that", re: new RegExp(`${CLAUSE_START}verify\\s+that\\b`, "i") },
];

export function leadingForms(text: string): string[] {
  return LEADING_FORMS.filter((f) => f.re.test(text)).map((f) => f.phrase);
}

/**
 * A completeness claim in a question's words: it asks for every one, all,
 * each, or a complete list, set or inventory. Such a question's established
 * or partial answer rests on a coverage record that says what was searched,
 * area by area (negative-bar.ts COVERAGE_AREAS): the calibration run sabfd76
 * answered "every file" and "every connection" established with no coverage
 * at all. A small word rule, set at the question's opening and at each new
 * revision of its text, whitespace folded first (a doubled space or a line
 * break is one space); the asker's own word (completeness true or false)
 * overrides it. "At all" asks whether, not how many; "at each" and "each
 * time" say when, not how many: none of them counts. Its false positives are
 * a question that asks for "each" item's detail ("which files were copied,
 * each with its time?" is marked, and it is one), and "all" in a phrase that
 * does not ask for a set ("all in all"); an asker who means otherwise says
 * --no-completeness.
 */
export const COMPLETENESS_WORDS = /\bevery\b|(?<!\bat )\beach\b(?! time\b)|(?<!\bat )\ball\b|\bcomplete (?:list|set|inventory)\b/i;
export function completenessWords(text: string): boolean {
  return COMPLETENESS_WORDS.test(text.replace(/\s+/g, " "));
}

/** Whole seconds from the environment, in milliseconds, or the default. */
function envMs(name: string, dfltSec: number): number {
  const raw = process.env[name]?.trim();
  const n = raw && /^\d+$/.test(raw) ? Number(raw) : dfltSec;
  return n * 1000;
}

/**
 * How long a seat a question is offered to has it first, from when the
 * offer reached it (SWARM_QUESTION_OFFER_SEC, or the offers' own
 * SWARM_OFFER_SEC, 60): one offer mechanism for both registers
 * (extensions/offers.ts).
 */
export function firstOfferMs(): number {
  return process.env.SWARM_QUESTION_OFFER_SEC?.trim() ? envMs("SWARM_QUESTION_OFFER_SEC", 60) : O.offerTtlMs();
}

export type QuestionEventKind =
  | "seed"
  | "objective"
  | "open"
  | "amend"
  | "priority"
  | "scope"
  | "clarify_ask"
  | "clarify_answer"
  | "withdraw"
  | "dispose"
  | "accept"
  | "sign"
  | "deliver"
  | "offer"
  | "offer_seen"
  | "offer_decline"
  | "offer_accept"
  | "triage"
  | "continue"
  | "evidence"
  | PM.PremiseEventKind;

/**
 * Who acted, as the record keeps it. A person is an enrolled id (`--as ID`,
 * or the console session's choice) or, when none was named, the OS account
 * and host the act came from, with `enrolled: false`: never promoted. Naming
 * an enrolled person is a claim; `identity: signed` says the act carries that
 * person's signature (a `sign` event right after it).
 */
export type QuestionOrigin = {
  kind: OriginKind;
  person?: string;
  name?: string;
  role?: ActorRole;
  agent?: string;
  os_user?: string;
  host?: string;
  via?: "cli" | "console" | "tool" | "goal";
  enrolled?: boolean;
  identity?: "claimed" | "signed";
  fingerprint?: string;
  /** An agent's question: the entry that raised it (E-<seq>). */
  source_entry?: string;
};

export type QuestionHint = { ref: string; value?: string };

/** What the actor said, as they said it: the part a signature covers. */
export type QuestionAct = {
  text?: string;
  neutral?: string;
  why?: string;
  objective?: string;
  objective_text?: string;
  parent?: string;
  materiality?: Materiality;
  priority?: Priority;
  reason?: string;
  expects?: Expects;
  /** The asker's word on whether the question asks for a complete set; absent, its words decide (completenessWords). */
  completeness?: boolean;
  /** What the question takes as happened (docs/adr/0011, "What a question presumes"): on an open, an amend, or an agent's clarification. Present only when given. */
  presumes?: string;
  /**
   * Whether the question must be established (docs/adr/0013, "A question
   * that must be established"): true on an open or an amend by the operator
   * or an examiner (or the goal's seed), false on an amend that releases it.
   * Present only when given.
   */
  must_establish?: boolean;
  hints?: QuestionHint[];
  attachments?: string[];
  suggested_to?: string;
  deadline?: string;
  submission?: string;
  expected_rev?: number;
  scope?: Scope;
  lead?: string;
  clarify?: string;
  what?: string;
  answer?: string;
  as?: AcceptAs;
  /** A goal question's own id when it is not its number ("bonus"). */
  section?: string;
  /** A premise act (premises.ts): the premise acted on, its words, locator, class, scope, or what an admission makes it. */
  premise?: PM.PremiseAct;
};

export type ActSignature = {
  person: string;
  format: "sshsig" | "cms";
  key_kind: string;
  fingerprint: string;
  principal: string;
  public_key?: string;
  statement_sha256: string;
  sig_b64: string;
};

export type QuestionEvent = {
  v: 1;
  seq: number;
  at: string;
  /** An agent's id, "system" for the harness, "operator" for a person on the operator's side (origin says who). */
  by: string;
  ev: QuestionEventKind;
  q?: string;
  /** A premise event's premise (P-<n>): premises ride this chain (premises.ts). */
  p?: string;
  /** The text revision the question stands at after this event. */
  rev?: number;
  act?: QuestionAct;
  origin?: QuestionOrigin;
  /** What the harness decided or computed for the act: never the actor's word. */
  decided?: Record<string, unknown>;
  // objective
  objective?: string;
  text?: string;
  // seed
  source?: string | null;
  questions?: string[];
  objectives?: string[];
  /** seed: the goal's premises, when it names any. */
  premises?: string[];
  // deliver, offer
  post?: { thread: string; id: number } | null;
  to?: string;
  until?: string;
  first?: boolean;
  why?: string;
  hypotheses?: number[];
  // sign
  target_seq?: number;
  target_hash?: string;
  signature?: ActSignature;
  // triage
  lead?: string;
  cause?: string;
  entries?: number[];
  /** offer_seen, offer_decline, offer_accept: the offer (its event's seq) it answers. */
  offer?: number;
  max_until?: string;
  prev: string;
  hash: string;
};

export type QuestionDraft = Omit<QuestionEvent, "v" | "seq" | "at" | "prev" | "hash"> & { at?: string };

export type Objective = { id: string; text: string; at: string; by: string; origin: QuestionOrigin | null; why: string };

export type Clarification = { id: string; at: string; by: string; what: string; to: string; answer: { at: string; by: string; text: string; origin: QuestionOrigin | null } | null };

export type Question = {
  id: string;
  n: number;
  /** The ledger section key its answer is recorded under (question:<section>): its number, or a goal's own id. */
  section: string;
  origin: QuestionOrigin;
  opened_by: string;
  opened_at: string;
  open_seq: number;
  rev: number;
  revisions: Array<{ rev: number; text: string; at: string; by: string; origin: QuestionOrigin; why?: string; seq: number }>;
  text: string;
  neutral: { text: string; at: string; origin: QuestionOrigin; rev: number } | null;
  why: string;
  objective: string | null;
  objective_text: string | null;
  parent: string | null;
  materiality: Materiality;
  priority: Priority;
  priority_reason: string | null;
  expects: Expects | null;
  /** Whether it asks for a complete set ("every", "all", "each", a complete list): its established or partial answer rests on a coverage record naming the areas searched. */
  completeness: boolean;
  /** Who said so: the asker (the act's completeness), or its words (completenessWords); null when neither. */
  completeness_by: "asker" | "words" | null;
  /**
   * What the question takes as happened, when somebody said so (docs/adr/0011,
   * "What a question presumes"): the asker's word on its open or an
   * amendment, or an agent's with a clarification it asked while none was
   * said; who, when, at which revision, by which act.
   */
  presumes: { text: string; rev: number; at: string; by: string; origin: QuestionOrigin; seq: number; via: "open" | "amend" | "clarify" } | null;
  /**
   * Whether it must be established, and who said so (docs/adr/0013, "A
   * question that must be established"): required by the goal, the
   * operator or an examiner, or released by them (`required: false`, with
   * why); null when nobody has said either. The chain keeps every act.
   */
  must_establish: { required: boolean; at: string; by: string; origin: QuestionOrigin; seq: number; rev: number; why: string | null } | null;
  hints: QuestionHint[];
  attachments: string[];
  suggested_to: string | null;
  deadline: string | null;
  submission: string | null;
  scope: Scope;
  scope_why: string;
  scope_history: Array<{ at: string; scope: Scope; why: string; origin: QuestionOrigin | null }>;
  review_query: boolean;
  leading_forms: string[];
  after_done: boolean;
  /** A follow-up (after_done) the run took up when it was resumed: when, and in which segment. */
  continued: { at: string; segment: number | null; seq: number } | null;
  withdrawn: { at: string; why: string; origin: QuestionOrigin } | null;
  /**
   * The operator's acceptance: of a revision, and of the answer that stood
   * then (its E-<seq> and hash, or none), at the event `seq`. It stands while
   * all of that is still so and no evidence arrived for the question after it.
   */
  accepted: { at: string; as: AcceptAs; why: string; rev: number; origin: QuestionOrigin; seq?: number; answer?: string | null; answer_hash?: string | null; ledger_seq?: number } | null;
  /**
   * Evidence that arrived for this question after the kickoff (swarm.sh
   * evidence add, docs/adr/0014): each arrival makes an answer recorded
   * before it stale, and lifts an acceptance made before it.
   */
  evidence: Array<{ seq: number; at: string; import: string; request: string | null; ledger_seq: number; inventory_rev: number | null }>;
  /** The negative bar's disposition (a later phase writes `dispose`); null until one is recorded. */
  disposition: Record<string, unknown> | null;
  clarifications: Clarification[];
  delivered: Map<number, { at: string; post: { thread: string; id: number } | null; hypotheses: number[] }>;
  offers: Array<{ at: string; to: string; rev: number; first: boolean; until: string | null; why: string; seq: number; seen_at: string | null; declined: { at: string; why: string } | null; accepted: { at: string } | null }>;
  /** Acts on this question that carry a signature: the act's seq, and the sign event's. */
  signed: Array<{ act_seq: number; sign_seq: number; person: string; fingerprint: string }>;
  last_seq: number;
};

export type TriageItem = { seq: number; at: string; q: string | null; lead: string | null; cause: string; entries: number[]; resolved: { at: string; decision: Scope; why: string; origin: QuestionOrigin | null } | null };

export type QuestionsState = {
  events: QuestionEvent[];
  questions: Map<string, Question>;
  /** The premise register, folded from the same chain (premises.ts): none on a chain from before it. */
  premises: Map<string, PM.Premise>;
  objectives: Map<string, Objective>;
  triage: TriageItem[];
  seeded: boolean;
  chain: { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };
};

// --- the chain (the lead register's helpers: one hash, one check) ---------------------------------

export function questionEventHash(e: Omit<QuestionEvent, "hash"> | QuestionEvent, prev: string): string {
  return L.leadEventHash(e as unknown as L.LeadEvent, prev);
}

/** Whether questions.jsonl chains from its first line to its last: the lead register's check, line for line. */
export function verifyQuestionChain(text: string): ReturnType<typeof L.verifyLeadChain> {
  return L.verifyLeadChain(text);
}

export async function readQuestionEvents(sandboxRoot: string): Promise<{ events: QuestionEvent[]; text: string }> {
  const text = await readFile(join(sandboxRoot, QUESTIONS_LOG), "utf8").catch(() => "");
  const events: QuestionEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as QuestionEvent);
    } catch {
      // The chain check names it.
    }
  }
  return { events, text };
}

/** Chain drafts onto `prev` from `seq`, without writing them. */
function chainDrafts(drafts: QuestionDraft[], prev: string, seq: number): QuestionEvent[] {
  const out: QuestionEvent[] = [];
  for (const raw of drafts) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: raw.at ?? new Date().toISOString(), ...Object.fromEntries(Object.entries(raw).filter(([k, x]) => k !== "at" && x !== undefined)) } as Omit<QuestionEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<QuestionEvent, "hash">;
    const e = { ...withPrev, hash: questionEventHash(withPrev, prev) } as QuestionEvent;
    out.push(e);
    prev = e.hash;
  }
  return out;
}

async function appendQuestionEvents(sandboxRoot: string, drafts: QuestionDraft[], held: P.HeldLock): Promise<QuestionEvent[]> {
  const { events: existing, text } = await readQuestionEvents(sandboxRoot);
  const chain = verifyQuestionChain(text);
  if (!chain.ok) throw new Error(`questions/questions.jsonl's chain is broken at line ${chain.broken_at} (${chain.reason}); the register takes no new event until the operator looks`);
  const out = chainDrafts(drafts, chain.head ?? "genesis", existing.length);
  await mkdir(join(sandboxRoot, QUESTIONS_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(sandboxRoot, QUESTIONS_LOG), out.map((e) => `${JSON.stringify(e)}\n`).join(""), "utf8");
  return out;
}

// --- the goal: its questions and objectives ------------------------------------------------------

/**
 * The goal's objectives: an `## Objectives` section (the kickoff writes a
 * goal's front-matter `objectives:` there too), one bullet or numbered line
 * each. `- O-1: text` names its id; a line without one is O-<its place>.
 */
export function goalObjectives(text: string): Array<{ id: string; text: string }> {
  const out: Array<{ id: string; text: string }> = [];
  const sections = [...text.matchAll(/^#{2,3}[ \t]*Objectives[ \t]*$([\s\S]*?)(?=^#{1,6}[ \t]|(?![\s\S]))/gim)].map((m) => m[1]);
  for (const body of sections) {
    // Each item whole: a bullet and the lines that continue it, up to a blank line or the next bullet.
    const items: string[] = [];
    let open = false;
    for (const line of body.split("\n")) {
      const item = /^\s*(?:[-*]|\d+[.)])\s+(.*\S)\s*$/.exec(line);
      if (item) {
        items.push(item[1]);
        open = true;
      } else if (open && line.trim() && !/^\s*#/.test(line)) items[items.length - 1] += ` ${line.trim()}`;
      else open = false;
    }
    for (const raw of items) {
      let t = raw;
      let id: string | null = null;
      const named = /^\**\s*([A-Za-z][A-Za-z0-9._-]{0,31})\s*\**\s*[:.)–-]\s+(.*)$/.exec(t);
      if (named && /\d/.test(named[1])) {
        const o = /^O-?(\d+)$/i.exec(named[1]);
        id = o ? `O-${Number(o[1])}` : named[1];
        t = named[2];
      }
      id ??= `O-${out.length + 1}`;
      if (!out.some((x) => x.id === id)) out.push({ id, text: t.trim() });
    }
  }
  return out;
}

/**
 * The goal's premises: a `## Premises` section (the kickoff writes a goal's
 * front-matter `premises:` there too), one bullet or numbered line each,
 * verbatim. A bullet may end with its scope in brackets, `[scope: questions
 * 1, 2; entities laptop-1; times 2024-01-01..2024-06-30]`; a bullet that
 * says none is about everything the goal asks. Each is a given: the operator
 * wrote the goal (docs/adr/0011, "Premises").
 */
export function goalPremises(text: string): Array<{ text: string; item: number; scope: PM.PremiseScope; bad?: string }> {
  const out: Array<{ text: string; item: number; scope: PM.PremiseScope; bad?: string }> = [];
  const sections = [...text.matchAll(/^#{2,3}[ \t]*Premises[ \t]*$([\s\S]*?)(?=^#{1,6}[ \t]|(?![\s\S]))/gim)].map((m) => m[1]);
  for (const body of sections) {
    const items: string[] = [];
    let open = false;
    for (const line of body.split("\n")) {
      const item = /^\s*(?:[-*]|\d+[.)])\s+(.*\S)\s*$/.exec(line);
      if (item) {
        items.push(item[1]);
        open = true;
      } else if (open && line.trim() && !/^\s*#/.test(line)) items[items.length - 1] += ` ${line.trim()}`;
      else open = false;
    }
    for (const raw of items) {
      let t = raw.trim();
      let scope: PM.PremiseScope = {};
      let bad: string | undefined;
      const m = /\s*\[scope:\s*([^\]]*)\]\s*$/i.exec(t);
      if (m) {
        t = t.slice(0, m.index).trim();
        const said: Record<string, string> = {};
        for (const part of m[1].split(";")) {
          const kv = /^\s*(questions|entities|times)\s+(.*?)\s*$/i.exec(part);
          if (kv) said[kv[1].toLowerCase()] = kv[2];
          else if (part.trim()) bad = `"${part.trim()}" is not questions, entities or times`;
        }
        const checked = PM.checkScope({ ...(said.questions ? { questions: said.questions } : {}), ...(said.entities ? { entities: said.entities } : {}), ...(said.times ? { times: said.times.split(/\s*,\s*/) } : {}) });
        if (checked.ok) scope = checked.scope;
        else bad = checked.reason;
      }
      t = t.replace(/^["'\u201c](.*)["'\u201d]$/, "$1").trim();
      if (t) out.push({ text: t, item: out.length + 1, scope, ...(bad ? { bad } : {}) });
    }
  }
  return out;
}

/**
 * What the goal's questions presume (docs/adr/0011, "What a question
 * presumes"): a `## Presumptions` section (the kickoff writes a goal's
 * front-matter `presumes:` there too), one bullet or numbered line each,
 * `- <question>: <what it takes as happened>`, the question named as the
 * goal names it (`7`, `Q-7`, `Q7`, `question:7`, or a goal's own id such as
 * `bonus`). The words after the colon are kept verbatim. A line that names
 * no question is kept with why (`bad`), and seeds nothing.
 */
export function goalPresumes(text: string): Array<{ section: string; text: string; item: number; bad?: string }> {
  const out: Array<{ section: string; text: string; item: number; bad?: string }> = [];
  const sections = [...text.matchAll(/^#{2,3}[ \t]*Presumptions[ \t]*$([\s\S]*?)(?=^#{1,6}[ \t]|(?![\s\S]))/gim)].map((m) => m[1]);
  for (const body of sections) {
    const items: string[] = [];
    let open = false;
    for (const line of body.split("\n")) {
      const item = /^\s*(?:[-*]|\d+[.)])\s+(.*\S)\s*$/.exec(line);
      if (item) {
        items.push(item[1]);
        open = true;
      } else if (open && line.trim() && !/^\s*#/.test(line)) items[items.length - 1] += ` ${line.trim()}`;
      else open = false;
    }
    for (const raw of items) {
      const m = /^\**\s*(?:question:)?([A-Za-z0-9][A-Za-z0-9._-]{0,31}?)\s*\**\s*:\s+(.*\S)\s*$/i.exec(raw.trim());
      const words = m?.[2]?.replace(/^["'\u201c](.*)["'\u201d]$/, "$1").trim();
      if (!m || !words) {
        out.push({ section: "", text: raw.trim(), item: out.length + 1, bad: "names no question: write it as - <question>: <what it takes as happened>" });
        continue;
      }
      out.push({ section: P.sectionKey(m[1]), text: words, item: out.length + 1 });
    }
  }
  return out;
}

/**
 * The goal's questions that must be established (docs/adr/0013, "A
 * question that must be established"): a `## Must establish` section (the
 * kickoff writes a goal's front-matter `must_establish:` there too), one
 * bullet or numbered line each, naming a question as the goal names it
 * (`1`, `Q-1`, `Q1`, `question:1`, or a goal's own id such as `bonus`),
 * optionally followed by `: why`. The goal owns the definition of done
 * (docs/adr/0002): for these, partial, not determinable, a bounded negative
 * short of the stronger bar and out of scope end no run. A line that names
 * nothing is kept with why (`bad`), and requires nothing.
 */
export function goalMustEstablish(text: string): Array<{ section: string; why: string | null; item: number; bad?: string }> {
  const out: Array<{ section: string; why: string | null; item: number; bad?: string }> = [];
  const sections = [...text.matchAll(/^#{2,3}[ \t]*Must establish[ \t]*$([\s\S]*?)(?=^#{1,6}[ \t]|(?![\s\S]))/gim)].map((m) => m[1]);
  for (const body of sections) {
    for (const line of body.split("\n")) {
      const item = /^\s*(?:[-*]|\d+[.)])\s+(.*\S)\s*$/.exec(line);
      if (!item) continue;
      const m = /^\**\s*(?:question:)?([A-Za-z0-9][A-Za-z0-9_-]{0,31}?)\s*\**\s*[.)]?\s*(?::\s*(.*\S))?\s*$/i.exec(item[1].trim());
      if (!m) {
        out.push({ section: "", why: null, item: out.length + 1, bad: "names no question: write it as - <question>, or - <question>: <why>" });
        continue;
      }
      out.push({ section: P.sectionKey(m[1]), why: m[2]?.replace(/^["'\u201c](.*)["'\u201d]$/, "$1").trim() || null, item: out.length + 1 });
    }
  }
  return out;
}

/** The brief a goal's answers check numbers its questions in (--sections-in), if any. */
function briefPathOf(goal: string): string | null {
  for (const check of L.goalChecks(goal)) {
    if (!check.includes("check-answers.ts")) continue;
    const words = L.shellWords(check);
    const i = words.indexOf("--sections-in");
    if (i >= 0 && words[i + 1]) return words[i + 1];
  }
  return null;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A goal question's words, as the goal (or its brief) numbers it: the line
 * that opens with its id and its whole body after it, verbatim, through
 * blank lines, paragraphs, bullets and indented lists, up to the next of
 * the goal's questions (a later number, or another id such as "Bonus:") or
 * the next heading, which ends the section. Nothing of a question is left
 * out of its first revision. Null when the document does not number it at
 * the start of a line.
 */
export function goalQuestionText(doc: string, id: string, others: string[] = []): string | null {
  const lines = doc.split("\n");
  const numeric = /^\d+$/.test(id);
  // A line that opens another of the goal's questions ends this one ("Bonus: …" after "2. …", "3." after "2.").
  const aliases = others.filter((o) => o !== id && !/^\d+$/.test(o)).map((o) => new RegExp(`^(?:#+ *)?(?:\\*\\* *)?${escapeRe(o)}(?![A-Za-z0-9])`, "i"));
  const later = new Set(others.filter((o) => /^\d+$/.test(o) && (!numeric || Number(o) > Number(id))).map(Number));
  const peer = /^(?:\*\* *)?(?:[Qq](?:uestion)?[ -]*)?0*(\d+)(?![0-9])(?:\*\*)?[.):](?:\*\*)?\s/;
  const heading = /^#{1,6}\s/;
  const start = numeric
    ? new RegExp(`^(?:#+ *)?(?:\\*\\* *)?(?:[Qq](?:uestion)?[ -]*)?0*${id}(?![0-9])(?:\\*\\*)?[.):]?(?:\\*\\*)?\\s+(\\S.*)$`)
    : new RegExp(`^(?:#+ *)?(?:\\*\\* *)?${escapeRe(id)}(?![A-Za-z0-9])(?:\\*\\*)?\\s*[.):]?\\s*(?:\\*\\*)?\\s*(\\S.*)$`, "i");
  for (let i = 0; i < lines.length; i++) {
    const m = start.exec(lines[i]);
    if (!m) continue;
    const out = [m[1].trimEnd()];
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j];
      if (heading.test(next) || aliases.some((re) => re.test(next))) break;
      const p = peer.exec(next);
      if (p && later.has(Number(p[1]))) break;
      out.push(next.trimEnd());
    }
    while (out.length > 1 && !out[out.length - 1].trim()) out.pop();
    return out.join("\n");
  }
  return null;
}

/**
 * The events that put the goal into the register: an `objective` event for
 * each objective it declares, an `open` for each question its answers check
 * names (Q-<n> for question n, so question:n and Q-n are one question; a
 * question the goal does not number takes the next free number and keeps its
 * id as its section), and a `seed` marker last.
 */
export async function seedDrafts(sandboxRoot: string, goal?: L.GoalQuestions): Promise<QuestionDraft[]> {
  const doc = await L.goalDocument(sandboxRoot);
  const gq = goal ?? (await L.goalQuestions(sandboxRoot));
  const at = new Date().toISOString();
  const drafts: QuestionDraft[] = [];
  const objectives = doc ? goalObjectives(doc.text) : [];
  for (const o of objectives) drafts.push({ at, by: "system", ev: "objective", objective: o.id, text: o.text, origin: { kind: "goal", via: "goal" }, why: "an objective of the goal" });
  const brief = doc ? briefPathOf(doc.text) : null;
  const briefText = brief ? await readFile(join(sandboxRoot, brief), "utf8").catch(() => "") : "";
  const numeric = gq.questions.filter((q) => /^\d+$/.test(q)).map(Number);
  let next = Math.max(0, ...numeric);
  const ids: string[] = [];
  // What the goal's questions presume, by section: present only when the goal says so, so a goal without it seeds as it always did.
  const presumed = new Map((doc ? goalPresumes(doc.text) : []).filter((x) => !x.bad).map((x) => [x.section, x.text]));
  // The goal's questions that must be established, by section, and why when it says: the same, present only when the goal names one.
  const required = new Map((doc ? goalMustEstablish(doc.text) : []).filter((x) => !x.bad).map((x) => [x.section, x.why]));
  for (const section of gq.questions) {
    const n = /^\d+$/.test(section) ? Number(section) : ++next;
    const id = `Q-${n}`;
    if (ids.includes(id)) continue;
    ids.push(id);
    const text = (briefText ? goalQuestionText(briefText, section, gq.questions) : null) ?? (doc ? goalQuestionText(doc.text, section, gq.questions) : null) ?? `question:${section}, as the goal numbers it`;
    drafts.push({
      at,
      by: "system",
      ev: "open",
      q: id,
      rev: 1,
      act: {
        text,
        why: "a question of the goal",
        materiality: "material",
        priority: "normal",
        ...(gq.existence.includes(section) ? { expects: "existence" as const } : {}),
        ...(presumed.get(P.sectionKey(section)) ? { presumes: presumed.get(P.sectionKey(section)) } : {}),
        ...(required.has(P.sectionKey(section)) ? { must_establish: true } : {}),
        ...(String(n) !== section ? { section } : {}),
      },
      origin: { kind: "goal", via: "goal" },
      decided: { scope: "in_scope", scope_why: "a question of the goal", section, leading_forms: leadingForms(text), ...(completenessWords(text) ? { completeness: true } : {}), ...(required.get(P.sectionKey(section)) ? { must_establish_why: required.get(P.sectionKey(section)) } : {}) },
    });
  }
  // The goal's premises, each a given (P-<n> in order): present only when the goal has a Premises section, so a goal without one seeds as it always did.
  const premises = doc ? goalPremises(doc.text) : [];
  for (const [i, g] of premises.entries()) {
    const scope = { ...g.scope, ...(g.scope.questions ? { questions: g.scope.questions.filter((q) => ids.includes(q)) } : {}) };
    if (scope.questions && !scope.questions.length) delete scope.questions;
    drafts.push({
      at,
      by: "system",
      ev: "premise_add",
      p: `P-${i + 1}`,
      rev: 1,
      act: { premise: { text: g.text, ...(Object.keys(scope).length ? { scope } : {}) }, why: "a premise of the goal" },
      origin: { kind: "goal", via: "goal" },
      decided: { class: "given", authority: "goal", locator: `the goal (${doc?.source === "registry" ? "the registry's copy" : "SWARM.md"}), Premises, item ${g.item}`, ...(g.bad ? { scope_ignored: g.bad } : {}) },
    });
  }
  drafts.push({ at, by: "system", ev: "seed", source: doc?.source ?? null, questions: ids, objectives: objectives.map((o) => o.id), ...(premises.length ? { premises: premises.map((_, i) => `P-${i + 1}`) } : {}) });
  return drafts;
}

/** Persist the goal's seed when the chain does not hold it yet, under a lock the caller holds. */
async function ensureSeededHeld(sandboxRoot: string, held: P.HeldLock): Promise<void> {
  const { events } = await readQuestionEvents(sandboxRoot);
  if (events.some((e) => e.ev === "seed")) return;
  await appendQuestionEvents(sandboxRoot, await seedDrafts(sandboxRoot), held);
}

/**
 * Put the goal into the register now (the kickoff calls it once the contract
 * is written). Idempotent. It says which questions must be established, and
 * what the goal's Must establish section names that is not one of its
 * questions (`must_establish_unknown`): that requires nothing, and the
 * kickoff warns of it.
 */
export async function seedRegister(sandboxRoot: string): Promise<{ seeded: boolean; questions: string[]; objectives: string[]; must_establish?: string[]; must_establish_unknown?: string[] }> {
  return L.withRegisters(sandboxRoot, async (held) => {
    const before = (await readQuestionEvents(sandboxRoot)).events.some((e) => e.ev === "seed");
    await ensureSeededHeld(sandboxRoot, held);
    const snap = await questionsSnapshot(sandboxRoot);
    if (!before) await writeQuestionsMd(sandboxRoot).catch(() => undefined);
    const doc = await L.goalDocument(sandboxRoot);
    const named = doc ? goalMustEstablish(doc.text) : [];
    const goalSections = new Set([...snap.state.questions.values()].filter((q) => q.origin.kind === "goal").map((q) => q.section));
    const required = [...snap.state.questions.values()].filter(mustEstablish).map((q) => q.id);
    const unknown = named.filter((x) => !x.bad && !goalSections.has(x.section)).map((x) => x.section).concat(named.filter((x) => x.bad).map((x) => `item ${x.item}`));
    // Present only when there is something to say, so a goal that requires nothing seeds as it always did.
    return { seeded: !before, questions: [...snap.state.questions.keys()], objectives: [...snap.state.objectives.keys()], ...(required.length ? { must_establish: required } : {}), ...(unknown.length ? { must_establish_unknown: unknown } : {}) };
  });
}

// --- folding ------------------------------------------------------------------------------------

function blankQuestion(e: QuestionEvent): Question {
  const act = e.act ?? {};
  const d = (e.decided ?? {}) as { scope?: Scope; scope_why?: string; section?: string; leading_forms?: string[]; after_done?: boolean; review_query?: boolean; objective_created?: string; completeness?: boolean; must_establish_why?: string };
  const n = Number(QUESTION_ID.exec(e.q ?? "")?.[1] ?? 0);
  const origin = e.origin ?? { kind: "goal" as const };
  return {
    id: e.q ?? "",
    n,
    section: d.section ?? act.section ?? String(n),
    origin,
    opened_by: e.by,
    opened_at: e.at,
    open_seq: e.seq,
    rev: e.rev ?? 1,
    revisions: [{ rev: e.rev ?? 1, text: act.text ?? "", at: e.at, by: e.by, origin, seq: e.seq }],
    text: act.text ?? "",
    neutral: act.neutral ? { text: act.neutral, at: e.at, origin, rev: e.rev ?? 1 } : null,
    why: act.why ?? "",
    objective: d.objective_created ?? (act.objective && act.objective !== "new" ? act.objective : null),
    objective_text: act.objective === "new" ? (act.objective_text ?? null) : null,
    parent: act.parent ?? null,
    materiality: act.materiality ?? "material",
    priority: act.priority ?? "normal",
    priority_reason: act.priority === "urgent" ? (act.reason ?? null) : null,
    expects: act.expects ?? null,
    completeness: typeof act.completeness === "boolean" ? act.completeness : d.completeness === true,
    completeness_by: typeof act.completeness === "boolean" ? "asker" : d.completeness === true ? "words" : null,
    presumes: act.presumes ? { text: act.presumes, rev: e.rev ?? 1, at: e.at, by: e.by, origin, seq: e.seq, via: "open" } : null,
    must_establish: act.must_establish === true ? { required: true, at: e.at, by: e.by, origin, seq: e.seq, rev: e.rev ?? 1, why: d.must_establish_why ?? null } : null,
    hints: act.hints ?? [],
    attachments: act.attachments ?? [],
    suggested_to: act.suggested_to ?? null,
    deadline: act.deadline ?? null,
    submission: act.submission ?? null,
    scope: d.scope ?? "proposed",
    scope_why: d.scope_why ?? "",
    scope_history: [{ at: e.at, scope: d.scope ?? "proposed", why: d.scope_why ?? "", origin }],
    review_query: d.review_query === true,
    leading_forms: d.leading_forms ?? [],
    after_done: d.after_done === true,
    continued: null,
    withdrawn: null,
    accepted: null,
    evidence: [],
    disposition: null,
    clarifications: [],
    delivered: new Map(),
    offers: [],
    signed: [],
    last_seq: e.seq,
  };
}

/** The register's state, folded from its events in order. */
export function foldQuestions(events: QuestionEvent[], chain: QuestionsState["chain"] = { ok: true, broken_at: null, reason: null, head: events.at(-1)?.hash ?? null }): QuestionsState {
  const questions = new Map<string, Question>();
  const objectives = new Map<string, Objective>();
  const triage: TriageItem[] = [];
  let seeded = false;
  const bySeq = new Map<number, QuestionEvent>();
  for (const e of events) {
    bySeq.set(e.seq, e);
    const q = e.q ? questions.get(e.q) : undefined;
    const act = e.act ?? {};
    const d = (e.decided ?? {}) as Record<string, unknown>;
    const origin = e.origin ?? null;
    switch (e.ev) {
      case "seed":
        seeded = true;
        break;
      case "objective":
        if (e.objective && !objectives.has(e.objective)) objectives.set(e.objective, { id: e.objective, text: e.text ?? "", at: e.at, by: e.by, origin, why: e.why ?? "" });
        break;
      case "open":
        if (e.q && !questions.has(e.q)) questions.set(e.q, blankQuestion(e));
        break;
      case "amend": {
        if (!q) break;
        if (act.text !== undefined && e.rev !== undefined && e.rev > q.rev) {
          q.rev = e.rev;
          q.text = act.text;
          q.revisions.push({ rev: e.rev, text: act.text, at: e.at, by: e.by, origin: origin ?? q.origin, ...(act.why ? { why: act.why } : {}), seq: e.seq });
          q.leading_forms = (d.leading_forms as string[] | undefined) ?? q.leading_forms;
          // An acceptance of an earlier revision no longer stands.
        }
        if (act.neutral !== undefined) q.neutral = { text: act.neutral, at: e.at, origin: origin ?? q.origin, rev: q.rev };
        if (act.materiality) q.materiality = act.materiality;
        if (act.expects) q.expects = act.expects;
        // The asker's word stands over the words; a new revision's words decide when the asker said nothing.
        if (typeof act.completeness === "boolean") {
          q.completeness = act.completeness;
          q.completeness_by = "asker";
        } else if (typeof d.completeness === "boolean" && q.completeness_by !== "asker") {
          q.completeness = d.completeness;
          q.completeness_by = d.completeness ? "words" : null;
        }
        if (act.presumes) q.presumes = { text: act.presumes, rev: q.rev, at: e.at, by: e.by, origin: origin ?? q.origin, seq: e.seq, via: "amend" };
        // Required, or released: the act that changed it, with its why; an act that says what stands already changes nothing.
        if (typeof act.must_establish === "boolean" && act.must_establish !== mustEstablish(q)) q.must_establish = { required: act.must_establish, at: e.at, by: e.by, origin: origin ?? q.origin, seq: e.seq, rev: q.rev, why: act.why ?? null };
        if (act.hints) q.hints = act.hints;
        if (act.attachments) q.attachments = act.attachments;
        if (act.deadline !== undefined) q.deadline = act.deadline || null;
        if (act.suggested_to !== undefined) q.suggested_to = act.suggested_to || null;
        if (typeof d.after_done === "boolean") q.after_done = d.after_done;
        q.last_seq = e.seq;
        break;
      }
      case "priority":
        if (!q || !act.priority) break;
        q.priority = act.priority;
        q.priority_reason = act.priority === "urgent" ? (act.reason ?? null) : null;
        q.last_seq = e.seq;
        break;
      case "scope": {
        if (act.lead) {
          const item = [...triage].reverse().find((t) => t.lead === act.lead && !t.resolved);
          if (item && act.scope) item.resolved = { at: e.at, decision: act.scope, why: act.why ?? "", origin };
          break;
        }
        if (!q || !act.scope) break;
        q.scope = act.scope;
        q.scope_why = (d.scope_why as string | undefined) ?? act.why ?? "";
        q.scope_history.push({ at: e.at, scope: act.scope, why: q.scope_why, origin });
        if (typeof d.objective_created === "string") {
          q.objective = d.objective_created;
          q.objective_text = null;
        }
        // An admission after the run's done is a follow-up; a resume makes it the run's work again.
        if (typeof d.after_done === "boolean") q.after_done = d.after_done;
        for (const t of triage) if (t.q === q.id && !t.resolved) t.resolved = { at: e.at, decision: act.scope, why: act.why ?? "", origin };
        q.last_seq = e.seq;
        break;
      }
      case "clarify_ask":
        if (!q || !act.clarify) break;
        q.clarifications.push({ id: act.clarify, at: e.at, by: e.by, what: act.what ?? "", to: String(d.to ?? ""), answer: null });
        // An agent's reading of what the question takes as happened, recorded while nobody had said so.
        if (act.presumes && !q.presumes) q.presumes = { text: act.presumes, rev: q.rev, at: e.at, by: e.by, origin: origin ?? q.origin, seq: e.seq, via: "clarify" };
        q.last_seq = e.seq;
        break;
      case "clarify_answer": {
        if (!q || !act.clarify) break;
        const c = q.clarifications.find((x) => x.id === act.clarify);
        if (c && !c.answer) c.answer = { at: e.at, by: e.by, text: act.answer ?? "", origin };
        q.last_seq = e.seq;
        break;
      }
      case "withdraw":
        if (!q) break;
        q.withdrawn = { at: e.at, why: act.why ?? "", origin: origin ?? q.origin };
        q.last_seq = e.seq;
        break;
      case "dispose":
        if (!q) break;
        q.disposition = { ...(d as Record<string, unknown>), at: e.at, by: e.by };
        q.last_seq = e.seq;
        break;
      case "accept":
        if (!q || !act.as) break;
        q.accepted = {
          at: e.at,
          as: act.as,
          why: act.why ?? "",
          rev: Number(d.rev ?? e.rev ?? q.rev),
          origin: origin ?? q.origin,
          seq: e.seq,
          ...("answer" in d ? { answer: (d.answer as string | null) ?? null } : {}),
          ...("answer_hash" in d ? { answer_hash: (d.answer_hash as string | null) ?? null } : {}),
          ...(typeof d.ledger_seq === "number" ? { ledger_seq: d.ledger_seq } : {}),
        };
        q.last_seq = e.seq;
        break;
      case "sign": {
        // A signature made after its act: attributed to the person the signed act names, never to the envelope's word.
        const target = e.target_seq !== undefined ? bySeq.get(e.target_seq) : undefined;
        if (!target || target.hash !== e.target_hash || !e.signature) break;
        const tq = target.q ? questions.get(target.q) : undefined;
        if (tq) tq.signed.push({ act_seq: target.seq, sign_seq: e.seq, person: target.origin?.person ?? "?", fingerprint: target.origin?.fingerprint ?? "?" });
        break;
      }
      case "deliver":
        if (!q || e.rev === undefined) break;
        if (!q.delivered.has(e.rev)) q.delivered.set(e.rev, { at: e.at, post: e.post ?? null, hypotheses: e.hypotheses ?? [] });
        break;
      case "offer":
        if (!q || !e.to) break;
        q.offers.push({ at: e.at, to: e.to, rev: e.rev ?? q.rev, first: e.first === true, until: e.until ?? null, why: e.why ?? "", seq: e.seq, seen_at: null, declined: null, accepted: null });
        break;
      case "offer_seen":
      case "offer_decline":
      case "offer_accept": {
        const o = q?.offers.find((x) => x.seq === e.offer);
        if (!o) break;
        if (e.ev === "offer_seen" && !o.seen_at) o.seen_at = e.at;
        if (e.ev === "offer_decline" && !o.declined) o.declined = { at: e.at, why: e.why ?? "" };
        if (e.ev === "offer_accept" && !o.accepted) o.accepted = { at: e.at };
        break;
      }
      case "triage":
        triage.push({ seq: e.seq, at: e.at, q: e.q ?? null, lead: e.lead ?? null, cause: e.cause ?? "", entries: e.entries ?? [], resolved: null });
        break;
      case "evidence":
        // New evidence for this question (the acquisition lane): what was concluded or accepted before it is reopened.
        if (!q) break;
        q.evidence.push({ seq: e.seq, at: e.at, import: String(d.import ?? ""), request: typeof d.request === "string" ? d.request : null, ledger_seq: Number(d.ledger_seq ?? 0), inventory_rev: typeof d.inventory_rev === "number" ? d.inventory_rev : null });
        q.last_seq = e.seq;
        break;
      case "continue":
        // A resume takes up the follow-ups recorded after the run's done: this run's work again.
        for (const id of e.questions ?? []) {
          const fq = questions.get(id);
          if (!fq || !fq.after_done) continue;
          fq.after_done = false;
          fq.continued = { at: e.at, segment: typeof d.segment === "number" ? d.segment : null, seq: e.seq };
        }
        break;
    }
    // An act that carries its own signature (every signed act since the register was made atomic): named by the person it says acted.
    if (e.signature && e.ev !== "sign" && e.q) {
      const sq = questions.get(e.q);
      if (sq) sq.signed.push({ act_seq: e.seq, sign_seq: e.seq, person: e.origin?.person ?? "?", fingerprint: e.origin?.fingerprint ?? "?" });
    }
  }
  return { events, questions, objectives, triage, seeded, chain, premises: PM.foldPremises(events) };
}

// --- the snapshot -------------------------------------------------------------------------------

export type QuestionsSnapshot = {
  state: QuestionsState;
  /** Each question by the ledger section its answer is recorded under. */
  bySection: Map<string, Question>;
  /** The goal's questions are on the chain, not only derived from the goal (a run from before the register, or one not yet written to). */
  seeded: boolean;
  goal: L.GoalQuestions;
  at: number;
};

/**
 * The register as it stands. A chain that does not hold the goal's seed yet
 * (a run from before the register, or one nothing has written to) is read
 * with the seed derived from the goal in front of it, never written: reading
 * a sealed run must not change it.
 */
export async function questionsSnapshot(sandboxRoot: string, o: { goal?: L.GoalQuestions } = {}): Promise<QuestionsSnapshot> {
  const { events, text } = await readQuestionEvents(sandboxRoot);
  const chain = verifyQuestionChain(text);
  const goal = o.goal ?? (await L.goalQuestions(sandboxRoot));
  const persisted = events.some((e) => e.ev === "seed");
  let all = events;
  if (!persisted && chain.ok) {
    const virtual = chainDrafts(await seedDrafts(sandboxRoot, goal), chain.head ?? "genesis", events.length);
    all = [...events, ...virtual];
  }
  const state = foldQuestions(all, { ...chain, head: chain.head });
  state.seeded = persisted;
  const bySection = new Map<string, Question>();
  for (const q of state.questions.values()) if (!bySection.has(q.section)) bySection.set(q.section, q);
  return { state, bySection, seeded: persisted, goal, at: Date.now() };
}

/** A register id or a goal section, as the register knows it: Q-19, question:19, 19, Q19, or a goal's own id. */
export function findQuestion(snap: QuestionsSnapshot, raw: unknown): Question | null {
  const text = String(raw ?? "").trim();
  const reg = /^Q-([1-9]\d{0,5})$/i.exec(text);
  if (reg) return snap.state.questions.get(`Q-${Number(reg[1])}`) ?? null;
  const key = P.sectionKey(text.replace(/^question:/i, ""));
  return snap.bySection.get(key) ?? null;
}

/** Who acted, in words: a person's name and role, claimed or signed, enrolled or not; an agent's id; the goal. */
export function originWords(o: QuestionOrigin | null | undefined): string {
  if (!o) return "?";
  if (o.kind === "goal") return "the goal";
  if (o.kind === "agent") return `${o.agent ?? "an agent"}${o.source_entry ? ` (from ${o.source_entry})` : ""}`;
  const who = o.name ? `${o.name} (${o.person})` : (o.person ?? "?");
  const how = [o.role ?? o.kind, o.identity ?? "claimed", o.enrolled === false ? "not enrolled" : null, o.via ? `via ${o.via}` : null].filter(Boolean).join(", ");
  return `${who}, ${how}`;
}

/** The name a person's board posts go under: analyst:<person>. */
export function posterOf(o: QuestionOrigin): string {
  const person = String(o.person ?? "unknown").replace(/[^A-Za-z0-9._@-]/g, "-");
  return `${o.kind === "reviewer" || o.kind === "observer" ? o.kind : "analyst"}:${person}`;
}

// --- the views ----------------------------------------------------------------------------------

export type QuestionView = {
  id: string;
  section: string;
  origin: QuestionOrigin;
  author: string;
  text: string;
  rev: number;
  revisions: Question["revisions"];
  neutral: Question["neutral"];
  why: string;
  objective: string | null;
  objective_text: string | null;
  parent: string | null;
  materiality: Materiality;
  priority: Priority;
  priority_reason: string | null;
  expects: Expects | null;
  completeness: boolean;
  completeness_by: Question["completeness_by"];
  /** What somebody said the question takes as happened (the asker, or an agent with a clarification). */
  presumes: Question["presumes"];
  /**
   * What the question presumes as the review rule reads it
   * (questionPresumption): its presumes, or a person's question's framing;
   * null when neither.
   */
  presumption: PM.Presumption | null;
  /** Whether it must be established, and who said so (or released it): docs/adr/0013, "A question that must be established". */
  must_establish: Question["must_establish"];
  hints: QuestionHint[];
  attachments: string[];
  suggested_to: string | null;
  deadline: string | null;
  scope: Scope;
  scope_why: string;
  scope_history: Question["scope_history"];
  review_query: boolean;
  leading_forms: string[];
  after_done: boolean;
  withdrawn: Question["withdrawn"];
  /** The operator's acceptance, and whether it still stands (it is bound to the revision it accepted). */
  accepted: (NonNullable<Question["accepted"]> & { stands: boolean }) | null;
  disposition: Question["disposition"];
  work: WorkState | null;
  /**
   * The standing answer entry in the question's section, the revision it
   * answers and whether that is an earlier one than the question's (stale); its result (an older answer's read from
   * inconclusive), and for a negative whether another seat reviewed it and
   * what coverage it rests on (the negative bar).
   */
  answer: {
    seq: number;
    at: string;
    inconclusive: boolean;
    result?: string;
    question_rev: number;
    stale: boolean;
    stale_why?: "revision" | "evidence";
    negative?: { reviewed: boolean; by: string[]; coverage: Array<{ seq: number; coverage: string | null }> };
    parts?: PM.AnswerPart[];
    /**
     * Its parts as its reviews weigh them (protocol.ts answerPartsStanding):
     * each row with the reviews that mark it not asked, the counts, the
     * plain line a partial answer leads with (`summary`), and, when every
     * asked part of a partial answer is established, the words said beside
     * its label (`plain`). Present only with parts.
     */
    standing?: PM.PartsStanding & { summary: string; plain: string | null };
    premises?: PM.PremiseCitation[];
    omitted?: Array<{ by: string; part: string; why: string }>;
    /** The tests of what the question presumes: the answer's own (by its author) and each review's, whole. Present only when there is one. */
    premise_tests?: Array<{ by: string; review: boolean; outcome: string; refs: string[] }>;
  } | null;
  /** Evidence that arrived for it after the kickoff (the acquisition lane). */
  evidence: Question["evidence"];
  leads: Array<{ id: string; status: L.LeadStatus; holder: string | null; disposition?: string; opened_by: string }>;
  clarifications: Clarification[];
  pending_clarifications: string[];
  offers: Question["offers"];
  delivered: Array<{ rev: number; at: string; post: { thread: string; id: number } | null; hypotheses: number[] }>;
  signed: Question["signed"];
  opened_at: string;
  opened_by: string;
};

export type ViewContext = { questions: QuestionsSnapshot; leads: L.LeadsState; ledger: L.LedgerView; paused?: boolean; attestations?: P.LedgerAttestation[] };

/** The standing answer entry of a section, if any. */
function standingAnswer(ledger: L.LedgerView, section: string): P.LedgerEntry | null {
  return ledger.entries.find((e) => e.kind === "answer" && e.section === `question:${section}` && !ledger.replaced.has(e.seq)) ?? null;
}

/**
 * Whether the operator's acceptance of a question still stands: it is of
 * the question's current revision, and of the answer that stands now (the
 * same entry, with the hash it had), or of none while none stands; and no
 * evidence arrived for the question after it (the acquisition lane,
 * docs/adr/0014, reopens what was accepted). An answer recorded, replaced
 * or corrected since is not what was accepted, and is held to the bar
 * again.
 */
export function acceptanceStands(q: Pick<Question, "accepted" | "rev" | "evidence" | "section">, ledger: L.LedgerView): boolean {
  if (!q.accepted || q.accepted.rev !== q.rev) return false;
  // Evidence that arrived after the acceptance (an acceptance from before the event seq was kept counts as the earliest).
  const at = q.accepted.seq ?? 0;
  if (q.evidence.some((x) => x.seq > at)) return false;
  if (q.accepted.answer === undefined) return true;
  const a = standingAnswer(ledger, q.section);
  if (!a) return q.accepted.answer === null;
  if (q.accepted.answer !== `E-${a.seq}`) return false;
  return q.accepted.answer_hash === undefined || q.accepted.answer_hash === null || q.accepted.answer_hash === (a.hash ?? null);
}

export function viewQuestion(q: Question, ctx: ViewContext): QuestionView {
  const leads = [...ctx.leads.leads.values()].filter((l) => l.answers.includes(q.section));
  const leadViews = leads.map((l) => {
    const status = L.leadStatus(l, ctx.leads, ctx.ledger);
    return { id: l.id, status, holder: l.holder, ...(l.closed ? { disposition: l.closed.disposition } : {}), opened_by: l.opened_by };
  });
  const pending = q.clarifications.filter((c) => !c.answer).map((c) => c.id);
  const inScope = q.scope === "in_scope" && !q.withdrawn && !q.after_done;
  const working = leadViews.some((l) => l.status !== "closed" && l.holder);
  const work: WorkState | null = !inScope ? null : ctx.paused ? "paused" : pending.length ? "clarification_needed" : working ? "working" : "admitted";
  const a = standingAnswer(ctx.ledger, q.section);
  const result = a ? NB.answerResult(a) : null;
  const negative =
    a && result && NB.NEGATIVE_RESULTS.has(result)
      ? (() => {
          const r = P.negativeReview(a, ctx.ledger.entries, ctx.attestations ?? []);
          const coverage = (a.support ?? []).map((x) => ctx.ledger.bySeq.get(x.seq)).filter((e): e is P.LedgerEntry => e?.kind === "coverage").map((e) => ({ seq: e.seq, coverage: e.coverage ?? null }));
          return { reviewed: r.reviewed, by: r.by, coverage };
        })()
      : null;
  const answer = a
    ? {
        seq: a.seq,
        at: a.at,
        inconclusive: a.inconclusive === true,
        ...(result ? { result } : {}),
        // Bound to the revision it answers (recorded under the register's
        // lock), never to when it was written: absent is revision 1.
        question_rev: a.question_rev ?? 1,
        // An answer is also stale when evidence for the question arrived after it was recorded.
        stale: (a.question_rev ?? 1) !== q.rev || q.evidence.some((x) => a.seq <= x.ledger_seq),
        ...((a.question_rev ?? 1) !== q.rev ? { stale_why: "revision" as const } : q.evidence.some((x) => a.seq <= x.ledger_seq) ? { stale_why: "evidence" as const } : {}),
        ...(negative ? { negative } : {}),
        // Its claim and open-part rows and the premises it cites (premises.ts), and each part a review says it leaves out: present only when it has them.
        ...(a.parts?.length ? { parts: a.parts } : {}),
        ...((): { standing?: PM.PartsStanding & { summary: string; plain: string | null } } => {
          const standing = P.answerPartsStanding(a, ctx.attestations ?? [], { entries: ctx.ledger.entries });
          return standing ? { standing: { ...standing, summary: PM.partsSummaryWords(standing), plain: PM.partialPlainWords(result, standing) } } : {};
        })(),
        ...(a.premises?.length ? { premises: a.premises } : {}),
        ...((): { premise_tests?: Array<{ by: string; review: boolean; outcome: string; refs: string[] }> } => {
          const tests = [
            ...(a.premise_tested ? [{ by: a.authors.join(", "), review: false, outcome: a.premise_tested.outcome, refs: a.premise_tested.refs }] : []),
            ...P.answerReviews(a, ctx.attestations ?? []).flatMap((x) => (x.answer_review?.premise_tested ? [{ by: x.by, review: true, outcome: x.answer_review.premise_tested.outcome, refs: x.answer_review.premise_tested.refs }] : [])),
          ];
          return tests.length ? { premise_tests: tests } : {};
        })(),
        ...((): { omitted?: Array<{ by: string; part: string; why: string }> } => {
          const omitted = P.answerReviews(a, ctx.attestations ?? []).flatMap((x) => (x.answer_review?.parts ?? []).filter((p) => p.missing).map((p) => ({ by: x.by, part: p.part, why: p.why })));
          return omitted.length ? { omitted } : {};
        })(),
      }
    : null;
  return {
    id: q.id,
    section: q.section,
    origin: q.origin,
    author: originWords(q.origin),
    text: q.text,
    rev: q.rev,
    revisions: q.revisions,
    neutral: q.neutral,
    why: q.why,
    objective: q.objective,
    objective_text: q.objective_text,
    parent: q.parent,
    materiality: q.materiality,
    priority: q.priority,
    priority_reason: q.priority_reason,
    expects: q.expects,
    completeness: q.completeness,
    completeness_by: q.completeness_by,
    presumes: q.presumes,
    presumption: questionPresumption(q, ctx.leads),
    must_establish: q.must_establish,
    hints: q.hints,
    attachments: q.attachments,
    suggested_to: q.suggested_to,
    deadline: q.deadline,
    scope: q.scope,
    scope_why: q.scope_why,
    scope_history: q.scope_history,
    review_query: q.review_query,
    leading_forms: q.leading_forms,
    after_done: q.after_done,
    withdrawn: q.withdrawn,
    accepted: q.accepted ? { ...q.accepted, stands: acceptanceStands(q, ctx.ledger) } : null,
    evidence: q.evidence,
    disposition: q.disposition,
    work,
    answer,
    leads: leadViews,
    clarifications: q.clarifications,
    pending_clarifications: pending,
    offers: q.offers,
    delivered: [...q.delivered.entries()].map(([rev, d]) => ({ rev, ...d })),
    signed: q.signed,
    opened_at: q.opened_at,
    opened_by: q.opened_by,
  };
}

/** Every question's view: persons' first, then the goal's in their order, then the agents', each by number. */
export function questionViews(ctx: ViewContext): QuestionView[] {
  const rank = (q: Question) => (HUMAN_ORIGINS.has(q.origin.kind) ? 0 : q.origin.kind === "goal" ? 1 : 2);
  return [...ctx.questions.state.questions.values()].sort((a, b) => rank(a) - rank(b) || a.n - b.n).map((q) => viewQuestion(q, ctx));
}

/**
 * A premise as the views show it: the register's record of it, who
 * designated it in words, and every standing answer that cites it, with its
 * stance, the revision it cites (current or not) and the entries it names.
 */
export type PremiseView = PM.Premise & { author: string; cited_by: Array<{ answer: number; section: string; stance: PM.PremiseStance; rev: number; conditional: boolean; refs: string[]; current: boolean }> };

export function premiseViews(ctx: Pick<ViewContext, "questions" | "ledger">): PremiseView[] {
  const standing = ctx.ledger.entries.filter((e) => e.kind === "answer" && e.section?.startsWith("question:") && !ctx.ledger.replaced.has(e.seq) && e.premises?.length);
  return [...ctx.questions.state.premises.values()]
    .sort((a, b) => a.n - b.n)
    .map((p) => ({
      ...p,
      author: p.authority === "goal" ? "the goal" : originWords(p.origin),
      cited_by: standing.flatMap((a) => (a.premises ?? []).filter((c) => c.id === p.id).map((c) => ({ answer: a.seq, section: a.section as string, stance: c.stance, rev: c.rev, conditional: c.conditional === true, refs: c.refs ?? [], current: c.rev === p.rev }))),
    }));
}

/** A premise in one line: its id, revision, class, author, words whole, locator and scope. */
export function premiseLine(p: PM.Premise, author: string): string {
  return `${p.id} rev ${p.rev}, ${PM.classWords(p.class)} (${author}): "${p.text}"${p.locator ? ` (at ${p.locator})` : ""}${Object.keys(p.scope).length ? ` [${PM.scopeWords(p.scope)}]` : ""}${p.withdrawn ? `; WITHDRAWN: ${p.withdrawn.why}` : ""}`;
}

/** The register with the ledger and the leads beside it, read now. */
export async function viewContext(sandboxRoot: string): Promise<ViewContext> {
  const ls = await L.leadsSnapshot(sandboxRoot);
  const questions = ls.questions ?? (await questionsSnapshot(sandboxRoot, { goal: ls.goal }));
  const budget = (await P.readBudget(sandboxRoot).catch(() => null)) as (P.BudgetRecord & { paused?: unknown }) | null;
  const attestations = await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]);
  // A paused run (the stop policy: a cap reached, the operator not yet asked) pauses every question in it.
  return { questions, leads: ls.state, ledger: ls.ledger, paused: Boolean(budget?.paused), attestations };
}

/**
 * What a question takes as happened (docs/adr/0011, "What a question
 * presumes"), when the record says: its `presumes` (the asker's word, or an
 * agent's), else, for a person's question, the proposition the register's
 * framing states (ADR 0011, item 7: the first lead under it that states a
 * proposition and its negation, in the order the leads were opened; the
 * question's own words while none has). Null when neither. The words are
 * the register's, never read for what they mean.
 */
export function questionPresumption(q: Question, leads: L.LeadsState | null): PM.Presumption | null {
  if (q.presumes) return { q: q.id, section: q.section, text: q.presumes.text, source: "presumes", by: originWords(q.presumes.origin) };
  if (!HUMAN_ORIGINS.has(q.origin.kind)) return null;
  const framed = [...(leads?.leads.values() ?? [])].filter((l) => l.answers.includes(q.section) && l.proposition).sort((a, b) => a.n - b.n)[0];
  return { q: q.id, section: q.section, text: framed?.proposition ?? q.text, source: "framing", by: originWords(q.origin), ...(framed ? { lead: framed.id, ...(framed.negation ? { negation: framed.negation } : {}) } : {}) };
}

/** Every question's presumption, by its section (questionPresumption): what the ledger gate and the attest read. */
export function presumptionsOf(qs: QuestionsSnapshot | null | undefined, leads: L.LeadsState | null): Map<string, PM.Presumption> {
  const out = new Map<string, PM.Presumption>();
  for (const q of qs?.state.questions.values() ?? []) {
    const p = questionPresumption(q, leads);
    if (p) out.set(q.section, p);
  }
  return out;
}

/** The questions a finish line holds the run to beyond the goal's own check: in scope, not withdrawn, not a follow-up, asked by a person or an agent. */
export function registerQuestions(snap: QuestionsSnapshot): Question[] {
  return [...snap.state.questions.values()].filter((q) => q.origin.kind !== "goal" && liveInScope(q));
}

/** A question this run's work is held to now: in scope, not withdrawn, and not a follow-up admitted after its done (that is a resume's). */
export function liveInScope(q: Pick<Question, "scope" | "withdrawn" | "after_done">): boolean {
  return q.scope === "in_scope" && !q.withdrawn && !q.after_done;
}

// --- a question that must be established (docs/adr/0013) ---------------------------------------

/** Whether a question must be established now: the goal, the operator or an examiner required it, and nobody released it since. */
export function mustEstablish(q: Pick<Question, "must_establish"> | null | undefined): boolean {
  return q?.must_establish?.required === true;
}

/** Who required it, in words: the goal, or the person. */
export function requiredByWords(q: Pick<Question, "must_establish">): string {
  return q.must_establish ? originWords(q.must_establish.origin) : "nobody";
}

/**
 * Whether an answer, by what it says it is, can meet the requirement:
 * established, a premise shown not to hold, or a bounded negative that says
 * the event did not happen (the stronger bar, which the record refuses
 * without its coverage); an answer from before results that is not marked
 * inconclusive reads as established. What it rests on is the answers
 * check's, which holds the rest of the bar (a best candidate, a premise
 * rejected on a search alone, a negative unreviewed). Readiness and every
 * seat's header read this; the finish line reads the answers check.
 */
export function establishesBy(a: Pick<P.LedgerEntry, "kind" | "result" | "inconclusive" | "asserts_absence">): boolean {
  const r = NB.answerResult(a);
  if (!r) return a.inconclusive !== true;
  return r === "established" || r === "premise_not_supported" || (r === "bounded_negative" && a.asserts_absence === true);
}

/** What a question that must be established ends on, said wherever it holds: what meets it, and the operator's two ways out, on the record. */
export const MUST_ESTABLISH_WAYS =
  "establish it (an answer on a standing finding another seat attests established), show on a finding that its premise does not hold, or settle it by a bounded negative under the stronger bar; partial, not determinable, a bounded negative short of the stronger bar and out of scope do not end the run on it, and only the operator accepts its limits (question accept) or releases the requirement (question amend --no-must-establish)";

// --- who may do what ----------------------------------------------------------------------------

/**
 * Who is acting. An agent is its seat (the hub decides it by the channel); a
 * person on the operator's side is their role and who they are: an enrolled
 * id (`--as`, or the console session's choice), claimed or signed, or, when
 * none was named, the OS account and host, not enrolled, with the operator's
 * authority over the run.
 */
export type Actor =
  | { kind: "agent"; agent: string }
  | { kind: "human"; role: ActorRole; person: string; name?: string; enrolled: boolean; os_user: string; host: string; via: "cli" | "console"; identity: "claimed" | "signed"; fingerprint?: string };

export function originOf(actor: Actor, sourceEntry?: string): QuestionOrigin {
  if (actor.kind === "agent") return { kind: "agent", agent: actor.agent, via: "tool", ...(sourceEntry ? { source_entry: sourceEntry } : {}) };
  const kind: OriginKind = actor.role === "reviewer" ? "reviewer" : actor.role === "observer" ? "observer" : "analyst";
  return {
    kind,
    person: actor.person,
    ...(actor.name ? { name: actor.name } : {}),
    role: actor.role,
    os_user: actor.os_user,
    host: actor.host,
    via: actor.via,
    enrolled: actor.enrolled,
    identity: actor.identity,
    ...(actor.fingerprint ? { fingerprint: actor.fingerprint } : {}),
  };
}

function authority(o: QuestionOrigin): boolean {
  return o.role === "operator" || o.role === "examiner";
}

/** Whether `o` asked `q` (a person's own question; the goal and the agents own none a person may change). */
function asked(q: Question, o: QuestionOrigin): boolean {
  return HUMAN_ORIGINS.has(q.origin.kind) && Boolean(o.person) && q.origin.person === o.person;
}

/** Why `o` may not act `ev` on `q`, or null when it may. The agents' own acts are their tools': they never change a person's or the goal's question. */
export function refusalFor(ev: ActKind, o: QuestionOrigin, q: Question | null): string | null {
  const who = originWords(o);
  if (o.kind === "agent") {
    if (ev === "open" || ev === "clarify_ask" || ev === "premise_propose") return null;
    if (PM.isPremiseEvent(ev)) return "an agent proposes a premise (premise_propose), which stays a proposition under test; adding, revising, admitting and withdrawing a premise are the operator's (swarm.sh question <run> premise …)";
    return `an agent does not ${ev.replace("_", " ")} a question: amending, re-prioritising, re-scoping, withdrawing and accepting are the asker's and the operator's`;
  }
  if (ev === "clarify_ask") return "a clarification is asked by an agent working the question (question_ask); a person answers it with clarify-reply";
  if (ev === "premise_propose") return "premise_propose is an agent's; on the operator's side a premise is added (premise add), and a proposition under test is admitted (premise admit)";
  if (ev === "open") return null;
  if (authority(o)) return null;
  if (PM.isPremiseEvent(ev)) return `${who}: designating the case's premises (adding, revising, admitting, withdrawing) is the examiner's or the operator's, not an ${o.role ?? o.kind}'s; ask it as a question instead`;
  const role = o.role ?? o.kind;
  if (ev === "scope" || ev === "accept") return `${who}: ${ev === "scope" ? "admitting to or excluding from the case" : "accepting a question's limits"} is the examiner's or the operator's, not an ${role}'s`;
  if (!q) return null;
  if (!asked(q, o)) return `${who} did not ask ${q.id} (${originWords(q.origin)} did): only its asker, the examiner or the operator may ${ev.replace("_", " ")} it`;
  if (ev === "amend" && role === "observer") return `${who}: an observer proposes questions; amending one is the examiner's or the operator's`;
  if (ev === "priority" && (role === "observer" || role === "reviewer")) return `${who}: a ${role} does not set priority; the examiner or the operator does`;
  return null;
}

// --- checking what an act says ------------------------------------------------------------------

type Fail = { ok: false; reason: string };

function bounded(name: string, raw: unknown, max: number, required: boolean): { ok: true; value: string } | Fail {
  const text = String(raw ?? "").trim();
  if (required && !text) return { ok: false, reason: `${name} is required` };
  if (text.length > max) return { ok: false, reason: `${name} is over ${max} characters: say it in fewer; nothing is cut, so a longer text is refused, not shortened` };
  return { ok: true, value: text };
}

function oneOf<T extends readonly string[]>(name: string, raw: unknown, allowed: T): { ok: true; value?: T[number] } | Fail {
  const text = String(raw ?? "").trim().toLowerCase().replace(/-/g, "_");
  if (!text) return { ok: true };
  if (!(allowed as readonly string[]).includes(text)) return { ok: false, reason: `${name} is one of ${allowed.join(", ")} (got ${JSON.stringify(raw)})` };
  return { ok: true, value: text as T[number] };
}

function pRef(raw: unknown): { ok: true; id: string } | Fail {
  const m = /^P-?([1-9]\d{0,5})$/i.exec(String(raw ?? "").trim());
  if (!m) return { ok: false, reason: `a premise is named P-<n> (got ${JSON.stringify(raw)})` };
  return { ok: true, id: `P-${Number(m[1])}` };
}

function qRef(raw: unknown): { ok: true; id: string } | Fail {
  const m = /^Q-?([1-9]\d{0,5})$/i.exec(String(raw ?? "").trim());
  if (!m) return { ok: false, reason: `a question is named Q-<n> (got ${JSON.stringify(raw)})` };
  return { ok: true, id: `Q-${Number(m[1])}` };
}

/**
 * The run's own sensitive values, as a question's words are held to them: a
 * question, its reasons and its hints may not carry any value the run marks
 * sensitive, whatever its origin and whoever writes it (B9: every entry
 * recorded sensitive, standing or not; no answer-value concept, no
 * exemption for the goal's own words; protocol.ts runSensitiveTokens).
 */
export async function sensitiveRefusal(sandboxRoot: string, texts: Array<[string, string | undefined]>): Promise<string | null> {
  return P.sensitiveRefusalOf(sandboxRoot, texts);
}

/** A hint or an attachment names an object of the run (a ref that resolves) or a path under it. */
async function checkRunRef(sandboxRoot: string, name: string, ref: string): Promise<string | null> {
  if (/^(input|job|import|member|sha256|tool|trace):/.test(ref)) {
    const r = await P.checkRefs(sandboxRoot, [ref]);
    return r.ok ? null : `${name}: ${r.reason}`;
  }
  if (isAbsolute(ref) || normalize(ref).startsWith("..")) return `${name} ${JSON.stringify(ref)} is not in the run: name a ref (input:<path>, job:<id>/<path>, member:<gen>#<n>) or a path under the run's directory`;
  if (!existsSync(join(sandboxRoot, normalize(ref)))) return `${name} ${JSON.stringify(ref)} names nothing in the run`;
  return null;
}

async function checkHints(sandboxRoot: string, raw: unknown): Promise<{ ok: true; hints: QuestionHint[] } | Fail> {
  const list = Array.isArray(raw) ? raw : raw === undefined || raw === null || raw === "" ? [] : [raw];
  const out: QuestionHint[] = [];
  for (const h of list) {
    const ref = String(typeof h === "string" ? h : ((h as QuestionHint)?.ref ?? "")).trim();
    const value = typeof h === "string" ? "" : String((h as QuestionHint)?.value ?? "").trim();
    if (!ref) return { ok: false, reason: "a hint is {ref, value?}: where to look (a ref or a path in the run), never what to find" };
    const bad = await checkRunRef(sandboxRoot, "hint", ref);
    if (bad) return { ok: false, reason: bad };
    if (value.length > QUESTION_WHY_MAX) return { ok: false, reason: `a hint's value is over ${QUESTION_WHY_MAX} characters` };
    if (!out.some((x) => x.ref === ref && (x.value ?? "") === value)) out.push({ ref, ...(value ? { value } : {}) });
  }
  if (out.length > QUESTION_MAX_HINTS) return { ok: false, reason: `a question carries at most ${QUESTION_MAX_HINTS} hints` };
  return { ok: true, hints: out };
}

async function checkAttachments(sandboxRoot: string, raw: unknown): Promise<{ ok: true; attachments: string[] } | Fail> {
  const list = [...new Set((Array.isArray(raw) ? raw.map(String) : raw ? String(raw).split(/[\s,]+/) : []).map((x) => x.trim()).filter(Boolean))];
  for (const a of list) {
    const bad = await checkRunRef(sandboxRoot, "attachment", a);
    if (bad) return { ok: false, reason: bad };
  }
  if (list.length > QUESTION_MAX_ATTACHMENTS) return { ok: false, reason: `a question carries at most ${QUESTION_MAX_ATTACHMENTS} attachments` };
  return { ok: true, attachments: list };
}

// --- acts ---------------------------------------------------------------------------------------

export type ActKind = "open" | "amend" | "priority" | "scope" | "withdraw" | "clarify_ask" | "clarify_answer" | "accept" | PM.PremiseEventKind;
export const ACT_KINDS: readonly ActKind[] = ["open", "amend", "priority", "scope", "withdraw", "clarify_ask", "clarify_answer", "accept", ...PM.PREMISE_EVENTS];

export type ActInput = {
  q?: string;
  text?: string;
  why?: string;
  neutral?: string;
  objective?: string;
  objective_text?: string;
  parent?: string;
  materiality?: string;
  priority?: string;
  reason?: string;
  expects?: string;
  /** true or false (yes, no): whether the question asks for a complete set; absent, its words decide. */
  completeness?: boolean | string;
  /** What the question takes as happened ("X happened"): its answer is reviewed against "the question's premise is not supported". */
  presumes?: string;
  /** true or false (yes, no): the question must be established, or (on an amend, with why) the requirement is released. The operator's or an examiner's. */
  must_establish?: boolean | string;
  hints?: unknown;
  attachments?: unknown;
  suggested_to?: string;
  deadline?: string;
  submission?: string;
  source_entry?: string;
  expected_rev?: number | string;
  scope?: string;
  lead?: string;
  clarify?: string;
  what?: string;
  answer?: string;
  /** An acceptance's (bounded, not_determinable), or a premise admission's (given, supplied_assertion). */
  as?: string;
  /** A premise act's: the premise acted on (P-<n>). */
  p?: string;
  /** A premise's: where its words stand (the brief's page and line, a ref, E-<seq>, the goal). */
  locator?: string;
  /** A premise the operator adds: given (the default), supplied_assertion or proposition_under_test. */
  class?: string;
  /** A premise's scope: {entities, times, questions}. */
  premise_scope?: unknown;
};

/** An act checked and put in its final words, ready to be signed and committed. */
export type PreparedAct = { ev: ActKind; q?: string; act: QuestionAct; origin: QuestionOrigin; by: string };

/**
 * Check an act's own words (what does not need the register's lock) and put
 * it in the form it will be recorded in: what a signature covers is exactly
 * what is committed.
 */
export async function prepareAct(sandboxRoot: string, actor: Actor, ev: ActKind, input: ActInput): Promise<{ ok: true; prepared: PreparedAct } | Fail> {
  if (!ACT_KINDS.includes(ev)) return { ok: false, reason: `an act is one of ${ACT_KINDS.join(", ")}` };
  const origin = originOf(actor, actor.kind === "agent" && input.source_entry ? String(input.source_entry).trim().toUpperCase() : undefined);
  if (actor.kind === "agent" && input.source_entry && !/^E-[1-9]\d{0,5}$/.test(origin.source_entry ?? "")) return { ok: false, reason: `source_entry names the entry that raised the question, E-<seq> (got ${JSON.stringify(input.source_entry)})` };
  const early = refusalFor(ev, origin, null);
  if (early) return { ok: false, reason: early };
  const by = actor.kind === "agent" ? actor.agent : "operator";
  const act: QuestionAct = {};
  let q: string | undefined;
  if (ev !== "open" && !PM.isPremiseEvent(ev)) {
    const r = input.lead && ev === "scope" ? null : qRef(input.q);
    if (r && !r.ok) return r;
    if (r) q = r.id;
  }
  const sensitive: Array<[string, string | undefined]> = [];
  const expectedRev = (): { ok: true; value?: number } | Fail => {
    if (input.expected_rev === undefined || input.expected_rev === null || String(input.expected_rev).trim() === "") return { ok: true };
    const n = Number(input.expected_rev);
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `expected_rev is the revision you read, a whole number (got ${JSON.stringify(input.expected_rev)})` };
    return { ok: true, value: n };
  };
  const completeness = ((): { ok: true; value?: boolean } | Fail => {
    const v = input.completeness;
    if (v === undefined || v === null || v === "") return { ok: true };
    if (typeof v === "boolean") return { ok: true, value: v };
    const t = String(v).trim().toLowerCase();
    if (["true", "yes"].includes(t)) return { ok: true, value: true };
    if (["false", "no"].includes(t)) return { ok: true, value: false };
    return { ok: false, reason: `completeness is true or false: whether the question asks for a complete set (every one, all, each, a complete list) (got ${JSON.stringify(v)})` };
  })();
  if (!completeness.ok) return completeness;
  const presumes = bounded("presumes", input.presumes, QUESTION_PRESUMES_MAX, false);
  if (!presumes.ok) return { ok: false, reason: `${presumes.reason}: what the question takes as happened, in one sentence ("the drive was wiped")` };
  if (presumes.value && !["open", "amend", "clarify_ask"].includes(ev)) return { ok: false, reason: "presumes is said when a question is opened, amended, or (by an agent) with a clarification" };
  // Whether the question must be established (docs/adr/0013): the definition of done is the goal's and the operator's, never an agent's.
  const required = ((): { ok: true; value?: boolean } | Fail => {
    const v = input.must_establish;
    if (v === undefined || v === null || v === "") return { ok: true };
    if (typeof v === "boolean") return { ok: true, value: v };
    const t = String(v).trim().toLowerCase();
    if (["true", "yes"].includes(t)) return { ok: true, value: true };
    if (["false", "no"].includes(t)) return { ok: true, value: false };
    return { ok: false, reason: `must_establish is true or false: whether the question must be established (got ${JSON.stringify(v)})` };
  })();
  if (!required.ok) return required;
  if (required.value !== undefined) {
    if (ev !== "open" && ev !== "amend") return { ok: false, reason: "must_establish is said when a question is opened or amended" };
    if (!authority(origin)) return { ok: false, reason: `${originWords(origin)}: requiring a question to be established is the examiner's or the operator's (or the goal's, in its Must establish section), as accepting its limits is` };
    if (ev === "open" && required.value === false) return { ok: false, reason: "a new question is not required to be established unless you say so: leave must_establish out" };
    if (ev === "open" && input.materiality === "background") return { ok: false, reason: "a question that must be established is material: the finish line waits for it (materiality material, or leave must_establish out)" };
    if (ev === "amend" && required.value === false && !String(input.why ?? "").trim()) return { ok: false, reason: "a release of the requirement says why (why): it is on the record beside who required it" };
  }
  switch (ev) {
    case "open": {
      const text = bounded("text", input.text, QUESTION_TEXT_MAX, true);
      if (!text.ok) return text;
      const why = bounded("why", input.why, QUESTION_WHY_MAX, true);
      if (!why.ok) return why;
      const neutral = bounded("neutral", input.neutral, QUESTION_TEXT_MAX, false);
      if (!neutral.ok) return neutral;
      const materiality = oneOf("materiality", input.materiality, MATERIALITY);
      if (!materiality.ok) return materiality;
      if (actor.kind === "agent" && !materiality.value) return { ok: false, reason: "materiality is required: material (the case needs its answer) or background (worth knowing; the finish line does not wait for it)" };
      const priority = oneOf("priority", input.priority, PRIORITIES);
      if (!priority.ok) return priority;
      const reason = bounded("reason", input.reason, QUESTION_WHY_MAX, false);
      if (!reason.ok) return reason;
      if (priority.value === "urgent" && !reason.value) return { ok: false, reason: "an urgent question says why it is urgent (reason); urgency changes the order it is offered in and nothing else" };
      if (priority.value === "urgent" && actor.kind === "agent") return { ok: false, reason: "urgency is the asker's or the operator's to set, not an agent's" };
      const expects = oneOf("expects", input.expects, EXPECTS);
      if (!expects.ok) return expects;
      const hints = await checkHints(sandboxRoot, input.hints);
      if (!hints.ok) return hints;
      const attachments = await checkAttachments(sandboxRoot, input.attachments);
      if (!attachments.ok) return attachments;
      const objective = String(input.objective ?? "").trim();
      const objectiveText = bounded("objective_text", input.objective_text, QUESTION_WHY_MAX, false);
      if (!objectiveText.ok) return objectiveText;
      if (objective && objective !== "new" && !OBJECTIVE_ID.test(objective)) return { ok: false, reason: `objective names one of the case's objectives (O-1), or "new" with objective_text (got ${JSON.stringify(objective)})` };
      if (objective === "new" && !objectiveText.value) return { ok: false, reason: 'objective "new" needs objective_text: the objective the question would add to the case' };
      if (objective === "new" && actor.kind === "agent") return { ok: false, reason: "an agent works inside the case's objectives: name one (objective) or the question this follows (parent); a new objective is the examiner's or the operator's" };
      if (objective !== "new" && objectiveText.value) return { ok: false, reason: 'objective_text comes with objective "new"' };
      const parent = input.parent ? qRef(input.parent) : null;
      if (parent && !parent.ok) return parent;
      const suggested = String(input.suggested_to ?? "").trim();
      if (suggested) {
        const team = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
        if (!team.includes(suggested)) return { ok: false, reason: `suggested_to names a seat of this run (${team.join(", ") || "none"}), got ${JSON.stringify(suggested)}` };
      }
      const deadline = String(input.deadline ?? "").trim();
      if (deadline && !Number.isFinite(Date.parse(deadline))) return { ok: false, reason: `deadline is a date and time (ISO 8601), got ${JSON.stringify(deadline)}` };
      const submission = String(input.submission ?? "").trim();
      if (submission && !/^[A-Za-z0-9._-]{1,100}$/.test(submission)) return { ok: false, reason: "submission is a token of up to 100 letters, digits, dots, dashes or underscores (the same token twice is one question)" };
      Object.assign(act, {
        text: text.value,
        why: why.value,
        ...(neutral.value ? { neutral: neutral.value } : {}),
        ...(objective ? { objective } : {}),
        ...(objectiveText.value ? { objective_text: objectiveText.value } : {}),
        ...(parent?.ok ? { parent: parent.id } : {}),
        materiality: materiality.value ?? "material",
        priority: priority.value ?? "normal",
        ...(reason.value && priority.value === "urgent" ? { reason: reason.value } : {}),
        ...(expects.value ? { expects: expects.value } : {}),
        ...(completeness.value !== undefined ? { completeness: completeness.value } : {}),
        ...(presumes.value ? { presumes: presumes.value } : {}),
        ...(required.value ? { must_establish: true } : {}),
        ...(hints.hints.length ? { hints: hints.hints } : {}),
        ...(attachments.attachments.length ? { attachments: attachments.attachments } : {}),
        ...(suggested ? { suggested_to: suggested } : {}),
        ...(deadline ? { deadline: new Date(Date.parse(deadline)).toISOString() } : {}),
        ...(submission ? { submission } : {}),
      });
      sensitive.push(["text", act.text], ["why", act.why], ["neutral", act.neutral], ["objective_text", act.objective_text], ["reason", act.reason], ["presumes", act.presumes], ...hints.hints.map((h): [string, string | undefined] => ["a hint's value", h.value]));
      break;
    }
    case "amend": {
      const rev = expectedRev();
      if (!rev.ok) return rev;
      if (rev.value === undefined) return { ok: false, reason: "an amendment names the revision it amends (expected_rev): an amendment against a revision somebody else has since replaced is refused, not merged" };
      const text = bounded("text", input.text, QUESTION_TEXT_MAX, false);
      if (!text.ok) return text;
      const why = bounded("why", input.why, QUESTION_WHY_MAX, false);
      if (!why.ok) return why;
      const neutral = bounded("neutral", input.neutral, QUESTION_TEXT_MAX, false);
      if (!neutral.ok) return neutral;
      const materiality = oneOf("materiality", input.materiality, MATERIALITY);
      if (!materiality.ok) return materiality;
      const expects = oneOf("expects", input.expects, EXPECTS);
      if (!expects.ok) return expects;
      const hints = input.hints !== undefined ? await checkHints(sandboxRoot, input.hints) : null;
      if (hints && !hints.ok) return hints;
      const attachments = input.attachments !== undefined ? await checkAttachments(sandboxRoot, input.attachments) : null;
      if (attachments && !attachments.ok) return attachments;
      const deadline = input.deadline === undefined ? undefined : String(input.deadline).trim();
      if (deadline && !Number.isFinite(Date.parse(deadline))) return { ok: false, reason: `deadline is a date and time (ISO 8601), got ${JSON.stringify(deadline)}` };
      const suggested = input.suggested_to === undefined ? undefined : String(input.suggested_to).trim();
      if (suggested) {
        const team = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
        if (!team.includes(suggested)) return { ok: false, reason: `suggested_to names a seat of this run (${team.join(", ") || "none"}), got ${JSON.stringify(suggested)}` };
      }
      Object.assign(act, {
        expected_rev: rev.value,
        ...(text.value ? { text: text.value } : {}),
        ...(why.value ? { why: why.value } : {}),
        ...(neutral.value ? { neutral: neutral.value } : {}),
        ...(materiality.value ? { materiality: materiality.value } : {}),
        ...(expects.value ? { expects: expects.value } : {}),
        ...(completeness.value !== undefined ? { completeness: completeness.value } : {}),
        ...(presumes.value ? { presumes: presumes.value } : {}),
        ...(required.value !== undefined ? { must_establish: required.value } : {}),
        ...(hints?.ok ? { hints: hints.hints } : {}),
        ...(attachments?.ok ? { attachments: attachments.attachments } : {}),
        ...(deadline !== undefined ? { deadline: deadline ? new Date(Date.parse(deadline)).toISOString() : "" } : {}),
        ...(suggested !== undefined ? { suggested_to: suggested } : {}),
      });
      const changes = Object.keys(act).filter((k) => k !== "expected_rev" && k !== "why");
      if (!changes.length) return { ok: false, reason: "an amendment changes something: text (a new revision), neutral, materiality, expects, completeness, presumes, must_establish, hints, attachments, deadline or suggested_to" };
      sensitive.push(["text", act.text], ["why", act.why], ["neutral", act.neutral], ["presumes", act.presumes], ...(hints?.ok ? hints.hints.map((h): [string, string | undefined] => ["a hint's value", h.value]) : []));
      break;
    }
    case "priority": {
      const priority = oneOf("priority", input.priority, PRIORITIES);
      if (!priority.ok) return priority;
      if (!priority.value) return { ok: false, reason: "priority is urgent or normal" };
      const reason = bounded("reason", input.reason, QUESTION_WHY_MAX, priority.value === "urgent");
      if (!reason.ok) return { ok: false, reason: priority.value === "urgent" ? "an urgent question says why it is urgent (reason)" : reason.reason };
      const rev = expectedRev();
      if (!rev.ok) return rev;
      Object.assign(act, { priority: priority.value, ...(reason.value ? { reason: reason.value } : {}), ...(rev.value ? { expected_rev: rev.value } : {}) });
      sensitive.push(["reason", act.reason]);
      break;
    }
    case "scope": {
      const scope = oneOf("scope", input.scope, SCOPES);
      if (!scope.ok) return scope;
      if (!scope.value || scope.value === "proposed") return { ok: false, reason: "scope is in_scope (admit it) or excluded (keep it out of the case), with why" };
      const why = bounded("why", input.why, QUESTION_WHY_MAX, true);
      if (!why.ok) return why;
      const lead = input.lead ? String(input.lead).trim().toUpperCase() : "";
      if (lead && !L.LEAD_ID.test(lead)) return { ok: false, reason: `a triaged lead is named L-<n> (got ${JSON.stringify(input.lead)})` };
      if (!lead && !q) return { ok: false, reason: "scope names a question (Q-<n>) or a lead in the triage queue (L-<n>)" };
      const rev = expectedRev();
      if (!rev.ok) return rev;
      Object.assign(act, { scope: scope.value, why: why.value, ...(lead ? { lead } : {}), ...(rev.value ? { expected_rev: rev.value } : {}) });
      sensitive.push(["why", act.why]);
      break;
    }
    case "withdraw": {
      const why = bounded("why", input.why, QUESTION_WHY_MAX, true);
      if (!why.ok) return { ok: false, reason: "a withdrawal says why (why): the question and what was found for it stay on the record" };
      const rev = expectedRev();
      if (!rev.ok) return rev;
      Object.assign(act, { why: why.value, ...(rev.value ? { expected_rev: rev.value } : {}) });
      sensitive.push(["why", act.why]);
      break;
    }
    case "clarify_ask": {
      const what = bounded("what_is_unclear", input.what, QUESTION_WHY_MAX, true);
      if (!what.ok) return what;
      Object.assign(act, { what: what.value, ...(presumes.value ? { presumes: presumes.value } : {}) });
      sensitive.push(["what_is_unclear", act.what], ["presumes", act.presumes]);
      break;
    }
    case "clarify_answer": {
      const c = String(input.clarify ?? "").trim().toUpperCase();
      if (!CLARIFY_ID.test(c)) return { ok: false, reason: `a clarification is named C-<n>, as its request says (got ${JSON.stringify(input.clarify)})` };
      const answer = bounded("the answer", input.answer, QUESTION_TEXT_MAX, true);
      if (!answer.ok) return answer;
      Object.assign(act, { clarify: c, answer: answer.value });
      sensitive.push(["the answer", act.answer]);
      break;
    }
    case "accept": {
      const as = oneOf("as", input.as, ACCEPT_AS);
      if (!as.ok) return as;
      if (!as.value) return { ok: false, reason: "an acceptance says what it accepts: bounded (the examination as far as it went) or not_determinable" };
      const why = bounded("why", input.why, QUESTION_WHY_MAX, true);
      if (!why.ok) return why;
      const rev = expectedRev();
      if (!rev.ok) return rev;
      if (rev.value === undefined) return { ok: false, reason: "an acceptance names the revision it accepts (expected_rev): it holds for that revision only" };
      Object.assign(act, { as: as.value, why: why.value, expected_rev: rev.value });
      sensitive.push(["why", act.why]);
      break;
    }
    case "premise_add":
    case "premise_propose": {
      const agent = ev === "premise_propose";
      const text = bounded("text", input.text, PM.PREMISE_TEXT_MAX, true);
      if (!text.ok) return { ok: false, reason: `${text.reason}: the premise's words, verbatim from where they stand` };
      const locator = bounded("locator", input.locator, PM.PREMISE_LOCATOR_MAX, agent);
      if (!locator.ok) return { ok: false, reason: agent ? `${locator.reason}: where its words stand (E-<seq> of the entry you read it in, a ref such as input:<path> with the page or line, or the goal's words)` : locator.reason };
      const why = bounded("why", input.why, QUESTION_WHY_MAX, agent);
      if (!why.ok) return { ok: false, reason: agent ? `${why.reason}: why the case's answers rest on it` : why.reason };
      const cls = oneOf("class", input.class, PM.PREMISE_CLASSES);
      if (!cls.ok) return cls;
      if (agent && cls.value && cls.value !== "proposition_under_test") return { ok: false, reason: "an agent's premise is a proposition under test until the operator admits it (swarm.sh question <run> premise admit P-<n> --as given|supplied_assertion): propose it without a class" };
      const scope = PM.checkScope(input.premise_scope);
      if (!scope.ok) return scope;
      const premise: PM.PremiseAct = { text: text.value, ...(locator.value ? { locator: locator.value } : {}), ...(!agent && cls.value ? { class: cls.value } : {}), ...(Object.keys(scope.scope).length ? { scope: scope.scope } : {}) };
      Object.assign(act, { premise, ...(why.value ? { why: why.value } : {}) });
      sensitive.push(["text", text.value], ["locator", locator.value], ["why", why.value], ...(scope.scope.entities ?? []).map((x): [string, string] => ["an entity of its scope", x]));
      break;
    }
    case "premise_revise":
    case "premise_admit":
    case "premise_withdraw": {
      const id = pRef(input.p);
      if (!id.ok) return id;
      const why = bounded("why", input.why, QUESTION_WHY_MAX, true);
      if (!why.ok) return { ok: false, reason: `${why.reason}: why the premise ${ev === "premise_revise" ? "is revised" : ev === "premise_admit" ? "is admitted" : "is withdrawn"}` };
      const rev = expectedRev();
      if (!rev.ok) return rev;
      if (ev === "premise_revise") {
        if (rev.value === undefined) return { ok: false, reason: "a revision names the revision it revises (expected_rev, --expect-rev): one against a revision somebody else has since replaced is refused, not merged" };
        const text = bounded("text", input.text, PM.PREMISE_TEXT_MAX, false);
        if (!text.ok) return text;
        const locator = bounded("locator", input.locator, PM.PREMISE_LOCATOR_MAX, false);
        if (!locator.ok) return locator;
        const scope = input.premise_scope !== undefined ? PM.checkScope(input.premise_scope) : null;
        if (scope && !scope.ok) return scope;
        if (!text.value && !locator.value && !scope) return { ok: false, reason: "a revision changes something: the premise's words (text), where they stand (locator), or its scope" };
        const premise: PM.PremiseAct = { id: id.id, ...(text.value ? { text: text.value } : {}), ...(locator.value ? { locator: locator.value } : {}), ...(scope?.ok ? { scope: scope.scope } : {}) };
        Object.assign(act, { premise, why: why.value, expected_rev: rev.value });
        sensitive.push(["text", text.value], ["locator", locator.value], ...((scope?.ok ? scope.scope.entities : undefined) ?? []).map((x): [string, string] => ["an entity of its scope", x]));
      } else if (ev === "premise_admit") {
        const as = oneOf("as", input.as, PM.ADMIT_AS);
        if (!as.ok) return as;
        if (!as.value) return { ok: false, reason: "an admission says what the premise becomes: given (not proved again) or supplied_assertion (assumed as the one who asserted it said it)" };
        const premise: PM.PremiseAct = { id: id.id, as: as.value };
        Object.assign(act, { premise, why: why.value, ...(rev.value ? { expected_rev: rev.value } : {}) });
      } else {
        const premise: PM.PremiseAct = { id: id.id };
        Object.assign(act, { premise, why: why.value, ...(rev.value ? { expected_rev: rev.value } : {}) });
      }
      sensitive.push(["why", why.value]);
      break;
    }
  }
  const leak = await sensitiveRefusal(sandboxRoot, sensitive);
  if (leak) return { ok: false, reason: leak };
  return { ok: true, prepared: { ev, ...(q ? { q } : {}), act, origin, by } };
}

/**
 * What a person signs for an act: the run, the act's kind, the question it
 * acts on (none for an open, whose number is the register's), what they said
 * and who they say they are, canonical. The `sign` event after the act
 * carries the signature over these bytes and names the act's hash.
 */
export function statementOf(p: PreparedAct, run: string): string {
  const opens = p.ev === "open" || p.ev === "premise_add" || p.ev === "premise_propose";
  return JSON.stringify(P.canonicalValue({ namespace: QUESTION_NAMESPACE, run, ev: p.ev, target: opens ? null : (p.q ?? p.act.premise?.id ?? p.act.lead ?? null), act: p.act, origin: p.origin }));
}

/** The statement an act on the chain was signed as, rebuilt from the chain. */
export function statementOfEvent(e: QuestionEvent, run: string): string {
  return statementOf({ ev: e.ev as ActKind, ...(e.q ? { q: e.q } : {}), act: e.act ?? {}, origin: e.origin ?? { kind: "analyst" }, by: e.by }, run);
}

export type ActResult = {
  ok: true;
  q?: string;
  /** A premise act's premise (P-<n>), and its class after the act. */
  p?: string;
  class?: PM.PremiseClass;
  rev?: number;
  seq: number;
  hash: string;
  /** The same submission again: nothing was written; the question it made is named. */
  duplicate?: true;
  scope?: Scope;
  scope_why?: string;
  after_done?: true;
  objective_created?: string;
  clarify?: string;
  closed_leads?: string[];
  triaged?: string[];
  signed?: { seq: number };
  leading_forms?: string[];
  /** An acceptance: what the finish line still holds on the question after it (the defects an acceptance never excuses), each in words; empty when nothing. */
  still_held?: string[];
  /** What the act implies could not be made in its hold of the lock: made at the next act or header. */
  effects_pending?: string;
};

type Commit = { append: QuestionDraft[]; leads?: L.LeadDraft[]; result: Omit<ActResult, "seq" | "hash" | "signed"> | Fail };

/**
 * A lead's standing findings: its jobs' interpretations that are findings,
 * the finding it was opened from (record(kind=finding, opens), origin E-n),
 * the findings it needs, and the finding it was closed resolved on. Any of
 * them makes the lead one that found or rests on something, which a
 * withdrawal sends to triage instead of closing.
 */
export function leadFindings(l: L.Lead, leads: L.LeadsState, ledger: L.LedgerView): number[] {
  const out = new Set<number>();
  const standingFinding = (seq: number) => {
    const e = ledger.bySeq.get(seq);
    if (e?.kind === "finding" && !ledger.replaced.has(e.seq)) out.add(e.seq);
  };
  const origin = /^E-(\d+)$/i.exec(l.origin.trim());
  if (origin) standingFinding(Number(origin[1]));
  for (const n of l.needs) {
    const m = /^E-(\d+)$/.exec(n);
    if (m) standingFinding(Number(m[1]));
  }
  for (const j of l.jobs) {
    for (const i of leads.interpretations.get(j) ?? []) {
      const e = ledger.bySeq.get(i.entry);
      if (e?.kind === "finding" && !ledger.replaced.has(e.seq)) out.add(e.seq);
    }
  }
  const m = l.closed ? /^E-(\d+)$/.exec(l.closed.ref) : null;
  if (m) {
    const e = ledger.bySeq.get(Number(m[1]));
    if (e?.kind === "finding" && !ledger.replaced.has(e.seq)) out.add(e.seq);
  }
  return [...out].sort((a, b) => a - b);
}

async function commitUnderLock(sandboxRoot: string, p: PreparedAct, snap: QuestionsSnapshot): Promise<Commit> {
  const fail = (reason: string): Commit => ({ append: [], result: { ok: false, reason } });
  const o = p.origin;
  const who = originWords(o);
  if (PM.isPremiseEvent(p.ev)) return commitPremise(p, snap);
  const q = p.q ? snap.state.questions.get(p.q) ?? null : null;
  if (p.ev !== "open" && !(p.ev === "scope" && p.act.lead)) {
    if (!q) return fail(`${p.q} is not in the question register`);
    const refused = refusalFor(p.ev, o, q);
    if (refused) return fail(refused);
    if (q.withdrawn && p.ev !== "clarify_answer") return fail(`${q.id} was withdrawn by ${originWords(q.withdrawn.origin)} at ${q.withdrawn.at} (${q.withdrawn.why}); it takes no further act`);
    if (p.act.expected_rev !== undefined && p.act.expected_rev !== q.rev) {
      const last = q.revisions.at(-1);
      return fail(`${q.id} is at revision ${q.rev}${last ? ` (by ${originWords(last.origin)} at ${last.at})` : ""}, not ${p.act.expected_rev}: read it again (questions show ${q.id}) and act against revision ${q.rev}`);
    }
  }
  const base = { by: p.by, origin: o };
  switch (p.ev) {
    case "open": {
      // The same submission token again is the same question: named, not made twice.
      if (p.act.submission) {
        const same = [...snap.state.questions.values()].find((x) => x.submission === p.act.submission && x.origin.person === o.person && x.origin.agent === o.agent);
        if (same) return { append: [], result: { ok: true, q: same.id, rev: same.rev, duplicate: true, scope: same.scope, scope_why: same.scope_why } };
      }
      const norm = (t: string) => t.replace(/\s+/g, " ").trim().toLowerCase();
      const twin = [...snap.state.questions.values()].find((x) => !x.withdrawn && x.scope !== "excluded" && norm(x.text) === norm(p.act.text ?? ""));
      if (twin) return fail(`${twin.id} asks this already, word for word (${originWords(twin.origin)}, ${twin.scope}): add to it with a hint or an amendment, or ask what is different`);
      const parent = p.act.parent ? snap.state.questions.get(p.act.parent) ?? null : null;
      if (p.act.parent && !parent) return fail(`parent ${p.act.parent} is not in the question register`);
      if (parent?.withdrawn) return fail(`parent ${parent.id} was withdrawn: a question does not follow a withdrawn one`);
      if (parent?.scope === "excluded") return fail(`parent ${parent.id} is excluded from the case`);
      const objective = p.act.objective && p.act.objective !== "new" ? p.act.objective : null;
      if (objective && !snap.state.objectives.has(objective)) return fail(`objective ${objective} is not one of the case's (${[...snap.state.objectives.keys()].join(", ") || "it declares none"})`);
      const parentIn = parent?.scope === "in_scope";
      let scope: Scope;
      let why: string;
      let created: string | undefined;
      const role = o.role;
      if (o.kind === "agent") {
        if (objective) [scope, why] = ["in_scope", `inside objective ${objective}`];
        else if (parentIn) [scope, why] = ["in_scope", `a follow-up of ${parent!.id}, which is in scope`];
        else [scope, why] = ["proposed", parent ? `a follow-up of ${parent.id}, which is ${parent.scope}: proposed, into the triage queue` : "names no objective and no parent in scope: proposed, into the triage queue"];
      } else if (role === "operator" || role === "examiner") {
        scope = "in_scope";
        why = `by the ${role}'s authority (${who})`;
        if (p.act.objective === "new") {
          const nums = [...snap.state.objectives.keys()].map((k) => Number(/^O-(\d+)$/.exec(k)?.[1] ?? 0));
          created = `O-${Math.max(0, ...nums) + 1}`;
          why = `scope expanded by ${o.name ?? o.person}: new objective ${created}`;
        }
      } else if (role === "analyst") {
        if (objective) [scope, why] = ["in_scope", `an analyst's question inside objective ${objective}`];
        else if (parentIn) [scope, why] = ["in_scope", `an analyst's follow-up of ${parent!.id}, which is in scope`];
        else [scope, why] = ["proposed", p.act.objective === "new" ? "it would add an objective to the case: proposed, for the examiner or the operator to admit" : "outside the case's objectives: proposed, for the examiner or the operator to admit"];
      } else if (role === "reviewer") [scope, why] = ["proposed", "a reviewer's query: proposed to the examiner"];
      else [scope, why] = ["proposed", "an observer's question: proposed, into the triage queue"];
      const nums = [...snap.state.questions.values()].map((x) => x.n);
      const id = `Q-${Math.max(0, ...nums) + 1}`;
      const afterDone = await P.swarmDoneExists(sandboxRoot);
      const lead = leadingForms(p.act.text ?? "");
      const append: QuestionDraft[] = [];
      if (created) append.push({ ...base, ev: "objective", objective: created, text: p.act.objective_text ?? "", why: `scope expanded by ${o.name ?? o.person}` });
      append.push({
        ...base,
        ev: "open",
        q: id,
        rev: 1,
        act: p.act,
        decided: {
          scope,
          scope_why: why,
          section: String(Number(id.slice(2))),
          leading_forms: lead,
          ...(completenessWords(p.act.text ?? "") ? { completeness: true } : {}),
          ...(created ? { objective_created: created } : {}),
          ...(role === "reviewer" ? { review_query: true } : {}),
          ...(afterDone ? { after_done: true } : {}),
        },
      });
      return {
        append,
        result: { ok: true, q: id, rev: 1, scope, scope_why: why, ...(afterDone ? { after_done: true as const } : {}), ...(created ? { objective_created: created } : {}), ...(lead.length ? { leading_forms: lead } : {}) },
      };
    }
    case "amend": {
      // Whether it must be established: required or released once; what stands already is said, not recorded again.
      if (p.act.must_establish !== undefined && p.act.must_establish === mustEstablish(q)) {
        const others = Object.keys(p.act).filter((k) => !["expected_rev", "why", "must_establish"].includes(k));
        if (!others.length) return fail(p.act.must_establish ? `${q!.id} must be established already (required by ${requiredByWords(q!)} at ${q!.must_establish!.at})` : `${q!.id} is not required to be established${q!.must_establish ? ` (released by ${originWords(q!.must_establish.origin)} at ${q!.must_establish.at})` : ""}`);
      }
      if ((p.act.must_establish ?? mustEstablish(q)) && (p.act.materiality ?? q!.materiality) !== "material") return fail(`a question that must be established is material: the finish line waits for it (${q!.id}${p.act.materiality ? " would be background" : " is background"}; release the requirement first, or make it material)`);
      const bump = p.act.text !== undefined && p.act.text !== q!.text;
      if (p.act.text !== undefined && !bump && Object.keys(p.act).filter((k) => !["expected_rev", "text", "why"].includes(k)).length === 0) return fail(`revision ${q!.rev} of ${q!.id} says this already`);
      if (bump) {
        const norm = (t: string) => t.replace(/\s+/g, " ").trim().toLowerCase();
        const twin = [...snap.state.questions.values()].find((x) => x.id !== q!.id && !x.withdrawn && x.scope !== "excluded" && norm(x.text) === norm(p.act.text ?? ""));
        if (twin) return fail(`${twin.id} asks this already, word for word: amend toward what is different, or withdraw one`);
      }
      const rev = bump ? q!.rev + 1 : q!.rev;
      const lead = bump ? leadingForms(p.act.text ?? "") : undefined;
      // A new revision after the run's done is new work, and the run is over: a follow-up for its continuation.
      const afterDone = bump && !q!.after_done && (await P.swarmDoneExists(sandboxRoot));
      // The act exactly as it was said (and signed): whether it makes a new revision is the harness's, in decided.
      return {
        append: [{ ...base, ev: "amend", q: q!.id, rev, act: p.act, decided: { ...(lead ? { leading_forms: lead } : {}), ...(bump ? { completeness: completenessWords(p.act.text ?? "") } : {}), revision: bump, ...(afterDone ? { after_done: true } : {}) } }],
        result: { ok: true, q: q!.id, rev, ...(lead?.length ? { leading_forms: lead } : {}), ...(afterDone ? { after_done: true as const } : {}) },
      };
    }
    case "priority": {
      if (q!.priority === p.act.priority && (q!.priority_reason ?? "") === (p.act.reason ?? "")) return fail(`${q!.id} is ${q!.priority} already`);
      return { append: [{ ...base, ev: "priority", q: q!.id, rev: q!.rev, act: p.act }], result: { ok: true, q: q!.id, rev: q!.rev } };
    }
    case "scope": {
      if (p.act.lead) {
        const refused = refusalFor("scope", o, null);
        if (refused) return fail(refused);
        const item = [...snap.state.triage].reverse().find((t) => t.lead === p.act.lead && !t.resolved);
        if (!item) return fail(`${p.act.lead} is not in the triage queue`);
        // Closing an excluded lead is the reconciliation's, in the same hold of the lock (and again after a crash).
        return { append: [{ ...base, ev: "scope", act: p.act, decided: { q: item.q } }], result: { ok: true } };
      }
      if (q!.scope === p.act.scope && !snap.state.triage.some((t) => t.q === q!.id && !t.resolved)) return fail(`${q!.id} is ${q!.scope} already`);
      if (q!.origin.kind === "goal" && p.act.scope === "excluded") return fail(`${q!.id} is a question of the goal: the goal's questions are the case's; withdraw it (with why) to take it off`);
      const append: QuestionDraft[] = [];
      let created: string | undefined;
      let why = `${p.act.scope === "in_scope" ? "admitted" : "excluded"} by ${who}: ${p.act.why}`;
      if (p.act.scope === "in_scope" && q!.objective_text && !q!.objective) {
        const nums = [...snap.state.objectives.keys()].map((k) => Number(/^O-(\d+)$/.exec(k)?.[1] ?? 0));
        created = `O-${Math.max(0, ...nums) + 1}`;
        append.push({ ...base, ev: "objective", objective: created, text: q!.objective_text, why: `scope expanded by ${o.name ?? o.person}, admitting ${q!.id}` });
        why = `admitted by ${who}, scope expanded: new objective ${created}: ${p.act.why}`;
      }
      // An admission after the run's done makes no work of this run: it is a follow-up for its continuation.
      const afterDone = p.act.scope === "in_scope" && !q!.after_done && (await P.swarmDoneExists(sandboxRoot));
      append.push({ ...base, ev: "scope", q: q!.id, rev: q!.rev, act: p.act, decided: { scope_why: why, from: q!.scope, ...(created ? { objective_created: created } : {}), ...(afterDone ? { after_done: true } : {}) } });
      return { append, result: { ok: true, q: q!.id, rev: q!.rev, scope: p.act.scope, scope_why: why, ...(created ? { objective_created: created } : {}), ...(afterDone ? { after_done: true as const } : {}) } };
    }
    case "withdraw": {
      // Its leads closed withdrawn, a lead that found something and its
      // follow-ups sent to triage: the reconciliation's, in the same hold of
      // the lock, and again at the next act or header if this one dies first.
      return { append: [{ ...base, ev: "withdraw", q: q!.id, rev: q!.rev, act: p.act }], result: { ok: true, q: q!.id, rev: q!.rev } };
    }
    case "clarify_ask": {
      if (q!.origin.kind === "agent") return fail(`${q!.id} was asked by ${q!.origin.agent}: ask on the board`);
      // What the question presumes is recorded once by an agent, and never over the asker's word: ask about it instead.
      if (p.act.presumes && q!.presumes) return fail(`${q!.id} presumes already, as ${originWords(q!.presumes.origin)} recorded it: "${q!.presumes.text}". The recorded word stands: ask what is unclear about it without presumes`);
      const n = [...snap.state.questions.values()].reduce((m, x) => m + x.clarifications.length, 0) + 1;
      const id = `C-${n}`;
      const to = q!.origin.kind === "goal" ? "operator" : posterOf(q!.origin);
      return { append: [{ ...base, ev: "clarify_ask", q: q!.id, rev: q!.rev, act: { ...p.act, clarify: id }, decided: { to } }], result: { ok: true, q: q!.id, rev: q!.rev, clarify: id } };
    }
    case "clarify_answer": {
      const c = q!.clarifications.find((x) => x.id === p.act.clarify);
      if (!c) return fail(`${p.act.clarify} is not a clarification asked on ${q!.id} (${q!.clarifications.map((x) => x.id).join(", ") || "none was"})`);
      if (c.answer) return fail(`${c.id} was answered by ${originWords(c.answer.origin)} at ${c.answer.at}`);
      return { append: [{ ...base, ev: "clarify_answer", q: q!.id, rev: q!.rev, act: p.act, decided: { asker: c.by } }], result: { ok: true, q: q!.id, rev: q!.rev, clarify: c.id } };
    }
    case "accept": {
      if (q!.scope !== "in_scope") return fail(`${q!.id} is ${q!.scope}: only a question in the case is accepted`);
      const ls = await L.leadsSnapshot(sandboxRoot);
      const open = [...ls.state.leads.values()].filter((l) => !l.closed && l.answers.includes(q!.section));
      if (open.length) return fail(`a route is still open on ${q!.id}: ${open.map((l) => `${l.id} (${l.holder ? `held by ${l.holder}` : "unheld"})`).join(", ")}; it is accepted once its leads are closed`);
      // The acceptance comes after the negative bar, never instead of it: a
      // negative nobody else has reviewed is reviewed first.
      const vc = await viewContext(sandboxRoot);
      const v = viewQuestion(q!, vc);
      if (v.answer?.negative && !v.answer.negative.reviewed && q!.materiality === "material") {
        return fail(`${q!.id}'s answer E-${v.answer.seq} is a negative (unreviewed): ${NB.resultWords(v.answer.result)}, and no other seat has reviewed it. An acceptance takes the examination's limits as they stand after review; it never stands in for one. It is accepted once a seat that recorded neither the answer nor its coverage record has attested it with review`);
      }
      // Taken as the ledger stands now (its head): evidence added before
      // this is excused by it, never evidence added after (acceptanceExcuses).
      // The reply says what the finish line still holds on the question.
      const ledgerSeq = vc.ledger.entries.reduce((m, e) => Math.max(m, e.seq), 0);
      const SW = await import("./store-sweep.ts");
      const gate = P.ledgerGate({
        entries: vc.ledger.entries,
        attestations: await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]),
        disputes: vc.ledger.disputes ?? [],
        sections: [`question:${q!.section}`],
        bar: () => ({ material: q!.materiality === "material", existence: q!.expects === "existence", completeness: q!.completeness }),
        sweeps: await SW.readSweeps(sandboxRoot).catch(() => []),
        ...(vc.questions.state.premises.size ? { premises: vc.questions.state.premises } : {}),
      });
      const stillHeld = gate.defects.filter((d) => d.section === `question:${q!.section}` && !P.acceptanceExcuses(d, ledgerSeq)).map((d) => `${d.code}: ${d.what}. Fix: ${d.fix}`);
      return {
        append: [{ ...base, ev: "accept", q: q!.id, rev: q!.rev, act: p.act, decided: { rev: q!.rev, outcome: "examination_limited", ledger_seq: ledgerSeq, ...(v.answer ? { answer: `E-${v.answer.seq}`, answer_hash: vc.ledger.bySeq.get(v.answer.seq)?.hash ?? null, ...(v.answer.result ? { result: v.answer.result } : {}) } : { answer: null, answer_hash: null }) } }],
        result: { ok: true, q: q!.id, rev: q!.rev, still_held: stillHeld },
      };
    }
  }
}

/**
 * A premise act under the lock (premises.ts): an add or a proposal is a new
 * P-<n> (a given unless the operator says otherwise; an agent's, a
 * proposition under test), never twice with the same words; a revision is
 * against the revision it read and changes something; an admission changes
 * a premise's class; a withdrawal needs its why. The questions a scope names
 * are in the register. Nothing else is changed: answers citing an earlier
 * revision are warned of, not rewritten.
 */
function commitPremise(p: PreparedAct, snap: QuestionsSnapshot): Commit {
  const fail = (reason: string): Commit => ({ append: [], result: { ok: false, reason } });
  const o = p.origin;
  const who = originWords(o);
  const base = { by: p.by, origin: o };
  const reg = snap.state.premises;
  const pa = p.act.premise ?? {};
  const unknownQs = (pa.scope?.questions ?? []).filter((id) => !snap.state.questions.has(id));
  if (unknownQs.length) return fail(`scope.questions names ${unknownQs.join(", ")}, not in the question register (questions list names them)`);
  const norm = (t: string) => t.replace(/\s+/g, " ").trim().toLowerCase();
  if (p.ev === "premise_add" || p.ev === "premise_propose") {
    const twin = [...reg.values()].find((x) => !x.withdrawn && norm(x.text) === norm(pa.text ?? ""));
    if (twin) return fail(`${twin.id} says this already, word for word (${PM.premiseWords(twin)}): ${p.ev === "premise_propose" ? `cite it in an answer (premises [{id: "${twin.id}", rev: ${twin.rev}, stance}])` : `revise it (premise revise ${twin.id} --expect-rev ${twin.rev}) or admit it`}`);
    const id = `P-${Math.max(0, ...[...reg.values()].map((x) => x.n)) + 1}`;
    const cls: PM.PremiseClass = p.ev === "premise_propose" ? "proposition_under_test" : (pa.class ?? "given");
    const authority: PM.PremiseAuthority = p.ev === "premise_propose" ? "agent" : "operator";
    const locator = pa.locator ?? `stated by ${who} on the question register`;
    return { append: [{ ...base, ev: p.ev, p: id, rev: 1, act: p.act, decided: { class: cls, authority, locator } }], result: { ok: true, p: id, rev: 1, class: cls } };
  }
  const x = pa.id ? reg.get(pa.id) : undefined;
  if (!x) return fail(`${pa.id ?? "the premise"} is not in the premise register (questions premise list names them)`);
  if (x.withdrawn) return fail(`${x.id} was withdrawn by ${originWords(x.withdrawn.origin)} at ${x.withdrawn.at} (${x.withdrawn.why}); it takes no further act: add a new premise`);
  if (p.act.expected_rev !== undefined && p.act.expected_rev !== x.rev) {
    const last = x.revisions.at(-1);
    return fail(`${x.id} is at revision ${x.rev}${last ? ` (by ${originWords(last.origin)} at ${last.at})` : ""}, not ${p.act.expected_rev}: read it again (questions premise show ${x.id}) and act against revision ${x.rev}`);
  }
  switch (p.ev) {
    case "premise_revise": {
      const same = (a: unknown, b: unknown) => JSON.stringify(P.canonicalValue(a ?? {})) === JSON.stringify(P.canonicalValue(b ?? {}));
      const changes = (pa.text !== undefined && pa.text !== x.text) || (pa.locator !== undefined && pa.locator !== x.locator) || (pa.scope !== undefined && !same(pa.scope, x.scope));
      if (!changes) return fail(`revision ${x.rev} of ${x.id} says this already`);
      if (pa.text !== undefined) {
        const twin = [...reg.values()].find((y) => y.id !== x.id && !y.withdrawn && norm(y.text) === norm(pa.text ?? ""));
        if (twin) return fail(`${twin.id} says this already, word for word: revise toward what is different, or withdraw one`);
      }
      return { append: [{ ...base, ev: "premise_revise", p: x.id, rev: x.rev + 1, act: p.act, decided: { revision: true, from: x.rev } }], result: { ok: true, p: x.id, rev: x.rev + 1, class: x.class } };
    }
    case "premise_admit": {
      if (x.class === pa.as) return fail(`${x.id} is ${PM.classWords(x.class)} already`);
      return { append: [{ ...base, ev: "premise_admit", p: x.id, rev: x.rev, act: p.act, decided: { from: x.class, class: pa.as } }], result: { ok: true, p: x.id, rev: x.rev, class: pa.as } };
    }
    default:
      return { append: [{ ...base, ev: "premise_withdraw", p: x.id, rev: x.rev, act: p.act }], result: { ok: true, p: x.id, rev: x.rev, class: x.class } };
  }
}

/**
 * What the register's acts imply on both registers, derived and made good
 * under a lock the caller holds: every open lead that serves only withdrawn
 * questions closed `withdrawn`, unless it found or rests on a finding and is
 * material, when it goes to triage instead (a closed one that found
 * something too); a lead the triage excluded closed; and every follow-up of
 * a withdrawn question sent to triage. Idempotent: what was made already is
 * not made again. Run in the same hold as the act that implies it, and at
 * every later act and header, so a crash between the act and its effects
 * leaves them undone only until the next read.
 */
async function reconcileHeld(sandboxRoot: string, held: P.HeldLock): Promise<{ closed: string[]; triaged: string[] }> {
  const qs = await questionsSnapshot(sandboxRoot);
  const withdrawn = new Map<string, Question>();
  for (const q of qs.state.questions.values()) if (q.withdrawn) withdrawn.set(q.section, q);
  const excludedLeads = qs.state.triage.filter((t) => t.lead && t.resolved?.decision === "excluded");
  if (!withdrawn.size && !excludedLeads.length) return { closed: [], triaged: [] };
  const ls = await L.leadsSnapshot(sandboxRoot);
  const drafts: QuestionDraft[] = [];
  const leads: L.LeadDraft[] = [];
  const closed: string[] = [];
  const triaged: string[] = [];
  for (const l of ls.state.leads.values()) {
    const items = qs.state.triage.filter((t) => t.lead === l.id);
    const excluded = items.find((t) => t.resolved?.decision === "excluded");
    if (excluded) {
      if (!l.closed) {
        leads.push({ by: "system", ev: "close", lead: l.id, generation: l.generation, disposition: "withdrawn", ref: excluded.q ?? "", why: `excluded in the triage by ${originWords(excluded.resolved!.origin)}: ${excluded.resolved!.why}` });
        closed.push(l.id);
      }
      continue;
    }
    if (items.length || !l.answers.length || !l.answers.every((s) => withdrawn.has(s))) continue;
    const wq = withdrawn.get(l.answers[0])!;
    const found = leadFindings(l, ls.state, ls.ledger);
    if (l.material && found.length) {
      drafts.push({ by: "system", ev: "triage", q: wq.id, lead: l.id, cause: `${wq.id} was withdrawn, and ${l.id} holds ${found.map((n) => `E-${n}`).join(", ")}: keep it (in_scope) or close it (excluded)`, entries: found });
      triaged.push(l.id);
    } else if (!l.closed) {
      leads.push({ by: "system", ev: "close", lead: l.id, generation: l.generation, disposition: "withdrawn", ref: wq.id, why: `${wq.id} was withdrawn by ${originWords(wq.withdrawn!.origin)}: ${wq.withdrawn!.why}` });
      closed.push(l.id);
    }
  }
  for (const child of qs.state.questions.values()) {
    if (!child.parent || child.withdrawn || child.scope === "excluded") continue;
    const parent = qs.state.questions.get(child.parent);
    if (!parent?.withdrawn || qs.state.triage.some((t) => t.q === child.id && !t.lead)) continue;
    drafts.push({ by: "system", ev: "triage", q: child.id, cause: `its parent ${parent.id} was withdrawn: keep it in the case (in_scope) or exclude it` });
    triaged.push(child.id);
  }
  if (drafts.length) await appendQuestionEvents(sandboxRoot, drafts, held);
  if (leads.length) await L.appendLeadEventsHeld(sandboxRoot, leads, held);
  if (drafts.length || leads.length) await writeQuestionsMd(sandboxRoot).catch(() => undefined);
  return { closed, triaged };
}

/** Make good what the register's acts imply and is not done yet (reconcileHeld), taking the lock only when something could be due. */
export async function reconcile(sandboxRoot: string): Promise<{ closed: string[]; triaged: string[] }> {
  const qs = await questionsSnapshot(sandboxRoot);
  if (![...qs.state.questions.values()].some((q) => q.withdrawn) && !qs.state.triage.some((t) => t.lead && t.resolved?.decision === "excluded")) return { closed: [], triaged: [] };
  return L.withRegisters(sandboxRoot, (held) => reconcileHeld(sandboxRoot, held)).catch(() => ({ closed: [], triaged: [] }));
}

/**
 * A resume takes up the follow-ups: every question admitted, opened or
 * amended into new work after the run's done (after_done), and not
 * withdrawn, is this run's work again from the resumed segment on. One
 * `continue` event names them, the durable receipt; the follow-up marks stay
 * on the events that made them. Nothing to take up writes nothing.
 */
export async function continueFollowUps(sandboxRoot: string, o: { segment: number; by: string }): Promise<string[]> {
  return L.withRegisters(sandboxRoot, async (held) => {
    if (await P.swarmDoneExists(sandboxRoot)) throw new Error("the run is still marked done: the follow-ups are taken up once the resume has moved its done aside");
    const snap = await questionsSnapshot(sandboxRoot);
    if (!snap.state.chain.ok) throw new Error(`questions/questions.jsonl's chain is broken at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})`);
    const ids = [...snap.state.questions.values()].filter((q) => q.after_done && !q.withdrawn).map((q) => q.id);
    if (!ids.length) return [];
    await appendQuestionEvents(sandboxRoot, [{ by: "system", ev: "continue", questions: ids, why: `the run was resumed by ${o.by} (segment ${o.segment}): the follow-ups recorded after its done are its work now`, decided: { segment: o.segment } }], held);
    await writeQuestionsMd(sandboxRoot).catch(() => undefined);
    return ids;
  });
}

/**
 * Commit a prepared act under the registers' lock, with the register read
 * inside it. A signature, when given, is carried on the act's own event, so
 * no act on the chain says it is signed without its signature beside it.
 * What the act implies on the lead register (leads a withdrawal closes, a
 * triage) is made in the same hold (reconcileHeld), and completed at the
 * next act or header if the process dies between the two. Nothing is
 * published here: the caller acknowledges after this returns, and delivers
 * (deliverPending), so a crash between the two loses no question.
 */
export async function commitAct(sandboxRoot: string, p: PreparedAct, o: { signature?: ActSignature } = {}): Promise<ActResult | Fail> {
  if (o.signature && (p.origin.identity !== "signed" || !p.origin.person || o.signature.person !== p.origin.person || o.signature.fingerprint !== p.origin.fingerprint)) return { ok: false, reason: "a signature is the acting person's own, with the key their act names, on an act that says it is signed" };
  if (!o.signature && p.origin.identity === "signed") return { ok: false, reason: "an act that says it is signed carries its signature" };
  try {
    return await L.withRegisters(sandboxRoot, async (held) => {
      await ensureSeededHeld(sandboxRoot, held);
      // What an earlier act implied and a crash left undone, first.
      await reconcileHeld(sandboxRoot, held).catch(() => undefined);
      const snap = await questionsSnapshot(sandboxRoot);
      if (!snap.state.chain.ok) return { ok: false as const, reason: `questions/questions.jsonl's chain is broken at line ${snap.state.chain.broken_at} (${snap.state.chain.reason}): the register takes no act until the operator looks` };
      const c = await commitUnderLock(sandboxRoot, p, snap);
      if (!c.result.ok) return c.result;
      if (!c.append.length) {
        const last = snap.state.events.at(-1);
        return { ...c.result, seq: last?.seq ?? 0, hash: last?.hash ?? "" } as ActResult;
      }
      // The act's own event carries its signature: one line, written whole or not at all.
      const at = c.append.map((d) => d.ev).lastIndexOf(p.ev);
      const drafts = o.signature ? c.append.map((d, i) => (i === at ? { ...d, signature: o.signature } : d)) : c.append;
      const events = await appendQuestionEvents(sandboxRoot, drafts, held);
      const act = [...events].reverse().find((e) => e.ev === p.ev) ?? events.at(-1)!;
      // What it implies on both registers, now; a failure here leaves the act committed and the effects to the next read.
      let effects: { closed: string[]; triaged: string[] } | { error: string };
      try {
        effects = await reconcileHeld(sandboxRoot, held);
      } catch (err) {
        effects = { error: (err as Error).message };
      }
      await writeQuestionsMd(sandboxRoot).catch(() => undefined);
      const reported = "error" in effects ? { effects_pending: `${effects.error}: what the act implies is made at the next act or header` } : p.ev === "withdraw" || p.ev === "scope" ? { closed_leads: effects.closed, triaged: effects.triaged } : {};
      return { ...c.result, seq: act.seq, hash: act.hash, ...(o.signature ? { signed: { seq: act.seq } } : {}), ...reported } as ActResult;
    });
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** Prepare and commit in one step: an agent's act, or a person's that is not signed. */
/**
 * Whether an act would be admitted now, by the checks its commit makes
 * against the register as it stands, with nothing written and nothing
 * delivered: what a resume asks of each question it is given before
 * anything of the run moves (docs/adr/0013, "A resume refuses a question it
 * cannot admit"). The register may move before the act is made; the act is
 * checked again then.
 */
export async function checkAct(sandboxRoot: string, p: PreparedAct): Promise<{ ok: true } | Fail> {
  const c = await commitUnderLock(sandboxRoot, p, await questionsSnapshot(sandboxRoot));
  return c.result.ok ? { ok: true } : { ok: false, reason: c.result.reason };
}

export async function act(sandboxRoot: string, actor: Actor, ev: ActKind, input: ActInput): Promise<ActResult | Fail> {
  const prepared = await prepareAct(sandboxRoot, actor, ev, input);
  if (!prepared.ok) return prepared;
  return commitAct(sandboxRoot, prepared.prepared);
}

// --- delivery: after the chain write, never before ------------------------------------------------

/** The words that tie a board post to a question's revision: a delivery that finds them posted records that post, and posts nothing twice. */
export function postMarker(q: string, rev: number): string {
  return `${q} (revision ${rev})`;
}

/** Seats that can still work: on the team, neither done nor marked dead. */
async function liveSeats(sandboxRoot: string): Promise<string[]> {
  const ids = await P.teamIds(sandboxRoot).catch(() => [] as string[]);
  return ids.filter((id) => !existsSync(join(sandboxRoot, "done", "agents", `${id}.done`)) && !existsSync(join(sandboxRoot, "done", "agents", `${id}.dead`)));
}

const refPath = (r: string) => r.replace(/^input:/, "inputs/").replace(/^job:/, "store/jobs/").replace(/\/+$/, "");
function refsMeet(a: string, b: string): boolean {
  const x = refPath(a);
  const y = refPath(b);
  return x === y || x.startsWith(`${y}/`) || y.startsWith(`${x}/`);
}

/**
 * How suited each seat is to a question, from what it has already worked:
 * a hint that meets a ref of an entry it recorded (3 each), a lead it held
 * under a question of the same objective (2), a lead it held under the
 * question's parent or under a sibling (1). Generic: refs, objectives and
 * lead history, never a question's words.
 */
export function seatSuitability(q: Question, seats: string[], ctx: ViewContext): Map<string, { score: number; why: string[] }> {
  const out = new Map<string, { score: number; why: string[] }>();
  const held = new Map<string, Set<string>>();
  for (const e of ctx.leads.events) {
    const seat = e.ev === "claim" ? (e.holder ?? e.by) : e.ev === "open" && e.holder ? e.holder : null;
    if (!seat || !e.lead) continue;
    const l = ctx.leads.leads.get(e.lead);
    if (!l) continue;
    const set = held.get(seat) ?? new Set<string>();
    for (const s of l.answers) set.add(s);
    held.set(seat, set);
  }
  for (const seat of seats) {
    const why: string[] = [];
    let score = 0;
    const refs = ctx.ledger.entries.filter((e) => (e.authors ?? [e.by]).includes(seat)).flatMap((e) => e.refs ?? []);
    const hits = q.hints.filter((h) => refs.some((r) => refsMeet(r, h.ref)));
    if (hits.length) {
      score += 3 * hits.length;
      why.push(`your entries cite ${hits.map((h) => h.ref).join(", ")}`);
    }
    const sections = held.get(seat) ?? new Set<string>();
    const worked = [...sections].map((s) => ctx.questions.bySection.get(s)).filter((x): x is Question => Boolean(x));
    if (q.objective && worked.some((w) => w.objective === q.objective)) {
      score += 2;
      why.push(`you held leads under objective ${q.objective}`);
    }
    if (q.parent && worked.some((w) => w.id === q.parent || w.parent === q.parent)) {
      score += 1;
      why.push(`you held leads under ${q.parent}`);
    }
    out.set(seat, { score, why });
  }
  return out;
}

/** The seats in the order a question is offered to them: most suited first, then the one idle longest. */
function rankSeats(q: Question, idle: Array<{ agent: string; since: number }>, ctx: ViewContext): Array<{ agent: string; score: number; why: string[] }> {
  const s = seatSuitability(q, idle.map((x) => x.agent), ctx);
  return idle
    .map((x) => ({ agent: x.agent, since: x.since, ...(s.get(x.agent) ?? { score: 0, why: [] }) }))
    .sort((a, b) => b.score - a.score || a.since - b.since || a.agent.localeCompare(b.agent))
    .map(({ since: _s, ...rest }) => rest);
}

async function jobsOf(sandboxRoot: string): Promise<L.JobFacts[]> {
  return L.readJobs(sandboxRoot).catch(() => [] as L.JobFacts[]);
}

/** The board post that delivers a person's question: whole, with what the header and the tools say of it. */
export function questionPostBody(q: Question, qs: QuestionsSnapshot, o: { offerTo: string | null; first: boolean; hypotheses: number[] }): string {
  const amended = q.rev > 1;
  const lines: string[] = [];
  lines.push(`QUESTION ${postMarker(q.id, q.rev)}${amended ? ", AMENDED" : ""} from ${originWords(q.origin)}; answer it in section question:${q.section}.`);
  if (q.priority === "urgent") lines.push(`Urgent: ${q.priority_reason ?? ""}. Urgency orders the offers; it takes no job and no lead from anyone.`);
  if (q.objective) lines.push(`Objective: ${q.objective}${qs.state.objectives.get(q.objective) ? ` "${qs.state.objectives.get(q.objective)!.text}"` : ""}`);
  if (q.parent) lines.push(`Follows: ${q.parent}.`);
  if (q.expects) lines.push(`Expects: ${q.expects} (a hint to the examination, never a format demand).`);
  if (q.presumes) lines.push(`Presumes: "${q.presumes.text}". Test whether it happened before answering, against the rival "the question's premise is not supported"; if the evidence does not support it, the answer is premise_not_supported.`);
  if (q.completeness) lines.push(`It asks for a complete set: an established or partial answer rests on a coverage record for it that says what was searched and its areas (${NB.COVERAGE_AREAS.join(", ")}), each searched, skipped or not_applicable.`);
  if (q.hints.length) lines.push(`Hints (where to look, never what to find): ${q.hints.map((h) => `${h.ref}${h.value ? ` (says: ${h.value})` : ""}`).join("; ")}.${o.hypotheses.length ? ` A hint that says something is recorded as a hypothesis to test: ${o.hypotheses.map((n) => `E-${n}`).join(", ")}.` : ""}`);
  if (q.attachments.length) lines.push(`Attachments: ${q.attachments.join(", ")} (supplied material: it proves nothing by itself).`);
  if (q.deadline) lines.push(`Wanted by: ${q.deadline}.`);
  if (q.leading_forms.length) lines.push(`Leading form (${q.leading_forms.map((f) => `"${f}"`).join(", ")}): it is worded as a conclusion. Test it; the critic says which contrary route was checked.`);
  lines.push("", q.text, "");
  if (q.neutral) lines.push(`Neutral formulation (${originWords(q.neutral.origin)}): ${q.neutral.text}`, "");
  lines.push(`Why: ${q.why}`, "");
  lines.push(
    o.offerTo
      ? o.first
        ? `Offered first to ${o.offerTo} (the asker's suggestion) for ${Math.round(firstOfferMs() / 1000)} s, then to whoever is idle; nobody owns it.`
        : `Offered to ${o.offerTo}; nobody owns it.`
      : "Offered to the first seat that becomes idle; nobody owns it.",
  );
  lines.push(
    `It is a proposition to test, never a conclusion to confirm: the first lead under it (lead_open with answers: ["${q.id}"]) states the proposition and its negation and plans a route that could disconfirm it; its answer names the contrary evidence (contrary) or says why there is none (contrary_none_why), and result premise_not_supported is an answer. Unclear? question_ask("${q.id}", what is unclear); the rest of the work goes on.`,
  );
  return lines.join("\n");
}

/** A hint that says something becomes a hypothesis in the ledger, recorded once, in the asker's name. */
async function hintHypotheses(sandboxRoot: string, q: Question): Promise<{ seqs: number[]; failed: string[] }> {
  const said = q.hints.filter((h) => h.value);
  if (!said.length) return { seqs: [], failed: [] };
  const poster = posterOf(q.origin);
  const out: number[] = [];
  const failed: string[] = [];
  for (const h of said) {
    const source = `${poster}'s hint on ${q.id}: ${h.ref}`;
    const entries = await P.readLedger(sandboxRoot).catch(() => [] as P.LedgerEntry[]);
    const had = entries.find((e) => e.kind === "hypothesis" && e.value === h.value && e.source === source);
    if (had) {
      out.push(had.seq);
      continue;
    }
    const refs = /^(input|job|import|member|sha256):/.test(h.ref) ? [h.ref] : [];
    const r = await P.recordEntry(
      { sandboxRoot, agentId: poster },
      {
        kind: "hypothesis",
        value: h.value!,
        source,
        evidence: `stated by ${originWords(q.origin)} with ${q.id} (revision ${q.rev}) as a hint on where to look; not examined: a proposition to test, never a fact`,
        ...(refs.length ? { refs } : {}),
        answers: [q.section],
        status: "open",
      } as P.LedgerInput,
    ).catch((err: Error) => ({ ok: false as const, reason: err.message }));
    // Recorded by the harness in the asker's name, through no seat's record and no hub recordEntry call: its own line carries its hash.
    if (r.ok && !r.merged) await P.traceHarnessEntry(sandboxRoot, r.entry, { fn: "questionHint", q: q.id });
    if (r.ok) out.push(r.entry.seq);
    else failed.push(`${h.ref}: ${r.reason}`);
  }
  return { seqs: out, failed };
}

/** The structured id a question's post carries in its front matter: a delivery that finds it records that post, and posts nothing twice. */
export function postKey(q: string, rev: number): string {
  return `question:${q}:r${rev}`;
}

export type Delivery = { q: string; rev: number; post: { thread: string; id: number } | null; offer_to: string | null; first: boolean; hypotheses: number[]; pending?: string };

/**
 * Publish what was committed and not yet published: each person's question
 * in scope, at each revision, once. The hints' hypotheses first, then the
 * board post (keyed by the question and its revision in its front matter, so
 * a retry finds it; to the seat it is offered to, so no other seat is woken),
 * then a `deliver` event and an `offer` to the asker's suggested seat for its
 * first minute or to the most suited idle seat. A revision whose post or
 * hypotheses could not be made stays pending, with no `deliver` event, and
 * is tried again at the next header or act. Clarifications are published
 * the same way: each request as an operator request, each answer as a post
 * to the seat that asked. Run after every act and on every header, so a
 * crash between the chain write and a publication leaves it undone only
 * until the next read.
 */
export async function deliverPending(sandboxRoot: string, o: { now?: number } = {}): Promise<Delivery[]> {
  const now = o.now ?? Date.now();
  const first = await questionsSnapshot(sandboxRoot);
  if ([...first.state.questions.values()].some((q) => q.clarifications.length)) await publishClarifications(sandboxRoot, first).catch(() => undefined);
  const due = (q: Question) => HUMAN_ORIGINS.has(q.origin.kind) && q.scope === "in_scope" && !q.withdrawn && !q.after_done && !q.delivered.has(q.rev);
  if (![...first.state.questions.values()].some(due)) return [];
  if (await P.swarmDoneExists(sandboxRoot)) return [];
  const out: Delivery[] = [];
  const ctx = await viewContext(sandboxRoot);
  const seats = await liveSeats(sandboxRoot);
  const idle = await L.idleSeats(sandboxRoot, ctx.leads, ctx.ledger, await jobsOf(sandboxRoot), now, ctx.questions).catch(() => [] as Array<{ agent: string; since: number }>);
  // One offer at a time per seat, across both registers and across this
  // batch: a seat offered one question here is not offered the next.
  const busy = await L.offeredSeats(sandboxRoot, ctx.leads, now, ctx.questions).catch(() => new Set<string>());
  for (const q of [...ctx.questions.state.questions.values()].filter(due)) {
    const already = q.offers.find((x) => x.rev === q.rev);
    let offer: { to: string; first: boolean; until?: string; why: string } | null = already ? { to: already.to, first: already.first, why: already.why, ...(already.until ? { until: already.until } : {}) } : null;
    // The asker's suggested seat first, when it can take it (not done, dead or compacting, and no offer standing for it); its first claim counts from when the offer reaches it.
    if (!offer && q.suggested_to && seats.includes(q.suggested_to) && !busy.has(q.suggested_to) && (await L.seatAvailable(sandboxRoot, q.suggested_to, undefined, now)).available) offer = { to: q.suggested_to, first: true, why: `suggested by ${q.origin.name ?? q.origin.person}` };
    if (!offer) {
      const pick = rankSeats(q, idle.filter((x) => !busy.has(x.agent)), ctx)[0];
      if (pick) offer = { to: pick.agent, first: false, why: pick.why.length ? `idle and suited: ${pick.why.join("; ")}` : "idle longest" };
    }
    if (offer && !already) busy.add(offer.to);
    // Nobody idle: the post goes to the seat most suited to it, so it wakes one seat, not all.
    const to = offer?.to ?? (seats.length ? rankSeats(q, seats.map((s) => ({ agent: s, since: 0 })), ctx)[0]?.agent : null) ?? "all";
    const hyp = await hintHypotheses(sandboxRoot, q);
    const base = { q: q.id, rev: q.rev, offer_to: offer?.to ?? null, first: offer?.first === true, hypotheses: hyp.seqs };
    if (hyp.failed.length) {
      out.push({ ...base, post: null, pending: `a hint's hypothesis was not recorded (${hyp.failed.join("; ")}): tried again at the next header` });
      continue;
    }
    let post: P.PostRecord | null = null;
    let postError = "";
    try {
      post = await P.registerPost(sandboxRoot, { from: posterOf(q.origin), to, tag: "question", body: questionPostBody(q, ctx.questions, { offerTo: offer?.to ?? null, first: offer?.first === true, hypotheses: hyp.seqs }), key: postKey(q.id, q.rev) });
    } catch (err) {
      postError = (err as Error).message;
    }
    if (!post) {
      out.push({ ...base, post: null, pending: `the board post was not made (${postError}): tried again at the next header` });
      continue;
    }
    await L.withRegisters(sandboxRoot, async (held) => {
      const snap = await questionsSnapshot(sandboxRoot);
      const cur = snap.state.questions.get(q.id);
      if (!cur || cur.rev !== q.rev || cur.delivered.has(q.rev)) return;
      const drafts: QuestionDraft[] = [{ by: "system", ev: "deliver", q: q.id, rev: q.rev, post: { thread: post!.thread, id: post!.id }, to, hypotheses: hyp.seqs }];
      // Read again under the lock: a seat offered something since (a lead, or a question by a delivery racing this one) is offered nothing more; the question is offered later, from a wait.
      const occupied = offer && !cur.offers.some((x) => x.rev === q.rev) ? await L.offeredSeats(sandboxRoot, L.foldLeads((await L.readLeadEvents(sandboxRoot)).events), now, snap) : null;
      if (offer && occupied && !occupied.has(offer.to)) drafts.push({ by: "system", ev: "offer", q: q.id, rev: q.rev, to: offer.to, first: offer.first, ...(offer.until ? { until: offer.until } : {}), why: offer.why, max_until: new Date(now + O.offerMaxAgeMs()).toISOString() });
      await appendQuestionEvents(sandboxRoot, drafts, held);
      await writeQuestionsMd(sandboxRoot).catch(() => undefined);
    }).catch(() => undefined);
    out.push({ ...base, post: { thread: post.thread, id: post.id } });
  }
  return out;
}

/**
 * A question's offer as the offers module reads it (extensions/offers.ts):
 * its first claim counted from when it reached its seat, never past its age
 * bound; accepted, it holds the question for the seat for one more window
 * from the acceptance, while the seat opens its lead.
 */
export function asOffer(o: Question["offers"][number]): O.Offer {
  return {
    seq: o.seq,
    at: o.at,
    to: o.to,
    rev: o.rev,
    reason: "question",
    seen_at: o.accepted ? o.accepted.at : o.seen_at,
    declined: o.declined,
    accepted: null,
    lapsed_at: null,
    ...(o.until && !o.seen_at && !o.accepted ? { until: o.until } : {}),
  };
}

/** The offer that holds a question for one seat now, if any. */
export function reservingQuestionOffer(q: Question, now: number): O.Offer | null {
  return O.reservingOffer(q.offers.filter((x) => x.rev === q.rev).map(asOffer), now, q.rev);
}

/** A question that should be offered now: a person's, delivered, in scope, with no answer and no open lead, and no offer holding it for this revision. */
function offerDue(q: Question, ctx: ViewContext, now: number): boolean {
  if (!HUMAN_ORIGINS.has(q.origin.kind) || q.scope !== "in_scope" || q.withdrawn || q.after_done || !q.delivered.has(q.rev)) return false;
  if (standingAnswer(ctx.ledger, q.section)) return false;
  if ([...ctx.leads.leads.values()].some((l) => !l.closed && l.answers.includes(q.section))) return false;
  // The seat it is offered to has it first (the asker's suggested seat, then the pool's), until that offer ends.
  return !reservingQuestionOffer(q, now);
}

/**
 * The offer a waiting seat makes to itself: a person's question nobody has
 * taken, past its suggested seat's first minute or never offered, goes to
 * the most suited idle seat, once per revision. Taken under the lock, so two
 * waits never both take it. Returns the question offered to this seat.
 */
export async function electQuestionOffer(ctx: P.SwarmContext, now = Date.now(), seen?: ViewContext): Promise<{ q: Question; offer: O.Offer } | null> {
  // A wait polls this every few seconds: with the snapshot it already holds, nothing is read when nothing is due.
  if (seen && ![...seen.questions.state.questions.values()].some((q) => offerDue(q, seen, now))) return null;
  const outer = await viewContext(ctx.sandboxRoot);
  const due = [...outer.questions.state.questions.values()].filter((q) => offerDue(q, outer, now));
  if (!due.length) return null;
  const idle = await L.idleSeats(ctx.sandboxRoot, outer.leads, outer.ledger, await jobsOf(ctx.sandboxRoot), now, outer.questions).catch(() => [] as Array<{ agent: string; since: number }>);
  if (!idle.some((x) => x.agent === ctx.agentId)) return null;
  const order = (a: Question, b: Question) => (a.priority === b.priority ? 0 : a.priority === "urgent" ? -1 : 1) || (a.deadline ?? "￿").localeCompare(b.deadline ?? "￿") || a.opened_at.localeCompare(b.opened_at);
  for (const q of due.sort(order)) {
    const offered = new Set(q.offers.filter((x) => x.rev === q.rev).map((x) => x.to));
    const pick = rankSeats(q, idle.filter((x) => !offered.has(x.agent)), outer)[0];
    if (pick?.agent !== ctx.agentId) continue;
    const taken = await L.withRegisters(ctx.sandboxRoot, async (held) => {
      const inner = await viewContext(ctx.sandboxRoot);
      const cur = inner.questions.state.questions.get(q.id);
      if (!cur || !offerDue(cur, inner, now)) return null;
      // One offer at a time, across both registers, read again under the lock.
      if ((await L.offeredSeats(ctx.sandboxRoot, inner.leads, now, inner.questions)).has(ctx.agentId)) return null;
      // Made and delivered at once: the seat's wait returns it now.
      const made = await appendQuestionEvents(ctx.sandboxRoot, [{ by: "system", ev: "offer", q: q.id, rev: cur.rev, to: ctx.agentId, first: false, why: pick.why.length ? `idle and suited: ${pick.why.join("; ")}` : "idle longest", max_until: new Date(now + O.offerMaxAgeMs()).toISOString() }], held);
      const seq = made.at(-1)!.seq;
      await appendQuestionEvents(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "offer_seen", q: q.id, offer: seq }], held);
      return seq;
    }).catch(() => null);
    if (taken !== null) {
      const cur = (await questionsSnapshot(ctx.sandboxRoot)).state.questions.get(q.id)!;
      return { q: cur, offer: asOffer(cur.offers.find((x) => x.seq === taken)!) };
    }
  }
  return null;
}

/** Record that question offers reached their seat: the first claim counts from here. */
export async function markQuestionOffersSeen(sandboxRoot: string, agent: string, list: Array<{ q: string; offer: number }>): Promise<void> {
  if (!list.length) return;
  await L.withRegisters(sandboxRoot, async (held) => {
    const snap = await questionsSnapshot(sandboxRoot);
    const drafts: QuestionDraft[] = [];
    for (const x of list) {
      const o = snap.state.questions.get(x.q)?.offers.find((y) => y.seq === x.offer);
      if (o && o.to === agent && !o.seen_at) drafts.push({ by: agent, ev: "offer_seen", q: x.q, offer: x.offer });
    }
    if (drafts.length) await appendQuestionEvents(sandboxRoot, drafts, held);
  });
}

/**
 * Answer a question's offer (A3, one mechanism with the leads'): accept
 * holds it for the seat for one more window while it opens its lead
 * (lead_open with answers naming it, take: true, the proposition, its
 * negation and the routes); decline, with why, passes it to the next seat
 * at once.
 */
export async function answerQuestionOffer(ctx: P.SwarmContext, raw: unknown, input: { action?: string; why?: string }, now = Date.now()): Promise<{ ok: true; q: string; action: string; until?: string } | Fail> {
  const ref = qRef(raw);
  if (!ref.ok) return ref;
  const action = String(input.action ?? "").trim();
  if (action !== "accept" && action !== "decline") return { ok: false, reason: "action is accept or decline" };
  const why = bounded("why", input.why, QUESTION_WHY_MAX, action === "decline");
  if (!why.ok) return { ok: false, reason: `${why.reason}: why you do not take it (the next seat reads it)` };
  try {
    return await L.withRegisters(ctx.sandboxRoot, async (held) => {
      const snap = await questionsSnapshot(ctx.sandboxRoot);
      const q = snap.state.questions.get(ref.id);
      if (!q) return { ok: false as const, reason: `${ref.id} is not in the question register` };
      const o = reservingQuestionOffer(q, now);
      const mine = o ? q.offers.find((x) => x.seq === o.seq) : undefined;
      if (!o || !mine || o.to !== ctx.agentId) return { ok: false as const, reason: `no offer of ${q.id} stands for you${o ? ` (it is offered to ${o.to})` : ""}` };
      if (action === "accept" && mine.accepted) return { ok: true as const, q: q.id, action, until: new Date(O.offerStatus(o, now, q.rev).until).toISOString() };
      await appendQuestionEvents(ctx.sandboxRoot, [{ by: ctx.agentId, ev: action === "accept" ? "offer_accept" : "offer_decline", q: q.id, offer: o.seq, ...(why.value ? { why: why.value } : {}) }], held);
      await writeQuestionsMd(ctx.sandboxRoot).catch(() => undefined);
      return { ok: true as const, q: q.id, action, ...(action === "accept" ? { until: new Date(now + O.offerTtlMs()).toISOString() } : {}) };
    });
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

// --- dispositions ------------------------------------------------------------------------------

/**
 * A question's evidential disposition as the ledger and the register give
 * it now: the standing answer and its result, for a negative whether
 * another seat reviewed it and the coverage it rests on, whether the answer
 * predates the last amendment, and the operator's acceptance when it
 * stands. Null while there is neither an answer nor an acceptance.
 */
export function dispositionOf(v: QuestionView): Record<string, unknown> | null {
  if (!v.answer && !v.accepted?.stands) return null;
  return {
    answer: v.answer ? `E-${v.answer.seq}` : null,
    result: v.answer?.result ?? null,
    ...(v.answer?.negative ? { reviewed: v.answer.negative.reviewed, reviewed_by: v.answer.negative.by, coverage: v.answer.negative.coverage.map((c) => `E-${c.seq} ${c.coverage ?? "not computed"}`) } : {}),
    stale: v.answer?.stale ?? false,
    ...(v.accepted?.stands ? { accepted: v.accepted.as } : {}),
  };
}

const sameDisposition = (a: Record<string, unknown> | null, b: Record<string, unknown> | null): boolean => {
  const strip = (x: Record<string, unknown> | null) => (x ? JSON.stringify(P.canonicalValue(Object.fromEntries(Object.entries(x).filter(([k]) => k !== "at" && k !== "by")))) : "null");
  return strip(a) === strip(b);
};

/**
 * Put each question's disposition on the chain when it changed: a `dispose`
 * event, the harness's, written after an answer, a review or an acceptance
 * changes how a question stands, so the register carries the history of
 * its dispositions and custody seals it. Run on every header, never by the
 * finish line (which reads the state and does not move it).
 */
export async function syncDispositions(sandboxRoot: string): Promise<string[]> {
  const outer = await viewContext(sandboxRoot);
  const due = questionViews(outer).filter((v) => !sameDisposition(dispositionOf(v), outer.questions.state.questions.get(v.id)?.disposition ?? null));
  if (!due.length) return [];
  return L.withRegisters(sandboxRoot, async (held) => {
    const ctx = await viewContext(sandboxRoot);
    const drafts: QuestionDraft[] = [];
    for (const v of questionViews(ctx)) {
      const now = dispositionOf(v);
      const had = ctx.questions.state.questions.get(v.id)?.disposition ?? null;
      if (sameDisposition(now, had)) continue;
      drafts.push({ by: "system", ev: "dispose", q: v.id, rev: v.rev, decided: now ?? { answer: null, result: null, withdrawn_answer: true } });
    }
    if (!drafts.length) return [];
    if (!ctx.questions.seeded) await ensureSeededHeld(sandboxRoot, held);
    await appendQuestionEvents(sandboxRoot, drafts, held);
    await writeQuestionsMd(sandboxRoot).catch(() => undefined);
    return drafts.map((d) => d.q!);
  }).catch(() => []);
}

// --- clarification ------------------------------------------------------------------------------

/**
 * The operator's request a clarification makes: derived from the committed
 * clarify_ask and written once to the operator requests' outbox
 * (extensions/requests.ts), keyed by its question and C-n, with a durable
 * R-<n>. A crash between the ask and the request is made good at the next
 * header. The command that answers it is returned.
 */
export async function writeClarificationRequest(sandboxRoot: string, q: string, clarify: string, _by: string): Promise<string> {
  const run = (await P.readTeam(sandboxRoot).catch(() => null))?.swarm_id ?? "";
  const R = await import("./requests.ts");
  await R.reconcileRequests(sandboxRoot);
  return `swarm.sh question ${run || "<run>"} clarify-reply ${q} ${clarify} "<your answer>"`;
}

/**
 * New evidence for questions (swarm.sh evidence add, docs/adr/0014): one
 * `evidence` event per question, under the registers' lock, naming the
 * import, the acquisition request and the ledger's last entry at that
 * moment. An answer recorded before it is stale until recorded again; an
 * acceptance made before it no longer stands. Questions the register does
 * not know are returned apart, never guessed.
 */
export async function recordEvidenceArrival(sandboxRoot: string, questions: string[], info: { import: string; request?: string | null; inventory_rev?: number | null; why?: string; ledger_seq?: number }): Promise<{ recorded: string[]; unknown: string[] }> {
  return L.withRegisters(sandboxRoot, async (held) => {
    await ensureSeededHeld(sandboxRoot, held);
    const snap = await questionsSnapshot(sandboxRoot);
    // The ledger as it stood when the addition was committed (given by a
    // replay after a crash), or as it stands now: the answers up to it were
    // recorded without the new evidence.
    const ledgerSeq = info.ledger_seq ?? ((await P.readLedger(sandboxRoot, { raw: true }).catch(() => [] as P.LedgerEntry[])).at(-1)?.seq ?? 0);
    const drafts: QuestionDraft[] = [];
    const recorded: string[] = [];
    const unknown: string[] = [];
    for (const raw of [...new Set(questions)]) {
      const q = findQuestion(snap, raw);
      if (!q) {
        unknown.push(raw);
        continue;
      }
      if (recorded.includes(q.id)) continue;
      recorded.push(q.id);
      // Once per import: a replay finds the arrival recorded and records it again nowhere.
      if (q.evidence.some((x) => x.import === info.import)) continue;
      drafts.push({ by: "system", ev: "evidence", q: q.id, rev: q.rev, decided: { import: info.import, ...(info.request ? { request: info.request } : {}), ledger_seq: ledgerSeq, ...(info.inventory_rev !== undefined && info.inventory_rev !== null ? { inventory_rev: info.inventory_rev } : {}), ...(info.why ? { why: info.why } : {}) } });
    }
    if (drafts.length) {
      await appendQuestionEvents(sandboxRoot, drafts, held);
      await writeQuestionsMd(sandboxRoot).catch(() => undefined);
    }
    return { recorded, unknown };
  });
}

/** The structured id a clarification's answer post carries: one post per clarification, found again by it. */
export function clarificationKey(q: string, clarify: string): string {
  return `clarification:${q}:${clarify}`;
}

/** The answer to a clarification, posted to the seat that asked it, once (by its key). */
export async function publishClarification(sandboxRoot: string, q: string, clarify: string): Promise<{ thread: string; id: number } | null> {
  const snap = await questionsSnapshot(sandboxRoot);
  const question = snap.state.questions.get(q);
  const c = question?.clarifications.find((x) => x.id === clarify);
  if (!question || !c?.answer) return null;
  const from = c.answer.origin && HUMAN_ORIGINS.has(c.answer.origin.kind) ? posterOf(c.answer.origin) : "analyst:operator";
  const body = [
    `CLARIFICATION ${clarify} on ${postMarker(q, question.rev)}, for ${c.by}, from ${originWords(c.answer.origin)}.`,
    `Asked: ${c.what}`,
    `Answer: ${c.answer.text}`,
    "",
    `The question: ${question.text}`,
    "A clarification says what the asker meant; it is not evidence.",
  ].join("\n");
  const post = await P.registerPost(sandboxRoot, { from, to: c.by, tag: "question", body, key: clarificationKey(q, clarify) });
  return { thread: post.thread, id: post.id };
}

/**
 * Every clarification as the chain holds it, published: each request as an
 * operator request, each answer as a post to the asker; what was published
 * already is found by its id and not published again. A finished run's
 * answers are not posted (nobody reads the board), and its requests still
 * are.
 */
export async function publishClarifications(sandboxRoot: string, snap?: QuestionsSnapshot): Promise<void> {
  const qs = snap ?? (await questionsSnapshot(sandboxRoot));
  const R = await import("./requests.ts");
  const written = (await R.requestsSnapshot(sandboxRoot).catch(() => null))?.byKey;
  const missing = [...qs.state.questions.values()].some((q) => q.clarifications.some((c) => !written?.has(`clarification:${q.id}#${c.id}`)));
  // Each request once, by its key, in one reconciliation; a failure here is retried at the next header.
  if (missing) await R.reconcileRequests(sandboxRoot);
  const done = await P.swarmDoneExists(sandboxRoot);
  for (const q of qs.state.questions.values()) {
    for (const c of q.clarifications) {
      if (c.answer && !done) await publishClarification(sandboxRoot, q.id, c.id).catch(() => undefined);
    }
  }
}

// --- what each agent is told --------------------------------------------------------------------

/** How far into the register an agent was last told (inbox/<id>/questions.json). */
type Told = { seq: number };

function toldPath(sandboxRoot: string, agent: string): string {
  return join(sandboxRoot, "inbox", agent, "questions.json");
}

export async function readTold(sandboxRoot: string, agent: string): Promise<Told> {
  try {
    const t = JSON.parse(await readFile(toldPath(sandboxRoot, agent), "utf8")) as Told;
    return { seq: Number(t.seq) || 0 };
  } catch {
    return { seq: 0 };
  }
}

export async function markTold(sandboxRoot: string, agent: string, snap: QuestionsSnapshot): Promise<void> {
  const path = toldPath(sandboxRoot, agent);
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify({ seq: snap.state.events.at(-1)?.seq ?? 0 })}\n`, "utf8");
  await rename(tmp, path);
}

export type QuestionNotice = { kind: "offer" | "clarified" | "amended" | "withdrawn" | "urgent" | "admitted" | "excluded" | "triage" | "premise"; q: string; text: string; wakes: boolean; offer?: number };

/**
 * What every seat is told of a premise event, once (premises.ts): a premise
 * added or proposed, revised, admitted or withdrawn, whole, with how an
 * answer cites it. Never a wake: it changes how an answer is recorded, not
 * what a seat does next.
 */
function premiseNotice(e: QuestionEvent, p: PM.Premise): QuestionNotice | null {
  const who = e.origin?.kind === "goal" ? "the goal" : originWords(e.origin);
  const cite = `premises [{id: "${p.id}", rev: ${e.rev ?? p.rev}, stance: "assumed" | "supported" | "contradicted" | "unresolved"}]`;
  const rev = p.revisions.find((r) => r.rev === e.rev) ?? p.revisions.at(-1)!;
  const words = `"${rev.text}"${rev.locator ? ` (at ${rev.locator})` : ""}${Object.keys(rev.scope).length ? ` [${PM.scopeWords(rev.scope)}]` : ""}`;
  switch (e.ev) {
    case "premise_add":
      return { kind: "premise", q: p.id, wakes: false, text: `PREMISE ${p.id} (revision 1), ${PM.classWords(String(e.decided?.class ?? p.class) as PM.PremiseClass)}, from ${who}: ${words}. ${String(e.decided?.class ?? "given") === "proposition_under_test" ? "It is under test: examine it like any claim; assume it only conditionally (conditional: true)." : "It is not proved again, and never an open part."} An answer that rests on it or bears on it cites it: ${cite}, a contradiction or support naming the finding in refs.` };
    case "premise_propose":
      return { kind: "premise", q: p.id, wakes: false, text: `PREMISE ${p.id} (revision 1) proposed by ${who}: ${words}. A proposition under test until the operator admits it: an answer cites it supported or contradicted on the finding that shows it (refs), unresolved, or assumed only conditionally (conditional: true, "assuming ${p.id}").` };
    case "premise_revise":
      return { kind: "premise", q: p.id, wakes: false, text: `PREMISE ${p.id} was revised to revision ${e.rev} by ${who}${e.act?.why ? ` (${e.act.why})` : ""}: ${words}. An answer citing an earlier revision is warned (premise_revised): record it again against revision ${e.rev} if it rests on it.` };
    case "premise_admit":
      return { kind: "premise", q: p.id, wakes: false, text: `PREMISE ${p.id} was admitted as ${PM.classWords(String(e.act?.premise?.as ?? p.class) as PM.PremiseClass)} by ${who}${e.act?.why ? ` (${e.act.why})` : ""}: ${words}. An answer may now assume it without a condition: ${cite}.` };
    case "premise_withdraw":
      return { kind: "premise", q: p.id, wakes: false, text: `PREMISE ${p.id} was withdrawn by ${who}: ${e.act?.why ?? ""}. An answer citing it is warned (premise_withdrawn): say what it rests on instead.` };
    default:
      return null;
  }
}

/** The leads an agent holds, open, and the questions they serve. */
function heldSections(agent: string, ctx: ViewContext): Set<string> {
  const out = new Set<string>();
  for (const l of ctx.leads.leads.values()) if (l.holder === agent && !l.closed) for (const s of l.answers) out.add(s);
  return out;
}

/** Whether two questions are under the same objective, or in the same line of follow-ups. */
function related(a: Question, b: Question): boolean {
  if (a.id === b.id) return true;
  if (a.objective && a.objective === b.objective) return true;
  return a.parent === b.id || b.parent === a.id || (a.parent !== null && a.parent === b.parent);
}

/** What changed in the register for this agent since it was last told: derived from the chain, so a restart loses none of it. */
export function questionNotices(agent: string, told: Told, ctx: ViewContext): QuestionNotice[] {
  const out: QuestionNotice[] = [];
  const qs = ctx.questions.state;
  const mine = heldSections(agent, ctx);
  const mineQs = [...mine].map((s) => ctx.questions.bySection.get(s)).filter((x): x is Question => Boolean(x));
  for (const e of qs.events) {
    if (e.seq <= told.seq) continue;
    if (PM.isPremiseEvent(e.ev)) {
      const p = e.p ? qs.premises.get(e.p) : undefined;
      const n = p ? premiseNotice(e, p) : null;
      if (n) out.push(n);
      continue;
    }
    const q = e.q ? qs.questions.get(e.q) : undefined;
    if (!q) continue;
    switch (e.ev) {
      case "offer": {
        if (e.to !== agent || q.withdrawn || standingAnswer(ctx.ledger, q.section) || [...ctx.leads.leads.values()].some((l) => !l.closed && l.answers.includes(q.section))) break;
        // Only while it still holds the question for this seat.
        const held = q.offers.find((x) => x.seq === e.seq);
        if (!held || held.rev !== q.rev || !O.reserving(asOffer(held), Date.now(), q.rev)) break;
        out.push({
          kind: "offer",
          q: q.id,
          offer: e.seq,
          wakes: true,
          text: `${q.id} is offered to you${e.first ? ` first, for ${Math.round(firstOfferMs() / 1000)} s from now (${e.why})` : ` for ${Math.round(firstOfferMs() / 1000)} s from now (${e.why})`}: "${q.text}" (${originWords(q.origin)}). Take it with lead_open(answers: ["${q.id}"], take: true, proposition, negation), or offer decline ${q.id} with why; nobody owns it.`,
        });
        break;
      }
      case "clarify_answer": {
        const asker = String((e.decided as { asker?: string } | undefined)?.asker ?? "");
        if (asker !== agent) break;
        out.push({ kind: "clarified", q: q.id, wakes: true, text: `${originWords(e.origin)} answered your clarification ${e.act?.clarify} on ${q.id}: ${e.act?.answer ?? ""}` });
        break;
      }
      case "amend":
        if ((e.decided as { revision?: boolean } | undefined)?.revision !== true || !mine.has(q.section)) break;
        out.push({ kind: "amended", q: q.id, wakes: true, text: `${q.id}, which your lead serves, was amended to revision ${e.rev} by ${originWords(e.origin)}: "${e.act?.text ?? ""}". Hold what you concluded against the earlier revision to this one; an answer to an earlier revision is stale until recorded again with question_rev: ${e.rev} (supersedes the standing one, even unchanged).` });
        break;
      case "withdraw": {
        const mineHere = [...ctx.leads.leads.values()].filter((l) => l.answers.includes(q.section) && (l.holder === agent || l.closed?.by === agent || (l.closed?.disposition === "withdrawn" && ctx.leads.events.some((x) => x.lead === l.id && (x.holder === agent || x.by === agent)))));
        if (!mineHere.length) break;
        const triaged = qs.triage.filter((t) => t.seq > e.seq && t.lead && mineHere.some((l) => l.id === t.lead)).map((t) => t.lead!);
        out.push({
          kind: "withdrawn",
          q: q.id,
          wakes: true,
          text: `${q.id} was withdrawn by ${originWords(e.origin)}: ${e.act?.why ?? ""}. ${mineHere.map((l) => (triaged.includes(l.id) ? `${l.id} holds findings and goes to the operator's triage, not closed` : `${l.id} closed withdrawn`)).join("; ")}. What was found stays in the ledger.`,
        });
        break;
      }
      case "priority":
      case "deliver": {
        const urgent = e.ev === "priority" ? e.act?.priority === "urgent" : q.priority === "urgent" && e.rev === 1;
        if (!urgent || q.withdrawn || !mineQs.some((m) => related(m, q))) break;
        out.push({ kind: "urgent", q: q.id, wakes: false, text: `URGENT ${q.id} (${q.priority_reason ?? ""}), under the objective you work: "${q.text}". It cancels nothing of yours; take it when your step ends if it is yours to take.` });
        break;
      }
      case "scope":
        if (q.origin.agent !== agent) break;
        out.push({ kind: e.act?.scope === "excluded" ? "excluded" : "admitted", q: q.id, wakes: false, text: `${q.id}, which you proposed, was ${e.act?.scope === "excluded" ? "excluded from the case" : "admitted to the case"} by ${originWords(e.origin)}: ${e.act?.why ?? ""}` });
        break;
      case "triage":
        if (!e.lead || ctx.leads.leads.get(e.lead)?.holder !== agent) break;
        out.push({ kind: "triage", q: q.id, wakes: false, text: `${e.lead}, which you hold, is in the operator's triage: ${e.cause ?? ""}` });
        break;
    }
  }
  return out;
}

/** A person's question in one header item: its words whole, who asked, and how it stands. */
function headerItem(v: QuestionView): string {
  const bits: string[] = [];
  if (v.objective) bits.push(`objective ${v.objective}`);
  if (v.parent) bits.push(`follows ${v.parent}`);
  if (v.hints.length) bits.push(`hints ${v.hints.map((h) => h.ref).join(", ")}`);
  if (v.suggested_to) bits.push(`suggested to ${v.suggested_to}`);
  if (v.deadline) bits.push(`wanted by ${v.deadline}`);
  if (v.leading_forms.length) bits.push(`leading form ${v.leading_forms.map((f) => `"${f}"`).join(", ")}: test it, never confirm it`);
  const open = v.leads.filter((l) => l.status !== "closed");
  const state = v.answer?.stale
    ? `answer E-${v.answer.seq} predates revision ${v.rev}: record it again`
    : v.pending_clarifications.length
      ? `clarification ${v.pending_clarifications.join(", ")} pending`
      : open.length
        ? open.map((l) => `${l.id} ${l.holder ? `held by ${l.holder}` : "unheld"}`).join(", ")
        : "no lead yet";
  return `${v.id} rev ${v.rev}${v.priority === "urgent" ? ` URGENT (${v.priority_reason ?? ""})` : ""} (${v.author}) "${v.text}"${bits.length ? ` [${bits.join("; ")}]` : ""}: ${state}`;
}

export type QuestionsDigest = { lines: string[]; notices: QuestionNotice[]; counts: { analyst: number; proposed: number; clarifications: number; triage: number } };

/**
 * The register's part of the header on every inbox and wait delivery,
 * ranked first: the persons' questions still to answer (whole), what waits
 * for the operator's triage, the clarifications not yet answered, and, for a
 * goal that names objectives and no questions, the ask to propose them.
 */
export function questionsDigest(agent: string, ctx: ViewContext, told: Told): QuestionsDigest {
  const views = questionViews(ctx);
  const live = views.filter((v) => v.scope === "in_scope" && !v.withdrawn && !v.after_done);
  const persons = live.filter((v) => HUMAN_ORIGINS.has(v.origin.kind) && (!v.answer || v.answer.stale)).sort((a, b) => (a.priority === b.priority ? 0 : a.priority === "urgent" ? -1 : 1) || (a.deadline ?? "￿").localeCompare(b.deadline ?? "￿") || a.opened_at.localeCompare(b.opened_at));
  const proposed = views.filter((v) => v.scope === "proposed" && !v.withdrawn);
  const triage = ctx.questions.state.triage.filter((t) => !t.resolved);
  const pending = views.flatMap((v) => v.clarifications.filter((c) => !c.answer).map((c) => ({ v, c })));
  const lines: string[] = [];
  if (persons.length) lines.push(`Analyst questions (${persons.length}), each a proposition to test, never a conclusion: ${persons.map(headerItem).join("; ")}.`);
  // The questions that must be established and are not yet (docs/adr/0013): every seat, every header, while it lasts.
  const required = live.filter((v) => mustEstablish(v) && !v.accepted?.stands && !(v.answer && !v.answer.stale && establishesBy(ctx.ledger.bySeq.get(v.answer.seq) ?? { kind: "answer", inconclusive: v.answer.inconclusive })));
  if (required.length) {
    const state = (v: QuestionView) => (!v.answer ? "no answer yet" : v.answer.stale ? `answer E-${v.answer.seq} is stale (record it again)` : `answer E-${v.answer.seq} is ${NB.resultWords(v.answer.result ?? (v.answer.inconclusive ? "not_determinable" : null))}`);
    lines.push(`Must be established (${required.length}): ${required.map((v) => `${v.id} (question:${v.section}, required by ${requiredByWords(v)}${v.must_establish?.why ? `: ${v.must_establish.why}` : ""}): ${state(v)}`).join("; ")}. For each, ${MUST_ESTABLISH_WAYS}.`);
  }
  const staleOthers = live.filter((v) => !HUMAN_ORIGINS.has(v.origin.kind) && v.answer?.stale);
  if (staleOthers.length) lines.push(`Amended after their answer (record the answer again): ${staleOthers.map((v) => `${v.id} rev ${v.rev} (answer E-${v.answer!.seq})`).join(", ")}.`);
  if (proposed.length || triage.length) {
    const items = [
      ...proposed.map((v) => `${v.id} (${v.author}${v.review_query ? ", a reviewer's query" : ""}) "${v.text}"`),
      ...triage.map((t) => `${t.lead ?? t.q}: ${t.cause}`),
    ];
    lines.push(`Waiting for the operator's triage, not the case's work yet (${items.length}): ${items.join("; ")}.`);
  }
  if (pending.length) lines.push(`Clarifications not answered yet (the rest of the work goes on): ${pending.map(({ v, c }) => `${c.id} on ${v.id} asked by ${c.by}: ${c.what}`).join("; ")}.`);
  // The premises the case takes, whole (premises.ts): an answer cites those it rests on or bears on; a given is never an open part.
  const premises = premiseViews(ctx).filter((p) => !p.withdrawn);
  if (premises.length) lines.push(`Premises (${premises.length}; an answer cites each it rests on or bears on: premises [{id, rev, stance: assumed | supported | contradicted | unresolved, refs?, conditional?}]; a given is not proved again and is never an open part; one under test is assumed only conditionally): ${premises.map((p) => premiseLine(p, p.author)).join("; ")}.`);
  const objectives = [...ctx.questions.state.objectives.values()];
  if (!live.length && objectives.length) {
    lines.push(
      `No questions yet: the goal names objectives and no questions (${objectives.map((o) => `${o.id} "${o.text}"`).join("; ")}). Propose the initial questions from the objectives and the inventory with question_open (objective: "${objectives[0].id}"); one inside an objective is admitted at once.`,
    );
  }
  const notices = questionNotices(agent, told, ctx);
  return { lines, notices, counts: { analyst: persons.length, proposed: proposed.length, clarifications: pending.length, triage: triage.length } };
}

// --- the views an agent asks for ----------------------------------------------------------------

export const QUESTIONS_VIEWS = ["list", "show", "triage", "objectives", "mine", "premises"] as const;

/** A question as a list shows it: whole words, no history. */
function brief(v: QuestionView): Record<string, unknown> {
  return {
    id: v.id,
    section: `question:${v.section}`,
    origin: v.origin.kind,
    author: v.author,
    text: v.text,
    rev: v.rev,
    scope: v.scope,
    work: v.work,
    materiality: v.materiality,
    priority: v.priority,
    ...(v.objective ? { objective: v.objective } : {}),
    ...(v.parent ? { parent: v.parent } : {}),
    ...(v.expects ? { expects: v.expects } : {}),
    ...(v.completeness ? { completeness: true } : {}),
    ...(v.presumption ? { presumes: v.presumption.text } : {}),
    ...(mustEstablish(v) ? { must_establish: `required by ${requiredByWords(v)}: ${MUST_ESTABLISH_WAYS}` } : {}),
    ...(v.leading_forms.length ? { leading_forms: v.leading_forms } : {}),
    answer: v.answer ? `E-${v.answer.seq}${v.answer.stale ? ` (stale: answers revision ${v.answer.question_rev} of ${v.rev})` : ""}` : null,
    leads: v.leads.map((l) => `${l.id} ${l.status}${l.holder ? ` (${l.holder})` : ""}`),
    ...(v.withdrawn ? { withdrawn: v.withdrawn } : {}),
    ...(v.pending_clarifications.length ? { pending_clarifications: v.pending_clarifications } : {}),
  };
}

/**
 * The register as an agent reads it: list (every question, whole, a page at
 * a time), show (one question with every revision, clarification, lead,
 * offer and its answer), triage (what waits for the operator), objectives,
 * mine (the questions this agent opened or asked about).
 */
export async function questionsView(ctx: P.SwarmContext, o: { view?: string; id?: string; from?: string; pageChars?: number } = {}): Promise<Record<string, unknown>> {
  const vc = await viewContext(ctx.sandboxRoot);
  const view = String(o.view ?? (o.id ? "show" : "list")).trim();
  if (!(QUESTIONS_VIEWS as readonly string[]).includes(view)) return { ok: false, reason: `view is one of ${QUESTIONS_VIEWS.join(", ")}` };
  const chain = vc.questions.state.chain.ok ? "intact" : `BROKEN at line ${vc.questions.state.chain.broken_at} (${vc.questions.state.chain.reason})`;
  if (view === "premises") return { ok: true, view, premises: premiseViews(vc), note: "Each premise whole, with its revisions, class, scope and the standing answers that cite it. A given is not proved again and never an open part; a proposition under test is assumed only conditionally until the operator admits it.", chain };
  if (view === "show" && /^P-?\d+$/i.test(String(o.id ?? "").trim())) {
    const id = `P-${Number(/(\d+)$/.exec(String(o.id))![1])}`;
    const p = premiseViews(vc).find((x) => x.id === id);
    if (!p) return { ok: false, reason: `${id} is not in the premise register (questions view premises lists them)` };
    const history = vc.questions.state.events.filter((e) => e.p === id).map(({ prev: _p, hash: _h, v: _v, signature, ...e }) => ({ ...e, ...(signature ? { signature: { person: signature.person, fingerprint: signature.fingerprint, format: signature.format } } : {}) }));
    return { ok: true, view, premise: p, history, chain };
  }
  if (view === "show") {
    const q = findQuestion(vc.questions, o.id);
    if (!q) return { ok: false, reason: `${JSON.stringify(o.id ?? "")} is not in the question register (a question is Q-<n>)` };
    const history = vc.questions.state.events.filter((e) => e.q === q.id).map(({ prev: _p, hash: _h, v: _v, signature, ...e }) => ({ ...e, ...(signature ? { signature: { person: signature.person, fingerprint: signature.fingerprint, format: signature.format } } : {}) }));
    return { ok: true, view, question: viewQuestion(q, vc), history, chain };
  }
  if (view === "objectives") return { ok: true, view, objectives: [...vc.questions.state.objectives.values()], chain };
  if (view === "triage") {
    const views = questionViews(vc);
    return { ok: true, view, proposed: views.filter((v) => v.scope === "proposed" && !v.withdrawn).map(brief), items: vc.questions.state.triage.filter((t) => !t.resolved), note: "The operator admits (in_scope) or excludes each; until then a proposed question is not the case's work, and a lead cannot name it.", chain };
  }
  let list = questionViews(vc);
  if (view === "mine") list = list.filter((v) => v.origin.agent === ctx.agentId || v.clarifications.some((c) => c.by === ctx.agentId));
  const start = o.from ? Math.max(0, list.findIndex((v) => v.id === o.from)) : 0;
  const pageChars = o.pageChars && o.pageChars > 0 ? o.pageChars : P.inboxPageChars();
  const page: Array<Record<string, unknown>> = [];
  let chars = 0;
  for (const v of list.slice(start)) {
    const b = brief(v);
    const size = JSON.stringify(b).length;
    if (page.length && chars + size > pageChars) break;
    page.push(b);
    chars += size;
  }
  const rest = list.length - start - page.length;
  return {
    ok: true,
    view,
    n: list.length,
    questions: page,
    remaining: rest,
    ...(rest > 0 ? { next: list[start + page.length].id, note: `${rest} more question(s), held back to keep this page under ${pageChars} characters; nothing was cut. Call questions again with from: "${list[start + page.length].id}".` } : {}),
    objectives: [...vc.questions.state.objectives.values()].map((x) => ({ id: x.id, text: x.text })),
    chain,
  };
}

/** An agent opens a question (question_open): admitted inside an objective or under a parent in scope, proposed otherwise. */
export async function questionOpen(ctx: P.SwarmContext, input: ActInput): Promise<ActResult | Fail> {
  const { expected_rev: _r, scope: _s, lead: _l, clarify: _c, what: _w, answer: _a, as: _as, priority: _p, reason: _re, suggested_to: _st, deadline: _d, ...rest } = input ?? {};
  return act(ctx.sandboxRoot, { kind: "agent", agent: ctx.agentId }, "open", rest);
}

/**
 * An agent proposes a premise (premise_propose): what several answers would
 * rest on, verbatim from where it stands, recorded as a proposition under
 * test until the operator admits it (premises.ts).
 */
export async function premisePropose(ctx: P.SwarmContext, input: { text?: string; locator?: string; why?: string; scope?: unknown }): Promise<ActResult | Fail> {
  return act(ctx.sandboxRoot, { kind: "agent", agent: ctx.agentId }, "premise_propose", { text: input?.text, locator: input?.locator, why: input?.why, ...(input?.scope !== undefined ? { premise_scope: input.scope } : {}) });
}

/**
 * An agent asks the question's author what is unclear (question_ask): an
 * operator request of kind clarification, with a durable id. With
 * `presumes`, the agent records what it reads the question as taking for
 * happened, while nobody has said so (docs/adr/0011, "What a question
 * presumes"): the asker sees it with the clarification.
 */
export async function questionAsk(ctx: P.SwarmContext, id: unknown, what: unknown, presumes?: unknown): Promise<(ActResult & { request?: string; request_id?: string; request_pending?: string }) | Fail> {
  const r = await act(ctx.sandboxRoot, { kind: "agent", agent: ctx.agentId }, "clarify_ask", { q: String(id ?? ""), what: String(what ?? ""), ...(presumes !== undefined && presumes !== null && String(presumes).trim() ? { presumes: String(presumes) } : {}) });
  if (!r.ok || !r.clarify || !r.q) return r;
  // Committed: the request is derived from the ask. A failure is said, never swallowed; the next header writes it.
  try {
    const request = await writeClarificationRequest(ctx.sandboxRoot, r.q, r.clarify, ctx.agentId);
    const R = await import("./requests.ts");
    const rid = (await R.requestsSnapshot(ctx.sandboxRoot)).byKey.get(`clarification:${r.q}#${r.clarify}`);
    return { ...r, request, ...(rid ? { request_id: rid } : {}) };
  } catch (err) {
    return { ...r, request_pending: `the clarification is committed as ${r.clarify} and could not be written to the operator's requests yet (${(err as Error).message}); the next header writes it` };
  }
}

// --- the rendered register ----------------------------------------------------------------------

export function renderQuestionsMd(ctx: ViewContext): string {
  const views = questionViews(ctx);
  const s = ctx.questions.state;
  const lines: string[] = ["# Questions", "", "What the examination is asked to establish, who asked it and how each stands. Rendered by the harness from `questions/questions.jsonl` after every change; do not edit.", ""];
  lines.push(`Chain: ${s.chain.ok ? `intact, ${s.events.length} events` : `BROKEN at line ${s.chain.broken_at} (${s.chain.reason})`}${ctx.questions.seeded ? "" : "; the goal's questions are derived from the goal (not yet written to the chain)"}.`, "");
  lines.push(`## Objectives (${s.objectives.size})`, "");
  if (!s.objectives.size) lines.push("None declared.", "");
  for (const o of s.objectives.values()) lines.push(`- ${o.id}: ${o.text}${o.origin && o.origin.kind !== "goal" ? ` (${o.why || `added by ${originWords(o.origin)}`})` : ""}`);
  if (s.objectives.size) lines.push("");
  const groups: Array<[string, QuestionView[]]> = [
    ["Asked by people", views.filter((v) => HUMAN_ORIGINS.has(v.origin.kind) && v.scope === "in_scope" && !v.withdrawn)],
    ["The goal's", views.filter((v) => v.origin.kind === "goal" && !v.withdrawn)],
    ["Opened by agents", views.filter((v) => v.origin.kind === "agent" && v.scope === "in_scope" && !v.withdrawn)],
    ["Proposed, waiting for the operator's triage", views.filter((v) => v.scope === "proposed" && !v.withdrawn)],
    ["Excluded", views.filter((v) => v.scope === "excluded" && !v.withdrawn)],
    ["Withdrawn", views.filter((v) => v.withdrawn)],
  ];
  for (const [name, list] of groups) {
    lines.push(`## ${name} (${list.length})`, "");
    if (!list.length) lines.push("None.", "");
    for (const v of list) {
      lines.push(`### ${v.id}${v.section !== String(Number(v.id.slice(2))) ? ` (question:${v.section})` : ""}: revision ${v.rev}`, "");
      lines.push(`- Asked by ${v.author} at ${v.opened_at}; ${v.scope}${v.scope_why ? ` (${v.scope_why})` : ""}${v.work ? `; ${v.work}` : ""}${v.after_done ? "; after the run's done: a follow-up, not this run's work" : ""}`);
      for (const r of v.revisions) lines.push(`- Revision ${r.rev} (${originWords(r.origin)}, ${r.at}): ${r.text}${r.why ? ` — why amended: ${r.why}` : ""}`);
      if (v.neutral) lines.push(`- Neutral formulation (${originWords(v.neutral.origin)}): ${v.neutral.text}`);
      lines.push(`- Why: ${v.why}`);
      const meta = [
        `materiality ${v.materiality}`,
        `priority ${v.priority}${v.priority_reason ? ` (${v.priority_reason})` : ""}`,
        v.expects ? `expects ${v.expects}` : null,
        v.completeness ? `asks for a complete set (${v.completeness_by === "asker" ? "the asker says so" : "by its words"}): an established or partial answer rests on a coverage record naming the areas searched` : null,
        v.objective ? `objective ${v.objective}` : v.objective_text ? `would add the objective "${v.objective_text}"` : null,
        v.parent ? `follows ${v.parent}` : null,
        v.suggested_to ? `suggested to ${v.suggested_to}` : null,
        v.deadline ? `wanted by ${v.deadline}` : null,
        v.review_query ? "a reviewer's query" : null,
      ].filter(Boolean);
      lines.push(`- ${meta.join("; ")}`);
      if (v.presumption) lines.push(`- Presumes ${PM.presumptionWords(v.presumption)}: its answer tests that premise first, against "the question's premise is not supported"`);
      if (v.must_establish?.required) lines.push(`- Must be established (required by ${originWords(v.must_establish.origin)} at ${v.must_establish.at}${v.must_establish.why ? `: ${v.must_establish.why}` : ""}): partial, not determinable, a bounded negative short of the stronger bar and out of scope end no run on it`);
      else if (v.must_establish) lines.push(`- The requirement that it be established was released by ${originWords(v.must_establish.origin)} at ${v.must_establish.at}: ${v.must_establish.why ?? ""}`);
      if (v.hints.length) lines.push(`- Hints: ${v.hints.map((h) => `${h.ref}${h.value ? ` (says: ${h.value})` : ""}`).join("; ")}`);
      if (v.attachments.length) lines.push(`- Attachments: ${v.attachments.join(", ")}`);
      if (v.leading_forms.length) lines.push(`- Leading form: ${v.leading_forms.map((f) => `"${f}"`).join(", ")} (flagged for the critic)`);
      if (v.leads.length) lines.push(`- Leads: ${v.leads.map((l) => `${l.id} ${l.status}${l.holder ? ` (${l.holder})` : ""}${l.disposition ? ` ${l.disposition}` : ""}`).join(", ")}`);
      lines.push(`- Answer: ${v.answer ? `E-${v.answer.seq}${v.answer.inconclusive ? " (inconclusive)" : ""}${v.answer.result ? ` (${NB.resultWords(v.answer.result)})` : ""}${v.answer.negative ? (v.answer.negative.reviewed ? `; negative, reviewed by ${v.answer.negative.by.join(", ")}` : "; negative (unreviewed)") : ""}${v.answer.negative?.coverage.length ? `; coverage ${v.answer.negative.coverage.map((c) => `E-${c.seq} ${c.coverage ?? "not computed"}`).join(", ")}` : ""}; answers revision ${v.answer.question_rev}${v.answer.stale ? ` of ${v.rev}: stale` : ""}` : "none yet"}`);
      if (v.answer?.standing && v.answer.result === "partial") lines.push(`- ${v.answer.standing.summary}${v.answer.standing.plain ? ` Partial as recorded, and ${v.answer.standing.plain}.` : ""}`);
      if (v.answer?.parts?.length) lines.push(`- The answer's parts: ${PM.partsWords(v.answer.parts)}`);
      for (const r of v.answer?.standing?.rows ?? []) for (const x of r.not_asked_by) lines.push(`- A part the question does not ask, as ${x.by}'s review marks it: ${r.id} "${r.part}" (${x.why})`);
      if (v.answer?.premises?.length) lines.push(`- The answer's premises: ${PM.citationsWords(v.answer.premises)}`);
      for (const x of v.answer?.omitted ?? []) lines.push(`- A part the answer leaves out, as ${x.by}'s review says: "${x.part}" (${x.why})`);
      for (const t of v.answer?.premise_tests ?? []) lines.push(`- The premise tested ${t.review ? `by ${t.by}'s review` : `by the answer (${t.by})`}: ${t.outcome} (${t.refs.join(", ")})`);
      for (const c of v.clarifications) lines.push(`- Clarification ${c.id} (${c.by}, ${c.at}): ${c.what}${c.answer ? ` — answered by ${originWords(c.answer.origin)} at ${c.answer.at}: ${c.answer.text}` : " — not answered yet"}`);
      for (const o of v.offers) lines.push(`- Offered to ${o.to} at ${o.at}${o.first ? ` first, until ${o.until}` : ""} (${o.why})`);
      if (v.accepted) lines.push(`- Accepted as ${v.accepted.as} by ${originWords(v.accepted.origin)} at ${v.accepted.at} for revision ${v.accepted.rev}${v.accepted.stands ? "" : " (no longer stands: amended, or new evidence arrived, since)"}: ${v.accepted.why}`);
      for (const x of v.evidence) lines.push(`- New evidence ${x.import}${x.request ? ` for ${x.request}` : ""} at ${x.at}${x.inventory_rev !== null ? ` (inventory revision ${x.inventory_rev})` : ""}: what was concluded or accepted before it is open again`);
      if (v.withdrawn) lines.push(`- Withdrawn by ${originWords(v.withdrawn.origin)} at ${v.withdrawn.at}: ${v.withdrawn.why}`);
      for (const g of v.signed) lines.push(`- Event ${g.act_seq} signed by ${g.person} (${g.fingerprint}), sign event ${g.sign_seq}`);
      lines.push("");
    }
  }
  // The premises (premises.ts): each whole, with its revisions, class and the answers that cite it.
  const premises = premiseViews(ctx);
  if (premises.length) {
    lines.push(`## Premises (${premises.length})`, "");
    for (const p of premises) {
      lines.push(`### ${p.id}: revision ${p.rev}, ${PM.classWords(p.class)}${p.withdrawn ? ", withdrawn" : ""}`, "");
      lines.push(`- Designated by ${p.author} at ${p.opened_at}${p.why ? ` (${p.why})` : ""}`);
      for (const r of p.revisions) lines.push(`- Revision ${r.rev} (${r.origin?.kind === "goal" ? "the goal" : originWords(r.origin)}, ${r.at}): ${r.text} — at ${r.locator || "no locator"}; scope ${PM.scopeWords(r.scope)}${r.why && r.rev > 1 ? ` — why revised: ${r.why}` : ""}`);
      if (p.classes.length > 1) lines.push(`- Class: ${p.classes.map((c) => `${PM.classWords(c.class)} (${c.at}${c.why ? `: ${c.why}` : ""})`).join(" → ")}`);
      lines.push(`- Cited by: ${p.cited_by.length ? p.cited_by.map((c) => `E-${c.answer} (${c.section}) ${c.conditional ? "assuming it" : c.stance}${c.refs.length ? ` on ${c.refs.join(", ")}` : ""}${c.current ? "" : ` at revision ${c.rev}`}`).join("; ") : "no standing answer"}`);
      if (p.withdrawn) lines.push(`- Withdrawn by ${originWords(p.withdrawn.origin)} at ${p.withdrawn.at}: ${p.withdrawn.why}`);
      lines.push("");
    }
  }
  const triage = s.triage;
  lines.push(`## Triage (${triage.filter((t) => !t.resolved).length} open)`, "");
  if (!triage.length) lines.push("None.", "");
  for (const t of triage) lines.push(`- ${t.lead ?? t.q} (${t.at}): ${t.cause}${t.resolved ? ` — ${t.resolved.decision === "in_scope" ? "kept" : "excluded"} by ${originWords(t.resolved.origin)}: ${t.resolved.why}` : ""}`);
  return `${lines.join("\n").trimEnd()}\n`;
}

export async function writeQuestionsMd(sandboxRoot: string): Promise<void> {
  const ctx = await viewContext(sandboxRoot);
  await mkdir(join(sandboxRoot, QUESTIONS_DIR), { recursive: true });
  await P.writeFileAtomic(join(sandboxRoot, QUESTIONS_MD), renderQuestionsMd(ctx));
}
