/**
 * The premise register, and an answer's claim and open-part rows
 * (docs/adr/0011 "Premises"; docs/adr/0013 "Claim and open-part rows").
 *
 * A case brief supplies things several questions share: whose device it is,
 * who the subject is, the scenario. On the calibration and CTF runs those
 * were words in reasoning ("rests on the case premise that …"): one answer
 * took a premise for granted while another answer's findings contradicted
 * it, nothing on the record said so, and a partial answer held a premise
 * open as if it were a part to prove. Here each premise is a `P-n` on the
 * question register's own chain (questions/questions.jsonl: the same lock,
 * the same hash, the same custody seal), with the words of its source
 * verbatim and where they stand (its locator), its authority (the goal's
 * front matter `premises:`, the operator, or an agent that proposed it), its
 * scope (the entities and times it is about, and the questions it applies
 * to), its revisions, and its class:
 * - `given`: designated by the operator (the goal, `swarm.sh question premise
 *   add`, the console). Not proved again, and never an open part.
 * - `supplied_assertion`: what someone asserted and the operator admitted as
 *   such (a client's statement, a witness's): assumed only as theirs, said
 *   so in the report.
 * - `proposition_under_test`: what an agent proposed (`premise_propose`), or
 *   the operator put under test. Examined like any claim; assumed only
 *   conditionally ("assuming P-n") until the operator admits it.
 *
 * Answers cite premises (`premises: [{id, rev, stance, refs?, conditional?,
 * scope?}]`, stance assumed, supported, contradicted or unresolved), and
 * carry their claims part by part (`parts: [{id, part, status, refs,
 * open_by?, limited_by?}]`, against the verbatim revision of the question
 * they answer).
 * Both are present-only in the ledger's hashed core: an answer without them
 * hashes as it always did.
 *
 * What this module holds is pure: the vocabulary, the fold of the premise
 * events, the shape of what an act and an answer say, and scope overlap.
 * The acts are the question register's (extensions/questions.ts); an
 * answer's rows are checked where it is recorded (extensions/protocol.ts);
 * the gate `premise_inconsistent` reads the pairs this module finds.
 * Nothing here reads a premise's words: entities and times compare as the
 * operator and the agents wrote them, never as what they mean.
 */
import type { QuestionEvent, QuestionOrigin } from "./questions.ts";

// --- the vocabulary ---------------------------------------------------------------------------

export const PREMISE_ID = /^P-([1-9]\d{0,5})$/;
export const PREMISE_CLASSES = ["given", "supplied_assertion", "proposition_under_test"] as const;
export type PremiseClass = (typeof PREMISE_CLASSES)[number];
/** What the operator's admission makes a proposition under test: a given, or a supplied assertion. */
export const ADMIT_AS = ["given", "supplied_assertion"] as const;
export type AdmitAs = (typeof ADMIT_AS)[number];
/** Who designated a premise: the goal's front matter, the operator (or an examiner), or an agent that proposed it. */
export const PREMISE_AUTHORITIES = ["goal", "operator", "agent"] as const;
export type PremiseAuthority = (typeof PREMISE_AUTHORITIES)[number];
/** How an answer stands on a premise it cites. */
export const PREMISE_STANCES = ["assumed", "supported", "contradicted", "unresolved"] as const;
export type PremiseStance = (typeof PREMISE_STANCES)[number];
/**
 * A part is established on entries, open (a route or an ask could still
 * settle it), or limited: the question asks it, and the evidence in scope
 * cannot settle it (docs/adr/0013, "A part at the limit of the evidence").
 * Open or limited, a part not established keeps the answer partial; the
 * report says which kind it is.
 */
export const PART_STATUSES = ["established", "open", "limited"] as const;
export type PartStatus = (typeof PART_STATUSES)[number];
/** A part's id: short, stable across the answer's revisions and its reviews (a, 1, who, when-2). */
export const PART_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/;

export const PREMISE_TEXT_MAX = 4000;
export const PREMISE_LOCATOR_MAX = 1000;
export const PREMISE_WHY_MAX = 2000;
export const PREMISE_MAX_ENTITIES = 20;
export const PREMISE_ENTITY_MAX = 200;
export const PREMISE_MAX_TIMES = 10;
export const PREMISE_MAX_QUESTIONS = 50;
export const ANSWER_MAX_PREMISES = 20;
export const ANSWER_MAX_PARTS = 20;
export const PART_TEXT_MAX = 1500;
export const PART_MAX_REFS = 50;

/** A time range, each end an ISO 8601 date or date-time as given; an end left out is open. */
export type TimeRange = { from?: string; to?: string };
/** What a premise is about: its entities, its times, and the questions it applies to (none named: all). */
export type PremiseScope = { entities?: string[]; times?: TimeRange[]; questions?: string[] };
/** An answer's narrowing of a premise's scope: the entities and times it assumes, supports or contradicts it for. */
export type CitationScope = { entities?: string[]; times?: TimeRange[] };

/**
 * An answer's citation of a premise: which, at which revision, how the
 * answer stands on it, the entries that show it (supported and contradicted
 * rest on findings), whether an assumption is conditional ("assuming P-n",
 * said so in the report), and the scope the answer narrows it to.
 */
export type PremiseCitation = { id: string; rev: number; stance: PremiseStance; refs?: string[]; conditional?: true; scope?: CitationScope };

/**
 * One row of an answer: a part the question asks, as the answer takes it
 * from the question's verbatim revision, established, open or limited, the
 * entries it rests on; for an open part what bounds it: an acquisition ask
 * (R-<n>), a route (a lead, L-<n>), or a limitation or a coverage record
 * (E-<seq>); for a limited part what shows the evidence cannot settle it
 * (`limited_by`): the coverage record for the question, or a limitation
 * whose reason is unavailable or excluded (E-<seq>). A premise is never an
 * open or a limited part.
 */
export type AnswerPart = { id: string; part: string; status: PartStatus; refs?: string[]; open_by?: string; limited_by?: string };

/**
 * What a premise act says of the premise, as the actor said it (the part a
 * signature covers, in the act's `premise`): the premise acted on (a
 * revision, an admission, a withdrawal), its words verbatim, where they
 * stand, its class (the operator's add), its scope, and what an admission
 * makes it.
 */
export type PremiseAct = { id?: string; text?: string; locator?: string; class?: PremiseClass; scope?: PremiseScope; as?: AdmitAs };

// --- the register, folded ---------------------------------------------------------------------

export type PremiseRevision = { rev: number; text: string; locator: string; scope: PremiseScope; at: string; by: string; origin: QuestionOrigin | null; why?: string; seq: number };

export type Premise = {
  id: string;
  n: number;
  authority: PremiseAuthority;
  origin: QuestionOrigin | null;
  /** Its class now, and each change of it (the admission of a proposition under test). */
  class: PremiseClass;
  classes: Array<{ class: PremiseClass; at: string; origin: QuestionOrigin | null; why: string; seq: number }>;
  /** Its revision now: the words, the locator and the scope; each revision kept whole. */
  rev: number;
  text: string;
  locator: string;
  scope: PremiseScope;
  revisions: PremiseRevision[];
  why: string;
  withdrawn: { at: string; why: string; origin: QuestionOrigin | null; seq: number } | null;
  opened_at: string;
  opened_by: string;
  open_seq: number;
  last_seq: number;
};

export const PREMISE_EVENTS = ["premise_add", "premise_propose", "premise_revise", "premise_admit", "premise_withdraw"] as const;
export type PremiseEventKind = (typeof PREMISE_EVENTS)[number];

export function isPremiseEvent(ev: string): ev is PremiseEventKind {
  return (PREMISE_EVENTS as readonly string[]).includes(ev);
}

/**
 * The premises the chain holds, folded from its events in order. An event
 * of a kind this fold does not know is left alone: a chain from before the
 * register reads as it did, with no premise.
 */
export function foldPremises(events: readonly QuestionEvent[]): Map<string, Premise> {
  const out = new Map<string, Premise>();
  for (const e of events) {
    if (!isPremiseEvent(e.ev) || !e.p) continue;
    // What the actor said of the premise (its words, locator, scope, class) is in act.premise; why and the revision read beside it.
    const act = { ...((e.act?.premise ?? {}) as Record<string, unknown>), why: e.act?.why } as Record<string, unknown>;
    const d = (e.decided ?? {}) as Record<string, unknown>;
    const origin = e.origin ?? null;
    const p = out.get(e.p);
    switch (e.ev) {
      case "premise_add":
      case "premise_propose": {
        if (p) break;
        const cls = (PREMISE_CLASSES as readonly string[]).includes(String(d.class)) ? (d.class as PremiseClass) : e.ev === "premise_propose" ? "proposition_under_test" : "given";
        const authority = (PREMISE_AUTHORITIES as readonly string[]).includes(String(d.authority)) ? (d.authority as PremiseAuthority) : e.ev === "premise_propose" ? "agent" : "operator";
        const text = String(act.text ?? "");
        const locator = String(d.locator ?? act.locator ?? "");
        const scope = (act.scope ?? {}) as PremiseScope;
        const n = Number(PREMISE_ID.exec(e.p)?.[1] ?? 0);
        out.set(e.p, {
          id: e.p,
          n,
          authority,
          origin,
          class: cls,
          classes: [{ class: cls, at: e.at, origin, why: String(act.why ?? ""), seq: e.seq }],
          rev: e.rev ?? 1,
          text,
          locator,
          scope,
          revisions: [{ rev: e.rev ?? 1, text, locator, scope, at: e.at, by: e.by, origin, ...(act.why ? { why: String(act.why) } : {}), seq: e.seq }],
          why: String(act.why ?? ""),
          withdrawn: null,
          opened_at: e.at,
          opened_by: e.by,
          open_seq: e.seq,
          last_seq: e.seq,
        });
        break;
      }
      case "premise_revise": {
        if (!p || e.rev === undefined || e.rev <= p.rev) break;
        const text = act.text !== undefined ? String(act.text) : p.text;
        const locator = act.locator !== undefined ? String(act.locator) : p.locator;
        const scope = act.scope !== undefined ? (act.scope as PremiseScope) : p.scope;
        p.rev = e.rev;
        p.text = text;
        p.locator = locator;
        p.scope = scope;
        p.revisions.push({ rev: e.rev, text, locator, scope, at: e.at, by: e.by, origin, ...(act.why ? { why: String(act.why) } : {}), seq: e.seq });
        p.last_seq = e.seq;
        break;
      }
      case "premise_admit": {
        if (!p || p.withdrawn) break;
        const cls = String(act.as ?? "");
        if (!(ADMIT_AS as readonly string[]).includes(cls)) break;
        p.class = cls as PremiseClass;
        p.classes.push({ class: p.class, at: e.at, origin, why: String(act.why ?? ""), seq: e.seq });
        p.last_seq = e.seq;
        break;
      }
      case "premise_withdraw":
        if (!p || p.withdrawn) break;
        p.withdrawn = { at: e.at, why: String(act.why ?? ""), origin, seq: e.seq };
        p.last_seq = e.seq;
        break;
    }
  }
  return out;
}

/** A premise's scope at a revision (its revisions are kept whole), or its scope now. */
export function scopeAt(p: Premise, rev: number): PremiseScope {
  return p.revisions.find((r) => r.rev === rev)?.scope ?? p.scope;
}

/** A premise in words: its id, class, revision, and authority. */
export function premiseWords(p: Pick<Premise, "id" | "class" | "rev" | "authority">): string {
  return `${p.id} (${classWords(p.class)}, revision ${p.rev}, ${p.authority === "goal" ? "from the goal" : p.authority === "agent" ? "proposed by an agent" : "the operator's"})`;
}

export function classWords(c: PremiseClass): string {
  return c === "given" ? "a given" : c === "supplied_assertion" ? "a supplied assertion" : "a proposition under test";
}

/** A scope in words: its entities, times and questions, or "unbounded". */
export function scopeWords(s: PremiseScope | CitationScope | undefined): string {
  const bits: string[] = [];
  if (s?.entities?.length) bits.push(`entities ${s.entities.join(", ")}`);
  if (s?.times?.length) bits.push(`times ${s.times.map((t) => `${t.from ?? "…"} to ${t.to ?? "…"}`).join("; ")}`);
  if ((s as PremiseScope | undefined)?.questions?.length) bits.push(`questions ${(s as PremiseScope).questions!.join(", ")}`);
  return bits.length ? bits.join("; ") : "unbounded";
}

// --- scope ------------------------------------------------------------------------------------

type Fail = { ok: false; reason: string };

const entityKey = (s: string) => s.normalize("NFKC").replace(/\s+/g, " ").trim().toLowerCase();

/** A time bound as a number (ms), a date alone reaching to the end of its day when it closes a range. */
function bound(v: string | undefined, end: boolean): number {
  if (!v) return end ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(v);
  const t = Date.parse(dateOnly ? `${v}T00:00:00Z` : v);
  return dateOnly && end ? t + 86_400_000 - 1 : t;
}

function rangesMeet(a: TimeRange, b: TimeRange): boolean {
  return bound(a.from, false) <= bound(b.to, true) && bound(b.from, false) <= bound(a.to, true);
}

function rangeWithin(inner: TimeRange, outer: TimeRange): boolean {
  return bound(inner.from, false) >= bound(outer.from, false) && bound(inner.to, true) <= bound(outer.to, true);
}

/**
 * Whether two scopes overlap: they do unless both name entities and share
 * none, or both name times and no two of their ranges meet. What a scope
 * leaves out is unbounded: it meets everything.
 */
export function scopesOverlap(a: CitationScope | undefined, b: CitationScope | undefined): boolean {
  if (a?.entities?.length && b?.entities?.length) {
    const bs = new Set(b.entities.map(entityKey));
    if (!a.entities.some((x) => bs.has(entityKey(x)))) return false;
  }
  if (a?.times?.length && b?.times?.length) {
    if (!a.times.some((x) => b.times!.some((y) => rangesMeet(x, y)))) return false;
  }
  return true;
}

/** Why a citation's scope is not inside its premise's (each named entity the premise's, each range inside one of its ranges), or null. */
export function scopeOutside(inner: CitationScope, outer: PremiseScope): string | null {
  if (inner.entities?.length && outer.entities?.length) {
    const os = new Set(outer.entities.map(entityKey));
    const out = inner.entities.filter((x) => !os.has(entityKey(x)));
    if (out.length) return `entities ${out.join(", ")} are not among the premise's (${outer.entities.join(", ")})`;
  }
  if (inner.times?.length && outer.times?.length) {
    const out = inner.times.filter((x) => !outer.times!.some((y) => rangeWithin(x, y)));
    if (out.length) return `times ${out.map((t) => `${t.from ?? "…"} to ${t.to ?? "…"}`).join("; ")} are not inside the premise's (${outer.times.map((t) => `${t.from ?? "…"} to ${t.to ?? "…"}`).join("; ")})`;
  }
  return null;
}

/** The scope a citation stands on: its own narrowing, or its premise's at the revision it cites (entities and times). */
export function citationScope(c: PremiseCitation, p: Premise | undefined): CitationScope {
  if (c.scope) return c.scope;
  if (!p) return {};
  const s = scopeAt(p, c.rev);
  return { ...(s.entities?.length ? { entities: s.entities } : {}), ...(s.times?.length ? { times: s.times } : {}) };
}

function textList(name: string, raw: unknown, max: number, each: number): { ok: true; value: string[] } | Fail {
  const list = raw === undefined || raw === null || raw === "" ? [] : Array.isArray(raw) ? raw : String(raw).split(/\s*[,;]\s*/);
  const out: string[] = [];
  for (const x of list) {
    const t = String(x ?? "").trim();
    if (!t) continue;
    if (t.length > each) return { ok: false, reason: `${name}: "${t.slice(0, 40)}…" is over ${each} characters: name it shorter; nothing is cut, so a longer one is refused` };
    if (!out.some((y) => entityKey(y) === entityKey(t))) out.push(t);
  }
  if (out.length > max) return { ok: false, reason: `${name} names at most ${max}` };
  return { ok: true, value: out };
}

/** A list of time ranges as given: [{from?, to?}], or "FROM..TO" / "FROM/TO" strings; each end an ISO 8601 date or date-time. */
function timeList(name: string, raw: unknown): { ok: true; value: TimeRange[] } | Fail {
  const list = raw === undefined || raw === null || raw === "" ? [] : Array.isArray(raw) ? raw : String(raw).split(/\s*;\s*/);
  const out: TimeRange[] = [];
  const shape = `${name} is a list of ranges, each {from, to} (either end may be left out) or "FROM..TO", each end an ISO 8601 date or date-time (2024-01-15, 2024-01-15T09:00:00Z)`;
  for (const x of list) {
    let from: string | undefined;
    let to: string | undefined;
    if (typeof x === "string") {
      const s = x.trim();
      const ends = s.includes("..") ? s.split("..") : s.split("/");
      if (ends.length !== 2) return { ok: false, reason: `${shape} (got ${JSON.stringify(x)})` };
      from = ends[0]!.trim() || undefined;
      to = ends[1]!.trim() || undefined;
    } else if (x && typeof x === "object") {
      const o = x as Record<string, unknown>;
      from = o.from === undefined || o.from === null || o.from === "" ? undefined : String(o.from).trim();
      to = o.to === undefined || o.to === null || o.to === "" ? undefined : String(o.to).trim();
    } else return { ok: false, reason: shape };
    if (!from && !to) return { ok: false, reason: `${shape}: a range names at least one end` };
    for (const v of [from, to]) if (v && !Number.isFinite(bound(v, false))) return { ok: false, reason: `${shape} (got ${JSON.stringify(v)})` };
    if (from && to && bound(from, false) > bound(to, true)) return { ok: false, reason: `${name}: ${from} is after ${to}` };
    out.push({ ...(from ? { from } : {}), ...(to ? { to } : {}) });
  }
  if (out.length > PREMISE_MAX_TIMES) return { ok: false, reason: `${name} names at most ${PREMISE_MAX_TIMES} ranges` };
  return { ok: true, value: out };
}

/**
 * A premise's scope as an act gives it: {entities, times, questions}, each
 * optional, each bounded (refused past it, never cut). The questions are
 * named Q-<n>; whether each is in the register is checked under the lock.
 */
export function checkScope(raw: unknown, o: { questions: boolean } = { questions: true }): { ok: true; scope: PremiseScope } | Fail {
  if (raw === undefined || raw === null || raw === "") return { ok: true, scope: {} };
  if (typeof raw !== "object" || Array.isArray(raw)) return { ok: false, reason: `scope is {entities?: [..], times?: [{from, to}], ${o.questions ? "questions?: [Q-<n>]" : ""}}: what the premise is about` };
  const r = raw as Record<string, unknown>;
  const extra = Object.keys(r).filter((k) => !["entities", "times", ...(o.questions ? ["questions"] : [])].includes(k));
  if (extra.length) return { ok: false, reason: `scope takes entities, times${o.questions ? " and questions" : ""}, not ${extra.join(", ")}` };
  const entities = textList("scope.entities", r.entities, PREMISE_MAX_ENTITIES, PREMISE_ENTITY_MAX);
  if (!entities.ok) return entities;
  const times = timeList("scope.times", r.times);
  if (!times.ok) return times;
  let questions: string[] = [];
  if (o.questions) {
    const q = textList("scope.questions", r.questions, PREMISE_MAX_QUESTIONS, 16);
    if (!q.ok) return q;
    questions = [];
    for (const x of q.value) {
      const m = /^(?:question:)?Q?-?([1-9]\d{0,5})$/i.exec(x);
      if (!m) return { ok: false, reason: `scope.questions names questions as Q-<n> (got ${JSON.stringify(x)})` };
      const id = `Q-${Number(m[1])}`;
      if (!questions.includes(id)) questions.push(id);
    }
  }
  return { ok: true, scope: { ...(entities.value.length ? { entities: entities.value } : {}), ...(times.value.length ? { times: times.value } : {}), ...(questions.length ? { questions } : {}) } };
}

// --- an answer's rows, as given ---------------------------------------------------------------

/** An entry citation as E-<seq> (from 12, "#12", "E-12"), or null. */
export function entryRef(v: unknown): string | null {
  const m = /^(?:#|E-)?([1-9]\d{0,6})$/i.exec(String(v ?? "").trim());
  return m ? `E-${Number(m[1])}` : null;
}

function refList(name: string, raw: unknown): { ok: true; value: string[] } | Fail {
  const list = raw === undefined || raw === null || raw === "" ? [] : Array.isArray(raw) ? raw : String(raw).split(/[\s,]+/);
  const out: string[] = [];
  for (const x of list) {
    if (String(x ?? "").trim() === "") continue;
    const r = entryRef(x);
    if (!r) return { ok: false, reason: `${name} names ledger entries as E-<seq> (got ${JSON.stringify(x)})` };
    if (!out.includes(r)) out.push(r);
  }
  if (out.length > PART_MAX_REFS) return { ok: false, reason: `${name} names at most ${PART_MAX_REFS} entries` };
  return { ok: true, value: out };
}

/**
 * An answer's `premises` as given, the shape only: each {id: P-<n>, rev,
 * stance, refs?, conditional?, scope?}. Whether each premise exists, stands
 * at that revision, may be assumed there, and what its refs are, is checked
 * against the register and the ledger where the answer is recorded.
 */
export function parseCitations(raw: unknown): { ok: true; citations: PremiseCitation[] } | Fail {
  if (raw === undefined || raw === null || (Array.isArray(raw) && !raw.length)) return { ok: true, citations: [] };
  const shape = "premises is [{id: P-<n>, rev: <the revision you read>, stance: assumed | supported | contradicted | unresolved, refs?: [E-<seq>], conditional?: true, scope?: {entities?, times?}}]: each premise the answer rests on, supports, contradicts or leaves unresolved";
  if (!Array.isArray(raw)) return { ok: false, reason: shape };
  if (raw.length > ANSWER_MAX_PREMISES) return { ok: false, reason: `premises cites at most ${ANSWER_MAX_PREMISES}` };
  const out: PremiseCitation[] = [];
  for (const x of raw) {
    const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
    const m = /^P-?([1-9]\d{0,5})$/i.exec(String(o.id ?? "").trim());
    if (!m) return { ok: false, reason: `${shape} (an id is P-<n>; got ${JSON.stringify(o.id)})` };
    const id = `P-${Number(m[1])}`;
    if (out.some((c) => c.id === id)) return { ok: false, reason: `premises cites ${id} twice: one citation per premise, with one stance` };
    const rev = Number(o.rev);
    if (!Number.isInteger(rev) || rev < 1) return { ok: false, reason: `premises: ${id}'s rev is the revision you read, a whole number (questions show ${id} says it; got ${JSON.stringify(o.rev)})` };
    const stance = String(o.stance ?? "").trim().toLowerCase();
    if (!(PREMISE_STANCES as readonly string[]).includes(stance)) return { ok: false, reason: `premises: ${id}'s stance is one of ${PREMISE_STANCES.join(", ")} (got ${JSON.stringify(o.stance)})` };
    const refs = refList(`premises: ${id}'s refs`, o.refs);
    if (!refs.ok) return refs;
    if (o.conditional !== undefined && o.conditional !== null && typeof o.conditional !== "boolean") return { ok: false, reason: `premises: ${id}'s conditional is true or false` };
    if (o.conditional === true && stance !== "assumed") return { ok: false, reason: `premises: ${id} is ${stance}: conditional is for an assumption ("assuming ${id}"), stance assumed` };
    let scope: CitationScope | undefined;
    if (o.scope !== undefined && o.scope !== null && o.scope !== "") {
      const s = checkScope(o.scope, { questions: false });
      if (!s.ok) return { ok: false, reason: `premises: ${id}'s ${s.reason}` };
      if (s.scope.entities?.length || s.scope.times?.length) scope = { ...(s.scope.entities?.length ? { entities: s.scope.entities } : {}), ...(s.scope.times?.length ? { times: s.scope.times } : {}) };
    }
    out.push({ id, rev, stance: stance as PremiseStance, ...(refs.value.length ? { refs: refs.value } : {}), ...(o.conditional === true ? { conditional: true as const } : {}), ...(scope ? { scope } : {}) });
  }
  return { ok: true, citations: out };
}

/**
 * An answer's `parts` as given, the shape only: each {id, part, status:
 * established | open | limited, refs?, open_by?, limited_by?}. A premise is
 * never an open or a limited part (P-<n> is refused here); what the refs,
 * open_by and limited_by name is checked against the ledger, the requests
 * and the leads where the answer is recorded.
 */
export function parseParts(raw: unknown): { ok: true; parts: AnswerPart[] } | Fail {
  if (raw === undefined || raw === null || (Array.isArray(raw) && !raw.length)) return { ok: true, parts: [] };
  const shape = "parts is [{id, part, status: established | open | limited, refs: [E-<seq>], open_by?: R-<n> | L-<n> | E-<seq>, limited_by?: E-<seq>}]: each part the question asks, as you read its revision, established on the entries in refs, open with what could still settle it, or limited with what shows the evidence in scope cannot";
  if (!Array.isArray(raw)) return { ok: false, reason: shape };
  if (raw.length > ANSWER_MAX_PARTS) return { ok: false, reason: `parts names at most ${ANSWER_MAX_PARTS}: keep the parts the question asks` };
  const out: AnswerPart[] = [];
  for (const x of raw) {
    const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
    const id = String(o.id ?? "").trim();
    if (!PART_ID.test(id)) return { ok: false, reason: `${shape} (a part's id is 1-16 letters, digits, dot, dash or underscore, starting with a letter or digit: a, b, who, when-2; got ${JSON.stringify(o.id)})` };
    if (out.some((p) => p.id === id)) return { ok: false, reason: `parts names "${id}" twice: each part has its own id` };
    const part = String(o.part ?? "").trim();
    if (!part) return { ok: false, reason: `parts: "${id}" says which part of the question it is (part)` };
    if (part.length > PART_TEXT_MAX) return { ok: false, reason: `parts: "${id}"'s part is over ${PART_TEXT_MAX} characters: say it in fewer; nothing is cut, so a longer one is refused` };
    const status = String(o.status ?? "").trim().toLowerCase();
    if (!(PART_STATUSES as readonly string[]).includes(status)) return { ok: false, reason: `parts: "${id}"'s status is established, open or limited (got ${JSON.stringify(o.status)})` };
    const refs = refList(`parts: "${id}"'s refs`, o.refs);
    if (!refs.ok) return refs;
    if (status === "established" && !refs.value.length) return { ok: false, reason: `parts: "${id}" is established: name the entries that establish it in refs (E-<seq>)` };
    let openBy: string | undefined;
    const rawBy = String(o.open_by ?? "").trim();
    if (rawBy) {
      if (status !== "open") return { ok: false, reason: `parts: "${id}" is ${status}: open_by is an open part's (what could still settle it)${status === "limited" ? `; a limited part names in limited_by what shows the evidence in scope cannot settle it` : ""}` };
      if (/^P-?\d+$/i.test(rawBy)) return { ok: false, reason: `parts: "${id}" is open by ${rawBy.toUpperCase()}, a premise, and a premise is never an open part: what the case takes as given is cited in premises (stance assumed; a given is not proved again). Name what bounds the part (an acquisition ask R-<n>, a route L-<n>, a limitation or a coverage record E-<seq>), or record the part established` };
      const r = /^R-?([1-9]\d{0,6})$/i.exec(rawBy) ? `R-${Number(/(\d+)$/.exec(rawBy)![1])}` : /^L-?([1-9]\d{0,5})$/i.exec(rawBy) ? `L-${Number(/(\d+)$/.exec(rawBy)![1])}` : entryRef(rawBy);
      if (!r) return { ok: false, reason: `parts: "${id}"'s open_by names what bounds it: an acquisition ask R-<n>, a route L-<n>, or a limitation or a coverage record E-<seq> (got ${JSON.stringify(o.open_by)})` };
      openBy = r;
    }
    if (status === "open" && !openBy) return { ok: false, reason: `parts: "${id}" is open: say what bounds it in open_by: an acquisition ask R-<n> (the source that would settle it), a route L-<n> (the lead that would examine it), or a limitation or a coverage record E-<seq> (why it could not be established)` };
    let limitedBy: string | undefined;
    const rawLimit = String(o.limited_by ?? "").trim();
    if (rawLimit) {
      if (status !== "limited") return { ok: false, reason: `parts: "${id}" is ${status}: limited_by is a limited part's (what shows the evidence in scope cannot settle it)` };
      if (/^P-?\d+$/i.test(rawLimit)) return { ok: false, reason: `parts: "${id}" is limited by ${rawLimit.toUpperCase()}, a premise, and a premise is never a limited part: what the case takes as given is cited in premises. Name the coverage record for the question, or a limitation whose reason is unavailable or excluded (E-<seq>)` };
      const r = entryRef(rawLimit);
      if (!r) return { ok: false, reason: `parts: "${id}"'s limited_by names what shows the evidence in scope cannot settle it: the coverage record for the question, or a limitation whose reason is unavailable or excluded, as E-<seq> (got ${JSON.stringify(o.limited_by)})` };
      limitedBy = r;
    }
    if (status === "limited" && !limitedBy) return { ok: false, reason: `parts: "${id}" is limited: name in limited_by what shows the evidence in scope cannot settle it: the coverage record for the question (what was searched for it), or a limitation whose reason is unavailable or excluded (E-<seq>). If a route or an ask could still settle it, it is open` };
    out.push({ id, part, status: status as PartStatus, ...(refs.value.length ? { refs: refs.value } : {}), ...(openBy ? { open_by: openBy } : {}), ...(limitedBy ? { limited_by: limitedBy } : {}) });
  }
  return { ok: true, parts: out };
}

/** An answer's parts in words: each id, established, open or limited (and by what), and its entries. */
export function partsWords(parts: readonly AnswerPart[]): string {
  const soFar = (p: AnswerPart) => (p.refs?.length ? ` (so far ${p.refs.join(", ")})` : "");
  return parts.map((p) => `${p.id} "${p.part}" ${p.status === "established" ? `established (${(p.refs ?? []).join(", ")})` : p.status === "limited" ? `at the limit of the evidence, shown by ${p.limited_by}${soFar(p)}` : `open, bounded by ${p.open_by}${soFar(p)}`}`).join("; ");
}

/**
 * What a question takes as happened (docs/adr/0011, "What a question
 * presumes"): the asker's word, or an agent's (`presumes`, on the question
 * register), or, for a person's question, the proposition the register's
 * framing states with its negation (the first lead under it that framed it;
 * the question's own words while none has). Its answer is reviewed against
 * the rival "the question's premise is not supported". Words the register
 * holds, never read for what they mean.
 */
export type Presumption = { q: string; section: string; text: string; source: "presumes" | "framing"; by: string; lead?: string; negation?: string };

/** A presumption in words: what it takes as happened, and whose word it is. */
export function presumptionWords(p: Presumption): string {
  return `"${p.text}" (${p.source === "presumes" ? `presumed by ${p.by}` : `${p.by}, framed ${p.lead ? `by ${p.lead}` : "by its own words (no lead has framed it yet)"}${p.negation ? `, against "${p.negation}"` : ""}`})`;
}

/**
 * A test of a question's premise (docs/adr/0011, "What a question
 * presumes"), on a review (`answer_review.premise_tested`) or on the answer
 * itself (`premise_tested`): what the test showed of whether the presumed
 * event happened, and the observation or job it rests on (E-<seq>, or an
 * object ref). The rival is fixed: the question's premise is not supported.
 */
export type PremiseTest = { outcome: string; refs: string[] };

/**
 * A review's word on a part of an answer, as the standing reads it
 * (protocol.ts AnswerReviewPart, with its reviewer): the part (the answer's
 * id, or its words), and whether the review marks it not asked by the
 * question or names it missing from the answer.
 */
export type PartMark = { by: string; id?: string; part: string; why: string; not_asked?: true; missing?: true };

/**
 * One of an answer's rows, with each review that marks it not asked by the
 * question and why; a limited row with whether its bound is reviewed by a
 * seat other than its authors, and by whom (null when the caller did not
 * read the ledger).
 */
export type PartRow = AnswerPart & { not_asked_by: Array<{ by: string; why: string }>; bound?: BoundReview | null };

/** Whether what a limited part is limited by stands reviewed as a negative is (protocol.ts limitedBoundReview): by whom, or why not. */
export type BoundReview = { reviewed: boolean; by: string[]; why?: string };

/**
 * An answer's parts as a reader weighs them (docs/adr/0013, "What the
 * report shows of an answer's parts"): its rows, each with the reviews that
 * mark it not asked; the parts the question asks, which are the rows no
 * review marks not asked and each part a review names missing from the
 * answer (once, however many reviews name it); how many of those the answer
 * holds established; its open rows, and how many of them a review marks not
 * asked; and whether every part the question asks is established (at least
 * one, and none named missing). A mark matches a row by its id, else by its
 * words as answers are compared (case and runs of space folded); a mark that
 * matches no row is kept apart, never dropped.
 */
export type PartsStanding = {
  rows: PartRow[];
  asked: number;
  established: number;
  /** Asked parts at the limit of the evidence, and how many of those rest on a bound no other seat has reviewed yet. */
  limited: number;
  limited_unreviewed: number;
  open: number;
  open_not_asked: number;
  missing: Array<{ by: string; part: string; why: string }>;
  all_asked_established: boolean;
  unmatched: PartMark[];
};

const foldWords = (s: string) => s.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();

export function partsStanding(parts: readonly AnswerPart[], marks: readonly PartMark[], bounds?: ReadonlyMap<string, BoundReview>): PartsStanding {
  const rows: PartRow[] = parts.map((p) => ({ ...p, not_asked_by: [], ...(p.status === "limited" && bounds ? { bound: (p.limited_by && bounds.get(p.limited_by)) || null } : {}) }));
  const unmatched: PartMark[] = [];
  const missing: PartsStanding["missing"] = [];
  for (const m of marks) {
    if (m.missing) {
      if (!missing.some((x) => foldWords(x.part) === foldWords(m.part))) missing.push({ by: m.by, part: m.part, why: m.why });
      continue;
    }
    if (!m.not_asked) continue;
    const row = rows.find((r) => (m.id ? r.id === m.id : foldWords(r.part) === foldWords(m.part)));
    if (!row) {
      unmatched.push(m);
      continue;
    }
    if (!row.not_asked_by.some((x) => x.by === m.by)) row.not_asked_by.push({ by: m.by, why: m.why });
  }
  const asked = rows.filter((r) => !r.not_asked_by.length);
  const established = asked.filter((r) => r.status === "established").length;
  const limited = asked.filter((r) => r.status === "limited");
  const open = rows.filter((r) => r.status === "open");
  return {
    rows,
    asked: asked.length + missing.length,
    established,
    limited: limited.length,
    limited_unreviewed: limited.filter((r) => r.bound && !r.bound.reviewed).length,
    open: open.length,
    open_not_asked: open.filter((r) => r.not_asked_by.length).length,
    missing,
    all_asked_established: asked.length > 0 && established === asked.length && !missing.length,
    unmatched,
  };
}

/**
 * The plain line an answer's parts lead with: "Asked parts: 3 of 3
 * established. Open: 1, which a review marks as not asked.", or "Asked
 * parts: 2 of 3 established, 1 at the limit of the evidence (its bound not
 * yet reviewed by another seat). Open: none." Harness words and counts only.
 */
export function partsSummaryWords(s: PartsStanding): string {
  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
  const open = !s.open
    ? "Open: none."
    : s.open_not_asked === s.open
      ? `Open: ${s.open}, ${plural(s.open, "which a review marks", "each of which a review marks")} as not asked.`
      : s.open_not_asked
        ? `Open: ${s.open}, of which ${s.open_not_asked} ${plural(s.open_not_asked, "a review marks", "reviews mark")} as not asked.`
        : `Open: ${s.open}.`;
  const missing = s.missing.length ? ` ${s.missing.length === 1 ? "A review names 1 part" : `Reviews name ${s.missing.length} parts`} of the question the answer leaves out.` : "";
  const limited = s.limited ? `, ${s.limited} at the limit of the evidence${s.limited_unreviewed ? ` (${s.limited_unreviewed === s.limited ? (s.limited === 1 ? "its bound" : "their bounds") : `${s.limited_unreviewed} of them`} not yet reviewed by another seat)` : ""}` : "";
  return `Asked parts: ${s.established} of ${s.asked} established${limited}. ${open}${missing}`;
}

/** What a partial answer whose every asked part is established says beside its label (the label is unchanged); null otherwise. */
export function partialPlainWords(result: string | null, s: PartsStanding | null): string | null {
  return result === "partial" && s?.all_asked_established ? "every part the question asks is established" : null;
}

/** An answer's premise citations in words. */
export function citationsWords(cs: readonly PremiseCitation[]): string {
  return cs.map((c) => `${c.stance === "assumed" && c.conditional ? `assuming ${c.id}` : `${c.id} ${c.stance}`} (revision ${c.rev}${c.scope ? `; ${scopeWords(c.scope)}` : ""})${c.refs?.length ? ` on ${c.refs.join(", ")}` : ""}`).join("; ");
}

// --- consistency ------------------------------------------------------------------------------

/** A standing answer's citations, by section and seq. */
export type CitingAnswer = { seq: number; section: string; citations: readonly PremiseCitation[] };

/**
 * One premise revision that one standing answer assumes, without a
 * condition, and another contradicts, over scopes that overlap: whether the
 * contradiction names a rebutting finding that stands (`rebutted`: the
 * finding, and so a premise dispute for the operator) is said with it.
 */
export type PremiseConflict = { premise: string; rev: number; assumed: { seq: number; section: string }; contradicted: { seq: number; section: string; rebuttal: string[] } };

/**
 * The pairs of standing answers that assume and contradict the same premise
 * revision over overlapping scopes (scopesOverlap on each citation's scope:
 * its own narrowing, or the premise's at that revision). A conditional
 * assumption ("assuming P-n") is none; neither is uncertainty (unresolved,
 * supported). Nor is a premise the operator withdrew, or a revision the
 * operator has revised since: the ruling is made, and the answers citing it
 * are warned (premise_withdrawn, premise_revised) until they are recorded
 * again; a hold on a retired revision would force nothing on either side
 * (the Fable review of the limits branch, P2-1). `rebuttal(refs)` says
 * which of a contradiction's refs name a standing, undisputed finding or
 * event. Pure.
 */
export function premiseConflicts(answers: readonly CitingAnswer[], premises: ReadonlyMap<string, Premise> | undefined, rebuttal: (refs: readonly string[]) => string[]): PremiseConflict[] {
  const out: PremiseConflict[] = [];
  const assumed: Array<{ a: CitingAnswer; c: PremiseCitation }> = [];
  const contradicted: Array<{ a: CitingAnswer; c: PremiseCitation }> = [];
  for (const a of answers) {
    for (const c of a.citations) {
      if (c.stance === "assumed" && !c.conditional) assumed.push({ a, c });
      else if (c.stance === "contradicted") contradicted.push({ a, c });
    }
  }
  for (const x of assumed) {
    for (const y of contradicted) {
      if (x.a.seq === y.a.seq || x.c.id !== y.c.id || x.c.rev !== y.c.rev) continue;
      const p = premises?.get(x.c.id);
      if (p && (p.withdrawn || p.rev !== x.c.rev)) continue;
      if (!scopesOverlap(citationScope(x.c, p), citationScope(y.c, p))) continue;
      out.push({ premise: x.c.id, rev: x.c.rev, assumed: { seq: x.a.seq, section: x.a.section }, contradicted: { seq: y.a.seq, section: y.a.section, rebuttal: rebuttal(y.c.refs ?? []) } });
    }
  }
  return out;
}

/** The key a premise dispute is written once by in the operator requests: one per premise revision (requests.ts). */
export function premiseDisputeKey(premise: string, rev: number): string {
  return `premise:${premise}@r${rev}`;
}
