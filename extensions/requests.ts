/**
 * The operator requests: everything the run asks of a person, each with a
 * durable id, a lifecycle and a transactional outbox (docs/adr/0014, the
 * case contract).
 *
 * A request comes from one of six places, each recorded first where its
 * state lives: a lead closed `needs_operator` (the lead register's close
 * event, with an `ask` when it asks for evidence: kind `acquisition`), a
 * clarification an agent asked of a question (the question register's
 * `clarify_ask`), a network item the policy engine opened (the grants chain's
 * `item`), a premise a standing answer contradicts on a standing finding (the
 * ledger's answer and its citation: kind `premise`, one per premise
 * revision, docs/adr/0011 "Premises"), and the harness's own stop proposal
 * when nothing yields (kind `decision`, recorded here first). That record is the commit; this module
 * derives the request from it and writes it once, keyed by where it came
 * from, under its own lock. So a process that dies between the commit and
 * the request loses nothing: the next reconciliation (every header, every
 * hub round, the watchdog's fallback) writes what is missing. An append that
 * fails is never swallowed: the caller is told it is pending.
 *
 * `requests/requests.jsonl` is the chain (the lead register's hash, so
 * custody checks it with the same code); `operator-requests.jsonl`, which the
 * console, the CLI, the calibration scorer and the package have always read,
 * is rendered from it after every write, one line per request as it stands,
 * and `requests/requests.md` beside it, never over a line the chain does not
 * hold: a run from before the chain, a first write cut off, or a line an
 * older harness appended since, each imported whole by its sha256 before
 * anything else is written (the first import published at once, by rename).
 *
 * The lifecycle: pending (committed, nobody told yet) → notified (the
 * operator's notification targets were handed its id) → acknowledged → one
 * of answered, declined, withdrawn. An acquisition also carries its own
 * stages: requested → authorised | declined → collecting → received →
 * validated | unavailable. Under the case policy's `more_evidence: no` the
 * hub answers an acquisition at once, "no additional input under this case
 * policy": a constraint of the case, never a finding that something is
 * absent. Under `yes` the policy authorises it, and the operator collects.
 *
 * Notifications carry ids only (the request's, its kind, the lead's or
 * question's id), never what was asked: a notification leaves the host. A
 * delivery is claimed on the chain before it is sent, so two dispatchers
 * (the hub, the watchdog's fallback) never both send one. The operator's
 * acts are said on the board from their events, once each, by key.
 * Nothing here knows a case or a tool.
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as PM from "./premises.ts";
import * as P from "./protocol.ts";
import type { QuestionEvent } from "./questions.ts";

// --- the files --------------------------------------------------------------------------------

export const REQUESTS_DIR = "requests";
export const REQUESTS_LOG = "requests/requests.jsonl";
export const REQUESTS_MD = "requests/requests.md";
/** The rendered view every older reader reads: one line per request, as it stands. */
export const REQUESTS_VIEW = "operator-requests.jsonl";
const LOCK = "requests";

// --- the vocabulary ---------------------------------------------------------------------------

export const REQUEST_KINDS = ["lead", "acquisition", "clarification", "decision", "network", "premise"] as const;
export type RequestKind = (typeof REQUEST_KINDS)[number];
export const REQUEST_STATES = ["pending", "notified", "acknowledged", "answered", "declined", "withdrawn"] as const;
export type RequestState = (typeof REQUEST_STATES)[number];
export const ACQUISITION_STAGES = ["requested", "authorised", "declined", "collecting", "received", "validated", "unavailable"] as const;
export type AcquisitionStage = (typeof ACQUISITION_STAGES)[number];
/** How soon: normal, urgent, or volatile (the source may be lost if it is not collected soon). */
export const URGENCY = ["normal", "urgent", "volatile"] as const;
export type Urgency = (typeof URGENCY)[number];
export const REQUEST_ID = /^R-([1-9]\d{0,6})$/;
export const ASK_TEXT_MAX = 2000;

/** The words the hub answers an acquisition with under more_evidence: no (case-policy.ts NO_MORE_EVIDENCE_ANSWER). */
export const NO_MORE_EVIDENCE = "no additional input under this case policy";

/**
 * What an acquisition asks for: the missing source, where it is, the
 * questions it bears on, what it would establish, how soon, who holds it,
 * and what authority collecting it needs.
 */
export type AcquisitionAsk = {
  kind: "acquisition";
  source: string;
  where: string;
  questions: string[];
  expected_value: string;
  urgency: Urgency;
  owner: string;
  authority_needed: string;
};

export type RequestEventKind = "open" | "notified" | "acknowledged" | "answered" | "declined" | "withdrawn" | "stage" | "claimed" | "delivery_failed";

export type RequestEvent = {
  v: 1;
  seq: number;
  at: string;
  /** Who: an agent, "harness", "case policy", "operator" or an enrolled person. */
  by: string;
  ev: RequestEventKind;
  rid: string;
  // open
  kind?: RequestKind;
  /** Where it came from, the key it is written once by: lead:L-3:<close seq>, clarification:Q-2#C-1, network:NI-1, decision:D-1, premise:P-1@r1. */
  key?: string;
  /** The request as its readers have always seen it (operator-requests.jsonl's line). */
  line?: Record<string, unknown>;
  ask?: AcquisitionAsk;
  questions?: string[];
  lead?: string;
  /** A line of a run from before the chain, kept whole. */
  imported?: boolean;
  /** An imported line: the sha256 of the line as the view held it, by which it is imported once. */
  line_sha256?: string;
  /** An imported line the watchdog of a run from before the chain had notified already (its traces/idle-nudge.requests count covered it). */
  legacy_notified?: boolean;
  /** claimed, notified, delivery_failed: the dispatch that claimed the delivery, so two dispatchers never both send. */
  claim?: string;
  /** An operator's act made through requests-cli or the console: said on the board, once, derived from this event. */
  announce?: boolean;
  // notified
  targets?: string[];
  notice?: Record<string, unknown>;
  // acknowledged, answered, declined, withdrawn
  text?: string;
  why?: string;
  cause?: string;
  // stage
  stage?: AcquisitionStage;
  import?: string;
  inventory_rev?: number;
  sha256?: string[];
  prev: string;
  hash: string;
};

export type RequestDraft = Omit<RequestEvent, "v" | "seq" | "at" | "prev" | "hash"> & { at?: string };

export type OperatorRequest = {
  rid: string;
  n: number;
  kind: RequestKind;
  key: string;
  at: string;
  by: string;
  line: Record<string, unknown>;
  ask: AcquisitionAsk | null;
  questions: string[];
  lead: string | null;
  imported: boolean;
  /** Imported, and notified already by the watchdog of the run from before the chain. */
  legacy_notified: boolean;
  /** A delivery claimed and not yet settled (notified, or failed): no other dispatch sends it while the claim is fresh. */
  claim: { at: string; token: string } | null;
  /** Deliveries that failed since the last success, and when the last did: the next is tried after a backoff. */
  failures: number;
  last_failure_at: string | null;
  state: RequestState;
  stage: AcquisitionStage | null;
  notified: Array<{ at: string; targets: string[] }>;
  acknowledged: { at: string; by: string } | null;
  closed: { ev: "answered" | "declined" | "withdrawn"; at: string; by: string; text: string; cause: string } | null;
  stages: Array<{ stage: AcquisitionStage; at: string; by: string; why: string; import?: string; inventory_rev?: number; sha256?: string[] }>;
  history: Array<{ seq: number; at: string; ev: RequestEventKind; by: string; text?: string; why?: string; cause?: string; stage?: AcquisitionStage; targets?: string[] }>;
  last_seq: number;
};

export type RequestsState = {
  events: RequestEvent[];
  requests: Map<string, OperatorRequest>;
  byKey: Map<string, string>;
  chain: { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };
};

// --- the chain (the lead register's hash: custody checks it with verifyLeadChain) ----------------

function core(e: Omit<RequestEvent, "prev" | "hash"> | RequestEvent): string {
  const { prev: _p, hash: _h, ...rest } = e as RequestEvent;
  return JSON.stringify(P.canonicalValue(rest));
}

export function requestEventHash(e: Omit<RequestEvent, "hash"> | RequestEvent, prev: string): string {
  return P.sha256Hex(`${prev}\n${core(e)}`);
}

export function verifyRequestChain(text: string): RequestsState["chain"] & { total: number } {
  let prev = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let e: RequestEvent;
    try {
      e = JSON.parse(line) as RequestEvent;
    } catch {
      return { ok: false, total, broken_at: total, reason: "the line is not JSON", head: null };
    }
    if (e.seq !== total) return { ok: false, total, broken_at: total, reason: `the line has seq ${e.seq}, not ${total}`, head: null };
    if (e.prev !== prev) return { ok: false, total, broken_at: total, reason: "the line does not chain to the one before", head: null };
    if (e.hash !== requestEventHash(e, prev)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    prev = e.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? prev : null };
}

export async function readRequestEvents(sandboxRoot: string): Promise<{ events: RequestEvent[]; text: string }> {
  const text = await readFile(join(sandboxRoot, REQUESTS_LOG), "utf8").catch(() => "");
  const events: RequestEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as RequestEvent);
    } catch {
      // the chain check names it
    }
  }
  return { events, text };
}

/** The requests as they stand, folded from the chain in order. */
export function foldRequests(events: RequestEvent[], chain: RequestsState["chain"] = { ok: true, broken_at: null, reason: null, head: events.at(-1)?.hash ?? null }): RequestsState {
  const requests = new Map<string, OperatorRequest>();
  const byKey = new Map<string, string>();
  for (const e of events) {
    if (e.ev === "open") {
      if (!e.rid || requests.has(e.rid)) continue;
      requests.set(e.rid, {
        rid: e.rid,
        n: Number(REQUEST_ID.exec(e.rid)?.[1] ?? 0),
        kind: e.kind ?? "lead",
        key: e.key ?? e.rid,
        at: e.at,
        by: e.by,
        line: e.line ?? {},
        ask: e.ask ?? null,
        questions: [...(e.questions ?? e.ask?.questions ?? [])],
        lead: e.lead ?? null,
        imported: e.imported === true,
        legacy_notified: e.legacy_notified === true,
        claim: null,
        failures: 0,
        last_failure_at: null,
        state: "pending",
        stage: e.kind === "acquisition" ? "requested" : null,
        notified: [],
        acknowledged: null,
        closed: null,
        stages: e.kind === "acquisition" ? [{ stage: "requested", at: e.at, by: e.by, why: "" }] : [],
        history: [{ seq: e.seq, at: e.at, ev: "open", by: e.by }],
        last_seq: e.seq,
      });
      if (e.key) byKey.set(e.key, e.rid);
      continue;
    }
    const r = requests.get(e.rid);
    if (!r) continue;
    if (e.ev === "claimed") {
      r.claim = { at: e.at, token: e.claim ?? "" };
      continue;
    }
    if (e.ev === "delivery_failed") {
      if (!r.claim || r.claim.token === e.claim) r.claim = null;
      // No target took it (none configured for this notifier): released, never a failure to back off from.
      if (e.cause !== "no_target") {
        r.failures += 1;
        r.last_failure_at = e.at;
      }
      r.history.push({ seq: e.seq, at: e.at, ev: e.ev, by: e.by, ...(e.why ? { why: e.why } : {}) });
      r.last_seq = e.seq;
      continue;
    }
    r.history.push({ seq: e.seq, at: e.at, ev: e.ev, by: e.by, ...(e.text ? { text: e.text } : {}), ...(e.why ? { why: e.why } : {}), ...(e.cause ? { cause: e.cause } : {}), ...(e.stage ? { stage: e.stage } : {}), ...(e.targets ? { targets: e.targets } : {}) });
    r.last_seq = e.seq;
    switch (e.ev) {
      case "notified":
        r.notified.push({ at: e.at, targets: e.targets ?? [] });
        r.claim = null;
        r.failures = 0;
        break;
      case "acknowledged":
        if (!r.acknowledged) r.acknowledged = { at: e.at, by: e.by };
        break;
      case "answered":
      case "declined":
      case "withdrawn":
        if (!r.closed) r.closed = { ev: e.ev, at: e.at, by: e.by, text: e.text ?? e.why ?? "", cause: e.cause ?? "" };
        break;
      case "stage":
        if (e.stage) {
          r.stage = e.stage;
          r.stages.push({ stage: e.stage, at: e.at, by: e.by, why: e.why ?? "", ...(e.import ? { import: e.import } : {}), ...(e.inventory_rev !== undefined ? { inventory_rev: e.inventory_rev } : {}), ...(e.sha256 ? { sha256: e.sha256 } : {}) });
        }
        break;
    }
  }
  for (const r of requests.values()) r.state = stateOf(r);
  return { events, requests, byKey, chain };
}

function stateOf(r: OperatorRequest): RequestState {
  if (r.closed) return r.closed.ev;
  if (r.acknowledged || (r.stage && ["authorised", "collecting", "received"].includes(r.stage))) return "acknowledged";
  if (r.notified.length) return "notified";
  return "pending";
}

export async function requestsSnapshot(sandboxRoot: string): Promise<RequestsState> {
  const { events, text } = await readRequestEvents(sandboxRoot);
  const chain = verifyRequestChain(text);
  return foldRequests(events, { ok: chain.ok, broken_at: chain.broken_at, reason: chain.reason, head: chain.head });
}

/** Whether a request still waits on a person. */
export function isOpen(r: OperatorRequest): boolean {
  return !r.closed;
}

async function appendHeld(sandboxRoot: string, drafts: RequestDraft[], held: P.HeldLock): Promise<RequestEvent[]> {
  const { events, text } = await readRequestEvents(sandboxRoot);
  const chain = verifyRequestChain(text);
  if (!chain.ok) throw new Error(`${REQUESTS_LOG}'s chain is broken at line ${chain.broken_at} (${chain.reason}); no request is written until the operator looks`);
  let prev = chain.head ?? "genesis";
  let seq = events.length;
  const out: RequestEvent[] = [];
  for (const raw of drafts) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: raw.at ?? new Date().toISOString(), ...Object.fromEntries(Object.entries(raw).filter(([k, x]) => k !== "at" && x !== undefined)) } as Omit<RequestEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<RequestEvent, "hash">;
    const e = { ...withPrev, hash: requestEventHash(withPrev, prev) } as RequestEvent;
    out.push(e);
    prev = e.hash;
  }
  if (!out.length) return out;
  await mkdir(join(sandboxRoot, REQUESTS_DIR), { recursive: true });
  await held.assertOwned();
  // One write, flushed before anything is said of it: the commit.
  const fh = await open(join(sandboxRoot, REQUESTS_LOG), "a");
  try {
    await fh.write(out.map((e) => `${JSON.stringify(e)}\n`).join(""));
    await fh.sync();
  } finally {
    await fh.close();
  }
  return out;
}

/** Run fn under the requests' lock with the state read inside it; what it returns is appended and the views rendered. */
async function transact<T>(sandboxRoot: string, fn: (s: RequestsState) => Promise<{ append: RequestDraft[]; result: T }>): Promise<T & { events: RequestEvent[] }> {
  return P.withNamedLock(sandboxRoot, LOCK, async (held) => {
    const imported = await importLegacy(sandboxRoot, held);
    const s = await requestsSnapshot(sandboxRoot);
    const { append, result } = await fn(s);
    const events = append.length ? await appendHeld(sandboxRoot, append, held) : [];
    if (events.length || imported) await renderViews(sandboxRoot).catch(() => undefined);
    return { ...result, events };
  });
}

// --- a run from before the chain -----------------------------------------------------------------

/** The key a request line of a run from before the chain is found by. */
function legacyKey(o: Record<string, unknown>, i: number): { kind: RequestKind; key: string } {
  const kind = String(o.kind ?? "");
  if (kind === "clarification") return { kind: "clarification", key: `clarification:${o.q ?? ""}#${o.id ?? ""}` };
  if (kind === "decision") return { kind: "decision", key: `decision:${o.id ?? i}` };
  if (kind === "network") return { kind: "network", key: `network:${o.item ?? i}` };
  return { kind: "lead", key: `lead:${o.lead ?? "?"}:legacy${i}` };
}

/**
 * How far the watchdog of a run from before the chain had notified its
 * lines: traces/idle-nudge.requests held the count of view lines it had
 * handed to notify.sh. A value that is not such a count (none, or the new
 * watchdog's time mark) says nothing, and nothing is taken as notified.
 */
async function legacyNotifiedCount(sandboxRoot: string): Promise<number> {
  const raw = (await readFile(join(sandboxRoot, "traces", "idle-nudge.requests"), "utf8").catch(() => "")).trim();
  const n = /^\d{1,6}$/.test(raw) ? Number(raw) : 0;
  return n;
}

/** A line of the view no chain event holds: one from before the chain, or written by an older harness since. */
function unimported(viewText: string, s: RequestsState): Array<{ raw: string; o: Record<string, unknown>; sha: string; index: number }> {
  const heldSha = new Set<string>();
  const heldLine = new Set<string>();
  for (const e of s.events) {
    if (e.ev !== "open") continue;
    if (e.line_sha256) heldSha.add(e.line_sha256);
    if (e.imported && e.line) heldLine.add(JSON.stringify(P.canonicalValue(e.line)));
  }
  const out: Array<{ raw: string; o: Record<string, unknown>; sha: string; index: number }> = [];
  let index = 0;
  for (const raw of viewText.split("\n")) {
    if (!raw.trim()) continue;
    index += 1;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      o = { unreadable: raw };
    }
    // A line rendered from the chain names a request the chain holds.
    if (typeof o.rid === "string" && s.requests.has(o.rid)) continue;
    const sha = P.sha256Hex(raw.trim());
    if (heldSha.has(sha) || heldLine.has(JSON.stringify(P.canonicalValue(o)))) continue;
    out.push({ raw, o, sha, index });
  }
  return out;
}

/**
 * Every line of operator-requests.jsonl that the chain does not hold,
 * imported whole before anything else is written, so the rendered view
 * never loses one: a run from before the chain (its first write), a chain
 * whose first write was cut off (an empty or absent requests.jsonl beside a
 * view with lines is an initialisation not finished, never a finished one),
 * and a line an older harness appended since. Each is found again by its
 * sha256, and imported once. The first import is published whole: written
 * beside the chain, flushed, and renamed onto it, so a crash leaves either
 * no chain (and the view untouched) or all of it.
 */
async function importLegacy(sandboxRoot: string, held: P.HeldLock): Promise<boolean> {
  const text = await readFile(join(sandboxRoot, REQUESTS_VIEW), "utf8").catch(() => "");
  if (!text.trim()) return false;
  const s = await requestsSnapshot(sandboxRoot);
  if (!s.chain.ok) return false;
  const lines = unimported(text, s);
  if (!lines.length) return false;
  const notifiedBefore = s.events.length ? 0 : await legacyNotifiedCount(sandboxRoot);
  let next = Math.max(0, ...[...s.requests.values()].map((x) => x.n));
  const drafts: RequestDraft[] = [];
  for (const { o, sha, index } of lines) {
    const legacy = legacyKey(o, index);
    const key = s.byKey.has(legacy.key) || drafts.some((d) => d.key === legacy.key) ? `legacy:${sha}` : legacy.key;
    next += 1;
    drafts.push({ at: typeof o.at === "string" ? o.at : undefined, by: String(o.by ?? "harness"), ev: "open", rid: `R-${next}`, kind: legacy.kind, key, line: o, imported: true, line_sha256: sha, ...(index <= notifiedBefore ? { legacy_notified: true } : {}), ...(typeof o.lead === "string" ? { lead: o.lead } : {}) });
  }
  if (s.events.length) {
    await appendHeld(sandboxRoot, drafts, held);
    return true;
  }
  // The first write: the whole import at once, never an empty or partial chain.
  let prev = "genesis";
  const out: string[] = [];
  let seq = 0;
  for (const raw of drafts) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: raw.at ?? new Date().toISOString(), ...Object.fromEntries(Object.entries(raw).filter(([k, x]) => k !== "at" && x !== undefined)) } as Omit<RequestEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<RequestEvent, "hash">;
    const e = { ...withPrev, hash: requestEventHash(withPrev, prev) } as RequestEvent;
    out.push(`${JSON.stringify(e)}\n`);
    prev = e.hash;
  }
  await mkdir(join(sandboxRoot, REQUESTS_DIR), { recursive: true });
  await held.assertOwned();
  const path = join(sandboxRoot, REQUESTS_LOG);
  const tmp = `${path}.import-${process.pid}-${Math.random().toString(36).slice(2)}`;
  const fh = await open(tmp, "w");
  try {
    await fh.write(out.join(""));
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
  return true;
}

// --- the views -------------------------------------------------------------------------------

/** One request as operator-requests.jsonl carries it: its line as always, and how it stands now. */
export function viewLine(r: OperatorRequest): Record<string, unknown> {
  return {
    ...r.line,
    rid: r.rid,
    kind: r.kind,
    state: r.state,
    ...(r.stage ? { stage: r.stage } : {}),
    ...(r.ask ? { ask: r.ask } : {}),
    ...(r.questions.length ? { questions: r.questions } : {}),
    ...(r.closed ? { closed: r.closed } : {}),
    ...(r.acknowledged ? { acknowledged: r.acknowledged } : {}),
    ...(r.notified.length ? { notified: r.notified } : {}),
    ...(r.stages.length > 1 ? { stages: r.stages } : {}),
  };
}

async function writeAtomic(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
  await writeFile(tmp, text, "utf8");
  await rename(tmp, path);
}

/** operator-requests.jsonl and requests/requests.md, rendered from the chain. */
export async function renderViews(sandboxRoot: string, snap?: RequestsState): Promise<void> {
  const s = snap ?? (await requestsSnapshot(sandboxRoot));
  // A view that holds a line the chain does not (a run from before the chain, an older harness's line) is never rewritten from the chain: the next write imports it first.
  const current = await readFile(join(sandboxRoot, REQUESTS_VIEW), "utf8").catch(() => "");
  if (current.trim() && unimported(current, s).length) return;
  const list = [...s.requests.values()].sort((a, b) => a.n - b.n);
  await writeAtomic(join(sandboxRoot, REQUESTS_VIEW), list.map((r) => `${JSON.stringify(viewLine(r))}\n`).join(""));
  const md: string[] = ["# Operator requests", "", "What the run asked of a person, and how each request stands. Rendered by the harness from `requests/requests.jsonl` after every change; do not edit.", ""];
  const open = list.filter(isOpen);
  md.push(`${list.length} request(s), ${open.length} open; chain ${s.chain.ok ? "intact" : `BROKEN at line ${s.chain.broken_at} (${s.chain.reason})`}.`, "");
  for (const r of list) {
    md.push(`## ${r.rid} — ${r.kind}, ${r.state}${r.stage ? ` (stage ${r.stage})` : ""}`, "");
    md.push(`- Asked by ${r.by} at ${r.at}${r.lead ? ` on ${r.lead}` : ""}${r.questions.length ? `; questions ${r.questions.join(", ")}` : ""}`);
    if (r.line.title) md.push(`- ${String(r.line.title)}`);
    if (r.line.request) md.push(`- Request: ${String(r.line.request)}`);
    if (r.ask) md.push(`- Source: ${r.ask.source}; where: ${r.ask.where}; would establish: ${r.ask.expected_value}; urgency ${r.ask.urgency}${r.ask.owner ? `; held by ${r.ask.owner}` : ""}${r.ask.authority_needed ? `; authority needed: ${r.ask.authority_needed}` : ""}`);
    if (r.line.answer) md.push(`- Answered with: \`${String(r.line.answer)}\``);
    for (const h of r.history.slice(1)) md.push(`- ${h.at} ${h.ev}${h.stage ? ` ${h.stage}` : ""} by ${h.by}${h.targets ? ` (to ${h.targets.join(", ") || "no target"})` : ""}${h.text ? `: ${h.text}` : h.why ? `: ${h.why}` : ""}`);
    md.push("");
  }
  await writeAtomic(join(sandboxRoot, REQUESTS_MD), `${md.join("\n")}\n`);
}

// --- the ask --------------------------------------------------------------------------------------

/**
 * An acquisition ask as an agent gives it on lead_close (needs_operator,
 * ask: {kind: "acquisition", …}), checked: the source, where it is and what
 * it would establish are required; urgency normal, urgent or volatile; the
 * questions are the lead's when none are named. Nothing is cut: a longer
 * text is refused.
 */
export function checkAsk(raw: unknown, leadAnswers: string[]): { ok: true; ask: AcquisitionAsk | null } | { ok: false; reason: string } {
  if (raw === undefined || raw === null || raw === "") return { ok: true, ask: null };
  if (typeof raw !== "object" || Array.isArray(raw)) return { ok: false, reason: "ask is an object: {kind: \"acquisition\", source, where, expected_value, urgency, questions?, owner?, authority_needed?}" };
  const a = raw as Record<string, unknown>;
  const kind = String(a.kind ?? "acquisition").trim().toLowerCase();
  if (kind !== "acquisition") return { ok: false, reason: `ask.kind is acquisition (evidence the run does not have); anything else the operator must do is said in ref (got ${JSON.stringify(a.kind)})` };
  const text = (name: string, required: boolean): { ok: true; value: string } | { ok: false; reason: string } => {
    const v = String(a[name] ?? "").trim();
    if (required && !v) return { ok: false, reason: `an acquisition names its ${name.replace(/_/g, " ")} (ask.${name})` };
    if (v.length > ASK_TEXT_MAX) return { ok: false, reason: `ask.${name} is over ${ASK_TEXT_MAX} characters: nothing is cut, so a longer text is refused` };
    return { ok: true, value: v };
  };
  const source = text("source", true);
  if (!source.ok) return source;
  const where = text("where", true);
  if (!where.ok) return where;
  const expected = text("expected_value", true);
  if (!expected.ok) return expected;
  const owner = text("owner", false);
  if (!owner.ok) return owner;
  const authority = text("authority_needed", false);
  if (!authority.ok) return authority;
  const urgency = String(a.urgency ?? "normal").trim().toLowerCase();
  if (!(URGENCY as readonly string[]).includes(urgency)) return { ok: false, reason: `ask.urgency is one of ${URGENCY.join(", ")} (volatile: the source may be lost if it is not collected soon)` };
  const qs = Array.isArray(a.questions) ? a.questions.map(String) : typeof a.questions === "string" ? a.questions.split(/[\s,]+/) : [];
  const questions = [...new Set((qs.length ? qs : leadAnswers).map((q) => q.trim()).filter(Boolean))];
  if (questions.length > 20) return { ok: false, reason: "an acquisition names at most 20 questions" };
  return { ok: true, ask: { kind: "acquisition", source: source.value, where: where.value, questions, expected_value: expected.value, urgency: urgency as Urgency, owner: owner.value, authority_needed: authority.value } };
}

/** A question id as the register writes it (Q-3), from Q-3, question:3, 3 or Q3. */
export function questionId(raw: string): string {
  const t = String(raw ?? "").trim();
  const m = /^(?:question:)?Q-?(\d+)$/i.exec(t) ?? /^(?:question:)?(\d+)$/.exec(t);
  return m ? `Q-${Number(m[1])}` : t;
}

// --- reconciliation: the requests the committed records imply ------------------------------------

type LeadEv = { seq: number; at: string; by: string; ev: string; lead?: string; title?: string; answers?: string[]; disposition?: string; ref?: string; ask?: unknown; why?: string; cause?: string; text?: string };
type QuestionEv = { seq: number; at: string; by: string; ev: string; q?: string; rev?: number; act?: { clarify?: string; what?: string; answer?: string; why?: string }; decided?: { to?: string } };
type NetEv = { seq: number; at: string; by: string; ev: string; item?: string; host?: string; lead?: string | null; request?: string; how?: string; why?: string; grant?: string; principal?: string };

function jsonLines<T>(text: string): T[] {
  const out: T[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch {
      // a torn line: the owning chain's check names it
    }
  }
  return out;
}

async function runId(sandboxRoot: string): Promise<string> {
  return (await P.readTeam(sandboxRoot).catch(() => null))?.swarm_id ?? "";
}

/** What the case policy says of more evidence (network/policy.json more_evidence): no, ask (the default, and a run with no policy) or yes. */
export async function casePolicyMoreEvidence(sandboxRoot: string): Promise<"no" | "ask" | "yes"> {
  try {
    const raw = JSON.parse(await readFile(join(sandboxRoot, "network", "policy.json"), "utf8")) as { more_evidence?: string };
    return raw.more_evidence === "no" || raw.more_evidence === "yes" ? raw.more_evidence : "ask";
  } catch {
    return "ask";
  }
}

/**
 * Write every request the committed records imply and this chain does not
 * hold yet, and close every open one whose answer they record: a lead's
 * close needs_operator (answered by the operator's note on it, withdrawn when
 * the harness reopened it first), a clarification (answered by its reply,
 * withdrawn with its question), a network item (granted or denied), a stop
 * proposal (answered when the operator stopped the run, withdrawn when it
 * finished otherwise). An acquisition is held to the case policy as it is
 * written: under more_evidence no it is declined at once with "no
 * additional input under this case policy"; under yes it is authorised.
 * Idempotent: a request is found again by its key.
 */
export async function reconcileRequests(sandboxRoot: string): Promise<{ opened: OperatorRequest[]; closed: string[] }> {
  const S = sandboxRoot;
  const leadsText = await readFile(join(S, "leads", "leads.jsonl"), "utf8").catch(() => "");
  const questionsText = await readFile(join(S, "questions", "questions.jsonl"), "utf8").catch(() => "");
  const grantsText = await readFile(join(S, "network", "grants.jsonl"), "utf8").catch(() => "");
  const leadEvents = jsonLines<LeadEv>(leadsText);
  const qEvents = jsonLines<QuestionEv>(questionsText);
  const netEvents = jsonLines<NetEv>(grantsText);
  const run = await runId(S);
  const more = await casePolicyMoreEvidence(S);
  // The premise disputes (docs/adr/0011, "Premises"): read only where the question chain holds a premise, so a run without one reads nothing more.
  const premiseEvents = qEvents.some((e) => PM.isPremiseEvent(e.ev));
  const premises = premiseEvents ? PM.foldPremises(qEvents as unknown as QuestionEvent[]) : new Map<string, PM.Premise>();
  const ledger = premiseEvents ? await P.readLedger(S).catch(() => [] as P.LedgerEntry[]) : [];
  const ledgerDisputes = premiseEvents ? await P.readDisputes(S).catch(() => [] as P.LedgerDispute[]) : [];
  const stopped = existsSync(join(S, P.STOPPED_REL));
  const finished = existsSync(join(S, "done", "SWARM_DONE"));
  const plan = (s: RequestsState): { append: RequestDraft[]; opened: string[]; closed: string[] } => {
    const append: RequestDraft[] = [];
    const opened: string[] = [];
    const closed: string[] = [];
    let next = Math.max(0, ...[...s.requests.values()].map((x) => x.n));
    const open = (d: Omit<RequestDraft, "rid" | "ev">): string => {
      next += 1;
      const rid = `R-${next}`;
      append.push({ ...d, ev: "open", rid });
      opened.push(rid);
      return rid;
    };
    // --- leads closed needs_operator ---
    const titles = new Map<string, { title: string; answers: string[] }>();
    for (const e of leadEvents) if (e.ev === "open" && e.lead) titles.set(e.lead, { title: e.title ?? "", answers: e.answers ?? [] });
    const importedLeads = [...s.requests.values()].filter((x) => x.imported && x.kind === "lead");
    const claimedImport = new Set<string>();
    for (const e of leadEvents) {
      if (e.ev !== "close" || e.disposition !== "needs_operator" || !e.lead) continue;
      const key = `lead:${e.lead}:${e.seq}`;
      let rid = s.byKey.get(key) ?? append.find((d) => d.key === key)?.rid;
      if (!rid) {
        // A request of a run from before the chain, for this close: the same lead, the same words.
        const legacy = importedLeads.find((x) => !claimedImport.has(x.rid) && x.line.lead === e.lead && String(x.line.request ?? "") === String(e.ref ?? ""));
        if (legacy) {
          claimedImport.add(legacy.rid);
          rid = legacy.rid;
        }
      }
      const lead = titles.get(e.lead);
      const answers = (lead?.answers ?? []).map(questionId);
      if (!rid) {
        const ask = e.ask && typeof e.ask === "object" ? (e.ask as AcquisitionAsk) : null;
        const kind: RequestKind = ask?.kind === "acquisition" ? "acquisition" : "lead";
        const questions = ask ? ask.questions.map(questionId) : answers;
        const answerCmd = kind === "acquisition"
          ? `swarm.sh evidence ${run || "<run>"} add PATH --for R-${next + 1} --why TEXT | swarm.sh requests ${run || "<run>"} authorise|decline|collecting|unavailable R-${next + 1} --why TEXT`
          : `swarm.sh lead ${run || "<run>"} note ${e.lead} "<your answer>" [--allow-host HOST]`;
        const line = { at: e.at, run, ...(kind === "acquisition" ? { kind } : {}), lead: e.lead, by: e.by, title: lead?.title ?? "", request: e.ref ?? "", answer: answerCmd };
        rid = open({ at: e.at, by: e.by, kind, key, line, lead: e.lead, ...(questions.length ? { questions } : {}), ...(ask ? { ask: { ...ask, questions } } : {}) });
        if (kind === "acquisition") {
          if (more === "no") {
            append.push({ by: "case policy", ev: "stage", rid, stage: "declined", why: `${NO_MORE_EVIDENCE} (more_evidence: no)` });
            append.push({ by: "case policy", ev: "declined", rid, text: NO_MORE_EVIDENCE, cause: "case_policy", why: "more_evidence: no: this case admits no further evidence; a constraint of the case, never a finding that the source or the fact is absent" });
            closed.push(rid);
          } else if (more === "yes") {
            append.push({ by: "case policy", ev: "stage", rid, stage: "authorised", why: "more_evidence: yes: further collection is expected under this case policy; the operator collects it" });
          }
        }
      }
      // Its answer, or its withdrawal, as the lead register records it.
      const req = s.requests.get(rid);
      const alreadyClosed = req?.closed || append.some((d) => d.rid === rid && (d.ev === "answered" || d.ev === "declined" || d.ev === "withdrawn"));
      if (alreadyClosed) continue;
      const after = leadEvents.filter((x) => x.lead === e.lead && x.seq > e.seq);
      const nextClose = after.find((x) => x.ev === "close");
      const note = after.find((x) => x.ev === "note" && x.by === "operator" && (!nextClose || x.seq < nextClose.seq));
      const reopen = after.find((x) => x.ev === "reopen" && (!nextClose || x.seq < nextClose.seq));
      if (note) {
        append.push({ at: note.at, by: "operator", ev: "answered", rid, text: note.text ?? "", cause: "lead_note" });
        closed.push(rid);
      } else if (reopen && reopen.cause !== "operator") {
        append.push({ at: reopen.at, by: reopen.by, ev: "withdrawn", rid, why: `${e.lead} was reopened (${reopen.cause ?? "harness"}): ${reopen.why ?? ""}`, cause: "lead_reopened" });
        closed.push(rid);
      }
    }
    // --- clarifications ---
    const withdrawnQ = new Map<string, QuestionEv>();
    for (const e of qEvents) if (e.ev === "withdraw" && e.q) withdrawnQ.set(e.q, e);
    for (const e of qEvents) {
      if (e.ev !== "clarify_ask" || !e.q || !e.act?.clarify) continue;
      const clarify = e.act.clarify;
      const key = `clarification:${e.q}#${clarify}`;
      let rid = s.byKey.get(key) ?? append.find((d) => d.key === key)?.rid;
      if (!rid) {
        const answer = `swarm.sh question ${run || "<run>"} clarify-reply ${e.q} ${e.act.clarify} "<your answer>"`;
        const line = { at: e.at, run, kind: "clarification", id: e.act.clarify, q: e.q, rev: e.rev ?? null, by: e.by, to: e.decided?.to || "operator", title: `${e.q}: clarification ${e.act.clarify}`, request: e.act.what ?? "", answer };
        rid = open({ at: e.at, by: e.by, kind: "clarification", key, line, questions: [e.q] });
      }
      const req = s.requests.get(rid);
      if (req?.closed || append.some((d) => d.rid === rid && d.ev !== "open" && d.ev !== "stage")) continue;
      const answered = qEvents.find((x) => x.ev === "clarify_answer" && x.q === e.q && x.act?.clarify === clarify);
      const wd = withdrawnQ.get(e.q);
      if (answered) {
        append.push({ at: answered.at, by: answered.by, ev: "answered", rid, text: answered.act?.answer ?? "", cause: "clarify_reply" });
        closed.push(rid);
      } else if (wd && wd.seq > e.seq) {
        append.push({ at: wd.at, by: wd.by, ev: "withdrawn", rid, why: `${e.q} was withdrawn: ${wd.act?.why ?? ""}`, cause: "question_withdrawn" });
        closed.push(rid);
      }
    }
    // --- network items ---
    const netRequests = new Map<string, NetEv>();
    for (const e of netEvents) if (e.ev === "request" && e.request) netRequests.set(e.request, e);
    for (const e of netEvents) {
      if (e.ev !== "item" || !e.item) continue;
      const key = `network:${e.item}`;
      let rid = s.byKey.get(key) ?? append.find((d) => d.key === key)?.rid;
      if (!rid) {
        const asker = netRequests.get(e.request ?? "");
        const by = asker?.principal ?? asker?.by ?? e.by;
        const answer = `swarm.sh net ${run || "<run>"} grant ${e.request ?? "NR-<n>"} --why TEXT | swarm.sh net ${run || "<run>"} deny ${e.item} --why TEXT`;
        const line = { at: e.at, run, kind: "network", item: e.item, lead: e.lead ?? "", by, title: `network: ${e.host ?? ""}`, request: `${by} asks to reach ${e.host ?? ""} for ${e.lead ?? "no lead"} (${e.request ?? ""}); refused automatically, overridable`, answer };
        rid = open({ at: e.at, by, kind: "network", key, line, ...(e.lead ? { lead: e.lead } : {}) });
      }
      const req = s.requests.get(rid);
      if (req?.closed || append.some((d) => d.rid === rid && d.ev !== "open")) continue;
      const shut = netEvents.find((x) => x.ev === "item_close" && x.item === e.item);
      if (shut) {
        append.push({ at: shut.at, by: shut.by, ev: shut.how === "granted" ? "answered" : "declined", rid, text: `${shut.how === "granted" ? `granted${shut.grant ? ` (${shut.grant})` : ""}` : "denied"}: ${shut.why ?? ""}`, cause: "network_item" });
        closed.push(rid);
      }
    }
    // --- premise disputes: a standing answer contradicts a premise revision on a standing finding ---
    if (premiseEvents) {
      const replaced = P.supersededBy(ledger);
      const bySeq = new Map(ledger.map((e) => [e.seq, e]));
      const inForce = new Set(P.disputesInForce(ledger, ledgerDisputes).map((d) => d.target));
      const rebuttals = new Map<string, Array<{ premise: string; rev: number; answer: P.LedgerEntry; refs: string[] }>>();
      for (const a of ledger) {
        if (a.kind !== "answer" || !a.section?.startsWith("question:") || replaced.has(a.seq)) continue;
        for (const c of a.premises ?? []) {
          if (c.stance !== "contradicted") continue;
          const refs = P.rebuttingRefs(c.refs ?? [], bySeq, replaced, inForce);
          if (!refs.length) continue;
          const key = PM.premiseDisputeKey(c.id, c.rev);
          rebuttals.set(key, [...(rebuttals.get(key) ?? []), { premise: c.id, rev: c.rev, answer: a, refs }]);
        }
      }
      for (const [key, list] of rebuttals) {
        if (s.byKey.get(key) ?? append.find((d) => d.key === key)) continue;
        const first = list[0]!;
        const answerCmd = `swarm.sh question ${run || "<run>"} premise revise ${first.premise} --expect-rev ${first.rev} --why TEXT [--text T] [--locator L] | swarm.sh question ${run || "<run>"} premise withdraw ${first.premise} --why TEXT | swarm.sh requests ${run || "<run>"} answer R-${next + 1} "the premise stands, and why"`;
        const line = { at: first.answer.at, run, kind: "premise", id: first.premise, rev: first.rev, by: first.answer.by, title: `${first.premise} revision ${first.rev} is disputed`, request: `${list.map((x) => `E-${x.answer.seq} (${x.answer.section}) contradicts it on ${x.refs.join(", ")}`).join("; ")}: rule on the premise. Nothing waits on it: the answers that assume it are warned`, answer: answerCmd };
        open({ at: first.answer.at, by: first.answer.by, kind: "premise", key, line, questions: [...new Set(list.map((x) => questionId(x.answer.section!)))] });
      }
      // Closed when the premise moved on (revised or withdrawn), or when no standing answer contradicts it on a standing finding any more.
      for (const req of s.requests.values()) {
        if (req.kind !== "premise" || req.closed) continue;
        const id = String(req.line.id ?? "");
        const rev = Number(req.line.rev ?? 0);
        const p = premises.get(id);
        if (p?.withdrawn) {
          append.push({ at: p.withdrawn.at, by: "operator", ev: "answered", rid: req.rid, text: `${id} was withdrawn: ${p.withdrawn.why}`, cause: "premise_withdrawn" });
          closed.push(req.rid);
        } else if (p && p.rev > rev) {
          const r = p.revisions.find((x) => x.rev > rev)!;
          append.push({ at: r.at, by: "operator", ev: "answered", rid: req.rid, text: `${id} was revised to revision ${r.rev}${r.why ? `: ${r.why}` : ""}`, cause: "premise_revised" });
          closed.push(req.rid);
        } else if (!rebuttals.has(req.key)) {
          append.push({ by: "harness", ev: "withdrawn", rid: req.rid, why: `no standing answer contradicts ${id} revision ${rev} on a standing finding any more`, cause: "no_rebuttal" });
          closed.push(req.rid);
        }
      }
    }
    // --- stop proposals: the operator stopped the run, or it finished otherwise ---
    for (const req of s.requests.values()) {
      if (req.kind !== "decision" || req.closed) continue;
      if (stopped) {
        append.push({ by: "operator", ev: "answered", rid: req.rid, text: "the operator stopped the run", cause: "stopped" });
        closed.push(req.rid);
      } else if (finished) {
        append.push({ by: "harness", ev: "withdrawn", rid: req.rid, why: "the run finished before the operator acted on the proposal", cause: "finished" });
        closed.push(req.rid);
      }
    }
    return { append, opened, closed };
  };
  // Read first, without the lock: a header or a round that finds nothing to write takes no lock.
  if (existsSync(join(S, REQUESTS_LOG)) || !existsSync(join(S, REQUESTS_VIEW))) {
    const now = await requestsSnapshot(S);
    const view = await readFile(join(S, REQUESTS_VIEW), "utf8").catch(() => "");
    if (now.chain.ok && !plan(now).append.length && !unimported(view, now).length) return { opened: [], closed: [] };
  }
  const r = await transact(S, async (s) => {
    const p = plan(s);
    return { append: p.append, result: { opened: p.opened, closed: p.closed } };
  });
  const snap = await requestsSnapshot(S);
  return { opened: r.opened.map((rid) => snap.requests.get(rid)!).filter(Boolean), closed: r.closed };
}

/**
 * A request the harness makes itself, recorded here first (a stop proposed
 * when nothing yields): written once by its key, the id returned.
 */
export async function openHarnessRequest(sandboxRoot: string, d: { kind: RequestKind; key: string; by: string; line: Record<string, unknown>; questions?: string[] }): Promise<{ rid: string; created: boolean }> {
  const r = await transact(sandboxRoot, async (s) => {
    const had = s.byKey.get(d.key);
    if (had) return { append: [], result: { rid: had, created: false } };
    const n = Math.max(0, ...[...s.requests.values()].map((x) => x.n)) + 1;
    const rid = `R-${n}`;
    return { append: [{ by: d.by, ev: "open" as const, rid, kind: d.kind, key: d.key, line: { ...d.line, rid }, ...(d.questions?.length ? { questions: d.questions } : {}) }], result: { rid, created: true } };
  });
  return { rid: r.rid, created: r.created };
}

/**
 * How many requests of a kind the run holds (a stop proposal's D-n counts
 * from it): the chain's, or, in a run whose requests predate the chain and
 * were not imported yet, the view's lines of that kind.
 */
export async function countKind(sandboxRoot: string, kind: RequestKind): Promise<number> {
  const s = await requestsSnapshot(sandboxRoot);
  let n = 0;
  for (const r of s.requests.values()) if (r.kind === kind) n += 1;
  // And the view's lines the chain does not hold yet (a run from before the chain, not imported yet).
  const view = await readFile(join(sandboxRoot, REQUESTS_VIEW), "utf8").catch(() => "");
  for (const l of unimported(view, s)) if ((l.o.kind ?? "lead") === kind) n += 1;
  return n;
}

// --- the operator's acts ---------------------------------------------------------------------

export type RequestActResult = { ok: true; request: OperatorRequest; events: number[] } | { ok: false; reason: string };

function requestRef(raw: unknown): { ok: true; rid: string } | { ok: false; reason: string } {
  const m = /^R-?([1-9]\d{0,6})$/i.exec(String(raw ?? "").trim());
  return m ? { ok: true, rid: `R-${Number(m[1])}` } : { ok: false, reason: `a request is named R-<n> (got ${JSON.stringify(raw)})` };
}

const STAGE_NEXT: Record<AcquisitionStage, AcquisitionStage[]> = {
  requested: ["authorised", "declined", "unavailable", "received"],
  authorised: ["collecting", "declined", "unavailable", "received"],
  collecting: ["received", "unavailable"],
  received: ["validated", "unavailable"],
  declined: [],
  validated: [],
  unavailable: [],
};

/**
 * One act of the operator's on a request: acknowledge it, answer it (a
 * decision, or a lead's through its note), decline or withdraw it, or move
 * an acquisition along its stages (authorised, declined, collecting,
 * received, validated, unavailable). Each needs its reason where the
 * lifecycle ends; an act on a closed request, or a stage out of order, is
 * refused with why.
 */
export async function requestAct(sandboxRoot: string, rawId: unknown, act: { ev: "acknowledged" | "answered" | "declined" | "withdrawn" | "stage"; by: string; text?: string; why?: string; stage?: AcquisitionStage; import?: string; inventory_rev?: number; sha256?: string[]; cause?: string; announce?: boolean }): Promise<RequestActResult> {
  const ref = requestRef(rawId);
  if (!ref.ok) return ref;
  const text = String(act.text ?? "").trim();
  const why = String(act.why ?? "").trim();
  if (text.length > 4000 || why.length > 4000) return { ok: false, reason: "a request's answer or reason is at most 4000 characters: nothing is cut, so a longer one is refused" };
  try {
    const r = await transact<{ ok: true } | { ok: false; reason: string }>(sandboxRoot, async (s) => {
      const req = s.requests.get(ref.rid);
      if (!req) return { append: [], result: { ok: false, reason: `${ref.rid} is not a request of this run` } };
      if (req.closed && act.ev !== "stage") return { append: [], result: { ok: false, reason: `${ref.rid} is ${req.closed.ev} already (by ${req.closed.by}, ${req.closed.at})` } };
      const drafts: RequestDraft[] = [];
      switch (act.ev) {
        case "acknowledged":
          if (req.acknowledged) return { append: [], result: { ok: false, reason: `${ref.rid} was acknowledged already, by ${req.acknowledged.by}` } };
          drafts.push({ by: act.by, ev: "acknowledged", rid: req.rid, ...(why ? { why } : {}) });
          break;
        case "answered":
          if (!text) return { append: [], result: { ok: false, reason: "an answer says what it is" } };
          drafts.push({ by: act.by, ev: "answered", rid: req.rid, text, cause: act.cause ?? "operator" });
          break;
        case "declined":
        case "withdrawn":
          if (!why) return { append: [], result: { ok: false, reason: `${act.ev === "declined" ? "a decline" : "a withdrawal"} says why` } };
          if (req.kind === "acquisition" && act.ev === "declined") drafts.push({ by: act.by, ev: "stage", rid: req.rid, stage: "declined", why });
          drafts.push({ by: act.by, ev: act.ev, rid: req.rid, why, cause: act.cause ?? "operator" });
          break;
        case "stage": {
          if (req.kind !== "acquisition") return { append: [], result: { ok: false, reason: `${ref.rid} is a ${req.kind} request: only an acquisition has stages` } };
          const st = act.stage as AcquisitionStage;
          if (!(ACQUISITION_STAGES as readonly string[]).includes(st) || st === "requested") return { append: [], result: { ok: false, reason: `a stage is one of ${ACQUISITION_STAGES.filter((x) => x !== "requested").join(", ")}` } };
          const at = req.stage ?? "requested";
          // Evidence may arrive for a request the case policy declined only when the operator says why (a new decision).
          if (!STAGE_NEXT[at].includes(st)) return { append: [], result: { ok: false, reason: `${ref.rid} is ${at}: it can go to ${STAGE_NEXT[at].join(", ") || "nothing further"}, not ${st}` } };
          if ((st === "declined" || st === "unavailable") && !why) return { append: [], result: { ok: false, reason: `${st} says why` } };
          drafts.push({ by: act.by, ev: "stage", rid: req.rid, stage: st, ...(why ? { why } : {}), ...(act.import ? { import: act.import } : {}), ...(act.inventory_rev !== undefined ? { inventory_rev: act.inventory_rev } : {}), ...(act.sha256?.length ? { sha256: act.sha256 } : {}) });
          if (!req.closed) {
            if (st === "declined") drafts.push({ by: act.by, ev: "declined", rid: req.rid, why, cause: "acquisition" });
            if (st === "unavailable") drafts.push({ by: act.by, ev: "answered", rid: req.rid, text: `unavailable: ${why}`, cause: "acquisition" });
            if (st === "validated") drafts.push({ by: act.by, ev: "answered", rid: req.rid, text: `received and validated${act.import ? ` as ${act.import}` : ""}${why ? `: ${why}` : ""}`, cause: "evidence_added" });
          }
          break;
        }
      }
      // The operator's act is said on the board, once, derived from its event (publishRequestActs).
      if (act.announce && drafts.length) drafts[0] = { ...drafts[0], announce: true };
      return { append: drafts, result: { ok: true } };
    });
    if (!r.ok) return r;
    const snap = await requestsSnapshot(sandboxRoot);
    return { ok: true, request: snap.requests.get(ref.rid)!, events: r.events.map((e) => e.seq) };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

// --- the outbox: notifications, ids only ------------------------------------------------------

/** What a notification of a request says: ids and kinds, never what was asked. */
export function noticeOf(r: OperatorRequest, run: string): Record<string, unknown> {
  const l = r.line;
  return {
    request: r.rid,
    kind: r.kind,
    run,
    ...(r.lead ? { lead: r.lead } : {}),
    ...(typeof l.q === "string" ? { question: l.q } : {}),
    ...(typeof l.id === "string" && /^[CDP]-\d+$/.test(l.id) ? { id: l.id } : {}),
    ...(typeof l.item === "string" ? { item: l.item } : {}),
    ...(r.questions.length ? { questions: r.questions.filter((q) => /^Q-\d+$/.test(q)) } : {}),
    ...(r.ask ? { urgency: r.ask.urgency } : {}),
    show: `swarm.sh requests ${run || "<run>"} show ${r.rid}`,
  };
}

/** Where the operator's notification targets for a run are kept, outside the run (swarm.sh start --notify). */
export function notifyTargetsOf(runsDir: string, run: string): string[] {
  if (!run || !/^[A-Za-z0-9_-]+$/.test(run) || !runsDir) return [];
  const out: string[] = [];
  const cmd = join(runsDir, "notify", `${run}.cmd`);
  if (existsSync(cmd)) out.push("command");
  try {
    for (const line of readFileSync(join(runsDir, "notify", `${run}.targets`), "utf8").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      const kind = /^([a-z]+):/.exec(t)?.[1] ?? "";
      if (["desktop", "ntfy", "mailto"].includes(kind)) out.push(kind);
    }
  } catch {
    // no typed targets
  }
  return out;
}

export type Notifier = (sandboxRoot: string, event: string, notice: Record<string, unknown>) => Promise<{ targets: string[] }>;

/** The runs directory a run's notification targets are under: the given one, SWARM_RUNS_DIR, or the checkout's runs/. */
export function runsDirOf(given?: string): string {
  if (given) return resolve(given);
  if (process.env.SWARM_RUNS_DIR) return resolve(process.env.SWARM_RUNS_DIR);
  return join(dirname(fileURLToPath(import.meta.url)), "..", "runs");
}

/**
 * The notifier the harness uses: scripts/notify.sh, which finds the run's
 * targets outside the run and hands each one the notice, detached and
 * bounded. Resolves with the targets it handed it to; none configured, none
 * handed (the request stays pending, and the console and the CLI show it).
 */
export function scriptNotifier(runsDir?: string): Notifier {
  return async (sandboxRoot, event, notice) => {
    const dir = runsDirOf(runsDir);
    const run = String(notice.run ?? (await runId(sandboxRoot)));
    const targets = notifyTargetsOf(dir, run);
    if (!targets.length) return { targets: [] };
    const script = join(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "notify.sh");
    if (!existsSync(script)) return { targets: [] };
    // notify.sh hands each target the notice detached and returns: waited for here without blocking the hub.
    const failed = await runNotify("bash", [script, sandboxRoot, event, JSON.stringify(notice)], { env: { ...process.env, SWARM_RUNS_DIR: dir } });
    if (failed) throw new Error(`notify.sh ${failed}`);
    return { targets };
  };
}

/** How long notify.sh may take to hand the notice on before it is stopped. */
export const NOTIFY_TIMEOUT_MS = 20_000;

/**
 * Run the notifier and say how it failed, or null when it exited 0: the
 * errno when it could not be started, that it took too long and was stopped,
 * the signal that ended it, or its exit status. The first three once all
 * read "could not be run", and a failed delivery said nothing of which.
 */
export function runNotify(cmd: string, args: string[], o: { env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): Promise<string | null> {
  const timeoutMs = o.timeoutMs ?? NOTIFY_TIMEOUT_MS;
  return new Promise((done) => {
    let settled = false;
    let timedOut = false;
    const settle = (why: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      done(why);
    };
    const child = spawn(cmd, args, { env: o.env ?? process.env, stdio: "ignore" });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);
    child.on("error", (err: NodeJS.ErrnoException) => settle(`could not be run (${err.code ?? err.message})`));
    child.on("close", (code, signal) => {
      if (timedOut) settle(`took more than ${timeoutMs >= 1000 ? `${Math.round(timeoutMs / 1000)} s` : `${timeoutMs} ms`} and was stopped`);
      else if (signal) settle(`was ended by ${signal}`);
      else settle(code === 0 ? null : `exited ${code}`);
    });
  });
}

/** How long a claimed delivery is held before another dispatch may take it over (its dispatcher died between the claim and the outcome). */
export const DELIVERY_CLAIM_TTL_MS = 10 * 60_000;

/** The wait after the n-th failed delivery in a row before the next is tried: one minute, doubling, at most an hour. */
export function deliveryBackoffMs(failures: number): number {
  return failures <= 0 ? 0 : Math.min(60_000 * 2 ** (failures - 1), 3_600_000);
}

/**
 * The outbox's delivery: every request committed and not yet notified is
 * claimed on the chain first (a `claimed` event, under the requests' lock),
 * then handed to the notifier with its ids, and `notified` (or
 * `delivery_failed`) goes on the chain after. Two dispatchers (the hub and
 * the watchdog's fallback) never both send one: the second finds it claimed.
 * A crash between the commit and the hand-over leaves it unclaimed or its
 * claim going stale, and the next dispatch sends it; a crash between the
 * hand-over and the `notified` line sends it once more once the claim is
 * stale (at least once, by its id). A failed delivery is tried again after
 * a backoff. A closed request is not notified; an imported one is, unless
 * the watchdog of its run from before the chain had notified it. With no
 * target configured nothing is claimed, sent or written: the request stays
 * pending.
 */
export async function dispatchRequests(sandboxRoot: string, o: { notifier?: Notifier; runsDir?: string; now?: number } = {}): Promise<Array<{ rid: string; targets: string[] }>> {
  const run = await runId(sandboxRoot);
  if (!o.notifier && !notifyTargetsOf(runsDirOf(o.runsDir), run).length) return [];
  const notifier = o.notifier ?? scriptNotifier(o.runsDir);
  const now = o.now ?? Date.now();
  const due = (r: OperatorRequest): boolean =>
    !r.closed &&
    !r.notified.length &&
    !(r.imported && r.legacy_notified) &&
    !(r.claim && now - Date.parse(r.claim.at) < DELIVERY_CLAIM_TTL_MS) &&
    !(r.failures && r.last_failure_at && now - Date.parse(r.last_failure_at) < deliveryBackoffMs(r.failures));
  const before = await requestsSnapshot(sandboxRoot);
  if (!before.chain.ok || ![...before.requests.values()].some(due)) return [];
  // The claim, on the chain, before anything is sent.
  const token = randomUUID();
  const claimed = await transact(sandboxRoot, async (s) => {
    const mine = [...s.requests.values()].filter(due).sort((a, b) => a.n - b.n);
    return { append: mine.map((r) => ({ by: "harness", ev: "claimed" as const, rid: r.rid, claim: token })), result: { rids: mine.map((r) => r.rid) } };
  });
  const snap = await requestsSnapshot(sandboxRoot);
  const out: Array<{ rid: string; targets: string[] }> = [];
  for (const rid of claimed.rids) {
    const r = snap.requests.get(rid);
    if (!r) continue;
    const notice = noticeOf(r, run);
    let why = "";
    const sent = await notifier(sandboxRoot, "operator_request", notice).catch((err: Error) => {
      why = err.message;
      return { targets: [] as string[] };
    });
    await transact(sandboxRoot, async (cur) => {
      const c = cur.requests.get(rid);
      if (!c || c.notified.length) return { append: [], result: {} };
      if (!sent.targets.length) return { append: [{ by: "harness", ev: "delivery_failed" as const, rid, claim: token, ...(why ? { why: `the notifier failed: ${why}` } : { why: "no notification target took it", cause: "no_target" }) }], result: {} };
      return { append: [{ by: "harness", ev: "notified" as const, rid, targets: sent.targets, notice, claim: token }], result: {} };
    });
    if (sent.targets.length) out.push({ rid, targets: sent.targets });
  }
  return out;
}

/** Where the operator's acts already said on the board are noted: a cache of the keyed posts, which are the truth. */
const ANNOUNCED_REL = "requests/announced.txt";

/**
 * Each operator's act on a request (acknowledged, answered, declined,
 * withdrawn, an acquisition's stage) said on the board, once, derived from
 * its event on the chain and found again by its key (request:<rid>:<seq>):
 * an act whose post failed, or whose process died after the commit, is said
 * at the next round. Addressed to the agent that asked, or to all.
 */
export async function publishRequestActs(sandboxRoot: string): Promise<Array<{ rid: string; seq: number; post: number }>> {
  const s = await requestsSnapshot(sandboxRoot);
  const acts = s.events.filter((e) => e.announce === true);
  if (!acts.length) return [];
  const done = new Set((await readFile(join(sandboxRoot, ANNOUNCED_REL), "utf8").catch(() => "")).split("\n").map((x) => x.trim()).filter(Boolean));
  const out: Array<{ rid: string; seq: number; post: number }> = [];
  for (const e of acts) {
    if (done.has(String(e.seq))) continue;
    const r = s.requests.get(e.rid);
    if (!r) continue;
    const what = e.ev === "stage" ? String(e.stage ?? "") : e.ev;
    const said = e.ev === "answered" ? e.text : e.why;
    const closed = s.events.filter((x) => x.rid === e.rid && x.seq >= e.seq && (x.ev === "declined" || x.ev === "answered" || x.ev === "withdrawn")).at(0);
    let words = `OPERATOR on ${r.rid} (${r.kind}${r.lead ? `, ${r.lead}` : ""}): ${what}${said ? `: ${said}` : ""}.`;
    if (r.kind === "acquisition" && (what === "declined" || closed?.ev === "declined")) words += ` The evidence will not come: record the gap as a limitation (reason unavailable) naming ${r.rid}, and answer on what the evidence holds. That is a limit of this examination, never a finding that the fact is absent.`;
    if (what === "unavailable") words += ` The source is unavailable: record it as a limitation (reason unavailable) naming ${r.rid}.`;
    const to = /^[A-Za-z0-9_-]+$/.test(r.by) && !["harness", "operator", "system"].includes(r.by) ? r.by : "all";
    const post = await P.systemPost(sandboxRoot, { tag: "ask", to, key: `request:${r.rid}:${e.seq}`, body: words });
    await mkdir(join(sandboxRoot, REQUESTS_DIR), { recursive: true });
    await writeFile(join(sandboxRoot, ANNOUNCED_REL), `${e.seq}\n`, { flag: "a" });
    out.push({ rid: r.rid, seq: e.seq, post: post.id });
  }
  return out;
}

/** Reconcile, then deliver: what the hub runs after every act that may open a request, and on its round. */
export async function fireRequests(sandboxRoot: string, o: { notifier?: Notifier; runsDir?: string; now?: number } = {}): Promise<{ opened: string[]; closed: string[]; notified: string[] }> {
  const r = await reconcileRequests(sandboxRoot);
  // The operator's acts not said on the board yet (a post that failed after its commit), said now.
  await publishRequestActs(sandboxRoot).catch(() => undefined);
  const d = await dispatchRequests(sandboxRoot, o);
  return { opened: r.opened.map((x) => x.rid), closed: r.closed, notified: d.map((x) => x.rid) };
}

// --- reading ------------------------------------------------------------------------------

/** The requests in brief, for the header badge: open ones by kind, and whether the chain holds. */
export type RequestsBrief = { total: number; open: number; by_kind: Record<string, number>; pending: number; acquisitions_open: number; chain_ok: boolean };

export function requestsBrief(s: RequestsState): RequestsBrief {
  const all = [...s.requests.values()];
  const open = all.filter(isOpen);
  const by: Record<string, number> = {};
  for (const r of open) by[r.kind] = (by[r.kind] ?? 0) + 1;
  return { total: all.length, open: open.length, by_kind: by, pending: open.filter((r) => r.state === "pending").length, acquisitions_open: open.filter((r) => r.kind === "acquisition").length, chain_ok: s.chain.ok };
}

/** The requests as a list for the CLI and the console: open first, by id. */
export function requestList(s: RequestsState): OperatorRequest[] {
  return [...s.requests.values()].sort((a, b) => Number(Boolean(a.closed)) - Number(Boolean(b.closed)) || a.n - b.n);
}

/** Every request, to append to a registry reader: the view's lines, whatever wrote them (a run from before the chain included). */
export async function readRequestLines(sandboxRoot: string): Promise<Array<Record<string, unknown>>> {
  const text = await readFile(join(sandboxRoot, REQUESTS_VIEW), "utf8").catch(() => "");
  const out: Array<Record<string, unknown>> = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as Record<string, unknown>);
    } catch {
      out.push({ unreadable: line });
    }
  }
  return out;
}
