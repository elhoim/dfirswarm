/**
 * The dynamic network mode's records (docs/adr/0011): every request, every
 * decision, every grant and what became of it, in `network/grants.jsonl`;
 * every fetch the fetch service made, in `network/fetches.jsonl`. Both are
 * append-only chains with the lead register's own code (extensions/leads.ts:
 * each line hashed over the one before it), and nothing here is ever
 * rewritten.
 *
 * Two writers, one file each. The hub (and the operator's CLI on the host,
 * under the same lock) writes grants.jsonl: requests, decisions, grants,
 * bindings to a job, revocations, operator items, contamination. The fetch
 * service writes fetches.jsonl and nothing else: an `attempt` line before a
 * byte leaves (a fetch whose line cannot be written is not made), a
 * `result` line after, a `refused` line for a use it turned away. A grant's
 * state is derived from both, never stored:
 *
 *   requested → granted | denied → active → exhausted | expired | revoked
 *
 * `granted` until its first use, `active` while it has uses left, then
 * `exhausted` at its count, `expired` past its time, `revoked` by the
 * operator, by the harness when its lead closed, or when its job ended.
 *
 * Ids: NR-<n> a request, N-<k> a grant, NI-<m> an operator item (one per
 * host and lead), and a capture is `net:<k>/<n>`, the n-th use of grant k.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";

export const NET_DIR = "network";
export const GRANTS_LOG = "network/grants.jsonl";
export const FETCH_LOG = "network/fetches.jsonl";
/** The grants chain's lock (locks/), which the hub and the operator's CLI share. */
export const NET_LOCK = ".network.lock";
/** The fetch log's lock: one fetch service, but a restarted one must not interleave with the old. */
export const FETCH_LOCK = ".network-fetch.lock";
/** Where captures are sealed, one directory per use: store/net/<k>/<n>/. */
export const CAPTURES_REL = "store/net";

/** Where a capture's undelivered bytes are kept: beside the run, in no VM's reach (an adapter that delivers only some fields). */
export function rawDir(sandbox: string): string {
  return `${resolve(sandbox)}.netraw`;
}

export type NetEvent = { v: 1; seq: number; at: string; by: string; ev: string; prev: string; hash: string } & Record<string, unknown>;
export type NetDraft = { by: string; ev: string; at?: string } & Record<string, unknown>;
export type ChainState = { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };

/** Whether a network log chains from its first line to its last (the lead register's own check). */
export function verifyNetChain(text: string): ChainState & { total: number } {
  return L.verifyLeadChain(text);
}

function eventHash(e: Omit<NetEvent, "hash">, prev: string): string {
  return L.leadEventHash(e as never, prev);
}

export async function readNetLog(sandbox: string, rel: string): Promise<{ events: NetEvent[]; text: string; chain: ChainState }> {
  const text = await readFile(join(sandbox, rel), "utf8").catch(() => "");
  return parseNetLog(text);
}

export function readNetLogSync(sandbox: string, rel: string): { events: NetEvent[]; text: string; chain: ChainState } {
  let text = "";
  try {
    text = readFileSync(join(sandbox, rel), "utf8");
  } catch {
    text = "";
  }
  return parseNetLog(text);
}

function parseNetLog(text: string): { events: NetEvent[]; text: string; chain: ChainState } {
  const events: NetEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as NetEvent);
    } catch {
      // the chain check names it
    }
  }
  const c = verifyNetChain(text);
  return { events, text, chain: { ok: c.ok, broken_at: c.broken_at, reason: c.reason, head: c.head } };
}

/**
 * Chain and append events, durably: written and fsynced before this returns,
 * so a caller that goes on (a fetch after its attempt line) goes on only
 * from a line on disk. Throws when the chain is broken or the write fails:
 * the caller refuses what it was about to do.
 */
export async function appendNetEvents(sandbox: string, rel: string, drafts: NetDraft[], held?: P.HeldLock): Promise<NetEvent[]> {
  const { events: existing, text } = await readNetLog(sandbox, rel);
  const chain = verifyNetChain(text);
  if (!chain.ok) throw new Error(`${rel}'s chain is broken at line ${chain.broken_at} (${chain.reason}); nothing more is written to it until the operator looks`);
  let prev = chain.head ?? "genesis";
  let seq = existing.length;
  const out: NetEvent[] = [];
  for (const d of drafts) {
    seq += 1;
    const body = { v: 1 as const, seq, at: d.at ?? new Date().toISOString(), ...Object.fromEntries(Object.entries(d).filter(([k, x]) => k !== "at" && x !== undefined)) } as Omit<NetEvent, "prev" | "hash">;
    const withPrev = { ...body, prev } as Omit<NetEvent, "hash">;
    const e = { ...withPrev, hash: eventHash(withPrev, prev) } as NetEvent;
    out.push(e);
    prev = e.hash;
  }
  await mkdir(dirname(join(sandbox, rel)), { recursive: true });
  await held?.assertOwned();
  const fd = openSync(join(sandbox, rel), "a", 0o644);
  try {
    writeSync(fd, out.map((e) => `${JSON.stringify(e)}\n`).join(""));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return out;
}

// --- the fold ----------------------------------------------------------------------------------

export type Reason = { step: number; rule: string; code: string; detail: string; overridable: boolean };

export type RequestRecord = {
  id: string;
  n: number;
  at: string;
  by: string;
  principal: string;
  lead: string | null;
  digest: string;
  input: Record<string, unknown>;
  /** The request's type: a mediated fetch, or a socket (tier 2). */
  type: "fetch" | "socket";
  host: string | null;
  decision?: { decision: "granted" | "denied"; by: string; at: string; reasons: Reason[]; grant?: string; item?: string; why?: string; same_as?: string; overridable?: boolean };
};

export type GrantRecord = {
  id: string;
  k: number;
  request: string | null;
  type: "fetch" | "socket";
  principal: string;
  lead: string | null;
  lead_generation?: number;
  adapter: string | null;
  method: string | null;
  url: string | null;
  scheme: string | null;
  host: string;
  port: number;
  path: string | null;
  redirects: { follow: "referral"; max: number; hosts: string[] } | null;
  response_fields: string[] | null;
  max_requests: number | null;
  max_bytes: number | null;
  ttl_seconds: number | null;
  granted_at: string;
  expires_at: string | null;
  granted_by: "policy" | "operator";
  why?: string;
  waived?: Reason[];
  key?: { env: string; header: string } | null;
  rate?: { min_interval_ms: number } | null;
  bound?: { job: string; at: string } | null;
  revoked?: { at: string; by: string; why: string; cause: string } | null;
  policy_digest?: string;
  /** A socket grant: the allowlist entry as the operator gave it (host, host:port, or *.host). */
  entry?: string;
};

export type ItemRecord = { id: string; host: string; lead: string | null; requests: string[]; reasons: Reason[]; opened_at: string; opened_by: string; closed?: { how: "granted" | "denied"; by: string; at: string; why: string; request?: string; grant?: string } };

export type FetchRecord = {
  grant: string;
  n: number;
  capture: string;
  principal: string;
  method: string;
  url: string;
  at: string;
  result?: { status?: number; error?: string; refused?: { code: string; detail: string }; bytes?: number; sha256?: string; complete: boolean; delivered: boolean; exposed?: Array<{ what: string; category: string }>; at: string };
};

export type NetState = {
  requests: Map<string, RequestRecord>;
  grants: Map<string, GrantRecord>;
  items: Map<string, ItemRecord>;
  contamination: Array<{ at: string; by: string; grant?: string; capture?: string; what: string; why: string; category?: string }>;
  /** Each grant's attempts, in order. */
  fetches: Map<string, FetchRecord[]>;
  /** Uses the fetch service turned away before an attempt (no grant, wrong principal, expired...). */
  refusals: Array<{ at: string; grant: string | null; principal: string; code: string; detail: string }>;
  chain: ChainState;
  fetchChain: ChainState;
  events: NetEvent[];
  fetchEvents: NetEvent[];
};

export function foldNet(grantEvents: NetEvent[], fetchEvents: NetEvent[], chain: ChainState = { ok: true, broken_at: null, reason: null, head: grantEvents.at(-1)?.hash ?? null }, fetchChain: ChainState = { ok: true, broken_at: null, reason: null, head: fetchEvents.at(-1)?.hash ?? null }): NetState {
  const requests = new Map<string, RequestRecord>();
  const grants = new Map<string, GrantRecord>();
  const items = new Map<string, ItemRecord>();
  const contamination: NetState["contamination"] = [];
  for (const e of grantEvents) {
    switch (e.ev) {
      case "request": {
        const id = String(e.request);
        requests.set(id, {
          id,
          n: Number(id.slice(3)),
          at: e.at,
          by: e.by,
          principal: String(e.principal ?? ""),
          lead: (e.lead as string) ?? null,
          digest: String(e.digest ?? ""),
          input: (e.input as Record<string, unknown>) ?? {},
          type: e.type === "socket" ? "socket" : "fetch",
          host: (e.host as string) ?? null,
        });
        break;
      }
      case "decide": {
        const r = requests.get(String(e.request));
        if (!r) break;
        r.decision = {
          decision: e.decision === "granted" ? "granted" : "denied",
          by: e.by,
          at: e.at,
          reasons: (e.reasons as Reason[]) ?? [],
          ...(e.grant ? { grant: String(e.grant) } : {}),
          ...(e.item ? { item: String(e.item) } : {}),
          ...(e.why ? { why: String(e.why) } : {}),
          ...(e.same_as ? { same_as: String(e.same_as) } : {}),
          ...(e.overridable !== undefined ? { overridable: e.overridable === true } : {}),
        };
        break;
      }
      case "grant": {
        const id = String(e.grant);
        const g = e.terms as Omit<GrantRecord, "id" | "k" | "granted_at" | "granted_by">;
        grants.set(id, { ...g, id, k: Number(id.slice(2)), granted_at: e.at, granted_by: e.by === "operator" ? "operator" : "policy", ...(e.why ? { why: String(e.why) } : {}), ...(e.waived ? { waived: e.waived as Reason[] } : {}), bound: null, revoked: null });
        break;
      }
      case "bind": {
        const g = grants.get(String(e.grant));
        if (g && !g.bound) {
          g.bound = { job: String(e.job), at: e.at };
          g.principal = `job:${String(e.job)}`;
        }
        break;
      }
      case "revoke": {
        const g = grants.get(String(e.grant));
        if (g && !g.revoked) g.revoked = { at: e.at, by: e.by, why: String(e.why ?? ""), cause: String(e.cause ?? "operator") };
        break;
      }
      case "item": {
        const id = String(e.item);
        items.set(id, { id, host: String(e.host ?? ""), lead: (e.lead as string) ?? null, requests: [String(e.request)], reasons: (e.reasons as Reason[]) ?? [], opened_at: e.at, opened_by: e.by });
        break;
      }
      case "item_join": {
        const it = items.get(String(e.item));
        if (it && !it.requests.includes(String(e.request))) it.requests.push(String(e.request));
        break;
      }
      case "item_close": {
        const it = items.get(String(e.item));
        if (it && !it.closed) it.closed = { how: e.how === "granted" ? "granted" : "denied", by: e.by, at: e.at, why: String(e.why ?? ""), ...(e.request ? { request: String(e.request) } : {}), ...(e.grant ? { grant: String(e.grant) } : {}) };
        break;
      }
      case "contamination":
        contamination.push({ at: e.at, by: e.by, ...(e.grant ? { grant: String(e.grant) } : {}), ...(e.capture ? { capture: String(e.capture) } : {}), what: String(e.what ?? ""), why: String(e.why ?? ""), ...(e.category ? { category: String(e.category) } : {}) });
        break;
    }
  }
  const fetches = new Map<string, FetchRecord[]>();
  const refusals: NetState["refusals"] = [];
  for (const e of fetchEvents) {
    if (e.ev === "attempt") {
      const list = fetches.get(String(e.grant)) ?? [];
      list.push({ grant: String(e.grant), n: Number(e.n), capture: String(e.capture), principal: String(e.principal ?? ""), method: String(e.method ?? ""), url: String(e.url ?? ""), at: e.at });
      fetches.set(String(e.grant), list);
    } else if (e.ev === "result") {
      const f = (fetches.get(String(e.grant)) ?? []).find((x) => x.n === Number(e.n));
      if (f) f.result = { ...(e.status !== undefined ? { status: Number(e.status) } : {}), ...(e.error ? { error: String(e.error) } : {}), ...(e.refused ? { refused: e.refused as { code: string; detail: string } } : {}), ...(e.bytes !== undefined ? { bytes: Number(e.bytes) } : {}), ...(e.sha256 ? { sha256: String(e.sha256) } : {}), complete: e.complete === true, delivered: e.delivered === true, ...(Array.isArray(e.exposed) ? { exposed: e.exposed as Array<{ what: string; category: string }> } : {}), at: e.at };
    } else if (e.ev === "refused") {
      refusals.push({ at: e.at, grant: (e.grant as string) ?? null, principal: String(e.principal ?? ""), code: String(e.code ?? ""), detail: String(e.detail ?? "") });
    }
  }
  return { requests, grants, items, contamination, fetches, refusals, chain, fetchChain, events: grantEvents, fetchEvents };
}

export async function readNetState(sandbox: string): Promise<NetState> {
  const g = await readNetLog(sandbox, GRANTS_LOG);
  const f = await readNetLog(sandbox, FETCH_LOG);
  return foldNet(g.events, f.events, g.chain, f.chain);
}

export function readNetStateSync(sandbox: string): NetState {
  const g = readNetLogSync(sandbox, GRANTS_LOG);
  const f = readNetLogSync(sandbox, FETCH_LOG);
  return foldNet(g.events, f.events, g.chain, f.chain);
}

export type GrantStatus = "granted" | "active" | "exhausted" | "expired" | "revoked";

/**
 * A grant's state now, derived: revoked (the operator, a closed lead, its
 * job's end), expired (past its time), exhausted (every use taken), active
 * (used, with uses left) or granted (not yet used). A socket grant has no
 * count and, unless the operator gave it a time, lasts the run.
 */
export function grantStatus(g: GrantRecord, state: Pick<NetState, "fetches">, now = Date.now()): { status: GrantStatus; uses: number; left: number | null; why?: string } {
  const uses = (state.fetches.get(g.id) ?? []).length;
  const left = g.max_requests === null ? null : Math.max(0, g.max_requests - uses);
  if (g.revoked) return { status: "revoked", uses, left, why: `${g.revoked.cause === "lead_closed" ? "its lead closed" : g.revoked.cause === "job_ended" ? "its job ended" : `revoked by ${g.revoked.by}`}: ${g.revoked.why}` };
  if (g.expires_at && now >= Date.parse(g.expires_at)) return { status: "expired", uses, left, why: `its time ran out at ${g.expires_at}` };
  if (left !== null && left <= 0) return { status: "exhausted", uses, left, why: `its ${g.max_requests} use${g.max_requests === 1 ? "" : "s"} ${g.max_requests === 1 ? "is" : "are"} taken` };
  return { status: uses ? "active" : "granted", uses, left };
}

/** Whether a lead is open (exists and not closed), from the register. */
export async function leadOpen(sandbox: string, lead: string | null): Promise<boolean> {
  if (!lead) return true;
  const { events } = await L.readLeadEvents(sandbox);
  const l = L.foldLeads(events).leads.get(lead);
  return Boolean(l && !l.closed);
}

/**
 * The socket grants in force for one requester's jobs (their hosts, as
 * allowlist entries): the operator's for every job ("jobs"), and those made
 * for a job of this requester; and the hosts whose socket grant was revoked.
 * A chain that does not verify gives nothing in force.
 */
export function socketHostsInForce(sandbox: string, requester?: string, now = Date.now()): { hosts: string[]; revoked: Set<string> } {
  const state = readNetStateSync(sandbox);
  const hosts: string[] = [];
  const revoked = new Set<string>();
  if (!state.chain.ok) return { hosts, revoked };
  for (const g of state.grants.values()) {
    if (g.type !== "socket") continue;
    if (requester !== undefined && g.principal !== "jobs" && g.principal !== `job-of:${requester}`) continue;
    const entry = g.entry ?? (g.port === 443 ? g.host : `${g.host}:${g.port}`);
    const st = grantStatus(g, state, now).status;
    if (st === "revoked" || st === "expired") revoked.add(entry);
    else if (!hosts.includes(entry)) hosts.push(entry);
  }
  for (const h of hosts) revoked.delete(h);
  return { hosts, revoked };
}

/** A capture's reference and where it is sealed. */
export function captureRef(grantK: number, n: number): string {
  return `net:${grantK}/${n}`;
}

export function captureDir(sandbox: string, grantK: number, n: number): string {
  return join(resolve(sandbox), CAPTURES_REL, String(grantK), String(n));
}

/** `net:<k>/<n>[/<file>]` read apart, or null. */
export function parseCaptureRef(ref: string): { k: number; n: number; file: string | null } | null {
  const m = /^net:([1-9]\d{0,6})\/([1-9]\d{0,6})(?:\/(.+))?$/.exec(ref.trim());
  if (!m) return null;
  return { k: Number(m[1]), n: Number(m[2]), file: m[3] ?? null };
}

/** The files of a sealed capture. */
export const CAPTURE_FILES = ["request.json", "response.json", "body", "capture.json"] as const;

export function netLogsExist(sandbox: string): boolean {
  return existsSync(join(sandbox, GRANTS_LOG)) || existsSync(join(sandbox, FETCH_LOG));
}

export type NetworkCheck = {
  grants: { lines: number; intact: boolean; detail: string };
  fetches: { lines: number; intact: boolean; detail: string };
  /** Each capture's files re-hashed against its manifest, and its manifest against the result line that sealed it. */
  captures: { sealed: number; verified: number; mismatched: string[]; missing: string[] };
};

/**
 * Custody's look at the network records: both chains, and every capture
 * the fetch log says was sealed, re-hashed. Null for a run that made no
 * request. The seal is each chain's length and head, as custody holds the
 * lead register's.
 */
export async function checkNetwork(sandbox: string): Promise<{ check: NetworkCheck; seal: { grants: { lines: number; head: string | null }; fetches: { lines: number; head: string | null } } } | null> {
  const S = resolve(sandbox);
  if (!netLogsExist(S)) return null;
  const g = await readNetLog(S, GRANTS_LOG);
  const f = await readNetLog(S, FETCH_LOG);
  const gv = verifyNetChain(g.text);
  const fv = verifyNetChain(f.text);
  const captures: NetworkCheck["captures"] = { sealed: 0, verified: 0, mismatched: [], missing: [] };
  const { createHash } = await import("node:crypto");
  for (const e of f.events) {
    if (e.ev !== "result" || typeof e.capture !== "string") continue;
    const c = parseCaptureRef(e.capture);
    if (!c) continue;
    captures.sealed += 1;
    const dir = captureDir(S, c.k, c.n);
    const manifestText = await readFile(join(dir, "manifest.json"), "utf8").catch(() => null);
    if (manifestText === null) {
      captures.missing.push(`${e.capture} (no manifest)`);
      continue;
    }
    if (typeof e.manifest_sha256 === "string" && createHash("sha256").update(manifestText).digest("hex") !== e.manifest_sha256) {
      captures.mismatched.push(`${e.capture}/manifest.json`);
      continue;
    }
    let ok = true;
    try {
      const m = JSON.parse(manifestText) as { files?: Array<{ path: string; sha256: string }> };
      for (const file of m.files ?? []) {
        const bytes = await readFile(join(dir, file.path)).catch(() => null);
        if (!bytes) {
          captures.missing.push(`${e.capture}/${file.path}`);
          ok = false;
        } else if (createHash("sha256").update(bytes).digest("hex") !== file.sha256) {
          captures.mismatched.push(`${e.capture}/${file.path}`);
          ok = false;
        }
      }
    } catch {
      captures.mismatched.push(`${e.capture}/manifest.json (not JSON)`);
      ok = false;
    }
    if (ok) captures.verified += 1;
  }
  const said = (v: ReturnType<typeof verifyNetChain>, what: string) => ({ lines: v.total, intact: v.ok, detail: v.ok ? `${v.total} ${what}, chain intact` : `broken at line ${v.broken_at} (${v.reason})` });
  return { check: { grants: said(gv, "events"), fetches: said(fv, "lines"), captures }, seal: { grants: { lines: gv.total, head: gv.head }, fetches: { lines: fv.total, head: fv.head } } };
}
