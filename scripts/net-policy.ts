/**
 * The dynamic network mode's policy engine (docs/adr/0012): whether one
 * request is granted, decided by rules alone, in a fixed order.
 *
 *   1. authentication   who asks is the channel (a seat's hub socket, the operator's CLI)
 *   2. schema           a strict request: known fields, typed values, an open lead the asker holds
 *   3. case policy      the network mode, the lookups ceiling, contact, disclosure, sockets
 *   4. hard denials     search, write-up and CTF sites, paste sites, social platforms, proxies, logins, uploads
 *   5. credentials      credential patterns, and any value the run marked sensitive, in what would leave
 *   6. evidence link    what leaves must be in the bytes the request cites, where the policy asks it
 *   7. enforceability   what is asked must be what the harness can hold it to
 *   8. quotas           grants in force, requests a window, grants a run
 *
 * The first step that refuses decides; its reasons are machine-readable
 * (step, rule, code, detail) and say whether the operator may override them.
 * Anything the rules cannot place is refused: a request with no adapter is
 * "uncertain", never guessed at. Free text (`purpose`) is stored and shown
 * and never read by a rule, so nothing written into a request, or into a
 * response it brings back, can change a decision. The same request (by its
 * digest: everything but its words) gets the same answer.
 *
 * An operator's grant runs the same engine with the overridable reasons
 * waived and recorded: a login, an upload, a credential, a sensitive value,
 * a malformed request or an internal case stay refused whoever asks.
 */
import { createHash } from "node:crypto";
import type { CasePolicy, DisclosureClass } from "./case-policy.ts";
import { DISCLOSURE_CLASSES } from "./case-policy.ts";
import { buildRequest, checkUrl, credentialParams, credentialPattern, denyCategory, hostName, loginPath, type Adapter, type BuiltRequest, type Catalogue, type DenyList } from "./net-adapters.ts";
import type { Reason } from "./net-grants.ts";

export type NetRequestInput = {
  lead?: unknown;
  adapter?: unknown;
  params?: unknown;
  /** A request with no adapter: one exact URL and a method, decided as uncertain unless the policy allows any lookup. */
  url?: unknown;
  method?: unknown;
  /** fetch (tier 1, the default) or socket (tier 2: host and port, for a job's own client). */
  type?: unknown;
  /** socket: the host and port. */
  host?: unknown;
  port?: unknown;
  /** Who will use it: this seat through net_fetch, or a job it runs (job_run net_grants). */
  for?: unknown;
  evidence?: unknown;
  purpose?: unknown;
  ttl_seconds?: unknown;
  max_requests?: unknown;
  client_request_id?: unknown;
};

export type Principal = { kind: "seat" | "operator" | "job"; id: string; authenticated: boolean };

export type LeadFacts = { exists: boolean; open: boolean; holder: string | null; generation: number };

export type EvidenceCheck = {
  /** Each value, and the ref whose bytes hold it; a value no ref holds is absent. */
  found: Map<string, string>;
  /** Refs that could not be read, and why. */
  unreadable: Array<{ ref: string; why: string }>;
  /** Refs read only up to the bound, where the value was not found. */
  bounded: string[];
};

export type PolicyEnv = {
  policy: CasePolicy;
  catalogue: Catalogue;
  deny: DenyList;
  /** The lead the request names, from the register. */
  lead: (id: string) => Promise<LeadFacts | null>;
  /** Whether each value occurs in the bytes of the cited refs (net-broker.ts reads them on the host). */
  evidence: (refs: string[], values: string[]) => Promise<EvidenceCheck>;
  /** The run's sensitive texts: ledger entries marked sensitive. */
  sensitive: () => Promise<string[]>;
  /** Adapters whose host-managed key is configured. */
  keys: ReadonlySet<string>;
  /** Whether the run has a job service (a job grant is held to it). */
  jobs: boolean;
  /** The asker's grants in force, its requests in the quota window, and the run's grants. */
  usage: { grants_in_force: number; requests_in_window: number; run_grants: number };
  /** The operator's grant: overridable reasons are waived. */
  override?: boolean;
};

export const QUOTAS = { grants_in_force: 8, requests_in_window: 40, window_minutes: 10, run_grants: 1000 };
/** A single lookup's grant: five minutes, one use, unless the request asks less (or, within the ceilings, more). */
export const GRANT_DEFAULTS = { ttl_seconds: 300, max_requests: 1 };
export const GRANT_CEILINGS = { ttl_seconds: 900, max_requests: 3 };
export const PURPOSE_MAX = 1000;
export const EVIDENCE_MAX = 20;

export type GrantTerms = {
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
  redirects: Adapter["redirects"] | null;
  response_fields: string[] | null;
  max_requests: number | null;
  max_bytes: number | null;
  ttl_seconds: number | null;
  key: Adapter["key"] | null;
  rate: Adapter["rate"] | null;
};

/** A request as the engine read it: what the digest is over. */
export type Normalized = {
  type: "fetch" | "socket";
  for: "seat" | "job";
  lead: string | null;
  adapter: string | null;
  params: Record<string, string>;
  method: string | null;
  url: string | null;
  host: string | null;
  port: number | null;
  evidence: string[];
  ttl_seconds: number;
  max_requests: number;
};

export type Decision = {
  decision: "granted" | "denied";
  reasons: Reason[];
  /** Every reason is one the operator may override. */
  overridable: boolean;
  /** The reasons an operator's grant waived. */
  waived: Reason[];
  normalized: Normalized | null;
  built: BuiltRequest | null;
  terms?: GrantTerms;
  digest: string;
  purpose: string;
  /** The host an operator item is opened for. */
  host: string | null;
};

const STEP_NAMES = ["", "authentication", "schema", "case policy", "hard denials", "credentials", "evidence link", "enforceability", "quotas"];

function reason(step: number, code: string, detail: string, overridable: boolean): Reason {
  return { step, rule: STEP_NAMES[step], code, detail, overridable };
}

/** The request's digest: everything the rules read, canonical, and nothing they do not (its purpose). */
export function requestDigest(principal: string, n: Normalized): string {
  const canon = (v: unknown): unknown => (Array.isArray(v) ? v.map(canon) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])])) : v);
  return createHash("sha256").update(JSON.stringify(canon({ principal, ...n, evidence: [...n.evidence].sort() }))).digest("hex");
}

const KNOWN = new Set(["lead", "adapter", "params", "url", "method", "type", "host", "port", "for", "evidence", "purpose", "ttl_seconds", "max_requests", "client_request_id"]);
const REF = /^(?:E-[1-9]\d{0,5}|(?:input|job|import|net|sha256|member):[^\s]{1,1000})$/;

function refList(v: unknown): string[] | null {
  if (v === undefined || v === null) return [];
  const raw = Array.isArray(v) ? v : typeof v === "string" ? v.split(/[\s,]+/) : null;
  if (!raw) return null;
  const out: string[] = [];
  for (const x of raw) {
    const ref = typeof x === "string" ? x.trim() : x && typeof x === "object" && typeof (x as { ref?: unknown }).ref === "string" ? String((x as { ref: string }).ref).trim() : null;
    if (ref === null) return null;
    if (ref && !out.includes(ref)) out.push(ref);
  }
  return out;
}

function intIn(v: unknown, dflt: number, min: number, max: number, name: string): { ok: true; value: number } | { ok: false; reason: string } {
  if (v === undefined || v === null) return { ok: true, value: dflt };
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : Number.NaN;
  if (!Number.isInteger(n) || n < min) return { ok: false, reason: `${name} is a whole number, at least ${min}` };
  return { ok: true, value: Math.min(n, max) };
}

/**
 * What would leave the run, as its parts: each value, the URL, the host,
 * and every path segment, query key and query value, each as sent and as a
 * server would read it percent-decoded (twice, for a value encoded twice).
 * A credential pattern or a sensitive value is looked for in all of them.
 */
export function outgoingComponents(raw: string[]): string[] {
  const out = new Set<string>();
  const decode = (v: string): string[] => {
    const seen = [v];
    let cur = v;
    for (let i = 0; i < 2; i += 1) {
      let next: string;
      try {
        next = decodeURIComponent(cur.replace(/\+/g, " "));
      } catch {
        break;
      }
      if (next === cur) break;
      seen.push(next);
      cur = next;
    }
    return seen;
  };
  for (const v of raw) {
    for (const d of decode(v)) out.add(d);
    let u: URL | null = null;
    try {
      u = /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? new URL(v) : null;
    } catch {
      u = null;
    }
    if (!u) continue;
    out.add(u.hostname);
    for (const seg of u.pathname.split("/")) if (seg) for (const d of decode(seg)) out.add(d);
    for (const kv of u.search.replace(/^\?/, "").split("&")) {
      if (!kv) continue;
      const eq = kv.indexOf("=");
      for (const part of eq < 0 ? [kv] : [kv.slice(0, eq), kv.slice(eq + 1)]) for (const d of decode(part)) out.add(d);
    }
  }
  return [...out];
}

/**
 * The values a sensitive entry holds, as tokens: a password, an account, a
 * host, a key, a hash, an address. A word of prose is not one: a token
 * counts when it has a digit, a capital after its first letter, or a . _ @
 * : / + = - inside it, or is sixteen characters or longer; and a whole entry
 * with no space in it is a value itself. Lowercased, six characters at least.
 */
export function sensitiveValues(texts: string[]): string[] {
  const out = new Set<string>();
  for (const t of texts) {
    const whole = t.trim();
    if (whole && !/\s/.test(whole) && whole.length >= 4) out.add(whole.toLowerCase());
    for (const raw of t.split(/[\s,;"'()<>[\]{}|`]+/)) {
      const tok = raw.replace(/^[.:!?/=+-]+|[.:!?/=+-]+$/g, "");
      if (tok.length < 6) continue;
      if (/\d/.test(tok) || /[A-Z]/.test(tok.slice(1)) || /[._@:/+=-]/.test(tok) || tok.length >= 16) out.add(tok.toLowerCase());
    }
  }
  return [...out];
}

/**
 * Decide one request. Every step runs in order; the first that refuses
 * decides. `env.override` (an operator's grant) waives the overridable
 * reasons, records them, and goes on.
 */
export async function evaluate(input: NetRequestInput, principal: Principal, env: PolicyEnv): Promise<Decision> {
  const p = env.policy;
  const waived: Reason[] = [];
  const purpose = typeof input.purpose === "string" ? input.purpose.trim() : "";
  let normalized: Normalized | null = null;
  let built: BuiltRequest | null = null;
  const principalText = `${principal.kind}:${principal.id}`;
  const deny = (reasons: Reason[], host: string | null = null): Decision => ({
    decision: "denied",
    reasons,
    overridable: reasons.every((r) => r.overridable),
    waived,
    normalized,
    built,
    digest: normalized ? requestDigest(principalText, normalized) : createHash("sha256").update(JSON.stringify({ principal: principalText, input: { ...input, purpose: undefined, client_request_id: undefined } })).digest("hex"),
    purpose,
    host,
  });
  /**
   * The reasons of one step: refused unless every one is overridable and the
   * operator is granting. An overridable refusal looks ahead: when a later
   * step would refuse even the operator (a credential, a login, a sensitive
   * value), those reasons join it and it is not overridable, so no operator
   * item is opened for a request nobody may grant.
   */
  const settle = async (reasons: Reason[], host: string | null): Promise<Decision | null> => {
    if (!reasons.length) return null;
    if (env.override && reasons.every((r) => r.overridable)) {
      waived.push(...reasons);
      return null;
    }
    if (!env.override && reasons.every((r) => r.overridable)) {
      const probe = await evaluate(input, principal, { ...env, override: true });
      if (probe.decision === "denied") return deny([...reasons, ...probe.reasons.filter((r) => !r.overridable)], host);
    }
    return deny(reasons, host);
  };

  // 1. authentication: who asks is the channel, never a field of the request.
  if (!principal.authenticated || !principal.id || principal.kind === "job") {
    return deny([reason(1, "unauthenticated", principal.kind === "job" ? "a job uses grants (job_run net_grants); only a seat or the operator asks for one" : "the request did not come on an authenticated channel", false)]);
  }

  // 2. schema.
  {
    const r: Reason[] = [];
    const bad = (code: string, detail: string) => r.push(reason(2, code, detail, false));
    const unknown = Object.keys(input).filter((k) => !KNOWN.has(k));
    if (unknown.length) bad("unknown_field", `a request has no ${unknown.join(", ")}`);
    const type = input.type === undefined || input.type === null || input.type === "fetch" ? "fetch" : input.type === "socket" ? "socket" : null;
    if (!type) bad("bad_type", "type is fetch (the default) or socket");
    const forWhom = input.for === undefined || input.for === null || input.for === "seat" ? "seat" : input.for === "job" ? "job" : null;
    if (!forWhom) bad("bad_for", "for is seat (the default: you fetch with net_fetch) or job (a job you run fetches it: job_run net_grants)");
    if (principal.kind === "seat" && !purpose) bad("no_purpose", "purpose is required: what the lookup is for, in words (stored and shown; no rule reads it)");
    if (purpose.length > PURPOSE_MAX) bad("purpose_too_long", `purpose is over ${PURPOSE_MAX} characters: nothing is cut, so a longer one is refused`);
    const crid = input.client_request_id;
    if (crid !== undefined && crid !== null && (typeof crid !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(crid))) bad("bad_client_request_id", "client_request_id is up to 64 letters, digits, . _ -");
    const evidence = refList(input.evidence);
    if (evidence === null) bad("bad_evidence", "evidence is a list of refs: E-<seq>, input:, job:<id>/<path>, import:, net:<k>/<n>, sha256:");
    else if (evidence.length > EVIDENCE_MAX) bad("too_much_evidence", `at most ${EVIDENCE_MAX} refs`);
    else for (const ref of evidence) if (!REF.test(ref)) bad("bad_ref", `${ref} is not a ref (E-<seq>, input:, job:<id>/<path>, import:, net:<k>/<n>, sha256:)`);
    const ttl = intIn(input.ttl_seconds, GRANT_DEFAULTS.ttl_seconds, 1, GRANT_CEILINGS.ttl_seconds, "ttl_seconds");
    if (!ttl.ok) bad("bad_ttl", ttl.reason);
    const maxReq = intIn(input.max_requests, GRANT_DEFAULTS.max_requests, 1, GRANT_CEILINGS.max_requests, "max_requests");
    if (!maxReq.ok) bad("bad_max_requests", maxReq.reason);
    // The lead: required of a seat, open, and the seat's own.
    const leadText = typeof input.lead === "string" ? input.lead.trim().toUpperCase() : "";
    let lead: string | null = null;
    if (leadText) {
      if (!/^L-[1-9]\d{0,5}$/.test(leadText)) bad("bad_lead", "lead is L-<n>");
      else lead = `L-${Number(leadText.slice(2))}`;
    } else if (principal.kind === "seat") bad("no_lead", "a request is tied to a lead: the one you hold that this lookup serves");
    let leadGen: number | undefined;
    if (lead) {
      const facts = await env.lead(lead);
      if (!facts?.exists) bad("no_such_lead", `${lead} does not exist`);
      else if (!facts.open) bad("lead_closed", `${lead} is closed: a closed lead's work asks for nothing more`);
      else if (principal.kind === "seat" && facts.holder !== principal.id) bad("lead_not_yours", facts.holder ? `${lead} is held by ${facts.holder}: its holder asks for what it needs` : `${lead} is held by nobody: lead_claim it first`);
      else leadGen = facts.generation;
    }
    // What is asked: an adapter's request, one exact URL, or a socket.
    let params: Record<string, string> = {};
    let method: string | null = null;
    let url: string | null = null;
    let host: string | null = null;
    let port: number | null = null;
    let adapterName: string | null = null;
    if (type === "socket") {
      if (input.adapter !== undefined || input.url !== undefined || input.params !== undefined) bad("socket_fields", "a socket request names a host and a port, nothing else");
      host = typeof input.host === "string" ? input.host.trim().toLowerCase() : null;
      if (!host || !hostName(host)) bad("bad_host", "a socket request names a host name (never an address)");
      const pt = intIn(input.port, 443, 1, 65535, "port");
      if (!pt.ok || (typeof input.port === "number" && input.port > 65535)) bad("bad_port", "port is 1 to 65535");
      else port = pt.value;
    } else if (input.adapter !== undefined && input.adapter !== null) {
      adapterName = typeof input.adapter === "string" ? input.adapter.trim() : "";
      const a = env.catalogue.byName.get(adapterName);
      if (!a) bad("no_such_adapter", `${JSON.stringify(adapterName)} is not in the catalogue (${[...env.catalogue.byName.keys()].join(", ")})`);
      else if (input.url !== undefined || input.method !== undefined || input.host !== undefined) bad("adapter_fields", "an adapter's request is its params: no url, method or host of your own");
      else {
        const b = buildRequest(a, (input.params && typeof input.params === "object" ? input.params : {}) as Record<string, unknown>);
        if (!b.ok) bad("bad_params", b.reason);
        else {
          built = b.request;
          params = b.request.values;
          method = b.request.method;
          url = b.request.url;
          host = b.request.host;
          port = b.request.port;
        }
      }
    } else {
      if (input.params !== undefined) bad("params_without_adapter", "params go with an adapter");
      method = typeof input.method === "string" ? input.method.trim().toUpperCase() : "GET";
      const u = typeof input.url === "string" ? checkUrl(input.url.trim()) : null;
      if (!u) bad("no_adapter_or_url", "name an adapter (net_request adapter=…) or one exact url");
      else if (!u.ok) bad("bad_url", u.reason);
      else {
        url = u.href;
        host = u.host;
        port = u.port;
        built = { adapter: "", method: method === "HEAD" ? "HEAD" : "GET", scheme: u.scheme, host: u.host, port: u.port, path: u.path, url: u.href, values: { url: u.href }, classes: ["public_indicator"] };
        params = { url: u.href };
      }
    }
    normalized = {
      type: type ?? "fetch",
      for: forWhom ?? "seat",
      lead,
      adapter: adapterName,
      params,
      method,
      url,
      host,
      port,
      evidence: evidence ?? [],
      ttl_seconds: ttl.ok ? ttl.value : GRANT_DEFAULTS.ttl_seconds,
      max_requests: maxReq.ok ? maxReq.value : GRANT_DEFAULTS.max_requests,
    };
    if (r.length) return deny(r, host);
    if (leadGen !== undefined) (normalized as Normalized & { lead_generation?: number }).lead_generation = leadGen;
  }
  const n = normalized as Normalized & { lead_generation?: number };
  const adapter = n.adapter ? (env.catalogue.byName.get(n.adapter) as Adapter) : null;
  const host = n.host;

  // 3. case policy.
  {
    const r: Reason[] = [];
    const internal = p.policy === "internal";
    if (n.type === "socket") {
      // A socket grant is the operator's, whatever the mode: the closed
      // mode's own way to allow a host while the run goes on.
      if (p.sockets === "none") r.push(reason(3, "socket_not_permitted", `policy ${p.policy} permits no socket grant (host and port, no method or path control, no content capture): every request here is mediated by the fetch service`, false));
      else if (principal.kind !== "operator") r.push(reason(3, "socket_operator", "a socket grant is never the hub's own: it gives a job's client a host and a port with no method, path or content control, so it is the operator's decision", true));
    } else if (p.network === "closed") r.push(reason(3, "network_closed", "this run's network is closed: its hosts were fixed at kickoff, and the operator allows one with swarm.sh lead <run> note L-<n> --allow-host", false));
    else {
      if (p.lookups === "none") r.push(reason(3, "lookups_none", `policy ${p.policy}: no lookup leaves this run`, !internal));
      else if (!adapter) {
        if (p.network !== "open" && !(p.lookups === "any" && p.contact === "active")) r.push(reason(3, "no_adapter", "uncertain: no approved adapter makes this request, and the hub does not guess what an arbitrary URL is; the operator decides", !internal));
      } else if (adapter.class === "evidence_linked" && p.lookups === "reference") r.push(reason(3, "lookups_ceiling", `${adapter.name} is an evidence-linked lookup; this case allows reference lookups only`, !internal));
      const active = adapter ? adapter.contact === "active" : true;
      if (active && p.network !== "open") {
        if (p.contact === "passive") r.push(reason(3, p.active_contact === "never" ? "contact_never" : "contact_passive", `${adapter ? adapter.name : "this request"} contacts what the evidence names (the host sees the request, and may be the subject's); ${p.active_contact === "never" ? `policy ${p.policy} never allows it` : "active contact is the operator's decision"}`, p.active_contact !== "never" && !internal));
        else if (p.active_contact === "never") r.push(reason(3, "contact_never", `policy ${p.policy} never contacts what the evidence names`, false));
        else if (p.active_contact === "operator" || !adapter || adapter.class !== "evidence_linked") r.push(reason(3, "contact_operator", "active contact is the operator's decision under this policy", !internal));
      }
      const classes = new Set<DisclosureClass>(built?.classes ?? []);
      for (const c of DISCLOSURE_CLASSES) {
        if (classes.has(c) && p.disclosure[c] !== "allow") r.push(reason(3, `disclosure_${c}`, `it sends ${c === "public_indicator" ? "a public indicator" : c === "internal_name" ? "an internal name or address" : c === "personal" ? "personal data" : c === "file_upload" ? "a file" : `a ${c}`} out of the run, which policy ${p.policy} does not allow${c === "internal_name" ? " (an internal name tells a third party about the case's network)" : ""}`, !internal && c !== "file_upload"));
      }
    }
    const d = await settle(r, host);
    if (d) return d;
  }

  // 4. hard denials.
  {
    const r: Reason[] = [];
    if (host) {
      const cat = denyCategory(host, env.deny);
      if (cat && !(adapter?.exception === cat.category)) r.push(reason(4, `deny_${cat.category}`, `${host} is ${cat.why}`, p.category_override));
    }
    if (n.type === "fetch" && n.method && n.method !== "GET" && n.method !== "HEAD") r.push(reason(4, "deny_upload", `${n.method}: only GET and HEAD are ever made; an upload or a state change is refused`, false));
    // A URL the agent gave (a raw request, an evidence-linked adapter's): its path and query are checked as they would be sent.
    const agentUrl = n.type === "fetch" && built && (!adapter || adapter.host === "from_url");
    if (agentUrl && built) {
      const login = loginPath(built.path, env.deny);
      if (login) r.push(reason(4, "deny_login", `the path names a login or an account (${login}): credentialed access is refused`, false));
    }
    const d = await settle(r, host);
    if (d) return d;
  }

  // 5. credentials and sensitive values, in what would leave: every
  // component as it is sent and as a server would decode it.
  {
    const r: Reason[] = [];
    const outgoing = outgoingComponents([...Object.values(n.params), ...(n.url ? [n.url] : []), ...(n.host ? [n.host] : [])]);
    for (const v of outgoing) {
      const hit = credentialPattern(v);
      if (hit) {
        r.push(reason(5, "credential_pattern", `what would leave looks like ${hit}: never sent`, false));
        break;
      }
    }
    if (n.type === "fetch" && built && (!adapter || adapter.host === "from_url")) {
      const keys = credentialParams(built.path, env.deny);
      if (keys.length) r.push(reason(5, "credential_param", `the URL carries ${keys.join(", ")}, which names a credential or a session: never sent`, false));
    }
    // A value the run marked sensitive, anywhere inside what would leave;
    // and what the agent gave, found inside a sensitive entry.
    const texts = await env.sensitive();
    const values = sensitiveValues(texts);
    const lowered = outgoing.map((v) => v.toLowerCase());
    const hit = values.find((sv) => lowered.some((o) => o.includes(sv)));
    const given = Object.values(n.params).filter((v) => v.length >= 4).map((v) => v.toLowerCase());
    if (hit || given.some((v) => texts.some((t) => t.toLowerCase().includes(v)))) {
      r.push(reason(5, "sensitive_value", "what would leave holds a value this run marked sensitive, or is part of an entry it marked sensitive: never sent", false));
    }
    const d = await settle(r, host);
    if (d) return d;
  }

  // 6. the evidence link.
  {
    const r: Reason[] = [];
    const required = p.evidence_link === "required" || !adapter || adapter.class === "evidence_linked" || n.type === "socket";
    if (required && n.type === "fetch") {
      const values = Object.values(n.params);
      if (!n.evidence.length) r.push(reason(6, "evidence_link_none", "this request must show what it sends is in the evidence: cite the entry or the object that holds it (evidence: [E-<seq>, job:<id>/<path>, input:…])", true));
      else if (values.length) {
        const check = await env.evidence(n.evidence, values);
        const missing = values.filter((v) => !check.found.has(v));
        if (missing.length) {
          const extra = [
            ...(check.unreadable.length ? [`not read: ${check.unreadable.map((u) => `${u.ref} (${u.why})`).join("; ")}`] : []),
            ...(check.bounded.length ? [`read only up to the bound, without it: ${check.bounded.join(", ")} (cite the job output or entry that holds it)`] : []),
          ];
          r.push(reason(6, "evidence_link_missing", `${missing.map((v) => JSON.stringify(v)).join(", ")} ${missing.length === 1 ? "is" : "are"} not in the cited bytes (${n.evidence.join(", ")}); a value derived from the evidence (a converted coordinate) is cited from the job output that holds it as sent${extra.length ? `; ${extra.join("; ")}` : ""}`, true));
        }
      }
    }
    const d = await settle(r, host);
    if (d) return d;
  }

  // 7. enforceability.
  {
    const r: Reason[] = [];
    if (n.for === "job" && !env.jobs) r.push(reason(7, "unenforceable_job", "this run has no job service: a grant for a job could not be held to one", false));
    if (n.type === "socket" && n.for !== "job" && principal.kind !== "operator") r.push(reason(7, "socket_for_seat", "a socket grant is for a job's client (for: job): a seat's VM keeps the network it booted with", false));
    if (n.type === "socket" && !env.jobs) r.push(reason(7, "unenforceable_socket", "this run has no job service: a socket grant is a job worker's egress, and there is none to give it to", false));
    if (adapter?.key && !env.keys.has(adapter.name)) r.push(reason(7, "key_not_configured", `${adapter.name} needs a key the operator configures on the host (${adapter.key.env}); none is, so it is off`, false));
    const d = await settle(r, host);
    if (d) return d;
  }

  // 8. quotas.
  if (!env.override) {
    const r: Reason[] = [];
    if (env.usage.grants_in_force >= QUOTAS.grants_in_force) r.push(reason(8, "quota_grants_in_force", `${env.usage.grants_in_force} of your grants are in force (the limit is ${QUOTAS.grants_in_force}): use or let them lapse first`, false));
    if (env.usage.requests_in_window >= QUOTAS.requests_in_window) r.push(reason(8, "quota_requests", `${env.usage.requests_in_window} requests from you in ${QUOTAS.window_minutes} minutes (the limit is ${QUOTAS.requests_in_window})`, false));
    if (env.usage.run_grants >= QUOTAS.run_grants) r.push(reason(8, "quota_run", `the run has made ${env.usage.run_grants} grants (the limit is ${QUOTAS.run_grants})`, false));
    if (r.length) return deny(r, host);
  }

  const terms: GrantTerms =
    n.type === "socket"
      ? { type: "socket", principal: principal.kind === "operator" ? "jobs" : `job-of:${principal.id}`, lead: n.lead, ...(n.lead_generation !== undefined ? { lead_generation: n.lead_generation } : {}), adapter: null, method: null, url: null, scheme: null, host: n.host as string, port: n.port as number, path: null, redirects: null, response_fields: null, max_requests: null, max_bytes: null, ttl_seconds: null, key: null, rate: null }
      : {
          type: "fetch",
          principal: n.for === "job" ? `job-of:${principal.kind === "operator" ? "operator" : principal.id}` : principalText,
          lead: n.lead,
          ...(n.lead_generation !== undefined ? { lead_generation: n.lead_generation } : {}),
          adapter: adapter?.name ?? null,
          method: built?.method ?? n.method,
          url: built?.url ?? n.url,
          scheme: built?.scheme ?? null,
          host: built?.host ?? (n.host as string),
          port: built?.port ?? (n.port as number),
          path: built?.path ?? null,
          redirects: adapter?.redirects ?? null,
          response_fields: adapter?.response?.fields ?? null,
          max_requests: n.max_requests,
          max_bytes: adapter ? adapter.max_bytes : 1024 * 1024,
          ttl_seconds: n.ttl_seconds,
          key: adapter?.key ?? null,
          rate: adapter?.rate ?? null,
        };
  return { decision: "granted", reasons: [], overridable: true, waived, normalized: n, built, terms, digest: requestDigest(principalText, n), purpose, host };
}
