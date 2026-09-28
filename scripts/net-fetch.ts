#!/usr/bin/env node
/**
 * The fetch service (`--network dynamic`; docs/adr/0012): the one process of
 * a run that makes a research request to the outside, and only one a grant
 * permits, exactly.
 *
 * It is a host process like the model gateway: started by the kickoff from
 * the run's frozen harness, kept by the hub's keeper, reached on one
 * loopback port. It reads no evidence: what it opens is the network records
 * (network/grants.jsonl, which the hub writes; the lead register, for a
 * grant's lead) and what it writes is its own log (network/fetches.jsonl)
 * and the captures it seals (store/net/<k>/<n>/, and outside every VM's
 * reach the bytes of a response an adapter delivers only in part).
 *
 * **Who asks is a token.** Each principal (`seat:<id>`, `job:<id>`) has a
 * token: an HMAC of its name under the run's secret, which this process and
 * the hub hold in the hub's directory (0700, mounted by no VM). The hub asks
 * for a seat, over loopback, after its own checks; a job's worker asks
 * itself, with the token of its job, which the hub put in the worker's
 * environment when it bound the job's grants. A grant names its principal,
 * and a use by any other is refused: a capability does not travel.
 *
 * **Exactly the grant.** The method is the grant's, the URL is the grant's,
 * byte for byte (a path next to it, another query, an added parameter: all
 * refused), and there is no body. Nothing the caller sends reaches the
 * request: the headers are this process's own (a user agent, an accept, and
 * for an adapter with a host-managed key, the key), so no guest's token, no
 * provider key and no cookie can leave with it. A redirect is never followed
 * unless the adapter declares referral hosts, and then only to one of them,
 * over https, asking the same thing; every other Location is returned as a
 * new destination to ask for.
 *
 * **Where it connects is checked, once.** The name is resolved here, every
 * address it resolves to must be public (loopback, private, link-local and
 * the metadata address, carrier-grade NAT, multicast, reserved, and IPv6
 * forms of them are refused), and the connection goes to the address that
 * was checked, with TLS verified against the name. A second answer from DNS
 * (rebinding) is never asked for. It is no proxy: CONNECT and absolute-form
 * requests are refused.
 *
 * **Nothing unrecorded.** The use is written to the log, fsynced, before a
 * byte leaves; a log that cannot be written stops the fetch. The response is
 * sealed whole or refused whole: a body over the grant's byte limit is not
 * kept in part, its size is recorded. A revocation or expiry during a
 * transfer stops it, and what came is sealed as incomplete and not
 * delivered.
 *
 *   node --experimental-strip-types scripts/net-fetch.ts plan --sandbox S --run ID --out FILE
 *   node --experimental-strip-types scripts/net-fetch.ts --config FILE [--port N] [--ready FILE] [--quiet]
 */
import { spawn } from "node:child_process";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest, createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, type Socket } from "node:net";
import { dirname, join, resolve } from "node:path";
import type { TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import { loadCatalogue, publicAddress, type Catalogue } from "./net-adapters.ts";
import { appendNetEvents, captureDir, captureRef, CAPTURES_REL, FETCH_LOCK, FETCH_LOG, grantStatus, leadOpen, parseCaptureRef, rawDir, readNetState, type GrantRecord, type NetDraft } from "./net-grants.ts";
import { denyCategory, loadDeny, type DenyList } from "./net-adapters.ts";

export type FetchLimits = {
  /** A request, from connect to the last byte (per hop). */
  deadline_ms: number;
  connect_ms: number;
  max_concurrent: number;
  max_concurrent_per_principal: number;
  /** A call's own body (its JSON), not a response. */
  max_call_bytes: number;
  /** How long a use waits for an adapter's rate interval before it is refused. */
  rate_wait_max_ms: number;
  /** How often a transfer checks that its grant still stands. */
  recheck_ms: number;
  /** Refusals logged per principal and code a minute; the rest are counted. */
  refusal_log_per_minute: number;
};

export const DEFAULT_FETCH_LIMITS: FetchLimits = {
  deadline_ms: 30_000,
  connect_ms: 10_000,
  max_concurrent: 8,
  max_concurrent_per_principal: 2,
  max_call_bytes: 64 * 1024,
  rate_wait_max_ms: 5_000,
  recheck_ms: 250,
  refusal_log_per_minute: 20,
};

export type NetFetchConfig = {
  v: 1;
  run: string;
  sandbox: string;
  /** The HMAC key of every principal's token: hex, in the hub's directory only. */
  secret: string;
  host?: string;
  port?: number;
  catalogue?: string;
  deny?: string;
  limits?: Partial<FetchLimits>;
};

/** A principal's token: what a job's worker is given, and what the hub shows for a seat. */
export function principalToken(secret: string, principal: string): string {
  return createHmac("sha256", Buffer.from(secret, "hex")).update(principal).digest("hex");
}

export const USER_AGENT = "dfirswarm-netfetch/1 (+https://dfirswarm.ai; a forensic reference lookup)";

/** The trace events the fetch service writes (reserved against forged tools). */
export const NET_FETCH_EVENTS = ["net_fetch_started", "net_fetch_refused"] as const;

export type FetchCall = { grant?: unknown; method?: unknown; url?: unknown; body?: unknown };

export type Hop = { url: string; address: string | null; status?: number; location?: string; followed?: boolean; refused?: string };

export type FetchAnswer = {
  ok: boolean;
  grant: string | null;
  code?: string;
  detail?: string;
  capture?: string;
  n?: number;
  status?: number;
  headers?: Array<[string, string]>;
  bytes?: number;
  sha256?: string;
  complete?: boolean;
  delivered?: boolean;
  /** A redirect not followed: the next destination, which needs a grant of its own. */
  location?: string;
  /** Where the delivered body is sealed, from the run's directory. */
  path?: string;
  body_b64?: string;
  hops?: Hop[];
  exposed?: Array<{ what: string; category: string }>;
  note?: string;
};

export type FetchOptions = {
  /** DNS: every address a name resolves to (tests stand in a resolver). */
  resolve?: (host: string) => Promise<string[]>;
  /** Whether an address may be connected to (tests allow the loopback of a mock server). */
  addressAllowed?: (ip: string) => boolean;
  /** The port actually connected for a grant's port (tests point 443 at a mock server). */
  connectPort?: (host: string, port: number) => number;
  /** Extra trusted CAs (tests); the system's are used otherwise. */
  ca?: string | Buffer;
  /** Host-managed keys, by adapter name, resolved from this process's environment at start. */
  keys?: Map<string, string>;
  now?: () => number;
  quiet?: boolean;
  traceEmit?: ((record: Record<string, unknown>) => void) | null;
};

const REDIRECT = new Set([301, 302, 303, 307, 308]);
/** Why a grant no longer stands: said as itself, never as an audit failure. */
const GRANT_REFUSALS = new Set(["expired", "revoked", "lead_closed", "no_grant", "grants_unreadable", "exhausted"]);

function writeAtomic(path: string, text: string, mode = 0o644): void {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, text, { mode });
  renameSync(tmp, path);
}

/** The keys the catalogue's adapters name, from this process's environment: the values stay here. */
export function resolveAdapterKeys(catalogue: Catalogue, env: NodeJS.ProcessEnv = process.env): Map<string, string> {
  const keys = new Map<string, string>();
  for (const a of catalogue.adapters) if (a.key && env[a.key.env]) keys.set(a.name, String(env[a.key.env]));
  return keys;
}

export class FetchService {
  readonly config: NetFetchConfig;
  readonly S: string;
  private readonly limits: FetchLimits;
  private readonly o: FetchOptions;
  private readonly catalogue: Catalogue;
  private readonly deny: DenyList;
  private readonly keys: Map<string, string>;
  private readonly inFlight = new Map<string, number>();
  private total = 0;
  private readonly lastAt = new Map<string, number>();
  /** Attempts this process has under way (grant#n): never reconciled as orphans. */
  private readonly active = new Set<string>();
  private reconcileTimer: ReturnType<typeof setInterval> | null = null;
  private readonly refusalsThisMinute = new Map<string, { minute: number; count: number }>();
  private server: Server | null = null;
  port = 0;

  constructor(config: NetFetchConfig, options: FetchOptions = {}) {
    if (!/^[0-9a-f]{64}$/.test(config.secret)) throw new Error("the fetch service's secret is 64 hex digits");
    this.config = config;
    this.S = resolve(config.sandbox);
    this.limits = { ...DEFAULT_FETCH_LIMITS, ...(config.limits ?? {}) };
    this.o = options;
    this.catalogue = loadCatalogue(config.catalogue);
    this.deny = loadDeny(config.deny);
    this.keys = options.keys ?? resolveAdapterKeys(this.catalogue);
  }

  /** Which adapters' keys are configured (names only), for the hub's enforceability step. */
  keyedAdapters(): string[] {
    return [...this.keys.keys()].sort();
  }

  private now(): number {
    return this.o.now ? this.o.now() : Date.now();
  }

  private allowed(ip: string): boolean {
    return (this.o.addressAllowed ?? publicAddress)(ip);
  }

  private async resolveHost(host: string): Promise<string[]> {
    if (this.o.resolve) return this.o.resolve(host);
    const all = await dnsLookup(host, { all: true, verbatim: true });
    return all.map((a) => a.address);
  }

  /** Whether a token is the principal's, compared in constant time. */
  authenticate(principal: string, token: string): boolean {
    if (!/^(seat|job):[A-Za-z0-9._-]{1,64}$/.test(principal) || !/^[0-9a-f]{64}$/.test(token)) return false;
    const want = Buffer.from(principalToken(this.config.secret, principal), "hex");
    const got = Buffer.from(token, "hex");
    return got.length === want.length && timingSafeEqual(got, want);
  }

  /** A refusal: logged (a few a minute per principal and code, the rest counted), traced once a minute, answered. */
  private async refuse(principal: string, grant: string | null, code: string, detail: string): Promise<FetchAnswer> {
    const key = `${principal}:${code}`;
    const minute = Math.floor(this.now() / 60_000);
    let seen = this.refusalsThisMinute.get(key);
    if (seen && seen.minute !== minute) {
      if (seen.count > this.limits.refusal_log_per_minute) await this.log([{ by: "fetch-service", ev: "refused", principal, grant, code, detail: `${seen.count - this.limits.refusal_log_per_minute} more refusals of this kind in the minute before, counted and not written one by one` }]).catch(() => undefined);
      seen = undefined;
    }
    if (!seen) {
      seen = { minute, count: 0 };
      this.refusalsThisMinute.set(key, seen);
      this.o.traceEmit?.({ tool: "net_fetch_refused", args: { via: "net-fetch", principal, grant, code }, result: { ok: false, detail } });
    }
    seen.count += 1;
    if (seen.count <= this.limits.refusal_log_per_minute) await this.log([{ by: "fetch-service", ev: "refused", principal, grant, code, detail }]).catch(() => undefined);
    return { ok: false, grant, code, detail };
  }

  private log(drafts: NetDraft[]) {
    return P.withNamedLock(this.S, FETCH_LOCK, (held) => appendNetEvents(this.S, FETCH_LOG, drafts, held));
  }

  /**
   * One use of a grant, by a principal whose token was checked. Every check
   * before the attempt line refuses with a code; after it, what happened is
   * the capture's.
   */
  async fetch(principal: string, token: string, call: FetchCall): Promise<FetchAnswer> {
    if (!this.authenticate(principal, token)) return this.refuse(/^(seat|job):[A-Za-z0-9._-]{1,64}$/.test(principal) ? principal : "?", null, "bad_token", "no valid principal token");
    const grantId = typeof call.grant === "string" ? call.grant.trim().toUpperCase() : "";
    if (!/^N-[1-9]\d{0,6}$/.test(grantId)) return this.refuse(principal, null, "no_grant", "name the grant: N-<k>");
    if (call.body !== undefined && call.body !== null && call.body !== "") return this.refuse(principal, grantId, "body_not_allowed", "a grant is a read: no request body is ever sent");
    const state = await readNetState(this.S);
    if (!state.chain.ok) return this.refuse(principal, grantId, "grants_unreadable", `network/grants.jsonl's chain is broken at line ${state.chain.broken_at} (${state.chain.reason}): no grant is honoured until the operator looks`);
    const g = state.grants.get(grantId);
    if (!g) return this.refuse(principal, grantId, "no_grant", `${grantId} is not a grant of this run`);
    if (g.type !== "fetch") return this.refuse(principal, grantId, "not_a_fetch_grant", `${grantId} is a socket grant: a job's own client uses it, in its worker's network`);
    if (g.principal !== principal) return this.refuse(principal, grantId, "principal_mismatch", `${grantId} is ${g.principal.startsWith("job-of:") ? `for a job of ${g.principal.slice(7)}, not yet bound to one (job_run net_grants)` : `${g.principal}'s`}, not ${principal}'s: a grant does not travel`);
    const st = grantStatus(g, state, this.now());
    if (st.status === "revoked" || st.status === "expired" || st.status === "exhausted") return this.refuse(principal, grantId, st.status, `${grantId} is ${st.status}: ${st.why}`);
    if (!(await leadOpen(this.S, g.lead))) return this.refuse(principal, grantId, "lead_closed", `${grantId}'s lead ${g.lead} is closed`);
    const method = call.method === undefined || call.method === null ? g.method : String(call.method).toUpperCase();
    if (method !== g.method) return this.refuse(principal, grantId, "method_mismatch", `${grantId} permits ${g.method}, not ${method}`);
    const url = call.url === undefined || call.url === null ? g.url : String(call.url);
    if (url !== g.url) return this.refuse(principal, grantId, "url_mismatch", `${grantId} permits exactly ${g.url}; a path beside it, another query or an added parameter is another request, which needs a grant of its own`);
    // Concurrency.
    if (this.total >= this.limits.max_concurrent || (this.inFlight.get(principal) ?? 0) >= this.limits.max_concurrent_per_principal) return this.refuse(principal, grantId, "busy", "too many fetches at once: try again when one ends");
    this.total += 1;
    this.inFlight.set(principal, (this.inFlight.get(principal) ?? 0) + 1);
    try {
      return await this.use(principal, g);
    } finally {
      this.total -= 1;
      this.inFlight.set(principal, Math.max(0, (this.inFlight.get(principal) ?? 1) - 1));
    }
  }

  /**
   * Whether a grant still stands right now (its time, its revocation, its
   * lead), read from the chain again: asked before the attempt is written,
   * after every DNS answer, during the transfer, and before anything is
   * published. A use count is not asked here: the use under way is counted.
   */
  private async invalid(id: string): Promise<{ code: string; detail: string } | null> {
    const s = await readNetState(this.S);
    if (!s.chain.ok) return { code: "grants_unreadable", detail: `network/grants.jsonl's chain is broken at line ${s.chain.broken_at}` };
    const g = s.grants.get(id);
    if (!g) return { code: "no_grant", detail: `${id} is not a grant of this run` };
    const st = grantStatus({ ...g, max_requests: null }, s, this.now());
    if (st.status === "revoked" || st.status === "expired") return { code: st.status, detail: `${id} is ${st.status}: ${st.why}` };
    if (!(await leadOpen(this.S, g.lead))) return { code: "lead_closed", detail: `${id}'s lead ${g.lead} is closed` };
    return null;
  }

  private async use(principal: string, g: GrantRecord): Promise<FetchAnswer> {
    // The adapter's rate, per host: a slot reserved at once (no two fetches
    // read the same last time), then waited for, or refused.
    if (g.rate?.min_interval_ms) {
      const now = this.now();
      const slot = Math.max(now, (this.lastAt.get(g.host) ?? 0) + g.rate.min_interval_ms);
      const wait = slot - now;
      if (wait > this.limits.rate_wait_max_ms) return this.refuse(principal, g.id, "rate", `${g.host} is asked at most once every ${g.rate.min_interval_ms} ms; try again in ${Math.ceil(wait / 1000)} s`);
      this.lastAt.set(g.host, slot);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }
    // The attempt, counted and written before anything leaves, under the
    // log's lock, with the grant held to again there: a wait is no licence.
    let n = 0;
    try {
      await P.withNamedLock(this.S, FETCH_LOCK, async (held) => {
        const stale = await this.invalid(g.id);
        if (stale) throw Object.assign(new Error(stale.detail), { code: stale.code });
        const fresh = await readNetState(this.S);
        const uses = (fresh.fetches.get(g.id) ?? []).length;
        if (g.max_requests !== null && uses >= g.max_requests) throw Object.assign(new Error(`${g.id}'s ${g.max_requests} use${g.max_requests === 1 ? " is" : "s are"} taken`), { code: "exhausted" });
        n = uses + 1;
        await appendNetEvents(this.S, FETCH_LOG, [{ by: "fetch-service", ev: "attempt", grant: g.id, n, capture: captureRef(g.k, n), principal, method: g.method, url: g.url }], held);
      });
    } catch (err) {
      const code = (err as { code?: string }).code ?? "";
      if (GRANT_REFUSALS.has(code)) return this.refuse(principal, g.id, code, (err as Error).message);
      return this.refuse(principal, g.id, "audit_unavailable", `the fetch could not be recorded (${(err as Error).message}); nothing unrecorded is fetched`);
    }
    const key = `${g.id}#${n}`;
    this.active.add(key);
    try {
      const started = new Date(this.now()).toISOString();
      const r = await this.carry(g);
      // Held to once more before anything is published: an answer that came
      // after the grant ended is kept, never delivered.
      if (!r.stopped && !r.oversize && !r.refused) {
        const stale = await this.invalid(g.id);
        if (stale) Object.assign(r, { stopped: stale.code, complete: false, error: `${stale.detail}, before the answer was published` });
      }
      return await this.seal(principal, g, n, started, r);
    } finally {
      this.active.delete(key);
    }
  }

  /**
   * The request, and the referral hops an adapter declares; each hop's
   * address checked, and the grant held to after each DNS answer. Only a
   * whole, in-limit redirect is ever followed: an oversize, broken or stopped
   * answer ends the fetch where it is.
   */
  private async carry(g: GrantRecord): Promise<Carried> {
    const hops: Hop[] = [];
    let url = g.url as string;
    const original = new URL(url);
    for (let hop = 0; ; hop += 1) {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      let addresses: string[];
      try {
        addresses = await this.resolveHost(host);
      } catch (err) {
        hops.push({ url, address: null, refused: `dns: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}` });
        return { hops, error: `the name ${host} did not resolve (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})` };
      }
      const stale = await this.invalid(g.id);
      if (stale) {
        hops.push({ url, address: null, refused: stale.code });
        return { hops, complete: false, stopped: stale.code, error: `${stale.detail}, before the connection: nothing was sent` };
      }
      if (!addresses.length) {
        hops.push({ url, address: null, refused: "dns: no address" });
        return { hops, error: `the name ${host} resolved to no address` };
      }
      const bad = addresses.filter((a) => !isIP(a) || !this.allowed(a));
      if (bad.length) {
        hops.push({ url, address: null, refused: `private or reserved address: ${bad.join(", ")}` });
        return { hops, refused: { code: "private_address", detail: `${host} resolves to ${bad.join(", ")}, which is not a public address: never connected to (DNS rebinding and internal hosts end here)` } };
      }
      // IPv4 first, then the rest: the address checked is the address connected to.
      const address = [...addresses.filter((a) => isIP(a) === 4), ...addresses.filter((a) => isIP(a) === 6)][0];
      const once = await this.once(g, u, address);
      hops.push({ url, address, ...(once.status !== undefined ? { status: once.status } : {}), ...(once.location ? { location: once.location } : {}) });
      const terminal = once.error || once.refused || once.oversize || once.stopped || once.complete !== true;
      if (terminal || once.status === undefined || !REDIRECT.has(once.status) || !once.location) {
        if (terminal && once.location) hops[hops.length - 1].followed = false;
        return { ...once, hops, ...(terminal && once.location ? { not_followed: "the answer was not whole (oversize, broken off or stopped): nothing past it is followed" } : {}) };
      }
      // A redirect: followed only to an adapter's declared referral host, asking the same thing.
      const next = this.referral(g, original, u, once.location);
      if (!next.ok || hop + 1 >= (g.redirects?.max ?? 0)) {
        hops[hops.length - 1].followed = false;
        return { ...once, hops, not_followed: next.ok ? `more than ${g.redirects?.max ?? 0} referrals` : next.why };
      }
      hops[hops.length - 1].followed = true;
      url = next.url;
    }
  }

  private referral(g: GrantRecord, original: URL, current: URL, location: string): { ok: true; url: string } | { ok: false; why: string } {
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      return { ok: false, why: "the Location is not a URL" };
    }
    if (!g.redirects || g.redirects.follow !== "referral") return { ok: false, why: "a redirect is never followed: the Location is a new destination, which needs a grant of its own" };
    if (next.protocol !== "https:" || next.username || next.password || (next.port && next.port !== "443")) return { ok: false, why: "a referral is followed only over https, on 443, with no credential in it" };
    const host = next.hostname.toLowerCase();
    if (isIP(host) || !g.redirects.hosts.includes(host)) return { ok: false, why: `${host} is not one of the adapter's referral hosts` };
    if (next.search || !next.pathname.toLowerCase().endsWith(original.pathname.toLowerCase())) return { ok: false, why: "the referral does not ask the same thing (its path must end with the original's, with no query)" };
    return { ok: true, url: next.href };
  }

  /** One request to one checked address; the body read up to the grant's limit and not a byte past it kept. */
  private once(g: GrantRecord, u: URL, address: string): Promise<Omit<Carried, "hops">> {
    const secure = u.protocol === "https:";
    const port = Number(u.port || (secure ? 443 : 80));
    const connectPort = this.o.connectPort ? this.o.connectPort(u.hostname, port) : port;
    const headers: Record<string, string> = { "user-agent": USER_AGENT, accept: "*/*", "accept-encoding": "identity", connection: "close" };
    const shown: Array<[string, string]> = Object.entries(headers);
    const key = g.adapter ? this.keys.get(g.adapter) : undefined;
    if (g.key && key) {
      headers[g.key.header] = key;
      shown.push([g.key.header, "[host-managed key, not recorded]"]);
    }
    const family = isIP(address);
    const pinned = (_host: string, opts: { all?: boolean } | undefined, cb: (err: Error | null, addr: string | Array<{ address: string; family: number }>, fam?: number) => void) => {
      if (opts && opts.all) cb(null, [{ address, family }]);
      else cb(null, address, family);
    };
    const maxBytes = g.max_bytes ?? 0;
    return new Promise((done) => {
      let finished = false;
      const chunks: Buffer[] = [];
      let bytes = 0;
      let tls: Carried["tls"] = null;
      const finish = (r: Omit<Carried, "hops">) => {
        if (finished) return;
        finished = true;
        clearTimeout(deadline);
        clearInterval(recheck);
        done({ ...r, sent: shown, address, ...(tls ? { tls } : {}) });
      };
      const req = (secure ? httpsRequest : httpRequest)(
        {
          protocol: u.protocol,
          hostname: u.hostname,
          port: connectPort,
          method: g.method as string,
          path: `${u.pathname}${u.search}`,
          headers,
          agent: false,
          lookup: pinned as never,
          timeout: this.limits.connect_ms,
          ...(secure ? { servername: u.hostname, rejectUnauthorized: true, ...(this.o.ca ? { ca: this.o.ca } : {}) } : {}),
        },
        (res) => {
          const sock = res.socket as TLSSocket;
          if (secure && typeof sock.getPeerCertificate === "function") {
            const c = sock.getPeerCertificate();
            tls = { protocol: sock.getProtocol?.() ?? null, cipher: sock.getCipher?.()?.name ?? null, authorized: sock.authorized === true, subject: c?.subject?.CN ?? null, issuer: c?.issuer?.CN ?? null, valid_from: c?.valid_from ?? null, valid_to: c?.valid_to ?? null, fingerprint256: c?.fingerprint256 ?? null, subjectaltname: c?.subjectaltname ?? null };
          }
          const status = res.statusCode ?? 0;
          const resHeaders: Array<[string, string]> = [];
          for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) resHeaders.push([res.rawHeaders[i], res.rawHeaders[i + 1]]);
          const location = typeof res.headers.location === "string" ? res.headers.location : undefined;
          const declared = Number(res.headers["content-length"]);
          if (g.method === "HEAD" || REDIRECT.has(status) && maxBytes === 0) {
            res.resume();
            res.on("end", () => finish({ status, headers: resHeaders, body: Buffer.alloc(0), complete: true, ...(location ? { location } : {}) }));
            res.on("error", () => finish({ status, headers: resHeaders, body: Buffer.alloc(0), complete: true, ...(location ? { location } : {}) }));
            return;
          }
          if (Number.isFinite(declared) && declared > maxBytes) {
            // Settled first: the stream's own errors after the cut are not the answer.
            finish({ status, headers: resHeaders, body: null, complete: false, oversize: { declared, limit: maxBytes }, ...(location ? { location } : {}) });
            res.destroy();
            req.destroy();
            return;
          }
          res.on("data", (c: Buffer) => {
            if (finished) return;
            bytes += c.length;
            if (bytes > maxBytes) {
              finish({ status, headers: resHeaders, body: null, complete: false, oversize: { received_at_least: bytes, limit: maxBytes, ...(Number.isFinite(declared) ? { declared } : {}) }, ...(location ? { location } : {}) });
              res.destroy();
              req.destroy();
              return;
            }
            chunks.push(c);
          });
          res.on("end", () => finish({ status, headers: resHeaders, body: Buffer.concat(chunks), complete: true, ...(location ? { location } : {}) }));
          res.on("error", (err) => finish({ status, headers: resHeaders, body: Buffer.concat(chunks), complete: false, error: `the response broke off: ${err.message}` }));
          res.on("aborted", () => finish({ status, headers: resHeaders, body: Buffer.concat(chunks), complete: false, error: "the response broke off" }));
        },
      );
      const deadline = setTimeout(() => {
        req.destroy();
        finish({ body: Buffer.concat(chunks), complete: false, error: `no whole answer within ${this.limits.deadline_ms / 1000} s` });
      }, this.limits.deadline_ms);
      // The grant, held to while the bytes come: revoked or expired, the transfer stops.
      const recheck = setInterval(() => {
        void this.invalid(g.id).then((stale) => {
          if (stale) {
            req.destroy();
            finish({ body: Buffer.concat(chunks), complete: false, stopped: stale.code, error: `${stale.detail}, during the transfer` });
          }
        }).catch(() => undefined);
      }, this.limits.recheck_ms);
      req.on("timeout", () => req.destroy(new Error(`the connection was silent for ${this.limits.connect_ms / 1000} s`)));
      req.on("error", (err) => finish({ body: Buffer.concat(chunks), complete: false, error: `${(err as NodeJS.ErrnoException).code ?? "error"}: ${err.message}` }));
      req.end();
    });
  }

  /**
   * Seal what came. What is delivered, and the record of the request and the
   * answer, are built in a staging directory beside the run and published as
   * store/net/<k>/<n>/ only once the result line is written: a capture no
   * seat can read until the log says what it is. Whatever was received and
   * not delivered (a filtered adapter's whole response and its headers, a
   * partial body, an answer withheld because its grant ended) is kept beside
   * the run in <run>.netraw/<k>/<n>/, in no VM's reach, and the capture
   * records each by its size and hash.
   */
  private async seal(principal: string, g: GrantRecord, n: number, started: string, r: Carried): Promise<FetchAnswer> {
    const ref = captureRef(g.k, n);
    const dir = captureDir(this.S, g.k, n);
    const finishedAt = new Date(this.now()).toISOString();
    const whole = r.complete === true && !r.oversize && !r.refused && !r.stopped;
    // A HEAD has no body; an oversize body was never kept.
    const body = g.method === "HEAD" || r.oversize || !r.body ? null : r.body;
    const keepDir = join(rawDir(this.S), String(g.k), String(n));
    const kept: Array<{ name: string; bytes: number; sha256: string; what: string }> = [];
    const keep = (name: string, bytes: Buffer, what: string) => {
      mkdirSync(keepDir, { recursive: true, mode: 0o700 });
      writeFileSync(join(keepDir, name), bytes, { mode: 0o400 });
      kept.push({ name, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"), what });
    };
    let delivered: Buffer | null = whole ? body : null;
    let note: string | undefined;
    if (body && !whole) keep(r.complete && r.stopped ? "body.withheld" : "body.partial", body, r.complete && r.stopped ? "the answer, withheld because its grant ended before it was published" : `the bytes received before the transfer ${r.stopped ? `was stopped (${r.stopped})` : "broke off"}`);
    let headers = r.headers ?? [];
    if (g.response_fields?.length) {
      // An adapter that delivers only some fields delivers those, as JSON; the
      // whole response and all its headers stay beside the run.
      if (headers.length) {
        keep("headers.json", Buffer.from(`${JSON.stringify(headers, null, 2)}\n`), "every header of the answer");
        headers = headers.filter(([k]) => ["content-type", "content-length", "date"].includes(k.toLowerCase()));
      }
      if (delivered) {
        const raw = delivered;
        keep("body", raw, "the whole response");
        try {
          const parsed = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
          const fields = Object.fromEntries(g.response_fields.filter((f) => f in parsed).map((f) => [f, parsed[f]]));
          delivered = Buffer.from(`${JSON.stringify(fields, null, 2)}\n`);
          note = `only ${g.response_fields.join(", ")} delivered, as the adapter says; the whole response is kept beside the run, outside the VMs (${raw.length} bytes, sha256 ${createHash("sha256").update(raw).digest("hex")})`;
        } catch {
          delivered = null;
          note = "the response is not JSON, so none of its fields could be delivered; it is kept whole beside the run, outside the VMs";
        }
      }
    }
    const exposed: Array<{ what: string; category: string }> = [];
    for (const h of r.hops) {
      if (!h.location) continue;
      let host = "";
      try {
        host = new URL(h.location, h.url).hostname.toLowerCase();
      } catch {
        continue;
      }
      const cat = denyCategory(host, this.deny);
      if (cat) exposed.push({ what: `a redirect to ${h.location}`, category: cat.category });
    }
    const request = { capture: ref, grant: g.id, n, principal, adapter: g.adapter, method: g.method, url: g.url, lead: g.lead, sent_headers: r.sent ?? [], address: r.address ?? null, hops: r.hops, ...(r.tls ? { tls: r.tls } : {}), started_at: started };
    const response = {
      status: r.status ?? null,
      headers,
      ...(g.response_fields?.length && (r.headers ?? []).length ? { headers_note: "only the content type, length and date; every header is kept beside the run" } : {}),
      finished_at: finishedAt,
      complete: whole,
      ...(r.error ? { error: r.error } : {}),
      ...(r.refused ? { refused: r.refused } : {}),
      ...(r.oversize ? { oversize: r.oversize, refused: { code: "oversize", detail: "the body is larger than the grant's limit: refused whole, never kept in part" } } : {}),
      ...(r.stopped ? { stopped: r.stopped } : {}),
      ...(r.location ? { location: r.location, followed: false, ...(r.not_followed ? { why_not_followed: r.not_followed } : {}) } : {}),
    };
    const files: Array<{ name: string; bytes: Buffer }> = [];
    files.push({ name: "request.json", bytes: Buffer.from(`${JSON.stringify(request, null, 2)}\n`) });
    files.push({ name: "response.json", bytes: Buffer.from(`${JSON.stringify(response, null, 2)}\n`) });
    if (delivered) files.push({ name: "body", bytes: delivered });
    const sha = delivered ? createHash("sha256").update(delivered).digest("hex") : undefined;
    const capture = {
      ref,
      grant: g.id,
      n,
      adapter: g.adapter,
      principal,
      method: g.method,
      url: g.url,
      status: r.status ?? null,
      complete: whole,
      delivered: Boolean(delivered),
      bytes: delivered?.length ?? 0,
      ...(sha ? { sha256: sha } : {}),
      ...(kept.length ? { kept: kept.map((x) => ({ ...x, where: `<run>.netraw/${g.k}/${n}/${x.name}` })) } : {}),
      ...(r.oversize ? { oversize: r.oversize } : {}),
      ...(r.stopped ? { stopped: r.stopped } : {}),
      ...(r.error ? { error: r.error } : {}),
      ...(note ? { note } : {}),
      external: "external material: collected now from a third party; an examiner records what it establishes. Its hash proves these bytes, not their truth or their fit to the time of the events",
      started_at: started,
      finished_at: finishedAt,
    };
    files.push({ name: "capture.json", bytes: Buffer.from(`${JSON.stringify(capture, null, 2)}\n`) });
    const manifest = {
      v: 1,
      job: ref,
      attempt: 1,
      sealed_at: finishedAt,
      files: files.map((f) => ({ path: f.name, path_b64: Buffer.from(f.name).toString("base64"), bytes: f.bytes.length, sha256: createHash("sha256").update(f.bytes).digest("hex"), mode: "0444" })),
      dirs: [],
      rejected: [],
      totals: { files: files.length, bytes: files.reduce((a, f) => a + f.bytes.length, 0) },
    };
    const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
    const staging = join(rawDir(this.S), ".staging", `${g.k}-${n}-${randomBytes(4).toString("hex")}`);
    mkdirSync(staging, { recursive: true, mode: 0o700 });
    for (const f of files) writeFileSync(join(staging, f.name), f.bytes, { mode: 0o444 });
    writeFileSync(join(staging, "manifest.json"), manifestText, { mode: 0o444 });
    const refused = r.refused ?? (r.oversize ? { code: "oversize", detail: `larger than the grant's ${g.max_bytes} bytes: refused whole` } : undefined);
    // The result line first, durably: without it nothing is published.
    try {
      await this.log([
        {
          by: "fetch-service",
          ev: "result",
          grant: g.id,
          n,
          capture: ref,
          ...(r.status !== undefined ? { status: r.status } : {}),
          ...(r.error ? { error: r.error } : {}),
          ...(refused ? { refused } : {}),
          ...(r.stopped ? { stopped: r.stopped } : {}),
          bytes: delivered?.length ?? 0,
          ...(sha ? { sha256: sha } : {}),
          complete: whole,
          delivered: Boolean(delivered),
          published: true,
          manifest_sha256: createHash("sha256").update(manifestText).digest("hex"),
          ...(kept.length ? { kept: kept.map((x) => ({ name: x.name, bytes: x.bytes, sha256: x.sha256 })) } : {}),
          ...(exposed.length ? { exposed } : {}),
        },
      ]);
    } catch (err) {
      // Not recorded, so not published: what came is kept beside the run, and the attempt waits for its outcome (reconcile).
      mkdirSync(keepDir, { recursive: true, mode: 0o700 });
      try {
        renameSync(staging, join(keepDir, "unpublished"));
      } catch {
        // left in the staging directory, beside the run all the same
      }
      if (!this.o.quiet) process.stderr.write(`net-fetch: the result of ${ref} could not be written (${(err as Error).message}); nothing was published\n`);
      return { ok: false, grant: g.id, capture: ref, n, delivered: false, complete: false, code: "audit_unavailable", detail: `the outcome of ${ref} could not be recorded (${(err as Error).message}): nothing was published or delivered, and the answer is kept beside the run` };
    }
    try {
      mkdirSync(dirname(dir), { recursive: true });
      try {
        renameSync(staging, dir);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EXDEV") throw err;
        cpSync(staging, dir, { recursive: true });
        rmSync(staging, { recursive: true, force: true });
      }
      chmodSync(dir, 0o555);
    } catch (err) {
      if (!this.o.quiet) process.stderr.write(`net-fetch: ${ref} was recorded and could not be published: ${(err as Error).message}\n`);
      return { ok: false, grant: g.id, capture: ref, n, delivered: false, complete: false, code: "publish_failed", detail: `${ref} was recorded and could not be published (${(err as Error).message}); custody names it missing` };
    }
    const answer: FetchAnswer = {
      ok: whole && (Boolean(delivered) || g.method === "HEAD"),
      grant: g.id,
      capture: ref,
      n,
      ...(r.status !== undefined ? { status: r.status } : {}),
      headers,
      bytes: delivered?.length ?? 0,
      ...(sha ? { sha256: sha } : {}),
      complete: whole,
      delivered: Boolean(delivered),
      ...(delivered ? { path: `${CAPTURES_REL}/${g.k}/${n}/body` } : {}),
      hops: r.hops,
      ...(r.location ? { location: new URL(r.location, r.hops.at(-1)?.url ?? (g.url as string)).href } : {}),
      ...(exposed.length ? { exposed } : {}),
      ...(refused ? { code: refused.code, detail: refused.detail } : r.error ? { code: r.stopped ?? "failed", detail: r.error } : {}),
      ...(note ? { note } : {}),
    };
    if (!answer.ok && !answer.code) {
      answer.code = "not_delivered";
      answer.detail = note ?? "nothing was delivered";
    }
    return answer;
  }

  /**
   * Give every attempt its outcome: an attempt line with no result (the
   * service stopped mid-fetch, or its result line could not be written) gets
   * one saying so, and that nothing of it was published. Run when the
   * service starts, and then for attempts older than a fetch can take.
   */
  async reconcile(olderThanMs = 0): Promise<number> {
    return P.withNamedLock(this.S, FETCH_LOCK, async (held) => {
      const s = await readNetState(this.S);
      if (!s.fetchChain.ok) return 0;
      const drafts: NetDraft[] = [];
      for (const list of s.fetches.values()) {
        for (const f of list) {
          if (f.result || this.active.has(`${f.grant}#${f.n}`)) continue;
          if (this.now() - Date.parse(f.at) < olderThanMs) continue;
          const c = parseCaptureRef(f.capture);
          const unpublished = c ? join(rawDir(this.S), String(c.k), String(c.n), "unpublished") : null;
          drafts.push({
            by: "fetch-service",
            ev: "result",
            grant: f.grant,
            n: f.n,
            capture: f.capture,
            error: "no outcome was recorded for this attempt (the fetch service stopped during it, or its result line could not be written); nothing of it was published or delivered",
            complete: false,
            delivered: false,
            published: false,
            reconciled: true,
            ...(unpublished && existsSync(unpublished) ? { kept: [{ name: "unpublished", what: "the capture as it was built, beside the run" }] } : {}),
          });
        }
      }
      if (drafts.length) await appendNetEvents(this.S, FETCH_LOG, drafts, held);
      return drafts.length;
    });
  }

  // --- the server ------------------------------------------------------------------------------

  private readCall(req: IncomingMessage): Promise<Buffer | "too_large" | "aborted"> {
    return new Promise((done) => {
      const parts: Buffer[] = [];
      let bytes = 0;
      let over = false;
      req.on("data", (c: Buffer) => {
        bytes += c.length;
        if (bytes > this.limits.max_call_bytes) over = true;
        else parts.push(c);
      });
      req.on("end", () => done(over ? "too_large" : Buffer.concat(parts)));
      req.on("error", () => done("aborted"));
    });
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(`${JSON.stringify(body)}\n`);
    };
    const target = req.url ?? "";
    if (!target.startsWith("/")) return send(400, { ok: false, code: "not_a_proxy", detail: "this is no proxy: a request names /v1/fetch, never another host" });
    if (req.method === "GET" && target === "/v1/health") return send(200, { ok: true, run: this.config.run });
    if (req.method !== "POST" || target !== "/v1/fetch") return send(404, { ok: false, code: "not_a_route", detail: "POST /v1/fetch with a grant" });
    const body = await this.readCall(req);
    if (body === "aborted") return;
    if (body === "too_large") return send(413, { ok: false, code: "call_too_large", detail: "a call is a grant id and at most a method and a URL" });
    let call: FetchCall;
    try {
      call = JSON.parse(body.toString("utf8")) as FetchCall;
    } catch {
      return send(400, { ok: false, code: "not_json", detail: "the call is JSON: {grant, method?, url?}" });
    }
    const auth = String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "").trim();
    const principal = String(req.headers["x-dfirswarm-principal"] ?? "").trim();
    const answer = await this.fetch(principal, auth, call);
    // A job's worker gets the delivered bytes with the answer; the hub reads them from the store.
    if (answer.delivered && answer.path && principal.startsWith("job:")) {
      try {
        answer.body_b64 = readFileSync(join(this.S, answer.path)).toString("base64");
      } catch {
        // the path is in the answer
      }
    }
    send(answer.code === "bad_token" ? 401 : answer.ok ? 200 : answer.capture ? 502 : 403, answer);
  }

  async listen(port = this.config.port ?? 0, host = this.config.host ?? "127.0.0.1"): Promise<number> {
    // Attempts a service before this one left without an outcome get theirs first.
    await this.reconcile().catch((err: Error) => {
      if (!this.o.quiet) process.stderr.write(`net-fetch: attempts could not be reconciled: ${err.message}\n`);
    });
    this.reconcileTimer = setInterval(() => void this.reconcile(this.limits.deadline_ms * 4 + 60_000).catch(() => undefined), 60_000);
    this.reconcileTimer.unref?.();
    const server = createServer((req, res) => {
      this.handle(req, res).catch((err) => {
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, code: "internal", detail: "the fetch service failed on this call" }));
        } else res.end();
        if (!this.o.quiet) process.stderr.write(`net-fetch: ${(err as Error).message}\n`);
      });
    });
    // No tunnel, ever: a CONNECT is answered and the socket closed.
    server.on("connect", (_req: IncomingMessage, socket: Socket) => {
      socket.end("HTTP/1.1 405 Method Not Allowed\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{\"ok\":false,\"code\":\"no_tunnel\",\"detail\":\"this is no proxy: CONNECT is refused\"}\n");
      void this.refuse("?", null, "no_tunnel", "a CONNECT was refused").catch(() => undefined);
    });
    server.on("upgrade", (_req: IncomingMessage, socket: Socket) => {
      socket.end("HTTP/1.1 405 Method Not Allowed\r\nconnection: close\r\n\r\n");
    });
    server.headersTimeout = 15_000;
    server.requestTimeout = 120_000;
    this.server = server;
    return new Promise((done, fail) => {
      server.once("error", fail);
      server.listen(port, host, () => {
        const addr = server.address();
        this.port = typeof addr === "object" && addr ? addr.port : port;
        this.o.traceEmit?.({ tool: "net_fetch_started", args: { via: "net-fetch" }, result: { ok: true, port: this.port, keyed: this.keyedAdapters() } });
        done(this.port);
      });
    });
  }

  close(): Promise<void> {
    if (this.reconcileTimer) clearInterval(this.reconcileTimer);
    return new Promise((done) => {
      if (!this.server) return done();
      this.server.close(() => done());
      this.server.closeAllConnections?.();
    });
  }
}

type Carried = {
  hops: Hop[];
  status?: number;
  headers?: Array<[string, string]>;
  body?: Buffer | null;
  complete?: boolean;
  location?: string;
  not_followed?: string;
  error?: string;
  refused?: { code: string; detail: string };
  oversize?: Record<string, number>;
  stopped?: string;
  sent?: Array<[string, string]>;
  address?: string;
  tls?: Record<string, unknown> | null;
};

/** The config of a run's fetch service: a fresh secret, in the hub's directory, 0600. */
export function planFetch(input: { sandbox: string; run: string; port?: number }): NetFetchConfig {
  return { v: 1, run: input.run, sandbox: resolve(input.sandbox), secret: randomBytes(32).toString("hex"), host: "127.0.0.1", ...(input.port ? { port: input.port } : {}) };
}

/** Trace lines through the collector, as the gateway sends them (scripts/trace-emit.mjs). */
function collectorEmitter(sandbox: string): ((record: Record<string, unknown>) => void) | null {
  if (!process.env.SWARM_TRACE_TOKEN) return null;
  const script = join(dirname(fileURLToPath(import.meta.url)), "trace-emit.mjs");
  return (record) => {
    const child = spawn(process.execPath, [script, sandbox], { stdio: ["pipe", "ignore", "ignore"], env: process.env });
    child.on("error", () => undefined);
    child.stdin?.end(JSON.stringify({ ts: new Date().toISOString(), agent: "system", ...record }));
  };
}

async function main(argv: string[]): Promise<void> {
  const opt = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  if (argv[0] === "plan") {
    const sandbox = opt("--sandbox");
    const run = opt("--run");
    const out = opt("--out");
    if (!sandbox || !run || !out) throw new Error("plan needs --sandbox, --run and --out");
    writeAtomic(out, `${JSON.stringify(planFetch({ sandbox, run }), null, 2)}\n`, 0o600);
    chmodSync(out, 0o600);
    process.stdout.write(`${JSON.stringify({ ok: true, config: out })}\n`);
    return;
  }
  const configPath = opt("--config");
  if (!configPath) {
    process.stderr.write("net-fetch: usage: net-fetch.ts plan --sandbox S --run ID --out FILE | --config FILE [--port N] [--ready FILE] [--quiet]\n");
    process.exit(2);
  }
  const config = JSON.parse(readFileSync(configPath, "utf8")) as NetFetchConfig;
  if (config.v !== 1 || !config.sandbox || !config.secret) throw new Error(`${configPath} is not a fetch service config`);
  const service = new FetchService(config, { quiet: argv.includes("--quiet"), traceEmit: collectorEmitter(config.sandbox) });
  const port = await service.listen(opt("--port") ? Number(opt("--port")) : config.port);
  const ready = opt("--ready");
  if (ready) writeAtomic(ready, `${JSON.stringify({ port, pid: process.pid, keyed: service.keyedAdapters() })}\n`);
  if (!argv.includes("--quiet")) process.stderr.write(`net-fetch: run ${config.run} on 127.0.0.1:${port}\n`);
  const stop = () => {
    void service.close().then(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`net-fetch: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
