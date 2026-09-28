/**
 * The adapter catalogue and the hard-deny list of the dynamic network mode
 * (network/adapters.json, network/deny.json; docs/adr/0012), and the typed
 * values an adapter takes.
 *
 * An adapter is one exact host, method and path template. What an agent
 * gives is a value of a declared type (a domain, a hash, a coordinate),
 * checked here and placed by the template, percent-encoded: it can never
 * become a host, a path segment, a query key or a second request. A geocoder
 * does not become a text-exfiltration endpoint because the only free text it
 * takes is a bounded place name that must be found in the evidence, and a map
 * query is built from a coordinate, a radius and a tag, never written.
 *
 * Nothing here knows a forensic format or a tool: the types are the public
 * shapes of the values the adapters send.
 */
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { DisclosureClass } from "./case-policy.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const CATALOGUE_PATH = join(ROOT, "network", "adapters.json");
export const DENY_PATH = join(ROOT, "network", "deny.json");

export const PARAM_TYPES = ["domain", "ip", "ip_or_prefix", "asn", "cve", "hash", "lat", "lon", "int", "enum", "osm_tag", "youtube_id", "place_text", "evidence_url"] as const;
export type ParamType = (typeof PARAM_TYPES)[number];
export type ParamSpec = { type: ParamType; min?: number; max?: number; values?: string[]; keys?: string[] };

export type Adapter = {
  name: string;
  title: string;
  class: "reference" | "evidence_linked";
  contact: "passive" | "active";
  disclosure: DisclosureClass | "none";
  /** A category of the deny list this adapter is a declared, narrow exception to. */
  exception?: string;
  scheme: "https" | "http" | "from_url";
  host: string;
  port?: number;
  method: "GET" | "HEAD";
  path: string;
  query?: Array<[string, string]>;
  params: Record<string, ParamSpec>;
  max_bytes: number;
  redirects?: { follow: "referral"; max: number; hosts: string[] };
  response?: { fields: string[] };
  key?: { env: string; header: string };
  rate?: { min_interval_ms: number };
  terms?: string;
};

export type Catalogue = { v: 1; adapters: Adapter[]; byName: Map<string, Adapter> };

export type DenyList = {
  v: 1;
  categories: Record<string, { why: string; hosts: string[] }>;
  login_paths: string[];
  credential_params: string[];
};

const NAME = /^[a-z][a-z0-9_]{1,40}$/;
const PARAM = /^[a-z][a-z0-9_]{0,40}$/;

/** The catalogue, every adapter checked; the first that is not an adapter throws with the reason. */
export function loadCatalogue(path = CATALOGUE_PATH): Catalogue {
  const raw = JSON.parse(readFileSync(path, "utf8")) as { v?: unknown; adapters?: unknown };
  if (raw.v !== 1 || !Array.isArray(raw.adapters)) throw new Error(`${path}: not an adapter catalogue (v 1, adapters)`);
  const byName = new Map<string, Adapter>();
  for (const a of raw.adapters as Adapter[]) {
    const bad = (why: string) => new Error(`${path}: adapter ${JSON.stringify(a?.name)}: ${why}`);
    if (!a || typeof a.name !== "string" || !NAME.test(a.name)) throw bad("a name is lowercase letters, digits and _");
    if (byName.has(a.name)) throw bad("named twice");
    if (a.class !== "reference" && a.class !== "evidence_linked") throw bad("class is reference or evidence_linked");
    if (a.contact !== "passive" && a.contact !== "active") throw bad("contact is passive or active");
    if (a.method !== "GET" && a.method !== "HEAD") throw bad("an adapter reads: GET or HEAD");
    if (!Number.isInteger(a.max_bytes) || a.max_bytes < 0 || a.max_bytes > 64 * 1024 * 1024) throw bad("max_bytes is 0 to 64 MiB");
    const dynamic = a.host === "from_url";
    if (dynamic !== (a.scheme === "from_url") || dynamic !== (a.path === "from_url")) throw bad("a host from the URL goes with a scheme and a path from the URL");
    if (dynamic && (Object.keys(a.params).length !== 1 || Object.values(a.params)[0].type !== "evidence_url")) throw bad("a host from the URL takes one evidence_url and nothing else");
    if (!dynamic) {
      if (a.scheme !== "https") throw bad("a fixed host is reached over https");
      if (!hostName(a.host)) throw bad(`${a.host} is not a host name`);
      if (!a.path.startsWith("/")) throw bad("a path starts with /");
    }
    for (const [p, spec] of Object.entries(a.params ?? {})) {
      if (!PARAM.test(p)) throw bad(`param ${p}: a name is lowercase letters, digits and _`);
      if (!(PARAM_TYPES as readonly string[]).includes(spec.type)) throw bad(`param ${p}: type ${spec.type} is not one of ${PARAM_TYPES.join(", ")}`);
    }
    const used = new Set([...(a.path ?? "").matchAll(/\{([a-z0-9_]+)(?::[a-z]+)?\}/g), ...(a.query ?? []).flatMap(([, v]) => [...v.matchAll(/\{([a-z0-9_]+)(?::[a-z]+)?\}/g)])].map((m) => m[1]));
    if (!dynamic) for (const p of Object.keys(a.params)) if (!used.has(p)) throw bad(`param ${p} is placed nowhere`);
    for (const u of used) if (!(u in a.params)) throw bad(`the template names {${u}}, which is not a param`);
    if (a.redirects && (a.redirects.follow !== "referral" || !Array.isArray(a.redirects.hosts) || !a.redirects.hosts.every((h) => hostName(h)))) throw bad("redirects: follow referral, to named hosts");
    if (a.key && (!/^[A-Z][A-Z0-9_]{2,63}$/.test(a.key.env) || !/^[a-z][a-z0-9-]{1,40}$/.test(a.key.header))) throw bad("key: an environment variable and a header name");
    byName.set(a.name, a);
  }
  return { v: 1, adapters: [...byName.values()], byName };
}

export function loadDeny(path = DENY_PATH): DenyList {
  const raw = JSON.parse(readFileSync(path, "utf8")) as DenyList;
  if (raw.v !== 1 || !raw.categories || !Array.isArray(raw.login_paths) || !Array.isArray(raw.credential_params)) throw new Error(`${path}: not a deny list`);
  return raw;
}

// --- names and addresses ---------------------------------------------------------------------

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A DNS name: labels, a top-level label that is not all digits, 253 characters at most. Lowercase. */
export function hostName(raw: string): boolean {
  const h = raw.toLowerCase();
  if (!h || h.length > 253 || isIP(h)) return false;
  const labels = h.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return false;
  return !/^\d+$/.test(labels.at(-1) ?? "");
}

/** Top-level labels that name a private network, never the public internet. */
const INTERNAL_TLDS = new Set(["local", "localhost", "lan", "home", "corp", "internal", "intranet", "private", "localdomain", "invalid", "test", "example", "arpa", "home.arpa"]);

/** Whether a name belongs to a private network: an internal top-level label (or a single label, which a hostName refuses). */
export function internalName(host: string): boolean {
  const labels = host.toLowerCase().split(".");
  return labels.length < 2 || INTERNAL_TLDS.has(labels.at(-1) ?? "");
}

function v4(ip: string): number[] {
  return ip.split(".").map(Number);
}

/**
 * An IPv6 address as its sixteen bytes, whatever its spelling (leading
 * zeros, `::` anywhere, an embedded dotted IPv4 tail, a zone), or null.
 * Classification reads these bytes, never the text: `64:ff9b::a00:1` and
 * `0064:ff9b::a00:1` are one address.
 */
export function ipv6Bytes(ip: string): number[] | null {
  let x = ip.trim().toLowerCase().replace(/^\[|\]$/g, "");
  const zone = x.indexOf("%");
  if (zone >= 0) x = x.slice(0, zone);
  if (isIP(x) !== 6) return null;
  const groups = (part: string): number[] | null => {
    if (!part) return [];
    const out: number[] = [];
    const items = part.split(":");
    for (let i = 0; i < items.length; i += 1) {
      const g = items[i];
      if (i === items.length - 1 && g.includes(".")) {
        if (isIP(g) !== 4) return null;
        const [a, b, c, d] = v4(g);
        out.push((a << 8) | b, (c << 8) | d);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
        out.push(Number.parseInt(g, 16));
      }
    }
    return out;
  };
  const halves = x.split("::");
  if (halves.length > 2) return null;
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return null;
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || head.length + fill + tail.length !== 8) return null;
  const words = [...head, ...Array(fill).fill(0), ...tail];
  return words.flatMap((w) => [(w >> 8) & 0xff, w & 0xff]);
}

/**
 * Whether an address is one the fetch service may connect to, and a value
 * that names the public internet: public unicast, never loopback, private,
 * link-local (the cloud metadata address with it), carrier-grade NAT,
 * multicast, documentation, benchmarking or reserved space. IPv6 is read by
 * its bytes: only global unicast (2000::/3) is public, less the ranges in
 * it that embed or stand for another address (6to4, Teredo and the rest of
 * 2001::/23) or are documentation; every IPv4-mapped, -compatible or NAT64
 * form (::ffff:0:0/96, ::/96, 64:ff9b::/96, 64:ff9b:1::/48) is outside
 * 2000::/3 and so never public, whatever it embeds.
 */
export function publicAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) {
    const [a, b, c] = v4(ip);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (kind === 6) {
    const b = ipv6Bytes(ip);
    if (!b) return false;
    if ((b[0] & 0xe0) !== 0x20) return false; // outside 2000::/3: loopback, unspecified, mapped, NAT64, ULA, link-local, multicast, reserved
    const w0 = (b[0] << 8) | b[1];
    const w1 = (b[2] << 8) | b[3];
    if (w0 === 0x2002) return false; // 6to4 embeds an IPv4 address
    if (w0 === 0x2001 && w1 < 0x0200) return false; // 2001::/23: Teredo, benchmarking, ORCHID and the other protocol assignments
    if (w0 === 0x2001 && w1 === 0x0db8) return false; // documentation
    if (w0 === 0x3fff && (w1 & 0xf000) === 0) return false; // 3fff::/20, documentation
    return true;
  }
  return false;
}

// --- values ------------------------------------------------------------------------------------

export type Checked = { ok: true; value: string; render: string; classes: DisclosureClass[] } | { ok: false; reason: string };

const HASH = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/;
const LAT = /^-?\d{1,2}(?:\.\d{1,10})?$/;
const LON = /^-?\d{1,3}(?:\.\d{1,10})?$/;

/** The algorithm a hex hash's length names. */
export function hashAlgorithm(hash: string): "md5" | "sha1" | "sha256" {
  return hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : "sha256";
}

/**
 * One value of a declared type: refused with the reason, or kept as the
 * agent wrote it (normalised only where the type says: a domain or a hash
 * lowercased, an AS number's digits) with the text it is placed as and the
 * classes of case data it carries.
 */
export function checkValue(name: string, spec: ParamSpec, raw: unknown): Checked {
  if (typeof raw !== "string" && typeof raw !== "number") return { ok: false, reason: `${name} is a ${spec.type}, given as a string` };
  const text = String(raw).trim();
  const fail = (why: string): Checked => ({ ok: false, reason: `${name}: ${why} (got ${JSON.stringify(text.length > 300 ? `${text.slice(0, 300)}…` : text)})` });
  switch (spec.type) {
    case "domain": {
      const d = text.toLowerCase().replace(/\.$/, "");
      if (!hostName(d)) return fail("a domain name (example.org), not an address, a URL or a single label");
      return { ok: true, value: d, render: d, classes: [internalName(d) ? "internal_name" : "public_indicator"] };
    }
    case "ip": {
      if (!isIP(text)) return fail("an IPv4 or IPv6 address");
      return { ok: true, value: text.toLowerCase(), render: text.toLowerCase(), classes: [publicAddress(text) ? "public_indicator" : "internal_name"] };
    }
    case "ip_or_prefix": {
      const [addr, prefix, more] = text.split("/");
      if (more !== undefined || !isIP(addr)) return fail("an IP address or a prefix (192.0.2.0/24)");
      if (prefix !== undefined && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > (isIP(addr) === 4 ? 32 : 128))) return fail("a prefix length that fits the address");
      return { ok: true, value: text.toLowerCase(), render: text.toLowerCase(), classes: [publicAddress(addr) ? "public_indicator" : "internal_name"] };
    }
    case "asn": {
      const m = /^(?:as)?(\d{1,10})$/i.exec(text);
      if (!m || Number(m[1]) > 4294967295 || Number(m[1]) === 0) return fail("an AS number (AS3333 or 3333)");
      return { ok: true, value: m[1], render: m[1], classes: ["public_indicator"] };
    }
    case "cve": {
      const c = text.toUpperCase();
      if (!/^CVE-\d{4}-\d{4,7}$/.test(c)) return fail("a CVE id (CVE-2024-3094)");
      return { ok: true, value: c, render: c, classes: ["public_indicator"] };
    }
    case "hash": {
      const h = text.toLowerCase();
      if (!HASH.test(h)) return fail("an MD5, SHA-1 or SHA-256 hash in hex");
      return { ok: true, value: h, render: h, classes: ["hash"] };
    }
    case "lat":
      if (!LAT.test(text) || Math.abs(Number(text)) > 90) return fail("a latitude in decimal degrees, -90 to 90, as written in the evidence");
      return { ok: true, value: text, render: text, classes: ["coordinate"] };
    case "lon":
      if (!LON.test(text) || Math.abs(Number(text)) > 180) return fail("a longitude in decimal degrees, -180 to 180, as written in the evidence");
      return { ok: true, value: text, render: text, classes: ["coordinate"] };
    case "int": {
      if (!/^\d{1,9}$/.test(text)) return fail("a whole number");
      const n = Number(text);
      if ((spec.min !== undefined && n < spec.min) || (spec.max !== undefined && n > spec.max)) return fail(`a whole number from ${spec.min ?? 0} to ${spec.max ?? "any"}`);
      return { ok: true, value: String(n), render: String(n), classes: [] };
    }
    case "enum":
      if (!(spec.values ?? []).includes(text)) return fail(`one of ${(spec.values ?? []).join(", ")}`);
      return { ok: true, value: text, render: text, classes: [] };
    case "osm_tag": {
      const m = /^([a-z_:]{1,40})(?:=([A-Za-z0-9_:-]{1,40}))?$/.exec(text);
      if (!m || !(spec.keys ?? []).includes(m[1])) return fail(`an OpenStreetMap tag: key or key=value, the key one of ${(spec.keys ?? []).join(", ")}`);
      return { ok: true, value: text, render: m[2] ? `["${m[1]}"="${m[2]}"]` : `["${m[1]}"]`, classes: [] };
    }
    case "youtube_id":
      if (!/^[A-Za-z0-9_-]{11}$/.test(text)) return fail("a YouTube video id: 11 letters, digits, - or _");
      return { ok: true, value: text, render: text, classes: ["public_indicator"] };
    case "place_text": {
      if (text.length < 2 || text.length > 200) return fail("a place name or address of 2 to 200 characters");
      // eslint-disable-next-line no-control-regex
      if (/[\x00-\x1f\x7f]/.test(text)) return fail("one line of printable text");
      if (/:\/\/|[<>{}[\]\\]/.test(text)) return fail("a place name, not a URL or markup");
      const classes: DisclosureClass[] = ["coordinate"];
      if (/@/.test(text)) classes.push("personal");
      return { ok: true, value: text, render: text, classes };
    }
    case "evidence_url": {
      const u = checkUrl(text);
      if (!u.ok) return fail(u.reason);
      return { ok: true, value: u.href, render: u.href, classes: [internalName(u.host) ? "internal_name" : "public_indicator"] };
    }
  }
}

/**
 * One exact URL, as the evidence holds it: http or https, a host name (never
 * an address: an address is where DNS rebinding and private ranges hide),
 * the scheme's own port, no user or password, no fragment, and already in
 * the form a request sends (so what is checked against the evidence is what
 * leaves). Returned with its host, port and path.
 */
export function checkUrl(raw: string): { ok: true; href: string; scheme: "http" | "https"; host: string; port: number; path: string } | { ok: false; reason: string } {
  if (raw.length > 2048) return { ok: false, reason: "a URL of at most 2048 characters" };
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: "not a URL" };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, reason: "an http or https URL" };
  if (u.username || u.password || /@/.test(raw.split("/")[2] ?? "")) return { ok: false, reason: "a URL with a user or password in it carries a credential: refused" };
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIP(host)) return { ok: false, reason: "a host name, never an address (IP literals are refused)" };
  if (!hostName(host)) return { ok: false, reason: `${host} is not a host name` };
  const scheme = u.protocol === "https:" ? "https" : "http";
  if (u.port && u.port !== (scheme === "https" ? "443" : "80")) return { ok: false, reason: `the scheme's own port only (${scheme === "https" ? 443 : 80})` };
  if (u.hash || raw.includes("#")) return { ok: false, reason: "no fragment: a fragment is never sent, so it is never granted" };
  if (u.href !== raw && `${raw}/` !== u.href) return { ok: false, reason: `not in the form a request sends (${u.href}); cite it as it is sent` };
  return { ok: true, href: u.href, scheme, host, port: scheme === "https" ? 443 : 80, path: `${u.pathname}${u.search}` };
}

// --- building a request ----------------------------------------------------------------------

export type BuiltRequest = {
  adapter: string;
  method: "GET" | "HEAD";
  scheme: "https" | "http";
  host: string;
  port: number;
  /** The path and query, exactly as sent. */
  path: string;
  url: string;
  /** Each value the agent gave, as it leaves the run: what the evidence link and the credential scan read. */
  values: Record<string, string>;
  classes: DisclosureClass[];
};

function render(template: string, values: Map<string, Checked & { ok: true }>, encode: (s: string) => string): string {
  return template.replace(/\{([a-z0-9_]+)(?::([a-z]+))?\}/g, (_, name: string, mod: string | undefined) => {
    const v = values.get(name);
    if (!v) throw new Error(`{${name}} has no value`);
    if (mod === "algorithm") return encode(hashAlgorithm(v.value));
    return encode(v.render);
  });
}

/**
 * An adapter's request from the agent's values: every param given, of its
 * type, and nothing else; placed by the template, each percent-encoded where
 * it goes. The result is the one request a grant permits.
 */
export function buildRequest(a: Adapter, params: Record<string, unknown>): { ok: true; request: BuiltRequest } | { ok: false; reason: string } {
  const given = Object.keys(params ?? {});
  const extra = given.filter((k) => !(k in a.params));
  if (extra.length) return { ok: false, reason: `${a.name} takes ${Object.keys(a.params).join(", ") || "no params"}; not ${extra.join(", ")}` };
  const checked = new Map<string, Checked & { ok: true }>();
  const classes = new Set<DisclosureClass>();
  if (a.disclosure !== "none") classes.add(a.disclosure);
  for (const [name, spec] of Object.entries(a.params)) {
    if (!(name in (params ?? {}))) return { ok: false, reason: `${a.name} needs ${name} (a ${spec.type})` };
    const c = checkValue(name, spec, params[name]);
    if (!c.ok) return c;
    checked.set(name, c);
    for (const k of c.classes) classes.add(k);
  }
  const values = Object.fromEntries([...checked].map(([k, v]) => [k, v.value]));
  if (a.host === "from_url") {
    const url = [...checked.values()][0].value;
    const u = checkUrl(url);
    if (!u.ok) return u;
    return { ok: true, request: { adapter: a.name, method: a.method, scheme: u.scheme, host: u.host, port: u.port, path: u.path, url: u.href, values, classes: [...classes] } };
  }
  let path: string;
  let query = "";
  try {
    path = render(a.path, checked, (s) => encodeURIComponent(s));
    if (a.query?.length) query = a.query.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(render(v, checked, (s) => s))}`).join("&");
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
  const full = query ? `${path}?${query}` : path;
  const port = a.port ?? 443;
  return { ok: true, request: { adapter: a.name, method: a.method, scheme: "https", host: a.host, port, path: full, url: `https://${a.host}${port === 443 ? "" : `:${port}`}${full}`, values, classes: [...classes] } };
}

// --- the hard denials ------------------------------------------------------------------------

/** Whether a host is a deny entry or a name under it; `name.*` is that label under any suffix. */
export function hostMatches(host: string, entry: string): boolean {
  const h = host.toLowerCase();
  const e = entry.toLowerCase();
  if (e.endsWith(".*")) {
    const label = e.slice(0, -2);
    return h.split(".").slice(0, -1).includes(label);
  }
  return h === e || h.endsWith(`.${e}`);
}

/** The deny category a host falls in, and why, or null. */
export function denyCategory(host: string, deny: DenyList): { category: string; why: string } | null {
  for (const [category, c] of Object.entries(deny.categories)) {
    if (c.hosts.some((e) => hostMatches(host, e))) return { category, why: c.why };
  }
  return null;
}

/** A path segment that names a login, an account or a session. */
export function loginPath(path: string, deny: DenyList): string | null {
  const segs = path.split("?")[0].toLowerCase().split("/").map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
  return segs.find((s) => deny.login_paths.includes(s)) ?? null;
}

/** The query keys of a URL that name a credential. */
export function credentialParams(path: string, deny: DenyList): string[] {
  const q = path.includes("?") ? path.slice(path.indexOf("?") + 1) : "";
  if (!q) return [];
  const out: string[] = [];
  for (const kv of q.split("&")) {
    let k = kv.split("=")[0];
    try {
      k = decodeURIComponent(k);
    } catch {
      // as written
    }
    if (deny.credential_params.includes(k.toLowerCase())) out.push(k);
  }
  return out;
}

/**
 * Credential patterns: a provider or cloud key, a token, a private key, a
 * bearer header. A value that looks like one is never sent out of the run,
 * whatever the adapter; the model provider's keys never reach this process
 * at all, and this is the second wall.
 */
export const CREDENTIAL_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "an OpenAI-style secret key", re: /\bsk-(?:proj-|ant-|or-)?[A-Za-z0-9_-]{16,}/ },
  { name: "an AWS access key id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "a GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{20,}/ },
  { name: "a GitLab token", re: /\bglpat-[A-Za-z0-9_-]{16,}/ },
  { name: "a Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: "a Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "a Google OAuth token", re: /\bya29\.[0-9A-Za-z_-]{20,}/ },
  { name: "a JSON web token", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/ },
  { name: "a private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "a bearer or basic authorization", re: /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}/ },
  { name: "a user and password in a URL", re: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i },
];

export function credentialPattern(text: string): string | null {
  for (const p of CREDENTIAL_PATTERNS) if (p.re.test(text)) return p.name;
  return null;
}
