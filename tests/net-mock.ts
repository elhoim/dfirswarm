/**
 * The dynamic network's test rig: a mock HTTPS server standing in for the
 * public internet on loopback (a self-signed certificate made once with
 * openssl, every name listed), a run with a lead held by a1 and a recorded
 * case policy, and a fetch service whose resolver and address check allow
 * the mock and nothing else private. Shared by tests/net-fetch.test.ts and
 * tests/net-hub.test.ts.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { resolveCasePolicy, type CasePolicy } from "../scripts/case-policy.ts";
import { publicAddress } from "../scripts/net-adapters.ts";
import { FetchService, planFetch, principalToken } from "../scripts/net-fetch.ts";
import { appendNetEvents, GRANTS_LOG, NET_LOCK, readNetState } from "../scripts/net-grants.ts";

export const dirs: string[] = [];
export const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers) await c().catch(() => undefined);
  // Captures are sealed read-only, their directories too.
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

// Every name by itself: a TLS client takes no wildcard over a single-label suffix (*.test).
const HOSTS = ["rdap.org", "rdap.verisign.com", "crt.sh", "nominatim.openstreetmap.org", "www.youtube.com", "stat.ripe.net", "hashlookup.circl.lu", "www.virustotal.com", "pastebin.com", "example.org", "*.example.org", ...["short", "evil", "elsewhere", "slow", "big", "chunked", "internal", "metadata", "v6", "ula", "mapped", "mixed", "rebind", "bit", "late"].map((h) => `${h}.test`)];

/** A self-signed certificate for the mock's names, made once; null where openssl is missing. */
let certs: { key: string; cert: string } | null | undefined;
export async function testCert(): Promise<{ key: string; cert: string } | null> {
  if (certs !== undefined) return certs;
  const d = await mkdtemp(join(tmpdir(), "netcert-"));
  dirs.push(d);
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(d, "k.pem"), "-out", join(d, "c.pem"), "-days", "2", "-subj", "/CN=dfirswarm-net-test", "-addext", `subjectAltName=${HOSTS.map((h) => `DNS:${h}`).join(",")}`], { stdio: "ignore" });
    certs = { key: await readFile(join(d, "k.pem"), "utf8"), cert: await readFile(join(d, "c.pem"), "utf8") };
  } catch {
    certs = null;
  }
  return certs;
}

export type Seen = { host: string; method: string; url: string; headers: Record<string, string | string[] | undefined> };

export type Handler = (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void;

export async function mockServer(route: (host: string, path: string) => Handler | null): Promise<{ port: number; seen: Seen[]; server: HttpsServer }> {
  const c = (await testCert())!;
  const seen: Seen[] = [];
  const server = createHttpsServer({ key: c.key, cert: c.cert }, (req, res) => {
    const host = String(req.headers.host ?? "").replace(/:\d+$/, "");
    seen.push({ host, method: req.method ?? "", url: req.url ?? "", headers: req.headers });
    const h = route(host, req.url ?? "");
    if (h) return h(req, res);
    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"error":"not here"}');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  closers.push(() => new Promise<void>((r) => server.close(() => r())));
  const addr = server.address();
  return { port: typeof addr === "object" && addr ? addr.port : 0, seen, server };
}

export const json = (body: unknown, status = 200, extra: Record<string, string> = {}): Handler => (_req, res) => {
  res.writeHead(status, { "content-type": "application/json", ...extra });
  res.end(JSON.stringify(body));
};

export type Setup = Awaited<ReturnType<typeof setup>>;

export async function setup(o: { policy?: string; route?: (host: string, path: string) => Handler | null; resolveMap?: Record<string, string[] | (() => string[])>; keys?: Map<string, string> } = {}) {
  const base = await mkdtemp(join(tmpdir(), "net-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "n1", agentIds: ["a1", "a2"], capUsd: 5, wallClockMinutes: 30 });
  const r = resolveCasePolicy({ flags: { policy: o.policy ?? "standard", network: "dynamic" }, isolation: "microvm" });
  assert.ok(r.ok, JSON.stringify(r));
  const policy = (r as { policy: CasePolicy }).policy;
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
  const lead = await L.openLead({ sandboxRoot: S, agentId: "a1" }, { title: "Look up what the evidence names", why: "It settles where the traffic went", take: true });
  assert.ok(lead.ok, (lead as { reason?: string }).reason);
  const mock = await mockServer(o.route ?? (() => null));
  const hubDir = join(base, "hub");
  await mkdir(hubDir, { recursive: true, mode: 0o700 });
  const config = planFetch({ sandbox: S, run: "n1" });
  await writeFile(join(hubDir, "net-fetch.json"), JSON.stringify(config), { mode: 0o600 });
  const resolved: string[] = [];
  const svc = new FetchService(config, {
    quiet: true,
    ca: (await testCert())!.cert,
    resolve: async (host) => {
      resolved.push(host);
      const m = o.resolveMap?.[host];
      if (m) return typeof m === "function" ? m() : m;
      return ["127.0.0.1"];
    },
    // The mock stands in for the public internet on loopback; nothing else private is allowed.
    addressAllowed: (ip) => ip === "127.0.0.1" || publicAddress(ip),
    connectPort: () => mock.port,
    ...(o.keys ? { keys: o.keys } : {}),
  });
  const port = await svc.listen(0);
  closers.push(() => svc.close());
  await writeFile(join(S, "network", "service.json"), JSON.stringify({ port, keyed: svc.keyedAdapters() }));
  return { S, base, hubDir, config, svc, port, mock, resolved, policy };
}

/** A grant written straight onto the chain, with the terms a test needs. */
export async function grant(s: Setup, terms: Record<string, unknown>): Promise<string> {
  return P.withNamedLock(s.S, NET_LOCK, async (held) => {
    const st = await readNetState(s.S);
    const id = `N-${st.grants.size + 1}`;
    const rq = `NR-${st.requests.size + 1}`;
    await appendNetEvents(s.S, GRANTS_LOG, [
      { by: "a1", ev: "request", request: rq, principal: "seat:a1", lead: "L-1", digest: `d${rq}`, type: "fetch", host: terms.host ?? "rdap.org", input: {} },
      { by: "policy", ev: "decide", request: rq, decision: "granted", reasons: [], grant: id },
      {
        by: "policy",
        ev: "grant",
        grant: id,
        request: rq,
        terms: {
          type: "fetch",
          principal: "seat:a1",
          lead: "L-1",
          adapter: "rdap_domain",
          method: "GET",
          url: "https://rdap.org/domain/example.org",
          scheme: "https",
          host: "rdap.org",
          port: 443,
          path: "/domain/example.org",
          redirects: null,
          response_fields: null,
          max_requests: 1,
          max_bytes: 1024 * 1024,
          ttl_seconds: 300,
          expires_at: new Date(Date.now() + 300_000).toISOString(),
          key: null,
          rate: null,
          request: rq,
          ...terms,
        },
      },
    ], held);
    return id;
  });
}

export const token = (s: Setup, principal: string) => principalToken(s.config.secret, principal);
export const use = (s: Setup, principal: string, call: Record<string, unknown>) => s.svc.fetch(principal, token(s, principal), call);

export async function skipWithoutTls(t: { skip: (m: string) => void }): Promise<boolean> {
  if (await testCert()) return false;
  t.skip("openssl is not available to make the mock's certificate");
  return true;
}

