/**
 * The adapter catalogue against the real services (docs/adr/0011): each
 * key-less adapter's request, made by the fetch service with its real
 * resolver and address check, answered and sealed. Off unless
 * SWARM_NET_LIVE=1 (it reaches the internet and the services' own limits);
 * VirusTotal only with DFIRSWARM_VT_API_KEY set. Every unit test of the
 * network mode runs against a local mock (tests/net-fetch.test.ts).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { buildRequest, loadCatalogue } from "../scripts/net-adapters.ts";
import { FetchService, planFetch, principalToken, resolveAdapterKeys } from "../scripts/net-fetch.ts";
import { appendNetEvents, GRANTS_LOG, NET_LOCK, readNetState } from "../scripts/net-grants.ts";

const LIVE = process.env.SWARM_NET_LIVE === "1";
const dirs: string[] = [];
after(async () => {
  // Captures are sealed read-only, their directories too.
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const SAMPLES: Record<string, Record<string, string>> = {
  rdap_domain: { domain: "example.com" },
  rdap_ip: { ip: "8.8.8.8" },
  rdap_autnum: { asn: "3333" },
  crtsh: { domain: "example.com" },
  nvd_cve: { cve: "CVE-2024-3094" },
  cisa_kev: {},
  circl_hashlookup: { hash: "d41d8cd98f00b204e9800998ecf8427e" },
  ripestat_prefix: { resource: "193.0.6.139" },
  ripestat_asn: { asn: "3333" },
  nominatim_reverse: { lat: "52.5163", lon: "13.3777" },
  nominatim_search: { q: "Brandenburger Tor, Berlin" },
  overpass_around: { lat: "52.5163", lon: "13.3777", radius: "200", tag: "tourism" },
  youtube_oembed: { video_id: "dQw4w9WgXcQ" },
  http_head: { url: "https://example.com/" },
  virustotal_file: { hash: "44d88612fea8a8f36de82e1278abb02f" },
};

test("every adapter answers from its real service, sealed, through the real resolver", { skip: LIVE ? false : "set SWARM_NET_LIVE=1 to reach the real services" }, async () => {
  const base = await mkdtemp(join(tmpdir(), "netlive-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "live", agentIds: ["a1"], capUsd: 1, wallClockMinutes: 30 });
  await L.openLead({ sandboxRoot: S, agentId: "a1" }, { title: "live adapters", why: "the catalogue against the services", take: true });
  await mkdir(join(S, "network"), { recursive: true });
  const config = planFetch({ sandbox: S, run: "live" });
  const catalogue = loadCatalogue();
  const keys = resolveAdapterKeys(catalogue);
  const svc = new FetchService(config, { quiet: true, keys });
  await svc.listen(0);
  try {
    for (const a of catalogue.adapters) {
      if (a.key && !keys.has(a.name)) continue;
      const b = buildRequest(a, SAMPLES[a.name] ?? {});
      assert.ok(b.ok, `${a.name}: ${(b as { reason?: string }).reason}`);
      if (!b.ok) continue;
      const id = await P.withNamedLock(S, NET_LOCK, async (held) => {
        const st = await readNetState(S);
        const g = `N-${st.grants.size + 1}`;
        await appendNetEvents(S, GRANTS_LOG, [{ by: "policy", ev: "grant", grant: g, terms: { type: "fetch", principal: "seat:a1", lead: "L-1", adapter: a.name, method: b.request.method, url: b.request.url, scheme: b.request.scheme, host: b.request.host, port: b.request.port, path: b.request.path, redirects: a.redirects ?? null, response_fields: a.response?.fields ?? null, max_requests: 1, max_bytes: a.max_bytes, ttl_seconds: 300, expires_at: new Date(Date.now() + 300_000).toISOString(), key: a.key ?? null, rate: null } }], held);
        return g;
      });
      const r = await svc.fetch("seat:a1", principalToken(config.secret, "seat:a1"), { grant: id });
      process.stdout.write(`# ${a.name}: ${r.status ?? r.code} ${r.bytes ?? 0} bytes${r.location ? ` -> ${r.location}` : ""}${r.hops && r.hops.length > 1 ? ` (${r.hops.length} hops)` : ""}\n`);
      assert.ok(r.capture, `${a.name}: ${JSON.stringify(r)}`);
      assert.notEqual(r.code, "private_address", a.name);
      assert.ok(r.status !== undefined && r.status >= 200 && r.status < 500, `${a.name}: ${JSON.stringify(r)}`);
    }
  } finally {
    await svc.close();
    await writeFile(join(base, "done"), "");
  }
});
