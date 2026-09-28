/**
 * The twelve defects an independent security review (Astra, over
 * 612cc29..0bacf82) found in the dynamic network, each reproduced here and
 * held fixed: sensitive values and encoded credentials in what leaves;
 * undelivered bytes where a seat could read them; an agent's own prose
 * taken as evidence; (the package hosts of a strict preset are the kickoff's,
 * tests/net-kickoff.test.sh); a grant used after it expired or was revoked;
 * a revoked socket host in another spelling; a fetch published without its
 * result line, and an attempt with no outcome passing custody; concurrent
 * requests past the grant quota and the adapter's interval; external
 * lineage lost through a path, a digest or a broad scope; the whole
 * response of a filtered adapter unverified; IPv6 classified by its text;
 * an oversize redirect followed.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import { appendFile, chmod, copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { resolveCasePolicy, type CasePolicy } from "../scripts/case-policy.ts";
import { checkValue, loadCatalogue, loadDeny, publicAddress } from "../scripts/net-adapters.ts";
import { evidenceCheck, externalLineage, operatorRevoke, operatorSocket, requestAccess } from "../scripts/net-broker.ts";
import { FetchService, principalToken } from "../scripts/net-fetch.ts";
import { checkNetwork, FETCH_LOG, rawDir, readNetState } from "../scripts/net-grants.ts";
import { evaluate, type NetRequestInput, type PolicyEnv } from "../scripts/net-policy.ts";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { grant, json, setup, skipWithoutTls, testCert, token, use, type Handler } from "./net-mock.ts";

function policy(flags: Record<string, string>): CasePolicy {
  const r = resolveCasePolicy({ flags, isolation: "microvm" });
  assert.ok(r.ok, JSON.stringify(r));
  return (r as { policy: CasePolicy }).policy;
}

const catalogue = loadCatalogue();
const deny = loadDeny();
function env(p: CasePolicy, o: Partial<PolicyEnv> & { found?: string[] } = {}): PolicyEnv {
  return {
    policy: p,
    catalogue,
    deny,
    lead: async () => ({ exists: true, open: true, holder: "a1", generation: 1 }),
    evidence: async (_refs, values) => ({ found: new Map(values.filter((v) => (o.found ?? []).includes(v)).map((v) => [v, "input:x"])), unreadable: [], bounded: [] }),
    sensitive: async () => [],
    keys: new Set(),
    jobs: true,
    usage: { grants_in_force: 0, requests_in_window: 0, run_grants: 0 },
    ...o,
  };
}
const seat = { kind: "seat" as const, id: "a1", authenticated: true };
const req = (x: Partial<NetRequestInput>): NetRequestInput => ({ lead: "L-1", purpose: "a lookup", evidence: ["input:x"], ...x });
const codes = (d: { reasons: Array<{ code: string }> }) => d.reasons.map((r) => r.code);

/** Every file under a directory, relative, recursively. */
function files(dir: string): string[] {
  const out: string[] = [];
  const walk = (rel: string) => {
    for (const e of readdirSync(join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(r);
      else out.push(r);
    }
  };
  if (existsSync(dir)) walk("");
  return out;
}

// --- 1 -------------------------------------------------------------------------------------------

test("1: a value the run marked sensitive does not leave inside a longer one, and an encoded credential is decoded before it is judged", async () => {
  const std = policy({ network: "dynamic" });
  const inside = await evaluate(req({ adapter: "rdap_domain", params: { domain: "purpleelephant42.example.org" } }), seat, env(std, { sensitive: async () => ["The vault's passphrase is PurpleElephant42, found in the keychain"] }));
  assert.equal(inside.decision, "denied");
  assert.ok(codes(inside).includes("sensitive_value"), JSON.stringify(inside.reasons));
  const ctf = policy({ policy: "ctf", network: "dynamic" });
  const url = "https://short.example.org/cb?x=sk-%70roj-abcdefghijklmnopqrstu";
  const enc = await evaluate(req({ adapter: "http_head", params: { url } }), seat, env(ctf, { found: [url] }));
  assert.equal(enc.decision, "denied");
  assert.ok(codes(enc).includes("credential_pattern"), JSON.stringify(enc.reasons));
  const path = "https://short.example.org/eyJhbGciOiJIUzI1NiJ9%2EeyJzdWIiOiIxMjM0NTY3ODkwIn0%2Eabcdefghij";
  const enc2 = await evaluate(req({ adapter: "http_head", params: { url: path } }), seat, env(ctf, { found: [path] }));
  assert.ok(codes(enc2).includes("credential_pattern"), JSON.stringify(enc2.reasons));
  // An ordinary word in a sensitive sentence is not a value: a lookup of an unrelated domain still goes.
  const plain = await evaluate(req({ adapter: "rdap_domain", params: { domain: "account.example.org" } }), seat, env(std, { sensitive: async () => ["The account password is PurpleElephant42"] }));
  assert.equal(plain.decision, "granted", JSON.stringify(plain.reasons));
});

// --- 2 -------------------------------------------------------------------------------------------

test("2: bytes that were not delivered (a partial body, a filtered adapter's broken answer) are kept outside the run, where no seat reads them", async (t) => {
  if (await skipWithoutTls(t)) return;
  const broken: Handler = (_req, res) => {
    res.writeHead(200, { "content-type": "application/json", "content-length": "400" });
    res.write('{"title":"A title","author_name":"the uploader, never to be delivered"');
    setTimeout(() => res.socket?.destroy(), 50);
  };
  const s = await setup({ route: (h) => (h === "www.youtube.com" || h === "slow.test" ? broken : null) });
  const g = await grant(s, { adapter: "youtube_oembed", url: "https://www.youtube.com/oembed?url=x", host: "www.youtube.com", path: "/oembed?url=x", response_fields: ["title"] });
  const a = await use(s, "seat:a1", { grant: g });
  assert.equal(a.delivered, false);
  const store = join(s.S, "store", "net", "1", "1");
  for (const f of files(store)) assert.doesNotMatch(await readFile(join(store, f), "utf8"), /uploader/, `store/net/1/1/${f} holds undelivered bytes`);
  assert.ok(files(join(rawDir(s.S), "1", "1")).some((f) => /partial/.test(f)), "the partial bytes are kept beside the run");
  // An unfiltered adapter's partial body likewise.
  const g2 = await grant(s, { url: "https://slow.test/x", host: "slow.test", path: "/x" });
  await use(s, "seat:a1", { grant: g2 });
  const store2 = join(s.S, "store", "net", "2", "1");
  for (const f of files(store2)) assert.doesNotMatch(await readFile(join(store2, f), "utf8"), /uploader/, `store/net/2/1/${f} holds undelivered bytes`);
  const cap = JSON.parse(await readFile(join(store2, "capture.json"), "utf8"));
  const partial = (cap.kept as Array<{ name: string; bytes: number; sha256: string }>).find((k) => k.name === "body.partial");
  assert.ok(partial && partial.bytes > 0 && /^[0-9a-f]{64}$/.test(partial.sha256), "the run records the partial bytes' size and hash");
});

// --- 3 -------------------------------------------------------------------------------------------

test("3: the evidence link reads source bytes, never an agent's own prose or a value its job was told to write", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route: () => null });
  const url = "https://c2.example.org/beacon";
  // A finding that only asserts the URL: prose, not evidence.
  const f = await P.recordEntry({ sandboxRoot: s.S, agentId: "a1" }, { kind: "finding", value: `The chat log points to ${url}`, source: "chat.db", evidence: "row 12", refs: ["unresolved:asserted"], confidence: "low", basis: "observed", indicates: "A pointer.", confidence_why: "Asserted." });
  assert.equal(f.ok, true, (f as { reason?: string }).reason);
  if (!f.ok) return;
  assert.equal((await evidenceCheck(s.S, [`E-${f.entry.seq}`], [url])).found.has(url), false, "an entry's own words authorised a disclosure");
  // A job whose own command wrote the value: authored, not derived.
  const mkJob = async (id: string, spec: Record<string, unknown>, out: string) => {
    const dir = join(s.S, "store", "jobs", id);
    await mkdir(join(dir, "out"), { recursive: true });
    await writeFile(join(dir, "out", "o.txt"), out);
    await writeFile(join(dir, "manifest.json"), JSON.stringify({ v: 1, job: id, attempt: 1, sealed_at: "x", files: [{ path: "o.txt", path_b64: Buffer.from("o.txt").toString("base64"), bytes: out.length, sha256: P.sha256Hex(out), mode: "0444" }], dirs: [], rejected: [], totals: { files: 1, bytes: out.length } }));
    await writeFile(join(dir, "job.json"), JSON.stringify({ id, attempt: 1, state: "committed", status: "ok", requester: { agent: "a1" }, spec }));
  };
  await mkJob("j000001", { kind: "command", command: `echo ${url} > $OUT/o.txt`, inputs: ["input:chat.db"], scope: "declared" }, `${url}\n`);
  assert.equal((await evidenceCheck(s.S, ["job:j000001/o.txt"], [url])).found.has(url), false, "a value the job's command wrote was taken as evidence");
  // A job that read only an agent's own scratch derived nothing from the evidence.
  await mkJob("j000002", { kind: "command", command: "cat work/a1/notes > $OUT/o.txt", inputs: ["work/a1/notes"], scope: "declared" }, `${url}\n`);
  assert.equal((await evidenceCheck(s.S, ["job:j000002/o.txt"], [url])).found.has(url), false, "a job over an agent's scratch was taken as evidence");
  // A job that parsed the evidence: its output is derivation, and counts.
  await mkJob("j000003", { kind: "command", command: "sqlite3 inputs/chat.db 'select body from m' > $OUT/o.txt", inputs: ["input:chat.db"], scope: "declared" }, `${url}\n`);
  assert.equal((await evidenceCheck(s.S, ["job:j000003/o.txt"], [url])).found.get(url), "job:j000003/o.txt");
  // An entry citing that job: its refs count, its words still do not.
  const g = await P.recordEntry({ sandboxRoot: s.S, agentId: "a1" }, { kind: "finding", value: "The chat log names a URL", source: "chat.db", evidence: "row 12", refs: ["job:j000003/o.txt"], confidence: "high", basis: "observed", indicates: "A pointer.", confidence_why: "Parsed." });
  assert.equal(g.ok, true, (g as { reason?: string }).reason);
  if (g.ok) assert.equal((await evidenceCheck(s.S, [`E-${g.entry.seq}`], [url])).found.has(url), true);
});

// --- 4 -------------------------------------------------------------------------------------------

test("4: a strict preset holds the run's whole direct egress, the package index and a pack's hosts included", async () => {
  const { egressConflicts } = await import("../scripts/case-policy.ts");
  for (const preset of ["ctf", "internal", "live_adversary"]) {
    const p = preset === "internal" ? policy({ policy: "internal" }) : policy({ policy: preset, network: "dynamic" });
    assert.equal(egressConflicts(p, { installHosts: ["pypi.org", "files.pythonhosted.org"] }).length, 1, preset);
    assert.equal(egressConflicts(p, { packHosts: ["api.vendor.example"] }).length, 1, preset);
    assert.deepEqual(egressConflicts(p, {}), [], preset);
  }
  assert.deepEqual(egressConflicts(policy({ network: "dynamic" }), { installHosts: ["pypi.org"], allowHosts: ["x.example.org"], packHosts: ["api.vendor.example"] }), []);
});

// --- 5 -------------------------------------------------------------------------------------------

test("5: a grant that expires during DNS or a rate wait, or is revoked before the answer is published, sends and delivers nothing", async (t) => {
  if (await skipWithoutTls(t)) return;
  let clock = Date.now();
  const s = await setup({ route: () => json({ ok: 1 }), resolveMap: { "late.test": () => { clock += 10 * 60_000; return ["127.0.0.1"]; } } });
  const svc = new FetchService(s.config, { quiet: true, ca: (await testCert())!.cert, resolve: async (h) => (h === "late.test" ? ((clock += 10 * 60_000), ["127.0.0.1"]) : ["127.0.0.1"]), addressAllowed: () => true, connectPort: () => s.mock.port, now: () => clock });
  const late = await grant(s, { url: "https://late.test/x", host: "late.test", path: "/x" });
  const r = await svc.fetch("seat:a1", token(s, "seat:a1"), { grant: late });
  assert.equal(r.delivered ?? false, false);
  assert.equal(r.code, "expired", JSON.stringify(r));
  assert.equal(s.mock.seen.length, 0, "a request left after its grant expired");
  // Revoked while it waits for the adapter's interval.
  const first = await grant(s, { rate: { min_interval_ms: 800 } });
  const second = await grant(s, { rate: { min_interval_ms: 800 } });
  assert.equal((await use(s, "seat:a1", { grant: first })).ok, true);
  const pending = use(s, "seat:a1", { grant: second });
  await new Promise((res) => setTimeout(res, 200));
  await operatorRevoke(s.S, second, "no longer needed");
  const w = await pending;
  assert.equal(w.code, "revoked", JSON.stringify(w));
  assert.equal(s.mock.seen.length, 1);
});

test("5b: an answer that arrives after its grant was revoked is not published, whatever the transfer's own checks saw", async (t) => {
  if (await skipWithoutTls(t)) return;
  const slow: Handler = (_req, res) => setTimeout(() => json({ late: true })(_req, res), 500);
  const s = await setup({ route: () => slow });
  const svc = new FetchService({ ...s.config, limits: { recheck_ms: 60_000 } }, { quiet: true, ca: (await testCert())!.cert, resolve: async () => ["127.0.0.1"], addressAllowed: () => true, connectPort: () => s.mock.port });
  const g = await grant(s, {});
  const pending = svc.fetch("seat:a1", principalToken(s.config.secret, "seat:a1"), { grant: g });
  await new Promise((res) => setTimeout(res, 200));
  await operatorRevoke(s.S, g, "stop");
  const a = await pending;
  assert.equal(a.delivered, false, JSON.stringify(a));
  assert.equal(a.code, "revoked");
  assert.equal(existsSync(join(s.S, "store", "net", "1", "1", "body")), false);
});

// --- 6 -------------------------------------------------------------------------------------------

test("6: a revoked socket grant takes its host away in every spelling, and the grant decides over a note's line", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route: () => null });
  for (const host of ["EXAMPLE.org", "example.org:443", "example.org."]) await appendFile(join(s.S, L.OPERATOR_HOSTS), `${JSON.stringify({ at: new Date().toISOString(), host, lead: "L-1", by: "operator" })}\n`);
  const g = await operatorSocket(s.S, { host: "Example.ORG", why: "the client needs it" });
  assert.equal(g.ok, true);
  if (!g.ok) return;
  assert.equal((await operatorRevoke(s.S, g.grant as string, "done with it")).ok, true);
  const svc = new JobService({ sandbox: s.S, run: "n1", image: "img", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker: async () => ({ code: 0, fenced: true }), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  t.after(() => svc.stop("over"));
  const job: JobRecord = { id: "j000009", attempt: 1, spec: { kind: "command", command: "true", inputs: [], scope: "declared", network: "allowlist", timeout_seconds: 60 }, requester: { agent: "a1" }, state: "accepted", accepted_at: new Date().toISOString() };
  const plan = await svc.workerSpecFor(job, join(`${s.S}.staging`, "j000009-1"));
  assert.deepEqual(plan.spec.network, { mode: "off" }, `the next worker still reaches ${JSON.stringify(plan.spec.network)}`);
});

// --- 7 -------------------------------------------------------------------------------------------

test("7: a fetch whose result line cannot be written is not published, and an attempt with no outcome fails custody until reconciled", async (t) => {
  if (await skipWithoutTls(t)) return;
  let S = "";
  const s = await setup({
    route: () => (req, res) => {
      // The log turns unwritable while the request is out: the attempt line is there, the result cannot follow.
      void chmod(join(S, FETCH_LOG), 0o444).then(() => json({ ldhName: "EXAMPLE.ORG" })(req, res));
    },
  });
  S = s.S;
  const g = await grant(s, {});
  const a = await use(s, "seat:a1", { grant: g });
  assert.equal(a.ok, false, JSON.stringify(a));
  assert.equal(a.delivered ?? false, false);
  assert.equal(a.code, "audit_unavailable");
  for (const f of files(join(s.S, "store", "net"))) assert.notEqual(f.split("/").at(-1), "body", `${f} was published without its result`);
  await chmod(join(s.S, FETCH_LOG), 0o644);
  const before = await checkNetwork(s.S);
  assert.equal(before?.check.fetches.unresolved?.length, 1, JSON.stringify(before?.check));
  // A fetch service that starts again gives the attempt its outcome, and custody holds.
  const again = new FetchService(s.config, { quiet: true });
  await again.reconcile();
  const after = await checkNetwork(s.S);
  assert.deepEqual(after?.check.fetches.unresolved, []);
  const st = await readNetState(s.S);
  assert.equal(st.fetches.get(g)?.[0].result?.delivered, false);
});

// --- 8 -------------------------------------------------------------------------------------------

test("8: concurrent requests cannot pass the grant quota, and concurrent fetches keep the adapter's interval", async (t) => {
  if (await skipWithoutTls(t)) return;
  const at: number[] = [];
  const s = await setup({ route: () => (req, res) => { at.push(Date.now()); json({ ok: 1 })(req, res); } });
  const answers = await Promise.all(Array.from({ length: 10 }, (_, i) => requestAccess(s.S, "a1", { lead: "L-1", adapter: "rdap_domain", params: { domain: `d${i}.example.org` }, purpose: "many at once" }, { jobs: true })));
  const granted = answers.filter((a) => a.ok).length;
  assert.ok(granted <= 8, `${granted} grants in force at once`);
  assert.ok(answers.some((a) => !a.ok && a.reasons.some((r) => r.code === "quota_grants_in_force")));
  const g1 = await grant(s, { rate: { min_interval_ms: 600 } });
  const g2 = await grant(s, { rate: { min_interval_ms: 600 } });
  const both = await Promise.all([use(s, "seat:a1", { grant: g1 }), use(s, "seat:a1", { grant: g2 })]);
  assert.ok(both.every((b) => b.ok), JSON.stringify(both));
  assert.equal(at.length, 2);
  assert.ok(Math.abs(at[1] - at[0]) >= 550, `two requests ${Math.abs(at[1] - at[0])} ms apart under a 600 ms interval`);
});

// --- 9 -------------------------------------------------------------------------------------------

test("9: external lineage follows what a job resolved, not how it was spelled: a store path, a broad scope, a digest", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route: () => json({ ldhName: "EXAMPLE.ORG" }) });
  const g = await grant(s, {});
  assert.equal((await use(s, "seat:a1", { grant: g })).ok, true);
  const later = new Date(Date.now() + 1000).toISOString();
  const journal = join(s.S, "store", "journal.jsonl");
  await appendFile(journal, `${JSON.stringify({ v: 1, seq: 0, at: later, type: "job_started", job: "j000001", declared: ["store/net/1/1/body"], scope: { kind: "declared" } })}\n`);
  await appendFile(journal, `${JSON.stringify({ v: 1, seq: 1, at: later, type: "job_started", job: "j000002", declared: [], scope: { kind: "default-all" } })}\n`);
  await appendFile(journal, `${JSON.stringify({ v: 1, seq: 2, at: new Date(Date.now() - 3_600_000).toISOString(), type: "job_started", job: "j000003", declared: [], scope: { kind: "default-all" } })}\n`);
  // A copy of the capture's body, stored by content: the same bytes, another name.
  const body = await readFile(join(s.S, "store", "net", "1", "1", "body"));
  await mkdir(join(s.S, "store", "blobs"), { recursive: true });
  await copyFile(join(s.S, "store", "net", "1", "1", "body"), join(s.S, "store", "blobs", P.sha256Hex(body)));
  const e = await P.recordEntry({ sandboxRoot: s.S, agentId: "a1" }, { kind: "finding", value: "The registrant record, by its content", source: "rdap", evidence: "blob", refs: [`sha256:${P.sha256Hex(body)}`], confidence: "medium", basis: "observed", indicates: "A record.", confidence_why: "Third party." });
  assert.equal(e.ok, true, (e as { reason?: string }).reason);
  const lin = await externalLineage(s.S);
  assert.ok(lin.jobs.has("j000001"), "a job that declared the capture by its store path");
  assert.ok(lin.jobs.has("j000002"), "a job whose broad scope could read the capture");
  assert.ok(!lin.jobs.has("j000003"), "a broad job that started before any capture existed");
  if (e.ok) assert.ok(lin.entries.has(e.entry.seq), "an entry citing the capture's bytes by digest");
});

// --- 10 ------------------------------------------------------------------------------------------

test("10: the whole response of a filtered adapter is verified by custody, and its loss is named", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route: () => json({ title: "A title", author_name: "someone" }) });
  const g = await grant(s, { adapter: "youtube_oembed", url: "https://www.youtube.com/oembed?url=x", host: "www.youtube.com", path: "/oembed?url=x", response_fields: ["title"] });
  assert.equal((await use(s, "seat:a1", { grant: g })).ok, true);
  const clean = await checkNetwork(s.S);
  assert.equal(clean?.check.captures.verified, 1);
  assert.equal(clean?.check.captures.raw_verified, 1);
  const raw = join(rawDir(s.S), "1", "1", "body");
  await chmod(raw, 0o644);
  await writeFile(raw, '{"title":"changed"}');
  assert.deepEqual((await checkNetwork(s.S))?.check.captures.mismatched, ["net:1/1 (the whole response beside the run)"]);
  await rm(raw);
  assert.deepEqual((await checkNetwork(s.S))?.check.captures.missing, ["net:1/1 (the whole response beside the run)"]);
});

// --- 11 ------------------------------------------------------------------------------------------

test("11: an IPv6 address is classified by its bytes, whatever its spelling", () => {
  for (const ip of ["64:ff9b::a00:1", "0064:ff9b::a00:1", "0064:ff9b:0000:0000:0000:0000:0a00:0001", "64:ff9b:1::1", "::ffff:0a00:0001", "::ffff:10.0.0.1", "0:0:0:0:0:ffff:7f00:1", "2002:0a00:0001::1", "2001:0000:4136:e378::1", "2001:0db8::1", "3fff::1", "100::1", "fe80:0000::1", "FC00::1", "::", "::1", "0000:0000:0000:0000:0000:0000:0000:0001", "ff02::1"]) {
    assert.equal(publicAddress(ip), false, ip);
  }
  for (const ip of ["2606:4700::1111", "2a00:1450:4001:80b::200e", "2606:4700:0000:0000:0000:0000:0000:1111"]) assert.equal(publicAddress(ip), true, ip);
  const c = checkValue("ip", { type: "ip" }, "0064:ff9b::a00:1");
  assert.ok(c.ok && c.classes.includes("internal_name"), JSON.stringify(c));
});

// --- 12 ------------------------------------------------------------------------------------------

test("12: an oversize redirect is refused whole, never followed, and its size is kept", async (t) => {
  if (await skipWithoutTls(t)) return;
  const big = "x".repeat(200 * 1024);
  const s = await setup({
    route: (h) =>
      h === "rdap.org"
        ? (_req, res) => {
            res.writeHead(302, { location: "https://rdap.verisign.com/com/v1/domain/EXAMPLE.ORG", "content-type": "text/plain", "content-length": String(big.length) });
            res.end(big);
          }
        : h === "rdap.verisign.com"
          ? json({ ldhName: "EXAMPLE.ORG" })
          : null,
  });
  const g = await grant(s, { max_bytes: 64 * 1024, redirects: { follow: "referral", max: 3, hosts: ["rdap.verisign.com"] } });
  const a = await use(s, "seat:a1", { grant: g });
  assert.equal(a.ok, false, JSON.stringify(a));
  assert.equal(a.code, "oversize");
  assert.ok(!s.mock.seen.some((x) => x.host === "rdap.verisign.com"), "the oversize redirect was followed");
  const resp = JSON.parse(await readFile(join(s.S, "store", "net", "1", "1", "response.json"), "utf8"));
  assert.equal(resp.oversize.declared, big.length);
  assert.equal(resp.complete, false);
});
