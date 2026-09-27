/**
 * Custody after Fable's and Codex's reading of the recorded verdicts: every
 * check says its status, so an omitted or failed one never reads as a quiet
 * pass; the verdict seals each chain's length and head, and a re-check names
 * what was written after the seal; the operator's audit is chained and
 * matched to the trace; acquisition hashes are held to the evidence; a
 * read-only verify writes nothing; the verdict can be signed and timestamped,
 * and a reference clock's offset recorded.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { appendFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { custodyAnchorPath, takeCustody, verdictOf, verifyCustody, type Custody } from "../scripts/custody.ts";
import { afterSeal, checksOf, parseAcquisitionHashes, readTimestampResponse, timestampRequest, verifySignature } from "../scripts/custody-checks.ts";
import { ledgerHash, type LedgerEntry } from "../extensions/protocol.ts";
import { readCustody } from "../scripts/ui/model.ts";
import { renderReport } from "../scripts/report.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    // A store leaves its sealed directories read-only.
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const md5 = (s: string) => createHash("md5").update(s).digest("hex");

/** Trace lines chained as the collector writes them: each names the sha256 of the line before (the first, ""). */
function chained(objs: unknown[], after = ""): string {
  let prev = after;
  let out = "";
  for (const o of objs) {
    const line = JSON.stringify({ ...(o as Record<string, unknown>), prev });
    out += `${line}\n`;
    prev = sha(line);
  }
  return out;
}

async function appendChained(file: string, objs: unknown[]): Promise<void> {
  const last = (await readFile(file, "utf8")).trim().split("\n").at(-1) ?? "";
  await appendFile(file, chained(objs, last ? sha(last) : ""));
}

/** A run with two evidence files, a trace, and its runs directory holding the operator's audit. */
async function run(extra: { acquisition?: unknown; traceLines?: unknown[] } = {}): Promise<{ root: string; runs: string }> {
  const runs = await mkdtemp(join(tmpdir(), "custody-seal-runs-"));
  dirs.push(runs);
  const root = join(runs, "s1");
  await mkdir(join(root, "inputs"), { recursive: true });
  await writeFile(join(root, "inputs", "disk.E01"), "disk bytes\n");
  await writeFile(join(root, "inputs", "notes.txt"), "notes\n");
  await writeFile(
    join(root, "inputs.json"),
    JSON.stringify({
      source: "/evidence",
      bytes: 17,
      // A copy: inputs/ is the run's own directory (held in place, it would be a link to /evidence).
      held: "copy",
      files: [
        { path: "inputs/disk.E01", bytes: 11, sha256: sha("disk bytes\n"), md5: md5("disk bytes\n") },
        { path: "inputs/notes.txt", bytes: 6, sha256: sha("notes\n") },
      ],
      ...(extra.acquisition ? { acquisition: extra.acquisition } : {}),
    }),
  );
  await mkdir(join(root, "traces"), { recursive: true });
  const lines = extra.traceLines ?? [{ ts: "2026-09-26T10:00:00Z", agent: "a0", tool: "bash", args: {}, result: { ok: true } }];
  await writeFile(join(root, "traces", "events.jsonl"), chained(lines));
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "s1", started_at: "2026-09-26T10:00:00Z" }));
  return { root, runs };
}

/** Lines of the operator's audit, chained as swarm.sh writes them. */
async function audit(runs: string, lines: Array<Record<string, unknown>>): Promise<void> {
  let prev: string | null = null;
  let text = "";
  for (const l of lines) {
    const line = JSON.stringify({ ...l, prev });
    text += `${line}\n`;
    prev = sha(line);
  }
  await writeFile(join(runs, "operator-audit.jsonl"), text);
}

test("every check says its status, and the summary says the evidence is unchanged since the run began", async () => {
  const { root, runs } = await run();
  const c = await takeCustody(root, { runsDir: runs });
  const status = Object.fromEntries(c.checks.map((x) => [x.name, x.status]));
  assert.equal(status.evidence, "passed");
  assert.equal(status["acquisition hashes"], "not_applicable");
  assert.equal(status["store"], "not_applicable");
  assert.equal(status["operator audit"], "not_applicable");
  assert.match(c.summary, /evidence unchanged since the run began \(.*\); acquisition hashes not given \(--inputs-hashes\)/);
  assert.match(c.summary, /checks: \d+ passed, 0 failed, 0 incomplete, 0 unavailable/);
  assert.match(c.summary, /anchors are the operator's own files beside the run/);
  assert.ok(c.timing.total_ms >= 0 && "the evidence re-hash" in c.timing.phases, "the parts' durations are recorded");
  assert.equal(c.timing.evidence_bytes, 17);
  // A part that raised is unavailable, with why; never an absent part that reads as nothing wrong.
  const errored = checksOf({ ...c, store: null, not_reached: [] } as never, { store: "the journal could not be read (EIO)" });
  assert.deepEqual(errored.find((x) => x.name === "store"), { name: "store", status: "unavailable", reason: "the journal could not be read (EIO)" });
  const partial = verdictOf({ phase: "the trace", run: "s1", inputsDone: true, inputs: null, sessions: { files: [], digest: "d", not_files: [] } }, "ended");
  assert.equal(partial.checks.find((x) => x.name === "trace")?.status, "incomplete");
});

test("the acquisition hashes given at kickoff are held to the evidence as re-hashed, and a mismatch is said", async () => {
  const good = await run({ acquisition: { source: "imager.log", source_sha256: "a".repeat(64), entries: [{ path: "inputs/disk.E01", algo: "md5", digest: md5("disk bytes\n") }, { path: "inputs/notes.txt", algo: "sha256", digest: sha("notes\n") }] } });
  const c = await takeCustody(good.root, { runsDir: good.runs });
  assert.deepEqual(c.acquisition, { source: "imager.log", source_sha256: "a".repeat(64), given: 2, matched: 2, mismatched: [], not_compared: [] });
  assert.match(c.summary, /matches the acquisition hashes given \(2 of 2\)/);
  const bad = await run({ acquisition: { source: "imager.log", entries: [{ path: "inputs/disk.E01", algo: "md5", digest: "0".repeat(32) }, { path: "inputs/notes.txt", algo: "sha1", digest: "1".repeat(40) }] } });
  const b = await takeCustody(bad.root, { runsDir: bad.runs });
  assert.deepEqual(b.acquisition?.mismatched, ["inputs/disk.E01 (md5)"]);
  assert.deepEqual(b.acquisition?.not_compared, ["inputs/notes.txt (sha1)"], "a digest custody did not compute is not compared, and said");
  assert.equal(b.checks.find((x) => x.name === "acquisition hashes")?.status, "failed");
  assert.match(b.summary, /DOES NOT MATCH THE ACQUISITION HASHES GIVEN: inputs\/disk\.E01 \(md5\)/);
});

test("an imager's hash list is read in the shapes imagers write, matched to the inputs by path or unique name", () => {
  const inputs = ["inputs/disk.E01", "inputs/mem/memdump.mem", "inputs/a/x.bin", "inputs/b/x.bin"];
  const text = [
    "# acquired 2026-09-01",
    `${"a".repeat(32)}  disk.E01`,
    `SHA256 (mem/memdump.mem) = ${"b".repeat(64)}`,
    `memdump.mem ${"c".repeat(40)}`,
    `${"d".repeat(64)} *x.bin`,
    `${"e".repeat(64)}  other.E01`,
    "Case number: 42",
  ].join("\n");
  const r = parseAcquisitionHashes(text, inputs);
  assert.deepEqual(r.entries, [
    { path: "inputs/disk.E01", algo: "md5", digest: "a".repeat(32) },
    { path: "inputs/mem/memdump.mem", algo: "sha256", digest: "b".repeat(64) },
    { path: "inputs/mem/memdump.mem", algo: "sha1", digest: "c".repeat(40) },
  ]);
  assert.deepEqual(r.unmatched, ["*x.bin", "other.E01"], "an ambiguous name and one not among the inputs are named");
  assert.equal(r.ignored, 1);
});

test("the operator's audit is chained and each operator line on the trace is on it", async () => {
  const stopLine = { ts: "2026-09-26T10:05:00Z", recv_ts: "2026-09-26T10:05:00Z", agent: "system", tool: "operator_action", args: { command: "stop", argv: ["s1"] }, result: {}, agent_unverified: true };
  const { root, runs } = await run({ traceLines: [{ ts: "2026-09-26T10:00:00Z", agent: "a0", tool: "bash", args: {}, result: {} }, stopLine] });
  await audit(runs, [
    { at: "2026-09-26T10:00:00Z", command: "start", argv: ["--n", "1"], cwd: "/", os_user: "h", host: "m", via: "cli" },
    { at: "2026-09-26T10:05:01Z", command: "stop", argv: ["s1"], cwd: "/", os_user: "h", host: "m", via: "cli" },
  ]);
  const c = await takeCustody(root, { runsDir: runs });
  assert.equal(c.operator?.intact, true);
  assert.equal(c.operator?.matched, 1);
  assert.equal(c.checks.find((x) => x.name === "operator audit")?.status, "passed");
  assert.match(c.summary, /1 operator action from a shell outside the run, each on the operator audit/);
  // An audit line changed afterwards breaks its chain; a trace action it does not carry is named.
  const text = await readFile(join(runs, "operator-audit.jsonl"), "utf8");
  await writeFile(join(runs, "operator-audit.jsonl"), text.replace('"argv":["--n","1"]', '"argv":["--n","9"]'));
  await appendChained(join(root, "traces", "events.jsonl"), [{ ...stopLine, args: { command: "say", argv: ["s1", "hello"] } }]);
  const d = await takeCustody(root, { runsDir: runs });
  assert.equal(d.operator?.intact, false);
  assert.equal(d.operator?.unmatched.length, 1);
  assert.equal(d.checks.find((x) => x.name === "operator audit")?.status, "failed");
  assert.match(d.summary, /OPERATOR AUDIT CHAIN BROKEN/);
});

test("a read-only check writes nothing; verify holds the run to the sealed prefix and names the closing lines after it", async () => {
  const { root, runs } = await run();
  const anchorBefore = await readFile(custodyAnchorPath(root), "utf8");
  const ro = await takeCustody(root, { readOnly: true, runsDir: runs });
  assert.ok(ro.checks.length);
  assert.equal(existsSync(join(root, "custody.json")), false, "no verdict written");
  assert.equal(existsSync(join(root, "artifacts.json")), false, "no index written");
  assert.equal(await readFile(custodyAnchorPath(root), "utf8"), anchorBefore, "the anchor is untouched");
  const c = await takeCustody(root, { runsDir: runs });
  assert.equal(c.seal.trace.lines, 1);
  // The hub's own lines after custody, and the operator's stop: expected, and named.
  const closing = [
    { ts: "2026-09-26T10:06:00Z", agent: "system", tool: "custody", args: { via: "hub" }, result: { ok: true } },
    { ts: "2026-09-26T10:06:00Z", agent: "system", tool: "hub_clear_up", args: {}, result: { ok: true } },
    { ts: "2026-09-26T10:06:01Z", agent: "system", tool: "operator_action", args: { command: "stop", argv: ["s1", "--after-hub"] }, result: {}, agent_unverified: true },
  ];
  await appendChained(join(root, "traces", "events.jsonl"), closing);
  const v = await verifyCustody(root, { runsDir: runs });
  assert.equal(v.prefix.intact, true, v.prefix.detail);
  assert.deepEqual(v.after_seal, { lines: 3, tools: ["custody", "hub_clear_up", "operator_action:stop"], closure_only: true });
  assert.equal(v.verdict.anchor, "matches the verdict anchored outside the run");
  assert.equal(v.ok, true, JSON.stringify(v, null, 1));
  // A sealed line changed afterwards is found; so is a line after the seal that is not a closing one.
  const text = await readFile(join(root, "traces", "events.jsonl"), "utf8");
  await writeFile(join(root, "traces", "events.jsonl"), text.replace('"tool":"bash"', '"tool":"record"'));
  await appendChained(join(root, "traces", "events.jsonl"), [{ ts: "t", agent: "a0", tool: "record", args: {}, result: {} }]);
  const w = await verifyCustody(root, { runsDir: runs });
  assert.equal(w.prefix.intact, false);
  assert.match(w.prefix.detail, /THE SEALED PREFIX CHANGED/);
  assert.equal(w.after_seal.closure_only, false);
  assert.equal(w.ok, false);
  assert.deepEqual(afterSeal('{"tool":"custody"}\n{"tool":"bash"}\n', 1), { lines: 1, tools: ["bash"], closure_only: false });
});

test("the verdict is signed with an SSH key and timestamped by an RFC 3161 authority; a reference clock's offset is recorded; verify checks them", async () => {
  const { root, runs } = await run();
  const keyDir = await mkdtemp(join(tmpdir(), "custody-key-"));
  dirs.push(keyDir);
  const key = join(keyDir, "id");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "examiner@lab", "-f", key]);
  // A stand-in authority: a granted response that carries the digest asked for and a time.
  const genTime = Buffer.from("20260926120000Z", "latin1");
  const server: Server = createServer((req, res) => {
    if (req.method === "HEAD") {
      res.writeHead(200, { date: new Date(Date.now() + 5_000).toUTCString() });
      res.end();
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const at = body.indexOf(Buffer.from([0x04, 0x20]));
      const digest = body.subarray(at + 2, at + 34);
      const status = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
      const token = Buffer.concat([Buffer.from([0x04, 0x20]), digest, Buffer.from([0x18, genTime.length]), genTime]);
      const resp = Buffer.concat([Buffer.from([0x30, status.length + token.length]), status, token]);
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(resp);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/tsa`;
  try {
    const c = await takeCustody(root, { runsDir: runs, signKey: key, timestampUrl: url, timeReference: url });
    assert.ok(c.time_reference && c.time_reference.offset_ms !== null && c.time_reference.offset_ms >= 3000 && c.time_reference.offset_ms <= 7000, JSON.stringify(c.time_reference));
    assert.match(c.summary, /the host's clock behind http:\/\/127\.0\.0\.1:\d+\/tsa by \d+ ms/);
    assert.ok(existsSync(join(root, "custody.json.sig")));
    assert.ok(existsSync(join(root, "custody.json.tsr")));
    const anchor = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as { custody: Array<{ signature?: { sha256?: string }; timestamp?: { gen_time?: string; signature?: unknown }; seal?: unknown }> };
    const last = anchor.custody.at(-1);
    assert.match(String(last?.signature?.sha256), /^[0-9a-f]{64}$/);
    assert.equal(last?.timestamp?.gen_time, "2026-09-26T12:00:00Z");
    assert.ok(last?.seal, "the seal is in the anchor too");
    const sig = await verifySignature(join(root, "custody.json"), join(root, "custody.json.sig"));
    assert.equal(sig.ok, true, sig.detail);
    // The console and the report read all of it.
    const view = await readCustody(root);
    assert.ok(view?.checks?.some((x) => x.name === "evidence" && x.status === "passed"));
    assert.equal(view?.seal?.trace.lines, 1);
    assert.match(String(view?.signature?.key), /SHA256:/);
    assert.equal(view?.timestamp?.gen_time, "2026-09-26T12:00:00Z");
    assert.ok(view?.time_reference?.custody && view.time_reference.custody.offset_ms !== null);
    const html = await renderReport(root, { runsDir: runs });
    for (const row of ["Custody checks", "Sealed", "Acquisition hashes", "Verdict signature", "Trusted timestamp", "Reference clock", "Check it again", "What the anchors are"]) assert.match(html, new RegExp(`<td>${row}</td>`), row);
    assert.match(html, /custody\.json\.tsr from http:\/\/127\.0\.0\.1:\d+\/tsa, 2026-09-26T12:00:00Z/);
    const v = await verifyCustody(root, { runsDir: runs });
    assert.equal(v.signature.ok, true);
    assert.equal(v.timestamp.imprint, true);
    // No CA was named: the token is held to the digest only, and says so.
    assert.equal(v.timestamp.signature?.verified, null);
    assert.match(v.timestamp.note, /imprint only, signature not verified/);
    assert.equal((last?.timestamp as { signature?: { verified?: unknown; detail?: string } } | undefined)?.signature?.verified, null);
    assert.equal(v.ok, true, JSON.stringify(v, null, 1));
    // Given a CA, a token that is not the authority's signature does not verify, and the check fails.
    if (opensslTs()) {
      const pki = await testPki();
      const withCa = await verifyCustody(root, { runsDir: runs, tsaCa: pki.ca });
      assert.equal(withCa.timestamp.signature?.verified, false, withCa.timestamp.note);
      assert.match(withCa.timestamp.note, /DOES NOT VERIFY/);
      assert.equal(withCa.ok, false);
    }
    // An edited verdict: the signature no longer holds, nor does the anchor or the token.
    const text = await readFile(join(root, "custody.json"), "utf8");
    await writeFile(join(root, "custody.json"), text.replace('"run": "s1"', '"run": "s2"'));
    const edited = await verifyCustody(root, { runsDir: runs });
    assert.equal(edited.signature.ok, false);
    assert.equal(edited.timestamp.imprint, false);
    assert.equal(edited.ok, false);
  } finally {
    server.close();
  }
});

test("a timestamp request is DER for sha256, and a response is read for its status, digest and time", () => {
  const digest = sha("x");
  const req = timestampRequest(digest, Buffer.from([1, 2, 3, 4]));
  assert.equal(req[0], 0x30);
  assert.ok(req.includes(Buffer.from(digest, "hex")));
  assert.ok(req.includes(Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])), "the sha256 OID");
  const refused = Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]);
  assert.deepEqual(readTimestampResponse(refused, digest), { granted: false, status: 2, imprint: false, gen_time: null });
});

test("custody's CLI exits 4 when a check does not pass, 0 when all do", async () => {
  const { root, runs } = await run();
  const cli = (r: string) => {
    try {
      execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "custody.ts"), r, "--quiet", "--runs-dir", runs], { stdio: "pipe" });
      return 0;
    } catch (err) {
      return (err as { status: number }).status;
    }
  };
  assert.equal(cli(root), 0);
  await writeFile(join(root, "inputs", "notes.txt"), "changed\n");
  assert.equal(cli(root), 4, "the evidence changed: a verdict, and not a pass");
  const c = JSON.parse(await readFile(join(root, "custody.json"), "utf8")) as Custody;
  assert.equal(c.checks.find((x) => x.name === "evidence")?.status, "failed");
});

/** Whether this host's openssl has the ts command. */
function opensslTs(): boolean {
  const r = spawnSync("openssl", ["ts", "-help"], { encoding: "utf8" });
  return !r.error && /-verify|-reply/.test(`${r.stdout}${r.stderr}`);
}

/** A CA and a timestamping certificate it signed, and an openssl ts config for the authority: made for the test. */
async function testPki(): Promise<{ dir: string; ca: string; otherCa: string; reply: (query: Buffer) => Buffer }> {
  const dir = await mkdtemp(join(tmpdir(), "custody-tsa-"));
  dirs.push(dir);
  const ssl = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  for (const name of ["ca", "other"]) ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.pem`, "-days", "2", "-subj", `/CN=Test ${name}`, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr", "-subj", "/CN=Test TSA");
  await writeFile(join(dir, "ext.cnf"), "extendedKeyUsage=critical,timeStamping\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n");
  ssl("x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.pem", "-days", "2", "-extfile", "ext.cnf");
  await writeFile(join(dir, "serial"), "01\n");
  await writeFile(
    join(dir, "tsa.cnf"),
    `[ tsa ]\ndefault_tsa = tsa1\n[ tsa1 ]\nserial = ${join(dir, "serial")}\ncrypto_device = builtin\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n`,
  );
  let n = 0;
  const reply = (query: Buffer) => {
    n += 1;
    const q = join(dir, `q${n}.tsq`);
    const r = join(dir, `r${n}.tsr`);
    writeFileSync(q, query);
    ssl("ts", "-reply", "-config", "tsa.cnf", "-queryfile", q, "-signer", "tsa.pem", "-inkey", "tsa.key", "-out", r);
    return readFileSync(r);
  };
  return { dir, ca: join(dir, "ca.pem"), otherCa: join(dir, "other.pem"), reply };
}

/** A v3 ledger entry chained on `prev`, with the refs and provenance the hub records. */
function v3(seq: number, value: string, prev: string): LedgerEntry {
  const e: LedgerEntry = { v: 3, seq, kind: "finding", value, source: "inputs/notes.txt", evidence: "line 1", confidence: "high", refs: ["input:inputs/notes.txt"], by: "a0", authors: ["a0"], at: `2026-09-27T00:00:0${seq}Z` };
  e.prev = prev;
  e.hash = ledgerHash(e, prev);
  return e;
}

/** A finished run with a report, a note and a ledger entry the trace carries, and its custody taken. */
async function sealedRun(): Promise<{ root: string; runs: string; e1: LedgerEntry }> {
  const e1 = v3(1, "The notes were written on the host", "genesis");
  const { root, runs } = await run({ traceLines: [{ ts: "2026-09-26T10:00:00Z", agent: "a0", tool: "record", args: {}, result: { ok: true, seq: 1, hash: e1.hash } }] });
  await mkdir(join(root, "ledger"), { recursive: true });
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n`);
  await mkdir(join(root, "work", "a0"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "# Report\n\nThe notes were written on the host [#1].\n");
  await writeFile(join(root, "work", "a0", "notes.md"), "scratch\n");
  const c = await takeCustody(root, { runsDir: runs });
  assert.equal(c.artifacts?.files, 2);
  return { root, runs, e1 };
}

test("verify holds work/ to the index custody sealed: a report edited, a file removed or added after the stop is named, and fails", async () => {
  const { root, runs } = await sealedRun();
  const ok = await verifyCustody(root, { runsDir: runs });
  assert.equal(ok.work.index, "sealed");
  assert.match(ok.work.detail, /every one of the 2 files the sealed index names is as sealed, and none was added/);
  assert.equal(ok.ok, true, JSON.stringify(ok, null, 1));
  // The report edited after the stop: every check still passes (each file hashed), and the seal does not.
  const report = join(root, "work", "report.md");
  const text = await readFile(report, "utf8");
  await writeFile(report, text.replace("on the host", "somewhere else"));
  const edited = await verifyCustody(root, { runsDir: runs });
  assert.deepEqual(edited.changed, [], "no check's status moved: the verdict's statuses alone never saw this");
  assert.deepEqual(edited.work.drift?.changed, ["work/report.md"]);
  assert.match(edited.work.detail, /NOT AS SEALED: 1 CHANGED \(work\/report\.md\)/);
  assert.equal(edited.ok, false);
  await writeFile(report, text);
  // A file removed, and one added.
  await rm(join(root, "work", "a0", "notes.md"));
  await writeFile(join(root, "work", "late.md"), "written after the stop\n");
  const moved = await verifyCustody(root, { runsDir: runs });
  assert.deepEqual(moved.work.drift?.removed, ["work/a0/notes.md"]);
  assert.deepEqual(moved.work.drift?.added, ["work/late.md"]);
  assert.equal(moved.ok, false);
  await writeFile(join(root, "work", "a0", "notes.md"), "scratch\n");
  await rm(join(root, "work", "late.md"));
  assert.equal((await verifyCustody(root, { runsDir: runs })).ok, true, "as sealed again");
  // The index itself replaced: it is not the one the verdict and the anchor name.
  const index = await readFile(join(root, "artifacts.json"), "utf8");
  await writeFile(join(root, "artifacts.json"), index.replace(/"generated_at": "[^"]+"/, '"generated_at": "2030-01-01T00:00:00.000Z"'));
  const swapped = await verifyCustody(root, { runsDir: runs });
  assert.equal(swapped.work.index, "differs");
  assert.match(swapped.work.detail, /THE SEALED INDEX CANNOT BE HELD TO: artifacts\.json is not the index the verdict sealed/);
  assert.equal(swapped.ok, false);
  await writeFile(join(root, "artifacts.json"), index);
  // The CLI says it too, and exits 4.
  await writeFile(report, `${text}tampered\n`);
  let out = "";
  let code = 0;
  try {
    out = execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "custody.ts"), root, "--verify", "--runs-dir", runs], { encoding: "utf8" });
  } catch (err) {
    code = (err as { status: number }).status;
    out = String((err as { stdout: string }).stdout);
  }
  assert.equal(code, 4, out);
  assert.match(out, /^Work files:   NOT AS SEALED: 1 CHANGED \(work\/report\.md\)$/m);
});

test("verify holds every chain to the length and head sealed: an appended, correctly chained entry is named; examiner notes after the run are said and allowed", async () => {
  const { root, runs, e1 } = await sealedRun();
  // A second entry appended after the stop, chained correctly on the first.
  const e2 = v3(2, "An entry nobody recorded through the tool", e1.hash as string);
  await appendFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e2)}\n`);
  const v = await verifyCustody(root, { runsDir: runs });
  assert.deepEqual(v.seal_drift.map((d) => d.what), ["ledger"]);
  assert.equal(v.seal_drift[0].sealed, `1 entries, head ${e1.hash}`);
  assert.equal(v.seal_drift[0].now, `2 entries, head ${e2.hash}`);
  assert.ok(v.changed.some((x) => x.check === "ledger" && x.now === "failed"), "and the ledger is not on the trace (a version 3 entry)");
  assert.equal(v.ok, false);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n`);
  // An attestation appended.
  await writeFile(join(root, "ledger", "attestations.jsonl"), `${JSON.stringify({ seq: 1, by: "a1", at: "t", prev: "genesis", hash: "0".repeat(64) })}\n`);
  const a = await verifyCustody(root, { runsDir: runs });
  assert.ok(a.seal_drift.some((d) => d.what === "ledger attestations" && d.sealed === "0 lines, head none"), JSON.stringify(a.seal_drift));
  assert.equal(a.ok, false);
  await rm(join(root, "ledger", "attestations.jsonl"));
  assert.equal((await verifyCustody(root, { runsDir: runs })).ok, true);
});

test("the store journal: an examiner's note after the run is said and allowed; any other line after the seal is not", async () => {
  const { root, runs } = await sealedRun();
  const { initStore, appendNote } = await import("../scripts/evidence-store.ts");
  await initStore(root);
  // A journal custody sealed: custody taken again with the store there.
  await takeCustody(root, { runsDir: runs });
  const sealed = JSON.parse(await readFile(join(root, "custody.json"), "utf8")) as Custody;
  assert.ok(sealed.seal.journal && sealed.seal.journal.lines >= 1);
  assert.equal((await verifyCustody(root, { runsDir: runs })).ok, true);
  await appendNote(root, { by: "H. Examiner", text: "j000001's partial output is not relied on" });
  const noted = await verifyCustody(root, { runsDir: runs });
  assert.deepEqual(noted.seal_drift, []);
  assert.deepEqual(noted.seal_after, ["store journal: 1 examiner note(s) after the seal"]);
  // A line that is not a note, chained on correctly, is a drift.
  const journal = join(root, "store", "journal.jsonl");
  const lines = (await readFile(journal, "utf8")).trim().split("\n");
  const raw = JSON.stringify({ v: 1, seq: lines.length, at: "t", type: "job_committed", job: "j000009", prev: sha(lines.at(-1) as string) });
  await appendFile(journal, `${raw}\n`);
  const bad = await verifyCustody(root, { runsDir: runs });
  assert.ok(bad.seal_drift.some((d) => d.what === "store journal" && /after the sealed line: note, job_committed/.test(d.now)), JSON.stringify(bad.seal_drift));
  assert.equal(bad.ok, false);
});

test("a token's signature is checked against the authority's CA when one is named: verified, recorded in the anchor, and a token from another authority fails", { skip: !opensslTs() && "no openssl ts on this host" }, async () => {
  const { root, runs } = await run();
  const pki = await testPki();
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(pki.reply(Buffer.concat(chunks)));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/tsa`;
  try {
    await takeCustody(root, { runsDir: runs, timestampUrl: url, timestampCa: pki.ca });
    const anchor = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as { custody: Array<{ timestamp?: { signature?: { verified?: boolean | null; ca?: string; ca_sha256?: string; detail?: string } } }> };
    const recorded = anchor.custody.at(-1)?.timestamp?.signature;
    assert.equal(recorded?.verified, true, recorded?.detail);
    assert.equal(recorded?.ca, pki.ca);
    assert.equal(recorded?.ca_sha256, sha(await readFile(pki.ca)));
    const v = await verifyCustody(root, { runsDir: runs, tsaCa: pki.ca });
    assert.equal(v.timestamp.signature?.verified, true, v.timestamp.note);
    assert.match(v.timestamp.note, /its signature: verified against /);
    assert.equal(v.ok, true, JSON.stringify(v, null, 1));
    // Held to a CA that did not issue it: the chain does not verify.
    const other = await verifyCustody(root, { runsDir: runs, tsaCa: pki.otherCa });
    assert.equal(other.timestamp.signature?.verified, false);
    assert.equal(other.ok, false);
    // No CA here: the anchor's record is named, and the check is imprint only.
    const none = await verifyCustody(root, { runsDir: runs });
    assert.match(none.timestamp.note, /imprint only, signature not verified here \(no CA given: --tsa-ca FILE\); the anchor says it verified against /);
    assert.equal(none.ok, true);
    // A CA file that is not there: named, and a check that was asked for and not made fails.
    const missing = await verifyCustody(root, { runsDir: runs, tsaCa: join(pki.dir, "nope.pem") });
    assert.equal(missing.timestamp.signature?.verified, null);
    assert.match(missing.timestamp.note, /NOT CHECKED \(no CA file at /);
    assert.equal(missing.ok, false);
  } finally {
    server.close();
  }
});

test("a read-only verify writes nothing in the run: a kept disk is loaded outside it, a disk an ended custody left is named and left, and it says what it touched", async () => {
  const { root, runs } = await run();
  const anchorText = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as Record<string, unknown>;
  await writeFile(custodyAnchorPath(root), JSON.stringify({ ...anchorText, isolation: "microvm" }));
  await mkdir(join(root, "vm"), { recursive: true });
  const snaps = `${root}.vm-snapshots`;
  await mkdir(snaps, { recursive: true });
  await writeFile(join(snaps, "a0.msb"), "disk bytes");
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", stopped_at: "t", snapshot: { path: join(snaps, "a0.msb"), sha256: sha("disk bytes") } }));
  // A stand-in msb that loads (it names a digest) and verifies.
  const bin = join(await mkdtemp(join(tmpdir(), "msb-stand-in-")), "msb");
  dirs.push(dirname(bin));
  await writeFile(bin, `#!/bin/sh\ncase "$2" in\n  load) mkdir -p "$4/x" && echo '{}' > "$4/x/snapshot.json" && echo "loaded sha256:${"d".repeat(64)}" ;;\n  verify) echo "Verification: verified" ;;\nesac\nexit 0\n`, { mode: 0o755 });
  const was = process.env.SWARM_MSB_BIN;
  process.env.SWARM_MSB_BIN = bin;
  try {
    await takeCustody(root, { runsDir: runs });
    await mkdir(join(snaps, ".verify-left"), { recursive: true });
    const scratch = await mkdtemp(join(tmpdir(), "verify-scratch-"));
    dirs.push(scratch);
    const v = await verifyCustody(root, { runsDir: runs, scratchDir: scratch });
    assert.ok(v.touched.some((t) => t.includes(join(snaps, ".verify-left")) && /not removed/.test(t)), v.touched.join("\n"));
    assert.ok(v.touched.some((t) => t.startsWith(`made ${join(scratch, ".verify-")}`) && t.endsWith("and removed it")), v.touched.join("\n"));
    assert.ok(v.touched.some((t) => /msb's index: loaded a0\.msb as sha256:d{64}, and removed it again/.test(t)), v.touched.join("\n"));
    assert.deepEqual((await readdir(snaps)).sort(), [".verify-left", "a0.msb"], "nothing added beside the snapshots, and what was there is left");
    assert.deepEqual(await readdir(scratch), [], "the scratch is cleared");
  } finally {
    if (was === undefined) delete process.env.SWARM_MSB_BIN;
    else process.env.SWARM_MSB_BIN = was;
    await rm(snaps, { recursive: true, force: true });
  }
});

test("custody taken again keeps each earlier verdict with the index it sealed, so every index the anchor names can still be checked", async () => {
  const { root, runs } = await sealedRun();
  const first = JSON.parse(await readFile(join(root, "custody.json"), "utf8")) as Custody;
  await writeFile(join(root, "work", "a0", "notes.md"), "scratch, changed\n");
  await takeCustody(root, { runsDir: runs });
  const aside = join(root, `artifacts.${first.at.replace(/[^0-9A-Za-z]/g, "")}.json`);
  const anchor = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as { custody: Array<{ artifacts_sha256: string }> };
  assert.equal(sha(await readFile(aside)), anchor.custody[0].artifacts_sha256, "the first verdict's index, as it sealed it");
  assert.equal(sha(await readFile(join(root, "artifacts.json"))), anchor.custody[1].artifacts_sha256);
  assert.notEqual(anchor.custody[0].artifacts_sha256, anchor.custody[1].artifacts_sha256);
});

/** Lines of ledger/disputes.jsonl chained as the hub writes them (protocol.ts disputeHash). */
function disputeLines(items: Array<{ act: "dispute" | "withdraw"; seq: number; target: string; by: string; why: string }>): string {
  let prev = "genesis";
  let out = "";
  items.forEach((d, i) => {
    const line = { v: 1, act: d.act, seq: d.seq, target: d.target, by: d.by, at: `2026-09-27T00:01:0${i}Z`, why: d.why };
    const hash = sha(`${prev}\n${JSON.stringify(line)}`);
    out += `${JSON.stringify({ ...line, prev, hash })}\n`;
    prev = hash;
  });
  return out;
}

test("the agents' disputes are a chain custody seals beside the ledger: its head and length in the seal, a line appended or rewritten after the stop named by verify", async () => {
  const { root, runs, e1 } = await sealedRun();
  const one = disputeLines([{ act: "dispute", seq: 1, target: e1.hash as string, by: "a1", why: "the host clock was not checked" }]);
  await writeFile(join(root, "ledger", "disputes.jsonl"), one);
  const c = await takeCustody(root, { runsDir: runs });
  assert.equal(c.disputes?.intact, true);
  assert.deepEqual(c.seal.disputes, { lines: 1, head: JSON.parse(one.trim()).hash });
  assert.equal(c.checks.find((x) => x.name === "ledger disputes")?.status, "passed");
  assert.match(c.summary, /1 ledger dispute line, chain intact/);
  const anchor = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as { custody: Array<{ seal?: { disputes?: unknown } }> };
  assert.deepEqual(anchor.custody.at(-1)?.seal?.disputes, c.seal.disputes, "the anchor carries the sealed head too");
  assert.equal((await verifyCustody(root, { runsDir: runs })).ok, true);
  // A withdrawal appended after the stop, chained correctly.
  const two = disputeLines([
    { act: "dispute", seq: 1, target: e1.hash as string, by: "a1", why: "the host clock was not checked" },
    { act: "withdraw", seq: 1, target: e1.hash as string, by: "a1", why: "it was" },
  ]);
  await writeFile(join(root, "ledger", "disputes.jsonl"), two);
  const v = await verifyCustody(root, { runsDir: runs });
  assert.ok(v.seal_drift.some((d) => d.what === "ledger disputes" && /^1 lines, head /.test(d.sealed) && /^2 lines, head /.test(d.now)), JSON.stringify(v.seal_drift));
  assert.equal(v.ok, false);
  // A line rewritten: the chain is broken, and the check fails.
  await writeFile(join(root, "ledger", "disputes.jsonl"), one.replace("was not checked", "was checked"));
  const b = await verifyCustody(root, { runsDir: runs });
  assert.equal(b.now.find((x) => x.name === "ledger disputes")?.status, "failed");
  assert.equal(b.ok, false);
  await writeFile(join(root, "ledger", "disputes.jsonl"), one);
  assert.equal((await verifyCustody(root, { runsDir: runs })).ok, true);
});

test("a verdict taken before disputes were sealed does not hold them, and says so", async () => {
  const { root, runs } = await sealedRun();
  const verdict = JSON.parse(await readFile(join(root, "custody.json"), "utf8")) as Custody;
  const { sealDrift } = await import("../scripts/custody.ts");
  const older = { ...verdict.seal } as Partial<Custody["seal"]>;
  delete older.disputes;
  const d = sealDrift(older, { ...verdict.seal, disputes: { lines: 2, head: "f".repeat(64) } }, null);
  assert.ok(d.not_sealed.includes("the disputes"));
  assert.ok(!d.drift.some((x) => x.what === "ledger disputes"));
});

/** Evidence held in place: a source directory with one file, and the manifest a --inputs-bind kickoff writes for it. */
async function heldInPlace(root: string, name: string): Promise<string> {
  const src = await realpathOf(await mkdtemp(join(tmpdir(), `custody-src-${name}-`)));
  dirs.push(src);
  await writeFile(join(src, "disk.E01"), `disk ${name}\n`);
  return src;
}
async function realpathOf(p: string): Promise<string> {
  const { realpath } = await import("node:fs/promises");
  return realpath(p);
}

test("evidence held in place is read through the link the kickoff made: one set's inputs/ still leads to the source it recorded, and a link moved to an identical copy is named", async () => {
  const { symlink, rm: remove, cp: copy } = await import("node:fs/promises");
  const runs = await mkdtemp(join(tmpdir(), "custody-links-"));
  dirs.push(runs);
  const root = join(runs, "s1");
  await mkdir(root, { recursive: true });
  const src = await heldInPlace(root, "a");
  await symlink(src, join(root, "inputs"));
  await writeFile(join(root, "inputs.json"), JSON.stringify({ source: src, held: "bind", bound: true, bytes: 7, files: [{ path: "inputs/disk.E01", bytes: 7, sha256: sha("disk a\n") }] }));
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "s1" }));
  const c = await takeCustody(root, { runsDir: runs });
  const inputs = c.inputs as { links?: { checked: number; moved: string[] }; unchanged: boolean };
  assert.deepEqual(inputs.links, { checked: 1, moved: [] });
  assert.equal(inputs.unchanged, true);
  assert.equal(c.checks.find((x) => x.name === "evidence")?.status, "passed");
  assert.match(c.summary, /1 link to where it was held still leading there/);
  // The same bytes in another place, and inputs/ made to lead there: the hashes hold, and the evidence is not the source recorded.
  const other = await realpathOf(await mkdtemp(join(tmpdir(), "custody-src-copy-")));
  dirs.push(other);
  await copy(join(src, "disk.E01"), join(other, "disk.E01"));
  await remove(join(root, "inputs"));
  await symlink(other, join(root, "inputs"));
  const moved = await takeCustody(root, { runsDir: runs });
  const m = moved.inputs as { links?: { checked: number; moved: string[] }; unchanged: boolean; changed: string[] };
  assert.deepEqual(m.changed, [], "the bytes are the same");
  assert.equal(m.links?.moved.length, 1);
  assert.match(m.links?.moved[0] ?? "", new RegExp(`^inputs leads to ${other.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}, not ${src.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}, the source the kickoff recorded$`));
  assert.equal(m.unchanged, false);
  const ev = moved.checks.find((x) => x.name === "evidence");
  assert.equal(ev?.status, "failed");
  assert.match(ev?.reason ?? "", /read through a link that does not lead where the kickoff recorded/);
  assert.match(moved.summary, /EVIDENCE READ THROUGH A LINK THAT MOVED: .* · the files read through it hash as the kickoff recorded .*which does not make them the source it recorded/);
  // Replaced by a directory of its own: no longer the link the kickoff made.
  await remove(join(root, "inputs"));
  await copy(src, join(root, "inputs"), { recursive: true });
  const dir = await takeCustody(root, { runsDir: runs });
  assert.match((dir.inputs as { links?: { moved: string[] } }).links?.moved[0] ?? "", /^inputs is no longer the link to .* the kickoff made: a directory is there$/);
});

test("several sets: each inputs/<set> link is held to the source inputs.json's sets records; a copied set has none to check", async () => {
  const { symlink, rm: remove } = await import("node:fs/promises");
  const runs = await mkdtemp(join(tmpdir(), "custody-sets-"));
  dirs.push(runs);
  const root = join(runs, "s2");
  await mkdir(join(root, "inputs"), { recursive: true });
  const a = await heldInPlace(root, "laptop");
  const b = await heldInPlace(root, "phone");
  await symlink(a, join(root, "inputs", "laptop"));
  await symlink(b, join(root, "inputs", "phone"));
  const manifest = {
    source: `${a}, ${b}`,
    held: "bind",
    sets: [
      { name: "laptop", path: "inputs/laptop", source: a, files: 1, bytes: 12 },
      { name: "phone", path: "inputs/phone", source: b, files: 1, bytes: 11 },
    ],
    bytes: 23,
    files: [
      { path: "inputs/laptop/disk.E01", bytes: 12, sha256: sha("disk laptop\n") },
      { path: "inputs/phone/disk.E01", bytes: 11, sha256: sha("disk phone\n") },
    ],
  };
  await writeFile(join(root, "inputs.json"), JSON.stringify(manifest));
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "s2" }));
  // What walking through the set links finds is PR #59's; the links themselves are checked here.
  let c = await takeCustody(root, { runsDir: runs });
  assert.deepEqual((c.inputs as { links?: unknown }).links, { checked: 2, moved: [] });
  assert.deepEqual((c.inputs as { changed: string[] }).changed, []);
  // One set's link made to lead to the other set's source.
  await remove(join(root, "inputs", "phone"));
  await symlink(a, join(root, "inputs", "phone"));
  c = await takeCustody(root, { runsDir: runs });
  const links = (c.inputs as { links?: { checked: number; moved: string[] } }).links;
  assert.equal(links?.checked, 1);
  assert.match(links?.moved.join("\n") ?? "", /^inputs\/phone leads to .*custody-src-laptop-.*, not .*custody-src-phone-.*, the source the kickoff recorded$/);
  assert.equal(c.checks.find((x) => x.name === "evidence")?.status, "failed");
  // Sets copied in: directories of the run's own, nothing to hold to a source.
  const { evidenceLinks } = await import("../scripts/custody.ts");
  assert.deepEqual(await evidenceLinks(root, { ...manifest, held: "copy", sets: [{ name: "gone", source: "/nowhere" }] }), { checked: 0, moved: ["inputs/gone is gone (it led to /nowhere)"] });
  const copied = join(runs, "s3");
  await mkdir(join(copied, "inputs", "laptop"), { recursive: true });
  assert.deepEqual(await evidenceLinks(copied, { ...manifest, held: "copy", sets: [{ name: "laptop", source: a }] }), { checked: 0, moved: [] });
});
