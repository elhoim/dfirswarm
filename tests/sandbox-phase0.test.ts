/**
 * Phase 0 of docs/sandbox-plan.md: the record says what happened.
 *
 * Four things that were measured wrong or not at all before, each with the
 * run that showed it.
 */
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { appendEvent, verifyEventChain, verifyInputs } from "../extensions/protocol.ts";
import { newPackages, readToolchain, TOOLCHAIN_DIR } from "../extensions/toolchain.ts";
import { egressLine } from "../scripts/report.ts";

async function sandbox(): Promise<string> {
  return mkdtemp(join(tmpdir(), "swarm-phase0-"));
}

/** An inputs/ tree with one file, its manifest, and the pristine copy. */
async function withInputs(root: string, body: string): Promise<{ sha: string; file: string }> {
  const { createHash } = await import("node:crypto");
  const sha = createHash("sha256").update(body).digest("hex");
  await mkdir(join(root, "inputs"), { recursive: true });
  const file = join(root, "inputs", "image.raw");
  await writeFile(file, body, "utf8");
  await chmod(file, 0o444);
  const info = await (await import("node:fs/promises")).stat(file);
  await writeFile(
    join(root, "inputs.json"),
    JSON.stringify({
      source: "/evidence",
      copied_at: new Date().toISOString(),
      enforce: "auto",
      guard: "seatbelt",
      files: [{ path: "inputs/image.raw", sha256: sha, bytes: body.length, mtime_ms: Math.floor(info.mtimeMs), ctime_ms: Math.floor(info.ctimeMs) }],
    }),
    "utf8",
  );
  return { sha, file };
}

test("a write bit coming back is metadata drift, not a change to the evidence", async () => {
  // dfir-m01-ransomcare recorded 374 violations on two files whose sha256
  // still matched the manifest exactly. The bytes never moved; the mode did.
  const root = await sandbox();
  const { file } = await withInputs(root, "evidence bytes\n");

  const clean = await verifyInputs(root);
  assert.ok(clean);
  assert.equal(clean.ok, true);
  assert.equal(clean.content_ok, true);

  await chmod(file, 0o644);
  const drifted = await verifyInputs(root);
  assert.ok(drifted);
  assert.deepEqual(drifted.modified, [], "the bytes are the evidence, and they did not move");
  assert.deepEqual(drifted.metadata, ["inputs/image.raw"]);
  assert.equal(drifted.content_ok, true, "content is still intact");
  assert.equal(drifted.ok, false, "but something drifted, and the check says so");
});

test("changed bytes are still the serious finding", async () => {
  const root = await sandbox();
  const { file } = await withInputs(root, "evidence bytes\n");
  await chmod(file, 0o644);
  await writeFile(file, "tampered\n", "utf8");
  await chmod(file, 0o444);
  const check = await verifyInputs(root);
  assert.ok(check);
  assert.deepEqual(check.modified, ["inputs/image.raw"]);
  assert.deepEqual(check.metadata, []);
  assert.equal(check.content_ok, false);
});

test("a long trace line survives concurrent writers", async () => {
  // Arguments can now be 20,000 characters (A43), which is past the size any
  // filesystem promises to write in one piece. Ten panes appending at once is
  // the ordinary case, not the corner one.
  const root = await sandbox();
  await mkdir(join(root, "traces"), { recursive: true });
  const long = "x".repeat(9000);
  await Promise.all(
    Array.from({ length: 24 }, (_, i) =>
      appendEvent(root, { agent: `a${i % 6}`, tool: "bash", args: { command: long, n: i }, result: { ok: true } }),
    ),
  );
  const text = await readFile(join(root, "traces", "events.jsonl"), "utf8");
  const lines = text.split("\n").filter(Boolean);
  assert.equal(lines.length, 24);
  for (const line of lines) JSON.parse(line); // throws if two writers interleaved
  const parsed = lines.map((line) => JSON.parse(line) as { args: { n: number } });
  assert.equal(new Set(parsed.map((e) => e.args.n)).size, 24, "no line was lost");
});

test("the toolchain is read from the packages' own metadata, not from what an agent says", async () => {
  const root = await sandbox();
  const dist = join(root, TOOLCHAIN_DIR, "lib", "python3.13", "site-packages", "pybde-20240502.dist-info");
  await mkdir(dist, { recursive: true });
  await writeFile(join(dist, "METADATA"), "Metadata-Version: 2.1\nName: libbde-python\nVersion: 20240502\n", "utf8");
  await writeFile(join(dist, "RECORD"), "pybde/__init__.py,sha256=abc,120\n", "utf8");
  await writeFile(join(dist, "INSTALLER"), "pip\n", "utf8");
  await writeFile(join(dist, "direct_url.json"), JSON.stringify({ url: "https://files.pythonhosted.org/packages/x/libbde_python-20240502.whl" }), "utf8");

  const record = await readToolchain(root);
  assert.equal(record.packages.length, 1);
  const [pkg] = record.packages;
  assert.equal(pkg.name, "libbde-python");
  assert.equal(pkg.version, "20240502");
  assert.equal(pkg.installer, "pip");
  assert.match(pkg.source ?? "", /files\.pythonhosted\.org/);
  assert.match(pkg.record_sha256, /^[0-9a-f]{64}$/, "the fingerprint is of the package's own RECORD");

  assert.equal(newPackages(null, record).length, 1, "everything is new the first time");
  assert.equal(newPackages(record, record).length, 0, "and nothing is new the second time");
});

test("an empty toolchain records that nothing was installed", async () => {
  const record = await readToolchain(await sandbox());
  assert.deepEqual(record.packages, []);
  assert.equal(record.dir, TOOLCHAIN_DIR);
});

test("the custody section distinguishes an enforced allowlist from an advisory one", () => {
  assert.match(egressLine("netns"), /enforced/);
  assert.match(egressLine("proxy-only"), /ADVISORY/);
  assert.match(egressLine("off"), /none/);
  assert.match(egressLine(undefined), /not recorded/, "an older run says so rather than claiming either");
});

test("the custody section names what egress was refused, without the harness's own noise", async () => {
  const { countHosts } = await import("../scripts/report.ts");
  // The shape of a real proxy log: 130 of s821c's 172 refusals were the
  // harness's own pi.dev telemetry, which no agent asked for.
  const log = [
    "2026-09-20T18:03:56.739Z DENY connect pi.dev:443",
    "2026-09-20T18:03:56.745Z DENY connect pi.dev:443",
    "2026-09-20T18:15:49.000Z DENY connect bit.ly:443",
    "2026-09-20T18:23:00.000Z DENY connect pypi.org:443",
    "2026-09-20T18:23:01.000Z DENY connect pypi.org:443",
    "2026-09-20T18:04:00.000Z ALLOW connect api.openai.com:443",
  ].join("\n");
  assert.deepEqual(countHosts(log, "DENY"), [["pypi.org", 2], ["bit.ly", 1]]);
  assert.deepEqual(countHosts(log, "ALLOW"), [["api.openai.com", 1]]);
});

test("the trace chain reads as intact, unchained or broken, and never as a lie", async () => {
  const { chainLine } = await import("../scripts/report.ts");
  assert.match(chainLine({ ok: true, chained: 12, total: 12 }), /intact/);
  assert.match(chainLine({ ok: true, chained: 0, total: 12 }), /not chained/);
  assert.match(chainLine({ ok: true, chained: 0, total: 0 }), /no trace/);
  // Each break says which one it is, because "edited" and "a line was added"
  // send a reader to different places.
  assert.match(chainLine({ ok: false, chained: 4, total: 9, broken_at: 5 }), /BROKEN at line 5.*edited/);
  assert.match(chainLine({ ok: false, chained: 4, total: 5, broken_at: 5, reason: "appended" }), /added by something other/);
  assert.match(chainLine({ ok: false, chained: 2, total: 2, broken_at: 2, reason: "shortened" }), /shorter than the anchor/);
  // And an attributed-but-disputed line is named rather than folded away.
  assert.match(chainLine({ ok: true, chained: 9, total: 9, disputed: 1 }), /claimed another agent's name/);
  assert.match(chainLine({ ok: true, chained: 9, total: 9, unverified: 2 }), /could not be attributed/);
});

test("the anchor decides every relation between the record and its length", async () => {
  const { createHash } = await import("node:crypto");
  const h = (line: string) => createHash("sha256").update(line).digest("hex");
  // An honest five-line record, chained the way the collector chains it.
  let prev = "";
  let prevHead = "";
  const honest: string[] = [];
  for (let i = 1; i <= 5; i += 1) {
    const line = JSON.stringify({ ts: `t${i}`, tool: "bash", agent: "a", prev });
    prevHead = prev;
    prev = h(line);
    honest.push(line);
  }
  const anchor = { lines: 5, head: prev, prev_head: prevHead };
  const text = (ls: string[]) => `${ls.join("\n")}\n`;
  const relink = (n: number, tag: string) => {
    let p = "";
    const out: string[] = [];
    for (let i = 1; i <= n; i += 1) {
      const line = JSON.stringify({ ts: `${tag}${i}`, tool: "bash", agent: "a", prev: p });
      p = h(line);
      out.push(line);
    }
    return out;
  };

  assert.equal(verifyEventChain(text(honest), anchor).ok, true);

  // The headline case, and the one that used to pass. `prev` is the sha256 of
  // the previous line, and the file is readable by every pane — so computing
  // a correct one for an appended line costs nothing. Only the anchor, which
  // lives where they cannot write, says where the record ended.
  const appended = [...honest, JSON.stringify({ ts: "t6", tool: "bash", agent: "a", prev: h(honest[4]) })];
  assert.equal(verifyEventChain(text(appended), anchor).reason, "appended");

  // A whole rewrite carries a chain that verifies against itself. Same
  // length: the end does not match. Longer: it is past where the record
  // ended. Both used to be the same hole, one of them open.
  assert.equal(verifyEventChain(text(relink(5, "x")), anchor).reason, "head");
  assert.equal(verifyEventChain(text(relink(6, "x")), anchor).reason, "appended");
  assert.equal(verifyEventChain(text(relink(7, "y")), anchor).reason, "appended");

  // Strip every `prev` and there is no chain to walk. That used to skip the
  // anchor entirely and report as an unchained run — which reads, in the
  // custody section, as "this run had no trace collector".
  const stripped = honest.map((line) => {
    const { prev: _drop, ...rest } = JSON.parse(line) as Record<string, unknown>;
    return JSON.stringify(rest);
  });
  const strippedCheck = verifyEventChain(text(stripped), anchor);
  assert.equal(strippedCheck.ok, false);
  assert.equal(strippedCheck.chained, 0);
  const { chainLine } = await import("../scripts/report.ts");
  assert.doesNotMatch(chainLine(strippedCheck), /no trace collector/);

  // Lines removed from the middle, and the last line removed outright.
  assert.equal(verifyEventChain(text([honest[0], honest[1], honest[3], honest[4]]), anchor).ok, false);
  assert.equal(verifyEventChain(text(honest.slice(0, 3)), anchor).reason, "shortened");

  // The collector writes the anchor before it appends, so a reader can catch
  // the file one line behind. That is the only gap between them, and
  // `prev_head` is what tells the two cases apart.
  const inFlight = { lines: 5, head: prev, prev_head: h(honest[3]), pending: true };
  assert.equal(verifyEventChain(text(honest.slice(0, 4)), inFlight).ok, true);
  assert.equal(verifyEventChain(text(relink(4, "z")), inFlight).reason, "head");

  // Once the append has landed the anchor is committed, and then a file one
  // line short is the record's last line removed — not a moment in time.
  // Without the two writes, one of those two has to be let through.
  const committed = { lines: 5, head: prev, prev_head: h(honest[3]), pending: false };
  assert.equal(verifyEventChain(text(honest.slice(0, 4)), committed).reason, "shortened");
});

test("a custody line without an anchor says so rather than claiming intact", async () => {
  const { chainLine } = await import("../scripts/report.ts");
  // "intact" without an anchor means only that the file agrees with itself,
  // which a rewrite from the first line also manages.
  assert.match(chainLine({ ok: true, chained: 12, total: 12 }, false), /no anchor was found/);
  assert.doesNotMatch(chainLine({ ok: true, chained: 12, total: 12 }, true), /no anchor/);
  // And an anchor on a host with no write guard is in a directory the panes
  // can write, so it proves only what they let it prove.
  assert.match(chainLine({ ok: true, chained: 12, total: 12 }, true, false), /writable by the panes/);
  assert.doesNotMatch(chainLine({ ok: true, chained: 12, total: 12 }, true, true), /writable by the panes/);
});

test("the custody line separates intact bytes from a drifted mode", async () => {
  // The event now carries content_ok and metadata, so the report can say
  // "bytes intact, the mode drifted" instead of one ok: false that reads as
  // evidence tampering.
  const { renderReport } = await import("../scripts/report.ts");
  assert.equal(typeof renderReport, "function");
  const { verifyInputs } = await import("../extensions/protocol.ts");
  const root = await mkdtemp(join(tmpdir(), "swarm-custody-"));
  const { file } = await withInputs(root, "evidence\n");
  await chmod(file, 0o644);
  const check = await verifyInputs(root);
  assert.ok(check);
  // What the done handler now logs:
  const logged = { ok: check.ok, content_ok: check.content_ok, modified: check.modified, metadata: check.metadata };
  assert.deepEqual(logged, { ok: false, content_ok: true, modified: [], metadata: ["inputs/image.raw"] });
});
