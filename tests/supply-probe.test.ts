/**
 * A supplied program is tested against a known answer in a job before the
 * seats rely on it (swarm.sh tool-supply --provides).
 */
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { adminCall, applySupply, applyUntested, decide, PROBE_PAYLOAD, probeFor, probePost, probeQrBase64, runProbes, untestedPost, type HubCall } from "../scripts/supply-probe.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const QRGEN = join(ROOT, "scripts", "lib", "qrgen.py");

test("the probe's QR symbol is a real one: reference format bits, a reference Reed-Solomon block, zero syndromes, a PNG", () => {
  const py = `
import sys; sys.path.insert(0, ${JSON.stringify(join(ROOT, "scripts", "lib"))}); import qrgen
assert format(qrgen.format_bits(0), "015b") == "111011111000100"
assert format(qrgen.format_bits(5), "015b") == "110001100011000"
data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236]
assert qrgen.rs_remainder(data, 13) == [168, 72, 22, 82, 217, 54, 156, 0, 46, 15, 180, 122, 16]
for v, (d, e, _) in qrgen.VERSIONS.items():
    cw = qrgen.codewords_for(b"k" * (d - 2), v)
    assert len(cw) == d + e and not any(qrgen.syndromes(cw, e)), v
m = qrgen.matrix("${PROBE_PAYLOAD}")
assert len(m) == 21 and all(len(r) == 21 for r in m)
assert [m[0][i] for i in range(7)] == [1] * 7 and m[13][8] == 1
print("ok")
`;
  assert.equal(execFileSync("python3", ["-I", "-c", py], { encoding: "utf8" }).trim(), "ok");
  const dir = mkdtempSync(join(tmpdir(), "qrgen-"));
  execFileSync("python3", ["-I", QRGEN, PROBE_PAYLOAD, join(dir, "p.png")]);
  assert.deepEqual([...readFileSync(join(dir, "p.png")).subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.ok(probeQrBase64().length > 200);
});

test("a probe passes only on the known answer; a decoder that reads no image fails, with what it printed", () => {
  const p = probeFor("qr-decode", "QUJD")!;
  assert.match(p.command, /zbarimg -q --raw "\$OUT\/probe\.png"/);
  assert.equal(decide(p, { id: "j000009", state: "committed", status: "ok" }, `${PROBE_PAYLOAD}\n`, "").ok, true);
  const broken = decide(p, { id: "j000010", state: "committed", status: "failed", reason: "exit 2" }, "", "ERROR: NoDecodeDelegateForThisImageFormat `PNG' @ error/constitute.c/ReadImage/594\n");
  assert.equal(broken.ok, false);
  assert.match(broken.said, /FAILED.*exit 2.*NoDecodeDelegateForThisImageFormat/);
  assert.equal(decide(p, { id: "j000011", state: "committed", status: "ok" }, "", "").ok, false, "silence with exit 0 is not a pass");
  assert.equal(decide(p, { id: "j000012", state: "running" }, "", "").ok, false);
  assert.equal(probeFor("ocr", "x"), null);
  assert.ok(probeFor("video-decode", "x") && probeFor("image-convert", "x"));
});

test("the probes run as jobs that name the supplied import in programs, and the seats are told which capability does not work", async () => {
  const calls: Array<[string, Record<string, unknown>]> = [];
  let n = 0;
  const call: HubCall = async (fn, arg) => {
    calls.push([fn, arg]);
    if (fn === "jobSubmit") return { ok: true, job: { job: `j00000${(n += 1)}`, state: "accepted" } };
    const id = String(arg.job_id);
    return id === "j000001"
      ? { ok: true, job: { job: id, state: "committed", status: "failed", reason: "exit 2", stderr: { tail: "NoDecodeDelegateForThisImageFormat" } } }
      : { ok: true, job: { job: id, state: "committed", status: "ok" }, stdout: { text: "frames=5\n" } };
  };
  const r = await runProbes(call, "mat-0002", ["qr-decode", "video-decode", "ocr"], { qr: "QUJD", sleep: async () => undefined });
  assert.equal(r.ok, false);
  assert.deepEqual(r.probes.map((x) => [x.capability, x.ok]), [["qr-decode", false], ["video-decode", true], ["ocr", false]]);
  const subs = calls.filter(([fn]) => fn === "jobSubmit");
  assert.equal(subs.length, 2, "a capability with no test starts no job");
  for (const [, arg] of subs) assert.deepEqual(arg.programs, ["import:mat-0002"]);
  const post = probePost("mat-0002", r.probes);
  assert.match(post, /qr-decode: DOES NOT WORK/);
  assert.match(post, /video-decode: WORKS/);
  assert.match(post, /must not be read as a negative/);
  assert.doesNotMatch(probePost("mat-0001", [r.probes[1]!]), /must not be read as a negative/);
});

test("a supplied program whose known-answer test passed meets the capability the case requires, and counts; one that failed does not", () => {
  const requires: Array<Record<string, unknown>> = [
    { capability: "qr-decode", met: false, by: [], wanted: ["zbarimg"], use: "decode QR symbols", present_but_failed_probe: ["zbarimg"] },
    { capability: "video-decode", met: false, by: [], wanted: ["ffmpeg"], use: "video" },
    { capability: "ocr", met: true, by: ["tesseract"], wanted: ["tesseract"], use: "ocr" },
  ];
  const r = applySupply(requires, "mat-0002", [
    { capability: "qr-decode", ok: true, job: "j000004", said: "known-answer test passed" },
    { capability: "video-decode", ok: false, job: "j000005", said: "known-answer test FAILED" },
  ]);
  assert.deepEqual(r, { met: 2, of: 3, newly_met: ["qr-decode"], unmet: ["video-decode"] });
  assert.equal(requires[0]!.met, true);
  assert.deepEqual(requires[0]!.by, ["import:mat-0002"]);
  assert.equal(requires[0]!.met_at_kickoff, false);
  assert.deepEqual(requires[0]!.supplied, { import: "mat-0002", ok: true, job: "j000004", said: "known-answer test passed" });
  assert.equal(requires[1]!.met, false, "a failed test meets nothing");
  assert.equal((requires[1]!.supplied as { ok: boolean }).ok, false);
  // A second supply that fails takes nothing away from the first that passed.
  const again = applySupply(requires, "mat-0003", [{ capability: "qr-decode", ok: false, job: "j000006", said: "FAILED" }]);
  assert.equal(again.met, 2);
  assert.equal(requires[0]!.met, true);
  const un = applyUntested(requires, "mat-0004", ["video-decode"], "the run has no hub with a job service to test it in");
  assert.deepEqual(un, { met: 2, of: 3, newly_met: [], unmet: ["video-decode"] });
  assert.deepEqual(requires[1]!.supplied, { import: "mat-0004", ok: null, untested: "the run has no hub with a job service to test it in" });
  const post = untestedPost("mat-0004", "nothing said what it is for (no --provides)", []);
  assert.match(post, /^SUPPLIED PROGRAM NOT TESTED: import:mat-0004 was not run against a known answer \(nothing said what it is for \(no --provides\)\)\./);
  assert.match(post, /says nothing about the evidence/);
  assert.match(untestedPost("mat-0004", "x", ["video-decode"]), /supplied for video-decode, which is therefore not shown to work/);
});

/** A stand-in for the hub's admin socket: jobs commit at once with the stdout `stdoutOf` gives; posts are kept. */
async function fakeHub(dir: string, stdoutOf: (command: string) => string): Promise<{ socket: string; posts: Array<Record<string, unknown>>; close: () => Promise<void> }> {
  const socket = join(dir, "admin.sock");
  const posts: Array<Record<string, unknown>> = [];
  const jobs = new Map<string, string>();
  const server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (d) => {
      buf += d;
      if (!buf.includes("\n")) return;
      const req = JSON.parse(buf.split("\n")[0]!) as { fn: string; args: [string, Record<string, unknown>] };
      const arg = req.args[1];
      let answer: Record<string, unknown> = { ok: true };
      if (req.fn === "jobSubmit") {
        const id = `j00000${jobs.size + 1}`;
        jobs.set(id, String(arg.command));
        answer = { ok: true, job: { job: id, state: "accepted" } };
      } else if (req.fn === "jobStatus") {
        answer = { ok: true, job: { job: arg.job_id, state: "committed", status: "ok" }, stdout: { text: stdoutOf(jobs.get(String(arg.job_id)) ?? "") } };
      } else if (req.fn === "systemPost") posts.push(arg);
      // As the hub answers an admin "call" (vm-hub.ts `call`): the board function's answer under `result`.
      c.end(`${JSON.stringify({ ok: true, result: answer })}\n`);
    });
  });
  await new Promise<void>((r) => server.listen(socket, r));
  return { socket, posts, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("the command: a passing probe makes the required capability met in toolbox.json and says the count; --untested records it untested and tells the seats", async () => {
  const sb = mkdtempSync(join(tmpdir(), "sp-"));
  writeFileSync(join(sb, "toolbox.json"), JSON.stringify({ preset: "dfir", present: [], missing: [], requires: [{ capability: "qr-decode", met: false, by: [], wanted: ["zbarimg"], use: "decode QR symbols" }, { capability: "ocr", met: false, by: [], wanted: ["tesseract"], use: "ocr" }] }));
  const hub = await fakeHub(sb, () => `${PROBE_PAYLOAD}\n`);
  // The contract as the kickoff renders it, before any program can be supplied.
  const goal = join(sb, "goal.md");
  writeFileSync(goal, "## Goal\n\nx\n\n## Definition of done\n\nd\n");
  execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "render-contract.ts"), join(ROOT, "prompts", "swarm.md.template"), join(sb, "SWARM.md"), goal, "`a0`", "5", "60", "1", "sw1", sb]);
  const kickoffMd = readFileSync(join(sb, "SWARM.md"), "utf8");
  try {
    const cli = (...a: string[]) => new Promise<{ code: number; out: string }>((resolve) => {
      execFile(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "supply-probe.ts"), sb, ...a], { encoding: "utf8" }, (err, out) => resolve({ code: err ? Number((err as { code?: number }).code ?? 1) : 0, out }));
    });
    const r = await cli("mat-0001", "--provides", "qr-decode", "--hub-admin", hub.socket, "--timeout", "30");
    assert.equal(r.code, 0, r.out);
    const out = JSON.parse(r.out) as { ok: boolean; requires: { met: number; of: number; newly_met: string[] } };
    assert.equal(out.ok, true);
    assert.deepEqual(out.requires, { met: 1, of: 2, newly_met: ["qr-decode"], unmet: ["ocr"] });
    const tb = JSON.parse(readFileSync(join(sb, "toolbox.json"), "utf8")) as { requires: Array<Record<string, unknown>> };
    assert.equal(tb.requires[0]!.met, true);
    assert.deepEqual(tb.requires[0]!.by, ["import:mat-0001"]);
    assert.match(String(hub.posts.at(-1)?.body), /qr-decode: WORKS/);
    // An untested supply is recorded and told to every seat.
    const u = await cli("mat-0002", "--untested", "the run has no hub with a job service to test it in", "--provides", "ocr", "--hub-admin", hub.socket);
    assert.equal(u.code, 0, u.out);
    const uo = JSON.parse(u.out) as { untested: boolean; posted: boolean; requires: { met: number } };
    assert.equal(uo.untested, true);
    assert.equal(uo.posted, true);
    assert.equal(uo.requires.met, 1);
    assert.match(String(hub.posts.at(-1)?.body), /^SUPPLIED PROGRAM NOT TESTED: import:mat-0002/);
    assert.equal(hub.posts.at(-1)?.to, "all");
    const rec = JSON.parse(readFileSync(join(sb, "supplied-capabilities.json"), "utf8")) as Record<string, Record<string, unknown>>;
    assert.ok(Array.isArray(rec["mat-0001"]!.probes));
    assert.equal(rec["mat-0002"]!.untested, "the run has no hub with a job service to test it in");
    // What a seat gets of a supply: the contract, rendered once at kickoff (before), is the same file after both
    // supplies and names the board as where a supply is said; the board has both posts, to everyone.
    assert.equal(readFileSync(join(sb, "SWARM.md"), "utf8"), kickoffMd, "a supply changed the contract");
    assert.match(kickoffMd, /\| qr-decode \| not met \(none of `zbarimg`\) \| decode QR symbols \|/);
    assert.match(kickoffMd, /This table is the kickoff's and is not updated: a program supplied after the start is said on the board \(SUPPLIED PROGRAM TESTED, or NOT TESTED\)/);
    assert.deepEqual(hub.posts.slice(-2).map((p) => [p.to, String(p.body).split(":")[0]]), [["all", "SUPPLIED PROGRAM TESTED"], ["all", "SUPPLIED PROGRAM NOT TESTED"]]);
    const bad = await cli("mat-0003", "--untested", "");
    assert.equal(bad.code, 2, "an empty reason is a usage error");
  } finally {
    await hub.close();
  }
});

test("a real zbarimg decodes the probe's PNG with the probe's own command, where this host has one", (t) => {
  try {
    execFileSync("sh", ["-c", "command -v zbarimg"], { stdio: "ignore" });
  } catch {
    t.skip("no zbarimg on this host");
    return;
  }
  const out = mkdtempSync(join(tmpdir(), "zbar-"));
  const p = probeFor("qr-decode", probeQrBase64())!;
  let stdout = "";
  let stderr = "";
  let status = "ok";
  try {
    stdout = execFileSync("sh", ["-c", p.command], { env: { ...process.env, OUT: out }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 });
  } catch (err) {
    status = "failed";
    stdout = String((err as { stdout?: string }).stdout ?? "");
    stderr = String((err as { stderr?: string }).stderr ?? "");
  }
  const r = decide(p, { id: "local", state: "committed", status }, stdout, stderr);
  assert.equal(r.ok, true, `this host's zbarimg did not read the probe: ${r.said}`);
});

test("adminCall takes the hub's envelope off: an accepted job keeps its id, a refusal keeps the hub's reason", async () => {
  const { unwrapAdmin } = await import("../scripts/supply-probe.ts");
  assert.deepEqual(unwrapAdmin({ ok: true, result: { ok: true, job: { job: "j000006" } } }), { ok: true, job: { job: "j000006" } });
  assert.deepEqual(unwrapAdmin({ ok: false, error: "jobSubmit is not a board function" }), { ok: false, reason: "jobSubmit is not a board function" });
  assert.equal(unwrapAdmin({ ok: false }).ok, false);
  assert.deepEqual(unwrapAdmin({ ok: true, result: null }), { ok: true, value: null });
  // Over a socket that answers as the hub does, a passing ffmpeg test reads as passed (it read as "not accepted").
  const dir = mkdtempSync(join(tmpdir(), "sp-env-"));
  const socket = join(dir, "admin.sock");
  const server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (d) => {
      buf += d;
      if (!buf.includes("\n")) return;
      const req = JSON.parse(buf.split("\n")[0]!) as { fn: string; args: [string, Record<string, unknown>] };
      const result = req.fn === "jobSubmit" ? { ok: true, job: { job: "j000006", state: "accepted" } } : { ok: true, job: { job: "j000006", state: "committed", status: "ok" }, stdout: { text: "frames=5\n" } };
      c.end(`${JSON.stringify({ ok: true, result })}\n`);
    });
  });
  await new Promise<void>((r) => server.listen(socket, r));
  try {
    const out = await runProbes(adminCall(socket, dir), "mat-0001", ["video-decode"], { sleep: async () => undefined });
    assert.equal(out.ok, true, JSON.stringify(out.probes));
    assert.equal(out.probes[0]!.job, "j000006");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});
