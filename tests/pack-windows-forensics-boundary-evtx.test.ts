/**
 * evtx_query and evtx_carve: the withholding boundary against random canaries planted in the slots the tools print (an EventData value, an
 * EventData name, the channel, the provider, the computer and the XML itself), the share printed whole asserted against the documented rate, the
 * shapes the boundary does not claim asserted to be printed, a `contains` that cannot be used as an oracle on withheld text, the backstop shown
 * to fire on every write path with the sanitiser removed, the values file held to a job run as secret output, and real event strings shown
 * unchanged.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, failed, stubModule, tool } from "./windows-pack-harness.ts";
import { EVTX_CARVE_STUB, eventXml, evtxChunk, evtxFileHeader } from "./windows-stub-evtx.ts";
import { SHAPES, leaked, plant, type Canary, type Shape } from "./windows-canary.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const N = 300;
const BOUND: Record<string, number> = {
  "token prefix families": 1, JWT: 1, "PEM private key": 1, "named secrets and user-info": 1, "invisible splits": 1,
  "AWS-shaped and base64 keys": 6, "generic random token": 3,
};
const NAMES = ["ghp", "akia", "glpat", "jwt", "aws_secret40", "b64_20", "pem", "pw_assign", "userinfo_at", "zw_split", "random_base62_24", "plain_password", "passphrase", "uuid_secret"];
const shapes = NAMES.map((n) => SHAPES.find((s) => s.name === n)!);
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const attrOk = (s: Shape): boolean => !/["<>&\u0000]/.test(s.make(() => 0.3).text) && s.name !== "pw_assign";

/** A log (header + chunks) and the same chunks as a blob, with the stand-in library. */
async function put(cwd: string, records: Array<{ number: number; xml: string }>): Promise<Record<string, string>> {
  const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
  const chunks: Buffer[] = [];
  for (let i = 0; i < records.length; i += 40) chunks.push(evtxChunk(records.slice(i, i + 40)));
  await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(chunks.length, records.length + 1), ...chunks]));
  await writeFile(join(cwd, "work", "Security.evtx.inject.json"), "{}");
  await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat(chunks));
  return stubs;
}

async function reachable(cwd: string, skip: (f: string) => boolean = () => false): Promise<string[]> {
  const out: string[] = [];
  for (const f of await everyFileUnder(cwd)) {
    if (f.endsWith("Security.evtx") || f.endsWith("blob.bin") || f.endsWith(".inject.json") || f.includes("/pystub/") || skip(f)) continue;
    out.push((await readFile(f)).toString("utf8"));
  }
  return out;
}

const rate = (canaries: Canary[], outputs: string[]): number => (100 * leaked(canaries, outputs)) / canaries.length;
function check(shape: Shape, r: number, where: string): void {
  if (shape.residual) assert.ok(r >= 90, `${shape.name}: a residual shape is printed in ${where} (${r}%)`);
  else assert.ok(r <= BOUND[shape.family], `${shape.name}: ${r}% printed whole in ${where}, bound ${BOUND[shape.family]}%`);
}

for (const shape of shapes) {
  test(`evtx_query and evtx_carve: ${shape.name} in an EventData value, an EventData name, a provider, a computer and the XML`, async () => {
    const canaries = plant(shape, N, 31).map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
    await withCwd(async (cwd) => {
      const records = canaries.map((c, i) => ({
        number: i + 1,
        xml: eventXml({ eid: 4688, rec: i + 1, time: "2026-09-01 10:00:00.000000", data: [["Payload", esc(c.text)], ["CommandLine", esc(c.text)], ...(attrOk(shape) ? [[`F${i}_${c.text}`, "x"] as [string, string]] : [])] })
          .replace("Microsoft-Windows-Security-Auditing", "Prov-" + (attrOk(shape) ? c.text : "x")).replace("<Computer>WS01</Computer>", `<Computer>${attrOk(shape) ? c.text : "WS01"}</Computer>`),
      }));
      const env = await put(cwd, records);
      const query = await tool("evtx_query", cwd, { path: "work/Security.evtx", limit: 5 }, env);
      const q = body<Answer>(query);
      assert.ok(q.boundary);
      check(shape, rate(canaries, [query.stdout, query.stderr, ...(await reachable(cwd, (f) => f.endsWith("blob.bin")))]), "evtx_query output or its result file");
      const carve = await tool("evtx_carve", cwd, { path: "work/blob.bin", limit: 5 }, env);
      body<Answer>(carve);
      check(shape, rate(canaries, [carve.stdout, carve.stderr, ...(await reachable(cwd))]), "evtx_carve output or its result file");
    });
  });
}

test("evtx_query and evtx_carve: contains is looked for in what is shown, so a needle cannot be used to test a withheld value", async () => {
  await withCwd(async (cwd) => {
    const secret = "AKIAQWERTYUIOPASDFGH";
    const records = [{ number: 1, xml: eventXml({ eid: 4688, rec: 1, data: [["CommandLine", `aws configure set aws_access_key_id ${secret} --profile p`]] }) }, { number: 2, xml: eventXml({ eid: 4688, rec: 2, data: [["CommandLine", "whoami /all"]] }) }];
    const env = await put(cwd, records);
    for (const [name, p] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]] as const) {
      const hit = body<Answer>(await tool(name, cwd, { path: p, contains: secret.slice(0, 12) }, env));
      assert.equal(hit.events_matched ?? hit.record_count, 0, `${name}: a needle that is part of a withheld value matches nothing`);
      const shown = body<Answer>(await tool(name, cwd, { path: p, contains: "aws_access_key_id" }, env));
      assert.equal(shown.events_matched ?? shown.record_count, 1, `${name}: the shown text is searchable`);
    }
  });
});

test("evtx_query and evtx_carve: with the sanitiser taken out the backstop still replaces the shapes it claims, on the answer and on the result file", async () => {
  await withCwd(async (cwd) => {
    const families = ["token prefix families", "JWT", "PEM private key", "named secrets and user-info"];
    for (const name of ["evtx_query", "evtx_carve"]) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace("    out = _show(str(s), kind, field)\n", "    out = str(s)\n");
      assert.ok(src.includes("    out = str(s)\n"), name);
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      for (const shape of shapes.filter((s) => families.includes(s.family) && s.name !== "userinfo_at" && s.name !== "zw_split")) {
        const canaries = plant(shape, 100, 9).map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
        const env = await put(cwd, canaries.map((c, i) => ({ number: i + 1, xml: eventXml({ eid: 1, rec: i + 1, data: [["CommandLine", esc(c.text)]] }) })));
        const run = await runPy(join(cwd, "copy", name, "run.py"), cwd, { path: name === "evtx_query" ? "work/Security.evtx" : "work/blob.bin", limit: 1 }, undefined, { ...env, AGENT_ID: "s1" });
        const out = JSON.parse(run.stdout) as Answer;
        const r = rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f.includes("/copy/")))]);
        assert.ok(r <= 2, `${name}/${shape.name}: ${r}% printed with the sanitiser removed`);
        assert.equal(out.status, "partial", `${name}/${shape.name}`);
        assert.ok(out.boundary.strings_replaced_by_the_backstop > 0, `${name}/${shape.name}`);
      }
    }
  });
});

test("evtx_query and evtx_carve: write_values is held to a job run as secret output, and the originals go to a 0600 file only", async () => {
  await withCwd(async (cwd) => {
    const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 12, 3);
    const env = await put(cwd, canaries.map((c, i) => ({ number: i + 1, xml: eventXml({ eid: 1, rec: i + 1, data: [["CommandLine", c.text]] }) })));
    for (const [name, p] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]] as const) {
      assert.match(failed(await tool(name, cwd, { path: p, write_values: true }, env)).error, /write_values is refused/, name);
      const out = join(cwd, "out-" + name);
      await mkdir(out, { recursive: true });
      const job = { ...env, JOB_ID: "j1", OUT: out };
      assert.match(failed(await tool(name, cwd, { path: p, write_values: true }, job)).error, /write_values is refused/, name);
      assert.deepEqual(await readdir(out), [], `${name}: nothing was written`);
      const run = await tool(name, cwd, { path: p, write_values: true }, { ...job, SECRET_OUTPUT: "1" });
      const answer = body<Answer>(run);
      const file = join(out, `${name}-values.jsonl`);
      assert.equal((await stat(file)).mode & 0o777, 0o600);
      const originals = (await readFile(file, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as Answer).value as string);
      assert.ok(canaries.every((c) => originals.some((o) => o.includes(c.cores[0]))), name);
      assert.equal(leaked(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f.endsWith("-values.jsonl")))]), 0, name);
      assert.equal(answer.boundary.values.written, canaries.length);
    }
  });
});

/** Real strings from event logs (the EVTX attack-sample logs): none may be withheld. */
const READABLE = [
  ["Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"], ["ParentImage", "C:\\Windows\\System32\\cmd.exe"],
  ["CommandLine", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\bob\\Desktop\\collect.ps1 -OutDir \"C:\\Temp\\out\""],
  ["User", "WIN-3QKR5M2L8SD\\Administrator"], ["ProcessGuid", "{A23EAE89-BD56-5903-0000-0010E9D95E00}"], ["UserSid", "S-1-5-21-1004336348-1177238915-682003330-500"],
  ["Hashes", "MD5=2C1AC7C0B9DDC2C8A6FF4F4BB2A57A8C,SHA256=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08,IMPHASH=C9F2F2B5BA2E9A0F8A2C0C7F5B2C3A11"],
  ["TargetObject", "HKU\\S-1-5-21-1004336348-1177238915-682003330-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive"], ["SourceIp", "10.0.2.15"],
  ["UtcTime", "2017-04-28 22:08:33.016"], ["Description", "Windows PowerShell"], ["Company", "Microsoft Corporation"],
] as Array<[string, string]>;

test("evtx_query and evtx_carve: event data an examiner must be able to read comes through unchanged", async () => {
  await withCwd(async (cwd) => {
    const env = await put(cwd, [{ number: 1, xml: eventXml({ eid: 1, rec: 1, time: "2017-04-28 22:08:33.016000", data: READABLE.map(([k, v]) => [k, esc(v)] as [string, string]) }).replace("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon") }]);
    const q = body<Answer>(await tool("evtx_query", cwd, { path: "work/Security.evtx" }, env));
    assert.deepEqual(q.events[0].data, Object.fromEntries(READABLE));
    assert.equal(q.events[0].provider, "Microsoft-Windows-Sysmon");
    assert.equal(q.boundary.strings_withheld, 0);
    const c = body<Answer>(await tool("evtx_carve", cwd, { path: "work/blob.bin" }, env));
    assert.deepEqual(c.records[0].data, Object.fromEntries(READABLE));
    assert.equal(c.boundary.strings_withheld, 0);
  });
});

test("the windows-forensics tools that carry the SHARED BOUNDARY block carry it identically", async () => {
  const { readdir: ls } = await import("node:fs/promises");
  const begin = "# BEGIN SHARED BOUNDARY";
  const end = "# END SHARED BOUNDARY";
  const found: Record<string, string> = {};
  for (const name of await ls(WIN)) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "");
    if (text.includes(begin)) found[name] = text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  }
  assert.ok(Object.keys(found).length >= 1);
  assert.equal(new Set(Object.values(found).map((b) => createHash("sha256").update(b).digest("hex"))).size, 1, `the block differs between ${Object.keys(found).join(", ")}`);
});
