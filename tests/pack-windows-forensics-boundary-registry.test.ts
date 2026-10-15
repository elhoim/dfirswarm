/**
 * regkv, shellbags and amcache_apps: the withholding boundary against random canaries planted in the slots the tools print (a value's data, its
 * name, a key name, binary data written as hex, a shell item's name, an Amcache path), the share printed whole asserted against the documented
 * rate, the unclaimed shapes asserted to be printed, the backstop shown to fire on every write path with the sanitiser removed, the values
 * file held to a job run as secret output, and strings an examiner must read shown unchanged. Real regipy where it is installed, the stand-in
 * otherwise.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, failed, tool } from "./windows-pack-harness.ts";
import { VARIANTS, type Node } from "./windows-stub-regipy.ts";
import { SHAPES, leaked, plant, type Canary, type Shape } from "./windows-canary.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const N = 300;
const BOUND: Record<string, number> = {
  "token prefix families": 1, JWT: 1, "PEM private key": 1, "named secrets and user-info": 1, "invisible splits": 1,
  "AWS-shaped and base64 keys": 6, "generic random token": 3,
};
const V = VARIANTS.find((v) => v.real && !v.skip) ?? VARIANTS[0];
const NAMES = ["ghp", "akia", "glpat", "jwt", "aws_secret40", "b64_20", "pem", "pw_assign", "userinfo_at", "zw_split", "random_base62_24", "plain_password", "passphrase", "uuid_secret"];
const shapes = NAMES.map((n) => SHAPES.find((s) => s.name === n)!);

/** Everything the tool left that a reader of the case can reach (not the hive itself). */
async function reachable(cwd: string, skip: (f: string) => boolean = () => false): Promise<string[]> {
  const out: string[] = [];
  for (const f of await everyFileUnder(cwd)) {
    if (/\/work\/[^/]+\.(dat|hve)$/.test(f) || /\/work\/(SECURITY|SOFTWARE|NTUSER\.DAT|UsrClass\.dat|Amcache\.hve)$/.test(f) || f.includes("/pystub/") || skip(f)) continue;
    out.push((await readFile(f)).toString("utf8"));
  }
  return out;
}

function check(shape: Shape, rate: number, where: string): void {
  if (shape.residual) assert.ok(rate >= 90, `${shape.name}: a residual shape is printed in ${where} (${rate}%)`);
  else assert.ok(rate <= BOUND[shape.family], `${shape.name}: ${rate}% printed whole in ${where}, bound ${BOUND[shape.family]}%`);
}

const rate = (canaries: Canary[], outputs: string[]): number => (100 * leaked(canaries, outputs)) / canaries.length;
/** A value of a REG_SZ cannot hold a NUL, and a key or value name cannot hold a backslash or NUL. */
const textOk = (s: Shape): boolean => s.name !== "nul_split";
const nameOk = (s: Shape): boolean => s.name !== "nul_split" && !s.make(() => 0.5).text.includes("\\");

for (const shape of shapes) {
  test(`regkv: ${shape.name} in a value's data, a value name, a key name and binary data`, async () => {
    const canaries = plant(shape, N, 21);
    await withCwd(async (cwd) => {
      const data: Node[] = canaries.map((c, i) => ({ name: `v${i}`, type: "sz" as const, value: c.text.replace(/\u0000/g, "") }));
      const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Data", values: data, children: nameOk(shape) ? canaries.map((c, i) => ({ name: `${i}_${c.text}`.slice(0, 200) })) : [] }] });
      const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", limit: 5 }, env);
      const out = body<Answer>(run);
      assert.ok(out.boundary);
      check(shape, rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))]), "a value's data or a key name");
      // value names
      if (nameOk(shape)) {
        const names: Node[] = canaries.map((c, i) => ({ name: `${i}_${c.text}`.slice(0, 200), type: "dword" as const, value: i }));
        const env2 = await V.write(cwd, "work/SYSTEM", { name: "HIVE", children: [{ name: "Names", values: names }] });
        const r2 = await tool("regkv", cwd, { hive: "work/SYSTEM", key: "Names" }, env2);
        check(shape, rate(canaries, [r2.stdout, r2.stderr]), "a value name");
      }
      // binary data: the canary written as Latin-1 bytes (the cases a registry holds binary data that is text)
      if (textOk(shape)) {
        const bin: Node[] = canaries.map((c, i) => ({ name: `b${i}`, type: "binary" as const, value: Buffer.concat([Buffer.from([1, 2, 3]), Buffer.from(c.text.replace(/[^\x20-\x7e]/g, ""), "latin1"), Buffer.from([4, 5])]) }));
        const env3 = await V.write(cwd, "work/DEFAULT", { name: "HIVE", children: [{ name: "Bin", values: bin }] });
        const r3 = await tool("regkv", cwd, { hive: "work/DEFAULT", key: "Bin" }, env3);
        const ascii = canaries.map((c) => ({ text: c.text, cores: c.cores.filter((core) => /^[\x20-\x7e]+$/.test(core)) })).filter((c) => c.cores.length);
        // the hex of the bytes is what the answer would print: look for the core as hex and as text
        const asHex = ascii.map((c) => ({ text: c.text, cores: c.cores.map((core) => Buffer.from(core, "latin1").toString("hex")) }));
        const binRate = (100 * (leaked(asHex, [r3.stdout]) + leaked(ascii, [r3.stdout]))) / Math.max(1, ascii.length);
        if (shape.residual) assert.ok(binRate >= 90, `${shape.name}: binary data with a residual shape is shown (${binRate}%)`);
        else assert.ok(binRate <= BOUND[shape.family], `${shape.name}: ${binRate}% printed in binary data, bound ${BOUND[shape.family]}%`);
      }
    });
  });
}

for (const shape of shapes.filter((s) => s.name !== "zw_split" && s.name !== "nul_split")) {
  test(`shellbags: ${shape.name} as the name of a shell item`, async () => {
    const canaries = plant(shape, N, 22).map((c) => ({ ...c, text: c.text.replace(/[^\x20-\x7e]/g, "") })).filter((c) => c.text.length >= 4);
    await withCwd(async (cwd) => {
      const item = (text: string): Buffer => { const content = Buffer.concat([Buffer.from([0x4e, 0x00]), Buffer.from(text, "latin1"), Buffer.from([0])]); const size = Buffer.alloc(2); size.writeUInt16LE(content.length + 2); return Buffer.concat([size, content]); };
      const values: Node[] = canaries.map((c, i) => ({ name: String(i), type: "binary" as const, value: item(c.text) }));
      const bag: Node = { name: "BagMRU", values, children: canaries.map((_, i) => ({ name: String(i) })) };
      const env = await V.write(cwd, "work/UsrClass.dat", { name: "HIVE", children: [{ name: "Local Settings", children: [{ name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] }] }] });
      const run = await tool("shellbags", cwd, { hive: "work/UsrClass.dat", limit: 5 }, env);
      const out = body<Answer>(run);
      assert.ok(out.boundary);
      check(shape, rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))]), "a shell item's name");
    });
  });
}

for (const shape of shapes.filter(textOk)) {
  test(`amcache_apps: ${shape.name} as a path, a name and a publisher`, async () => {
    const canaries = plant(shape, N, 23).map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
    await withCwd(async (cwd) => {
      const rows: Node[] = canaries.map((c, i) => ({ name: `${i}`, values: [{ name: "LowerCaseLongPath", type: "sz" as const, value: c.text }, { name: "Publisher", type: "sz" as const, value: c.text }, { name: `N${i}_${nameOk(shape) ? c.text : "x"}`.slice(0, 200), type: "sz" as const, value: "v" }] }));
      const env = await V.write(cwd, "work/Amcache.hve", { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] });
      const run = await tool("amcache_apps", cwd, { hive: "work/Amcache.hve", limit: 5 }, env);
      const out = body<Answer>(run);
      assert.ok(out.boundary);
      check(shape, rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))]), "a path, a publisher or a value name");
    });
  });
}

test("regkv, shellbags and amcache_apps: with the sanitiser taken out the backstop still replaces the shapes it claims, on the answer and on the pages", async () => {
  await withCwd(async (cwd) => {
    const families = ["token prefix families", "JWT", "PEM private key", "named secrets and user-info"];
    for (const name of ["regkv", "amcache_apps"]) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace("    out = _show(str(s), kind, field)\n", "    out = str(s)\n");
      assert.ok(src.includes("    out = str(s)\n"), name);
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      for (const shape of shapes.filter((s) => families.includes(s.family) && textOk(s) && s.name !== "userinfo_at")) {
        const canaries = plant(shape, 120, 7);
        const data: Node[] = canaries.map((c, i) => ({ name: `v${i}`, type: "sz" as const, value: c.text }));
        const rows: Node[] = canaries.map((c, i) => ({ name: `${i}`, values: [{ name: "LowerCaseLongPath", type: "sz" as const, value: c.text }] }));
        const hive = name === "regkv" ? { name: "HIVE", children: [{ name: "Data", values: data }] } : { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] };
        const env = await V.write(cwd, `work/${name}.dat`, hive);
        const args = name === "regkv" ? { hive: `work/${name}.dat`, key: "Data" } : { hive: `work/${name}.dat`, limit: 1 };
        const run = await runPy(join(cwd, "copy", name, "run.py"), cwd, args, undefined, { ...env, AGENT_ID: "s1" });
        const out = JSON.parse(run.stdout) as Answer;
        const files = await reachable(cwd, (f) => f.includes("/copy/"));
        const r = rate(canaries, [run.stdout, run.stderr, ...files]);
        assert.ok(r <= 2, `${name}/${shape.name}: ${r}% printed with the sanitiser removed`);
        assert.equal(out.status, "partial", `${name}/${shape.name}`);
        assert.ok(out.boundary.strings_replaced_by_the_backstop > 0, `${name}/${shape.name}`);
      }
    }
  });
});

test("regkv, shellbags and amcache_apps: write_values is held to a job run as secret output, and the originals go to a 0600 file only", async () => {
  await withCwd(async (cwd) => {
    const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 10, 3);
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Data", values: canaries.map((c, i) => ({ name: `v${i}`, type: "sz" as const, value: c.text })) }] });
    const outside = failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", write_values: true }, env));
    assert.match(outside.error, /write_values is refused/);
    const out = join(cwd, "out");
    await mkdir(out, { recursive: true });
    const job = { ...env, JOB_ID: "j1", OUT: out };
    assert.match(failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", write_values: true }, job)).error, /write_values is refused/);
    assert.deepEqual(await everyFileUnder(out), []);
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", write_values: true }, { ...job, SECRET_OUTPUT: "1" });
    const answer = body<Answer>(run);
    const file = join(out, "regkv-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const originals = (await readFile(file, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as Answer).value as string);
    assert.ok(canaries.every((c) => originals.some((o) => o.includes(c.cores[0]))));
    assert.equal(leaked(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f === file))]), 0);
    assert.equal(answer.boundary.values.written, canaries.length);
    for (const name of ["shellbags", "amcache_apps"]) assert.match(failed(await tool(name, cwd, { hive: "work/SOFTWARE", write_values: true }, env)).error, /write_values is refused/, name);
  });
});

/** What an examiner reads in a hive: none of it may be withheld. */
const READABLE_NAMES = [
  "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
  "Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00", "S-1-5-21-1004336348-1177238915-682003330-1001", "Microsoft.WindowsCalculator_10.2103.8.0_x64__8wekyb3d8bbwe",
  "CDPUserSvc_4f2a1", "wuauserv", "Windows NT", "DisplayName", "UninstallString", "ImagePath", "(default)", "MRUListEx", "ControlSet001", "TimeZoneKeyName",
];
const READABLE_DATA = [
  "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -osint -url \"%1\"", "Microsoft Corporation", "10.0.19045.3803",
  "@%SystemRoot%\\system32\\shell32.dll,-21813", "S-1-5-21-1004336348-1177238915-682003330-1001", "DESKTOP-4F2K9QD", "Pacific Standard Time", "2026-09-01 10:00:00.123456",
  "{54849625-5478-4994-A5BA-3E3B0328C30D}", "Windows Defender Antivirus Service", "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
];

test("regkv: names and data an examiner must be able to read come through unchanged", async () => {
  await withCwd(async (cwd) => {
    const values: Node[] = READABLE_DATA.map((t, i) => ({ name: READABLE_NAMES[i % READABLE_NAMES.length] + (i >= READABLE_NAMES.length ? "_" + i : ""), type: "sz" as const, value: t }));
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Readable", values, children: READABLE_NAMES.filter((n) => !n.includes("\\")).map((name) => ({ name })) }] });
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Readable" }, env));
    assert.deepEqual(Object.values(out.values), READABLE_DATA);
    assert.deepEqual(out.subkeys.map((s: Answer) => s.name), READABLE_NAMES.filter((n) => !n.includes("\\")));
    assert.equal(out.boundary.strings_withheld, 0);
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
