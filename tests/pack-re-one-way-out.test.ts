/**
 * The one way out of doc_structure, pe_directories and the capa-floss recipe, as a structural guarantee rather than a list of cases:
 *   - the sanitiser (shown_path) withholds every shape of tests/pack-re-canary-shapes.ts in every copy of the shared block, also when
 *     the shape is joined to a path by `/`, cut right after an `@`, or has a letter in front of it, and its output is a fixed point;
 *   - the backstop (final_check) sits between the sanitiser and every byte a tool writes: with the sanitiser taken out of a real call
 *     (shown_answer replaced by the identity) and unsanitised strings injected into the answer and into every table row, stdout and
 *     every table file still hold no window of a canary, every caught field is counted in `withheld_by_final_check` and named in
 *     `problems`, and a complete answer becomes partial;
 *   - numbers of 32 digits or more, a file key spelled like a marker the tool writes, and a file key spelled `<key>_not_shown` are
 *     handled without loss and without a fake marker.
 * Every input is generated here; nothing is read from a tool's output to build one.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, RE, body, buildZip, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPdf, buildPeDirs } from "./pack-re-doc-fixtures.ts";
import { SHAPES, canaries, needles, prng } from "./pack-re-canary-shapes.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const COPIES = [DOC_STRUCTURE, PE_DIRECTORIES, CAPA_FLOSS];

const LOAD = [
  "import importlib.util, io, json, sys",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

/** Python code run with the tool's module loaded as `m`; stdin is JSON, stdout is what the code prints. */
function py(path: string, code: string, input: unknown = null, cwd?: string, env: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path], { input: JSON.stringify(input), encoding: "utf8", cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, maxBuffer: 1 << 28 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function clean(where: string, data: string | Buffer, list: ReturnType<typeof needles>): void {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  for (const n of list) assert.ok(!buf.includes(n.bytes), `${where}: holds ${n.label}`);
}

test("the sanitiser in each copy of the shared block withholds every shape, 300 canaries of each, alone, inside a path, after a `/`, with a letter in front and cut after an `@`", () => {
  const texts: { text: string; c: ReturnType<typeof canaries>[number][1] }[] = [];
  for (let seed = 0; seed < 300; seed++) {
    const max = [31, 200, 2000][seed % 3]!;
    for (const [, c] of canaries(max, 10_000 + seed)) {
      for (const wrap of [(s: string) => s, (s: string) => `word/${s}.xml`, (s: string) => `C:/Users/x/${s}`, (s: string) => `a b ${s} c`, (s: string) => `x${s}`, (s: string) => `Macros/VBA/${s}/dir`]) {
        texts.push({ text: wrap(c.plant), c });
      }
    }
  }
  for (const path of COPIES) {
    const r = py(path, "texts = json.load(sys.stdin)\nprint(json.dumps([m.shown_path(t) for t in texts]))", texts.map((t) => t.text));
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as string[];
    out.forEach((shown, i) => clean(`${path} shown_path(${JSON.stringify(texts[i]!.text)}) = ${JSON.stringify(shown)}`, shown, needles(texts[i]!.c)));
  }
});

test("the sanitiser's output is a fixed point, so the backstop catches only what did not pass it: 20,000 generated strings in each copy", () => {
  const rnd = prng(77);
  const alphabet = "abcXYZ019/_-+=:@.%~ <>#;?&\\";
  const texts: string[] = [];
  const names = Object.values(SHAPES);
  for (let i = 0; i < 20000; i++) {
    let s = "";
    const n = 1 + Math.floor(rnd() * 6);
    for (let k = 0; k < n; k++) {
      if (rnd() < 0.3) {
        const c = names[Math.floor(rnd() * names.length)]!(200, prng(i * 13 + k));
        if (c) s += c.plant;
      } else {
        for (let j = Math.floor(rnd() * 24); j > 0; j--) s += alphabet[Math.floor(rnd() * alphabet.length)];
      }
    }
    texts.push(s);
  }
  for (const path of COPIES) {
    const r = py(path, "texts = json.load(sys.stdin)\nbad = [t for t in texts if m.shown_path(m.shown_path(t)) != m.shown_path(t)]\nprint(json.dumps(bad[:5]))", texts);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), [], `${path}: not a fixed point`);
  }
});

test("final_check withholds an unsanitised key and value, a long number and a value JSON does not carry, counts each, and lets through only a registered string under a safe key", () => {
  const code = [
    "made = m.made('AKIAIOSFODNN7EXAMPLE') if hasattr(m, 'made') else None",
    "safe = (lambda k, v: k == 'clsid' and v == 'AKIAIOSFODNN7EXAMPLE')",
    "value = {'path': 'word/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.xml', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY': 1, 'n': 10 ** 33, 'b': b'x',",
    "         'clsid': 'AKIAIOSFODNN7EXAMPLE', 'other': 'AKIAIOSFODNN7EXAMPLE', 'fine': 'Macros/VBA/ThisDocument', 'list': ['u:PwSecret123@', 'ok']}",
    "out = m.final_check(value, safe)",
    "print(json.dumps({'out': out, 'fields': m.FINAL['fields']}))",
  ].join("\n");
  for (const path of COPIES) {
    const r = py(path, code);
    assert.equal(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout) as Json;
    assert.equal(o.fields, 6, `${path}: ${r.stdout}`);
    assert.equal(o.out.clsid, "AKIAIOSFODNN7EXAMPLE", "a registered string under a safe key passes");
    assert.match(o.out.other, /^<withheld by the final check: 20 characters>$/);
    assert.match(o.out.path, /^<withheld by the final check: \d+ characters>$/);
    assert.match(o.out.n, /^<withheld by the final check: a number of 110 bits>$/);
    assert.match(o.out.b, /^<withheld by the final check: a value of type bytes>$/);
    assert.equal(o.out.fine, "Macros/VBA/ThisDocument");
    assert.deepEqual(o.out.list, ["<withheld by the final check: 14 characters>", "ok"]);
    assert.ok(Object.keys(o.out).some((k) => /^<withheld by the final check: a key of 40 characters>$/.test(k)));
    clean(path, r.stdout, needles({ plant: "", check: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"], pw: "PwSecret123" }));
  }
});

// A real call with the sanitiser removed: shown_answer is the identity, and every table row and the answer carry a raw canary key
// and value. Only the backstop stands between them and the output.
const BYPASS = [
  "CANARY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
  "m.shown_answer = lambda value, key='', spill=None: value",
  "add = m.LosslessPage.add",
  "m.LosslessPage.add = lambda self, row: add(self, {**row, 'planted/' + CANARY: 'u:PwQx7Zr3Kd99@'})",
  "emit = m.emit",
  "m.emit = lambda result, spill=None, indent=2: emit({**result, 'injected': 'ghp_' + 'Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j'}, spill, indent)",
  "sys.stdin = io.StringIO(sys.stdin.read())",
  "try:",
  "    m.main()",
  "except SystemExit:",
  "    pass",
].join("\n");

const INJECTED = needles({ plant: "", check: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j"], pw: "PwQx7Zr3Kd99" });

for (const [label, script, name, make] of [
  ["doc_structure (a ZIP package)", DOC_STRUCTURE, "p.docx", () => buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, { name: "word/document.xml", data: Buffer.from("<a/>") }, { name: "word/b.xml", data: Buffer.from("<a/>") }])],
  ["doc_structure (a PDF)", DOC_STRUCTURE, "p.pdf", () => buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /URI /URI (http://h.example/) >> >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" }], "/Root 1 0 R").file],
  ["pe_directories", PE_DIRECTORIES, "p.dll", () => buildPeDirs({ exports: { imageName: "a.dll", functions: [{ name: "f" }, { name: "g" }] } }).file],
] as const) {
  test(`the backstop holds with the sanitiser removed: ${label}, unsanitised strings injected into the answer and every table row`, async () => {
    await withCwd(async (cwd) => {
      // the same file through the real tool: complete, nothing caught
      await put(cwd, `work/in/${name}`, make());
      const plain = body(await tool(script, cwd, { path: `work/in/${name}`, limit: 1 }));
      assert.equal(plain.withheld_by_final_check, undefined, "nothing for the backstop to catch in a real call");
      const r = py(script, BYPASS, { path: `work/in/${name}`, limit: 1 }, cwd);
      assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
      const a = JSON.parse(r.stdout) as Json;
      clean(`${label} stdout`, r.stdout, INJECTED);
      let files = 0;
      for (const f of await filesUnder(join(cwd, "work"))) {
        if (f.startsWith("in/") || /withheld-names/.test(f)) continue;
        files += 1;
        clean(`${label} work/${f}`, await readFile(join(cwd, "work", f)), INJECTED);
      }
      assert.ok(files >= 1, "limit 1 wrote at least one table file");
      assert.ok(a.withheld_by_final_check >= 2, JSON.stringify(a.withheld_by_final_check));
      assert.equal(a.status, "partial");
      assert.ok(a.problems.some((p: string) => /the final check withheld \d+ field/.test(p)), JSON.stringify(a.problems));
    });
  });
}

test("a number of 32 digits or more (a /Count, a /Prev) is given by its size; a shorter one is printed", async () => {
  await withCwd(async (cwd) => {
    const big = "123456789012345678901234567890123";
    await put(cwd, "work/n.pdf", buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: `<< /Type /Pages /Kids [] /Count ${big} >>` }], `/Root 1 0 R /Size 3 /Prev ${big}`).file);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/n.pdf" });
    const a = JSON.parse(r.stdout) as Json;
    assert.ok(!r.stdout.includes(big.slice(0, 20)), "the digits are not printed");
    assert.equal(a.withheld_by_final_check, undefined);
    assert.match(JSON.stringify(a), /<a number of 107 bits, withheld>/);
  });
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const r = py(path, "print(json.dumps([m.shown_answer(10 ** 31), m.shown_answer(10 ** 31 - 1), m.shown_answer(-(10 ** 40)), m.shown_answer(True)]))");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), `["<a number of 103 bits, withheld>", ${"9".repeat(31)}, "<a number of 133 bits, withheld>", true]`);
  }
});

test("a key out of the file spelled like a marker the tool writes keeps its '<' escaped, and a file key `<key>_not_shown` is kept beside the spill file's", async () => {
  await withCwd(async (cwd) => {
    const fake = "<token-shaped text withheld 20 characters> #2";
    const esc = fake.replace(/[^A-Za-z0-9]/g, (ch) => "#" + ch.charCodeAt(0).toString(16).padStart(2, "0"));
    const cf = `/CF << /AKIAAAAAAAAAAAAAAAAA << /CFM /V2 >> /${esc} << /CFM /AESV3 >> /AKIABBBBBBBBBBBBBBBB << /CFM /None >> >>`;
    await put(cwd, "work/c.pdf", buildPdf([{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" },
      { num: 4, body: `<< /Filter /Standard /V 4 /R 4 /O (aaaa) /U (aaaa) /P -4 ${cf} /StmF /StdCF /StrF /StdCF >>` }], "/Root 1 0 R /Encrypt 4 0 R /ID [(a) (a)]").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/c.pdf" }));
    const keys = Object.keys(a.encryption.dictionary.crypt_filters);
    assert.equal(keys.length, 3, JSON.stringify(keys));
    assert.ok(keys.includes("\\x3ctoken-shaped text withheld 20 characters> #2"), JSON.stringify(keys));
    assert.equal(keys.filter((k) => k.startsWith("<token-shaped text withheld 20 characters>")).length, 2);
  });
  for (const path of [DOC_STRUCTURE, PE_DIRECTORIES]) {
    const code = [
      "class C: key = 'k'",
      "spill = m.Spill(C(), 2)",
      "spill.write = lambda key, items: {'items': len(items)}",
      "print(json.dumps(m.shown_answer({'x_not_shown': 'the file value', 'x': [1, 2, 3, 4]}, '', spill)))",
    ].join("\n");
    const r = py(path, code);
    assert.equal(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout) as Json;
    assert.equal(o.x_not_shown, "the file value", r.stdout);
    assert.deepEqual(o["x_not_shown #2"], { items: 4 });
    assert.deepEqual(o.x, [1, 2]);
  }
});
