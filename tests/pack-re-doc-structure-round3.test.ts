/**
 * doc_structure, the findings of the third review, each case named after its finding: direct PDF actions known by their place (never
 * by a Python object's identity), the parser's memory held to a budget of what it keeps, duplicate names in a compound file's storage,
 * the scan-mode trailer search with a budget of its own, and the smaller items. Every file is written here from the format's own rules
 * (ISO 32000-1 objects, cross-reference tables, object streams and the Flate filter; [MS-CFB] directory entries and their name rule;
 * [MS-OVBA] dir streams; the PKWARE APPNOTE local and central headers), never from the tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { deflateSync } from "node:zlib";
import { test } from "node:test";
import { DOC_STRUCTURE, body, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, Run } from "./pack-re-harness.ts";
import { buildPdf } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";

/** The tool with a hard wall limit and the child's peak RSS (and, with `rlimitMb`, an address-space limit it cannot pass). */
export function bounded(cwd: string, args: Record<string, unknown>, killAfterMs: number, rlimitMb = 0): { run: Run; seconds: number; rssMb: number } {
  const wrapper = [
    "import json, resource, subprocess, sys, time",
    "limit = int(sys.argv[3])",
    "def pre():",
    "    if limit:",
    "        resource.setrlimit(resource.RLIMIT_AS, (limit << 20, limit << 20))",
    "t = time.monotonic()",
    "try:",
    "    p = subprocess.run([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True, timeout=float(sys.argv[2]), preexec_fn=pre if limit and sys.platform != 'darwin' else None)",
    "    code, out, err = p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')",
    "except subprocess.TimeoutExpired as exc:",
    "    code, out, err = None, (exc.stdout or b'').decode('utf-8', 'replace'), 'killed at the case limit'",
    "r = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss",
    "print(json.dumps({'code': code, 'stdout': out, 'stderr': err, 'seconds': time.monotonic() - t, 'rss_mb': r / (1 << 20) if sys.platform == 'darwin' else r / 1024}))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", wrapper, DOC_STRUCTURE, String(killAfterMs / 1000), String(rlimitMb)], { cwd, input: JSON.stringify(args), encoding: "utf8", maxBuffer: 1 << 28, env: { ...process.env, AGENT_ID: "s1" } });
  assert.equal(r.status, 0, r.stderr);
  const o = JSON.parse(r.stdout);
  return { run: { code: o.code, stdout: o.stdout, stderr: o.stderr }, seconds: o.seconds, rssMb: o.rss_mb };
}

// --- P1-2: direct actions are known by their place ------------------------------------------------------------------------------

/** 200 pages, each with 20 Link annotations of their own, each with its own direct URI action: 4,202 objects, past the object cache. */
function linkHeavy(pages = 200, perPage = 20): Buffer {
  const objs: PdfObj[] = [{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }];
  const kids: string[] = [];
  let num = 3;
  for (let p = 0; p < pages; p++) {
    const page = num++;
    kids.push(`${page} 0 R`);
    const annots: string[] = [];
    for (let a = 0; a < perPage; a++) {
      const an = num++;
      annots.push(`${an} 0 R`);
      objs.push({ num: an, body: `<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (http://h.example/p${p}/a${a}) >> >>` });
    }
    objs.push({ num: page, body: `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Annots [ ${annots.join(" ")} ] >>` });
  }
  objs.push({ num: 2, body: `<< /Type /Pages /Kids [ ${kids.join(" ")} ] /Count ${pages} >>` });
  return buildPdf(objs.sort((x, y) => x.num - y.num), "/Root 1 0 R").file;
}

test("P1-2 4,000 Link annotations each with its own direct action, past the object cache: 4,000 actions, complete, the same on five runs", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/links.pdf", linkHeavy());
    const counts: number[] = [];
    for (let i = 0; i < 5; i++) {
      const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/links.pdf" }));
      assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
      counts.push(a.actions.count);
      assert.equal(a.tables.pdf_actions.matched, 4000);
      assert.equal(a.annotation_subtypes.Link, 4000);
    }
    assert.deepEqual(counts, [4000, 4000, 4000, 4000, 4000]);
  });
});

test("P1-2 a /Next chain that two links reach is 'reached by two /Next links', a chain that returns is a cycle; a direct /Next is a row of its own", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [
      { num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /AA << /WC 7 0 R >> >>" },
      { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" },
      // 4 -> [5, 6]; 5 -> 6: object 6 is reached twice, not a cycle
      { num: 4, body: "<< /S /URI /URI (http://a.example/) /Next [ 5 0 R 6 0 R ] >>" },
      { num: 5, body: "<< /S /URI /URI (http://b.example/) /Next 6 0 R >>" },
      { num: 6, body: "<< /S /URI /URI (http://c.example/) /Next << /S /URI /URI (http://direct.example/) >> >>" },
      // 7 -> 8 -> 7: a cycle
      { num: 7, body: "<< /S /URI /URI (http://d.example/) /Next 8 0 R >>" },
      { num: 8, body: "<< /S /URI /URI (http://e.example/) /Next 7 0 R >>" },
    ];
    await put(cwd, "work/next.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/next.pdf" }));
    assert.ok(a.problems.some((p: string) => /reached from Catalog\/OpenAction reaches object 6 by two \/Next links: it is listed once/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.problems.some((p: string) => /reached from Catalog\/AA\/WC returns to object 7: a cycle, followed once/.test(p)), JSON.stringify(a.problems));
    assert.ok(!a.problems.some((p: string) => /object 6: a cycle/.test(p)), JSON.stringify(a.problems));
    // 4, 5, 6, the direct one after 6 (reached once: the second way to 6 is not followed again), 7, 8
    assert.equal(a.actions.count, 6, JSON.stringify(a.tables.pdf_actions.rows));
  });
});

test("P3 a chain of more than eight references in a row is a problem, not a silent stop", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" }];
    for (let i = 10; i < 20; i++) objs.push({ num: i, body: `${i + 1} 0 R` });
    objs.push({ num: 20, body: "<< /S /JavaScript /JS (app.alert(1)) >>" });
    await put(cwd, "work/hops.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/hops.pdf" }));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /object 10 leads through more than 8 references in a row/.test(p)), JSON.stringify(a.problems));
  });
});

// --- P1-3: what the parser keeps is bounded by its size --------------------------------------------------------------------------

/** A PDF whose objects are in Flate object streams (ISO 32000-1 7.5.7) and whose index is a cross-reference stream (7.5.8). */
function objstmPdf(direct: Map<number, string>, streams: Map<number, [number, Buffer][]>): Buffer {
  const parts: Buffer[] = [Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const ent = new Map<number, [number, number, number]>();
  const push = (b: Buffer): void => { parts.push(b); at += b.length; };
  for (const [n, body] of [...direct].sort((x, y) => x[0] - y[0])) {
    ent.set(n, [1, at, 0]);
    push(Buffer.from(`${n} 0 obj\n${body}\nendobj\n`, "latin1"));
  }
  for (const [stm, members] of streams) {
    let hdr = "";
    const bodies: Buffer[] = [];
    let off = 0;
    members.forEach(([num, b], i) => { hdr += `${num} ${off} `; bodies.push(b, Buffer.from("\n")); off += b.length + 1; ent.set(num, [2, stm, i]); });
    const raw = deflateSync(Buffer.concat([Buffer.from(hdr, "latin1"), ...bodies]));
    ent.set(stm, [1, at, 0]);
    push(Buffer.concat([Buffer.from(`${stm} 0 obj\n<< /Type /ObjStm /N ${members.length} /First ${hdr.length} /Filter /FlateDecode /Length ${raw.length} >>\nstream\n`, "latin1"), raw, Buffer.from("\nendstream\nendobj\n")]));
  }
  const xn = Math.max(...ent.keys()) + 1;
  ent.set(xn, [1, at, 0]);
  const size = xn + 1;
  const rows = Buffer.alloc(size * 7);
  for (let n = 0; n < size; n++) {
    const [t, a, b] = ent.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    rows[n * 7] = t;
    rows.writeUInt32BE(a, n * 7 + 1);
    rows.writeUInt16BE(b, n * 7 + 5);
  }
  const x = at;
  push(Buffer.concat([Buffer.from(`${xn} 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 2] /Root 1 0 R /Length ${rows.length} >>\nstream\n`, "latin1"), rows, Buffer.from(`\nendstream\nendobj\nstartxref\n${x}\n%%EOF\n`, "latin1")]));
  return Buffer.concat(parts);
}

const BASE = new Map<number, string>([[1, "<< /Type /Catalog /Pages 2 0 R >>"], [2, "<< /Type /Pages /Kids [] /Count 0 >>"]]);
const names = (n: number): Buffer => Buffer.from("[" + "/a".repeat(n) + "]", "latin1");

test("P1-3 a 118 KB file of four object streams, seven members each of 999,000 names: under 400 MB, partial, the bound named (3 GB, complete, before)", async () => {
  await withCwd(async (cwd) => {
    const streams = new Map<number, [number, Buffer][]>();
    for (let s = 0; s < 4; s++) streams.set(100 + s, Array.from({ length: 7 }, (_x, k): [number, Buffer] => [200 + s * 10 + k, names(999_000)]));
    await put(cwd, "work/mem.pdf", objstmPdf(BASE, streams));
    // the members compress well past max_ratio's 1,000: the ratio is lifted so that the parser, not the decoder, meets them
    const { run, seconds, rssMb } = bounded(cwd, { path: "work/mem.pdf", max_ratio: 1_000_000 }, 120_000);
    const a = JSON.parse(run.stdout) as Json;
    assert.ok(rssMb < 400, `${rssMb.toFixed(0)} MB`);
    assert.ok(seconds < 60, `${seconds.toFixed(1)} s`);
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /more than 250000 values in one parse/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.census.objects_not_read_at_a_limit, 28);
  });
});

test("P1-3 objects under the per-parse bound, many of them, in object streams and outside: every one read, complete, under 400 MB (the cache is held to its size)", async () => {
  await withCwd(async (cwd) => {
    const streams = new Map<number, [number, Buffer][]>();
    for (let s = 0; s < 4; s++) streams.set(100 + s, Array.from({ length: 7 }, (_x, k): [number, Buffer] => [200 + s * 10 + k, names(240_000)]));
    const direct = new Map(BASE);
    for (let k = 0; k < 5; k++) direct.set(300 + k, "[" + "/a".repeat(240_000) + "]");
    await put(cwd, "work/many.pdf", objstmPdf(direct, streams));
    const { run, rssMb } = bounded(cwd, { path: "work/many.pdf", max_ratio: 1_000_000 }, 120_000);
    const a = JSON.parse(run.stdout) as Json;
    assert.ok(rssMb < 400, `${rssMb.toFixed(0)} MB`);
    assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
    assert.equal(a.census.objects_listed, 2 + 4 + 28 + 5 + 1);
    assert.equal(a.census.objects_not_read_at_a_limit, 0);
  });
});

test("P3 object streams whose members interleave are decoded again when they leave the cache, and counted against max_total_bytes once: complete", async () => {
  await withCwd(async (cwd) => {
    const streams = new Map<number, [number, Buffer][]>();
    const pad = Buffer.from("(" + "x".repeat(2000) + ")", "latin1");
    for (let s = 0; s < 8; s++) streams.set(100 + s, []);
    for (let k = 0; k < 400; k++) streams.get(100 + (k % 8))!.push([1000 + k, pad]);
    await put(cwd, "work/il.pdf", objstmPdf(BASE, streams));
    // eight streams of about 100 KB decoded: 800 KB read once; a cache of six re-read every one of them before, past 1 MB
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/il.pdf", max_total_bytes: 1 << 20 }));
    assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
    assert.equal(a.census.objects_not_read_at_a_limit, 0);
    assert.ok(a.budgets.stream_bytes_read < 1 << 20);
  });
});

test("P3 more than 100 distinct filter chains: the first 100 are counted by chain, the rest are counted and the limit is named", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" }];
    for (let i = 0; i < 120; i++) objs.push({ num: 10 + i, body: `<< /Filter /F${i} >>`, stream: Buffer.from("x") });
    await put(cwd, "work/f.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/f.pdf" }));
    assert.equal(a.streams.count, 120);
    assert.equal(Object.values(a.streams.by_filter_chain as Record<string, number>).reduce((x, y) => x + y, 0), 100);
    assert.equal(a.streams.in_chains_past_the_first_100, 20);
    assert.ok(a.limits_hit.some((l: string) => /more than 100 distinct filter chains/.test(l)), JSON.stringify(a.limits_hit));
  });
});
