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
