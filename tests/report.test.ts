/**
 * The report. Two things are being pinned here.
 *
 * One: the Markdown renderer really does handle what the delivered reports
 * contain. The corpus under docs/use-cases is the fixture — eighteen reports
 * written by swarms on real cases — and every one of them has to survive the
 * round trip with its headings, tables and code spans intact and nothing of
 * it escaping as raw HTML.
 *
 * Two: the citation lint is the corrected rule, not the one the improvement
 * plan wrote. B10 said a section must cite a path under inputs/, catalog/ or
 * work/; applied to these reports it rejects most of their sections, because
 * a forensic citation is usually an inode, a record id or a registry key.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { escapeHtml, lintReport, markdownToHtml, renderReport } from "../scripts/report.ts";
import { recordEntry, createContext, initSandbox } from "../extensions/protocol.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CASES = join(ROOT, "docs", "use-cases");

async function deliveredReports(): Promise<Array<{ name: string; text: string }>> {
  const out: Array<{ name: string; text: string }> = [];
  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > 3) return;
    for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) await walk(abs, depth + 1);
      else if (entry.isFile() && entry.name === "report.md") out.push({ name: abs.slice(CASES.length + 1), text: await readFile(abs, "utf8") });
    }
  }
  await walk(CASES, 0);
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

test("every delivered report survives the renderer with nothing escaping as HTML", async () => {
  const reports = await deliveredReports();
  assert.ok(reports.length >= 15, `expected the delivered corpus, got ${reports.length}`);
  for (const { name, text } of reports) {
    const html = markdownToHtml(text);
    assert.ok(html.length > 0, `${name} rendered to nothing`);

    // Nothing in the source may become markup. Rather than hunting for the
    // dangerous forms one at a time — a search that reports `OnTop = False`
    // inside a registry dump as an event handler — enumerate every tag the
    // output contains: the renderer emits a fixed vocabulary and exactly one
    // attribute, so anything else came from the document.
    for (const [tag] of html.matchAll(/<[^>]+>/g)) {
      assert.match(
        tag,
        /^<\/?(?:h[1-6]|p|ul|ol|li|table|thead|tbody|tr|th|td|pre|code|strong|em|blockquote|hr)>$|^<span class="url">$/,
        `${name} produced ${tag}`,
      );
    }

    // Every heading in the source reaches the output as a heading — and a `#`
    // line inside a fence is a shell comment, not a heading, which is why
    // this counts fences rather than hash marks.
    let inFence = false;
    let headings = 0;
    for (const line of text.split("\n")) {
      if (/^```/.test(line)) {
        inFence = !inFence;
        continue;
      }
      if (!inFence && /^#{1,6}\s+\S/.test(line)) headings++;
    }
    const rendered = (html.match(/<h[1-6]>/g) ?? []).length;
    assert.equal(rendered, headings, `${name}: ${headings} headings in, ${rendered} out`);
  }
});

/**
 * A report published as measured rather than as an exemplar, with what it
 * fails on written down.
 *
 * Run 4 is the first run on a Linux server: four agents on a small model,
 * where the earlier runs of that case had seven on large ones. Three of its
 * eight sections cite nothing checkable. The file is what the swarm wrote and
 * is not edited — a report in this repository is evidence of a run, not a
 * model answer — so the lint records the shortfall by name and asserts its
 * size, which is stricter than an exemption: the report may not quietly get
 * worse, and if someone "fixes" the artifact the test says so too.
 */
const AS_MEASURED: Record<string, number> = {
  "dfir-web-server-case/run-4-linux/report.md": 3,
};

test("the citation lint is the corrected rule, and the delivered reports pass it", async () => {
  const reports = await deliveredReports();
  const failures: string[] = [];
  for (const { name, text } of reports) {
    const findings = lintReport(text);
    const allowed = AS_MEASURED[name];
    if (allowed !== undefined) {
      assert.equal(findings.length, allowed, `${name} is published as measured with ${allowed} uncited sections, found ${findings.length}: ${findings.map((f) => f.section).join("; ")}`);
      continue;
    }
    if (findings.length) failures.push(`${name}: ${findings.map((f) => f.section).join("; ")}`);
  }
  assert.deepEqual(failures, [], "every numbered section in the corpus cites something checkable");

  // And the rule still catches a section that cites nothing.
  const bare = lintReport("## 1. What happened\n\nSomebody got in and took the files.\n");
  assert.equal(bare.length, 1);
  assert.match(bare[0].section, /^1\. What happened/);

  // Each accepted form on its own: a code span, an exhibit, an inode, a
  // record id and a registry key.
  for (const body of [
    "The shell is at `c:\\\\inetpub\\\\cmd.aspx`.",
    "See E-14.",
    "MFT inode 126755 carries it.",
    "Record 33194-128-4 holds the data.",
    "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services was changed.",
  ]) {
    assert.deepEqual(lintReport(`## 2. Finding\n\n${body}\n`), [], `should accept: ${body}`);
  }
});

test("the renderer handles the vocabulary, and nothing more", () => {
  const html = markdownToHtml(
    [
      "# Title",
      "",
      "A paragraph with `code`, **bold** and *italic*.",
      "",
      "- one",
      "- two that wraps onto",
      "  a second line",
      "",
      "1. first",
      "2. second",
      "",
      "| A | B |",
      "| --- | --- |",
      "| 1 | 2 |",
      "",
      "> quoted",
      "",
      "```",
      "raw <not> markup",
      "```",
      "",
      "---",
    ].join("\n"),
  );
  assert.match(html, /<h1>Title<\/h1>/);
  assert.match(html, /<code>code<\/code>/);
  assert.match(html, /<strong>bold<\/strong>/);
  assert.match(html, /<em>italic<\/em>/);
  // A soft-wrapped bullet stays inside its item: the tail of a sentence
  // becoming a paragraph outside the list is how a caveat reads as a claim.
  assert.match(html, /<li>two that wraps onto a second line<\/li>/);
  assert.match(html, /<ol>\s*<li>first<\/li>/);
  assert.match(html, /<th>A<\/th><th>B<\/th>/);
  assert.match(html, /<blockquote>/);
  assert.match(html, /<pre><code>raw &lt;not&gt; markup<\/code><\/pre>/);
  assert.match(html, /<hr>/);
});

test("a code span is not reinterpreted as markup", () => {
  const html = markdownToHtml("Use `a **b** c` and `<script>`.");
  assert.match(html, /<code>a \*\*b\*\* c<\/code>/, "markup inside a code span stays literal");
  assert.match(html, /<code>&lt;script&gt;<\/code>/);
  assert.doesNotMatch(html, /<strong>/);
});

test("escapeHtml covers the five characters that matter", () => {
  assert.equal(escapeHtml(`<a href="x">&'`), "&lt;a href=&quot;x&quot;&gt;&amp;'");
});

async function sandboxWithLedger(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "report-"));
  await initSandbox(root, { reset: true, swarmId: "sr001", agentIds: ["sr00100", "sr00101"], capUsd: 5, wallClockMinutes: 30, goal: "Establish how the host was compromised." });
  const a = createContext(root, "sr00100");
  for (const entry of [
    { kind: "event", ts: "2026-02-11T02:57:12Z", value: "First request from 203.0.113.24", source: "inputs/u_ex.log", evidence: "line 4418" },
    { kind: "event", ts: "2026-02-11T02:57:52Z", value: "upload.aspx written", source: "MFT", evidence: "inode 33194-128-4" },
    { kind: "ioc", value: "203.0.113.24", source: "inputs/u_ex.log", evidence: "40 requests", confidence: "high" },
    { kind: "finding", value: "Entry was an unauthenticated upload", source: "work/notes.md", evidence: "no 4624 before 02:57:12", confidence: "medium" },
  ] as const) {
    const r = await recordEntry(a, entry);
    if (!r.ok) throw new Error(r.reason);
  }
  await mkdir(join(root, "work"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "## 1. Entry\n\nThrough `upload.aspx`, inode 33194-128-4.\n", "utf8");
  return root;
}

test("the report is one self-contained file that cites the ledger's own sequence", async () => {
  const root = await sandboxWithLedger();
  try {
    const html = await renderReport(root, { runsDir: join(root, ".."), caseId: "CASE-2026-004", examiner: "H. Ozturkci", now: "2026-02-12T09:00:00.000Z" });

    // Self-contained: nothing is fetched. The one <style> is inline, the mark
    // is an inline <svg>, and there is no <img>, <link> or <script>.
    assert.doesNotMatch(html, /<script/i);
    assert.doesNotMatch(html, /<link\b/i);
    assert.doesNotMatch(html, /<img\b/i);
    assert.doesNotMatch(html, /\bsrc\s*=\s*["']https?:/i);
    assert.doesNotMatch(html, /@import/i);
    assert.match(html, /<svg[^>]*viewBox="0 0 64 64"/, "the mark is inlined, not linked");

    assert.match(html, /CASE-2026-004/);
    assert.match(html, /H\. Ozturkci/);
    assert.match(html, /2026-02-12T09:00:00\.000Z/, "generated_at is fixed, so two renders match");

    // Exhibit numbers are the ledger's seq, so the console, ledger.jsonl and
    // this document all name the same row.
    assert.match(html, /E-1/);
    assert.match(html, /E-4/);
    // The section head is a number beside the title, not "4." inside it.
    assert.match(html, /<span class="n">4<\/span><h2>Indicators and findings<\/h2>/);
    // The cover carries the numbers a reader needs before the fold.
    assert.match(html, /class="scorecard"/, "the cover has its scorecard");
    assert.match(html, /class="tl"/, "the timeline is a rail, not a five-column table");
    assert.match(html, /class="verdict /, "the findings are verdict cards");
    assert.match(html, /203\.0\.113\.24/);
    assert.match(html, /inode 33194-128-4/);

    // The swarm's own report is reproduced, with its headings demoted so the
    // document keeps one outline.
    assert.match(html, /The swarm's own report \(report\.md\)/);
    assert.match(html, /<h4>1\. Entry<\/h4>/);

    // Two renders with the same `now` are byte-identical.
    const again = await renderReport(root, { runsDir: join(root, ".."), caseId: "CASE-2026-004", examiner: "H. Ozturkci", now: "2026-02-12T09:00:00.000Z" });
    assert.equal(again, html);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a run with nothing recorded says so instead of printing empty sections", async () => {
  const root = await mkdtemp(join(tmpdir(), "report-empty-"));
  try {
    await initSandbox(root, { reset: true, swarmId: "sr002", agentIds: ["sr00200"], capUsd: 1, wallClockMinutes: 5, goal: "Nothing happened here." });
    const html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    assert.match(html, /recorded no findings/i);
    assert.match(html, /no timeline/i);
    assert.match(html, /was given no read-only inputs/i);
    // And it says why the document has no conclusions, in the limitations.
    assert.match(html, /did not finish/);
    assert.match(html, /No findings were recorded/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the print stylesheet keeps the rules that decide whether the PDF is usable", async () => {
  const root = await sandboxWithLedger();
  try {
    const html = await renderReport(root, { runsDir: join(root, ".."), now: "2026-02-12T09:00:00.000Z" });
    const print = html.slice(html.indexOf("@media print"));
    // Each of these exists because of something that breaks without it.
    assert.match(print, /@page\s*\{[^}]*size:\s*A4/, "the page box");
    assert.match(print, /thead\s*\{\s*display:\s*table-header-group/, "a long timeline repeats its column headers");
    assert.match(print, /\.exhibit[^{]*\{[^}]*break-inside:\s*avoid-page/, "an exhibit is never split");
    assert.match(print, /orphans:\s*3;\s*widows:\s*3/, "no stranded single lines");
    assert.match(print, /break-after:\s*avoid-page/, "a heading never ends a page");
    assert.match(print, /print-color-adjust:\s*exact/, "chips keep their ground");
    // A 64-character hash has to be breakable or it overflows the column.
    assert.match(html, /\.hash\s*\{[^}]*word-break:\s*break-all/);
    // And the document does not claim page numbers it cannot compute.
    assert.match(html, /Section numbers, not page numbers/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a long line of table or link punctuation renders in linear time", () => {
  // Each of these used to be scanned once per starting position: 20,000
  // characters took seconds, and the report and the artifact preview both
  // render whatever markdown work/ holds.
  const lines = {
    pipes: `| a | b |\n${"|".repeat(20_000)}x`,
    cells: `| a | b |\n${"| -".repeat(7_000)}x`,
    brackets: "[".repeat(20_000),
    links: "[a](".repeat(5_000),
  };
  for (const [name, md] of Object.entries(lines)) {
    const started = performance.now();
    markdownToHtml(md);
    const ms = performance.now() - started;
    assert.ok(ms < 3_000, `${name}: ${Math.round(ms)} ms`);
  }
  // What the rewrite must still do: a divider is recognised with or without
  // outer pipes and alignment colons, a pipe-free rule is not a divider, and
  // a link keeps its label and shows its target.
  assert.match(markdownToHtml("| A | B |\n|:---|---:|\n| 1 | 2 |"), /<th>A<\/th><th>B<\/th>/);
  assert.match(markdownToHtml("A | B\n--- | ---\n1 | 2"), /<th>A<\/th><th>B<\/th>/);
  assert.doesNotMatch(markdownToHtml("A | B\n---\n"), /<table>/);
  assert.doesNotMatch(markdownToHtml("| A | B |\n|---|x|\n"), /<table>/);
  assert.match(markdownToHtml("See [the log](https://example.org/a) now."), /See the log <span class="url">\(https:\/\/example\.org\/a\)<\/span> now\./);
});
