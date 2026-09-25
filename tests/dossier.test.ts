/**
 * The dossier: one walk of work/, one report, one summary. Package, the
 * console and the HTML used to each assemble that set, hashing work/ twice
 * and leaving the download rows with no hash at all.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { buildDossier, writeDossierFiles } from "../scripts/dossier.ts";

const sha = (text: string) => createHash("sha256").update(text).digest("hex");

async function withSandbox(fn: (sandbox: string) => Promise<void>): Promise<void> {
  const sandbox = await mkdtemp(join(tmpdir(), "dossier-"));
  try {
    await mkdir(join(sandbox, "work"), { recursive: true });
    await mkdir(join(sandbox, "traces"), { recursive: true });
    await mkdir(join(sandbox, "ledger"), { recursive: true });
    await writeFile(join(sandbox, "traces", "events.jsonl"), "", "utf8");
    await fn(sandbox);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
}

test("one build hashes work/ once and puts that hash on the report and on the file row", async () => {
  await withSandbox(async (sandbox) => {
    const body = "# Notes\n";
    await writeFile(join(sandbox, "work", "notes.md"), body, "utf8");
    const dossier = await buildDossier(sandbox);
    const hashed = dossier.artifacts.files.find((f) => f.path === "work/notes.md");
    assert.equal(hashed?.sha256, sha(body));
    assert.match(dossier.reportHtml, new RegExp(hashed!.sha256), "the report cites the same hash");
    const reportRow = dossier.files.find((f) => f.name === "report.html");
    assert.equal(reportRow?.present, true);
    assert.equal(reportRow?.sha256, sha(dossier.reportHtml));
    assert.equal(reportRow?.bytes, Buffer.byteLength(dossier.reportHtml));
    const artifactsRow = dossier.files.find((f) => f.name === "artifacts.json");
    assert.equal(artifactsRow?.sha256, sha(dossier.artifactsJson));
    const summaryRow = dossier.files.find((f) => f.name === "summary.md");
    assert.equal(summaryRow?.sha256, sha(dossier.summaryMd));
    const ledgerRow = dossier.files.find((f) => f.name === "ledger.jsonl");
    assert.equal(ledgerRow?.present, false);
    assert.equal(ledgerRow?.sha256, null);
  });
});

test("writeDossierFiles writes the generated files and the court-set list, and nothing else", async () => {
  await withSandbox(async (sandbox) => {
    await writeFile(join(sandbox, "work", "notes.md"), "x\n", "utf8");
    const dossier = await buildDossier(sandbox);
    const out = join(sandbox, "package");
    await writeDossierFiles(out, dossier);
    assert.equal(await readFile(join(out, "report.html"), "utf8"), dossier.reportHtml);
    assert.equal(await readFile(join(out, "summary.md"), "utf8"), dossier.summaryMd);
    assert.equal(await readFile(join(out, "artifacts.json"), "utf8"), dossier.artifactsJson);
    assert.equal(await readFile(join(out, "court-set.json"), "utf8"), dossier.courtSetJson);
    // No operator line names this run: no slice of the record is written.
    assert.deepEqual((await readdir(out)).sort(), ["artifacts.json", "court-set.json", "report.html", "summary.md"]);
  });
});

test("the court set is listed in the dossier itself: each file with its hash or why it is absent, printed in the report and written as court-set.json", async () => {
  const runs = await mkdtemp(join(tmpdir(), "dossier-runs-"));
  const sandbox = join(runs, "sc001");
  try {
    await mkdir(join(sandbox, "work"), { recursive: true });
    await mkdir(join(sandbox, "traces"), { recursive: true });
    await mkdir(join(sandbox, "vm"), { recursive: true });
    await writeFile(join(sandbox, "traces", "events.jsonl"), "", "utf8");
    await writeFile(join(sandbox, "team.json"), JSON.stringify({ swarm_id: "sc001", n: 1, agents: [{ id: "sc00100" }] }));
    await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "sc001", sandbox }] }));
    const custody = '{"summary":"evidence unchanged"}\n';
    await writeFile(join(sandbox, "custody.json"), custody);
    await writeFile(join(sandbox, "inputs.json"), '{"files":[]}\n');
    await writeFile(join(sandbox, "vm", "sc00100.json"), '{"agent":"sc00100"}\n');
    await writeFile(join(sandbox, "vm", "not a record.txt"), "ignored");
    const ours = JSON.stringify({ at: "t1", command: "start", argv: ["start", "--label", "x", "sc001"], prev: null });
    const other = JSON.stringify({ at: "t2", command: "stop", argv: ["stop", "sz999"], prev: sha(ours) });
    const ours2 = JSON.stringify({ at: "t3", command: "stop sc001", argv: ["stop"], prev: sha(other) });
    await writeFile(join(runs, "operator-audit.jsonl"), `${ours}\n${other}\n${ours2}\n`);
    const dossier = await buildDossier(sandbox, { runsDir: runs });
    const byName = new Map(dossier.court.map((f) => [f.name, f]));
    assert.deepEqual([...byName.keys()], ["custody.json", "custody-anchor.json", "inputs.json", "vm-sc00100.json", "operator-audit.jsonl"]);
    assert.equal(byName.get("custody.json")?.sha256, sha(custody));
    assert.equal(byName.get("custody-anchor.json")?.present, false);
    assert.equal(byName.get("custody-anchor.json")?.reason, "not written for this run");
    // Only this run's lines of the operator's record, byte for byte.
    assert.equal(dossier.operatorAudit, `${ours}\n${ours2}\n`);
    assert.equal(byName.get("operator-audit.jsonl")?.sha256, sha(`${ours}\n${ours2}\n`));
    // The report names every file handed over with it, except itself.
    assert.match(dossier.reportHtml, /<h3>Files handed over with this report \(10\)<\/h3>/);
    assert.match(dossier.reportHtml, new RegExp(`<code>custody.json</code></td><td class="num">[^<]+</td><td class="hash">${sha(custody)}</td>`));
    assert.match(dossier.reportHtml, /<code>custody-anchor.json<\/code><\/td><td class="num">—<\/td><td class="hash">absent: not written for this run<\/td>/);
    assert.doesNotMatch(dossier.reportHtml, /<code>report\.html<\/code><\/td>/);
    // court-set.json lists all of it, the report with its hash as generated.
    const list = JSON.parse(dossier.courtSetJson) as { run: string; files: Array<{ name: string; sha256: string | null; present: boolean; reason?: string }> };
    assert.equal(list.run, "sc001");
    assert.deepEqual(list.files.map((f) => f.name), ["report.html", "summary.md", "artifacts.json", "ledger.jsonl", "ledger.md", "trace.jsonl", "custody.json", "custody-anchor.json", "inputs.json", "vm-sc00100.json", "operator-audit.jsonl"]);
    assert.equal(list.files[0].sha256, sha(dossier.reportHtml));
    const out = join(runs, "package");
    await writeDossierFiles(out, dossier);
    assert.equal(await readFile(join(out, "operator-audit.jsonl"), "utf8"), dossier.operatorAudit);
    assert.deepEqual((await readdir(out)).sort(), ["artifacts.json", "court-set.json", "operator-audit.jsonl", "report.html", "summary.md"]);
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});
