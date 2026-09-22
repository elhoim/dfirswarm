/**
 * The dossier: one walk of work/, one report, one summary. Package, the
 * console and the HTML used to each assemble that set, hashing work/ twice
 * and leaving the download rows with no hash at all.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

test("writeDossierFiles writes the three generated files and nothing else", async () => {
  await withSandbox(async (sandbox) => {
    await writeFile(join(sandbox, "work", "notes.md"), "x\n", "utf8");
    const dossier = await buildDossier(sandbox);
    const out = join(sandbox, "package");
    await writeDossierFiles(out, dossier);
    assert.equal(await readFile(join(out, "report.html"), "utf8"), dossier.reportHtml);
    assert.equal(await readFile(join(out, "summary.md"), "utf8"), dossier.summaryMd);
    assert.equal(await readFile(join(out, "artifacts.json"), "utf8"), dossier.artifactsJson);
  });
});
