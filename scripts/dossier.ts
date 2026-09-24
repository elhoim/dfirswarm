#!/usr/bin/env node
/**
 * The handover as one product.
 *
 *   node --experimental-strip-types scripts/dossier.ts <sandbox> [--write DIR]
 *
 * Package, the console, and the HTML report used to each assemble the same
 * set of files: hash work/, render the report (which hashed work/ again),
 * render the summary, then hope the hashes on the download rows existed.
 * This builds that set once. `--write DIR` is what `swarm.sh package` calls.
 */
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EVENTS_REL } from "../extensions/protocol.ts";
import { hashArtifacts, type ArtifactIndex } from "./artifacts.ts";
import { hashRegularFile } from "./regular-file.ts";
import { renderReport, type ReportOptions } from "./report.ts";
import { summarize } from "./summary.ts";

export type DossierFile = {
  name: string;
  description: string;
  present: boolean;
  reason?: string;
  bytes: number | null;
  sha256: string | null;
  type: string;
};

export type Dossier = {
  artifacts: ArtifactIndex;
  reportHtml: string;
  summaryMd: string;
  artifactsJson: string;
  files: DossierFile[];
};

function sha256OfString(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * A file the dossier lists and does not rewrite (the trace, the ledger):
 * its size and sha256, read as it lies. One that is not there is `missing`
 * (the caller says why that is normal); one that is there and could not be
 * read (a link, a directory, a read that failed) says so, rather than
 * passing for a run that produced none. Hashed as a stream: a trace past
 * the size one string can hold is listed, not dropped.
 */
async function listedFile(
  path: string,
  name: string,
  description: string,
  type: string,
  missingReason: string,
): Promise<DossierFile> {
  const r = await hashRegularFile(path).catch((err: Error) => ({ why: `unreadable (${(err as NodeJS.ErrnoException).code ?? err.message})` }));
  if (r === null) return { name, description, type, present: false, reason: "could not be read: interrupted", bytes: null, sha256: null };
  if ("why" in r) {
    const reason = r.why === "missing" ? missingReason : `there, and could not be read: ${r.why}`;
    return { name, description, type, present: false, reason, bytes: null, sha256: null };
  }
  return { name, description, type, present: true, bytes: r.size, sha256: r.sha256 };
}

function fileOf(
  name: string,
  description: string,
  type: string,
  body: string | null,
  missingReason: string,
): DossierFile {
  if (body === null) {
    return { name, description, type, present: false, reason: missingReason, bytes: null, sha256: null };
  }
  return {
    name,
    description,
    type,
    present: true,
    bytes: Buffer.byteLength(body),
    sha256: sha256OfString(body),
  };
}

export async function buildDossier(sandboxArg: string, options: ReportOptions = {}): Promise<Dossier> {
  const sandbox = resolve(sandboxArg);
  const artifacts = await hashArtifacts(sandbox);
  const artifactsJson = `${JSON.stringify(artifacts, null, 2)}\n`;
  const [reportHtml, summaryMd, ledgerJsonl, ledgerMd, trace] = await Promise.all([
    renderReport(sandbox, { ...options, artifacts }),
    summarize(sandbox, { runsDir: options.runsDir }),
    listedFile(join(sandbox, "ledger", "entries.jsonl"), "ledger.jsonl", "The timeline, indicators and findings as the agents recorded them.", "application/x-ndjson; charset=utf-8", "nothing recorded"),
    listedFile(join(sandbox, "ledger", "ledger.md"), "ledger.md", "The same ledger, rendered.", "text/markdown; charset=utf-8", "nothing recorded"),
    listedFile(join(sandbox, EVENTS_REL), "trace.jsonl", "Every tool call the swarm made, whole — not the page the Traces tab shows.", "application/x-ndjson; charset=utf-8", "not produced"),
  ]);
  const files: DossierFile[] = [
    fileOf(
      "report.html",
      "The report: cover, evidence, timeline, exhibits, method, artifacts, custody. One file, nothing fetched.",
      "text/html; charset=utf-8",
      reportHtml,
      "not produced",
    ),
    fileOf(
      "summary.md",
      "The run summary, rendered from the sandbox's own files.",
      "text/markdown; charset=utf-8",
      summaryMd,
      "not produced",
    ),
    fileOf(
      "artifacts.json",
      "Every file under work/, with its sha256 — including what stays in the sandbox.",
      "application/json; charset=utf-8",
      artifactsJson,
      "not produced",
    ),
    ledgerJsonl,
    ledgerMd,
    trace,
  ];
  return { artifacts, reportHtml, summaryMd, artifactsJson, files };
}

export async function writeDossierFiles(dir: string, dossier: Dossier): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "summary.md"), dossier.summaryMd);
  await writeFile(join(dir, "artifacts.json"), dossier.artifactsJson);
  await writeFile(join(dir, "report.html"), dossier.reportHtml);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const writeAt = args.includes("--write") ? args[args.indexOf("--write") + 1] : "";
  const sandbox = args.find((a) => !a.startsWith("--") && a !== writeAt);
  if (!sandbox || (args.includes("--write") && !writeAt)) {
    console.error("Usage: dossier.ts <sandbox> [--write DIR]");
    process.exit(2);
  }
  const dossier = await buildDossier(sandbox);
  if (writeAt) {
    await writeDossierFiles(writeAt, dossier);
    process.stdout.write(`Wrote ${writeAt}/report.html, summary.md, artifacts.json\n`);
  } else {
    process.stdout.write(`${JSON.stringify({ files: dossier.files, artifacts: dossier.artifacts }, null, 2)}\n`);
  }
}
