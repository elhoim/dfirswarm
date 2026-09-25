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
 *
 * The court set is listed in the dossier itself: every file a court or a
 * counterparty receives beside the report (the generated ones, the ledger,
 * the trace, and the custody verdict, its anchor outside the run, the
 * evidence manifest, each VM's record and this run's lines of the
 * operator's record), each with its size and sha256 or the reason it is
 * absent. The report prints that list, and `--write` writes it as
 * court-set.json with the operator's lines beside it.
 */
import { createHash } from "node:crypto";
import { lstat, mkdir, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EVENTS_REL } from "../extensions/protocol.ts";
import { hashArtifacts, type ArtifactIndex } from "./artifacts.ts";
import { hashRegularFile, readRegularText } from "./regular-file.ts";
import { renderReport, type ReportOptions } from "./report.ts";
import { findRunBySandbox } from "./run-record.ts";
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
  /** The files handed over beside these, by the names the console and court-set.json use. */
  court: DossierFile[];
  /** This run's lines of runs/operator-audit.jsonl, as written ("" when none name it). */
  operatorAudit: string;
  /** Every file of the set, generated and court, with its hash: court-set.json. */
  courtSetJson: string;
};

const JSON_TYPE = "application/json; charset=utf-8";

/**
 * This run's lines of the operator's record, byte for byte as written: a
 * line names the run when its argv carries the run id or its command
 * does. The record's chain runs over the whole file in the runs directory,
 * which is where it is checked.
 */
async function operatorAuditLines(runsDir: string, runId: string): Promise<{ text: string; reason?: string }> {
  const file = join(runsDir, "operator-audit.jsonl");
  const st = await lstat(file).catch(() => null);
  if (!st) return { text: "", reason: "no operator record in the runs directory" };
  const read = await readRegularText(file, Math.max(st.size, 1));
  if ("why" in read) return { text: "", reason: `the operator record is ${read.why}` };
  const kept: string[] = [];
  for (const line of read.text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line) as { argv?: unknown; command?: unknown };
      const argv = Array.isArray(rec.argv) ? rec.argv.map(String) : [];
      if (runId && (argv.includes(runId) || String(rec.command ?? "").includes(runId))) kept.push(line);
    } catch {
      // a torn line is the chain's to name, in the whole file
    }
  }
  return kept.length ? { text: `${kept.join("\n")}\n` } : { text: "", reason: "no line of the operator's record names this run" };
}

/**
 * The court set's own files, beside the generated ones: the custody
 * verdict, the verdict anchored outside the run, the evidence manifest,
 * each VM's record and this run's lines of the operator's record. The names
 * are the console's download names.
 */
export async function courtSet(sandboxArg: string, runId: string, runsDir: string): Promise<{ files: DossierFile[]; operatorAudit: string }> {
  const sandbox = resolve(sandboxArg);
  const files: DossierFile[] = [
    await listedFile(join(sandbox, "custody.json"), "custody.json", "The host's custody verdict at stop: the evidence re-hashed, the trace and ledger chains, the kept outputs, each VM.", JSON_TYPE, "not written for this run (swarm.sh stop takes custody)"),
    await listedFile(`${sandbox}.custody-anchor.json`, "custody-anchor.json", "The kickoff's anchor outside the run, with each verdict's hash: custody.json is checked against it.", JSON_TYPE, "not written for this run"),
    await listedFile(join(sandbox, "inputs.json"), "inputs.json", "The evidence manifest the kickoff wrote: every name with its sha256, and md5 and sha1 when taken.", JSON_TYPE, "no evidence was given to this run"),
  ];
  for (const f of (await readdir(join(sandbox, "vm")).catch(() => [] as string[])).sort()) {
    const m = /^([A-Za-z0-9][A-Za-z0-9_-]{0,63})\.json$/.exec(f);
    if (!m) continue;
    files.push(await listedFile(join(sandbox, "vm", f), `vm-${f}`, `The record of ${m[1]}'s VM: its image, size, mounts, network, placeholders, probe, and what its stop did.`, JSON_TYPE, "not written"));
  }
  const audit = await operatorAuditLines(runsDir, runId);
  files.push(
    audit.text
      ? fileOf("operator-audit.jsonl", "This run's lines of the operator's record (who ran which command, from where), as written; the record's chain runs over the whole file in the runs directory.", "application/x-ndjson; charset=utf-8", audit.text, "")
      : { name: "operator-audit.jsonl", description: "This run's lines of the operator's record.", type: "application/x-ndjson; charset=utf-8", present: false, reason: audit.reason, bytes: null, sha256: null },
  );
  return { files, operatorAudit: audit.text };
}

/** court-set.json: the whole hand-over, listed. */
function courtSetText(runId: string, files: DossierFile[]): string {
  return `${JSON.stringify(
    {
      run: runId || null,
      note: "Every file handed over with this run's report, with its size and sha256 as the dossier read it, or the reason it is absent. report.html is listed with the hash of the report as generated beside this file.",
      files: files.map((f) => ({ name: f.name, present: f.present, bytes: f.bytes, sha256: f.sha256, ...(f.reason ? { reason: f.reason } : {}), description: f.description })),
    },
    null,
    2,
  )}\n`;
}

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
  const runsDir = options.runsDir ?? process.env.SWARM_RUNS_DIR ?? dirname(sandbox);
  const run = await findRunBySandbox(sandbox, runsDir);
  const teamId = await readRegularText(join(sandbox, "team.json"), 16 * 1024 * 1024).then((r) => ("text" in r ? String((JSON.parse(r.text) as { swarm_id?: unknown }).swarm_id ?? "") : "")).catch(() => "");
  const runId = run?.id ?? teamId;
  const artifacts = await hashArtifacts(sandbox);
  const artifactsJson = `${JSON.stringify(artifacts, null, 2)}\n`;
  const court = await courtSet(sandbox, runId, runsDir);
  const [summaryMd, ledgerJsonl, ledgerMd, trace] = await Promise.all([
    summarize(sandbox, { runsDir: options.runsDir }),
    listedFile(join(sandbox, "ledger", "entries.jsonl"), "ledger.jsonl", "The timeline, indicators, findings and searches that found nothing, as the agents recorded them, corrections included.", "application/x-ndjson; charset=utf-8", "nothing recorded"),
    listedFile(join(sandbox, "ledger", "ledger.md"), "ledger.md", "The same ledger, rendered.", "text/markdown; charset=utf-8", "nothing recorded"),
    listedFile(join(sandbox, EVENTS_REL), "trace.jsonl", "Every tool call the swarm made, whole — not the page the Traces tab shows.", "application/x-ndjson; charset=utf-8", "not produced"),
  ]);
  const summaryRow = fileOf("summary.md", "The run summary, rendered from the sandbox's own files.", "text/markdown; charset=utf-8", summaryMd, "not produced");
  const artifactsRow = fileOf("artifacts.json", "Every file under work/, with its sha256 — including what stays in the sandbox.", "application/json; charset=utf-8", artifactsJson, "not produced");
  // The report lists every file handed over with it but itself: its own
  // hash cannot be inside it, and court-set.json carries it.
  const reportHtml = await renderReport(sandbox, { ...options, artifacts, handover: [summaryRow, artifactsRow, ledgerJsonl, ledgerMd, trace, ...court.files] });
  const files: DossierFile[] = [
    fileOf(
      "report.html",
      "The report: cover, evidence, timeline, exhibits, method, artifacts, custody, and the list of the files handed over with it. One file, nothing fetched.",
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
  const courtSetJson = courtSetText(runId, [...files, ...court.files]);
  return { artifacts, reportHtml, summaryMd, artifactsJson, files, court: court.files, operatorAudit: court.operatorAudit, courtSetJson };
}

export async function writeDossierFiles(dir: string, dossier: Dossier): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "summary.md"), dossier.summaryMd);
  await writeFile(join(dir, "artifacts.json"), dossier.artifactsJson);
  await writeFile(join(dir, "report.html"), dossier.reportHtml);
  // The hand-over, listed with every file's hash, and the operator's lines
  // for this run, which no other part of the package carries.
  await writeFile(join(dir, "court-set.json"), dossier.courtSetJson);
  if (dossier.operatorAudit) await writeFile(join(dir, "operator-audit.jsonl"), dossier.operatorAudit);
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
    process.stdout.write(`Wrote ${writeAt}/report.html, summary.md, artifacts.json, court-set.json${dossier.operatorAudit ? ", operator-audit.jsonl" : ""}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({ files: dossier.files, court: dossier.court, artifacts: dossier.artifacts }, null, 2)}\n`);
  }
}
