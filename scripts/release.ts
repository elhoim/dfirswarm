#!/usr/bin/env node
/**
 * Writing a run's releases (scripts/release-record.ts says what a release
 * is, and how it is checked).
 *
 * draft: the harness's record when custody is taken at stop, sealed by this
 *   install's machine key (scripts/signers.ts): the swarm's report and a
 *   rendering of it (generated at the release's own time, with the DRAFT
 *   mark), the custody verdict and its anchor, the index of work/ custody
 *   sealed, every chain's head and length, the harness and the models. It
 *   is refused when the run is not as custody sealed it, and it is written
 *   once per verdict (a later custody writes the next version).
 * prepare, seal: an enrolled examiner's adoption, in two halves. prepare
 *   reads every standing conclusion's disposition from the review (a
 *   conclusion whose support is defective and that is neither withdrawn nor
 *   rendered inconclusive refuses it), renders the final bytes once (no
 *   DRAFT mark, a fixed time) into release/.pending-<nonce>/ and says what
 *   will be signed: the sha256 values, the gate's counts, the key. seal signs
 *   exactly those bytes once the examiner has confirmed, with their own
 *   secret (a passphrase, a FIDO PIN or touch, a token's PIN), and refuses
 *   when anything moved since or fifteen minutes passed. The review's
 *   sign-off line, written after, names the release. A later adoption is an
 *   amendment and says why.
 * sign: prepare, the summary and a confirmation on the terminal, the secret
 *   read with echo off, seal: the command line's way (`swarm.sh review <id>
 *   --sign`); --yes skips only the confirmation, and the release then
 *   records the consent as presented.
 * print: a PDF of a release's HTML, printed after it was sealed: a print
 *   record beside it, which the next release binds.
 * timestamp: an RFC 3161 token over a release's signature, obtained later
 *   (an air-gapped lab): the proof of existence dates from the token.
 * mirror, ots, transparency: the release's digest line to an independent
 *   copy (a command, a directory, a printed line for the case file), an
 *   OpenTimestamps proof, a transparency log's receipt.
 *
 * Nothing in a release directory is written over. A release changes by a
 * new version, which names the one before it and why it was made; a new
 * examination (evidence examined again, or more of it) reopens the
 * evidence cutoff and is a new run, not an amendment.
 *
 *   node scripts/release.ts draft <sandbox> [--run ID] [--runs DIR] [--reason TEXT] [--quiet]
 *   node scripts/release.ts sign --runs DIR --run ID --sandbox DIR [--examiner ID] [--pdf] [--amend-reason TEXT] [--report PATH] [--no-timestamp] [--yes] [--secret-fd N]
 *   node scripts/release.ts prepare <sandbox> --run ID --runs DIR [--examiner ID] [--pdf] [--amend-reason TEXT] [--report PATH] [--via console|cli] --json
 *   node scripts/release.ts seal <sandbox> --run ID --runs DIR --nonce N --shown SHA256 --examiner ID [--via console|cli] [--consent confirmed|presented] [--secret-fd N] [--no-timestamp] --json
 *   node scripts/release.ts discard <sandbox> --run ID --runs DIR --nonce N
 *   node scripts/release.ts show <sandbox> [--run ID] [--runs DIR] [--json]
 *   node scripts/release.ts verify <sandbox> [--run ID] [--runs DIR] [--allowed-signers FILE] [--ca FILE [--ca-intermediate FILE]] [--tsa-ca FILE]
 *   node scripts/release.ts print <sandbox> [--version N]
 *   node scripts/release.ts timestamp <sandbox> [--run ID] [--runs DIR] [--version N] [--tsa-url URL] [--tsa-ca FILE]
 *   node scripts/release.ts mirror <sandbox> [--version N] --to cmd:COMMAND|dir:PATH|print
 *   node scripts/release.ts ots <sandbox> [--version N] [--upgrade]
 *   node scripts/release.ts transparency <sandbox> [--version N] --log COMMAND
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { custodyAnchorPath, verdictAnchorState } from "./custody.ts";
import { hashRegularFile, readRegularText, writeFileNoFollowSync } from "./regular-file.ts";
import { renderReport, readReviewState, type RenderRelease } from "./report.ts";
import { adoptionState, appendReview, independenceConflict, isSandboxPath, readReviews, reviewsPath, satisfiesPolicy, NO_TECHNICAL_REVIEW, type TechnicalReview } from "./review.ts";
import { dispositionsOf } from "./adoption.ts";
import {
  digestLine,
  hashFieldHead,
  pickRelease,
  lineHashes,
  lineHead,
  qrString,
  readReleases,
  releaseDir,
  releaseSigName,
  releaseSigPath,
  runLayout,
  verifyReleases,
  CONSENT_STATEMENT,
  RELEASE_DIR,
  RELEASE_KIND,
  RELEASE_SCHEMA,
  type ReleaseAdoption,
  type ReleaseRecord,
  type ReleaseSigner,
  type ReleaseSigning,
} from "./release-record.ts";
import { mirrorRelease, timestampRelease } from "./release-witness.ts";
import { otsRelease, transparencyRelease } from "./release-adapters.ts";
import { checkSshSignature, consoleRefusal, dfirswarmHome, keyNeeds, keyWords, listExaminers, loadExaminer, machineSigner, roleWords, signAs, sshKeygen, sshSign, verifyAs, RELEASE_NAMESPACE, type Examiner, type MachineSigner, type Person } from "./signers.ts";
import { opensslBinary } from "./pkcs11.ts";
import { confirmOnTty, hasTty, readFromTty, readSecretFromFd, wipe } from "./secret-io.ts";
import { readLedger, supersededBy, verifyAttestationChain, verifyDisputeChain, verifyLedgerChain, type LedgerEntry } from "../extensions/protocol.ts";
import { verifyLeadChain } from "../extensions/leads.ts";
import { verifyJournalText } from "./evidence-store.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** What the evidence cutoff is, said in every release. */
export const CUTOFF_NOTE =
  "The examination covers the evidence as custody sealed it at this time. A release after it corrects or re-renders what this examination found, or records the examiner's adoption; it examines nothing again. A new examination (the same evidence examined again, or more of it) reopens the cutoff: it is a new run, with its own custody and its own releases, never an amendment of these.";

type Registry = { runs?: Array<Record<string, unknown>> };

export type RunCtx = { sandbox: string; run: string | null; runsDir: string; rec: Record<string, unknown> | null; anchorFile: string; reviewFile: string | null };

/** The run a sandbox is: its id, its registry record and its anchor beside it. */
export function runContext(sandboxArg: string, o: { run?: string; runsDir?: string } = {}): RunCtx {
  const sandbox = resolve(sandboxArg);
  const runsDir = resolve(o.runsDir ?? process.env.SWARM_RUNS_DIR ?? dirname(sandbox));
  let reg: Registry = {};
  try {
    reg = JSON.parse(readFileSync(join(runsDir, "registry.json"), "utf8")) as Registry;
  } catch {
    reg = {};
  }
  let anchorRun: string | null = null;
  try {
    anchorRun = String((JSON.parse(readFileSync(custodyAnchorPath(sandbox), "utf8")) as { run?: string }).run ?? "") || null;
  } catch {
    anchorRun = null;
  }
  const rec = (reg.runs ?? []).find((r) => (o.run && r.id === o.run) || (!o.run && typeof r.sandbox === "string" && resolve(r.sandbox) === sandbox)) ?? null;
  const run = o.run ?? (typeof rec?.id === "string" ? rec.id : null) ?? anchorRun;
  const reviewFile = run && /^[A-Za-z0-9_-]+$/.test(run) ? reviewsPath(runsDir, run) : null;
  return { sandbox, run, runsDir, rec, anchorFile: custodyAnchorPath(sandbox), reviewFile };
}

function git(args: string[]): string | null {
  const r = spawnSync("git", ["-C", ROOT, ...args], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

function fileSha(p: string): string | null {
  try {
    return sha256(readFileSync(p));
  } catch {
    return null;
  }
}

/**
 * Whether the run is as custody sealed it, in what a release binds: the
 * ledger, its attestations and disputes and the store journal against the
 * verdict's seal (examiner notes may follow the journal's sealed line), and
 * the swarm's report against the index custody sealed. What does not hold
 * is named; what the verdict did not seal (an older custody) is said as
 * not bound.
 */
export async function asSealed(ctx: RunCtx, custody: { seal?: Record<string, { lines?: number; entries?: number; head?: string | null } | null>; artifacts?: { index_sha256?: string } | null } | null, reportPath: string): Promise<{ drift: string[]; missing: string[]; reportSealed: boolean | null }> {
  const drift: string[] = [];
  const missing: string[] = [];
  const S = ctx.sandbox;
  const read = (rel: string) => (existsSync(join(S, rel)) ? readFileSync(join(S, rel), "utf8") : null);
  const seal = custody?.seal;
  if (!seal) missing.push("the verdict seals no chain's head (a custody from before the seal): the chains are bound as they are now");
  else {
    // Each chain read the way custody read it when it sealed it (up to a break, when there is one), so a
    // chain that was broken then is not taken for one changed since.
    const lv = verifyLedgerChain(read("ledger/entries.jsonl") ?? "");
    const ledger = { lines: lv.total, head: lv.hashes.at(-1) ?? null };
    if (seal.ledger && (seal.ledger.entries !== ledger.lines || (seal.ledger.head ?? null) !== ledger.head)) drift.push(`the ledger (sealed ${seal.ledger.entries} entries, head ${seal.ledger.head ?? "none"}; now ${ledger.lines}, head ${ledger.head ?? "none"})`);
    const attText = read("ledger/attestations.jsonl");
    const av = attText && attText.trim() ? verifyAttestationChain(attText) : { total: 0, head: null };
    const att = { lines: av.total, head: av.head };
    if (seal.attestations && (seal.attestations.lines !== att.lines || (seal.attestations.head ?? null) !== att.head)) drift.push(`the attestations (sealed ${seal.attestations.lines} lines; now ${att.lines})`);
    const dispText = read("ledger/disputes.jsonl");
    const dv = dispText && dispText.trim() ? verifyDisputeChain(dispText) : { total: 0, head: null };
    const disp = { lines: dv.total, head: dv.head };
    if (!seal.disputes) {
      if (disp.lines) missing.push("the verdict did not seal the disputes (a custody from before they were sealed)");
    } else if (seal.disputes.lines !== disp.lines || (seal.disputes.head ?? null) !== disp.head) drift.push(`the disputes (sealed ${seal.disputes.lines} lines; now ${disp.lines})`);
    // The lead register, sealed unsigned beside the ledger: how the investigation proceeded.
    const leadsText = read("leads/leads.jsonl");
    const lv2 = leadsText && leadsText.trim() ? verifyLeadChain(leadsText) : { total: 0, head: null };
    if (!seal.leads) {
      if (lv2.total) missing.push("the verdict did not seal the lead register (a custody from before it was sealed)");
    } else if ((seal.leads.lines ?? 0) !== lv2.total || (seal.leads.head ?? null) !== lv2.head) drift.push(`the lead register (sealed ${seal.leads.lines} events; now ${lv2.total})`);
    // The question register, the same way: what was asked, by whom, and how each question stood.
    const questionsText = read("questions/questions.jsonl");
    const qv = questionsText && questionsText.trim() ? verifyLeadChain(questionsText) : { total: 0, head: null };
    if (!seal.questions) {
      if (qv.total) missing.push("the verdict did not seal the question register (a custody from before it was sealed)");
    } else if ((seal.questions.lines ?? 0) !== qv.total || (seal.questions.head ?? null) !== qv.head) drift.push(`the question register (sealed ${seal.questions.lines} events; now ${qv.total})`);
    const journalText = read("store/journal.jsonl");
    if (seal.journal) {
      const hashes = verifyJournalText(journalText ?? "").hashes;
      const n = seal.journal.lines ?? 0;
      const types = (journalText ?? "").split("\n").filter((l) => l.trim()).map((l) => {
        try {
          return String((JSON.parse(l) as { type?: unknown }).type ?? "");
        } catch {
          return "";
        }
      });
      if ((n ? hashes[n - 1] : null) !== (seal.journal.head ?? null) || !types.slice(n).every((x) => x === "note")) drift.push(`the store journal (sealed ${n} lines, head ${seal.journal.head ?? "none"}; now ${hashes.length})`);
    }
  }
  let reportSealed: boolean | null = null;
  const want = custody?.artifacts?.index_sha256;
  if (!want) missing.push("the verdict sealed no index of work/ (a custody from before the index): the swarm's report is bound by its hash now, not held to a seal");
  else {
    const idx = read("artifacts.json");
    if (idx === null || sha256(idx) !== want) drift.push(`artifacts.json, the index of work/ the verdict sealed (${want}), is ${idx === null ? "gone" : "not those bytes"}`);
    else {
      const sealed = ((JSON.parse(idx) as { files?: Array<{ path: string; sha256: string }> }).files ?? []).find((f) => f.path === reportPath);
      const now = fileSha(join(S, reportPath));
      if (!sealed) reportSealed = now === null ? null : false;
      else if (now !== sealed.sha256) drift.push(`${reportPath} (custody sealed ${sealed.sha256}; ${now ? `it is ${now} now` : "it is gone"})`);
      else reportSealed = true;
      if (sealed === undefined && now !== null) missing.push(`${reportPath} is not in the index custody sealed: it was written after the stop, and is bound by its hash now`);
    }
  }
  return { drift, missing, reportSealed };
}

type SignerInput = { kind: "machine"; machine: MachineSigner } | { kind: "examiner"; examiner: Person; enrolmentSha: string };

type ReleaseInput = {
  state: "draft" | "adopted";
  reason: string;
  signer: SignerInput;
  adoption: ReleaseAdoption | null;
  renderAdoption: RenderRelease["adoption"];
  /** How many lines of the review the release binds (the review as it is now). */
  reviewLines: number;
  pdf: boolean;
  reportPath: string;
  policy?: ReleaseRecord["policy"];
};

export type Written = { version: number; dir: string; sha256: string; sigSha: string; record: ReleaseRecord; line: string; qr: string };

/** A wrong passphrase or PIN: nothing was signed, and the console counts it against the person. */
export class WrongSecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrongSecretError";
  }
}

/** How long a prepared release waits for its seal. */
export const PENDING_TTL_MS = 15 * 60_000;
const NONCE = /^[0-9a-f]{32}$/;

/** The verdict a release binds, checked against its anchor and the run as custody sealed it. */
async function sealableCustody(ctx: RunCtx, reportPath: string): Promise<{ custodyText: string; custody: CustodyShape; sealed: Awaited<ReturnType<typeof asSealed>> }> {
  const S = ctx.sandbox;
  const custodyText = await readRegularText(join(S, "custody.json"), 256 * 1024 * 1024);
  if ("why" in custodyText) throw new Error(`there is no custody verdict to release (custody.json is ${custodyText.why}): swarm.sh stop takes custody`);
  const custody = JSON.parse(custodyText.text) as CustodyShape;
  const anchorState = await verdictAnchorState(S);
  if (anchorState.state !== "matches") throw new Error(`custody.json is not the verdict anchored beside the run (${anchorState.state === "differs" ? anchorState.note : anchorState.state}): a release binds only a verdict its anchor names; swarm.sh custody-verify ${ctx.run ?? "<id>"} says what changed`);
  const sealed = await asSealed(ctx, custody, reportPath);
  if (sealed.drift.length) throw new Error(`the run is not as custody sealed it: ${sealed.drift.join("; ")}. A release binds only what custody sealed; swarm.sh custody-verify ${ctx.run ?? "<id>"} names each change`);
  return { custodyText: custodyText.text, custody, sealed };
}

type CustodyShape = { at?: string; summary?: string; seal?: Record<string, { lines?: number; entries?: number; head?: string | null; last_line_sha256?: string | null } | null>; artifacts?: { index_sha256?: string; files?: number } | null; models?: unknown };

type SignerIsolation = { isolation?: string; guard?: string; keys_hidden?: boolean; hidden?: string[]; agent_sockets?: string[]; exposed?: string[]; exposure_accepted?: boolean; why?: string };
type EarlierRunsHidden = { by?: string | null; sandboxes?: number; reviews?: string | null; skipped?: string[]; why?: string };

/**
 * Where the run ran and whether the signers' keys were out of its agents'
 * reach, as the kickoff recorded it in the registry (docs/observability.md):
 * `signer_keys_hidden`, `signer_isolation` (the isolation, the guard, what
 * was hidden and what exposed, whether --accept-signer-exposure let it
 * start) and `earlier_runs_hidden`. The release binds them as they are. A
 * record without them was made before they existed, and what its agents
 * could reach is unknown.
 */
export function hostExposure(ctx: RunCtx): NonNullable<ReleaseRecord["host"]> {
  const rec = ctx.rec;
  const si = (rec?.signer_isolation ?? null) as SignerIsolation | null;
  const earlier = (rec?.earlier_runs_hidden ?? null) as EarlierRunsHidden | null;
  const iso = rec ? (si?.isolation ?? ((rec.isolation as { mode?: unknown } | undefined)?.mode as string | undefined) ?? "host") : null;
  const hidden = typeof rec?.signer_keys_hidden === "boolean" ? rec.signer_keys_hidden : typeof si?.keys_hidden === "boolean" ? si.keys_hidden : null;
  const why = si?.why ?? null;
  const said = why ? ` (${why}${si?.exposure_accepted ? "; started with --accept-signer-exposure" : ""})` : si?.exposure_accepted ? " (started with --accept-signer-exposure)" : "";
  const note =
    iso === null
      ? "the run's registry record was not found: where it ran, and whether its agents could read the signers' keys, is unknown"
      : iso === "microvm"
        ? `the agents ran in microVMs, which do not mount the host's home${hidden === false ? `; the kickoff nonetheless recorded the signers' keys as not hidden${said}` : ""}`
        : hidden === true
          ? "the agents ran on the host (host mode), with the signers' keys hidden from their panes"
          : hidden === false
            ? `the agents ran on the host (host mode), and the signers' keys were NOT hidden from their panes${said}: a key the panes could read may have been copied; rotate the machine key (swarm.sh machine rotate) and any examiner key without a passphrase`
            : "the agents ran on the host (host mode), and the kickoff did not record whether the signers' keys were hidden from their panes: unknown";
  return { isolation: iso, signer_keys_hidden: hidden, note, ...(si ? { signer_isolation: si } : {}), ...(earlier ? { earlier_runs_hidden: earlier } : {}) };
}

/** Whether a seal needs a current technical review signed by its reviewer: the run's kickoff flag, or the environment's. */
export function technicalReviewPolicy(ctx: RunCtx): NonNullable<ReleaseRecord["policy"]> {
  if (ctx.rec?.require_technical_review === true) return { require_technical_review: true, source: "the run's kickoff (--require-technical-review)" };
  if (process.env.SWARM_REQUIRE_TECHNICAL_REVIEW === "1") return { require_technical_review: true, source: "SWARM_REQUIRE_TECHNICAL_REVIEW=1" };
  return { require_technical_review: false, source: null };
}

/**
 * Render and record one release into `dir` (report.html, a PDF when asked,
 * and the record, not yet signed). The rendering is generated at the
 * release's own time `at`, so the same release rendered again is the same
 * bytes.
 */
async function buildRelease(ctx: RunCtx, input: ReleaseInput, dir: string, o: { version: number; prevRel: ReturnType<typeof readReleases>[number] | null; at: string; custodyText: string; custody: CustodyShape; sealed: Awaited<ReturnType<typeof asSealed>> }): Promise<ReleaseRecord> {
  const S = ctx.sandbox;
  const { version, prevRel, at, custody, sealed } = o;
  const existing = readReleases(S);
  // The review as it stands, rendered as the release binds it.
  const reviewRead = ctx.run ? await readReviews(ctx.runsDir, ctx.run).catch(() => []) : [];
  const reviewLines = Math.min(input.reviewLines, reviewRead.length);
  const ledger = await readLedger(S, { raw: true });
  const reviewState = ctx.run ? await readReviewState(ctx.runsDir, ctx.run, S, ledger, reviewLines) : null;
  let signer: ReleaseSigner;
  if (input.signer.kind === "machine") {
    const m = input.signer.machine;
    signer = { kind: "machine", principal: m.principal, public: m.public, fingerprint: m.fingerprint, key_kind: "machine", machine: { id: m.id, host: m.host, label: m.label } };
  } else {
    const p = input.signer.examiner;
    const k = p.key;
    signer = {
      kind: "examiner",
      principal: p.principal,
      public: k.kind === "pkcs11" ? "" : k.public,
      fingerprint: k.fingerprint,
      key_kind: k.kind,
      ...(k.kind === "pkcs11" ? { certificate: { sha256: k.certificate.sha256, cn: k.certificate.cn, issuer: k.certificate.issuer, not_before: k.certificate.not_before, not_after: k.certificate.not_after, key_usage: k.certificate.key_usage, qc_statement: k.certificate.qc_statement } } : {}),
      examiner: { id: p.id, name: p.name, organisation: p.organisation, competence: p.competence, enrolled_at: p.enrolled_at, enrolment_sha256: input.signer.enrolmentSha },
    };
  }
  const render: RenderRelease = {
    version,
    state: input.state,
    at,
    ...(signer.kind === "examiner" && signer.examiner ? { examiner: { id: signer.examiner.id, name: signer.examiner.name, organisation: signer.examiner.organisation, competence: signer.examiner.competence, fingerprint: signer.fingerprint } } : {}),
    ...(signer.kind === "machine" ? { machine: { fingerprint: signer.fingerprint } } : {}),
    adoption: input.renderAdoption ?? null,
  };
  const html = await renderReport(S, { runsDir: ctx.runsDir, now: at, release: render, review: reviewState });
  writeFileSync(join(dir, "report.html"), html, { mode: 0o600 });
  let pdf: ReleaseRecord["report"]["pdf"] = null;
  if (input.pdf) {
    const printed = printPdf(join(dir, "report.html"), join(dir, "report.pdf"));
    if (!printed.ok) throw new Error(`the PDF could not be printed (${printed.why}); sign without --pdf and print it later (swarm.sh releases <id> --print ${version})`);
    pdf = { path: `${RELEASE_DIR}/v${version}/report.pdf`, sha256: sha256(readFileSync(join(dir, "report.pdf"))), bytes: readFileSync(join(dir, "report.pdf")).length, printer: printed.printer };
  }
  // Every print of an earlier release's HTML, carried into this one.
  const prints: ReleaseRecord["report"]["prints"] = [];
  for (const r of existing) {
    for (const f of readdirSync(r.dir).filter((n) => /^print-\d+\.json$/.test(n)).sort()) {
      try {
        const p = JSON.parse(readFileSync(join(r.dir, f), "utf8")) as { pdf?: { sha256?: string } };
        prints.push({ path: `${RELEASE_DIR}/v${r.version}/${f}`, sha256: sha256(readFileSync(join(r.dir, f))), release: r.version, pdf_sha256: String(p.pdf?.sha256 ?? "") });
      } catch {
        // an unreadable print record is not carried; verify names it by its absence
      }
    }
  }
  const reportAbs = join(S, input.reportPath);
  const md = existsSync(reportAbs) ? await hashRegularFile(reportAbs) : null;
  const reviewHead = reviewLines ? { lines: reviewLines, head: lineHashes(reviewRead.slice(0, reviewLines).map((l) => l.text).join("\n")).at(-1) ?? null } : null;
  const read = (rel: string) => (existsSync(join(S, rel)) ? readFileSync(join(S, rel), "utf8") : null);
  const trace = lineHead(read("traces/events.jsonl"));
  const journal = read("store/journal.jsonl");
  const ledgerHead = hashFieldHead(read("ledger/entries.jsonl"));
  const renderer: Record<string, string> = {};
  for (const f of ["scripts/report.ts", "scripts/report-body.ts", "ui/src/lib/markdown.ts"]) {
    const s = fileSha(join(ROOT, f));
    if (s) renderer[f] = s;
  }
  const kickoff = (ctx.rec?.provenance as { harness_commit?: string } | undefined)?.harness_commit ?? (typeof ctx.rec?.harness_commit === "string" ? ctx.rec.harness_commit : null);
  const missing = [...sealed.missing];
  if (!md || !("sha256" in md)) missing.push(`there is no ${input.reportPath}: the release binds the rendering alone`);
  if (!ctx.run) missing.push("the run's id is not known here: its examiner's review is not bound");
  const host = hostExposure(ctx);
  const keyWord = signer.key_kind === "pkcs11" ? `the e-signature certificate ${signer.fingerprint}${signer.certificate?.cn ? ` (CN ${signer.certificate.cn})` : ""}` : signer.key_kind === "fido" ? `the FIDO key ${signer.fingerprint}` : `the key ${signer.fingerprint}`;
  return {
    kind: RELEASE_KIND,
    schema: RELEASE_SCHEMA,
    run: ctx.run,
    version,
    state: input.state,
    at,
    reason: input.reason,
    prev: prevRel?.sha256 ? { version: prevRel.version, sha256: prevRel.sha256, signature_sha256: fileSha(releaseSigPath(prevRel.dir)) } : null,
    signer,
    statement:
      input.state === "adopted"
        ? `Adopted by ${signer.examiner?.name ?? "the examiner"} (${signer.examiner?.organisation ?? "?"}), an examiner enrolled on this install, with ${keyWord}. The conclusions this release lists as adopted or qualified are the examiner's; the ones withdrawn or rendered inconclusive are not conclusions; every other one is the agents' conclusion, not adopted.`
        : `Sealed by this install's machine key (${signer.fingerprint}) when custody was taken: a record of what the host held then. The machine key is not an examiner. No one has adopted this release: every conclusion in it is the agents'.`,
    report: {
      markdown: md && "sha256" in md ? { path: input.reportPath, sha256: md.sha256, sealed: sealed.reportSealed } : null,
      html: { path: `${RELEASE_DIR}/v${version}/report.html`, sha256: sha256(html), bytes: Buffer.byteLength(html), generated_at: at, watermark: input.state === "adopted" && version >= 1 ? null : "DRAFT" },
      pdf,
      prints,
    },
    custody: { sha256: sha256(o.custodyText), at: custody.at ?? null, anchor: basename(ctx.anchorFile), summary: custody.summary ?? null },
    sealed_index: custody.artifacts?.index_sha256 ? { sha256: custody.artifacts.index_sha256, files: custody.artifacts.files ?? null } : null,
    chains: {
      ledger: { entries: ledgerHead.lines, head: ledgerHead.head },
      attestations: hashFieldHead(read("ledger/attestations.jsonl")),
      disputes: hashFieldHead(read("ledger/disputes.jsonl")),
      journal: journal === null ? null : lineHead(journal),
      trace: { lines: trace.lines, last_line_sha256: trace.head, sealed_lines: (custody.seal?.trace?.lines as number | undefined) ?? null },
      review: reviewHead,
      ledger_versions: [...new Set(ledger.map((e) => Number(e.v ?? 1)))].sort((a, b) => a - b),
    },
    versions: {
      dfirswarm: (() => {
        try {
          return String((JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version?: string }).version ?? "unknown");
        } catch {
          return "unknown (no package.json beside the scripts)";
        }
      })(),
      harness_commit_at_kickoff: kickoff ?? null,
      harness_commit_now: git(["rev-parse", "HEAD"]),
      harness_dirty_now: (() => {
        const s = git(["status", "--porcelain", "--untracked-files=no"]);
        return s === null ? null : s.length > 0;
      })(),
      renderer_sha256: sha256(Object.entries(renderer).map(([f, s]) => `${s}  ${f}`).join("\n")),
      release_sha256: sha256(["scripts/release.ts", "scripts/release-record.ts"].map((f) => `${fileSha(join(ROOT, f)) ?? "missing"}  ${f}`).join("\n")),
      run_contract_sha256: fileSha(join(S, "SWARM.md")),
    },
    models: custody.models ?? null,
    evidence_cutoff: { at: custody.at ?? null, note: CUTOFF_NOTE },
    adoption: input.adoption,
    timestamp: {
      authority: input.signer.kind === "examiner" ? (input.signer.examiner.tsa?.url ?? null) : draftTsa(ctx).url,
      note: `A token, when there is one, is over ${releaseSigName({ signer })} and kept beside it (${releaseSigName({ signer })}.tsr, timestamp.json): it cannot be inside the bytes it dates. Without one, the release's time is this host's clock.`,
    },
    missing,
    host,
    ...(input.policy ? { policy: input.policy } : {}),
  };
}

/**
 * Put a signed release in place: its files read-only, the directory renamed
 * from its working name to release/v<N> only once the signature verifies
 * (a failure leaves nothing that looks like a release), and its line in the
 * anchor beside the run.
 */
function placeRelease(ctx: RunCtx, dir: string, record: ReleaseRecord, sigFile: string, sigSha: string, say: (s: string) => void): Written {
  for (const f of readdirSync(dir)) chmodSync(join(dir, f), 0o444);
  const target = releaseDir(ctx.sandbox, record.version);
  if (existsSync(target)) throw new Error(`${target} appeared while this release was being made: nothing is written over it`);
  renameSync(dir, target);
  const text = readFileSync(join(target, "release.json"), "utf8");
  const sha = sha256(text);
  const line = digestLine(record, sha, sigSha);
  const qr = qrString(record, sha);
  anchorRelease(ctx.anchorFile, { version: record.version, at: record.at, state: record.state, sha256: sha, signature_sha256: sigSha, signer: record.signer.fingerprint, principal: record.signer.principal, line }, say);
  void sigFile;
  return { version: record.version, dir: target, sha256: sha, sigSha, record, line, qr };
}

/** The machine's release: rendered, recorded, sealed with the machine key and put in place, in one step. */
async function writeRelease(ctx: RunCtx, input: ReleaseInput & { signer: { kind: "machine"; machine: MachineSigner } }, say: (s: string) => void): Promise<Written> {
  const S = ctx.sandbox;
  const { custodyText, custody, sealed } = await sealableCustody(ctx, input.reportPath);
  const existing = readReleases(S);
  const broken = existing.find((r) => !r.record);
  if (broken) throw new Error(`release v${broken.version} cannot be read (${broken.error}): nothing is added after it`);
  const version = existing.length ? (existing.at(-1) as { version: number }).version + 1 : 0;
  const base = join(S, RELEASE_DIR);
  mkdirSync(base, { recursive: true });
  const tmp = join(base, `.v${version}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  mkdirSync(tmp);
  try {
    const record = await buildRelease(ctx, input, tmp, { version, prevRel: existing.at(-1) ?? null, at: new Date().toISOString(), custodyText, custody, sealed });
    const text = `${JSON.stringify(record, null, 2)}\n`;
    writeFileSync(join(tmp, "release.json"), text);
    const signed = sshSign(join(tmp, "release.json"), input.signer.machine.key, RELEASE_NAMESPACE);
    if (!signed.ok) throw new Error(`release v${version} could not be sealed: ${signed.why}`);
    const check = checkSshSignature({ file: join(tmp, "release.json"), sig: signed.sig, namespace: RELEASE_NAMESPACE, principal: record.signer.principal, publicKey: record.signer.public });
    if (check.state !== "unchecked") throw new Error(`the seal just made does not verify under the machine key the release names: ${check.detail}`);
    return placeRelease(ctx, tmp, record, "release.json.sig", signed.sha256, say);
  } catch (err) {
    rmSync(tmp, { recursive: true, force: true });
    throw err;
  }
}

/** A release's line added to the anchor beside the run, the kickoff's and custody's fields left as they are. */
function anchorRelease(anchorFile: string, entry: Record<string, unknown>, say: (s: string) => void): void {
  try {
    let anchor: Record<string, unknown> = {};
    try {
      anchor = JSON.parse(readFileSync(anchorFile, "utf8")) as Record<string, unknown>;
    } catch {
      anchor = {};
    }
    const releases = Array.isArray(anchor.releases) ? (anchor.releases as unknown[]) : [];
    releases.push(entry);
    writeFileNoFollowSync(dirname(anchorFile), basename(anchorFile), `${JSON.stringify({ ...anchor, releases }, null, 2)}\n`, 0o444);
  } catch (err) {
    say(`WARN: the release could not be added to the anchor beside the run (${(err as Error).message}): verify will say it is not anchored`);
  }
}

/** Where a draft's timestamp comes from: the run's custody set-up, or the environment's. */
function draftTsa(ctx: RunCtx): { url: string | null; ca: string | null } {
  const seal = (ctx.rec?.custody_seal ?? null) as { timestamp_url?: string | null; timestamp_ca?: string | null } | null;
  return { url: seal?.timestamp_url ?? process.env.SWARM_CUSTODY_TSA_URL ?? null, ca: seal?.timestamp_ca ?? process.env.SWARM_CUSTODY_TSA_CA ?? null };
}

/** Where a release's digest line is copied to: the run's --anchor-mirror, or the environment's. */
function mirrorTarget(ctx: RunCtx): string | null {
  const m = ctx.rec?.anchor_mirror;
  return typeof m === "string" && m ? m : process.env.SWARM_ANCHOR_MIRROR || null;
}

function printPdf(html: string, pdf: string): { ok: true; printer: string } | { ok: false; why: string } {
  const r = spawnSync("bash", [join(ROOT, "scripts", "print-pdf.sh"), html, pdf], { encoding: "utf8", timeout: 10 * 60_000 });
  if (r.status !== 0 || !existsSync(pdf)) return { ok: false, why: `${r.stderr || r.stdout}`.trim() || `exit ${r.status}` };
  return { ok: true, printer: `scripts/print-pdf.sh (${process.env.SWARM_CHROME ? basename(process.env.SWARM_CHROME) : "the first Chrome, Chromium or Edge found"})` };
}

// --- the acts -----------------------------------------------------------------------------

/** The machine's draft, once per custody verdict unless a reason is given for another. */
export async function draftRelease(ctx: RunCtx, o: { reason?: string; home?: string; say?: (s: string) => void } = {}): Promise<{ written: Written | null; skipped: string | null }> {
  const say = o.say ?? (() => undefined);
  const custodySha = fileSha(join(ctx.sandbox, "custody.json"));
  if (!custodySha) throw new Error("there is no custody verdict to release: swarm.sh stop takes custody (and writes the draft)");
  const existing = readReleases(ctx.sandbox);
  const same = existing.find((r) => r.record?.custody?.sha256 === custodySha);
  if (same && !o.reason) return { written: null, skipped: `release v${same.version} already binds this custody verdict (${same.record?.state}); a new draft needs a reason (--reason TEXT)` };
  const machine = machineSigner(o.home ?? dfirswarmHome());
  if ("why" in machine) throw new Error(`no machine key to seal the draft with: ${machine.why}`);
  const reviewLines = ctx.run ? (await readReviews(ctx.runsDir, ctx.run).catch(() => [])).length : 0;
  const written = await writeRelease(
    ctx,
    {
      state: "draft",
      reason: o.reason ?? (existing.length ? `custody taken again (${readCustodyAt(ctx) ?? "?"})` : "custody taken at stop"),
      signer: { kind: "machine", machine },
      adoption: null,
      renderAdoption: null,
      reviewLines,
      pdf: false,
      reportPath: "work/report.md",
    },
    say,
  );
  await afterRelease(ctx, written, { tsa: draftTsa(ctx), say });
  return { written, skipped: null };
}

function readCustodyAt(ctx: RunCtx): string | null {
  try {
    return String((JSON.parse(readFileSync(join(ctx.sandbox, "custody.json"), "utf8")) as { at?: string }).at ?? "") || null;
  } catch {
    return null;
  }
}

/** What follows a release, none of it blocking: a timestamp when an authority is set up, a mirror when one is named. */
async function afterRelease(ctx: RunCtx, w: Written, o: { tsa: { url: string | null; ca: string | null }; noTimestamp?: boolean; say: (s: string) => void }): Promise<void> {
  if (o.tsa.url && !o.noTimestamp) {
    const t = await timestampRelease(w.dir, { url: o.tsa.url, ca: o.tsa.ca, releaseAt: w.record.at });
    o.say(t.ok ? `Timestamp:    ${t.note}` : `WARN: release v${w.version} was not timestamped (${t.why}); swarm.sh timestamp ${ctx.run ?? "<id>"} obtains a token later`);
  }
  const target = mirrorTarget(ctx);
  if (target) {
    const m = mirrorRelease(ctx.sandbox, w.dir, target);
    o.say(m.ok ? `Mirror:       ${m.note}` : `WARN: the release's digest line did not reach ${target} (${m.why})`);
  }
}

/**
 * Every disposition the review holds, and what the release gate makes of
 * the standing conclusions: the dispositions (enriched with the entry's
 * kind and section), the answers left to the agents, the defective ones and
 * how each is resolved, the technical reviews (each with where it stands),
 * and why a release is refused (a defective conclusion neither withdrawn nor
 * rendered inconclusive, or a review whose chain is broken).
 */
export async function adoptionGate(ctx: RunCtx): Promise<{ adoption: ReleaseAdoption; render: NonNullable<RenderRelease["adoption"]>; refused: string[]; reviewLines: number }> {
  if (!ctx.run) throw new Error("the run's id is not known: pass --run ID");
  const st = await adoptionState({ runsDir: ctx.runsDir, run: ctx.run, sandbox: ctx.sandbox });
  const refused: string[] = [];
  if (!st.chain.ok) refused.push(`the examiner's review is broken (${st.chain.reason}): nothing is adopted from it`);
  for (const a of st.blocked) refused.push(`E-${a.seq}${a.section ? ` (${a.section})` : ""} is not supported as it stands (${a.defects.map((d) => d.what).join("; ")}) and is neither withdrawn nor rendered inconclusive: --reject ${a.seq} --note TEXT or --inconclusive ${a.seq} --note TEXT (an unsupported conclusion is not waived; repairing its support is a new examination)`);
  for (const t of st.technical) if (t.status === "bad-signature") refused.push(`the technical review by ${t.reviewer.name} (review line ${t.review_seq}): ${t.words}`);
  const lines = (await readReviews(ctx.runsDir, ctx.run)).filter((l) => typeof l.action === "string");
  const ledger = await readLedger(ctx.sandbox, { raw: true });
  const bySeq = new Map<number, LedgerEntry>(ledger.map((e) => [e.seq, e]));
  const replaced = supersededBy(ledger);
  const dispositions = [...dispositionsOf(lines).values()]
    .map((d) => {
      const e = bySeq.get(d.seq);
      return { seq: d.seq, hash: d.hash, kind: e?.kind ?? null, section: typeof e?.section === "string" ? e.section : null, disposition: d.disposition, note: d.note, examiner: d.examiner, at: d.at, review_seq: d.review_seq };
    })
    .sort((a, b) => a.seq - b.seq);
  const standing = st.answers.filter((a) => a.superseded_by === null);
  const count = (s: string) => standing.filter((a) => a.standing === s).length;
  const openRejections = [...dispositionsOf(lines).values()].filter((d) => d.disposition === "reject" && bySeq.get(d.seq)?.kind !== "answer" && !replaced.has(d.seq)).map((d) => d.seq);
  const adoption: ReleaseAdoption = {
    review: { lines: st.lines, head: st.head },
    dispositions,
    not_adopted: standing.filter((a) => a.standing === "not adopted").map((a) => ({ seq: a.seq, hash: a.hash, section: a.section })),
    defects: standing.filter((a) => a.defects.length).map((a) => ({ seq: a.seq, defects: a.defects.map((d) => d.what), disposition: a.standing })),
    technical_review: st.technical,
    open_rejections: openRejections,
    scope: st.scope,
  };
  const render = {
    adopted: count("adopted"),
    qualified: count("qualified"),
    withdrawn: count("withdrawn"),
    inconclusive: count("inconclusive"),
    not_adopted: count("not adopted"),
    scope: st.scope,
    technical: st.technical.map((t) => `${t.reviewer.name} (${t.reviewer.competence})${t.outcome ? `, ${t.outcome}` : ""}: ${t.methods_checked}; ${t.words}`),
  };
  return { adoption, render, refused, reviewLines: st.lines };
}

/** The examiner named, or the only one enrolled; refused when none can sign. */
function pickExaminer(o: { examiner?: string; home: string }): { examiner: Person; sha256: string } {
  let ex: { examiner: Examiner; sha256: string } | { why: string };
  if (o.examiner) ex = loadExaminer(o.examiner, o.home);
  else {
    const all = listExaminers(o.home);
    ex = all.length === 1 ? loadExaminer(all[0].id, o.home) : { why: all.length ? `${all.length} examiners are enrolled (${all.map((e) => e.id).join(", ")}): name one (--examiner ID)` : "no examiner is enrolled on this install: swarm.sh examiner enroll" };
  }
  if ("why" in ex) throw new Error(`a release is signed by an enrolled examiner: ${ex.why}`);
  if (ex.examiner.role !== "examiner") {
    throw new Error(
      ex.examiner.role === "reviewer"
        ? `${ex.examiner.name} (${ex.examiner.id}) is enrolled as a technical reviewer, not an examiner: a reviewer signs their own review, never a release`
        : `${ex.examiner.name} (${ex.examiner.id}) is enrolled as ${roleWords(ex.examiner.role)}, not an examiner: ${ex.examiner.role === "analyst" ? "an analyst adds questions to a case" : "an observer proposes questions"}, and never signs a release`,
    );
  }
  const k = ex.examiner.key;
  if (k.kind !== "pkcs11" && !existsSync(k.path)) throw new Error(`the examiner's key is not at ${k.path}`);
  if (k.kind === "pkcs11" && !existsSync(k.module)) throw new Error(`the examiner's PKCS#11 module is not at ${k.module}`);
  return ex;
}

/** Why no bound technical review stands in the examiner's way: a reviewer who is the examiner is refused. */
function independence(technical: TechnicalReview[], p: Person): string[] {
  const out: string[] = [];
  for (const t of technical) {
    const clash = independenceConflict({ id: t.reviewer.id ?? null, name: t.reviewer.name, fingerprint: t.reviewer.fingerprint ?? t.countersign?.fingerprint ?? null }, { id: p.id, name: p.name, fingerprint: p.key.fingerprint });
    if (clash) out.push(`the technical reviewer at review line ${t.review_seq} (${t.reviewer.name}) ${clash}: one person is never examiner and reviewer on one run`);
  }
  return out;
}

export type Prepared = {
  nonce: string;
  run: string;
  version: number;
  prepared_at: string;
  expires_at: string;
  pending: string;
  report: { html: { path: string; sha256: string; bytes: number }; markdown: { path: string; sha256: string } | null; pdf: { sha256: string } | null };
  record_sha256: string;
  gate: { adopted: number; qualified: number; withdrawn: number; inconclusive: number; not_adopted: number; scope: "answers" | "report"; defects: number; open_rejections: number[] };
  technical: Array<{ review_seq: number; reviewer: string; outcome: string | null; status: string; words: string }>;
  policy: NonNullable<ReleaseRecord["policy"]> & { satisfied: boolean };
  signer: { id: string; name: string; organisation: string; kind: "ssh" | "fido" | "pkcs11"; fingerprint: string; words: string; secret: "passphrase" | "fido-pin" | "pin" | null; touch: boolean };
  statement: string;
  reason: string;
};

type PendingMeta = {
  kind: "dfirswarm-pending-release";
  nonce: string;
  run: string;
  version: number;
  prepared_at: string;
  via: "console" | "cli";
  examiner: { id: string; enrolment_sha256: string; fingerprint: string; kind: string };
  html_sha256: string;
  pdf_sha256: string | null;
  record_sha256: string;
  review: { lines: number; head: string | null };
  custody_sha256: string;
  report_path: string;
  report_sha256: string | null;
  prev_sha256: string | null;
};

const pendingDir = (S: string, nonce: string) => join(S, RELEASE_DIR, `.pending-${nonce}`);

/** Prepared releases past their fifteen minutes are removed: a seal after them prepares again. */
function sweepPending(S: string, now = Date.now()): void {
  const base = join(S, RELEASE_DIR);
  if (!existsSync(base)) return;
  for (const n of readdirSync(base)) {
    if (!/^\.pending-[0-9a-f]{32}$/.test(n)) continue;
    const dir = join(base, n);
    try {
      const meta = JSON.parse(readFileSync(join(dir, "pending.json"), "utf8")) as PendingMeta;
      if (now - Date.parse(meta.prepared_at) <= PENDING_TTL_MS) continue;
    } catch {
      // unreadable: removed like an expired one
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A prepared release given up (the examiner did not confirm): removed. */
export function discardPrepared(ctx: RunCtx, nonce: string): boolean {
  if (!NONCE.test(nonce)) return false;
  const dir = pendingDir(ctx.sandbox, nonce);
  if (!existsSync(dir)) return false;
  rmSync(dir, { recursive: true, force: true });
  return true;
}

/**
 * The first half of an adoption: everything the examiner is asked to
 * confirm, rendered once. The final bytes (no DRAFT mark) are rendered with a
 * fixed time into release/.pending-<nonce>/ (0700, files 0600), with the
 * record that will be signed, and nothing after the examiner's consent is
 * rendered again. Refused when the release gate refuses, when the policy
 * wants a signed technical review there is not, or when a technical reviewer
 * is the examiner. A run with no release gets the machine's draft first.
 */
export async function prepareRelease(ctx: RunCtx, o: { examiner?: string; pdf?: boolean; amendReason?: string; report?: string; home?: string; via?: "console" | "cli"; say?: (s: string) => void }): Promise<Prepared> {
  const say = o.say ?? (() => undefined);
  const home = o.home ?? dfirswarmHome();
  const via = o.via ?? "cli";
  const ex = pickExaminer({ examiner: o.examiner, home });
  if (via === "console") {
    const refused = consoleRefusal(ex.examiner);
    if (refused) throw new Error(refused);
  }
  if (!ctx.run) throw new Error("the run's id is not known: pass --run ID");
  const reportPath = o.report ?? "work/report.md";
  if (!isSandboxPath(reportPath)) throw new Error(`${JSON.stringify(reportPath)} is not a path under the run`);
  if (!fileSha(join(ctx.sandbox, reportPath))) throw new Error(`there is no ${reportPath} in run ${ctx.run} to sign over: a sign-off is over the report the examiner read (--report PATH names another)`);
  let releases = readReleases(ctx.sandbox);
  const adopted = [...releases].reverse().find((r) => r.record?.state === "adopted");
  if (adopted && !o.amendReason?.trim()) throw new Error(`release v${adopted.version} is adopted already: a later adoption is an amendment and says why (--amend-reason TEXT). A new examination is a new run.`);
  if (!adopted && o.amendReason) throw new Error("there is no adopted release to amend: sign without --amend-reason");
  const gate = await adoptionGate(ctx);
  const policy = technicalReviewPolicy(ctx);
  const satisfied = gate.adoption.technical_review.some(satisfiesPolicy);
  const refused = [...gate.refused, ...independence(gate.adoption.technical_review, ex.examiner)];
  if (policy.require_technical_review && !satisfied) refused.push(`${policy.source} requires a technical review signed by its reviewer, over the run as it stands, whose outcome is not a disagreement: ${gate.adoption.technical_review.length ? gate.adoption.technical_review.map((t) => `review line ${t.review_seq} by ${t.reviewer.name} is ${t.outcome ?? "without an outcome"}, ${t.words}`).join("; ") : NO_TECHNICAL_REVIEW.toLowerCase()}`);
  if (refused.length) throw new Error(`the release is refused:\n  - ${refused.join("\n  - ")}`);
  // A run with no release yet (stopped before releases, or with custody later) gets the machine's draft first.
  if (!releases.length) {
    const d = await draftRelease(ctx, { home, reason: "the machine's draft, written before the first adoption: none was written when custody was taken", say });
    if (d.written) say(`Release:      v${d.written.version} DRAFT sealed first by the machine key (${d.written.record.signer.fingerprint})`);
    releases = readReleases(ctx.sandbox);
  }
  const broken = releases.find((r) => !r.record);
  if (broken) throw new Error(`release v${broken.version} cannot be read (${broken.error}): nothing is added after it`);
  sweepPending(ctx.sandbox);
  const { custodyText, custody, sealed } = await sealableCustody(ctx, reportPath);
  const nonce = randomBytes(16).toString("hex");
  const dir = pendingDir(ctx.sandbox, nonce);
  mkdirSync(join(ctx.sandbox, RELEASE_DIR), { recursive: true });
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  const prevRel = releases.at(-1) ?? null;
  const version = prevRel ? prevRel.version + 1 : 0;
  const preparedAt = new Date().toISOString();
  try {
    const record = await buildRelease(
      ctx,
      {
        state: "adopted",
        reason: adopted ? `amendment of v${adopted.version}: ${o.amendReason?.trim()}` : "adopted by the examiner",
        signer: { kind: "examiner", examiner: ex.examiner, enrolmentSha: ex.sha256 },
        adoption: gate.adoption,
        renderAdoption: gate.render,
        reviewLines: gate.reviewLines,
        pdf: Boolean(o.pdf),
        reportPath,
        policy,
      },
      dir,
      { version, prevRel, at: preparedAt, custodyText, custody, sealed },
    );
    const recordText = `${JSON.stringify(record, null, 2)}\n`;
    writeFileSync(join(dir, "record.json"), recordText, { mode: 0o600 });
    const html = readFileSync(join(dir, "report.html"));
    const meta: PendingMeta = {
      kind: "dfirswarm-pending-release",
      nonce,
      run: ctx.run,
      version,
      prepared_at: preparedAt,
      via,
      examiner: { id: ex.examiner.id, enrolment_sha256: ex.sha256, fingerprint: ex.examiner.key.fingerprint, kind: ex.examiner.key.kind },
      html_sha256: sha256(html),
      pdf_sha256: record.report.pdf?.sha256 ?? null,
      record_sha256: sha256(recordText),
      review: gate.adoption.review,
      custody_sha256: sha256(custodyText),
      report_path: reportPath,
      report_sha256: record.report.markdown?.sha256 ?? null,
      prev_sha256: prevRel?.sha256 ?? null,
    };
    writeFileSync(join(dir, "pending.json"), `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600 });
    for (const f of readdirSync(dir)) chmodSync(join(dir, f), 0o600);
    const needs = keyNeeds(ex.examiner);
    return {
      nonce,
      run: ctx.run,
      version,
      prepared_at: preparedAt,
      expires_at: new Date(Date.parse(preparedAt) + PENDING_TTL_MS).toISOString(),
      pending: dir,
      report: { html: { path: join(dir, "report.html"), sha256: meta.html_sha256, bytes: html.length }, markdown: record.report.markdown ? { path: record.report.markdown.path, sha256: record.report.markdown.sha256 } : null, pdf: record.report.pdf ? { sha256: record.report.pdf.sha256 } : null },
      record_sha256: meta.record_sha256,
      gate: { adopted: gate.render.adopted, qualified: gate.render.qualified, withdrawn: gate.render.withdrawn, inconclusive: gate.render.inconclusive, not_adopted: gate.render.not_adopted, scope: gate.render.scope, defects: gate.adoption.defects.length, open_rejections: gate.adoption.open_rejections },
      technical: gate.adoption.technical_review.map((t) => ({ review_seq: t.review_seq, reviewer: t.reviewer.name, outcome: t.outcome ?? null, status: t.status ?? "recorded", words: t.words ?? "" })),
      policy: { ...policy, satisfied },
      signer: { id: ex.examiner.id, name: ex.examiner.name, organisation: ex.examiner.organisation, kind: ex.examiner.key.kind, fingerprint: ex.examiner.key.fingerprint, words: keyWords(ex.examiner.key), ...needs },
      statement: CONSENT_STATEMENT,
      reason: record.reason,
    };
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

/**
 * The second half: the prepared release signed, exactly as prepared and
 * shown. Refused when the nonce is unknown or used, when the prepared release
 * is older than fifteen minutes, when the bytes shown are not the bytes
 * prepared, when the review, custody, the report or the releases moved since,
 * when the gate or the policy now refuses, or when the key is not one this
 * way of signing takes. A wrong passphrase or PIN leaves the prepared release
 * as it was (and throws WrongSecretError); a seal that succeeds renames it
 * into place, so its nonce is spent.
 */
export async function sealPrepared(
  ctx: RunCtx,
  o: { nonce: string; shownSha256: string; examiner: string; secret: Buffer | null; consent: "confirmed" | "presented"; via: "console" | "cli"; home?: string; noTimestamp?: boolean; say?: (s: string) => void; now?: number },
): Promise<Written> {
  const say = o.say ?? (() => undefined);
  const home = o.home ?? dfirswarmHome();
  if (!NONCE.test(o.nonce)) throw new Error("that is not a prepared release's nonce");
  if (!ctx.run) throw new Error("the run's id is not known: pass --run ID");
  const releases = readReleases(ctx.sandbox);
  const used = releases.find((r) => r.record?.signing?.nonce === o.nonce);
  if (used) throw new Error(`the prepared release ${o.nonce} was sealed already, as v${used.version}: a nonce is used once`);
  const dir = pendingDir(ctx.sandbox, o.nonce);
  let meta: PendingMeta;
  try {
    meta = JSON.parse(readFileSync(join(dir, "pending.json"), "utf8")) as PendingMeta;
  } catch {
    throw new Error(`there is no prepared release ${o.nonce} in run ${ctx.run}: it expired, was discarded, or was never prepared. Prepare it again.`);
  }
  const now = o.now ?? Date.now();
  if (now - Date.parse(meta.prepared_at) > PENDING_TTL_MS) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`the prepared release is older than 15 minutes (prepared ${meta.prepared_at}): nothing was signed. Prepare it again and read what it shows.`);
  }
  const stale = (why: string): never => {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`the prepared release no longer stands (${why}): nothing was signed. Prepare it again.`);
  };
  if (meta.run !== ctx.run) stale(`it was prepared for run ${meta.run}`);
  if (meta.examiner.id !== o.examiner) throw new Error(`the prepared release is ${meta.examiner.id}'s to seal, not ${o.examiner}'s`);
  const ex = loadExaminer(o.examiner, home);
  if ("why" in ex) throw new Error(`a release is signed by an enrolled examiner: ${ex.why}`);
  if (ex.sha256 !== meta.examiner.enrolment_sha256 || ex.examiner.key.fingerprint !== meta.examiner.fingerprint) stale(`${ex.examiner.name}'s enrolment changed since it was prepared`);
  if (o.via === "console") {
    const refused = consoleRefusal(ex.examiner);
    if (refused) throw new Error(refused);
  }
  // The bytes: what was shown is what was prepared is what is signed.
  const htmlSha = fileSha(join(dir, "report.html"));
  if (o.shownSha256 !== meta.html_sha256) throw new Error(`the report shown (sha256 ${o.shownSha256}) is not the one prepared (${meta.html_sha256}): nothing was signed`);
  if (htmlSha !== meta.html_sha256) stale("its report.html changed after it was prepared");
  if (meta.pdf_sha256 && fileSha(join(dir, "report.pdf")) !== meta.pdf_sha256) stale("its report.pdf changed after it was prepared");
  const recordText = readFileSync(join(dir, "record.json"), "utf8");
  if (sha256(recordText) !== meta.record_sha256) stale("its record changed after it was prepared");
  // The run: its review, custody, the report and the releases as they were prepared over.
  const reviewNow = await readReviews(ctx.runsDir, ctx.run);
  const headNow = reviewNow.length ? sha256(reviewNow[reviewNow.length - 1].text) : null;
  if (reviewNow.length !== meta.review.lines || headNow !== meta.review.head) stale(`the examiner's review moved since (${meta.review.lines} lines then, ${reviewNow.length} now)`);
  if (fileSha(join(ctx.sandbox, "custody.json")) !== meta.custody_sha256) stale("custody.json changed since");
  await sealableCustody(ctx, meta.report_path).catch((err: Error) => stale(err.message));
  if (fileSha(join(ctx.sandbox, meta.report_path)) !== meta.report_sha256) stale(`${meta.report_path} changed since`);
  const last = releases.at(-1) ?? null;
  if ((last?.version ?? -1) !== meta.version - 1 || (last?.sha256 ?? null) !== meta.prev_sha256) stale(`another release was written since (the latest is v${last?.version ?? "none"})`);
  // The gate and the policy, again: consent never waives a defect.
  const gate = await adoptionGate(ctx);
  const policy = technicalReviewPolicy(ctx);
  const refused = [...gate.refused, ...independence(gate.adoption.technical_review, ex.examiner)];
  if (policy.require_technical_review && !gate.adoption.technical_review.some(satisfiesPolicy)) refused.push(`${policy.source} requires a current technical review signed by its reviewer whose outcome is not a disagreement`);
  if (refused.length) throw new Error(`the release is refused:\n  - ${refused.join("\n  - ")}`);
  const record = JSON.parse(recordText) as ReleaseRecord;
  const person = ex.examiner;
  const k = person.key;
  const confirmedAt = new Date(now).toISOString();
  const signing: ReleaseSigning = {
    via: o.via,
    consent: o.consent,
    statement: CONSENT_STATEMENT,
    shown_sha256: o.shownSha256,
    nonce: o.nonce,
    prepared_at: meta.prepared_at,
    confirmed_at: confirmedAt,
    key: { kind: k.kind, fingerprint: k.fingerprint },
    ssh_keygen: k.kind === "pkcs11" ? null : k.kind === "fido" ? k.ssh_keygen : sshKeygen(),
    openssl: k.kind === "pkcs11" ? ("path" in opensslBinary() ? (opensslBinary() as { path: string }).path : null) : null,
  };
  const final: ReleaseRecord = { ...record, signing };
  const text = `${JSON.stringify(final, null, 2)}\n`;
  const file = join(dir, "release.json");
  const sigName = releaseSigName(final);
  const clean = () => {
    for (const f of ["release.json", sigName, "report.pdf.p7s"]) rmSync(join(dir, f), { force: true });
  };
  writeFileSync(file, text, { mode: 0o600 });
  const signed = signAs(person, file, RELEASE_NAMESPACE, o.secret, { dropAgent: o.via === "console" });
  if (!signed.ok) {
    clean();
    if (signed.wrongSecret) throw new WrongSecretError(`nothing was signed: ${signed.why}`);
    throw new Error(`release v${meta.version} could not be signed: ${signed.why}`);
  }
  if (record.report.pdf && k.kind === "pkcs11") {
    const pdf = signAs(person, join(dir, "report.pdf"), RELEASE_NAMESPACE, o.secret);
    if (!pdf.ok) {
      clean();
      if (pdf.wrongSecret) throw new WrongSecretError(`nothing was signed: ${pdf.why}`);
      throw new Error(`report.pdf could not be signed on the token: ${pdf.why}`);
    }
  }
  const check = verifyAs(person, file, signed.sig, RELEASE_NAMESPACE);
  if (check.state !== "unchecked") {
    clean();
    throw new Error(`the signature just made does not verify under the key the release names: ${check.detail}`);
  }
  rmSync(join(dir, "record.json"), { force: true });
  rmSync(join(dir, "pending.json"), { force: true });
  const written = placeRelease(ctx, dir, final, sigName, signed.sha256, say);
  // The review's sign-off, after the signature, naming what was signed.
  try {
    await appendReview(ctx.runsDir, ctx.run, ctx.sandbox, {
      action: "sign",
      examiner: person.name,
      examinerId: person.id,
      key: k.fingerprint,
      report: meta.report_path,
      release: { version: written.version, sha256: written.sha256, signature_sha256: written.sigSha },
    });
  } catch (err) {
    say(`WARN: release v${written.version} is signed and in place, and the review's sign-off line naming it was not written (${(err as Error).message}); verify will say so`);
  }
  await afterRelease(ctx, written, { tsa: { url: person.tsa?.url ?? null, ca: person.tsa?.ca ?? null }, noTimestamp: o.noTimestamp, say });
  return written;
}

/**
 * An enrolled examiner's adoption in one call: prepared and sealed at once,
 * the consent recorded as presented unless the caller says it was confirmed.
 * The command line and the console prepare, show and ask in between.
 */
export async function signRelease(ctx: RunCtx, o: { examiner?: string; pdf?: boolean; amendReason?: string; report?: string; noTimestamp?: boolean; home?: string; say?: (s: string) => void; secret?: Buffer | null; consent?: "confirmed" | "presented"; via?: "console" | "cli" }): Promise<Written> {
  const p = await prepareRelease(ctx, { examiner: o.examiner, pdf: o.pdf, amendReason: o.amendReason, report: o.report, home: o.home, via: o.via, say: o.say });
  try {
    return await sealPrepared(ctx, { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: p.signer.id, secret: o.secret ?? null, consent: o.consent ?? "presented", via: o.via ?? "cli", home: o.home, noTimestamp: o.noTimestamp, say: o.say });
  } catch (err) {
    discardPrepared(ctx, p.nonce);
    throw err;
  }
}

// --- after a release: print, timestamp, mirror, OpenTimestamps, a transparency log --------------

/** A PDF of a release's HTML, printed after it was sealed: beside it, never in it; the next release binds the record. */
export function printRelease(S: string, version?: number): { pdf: string; record: string; sha256: string } {
  const r = pickRelease(S, version);
  let k = 1;
  while (existsSync(join(r.dir, `print-${k}.json`))) k += 1;
  const pdf = join(r.dir, `print-${k}.pdf`);
  const printed = printPdf(join(r.dir, "report.html"), pdf);
  if (!printed.ok) throw new Error(`release v${r.version}'s HTML could not be printed: ${printed.why}`);
  const bytes = readFileSync(pdf);
  const htmlSha = sha256(readFileSync(join(r.dir, "report.html")));
  const rec = {
    kind: "dfirswarm-release-print",
    release: r.version,
    release_sha256: r.sha256,
    html_sha256: htmlSha,
    html_is_the_release: htmlSha === r.record.report.html.sha256,
    pdf: { path: `${RELEASE_DIR}/v${r.version}/print-${k}.pdf`, sha256: sha256(bytes), bytes: bytes.length },
    printed_at: new Date().toISOString(),
    printer: printed.printer,
    note: `A print of release v${r.version}'s HTML, made after that release was sealed: it is not inside it, and the next release binds this record. The PDF's bytes are the printer's; the HTML's are the release's.`,
  };
  writeFileSync(join(r.dir, `print-${k}.json`), `${JSON.stringify(rec, null, 2)}\n`, { mode: 0o444, flag: "wx" });
  chmodSync(pdf, 0o444);
  return { pdf, record: join(r.dir, `print-${k}.json`), sha256: rec.pdf.sha256 };
}

// --- the command line ----------------------------------------------------------------------------

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

/**
 * The command line's adoption: prepare, show what will be signed, ask on the
 * terminal, take the secret there (echo off) or from a descriptor, seal. With
 * --yes only the confirmation is skipped. Null when the examiner said no.
 */
async function signOnTerminal(ctx: RunCtx, args: string[], say: (s: string) => void): Promise<Written | null> {
  const yes = args.includes("--yes");
  const fd = opt(args, "--secret-fd");
  const tty = hasTty();
  if (!yes && !tty) throw new Error("a sign-off asks for the examiner's confirmation on the terminal, and there is none: run it at a terminal, or pass --yes (which skips only the confirmation; the release then records the consent as presented, not confirmed)");
  const p = await prepareRelease(ctx, { examiner: opt(args, "--examiner"), pdf: args.includes("--pdf"), amendReason: opt(args, "--amend-reason"), report: opt(args, "--report"), via: "cli", say });
  const g = p.gate;
  say(`To sign:      release v${p.version} of run ${p.run}, ${p.reason}`);
  say(`Examiner:     ${p.signer.name} (${p.signer.id}), ${p.signer.organisation}`);
  say(`Report:       ${p.report.markdown ? `${p.report.markdown.path} sha256 ${p.report.markdown.sha256}; ` : ""}the release's report.html sha256 ${p.report.html.sha256}${p.report.pdf ? `; report.pdf sha256 ${p.report.pdf.sha256}` : ""}`);
  say(`              read it before you confirm: ${p.report.html.path}`);
  say(`Adoption:     ${g.scope === "answers" ? `${g.adopted} adopted, ${g.qualified} qualified, ${g.withdrawn} withdrawn, ${g.inconclusive} rendered inconclusive, ${g.not_adopted} not adopted (the agents')` : "the report as a whole (a ledger with no answer entries)"}${g.open_rejections.length ? `; rejections standing: ${g.open_rejections.map((n) => `E-${n}`).join(", ")}` : ""}`);
  say(`Technical:    ${p.technical.length ? p.technical.map((t) => `${t.reviewer}${t.outcome ? ` (${t.outcome})` : ""}: ${t.words}`).join("; ") : NO_TECHNICAL_REVIEW}${p.policy.require_technical_review ? ` [required by ${p.policy.source}]` : ""}`);
  say(`Key:          ${p.signer.words}`);
  say(`Statement:    ${p.statement}.`);
  let consent: "confirmed" | "presented" = "presented";
  if (!yes) {
    const ok = await confirmOnTty(`${p.statement}. Adopt and sign release v${p.version} as ${p.signer.name}?`).catch(() => false);
    if (!ok) {
      discardPrepared(ctx, p.nonce);
      say("Not signed:   nothing was written.");
      return null;
    }
    consent = "confirmed";
  }
  const prompt = p.signer.secret === "pin" ? "The e-signature token's PIN (not shown): " : p.signer.secret === "fido-pin" ? "The FIDO key's PIN (not shown): " : "The key's passphrase (not shown): ";
  for (let attempt = 1; ; attempt++) {
    let secret: Buffer | null = null;
    try {
      if (fd !== undefined) secret = readSecretFromFd(Number(fd));
      else if (p.signer.secret) {
        if (!tty) throw new Error(`the ${p.signer.secret === "passphrase" ? "key's passphrase" : "PIN"} is asked on the terminal, and there is none: run it at a terminal, or --secret-fd N`);
        secret = await readFromTty(prompt);
      }
      if (p.signer.touch) say("Touch your key now, every time it blinks.");
      return await sealPrepared(ctx, { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: p.signer.id, secret, consent, via: "cli", noTimestamp: args.includes("--no-timestamp"), say });
    } catch (err) {
      if (err instanceof WrongSecretError && fd === undefined && tty && attempt < 3) {
        say(`WRONG:        ${err.message}; try again (${3 - attempt} left).`);
        continue;
      }
      discardPrepared(ctx, p.nonce);
      throw err;
    } finally {
      wipe(secret);
    }
  }
}

function showLines(ctx: RunCtx): string[] {
  const all = readReleases(ctx.sandbox);
  if (!all.length) return [`Run ${ctx.run ?? ctx.sandbox} has no release.`];
  const out: string[] = [];
  for (const r of all) {
    if (!r.record) {
      out.push(`v${r.version}: ${r.error}`);
      continue;
    }
    const x = r.record;
    const side = readdirSync(r.dir).filter((f) => !["release.json", "release.json.sig", "report.html", "report.pdf"].includes(f)).sort();
    out.push(
      `v${r.version}  ${x.state === "adopted" ? "ADOPTED" : "DRAFT  "}  ${x.at}  ${x.state === "adopted" ? `by ${x.signer.examiner?.name ?? "?"} (${x.signer.examiner?.organisation ?? "?"}), ${x.signer.key_kind === "pkcs11" ? "e-signature certificate" : x.signer.key_kind === "fido" ? "FIDO key" : "key"} ${x.signer.fingerprint}${x.signing ? `, signed ${x.signing.via === "console" ? "from the console" : "on the command line"} (consent ${x.signing.consent})` : ""}` : `sealed by the machine key ${x.signer.fingerprint}, adopted by no one`}`,
      `     ${x.reason}; release.json sha256 ${r.sha256}; report.html ${x.report.html.sha256}${x.report.pdf ? `; report.pdf ${x.report.pdf.sha256}` : ""}`,
    );
    if (x.adoption) out.push(`     ${x.adoption.scope === "answers" ? `${x.adoption.dispositions.length} disposition(s), ${x.adoption.not_adopted.length} answer(s) not adopted, ${x.adoption.defects.length} with defective support (each withdrawn or inconclusive)` : "the report as a whole (a ledger with no answer entries)"}${x.adoption.technical_review.length ? `; technical review by ${x.adoption.technical_review.map((t) => t.reviewer.name).join(", ")}` : ""}`);
    if (x.missing.length) out.push(`     could not bind: ${x.missing.join("; ")}`);
    if (side.length) out.push(`     beside it: ${side.join(", ")}`);
  }
  out.push(`Evidence cutoff: ${all.at(-1)?.record?.evidence_cutoff.at ?? "?"}. ${CUTOFF_NOTE}`);
  return out;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  const positional = args.find((a, i) => !a.startsWith("--") && !(args[i - 1] ?? "").startsWith("--"));
  const say = (s: string) => console.log(s);
  const sandboxArg = opt(args, "--sandbox") ?? positional;
  if (!sandboxArg) {
    console.error("usage: release.ts draft|prepare|seal|discard|sign|show|verify|print|timestamp|mirror|ots|transparency <sandbox> …");
    return 2;
  }
  const ctx = runContext(sandboxArg, { run: opt(args, "--run"), runsDir: opt(args, "--runs") });
  const version = opt(args, "--version") !== undefined ? Number(opt(args, "--version")) : undefined;
  switch (cmd) {
    case "draft": {
      const d = await draftRelease(ctx, { reason: opt(args, "--reason"), say });
      if (d.skipped) {
        if (!args.includes("--quiet")) console.log(`Release:      ${d.skipped}`);
        return 0;
      }
      const w = d.written as Written;
      console.log(`Release:      v${w.version} DRAFT, sealed by this install's machine key ${w.record.signer.fingerprint} (not an examiner; adopted by no one): ${join(RELEASE_DIR, `v${w.version}`)}`);
      console.log(`Digest:       ${w.line}`);
      return 0;
    }
    case "prepare": {
      const p = await prepareRelease(ctx, { examiner: opt(args, "--examiner"), pdf: args.includes("--pdf"), amendReason: opt(args, "--amend-reason"), report: opt(args, "--report"), via: opt(args, "--via") === "console" ? "console" : "cli", say: (m) => console.error(m) });
      console.log(JSON.stringify(p));
      return 0;
    }
    case "seal": {
      const fd = opt(args, "--secret-fd");
      let secret: Buffer | null = null;
      try {
        secret = fd === undefined ? null : readSecretFromFd(Number(fd));
        const w = await sealPrepared(ctx, {
          nonce: opt(args, "--nonce") ?? "",
          shownSha256: opt(args, "--shown") ?? "",
          examiner: opt(args, "--examiner") ?? "",
          secret,
          consent: opt(args, "--consent") === "presented" ? "presented" : "confirmed",
          via: opt(args, "--via") === "console" ? "console" : "cli",
          noTimestamp: args.includes("--no-timestamp"),
          say: (m) => console.error(m),
        });
        console.log(JSON.stringify({ ok: true, version: w.version, sha256: w.sha256, signature_sha256: w.sigSha, line: w.line, dir: w.dir }));
        return 0;
      } catch (err) {
        console.log(JSON.stringify({ ok: false, error: (err as Error).message, wrong_secret: err instanceof WrongSecretError }));
        return err instanceof WrongSecretError ? 5 : 1;
      } finally {
        wipe(secret);
      }
    }
    case "discard": {
      console.log(discardPrepared(ctx, opt(args, "--nonce") ?? "") ? "Discarded:    the prepared release; nothing was signed." : "Nothing to discard.");
      return 0;
    }
    case "sign": {
      const w = await signOnTerminal(ctx, args, say);
      if (!w) return 1;
      const a = w.record.adoption;
      console.log(`Release:      v${w.version} ADOPTED by ${w.record.signer.examiner?.name} (${w.record.signer.examiner?.organisation}), signed with ${w.record.signer.key_kind === "pkcs11" ? "the e-signature certificate " : w.record.signer.key_kind === "fido" ? "the FIDO key " : ""}${w.record.signer.fingerprint}: ${join(RELEASE_DIR, `v${w.version}`)}${w.record.report.pdf ? " (with report.pdf)" : ""}`);
      console.log(`Consent:      ${w.record.signing?.consent === "presented" ? "presented; its confirmation was skipped (--yes)" : "confirmed at the terminal"}: "${CONSENT_STATEMENT}", over report.html ${w.record.signing?.shown_sha256 ?? "?"}`);
      if (a) console.log(`Adoption:     ${a.scope === "answers" ? `${a.dispositions.filter((d) => d.kind === "answer").length} answer disposition(s); ${a.not_adopted.length} standing answer(s) not adopted, which the report shows as the agents' conclusions` : "the report as a whole: this ledger has no answer entries (recorded before ledger version 4)"}`);
      console.log(`Digest:       ${w.line}`);
      console.log(`Cutoff:       the evidence as custody sealed it at ${w.record.evidence_cutoff.at ?? "?"}; a new examination is a new run.`);
      return 0;
    }
    case "show": {
      if (args.includes("--json")) console.log(JSON.stringify(readReleases(ctx.sandbox).map((r) => ({ version: r.version, sha256: r.sha256, error: r.error, record: r.record })), null, 2));
      else for (const l of showLines(ctx)) console.log(l);
      return 0;
    }
    case "verify": {
      const v = await verifyReleases(runLayout(ctx.sandbox, ctx.reviewFile && existsSync(ctx.reviewFile) ? ctx.reviewFile : null, existsSync(ctx.anchorFile) ? ctx.anchorFile : null), { allowedSigners: opt(args, "--allowed-signers"), tsaCa: opt(args, "--tsa-ca"), ca: opt(args, "--ca"), caIntermediate: opt(args, "--ca-intermediate") });
      for (const l of v.lines) console.log(l);
      const adoptedUnchecked = v.signatures.filter((s) => s.adopted && s.state !== "verified");
      if (!v.ok) {
        console.log("RELEASES NOT VERIFIED: see above.");
        return 4;
      }
      if (adoptedUnchecked.length) {
        const cert = adoptedUnchecked.some((s) => s.key_kind === "pkcs11");
        const key = adoptedUnchecked.some((s) => s.key_kind !== "pkcs11");
        console.log(`RELEASES VERIFIED, ${[key ? "THE EXAMINER'S KEY NOT CHECKED AGAINST A SIGNER REGISTER (--allowed-signers FILE)" : "", cert ? "THE E-SIGNATURE'S CERTIFICATE CHAIN NOT CHECKED (--ca FILE)" : ""].filter(Boolean).join("; ")}.`);
        return 3;
      }
      // The machine's seal is only ever self-checked: a run no examiner has adopted is never "verified".
      if (v.releases && !v.signatures.some((s) => s.adopted)) {
        console.log("RELEASES HOLD: the machine's seal, self-checked; no examiner has adopted any.");
        return 0;
      }
      console.log(v.releases ? "RELEASES VERIFIED." : "NO RELEASES.");
      return 0;
    }
    case "print": {
      const p = printRelease(ctx.sandbox, version);
      console.log(`Printed:      ${p.pdf} (sha256 ${p.sha256}); ${basename(p.record)} beside it, which the next release binds`);
      return 0;
    }
    case "timestamp": {
      const r = pickRelease(ctx.sandbox, version);
      const url = opt(args, "--tsa-url") ?? (r.record.signer.kind === "examiner" ? loadExaminerTsa(r.record) : null)?.url ?? draftTsa(ctx).url;
      const ca = opt(args, "--tsa-ca") ?? (r.record.signer.kind === "examiner" ? loadExaminerTsa(r.record) : null)?.ca ?? draftTsa(ctx).ca;
      if (!url) {
        console.error("BLOCKER: no timestamp authority: pass --tsa-url URL (and --tsa-ca FILE to check its signature), or enrol the examiner with one");
        return 2;
      }
      const t = await timestampRelease(r.dir, { url, ca: ca ?? null, releaseAt: r.record.at });
      if (!t.ok) {
        console.error(`BLOCKER: release v${r.version} was not timestamped: ${t.why}`);
        return 1;
      }
      console.log(`Timestamp:    release v${r.version}: ${t.note}`);
      if (t.verified === false) return 4;
      return t.verified === true ? 0 : 3;
    }
    case "mirror": {
      const r = pickRelease(ctx.sandbox, version);
      const target = opt(args, "--to") ?? mirrorTarget(ctx);
      if (!target) {
        console.error("BLOCKER: no mirror: --to cmd:COMMAND|dir:PATH|print, or the run's --anchor-mirror");
        return 2;
      }
      const m = mirrorRelease(ctx.sandbox, r.dir, target);
      if (!m.ok) {
        console.error(`BLOCKER: ${m.why}`);
        return 1;
      }
      console.log(`Mirror:       ${m.note}`);
      return 0;
    }
    case "ots": {
      const o = otsRelease(ctx.sandbox, { version, upgrade: args.includes("--upgrade") });
      console.log(`OpenTimestamps: ${o.note}`);
      return o.ok ? 0 : 3;
    }
    case "transparency": {
      const command = opt(args, "--log") ?? process.env.SWARM_TRANSPARENCY_LOG;
      if (!command) {
        console.error("BLOCKER: no transparency log command (--log COMMAND or SWARM_TRANSPARENCY_LOG)");
        return 2;
      }
      const t = transparencyRelease(ctx.sandbox, command, version);
      console.log(`Transparency: ${t.note}`);
      return t.ok ? 0 : 1;
    }
    default:
      console.error("usage: release.ts draft|sign|show|verify|print|timestamp|mirror|ots|transparency <sandbox> …");
      return 2;
  }
}

/** The enrolled examiner's authority, when the examiner who signed a release is still enrolled here. */
function loadExaminerTsa(r: ReleaseRecord): { url: string | null; ca: string | null } | null {
  const id = r.signer.examiner?.id;
  if (!id) return null;
  const e = loadExaminer(id);
  return "examiner" in e ? { url: e.examiner.tsa?.url ?? null, ca: e.examiner.tsa?.ca ?? null } : null;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`BLOCKER: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    },
  );
}
