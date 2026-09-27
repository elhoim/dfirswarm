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
 * sign: an enrolled examiner's adoption. Every standing conclusion's
 *   disposition is read from the review; a conclusion whose support is
 *   defective and that is neither withdrawn nor rendered inconclusive
 *   refuses it. The final bytes are rendered for this release (no DRAFT
 *   mark) and printed when asked, before the record is written and signed
 *   with the examiner's key; the review's sign-off line, written after,
 *   names the release. A later adoption is an amendment and says why.
 * print: a PDF of a release's HTML, printed after it was sealed: a print
 *   record beside it, which the next release binds.
 *
 * Nothing in a release directory is written over. A release changes by a
 * new version, which names the one before it and why it was made; a new
 * examination (evidence examined again, or more of it) reopens the
 * evidence cutoff and is a new run, not an amendment.
 *
 *   node scripts/release.ts draft <sandbox> [--run ID] [--runs DIR] [--reason TEXT] [--quiet]
 *   node scripts/release.ts sign --runs DIR --run ID --sandbox DIR [--examiner ID] [--pdf] [--amend-reason TEXT] [--report PATH]
 *   node scripts/release.ts show <sandbox> [--run ID] [--runs DIR] [--json]
 *   node scripts/release.ts verify <sandbox> [--run ID] [--runs DIR] [--allowed-signers FILE] [--tsa-ca FILE]
 *   node scripts/release.ts print <sandbox> [--version N]
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { custodyAnchorPath, verdictAnchorState } from "./custody.ts";
import { hashRegularFile, readRegularText, writeFileNoFollowSync } from "./regular-file.ts";
import { renderReport, readReviewState, type RenderRelease } from "./report.ts";
import { adoptionState, appendReview, isSandboxPath, readReviews, reviewsPath } from "./review.ts";
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
  runLayout,
  verifyReleases,
  RELEASE_DIR,
  RELEASE_KIND,
  RELEASE_SCHEMA,
  type ReleaseAdoption,
  type ReleaseRecord,
  type ReleaseSigner,
} from "./release-record.ts";
import { checkSshSignature, dfirswarmHome, listExaminers, loadExaminer, machineSigner, sshSign, RELEASE_NAMESPACE, type Examiner, type MachineSigner } from "./signers.ts";
import { readLedger, supersededBy, verifyAttestationChain, verifyDisputeChain, verifyLedgerChain, type LedgerEntry } from "../extensions/protocol.ts";
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

type ReleaseInput = {
  state: "draft" | "adopted";
  reason: string;
  signer: { kind: "machine"; machine: MachineSigner } | { kind: "examiner"; examiner: Examiner; enrolmentSha: string };
  adoption: ReleaseAdoption | null;
  renderAdoption: RenderRelease["adoption"];
  /** How many lines of the review the release binds (the review as it is now). */
  reviewLines: number;
  pdf: boolean;
  reportPath: string;
};

export type Written = { version: number; dir: string; sha256: string; sigSha: string; record: ReleaseRecord; line: string; qr: string };

/**
 * Render, record, sign and put in place one release. The directory is
 * built beside release/ under a name of its own and renamed into place only
 * once its signature verifies; a failure leaves nothing that looks like a
 * release. Its line goes into the anchor beside the run.
 */
async function writeRelease(ctx: RunCtx, input: ReleaseInput, say: (s: string) => void): Promise<Written> {
  const S = ctx.sandbox;
  const custodyText = await readRegularText(join(S, "custody.json"), 256 * 1024 * 1024);
  if ("why" in custodyText) throw new Error(`there is no custody verdict to release (custody.json is ${custodyText.why}): swarm.sh stop takes custody`);
  const custody = JSON.parse(custodyText.text) as { at?: string; summary?: string; seal?: Record<string, { lines?: number; entries?: number; head?: string | null; last_line_sha256?: string | null } | null>; artifacts?: { index_sha256?: string; files?: number } | null; models?: unknown };
  const anchorState = await verdictAnchorState(S);
  if (anchorState.state !== "matches") throw new Error(`custody.json is not the verdict anchored beside the run (${anchorState.state === "differs" ? anchorState.note : anchorState.state}): a release binds only a verdict its anchor names; swarm.sh custody-verify ${ctx.run ?? "<id>"} says what changed`);
  const sealed = await asSealed(ctx, custody, input.reportPath);
  if (sealed.drift.length) throw new Error(`the run is not as custody sealed it: ${sealed.drift.join("; ")}. A release binds only what custody sealed; swarm.sh custody-verify ${ctx.run ?? "<id>"} names each change`);
  const existing = readReleases(S);
  const broken = existing.find((r) => !r.record);
  if (broken) throw new Error(`release v${broken.version} cannot be read (${broken.error}): nothing is added after it`);
  const version = existing.length ? (existing.at(-1) as { version: number }).version + 1 : 0;
  const prevRel = existing.at(-1) ?? null;
  const at = new Date().toISOString();
  const base = join(S, RELEASE_DIR);
  mkdirSync(base, { recursive: true });
  const tmp = join(base, `.v${version}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  mkdirSync(tmp);
  try {
    // The review as it stands, rendered as the release binds it.
    const reviewRead = ctx.run ? await readReviews(ctx.runsDir, ctx.run).catch(() => []) : [];
    const reviewLines = Math.min(input.reviewLines, reviewRead.length);
    const ledger = await readLedger(S, { raw: true });
    const reviewState = ctx.run ? await readReviewState(ctx.runsDir, ctx.run, S, ledger, reviewLines) : null;
    const signer: ReleaseSigner =
      input.signer.kind === "machine"
        ? { kind: "machine", principal: input.signer.machine.principal, public: input.signer.machine.public, fingerprint: input.signer.machine.fingerprint, machine: { id: input.signer.machine.id, host: input.signer.machine.host, label: input.signer.machine.label } }
        : {
            kind: "examiner",
            principal: input.signer.examiner.principal,
            public: input.signer.examiner.key.public,
            fingerprint: input.signer.examiner.key.fingerprint,
            examiner: { id: input.signer.examiner.id, name: input.signer.examiner.name, organisation: input.signer.examiner.organisation, competence: input.signer.examiner.competence, enrolled_at: input.signer.examiner.enrolled_at, enrolment_sha256: input.signer.enrolmentSha },
          };
    const render: RenderRelease = {
      version,
      state: input.state,
      at,
      ...(signer.kind === "examiner" && signer.examiner ? { examiner: { id: signer.examiner.id, name: signer.examiner.name, organisation: signer.examiner.organisation, competence: signer.examiner.competence, fingerprint: signer.fingerprint } } : {}),
      ...(signer.kind === "machine" ? { machine: { fingerprint: signer.fingerprint } } : {}),
      adoption: input.renderAdoption ?? null,
    };
    const html = await renderReport(S, { runsDir: ctx.runsDir, now: at, release: render, review: reviewState });
    writeFileSync(join(tmp, "report.html"), html);
    let pdf: ReleaseRecord["report"]["pdf"] = null;
    if (input.pdf) {
      const printed = printPdf(join(tmp, "report.html"), join(tmp, "report.pdf"));
      if (!printed.ok) throw new Error(`the PDF could not be printed (${printed.why}); sign without --pdf and print it later (swarm.sh releases <id> --print ${version})`);
      pdf = { path: `${RELEASE_DIR}/v${version}/report.pdf`, sha256: sha256(readFileSync(join(tmp, "report.pdf"))), bytes: readFileSync(join(tmp, "report.pdf")).length, printer: printed.printer };
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
    const record: ReleaseRecord = {
      kind: RELEASE_KIND,
      schema: RELEASE_SCHEMA,
      run: ctx.run,
      version,
      state: input.state,
      at,
      reason: input.reason,
      prev: prevRel?.sha256 ? { version: prevRel.version, sha256: prevRel.sha256, signature_sha256: fileSha(join(prevRel.dir, "release.json.sig")) } : null,
      signer,
      statement:
        input.state === "adopted"
          ? `Adopted by ${signer.examiner?.name ?? "the examiner"} (${signer.examiner?.organisation ?? "?"}), an examiner enrolled on this install, with the key ${signer.fingerprint}. The conclusions this release lists as adopted or qualified are the examiner's; the ones withdrawn or rendered inconclusive are not conclusions; every other one is the agents' conclusion, not adopted.`
          : `Sealed by this install's machine key (${signer.fingerprint}) when custody was taken: a record of what the host held then. The machine key is not an examiner. No one has adopted this release: every conclusion in it is the agents'.`,
      report: {
        markdown: md && "sha256" in md ? { path: input.reportPath, sha256: md.sha256, sealed: sealed.reportSealed } : null,
        html: { path: `${RELEASE_DIR}/v${version}/report.html`, sha256: sha256(html), bytes: Buffer.byteLength(html), generated_at: at, watermark: input.state === "adopted" && version >= 1 ? null : "DRAFT" },
        pdf,
        prints,
      },
      custody: { sha256: sha256(custodyText.text), at: custody.at ?? null, anchor: basename(ctx.anchorFile), summary: custody.summary ?? null },
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
        note: "A token, when there is one, is over release.json.sig and kept beside it (release.json.sig.tsr, timestamp.json): it cannot be inside the bytes it dates. Without one, the release's time is this host's clock.",
      },
      missing,
    };
    const text = `${JSON.stringify(record, null, 2)}\n`;
    writeFileSync(join(tmp, "release.json"), text);
    const key = input.signer.kind === "machine" ? input.signer.machine.key : input.signer.examiner.key.path;
    const signed = sshSign(join(tmp, "release.json"), key, RELEASE_NAMESPACE);
    if (!signed.ok) throw new Error(`release v${version} could not be signed: ${signed.why}`);
    const check = checkSshSignature({ file: join(tmp, "release.json"), sig: signed.sig, namespace: RELEASE_NAMESPACE, principal: signer.principal, publicKey: signer.public });
    if (check.state !== "unchecked") throw new Error(`the signature just made does not verify under the key the release names: ${check.detail}`);
    for (const f of readdirSync(tmp)) chmodSync(join(tmp, f), 0o444);
    const dir = releaseDir(S, version);
    if (existsSync(dir)) throw new Error(`${dir} appeared while this release was being made: nothing is written over it`);
    renameSync(tmp, dir);
    const sha = sha256(text);
    const sigSha = signed.sha256;
    const line = digestLine(record, sha, sigSha);
    const qr = qrString(record, sha);
    anchorRelease(ctx.anchorFile, { version, at, state: record.state, sha256: sha, signature_sha256: sigSha, signer: signer.fingerprint, principal: signer.principal, line }, say);
    return { version, dir, sha256: sha, sigSha, record, line, qr };
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
  return { written, skipped: null };
}

function readCustodyAt(ctx: RunCtx): string | null {
  try {
    return String((JSON.parse(readFileSync(join(ctx.sandbox, "custody.json"), "utf8")) as { at?: string }).at ?? "") || null;
  } catch {
    return null;
  }
}

/**
 * Every disposition the review holds, and what the release gate makes of
 * the standing conclusions: the dispositions (enriched with the entry's
 * kind and section), the answers left to the agents, the defective ones and
 * how each is resolved, the technical reviews, and why a release is
 * refused (a defective conclusion neither withdrawn nor rendered
 * inconclusive, or a review whose chain is broken).
 */
export async function adoptionGate(ctx: RunCtx): Promise<{ adoption: ReleaseAdoption; render: NonNullable<RenderRelease["adoption"]>; refused: string[]; reviewLines: number }> {
  if (!ctx.run) throw new Error("the run's id is not known: pass --run ID");
  const st = await adoptionState({ runsDir: ctx.runsDir, run: ctx.run, sandbox: ctx.sandbox });
  const refused: string[] = [];
  if (!st.chain.ok) refused.push(`the examiner's review is broken (${st.chain.reason}): nothing is adopted from it`);
  for (const a of st.blocked) refused.push(`E-${a.seq}${a.section ? ` (${a.section})` : ""} is not supported as it stands (${a.defects.map((d) => d.what).join("; ")}) and is neither withdrawn nor rendered inconclusive: --reject ${a.seq} --note TEXT or --inconclusive ${a.seq} --note TEXT (an unsupported conclusion is not waived; repairing its support is a new examination)`);
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
    technical: st.technical.map((t) => `${t.reviewer.name} (${t.reviewer.competence}): ${t.methods_checked}`),
  };
  return { adoption, render, refused, reviewLines: st.lines };
}

/** An enrolled examiner's adoption: release vN+1, signed with the examiner's key, and the review's sign-off naming it. */
export async function signRelease(ctx: RunCtx, o: { examiner?: string; pdf?: boolean; amendReason?: string; report?: string; noTimestamp?: boolean; home?: string; say?: (s: string) => void }): Promise<Written> {
  const say = o.say ?? (() => undefined);
  const home = o.home ?? dfirswarmHome();
  let ex: { examiner: Examiner; sha256: string } | { why: string };
  if (o.examiner) ex = loadExaminer(o.examiner, home);
  else {
    const all = listExaminers(home);
    ex = all.length === 1 ? loadExaminer(all[0].id, home) : { why: all.length ? `${all.length} examiners are enrolled (${all.map((e) => e.id).join(", ")}): name one (--examiner ID)` : "no examiner is enrolled on this install: swarm.sh examiner enroll" };
  }
  if ("why" in ex) throw new Error(`a release is signed by an enrolled examiner: ${ex.why}`);
  if (!existsSync(ex.examiner.key.path)) throw new Error(`the examiner's key is not at ${ex.examiner.key.path}`);
  if (!ctx.run) throw new Error("the run's id is not known: pass --run ID");
  const reportPath = o.report ?? "work/report.md";
  if (!isSandboxPath(reportPath)) throw new Error(`${JSON.stringify(reportPath)} is not a path under the run`);
  if (!fileSha(join(ctx.sandbox, reportPath))) throw new Error(`there is no ${reportPath} in run ${ctx.run} to sign over: a sign-off is over the report the examiner read (--report PATH names another)`);
  let releases = readReleases(ctx.sandbox);
  const adopted = [...releases].reverse().find((r) => r.record?.state === "adopted");
  if (adopted && !o.amendReason?.trim()) throw new Error(`release v${adopted.version} is adopted already: a later adoption is an amendment and says why (--amend-reason TEXT). A new examination is a new run.`);
  if (!adopted && o.amendReason) throw new Error("there is no adopted release to amend: sign without --amend-reason");
  const gate = await adoptionGate(ctx);
  if (gate.refused.length) throw new Error(`the release is refused:\n  - ${gate.refused.join("\n  - ")}`);
  // A run with no release yet (stopped before releases, or with custody later) gets the machine's draft first.
  if (!releases.length) {
    const d = await draftRelease(ctx, { home, reason: "the machine's draft, written before the first adoption: none was written when custody was taken", say });
    if (d.written) say(`Release:      v${d.written.version} DRAFT sealed first by the machine key (${d.written.record.signer.fingerprint})`);
    releases = readReleases(ctx.sandbox);
  }
  const written = await writeRelease(
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
    },
    say,
  );
  // The review's sign-off, after the signature, naming what was signed.
  try {
    await appendReview(ctx.runsDir, ctx.run, ctx.sandbox, {
      action: "sign",
      examiner: ex.examiner.name,
      examinerId: ex.examiner.id,
      key: ex.examiner.key.fingerprint,
      report: reportPath,
      release: { version: written.version, sha256: written.sha256, signature_sha256: written.sigSha },
    });
  } catch (err) {
    say(`WARN: release v${written.version} is signed and in place, and the review's sign-off line naming it was not written (${(err as Error).message}); verify will say so`);
  }
  return written;
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
      `v${r.version}  ${x.state === "adopted" ? "ADOPTED" : "DRAFT  "}  ${x.at}  ${x.state === "adopted" ? `by ${x.signer.examiner?.name ?? "?"} (${x.signer.examiner?.organisation ?? "?"}), key ${x.signer.fingerprint}` : `sealed by the machine key ${x.signer.fingerprint}, adopted by no one`}`,
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
    console.error("usage: release.ts draft|sign|show|verify|print <sandbox> …");
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
    case "sign": {
      const w = await signRelease(ctx, { examiner: opt(args, "--examiner"), pdf: args.includes("--pdf"), amendReason: opt(args, "--amend-reason"), report: opt(args, "--report"), say });
      const a = w.record.adoption;
      console.log(`Release:      v${w.version} ADOPTED by ${w.record.signer.examiner?.name} (${w.record.signer.examiner?.organisation}), signed with ${w.record.signer.fingerprint}: ${join(RELEASE_DIR, `v${w.version}`)}${w.record.report.pdf ? " (with report.pdf)" : ""}`);
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
      const v = await verifyReleases(runLayout(ctx.sandbox, ctx.reviewFile && existsSync(ctx.reviewFile) ? ctx.reviewFile : null, existsSync(ctx.anchorFile) ? ctx.anchorFile : null), { allowedSigners: opt(args, "--allowed-signers"), tsaCa: opt(args, "--tsa-ca") });
      for (const l of v.lines) console.log(l);
      const adoptedUnchecked = v.signatures.some((s) => s.adopted && s.state !== "verified");
      if (!v.ok) {
        console.log("RELEASES NOT VERIFIED: see above.");
        return 4;
      }
      if (adoptedUnchecked) {
        console.log("RELEASES VERIFIED, THE EXAMINER'S KEY NOT CHECKED AGAINST A SIGNER REGISTER (--allowed-signers FILE).");
        return 3;
      }
      console.log(v.releases ? "RELEASES VERIFIED." : "NO RELEASES.");
      return 0;
    }
    case "print": {
      const p = printRelease(ctx.sandbox, version);
      console.log(`Printed:      ${p.pdf} (sha256 ${p.sha256}); ${basename(p.record)} beside it, which the next release binds`);
      return 0;
    }
    default:
      console.error("usage: release.ts draft|sign|show|verify|print <sandbox> …");
      return 2;
  }
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
