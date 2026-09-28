/**
 * A run's releases as files, and how a reader checks them, in the run or
 * in a package (scripts/release.ts writes them).
 *
 * A release is what was handed over, as which bytes, sealed by whom:
 *
 *   release/v<N>/release.json       the record (below)
 *   release/v<N>/release.json.sig   its ssh signature (namespace dfirswarm-release): the machine's, an ssh or a FIDO key's
 *   release/v<N>/release.json.p7s   or its CAdES-BES CMS, made on an e-signature token (and report.pdf.p7s beside a PDF)
 *   release/v<N>/report.html        the report's bytes this release is, rendered before signing
 *   release/v<N>/report.pdf         the printed PDF, when it was printed for this release
 *   release/v<N>/print-<k>.json     a later print of this release's HTML (with print-<k>.pdf)
 *   release/v<N>/release.json.sig.tsr, timestamp.json   an RFC 3161 token over the signature, and what it says
 *   release/v<N>/mirror.json, case-file.txt, transparency-*.json, *.ots   independent copies of its digest line
 *
 * v0 is written when custody is taken at stop: a DRAFT, sealed by this
 * install's machine key, binding the swarm's report and a rendering of it,
 * the custody verdict and its anchor, the index of work/ custody sealed, and
 * the head and length of every chain. It is the machine's record of what
 * the host held, adopted by no one: it is sealed, never signed, and its seal
 * is checked only as the machine's ("machine seal, self-checked"). v1 is
 * written when an enrolled examiner signs (`swarm.sh review <id> --sign`, or
 * the console's Release panel): prepared first (the final bytes rendered
 * once, with no DRAFT mark, shown with their sha256), then sealed with the
 * examiner's key over exactly those bytes, with how it was signed (`via`,
 * the consent statement, the sha256 shown, when it was confirmed, the key's
 * kind and fingerprint, the program that signed). Every later version names
 * the one before it (`prev`, its sha256) and why it was made. Nothing in a
 * release is written again: a correction is a new version.
 *
 * The sidecars (a token, a mirror's receipt, a print record, an
 * OpenTimestamps proof) are about a release's bytes and never inside them:
 * a token obtained later dates the proof of existence from then.
 *
 * Machine custody and human adoption are kept apart in every word here: a
 * machine seal is never an examiner's, and a draft is never adopted.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { readTimestampResponse, verifyTimestampToken } from "./custody-checks.ts";
import { checkSshSignature, RELEASE_NAMESPACE, type SignatureState } from "./signers.ts";
import { cmsVerify } from "./pkcs11.ts";
import { dispositionsHead, technicalReviewsOf, satisfiesPolicy, NO_TECHNICAL_REVIEW, type ReviewLine, type TechnicalReview } from "./review.ts";

export const RELEASE_DIR = "release";
/** 2: a signer's key kind, how it was signed (`signing`), the host's exposure, the policy. 1 is still read. */
export const RELEASE_SCHEMA = 2;
export const RELEASE_SCHEMAS: readonly number[] = [1, 2];
export const RELEASE_KIND = "dfirswarm-release";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

export type ChainHead = { lines: number; head: string | null };

/** The ledger's chains a release binds by head and length. */
type ChainKind = "ledger" | "attestations" | "disputes";

export type ReleaseSigner = {
  kind: "machine" | "examiner";
  principal: string;
  /** The signing key's public half (an ssh public key line): public, and what a reader checks the signature against. Empty for a certificate, which travels inside the CMS. */
  public: string;
  fingerprint: string;
  /** The key's kind: the machine's, an ssh key, a FIDO key, a token's certificate (absent: schema 1, an ssh key). */
  key_kind?: "machine" | "ssh" | "fido" | "pkcs11";
  /** A token's certificate, as shown: never its subject beyond the CN. */
  certificate?: { sha256: string; cn: string | null; issuer: string; not_before: string; not_after: string; key_usage: string[]; qc_statement: boolean };
  /** The machine key: which install, and what it is. */
  machine?: { id: string; host: string; label: string };
  /** The enrolled examiner: who, for whom, on what competence, and the enrolment record's sha256. */
  examiner?: { id: string; name: string; organisation: string; competence: string; enrolled_at: string; enrolment_sha256: string };
};

/** An examiner's disposition of an answer (or any entry), as the release binds it. */
export type ReleaseDisposition = { seq: number; hash: string | null; kind: string | null; section: string | null; disposition: string; note: string | null; examiner: string; at: string; review_seq: number };

export type ReleaseAdoption = {
  /** The review the dispositions are read from: its lines and the last line's sha256 when the release was made. */
  review: ChainHead;
  dispositions: ReleaseDisposition[];
  /** Standing answers the examiner made no disposition on: the agents' conclusions, not adopted. */
  not_adopted: Array<{ seq: number; hash: string | null; section: string | null }>;
  /** Answers whose support is defective, with the disposition that resolves each (withdrawn or inconclusive). */
  defects: Array<{ seq: number; defects: string[]; disposition: string }>;
  technical_review: TechnicalReview[];
  open_rejections: number[];
  /** A ledger with no answer entries (before version 4): the release adopts the report as a whole. */
  scope: "answers" | "report";
};

export type ReleaseRecord = {
  kind: typeof RELEASE_KIND;
  schema: number;
  run: string | null;
  version: number;
  state: "draft" | "adopted";
  at: string;
  reason: string;
  prev: { version: number; sha256: string; signature_sha256: string | null } | null;
  signer: ReleaseSigner;
  statement: string;
  report: {
    markdown: { path: string; sha256: string; sealed: boolean | null } | null;
    html: { path: string; sha256: string; bytes: number; generated_at: string; watermark: string | null };
    pdf: { path: string; sha256: string; bytes: number; printer: string } | null;
    /** Earlier prints of an earlier release's HTML, carried into this one. */
    prints: Array<{ path: string; sha256: string; release: number; pdf_sha256: string }>;
  };
  custody: { sha256: string; at: string | null; anchor: string; summary: string | null } | null;
  sealed_index: { sha256: string; files: number | null } | null;
  chains: {
    ledger: { entries: number; head: string | null };
    attestations: ChainHead;
    disputes: ChainHead;
    journal: ChainHead | null;
    trace: { lines: number; last_line_sha256: string | null; sealed_lines: number | null };
    review: ChainHead | null;
    ledger_versions: number[];
  };
  versions: {
    dfirswarm: string;
    harness_commit_at_kickoff: string | null;
    harness_commit_now: string | null;
    harness_dirty_now: boolean | null;
    renderer_sha256: string;
    release_sha256: string;
    run_contract_sha256: string | null;
  };
  models: unknown;
  evidence_cutoff: { at: string | null; note: string };
  adoption: ReleaseAdoption | null;
  timestamp: { authority: string | null; note: string };
  /** What this release could not bind, and why (an older run, a custody from before a part was sealed). */
  missing: string[];
  /** How the examiner signed it: prepared and shown, then confirmed and sealed (schema 2, an adoption). */
  signing?: ReleaseSigning;
  /** Where the run ran and whether the signers' keys were hidden from its agents, as the kickoff recorded it (null: not recorded). */
  host?: {
    isolation: string | null;
    signer_keys_hidden: boolean | null;
    note: string;
    /** The kickoff's record of how the signing keys were kept from the agents, bound as it was (docs/observability.md). */
    signer_isolation?: { isolation?: string; guard?: string; keys_hidden?: boolean; hidden?: string[]; agent_sockets?: string[]; exposed?: string[]; exposure_accepted?: boolean; why?: string };
    earlier_runs_hidden?: { by?: string | null; sandboxes?: number; reviews?: string | null; skipped?: string[]; why?: string };
  };
  /** The technical-review policy in force when it was sealed. */
  policy?: { require_technical_review: boolean; source: string | null };
};

/** What the examiner confirms, word for word, before a release is sealed. */
export const CONSENT_STATEMENT = "I have read the report and the answers I adopt";

export type ReleaseSigning = {
  via: "console" | "cli";
  /** confirmed: asked and answered; presented: shown, with the confirmation skipped (--yes). */
  consent: "confirmed" | "presented";
  statement: string;
  /** report.html's sha256 as it was shown before the confirmation. */
  shown_sha256: string;
  nonce: string;
  prepared_at: string;
  confirmed_at: string;
  key: { kind: "ssh" | "fido" | "pkcs11"; fingerprint: string };
  /** The program that made the signature. */
  ssh_keygen: string | null;
  openssl: string | null;
};

/** The signature file beside a release.json: a CMS for a token's certificate, else an SSHSIG. */
export function releaseSigName(x: Pick<ReleaseRecord, "signer"> | null | undefined): "release.json.p7s" | "release.json.sig" {
  return x?.signer?.key_kind === "pkcs11" ? "release.json.p7s" : "release.json.sig";
}

/** The signature file in a release directory, whichever kind it is. */
export function releaseSigPath(dir: string): string {
  return existsSync(join(dir, "release.json.p7s")) ? join(dir, "release.json.p7s") : join(dir, "release.json.sig");
}

export function releaseDir(root: string, version: number): string {
  return join(root, RELEASE_DIR, `v${version}`);
}

export type ReadRelease = { version: number; dir: string; text: string | null; sha256: string | null; record: ReleaseRecord | null; error: string | null };

/** Every release under `root`/release, by version, in order; a gap or an unreadable one is named, not skipped. */
export function readReleases(root: string): ReadRelease[] {
  const base = join(root, RELEASE_DIR);
  if (!existsSync(base)) return [];
  const versions = readdirSync(base)
    .map((n) => /^v(0|[1-9]\d{0,5})$/.exec(n))
    .filter((m): m is RegExpExecArray => Boolean(m))
    .map((m) => Number(m[1]))
    .sort((a, b) => a - b);
  return versions.map((version) => {
    const dir = releaseDir(root, version);
    const file = join(dir, "release.json");
    try {
      const st = lstatSync(file);
      if (!st.isFile()) return { version, dir, text: null, sha256: null, record: null, error: "release.json is not a regular file" };
      const text = readFileSync(file, "utf8");
      return { version, dir, text, sha256: sha256(text), record: JSON.parse(text) as ReleaseRecord, error: null };
    } catch (err) {
      return { version, dir, text: null, sha256: null, record: null, error: (err as NodeJS.ErrnoException).code === "ENOENT" ? "no release.json" : `release.json is not readable JSON (${(err as Error).message})` };
    }
  });
}

/** One release by version (the latest when none is named), readable, or why not. */
export function pickRelease(S: string, version?: number): { version: number; dir: string; record: ReleaseRecord; sha256: string } {
  const all = readReleases(S);
  if (!all.length) throw new Error("the run has no release");
  const r = version === undefined ? all.at(-1) : all.find((x) => x.version === version);
  if (!r) throw new Error(`the run has no release v${version}`);
  if (!r.record || !r.sha256) throw new Error(`release v${r.version} cannot be read (${r.error})`);
  return { version: r.version, dir: r.dir, record: r.record, sha256: r.sha256 };
}

/**
 * The release state a report and a summary read, the same way: the release
 * a rendering is for when it is one (its own bytes), else the run's latest
 * release. `release` is what the report body takes (report-body.ts
 * ReportRelease: a draft unless an examiner adopted it); `examiner` is the
 * enrolled examiner who adopted it, never the kickoff's `examiner` string;
 * `own` says whether the rendering is that release's own bytes.
 */
export function bodyRelease(
  root: string,
  forRelease?: { version: number; state: "draft" | "adopted"; at: string; examiner?: { name: string; organisation: string; competence: string } | null } | null,
): { release: { version: number; at: string; state: "draft" | "adopted" } | null; examiner: { name: string; organisation: string; competence: string } | null; own: boolean; latest: ReadRelease | null } {
  if (forRelease) {
    return {
      release: { version: forRelease.version, at: forRelease.at, state: forRelease.state },
      examiner: forRelease.state === "adopted" && forRelease.examiner ? { name: forRelease.examiner.name, organisation: forRelease.examiner.organisation, competence: forRelease.examiner.competence } : null,
      own: true,
      latest: null,
    };
  }
  const latest = readReleases(root).at(-1) ?? null;
  const x = latest?.record ?? null;
  if (!latest || !x) return { release: null, examiner: null, own: false, latest };
  const e = x.state === "adopted" ? x.signer.examiner : undefined;
  return { release: { version: x.version, at: x.at, state: x.state }, examiner: e ? { name: e.name, organisation: e.organisation, competence: e.competence } : null, own: false, latest };
}

/** The latest release, and the latest adopted one. */
export function releaseStateOf(root: string): { latest: ReadRelease | null; adopted: ReadRelease | null; count: number } {
  const all = readReleases(root);
  return { latest: all.at(-1) ?? null, adopted: [...all].reverse().find((r) => r.record?.state === "adopted") ?? null, count: all.length };
}

/** The one line a release's digest travels in: printed, mirrored, piped to a witness. */
export function digestLine(r: ReleaseRecord, sha: string, sigSha: string | null): string {
  return `dfirswarm-release run=${r.run ?? "-"} v=${r.version} state=${r.state} sha256=${sha} sig=${sigSha ?? "-"} signer=${r.signer.fingerprint} at=${r.at}`;
}

/** The digest in QR alphanumeric characters only (digits, capitals, colon), for the case file. */
export function qrString(r: ReleaseRecord, sha: string): string {
  return `DFSR1:${String(r.run ?? "-").toUpperCase().replace(/[^0-9A-Z]/g, "")}:V${r.version}:${sha.toUpperCase()}`;
}

// --- chain heads -----------------------------------------------------------------------------

/** Each line's own hash: its sha256, or the hash a redacted line carries for the line it replaced. */
export function lineHashes(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let own = sha256(line);
    try {
      const o = JSON.parse(line) as { redacted?: unknown; line_sha256?: unknown };
      if (o.redacted === true && typeof o.line_sha256 === "string") own = o.line_sha256;
    } catch {
      // not JSON: its own bytes
    }
    out.push(own);
  }
  return out;
}

/**
 * Whether the first `n` lines of a prev-chained file (the trace, the store
 * journal, the review) each name the one before by its hash: a line changed
 * before the last one a release binds breaks the chain after it. A redacted
 * line is taken by the hash it carries. Null when it holds; the line that
 * does not, when it breaks.
 */
export function prevChainBreak(text: string, n: number): number | null {
  const lines = text.split("\n").filter((l) => l.trim()).slice(0, n);
  let prev: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    let o: { prev?: unknown; redacted?: unknown; line_sha256?: unknown };
    try {
      o = JSON.parse(lines[i]) as typeof o;
    } catch {
      return i + 1;
    }
    const redacted = o.redacted === true && typeof o.line_sha256 === "string";
    if (!redacted && i > 0 && o.prev !== prev) return i + 1;
    if (!redacted && i === 0 && !(o.prev === undefined || o.prev === null || o.prev === "" || o.prev === "genesis")) return 1;
    prev = redacted ? String(o.line_sha256) : sha256(lines[i]);
  }
  return null;
}

/** A hashed chain's length and head: the last line's `hash` field (the ledger, attestations, disputes). */
export function hashFieldHead(text: string | null): ChainHead {
  const lines = (text ?? "").split("\n").filter((l) => l.trim());
  let head: string | null = null;
  for (const l of [...lines].reverse()) {
    try {
      const h = (JSON.parse(l) as { hash?: unknown }).hash;
      if (typeof h === "string") {
        head = h;
        break;
      }
    } catch {
      // a torn line has no hash
    }
  }
  return { lines: lines.length, head };
}

/** The `hash` field of line `n` (1-based) of a hashed chain, or null: whether a bound head is still at its place. */
export function hashFieldAt(text: string | null, n: number): string | null {
  if (n <= 0) return null;
  const line = (text ?? "").split("\n").filter((l) => l.trim())[n - 1];
  if (line === undefined) return null;
  try {
    const h = (JSON.parse(line) as { hash?: unknown }).hash;
    return typeof h === "string" ? h : null;
  } catch {
    return null;
  }
}

/** A prev-chained file's length and head: the last line's own hash (the trace, the journal, the review). */
export function lineHead(text: string | null): ChainHead {
  const h = lineHashes(text ?? "");
  return { lines: h.length, head: h.at(-1) ?? null };
}

// --- where things are ---------------------------------------------------------------------------

/**
 * Where a release's bound parts are: in the run itself, or as a package lays
 * them out. Paths are under `root` unless absolute.
 */
export type ReleaseLayout = {
  root: string;
  where: "run" | "package";
  custody: string;
  custodyHistory: string[];
  sealedIndex: string;
  indexHistory: string[];
  ledger: string;
  attestations: string;
  disputes: string;
  journal: string;
  trace: string;
  /** The two registers custody seals by head and count (the lead and the question register): checked against the verdict a release binds. */
  leads: string;
  questions: string;
  review: string | null;
  anchor: string | null;
  /** A package made with --redact: each changed file's sha256 before and after. */
  redactions: Map<string, { before: string; after: string }>;
};

function listMatching(root: string, dir: string, re: RegExp): string[] {
  const abs = join(root, dir);
  if (!existsSync(abs)) return [];
  return readdirSync(abs)
    .filter((n) => re.test(n))
    .sort()
    .map((n) => (dir ? `${dir}/${n}` : n));
}

export function runLayout(sandbox: string, reviewFile: string | null, anchorFile: string | null): ReleaseLayout {
  return {
    root: sandbox,
    where: "run",
    custody: "custody.json",
    custodyHistory: listMatching(sandbox, "", /^custody\.[0-9A-Za-z]+\.json$/),
    sealedIndex: "artifacts.json",
    indexHistory: listMatching(sandbox, "", /^artifacts\.[0-9A-Za-z]+\.json$/),
    ledger: "ledger/entries.jsonl",
    attestations: "ledger/attestations.jsonl",
    disputes: "ledger/disputes.jsonl",
    journal: "store/journal.jsonl",
    trace: "traces/events.jsonl",
    leads: "leads/leads.jsonl",
    questions: "questions/questions.jsonl",
    review: reviewFile,
    anchor: anchorFile,
    redactions: new Map(),
  };
}

/** REDACTIONS.txt's rows: each file changed by redaction, with its sha256 before and after. */
export function redactionRows(text: string | null): Map<string, { before: string; after: string }> {
  const out = new Map<string, { before: string; after: string }>();
  for (const line of (text ?? "").split("\n")) {
    const m = /^([0-9a-f]{64})  ([0-9a-f]{64})  (.+?)  \S.*$/.exec(line);
    if (m) out.set(m[3], { before: m[1], after: m[2] });
  }
  return out;
}

export function packageLayout(dir: string): ReleaseLayout {
  const read = (rel: string) => (existsSync(join(dir, rel)) ? readFileSync(join(dir, rel), "utf8") : null);
  return {
    root: dir,
    where: "package",
    custody: "custody.json",
    custodyHistory: listMatching(dir, "custody-history", /^custody\.[0-9A-Za-z]+\.json$/),
    sealedIndex: "artifacts.sealed.json",
    indexHistory: listMatching(dir, "custody-history", /^artifacts\.[0-9A-Za-z]+\.json$/),
    ledger: "ledger.jsonl",
    attestations: "ledger-attestations.jsonl",
    disputes: "ledger-disputes.jsonl",
    journal: "store/journal.jsonl",
    trace: "trace/events.jsonl",
    leads: "leads.jsonl",
    questions: "questions.jsonl",
    review: existsSync(join(dir, "review.jsonl")) ? join(dir, "review.jsonl") : null,
    anchor: existsSync(join(dir, "trace", "custody-anchor.json")) ? join(dir, "trace", "custody-anchor.json") : null,
    redactions: redactionRows(read("REDACTIONS.txt")),
  };
}

// --- checking ------------------------------------------------------------------------------------

export type ReleaseCheck = {
  ok: boolean;
  lines: string[];
  releases: number;
  /** Each release's signature, by version: what it shows about who sealed it. */
  signatures: Array<{ version: number; kind: "machine" | "examiner" | "unknown"; key_kind?: string; state: SignatureState; adopted: boolean }>;
  /** Every technical review in the review here, against the run's latest release: the report's five wordings. */
  technical?: TechnicalReview[];
};

const abs = (root: string, p: string) => (p.startsWith("/") ? p : join(root, p));
const readText = (p: string | null): string | null => {
  if (!p || !existsSync(p)) return null;
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
};
const fileSha = (p: string): string | null => {
  try {
    return lstatSync(p).isFile() ? sha256(readFileSync(p)) : null;
  } catch {
    return null;
  }
};

/**
 * Every release under the layout's root, walked in order: each one's
 * record, its place in the chain (prev names the one before by its sha256,
 * no version missing), its signature (against an allowed-signers file when
 * one is given, else against the key the release names, said as that), the
 * bytes it binds (the report's HTML and PDF, the swarm's report, a print),
 * the custody verdict and the index it names (the current ones or ones
 * custody kept aside), the lead and question registers as that verdict
 * sealed them (their heads and counts; appended to since is a prefix, cut
 * or rewritten fails), the ledger, its attestations and disputes as they
 * are, the trace, the journal and the review as prefixes (lines may follow
 * a release; the ones it bound may not change), its line in the anchor
 * beside the run, and a timestamp token over its signature, against the
 * authority's CA when one is given.
 */
export async function verifyReleases(layout: ReleaseLayout, opts: { allowedSigners?: string; tsaCa?: string; ca?: string; caIntermediate?: string } = {}): Promise<ReleaseCheck> {
  const all = readReleases(layout.root);
  const lines: string[] = [];
  const signatures: ReleaseCheck["signatures"] = [];
  let ok = true;
  const fail = (s: string) => {
    ok = false;
    lines.push(s);
  };
  if (!all.length) return { ok: true, lines: ["Releases:     none (a run stopped before releases were written, or with no custody taken; swarm.sh releases <id> --draft writes one for a run that has a verdict)"], releases: 0, signatures };
  // A file a release binds: the same bytes, or redacted from those bytes (REDACTIONS.txt names both).
  const held = (relPath: string, want: string | null | undefined): "matches" | "redacted" | "withheld" | "missing" | "differs" => {
    const p = abs(layout.root, relPath);
    const have = fileSha(p);
    if (have === null) return "missing";
    if (have === want) return "matches";
    const r = layout.redactions.get(relPath);
    if (r && r.before === want && r.after === have) {
      const text = readText(p) ?? "";
      return /^\[withheld: /.test(text) ? "withheld" : "redacted";
    }
    return "differs";
  };
  const heldWord = (h: ReturnType<typeof held>) => (h === "matches" ? "as bound" : h === "redacted" ? "redacted from the bound bytes (REDACTIONS.txt)" : h === "withheld" ? "withheld from this package (REDACTIONS.txt names the bound sha256)" : h === "missing" ? "NOT THERE" : "NOT THE BOUND BYTES");
  let anchorReleases: Array<{ version?: number; sha256?: string }> | null = null;
  // The resumes the anchor names, as written: each is weighed below against the chains before it relaxes anything.
  let anchorResumes: unknown[] = [];
  const anchorText = readText(layout.anchor);
  if (anchorText) {
    try {
      const a = JSON.parse(anchorText) as { releases?: unknown; resumes?: unknown };
      anchorReleases = Array.isArray(a.releases) ? (a.releases as Array<{ version?: number; sha256?: string }>) : [];
      anchorResumes = Array.isArray(a.resumes) ? a.resumes : [];
    } catch {
      anchorReleases = null;
    }
  }
  const ledgerText = readText(abs(layout.root, layout.ledger));
  const attText = readText(abs(layout.root, layout.attestations));
  const dispText = readText(abs(layout.root, layout.disputes));
  const ledgerNow = hashFieldHead(ledgerText);
  const attNow = hashFieldHead(attText);
  const dispNow = hashFieldHead(dispText);
  /**
   * The first n lines of a chain, verified with its own verifier (every
   * line's hash recomputed from what it holds, and chained to the one
   * before), and the head they end on. In a run only: a package's chains
   * may carry redacted lines, which its own check (package-tools.ts) walks
   * by the hashes they keep; there the stored hash fields are compared.
   */
  const P = layout.where === "run" ? await import("../extensions/protocol.ts") : null;
  const texts: Record<ChainKind, string | null> = { ledger: ledgerText, attestations: attText, disputes: dispText };
  const prefixOf = (kind: ChainKind, n: number): { ok: true; head: string | null } | { ok: false; why: string } => {
    const text = texts[kind];
    const lines = (text ?? "").split("\n").filter((l) => l.trim());
    if (n > lines.length) return { ok: false, why: `it has ${lines.length} line(s), fewer than ${n}` };
    if (n === 0) return { ok: true, head: null };
    const first = `${lines.slice(0, n).join("\n")}\n`;
    if (!P) return { ok: true, head: hashFieldAt(first, n) };
    if (kind === "ledger") {
      const v = P.verifyLedgerChain(first);
      return v.ok ? { ok: true, head: v.hashes.at(-1) ?? null } : { ok: false, why: `its chain is broken at line ${v.broken_at} (${v.reason})` };
    }
    const v = kind === "attestations" ? P.verifyAttestationChain(first) : P.verifyDisputeChain(first);
    return v.ok ? { ok: true, head: v.head } : { ok: false, why: `its chain is broken at line ${v.broken_at} (${v.reason})` };
  };
  /**
   * The resumes that stand: each recorded with its segment and the heads of
   * the chains as the resume found them, every one of those heads the one
   * the verified chain holds at that length. A bare time, a boundary the
   * chain does not hold, or a line of the anchor that says less, relaxes
   * nothing.
   */
  const resumes = anchorResumes
    .map((raw) => {
      const r = (raw && typeof raw === "object" ? raw : {}) as { at?: unknown; segment?: unknown; heads?: Record<string, { lines?: unknown; head?: unknown } | undefined> };
      const at = typeof r.at === "string" && Number.isFinite(Date.parse(r.at)) ? r.at : null;
      if (!at || !Number.isInteger(r.segment) || Number(r.segment) < 1 || !r.heads || typeof r.heads !== "object") return null;
      const heads: Partial<Record<ChainKind, ChainHead>> = {};
      for (const kind of ["ledger", "attestations", "disputes"] as const) {
        const h = r.heads[kind];
        if (!h) continue;
        const lines = Number(h.lines);
        if (!Number.isInteger(lines) || lines < 0) return null;
        const got = prefixOf(kind, lines);
        if (!got.ok || got.head !== ((h.head as string | null | undefined) ?? null)) return null;
        heads[kind] = { lines, head: got.head };
      }
      return heads.ledger ? { at, heads } : null;
    })
    .filter((x): x is { at: string; heads: Partial<Record<ChainKind, ChainHead>> } => x !== null);
  const resumedAfter = (at: string) => resumes.some((r) => Date.parse(r.at) > Date.parse(at));
  // The registers custody seals by head and count, which a release binds through the verdict it binds.
  // In a run, each is verified whole as well (every event's hash over its
  // content); a package's may carry redacted events, which its own check
  // (package-tools.ts) verifies by the hashes they keep.
  const verifyChain = layout.where === "run" ? (await import("../extensions/leads.ts")).verifyLeadChain : null;
  const registers = ([["the lead register", layout.leads, "leads"], ["the question register", layout.questions, "questions"]] as const).map(([what, rel, key]) => {
    const text = readText(abs(layout.root, rel));
    const v = verifyChain && text ? verifyChain(text) : null;
    return { what, key, text, now: hashFieldHead(text), broken: v && !v.ok ? `broken at line ${v.broken_at} (${v.reason})` : null };
  });
  /**
   * A chain bound as it is, or, when a resume that stands was recorded after
   * the release at a boundary at or past what it binds, as a prefix. Either
   * way the lines it binds are verified, never read by their hash fields.
   * What the continuation appended is the next release's to bind.
   */
  const asBound = (kind: ChainKind, what: string, bound: ChainHead, now: ChainHead, at: string, bad: string[], parts: string[]) => {
    const got = prefixOf(kind, bound.lines);
    if (!got.ok && bound.lines <= now.lines) {
      bad.push(`${what} it binds does not verify: ${got.why}`);
      return;
    }
    if (got.ok && got.head === bound.head && bound.lines === now.lines) return;
    const resumed = resumes.some((r) => Date.parse(r.at) > Date.parse(at) && (r.heads[kind] ?? r.heads.ledger)!.lines >= bound.lines);
    if (got.ok && got.head === bound.head && resumed && now.lines > bound.lines) {
      parts.push(`${what} it binds is a prefix of ${what} here (${bound.lines} of ${now.lines}): the run was resumed after it, and a later release binds the continuation`);
      return;
    }
    bad.push(`${what} here ${what === "the ledger" ? "is not the one" : "are not the ones"} it binds (${bound.lines} ${what === "the ledger" ? "entries" : "lines"}, head ${bound.head ?? "none"}; here ${now.lines}, head ${now.head ?? "none"})`);
  };
  const traceText = readText(abs(layout.root, layout.trace));
  const traceHashes = lineHashes(traceText ?? "");
  const journalText = readText(abs(layout.root, layout.journal));
  const journalHashes = journalText === null ? null : lineHashes(journalText);
  const reviewText = layout.review ? readText(layout.review) : null;
  const reviewHashes = layout.review ? lineHashes(reviewText ?? "") : null;
  const reviewLines = (reviewText ?? "").split("\n").filter((l) => l.trim());
  let prev: ReadRelease | null = null;
  let expected = 0;
  for (const r of all) {
    const tag = `Release v${r.version}:`.padEnd(14);
    if (r.version !== expected) fail(`${tag}VERSION ${expected} IS MISSING before it`);
    expected = r.version + 1;
    if (!r.record || !r.text || !r.sha256) {
      fail(`${tag}${r.error ?? "unreadable"}`);
      prev = r;
      continue;
    }
    const x = r.record;
    const parts: string[] = [];
    const bad: string[] = [];
    if (x.kind !== RELEASE_KIND || !RELEASE_SCHEMAS.includes(x.schema)) bad.push(`a record of kind ${JSON.stringify(x.kind)} schema ${JSON.stringify(x.schema)}, which this verifier does not know`);
    if (x.version !== r.version) bad.push(`it says it is version ${x.version}`);
    // Its place in the chain.
    if (r.version === 0) {
      if (x.prev !== null) bad.push("version 0 names a release before it");
    } else if (!x.prev || x.prev.version !== r.version - 1) bad.push(`it does not name v${r.version - 1} as the release before it`);
    else if (!prev?.sha256) bad.push(`it names v${r.version - 1}, which cannot be read`);
    else if (x.prev.sha256 !== prev.sha256) bad.push(`the v${r.version - 1} it names (${x.prev.sha256}) is not the v${r.version - 1} here (${prev.sha256})`);
    else parts.push(`follows v${r.version - 1}`);
    // Its signature, by its kind: the machine's seal is checked only against the machine key it names, and is never "verified".
    const sigPath = join(r.dir, releaseSigName(x));
    const releaseFile = join(r.dir, "release.json");
    let sig: { state: SignatureState; detail: string };
    if (x.signer?.kind === "machine") {
      const s = checkSshSignature({ file: releaseFile, sig: sigPath, namespace: RELEASE_NAMESPACE, principal: x.signer.principal ?? "", publicKey: x.signer.public ?? "" });
      sig = s.state === "unchecked" ? { state: "self-checked", detail: "machine seal, self-checked (sound under the machine key it names: it shows the install's machine key sealed these bytes, no more)" } : s;
    } else if (x.signer?.key_kind === "pkcs11") {
      const v = cmsVerify({ file: releaseFile, sig: sigPath, certSha256: x.signer.certificate?.sha256 ?? "", ca: opts.ca, intermediates: opts.caIntermediate });
      sig = { state: v.state, detail: v.detail };
    } else sig = checkSshSignature({ file: releaseFile, sig: sigPath, namespace: RELEASE_NAMESPACE, principal: x.signer?.principal ?? "", publicKey: x.signer?.public ?? "", allowedSigners: opts.allowedSigners });
    const kindWords = x.signer?.key_kind === "pkcs11" ? "e-signature certificate" : x.signer?.key_kind === "fido" ? "FIDO key" : "key";
    const who = x.signer?.kind === "examiner" ? `the examiner ${x.signer.examiner?.name ?? "?"} (${kindWords} ${x.signer.fingerprint})` : x.signer?.kind === "machine" ? `this install's machine key (${x.signer.fingerprint}), not an examiner` : "an unknown signer";
    signatures.push({ version: r.version, kind: x.signer?.kind ?? "unknown", state: sig.state, adopted: x.state === "adopted" });
    if (sig.state === "bad" || sig.state === "wrong-principal") bad.push(`SIGNATURE: ${sig.detail}`);
    else parts.push(`sealed by ${who}: ${sig.state === "self-checked" || x.signer?.key_kind === "pkcs11" ? sig.detail : `signature ${sig.state === "verified" ? `verified, ${sig.detail}` : sig.detail}`}`);
    if (x.signing) parts.push(`signed ${x.signing.via === "console" ? "from the console" : "on the command line"}, the consent ${x.signing.consent === "confirmed" ? `confirmed at ${x.signing.confirmed_at}` : `presented and its confirmation skipped (--yes) at ${x.signing.confirmed_at}`} over report.html ${x.signing.shown_sha256 === x.report?.html?.sha256 ? "as shown" : `NOT AS SHOWN (${x.signing.shown_sha256})`}`);
    if (x.signing && x.signing.shown_sha256 !== x.report?.html?.sha256) bad.push("the report.html it binds is not the one the examiner was shown");
    // A PDF signed on the token beside it.
    if (x.report?.pdf && x.signer?.key_kind === "pkcs11") {
      const pdfSig = cmsVerify({ file: join(layout.root, x.report.pdf.path), sig: join(layout.root, `${x.report.pdf.path}.p7s`), certSha256: x.signer.certificate?.sha256 ?? "", ca: opts.ca, intermediates: opts.caIntermediate });
      (pdfSig.state === "bad" ? bad : parts).push(`report.pdf's e-signature: ${pdfSig.detail}`);
    }
    if (x.state === "adopted" && x.signer?.kind !== "examiner") bad.push("it says adopted and is not an examiner's");
    if (x.state === "draft" && x.signer?.kind === "examiner") parts.push("a draft sealed by an examiner's key: not an adoption");
    // The bytes it binds.
    const html = held(x.report?.html?.path ?? `${RELEASE_DIR}/v${r.version}/report.html`, x.report?.html?.sha256);
    (html === "differs" || html === "missing" ? bad : parts).push(`report.html ${heldWord(html)}`);
    if (x.report?.pdf) {
      const pdf = held(x.report.pdf.path, x.report.pdf.sha256);
      (pdf === "differs" || pdf === "missing" ? bad : parts).push(`report.pdf ${heldWord(pdf)}`);
    }
    for (const p of x.report?.prints ?? []) {
      const h = held(p.path, p.sha256);
      (h === "differs" || h === "missing" ? bad : parts).push(`the print record ${p.path} ${heldWord(h)}`);
    }
    if (x.report?.markdown) {
      const md = held(x.report.markdown.path, x.report.markdown.sha256);
      // The run resumed after it and its continuation wrote its own report: the bytes this one binds were kept, by their digest.
      const keptAt = `${RELEASE_DIR}/bound/${x.report.markdown.sha256}`;
      if ((md === "differs" || md === "missing") && /^[0-9a-f]{64}$/.test(x.report.markdown.sha256) && resumedAfter(x.at) && held(keptAt, x.report.markdown.sha256) === "matches") {
        parts.push(`${x.report.markdown.path} as bound, kept at ${keptAt} when the run was resumed (the continuation's report is the next release's)`);
      } else (md === "differs" ? bad : parts).push(`${x.report.markdown.path} ${md === "missing" ? "not here (left in the run)" : heldWord(md)}`);
    }
    // The verdict and the index it names: the current ones, or ones custody kept aside.
    if (x.custody) {
      const candidates = [layout.custody, ...layout.custodyHistory];
      const hit = candidates.find((c) => held(c, x.custody?.sha256) !== "differs" && held(c, x.custody?.sha256) !== "missing");
      if (!hit) bad.push(`the custody verdict it binds (${x.custody.sha256}) is not here`);
      else {
        parts.push(hit === layout.custody ? "binds this custody verdict" : `binds an earlier custody verdict (${hit}); custody was taken again since`);
        // The registers that verdict sealed, held to what is here as the ledger is: as bound, or a prefix after a resume.
        // A verdict from before the seal sealed no chain's head, and holds the registers to nothing.
        let seal: Record<string, { lines?: number; head?: string | null } | undefined> | null = null;
        let readable = true;
        try {
          seal = (JSON.parse(readText(abs(layout.root, hit)) ?? "{}") as { seal?: Record<string, { lines?: number; head?: string | null }> }).seal ?? null;
        } catch {
          readable = false;
        }
        if (!readable) bad.push("the custody verdict it binds is not JSON: the chains it sealed cannot be read");
        else if (seal) {
          for (const g of registers) {
            const sealed = seal[g.key];
            if (!sealed) continue; // a verdict taken before that register was sealed
            const bound = { lines: Number(sealed.lines ?? 0), head: sealed.head ?? null };
            if (g.broken) {
              bad.push(`${g.what}'s chain here is ${g.broken}: it is not the one the custody verdict it binds sealed`);
              continue;
            }
            if (bound.lines === g.now.lines && bound.head === g.now.head) continue;
            // Appended to since (a follow-up recorded after the verdict, or the continuation of a resume), the part it binds intact.
            if (g.now.lines > bound.lines && (bound.lines === 0 || hashFieldAt(g.text, bound.lines) === bound.head)) {
              parts.push(`${g.what} it binds (${bound.lines} events) is a prefix of ${g.what} here (${g.now.lines}): what follows was recorded after the verdict`);
              continue;
            }
            bad.push(`${g.what} here is not the one the custody verdict it binds sealed (${bound.lines} events, head ${bound.head ?? "none"}; here ${g.now.lines}, head ${g.now.head ?? "none"}): it was deleted, cut or rewritten`);
          }
        }
      }
    }
    if (x.sealed_index) {
      const candidates = [layout.sealedIndex, ...layout.indexHistory];
      const hit = candidates.find((c) => ["matches", "redacted"].includes(held(c, x.sealed_index?.sha256)));
      if (!hit) bad.push(`the sealed index of work/ it binds (${x.sealed_index.sha256}) is not here`);
    }
    // The chains custody sealed: as they are; the growing ones as prefixes.
    const c = x.chains;
    if (c) {
      if (c.ledger) asBound("ledger", "the ledger", { lines: c.ledger.entries, head: c.ledger.head }, ledgerNow, x.at, bad, parts);
      if (c.attestations) asBound("attestations", "the attestations", c.attestations, attNow, x.at, bad, parts);
      if (c.disputes) asBound("disputes", "the disputes", c.disputes, dispNow, x.at, bad, parts);
      if (c.trace?.lines) {
        const at = traceHashes[c.trace.lines - 1];
        const broke = prevChainBreak(traceText ?? "", c.trace.lines);
        if (at === undefined) bad.push(`the trace has ${traceHashes.length} lines, fewer than the ${c.trace.lines} it binds`);
        else if (at !== c.trace.last_line_sha256) bad.push(`trace line ${c.trace.lines} is not the one it binds`);
        else if (broke !== null) bad.push(`trace line ${broke} does not name the line before it: the trace it binds was changed`);
      }
      if (c.journal) {
        if (!journalHashes) bad.push("the store journal it binds is not here");
        else if (c.journal.lines && journalHashes[c.journal.lines - 1] !== c.journal.head) bad.push(`store journal line ${c.journal.lines} is not the one it binds`);
        else if (c.journal.lines && prevChainBreak(journalText ?? "", c.journal.lines) !== null) bad.push(`store journal line ${prevChainBreak(journalText ?? "", c.journal.lines)} does not name the line before it`);
      }
      if (c.review && c.review.lines) {
        const broke = prevChainBreak(reviewText ?? "", c.review.lines);
        if (!reviewHashes) parts.push("the review it binds is not here");
        else if (reviewHashes[c.review.lines - 1] !== c.review.head) bad.push(`review line ${c.review.lines} is not the one it binds: the examiner's review changed under it`);
        else if (broke !== null) bad.push(`review line ${broke} does not name the line before it: the examiner's review changed under it`);
      }
      if (!bad.length) parts.push("every chain it binds is as bound");
    }
    // The examiner's sign-off names it (the review line written after the signature).
    if (x.state === "adopted" && reviewLines.length) {
      const named = reviewLines.some((l) => {
        try {
          const o = JSON.parse(l) as { action?: string; release?: { version?: number; sha256?: string } };
          return o.action === "sign" && o.release?.version === r.version && o.release?.sha256 === r.sha256;
        } catch {
          return false;
        }
      });
      parts.push(named ? "the review's sign-off names it" : "NO SIGN-OFF IN THE REVIEW NAMES IT (the line after its signature was not written)");
    }
    // Its line in the anchor beside the run.
    if (anchorReleases) {
      const a = anchorReleases.find((e) => e.version === r.version);
      if (!a) bad.push("the anchor beside the run does not name it");
      else if (a.sha256 !== r.sha256) bad.push(`the anchor names another v${r.version} (${a.sha256})`);
      else parts.push("anchored beside the run");
    } else parts.push(layout.anchor ? "the anchor is not readable" : "no anchor here to hold it to");
    // A token over its signature.
    const tsr = `${sigPath}.tsr`;
    if (existsSync(tsr) && existsSync(sigPath)) {
      const sigSha = fileSha(sigPath) ?? "";
      const read = readTimestampResponse(readFileSync(tsr), sigSha);
      const said = readText(join(r.dir, "timestamp.json"));
      let obtained: string | null = null;
      try {
        obtained = said ? String((JSON.parse(said) as { obtained_at?: string }).obtained_at ?? "") || null : null;
      } catch {
        obtained = null;
      }
      const checked = opts.tsaCa ? await verifyTimestampToken(tsr, sigPath, opts.tsaCa) : null;
      const later = obtained && Date.parse(obtained) - Date.parse(x.at) > 10 * 60_000 ? `, obtained ${obtained}, after the release (${x.at}): the proof of existence dates from the token's time, not the release's` : "";
      if (!read.imprint) bad.push("its timestamp token does not name its signature's sha256");
      else if (checked?.verified === false) bad.push(`its timestamp token DOES NOT VERIFY against ${opts.tsaCa} (${checked.detail})`);
      else if (opts.tsaCa && checked?.verified !== true) bad.push(`its timestamp token was not checked against ${opts.tsaCa} (${checked?.detail ?? "no answer"})`);
      else parts.push(`timestamped ${read.gen_time ?? "(time unread)"}${checked?.verified ? ` (token verified against ${opts.tsaCa})` : " (imprint only: give --tsa-ca FILE to check the authority's signature)"}${later}`);
    } else parts.push("not timestamped");
    // The technical reviews it binds as signed: still signed and over the state it binds.
    if (x.adoption?.technical_review?.length && reviewText !== null && c?.review) {
      const boundLines = reviewLines.slice(0, c.review.lines).map((l) => {
        try {
          return { ...(JSON.parse(l) as ReviewLine), text: l };
        } catch {
          return { text: l } as ReviewLine & { text: string };
        }
      });
      const boundState = { report_sha256: x.report?.markdown?.sha256 ?? null, ledger_head: c.ledger?.head ?? null, custody_sha256: x.custody?.sha256 ?? null, dispositions_head: dispositionsHead(boundLines) };
      const now = technicalReviewsOf(boundLines, boundState);
      for (const t of x.adoption.technical_review) {
        const again = now.find((n) => n.review_seq === t.review_seq);
        const claimed = t.status === "signed" || t.status === "countersigned-after-release";
        if (!again) bad.push(`the technical review at review line ${t.review_seq} it binds is not in the review here`);
        else if (claimed && again.status !== t.status) bad.push(`the technical review by ${t.reviewer.name} (review line ${t.review_seq}) it binds as ${t.status} is now: ${again.words}`);
        else if (again.status === "bad-signature") bad.push(`the technical review by ${t.reviewer.name}: ${again.words}`);
        else parts.push(`technical review by ${t.reviewer.name}${t.outcome ? ` (${t.outcome})` : ""}: ${again.words}`);
      }
      if (x.policy?.require_technical_review && !now.some(satisfiesPolicy)) bad.push("it was sealed under --require-technical-review, and no technical review it binds is signed by the reviewer, current and other than a disagreement");
    } else if (x.state === "adopted" && x.schema === 2) parts.push(`${NO_TECHNICAL_REVIEW.toLowerCase()} bound`);
    // Where the run ran, when its agents may have reached the signers' keys (host mode, not recorded as hidden).
    if (x.host && x.host.isolation !== "microvm" && x.host.signer_keys_hidden !== true) parts.push(`the host: ${x.host.note}`);
    if (x.missing?.length) parts.push(`could not bind: ${x.missing.join("; ")}`);
    if (bad.length) fail(`${tag}${x.state.toUpperCase()}, ${x.at}, NOT AS SEALED: ${bad.join("; ")}${parts.length ? ` (${parts.join("; ")})` : ""}`);
    else lines.push(`${tag}${x.state === "adopted" ? "ADOPTED" : "DRAFT"}, ${x.at}, ${x.reason}: ${parts.join("; ")}`);
    prev = r;
  }
  // Every technical review in the review, against the latest release's state: said, and a countersign that does not verify fails.
  let technical: TechnicalReview[] | undefined;
  const latest = all.at(-1)?.record;
  if (reviewText !== null && latest) {
    const parsed = reviewLines.map((l) => {
      try {
        return { ...(JSON.parse(l) as ReviewLine), text: l };
      } catch {
        return { text: l } as ReviewLine & { text: string };
      }
    });
    technical = technicalReviewsOf(parsed, { report_sha256: latest.report?.markdown?.sha256 ?? null, ledger_head: latest.chains?.ledger?.head ?? null, custody_sha256: latest.custody?.sha256 ?? null, dispositions_head: dispositionsHead(parsed) });
    if (!technical.length) lines.push(`Technical:    ${NO_TECHNICAL_REVIEW}.`);
    for (const t of technical) {
      const line = `Technical:    review line ${t.review_seq}, by ${t.reviewer.name}${t.outcome ? `, ${t.outcome}` : ""}: ${t.words}`;
      if (t.status === "bad-signature") fail(line);
      else lines.push(line);
    }
  }
  // What the chain comes to.
  const last = all.at(-1)?.record;
  const adopted = [...all].reverse().find((r) => r.record?.state === "adopted");
  lines.push(
    `Releases:     ${all.length} (v0..v${all.at(-1)?.version}); ${adopted ? `the latest adoption is v${adopted.version} by ${adopted.record?.signer.examiner?.name ?? "?"}` : "none adopted by an examiner: every one is the machine's draft"}${last && adopted && last !== adopted.record ? `; v${all.at(-1)?.version} after it is a ${last.state}` : ""}`,
  );

  return { ok, lines, releases: all.length, signatures, technical };
}
