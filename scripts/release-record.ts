/**
 * A run's releases as files, and how a reader checks them, in the run or
 * in a package (scripts/release.ts writes them).
 *
 * A release is what was handed over, as which bytes, sealed by whom:
 *
 *   release/v<N>/release.json       the record (below)
 *   release/v<N>/release.json.sig   its ssh signature (namespace dfirswarm-release)
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
 * the host held, adopted by no one. v1 is written when an enrolled examiner
 * signs (`swarm.sh review <id> --sign`): the examiner's key, the
 * dispositions of each answer, the report's final bytes rendered for that
 * release (no DRAFT mark) and printed when asked. Every later version names
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

export const RELEASE_DIR = "release";
export const RELEASE_SCHEMA = 1;
export const RELEASE_KIND = "dfirswarm-release";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

export type ChainHead = { lines: number; head: string | null };

export type ReleaseSigner = {
  kind: "machine" | "examiner";
  principal: string;
  /** The signing key's public half (an ssh public key line): public, and what a reader checks the signature against. */
  public: string;
  fingerprint: string;
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
  technical_review: Array<{ reviewer: { name: string; organisation: string | null; competence: string }; methods_checked: string; entries: Array<{ seq: number; hash: string | null }>; note: string | null; at: string; review_seq: number; recorded_by: string }>;
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
};

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
  signatures: Array<{ version: number; kind: "machine" | "examiner" | "unknown"; state: SignatureState; adopted: boolean }>;
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
 * custody kept aside), the ledger, its attestations and disputes as they
 * are, the trace, the journal and the review as prefixes (lines may follow
 * a release; the ones it bound may not change), its line in the anchor
 * beside the run, and a timestamp token over its signature, against the
 * authority's CA when one is given.
 */
export async function verifyReleases(layout: ReleaseLayout, opts: { allowedSigners?: string; tsaCa?: string } = {}): Promise<ReleaseCheck> {
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
  const anchorText = readText(layout.anchor);
  if (anchorText) {
    try {
      const a = JSON.parse(anchorText) as { releases?: unknown };
      anchorReleases = Array.isArray(a.releases) ? (a.releases as Array<{ version?: number; sha256?: string }>) : [];
    } catch {
      anchorReleases = null;
    }
  }
  const ledgerNow = hashFieldHead(readText(abs(layout.root, layout.ledger)));
  const attNow = hashFieldHead(readText(abs(layout.root, layout.attestations)));
  const dispNow = hashFieldHead(readText(abs(layout.root, layout.disputes)));
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
    if (x.kind !== RELEASE_KIND || x.schema !== RELEASE_SCHEMA) bad.push(`a record of kind ${JSON.stringify(x.kind)} schema ${JSON.stringify(x.schema)}, which this verifier does not know`);
    if (x.version !== r.version) bad.push(`it says it is version ${x.version}`);
    // Its place in the chain.
    if (r.version === 0) {
      if (x.prev !== null) bad.push("version 0 names a release before it");
    } else if (!x.prev || x.prev.version !== r.version - 1) bad.push(`it does not name v${r.version - 1} as the release before it`);
    else if (!prev?.sha256) bad.push(`it names v${r.version - 1}, which cannot be read`);
    else if (x.prev.sha256 !== prev.sha256) bad.push(`the v${r.version - 1} it names (${x.prev.sha256}) is not the v${r.version - 1} here (${prev.sha256})`);
    else parts.push(`follows v${r.version - 1}`);
    // Its signature.
    const sigPath = join(r.dir, "release.json.sig");
    const sig = checkSshSignature({ file: join(r.dir, "release.json"), sig: sigPath, namespace: RELEASE_NAMESPACE, principal: x.signer?.principal ?? "", publicKey: x.signer?.public ?? "", allowedSigners: opts.allowedSigners });
    const who = x.signer?.kind === "examiner" ? `the examiner ${x.signer.examiner?.name ?? "?"} (${x.signer.fingerprint})` : x.signer?.kind === "machine" ? `this install's machine key (${x.signer.fingerprint}), not an examiner` : "an unknown signer";
    signatures.push({ version: r.version, kind: x.signer?.kind ?? "unknown", state: sig.state, adopted: x.state === "adopted" });
    if (sig.state === "bad" || sig.state === "wrong-principal") bad.push(`SIGNATURE: ${sig.detail}`);
    else parts.push(`sealed by ${who}: signature ${sig.state === "verified" ? `verified, ${sig.detail}` : sig.detail}`);
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
      (md === "differs" ? bad : parts).push(`${x.report.markdown.path} ${md === "missing" ? "not here (left in the run)" : heldWord(md)}`);
    }
    // The verdict and the index it names: the current ones, or ones custody kept aside.
    if (x.custody) {
      const candidates = [layout.custody, ...layout.custodyHistory];
      const hit = candidates.find((c) => held(c, x.custody?.sha256) !== "differs" && held(c, x.custody?.sha256) !== "missing");
      if (!hit) bad.push(`the custody verdict it binds (${x.custody.sha256}) is not here`);
      else parts.push(hit === layout.custody ? "binds this custody verdict" : `binds an earlier custody verdict (${hit}); custody was taken again since`);
    }
    if (x.sealed_index) {
      const candidates = [layout.sealedIndex, ...layout.indexHistory];
      const hit = candidates.find((c) => ["matches", "redacted"].includes(held(c, x.sealed_index?.sha256)));
      if (!hit) bad.push(`the sealed index of work/ it binds (${x.sealed_index.sha256}) is not here`);
    }
    // The chains custody sealed: as they are; the growing ones as prefixes.
    const c = x.chains;
    if (c) {
      if (c.ledger && (c.ledger.entries !== ledgerNow.lines || c.ledger.head !== ledgerNow.head)) bad.push(`the ledger is not the one it binds (${c.ledger.entries} entries, head ${c.ledger.head ?? "none"}; here ${ledgerNow.lines}, head ${ledgerNow.head ?? "none"})`);
      if (c.attestations && (c.attestations.lines !== attNow.lines || c.attestations.head !== attNow.head)) bad.push(`the attestations are not the ones it binds (${c.attestations.lines} lines; here ${attNow.lines})`);
      if (c.disputes && (c.disputes.lines !== dispNow.lines || c.disputes.head !== dispNow.head)) bad.push(`the disputes are not the ones it binds (${c.disputes.lines} lines; here ${dispNow.lines})`);
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
    const tsr = join(r.dir, "release.json.sig.tsr");
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
    if (x.missing?.length) parts.push(`could not bind: ${x.missing.join("; ")}`);
    if (bad.length) fail(`${tag}${x.state.toUpperCase()}, ${x.at}, NOT AS SEALED: ${bad.join("; ")}${parts.length ? ` (${parts.join("; ")})` : ""}`);
    else lines.push(`${tag}${x.state === "adopted" ? "ADOPTED" : "DRAFT"}, ${x.at}, ${x.reason}: ${parts.join("; ")}`);
    prev = r;
  }
  // What the chain comes to.
  const last = all.at(-1)?.record;
  const adopted = [...all].reverse().find((r) => r.record?.state === "adopted");
  lines.push(
    `Releases:     ${all.length} (v0..v${all.at(-1)?.version}); ${adopted ? `the latest adoption is v${adopted.version} by ${adopted.record?.signer.examiner?.name ?? "?"}` : "none adopted by an examiner: every one is the machine's draft"}${last && adopted && last !== adopted.record ? `; v${all.at(-1)?.version} after it is a ${last.state}` : ""}`,
  );

  return { ok, lines, releases: all.length, signatures };
}
