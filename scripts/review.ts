/**
 * The examiner's review of a run's ledger: the one writer of it.
 *
 * An entry the swarm recorded is the swarm's word. What the examiner makes
 * of it — accepted, rejected, amended with a note — and the sign-off over
 * the whole ledger are the examiner's, and they are kept apart from
 * anything an agent can reach: `$SWARM_RUNS_DIR/reviews/<run>.jsonl`,
 * beside the registry, 0600. One JSON line per act, chained: each line's
 * `prev` is the SHA-256 of the previous line's text, as the operator's
 * audit is, so a line taken out or changed breaks the chain. Written under
 * a lock, appended, never rewritten.
 *
 *   {v: 1, seq, at, examiner, os_user, host, action: accept|reject|amend|sign,
 *    entry_seq?, entry_hash?, note?, ledger_head?, ledger_entries?,
 *    report_path?, report_sha256?, attestations_head?, open_rejections?, prev}
 *
 * The examiner's disposition of a conclusion (an `answer` entry, ledger
 * version 4, or any entry) is `adopt`, `qualify` (adopt with a stated
 * qualification), `reject` (withdraw it) or `inconclusive`, by seq and
 * hash. A conclusion whose support is defective (scripts/adoption.ts) is
 * refused `adopt` and `qualify`: the examiner cannot waive missing evidence
 * into a supported conclusion; it is withdrawn or rendered inconclusive, and
 * repairing its support is further examination (a new run), not a review
 * act. `technical_review` records a second person who checked the methods:
 * who, on what competence, what was checked. These acts, and `sign`, are an
 * enrolled examiner's (scripts/signers.ts): the line names the examiner's
 * id and key; `sign` is written by scripts/release.ts after the release it
 * names was signed with that key, and names it (version, sha256, the
 * signature's sha256). accept, reject and amend of a finding may still name
 * an examiner who is not enrolled, and the line says so by carrying no id.
 * The run's registry `examiner` (what the kickoff was told) is never taken
 * for the examiner.
 *
 * `entry_hash` is the entry's own hash from the ledger's chain (its
 * immutable core); `sign` records the head of the chain it signs, the
 * report's own hash and the head of the attestations, and the entries the
 * examiner had rejected and not since accepted, so a sign-off over a ledger
 * or a report that changed afterwards is seen to be over another, and a
 * sign-off with objections standing says so. A sign-off is over a report:
 * with no report at the path it names, it is refused, never written over
 * nothing. `show` exits 4 when the ledger or the report has moved since the
 * sign-off: a sign-off that covers something else is not a pass.
 *
 * Usage:
 *   node scripts/review.ts add --runs DIR --run ID --sandbox DIR --examiner NAME
 *        --action accept|reject|amend|sign [--entry SEQ] [--note TEXT]
 *   node scripts/review.ts show --runs DIR --run ID [--sandbox DIR] [--json]
 *        (exit 1: the review's chain is broken; 4: the sign-off does not cover
 *        the ledger head or the report as they are now)
 *   node scripts/review.ts verify --runs DIR --run ID
 *   node scripts/review.ts prior --runs DIR --run ID --sandbox DIR --out FILE
 */
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, mkdir, open, rm, stat, writeFile } from "node:fs/promises";
import { hostname, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { hashRegularFile, readRegularText } from "./regular-file.ts";
import { dispositionsOf, dispositionWords, supportDefects, type Defect, type DispositionAct } from "./adoption.ts";
import { loadExaminer } from "./signers.ts";
import { supersededBy, type LedgerDispute, type LedgerEntry } from "../extensions/protocol.ts";

export type ReviewAction = "accept" | "reject" | "amend" | "sign" | "adopt" | "qualify" | "inconclusive" | "technical_review";
export const REVIEW_ACTIONS: readonly ReviewAction[] = ["accept", "reject", "amend", "sign", "adopt", "qualify", "inconclusive", "technical_review"];
/**
 * The acts only an enrolled examiner makes. A sign-off is one too; it is
 * written by scripts/release.ts once the release it names is signed with
 * the enrolled examiner's key (the CLI here refuses to write one), and a
 * sign line without a release is an older run's chained record.
 */
export const ENROLLED_ACTIONS: readonly ReviewAction[] = ["adopt", "qualify", "inconclusive", "technical_review"];

export type ReviewLine = {
  v: 1;
  seq: number;
  at: string;
  examiner: string;
  os_user: string;
  host: string;
  action: ReviewAction;
  entry_seq?: number;
  entry_hash?: string;
  /** The entry's kind and, for an answer, its section, as the act saw them. */
  entry_kind?: string;
  section?: string;
  /** The enrolled examiner's id and key fingerprint (scripts/signers.ts); absent for a name given free. */
  examiner_id?: string;
  key?: string;
  note?: string;
  /** technical_review: the second person, what qualifies them, what they checked, and over which entries. */
  reviewer?: { name: string; organisation?: string; competence: string };
  methods_checked?: string;
  entries?: Array<{ seq: number; hash: string }>;
  /** sign: the release the examiner signed (scripts/release.ts), by version, sha256 and its signature's sha256. */
  release?: { version: number; sha256: string; signature_sha256: string };
  ledger_head?: string;
  ledger_entries?: number;
  /** The report the sign-off is over, as a path under the sandbox and its sha256 (null: there was none). */
  report_path?: string;
  report_sha256?: string | null;
  /** The last line of ledger/attestations.jsonl, or null when there are none. */
  attestations_head?: string | null;
  /** Entries whose latest review was a rejection when the examiner signed. */
  open_rejections?: number[];
  prev: string | null;
};

/** A line as it was read: the parsed object and the exact text the next line's `prev` hashes. */
export type ReadReviewLine = ReviewLine & { text: string };

type LedgerLine = { seq?: number; kind?: string; ts?: string; value?: string; source?: string; evidence?: string; confidence?: string; by?: string; at?: string; hash?: string; supersedes?: number };

const sha256 = (text: string | Buffer) => createHash("sha256").update(text).digest("hex");

/**
 * A review or a ledger that is there and is not a regular file: a link, a
 * FIFO, a directory planted in its place. Never read through, and never
 * taken for "no review": the caller says what it found.
 */
export class ReviewFileError extends Error {
  readonly why: string;
  readonly path: string;
  constructor(path: string, why: string) {
    super(`${path} is ${why}; it is not read`);
    this.name = "ReviewFileError";
    this.path = path;
    this.why = why;
  }
}

/** Reviews and ledgers are small; a file past this is refused, never cut. */
const READ_MAX_BYTES = 512 * 1024 * 1024;

/** A file's text through the no-follow reader: "" when missing, a ReviewFileError for anything but a regular file. */
async function readText(path: string): Promise<string> {
  const r = await readRegularText(path, READ_MAX_BYTES);
  if ("text" in r) return r.text;
  if (r.why === "missing") return "";
  throw new ReviewFileError(path, r.why);
}

export function reviewsPath(runsDir: string, runId: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(runId)) throw new Error(`not a run id: ${JSON.stringify(runId)}`);
  return join(runsDir, "reviews", `${runId}.jsonl`);
}

/**
 * Every review line of a run in file order, each with its own text; [] when
 * there is none. A torn or foreign line is kept as text with no fields, so
 * the chain check sees it. A link, a FIFO or anything but a regular file in
 * the review's place throws a ReviewFileError: it is not a review, and it
 * is not "no review" either.
 */
export async function readReviews(runsDir: string, runId: string): Promise<ReadReviewLine[]> {
  const text = await readText(reviewsPath(runsDir, runId));
  const out: ReadReviewLine[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    try {
      out.push({ ...(JSON.parse(line) as ReviewLine), text: line });
    } catch {
      out.push({ text: line } as ReadReviewLine);
    }
  }
  return out;
}

/**
 * Whether the lines are the chain they claim: seq from 1 up by one, each
 * `prev` the SHA-256 of the line before (null on the first), every action
 * one of the four. Takes what readReviews returned, or the file's text.
 */
export function verifyReviewChain(lines: ReadReviewLine[] | Array<{ text: string }> | string): { ok: boolean; total: number; broken_at: number | null; reason: string | null } {
  const texts = typeof lines === "string" ? lines.split("\n").filter(Boolean) : lines.map((l) => l.text);
  let prev: string | null = null;
  for (let i = 0; i < texts.length; i++) {
    let line: ReviewLine;
    try {
      line = JSON.parse(texts[i]) as ReviewLine;
    } catch {
      return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} is not JSON` };
    }
    if (line.seq !== i + 1) return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} says seq ${line.seq}` };
    if ((line.prev ?? null) !== prev) return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} does not follow the line before it (a line was changed, removed or put in)` };
    if (!REVIEW_ACTIONS.includes(line.action)) return { ok: false, total: texts.length, broken_at: i + 1, reason: `line ${i + 1} has no known action` };
    prev = sha256(texts[i]);
  }
  return { ok: true, total: texts.length, broken_at: null, reason: null };
}

/** Each reviewed entry's latest act, and the latest sign-off. */
export function reviewState(lines: ReviewLine[]): { entries: Map<number, ReviewLine>; signed: ReviewLine | null } {
  const entries = new Map<number, ReviewLine>();
  let signed: ReviewLine | null = null;
  for (const l of lines) {
    if (l.action === "sign") signed = l;
    else if (typeof l.entry_seq === "number") entries.set(l.entry_seq, l);
  }
  return { entries, signed };
}

async function readLedger(sandbox: string): Promise<{ entries: Array<LedgerLine & { text: string }>; sha256: string }> {
  const file = join(sandbox, "ledger", "entries.jsonl");
  // In a host run the ledger sits where a pane can write: a link or a FIFO
  // there is refused by name, never read through or waited on.
  const raw = Buffer.from(await readText(file), "utf8");
  const entries: Array<LedgerLine & { text: string }> = [];
  for (const line of raw.toString("utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      entries.push({ ...(JSON.parse(line) as LedgerLine), text: line });
    } catch {
      // a torn line is no entry
    }
  }
  return { entries, sha256: sha256(raw) };
}

/** The entry's own hash from the ledger's chain, or the line's when it is unchained. */
const entryHash = (e: LedgerLine & { text: string }) => e.hash ?? sha256(e.text);

/** The head of the ledger a sign-off is over: the last entry's chain hash, or the file's when nothing is chained. */
export function ledgerHead(entries: Array<LedgerLine & { text: string }>, fileSha: string): string {
  const last = [...entries].reverse().find((e) => typeof e.hash === "string");
  return last?.hash ?? `file:${fileSha}`;
}

async function withLock<T>(file: string, fn: () => Promise<T>): Promise<T> {
  const lock = `${file}.lock`;
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      await mkdir(lock);
      break;
    } catch {
      // A lock a writer left when it died goes stale after a minute.
      const st = await stat(lock).catch(() => null);
      if (st && Date.now() - st.mtimeMs > 60_000) {
        await rm(lock, { recursive: true, force: true });
        continue;
      }
      if (Date.now() > deadline) throw new Error(`${lock} is held; another review is being written`);
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lock, { recursive: true, force: true });
  }
}

export type ReviewInput = {
  action: ReviewAction;
  examiner: string;
  /** The enrolled examiner's id and key fingerprint; required for the acts only an enrolled examiner makes. */
  examinerId?: string;
  key?: string;
  entry_seq?: number;
  note?: string;
  report?: string;
  /** technical_review: who checked the methods, and what. */
  reviewer?: { name: string; organisation?: string; competence: string };
  methodsChecked?: string;
  entries?: number[];
  /** sign: the release it is over. */
  release?: { version: number; sha256: string; signature_sha256: string };
};

/** The agents' disputes (ledger/disputes.jsonl), read as a regular file; [] when there are none. */
export async function readDisputeLines(sandbox: string): Promise<LedgerDispute[]> {
  const text = await readText(join(sandbox, "ledger", "disputes.jsonl"));
  const out: LedgerDispute[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerDispute);
    } catch {
      // a torn line disputes nothing
    }
  }
  return out;
}

/**
 * Each entry's refs on a job that did not succeed and that the entry does
 * not qualify, as "ref (status)", by seq: the job's own record under
 * store/jobs/ says how it ended (as check-answers.ts reads it).
 */
export async function failedJobRefs(sandbox: string, entries: readonly LedgerEntry[]): Promise<Map<number, string[]>> {
  const status = new Map<string, string | null>();
  const out = new Map<number, string[]>();
  for (const e of entries) {
    for (const ref of e.refs ?? []) {
      const m = /^job:([a-z0-9-]{1,64})(?:\/|$)/.exec(ref);
      if (!m) continue;
      if (!status.has(m[1])) {
        const r = await readRegularText(join(sandbox, "store", "jobs", m[1], "job.json"), 16 * 1024 * 1024).catch(() => null);
        let st: string | null = null;
        try {
          st = r && "text" in r ? ((JSON.parse(r.text) as { status?: string }).status ?? null) : null;
        } catch {
          st = null;
        }
        status.set(m[1], st);
      }
      const st = status.get(m[1]);
      if (st && st !== "ok" && !(e.qualifies ?? []).some((q) => q.ref === ref)) out.set(e.seq, [...(out.get(e.seq) ?? []), `${ref} (${st})`]);
    }
  }
  return out;
}

/** The ledger as entries, what each standing one's support lacks, and what supersedes what. */
export async function ledgerDefects(sandbox: string): Promise<{ entries: LedgerEntry[]; defects: Map<number, Defect[]>; superseded: Map<number, number> }> {
  const ledger = await readLedger(sandbox);
  const entries = ledger.entries.map(({ text: _text, ...e }) => e as unknown as LedgerEntry);
  const disputes = await readDisputeLines(sandbox);
  const failed = await failedJobRefs(sandbox, entries);
  return { entries, defects: supportDefects(entries, disputes, failed), superseded: supersededBy(entries) };
}

/** A relative path that stays under the run: no leading slash, no "..". */
export function isSandboxPath(rel: string): boolean {
  return Boolean(rel) && !rel.startsWith("/") && !rel.split("/").includes("..");
}

/**
 * What a sign-off covers, against the run as it is now: whether the
 * ledger's head and the report's hash are still the ones it names. A
 * sign-off that names no report (one written before a report was required)
 * covers none; null is a part that was not read. `current` is true only
 * when the review's chain holds and both are the ones signed.
 */
export function signoffCoverage(signed: ReviewLine, now: { chainOk: boolean; ledgerHead: string | null; reportSha: string | null | undefined }): { ledger: boolean | null; report: boolean | null; current: boolean } {
  const ledger = now.ledgerHead === null || !signed.ledger_head ? null : signed.ledger_head === now.ledgerHead;
  const report = !signed.report_sha256 ? false : now.reportSha === undefined ? null : signed.report_sha256 === now.reportSha;
  return { ledger, report, current: now.chainOk && ledger === true && report === true };
}

/** The sha256 of a regular file's bytes under the sandbox (as the report and custody hash it), or null when there is none. */
async function sandboxFileSha(sandbox: string, rel: string): Promise<string | null> {
  const r = await hashRegularFile(join(sandbox, rel)).catch(() => null);
  return r && "sha256" in r ? r.sha256 : null;
}

/** The attestations' head: the last line's hash, or null. */
async function attestationsHead(sandbox: string): Promise<string | null> {
  const r = await readRegularText(join(sandbox, "ledger", "attestations.jsonl"), READ_MAX_BYTES).catch(() => null);
  const text = r && "text" in r ? r.text : "";
  const last = text.trim().split("\n").filter(Boolean).at(-1);
  if (!last) return null;
  try {
    return (JSON.parse(last) as { hash?: string }).hash ?? null;
  } catch {
    return null;
  }
}

/** Append one act to a run's review, checked against its ledger. Returns the line written. */
export async function appendReview(runsDir: string, runId: string, sandbox: string, input: ReviewInput): Promise<ReviewLine> {
  if (!REVIEW_ACTIONS.includes(input.action)) throw new Error(`action must be one of ${REVIEW_ACTIONS.join(", ")}`);
  const examiner = (input.examiner ?? "").trim();
  if (!examiner) throw new Error("an examiner's name is required (--examiner)");
  if (ENROLLED_ACTIONS.includes(input.action) && !input.examinerId) throw new Error(`${input.action.replace("_", " ")} is an enrolled examiner's act: enrol with swarm.sh examiner enroll, and name the examiner by id (--examiner ID)`);
  const note = input.note?.trim() || undefined;
  if ((input.action === "reject" || input.action === "amend" || input.action === "qualify" || input.action === "inconclusive") && !note) throw new Error(`${input.action} needs a note saying why (--note)`);
  const ledger = await readLedger(sandbox);
  // What stands in the way of adopting a conclusion, read before the lock (the ledger is sealed once the run has ended).
  const judged = input.action === "adopt" || input.action === "qualify" ? await ledgerDefects(sandbox) : null;
  const file = reviewsPath(runsDir, runId);
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await chmod(dirname(file), 0o700).catch(() => undefined);
  return withLock(file, async () => {
    const before = await readReviews(runsDir, runId);
    const chain = verifyReviewChain(before);
    if (!chain.ok) throw new Error(`the review of ${runId} is broken (${chain.reason}); nothing is added to a broken chain`);
    const line: ReviewLine = {
      v: 1,
      seq: before.length + 1,
      at: new Date().toISOString(),
      examiner,
      os_user: userInfo().username,
      host: hostname(),
      action: input.action,
      prev: before.length ? sha256(before[before.length - 1].text) : null,
    };
    if (input.examinerId) line.examiner_id = input.examinerId;
    if (input.key) line.key = input.key;
    if (input.action === "sign") {
      if (!ledger.entries.length) throw new Error(`run ${runId} has no ledger entries to sign`);
      line.ledger_head = ledgerHead(ledger.entries, ledger.sha256);
      line.ledger_entries = ledger.entries.length;
      // The report the examiner read, and what still stood against it.
      line.report_path = input.report ?? "work/report.md";
      if (!isSandboxPath(line.report_path)) throw new Error(`${JSON.stringify(line.report_path)} is not a path under the run (--report work/…)`);
      line.report_sha256 = await sandboxFileSha(sandbox, line.report_path);
      // A sign-off names the report the examiner read; over nothing, it would read as over whatever is there later.
      if (!line.report_sha256) throw new Error(`there is no ${line.report_path} in run ${runId} to sign over: a sign-off is over the report the examiner read (--report PATH names another)`);
      line.attestations_head = await attestationsHead(sandbox);
      // An answer rejected is withdrawn, a disposition, not an objection left standing against the sign-off.
      line.open_rejections = [...reviewState(before).entries.values()].filter((l) => l.action === "reject" && l.entry_kind !== "answer").map((l) => l.entry_seq as number).sort((a, b) => a - b);
      if (input.release) line.release = input.release;
    } else if (input.action === "technical_review") {
      // A second person who checked the methods: who, on what competence, what they checked.
      const r = input.reviewer;
      if (!r?.name?.trim()) throw new Error("a technical review names who did it (--reviewer NAME)");
      if (!r.competence?.trim()) throw new Error("a technical review says what qualifies the reviewer (--competence TEXT)");
      if (!input.methodsChecked?.trim()) throw new Error("a technical review says which methods were checked (--checked TEXT)");
      line.reviewer = { name: r.name.trim(), ...(r.organisation?.trim() ? { organisation: r.organisation.trim() } : {}), competence: r.competence.trim() };
      line.methods_checked = input.methodsChecked.trim();
      if (input.entries?.length) {
        line.entries = input.entries.map((seq) => {
          const e = ledger.entries.find((x) => x.seq === seq);
          if (!e) throw new Error(`run ${runId} has no ledger entry ${seq}`);
          return { seq, hash: entryHash(e) };
        });
      }
    } else {
      if (!Number.isInteger(input.entry_seq)) throw new Error(`${input.action} needs the entry's seq (--entry N)`);
      const entry = ledger.entries.find((e) => e.seq === input.entry_seq);
      if (!entry) throw new Error(`run ${runId} has no ledger entry ${input.entry_seq}`);
      line.entry_seq = input.entry_seq;
      line.entry_hash = entryHash(entry);
      if (entry.kind) line.entry_kind = entry.kind;
      const section = (entry as { section?: unknown }).section;
      if (typeof section === "string") line.section = section;
      // Withdrawing a conclusion is a disposition, and an enrolled examiner's.
      if (input.action === "reject" && entry.kind === "answer" && !input.examinerId) throw new Error("withdrawing an answer is an enrolled examiner's disposition: name the examiner by id (--examiner ID)");
      if ((input.action === "adopt" || input.action === "qualify") && judged) {
        const by = judged.superseded.get(entry.seq as number);
        if (by !== undefined) throw new Error(`E-${entry.seq} is superseded by E-${by}: the correction is what stands, and what is adopted`);
        const d = judged.defects.get(entry.seq as number) ?? [];
        if (d.length) {
          throw new Error(
            `E-${entry.seq} cannot be ${input.action === "adopt" ? "adopted" : "qualified"}: its support is not sound as it stands (${d.map((x) => x.what).join("; ")}). An unsupported conclusion is not waived: withdraw it (--reject ${entry.seq} --note), or render it inconclusive (--inconclusive ${entry.seq} --note). Repairing its support is further examination: a new run, whose evidence cutoff is reopened.`,
          );
        }
      }
    }
    if (note) line.note = note;
    const text = JSON.stringify(line);
    // Appended through a handle that follows no link and waits on no FIFO,
    // and only to a regular file.
    const handle = await open(file, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK, 0o600).catch((err: NodeJS.ErrnoException) => {
      throw new ReviewFileError(file, err.code === "ELOOP" ? "a link" : `not writable (${err.code ?? "error"})`);
    });
    try {
      if (!(await handle.stat()).isFile()) throw new ReviewFileError(file, "not a regular file");
      await handle.write(`${text}\n`);
    } finally {
      await handle.close();
    }
    await chmod(file, 0o600).catch(() => undefined);
    return line;
  });
}

/** A technical reviewer's record, as the release binds it. */
export type TechnicalReview = { reviewer: { name: string; organisation: string | null; competence: string }; methods_checked: string; entries: Array<{ seq: number; hash: string | null }>; note: string | null; at: string; review_seq: number; recorded_by: string };

/**
 * The examiner's review as the report body takes it (scripts/report-body.ts
 * `HumanReview`, structurally): the enrolled examiner, the technical
 * reviewer, the latest act on each entry, the sign-off.
 */
export type ReviewForReport = {
  examiner?: { name: string; organisation?: string; competence?: string } | null;
  technicalReviewer?: { name: string; competence?: string; checked?: string } | null;
  entries?: Map<number, { action: string; by: string; at: string; note?: string; entry_hash?: string }>;
  signed?: { by: string; at: string; ledger_head?: string } | null;
  unreadable?: string;
};

/** One conclusion and where the examiner left it. */
export type AnswerAdoption = {
  seq: number;
  hash: string | null;
  section: string | null;
  value: string;
  /** Superseded by a later answer: history, not a conclusion to adopt. */
  superseded_by: number | null;
  disposition: DispositionAct | null;
  /** The disposition was made on another hash than the entry's: it does not apply. */
  stale: boolean;
  defects: Defect[];
  /** adopted | qualified | withdrawn | inconclusive | not adopted: what the report shows. */
  standing: "adopted" | "qualified" | "withdrawn" | "inconclusive" | "not adopted";
  words: string;
};

export type AdoptionState = {
  review: ReviewForReport | null;
  chain: { ok: boolean; reason: string | null };
  answers: AnswerAdoption[];
  /** Standing answers whose support is defective and that no withdrawal or inconclusive disposition resolves: they block a release. */
  blocked: AnswerAdoption[];
  technical: TechnicalReview[];
  /** The ledger has no answer entries (before version 4): adoption is of the report as a whole. */
  scope: "answers" | "report";
  lines: number;
  head: string | null;
};

/**
 * Where the examiner has left each conclusion, for the report and the
 * release: every standing answer with its latest disposition (by seq, held
 * to its hash), its support defects, and whether it blocks a release (a
 * defective answer neither withdrawn nor rendered inconclusive); the
 * technical reviews; the review in the shape the report body takes.
 * `upTo` reads only the review's first lines (what a release bound).
 */
export async function adoptionState(o: { runsDir: string; run: string; sandbox: string; upTo?: number; examiner?: { name: string; organisation?: string; competence?: string } | null }): Promise<AdoptionState> {
  let read: ReadReviewLine[];
  try {
    read = await readReviews(o.runsDir, o.run);
  } catch (err) {
    if (!(err instanceof ReviewFileError)) throw err;
    return { review: { unreadable: err.why }, chain: { ok: false, reason: err.why }, answers: [], blocked: [], technical: [], scope: "report", lines: 0, head: null };
  }
  if (o.upTo !== undefined) read = read.slice(0, o.upTo);
  const chain = verifyReviewChain(read);
  const lines = read.filter((l) => typeof (l as ReviewLine).action === "string") as ReviewLine[];
  const { entries: latest, signed } = reviewState(lines);
  const acts = dispositionsOf(lines);
  const { entries, defects, superseded } = await ledgerDefects(o.sandbox);
  const answers: AnswerAdoption[] = [];
  for (const e of entries) {
    if (e.kind !== "answer") continue;
    const d = acts.get(e.seq) ?? null;
    const stale = Boolean(d?.hash && e.hash && d.hash !== e.hash);
    const live = stale ? null : d;
    const standing: AnswerAdoption["standing"] = !live ? "not adopted" : live.disposition === "adopt" ? "adopted" : live.disposition === "qualify" ? "qualified" : live.disposition === "reject" ? "withdrawn" : "inconclusive";
    answers.push({
      seq: e.seq,
      hash: e.hash ?? null,
      section: typeof e.section === "string" ? e.section : null,
      value: String(e.value ?? ""),
      superseded_by: superseded.get(e.seq) ?? null,
      disposition: d,
      stale,
      defects: defects.get(e.seq) ?? [],
      standing,
      words: dispositionWords(d, e),
    });
  }
  const blocked = answers.filter((a) => a.superseded_by === null && a.defects.length && !(a.standing === "withdrawn" || a.standing === "inconclusive"));
  const technical: TechnicalReview[] = lines
    .filter((l) => l.action === "technical_review" && l.reviewer)
    .map((l) => ({
      reviewer: { name: l.reviewer?.name ?? "?", organisation: l.reviewer?.organisation ?? null, competence: l.reviewer?.competence ?? "" },
      methods_checked: l.methods_checked ?? "",
      entries: (l.entries ?? []).map((x) => ({ seq: x.seq, hash: x.hash ?? null })),
      note: l.note ?? null,
      at: l.at,
      review_seq: l.seq,
      recorded_by: `${l.examiner} (${l.os_user}@${l.host})`,
    }));
  const tr = technical.at(-1);
  const review: ReviewForReport | null = lines.length || o.examiner
    ? {
        ...(o.examiner ? { examiner: o.examiner } : {}),
        technicalReviewer: tr ? { name: tr.reviewer.name, competence: tr.reviewer.competence, checked: tr.methods_checked } : null,
        entries: new Map([...latest].map(([seq, l]) => [seq, { action: l.action, by: l.examiner, at: l.at, ...(l.note ? { note: l.note } : {}), ...(l.entry_hash ? { entry_hash: l.entry_hash } : {}) }])),
        signed: signed ? { by: signed.examiner, at: signed.at, ...(signed.ledger_head ? { ledger_head: signed.ledger_head } : {}) } : null,
      }
    : null;
  return {
    review,
    chain: { ok: chain.ok, reason: chain.reason },
    answers,
    blocked,
    technical,
    scope: entries.some((e) => e.kind === "answer") ? "answers" : "report",
    lines: read.length,
    head: read.length ? sha256(read[read.length - 1].text) : null,
  };
}

/**
 * An earlier run's claims as hypotheses for a new run (`--ledger-from`):
 * with its examiner's reviews, only the entries accepted or amended (with
 * the note); without, every entry, marked unreviewed. Markdown, one section
 * per entry, whole; each with the run, its seq and its hash.
 */
export async function priorLedger(runsDir: string, runId: string, sandbox: string): Promise<{ markdown: string; entries: number; reviewed: boolean; ledger_sha256: string }> {
  const ledger = await readLedger(sandbox);
  const lines = (await readReviews(runsDir, runId)).filter((l) => l.action);
  const chain = verifyReviewChain(await readReviews(runsDir, runId));
  const reviewed = lines.length > 0 && chain.ok;
  const state = reviewState(lines);
  const picked = ledger.entries.filter((e) => {
    if (!reviewed) return true;
    const act = typeof e.seq === "number" ? state.entries.get(e.seq) : undefined;
    return !!act && ["accept", "amend", "adopt", "qualify"].includes(act.action) && act.entry_hash === entryHash(e);
  });
  const out: string[] = [
    `# Prior claims: run ${runId}`,
    "",
    "These are an earlier run's ledger entries, brought in with --ledger-from as hypotheses to",
    "re-derive or refute from the evidence. They are not findings and are not in this run's ledger.",
    "A claim that rests on one must cite what was read in the evidence, never this file.",
    "",
    reviewed
      ? `Reviewed: yes. Only the entries run ${runId}'s examiner accepted or amended are here (${picked.length} of ${ledger.entries.length}).`
      : lines.length && !chain.ok
        ? `Reviewed: the examiner's review of run ${runId} does not verify (${chain.reason}), so no acceptance is taken from it: every entry is here, unreviewed (${ledger.entries.length}).`
        : `Reviewed: no. No examiner has reviewed run ${runId}: every entry is here, unreviewed (${ledger.entries.length}).`,
    `Ledger of run ${runId}: sha256 ${ledger.sha256}.`,
    "",
  ];
  for (const e of picked) {
    const act = reviewed && typeof e.seq === "number" ? state.entries.get(e.seq) : undefined;
    out.push(`## ${runId}#${e.seq ?? "?"} · ${e.kind ?? "entry"} · ${act ? (act.action === "amend" ? "amended by the examiner" : act.action === "qualify" ? "adopted with a qualification by the examiner" : act.action === "adopt" ? "adopted by the examiner" : "accepted by the examiner") : "unreviewed"}`, "");
    const field = (name: string, value: unknown) => {
      if (value === undefined || value === null || value === "") return;
      const text = String(value);
      out.push(text.includes("\n") ? `- ${name}:\n\n${text.split("\n").map((l) => `      ${l}`).join("\n")}\n` : `- ${name}: ${text}`);
    };
    field("Claim", e.value);
    field("Time", e.ts);
    field("Source", e.source);
    field("Evidence", e.evidence);
    field("Confidence", e.confidence);
    field("Supersedes", e.supersedes);
    field("Recorded by", e.by);
    field("Examiner's note", act?.note);
    out.push(`- Entry hash: \`${entryHash(e)}\``, "");
  }
  return { markdown: `${out.join("\n")}\n`, entries: picked.length, reviewed, ledger_sha256: ledger.sha256 };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  const runsDir = opt(args, "--runs") ?? process.env.SWARM_RUNS_DIR;
  const run = opt(args, "--run");
  if (!runsDir || !run) {
    console.error("review: --runs DIR and --run ID are required");
    return 2;
  }
  switch (cmd) {
    case "add": {
      const sandbox = opt(args, "--sandbox");
      if (!sandbox) {
        console.error("review add: --sandbox DIR is required");
        return 2;
      }
      const action = (opt(args, "--action") ?? "") as ReviewAction;
      if (action === "sign") {
        console.error("review add: a sign-off is written by scripts/release.ts sign (swarm.sh review <id> --sign), after it has signed the release with the enrolled examiner's key");
        return 2;
      }
      // An enrolled examiner by id, or a name given free (accept, reject and amend of a finding only).
      const who = opt(args, "--examiner") ?? "";
      const enrolled = who ? loadExaminer(who) : { why: "none given" };
      if (ENROLLED_ACTIONS.includes(action) && "why" in enrolled) {
        console.error(`review add: ${action.replace("_", " ")} is an enrolled examiner's act: ${enrolled.why}`);
        return 2;
      }
      const entry = opt(args, "--entry");
      const entries = opt(args, "--entries");
      const line = await appendReview(runsDir, run, sandbox, {
        action,
        examiner: "examiner" in enrolled ? enrolled.examiner.name : who,
        ...("examiner" in enrolled ? { examinerId: enrolled.examiner.id, key: enrolled.examiner.key.fingerprint } : {}),
        entry_seq: entry === undefined ? undefined : Number(entry),
        note: opt(args, "--note"),
        report: opt(args, "--report"),
        ...(action === "technical_review"
          ? {
              reviewer: { name: opt(args, "--reviewer") ?? "", organisation: opt(args, "--organisation"), competence: opt(args, "--competence") ?? "" },
              methodsChecked: opt(args, "--checked"),
              entries: entries ? entries.split(",").map((s) => Number(s.trim().replace(/^(?:#|E-)/i, ""))).filter((n) => Number.isInteger(n) && n > 0) : undefined,
            }
          : {}),
      });
      console.log(JSON.stringify(line));
      return 0;
    }
    case "verify": {
      const v = verifyReviewChain(await readReviews(runsDir, run));
      console.log(JSON.stringify(v));
      return v.ok ? 0 : 1;
    }
    case "show": {
      const lines = await readReviews(runsDir, run);
      const v = verifyReviewChain(lines);
      const state = reviewState(lines);
      let head: string | null = null;
      let reportNow: string | null | undefined;
      const sandbox = opt(args, "--sandbox");
      if (sandbox) {
        const ledger = await readLedger(sandbox).catch(() => null);
        if (ledger) head = ledgerHead(ledger.entries, ledger.sha256);
        if (state.signed?.report_path && isSandboxPath(state.signed.report_path)) reportNow = await sandboxFileSha(sandbox, state.signed.report_path);
      }
      const s0 = state.signed;
      const covers = s0 && sandbox ? signoffCoverage(s0, { chainOk: v.ok, ledgerHead: head, reportSha: reportNow }) : null;
      const summary = {
        run,
        lines: lines.length,
        chain: v,
        entries: [...state.entries.values()].map((l) => ({ seq: l.entry_seq, action: l.action, examiner: l.examiner, enrolled: Boolean(l.examiner_id), at: l.at, note: l.note ?? null })),
        technical_reviews: lines.filter((l) => l.action === "technical_review").map((l) => ({ reviewer: l.reviewer ?? null, checked: l.methods_checked ?? null, at: l.at })),
        signed: s0
          ? {
              examiner: s0.examiner,
              at: s0.at,
              ledger_head: s0.ledger_head,
              current: head === null ? null : head === s0.ledger_head,
              report_path: s0.report_path ?? null,
              report_sha256: s0.report_sha256 ?? null,
              report_current: reportNow === undefined || s0.report_sha256 === undefined ? null : reportNow === s0.report_sha256,
              covers_current: covers ? covers.current : null,
              open_rejections: s0.open_rejections ?? [],
              enrolled: Boolean(s0.examiner_id),
              key: s0.key ?? null,
              release: s0.release ?? null,
            }
          : null,
      };
      if (args.includes("--json")) {
        console.log(JSON.stringify(summary));
      } else {
        console.log(`Review of ${run}: ${lines.length} act(s); the chain ${v.ok ? "verifies" : `is BROKEN (${v.reason})`}.`);
        const verb: Record<string, string> = { accept: "accepted", reject: "rejected (for an answer: withdrawn)", amend: "amended", adopt: "adopted", qualify: "adopted with a qualification", inconclusive: "rendered inconclusive" };
        for (const e of summary.entries) console.log(`  #${e.seq}: ${verb[e.action] ?? e.action} by ${e.examiner}${e.enrolled ? "" : " (not an enrolled examiner)"} at ${e.at}${e.note ? ` (${e.note})` : ""}`);
        for (const r of summary.technical_reviews) console.log(`  Technical review by ${r.reviewer?.name ?? "?"}${r.reviewer?.organisation ? `, ${r.reviewer.organisation}` : ""} (${r.reviewer?.competence ?? "competence not said"}) at ${r.at}: checked ${r.checked ?? "?"}`);
        if (summary.signed) {
          console.log(`  Signed by ${summary.signed.examiner} at ${summary.signed.at}, over ledger head ${summary.signed.ledger_head}${summary.signed.current === false ? " (the ledger has changed since: the sign-off is over an earlier one)" : ""}.`);
          console.log(summary.signed.release ? `  With the enrolled examiner's key ${summary.signed.key ?? "?"}: release v${summary.signed.release.version} (release.json sha256 ${summary.signed.release.sha256}; swarm.sh releases ${run} --verify checks its signature).` : "  A sign-off from before releases: a chained record in this file, not a signature by the examiner's key.");
          if (summary.signed.report_path) console.log(`  Over ${summary.signed.report_path} ${summary.signed.report_sha256 ?? "(absent when signed)"}${summary.signed.report_current === false ? ` (the report has changed since: it is ${reportNow ?? "gone"} now)` : ""}.`);
          else console.log("  Over no report (a sign-off from before one was named).");
          if (summary.signed.open_rejections.length) console.log(`  Signed with rejections standing: ${summary.signed.open_rejections.map((n) => `#${n}`).join(", ")}.`);
          if (covers && !covers.current && v.ok) console.log("  THE SIGN-OFF DOES NOT COVER THE RUN AS IT STANDS: what changed since is the agents' word, not the examiner's.");
        } else {
          console.log("  Not signed.");
        }
      }
      // 1: the review's own chain is broken; 4: it holds, and the sign-off does not cover the ledger or the report as they are now.
      return !v.ok ? 1 : covers && !covers.current ? 4 : 0;
    }
    case "prior": {
      const sandbox = opt(args, "--sandbox");
      const out = opt(args, "--out");
      if (!sandbox || !out) {
        console.error("review prior: --sandbox DIR and --out FILE are required");
        return 2;
      }
      const p = await priorLedger(runsDir, run, sandbox);
      await writeFile(out, p.markdown, { mode: 0o644 });
      console.log(JSON.stringify({ entries: p.entries, reviewed: p.reviewed, ledger_sha256: p.ledger_sha256 }));
      return 0;
    }
    default:
      console.error("review: add | show | verify | prior");
      return 2;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`review: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    },
  );
}
