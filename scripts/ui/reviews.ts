/**
 * The examiner's review of a run, as the console reads it:
 * `$SWARM_RUNS_DIR/reviews/<run-id>.jsonl`, outside the run where no agent
 * reaches it, written by scripts/review.ts alone (through `swarm.sh review`).
 * Each line carries the sha256 of the one before it, so a line taken out or
 * changed breaks the chain; the console checks that here and says where.
 * Read by review.ts's own reader: no link followed, nothing but a regular
 * file opened, and anything else in the file's place is an error shown as
 * one, never "not reviewed".
 */
import { createHash } from "node:crypto";
import { readReviews as readReviewLines, ReviewFileError, reviewsPath, verifyReviewChain } from "../review.ts";

export type ReviewAction = "accept" | "reject" | "amend" | "sign";

export type ReviewLine = {
  seq: number;
  at: string;
  examiner: string;
  os_user: string;
  host: string;
  action: ReviewAction;
  entry_seq: number | null;
  entry_hash: string | null;
  note: string | null;
  /** On a sign: the ledger head hash the examiner signed. */
  ledger_head: string | null;
  /** Whether this line's `prev` is the sha256 of the line before it. */
  chained: boolean;
};

export type ReviewState = {
  /** Whether the run has a review file at all. */
  present: boolean;
  /** Why the review file was not read (a link, a FIFO, a directory in its place), or null. */
  error: string | null;
  lines: ReviewLine[];
  chain: { intact: boolean; detail: string };
  /** The latest decision on each ledger entry, by its seq. */
  by_entry: Record<string, { action: Exclude<ReviewAction, "sign">; examiner: string; at: string; note: string | null; entry_hash: string | null }>;
  /** The latest signature over the ledger head, or null. */
  signed: { examiner: string; at: string; ledger_head: string | null } | null;
};

const ACTIONS = new Set(["accept", "reject", "amend", "sign"]);

export function reviewFile(runsDir: string, runId: string): string {
  return reviewsPath(runsDir, runId);
}

/** Parse and check a review file's text: one decision per line, each chained to the one before. */
export function parseReviews(text: string): Omit<ReviewState, "present" | "error"> {
  const lines: ReviewLine[] = [];
  let prevText: string | null = null;
  let firstBreak: number | null = null;
  let n = 0;
  for (const raw of text.split("\n")) {
    if (!raw.trim()) continue;
    n += 1;
    let rec: Record<string, unknown>;
    try {
      rec = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      if (firstBreak === null) firstBreak = n;
      prevText = raw;
      continue;
    }
    const want = prevText === null ? null : createHash("sha256").update(prevText).digest("hex");
    const chained = (rec.prev ?? null) === want;
    if (!chained && firstBreak === null) firstBreak = n;
    prevText = raw;
    const action = String(rec.action ?? "");
    if (!ACTIONS.has(action)) {
      if (firstBreak === null) firstBreak = n;
      continue;
    }
    lines.push({
      seq: typeof rec.seq === "number" ? rec.seq : n,
      at: String(rec.at ?? ""),
      examiner: String(rec.examiner ?? "?"),
      os_user: String(rec.os_user ?? "?"),
      host: String(rec.host ?? "?"),
      action: action as ReviewAction,
      entry_seq: typeof rec.entry_seq === "number" ? rec.entry_seq : null,
      entry_hash: typeof rec.entry_hash === "string" ? rec.entry_hash : null,
      note: typeof rec.note === "string" && rec.note ? rec.note : null,
      ledger_head: typeof rec.ledger_head === "string" ? rec.ledger_head : null,
      chained,
    });
  }
  const byEntry: ReviewState["by_entry"] = {};
  let signed: ReviewState["signed"] = null;
  for (const l of lines) {
    if (l.action === "sign") signed = { examiner: l.examiner, at: l.at, ledger_head: l.ledger_head };
    else if (l.entry_seq !== null) byEntry[String(l.entry_seq)] = { action: l.action, examiner: l.examiner, at: l.at, note: l.note, entry_hash: l.entry_hash };
  }
  // The chain's verdict is the writer's own rule (scripts/review.ts: each
  // prev the hash of the line before, seq from 1 up by one), so the console
  // and `swarm.sh review` cannot disagree about a file.
  const verdict = verifyReviewChain(text);
  const intact = verdict.ok && firstBreak === null;
  return {
    lines,
    chain: {
      intact,
      detail: intact
        ? `${n} line${n === 1 ? "" : "s"}, each chained to the one before`
        : verdict.reason
          ? `the chain breaks: ${verdict.reason}`
          : `the chain breaks at line ${firstBreak} of ${n}: a line taken out, changed or not a review`,
    },
    by_entry: byEntry,
    signed,
  };
}

export async function readReviews(runsDir: string, runId: string): Promise<ReviewState> {
  let lines: Array<{ text: string }>;
  try {
    lines = await readReviewLines(runsDir, runId);
  } catch (err) {
    if (!(err instanceof ReviewFileError)) throw err;
    return { present: true, error: err.message, lines: [], chain: { intact: false, detail: `the review file was not read: ${err.why}` }, by_entry: {}, signed: null };
  }
  if (!lines.length) return { present: false, error: null, lines: [], chain: { intact: true, detail: "not reviewed by an examiner" }, by_entry: {}, signed: null };
  return { present: true, error: null, ...parseReviews(lines.map((l) => l.text).join("\n") + "\n") };
}
