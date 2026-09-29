/**
 * What the examiner may adopt, and what stands in the way: the support
 * defects of a conclusion, and the examiner's disposition of each.
 *
 * An `answer` (ledger version 4) is a conclusion the report author wrote
 * from the ledger, citing the entries it rests on by seq and hash
 * (`support`), the ones against it (`contrary`), and saying why a disputed
 * or failed-job entry still holds (`qualifies`). The examiner adopts,
 * qualifies, rejects (withdraws) or renders inconclusive each one, by seq
 * and hash (scripts/review.ts). A conclusion whose support is defective
 * cannot be adopted or qualified: the examiner cannot waive missing
 * evidence into a supported conclusion. It is withdrawn, rendered
 * inconclusive, or its support is repaired, and repairing it is further
 * examination (the run resumed, or a new run: the evidence cutoff reopens),
 * not a review act.
 *
 * The same acts work on any ledger entry by seq and hash; the checks below
 * read whatever fields an entry has and name only what they find. Nothing
 * here knows a tool or an evidence format. Pure: the caller reads the files;
 * the answers' own checks are the ledger gate's (extensions/protocol.ts).
 */

import { answerProblems, standingDisputes, supersededBy, type LedgerDispute, type LedgerEntry } from "../extensions/protocol.ts";

export type Disposition = "adopt" | "qualify" | "reject" | "inconclusive";
export const DISPOSITIONS: readonly Disposition[] = ["adopt", "qualify", "reject", "inconclusive"];

export type Defect = { code: string; what: string };

/**
 * Every entry's support defects, by seq. For a standing answer, what the
 * ledger gate names (protocol.ts answerProblems: support or limitations
 * that name no entry or another hash, superseded without the correction
 * cited, disputed or resting on a failed job's output without `qualifies`,
 * an answer resting on an answer that no longer stands), and beside it: no
 * support cited at all, and the tokens the hub found in the answer's text
 * and in none of its cited entries (`unsupported_tokens`). For any entry: a
 * dispute of it that stands, and its own refs on a job that did not
 * succeed, not qualified. `failed` maps an entry's seq to its refs on jobs
 * that did not succeed and that it does not qualify, as "ref (status)"
 * (failedJobRefs in review.ts, as check-answers.ts reads them).
 * A superseded entry is not standing and has none: its correction is what
 * is reviewed.
 */
export function supportDefects(entries: LedgerEntry[], disputes: LedgerDispute[] = [], failed: Map<number, string[]> = new Map()): Map<number, Defect[]> {
  const replaced = supersededBy(entries);
  const gate = answerProblems(entries, disputes, failed);
  const disputed = new Map<string, LedgerDispute[]>();
  for (const d of standingDisputes(disputes)) disputed.set(d.target, [...(disputed.get(d.target) ?? []), d]);
  const out = new Map<number, Defect[]>();
  for (const e of entries) {
    if (replaced.has(e.seq)) continue;
    const d: Defect[] = [];
    const against = e.hash ? disputed.get(e.hash) : undefined;
    if (against?.length) d.push({ code: "disputed", what: `E-${e.seq} is itself disputed (${against.map((x) => `${x.by}: ${x.why}`).join("; ")}) and the dispute stands` });
    if (e.kind === "answer") {
      if (!e.support?.length) d.push({ code: "no_support", what: `answer E-${e.seq} cites no entry it rests on` });
      for (const p of gate.get(e.seq) ?? []) d.push({ code: "support", what: `answer E-${e.seq}: ${p}` });
      const tokens = e.unsupported_tokens ?? [];
      if (tokens.length) d.push({ code: "unsupported_tokens", what: `answer E-${e.seq} states ${tokens.length === 1 ? "a specific" : `${tokens.length} specifics`} found in none of the entries it cites: ${tokens.join(", ")}` });
    } else {
      const own = failed.get(e.seq) ?? [];
      if (own.length) d.push({ code: "failed_job", what: `E-${e.seq} rests on the kept output of a job that did not succeed (${own.join("; ")}) and does not say why those bytes hold (qualifies)` });
    }
    if (d.length) out.set(e.seq, d);
  }
  return out;
}

/** One disposition act as the review file keeps it (scripts/review.ts). */
export type DispositionAct = {
  seq: number;
  hash: string | null;
  disposition: Disposition;
  note: string | null;
  examiner: string;
  examiner_id: string | null;
  at: string;
  /** The act's line in the review. */
  review_seq: number;
};

/** The latest disposition of each entry, from the review's lines in order. */
export function dispositionsOf(lines: ReadonlyArray<{ seq?: number; action?: string; entry_seq?: number; entry_hash?: string; note?: string; examiner?: string; examiner_id?: string; at?: string }>): Map<number, DispositionAct> {
  const out = new Map<number, DispositionAct>();
  for (const l of lines) {
    if (!DISPOSITIONS.includes(l.action as Disposition) || typeof l.entry_seq !== "number") continue;
    out.set(l.entry_seq, {
      seq: l.entry_seq,
      hash: l.entry_hash ?? null,
      disposition: l.action as Disposition,
      note: l.note ?? null,
      examiner: String(l.examiner ?? "?"),
      examiner_id: l.examiner_id ?? null,
      at: String(l.at ?? ""),
      review_seq: Number(l.seq ?? 0),
    });
  }
  return out;
}

/** A disposition in the report's words. */
export function dispositionWords(d: DispositionAct | null, entry: { hash?: string } | null): string {
  if (!d) return "the agents' conclusion, not adopted";
  const other = d.hash && entry?.hash && d.hash !== entry.hash ? `; made on entry hash ${d.hash}, which is not this entry's: it does not apply` : "";
  const note = d.note ? `: ${d.note}` : "";
  switch (d.disposition) {
    case "adopt":
      return `adopted by ${d.examiner} at ${d.at}${note}${other}`;
    case "qualify":
      return `adopted with a qualification by ${d.examiner} at ${d.at}${note}${other}`;
    case "reject":
      return `withdrawn by the examiner ${d.examiner} at ${d.at}${note}${other}`;
    default:
      return `rendered inconclusive by the examiner ${d.examiner} at ${d.at}${note}${other}`;
  }
}
