/**
 * When a value was first in front of a seat (swarm.sh metrics, "Minutes from
 * first sighting to answer").
 *
 * The trace keeps the text of a built-in tool's result (read, bash, grep) and
 * of a tool run in the seat's VM whole, but of a job's answer (job_run,
 * job_status), a store_find hit list, or a pack tool run again as a job only
 * its size. Those rows carry a sighting digest instead: the candidate tokens
 * of the answer text (each line, each field, each word, normalized), each as
 * the first eight hex digits of a sha256, at most SIGHTING_MAX of them. No text
 * is kept: a metric can ask "did this row hold this value?" of a value it
 * already has, and nothing more. A short value's digest can be guessed by
 * trying values, as its text could be read from the rows that keep text whole;
 * the trace is the run's own record and is handled as such.
 *
 * A value is matched as the answer-format check reads it: the first line of
 * the answer's value without list, emphasis or code marks (answer-format.ts
 * firstLine), lower case, its inner spaces collapsed and its edge punctuation
 * dropped.
 */
import { createHash } from "node:crypto";
import { firstLine, questionFormat } from "./answer-format.ts";

export const SIGHTING_FORMAT = 1;
/** Digests a row carries at most; a row cut there says so (`cut`). */
export const SIGHTING_MAX = 2048;
/** A token shorter than this is too common to say a value was seen. */
export const SIGHTING_MIN_CHARS = 4;
/** And one longer than this is not a value an answer gives on its first line. */
export const SIGHTING_MAX_CHARS = 512;
/** How much of a row's text is read for tokens. */
const TEXT_MAX = 512 * 1024;

export type SightingDigest = { v: typeof SIGHTING_FORMAT; d: string; n: number; cut?: true };

const EDGE = /^[\s.,;:!?"'`()[\]{}<>*]+|[\s.,;:!?"'`()[\]{}<>*]+$/g;

/** A token or a value as both sides are compared: lower case, inner spaces collapsed, edge punctuation dropped. */
export function sightingKey(raw: string): string {
  return String(raw ?? "").normalize("NFKC").toLowerCase().replace(/\s+/g, " ").replace(EDGE, "");
}

/** The key an answer's value is matched by: its first line as the format check reads it. Null when too short or too long to match. */
export function answerKey(value: string): string | null {
  const k = sightingKey(firstLine(value));
  return k.length >= SIGHTING_MIN_CHARS && k.length <= SIGHTING_MAX_CHARS ? k : null;
}

function keep(out: Set<string>, raw: string): void {
  const k = sightingKey(raw);
  if (k.length >= SIGHTING_MIN_CHARS && k.length <= SIGHTING_MAX_CHARS) out.add(k);
}

/** A text's candidate tokens: each line, each field (split on tabs, wide spaces, commas, bars, quotes, brackets, '=' and ': '), and each word. */
export function candidateTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.slice(0, TEXT_MAX).split(/\r?\n/)) {
    if (!line.trim()) continue;
    keep(out, line);
    for (const field of line.split(/\t|\s{2,}|[,;|"'`<>(){}[\]=]|:\s/)) keep(out, field);
    for (const word of line.split(/\s+/)) keep(out, word);
  }
  return out;
}

/** Every string a result holds, depth first, up to the text bound. */
function stringsOf(value: unknown, out: string[] = [], budget = { left: TEXT_MAX }, depth = 0): string[] {
  if (budget.left <= 0 || depth > 12) return out;
  if (typeof value === "string") {
    out.push(value.slice(0, budget.left));
    budget.left -= value.length;
  } else if (Array.isArray(value)) {
    for (const v of value) stringsOf(v, out, budget, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) stringsOf(v, out, budget, depth + 1);
  }
  return out;
}

const digest = (key: string): string => createHash("sha256").update(`dfirswarm-sighting/1\u0000${key}`).digest("hex").slice(0, 8);

/** A result's sighting digest: undefined when it holds no candidate token. */
export function sightingDigest(value: unknown, max = SIGHTING_MAX): SightingDigest | undefined {
  const tokens = new Set<string>();
  for (const s of stringsOf(value)) for (const t of candidateTokens(s)) tokens.add(t);
  if (!tokens.size) return undefined;
  const ds = [...new Set([...tokens].map(digest))];
  const cut = ds.length > max;
  return { v: SIGHTING_FORMAT, d: ds.slice(0, max).join(""), n: Math.min(ds.length, max), ...(cut ? { cut: true as const } : {}) };
}

/** Whether a row's digest holds a key (a value's, as answerKey gives it). */
export function digestHolds(d: unknown, key: string): boolean {
  const s = d && typeof d === "object" ? (d as { d?: unknown }).d : undefined;
  if (typeof s !== "string" || !s) return false;
  const want = digest(key);
  for (let i = 0; i + 8 <= s.length; i += 8) if (s.slice(i, i + 8) === want) return true;
  return false;
}

/**
 * The pieces of an answer whose question asks a format of several (Name_md5(file), ip:port): each piece's key, when the
 * first line is in that format and every piece is long enough to match. A value made of two findings is never in one
 * tool's output whole; it is in front of the seat once every piece has been.
 */
export function answerPieces(value: string, questionText: string | null | undefined): string[] | null {
  const f = questionText ? questionFormat(questionText) : null;
  if (!f || f.pieces.length < 2) return null;
  const re = new RegExp(`^${f.pieces.map((p) => `${p.join}(${p.re})`).join("")}$`, "i");
  const m = re.exec(firstLine(value));
  if (!m) return null;
  const keys = m.slice(1).map((x) => sightingKey(x ?? ""));
  return keys.every((k) => k.length >= SIGHTING_MIN_CHARS && k.length <= SIGHTING_MAX_CHARS) ? keys : null;
}

/** A text the trace kept whole, as textHolds reads it: lower case, spaces collapsed. Once a row. */
export function sightingText(text: string): string {
  return String(text ?? "").normalize("NFKC").toLowerCase().replace(/\s+/g, " ");
}

/** Whether a text the trace kept whole (as sightingText gives it) holds a key, not inside a longer word or number. */
export function textHolds(lowerText: string, key: string): boolean {
  let from = 0;
  for (;;) {
    const i = lowerText.indexOf(key, from);
    if (i < 0) return false;
    const before = i > 0 ? lowerText[i - 1]! : "";
    const after = lowerText[i + key.length] ?? "";
    if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return true;
    from = i + 1;
  }
}

// --- the asked format, sighted (B5) ---------------------------------------------------------------

/** A question still open (in scope, not withdrawn, no standing answer) and its words, where its asked format is read from. */
export type OpenQuestion = { section: string; text: string };

/** How much of a result's text is searched for an asked format. */
const SIGHT_TEXT_MAX = 512 * 1024;

/**
 * A pattern that finds an asked format inside a result's text, or null when the format says too little to be worth a
 * line: a single digest, address, port or address of mail, or free words alone, is in nearly every listing a job
 * prints, so only a format of several pieces with one that is not free words (Name_md5(file), ip:port,
 * md5(a)_md5(b)) or a clock of several placeholders (DD-MM-YYYY-HH-MM) is looked for. A free-words piece is one run of
 * characters with no space or separator in it here.
 */
export function formatScanner(questionText: string): { format: string; re: RegExp } | null {
  const known = scanners.get(questionText);
  if (known !== undefined) return known;
  const f = questionFormat(questionText);
  const distinctive = f && f.pieces.length ? (f.pieces.length >= 2 ? f.pieces.some((p) => p.kind !== "text") : f.pieces[0]!.kind === "clock" && /[-.]/.test(f.format)) : false;
  const body = f && distinctive ? f.pieces.map((p) => `${p.join}${p.kind === "text" ? "[^\\s|,;\"'<>()\\[\\]{}_:/@]+" : `(?:${p.re})`}`).join("") : null;
  const out = f && body ? { format: f.format, re: new RegExp(`(?<![0-9A-Za-z])${body}(?![0-9A-Za-z])`, "i") } : null;
  if (scanners.size > 256) scanners.clear();
  scanners.set(questionText, out);
  return out;
}
/** Each question's scanner, by its words: a question's words change only with its revision. */
const scanners = new Map<string, { format: string; re: RegExp } | null>();

/**
 * The open questions whose asked format a result's text holds: each question once, with its format. The value that
 * matched is never returned, so nothing that says it can carry it on (the line to the seat, the trace row).
 */
export function sightedFormats(text: string, open: readonly OpenQuestion[]): Array<{ section: string; format: string }> {
  const t = String(text ?? "").slice(0, SIGHT_TEXT_MAX);
  if (!t) return [];
  const out: Array<{ section: string; format: string }> = [];
  for (const q of open) {
    const s = formatScanner(q.text);
    if (s && s.re.test(t)) out.push({ section: q.section, format: s.format });
  }
  return out;
}

/** The one line a seat is told when a result it read holds a string in an open question's asked format. */
export function sightedLine(hits: ReadonlyArray<{ section: string; format: string }>): string | null {
  if (!hits.length) return null;
  const each = hits.map((h) => `${h.section} (${h.format})`).join(", ");
  const ids = hits.map((h) => h.section.replace(/^question:/, "")).join(", ");
  return `This result holds a string in the form ${hits.length === 1 ? "an open question asks for" : "open questions ask for"}: ${each}, with no answer yet. If it is the answer, record it: as the answer, as a finding with answers: [${ids}] if another seat holds the lead, or, not yet verified, as a candidate (record_candidate: question, value, ref).`;
}
