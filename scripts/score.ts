/**
 * An accuracy check an operator runs by hand and reads, and nothing more.
 *
 *   node --experimental-strip-types scripts/score.ts <sandbox> --answers FILE.json
 *
 * CTF correctness is deliberately not recorded anywhere: not in the run, not
 * in the registry, not on the trace, not in a package. This script keeps to
 * that. It only reads, prints its result to the terminal and exits; it writes
 * no file, sets no field and emits no line. What it prints is for the person
 * who ran it.
 *
 * The answers file is the operator's own: a JSON list of
 *   {id, question, accept: [pattern, …], reject?: [pattern, …]}
 * A pattern written /like this/i is a regular expression; any other string
 * is matched as plain text, case ignored.
 *
 * Matched, generically and with no per-case or per-tool knowledge, against
 * the run's delivered report (the file the finish sentinel names, or
 * work/report.md), every ledger entry's value, and the other deliverables at
 * the top of work/. Per question: found (and where), not found, or
 * contradicted (a reject pattern matched, wherever an accept one did too).
 */
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SENTINEL_REL, claimKey, readLedger, readSandboxFile } from "../extensions/protocol.ts";
import { parseFrontMatter } from "./report.ts";

export type Answer = { id: string; question?: string; accept: string[]; reject?: string[] };
export type Place = { where: string; text: string };
export type Verdict = "found" | "not found" | "contradicted";
export type ScoreResult = { id: string; question: string; verdict: Verdict; found: Place[]; rejected: Place[] };

/** Past this a deliverable is not read, and is named as skipped. */
const SCORE_MAX_BYTES = 16 * 1024 * 1024;

/** A pattern as the answers file writes it: /re/flags, or plain text. */
export function patternOf(p: string): RegExp {
  const m = /^\/(.+)\/([a-z]*)$/s.exec(p);
  // "g" or "y" would make test() carry its position from one line to the next.
  if (m) return new RegExp(m[1], m[2].replace(/[gy]/g, ""));
  return new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
}

type Text = { where: string; lines: string[] };

/** What the run delivered, read without following anything an agent could plant. */
async function deliveredTexts(sandbox: string): Promise<{ texts: Text[]; skipped: string[] }> {
  const texts: Text[] = [];
  const skipped: string[] = [];
  const seen = new Set<string>();
  const readText = async (rel: string, label: string) => {
    let key: string;
    try {
      key = claimKey(sandbox, rel);
    } catch {
      return;
    }
    if (!key.startsWith("work/") || seen.has(key)) return;
    seen.add(key);
    let read: Awaited<ReturnType<typeof readSandboxFile>>;
    try {
      read = await readSandboxFile(sandbox, key, { maxBytes: SCORE_MAX_BYTES });
    } catch (err) {
      skipped.push(`${key} (${(err as Error).message})`);
      return;
    }
    if (!read) return;
    if (read.bytes.subarray(0, 8192).includes(0)) {
      skipped.push(`${key} (binary)`);
      return;
    }
    texts.push({ where: `${label}${key}`, lines: read.bytes.toString("utf8").split("\n") });
  };
  const sentinel = await readFile(join(sandbox, SENTINEL_REL), "utf8").catch(() => null);
  const output = sentinel ? parseFrontMatter(sentinel).output : undefined;
  if (output) await readText(output, "the report ");
  await readText("work/report.md", "the report ");
  const entries = await readdir(join(sandbox, "work"), { withFileTypes: true }).catch(() => []);
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (e.isFile() && !e.name.startsWith(".")) await readText(`work/${e.name}`, "");
  }
  return { texts, skipped };
}

export async function scoreRun(sandboxArg: string, answers: Answer[]): Promise<{ results: ScoreResult[]; skipped: string[] }> {
  const sandbox = resolve(sandboxArg);
  const { texts, skipped } = await deliveredTexts(sandbox);
  const ledger = await readLedger(sandbox);
  const places = (patterns: string[] | undefined): Place[] => {
    const out: Place[] = [];
    for (const p of patterns ?? []) {
      const re = patternOf(p);
      for (const t of texts) {
        t.lines.forEach((line, i) => {
          if (re.test(line)) out.push({ where: `${t.where}:${i + 1}`, text: line.trim() });
        });
      }
      for (const e of ledger) if (re.test(e.value)) out.push({ where: `ledger E-${e.seq}`, text: e.value });
    }
    return out;
  };
  const results = answers.map((a) => {
    const found = places(a.accept);
    const rejected = places(a.reject);
    const verdict: Verdict = rejected.length ? "contradicted" : found.length ? "found" : "not found";
    return { id: String(a.id), question: a.question ?? "", verdict, found, rejected };
  });
  return { results, skipped };
}

/** The answers file, checked: a list of {id, accept: [...]}. */
export function parseAnswers(text: string): Answer[] {
  const parsed = JSON.parse(text) as unknown;
  if (!Array.isArray(parsed)) throw new Error("the answers file must be a JSON list");
  return parsed.map((raw, i) => {
    const a = raw as Partial<Answer>;
    if (!a || (typeof a.id !== "string" && typeof a.id !== "number")) throw new Error(`answer ${i + 1} has no id`);
    if (!Array.isArray(a.accept) || !a.accept.every((p) => typeof p === "string")) throw new Error(`answer ${a.id} has no accept list of strings`);
    if (a.reject !== undefined && (!Array.isArray(a.reject) || !a.reject.every((p) => typeof p === "string"))) throw new Error(`answer ${a.id}: reject must be a list of strings`);
    return { id: String(a.id), question: typeof a.question === "string" ? a.question : "", accept: a.accept, reject: a.reject };
  });
}

export function scoreText(r: { results: ScoreResult[]; skipped: string[] }): string {
  const lines: string[] = [];
  for (const q of r.results) {
    lines.push(`${q.id}  ${q.verdict.toUpperCase()}${q.question ? `  ${q.question}` : ""}`);
    for (const p of q.rejected) lines.push(`    rejected at ${p.where}: ${p.text}`);
    for (const p of q.found) lines.push(`    found at ${p.where}: ${p.text}`);
  }
  const n = (v: Verdict) => r.results.filter((q) => q.verdict === v).length;
  lines.push("");
  lines.push(`${n("found")} found, ${n("not found")} not found, ${n("contradicted")} contradicted, of ${r.results.length}.`);
  if (r.skipped.length) lines.push(`Not read: ${r.skipped.join("; ")}.`);
  lines.push("Nothing was written: this check is not recorded anywhere.");
  return `${lines.join("\n")}\n`;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const i = args.indexOf("--answers");
  const answersFile = i >= 0 ? args[i + 1] : undefined;
  const sandbox = args.find((a, k) => !a.startsWith("--") && args[k - 1] !== "--answers");
  if (!sandbox || !answersFile) {
    console.error("Usage: score.ts <sandbox> --answers FILE.json");
    process.exit(2);
  }
  let answers: Answer[];
  try {
    answers = parseAnswers(await readFile(answersFile, "utf8"));
  } catch (err) {
    console.error(`score.ts: ${(err as Error).message}`);
    process.exit(2);
  }
  process.stdout.write(scoreText(await scoreRun(sandbox, answers)));
}
