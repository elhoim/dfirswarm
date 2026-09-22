/**
 * The goal library: the markdown documents under `prompts/goals/` that a swarm
 * can be launched from, readable and writable from the web app.
 *
 * A goal document is the contract. It is the one input worth iterating on
 * between runs — far more than N or the cap — so it belongs somewhere you can
 * edit it, keep it, and start the next run from it, rather than in a textarea
 * that is empty again tomorrow.
 *
 * Writing here never touches a running swarm. `SWARM.md` inside a sandbox stays
 * harness-owned: an agent that could edit its own definition of done could
 * certify itself, which is exactly what the protected-path rule exists to stop.
 */
import { randomBytes } from "node:crypto";
import { lstat, mkdir, readdir, readFile, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";

/** Same rule as the CLI: a swarm with no finish line does not start. */
export const HAS_DEFINITION_OF_DONE = /^##\s+Definition of done\s*$/im;
export const GOAL_MAX_CHARS = 32_000;
/** Keeps a name a plain file in one directory, with no way out of it. */
const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export type GoalSummary = {
  name: string;
  /** First non-empty line under `## Goal`, or the first prose line. */
  title: string;
  bytes: number;
  updated_at: string;
  has_definition_of_done: boolean;
  /** How many `## Checks` bullets await-done.sh would run. */
  checks: number;
};

export type GoalDocument = GoalSummary & { text: string };

export class GoalError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function goalsDir(root: string): string {
  return join(root, "prompts", "goals");
}

export function safeGoalName(raw: unknown): string {
  const name = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (!NAME_RE.test(name)) {
    throw new GoalError(400, "goal name must be [a-z0-9][a-z0-9_-]{0,63}");
  }
  return name;
}

/**
 * Resolve inside the library, or refuse.
 *
 * NAME_RE already forbids separators, so the lexical check is belt and braces.
 * The symlink check is not: a goals directory that is itself a link, or a
 * `name.md` that links elsewhere, would otherwise let an unauthenticated read
 * return any file on the host and a token-gated write land outside the library.
 */
async function goalPath(root: string, name: string): Promise<string> {
  const dir = resolve(goalsDir(root));
  const file = resolve(dir, `${name}.md`);
  if (!file.startsWith(dir + sep)) throw new GoalError(400, "goal name escapes the library");

  // The library directory must be a real directory, not a link out of the repo.
  const realDir = await realpath(dir).catch(() => null);
  if (realDir !== null) {
    const info = await lstat(dir).catch(() => null);
    if (info?.isSymbolicLink()) throw new GoalError(400, "the goal library is a symlink; refusing to follow it");
  }

  // An existing entry must be a plain file sitting in that directory.
  const link = await lstat(file).catch(() => null);
  if (link) {
    if (!link.isFile()) throw new GoalError(400, `${name} is not a goal document`);
    const real = await realpath(file).catch(() => null);
    const base = realDir ?? dir;
    if (real === null || !real.startsWith(base + sep)) {
      throw new GoalError(400, `${name} points outside the goal library`);
    }
  }
  return file;
}

/**
 * The `## Checks` bullets, counted the way `await-done.sh` actually finds them.
 *
 * This number is shown next to a goal in the library, so it has to agree with
 * what will run. The extractor there tracks fences, treats *any* heading as
 * ending the section (not just another `##`), and takes every backticked span
 * on a bullet — all three were wrong here, in both directions.
 */
export function countChecks(text: string): number {
  let inChecks = false;
  let fence: string | null = null;
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    const fenceMatch = /^\s*(```+|~~~+)/.exec(line);
    if (fenceMatch) {
      if (fence === null) fence = fenceMatch[1][0];
      else if (fenceMatch[1][0] === fence) fence = null;
      continue;
    }
    if (fence !== null) continue;
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      inChecks = heading[1].length === 2 && /^Checks\s*$/i.test(heading[2].trim());
      continue;
    }
    if (!inChecks) continue;
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (!bullet) continue;
    count += (bullet[1].match(/`[^`]+`/g) ?? []).length;
  }
  return count;
}

function titleOf(text: string): string {
  const lines = text.split(/\r?\n/);
  const goalAt = lines.findIndex((line) => /^##\s+Goal\s*$/i.test(line.trim()));
  const from = goalAt >= 0 ? goalAt + 1 : 0;
  for (let i = from; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    return line.length > 160 ? `${line.slice(0, 159)}…` : line;
  }
  return "(no description)";
}

function summarise(name: string, text: string, bytes: number, updatedAt: string): GoalSummary {
  return {
    name,
    title: titleOf(text),
    bytes,
    updated_at: updatedAt,
    has_definition_of_done: HAS_DEFINITION_OF_DONE.test(text),
    checks: countChecks(text),
  };
}

export async function listGoals(root: string): Promise<GoalSummary[]> {
  const dir = goalsDir(root);
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const out: GoalSummary[] = [];
  for (const file of names.sort()) {
    if (!file.endsWith(".md")) continue;
    const name = file.slice(0, -3);
    if (!NAME_RE.test(name)) continue;
    try {
      const file = await goalPath(root, name);
      const [text, info] = await Promise.all([readFile(file, "utf8"), stat(file)]);
      out.push(summarise(name, text, info.size, info.mtime.toISOString()));
    } catch {
      // A symlink, a missing file, or an unreadable document is not a goal
      // you can launch — the named route already refuses those.
    }
  }
  return out;
}

export async function readGoal(root: string, rawName: string): Promise<GoalDocument> {
  const name = safeGoalName(rawName);
  const file = await goalPath(root, name);
  let text: string;
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    [text, info] = await Promise.all([readFile(file, "utf8"), stat(file)]);
  } catch {
    throw new GoalError(404, `no goal named ${name}`);
  }
  return { ...summarise(name, text, info.size, info.mtime.toISOString()), text };
}

export async function saveGoal(root: string, rawName: string, rawText: unknown): Promise<GoalDocument> {
  const name = safeGoalName(rawName);
  const text = typeof rawText === "string" ? rawText : "";
  if (!text.trim()) throw new GoalError(400, "a goal document cannot be empty");
  if (text.length > GOAL_MAX_CHARS) {
    throw new GoalError(400, `goal is longer than ${GOAL_MAX_CHARS} characters`);
  }
  if (!HAS_DEFINITION_OF_DONE.test(text)) {
    throw new GoalError(
      400,
      'goal needs a "## Definition of done" section (see prompts/goals/hello.md)',
    );
  }
  await mkdir(goalsDir(root), { recursive: true });
  const file = await goalPath(root, name);
  // Write beside it and rename: a half-written goal file is a broken contract,
  // and swarm.sh may be reading this directory at the same moment.
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const body = text.endsWith("\n") ? text : `${text}\n`;
  try {
    await writeFile(tmp, body, "utf8");
    await rename(tmp, file);
  } catch (err) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
  return readGoal(root, name);
}

export async function deleteGoal(root: string, rawName: string): Promise<void> {
  const name = safeGoalName(rawName);
  const file = await goalPath(root, name);
  try {
    await stat(file);
  } catch {
    throw new GoalError(404, `no goal named ${name}`);
  }
  await rm(file, { force: true });
}
