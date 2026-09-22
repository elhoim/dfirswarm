/**
 * The investigation library: the goal documents under `library/<category>/`
 * that a case can be started from, read from disk on every request so an
 * edit to a file is what the picker offers next.
 *
 * `prompts/goals/` is the operator's own shelf: what they wrote, saved from
 * the console, launched before. The library is the other shelf: one
 * document per kind of investigation — a Windows host, a Linux web server,
 * a memory dump, a bundle of logs, a capture — written to the swarm's
 * contract (a definition of done, checks the finish line can run, a way to
 * divide the work) and generic over the evidence the operator brings.
 *
 * An entry opens with a metadata block between two `---` lines: the title
 * and summary the picker shows, the category it sits under, what evidence
 * it expects, and what it suggests for the team. The block is for the
 * picker; the document the contract is built from starts after it, and
 * `swarm.sh` strips it the same way when a file is launched from the CLI.
 *
 * Read-only from the web app on purpose. The library is part of the repo,
 * edited like the rest of it; what an operator loads and changes in the
 * editor is theirs to save under `prompts/goals/`.
 */
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { countChecks, GoalError, HAS_DEFINITION_OF_DONE } from "./goals.ts";

/** One directory per category; the order here is the order the picker groups them in. */
export const LIBRARY_CATEGORIES = [
  "windows",
  "linux",
  "macos",
  "memory",
  "logs",
  "network",
  "malware",
  "cloud",
  "mobile",
  "general",
] as const;
export type LibraryCategory = (typeof LIBRARY_CATEGORIES)[number];

export const LIBRARY_EVIDENCE = [
  "disk-image",
  "memory-dump",
  "logs",
  "evtx",
  "registry",
  "pcap",
  "mailbox",
  "mobile-fs",
  "cloud-export",
  "files",
  "unallocated",
  "container",
  "triage-package",
] as const;

export const LIBRARY_OS = ["windows", "linux", "macos", "mixed", "any"] as const;

const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export type LibraryEntry = {
  /** `<category>/<slug>`, the file's path under library/ without `.md`. */
  id: string;
  category: LibraryCategory;
  slug: string;
  title: string;
  summary: string;
  evidence: string[];
  os: string;
  tags: string[];
  /** What the operator is expected to put under inputs/. */
  inputs: string;
  /** Suggestions, not settings: the form applies them only when asked. */
  seats?: number;
  cap_usd?: number;
  wall_clock?: number;
  checks: number;
  has_definition_of_done: boolean;
  bytes: number;
  updated_at: string;
};

export type LibraryDocument = LibraryEntry & {
  /** The goal document with the metadata block removed: what the editor gets. */
  text: string;
};

export type FrontMatter = { meta: Record<string, string>; body: string };

/**
 * A metadata block is `---`, `key: value` lines, `---`, at the very top. No
 * YAML: a list is a comma-separated value, a number is a number, and a key
 * this module does not know is kept in `meta` and otherwise ignored. A file
 * with no block, or a block that never closes, is all body.
 */
export function parseFrontMatter(text: string): FrontMatter {
  const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!m) return { meta: {}, body: text };
  const meta: Record<string, string> = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([a-z][a-z0-9_]*)\s*:\s*(.*)$/.exec(line.trim());
    if (kv) meta[kv[1]] = kv[2].trim();
  }
  return { meta, body: text.slice(m[0].length).replace(/^(\r?\n)+/, "") };
}

export function libraryDir(root: string): string {
  return join(root, "library");
}

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function num(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function titleOf(body: string): string {
  const lines = body.split(/\r?\n/);
  const goalAt = lines.findIndex((line) => /^##\s+Goal\s*$/i.test(line.trim()));
  for (let i = goalAt >= 0 ? goalAt + 1 : 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    return line.length > 120 ? `${line.slice(0, 119)}…` : line;
  }
  return "(untitled)";
}

export function isLibraryId(raw: string): raw is string {
  const parts = raw.split("/");
  return parts.length === 2 && (LIBRARY_CATEGORIES as readonly string[]).includes(parts[0]) && SLUG_RE.test(parts[1]);
}

export function safeLibraryId(raw: unknown): { category: LibraryCategory; slug: string; id: string } {
  const id = typeof raw === "string" ? raw.trim() : "";
  if (!isLibraryId(id)) {
    throw new GoalError(400, `a library id is <category>/<slug> with a category among ${LIBRARY_CATEGORIES.join(", ")}`);
  }
  const [category, slug] = id.split("/") as [LibraryCategory, string];
  return { category, slug, id };
}

/**
 * Resolve inside the library, or refuse: the directory, the category and the
 * entry must be real files under the repo, not links out of it. An
 * unauthenticated read of an arbitrary host file is what this stops.
 */
async function entryPath(root: string, category: string, slug: string): Promise<string> {
  const dir = resolve(libraryDir(root));
  const file = resolve(dir, category, `${slug}.md`);
  if (!file.startsWith(dir + sep)) throw new GoalError(400, "library id escapes the library");
  for (const p of [dir, resolve(dir, category)]) {
    const info = await lstat(p).catch(() => null);
    if (info?.isSymbolicLink()) throw new GoalError(400, "the library holds a symlink; refusing to follow it");
  }
  const link = await lstat(file).catch(() => null);
  if (link) {
    if (!link.isFile()) throw new GoalError(400, `${category}/${slug} is not a library entry`);
    const realDir = await realpath(dir).catch(() => dir);
    const real = await realpath(file).catch(() => null);
    if (real === null || !real.startsWith(realDir + sep)) {
      throw new GoalError(400, `${category}/${slug} points outside the library`);
    }
  }
  return file;
}

function describe(category: LibraryCategory, slug: string, text: string, bytes: number, updatedAt: string): LibraryDocument {
  const { meta, body } = parseFrontMatter(text);
  return {
    id: `${category}/${slug}`,
    category,
    slug,
    title: meta.title || titleOf(body),
    summary: meta.summary || "",
    evidence: list(meta.evidence),
    os: meta.os || "any",
    tags: list(meta.tags),
    inputs: meta.inputs || "",
    seats: num(meta.seats),
    cap_usd: num(meta.cap_usd),
    wall_clock: num(meta.wall_clock),
    checks: countChecks(body),
    has_definition_of_done: HAS_DEFINITION_OF_DONE.test(body),
    bytes,
    updated_at: updatedAt,
    text: body,
  };
}

/** Every entry, category by category in the library's own order, slugs sorted. */
export async function listLibrary(root: string): Promise<LibraryEntry[]> {
  const out: LibraryEntry[] = [];
  for (const category of LIBRARY_CATEGORIES) {
    let names: string[];
    try {
      names = await readdir(join(libraryDir(root), category));
    } catch {
      continue;
    }
    for (const file of names.sort()) {
      if (!file.endsWith(".md")) continue;
      const slug = file.slice(0, -3);
      if (!SLUG_RE.test(slug)) continue;
      try {
        const path = await entryPath(root, category, slug);
        const [text, info] = await Promise.all([readFile(path, "utf8"), stat(path)]);
        const { text: _body, ...entry } = describe(category, slug, text, info.size, info.mtime.toISOString());
        out.push(entry);
      } catch {
        // A symlink or an unreadable file is not an entry the picker can offer.
      }
    }
  }
  return out;
}

export async function readLibraryEntry(root: string, rawId: unknown): Promise<LibraryDocument> {
  const { category, slug } = safeLibraryId(rawId);
  const path = await entryPath(root, category, slug);
  let text: string;
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    [text, info] = await Promise.all([readFile(path, "utf8"), stat(path)]);
  } catch {
    throw new GoalError(404, `no library entry ${category}/${slug}`);
  }
  return describe(category, slug, text, info.size, info.mtime.toISOString());
}
