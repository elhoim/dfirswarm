/**
 * The changelog's fragments. A pull request writes its entry to
 * changelog.d/<branch-slug>.md (the branch name with `/` as `-`), never to
 * CHANGELOG.md: every branch then adds a file of its own, and two branches no
 * longer conflict on the top of one section. When the owner cuts a release,
 * this folds the fragments into CHANGELOG.md's `[Unreleased]` section, newest
 * first (by when each landed on the checked-out branch), and removes them.
 *
 *   node --experimental-strip-types scripts/changelog.ts --check
 *   node --experimental-strip-types scripts/changelog.ts --fold [--release X.Y.Z [--date YYYY-MM-DD]]
 *
 * `--check` says whether every fragment is well formed; tests/changelog.test.ts
 * runs it, so CI does. `--release` also turns `[Unreleased]` into the version's
 * section, opens an empty `[Unreleased]` above it and updates the links at the
 * end of the file. Nothing is committed: the owner reads `git diff` and commits.
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const REPO_URL = "https://github.com/halilozturkci/dfirswarm";

/** What is wrong with one fragment, in words; empty when it is well formed. */
export function checkFragment(text: string): string[] {
  const problems: string[] = [];
  const lines = text.split("\n");
  const first = lines.find((l) => l.trim() !== "");
  if (first === undefined) return ["it is empty"];
  if (!/^### \S/.test(first)) problems.push("it does not start with a `### ` heading (`### Added: …`, `### Changed: …`, `### Fixed: …`)");
  let fenced = false;
  for (const l of lines) {
    if (/^\s*(```|~~~)/.test(l)) fenced = !fenced;
    else if (!fenced && /^#{1,2} /.test(l)) problems.push(`a heading above level 3 would break CHANGELOG.md's sections: ${l}`);
  }
  return problems;
}

/** The fragment files (changelog.d/*.md, the README aside), sorted by name. */
export function fragmentFiles(root: string = ROOT): string[] {
  let names: string[];
  try {
    names = readdirSync(join(root, "changelog.d"));
  } catch {
    return [];
  }
  return names.filter((n) => n.endsWith(".md") && n !== "README.md").sort().map((n) => join("changelog.d", n));
}

/** When a fragment landed on the checked-out branch (seconds), or null while it is not committed. */
function landed(root: string, file: string): number | null {
  try {
    const out = execFileSync("git", ["log", "--first-parent", "--diff-filter=A", "--format=%ct", "-1", "--", file], { cwd: root, encoding: "utf8" }).trim();
    return out ? Number(out) : null;
  } catch {
    return null;
  }
}

/** Newest first: a fragment not committed yet is the newest; a tie goes by name. */
export function newestFirst(entries: Array<{ file: string; landed: number | null }>): string[] {
  const t = (e: { landed: number | null }) => (e.landed === null ? Number.POSITIVE_INFINITY : e.landed);
  return [...entries].sort((a, b) => t(b) - t(a) || a.file.localeCompare(b.file)).map((e) => e.file);
}

/**
 * CHANGELOG.md with the fragments (already newest first) at the top of
 * `[Unreleased]`, and, with a release, that section cut into the version's.
 */
export function fold(changelog: string, fragments: string[], release?: { version: string; date: string }): string {
  const lines = changelog.split("\n");
  const at = lines.indexOf("## [Unreleased]");
  if (at < 0) throw new Error('CHANGELOG.md has no "## [Unreleased]" line');
  const added = fragments.map((f) => f.trim()).filter(Boolean).flatMap((f) => [...f.split("\n"), ""]);
  const rest = lines.slice(at + 1);
  while (rest.length && rest[0].trim() === "") rest.shift();
  const out = [...lines.slice(0, at + 1), "", ...added, ...rest];
  if (!release) return out.join("\n");
  if (!/^\d+\.\d+\.\d+$/.test(release.version)) throw new Error(`--release wants MAJOR.MINOR.PATCH, not ${release.version}`);
  if (!/^\d{4}-\d\d-\d\d$/.test(release.date)) throw new Error(`--date wants YYYY-MM-DD, not ${release.date}`);
  if (out.some((l) => l.startsWith(`## [${release.version}]`))) throw new Error(`CHANGELOG.md already has a ${release.version} section`);
  out.splice(at + 1, 0, "", `## [${release.version}] — ${release.date}`);
  const link = out.findIndex((l) => l.startsWith("[Unreleased]: "));
  if (link >= 0) {
    const prev = /\/compare\/(\S+?)\.\.\.HEAD$/.exec(out[link])?.[1];
    out[link] = `[Unreleased]: ${REPO_URL}/compare/v${release.version}...HEAD`;
    out.splice(link + 1, 0, `[${release.version}]: ${REPO_URL}/${prev ? `compare/${prev}...v${release.version}` : `releases/tag/v${release.version}`}`);
  }
  return out.join("\n");
}

function main(argv: string[]): number {
  const files = fragmentFiles();
  const bad = files.flatMap((f) => checkFragment(readFileSync(join(ROOT, f), "utf8")).map((p) => `${f}: ${p}`));
  if (argv[0] === "--check") {
    for (const b of bad) console.error(`changelog: ${b}`);
    if (!bad.length) console.log(`changelog: ${files.length} fragment(s), each well formed`);
    return bad.length ? 1 : 0;
  }
  if (argv[0] !== "--fold") {
    console.error("usage: changelog.ts --check | --fold [--release X.Y.Z [--date YYYY-MM-DD]]");
    return 2;
  }
  if (bad.length) {
    for (const b of bad) console.error(`changelog: ${b}`);
    return 1;
  }
  const opt = (name: string) => {
    const i = argv.indexOf(name);
    if (i < 0) return undefined;
    if (!argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error(`${name} wants a value`);
    return argv[i + 1];
  };
  const version = opt("--release");
  const release = version ? { version, date: opt("--date") ?? new Date().toISOString().slice(0, 10) } : undefined;
  if (!files.length && !release) {
    console.log("changelog: no fragments under changelog.d/; nothing to fold");
    return 0;
  }
  const order = newestFirst(files.map((file) => ({ file, landed: landed(ROOT, file) })));
  const path = join(ROOT, "CHANGELOG.md");
  writeFileSync(path, fold(readFileSync(path, "utf8"), order.map((f) => readFileSync(join(ROOT, f), "utf8")), release));
  for (const f of order) rmSync(join(ROOT, f));
  console.log(`changelog: folded ${order.length} fragment(s) into CHANGELOG.md, newest first${release ? `, and cut ${release.version} (${release.date})` : ""}: ${order.join(", ") || "none"}`);
  console.log("changelog: read git diff, then commit CHANGELOG.md and the removed fragments");
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    console.error(`changelog: ${(err as Error).message}`);
    process.exit(1);
  }
}
