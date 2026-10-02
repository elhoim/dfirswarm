/**
 * Every published case says where its challenge comes from. A case folder
 * under docs/use-cases (a folder that holds the run's goal.md) carries a
 * SOURCE.md whose table names the challenge's author, its link and the
 * licence the source states, "unknown, see link" when it states none
 * (docs/use-cases/README.md, "How a folder is laid out"; NOTICE, "Case
 * material"). The first half holds the check to a scratch tree; the second
 * runs it on the cases that ship.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));
const CASES = join(REPO, "docs", "use-cases");
const REQUIRED = ["Author", "Link", "Licence"] as const;

async function exists(path: string): Promise<boolean> {
  return stat(path).then(
    () => true,
    () => false,
  );
}

/** The case folders under root: every folder, two levels deep at most, that holds a goal.md. */
async function caseFolders(root: string, depth = 0): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = join(root, entry.name);
    if (await exists(join(dir, "goal.md"))) out.push(dir);
    else if (depth < 1) out.push(...(await caseFolders(dir, depth + 1)));
  }
  return out.sort();
}

/** The `| Key | value |` rows of a SOURCE.md, the header and separator rows aside. */
function sourceRows(text: string): Map<string, string> {
  const rows = new Map<string, string>();
  for (const line of text.split("\n")) {
    const m = /^\|\s*([^|]*?)\s*\|\s*(.*?)\s*\|\s*$/.exec(line);
    if (!m || !m[1] || /^-+$/.test(m[1])) continue;
    rows.set(m[1], m[2]);
  }
  return rows;
}

/** What is wrong with the case folders under root, one line each, by path. */
async function sourceProblems(root: string): Promise<string[]> {
  const problems: string[] = [];
  for (const dir of await caseFolders(root)) {
    const at = relative(root, dir);
    const file = join(dir, "SOURCE.md");
    if (!(await exists(file))) {
      problems.push(`${at}: no SOURCE.md (the challenge's author, link and licence)`);
      continue;
    }
    const rows = sourceRows(await readFile(file, "utf8"));
    for (const key of REQUIRED) {
      if (!rows.get(key)) problems.push(`${at}/SOURCE.md: no ${key} row, or an empty one`);
    }
    const link = rows.get("Link");
    if (link && !/^https:\/\/\S+$/.test(link)) problems.push(`${at}/SOURCE.md: the Link is not one https URL: ${link}`);
  }
  return problems;
}

const GOOD = `# Source: a case

| | |
| --- | --- |
| Author | Someone |
| Link | https://example.org/challenge |
| Licence | unknown, see link |
`;

test("a case folder without SOURCE.md, or with an incomplete one, is named; a series folder is not a case", async () => {
  const root = await mkdtemp(join(tmpdir(), "use-case-sources-"));
  try {
    const mk = async (path: string, files: Record<string, string>) => {
      await mkdir(join(root, path), { recursive: true });
      for (const [name, text] of Object.entries(files)) await writeFile(join(root, path, name), text);
    };
    await mk("good", { "goal.md": "## Goal\n", "SOURCE.md": GOOD });
    await mk("missing", { "goal.md": "## Goal\n", "README.md": "# no source\n" });
    await mk("empty-licence", { "goal.md": "## Goal\n", "SOURCE.md": GOOD.replace("unknown, see link", "") });
    await mk("no-author", { "goal.md": "## Goal\n", "SOURCE.md": GOOD.replace("| Author | Someone |\n", "") });
    await mk("bad-link", { "goal.md": "## Goal\n", "SOURCE.md": GOOD.replace("https://example.org/challenge", "see the README") });
    await mk("series", { "README.md": "# a series of cases\n" });
    await mk("series/one", { "goal.md": "## Goal\n", "SOURCE.md": GOOD });
    await mk("series/two", { "goal.md": "## Goal\n" });
    await mk("good/run-2", { "goal.md": "## Goal\n" });

    assert.deepEqual(await sourceProblems(root), [
      "bad-link/SOURCE.md: the Link is not one https URL: see the README",
      "empty-licence/SOURCE.md: no Licence row, or an empty one",
      "missing: no SOURCE.md (the challenge's author, link and licence)",
      "no-author/SOURCE.md: no Author row, or an empty one",
      "series/two: no SOURCE.md (the challenge's author, link and licence)",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("every published case names its challenge's author, link and licence in SOURCE.md", async () => {
  const cases = await caseFolders(CASES);
  assert.ok(cases.length >= 17, `the published cases are found (${cases.length})`);
  assert.deepEqual(await sourceProblems(CASES), []);
});
