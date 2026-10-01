/**
 * `npm test`: every node suite under tests/ (`*.test.ts` at any depth, the
 * fixtures aside), found rather than listed. A new suite needs no edit
 * anywhere, and two branches that each add one no longer both rewrite the one
 * line of package.json that used to name them all.
 *
 * The suites `npm test` must not run are named in tests/node-tests.skip, one
 * path per line, each with its reason. A path there that no longer exists
 * fails the run, so the list cannot go stale.
 *
 *   node --experimental-strip-types scripts/test-node.ts [node --test options…]
 *
 * Options are handed to `node --test` before the files
 * (`npm test -- --test-name-pattern=…`).
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

/** The skip list: `<path relative to the repo>  # why`, blank lines and `#` lines ignored. */
export function readSkipList(text: string): string[] {
  return text.split("\n").map((line) => line.replace(/#.*$/, "").trim()).filter(Boolean);
}

/** The node suites `npm test` runs, sorted, and the skip list's paths; throws on a skip entry that names no suite. */
export function nodeSuites(root: string = ROOT): { run: string[]; skipped: string[] } {
  const tests = join(root, "tests");
  const found = (readdirSync(tests, { recursive: true }) as string[])
    .filter((p) => p.endsWith(".test.ts") && !p.split(sep).includes("fixtures"))
    .map((p) => relative(root, join(tests, p)).split(sep).join("/"))
    .sort();
  const listFile = join(tests, "node-tests.skip");
  const skipped = existsSync(listFile) ? readSkipList(readFileSync(listFile, "utf8")) : [];
  const stale = skipped.filter((p) => !found.includes(p));
  if (stale.length) throw new Error(`tests/node-tests.skip names ${stale.join(", ")}, which no node suite is: remove the line`);
  return { run: found.filter((p) => !skipped.includes(p)), skipped };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let suites: { run: string[]; skipped: string[] };
  try {
    suites = nodeSuites();
  } catch (err) {
    console.error(`test-node: ${(err as Error).message}`);
    process.exit(2);
  }
  if (!suites.run.length) {
    console.error("test-node: no node suites found under tests/");
    process.exit(2);
  }
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--test", ...process.argv.slice(2), ...suites.run], { cwd: ROOT, stdio: "inherit" });
  if (r.error) {
    console.error(`test-node: ${r.error.message}`);
    process.exit(2);
  }
  process.exit(r.status ?? 1);
}
