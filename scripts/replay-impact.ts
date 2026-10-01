/**
 * A change's impact line: every contract fixture (tests/fixtures/contract/)
 * replayed under a base commit and under this checkout, and each difference
 * named, the way `swarm.sh replay --compare` names them for one run
 * (docs/adr/0017, "Measuring a rule change"). CI runs it on a pull request
 * against its base and writes the table to the job's summary, so a reviewer
 * sees what a rule change reaches before reading the code. It fails only
 * when it cannot replay: a difference is information, never a failure (the
 * contract fixtures' own expectations are what the tests hold).
 *
 *   node --experimental-strip-types scripts/replay-impact.ts <base-commit> [--out FILE]
 *
 * Ids, codes and counts only, never an answer's words.
 */
import { appendFileSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { extractCommit, replay, resolveRun, type Difference, type Target } from "./replay.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const FIXTURES = join(ROOT, "tests", "fixtures", "contract");

export type Impact = { base: string; fixtures: number; changed: Array<{ fixture: string; differences: Difference[] }>; errors: Array<{ fixture: string; error: string }> };

export async function replayImpact(base: string): Promise<Impact> {
  const work = mkdtempSync(join(tmpdir(), "replay-impact-"));
  try {
    const old = join(work, "base");
    await extractCommit(base, old);
    const targets: Target[] = [{ label: `base ${base.slice(0, 7)}`, harness: old, how: `${base.slice(0, 7)}, extracted`, commit: base }, { label: "this checkout", harness: ROOT, how: "this checkout", commit: null }];
    const names = readdirSync(FIXTURES, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    const out: Impact = { base, fixtures: names.length, changed: [], errors: [] };
    for (const name of names) {
      try {
        const r = await replay({ run: await resolveRun(join(FIXTURES, name, "run")), targets, scratch: mkdtempSync(join(work, `${name}-`)) });
        if (r.differences?.length) out.changed.push({ fixture: name, differences: r.differences });
      } catch (err) {
        out.errors.push({ fixture: name, error: (err as Error).message });
      }
    }
    return out;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** The impact as a Markdown block for a pull request's summary. */
export function impactMarkdown(i: Impact): string {
  const lines = [`### Replay impact against ${i.base.slice(0, 7)}`, ""];
  if (!i.changed.length && !i.errors.length) lines.push(`No difference: all ${i.fixtures} contract fixtures read the same under the base and this change.`);
  else {
    lines.push(`${i.changed.length} of ${i.fixtures} contract fixtures read differently under this change${i.errors.length ? `; ${i.errors.length} could not be replayed` : ""}. A difference is what the change reaches, not a failure: the fixtures' own expectations are what the tests hold.`, "");
    if (i.changed.length) {
      lines.push("| Fixture | Section | What | Base | This change |", "| --- | --- | --- | --- | --- |");
      const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
      for (const c of i.changed) for (const d of c.differences) lines.push(`| ${c.fixture} | ${d.section ?? "—"} | ${cell(d.field)}${d.policy && d.policy !== "as run" ? ` (${d.policy})` : ""} | ${cell(d.a)} | ${cell(d.b)} |`);
    }
    for (const e of i.errors) lines.push("", `- ${e.fixture}: not replayed (${e.error})`);
  }
  return `${lines.join("\n")}\n`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const base = args.find((a) => !a.startsWith("--"));
  if (!base) {
    process.stderr.write("usage: replay-impact.ts <base-commit> [--out FILE]\n");
    process.exit(2);
  }
  const i = await replayImpact(base);
  const md = impactMarkdown(i);
  process.stdout.write(md);
  const at = args.indexOf("--out");
  if (at >= 0 && args[at + 1]) writeFileSync(args[at + 1]!, md);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
  process.exit(i.errors.length === i.fixtures ? 1 : 0);
}
