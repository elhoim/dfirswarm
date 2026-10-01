/**
 * The rule register: every coded rule of the ledger (the defects the gate
 * holds on, the warnings it says, and the caps an attest is recorded under),
 * with where each is raised, the design that states it, and the tests and
 * contract fixtures that exercise it. It is generated from the code, never
 * written by hand, and checked in as docs/rules.md: a change to a rule shows
 * in that file's diff, and tests/rules-register.test.ts fails when the file
 * is stale, or when a rule has no test, no fixture and no design.
 *
 *   node --experimental-strip-types scripts/rules.ts [--write | --check] [--json]
 *
 * Words and names from the source only: it reads the code, the ADRs and the
 * tests as text, and runs nothing.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
export const REGISTER = join(ROOT, "docs", "rules.md");

export type RuleKind = "defect" | "warning" | "cap";
export type Rule = {
  code: string;
  kind: RuleKind;
  /** The functions that raise it, by module: the function around each `code: "<code>"`. */
  raised: Array<{ file: string; fn: string }>;
  /** The design sections that name it: the ADR and its heading. */
  design: Array<{ file: string; section: string }>;
  /** The tests that name it, by file. */
  tests: string[];
  /** The contract fixtures whose expectation names it. */
  fixtures: string[];
};

const read = (p: string) => readFileSync(p, "utf8");
const list = (dir: string, re: RegExp) => readdirSync(join(ROOT, dir)).filter((f) => re.test(f)).sort().map((f) => join(dir, f));

/** The codes of one of the rule unions in extensions/ledger-rules.ts: `export type <name> = { code: "a" | "b" …`. */
function unionCodes(src: string, typeName: string): string[] {
  const at = src.indexOf(`export type ${typeName} =`);
  if (at < 0) throw new Error(`extensions/ledger-rules.ts has no type ${typeName}`);
  const m = /code:\s*((?:"[a-z_]+"\s*\|?\s*)+)/.exec(src.slice(at, at + 4000));
  if (!m) throw new Error(`${typeName} has no code union`);
  return [...m[1]!.matchAll(/"([a-z_]+)"/g)].map((x) => x[1]!);
}

/** The top-level function a line of a module sits in: the nearest `function <name>` or `const <name> =` above it at column 0. */
function enclosing(lines: string[], i: number): string {
  for (let k = i; k >= 0; k--) {
    const m = /^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|^(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*[:=]/.exec(lines[k]!);
    if (m) return m[1] ?? m[2]!;
  }
  return "(module)";
}

export function buildRegister(): Rule[] {
  const rules = read(join(ROOT, "extensions", "ledger-rules.ts"));
  const kinds: Array<[RuleKind, string]> = [["defect", "LedgerDefect"], ["warning", "LedgerWarning"], ["cap", "ReviewEvidenceCap"]];
  const codes: Array<[string, RuleKind]> = [];
  for (const [kind, t] of kinds) for (const c of unionCodes(rules, t)) if (!codes.some(([x]) => x === c)) codes.push([c, kind]);

  const modules = list("extensions", /\.ts$/).concat(list("scripts", /\.ts$/)).filter((f) => !f.endsWith("scripts/rules.ts"));
  const moduleLines = modules.map((f) => [f, read(join(ROOT, f)).split("\n")] as const);
  // The design: the ADRs, and the protocol's own document, section by section.
  const adrs = [...list(join("docs", "adr"), /\.md$/), join("docs", "protocol.md")].map((f) => [f, read(join(ROOT, f)).split("\n")] as const);
  // The tests, and the rule-level tests under tests/rules/ named by code.
  const tests = [...list("tests", /\.test\.(ts|sh)$/), ...list(join("tests", "rules"), /\.test\.ts$/)].map((f) => [f, read(join(ROOT, f))] as const);
  const fixtureDir = join("tests", "fixtures", "contract");
  const fixtures = readdirSync(join(ROOT, fixtureDir), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort()
    .map((n) => [n, (() => { try { return read(join(ROOT, fixtureDir, n, "expect.json")); } catch { return ""; } })()] as const);

  return codes.map(([code, kind]) => {
    const word = new RegExp(`(?<![A-Za-z_])${code}(?![A-Za-z_])`);
    const raised: Rule["raised"] = [];
    for (const [file, lines] of moduleLines) {
      for (const [i, l] of lines.entries()) {
        if (!l.includes(`code: "${code}"`)) continue;
        const fn = enclosing(lines, i);
        if (!raised.some((r) => r.file === file && r.fn === fn)) raised.push({ file, fn });
      }
    }
    const design: Rule["design"] = [];
    for (const [file, lines] of adrs) {
      let section = "(top)";
      for (const l of lines) {
        const h = /^#{2,4}\s+(.*)$/.exec(l);
        if (h) section = h[1]!.trim();
        else if (word.test(l) && !design.some((d) => d.file === file && d.section === section)) design.push({ file, section });
      }
    }
    return {
      code,
      kind,
      raised,
      design,
      tests: tests.filter(([, t]) => word.test(t)).map(([f]) => f),
      fixtures: fixtures.filter(([, e]) => word.test(e)).map(([n]) => n),
    };
  });
}

/** The register as docs/rules.md: a table per kind, then each rule's links. */
export function registerMarkdown(rules: Rule[]): string {
  const out: string[] = [
    "# The rule register",
    "",
    "Generated by `scripts/rules.ts --write` from the code; do not edit by hand. `tests/rules-register.test.ts` fails when this file is stale, or when a rule has no test, no contract fixture and no design section.",
    "",
    "Each coded rule of the ledger: a defect holds the finish line, a warning is said where the decision is made and holds nothing, and a cap records an established attest as a best candidate. For each: where it is raised, the design that states it, and the tests and contract fixtures that exercise it. A change to a rule shows in this file's diff; `swarm.sh replay <run> --compare A B` measures it over recorded runs.",
    "",
  ];
  const titles: Record<RuleKind, string> = { defect: "Defects (hold the finish line)", warning: "Warnings (hold nothing)", cap: "Review caps (recorded best_candidate)" };
  for (const kind of ["defect", "warning", "cap"] as RuleKind[]) {
    const rs = rules.filter((r) => r.kind === kind);
    out.push(`## ${titles[kind]}`, "", "| Code | Raised in | Design | Tests | Fixtures |", "| --- | --- | --- | --- | --- |");
    for (const r of rs) {
      const raised = r.raised.map((x) => `\`${x.fn}\` (${basename(x.file)})`).join(", ") || "—";
      const design = r.design.map((d) => `${basename(d.file) === "protocol.md" ? "protocol" : `ADR ${basename(d.file).slice(0, 4)}`} "${d.section}"`).join("; ") || "—";
      const tests = r.tests.map((t) => (t.startsWith(join("tests", "rules")) ? `rules/${basename(t)}` : basename(t))).join(", ") || "—";
      const fx = r.fixtures.join(", ") || "—";
      out.push(`| \`${r.code}\` | ${raised} | ${design} | ${tests} | ${fx} |`);
    }
    out.push("");
  }
  return `${out.join("\n").trimEnd()}\n`;
}

/** The rules nothing exercises or states: no test and no fixture, or no design section. */
export function gaps(rules: Rule[]): Array<{ code: string; missing: string[] }> {
  return rules
    .map((r) => ({ code: r.code, missing: [...(!r.tests.length && !r.fixtures.length ? ["a test or a contract fixture"] : []), ...(!r.design.length ? ["a design section"] : []), ...(!r.raised.length ? ["a place it is raised"] : [])] }))
    .filter((g) => g.missing.length);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rules = buildRegister();
  const md = registerMarkdown(rules);
  if (process.argv.includes("--json")) process.stdout.write(`${JSON.stringify({ rules, gaps: gaps(rules) }, null, 2)}\n`);
  else if (process.argv.includes("--write")) {
    writeFileSync(REGISTER, md);
    process.stdout.write(`${REGISTER}: ${rules.length} rules\n`);
  } else if (process.argv.includes("--check")) {
    let now = "";
    try {
      now = read(REGISTER);
    } catch {
      now = "";
    }
    const g = gaps(rules);
    if (now !== md) process.stderr.write("docs/rules.md is stale: run node --experimental-strip-types scripts/rules.ts --write\n");
    for (const x of g) process.stderr.write(`${x.code}: no ${x.missing.join(", no ")}\n`);
    process.exit(now === md && !g.length ? 0 : 1);
  } else process.stdout.write(md);
}
