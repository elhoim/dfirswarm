/**
 * computer-forensics-base: the skills are held to the size and shape rules for a skill leaf (a leaf is at most
 * 800 tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at
 * most two deep and its chain at most 1,900 tokens; an index entry is at most 40 tokens), they say what an
 * artefact shows, does not show and what to record, the tools and programs a body names are in its front matter,
 * and the field names they teach are fields the tools really write, so a skill cannot keep teaching a field a
 * tool no longer has. The overclaims the review found, and the ones the split pass could bring back, are not in
 * them, and every id another pack reaches through `needs` is still a skill of this pack.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "computer-forensics-base");
const SKILLS = join(PACK, "skills");
const TOKENS = (text: string): number => Buffer.byteLength(text) / 4.245;

type Skill = { id: string; meta: Record<string, string | string[]>; body: string; text: string };

async function load(root: string): Promise<Map<string, Skill>> {
  const out = new Map<string, Skill>();
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(join(dir, e.name));
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") {
        const text = await readFile(join(dir, e.name), "utf8");
        const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
        assert.ok(m, `${e.name} has front matter`);
        const meta: Record<string, string | string[]> = {};
        for (const line of m[1].split("\n")) {
          const [k, ...rest] = line.split(":");
          const v = rest.join(":").trim();
          meta[k.trim()] = v.startsWith("[") ? v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : v;
        }
        out.set(String(meta.id), { id: String(meta.id), meta, body: text.slice(m[0].length), text });
      }
    }
  };
  await walk(root);
  return out;
}

// The second-level leaves: each is pointed to by the leaf that says when to open it, and opens with "Use only if".
const SECOND_LEVEL: Record<string, string> = {
  "filesystem/scanners": "filesystem/carving",
  "filesystem/encrypted-metadata": "filesystem/encrypted",
  "timeline/super-scope": "timeline/super",
};

// Skills whose tools can put secrets, credentials or private text in front of the agent: each has a Sensitive output part.
const SENSITIVE = [
  "data/documents-media", "data/sqlite", "filesystem/carving", "filesystem/encrypted-metadata", "filesystem/extract",
  "filesystem/scanners", "filesystem/semantics", "timeline/super", "evidence/archives",
];

// The skills added by Phase 2b; each has the full set of parts.
const NEW = [
  "evidence/scope", "evidence/provenance", "evidence/coverage", "evidence/tool-validation", "timeline/clocks",
  "filesystem/semantics", "filesystem/layers", "data/documents-media",
];

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 25);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    if (s.id in SECOND_LEVEL) assert.match(first, /^Use only if /, `${s.id} says it is a second-level leaf`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The two reporting leaves are method leaves about the ledger's acts: they read no artefact, so they show nothing.
    if (!s.id.startsWith("reporting/")) assert.match(s.body, /\*\*Does not show\.\*\*/, `${s.id} has a Does not show part`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
  assert.ok(TOKENS(index) <= 1000, `the pack index is ${Math.round(TOKENS(index))} tokens`);
});

test("the new skills say what to record, and the skills whose tools can surface secrets have a Sensitive output part", async () => {
  const skills = await load(SKILLS);
  for (const id of NEW) {
    const s = skills.get(id);
    assert.ok(s, id);
    assert.match(s.body, /\*\*Record\.\*\*/, `${id} says what to record`);
  }
  for (const id of SENSITIVE) assert.match(skills.get(id)!.body, /\*\*Sensitive output\.\*\*/, `${id} has Sensitive output`);
  // The phrase is the worker prompt's: a job that may read a secret runs with secret_output: true.
  const prompt = await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /runs with `secret_output: true`/);
  for (const id of ["data/sqlite", "data/documents-media", "filesystem/scanners", "filesystem/encrypted-metadata", "filesystem/extract", "filesystem/semantics"]) {
    assert.match(skills.get(id)!.body, /`secret_output: true`/, `${id} says secret_output: true`);
  }
  // The skill about hashes writes the secret-digest exception, and the SQLite one keeps a short BLOB's digest out of the ledger.
  assert.match(skills.get("evidence/provenance")!.body, /A digest of a secret is not/);
  assert.match(skills.get("data/sqlite")!.body, /never the value, a fragment of it, or the `sha256` and base64 of a short BLOB/);
});

test("needs is at most two deep and its chain is at most 1,900 tokens; every id another pack needs is still here", async () => {
  const skills = await load(SKILLS);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = skills.get(id);
    assert.ok(s, `${id} resolves`);
    let best = { depth: 0, ids: [id] };
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  for (const id of skills.keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const reached = new Set<string>();
    const add = (i: string): void => {
      if (reached.has(i)) return;
      reached.add(i);
      for (const n of (skills.get(i)!.meta.needs as string[]) ?? []) add(n);
    };
    add(id);
    const tokens = [...reached].reduce((n, i) => n + TOKENS(skills.get(i)!.text), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
  // The only edge left is a real assumption: a dispute is made against a citation.
  assert.deepEqual(
    [...skills.values()].filter((s) => ((s.meta.needs as string[]) ?? []).length).map((s) => `${s.id} > ${(s.meta.needs as string[]).join(",")}`),
    ["reporting/disagreement > reporting/citations"],
  );
  // Other packs reach these through `needs` (and name them in their text): an id removed or renamed here breaks them.
  const packs = join(ROOT, "packs");
  const reachedByOthers = new Set<string>();
  for (const p of await readdir(packs)) {
    if (p === "computer-forensics-base") continue;
    const dir = join(packs, p, "skills");
    const others = await load(dir).catch(() => new Map<string, Skill>());
    for (const s of others.values()) for (const n of (s.meta.needs as string[]) ?? []) if (!others.has(n)) reachedByOthers.add(n.replace(/^computer-forensics-base:/, ""));
  }
  assert.ok(reachedByOthers.size > 0);
  for (const id of reachedByOthers) assert.ok(skills.has(id), `another pack needs ${id}, which this pack no longer has`);
  for (const id of ["evidence/imaging", "evidence/verify", "filesystem/carving", "filesystem/encrypted", "reporting/citations", "timeline/build", "timeline/super"]) {
    assert.ok(skills.has(id), `${id} is still a skill (other packs name it)`);
  }
});

test("every second-level leaf is pointed to by a leaf that says when to open it, and the new method leaves are reachable from the leaves they specialise", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(SECOND_LEVEL)) {
    const p = skills.get(parent)!;
    const at = p.body.indexOf(`\`${child}\``);
    assert.ok(at >= 0, `${parent} points to ${child}`);
    assert.match(p.body.slice(Math.max(0, at - 160), at + 40), /\bNot for\b|[Oo]nly if|\bsays when\b/, `${parent} says when to open ${child}`);
  }
  // Pointers: who sends the agent to the new leaves.
  const pointers: Array<[string, string]> = [
    ["evidence/verify", "evidence/provenance"], ["evidence/catalog", "evidence/coverage"], ["filesystem/carving", "evidence/coverage"],
    ["timeline/build", "timeline/clocks"], ["timeline/super-scope", "timeline/clocks"], ["data/sqlite", "timeline/clocks"],
    ["evidence/imaging", "filesystem/layers"], ["filesystem/carving", "filesystem/layers"], ["filesystem/extract", "filesystem/semantics"],
    ["filesystem/encrypted-metadata", "evidence/scope"], ["data/documents-media", "evidence/scope"], ["evidence/coverage", "evidence/tool-validation"],
    ["reporting/citations", "evidence/coverage"],
  ];
  for (const [from, to] of pointers) assert.ok(skills.get(from)!.body.includes(`\`${to}\``), `${from} points to ${to}`);
  // Every skill is named by another skill of the pack, besides being in the index: none is reachable only by luck.
  const everything = [...skills.values()];
  for (const s of everything) {
    assert.ok(everything.some((o) => o.id !== s.id && o.body.includes(`\`${s.id}\``)), `${s.id} is named by no other skill`);
  }
});

// Fields and names a skill teaches, each of which a tool must write or read: file -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["tools/sqlite_snapshot/run.py", "data/sqlite", ["changed_during_copy", "frames_committed", "frames_uncommitted_valid", "first_invalid_frame", "counts_agree", "rollback_journal", "pages_of_the_main_file_changed_by_the_wal"]],
  ["tools/sqlite_query/run.py", "data/sqlite", ["snapshot_status", "rows_file", "blob_b64", "freelist_count", "application_id", "user_version"]],
  ["tools/catalog_search/run.py", "evidence/coverage", ["all_matches", "revision", "matched"]],
  ["tools/timestamp_decode/run.py", "timeline/clocks", ["remainder_s"]],
  ["tools/timeline_super/run.py", "timeline/super", ["status", "collect_exit", "export_exit", "invalid_lines", "resume"]],
  ["tools/timeline_super/run.py", "timeline/super-scope", ["timezone", "storage_file", "psort_filter", "mode"]],
  ["tools/image_layout/run.py", "evidence/imaging", ["partition_table", "raw_outputs", "sector_size"]],
  ["tools/check_inputs/run.py", "evidence/verify", ["not_checked"]],
  ["tools/file_carver/run.py", "filesystem/carving", ["boundary", "overlay_uncertain", "validated", "heuristic"]],
  ["tools/ioc_scan/run.py", "filesystem/scanners", ["write_values", "all_results"]],
  ["tools/feature_scan/run.py", "filesystem/scanners", ["out_dir_contains_secret_values", "report.xml"]],
  ["tools/archive_extract/run.py", "evidence/provenance", ["SHORT_MEMBER"]],
];

test("the tool fields a skill names are fields the tools write", async () => {
  const skills = await load(SKILLS);
  for (const [file, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, file), "utf8");
    const body = skills.get(skillId)!.body;
    for (const name of names) {
      // SHORT_MEMBER is the constant behind the 128-byte rule the provenance leaf states.
      if (name === "SHORT_MEMBER") {
        assert.match(body, /under 128 bytes/);
        assert.match(script, /SHORT_MEMBER = 128/);
        continue;
      }
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      const written = /^[a-z_]+$/.test(name) ? script.includes(`"${name}"`) || script.includes(`${name}=`) || script.includes(`${name}:`) : script.includes(name);
      assert.ok(written, `${file} writes ${name}, which ${skillId} teaches`);
    }
  }
});

test("the claims the review found are not in the skills, and the front matter lists what the body names", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  const banned: RegExp[] = [
    /Nothing you extract can execute/i,
    /decided more than one case/i,
    /dislocker[^\n]* -p<[^>]*>/i,
    /there is nothing to weigh/i,
    /\bprobably encrypted\b/i,
    /no disk, no partition, no inode/i,
    /cuts it down without running the collection again/i,
    /`timestamp_decode`[^.\n]*\bsettles\b/i,
    /\blossless\b[^.\n]*`file_carver`|`file_carver`[^.\n]*\blossless\b/i,
    /a clock change stops mattering/i,
    /newest messages are (the ones )?in the WAL/i,
    /\bcannot be recovered\b(?![^\n]*(only after|never))/i,
    /\bhash of (the|a) (secret|password|key)[^\n]*\b(quote|write it|record it)\b/i,
    /--password[= ]|passphrase on the command line is fine/i,
  ];
  for (const re of banned) assert.doesNotMatch(all, re);
  // A body that names a tool of the pack in code lists it; the list is exactly what the pack-links lint holds, and here for the new leaves.
  const tools = (await readdir(join(PACK, "tools"))).sort();
  for (const s of skills.values()) {
    const listed = new Set([...(s.meta.tools as string[]), ...(s.meta.requires_host as string[])]);
    for (const t of tools) {
      const named = new RegExp("(?<![\\w.-])" + t + "(?![\\w-])").test(s.body);
      if (named) assert.ok(listed.has(t), `${s.id} names ${t} but does not list it`);
    }
    for (const t of listed) assert.ok(new RegExp("(?<![\\w.-])" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?![\\w-])").test(s.body), `${s.id} lists ${t} but never names it`);
  }
  // No version fact is stated for a program the pack does not pin: a dated "as of" is the form for one.
  assert.doesNotMatch(all, /\b(Plaso|libewf|Sleuth Kit|SQLite|bulk_extractor|steghide|exiftool) (version )?\d+(\.\d+)+/);
  // The stand-in rules: the method leaves name no tool they do not use (scope is a method leaf), and a secret is never put on a command line.
  assert.deepEqual(skills.get("evidence/scope")!.meta.tools, []);
  assert.match(skills.get("filesystem/encrypted-metadata")!.body, /It never goes on a command line: argv is recorded in the trace/);
});

test("the sizes the split pass reached stay: the skills that were over a budget are not on the golden list any more", async () => {
  const golden = await readFile(join(ROOT, "tests", "skill-budgets.golden"), "utf8");
  assert.doesNotMatch(golden, /^computer-forensics-base /m, "the base pack has no known budget finding left");
});
