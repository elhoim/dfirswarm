/**
 * memory-forensics: the split pass. Every skill is a leaf within the size budget (at most 800 tokens, estimated
 * as bytes / 4.245, and 300 lines; an index entry at most 40 tokens), `needs` is at most two deep and its chain
 * at most 1,900 tokens, every second-level leaf is pointed to by a leaf that says when to open it, every id the
 * pack had before the split (and every id another pack names) is still a skill, and no rule of the review was
 * lost in the move: tests/pack-split-rules/memory-forensics.json lists, per old skill, the sentences that carry a Shows / Does not
 * show / Record / Sensitive output / bounded-negative / corroboration rule, and each must still be in the pack.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "memory-forensics");
const SKILLS = join(PACK, "skills");
const BASE_SKILLS = join(ROOT, "packs", "computer-forensics-base", "skills");
const TOKENS = (text: string): number => Buffer.byteLength(text) / 4.245;
const flat = (s: string): string => s.replace(/\s+/g, " ");
const norm = (s: string): string => s.replace(/[`*]/g, "").replace(/\s+/g, " ").toLowerCase().trim();

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

// The decision leaves (the nine ids the pack had before the split) and their second-level leaves.
const OLD_IDS = [
  "acquire/images", "credentials/material", "network/state", "patterns/yara", "processes/injection",
  "strings/discipline", "triage/no-framework", "triage/volatility", "triage/what-you-have",
];
const SECOND: Record<string, string> = {
  "triage/container-details": "triage/what-you-have",
  "triage/carve-signatures": "triage/no-framework",
  "triage/paging-files": "triage/no-framework",
  "triage/volatility-symbols": "triage/volatility",
  "triage/volatility-plugins": "triage/volatility",
  "triage/volatility-catalogue": "triage/volatility",
  "processes/preserve-regions": "processes/injection",
  "network/timestamps-dns": "network/state",
  "credentials/key-schedules": "credentials/material",
  "acquire/avml-and-preserve": "acquire/images",
};

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, OLD_IDS.length + Object.keys(SECOND).length);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    assert.match(flat(s.body), /Does not show/i, `${s.id} says what it does not show`);
    assert.ok(s.body.includes("Sensitive output") || s.body.includes("Record:"), `${s.id} has Sensitive output or Record`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const walk = (id: string, seen: string[], members: Set<string>): number => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    members.add(id);
    let depth = 0;
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      depth = Math.max(depth, 1 + walk(n, [...seen, id], members));
    }
    return depth;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const members = new Set<string>();
    const depth = walk(id, [], members);
    assert.ok(depth <= 2, `${id} needs ${depth} deep`);
    const tokens = [...members].reduce((n, i) => n + TOKENS(all.get(i)!.text), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
  // A needs edge is for an assumption the skill cannot do without, not for a pointer: the second-level leaves need nothing.
  for (const child of Object.keys(SECOND)) assert.deepEqual((await load(SKILLS)).get(child)!.meta.needs, [], `${child} needs nothing`);
});

test("every second-level leaf is pointed to by a leaf that says when to open it", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(SECOND)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    assert.match(p.body, new RegExp(`Only (if|for)[\\s\\S]{0,320}\`${child}\``), `${parent} says when to open ${child}`);
    assert.match(skills.get(child)!.body.trim().split("\n")[0], /^Use only if /, `${child} says it is a second-level leaf`);
  }
});

test("every id the pack had, and every id another pack names, is still a skill", async () => {
  const skills = await load(SKILLS);
  for (const id of OLD_IDS) assert.ok(skills.has(id), `${id} is still a skill`);
  // Other packs name this pack's ids in prose (windows-forensics' memory skill) and in tests; each must resolve.
  const windows = await readFile(join(ROOT, "packs", "windows-forensics", "skills", "memory", "windows.md"), "utf8");
  for (const id of ["triage/volatility", "processes/injection", "strings/discipline"]) {
    assert.ok(windows.includes(`\`${id}\``) && skills.has(id), `windows-forensics names ${id}`);
  }
});

test("no rule of the review was lost in the move: the register of sentences is still in the pack", async () => {
  const skills = await load(SKILLS);
  const corpus = norm([...skills.values()].map((s) => s.body).join("\n"));
  const rules = JSON.parse(await readFile(join(ROOT, "tests", "pack-split-rules", "memory-forensics.json"), "utf8")) as Array<[string, string]>;
  assert.ok(rules.length >= 100, "the register is the whole one");
  for (const [from, frag] of rules) assert.ok(corpus.includes(frag), `from ${from}, gone: "${frag}" (moved or reworded: update tests/pack-split-rules/memory-forensics.json in the same change)`);
});

test("the rules the pack is held to are in the skills that carry them", async () => {
  const skills = await load(SKILLS);
  const body = (id: string): string => skills.get(id)!.body;
  // The Volatility offline rule stays, with the symbol rule beside it and no fetch fallback.
  assert.match(body("triage/volatility"), /vol --offline -vv -f IMAGE windows\.info/);
  assert.match(body("triage/volatility"), /Do not switch off `--offline`, and fetch nothing/);
  assert.match(body("triage/volatility"), /Never copy a symbol\s+table into a job's output/);
  assert.match(body("triage/volatility-catalogue"), /you do not run that fallback/);
  // Version facts are dated and name the version they hold for.
  for (const id of ["triage/volatility-plugins", "triage/volatility-symbols", "patterns/yara", "processes/injection", "triage/container-details"]) {
    assert.match(body(id), /as of October\s+2026/, `${id} dates its version facts`);
    assert.match(body(id), /2\.28\.2/, `${id} names the version`);
  }
  // The secret rules: the home of the rule, and a Sensitive output line wherever a secret-reaching tool or plugin is named.
  const home = body("credentials/material");
  assert.match(home, /\*\*Sensitive output\.\*\*[\s\S]*secret_output: true/);
  assert.match(home, /never a hash, digest, fingerprint or masked "shape" of a secret/);
  assert.match(home, /at most the first 4 and\s+the last 4/);
  assert.match(home, /A secret found in\s+evidence is an indicator, never a credential/);
  for (const id of ["triage/volatility", "triage/volatility-plugins", "triage/no-framework", "triage/carve-signatures", "triage/paging-files", "strings/discipline", "network/state", "patterns/yara", "processes/injection", "processes/preserve-regions", "credentials/key-schedules"]) {
    assert.match(body(id), /Sensitive output/, `${id} has a Sensitive output line`);
    assert.match(body(id), /secret_output: true/, `${id} says the job runs with secret_output: true`);
  }
  assert.match(body("credentials/key-schedules"), /copy neither the key nor that digest/);
  assert.match(body("credentials/key-schedules"), /take the\s+offsets and the count, not the keys/);
  // Four questions stay four; a negative is bounded.
  assert.match(home, /Four questions, each with its own evidence/);
  assert.match(body("strings/discipline"), /A hit with no locator is not evidence/);
  assert.match(body("network/timestamps-dns"), /record the route as\s+unexamined/);
});

test("the claims the review removed are not back, and the front matter lists what the body names", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  const banned: RegExp[] = [
    /memory is where credentials are in the clear/i,
    /sha256 to record/i,
    /record (its|the|a secret's) hash/i,
    /instant of acquisition/i,
    /page-file structures/i,
    /a snapshot is (always )?the best/i,
    /every capture is a smear/i,
    /^\s+avml\s+-/m,
    /^\s+vol(\.py)? .*\bwindows\.malfind\b/m,
    /\b(is|are|was|were) (the )?injected code\b/i,
  ];
  for (const re of banned) {
    assert.doesNotMatch(all, re, `${re} is not in the pack's skills`);
  }
  for (const s of skills.values()) {
    for (const tool of (s.meta.tools as string[]) ?? []) assert.ok(s.body.includes(tool), `${s.id} lists ${tool} and names it`);
    for (const prog of (s.meta.requires_host as string[]) ?? []) assert.ok(s.body.includes(prog), `${s.id} lists ${prog} and names it`);
  }
});

// Fields and names a skill teaches, each of which a tool must write: file -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["tools/mem_carve/run.py", "triage/carve-signatures", ["signature_offset", "object_offset", "validation"]],
  ["tools/mem_profile/run.py", "triage/container-details", ["physical_start", "file_offset"]],
  ["tools/mem_profile/run.py", "triage/what-you-have", ["file_pages_4k_estimate"]],
  ["tools/mem_fs/run.py", "processes/preserve-regions", ["write_values", "export-manifest.jsonl"]],
];

test("the tool fields a skill names are fields the tools write", async () => {
  const skills = await load(SKILLS);
  for (const [file, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, file), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      const written = /^[a-z_0-9]+$/.test(name) ? script.includes(`"${name}"`) : script.includes(name);
      assert.ok(written, `${file} writes ${name}, which ${skillId} teaches`);
    }
  }
});
