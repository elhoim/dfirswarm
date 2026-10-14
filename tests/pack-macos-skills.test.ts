/**
 * macos-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800 tokens,
 * estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..." or, for a second-level leaf,
 * "Use only if ... Not for ..."; `needs` is at most two deep and its chain at most 1,900 tokens counting the base
 * skills it reaches; an index entry is at most 40 tokens). They say what an artefact shows, what it does not and what
 * to record, and the tool fields they name are fields those tools really write. The split of a long skill into a
 * decision-rule leaf and second-level leaves keeps every rule: the key rules are asserted here by their wording.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "macos-forensics");
const SKILLS = join(PACK, "skills");
const BASE_SKILLS = join(ROOT, "packs", "computer-forensics-base", "skills");
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

// Every old skill id stays, as a decision-rule leaf; the second-level leaves are reached from a parent by "only if".
const OLD_IDS = [
  "accounts/users", "artifacts/fsevents", "artifacts/knowledgec", "artifacts/plists", "filesystem/apfs",
  "logs/unified", "persistence/mechanisms", "triage/system-profile",
];
const CHILDREN: Record<string, string> = {
  "triage/clocks-hardware": "triage/system-profile",
  "accounts/attribution-remote": "accounts/users",
  "artifacts/plists-archives-dates": "artifacts/plists",
  "artifacts/fsevents-dating": "artifacts/fsevents",
  "artifacts/knowledgec-fields-time": "artifacts/knowledgec",
  "filesystem/apfs-recovery": "filesystem/apfs",
  "filesystem/apfs-encryption": "filesystem/apfs",
  "logs/unified-readers": "logs/unified",
  "persistence/login-items-quieter": "persistence/mechanisms",
};
// The leaves that can reach secret material say so; the rest point to them.
const SECRET_LEAVES = ["accounts/users", "artifacts/plists", "artifacts/knowledgec", "logs/unified", "persistence/mechanisms", "triage/system-profile"];

test("every skill is a leaf within the budget, opens with Use when/only if ... Not for ..., has a short index entry, and old ids stay", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, OLD_IDS.length + Object.keys(CHILDREN).length);
  for (const id of OLD_IDS) assert.ok(skills.has(id), `old id ${id} is alive`);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, s.id in CHILDREN ? /^Use only if / : /^Use when /, `${s.id} opens with the right Use line`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    assert.match(s.body, /\b(Shows|Does not show)[.:]/, `${s.id} says what it shows or does not show`);
    assert.match(s.body, /Does not show[.:*]/, `${s.id} has Does not show`);
    if (SECRET_LEAVES.includes(s.id)) assert.match(s.body, /Sensitive output/, `${s.id} has Sensitive output`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const closure = (id: string, depth: number, acc: Map<string, number>): void => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    assert.ok(depth <= 2, `${id} is reached ${depth} deep`);
    acc.set(id, depth);
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!acc.has(n) || acc.get(n)! < depth + 1, `no cycle at ${n}`);
      closure(n, depth + 1, acc);
    }
  };
  for (const id of (await load(SKILLS)).keys()) {
    const acc = new Map<string, number>();
    closure(id, 0, acc);
    const tokens = [...acc.keys()].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by its parent with an 'only if' that says when to open it", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(CHILDREN)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    const at = p.body.indexOf(`\`${child}\``);
    assert.ok(at >= 0, `${parent} points to ${child}`);
    assert.match(p.body.slice(Math.max(0, at - 260), at + 160), /[Oo]nly if/, `${parent} says when to open ${child}`);
  }
});

// Fields and names a skill teaches, each of which a tool must write or read: tool -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["plist_read", "artifacts/plists", ["extracted_file_mtime", "write_values"]],
  ["knowledgec_query", "artifacts/knowledgec", ["source_used", "problems", "filters_unapplied"]],
  ["knowledgec_query", "artifacts/knowledgec-fields-time", ["value_type_code", "utc_offset_seconds", "export_oversize", "_truncated", "_where"]],
  ["fsevents_parse", "artifacts/fsevents", ["files_by_state", "flags_undecoded", "coverage", "problems"]],
  ["unified_log", "logs/unified", ["decoded_coverage", "support_files", "problems", "warnings"]],
  ["unified_log", "logs/unified-readers", ["reader"]],
];

test("the tool fields a skill names are fields the tools write", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, "tools", tool, "run.py"), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name), `${tool} writes ${name}, which ${skillId} teaches`);
    }
  }
});

test("the front matter lists the tools of the pack that the body names, and only those", async () => {
  const skills = await load(SKILLS);
  const tools = (await readdir(join(PACK, "tools"))).filter((n) => !n.startsWith("."));
  for (const s of skills.values()) {
    const listed = new Set(s.meta.tools as string[]);
    for (const name of tools) {
      const named = new RegExp("(^|[^A-Za-z0-9_-])" + name + "([^A-Za-z0-9_-]|$)").test(s.body);
      assert.equal(listed.has(name), named, `${s.id}: ${name} ${named ? "is named but not listed" : "is listed but not named"}`);
    }
  }
});

test("the rules the split keeps: observation against verdict, bounded negatives, the secret boundary, APFS and TCC limits", async () => {
  const skills = await load(SKILLS);
  const has = (id: string, re: RegExp): void => assert.match(skills.get(id)!.body.replace(/\s+/g, " "), re, `${id}: ${re}`);
  has("triage/system-profile", /A set of files is not a volume/);
  has("triage/system-profile", /there is no `BuildVersion`/);
  has("triage/system-profile", /it is not a record of installation/);
  has("triage/system-profile", /a packaging limit that says nothing about the subject's hardware/);
  has("triage/clocks-hardware", /applying the zone to them shifts them twice/);
  has("triage/clocks-hardware", /Report a serial number only when its source identifies this Mac/);
  has("accounts/users", /Membership at acquisition does not show membership at an earlier event/);
  has("accounts/users", /It is not a password-change, account-creation, login or key-installation event/);
  has("accounts/users", /never its bytes, a preview or a hash/);
  has("accounts/attribution-remote", /they do not show keyboard input or physical presence, in a row or alone/);
  has("accounts/attribution-remote", /Naming a person needs case evidence the artefacts here do not supply/);
  has("accounts/attribution-remote", /it does not show that the host was reachable, that the key was accepted, or that anyone logged in/);
  has("artifacts/plists", /Neither the file's mtime nor a clean shutdown establishes that/);
  has("artifacts/plists", /never a value, a fragment or a hash of one/);
  has("artifacts/plists-archives-dates", /a plausible date is not proof that the epoch is the field's/);
  has("artifacts/fsevents", /A zero count, an empty `problems` list or an exit of 0 is not a finished examination/);
  has("artifacts/fsevents", /no matching record was decoded from these files, by this parser and filter/);
  has("artifacts/fsevents-dating", /Event ids \(printed by `fsevents_parse`\) order records; they do not date them/);
  has("artifacts/fsevents-dating", /One anchor bounds the interval on one side/);
  has("artifacts/knowledgec", /keep apart "not retained", "not acquired", "unsupported" and "searched, no match"/);
  has("artifacts/knowledgec", /Does not show: keyboard input, physical presence, attention, intent or who the human was/);
  has("artifacts/knowledgec-fields-time", /do not read creation \(ingestion\) time as the time of the activity/);
  has("filesystem/apfs", /write "snapshot coverage unavailable", not "no snapshots"/);
  has("filesystem/apfs-recovery", /there is no NTFS-style `\$MFT` does not mean there is no recoverable history/);
  has("filesystem/apfs-encryption", /`fvdeinfo` is for Core Storage; it is not assumed to read APFS/);
  has("logs/unified", /Complete is not a coverage claim/);
  has("logs/unified", /not proof that everything between them was recorded/);
  has("logs/unified-readers", /It does not bring back an entry that was never persisted, was removed by retention or was redacted/);
  has("persistence/mechanisms", /an agent loaded at login has not shown its program ran then/);
  has("persistence/mechanisms", /which no key-name pattern in `plist_read` catches/);
  has("persistence/login-items-quieter", /A registration is not execution/);
  has("persistence/login-items-quieter", /do not read an Accessibility permission as root or SYSTEM, or a TCC row's modified time as the time of a grant/);
});

test("a skill that can reach secrets says the job runs with secret_output and cites a locator, never a value, a fragment or a hash", async () => {
  const skills = await load(SKILLS);
  for (const id of ["accounts/users", "artifacts/plists", "persistence/mechanisms", "triage/system-profile"]) {
    const body = skills.get(id)!.body;
    assert.match(body, /secret_output/, `${id} names secret_output`);
    assert.match(body, /(never|no) [^.]*(hash|value|bytes)/i, `${id} forbids a value or hash`);
  }
});

test("no skill states an Apple version fact it cannot source, and the APFS time fact stays a Unix epoch", async () => {
  const all = [...(await load(SKILLS)).values()].map((s) => s.body).join("\n");
  assert.doesNotMatch(all, /\b(macOS|OS X|Mac OS X) ?(1[0-9]|2[0-9]|[0-9])(\.\d+)?\b/);
  assert.doesNotMatch(all, /\b(Sonoma|Ventura|Sequoia|Monterey|Big Sur|Catalina|Mojave|Tahoe)\b/);
  assert.match(all, /nanoseconds since the Unix epoch, not the Apple epoch/);
});
