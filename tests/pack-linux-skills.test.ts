/**
 * linux-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800 tokens,
 * estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..." or, for a second-level leaf,
 * "Use only if ... Not for ..."; `needs` is at most two deep and its chain at most 1,900 tokens counting the base
 * skills it reaches; an index entry is at most 40 tokens), they say what an artefact shows, what it does not and what
 * to record, and the tool fields they name are fields those tools really write. The split of a long skill into a
 * decision-rule leaf and second-level leaves keeps every rule: the key rules are asserted here by their text.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "linux-forensics");
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
  "accounts/users", "containers/docker", "filesystem/ext", "filesystem/storage", "logs/auth", "logs/journal",
  "packages/integrity", "persistence/mechanisms", "timeline/linux", "triage/system-profile",
];
const CHILDREN: Record<string, string> = {
  "triage/identity-files": "triage/system-profile",
  "triage/clocks-boots": "triage/system-profile",
  "accounts/sessions-histories": "accounts/users",
  "containers/layers-times": "containers/docker",
  "containers/removed-logs": "containers/docker",
  "filesystem/ext-deleted": "filesystem/ext",
  "filesystem/storage-lvm-luks": "filesystem/storage",
  "filesystem/storage-xfs-btrfs-virtual": "filesystem/storage",
  "logs/auth-lines": "logs/auth",
  "logs/auth-time": "logs/auth",
  "logs/journal-clocks-verify": "logs/journal",
  "packages/baseline": "packages/integrity",
  "persistence/cron-timers": "persistence/mechanisms",
  "persistence/quieter-routes": "persistence/mechanisms",
  "timeline/linux-normalise": "timeline/linux",
};

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
    for (const part of ["Shows", "Does not show", "Record", "Sensitive output"]) {
      assert.match(s.body, new RegExp(`(^|\\. )${part}:`, "m"), `${s.id} has ${part}`);
    }
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    let best = { depth: 0, ids: [id] };
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  const closure = (id: string, acc: Set<string> = new Set()): Set<string> => {
    acc.add(id);
    for (const n of (all.get(id)?.meta.needs as string[]) ?? []) closure(n, acc);
    return acc;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const tokens = [...closure(id)].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
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
    assert.match(p.body.slice(Math.max(0, at - 260), at + 120), /[Oo]nly (if|once)|read with/, `${parent} says when to open ${child}`);
  }
});

// Fields and names a skill teaches, each of which a tool must write or read: tool -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["auth_log", "logs/auth", ["order_basis", "cross_file_order", "year_basis", "write_text", "preview_text"]],
  ["auth_log", "logs/auth-time", ["year_basis", "time_raw", "time_utc", "time_zone", "rollovers", "rollover_lines", "reordered", "unparsed", "read_errors", "all_lines_parsed", "max_seconds"]],
  ["auth_log", "logs/auth-lines", ["user_bytes", "user_withheld"]],
  ["journal_export", "logs/journal", ["boots", "realtime_us", "monotonic_us", "native_line", "oversized_lines", "write_text", "preview_text", "journal-native.jsonl"]],
  ["journal_export", "logs/journal-clocks-verify", ["verify"]],
  ["utmp_parse", "accounts/sessions-histories", ["layout", "byte_order"]],
  ["shell_history", "accounts/sessions-histories", ["write_commands"]],
  ["linux_triage", "triage/system-profile", ["execution_complete", "coverage", "parsed"]],
  ["cron_dump", "persistence/cron-timers", ["unsupported", "write_text"]],
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

test("the rules the split keeps: observation against verdict, bounded negatives, how the tools' status field is described", async () => {
  const skills = await load(SKILLS);
  const has = (id: string, re: RegExp): void => assert.match(skills.get(id)!.body.replace(/\s+/g, " "), re, `${id}: ${re}`);
  has("triage/system-profile", /`execution_complete` says the processes exited 0, which is not coverage/);
  has("triage/system-profile", /Treat an `empty` result as a parser's result, not as an absence/);
  has("triage/identity-files", /say the installation date is not determinable/);
  has("triage/clocks-boots", /a reboot that left no record in one source is not shown not to have happened/);
  has("triage/clocks-boots", /not from `\/etc\/timezone` alone/);
  has("accounts/users", /not to every root command/);
  has("accounts/users", /who was at the keyboard, or that a command ran/);
  has("accounts/sessions-histories", /a session with no end record is not shown to be open/);
  has("containers/docker", /that a risky configuration was exploited/);
  has("containers/removed-logs", /do not let a missing Docker directory clear the other runtimes/);
  has("filesystem/ext", /a lead and not a timestomping diagnosis/);
  has("filesystem/ext-deleted", /Do not write that contents are unrecoverable on the strength of an inode and a journal search/);
  has("filesystem/storage", /Do not call an unreadable partition damaged until you have identified the layer at its offset/);
  has("filesystem/storage-lvm-luks", /Header inspection does not show who owns a key slot/);
  has("logs/auth", /report a disagreement as a question with the alternatives, not as a finding/);
  has("logs/auth-time", /`status` is `complete` only where `all_lines_parsed` is true, which says every line matched a syslog shape and every file was read through, nothing more/);
  has("logs/auth-lines", /a person; for `publickey`, only a key/);
  has("logs/journal", /It does not show the historical storage policy/);
  has("logs/journal-clocks-verify", /A clean result does not authenticate an unsealed journal/);
  has("packages/integrity", /Run no verification script from the evidence/);
  has("packages/baseline", /a clean report is not a clean machine/);
  has("persistence/mechanisms", /No candidate matching these mechanisms was identified in these sources over this period/);
  has("persistence/cron-timers", /so an empty result there is not a negative/);
  has("timeline/linux", /a clean run is no evidence of RPM, newer accounting or full container coverage/);
  has("timeline/linux-normalise", /An empty parser result supports an absence only when/);
});

test("a skill that can reach secrets says the job runs with secret_output and cites a locator, never a value, a fragment or a hash", async () => {
  const skills = await load(SKILLS);
  for (const id of ["accounts/users", "accounts/sessions-histories", "logs/auth", "logs/journal", "persistence/mechanisms", "persistence/cron-timers", "timeline/linux", "triage/system-profile"]) {
    const body = skills.get(id)!.body;
    assert.match(body, /secret_output/, `${id} names secret_output`);
    assert.match(body, /(never|no) [^.]*(hash|value)/i, `${id} forbids a value or hash`);
  }
});

test("no skill states a distribution default it cannot source", async () => {
  const all = [...(await load(SKILLS)).values()].map((s) => s.body).join("\n");
  assert.doesNotMatch(all, /\b(Ubuntu|Debian|Red Hat|RHEL|Fedora|CentOS)\b[^.\n]{0,40}\b(defaults? to|by default)\b/i);
});
