/**
 * The cloud pack's skills: what each says it shows and does not, the credential boundary, the leaf budget, and the claims the review
 * removed (an operation read as an effect, a retention figure, a window of attacker access computed from two times). A claim that
 * returns fails by its wording; a fixture here is the skill's own text, never a tool's output.
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const SKILLS = join(ROOT, "packs", "cloud-forensics", "skills");
const IDS = [
  "aws/cloudtrail",
  "entra/signins",
  "google/workspace",
  "google/workspace-access",
  "identity/grants",
  "identity/tokens",
  "logs/sources",
  "logs/what-exists",
  "m365/unified-audit-log",
];

const read = (id: string): { front: Record<string, string>; text: string; body: string } => {
  const text = readFileSync(join(SKILLS, `${id}.md`), "utf8");
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  assert.ok(m, `${id} has front matter`);
  const front: Record<string, string> = {};
  for (const line of m[1].split("\n")) {
    const i = line.indexOf(":");
    front[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return { front, text, body: m[2] };
};

const list = (v: string): string[] => v.replace(/^\[|\]$/g, "").split(",").map((s) => s.trim()).filter(Boolean);

test("the pack carries these nine skills and no others", () => {
  const found: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(join(dir, e.name), `${prefix}${e.name}/`);
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") found.push(`${prefix}${e.name.replace(/\.md$/, "")}`);
    }
  };
  walk(SKILLS, "");
  assert.deepEqual(found.sort(), [...IDS].sort());
});

test("every skill is a leaf: at most 800 tokens (bytes / 4.245) and 300 lines, and its first line says when to use it and when not to", () => {
  for (const id of IDS) {
    const { text, body } = read(id);
    const tokens = Math.round(Buffer.byteLength(text) / 4.245);
    assert.ok(tokens <= 800, `${id} is ${tokens} tokens`);
    assert.ok(text.split("\n").length <= 300);
    assert.match(body.trimStart().split("\n")[0], /^Use when .*\bNot for\b/, `${id}: first line`);
  }
});

test("needs chains are two deep at most, every id resolves in the pack or in the base, and no skill declares a host program it does not run", () => {
  const base = new Set(["evidence/verify"]);
  const needs = (id: string): string[] => list(read(id).front.needs ?? "[]");
  const chain = (id: string): number => (base.has(id) ? 0 : 1 + Math.max(0, ...needs(id).map(chain)));
  for (const id of IDS) {
    for (const n of needs(id)) assert.ok(IDS.includes(n) || base.has(n), `${id} needs ${n}`);
    assert.ok(chain(id) <= 2, `${id} needs chain is ${chain(id)} deep`);
    assert.equal(read(id).front.requires_host, "[]", `${id} runs no host program: the pack's programs are an operator's acquisition tools`);
  }
});

test("each skill names the tools its front matter lists, and says what it does not show", () => {
  for (const id of IDS) {
    const { front, body } = read(id);
    for (const tool of list(front.tools ?? "[]")) assert.ok(body.includes(tool), `${id} lists ${tool} and does not name it`);
    for (const tool of ["cloudtrail_parse", "signin_analyse", "ual_parse"]) if (body.includes(tool)) assert.ok(list(front.tools).includes(tool), `${id} names ${tool} and does not list it`);
    assert.match(body, /\*\*Does not show:\*\*/, `${id} says what it does not show`);
  }
});

test("a skill whose tool can reach a secret says how it is run and what is never written", () => {
  for (const id of ["aws/cloudtrail", "entra/signins", "m365/unified-audit-log", "google/workspace", "identity/tokens"]) {
    const { body } = read(id);
    assert.match(body, /\*\*Sensitive output:\*\*/, id);
    assert.match(body, /secret_output: true/, `${id} says to run the job with secret_output: true`);
  }
  const tokens = read("identity/tokens").body;
  assert.match(tokens, /Do not authenticate with, replay, refresh or submit a recovered token/, "tokens: no replay of a recovered token");
  assert.match(tokens, /never its value, a fragment or a hash of a secret/);
  assert.match(tokens, /decoding does not validate a signature/);
});

test("the claims the review removed do not come back", () => {
  const all = IDS.map((id) => ({ id, ...read(id) }));
  const gone: Array<[RegExp, string]> = [
    [/four-hour window|a window in which the attacker/i, "an attacker access window computed from two administrative times"],
    [/single most common failure|none of those revoke/i, "tokens' unsupported opening"],
    [/equivalent of clearing the event log/i, "StopLogging as clearing the log"],
    [/first hour of an intrusion|shape of enumeration/i, "denials as the start of an intrusion"],
    [/the exfiltration (route|question)/i, "sharing or access as exfiltration"],
    [/every sign-in attempt|only on the business tiers/i, "an unsourced coverage rule"],
    [/enumerate/i, "live-access wording in an offline pack"],
    [/one log for every workload|a row per operation/i, "the unified audit log as complete and one row per action"],
    [/\b(30|thirty) minutes\b|\b180 days\b|\b90 days\b|seven days on Free/i, "a retention or delay figure no one supplied"],
    [/two-minute|one-hour intervals/i, "a fixed aggregation window stated as fact"],
    [/the tenant is (Google|Microsoft|AWS)\b/i, "a tenant label as a routing rule"],
    [/\brole_assumed_by\b/, "the old attribution field"],
    [/\bpwsh\b|\baws\b (CLI|configure|sts)/, "a host program this pack does not run"],
  ];
  for (const { id, text } of all) for (const [rx, what] of gone) assert.doesNotMatch(text, rx, `${id}: ${what}`);
  const signins = all.find((s) => s.id === "entra/signins")!.text;
  assert.doesNotMatch(signins, /50126[^.]*wrong password|50158[^.]*conditional access failure/i, "result codes are the provider's words, not a narrowed gloss");
});

test("the retention and delay figures are not in the README either, and the goal does not presume what it asks", () => {
  const readme = readFileSync(join(ROOT, "packs", "cloud-forensics", "README.md"), "utf8");
  assert.doesNotMatch(readme, /\b(180|90) days\b|seven days on Free|17 October 2023/i);
  const goal = readFileSync(join(ROOT, "packs", "cloud-forensics", "goals", "tenant-compromise.md"), "utf8");
  assert.doesNotMatch(goal, /the first sign-in that was not the user|what the\s+attacker still holds/i);
  assert.match(goal, /not established/);
  // The acceptance checks are not weakened: the five-event minimum and the revocation grep stay, and a check binds answer 6.
  assert.match(goal, /-ge 5/);
  assert.match(goal, /grep -qiE 'retention\|revok' work\/report\.md/);
  assert.match(goal, /awk '\/\^## 6\\\.\//);
});

test("pwsh and aws are said to be an operator's acquisition tools, in requires and not in a skill", () => {
  const host = JSON.parse(readFileSync(join(ROOT, "packs", "cloud-forensics", "requires", "host.json"), "utf8"));
  for (const b of host.binaries) {
    assert.match(b.why, /operator's acquisition/);
    assert.match(b.why, /never (passes|connects)|an agent never/);
  }
  const pack = JSON.parse(readFileSync(join(ROOT, "packs", "cloud-forensics", "pack.json"), "utf8"));
  assert.ok(pack.unreferenced_ok.some((e: { name: string; why: string }) => e.name === "pwsh" && /never connects to a tenant/.test(e.why)));
  assert.equal(pack.skills, 9);
});
