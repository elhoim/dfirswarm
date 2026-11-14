/**
 * A note's card (`card:` in its front matter) is what a seat is shown with the
 * result of a call that matches the note, whether or not it ever loads the note
 * (extensions/skills.ts, chooseCard). It is written as a few rules with their
 * argument forms, so it is held to the tools' manifests here: its size and its
 * number of sentences, the tools the note names exist and the card names one,
 * every argument form it writes belongs to one of them and every key of it is a
 * parameter that tool declares. And every hand-written card is reached: for
 * every run its pack can be in, a call is enumerated that brings it to a seat
 * that has seen nothing yet.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  CARD_MAX_CHARS,
  CARD_TOOL_SPREAD,
  cardForms,
  cardIndex,
  cardSentences,
  chooseCard,
  HAND_CARD_MAX,
  HAND_CARD_SENTENCES,
  readPackIndexes,
  readSkillFile,
  toolRules,
  type CardCall,
  type CardIndex,
  type CardNote,
} from "../extensions/skills.ts";

const ROOT = join(import.meta.dirname, "..");
const PACKS = join(ROOT, "packs");
const PACK_IDS = readdirSync(PACKS).filter((p) => existsSync(join(PACKS, p, "skills", "INDEX.md"))).sort();

type Param = { type?: string; description?: string; items?: unknown; properties?: unknown };
/** A tool's declared parameters, from the first pack that carries it (its own pack first). */
function params(pack: string, tool: string): Record<string, Param> | null {
  for (const p of [pack, ...PACK_IDS]) {
    const m = join(PACKS, p, "tools", tool, "manifest.json");
    if (existsSync(m)) return (JSON.parse(readFileSync(m, "utf8")) as { params?: Record<string, Param> }).params ?? {};
  }
  return null;
}
/** job_run's own arguments (extensions/agent-swarm.ts): a card may say how the job is run. */
const JOB_RUN = new Set(["command", "tool", "import", "args", "inputs", "timeout_seconds", "network", "profile", "wait_seconds", "lead", "net_grants", "independent", "programs", "secret_output"]);

/** The packs a run of `pack` carries: it and what it depends on. */
function closure(pack: string): string[] {
  const out = new Set<string>();
  const add = (p: string) => {
    if (out.has(p)) return;
    out.add(p);
    const deps = (JSON.parse(readFileSync(join(PACKS, p, "pack.json"), "utf8")) as { depends?: string[] }).depends ?? [];
    for (const d of deps) add(d.split(/[<>=!~ ]/)[0]!);
  };
  add(pack);
  return [...out].sort();
}

const indexes = new Map<string, Promise<CardIndex>>();
const indexOf = (packs: string[]) => {
  const k = packs.join(",");
  if (!indexes.has(k)) indexes.set(k, readPackIndexes(packs.map((p) => join(PACKS, p))).then((all) => cardIndex(all)));
  return indexes.get(k)!;
};

/** A form the card writes, made a call: each placeholder given its own words ("<SAM>" is SAM, "<flow log>" flow log). */
const filled = (v: unknown): unknown =>
  typeof v === "string" ? v.replace(/<([^<>]*)>/g, "$1") : Array.isArray(v) ? v.map(filled) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, filled(x)])) : v;
const call = (tool: string, args: Record<string, unknown> = {}): CardCall => ({ tool, programs: [], args, text: "", lead: null });

type Route = "its own argument form" | "the tool's first call" | "a lead it fits";
/** The call that brings a note's card to a seat that has seen nothing, and how; null when none of the three does. */
async function reach(index: CardIndex, n: CardNote): Promise<{ route: Route; call: CardCall; lead?: string } | null> {
  const fresh = new Set<string>();
  const none = () => false;
  const brings = (c: CardCall, lead = "") => {
    const got = chooseCard(index, c, fresh, none, lead);
    return got?.kind === "note" && got.note === n;
  };
  for (const t of n.tools) {
    for (const f of n.examples.get(t) ?? []) {
      const c = call(t, filled(f) as Record<string, unknown>);
      if (brings(c)) return { route: "its own argument form", call: c };
    }
  }
  for (const t of n.tools) if (brings(call(t))) return { route: "the tool's first call", call: call(t) };
  // A seat that works a lead about the note's subject: the lead says what the index's line for the note says.
  const when = (await readSkillFile(n.pack, n.id))?.when ?? "";
  for (const t of n.tools) if (brings(call(t), when)) return { route: "a lead it fits", call: call(t), lead: when };
  return null;
}

test("every hand-written card is short: at most HAND_CARD_MAX characters and HAND_CARD_SENTENCES sentences, and it names a tool of its note, which exists", async () => {
  const index = await indexOf(PACK_IDS);
  const hand = index.notes.filter((n) => n.hand);
  assert.ok(hand.length >= 200, `${hand.length} hand-written cards`);
  const long: string[] = [];
  for (const n of hand) {
    assert.ok(n.card.length <= CARD_MAX_CHARS);
    const sentences = cardSentences(n.card).length;
    if (n.card.length > HAND_CARD_MAX || sentences > HAND_CARD_SENTENCES) long.push(`${n.pack.id}:${n.id} (${n.card.length} characters, ${sentences} sentences)`);
    assert.ok(n.tools.length, `${n.pack.id}:${n.id}: a card is shown with a tool's result, and the note names no tool`);
    for (const t of n.tools) assert.ok(params(n.pack.id, t), `${n.pack.id}:${n.id}: names the tool ${t}, and no pack has it`);
    assert.ok(n.tools.some((t) => new RegExp(`(?<![A-Za-z0-9_])${t}(?![A-Za-z0-9_])`).test(n.card)), `${n.pack.id}:${n.id}: its card names none of its tools (${n.tools.join(", ")})`);
  }
  assert.deepEqual(long, [], `cards over ${HAND_CARD_MAX} characters or ${HAND_CARD_SENTENCES} sentences: keep the rules, cut the repetition`);
  const sorted = hand.map((n) => n.card.length).sort((a, b) => a - b);
  console.log(`# ${hand.length} hand cards; median ${sorted[Math.floor(sorted.length / 2)]} characters, longest ${sorted.at(-1)}`);
});

test("every argument form a card writes belongs to a tool its note names, and every key it gives is a parameter that tool declares", async () => {
  const index = await indexOf(PACK_IDS);
  const bad: string[] = [];
  for (const n of index.notes.filter((x) => x.hand)) {
    for (const { owner, form, text } of cardForms(n.card, n.tools)) {
      if (!owner) {
        bad.push(`${n.pack.id}:${n.id}: ${text.slice(0, 80)} is the form of no tool the note names (${n.tools.join(", ")})`);
        continue;
      }
      const declared = params(n.pack.id, owner) ?? {};
      for (const [k, v] of Object.entries(form)) {
        if (!Object.hasOwn(declared, k)) {
          bad.push(`${n.pack.id}:${n.id}: ${owner} ${text.slice(0, 80)} gives "${k}", which ${owner} does not declare`);
          continue;
        }
        // A key inside a parameter's value (the host of {"events": [{"host": ...}]}) is held to that parameter's own declaration.
        const own = JSON.stringify(declared[k]);
        const inner = new Set<string>();
        const walk = (x: unknown) => {
          if (Array.isArray(x)) x.forEach(walk);
          else if (x && typeof x === "object") {
            for (const [ik, iv] of Object.entries(x)) {
              inner.add(ik);
              walk(iv);
            }
          }
        };
        walk(v);
        for (const ik of inner) if (!new RegExp(`\\b${ik}\\b`).test(own)) bad.push(`${n.pack.id}:${n.id}: ${owner}'s ${k} is given a key "${ik}" its declaration does not name`);
      }
    }
    // A flag written plainly ("with secret_output: true", "hex: true") is a parameter of a tool named before it in its sentence, or job_run's.
    for (const s of cardSentences(n.card)) {
      for (const m of s.matchAll(/(?<!["\w])([a-z][a-z0-9]*_[a-z0-9_]+|hex|limit|offset|entry): (true|false|\d+)\b/g)) {
        const before = n.tools.filter((t) => s.slice(0, m.index).includes(t));
        if (JOB_RUN.has(m[1]!) || before.some((t) => Object.hasOwn(params(n.pack.id, t) ?? {}, m[1]!))) continue;
        bad.push(`${n.pack.id}:${n.id}: "${m[0]}" is no parameter of ${before.join(" or ") || "a tool named before it"}, nor of job_run`);
      }
    }
  }
  assert.deepEqual(bad, []);
});

test("every hand-written card is reached: in every run its pack is in, a call brings it to a seat that has seen nothing", async () => {
  const runs: Array<{ name: string; packs: string[]; own: string[] }> = [{ name: "every pack", packs: PACK_IDS, own: PACK_IDS }, ...PACK_IDS.map((p) => ({ name: p, packs: closure(p), own: [p] }))];
  const routes = new Map<string, number>();
  const unreached: string[] = [];
  let checked = 0;
  for (const run of runs) {
    const index = await indexOf(run.packs);
    for (const n of index.notes.filter((x) => x.hand && run.own.includes(x.pack.id))) {
      checked++;
      const r = await reach(index, n);
      if (!r) unreached.push(`${run.name}: ${n.pack.id}:${n.id} (${n.tools.join(", ")})`);
      else if (run.name === "every pack") routes.set(r.route, (routes.get(r.route) ?? 0) + 1);
    }
  }
  console.log(`# ${checked} card-runs checked; with every pack: ${[...routes].map(([k, v]) => `${v} by ${k}`).join(", ")}`);
  assert.deepEqual(unreached, []);
});

test("a tool more than CARD_TOOL_SPREAD notes name has rules of its own in every run: sentences of its notes' hand cards, never its description", async () => {
  const runs = [PACK_IDS, ...PACK_IDS.map(closure)];
  const none: string[] = [];
  let tools = 0;
  for (const packs of runs) {
    const index = await indexOf(packs);
    for (const [tool, notes] of index.byTool) {
      if (notes.length <= CARD_TOOL_SPREAD) continue;
      tools++;
      if (!toolRules(tool, notes)) none.push(`${packs.length === PACK_IDS.length ? "every pack" : packs.join("+")}: ${tool} (${notes.length} notes)`);
    }
  }
  assert.ok(tools >= 40, `${tools} tool-runs`);
  assert.deepEqual(none, [], "a tool many notes name and none of their cards states a rule of: write one in the card of the note that is its method");
});

test("a card is reached as a seat meets it: its own argument form brings it, another value of the kind it names does not, and the first call of a tool many notes name shows the rules they give", async () => {
  const index = await indexOf(PACK_IDS);
  const fresh = new Set<string>();
  const none = () => false;
  const note = (pack: string, id: string) => {
    const n = index.notes.find((x) => x.pack.id === pack && x.id === id);
    assert.ok(n, `${pack}:${id}`);
    return n;
  };
  const picked = (c: CardCall, ever: ReadonlySet<string> = fresh, holds: (k: string) => boolean = none, lead = "") => {
    const got = chooseCard(index, c, ever, holds, lead);
    return got?.kind === "note" ? got.note : got;
  };
  // cloud_normalise: thirteen notes, one a provider each.
  assert.equal(picked(call("cloud_normalise", { path: "inputs/audit/gcp.jsonl", provider: "gcp" })), note("cloud-forensics", "gcp/audit-logs"));
  assert.equal(picked(call("cloud_normalise", { path: "inputs/flow.log", provider: "aws_vpc" })), note("cloud-forensics", "aws/vpc-flow"));
  // regkv: nineteen notes; the hive and the key tell them apart.
  assert.equal(picked(call("regkv", { hive: "inputs/C/Windows/System32/config/SAM", key: "SAM\\Domains\\Account\\Users" })), note("windows-forensics", "accounts/logons"));
  assert.equal(picked(call("regkv", { hive: "inputs/C/Windows/System32/config/SYSTEM", key: "ControlSet001\\Control\\TimeZoneInformation" })), note("windows-forensics", "registry/clock"));
  // A user's hive is not the SOFTWARE hive the system-profile note writes, though its key holds the same words.
  assert.notEqual(picked(call("regkv", { hive: "inputs/C/Users/u/NTUSER.DAT", key: "Software\\Microsoft\\Windows NT\\CurrentVersion" })), note("windows-forensics", "registry/system-profile"));
  // A call that matches none: the rules the notes give of the tool, each a sentence of a hand card that names it; never a list of ids, never the manifest.
  for (const tool of ["regkv", "cloud_normalise", "pe_info", "evtx_query"]) {
    const got = chooseCard(index, call(tool, { path: "inputs/x" }), fresh, none);
    assert.equal(got?.kind, "rules", tool);
    if (got?.kind !== "rules") continue;
    assert.ok(got.notes.length > CARD_TOOL_SPREAD);
    const hand = index.notes.filter((n) => n.hand && n.tools.includes(tool));
    for (const s of cardSentences(got.text)) assert.ok(hand.some((n) => n.card.includes(s)), `${tool}: "${s}" is a rule of one of its notes`);
    assert.ok(got.text.length <= CARD_MAX_CHARS && cardSentences(got.text).length >= 2, `${tool}: ${got.text}`);
    // Once shown, a tool's first call is spent: the next call that matches no note brings nothing.
    assert.equal(chooseCard(index, call(tool, { path: "inputs/y" }), new Set([`tool:${tool}`]), none), null);
  }
  // A note the seat holds, or whose card it was shown, is not brought again.
  const gcp = note("cloud-forensics", "gcp/audit-logs");
  assert.equal(picked(call("cloud_normalise", { provider: "gcp" }), new Set(["tool:cloud_normalise", `note:${gcp.key}`])), null);
  assert.equal(picked(call("cloud_normalise", { provider: "gcp" }), new Set(["tool:cloud_normalise"]), (k) => k === gcp.key), null);
  // A command that runs a program a note names: the note it matches.
  assert.equal(picked({ tool: null, programs: ["capa"], args: {}, text: "capa -j inputs/sample.exe", lead: null }), note("reverse-engineering", "capabilities/mapping"));
});
