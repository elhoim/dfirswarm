/**
 * Skills: a run's packs as a seat meets them.
 *
 * A pack's method is a tree of small files (docs/packs.md, section 1). Four
 * things decide whether a seat uses it, and this module is all four:
 *
 * - The index is a section of the seat's system prompt. The kickoff renders it
 *   into `.pi/APPEND_SYSTEM.md` (scripts/seat-prompt.ts), which Pi puts in
 *   its own prompt sections for every run: a prompt section is checkpointed
 *   and replayed after a compaction, a tool result is not, and the summary of a
 *   compaction keeps 2,000 characters of one. It is not left to the forced
 *   prompt of `before_agent_start`: that prompt lasts for the run a user prompt
 *   starts, and the run a hand-off starts (a custom message, which has no
 *   `before_agent_start`) goes back to Pi's own sections (tests/skills-e2e.test.ts
 *   shows it through the real CLI). `promptSection` is the fallback for a prompt
 *   that does not carry the section. Measured on 458 seats: 88 % never called
 *   `skill` when the index only came back from `skill()`.
 * - The `skill` tool returns plain Markdown (no front matter, no JSON
 *   envelope), names the pack that served it, lists `needs` with their cost
 *   instead of loading them, and does not send a body the seat already holds.
 * - Every load is on the trace with the file's sha256 and its token count, so
 *   a report can say which version of which note a conclusion rests on.
 * - `skill_done(id, note)` says a seat is finished with a body. It marks the
 *   body releasable in the ledger below and records the event.
 * - The unloader replaces a finished body in the seat's context with a one-line
 *   stub ("<id> released (N tokens). Re-load with skill('<id>')."). It is a
 *   persisted `context_edit` draft returned from `turn_end` (Pi 0.87.1,
 *   dist/core/agent-session.js `_dispatchTurnEndBoundary`: the drafts are
 *   committed before the next request is built from the session's projection),
 *   so the raw tool result stays in the session file (custody and replay see
 *   what they always saw) and only what the model is sent changes. Which body
 *   leaves when depends on the model (`releaseClassOf`) and on `--skill-release`
 *   (`SWARM_SKILL_RELEASE`); `planRelease` holds the rules and docs/packs.md
 *   section 1 says why.
 *
 * The module knows no pack and no tool by name: it reads `skills/INDEX.md` and
 * `skills/<id>.md` of whatever `SWARM_PACK_DIRS` lists, and nothing else.
 */
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { ExtensionAPI, SessionBoundaryDraft } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

/** The estimator the pack lint will use: bytes per token over every shipped skill (o200k_base). */
export const BYTES_PER_TOKEN = 4.245;

/**
 * What the index may cost the seat that carries it, in estimated tokens: one
 * entry, one pack's index, the index of the whole run. Above the pack or the
 * run budget the prompt shows each pack's router only.
 */
export const SKILL_BUDGET = { entry: 40, pack: 1_000, run: 2_500 } as const;
export type SkillBudget = { entry: number; pack: number; run: number };

/** Bodies a seat may hold at once before the harness reminds it to finish one. */
export const MAX_LIVE_SKILLS = 3;

/**
 * What `--skill-release` (env `SWARM_SKILL_RELEASE`) says about the bodies a
 * seat has finished with:
 * - `compaction`, the default: bodies leave only when a seat hands off to itself
 *   (the turn its `self_compact` came back successfully, just before the
 *   compaction rewrites the prefix anyway), whatever the model. The summary
 *   input is shaped in this mode too;
 * - `auto`: a body marked done also leaves at the next turn boundary, on a
 *   model whose class says an edit of an earlier tool result is safe
 *   (`releaseClassOf`: the Responses family, or a model that does not reason),
 *   and when no signed thinking block comes after it. The experiment arm: a
 *   mid-run release does not pay back its cache write on a cache-priced
 *   provider before a context is cut (docs/packs.md), and nobody has measured
 *   what it buys in attention;
 * - `off`: nothing is released and the summary input is not shaped (the
 *   behaviour of a seat before the unloader existed).
 * An unknown value is `compaction`.
 */
export type ReleaseMode = "auto" | "compaction" | "off";
export const RELEASE_MODES: readonly ReleaseMode[] = ["auto", "compaction", "off"];
export const DEFAULT_RELEASE_MODE: ReleaseMode = "compaction";

export function parseReleaseMode(raw: string | undefined | null): ReleaseMode | null {
  const value = (raw ?? "").trim().toLowerCase();
  return (RELEASE_MODES as readonly string[]).includes(value) ? (value as ReleaseMode) : null;
}

/** First line of the section in the prompt; the tests and the audit look for it. */
export const SKILLS_SECTION_TITLE = "Skills carried by this run";

export function estimateTokens(text: string): number {
  const bytes = Buffer.byteLength(text, "utf8");
  return bytes === 0 ? 0 : Math.ceil(bytes / BYTES_PER_TOKEN);
}

function sha256Of(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// Packs and their indexes
// ---------------------------------------------------------------------------

export type PackRef = { id: string; version: string; dir: string; /** How many skills pack.json says the pack carries, when it says. */ declared?: number };
export type IndexEntry = { id: string; line: string; tokens: number };
export type PackIndex = PackRef & {
  entries: IndexEntry[];
  /** The skill the pack declares as its router (`Router:` line of INDEX.md), when it names one the index lists. */
  router: string | null;
  /**
   * The notes the pack names as its core (`Core:` line of INDEX.md: the ones
   * its cases reach for most), those the index lists, in its order: shown
   * beside the router, as the run's budget allows, when the index collapses.
   */
  core?: string[];
  /** Tokens of every entry line. */
  tokens: number;
  /** Why the pack's index could not be read, when it carries skills and it could not. */
  error?: string;
};

const PACK_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

export function packDirsFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.SWARM_PACK_DIRS || "").split(":").filter(Boolean);
}

export async function readPackRef(dir: string): Promise<PackRef> {
  let id = basename(dir);
  let version = "";
  let declared: number | undefined;
  try {
    const manifest = JSON.parse(await readFile(join(dir, "pack.json"), "utf8")) as { id?: unknown; version?: unknown; skills?: unknown };
    if (typeof manifest.id === "string" && PACK_ID.test(manifest.id)) id = manifest.id;
    if (typeof manifest.version === "string") version = manifest.version;
    if (typeof manifest.skills === "number" && Number.isInteger(manifest.skills)) declared = manifest.skills;
  } catch {
    // a pack directory without a readable manifest is still a directory of skills
  }
  return { id, version, dir, ...(declared !== undefined ? { declared } : {}) };
}

/** The entries of one INDEX.md, the router it names and its core notes. */
export function parseIndex(text: string): { entries: IndexEntry[]; router: string | null; core: string[] } {
  const entries: IndexEntry[] = [];
  let router: string | null = null;
  let core: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const entry = /^- `([^`]+)`/.exec(line);
    if (entry) {
      entries.push({ id: entry[1]!, line, tokens: estimateTokens(line) });
      continue;
    }
    const named = /^Router: `([^`]+)`\s*$/.exec(line);
    if (named) router = named[1]!;
    if (/^Core: /.test(line)) core = [...line.matchAll(/`([^`]+)`/g)].map((m) => m[1]!);
  }
  if (router && !entries.some((e) => e.id === router)) router = null;
  core = [...new Set(core)].filter((id) => id !== router && entries.some((e) => e.id === id));
  return { entries, router, core };
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

export async function readPackIndex(dir: string): Promise<PackIndex> {
  const ref = await readPackRef(dir);
  const out: PackIndex = { ...ref, entries: [], router: null, tokens: 0 };
  let text: string;
  try {
    text = await readFile(join(dir, "skills", "INDEX.md"), "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // A pack of tools or recipes alone has no skills directory and no index.
    if (code === "ENOENT" && !(await exists(join(dir, "skills")))) return out;
    out.error = code === "ENOENT" ? "skills/ has no INDEX.md" : `skills/INDEX.md cannot be read (${code ?? "error"})`;
    return out;
  }
  const parsed = parseIndex(text);
  out.entries = parsed.entries;
  out.router = parsed.router;
  if (parsed.core.length) out.core = parsed.core;
  out.tokens = parsed.entries.reduce((sum, e) => sum + e.tokens, 0);
  // An index that lists nothing for a pack that counts skills is a broken index, not a pack with none.
  if (parsed.entries.length === 0 && (out.declared ?? 0) > 0) out.error = `skills/INDEX.md lists no skill although pack.json counts ${out.declared}`;
  return out;
}

export async function readPackIndexes(dirs: string[]): Promise<PackIndex[]> {
  return Promise.all(dirs.map((dir) => readPackIndex(dir)));
}

/** Ids more than one pack of the run carries. */
export function collidingIds(packs: PackIndex[]): Set<string> {
  const seen = new Map<string, number>();
  for (const pack of packs) for (const id of new Set(pack.entries.map((e) => e.id))) seen.set(id, (seen.get(id) ?? 0) + 1);
  return new Set([...seen].filter(([, n]) => n > 1).map(([id]) => id));
}

/** `pack:id` where the bare id would be ambiguous, the entry line otherwise as the pack wrote it. */
function entryLine(pack: PackIndex, entry: IndexEntry, colliding: Set<string>): string {
  return colliding.has(entry.id) ? entry.line.replace(/^- `[^`]+`/, `- \`${pack.id}:${entry.id}\``) : entry.line;
}

// ---------------------------------------------------------------------------
// The section of the prompt
// ---------------------------------------------------------------------------

export type SectionReport = {
  /** Every pack's entries are in the section, or at least one pack shows its router only. */
  mode: "full" | "routers";
  packs: Array<{ id: string; version: string; skills: number; tokens: number; shown: "full" | "router"; router: string | null; core_shown?: string[] }>;
  /** Tokens of every entry of every pack, and of the entries the section carries. */
  index_tokens: number;
  shown_tokens: number;
  /** The whole section, with its words. */
  section_tokens: number;
  chars: number;
  sha256: string;
  budget: SkillBudget;
  /** A budget that was passed, in words: "pack x 1,200 > 1,000", "run 3,000 > 2,500". */
  over_budget: string[];
  /** Packs over budget that name no router, so they are shown in full. */
  no_router: string[];
  /** Entries over the entry budget, shown whole: the pack's seal refuses them, the prompt never cuts one. */
  long_entries: Array<{ pack: string; id: string; tokens: number }>;
  collisions: string[];
  /** Packs whose index could not be read. */
  unreadable: Array<{ pack: string; reason: string }>;
};

const fmt = (n: number) => n.toLocaleString("en-US");

/**
 * The Skills section of a seat's system prompt, from the packs' indexes.
 *
 * Within budget every entry is shown, as the pack's own INDEX.md line. A pack
 * whose entries pass the pack budget shows its router only; when the run's
 * entries still pass the run budget, every pack that names a router does. A
 * pack with no router cannot be shortened and is shown whole (the report says
 * so): the section never cuts an entry, and `skill()` with no id lists them all.
 */
export function renderSkillsSection(packs: PackIndex[], budget: SkillBudget = SKILL_BUDGET): { text: string; report: SectionReport } {
  const live = packs.filter((p) => p.entries.length > 0);
  const colliding = collidingIds(live);
  const shown = new Map<string, "full" | "router">(live.map((p) => [p.id, "full"]));
  const overBudget: string[] = [];
  const cost = () => live.reduce((sum, p) => sum + (shown.get(p.id) === "router" ? p.entries.find((e) => e.id === p.router)!.tokens : p.tokens), 0);
  const indexTokens = live.reduce((sum, p) => sum + p.tokens, 0);

  for (const p of live) {
    if (p.tokens > budget.pack) {
      overBudget.push(`pack ${p.id} ${fmt(p.tokens)} > ${fmt(budget.pack)}`);
      if (p.router) shown.set(p.id, "router");
    }
  }
  const runOver = cost() > budget.run;
  if (runOver) {
    overBudget.push(`run ${fmt(indexTokens)} > ${fmt(budget.run)}`);
    for (const p of live) if (p.router) shown.set(p.id, "router");
  }
  // Graded, not all or nothing: beside each collapsed pack's router, the notes it names as its core, one pack's at a time in turn, while
  // the run's budget (and the pack's) has room. A pack that names none shows its router only, as before.
  const beside = new Map<string, IndexEntry[]>();
  const besideTokens = () => [...beside.values()].flat().reduce((sum, e) => sum + e.tokens, 0);
  const packShown = (p: PackIndex) => p.entries.find((e) => e.id === p.router)!.tokens + (beside.get(p.id) ?? []).reduce((sum, e) => sum + e.tokens, 0);
  const queues = live.filter((p) => shown.get(p.id) === "router" && p.core?.length).map((p) => ({ p, ids: [...p.core!] }));
  for (let added = true; added; ) {
    added = false;
    for (const q of queues) {
      const id = q.ids.shift();
      if (!id) continue;
      const entry = q.p.entries.find((e) => e.id === id)!;
      if (cost() + besideTokens() + entry.tokens > budget.run || packShown(q.p) + entry.tokens > budget.pack) {
        q.ids.length = 0;
        continue;
      }
      beside.set(q.p.id, [...(beside.get(q.p.id) ?? []), entry]);
      added = true;
    }
  }
  // A pack that was part of the overrun and names no router: nothing to shorten it to.
  const noRouter = live.filter((p) => !p.router && (p.tokens > budget.pack || runOver)).map((p) => p.id);
  const collapsed = live.some((p) => shown.get(p.id) === "router");

  const lines: string[] = [SKILLS_SECTION_TITLE, ""];
  lines.push(
    "The packs this run was started with carry method notes. Below is their index: one line per skill, what it is for and when to reach for it. " +
      'Load a body with skill(id) before you work that kind of artefact ("Skills" above says how). A skill more than one pack carries is listed as pack:id.',
  );
  if (collapsed) {
    lines.push(
      `This index is over its budget (${fmt(indexTokens)} tokens of entries; ${fmt(budget.pack)} a pack, ${fmt(budget.run)} the run), so a pack marked "router only" shows the one note that routes to the rest: load it and it names the notes under it. A pack marked "router and N core notes" shows beside its router the notes it names as its core, as the budget allows. skill() with no id lists every skill of every pack.`,
    );
  }
  let shownTokens = 0;
  for (const p of live) {
    const router = shown.get(p.id) === "router";
    const core = new Set((beside.get(p.id) ?? []).map((e) => e.id));
    lines.push("");
    lines.push(`${p.id}${p.version ? ` ${p.version}` : ""} (${p.entries.length} skill${p.entries.length === 1 ? "" : "s"}${router ? (core.size ? `, router and ${core.size} core note${core.size === 1 ? "" : "s"}` : ", router only") : ""})`);
    for (const entry of p.entries) {
      if (router && entry.id !== p.router && !core.has(entry.id)) continue;
      lines.push(entryLine(p, entry, colliding));
      shownTokens += entry.tokens;
    }
  }
  const text = live.length ? lines.join("\n") : "";
  const report: SectionReport = {
    mode: collapsed ? "routers" : "full",
    packs: live.map((p) => ({ id: p.id, version: p.version, skills: p.entries.length, tokens: p.tokens, shown: shown.get(p.id)!, router: p.router, ...(beside.get(p.id)?.length ? { core_shown: beside.get(p.id)!.map((e) => e.id) } : {}) })),
    index_tokens: indexTokens,
    shown_tokens: shownTokens,
    section_tokens: estimateTokens(text),
    chars: text.length,
    sha256: sha256Of(text),
    budget,
    over_budget: overBudget,
    no_router: noRouter,
    long_entries: live.flatMap((p) => p.entries.filter((e) => e.tokens > budget.entry).map((e) => ({ pack: p.id, id: e.id, tokens: e.tokens }))),
    collisions: [...colliding].sort(),
    unreadable: packs.filter((p) => p.error).map((p) => ({ pack: p.id, reason: p.error! })),
  };
  return { text, report };
}

/** Every entry of every pack, whole: what `skill()` with no id answers when the prompt shows routers only. */
export function renderFullIndex(packs: PackIndex[]): string {
  const live = packs.filter((p) => p.entries.length > 0);
  if (!live.length) return "The packs carry no skills.";
  const colliding = collidingIds(live);
  const out: string[] = [];
  for (const p of live) {
    out.push(`${p.id}${p.version ? ` ${p.version}` : ""} (${p.entries.length} skill${p.entries.length === 1 ? "" : "s"})`);
    for (const entry of p.entries) out.push(entryLine(p, entry, colliding));
    out.push("");
  }
  return out.join("\n").trimEnd();
}

// ---------------------------------------------------------------------------
// A skill file
// ---------------------------------------------------------------------------

export type SkillMeta = Record<string, string | string[]>;

/** The front matter pack.sh validates, and the body after it. A file without front matter is all body. */
export function splitSkill(text: string): { meta: SkillMeta; body: string } {
  // pack.sh reads a file with universal newlines, so a CRLF skill seals; its front matter has to strip all the same.
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
  if (!m) return { meta: {}, body: text.trim() };
  const meta: SkillMeta = {};
  for (const line of m[1]!.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#") || !line.includes(":")) continue;
    const at = line.indexOf(":");
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    meta[key] = value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : value;
  }
  return { meta, body: text.slice(m[0].length).trim() };
}

function listOf(value: string | string[] | undefined): string[] {
  return Array.isArray(value) ? value : value ? [value] : [];
}

export type SkillFile = {
  pack: PackRef;
  id: string;
  title: string;
  /** sha256 of the file as the pack ships it, the number pack.json's checksums carry. */
  sha256: string;
  bytes: number;
  /** What the seat receives: the body without front matter. */
  body: string;
  tokens: number;
  needs: string[];
  tools: string[];
  /** The host programs its commands run (`requires_host:`): a command that runs one is a call of the note too. */
  programs: string[];
  /** Its `when:` line: what work it is for. */
  when: string;
  /** The note's own card (`card:` in its front matter), when it writes one: what a seat is shown when it calls one of the note's tools without holding it. */
  card: string | null;
};

const SKILL_ID = /^[a-z0-9][a-z0-9_/-]{0,127}$/;

export async function readSkillFile(pack: PackRef, id: string): Promise<SkillFile | null> {
  let raw: Buffer;
  try {
    raw = await readFile(join(pack.dir, "skills", `${id}.md`));
  } catch {
    return null;
  }
  const { meta, body } = splitSkill(raw.toString("utf8"));
  return {
    pack,
    id,
    title: typeof meta.title === "string" ? meta.title : "",
    sha256: sha256Of(raw),
    bytes: raw.length,
    body,
    tokens: estimateTokens(body),
    needs: listOf(meta.needs),
    tools: listOf(meta.tools),
    programs: listOf(meta.requires_host),
    when: typeof meta.when === "string" ? meta.when : "",
    card: typeof meta.card === "string" && meta.card.trim() ? meta.card.trim() : null,
  };
}

// ---------------------------------------------------------------------------
// Cards: a note's rules where its tool is called
// ---------------------------------------------------------------------------

/**
 * A card is a note's few lines a seat must not miss, shown with the result of a
 * call to one of the tools the note names (`tools:`), or of a command that runs
 * one of its programs (`requires_host:`), when the seat does not hold the note:
 * the method comes to the call instead of waiting to be asked for. Pull alone
 * did not reach the open models of the runs of one case: 5 of 8 seats of the
 * run sf4406b never loaded a note, and 5 of its 55 pack-tool calls (9 %) came
 * from a seat that held the tool's note (48 of 65, 74 %, on a Codex run). Its
 * ad1_extract errors were what evidence/ad1 says.
 *
 * Which note's card a call brings is the note the call matches (`matchCard`):
 * the argument forms its card writes for that tool (a provider, a source, a
 * hive, a key), the words of the arguments the call gives, and the lead the
 * seat works under. A tool many notes name (regkv, cloud_normalise, pe_info)
 * shows each note's card on the call that matches it, so every note with a card
 * has a call that reaches it. A call that matches no one note shows, on the
 * tool's first call, the most specific note's card when at most
 * CARD_TOOL_SPREAD notes name the tool, else the rules its notes give of it
 * (`toolRules`). Each card once in the run for a seat, a relaunch included.
 * `--skill-cards off` (SWARM_SKILL_CARDS) turns them off.
 */
export const CARD_MAX_CHARS = 700;
/**
 * A hand-written card (`card:`) is at most this long, and at most HAND_CARD_SENTENCES sentences: two or three rules with their
 * argument forms, and what the tool does not show. Hand cards ran a median of 4 sentences and 445 characters.
 */
export const HAND_CARD_MAX = 400;
export const HAND_CARD_SENTENCES = 4;
/** A tool more notes than this name has no one method: a call that matches none of them shows the rules its notes give of it. */
export const CARD_TOOL_SPREAD = 3;
/** The hand-off's skills line is at most this long: the notes read, the cards of the notes and tools the seat worked with, whole. */
export const HANDOFF_SKILLS_MAX = 800;
/** The session entry that keeps what cards a seat was shown (`registerSkills`). */
export const CARDS_STATE_TYPE = "dfirswarm-skill-cards";
/** The cards state a session's branch keeps: its last entry of CARDS_STATE_TYPE, or nothing. */
export function cardsStateOf(entries: readonly unknown[]): { ever: string[]; held: Array<[string, string]> } | null {
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i] as { type?: string; customType?: string; data?: { version?: number; ever?: unknown; held?: unknown } } | null;
    if (e?.type !== "custom" || e.customType !== CARDS_STATE_TYPE || e.data?.version !== 1) continue;
    const ever = Array.isArray(e.data.ever) ? e.data.ever.filter((x): x is string => typeof x === "string") : [];
    const held = Array.isArray(e.data.held) ? e.data.held.filter((x): x is [string, string] => Array.isArray(x) && typeof x[0] === "string" && typeof x[1] === "string") : [];
    return { ever, held };
  }
  return null;
}
export type CardsMode = "on" | "off" | "inject";
export function parseCardsMode(raw: string | undefined): CardsMode {
  const v = raw?.trim().toLowerCase();
  // inject: as on, and a lead that is opened or claimed comes back with the rules of the notes that fit it, not their
  // names (the forced arm of the notes experiment: do the rules change what a seat does when they are in front of it?).
  return v === "off" ? "off" : v === "inject" ? "inject" : "on";
}

/** A card cut at a sentence within `max` characters. */
function cutCard(t: string, max = CARD_MAX_CHARS): string {
  if (t.length <= max) return t;
  const head = t.slice(0, max);
  const end = Math.max(head.lastIndexOf(". "), head.lastIndexOf(".\n"));
  return `${(end > max / 2 ? head.slice(0, end + 1) : head).trimEnd()} …`;
}

/**
 * A note's card: its own `card:` when it writes one; else, from its body, the
 * paragraph that says when to use it, its first example call (an indented
 * block, three lines at most) and what it does not show. Cut at a sentence
 * within CARD_MAX_CHARS.
 */
export function skillCard(file: Pick<SkillFile, "title" | "body" | "card">): string {
  if (file.card) return cutCard(file.card);
  const paras = file.body.split(/\n\s*\n/).map((p) => p.replace(/\s+$/, "")).filter((p) => p.trim());
  const out: string[] = [];
  if (file.title) out.push(file.title.endsWith(".") ? file.title : `${file.title}.`);
  const use = paras.find((p) => /^Use when\b/.test(p.trim()));
  if (use) out.push(use.trim().replace(/\s*\n\s*/g, " "));
  const example = paras.find((p) => p.split("\n").every((l) => /^( {4}|\t)/.test(l)));
  if (example) out.push(example.split("\n").slice(0, 3).map((l) => `    ${l.trim()}`).join("\n"));
  const limit = paras.find((p) => /^\*\*Does not show\.?\*\*/.test(p.trim()));
  if (limit) out.push(limit.trim().replace(/\s*\n\s*/g, " "));
  return cutCard(out.join("\n"));
}

/**
 * A tool's card from its own manifest, for a tool no note names: the part of its description past the first sentence
 * (SWARM.md already carries the first), cut at a sentence within CARD_MAX_CHARS. Null for a forged tool (its maker
 * wrote it this run), a manifest that cannot be read, or a description of one sentence.
 */
export async function manifestCard(sandboxRoot: string, tool: string): Promise<string | null> {
  if (!/^[a-z0-9_]{1,64}$/.test(tool)) return null;
  try {
    const m = JSON.parse(await readFile(join(sandboxRoot, "tools", tool, "manifest.json"), "utf8")) as { description?: unknown };
    const text = typeof m.description === "string" ? m.description.replace(/\s+/g, " ").trim() : "";
    const first = /^.*?[.!?](?=\s|$)/.exec(text)?.[0] ?? text;
    const rest = text.slice(first.length).trim();
    if (rest.length < 80) return null;
    return cutCard(rest);
  } catch {
    return null;
  }
}

const NOTE_STOP = new Set("the a an and or of to in on for from with by is are was were be it its this that what which when where how who why answer question find recover lead work data file files evidence image case".split(" "));
const noteWords = (t: string): string[] => [...new Set(t.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !NOTE_STOP.has(w)))];
/** Words a call's arguments share with every run (a run's own directories, a placeholder's filler): they tell no note apart. */
const CALL_STOP = new Set([..."inputs input work store jobs job out your name names path paths dir directory folder tree root json jsonl txt csv log logs tmp out_dir one each not all any".split(" ")]);
/** The words of a text as the cards compare them: lower case, three letters or more, no stop word. */
export const cardWords = (t: string): string[] => noteWords(t).filter((w) => !CALL_STOP.has(w));

/**
 * The notes of the run's packs that fit a piece of work, by the words its title and reason share with a note's id,
 * title and "when" line: at most `n`, the best first, each sharing at least two words. For a lead a seat opens or
 * claims: the notes reached the open-weight seats only after a tool was called (a card), and a seat that never calls
 * the tool never sees its note. A router is never offered (it is in the prompt).
 */
export function notesForText(packs: readonly PackIndex[], text: string, n = 3): Array<{ ref: string; when: string; score: number; pack: string; id: string }> {
  const want = new Set(noteWords(text));
  if (want.size < 2) return [];
  const ids = new Map<string, number>();
  for (const p of packs) for (const e of p.entries) ids.set(e.id, (ids.get(e.id) ?? 0) + 1);
  const out: Array<{ ref: string; when: string; score: number; pack: string; id: string }> = [];
  for (const p of packs) {
    for (const e of p.entries) {
      if (e.id === p.router) continue;
      // An index line is the note's id and when it applies.
      const when = e.line.replace(/^[-*\s]*/, "").replace(e.id, "").replace(/^[`:\s—-]+/, "").trim();
      const have = noteWords(`${e.id.replace(/[/_-]/g, " ")} ${when}`);
      const score = have.filter((w) => want.has(w)).length;
      if (score >= 2) out.push({ ref: (ids.get(e.id) ?? 0) > 1 ? `${p.id}:${e.id}` : e.id, when, score, pack: p.id, id: e.id });
    }
  }
  return out.sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref)).slice(0, n);
}

/** A call as the cards read it: a tool and its arguments, or a command and the programs it runs; and the lead it names. */
export type CardCall = { tool: string | null; programs: string[]; args: Record<string, unknown>; text: string; lead: string | null };

const isRecord = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);

/** What runs a command line's programs and is not one of them. */
const WRAPPERS = new Set(["sudo", "env", "time", "nice", "nohup", "exec", "command", "timeout", "stdbuf", "xargs", "then", "do", "else", "if", "while", "!"]);

/** The programs a command line runs: the first word of each of its commands, by its base name, and the script or module a Python runs. */
export function commandPrograms(cmd: string): string[] {
  const out: string[] = [];
  const bare = (w: string) => w.replace(/^['"]+|['"]+$/g, "").split("/").pop() ?? "";
  for (const seg of cmd.split(/\|\||&&|\$\(|[;|&\n(){}`]/)) {
    const words = seg.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < words.length) {
      const w = words[i]!;
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) i++;
      else if (WRAPPERS.has(w)) {
        i++;
        // Its options, an option's value (timeout -s KILL) and a duration.
        while (i < words.length && (/^-/.test(words[i]!) || /^\d+(\.\d+)?[smhd]?$/.test(words[i]!) || (/^-\w$/.test(words[i - 1]!) && /^[A-Z0-9]+$/.test(words[i]!)))) i++;
      } else break;
    }
    if (i >= words.length) continue;
    const prog = bare(words[i]!);
    if (!prog || !/^[A-Za-z0-9_.+-]{1,64}$/.test(prog)) continue;
    out.push(prog);
    if (/^python[0-9.]*$/.test(prog)) {
      const next = words[i + 1];
      if (next === "-m" && words[i + 2]) out.push(bare(words[i + 2]!));
      else if (next && /\.py['"]?$/.test(next)) out.push(bare(next));
    }
  }
  return [...new Set(out)];
}

/** The call a tool's result is of: null for the skill tools, and for a job that runs neither a tool nor a command. */
export function cardCallOf(name: string, input: Record<string, unknown> | undefined): CardCall | null {
  if (!name || name === "skill" || name === "skill_done") return null;
  const lead = typeof input?.lead === "string" && input.lead.trim() ? input.lead.trim() : null;
  if (name === "job_run") {
    if (typeof input?.tool === "string" && input.tool.trim()) return { tool: input.tool.trim(), programs: [], args: isRecord(input.args) ? input.args : {}, text: "", lead };
    if (typeof input?.command === "string" && input.command.trim()) return { tool: null, programs: commandPrograms(input.command), args: {}, text: input.command, lead };
    return null;
  }
  if (name === "bash") return typeof input?.command === "string" && input.command.trim() ? { tool: null, programs: commandPrograms(input.command), args: {}, text: input.command, lead: null } : null;
  return { tool: name, programs: [], args: input ?? {}, text: "", lead: null };
}

/** The [start, end) of each JSON object a text writes, outermost only (a brace inside a quoted string is text). */
function objectSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let depth = 0;
  let start = -1;
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === "\\") i++;
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === '"' && depth > 0) quoted = true;
    else if (c === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}" && depth > 0) {
      depth--;
      if (depth === 0) spans.push([start, i + 1]);
    }
  }
  return spans;
}

/**
 * An argument form a card writes, as an object: JSON, with a bare placeholder (<n>) taken as a string and an elided list
 * ([...]) as empty; else the key-value pairs at its top level that are written plainly. Null when it writes none.
 */
export function cardObject(text: string): Record<string, unknown> | null {
  const t = text.replace(/\[\s*(?:\.\.\.|…)\s*\]/g, "[]").replace(/([:[,]\s*)<([^<>"\n]{1,80})>/g, '$1"<$2>"');
  try {
    const v = JSON.parse(t) as unknown;
    if (isRecord(v)) return v;
  } catch {
    // not JSON as it stands: its plain pairs below
  }
  const out: Record<string, unknown> = {};
  let depth = 0;
  for (let i = 0; i < t.length; i++) {
    const c = t[i]!;
    if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") depth--;
    else if (c === '"' && depth === 1) {
      const m = /^"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*("(?:[^"\\]|\\.)*"|true|false|-?\d+(?:\.\d+)?)/.exec(t.slice(i));
      if (m) {
        try {
          out[m[1]!] = JSON.parse(m[2]!);
        } catch {
          out[m[1]!] = m[2]!;
        }
        i += m[0].length - 1;
      } else {
        const skip = /^"(?:[^"\\]|\\.)*"/.exec(t.slice(i));
        if (skip) i += skip[0].length - 1;
      }
    }
  }
  return Object.keys(out).length ? out : null;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const mentionRe = (name: string) => new RegExp(`(?<![A-Za-z0-9_])${escapeRe(name)}(?![A-Za-z0-9_])`, "g");

/** A card's sentences: split after a full stop that ends a sentence, never inside an argument form. */
export function cardSentences(card: string): string[] {
  const spans = objectSpans(card);
  const out: string[] = [];
  let from = 0;
  for (const m of card.matchAll(/[.!?]\s+(?=\S)/g)) {
    const at = m.index! + 1;
    if (spans.some(([a, b]) => at > a && at < b)) continue;
    // An abbreviation's full stop ends no sentence.
    if (/(?:\b(?:e\.g|i\.e|etc|vs|cf|approx|no)|\.\.)\.$/i.test(card.slice(Math.max(0, at - 8), at))) continue;
    out.push(card.slice(from, at).trim());
    from = at;
  }
  out.push(card.slice(from).trim());
  return out.filter(Boolean);
}

/**
 * The argument forms a card writes, each with the tool it is a form of: the nearest of `names` (the note's tools)
 * written before it outside any form, else the first one after it in the same sentence; null when none is. `text` is
 * the form as written.
 */
export function cardForms(card: string, names: readonly string[]): Array<{ owner: string | null; form: Record<string, unknown>; text: string }> {
  const spans = objectSpans(card);
  const inside = (at: number) => spans.some(([a, b]) => at >= a && at < b);
  const mentions: Array<{ at: number; name: string }> = [];
  for (const name of names) for (const m of card.matchAll(mentionRe(name))) if (!inside(m.index!)) mentions.push({ at: m.index!, name });
  mentions.sort((a, b) => a.at - b.at);
  const out: Array<{ owner: string | null; form: Record<string, unknown>; text: string }> = [];
  for (const [a, b] of spans) {
    const form = cardObject(card.slice(a, b));
    if (!form) continue;
    let owner = mentions.filter((m) => m.at < a).pop()?.name ?? null;
    if (!owner) {
      const end = /[.!?](\s|$)/.exec(card.slice(b))?.index;
      owner = mentions.find((m) => m.at > b && (end === undefined || m.at < b + end))?.name ?? null;
    }
    out.push({ owner, form, text: card.slice(a, b) });
  }
  return out;
}

/** The argument forms a card writes, by the tool each is a form of (cardForms); a form no name owns is left out. */
export function cardExamples(card: string, names: readonly string[]): Map<string, Array<Record<string, unknown>>> {
  const out = new Map<string, Array<Record<string, unknown>>>();
  for (const { owner, form } of cardForms(card, names)) if (owner) out.set(owner, [...(out.get(owner) ?? []), form]);
  return out;
}

/** A note as the cards choose among them. */
export type CardNote = {
  pack: PackRef;
  id: string;
  /** SkillLedger.key of the note; `ref` is how a seat names it (pack:id where two packs of the run carry the id). */
  key: string;
  ref: string;
  tools: string[];
  programs: string[];
  card: string;
  /** Its card is its own `card:` line, not one taken from its body. */
  hand: boolean;
  examples: Map<string, Array<Record<string, unknown>>>;
  /** Words of its id, title and when line: what a lead about its subject shares with it. */
  about: Set<string>;
  /** Words of its whole text (title, when line, body, card): what tells a word common to a tool's notes from one of its own. */
  words: Set<string>;
};
export type CardIndex = { notes: CardNote[]; byTool: Map<string, CardNote[]>; byProgram: Map<string, CardNote[]> };

/** Every note of the run's packs that names a tool or a program, by each name, the most specific (fewest names) first. */
export async function cardIndex(packs: readonly PackIndex[]): Promise<CardIndex> {
  const ids = new Map<string, number>();
  for (const p of packs) for (const e of p.entries) ids.set(e.id, (ids.get(e.id) ?? 0) + 1);
  const notes: CardNote[] = [];
  for (const pack of packs) {
    for (const entry of pack.entries) {
      const file = await readSkillFile(pack, entry.id);
      if (!file || (!file.tools.length && !file.programs.length)) continue;
      const card = skillCard(file);
      notes.push({
        pack,
        id: entry.id,
        key: SkillLedger.key(pack.id, entry.id),
        ref: (ids.get(entry.id) ?? 0) > 1 ? `${pack.id}:${entry.id}` : entry.id,
        tools: file.tools,
        programs: file.programs,
        card,
        hand: Boolean(file.card),
        examples: cardExamples(card, file.tools),
        about: new Set(cardWords(`${entry.id.replace(/[/_-]/g, " ")} ${file.title} ${file.when}`)),
        words: new Set(cardWords(`${file.title} ${file.when} ${file.body} ${card}`)),
      });
    }
  }
  const byTool = new Map<string, CardNote[]>();
  const byProgram = new Map<string, CardNote[]>();
  for (const n of notes) {
    for (const t of n.tools) byTool.set(t, [...(byTool.get(t) ?? []), n]);
    for (const p of n.programs) byProgram.set(p, [...(byProgram.get(p) ?? []), n]);
  }
  for (const map of [byTool, byProgram]) for (const list of map.values()) list.sort((a, b) => a.tools.length + a.programs.length - (b.tools.length + b.programs.length) || a.id.localeCompare(b.id) || a.pack.id.localeCompare(b.pack.id));
  return { notes, byTool, byProgram };
}

/** Every string a value holds, keys left out. */
function stringsOf(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) stringsOf(x, out);
  else if (isRecord(v)) for (const x of Object.values(v)) stringsOf(x, out);
  return out;
}

const placeholder = (v: unknown) => typeof v === "string" && /<[^<>]*>|\.\.\.|…|\{OUT\}|\$OUT/.test(v);
/** A value that names a kind (a provider, a source, a format): one token. A call that gives another one is not that note's. */
const kindValue = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_.:+-]{1,40}$/.test(v) && !placeholder(v);
const same = (a: unknown, b: unknown): boolean => {
  if (Array.isArray(b)) return b.every((x) => (Array.isArray(a) ? a : [a]).some((y) => same(y, x)));
  if (typeof b === "string") return typeof a === "string" && a.trim().toLowerCase() === b.toLowerCase();
  return String(a) === String(b);
};

/** How a call and a note's card agree: the pairs it gives as the card writes them, its words in the card's forms, and the lead's in the note's subject. */
type Agreement = { pairs: string[]; words: string[]; lead: string[] };

/** A value the card itself writes as one to give ("try \"hidden\" and \"backup\" separately"): a call that gives it is not another kind. */
const cardNamesValue = (card: string, v: unknown): boolean => kindValue(v) && new RegExp(`"${escapeRe(v)}"`, "i").test(card);

function agreement(note: CardNote, call: CardCall, name: string, callWords: Set<string>, leadWords: Set<string>, common: (w: string) => boolean): Agreement | null {
  const forms = call.tool ? (note.examples.get(name) ?? []) : [];
  // A form the call contradicts (it gives another value of a kind the form names, and one the card does not name) is not
  // the call's; a note whose every form is contradicted is not either.
  const kept = forms.filter((f) => !Object.entries(f).some(([k, v]) => kindValue(v) && call.args[k] !== undefined && !same(call.args[k], v) && !cardNamesValue(note.card, call.args[k])));
  if (forms.length && !kept.length) return null;
  const pairs = new Set<string>();
  const words = new Set<string>();
  for (const f of kept) {
    // Words count argument by argument: the call's hive against the form's hive. A form whose one-word placeholder the
    // call's value does not hold (<SOFTWARE> for an NTUSER.DAT) is about another file, and its words count for nothing.
    const agreed = new Set<string>();
    let other = false;
    for (const [k, v] of Object.entries(f)) {
      if (call.args[k] === undefined) continue;
      if (!placeholder(v) && (typeof v !== "object" || Array.isArray(v)) && same(call.args[k], v)) pairs.add(`${k}=${JSON.stringify(v)}`);
      const formWords = cardWords(stringsOf(v).join(" "));
      const given = new Set(cardWords(stringsOf(call.args[k]).join(" ")));
      const shared = formWords.filter((w) => given.has(w));
      // Only a word of the form's own: a hive's name, Microsoft, CurrentVersion, ControlSet00n are in the keys of many
      // notes of the tool and tell none of them apart.
      for (const w of shared) if (!common(w)) agreed.add(w);
      if (!shared.length && formWords.length && given.size && typeof v === "string" && /^<[^<>\s]+>$/.test(v)) other = true;
    }
    if (!other) for (const w of agreed) words.add(w);
  }
  // A command writes no argument form: its words are read against the note's subject.
  const cmd = call.tool ? [] : [...callWords].filter((w) => note.about.has(w));
  return { pairs: [...pairs], words: call.tool ? [...words] : cmd, lead: [...leadWords].filter((w) => note.about.has(w)) };
}

/**
 * The words common to the notes that name a tool: a word more than a quarter of them hold (and at least three) in their
 * title, when line, body or card is a path segment or a term of the tool's whole domain (a hive's name, Microsoft,
 * Windows, CurrentVersion, ControlSet00n, Control, Software for regkv), not of one note's form.
 */
export function commonWords(notes: readonly CardNote[]): (w: string) => boolean {
  const bound = Math.max(2, notes.length / 4);
  const df = new Map<string, number>();
  for (const n of notes) for (const w of n.words ?? []) df.set(w, (df.get(w) ?? 0) + 1);
  return (w) => (df.get(w) ?? 0) > bound;
}

/**
 * The note a call matches, among the notes that name its tool (or the program its command runs): the call gives a value
 * a note's card writes for that tool (3 a pair), a word of its arguments that the card's forms hold and that is the
 * form's own, not common to the tool's notes (commonWords; 2 a word), or works a lead whose words the note's subject
 * holds (1 a word). What most of the notes share tells none apart: a pair or a word counts only when at most half of them
 * have it. The note matches with 2 or more, strictly more than any other. `fit` is every note the call does not
 * contradict (a provider another than the one a note's every form names, and its card does not name).
 */
export function matchCard(call: CardCall, name: string, notes: readonly CardNote[], leadText = ""): { best: CardNote | null; score: number; by: "args" | "lead" | null; fit: CardNote[] } {
  const callWords = new Set(cardWords(call.tool ? stringsOf(call.args).join(" ") : call.text));
  const leadWords = new Set(cardWords(leadText));
  const common = commonWords(notes);
  const rows: Array<{ note: CardNote; a: Agreement }> = [];
  for (const note of notes) {
    const a = agreement(note, call, name, callWords, leadWords, common);
    if (a) rows.push({ note, a });
  }
  const fit = rows.map((r) => r.note);
  const limit = Math.max(1, Math.floor(rows.length / 2));
  const count = (pick: (a: Agreement) => string[]) => {
    const c = new Map<string, number>();
    for (const r of rows) for (const x of pick(r.a)) c.set(x, (c.get(x) ?? 0) + 1);
    return (x: string) => (c.get(x) ?? 0) <= limit;
  };
  const rare = { pairs: count((a) => a.pairs), words: count((a) => a.words), lead: count((a) => a.lead) };
  const scored = rows
    .map((r) => {
      const args = 3 * r.a.pairs.filter(rare.pairs).length + 2 * r.a.words.filter(rare.words).length;
      const lead = r.a.lead.filter(rare.lead).length;
      return { note: r.note, score: args + lead, by: (args >= lead ? "args" : "lead") as "args" | "lead" };
    })
    .sort((a, b) => b.score - a.score);
  const [first, second] = scored;
  if (!first || first.score < 2 || (second && second.score === first.score)) return { best: null, score: first?.score ?? 0, by: null, fit };
  return { best: first.note, score: first.score, by: first.by, fit };
}

/** What a call brings: a note's card, the rules a tool's notes give of it, a tool's own manifest, or nothing. */
export type CardChoice =
  | { kind: "note"; name: string; note: CardNote; by: "args" | "lead" | "first" }
  | { kind: "rules"; name: string; notes: CardNote[]; text: string }
  | { kind: "manifest"; name: string };

/**
 * The card a call brings, by what the seat has seen (`ever`: `note:<key>`, `tool:<name>`) and holds. The note the call
 * matches (matchCard), if the seat neither holds it nor was shown its card. Else, on the first call of the tool (or of
 * the program): the most specific note's card that names the tool when at most CARD_TOOL_SPREAD notes name it and the
 * call contradicts none of them (the tool's own manifest when no card of them names it); else the rules its notes give
 * of it (toolRules); else, for a tool no note names, its own manifest's. Never
 * the bare list of note ids ("Notes that name regkv: ... and 11 more"), which was 9 of 39 cards of one run and
 * followed by no load. A command's programs are tried in their order. `ever` is not changed here.
 */
export function chooseCard(index: CardIndex, call: CardCall, ever: ReadonlySet<string>, holds: (key: string) => boolean, leadText = ""): CardChoice | null {
  for (const name of call.tool ? [call.tool] : call.programs) {
    const all = (call.tool ? index.byTool : index.byProgram).get(name) ?? [];
    if (!call.tool && !all.length) continue;
    const open = (n: CardNote) => !holds(n.key) && !ever.has(`note:${n.key}`);
    const m = matchCard(call, name, all, leadText);
    if (m.best && open(m.best)) return { kind: "note", name, note: m.best, by: m.by ?? "args" };
    if (ever.has(`tool:${name}`)) continue;
    if (all.length && all.length <= CARD_TOOL_SPREAD) {
      // One of a few notes is the method: the most specific the call does not contradict and whose card names the tool,
      // unless the seat holds it. A card that does not name the tool (another tool's rules) is not shown for it: where
      // none does, the tool's own manifest says what it is.
      const top = m.fit.find((n) => mentionRe(name).test(n.card));
      if (top && open(top)) return { kind: "note", name, note: top, by: "first" };
      if (!top && call.tool && !all.some((n) => mentionRe(name).test(n.card))) return { kind: "manifest", name };
      continue;
    }
    if (!all.length) return { kind: "manifest", name };
    // The rules of the notes the seat holds, or whose card it was shown, are not given again.
    const notes = (m.fit.length ? m.fit : all).filter(open);
    const text = toolRules(name, notes);
    if (text) return { kind: "rules", name, notes, text };
  }
  return null;
}

/**
 * The rules a tool's notes give of it, for a call of a tool many notes name that matches none of them: each sentence of
 * their own cards that names the tool, each once, whole sentences within CARD_MAX_CHARS; the ones the tool is the
 * subject of first, and of those the ones that hold for any call (no note's argument form) before the ones a note's
 * form makes its own case. Null when no hand-written card names it.
 */
export function toolRules(name: string, notes: readonly CardNote[], max = CARD_MAX_CHARS): string | null {
  const seen = new Set<string>();
  const found: Array<{ text: string; rank: number; order: number }> = [];
  for (const n of notes) {
    if (!n.hand) continue;
    for (const s of cardSentences(n.card)) {
      if (!mentionRe(name).test(s) || /^Does not show\b/.test(s)) continue;
      const key = s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
      if (seen.has(key)) continue;
      seen.add(key);
      // The tool as the sentence's subject first, a rule for any call before one with a note's own argument form.
      const subject = new RegExp(`^${escapeRe(name)}(?![A-Za-z0-9_])`).test(s);
      const own = cardExamples(s, n.tools).has(name);
      found.push({ text: s, rank: (subject ? 0 : 2) + (own ? 1 : 0), order: found.length });
    }
  }
  found.sort((a, b) => a.rank - b.rank || a.order - b.order);
  const out: string[] = [];
  let length = 0;
  for (const f of found) {
    if (length + f.text.length + 1 > max) continue;
    out.push(f.text);
    length += f.text.length + 1;
  }
  return out.length ? out.join(" ") : null;
}

// ---------------------------------------------------------------------------
// Which skill the seat meant
// ---------------------------------------------------------------------------

export type Wanted = { pack: string | null; id: string };

/** `pack:id` or the pack-relative id; null when it is neither. */
export function parseWanted(raw: string): Wanted | null {
  const m = /^(?:([a-z0-9][a-z0-9-]{0,63}):)?(.+)$/.exec(raw.trim());
  if (!m) return null;
  const id = m[2]!;
  if (!SKILL_ID.test(id) || id.includes("..")) return null;
  return { pack: m[1] ?? null, id };
}

export type Located = {
  pack: PackRef;
  id: string;
  /** The other packs of the run that carry the same bare id. */
  others: PackRef[];
  /** The leading segment taken off an id asked with its pack in front ("linux" of "linux/accounts/users"). */
  prefix?: string;
};

/**
 * The short names a pack goes by in what seats write: each whole word of its
 * id ("base" of computer-forensics-base, "windows" of windows-forensics,
 * "ransomware" of ransomware-response), its words up to a dash
 * ("computer-forensics"), and the namespace its router sits in (base/router,
 * windows/router), which is the name the index shows a seat when it is over
 * budget. 24 of 25 failed loads in three runs of one case were an id with one
 * of these in front, as `base:evidence/ad1` or `base/evidence/ad1`. A part of a
 * word ("lin", "comp") is no pack's name.
 */
async function packGoesBy(pack: PackRef, name: string): Promise<boolean> {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) return false;
  if (pack.id === name || pack.id.startsWith(`${name}-`)) return true;
  if (pack.id.split("-").includes(name)) return true;
  return exists(join(pack.dir, "skills", name, "router.md"));
}

export async function locateSkill(packs: PackRef[], wanted: Wanted): Promise<{ found: Located } | { missing: "no such pack" | "no such skill" }> {
  const has = (pack: PackRef, id = wanted.id) => exists(join(pack.dir, "skills", `${id}.md`));
  if (wanted.pack) {
    const pack = packs.find((p) => p.id === wanted.pack);
    if (pack) return (await has(pack)) ? { found: { pack, id: wanted.id, others: [] } } : { missing: "no such skill" };
    // A pack's short name in front ("base:evidence/ad1", "windows:execution/prefetch"): the one pack that goes by it and carries the id; else the
    // one pack of the run that carries the id at all. Two that carry it: none is chosen, the seat is told the ids.
    const named: PackRef[] = [];
    for (const p of packs) if ((await packGoesBy(p, wanted.pack)) && (await has(p))) named.push(p);
    if (named.length === 1) return { found: { pack: named[0]!, id: wanted.id, others: [], prefix: `${wanted.pack}:` } };
    if (!named.length) {
      const carrying: PackRef[] = [];
      for (const p of packs) if (await has(p)) carrying.push(p);
      if (carrying.length === 1) return { found: { pack: carrying[0]!, id: wanted.id, others: [], prefix: `${wanted.pack}:` } };
    }
    return { missing: named.length ? "no such skill" : "no such pack" };
  }
  const carrying: PackRef[] = [];
  for (const pack of packs) if (await has(pack)) carrying.push(pack);
  if (carrying.length) return { found: { pack: carrying[0]!, id: wanted.id, others: carrying.slice(1) } };
  // The id with its pack in front, slash separated ("windows/execution/prefetch", 17 of 143 calls; the
  // first microVM case run asked for "linux/accounts/users"; "base/evidence/ad1" after the index showed
  // base/router): a leading segment that is a name the pack goes by (packGoesBy) is taken off, and the
  // rest is looked up in those packs only. Carried by exactly one of them, it is that note; otherwise
  // there is none. A misspelt id is not sent to some other pack's note.
  const cut = wanted.id.indexOf("/");
  if (cut >= 3) {
    const prefix = wanted.id.slice(0, cut);
    const rest = wanted.id.slice(cut + 1);
    const named: PackRef[] = [];
    for (const pack of packs) if ((await packGoesBy(pack, prefix)) && (await has(pack, rest))) named.push(pack);
    if (named.length === 1) return { found: { pack: named[0]!, id: rest, others: [], prefix } };
  }
  return { missing: "no such skill" };
}

const squash = (text: string) => text.toLowerCase().replace(/\.md$/, "").replace(/[^a-z0-9/]/g, "");

/**
 * Ids a seat probably meant, or none. The shape that fails is the id with a pack
 * in front of it ("windows/execution/prefetch", 17 of 143 calls): a leading
 * segment that is the start of a pack id of this run is taken off, dashes do
 * not count ("anti-forensics" is "antiforensics"), and only a close match is
 * named (the same id in another place, the same last segment, a directory of
 * that name). A weak match is worse than none: it sends the seat to a note
 * about something else.
 */
export function suggestIds(packs: PackIndex[], asked: string, limit = 5): string[] {
  const afterPack = asked.toLowerCase().replace(/^.*:/, "");
  const raw = afterPack.split("/").filter(Boolean);
  const packIds = packs.map((p) => p.id.toLowerCase());
  const head = raw[0] ?? "";
  const segments = (raw.length > 0 && head.length >= 3 && packIds.some((id) => id.startsWith(head)) ? raw.slice(1) : raw).map(squash).filter(Boolean);
  if (!segments.length) return [];
  const wanted = segments.join("/");
  const last = segments[segments.length - 1]!;
  const lastTwo = segments.slice(-2).join("/");
  const colliding = collidingIds(packs);
  const scored: Array<{ ref: string; score: number }> = [];
  for (const pack of packs) {
    for (const entry of pack.entries) {
      const id = squash(entry.id);
      let score = 0;
      if (id === wanted) score = 5;
      else if (lastTwo && id === lastTwo) score = 4;
      else if (id === last || id.endsWith(`/${last}`) || id.startsWith(`${wanted}/`)) score = 3;
      if (score) scored.push({ ref: colliding.has(entry.id) ? `${pack.id}:${entry.id}` : entry.id, score });
    }
  }
  const best = scored.reduce((m, x) => Math.max(m, x.score), 0);
  return scored
    .filter((x) => x.score === best)
    .sort((a, b) => a.ref.localeCompare(b.ref))
    .slice(0, limit)
    .map((x) => x.ref);
}

// ---------------------------------------------------------------------------
// What this seat has loaded
// ---------------------------------------------------------------------------

export type SkillLoad = {
  /** `pack:id`. */
  key: string;
  pack: string;
  id: string;
  /** The turn the load happened in (the number of turns finished, plus the one it was in). */
  turn: number;
  at: string;
  sha256: string;
  tokens: number;
  /** The tool call that delivered the body: how an unloader finds its result in the session. */
  toolCallId: string;
  /** The session entry holding the result, when the ledger was read off the session (the unloader's edit target). */
  entryId?: string;
  /** For a load read off the session whose result was edited: the turn that edit was made in (assistant messages before it), when the whole branch was given. */
  releasedTurn?: number | null;
  /** Set by `skill_done`. */
  done?: { turn: number; note: string };
};

type SessionEntryLike = {
  type?: string;
  id?: string;
  timestamp?: string;
  targetId?: string;
  message?: { role?: string; toolName?: string; toolCallId?: string; details?: Record<string, unknown> };
};

/**
 * The skill bodies the session's own entries hold, in the order they were
 * loaded: what `buildContextEntries()` returns is exactly what the model sees
 * (the compaction, the kept tail, everything after), so a ledger rebuilt from
 * it is exact where one kept in memory can only guess. The tool results'
 * `details` carry the id, pack, hash, tokens and turn; a `skill_done` result
 * marks its body. Also the turn the index was last listed in, when a
 * `skill()` index answer is still in the context.
 *
 * A `context_edit` entry (the unloader's stubs, Pi's own omissions after an
 * overflow) changes what the model is sent of the entry it targets, and the
 * entry itself stays in the session: a body whose result has been edited is
 * not in the context any more, so it is returned in `released`, not in `loads`.
 * The latest edit of a target wins, and an edit is only ever of an earlier entry.
 * Given the whole branch as well, it says in which turn each edit was made (the
 * assistant messages before it), which the context entries alone cannot: after a
 * compaction they begin at its kept tail.
 */
export function loadsFromEntries(entries: readonly unknown[], branch?: readonly unknown[]): { loads: SkillLoad[]; released: SkillLoad[]; indexTurn: number | null } {
  const byKey = new Map<string, SkillLoad>();
  const released: SkillLoad[] = [];
  const edited = new Set<string>();
  const editTurn = new Map<string, number>();
  if (branch) {
    let turns = 0;
    for (const raw of branch) {
      const e = raw as SessionEntryLike | null;
      if (e?.type === "message" && e.message?.role === "assistant") turns += 1;
      else if (e?.type === "context_edit" && typeof e.targetId === "string") editTurn.set(e.targetId, turns);
    }
  }
  for (const raw of entries) {
    const e = raw as SessionEntryLike | null;
    if (e?.type === "context_edit" && typeof e.targetId === "string") edited.add(e.targetId);
  }
  let indexTurn: number | null = null;
  for (const raw of entries) {
    const e = raw as SessionEntryLike | null;
    if (e?.type !== "message" || e.message?.role !== "toolResult") continue;
    const m = e.message;
    const d = m.details ?? {};
    const gone = typeof e.id === "string" && edited.has(e.id);
    if (m.toolName === "skill") {
      if (d.ok !== true) continue;
      if (d.index === true) {
        if (!gone && d.in_prompt !== true && typeof d.turn === "number") indexTurn = d.turn;
        continue;
      }
      if (d.already_loaded === true || typeof d.id !== "string" || typeof d.pack !== "string") continue;
      const key = SkillLedger.key(d.pack, d.id);
      const load: SkillLoad = {
        key,
        pack: d.pack,
        id: d.id,
        turn: typeof d.turn === "number" ? d.turn : 0,
        at: typeof e.timestamp === "string" ? e.timestamp : "",
        sha256: typeof d.sha256 === "string" ? d.sha256 : "",
        tokens: typeof d.tokens === "number" ? d.tokens : 0,
        toolCallId: typeof m.toolCallId === "string" ? m.toolCallId : (e.id ?? ""),
        ...(typeof e.id === "string" ? { entryId: e.id } : {}),
      };
      if (gone) released.push({ ...load, releasedTurn: (typeof e.id === "string" ? editTurn.get(e.id) : undefined) ?? null });
      else byKey.set(key, load);
    } else if (m.toolName === "skill_done" && d.ok === true && typeof d.id === "string" && typeof d.pack === "string") {
      const load = byKey.get(SkillLedger.key(d.pack, d.id));
      if (load && !load.done) load.done = { turn: typeof d.turn === "number" ? d.turn : load.turn, note: typeof d.note === "string" ? d.note : "" };
    }
  }
  return { loads: [...byKey.values()], released, indexTurn };
}

/** Assistant messages on the session's path: the turns this seat has had, so a restarted process counts on from them. */
export function assistantTurns(entries: readonly unknown[]): number {
  return entries.filter((raw) => {
    const e = raw as SessionEntryLike | null;
    return e?.type === "message" && e.message?.role === "assistant";
  }).length;
}

/**
 * The bodies one seat holds, as far as the harness can know: loaded since
 * the context was last cut. A compaction keeps the newest part of the
 * history verbatim (Pi's `keepRecentTokens`), so what a compaction takes out
 * is not every body: `reconcile` is given the bodies the session says are
 * still in context and keeps exactly those, and `restore` does the same for a
 * process that starts on a session that already has some.
 *
 * The unloader (registerSkills' `turn_end` handler) takes `releasable()` at a
 * turn boundary, appends a stub for each body that `planRelease` lets go and
 * calls `release(key)`; from then on `skill(id)` delivers the body again, and
 * the ledger remembers that it was released: a body released once in a context
 * epoch (the time between two compactions) is not released a second time, so a
 * seat that keeps needing one does not make the harness rewrite its history
 * over and over.
 */
type Released = SkillLoad & { releasedTurn: number | null; reason: string };

export class SkillLedger {
  private live = new Map<string, SkillLoad>();
  /** What the last compaction took out of the context, not fetched again since. */
  private lost: SkillLoad[] = [];
  /** Bodies released by a stub in this epoch, the latest of each key (kept when the key is loaded again). */
  private released = new Map<string, Released>();
  /** What stood in the context when the last compaction ran: the hand-off line's account of it. */
  private compacted: { kept: SkillLoad[]; released: Released[] } = { kept: [], released: [] };
  private indexTurn: number | null = null;

  static key(pack: string, id: string): string {
    return `${pack}:${id}`;
  }

  get(key: string): SkillLoad | undefined {
    return this.live.get(key);
  }

  record(load: SkillLoad): void {
    this.live.set(load.key, load);
    this.lost = this.lost.filter((l) => l.key !== load.key);
  }

  /** The bodies held and not yet marked done. */
  working(): SkillLoad[] {
    return [...this.live.values()].filter((l) => !l.done);
  }

  /** Every body held, in the order loaded. */
  held(): SkillLoad[] {
    return [...this.live.values()];
  }

  /** Marks a held body done; null when this seat does not hold it. */
  markDone(key: string, turn: number, note: string): SkillLoad | null {
    const load = this.live.get(key);
    if (!load) return null;
    if (!load.done) load.done = { turn, note };
    return load;
  }

  /** Bodies the seat said it is finished with and that are still in its context: the unloader's input. */
  releasable(): SkillLoad[] {
    return [...this.live.values()].filter((l) => l.done);
  }

  /** The unloader replaced this body in the context: it is no longer held, and the ledger remembers when and why. */
  release(key: string, info: { turn: number; reason: string } = { turn: 0, reason: "released" }): SkillLoad | null {
    const load = this.live.get(key);
    if (!load) return null;
    this.live.delete(key);
    this.released.set(key, { ...load, releasedTurn: info.turn, reason: info.reason });
    return load;
  }

  /** A release that never landed (the edit is not in the session): the body is still in the context and held again, with its done mark. */
  unrelease(key: string, turn: number): SkillLoad | null {
    const gone = this.released.get(key);
    if (!gone || gone.releasedTurn !== turn) return null;
    this.released.delete(key);
    const { releasedTurn: _turn, reason: _reason, ...load } = gone;
    this.live.set(key, load);
    return load;
  }

  /** The ledger held a body the session no longer shows in the context: forget it, without calling it a release. */
  drop(key: string): void {
    this.live.delete(key);
  }

  /** The bodies released in this context epoch, the latest of each key. */
  releasedLoads(): SkillLoad[] {
    return [...this.released.values()];
  }

  /** The turn this key was last released in, in this context epoch; undefined when it was not (or a compaction has been since). */
  releasedAt(key: string): number | null | undefined {
    return this.released.get(key)?.releasedTurn;
  }

  /** Nothing is known to be in the context any more (the session could not be read after a compaction). */
  onCompaction(): SkillLoad[] {
    const taken = [...this.live.values()];
    this.compacted = { kept: [], released: [...this.released.values()] };
    this.lost = taken;
    this.live.clear();
    this.released.clear();
    this.indexTurn = null;
    return taken;
  }

  /**
   * A compaction ran, and `inContext` is what the session says is still there:
   * the rest is lost. `stubs` are the bodies the context still holds as stubs
   * (a released result in the kept tail): their release stays on the record.
   */
  reconcile(inContext: readonly SkillLoad[], indexTurn: number | null, stubs: readonly SkillLoad[] = []): { kept: SkillLoad[]; lost: SkillLoad[] } {
    const before = [...this.live.values()];
    const next = new Map<string, SkillLoad>();
    for (const load of inContext) {
      const prior = before.find((b) => b.key === load.key && b.toolCallId === load.toolCallId);
      next.set(load.key, { ...load, ...(load.done ? {} : prior?.done ? { done: prior.done } : {}) });
    }
    const lost = before.filter((b) => !next.has(b.key) || next.get(b.key)!.toolCallId !== b.toolCallId);
    this.compacted = { kept: [...next.values()], released: [...this.released.values()] };
    this.live = next;
    this.lost = lost;
    this.indexTurn = indexTurn;
    this.released = new Map(stubs.map((s) => [s.key, { ...s, releasedTurn: s.releasedTurn ?? null, reason: "edit" }]));
    return { kept: [...next.values()], lost };
  }

  /** A process started on a session that already holds some bodies (and some stubs). */
  restore(inContext: readonly SkillLoad[], indexTurn: number | null, stubs: readonly SkillLoad[] = []): void {
    this.reconcile(inContext, indexTurn, stubs);
    this.lost = [];
    this.compacted = { kept: [], released: [] };
  }

  /** Skills the seat held when it last handed off, for the line under the hand-off header. */
  handoffIds(): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const load of this.lost) {
      if (seen.has(load.key)) continue;
      seen.add(load.key);
      out.push(load.key);
    }
    return out;
  }

  /**
   * What the last compaction left of the notes the seat had read: the ones it
   * took out (not loaded again since), the ones the newest part of the history
   * kept, and the ones the unloader had already replaced by a stub. Ids, sizes
   * and whether the seat said it was done; never a body.
   */
  compactionAccount(): { lost: SkillLoad[]; kept: SkillLoad[]; released: Released[] } {
    return { lost: [...this.lost], kept: this.compacted.kept.filter((k) => this.live.has(k.key)), released: this.compacted.released };
  }

  indexShownAt(): number | null {
    return this.indexTurn;
  }

  markIndexShown(turn: number): void {
    this.indexTurn = turn;
  }

  wasLostAtCompaction(key: string): boolean {
    return this.lost.some((l) => l.key === key);
  }
}

// ---------------------------------------------------------------------------
// Releasing a body: which model, which policy, which bodies, what the stub says
// ---------------------------------------------------------------------------

/**
 * The model facts the policy reads: Pi's own catalogue entry for the seat's
 * model (`ctx.model`; `api` and `reasoning` are catalogue fields), never its
 * name.
 */
export type ModelFacts = { api?: string; provider?: string; id?: string; reasoning?: boolean };

/**
 * The APIs a body may be released on at a turn boundary: Pi's own request builder,
 * run offline to `onPayload` before and after an edit, changes only the edited
 * `function_call_output` there and sends every reasoning item (with its
 * `encrypted_content`) as it was (tests/skill-unload.test.ts). This is an allow-list
 * on purpose: any other API that carries reasoning is released at a compaction only
 * until it has been shown the same.
 */
export const BOUNDARY_SAFE_APIS: ReadonlySet<string> = new Set(["openai-responses", "openai-codex-responses", "azure-openai-responses"]);

/**
 * APIs whose reasoning blocks the provider signs and Pi sends back with the
 * history (pi-ai's dist/api/anthropic-messages.js, `thinkingSignature`).
 * Anthropic's own guide says a client-side edit of an earlier turn "can
 * invalidate the thinking blocks in every later assistant turn" on Claude
 * Fable 5.1, Opus 5.5 and Sonnet 5.5 (Sonnet 5 in Pi 0.87.1's catalogue), and
 * Pi tells the managed-effort ones to drop a block whose prefix no longer
 * matches (anthropic-messages.js `block_binding.prefix_mismatch_behavior:
 * "drop_block"`; the drops come back as `thinking_dropped` diagnostics). The same
 * API serves the older Claude models and Bedrock serves Claude through the other
 * one. Used to name the reason; what is released where is `BOUNDARY_SAFE_APIS`.
 */
export const SIGNED_THINKING_APIS: ReadonlySet<string> = new Set(["anthropic-messages", "bedrock-converse-stream"]);

/**
 * - `open`: the API is on the allow-list (`BOUNDARY_SAFE_APIS`), or the catalogue
 *   does not mark the model as reasoning (it writes no thinking blocks; a block
 *   an earlier model wrote still keeps a body, see `signedThinkingAfter`).
 * - `signed-thinking`: the catalogue marks the model as reasoning and its API
 *   signs the thinking blocks.
 * - `unproven`: the catalogue marks the model as reasoning, on an API that is
 *   neither on the allow-list nor known to sign: OpenRouter's and the radius
 *   gateway's Claude entries replay Anthropic's signatures through it, and a
 *   local reasoning model's replay has not been looked at.
 * - `unknown`: the session names no model.
 * Everything but `open` releases at a compaction only.
 */
export type ReleaseClass = "open" | "signed-thinking" | "unproven" | "unknown";

export function releaseClassOf(model: ModelFacts | undefined): { cls: ReleaseClass; why: string } {
  if (!model) return { cls: "unknown", why: "the session reports no model" };
  const api = typeof model.api === "string" ? model.api : "";
  if (BOUNDARY_SAFE_APIS.has(api)) return { cls: "open", why: `api ${api} replays reasoning as items tied to their own calls; an edit of one tool result changes that result alone` };
  if (model.reasoning !== true) return { cls: "open", why: `the catalogue does not mark this ${api || "unknown"}-api model as reasoning, so it writes no thinking blocks` };
  if (SIGNED_THINKING_APIS.has(api)) return { cls: "signed-thinking", why: `the catalogue marks this model as reasoning and its api (${api}) signs thinking blocks bound to the history before them: a client-side edit of an earlier turn can invalidate them, whatever the thinking level now is` };
  return { cls: "unproven", why: `the catalogue marks this model as reasoning on api ${api || "unknown"}, which is not on the allow-list for a release at a turn boundary` };
}

/** What the policy comes to for this seat right now. */
export type EffectiveRelease = "boundary" | "compaction" | "off";

export function effectiveRelease(mode: ReleaseMode, cls: ReleaseClass): EffectiveRelease {
  if (mode === "off") return "off";
  if (mode === "compaction") return "compaction";
  return cls === "open" ? "boundary" : "compaction";
}

/**
 * True when an assistant message after the entry carries a thinking block with a
 * signature that is not an item of the allow-listed APIs: such a block is bound to
 * the history before it and is sent back whatever model or thinking level the seat
 * has now (pi-ai's transform-messages keeps a block's signature for the model that
 * wrote it; convertMessages replays it at any level), so editing the entry would
 * leave it behind an edit. A switch of model or of thinking level mid-run is how
 * a seat on an open class ends up with one.
 */
export function signedThinkingAfter(entries: readonly unknown[], entryId: string): boolean {
  const at = entries.findIndex((e) => (e as { id?: string } | null)?.id === entryId);
  if (at < 0) return false;
  for (const raw of entries.slice(at + 1)) {
    const e = raw as { type?: string; message?: { role?: string; api?: string; content?: unknown } } | null;
    if (e?.type !== "message" || e.message?.role !== "assistant" || !Array.isArray(e.message.content)) continue;
    if (e.message.api !== undefined && BOUNDARY_SAFE_APIS.has(e.message.api)) continue;
    for (const block of e.message.content as Array<{ type?: string; thinkingSignature?: unknown }>) {
      if (block?.type === "thinking" && typeof block.thinkingSignature === "string" && block.thinkingSignature.trim().length > 0) return true;
    }
  }
  return false;
}

/** The stub that stands in the context for a released body. One line; names the way back. */
export function stubText(ref: string, tokens: number): string {
  return `${ref} released (${tokens} tokens). Re-load with skill('${ref}').`;
}

const STUB_RE = /^(\S+) released \((\d+) tokens\)\. Re-load with skill\('([^']+)'\)\.$/;

/** True when a tool result's text is a stub `stubText` wrote. */
export function isStub(text: string): boolean {
  return STUB_RE.test(text.trim());
}

/**
 * About how many tokens follow a session entry in the model's context (Pi's
 * own estimate, characters over four, with the reasoning items' and thinking
 * blocks' signatures counted: they are sent again): what a provider's prompt
 * cache has to write again when that entry is edited, at the least. Where the
 * cache is a single trailing breakpoint with a short look-back (Anthropic's), an
 * edit far behind it can cost the whole message part, not the suffix alone. The
 * unloader puts it on the `skill_unload` row, so a run can say what its releases
 * cost.
 */
export function suffixTokens(contextEntries: readonly unknown[], entryId: string): number | null {
  const at = contextEntries.findIndex((e) => (e as { sourceEntry?: { id?: string } } | null)?.sourceEntry?.id === entryId);
  if (at < 0) return null;
  let chars = 0;
  for (const entry of contextEntries.slice(at + 1)) {
    for (const message of (entry as { messages?: unknown[] }).messages ?? []) {
      const m = message as { content?: unknown };
      if (typeof m.content === "string") chars += m.content.length;
      else if (Array.isArray(m.content)) {
        for (const block of m.content as Array<{ type?: string; text?: string; thinking?: string; thinkingSignature?: string; arguments?: unknown }>) {
          if (block.type === "text") chars += (block.text ?? "").length;
          // A reasoning item travels with its encrypted content, a thinking block with its signature: both are sent again.
          else if (block.type === "thinking") chars += (block.thinking ?? "").length + (typeof block.thinkingSignature === "string" ? block.thinkingSignature.length : 0);
          else if (block.type === "toolCall") chars += JSON.stringify(block.arguments ?? {}).length;
        }
      }
    }
  }
  return Math.ceil(chars / 4);
}

export type ReleaseTrigger = "turn_end" | "compaction";

export type ReleasePlan = {
  release: SkillLoad[];
  /** Held bodies the plan leaves alone, and the rule that left them. */
  keep: Array<{ load: SkillLoad; why: string }>;
};

/**
 * Which held bodies leave the context at a boundary. The rules, in the order
 * they are asked (docs/packs.md section 1 has the reasons):
 * - only a body the seat marked done is ever released. A body it has not
 *   finished with is never touched, however many it holds: the three newest
 *   (`MAX_LIVE_SKILLS`) are the ones it is working from;
 * - not while the policy says otherwise: `off` releases nothing, and a policy
 *   of `compaction` releases only at a compaction (`trigger: "compaction"`);
 * - not a body the model has not had a turn with: one loaded in the turn that is
 *   ending was never read by an assistant message, whatever was marked;
 * - not a body with a signed thinking block after it in the context
 *   (`signedAfter`), whatever model or thinking level the seat has now: the edit
 *   would leave the block behind it. At a compaction the history is replaced
 *   anyway, so that rule does not apply there;
 * - not a second time in one context epoch (`releasedAt`): a body the seat
 *   loaded again after a release is held until the next compaction, so history
 *   is not rewritten back and forth for one note (never toggle). At a compaction
 *   the prefix is rewritten anyway, so that rule does not apply there.
 * Every body the plan releases is released in the same boundary: one edit of
 * the history, however many bodies.
 */
export function planRelease(input: {
  held: readonly SkillLoad[];
  /** The turn that is ending: turns finished, this one included. */
  turn: number;
  effective: EffectiveRelease;
  trigger: ReleaseTrigger;
  releasedAt: (key: string) => number | null | undefined;
  /** Whether the context holds a signed thinking block after this body's result. Absent: none does. */
  signedAfter?: (load: SkillLoad) => boolean;
}): ReleasePlan {
  const plan: ReleasePlan = { release: [], keep: [] };
  for (const load of input.held) {
    const keep = (why: string) => plan.keep.push({ load, why });
    if (!load.done) keep("not marked done");
    else if (input.effective === "off") keep("release is off");
    else if (input.trigger === "turn_end" && input.effective !== "boundary") keep("this model's bodies leave at a compaction only");
    else if (load.turn >= input.turn) keep("no turn has read it yet");
    else if (input.trigger === "turn_end" && input.signedAfter?.(load)) keep("a signed thinking block comes after it in the context");
    else if (input.trigger === "turn_end" && input.releasedAt(load.key) !== undefined) keep("released once already in this context");
    else plan.release.push(load);
  }
  return plan;
}

// ---------------------------------------------------------------------------
// What a compaction's summary is told of the notes a seat read
// ---------------------------------------------------------------------------

type MessageLike = { role?: string; toolName?: string; toolCallId?: string; details?: Record<string, unknown>; content?: unknown };

/** One note a seat read, as the summary input and the hand-off header list it: ids and sizes, never text. */
export type SkillRead = { key: string; id: string; pack: string; tokens: number; turn: number; done: boolean; released: boolean; /** The tool call that delivered it. */ call: string | null };

function textOfContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b) => (b && typeof b === "object" && (b as { type?: string }).type === "text" ? String((b as { text?: string }).text ?? "") : "")).join("");
}

/**
 * The part of a conversation a compaction is going to summarise, with every
 * skill body in it replaced by one line that names the note and its size (a
 * body the unloader already released is a stub and stays one), and the list of
 * notes read. Pi serialises each tool result for the summariser cut to 2,000
 * characters; a note's first 2,000 characters are method, not case facts, and
 * not what the summary should be written from. The messages are not changed in
 * place: the session keeps the whole result.
 */
export function shapeForSummary(messages: readonly unknown[]): { messages: unknown[]; reads: SkillRead[] } {
  const reads = new Map<string, SkillRead>();
  const shaped = messages.map((raw) => {
    const m = raw as MessageLike | null;
    if (m?.role !== "toolResult" || m.toolName !== "skill") return raw;
    const d = m.details ?? {};
    if (d.ok !== true) return raw;
    if (d.index === true) {
      const turn = typeof d.turn === "number" ? d.turn : 0;
      return { ...m, content: [{ type: "text", text: `[the skill index was listed at turn ${turn}; it is not part of this summary input]` }] };
    }
    if (d.already_loaded === true || typeof d.id !== "string" || typeof d.pack !== "string") return raw;
    const key = SkillLedger.key(d.pack, d.id);
    const tokens = typeof d.tokens === "number" ? d.tokens : 0;
    const turn = typeof d.turn === "number" ? d.turn : 0;
    const released = isStub(textOfContent(m.content));
    const call = typeof m.toolCallId === "string" ? m.toolCallId : null;
    reads.set(call ?? `${key}@${turn}`, { key, id: d.id, pack: d.pack, tokens, turn, done: released, released, call });
    if (released) return raw;
    return { ...m, content: [{ type: "text", text: `[note ${key}: ${tokens} tokens, read at turn ${turn}; its text is not part of this summary input]` }] };
  });
  // A skill_done result marks the latest read of that note it follows.
  const order = [...reads.values()];
  for (const raw of messages) {
    const m = raw as MessageLike | null;
    if (m?.role !== "toolResult" || m.toolName !== "skill_done" || m.details?.ok !== true) continue;
    const d = m.details;
    if (typeof d.id !== "string" || typeof d.pack !== "string") continue;
    const key = SkillLedger.key(d.pack, d.id);
    const open = [...order].reverse().find((r) => r.key === key && !r.done);
    if (open) open.done = true;
  }
  return { messages: shaped, reads: order };
}

/** The block the summary call is given beside the conversation. Facts only; the summary prompt says what to do with them. */
export function renderSkillsRead(reads: readonly SkillRead[]): string {
  if (!reads.length) return "";
  const lines = [
    "<skills-read>",
    "Method notes this agent read in the conversation above. Only their ids and sizes are here, never their text:",
  ];
  for (const r of reads) {
    lines.push(`- ${r.key}: ${r.tokens} tokens, read at turn ${r.turn}, ${r.released ? "marked done and released from its context" : r.done ? "marked done" : "not marked done"}`);
  }
  const open = reads.filter((r) => !r.done);
  if (open.length) lines.push(`Not marked done (probably still needed after the compaction): ${[...new Set(open.map((r) => r.key))].join(", ")}.`);
  lines.push("</skills-read>");
  return lines.join("\n");
}

/**
 * The hand-off header's account of the notes the seat read before a compaction,
 * each id once: the ones it took out, the ones the unloader had replaced by a
 * stub, the ones still in the context, each with its size and whether the seat
 * marked it done, and which are probably still needed. Empty when the compaction
 * took nothing a seat had read.
 */
export function renderHandoffReads(account: { lost: readonly SkillLoad[]; kept: readonly SkillLoad[]; released: ReadonlyArray<SkillLoad> }): string {
  if (!account.lost.length && !account.released.length) return "";
  const parts: string[] = [];
  for (const l of account.lost) parts.push(`${l.key} ${l.tokens} (taken out of your context, ${l.done ? "marked done" : "not marked done"})`);
  for (const l of account.released) parts.push(`${l.key} ${l.tokens} (marked done, released earlier)`);
  for (const l of account.kept) parts.push(`${l.key} ${l.tokens} (${l.done ? "marked done; " : ""}still in your context)`);
  const lines = [`Method notes you read since your last compaction, with their size in tokens (never their text): ${parts.join(", ")}.`];
  const needed = [...new Set(account.lost.filter((l) => !l.done).map((l) => l.key))];
  lines.push(`Load again (skill(id)) the ones you still need${needed.length ? `; not marked done, so probably still needed: ${needed.join(", ")}` : ""}.`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// The tools
// ---------------------------------------------------------------------------

export type SkillsDeps = {
  packDirs: string[];
  agentId: () => string;
  /** One trace line; the extension's own `logEvent`, so attribution and the collector are the same. */
  trace: (cwd: string, tool: string, args: Record<string, unknown>, result: unknown, durationMs?: number) => Promise<void>;
  /** How many turns this seat has finished. */
  turns: () => number;
  /** A process that starts on an existing session counts its turns on from the session's. */
  restoreTurns?: (turns: number) => void;
  /** A fault the operator and the peers should see (the extension posts it on the board). */
  fault: (cwd: string, message: string) => Promise<void>;
  /** `--skill-release` as the kickoff passed it (`SWARM_SKILL_RELEASE`): compaction, auto or off. Anything else is compaction (the least aggressive release), and the policy row says so. */
  release?: string;
  /** True while a hand-off compaction is about to run (the seat saved its note): the prefix is rewritten anyway, so finished bodies leave with it. */
  compactionPending?: () => boolean;
  /** `--skill-cards` as the kickoff passed it (`SWARM_SKILL_CARDS`): on, the default, or off. */
  cards?: string;
};

export type SkillsHandle = {
  /**
   * What to add to the forced system prompt, with its leading blank line:
   * nothing when `basePrompt` (Pi's own rendering of the seat's prompt) already
   * carries this run's index whole, the index when it does not (with a word
   * when the prompt carries another one), and nothing when the packs carry no
   * skills. Writes the one `skills_index` row of the process.
   */
  promptSection: (cwd: string, basePrompt: string) => Promise<string>;
  /** The lines the hand-off header carries, at most `max` characters (HANDOFF_SKILLS_MAX): the skill bodies a compaction took out of this seat's context, the cards of the notes and tools it worked with, and where the index is when its prompt does not carry it. Empty when none. */
  handoffLine: (max?: number) => string;
  /**
   * The part of the conversation a compaction is going to summarise, shaped for
   * the summary call: every skill body in it is one line naming the note and its
   * size, and `block` lists the notes read (ids and sizes, with whether each was
   * marked done). Unchanged, with an empty block, when the release policy is off.
   */
  summaryInput: (history: readonly unknown[], turnPrefix: readonly unknown[]) => { history: unknown[]; turnPrefix: unknown[]; block: string };
  ledger: SkillLedger;
};

/** Where the seat's prompt got the index from: Pi's own prompt (the kickoff's file), the extension (that run only), or nowhere. */
export type IndexSource = "prompt" | "stale" | "extension" | "none";

function text(value: string, details: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: value }], details };
}

/** How many thinking blocks an assistant message's diagnostics say Anthropic dropped (Pi's own count, interactive-mode.js `countDroppedThinkingBlocks`). */
export function countDroppedThinkingBlocks(message: { diagnostics?: unknown }): number {
  let count = 0;
  const diagnostics = Array.isArray(message.diagnostics) ? (message.diagnostics as Array<{ type?: string; details?: { transformations?: unknown } }>) : [];
  for (const diagnostic of diagnostics) {
    if (diagnostic?.type !== "anthropic_input_transformations") continue;
    const transformations = diagnostic.details?.transformations;
    if (!Array.isArray(transformations)) continue;
    count += transformations.filter((t) => typeof t === "object" && t !== null && (t as { type?: string }).type === "thinking_dropped").length;
  }
  return count;
}

export function registerSkills(pi: ExtensionAPI, deps: SkillsDeps): SkillsHandle {
  const ledger = new SkillLedger();
  const requestedRelease = parseReleaseMode(deps.release);
  const releaseMode: ReleaseMode = requestedRelease ?? DEFAULT_RELEASE_MODE;
  /** The policy row is written when this changes: the model, the thinking level, what they come to. */
  let policyKey = "";
  /** Releases whose edit the session has not been seen to hold yet: checked at the next boundary. */
  let unverified: Array<{ load: SkillLoad; entryId: string; turn: number; reason: string }> = [];
  /** Bodies whose edit did not land in this context epoch: not tried again until a compaction. */
  const unreleasable = new Set<string>();
  /** What the next assistant reply is to be read for: set by a release and by a compaction. */
  let watch: { after: "release" | "compaction"; turn: number } | null = null;
  let indexes: Promise<PackIndex[]> | null = null;
  const packIndexes = () => (indexes ??= readPackIndexes(deps.packDirs));
  let section: Promise<{ text: string; report: SectionReport }> | null = null;
  let sectionLogged = false;
  let source: IndexSource | null = null;
  let sectionText = "";

  const sectionOnce = async () => (section ??= packIndexes().then((all) => renderSkillsSection(all)));
  const cardsMode = parseCardsMode(deps.cards);
  let cards: Promise<CardIndex> | null = null;
  const cardsOnce = () => (cards ??= packIndexes().then((all) => cardIndex(all)));
  /**
   * What this seat was shown in this run (never cleared): `note:<key>` a note's card, `tool:<name>` a tool's first call,
   * `lead:<id>` a lead's notes; and the cards' words by the name the seat knows them by, to carry across a compaction.
   * Both are kept in the session (CARDS_STATE_TYPE), so a seat the watchdog starts again on its session is not shown them again.
   */
  const cardsEver = new Set<string>();
  const cardsHeld = new Map<string, string>();
  /** Each note's card, by its key, once read: the hand-off header's cards are taken from here (it is written without a wait). */
  const cardText = new Map<string, string>();
  /** The words of each lead this seat opened or claimed, and of the last one: the work a call is made for. */
  const leadTexts = new Map<string, string>();
  let lastLead = "";
  const saveCards = () => {
    try {
      (pi as { appendEntry?: (type: string, data: unknown) => void }).appendEntry?.(CARDS_STATE_TYPE, { version: 1, ever: [...cardsEver], held: [...cardsHeld] });
    } catch {
      // the session may be ending; the state is still in memory
    }
  };

  // Pi runs the tool calls of one assistant message at the same time. Both of ours read
  // and write one ledger with awaits between, so they take turns, in the order the
  // message lists them (executionMode "sequential" would hold a message's bash calls back too).
  let chain: Promise<void> = Promise.resolve();
  const inTurn = <A extends unknown[], R>(run: (...args: A) => Promise<R>) => (...args: A): Promise<R> => {
    const next = chain.then(() => run(...args));
    chain = next.then(() => undefined, () => undefined);
    return next;
  };

  /** The Skills section, and the one trace row that says what it carried, where it came from, or that it could not be built. */
  async function promptSection(cwd: string, basePrompt: string): Promise<string> {
    let built: { text: string; report: SectionReport };
    try {
      built = await sectionOnce();
    } catch (err) {
      built = { text: "", report: { unreadable: [{ pack: "*", reason: err instanceof Error ? err.message : String(err) }] } as SectionReport };
    }
    // Pi's own rendering of the prompt carries it when the kickoff wrote .pi/APPEND_SYSTEM.md. Having the heading is not
    // having the index: a file written for other packs, or a one-line heading, is a section that lists the wrong skills.
    const exact = built.text !== "" && basePrompt.includes(built.text);
    const headed = built.text !== "" && basePrompt.includes(SKILLS_SECTION_TITLE);
    const now: IndexSource = built.text === "" ? "none" : exact ? "prompt" : headed ? "stale" : "extension";
    source = now;
    sectionText = built.text;
    if (!sectionLogged) {
      sectionLogged = true;
      const { report } = built;
      const failed = report.unreadable ?? [];
      await deps
        .trace(cwd, "skills_index", {}, { ok: failed.length === 0 && now !== "stale", source: now, ...(headed ? { matches_packs: exact } : {}), ...report })
        .catch(() => undefined);
      if (failed.length) {
        await deps
          .fault(
            cwd,
            `HARNESS FAULT: the Skills section of ${deps.agentId() || "this agent"}'s prompt could not list ${failed.map((f) => `${f.pack} (${f.reason})`).join(", ")}. Those packs' skills are not in the index this seat was given: it can still call skill() with no id and skill(id).`,
          )
          .catch(() => undefined);
      }
      if (now === "stale") {
        await deps
          .fault(
            cwd,
            `HARNESS FAULT: ${deps.agentId() || "this agent"}'s prompt carries a Skills section that is not the index of this run's packs (a .pi/APPEND_SYSTEM.md written for other packs, or a heading with no index under it). The current index is added after it for this run; the file is wrong, and a run a hand-off starts will show the old one. Tell the operator.`,
          )
          .catch(() => undefined);
      }
    }
    if (!built.text || exact) return "";
    return `\n\n${now === "stale" ? "The Skills section above does not list this run's packs; this is their index:\n\n" : ""}${built.text}`;
  }

  /**
   * The hand-off's skills line, at most `max` characters (the header it goes in is 2,000 beside the note): the notes the
   * compaction took out, then the cards of those notes and of the tools the seat ran (shown once in the run, so carried
   * here), the last first, each whole, as many as fit; and, when the prompt lost the index, where it is (never the index
   * itself, which ran to thousands of characters), first, so that it is the last line a header with less room drops.
   */
  function handoffLine(max: number = HANDOFF_SKILLS_MAX): string {
    const ids = ledger.handoffIds();
    const indexLine = sectionText && (source === "extension" || source === "stale") ? "Your prompt no longer carries this run's skill index: skill() with no id lists it." : "";
    // The cards of the notes the compaction took out, the last read first, then the rules shown with a call (not shown again in this run), the last first.
    const items: Array<[string, string]> = [];
    if (cardsMode !== "off") {
      const listed = new Set<string>();
      const take = (ref: string, card: string | undefined) => {
        const bare = ref.split(":").pop()!;
        if (!card || listed.has(bare)) return;
        items.push([ref, card]);
        listed.add(bare);
      };
      for (const k of ids.slice().reverse()) take(k, cardText.get(k));
      for (const [ref, c] of [...cardsHeld.entries()].reverse()) take(ref, c);
    }
    const head = "Rules you worked with (shown once in the run; whole note: skill(id)):";
    // The index's line first, always (it is short, and a header with less room drops lines from the end), then the
    // account of the notes read, then whole cards while they fit.
    const render = (account: string): { text: string; rows: number } => {
      const lines: string[] = indexLine && indexLine.length <= max ? [indexLine] : [];
      let room = max - (lines.length ? indexLine.length + 1 : 0);
      if (account && account.length <= room) {
        lines.push(account);
        room -= account.length + 1;
      }
      const rows: string[] = [];
      let used = head.length + 1;
      for (const [ref, c] of items) {
        const row = `- ${ref}: ${c.replace(/\s*\n\s*/g, " ")}`;
        if (used + row.length + 1 > room) continue;
        rows.push(row);
        used += row.length + 1;
      }
      if (rows.length) lines.push(`${head}\n${rows.join("\n")}`);
      return { text: lines.join("\n"), rows: rows.length };
    };
    // The whole account (sizes, done or not) when a card still fits beside it; else the ids, as many as leave room for one.
    // With the release policy off the account is the line a seat had before the unloader.
    const short = (n: number) => `Skill bodies a compaction took out of your context: ${ids.slice(0, n).join(", ")}${n < ids.length ? `, and ${ids.length - n} more` : ""}. Load again (skill(id)) the ones you still need.`;
    const accounts = [...(releaseMode === "off" ? [] : [renderHandoffReads(ledger.compactionAccount())]), ...ids.map((_, k) => short(ids.length - k)), ""].filter((a, k, all) => a || k === all.length - 1);
    let best: { text: string; rows: number } | null = null;
    for (const a of accounts) {
      const got = render(a);
      if (got.text.length > max) continue;
      if (!best) best = got;
      if (!items.length || got.rows > 0) return got.text;
    }
    return best?.text ?? "";
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      const inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries(), ctx.sessionManager.getBranch());
      ledger.restore(inContext.loads, inContext.indexTurn, inContext.released);
      deps.restoreTurns?.(assistantTurns(ctx.sessionManager.getBranch()));
    } catch {
      // a session that cannot be read starts with an empty ledger: a body is sent once more, nothing worse
    }
    try {
      // A process started again on its session (the watchdog's relaunch) is the same seat: the cards it was shown stay shown.
      // A fresh session (the old one set aside) has none of them in its context, and is shown them again.
      const kept = cardsStateOf(ctx.sessionManager.getBranch());
      if (kept) {
        for (const k of kept.ever) cardsEver.add(k);
        for (const [ref, card] of kept.held) cardsHeld.set(ref, card);
      }
    } catch {
      // a branch that cannot be read: the cards are shown once more, nothing worse
    }
  });

  pi.on("session_compact", async (_event, ctx) => {
    // The releases of the boundary before this compaction (the hand-off's own) are checked against the branch
    // before the ledger is rebuilt from it: a draft Pi did not commit is said, and the metrics stop counting it.
    await verifyReleases(ctx as unknown as BoundaryCtx).catch(() => undefined);
    let result: { kept: SkillLoad[]; lost: SkillLoad[] };
    try {
      const inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries(), ctx.sessionManager.getBranch());
      result = ledger.reconcile(inContext.loads, inContext.indexTurn, inContext.released);
    } catch {
      result = { kept: [], lost: ledger.onCompaction() };
    }
    // A compaction rebuilt the ledger from the session: what was waiting to be checked is settled by it.
    unverified = [];
    unreleasable.clear();
    watch = { after: "compaction", turn: deps.turns() };
    const stubbed = ledger.compactionAccount().released;
    if (result.kept.length || result.lost.length || stubbed.length) {
      const ref = (l: SkillLoad) => ({ key: l.key, turn: l.turn });
      await deps
        .trace(ctx.cwd, "skills_compacted", {}, { ok: true, kept: result.kept.map(ref), lost: result.lost.map(ref), ...(stubbed.length ? { released: stubbed.map(ref) } : {}) })
        .catch(() => undefined);
    }
  });

  const packRefs = async (): Promise<PackIndex[]> => packIndexes();
  const sampleId = (all: PackIndex[]) => all.find((p) => p.entries.length)?.entries[0]?.id ?? "area/topic";

  async function runSkill(toolCallId: string, params: { id?: string }, _signal: unknown, _onUpdate: unknown, toolCtx: { cwd: string }) {
    const started = Date.now();
    const cwd = toolCtx.cwd;
    const turn = deps.turns() + 1;
    const wantedRaw = typeof params?.id === "string" ? params.id.trim() : "";
    const all = await packRefs();

    if (!wantedRaw) {
      const built = await sectionOnce().catch(() => null);
      // The prompt carries the index whole only when the kickoff's file put it there and no pack is shown by its router alone.
      const inPrompt = built !== null && built.text !== "" && built.report.mode === "full" && source === "prompt";
      const shownAt = ledger.indexShownAt();
      let out: string;
      if (inPrompt) out = `The whole index of this run's packs is in your instructions, under "${SKILLS_SECTION_TITLE}". Load a note with skill(id).`;
      else if (shownAt !== null) out = `The index was already listed at turn ${shownAt}; it is still in your context. Load a note with skill(id).`;
      else {
        out = renderFullIndex(all);
        ledger.markIndexShown(turn);
      }
      await deps.trace(cwd, "skill", { id: "INDEX" }, { ok: true, bytes: Buffer.byteLength(out), tokens: estimateTokens(out), in_prompt: inPrompt, ...(shownAt !== null && !inPrompt ? { already_loaded: true, loaded_at_turn: shownAt } : {}) }, Date.now() - started);
      return text(out, { ok: true, index: true, in_prompt: inPrompt, turn: shownAt ?? turn });
    }

    const wanted = parseWanted(wantedRaw);
    if (!wanted) {
      await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: "bad id" }, Date.now() - started);
      const sample = sampleId(all);
      const out = `A skill id is lower case and slash separated, as listed in your instructions ("${sample}"), optionally with its pack in front ("${all.find((p) => p.entries.length)?.id ?? "pack"}:${sample}").`;
      return text(out, { ok: false, error: "bad id" });
    }

    const located = await locateSkill(all, wanted);
    if ("missing" in located) {
      const maybe = suggestIds(all, wantedRaw);
      await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: located.missing, ...(maybe.length ? { suggested: maybe } : {}) }, Date.now() - started);
      const which = located.missing === "no such pack" ? `No pack "${wanted.pack}" in this run (it carries: ${all.map((p) => p.id).join(", ") || "none"}).` : `No skill "${wantedRaw}" in this run's packs.`;
      const hint = maybe.length ? ` Did you mean: ${maybe.join(", ")}?` : ` No close match; read the index in your instructions ("${SKILLS_SECTION_TITLE}") for the id of the note you want.`;
      const out = `${which}${hint} skill() with no id lists the ids.`;
      return text(out, { ok: false, error: located.missing, suggested: maybe });
    }

    const { pack, id, others, prefix } = located.found;
    const key = SkillLedger.key(pack.id, id);
    const held = ledger.get(key);
    if (held) {
      const out = `\`${id}\` (${pack.id}) is already in your context, loaded at turn ${held.turn}${held.done ? " and marked done" : ""}; not sent again.`;
      await deps.trace(cwd, "skill", { id }, { ok: true, already_loaded: true, pack: pack.id, loaded_at_turn: held.turn, turn, sha256: held.sha256, tokens_saved: held.tokens }, Date.now() - started);
      return text(out, { ok: true, already_loaded: true, id, pack: pack.id, loaded_at_turn: held.turn });
    }

    const file = await readSkillFile(pack, id);
    if (file) cardText.set(SkillLedger.key(pack.id, id), skillCard(file));
    if (!file) {
      await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: "no such skill" }, Date.now() - started);
      return text(`No skill "${wantedRaw}" in this run's packs.`, { ok: false, error: "no such skill" });
    }

    // What it builds on, with the cost of each: the seat chooses, nothing is loaded for it.
    const needs: Array<{ ref: string; id: string; pack: string | null; tokens: number | null; loaded_at_turn?: number }> = [];
    for (const need of file.needs) {
      const wantedNeed = parseWanted(need);
      if (!wantedNeed) {
        needs.push({ ref: need, id: need, pack: null, tokens: null });
        continue;
      }
      // The pack that carries the skill first; the others in the run's order.
      const order = wantedNeed.pack ? all.filter((p) => p.id === wantedNeed.pack) : [pack, ...all.filter((p) => p.dir !== pack.dir)];
      let found: SkillFile | null = null;
      for (const p of order) {
        found = await readSkillFile(p, wantedNeed.id);
        if (found) break;
      }
      if (!found) {
        needs.push({ ref: need, id: wantedNeed.id, pack: null, tokens: null });
        continue;
      }
      const heldNeed = ledger.get(SkillLedger.key(found.pack.id, found.id));
      const crossPack = found.pack.dir !== pack.dir;
      const clash = all.filter((p) => p.entries.some((e) => e.id === found!.id)).length > 1;
      needs.push({ ref: crossPack || clash ? `${found.pack.id}:${found.id}` : found.id, id: found.id, pack: found.pack.id, tokens: found.tokens, ...(heldNeed ? { loaded_at_turn: heldNeed.turn } : {}) });
    }

    const reload = ledger.wasLostAtCompaction(key);
    const releasedTurn = ledger.releasedAt(key);
    const working = ledger.working();
    const lines: string[] = [`Skill \`${id}\` (pack ${pack.id}${pack.version ? ` ${pack.version}` : ""}, about ${fmt(file.tokens)} tokens)${file.title ? `: ${file.title}` : ""}`, "", file.body];
    const tail: string[] = [];
    if (needs.length) {
      tail.push(
        `Builds on, not loaded: ${needs.map((n) => (n.tokens === null ? `\`${n.ref}\` (not carried by this run's packs)` : n.loaded_at_turn !== undefined ? `\`${n.ref}\` (already loaded, turn ${n.loaded_at_turn})` : `\`${n.ref}\` (about ${fmt(n.tokens)} tokens)`)).join(", ")}. Load those you need.`,
      );
    }
    if (prefix) tail.push(`Asked as \`${wantedRaw}\`: its id is \`${id}\` (pack ${pack.id}), the one skill_done and the index use; a pack goes in front as ${pack.id}:${id}.`);
    if (others.length) tail.push(`Also carried by ${others.map((p) => p.id).join(", ")}: skill("${others[0]!.id}:${id}") loads that one.`);
    if (working.length >= MAX_LIVE_SKILLS) tail.push(`You hold ${working.length} notes you have not marked done (${working.map((l) => l.id).join(", ")}). Mark the ones you have finished with skill_done before you load more.`);
    const delivered = [...lines, ...(tail.length ? ["", ...tail] : [])].join("\n");

    ledger.record({ key, pack: pack.id, id, turn, at: new Date().toISOString(), sha256: file.sha256, tokens: file.tokens, toolCallId });
    await deps.trace(
      cwd,
      "skill",
      { id, ...(wantedRaw !== id ? { requested: wantedRaw } : {}) },
      {
        ok: true,
        pack: pack.id,
        pack_version: pack.version,
        bytes: file.bytes,
        sha256: file.sha256,
        tokens: file.tokens,
        turn,
        tools: file.tools,
        needs: file.needs,
        ...(others.length ? { also_in: others.map((p) => p.id) } : {}),
        ...(reload ? { reload_after_compaction: true } : {}),
        ...(releasedTurn !== undefined ? { reload_after_release: true, released_turn: releasedTurn } : {}),
        ...(working.length >= MAX_LIVE_SKILLS ? { holding: working.length } : {}),
        call: toolCallId,
      },
      Date.now() - started,
    );
    return text(delivered, { ok: true, id, pack: pack.id, pack_version: pack.version, sha256: file.sha256, bytes: file.bytes, tokens: file.tokens, turn, needs, also_in: others.map((p) => p.id) });
  }

  async function runSkillDone(_toolCallId: string, params: { id: string; note?: string }, _signal: unknown, _onUpdate: unknown, toolCtx: { cwd: string }) {
    const started = Date.now();
    const cwd = toolCtx.cwd;
    const turn = deps.turns() + 1;
    const raw = typeof params?.id === "string" ? params.id.trim() : "";
    const note = typeof params?.note === "string" ? params.note : "";
    const wanted = parseWanted(raw);
    // Which loaded note it names: the exact key, or the bare id when one held note has it.
    const held = wanted ? [...ledger.working(), ...ledger.releasable()].filter((l) => l.id === wanted.id && (!wanted.pack || l.pack === wanted.pack)) : [];
    const target = held.length === 1 ? held[0]! : null;
    if (!target) {
      const reason = !wanted ? "bad id" : held.length > 1 ? "ambiguous" : "not loaded";
      // A note this seat finished with and the harness already released is not "unknown": it says so.
      const gone = wanted && reason === "not loaded" ? ledger.releasedLoads().find((l) => l.id === wanted.id && (!wanted.pack || l.pack === wanted.pack)) : undefined;
      await deps.trace(cwd, "skill_done", { id: raw, ...(note ? { note } : {}) }, { ok: false, error: reason, turn, ...(gone ? { released: true } : {}) }, Date.now() - started);
      const out =
        reason === "ambiguous"
          ? `More than one pack's \`${raw}\` is loaded: name it as pack:id (${held.map((l) => l.key).join(", ")}).`
          : gone
            ? `\`${raw}\` was already marked done and has been released from your context (a one-line stub stands in its place); skill("${raw}") loads it again. Nothing to mark done.`
            : `\`${raw}\` is not among the notes you have loaded (none, a compaction took it out of your context, or it was released). Nothing to mark done.`;
      // A note that is no longer in the context has nothing left to release, which is what skill_done is for: that is an
      // answer, not an error (20 such refusals in two runs, each a turn spent on a note a compaction had already taken).
      if (reason === "not loaded") return text(out.replace("Nothing to mark done.", "Nothing is left to mark done: it is already out of your context."), { ok: true, already_gone: true });
      return text(out, { ok: false, error: reason });
    }
    const already = Boolean(target.done);
    ledger.markDone(target.key, turn, note);
    await deps.trace(
      cwd,
      "skill_done",
      { id: target.id, ...(note ? { note } : {}) },
      { ok: true, pack: target.pack, sha256: target.sha256, tokens: target.tokens, loaded_turn: target.turn, held_turns: turn - target.turn, turn, releasable: true, ...(already ? { already_done: true } : {}) },
      Date.now() - started,
    );
    return text(already ? `\`${target.id}\` was already marked done (turn ${target.done!.turn}).` : `Recorded: \`${target.id}\` is done. Load it again with skill("${target.id}") if you need it later.`, { ok: true, id: target.id, pack: target.pack, turn, note });
  }

  // -------------------------------------------------------------------------
  // The unloader: a finished body is replaced by a stub at a turn boundary
  // -------------------------------------------------------------------------

  type BoundaryCtx = {
    cwd: string;
    model?: ModelFacts;
    thinkingLevel?: string;
    sessionManager: { buildContextEntries: () => unknown[]; getBranch: () => unknown[] };
  };
  type BoundaryEvent = {
    entries?: SessionBoundaryDraft[];
    outcome?: string;
    context?: { contextEntries?: readonly unknown[] };
    toolResults?: Array<{ toolName?: string; isError?: boolean }>;
  };

  /** What the policy comes to for this seat now, and the one trace row that says so whenever it changes. */
  async function settlePolicy(ctx: BoundaryCtx): Promise<{ effective: EffectiveRelease; cls: ReleaseClass }> {
    let level: string | undefined;
    try {
      level = ctx.thinkingLevel;
    } catch {
      level = undefined;
    }
    const model = ctx.model;
    const { cls, why } = releaseClassOf(model);
    const effective = effectiveRelease(releaseMode, cls);
    const name = model ? `${model.provider ?? "?"}/${model.id ?? "?"}` : null;
    const key = [releaseMode, effective, cls, model?.api ?? "", name ?? "", level ?? ""].join("|");
    if (key !== policyKey) {
      policyKey = key;
      await deps
        .trace(
          ctx.cwd,
          "skill_release_policy",
          {},
          {
            ok: deps.release === undefined || requestedRelease !== null,
            mode: releaseMode,
            ...(deps.release !== undefined && requestedRelease === null ? { requested: deps.release } : {}),
            effective,
            class: cls,
            why,
            model: name,
            api: model?.api ?? null,
            reasoning: model?.reasoning ?? null,
            thinking_level: level ?? null,
          },
        )
        .catch(() => undefined);
    }
    return { effective, cls };
  }

  /**
   * The releases of the last boundary, checked against the session: a draft Pi
   * did not commit (an older Pi, or a boundary another extension's invalid
   * draft cancelled) leaves the body in the context, and the ledger and the trace
   * must not say otherwise. The body is held again, said on the trace (the row
   * names the same call and entry as the release it takes back, which the metrics
   * read), and not tried again until a compaction. Read off the whole branch, so
   * it holds at a compaction too, when the context entries no longer reach back.
   */
  async function verifyReleases(ctx: BoundaryCtx): Promise<void> {
    if (!unverified.length) return;
    const pending = unverified;
    unverified = [];
    let entries: unknown[];
    try {
      entries = ctx.sessionManager.getBranch();
    } catch {
      return;
    }
    const edited = new Set(entries.map((e) => e as { type?: string; targetId?: string }).filter((e) => e.type === "context_edit").map((e) => e.targetId));
    for (const p of pending) {
      if (edited.has(p.entryId)) continue;
      if (ledger.unrelease(p.load.key, p.turn)) unreleasable.add(p.load.key);
      await deps
        .trace(ctx.cwd, "skill_unload", { id: p.load.id }, { ok: false, error: "the edit was not committed; the body is still in the context", pack: p.load.pack, call: p.load.toolCallId, entry: p.entryId, reason: p.reason, turn: p.turn })
        .catch(() => undefined);
    }
  }

  /**
   * At the end of a turn: replace every body the seat finished with, and the
   * policy lets go, by a stub; all of them in this one return, so the history
   * is rewritten once however many bodies leave. The result is a `context_edit`
   * draft per body (Pi appends them before it builds the next request); the
   * session keeps the raw tool result. The ledger is told only for the bodies
   * the session shows are in the context and not yet edited: it is read off the
   * session here, as at a compaction, so a stale ledger cannot aim an edit at
   * an entry that is gone.
   *
   * The trigger is `compaction` only on the turn in which the seat's
   * `self_compact` came back successfully (the run ends with it, and the
   * compaction that follows rewrites the prefix anyway). A hand-off that failed
   * and was given up is not that: the seat goes on working, and its bodies are
   * released by the turn-end rules or not at all.
   */
  async function releaseAtBoundary(event: BoundaryEvent, ctx: BoundaryCtx): Promise<{ entries: SessionBoundaryDraft[] } | undefined> {
    await verifyReleases(ctx);
    const policy = await settlePolicy(ctx);
    if (policy.effective === "off") return undefined;
    if (event.outcome !== undefined && event.outcome !== "completed") return undefined;
    if (!ledger.releasable().length) return undefined;
    const turn = deps.turns();
    const handedOff = (event.toolResults ?? []).some((r) => r.toolName === "self_compact" && r.isError !== true) && deps.compactionPending?.() !== false;
    const trigger: ReleaseTrigger = handedOff ? "compaction" : "turn_end";
    if (trigger === "turn_end" && policy.effective !== "boundary") return undefined;

    let entries: unknown[];
    let inContext: ReturnType<typeof loadsFromEntries>;
    try {
      entries = ctx.sessionManager.buildContextEntries();
      inContext = loadsFromEntries(entries);
    } catch {
      return undefined;
    }
    const entryOf = (load: SkillLoad) => inContext.loads.find((l) => l.key === load.key && l.toolCallId === load.toolCallId && l.entryId !== undefined)?.entryId;
    const plan = planRelease({
      held: ledger.held().filter((l) => !unreleasable.has(l.key)),
      turn,
      effective: policy.effective,
      trigger,
      releasedAt: (key) => ledger.releasedAt(key),
      signedAfter: (load) => {
        const id = entryOf(load);
        return id !== undefined && signedThinkingAfter(entries, id);
      },
    });
    if (!plan.release.length) return undefined;

    const colliding = collidingIds(await packIndexes());
    const reason = trigger === "compaction" ? "compaction" : "done";
    const drafts: SessionBoundaryDraft[] = [];
    const rows: Array<{ load: SkillLoad; entryId: string; stub: string; suffix: number | null }> = [];
    for (const load of plan.release) {
      const entryId = entryOf(load);
      if (entryId === undefined) {
        // The ledger holds a body the session no longer shows in the context (a compaction took it, or someone else edited it).
        ledger.drop(load.key);
        await deps.trace(ctx.cwd, "skill_unload", { id: load.id }, { ok: false, error: "not in the context", pack: load.pack, call: load.toolCallId, reason, turn }).catch(() => undefined);
        continue;
      }
      const stub = stubText(colliding.has(load.id) ? load.key : load.id, load.tokens);
      drafts.push({ type: "context_edit", targetId: entryId, replacement: { content: [{ type: "text", text: stub }] } });
      rows.push({ load, entryId, stub, suffix: suffixTokens(event.context?.contextEntries ?? [], entryId) });
    }
    if (!drafts.length) return undefined;
    // The cache writes once, from the earliest edit: the batch's cost is the largest suffix, not their sum.
    const batchSuffix = rows.reduce<number | null>((max, r) => (r.suffix === null ? max : max === null ? r.suffix : Math.max(max, r.suffix)), null);
    for (const { load, entryId, stub, suffix } of rows) {
      ledger.release(load.key, { turn, reason });
      unverified.push({ load, entryId, turn, reason });
      await deps
        .trace(
          ctx.cwd,
          "skill_unload",
          { id: load.id },
          {
            ok: true,
            pack: load.pack,
            sha256: load.sha256,
            tokens: load.tokens,
            call: load.toolCallId,
            entry: entryId,
            reason,
            turn,
            loaded_turn: load.turn,
            done_turn: load.done?.turn ?? null,
            held_turns: turn - load.turn,
            batch: rows.length,
            stub_tokens: estimateTokens(stub),
            suffix_tokens: suffix,
            batch_suffix_tokens: batchSuffix,
            policy: releaseMode,
            class: policy.cls,
          },
        )
        .catch(() => undefined);
    }
    // The next reply says whether the provider dropped any thinking block after this edit (Anthropic does, and tells Pi).
    watch = { after: "release", turn };
    return { entries: [...(event.entries ?? []), ...drafts] };
  }

  pi.on("turn_end", async (event, ctx) => {
    try {
      return await releaseAtBoundary(event as unknown as BoundaryEvent, ctx as unknown as BoundaryCtx);
    } catch {
      // a release that cannot be made leaves the body where it is: nothing worse than before the unloader
      return undefined;
    }
  });

  pi.on("tool_result", async (event, ctx) => {
    if (cardsMode === "off") return undefined;
    const ev = event as unknown as { toolName?: string; input?: Record<string, unknown>; isError?: boolean };
    const cwd = (ctx as unknown as { cwd: string }).cwd;
    const content = Array.isArray(event.content) ? event.content : [];
    // A lead taken: the notes that fit its work, by name, once a lead (notesForText); and its words, which choose the card of a later call.
    if ((ev.toolName === "lead_open" || ev.toolName === "lead_claim") && !ev.isError) {
      try {
        const said = content.map((c) => (c as { text?: string }).text ?? "").join(" ");
        const lead = /\bL-\d+\b/.exec(`${String(ev.input?.lead ?? "")} ${said}`)?.[0] ?? "";
        const about = `${String(ev.input?.title ?? "")} ${String(ev.input?.why ?? "")} ${/"title":\s*"([^"]{0,300})"/.exec(said)?.[1] ?? ""}`;
        if (about.trim()) {
          if (lead) leadTexts.set(lead, about);
          lastLead = about;
        }
        const key = `lead:${lead || about.slice(0, 80)}`;
        if (cardsEver.has(key)) return undefined;
        // The ledger keys a note by pack:id (SkillLedger.key); its ref is the bare id where one pack carries it.
        const notes = notesForText(await packIndexes(), about).filter((x) => !ledger.get(SkillLedger.key(x.pack, x.id)) && !cardsHeld.has(x.ref));
        if (!notes.length) return undefined;
        cardsEver.add(key);
        let words = `Notes of this run's packs that fit this lead (each is a page of method: load the one you need with skill(id) before the work, not after): ${notes.map((x) => `${x.ref}${x.when ? ` (${x.when.length > 110 ? `${x.when.slice(0, 109)}\u2026` : x.when})` : ""}`).join("; ")}.`;
        if (cardsMode === "inject") {
          // The forced arm: the rules themselves, for the two notes that fit best.
          const all = await packIndexes();
          const ruled: string[] = [];
          for (const x of notes.slice(0, 2)) {
            const pack = all.find((p) => p.id === x.pack);
            const file = pack ? await readSkillFile(pack, x.id) : null;
            if (!file) continue;
            const card = skillCard(file);
            cardsHeld.set(x.ref, card);
            cardsEver.add(`note:${SkillLedger.key(x.pack, x.id)}`);
            ruled.push(`- ${x.ref}:\n${card.split("\n").map((l) => `  ${l}`).join("\n")}`);
          }
          if (ruled.length) words = `The rules of the notes that fit this lead, to work by (the whole note: skill(id)):\n${ruled.join("\n")}`;
        }
        saveCards();
        await deps.trace(cwd, "skill_card", { lead, ids: notes.map((x) => x.ref) }, { ok: true, kind: cardsMode === "inject" ? "lead_injected" : "lead", tokens: estimateTokens(words), turn: deps.turns() }).catch(() => undefined);
        return { content: [...content, { type: "text" as const, text: words }] };
      } catch {
        return undefined;
      }
    }
    // A call that was refused or failed before it ran gets no card: seven of 39 cards of one run were pinned to a refusal.
    if (ev.isError) return undefined;
    const call = cardCallOf(ev.toolName ?? "", ev.input);
    if (!call) return undefined;
    try {
      const shown = await cardFor(call, cwd);
      if (!shown) return undefined;
      saveCards();
      await deps.trace(cwd, "skill_card", { tool: shown.name, id: shown.id }, { ok: true, pack: shown.pack, by: shown.by, tokens: estimateTokens(shown.words), turn: deps.turns() }).catch(() => undefined);
      // First in the result, where it is read: 24 of 39 cards sat in the last fifth of the result they came with.
      return { content: [{ type: "text" as const, text: shown.words }, ...content] };
    } catch {
      return undefined;
    }
  });

  /** The card a call brings (chooseCard) and its words; the state says it was shown, and a name asked once is not asked again. */
  async function cardFor(call: CardCall, cwd: string): Promise<{ name: string; id: string; pack: string | null; by: string; words: string } | null> {
    const index = await cardsOnce();
    const leadText = (call.lead && leadTexts.get(call.lead)) || lastLead;
    const choice = chooseCard(index, call, cardsEver, (key) => Boolean(ledger.get(key)), leadText);
    // Asked once a name, whatever the answer: a shell or a read has no rules, and is not looked up at every call. But a
    // note's card a call matched does not spend the first call of a tool many notes name: the rules they give of it
    // still come with the first call that matches none of them.
    for (const name of call.tool ? [call.tool] : call.programs) {
      const notes = (call.tool ? index.byTool : index.byProgram).get(name);
      if (choice?.kind === "note" && choice.name === name && choice.by !== "first" && (notes?.length ?? 0) > CARD_TOOL_SPREAD) continue;
      if (notes || call.tool) cardsEver.add(`tool:${name}`);
    }
    if (!choice) return null;
    if (choice.kind === "note") {
      const { note, name } = choice;
      cardsEver.add(`note:${note.key}`);
      cardText.set(note.key, note.card);
      cardsHeld.set(note.ref, note.card);
      return { name, id: note.id, pack: note.pack.id, by: choice.by, words: `Before you read this result, the rules of ${name} (from the note \`${note.ref}\`, ${note.pack.id}; the whole note: skill('${note.ref}')):\n${note.card}` };
    }
    if (choice.kind === "rules") {
      cardsHeld.set(`${choice.name} (its notes)`, choice.text);
      return { name: choice.name, id: "rules", pack: null, by: "first", words: `Before you read this result, the rules of ${choice.name} from the notes that name it (a call that gives what one of them writes brings that note's card; the whole note: skill(id)):\n${choice.text}` };
    }
    const card = await manifestCard(cwd, choice.name);
    if (!card) return null;
    cardsHeld.set(`${choice.name} (its manifest)`, card);
    return { name: choice.name, id: "manifest", pack: null, by: "first", words: `Before you read this result, what ${choice.name} says of itself (its manifest; whole with tools(name: "${choice.name}")):\n${card}` };
  }

  /**
   * The first assistant reply after a release or a compaction, and how many thinking
   * blocks the provider says it dropped from the history it was sent. Pi records
   * that (pi-ai's anthropic-messages.js: the response's `input_transformations`
   * become an `anthropic_input_transformations` diagnostic on the message, which
   * Pi's own interface counts as "Anthropic dropped N thinking blocks"). Only the
   * Anthropic transport reports it, so only its replies get a row. One Claude run
   * answers the question the policy for those models rests on.
   */
  pi.on("message_end", async (event, ctx) => {
    const message = (event as unknown as { message?: { role?: string; api?: string; model?: string; diagnostics?: unknown } }).message;
    if (!watch || message?.role !== "assistant") return undefined;
    const armed = watch;
    watch = null;
    if (message.api !== "anthropic-messages") return undefined;
    const dropped = countDroppedThinkingBlocks(message);
    await deps
      .trace((ctx as unknown as { cwd: string }).cwd, "skill_release_effect", {}, { ok: true, after: armed.after, turn: armed.turn, reply_turn: deps.turns() + 1, thinking_dropped: dropped, model: message.model ?? null })
      .catch(() => undefined);
    return undefined;
  });

  function summaryInput(history: readonly unknown[], turnPrefix: readonly unknown[]): { history: unknown[]; turnPrefix: unknown[]; block: string } {
    if (releaseMode === "off") return { history: [...history], turnPrefix: [...turnPrefix], block: "" };
    const shaped = shapeForSummary([...history, ...turnPrefix]);
    // A note read in the part being summarised and marked done after the cut (in the kept tail) is done all the same: the ledger knows.
    for (const read of shaped.reads) {
      const held = ledger.get(read.key);
      if (!read.done && held?.done && held.toolCallId === read.call) read.done = true;
    }
    return { history: shaped.messages.slice(0, history.length), turnPrefix: shaped.messages.slice(history.length), block: renderSkillsRead(shaped.reads) };
  }

  pi.registerTool({
    name: "skill",
    label: "Skill",
    description:
      'Method notes from this run\'s packs. The index is in your instructions ("Skills carried by this run"): load a note with skill(id) before you work that kind of artefact. Plain Markdown comes back, with the notes it builds on listed with their cost (not loaded). id is as listed, or pack:id when more than one pack carries it (pack:area/topic). A note already in your context is not sent again. With no id: the index, when your instructions do not carry it whole. Finish a note with skill_done.',
    promptSnippet: "Load a method note from an installed pack",
    promptGuidelines: [
      'Before you work an artefact class, find it in the index under "Skills carried by this run" and load its note with skill(id).',
      "Load a note once, apply it, then skill_done(id, note); load again after a compaction if you still need it.",
    ],
    parameters: Type.Object({
      id: Type.Optional(Type.String({ description: "Skill id as listed (area/topic), or pack:id (pack:area/topic). Omit for the index." })),
    }),
    execute: inTurn(runSkill),
  });

  pi.registerTool({
    name: "skill_done",
    label: "Skill done",
    description:
      "Say you are finished with a skill note you loaded: its id, and one line on what you took from it or why it did not apply. It is recorded for the report, and the note may leave your context; skill(id) brings it back.",
    promptSnippet: "Mark a loaded skill note finished",
    promptGuidelines: ["Call skill_done(id, note) when the topic a note covers is finished, before you load a fourth."],
    parameters: Type.Object({
      id: Type.String({ description: "The id you loaded, as skill() gave it." }),
      note: Type.Optional(Type.String({ description: "One line: what you took from it, or why it did not apply." })),
    }),
    execute: inTurn(runSkillDone),
  });

  return { promptSection, handoffLine, summaryInput, ledger };
}
