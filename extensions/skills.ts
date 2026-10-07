/**
 * Skills: a run's packs as a seat meets them.
 *
 * A pack's method is a tree of small files (docs/packs.md, section 1). Four
 * things decide whether a seat uses it, and this module is all four:
 *
 * - The index is a section of the seat's system prompt. The kickoff renders it
 *   into `.pi/APPEND_SYSTEM.md` (scripts/skills-section.ts), which Pi puts in
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
 *   body releasable in the ledger below and records the event. Releasing it
 *   (replacing it in the seat's context with a stub) is the unloader's job and
 *   is not done here: `SkillLedger.releasable()` is its entry point.
 *
 * The module knows no pack and no tool by name: it reads `skills/INDEX.md` and
 * `skills/<id>.md` of whatever `SWARM_PACK_DIRS` lists, and nothing else.
 */
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
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

export type PackRef = { id: string; version: string; dir: string };
export type IndexEntry = { id: string; line: string; tokens: number };
export type PackIndex = PackRef & {
  entries: IndexEntry[];
  /** The skill the pack declares as its router (`Router:` line of INDEX.md), when it names one the index lists. */
  router: string | null;
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
  try {
    const manifest = JSON.parse(await readFile(join(dir, "pack.json"), "utf8")) as { id?: unknown; version?: unknown };
    if (typeof manifest.id === "string" && PACK_ID.test(manifest.id)) id = manifest.id;
    if (typeof manifest.version === "string") version = manifest.version;
  } catch {
    // a pack directory without a readable manifest is still a directory of skills
  }
  return { id, version, dir };
}

/** The entries of one INDEX.md, and the router it names. */
export function parseIndex(text: string): { entries: IndexEntry[]; router: string | null } {
  const entries: IndexEntry[] = [];
  let router: string | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const entry = /^- `([^`]+)`/.exec(line);
    if (entry) {
      entries.push({ id: entry[1]!, line, tokens: estimateTokens(line) });
      continue;
    }
    const named = /^Router: `([^`]+)`\s*$/.exec(line);
    if (named) router = named[1]!;
  }
  if (router && !entries.some((e) => e.id === router)) router = null;
  return { entries, router };
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
  out.tokens = parsed.entries.reduce((sum, e) => sum + e.tokens, 0);
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
  packs: Array<{ id: string; version: string; skills: number; tokens: number; shown: "full" | "router"; router: string | null }>;
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
      `This index is over its budget (${fmt(indexTokens)} tokens of entries; ${fmt(budget.pack)} a pack, ${fmt(budget.run)} the run), so a pack marked "router only" shows the one note that routes to the rest: load it and it names the notes under it. skill() with no id lists every skill of every pack.`,
    );
  }
  let shownTokens = 0;
  for (const p of live) {
    const router = shown.get(p.id) === "router";
    lines.push("");
    lines.push(`${p.id}${p.version ? ` ${p.version}` : ""} (${p.entries.length} skill${p.entries.length === 1 ? "" : "s"}${router ? ", router only" : ""})`);
    for (const entry of p.entries) {
      if (router && entry.id !== p.router) continue;
      lines.push(entryLine(p, entry, colliding));
      shownTokens += entry.tokens;
    }
  }
  const text = live.length ? lines.join("\n") : "";
  const report: SectionReport = {
    mode: collapsed ? "routers" : "full",
    packs: live.map((p) => ({ id: p.id, version: p.version, skills: p.entries.length, tokens: p.tokens, shown: shown.get(p.id)!, router: p.router })),
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
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  if (!m) return { meta: {}, body: text.trim() };
  const meta: SkillMeta = {};
  for (const line of m[1]!.split("\n")) {
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
  };
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

export type Located = { pack: PackRef; id: string; /** The other packs of the run that carry the same bare id. */ others: PackRef[] };

export async function locateSkill(packs: PackRef[], wanted: Wanted): Promise<{ found: Located } | { missing: "no such pack" | "no such skill" }> {
  const has = (pack: PackRef) => exists(join(pack.dir, "skills", `${wanted.id}.md`));
  if (wanted.pack) {
    const pack = packs.find((p) => p.id === wanted.pack);
    if (!pack) return { missing: "no such pack" };
    return (await has(pack)) ? { found: { pack, id: wanted.id, others: [] } } : { missing: "no such skill" };
  }
  const carrying: PackRef[] = [];
  for (const pack of packs) if (await has(pack)) carrying.push(pack);
  if (!carrying.length) return { missing: "no such skill" };
  return { found: { pack: carrying[0]!, id: wanted.id, others: carrying.slice(1) } };
}

/** Ids a seat probably meant: the bare id under a pack prefix or a tool name is the shape 17 of 143 calls got wrong. */
export function suggestIds(packs: PackIndex[], asked: string, limit = 5): string[] {
  const wanted = asked.toLowerCase().replace(/^.*:/, "").replace(/\.md$/, "");
  const segments = wanted.split("/").filter(Boolean);
  const last = segments[segments.length - 1] ?? wanted;
  const lastTwo = segments.slice(-2).join("/");
  const colliding = collidingIds(packs);
  const scored: Array<{ ref: string; score: number }> = [];
  for (const pack of packs) {
    for (const entry of pack.entries) {
      const id = entry.id;
      let score = 0;
      if (lastTwo && id === lastTwo) score = 4;
      else if (id.endsWith(`/${last}`) || id === last) score = 3;
      else if (wanted.includes(id) || id.includes(wanted)) score = 2;
      else if (segments.some((s) => s.length > 3 && id.split("/").includes(s))) score = 1;
      if (score) scored.push({ ref: colliding.has(id) ? `${pack.id}:${id}` : id, score });
    }
  }
  // A good match hides the weak ones: a near-miss on a pack prefix should name the one id, not a third of the pack.
  const best = scored.reduce((m, s) => Math.max(m, s.score), 0);
  return scored
    .filter((s) => s.score >= (best >= 3 ? 3 : 1))
    .sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref))
    .slice(0, limit)
    .map((s) => s.ref);
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
  /** Set by `skill_done`. */
  done?: { turn: number; note: string };
};

/**
 * The bodies one seat holds, as far as the harness can know: what it fetched
 * since its last compaction. A compaction summarises every body away (the kept
 * tail may hold the newest, which is not worth the guess), so after one the
 * ledger is empty and the same call delivers the body again.
 *
 * The unloader (not built here) takes `releasable()` at a turn boundary,
 * replaces each body's tool result with a stub and calls `release(key)`; from
 * then on `skill(id)` delivers the body again.
 */
export class SkillLedger {
  private live = new Map<string, SkillLoad>();
  /** What the last compaction took out of the context, not fetched again since. */
  private lost: SkillLoad[] = [];
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

  /** The unloader replaced this body in the context: it is no longer held. */
  release(key: string): void {
    this.live.delete(key);
  }

  /** A compaction ran: nothing fetched before it is in the context any more. */
  onCompaction(): SkillLoad[] {
    const taken = [...this.live.values()];
    this.lost = taken;
    this.live.clear();
    this.indexTurn = null;
    return taken;
  }

  /** Skills the seat held when it last handed off, for the line under the hand-off header. */
  handoffIds(): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const load of [...this.lost, ...this.live.values()]) {
      if (seen.has(load.key)) continue;
      seen.add(load.key);
      out.push(load.key);
    }
    return out;
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
// The tools
// ---------------------------------------------------------------------------

export type SkillsDeps = {
  packDirs: string[];
  agentId: () => string;
  /** One trace line; the extension's own `logEvent`, so attribution and the collector are the same. */
  trace: (cwd: string, tool: string, args: Record<string, unknown>, result: unknown, durationMs?: number) => Promise<void>;
  /** How many turns this seat has finished. */
  turns: () => number;
  /** A fault the operator and the peers should see (the extension posts it on the board). */
  fault: (cwd: string, message: string) => Promise<void>;
};

export type SkillsHandle = {
  /**
   * What to add to the forced system prompt, with its leading blank line:
   * nothing when `basePrompt` (Pi's own rendering of the seat's prompt) already
   * carries the Skills section, the section itself when it does not, and
   * nothing when the packs carry no skills. Writes the one `skills_index` row.
   */
  promptSection: (cwd: string, basePrompt: string) => Promise<string>;
  /** The line the hand-off header carries: the skills this seat held before its context was compacted. Empty when none. */
  handoffLine: () => string;
  ledger: SkillLedger;
};

function text(value: string, details: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: value }], details };
}

export function registerSkills(pi: ExtensionAPI, deps: SkillsDeps): SkillsHandle {
  const ledger = new SkillLedger();
  let indexes: Promise<PackIndex[]> | null = null;
  const packIndexes = () => (indexes ??= readPackIndexes(deps.packDirs));
  let section: Promise<{ text: string; report: SectionReport }> | null = null;
  let sectionLogged = false;

  const sectionOnce = async () => (section ??= packIndexes().then((all) => renderSkillsSection(all)));

  /** The Skills section, and the one trace row that says what it carried, where it came from, or that it could not be built. */
  async function promptSection(cwd: string, basePrompt: string): Promise<string> {
    let built: { text: string; report: SectionReport };
    try {
      built = await sectionOnce();
    } catch (err) {
      built = { text: "", report: { unreadable: [{ pack: "*", reason: err instanceof Error ? err.message : String(err) }] } as SectionReport };
    }
    // Pi's own rendering of the prompt carries it when the kickoff wrote .pi/APPEND_SYSTEM.md.
    const inBase = built.text !== "" && basePrompt.includes(SKILLS_SECTION_TITLE);
    if (!sectionLogged) {
      sectionLogged = true;
      const { report } = built;
      const failed = report.unreadable ?? [];
      const source = built.text === "" ? "none" : inBase ? "prompt" : "extension";
      await deps
        .trace(cwd, "skills_index", {}, { ok: failed.length === 0, source, ...(inBase ? { matches_packs: basePrompt.includes(built.text) } : {}), ...report })
        .catch(() => undefined);
      if (failed.length) {
        await deps
          .fault(
            cwd,
            `HARNESS FAULT: the Skills section of ${deps.agentId() || "this agent"}'s prompt could not list ${failed.map((f) => `${f.pack} (${f.reason})`).join(", ")}. Those packs' skills are not in the index this seat was given: it can still call skill() with no id and skill(id).`,
          )
          .catch(() => undefined);
      }
    }
    return built.text && !inBase ? `\n\n${built.text}` : "";
  }

  function handoffLine(): string {
    const ids = ledger.handoffIds();
    return ids.length ? `Skill bodies you had loaded, now out of your context: ${ids.join(", ")}. Load again (skill(id)) the ones you still need.` : "";
  }

  pi.on("session_compact", async () => {
    ledger.onCompaction();
  });

  const packRefs = async (): Promise<PackIndex[]> => packIndexes();

  pi.registerTool({
    name: "skill",
    label: "Skill",
    description:
      'Method notes from this run\'s packs. The index is in your instructions ("Skills carried by this run"): load a note with skill(id) before you work that kind of artefact. Plain Markdown comes back, with the notes it builds on listed with their cost (not loaded). id is as listed, or pack:id when more than one pack carries it, for example execution/prefetch or windows-forensics:execution/prefetch. A note already in your context is not sent again. With no id: the index, when your instructions do not carry it whole. Finish a note with skill_done.',
    promptSnippet: "Load a method note from an installed pack",
    promptGuidelines: [
      'Before you work an artefact class, find it in the index under "Skills carried by this run" and load its note with skill(id).',
      "Load a note once, apply it, then skill_done(id, note); load again after a compaction if you still need it.",
    ],
    parameters: Type.Object({
      id: Type.Optional(Type.String({ description: "Skill id as listed (execution/prefetch), or pack:id (windows-forensics:execution/prefetch). Omit for the index." })),
    }),
    async execute(toolCallId: string, params: { id?: string }, _signal: unknown, _onUpdate: unknown, toolCtx: { cwd: string }) {
      const started = Date.now();
      const cwd = toolCtx.cwd;
      const turn = deps.turns() + 1;
      const wantedRaw = typeof params?.id === "string" ? params.id.trim() : "";
      const all = await packRefs();

      if (!wantedRaw) {
        const built = await sectionOnce().catch(() => null);
        const inPrompt = built !== null && built.text !== "" && built.report.mode === "full";
        const shownAt = ledger.indexShownAt();
        let out: string;
        if (inPrompt) out = `The whole index of this run's packs is in your instructions, under "${SKILLS_SECTION_TITLE}". Load a note with skill(id).`;
        else if (shownAt !== null) out = `The index was already listed at turn ${shownAt}; it is still in your context. Load a note with skill(id).`;
        else {
          out = renderFullIndex(all);
          ledger.markIndexShown(turn);
        }
        await deps.trace(cwd, "skill", { id: "INDEX" }, { ok: true, bytes: Buffer.byteLength(out), tokens: estimateTokens(out), in_prompt: inPrompt, ...(shownAt !== null && !inPrompt ? { already_loaded: true, loaded_at_turn: shownAt } : {}) }, Date.now() - started);
        return text(out, { ok: true, index: true, in_prompt: inPrompt });
      }

      const wanted = parseWanted(wantedRaw);
      if (!wanted) {
        await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: "bad id" }, Date.now() - started);
        const out = 'A skill id is lower case and slash separated, as listed in your instructions ("execution/prefetch"), optionally with its pack in front ("windows-forensics:execution/prefetch").';
        return text(out, { ok: false, error: "bad id" });
      }

      const located = await locateSkill(all, wanted);
      if ("missing" in located) {
        const maybe = suggestIds(all, wantedRaw);
        await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: located.missing, ...(maybe.length ? { suggested: maybe } : {}) }, Date.now() - started);
        const which = located.missing === "no such pack" ? `No pack "${wanted.pack}" in this run (it carries: ${all.map((p) => p.id).join(", ") || "none"}).` : `No skill "${wantedRaw}" in this run's packs.`;
        const out = `${which}${maybe.length ? ` Did you mean: ${maybe.join(", ")}?` : ""} The ids are in your instructions ("${SKILLS_SECTION_TITLE}"); skill() with no id lists them.`;
        return text(out, { ok: false, error: located.missing, suggested: maybe });
      }

      const { pack, id, others } = located.found;
      const key = SkillLedger.key(pack.id, id);
      const held = ledger.get(key);
      if (held) {
        const out = `\`${id}\` (${pack.id}) is already in your context, loaded at turn ${held.turn}${held.done ? " and marked done" : ""}; not sent again.`;
        await deps.trace(cwd, "skill", { id }, { ok: true, already_loaded: true, pack: pack.id, loaded_at_turn: held.turn, turn, sha256: held.sha256, tokens_saved: held.tokens }, Date.now() - started);
        return text(out, { ok: true, already_loaded: true, id, pack: pack.id, loaded_at_turn: held.turn });
      }

      const file = await readSkillFile(pack, id);
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
      const working = ledger.working();
      const lines: string[] = [`Skill \`${id}\` (pack ${pack.id}${pack.version ? ` ${pack.version}` : ""}, about ${fmt(file.tokens)} tokens)${file.title ? `: ${file.title}` : ""}`, "", file.body];
      const tail: string[] = [];
      if (needs.length) {
        tail.push(
          `Builds on, not loaded: ${needs.map((n) => (n.tokens === null ? `\`${n.ref}\` (not carried by this run's packs)` : n.loaded_at_turn !== undefined ? `\`${n.ref}\` (already loaded, turn ${n.loaded_at_turn})` : `\`${n.ref}\` (about ${fmt(n.tokens)} tokens)`)).join(", ")}. Load those you need.`,
        );
      }
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
          ...(working.length >= MAX_LIVE_SKILLS ? { holding: working.length } : {}),
        },
        Date.now() - started,
      );
      return text(delivered, { ok: true, id, pack: pack.id, pack_version: pack.version, sha256: file.sha256, bytes: file.bytes, tokens: file.tokens, turn, needs, also_in: others.map((p) => p.id) });
    },
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
    async execute(_toolCallId: string, params: { id: string; note?: string }, _signal: unknown, _onUpdate: unknown, toolCtx: { cwd: string }) {
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
        await deps.trace(cwd, "skill_done", { id: raw, ...(note ? { note } : {}) }, { ok: false, error: reason, turn }, Date.now() - started);
        const out =
          reason === "ambiguous"
            ? `More than one pack's \`${raw}\` is loaded: name it as pack:id (${held.map((l) => l.key).join(", ")}).`
            : `\`${raw}\` is not among the notes you have loaded (none, or a compaction took it out of your context). Nothing to mark done.`;
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
      return text(already ? `\`${target.id}\` was already marked done (turn ${target.done!.turn}).` : `Recorded: \`${target.id}\` is done. Load it again with skill("${target.id}") if you need it later.`, { ok: true, id: target.id, pack: target.pack });
    },
  });

  return { promptSection, handoffLine, ledger };
}
