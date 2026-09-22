/**
 * What a board of posts adds up to.
 *
 * The Every-post tab showed a thread, its pulse line, and then a page of
 * white space — a strange thing to do with the only record of how ten
 * strangers divided a case between them. Everything here is counted from the
 * posts themselves; no model is asked what it thinks happened.
 *
 * Kept pure and out of the components so the arithmetic can be tested. A
 * wrong count in a panel that claims to be an audit trail is worse than no
 * panel at all.
 */
import type { PostTag, TimedPost } from "./types.ts";

/** The protocol's vocabulary, in the order the board uses it. */
export const TAGS: PostTag[] = ["intro", "ask", "claim", "result", "hold", "veto", "stop"];

/** Where the board caught: somebody held, vetoed or called a stop. */
export const FRICTION: PostTag[] = ["hold", "veto", "stop"];

export type SpeakerRow = {
  id: string;
  posts: number;
  chars: number;
  tags: Record<string, number>;
  firstAt: string | null;
  lastAt: string | null;
  /** The last name this author signed a post with, when it signed one. */
  name: string | null;
};

/** A gap in the conversation: the post before it, and the one that ended it. */
export type Silence = { ms: number; before: TimedPost; after: TimedPost };

export type Mention = { from: string; to: string; n: number };

export type Artefact = { path: string; n: number; by: string[] };

export type BoardStats = {
  posts: number;
  /** Posts the harness itself wrote; they are not one of the team's voices. */
  system: number;
  threads: number;
  chars: number;
  spanMs: number;
  medianGapMs: number;
  busiest: { minute: string; n: number } | null;
  tags: Array<{ tag: string; n: number }>;
  speakers: SpeakerRow[];
  /** Team members who never posted at all. */
  mute: string[];
  silences: Silence[];
  mentions: Mention[];
  /** Agents nobody ever named in a post. */
  unnamed: string[];
  friction: TimedPost[];
  artefacts: Artefact[];
};

function ms(at: string | null | undefined): number {
  const t = at ? Date.parse(at) : NaN;
  return Number.isFinite(t) ? t : NaN;
}

function median(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

/**
 * Paths the board talked about.
 *
 * Only the harness's own directories count — `work/`, `inputs/`, `catalog/`
 * and the rest. A bare filename in prose is too easy to get wrong, and a
 * wrong citation in a forensic console is worse than no citation.
 */
const PATH_RE = /\b(?:work|inputs|catalog|ledger|threads|done|tools)\/[A-Za-z0-9._\-/]+/g;

function cleanPath(raw: string): string {
  return raw.replace(/[.,;:)\]`'"]+$/, "");
}

/**
 * Who named whom.
 *
 * Agent ids are matched literally — `s821c03` cannot be anything else — and
 * naming yourself does not count. Chosen names are deliberately not matched:
 * they are prose ("Vault unlock", "Laptop Recon"), and matching them would
 * count every sentence about the vault as naming an agent.
 */
function mentionsIn(body: string, ids: string[], self: string): string[] {
  const out: string[] = [];
  for (const id of ids) {
    if (id === self) continue;
    if (body.includes(id)) out.push(id);
  }
  return out;
}

const PAIR = "->";

export function boardStats(posts: TimedPost[], team: string[]): BoardStats {
  const ordered = [...posts].sort((a, b) => (ms(a.at) || 0) - (ms(b.at) || 0) || a.id - b.id);
  const voices = ordered.filter((p) => p.from !== "system");
  const ids = [...new Set([...team, ...voices.map((p) => p.from)])];

  const tagCount = new Map<string, number>();
  const bySpeaker = new Map<string, SpeakerRow>();
  const mentionCount = new Map<string, number>();
  const artefacts = new Map<string, { n: number; by: Set<string> }>();
  const perMinute = new Map<string, number>();

  for (const p of ordered) {
    const minute = p.at ? p.at.slice(0, 16) : "";
    if (minute) perMinute.set(minute, (perMinute.get(minute) ?? 0) + 1);
    for (const raw of p.body.match(PATH_RE) ?? []) {
      const path = cleanPath(raw);
      if (path.length < 6) continue;
      const row = artefacts.get(path) ?? { n: 0, by: new Set<string>() };
      row.n += 1;
      row.by.add(p.from);
      artefacts.set(path, row);
    }
    if (p.from === "system") continue;
    tagCount.set(p.tag, (tagCount.get(p.tag) ?? 0) + 1);
    const row = bySpeaker.get(p.from) ?? { id: p.from, posts: 0, chars: 0, tags: {}, firstAt: null, lastAt: null, name: null };
    row.posts += 1;
    row.chars += p.body.length;
    row.tags[p.tag] = (row.tags[p.tag] ?? 0) + 1;
    row.firstAt = row.firstAt ?? p.at;
    row.lastAt = p.at ?? row.lastAt;
    if (p.name) row.name = p.name;
    bySpeaker.set(p.from, row);
    // `to` is an address; the body is where agents actually name each other.
    // Both count, once per post per pair.
    const named = new Set(mentionsIn(p.body, ids, p.from));
    if (p.to && p.to !== "all" && p.to !== p.from) named.add(p.to);
    for (const to of named) {
      const key = `${p.from}${PAIR}${to}`;
      mentionCount.set(key, (mentionCount.get(key) ?? 0) + 1);
    }
  }

  const stamps = voices.map((p) => ms(p.at)).filter((n) => Number.isFinite(n));
  const gaps: number[] = [];
  const silences: Silence[] = [];
  for (let i = 1; i < voices.length; i += 1) {
    const a = ms(voices[i - 1].at);
    const b = ms(voices[i].at);
    if (!Number.isFinite(a) || !Number.isFinite(b)) continue;
    gaps.push(b - a);
    silences.push({ ms: b - a, before: voices[i - 1], after: voices[i] });
  }
  silences.sort((a, b) => b.ms - a.ms);

  const mentions: Mention[] = [...mentionCount.entries()]
    .map(([key, n]) => {
      const [from, to] = key.split(PAIR);
      return { from, to, n };
    })
    .sort((a, b) => b.n - a.n || a.from.localeCompare(b.from));

  const mentioned = new Set(mentions.map((m) => m.to));
  const busiest = [...perMinute.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];

  return {
    posts: ordered.length,
    system: ordered.length - voices.length,
    threads: new Set(ordered.map((p) => p.thread)).size,
    chars: ordered.reduce((sum, p) => sum + p.body.length, 0),
    spanMs: stamps.length > 1 ? Math.max(...stamps) - Math.min(...stamps) : 0,
    medianGapMs: median(gaps),
    busiest: busiest ? { minute: busiest[0], n: busiest[1] } : null,
    tags: TAGS.map((tag) => ({ tag, n: tagCount.get(tag) ?? 0 })).filter((t) => t.n > 0),
    speakers: [...bySpeaker.values()].sort((a, b) => b.posts - a.posts || a.id.localeCompare(b.id)),
    mute: team.filter((id) => !bySpeaker.has(id)),
    silences: silences.slice(0, 3),
    mentions,
    unnamed: ids.filter((id) => !mentioned.has(id)).sort(),
    friction: ordered.filter((p) => FRICTION.includes(p.tag)),
    artefacts: [...artefacts.entries()]
      .map(([path, row]) => ({ path, n: row.n, by: [...row.by].sort() }))
      .sort((a, b) => b.n - a.n || a.path.localeCompare(b.path))
      .slice(0, 10),
  };
}
