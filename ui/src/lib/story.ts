/**
 * The board, as a story.
 *
 * A swarm's main thread is a negotiation followed by work followed by a
 * sign-off, with the harness interjecting when it has to. Read as a flat list
 * of 30 posts it is noise; read as phases it is a narrative an operator can
 * follow in ten seconds. The grouping is deliberately simple — tags and order,
 * nothing clever — so it never claims more than the board actually says.
 */
import type { PostTag, TimedPost } from "./types";

export type PhaseKind = "joining" | "negotiating" | "building" | "signoff" | "harness" | "stopped" | "aftermath";

export type Phase = {
  kind: PhaseKind;
  title: string;
  /** One quiet line under the title. */
  summary: string;
  posts: TimedPost[];
};

const TITLES: Record<PhaseKind, string> = {
  joining: "Joining",
  negotiating: "Negotiating slices",
  building: "Building",
  signoff: "Sign-off",
  harness: "The harness speaks",
  stopped: "Stopped",
  aftermath: "After the sentinel",
};

export function isApproval(post: TimedPost): boolean {
  return /^approved\b/i.test(post.body.trim());
}

/** Which phase a single post belongs to, given the phase the story is in. */
/** A system `stop` post is either the steer ("finish what is in hand") or the sentinel itself. */
function isSentinelPost(post: TimedPost): boolean {
  return /done\/SWARM_DONE/.test(post.body);
}

function kindOf(post: TimedPost, current: PhaseKind | null): PhaseKind {
  // `system via <seat>` is a seat's harness code in its VM: the seat's
  // word, placed in the story as the seat's post, never the harness's.
  if (post.from === "system" && !post.via) return post.tag === "stop" && isSentinelPost(post) ? "stopped" : "harness";
  // Once the sentinel is announced, whatever the agents still say is
  // aftermath — a late approval or a last note — not a new phase of work.
  if (current === "stopped" || current === "aftermath") return "aftermath";
  if (isApproval(post)) return "signoff";
  const tag = post.tag as PostTag;
  if (tag === "intro") return current === null || current === "joining" ? "joining" : current;
  if (tag === "result") return current === "signoff" ? "signoff" : "building";
  if (tag === "stop") return "stopped";
  // ask / claim / hold / veto: negotiation, unless the build is already under
  // way — then it is the team talking while it works.
  if (current === "building" || current === "signoff") return current;
  return "negotiating";
}

function summarise(kind: PhaseKind, posts: TimedPost[]): string {
  const who = new Set(posts.map((p) => p.from));
  switch (kind) {
    case "joining":
      return `${posts.length} intro${posts.length === 1 ? "" : "s"} from ${who.size} agent${who.size === 1 ? "" : "s"}`;
    case "negotiating": {
      const asks = posts.filter((p) => p.tag === "ask").length;
      const claims = posts.filter((p) => p.tag === "claim").length;
      const holds = posts.filter((p) => p.tag === "hold" || p.tag === "veto").length;
      const parts = [asks ? `${asks} ask${asks === 1 ? "" : "s"}` : "", claims ? `${claims} claim${claims === 1 ? "" : "s"}` : "", holds ? `${holds} hold/veto` : ""].filter(Boolean);
      return parts.join(" · ") || `${posts.length} posts`;
    }
    case "building":
      return `${posts.length} result${posts.length === 1 ? "" : "s"} from ${who.size} agent${who.size === 1 ? "" : "s"}`;
    case "signoff": {
      const hashes = new Set(posts.filter(isApproval).map((p) => p.body.trim().split(/\s+/)[1] ?? ""));
      const n = posts.filter(isApproval).length;
      return hashes.size === 1 ? `${n} approval${n === 1 ? "" : "s"} on the same hash` : `${n} approval${n === 1 ? "" : "s"} on ${hashes.size} different hashes`;
    }
    case "harness":
      return `${posts.length} announcement${posts.length === 1 ? "" : "s"}`;
    case "stopped": {
      // The system post says who wrote the sentinel: an agent that met the
      // definition of done, or the harness itself after a cap or wall clock.
      const body = posts[0]?.body ?? "";
      const byAgent = /written by ([\w-]+)/.exec(body);
      if (byAgent) return `${byAgent[1]} wrote the sentinel`;
      if (/harness wrote/i.test(body)) return "the harness ended the run";
      return "the run ended";
    }
    case "aftermath": {
      const late = posts.filter(isApproval).length;
      return late ? `${late} late approval${late === 1 ? "" : "s"} after the sentinel` : `${posts.length} post${posts.length === 1 ? "" : "s"} after the sentinel`;
    }
  }
}

/** Group a thread's posts into phases, in order. Consecutive posts of one kind share a phase. */
export function storyOf(posts: TimedPost[]): Phase[] {
  const sorted = [...posts].sort((a, b) => a.id - b.id);
  const phases: Phase[] = [];
  let current: PhaseKind | null = null;
  for (const post of sorted) {
    const kind = kindOf(post, current);
    const last = phases[phases.length - 1];
    if (last && last.kind === kind) {
      last.posts.push(post);
    } else {
      phases.push({ kind, title: TITLES[kind], summary: "", posts: [post] });
    }
    // Harness interjections do not move the story forward.
    if (kind !== "harness") current = kind;
  }
  for (const phase of phases) phase.summary = summarise(phase.kind, phase.posts);
  return phases;
}

/** The approvals on one content hash, if the sign-off has converged. */
export function agreedHash(posts: TimedPost[]): { hash: string; by: string[] } | null {
  const byHash = new Map<string, Set<string>>();
  for (const post of posts) {
    if (!isApproval(post)) continue;
    const hash = post.body.trim().split(/\s+/)[1];
    if (!hash) continue;
    if (!byHash.has(hash)) byHash.set(hash, new Set());
    byHash.get(hash)!.add(post.from);
  }
  let best: { hash: string; by: string[] } | null = null;
  for (const [hash, who] of byHash) {
    if (!best || who.size > best.by.length) best = { hash, by: [...who] };
  }
  return best;
}
