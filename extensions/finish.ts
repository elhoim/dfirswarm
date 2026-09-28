/**
 * The finish: one coordinator, one check result per revision, readiness
 * shown to everyone, and typed acts around the report (docs/adr/0015).
 *
 * On ctf12 every seat called `done` when the last attest landed: Belka had
 * nine calls by six seats in 58 s and three sentinels in one second, c09 all
 * eight seats in 61 s, and the tail from every question answered to the
 * sentinel ran 33 to 64 minutes. Three things fed it, each verified in the
 * code: the late-posts rule fired once per seat and asked each to explain
 * itself on the board, which made the next seat's late post; historical
 * limiting closes blocked after their questions were answered; and the
 * prompt told every seat to call done. Here:
 *
 * - One coordinator holds the finish, by a lease with a generation in
 *   `leads/finish.jsonl` (a chain, the lead register's helpers). It is the
 *   seat that published the report last when the lease is first needed, or
 *   the first seat to call done; a seat that is done, dead, compacting or
 *   silent past the stale limit is unavailable, and the next seat's done
 *   takes the lease over (generation + 1). Any other seat's `done` is
 *   answered "not yours", quietly: no board post, no finish line run, not a
 *   refusal.
 * - Readiness is computed from the registers for every revision (the open
 *   leads, the questions' answers and the ledger gate over them, the
 *   negatives, best candidates and route limitations), shown in every
 *   header, and posted once each time it turns ready or back.
 * - A check (the operator's finish line run for a done) is recorded with
 *   the revision it ran against, and a done at the same revision takes that
 *   result instead of running it again.
 * - The report is reviewed with typed acts: an ack of its digest ("no
 *   objection") is not a late post; an objection, or a result or veto
 *   posted after the report was written, needs the coordinator's typed
 *   resolution (folded into the report, or not material, with why) before
 *   the done goes on. Reading them is not enough.
 * - The final check is atomic over the report's digest and the state
 *   revision (protocol.ts stateRevision: the board's verdict posts, the
 *   ledger and its review, the leads, the questions, the jobs, the policy
 *   and the operator's decisions): the sentinel is written only while that
 *   revision still holds.
 *
 * Nothing here judges an answer or reads a case: the registers say what is
 * open, and the operator's checks say whether the goal is met.
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import type { Dirent } from "node:fs";
import { appendFile, mkdir, readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import * as L from "./leads.ts";
import * as NB from "./negative-bar.ts";
import * as P from "./protocol.ts";

export const FINISH_LOG = "leads/finish.jsonl";
/** How a done that is not the coordinator's is answered: quietly, never as a refusal. */
export const NOT_YOURS = "not yours: ";
/** The finish register's own lock: a lease is taken and a check recorded under it, never under the registers' (a done's sentinel is). */
const FINISH_LOCK = ".finish.lock";

export type FinishEventKind = "lease" | "ack" | "resolve" | "readiness" | "check";

export type FinishEvent = {
  v: 1;
  seq: number;
  at: string;
  by: string;
  ev: FinishEventKind;
  /** lease: who holds it now, at which generation, whom it was taken from, and why. */
  holder?: string;
  generation?: number;
  from?: string;
  why?: string;
  /** lease: the report the finish stands on (the path a done names). */
  report?: string;
  /**
   * lease: when the report was written as the finish began (ms since the
   * epoch): a result or veto posted after it is late against the report, and
   * stays so through every later version of it until a resolution answers it.
   */
  since?: number;
  /** ack: the report's digest the review is of, and its verdict. */
  digest?: string;
  verdict?: "no_objection" | "objection";
  /** resolve: the late post (its id) or the objection (its ack's seq) it resolves, and how; ack and resolve: the report's digest (a folded resolution names the version it was folded into). */
  post?: number;
  ack?: number;
  how?: "folded" | "not_material";
  /** readiness: whether the registers say the finish line is met, at which revision, and what holds it. */
  ready?: boolean;
  revision?: string;
  items?: string[];
  /** check: what the finish line said at that revision. */
  proceed?: boolean;
  outcome?: string;
  reason?: string;
  run?: unknown;
  prev: string;
  hash: string;
};

export type FinishState = {
  events: FinishEvent[];
  lease: { holder: string; generation: number; at: string; why: string; report: string | null; since: number | null; from?: string } | null;
  acks: Array<{ seq: number; at: string; by: string; digest: string; verdict: "no_objection" | "objection"; why: string }>;
  resolutions: Array<{ seq: number; at: string; by: string; post?: number; ack?: number; how: "folded" | "not_material"; why: string; digest: string | null }>;
  readiness: { ready: boolean; revision: string; items: string[]; at: string } | null;
  checks: Array<{ seq: number; at: string; by: string; revision: string; proceed: boolean; outcome?: string; reason?: string; run?: unknown }>;
  chain: { ok: boolean; broken_at: number | null; reason: string | null; head: string | null };
};

export async function readFinish(sandboxRoot: string): Promise<FinishState> {
  const text = await readFile(join(sandboxRoot, FINISH_LOG), "utf8").catch(() => "");
  const chain = L.verifyLeadChain(text);
  const events: FinishEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as FinishEvent);
    } catch {
      // The chain check names it.
    }
  }
  const st: FinishState = { events, lease: null, acks: [], resolutions: [], readiness: null, checks: [], chain };
  for (const e of events) {
    switch (e.ev) {
      case "lease":
        if (e.holder) {
          // The earliest anchor a lease ever named stays: what was late against the report stays late.
          const since = typeof e.since === "number" ? (typeof st.lease?.since === "number" ? Math.min(st.lease.since, e.since) : e.since) : (st.lease?.since ?? null);
          st.lease = { holder: e.holder, generation: e.generation ?? (st.lease?.generation ?? 0) + 1, at: e.at, why: e.why ?? "", report: e.report ?? st.lease?.report ?? null, since, ...(e.from ? { from: e.from } : {}) };
        }
        break;
      case "ack":
        if (e.digest && e.verdict) st.acks.push({ seq: e.seq, at: e.at, by: e.by, digest: e.digest, verdict: e.verdict, why: e.why ?? "" });
        break;
      case "resolve":
        if (e.how) st.resolutions.push({ seq: e.seq, at: e.at, by: e.by, ...(e.post !== undefined ? { post: e.post } : {}), ...(e.ack !== undefined ? { ack: e.ack } : {}), how: e.how, why: e.why ?? "", digest: e.digest ?? null });
        break;
      case "readiness":
        st.readiness = { ready: e.ready === true, revision: e.revision ?? "", items: e.items ?? [], at: e.at };
        break;
      case "check":
        if (e.revision) st.checks.push({ seq: e.seq, at: e.at, by: e.by, revision: e.revision, proceed: e.proceed === true, ...(e.outcome ? { outcome: e.outcome } : {}), ...(e.reason ? { reason: e.reason } : {}), ...(e.run !== undefined ? { run: e.run } : {}) });
        break;
    }
  }
  return st;
}

/** Append finish events under the finish lock the caller holds. */
async function appendFinish(sandboxRoot: string, drafts: Array<Omit<FinishEvent, "v" | "seq" | "at" | "prev" | "hash">>, held: P.HeldLock): Promise<FinishEvent[]> {
  const st = await readFinish(sandboxRoot);
  if (!st.chain.ok) throw new Error(`${FINISH_LOG}'s chain is broken at line ${st.chain.broken_at} (${st.chain.reason}): the finish takes no new act until the operator looks`);
  let prev = st.chain.head ?? "genesis";
  let seq = st.events.length;
  const out: FinishEvent[] = [];
  for (const d of drafts) {
    seq += 1;
    const draft = { v: 1 as const, seq, at: new Date().toISOString(), ...Object.fromEntries(Object.entries(d).filter(([, x]) => x !== undefined)) } as Omit<FinishEvent, "prev" | "hash">;
    const withPrev = { ...draft, prev } as Omit<FinishEvent, "hash">;
    const e = { ...withPrev, hash: L.leadEventHash(withPrev as unknown as L.LeadEvent, prev) } as FinishEvent;
    out.push(e);
    prev = e.hash;
  }
  await mkdir(join(sandboxRoot, L.LEADS_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(sandboxRoot, FINISH_LOG), out.map((e) => `${JSON.stringify(e)}\n`).join(""), "utf8");
  return out;
}

function withFinish<T>(sandboxRoot: string, fn: (held: P.HeldLock) => Promise<T>): Promise<T> {
  return P.withNamedLock(sandboxRoot, FINISH_LOCK, fn);
}

/** The report's sha256, or null while it does not exist. */
export async function reportDigest(sandboxRoot: string, report: string | null | undefined): Promise<string | null> {
  if (!report) return null;
  const bytes = await P.readSandboxFile(sandboxRoot, report).catch(() => null);
  return bytes ? createHash("sha256").update(bytes.bytes).digest("hex") : null;
}

/** Who published the report last: the seat that wrote its newest revision (history/). */
export async function reportPublisher(sandboxRoot: string, report: string): Promise<string | null> {
  const versions = await P.listFileHistory(sandboxRoot, report).catch(() => [] as P.FileVersion[]);
  return versions.at(-1)?.agent ?? null;
}

/**
 * Whether a seat can hold the finish now: a seat (not done, dead or
 * compacting: leads.ts seatAvailable) that has acted within the stale limit
 * or has a job running. A compacting coordinator is unavailable for the
 * whole compaction, so the last done does not wait on it.
 */
export async function coordinatorAvailable(sandboxRoot: string, agent: string, now = Date.now()): Promise<{ available: boolean; why: string }> {
  const activity = await L.recentActivity(sandboxRoot, Math.max(L.leadStaleMs(), L.LEAD_COMPACTION_BOUND_MS), now);
  const seat = await L.seatAvailable(sandboxRoot, agent, activity, now);
  if (!seat.available) return seat;
  const jobs = await L.readJobs(sandboxRoot).catch(() => [] as L.JobFacts[]);
  const live = await L.holderLiveness(sandboxRoot, agent, jobs, activity, now);
  return live.stale ? { available: false, why: live.why } : { available: true, why: live.why };
}

export type FinishTurn = {
  /** This seat coordinates the finish: its done goes on. */
  mine: boolean;
  holder: string;
  generation: number;
  why: string;
  /** Taken over now, from whom (unavailable). */
  took_over?: string;
  report: string | null;
};

/**
 * A seat's done asks for the finish (A4). With no lease yet, the report's
 * last publisher holds it when it can, else the seat asking; a holder that
 * is unavailable (done, dead, compacting, silent) is taken over by the seat
 * asking, at the next generation. Otherwise the finish is the holder's, and
 * this seat's done is "not yours".
 */
export async function finishTurn(ctx: P.SwarmContext, input: { output_file?: string } = {}, now = Date.now()): Promise<FinishTurn> {
  const report = String(input.output_file ?? "").trim() || null;
  const publisher = report ? await reportPublisher(ctx.sandboxRoot, report) : null;
  return withFinish(ctx.sandboxRoot, async (held) => {
    const st = await readFinish(ctx.sandboxRoot);
    const lease = st.lease;
    // Once the sentinel is written the finish is over: a done marker makes its
    // coordinator unavailable, and nobody takes over what has ended.
    if (await P.swarmDoneExists(ctx.sandboxRoot)) return { mine: false, holder: lease?.holder ?? "", generation: lease?.generation ?? 0, why: "the run is finished (done/SWARM_DONE)", report: lease?.report ?? report };
    // When the report was written as the finish began: what is posted after it is late, whatever version follows.
    const writtenAt = async (path: string | null) => (path ? (await P.outputWrittenAt(ctx.sandboxRoot, path)) || null : null);
    if (!lease) {
      const pub = publisher && publisher !== ctx.agentId ? await coordinatorAvailable(ctx.sandboxRoot, publisher, now) : null;
      const holder = pub?.available ? publisher! : ctx.agentId;
      const why = holder === publisher ? `${holder} published ${report} last` : publisher ? `${publisher}, who published ${report} last, is unavailable (${pub?.why}): the first seat to call done holds it` : "the first seat to call done holds it";
      const since = await writtenAt(report);
      await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "lease", holder, generation: 1, why, ...(report ? { report } : {}), ...(since ? { since } : {}) }], held);
      return { mine: holder === ctx.agentId, holder, generation: 1, why, report };
    }
    if (lease.holder === ctx.agentId) {
      // The coordinator's own done names the report: kept current on the lease, with its anchor once it exists.
      const since = lease.since === null ? await writtenAt(report ?? lease.report) : null;
      if ((report && report !== lease.report) || since) await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "lease", holder: lease.holder, generation: lease.generation, why: report && report !== lease.report ? `the report is ${report}` : lease.why, ...(report ? { report } : {}), ...(since ? { since } : {}) }], held);
      return { mine: true, holder: lease.holder, generation: lease.generation, why: lease.why, report: report ?? lease.report };
    }
    const avail = await coordinatorAvailable(ctx.sandboxRoot, lease.holder, now);
    if (avail.available) return { mine: false, holder: lease.holder, generation: lease.generation, why: lease.why, report: lease.report };
    const generation = lease.generation + 1;
    const why = `${lease.holder} is unavailable (${avail.why}): taken over by ${ctx.agentId}`;
    const since = lease.since ?? (await writtenAt(report ?? lease.report));
    await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "lease", holder: ctx.agentId, generation, from: lease.holder, why, ...(report ?? lease.report ? { report: report ?? lease.report! } : {}), ...(since ? { since } : {}) }], held);
    return { mine: true, holder: ctx.agentId, generation, why, took_over: lease.holder, report: report ?? lease.report };
  });
}

/** A seat's done, as the finish answers it: whose it is, what is late against the report, and whether the registers say it is ready. */
export async function finishTurnFor(ctx: P.SwarmContext, input: { output_file?: string } = {}): Promise<FinishTurn & { late: LateItem[]; readiness: { ready: boolean; items: string[]; limited: string[]; revision: string } }> {
  const turn = await finishTurn(ctx, input);
  const r = await readiness(ctx.sandboxRoot);
  return { ...turn, late: turn.mine ? await lateItems(ctx.sandboxRoot, ctx.agentId, turn.report) : [], readiness: { ready: r.ready, items: r.items, limited: r.limited, revision: r.revision } };
}

/** The finish tool's acts: status for anyone, ack for a reviewer, resolve for the coordinator. */
export async function finishAct(ctx: P.SwarmContext, input: { action?: string; digest?: string; verdict?: string; why?: string; post?: unknown; ack?: unknown; how?: string }): Promise<Record<string, unknown>> {
  const action = String(input.action ?? "status").trim();
  if (action === "status") return finishStatus(ctx);
  if (action === "ack") return ackReport(ctx, input);
  if (action === "resolve") return resolveLate(ctx, input);
  return { ok: false, reason: "action is status, ack or resolve" };
}

/** Whether a seat may write the sentinel: it holds the finish, or nobody does, or the holder is unavailable. */
export async function mayFinish(sandboxRoot: string, agent: string, now = Date.now()): Promise<{ ok: true } | { ok: false; holder: string; reason: string }> {
  const lease = (await readFinish(sandboxRoot)).lease;
  if (!lease || lease.holder === agent) return { ok: true };
  if (!(await coordinatorAvailable(sandboxRoot, lease.holder, now)).available) return { ok: true };
  return { ok: false, holder: lease.holder, reason: `${NOT_YOURS}${lease.holder} coordinates the finish (generation ${lease.generation}); its done ends the run` };
}

/** How a sentinel held by what is late against the report is refused (finishTransaction). */
export const LATE_PENDING = "late against the report: ";

/** A late item in words. */
export function lateWords(x: LateItem): string {
  return x.kind === "post" ? `post #${x.id} (${x.tag}) by ${x.by}` : `objection ${x.id} by ${x.by}: ${x.why}`;
}

/**
 * The finish's part of the one transaction that writes the sentinel (A4):
 * `write` runs under the finish register's lock, so no lease is taken over
 * and no objection is acked between the check and the sentinel, and only
 * while (1) the seat holds the lease at the holder and generation its done
 * began with (`expected`, carried through done; without it, any other
 * holder that can still take the finish refuses it) and (2) nothing late
 * against the report waits for a resolution. What the checks were run
 * against is the caller's to hold (the state revision, under the
 * registers' lock inside `write`). A seat's done marker is written inside
 * `write` too: it makes the seat unavailable, and a takeover waits for the
 * lock until the sentinel is written or the marker gone.
 */
export async function finishTransaction<T>(sandboxRoot: string, agent: string, expected: { holder: string; generation: number } | undefined, write: () => Promise<T>, now = Date.now()): Promise<T> {
  return withFinish(sandboxRoot, async () => {
    const lease = (await readFinish(sandboxRoot)).lease;
    if (expected) {
      if (!lease || expected.holder !== agent || lease.holder !== expected.holder || lease.generation !== expected.generation) {
        throw new Error(`${NOT_YOURS}${lease ? `${lease.holder} holds it at generation ${lease.generation}` : "nobody holds it"}, not ${expected.holder} at generation ${expected.generation}, which this done began with: ${lease && lease.holder !== agent ? `${lease.holder}'s done ends the run` : "call done again"}`);
      }
    } else if (lease && lease.holder !== agent && (await coordinatorAvailable(sandboxRoot, lease.holder, now)).available) {
      throw new Error(`${NOT_YOURS}${lease.holder} coordinates the finish (generation ${lease.generation}); its done ends the run`);
    }
    if (lease) {
      const late = await lateItems(sandboxRoot, lease.holder, lease.report);
      if (late.length) throw new Error(`${LATE_PENDING}${late.map(lateWords).join("; ")}. Each needs the coordinator's typed resolution (finish resolve: folded, saying where the report says it now, or not_material, with why) before the sentinel is written`);
    }
    return write();
  });
}

/**
 * The parts of the state revision the finish adds (protocol.ts
 * stateRevision): the report's digest (the path the lease names), each
 * job's state, the policy (the stop policy, the caps, a pause, the
 * contract and the run's case record when it has one) and the operator's
 * decisions (requests and their answers, hosts allowed). The review's acks
 * are not in it: a typed ack is not a change of state.
 */
export async function finishParts(sandboxRoot: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const lease = (await readFinish(sandboxRoot).catch(() => null))?.lease ?? null;
  if (lease?.report) out.report = `${lease.report}:${(await reportDigest(sandboxRoot, lease.report)) ?? "missing"}`;
  // The shared deliverables a goal's checks read (the report among them, at
  // the top of work/): each by name, size and time, so a check result is
  // never taken for a revision whose deliverables changed since.
  const top: string[] = [];
  for (const d of await readdir(join(sandboxRoot, "work"), { withFileTypes: true }).catch(() => [] as Dirent[])) {
    if (!d.isFile() || d.name.startsWith(".")) continue;
    const st = await stat(join(sandboxRoot, "work", d.name)).catch(() => null);
    if (st) top.push(`${d.name}:${st.size}:${Math.round(st.mtimeMs)}`);
  }
  out.deliverables = P.sha256Hex(top.sort().join("\n"));
  const jobs = await L.readJobs(sandboxRoot).catch(() => [] as L.JobFacts[]);
  out.jobs = P.sha256Hex(jobs.map((j) => `${j.id}:${j.state}:${j.status ?? ""}`).join("\n"));
  // What of each job's stdout its requester was handed (the journal's
  // job_returned): the gate holds a job whose output was read only in part,
  // so a page read after a check (a new unread-output defect), or the rest
  // read after a refusal (its fix), moves the revision. Counted as the bytes
  // still unread of the whole: the same page handed over again moves nothing.
  const reads = await L.stdoutReads(sandboxRoot).catch(() => new Map<string, Map<string, Array<[number, number]>>>());
  const delivered: string[] = [];
  for (const j of jobs) {
    const spans = reads.get(j.id)?.get(j.agent);
    if (!spans?.length) continue;
    const total = await stat(join(sandboxRoot, "store", "jobs", j.id, "stdout.log")).then((x) => x.size).catch(() => 0);
    delivered.push(`${j.id}:${j.agent}:${L.unreadBytes(spans, total)}/${total}`);
  }
  out.delivery = P.sha256Hex(delivered.join("\n"));
  const b = await P.readBudget(sandboxRoot).catch(() => null);
  const policy: Record<string, unknown> = b ? { stop_policy: P.stopPolicyOf(b), until_solved: b.until_solved === true, paused: b.paused ?? null, cap_usd: b.cap_usd, cap_tokens: b.cap_tokens ?? null, wall_clock_minutes: b.wall_clock_minutes } : {};
  for (const rel of ["SWARM.md", "run.json", "policy.json"]) {
    const bytes = await readFile(join(sandboxRoot, rel)).catch(() => null);
    if (bytes) policy[rel] = P.sha256Hex(bytes);
  }
  out.policy = P.sha256Hex(JSON.stringify(P.canonicalValue(policy)));
  const decisions: string[] = [];
  for (const rel of [L.OPERATOR_REQUESTS, L.OPERATOR_HOSTS]) {
    const bytes = await readFile(join(sandboxRoot, rel)).catch(() => null);
    decisions.push(bytes ? `${rel}:${bytes.length}:${P.sha256Hex(bytes)}` : `${rel}:none`);
  }
  out.operator = P.sha256Hex(decisions.join("\n"));
  return out;
}

// --- the report's review ----------------------------------------------------------------------

export type LateItem = { kind: "post" | "objection"; id: number; by: string; tag?: string; why?: string };

/**
 * What the coordinator must answer before its done goes on: each result or
 * veto another seat posted after the report was written as the finish began
 * (the lease's `since`; the report's last write for a lease from before it),
 * and each objection acked against any version of the report, that no typed
 * resolution answers. They are obligations, kept through every later
 * version of the report until a resolution names them (publishing the
 * report again answers nothing by itself); an objector's own later ack
 * answers its objection. A typed ack of no objection is none of these.
 */
export async function lateItems(sandboxRoot: string, coordinator: string, report: string | null): Promise<LateItem[]> {
  if (!report) return [];
  const st = await readFinish(sandboxRoot);
  const since = st.lease?.report === report && typeof st.lease.since === "number" ? st.lease.since : undefined;
  const posts = await P.correctionsAfter(sandboxRoot, report, coordinator, since).catch(() => [] as Array<{ id: number; from: string; tag: P.PostTag }>);
  const out: LateItem[] = [];
  for (const p of posts) if (!st.resolutions.some((r) => r.post === p.id)) out.push({ kind: "post", id: p.id, by: p.from, tag: p.tag });
  for (const a of st.acks) {
    if (a.verdict !== "objection") continue;
    if (st.resolutions.some((r) => r.ack === a.seq)) continue;
    // A later ack by the same seat, of any version, answers its own objection.
    if (st.acks.some((b) => b.by === a.by && b.seq > a.seq)) continue;
    out.push({ kind: "objection", id: a.seq, by: a.by, why: a.why });
  }
  return out;
}

/**
 * A seat's review of the report (A4): the digest it read (the report's
 * current one when left out) and its verdict. No objection is a typed ack,
 * never a late post; an objection says why and holds the coordinator's done
 * until the coordinator resolves it.
 */
export async function ackReport(ctx: P.SwarmContext, input: { digest?: string; verdict?: string; why?: string }): Promise<{ ok: true; seq: number; digest: string } | { ok: false; reason: string }> {
  const verdict = String(input.verdict ?? "").trim();
  if (verdict !== "no_objection" && verdict !== "objection") return { ok: false, reason: "verdict is no_objection or objection" };
  const why = String(input.why ?? "").trim();
  if (verdict === "objection" && !why) return { ok: false, reason: "an objection says why: what in the report does not hold, and what shows it" };
  if (why.length > L.LEAD_WHY_MAX) return { ok: false, reason: `why is over ${L.LEAD_WHY_MAX} characters: nothing is cut, so a longer text is refused` };
  return withFinish(ctx.sandboxRoot, async (held) => {
    const st = await readFinish(ctx.sandboxRoot);
    const report = st.lease?.report ?? null;
    if (!report) return { ok: false as const, reason: "no report is named yet: the coordinator's done names it" };
    const current = await reportDigest(ctx.sandboxRoot, report);
    if (!current) return { ok: false as const, reason: `${report} does not exist yet` };
    const digest = String(input.digest ?? "").trim() || current;
    if (digest !== current) return { ok: false as const, reason: `${report} is at digest ${current} now, not ${digest}: read it again, then ack what you read` };
    if (st.lease?.holder === ctx.agentId) return { ok: false as const, reason: "you coordinate the finish: an ack is another seat's review of your report" };
    const [e] = await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "ack", digest, verdict, ...(why ? { why } : {}) }], held);
    return { ok: true as const, seq: e.seq, digest };
  });
}

/** The coordinator answers a late post or an objection with a typed resolution: folded into the report, or not material, with why. */
export async function resolveLate(ctx: P.SwarmContext, input: { post?: unknown; ack?: unknown; how?: string; why?: string }): Promise<{ ok: true; seq: number } | { ok: false; reason: string }> {
  const how = String(input.how ?? "").trim();
  if (how !== "folded" && how !== "not_material") return { ok: false, reason: "how is folded (the report now says it) or not_material (it changes nothing the report concludes)" };
  const why = String(input.why ?? "").trim();
  if (!why) return { ok: false, reason: `why is required: ${how === "folded" ? "where the report says it now" : "why it changes nothing the report concludes"}` };
  const post = input.post !== undefined && input.post !== null && String(input.post).trim() ? Number(String(input.post).replace(/^#/, "")) : undefined;
  const ack = input.ack !== undefined && input.ack !== null && String(input.ack).trim() ? Number(input.ack) : undefined;
  if ((post === undefined) === (ack === undefined)) return { ok: false, reason: "name one: post (the late post's id, #123) or ack (the objection's seq)" };
  return withFinish(ctx.sandboxRoot, async (held) => {
    const st = await readFinish(ctx.sandboxRoot);
    if (st.lease?.holder !== ctx.agentId) return { ok: false as const, reason: `resolutions are the coordinator's${st.lease ? ` (${st.lease.holder})` : ""}` };
    const open = await lateItems(ctx.sandboxRoot, ctx.agentId, st.lease.report);
    const hit = open.find((x) => (post !== undefined && x.kind === "post" && x.id === post) || (ack !== undefined && x.kind === "objection" && x.id === ack));
    if (!hit) return { ok: false as const, reason: `${post !== undefined ? `post #${post}` : `objection ${ack}`} is not open against the report (open: ${open.map((x) => (x.kind === "post" ? `post #${x.id}` : `objection ${x.id}`)).join(", ") || "none"})` };
    // Bound to the version of the report it was made against: a folded item is in that one.
    const digest = await reportDigest(ctx.sandboxRoot, st.lease.report);
    const [e] = await appendFinish(ctx.sandboxRoot, [{ by: ctx.agentId, ev: "resolve", ...(post !== undefined ? { post } : {}), ...(ack !== undefined ? { ack } : {}), how: how as "folded" | "not_material", why, ...(digest ? { digest } : {}) }], held);
    return { ok: true as const, seq: e.seq };
  });
}

// --- readiness ----------------------------------------------------------------------------------

/** The answer sections a goal's check names beside its questions: summary and narrative, when it names them. */
async function goalExtraSections(sandboxRoot: string): Promise<string[]> {
  const doc = await L.goalDocument(sandboxRoot);
  if (!doc) return [];
  const out: string[] = [];
  for (const check of L.goalChecks(doc.text)) {
    if (!check.includes("check-answers.ts")) continue;
    const words = L.shellWords(check);
    const i = words.indexOf("--sections");
    for (const raw of (i >= 0 ? words[i + 1] ?? "" : "").split(",")) {
      const s = raw.trim().toLowerCase();
      if ((s === "summary" || s === "narrative") && !out.includes(s)) out.push(s);
    }
  }
  return out;
}

export type Readiness = { ready: boolean; revision: string; items: string[]; limited: string[] };

const readinessCache = new Map<string, Readiness>();

/** How many times readiness reads the registers again when the state moved while it read them, before it answers uncached. */
const READINESS_ATTEMPTS = 3;

/**
 * Whether the registers say the finish line is met, at the revision it is
 * computed for: no material lead open (or waiting for a closure's
 * confirmation), no lead's job waiting for an interpretation, every
 * question in scope answered with nothing the ledger gate holds against it
 * (a negative unreviewed, a dispute, a best candidate only, a stale
 * answer), and under the operator's stop policy no route limitation left.
 * What would still limit the run is listed apart. Cheap and generic: the
 * goal's own checks run only at the coordinator's done. One result per
 * revision, shared by every reader in this process, and only for the
 * revision its own snapshot was read at: the snapshot is read here, between
 * two readings of the revision that agree (a caller's snapshot may be older
 * than the revision, and a lead admitted between them would be cached as
 * never there). A state that never holds still is answered, never cached.
 */
export async function readiness(sandboxRoot: string): Promise<Readiness> {
  let last: Readiness | null = null;
  for (let i = 0; i < READINESS_ATTEMPTS; i++) {
    const { revision } = await P.stateRevision(sandboxRoot);
    const hit = readinessCache.get(`${sandboxRoot}\u0000${revision}`);
    if (hit) return hit;
    const out = await computeReadiness(sandboxRoot, await L.leadsSnapshot(sandboxRoot), revision);
    if ((await P.stateRevision(sandboxRoot)).revision !== revision) {
      last = out;
      continue;
    }
    readinessCache.set(`${sandboxRoot}\u0000${revision}`, out);
    if (readinessCache.size > 256) readinessCache.delete(readinessCache.keys().next().value!);
    return out;
  }
  return last!;
}

async function computeReadiness(sandboxRoot: string, s: L.LeadsSnapshot, revision: string): Promise<Readiness> {
  const items: string[] = [];
  const limited: string[] = [];
  const lead = await L.leadDefects(sandboxRoot, s);
  for (const d of lead.defects) items.push(d.what);
  const sections = [...L.caseQuestions(s).map((q) => `question:${q}`), ...(await goalExtraSections(sandboxRoot))];
  const attestations = await P.readAttestations(sandboxRoot).catch(() => [] as P.LedgerAttestation[]);
  const disputes = await P.readDisputes(sandboxRoot).catch(() => [] as P.LedgerDispute[]);
  const barOf = (id: string) => {
    const q = s.questions?.bySection.get(P.sectionKey(id));
    return { material: s.goal.questions.map(P.sectionKey).includes(P.sectionKey(id)) || !q || q.materiality === "material", existence: s.goal.existence.map(P.sectionKey).includes(P.sectionKey(id)) || q?.expects === "existence" };
  };
  const gate = P.ledgerGate({ entries: s.ledger.entries, attestations, disputes, sections, bar: barOf });
  const accepted = new Set<string>();
  for (const q of s.questions?.state.questions.values() ?? []) if (q.accepted && (await import("./questions.ts")).acceptanceStands(q, s.ledger)) accepted.add(`question:${q.section}`);
  for (const d of gate.open) {
    if (d.section && accepted.has(d.section) && !["coverage_missing", "coverage_stale", "negative_unreviewed", "wording"].includes(d.code)) continue;
    items.push(d.what);
  }
  // Best candidates, stale answers, and what else would limit the run.
  const disposed = new Map<string, "answered" | "accepted">();
  for (const sec of sections) {
    if (!sec.startsWith("question:")) continue;
    if (accepted.has(sec)) {
      disposed.set(sec.slice("question:".length), "accepted");
      limited.push(`${sec} was accepted by the operator`);
      continue;
    }
    const a = gate.answers[sec];
    if (!a) continue;
    const reviews = attestations.filter((x) => P.attestationAct(x) === "attest" && x.target === a.hash && !a.authors.includes(x.by));
    const result = NB.answerResult(a);
    if (reviews.length && !reviews.some(P.attestEstablishes) && !(result && NB.NEGATIVE_RESULTS.has(result))) {
      limited.push(`${sec} is a best candidate, not established (E-${a.seq})`);
      continue;
    }
    const q = s.questions?.bySection.get(sec.slice("question:".length));
    if (q && (a.question_rev ?? 1) !== q.rev) {
      items.push(`${sec}'s answer E-${a.seq} predates revision ${q.rev} of ${q.id}`);
      continue;
    }
    if (result && result !== "established" && result !== "premise_not_supported") limited.push(`${sec} is ${NB.resultWords(result)}`);
    if (!gate.defects.some((d) => d.section === sec)) disposed.set(sec.slice("question:".length), "answered");
  }
  for (const l of lead.limiting) {
    const lv = s.state.leads.get(l.lead);
    const v = lv ? L.routeLimitation(lv, (q) => disposed.get(q) ?? null) : { limiting: true, why: "" };
    if (v.limiting) limited.push(`${l.lead} was closed ${l.disposition} (${l.ref})${v.why ? `: ${v.why}` : ""}`);
  }
  const budget = await P.readBudget(sandboxRoot).catch(() => null);
  const operatorStop = P.stopPolicyOf(budget) === "operator";
  const blocking = operatorStop ? [...items, ...limited.filter((x) => !/accepted by the operator/.test(x))] : items;
  return { ready: !blocking.length, revision, items: blocking, limited };
}


/**
 * Readiness posted once each time it turns (A4): ready, the coordinator is
 * told to call done and everyone else to wait; not ready again, what came
 * up. Recorded in the finish register, so a restart posts nothing twice.
 */
export async function syncReadiness(sandboxRoot: string, r: Readiness): Promise<boolean> {
  const st = await readFinish(sandboxRoot);
  const last = st.readiness;
  if (last && last.ready === r.ready) return false;
  if (!last && !r.ready) return false;
  if (await P.swarmDoneExists(sandboxRoot)) return false;
  return withFinish(sandboxRoot, async (held) => {
    const again = (await readFinish(sandboxRoot)).readiness;
    if (again && again.ready === r.ready) return false;
    await appendFinish(sandboxRoot, [{ by: "system", ev: "readiness", ready: r.ready, revision: r.revision, items: r.items }], held);
    const lease = st.lease;
    const who = lease ? `${lease.holder} coordinates the finish (generation ${lease.generation})` : "the first seat to call done coordinates the finish (normally whoever publishes the report)";
    const body = r.ready
      ? `FINISH READY by the registers at revision ${r.revision.slice(0, 12)}: every material lead has a disposition, every question in scope an answer the ledger gate holds nothing against${r.limited.length ? ` (limited: ${r.limited.join("; ")})` : ""}. ${who}: its done runs the goal's checks. Everyone else: do not call done; review the report (finish ack), say what is still open, or wait.`
      : `FINISH NOT READY again at revision ${r.revision.slice(0, 12)}: ${r.items.join("; ")}.`;
    await P.systemPost(sandboxRoot, { tag: "hold", body }).catch(() => undefined);
    return true;
  }).catch(() => false);
}

/** The finish in the header (A4): readiness, the coordinator, and what this seat does about it. */
export async function finishHeader(sandboxRoot: string, me: string): Promise<string | null> {
  if (await P.swarmDoneExists(sandboxRoot)) return null;
  const r = await readiness(sandboxRoot);
  await syncReadiness(sandboxRoot, r).catch(() => false);
  const st = await readFinish(sandboxRoot);
  const lease = st.lease;
  const mine = lease?.holder === me;
  const who = lease ? `${lease.holder}${mine ? " (you)" : ""} coordinates it (generation ${lease.generation})` : "nobody coordinates it yet: the first done takes it (normally the report's publisher)";
  const state = r.ready ? `READY by the registers${r.limited.length ? `, limited: ${r.limited.join("; ")}` : ""}` : `not ready (${r.items.length}): ${r.items.join("; ")}`;
  let act = "";
  if (mine) {
    const late = await lateItems(sandboxRoot, me, lease.report);
    act = late.length ? ` Late against the report, each for your typed resolution (finish resolve): ${late.map((x) => (x.kind === "post" ? `post #${x.id} (${x.tag}) by ${x.by}` : `objection ${x.id} by ${x.by}: ${x.why}`)).join("; ")}.` : r.ready ? " Call done." : "";
    const digest = await reportDigest(sandboxRoot, lease.report);
    const acks = st.acks.filter((a) => a.digest === digest && a.verdict === "no_objection").map((a) => a.by);
    if (acks.length) act += ` Reviewed with no objection: ${[...new Set(acks)].join(", ")}.`;
  } else if (lease) act = " Your done is not the finish: when your slice ends, review the report (finish ack) or say on the board what is open, and wait.";
  return `Finish: ${state}; ${who}.${act}`;
}

// --- checks, one per revision ------------------------------------------------------------------

/** The check recorded for a revision, if any: a done at the same revision takes it instead of running the finish line again. */
export async function checkAt(sandboxRoot: string, revision: string): Promise<FinishState["checks"][number] | null> {
  if (!revision) return null;
  return (await readFinish(sandboxRoot)).checks.filter((c) => c.revision === revision).at(-1) ?? null;
}

/** Record what the finish line said at a revision (whole: the run the verdict was made from). */
export async function recordCheck(sandboxRoot: string, by: string, revision: string, verdict: { proceed: boolean; outcome?: string; reason?: string }, run: unknown): Promise<void> {
  if (!revision) return;
  await withFinish(sandboxRoot, async (held) => {
    if ((await readFinish(sandboxRoot)).checks.some((c) => c.revision === revision)) return;
    await appendFinish(sandboxRoot, [{ by, ev: "check", revision, proceed: verdict.proceed, ...(verdict.outcome ? { outcome: verdict.outcome } : {}), ...(verdict.reason ? { reason: verdict.reason } : {}), run }], held);
  });
}

/** Where the finish stands, for any seat (finish status): readiness, the coordinator, the last check and the report's review. */
export async function finishStatus(ctx: P.SwarmContext): Promise<Record<string, unknown>> {
  const r = await readiness(ctx.sandboxRoot);
  const st = await readFinish(ctx.sandboxRoot);
  const digest = await reportDigest(ctx.sandboxRoot, st.lease?.report);
  const last = st.checks.at(-1);
  return {
    ok: true,
    ready: r.ready,
    revision: r.revision,
    items: r.items,
    limited: r.limited,
    coordinator: st.lease ? { holder: st.lease.holder, generation: st.lease.generation, why: st.lease.why, report: st.lease.report, digest } : null,
    ...(last ? { last_check: { revision: last.revision, current: last.revision === r.revision, proceed: last.proceed, outcome: last.outcome ?? null, reason: last.reason ?? null, by: last.by, at: last.at } } : {}),
    acks: st.acks.filter((a) => a.digest === digest).map((a) => ({ seq: a.seq, by: a.by, verdict: a.verdict, why: a.why })),
    late: st.lease ? await lateItems(ctx.sandboxRoot, st.lease.holder, st.lease.report) : [],
    chain: st.chain.ok ? "intact" : `BROKEN at line ${st.chain.broken_at} (${st.chain.reason})`,
    ...(existsSync(join(ctx.sandboxRoot, FINISH_LOG)) ? {} : { note: "no finish act yet" }),
  };
}
