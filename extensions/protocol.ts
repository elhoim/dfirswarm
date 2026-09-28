/**
 * The DFIR Swarm protocol: the board, exclusive file claims, the write guard,
 * the sentinel, the budget, file history, the bash-write watch, forged tools,
 * read-only inputs, the ledger and the names. Pure functions over the sandbox
 * on disk; nothing here imports Pi. The layout is documented in
 * docs/protocol.md, and the Pi-facing side (tools and hooks) lives in
 * `agent-swarm.ts`.
 *
 * Claim key = sandbox-relative path. Locks use spawner-assigned agent ids,
 * not the names agents choose for themselves.
 */

import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  closeSync,
  createReadStream,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { connect, type Socket } from "node:net";
import {
  appendFile,
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { basename, dirname, join, posix, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import * as NB from "./negative-bar.ts";

/**
 * Claims are short leases, renewed by re-claiming: make the edit, release,
 * or call claim_file again to keep the lease. 120s is
 * long enough for one provider round on a slow model without leaving a dead
 * agent's claim standing for minutes.
 */
export const DEFAULT_CLAIM_SECONDS = 120;
export const MAX_CLAIM_SECONDS = 600;
export const TABLE_LOCK_WAIT_MS = 10_000;
export const TABLE_LOCK_STALE_MS = 15_000;
/** How often a holder refreshes its table lock; well inside the stale window. */
export const TABLE_LOCK_HEARTBEAT_MS = 3_000;
/** The table lock's timings. Only tests change them, to shorten a stall. */
export const tableLockTiming = {
  waitMs: TABLE_LOCK_WAIT_MS,
  staleMs: TABLE_LOCK_STALE_MS,
  heartbeatMs: TABLE_LOCK_HEARTBEAT_MS,
};
export const DEFAULT_SWARM_ID = "hello-n2";
export const DEFAULT_AGENT_IDS = ["agent00", "agent01"] as const;
export const SENTINEL_REL = "done/SWARM_DONE";
/** Written by scripts/reap.sh when every seat is marked done or dead and no sentinel exists: a stop, not a finish. */
export const ALL_DEAD_REL = "done/ALL_AGENTS_DEAD";
export const HELLO_REL = "work/hello.txt";
/** An agent silent this long is stalled and shown as "?"; a local choice. */
export const DEFAULT_STALL_MS = 90_000;

/** The harness writes on the board under this name. No worker may take it. */
export const SYSTEM_AGENT = "system";
/**
 * The named lock the lead register and the question register are written
 * under (extensions/leads.ts, extensions/questions.ts). A done's sentinel is
 * written under it too (markDone), so a question admitted while the finish
 * line runs is either in the state that line was judged against, or it sees
 * the sentinel and is recorded as a follow-up.
 */
export const REGISTER_LOCK = ".leads.lock";
export const PRIMARY_THREAD = "main";
export const THREAD_META = "meta.json";
export const CURSORS_REL = "cursors.json";

/**
 * Paths the harness owns. Agents never write here: claims are refused, the
 * write guard blocks, and the bash-write detector reports a violation. The
 * sentinel is the swarm's clock, so only `markDone` may set it; budget.json
 * holds the cap, so an agent that could write it could lift its own cap.
 */
export const PROTECTED_PREFIXES = [
  "done/",
  "locks/",
  "traces/",
  "history/",
  "inbox/",
  "threads/",
  ".pi/",
  ".pi-sessions/",
  "bin/",
  // Forged tools are written through make_tool, which records who wrote what
  // and announces it; a direct write would be a tool nobody can account for.
  "tools/",
  // Read-only inputs: the files the operator handed the swarm to analyse, the
  // pristine copy they are healed from, and the guard's own files. Reading is
  // free; writing, deleting and re-permissioning are not.
  "inputs/",
  ".inputs-pristine/",
  ".fsguard/",
  ".zsh/",
  ".bash/",
  // Each job image's own list of programs, read from the image at kickoff.
  "images/",
  // The findings ledger and the evidence catalog are written by the harness
  // (through `record`, and at kickoff) and read by everyone.
  "ledger/",
  "catalog/",
  // The lead register (extensions/leads.ts): written through the lead tools
  // and by the hub, read by everyone.
  "leads/",
  // The question register (extensions/questions.ts), the same way: its
  // tools, the hub and the operator's CLI write it.
  "questions/",
  // The whole output of every tool call whose result reached the model as
  // a prefix (Pi's `bash` past its 50 KB, a forged tool past its 64 KB, a
  // page's text past what browser_check delivers). Written by the harness,
  // named from the trace with its size and hash; the record, not scratch.
  "tool-output/",
  // What each agent's VM was (--isolation microvm): its image, its mounts,
  // its network and its snapshot, written by the VM manager on the host.
  "vm/",
] as const;

export const PROTECTED_FILES = [
  "SWARM.md",
  "team.json",
  "budget.json",
  "layout.json",
  "netguard.pid",
  "netguard.port",
  "idle-nudge.pid",
  "inputs.json",
  "toolbox.json",
  // What a run installed into work/.toolchain/, derived by the harness from
  // the packages' own dist-info rather than from what an agent says it did.
  "toolchain.json",
  // Both are read by commands that run OUTSIDE the pane's guard, as the
  // examiner: `inputs.device` is handed to `hdiutil detach` and `collector.pid`
  // to `kill`. A pane that could write them would be choosing what the harness
  // ejects or signals.
  "inputs.device",
  "collector.pid",
  // What each agent calls itself, written only through the `name` tool: a
  // peer that could rewrite it could rename everyone else.
  "names.json",
  // Read by `swarm.sh stop` outside every agent's reach, as the examiner:
  // which process is the hub, and which directory is its to delete.
  "hub.pid",
  "hub.dir",
  // The harness's own verdict on the run, taken on the host after it ended,
  // its earlier verdicts (custody.<stamp>.json, custody.previous*.json:
  // PROTECTED_ROOT_PATTERNS) and the index of the run's artifacts.
  "custody.json",
  "artifacts.json",
  "compact-prompt.md",
  // The kickoff each agent's Pi starts with.
  ".kickoff",
  // The host's spill of trace lines the collector did not take
  // (TRACE_SPILL_REL): custody reads it as the harness's own record.
  "work/.trace-spill.jsonl",
  // What the agents asked of the operator (a lead closed needs_operator), and
  // the hosts the operator allowed in answer: the job service reaches those.
  "operator-requests.jsonl",
  "operator-hosts.jsonl",
] as const;

/**
 * Harness files at the sandbox root named by a pattern: custody's earlier
 * verdicts (custody.<stamp>.json, custody.previous.json,
 * custody.previous-<stamp>.json), a custody.json it moved aside, and the
 * index each earlier verdict sealed (artifacts.<stamp>.json). Keys are
 * lower-cased before the test.
 */
export const PROTECTED_ROOT_PATTERNS: readonly RegExp[] = [/^custody\.[^/]*$/, /^artifacts\.[^/]*$/];

/**
 * True when `pathKey` (sandbox-relative, forward slashes) belongs to the
 * harness. Matching is case-insensitive: on a case-insensitive filesystem
 * (macOS by default) `BUDGET.JSON` and `budget.json` are the same file, and
 * a case-sensitive host merely refuses an oddly-cased name it has no reason
 * to want. Symlinks are handled by `realPathKey`, not here.
 */
export function isProtectedPath(pathKey: string): boolean {
  const key = pathKey.replace(/^\.\//, "").toLowerCase();
  if ((PROTECTED_FILES as readonly string[]).some((file) => file.toLowerCase() === key)) return true;
  if (PROTECTED_ROOT_PATTERNS.some((re) => re.test(key))) return true;
  return (PROTECTED_PREFIXES as readonly string[]).some((prefix) =>
    key.startsWith(prefix.toLowerCase()),
  );
}

const POST_TAGS = [
  "intro",
  "ask",
  "claim",
  "result",
  "hold",
  "veto",
  "stop",
  // A person's question, posted by the question register (registerPost);
  // never an agent's tag.
  "question",
] as const;

export type PostTag = (typeof POST_TAGS)[number];

export type SwarmContext = {
  sandboxRoot: string;
  agentId: string;
};

export type TeamRecord = {
  swarm_id: string;
  n: number;
  agents: Array<{ id: string; role: string; pane?: string; model?: string }>;
};

export type AgentBudget = {
  spent_usd: number;
  tokens: number;
  calls: number;
  /**
   * "model-gateway" when the row's spend was metered on the host, off the
   * provider's own answers (scripts/model-gateway.ts); absent, it is what
   * the seat reported about itself.
   */
  metered_by?: "model-gateway";
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  /** Context occupancy from Pi's own estimate (ctx.getContextUsage). */
  context_tokens?: number;
  context_window?: number;
  /** The effective ceiling the self-compaction thresholds are fractions of
   *  (extensions/context-ceiling.ts); absent when self-compaction is off. */
  context_ceiling?: number;
  /** idle · notice · warning · forced, against that ceiling. */
  context_level?: string;
  /** True while every tool but self_compact, budget and done is blocked. */
  context_locked?: boolean;
  /** Compactions Pi recorded in this session (hand-offs and its own fallbacks), and what they cost. */
  compactions?: number;
  compaction_tokens?: number;
  compaction_usd?: number;
  /** Hand-offs completed through self_compact: the note came back. */
  handoffs?: number;
  /** The seat's model, `provider/id`, as the kickoff assigned it. It rides
   *  here so a per-model cap can be summed from this record alone. */
  model?: string;
  /** What the seat's Pi sessions other than the live one spent (a restart,
   *  `/new`). The counters above are the seat's whole run: this plus the
   *  live session. See foldSessionSlice. */
  earlier_sessions?: CarriedCounters;
  /** The Pi session this row's live counters come from, when Pi says. */
  session_id?: string;
  /** Each session's last report, by session id, when reports carry one. The
   *  counters above are their sum; see foldSessionSlice. */
  sessions?: Record<string, CarriedCounters>;
};

/** The counters a Pi session reports and a fold adds up. */
export const SESSION_COUNTERS = [
  "spent_usd",
  "tokens",
  "calls",
  "input",
  "output",
  "cache_read",
  "cache_write",
] as const;
export type SessionCounters = Record<(typeof SESSION_COUNTERS)[number], number>;
/** SessionCounters plus the compaction and hand-off counts, present when non-zero. */
export type CarriedCounters = SessionCounters &
  Partial<Record<"compactions" | "compaction_tokens" | "compaction_usd" | "handoffs", number>>;

export type BudgetRecord = {
  cap_usd: number;
  spent_usd: number;
  tokens: number;
  calls: number;
  wall_clock_minutes: number;
  started_at: string;
  /** Official Pi: sessionManager.getEntries() + Usage.cost (footer / get_session_stats). */
  source: string;
  hard_kill: boolean;
  cap_steer_sent: boolean;
  /** When the swarm was first steered to stop, and why. Swarm-wide, so the
   *  grace period survives the process that noticed and is the same clock
   *  for every agent. */
  stop_steer_at?: string;
  stop_reason?: StopReason;
  /** A cap each agent has on its own; over it, only that agent is stopped. */
  cap_per_agent_usd?: number;
  /** The same in tokens: the per-agent brake of a team whose dollars are not
   *  charged (a subscription, a local server). */
  cap_per_agent_tokens?: number;
  /** Every change the operator made to the caps while the run went on, in
   *  order, each with the caps it left (capFingerprint): the shell watch
   *  tells such a change from a shell writer's by it. */
  cap_changes?: CapChange[];
  /** A cap per model, `provider/id` to USD: a ceiling on the combined spend
   *  of every agent running that model. Over it, each of them is steered and
   *  stopped the way the per-agent cap does it; other models' agents go on. */
  cap_per_model_usd?: Record<string, number>;
  /** False when no model on the team bills anything — a server on this
   *  machine or this network. Pi then reports cost as an exact zero, so the
   *  USD cap could never fire and `cap_tokens` is the brake. Absent means
   *  true, which every run before local models was. Decided by the kickoff
   *  from models.json, never inferred from spend: a measured zero and an
   *  unmeasured one look the same in a session. */
  metered?: boolean;
  /** A cap in tokens over every turn: what the kickoff requires for an
   *  unmetered team, and an optional second brake for any other. */
  cap_tokens?: number;
  /**
   * The run was started until solved (--until-solved, or the goal's
   * `until_solved: true`): no wall clock, every cap advisory (spend is
   * recorded and shown, nothing is stopped for it), no abandon, and done
   * when every question in scope has a disposition under the bar, as any
   * run's; otherwise only the operator ends it.
   */
  until_solved?: boolean;
  /** Until solved: minutes without progress before the watchdog posts a regroup (default 15). */
  stall_minutes?: number;
  /**
   * How the seats coordinate (docs/adr/0015), from the kickoff: the seconds
   * each seat's first choice waits for the seat before it, and the bound
   * over all of them (leads.ts admitFirstChoice). Absent: no stagger.
   */
  coordination?: { first_choice_stagger_sec?: number; first_choice_bound_sec?: number };
  /**
   * What reaching a cap does (the stop policy, docs/adr/0013): cap-pause
   * (the default) pauses the run for the operator to extend or stop it,
   * cap-stop stops it (an unattended run), operator is --until-solved (no
   * wall clock, caps advisory, only the operator ends it). Absent on a run
   * from before the policy, which stopped at its caps (stopPolicyOf).
   */
  stop_policy?: StopPolicy;
  /** The pause in force, when a cap paused the run: seats idle, no model call goes out, until the operator extends or stops it. */
  paused?: PauseRecord;
  /** Every pause that was lifted, in order, with who lifted it and what they gave. */
  pauses?: PauseRecord[];
  /**
   * The wall clock across pauses and resumes: the minutes already used
   * (wall_used_ms) and when the current stretch began (wall_base_at, the
   * run's start when absent). A pause freezes it at the pause.
   */
  wall_used_ms?: number;
  wall_base_at?: string;
  /** Every resume of the run after a stop or a seal (swarm.sh resume), by whom and when. */
  resumes?: Array<{ at: string; by: string; from: string }>;
  agents: Record<string, AgentBudget>;
};

/** What a cap does to the run: pause it (the default), stop it, or nothing (the operator's). */
export const STOP_POLICIES = ["cap-pause", "cap-stop", "operator"] as const;
export type StopPolicy = (typeof STOP_POLICIES)[number];
export const DEFAULT_STOP_POLICY: StopPolicy = "cap-pause";
/**
 * The token cap a kickoff sets when none is given, on a team whose dollars
 * are charged (a second brake beside the dollar cap; a team whose dollars
 * are not names its own, since tokens are its only brake). A hundred
 * million: the ten-agent BelkaCTF #6 run on a subscription used 277M, a
 * small goal on two agents a few million.
 */
export const DEFAULT_CAP_TOKENS = 100_000_000;

/** A pause: when, for which cap, in words; and once lifted, when, by whom, with what. */
export type PauseRecord = { at: string; reason: StopReason; detail: string; resumed_at?: string; resumed_by?: string; set?: Partial<Record<CapField, number>> };

/** The run's stop policy: its own, the operator's when it runs until solved, and cap-stop for a run from before the policy. */
export function stopPolicyOf(b: { until_solved?: boolean; stop_policy?: string } | null | undefined): StopPolicy {
  if (b?.until_solved === true || b?.stop_policy === "operator") return "operator";
  if (b?.stop_policy === "cap-pause") return "cap-pause";
  return "cap-stop";
}

/** How much wall clock the run has used: the stretches before, and the current one up to now, or up to the pause in force. */
export function wallElapsedMs(b: Pick<BudgetRecord, "started_at" | "wall_used_ms" | "wall_base_at" | "paused">, now = Date.now()): number {
  const base = Date.parse(b.wall_base_at ?? b.started_at);
  const end = b.paused ? Date.parse(b.paused.at) : now;
  const stretch = Number.isFinite(base) && Number.isFinite(end) ? Math.max(0, end - base) : 0;
  return Math.max(0, Number(b.wall_used_ms) || 0) + stretch;
}

/** One change of the caps made while the run went on (setCaps). */
export type CapChange = {
  at: string;
  /** Who made it: "operator" from swarm.sh cap, the console's user by name. */
  by: string;
  /** The fields set, each to its new value. */
  set: Partial<Record<CapField, number>>;
  /** The caps as they stood after it (capFingerprint). */
  caps: string;
};

export const CAP_FIELDS = ["cap_usd", "cap_tokens", "cap_per_agent_usd", "cap_per_agent_tokens", "wall_clock_minutes"] as const;
export type CapField = (typeof CAP_FIELDS)[number];

export type SessionUsageSlice = AgentBudget;

export type StopReason = "cap" | "wall_clock";

export type SwarmEvent = {
  ts: string;
  agent: string;
  tool: string;
  args: Record<string, unknown>;
  result: unknown;
  /** The sending process's id and its count of lines sent (appendEvent). */
  sid?: string;
  seq?: number;
  /** The collector's clock when the line reached it; the sender's `ts` is, in a VM, the guest's. */
  recv_ts?: string;
};

/** When a line happened by the host's clock: the collector's stamp when there is one. */
export function hostTime(e: { ts: string; recv_ts?: string }): string {
  return e.recv_ts || e.ts;
}

export const BUDGET_SOURCE = "pi.sessionManager.getEntries";
export const EVENTS_REL = "traces/events.jsonl";
/**
 * Where a trace line goes when it can reach neither the collector nor the
 * file. A run should never have one; a run that does must be able to say so.
 */
export const TRACE_SPILL_REL = "work/.trace-spill.jsonl";

/**
 * Where this process spills a trace line it could not hand to the collector.
 * On the host, one shared file under work/. In a microVM a file two VMs
 * append to loses lines (virtio-fs keeps no O_APPEND promise between guests:
 * a spill shared by two agents was found torn at line 24, measured), so each
 * agent spills into its own tool-output/ directory, which only its VM writes.
 */
export function traceSpillRel(env: NodeJS.ProcessEnv = process.env): string {
  const agent = env.AGENT_ID?.trim() ?? "";
  if (env.SWARM_ISOLATION === "microvm" && /^[a-z][a-z0-9_-]{0,31}$/.test(agent)) return `tool-output/${agent}/trace-spill.jsonl`;
  return TRACE_SPILL_REL;
}
export const HISTORY_REL = "history";
export const CAP_STEER =
  "Swarm spend cap hit. Call done with reason cannot_complete and stop. Do not start new work.";
export const TOKEN_CAP_STEER =
  "Swarm token cap hit. Call done with reason cannot_complete and stop. Do not start new work.";

/**
 * Whether the swarm is over the cap that applies to it: the USD cap when the
 * team is metered, the token cap whenever one is set. A free team's spend is
 * an exact zero, so without the token cap it would never be over anything —
 * which is the state local models were in before this existed.
 */
export function overCap(budget: BudgetRecord): { over: boolean; by: "usd" | "tokens" | null } {
  // An until-solved run's caps are advisory: spend is recorded and shown,
  // and nothing is stopped for it.
  if (budget.until_solved === true) return { over: false, by: null };
  const usd = budget.metered !== false && budget.cap_usd > 0 && budget.spent_usd >= budget.cap_usd;
  const capTokens = Number(budget.cap_tokens) || 0;
  const tokens = capTokens > 0 && budget.tokens >= capTokens;
  return { over: usd || tokens, by: usd ? "usd" : tokens ? "tokens" : null };
}

export type LockRecord = {
  path: string;
  owner: string;
  /** Why the owner took the path. Quoted back in violation reports. */
  reason: string;
  /** Lease length in seconds, as requested at claim time. */
  seconds: number;
  claimed_at: string;
  expires_at: string;
  /** Taken by the harness for a shell writer, not asked for by the agent. */
  implicit?: true;
};

export type PostRecord = {
  id: number;
  thread: string;
  from: string;
  to: string;
  tag: PostTag;
  body: string;
  path: string;
  /** What the author calls itself, if it has said. */
  name?: string;
  /**
   * A harness post sent from inside an agent's VM: the agent whose harness
   * hook said it. The hub sets it; nothing an agent passes can.
   */
  via?: string;
};

/** `threads/<name>/meta.json`. Membership decides who a no-arg `inbox` serves. */
export type ThreadMeta = {
  name: string;
  purpose: string;
  created_by: string;
  created_at: string;
  members: string[];
};

export type ClaimResult =
  | {
      ok: true;
      /** Whose expired claim this took over, when it took one over. */
      taken_over_from?: string;
      path: string;
      owner: string;
      reason: string;
      seconds: number;
      expires_at: string;
      refreshed: boolean;
      /** Tool text: tells the agent what to do next with the lease. */
      note: string;
    }
  | {
      ok: false;
      conflict: true;
      path: string;
      owner: string;
      reason: string;
      expires_at: string;
      note: string;
    }
  | { ok: false; protected: true; path: string; note: string };

export type ClaimView = LockRecord & { expires_in_seconds: number };

export type GuardResult =
  | { ok: true; path: string; refreshed: boolean }
  | { ok: false; reason: string; path?: string; owner?: string; protected?: true; inputs?: true };

export type DoneResult = {
  terminate: true;
  agent_done: string;
  sentinel: string;
  created_sentinel: boolean;
  reason: string;
  output_file: string;
  /** How the run ended, when the finish line said (FinishOutcome). */
  outcome?: string;
};

/** Who has asked to abandon the run, and who is still working. */
export type AbandonGate = { proceed: boolean; votes: string[]; working: string[]; first_vote: boolean };

/** An abandon that one agent asked for while others still work: recorded, not done. */
export type DoneRefused = {
  terminate: false;
  refused: string;
  abandon: AbandonGate;
  created_sentinel: false;
  reason: string;
  output_file: string;
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

export function isPostTag(value: string): value is PostTag {
  return (POST_TAGS as readonly string[]).includes(value);
}

export function resolveAgentId(explicit?: string): string {
  const fromEnv = process.env.AGENT_ID?.trim();
  const id = (explicit ?? fromEnv ?? "").trim();
  if (!id) {
    throw new Error(
      "AGENT_ID is required. The spawner assigns ids; do not invent a lock owner.",
    );
  }
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(id)) {
    throw new Error(`Invalid agent id "${id}". Use Herdr-safe [a-z][a-z0-9_-]{0,31}.`);
  }
  if (id === SYSTEM_AGENT) {
    throw new Error(`Agent id "${SYSTEM_AGENT}" is reserved for the harness.`);
  }
  return id;
}

export function createContext(sandboxRoot: string, agentId?: string): SwarmContext {
  return {
    sandboxRoot: resolve(sandboxRoot),
    agentId: resolveAgentId(agentId),
  };
}

/**
 * The harness's own voice on the board. Only `system` posts may be authored
 * with it; it never claims files, so it bypasses `resolveAgentId`.
 */
export function systemContext(sandboxRoot: string): SwarmContext {
  return { sandboxRoot: resolve(sandboxRoot), agentId: SYSTEM_AGENT };
}

export function claimKey(sandboxRoot: string, rawPath: string): string {
  const root = resolve(sandboxRoot);
  const abs = resolve(root, rawPath);
  const rel = relative(root, abs);
  if (rel === "" || rel.startsWith("..") || rel.split(sep).includes("..")) {
    throw new Error(`Path escapes sandbox: ${rawPath}`);
  }
  return rel.split(sep).join("/");
}

/**
 * The claim key a path really addresses, with symlinks resolved. `claimKey`
 * is lexical, so `work/b -> ../budget.json` would otherwise look like an
 * ordinary work file and let an agent write a harness-owned file through it.
 * Resolves the deepest existing ancestor, since the leaf usually does not
 * exist yet on a first write. Throws if the real path leaves the sandbox.
 */
export async function realPathKey(sandboxRoot: string, rawPath: string): Promise<string> {
  const lexical = claimKey(sandboxRoot, rawPath);
  const realRoot = await realpath(sandboxRoot).catch(() => resolve(sandboxRoot));
  let probe = resolve(realRoot, lexical);
  const tail: string[] = [];
  for (;;) {
    const real = await realpath(probe).catch(() => null);
    if (real !== null) {
      return claimKey(realRoot, tail.length ? join(real, ...tail) : real);
    }
    const parent = dirname(probe);
    if (parent === probe) return lexical;
    tail.unshift(basename(probe));
    probe = parent;
  }
}

/**
 * The seat whose own directory `pathKey` is in: `work/<id>/`,
 * `work/extracted/<id>/`, `work/quarantine/<id>/`, `tool-output/<id>/` or
 * `.pi-sessions/<id>/`, for a seat on `ids`; null for any other path. In a
 * microVM these are the only directories a seat can write, so they are also
 * the only ones whose layout a seat controls while the run is up.
 *
 * Compared without regard to case: on a case-insensitive disk (macOS)
 * `work/A1/x` is a1's file, and a check that took `A1` for a stranger let a
 * seat publish over a peer's file.
 */
export function seatHoleOwner(pathKey: string, ids: readonly string[]): string | null {
  const m = pathKey.toLowerCase().match(/^(?:work\/(?:extracted\/|quarantine\/)?|tool-output\/|\.pi-sessions\/)([a-z][a-z0-9_-]{0,31})(?:\/|$)/);
  if (!m) return null;
  return ids.find((id) => id.toLowerCase() === m[1]) ?? null;
}

/** The team's seat ids, or none when the team file cannot be read. */
export async function teamIds(sandboxRoot: string): Promise<string[]> {
  try {
    return (await readTeam(sandboxRoot)).agents.map((a) => a.id);
  } catch {
    return [];
  }
}

/** A file too large for what was asked of it; `code` is EFBIG. */
export class FileTooLarge extends Error {
  readonly code = "EFBIG";
  readonly size: number;
  constructor(pathKey: string, size: number, limit: number) {
    super(`${pathKey} is ${size} bytes, more than the ${limit} this takes`);
    this.size = size;
  }
}

/**
 * A file under the sandbox, opened for the harness on the host, without
 * following a link an agent may have planted. An agent in a microVM writes
 * its own directories through virtio-fs, and the link it makes there is a
 * real link on the host (measured); the hub reads history and diffs as the
 * operator's own user, so a link to the operator's home would read the
 * operator's home.
 *
 * The path is resolved once (`realPathKey`, which refuses anything that
 * leaves the sandbox), the resolved file is opened with O_NOFOLLOW, and the
 * open file is compared by device and inode with what was resolved. O_NOFOLLOW
 * guards only the last component, though: a directory on the way swapped for
 * a link between the resolve and the open opens a file elsewhere (measured:
 * 140 of 39,385 racing reads). So the path is resolved again after the open,
 * and the file it names now must be the one that is open: a link still in
 * place leaves the sandbox and is refused, and one swapped back names another
 * file. On Linux the kernel names the file the descriptor holds
 * (/proc/self/fd), which closes the race; macOS has no such name, and there
 * the second resolve narrows it without closing it (measured: 1 of 9,055
 * racing reads still got through). Nothing is truncated before that check,
 * and a FIFO does not hold the open (O_NONBLOCK). So the hub never opens a
 * file under a seat's own directory while the seat is up (`seatHoleOwner`):
 * the seat sends the bytes instead, and the race has nothing to win.
 */
export async function openSandboxFile(
  sandboxRoot: string,
  rawPath: string,
  mode: "read" | "write",
): Promise<{ handle: Awaited<ReturnType<typeof open>>; pathKey: string; abs: string; size: number }> {
  const pathKey = await realPathKey(sandboxRoot, rawPath);
  const realRoot = await realpath(sandboxRoot).catch(() => resolve(sandboxRoot));
  const abs = resolve(realRoot, pathKey);
  const O = fsConstants;
  if (mode === "write") await mkdir(dirname(abs), { recursive: true });
  const before = await lstat(abs).catch(() => null);
  if (before?.isSymbolicLink()) throw new Error(`symbolic link refused: ${pathKey}`);
  if (before && !before.isFile()) throw new Error(`not a regular file: ${pathKey}`);
  const flags = mode === "read" ? O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK : O.O_WRONLY | O.O_CREAT | O.O_NOFOLLOW | O.O_NONBLOCK;
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(abs, flags, 0o644);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "EMLINK") throw new Error(`symbolic link refused: ${pathKey}`);
    throw err;
  }
  const after = await handle.stat();
  let same = after.isFile() && (!before || (before.dev === after.dev && before.ino === after.ino));
  if (same && process.platform === "linux") {
    // Linux names the file an open descriptor holds: whatever the path did
    // on the way, the file open is the one at `abs` or it is refused.
    same = (await readlink(`/proc/self/fd/${handle.fd}`).catch(() => "")) === abs;
  } else if (same) {
    try {
      const again = await realPathKey(sandboxRoot, pathKey);
      const now = again === pathKey ? await lstat(resolve(realRoot, again)) : null;
      same = now !== null && now.isFile() && now.dev === after.dev && now.ino === after.ino;
    } catch {
      same = false;
    }
  }
  if (!same) {
    await handle.close();
    throw new Error(`the file changed under the harness: ${pathKey}`);
  }
  return { handle, pathKey, abs, size: after.size };
}

/**
 * The bytes of a sandbox file, read without following a planted link; null
 * when there is no such file. Past `maxBytes` it throws `FileTooLarge`
 * instead of reading: a sparse file of a few gigabytes is a few bytes on the
 * guest's side and all of the hub's memory on this one.
 */
export async function readSandboxFile(sandboxRoot: string, rawPath: string, options: { maxBytes?: number } = {}): Promise<{ pathKey: string; bytes: Buffer } | null> {
  let opened: Awaited<ReturnType<typeof openSandboxFile>>;
  try {
    opened = await openSandboxFile(sandboxRoot, rawPath, "read");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  try {
    if (options.maxBytes !== undefined && opened.size > options.maxBytes) throw new FileTooLarge(opened.pathKey, opened.size, options.maxBytes);
    return { pathKey: opened.pathKey, bytes: await opened.handle.readFile() };
  } finally {
    await opened.handle.close();
  }
}

/** The sha256 and size of a sandbox file, streamed: for a file too large to hold. */
export async function hashSandboxFile(sandboxRoot: string, rawPath: string): Promise<{ pathKey: string; sha256: string; bytes: number } | null> {
  let opened: Awaited<ReturnType<typeof openSandboxFile>>;
  try {
    opened = await openSandboxFile(sandboxRoot, rawPath, "read");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  try {
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of opened.handle.createReadStream({ autoClose: false })) {
      hash.update(chunk as Buffer);
      bytes += (chunk as Buffer).byteLength;
    }
    return { pathKey: opened.pathKey, sha256: hash.digest("hex"), bytes };
  } finally {
    await opened.handle.close();
  }
}

/** Write a sandbox file in place, never through a link; emptied only once it is known to be the file resolved. */
export async function writeSandboxFile(sandboxRoot: string, rawPath: string, bytes: Buffer | string): Promise<string> {
  const opened = await openSandboxFile(sandboxRoot, rawPath, "write");
  try {
    await opened.handle.truncate(0);
    await opened.handle.writeFile(bytes);
    return opened.pathKey;
  } finally {
    await opened.handle.close();
  }
}

export type PublishResult = { ok: true; path: string; from: string; sha256: string; bytes: number; rev: number | null } | { ok: false; reason: string; path?: string };

/**
 * Put a file of the agent's own into the shared part of `work/`. In a
 * microVM `work/` is read-only but for the agent's own directories, so a
 * shared deliverable (`work/report.md`, `work/timeline.md`) is written by the
 * harness: the destination is claimed for the agent (or refused when a peer
 * holds it, or when it is any seat's own directory), written in place, and
 * recorded in history under the agent's name. On the host the bytes are read
 * from the agent's directory without following a link; from a VM they come
 * with the call (`options.bytes`), since the hub does not open a file under
 * a directory a running seat can rearrange. On the host the same call does
 * the same thing, so a goal reads the same either way.
 */
export async function publishFile(ctx: SwarmContext, fromRaw: string, toRaw?: string, options: { bytes?: Buffer; ids?: string[] } = {}): Promise<PublishResult> {
  let fromKey: string;
  try {
    fromKey = await realPathKey(ctx.sandboxRoot, fromRaw);
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
  if (!isOwnScratch(fromKey, ctx.agentId)) {
    return { ok: false, reason: `publish takes a file of your own: ${fromKey} is not under work/${ctx.agentId}/, work/extracted/${ctx.agentId}/ or work/quarantine/${ctx.agentId}/`, path: fromKey };
  }
  const lexicalTo = claimKey(ctx.sandboxRoot, toRaw && toRaw.trim() ? toRaw : `work/${basename(fromKey)}`);
  // Every check on the destination is made on the path it really names:
  // a lexical `work/A1/x` is a1's file on a disk that ignores case.
  let toKey: string;
  try {
    toKey = await realPathKey(ctx.sandboxRoot, lexicalTo);
  } catch (err) {
    return { ok: false, reason: (err as Error).message, path: lexicalTo };
  }
  if (!toKey.startsWith("work/") || toKey === "work/") return { ok: false, reason: `a file is published under work/: ${toKey}`, path: toKey };
  // work/'s dot entries are the run's own: the trace spill custody reads,
  // the shared install area, the panes' temp directory.
  if (/^work\/\./.test(toKey) || isProtectedPath(toKey)) {
    return { ok: false, reason: `${toKey} is the harness's, not a shared file: publish to a name under work/ that does not start with a dot`, path: toKey };
  }
  // Whose directories are whose: the hub's roster when it passes one, else
  // the team file. With neither there is no telling a peer's directory from
  // a shared one, and nothing is published.
  const ids = options.ids?.length ? options.ids : await teamIds(ctx.sandboxRoot);
  if (!ids.length) return { ok: false, reason: "the run's team cannot be read, so a peer's directory cannot be told from a shared one; nothing is published", path: toKey };
  const owner = seatHoleOwner(toKey, [ctx.agentId, ...ids]) ?? seatHoleOwner(lexicalTo, ids);
  if (owner && owner.toLowerCase() === ctx.agentId.toLowerCase()) return { ok: false, reason: `${toKey} is your own directory already; publish puts a file in the shared part of work/`, path: toKey };
  if (owner) return { ok: false, reason: `${toKey} is ${owner}'s own directory; a peer's scratch is theirs to write`, path: toKey };
  let bytes: Buffer;
  if (options.bytes) {
    bytes = options.bytes;
  } else {
    const read = await readSandboxFile(ctx.sandboxRoot, fromKey);
    if (!read) return { ok: false, reason: `no such file: ${fromKey}`, path: fromKey };
    bytes = read.bytes;
  }
  const held = await heldBy(ctx, toKey);
  if (held && held.owner !== ctx.agentId) return { ok: false, reason: `claim violation: ${toKey} is held by ${held.owner}`, path: toKey };
  const claim = held ? { ok: true } : await claimFile(ctx, toKey, { reason: "publish", implicit: true });
  if (!claim.ok) return { ok: false, reason: `could not claim ${toKey}: ${"reason" in claim ? String((claim as { reason?: string }).reason) : "held by a peer"}`, path: toKey };
  const guard = await guardWrite(ctx, toKey);
  if (!guard.ok) return { ok: false, reason: guard.reason, path: toKey };
  await recordFileVersion(ctx.sandboxRoot, toKey, ctx.agentId).catch(() => null);
  try {
    await writeSandboxFile(ctx.sandboxRoot, toKey, bytes);
  } catch (err) {
    return { ok: false, reason: (err as Error).message, path: toKey };
  }
  const version = await recordFileVersion(ctx.sandboxRoot, toKey, ctx.agentId, { bytes }).catch(() => null);
  return { ok: true, path: toKey, from: fromKey, sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.byteLength, rev: version?.rev ?? null };
}

/** True when either the lexical path or what it really points at is harness-owned. */
export async function resolvesToProtected(sandboxRoot: string, rawPath: string): Promise<boolean> {
  if (isProtectedPath(claimKey(sandboxRoot, rawPath))) return true;
  try {
    return isProtectedPath(await realPathKey(sandboxRoot, rawPath));
  } catch {
    // Escapes the sandbox once resolved: treat as refused, like claimKey does.
    return true;
  }
}

export function lockHash(pathKey: string): string {
  return createHash("sha256").update(pathKey).digest("hex");
}

export function lockPath(sandboxRoot: string, pathKey: string): string {
  return join(sandboxRoot, "locks", `${lockHash(pathKey)}.json`);
}

export function sentinelPath(sandboxRoot: string): string {
  return join(sandboxRoot, SENTINEL_REL);
}

/**
 * Create done/SWARM_DONE, or report that someone else got there first.
 *
 * The sentinel is the swarm's clock and its record of who ended the run, so
 * "check, then write" is not good enough: two agents calling `done` in the same
 * instant would both believe they created it, both announce it on the board,
 * and the second write would overwrite the first one's provenance. An exclusive
 * create is decided by the filesystem, so it needs no lock and composes with
 * the harness's own stop path, which holds a different one.
 */
export async function createSentinel(sandboxRoot: string, body: string): Promise<boolean> {
  const sentinel = sentinelPath(sandboxRoot);
  await mkdir(dirname(sentinel), { recursive: true });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await writeFile(sentinel, body, { encoding: "utf8", flag: "wx" });
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // EEXIST covers a dangling symlink, which everything downstream reads as
      // "no sentinel" — leaving a swarm that can never be stopped. Clear that
      // one case and try again; a real sentinel is left alone.
      if (await swarmDoneExists(sandboxRoot)) return false;
      await rm(sentinel, { force: true }).catch(() => undefined);
    }
  }
  return false;
}

export function agentDonePath(sandboxRoot: string, agentId: string): string {
  return join(sandboxRoot, "done", "agents", `${agentId}.done`);
}

export function agentDeadPath(sandboxRoot: string, agentId: string): string {
  return join(sandboxRoot, "done", "agents", `${agentId}.dead`);
}

/**
 * The netguard sidecar outlives the agents it fronted: `swarm.sh stop` kills
 * it, but a swarm that finishes on its own sentinel leaves it listening
 * until someone runs stop. The last agent to leave turns the light off —
 * when every id in team.json has a done or dead marker, the pid in
 * netguard.pid gets TERM. Best effort: a missing file or a dead pid is fine.
 */
export async function stopNetguardSidecarIfOver(sandboxRoot: string): Promise<boolean> {
  let team: TeamRecord;
  try {
    team = await readTeam(sandboxRoot);
  } catch {
    return false;
  }
  for (const agent of team.agents) {
    const marker = await readAgentMarker(sandboxRoot, agent.id);
    if (marker !== "done" && marker !== "dead") return false;
  }
  const raw = await readFile(join(sandboxRoot, "netguard.pid"), "utf8").catch(() => "");
  const pid = Number(raw.trim());
  if (!Number.isInteger(pid) || pid <= 1) return false;
  try {
    process.kill(pid, "SIGTERM");
    return true;
  } catch {
    return false;
  }
}

export async function swarmDoneExists(sandboxRoot: string): Promise<boolean> {
  try {
    await stat(sentinelPath(sandboxRoot));
    return true;
  } catch {
    return false;
  }
}

let lockNamespaceCache: string | undefined;

/**
 * Where a pid recorded in a lock can be checked: this pid namespace and boot
 * on Linux, this boot on macOS. Two processes that print the same string
 * number their processes alike, so one can ask whether the other's pid is
 * live. "" when it cannot be told, and then only the lock's age counts.
 * The bash copies in reap.sh and swarm.sh print the same string.
 *
 * On macOS the boot is the boot session's UUID, not the host's name: a Mac
 * with no HostName set takes its name from the network it is on, so after a
 * sleep on another network reap.sh or `swarm.sh say` would print another
 * string than the panes stamped, and a stalled holder's lock would be judged
 * by its age alone.
 */
export function lockNamespace(): string {
  if (lockNamespaceCache !== undefined) return lockNamespaceCache;
  let ns = "";
  try {
    if (process.platform === "linux") {
      const pidNs = readlinkSync("/proc/self/ns/pid");
      const boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
      if (pidNs && boot) ns = `linux:${pidNs}:${boot}`;
    } else if (process.platform === "darwin") {
      const session = execFileSync("sysctl", ["-n", "kern.bootsessionuuid"], { encoding: "utf8", timeout: 2_000 }).trim();
      if (/^[0-9A-Fa-f-]+$/.test(session)) ns = `darwin:${session}`;
    }
  } catch {
    ns = "";
  }
  lockNamespaceCache = ns;
  return ns;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: it exists, it just is not ours to signal.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** What a holder writes into a lock directory it has just made. */
async function stampLock(dir: string, token: string): Promise<void> {
  await writeFile(join(dir, "pid"), String(process.pid), "utf8");
  await writeFile(join(dir, "ns"), lockNamespace(), "utf8");
  await writeFile(join(dir, "owner"), token, "utf8");
}

/**
 * "Now" by the clock that stamps the lock: the mtime of a probe file written
 * just now next to it. A holder in a microVM or on an NFS client stamps its
 * lock through the filesystem, and so does the probe, so the two are compared
 * on one clock whatever the host's and the guest's clocks say. Falls back to
 * our own clock when the probe cannot be written.
 */
async function filesystemNow(probe: string): Promise<number> {
  try {
    await writeFile(probe, String(process.pid), "utf8");
    return (await stat(probe)).mtimeMs;
  } catch {
    return Date.now();
  }
}

/**
 * How long since a lock last changed: made, or its `beat` file rewritten by
 * the holder's heartbeat. null when the lock is gone.
 */
async function lockAgeMs(dir: string, probe: string): Promise<number | null> {
  const now = await filesystemNow(probe);
  const info = await stat(dir).catch(() => null);
  if (info === null) return null;
  const beat = await stat(join(dir, "beat")).catch(() => null);
  return now - Math.max(info.mtimeMs, beat?.mtimeMs ?? 0);
}

/**
 * A lock is stale once it is older than the stale age, unless its holder is
 * known to be alive. Its holder is known to be alive only when it recorded the
 * same namespace as ours and its pid is live here; anything else — another
 * pane's pid namespace, another VM, an older lock with no `ns` — is judged by
 * age alone. So a holder that stalls (SIGSTOP, swap, a laptop asleep) keeps
 * its lock from a peer that can see it, and loses it after the stale age only
 * to a peer that cannot.
 */
async function lockIsStale(dir: string, probe: string): Promise<boolean> {
  const age = await lockAgeMs(dir, probe);
  if (age === null || age < tableLockTiming.staleMs) return false;
  const ns = (await readFile(join(dir, "ns"), "utf8").catch(() => "")).trim();
  if (ns && ns === lockNamespace()) {
    const pid = (await readFile(join(dir, "pid"), "utf8").catch(() => "")).trim();
    if (/^[1-9]\d*$/.test(pid) && pidAlive(Number(pid))) return false;
  }
  return true;
}

/** Say that a holder's lock was taken over while it held it. */
export function warnLockLost(message: string): void {
  process.emitWarning(message, { code: "DFIRSWARM_TABLE_LOCK_LOST" });
}

/**
 * Break a lock whose holder has stopped (see lockIsStale).
 *
 * A holder refreshes its lock's mtime every TABLE_LOCK_HEARTBEAT_MS, so an old
 * lock has no live holder unless that holder has stalled; a stalled holder is
 * kept by its pid where a peer can check it. The pid alone used to decide and
 * cannot: under fsguard's pid namespaces each pane numbers its own processes,
 * so a live holder in another pane looked dead and lost its lock after 15 s,
 * and an unrelated live pid could keep a dead lock standing.
 *
 * Breaking takes a second mkdir lock, `<lock>.break`, and judges the lock
 * again under it. Two waiters could otherwise both judge one dead lock stale:
 * the first removed it and took the lock, and the second's rm then removed
 * that live lock, putting both in the critical section.
 */
async function maybeBreakStaleTableLock(lockDir: string, token: string, probe: string): Promise<void> {
  if (!(await lockIsStale(lockDir, probe))) return;
  const breakDir = `${lockDir}.break`;
  try {
    await mkdir(breakDir);
  } catch {
    // Someone else is breaking it. One that died mid-break leaves its own
    // lock behind, cleared here once that is stale too.
    if (await lockIsStale(breakDir, probe)) await rm(breakDir, { recursive: true, force: true }).catch(() => undefined);
    return;
  }
  try {
    await stampLock(breakDir, token);
    if (await lockIsStale(lockDir, probe)) await rm(lockDir, { recursive: true, force: true }).catch(() => undefined);
  } finally {
    await releaseLockDir(breakDir, token);
  }
}

/**
 * Remove a lock directory only while it is still ours.
 *
 * Reading `owner` and then removing the path left a gap in which the lock
 * could be broken and taken by someone else, whose lock the rm then removed.
 * So the lock is first renamed to a name only we use, and `owner` is read
 * from there: what was renamed is exactly what gets judged. If it turns out
 * not to be ours (taken over between the read and the rename), it is renamed
 * back unless a new lock has appeared at the path meanwhile. That last step
 * still has a gap, but reaching it takes a stall, a break and a new mkdir
 * inside two renames.
 */
async function releaseLockDir(dir: string, token: string): Promise<void> {
  const lost = () =>
    warnLockLost(`${basename(dir)} was taken over while this process held it; another process may have been inside with it`);
  const owner = await readFile(join(dir, "owner"), "utf8").catch(() => "");
  if (owner !== token) return lost();
  const tomb = `${dir}.released.${token}`;
  try {
    await rename(dir, tomb);
  } catch {
    return lost();
  }
  if ((await readFile(join(tomb, "owner"), "utf8").catch(() => "")) === token) {
    await rm(tomb, { recursive: true, force: true });
    return;
  }
  const occupied = await stat(dir).then(() => true, () => false);
  if (occupied || !(await rename(tomb, dir).then(() => true, () => false))) {
    await rm(tomb, { recursive: true, force: true });
  }
  lost();
}

/** Thrown when a holder finds, before a write, that its lock was taken over. */
export class TableLockLostError extends Error {}

/** What a holder can ask of the lock it holds. */
export type HeldLock = {
  /**
   * Throws TableLockLostError when the lock is no longer ours: it was broken
   * while we stalled and someone else may be inside. Called just before a
   * read-modify-write commits, so a lost lock costs the write rather than
   * overwriting the other holder's. The check and the write are still two
   * steps, so this narrows the window; it does not close it.
   */
  assertOwned(): Promise<void>;
};

export async function withTableLock<T>(
  sandboxRoot: string,
  fn: (lock: HeldLock) => Promise<T>,
): Promise<T> {
  return withNamedLock(sandboxRoot, ".table.lock", fn);
}

/**
 * One named mutex under `locks/`, so two writers of the same file wait for
 * each other and nobody else waits for them.
 *
 * `withTableLock` used to be the only one, which meant the trace — the
 * highest-frequency write in the system, one line per tool call from every
 * pane — would have had to queue behind every budget fold and every ledger
 * render to be safe. Its own lock costs nothing and blocks nobody.
 */
export async function withNamedLock<T>(
  sandboxRoot: string,
  name: string,
  fn: (lock: HeldLock) => Promise<T>,
): Promise<T> {
  const lockDir = join(sandboxRoot, "locks", name);
  await mkdir(join(sandboxRoot, "locks"), { recursive: true });
  const deadline = Date.now() + tableLockTiming.waitMs;
  const token = `${process.pid}-${randomUUID()}`;
  const probe = join(sandboxRoot, "locks", `.probe.${token}`);
  try {
    while (true) {
      try {
        await mkdir(lockDir);
        await stampLock(lockDir, token);
        break;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== "EEXIST") throw err;
        await maybeBreakStaleTableLock(lockDir, token, probe);
        if (Date.now() > deadline) {
          throw new Error(`Timed out waiting for locks/${name}`);
        }
        await sleep(20);
      }
    }
  } finally {
    await rm(probe, { force: true }).catch(() => undefined);
  }
  // The heartbeat that keeps a held lock from ever looking stale. It writes a
  // file rather than setting a time, so the filesystem stamps it (see
  // filesystemNow), and it stops once the lock is no longer ours: a holder
  // whose lock was broken while it stalled must not keep the next holder's
  // lock fresh.
  const heartbeat = setInterval(() => {
    readFile(join(lockDir, "owner"), "utf8")
      .then((owner) => {
        if (owner !== token) {
          clearInterval(heartbeat);
          return;
        }
        return writeFile(join(lockDir, "beat"), token, "utf8");
      })
      .catch(() => undefined);
  }, tableLockTiming.heartbeatMs);
  heartbeat.unref();
  const held: HeldLock = {
    async assertOwned() {
      const owner = await readFile(join(lockDir, "owner"), "utf8").catch(() => "");
      if (owner !== token) {
        throw new TableLockLostError(
          `locks/${name} was taken over while this call held it, so its write was not made. Try again.`,
        );
      }
    },
  };
  try {
    return await fn(held);
  } finally {
    clearInterval(heartbeat);
    // Remove only our own lock. One broken while its holder stalled may
    // already belong to someone else, and that is said rather than ignored.
    await releaseLockDir(lockDir, token);
  }
}

function lockLive(lock: LockRecord, now = Date.now()): boolean {
  return Date.parse(lock.expires_at) > now;
}

async function readLock(file: string): Promise<LockRecord | null> {
  try {
    const raw = await readFile(file, "utf8");
    return JSON.parse(raw) as LockRecord;
  } catch {
    return null;
  }
}

export async function readTeam(sandboxRoot: string): Promise<TeamRecord> {
  const raw = await readFile(join(sandboxRoot, "team.json"), "utf8");
  return JSON.parse(raw) as TeamRecord;
}

export function emptyAgentBudget(): AgentBudget {
  return {
    spent_usd: 0,
    tokens: 0,
    calls: 0,
    input: 0,
    output: 0,
    cache_read: 0,
    cache_write: 0,
  };
}

export function normalizeBudget(raw: Partial<BudgetRecord> | null | undefined): BudgetRecord {
  const agents: Record<string, AgentBudget> = {};
  if (raw?.agents && typeof raw.agents === "object") {
    for (const [id, slice] of Object.entries(raw.agents)) {
      agents[id] = {
        ...emptyAgentBudget(),
        ...(slice ?? {}),
      };
    }
  }
  return {
    cap_usd: Number(raw?.cap_usd) || 0,
    spent_usd: Number(raw?.spent_usd) || 0,
    tokens: Number(raw?.tokens) || 0,
    calls: Number(raw?.calls) || 0,
    // An until-solved run has no wall clock: its zero is kept, not read as unset.
    wall_clock_minutes: raw?.until_solved === true ? Math.max(0, Number(raw?.wall_clock_minutes) || 0) : Number(raw?.wall_clock_minutes) || 15,
    started_at: raw?.started_at ?? new Date().toISOString(),
    source: raw?.source ?? BUDGET_SOURCE,
    hard_kill: Boolean(raw?.hard_kill),
    cap_steer_sent: Boolean(raw?.cap_steer_sent),
    // The kickoff writes the per-agent cap once; every fold of session usage
    // rewrites the record, so a field left out here is a cap that silently
    // stops existing after the first model call.
    ...(Number(raw?.cap_per_agent_usd) > 0
      ? { cap_per_agent_usd: Number(raw?.cap_per_agent_usd) }
      : {}),
    ...(Number(raw?.cap_per_agent_tokens) > 0
      ? { cap_per_agent_tokens: Number(raw?.cap_per_agent_tokens) }
      : {}),
    ...(Array.isArray(raw?.cap_changes) && raw.cap_changes.length ? { cap_changes: raw.cap_changes } : {}),
    ...(() => {
      const caps = perModelCaps(raw?.cap_per_model_usd);
      return Object.keys(caps).length ? { cap_per_model_usd: caps } : {};
    })(),
    // The same holds for the two fields a free team's brake is made of.
    metered: raw?.metered !== false,
    ...(Number(raw?.cap_tokens) > 0 ? { cap_tokens: Number(raw?.cap_tokens) } : {}),
    ...(raw?.stop_steer_at ? { stop_steer_at: raw.stop_steer_at } : {}),
    ...(raw?.stop_reason ? { stop_reason: raw.stop_reason } : {}),
    ...(raw?.until_solved === true ? { until_solved: true } : {}),
    ...(Number(raw?.stall_minutes) > 0 ? { stall_minutes: Number(raw?.stall_minutes) } : {}),
    // How the seats coordinate: kept by every fold, as the stop policy is.
    ...(raw?.coordination && typeof raw.coordination === "object" ? { coordination: { ...(Number(raw.coordination.first_choice_stagger_sec) > 0 ? { first_choice_stagger_sec: Number(raw.coordination.first_choice_stagger_sec) } : {}), ...(Number(raw.coordination.first_choice_bound_sec) > 0 ? { first_choice_bound_sec: Number(raw.coordination.first_choice_bound_sec) } : {}) } } : {}),
    // The stop policy and its pauses: kept by every fold, or a pause would lift itself on the next model call's usage.
    ...((STOP_POLICIES as readonly string[]).includes(String(raw?.stop_policy)) ? { stop_policy: raw!.stop_policy as StopPolicy } : {}),
    ...(raw?.paused && typeof raw.paused === "object" && typeof raw.paused.at === "string" ? { paused: raw.paused } : {}),
    ...(Array.isArray(raw?.pauses) && raw.pauses.length ? { pauses: raw.pauses } : {}),
    ...(Number(raw?.wall_used_ms) > 0 ? { wall_used_ms: Number(raw?.wall_used_ms) } : {}),
    ...(typeof raw?.wall_base_at === "string" && raw.wall_base_at ? { wall_base_at: raw.wall_base_at } : {}),
    ...(Array.isArray(raw?.resumes) && raw.resumes.length ? { resumes: raw.resumes } : {}),
    agents,
  };
}

/** The per-model caps that are real: a positive number under a model id. */
function perModelCaps(raw: unknown): Record<string, number> {
  const caps: Record<string, number> = {};
  if (!raw || typeof raw !== "object") return caps;
  for (const [model, cap] of Object.entries(raw as Record<string, unknown>)) {
    const value = Number(cap);
    if (model && Number.isFinite(value) && value > 0) caps[model] = value;
  }
  return caps;
}

/**
 * A file every reader must see whole: written beside itself and renamed,
 * which is atomic on POSIX. A plain writeFile truncates first, and a writer
 * killed in between left budget.json empty, which the next usage fold then
 * rebuilt from defaults: no cap, a fifteen-minute clock started now.
 */
export async function writeFileAtomic(path: string, text: string): Promise<void> {
  const staging = join(dirname(path), `.${basename(path)}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`);
  try {
    await writeFile(staging, text, "utf8");
    await rename(staging, path);
  } catch (err) {
    await rm(staging, { force: true }).catch(() => undefined);
    throw err;
  }
}

/** How long a fold waits before reading an unreadable budget.json again. */
const BUDGET_REREAD_MS = 100;

export async function readBudget(sandboxRoot: string): Promise<BudgetRecord> {
  const raw = await readFile(join(sandboxRoot, "budget.json"), "utf8");
  return normalizeBudget(JSON.parse(raw) as Partial<BudgetRecord>);
}

/** True when the run's guard holds budget.json by its inode (Landlock alone). */
async function budgetPinnedByInode(sandboxRoot: string): Promise<boolean> {
  const plan = await readFile(join(sandboxRoot, ".fsguard", "plan.txt"), "utf8").catch(() => "");
  return /^mode: landlock$/m.test(plan);
}

/**
 * Replace budget.json whole: a temp file beside it, then `rename` over it, so
 * a reader outside the table lock (`maybeEnforceStops`, `watchCaps`, the UI,
 * observe) sees the old record or the new one, never half of one, and a
 * crash mid-write leaves the old record in place.
 *
 * The temp file sits in budget.json's own directory, the sandbox root, since
 * `rename` does not cross filesystems.
 *
 * Under Landlock alone (`mode: landlock` in the kickoff's .fsguard/plan.txt)
 * the record is written in place, as it always was, by every process of the
 * run. There inputs/ is carved out of the sandbox, so the root is
 * listing-only (scripts/landlock.py `plan`) and budget.json's rights are a
 * rule on its inode, taken when each pane started. A rename cannot happen
 * inside such a pane, and one from a pane that runs without the guard would
 * put a new inode at the name that no confined pane could read or write
 * again. An EACCES or EPERM on the temp file falls back the same way.
 * Any other failure (a full disk) is thrown, not retried in place:
 * truncating the live file on a disk that cannot take the new bytes is how a
 * torn record is made.
 */
export async function writeBudget(sandboxRoot: string, budget: BudgetRecord): Promise<void> {
  const normalized = normalizeBudget(budget);
  const target = join(sandboxRoot, "budget.json");
  const body = `${JSON.stringify(normalized, null, 2)}\n`;
  if (await budgetPinnedByInode(sandboxRoot)) {
    await writeFile(target, body, "utf8");
    return;
  }
  const temp = join(dirname(target), `.budget.json.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  try {
    // `wx`: never through a link or over a file someone put at that name.
    await writeFile(temp, body, { encoding: "utf8", flag: "wx", mode: 0o644 });
    await rename(temp, target);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // A write that failed after the open (a full disk) leaves a partial temp
    // file behind; EEXIST means the name was someone else's, so leave it.
    if (code !== "EEXIST") await rm(temp, { force: true }).catch(() => undefined);
    if (code !== "EACCES" && code !== "EPERM") throw err;
    await writeFile(target, body, "utf8");
  }
}

/** Session-scoped counters that are not spend but ride with it: what the
 *  session's compactions cost and how many hand-offs it completed. Carried
 *  forward like the spend, so a restart does not reset "hand-offs cost X"
 *  next to a whole-run total. Left out of a row that never had them. */
export const SESSION_EXTRAS = ["compactions", "compaction_tokens", "compaction_usd", "handoffs"] as const;
/** Stands for what a seat recorded before its reports carried a session id. */
export const UNKEYED_SESSION = "unkeyed";

function countersOf(row: Partial<AgentBudget> | undefined): CarriedCounters {
  const out = { spent_usd: 0, tokens: 0, calls: 0, input: 0, output: 0, cache_read: 0, cache_write: 0 } as CarriedCounters;
  for (const key of SESSION_COUNTERS) out[key] = Number(row?.[key]) || 0;
  for (const key of SESSION_EXTRAS) {
    const value = Number(row?.[key]) || 0;
    if (value > 0) out[key] = value;
  }
  return out;
}

function addCounters(a: CarriedCounters, b: CarriedCounters, sign = 1): CarriedCounters {
  const out = { ...a } as CarriedCounters;
  const round = (key: string, value: number) => (key.endsWith("_usd") ? Number(value.toFixed(6)) : value);
  for (const key of SESSION_COUNTERS) out[key] = round(key, (a[key] || 0) + sign * (b[key] || 0));
  for (const key of SESSION_EXTRAS) {
    const value = round(key, (a[key] || 0) + sign * (b[key] || 0));
    if (value > 0) out[key] = value;
    else delete out[key];
  }
  return out;
}

function anyCounter(counters: CarriedCounters): boolean {
  return [...SESSION_COUNTERS, ...SESSION_EXTRAS].some((key) => (counters[key] || 0) > 0);
}

/**
 * A seat's row after a fold, never smaller than before it. Pi reports a
 * session's own totals, so a pane whose session restarts reports from zero
 * again; replacing the row with that would hand back money already spent
 * and could lift a swarm over its cap back under it.
 *
 * With a session id on the report (`sessionManager.getSessionId()`), the row
 * keeps each session's last report under its id in `sessions` and its
 * counters are their sum: a restart adds a session, `/new` then `/resume`
 * back replaces the resumed session's entry instead of adding it again, and
 * two processes sharing one AGENT_ID each keep their own entry. A session
 * whose report goes down is not believed (sessions are append-only); its
 * last report stands.
 *
 * Without an id, a counter going down is what says a new session began: the
 * seat's totals so far are carried forward in `earlier_sessions` and the new
 * session adds to them. That heuristic over-counts where the id does not:
 * `/new` then `/resume` back adds the resumed session again (5 -> 0.5 -> 5 ->
 * 5.2 records 10.2, not 5.7), and two live processes with one AGENT_ID add a
 * full copy at every alternation.
 *
 * Either way, `/fork` over-counts: the new session starts with a copy of the
 * prefix's entries, usage included, and gets a new id, so the prefix is
 * counted in both sessions (5 USD forked at call 31 records about 8.1). A
 * report that switches between having an id and not (getSessionId failing
 * now and then) counts the live session twice. Every one of these errs high,
 * which for a brake is the safe side, and none occurs in a headless swarm.
 */
export function foldSessionSlice(previous: AgentBudget | undefined, slice: SessionUsageSlice): AgentBudget {
  // A report of nothing at all is not a new session: it is what a failed read
  // of the session looks like, and folding it as one would add the whole old
  // session again on the next good read (4 -> 0 -> 5 recorded 9). A session
  // that really is new has nothing to add yet, so keeping the counters loses
  // nothing; its first real report starts the carry.
  const kept = new Set<string>([...SESSION_COUNTERS, ...SESSION_EXTRAS, "session_id", "sessions", "earlier_sessions"]);
  if (previous && SESSION_COUNTERS.every((key) => !(Number(slice[key]) > 0))) {
    const row: AgentBudget = { ...previous };
    for (const [key, value] of Object.entries(slice)) {
      if (!kept.has(key) && value !== undefined) (row as Record<string, unknown>)[key] = value;
    }
    return row;
  }
  const row: AgentBudget = { ...emptyAgentBudget(), ...slice };
  delete row.earlier_sessions;
  delete row.sessions;
  delete row.session_id;
  const put = (counters: CarriedCounters) => {
    for (const key of SESSION_EXTRAS) delete row[key];
    Object.assign(row, counters);
  };
  const live = countersOf(slice);
  const sessionId = typeof slice.session_id === "string" && slice.session_id ? slice.session_id : undefined;

  if (sessionId) {
    const sessions: Record<string, CarriedCounters> = {};
    for (const [id, counters] of Object.entries(previous?.sessions ?? {})) sessions[id] = countersOf(counters);
    // A row folded before reports carried an id: all of it is an earlier session.
    if (previous && !previous.sessions && anyCounter(countersOf(previous))) sessions[UNKEYED_SESSION] = countersOf(previous);
    const before = sessions[sessionId];
    if (!before || !SESSION_COUNTERS.some((key) => live[key] < before[key] - 1e-9)) sessions[sessionId] = live;
    let total = countersOf(undefined);
    for (const counters of Object.values(sessions)) total = addCounters(total, counters);
    put(total);
    row.session_id = sessionId;
    row.sessions = sessions;
    const earlier = addCounters(total, sessions[sessionId], -1);
    if (Object.keys(sessions).length > 1) row.earlier_sessions = earlier;
    return row;
  }

  let carried = countersOf(undefined);
  if (previous) {
    const before = countersOf(previous.earlier_sessions);
    // What the live session had reported at the last fold.
    const lastLive = addCounters(countersOf(previous), before, -1);
    const restarted = SESSION_COUNTERS.some((key) => live[key] < lastLive[key] - 1e-9);
    carried = restarted ? countersOf(previous) : before;
  }
  if (anyCounter(carried)) {
    put(addCounters(carried, live));
    row.earlier_sessions = carried;
  }
  return row;
}

/**
 * The hello exercise, as a goal document. The canonical copy an operator
 * edits is prompts/goals/hello.md; this is the fallback for sandboxes built
 * straight from `initSandbox` (tests and fixtures), which cannot read the
 * repo. Both carry their own definition of done — nothing else supplies one.
 */
export const DEFAULT_GOAL_DOCUMENT = `## Goal

Peer agents share this isolated folder. Each of you introduces yourself on
\`threads/main\`, then the team writes one file containing every assigned
agent id. Claim the file before writing it and yield on a conflict.

## Definition of done

\`${HELLO_REL}\` exists and contains every id listed in \`team.json\`, one per line.

## Checks

- \`test -f ${HELLO_REL}\`
- \`ids=$(jq -e -r '.agents[].id' team.json) && for id in $ids; do grep -qw "$id" ${HELLO_REL} || exit 1; done\`
`;

/**
 * Frame a goal document as the swarm contract. The goal brings its own
 * definition of done and checks; the harness adds only the team, the caps and
 * the bail-out.
 */
export function swarmMarkdown(
  swarmId: string,
  agentIds: readonly string[],
  options: { capUsd?: number; wallClockMinutes?: number; goal?: string; n?: number } = {},
): string {
  const idList = agentIds.map((id) => `\`${id}\``).join(", ");
  const cap = options.capUsd ?? 1;
  const wall = options.wallClockMinutes ?? 15;
  const n = options.n ?? agentIds.length;
  const goal = options.goal?.trim() || DEFAULT_GOAL_DOCUMENT;
  return `# Swarm contract

${goal}

## Team

Assigned ids: ${idList}

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Caps

- Spend: $${cap.toFixed(2)} USD across the swarm
- Wall clock: ${wall} minutes
- N: ${n}
- Swarm id: \`${swarmId}\`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
\`done\` with reason \`cannot_complete\` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.
`;
}

export async function initSandbox(
  sandboxRoot: string,
  options: {
    swarmId?: string;
    agentIds?: readonly string[];
    reset?: boolean;
    capUsd?: number;
    wallClockMinutes?: number;
    goal?: string;
    hardKill?: boolean;
    roles?: readonly string[];
  } = {},
): Promise<void> {
  const swarmId = options.swarmId ?? DEFAULT_SWARM_ID;
  const agentIds = options.agentIds ?? DEFAULT_AGENT_IDS;
  const root = resolve(sandboxRoot);

  if (options.reset) {
    await rm(root, { recursive: true, force: true });
  }

  const dirs = [
    join(root, "threads", "main"),
    join(root, "work"),
    join(root, "locks"),
    join(root, "done", "agents"),
    join(root, "traces"),
    join(root, HISTORY_REL),
    ...agentIds.map((id) => join(root, "inbox", id)),
  ];
  for (const dir of dirs) {
    await mkdir(dir, { recursive: true });
  }

  const team: TeamRecord = {
    swarm_id: swarmId,
    n: agentIds.length,
    agents: agentIds.map((id, i) => ({
      id,
      role: options.roles?.[i] ?? "worker",
    })),
  };
  const budget = normalizeBudget({
    cap_usd: options.capUsd ?? 1,
    spent_usd: 0,
    tokens: 0,
    calls: 0,
    wall_clock_minutes: options.wallClockMinutes ?? 15,
    started_at: new Date().toISOString(),
    source: BUDGET_SOURCE,
    hard_kill: options.hardKill ?? false,
    cap_steer_sent: false,
    agents: Object.fromEntries(agentIds.map((id) => [id, emptyAgentBudget()])),
  });

  await writeFile(
    join(root, "SWARM.md"),
    swarmMarkdown(swarmId, agentIds, {
      capUsd: budget.cap_usd,
      wallClockMinutes: budget.wall_clock_minutes,
      goal: options.goal,
      n: agentIds.length,
    }),
    "utf8",
  );
  await writeFile(join(root, "team.json"), `${JSON.stringify(team, null, 2)}\n`, "utf8");
  await writeBudget(root, budget);
  try {
    await stat(join(root, EVENTS_REL));
  } catch {
    await writeFile(join(root, EVENTS_REL), "", "utf8");
  }

  for (const id of agentIds) {
    const cursors = join(root, "inbox", id, CURSORS_REL);
    try {
      await stat(cursors);
    } catch {
      await writeFile(cursors, "{}\n", "utf8");
    }
  }

  const mainMeta = await readThreadMeta(root, PRIMARY_THREAD);
  if (!mainMeta) {
    await writeThreadMeta(root, {
      name: PRIMARY_THREAD,
      purpose: "Primary thread. Everyone reads it; the harness posts here.",
      created_by: SYSTEM_AGENT,
      created_at: new Date().toISOString(),
      members: [...agentIds],
    });
  }
}

/**
 * Values interpolated into YAML frontmatter. A newline in `to` / `reason` /
 * `output` would become extra keys (`from`, `id`) and later keys win in
 * `parseFrontMatter`, which is how a post could impersonate `system` and
 * jump the inbox cursor.
 */
export function yamlOneLine(value: string): string {
  return String(value)
    .replace(/[\r\n\u0085\u2028\u2029]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function parseFrontMatter(text: string): { attrs: Record<string, string>; body: string } {
  const match = text.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!match) return { attrs: {}, body: text.trim() };
  const attrs: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    if (!key || key in attrs) continue;
    attrs[key] = line.slice(idx + 1).trim();
  }
  return { attrs, body: match[2].trim() };
}

async function listPostFiles(sandboxRoot: string, thread: string): Promise<string[]> {
  const dir = join(sandboxRoot, "threads", thread);
  try {
    const names = await readdir(dir);
    return names
      .filter((name) => /^\d{6}-.+\.md$/.test(name))
      .sort()
      .map((name) => join(dir, name));
  } catch {
    return [];
  }
}

/** Highest post id in a thread, from the 6-digit filename prefixes; 0 when empty. */
async function maxPostId(sandboxRoot: string, thread: string): Promise<number> {
  let names: string[];
  try {
    names = await readdir(join(sandboxRoot, "threads", thread));
  } catch {
    return 0;
  }
  let max = 0;
  for (const name of names) {
    if (!/^\d{6}-.+\.md$/.test(name)) continue;
    const id = Number.parseInt(name.slice(0, 6), 10);
    if (id > max) max = id;
  }
  return max;
}

async function nextPostId(sandboxRoot: string, thread: string): Promise<number> {
  return (await maxPostId(sandboxRoot, thread)) + 1;
}

/**
 * A result posted after the output file was last written: on the Azure run the
 * critic signed off, three seats then corrected the download origin on the
 * board, the timeline was republished, and the report went out with the wrong
 * answer because nothing made the sentinel wait for it.
 *
 * Only `result` and `veto` posts count — an `ask` is a question, not a
 * correction — and only posts by somebody other than the agent calling `done`,
 * because an agent quoting itself is not news.
 */
export async function outputWrittenAt(sandboxRoot: string, outputFile: string): Promise<number> {
  let pathKey: string;
  try {
    pathKey = claimKey(sandboxRoot, outputFile);
  } catch {
    // A `..` escape must not supply an mtime that skips the late-correction check.
    return 0;
  }
  const abs = resolve(sandboxRoot, pathKey);
  const info = await lstat(abs).catch(() => null);
  if (!info) return 0;
  if (info.isSymbolicLink()) {
    const real = await realpath(abs).catch(() => null);
    const root = await realpath(sandboxRoot).catch(() => resolve(sandboxRoot));
    if (!real || (real !== root && !real.startsWith(root + sep))) return 0;
    const target = await stat(abs).catch(() => null);
    return target?.mtimeMs ?? 0;
  }
  return info.mtimeMs;
}

export async function correctionsAfter(
  sandboxRoot: string,
  outputFile: string,
  agentId: string,
  since?: number,
): Promise<Array<{ id: number; from: string; tag: PostTag }>> {
  // A missing output is not "no corrections": it has never answered the board.
  // `since` (the finish's anchor, extensions/finish.ts) keeps what was late
  // against an earlier version of the output late through the later ones.
  const writtenAt = typeof since === "number" && Number.isFinite(since) ? since : await outputWrittenAt(sandboxRoot, outputFile);
  const dir = join(sandboxRoot, "threads", PRIMARY_THREAD);
  const files = await readdir(dir).catch(() => [] as string[]);
  const out: Array<{ id: number; from: string; tag: PostTag }> = [];
  for (const name of files) {
    if (!name.endsWith(".md")) continue;
    const file = join(dir, name);
    const postedAt = await stat(file).then((s) => s.mtimeMs).catch(() => 0);
    if (postedAt <= writtenAt) continue;
    const post = await readPost(file).catch(() => null);
    if (!post) continue;
    if (post.from === agentId || post.from === SYSTEM_AGENT) continue;
    if (post.tag !== "result" && post.tag !== "veto") continue;
    out.push({ id: post.id, from: post.from, tag: post.tag });
  }
  return out.sort((a, b) => a.id - b.id);
}

/** `names.json`: what each agent decided to call itself, and when. */
export type NameRecord = {
  /** The agent's id, which the harness allocated and nobody chose. */
  id: string;
  /** What it calls itself, in its own words. */
  name: string;
  /** What it said it was taking on when it chose the name. */
  doing?: string;
  at: string;
  /** When it first named itself: its first choice (A1), kept whatever it says since. */
  first_at?: string;
};

export const NAMES_REL = "names.json";

/**
 * A name an agent gave itself, tidied just enough to sit beside an id on a
 * board: one line, no markup, 32 characters. The harness never invents one and
 * never assigns work — an agent decides what it is doing and says so, and this
 * is where that answer is kept.
 */
export function tidyName(raw: string | undefined | null): string | undefined {
  if (!raw) return undefined;
  const one = String(raw).replace(/[`*_\[\]]/g, "").replace(/\s+/g, " ").trim();
  if (!one) return undefined;
  return one.length > 32 ? `${one.slice(0, 31)}…` : one;
}

export async function readNames(sandboxRoot: string): Promise<NameRecord[]> {
  const raw = await readFile(join(sandboxRoot, NAMES_REL), "utf8").catch(() => "");
  if (!raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw) as { names?: NameRecord[] };
    return Array.isArray(parsed.names) ? parsed.names : [];
  } catch {
    return [];
  }
}

export async function nameOf(sandboxRoot: string, agentId: string): Promise<string | undefined> {
  return (await readNames(sandboxRoot)).find((n) => n.id === agentId)?.name;
}

/**
 * Take a name. Two agents may not answer to the same one, because the board
 * has to stay readable. A seat's name is stable once given (A1): on ctf12
 * Belka's seats renamed themselves 19 times in the first three minutes, and
 * a rename was read as a claim on work. What a seat works on shows from the
 * lead it holds (its label, leads.ts seatLabel); a later call updates what
 * it says it is doing, and keeps the name.
 */
export type NameResult =
  | {
      ok: true;
      name: string;
      /** The name asked for, when the stable one was kept instead. */
      asked?: string;
      /** A first choice made in turn (leads.ts admitFirstChoice): the order, the wait and the register's coverage then. */
      admission?: unknown;
      previous?: string;
      /** Everyone else who has said what they are doing. */
      peers: Array<{ id: string; name: string; doing?: string }>;
      /** Peers whose stated work looks like this one's. Nothing is reassigned. */
      overlaps?: Array<{ name: string; doing?: string }>;
    }
  | { ok: false; error: string; taken_by?: string };

export async function claimName(
  sandboxRoot: string,
  agentId: string,
  rawName: string,
  doing?: string,
): Promise<NameResult> {
  const asked = tidyName(rawName);
  if (!asked) return { ok: false, error: "A name is one line of text; this one was empty." };
  // A name and what an agent says it is doing sit on every board, header
  // and report: neither may carry a value the run marks sensitive (B9),
  // whatever its origin, the goal's own words included.
  const leak = await sensitiveRefusalOf(sandboxRoot, [["the name", String(rawName ?? "")], ["the name", asked], ["doing", doing ? String(doing) : ""]]);
  if (leak) return { ok: false, error: `${leak}. Nothing was recorded.` };
  // A seat's first choice waits for its turn when the kickoff staggers them (leads.ts).
  const admission = await import("./leads.ts").then((L) => L.admitFirstChoice(sandboxRoot, agentId)).catch(() => null);
  return withTableLock(sandboxRoot, async () => {
    const names = await readNames(sandboxRoot);
    const had = names.find((n) => n.id === agentId);
    // Stable once given: a later call keeps the name and updates what the seat is doing.
    const name = had?.name ?? asked;
    // "dump5 hunter" and "dump5-hunter" are one name to a reader, and two
    // agents took exactly that pair on the memory case. Compare what a reader
    // sees: letters and digits, nothing else.
    const key = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "");
    const clash = names.find((n) => n.id !== agentId && key(n.name) === key(name));
    if (clash) {
      return { ok: false as const, error: `${clash.id} already answers to "${name}". Pick another.`, taken_by: clash.id };
    }
    const previous = had?.name;
    const next = names.filter((n) => n.id !== agentId);
    // Whole: what an agent says it is doing is part of the record, and a
    // sentence cut at 280 characters read as one the agent never wrote.
    const doingText = doing ? String(doing).trim() : "";
    const at = new Date().toISOString();
    const mine = { id: agentId, name, ...(doingText ? { doing: doingText } : had?.doing ? { doing: had.doing } : {}), at, first_at: had?.first_at ?? had?.at ?? at };
    next.push(mine);
    next.sort((a, b) => a.id.localeCompare(b.id));
    await writeFile(join(sandboxRoot, NAMES_REL), `${JSON.stringify({ names: next }, null, 2)}\n`, "utf8");
    // Who else is here, and who said something close to this. Nobody is moved:
    // the swarm divides its own work, and this is what it needs to do that —
    // the same overlap that four agents on one case found only by colliding.
    const peers = next.filter((n) => n.id !== agentId);
    const close = doing
      ? peers.filter((n) => n.doing && overlap(meaningfulWords(doing), meaningfulWords(n.doing)) >= 0.5)
      : [];
    return {
      ok: true as const,
      name,
      ...(had && key(asked) !== key(had.name) ? { asked } : {}),
      ...(admission ? { admission } : {}),
      ...(previous ? { previous } : {}),
      peers: peers.map((n) => ({ id: n.id, name: n.name, ...(n.doing ? { doing: n.doing } : {}) })),
      ...(close.length
        ? { overlaps: close.map((n) => ({ name: n.name, doing: n.doing })) }
        : {}),
    };
  });
}

export async function readPost(file: string): Promise<PostRecord> {
  const text = await readFile(file, "utf8");
  const { attrs, body } = parseFrontMatter(text);
  const rawTag = attrs.tag ?? "";
  const tag: PostTag = isPostTag(rawTag) ? rawTag : "ask";
  const fileId = Number.parseInt(basename(file).slice(0, 6), 10);
  const id = Number.isFinite(fileId) && fileId > 0 ? fileId : Number.parseInt(attrs.id ?? "0", 10);
  return {
    id,
    thread: attrs.thread ?? "main",
    from: attrs.from ?? "unknown",
    to: attrs.to ?? "all",
    tag,
    body,
    path: file,
    ...(attrs.name ? { name: attrs.name } : {}),
    ...(attrs.via ? { via: attrs.via } : {}),
  };
}

/**
 * Who a post is from, as an agent reads it. A harness post sent from inside
 * a VM (a seat's extension posting a veto or a notice) is the harness code
 * in that seat's VM, which the seat's guest root controls: peers read it as
 * that seat's, never as the harness's own.
 */
export function postSender(post: { from: string; via?: string }): string {
  return post.via ? `${post.from} via ${post.via}` : post.from;
}

export function normalizeThreadName(raw: string | undefined): string {
  const name = (raw ?? PRIMARY_THREAD).replace(/[^a-zA-Z0-9_-]/g, "");
  if (!name) throw new Error("Invalid thread name");
  return name;
}

function threadMetaPath(sandboxRoot: string, thread: string): string {
  return join(sandboxRoot, "threads", thread, THREAD_META);
}

export async function readThreadMeta(
  sandboxRoot: string,
  thread: string,
): Promise<ThreadMeta | null> {
  try {
    const raw = await readFile(threadMetaPath(sandboxRoot, thread), "utf8");
    const parsed = JSON.parse(raw) as Partial<ThreadMeta>;
    return {
      name: parsed.name ?? thread,
      purpose: parsed.purpose ?? "",
      created_by: parsed.created_by ?? "unknown",
      created_at: parsed.created_at ?? "",
      members: Array.isArray(parsed.members) ? parsed.members : [],
    };
  } catch {
    return null;
  }
}

async function writeThreadMeta(sandboxRoot: string, meta: ThreadMeta): Promise<void> {
  const file = threadMetaPath(sandboxRoot, meta.name);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(meta, null, 2)}\n`, "utf8");
}

/**
 * Ensure the thread exists and `agentId` is on its member list. Members are
 * who gets the thread in a no-argument `inbox`; posting joins you implicitly,
 * `thread_join` lets a reader (a critic, say) subscribe without posting.
 */
async function ensureThreadMember(
  sandboxRoot: string,
  thread: string,
  agentId: string,
  options: { purpose?: string; creator?: string } = {},
): Promise<ThreadMeta> {
  const existing = await readThreadMeta(sandboxRoot, thread);
  const meta: ThreadMeta = existing ?? {
    name: thread,
    purpose: options.purpose ?? "",
    created_by: options.creator ?? agentId,
    created_at: new Date().toISOString(),
    members: [],
  };
  if (options.purpose && !meta.purpose) meta.purpose = options.purpose;
  if (agentId !== SYSTEM_AGENT && !meta.members.includes(agentId)) {
    meta.members.push(agentId);
  }
  await writeThreadMeta(sandboxRoot, meta);
  return meta;
}

export async function threadOpen(
  ctx: SwarmContext,
  args: { name: string; purpose: string },
): Promise<ThreadMeta & { created: boolean }> {
  const thread = normalizeThreadName(args.name);
  const purpose = args.purpose.trim();
  if (!purpose) throw new Error("thread_open requires a purpose: say what the thread is for.");
  return withTableLock(ctx.sandboxRoot, async () => {
    const existing = await readThreadMeta(ctx.sandboxRoot, thread);
    const meta = await ensureThreadMember(ctx.sandboxRoot, thread, ctx.agentId, {
      purpose,
      creator: ctx.agentId,
    });
    return { ...meta, created: existing === null };
  });
}

export async function threadJoin(ctx: SwarmContext, name: string): Promise<ThreadMeta> {
  const thread = normalizeThreadName(name);
  return withTableLock(ctx.sandboxRoot, async () => {
    const existing = await readThreadMeta(ctx.sandboxRoot, thread);
    if (!existing) {
      const files = await listPostFiles(ctx.sandboxRoot, thread);
      if (files.length === 0) throw new Error(`No thread named "${thread}"`);
    }
    return ensureThreadMember(ctx.sandboxRoot, thread, ctx.agentId);
  });
}

/** Every thread on the board, whether or not it has a meta.json yet. */
export async function listThreadNames(sandboxRoot: string): Promise<string[]> {
  const names = await readdir(join(sandboxRoot, "threads"), { withFileTypes: true }).catch(
    () => [] as Array<{ name: string; isDirectory(): boolean }>,
  );
  return names.filter((e) => e.isDirectory()).map((e) => e.name).sort();
}

export async function postMessage(
  ctx: SwarmContext,
  args: { thread?: string; to?: string; tag: string; body: string; via?: string; key?: string },
): Promise<PostRecord & { existing?: true }> {
  if (!isPostTag(args.tag)) {
    throw new Error(`Unknown tag "${args.tag}". Use: ${POST_TAGS.filter((t) => t !== "question").join(", ")}`);
  }
  if (args.tag === "question") {
    throw new Error('The "question" tag is the question register\'s: a person\'s question reaches the board through it. Open a question with question_open, or post with tag ask.');
  }
  const tag: PostTag = args.tag;
  const thread = normalizeThreadName(args.thread);
  const to = yamlOneLine(args.to ?? "all") || "all";
  const body = args.body.trim();
  if (!body) throw new Error("Post body is empty");

  // A key is the harness's alone (a system post): a structured id in the
  // front matter, where no body text can imitate it, by which a post already
  // made is found again and not made twice (an addition replayed after a
  // crash, a request's outcome published again).
  const key = ctx.agentId === "system" && args.key ? yamlOneLine(args.key) : "";
  if (key && !/^[A-Za-z0-9:._-]{1,200}$/.test(key)) throw new Error(`a system post's key is a structured id (got ${JSON.stringify(args.key)})`);
  return withTableLock(ctx.sandboxRoot, async () => {
    const dir = join(ctx.sandboxRoot, "threads", thread);
    await mkdir(dir, { recursive: true });
    if (key) {
      for (const n of (await readdir(dir).catch(() => [] as string[])).filter((x) => /^\d{6}-system\.md$/.test(x)).sort()) {
        const t = await readFile(join(dir, n), "utf8").catch(() => null);
        if (t === null) continue;
        const { attrs } = parseFrontMatter(t);
        if (attrs.key === key && attrs.from === "system") {
          const post = await readPost(join(dir, n)).catch(() => null);
          if (post) return { ...post, existing: true as const };
        }
      }
    }
    await ensureThreadMember(ctx.sandboxRoot, thread, ctx.agentId);
    const id = await nextPostId(ctx.sandboxRoot, thread);
    const filename = `${String(id).padStart(6, "0")}-${ctx.agentId}.md`;
    const path = join(dir, filename);
    const name = yamlOneLine((await nameOf(ctx.sandboxRoot, ctx.agentId).catch(() => undefined)) ?? "");
    const via = yamlOneLine(args.via ?? "");
    const text = `---
id: ${id}
thread: ${thread}
from: ${ctx.agentId}
to: ${to}
tag: ${tag}
${name ? `name: ${name}\n` : ""}${via ? `via: ${via}\n` : ""}${key ? `key: ${key}\n` : ""}---

${body}
`;
    // Readers scan this directory without the table lock, so the file has to
    // appear whole: write beside it and rename, which is atomic on POSIX.
    const staging = join(dir, `.${filename}.tmp`);
    await writeFile(staging, text, "utf8");
    await rename(staging, path);
    return {
      id,
      thread,
      from: ctx.agentId,
      to,
      tag,
      body,
      path,
      ...(name ? { name } : {}),
      ...(via ? { via } : {}),
    };
  });
}

/**
 * A post in a person's name from the question register (from:
 * analyst:<person>, tag question): never an agent's, so it joins no thread
 * and names no seat. With a key (a structured id such as
 * question:Q-4:r1), written in the post's front matter where no body text
 * can imitate it, a post already on the thread with that exact key is
 * returned instead of a second one, taken under the same lock a post id is,
 * so a delivery that runs again after a crash posts once.
 */
export async function registerPost(
  sandboxRoot: string,
  args: { from: string; to?: string; tag: string; body: string; thread?: string; key?: string },
): Promise<PostRecord & { existing?: true }> {
  if (!isPostTag(args.tag)) throw new Error(`Unknown tag "${args.tag}"`);
  const from = yamlOneLine(args.from);
  if (!/^(analyst|reviewer|observer):[A-Za-z0-9._@-]{1,160}$/.test(from)) throw new Error(`a register post is from analyst:, reviewer: or observer:<person> (got ${JSON.stringify(args.from)})`);
  const thread = normalizeThreadName(args.thread);
  const to = yamlOneLine(args.to ?? "all") || "all";
  const body = args.body.trim();
  if (!body) throw new Error("Post body is empty");
  const tag = args.tag as PostTag;
  return withTableLock(sandboxRoot, async () => {
    const dir = join(sandboxRoot, "threads", thread);
    await mkdir(dir, { recursive: true });
    const kind = from.slice(0, from.indexOf(":"));
    const key = args.key ? yamlOneLine(args.key) : "";
    if (key && !/^[A-Za-z0-9:._-]{1,200}$/.test(key)) throw new Error(`a register post's key is a structured id (got ${JSON.stringify(args.key)})`);
    if (key) {
      for (const name of (await readdir(dir).catch(() => [] as string[])).filter((n) => /^\d{6}-.+\.md$/.test(n) && n.includes(`-${kind}-`)).sort()) {
        const text = await readFile(join(dir, name), "utf8").catch(() => null);
        if (text === null) continue;
        const { attrs } = parseFrontMatter(text);
        if (attrs.key === key && attrs.from === from) {
          const post = await readPost(join(dir, name)).catch(() => null);
          if (post) return { ...post, existing: true as const };
        }
      }
    }
    const id = await nextPostId(sandboxRoot, thread);
    const filename = `${String(id).padStart(6, "0")}-${from.replace(/[^A-Za-z0-9_-]/g, "-")}.md`;
    const path = join(dir, filename);
    const text = `---
id: ${id}
thread: ${thread}
from: ${from}
to: ${to}
tag: ${tag}
${key ? `key: ${key}\n` : ""}---

${body}
`;
    const staging = join(dir, `.${filename}.tmp`);
    await writeFile(staging, text, "utf8");
    await rename(staging, path);
    return { id, thread, from, to, tag, body, path };
  });
}

/** Harness announcement on the board. Never joins a thread, never claims. */
export async function systemPost(
  sandboxRoot: string,
  args: { tag: string; body: string; thread?: string; to?: string; via?: string; key?: string },
): Promise<PostRecord & { existing?: true }> {
  return postMessage(systemContext(sandboxRoot), args);
}

function cursorsPath(sandboxRoot: string, agentId: string): string {
  return join(sandboxRoot, "inbox", agentId, CURSORS_REL);
}

/**
 * Per-thread read cursors. One number per thread, so reading `ops` can never
 * hide unread `main` posts (a single counter used to do exactly that).
 */
export async function readCursors(
  sandboxRoot: string,
  agentId: string,
): Promise<Record<string, number>> {
  const raw = await readFile(cursorsPath(sandboxRoot, agentId), "utf8").catch(() => "");
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      // Null prototype: a thread legitimately named `constructor` or
      // `__proto__` would otherwise read back an inherited member and make
      // every post in it look already seen.
      const out: Record<string, number> = Object.create(null);
      for (const [thread, value] of Object.entries(parsed)) {
        const n = Number(value);
        if (Number.isFinite(n)) out[thread] = n;
      }
      return out;
    } catch {
      // fall through to the legacy cursor
    }
  }
  // Legacy single-counter layout (`inbox/<id>/seen`).
  const legacy = await readFile(join(sandboxRoot, "inbox", agentId, "seen"), "utf8").catch(() => "");
  const seen = Number.parseInt(legacy.trim(), 10);
  const out: Record<string, number> = Object.create(null);
  if (Number.isFinite(seen) && seen > 0) out[PRIMARY_THREAD] = seen;
  return out;
}

async function writeCursors(
  sandboxRoot: string,
  agentId: string,
  cursors: Record<string, number>,
): Promise<void> {
  const file = cursorsPath(sandboxRoot, agentId);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(cursors, null, 2)}\n`, "utf8");
}

/** Threads this agent reads by default: the primary thread plus its memberships. */
export async function subscribedThreads(
  sandboxRoot: string,
  agentId: string,
): Promise<string[]> {
  const names = await listThreadNames(sandboxRoot);
  const out = new Set<string>([PRIMARY_THREAD]);
  for (const name of names) {
    const meta = await readThreadMeta(sandboxRoot, name);
    if (meta?.members.includes(agentId)) out.add(name);
  }
  return [...out].sort((a, b) => (a === PRIMARY_THREAD ? -1 : b === PRIMARY_THREAD ? 1 : a.localeCompare(b)));
}

/**
 * The most post text one `inbox` or `wait` delivery carries, in characters
 * of post bodies. Whole posts only: a post is never cut, a delivery that
 * would go past the bound stops before the post that breaks it, and what
 * stayed behind is still unread for the next call. On the Linux run s3096
 * two `wait` results carried 578 posts each, 240k characters, 64k tokens: a
 * quarter of the working context in one call, and the reason the wall was
 * ever in reach of a single result. 0 means no bound.
 */
export const INBOX_PAGE_CHARS_DEFAULT = 40_000;

/** The page bound the kickoff handed this pane (`SWARM_INBOX_PAGE_CHARS`), or the default. */
export function inboxPageChars(env: Record<string, string | undefined> = process.env): number {
  const raw = env.SWARM_INBOX_PAGE_CHARS?.trim();
  if (!raw) return INBOX_PAGE_CHARS_DEFAULT;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : INBOX_PAGE_CHARS_DEFAULT;
}

export async function readInbox(
  ctx: SwarmContext,
  args: { thread?: string; markSeen?: boolean; pageChars?: number } = {},
): Promise<{
  swarm_done: boolean;
  seen: number;
  cursors: Record<string, number>;
  threads: string[];
  posts: PostRecord[];
  /** Unread posts held back by the page bound; the next call delivers them. */
  remaining: number;
  /** The bound this delivery was cut to, 0 when unbounded. */
  page_chars: number;
}> {
  const markSeen = args.markSeen ?? true;
  const threads = args.thread
    ? [normalizeThreadName(args.thread)]
    : await subscribedThreads(ctx.sandboxRoot, ctx.agentId);
  const cursors = await readCursors(ctx.sandboxRoot, ctx.agentId);
  const unread: PostRecord[] = [];

  for (const thread of threads) {
    const seen = cursors[thread] ?? 0;
    for (const file of await listPostFiles(ctx.sandboxRoot, thread)) {
      // Already seen by its filename id: skip the read. A 000000 prefix falls
      // back to the front-matter id in readPost, so it is still read.
      const fileId = Number.parseInt(basename(file).slice(0, 6), 10);
      if (fileId > 0 && fileId <= seen) continue;
      const record = await readPost(file);
      if (record.id > seen) unread.push(record);
    }
  }
  unread.sort((a, b) => (a.thread === b.thread ? a.id - b.id : a.thread.localeCompare(b.thread)));

  // The page: whole posts, in order, until the next one would break the
  // bound. Within a thread the delivered posts are always a prefix of the
  // unread ones, so a cursor moved to the last delivered id leaves exactly
  // the held-back posts unread.
  const pageChars = args.pageChars ?? inboxPageChars();
  const posts: PostRecord[] = [];
  let chars = 0;
  for (const record of unread) {
    if (pageChars > 0 && posts.length > 0 && chars + record.body.length > pageChars) break;
    posts.push(record);
    chars += record.body.length;
  }
  for (const record of posts) cursors[record.thread] = Math.max(cursors[record.thread] ?? 0, record.id);
  const remaining = unread.length - posts.length;

  if (markSeen) {
    // Re-read under the mutex and keep the highest cursor per thread: two
    // overlapping reads by the same agent would otherwise clobber each
    // other's progress and redeliver posts.
    await withTableLock(ctx.sandboxRoot, async () => {
      const onDisk = await readCursors(ctx.sandboxRoot, ctx.agentId);
      const merged: Record<string, number> = Object.create(null);
      for (const [thread, value] of Object.entries(onDisk)) merged[thread] = value;
      for (const [thread, value] of Object.entries(cursors)) {
        merged[thread] = Math.max(merged[thread] ?? 0, value);
      }
      await writeCursors(ctx.sandboxRoot, ctx.agentId, merged);
    });
  }
  return {
    swarm_done: await swarmDoneExists(ctx.sandboxRoot),
    // Back-compat scalar: the primary thread's cursor.
    seen: cursors[PRIMARY_THREAD] ?? 0,
    cursors,
    threads,
    posts,
    remaining,
    page_chars: pageChars,
  };
}

/**
 * Event-log shape for `inbox` and `wait`: every delivered post's id and
 * sender, whole, and how many stayed unread. The list used to stop at
 * twenty, which left a 578-post delivery on the trace as twenty ids and a
 * count; the bodies are on disk under threads/, the ids say which ones
 * this agent was handed and when.
 */
export function inboxLogResult(box: {
  swarm_done: boolean;
  seen: number;
  posts: ReadonlyArray<{ id: number; from: string }>;
  remaining?: number;
}): {
  swarm_done: boolean;
  seen: number;
  n: number;
  from: string[];
  ids: number[];
  remaining: number;
} {
  return {
    swarm_done: box.swarm_done,
    seen: box.seen,
    n: box.posts.length,
    from: box.posts.map((p) => p.from),
    ids: box.posts.map((p) => p.id),
    remaining: box.remaining ?? 0,
  };
}

export async function listTeam(ctx: SwarmContext): Promise<TeamRecord> {
  return readTeam(ctx.sandboxRoot);
}

/** A peer's job still to finish, as the store's own record of it says. */
export type PeerJob = {
  id: string;
  kind: string;
  profile: string | null;
  command?: string;
  tool?: string;
  args?: Record<string, unknown>;
  recipe?: string;
  source?: string;
  state: string;
  since: string | null;
};

/** One peer, as the board, the store and the ledger have it. Never the trace. */
export type PeerView = {
  id: string;
  role: string;
  model?: string;
  name: string | null;
  doing: string | null;
  /** When it last said what it calls itself and what it is doing (names.json). */
  named_at: string | null;
  /** `done` or `dead` when its marker is there; null while it works. */
  marker: "done" | "dead" | null;
  /** Its latest post on any thread (the board's file, written when it was posted), and how many it has made. */
  last_post: { id: number; thread: string; tag: string; to: string; at: string } | null;
  posts: number;
  /** Jobs it asked for that are not over (accepted, running, finished, fenced), from store/jobs/<id>/job.json. */
  open_jobs: PeerJob[];
  /** How many ledger entries it recorded, and its last few: the whole of each is `ledger` by seq. */
  ledger: { total: number; last: Array<{ seq: number; kind: string; value_first_line: string; superseded_by?: number }> };
  /** The leads it holds (A1): what it works on shows from these, not from its name. */
  holds?: Array<{ id: string; title: string; status: string }>;
  /** Its visible label: its stable name, and the leads it holds. */
  label?: string;
};

export type TeamView = TeamRecord & {
  /** Every seat but the caller, in team order, from `from` on, as many whole peers as the page holds. */
  peers: PeerView[];
  /** Peers not in this page; call again with `from: next` for them. */
  remaining: number;
  next?: string;
  note?: string;
};

/** How many of a peer's latest ledger entries list_team shows. */
export const TEAM_VIEW_LEDGER_LAST = 3;
const OPEN_JOB_STATES = new Set(["accepted", "running", "finished", "fenced"]);

/**
 * What each peer is doing and what it found, for `list_team`, built from the
 * harness's own records: names.json and the board (who said what, when),
 * the store's job records (what it asked the workers to run), the ledger
 * (what it recorded). Never from the trace: in a microVM a seat does not see
 * it, and a seat that is to re-derive a peer's finding reads what the peer
 * recorded and sealed, not how it got there. The page is whole peers,
 * bounded like an inbox delivery (`pageChars`, 0 for no bound); nothing in a
 * peer is cut, except that a ledger entry is shown by its first line, the
 * whole of it one `ledger` call away by its seq.
 */
export async function teamView(ctx: SwarmContext, opts: { from?: string; pageChars?: number } = {}): Promise<TeamView> {
  const S = ctx.sandboxRoot;
  const team = await readTeam(S);
  const names = await readNames(S);
  // The board: each author's latest post and its count, by the file names
  // (`000123-<author>.md`), then that one post read for its thread and tag.
  // When it was posted is when the harness wrote its file: posts are never
  // rewritten.
  const latest = new Map<string, { file: string; at: Date; count: number }>();
  for (const thread of await listThreadNames(S)) {
    for (const file of await listPostFiles(S, thread)) {
      const m = /^\d{6}-(.+)\.md$/.exec(basename(file));
      if (!m) continue;
      const at = await stat(file).then((st) => st.mtime).catch(() => null);
      if (!at) continue;
      const was = latest.get(m[1]!);
      latest.set(m[1]!, !was || at >= was.at ? { file, at, count: (was?.count ?? 0) + 1 } : { ...was, count: was.count + 1 });
    }
  }
  // The store: every job's own record.
  const jobsByAgent = new Map<string, PeerJob[]>();
  const jobDirs = await readdir(join(S, "store", "jobs")).catch(() => [] as string[]);
  for (const dir of jobDirs.sort()) {
    const job = await readFile(join(S, "store", "jobs", dir, "job.json"), "utf8")
      .then((t) => JSON.parse(t) as { id?: string; spec?: Record<string, unknown>; requester?: { agent?: string }; state?: string; accepted_at?: string; started_at?: string })
      .catch(() => null);
    const who = job?.requester?.agent;
    if (!job || !who || !OPEN_JOB_STATES.has(String(job.state))) continue;
    const spec = job.spec ?? {};
    const view: PeerJob = {
      id: String(job.id ?? dir),
      kind: String(spec.kind ?? "?"),
      profile: typeof spec.profile === "string" ? spec.profile : null,
      ...(typeof spec.command === "string" ? { command: spec.command } : {}),
      ...(typeof spec.tool === "string" ? { tool: spec.tool } : {}),
      ...(spec.args && typeof spec.args === "object" ? { args: spec.args as Record<string, unknown> } : {}),
      ...(typeof spec.recipe === "string" ? { recipe: spec.recipe } : {}),
      ...(typeof spec.source === "string" ? { source: spec.source } : {}),
      state: String(job.state),
      since: job.started_at ?? job.accepted_at ?? null,
    };
    jobsByAgent.set(who, [...(jobsByAgent.get(who) ?? []), view]);
  }
  const ledger = await readLedger(S);
  const replaced = supersededBy(ledger);
  // What each seat works on, from the lead register (A1: the label follows the held lead, the name stays).
  const L = await import("./leads.ts");
  const leadSnap = await L.leadsSnapshot(S).catch(() => null);
  const peers: PeerView[] = [];
  for (const a of team.agents) {
    if (a.id === ctx.agentId) continue;
    const named = names.find((n) => n.id === a.id);
    const holds = leadSnap ? L.heldLeads(leadSnap, a.id) : [];
    const post = latest.get(a.id);
    const record = post ? await readPost(post.file).catch(() => null) : null;
    const theirs = ledger.filter((e) => e.by === a.id);
    const there = (path: string) => stat(path).then(() => true, () => false);
    const marker = (await there(agentDonePath(S, a.id))) ? "done" : (await there(agentDeadPath(S, a.id))) ? "dead" : null;
    peers.push({
      id: a.id,
      role: a.role,
      ...(a.model ? { model: a.model } : {}),
      name: named?.name ?? null,
      doing: named?.doing ?? null,
      named_at: named?.at ?? null,
      marker,
      last_post: post && record ? { id: record.id, thread: record.thread, tag: record.tag, to: record.to, at: post.at.toISOString() } : null,
      posts: post?.count ?? 0,
      open_jobs: jobsByAgent.get(a.id) ?? [],
      ...(leadSnap ? { holds, label: L.seatLabel(a.id, named?.name ?? null, holds) } : {}),
      ledger: {
        total: theirs.length,
        last: theirs.slice(-TEAM_VIEW_LEDGER_LAST).map((e) => ({
          seq: e.seq,
          kind: e.kind,
          value_first_line: String(e.value ?? "").split("\n")[0]!,
          ...(replaced.has(e.seq) ? { superseded_by: replaced.get(e.seq) } : {}),
        })),
      },
    });
  }
  // The page: whole peers from `from` on, until the next would break the bound.
  const start = opts.from ? Math.max(0, peers.findIndex((p) => p.id === opts.from)) : 0;
  const pageChars = opts.pageChars ?? inboxPageChars();
  const page: PeerView[] = [];
  let chars = 0;
  for (const peer of peers.slice(start)) {
    const size = JSON.stringify(peer).length;
    if (pageChars > 0 && page.length > 0 && chars + size > pageChars) break;
    page.push(peer);
    chars += size;
  }
  const rest = peers.slice(start + page.length);
  return {
    ...team,
    peers: page,
    remaining: rest.length,
    ...(rest.length ? { next: rest[0]!.id, note: `${rest.length} more peer(s) past this page's bound; call list_team with from: "${rest[0]!.id}" for them.` } : {}),
  };
}

export async function readBudgetStatus(ctx: SwarmContext): Promise<{
  budget: BudgetRecord;
  remaining_usd: number;
  remaining_minutes: number;
  over_budget: boolean;
  over_time: boolean;
  tokens: number;
  calls: number;
  /** False on a team of local models: spend is not measured, tokens are. */
  metered: boolean;
  /** Tokens left under `cap_tokens`, or null when there is no token cap. */
  remaining_tokens: number | null;
  /** Tokens left under this agent's own cap (`cap_per_agent_tokens`), or null when it has none. */
  remaining_tokens_mine: number | null;
  this_agent: AgentBudget;
}> {
  const budget = await readBudget(ctx.sandboxRoot);
  const elapsedMs = Date.now() - Date.parse(budget.started_at);
  const remainingMinutes = Math.max(
    0,
    budget.wall_clock_minutes - elapsedMs / 60_000,
  );
  const remainingUsd = Math.max(0, budget.cap_usd - budget.spent_usd);
  const capTokens = Number(budget.cap_tokens) || 0;
  return {
    budget,
    remaining_usd: Number(remainingUsd.toFixed(4)),
    remaining_minutes: Number(remainingMinutes.toFixed(2)),
    over_budget: overCap(budget).over,
    over_time: remainingMinutes <= 0,
    tokens: budget.tokens,
    calls: budget.calls,
    metered: budget.metered !== false,
    remaining_tokens: capTokens > 0 ? Math.max(0, capTokens - budget.tokens) : null,
    remaining_tokens_mine:
      Number(budget.cap_per_agent_tokens) > 0
        ? Math.max(0, Number(budget.cap_per_agent_tokens) - (budget.agents[ctx.agentId]?.tokens ?? 0))
        : null,
    this_agent: budget.agents[ctx.agentId] ?? emptyAgentBudget(),
  };
}

export type ClaimOptions = { reason?: string; seconds?: number; implicit?: boolean };

export function clampClaimSeconds(seconds: number | undefined): number {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_CLAIM_SECONDS;
  // A fractional request must not round down to zero and hand back a lease
  // that is already expired when the caller reads it.
  return Math.min(Math.max(1, Math.round(value)), MAX_CLAIM_SECONDS);
}

/**
 * Take (or renew) the lease on a path. Same owner re-claiming extends it;
 * another live owner is a conflict, which is normal traffic, not a violation.
 * Harness-owned paths are refused outright.
 */
export async function claimFile(
  ctx: SwarmContext,
  rawPath: string,
  options: ClaimOptions = {},
): Promise<ClaimResult> {
  const pathKey = await realPathKey(ctx.sandboxRoot, rawPath);
  if (await resolvesToInputs(ctx.sandboxRoot, rawPath)) {
    return {
      ok: false,
      protected: true,
      path: pathKey,
      note: `${pathKey} is a read-only input and cannot be claimed. Read it in place; copy it into work/ if you need a version you can change.`,
    };
  }
  if (await resolvesToProtected(ctx.sandboxRoot, rawPath)) {
    return {
      ok: false,
      protected: true,
      path: pathKey,
      note: `${pathKey} belongs to the harness and cannot be claimed. Use post/done/file_restore instead of writing it.`,
    };
  }
  const peer = await peerHoleOf(ctx, pathKey);
  if (peer) {
    return {
      ok: false,
      conflict: true,
      path: pathKey,
      owner: peer,
      reason: `${peer}'s own directory`,
      expires_at: "",
      note: `${pathKey} is in ${peer}'s own directory, and a peer's scratch is theirs to write. Ask ${peer} on the board, or copy the file into your own directory and work there.`,
    };
  }
  const reason = (options.reason ?? "").trim();
  if (!reason) {
    throw new Error("claim_file requires a reason: say what you are about to do with the path.");
  }
  const seconds = clampClaimSeconds(options.seconds);
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const file = lockPath(ctx.sandboxRoot, pathKey);
    const existing = await readLock(file);
    const now = Date.now();
    if (existing && lockLive(existing, now) && existing.owner !== ctx.agentId) {
      return {
        ok: false,
        conflict: true,
        path: pathKey,
        owner: existing.owner,
        reason: existing.reason ?? "",
        expires_at: existing.expires_at,
        note: `Held by ${existing.owner} ("${existing.reason ?? ""}") until ${existing.expires_at}. Post about it and do other work; do not overwrite.`,
      };
    }
    const refreshed = Boolean(existing && existing.owner === ctx.agentId && lockLive(existing, now));
    // A lease that ran out belongs to nobody, and on a long case that is how a
    // stalled agent's files come back: the ninth case ended with two seats
    // holding work/report.md and work/crypto.md having made no tool call for
    // half an hour, and nothing told their peers the files were free.
    const takenOverFrom =
      existing && existing.owner !== ctx.agentId && !lockLive(existing, now) ? existing.owner : undefined;
    const record: LockRecord = {
      path: pathKey,
      owner: ctx.agentId,
      reason,
      seconds,
      claimed_at: refreshed ? existing!.claimed_at : new Date(now).toISOString(),
      expires_at: new Date(now + seconds * 1000).toISOString(),
      ...(options.implicit ? { implicit: true as const } : {}),
    };
    await mkdir(join(ctx.sandboxRoot, "locks"), { recursive: true });
    await held.assertOwned();
    await writeFile(file, `${JSON.stringify(record, null, 2)}\n`, "utf8");
    return {
      ok: true,
      path: pathKey,
      owner: ctx.agentId,
      reason,
      seconds,
      expires_at: record.expires_at,
      refreshed,
      ...(takenOverFrom ? { taken_over_from: takenOverFrom } : {}),
      note: `${refreshed ? "Renewed" : "Claimed"} '${pathKey}' for ${seconds}s.${
        takenOverFrom ? ` ${takenOverFrom}'s claim on it had expired; the board has been told.` : ""
      } Make your edit, then release_file("${pathKey}"). Re-call claim_file to renew.`,
    };
  });
}

/** Every live claim, newest lease last. Expired leases are not listed. */
export async function listClaims(sandboxRoot: string): Promise<ClaimView[]> {
  const dir = join(sandboxRoot, "locks");
  const names = await readdir(dir).catch(() => []);
  const now = Date.now();
  const out: ClaimView[] = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const lock = await readLock(join(dir, name));
    if (!lock || !lockLive(lock, now)) continue;
    out.push({
      ...lock,
      reason: lock.reason ?? "",
      seconds: lock.seconds ?? DEFAULT_CLAIM_SECONDS,
      expires_in_seconds: Math.max(0, Math.round((Date.parse(lock.expires_at) - now) / 1000)),
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

export async function releaseFile(
  ctx: SwarmContext,
  rawPath: string,
): Promise<{ ok: boolean; path: string; released: boolean }> {
  const pathKey = await realPathKey(ctx.sandboxRoot, rawPath);
  return withTableLock(ctx.sandboxRoot, async () => {
    const file = lockPath(ctx.sandboxRoot, pathKey);
    const existing = await readLock(file);
    if (!existing) return { ok: true, path: pathKey, released: false };
    if (existing.owner !== ctx.agentId && lockLive(existing)) {
      return { ok: false, path: pathKey, released: false };
    }
    await rm(file, { force: true });
    return { ok: true, path: pathKey, released: true };
  });
}

export async function releaseAllOwned(ctx: SwarmContext): Promise<string[]> {
  return withTableLock(ctx.sandboxRoot, async () => {
    const dir = join(ctx.sandboxRoot, "locks");
    const names = await readdir(dir).catch(() => []);
    const dropped: string[] = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      const file = join(dir, name);
      const lock = await readLock(file);
      if (lock?.owner === ctx.agentId) {
        await rm(file, { force: true });
        dropped.push(lock.path);
      }
    }
    return dropped;
  });
}

export type AgentMarker = "done" | "dead" | "stalled" | "active";

/**
 * The event log, parsed, served from memory while the file's size and mtime
 * are what they were last time. The log is append-only, and every reader of
 * a swarm — the console's list, its detail view, the marker of each agent —
 * used to parse the whole file again per request. The array is shared:
 * callers read it and never change it.
 */
const eventLogCache = new Map<string, { size: number; mtimeMs: number; events: readonly SwarmEvent[] }>();
const EVENT_LOG_CACHE_MAX = 64;

/** Why each sandbox's trace could not be read at its last read; absent when it was read, or is not there. */
const eventLogProblems = new Map<string, string>();

/**
 * The event log and, when there is one but it could not be read, why: a
 * trace that is a link, a directory or a FIFO, or a read that failed, is
 * not "no trace". Read line by line, so a trace past the size one string
 * can hold (512 MB) is read too, not dropped whole.
 */
export async function readEventLogChecked(sandboxRoot: string): Promise<{ events: readonly SwarmEvent[]; unreadable: string | null }> {
  const file = join(sandboxRoot, EVENTS_REL);
  const fail = (why: string) => {
    eventLogCache.delete(file);
    eventLogProblems.set(file, why);
    return { events: [] as readonly SwarmEvent[], unreadable: why };
  };
  const info = await lstat(file).catch((err: NodeJS.ErrnoException) => (err.code === "ENOENT" || err.code === "ENOTDIR" ? null : err));
  if (info === null) {
    eventLogCache.delete(file);
    eventLogProblems.delete(file);
    return { events: [], unreadable: null };
  }
  if (info instanceof Error) return fail(`unreadable (${(info as NodeJS.ErrnoException).code ?? info.message})`);
  if (info.isSymbolicLink()) return fail("a link, not the trace");
  if (!info.isFile()) return fail("not a regular file");
  const hit = eventLogCache.get(file);
  if (hit && hit.size === info.size && hit.mtimeMs === info.mtimeMs) {
    eventLogProblems.delete(file);
    return { events: hit.events, unreadable: null };
  }
  const events: SwarmEvent[] = [];
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  try {
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const lines = createInterface({ input: handle.createReadStream({ autoClose: false, encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of lines) {
      if (!line.trim()) continue;
      try {
        events.push(JSON.parse(line) as SwarmEvent);
      } catch {
        // a torn line is skipped, not fatal
      }
    }
  } catch (err) {
    return fail(`unreadable (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})`);
  } finally {
    await handle?.close().catch(() => undefined);
  }
  if (eventLogCache.size >= EVENT_LOG_CACHE_MAX) eventLogCache.clear();
  eventLogCache.set(file, { size: info.size, mtimeMs: info.mtimeMs, events });
  eventLogProblems.delete(file);
  return { events, unreadable: null };
}

/**
 * The event log, parsed, for readers that want the lines only. A trace
 * that is there and could not be read gives no lines here; `eventLogProblem`
 * (or readEventLogChecked) says why, so a caller can say it too rather than
 * report a run with no trace.
 */
export async function readEventLog(sandboxRoot: string): Promise<readonly SwarmEvent[]> {
  return (await readEventLogChecked(sandboxRoot)).events;
}

/** Why the sandbox's trace could not be read at its last read, or null. */
export function eventLogProblem(sandboxRoot: string): string | null {
  return eventLogProblems.get(join(sandboxRoot, EVENTS_REL)) ?? null;
}

export async function lastAgentActivityMs(
  sandboxRoot: string,
  agentId: string,
): Promise<number | null> {
  let last: number | null = null;
  for (const ev of await readEventLog(sandboxRoot)) {
    if (ev.agent !== agentId || !ev.ts) continue;
    const t = Date.parse(ev.ts);
    if (!Number.isNaN(t)) last = t;
  }
  return last;
}

export async function readAgentMarker(
  sandboxRoot: string,
  agentId: string,
  options: { now?: number; stallMs?: number } = {},
): Promise<AgentMarker> {
  try {
    await stat(agentDonePath(sandboxRoot, agentId));
    return "done";
  } catch {
    // continue
  }
  try {
    await stat(agentDeadPath(sandboxRoot, agentId));
    return "dead";
  } catch {
    // continue
  }
  const now = options.now ?? Date.now();
  const stallMs = options.stallMs ?? DEFAULT_STALL_MS;
  const last = await lastAgentActivityMs(sandboxRoot, agentId);
  if (last === null || now - last >= stallMs) return "stalled";
  return "active";
}

export type ReapResult = {
  agent: string;
  dead_file: string;
  released: string[];
};

/**
 * Harness reaping for "?" agents: they did work then fell asleep.
 * Writes done/agents/<id>.dead, drops their locks, logs `reaped`.
 * Does not write SWARM_DONE. The timeout is the caller's choice.
 */
export async function reapStalledAgents(
  sandboxRoot: string,
  options: { now?: number; stallMs?: number } = {},
): Promise<ReapResult[]> {
  const team = await listTeam({ sandboxRoot, agentId: "reaper" });
  const out: ReapResult[] = [];
  for (const member of team.agents) {
    const marker = await readAgentMarker(sandboxRoot, member.id, options);
    if (marker !== "stalled") continue;
    const ctx = createContext(sandboxRoot, member.id);
    const released = await releaseAllOwned(ctx);
    const deadFile = agentDeadPath(sandboxRoot, member.id);
    await mkdir(dirname(deadFile), { recursive: true });
    const stamp = new Date(options.now ?? Date.now()).toISOString();
    await writeFile(
      deadFile,
      `---
by: harness
reason: stalled
agent: ${member.id}
at: ${stamp}
---

Worker ${member.id} stopped running. Reaped by the harness, not done.
`,
      "utf8",
    );
    await appendEvent(sandboxRoot, {
      agent: member.id,
      tool: "reaped",
      args: { stall_ms: options.stallMs ?? DEFAULT_STALL_MS },
      result: { ok: true, released, dead_file: deadFile },
    });
    out.push({ agent: member.id, dead_file: deadFile, released });
  }
  return out;
}

export async function heldBy(ctx: SwarmContext, rawPath: string): Promise<LockRecord | null> {
  const pathKey = await realPathKey(ctx.sandboxRoot, rawPath);
  const lock = await readLock(lockPath(ctx.sandboxRoot, pathKey));
  if (!lock || !lockLive(lock)) return null;
  return lock;
}

/** work/<agent id>/… — the writer's own scratch directory. */
/**
 * Somewhere only this agent writes: its scratch directory, and its own corner
 * of the extraction root. Several agents pulling the same hives into one
 * `work/extracted/` is what produced the real claim conflicts in the later
 * forensic cases — four in forty seconds on one run — so each has a corner of
 * its own, and the shared root is for what peers must read.
 */
/**
 * The peer whose own directory `pathKey` is in, when that is not the
 * caller's: a claim there, and so a write, a restore or a publish there, is
 * refused — a lease a peer took would also lock the owner out of its own
 * directory, whose writes need no claim. Someone outside the team (the
 * operator restoring a revision from the console, the harness) is not a
 * peer and is not refused, and a team that cannot be read refuses nothing.
 */
async function peerHoleOf(ctx: SwarmContext, pathKey: string): Promise<string | null> {
  if (ctx.agentId === SYSTEM_AGENT) return null;
  const ids = await teamIds(ctx.sandboxRoot);
  if (!ids.some((id) => id.toLowerCase() === ctx.agentId.toLowerCase())) return null;
  const owner = seatHoleOwner(pathKey, ids);
  return owner && owner.toLowerCase() !== ctx.agentId.toLowerCase() ? owner : null;
}

export function isOwnScratch(pathKey: string, agentId: string): boolean {
  if (!agentId || agentId === SYSTEM_AGENT) return false;
  return (
    pathKey.startsWith(`work/${agentId}/`) ||
    pathKey.startsWith(`work/extracted/${agentId}/`) ||
    pathKey.startsWith(`work/quarantine/${agentId}/`)
  );
}

export async function guardWrite(ctx: SwarmContext, rawPath: string): Promise<GuardResult> {
  let pathKey: string;
  try {
    pathKey = await realPathKey(ctx.sandboxRoot, rawPath);
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
  if (await resolvesToInputs(ctx.sandboxRoot, pathKey)) {
    return {
      ok: false,
      reason: `read-only input: ${pathKey}. Inputs are never written or deleted; copy the file into work/ if you need a version you can change.`,
      path: pathKey,
      protected: true,
      inputs: true,
    };
  }
  if (await resolvesToProtected(ctx.sandboxRoot, pathKey)) {
    return {
      ok: false,
      reason: `harness-owned path: ${pathKey}. Use post/done/file_restore; do not write it directly.`,
      path: pathKey,
      protected: true,
    };
  }
  const peer = await peerHoleOf(ctx, pathKey);
  if (peer) {
    return { ok: false, reason: `claim violation: ${pathKey} is in ${peer}'s own directory; a peer's scratch is theirs to write`, path: pathKey, owner: peer };
  }
  const lock = await heldBy(ctx, pathKey);
  if (!lock) {
    // An agent's own scratch directory, work/<id>/, is its own: the guard
    // takes the lease for it rather than refusing, so the prompt's "no claim
    // needed there" is true for edit/write as it is for a shell write.
    if (isOwnScratch(pathKey, ctx.agentId)) {
      const taken = await claimFile(ctx, pathKey, { reason: "own scratch", implicit: true });
      if (taken.ok) return { ok: true, path: pathKey, refreshed: false };
    }
    return {
      ok: false,
      reason: `claim violation: ${pathKey} (no lock)`,
      path: pathKey,
    };
  }
  if (lock.owner !== ctx.agentId) {
    return {
      ok: false,
      reason: `claim violation: ${pathKey}`,
      path: pathKey,
      owner: lock.owner,
    };
  }
  // A legal write renews the lease on the owner's own terms. The renewal can
  // still fail: between the check above and here the lease may have expired
  // and been taken by someone else, and writing then would stomp their work.
  const refreshed = await claimFile(ctx, pathKey, {
    reason: lock.reason || "write in progress",
    seconds: lock.seconds,
  });
  if (!refreshed.ok) {
    // The path can also have become harness-owned since the check above — a
    // symlink now resolving into a protected prefix. Saying "lease expired"
    // there would send the agent off to re-claim something unclaimable.
    if ("protected" in refreshed) {
      return {
        ok: false,
        reason: `harness-owned path: ${pathKey}. Use post/done/file_restore; do not write it directly.`,
        path: pathKey,
        protected: true,
      };
    }
    return {
      ok: false,
      reason: `claim violation: ${pathKey} (lease expired mid-write)`,
      path: pathKey,
      owner: "conflict" in refreshed ? refreshed.owner : undefined,
    };
  }
  return { ok: true, path: pathKey, refreshed: refreshed.refreshed };
}

/**
 * Official Pi built-in `read`/`edit` docs use `path`. `write` follows the same
 * field in current docs. Extra keys are SPECULATIVE fallbacks if a schema
 * rename lands — confirm with `pi.getAllTools()` on the live binary.
 */
export function extractWritePath(input: Record<string, unknown> | undefined): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  for (const key of ["path", "filePath", "file_path", "file"]) {
    const value = input[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return undefined;
}

export async function markDone(
  ctx: SwarmContext,
  args: { reason: string; outputFile: string; createSentinel?: boolean; outcome?: FinishOutcome; revision?: string; finish?: { holder: string; generation: number } },
): Promise<DoneResult | DoneRefused> {
  const reason = yamlOneLine(args.reason);
  const outputFile = yamlOneLine(args.outputFile);
  if (!reason) throw new Error("done requires a reason");
  if (!outputFile) throw new Error("done requires output_file");
  // The report reads the output file back: it names a file in the run.
  claimKey(ctx.sandboxRoot, outputFile);

  // A per-agent cap stop is one seat leaving. The swarm's clock is
  // done/SWARM_DONE; writing it here would shut every other pane.
  const seatOnly = args.createSentinel === false || reason === "agent_cap";
  // An until-solved run takes no abandon, a vote or not: only the operator
  // ends it (swarm.sh stop), or every question disposed under the bar.
  if (!seatOnly && reason.startsWith(ABANDON_PREFIX) && (await readBudget(ctx.sandboxRoot).catch(() => null))?.until_solved === true) {
    throw new Error(UNTIL_SOLVED_NO_ABANDON);
  }
  if (!seatOnly && reason.startsWith(ABANDON_PREFIX) && !(await swarmDoneExists(ctx.sandboxRoot))) {
    const gate = await abandonGate(ctx.sandboxRoot, ctx.agentId, reason);
    if (!gate.proceed) {
      const others = gate.working.length;
      return {
        terminate: false,
        refused:
          `An abandon ends the run for everyone, so one agent's word is not enough while ${others} other agent${others === 1 ? " is" : "s are"} still working (${gate.working.join(", ")}). ` +
          `Your abandon is recorded (done/abandon/${ctx.agentId}.md) and the board is asked: the run ends when a second agent also calls done with abandon: true, or when no other agent is still working. ` +
          `If only your own slice failed, post what you tried and what blocked it to the board, then take another open question or wait.`,
        abandon: gate,
        created_sentinel: false,
        reason,
        output_file: outputFile,
      };
    }
  }

  // The finish is one seat's (A4, extensions/finish.ts): a done that would
  // end the swarm is checked against the coordinator's lease (the holder and
  // generation its done began with, `finish`) and what is late against the
  // report, in the same transaction that writes this seat's marker and the
  // sentinel (finishTransaction), never only before.
  const ending = !seatOnly && !reason.startsWith(ABANDON_PREFIX) && !(await swarmDoneExists(ctx.sandboxRoot));

  const by = ctx.agentId;
  const stamp = new Date().toISOString();
  const agentFile = agentDonePath(ctx.sandboxRoot, ctx.agentId);
  const sentinel = sentinelPath(ctx.sandboxRoot);

  // How the run ended, when the finish line said (FinishOutcome): an
  // abandon is abandoned whatever the caller passed.
  const outcome: FinishOutcome | undefined = reason.startsWith(ABANDON_PREFIX) ? "abandoned" : args.outcome && (FINISH_OUTCOMES as readonly string[]).includes(args.outcome) ? args.outcome : undefined;
  const outcomeLine = outcome && !seatOnly ? `outcome: ${outcome}\n` : "";
  const agentBody = `---
by: ${by}
output: ${outputFile}
reason: ${reason}
${outcomeLine}at: ${stamp}
---

Worker ${by} is exiting.
`;
  const sentinelText = `---
by: ${by}
output: ${outputFile}
reason: ${reason}
${outcomeLine}at: ${stamp}
---

Collective finished. Presence of this file is the clock. Call done and stop.
`;
  // The sentinel is written under the registers' lock, against the state the
  // finish line was judged on (`revision`, when the caller ran it): a question
  // admitted or a lead opened after that line either moved the state, and the
  // done is refused to be run again, or finds the sentinel and is recorded as
  // a follow-up. Admission and a terminal done are never interleaved.
  const writeDone = async (): Promise<boolean> => {
    await mkdir(dirname(agentFile), { recursive: true });
    await writeFile(agentFile, agentBody, "utf8");
    if (seatOnly) return false;
    if (!args.revision) return createSentinel(ctx.sandboxRoot, sentinelText);
    return withNamedLock(ctx.sandboxRoot, REGISTER_LOCK, async () => {
      if (!(await swarmDoneExists(ctx.sandboxRoot)) && (await stateRevision(ctx.sandboxRoot).catch(() => ({ revision: "" }))).revision !== args.revision) {
        await rm(agentFile, { force: true }).catch(() => undefined);
        throw new Error(FINISH_LINE_UNSETTLED);
      }
      return createSentinel(ctx.sandboxRoot, sentinelText);
    });
  };
  const created = ending ? await (await import("./finish.ts")).finishTransaction(ctx.sandboxRoot, ctx.agentId, args.finish, writeDone) : await writeDone();

  await releaseAllOwned(ctx);

  return {
    terminate: true,
    agent_done: agentFile,
    sentinel,
    created_sentinel: created,
    reason,
    output_file: outputFile,
    ...(outcome && !seatOnly ? { outcome } : {}),
  };
}

/** The reason prefix of a done that gives the run up without its checks. */
export const ABANDON_PREFIX = "ABANDONED: ";

export function abandonVotePath(sandboxRoot: string, agentId: string): string {
  return join(sandboxRoot, "done", "abandon", `${agentId}.md`);
}

/**
 * An abandon ends the run for everyone and skips the finish line, so one
 * agent's word is not enough while others are still working: run sfeeebb
 * lost a ten-agent case after six minutes to one seat whose own slice had
 * not come together. The caller's vote is recorded under done/abandon/; the
 * run may end when a second agent has voted too, or when no other agent is
 * still working (every peer has a .done or a .dead marker, as reap and
 * await-done read them). No team file, no peers.
 */
export async function abandonGate(sandboxRoot: string, agentId: string, reason: string): Promise<AbandonGate> {
  const mine = abandonVotePath(sandboxRoot, agentId);
  await mkdir(dirname(mine), { recursive: true });
  const first = !(await stat(mine).then(() => true).catch(() => false));
  await writeFile(mine, `---\nby: ${agentId}\nreason: ${yamlOneLine(reason)}\nat: ${new Date().toISOString()}\n---\n`, "utf8");
  const votes = (await readdir(dirname(mine)).catch(() => [] as string[]))
    .filter((n) => n.endsWith(".md"))
    .map((n) => n.slice(0, -3))
    .sort();
  const team = await readTeam(sandboxRoot).catch(() => null);
  const working: string[] = [];
  for (const member of team?.agents ?? []) {
    if (member.id === agentId || votes.includes(member.id)) continue;
    const marked = await Promise.all(
      [agentDonePath(sandboxRoot, member.id), agentDeadPath(sandboxRoot, member.id)].map((p) => stat(p).then(() => true).catch(() => false)),
    );
    if (!marked.some(Boolean)) working.push(member.id);
  }
  return { proceed: votes.length >= 2 || working.length === 0, votes, working, first_vote: first };
}

export function toolText(payload: unknown): string {
  return `${JSON.stringify(payload, null, 2)}\n`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asUsage(value: unknown): {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  cost: number;
} | null {
  if (!isRecord(value)) return null;
  const cost = isRecord(value.cost) ? Number(value.cost.total) || 0 : 0;
  return {
    input: Number(value.input) || 0,
    output: Number(value.output) || 0,
    cacheRead: Number(value.cacheRead) || 0,
    cacheWrite: Number(value.cacheWrite) || 0,
    cost,
  };
}

/**
 * Sum official Pi session Usage the same way the footer / get_session_stats do.
 * Source: pi-coding-agent `usage-totals.js` (`addUsageToTotals`) and
 * docs/session-format.md `Usage` (`cost.total`, input/output/cache*).
 * tokens = input + output + cacheRead + cacheWrite.
 * calls = assistant messages that carried Usage (provider LLM rounds).
 */
export function usageFromSessionEntries(entries: unknown[]): SessionUsageSlice {
  const slice = emptyAgentBudget();
  if (!Array.isArray(entries)) return slice;
  for (const entry of entries) {
    if (!isRecord(entry)) continue;
    let usage: ReturnType<typeof asUsage> = null;
    if (entry.type === "message" && isRecord(entry.message)) {
      if (entry.message.role === "assistant") {
        usage = asUsage(entry.message.usage);
        if (usage) slice.calls += 1;
      } else if (entry.message.role === "toolResult") {
        usage = asUsage(entry.message.usage);
      }
    } else if (entry.type === "compaction" || entry.type === "branch_summary") {
      usage = asUsage(entry.usage);
      if (entry.type === "compaction") {
        // A compaction is a cost of its own: the summary call re-reads the
        // context it replaces. Counted apart, so the report can say what the
        // hand-offs cost next to what they saved.
        slice.compactions = (slice.compactions ?? 0) + 1;
        if (usage) {
          slice.compaction_tokens = (slice.compaction_tokens ?? 0) + usage.input + usage.output + usage.cacheRead + usage.cacheWrite;
          slice.compaction_usd = Number(((slice.compaction_usd ?? 0) + usage.cost).toFixed(6));
        }
      }
    }
    if (!usage) continue;
    slice.input += usage.input;
    slice.output += usage.output;
    slice.cache_read += usage.cacheRead;
    slice.cache_write += usage.cacheWrite;
    slice.spent_usd += usage.cost;
  }
  slice.tokens = slice.input + slice.output + slice.cache_read + slice.cache_write;
  slice.spent_usd = Number(slice.spent_usd.toFixed(6));
  return slice;
}

/**
 * The key under which an *archived* trace line says an argument was clipped.
 *
 * Nothing writes it any more. It was 80 characters, then 2,000, then 20,000
 * as a "safety valve": each limit was defended as one nothing real would
 * reach, and each one cut something real (910 of 2,343 arguments on
 * BelkaCTF #6 at 80; a `bash` line lost the half that said which evidence
 * it read). The rule now is the one a forensic record needs: the trace keeps
 * everything, whole. The key stays exported so the console can still say
 * "the harness kept an opening" about runs recorded under the old limits.
 */
export const ARG_TRUNCATED_KEY = "_truncated";

/**
 * What the trace keeps of a tool call's arguments: everything.
 *
 * Scalars as they are, structures as structures, strings whole whatever
 * their length. Only `null`/`undefined` are left out (they carry nothing),
 * and a value that cannot be serialised is skipped rather than guessed at.
 * The size of a line is the collector's and the console's problem, not the
 * record's: an audit trail that shortens what it audits is not an audit
 * trail, and the context-growth analysis this feature rests on was
 * impossible against a trace that kept 2,000 characters of each result.
 */
export function summarizeArgs(args: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!args) return out;
  for (const [key, value] of Object.entries(args)) {
    if (value == null || key === ARG_TRUNCATED_KEY) continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    } else {
      try {
        if (JSON.stringify(value) === undefined) continue;
      } catch {
        continue;
      }
      out[key] = value;
    }
  }
  return out;
}

export type ChainCheck = {
  /** Every line's `prev` matches the hash of the line before it. */
  ok: boolean;
  /** Lines carrying a `prev` field at all. */
  chained: number;
  total: number;
  /** 1-based line number of the first break, when there is one. */
  broken_at?: number;
  /** What went wrong, for a reader who has to act on it. */
  reason?: "edited" | "appended" | "shortened" | "head";
  /** Lines the collector could not attribute to a token it had handed out. */
  unverified: number;
  /** Lines whose sender claimed to be another agent. */
  disputed: number;
};

/**
 * The head of the chain as the collector last recorded it, outside the
 * sandbox.
 *
 * The collector writes this *before* it appends, so the anchor is never
 * behind the file: `head` names the line about to exist and `prev_head` the
 * one before it. A reader that catches the window between the two sees a file
 * one line shorter than the anchor, which `prev_head` tells it is fine —
 * without that, the same window is indistinguishable from a line appended by
 * something that is not the collector, and that is the case the anchor exists
 * to catch.
 */
export type ChainAnchor = { lines: number; head: string; prev_head?: string; pending?: boolean };

/**
 * Walk the trace's hash chain.
 *
 * A line the collector wrote carries `prev`: the sha256 of the line before
 * it. Appending a fabricated line is undetectable in a file whose only
 * property is that it grows; it is not undetectable in a file where every
 * line names its parent. A run with no collector has no chain, and this
 * reports that rather than calling it a failure.
 */
export function verifyEventChain(text: string, anchor?: ChainAnchor | null): ChainCheck {
  const verifier = eventChainVerifier(anchor);
  for (const line of text.split("\n")) verifier.push(line);
  return verifier.finish();
}

/**
 * The same check, a line at a time: custody reads a trace of any size
 * without holding it whole (a string past about 512 MB is not one Node can
 * make). Empty lines are skipped, as a split and filter would.
 */
export function eventChainVerifier(anchor?: ChainAnchor | null): { push(line: string): void; finish(): ChainCheck } {
  let previous = "";
  let chained = 0;
  let unverified = 0;
  let disputed = 0;
  let started = false;
  let total = 0;
  let failed: { broken_at: number; reason: ChainCheck["reason"] } | null = null;
  const fail = (broken_at: number, reason: ChainCheck["reason"]) => {
    failed = { broken_at, reason };
  };
  return {
    push(line: string) {
      if (line === "") return;
      total += 1;
      if (failed) return;
      let record: { prev?: unknown; agent_unverified?: unknown; claimed_agent?: unknown };
      try {
        record = JSON.parse(line) as typeof record;
      } catch {
        fail(total, "edited");
        return;
      }
      if (record.agent_unverified === true) unverified += 1;
      if (typeof record.claimed_agent === "string") disputed += 1;
      const prev = typeof record.prev === "string" ? record.prev : null;
      if (prev === null) {
        // Once the collector has written a line, every later line came through
        // it too — the shell helpers send over the socket like everything else.
        // An unchained line after that point is something else's append, which
        // is exactly the case a growing file cannot notice on its own.
        if (started) {
          fail(total, "appended");
          return;
        }
      } else {
        chained += 1;
        started = true;
        if (prev !== previous) {
          fail(total, "edited");
          return;
        }
      }
      previous = createHash("sha256").update(line).digest("hex");
    },
    finish(): ChainCheck {
      if (failed) return { ok: false, chained, total, broken_at: (failed as { broken_at: number }).broken_at, reason: (failed as { reason: ChainCheck["reason"] }).reason, unverified, disputed };
      // A file rewritten from the start carries a chain that verifies against
      // itself. The anchor is what it cannot reproduce: it lives outside the
      // sandbox, where the write guard keeps a pane from reaching it.
      //
      // This used to check two cases and let the rest through, which left the
      // headline open: a line appended with a correctly computed `prev` — and the
      // hash it needs is the previous line, which any pane can read — still came
      // back `ok`. So did a whole rewrite padded out to more lines than the
      // anchor names. And because it only ran `if (chained)`, stripping every
      // `prev` in the file skipped the anchor entirely and reported the result as
      // an unchained run, which reads as "this run had no collector".
      //
      // The anchor is a commitment to a length *and* an end. Every relation
      // between the file and it is decided here, including the ones that mean the
      // file is fine.
      if (anchor) {
        if (!chained && anchor.lines > 0) {
          // Every `prev` gone, but the collector recorded a chain. Whatever this
          // file is, it is not the record that was written.
          return { ok: false, chained, total, broken_at: 1, reason: "head", unverified, disputed };
        }
        if (total > anchor.lines) {
          return { ok: false, chained, total, broken_at: anchor.lines + 1, reason: "appended", unverified, disputed };
        }
        if (total === anchor.lines) {
          if (previous !== anchor.head) {
            return { ok: false, chained, total, broken_at: total, reason: "head", unverified, disputed };
          }
        } else if (anchor.pending === true && total === anchor.lines - 1 && typeof anchor.prev_head === "string") {
          // The collector brackets its append with two anchor writes, and this is
          // the moment between them: the line is promised but not yet on disk.
          // Only then may the file be one line short, and only if it ends exactly
          // where the anchor says it did before. A committed anchor one line
          // ahead of the file is the record's last line removed.
          if (previous !== anchor.prev_head) {
            return { ok: false, chained, total, broken_at: total, reason: "head", unverified, disputed };
          }
        } else {
          return { ok: false, chained, total, broken_at: total, reason: "shortened", unverified, disputed };
        }
      }
      return { ok: true, chained, total, unverified, disputed };
    },
  };
}

/**
 * Where the collector listens, relative to the sandbox.
 *
 * Inside `traces/`, not beside it. A socket in the sandbox root sits in a
 * directory the panes can write, so an agent could unlink it — and then
 * either bind its own and become the trace's writer, or simply leave every
 * later event with nowhere to go. Under `traces/` the write guard denies the
 * directory, so the socket cannot be removed or replaced; connecting to it
 * needs only `network-outbound`, which the profile allows.
 */
export const COLLECTOR_SOCKET_REL = "traces/.collector.sock";

/**
 * Hand one line to the collector, or say it could not.
 *
 * Returns false whenever there is no collector — no socket set, nothing
 * listening, a write that failed — so the caller falls back to appending the
 * line itself. A run without a collector is the old behaviour, not a run
 * that silently loses its trace.
 */
/**
 * The same socket, named so the kernel will take it.
 *
 * `/var/folders/...` and `/private/var/folders/...` are the same directory
 * through a symlink, so a relative path computed from the unresolved cwd can
 * come out as `../../../private/var/...` — longer than what it replaced. Both
 * ends are resolved first, and the result is used only if it is actually
 * shorter.
 */
function shortSocketPath(configured: string): string {
  try {
    const here = realpathSync(process.cwd());
    const there = realpathSync(dirname(configured));
    const candidate = join(relative(here, there), basename(configured));
    if (candidate && candidate.length < configured.length) return candidate;
  } catch {
    // the socket's directory may not exist yet; the absolute path is the answer
  }
  return configured;
}

let collectorFailures = 0;
let collectorGaveUpAt = 0;
/** Which socket those failures were against: a different one is a fresh start. */
let collectorFailuresFor = "";

/**
 * A request or an answer larger than this travels between a VM and the hub
 * in parts of this size, each acknowledged before the next goes. One
 * multi-megabyte line stalled msb's vsock path from guest to host in two
 * real runs (a seat's file recorded after an extraction: 6.6 MB and 10.6 MB
 * left queued in the guest), and every later call on that connection waited
 * behind it until the seat was stopped as cut off from the hub. Measured
 * since with the guest's own board client: one write of about 215 KB passes,
 * one of about 262 KB stalls the link for good, whatever went before (1.77 MB
 * in small lines passed). A part is 32 KiB, about 44 KB of base64 on the
 * wire. SWARM_TRANSFER_PART_BYTES changes it for an experiment, and belongs
 * on both ends alike: the hub refuses a part larger than its own.
 */
export const TRANSFER_PART_BYTES = Math.max(4096, Number(process.env.SWARM_TRANSFER_PART_BYTES) || 32 * 1024);
/**
 * The largest line either end writes on a VM's hub link: a part in base64
 * and its envelope. Anything larger goes in parts or not at all; a line past
 * it is refused by name (WireLineTooLarge), never written.
 */
export const WIRE_LINE_MAX = Math.ceil(TRANSFER_PART_BYTES / 3) * 4 + 1024;
/** A connection whose queued writes have not moved in this long carries nothing any more. */
export const WRITE_STALL_MS = 20_000;

/** A line for a VM's hub link past WIRE_LINE_MAX: it is not written. */
export class WireLineTooLarge extends Error {
  readonly bytes: number;
  constructor(bytes: number, what = "a line") {
    super(`${what} of ${bytes} bytes is past the ${WIRE_LINE_MAX}-byte line limit of a VM's hub link, and was not sent: one write that large stalls the link, so large things go in parts`);
    this.name = "WireLineTooLarge";
    this.bytes = bytes;
  }
}

/** `line` unchanged, or WireLineTooLarge: every write on a VM's hub link is checked here. */
export function wireChecked(line: string, what?: string): string {
  const bytes = Buffer.byteLength(line);
  if (bytes > WIRE_LINE_MAX) throw new WireLineTooLarge(bytes, what);
  return line;
}

/** `body` as one line for a VM's hub link, or WireLineTooLarge. */
export function wireLine(body: unknown, what?: string): string {
  return wireChecked(`${JSON.stringify(body)}\n`, what);
}

/**
 * Destroy `socket` when bytes wait to go out and none has left for
 * `stallMs`: a link that stopped carrying data is replaced, not waited on.
 * Progress is the queue emptying or shrinking (Node's buffer and libuv's);
 * `bytesWritten` is no measure, since it counts what is only queued.
 */
export function watchWriteStall(socket: Socket, stallMs = WRITE_STALL_MS): void {
  const queued = () => socket.writableLength + ((socket as unknown as { _handle?: { writeQueueSize?: number } })._handle?.writeQueueSize ?? 0);
  let last = queued();
  let since = Date.now();
  const timer = setInterval(() => {
    if (socket.destroyed) {
      clearInterval(timer);
      return;
    }
    const now = queued();
    if (now === 0 || now < last) {
      last = now;
      since = Date.now();
      return;
    }
    last = now;
    if (Date.now() - since >= stallMs) {
      clearInterval(timer);
      socket.destroy(new Error(`nothing written for ${Math.round(stallMs / 1000)}s`));
    }
  }, Math.max(20, Math.min(5_000, Math.floor(stallMs / 4))));
  timer.unref();
  socket.once("close", () => clearInterval(timer));
}

/** What names a transfer: the hub holds its bytes under `id` until they are whole, or fetched. */
export type TransferRef = { id: string; size: number; sha256: string };
/** The hub's answer to one part: an upload's acknowledgement, or a download's bytes. */
export type PartAnswer = { t?: string; id?: string; ok?: boolean; error?: string; got?: number; off?: number; b64?: string };

/**
 * The parts of every transfer on one connection to the hub, in turn: one
 * part in flight on the connection at a time, answered before the next goes
 * (several transfers take turns part by part), so however many wait, no
 * more than one part's line is ever queued on the link. A part not answered
 * in time closes the connection, which fails every transfer on it, and its
 * owner opens another. Its errors come from `error`, so each owner reports
 * them in its own terms; `lost` says the link went.
 */
export class TransferLane {
  private readonly waits = new Map<string, { resolve: (answer: PartAnswer) => void; reject: (err: Error) => void }>();
  private turn: Promise<unknown> = Promise.resolve();
  private uploading: Promise<unknown> = Promise.resolve();
  private readonly socket: Socket;
  private readonly timeoutMs: number;
  private readonly error: (message: string, lost: boolean) => Error;

  constructor(socket: Socket, timeoutMs: number, error: (message: string, lost: boolean) => Error = (message) => new Error(message)) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.error = error;
  }

  /** A line read from the connection: true when it was a part's answer, which is then settled. */
  take(message: PartAnswer | null | undefined): boolean {
    if (!message || (message.t !== "up" && message.t !== "down") || typeof message.id !== "string") return false;
    const key = `${message.t}:${message.id}`;
    const wait = this.waits.get(key);
    if (wait) {
      this.waits.delete(key);
      wait.resolve(message);
    }
    return true;
  }

  /** The connection closed: every part waiting on it fails. */
  fail(why: string): void {
    for (const [key, wait] of this.waits) {
      this.waits.delete(key);
      wait.reject(this.error(`${why} (${key})`, true));
    }
  }

  /**
   * `bytes` sent ahead in parts; the hub holds them under the name returned.
   * One upload at a time on a connection: the hub takes a few per seat at
   * once, and a burst of parallel publishes waits its turn rather than being
   * refused.
   */
  upload(bytes: Buffer): Promise<TransferRef> {
    const sent = this.uploading.then(async () => {
      const id = randomUUID();
      for (let off = 0; off < bytes.length; off += TRANSFER_PART_BYTES) {
        const answer = await this.ask({ t: "up", id, size: bytes.length, off, b64: bytes.subarray(off, off + TRANSFER_PART_BYTES).toString("base64") });
        if (!answer.ok) throw this.error(answer.error || "the hub refused a part", false);
      }
      return { id, size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    });
    this.uploading = sent.catch(() => undefined);
    return sent;
  }

  /**
   * What the hub kept under `ref`, fetched in parts and checked whole; only
   * then is the hub told it may drop it. A fetch that failed leaves it there
   * until the connection closes or it idles out.
   */
  async download(ref: TransferRef): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let got = 0;
    while (got < ref.size) {
      const answer = await this.ask({ t: "down", id: ref.id, off: got });
      if (answer.ok === false || typeof answer.b64 !== "string" || answer.off !== got) throw this.error(answer.error || "the hub sent a part out of turn", true);
      const bytes = Buffer.from(answer.b64, "base64");
      if (!bytes.length) throw this.error("the hub sent an empty part before the whole had come", true);
      chunks.push(bytes);
      got += bytes.length;
    }
    const whole = Buffer.concat(chunks);
    if (whole.length !== ref.size || createHash("sha256").update(whole).digest("hex") !== ref.sha256) {
      throw this.error("what was fetched in parts does not match what the hub said it was", true);
    }
    try {
      this.socket.write(wireLine({ t: "down", id: ref.id, done: true }));
    } catch {
      // the hub drops what it kept on its own, when the connection closes or idles
    }
    return whole;
  }

  /** One part out, and its answer back, when the part before it (of any transfer) has had its answer. */
  private ask(message: { t: "up" | "down"; id: string } & Record<string, unknown>): Promise<PartAnswer> {
    const key = `${message.t}:${message.id}`;
    const asked = this.turn.then(
      () =>
        new Promise<PartAnswer>((resolve, reject) => {
          if (this.socket.destroyed) {
            reject(this.error("the hub link closed during a transfer", true));
            return;
          }
          const timer = setTimeout(() => {
            this.waits.delete(key);
            if (!this.socket.destroyed) this.socket.destroy(new Error("a transfer part not answered"));
            reject(this.error(`the hub did not answer a transfer part within ${Math.round(this.timeoutMs / 1000)}s; the link closed and a new one opens`, true));
          }, this.timeoutMs);
          this.waits.set(key, {
            resolve: (answer) => {
              clearTimeout(timer);
              resolve(answer);
            },
            reject: (err) => {
              clearTimeout(timer);
              reject(err);
            },
          });
          try {
            this.socket.write(wireLine(message, "a transfer part"));
          } catch (err) {
            this.waits.delete(key);
            clearTimeout(timer);
            reject(err as Error);
          }
        }),
    );
    this.turn = asked.catch(() => undefined);
    return asked;
  }
}

/**
 * In a microVM the trace goes to the hub on one held connection, line after
 * line, each answered in order. A connection per line is what a pane on the
 * host does; through a VM's vsock path, connections opened in a burst were
 * refused (measured on the board's calls, extensions/board.ts), and a refused
 * trace line lands in the spill instead of the chain. A line past a part (a
 * tool's whole output is kept in the trace) goes ahead in parts, and the hub
 * forwards it whole: nothing is cut, and no write on the link is large.
 */
type HeldTrace = { path: string; socket: Socket; waiting: Array<(ok: boolean) => void>; buffer: string; lane: TransferLane };
let heldTrace: HeldTrace | null = null;
let heldTraceOpening: Promise<HeldTrace> | null = null;

function openHeldTrace(socketPath: string): Promise<HeldTrace> {
  if (heldTrace && heldTrace.path === socketPath && !heldTrace.socket.destroyed) return Promise.resolve(heldTrace);
  if (heldTraceOpening) return heldTraceOpening;
  // Another socket than the held one's: that link is done with.
  heldTrace?.socket.destroy();
  heldTraceOpening = new Promise<HeldTrace>((resolve, reject) => {
    const socket = connect(socketPath);
    socket.once("error", reject);
    socket.once("connect", () => {
      const auth = seatAuthLine();
      if (auth) socket.write(auth);
      const ch: HeldTrace = { path: socketPath, socket, waiting: [], buffer: "", lane: new TransferLane(socket, COLLECTOR_TIMEOUT_MS * 5) };
      socket.setEncoding("utf8");
      socket.unref();
      // A link whose writes stopped moving is closed, and the next line
      // opens another: the lines waiting on it settle as not taken.
      watchWriteStall(socket);
      socket.on("data", (chunk: string) => {
        ch.buffer += chunk;
        let cut;
        while ((cut = ch.buffer.indexOf("\n")) >= 0) {
          const answer = ch.buffer.slice(0, cut);
          ch.buffer = ch.buffer.slice(cut + 1);
          let parsed: (PartAnswer & { ok?: unknown }) | null = null;
          try {
            parsed = JSON.parse(answer);
          } catch {
            parsed = null;
          }
          // A part's acknowledgement is the lane's; every other answer is
          // the next waiting line's, in order.
          if (ch.lane.take(parsed)) continue;
          ch.waiting.shift()?.(parsed?.ok === true);
        }
      });
      socket.on("close", () => {
        if (heldTrace === ch) heldTrace = null;
        ch.lane.fail("the trace link closed");
        for (const settle of ch.waiting.splice(0)) settle(false);
      });
      socket.on("error", () => undefined);
      heldTrace = ch;
      resolve(ch);
    });
  }).finally(() => {
    heldTraceOpening = null;
  });
  return heldTraceOpening;
}

async function sendHeldTrace(socketPath: string, line: string): Promise<boolean> {
  let ch: HeldTrace;
  try {
    ch = await openHeldTrace(socketPath);
  } catch {
    return false;
  }
  let wire = line;
  if (Buffer.byteLength(line) > TRANSFER_PART_BYTES) {
    try {
      const upload = await ch.lane.upload(Buffer.from(line.endsWith("\n") ? line.slice(0, -1) : line, "utf8"));
      wire = wireLine({ t: "trace", upload }, "a trace line");
    } catch {
      return false;
    }
  }
  try {
    wireChecked(wire, "a trace line");
  } catch {
    return false;
  }
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const settle = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => {
      ch.socket.destroy();
      settle(false);
    }, COLLECTOR_TIMEOUT_MS * 5);
    if (ch.socket.destroyed) {
      settle(false);
      return;
    }
    ch.waiting.push(settle);
    try {
      ch.socket.write(wire);
    } catch {
      ch.socket.destroy();
    }
  });
}

async function sendToCollector(sandboxRoot: string, line: string): Promise<boolean> {
  const configured = process.env.SWARM_TRACE_SOCKET || "";
  if (!configured) return false;
  if (process.env.SWARM_ISOLATION === "microvm") return sendHeldTrace(configured, line);
  if (configured !== collectorFailuresFor) {
    collectorFailuresFor = configured;
    collectorFailures = 0;
  }
  // Unix socket paths are limited to about 104 bytes. A sandbox under a long
  // home is past that, so a path the kernel would refuse is shortened by
  // making it relative to this process — the pane's cwd is the sandbox, which
  // turns 110 characters into `traces/.collector.sock`.
  const socketPath = configured.length > SOCKET_PATH_SAFE ? shortSocketPath(configured) : configured;
  // A collector that has stopped answering must not cost every later call its
  // timeout: at one line per tool call and a thousand calls a run, that is
  // half an hour of waiting for a process that is not there. But the give-up
  // has to expire, or three transient failures — a restart, a moment of load
  // — would send the rest of the run's record to the spill file for good.
  if (collectorFailures >= COLLECTOR_GIVE_UP_AFTER) {
    if (Date.now() - collectorGaveUpAt < COLLECTOR_RETRY_AFTER_MS) return false;
    collectorFailures = 0;
  }
  return new Promise<boolean>((resolvePromise) => {
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      collectorFailures = ok ? 0 : collectorFailures + 1;
      if (!ok && collectorFailures === COLLECTOR_GIVE_UP_AFTER) collectorGaveUpAt = Date.now();
      resolvePromise(ok);
    };
    try {
      const socket = connect(socketPath);
      let answer = "";
      socket.setTimeout(COLLECTOR_TIMEOUT_MS, () => {
        socket.destroy();
        finish(false);
      });
      socket.on("error", () => finish(false));
      // True means the collector *wrote* it. Resolving on the flush instead
      // meant a refused line — one past the size limit, say — looked like a
      // recorded one, so it never reached the spill file either. A tool call
      // with 51 arguments of 20,000 characters is over that limit, and an
      // agent that forges its own tools chooses the arguments.
      //
      // On the reply itself rather than on the close: the collector serves
      // more than one line per connection and has no reason to hang up, so
      // waiting for the socket to end is waiting for the timeout.
      socket.on("data", (chunk) => {
        answer += chunk.toString("utf8");
        const cut = answer.indexOf("\n");
        if (cut < 0) return;
        try {
          finish(JSON.parse(answer.slice(0, cut))?.ok === true);
        } catch {
          finish(false);
        }
        socket.destroy();
      });
      socket.on("close", () => finish(false));
      socket.on("connect", () => {
        socket.write(line);
      });
    } catch {
      finish(false);
    }
  });
}

/** Beside the collector's, in the one directory a pane may not write. */
export const NUDGE_SOCKET_REL = "traces/.nudge.sock";

/**
 * Wake a peer, without being able to say anything to it.
 *
 * This used to be `spawn("herdr", ["agent", "prompt", peer, message])` from
 * inside the pane, which needed Herdr's control socket — a socket with no
 * authentication, whose `layout.apply` starts a process outside the seatbelt
 * profile and whose `pane.send_text` types into any pane. The write guard
 * denies it now, and this goes to `scripts/nudge-broker.mjs` instead: the
 * pane names a `kind`, the broker owns the words.
 *
 * `false` means the peer was not reached — the caller records that, and the
 * sentinel hook still stops the peer on its next tool call.
 */
export async function nudgePeerViaBroker(sandboxRoot: string, peer: string, kind: string, from: string): Promise<boolean> {
  const configured = process.env.SWARM_NUDGE_SOCKET || join(sandboxRoot, NUDGE_SOCKET_REL);
  const socketPath = configured.length > SOCKET_PATH_SAFE ? shortSocketPath(configured) : configured;
  return new Promise<boolean>((resolvePromise) => {
    let settled = false;
    let answer = "";
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      resolvePromise(ok);
    };
    try {
      const socket = connect(socketPath);
      socket.setTimeout(NUDGE_TIMEOUT_MS, () => {
        socket.destroy();
        finish(false);
      });
      socket.on("error", () => finish(false));
      socket.on("data", (chunk) => {
        answer += chunk.toString("utf8");
      });
      socket.on("close", () => {
        try {
          finish(JSON.parse(answer.trim() || "{}")?.ok === true);
        } catch {
          finish(false);
        }
      });
      socket.on("connect", () => {
        socket.write(`${seatAuthLine()}${JSON.stringify({ kind, peer, from })}\n`);
      });
    } catch {
      finish(false);
    }
  });
}

const COLLECTOR_TIMEOUT_MS = 2000;
/** A nudge waits on `herdr agent prompt`, which the broker caps at 5s. */
const NUDGE_TIMEOUT_MS = 8000;
/** Below the ~104-byte `sun_path` limit with room for a prefix. */
const SOCKET_PATH_SAFE = 96;

/**
 * The first line a VM's process writes on every connection it opens to its
 * seat's hub socket: the seat token the kickoff gave that VM alone
 * (SWARM_SEAT_TOKEN). The hub serves a seat's socket only after it, so a
 * process outside the VM that can reach the socket file (a host-mode pane
 * on a host where only Landlock guards, say) cannot speak as the seat. The
 * hub answers a good one with nothing, so every client reads its replies as
 * before. Empty outside a VM: no pane is ever given a seat token.
 */
export function seatAuthLine(env: NodeJS.ProcessEnv = process.env): string {
  const token = env.SWARM_SEAT_TOKEN;
  return token ? `${JSON.stringify({ t: "auth", token })}\n` : "";
}
/** Consecutive failures after which this pane stops trying the socket. */
const COLLECTOR_GIVE_UP_AFTER = 3;
/** How long a pane stays away before trying the collector again. */
const COLLECTOR_RETRY_AFTER_MS = 30_000;

/**
 * How much a single `write` is atomic for in practice. POSIX promises this
 * much for a pipe; every filesystem this runs on does at least as well, and
 * nothing promises more.
 */
const ATOMIC_APPEND_BYTES = 4096;

/**
 * The token this pane was given, which decides whose line this is.
 *
 * It travels in the environment because on macOS no other process can read a
 * process's environment (measured) and Herdr's API does not expose a pane's
 * env (measured) — so while every pane shares one uid, this is the only thing
 * that separates them. It is stripped by the collector and never written.
 */
function traceToken(): string {
  return process.env.SWARM_TRACE_TOKEN || "";
}

/**
 * Whether the trace's tail refuses a direct append, read from the end of the
 * file so a long trace is not loaded whole on every fallback: its last line
 * carries the collector's `prev`, or it is a fragment (no closing newline, or
 * not JSON) that a collector killed mid-append left behind. A line appended
 * onto a fragment would fuse with it and corrupt the record for good.
 */
async function tailRefusesAppend(file: string): Promise<boolean> {
  let handle;
  try {
    handle = await open(file, "r");
  } catch {
    return false;
  }
  try {
    const { size } = await handle.stat();
    if (size === 0) return false;
    const lastByte = Buffer.alloc(1);
    await handle.read(lastByte, 0, 1, size - 1);
    if (lastByte[0] !== 0x0a) return true;
    const CHUNK = 65536;
    const chunks: Buffer[] = [];
    let end = size;
    let seen = 0;
    while (end > 0) {
      const start = Math.max(0, end - CHUNK);
      const buf = Buffer.alloc(end - start);
      await handle.read(buf, 0, buf.length, start);
      chunks.unshift(buf);
      seen += buf.length;
      end = start;
      const text = Buffer.concat(chunks, seen).toString("utf8").replace(/\n+$/, "");
      const cut = text.lastIndexOf("\n");
      if (cut >= 0 || end === 0) {
        const last = text.slice(cut + 1);
        if (!last) return false;
        try {
          const record = JSON.parse(last) as { prev?: unknown };
          return typeof record?.prev === "string";
        } catch {
          return true;
        }
      }
    }
    return false;
  } catch {
    // Unreadable is not chained: the append below meets the same error and
    // spills, as it always has.
    return false;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/**
 * Each process's own count of the lines it sent, under an id of its own: a
 * line that reached the chain and the spill both (a collector that answered
 * late) is the same (sid, seq) twice, and a gap in a process's seq is a line
 * that reached neither. Custody reads both.
 */
const TRACE_SID = createHash("sha256").update(`${process.pid}:${Date.now()}:${Math.random()}`).digest("hex").slice(0, 12);
let traceSeq = 0;
/** In a VM: lines went to this seat's spill, and how far into it has been sent on since. */
let vmSpilled = false;
let spillResent = 0;

/**
 * Once the link is back, what a VM spilled while it was down goes on to the
 * chain, in order, under its own sid and seq: the lines were the seat's own
 * and belong in the anchored record, not only in a file in the seat's own
 * directory. The spill stays as it was (custody counts a line in both as a
 * duplicate, not a loss), and a line the collector still refuses stops the
 * resend until the next time.
 */
async function resendSpill(sandboxRoot: string, token: string): Promise<void> {
  vmSpilled = false;
  const file = join(sandboxRoot, traceSpillRel());
  const text = await readFile(file, "utf8").catch(() => "");
  if (text.length <= spillResent) return;
  const lines = text.slice(spillResent).split("\n");
  const tail = lines.pop() ?? "";
  let sent = spillResent;
  for (const l of lines) {
    sent += l.length + 1;
    if (!l.trim()) continue;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(l) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (!(await sendToCollector(sandboxRoot, `${JSON.stringify(token ? { ...parsed, token, resent: true } : { ...parsed, resent: true })}\n`))) {
      vmSpilled = true;
      return;
    }
    spillResent = sent;
  }
  if (tail) vmSpilled = true;
}

export async function appendEvent(
  sandboxRoot: string,
  event: Omit<SwarmEvent, "ts"> & { ts?: string },
): Promise<SwarmEvent> {
  const token = traceToken();
  // The token that attributes this line, and the console's mutation token,
  // are credentials. A shell's `env`, a tool that prints its environment, and
  // the whole output now kept in the trace would otherwise publish them to
  // every reader of the trace — and one pane's token lets another speak as it.
  const credentials: Record<string, string> = {};
  if (token) credentials.SWARM_TRACE_TOKEN = token;
  if (process.env.SWARM_UI_TOKEN) credentials.SWARM_UI_TOKEN = process.env.SWARM_UI_TOKEN;
  const record: SwarmEvent = redactSecrets(
    {
      ts: event.ts ?? new Date().toISOString(),
      agent: event.agent,
      tool: event.tool,
      args: event.args ?? {},
      result: event.result ?? {},
      sid: TRACE_SID,
      seq: ++traceSeq,
    },
    credentials,
  );
  const file = join(sandboxRoot, EVENTS_REL);
  const line = `${JSON.stringify(token ? { ...record, token } : record)}\n`;
  // The collector, when this run has one: a process outside the pane's
  // sandbox profile, holding the only writable handle to the trace. The pane
  // may connect to its socket and may not write the directory, so an agent
  // cannot edit the record of what it did.
  if (await sendToCollector(sandboxRoot, line)) {
    if (vmSpilled) await resendSpill(sandboxRoot, token);
    return record;
  }
  // The fallback writes the file itself, and the token is a secret, not a
  // field: it goes to the collector and nowhere else.
  const plain = `${JSON.stringify(record)}\n`;
  // In a VM the trace directory is read-only and shared: the spill is the
  // only place a line can go.
  if (process.env.SWARM_ISOLATION === "microvm") {
    // A line that reaches neither the collector nor the spill is lost, and a
    // lost line must not pass for a recorded one.
    await appendFile(join(sandboxRoot, traceSpillRel()), plain, "utf8");
    vmSpilled = true;
    return record;
  }
  await mkdir(dirname(file), { recursive: true }).catch(() => undefined);
  // A chained record must not take an unchained line: the verifier reports it
  // as "appended" by something other than the collector — a tamper alarm the
  // harness raises against itself. This is a collector that stopped answering
  // with no write guard to make traces/ read-only. The line goes to the spill
  // file, as the shell watchdogs do; only an unchained record takes the append.
  // So does a torn tail, which the appended line would fuse with.
  if (await tailRefusesAppend(file)) {
    await mkdir(dirname(join(sandboxRoot, TRACE_SPILL_REL)), { recursive: true }).catch(() => undefined);
    await appendFile(join(sandboxRoot, TRACE_SPILL_REL), plain, "utf8");
    return record;
  }
  // O_APPEND keeps two writers from overwriting each other, but a line is no
  // longer guaranteed to be small: an argument may now be 20,000 characters
  // (A43), which is past the size any filesystem promises to write in one
  // piece — and virtiofs, which a containerised run would use, promises
  // nothing at all. A short line takes the cheap path; a long one takes the
  // trace's own lock, which nothing else waits on.
  try {
    if (Buffer.byteLength(plain, "utf8") <= ATOMIC_APPEND_BYTES) {
      await appendFile(file, plain, "utf8");
    } else {
      await withNamedLock(sandboxRoot, ".events.lock", async () => {
        await appendFile(file, plain, "utf8");
      });
    }
  } catch (err) {
    // With a collector running, `traces/` is read-only to this pane — which is
    // the point — so a failed send leaves nowhere to write the line. Losing it
    // in silence is the one outcome a record cannot have: it goes to a spill
    // file in `work/`, which the report and the package name.
    await appendFile(join(sandboxRoot, traceSpillRel()), plain, "utf8").catch(() => undefined);
    throw err;
  }
  return record;
}

export function formatEventLine(event: SwarmEvent): string {
  const args = Object.entries(event.args)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" ");
  const result =
    event.result && isRecord(event.result)
      ? Object.entries(event.result)
          .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
          .map(([k, v]) => `${k}=${v}`)
          .join(" ")
      : "";
  return [event.ts, event.agent, event.tool, args, result].filter(Boolean).join("  ");
}

/** The counters of a seat's spend that only ever grow within a run. */
export const MONOTONIC_USAGE_KEYS = ["spent_usd", "tokens", "calls", "input", "output", "cache_read", "cache_write"] as const;

/** What applySessionUsage throws when budget.json is there and does not parse. */
const BUDGET_UNREADABLE_PREFIX = "budget.json does not read";

/**
 * Whether an error from applySessionUsage is its refusal to fold over an
 * unreadable budget.json. Read from the message, which is what survives the
 * hub's socket in a microVM; any other failure (a lock timeout, a lost hub,
 * a report that went backwards) is not this and is not reported as it.
 */
export function isBudgetUnreadable(err: unknown): boolean {
  return (err instanceof Error ? err.message : String(err)).includes(BUDGET_UNREADABLE_PREFIX);
}

/** Sandboxes whose unreadable budget.json this process has already reported. */
const budgetUnreadableTold = new Set<string>();

/**
 * Say, once per process, that a fold was refused because budget.json could
 * not be read. While that lasts no cap and no wall clock is enforced from
 * this pane (the stop checks skip an unreadable file too, and so does the
 * hub's backstop in a microVM run), which is worth a veto on the board: a
 * trace row on every turn end is where nobody looks. `post` is the board's
 * system post as the caller reaches it (the hub, from a VM). Returns whether
 * this call told.
 */
export async function reportBudgetUnreadable(
  sandboxRoot: string,
  agentId: string,
  error: string,
  post: typeof systemPost = systemPost,
): Promise<boolean> {
  const key = resolve(sandboxRoot);
  if (budgetUnreadableTold.has(key)) return false;
  budgetUnreadableTold.add(key);
  await appendEvent(sandboxRoot, { agent: agentId || "unknown", tool: "budget_unreadable", args: {}, result: { error } }).catch(() => undefined);
  await post(sandboxRoot, {
    tag: "veto",
    body: `BUDGET UNREADABLE: budget.json does not parse, so ${agentId}'s spend is not being folded into it and no cap or wall clock is enforced while it stays that way. Put a valid budget.json back (the caps from the kickoff) and the next turn folds again. (${error})`,
  }).catch(() => undefined);
  return true;
}

export async function applySessionUsage(
  sandboxRoot: string,
  agentId: string,
  slice: SessionUsageSlice,
  options: { monotonic?: boolean } = {},
): Promise<{
  budget: BudgetRecord;
  over_budget: boolean;
  first_over: boolean;
}> {
  return withTableLock(sandboxRoot, async (held) => {
    // A sandbox with no budget yet starts one; a budget.json that is there
    // and does not read is the run's caps, and is never rebuilt from
    // defaults (no cap, a fifteen-minute clock started now). It is read once
    // more first: the harness's own writes are whole (writeBudget), but an
    // operator raising a cap in an editor may be caught mid-save.
    const budget = await readBudget(sandboxRoot)
      .catch(async (err: NodeJS.ErrnoException) => {
        if (err?.code === "ENOENT") return normalizeBudget({ started_at: new Date().toISOString() });
        await sleep(BUDGET_REREAD_MS);
        return readBudget(sandboxRoot);
      })
      .catch((err: unknown) => {
        throw new Error(`${BUDGET_UNREADABLE_PREFIX} (${err instanceof Error ? err.message : String(err)}); its caps are left as they are`);
      });
    if (options.monotonic) {
      // Checked here, under the table lock, against the row this write
      // replaces: two reports in flight at once cannot both pass a check made
      // before either was written and leave the smaller one on disk. A report
      // under a session id is checked against that session's last report: a
      // new id is a Pi that restarted, whose totals begin again at zero and
      // are added to the seat's (foldSessionSlice). Checked against the whole
      // row, a restarted seat's reports were refused until its new session
      // alone passed the old total, and the spend between went uncounted.
      // Without an id, the whole row, as before. Either way the row never
      // goes down.
      const was = budget.agents[agentId];
      const id = typeof slice.session_id === "string" && slice.session_id ? slice.session_id : undefined;
      const against: Partial<Record<(typeof MONOTONIC_USAGE_KEYS)[number], number>> | undefined = id ? was?.sessions?.[id] : was;
      for (const key of MONOTONIC_USAGE_KEYS) {
        const before = Number(against?.[key] ?? 0);
        const now = Number(slice[key] ?? 0);
        if (now + 1e-9 < before) throw new Error(`usage went backwards: ${key} ${now} < ${before}; a seat's spend only grows`);
      }
    }
    // The kickoff wrote the seat's model once; a fold that dropped it would
    // take the seat out of its model's cap after the first provider call.
    const model = budget.agents[agentId]?.model ?? slice.model;
    budget.agents[agentId] = { ...foldSessionSlice(budget.agents[agentId], slice), ...(model ? { model } : {}) };
    let spent = 0;
    let tokens = 0;
    let calls = 0;
    for (const row of Object.values(budget.agents)) {
      spent += row.spent_usd;
      tokens += row.tokens;
      calls += row.calls;
    }
    budget.spent_usd = Number(spent.toFixed(6));
    budget.tokens = tokens;
    budget.calls = calls;
    budget.source = BUDGET_SOURCE;
    const over = overCap(budget).over;
    const first_over = over && !budget.cap_steer_sent;
    if (first_over) budget.cap_steer_sent = true;
    await held.assertOwned();
    await writeBudget(sandboxRoot, budget);
    return { budget, over_budget: over, first_over };
  });
}

export type FileVersion = {
  rev: number;
  ts: string;
  agent: string;
  path: string;
  bytes: number;
  /** Content hash. Agents quote the short form when signing off on a file. */
  sha256: string;
  /** False when only the hash was kept: the file was past `HISTORY_STORE_MAX_BYTES`. */
  stored?: false;
};

/**
 * Past this a revision is recorded by its hash and size, not copied: an
 * extracted disk image or a memory dump written into an agent's directory is
 * not a document anyone restores, and a copy per revision would fill the
 * disk (and, from a VM, travel the hub link whole).
 */
export const HISTORY_STORE_MAX_BYTES = 32 * 1024 * 1024;

/** How many hex characters agents see and may pass back to `file_diff`. */
export const SHORT_HASH_LENGTH = 8;

export function shortHash(sha256: string): string {
  return sha256.slice(0, SHORT_HASH_LENGTH);
}

function historyDir(sandboxRoot: string, pathKey: string): string {
  return join(sandboxRoot, HISTORY_REL, lockHash(pathKey));
}

/** Where revision `rev` of a file's bytes is kept. */
export function historyRevisionPath(sandboxRoot: string, pathKey: string, rev: number): string {
  return join(historyDir(sandboxRoot, pathKey), `${String(rev).padStart(6, "0")}.bin`);
}

export function sha256Hex(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * How long a guest waits for a file the host wrote a moment ago: virtio-fs
 * caches a file's size and existence for five seconds in each guest
 * (docs/adr/0009), and this is that and a margin.
 */
export const GUEST_CACHE_WAIT_MS = 8_000;

export async function listFileHistory(
  sandboxRoot: string,
  rawPath: string,
): Promise<FileVersion[]> {
  // History is kept by the path a file really has. A path that resolves out
  // of the sandbox (a planted link) has none; the write watch asks about
  // such paths and wants "no history", not a refusal.
  let pathKey: string;
  try {
    pathKey = await realPathKey(sandboxRoot, rawPath);
  } catch {
    return [];
  }
  const dir = historyDir(sandboxRoot, pathKey);
  try {
    const raw = await readFile(join(dir, "index.json"), "utf8");
    const parsed = JSON.parse(raw) as FileVersion[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * Copy the current file into history/<hash>/<rev>. Local numbered copies
 * are the smallest store that works.
 * Content-identical writes do not create a revision, so the pre-write and
 * post-write snapshots around one edit collapse into a single entry.
 */
/** What a revision records: the bytes (when they are kept), their hash and size. */
async function takeRevisionBytes(
  sandboxRoot: string,
  rawPath: string,
  options: { bytes?: Buffer; hashOnly?: { sha256: string; bytes: number } },
): Promise<{ pathKey: string; bytes: Buffer | null; sha256: string; size: number } | null> {
  if (options.bytes) {
    const pathKey = await realPathKey(sandboxRoot, rawPath);
    return { pathKey, bytes: options.bytes, sha256: createHash("sha256").update(options.bytes).digest("hex"), size: options.bytes.byteLength };
  }
  if (options.hashOnly) {
    const pathKey = await realPathKey(sandboxRoot, rawPath);
    return { pathKey, bytes: null, sha256: options.hashOnly.sha256, size: options.hashOnly.bytes };
  }
  try {
    const read = await readSandboxFile(sandboxRoot, rawPath, { maxBytes: HISTORY_STORE_MAX_BYTES });
    if (!read) return null;
    return { pathKey: read.pathKey, bytes: read.bytes, sha256: createHash("sha256").update(read.bytes).digest("hex"), size: read.bytes.byteLength };
  } catch (err) {
    if (!(err instanceof FileTooLarge)) throw err;
  }
  const hashed = await hashSandboxFile(sandboxRoot, rawPath);
  return hashed ? { pathKey: hashed.pathKey, bytes: null, sha256: hashed.sha256, size: hashed.bytes } : null;
}

export async function recordFileVersion(
  sandboxRoot: string,
  rawPath: string,
  agentId: string,
  options: { bytes?: Buffer; hashOnly?: { sha256: string; bytes: number }; missing?: boolean } = {},
): Promise<FileVersion | null> {
  // Never through a link: the file is what the resolved path names, or
  // nothing; a link out of the sandbox, or a link at all, is a refusal the
  // caller hears about. From a VM the bytes (or, past the store limit, the
  // hash) come with the call: the hub does not open a file under a
  // directory a running seat can rearrange.
  if (options.missing) return null;
  const taken = await takeRevisionBytes(sandboxRoot, rawPath, options);
  if (!taken) return null;
  const { pathKey, sha256, size } = taken;
  let bytes = taken.bytes;
  if (bytes && bytes.byteLength > HISTORY_STORE_MAX_BYTES) bytes = null;
  // Allocating the next revision number is a read-modify-write on
  // index.json shared by every process (agents, the reaper, the web
  // operator). Without the mutex two writers take the same number, one
  // binary overwrites the other, and the surviving index entry names a hash
  // the stored bytes do not have.
  const key = pathKey;
  return withTableLock(sandboxRoot, async (held) => {
    const dir = historyDir(sandboxRoot, key);
    await mkdir(dir, { recursive: true });
    const versions = await listFileHistory(sandboxRoot, key);
    const last = versions.at(-1);
    if (last?.sha256 === sha256) return null;
    const rev = (last?.rev ?? 0) + 1;
    await held.assertOwned();
    if (bytes) await writeFile(join(dir, `${String(rev).padStart(6, "0")}.bin`), bytes);
    const record: FileVersion = {
      rev,
      ts: new Date().toISOString(),
      agent: agentId,
      path: key,
      bytes: size,
      sha256,
      ...(bytes ? {} : { stored: false as const }),
    };
    versions.push(record);
    await writeFileAtomic(join(dir, "index.json"), `${JSON.stringify(versions, null, 2)}\n`);
    return record;
  });
}

/** Why a revision's bytes cannot be read back, when they were not kept. */
function notStored(pathKey: string, v: FileVersion): string {
  return `${pathKey} rev ${v.rev} was recorded by its hash only (${v.bytes} bytes, past the ${HISTORY_STORE_MAX_BYTES}-byte store limit); its bytes were not kept`;
}

/**
 * Accept what an agent is likely to hold: a revision number, a short or full
 * content hash, or `latest` / `disk` for the bytes on disk right now.
 */
/** Past this a file is not diffed: a diff of a disk image is not something anyone reads. */
export const DIFF_MAX_BYTES = 16 * 1024 * 1024;

export function isDiskRef(ref: number | string | undefined): boolean {
  const token = String(ref ?? "").trim().toLowerCase();
  return token === "disk" || token === "latest" || token === "working";
}

export async function resolveRevision(
  sandboxRoot: string,
  rawPath: string,
  ref: number | string,
  options: { disk?: Buffer | null } = {},
): Promise<{ rev: number | null; sha256: string | null; text: string } | null> {
  const pathKey = await realPathKey(sandboxRoot, rawPath);
  const versions = await listFileHistory(sandboxRoot, pathKey);
  const token = String(ref).trim().toLowerCase();

  if (isDiskRef(token)) {
    // From a VM the bytes on disk come with the call (`options.disk`, null
    // for no such file): the hub does not open a file under a directory a
    // running seat can rearrange.
    let bytes: Buffer | null;
    if (options.disk !== undefined) {
      bytes = options.disk;
    } else {
      try {
        bytes = (await readSandboxFile(sandboxRoot, pathKey, { maxBytes: DIFF_MAX_BYTES }))?.bytes ?? null;
      } catch (err) {
        if (err instanceof FileTooLarge) throw new Error(`${pathKey} is too large to diff (${err.size} bytes; the limit is ${DIFF_MAX_BYTES})`);
        bytes = null;
      }
    }
    if (!bytes) return null;
    return { rev: null, sha256: createHash("sha256").update(bytes).digest("hex"), text: bytes.toString("utf8") };
  }

  let match: FileVersion | undefined;
  if (/^\d+$/.test(token)) {
    match = versions.find((v) => v.rev === Number.parseInt(token, 10));
  }
  if (!match && /^[0-9a-f]{4,64}$/.test(token)) {
    const hits = versions.filter((v) => (v.sha256 ?? "").startsWith(token));
    // Dedupe only compares against the previous revision, so restoring an
    // older version records the same content again. Several revisions with
    // one hash are the same bytes: take the newest instead of refusing.
    const distinct = new Set(hits.map((v) => v.sha256));
    if (distinct.size > 1) {
      throw new Error(`Ambiguous revision "${ref}": ${distinct.size} different contents match`);
    }
    match = hits.at(-1);
  }
  if (!match) return null;
  if (match.stored === false) throw new Error(notStored(pathKey, match));
  if (match.bytes > DIFF_MAX_BYTES) throw new Error(`${pathKey} rev ${match.rev} is too large to diff (${match.bytes} bytes; the limit is ${DIFF_MAX_BYTES})`);
  const file = join(historyDir(sandboxRoot, pathKey), `${String(match.rev).padStart(6, "0")}.bin`);
  const text = await readFile(file, "utf8").catch(() => null);
  if (text === null) return null;
  return { rev: match.rev, sha256: match.sha256 ?? null, text };
}

export async function readFileVersion(
  sandboxRoot: string,
  rawPath: string,
  rev: number,
): Promise<{ path: string; rev: number; text: string } | null> {
  const pathKey = await realPathKey(sandboxRoot, rawPath);
  const versions = await listFileHistory(sandboxRoot, pathKey);
  const version = versions.find((v) => v.rev === rev);
  if (!version) return null;
  if (version.stored === false) throw new Error(notStored(pathKey, version));
  const file = join(historyDir(sandboxRoot, pathKey), `${String(rev).padStart(6, "0")}.bin`);
  const text = await readFile(file, "utf8");
  return { path: pathKey, rev, text };
}

type DiffRow = { sign: " " | "-" | "+"; text: string };

/**
 * A trailing newline ends the last line, it does not start an empty one.
 * Without this an empty file reads as one empty line and diffs against a
 * one-line file report a removal that never happened.
 */
export function splitLines(text: string): string[] {
  if (text === "") return [];
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines;
}

/**
 * The LCS matrix is O(n*m) cells, so two 50k-line files would ask for
 * billions of them and take the process down. Trimming the common prefix and
 * suffix first collapses the usual case (an edit in the middle of a long
 * file); anything still larger than this budget falls back to a block
 * replace, which is coarse but honest and bounded.
 */
export const DIFF_MAX_CELLS = 4_000_000;

function lcsDiff(a: string[], b: string[]): DiffRow[] {
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffRow[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ sign: " ", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ sign: "-", text: a[i++] });
    } else {
      out.push({ sign: "+", text: b[j++] });
    }
  }
  while (i < n) out.push({ sign: "-", text: a[i++] });
  while (j < m) out.push({ sign: "+", text: b[j++] });
  return out;
}

function diffLines(a: string[], b: string[]): DiffRow[] {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  const middle: DiffRow[] =
    midA.length * midB.length > DIFF_MAX_CELLS
      ? [
          ...midA.map((text): DiffRow => ({ sign: "-", text })),
          ...midB.map((text): DiffRow => ({ sign: "+", text })),
        ]
      : lcsDiff(midA, midB);
  return [
    ...a.slice(0, start).map((text): DiffRow => ({ sign: " ", text })),
    ...middle,
    ...a.slice(endA).map((text): DiffRow => ({ sign: " ", text })),
  ];
}

export type FileDiffResult = {
  path: string;
  from: { rev: number | null; sha256: string | null };
  to: { rev: number | null; sha256: string | null };
  identical: boolean;
  added: number;
  removed: number;
  diff: string;
  truncated: boolean;
};

export const DIFF_MAX_LINES = 400;

/**
 * Diff two revisions of a work file. Refs are revision numbers, content
 * hashes (short or full), or `disk`. Defaults to "last recorded revision
 * against what is on disk now", which is what an agent asking "did someone
 * change this under me?" wants.
 */
export async function fileDiff(
  sandboxRoot: string,
  rawPath: string,
  fromRef?: number | string,
  toRef?: number | string,
  options: { disk?: Buffer | null } = {},
): Promise<FileDiffResult> {
  const pathKey = await realPathKey(sandboxRoot, rawPath);
  const versions = await listFileHistory(sandboxRoot, pathKey);
  const from = fromRef ?? versions.at(-1)?.rev ?? "disk";
  const to = toRef ?? "disk";

  const left = await resolveRevision(sandboxRoot, pathKey, from, options);
  if (!left) throw new Error(`No revision "${from}" for ${pathKey}`);
  const right = await resolveRevision(sandboxRoot, pathKey, to, options);
  if (!right) throw new Error(`No revision "${to}" for ${pathKey}`);

  const rows = diffLines(splitLines(left.text), splitLines(right.text));
  const added = rows.filter((r) => r.sign === "+").length;
  const removed = rows.filter((r) => r.sign === "-").length;
  const shown = rows.slice(0, DIFF_MAX_LINES);
  return {
    path: pathKey,
    from: { rev: left.rev, sha256: left.sha256 },
    to: { rev: right.rev, sha256: right.sha256 },
    identical: added === 0 && removed === 0,
    added,
    removed,
    diff: shown.map((r) => `${r.sign}${r.text}`).join("\n"),
    truncated: rows.length > shown.length,
  };
}

export async function restoreFileVersion(
  ctx: SwarmContext,
  rawPath: string,
  rev: number,
): Promise<{ ok: boolean; path: string; rev: number; reason?: string; landed_rev?: number | null; sha256?: string }> {
  const pathKey = await realPathKey(ctx.sandboxRoot, rawPath);
  const guard = await guardWrite(ctx, pathKey);
  if (!guard.ok) {
    return { ok: false, path: pathKey, rev, reason: guard.reason };
  }
  const versions = await listFileHistory(ctx.sandboxRoot, pathKey);
  const version = versions.find((v) => v.rev === rev);
  if (!version) {
    return { ok: false, path: pathKey, rev, reason: `no history rev ${rev}` };
  }
  if (version.stored === false) return { ok: false, path: pathKey, rev, reason: notStored(pathKey, version) };
  // Snapshot first, in case the bytes on disk drifted from the last recorded
  // revision (a bash write, say). Deduping makes this a no-op when they match.
  await recordFileVersion(ctx.sandboxRoot, pathKey, ctx.agentId);
  const src = join(historyDir(ctx.sandboxRoot, pathKey), `${String(rev).padStart(6, "0")}.bin`);
  // In place and never through a link: the destination is opened with
  // O_NOFOLLOW and checked against what was resolved, so a link swapped in
  // after the guard's check lands the bytes nowhere.
  try {
    await writeSandboxFile(ctx.sandboxRoot, pathKey, await readFile(src));
  } catch (err) {
    return { ok: false, path: pathKey, rev, reason: (err as Error).message };
  }
  // Then record the restore itself, so history stays a truthful log of what
  // the file looked like over time and who put it that way.
  const landed = await recordFileVersion(ctx.sandboxRoot, pathKey, ctx.agentId);
  return { ok: true, path: pathKey, rev, landed_rev: landed?.rev ?? null, sha256: version.sha256 };
}

/**
 * How long past a cap the harness waits for an agent to stop itself before
 * setting the sentinel. The steer arrives as a user message, so an agent that
 * is mid-turn (or asleep in `wait`) needs a moment to see it and call done.
 */
export const STOP_GRACE_MS = 2 * 60 * 1000;

export type BudgetPressure = {
  over_budget: boolean;
  over_time: boolean;
  /** How long the swarm has been over a limit, 0 when it is not. */
  overdue_ms: number;
  reason: StopReason | null;
  elapsed_minutes: number;
};

/** Where the swarm stands against its two caps. Pure, so it is easy to test. */
export function budgetPressure(budget: BudgetRecord, now = Date.now()): BudgetPressure {
  // The wall clock across pauses and resumes: a paused run's is frozen at its pause.
  const elapsedMs = wallElapsedMs(budget, now);
  // An until-solved run has no wall clock, and its caps are advisory.
  const wallMs = budget.until_solved === true ? 0 : budget.wall_clock_minutes * 60_000;
  const overBudget = overCap(budget).over;
  const overTime = wallMs > 0 && elapsedMs >= wallMs;
  return {
    over_budget: overBudget,
    over_time: overTime,
    overdue_ms: overTime ? elapsedMs - wallMs : 0,
    reason: overBudget ? "cap" : overTime ? "wall_clock" : null,
    elapsed_minutes: Number((elapsedMs / 60_000).toFixed(2)),
  };
}

/**
 * Change the caps while the run goes on: the operator's `swarm.sh cap`.
 * Under the table lock, as every fold of usage is, so the next fold (the
 * hub's, a seat's) reads it and keeps it. Each change is kept in cap_changes
 * with the caps it left, which is how the shell watch tells it from a shell
 * writer's. A swarm-wide stop steer the run is no longer over is withdrawn;
 * a seat's own cap steer lifts by itself on the next check. The run's brake
 * stays: a team whose dollars are charged keeps a dollar cap above zero, one
 * whose are not keeps a token cap. A finished run is not brought back.
 */
export async function setCaps(
  sandboxRoot: string,
  set: Partial<Record<CapField, number>>,
  by: string,
): Promise<{ budget: BudgetRecord; before: Partial<Record<CapField, number | null>>; withdrawn: boolean; resumed?: PauseRecord }> {
  const fields = Object.entries(set).filter(([k, v]) => (CAP_FIELDS as readonly string[]).includes(k) && v !== undefined) as Array<[CapField, number]>;
  if (!fields.length) throw new Error("no cap to set: give --usd, --tokens, --per-agent-usd, --per-agent-tokens or --wall-clock");
  for (const [k, v] of fields) {
    if (!Number.isFinite(v) || v < 0) throw new Error(`${k} must be a number, zero or above (got ${v})`);
    if (k === "wall_clock_minutes" && v <= 0) throw new Error("the wall clock must be above zero minutes");
  }
  if (await swarmDoneExists(sandboxRoot)) throw new Error("the run is finished (done/SWARM_DONE exists); a cap does not bring it back");
  return withTableLock(sandboxRoot, async (held) => {
    const budget = await readBudget(sandboxRoot);
    const before: Partial<Record<CapField, number | null>> = {};
    for (const [k, v] of fields) {
      before[k] = (budget[k] as number | undefined) ?? null;
      (budget as Record<CapField, number | undefined>)[k] = v;
    }
    // An until-solved run's caps are advisory: the brake is the operator's stop.
    if (budget.until_solved !== true && budget.metered !== false && !(budget.cap_usd > 0)) {
      throw new Error("this team's dollars are charged, so its dollar cap stays above zero");
    }
    if (budget.until_solved !== true && budget.metered === false && !(Number(budget.cap_tokens) > 0)) {
      throw new Error("this team's dollars are not charged, so its token cap stays above zero");
    }
    let withdrawn = false;
    if ((budget.cap_steer_sent || budget.stop_steer_at) && !budgetPressure(budget).reason) {
      budget.cap_steer_sent = false;
      delete budget.stop_steer_at;
      delete budget.stop_reason;
      withdrawn = true;
    }
    // A paused run whose caps now leave room goes on.
    const resumed = liftPause(budget, by, Object.fromEntries(fields));
    budget.cap_changes = [
      ...(budget.cap_changes ?? []),
      { at: new Date().toISOString(), by, set: Object.fromEntries(fields), caps: capFingerprint(normalizeBudget(budget)) },
    ];
    await held.assertOwned();
    await writeBudget(sandboxRoot, budget);
    return { budget: normalizeBudget(budget), before, withdrawn, ...(resumed ? { resumed } : {}) };
  });
}

/**
 * Lift the pause in force, when the run is no longer over a cap: the wall
 * clock's stretch up to the pause is kept, a new one starts now, and the
 * pause goes to the history with who lifted it and what they gave. The
 * steer that announced it is withdrawn. Mutates `budget`; the caller holds
 * the table lock and writes it.
 */
function liftPause(budget: BudgetRecord, by: string, set: Partial<Record<CapField, number>>, now = Date.now()): PauseRecord | null {
  if (!budget.paused) return null;
  const hypothetical = { ...budget, paused: undefined, wall_used_ms: wallElapsedMs(budget, now), wall_base_at: new Date(now).toISOString() } as BudgetRecord;
  if (budgetPressure(hypothetical, now).reason) return null;
  const done: PauseRecord = { ...budget.paused, resumed_at: new Date(now).toISOString(), resumed_by: by, set };
  budget.wall_used_ms = hypothetical.wall_used_ms;
  budget.wall_base_at = hypothetical.wall_base_at;
  delete budget.paused;
  budget.pauses = [...(budget.pauses ?? []), done];
  budget.cap_steer_sent = false;
  delete budget.stop_steer_at;
  delete budget.stop_reason;
  return done;
}

/**
 * The operator's extension of a run (swarm.sh extend): more wall clock
 * (minutes), more tokens, more dollars, each added to the cap it extends,
 * under the table lock as every cap change is. A paused run whose caps then
 * leave room goes on (the watchdog wakes its seats); one still over a cap is
 * refused, saying which and by how much, and nothing is changed. A finished
 * run is not brought back: that is resume.
 */
export async function extendRun(
  sandboxRoot: string,
  add: { minutes?: number; tokens?: number; usd?: number },
  by: string,
  now = Date.now(),
): Promise<{ budget: BudgetRecord; set: Partial<Record<CapField, number>>; resumed: PauseRecord | null }> {
  const given = Object.entries(add).filter(([, v]) => v !== undefined && v !== null) as Array<[keyof typeof add, number]>;
  if (!given.length) throw new Error("nothing to extend by: give --minutes N, --tokens N or --usd N");
  for (const [k, v] of given) if (!Number.isFinite(v) || v <= 0) throw new Error(`--${k} takes a number above zero (got ${v})`);
  return withTableLock(sandboxRoot, async (held) => {
    // The run's end is read under the lock every stop writes it under: a
    // stop, the harness's or the operator's, that took the lock first is
    // not undone by an extension that was waiting for it.
    if (await swarmDoneExists(sandboxRoot)) throw new Error("the run is finished (done/SWARM_DONE exists): an extension does not bring it back; swarm.sh resume continues it");
    if (await lstat(join(sandboxRoot, STOPPED_REL)).then(() => true).catch(() => false)) throw new Error("the run was stopped (done/STOPPED exists): an extension does not bring it back; swarm.sh resume continues it");
    const budget = await readBudget(sandboxRoot);
    if (stopPolicyOf(budget) === "operator") throw new Error("this run's stop is the operator's (--stop operator): it has no wall clock and its caps are advisory, so there is nothing to extend; swarm.sh stop ends it");
    const set: Partial<Record<CapField, number>> = {};
    if (add.minutes) set.wall_clock_minutes = budget.wall_clock_minutes + add.minutes;
    if (add.tokens) {
      if (!(Number(budget.cap_tokens) > 0)) throw new Error("--tokens: this run has no token cap to extend (swarm.sh cap --tokens N sets one)");
      set.cap_tokens = Math.max(Number(budget.cap_tokens), budget.tokens) + add.tokens;
    }
    if (add.usd) {
      if (budget.metered === false) throw new Error("--usd: this team's dollars are not charged, so the dollar cap brakes nothing; extend --tokens instead");
      set.cap_usd = Number((Math.max(budget.cap_usd, budget.spent_usd) + add.usd).toFixed(6));
    }
    for (const [k, v] of Object.entries(set) as Array<[CapField, number]>) (budget as Record<CapField, number | undefined>)[k] = v;
    const resumed = liftPause(budget, by, set, now);
    if (budget.paused) {
      const hypothetical = { ...budget, paused: undefined, wall_used_ms: wallElapsedMs(budget, now), wall_base_at: new Date(now).toISOString() } as BudgetRecord;
      const p = budgetPressure(hypothetical, now);
      const over = p.reason === "wall_clock" ? `the wall clock (${Math.round(wallElapsedMs(budget, now) / 60_000)} of ${budget.wall_clock_minutes} minutes used)` : overCap(hypothetical).by === "tokens" ? `the token cap (${budget.tokens} of ${budget.cap_tokens})` : `the dollar cap ($${budget.spent_usd} of $${budget.cap_usd})`;
      throw new Error(`the run would still be over ${over}: extend it by more, or by that cap too; nothing was changed`);
    }
    budget.cap_changes = [...(budget.cap_changes ?? []), { at: new Date(now).toISOString(), by, set, caps: capFingerprint(normalizeBudget(budget)) }];
    await held.assertOwned();
    await writeBudget(sandboxRoot, budget);
    return { budget: normalizeBudget(budget), set, resumed };
  });
}

/**
 * Pause the run at a cap (the cap-pause policy): the seats finish their
 * step and go idle, no model call goes out (the extension refuses it on the
 * host, the model gateway in a VM, and neither the hub nor the watchdog
 * prompts a paused seat), and what the run holds stays as it is. Re-checked
 * under the lock, like the harness's stop. Idempotent.
 */
export async function pauseRun(sandboxRoot: string, reason: StopReason, detail: string, now = Date.now()): Promise<{ paused: boolean; at: string; already?: true; stale?: true }> {
  return withTableLock(sandboxRoot, async (held) => {
    if (await swarmDoneExists(sandboxRoot)) return { paused: false, at: new Date(now).toISOString(), stale: true as const };
    const budget = await readBudget(sandboxRoot).catch(() => null);
    if (!budget) return { paused: false, at: new Date(now).toISOString(), stale: true as const };
    if (budget.paused) return { paused: false, at: budget.paused.at, already: true as const };
    if (!budgetPressure(budget, now).reason) return { paused: false, at: new Date(now).toISOString(), stale: true as const };
    budget.paused = { at: new Date(now).toISOString(), reason, detail };
    await held.assertOwned();
    await writeBudget(sandboxRoot, budget);
    return { paused: true, at: budget.paused.at };
  });
}

/** Whether the run is paused now. */
export function isPaused(b: { paused?: unknown } | null | undefined): boolean {
  return Boolean(b?.paused);
}

/** What the agents are told when a cap is reached, by the run's stop policy. */
export function capSteerText(budget: BudgetRecord, pressure: BudgetPressure): string {
  const byTokens = pressure.reason === "cap" && overCap(budget).by === "tokens";
  const what = pressure.reason === "wall_clock" ? `wall clock (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes)` : byTokens ? `token cap (${budget.tokens.toLocaleString("en-US")} of ${Number(budget.cap_tokens).toLocaleString("en-US")})` : `spend cap ($${budget.spent_usd} of $${budget.cap_usd})`;
  if (stopPolicyOf(budget) === "cap-pause") {
    return (
      `The run's ${what} is reached: it pauses in ${Math.round(STOP_GRACE_MS / 60_000)} minutes, for the operator to extend it or stop it. ` +
      "Record what you hold now: each finding, a limitation for what you could not finish, a coverage record for a search you finished; release the leads you will not finish, with why. " +
      "Start nothing new, and do not call done unless the finish line is met. While the run is paused no model call goes out; the operator's extension wakes you where you were."
    );
  }
  if (pressure.reason === "wall_clock") return `Swarm wall clock hit (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes). Call done with reason cannot_complete and stop. Do not start new work.`;
  return byTokens ? TOKEN_CAP_STEER : CAP_STEER;
}

/**
 * What the harness does once a cap's grace period has passed, by the stop
 * policy: pause the run (cap-pause) or write the sentinel as the harness,
 * the run stopped (cap-stop). Under the operator's policy a cap is advisory
 * and nothing is done. Both re-check the cap under the lock.
 */
export async function capAct(sandboxRoot: string, reason: StopReason, detail: string): Promise<{ kind: "paused" | "stopped" | "none"; created: boolean }> {
  const budget = await readBudget(sandboxRoot).catch(() => null);
  const policy = stopPolicyOf(budget);
  if (policy === "operator") return { kind: "none", created: false };
  if (policy === "cap-pause") {
    const p = await pauseRun(sandboxRoot, reason, detail);
    return { kind: "paused", created: p.paused };
  }
  const stop = await harnessStop(sandboxRoot, reason, detail, { verify: true });
  return { kind: "stopped", created: stop.created };
}

/**
 * Whether one agent is over its own cap, in dollars or in tokens. The dollar
 * cap holds only on a team whose dollars are charged (`metered`): on a
 * subscription Pi's dollars are an estimate, and a Luna seat that used ten
 * million tokens read as $0.13 beside a Daybreak seat's $14.
 */
export function agentPressure(
  budget: BudgetRecord,
  agentId: string,
): { over: boolean; by: "usd" | "tokens" | null; spent_usd: number; cap_usd: number; tokens: number; cap_tokens: number } {
  // Advisory in an until-solved run: shown, never a stop.
  const advisory = budget.until_solved === true;
  const capUsd = budget.metered !== false && !advisory ? Number(budget.cap_per_agent_usd) || 0 : 0;
  const capTokens = advisory ? 0 : Number(budget.cap_per_agent_tokens) || 0;
  const row = budget.agents?.[agentId];
  const spent = row?.spent_usd ?? 0;
  const tokens = row?.tokens ?? 0;
  const usd = capUsd > 0 && spent >= capUsd;
  const tok = capTokens > 0 && tokens >= capTokens;
  return { over: usd || tok, by: usd ? "usd" : tok ? "tokens" : null, spent_usd: spent, cap_usd: capUsd, tokens, cap_tokens: capTokens };
}

/**
 * Whether a model's agents, together, are over that model's cap. The spend
 * is summed over every seat whose recorded model is `model`; a model with no
 * cap is never over, and neither is a seat with no model on record. Pure,
 * like `agentPressure`, and read from the budget record alone.
 */
export function modelPressure(
  budget: BudgetRecord,
  model: string | undefined,
): { over: boolean; spent_usd: number; cap_usd: number; agents: number } {
  // A per-model cap is dollars, and holds only where dollars are charged;
  // in an until-solved run it is advisory.
  const cap = model && budget.metered !== false && budget.until_solved !== true ? Number(budget.cap_per_model_usd?.[model]) || 0 : 0;
  let spent = 0;
  let agents = 0;
  if (model) {
    for (const row of Object.values(budget.agents ?? {})) {
      if (row?.model !== model) continue;
      spent += row.spent_usd ?? 0;
      agents += 1;
    }
  }
  spent = Number(spent.toFixed(6));
  return { over: cap > 0 && spent >= cap, spent_usd: spent, cap_usd: cap, agents };
}

/**
 * Claim the swarm-wide stop clock. Exactly one caller gets `claimed: true`,
 * so the steer is announced on the board once rather than once per agent,
 * and every agent measures the grace period from the same instant.
 */
export async function markStopSteer(
  sandboxRoot: string,
  reason: StopReason,
): Promise<{ claimed: boolean; at: string }> {
  return withTableLock(sandboxRoot, async () => {
    const budget = await readBudget(sandboxRoot).catch(() => null);
    if (!budget) return { claimed: false, at: new Date().toISOString() };
    if (budget.stop_steer_at) return { claimed: false, at: budget.stop_steer_at };
    const at = new Date().toISOString();
    budget.stop_steer_at = at;
    budget.stop_reason = reason;
    if (reason === "cap") budget.cap_steer_sent = true;
    await writeBudget(sandboxRoot, budget);
    return { claimed: true, at };
  });
}

/** Drop the stop clock when the swarm is back under both limits (a raised cap). */
export async function clearStopSteer(sandboxRoot: string): Promise<void> {
  await withTableLock(sandboxRoot, async () => {
    const budget = await readBudget(sandboxRoot).catch(() => null);
    if (!budget?.stop_steer_at) return;
    delete budget.stop_steer_at;
    delete budget.stop_reason;
    await writeBudget(sandboxRoot, budget);
  });
}

/**
 * The harness's own stop. Agents are steered to call `done` first; this is
 * what happens when they do not — the kill switch lives in the harness, not
 * in the prompt. Idempotent: an existing sentinel is never overwritten.
 * The limit is re-checked under the lock, so a decision made from a budget
 * read seconds ago cannot stop a swarm that is no longer over it.
 */
export async function harnessStop(
  sandboxRoot: string,
  reason: StopReason,
  detail: string,
  options: { verify?: boolean } = {},
): Promise<{ created: boolean; sentinel: string; stale?: true }> {
  const sentinel = sentinelPath(sandboxRoot);
  return withTableLock(sandboxRoot, async () => {
    if (await swarmDoneExists(sandboxRoot)) return { created: false, sentinel };
    if (options.verify) {
      const budget = await readBudget(sandboxRoot).catch(() => null);
      if (!budget || !budgetPressure(budget).reason) {
        return { created: false, sentinel, stale: true as const };
      }
    }
    // A run the harness stopped at a cap is stopped, never completed.
    const created = await createSentinel(
      sandboxRoot,
      `---
by: harness
output: ""
reason: ${reason}
outcome: stopped
at: ${new Date().toISOString()}
---

${detail}
`,
    );
    return { created, sentinel };
  });
}

/** Highest post id per thread, read from filenames so it costs one readdir. */
export async function latestPostIds(
  sandboxRoot: string,
  threads: readonly string[],
): Promise<Record<string, number>> {
  const out: Record<string, number> = Object.create(null);
  for (const thread of threads) out[thread] = await maxPostId(sandboxRoot, thread);
  return out;
}

export type WaitOutcome = "post" | "sentinel" | "claim_lost" | "timeout" | "prompt" | "lead";

/**
 * When a seat began waiting, kept by the harness in inbox/<id>/waiting.json
 * for the lead register, which wakes the seat idle longest for a lead nobody
 * holds. A seat that waits again within WAIT_CHAIN_MS of its last wait ending
 * has been waiting all along (a wait returns every minute or so, and the
 * model's turn between two is not work); one that worked longer between two
 * waits starts a new spell.
 */
export type WaitingMark = { since: string; started_at: string; ended_at?: string };
export const WAIT_CHAIN_MS = 45_000;

function waitingPath(sandboxRoot: string, agentId: string): string {
  return join(sandboxRoot, "inbox", agentId, "waiting.json");
}

export async function readWaiting(sandboxRoot: string, agentId: string): Promise<WaitingMark | null> {
  try {
    const m = JSON.parse(await readFile(waitingPath(sandboxRoot, agentId), "utf8")) as WaitingMark;
    return typeof m.since === "string" && typeof m.started_at === "string" ? m : null;
  } catch {
    return null;
  }
}

/** When the spell of waiting now under way began, or null when the seat is not waiting now. */
export function waitingSince(mark: WaitingMark | null, now = Date.now()): number | null {
  if (!mark) return null;
  const started = Date.parse(mark.started_at);
  const ended = mark.ended_at ? Date.parse(mark.ended_at) : NaN;
  if (Number.isFinite(ended) && ended >= started) return null;
  const since = Date.parse(mark.since);
  return Number.isFinite(since) && since <= now ? since : null;
}

async function markWaiting(sandboxRoot: string, agentId: string, ended: boolean): Promise<void> {
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(agentId) || agentId === SYSTEM_AGENT) return;
  const now = new Date();
  const prev = await readWaiting(sandboxRoot, agentId);
  let mark: WaitingMark;
  if (ended) {
    if (!prev) return;
    mark = { ...prev, ended_at: now.toISOString() };
  } else {
    const lastEnd = prev?.ended_at ? Date.parse(prev.ended_at) : NaN;
    const chained = prev && (!prev.ended_at || (Number.isFinite(lastEnd) && now.getTime() - lastEnd <= WAIT_CHAIN_MS));
    mark = { since: chained ? prev!.since : now.toISOString(), started_at: now.toISOString() };
  }
  const path = waitingPath(sandboxRoot, agentId);
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(tmp, `${JSON.stringify(mark)}\n`, "utf8");
  await rename(tmp, path);
}

export type WaitResult = {
  reason: WaitOutcome;
  waited_ms: number;
  detail: string;
  /** Posts on the primary thread addressed only to other agents that arrived and did not wake this one. */
  passed?: number;
};

/**
 * Whether a post on the primary thread is for `agentId`, as `wait` decides
 * whether to wake it: yes when its `to` is empty or everyone ("all"), names
 * this agent by id or by the name it chose, or names nobody on the team (a
 * role, a word: better woken than missing it). No only when it names
 * teammates and not this agent. The BelkaCTF #6 run's ten agents woke 1,291
 * times for posts, and 586 of those wake-ups were for posts addressed only
 * to someone else, each a model turn with the whole context resent.
 */
export function postIsFor(to: string, agentId: string, team: ReadonlyArray<{ id: string; name?: string }>): boolean {
  const t = (to ?? "").trim().toLowerCase();
  if (!t || /(^|[\s,;/])(all|everyone|everybody|team)([\s,;/.!]|$)/.test(t)) return true;
  const me = agentId.toLowerCase();
  const named = (m: { id: string; name?: string }) => {
    const name = (m.name ?? "").trim().toLowerCase();
    return t.includes(m.id.toLowerCase()) || (name.length >= 3 && t.includes(name));
  };
  if (named({ id: agentId, name: team.find((m) => m.id.toLowerCase() === me)?.name })) return true;
  return !team.some((m) => m.id.toLowerCase() !== me && named(m));
}

export const WAIT_MAX_SECONDS = 300;
export const WAIT_POLL_MS = 500;

/**
 * Block until something the agent cares about happens, so an idle worker does
 * not burn a provider round per poll (`sleep 30` then `cat done/SWARM_DONE`
 * costs a full turn each time). Returns on a new post in a subscribed thread,
 * the sentinel appearing, losing a claim it held, or the deadline. A post on
 * the primary thread addressed only to other agents (postIsFor) does not wake
 * it unless `everyPost` is set: it stays unread, and the delivery that follows
 * the next wake carries it. A post in a side thread always wakes its members.
 */
export async function waitForSwarmChange(
  ctx: SwarmContext,
  options: { seconds?: number; signal?: AbortSignal; pollMs?: number; everyPost?: boolean; extraWake?: () => Promise<string | null> } = {},
): Promise<WaitResult> {
  await markWaiting(ctx.sandboxRoot, ctx.agentId, false).catch(() => undefined);
  try {
    return await waitLoop(ctx, options);
  } finally {
    await markWaiting(ctx.sandboxRoot, ctx.agentId, true).catch(() => undefined);
  }
}

async function waitLoop(
  ctx: SwarmContext,
  options: { seconds?: number; signal?: AbortSignal; pollMs?: number; everyPost?: boolean; extraWake?: () => Promise<string | null> },
): Promise<WaitResult> {
  const seconds = Math.min(Math.max(1, Math.round(options.seconds ?? 60)), WAIT_MAX_SECONDS);
  const pollMs = options.pollMs ?? WAIT_POLL_MS;
  const started = Date.now();
  const deadline = started + seconds * 1000;

  const threads = await subscribedThreads(ctx.sandboxRoot, ctx.agentId);
  const cursors = await readCursors(ctx.sandboxRoot, ctx.agentId);
  const mine = new Set(
    (await listClaims(ctx.sandboxRoot))
      .filter((c) => c.owner === ctx.agentId)
      .map((c) => c.path),
  );
  const elapsed = () => Date.now() - started;
  // How far this wait has looked in each thread: from the cursor, so an
  // unread post already there is judged too, and past each post that was
  // someone else's, so it is judged once.
  const seen: Record<string, number> = { ...cursors };
  let passed = 0;
  const withPassed = <T extends WaitResult>(r: T): T => (passed > 0 ? { ...r, passed } : r);

  for (;;) {
    if (await swarmDoneExists(ctx.sandboxRoot)) {
      return withPassed({ reason: "sentinel", waited_ms: elapsed(), detail: "done/SWARM_DONE exists. Call done and stop." });
    }

    const latest = await latestPostIds(ctx.sandboxRoot, threads);
    const fresh = Object.entries(latest).filter(([thread, id]) => id > (seen[thread] ?? 0));
    if (fresh.length > 0) {
      const waking: string[] = [];
      let team: Array<{ id: string; name?: string }> | null = null;
      for (const [thread, id] of fresh) {
        if (options.everyPost || thread !== PRIMARY_THREAD) {
          waking.push(thread);
          continue;
        }
        if (!team) {
          const names = await readNames(ctx.sandboxRoot);
          team = (await teamIds(ctx.sandboxRoot)).map((tid) => ({ id: tid, name: names.find((n) => n.id === tid)?.name }));
        }
        let forMe = false;
        for (const file of await listPostFiles(ctx.sandboxRoot, thread)) {
          const n = Number.parseInt(basename(file).slice(0, 6), 10);
          if (!(n > (seen[thread] ?? 0) && n <= id)) continue;
          const post = await readPost(file).catch(() => null);
          // A post that cannot be read is not known to be someone else's.
          if (!post || postIsFor(post.to, ctx.agentId, team)) {
            forMe = true;
            break;
          }
          passed += 1;
        }
        if (forMe) waking.push(thread);
        else seen[thread] = id;
      }
      if (waking.length > 0) {
        const note = passed > 0 ? ` ${passed} post(s) to other agents came in as well; the delivery has them.` : "";
        return withPassed({ reason: "post", waited_ms: elapsed(), detail: `New posts in: ${waking.join(", ")}. Call inbox.${note}` });
      }
    }

    // The lead register's news for this seat: its lead ready, a need that
    // will not come, its lead marked stale or taken over or reopened, the
    // operator's note, or a wake for a ready lead nobody holds (leads.ts).
    if (options.extraWake) {
      const said = await options.extraWake().catch(() => null);
      if (said) return withPassed({ reason: "lead", waited_ms: elapsed(), detail: `${said} The leads line of this delivery has the rest.` });
    }

    if (mine.size > 0) {
      const held = new Set(
        (await listClaims(ctx.sandboxRoot))
          .filter((c) => c.owner === ctx.agentId)
          .map((c) => c.path),
      );
      const lost = [...mine].filter((path) => !held.has(path));
      if (lost.length > 0) {
        return withPassed({
          reason: "claim_lost",
          waited_ms: elapsed(),
          detail: `Your lease lapsed on: ${lost.join(", ")}. Re-claim before writing.`,
        });
      }
    }

    if (Date.now() >= deadline) {
      const note = passed > 0 ? ` ${passed} post(s) to other agents came in; inbox has them.` : "";
      return withPassed({ reason: "timeout", waited_ms: elapsed(), detail: `Nothing for you in ${seconds}s.${note}` });
    }
    if (options.signal?.aborted) {
      return withPassed({ reason: "timeout", waited_ms: elapsed(), detail: "Wait aborted." });
    }
    await sleep(Math.min(pollMs, Math.max(1, deadline - Date.now())));
  }
}

/**
 * Files an agent must never rewrite that the harness itself does not rewrite
 * during a run. budget.json, traces/, locks/, inbox/ and history/ all change
 * constantly under normal operation, so watching their bytes would blame
 * whoever happened to be running a shell command at the time. threads/ is the
 * same: every post lands there. Those are covered by the claim refusal and the
 * write guard; only the shell can touch them unseen, and that is a documented
 * limit rather than something this comparison can close.
 */
// The all-dead marker is as much the harness's as the sentinel: a pane's
// shell that wrote it would end the run as a failure no one had.
const BASH_WATCH_FILES = ["SWARM.md", "team.json", "layout.json", SENTINEL_REL, ALL_DEAD_REL] as const;

/**
 * The two records a case rests on: what the agents found, and what the harness
 * saw them do. Both are append-only by construction and both grow constantly,
 * so comparing their bytes would blame whoever happened to be running a shell
 * when a peer recorded something. What can be compared is the shape of the
 * growth: a file that only ever gained bytes at its end is intact, and one
 * whose prefix changed or that got shorter was rewritten. `edit` and `write`
 * already refuse both paths; this is the shell, which no hook can intercept.
 */
// The host's spill of trace lines the collector did not take is the record
// too: a shell that rewrote it would unsay what the harness kept.
const APPEND_ONLY_WATCH = ["ledger/entries.jsonl", "traces/events.jsonl", TRACE_SPILL_REL, "leads/leads.jsonl", "questions/questions.jsonl"] as const;

/**
 * Size and full digest of an append-only record, taken before a shell call.
 * The ledger also keeps the digest of its entries' chained cores: a merge
 * (a second agent citing an entry) rewrites the file to add an author, which
 * changes its bytes and not one chained core.
 */
export type AppendOnlyMark = { size: number; sha: string; cores?: { lines: number; digest: string } };

const LEDGER_WATCH = "ledger/entries.jsonl";

/** The digest of the first `limit` entries' chained cores (all, by default), and how many it covered. */
function ledgerCoreDigest(text: string, limit = Infinity): { lines: number; digest: string } {
  const hash = createHash("sha256");
  let lines = 0;
  for (const line of text.split("\n")) {
    if (lines >= limit) break;
    if (!line.trim()) continue;
    lines += 1;
    let e: LedgerEntry;
    try {
      e = JSON.parse(line) as LedgerEntry;
    } catch {
      hash.update(`raw\u0000${line}\u0000`);
      continue;
    }
    hash.update(`${ledgerCore(e)}\u0000${e.prev ?? ""}\u0000${e.hash ?? ""}\u0000`);
  }
  return { lines, digest: hash.digest("hex") };
}

/**
 * Hash the first `bytes` of a file. Used to ask whether what a record used to
 * hold is still, byte for byte, its own opening — which is the whole question
 * for a file that is only ever appended to.
 */
async function hashOfPrefix(sandboxRoot: string, pathKey: string, bytes: number): Promise<string> {
  if (bytes <= 0) return createHash("sha256").digest("hex");
  const abs = resolve(sandboxRoot, pathKey);
  const handle = await open(abs, "r").catch(() => null);
  if (!handle) return "";
  try {
    const hash = createHash("sha256");
    const buf = Buffer.allocUnsafe(Math.min(bytes, 1 << 20));
    let read = 0;
    while (read < bytes) {
      const { bytesRead } = await handle.read(buf, 0, Math.min(buf.length, bytes - read), read);
      if (bytesRead <= 0) return "";
      hash.update(buf.subarray(0, bytesRead));
      read += bytesRead;
    }
    return hash.digest("hex");
  } finally {
    await handle.close().catch(() => {});
  }
}

/** The first `bytes` of a file as text, or null when it cannot be read. */
async function readPrefixText(sandboxRoot: string, pathKey: string, bytes: number): Promise<string | null> {
  const handle = await open(resolve(sandboxRoot, pathKey), "r").catch(() => null);
  if (!handle) return null;
  try {
    const buf = Buffer.alloc(bytes);
    let read = 0;
    while (read < bytes) {
      const { bytesRead } = await handle.read(buf, read, bytes - read, read);
      if (bytesRead <= 0) break;
      read += bytesRead;
    }
    return buf.subarray(0, read).toString("utf8");
  } finally {
    await handle.close().catch(() => {});
  }
}

/** Where each append-only record stood before the call. */
async function appendOnlyMarks(sandboxRoot: string): Promise<Map<string, AppendOnlyMark>> {
  const marks = new Map<string, AppendOnlyMark>();
  for (const pathKey of APPEND_ONLY_WATCH) {
    const info = await stat(resolve(sandboxRoot, pathKey)).catch(() => null);
    if (!info || !info.isFile()) continue;
    // The size and the digest have to describe the same bytes. This used to
    // stat for the size and then hash the whole file, and between the two the
    // collector appends: four agents logging keep this file growing, and the
    // very tool_call event for the shell about to run lands here. A digest
    // over S+delta bytes never matches the S-byte prefix hashed afterwards,
    // and run s7099 posted RECORD REWRITTEN for regipy reads that touched
    // nothing. Hash exactly the sized prefix, as the comparison does.
    const mark: AppendOnlyMark = { size: info.size, sha: await hashOfPrefix(sandboxRoot, pathKey, info.size) };
    if (pathKey === LEDGER_WATCH) {
      const text = await readPrefixText(sandboxRoot, pathKey, info.size);
      if (text !== null) mark.cores = ledgerCoreDigest(text);
    }
    marks.set(pathKey, mark);
  }
  return marks;
}

/** How many files under work/ the snapshot will hash, and how deep it walks.
 *  Plenty for an artifact directory; a run that extracts thousands of files
 *  is told once that the watch no longer covers all of them (see
 *  `WatchSnapshot.truncated`). */
export const BASH_WATCH_MAX_WORK_FILES = 500;
export const BASH_WATCH_MAX_DEPTH = 8;

export type WatchSnapshot = {
  hashes: Map<string, string>;
  /** The caps themselves, which only the operator changes mid-run (setCaps). */
  caps: string;
  /** How many operator changes budget.json recorded, and the caps the last one left. */
  capChanges?: number;
  lastCapChange?: string;
  /** Where the ledger and the trace stood: compared for growth, not equality. */
  appendOnly: Map<string, AppendOnlyMark>;
  /** True when work/ held more files, or nested deeper, than the watch covers:
   *  a shell write to a file it left out is not seen. */
  truncated: boolean;
};

export function capFingerprint(budget: BudgetRecord | null): string {
  if (!budget) return "";
  const metered = budget.metered === false ? "0" : "1";
  const perModel = JSON.stringify(Object.entries(budget.cap_per_model_usd ?? {}).sort());
  return `${budget.cap_usd}|${budget.wall_clock_minutes}|${budget.started_at}|${budget.cap_tokens ?? ""}|${metered}|${budget.cap_per_agent_usd ?? ""}|${budget.cap_per_agent_tokens ?? ""}|${perModel}`;
}

/**
 * Directories under work/ that belong to everyone and to nobody: the package
 * install area (`--allow-install` puts pip's venv there) and the panes' temp
 * directory (their TMPDIR; Pi spills a long bash output there). The watch
 * leaves them out. On run 6 the venv one agent created was 653 implicit
 * claims for that agent, seven CLAIM VIOLATION posts against the peer whose
 * pip wrote into it next, and enough files to push the watch past its
 * budget, so every agent was told the watch no longer covered work/.
 */
export const SHARED_WORK_DIRS = [".toolchain", ".tmp"] as const;

/**
 * The files under work/, or under `root` (a directory below work/) with a
 * budget of its own: a VM seat's watch walks only its own directories, so a
 * peer's extraction of thousands of files cannot use up the budget first.
 */
async function listWorkFiles(sandboxRoot: string, root = "work"): Promise<{ files: string[]; truncated: boolean }> {
  const out: string[] = [];
  let truncated = false;
  const top = root === "work";
  async function walk(dir: string, depth: number): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (top && depth === 0 && (SHARED_WORK_DIRS as readonly string[]).includes(entry.name)) continue;
        if (depth >= BASH_WATCH_MAX_DEPTH) {
          truncated = true;
          continue;
        }
        await walk(abs, depth + 1);
      } else if (entry.isFile()) {
        // The harness's own spill of trace lines the collector did not take:
        // it grows during a shell call because the harness writes it, and a
        // watch that counted it blamed the agent's command (measured: a false
        // CLAIM VIOLATION on the first microVM run).
        if (top && depth === 0 && entry.name === ".trace-spill.jsonl") continue;
        if (out.length >= BASH_WATCH_MAX_WORK_FILES) {
          truncated = true;
          return;
        }
        out.push(claimKey(sandboxRoot, abs));
      }
    }
  }
  await walk(join(sandboxRoot, root), 0);
  return { files: out, truncated };
}

/** sha256 of a file by streaming: a 25 GB disk image must not become a Buffer. */
export async function sha256File(abs: string | Buffer): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(abs)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

async function hashOf(sandboxRoot: string, pathKey: string): Promise<string> {
  try {
    return await sha256File(resolve(sandboxRoot, pathKey));
  } catch {
    return "";
  }
}

/**
 * sha256 of a watched file that is not an input, re-read only when its size,
 * mtime or ctime moved. Every shell call brackets every file under work/
 * twice, and a forensic run's extracted artefacts run to gigabytes: hashing
 * all of it on each command was the harness paying, in seconds per call, for
 * what the agents had already written. A change to the bytes moves mtime and
 * ctime, so a stale entry cannot hide a write; the map is cleared when it
 * grows past what one run can reasonably hold.
 */
const workHashCache = new Map<string, { size: number; mtimeMs: number; ctimeMs: number; sha: string }>();
const WORK_HASH_CACHE_MAX = 4000;

async function hashOfWatched(sandboxRoot: string, pathKey: string): Promise<string> {
  const abs = resolve(sandboxRoot, pathKey);
  const info = await stat(abs).catch(() => null);
  if (!info || !info.isFile()) {
    workHashCache.delete(abs);
    return "";
  }
  const hit = workHashCache.get(abs);
  if (hit && hit.size === info.size && hit.mtimeMs === info.mtimeMs && hit.ctimeMs === info.ctimeMs) return hit.sha;
  const sha = await hashOf(sandboxRoot, pathKey);
  if (sha) {
    if (workHashCache.size >= WORK_HASH_CACHE_MAX) workHashCache.clear();
    workHashCache.set(abs, { size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs, sha });
  }
  return sha;
}

/**
 * What to compare either side of a `bash` call, which no hook can intercept:
 * everything under work/ (the artifacts, claimed or not), the handful of
 * harness files above, every live claim, and the caps.
 */
/**
 * In a microVM a seat can write only its own directories: the rest of the
 * run is read-only in its VM, and whatever changes there changed through the
 * hub (a peer's publish, recorded with its author) or on the host. Watching
 * it from here only read a five-second-old view of other seats' work and
 * blamed this seat's command for it; so a VM's watch is its own directories.
 */
export function vmSeatScope(agentId: string | undefined, env: NodeJS.ProcessEnv = process.env): string[] | null {
  if (env.SWARM_ISOLATION !== "microvm" || !agentId || agentId === SYSTEM_AGENT) return null;
  return [`work/${agentId}/`, `work/extracted/${agentId}/`, `work/quarantine/${agentId}/`];
}

export async function watchedPathHashes(
  sandboxRoot: string,
  agentId?: string,
  opts: { appendOnly?: boolean } = {},
): Promise<WatchSnapshot> {
  const scope = vmSeatScope(agentId);
  if (scope) {
    const hashes = new Map<string, string>();
    let truncated = false;
    for (const dir of scope) {
      const work = await listWorkFiles(sandboxRoot, dir.replace(/\/$/, ""));
      truncated ||= work.truncated;
      for (const file of work.files) hashes.set(file, await hashOfWatched(sandboxRoot, file));
    }
    return { hashes, caps: "", appendOnly: new Map(), truncated };
  }
  const hashes = new Map<string, string>();
  const paths = new Set<string>((await listClaims(sandboxRoot)).map((c) => c.path));
  for (const file of BASH_WATCH_FILES) paths.add(file);
  const work = await listWorkFiles(sandboxRoot);
  for (const file of work.files) paths.add(file);
  // A shell write into tools/ is a tool nobody forged: watch every file there.
  for (const file of await listToolFiles(sandboxRoot)) paths.add(file);
  // Inputs can be large and never change, so they go through the manifest-
  // seeded stat cache: a file with the same size, mtime and ctime as last
  // time is not read again.
  const inputs = new Set(await listInputFiles(sandboxRoot));
  for (const file of inputs) paths.add(file);
  for (const pathKey of paths) {
    hashes.set(pathKey, inputs.has(pathKey) ? await hashOfCached(sandboxRoot, pathKey) : await hashOfWatched(sandboxRoot, pathKey));
  }
  const budgetNow = await readBudget(sandboxRoot).catch(() => null);
  return {
    hashes,
    caps: capFingerprint(budgetNow),
    capChanges: budgetNow?.cap_changes?.length ?? 0,
    lastCapChange: budgetNow?.cap_changes?.at(-1)?.caps ?? "",
    // Only the before-snapshot's marks are read: the after side checks the
    // prefix against them directly, so it skips the two full-file hashes.
    appendOnly: opts.appendOnly === false ? new Map() : await appendOnlyMarks(sandboxRoot),
    truncated: work.truncated,
  };
}

export type BashWriteReport = {
  path: string;
  /** Live claim on the path at the time of the write, if any. */
  owner: string | null;
  owner_reason: string | null;
  protected: boolean;
  /** True when the writer was allowed to write it (their own live claim). */
  legitimate: boolean;
  /** Whether a revision predating this write exists to restore. */
  recoverable: boolean;
  /** Under inputs/: the harness heals it from the pristine copy itself. */
  inputs?: boolean;
  /** An append-only record that was not appended to: it shrank, or its opening
   *  bytes changed. The ledger and the trace are the only two watched this way. */
  rewritten?: boolean;
};

/** True when the bytes on disk are the newest thing history knows about. */
/**
 * Where the write diff asks who holds a path and what its history says. On
 * the host that is these files; in a VM it is the hub, because the VM reads
 * locks/ and history/ through a share that caches attributes for 5 s, and a
 * revision recorded a moment ago would look like an unaccounted write.
 */
export type WatchLookups = {
  listClaims: (sandboxRoot: string) => Promise<LockRecord[]>;
  listFileHistory: (sandboxRoot: string, rawPath: string) => Promise<FileVersion[]>;
};

async function accountedForByHistory(sandboxRoot: string, pathKey: string, lookups: WatchLookups): Promise<boolean> {
  const versions = await lookups.listFileHistory(sandboxRoot, pathKey);
  const latest = versions.at(-1);
  if (!latest) return false;
  return (await hashOfWatched(sandboxRoot, pathKey)) === latest.sha256;
}

/**
 * Compare two snapshots and describe what a bash command changed: who wrote
 * what, whose claim it was, and that the change was snapshotted.
 *
 * Two agents share this directory, so "the bytes changed while my shell ran"
 * is not on its own proof that my shell changed them: a peer's ordinary
 * `edit` lands in the same window. Every legal write is recorded in history
 * as it happens, so a change that matches the newest revision is somebody's
 * accounted-for write and is not reported here. The residual race — a peer's
 * revision landing a few milliseconds after we look — is why the caller
 * settles before asking. It can duplicate a report, never invent one against
 * an idle agent.
 */
export async function diffWatchedPaths(
  sandboxRoot: string,
  before: WatchSnapshot,
  writer: string,
  lookups: WatchLookups = { listClaims, listFileHistory },
): Promise<BashWriteReport[]> {
  const after = await watchedPathHashes(sandboxRoot, writer, { appendOnly: false });
  const claims = new Map((await lookups.listClaims(sandboxRoot)).map((c) => [c.path, c]));
  const out: BashWriteReport[] = [];

  // An operator raising a cap while this shell ran is recorded as such
  // (setCaps): a new entry whose caps are the ones now on disk. Anything else
  // that moved the caps is the shell's.
  const byOperator = (after.capChanges ?? 0) > (before.capChanges ?? 0) && after.lastCapChange === after.caps;
  if (before.caps && after.caps && before.caps !== after.caps && !byOperator) {
    out.push({
      path: "budget.json",
      owner: null,
      owner_reason: null,
      protected: true,
      legitimate: false,
      recoverable: false,
    });
  }

  // The ledger and the trace are compared for growth, not for equality: a peer
  // recording a finding while this shell ran is normal and must not be
  // reported. A record that got shorter, or whose opening bytes are no longer
  // what they were, was rewritten rather than appended to.
  for (const [pathKey, mark] of before.appendOnly) {
    const info = await stat(resolve(sandboxRoot, pathKey)).catch(() => null);
    const size = info && info.isFile() ? info.size : 0;
    const prefix = size >= mark.size ? await hashOfPrefix(sandboxRoot, pathKey, mark.size) : "";
    if (size >= mark.size && prefix === mark.sha) continue;
    // A ledger whose earlier entries kept every chained core was merged
    // into (an author added), not rewritten.
    if (mark.cores && size > 0) {
      const text = await readPrefixText(sandboxRoot, pathKey, size);
      if (text !== null) {
        const now = ledgerCoreDigest(text, mark.cores.lines);
        if (now.lines === mark.cores.lines && now.digest === mark.cores.digest) continue;
      }
    }
    out.push({
      path: pathKey,
      owner: null,
      owner_reason: null,
      protected: true,
      legitimate: false,
      recoverable: false,
      rewritten: true,
    });
  }

  // Union of both snapshots: a path can leave the watch set mid-command when
  // its claim expires, and the write would otherwise vanish with it. A path
  // that only left the set is re-hashed rather than assumed empty, so an
  // expiring lease is not reported as a deletion.
  for (const pathKey of new Set([...before.hashes.keys(), ...after.hashes.keys()])) {
    const was = before.hashes.get(pathKey) ?? "";
    const now = after.hashes.has(pathKey)
      ? (after.hashes.get(pathKey) as string)
      : isInputsPath(pathKey)
        ? await hashOfCached(sandboxRoot, pathKey)
        : await hashOfWatched(sandboxRoot, pathKey);
    if (was === now) continue;
    if (await accountedForByHistory(sandboxRoot, pathKey, lookups)) continue;
    const claim = claims.get(pathKey);
    const isProtected = isProtectedPath(pathKey);
    const isInput = isInputsPath(pathKey);
    const versions = isInput ? [] : await lookups.listFileHistory(sandboxRoot, pathKey);
    out.push({
      path: pathKey,
      owner: claim?.owner ?? null,
      owner_reason: claim?.reason ?? null,
      protected: isProtected,
      legitimate: !isProtected && claim?.owner === writer,
      recoverable: isInput || versions.length > 0,
      ...(isInput ? { inputs: true } : {}),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Forged tools: an agent writes a tool, the swarm uses it.
//
// A goal can need something no built-in tool does — a parser for one file
// type, a checker for one invariant. The agent writes the script once with
// `make_tool`; it lands under tools/<name>/ with a manifest that says what it
// takes, who wrote it and what its bytes hash to; every agent's harness
// registers it as a real tool on its next wake-up. The runner is a plain
// subprocess in the sandbox — a forged tool is a `bash` with a schema and a
// name on it, and it lives under the same containment as bash does.
// ---------------------------------------------------------------------------

export const TOOLS_DIR = "tools";
export const TOOL_MANIFEST = "manifest.json";
/** Short, lower-case, a verb-ish thing: the LLM has to spell it back. */
export const TOOL_NAME_RE = /^[a-z][a-z0-9_]{2,31}$/;
export const TOOL_RUNTIMES = ["python3", "node", "bash"] as const;
export type ToolRuntime = (typeof TOOL_RUNTIMES)[number];
export const TOOL_PARAM_TYPES = ["string", "number", "integer", "boolean", "array", "object"] as const;
export type ToolParamType = (typeof TOOL_PARAM_TYPES)[number];
export const TOOL_SCRIPT_MAX_BYTES = 64 * 1024;
/**
 * How much of a forged tool's stdout the model receives in the call. Not a
 * cap on the tool: past this the whole stream goes to a file under
 * tool-output/ and the result names it, with its size and hash. The tool
 * used to be killed here and the rest of its output dropped unrecorded.
 */
export const TOOL_OUTPUT_MAX_BYTES = 64 * 1024;
/** Where the harness keeps the whole output of a call whose result reached the model as a prefix. */
export const TOOL_OUTPUT_REL = "tool-output";

/** A whole output kept on disk, as the trace and the model's result name it. */
export type FullOutputRef = {
  /** Sandbox-relative path under tool-output/. */
  path: string;
  bytes: number;
  lines: number;
  sha256: string;
  /** Set when the file could not be written whole; the prefix the model saw is still on the trace. */
  write_error?: string;
};

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** A file name for one call's whole output: sortable by time, unique enough for a pane. */
export function toolOutputRel(agentId: string | undefined, tool: string, stream: "out" | "err" | "text"): string {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 17);
  const who = agentId && /^[a-z][a-z0-9_-]{0,31}$/.test(agentId) ? agentId : "unknown";
  const what = tool.replace(/[^a-z0-9_-]/gi, "_").slice(0, 40) || "tool";
  const salt = Math.random().toString(36).slice(2, 6);
  return `${TOOL_OUTPUT_REL}/${who}/${stamp}-${what}-${salt}.${stream}.log`;
}

/** How many `\n` bytes a buffer holds. */
function countNewlines(buf: Buffer): number {
  let n = 0;
  for (let at = buf.indexOf(10); at !== -1; at = buf.indexOf(10, at + 1)) n += 1;
  return n;
}

/**
 * Keep a text whole under tool-output/ and describe it. For a result that
 * already exists in memory (Pi's own bash spill, a page's text); a forged
 * tool streams through `StreamCapture` instead so nothing is ever held whole.
 */
export async function keepToolOutput(sandboxRoot: string, rel: string, data: Buffer | string): Promise<FullOutputRef> {
  const buffer = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const lines = countNewlines(buffer);
  const ref: FullOutputRef = { path: rel, bytes: buffer.length, lines, sha256: createHash("sha256").update(buffer).digest("hex") };
  try {
    await mkdir(dirname(join(sandboxRoot, rel)), { recursive: true });
    await writeFile(join(sandboxRoot, rel), buffer);
  } catch (error) {
    ref.write_error = error instanceof Error ? error.message : String(error);
  }
  return ref;
}

/**
 * Move a whole output Pi spilled to the host's temp directory (its bash
 * tool past 50 KB) into the sandbox, streamed: the file is the record and
 * may be far larger than memory should hold.
 */
export async function keepToolOutputFromFile(sandboxRoot: string, rel: string, source: string): Promise<FullOutputRef> {
  const hash = createHash("sha256");
  let bytes = 0;
  let lines = 0;
  const target = join(sandboxRoot, rel);
  await mkdir(dirname(target), { recursive: true });
  const out = await open(target, "w");
  try {
    for await (const chunk of createReadStream(source)) {
      const buffer = chunk as Buffer;
      hash.update(buffer);
      bytes += buffer.length;
      lines += countNewlines(buffer);
      await out.write(buffer);
    }
  } finally {
    await out.close();
  }
  return { path: rel, bytes, lines, sha256: hash.digest("hex") };
}

/** The line a prefix result ends with, so the model knows what it has and where the rest is. */
export function fullOutputTrailer(shownLines: number, shownBytes: number, ref: FullOutputRef, note = "Full output"): string {
  const where = ref.write_error ? `${ref.path} could not be written (${ref.write_error})` : ref.path;
  return `[Showing the first ${shownLines} of ${ref.lines} lines (${fmtBytes(shownBytes)} of ${fmtBytes(ref.bytes)}). ${note}: ${where}]`;
}
export const TOOL_TIMEOUT_DEFAULT_SECONDS = 30;
export const TOOL_TIMEOUT_MAX_SECONDS = 120;
/**
 * The ceiling for a pack's tool, sealed and reviewed with its pack: a super
 * timeline or a memory carve asks for up to an hour. Every run clamped them to
 * the forged-tool ceiling of 120 s while telling the model the manifest's
 * figure, so timeline_super (3600 s) and mem_carve (900 s) died at 120 s.
 */
export const PACK_TOOL_TIMEOUT_MAX_SECONDS = 3600;

/** The timeout a tool's run is actually given: its manifest's, within its ceiling. */
export function toolTimeoutSeconds(manifest: Pick<ForgedToolManifest, "timeout_seconds" | "pack">): number {
  const ceiling = manifest.pack ? PACK_TOOL_TIMEOUT_MAX_SECONDS : TOOL_TIMEOUT_MAX_SECONDS;
  return Math.min(ceiling, Math.max(1, Number(manifest.timeout_seconds) || TOOL_TIMEOUT_DEFAULT_SECONDS));
}
export const TOOL_DESCRIPTION_MAX_CHARS = 400;
export const TOOL_MAX_PARAMS = 16;
export const TOOL_HASH_RE = /^[0-9a-f]{64}$/;

/** A manifest sha256 is a full SHA-256 hex digest, never empty and never a stub. */
export function isToolHash(value: string): boolean {
  return TOOL_HASH_RE.test(value);
}
/** Names the harness and Pi already use; a forged tool cannot shadow them. */
export const TOOL_RESERVED_NAMES = new Set([
  "read", "bash", "edit", "write", "grep", "find", "ls", "powershell",
  "post", "inbox", "wait", "claim_file", "release_file", "claims", "list_team", "budget",
  "file_history", "file_restore", "file_diff", "thread_open", "thread_join", "done",
  "playwright", "browser_check", "make_tool", "tools", "system", "inputs", "name", "record", "ledger",
  "attest", "dispute",
  // the harness's own trace events: a forged tool with one of these names
  // would land its calls under the same name and be counted as the event
  "agent_start", "agent_stop", "thinking", "claim_violation", "inputs_guard", "inputs_violation",
  "inputs_check", "cap_steer", "wall_steer", "harness_stop", "reap", "reaped", "tool_loaded",
  "forge_hint", "sentinel_nudge", "idle_nudge", "agent_cap_steer", "agent_cap_stop",
  "extension_error", "watch_truncated", "agent_error", "toolchain",
  // self-compaction: the tool, the per-turn context row and the hand-off events
  "self_compact", "context", "compact_notice", "compact_warning", "compact_forced", "compact_hold",
  "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled", "compact_config", "compact_held",
  // microVM runs: the tool that writes a shared file, the hub's own lines,
  // and what an agent's extension says about the hub (tests/reserved-names)
  "publish_file", "publish_needed", "skill", "finish_line", "hub_call", "hub_link", "hub_prompt",
  "hub_lost", "hub_lost_stop", "hub_restarted", "hub_clear_up", "vm_finish", "custody", "record_violation",
  // The keeper restarting the collector, an operator's own command or
  // console action, and the console opening an artifact with its scripts.
  "collector_restarted", "operator_action", "artifact_scripts",
  // A long command run again pointed at its kept output, a seat stopped
  // before a model call, a ledger correction, the operator's --notify hook,
  // the hub's history quota and a connection refused its seat token.
  "repeat_hint", "job_hint", "budget_precall_stop", "ledger_superseded", "notify", "history_quota", "seat_auth",
  // Tool jobs in worker VMs and the catalogue they grow (scripts/job-service.ts).
  "job_run", "job_status", "catalog_request",
  // The host-side model gateway (scripts/model-gateway.ts).
  "model_gateway_started", "model_gateway_refused", "model_gateway_upstream_error", "model_gateway_restarted",
  // A budget fold refused over an unreadable budget.json, and what a
  // collector restarted over a torn or mismatched trace records.
  "budget_unreadable", "trace_anchor_mismatch", "trace_fragment_cut",
  // The lead register (extensions/leads.ts): its tools, what a record opened
  // and interpreted, the watchdog's regroup in an until-solved run, and the
  // operator's answer to a lead.
  "lead_open", "lead_claim", "lead_release", "lead_close", "lead_link", "leads", "record_leads", "regroup", "operator_note",
  // The question register (extensions/questions.ts): its tools.
  "question_open", "questions", "question_ask",
  // The coordination of the work and of the finish (docs/adr/0015): a lead
  // reopened by an agent, a limiting route reviewed.
  "lead_reopen", "route_review", "lead_handoff", "lead_confirm", "offer", "finish", "done_deferred",
  // The runtime (docs/adr/0015): the seats' tokens renewed on the host.
  "secrets_renewed",
  // The stop policy (docs/adr/0013): a run paused at a cap, a seat's call held
  // by the pause, the seats woken after an extension, a stop proposed to the
  // operator, and a run resumed after a stop or a seal.
  "run_paused", "pause_hold", "resume_wake", "stop_proposed", "run_resumed",
  // The operator requests' outbox (extensions/requests.ts, docs/adr/0014): a request handed to the operator's notification targets.
  "request_notified",
  // The dynamic network (scripts/net-broker.ts, scripts/net-fetch.ts): its
  // tools, and the fetch service's own lines and its keeper's restart.
  "net_request", "net_fetch", "network", "net_fetch_started", "net_fetch_refused", "net_fetch_restarted",
]);

const RUNTIME_EXT: Record<ToolRuntime, string> = { python3: "py", node: "mjs", bash: "sh" };

export type ForgedParam = {
  type: ToolParamType;
  description?: string;
  required?: boolean;
  enum?: string[];
};

export type ForgedToolManifest = {
  name: string;
  description: string;
  params: Record<string, ForgedParam>;
  runtime: ToolRuntime;
  entry: string;
  timeout_seconds: number;
  /** One example call, as the author would write it; shown to peers. */
  example?: string;
  by: string;
  at: string;
  version: number;
  sha256: string;
  /** The pack this tool was seeded from, when a run carried one. Absent for a
   *  tool an agent forged during the run. */
  pack?: string;
  /** Programs the script calls, as its author named them: what a later case
   *  (or `tools --save` into a library) needs its image to hold. */
  requires?: string[];
  /**
   * Python modules the script imports only when it is called, under a try
   * that catches ImportError, because only some images carry them (Pillow,
   * pytsk3, pyewf): the tool says one is missing rather than failing on an
   * import line. The library's check (tests/recipe.test.sh) holds every
   * other import to images/library-python.txt and these to their guard.
   */
  optional_python?: string[];
  /** The image the tool was forged against, by digest, in a VM run. */
  image_digest?: string;
  /**
   * What the tool reads, for the hint at a job's admission (scripts/library-hint.ts,
   * docs/adr/0016): extensions, magic bytes at an offset (hex), and file names
   * (`*` for any run of characters). Matched, never enforced.
   */
  use?: { extensions?: string[]; magic?: Array<{ offset: number; hex: string }>; names?: string[] };
};

export type ForgeToolSpec = {
  name: string;
  description: string;
  params?: Record<string, ForgedParam>;
  runtime: ToolRuntime;
  script: string;
  timeout_seconds?: number;
  example?: string;
  requires?: string[];
};

export type ForgeResult =
  | { ok: true; manifest: ForgedToolManifest; created: boolean }
  | { ok: false; reason: string };

/** What make_tool refuses before anything touches disk, with the reason spelled out. */
/**
 * Why a name is taken, in one sentence, for the names an agent is most likely
 * to reach for. Challenge 8 spent six refusals and a forged look-alike on
 * `inputs_check` because the refusal said only "pick another name", and the
 * goal's own checks look for that event: five agents read it as a tool they
 * had to supply. A refusal that says who writes the name ends the guessing.
 */
const RESERVED_NAME_REASON: Record<string, string> = {
  inputs_check: "the harness writes it when `done` verifies the inputs on the way out; you do not have to do anything for it",
  inputs_guard: "the harness writes it when it sets up the read-only guard",
  inputs_violation: "the harness writes it when something changes `inputs/`",
  claim_violation: "the harness writes it when a write lands on a file a peer holds",
  file_history: "the harness writes it when it snapshots a change",
  forge_hint: "the harness writes it when you repeat a command a tool could carry",
  job_hint: "the harness writes it when a long shell command read the evidence where a job would have sealed its output",
  idle_nudge: "the harness writes it when it prompts an agent that stopped",
  sentinel_nudge: "the harness writes it when it tells the swarm the sentinel is up",
  agent_cap_steer: "the harness writes it when an agent passes its own spend cap, or its model's",
  extension_error: "the harness writes it when its own code fails",
  agent_error: "the harness writes it when an agent's turn ends in a provider error",
  context: "the harness writes it at every turn end: how full this agent's context is",
  compact_done: "the harness writes it when a compaction lands; `self_compact` is the tool that asks for one",
  self_compact: "a built-in tool: call `self_compact` with a note_to_self to compact your own context",
  record: "a built-in tool: call `record` to put a fact in the ledger",
  ledger: "a built-in tool: call `ledger` to read the ledger back",
  name: "a built-in tool: call `name` to say what to call you and what you are doing",
  inputs: "a built-in tool: call `inputs` to list the evidence",
  tools: "a built-in tool: call `tools` to see what peers have forged",
  done: "a built-in tool: call `done` to end your part",
};

export function validateToolSpec(spec: unknown): { ok: true; spec: ForgeToolSpec } | { ok: false; reason: string } {
  if (!isRecord(spec)) return { ok: false, reason: "spec must be an object" };
  const name = typeof spec.name === "string" ? spec.name.trim() : "";
  if (!TOOL_NAME_RE.test(name)) return { ok: false, reason: `name must match ${TOOL_NAME_RE} (got "${name}")` };
  if (TOOL_RESERVED_NAMES.has(name)) {
    const why = RESERVED_NAME_REASON[name];
    return {
      ok: false,
      reason: why
        ? `"${name}" is taken: ${why}. Nothing needs forging under that name; pick another if your tool does something else.`
        : `"${name}" is a harness or Pi tool; pick another name`,
    };
  }
  const description = typeof spec.description === "string" ? spec.description.trim() : "";
  if (!description) return { ok: false, reason: "description is required: peers pick tools by it" };
  if (description.length > TOOL_DESCRIPTION_MAX_CHARS) return { ok: false, reason: `description is longer than ${TOOL_DESCRIPTION_MAX_CHARS} chars` };
  const runtime = spec.runtime;
  if (typeof runtime !== "string" || !(TOOL_RUNTIMES as readonly string[]).includes(runtime)) {
    return { ok: false, reason: `runtime must be one of ${TOOL_RUNTIMES.join(", ")}` };
  }
  const script = typeof spec.script === "string" ? spec.script : "";
  if (!script.trim()) return { ok: false, reason: "script is empty" };
  if (Buffer.byteLength(script, "utf8") > TOOL_SCRIPT_MAX_BYTES) return { ok: false, reason: `script is over ${TOOL_SCRIPT_MAX_BYTES} bytes` };
  const params: Record<string, ForgedParam> = {};
  if (spec.params !== undefined) {
    if (!isRecord(spec.params)) return { ok: false, reason: "params must be an object of {name: {type, description, required, enum}}" };
    const entries = Object.entries(spec.params);
    if (entries.length > TOOL_MAX_PARAMS) return { ok: false, reason: `at most ${TOOL_MAX_PARAMS} params` };
    for (const [key, raw] of entries) {
      if (!TOOL_NAME_RE.test(key)) return { ok: false, reason: `param "${key}" must match ${TOOL_NAME_RE}` };
      if (!isRecord(raw)) return { ok: false, reason: `param "${key}" must be an object` };
      const type = raw.type;
      if (typeof type !== "string" || !(TOOL_PARAM_TYPES as readonly string[]).includes(type)) {
        return { ok: false, reason: `param "${key}": type must be one of ${TOOL_PARAM_TYPES.join(", ")}` };
      }
      const param: ForgedParam = { type: type as ToolParamType };
      if (raw.description !== undefined) {
        if (typeof raw.description !== "string") return { ok: false, reason: `param "${key}": description must be a string` };
        // Refused, not cut: a description the model reads is part of the
        // tool's record, and a silent cut is a description nobody wrote.
        if (raw.description.length > TOOL_DESCRIPTION_MAX_CHARS) return { ok: false, reason: `param "${key}": description is longer than ${TOOL_DESCRIPTION_MAX_CHARS} chars` };
        param.description = raw.description;
      }
      if (raw.required !== undefined) {
        if (typeof raw.required !== "boolean") return { ok: false, reason: `param "${key}": required must be a boolean` };
        param.required = raw.required;
      }
      if (raw.enum !== undefined) {
        if (!Array.isArray(raw.enum) || raw.enum.length === 0 || raw.enum.length > 64 || !raw.enum.every((v) => typeof v === "string")) {
          return { ok: false, reason: `param "${key}": enum must be a non-empty list of strings` };
        }
        if (type !== "string") return { ok: false, reason: `param "${key}": enum is only for string params` };
        param.enum = raw.enum as string[];
      }
      params[key] = param;
    }
  }
  let timeout = TOOL_TIMEOUT_DEFAULT_SECONDS;
  if (spec.timeout_seconds !== undefined) {
    const t = Number(spec.timeout_seconds);
    if (!Number.isFinite(t) || t < 1) return { ok: false, reason: "timeout_seconds must be at least 1" };
    timeout = Math.min(TOOL_TIMEOUT_MAX_SECONDS, Math.floor(t));
  }
  const example = typeof spec.example === "string" && spec.example.trim() ? spec.example.trim() : undefined;
  if (example && example.length > TOOL_DESCRIPTION_MAX_CHARS) return { ok: false, reason: `example is longer than ${TOOL_DESCRIPTION_MAX_CHARS} chars` };
  let requires: string[] | undefined;
  if (spec.requires !== undefined) {
    if (!Array.isArray(spec.requires) || spec.requires.length > 32 || !spec.requires.every((r) => typeof r === "string" && /^[A-Za-z0-9._+-]{1,64}$/.test(r))) {
      return { ok: false, reason: "requires must be a list of program names (at most 32)" };
    }
    requires = [...new Set(spec.requires as string[])];
  }
  return { ok: true, spec: { name, description, params, runtime: runtime as ToolRuntime, script, timeout_seconds: timeout, ...(example ? { example } : {}), ...(requires?.length ? { requires } : {}) } };
}

export function toolDir(sandboxRoot: string, name: string): string {
  return join(sandboxRoot, TOOLS_DIR, name);
}

/** A tool's entry is a plain file name in its own directory, never a path. */
const TOOL_ENTRY_RE = /^[a-z0-9_][a-z0-9_.-]{0,63}$/i;

function parseManifest(raw: string): ForgedToolManifest | null {
  try {
    const m = JSON.parse(raw) as Partial<ForgedToolManifest>;
    if (!m || typeof m.name !== "string" || !TOOL_NAME_RE.test(m.name)) return null;
    if (typeof m.description !== "string" || typeof m.entry !== "string" || typeof m.by !== "string") return null;
    if (!TOOL_ENTRY_RE.test(m.entry)) return null;
    if (typeof m.runtime !== "string" || !(TOOL_RUNTIMES as readonly string[]).includes(m.runtime)) return null;
    if (typeof m.sha256 !== "string" || !isToolHash(m.sha256)) return null;
    return {
      name: m.name,
      description: m.description,
      params: isRecord(m.params) ? (m.params as Record<string, ForgedParam>) : {},
      runtime: m.runtime as ToolRuntime,
      entry: m.entry,
      timeout_seconds: Number(m.timeout_seconds) || TOOL_TIMEOUT_DEFAULT_SECONDS,
      ...(typeof m.example === "string" ? { example: m.example } : {}),
      by: m.by,
      at: typeof m.at === "string" ? m.at : "",
      version: Number(m.version) || 1,
      sha256: m.sha256,
      ...(typeof m.pack === "string" && m.pack ? { pack: m.pack } : {}),
      ...(Array.isArray(m.requires) && m.requires.every((r: unknown) => typeof r === "string") ? { requires: m.requires as string[] } : {}),
      ...(Array.isArray(m.optional_python) && m.optional_python.every((r: unknown) => typeof r === "string") ? { optional_python: m.optional_python as string[] } : {}),
      ...(typeof m.image_digest === "string" && m.image_digest ? { image_digest: m.image_digest } : {}),
    };
  } catch {
    return null;
  }
}

/**
 * Where a tool's entry really is, or null when it is missing, is a link, or
 * resolves outside the tool's own directory. The runner and the console's
 * read route both go through this: a manifest a shell rewrote, or a link
 * planted next to it, must not turn either into a way to read or run a file
 * elsewhere. A tool's entry is a plain file the harness wrote, so a symlink
 * is refused rather than followed and then checked.
 */
async function resolveToolEntry(
  sandboxRoot: string,
  manifest: ForgedToolManifest,
): Promise<{ real: string } | { real: null; why: "missing" | "outside" }> {
  const dir = toolDir(sandboxRoot, manifest.name);
  const entryAbs = resolve(dir, manifest.entry);
  const info = await lstat(entryAbs).catch(() => null);
  if (!info) return { real: null, why: "missing" };
  if (info.isSymbolicLink()) return { real: null, why: "outside" };
  if (!info.isFile()) return { real: null, why: "missing" };
  const real = await realpath(entryAbs).catch(() => null);
  if (!real) return { real: null, why: "missing" };
  const realDir = await realpath(dir).catch(() => dir);
  return real.startsWith(`${realDir}${sep}`) ? { real } : { real: null, why: "outside" };
}

export async function readForgedTool(sandboxRoot: string, name: string): Promise<{ manifest: ForgedToolManifest; script: string } | null> {
  if (!TOOL_NAME_RE.test(name) || TOOL_RESERVED_NAMES.has(name)) return null;
  const dir = toolDir(sandboxRoot, name);
  const manifestAbs = join(dir, TOOL_MANIFEST);
  const manStat = await lstat(manifestAbs).catch(() => null);
  if (!manStat || manStat.isSymbolicLink() || !manStat.isFile()) return null;
  const manifest = parseManifest(await readFile(manifestAbs, "utf8").catch(() => ""));
  if (!manifest) return null;
  const entry = await resolveToolEntry(sandboxRoot, manifest);
  if (entry.real === null) return null;
  const script = await readFile(entry.real, "utf8").catch(() => null);
  if (script === null) return null;
  return { manifest, script };
}

/** Every tool on disk with a readable manifest, oldest first. */
export async function listForgedTools(sandboxRoot: string): Promise<ForgedToolManifest[]> {
  const entries = await readdir(join(sandboxRoot, TOOLS_DIR), { withFileTypes: true }).catch(() => []);
  const out: ForgedToolManifest[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !TOOL_NAME_RE.test(entry.name) || TOOL_RESERVED_NAMES.has(entry.name)) continue;
    const manifest = parseManifest(await readFile(join(sandboxRoot, TOOLS_DIR, entry.name, TOOL_MANIFEST), "utf8").catch(() => ""));
    if (manifest && manifest.name === entry.name) out.push(manifest);
  }
  return out.sort((a, b) => a.at.localeCompare(b.at) || a.name.localeCompare(b.name));
}

/**
 * Record the current bytes of every forged tool that has no history yet, so
 * `--tools-from` seeds get a harness-owned hash the same way make_tool does.
 */
export async function sealForgedTools(sandboxRoot: string, agentId = "harness"): Promise<number> {
  let n = 0;
  for (const manifest of await listForgedTools(sandboxRoot)) {
    const manifestPath = `${TOOLS_DIR}/${manifest.name}/${TOOL_MANIFEST}`;
    const versions = await listFileHistory(sandboxRoot, manifestPath);
    if (versions.length) continue;
    await recordFileVersion(sandboxRoot, `${TOOLS_DIR}/${manifest.name}/${manifest.entry}`, agentId).catch(() => null);
    await recordFileVersion(sandboxRoot, manifestPath, agentId).catch(() => null);
    n += 1;
  }
  return n;
}

/**
 * A tools/<name>/… path that appeared during this call, written by another
 * agent's make_tool. A rewrite of a tool that already existed is not a peer
 * forge: post-write agreement between script and manifest is cheap to fake.
 */
export async function isPeerForgedTool(
  cwd: string,
  pathKey: string,
  agentId: string,
  before?: WatchSnapshot,
): Promise<boolean> {
  const parts = pathKey.split("/");
  if (parts[0] !== TOOLS_DIR || parts.length < 3) return false;
  if (TOOL_RESERVED_NAMES.has(parts[1])) return false;
  // No snapshot, or the path was already there: this is not a new peer forge.
  if (!before || before.hashes.has(pathKey)) return false;
  const tool = await readForgedTool(cwd, parts[1]).catch(() => null);
  if (!tool || tool.manifest.by === agentId) return false;
  if (!isToolHash(tool.manifest.sha256)) return false;
  return createHash("sha256").update(tool.script).digest("hex") === tool.manifest.sha256;
}

/** The files under tools/, for the bash-write watch. */
export async function listToolFiles(sandboxRoot: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(join(sandboxRoot, TOOLS_DIR), { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const files = await readdir(join(sandboxRoot, TOOLS_DIR, entry.name), { withFileTypes: true }).catch(() => []);
    for (const file of files) {
      if (file.isFile()) out.push(`${TOOLS_DIR}/${entry.name}/${file.name}`);
    }
  }
  return out;
}

/**
 * Write a tool. Creating is an exclusive mkdir, so two agents forging the
 * same name at once cannot both win. Replacing is allowed to the author, or
 * to anyone once the author has stopped — a tool must not become a dead
 * agent's monument, and a live author's work must not be rewritten under
 * them by a peer who disagrees. Each version is a revision in file history.
 */
/** Words that say nothing about what a tool does, so they cannot make two alike. */
const TOOL_STOPWORDS = new Set([
  "a", "an", "the", "and", "or", "of", "for", "from", "into", "to", "in", "on", "with", "by",
  "run", "runs", "return", "returns", "get", "gets", "list", "lists", "tool", "file", "files",
  "output", "input", "given", "each", "all", "this", "that", "it", "its", "as", "at", "is", "be",
]);

/** Crude stemming, so "print", "prints" and "printing" are one word. */
function stem(word: string): string {
  if (word.length > 5 && word.endsWith("ing")) return word.slice(0, -3);
  if (word.length > 4 && word.endsWith("ed")) return word.slice(0, -2);
  if (word.length > 4 && word.endsWith("es")) return word.slice(0, -2);
  if (word.length > 3 && word.endsWith("s")) return word.slice(0, -1);
  return word;
}

function meaningfulWords(text: string): Set<string> {
  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .split(" ")
    .filter((w) => w.length > 2 && !TOOL_STOPWORDS.has(w))
    .map(stem);
  return new Set(words);
}

function overlap(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0;
  let shared = 0;
  for (const w of a) if (b.has(w)) shared += 1;
  return shared / Math.min(a.size, b.size);
}

/**
 * A tool that already does this, under another name. Two agents reaching for
 * the same capability seconds apart is the common case — the board
 * announcement arrives after both are in flight — so the check is on what the
 * tool is, not on what it is called: the same runtime, overlapping parameter
 * names, and a description made of the same words.
 */
export function findNearDuplicate(
  spec: { name: string; description: string; runtime: string; params?: Record<string, unknown> },
  existing: ReadonlyArray<ForgedToolManifest>,
): ForgedToolManifest | undefined {
  const words = meaningfulWords(`${spec.name} ${spec.description}`);
  const params = new Set(Object.keys(spec.params ?? {}));
  for (const other of existing) {
    if (other.name === spec.name) continue;
    if (other.runtime !== spec.runtime) continue;
    const theirWords = meaningfulWords(`${other.name} ${other.description}`);
    const theirParams = new Set(Object.keys(other.params ?? {}));
    const sameIdea = overlap(words, theirWords) >= 0.6;
    const sameShape = params.size === 0 && theirParams.size === 0 ? true : overlap(params, theirParams) >= 0.5;
    if (sameIdea && sameShape) return other;
  }
  return undefined;
}

export async function forgeTool(ctx: SwarmContext, rawSpec: unknown): Promise<ForgeResult> {
  const checked = validateToolSpec(rawSpec);
  if (!checked.ok) return { ok: false, reason: checked.reason };
  const spec = checked.spec;
  if (!ctx.agentId || ctx.agentId === SYSTEM_AGENT) return { ok: false, reason: "AGENT_ID unset" };
  if (await swarmDoneExists(ctx.sandboxRoot)) return { ok: false, reason: "done/SWARM_DONE exists: the swarm is over" };
  const dir = toolDir(ctx.sandboxRoot, spec.name);
  // Before anything is written: is this the tool a peer forged a minute ago
  // under a different name? Say whose it is and let the agent call it.
  const twin = findNearDuplicate(spec, await listForgedTools(ctx.sandboxRoot).catch(() => []));
  if (twin) {
    return {
      ok: false,
      reason: `"${twin.name}" already does this — forged by ${twin.by}${twin.example ? `, e.g. ${twin.example}` : ""}. Call it, or forge something that is genuinely different and say on the board how it differs.`,
    };
  }
  await mkdir(join(ctx.sandboxRoot, TOOLS_DIR), { recursive: true });
  let created = true;
  let version = 1;
  try {
    await mkdir(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    created = false;
    const existing = parseManifest(await readFile(join(dir, TOOL_MANIFEST), "utf8").catch(() => ""));
    if (!existing) {
      // The directory is there but its manifest is not: someone else won the
      // mkdir a moment ago and is still writing. Two writers of one tool is
      // exactly what the exclusive create is for, so the loser is refused.
      return { ok: false, reason: `"${spec.name}" is being forged by a peer right now; wait for the announcement or pick another name` };
    }
    {
      if (existing.by !== ctx.agentId) {
        const marker = await readAgentMarker(ctx.sandboxRoot, existing.by);
        if (marker !== "done" && marker !== "dead") {
          return { ok: false, reason: `"${spec.name}" was forged by ${existing.by}, who is still active. Ask them on the board, or forge it under another name.` };
        }
      }
      version = existing.version + 1;
    }
  }
  const entry = `run.${RUNTIME_EXT[spec.runtime]}`;
  const sha256 = createHash("sha256").update(spec.script).digest("hex");
  const manifest: ForgedToolManifest = {
    name: spec.name,
    description: spec.description,
    params: spec.params ?? {},
    runtime: spec.runtime,
    entry,
    timeout_seconds: spec.timeout_seconds ?? TOOL_TIMEOUT_DEFAULT_SECONDS,
    ...(spec.example ? { example: spec.example } : {}),
    ...(spec.requires?.length ? { requires: spec.requires } : {}),
    // In a VM run the hub forges on the host and knows the run's image.
    ...(process.env.SWARM_VM_IMAGE_DIGEST ? { image_digest: process.env.SWARM_VM_IMAGE_DIGEST } : {}),
    by: ctx.agentId,
    at: new Date().toISOString(),
    version,
    sha256,
  };
  // Script first, manifest last: a manifest is the promise that its entry runs.
  const nonce = `${process.pid}.${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 8)}`;
  const scriptTmp = join(dir, `.${entry}.${nonce}.tmp`);
  await writeFile(scriptTmp, spec.script, { encoding: "utf8", mode: 0o644 });
  await rename(scriptTmp, join(dir, entry));
  const manifestTmp = join(dir, `.${TOOL_MANIFEST}.${nonce}.tmp`);
  await writeFile(manifestTmp, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await rename(manifestTmp, join(dir, TOOL_MANIFEST));
  try {
    await recordFileVersion(ctx.sandboxRoot, `${TOOLS_DIR}/${spec.name}/${entry}`, ctx.agentId);
    await recordFileVersion(ctx.sandboxRoot, `${TOOLS_DIR}/${spec.name}/${TOOL_MANIFEST}`, ctx.agentId);
  } catch {
    // history is observability, not the tool — but runForgedTool prefers it
    // when present, so a rewrite of script+manifest cannot stay in agreement.
  }
  return { ok: true, manifest, created };
}

export type ForgedRunResult = {
  ok: boolean;
  exit_code: number | null;
  signal: string | null;
  /** What the model receives: the whole stream when it fit, else its first lines and a trailer naming the file. */
  stdout: string;
  stderr: string;
  duration_ms: number;
  timed_out: boolean;
  /** True when stdout or stderr reached the model as a prefix; the whole stream is under tool-output/. */
  truncated: boolean;
  full_output?: FullOutputRef;
  full_stderr?: FullOutputRef;
};

/**
 * One stream of a child, captured whole. The first `max` bytes stay in
 * memory for the model; from the first byte past them, everything held so
 * far and everything that follows goes to a file under tool-output/, so
 * nothing the tool printed is ever dropped and the tool is never killed for
 * printing. Peak memory stays at `max`. The class it replaces dropped every
 * byte past the bound and killed the child, and on a forensic run a parser
 * that emits a large CSV is the normal case, not the failure.
 */
export class StreamCapture {
  readonly max: number;
  /** Absolute path of the spill file. */
  readonly file: string;
  /** Sandbox-relative path of the spill file, as the record names it. */
  readonly rel: string;
  private readonly parts: Buffer[] = [];
  private held = 0;
  private fd: number | undefined;
  private spilled = false;
  private readonly hash = createHash("sha256");
  bytes = 0;
  lines = 0;
  write_error?: string;
  constructor(max: number, sandboxRoot: string, rel: string) {
    this.max = max;
    this.rel = rel;
    this.file = join(sandboxRoot, rel);
  }
  push(chunk: Buffer): void {
    this.hash.update(chunk);
    this.bytes += chunk.length;
    this.lines += countNewlines(chunk);
    const room = this.max - this.held;
    if (!this.spilled) {
      if (chunk.length <= room) {
        this.parts.push(chunk);
        this.held += chunk.length;
        return;
      }
      this.spilled = true;
      this.write(() => {
        mkdirSync(dirname(this.file), { recursive: true });
        this.fd = openSync(this.file, "w");
        for (const part of this.parts) writeSync(this.fd, part);
      });
      if (room > 0) {
        this.parts.push(chunk.subarray(0, room));
        this.held += room;
      }
    }
    this.write(() => {
      if (this.fd !== undefined) writeSync(this.fd, chunk);
    });
  }
  private write(fn: () => void): void {
    if (this.write_error) return;
    try {
      fn();
    } catch (error) {
      this.write_error = error instanceof Error ? error.message : String(error);
    }
  }
  /** Close the spill file and describe it; undefined when the stream fit and no file was written. */
  close(): FullOutputRef | undefined {
    if (this.fd !== undefined) {
      try {
        closeSync(this.fd);
      } catch {
        // nothing to do: the bytes that reached the file are there
      }
      this.fd = undefined;
    }
    if (!this.spilled) return undefined;
    const ref: FullOutputRef = { path: this.rel, bytes: this.bytes, lines: this.lines, sha256: this.hash.digest("hex") };
    if (this.write_error) ref.write_error = this.write_error;
    return ref;
  }
  /** What the model receives. `ref` is the closed stream's reference when it spilled. */
  text(ref?: FullOutputRef): string {
    const all = Buffer.concat(this.parts, this.held);
    if (!ref) return all.toString("utf8");
    // Whole lines only, like Pi's own bash tool; a stream with no line break
    // in its first `max` bytes is shown as it is.
    const cut = all.lastIndexOf(10);
    const shown = cut > 0 ? all.subarray(0, cut) : all;
    let shownLines = countNewlines(shown);
    if (cut > 0) shownLines += 1;
    return `${shown.toString("utf8")}\n\n${fullOutputTrailer(shownLines, shown.length, ref)}`;
  }
}

const FORGED_ENV_KEEP = new Set([
  "PATH",
  "HOME",
  "USER",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TMPDIR",
  "TMP",
  "TEMP",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "ALL_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
  "all_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
  "NODE_EXTRA_CA_CERTS",
  // Where an agent's own installs live. Without these a forged tool could not
  // import a package the same agent had just installed with pip.
  "PYTHONUSERBASE",
  "PYTHONPATH",
  "VIRTUAL_ENV",
]);

/**
 * SWARM_ variables tell a tool about its run, so they pass — except these,
 * which are not context but credentials. SWARM_UI_TOKEN is the console's
 * mutation token, which starts, stops and reaps swarms; a pane inherits it
 * whenever the operator exported it before starting Herdr. SWARM_TRACE_TOKEN
 * is the calling pane's own trace identity, and a forged tool is code another
 * agent may have written: the harness records the call itself, so the tool
 * never needs it.
 */
export const FORGED_ENV_DENY = new Set(["SWARM_UI_TOKEN", "SWARM_TRACE_TOKEN"]);

/** What a forged subprocess may see: PATH, proxy, locale — not the pane's API keys. */
export function forgedToolEnv(
  extra: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (FORGED_ENV_DENY.has(key)) continue;
    if (FORGED_ENV_KEEP.has(key) || key.startsWith("SWARM_")) env[key] = value;
  }
  return { ...env, ...extra };
}

/**
 * A pack's secrets, for that pack's own tools and nothing else
 * (docs/packs.md §4).
 *
 * The kickoff describes them in SWARM_PACK_SECRETS as JSON:
 * `{"<pack id>": {"names": ["VT_API_KEY"], "file": "<secrets.env>"}}`.
 * - In a microVM the names are enough: each is already in the VM's
 *   environment as a placeholder that the host swaps for the real value on
 *   the way to the host the secret is bound to, so the value never enters the
 *   VM. `file` is absent.
 * - On the host, `file` is present only when the operator accepted, with
 *   --allow-pack-secrets, that a pane can read what its own extension can;
 *   the value is read at call time and handed to the tool's child process.
 *
 * A tool forged during the run has no pack and gets nothing.
 */
export type PackSecretsSpec = Record<string, { names?: string[]; file?: string }>;

export function packSecretsSpec(env: NodeJS.ProcessEnv = process.env): PackSecretsSpec {
  const raw = env.SWARM_PACK_SECRETS;
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as PackSecretsSpec) : {};
  } catch {
    return {};
  }
}

const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]{1,63}$/;

/** KEY=VALUE lines, as `pack install` writes them; anything else is ignored. */
export function parseSecretsEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const at = line.indexOf("=");
    if (at <= 0) continue;
    const key = line.slice(0, at).trim();
    if (SECRET_NAME_RE.test(key)) out[key] = line.slice(at + 1);
  }
  return out;
}

export async function packSecretsFor(
  manifest: { pack?: string },
  env: NodeJS.ProcessEnv = process.env,
): Promise<Record<string, string>> {
  if (!manifest.pack) return {};
  const spec = packSecretsSpec(env)[manifest.pack];
  if (!spec) return {};
  const out: Record<string, string> = {};
  for (const name of spec.names ?? []) {
    if (SECRET_NAME_RE.test(name) && typeof env[name] === "string") out[name] = env[name] as string;
  }
  if (spec.file) {
    const text = await readFile(spec.file, "utf8").catch(() => "");
    Object.assign(out, parseSecretsEnv(text));
  }
  return out;
}

/**
 * Put `[secret NAME]` where a secret's value appears. The trace keeps every
 * character an agent produced — except these, which the pack's author and the
 * operator did not give to the record. Values shorter than 6 characters are
 * left alone: they are not credentials, and replacing them would mangle text.
 */
export function redactSecrets<T>(value: T, secrets: Record<string, string>): T {
  const pairs = Object.entries(secrets).filter(([, v]) => typeof v === "string" && v.length >= 6);
  if (!pairs.length) return value;
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") {
      let t = v;
      for (const [name, secret] of pairs) t = t.split(secret).join(`[secret ${name}]`);
      return t;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}

/**
 * The script hash a tool was sealed with, by name: what the hub answers a VM,
 * read on the host, where the record is current (a guest reads tools/ and
 * history/ up to five seconds old). Empty when there is no such tool.
 */
export async function forgedToolSeal(sandboxRoot: string, name: string): Promise<string> {
  if (!/^[a-z][a-z0-9_]{2,31}$/.test(String(name))) return "";
  const read = await readSandboxFile(sandboxRoot, `${TOOLS_DIR}/${name}/${TOOL_MANIFEST}`).catch(() => null);
  const manifest = read ? parseManifest(read.bytes.toString("utf8")) : null;
  return manifest ? expectedToolHash(sandboxRoot, manifest) : "";
}

/** The hash make_tool (or sealForgedTools) recorded, not whatever is on disk now. */
async function expectedToolHash(sandboxRoot: string, manifest: ForgedToolManifest): Promise<string> {
  const versions = await listFileHistory(sandboxRoot, `${TOOLS_DIR}/${manifest.name}/${TOOL_MANIFEST}`);
  const last = versions.at(-1);
  if (last) {
    const rec = await readFileVersion(sandboxRoot, `${TOOLS_DIR}/${manifest.name}/${TOOL_MANIFEST}`, last.rev).catch(() => null);
    if (rec) {
      const sealed = parseManifest(rec.text);
      if (sealed && isToolHash(sealed.sha256)) return sealed.sha256;
    }
  }
  return manifest.sha256;
}

/**
 * Run a forged tool: `<runtime> tools/<name>/<entry>` in the sandbox, the
 * arguments as one JSON object on stdin, stdout as the result. The entry has
 * to resolve inside its own directory (no symlink out of the sandbox), the
 * bytes have to match the manifest (a tool a shell rewrote is not the tool
 * that was announced), and the process gets the manifest's timeout, then
 * SIGKILL. Output is capped so a chatty script cannot flood the model.
 */
/**
 * Why a tool run failed for want of a program or a module, or null: the
 * shell's 127 or "command not found", Python's ModuleNotFoundError, a
 * program looked up by name and not found, a tool's own "not on PATH" or
 * "is not installed". Generic: it reads what any runtime says, and names no
 * tool or program.
 */
export function lacksProgram(run: { exit_code: number | null; stdout: string; stderr: string }): string | null {
  const text = `${run.stderr}\n${run.stdout}`;
  const m =
    /No module named '([^']+)'/.exec(text) ??
    /([A-Za-z0-9_.+-]+): command not found/.exec(text) ??
    /No such file or directory: '([^'/\s]+)'/.exec(text) ??
    /(?:^|\W)([A-Za-z0-9_.+-]+) (?:is )?not (?:on PATH|installed|found in PATH)/i.exec(text);
  if (m) return `${m[1]} is not in this VM`;
  if (run.exit_code === 127) return "a program it runs is not in this VM (exit 127)";
  return null;
}

/**
 * Where a string argument lies in one of the agent's own writable
 * directories — the only places its VM lets a tool write — as a path relative
 * to the run, normalised, with the place under {OUT} it takes in a job; null
 * when it is not in one. A path is taken relative to the run or absolute under
 * `root` (the run's directory, the same path in every VM), and `./`, `//`,
 * `.` and `..` are resolved first, so each way of naming a place maps alike.
 * Generic: it knows the agent's directories, never a tool or a parameter.
 */
function ownPlace(value: string, agentId: string, root?: string): { rel: string; out: string } | null {
  if (!value || value.includes("{OUT}") || value.includes("\0")) return null;
  let path = value;
  if (path.startsWith("/")) {
    const base = root ? posix.normalize(root).replace(/\/+$/, "") : "";
    if (!base || !(path === base || path.startsWith(`${base}/`))) return null;
    path = path.slice(base.length + 1);
  }
  const rel = posix.normalize(path || ".").replace(/\/+$/, "");
  if (rel === "." || rel === ".." || rel.startsWith("../")) return null;
  const homes: Array<[string, string]> = [
    [`work/extracted/${agentId}`, "{OUT}/extracted"],
    [`work/quarantine/${agentId}`, "{OUT}/quarantine"],
    [`tool-output/${agentId}`, "{OUT}/tool-output"],
    [`work/${agentId}`, "{OUT}"],
  ];
  for (const [from, to] of homes) if (rel === from || rel.startsWith(`${from}/`)) return { rel, out: to + rel.slice(from.length) };
  return null;
}

function mapStrings(v: unknown, fn: (s: string) => string): unknown {
  return typeof v === "string" ? fn(v)
    : Array.isArray(v) ? v.map((x) => mapStrings(x, fn))
      : v && typeof v === "object" ? Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, mapStrings(x, fn)])) : v;
}

/**
 * A tool's arguments for a run as a job: a place the tool would write in one
 * of the agent's own writable directories becomes a place under {OUT}, since
 * a worker writes only its $OUT (sealed into store/jobs/<id>/out/) and sees
 * the rest of the run read-only. work/<id>/x is {OUT}/x; work/extracted/<id>/x
 * is {OUT}/extracted/x, work/quarantine/<id>/x {OUT}/quarantine/x and
 * tool-output/<id>/x {OUT}/tool-output/x (the first reruns wrote an
 * extraction to work/extracted/<id>/ and every one failed read-only), however
 * the path is written (relative, absolute under `root`, with ./ or ..).
 *
 * A path there that already held something when the agent called the tool
 * (`held`, see heldOwnPaths) is what the tool reads, not where it writes: it
 * stays as given, since the worker reads all of work/ where it is. Mapped,
 * a database the agent had extracted would be looked for in an empty $OUT,
 * and the job would find nothing to read.
 */
export function ownPathsToOut(
  args: Record<string, unknown>,
  agentId: string | undefined,
  o: { root?: string; held?: ReadonlySet<string> } = {},
): Record<string, unknown> {
  if (!agentId) return args;
  return mapStrings(args, (v) => {
    const place = ownPlace(v, agentId, o.root);
    return place && !o.held?.has(place.rel) ? place.out : v;
  }) as Record<string, unknown>;
}

/**
 * The places in a tool's arguments, in the agent's own writable directories,
 * that hold something now: a file with bytes in it or a directory with
 * entries. Taken before the tool runs in the agent's VM, so what a failed
 * attempt there created (an empty output file, an output directory made
 * before the missing program was called) is still a place to write.
 */
export async function heldOwnPaths(root: string, args: Record<string, unknown>, agentId: string | undefined): Promise<Set<string>> {
  const held = new Set<string>();
  if (!agentId) return held;
  const places: string[] = [];
  mapStrings(args, (v) => {
    const place = ownPlace(v, agentId, root);
    if (place) places.push(place.rel);
    return v;
  });
  for (const rel of places) {
    const st = await stat(join(root, rel)).catch(() => null);
    if (!st) continue;
    if (st.isFile() ? st.size > 0 : st.isDirectory() && (await readdir(join(root, rel)).catch(() => [])).length > 0) held.add(rel);
  }
  return held;
}

/**
 * For the answer of a tool rerun as a job: each path the agent gave that was
 * mapped under {OUT}, and where it is now that the job is sealed,
 * store/jobs/<id>/out/<rest>. The agent reads and cites it from there.
 */
export function writtenToOf(given: unknown, mapped: unknown, job: string): Record<string, string> {
  const moved: Record<string, string> = {};
  const walk = (a: unknown, b: unknown): void => {
    if (typeof a === "string" && typeof b === "string") {
      if (a !== b && (b === "{OUT}" || b.startsWith("{OUT}/"))) moved[a] = `store/jobs/${job}/out${b.slice("{OUT}".length)}`;
    } else if (a && b && typeof a === "object" && typeof b === "object") {
      for (const k of Object.keys(a as object)) walk((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]);
    }
  };
  walk(given, mapped);
  return moved;
}

/**
 * For the answer of a tool rerun as a job: each place under the job's staging
 * directory its output names — <run>/.jobs/<id>/…, or .jobs/<id>/… from the
 * run's directory, where the worker ran it — and where that place is now the
 * job is sealed, store/jobs/<id>/out/…. The output itself is sealed and stays
 * as it is; this says where to find what it names. Generic: it reads the
 * job's own directory in any text, never a tool's format.
 */
export function stagedPaths(text: string, root: string, job: string): Record<string, string> {
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const base = posix.normalize(root).replace(/\/+$/, "");
  const stage = `.jobs/${job}`;
  const re = new RegExp(`(?<![\\w./-])(?:${base ? `${esc(base)}/|` : ""}\\./)?${esc(stage)}(?=$|[/\\s"'\`<>,;:)\\]}])(?:/[^\\s"'\`<>]*)?`, "g");
  const paths: Record<string, string> = {};
  for (const m of text.matchAll(re)) {
    const printed = m[0].replace(/(?<=.)[.,;:)\]}]+$/, "");
    paths[printed] = `store/jobs/${job}/out${printed.slice(printed.indexOf(stage) + stage.length).replace(/\/+$/, "")}`;
  }
  return paths;
}

/** stagedPaths over a whole file, a line at a time: a job's sealed stdout.log. */
export async function stagedPathsIn(file: string, root: string, job: string): Promise<Record<string, string>> {
  const handle = await open(file, "r");
  try {
    const paths: Record<string, string> = {};
    const lines = createInterface({ input: handle.createReadStream({ autoClose: false, encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of lines) Object.assign(paths, stagedPaths(line, root, job));
    return paths;
  } finally {
    await handle.close();
  }
}

export async function runForgedTool(
  sandboxRoot: string,
  manifest: ForgedToolManifest,
  args: Record<string, unknown>,
  options: { signal?: AbortSignal; env?: Record<string, string | undefined>; agentId?: string; sealed?: string } = {},
): Promise<ForgedRunResult> {
  const started = Date.now();
  const fail = (reason: string): ForgedRunResult => ({ ok: false, exit_code: null, signal: null, stdout: "", stderr: reason, duration_ms: Date.now() - started, timed_out: false, truncated: false });
  const entry = await resolveToolEntry(sandboxRoot, manifest);
  if (entry.real === null) {
    return fail(
      entry.why === "missing"
        ? `tool "${manifest.name}" has no entry file ${manifest.entry}`
        : `tool "${manifest.name}" entry resolves outside its directory`,
    );
  }
  const real = entry.real;
  let bytes = await readFile(real).catch(() => null);
  if (!bytes) return fail(`tool "${manifest.name}" entry is unreadable`);
  let sha256 = createHash("sha256").update(bytes).digest("hex");
  // In a VM the seal comes from the hub (options.sealed), read on the host
  // where the record is current: the guest's own tools/ and history/ are up
  // to five seconds old, and both stale together read as the old version
  // matching its old seal — v1 run while the record said v2. The bytes here
  // are read again until they are the sealed ones, for as long as the cache
  // can lag, and a tool that never gets there is not run.
  const expected = options.sealed ?? (await expectedToolHash(sandboxRoot, manifest));
  if (isToolHash(expected) && sha256 !== expected && process.env.SWARM_ISOLATION === "microvm") {
    const deadline = Date.now() + GUEST_CACHE_WAIT_MS;
    while (sha256 !== expected && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 250));
      bytes = (await readFile(real).catch(() => null)) ?? bytes;
      sha256 = createHash("sha256").update(bytes).digest("hex");
    }
  }
  if (!isToolHash(expected) || sha256 !== expected) {
    return fail(`tool "${manifest.name}" on disk (${shortHash(sha256)}) does not match its manifest (${shortHash(expected || "missing")}); re-forge it with make_tool`);
  }
  const timeoutMs = toolTimeoutSeconds(manifest) * 1000;
  return new Promise<ForgedRunResult>((resolveRun) => {
    const stdout = new StreamCapture(TOOL_OUTPUT_MAX_BYTES, sandboxRoot, toolOutputRel(options.agentId, manifest.name, "out"));
    const stderr = new StreamCapture(TOOL_OUTPUT_MAX_BYTES / 4, sandboxRoot, toolOutputRel(options.agentId, manifest.name, "err"));
    let timedOut = false;
    let settled = false;
    // Its own process group, so a timeout or an abort kills the grandchildren
    // too — a `bash` entry that spawned `sleep` must not outlive the call.
    // Colour is forced off: a tool's stdout is data for a model, not a terminal.
    const child = spawn(manifest.runtime, [real], {
      cwd: sandboxRoot,
      env: forgedToolEnv({
        ...options.env,
        SWARM_SANDBOX: sandboxRoot,
        SWARM_TOOL: manifest.name,
        ...(options.agentId ? { AGENT_ID: options.agentId } : {}),
        NO_COLOR: "1",
        FORCE_COLOR: "0",
        TERM: "dumb",
      }),
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    const killTree = () => {
      try {
        if (child.pid && process.platform !== "win32") process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          // already gone
        }
      }
    };
    const finish = (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      const fullOutput = stdout.close();
      const fullStderr = stderr.close();
      resolveRun({
        ok: !timedOut && code === 0,
        exit_code: code,
        signal,
        stdout: stdout.text(fullOutput),
        stderr: stderr.text(fullStderr),
        duration_ms: Date.now() - started,
        timed_out: timedOut,
        truncated: Boolean(fullOutput || fullStderr),
        ...(fullOutput ? { full_output: fullOutput } : {}),
        ...(fullStderr ? { full_stderr: fullStderr } : {}),
      });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killTree();
    }, timeoutMs);
    const onAbort = () => killTree();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (err) => {
      stderr.push(Buffer.from(`${manifest.runtime}: ${err.message}\n`));
      finish(null, null);
    });
    child.on("close", (code, signal) => finish(code, signal));
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(args ?? {}));
  });
}

// ---------------------------------------------------------------------------
// Read-only inputs: files the swarm may read and never change.
//
// The operator hands the swarm a directory to analyse. The kickoff copies it
// to inputs/ (the original is never touched), takes away the write bits,
// keeps a pristine clone under .inputs-pristine/ and writes inputs.json: what
// was copied, its hashes, and which guard the panes got. Three layers keep
// the copy intact, from the tool call down to the kernel:
//   1. edit/write/claim_file/file_restore refuse anything under inputs/
//      (guardWrite, claimFile above);
//   2. a bash call that changed, added or removed a file under inputs/ is
//      detected like any other shell write and healed from the pristine copy
//      (healInputs), and the board is told;
//   3. where the host can do it, the whole pane runs with inputs/ read-only
//      at the kernel (scripts/fsguard.sh: seatbelt on macOS, a mount
//      namespace on Linux), so nothing gets as far as layer 2.
// ---------------------------------------------------------------------------

export const INPUTS_DIR = "inputs";
export const INPUTS_MANIFEST = "inputs.json";
export const INPUTS_PRISTINE_DIR = ".inputs-pristine";

export type InputFile = {
  path: string;
  bytes: number;
  sha256: string;
  /** The digests courts and acquisition tools quote beside sha256, when the kickoff took them. sha256 decides. */
  md5?: string;
  sha1?: string;
  /**
   * A name in the evidence that is neither a file nor a link — a FIFO, a
   * socket, a device node (an extracted Linux root has them) — recorded as
   * the kind it is and never opened: every walk counts it, and a change of
   * kind is a change.
   */
  special?: "fifo" | "socket" | "char" | "block";
  /** The stat the kickoff saw after locking the file, so a large input is
   *  not re-hashed while nothing about it has moved. */
  mtime_ms?: number;
  ctime_ms?: number;
  /**
   * The mode and link count the kickoff saw, as octal and a number.
   *
   * The copy path locks every file to 444 and one name, so it can assume
   * them. An attached image cannot be chmod'ed — its files arrive with
   * whatever mode the image holds, often 644 — and assuming 444 there made
   * every file of every image run drift on the first sweep. Recorded when the
   * kickoff cannot dictate it.
   */
  mode?: string;
  links?: number;
  /**
   * A symbolic link inside the evidence, recorded as the link it is: its
   * target, never followed. Every walk over the evidence — this manifest,
   * the agents' `inputs` check, the pack's check_inputs, host custody —
   * treats a link the same way, so a link that was there at the start is
   * never reported as a changed or an added file.
   */
  link?: string;
  /**
   * A name, or a link's target, whose bytes are not UTF-8 (a Windows-1254
   * or Latin-1 name from an archive, on a filesystem that keeps bytes):
   * `path` and `link` are then only for reading, and these hold the bytes,
   * base64. Every walk compares names by their bytes.
   */
  path_b64?: string;
  link_b64?: string;
};

/**
 * One evidence set of several, each at inputs/<name>/: a directory of the
 * copy, or a link to the directory held in place. One set is inputs/ itself
 * and the manifest has no `sets`.
 */
export type InputSet = {
  name: string;
  /** `inputs/<name>`, where its files are. */
  path: string;
  /** Where it came from (resolved, for a set held in place). */
  source: string;
  files: number;
  bytes: number;
};

export type InputsManifest = {
  /** Where the copy came from, as the operator named it; every set's, comma-separated, when there are several. */
  source: string;
  /** Several sets, each at inputs/<name>/; absent for one. */
  sets?: InputSet[];
  /** How the evidence is held: `copy`, `bind` (in place) or `image`. */
  held?: string;
  copied_at: string;
  files: InputFile[];
  bytes: number;
  /** What the operator asked for: auto | on | off. */
  enforce: string;
  /** What the kickoff could set up for the panes: seatbelt | mountns | none. */
  guard: string;
};

export type InputsCheck = {
  /** Nothing drifted at all: bytes, metadata, presence. */
  ok: boolean;
  /**
   * The bytes of every file the manifest knows still match.
   *
   * This is the evidence-integrity question, and it is not the same question
   * as `ok`. One archived run recorded 374 violations on two files whose
   * sha256 still matched the manifest exactly — the write bit had come back,
   * nothing else. A run that reports "evidence modified" 374 times about
   * evidence that never changed teaches its reader to stop looking.
   */
  content_ok: boolean;
  /** Bytes differ from the manifest's file: the serious one. */
  modified: string[];
  /** Bytes match; mode or link count drifted. A precursor, not a change. */
  metadata: string[];
  missing: string[];
  /** Files and symlinks the manifest does not know. */
  added: string[];
  /**
   * Files whose bytes match the manifest's sha256 but not its md5 or sha1,
   * as read again now: the manifest disagrees with itself (sha256 decides
   * about the bytes; this says the record around them was changed).
   */
  digest_mismatch: string[];
  checked: number;
};

export type InputsHeal = { path: string; action: "restored" | "removed" | "failed"; error?: string };

/** True for inputs/ itself and anything under it (sandbox-relative key). */
export function isInputsPath(pathKey: string): boolean {
  const key = pathKey.replace(/^\.\//, "").toLowerCase();
  return key === INPUTS_DIR || key.startsWith(`${INPUTS_DIR}/`);
}

/** True when either the lexical path or what it really points at is an input. */
export async function resolvesToInputs(sandboxRoot: string, rawPath: string): Promise<boolean> {
  if (isInputsPath(claimKey(sandboxRoot, rawPath))) return true;
  try {
    return isInputsPath(await realPathKey(sandboxRoot, rawPath));
  } catch {
    return false;
  }
}

export async function readInputsManifest(sandboxRoot: string): Promise<InputsManifest | null> {
  const text = await readFile(join(sandboxRoot, INPUTS_MANIFEST), "utf8").catch(() => null);
  if (!text) return null;
  try {
    const parsed = JSON.parse(text) as Partial<InputsManifest>;
    if (!Array.isArray(parsed.files)) return null;
    return {
      source: typeof parsed.source === "string" ? parsed.source : "",
      copied_at: typeof parsed.copied_at === "string" ? parsed.copied_at : "",
      files: parsed.files
        .filter((f): f is InputFile => Boolean(f) && typeof f.path === "string" && typeof f.sha256 === "string")
        .map((f) => ({
          path: f.path,
          bytes: Number(f.bytes) || 0,
          sha256: f.sha256,
          ...(typeof f.md5 === "string" && /^[0-9a-fA-F]{32}$/.test(f.md5) ? { md5: f.md5.toLowerCase() } : {}),
          ...(typeof f.sha1 === "string" && /^[0-9a-fA-F]{40}$/.test(f.sha1) ? { sha1: f.sha1.toLowerCase() } : {}),
          ...(typeof f.mtime_ms === "number" ? { mtime_ms: f.mtime_ms } : {}),
          ...(typeof f.ctime_ms === "number" ? { ctime_ms: f.ctime_ms } : {}),
          // How the file is held, when the kickoff recorded it rather than
          // dictating it. Dropping these here is what made an attached image
          // drift on its own first sweep.
          ...(typeof f.mode === "string" ? { mode: f.mode } : {}),
          ...(typeof f.links === "number" ? { links: f.links } : {}),
          // A link inside the evidence, checked as a link by every walk.
          ...(typeof f.link === "string" ? { link: f.link } : {}),
          ...(typeof f.path_b64 === "string" ? { path_b64: f.path_b64 } : {}),
          ...(typeof f.link_b64 === "string"
            ? { link_b64: f.link_b64 }
            : typeof (f as unknown as { target_b64?: unknown }).target_b64 === "string"
              ? { link_b64: (f as unknown as { target_b64: string }).target_b64 }
              : {}),
          ...(f.special === "fifo" || f.special === "socket" || f.special === "char" || f.special === "block" ? { special: f.special } : {}),
        })),
      bytes: Number(parsed.bytes) || 0,
      enforce: typeof parsed.enforce === "string" ? parsed.enforce : "auto",
      guard: typeof parsed.guard === "string" ? parsed.guard : "none",
      ...(typeof (parsed as { held?: unknown }).held === "string" ? { held: (parsed as { held: string }).held } : {}),
      ...(Array.isArray(parsed.sets) ? { sets: inputSetsOf(parsed.sets) } : {}),
    };
  } catch {
    return null;
  }
}

/** The `sets` of a manifest, each with a name that is one directory under inputs/. */
function inputSetsOf(raw: unknown): InputSet[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((x): x is Record<string, unknown> => Boolean(x) && typeof x === "object" && typeof (x as { name?: unknown }).name === "string")
    .filter((x) => {
      const name = x.name as string;
      return name !== "" && name !== "." && name !== ".." && !name.includes("/") && !name.includes("\0");
    })
    .map((x) => ({
      name: x.name as string,
      path: `${INPUTS_DIR}/${x.name as string}`,
      source: typeof x.source === "string" ? x.source : "",
      files: Number(x.files) || 0,
      bytes: Number(x.bytes) || 0,
    }));
}

/**
 * Every regular file and symlink under inputs/, as sandbox-relative keys, in
 * byte order. A symlink can only be foreign — the kickoff dereferenced every
 * one it copied — so it is listed to be found as an addition and removed.
 *
 * There is no ceiling on the count or the depth. There used to be one, 5,000
 * files and 12 levels, left behind when the kickoff dropped its own: every
 * manifest file past the ceiling then read as "missing", and a KAPE-style
 * triage set failed its custody check on every sweep while nothing had
 * changed. The manifest lists every file, so the walk does too.
 */
export async function listInputFiles(sandboxRoot: string): Promise<string[]> {
  const out: string[] = [];
  const top = join(sandboxRoot, INPUTS_DIR);
  const sets = await inputSetNames(sandboxRoot);
  async function walk(dir: string): Promise<void> {
    const entries = (await readdir(dir, { withFileTypes: true }).catch(() => [])).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory() || (dir === top && entry.isSymbolicLink() && sets.has(entry.name))) await walk(abs);
      // Every name that is not a directory: a file, a link, and a FIFO,
      // socket or device node, which the manifest records by kind.
      else out.push(claimKey(sandboxRoot, abs));
    }
  }
  await walk(top);
  return out;
}

/** Whether these bytes are UTF-8 as they stand: decoding them and encoding back gives the same bytes. */
function isUtf8(bytes: Buffer): boolean {
  return Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes);
}

/** A name's bytes as a map key: latin1 maps each byte to one character, so no two names share a key. */
function byteKey(bytes: Buffer): string {
  return bytes.toString("latin1");
}

/** The bytes of a manifest entry's name, as the kickoff read them. */
function inputNameBytes(file: InputFile): Buffer {
  return typeof file.path_b64 === "string" ? Buffer.from(file.path_b64, "base64") : Buffer.from(file.path, "utf8");
}

/**
 * Every name under inputs/ that is not a directory, by its bytes: the key
 * (see byteKey), the name as text for reading, and the path to open. A
 * string walk turned a name that is not UTF-8 into a different name, which
 * then read as one file missing and another added.
 */
async function listInputEntries(sandboxRoot: string): Promise<Map<string, { display: string; abs: Buffer }>> {
  const out = new Map<string, { display: string; abs: Buffer }>();
  const slash = Buffer.from("/");
  const top = Buffer.from(INPUTS_DIR);
  const sets = await inputSetNames(sandboxRoot);
  async function walk(abs: Buffer, rel: Buffer): Promise<void> {
    const entries = (await readdir(abs, { withFileTypes: true, encoding: "buffer" }).catch(() => [])).sort((a, b) =>
      Buffer.compare(a.name as unknown as Buffer, b.name as unknown as Buffer),
    );
    for (const entry of entries) {
      const name = entry.name as unknown as Buffer;
      const childAbs = Buffer.concat([abs, slash, name]);
      const childRel = Buffer.concat([rel, slash, name]);
      if (entry.isDirectory() || (rel.equals(top) && entry.isSymbolicLink() && isUtf8(name) && sets.has(name.toString("utf8")))) await walk(childAbs, childRel);
      else out.set(byteKey(childRel), { display: childRel.toString("utf8"), abs: childAbs });
    }
  }
  await walk(Buffer.from(join(sandboxRoot, INPUTS_DIR)), top);
  return out;
}

/** The kind of a name in the evidence that is not a file, a link or a directory. */
export function specialKind(st: { isFIFO(): boolean; isSocket(): boolean; isCharacterDevice(): boolean; isBlockDevice(): boolean }): InputFile["special"] | null {
  if (st.isFIFO()) return "fifo";
  if (st.isSocket()) return "socket";
  if (st.isCharacterDevice()) return "char";
  if (st.isBlockDevice()) return "block";
  return null;
}

const inputHashCache = new Map<string, { size: number; mtimeMs: number; ctimeMs: number; sha: string; md5?: string; sha1?: string }>();

/** sha256, sha1 and md5 of a file in one read. */
async function digestsOfFile(abs: string | Buffer): Promise<{ sha256: string; sha1: string; md5: string } | null> {
  try {
    const h256 = createHash("sha256");
    const h1 = createHash("sha1");
    const h5 = createHash("md5");
    for await (const chunk of createReadStream(abs)) {
      h256.update(chunk as Buffer);
      h1.update(chunk as Buffer);
      h5.update(chunk as Buffer);
    }
    return { sha256: h256.digest("hex"), sha1: h1.digest("hex"), md5: h5.digest("hex") };
  } catch {
    return null;
  }
}

/** inputs.json per sandbox, re-read when its mtime moves, for the manifest-seeded cache below. */
const manifestCache = new Map<string, { mtimeMs: number; byPath: Map<string, InputFile>; sets: Set<string> }>();

async function cachedManifest(sandboxRoot: string): Promise<{ byPath: Map<string, InputFile>; sets: Set<string> } | null> {
  const file = join(sandboxRoot, INPUTS_MANIFEST);
  const info = await stat(file).catch(() => null);
  if (!info) return null;
  let entry = manifestCache.get(sandboxRoot);
  if (!entry || entry.mtimeMs !== info.mtimeMs) {
    const manifest = await readInputsManifest(sandboxRoot);
    entry = {
      mtimeMs: info.mtimeMs,
      byPath: new Map((manifest?.files ?? []).map((f) => [f.path, f])),
      sets: new Set((manifest?.sets ?? []).map((set) => set.name)),
    };
    manifestCache.set(sandboxRoot, entry);
  }
  return entry;
}

async function manifestEntry(sandboxRoot: string, pathKey: string): Promise<InputFile | null> {
  return (await cachedManifest(sandboxRoot))?.byPath.get(pathKey) ?? null;
}

/**
 * The names of the sets directly under inputs/, when the manifest has
 * several. A set held in place is a link there (inputs/<name> -> its
 * directory), and every walk over the evidence goes through it, as it goes
 * through inputs/ when one set is held in place: the set is the evidence,
 * the link only where it is. Any other link is a name of its own.
 */
export async function inputSetNames(sandboxRoot: string): Promise<Set<string>> {
  return (await cachedManifest(sandboxRoot))?.sets ?? new Set();
}

/**
 * The fingerprint of an input: its sha256, its mode and its link count, as
 * `<sha>|mode=<octal>|links=<n>`; a symlink fingerprints as `link:<target>`.
 * The sha is re-read only when size, mtime or ctime moved. mtime and size
 * can be put back by the file's owner (`touch -t`), ctime cannot without
 * root, so a rewrite is always re-hashed. The mode is part of it because a
 * write bit is the road to a later change, and the link count because a
 * second name for the inode outside inputs/ is a road around the path checks.
 */
async function hashOfCached(sandboxRoot: string, pathKey: string, opts: { abs?: Buffer; known?: InputFile } = {}): Promise<string> {
  // A name whose bytes are not UTF-8 is opened by its bytes, and its
  // manifest entry comes with it (two such names can read alike as text).
  const abs: string | Buffer = opts.abs ?? resolve(sandboxRoot, pathKey);
  const cacheKey = typeof abs === "string" ? abs : byteKey(abs);
  const info = await lstat(abs).catch(() => null);
  if (!info) {
    inputHashCache.delete(cacheKey);
    return "";
  }
  if (info.isSymbolicLink()) {
    inputHashCache.delete(cacheKey);
    const target = await readlink(abs, { encoding: "buffer" }).catch(() => null);
    if (!target) return "link:?";
    return isUtf8(target) ? `link:${target.toString("utf8")}` : `link-b64:${target.toString("base64")}`;
  }
  if (!info.isFile()) {
    inputHashCache.delete(cacheKey);
    const kind = specialKind(info);
    return kind ? `special:${kind}` : "";
  }
  const hit = inputHashCache.get(cacheKey);
  let sha: string;
  if (hit && hit.size === info.size && hit.mtimeMs === info.mtimeMs && hit.ctimeMs === info.ctimeMs) {
    sha = hit.sha;
  } else {
    // The manifest is the first cache: while the size, mtime and ctime are
    // what the kickoff recorded after locking the file, its sha holds, and a
    // 25 GB image is never read again just to be sure.
    const known = opts.known ?? (await manifestEntry(sandboxRoot, pathKey));
    const unchanged =
      known &&
      known.bytes === info.size &&
      typeof known.mtime_ms === "number" &&
      typeof known.ctime_ms === "number" &&
      known.mtime_ms === Math.floor(info.mtimeMs) &&
      known.ctime_ms === Math.floor(info.ctimeMs);
    // A file read again is read for all three digests at once, so the
    // manifest's md5 and sha1 are checked on the same bytes as its sha256.
    const read = unchanged ? null : await digestsOfFile(abs);
    sha = unchanged ? known.sha256 : (read?.sha256 ?? "");
    inputHashCache.set(cacheKey, { size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs, sha, ...(read ? { md5: read.md5, sha1: read.sha1 } : {}) });
  }
  return `${sha}|mode=${(info.mode & 0o777).toString(8)}|links=${info.nlink}`;
}

/**
 * The fingerprint the manifest promises: the bytes, and how the file was held
 * when the kickoff recorded it.
 *
 * `444|1` for a copy the kickoff locked itself; whatever was recorded for an
 * attached image, which it cannot lock and must therefore describe.
 */
function expectedFingerprint(file: { sha256: string; mode?: string; links?: number; link?: string; link_b64?: string; special?: string }): string {
  if (typeof file.link_b64 === "string") return `link-b64:${file.link_b64}`;
  if (typeof file.link === "string") return `link:${file.link}`;
  if (file.special) return `special:${file.special}`;
  return `${file.sha256}|mode=${file.mode ?? "444"}|links=${file.links ?? 1}`;
}

/** Compare inputs/ with its manifest. Null when this swarm has no inputs. */
export async function verifyInputs(sandboxRoot: string): Promise<InputsCheck | null> {
  const manifest = await readInputsManifest(sandboxRoot);
  if (!manifest) return null;
  // By the bytes of each name, on both sides (inputNameBytes, listInputEntries).
  const known = new Map(manifest.files.map((f) => [byteKey(inputNameBytes(f)), f]));
  const onDisk = await listInputEntries(sandboxRoot);
  const modified: string[] = [];
  const missing: string[] = [];
  const added: string[] = [];
  const metadata: string[] = [];
  const digestMismatch: string[] = [];
  for (const [key, file] of known) {
    const there = onDisk.get(key);
    if (!there) {
      missing.push(file.path);
      continue;
    }
    const raw = typeof file.path_b64 === "string" || !isUtf8(Buffer.from(key, "latin1"));
    const found = await hashOfCached(sandboxRoot, file.path, raw ? { abs: there.abs, known: file } : {});
    if (found.startsWith(`${file.sha256}|`)) {
      // Read again now (not taken from the manifest on an unmoved stat): the
      // other digests the manifest records must be these bytes' too.
      const read = inputHashCache.get(raw ? byteKey(there.abs) : resolve(sandboxRoot, file.path));
      if ((file.md5 && read?.md5 && read.md5 !== file.md5) || (file.sha1 && read?.sha1 && read.sha1 !== file.sha1)) digestMismatch.push(file.path);
    }
    if (found === expectedFingerprint(file)) continue;
    // `<sha>|mode=<octal>|links=<n>`: the first field is the bytes and the
    // rest is how the file is held. Only the first one is the evidence.
    if (found.startsWith(`${file.sha256}|`)) metadata.push(file.path);
    else modified.push(file.path);
  }
  for (const [key, there] of onDisk) if (!known.has(key)) added.push(there.display);
  const contentOk = modified.length === 0 && missing.length === 0 && added.length === 0;
  return {
    ok: contentOk && metadata.length === 0,
    content_ok: contentOk,
    modified,
    metadata,
    missing,
    added,
    digest_mismatch: digestMismatch,
    checked: known.size,
  };
}

/** Run `fn` with the parent directory temporarily writable, then lock it again. */
async function withWritableParent(abs: string, fn: () => Promise<void>): Promise<void> {
  const dir = dirname(abs);
  await mkdir(dir, { recursive: true });
  const before = (await stat(dir)).mode & 0o7777;
  await chmod(dir, before | 0o700);
  try {
    await fn();
  } finally {
    await chmod(dir, before & ~0o222).catch(() => undefined);
  }
}

/**
 * Put inputs/ back the way the manifest says. A file the manifest knows is
 * copied back from the pristine clone; a file it does not know is removed.
 * With no `only`, everything verifyInputs found wrong is healed. Under a
 * kernel guard this cannot run either (the harness shares the pane), and
 * does not need to.
 */
export async function healInputs(sandboxRoot: string, only?: string[]): Promise<InputsHeal[]> {
  const manifest = await readInputsManifest(sandboxRoot);
  if (!manifest) return [];
  const known = new Set(manifest.files.map((f) => f.path));
  let targets = only;
  if (!targets) {
    const check = await verifyInputs(sandboxRoot);
    targets = check ? [...check.modified, ...check.metadata, ...check.missing, ...check.added] : [];
  }
  const out: InputsHeal[] = [];
  for (const pathKey of targets) {
    if (!isInputsPath(pathKey) || pathKey === INPUTS_DIR) continue;
    const abs = resolve(sandboxRoot, pathKey);
    try {
      if (known.has(pathKey)) {
        const pristine = resolve(sandboxRoot, INPUTS_PRISTINE_DIR, pathKey.slice(INPUTS_DIR.length + 1));
        await withWritableParent(abs, async () => {
          await rm(abs, { recursive: true, force: true });
          await copyFile(pristine, abs);
          await chmod(abs, 0o444);
        });
        inputHashCache.delete(abs);
        out.push({ path: pathKey, action: "restored" });
      } else {
        await withWritableParent(abs, () => rm(abs, { recursive: true, force: true }));
        inputHashCache.delete(abs);
        out.push({ path: pathKey, action: "removed" });
      }
    } catch (err) {
      out.push({ path: pathKey, action: "failed", error: (err as Error).message });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The ledger: findings, timeline events and indicators with provenance.
//
// A forensic swarm produces three kinds of fact that have to survive the run
// in one place: dated events for the timeline, indicators (an address, a
// hash, a file name, an account), and findings (a conclusion with its
// evidence). In the first run these lived in posts on a thread and were
// merged by hand. `record` appends one entry to ledger/entries.jsonl with
// the author, a sequence number and the time; entries with the same kind,
// value and timestamp merge into one with every author listed; and the
// harness renders ledger/ledger.md — the timeline in time order, the IOC
// table, the findings — after every write, so the report cites one file.
// ---------------------------------------------------------------------------

export const LEDGER_DIR = "ledger";
export const LEDGER_ENTRIES = "ledger/entries.jsonl";
export const LEDGER_MD = "ledger/ledger.md";
/**
 * `absence`: a search that found nothing, when that matters to the case. It
 * holds only for what was searched, with what and how far, so all of it is
 * required (recordEntry).
 *
 * `coverage`: what a negative, or a "not determinable", was searched over
 * (the negative bar, extensions/negative-bar.ts): the proposition searched
 * (value), the inventory revision, the objects (refs), the time range, the
 * method and its settings, what was covered, skipped and failed, the
 * results, the alternatives left open and the detection opportunity. The hub
 * adds whether the jobs behind it were given every object it names.
 */
export const LEDGER_KINDS = ["event", "ioc", "finding", "absence", "hypothesis", "limitation", "answer", "coverage", "external"] as const;
/**
 * The kinds an agent records. `external` is material that entered the run
 * from outside the evidence (a capture the fetch service sealed, material
 * the operator supplied): the harness writes it with its provenance
 * (recordExternal), and an examiner records what it establishes.
 */
export const LEDGER_AGENT_KINDS = ["event", "ioc", "finding", "absence", "hypothesis", "limitation", "answer", "coverage"] as const;
/** Where external material came from (Plan 3 WP3 and WP6; docs/adr/0012). */
export const LEDGER_SOURCE_CLASSES = ["acquired_evidence", "case_material", "operator_supplied", "external_capture"] as const;
export const LEDGER_CONFIDENCE = ["high", "medium", "low"] as const;
/**
 * Version 3 (2026-09-26, after Fable and Codex read 1,040 entries of 14 runs):
 * two kinds and some optional fields for what the agents were writing in
 * prose. A hypothesis is a proposition under test, with its status; a
 * limitation says what the examination could not establish, and why. The
 * fields type what 80 findings tagged by hand (the question), 92 entries
 * cross-referenced (relations), 110 events hedged (which clock the time came
 * from) and 7 indicators warned about (a secret).
 */
export const LEDGER_HYPOTHESIS_STATUS = ["open", "supported", "refuted"] as const;
export const LEDGER_LIMITATION_REASONS = ["not_examined", "unavailable", "failed", "partial", "excluded"] as const;
export const LEDGER_REL_KINDS = ["supports", "contradicts", "duplicates", "derived_from"] as const;
export const LEDGER_BASIS = ["observed", "inferred"] as const;
export const LEDGER_PRECISION = ["date", "minute", "second", "subsecond", "unknown"] as const;
export const LEDGER_COMPLETION = ["complete", "partial", "failed"] as const;
export const LEDGER_SUBJECT_TYPES = ["account", "device", "person", "unknown"] as const;
export const LEDGER_MAX_ANSWERS = 8;
export const LEDGER_ANSWER_ID = /^[A-Za-z0-9._-]{1,16}$/;
export const LEDGER_MAX_REL = 10;
export const LEDGER_CLOCK_MAX_CHARS = 120;
export const LEDGER_BECAUSE_MAX_CHARS = 500;
export const LEDGER_MAX_LOCATORS = 10;
export const LEDGER_LOCATOR_MAX_CHARS = 200;
export const LEDGER_SUBJECT_MAX_CHARS = 200;
/** Who else recorded an entry word for word: appended here, never written into the entry. */
export const LEDGER_ATTESTATIONS = "ledger/attestations.jsonl";
export const LEDGER_VALUE_MAX_CHARS = 2000;
/**
 * Provenance has room but not the whole of it: a source names where a fact
 * was seen, evidence says how to check it. Over these an entry is refused
 * with the reason, never cut; the two used to be cut to 500 and 1000
 * characters in silence, which left the ledger holding provenance nobody
 * had written.
 */
export const LEDGER_SOURCE_MAX_CHARS = 1000;
export const LEDGER_EVIDENCE_MAX_CHARS = 4000;
export const LEDGER_MAX_ENTRIES = 5000;
/** A finding names the objects it rests on: at most this many, each this long. */
export const LEDGER_MAX_REFS = 20;
export const LEDGER_REF_MAX_CHARS = 300;
/**
 * Version 4 (2026-09-27, after two rounds between Claude, Fable and
 * GPT-6-Astra on a report that interprets): a finding says what the
 * observation indicates and why that confidence, what else could explain it,
 * and, when it rests on a job that did not succeed, why those bytes still
 * hold; the hub writes how each cited object was made into the entry. An
 * `answer` is the swarm's answer to one question of the goal, or its summary
 * or narrative, resting on entries it cites by hash. The versions a ledger
 * may hold, oldest first: an entry of another is refused by the verifier.
 */
export const LEDGER_VERSIONS = [2, 3, 4] as const;
export const LEDGER_VERSION = 4;
export const LEDGER_ALTERNATIVE_STATUS = ["rejected", "open"] as const;
/** A finding's interpretation: one to three sentences each; over these it is refused with the reason, never cut. */
export const LEDGER_INDICATES_MAX_CHARS = 1500;
export const LEDGER_WHY_MAX_CHARS = 1500;
/**
 * An answer's result (extensions/negative-bar.ts): established, partial,
 * bounded_negative (no evidence found in a named scope), not_determinable
 * (the old `inconclusive`, which is still taken and read as it), out_of_scope
 * and premise_not_supported, which answers a question whose premise the
 * evidence does not bear out ("when did X delete the file" when nothing
 * shows X deleted it): a valid answer to a person's question, which is a
 * proposition to test, never a conclusion to confirm. An answer without one
 * (recorded before results) reads as it always did.
 */
export const LEDGER_ANSWER_RESULTS = NB.ANSWER_RESULTS;
export const LEDGER_MAX_ALTERNATIVES = 10;
export const LEDGER_MAX_QUALIFIES = 20;
/** An answer's reasoning holds a narrative: room for one, still bounded. */
export const LEDGER_REASONING_MAX_CHARS = 20000;
/** How many entries one answer may cite, as support, contrary evidence or limitations. */
export const LEDGER_MAX_CITATIONS = 200;
export const LEDGER_SECTION_SPECIAL = ["summary", "narrative"] as const;
/** Who re-derived an entry, and how, or disputed it: beside the ledger, each file its own chain. */
export const LEDGER_DISPUTES = "ledger/disputes.jsonl";
export const LEDGER_ACT_MAX_CHARS = 2000;

export type LedgerKind = (typeof LEDGER_KINDS)[number];
export type LedgerRel = { to: number; kind: (typeof LEDGER_REL_KINDS)[number] };
export type LedgerLocator = { ref: string; at: string };
export type LedgerAttribution = { subject: string; subject_type: (typeof LEDGER_SUBJECT_TYPES)[number]; basis_refs?: string[] };
/** Something else that could explain an inferred finding: rejected with why, or left open; `test_refs` the objects that tested it. */
export type LedgerAlternative = { explanation: string; status: (typeof LEDGER_ALTERNATIVE_STATUS)[number]; why: string; test_refs?: string[] };
/** Why a ref's bytes still support the entry although its job did not succeed; on an answer, `ref` is a cited entry (E-<seq>). */
export type LedgerQualify = { ref: string; why: string };
/** An answer's edge to an entry it cites: the seq, and the entry's hash when the answer was recorded. */
export type LedgerEdge = { seq: number; hash: string };
/** How a cited object was made, as the run recorded it: canonical, keys sorted, no times (ledgerMethods). */
export type LedgerMethod = Record<string, unknown>;
export type LedgerEntry = {
  /** 2: the chain covers the provenance too (ledgerCore). 3: and the fields below, when present. 4: and the interpretation and the answer's fields. */
  v?: 2 | 3 | 4;
  seq: number;
  kind: LedgerKind;
  /** ISO 8601 for an event, in UTC; optional for the other kinds. */
  ts?: string;
  /** What the agent wrote for `ts`, when it was not already the UTC value (an offset, a date alone). Not in the chain. */
  ts_raw?: string;
  value: string;
  /** Where it was seen: a path, a log, a plugin, a registry key. */
  source?: string;
  /** How to check it: the command, the inode, the record id, the hash. */
  evidence?: string;
  confidence?: (typeof LEDGER_CONFIDENCE)[number];
  /**
   * The seq of the entry this one corrects. Nothing is deleted: the older
   * entry stays where it was, and this one is the correction. In the chained
   * core when present, so a correction cannot be moved to another entry.
   */
  supersedes?: number;
  /**
   * The run's objects the entry rests on, each resolved when it was written:
   * input:<path>, job:<id>/<path>, import:<id>/<path>, member:<gen>#<n>,
   * sha256:<hex>, or unresolved:<why>. In the chained core when present.
   */
  refs?: string[];
  /** The goal sections the entry answers ("3", "Q3", "allegation-2"). */
  answers?: string[];
  /** Links to other entries: supports, contradicts, duplicates, derived_from. */
  rel?: LedgerRel[];
  /** The entry, or what it cites, holds a credential, a key or personal data a package must not carry out. */
  sensitive?: boolean;
  /** On an event: the clock the time came from ("NTFS $SI created", "device local, offset unknown"). */
  clock?: string;
  /** How precise the time is; a date alone is "date", never midnight UTC. */
  precision?: (typeof LEDGER_PRECISION)[number];
  /** Seen in the evidence, or reasoned from it. */
  basis?: (typeof LEDGER_BASIS)[number];
  /** A hypothesis's status. */
  status?: (typeof LEDGER_HYPOTHESIS_STATUS)[number];
  /** A limitation's reason. */
  reason?: (typeof LEDGER_LIMITATION_REASONS)[number];
  /** An absence's search: complete, or partial or failed (the rest is a limitation). */
  completion?: (typeof LEDGER_COMPLETION)[number];
  /** Who or what an action is attributed to, and on what. */
  attribution?: LedgerAttribution;
  /** Where in a cited object: a row, an offset, a record id. */
  locators?: LedgerLocator[];
  /** Why a correction corrects. */
  because?: string;
  /** Version 4, a finding: what the observation means, and the step from one to the other. */
  indicates?: string;
  /** Version 4: why that confidence — provenance, method, specificity, whether the sources depend on each other. */
  confidence_why?: string;
  /** Version 4, a finding: what else could explain it (required when basis is inferred). */
  alternatives?: LedgerAlternative[];
  /** Version 4, a finding: why no alternative was considered, in place of an empty list. */
  alternatives_none_why?: string;
  /** Version 4, a finding: what it means for the case, when the finder can say. */
  significance?: string;
  /** Version 4: why the kept output of a job that did not succeed still supports the entry. */
  qualifies?: LedgerQualify[];
  /** Version 4, written by the hub: how each cited object was made (a job, an import). */
  method?: LedgerMethod[];
  /** Version 4, an answer, written by the hub: hashes, paths, times, inodes, addresses and accounts in its text that no cited entry holds. */
  unsupported_tokens?: string[];
  /** Version 4, an answer: question:<id>, summary or narrative. */
  section?: string;
  /** Version 4, an answer: the reasoning, citing E-<seq> for each claim. */
  reasoning?: string;
  /** Version 4, an answer, written by the hub: the entries its text cites, by hash. */
  support?: LedgerEdge[];
  /** Version 4, an answer: the entries that say otherwise, by hash. */
  contrary?: LedgerEdge[];
  /** Version 4, an answer: the limitation entries that bound it, by hash. */
  limitations?: LedgerEdge[];
  /** Version 4, an answer: what else could still explain it. */
  alternatives_open?: string;
  /** Version 4, an answer: what evidence would change it. */
  would_change?: string;
  /** Version 4, an answer: expressly inconclusive. */
  inconclusive?: boolean;
  /** Version 4, an answer: its result, when it is one of LEDGER_ANSWER_RESULTS (premise_not_supported: the question's premise does not hold). */
  result?: (typeof LEDGER_ANSWER_RESULTS)[number];
  /** Version 4, an answer to a person's question: why no entry says otherwise, in place of an empty contrary. */
  contrary_none_why?: string;
  /**
   * Version 4, an answer to a question of the register: the revision of the
   * question it answers, checked against the register under its lock when it
   * is recorded. Absent is revision 1; an answer to an earlier revision than
   * the question's is stale.
   */
  question_rev?: number;
  /** Version 4, an answer: it says the event did not happen, not only that no evidence of it was found; the negative bar says when it may. */
  asserts_absence?: boolean;
  /**
   * A summary's or a narrative's symbolic citations (A4): each question it
   * cites as Q-<n>, the answer that stood then, and that answer's
   * fingerprint (its result, the revision it answers, and the hashes of what
   * it rests on, what says otherwise and what bounds it). A correction of
   * the answer that keeps the fingerprint (a wording change) leaves the
   * summary standing; one that changes its support, scope or contrary
   * evidence makes it be recorded again.
   */
  question_refs?: Array<{ q: string; section: string; answer: number; fp: string }>;
  /** A coverage record: the inventory revision its search saw (negative-bar.ts inventoryRevision). */
  inventory_rev?: string;
  /** A coverage record: the time range the search covered, or why it has none. */
  time_range?: string;
  /** A coverage record: how the search was made (the method), and with what settings. */
  search_method?: string;
  settings?: string;
  /** A coverage record: what the search actually covered, what it skipped or did not read, and what failed. */
  coverage_actual?: string;
  skipped?: string;
  failures?: string;
  /** A coverage record: the results the search produced: entries (E-<seq>) and job outputs (job:<id>[/<path>]). */
  result_refs?: string[];
  /**
   * A coverage record: each entry among its results (E-<seq>) by the hash it
   * had when the record was made. A result corrected, disputed or changed
   * after the record takes the record out of standing (coverageProblems).
   */
  result_bound?: LedgerEdge[];
  /** A coverage record: whether the event would have left a trace in these sources, given collection and retention, and why. */
  detection_opportunity?: { trace_expected: NB.TraceExpected; why: string };
  /** A coverage record, written by the hub: whether the jobs behind it were given every object it names (negative-bar.ts). */
  coverage?: "complete" | "partial";
  coverage_detail?: { units: NB.CoverageUnit[]; jobs: string[]; why: string[] };
  /** A coverage record, written by the hub: the planned routes of its questions that nothing under them examined. */
  not_examined?: Array<{ source: string; method: string; why: string }>;
  /** An external entry: where the material came from (LEDGER_SOURCE_CLASSES), written by the harness. */
  source_class?: (typeof LEDGER_SOURCE_CLASSES)[number];
  /** An external entry: who supplied it, when, from where, its sha256, what it may be used for (and, for a capture, its grant and request). */
  provenance?: { supplied_by: string; at: string; from: string; sha256?: string; permitted_use: string } & Record<string, unknown>;
  by: string;
  authors: string[];
  at: string;
  /** The chain: the previous entry's hash (or "genesis"), and this entry's own over its immutable core. */
  prev?: string;
  hash?: string;
};

/**
 * What of a ledger entry never changes once written: a merge adds an author
 * or a first citation, it does not move an event or reword a finding. The
 * chain is over this, so a merge leaves it intact and a rewritten entry
 * breaks it.
 */
/**
 * An entry's immutable core. From version 2 its provenance is in it too —
 * where it was seen, how to check it, how sure — since provenance is required
 * at creation and a merge only fills it in when it was empty, which a
 * version 2 entry never is: a rewritten source is a broken chain.
 */
/** The fields version 3 adds to the core, each only when present. */
function ledgerV3Fields(e: LedgerEntry): Record<string, unknown> {
  return {
    ...(e.answers?.length ? { answers: e.answers } : {}),
    ...(e.rel?.length ? { rel: e.rel.map((r) => ({ to: r.to, kind: r.kind })) } : {}),
    ...(e.sensitive ? { sensitive: true } : {}),
    ...(e.clock ? { clock: e.clock } : {}),
    ...(e.precision ? { precision: e.precision } : {}),
    ...(e.basis ? { basis: e.basis } : {}),
    ...(e.status ? { status: e.status } : {}),
    ...(e.reason ? { reason: e.reason } : {}),
    ...(e.completion ? { completion: e.completion } : {}),
    ...(e.attribution ? { attribution: { subject: e.attribution.subject, subject_type: e.attribution.subject_type, ...(e.attribution.basis_refs?.length ? { basis_refs: e.attribution.basis_refs } : {}) } } : {}),
    ...(e.locators?.length ? { locators: e.locators.map((l) => ({ ref: l.ref, at: l.at })) } : {}),
    ...(e.because ? { because: e.because } : {}),
  };
}

/**
 * A value with every object's keys sorted, arrays in their order: the form a
 * hub-written record takes in the core, so the line alone re-verifies
 * whatever order its keys were written in.
 */
export function canonicalValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalValue);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return Object.fromEntries(Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => [k, canonicalValue(o[k])]));
  }
  return v;
}

const edgesCore = (edges: LedgerEdge[]) => edges.map((x) => ({ seq: x.seq, hash: x.hash }));

/**
 * The fields version 4 adds to the core, each only when present: a finding's
 * interpretation, the hub's method records and token marks, and an answer's
 * fields. Nested objects are taken field by field, as version 3's are; the
 * method records whole, canonical.
 */
function ledgerV4Fields(e: LedgerEntry): Record<string, unknown> {
  return {
    ...(e.indicates ? { indicates: e.indicates } : {}),
    ...(e.confidence_why ? { confidence_why: e.confidence_why } : {}),
    ...(e.alternatives?.length ? { alternatives: e.alternatives.map((a) => ({ explanation: a.explanation, status: a.status, why: a.why, ...(a.test_refs?.length ? { test_refs: a.test_refs } : {}) })) } : {}),
    ...(e.alternatives_none_why ? { alternatives_none_why: e.alternatives_none_why } : {}),
    ...(e.significance ? { significance: e.significance } : {}),
    ...(e.qualifies?.length ? { qualifies: e.qualifies.map((q) => ({ ref: q.ref, why: q.why })) } : {}),
    ...(e.method?.length ? { method: e.method.map(canonicalValue) } : {}),
    ...(e.section ? { section: e.section } : {}),
    ...(e.reasoning ? { reasoning: e.reasoning } : {}),
    ...(e.support?.length ? { support: edgesCore(e.support) } : {}),
    ...(e.contrary?.length ? { contrary: edgesCore(e.contrary) } : {}),
    ...(e.limitations?.length ? { limitations: edgesCore(e.limitations) } : {}),
    ...(e.alternatives_open ? { alternatives_open: e.alternatives_open } : {}),
    ...(e.would_change ? { would_change: e.would_change } : {}),
    ...(e.inconclusive ? { inconclusive: true } : {}),
    ...(e.result ? { result: e.result } : {}),
    ...(e.contrary_none_why ? { contrary_none_why: e.contrary_none_why } : {}),
    ...(e.question_rev !== undefined ? { question_rev: e.question_rev } : {}),
    ...(e.question_refs?.length ? { question_refs: e.question_refs.map((r) => ({ q: r.q, section: r.section, answer: r.answer, fp: r.fp })) } : {}),
    ...(e.unsupported_tokens?.length ? { unsupported_tokens: e.unsupported_tokens } : {}),
    ...coverageFields(e),
    ...(e.source_class ? { source_class: e.source_class } : {}),
    ...(e.provenance ? { provenance: canonicalValue(e.provenance) } : {}),
  };
}

/**
 * The negative bar's fields in the core, each only when present: an
 * answer's assertion of absence, and a coverage record's own fields with
 * what the hub computed for it, canonical. An entry from before them gives
 * the core it always did.
 */
function coverageFields(e: LedgerEntry): Record<string, unknown> {
  return {
    ...(e.asserts_absence ? { asserts_absence: true } : {}),
    ...(e.inventory_rev ? { inventory_rev: e.inventory_rev } : {}),
    ...(e.time_range ? { time_range: e.time_range } : {}),
    ...(e.search_method ? { search_method: e.search_method } : {}),
    ...(e.settings ? { settings: e.settings } : {}),
    ...(e.coverage_actual ? { coverage_actual: e.coverage_actual } : {}),
    ...(e.skipped ? { skipped: e.skipped } : {}),
    ...(e.failures ? { failures: e.failures } : {}),
    ...(e.result_refs?.length ? { result_refs: e.result_refs } : {}),
    ...(e.result_bound?.length ? { result_bound: e.result_bound.map((x) => ({ seq: x.seq, hash: x.hash })) } : {}),
    ...(e.detection_opportunity ? { detection_opportunity: { trace_expected: e.detection_opportunity.trace_expected, why: e.detection_opportunity.why } } : {}),
    ...(e.coverage ? { coverage: e.coverage } : {}),
    ...(e.coverage_detail ? { coverage_detail: canonicalValue(e.coverage_detail) } : {}),
    ...(e.not_examined?.length ? { not_examined: e.not_examined.map((r) => ({ source: r.source, method: r.method, why: r.why })) } : {}),
  };
}

/**
 * What an entry says, without who said it or when: two entries with the same
 * content say the same thing. A correction that says the same thing is
 * refused; a second author saying the same thing is an attestation. From
 * version 4 what a finding indicates is part of what it says (another
 * indication is another claim), and so is why a failed job's bytes still
 * hold; an answer is all of its fields. An entry of an older version gives
 * the same content it always did.
 */
export function ledgerContent(e: LedgerEntry): string {
  const { because: _because, ...v3 } = ledgerV3Fields(e);
  const v4 =
    e.kind === "answer"
      ? (({ unsupported_tokens: _tokens, ...rest }) => rest)(ledgerV4Fields(e))
      : e.kind === "coverage"
        ? (({ coverage: _c, coverage_detail: _d, not_examined: _n, ...rest }) => ({ ...rest, ...(e.alternatives_open ? { alternatives_open: e.alternatives_open } : {}) }))(coverageFields(e))
        : { ...(e.indicates ? { indicates: e.indicates } : {}), ...(e.qualifies?.length ? { qualifies: e.qualifies.map((q) => ({ ref: q.ref, why: q.why })) } : {}) };
  return JSON.stringify({ kind: e.kind, ts: e.ts ?? "", value: e.value, source: e.source ?? "", evidence: e.evidence ?? "", confidence: e.confidence ?? "", refs: e.refs ?? [], ...v3, ...v4 });
}

/**
 * An entry's chained core, by its version: each version's bytes exactly as
 * they were when entries of it were written, so an old ledger verifies as it
 * always did. A version this harness does not know has no core of its own:
 * the whole line stands in, so nothing about it can change unseen, and the
 * verifier refuses it (verifyLedgerChain).
 */
export function ledgerCore(e: LedgerEntry): string {
  switch (e.v) {
    case 4:
      return JSON.stringify({ v: 4, seq: e.seq, kind: e.kind, ts: e.ts ?? "", value: e.value, source: e.source ?? "", evidence: e.evidence ?? "", confidence: e.confidence ?? "", ...(e.supersedes !== undefined ? { supersedes: e.supersedes } : {}), ...(e.refs?.length ? { refs: e.refs } : {}), ...ledgerV3Fields(e), ...ledgerV4Fields(e), by: e.by, at: e.at });
    case 3:
      return JSON.stringify({ v: 3, seq: e.seq, kind: e.kind, ts: e.ts ?? "", value: e.value, source: e.source ?? "", evidence: e.evidence ?? "", confidence: e.confidence ?? "", ...(e.supersedes !== undefined ? { supersedes: e.supersedes } : {}), ...(e.refs?.length ? { refs: e.refs } : {}), ...ledgerV3Fields(e), by: e.by, at: e.at });
    case 2:
      // `supersedes` only when there is one: every entry written before it
      // existed keeps the core, and the hash, it was chained with.
      // `refs` likewise: added, removed or changed after the fact, it breaks the chain.
      return JSON.stringify({ v: 2, seq: e.seq, kind: e.kind, ts: e.ts ?? "", value: e.value, source: e.source ?? "", evidence: e.evidence ?? "", confidence: e.confidence ?? "", ...(e.supersedes !== undefined ? { supersedes: e.supersedes } : {}), ...(e.refs?.length ? { refs: e.refs } : {}), by: e.by, at: e.at });
    case undefined:
      return JSON.stringify({ seq: e.seq, kind: e.kind, ts: e.ts ?? "", value: e.value, by: e.by, at: e.at });
    default: {
      const { prev: _prev, hash: _hash, ...line } = e as LedgerEntry & Record<string, unknown>;
      return JSON.stringify({ unknown_version: (e as { v?: unknown }).v ?? null, line: canonicalValue(line) });
    }
  }
}

export function ledgerHash(e: LedgerEntry, prev: string): string {
  return createHash("sha256").update(`${prev}\n${ledgerCore(e)}`).digest("hex");
}

/**
 * Walk the ledger's chain: every entry that carries `prev` must name the hash
 * of the entry before it, and its own hash must be what its core gives.
 * Entries written before the ledger was chained carry neither and are
 * counted unchained, not broken — but only before the first chained entry:
 * the first chained entry names the last of them (recordEntry links a legacy
 * entry by its core's hash from genesis), and an unchained line after a
 * chained one is a line added outside the chain, which breaks it. So is an
 * entry of an older version after a newer one (a version 1 entry after a
 * version 2 one, a 3 after a 4): the harness never writes one again, and its
 * core leaves out what the newer chain covers. A version this harness does
 * not know is refused, never read as the nearest one it does.
 */
export function verifyLedgerChain(text: string): { ok: boolean; total: number; chained: number; broken_at: number | null; reason: string | null; hashes: string[] } {
  let total = 0;
  let chained = 0;
  let last = "genesis";
  let newest = 1;
  const hashes: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let e: LedgerEntry;
    try {
      e = JSON.parse(line) as LedgerEntry;
    } catch {
      return { ok: false, total, chained, broken_at: total, reason: "not json", hashes };
    }
    if (e.v !== undefined && !(LEDGER_VERSIONS as readonly unknown[]).includes(e.v)) {
      return { ok: false, total, chained, broken_at: total, reason: `an entry of version ${JSON.stringify(e.v)}, which this harness does not know`, hashes };
    }
    const version = e.v ?? 1;
    if (version < newest) return { ok: false, total, chained, broken_at: total, reason: `a version ${version} entry after version ${newest} ones`, hashes };
    newest = version;
    if (!e.prev && !e.hash) {
      if (chained > 0) return { ok: false, total, chained, broken_at: total, reason: "an entry without the chain after chained ones", hashes };
      last = ledgerHash(e, "genesis");
      continue;
    }
    if (e.prev !== last) return { ok: false, total, chained, broken_at: total, reason: "prev does not name the entry before it", hashes };
    if (e.hash !== ledgerHash(e, e.prev)) return { ok: false, total, chained, broken_at: total, reason: "the entry's core was rewritten", hashes };
    chained += 1;
    last = e.hash;
    hashes.push(e.hash);
  }
  return { ok: true, total, chained, broken_at: null, reason: null, hashes };
}

export type LedgerInput = {
  kind: string;
  ts?: string;
  value: string;
  source?: string;
  evidence?: string;
  confidence?: string;
  /** The seq of an entry this one corrects. */
  supersedes?: number | string;
  /** The run's objects it rests on (LedgerEntry.refs); a list, or one string of them separated by commas or spaces. */
  refs?: string[] | string;
  answers?: string[] | string;
  rel?: Array<{ to: number | string; kind: string }>;
  sensitive?: boolean;
  clock?: string;
  precision?: string;
  basis?: string;
  status?: string;
  reason?: string;
  completion?: string;
  attribution?: { subject?: string; subject_type?: string; basis_refs?: string[] | string };
  locators?: Array<{ ref?: string; at?: string }>;
  because?: string;
  indicates?: string;
  confidence_why?: string;
  alternatives?: Array<{ explanation?: string; status?: string; why?: string; test_refs?: string[] | string }>;
  alternatives_none_why?: string;
  significance?: string;
  qualifies?: Array<{ ref?: string; why?: string }>;
  /** An answer's: question:<id> (or the id alone), summary or narrative. */
  section?: string;
  reasoning?: string;
  /** An answer's: the entries that say otherwise, by seq (12, "#12", "E-12"). */
  contrary?: Array<number | string> | string;
  /** An answer's: the limitation entries that bound it, by seq. */
  limitations?: Array<number | string> | string;
  alternatives_open?: string;
  would_change?: string;
  inconclusive?: boolean;
  /** An answer's result (LEDGER_ANSWER_RESULTS; premise_not_supported: the premise the question asks about does not hold). */
  result?: string;
  /** An answer to a person's question: why no entry says otherwise. */
  contrary_none_why?: string;
  /** An answer to a register question: the revision it answers (required once the question is amended past revision 1). */
  question_rev?: number | string;
  /** An answer: it says the event did not happen (only on an existence question whose coverage is complete and would have shown it). */
  asserts_absence?: boolean;
  /** A coverage record's own fields (kind coverage); its value is the proposition searched, its refs the objects. */
  proposition?: string;
  inventory_rev?: string;
  time_range?: string;
  search_method?: string;
  settings?: string;
  coverage_actual?: string;
  skipped?: string;
  failures?: string;
  result_refs?: string[] | string;
  detection_opportunity?: { trace_expected?: string; why?: string };
};

function listOf(v: string[] | string | undefined): string[] {
  return [...new Set((Array.isArray(v) ? v.map(String) : String(v ?? "").split(/[\s,]+/)).map((x) => x.trim()).filter(Boolean))];
}

function oneOf<T extends readonly string[]>(name: string, v: unknown, allowed: T): { ok: true; value?: T[number] } | { ok: false; reason: string } {
  const text = String(v ?? "").trim().toLowerCase();
  if (!text) return { ok: true };
  if (!(allowed as readonly string[]).includes(text)) return { ok: false, reason: `${name} must be one of ${allowed.join(", ")}` };
  return { ok: true, value: text as T[number] };
}

/**
 * The version 3 fields an input carries, checked. `rel` is checked against
 * the ledger inside the lock (recordEntry); the rest needs nothing but the
 * input and, for attribution's refs, the run.
 */
async function ledgerV3Input(
  sandboxRoot: string,
  input: LedgerInput,
  kind: string,
  refs: string[],
  hasTs: boolean,
  tsRaw: string | undefined,
  superseding: boolean,
): Promise<{ ok: true; fields: Partial<LedgerEntry>; rel: Array<{ to: number; kind: (typeof LEDGER_REL_KINDS)[number] }> } | { ok: false; reason: string }> {
  const fields: Partial<LedgerEntry> = {};
  const answers = listOf(input.answers);
  if (answers.length > LEDGER_MAX_ANSWERS) return { ok: false, reason: `answers names ${answers.length} sections, more than ${LEDGER_MAX_ANSWERS}` };
  const badAnswer = answers.find((a) => !LEDGER_ANSWER_ID.test(a));
  if (badAnswer) return { ok: false, reason: `answers takes the goal's section ids, 1-16 letters, digits, dot, dash or underscore ("3", "Q3", "allegation-2"; got ${JSON.stringify(badAnswer)})` };
  if (answers.length) fields.answers = answers;
  const rel: Array<{ to: number; kind: (typeof LEDGER_REL_KINDS)[number] }> = [];
  for (const r of Array.isArray(input.rel) ? input.rel : []) {
    const to = Number(String(r?.to ?? "").trim().replace(/^#/, ""));
    if (!Number.isInteger(to) || to < 1) return { ok: false, reason: `rel.to names an entry by its seq, a whole number (got ${JSON.stringify(r?.to)})` };
    const k = oneOf("rel.kind", r?.kind, LEDGER_REL_KINDS);
    if (!k.ok) return k;
    if (!k.value) return { ok: false, reason: `rel.kind is required: ${LEDGER_REL_KINDS.join(", ")}` };
    if (!rel.some((x) => x.to === to && x.kind === k.value)) rel.push({ to, kind: k.value });
  }
  if (rel.length > LEDGER_MAX_REL) return { ok: false, reason: `rel links ${rel.length} entries, more than ${LEDGER_MAX_REL}` };
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") return { ok: false, reason: "sensitive is true or false" };
  if (input.sensitive === true) fields.sensitive = true;
  const clock = String(input.clock ?? "").trim();
  if (clock) {
    if (!hasTs) return { ok: false, reason: "clock names the clock an entry's ts came from: give ts too" };
    if (clock.length > LEDGER_CLOCK_MAX_CHARS) return { ok: false, reason: `clock is over ${LEDGER_CLOCK_MAX_CHARS} characters: name the clock ("NTFS $SI created", "device local, offset unknown")` };
    fields.clock = clock;
  }
  const precision = oneOf("precision", input.precision, LEDGER_PRECISION);
  if (!precision.ok) return precision;
  if (precision.value && !hasTs) return { ok: false, reason: "precision says how precise an entry's ts is: give ts too" };
  // A date alone is a day, not midnight UTC: said, unless the agent said otherwise.
  const dateOnly = tsRaw !== undefined && /^\d{4}-\d{2}-\d{2}$/.test(tsRaw.trim());
  if (precision.value) fields.precision = precision.value;
  else if (dateOnly) fields.precision = "date";
  const basis = oneOf("basis", input.basis, LEDGER_BASIS);
  if (!basis.ok) return basis;
  if (basis.value) fields.basis = basis.value;
  const status = oneOf("status", input.status, LEDGER_HYPOTHESIS_STATUS);
  if (!status.ok) return status;
  if (status.value && kind !== "hypothesis") return { ok: false, reason: "status is a hypothesis's: open, supported or refuted" };
  if (kind === "hypothesis") fields.status = status.value ?? "open";
  const reason = oneOf("reason", input.reason, LEDGER_LIMITATION_REASONS);
  if (!reason.ok) return reason;
  if (reason.value && kind !== "limitation") return { ok: false, reason: "reason is a limitation's: why the examination could not establish it" };
  if (kind === "limitation") {
    if (!reason.value) return { ok: false, reason: `a limitation needs a reason: ${LEDGER_LIMITATION_REASONS.join(", ")}` };
    fields.reason = reason.value;
  }
  const completion = oneOf("completion", input.completion, LEDGER_COMPLETION);
  if (!completion.ok) return completion;
  if (completion.value && kind !== "absence") return { ok: false, reason: "completion is an absence's: how far the search got (complete, partial, failed)" };
  if (completion.value) fields.completion = completion.value;
  if (input.attribution !== undefined && input.attribution !== null) {
    const a = input.attribution;
    const subject = String(a.subject ?? "").trim();
    if (!subject) return { ok: false, reason: "attribution.subject is required: the account, device or person" };
    if (subject.length > LEDGER_SUBJECT_MAX_CHARS) return { ok: false, reason: `attribution.subject is over ${LEDGER_SUBJECT_MAX_CHARS} characters` };
    const type = oneOf("attribution.subject_type", a.subject_type ?? "unknown", LEDGER_SUBJECT_TYPES);
    if (!type.ok) return type;
    const basisRefs = listOf(a.basis_refs);
    if (basisRefs.length > LEDGER_MAX_REFS) return { ok: false, reason: `attribution.basis_refs names more than ${LEDGER_MAX_REFS} objects` };
    if (basisRefs.length) {
      const checked = await checkRefs(sandboxRoot, basisRefs);
      if (!checked.ok) return { ok: false, reason: `attribution.basis_refs: ${checked.reason}` };
    }
    fields.attribution = { subject, subject_type: type.value ?? "unknown", ...(basisRefs.length ? { basis_refs: basisRefs } : {}) };
  }
  const locators: LedgerLocator[] = [];
  for (const l of Array.isArray(input.locators) ? input.locators : []) {
    const ref = String(l?.ref ?? "").trim();
    const at = String(l?.at ?? "").trim();
    if (!ref || !at) return { ok: false, reason: "a locator is {ref, at}: one of the entry's refs, and where in it (a row, an offset, a record id)" };
    if (!refs.includes(ref)) return { ok: false, reason: `locator ref ${JSON.stringify(ref)} is not one of the entry's refs` };
    if (at.length > LEDGER_LOCATOR_MAX_CHARS) return { ok: false, reason: `a locator's at is over ${LEDGER_LOCATOR_MAX_CHARS} characters` };
    locators.push({ ref, at });
  }
  if (locators.length > LEDGER_MAX_LOCATORS) return { ok: false, reason: `locators names more than ${LEDGER_MAX_LOCATORS} places` };
  if (locators.length) fields.locators = locators;
  const because = String(input.because ?? "").trim();
  if (because) {
    if (!superseding) return { ok: false, reason: "because says why a correction corrects: give supersedes too" };
    if (because.length > LEDGER_BECAUSE_MAX_CHARS) return { ok: false, reason: `because is over ${LEDGER_BECAUSE_MAX_CHARS} characters` };
    fields.because = because;
  }
  return { ok: true, fields, rel };
}

/** The fields only an answer takes, and only a finding takes: named in a refusal when they come with another kind. */
const ANSWER_ONLY_FIELDS = ["section", "reasoning", "contrary", "limitations", "alternatives_open", "would_change", "inconclusive", "result", "contrary_none_why", "asserts_absence", "question_rev"] as const;
const FINDING_ONLY_FIELDS = ["indicates", "alternatives", "alternatives_none_why", "significance"] as const;
/** The fields only a coverage record takes. */
const COVERAGE_ONLY_FIELDS = ["proposition", "inventory_rev", "time_range", "search_method", "settings", "coverage_actual", "skipped", "failures", "result_refs", "result_bound", "detection_opportunity"] as const;

function given(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "string") return v.trim() !== "";
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

function boundedText(name: string, v: unknown, max: number): { ok: true; value: string } | { ok: false; reason: string } {
  const text = String(v ?? "").trim();
  if (text.length > max) return { ok: false, reason: `${name} is over ${max} characters: say it in fewer, and put the material itself in a work/ file cited by a job` };
  return { ok: true, value: text };
}

/**
 * The version 4 fields a non-answer input carries, checked. A finding is an
 * observation and what the finder makes of it, written while the artefact is
 * open: `basis`, `confidence`, `indicates` and `confidence_why` are required
 * on it, and when it is inferred, what else could explain it (or why nothing
 * else was considered: an invented alternative is worse than none). A ref
 * whose job did not succeed needs `qualifies` on a finding (why those bytes
 * are still usable), and can never show that something is absent. Nothing
 * here weighs the confidence: it is the quality of the evidence, which the
 * finder states and a reader judges.
 */
async function ledgerV4Input(
  sandboxRoot: string,
  input: LedgerInput,
  kind: string,
  refs: string[],
  failed: Array<{ ref: string; status: string }>,
  basis: string | undefined,
  confidence: string,
): Promise<{ ok: true; fields: Partial<LedgerEntry> } | { ok: false; reason: string }> {
  const raw = input as Record<string, unknown>;
  const answerOnly = ANSWER_ONLY_FIELDS.find((f) => given(raw[f]));
  if (answerOnly) return { ok: false, reason: `${answerOnly} is an answer's: record kind=answer with its section to answer a question` };
  const coverageOnly = COVERAGE_ONLY_FIELDS.find((f) => given(raw[f]));
  if (coverageOnly) return { ok: false, reason: `${coverageOnly} is a coverage record's: record kind=coverage for what a negative was searched over` };
  if (kind !== "finding") {
    const findingOnly = FINDING_ONLY_FIELDS.find((f) => given(raw[f]));
    if (findingOnly) return { ok: false, reason: `${findingOnly} is a finding's: what an observation indicates and what else could explain it are recorded on kind=finding` };
  }
  const fields: Partial<LedgerEntry> = {};
  const why = boundedText("confidence_why", input.confidence_why, LEDGER_WHY_MAX_CHARS);
  if (!why.ok) return why;
  if (why.value && !confidence) return { ok: false, reason: "confidence_why says why that confidence: give confidence too" };
  if (why.value) fields.confidence_why = why.value;
  // What a failed job's kept bytes are still good for, ref by ref.
  const qualifies: LedgerQualify[] = [];
  for (const q of Array.isArray(input.qualifies) ? input.qualifies : []) {
    const ref = String(q?.ref ?? "").trim();
    const text = boundedText("a qualifies why", q?.why, LEDGER_WHY_MAX_CHARS);
    if (!text.ok) return text;
    if (!ref || !text.value) return { ok: false, reason: "qualifies is [{ref, why}]: one of the entry's refs whose job did not succeed, and why its kept bytes still support this entry" };
    if (!refs.includes(ref)) return { ok: false, reason: `qualifies names ${JSON.stringify(ref)}, which is not one of the entry's refs` };
    if (!failed.some((f) => f.ref === ref)) return { ok: false, reason: `qualifies names ${ref}, whose job succeeded: it qualifies only the output of a job that did not` };
    if (!qualifies.some((x) => x.ref === ref)) qualifies.push({ ref, why: text.value });
  }
  if (qualifies.length > LEDGER_MAX_QUALIFIES) return { ok: false, reason: `qualifies names more than ${LEDGER_MAX_QUALIFIES} refs` };
  if (qualifies.length && (kind === "limitation" || kind === "absence")) {
    return { ok: false, reason: `qualifies says why a failed job's bytes still support a claim; a ${kind} rests on what could not be done, and says so in its own fields` };
  }
  if (failed.length && kind === "absence" && (input.completion === undefined || String(input.completion).trim().toLowerCase() === "complete" || String(input.completion).trim() === "")) {
    return { ok: false, reason: `the output of a job that did not succeed cannot show that something is absent (${failed.map((f) => `${f.ref}: ${f.status}`).join(", ")}): record the search with completion partial or failed, and what was not reached as kind=limitation` };
  }
  if (kind === "finding") {
    const missing = failed.filter((f) => !qualifies.some((q) => q.ref === f.ref));
    if (missing.length) {
      return { ok: false, reason: `this finding rests on the kept output of a job that did not succeed (${missing.map((f) => `${f.ref}: ${f.status}`).join(", ")}): say in qualifies [{ref, why}] why those bytes are still usable, or cite the output of a job that worked` };
    }
  }
  if (qualifies.length) fields.qualifies = qualifies;
  if (kind !== "finding") return { ok: true, fields };
  if (!basis) return { ok: false, reason: "a finding says whether it was seen in the evidence or reasoned from it: basis observed or inferred" };
  if (!confidence) return { ok: false, reason: "a finding says how sure: confidence high, medium or low, with confidence_why" };
  const indicates = boundedText("indicates", input.indicates, LEDGER_INDICATES_MAX_CHARS);
  if (!indicates.ok) return indicates;
  if (!indicates.value) return { ok: false, reason: "indicates is required on a finding: what the observation means, and the step from one to the other, in one to three sentences" };
  fields.indicates = indicates.value;
  if (!fields.confidence_why) {
    return { ok: false, reason: "confidence_why is required on a finding: where the data came from, whether the method is reliable for it, how specific the observation is, and whether your sources depend on each other" };
  }
  const alternatives: LedgerAlternative[] = [];
  for (const a of Array.isArray(input.alternatives) ? input.alternatives : []) {
    const explanation = boundedText("an alternative's explanation", a?.explanation, LEDGER_WHY_MAX_CHARS);
    if (!explanation.ok) return explanation;
    const aWhy = boundedText("an alternative's why", a?.why, LEDGER_WHY_MAX_CHARS);
    if (!aWhy.ok) return aWhy;
    const status = oneOf("an alternative's status", a?.status, LEDGER_ALTERNATIVE_STATUS);
    if (!status.ok) return status;
    if (!explanation.value || !status.value || !aWhy.value) return { ok: false, reason: "an alternative is {explanation, status: rejected | open, why, test_refs?}: what else could explain it, whether it was rejected or is still open, and why" };
    const testRefs = listOf(a?.test_refs);
    if (testRefs.length > LEDGER_MAX_REFS) return { ok: false, reason: `an alternative's test_refs names more than ${LEDGER_MAX_REFS} objects` };
    if (testRefs.length) {
      const checked = await checkRefs(sandboxRoot, testRefs);
      if (!checked.ok) return { ok: false, reason: `an alternative's test_refs: ${checked.reason}` };
    }
    alternatives.push({ explanation: explanation.value, status: status.value, why: aWhy.value, ...(testRefs.length ? { test_refs: testRefs } : {}) });
  }
  if (alternatives.length > LEDGER_MAX_ALTERNATIVES) return { ok: false, reason: `alternatives lists more than ${LEDGER_MAX_ALTERNATIVES}: keep the ones a reader must weigh` };
  const noneWhy = boundedText("alternatives_none_why", input.alternatives_none_why, LEDGER_WHY_MAX_CHARS);
  if (!noneWhy.ok) return noneWhy;
  if (noneWhy.value && alternatives.length) return { ok: false, reason: "alternatives_none_why says no alternative was considered: give it or the alternatives, not both" };
  if (basis === "inferred" && !alternatives.length && !noneWhy.value) {
    return { ok: false, reason: "an inferred finding lists what else could explain it in alternatives [{explanation, status: rejected | open, why}], or says in alternatives_none_why why none was considered; never invent one" };
  }
  if (alternatives.length) fields.alternatives = alternatives;
  if (noneWhy.value) fields.alternatives_none_why = noneWhy.value;
  const significance = boundedText("significance", input.significance, LEDGER_WHY_MAX_CHARS);
  if (!significance.ok) return significance;
  if (significance.value) fields.significance = significance.value;
  return { ok: true, fields };
}

/**
 * How each object an entry cites was made, as the run recorded it: one
 * canonical record per job (its kind, the command or the tool with its sha256
 * and arguments, the recipe, the image and its digest, the scope it declared,
 * its network, how it ended), or per import. It describes recorded
 * execution, not the reads a tool made, and what the run did not record
 * stays "unknown". No times: the same job gives the same record. A ref kind
 * whose making is recorded elsewhere joins METHOD_DERIVERS; `tool:` and
 * `trace:` refs join once their grammar is fixed with the job service.
 */
export async function ledgerMethods(sandboxRoot: string, refs: string[]): Promise<LedgerMethod[]> {
  const out = new Map<string, LedgerMethod>();
  for (const ref of refs) {
    const m = /^([a-z0-9]+):(.*)$/s.exec(ref);
    const derive = m ? METHOD_DERIVERS[m[1]] : undefined;
    if (!derive || !m) continue;
    const got = await derive(sandboxRoot, m[2]).catch(() => null);
    if (got && !out.has(got.key)) out.set(got.key, canonicalValue(got.method) as LedgerMethod);
  }
  return [...out.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([, v]) => v);
}

type JobJson = {
  id?: string;
  spec?: { kind?: string; tool?: string; args?: unknown; command?: string; recipe?: string; target?: { ref?: string; name?: string }; targets?: Array<{ ref?: string; name?: string }>; inputs?: string[]; source?: string; network?: string; profile?: string };
  requester?: { agent?: string };
  status?: string;
  exit?: number | null;
  image?: string;
  image_digest?: string;
  tool_sha256?: string;
};

/** A job's method record, from its job.json beside its sealed output. */
async function jobMethod(sandboxRoot: string, id: string): Promise<{ key: string; method: LedgerMethod } | null> {
  if (!/^[a-z0-9-]{1,64}$/.test(id)) return null;
  const job = await readFile(join(sandboxRoot, "store", "jobs", id, "job.json"), "utf8")
    .then((t) => JSON.parse(t) as JobJson)
    .catch(() => null);
  if (!job) return { key: `job:${id}`, method: { kind: "job", job: id, record: "no job.json: how it was made is unknown" } };
  const s = job.spec ?? {};
  const method: LedgerMethod = {
    kind: s.kind === "import" ? "import" : "job",
    job: id,
    job_kind: s.kind ?? "unknown",
    status: job.status ?? "unknown",
    ...(job.exit !== undefined ? { exit: job.exit } : {}),
    image: job.image ?? "unknown",
    image_digest: job.image_digest ?? "unknown",
    declared_scope: Array.isArray(s.inputs) ? s.inputs : "unknown",
    network: s.network ?? "unknown",
    ...(s.profile ? { profile: s.profile } : {}),
  };
  if (s.kind === "tool") Object.assign(method, { tool: s.tool ?? "unknown", tool_sha256: job.tool_sha256 ?? "unknown", tool_version: "unknown", args: s.args ?? {} });
  else if (s.kind === "command") Object.assign(method, { command: s.command ?? "" });
  else if (s.kind === "recipe") Object.assign(method, { recipe: s.recipe ?? "unknown", recipe_sha256: job.tool_sha256 ?? "unknown", target: s.target?.ref ?? s.target?.name ?? "unknown" });
  else if (s.kind === "detect") Object.assign(method, { targets: (s.targets ?? []).map((t) => t.ref ?? t.name ?? "unknown") });
  else if (s.kind === "import") {
    // The job copied the file; who made it, and how, the run did not record.
    Object.assign(method, { source: s.source ?? "unknown", produced_by: `${job.requester?.agent ?? "unknown"}, in its own VM; how the file was made is not recorded`, copied_live: true });
  }
  return { key: `job:${id}`, method };
}

const METHOD_DERIVERS: Record<string, (sandboxRoot: string, value: string) => Promise<{ key: string; method: LedgerMethod } | null>> = {
  job: (S, value) => jobMethod(S, value.split("/")[0]),
  // A brain's own file brought into store/imports: its making is not recorded.
  import: async (_S, value) => {
    const id = value.split("/")[0];
    return /^[a-z0-9-]{1,64}$/.test(id) ? { key: `import:${id}`, method: { kind: "import", import: id, produced_by: "unknown: a file brought into the store; how it was made is not recorded" } } : null;
  },
  // An archive member of the catalogue: the recipe job that listed it.
  member: async (S, value) => {
    const gen = /^([a-z0-9-]+)#\d+$/.exec(value)?.[1];
    if (!gen) return null;
    const g = await readFile(join(S, "catalog", "gen", gen, "generation.json"), "utf8")
      .then((t) => JSON.parse(t) as { job?: string })
      .catch(() => null);
    return g?.job ? jobMethod(S, g.job) : null;
  },
};

/**
 * The seq each corrected entry is superseded by. A correction of a correction
 * names the one it replaces, so following the map from any entry reaches the
 * one that stands.
 */
export function supersededBy(entries: LedgerEntry[]): Map<number, number> {
  const out = new Map<number, number>();
  for (const e of entries) if (typeof e.supersedes === "number") out.set(e.supersedes, e.seq);
  return out;
}

export type LedgerResult =
  | { ok: true; entry: LedgerEntry; merged: boolean; total: number; note?: string }
  | { ok: false; reason: string };

/** The names closest to `want`: the same base name first, then by edit distance. */
function nearestNames(want: string, names: string[], n = 5): string[] {
  const base = (x: string) => x.slice(x.lastIndexOf("/") + 1).toLowerCase();
  const dist = (a: string, b: string) => {
    a = a.slice(-200);
    b = b.slice(-200);
    let row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i += 1) {
      const next = [i];
      for (let j = 1; j <= b.length; j += 1) next.push(Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)));
      row = next;
    }
    return row[b.length];
  };
  return names
    .map((x) => ({ x, d: (base(x) === base(want) ? 0 : 1000) + dist(x.toLowerCase(), want.toLowerCase()) }))
    .sort((a, b) => a.d - b.d)
    .slice(0, n)
    .map((r) => r.x);
}

/**
 * Every ref resolved against the run as it is now, or the first that is not,
 * with the names nearest to it: a typo costs one turn, where a wrong ref on
 * the chain would stand for good.
 */
export async function checkRefs(sandboxRoot: string, refs: string[]): Promise<{ ok: true; resolved: Array<{ ref: string; kind: string; status?: string }> } | { ok: false; reason: string }> {
  // Loaded when a ref is checked, not with the extension: a VM that mounts
  // only extensions/ still loads it, and in a VM the hub checks refs anyway.
  const { readManifest, resolveRef, storePaths } = await import("../scripts/evidence-store.ts");
  const resolved: Array<{ ref: string; kind: string; status?: string }> = [];
  for (const ref of refs) {
    const r = await resolveRef(sandboxRoot, ref);
    if (r.ok) {
      resolved.push({ ref, kind: r.kind, ...(r.status ? { status: r.status } : {}) });
      continue;
    }
    let near: string[] = [];
    const m = /^(job|import|input):(.*)$/s.exec(ref);
    try {
      if (m && m[1] === "input") {
        const inputs = JSON.parse(await readFile(join(sandboxRoot, "inputs.json"), "utf8")) as { files?: Array<{ path: string }> };
        near = nearestNames(m[2].startsWith("inputs/") ? m[2] : `inputs/${m[2]}`, (inputs.files ?? []).map((f) => f.path)).map((p) => `input:${p.replace(/^inputs\//, "")}`);
      } else if (m) {
        const slash = m[2].indexOf("/");
        const id = slash < 0 ? m[2] : m[2].slice(0, slash);
        const P = storePaths(sandboxRoot);
        const found = await readManifest(join(m[1] === "job" ? P.jobs : P.imports, id, "manifest.json"));
        if (found && slash >= 0) near = nearestNames(m[2].slice(slash + 1), found.manifest.files.map((f) => f.path)).map((p) => `${m[1]}:${id}/${p}`);
        else if (!found) near = nearestNames(id, await readdir(m[1] === "job" ? P.jobs : P.imports).catch(() => [])).map((x) => `${m[1]}:${x}`);
      }
    } catch {
      near = [];
    }
    return { ok: false, reason: `ref ${JSON.stringify(ref)} does not resolve: ${r.reason}${near.length ? `; nearest: ${near.join(", ")}` : ""}. A ref names an object of this run (input:<path>, job:<id>/<path>, import:<id>/<path>, member:<gen>#<n>, sha256:<hex>, or a brain's own output: tool:<seat>/<file> under tool-output/, trace:<sha256> of one trace line, which the hub seals first and cites as the import it became), or says why none can be named (unresolved:<why>).` };
  }
  return { ok: true, resolved };
}

const TS_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const TS_DATE_TIME = /^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)(Z|z|[+-]\d{2}:?\d{2})?$/;

/**
 * An event's time, in UTC, from what the agent wrote. A date and a time
 * must say their zone: `Z`, or the offset the source records. ECMAScript
 * reads a date-time without one as the host's local time, so the same
 * entry was 12:44Z on the droplet, 09:44Z on a Mac in Istanbul and 17:44Z
 * in New York, and the text it came from was gone. A date alone is a date.
 * Nothing else (01/02/2024 is two different days) is taken. What the agent
 * wrote is kept beside the UTC value when the two differ.
 */
export function normalizeTs(raw: string | undefined): { ok: true; ts?: string; raw?: string } | { ok: false; reason: string } {
  const text = (raw ?? "").trim();
  if (!text) return { ok: true };
  let iso: string;
  if (TS_DATE.test(text)) {
    iso = `${text}T00:00:00Z`;
  } else {
    const m = TS_DATE_TIME.exec(text);
    if (!m) {
      return { ok: false, reason: `ts must be ISO 8601 with its zone, e.g. 2024-01-15T12:44:22Z or 2024-01-15T15:44:22+03:00 (got ${JSON.stringify(text)})` };
    }
    if (!m[3]) {
      return {
        ok: false,
        reason: `ts ${JSON.stringify(text)} has no zone: add Z if the source's time is UTC, or the offset the source records (+03:00). The time zone is part of the evidence; the harness does not guess it.`,
      };
    }
    const zone = /^[Zz]$/.test(m[3]) ? "Z" : m[3].length === 5 ? `${m[3].slice(0, 3)}:${m[3].slice(3)}` : m[3];
    iso = `${m[1]}T${m[2]}${zone}`;
  }
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return { ok: false, reason: `ts is not a real time (got ${JSON.stringify(text)})` };
  const ts = new Date(ms).toISOString();
  return { ok: true, ts, ...(ts !== text ? { raw: text } : {}) };
}

/**
 * The ledger's entries, each with its attestations' authors folded into
 * `authors` (in memory: entries.jsonl is never rewritten). `raw` gives the
 * lines as written.
 */
export async function readLedger(sandboxRoot: string, opts: { raw?: boolean } = {}): Promise<LedgerEntry[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_ENTRIES), "utf8").catch(() => "");
  const out: LedgerEntry[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerEntry);
    } catch {
      // a torn line is skipped, not fatal
    }
  }
  return opts.raw ? out : withAttestations(sandboxRoot, out);
}

/** Append one entry, merging with an equal one, and re-render ledger.md. */
export async function recordEntry(ctx: SwarmContext, input: LedgerInput): Promise<LedgerResult> {
  // Q-<n> names a question of the register: its section, which is n unless
  // the goal gave it its own id.
  if (typeof input.section === "string" && /^(question:)?Q-\d/i.test(input.section.trim())) input = { ...input, section: await registerSection(ctx.sandboxRoot, input.section) };
  if (input.answers !== undefined && (Array.isArray(input.answers) ? input.answers : String(input.answers).split(/[\s,]+/)).some((a) => /^Q-\d/i.test(String(a).trim()))) {
    const list = Array.isArray(input.answers) ? input.answers.map(String) : String(input.answers).split(/[\s,]+/);
    input = { ...input, answers: await Promise.all(list.map((a) => registerSection(ctx.sandboxRoot, a.trim()))) };
  }
  const kind = String(input.kind ?? "").trim().toLowerCase();
  if (!(LEDGER_KINDS as readonly string[]).includes(kind)) {
    return { ok: false, reason: `kind must be one of ${LEDGER_KINDS.join(", ")}` };
  }
  if (kind === "external") return { ok: false, reason: "external material is recorded by the harness when it enters the run (a capture the fetch service sealed, material the operator supplied), with its provenance: cite it (net:<k>/<n>, E-<seq>) and record what it establishes as a finding of yours" };
  if (kind === "answer") return recordAnswer(ctx, input);
  if (kind === "coverage") return recordCoverage(ctx, input);
  const absence = kind === "absence";
  const limitation = kind === "limitation";
  const value = String(input.value ?? "").trim();
  if (!value) {
    return {
      ok: false,
      reason: absence
        ? "value is required: what was looked for and not found, in one sentence"
        : limitation
          ? "value is required: what the examination could not establish, in one sentence"
          : kind === "hypothesis"
            ? "value is required: the proposition under test, in one sentence"
            : "value is required: the event, the indicator or the finding, in one sentence",
    };
  }
  if (value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `value is over ${LEDGER_VALUE_MAX_CHARS} characters` };
  const ts = normalizeTs(input.ts);
  if (!ts.ok) return ts;
  if (kind === "event" && !ts.ts) return { ok: false, reason: "an event needs a ts (ISO 8601 with its zone: Z for UTC, or the source's offset)" };
  const confidence = String(input.confidence ?? "").trim().toLowerCase();
  if (confidence && !(LEDGER_CONFIDENCE as readonly string[]).includes(confidence)) {
    return { ok: false, reason: `confidence must be one of ${LEDGER_CONFIDENCE.join(", ")}` };
  }
  // Provenance is not optional. Across fifteen cases every one of 1501
  // ledger entries already carried both, so this costs a working run
  // nothing; what it stops is the entry that reads like a conclusion and
  // cannot be checked, which is the one a reader has no way to spot.
  const source = String(input.source ?? "").trim();
  if (!source) {
    return {
      ok: false,
      reason: absence
        ? "source is required: what was searched — the path, image, log or artefact the search ran over. 'Not found' is only ever 'not found there'."
        : limitation
          ? "source is required: what could not be examined — the object, volume, artefact or scope"
          : "source is required: where it was seen — a path, a log, a plugin, a registry key",
    };
  }
  if (source.length > LEDGER_SOURCE_MAX_CHARS) {
    return { ok: false, reason: `source is over ${LEDGER_SOURCE_MAX_CHARS} characters: name where it was seen, and put the material itself in a work/ file` };
  }
  const evidence = String(input.evidence ?? "").trim();
  if (!evidence) {
    return {
      ok: false,
      reason: absence
        ? "evidence is required: the query, the tool and its version, and the scope searched — allocated files only, or unallocated space and slack too, and the time range. An empty result holds only for that query and that scope."
        : limitation
          ? "evidence is required: what was tried and why it could not be done — the command, the error, the missing key or tool"
          : "evidence is required: how to check it — the command, the inode, the record id, the hash",
    };
  }
  if (evidence.length > LEDGER_EVIDENCE_MAX_CHARS) {
    return { ok: false, reason: `evidence is over ${LEDGER_EVIDENCE_MAX_CHARS} characters: say how to check it, and put the material itself in a work/ file` };
  }
  const refs = [...new Set((Array.isArray(input.refs) ? input.refs.map(String) : String(input.refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))];
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names ${refs.length} objects, more than ${LEDGER_MAX_REFS}: name the ones the entry rests on, and the rest in evidence` };
  const long = refs.find((r) => r.length > LEDGER_REF_MAX_CHARS);
  if (long) return { ok: false, reason: `a ref is over ${LEDGER_REF_MAX_CHARS} characters: ${JSON.stringify(long.slice(0, 80))}…` };
  // The refs whose job did not succeed, as resolveRef reads the job's own status.
  const failed: Array<{ ref: string; status: string }> = [];
  if (refs.length) {
    const checked = await checkRefs(ctx.sandboxRoot, refs);
    if (!checked.ok) return checked;
    for (const r of checked.resolved) if (r.kind === "job" && r.status && r.status !== "ok") failed.push({ ref: r.ref, status: r.status });
  }
  // A finding with no ref is taken, and told what would let a reader check
  // it: the ask rides in the answer, never as an error.
  // A file in an agent's own work/ is what the #10 reports cited in prose:
  // said by name, with the way to make it an object of the run.
  const workFile = /(?:^|[\s`'"(])(?:\.\/)?(work\/[^\s`'",;)]+)/.exec(`${source} ${evidence}`)?.[1];
  const note =
    kind === "finding" && !refs.length
      ? workFile
        ? `no object of the run cited: ${workFile} is a file in an agent's own work/, which a reader cannot check against the run's record; seal it with job_run import=${workFile} (or run the work that made it as a job) and cite it as job:<id>/<path> in refs, then record this again with its refs`
        : "no object of the run cited: add refs (job:<id>/<path>, input:<path>, member:<gen>#<n>, sha256:<hex>, or unresolved:<why>) so a reader can check it; to add them to this entry, record it again with its refs"
      : undefined;
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})` };
    supersedes = n;
  }
  const v3 = await ledgerV3Input(ctx.sandboxRoot, input, kind, refs, Boolean(ts.ts), typeof input.ts === "string" ? input.ts : undefined, supersedes !== undefined);
  if (!v3.ok) return v3;
  const v4 = await ledgerV4Input(ctx.sandboxRoot, input, kind, refs, failed, v3.fields.basis, confidence);
  if (!v4.ok) return v4;
  // How each cited object was made, as the run recorded it: written by the
  // hub into the entry and its core, so the line alone says it.
  const method = refs.length ? await ledgerMethods(ctx.sandboxRoot, refs) : [];
  // An object a failed or cancelled job left is kept and citable (ADR 0010),
  // and said: an answer resting on it should not read as resting on a job that
  // worked. A finding says why in qualifies (ledgerV4Input); another kind is told.
  const notes: string[] = [];
  if (note) notes.push(note);
  const unqualified = failed.filter((f) => !(v4.fields.qualifies ?? []).some((q) => q.ref === f.ref));
  if (unqualified.length) {
    notes.push(`rests on the kept output of a job that did not succeed: ${unqualified.map((f) => `${f.ref} (job ${f.ref.slice(4).split("/")[0]}: ${f.status})`).join(", ")}; say why those bytes are still usable in qualifies [{ref, why}], or cite the output of a job that worked`);
  }
  if (v3.fields.completion && v3.fields.completion !== "complete") {
    notes.push(`the search was ${v3.fields.completion}: this absence holds only for what was searched; record what was not reached as kind=limitation (reason ${v3.fields.completion === "failed" ? "failed" : "partial"})`);
  }
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const replaced = supersededBy(entries);
    const bySeq = new Map(entries.map((e) => [e.seq, e]));
    for (const r of v3.rel) {
      const target = bySeq.get(r.to);
      if (!target) return { ok: false, reason: `rel names #${r.to}: there is no entry #${r.to} in the ledger (list them with ledger)` };
      const standing = replaced.get(r.to);
      if (r.kind === "duplicates" && standing !== undefined) return { ok: false, reason: `#${r.to} is superseded by #${standing}: a duplicate names the entry that stands, #${standing}` };
    }
    const candidate: LedgerEntry = {
      v: LEDGER_VERSION,
      seq: (entries.at(-1)?.seq ?? 0) + 1,
      kind: kind as LedgerKind,
      ...(ts.ts ? { ts: ts.ts } : {}),
      ...(ts.raw ? { ts_raw: ts.raw } : {}),
      value,
      source,
      evidence,
      ...(confidence ? { confidence: confidence as LedgerEntry["confidence"] } : {}),
      ...(refs.length ? { refs } : {}),
      ...v3.fields,
      ...(v3.rel.length ? { rel: v3.rel } : {}),
      ...v4.fields,
      ...(method.length ? { method } : {}),
      by: ctx.agentId,
      authors: [ctx.agentId],
      at: new Date().toISOString(),
    };
    const content = ledgerContent(candidate);
    if (supersedes !== undefined) {
      const target = bySeq.get(supersedes);
      if (!target) return { ok: false, reason: `supersedes #${supersedes}: there is no entry #${supersedes} in the ledger (list them with ledger)` };
      const already = replaced.get(supersedes);
      if (already !== undefined) return { ok: false, reason: `#${supersedes} is already superseded by #${already}: correct #${already} instead, so the corrections stay one line` };
      if (target.kind === "answer") return { ok: false, reason: `#${supersedes} is an answer: an answer is corrected by an answer to the same section (kind=answer, supersedes=${supersedes})` };
      // The whole of what it says, not the sentence alone: the same sentence
      // with another confidence, other refs or another status is a correction.
      if (ledgerContent(target) === content) {
        return { ok: false, reason: `the correction repeats #${supersedes} word for word, with the same confidence, refs and fields: a correction says what is right now` };
      }
    }
    // A correction is always its own entry. The same content again, from
    // anyone, is the entry that stands: a second author is an attestation,
    // appended, and the entry is never rewritten.
    const sameContent = supersedes === undefined ? entries.filter((e) => !replaced.has(e.seq) && ledgerContent(e) === content) : [];
    if (sameContent.length) return mergeSameContent(ctx, held, sameContent[0]);
    // The same sentence, from anyone: with refs where the standing one has
    // none, it is recorded anew and corrects it; otherwise it is its own
    // entry and is told of the other.
    const sameWords = supersedes === undefined ? entries.filter((e) => !replaced.has(e.seq) && e.kind === kind && e.value === value && (e.ts ?? "") === (ts.ts ?? "")) : [];
    const words = sameWords[0];
    if (words && refs.length && !words.refs?.length) {
      supersedes = words.seq;
    } else if (words) {
      notes.push(`#${words.seq} says the same sentence with other provenance or fields; if this one corrects it, record it with supersedes=${words.seq}; if it restates it, link it with rel {to: ${words.seq}, kind: "duplicates"}`);
    }
    return appendLedgerEntry(ctx, held, entries, { ...candidate, ...(supersedes !== undefined ? { supersedes } : {}) }, notes);
  });
}

/**
 * The same content again, from anyone, is the entry that stands: a second
 * author is an attestation of the kind "same content", appended, and the
 * entry is never rewritten.
 */
async function mergeSameContent(ctx: SwarmContext, held: { assertOwned(): Promise<void> }, same: LedgerEntry): Promise<LedgerResult> {
  const attested = await readAttestations(ctx.sandboxRoot);
  const already = same.by === ctx.agentId || same.authors.includes(ctx.agentId) || attested.some((a) => a.seq === same.seq && a.by === ctx.agentId && attestationAct(a) === "same_content");
  if (!already) {
    await held.assertOwned();
    await appendAttestation(ctx.sandboxRoot, attested, { v: 2, act: "same_content", seq: same.seq, target: same.hash ?? ledgerHash(same, "genesis"), by: ctx.agentId, at: new Date().toISOString() });
  }
  const all = await withAttestations(ctx.sandboxRoot, await readLedger(ctx.sandboxRoot, { raw: true }));
  await renderLedger(ctx.sandboxRoot, all);
  const stood = all.find((e) => e.seq === same.seq) ?? same;
  return { ok: true, entry: stood, merged: true, total: all.length, note: already ? `#${same.seq} already says this, recorded by you` : `#${same.seq} already says this word for word: recorded as your attestation of it (ledger/attestations.jsonl), not as a new entry` };
}

/** Chain and append one entry, and render ledger.md again. */
async function appendLedgerEntry(ctx: SwarmContext, held: { assertOwned(): Promise<void> }, entries: LedgerEntry[], entry: LedgerEntry, notes: string[]): Promise<LedgerResult> {
  if (entries.length >= LEDGER_MAX_ENTRIES) return { ok: false, reason: `the ledger holds ${LEDGER_MAX_ENTRIES} entries already` };
  // Every record an agent makes, of every kind, held to the case policy's
  // material use on what it rests on, transitively: the one place every
  // entry passes through. The harness's own external entries record the
  // material; they do not rest on it.
  if (entry.kind !== "external") {
    const use = await materialUseRefusal(ctx.sandboxRoot, entry as unknown as Record<string, unknown>);
    if (use) return { ok: false, reason: use };
  }
  // An entry whose refs reach a sensitive output (a job run with
  // secret_output, or one made from such an output) is recorded sensitive
  // (docs/adr/0016): its words are held to the run's sensitivity from now on.
  if (entry.refs?.length && !entry.sensitive) {
    const { sensitiveRefs } = await import("../scripts/output-hygiene.ts");
    const hits = await sensitiveRefs(ctx.sandboxRoot, entry.refs).catch(() => []);
    if (hits.length) {
      entry.sensitive = true;
      notes.push(`recorded sensitive: it cites sensitive output (${hits.map((h) => `${h.ref}, job ${h.job}${h.why === "secret_output" ? " ran with secret_output" : ", made from a sensitive output"}`).join("; ")}); no name, doing label or question may carry what it says, and a redacted package takes its words out`);
    }
  }
  // Keys in a stable order: the core is computed from the fields, not the line.
  // Chained like the trace: each entry names the one before it.
  const previous = entries.at(-1);
  entry.prev = previous?.hash ?? (previous ? ledgerHash(previous, "genesis") : "genesis");
  entry.hash = ledgerHash(entry, entry.prev);
  await mkdir(join(ctx.sandboxRoot, LEDGER_DIR), { recursive: true });
  await held.assertOwned();
  await appendFile(join(ctx.sandboxRoot, LEDGER_ENTRIES), `${JSON.stringify(entry)}\n`, "utf8");
  entries.push(entry);
  await renderLedger(ctx.sandboxRoot, await withAttestations(ctx.sandboxRoot, entries));
  return { ok: true, entry, merged: false, total: entries.length, ...(notes.length ? { note: notes.join("; ") } : {}) };
}

/** The classes of material the case policy says may not be used (material_use none), and the preset; null when none is forbidden. */
export async function forbiddenMaterialClasses(sandboxRoot: string): Promise<{ classes: Set<string>; preset: string } | null> {
  try {
    const p = JSON.parse(await readFile(join(sandboxRoot, "network", "policy.json"), "utf8")) as { policy?: string; material_use?: unknown };
    if (!p.material_use || typeof p.material_use !== "object") return null;
    const none = Object.entries(p.material_use as Record<string, unknown>).filter(([, v]) => String(v) === "none").map(([k]) => k);
    return none.length ? { classes: new Set(none), preset: String(p.policy ?? "standard") } : null;
  } catch {
    return null;
  }
}

/**
 * The case policy's material use, held at the record (docs/adr/0014): a
 * record that rests on material whose class the policy says may not be used
 * (`none`) is refused, whatever it cites: the material's own ref, the same
 * bytes by their digest (`sha256:`), a job's output made from it, a
 * catalogue member of such a job, or an entry that rests on it (support,
 * limitations, derived_from, a coverage record's results). The lineage is
 * the external lineage's (scripts/net-broker.ts), read over what each ref
 * resolves to, transitively; `reference` and `evidence` are taken, and what
 * rests on them is flagged where the answers are weighed. A run whose policy
 * forbids no class refuses nothing, and reads nothing.
 */
export async function materialUseRefusal(sandboxRoot: string, cand: string[] | (Partial<LedgerEntry> & Record<string, unknown>)): Promise<string | null> {
  const forbidden = await forbiddenMaterialClasses(sandboxRoot);
  if (!forbidden) return null;
  const record = Array.isArray(cand) ? { refs: cand } : cand;
  const { externalLineage } = await import("../scripts/net-broker.ts");
  const lineage = await externalLineage(sandboxRoot);
  for (const hit of await lineage.probe(record)) {
    const cls = hit.classes.find((c) => forbidden.classes.has(c));
    if (!cls) continue;
    return `${hit.cite} rests on ${cls.replace(/_/g, " ")} (${hit.via.join(", ")}), which case policy ${forbidden.preset} does not let a record cite or rest on (material_use ${cls}=none): it is kept on the record, and the examination does not rest on it`;
  }
  return null;
}

/**
 * External material, recorded by the harness as it enters the run: a
 * capture the fetch service sealed (source_class external_capture), material
 * the operator supplied. Its refs resolve now; its provenance is part of the
 * chained core. It is never an agent's: an agent cites it and records what
 * it establishes. The same material again (the same refs and class) is the
 * entry that stands.
 */
export async function recordExternal(sandboxRoot: string, input: { value: string; source: string; evidence: string; refs: string[]; source_class: (typeof LEDGER_SOURCE_CLASSES)[number]; provenance: NonNullable<LedgerEntry["provenance"]>; sensitive?: boolean }): Promise<LedgerResult> {
  const value = String(input.value ?? "").trim();
  if (!value || value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `an external entry says what the material is in 1 to ${LEDGER_VALUE_MAX_CHARS} characters` };
  if (!(LEDGER_SOURCE_CLASSES as readonly string[]).includes(input.source_class)) return { ok: false, reason: `source_class is one of ${LEDGER_SOURCE_CLASSES.join(", ")}` };
  if (!input.refs.length || input.refs.length > LEDGER_MAX_REFS) return { ok: false, reason: "an external entry cites the material it records" };
  const checked = await checkRefs(sandboxRoot, input.refs);
  if (!checked.ok) return checked;
  return withTableLock(sandboxRoot, async (held) => {
    const entries = await readLedger(sandboxRoot);
    const same = entries.find((e) => e.kind === "external" && e.source_class === input.source_class && JSON.stringify(e.refs ?? []) === JSON.stringify(input.refs));
    if (same) return { ok: true, entry: same, merged: true, total: entries.length, note: `#${same.seq} records it already` };
    const entry: LedgerEntry = {
      v: LEDGER_VERSION,
      seq: (entries.at(-1)?.seq ?? 0) + 1,
      kind: "external",
      value,
      source: input.source,
      evidence: input.evidence,
      refs: input.refs,
      ...(input.sensitive ? { sensitive: true } : {}),
      source_class: input.source_class,
      provenance: input.provenance,
      by: "system",
      authors: ["system"],
      at: new Date().toISOString(),
    };
    return appendLedgerEntry({ sandboxRoot, agentId: "system" }, held, entries, entry, []);
  });
}

/**
 * A line of ledger/attestations.jsonl. Version 1 (no `v`) is a second author
 * recording an entry word for word, hashed over {seq, by, at}. Version 2
 * binds the entry's hash and says which act it is: `same_content`, the same
 * second author, or `attest`, an agent other than the entry's authors saying
 * what it re-derived, from which sealed objects, and what it only read, all
 * inside the hashed record. A duplicate is co-authorship, never a check.
 */
export type LedgerAttestation = {
  v?: 2;
  act?: "same_content" | "attest";
  seq: number;
  /** The attested entry's hash. */
  target?: string;
  by: string;
  at: string;
  /** An attest's: what was re-derived from which sealed object, and what was only read. */
  how?: string;
  /** An attest's: the sealed objects it re-derived from, each resolved. */
  refs?: string[];
  /**
   * An attest of a negative (a coverage record, or an answer bounded_negative
   * or not_determinable): whether the reviewer challenged the detection
   * assumptions, reproduced a decisive check, tried a materially different
   * route, each with what was done or why not. Inside the hashed record.
   */
  review?: NB.NegativeReview;
  /**
   * An attest of an answer to a question: whether the reviewer holds it
   * established, or a best candidate (what the evidence best supports, not
   * shown to be the answer). A best candidate does not satisfy the finish
   * line. Absent on a line from before strengths (read as it always was).
   */
  strength?: AttestStrength;
  /** An attest of an answer to a question: what the review of the answer found, part by part. */
  answer_review?: AnswerReview;
  /** Written by the hub: why only a best candidate could be attested (a medium or low confidence, a part not established, a route not taken). */
  capped?: string[];
  prev?: string;
  hash?: string;
};

/** How strongly a review holds an answer: established, or a best candidate. */
export const ATTEST_STRENGTHS = ["established", "best_candidate"] as const;
export type AttestStrength = (typeof ATTEST_STRENGTHS)[number];

/**
 * A review of an answer to a question (B2): what the reviewer reproduced
 * and what it only read, whether each part the question asks is
 * established, the inference that connects the observations to the answer,
 * the alternatives the evidence still allows, and whether another source
 * family was checked (or why not: never a compulsory box, but its absence
 * is said).
 */
export type AnswerReview = {
  reproduced: string;
  read: string;
  parts: Array<{ part: string; established: boolean; why: string }>;
  inference: string;
  alternatives: string;
  other_family: { checked: boolean; text: string };
};
export const ANSWER_REVIEW_MAX_PARTS = 20;

/** An answer review as given: every field said, each bounded (refused past it, never cut). */
export function checkAnswerReview(raw: unknown): { ok: true; review: AnswerReview } | { ok: false; reason: string } {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const shape = "answer_review is {reproduced, read, parts: [{part, established, why}], inference, alternatives, other_family: {checked, text}}";
  const text = (name: string, v: unknown): { ok: true; value: string } | { ok: false; reason: string } => {
    const t = String(v ?? "").trim();
    if (!t) return { ok: false, reason: `answer_review.${name} is required (${shape}): say it, or "none" and why` };
    if (t.length > LEDGER_ACT_MAX_CHARS) return { ok: false, reason: `answer_review.${name} is over ${LEDGER_ACT_MAX_CHARS} characters: say it in fewer; nothing is cut, so a longer text is refused` };
    return { ok: true, value: t };
  };
  const reproduced = text("reproduced", r.reproduced);
  if (!reproduced.ok) return reproduced;
  const read = text("read", r.read);
  if (!read.ok) return read;
  const inference = text("inference", r.inference);
  if (!inference.ok) return inference;
  const alternatives = text("alternatives", r.alternatives);
  if (!alternatives.ok) return alternatives;
  if (!Array.isArray(r.parts) || !r.parts.length) return { ok: false, reason: `answer_review.parts names each part the question asks, [{part, established: true|false, why}], at least one (${shape})` };
  if (r.parts.length > ANSWER_REVIEW_MAX_PARTS) return { ok: false, reason: `answer_review.parts names at most ${ANSWER_REVIEW_MAX_PARTS} parts` };
  const parts: AnswerReview["parts"] = [];
  for (const p of r.parts) {
    const o = (p && typeof p === "object" ? p : {}) as Record<string, unknown>;
    const part = text("parts[].part", o.part);
    if (!part.ok) return part;
    if (typeof o.established !== "boolean") return { ok: false, reason: `answer_review.parts[].established is true or false: whether "${part.value}" is established` };
    const why = text("parts[].why", o.why);
    if (!why.ok) return why;
    parts.push({ part: part.value, established: o.established, why: why.value });
  }
  const f = (r.other_family && typeof r.other_family === "object" ? r.other_family : null) as Record<string, unknown> | null;
  if (!f || typeof f.checked !== "boolean") return { ok: false, reason: "answer_review.other_family is {checked: true|false, text}: whether a materially different source family was checked, and which, or why not" };
  const ft = text("other_family.text", f.text);
  if (!ft.ok) return ft;
  return { ok: true, review: { reproduced: reproduced.value, read: read.value, parts, inference: inference.value, alternatives: alternatives.value, other_family: { checked: f.checked, text: ft.value } } };
}

/** An answer review in words, for the ledger's rendering and the report. */
export function answerReviewWords(r: AnswerReview): string {
  return `reproduced: ${r.reproduced}; only read: ${r.read}; parts: ${r.parts.map((p) => `${p.part} ${p.established ? "established" : "NOT established"} (${p.why})`).join("; ")}; inference: ${r.inference}; alternatives still open: ${r.alternatives}; another source family ${r.other_family.checked ? "checked" : "not checked"}: ${r.other_family.text}`;
}

/** Whether an attestation holds its answer established: a best candidate does not; a line from before strengths reads as it always did. */
export function attestEstablishes(a: LedgerAttestation): boolean {
  return a.strength !== "best_candidate";
}

/** The act of an attestation line: a version 1 line is a second author. */
export function attestationAct(a: LedgerAttestation): "same_content" | "attest" {
  return a.v === 2 && a.act === "attest" ? "attest" : "same_content";
}

export function attestationHash(a: LedgerAttestation, prev: string): string {
  const core =
    a.v === 2
      ? JSON.stringify({ v: 2, act: a.act, seq: a.seq, target: a.target, by: a.by, at: a.at, ...(a.how ? { how: a.how } : {}), ...(a.refs?.length ? { refs: a.refs } : {}), ...(a.review ? { review: canonicalValue(a.review) } : {}), ...(a.strength ? { strength: a.strength } : {}), ...(a.answer_review ? { answer_review: canonicalValue(a.answer_review) } : {}), ...(a.capped?.length ? { capped: a.capped } : {}) })
      : JSON.stringify({ seq: a.seq, by: a.by, at: a.at });
  return createHash("sha256").update(`${prev}\n${core}`).digest("hex");
}

export async function readAttestations(sandboxRoot: string): Promise<LedgerAttestation[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_ATTESTATIONS), "utf8").catch(() => "");
  const out: LedgerAttestation[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerAttestation);
    } catch {
      // a torn line is left for custody to name
    }
  }
  return out;
}

async function appendAttestation(sandboxRoot: string, existing: LedgerAttestation[], a: LedgerAttestation): Promise<LedgerAttestation> {
  const prev = existing.at(-1)?.hash ?? "genesis";
  const line: LedgerAttestation = { ...a, prev, hash: attestationHash(a, prev) };
  await mkdir(join(sandboxRoot, LEDGER_DIR), { recursive: true });
  await appendFile(join(sandboxRoot, LEDGER_ATTESTATIONS), `${JSON.stringify(line)}\n`, "utf8");
  return line;
}

/**
 * The attestations' own chain: each line names the one before it, and its
 * hash is over its version's record. A version 1 line after a version 2 one
 * is refused (the harness writes none again), and so is a version it does
 * not know, or a version 2 line that is neither act.
 */
export function verifyAttestationChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let last = "genesis";
  let total = 0;
  let sawV2 = false;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let a: LedgerAttestation;
    try {
      a = JSON.parse(line) as LedgerAttestation;
    } catch {
      return { ok: false, total, broken_at: total, reason: "not json", head: null };
    }
    if (a.v !== undefined && a.v !== 2) return { ok: false, total, broken_at: total, reason: `an attestation of version ${JSON.stringify(a.v)}, which this harness does not know`, head: null };
    if (a.v === 2 && a.act !== "same_content" && a.act !== "attest") return { ok: false, total, broken_at: total, reason: `an attestation whose act is ${JSON.stringify(a.act)}`, head: null };
    if (a.v === undefined && sawV2) return { ok: false, total, broken_at: total, reason: "a version 1 attestation after version 2 ones", head: null };
    if (a.v === 2) sawV2 = true;
    if (a.prev !== last) return { ok: false, total, broken_at: total, reason: "prev does not name the line before it", head: null };
    if (a.hash !== attestationHash(a, last)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    last = a.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? last : null };
}

/**
 * Entries with every second author added to `authors`, in memory only. An
 * attest is not authorship: the agent that re-derived an entry is its
 * checker, and is never folded in.
 */
export async function withAttestations(sandboxRoot: string, entries: LedgerEntry[]): Promise<LedgerEntry[]> {
  const attested = (await readAttestations(sandboxRoot)).filter((a) => attestationAct(a) === "same_content");
  if (!attested.length) return entries;
  const extra = new Map<number, string[]>();
  for (const a of attested) extra.set(a.seq, [...(extra.get(a.seq) ?? []), a.by]);
  return entries.map((e) => {
    const more = (extra.get(e.seq) ?? []).filter((b) => !e.authors.includes(b));
    return more.length ? { ...e, authors: [...e.authors, ...more] } : e;
  });
}

/** Each job: ref whose job did not end ok, with the job's status. */
export async function refsOnFailedJobs(sandboxRoot: string, refs: string[]): Promise<Array<{ ref: string; job: string; status: string }>> {
  const out: Array<{ ref: string; job: string; status: string }> = [];
  const seen = new Map<string, string | null>();
  for (const ref of refs) {
    const m = /^job:(j\d{6})\//.exec(ref);
    if (!m) continue;
    if (!seen.has(m[1])) {
      const job = await readFile(join(sandboxRoot, "store", "jobs", m[1], "job.json"), "utf8").then((t) => JSON.parse(t) as { status?: string }).catch(() => null);
      seen.set(m[1], job?.status ?? null);
    }
    const status = seen.get(m[1]);
    if (status && status !== "ok") out.push({ ref, job: m[1], status });
  }
  return out;
}

function mdCell(text: string | undefined): string {
  return (text ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** ledger/ledger.md: the timeline in time order, the indicators, the findings. */
export async function renderLedger(sandboxRoot: string, entries?: LedgerEntry[]): Promise<string> {
  const all = await withAttestations(sandboxRoot, entries ?? (await readLedger(sandboxRoot)));
  const events = all.filter((e) => e.kind === "event").sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? "") || a.seq - b.seq);
  const iocs = all.filter((e) => e.kind === "ioc");
  const findings = all.filter((e) => e.kind === "finding");
  const absences = all.filter((e) => e.kind === "absence");
  const hypotheses = all.filter((e) => e.kind === "hypothesis");
  const limitations = all.filter((e) => e.kind === "limitation");
  const answers = all.filter((e) => e.kind === "answer");
  const coverages = all.filter((e) => e.kind === "coverage");
  const replaced = supersededBy(all);
  const contradictions = standingContradictions(all);
  // Who re-derived an entry, and who disputes it: read beside the ledger, never written into it.
  const allAttestations = await readAttestations(sandboxRoot);
  const attests = allAttestations.filter((a) => attestationAct(a) === "attest");
  const disputes = disputesInForce(all, await readDisputes(sandboxRoot));
  const problems = answers.length ? answerProblems(all, await readDisputes(sandboxRoot)) : new Map<number, string[]>();
  const lines: string[] = [
    "# Ledger",
    "",
    `${all.length} entries: ${events.length} events, ${iocs.length} indicators, ${findings.length} findings, ${absences.length} searches that found nothing${hypotheses.length ? `, ${hypotheses.length} hypotheses` : ""}${limitations.length ? `, ${limitations.length} limitations` : ""}${coverages.length ? `, ${coverages.length} coverage records` : ""}${answers.length ? `, ${answers.length} answers` : ""}${replaced.size ? `; ${replaced.size} corrected by a later entry, which stands` : ""}${contradictions.length ? `; ${contradictions.length} standing contradiction${contradictions.length === 1 ? "" : "s"}` : ""}. Written by the harness from \`record\`, \`attest\` and \`dispute\`; cite it as \`ledger/ledger.md\`.`,
    "",
  ];
  const acts = (e: LedgerEntry) => {
    const h = e.hash ?? ledgerHash(e, "genesis");
    const by = attests.filter((a) => a.target === h).map((a) => `${a.by}${a.strength === "best_candidate" ? " (best candidate)" : ""}`);
    const against = disputes.filter((d) => d.target === h);
    return `${by.length ? ` [attested by ${[...new Set(by)].join(", ")}]` : ""}${against.length ? ` **[disputed by ${against.map((d) => `${d.by}: ${mdCell(d.why)}${d.inherited_from !== undefined ? ` (raised on #${d.inherited_from}, which it corrects; open until answered)` : ""}`).join("; ")}]**` : ""}`;
  };
  // A corrected entry stays where it was, marked; its correction says what it corrects.
  const mark = (e: LedgerEntry) =>
    `${replaced.has(e.seq) ? ` **(superseded by #${replaced.get(e.seq)})**` : ""}${e.supersedes !== undefined ? ` (corrects #${e.supersedes}${e.because ? `: ${mdCell(e.because)}` : ""})` : ""}${ledgerFieldsText(e)}${acts(e)}`;
  lines.push("## Timeline", "", "| # | Time (UTC) | Event | Source | Evidence | By |", "| --- | --- | --- | --- | --- | --- |");
  // A time the source gave with an offset (or as a date) is shown as written too.
  const asWritten = (e: LedgerEntry) => (e.ts_raw && !/[Zz]$/.test(e.ts_raw) && !(e.precision === "date" && e.ts_raw === (e.ts ?? "").slice(0, 10)) ? ` (as written: ${mdCell(e.ts_raw)})` : "");
  // A date alone is shown as a date; the clock the time came from beside it.
  const when = (e: LedgerEntry) => `${e.precision === "date" ? (e.ts ?? "").slice(0, 10) : e.ts}${asWritten(e)}${e.clock ? ` · clock: ${mdCell(e.clock)}` : ""}${e.precision && e.precision !== "date" ? ` · precision: ${e.precision}` : ""}`;
  // The objects an entry rests on, with its evidence.
  const ev = (e: LedgerEntry) => `${mdCell(e.evidence)}${e.refs?.length ? ` · refs: ${mdCell(e.refs.join(", "))}` : ""}${e.locators?.length ? ` · at: ${mdCell(e.locators.map((l) => `${l.ref} ${l.at}`).join("; "))}` : ""}`;
  for (const e of events) lines.push(`| ${e.seq} | ${when(e)} | ${mdCell(e.value)}${mark(e)} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  lines.push("", "## Indicators", "", "| # | Indicator | Source | Evidence | Confidence | By |", "| --- | --- | --- | --- | --- | --- |");
  for (const e of iocs) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${mdCell(e.source)} | ${ev(e)} | ${e.confidence ?? ""} | ${e.authors.join(", ")} |`);
  lines.push("", "## Findings", "");
  for (const e of findings) {
    lines.push(`- **#${e.seq}** ${e.value}${mark(e)}${e.confidence ? ` _(${e.confidence})_` : ""}${e.source ? ` — source: ${e.source}` : ""}${e.evidence ? ` — evidence: ${e.evidence}` : ""}${e.refs?.length ? ` — refs: ${e.refs.map((r) => `\`${r}\``).join(", ")}` : ""}${interpretationText(e)} — by ${e.authors.join(", ")}`);
  }
  if (answers.length) {
    // The swarm's answers, each with what it rests on; one stands per section.
    lines.push("", "## Answers", "");
    for (const e of answers) {
      const cites = (label: string, edges?: LedgerEdge[]) => (edges?.length ? ` — ${label}: ${edges.map((x) => `E-${x.seq}`).join(", ")}` : "");
      const p = problems.get(e.seq);
      const r = NB.answerResult(e);
      const neg = r && NB.NEGATIVE_RESULTS.has(r) && e.section?.startsWith("question:") ? negativeReview(e, all, allAttestations) : null;
      const negText = neg ? (neg.reviewed ? ` (negative, reviewed by ${neg.by.join(", ")})` : " **(negative, unreviewed)**") : "";
      lines.push(
        `- **#${e.seq}** ${e.section}${e.question_rev ? ` (revision ${e.question_rev})` : ""}${e.inconclusive ? " (inconclusive)" : ""}${e.result ? ` (${e.result})` : ""}${e.asserts_absence ? " (asserts absence)" : ""}${negText}: ${e.value}${mark(e)}${e.confidence ? ` _(${e.confidence}${e.confidence_why ? `: ${e.confidence_why}` : ""})_` : ""}${cites("rests on", e.support)}${cites("contrary", e.contrary)}${e.contrary_none_why ? ` — nothing says otherwise: ${e.contrary_none_why}` : ""}${cites("limitations", e.limitations)}${e.qualifies?.length ? ` — qualifies: ${e.qualifies.map((q) => `${q.ref} (${q.why})`).join("; ")}` : ""}${e.alternatives_open ? ` — still open: ${e.alternatives_open}` : ""}${e.would_change ? ` — would change it: ${e.would_change}` : ""}${e.unsupported_tokens?.length ? ` — in none of the cited entries: ${e.unsupported_tokens.join(", ")}` : ""}${p?.length ? ` — **no longer stands on its support: ${p.join("; ")}**` : ""} — reasoning: ${e.reasoning ?? ""} — by ${e.authors.join(", ")}`,
      );
    }
  }
  if (hypotheses.length) {
    lines.push("", "## Hypotheses", "", "| # | Hypothesis | Status | Source | Evidence | By |", "| --- | --- | --- | --- | --- | --- |");
    for (const e of hypotheses) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${e.status ?? "open"} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  }
  // Searched and not found: what, where, and how far. Each holds for that
  // query and that scope only.
  lines.push("", "## Searched, not found", "", "| # | Looked for | Searched | Query, tool, scope | By |", "| --- | --- | --- | --- | --- |");
  for (const e of absences) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  const externals = all.filter((e) => e.kind === "external");
  if (externals.length) {
    // What entered from outside the evidence, with where from: a capture's hash proves its bytes, not their truth.
    lines.push("", "## External material", "", "| # | What | Class | From | Provenance | By |", "| --- | --- | --- | --- | --- | --- |");
    for (const e of externals) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${e.source_class ?? ""} | ${mdCell(e.provenance?.from ?? e.source)} | ${ev(e)}${e.provenance?.sha256 ? ` · sha256 ${e.provenance.sha256}` : ""} | ${e.authors.join(", ")} |`);
  }
  if (limitations.length) {
    lines.push("", "## Limitations", "", "| # | Not established | Reason | Scope | What was tried | By |", "| --- | --- | --- | --- | --- | --- |");
    for (const e of limitations) lines.push(`| ${e.seq} | ${mdCell(e.value)}${mark(e)} | ${e.reason ?? ""} | ${mdCell(e.source)} | ${ev(e)} | ${e.authors.join(", ")} |`);
  }
  if (coverages.length) {
    // What each negative was searched over, what the hub found the jobs were given, and who reviewed it.
    lines.push("", "## Coverage records", "");
    for (const e of coverages) {
      const neg = negativeReview(e, all, allAttestations);
      lines.push(
        `- **#${e.seq}** for ${(e.answers ?? []).map((a) => `question:${a}`).join(", ")}: proposition: ${e.value}${mark(e)} — objects: ${(e.refs ?? []).map((r) => `\`${r}\``).join(", ")} — time range: ${e.time_range ?? ""} — method: ${e.search_method ?? ""} (settings: ${e.settings ?? ""}) — covered: ${e.coverage_actual ?? ""} — skipped: ${e.skipped ?? ""} — failures: ${e.failures ?? ""} — results: ${(e.result_refs ?? []).join(", ")} — alternatives: ${e.alternatives_open ?? ""} — detection opportunity: trace expected ${e.detection_opportunity?.trace_expected ?? "?"}, ${e.detection_opportunity?.why ?? ""} — inventory ${e.inventory_rev ?? "?"} — **coverage ${e.coverage ?? "not computed"}**${e.coverage_detail?.why.length ? ` (${e.coverage_detail.why.join("; ")})` : ""}${e.not_examined?.length ? ` — planned routes not examined: ${e.not_examined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")}` : ""} — ${neg.reviewed ? `reviewed by ${neg.by.join(", ")}: ${neg.reviews.map((x) => NB.reviewWords(x.review)).join(" / ")}` : "**unreviewed**"} — by ${e.authors.join(", ")}`,
      );
    }
  }
  if (contradictions.length) {
    // Weighed: an answer holds both, one as contrary evidence, or a limitation names both.
    const open = new Set(openContradictions(all).map((c) => `${c.from}:${c.to}`));
    lines.push("", "## Standing contradictions", "");
    for (const c of contradictions) lines.push(`- #${c.from} contradicts #${c.to}; both stand${open.has(`${c.from}:${c.to}`) ? "" : " (weighed in an answer or named by a limitation)"}`);
  }
  const text = lines.join("\n") + "\n";
  await mkdir(join(sandboxRoot, LEDGER_DIR), { recursive: true });
  await writeFile(join(sandboxRoot, LEDGER_MD), text, "utf8");
  return text;
}

/**
 * A finding's version 4 fields as a tail for a rendered line: what it
 * indicates, why that confidence, what else could explain it, why a failed
 * job's bytes still hold, and how its objects were made. A finding written
 * before version 4 says its interpretation was not recorded.
 */
export function interpretationText(e: LedgerEntry): string {
  if (e.kind !== "finding") return "";
  if (!e.indicates && (e.v ?? 1) < 4) return " — interpretation not recorded";
  const parts: string[] = [];
  if (e.indicates) parts.push(`indicates: ${e.indicates}`);
  if (e.confidence_why) parts.push(`why that confidence: ${e.confidence_why}`);
  if (e.alternatives?.length) parts.push(`alternatives: ${e.alternatives.map((a) => `${a.explanation} (${a.status}: ${a.why}${a.test_refs?.length ? `; tested with ${a.test_refs.join(", ")}` : ""})`).join("; ")}`);
  if (e.alternatives_none_why) parts.push(`no alternative considered: ${e.alternatives_none_why}`);
  if (e.significance) parts.push(`significance: ${e.significance}`);
  if (e.qualifies?.length) parts.push(`from a job that did not succeed: ${e.qualifies.map((q) => `${q.ref} (${q.why})`).join("; ")}`);
  if (e.method?.length) parts.push(`made by: ${e.method.map(methodText).join("; ")}`);
  return parts.map((p) => ` — ${p}`).join("");
}

/** One method record in a line: the job, what it ran, where, and how it ended. */
export function methodText(m: LedgerMethod): string {
  const what = m.tool ? `tool ${String(m.tool)}` : m.recipe ? `recipe ${String(m.recipe)}` : m.command !== undefined ? `command \`${String(m.command)}\`` : m.source ? `import of ${String(m.source)} (${String(m.produced_by ?? "producer unknown")})` : m.job_kind ? String(m.job_kind) : String(m.kind ?? "object");
  return `${m.job ? `job ${String(m.job)}: ` : m.import ? `import ${String(m.import)}: ` : ""}${what}${m.image ? ` in ${String(m.image)} (${String(m.image_digest ?? "digest unknown")})` : ""}${m.status ? `, ${String(m.status)}` : ""}`;
}

/** The typed fields of an entry, as a short tail for a rendered line. */
export function ledgerFieldsText(e: LedgerEntry): string {
  const parts: string[] = [];
  if (e.answers?.length) parts.push(`answers ${e.answers.join(", ")}`);
  if (e.rel?.length) parts.push(e.rel.map((r) => `${r.kind.replace("_", " ")} #${r.to}`).join(", "));
  if (e.basis) parts.push(e.basis);
  if (e.completion && e.completion !== "complete") parts.push(`search ${e.completion}`);
  if (e.attribution) parts.push(`attributed to ${e.attribution.subject} (${e.attribution.subject_type})`);
  if (e.sensitive) parts.push("sensitive");
  return parts.length ? ` [${mdCell(parts.join("; "))}]` : "";
}

/** Pairs where one standing entry says it contradicts another standing entry. */
export function standingContradictions(entries: LedgerEntry[]): Array<{ from: number; to: number }> {
  const replaced = supersededBy(entries);
  const out: Array<{ from: number; to: number }> = [];
  for (const e of entries) {
    if (replaced.has(e.seq)) continue;
    for (const r of e.rel ?? []) if (r.kind === "contradicts" && !replaced.has(r.to) && entries.some((x) => x.seq === r.to)) out.push({ from: e.seq, to: r.to });
  }
  return out;
}

export async function listLedger(sandboxRoot: string, filter: { kind?: string; limit?: number } = {}): Promise<LedgerEntry[]> {
  const all = await withAttestations(sandboxRoot, await readLedger(sandboxRoot));
  const kind = (filter.kind ?? "").trim().toLowerCase();
  const picked = kind ? all.filter((e) => e.kind === kind) : all;
  const limit = Math.max(1, Math.min(500, Number(filter.limit) || 200));
  // A corrected entry is listed with the entry that corrects it; every entry
  // with who re-derived it and who disputes it; an answer with what keeps it
  // from standing on its support, when anything does.
  const replaced = supersededBy(all);
  const attests = (await readAttestations(sandboxRoot)).filter((a) => attestationAct(a) === "attest");
  const allDisputes = await readDisputes(sandboxRoot);
  const disputes = disputesInForce(all, allDisputes);
  const problems = all.some((e) => e.kind === "answer") ? answerProblems(all, allDisputes) : new Map<number, string[]>();
  return picked.slice(-limit).map((e) => {
    const h = e.hash ?? ledgerHash(e, "genesis");
    const by = [...new Set(attests.filter((a) => a.target === h).map((a) => a.by))];
    const against = disputes.filter((d) => d.target === h).map((d) => ({ by: d.by, why: d.why, ...(d.inherited_from !== undefined ? { inherited_from: d.inherited_from } : {}) }));
    return {
      ...e,
      ...(replaced.has(e.seq) ? { superseded_by: replaced.get(e.seq) } : {}),
      ...(by.length ? { attested_by: by } : {}),
      ...(against.length ? { disputed_by: against } : {}),
      ...(problems.has(e.seq) ? { problems: problems.get(e.seq) } : {}),
    };
  });
}

// ---------------------------------------------------------------------------
// Interpretation, answers and the acts on them (ledger version 4).
//
// A finding says what it indicates; an `answer` is the swarm's answer to one
// question of the goal (or its summary, or its narrative), resting on the
// entries it cites by hash. A critic other than the author re-derives what an
// answer rests on and says so with `attest`, or says why not with `dispute`;
// both are hub-written, each in its own chain beside the ledger. Whether a
// run may end is the goal's to say: its check reads the answers (the ledger
// gate below, run by scripts/check-answers.ts), refuses a done that leaves a
// mechanical defect, names the fix, and lets the next done through once a
// limitation names each defect that is left. Nothing here judges whether an
// answer is right: that is the critic's and the examiner's.
// ---------------------------------------------------------------------------

/** A goal section id as an answer names it: "3", "Q3" and "question:3" are question:3; summary and narrative are themselves. */
export function answerSection(raw: string): { ok: true; section: string; id: string } | { ok: false; reason: string } {
  const text = String(raw ?? "").trim();
  const lower = text.toLowerCase();
  if ((LEDGER_SECTION_SPECIAL as readonly string[]).includes(lower)) return { ok: true, section: lower, id: lower };
  const id = sectionKey(lower.startsWith("question:") ? text.slice("question:".length) : text);
  if (!id || !LEDGER_ANSWER_ID.test(id) || (LEDGER_SECTION_SPECIAL as readonly string[]).includes(id.toLowerCase())) {
    return { ok: false, reason: `section is question:<id> (the goal's question, "question:3"), summary or narrative (got ${JSON.stringify(text)})` };
  }
  return { ok: true, section: `question:${id}`, id };
}

/**
 * The questions a brief numbers: the distinct numbers that open a line
 * (`1.`, `1)`, `1:`, `Q1`, `Question 1`, `**1.**`, `### 1.`), in the order
 * they first appear; the same count the goals' awk takes of inputs/CASE.md.
 */
export function briefQuestions(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const m = /^(#+ *)?(\*\* *)?([Qq](uestion)? *[0-9]+|[0-9]+[.):]([ *]|$))/.exec(line);
    if (!m) continue;
    const n = String(Number(m[0].replace(/[^0-9]/g, "")));
    if (!out.includes(n)) out.push(n);
  }
  return out;
}

/** A section id as the goal numbers it: "3", "Q3" and "q3" are section 3. */
export function sectionKey(id: string): string {
  // Q-19, the question register's id, is question:19 too.
  return String(id ?? "").trim().replace(/^q-?(?=\d)/i, "");
}

/** The goal id a section's entries name in `answers`: 3 for question:3, summary, narrative. */
export function sectionAnswersId(section: string): string {
  return section.startsWith("question:") ? section.slice("question:".length) : section;
}

/** The entries a text cites as E-<seq>, and every seq of a range E-12–E-15 (at most 50 a range). */
export function answerCitations(text: string): number[] {
  const out = new Set<number>();
  for (const m of String(text ?? "").matchAll(/\bE-(\d{1,5})(?:\s*[–-]\s*E-?(\d{1,5}))?\b/g)) {
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    if (b >= a && b - a <= 50) for (let n = a; n <= b; n += 1) out.add(n);
    else out.add(a);
  }
  return [...out].filter((n) => n > 0);
}

/** A list of seqs as an agent writes them: 12, "12", "#12", "E-12", or one string of them. */
function seqList(name: string, v: Array<number | string> | string | undefined): { ok: true; seqs: number[] } | { ok: false; reason: string } {
  const items = Array.isArray(v) ? v.map(String) : String(v ?? "").split(/[\s,]+/);
  const out: number[] = [];
  for (const raw of items.map((x) => x.trim()).filter(Boolean)) {
    const n = Number(raw.replace(/^(?:#|E-)/i, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `${name} names entries by seq (12, "#12" or "E-12"; got ${JSON.stringify(raw)})` };
    if (!out.includes(n)) out.push(n);
  }
  return { ok: true, seqs: out };
}

/** Where a chain of corrections from `seq` ends: the entry that stands. */
export function standingSeq(seq: number, replaced: Map<number, number>): number {
  let at = seq;
  for (let i = 0; i < 10_000 && replaced.has(at); i += 1) at = replaced.get(at) as number;
  return at;
}

/** The seqs a limitation names: its links, and each E-<seq> in what it says. */
export function limitationCites(e: LedgerEntry): Set<number> {
  const out = new Set<number>((e.rel ?? []).map((r) => r.to));
  for (const n of answerCitations(`${e.value}\n${e.source ?? ""}\n${e.evidence ?? ""}`)) out.add(n);
  return out;
}

// --- the token check ------------------------------------------------------------------------

/**
 * The specifics an answer's text asserts that a reader could look up: hashes,
 * paths (and registry keys), times, inodes, addresses and accounts. Each is
 * kept as written and normalised for matching: hex lower-case; a path's
 * separators as "/", its case folded and a drive letter dropped; a time to
 * the second, in UTC when it says its zone (a date alone, or a time to the
 * minute, matches any time within it); an NTFS `inode-type-id` by its first
 * number. Token matching finds omissions, never entailment: a token in no
 * cited entry is marked, never refused, and a legitimate transformation
 * (a conversion, a sum) needs its derivation recorded as an entry.
 */
export type AnswerToken = { kind: "hash" | "path" | "time" | "inode" | "ip" | "account"; text: string; norm: string };

const TOKEN_TIME = /\b(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s?(Z|z|UTC|[+-]\d{2}:?\d{2})?)?(?![\d:])/g;

function normalizeTokenTime(m: RegExpMatchArray): string | null {
  const [, y, mo, d, h, mi, sec, zone] = m;
  if (Number(mo) < 1 || Number(mo) > 12 || Number(d) < 1 || Number(d) > 31) return null;
  if (h === undefined) return `${y}-${mo}-${d}`;
  const naive = `${y}-${mo}-${d}T${h}:${mi}${sec !== undefined ? `:${sec}` : ""}`;
  if (!zone) return naive;
  const z = /^(z|utc)$/i.test(zone) ? "Z" : zone.length === 5 ? `${zone.slice(0, 3)}:${zone.slice(3)}` : zone;
  const ms = Date.parse(`${y}-${mo}-${d}T${h}:${mi}:${sec ?? "00"}${z}`);
  if (!Number.isFinite(ms)) return naive;
  const iso = new Date(ms).toISOString();
  return sec !== undefined ? iso.slice(0, 19) : iso.slice(0, 16);
}

function normalizePathText(text: string): string {
  return text.toLowerCase().replace(/\\+/g, "/").replace(/\/{2,}/g, "/").replace(/(^|[\s"'`(=])[a-z]:(?=\/)/g, "$1").replace(/\/$/, "");
}

/** The tokens of a text, each once by its normalised form, in the order they first appear. */
export function answerTokens(text: string): AnswerToken[] {
  const found: Array<{ at: number; t: AnswerToken }> = [];
  const add = (at: number, t: AnswerToken) => found.push({ at, t });
  const src = String(text ?? "");
  for (const m of src.matchAll(TOKEN_TIME)) {
    const norm = normalizeTokenTime(m);
    if (norm) add(m.index ?? 0, { kind: "time", text: m[0].trim(), norm });
  }
  for (const m of src.matchAll(/(?<![0-9A-Za-z])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9A-Za-z])/g)) add(m.index ?? 0, { kind: "hash", text: m[0], norm: m[0].toLowerCase() });
  for (const m of src.matchAll(/(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.]*\d)/g)) add(m.index ?? 0, { kind: "ip", text: m[0], norm: m[0] });
  // An IPv6 address: eight groups, or fewer with one "::"; a time of day is not one.
  for (const m of src.matchAll(/(?<![\w:.])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])/g)) {
    const v = m[0];
    const gaps = (v.match(/::/g) ?? []).length;
    const groups = v.split(":");
    if (gaps > 1 || (gaps === 0 && groups.length !== 8) || v.includes(":::") || v === "::") continue;
    if (gaps === 0 && groups.some((g) => !g)) continue;
    if (/^\d{1,2}(:\d{2}){1,2}$/.test(v)) continue;
    add(m.index ?? 0, { kind: "ip", text: v, norm: v.toLowerCase() });
  }
  // A SID's numbers are not an inode's: masked before inodes are read.
  const unSid = src.replace(/\bS-1-\d{1,3}(?:-\d{1,12}){1,14}\b/gi, (x) => " ".repeat(x.length));
  for (const m of unSid.matchAll(/\b(\d{1,12})-(\d{1,5})-(\d{1,5})\b/g)) {
    if (/^\d{4}$/.test(m[1]) && /^\d{2}$/.test(m[2]) && /^\d{2}$/.test(m[3])) continue;
    add(m.index ?? 0, { kind: "inode", text: m[0], norm: String(Number(m[1])) });
  }
  for (const m of src.matchAll(/\binode\s*[#:=]?\s*(\d{1,12})\b/gi)) add(m.index ?? 0, { kind: "inode", text: m[0], norm: String(Number(m[1])) });
  for (const m of src.matchAll(/\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g)) add(m.index ?? 0, { kind: "account", text: m[0], norm: m[0].toLowerCase() });
  for (const m of src.matchAll(/\bS-1-\d{1,3}(?:-\d{1,12}){1,14}\b/gi)) add(m.index ?? 0, { kind: "account", text: m[0], norm: m[0].toUpperCase() });
  // Paths (and registry keys): a word with a separator that is rooted (a
  // drive, a UNC share, /, ~), has two separators or ends in an extension;
  // one backslash between two names is an account (DOMAIN\user). A URL,
  // an E-<seq> pair and a number like 03/20/2024 are none of them.
  for (const m of src.matchAll(/[^\s"'`<>|,;()[\]{}]+/g)) {
    const v = m[0].replace(/^[*_]+/, "").replace(/[*_]+$/, "").replace(/[.:!?]+$/, "");
    if (!/[\\/]/.test(v) || v.includes("://") || /^E-\d/i.test(v)) continue;
    const segs = v.split(/[\\/]+/).filter(Boolean);
    if (!segs.length || segs.every((x) => /^\d+$/.test(x))) continue;
    const seps = (v.match(/[\\/]/g) ?? []).length;
    const rooted = /^(?:[A-Za-z]:[\\/]|\\\\|\/|~\/)/.test(v);
    const ext = /\.[A-Za-z0-9]{1,8}$/.test(segs.at(-1) ?? "");
    if (!rooted && seps < 2 && !ext) {
      if (seps === 1 && /^[A-Za-z][\w.-]*\\[A-Za-z][\w.$-]*$/.test(v)) add(m.index ?? 0, { kind: "account", text: v, norm: v.toLowerCase().replace(/\\/g, "/") });
      continue;
    }
    add(m.index ?? 0, { kind: "path", text: v, norm: normalizePathText(v) });
  }
  const seen = new Set<string>();
  const out: AnswerToken[] = [];
  for (const { t } of found.sort((a, b) => a.at - b.at)) {
    const key = `${t.kind}\u0000${t.norm}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}

/** Every string an entry holds, but who wrote it, when, and the chain's own hashes. */
function entryText(e: LedgerEntry): string {
  const skip = new Set(["by", "authors", "at", "prev", "hash", "support", "contrary", "limitations", "unsupported_tokens", "v", "seq", "kind"]);
  const parts: string[] = [];
  const walk = (v: unknown) => {
    if (typeof v === "string") parts.push(v);
    else if (typeof v === "number") parts.push(String(v));
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x);
  };
  for (const [k, v] of Object.entries(e)) if (!skip.has(k)) walk(v);
  return parts.join("\n");
}

/**
 * The tokens of an answer's text that none of the entries it rests on holds.
 * An answer cited by another lends its own cited entries, never its text: a
 * token an answer asserted without support does not become supported by
 * being repeated in a summary.
 */
export function unsupportedTokens(text: string, cited: LedgerEntry[], bySeq: Map<number, LedgerEntry>): string[] {
  const pool: LedgerEntry[] = [];
  const seen = new Set<number>();
  const visit = (e: LedgerEntry | undefined) => {
    if (!e || seen.has(e.seq)) return;
    seen.add(e.seq);
    if (e.kind === "answer") for (const x of [...(e.support ?? []), ...(e.contrary ?? []), ...(e.limitations ?? [])]) visit(bySeq.get(x.seq));
    else pool.push(e);
  };
  for (const e of cited) visit(e);
  const raw = pool.map(entryText).join("\n");
  const flat = normalizePathText(raw);
  const lower = raw.toLowerCase();
  const poolTokens = answerTokens(raw);
  const times = poolTokens.filter((t) => t.kind === "time").map((t) => t.norm);
  for (const e of pool) if (e.ts) times.push(e.ts.slice(0, 19));
  const word = (hay: string, needle: string) => new RegExp(`(?<![\\w.])${needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w])`).test(hay);
  const out: string[] = [];
  for (const t of answerTokens(text)) {
    let ok = false;
    if (t.kind === "time") ok = times.some((x) => x.startsWith(t.norm));
    else if (t.kind === "hash") ok = lower.includes(t.norm);
    else if (t.kind === "path") ok = flat.includes(t.norm);
    else if (t.kind === "inode") ok = word(raw, t.norm);
    else if (t.kind === "ip") ok = word(lower, t.norm);
    else ok = flat.includes(t.norm) || lower.includes(t.norm) || raw.toUpperCase().includes(t.norm);
    if (!ok) out.push(t.text);
  }
  return out;
}

// --- disputes -------------------------------------------------------------------------------

/**
 * A line of ledger/disputes.jsonl: an agent other than an entry's authors
 * says why the entry does not hold (`dispute`), or takes that back
 * (`withdraw`, its own dispute only). The why is inside the hashed record;
 * the chain is the file's own.
 */
export type LedgerDispute = { v: 1; act: "dispute" | "withdraw"; seq: number; target: string; by: string; at: string; why: string; refs?: string[]; prev?: string; hash?: string };

export function disputeHash(d: LedgerDispute, prev: string): string {
  const core = JSON.stringify({ v: d.v, act: d.act, seq: d.seq, target: d.target, by: d.by, at: d.at, why: d.why, ...(d.refs?.length ? { refs: d.refs } : {}) });
  return createHash("sha256").update(`${prev}\n${core}`).digest("hex");
}

export async function readDisputes(sandboxRoot: string): Promise<LedgerDispute[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_DISPUTES), "utf8").catch(() => "");
  const out: LedgerDispute[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerDispute);
    } catch {
      // a torn line is left for the chain check to name
    }
  }
  return out;
}

/** The disputes' own chain: each line names the one before it; an unknown version or act is refused. */
export function verifyDisputeChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let last = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let d: LedgerDispute;
    try {
      d = JSON.parse(line) as LedgerDispute;
    } catch {
      return { ok: false, total, broken_at: total, reason: "not json", head: null };
    }
    if (d.v !== 1) return { ok: false, total, broken_at: total, reason: `a dispute of version ${JSON.stringify(d.v)}, which this harness does not know`, head: null };
    if (d.act !== "dispute" && d.act !== "withdraw") return { ok: false, total, broken_at: total, reason: `a dispute line whose act is ${JSON.stringify(d.act)}`, head: null };
    if (d.prev !== last) return { ok: false, total, broken_at: total, reason: "prev does not name the line before it", head: null };
    if (d.hash !== disputeHash(d, last)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    last = d.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? last : null };
}

/** The disputes that stand: each not withdrawn since by the agent that raised it. */
export function standingDisputes(disputes: LedgerDispute[]): LedgerDispute[] {
  const open = new Map<string, LedgerDispute>();
  for (const d of disputes) {
    const key = `${d.target}\u0000${d.by}`;
    if (d.act === "dispute") open.set(key, d);
    else open.delete(key);
  }
  return [...open.values()];
}

/** A dispute in force: one that stands, on the entry it names or, when that entry was corrected, on the correction that stands in its place (inherited_from names the entry it was raised on). */
export type DisputeInForce = LedgerDispute & { inherited_from?: number };

/**
 * The disputes in force. A correction may fix a disputed entry, but the
 * dispute stays open until it is answered: the disputer withdraws it once
 * the correction answers what it said. Until then it stands on the
 * correction that stands in the entry's place (on Belka two limitations
 * were superseded over a standing objection, and the answer and summary
 * that rested on them fell with nobody told why). Each standing dispute on
 * the entry it names, and each whose entry was superseded again on the
 * head of its chain of corrections, marked inherited_from.
 */
export function disputesInForce(entries: LedgerEntry[], disputes: LedgerDispute[]): DisputeInForce[] {
  const standing = standingDisputes(disputes);
  if (!standing.length) return [];
  const replaced = supersededBy(entries);
  if (!replaced.size) return standing;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const byHash = new Map(entries.map((e) => [e.hash ?? ledgerHash(e, "genesis"), e]));
  const out: DisputeInForce[] = [...standing];
  for (const d of standing) {
    const e = byHash.get(d.target);
    if (!e || !replaced.has(e.seq)) continue;
    const head = bySeq.get(standingSeq(e.seq, replaced));
    if (!head || head.seq === e.seq) continue;
    out.push({ ...d, target: head.hash ?? ledgerHash(head, "genesis"), inherited_from: e.seq });
  }
  return out;
}

/** A dispute in force, in words: who, why, and the entry it was raised on when it is inherited. */
export function disputeWords(d: DisputeInForce): string {
  return `${d.by} (${d.why})${d.inherited_from !== undefined ? ` raised on E-${d.inherited_from}, which it corrects, and not yet answered` : ""}`;
}

// --- attest and dispute ---------------------------------------------------------------------

export type LedgerActInput = { seq?: number | string; how?: string; why?: string; refs?: string[] | string; withdraw?: boolean; review?: unknown; strength?: unknown; answer_review?: unknown };

/** The standing entries an answer cites that were recorded for its own question (`id`, its section key). */
export function citedForQuestion(a: LedgerEntry, bySeq: Map<number, LedgerEntry>, replaced: Map<number, number>, id: string): LedgerEntry[] {
  return (a.support ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => Boolean(e) && !replaced.has((e as LedgerEntry).seq) && ((e as LedgerEntry).answers ?? []).some((x) => sectionKey(x) === id));
}

/**
 * Whether an answer's result makes it a negative the bar holds (the finish
 * gate's own test): a bounded negative, not determinable, or a premise
 * rejected on a search alone, where none of the standing entries it cites
 * for its question (`cited`, citedForQuestion) is a finding that shows the
 * premise false.
 */
export function negativeByResult(result: string | null, cited: LedgerEntry[]): boolean {
  return Boolean(result && (NB.NEGATIVE_RESULTS.has(result) || (result === "premise_not_supported" && !cited.some((e) => e.kind === "finding"))));
}

/** Whether an entry is a negative the review bar holds: a coverage record, or an answer bounded_negative or not_determinable. */
export function isNegativeEntry(e: LedgerEntry): boolean {
  if (e.kind === "coverage") return true;
  const r = NB.answerResult(e);
  return r !== null && NB.NEGATIVE_RESULTS.has(r) && Boolean(e.section?.startsWith("question:"));
}
export type LedgerActResult<T> = { ok: true; line: T; appended: boolean; note?: string } | { ok: false; reason: string };

/** The entry an act names, standing, and not the actor's own. */
function actTarget(entries: LedgerEntry[], raw: number | string | undefined, agentId: string, act: string): { ok: true; entry: LedgerEntry } | { ok: false; reason: string } {
  const n = Number(String(raw ?? "").trim().replace(/^(?:#|E-)/i, ""));
  if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `${act} names an entry by its seq (12, "#12" or "E-12"; got ${JSON.stringify(raw)})` };
  const entry = entries.find((e) => e.seq === n);
  if (!entry) return { ok: false, reason: `there is no entry #${n} in the ledger (list them with ledger)` };
  const replaced = supersededBy(entries);
  if (replaced.has(n)) return { ok: false, reason: `#${n} is superseded by #${standingSeq(n, replaced)}: ${act} the entry that stands` };
  if (entry.by === agentId || entry.authors.includes(agentId)) {
    return { ok: false, reason: act === "attest" ? `#${n} is yours (you recorded it, or the same words): an attestation is somebody else re-deriving it` : `#${n} is yours: correct it with record(supersedes=${n}) instead of disputing it` };
  }
  return { ok: true, entry };
}

/**
 * Why a review can hold an answer to a question only as a best candidate
 * (B2), each in words: its confidence is medium or low; the review says a
 * part the question asks is not established; or its would_change names a
 * route nothing took: a planned route of the question (lead_open routes)
 * that no job under it examined, named by its source, or a lead (L-<n>)
 * that is not closed resolved, negative or duplicate. Read from the
 * registers and the refs; the answer's words are only searched for the
 * route sources and lead ids themselves. Empty when nothing caps it.
 */
export async function strengthCaps(sandboxRoot: string, answer: LedgerEntry, review: AnswerReview | null): Promise<string[]> {
  const out: string[] = [];
  if (answer.confidence === "medium" || answer.confidence === "low") out.push(`its confidence is ${answer.confidence}`);
  for (const p of review?.parts ?? []) if (!p.established) out.push(`the review holds "${p.part}" not established (${p.why})`);
  const change = String(answer.would_change ?? "");
  if (!change || !answer.section?.startsWith("question:")) return out;
  const id = sectionAnswersId(answer.section);
  const bar = await questionBar(sandboxRoot, id).catch(() => null);
  const lower = change.toLowerCase();
  for (const r of bar?.routes ?? []) {
    const src = r.source.trim();
    if (src.length < 3 || !lower.includes(src.toLowerCase())) continue;
    const ex = await NB.routeExamined(sandboxRoot, r, { jobs: bar?.jobs ?? [], objects: [] }).catch(() => ({ examined: false, how: "it could not be checked" }));
    if (!ex.examined) out.push(`would_change names ${src} (${r.method}), a planned route nothing examined (${ex.how})`);
  }
  const named = [...new Set([...change.matchAll(/\bL-([1-9]\d{0,5})\b/g)].map((m) => `L-${Number(m[1])}`))];
  if (named.length) {
    const L = await import("./leads.ts");
    const snap = await L.leadsSnapshot(sandboxRoot).catch(() => null);
    for (const lid of named) {
      const l = snap?.state.leads.get(lid);
      if (!l) continue;
      if (l.closed && ["resolved", "negative", "duplicate"].includes(l.closed.disposition)) continue;
      out.push(`would_change names ${lid}, a route not taken (${l.closed ? `closed ${l.closed.disposition}` : l.holder ? `held by ${l.holder}, open` : "open, unheld"})`);
    }
  }
  return out;
}

/**
 * Attest an entry: an agent other than its authors re-derived it and says
 * how — what it re-derived from which sealed objects, and what it only read.
 * Hub-written into ledger/attestations.jsonl (version 2, the how inside the
 * hashed record). The same agent attesting the same entry again is told so.
 */
export async function attestEntry(ctx: SwarmContext, input: LedgerActInput): Promise<LedgerActResult<LedgerAttestation>> {
  const how = boundedText("how", input.how, LEDGER_ACT_MAX_CHARS);
  if (!how.ok) return how;
  if (!how.value) return { ok: false, reason: "how is required: what you re-derived, from which sealed object (job:<id>/<path>, input:<path>, …), and what you only read" };
  const refs = listOf(input.refs);
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names more than ${LEDGER_MAX_REFS} objects` };
  if (refs.length) {
    const checked = await checkRefs(ctx.sandboxRoot, refs);
    if (!checked.ok) return checked;
    const use = await materialUseRefusal(ctx.sandboxRoot, refs);
    if (use) return { ok: false, reason: use };
  }
  let review: NB.NegativeReview | null = null;
  if (input.review !== undefined && input.review !== null) {
    const r = NB.checkReview(input.review);
    if (!r.ok) return r;
    review = r.review;
  }
  const strengthText = String(input.strength ?? "").trim().toLowerCase().replace(/-/g, "_");
  if (strengthText && !(ATTEST_STRENGTHS as readonly string[]).includes(strengthText)) return { ok: false, reason: `strength is established or best_candidate (got ${JSON.stringify(input.strength)})` };
  const strength = (strengthText || undefined) as AttestStrength | undefined;
  let answerReview: AnswerReview | null = null;
  if (input.answer_review !== undefined && input.answer_review !== null) {
    const r = checkAnswerReview(input.answer_review);
    if (!r.ok) return r;
    answerReview = r.review;
  }
  // What caps a review at best_candidate is read before the lock: the route
  // plan and the jobs under the question (the lead register), never the
  // answer's words beyond the refs and lead ids its would_change names.
  const pre = await readLedger(ctx.sandboxRoot);
  const preTarget = actTarget(pre, input.seq, ctx.agentId, "attest");
  const caps = preTarget.ok && preTarget.entry.kind === "answer" && preTarget.entry.section?.startsWith("question:") && !isNegativeEntry(preTarget.entry) ? await strengthCaps(ctx.sandboxRoot, preTarget.entry, answerReview) : [];
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const t = actTarget(entries, input.seq, ctx.agentId, "attest");
    if (!t.ok) return t;
    const target = t.entry.hash ?? ledgerHash(t.entry, "genesis");
    // An answer to a question is attested with how strongly the review holds
    // it, and the review part by part (B2): a best candidate you cannot break
    // is still a best candidate. A medium or low confidence, a part not
    // established, or a route its would_change names that nothing took
    // allows only best_candidate, which does not satisfy the finish line.
    const questionAnswer = t.entry.kind === "answer" && Boolean(t.entry.section?.startsWith("question:")) && !isNegativeEntry(t.entry);
    if (questionAnswer) {
      if (!strength) return { ok: false, reason: `#${t.entry.seq} answers ${t.entry.section}: its attest says how strongly you hold it, strength established or best_candidate, with answer_review {reproduced, read, parts: [{part, established, why}], inference, alternatives, other_family: {checked, text}}` };
      if (!answerReview) return { ok: false, reason: `#${t.entry.seq} answers ${t.entry.section}: give answer_review {reproduced (what you re-derived yourself), read (what you only read), parts (each part the question asks, established or not, and why), inference (what connects the observations to the answer), alternatives (what the evidence still allows), other_family {checked, text} (whether another source family was checked, or why not)}` };
      if (strength === "established" && caps.length) return { ok: false, reason: `#${t.entry.seq} can be attested best_candidate only: ${caps.join("; ")}. Attest it best_candidate (it does not satisfy the finish line), or take the route and record what it shows` };
    } else if (answerReview) {
      return { ok: false, reason: `answer_review is for an answer to a question; #${t.entry.seq} is ${isNegativeEntry(t.entry) ? "a negative: its attest is a review {detection, reproduced, other_route}" : t.entry.kind === "answer" ? `the ${t.entry.section} (say in how what you re-derived)` : `a ${t.entry.kind}: say in how what you re-derived`}` };
    } else if (strength && !(t.entry.kind === "answer" && t.entry.section?.startsWith("question:"))) {
      return { ok: false, reason: `strength is for an answer to a question; #${t.entry.seq} is ${t.entry.kind === "answer" ? `the ${t.entry.section}` : `a ${t.entry.kind}`}` };
    }
    // A negative is attested with its review: what was challenged, reproduced or tried, or why not.
    const negative = isNegativeEntry(t.entry);
    if (negative && !review) {
      return {
        ok: false,
        reason: `#${t.entry.seq} is a ${t.entry.kind === "coverage" ? "coverage record" : `negative answer (${NB.resultWords(NB.answerResult(t.entry))})`}: its attest is a review. Give review {detection: {done, text}, reproduced: {done, text}, other_route: {done, text}}: whether you challenged the detection assumptions, reproduced a decisive check, tried a materially different route, each with what you did or why not`,
      };
    }
    if (!negative && review) return { ok: false, reason: `review is for a negative (a coverage record, or an answer bounded_negative or not_determinable); #${t.entry.seq} is a ${t.entry.kind}: say in how what you re-derived` };
    if (negative && t.entry.kind === "answer") {
      // Whoever recorded a coverage record the answer rests on is not its reviewer either.
      const bySeq = new Map(entries.map((e) => [e.seq, e]));
      const covAuthors = (t.entry.support ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => e?.kind === "coverage").flatMap((e) => e.authors);
      if (covAuthors.includes(ctx.agentId)) return { ok: false, reason: `you recorded the coverage record #${t.entry.seq} rests on: a review of a negative is another seat's` };
    }
    const mineAgainst = disputesInForce(entries, await readDisputes(ctx.sandboxRoot)).find((d) => d.target === target && d.by === ctx.agentId);
    if (mineAgainst) {
      return { ok: false, reason: mineAgainst.inherited_from !== undefined ? `you disputed #${mineAgainst.inherited_from}, which #${t.entry.seq} corrects, and the dispute stands on the correction until you answer it: withdraw it (dispute withdraw=true on #${t.entry.seq}, with why the correction answers it) before attesting` : `you dispute #${t.entry.seq}: withdraw the dispute (dispute withdraw=true, with why) before attesting it` };
    }
    const attested = await readAttestations(ctx.sandboxRoot);
    const mine = attested.find((a) => attestationAct(a) === "attest" && a.target === target && a.by === ctx.agentId);
    if (mine) return { ok: true, line: mine, appended: false, note: `you attested #${t.entry.seq} already` };
    await held.assertOwned();
    const line = await appendAttestation(ctx.sandboxRoot, attested, { v: 2, act: "attest", seq: t.entry.seq, target, by: ctx.agentId, at: new Date().toISOString(), how: how.value, ...(refs.length ? { refs } : {}), ...(review ? { review } : {}), ...(strength ? { strength } : {}), ...(answerReview ? { answer_review: answerReview } : {}), ...(questionAnswer && caps.length ? { capped: caps } : {}) });
    await renderLedger(ctx.sandboxRoot);
    const note = review
      ? `recorded as the review of a negative: ${NB.reviewWords(review)}`
      : strength === "best_candidate"
        ? `recorded as a best candidate${caps.length ? ` (${caps.join("; ")})` : ""}: ${t.entry.section} is not established by it, and the finish line says so; the way out is the route that would settle it, or the operator's acceptance of its limits`
        : undefined;
    return { ok: true, line, appended: true, ...(note ? { note } : {}) };
  });
}

/**
 * Why a coverage record no longer says what its search found: an entry
 * among its results that is not in the ledger, is not the entry it bound
 * (another hash), was superseded, or is disputed. A record from before
 * results were bound is held to its results as they stand. Empty when it
 * stands.
 */
export function coverageProblems(c: LedgerEntry, entries: LedgerEntry[], disputes: LedgerDispute[] = []): string[] {
  return coverageStaleness(c, entries, disputes).map((x) =>
    x.code === "missing"
      ? `its result E-${x.result} is not in the ledger`
      : x.code === "rebound"
        ? `its result E-${x.result} is not the entry it bound (the hash differs)`
        : x.code === "superseded"
          ? `its result E-${x.result} is superseded by #${x.by_seq}`
          : `its result E-${x.result} is disputed by ${x.disputes!.map(disputeWords).join("; ")}`,
  );
}

/**
 * coverageProblems as data: each result of the record that no longer stands,
 * by code (missing, rebound: another entry than the one bound, superseded,
 * disputed), with the entry that superseded it or the disputes against it.
 */
export function coverageStaleness(c: LedgerEntry, entries: LedgerEntry[], disputes: LedgerDispute[] = []): Array<{ result: number; code: "missing" | "rebound" | "superseded" | "disputed"; by_seq?: number; disputes?: DisputeInForce[] }> {
  if (c.kind !== "coverage") return [];
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  // A dispute stays in force on the correction of the entry it named (B18, disputesInForce).
  const against = disputesInForce(entries, disputes);
  const out: Array<{ result: number; code: "missing" | "rebound" | "superseded" | "disputed"; by_seq?: number; disputes?: DisputeInForce[] }> = [];
  for (const r of c.result_refs ?? []) {
    const m = /^E-(\d+)$/.exec(r);
    if (!m) continue;
    const seq = Number(m[1]);
    const e = bySeq.get(seq);
    if (!e) {
      out.push({ result: seq, code: "missing" });
      continue;
    }
    const hash = e.hash ?? ledgerHash(e, "genesis");
    const bound = c.result_bound?.find((x) => x.seq === seq);
    if (bound && bound.hash !== hash) out.push({ result: seq, code: "rebound" });
    if (replaced.has(seq)) out.push({ result: seq, code: "superseded", by_seq: standingSeq(seq, replaced) });
    const d = against.filter((x) => x.target === hash);
    if (d.length) out.push({ result: seq, code: "disputed", disputes: d });
  }
  return out;
}

/**
 * Whether a negative stands reviewed: an attest with its review, by a seat
 * that recorded neither the answer nor a coverage record it rests on, on the
 * answer or on one of those records. Who reviewed, and what they said. A
 * review is of what stood when it was made: one on a coverage record whose
 * results no longer stand counts for nothing, and neither does one on the
 * answer while any coverage record it rests on is so.
 */
export function negativeReview(
  answer: LedgerEntry,
  entries: LedgerEntry[],
  attestations: LedgerAttestation[],
  disputes: LedgerDispute[] = [],
): { reviewed: boolean; by: string[]; reviews: Array<{ by: string; seq: number; review: NB.NegativeReview }>; stale: Array<{ seq: number; problems: string[] }> } {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const cov = answer.kind === "coverage" ? [answer] : (answer.support ?? []).map((x) => bySeq.get(x.seq)).filter((e): e is LedgerEntry => e?.kind === "coverage" && !replaced.has(e.seq));
  const stale = cov.map((c) => ({ seq: c.seq, problems: coverageProblems(c, entries, disputes) })).filter((x) => x.problems.length);
  const standingCov = cov.filter((c) => !stale.some((x) => x.seq === c.seq));
  const authors = new Set([answer.by, ...answer.authors, ...cov.flatMap((c) => [c.by, ...c.authors])]);
  const targets = new Map<string, number>([...(stale.length && answer.kind !== "coverage" ? [] : [[answer.hash ?? ledgerHash(answer, "genesis"), answer.seq] as [string, number]]), ...standingCov.map((c): [string, number] => [c.hash ?? ledgerHash(c, "genesis"), c.seq])]);
  const reviews = attestations.filter((a) => attestationAct(a) === "attest" && a.review && a.target && targets.has(a.target) && !authors.has(a.by)).map((a) => ({ by: a.by, seq: targets.get(a.target!)!, review: a.review! }));
  return { reviewed: reviews.length > 0, by: [...new Set(reviews.map((r) => r.by))], reviews, stale };
}

/**
 * Dispute an entry: why it does not hold, with the objects that show it.
 * Or, with `withdraw`, take one's own dispute back and say why. Hub-written
 * into ledger/disputes.jsonl. An answer resting on a disputed entry is marked
 * until it is recorded again with the dispute answered.
 */
export async function disputeEntry(ctx: SwarmContext, input: LedgerActInput): Promise<LedgerActResult<LedgerDispute>> {
  const why = boundedText("why", input.why, LEDGER_ACT_MAX_CHARS);
  if (!why.ok) return why;
  if (!why.value) return { ok: false, reason: input.withdraw ? "why is required: why the dispute no longer stands" : "why is required: what does not hold, and what shows it" };
  const refs = listOf(input.refs);
  if (refs.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names more than ${LEDGER_MAX_REFS} objects` };
  if (refs.length) {
    const checked = await checkRefs(ctx.sandboxRoot, refs);
    if (!checked.ok) return checked;
    if (!input.withdraw) {
      const use = await materialUseRefusal(ctx.sandboxRoot, refs);
      if (use) return { ok: false, reason: use };
    }
  }
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const t = actTarget(entries, input.seq, ctx.agentId, "dispute");
    if (!t.ok) return t;
    const target = t.entry.hash ?? ledgerHash(t.entry, "genesis");
    const all = await readDisputes(ctx.sandboxRoot);
    // A dispute stands on the correction of the entry it named until the
    // disputer answers it (B18): withdrawn by naming either entry.
    const standing = disputesInForce(entries, all).find((d) => d.target === target && d.by === ctx.agentId);
    if (input.withdraw && !standing) return { ok: false, reason: `you have no standing dispute of #${t.entry.seq} to withdraw` };
    if (!input.withdraw && standing) return { ok: true, line: standing, appended: false, note: standing.inherited_from !== undefined ? `you disputed #${standing.inherited_from}, which #${t.entry.seq} corrects, and that dispute stands on it until you withdraw it: ${standing.why}` : `you dispute #${t.entry.seq} already: ${standing.why}` };
    // A withdrawal names the dispute it ends: the entry that dispute was raised on.
    const named = standing?.inherited_from !== undefined ? entries.find((e) => e.seq === standing.inherited_from) : undefined;
    const d: LedgerDispute = { v: 1, act: input.withdraw ? "withdraw" : "dispute", seq: named ? named.seq : t.entry.seq, target: named ? (named.hash ?? ledgerHash(named, "genesis")) : target, by: ctx.agentId, at: new Date().toISOString(), why: why.value, ...(refs.length ? { refs } : {}) };
    const prev = all.at(-1)?.hash ?? "genesis";
    const line: LedgerDispute = { ...d, prev, hash: disputeHash(d, prev) };
    await held.assertOwned();
    await mkdir(join(ctx.sandboxRoot, LEDGER_DIR), { recursive: true });
    await appendFile(join(ctx.sandboxRoot, LEDGER_DISPUTES), `${JSON.stringify(line)}\n`, "utf8");
    await renderLedger(ctx.sandboxRoot);
    return { ok: true, line, appended: true };
  });
}

// --- answers --------------------------------------------------------------------------------

/** The fields an answer never takes: it rests on entries, not objects, and states no event. */
const NOT_ANSWER_FIELDS = ["ts", "refs", "answers", "rel", "clock", "precision", "basis", "status", "reason", "completion", "attribution", "locators", "indicates", "alternatives", "alternatives_none_why", "significance", ...COVERAGE_ONLY_FIELDS] as const;

/** Each ref of an entry whose job did not succeed and that the entry does not qualify itself. */
async function unqualifiedFailedRefs(sandboxRoot: string, e: LedgerEntry): Promise<string[]> {
  if (!e.refs?.length) return [];
  const { resolveRef } = await import("../scripts/evidence-store.ts");
  const out: string[] = [];
  for (const ref of e.refs) {
    if (!ref.startsWith("job:")) continue;
    const r = await resolveRef(sandboxRoot, ref).catch(() => null);
    if (r?.ok && r.status && r.status !== "ok" && !(e.qualifies ?? []).some((q) => q.ref === ref)) out.push(`${ref} (${r.status})`);
  }
  return out;
}

/**
 * What an answer concludes and rests on, as a summary's symbolic citation
 * binds it (A4): its result, the question revision it answers, and the
 * hashes of its support, its contrary evidence and its limitations. Its
 * words are not in it: a correction that only rewords keeps it.
 */
export function answerFingerprint(a: LedgerEntry): string {
  const hashes = (edges: LedgerEdge[] | undefined) => (edges ?? []).map((x) => x.hash).sort();
  return sha256Hex(JSON.stringify({ result: NB.answerResult(a), question_rev: a.question_rev ?? 1, support: hashes(a.support), contrary: hashes(a.contrary), limitations: hashes(a.limitations), inconclusive: a.inconclusive === true, asserts_absence: a.asserts_absence === true }));
}

/** The questions a summary or a narrative names symbolically: Q-<n>, and question:<id>. */
export function symbolicQuestions(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/\bQ-([1-9]\d{0,5})\b/g)) if (!out.includes(`Q-${Number(m[1])}`)) out.push(`Q-${Number(m[1])}`);
  for (const m of text.matchAll(/\bquestion:([A-Za-z0-9._-]{1,16})\b/g)) if (!out.includes(`question:${m[1]}`)) out.push(`question:${m[1]}`);
  return out;
}

/**
 * Why each standing answer no longer stands on its own support, transitively:
 * an entry it cites was superseded and its correction is not cited with it,
 * or was disputed (or rests on a failed job) and the answer does not qualify
 * it, or is an answer that itself no longer stands; or the cited hash is not
 * the entry's. Its contrary evidence is held to the same: corrected or
 * disputed since it was weighed, the answer is weighed again. `failed` names, by seq, the entries resting on a failed job's
 * output that they do not qualify themselves.
 */
export function answerProblems(entries: LedgerEntry[], disputes: LedgerDispute[], failed: Map<number, string[]> = new Map()): Map<number, string[]> {
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const disputed = new Map<string, DisputeInForce[]>();
  for (const d of disputesInForce(entries, disputes)) disputed.set(d.target, [...(disputed.get(d.target) ?? []), d]);
  const memo = new Map<number, string[]>();
  const visiting = new Set<number>();
  const problemsOf = (a: LedgerEntry): string[] => {
    const hit = memo.get(a.seq);
    if (hit) return hit;
    if (visiting.has(a.seq)) return [];
    visiting.add(a.seq);
    const out: string[] = [];
    const qualified = (seq: number) => (a.qualifies ?? []).some((q) => q.ref === `E-${seq}`);
    const cited = new Set([...(a.support ?? []), ...(a.contrary ?? []), ...(a.limitations ?? [])].map((x) => x.seq));
    // A summary's symbolic citations (A4): each question's standing answer,
    // held to the fingerprint it had when cited, never to its seq alone.
    for (const r of a.question_refs ?? []) {
      const now = entries.find((e) => e.kind === "answer" && e.section === r.section && !replaced.has(e.seq));
      if (!now) {
        out.push(`it cites ${r.q} (${r.section}), which has no standing answer now`);
        continue;
      }
      if (answerFingerprint(now) !== r.fp) {
        out.push(`it cites ${r.q} (${r.section}), whose answer changed its support, scope or contrary evidence since it was cited (E-${r.answer}${now.seq !== r.answer ? ` → E-${now.seq}` : ""})`);
        continue;
      }
      const sub = problemsOf(now);
      if (sub.length) out.push(`it cites ${r.q} (${r.section}), whose answer E-${now.seq} no longer stands on its own support`);
    }
    for (const [edges, role] of [[a.support ?? [], "rests on"], [a.limitations ?? [], "is bounded by"]] as const) {
      for (const edge of edges) {
        const t = bySeq.get(edge.seq);
        if (!t) {
          out.push(`it ${role} E-${edge.seq}, which is not in the ledger`);
          continue;
        }
        if ((t.hash ?? ledgerHash(t, "genesis")) !== edge.hash) {
          out.push(`it ${role} E-${edge.seq} by a hash that is not that entry's`);
          continue;
        }
        if (replaced.has(t.seq)) {
          const now = standingSeq(t.seq, replaced);
          if (!cited.has(now)) out.push(`it ${role} E-${t.seq}, superseded by #${now}, and does not cite the correction`);
          continue;
        }
        const against = disputed.get(edge.hash);
        if (against?.length && !qualified(t.seq)) out.push(`it ${role} E-${t.seq}, disputed by ${against.map(disputeWords).join("; ")}`);
        const bad = failed.get(t.seq);
        if (bad?.length && !qualified(t.seq)) out.push(`it ${role} E-${t.seq}, which rests on the kept output of a job that did not succeed (${bad.join(", ")}) and says nothing of it`);
        if (t.kind === "answer") {
          const sub = problemsOf(t);
          if (sub.length) out.push(`it ${role} E-${t.seq}, an answer that no longer stands on its own support`);
        }
      }
    }
    // The contrary evidence it weighed (A4): the weighing was of the entry
    // as it stood. Corrected since (and the correction not weighed with it)
    // or disputed (and not qualified), what the answer concludes against it
    // is to be weighed again; its fingerprint holds the hashes it cited, so
    // only its current standing shows the change.
    for (const edge of a.contrary ?? []) {
      const t = bySeq.get(edge.seq);
      if (!t) {
        out.push(`it weighs E-${edge.seq} as contrary evidence, which is not in the ledger`);
        continue;
      }
      if ((t.hash ?? ledgerHash(t, "genesis")) !== edge.hash) {
        out.push(`it weighs E-${edge.seq} as contrary evidence by a hash that is not that entry's`);
        continue;
      }
      if (replaced.has(t.seq)) {
        const now = standingSeq(t.seq, replaced);
        if (!cited.has(now)) out.push(`it weighs E-${t.seq} as contrary evidence, superseded by #${now}, and does not weigh the correction`);
        continue;
      }
      const against = disputed.get(edge.hash);
      if (against?.length && !qualified(t.seq)) out.push(`it weighs E-${t.seq} as contrary evidence, disputed by ${against.map(disputeWords).join("; ")}`);
    }
    visiting.delete(a.seq);
    memo.set(a.seq, out);
    return out;
  };
  const result = new Map<number, string[]>();
  for (const e of entries) {
    if (e.kind !== "answer" || replaced.has(e.seq)) continue;
    const p = problemsOf(e);
    if (p.length) result.set(e.seq, p);
  }
  return result;
}

/** The fields of an entry, of any version, that can hold what it says. */
const ENTRY_TEXT_FIELDS = ["value", "evidence", "source", "indicates", "confidence_why", "reasoning", "would_change", "alternatives_open", "alternatives_none_why", "because", "time_range", "search_method", "settings", "coverage_actual", "skipped", "failures"] as const;

/** One of a sensitive entry's words, with the entry it came from; `exact` when it is a short field held whole, matched as a whole word. */
export type SensitiveToken = { token: string; seq: number; exact?: boolean };

/**
 * What a sensitive entry says, as the words redaction looks for: each text
 * field whole (six characters or more, or four with a digit in it), and
 * each identifier-like run inside one (eight characters or more with a
 * digit, an @, a dot, a slash, a backslash or a colon in it: a key, a
 * token, an address, a path, an account), longest first, each with the
 * entry it came from. With `short`, a field shorter than that (a name such
 * as "Alice") is kept too, whole and marked `exact`: what a person marked
 * sensitive stays so whatever its length, and it is matched as a whole word
 * (B9), never inside another.
 */
export function sensitiveTokens(entries: LedgerEntry[], o: { short?: boolean } = {}): SensitiveToken[] {
  const out = new Map<string, number>();
  const exact = new Set<string>();
  const add = (t: string, seq: number, isExact = false) => {
    if (!out.has(t)) {
      out.set(t, seq);
      if (isExact) exact.add(t);
    }
  };
  for (const e of entries) {
    if (!e.sensitive) continue;
    const raw = e as unknown as Record<string, unknown>;
    const texts: string[] = [];
    for (const f of ENTRY_TEXT_FIELDS) if (typeof raw[f] === "string") texts.push(raw[f] as string);
    if (e.attribution?.subject) texts.push(e.attribution.subject);
    for (const l of e.locators ?? []) texts.push(l.at);
    for (const a of (raw.alternatives as Array<{ explanation?: string; why?: string }> | undefined) ?? []) texts.push(a.explanation ?? "", a.why ?? "");
    for (const q of (raw.qualifies as Array<{ why?: string }> | undefined) ?? []) texts.push(q.why ?? "");
    for (const w of texts) {
      const whole = (w ?? "").trim();
      if (whole.length >= 6 || (whole.length >= 4 && /\d/.test(whole))) add(whole, e.seq);
      else if (o.short && sensitiveFold(whole).length >= 2) add(whole, e.seq, true);
      for (const t of whole.match(/[^\s"'`,;()<>[\]{}]{8,}/g) ?? []) if (/[\d@./\\:]/.test(t)) add(t.replace(/[.:]+$/, ""), e.seq);
    }
  }
  return [...out].map(([token, seq]) => ({ token, seq, ...(exact.has(token) ? { exact: true } : {}) })).sort((a, b) => b.token.length - a.token.length || a.token.localeCompare(b.token));
}

/**
 * A text as B9 compares it: Unicode folded to its compatibility form (NFKC:
 * a full-width or composed letter is the letter), invisible format and
 * default-ignorable characters removed, case folded, and the markup a name
 * loses when it is tidied (backquote, asterisk, underscore, brackets)
 * dropped and whitespace collapsed, so what is compared is what a board
 * would show.
 */
export function sensitiveFold(text: string): string {
  return String(text ?? "")
    .normalize("NFKC")
    .replace(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, "")
    .toLowerCase()
    .normalize("NFKC")
    .replace(/[`*_\[\]]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Every value the run marks sensitive, whatever its origin (B9, docs/adr/0014):
 * what each ledger entry recorded sensitive says, of any kind and by anyone
 * (an agent's finding or answer, external material the operator supplied as
 * sensitive), standing or superseded, since a value once marked sensitive
 * stays so. There is no "answer value" concept and no exemption for words
 * the goal itself uses: a value is sensitive wherever it first appeared.
 */
export async function runSensitiveTokens(sandboxRoot: string): Promise<SensitiveToken[]> {
  const entries = await readLedger(sandboxRoot, { raw: true }).catch(() => [] as LedgerEntry[]);
  return entries.some((e) => e.sensitive) ? sensitiveTokens(entries, { short: true }) : [];
}

/**
 * The first sensitive value a text holds, or null: both folded the same way
 * (sensitiveFold), a value held inside the text, and a short value held
 * whole (`exact`) found only as a whole word.
 */
export function sensitiveHit(text: string, tokens: SensitiveToken[]): SensitiveToken | null {
  if (!text || !tokens.length) return null;
  const folded = sensitiveFold(text);
  const squeezed = folded.replace(/ /g, "");
  for (const t of tokens) {
    const f = sensitiveFold(t.token);
    if (!f) continue;
    if (t.exact) {
      if (new RegExp(`(?<![\\p{L}\\p{N}])${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}])`, "u").test(folded)) return t;
      continue;
    }
    // A value is found as it would be read: inside the text, or with the spaces a line break or a tidy put in it taken out.
    if (folded.includes(f) || (f.length >= 6 && squeezed.includes(f.replace(/ /g, "")))) return t;
  }
  return null;
}

/**
 * The refusal for words that would carry a value the run marks sensitive
 * (a name, a `doing` label, a question's text, its reasons and hints),
 * naming the field and the entry, never the value; null when none does.
 */
export async function sensitiveRefusalOf(sandboxRoot: string, texts: Array<[string, string | undefined | null]>): Promise<string | null> {
  const tokens = await runSensitiveTokens(sandboxRoot);
  if (!tokens.length) return null;
  for (const [name, text] of texts) {
    const hit = text ? sensitiveHit(text, tokens) : null;
    if (hit) return `${name} holds a value the run marks sensitive (E-${hit.seq}): say it without the value; the entry can be cited by its number`;
  }
  return null;
}

/** Who asked a question section, when a person did (the question register): their words for the refusal, or null. */
async function personsQuestion(sandboxRoot: string, sectionId: string): Promise<string | null> {
  const Q = await import("./questions.ts");
  const snap = await Q.questionsSnapshot(sandboxRoot);
  const q = snap.bySection.get(sectionId);
  if (!q || !Q.HUMAN_ORIGINS.has(q.origin.kind)) return null;
  return `${q.id}, asked by ${Q.originWords(q.origin)}`;
}

/** A question section's register id and current revision, or null when the register has no question for it. */
async function registerRevision(sandboxRoot: string, sectionId: string): Promise<{ id: string; rev: number } | null> {
  const Q = await import("./questions.ts");
  const q = (await Q.questionsSnapshot(sandboxRoot)).bySection.get(sectionId);
  return q ? { id: q.id, rev: q.rev } : null;
}

/**
 * A register id (Q-9) as the section it answers: its number, or the goal's
 * own id when the goal numbers it otherwise ("bonus"). Other ids pass.
 */
async function registerSection(sandboxRoot: string, raw: string): Promise<string> {
  const m = /^(question:)?Q-([1-9]\d{0,5})$/i.exec(String(raw ?? "").trim());
  if (!m) return raw;
  const Q = await import("./questions.ts");
  const q = (await Q.questionsSnapshot(sandboxRoot)).state.questions.get(`Q-${Number(m[2])}`);
  return q ? `${m[1] ?? ""}${q.section}` : raw;
}

/**
 * What the negative bar needs to know of a question section: whether it is
 * material (the goal's always are; a register question says), whether it
 * asks whether something exists (the goal's --existence, or the register's
 * expects), its route plan (every route the leads under it planned), and the
 * jobs run under those leads. Read from the registers, never from words.
 */
export async function questionBar(sandboxRoot: string, sectionId: string): Promise<{ material: boolean; existence: boolean; routes: NB.Route[]; jobs: string[]; question: string | null }> {
  const L = await import("./leads.ts");
  const snap = await L.leadsSnapshot(sandboxRoot);
  const id = sectionKey(sectionId);
  const q = snap.questions?.bySection.get(id) ?? null;
  const goal = snap.goal.questions.map(sectionKey).includes(id);
  const material = goal || !q ? true : q.materiality === "material";
  const existence = snap.goal.existence.map(sectionKey).includes(id) || q?.expects === "existence";
  const routes: NB.Route[] = [];
  const jobs: string[] = [];
  for (const l of snap.state.leads.values()) {
    if (!l.answers.some((a) => sectionKey(a) === id)) continue;
    for (const r of l.routes ?? []) if (!routes.some((x) => x.source === r.source && x.method === r.method)) routes.push(r);
    for (const j of l.jobs) if (!jobs.includes(j)) jobs.push(j);
  }
  return { material, existence, routes, jobs, question: q?.id ?? null };
}

/**
 * Record a coverage record (recordEntry with kind=coverage): what a negative,
 * or a "not determinable", was searched over. Every field is required, each
 * may say "none" with why; the hub adds the inventory revision, whether the
 * jobs behind it were given every object it names (coverage complete or
 * partial, with each unit and how), and the planned routes of its questions
 * that nothing examined. A record is about questions: it names them in
 * answers, and an answer cites it.
 */
async function recordCoverage(ctx: SwarmContext, input: LedgerInput): Promise<LedgerResult> {
  const raw = input as Record<string, unknown>;
  const notHere = [...ANSWER_ONLY_FIELDS.filter((f) => f !== "alternatives_open"), "indicates", "alternatives_none_why", "significance", "status", "reason", "completion", "ts", "clock", "precision", "basis", "attribution", "locators"].find((f) => given(raw[f]) && !(f === "alternatives" && typeof raw[f] === "string"));
  if (notHere) return { ok: false, reason: `${notHere} is not a coverage record's: it says what a search covered, and the entries it rests on say what was found` };
  const proposition = String(input.proposition ?? "").trim();
  const said = String(input.value ?? "").trim();
  if (proposition && said && proposition !== said) return { ok: false, reason: "value and proposition are the same field on a coverage record (the proposition searched): give one" };
  const value = proposition || said;
  if (!value) return { ok: false, reason: "proposition (or value) is required: the proposition the search tested, in one sentence (\"the account signed in from outside the office network\")" };
  if (value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `the proposition is over ${LEDGER_VALUE_MAX_CHARS} characters` };
  const text = (name: string, v: unknown, required = true): { ok: true; value: string } | { ok: false; reason: string } => {
    const t = boundedText(name, v, NB.COVERAGE_TEXT_MAX);
    if (!t.ok) return t;
    if (required && !t.value) return { ok: false, reason: `${name} is required on a coverage record${name === "skipped" || name === "failures" ? ' ("none" when nothing was, with how that is known)' : ""}` };
    return t;
  };
  const timeRange = text("time_range", input.time_range);
  if (!timeRange.ok) return timeRange;
  const method = text("search_method", input.search_method);
  if (!method.ok) return method;
  const settings = text("settings", input.settings);
  if (!settings.ok) return settings;
  const actual = text("coverage_actual", input.coverage_actual);
  if (!actual.ok) return actual;
  const skipped = text("skipped", input.skipped);
  if (!skipped.ok) return skipped;
  const failures = text("failures", input.failures);
  if (!failures.ok) return failures;
  const alternatives = text("alternatives", typeof raw.alternatives === "string" ? raw.alternatives : input.alternatives_open);
  if (!alternatives.ok) return { ok: false, reason: alternatives.reason.replace("alternatives is required", "alternatives is required: the explanations or routes still open, or none and why") };
  const d = (input.detection_opportunity ?? {}) as { trace_expected?: unknown; why?: unknown };
  const expected = String(d.trace_expected ?? "").trim().toLowerCase();
  if (!(NB.TRACE_EXPECTED as readonly string[]).includes(expected)) return { ok: false, reason: "detection_opportunity is {trace_expected: yes | no | unknown, why}: would the event have left a trace in these sources, given what was collected and what they keep, and why" };
  const dWhy = text("detection_opportunity.why", d.why);
  if (!dWhy.ok) return dWhy;
  const source = boundedText("source", input.source, LEDGER_SOURCE_MAX_CHARS);
  if (!source.ok) return source;
  const evidence = boundedText("evidence", input.evidence, LEDGER_EVIDENCE_MAX_CHARS);
  if (!evidence.ok) return evidence;
  const answers = listOf(input.answers);
  if (!answers.length) return { ok: false, reason: 'answers is required on a coverage record: the questions its search was for ("3", "Q-19")' };
  if (answers.length > LEDGER_MAX_ANSWERS) return { ok: false, reason: `answers names more than ${LEDGER_MAX_ANSWERS} sections` };
  const badAnswer = answers.find((a) => !LEDGER_ANSWER_ID.test(a));
  if (badAnswer) return { ok: false, reason: `answers takes the questions' section ids (got ${JSON.stringify(badAnswer)})` };
  const objects = [...new Set((Array.isArray(input.refs) ? input.refs.map(String) : String(input.refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))];
  if (!objects.length) return { ok: false, reason: "refs is required on a coverage record: the objects the search was over (input:<path>, member:<gen>#<n>, job:<id>/<path>, …); the hub holds the jobs behind it to them" };
  if (objects.length > LEDGER_MAX_REFS) return { ok: false, reason: `refs names more than ${LEDGER_MAX_REFS} objects: name the directory or the container that holds them` };
  // Each object resolves, or is a directory of the run's objects (the evidence
  // directory, a job's whole output, a generation) as the job scopes take it.
  for (const obj of objects) {
    const checked = await checkRefs(ctx.sandboxRoot, [obj]);
    if (checked.ok) continue;
    const dir = await NB.coverageDirectory(ctx.sandboxRoot, obj);
    if (!dir.ok) return checked;
  }
  const results = [...new Set((Array.isArray(input.result_refs) ? input.result_refs.map(String) : String(input.result_refs ?? "").split(/[\s,]+/)).map((r) => r.trim()).filter(Boolean))].map((r) => (/^#\d+$/.test(r) ? `E-${r.slice(1)}` : /^e-\d+$/i.test(r) ? r.toUpperCase() : r));
  if (!results.length) return { ok: false, reason: "result_refs is required: what the search produced, the entries (E-<seq>: an absence, a limitation, a finding) and the job outputs (job:<id>[/<path>])" };
  if (results.length > LEDGER_MAX_CITATIONS) return { ok: false, reason: `result_refs names more than ${LEDGER_MAX_CITATIONS}` };
  const jobRefs = results.filter((r) => !/^E-\d+$/.test(r));
  const badResult = jobRefs.find((r) => !/^(job|import|member|sha256|input):/.test(r));
  if (badResult) return { ok: false, reason: `result_refs names entries as E-<seq> and objects as job:<id>[/<path>] (got ${JSON.stringify(badResult)})` };
  if (jobRefs.length) {
    const c = await checkRefs(ctx.sandboxRoot, jobRefs);
    if (!c.ok) return { ok: false, reason: `result_refs: ${c.reason}` };
  }
  const inventory = await NB.inventoryRevision(ctx.sandboxRoot);
  const givenRev = String(input.inventory_rev ?? "").trim();
  if (givenRev && givenRev !== inventory) return { ok: false, reason: `inventory_rev ${givenRev} is not the run's inventory now (${inventory}): the evidence changed since the search; leave it out, and the hub writes the one the record is made against` };
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})` };
    supersedes = n;
  }
  const because = boundedText("because", input.because, LEDGER_BECAUSE_MAX_CHARS);
  if (!because.ok) return because;
  if (because.value && supersedes === undefined) return { ok: false, reason: "because says why a correction corrects: give supersedes too" };
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") return { ok: false, reason: "sensitive is true or false" };
  // The planned routes of the questions it is for, and the jobs under them.
  const bars = await Promise.all(answers.map((a) => questionBar(ctx.sandboxRoot, a)));
  const L = await import("./leads.ts");
  const leads = await L.leadsSnapshot(ctx.sandboxRoot);
  const method2 = await ledgerMethods(ctx.sandboxRoot, objects);
  return withTableLock(ctx.sandboxRoot, async (held) => {
    const entries = await readLedger(ctx.sandboxRoot);
    const bySeq = new Map(entries.map((e) => [e.seq, e]));
    const replaced = supersededBy(entries);
    for (const r of results.filter((x) => /^E-\d+$/.test(x))) {
      const n = Number(r.slice(2));
      const e = bySeq.get(n);
      if (!e) return { ok: false, reason: `result_refs names ${r}: there is no entry #${n} in the ledger` };
      if (replaced.has(n)) return { ok: false, reason: `result_refs names ${r}, superseded by #${standingSeq(n, replaced)}: name the entry that stands` };
      if (e.kind === "answer" || e.kind === "coverage") return { ok: false, reason: `result_refs names ${r}, a ${e.kind}: a search's results are what it found or failed to (absences, limitations, findings, events)` };
    }
    if (supersedes !== undefined) {
      const target = bySeq.get(supersedes);
      if (!target) return { ok: false, reason: `supersedes #${supersedes}: there is no entry #${supersedes} in the ledger` };
      if (target.kind !== "coverage") return { ok: false, reason: `#${supersedes} is a ${target.kind}: a coverage record corrects a coverage record` };
      const already = replaced.get(supersedes);
      if (already !== undefined) return { ok: false, reason: `#${supersedes} is already superseded by #${already}: correct #${already} instead` };
    }
    const cov = await NB.computeObjectCoverage(ctx.sandboxRoot, { objects, resultRefs: results, entries, interpretations: leads.state.interpretations });
    // The planned routes nothing examined: said on the record, whatever the search found.
    const notExamined: Array<{ source: string; method: string; why: string }> = [];
    for (const b of bars) {
      for (const r of b.routes) {
        if (notExamined.some((x) => x.source === r.source && x.method === r.method)) continue;
        const ex = await NB.routeExamined(ctx.sandboxRoot, r, { jobs: [...new Set([...b.jobs, ...cov.jobs])], objects });
        if (!ex.examined) notExamined.push({ source: r.source, method: r.method, why: ex.how });
      }
    }
    const candidate: LedgerEntry = {
      v: LEDGER_VERSION,
      seq: (entries.at(-1)?.seq ?? 0) + 1,
      kind: "coverage",
      value,
      ...(source.value ? { source: source.value } : {}),
      ...(evidence.value ? { evidence: evidence.value } : {}),
      refs: objects,
      answers,
      ...(input.sensitive === true ? { sensitive: true } : {}),
      ...(because.value ? { because: because.value } : {}),
      ...(method2.length ? { method: method2 } : {}),
      alternatives_open: alternatives.value,
      inventory_rev: inventory,
      time_range: timeRange.value,
      search_method: method.value,
      settings: settings.value,
      coverage_actual: actual.value,
      skipped: skipped.value,
      failures: failures.value,
      result_refs: results,
      // Its entries among its results, bound by the hash each has now.
      ...(results.some((x) => /^E-\d+$/.test(x)) ? { result_bound: results.filter((x) => /^E-\d+$/.test(x)).map((x) => { const e = bySeq.get(Number(x.slice(2))) as LedgerEntry; return { seq: e.seq, hash: e.hash ?? ledgerHash(e, "genesis") }; }) } : {}),
      detection_opportunity: { trace_expected: expected as NB.TraceExpected, why: dWhy.value },
      coverage: cov.coverage,
      coverage_detail: { units: cov.units, jobs: cov.jobs, why: cov.why },
      ...(notExamined.length ? { not_examined: notExamined } : {}),
      by: ctx.agentId,
      authors: [ctx.agentId],
      at: new Date().toISOString(),
    };
    const notes: string[] = [];
    notes.push(cov.coverage === "complete" ? "the hub finds the jobs behind it were given every object it names: coverage complete" : `the hub marks it coverage partial: ${cov.why.join("; ")}`);
    if (notExamined.length) notes.push(`planned routes not examined: ${notExamined.map((r) => `${r.source} (${r.method}): ${r.why}`).join("; ")}`);
    if (bars.some((b) => b.material && !b.routes.length)) notes.push("a question it is for has no route plan: a negative on a material question closes against one (lead_link routes)");
    notes.push("a material negative resting on it needs another seat's review: attest this record, or the answer, with review {detection, reproduced, other_route}");
    if (supersedes === undefined) {
      const same = entries.find((e) => !replaced.has(e.seq) && e.kind === "coverage" && ledgerContent(e) === ledgerContent(candidate));
      if (same) return mergeSameContent(ctx, held, same);
    }
    return appendLedgerEntry(ctx, held, entries, { ...candidate, ...(supersedes !== undefined ? { supersedes } : {}) }, notes);
  });
}

/** Record an answer (recordEntry with kind=answer): its checks need the ledger, so they run under the lock. */
async function recordAnswer(ctx: SwarmContext, input: LedgerInput): Promise<LedgerResult> {
  const raw = input as Record<string, unknown>;
  const wrong = NOT_ANSWER_FIELDS.find((f) => given(raw[f]));
  if (wrong) return { ok: false, reason: `${wrong} is not an answer's: an answer rests on ledger entries it cites as E-<seq>; record the fact itself as a finding, an event or an indicator first` };
  const sec = answerSection(String(input.section ?? ""));
  if (!sec.ok) return sec;
  const question = sec.section.startsWith("question:");
  const value = String(input.value ?? "").trim();
  if (!value) return { ok: false, reason: question ? "value is required: the answer itself, as the reader is to be told it" : sec.section === "summary" ? "value is required: the summary a decision maker reads first" : "value is required: what happened, in a paragraph; the whole narrative goes in reasoning" };
  if (value.length > LEDGER_VALUE_MAX_CHARS) return { ok: false, reason: `value is over ${LEDGER_VALUE_MAX_CHARS} characters: put the rest in reasoning` };
  const reasoning = boundedText("reasoning", input.reasoning, LEDGER_REASONING_MAX_CHARS);
  if (!reasoning.ok) return reasoning;
  if (!reasoning.value) return { ok: false, reason: "reasoning is required: how the cited entries lead to the answer, citing E-<seq> for every claim" };
  const confidence = String(input.confidence ?? "").trim().toLowerCase();
  if (confidence && !(LEDGER_CONFIDENCE as readonly string[]).includes(confidence)) return { ok: false, reason: `confidence must be one of ${LEDGER_CONFIDENCE.join(", ")}` };
  const why = boundedText("confidence_why", input.confidence_why, LEDGER_WHY_MAX_CHARS);
  if (!why.ok) return why;
  const openAlt = boundedText("alternatives_open", input.alternatives_open, LEDGER_WHY_MAX_CHARS);
  if (!openAlt.ok) return openAlt;
  const change = boundedText("would_change", input.would_change, LEDGER_WHY_MAX_CHARS);
  if (!change.ok) return change;
  if (question) {
    if (!confidence) return { ok: false, reason: "an answer to a question says how sure: confidence high, medium or low, with confidence_why" };
    if (!why.value) return { ok: false, reason: "confidence_why is required: the quality of the evidence the answer rests on, not a count of it" };
    if (!openAlt.value) return { ok: false, reason: "alternatives_open is required: what else could still explain it, or that nothing remains open and why" };
    if (!change.value) return { ok: false, reason: "would_change is required: what evidence would change this answer" };
  } else if (why.value && !confidence) return { ok: false, reason: "confidence_why says why that confidence: give confidence too" };
  if (input.inconclusive !== undefined && input.inconclusive !== null && typeof input.inconclusive !== "boolean") return { ok: false, reason: "inconclusive is true or false" };
  if (input.sensitive !== undefined && input.sensitive !== null && typeof input.sensitive !== "boolean") return { ok: false, reason: "sensitive is true or false" };
  const contrary = seqList("contrary", input.contrary);
  if (!contrary.ok) return contrary;
  const limits = seqList("limitations", input.limitations);
  if (!limits.ok) return limits;
  let resultText = String(input.result ?? "").trim().toLowerCase().replace(/-/g, "_");
  if (resultText && !(LEDGER_ANSWER_RESULTS as readonly string[]).includes(resultText)) return { ok: false, reason: `result is one of ${LEDGER_ANSWER_RESULTS.join(", ")} (got ${JSON.stringify(input.result)})` };
  // The old way of saying it: inconclusive is not_determinable, and is recorded as both.
  if (input.inconclusive === true) {
    if (resultText && resultText !== "not_determinable") return { ok: false, reason: `inconclusive is the old word for result not_determinable: it cannot come with result ${resultText}` };
    if (question) resultText = "not_determinable";
  }
  if (question && !resultText) {
    return {
      ok: false,
      reason:
        "an answer to a question states its result: established (answered on findings), partial (part of it), bounded_negative (no evidence of it found in a named scope: rests on a coverage record), not_determinable (the evidence cannot settle it: rests on a coverage record too), out_of_scope (the case's evidence cannot bear on it) or premise_not_supported (what it takes for granted does not hold)",
    };
  }
  if (input.asserts_absence !== undefined && input.asserts_absence !== null && typeof input.asserts_absence !== "boolean") return { ok: false, reason: "asserts_absence is true or false" };
  if (input.asserts_absence === true && resultText !== "bounded_negative") return { ok: false, reason: "asserts_absence says the event did not happen: it comes with result bounded_negative, on an existence question whose coverage record is complete and says the event would have left a trace" };
  const noneWhy = boundedText("contrary_none_why", input.contrary_none_why, LEDGER_WHY_MAX_CHARS);
  if (!noneWhy.ok) return noneWhy;
  if (!question && (resultText || noneWhy.value || input.asserts_absence === true)) return { ok: false, reason: "result, asserts_absence and contrary_none_why are a question's answer's" };
  let questionRev: number | undefined;
  if (input.question_rev !== undefined && input.question_rev !== null && String(input.question_rev).trim() !== "") {
    const n = Number(input.question_rev);
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `question_rev is the revision of the question this answers, a whole number (got ${JSON.stringify(input.question_rev)})` };
    if (!question) return { ok: false, reason: "question_rev is a question's answer's" };
    questionRev = n;
  }
  if (noneWhy.value && contrary.seqs.length) return { ok: false, reason: "contrary_none_why says no entry says otherwise: give contrary or contrary_none_why, not both" };
  // A person's question is a hypothesis to test: its answer names what says
  // otherwise, or says why nothing does (extensions/questions.ts).
  if (question && !contrary.seqs.length && !noneWhy.value) {
    const asker = await personsQuestion(ctx.sandboxRoot, sec.id).catch(() => null);
    if (asker) return { ok: false, reason: `${sec.section} is ${asker}: a person's question is a proposition to test, never a conclusion to confirm. Name the entries that say otherwise (contrary), or say why none does (contrary_none_why); result premise_not_supported is an answer` };
  }
  const quals: Array<{ seq: number; why: string }> = [];
  for (const q of Array.isArray(input.qualifies) ? input.qualifies : []) {
    const n = Number(String(q?.ref ?? "").trim().replace(/^(?:#|E-)/i, ""));
    const text = boundedText("a qualifies why", q?.why, LEDGER_WHY_MAX_CHARS);
    if (!text.ok) return text;
    if (!Number.isInteger(n) || n < 1 || !text.value) return { ok: false, reason: "an answer's qualifies is [{ref: \"E-<seq>\", why}]: a cited entry that is disputed or rests on a failed job, and why it still supports the answer" };
    if (!quals.some((x) => x.seq === n)) quals.push({ seq: n, why: text.value });
  }
  let supersedes: number | undefined;
  if (input.supersedes !== undefined && input.supersedes !== null && String(input.supersedes).trim() !== "") {
    const n = Number(String(input.supersedes).trim().replace(/^#/, ""));
    if (!Number.isInteger(n) || n < 1) return { ok: false, reason: `supersedes names an entry by its seq, a whole number (got ${JSON.stringify(input.supersedes)})` };
    supersedes = n;
  }
  const because = boundedText("because", input.because, LEDGER_BECAUSE_MAX_CHARS);
  if (!because.ok) return because;
  if (because.value && supersedes === undefined) return { ok: false, reason: "because says why a correction corrects: give supersedes too" };
  const source = boundedText("source", input.source, LEDGER_SOURCE_MAX_CHARS);
  if (!source.ok) return source;
  const evidence = boundedText("evidence", input.evidence, LEDGER_EVIDENCE_MAX_CHARS);
  if (!evidence.ok) return evidence;
  const cited = answerCitations(`${value}\n${reasoning.value}`);
  const support = cited.filter((n) => !contrary.seqs.includes(n) && !limits.seqs.includes(n));
  // A summary or a narrative cites the questions it sums up symbolically
  // (Q-<n>): bound to each answer's conclusion, not to its seq (A4).
  const symbolic: Array<{ q: string; section: string }> = [];
  if (!question) {
    for (const name of symbolicQuestions(`${value}\n${reasoning.value}`)) {
      const id = name.startsWith("question:") ? sectionKey(name.slice("question:".length)) : sectionKey(await registerSection(ctx.sandboxRoot, name));
      if (!LEDGER_ANSWER_ID.test(id)) return { ok: false, reason: `${name} is not a question this run has (questions list names them)` };
      if (!symbolic.some((x) => x.section === `question:${id}`)) symbolic.push({ q: name, section: `question:${id}` });
    }
  }
  if (support.length + contrary.seqs.length + limits.seqs.length > LEDGER_MAX_CITATIONS) return { ok: false, reason: `the answer cites more than ${LEDGER_MAX_CITATIONS} entries: cite the ones it rests on` };
  // The negative bar (extensions/negative-bar.ts): what the question is, as the registers say.
  const bar = question ? await questionBar(ctx.sandboxRoot, sec.id) : null;
  const negative = NB.NEGATIVE_RESULTS.has(resultText);
  const absolute = question ? NB.absoluteAbsenceForms(`${value}\n${reasoning.value}`) : [];
  if (absolute.length && !input.asserts_absence) {
    return { ok: false, reason: `it is worded as the event's absence (${absolute.map((f) => `"${f}"`).join(", ")}): a negative says "No evidence of <what> was found in <scope>". "It did not happen" is for an existence question whose coverage record is complete and says the event would have left a trace there, recorded with asserts_absence: true` };
  }
  if (negative && bar?.material && !bar.routes.length) {
    return { ok: false, reason: `${sec.section} is a material question with no route plan: a ${NB.resultWords(resultText)} closes against the sources and methods planned before the search. Give the lead under it its routes (lead_link with routes [{source, method}]), then record this again` };
  }
  // Which revision of the question it answers, held still while the answer
  // is written: the register's lock (the questions' amendments take it too),
  // then the ledger's. A question amended since the agent read it refuses
  // the answer; one amended past revision 1 needs its revision said.
  return withNamedLock(ctx.sandboxRoot, REGISTER_LOCK, async () => {
    if (question) {
      const reg = await registerRevision(ctx.sandboxRoot, sec.id).catch(() => null);
      if (reg) {
        if (questionRev !== undefined && questionRev !== reg.rev) return { ok: false as const, reason: `${reg.id} (${sec.section}) is at revision ${reg.rev}, amended since the revision ${questionRev} this answers: read it again (questions show ${reg.id}) and answer revision ${reg.rev}, with question_rev: ${reg.rev}` };
        if (questionRev === undefined && reg.rev > 1) return { ok: false as const, reason: `${reg.id} (${sec.section}) was amended to revision ${reg.rev}: say which revision this answers (question_rev: ${reg.rev}, after reading it with questions show ${reg.id}); an answer to an earlier revision is stale` };
      }
    }
    return withTableLock(ctx.sandboxRoot, async (held) => {
      const entries = await readLedger(ctx.sandboxRoot);
      const disputes = await readDisputes(ctx.sandboxRoot);
      const bySeq = new Map(entries.map((e) => [e.seq, e]));
      const replaced = supersededBy(entries);
      const hashOf = (e: LedgerEntry) => e.hash ?? ledgerHash(e, "genesis");
      const standing = entries.find((e) => e.kind === "answer" && e.section === sec.section && !replaced.has(e.seq));
      if (supersedes !== undefined) {
        const target = bySeq.get(supersedes);
        if (!target) return { ok: false, reason: `supersedes #${supersedes}: there is no entry #${supersedes} in the ledger (list them with ledger)` };
        if (target.kind !== "answer") return { ok: false, reason: `#${supersedes} is a ${target.kind}: an answer corrects an answer; correct the ${target.kind} with a ${target.kind}` };
        if (target.section !== sec.section) return { ok: false, reason: `#${supersedes} answers ${target.section}: an answer corrects the answer to its own section` };
        const already = replaced.get(supersedes);
        if (already !== undefined) return { ok: false, reason: `#${supersedes} is already superseded by #${already}: correct #${already} instead, so the corrections stay one line` };
      }
      // A summary or a narrative that cites a question's answer by its seq
      // (E-n) is bound to that question instead (question:N): the pilot's
      // summary and narrative cited three answers by seq and fell with every
      // revision of each. Its binding is then to the answer's conclusion (the
      // fingerprint below), whichever answer stands for the question now,
      // and the reply says so.
      const bound: Array<{ seq: number; section: string; standing: number | null }> = [];
      if (!question) {
        for (let i = support.length - 1; i >= 0; i--) {
          const e = bySeq.get(support[i]!);
          if (e?.kind !== "answer" || !e.section?.startsWith("question:")) continue;
          const standingNow = entries.find((x) => x.kind === "answer" && x.section === e.section && !replaced.has(x.seq));
          bound.unshift({ seq: e.seq, section: e.section, standing: standingNow?.seq ?? null });
          if (!symbolic.some((x) => x.section === e.section)) symbolic.push({ q: e.section, section: e.section });
          support.splice(i, 1);
        }
      }
      // A question's answer cited symbolically is not cited by seq as well:
      // its correction would take the summary down with it.
      for (let i = support.length - 1; i >= 0; i--) {
        const e = bySeq.get(support[i]!);
        if (e?.kind === "answer" && symbolic.some((x) => x.section === e.section)) support.splice(i, 1);
      }
      const questionRefs: NonNullable<LedgerEntry["question_refs"]> = [];
      if (symbolic.length) {
        const fallen = answerProblems(entries, disputes);
        for (const x of symbolic) {
          const a = entries.find((e) => e.kind === "answer" && e.section === x.section && !replaced.has(e.seq));
          if (!a) return { ok: false, reason: `${x.q} (${x.section}) has no standing answer yet: a ${sec.section} cites an answer that stands` };
          if (fallen.has(a.seq)) return { ok: false, reason: `${x.q}'s answer E-${a.seq} no longer stands on its own support (${(fallen.get(a.seq) as string[]).join("; ")}): it is to be recorded again first` };
          questionRefs.push({ q: x.q, section: x.section, answer: a.seq, fp: answerFingerprint(a) });
        }
      }
      for (const n of [...support, ...contrary.seqs, ...limits.seqs]) {
        if (!bySeq.has(n)) return { ok: false, reason: `E-${n}: there is no entry #${n} in the ledger (list them with ledger)` };
        if (n === supersedes) return { ok: false, reason: `E-${n} is the answer this one replaces: an answer does not rest on the answer it corrects` };
      }
      for (const n of limits.seqs) {
        const l = bySeq.get(n) as LedgerEntry;
        if (l.kind !== "limitation") return { ok: false, reason: `limitations names #${n}, a ${l.kind}: it takes limitation entries` };
        if (replaced.has(n)) return { ok: false, reason: `limitations names #${n}, superseded by #${standingSeq(n, replaced)}: name the limitation that stands` };
      }
      // Every claimed support is checked, not one matching citation.
      const disputedBy = new Map<string, DisputeInForce[]>();
      for (const d of disputesInForce(entries, disputes)) disputedBy.set(d.target, [...(disputedBy.get(d.target) ?? []), d]);
      const problems = answerProblems(entries, disputes);
      const needs = new Set<number>();
      for (const n of support) {
        const e = bySeq.get(n) as LedgerEntry;
        if (replaced.has(n)) {
          const now = standingSeq(n, replaced);
          if (!cited.includes(now)) return { ok: false, reason: `E-${n} is superseded by #${now}: cite E-${now}, the correction, with it or instead (a superseded entry explains history; it supports nothing)` };
          continue;
        }
        if (e.kind === "answer" && problems.has(n)) return { ok: false, reason: `E-${n} is an answer that no longer stands on its own support (${(problems.get(n) as string[]).join("; ")}): it is to be recorded again first` };
        const against = disputedBy.get(hashOf(e));
        const failed = await unqualifiedFailedRefs(ctx.sandboxRoot, e);
        if (against?.length || failed.length) {
          if (!quals.some((q) => q.seq === n)) {
            return {
              ok: false,
              reason: against?.length
                ? `E-${n} is disputed by ${against.map((d) => `${d.by}: ${d.why}${d.inherited_from !== undefined ? ` (raised on E-${d.inherited_from}, which it corrects: the dispute is open until ${d.by} withdraws it)` : ""}`).join("; ")}; cite its correction, drop it, or say in qualifies [{ref: "E-${n}", why}] why it still supports this answer`
                : `E-${n} rests on the kept output of a job that did not succeed (${failed.join(", ")}) and does not say why it still holds: say so in qualifies [{ref: "E-${n}", why}], or cite an entry resting on a job that worked`,
            };
          }
          needs.add(n);
        }
      }
      const extra = quals.find((q) => !needs.has(q.seq));
      if (extra) return { ok: false, reason: `qualifies names E-${extra.seq}, which ${support.includes(extra.seq) ? "is neither disputed nor resting on a failed job" : "the answer does not cite as support"}: it qualifies only a cited entry that needs it` };
      // What the answer stands on: an entry that names its question, or for a
      // summary or a narrative any entry that stands.
      const standingCites = [...support, ...limits.seqs].filter((n) => !replaced.has(n)).map((n) => bySeq.get(n) as LedgerEntry);
      if (question) {
        const id = sectionAnswersId(sec.section);
        const naming = (kinds: string[]) => standingCites.filter((e) => kinds.includes(e.kind) && (e.answers ?? []).some((a) => sectionKey(a) === id));
        if (!naming(["finding", "absence", "limitation", "coverage"]).length) {
          return { ok: false, reason: `an answer to ${sec.section} rests on at least one standing finding, search, limitation or coverage record recorded with answers=["${id}"] and cited as E-<seq>${standingCites.length ? ` (none of ${standingCites.map((e) => `E-${e.seq}`).join(", ")} names it)` : " (the answer cites no standing entry)"}` };
        }
        // The result says what the answer rests on: findings for what is established, a coverage record for a material negative.
        if ((resultText === "established" || resultText === "partial") && !naming(["finding"]).length) {
          return { ok: false, reason: `a result ${resultText} rests on a standing finding recorded with answers=["${id}"] and cited as E-<seq>; if nothing was found, the result is bounded_negative or not_determinable, resting on a coverage record` };
        }
        // A premise is shown not to hold by what was found, never by a search that found nothing.
        if (resultText === "premise_not_supported" && !naming(["finding"]).length) {
          return { ok: false, reason: `premise_not_supported rests on a standing finding recorded with answers=["${id}"] that shows the premise does not hold, cited as E-<seq>; a search that found nothing is a bounded_negative (or not_determinable), resting on a coverage record and reviewed by another seat` };
        }
        const coverage = naming(["coverage"]);
        if (negative && bar?.material && !coverage.length) {
          return {
            ok: false,
            reason: `a ${NB.resultWords(resultText)} on a material question rests on a coverage record: record kind=coverage with answers=["${id}"] (the proposition searched, the objects in refs, time_range, search_method, settings, coverage_actual, skipped, failures, result_refs, alternatives and detection_opportunity), and cite it as E-<seq>`,
          };
        }
        if (input.asserts_absence === true) {
          const complete = coverage.filter((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes" && !coverageProblems(c, entries, disputes).length);
          if (!bar?.existence) return { ok: false, reason: `asserts_absence says the event did not happen: only an answer to a question that asks whether something exists may say that (the goal's --existence, or the register's expects existence); ${sec.section} does not. Say "No evidence of … was found in …"` };
          if (!complete.length) return { ok: false, reason: `asserts_absence says the event did not happen: it rests on a coverage record the hub found complete and that says the event would have left a trace (detection_opportunity.trace_expected yes); ${coverage.length ? coverage.map((c) => `E-${c.seq} is coverage ${c.coverage ?? "unknown"}, trace expected ${c.detection_opportunity?.trace_expected ?? "?"}`).join("; ") : "it cites no coverage record"}. Say "No evidence of … was found in …" instead` };
        }
      } else if (!standingCites.length && !questionRefs.length) {
        return { ok: false, reason: `a ${sec.section} cites at least one standing entry as E-<seq>, or the questions it sums up as Q-<n>` };
      }
      const edge = (n: number): LedgerEdge => ({ seq: n, hash: hashOf(bySeq.get(n) as LedgerEntry) });
      const citedEntries = [...support, ...contrary.seqs, ...limits.seqs, ...questionRefs.map((r) => r.answer)].map((n) => bySeq.get(n) as LedgerEntry);
      const tokens = unsupportedTokens(`${value}\n${reasoning.value}`, citedEntries, bySeq);
      const candidate: LedgerEntry = {
        v: LEDGER_VERSION,
        seq: (entries.at(-1)?.seq ?? 0) + 1,
        kind: "answer",
        value,
        ...(source.value ? { source: source.value } : {}),
        ...(evidence.value ? { evidence: evidence.value } : {}),
        ...(confidence ? { confidence: confidence as LedgerEntry["confidence"] } : {}),
        ...(input.sensitive === true ? { sensitive: true } : {}),
        ...(because.value ? { because: because.value } : {}),
        ...(why.value ? { confidence_why: why.value } : {}),
        ...(quals.length ? { qualifies: quals.map((q) => ({ ref: `E-${q.seq}`, why: q.why })) } : {}),
        section: sec.section,
        reasoning: reasoning.value,
        ...(support.length ? { support: support.map(edge) } : {}),
        ...(contrary.seqs.length ? { contrary: contrary.seqs.map(edge) } : {}),
        ...(limits.seqs.length ? { limitations: limits.seqs.map(edge) } : {}),
        ...(openAlt.value ? { alternatives_open: openAlt.value } : {}),
        ...(change.value ? { would_change: change.value } : {}),
        ...(input.inconclusive === true ? { inconclusive: true } : {}),
        ...(resultText ? { result: resultText as LedgerEntry["result"] } : {}),
        ...(noneWhy.value ? { contrary_none_why: noneWhy.value } : {}),
        ...(questionRev !== undefined ? { question_rev: questionRev } : {}),
        ...(questionRefs.length ? { question_refs: questionRefs } : {}),
        ...(input.asserts_absence === true ? { asserts_absence: true } : {}),
        ...(tokens.length ? { unsupported_tokens: tokens } : {}),
        by: ctx.agentId,
        authors: [ctx.agentId],
        at: new Date().toISOString(),
      };
      const content = ledgerContent(candidate);
      if (supersedes !== undefined && ledgerContent(bySeq.get(supersedes) as LedgerEntry) === content) {
        return { ok: false, reason: `the correction repeats #${supersedes} word for word: a correction says what is right now` };
      }
      if (supersedes === undefined && standing && ledgerContent(standing) === content) return mergeSameContent(ctx, held, standing);
      if (standing && supersedes !== standing.seq) {
        return { ok: false, reason: `${sec.section} is answered by #${standing.seq} already: one answer stands for a section; to revise it, record this with supersedes=${standing.seq}` };
      }
      const notes: string[] = [];
      if (bound.length) notes.push(`${bound.map((b) => `E-${b.seq} (the answer to ${b.section}${b.standing !== null && b.standing !== b.seq ? `, now E-${b.standing}` : ""})`).join(", ")} ${bound.length === 1 ? "is" : "are"} cited as ${[...new Set(bound.map((b) => b.section))].join(", ")}: a ${sec.section} is bound to the questions it sums up, to each answer's conclusion (its result, the revision it answers, its support and contrary evidence), not to its seq, so a reworded correction of an answer keeps it standing. Cite Q-<n> or question:<n> for an answer in a ${sec.section}`);
      if (tokens.length) notes.push(`in none of the cited entries: ${tokens.join(", ")}; cite the entry that holds each, or record how it was derived as its own entry and cite that (marked on the answer; the release counts them)`);
      if (question && resultText !== "not_determinable" && standingCites.every((e) => e.kind === "limitation")) notes.push("it rests on limitations only: if the ledger cannot answer it, say so with result not_determinable, resting on a coverage record");
      if (question && negative && bar?.material) {
        const cov = standingCites.filter((e) => e.kind === "coverage");
        if (cov.some((c) => c.coverage === "partial")) notes.push(`its coverage record${cov.length > 1 ? "s are" : " is"} partial (${cov.filter((c) => c.coverage === "partial").map((c) => `E-${c.seq}`).join(", ")}): the report says what was not covered`);
        notes.push(`a material negative is reviewed by another seat before the run may end: an attest on this answer or on ${cov.map((c) => `E-${c.seq}`).join(", ")} with review {detection, reproduced, other_route}; until then it shows as negative (unreviewed)`);
      }
      return appendLedgerEntry(ctx, held, entries, { ...candidate, ...(supersedes !== undefined ? { supersedes } : {}) }, notes);
    });
  });
}


// --- the gate at done -----------------------------------------------------------------------

/**
 * A mechanical defect the finish line names before the run may end, with
 * what fixes it. `named_by` lists the standing limitations that name it: the
 * answers check passes once each defect is fixed or named, and a named
 * defect stays one. The finish line holds done on it under every stop
 * policy (finish-gate.ts holding): a question ends on a disposition under
 * the bar, never on a limitation that names it; the release counts it.
 */
export type LedgerDefect = {
  code: "no_answer" | "answer_support" | "answer_disputed" | "no_critic_act" | "open_contradiction" | "coverage_missing" | "negative_unreviewed" | "wording" | "coverage_stale" | "material_use" | "partial_output";
  section?: string;
  seqs: number[];
  what: string;
  fix: string;
  named_by: number[];
};

export type LedgerGate = {
  /** Each wanted section's standing answer, or null. */
  answers: Record<string, LedgerEntry | null>;
  defects: LedgerDefect[];
  /** The defects no limitation names: what keeps the run from ending. */
  open: LedgerDefect[];
  /** Every standing answer's unsupported tokens, by seq (the release counts them). */
  unsupported: Record<number, string[]>;
};

/** The job statuses whose kept output is partial by an act, not by its own failure: cancelled by an agent or the harness, or stopped (docs/adr/0016). */
export const PARTIAL_STATUSES: ReadonlySet<string> = new Set(["cancelled", "stopped"]);

/**
 * The standing entries that cite the kept output of a cancelled or stopped
 * job without saying how they treat it (qualifies {ref, why}): by seq, each
 * such ref with the producing job and its status. A limitation says what
 * could not be done and is its own disposition; so is a search recorded
 * partial or failed, and a coverage record, whose coverage_actual, skipped
 * and failures say it. Pure: `producerOf(ref)` resolves a citation to the
 * job whose output it names and that job's status, following a digest or a
 * copy to the job that wrote those bytes (scripts/output-hygiene.ts builds
 * it from the store); a citation that names no job's output is null.
 */
export function partialOutputCites(entries: LedgerEntry[], producerOf: (ref: string) => { job: string; status: string } | null | undefined): Map<number, Array<{ ref: string; job: string; status: string }>> {
  const replaced = supersededBy(entries);
  const out = new Map<number, Array<{ ref: string; job: string; status: string }>>();
  for (const e of entries) {
    if (replaced.has(e.seq) || e.kind === "limitation" || e.kind === "coverage" || e.kind === "answer") continue;
    if (e.kind === "absence" && e.completion && e.completion !== "complete") continue;
    for (const ref of e.refs ?? []) {
      const p = producerOf(ref);
      if (!p || !PARTIAL_STATUSES.has(p.status)) continue;
      if ((e.qualifies ?? []).some((q) => q.ref === ref)) continue;
      out.set(e.seq, [...(out.get(e.seq) ?? []), { ref, job: p.job, status: p.status }]);
    }
  }
  return out;
}

/** Contradictions that stand and that nothing has weighed: no answer holds both with one as contrary evidence, no limitation names both. */
export function openContradictions(entries: LedgerEntry[]): Array<{ from: number; to: number }> {
  const replaced = supersededBy(entries);
  const answers = entries.filter((e) => e.kind === "answer" && !replaced.has(e.seq));
  const limits = entries.filter((e) => e.kind === "limitation" && !replaced.has(e.seq));
  return standingContradictions(entries).filter(({ from, to }) => {
    const weighed = answers.some((a) => {
      const contra = new Set((a.contrary ?? []).map((x) => x.seq));
      const all = new Set([...contra, ...(a.support ?? []).map((x) => x.seq)]);
      return all.has(from) && all.has(to) && (contra.has(from) || contra.has(to));
    });
    const named = limits.some((l) => {
      const c = limitationCites(l);
      return c.has(from) && c.has(to);
    });
    return !weighed && !named;
  });
}

/**
 * The ledger gate: each wanted section's answer (question:<id>, summary,
 * narrative), what keeps it from standing, whether a critic acted on it, and
 * the contradictions left open. Pure over what was read: the caller reads
 * the files (and which entries rest on a failed job) and verifies the chains.
 */
export function ledgerGate(o: { entries: LedgerEntry[]; attestations: LedgerAttestation[]; disputes: LedgerDispute[]; sections: string[]; failed?: Map<number, string[]>; bar?: (sectionId: string) => { material: boolean; existence: boolean }; partial?: Map<number, Array<{ ref: string; job: string; status: string }>> }): LedgerGate {
  const { entries } = o;
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = supersededBy(entries);
  const limits = entries.filter((e) => e.kind === "limitation" && !replaced.has(e.seq));
  const problems = answerProblems(entries, o.disputes, o.failed);
  const standingD = disputesInForce(entries, o.disputes);
  const defects: LedgerDefect[] = [];
  const answers: Record<string, LedgerEntry | null> = {};
  const unsupported: Record<number, string[]> = {};
  const namedFor = (seq: number) => limits.filter((l) => limitationCites(l).has(seq)).map((l) => l.seq);
  for (const raw of o.sections) {
    const sec = answerSection(raw);
    if (!sec.ok) continue;
    const a = entries.find((e) => e.kind === "answer" && e.section === sec.section && !replaced.has(e.seq)) ?? null;
    answers[sec.section] = a;
    const id = sectionAnswersId(sec.section);
    if (!a) {
      defects.push({
        code: "no_answer",
        section: sec.section,
        seqs: [],
        what: `${sec.section} has no answer`,
        fix: `record kind=answer section=${sec.section} citing E-<seq> of the entries it rests on${sec.section.startsWith("question:") ? ` (at least one recorded with answers=["${id}"])` : ""}; if the ledger cannot answer it, record kind=limitation with answers=["${id}"] saying why`,
        named_by: limits.filter((l) => (l.answers ?? []).some((x) => sectionKey(x) === id)).map((l) => l.seq),
      });
      continue;
    }
    if (a.unsupported_tokens?.length) unsupported[a.seq] = a.unsupported_tokens;
    const p = problems.get(a.seq);
    if (p?.length) {
      defects.push({ code: "answer_support", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) no longer stands on its support: ${p.join("; ")}`, fix: `record the answer again with supersedes=${a.seq}, citing what stands now (a correction, or qualifies [{ref: "E-<seq>", why}] for a disputed or failed-job entry), or record a limitation citing E-${a.seq} that says why it stands as it is`, named_by: namedFor(a.seq) });
    }
    const target = a.hash ?? ledgerHash(a, "genesis");
    const against = standingD.filter((d) => d.target === target);
    if (against.length) {
      const inherited = against.filter((d) => d.inherited_from !== undefined);
      defects.push({
        code: "answer_disputed",
        section: sec.section,
        seqs: [a.seq],
        what: `answer #${a.seq} (${sec.section}) is disputed by ${against.map((d) => `${d.by}: ${d.why}${d.inherited_from !== undefined ? ` (raised on #${d.inherited_from}, which it corrects: a correction does not answer a dispute)` : ""}`).join("; ")}`,
        fix: inherited.length
          ? `the disputer reads the correction and withdraws the dispute when it answers it (dispute withdraw=true on #${a.seq}, with why), or disputes it again; or record a limitation citing E-${a.seq}`
          : `answer the dispute: correct the answer (record it again with supersedes=${a.seq}) and have the disputer withdraw it (dispute withdraw=true, with why) once the correction answers it, or record a limitation citing E-${a.seq}`,
        named_by: namedFor(a.seq),
      });
    }
    // The negative bar, on an answer that states its result (one recorded
    // before results reads as it always did): a material negative rests on
    // a standing coverage record whose results still stand and is reviewed
    // by another seat, and an answer is worded as what was not found where,
    // whatever its result, unless the bar for "it did not happen" is met.
    // A premise rejected on a search alone is a negative too. None of these
    // is excused by a limitation.
    const result = NB.answerResult(a);
    const bar = sec.section.startsWith("question:") ? (o.bar?.(id) ?? { material: true, existence: false }) : null;
    const cited = citedForQuestion(a, bySeq, replaced, id);
    const negativeLike = negativeByResult(result, cited);
    const review = negativeLike ? negativeReview(a, entries, o.attestations, o.disputes) : null;
    const cov = cited.filter((c) => c.kind === "coverage" && !review?.stale.some((x) => x.seq === c.seq));
    if (bar && result && negativeLike) {
      for (const st of review?.stale ?? []) {
        defects.push({ code: "coverage_stale", section: sec.section, seqs: [a.seq, st.seq], what: `answer #${a.seq} (${sec.section}) rests on coverage record E-${st.seq}, which no longer says what its search found: ${st.problems.join("; ")}`, fix: `record the coverage again with supersedes=${st.seq} over the results that stand now, and the answer again with supersedes=${a.seq} citing it; another seat reviews it again`, named_by: [] });
      }
      const what = result === "premise_not_supported" ? "a premise rejected on a search alone (no finding shows it false)" : NB.resultWords(result);
      if (bar.material && !cov.length) {
        defects.push({ code: "coverage_missing", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) is ${what} on a material question and rests on no standing coverage record`, fix: `record kind=coverage with answers=["${id}"] (what was searched, over which objects, how, what was covered, skipped and failed, the results, the alternatives, the detection opportunity) and record the answer again with supersedes=${a.seq} citing it`, named_by: [] });
      }
      if (bar.material && !review?.reviewed) {
        defects.push({ code: "negative_unreviewed", section: sec.section, seqs: [a.seq, ...cov.map((c) => c.seq)], what: `answer #${a.seq} (${sec.section}) is a negative (unreviewed): ${what} on a material question, and no other seat has reviewed it`, fix: `a seat that recorded neither it nor its coverage record attests #${a.seq}${cov.length ? ` or ${cov.map((c) => `#${c.seq}`).join(", ")}` : ""} with review {detection, reproduced, other_route}: whether it challenged the detection assumptions, reproduced a decisive check, tried a materially different route, each with what it did or why not`, named_by: [] });
      }
    }
    if (bar && result) {
      const forms = NB.absoluteAbsenceForms(`${a.value}\n${a.reasoning ?? ""}`);
      const earned = a.asserts_absence === true && result === "bounded_negative" && bar.existence && cov.some((c) => c.coverage === "complete" && c.detection_opportunity?.trace_expected === "yes");
      if ((forms.length || a.asserts_absence) && !earned) {
        defects.push({ code: "wording", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) says the event did not happen${forms.length ? ` (${forms.map((f) => `"${f}"`).join(", ")})` : ""}, and the bar for saying so is not met: ${result !== "bounded_negative" ? `its result is ${NB.resultWords(result)}, and only a bounded negative may say it` : !bar.existence ? "the question does not ask whether something exists" : !cov.some((c) => c.coverage === "complete") ? "no coverage record it rests on is complete" : "no coverage record it rests on says the event would have left a trace"}`, fix: `record the answer again with supersedes=${a.seq}, worded "No evidence of … was found in …" (the coverage record's scope)`, named_by: [] });
      }
    }
    const acted = o.attestations.some((x) => attestationAct(x) === "attest" && x.target === target && !a.authors.includes(x.by) && x.by !== a.by) || against.some((d) => !a.authors.includes(d.by)) || Boolean(review?.reviewed);
    if (!acted) {
      defects.push({ code: "no_critic_act", section: sec.section, seqs: [a.seq], what: `answer #${a.seq} (${sec.section}) has no critic act`, fix: `an agent other than its author re-derives what it rests on from the sealed refs and records attest (how) or dispute (why) on #${a.seq}`, named_by: namedFor(a.seq) });
    }
  }
  for (const c of openContradictions(entries)) {
    defects.push({ code: "open_contradiction", seqs: [c.from, c.to], what: `#${c.from} contradicts #${c.to} and both stand`, fix: `supersede the one that is wrong, weigh both in an answer (one as support, the other in contrary), or record a limitation citing E-${c.from} and E-${c.to}`, named_by: [] });
  }
  // The kept output of a job that was cancelled or stopped, cited later: the
  // entry says how it treats what the job wrote before it was stopped, or it
  // stands as a defect (docs/adr/0016). Fixed by the entry, never named.
  for (const [seq, refs] of o.partial ?? []) {
    const e = bySeq.get(seq);
    if (!e || replaced.has(seq)) continue;
    defects.push({
      code: "partial_output",
      seqs: [seq],
      what: `#${seq} cites the kept output of ${refs.map((r) => `job ${r.job} (${r.status})`).filter((x, i, a) => a.indexOf(x) === i).join(", ")} (${refs.map((r) => r.ref).join(", ")}) and does not say how it treats a partial output`,
      fix: `record it again with supersedes=${seq} and qualifies [{ref, why}] for each such ref (what the job wrote before it was stopped, and why that part still holds), or cite the output of a job that ran to its end`,
      named_by: [],
    });
  }
  return { answers, defects, open: defects.filter((d) => !d.named_by.length), unsupported };
}

/**
 * Whether a turn that ended in an error was the provider's doing, or the
 * harness's own. When the harness stops an agent (the sentinel landed, a cap
 * bound, a hard kill) it aborts the turn in flight, and Pi records that as an
 * error whose message is the abort's: "This operation was aborted". That is
 * not the provider answering, and the board must not say it was. A stop the
 * harness itself began names its reason; an abort after the sentinel is the
 * same thing seen from a process that did not set the flag.
 *
 * A connection that died is the same once the run is over: the last agent
 * out turns the proxy off, and every turn still streaming through it ends
 * with "Connection error." or "terminated". On run s57e9 that put four
 * PROVIDER ERROR vetoes on the board of a finished run, six seconds after the
 * sentinel. A provider's own answer — a status, a balance, a rate limit — is
 * the provider's whether or not the run is over, and stays reported.
 */
export function classifyTurnError(
  reason: string,
  harnessStop: string | null,
  swarmDone: boolean,
): "provider" | "harness" {
  const aborted = /\baborted\b/i.test(reason);
  const tornDown = /connection error|\bterminated\b|ECONNRESET|ECONNREFUSED|EPIPE|socket hang up|fetch failed/i.test(reason);
  if ((harnessStop || swarmDone) && (aborted || tornDown)) return "harness";
  return "provider";
}

/** A page of a job's stdout as the job service hands it back (job_run, job_status). */
export type JobStdoutPage = { offset: number; bytes: number; total: number; text?: string; next: number | null; path: string };

/**
 * What a page of a job's stdout leaves unread, said plainly. On the Belka run
 * s94e373 a job returned the first 8,192 of 18,206 bytes of a notes
 * database; the note the three blocked agents needed began at byte 10,709,
 * and nothing in the result said that most of the output was still unread.
 * The key sat on the agent's screen, in the half it never read, for the
 * rest of the run. Null when the page reaches the end.
 */
export function jobPageNote(job: string, page: JobStdoutPage): string | null {
  const end = page.offset + page.bytes;
  const unread = Math.max(0, page.total - end);
  if (!unread) return null;
  const before = page.offset > 0 ? ` (bytes 0-${page.offset} came on earlier pages)` : "";
  return (
    `This is bytes ${page.offset}-${end} of ${page.total} of ${job}'s stdout${before}: ${unread} bytes are unread. ` +
    `Read the next page with job_status(job_id: "${job}", offset: ${end}), or read ${page.path} whole, before you draw a conclusion from this page. ` +
    `Until the rest is read, or an entry you record with interprets: [{job: "${job}", rest: "how you read the rest, or why not"}] says why not, ${job} stays on your list of jobs awaiting interpretation.`
  );
}

/**
 * What the board is told when a seat's turn ends in the provider's error.
 * It used to say the seat's work was "free", and on the Belka run s306463
 * a peer began taking over an agent that had only lost one turn: the agent
 * came back, the two collided, and the board spent four posts sorting it
 * out. A failed turn transfers nothing. The work stands as the seat's until
 * the seat itself, or the hub (a lead reclaimed from a stale holder), says
 * otherwise.
 */
export function providerErrorPost(agentId: string, model: string, reason: string): string {
  return (
    `PROVIDER ERROR: ${agentId}'s turn on ${model} ended with: ${reason}. ` +
    `Nothing this agent or a peer does will change that: it is the provider answering, not the harness. ` +
    `Only this turn failed. ${agentId}'s work, its leads and its claims stand as its own until ${agentId} or the hub says otherwise; ` +
    `do not take them over on the strength of this post. If ${agentId} stays silent, its leads show as stale in \`leads\` and can be reclaimed from there.`
  );
}

/**
 * The shared install area and the scratch dir are nobody's work product. pip
 * writes hundreds of files under work/.toolchain/, a tool keeps its cache
 * there, and two agents installing at once are not in conflict over the case:
 * on run sb36f that read as 442 claim violations over pytz's zoneinfo. What
 * was installed is still inventoried from toolchain.json.
 */
export function isSharedScratch(path: string): boolean {
  // One list for the two readers: the shell-write watch leaves these
  // directories out of its snapshot (`SHARED_WORK_DIRS`, above), and a
  // report that still names one of them is dropped here.
  return (SHARED_WORK_DIRS as readonly string[]).some((dir) => path === `work/${dir}` || path.startsWith(`work/${dir}/`));
}

/** Where await-done.sh may read a finish line that certifies a run: the operator's copy. */
export const FINISH_LINE_TRUSTED_SOURCES = new Set(["registry"]);

/**
 * The operator's finish line, run once, right now, by await-done.sh from the
 * registry: what an agent's `done` runs before the sentinel, and what the VM
 * hub runs again on the host before it lets a sentinel be written.
 */
export async function runFinishLine(sandbox: string): Promise<FinishLineRun | null> {
  const script = resolve(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "await-done.sh");
  const run = await new Promise<FinishLineRun | null>((done) => {
    execFile(
      "bash",
      [script, "--sandbox", sandbox, "--checks-json", "--check-timeout", "120"],
      { cwd: sandbox, timeout: 15 * 60_000, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, CHECKS_SOURCE: "done" } },
      (err, stdout) => {
        try {
          const parsed = JSON.parse(String(stdout || "").trim().split("\n").pop() || "") as FinishLineRun;
          if (typeof parsed.total === "number" && Array.isArray(parsed.checks)) return done(parsed);
        } catch {
          /* fall through */
        }
        done(err ? { total: 0, passed: 0, checks: [], error: String(err.message || err) } : null);
      },
    );
  });
  // The harness's own part (scripts/finish-gate.ts): the lead register's
  // open work, and whether the run would end completed or examination-
  // limited. Read after the goal's checks, from the same files; the caller
  // binds both to one revision (runFinishLineBound, the hub's markDone).
  if (!run) return run;
  try {
    const { finishGate } = (await import(resolve(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "finish-gate.ts"))) as typeof import("../scripts/finish-gate.ts");
    run.gate = await finishGate(sandbox, run);
  } catch (err) {
    run.gate = { defects: [], limited: [], questions: [], until_solved: false, error: `the harness's gate could not be run: ${(err as Error).message}` };
  }
  return run;
}

/** The record a finish line reads that is not the goal's own files: where each lives. */
export const REVISION_FILES = { ledger: LEDGER_ENTRIES, attestations: "ledger/attestations.jsonl", disputes: "ledger/disputes.jsonl", leads: "leads/leads.jsonl", questions: "questions/questions.jsonl" } as const;

/**
 * Whether a line of the lead or the question register is an offer's
 * bookkeeping (docs/adr/0015): an offer made, delivered, declined, accepted
 * or lapsed, or a wake from before offers. Those say who may take a piece of
 * work first, never what the finish rests on, and idle seats write them all
 * the time: were they in the revision, a waiting seat's delivered offer would
 * make the coordinator's finish line run again, and one check result per
 * revision would not hold. A closure offered to its closer to confirm is not
 * bookkeeping: until it is confirmed it holds the finish. The lines are the
 * registers' own compact JSON, where `"ev":"…"` can only be the event's key
 * (a quote inside a value is escaped).
 */
export function offerBookkeeping(line: string): boolean {
  if (line.includes('"ev":"wake"')) return true;
  if (!line.includes('"ev":"offer')) return false;
  return !(line.includes('"ev":"offer"') && line.includes('"reason":"confirm"'));
}

/** A register's part of the revision: its bytes, less its offers' bookkeeping for the lead and question registers. */
function revisionPart(name: string, bytes: Buffer): string {
  if (name !== "leads" && name !== "questions") return `${bytes.length}:${sha256Hex(bytes)}`;
  const kept = Buffer.from(
    bytes
      .toString("utf8")
      .split("\n")
      .filter((line) => !offerBookkeeping(line))
      .join("\n"),
    "utf8",
  );
  return `${kept.length}:${sha256Hex(kept)}`;
}

/** Tags of a post that can change a verdict: a result, a veto, a hold, a stop. */
const VERDICT_TAGS = new Set<string>(["result", "veto", "hold", "stop"]);
/** A post never changes once written, so its tag and sender are read once per process. */
const postTagCache = new Map<string, { tag: string; from: string }>();

/**
 * The state a finish line is judged against, as one revision: the board (per
 * thread, the newest agent post that can change a verdict: a result, a veto,
 * a hold or a stop; an intro or a claim cannot), the ledger (every byte: a
 * merge rewrites an entry's authors, and an author may not attest), the
 * review (the attestations and the disputes), the leads and the questions
 * (less their offers' bookkeeping: offerBookkeeping). A finish line run
 * against one revision holds only while the revision does: on the VM hub a
 * passing run was reused for 30 s whatever had changed in between, and a
 * dispute recorded in that window did not stop the sentinel.
 */
export async function stateRevision(sandboxRoot: string): Promise<{ revision: string; parts: Record<string, string> }> {
  const parts = await stateParts(sandboxRoot);
  // What the finish rests on beyond the registers (A4): the report the
  // coordinator's done names (by its digest), every job's state, the run's
  // policy (the case policy too), the operator's decisions (the requests'
  // chain, less its delivery bookkeeping) and what was added after the
  // kickoff (docs/adr/0014). A job committed, a report rewritten, a pause, a
  // host allowed, a request answered or evidence added between the finish
  // line and the sentinel moves the revision, and the done is run again.
  const { finishParts } = await import("./finish.ts");
  Object.assign(parts, await finishParts(sandboxRoot));
  return { revision: sha256Hex(JSON.stringify(parts)), parts };
}

async function stateParts(sandboxRoot: string): Promise<Record<string, string>> {
  const parts: Record<string, string> = {};
  const board: Record<string, number> = {};
  for (const thread of await listThreadNames(sandboxRoot)) {
    let newest = 0;
    for (const file of await listPostFiles(sandboxRoot, thread)) {
      let seen = postTagCache.get(file);
      if (!seen) {
        const post = await readPost(file).catch(() => null);
        if (!post) continue;
        seen = { tag: post.tag, from: post.from };
        postTagCache.set(file, seen);
      }
      if (seen.from === SYSTEM_AGENT || !VERDICT_TAGS.has(seen.tag)) continue;
      newest = Math.max(newest, Number.parseInt(basename(file).slice(0, 6), 10) || 0);
    }
    if (newest) board[thread] = newest;
  }
  parts.board = JSON.stringify(board);
  for (const [name, rel] of Object.entries(REVISION_FILES)) {
    const bytes = await readFile(join(sandboxRoot, rel)).catch(() => null);
    parts[name] = bytes ? revisionPart(name, bytes) : "none";
  }
  return parts;
}

/** How many times a finish line is run again when the state moved under it, before done is refused. */
export const FINISH_LINE_ATTEMPTS = 3;

/**
 * The finish line bound to a revision: the revision taken before the run, the
 * run, and the revision again after it. A run the state moved under is run
 * again, up to FINISH_LINE_ATTEMPTS times; `settled` false says it never held
 * still, and the caller refuses rather than write a sentinel on a verdict the
 * state no longer matches.
 */
export async function runFinishLineBound(
  sandboxRoot: string,
  runner: (sandbox: string) => Promise<FinishLineRun | null> = runFinishLine,
  attempts = FINISH_LINE_ATTEMPTS,
): Promise<{ run: FinishLineRun | null; revision: string; settled: boolean; runs: number }> {
  let last: { run: FinishLineRun | null; revision: string } = { run: null, revision: "" };
  for (let i = 1; i <= attempts; i++) {
    const before = (await stateRevision(sandboxRoot).catch(() => ({ revision: "" }))).revision;
    const run = await runner(sandboxRoot).catch(() => null);
    const after = (await stateRevision(sandboxRoot).catch(() => ({ revision: "" }))).revision;
    last = { run, revision: before };
    if (before === after) return { ...last, settled: true, runs: i };
  }
  return { ...last, settled: false, runs: attempts };
}

/** The refusal of a done whose finish line never held still. */
export const FINISH_LINE_UNSETTLED =
  `The board, the ledger, the review or the leads changed while the finish line ran, ${FINISH_LINE_ATTEMPTS} times in a row, ` +
  "so no verdict matches the state a sentinel would close. Read what landed (inbox, ledger, leads), then call done again.";

/**
 * What await-done.sh --checks-json prints: the finish line, run once, right
 * now. What a failing check said (`out`, and `fix` or `output` when a runner
 * gives them) the refusal carries to the agent verbatim.
 */
export type FinishLineRun = {
  total: number;
  passed: number;
  /**
   * A failing check's output, whole when it is at most 64 KiB (out), and its
   * size (out_bytes): the runner's own words for the check. `fix` or
   * `output`, when a runner gives them, are the check's words too.
   */
  checks: Array<{ cmd: string; ok: boolean; ms?: number; timed_out?: boolean; out?: string; out_bytes?: number; fix?: string; output?: string; answers?: { outcomes?: Record<string, string>; named?: string[]; existence?: string[]; mode?: string } }>;
  source?: string | null;
  error?: string;
  /** The harness's part, beside the goal's checks (scripts/finish-gate.ts). */
  gate?: FinishGateView;
};

/** What the harness's gate says (scripts/finish-gate.ts's FinishGate, as the verdict reads it). */
export type FinishGateView = {
  defects: Array<{ code: string; lead?: string; job?: string; question?: string; what: string; fix: string }>;
  limited: string[];
  /** Each question, how it stands, what blocks it, and its disposition under the bar when it has one (established, partial, bounded_negative, not_determinable, premise_not_supported, out_of_scope). */
  questions?: Array<{ id: string; outcome: string; blocks: string[]; disposition?: string }>;
  until_solved?: boolean;
  /** The lines of `limited` that are the operator's acceptances. */
  accepted?: string[];
  /** What holds a run under the operator's stop policy beside its questions: a defect a limitation only names. */
  holding?: string[];
  error?: string;
};

/**
 * How a run ended, as the sentinel and the record say it. `completed`: the
 * finish line was run and met. `examination_limited`: it was met, and the
 * run says what it could not establish (a limitation never reads as an
 * answer). `abandoned`: given up without its checks. `verification_unavailable`:
 * the harness could not run the finish line at all, so nothing was
 * established either way; it never reads as completed.
 */
export const FINISH_OUTCOMES = ["completed", "examination_limited", "abandoned", "verification_unavailable"] as const;
export type FinishOutcome = (typeof FINISH_OUTCOMES)[number];
/**
 * How a run stands or ended, beyond what a done can say: `paused` (a cap
 * paused it; the operator extends or stops it) and `stopped` (the operator
 * stopped it, or a cap did under cap-stop): never `completed`, whatever its
 * answers say.
 */
export const RUN_OUTCOMES = ["completed", "examination_limited", "paused", "stopped", "abandoned", "verification_unavailable"] as const;
export type RunOutcome = (typeof RUN_OUTCOMES)[number];
/** The operator's stop of a run with no sentinel (swarm.sh stop): the outcome stopped, by whom, when, why. */
export const STOPPED_REL = "done/STOPPED";

/**
 * How a run stands, from its own files: stopped (the operator's STOPPED, or
 * the harness's sentinel at a cap), the outcome a done wrote in the
 * sentinel, paused (a cap, the run not finished), or null while it runs.
 */
export async function runOutcome(sandboxRoot: string): Promise<{ outcome: RunOutcome | null; by: string | null; at: string | null; why: string | null }> {
  const front = (text: string) => Object.fromEntries([...text.matchAll(/^([a-z_]+):[ \t]*(.*)$/gm)].map((m) => [m[1], m[2].trim()])) as Record<string, string>;
  const stopped = await readFile(join(sandboxRoot, STOPPED_REL), "utf8").catch(() => null);
  if (stopped !== null) {
    try {
      const j = JSON.parse(stopped) as { by?: string; at?: string; why?: string };
      return { outcome: "stopped", by: j.by ?? null, at: j.at ?? null, why: j.why ?? null };
    } catch {
      return { outcome: "stopped", by: null, at: null, why: null };
    }
  }
  const sentinel = await readFile(sentinelPath(sandboxRoot), "utf8").catch(() => null);
  if (sentinel !== null) {
    const f = front(sentinel);
    const said = (RUN_OUTCOMES as readonly string[]).includes(f.outcome ?? "") ? (f.outcome as RunOutcome) : null;
    const byCap = f.by === "harness" && (f.reason === "cap" || f.reason === "wall_clock");
    return { outcome: byCap ? "stopped" : said, by: f.by ?? null, at: f.at ?? null, why: f.reason ?? null };
  }
  const budget = await readBudget(sandboxRoot).catch(() => null);
  if (budget?.paused) return { outcome: "paused", by: "harness", at: budget.paused.at, why: budget.paused.detail };
  return { outcome: null, by: null, at: null, why: null };
}

/**
 * The notice of a pause, claimed once: whichever process sees an
 * unnotified pause first (the watchdog, the hub) creates its mark under
 * traces/pause-notices/ and tells the operator; every other sees the mark.
 * Durable, so a pause written by a pane, or one whose creator died before
 * it said so, is still told. True when this call claimed it.
 */
export async function claimPauseNotice(sandboxRoot: string, pausedAt: string): Promise<boolean> {
  const dir = join(sandboxRoot, "traces", "pause-notices");
  await mkdir(dir, { recursive: true });
  const name = createHash("sha256").update(pausedAt).digest("hex").slice(0, 32);
  return writeFile(join(dir, name), `${pausedAt}\n`, { encoding: "utf8", flag: "wx" }).then(
    () => true,
    () => false,
  );
}

/** Record the operator's stop of a run that has no sentinel: done/STOPPED, once. */
export async function markStopped(sandboxRoot: string, by: string, why: string): Promise<{ written: boolean }> {
  // Under the lock an extension takes, so the two are ordered: one that
  // came first is in the caps the stop leaves, one that comes after is refused.
  return withTableLock(sandboxRoot, async () => {
    if (await swarmDoneExists(sandboxRoot)) return { written: false };
    const file = join(sandboxRoot, STOPPED_REL);
    if (await lstat(file).then(() => true).catch(() => false)) return { written: false };
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify({ outcome: "stopped", by, at: new Date().toISOString(), why })}\n`, { encoding: "utf8", flag: "wx" }).catch(() => undefined);
    return { written: true };
  });
}

/** The reason prefix of a done the harness could not check. */
export const VERIFICATION_UNAVAILABLE_PREFIX = "VERIFICATION UNAVAILABLE: ";

/**
 * What a question may end on under the bar, said to the agents of a run
 * under the operator's stop policy: every disposition, and the way to one
 * when the evidence cannot answer it (docs/adr/0013).
 */
export const DISPOSITION_WORDS =
  "every question in scope has a disposition under the bar: established; partial; a bounded negative or not determinable, each resting on a coverage record another seat has reviewed; a premise shown not to hold; out of scope; accepted by the operator; or withdrawn";
export const NEGATIVE_PATH_WORDS =
  "When the evidence cannot answer a question, that is an answer too: plan its routes (lead_open or lead_link with routes), record a coverage record (kind=coverage: what was searched, over which objects, how, what was covered, skipped and failed, the results, what is still open, and whether the event would have left a trace), have another seat review it (attest with review {detection, reproduced, other_route}), then answer not_determinable, or bounded_negative when nothing was found in that scope";

/** The refusal of an abandon in an until-solved run: only the operator ends it. */
export const UNTIL_SOLVED_NO_ABANDON =
  `This run was started until solved (--stop operator): no caps, no wall clock, and it ends when ${DISPOSITION_WORDS}, or when the operator stops it (swarm.sh stop). The agents cannot abandon it. ` +
  `${NEGATIVE_PATH_WORDS}. Post what blocks you, open a lead for another route, or close a lead needs_operator for what only the operator can give, and keep working.`;

export type FinishVerdict =
  | { proceed: true; outcome: FinishOutcome; note?: string; reasonPrefix?: string }
  | { proceed: false; reason: string; failing: string };

/**
 * Whether a `done` that would write the sentinel may go ahead. The checks are
 * the operator's, read from the registry by await-done.sh, so an agent cannot
 * rewrite them; but until now nothing ran them at the moment `done` was
 * called, and on run sb36f a nano agent ended a 25 GB case after four minutes
 * by calling done when its own slice was finished, with no report written. A
 * failing finish line is a refusal that names every check that fails and
 * what makes it pass (`failing` is the first, for the record's one field).
 * `abandon` is the way out the guidelines promise for a task that is
 * impossible or unsafe: the sentinel is written and says so. A run whose
 * checks cannot be run at all is not held hostage by the runner, but it is
 * not a clean done either: it proceeds as `verification_unavailable`, the
 * sentinel's reason says so, and the trace records why.
 */
export function finishLineVerdict(run: FinishLineRun | null, abandon: boolean, opts: { untilSolved?: boolean } = {}): FinishVerdict {
  // A run under the operator's stop policy (--stop operator, --until-solved)
  // has no caps and no wall clock, and one end the agents can reach: every
  // question in scope with a disposition under the bar, the same end any run
  // takes. Giving up is the operator's (swarm.sh stop), never a vote.
  const until = opts.untilSolved === true || run?.gate?.until_solved === true;
  if (!run || run.error) {
    const why = run?.error ? ` (${run.error})` : "";
    if (until) return { proceed: false, failing: "(finish line unavailable)", reason: `The finish line could not be run${why}, so nothing can show that every question has a disposition under the bar, and this run ends only then. Say so on the board and keep working; the operator sees the same.` };
    if (abandon) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `the finish line could not be run${why}; abandoned on purpose` };
    return { proceed: true, outcome: "verification_unavailable", reasonPrefix: VERIFICATION_UNAVAILABLE_PREFIX, note: `the finish line could not be run${why}; done proceeds as verification_unavailable, never as completed` };
  }
  // A finish line that is met, or has nothing to meet, proves something only
  // if the checks are the operator's. Read from anywhere else they are checks
  // an agent could have rewritten — on the host SWARM.md is writable from a
  // shell — so passing them certifies nothing. The harness hands every pane
  // the registry (SWARM_RUNS_DIR), and a microVM a read-only view of it, so a
  // different source means something is wrong. A failing finish line is a
  // refusal either way, and the check that fails is the useful thing to say.
  const untrusted = Boolean(run.source) && !FINISH_LINE_TRUSTED_SOURCES.has(run.source as string);
  if (untrusted && run.passed >= run.total) {
    // Abandoning claims nothing, so it is still the way out.
    if (abandon && !until) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `checks read from the ${run.source} were not trusted; abandoned on purpose` };
    return {
      proceed: false,
      failing: `(checks read from ${run.source})`,
      reason:
        `The finish line was read from the ${run.source}, which agents can edit, not from the operator's registry, so it cannot certify the run. ` +
        `This is the harness's problem, not yours: say so on the board and wait for the operator. If the goal cannot be met at all, call done again with abandon: true and say why.`,
    };
  }
  if (run.total === 0 || run.passed >= run.total) {
    // The goal's checks are met: what the harness's gate says decides, and an
    // abandon counts only while a question has no disposition under the bar.
    const noChecks = run.total === 0 ? "the goal has no checks" : undefined;
    const gate = run.gate;
    if (!gate) return { proceed: true, outcome: "completed", ...(noChecks ? { note: noChecks } : {}) };
    if (gate.error) {
      if (until) return { proceed: false, failing: "(gate unavailable)", reason: `The goal's checks pass, but ${gate.error}; this run ends only when every question is shown to have a disposition under the bar. Say so on the board; the operator sees the same.` };
      return { proceed: true, outcome: "verification_unavailable", reasonPrefix: VERIFICATION_UNAVAILABLE_PREFIX, note: gate.error };
    }
    if (gate.defects.length) {
      const each = gate.defects.map((d) => `- ${d.what}. Fix: ${d.fix}`).join("\n");
      return {
        proceed: false,
        failing: `${gate.defects[0].code}${gate.defects[0].lead ? ` ${gate.defects[0].lead}` : ""}${gate.defects[0].job ? ` ${gate.defects[0].job}` : ""}${gate.defects[0].question ? ` ${gate.defects[0].question}` : ""}`,
        reason:
          `The goal's checks pass, but material work is still open: ${gate.defects.length} item${gate.defects.length === 1 ? "" : "s"} the lead and question registers hold against done:\n${each}\n` +
          "A lead is disposed of with lead_close; a lead's job is interpreted by recording what its output shows with interprets naming it; a question in scope is answered in the ledger in its section. Then call done again.",
      };
    }
    // One rule under every stop policy (docs/adr/0013, joint-r3 Phase 1a):
    // done finishes a run only when every question in scope has a
    // disposition under the bar (answered; partial; a bounded negative or not
    // determinable on a coverage record another seat reviewed; a premise
    // shown not to hold; out of scope; accepted; withdrawn). What holds it: a
    // question with none (a best candidate, an unreviewed or stale negative,
    // an answer resting on a limitation, a quick negative nobody attested),
    // and a defect a limitation only names: "looked, not found" is no end.
    // The stop policy decides only who else ends the run: a cap pauses or
    // stops it, and the operator stops it, whatever the questions' state
    // (paused, stopped; never completed). Under --stop operator nothing else
    // does, and nobody abandons.
    {
      const acceptedIds = (gate.questions ?? []).filter((q) => q.outcome === "accepted").map((q) => q.id);
      const byOperator = (l: string) => (gate.accepted ?? []).includes(l) || acceptedIds.some((id) => l.startsWith(`question:${id} `));
      const open = (gate.questions ?? []).filter((q) => q.outcome !== "answered" && q.outcome !== "accepted" && q.outcome !== "withdrawn" && !q.disposition);
      // A gate from before dispositions says nothing of what holds beside its questions: every line an operator did not take holds.
      const holding = gate.holding ?? gate.limited.filter((l: string) => !byOperator(l) && !open.some((q) => l.startsWith(`question:${q.id} `)));
      if (open.length || holding.length) {
        // Giving up is still a way out where the operator is not the only one who ends the run.
        if (abandon && !until) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `the goal's checks pass, and ${open.length ? `${open.length} question(s) have no disposition under the bar` : "a defect a limitation only names stands"}; abandoned on purpose` };
        const qs = open.map((q) => `- question:${q.id} is ${q.outcome}, with no disposition under the bar: ${q.blocks.join("; ")}`).join("\n");
        return {
          proceed: false,
          failing: open[0] ? `question:${open[0].id}` : "(a defect a limitation names)",
          reason:
            (until
              ? `This run's stop is the operator's (--stop operator): no caps, no wall clock, and it ends when ${DISPOSITION_WORDS}; with no material lead open and no defect. `
              : `done finishes a run, whatever its stop policy, only when ${DISPOSITION_WORDS}; with no material lead open and no defect. A cap pauses or stops the run whatever the questions' state, and the operator may stop it: that end is stopped, never completed. `) +
            `${open.length ? `No disposition yet:\n${qs}\n` : ""}${holding.length ? `A defect is fixed, never only named:\n${holding.map((l) => `- ${l}`).join("\n")}\n` : ""}` +
            `${NEGATIVE_PATH_WORDS}. Otherwise take another route (lead_open), or close a lead needs_operator when only the operator can unblock it. ` +
            (until ? "Only the operator can stop this run." : "If the goal cannot be met at all, call done again with abandon: true and say why on the board."),
        };
      }
    }
    if (gate.limited.length) return { proceed: true, outcome: "examination_limited", note: `examination-limited: ${gate.limited.join("; ")}` };
    return { proceed: true, outcome: "completed", ...(noChecks ? { note: noChecks } : {}) };
  }
  if (until && abandon) return { proceed: false, failing: "(until solved)", reason: UNTIL_SOLVED_NO_ABANDON };
  if (abandon) return { proceed: true, outcome: "abandoned", reasonPrefix: ABANDON_PREFIX, note: `${run.passed} of ${run.total} checks pass; abandoned on purpose` };
  const failed = run.checks.filter((c) => !c.ok);
  const failing = failed[0]?.cmd ?? "(unknown check)";
  // Each failing check, and what makes it pass. What the check said, when it
  // said something, verbatim: a check such as check-answers.ts names each
  // defect and its fix there (`out`, whole up to what the finish line hands
  // back; past that, its size and the way to read it all). Otherwise the
  // command itself, which is the test.
  const each = failed.length
    ? failed
        .map((c) => {
          const head = `- \`${c.cmd}\` ${c.timed_out ? "timed out" : "fails"}.`;
          const said = [c.out, c.fix, c.output].filter((t): t is string => typeof t === "string" && t.trim().length > 0).map((t) => t.trimEnd());
          if (said.length) return `${head} It says:\n${said.join("\n")}`;
          if (c.out_bytes) return `${head} It printed ${c.out_bytes} bytes; run it from the run's directory to read them.`;
          return `${head} Fix: ${c.timed_out ? "it has to finish within the check's time limit and succeed" : "make this command succeed when run from the run's directory"}`;
        })
        .join("\n")
    : "- the runner reported fewer passing checks than it ran, and named none";
  return {
    proceed: false,
    failing,
    reason:
      `The finish line is not met: ${run.passed} of ${run.total} checks pass. The harness ran the goal's checks when you called done; each that fails:\n${each}\n` +
      `done ends the whole swarm, not your slice. If your slice is finished, post it to the board and take the next one, or wait. ` +
      `If the finish line cannot be met, call done again with abandon: true and say why on the board.`,
  };
}

/** The first command word of a shell line, past env assignments and `cd x &&`. */
export function leadingCommand(command: string): string {
  let text = command.trim();
  // drop a leading `cd … &&` or `cd … ;`
  text = text.replace(/^cd\s+[^&;|\n]+(&&|;|\n)\s*/, "");
  // drop VAR=value prefixes
  text = text.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+)+/, "");
  const word = text.split(/\s+/)[0] ?? "";
  const base = word.split("/").pop() ?? word;
  return /^[A-Za-z0-9_.+-]{1,40}$/.test(base) ? base : "";
}
