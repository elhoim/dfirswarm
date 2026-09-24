/**
 * Read models for the web app. Everything here is derived from files the
 * spawner and extension already write under runs/<id>/. No new
 * on-disk protocol.
 */
import { execFile } from "node:child_process";
import { constants as fsConstants, existsSync } from "node:fs";
import { lstat, open, readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { artifactKind } from "../artifact-kind.ts";
import {
  LEDGER_MD,
  listForgedTools,
  readInputsManifest,
  readLedger,
  readNames,
  type ForgedToolManifest,
  type InputFile,
  type LedgerEntry,
  type NameRecord,
} from "../../extensions/protocol.ts";
import {
  listSwarmSummaries,
  loadRegistry,
  readSwarmDetail,
  readThreadPosts,
  type AgentView,
  type SwarmDetail,
  type SwarmSummary,
} from "../../extensions/observe.ts";
import { agentDeadPath, agentDonePath, hostTime, readEventLog, type PostRecord, type SwarmEvent } from "../../extensions/protocol.ts";
import { isFailureEvent } from "../../ui/src/lib/event-taxonomy.ts";
import { countChecks } from "./goals.ts";

export type RegistryRun = {
  /** The packs this run carried, with the checksum of each manifest. */
  packs?: Array<{ id: string; version: string; manifest_sha256: string }>;
  id: string;
  label?: string;
  state?: string;
  sandbox?: string;
  n?: number;
  model?: string;
  cap_usd?: number;
  wall_clock_minutes?: number;
  hard_kill?: boolean;
  tool_forging?: boolean;
  /** The kickoff's self-compaction options; absent on runs older than the feature. */
  self_compact?: { enabled: boolean; notice_at: string; warn_at: string; compact_at: string; prompt: string | null; model?: string | null; set?: { notice_at: boolean; warn_at: boolean; compact_at: boolean } };
  /** How much post text one inbox/wait delivery carries; absent on runs older than the bound. */
  inbox_page_chars?: number;
  inputs?: { source: string; files: number; bytes: number; enforce: string; guard: string } | null;
  goal?: string;
  agents?: string[];
  started_at?: string;
  /** guarded · hosts · open · local (the local endpoints and nothing else). */
  net?: string;
  netguard?: boolean;
  /** netns (enforced) · proxy-only (advisory) · off — what the host could give, measured at kickoff. */
  netguard_mode?: string;
  /** seatbelt · mountns · none — where the panes could write. */
  write_guard?: string;
  /** "sealed", "open" or "unenforced": could a pane reach Herdr's control socket. */
  herdr_socket?: string;
  /** "read-only", "writable" or "not-applicable": could a pane drop code into Pi's extensions/. */
  pi_extensions?: string;
  /** What the host could enforce, probed at kickoff: seatbelt, userns, netns, pidns, landlock_abi, bwrap. */
  host_caps?: Record<string, unknown>;
  /** "token", "ancestry" or "token-exposed": how the collector decided whose line each one was. */
  attribution?: string;
  /** "kernel", "partial", "none" or "unmeasured": what the panes' own probes said the guard was. */
  write_guard_measured?: string;
  metered?: boolean;
  cap_tokens?: number | null;
  local_models?: string[];
  workspace_id?: string;
  workspace_ids?: string[];
  probe_agent?: string;
  tab_count?: number;
  split_failures?: number;
  extra_workspaces?: number;
  /** Where the agents ran; `mode` is host or microvm. Absent on runs older than isolation. */
  isolation?: { mode?: string; image?: string; snapshot?: boolean; oauth_allowed?: boolean };
  /**
   * Each pack's secrets and what the kickoff did with them: injected (bound
   * to their hosts, the value never in a VM), withheld, exposed (host panes
   * with --allow-pack-secrets) or not-set.
   */
  pack_secrets?: Record<string, { names?: string[]; mode?: string }>;
};

export type SwarmRow = SwarmSummary & {
  started_at: string;
  elapsed_ms: number;
  finished_at: string | null;
  goal: string;
  wall_clock_minutes: number;
  /** False when no model on the team bills: spend is an exact zero and cap_tokens is the brake. */
  metered: boolean;
  cap_tokens: number;
  net: string;
  agents_total: number;
  agents_done: number;
  agents_dead: number;
  violations: number;
  /** The newest post on threads/main — what the swarm last said, for the list. */
  last_post: { from: string; tag: string; body: string; at: string | null } | null;
  /** How many `## Checks` the goal defines; the finish line's denominator. */
  checks_total: number;
  /** Threads on the board and posts across all of them, for the list. */
  threads_total: number;
  posts_total: number;
  /** running | done | stopped | prepared | failed | finish_failed | stop_incomplete | unknown, derived from sentinel + registry */
  phase: SwarmPhase;
  /**
   * A VM run whose sentinel is written and whose VMs are not all put away
   * yet: the hub is waiting for the agents to get out, or snapshotting and
   * removing the VMs and taking custody (its status says finished, not
   * finish_done). Stopping now would race it.
   */
  finishing: boolean;
  /** Frontmatter `by` on done/SWARM_DONE, when the swarm is finished. */
  sentinel_by: string | null;
  /** budget.json stop_reason (cap / wall_clock), when the harness steered or stopped. */
  stop_reason: string | null;
  /** How many tools the run forged (directories under tools/ with a manifest): what --tools-from can seed. */
  tools_forged: number;
  /** The inputs directory the run was given, from inputs.json, or null: what a clean room is about. */
  inputs_source: string | null;
};

/** One post as a dot on a thread's pulse line: when, and who. */
export type ThreadDot = { at: string | null; from: string; tag: string };

/**
 * The swarm's activity over its lifetime, bucketed for the strip at the foot
 * of the page: messages (posts) against tool calls.
 */
export type ActivitySeries = {
  from: string | null;
  to: string | null;
  messages: number;
  tool_calls: number;
  buckets: Array<{ m: number; c: number }>;
};

/** Lifecycle and harness lines: not something an agent chose to call. */
export const LIFECYCLE_TOOLS = new Set(["agent_start", "agent_stop", "harness_stop", "cap_steer", "wall_steer", "claim_violation", "reap", "reaped", "thinking"]);

export function activitySeries(events: readonly SwarmEvent[], from: string | null, to: string | null, buckets = 96, now = Date.now()): ActivitySeries {
  const stamps = events.map((e) => Date.parse(hostTime(e))).filter((n) => Number.isFinite(n));
  const startMs = from && Number.isFinite(Date.parse(from)) ? Date.parse(from) : stamps.length ? Math.min(...stamps) : NaN;
  const endMs = to && Number.isFinite(Date.parse(to)) ? Date.parse(to) : stamps.length ? Math.max(now, ...stamps) : NaN;
  const series: ActivitySeries = {
    from: Number.isFinite(startMs) ? new Date(startMs).toISOString() : null,
    to: Number.isFinite(endMs) ? new Date(endMs).toISOString() : null,
    messages: 0,
    tool_calls: 0,
    buckets: Array.from({ length: buckets }, () => ({ m: 0, c: 0 })),
  };
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return series;
  const span = Math.max(1, endMs - startMs);
  for (const e of events) {
    const t = Date.parse(hostTime(e));
    if (!Number.isFinite(t)) continue;
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor(((t - startMs) / span) * buckets)));
    if (e.tool === "post") {
      series.messages += 1;
      series.buckets[idx].m += 1;
    } else if (!LIFECYCLE_TOOLS.has(e.tool)) {
      series.tool_calls += 1;
      series.buckets[idx].c += 1;
    }
  }
  return series;
}

export type SwarmPhase = "running" | "done" | "stopped" | "prepared" | "failed" | "finish_failed" | "stop_incomplete" | "unknown";

export type MarkerInfo = {
  reason?: string;
  at?: string;
  by?: string;
  output?: string;
  idle_seconds?: number;
  locks_released?: number;
};

export type AgentRow = AgentView & {
  callsign: string | null;
  spent_usd: number;
  tokens: number;
  calls: number;
  /** How full this agent's context is, from Pi's own estimate. */
  context_tokens: number;
  context_window: number;
  /** Self-compaction: the ceiling the lines are fractions of (0 when the run had none), the level, the lock. */
  context_ceiling: number;
  context_level: string;
  context_locked: boolean;
  /** Compactions Pi recorded, what they cost, the hand-offs alone, and when each compaction landed. */
  compactions: number;
  compaction_usd: number;
  handoffs: number;
  compaction_at: string[];
  posts: number;
  /** Posts by this agent per thread, for the agent card's THREADS list. */
  thread_posts: Record<string, number>;
  first_event_at: string | null;
  last_event_at: string | null;
  /** Calls that came back as a failure (ok:false, an error, a timeout, a blocked write), with when. */
  failures: number;
  failure_at: string[];
  marker_info: MarkerInfo | null;
};

export type WorkFile = {
  path: string;
  name: string;
  bytes: number;
  mtime: string;
  kind: "html" | "svg" | "image" | "text" | "json" | "binary";
  previewable: boolean;
};

export type ThreadRow = SwarmDetail["threads"][number] & {
  created_by: string | null;
  created_at: string | null;
  /** Every post as a dot, so the list can draw who spoke when. */
  activity: ThreadDot[];
};

export type TimedPost = PostRecord & { at: string | null };

export type SentinelInfo = {
  by?: string;
  output?: string;
  reason?: string;
  at?: string;
};

/** A forged tool with how the swarm has used it. */
/** The read-only inputs a swarm was given, with what the trace says about them. */
export type InputsView = {
  source: string;
  copied_at: string;
  files: InputFile[];
  bytes: number;
  /** What the operator asked for: auto | on | off. */
  enforce: string;
  /** What the kickoff could set up: seatbelt | mountns | none. */
  guard: string;
  /** What the panes measured at session start: kernel | mode | none, per agent. */
  enforced: Record<string, string>;
  violations: SwarmEvent[];
  /** The latest inputs_check line, if an agent has called done. */
  check: { ok: boolean; content_ok: boolean; checked: number; modified: string[]; metadata: string[]; missing: string[]; added: string[]; by: string; at: string } | null;
};

/** A pack as the run carried it: what the record says, plus the inventory read
 *  back from the installed pack so the console can show what went unused. */
export type PackView = {
  id: string;
  version: string;
  manifest_sha256: string;
  /** False when the pack has since been removed or replaced on this host. */
  installed: boolean;
  name: string;
  description: string;
  skills: Array<{ id: string; title: string; when: string }>;
  tools: string[];
};

export type ForgedToolRow = ForgedToolManifest & {
  calls: number;
  failures: number;
  users: string[];
  last_used_at: string | null;
};

/** One agent's VM as the console shows it: its record, and the hub's live word on it. */
export type VmHealth = {
  agent: string;
  name: string | null;
  image: { ref: string | null; digest: string | null; expected: string | null };
  cpus: number | null;
  memory_mib: number | null;
  /** What the kickoff's probe found in the VM. */
  probe: { hub: boolean; floor: string | null; inputs: string | null; clock_skew_s: number | null; fuse: boolean | null; loop: boolean | null; missing: string[] };
  fit_warnings: string[];
  /**
   * The hub's word on this agent: working, idle, done, gone, and when it last
   * heard a line from the VM; null when no hub answers for this run. When the
   * hub is not alive this is what it last wrote, not what is true now.
   */
  live: { state: string; connected: boolean; since: string | null; last_seen: string | null } | null;
  /**
   * The run's hub (one for every VM, repeated on each): alive when hub.pid is
   * a vm-hub.ts serving this run's hub directory and the status shown was
   * written by that process. null when no hub is recorded: before the
   * kickoff started it, or after stop put it away.
   */
  hub_alive: boolean | null;
  /** What was found about the hub, in words, with how stale its status is. */
  hub_detail: string | null;
  /** How loud to be about the hub: ok, warn (down but being brought back, or ended by the stop), danger (down and nothing brings it back). */
  hub_tone: "ok" | "warn" | "danger" | null;
  /** The hub's keeper (hub-supervise.sh), which restarts a dead hub until the stop; null when none is recorded. */
  hub_keeper_alive: boolean | null;
  /** The run's stop has begun (the hub directory's .stop): a hub ended now was ended on purpose. */
  hub_stop_begun: boolean;
  /** The hub says it is putting the VMs away and taking custody (finished, not yet finish_done). */
  hub_finishing: boolean;
  /** Seconds since the hub last wrote status.json. It writes on a change of a seat's state or link, not on a clock, so a quiet hub's is old. */
  hub_status_age_s: number | null;
  /** What the VM mounts, from its record: the host path, where it appears in the VM, ro or rw, no-exec. */
  mounts: Array<{ host: string; guest: string; mode: string; noexec: boolean }>;
  /** Its network policy: deny by default plus these hosts, or public (--no-netguard); null on a record without one. */
  network: { default: string; allow_hosts: string[]; host_ports: number[] } | null;
  /** The credentials bound to it as placeholders, each with the only hosts it is swapped in for. */
  secrets: Array<{ name: string; hosts: string[] }>;
  /** Each pack's secrets and what the kickoff did with them (the run record's pack_secrets): the same for every VM. */
  pack_secrets: Array<{ pack: string; names: string[]; mode: string }>;
  stopped_at: string | null;
  snapshot: "kept" | "not kept" | "failed" | null;
  installed_outside: string[];
  runtime: string | null;
  runtime_changed: string | null;
};

/**
 * custody.json as the console shows it: custody.ts's own summary, whole, and
 * the parts of it an examiner asks about, with every name kept. `problems`
 * is what custody flagged; an empty list is a clean verdict.
 */
export type CustodyView = {
  at: string | null;
  summary: string;
  verdict: "clean" | "attention";
  problems: string[];
  /** `skipped`: files not re-read before custody's deadline, which the verdict does not cover; `complete` is false when there are any. */
  evidence:
    | null
    | { unverifiable: string }
    | { files: number; bytes: number; unchanged: boolean; complete: boolean; changed: string[]; missing: string[]; added: string[]; skipped: string[]; manifest_anchored: boolean | null };
  /** Names under the sessions that are not regular files (a link, a device): sealed nothing. */
  sessions_not_files: string[];
  /** `refused_spills`: spill files custody would not read, and why. */
  trace: { lines: number; intact: boolean; detail: string; unverified: number; disputed: number; spilled: number; lost: number; refused_spills: Array<{ path: string; why: string }> } | null;
  /** `missing_from_ledger`: hashes the trace carries and the ledger does not (deleted); `not_on_trace`: chained entries never on the trace (written without the tool). */
  ledger: { entries: number; chained: number | null; intact: boolean; detail: string; missing_from_ledger: string[]; not_on_trace: number[] } | null;
  tool_outputs: { referenced: number; verified: number; missing: string[]; mismatched: string[]; refused: string[] } | null;
  vms: Array<{
    agent: string;
    /** The sha256 of the VM's record as custody read it. */
    record_sha256: string | null;
    stopped: boolean;
    kept: string | null;
    /** verified, unverified, an error, or null when no snapshot was taken. */
    snapshot: string | null;
    image: string | null;
    expected_image: string | null;
    image_differs: boolean;
    secret_violations: Array<{ at: string; env: string; host: string; method: string; path: string; action: string }>;
    installed_outside: string[];
    installed_note: string | null;
    runtime_changed: string | null;
  }> | null;
  incomplete: string | null;
};

export type SwarmView = Omit<SwarmDetail, "summary" | "agents" | "threads"> & {
  summary: SwarmRow;
  agents: AgentRow[];
  threads: ThreadRow[];
  /**
   * `goal` is the rendered SWARM.md the agents work from. This is the goal
   * document the operator submitted — the part worth carrying into the next
   * run or keeping in the library.
   */
  goal_document: string;
  registry: RegistryRun | null;
  work: WorkFile[];
  layout: Record<string, unknown> | null;
  violations: SwarmEvent[];
  sentinel_info: SentinelInfo | null;
  activity: ActivitySeries;
  /** Tools the agents forged, with usage from the event log. */
  tools: ForgedToolRow[];
  /** The packs this run carried, with everything each one holds, so the console
   *  can say what was consulted and what was carried and never opened. */
  packs: PackView[];
  /** The read-only inputs, or null when the swarm was given none. */
  inputs: InputsView | null;
  /** What the agents recorded with `record`: events, indicators, findings. */
  ledger: LedgerView;
  /** What each agent decided to call itself, in its own words. */
  names: NameRecord[];
  /** A microVM run's VMs; empty for a host run. */
  vms: VmHealth[];
  /** What the last custody check found (custody.json), or null before any stop or hub finish took one. */
  custody: CustodyView | null;
};

/** ledger/entries.jsonl as the agents wrote it, and whether ledger.md exists. */
export type LedgerView = {
  entries: LedgerEntry[];
  /** True once the harness has rendered ledger/ledger.md. */
  rendered: boolean;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

async function mtimeIso(path: string): Promise<string | null> {
  try {
    return (await stat(path)).mtime.toISOString();
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function parseFrontMatter(text: string): Record<string, string> {
  const match = text.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};
  const attrs: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    attrs[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return attrs;
}

export function derivePhase(state: string, done: boolean): SwarmPhase {
  // `finish_failed`: the hub reached the end of a VM run and could not put
  // its VMs away. The sentinel is there, so without this line the failure
  // read as a plain "done" and VMs left running went unmentioned.
  if (state === "finish_failed") return "finish_failed";
  // `stop_incomplete`: swarm.sh stop ran and a VM of the run was still up
  // after it. Whatever the sentinel says, that is what the operator must see.
  if (state === "stop_incomplete") return "stop_incomplete";
  if (done) return "done";
  if (state === "running") return "running";
  // `finished`: the hub put a VM run away after its sentinel; without the
  // sentinel it is a run that ended, which the console calls stopped.
  if (state === "stopped" || state === "finished") return "stopped";
  if (state === "prepared") return "prepared";
  // A kickoff that did not get its agents running: said, not "unknown".
  if (state === "failed") return "failed";
  return "unknown";
}

async function countMarkers(sandbox: string, ids: string[]): Promise<{ done: number; dead: number }> {
  let done = 0;
  let dead = 0;
  for (const id of ids) {
    if (await exists(agentDonePath(sandbox, id))) done += 1;
    else if (await exists(agentDeadPath(sandbox, id))) dead += 1;
  }
  return { done, dead };
}

/** The event log from the protocol's own cache: parsed once per change, shared, never mutated here. */
function readEvents(sandbox: string): Promise<readonly SwarmEvent[]> {
  return readEventLog(sandbox);
}

export async function findRun(runsDir: string, id: string): Promise<RegistryRun | null> {
  const runs = await loadRegistry(runsDir);
  const run = runs.find((r) => isRecord(r) && r.id === id);
  return run ? (run as RegistryRun) : null;
}

async function enrichSummary(
  runsDir: string,
  summary: SwarmSummary,
  runsById: Map<string, RegistryRun>,
  now: number,
): Promise<SwarmRow> {
  const run = runsById.get(summary.id);
  const sandbox = summary.sandbox;
  const toolsForged = await countForgedTools(sandbox);
  const inputsSource = (await readInputsManifest(sandbox).catch(() => null))?.source ?? null;
  const budgetRaw = await readFile(join(sandbox, "budget.json"), "utf8").catch(() => "{}");
  let started = run?.started_at ?? "";
  let wall = Number(run?.wall_clock_minutes) || 0;
  let metered = run?.metered !== false;
  let capTokens = Number(run?.cap_tokens) || 0;
  let stopReason: string | null = null;
  try {
    const budget = JSON.parse(budgetRaw) as {
      started_at?: string;
      wall_clock_minutes?: number;
      metered?: boolean;
      cap_tokens?: number;
      stop_reason?: string;
    };
    if (!started && budget.started_at) started = budget.started_at;
    if (!wall && budget.wall_clock_minutes) wall = Number(budget.wall_clock_minutes) || 0;
    if (budget.metered === false) metered = false;
    if (!capTokens && budget.cap_tokens) capTokens = Number(budget.cap_tokens) || 0;
    if (typeof budget.stop_reason === "string" && budget.stop_reason) stopReason = budget.stop_reason;
  } catch {
    // budget missing or torn
  }
  const finishedAt = summary.done ? await mtimeIso(join(sandbox, "done", "SWARM_DONE")) : null;
  const startMs = Date.parse(started);
  const endMs = finishedAt ? Date.parse(finishedAt) : now;
  const elapsed = Number.isFinite(startMs) ? Math.max(0, endMs - startMs) : 0;
  const ids = Array.isArray(run?.agents) ? run!.agents! : [];
  const markers = await countMarkers(sandbox, ids);
  const events = await readEvents(sandbox);
  const violations = events.filter((e) => e.tool === "claim_violation").length;
  const goalText = typeof run?.goal === "string" ? run.goal : "";
  const mainPosts = await readThreadPosts(sandbox, "main").catch(() => [] as PostRecord[]);
  const newest = mainPosts.length ? mainPosts[mainPosts.length - 1] : null;
  const threadNames = (await readdir(join(sandbox, "threads"), { withFileTypes: true }).catch(() => [])).filter((d) => d.isDirectory()).map((d) => d.name);
  let postsTotal = mainPosts.length;
  for (const name of threadNames) {
    if (name === "main") continue;
    postsTotal += (await readThreadPosts(sandbox, name).catch(() => [] as PostRecord[])).length;
  }
  const lastPost = newest
    ? {
        from: newest.from,
        tag: newest.tag,
        body: newest.body.length > 240 ? `${newest.body.slice(0, 239)}…` : newest.body,
        at: await mtimeIso(newest.path),
      }
    : null;
  let sentinelBy: string | null = null;
  if (summary.done) {
    const text = await readFile(join(sandbox, "done", "SWARM_DONE"), "utf8").catch(() => "");
    const fm = parseFrontMatter(text);
    if (fm.by) sentinelBy = fm.by;
    if (!stopReason && fm.reason) stopReason = fm.reason;
  }
  void runsDir;
  // The same predicate for the list and the run page, so neither says
  // "done" while the hub is still snapshotting.
  const finishing = summary.done && run?.isolation?.mode === "microvm" && (await vmRunFinishing(sandbox, summary.state));
  return {
    ...summary,
    started_at: started,
    elapsed_ms: elapsed,
    finished_at: finishedAt,
    goal: typeof run?.goal === "string" ? run.goal : "",
    wall_clock_minutes: wall,
    metered,
    cap_tokens: capTokens,
    net: typeof run?.net === "string" ? run.net : "guarded",
    agents_total: ids.length || summary.n,
    agents_done: markers.done,
    agents_dead: markers.dead,
    violations,
    last_post: lastPost,
    checks_total: countChecks(goalText),
    threads_total: threadNames.length,
    posts_total: postsTotal,
    phase: derivePhase(summary.state, summary.done),
    finishing,
    sentinel_by: sentinelBy,
    stop_reason: stopReason,
    tools_forged: toolsForged,
    inputs_source: inputsSource,
  };
}

export async function listSwarmRows(runsDir: string, now = Date.now()): Promise<SwarmRow[]> {
  const [summaries, runs] = await Promise.all([listSwarmSummaries(runsDir), loadRegistry(runsDir)]);
  const byId = new Map<string, RegistryRun>();
  for (const run of runs) {
    if (isRecord(run) && typeof run.id === "string") byId.set(run.id, run as RegistryRun);
  }
  const rows: SwarmRow[] = [];
  for (const s of summaries) rows.push(await enrichSummary(runsDir, s, byId, now));
  return rows;
}

export async function listWorkFiles(sandbox: string, maxDepth = 3): Promise<WorkFile[]> {
  const root = join(sandbox, "work");
  const out: WorkFile[] = [];
  async function walk(dir: string, depth: number) {
    const names = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of names) {
      if (entry.name === ".gitkeep") continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (depth < maxDepth) await walk(abs, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const info = await stat(abs).catch(() => null);
      if (!info) continue;
      const rel = relative(root, abs).split(sep).join("/");
      const kind = artifactKind(entry.name);
      out.push({
        path: `work/${rel}`,
        name: rel,
        bytes: info.size,
        mtime: info.mtime.toISOString(),
        kind,
        previewable: kind !== "binary",
      });
    }
  }
  await walk(root, 0);
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export type WorkFileError = { error: 400 | 404 | 409; message: string };

/**
 * Open a work/ artifact for the unauthenticated GET. Lexical escape is 400;
 * a missing file is 404; a symlink or a realpath outside work/ is 409 so a
 * pane's `ln -s /etc/passwd work/leak.txt` cannot be read from the console.
 */
export async function resolveWorkFile(sandbox: string, rel: string): Promise<string | WorkFileError> {
  return resolveSandboxFile(sandbox, "work", rel, "artifact");
}

/**
 * The whole output of a tool call, kept under tool-output/ when the model
 * received a prefix. Same checks as an artifact: the directory is written by
 * the harness, but a shell can plant a link there, and the route is open.
 */
export async function resolveToolOutputFile(sandbox: string, rel: string): Promise<string | WorkFileError> {
  return resolveSandboxFile(sandbox, "tool-output", rel, "tool output");
}

async function resolveSandboxFile(sandbox: string, dir: "work" | "tool-output", rel: string, what: string): Promise<string | WorkFileError> {
  const root = resolve(sandbox, dir);
  const lexical = resolve(root, rel);
  const back = relative(root, lexical);
  if (back === "" || back.startsWith("..") || back.split(sep).includes("..")) return { error: 400, message: `path escapes ${dir}/` };
  const st = await lstat(lexical).catch(() => null);
  if (!st) return { error: 404, message: `${what} not found` };
  if (st.isSymbolicLink()) return { error: 409, message: `${what} is a symlink` };
  if (!st.isFile()) return { error: 404, message: `${what} not found` };
  const real = await realpath(lexical).catch(() => null);
  const realSandbox = await realpath(sandbox).catch(() => resolve(sandbox));
  const realRoot = join(realSandbox, dir);
  if (!real || (real !== realRoot && !real.startsWith(`${realRoot}${sep}`))) {
    return { error: 409, message: `${what} is no longer a file inside ${dir}/` };
  }
  return real;
}

const CALLSIGN_PATTERNS = [
  /\b(?:call me|i am|i'm|this is|name(?: is)?:?)\s+["“']?([A-Z][A-Za-z0-9_-]{1,23})["”']?/i,
  /^["“']?([A-Z][A-Za-z0-9_-]{1,23})["”']?\s+(?:here|reporting|checking in)/i,
];

/**
 * Agents tend to name themselves in chat (Scout, Stitch...). The protocol has
 * no callsign field, so this is a heuristic read of the first `intro` post.
 */
export function deriveCallsign(posts: PostRecord[], agentId: string): string | null {
  const intro = posts.find((p) => p.from === agentId && p.tag === "intro");
  if (!intro) return null;
  const firstLine = intro.body.split("\n")[0]?.trim() ?? "";
  for (const re of CALLSIGN_PATTERNS) {
    const m = firstLine.match(re);
    if (m && m[1].toLowerCase() !== agentId.toLowerCase()) return m[1];
  }
  return null;
}

async function readMarkerInfo(sandbox: string, agent: AgentView): Promise<MarkerInfo | null> {
  const file =
    agent.marker === "done"
      ? agentDonePath(sandbox, agent.id)
      : agent.marker === "dead"
        ? agentDeadPath(sandbox, agent.id)
        : null;
  if (!file) return null;
  const text = await readFile(file, "utf8").catch(() => "");
  if (!text) return null;
  const fm = parseFrontMatter(text);
  const info: MarkerInfo = {};
  if (fm.reason) info.reason = fm.reason;
  if (fm.at) info.at = fm.at;
  if (fm.by) info.by = fm.by;
  if (fm.output) info.output = fm.output;
  if (fm.idle_seconds) info.idle_seconds = Number(fm.idle_seconds);
  if (fm.locks_released) info.locks_released = Number(fm.locks_released);
  return info;
}

/** Posts carry no timestamp in their frontmatter; the file mtime is the clock. */
export async function readTimedPosts(sandbox: string, thread: string): Promise<TimedPost[]> {
  const posts = await readThreadPosts(sandbox, thread);
  const out: TimedPost[] = [];
  for (const p of posts) out.push({ ...p, at: await mtimeIso(p.path) });
  return out;
}

/**
 * Every post the swarm wrote, across every thread, in time order.
 *
 * The swarm view ships each thread's `activity` — a timestamp, an author and
 * a tag per post — which is enough to draw a pulse line and nothing else.
 * Anything that reads what was actually said (who named whom, which files the
 * board argued about, where somebody said stop) needs the bodies, and they
 * are too heavy for a view re-read on every change. So they are their own
 * request, made once by the panel that wants them.
 */
export async function readAllPosts(sandbox: string): Promise<TimedPost[]> {
  const names = (await readdir(join(sandbox, "threads"), { withFileTypes: true }).catch(() => []))
    .filter((d) => d.isDirectory())
    .map((d) => d.name);
  const out: TimedPost[] = [];
  for (const name of names) out.push(...(await readTimedPosts(sandbox, name).catch(() => [])));
  // Posts are numbered per thread, so the id breaks a tie within one thread
  // and the clock orders the board as a whole.
  out.sort((a, b) => (a.at ?? "").localeCompare(b.at ?? "") || a.id - b.id);
  return out;
}

export async function readSwarmView(runsDir: string, id: string, traceLimit = 400): Promise<SwarmView | null> {
  const detail = await readSwarmDetail(runsDir, id, traceLimit);
  if (!detail) return null;
  const sandbox = detail.summary.sandbox;
  const run = await findRun(runsDir, id);
  // This swarm's row, enriched the way the list enriches every row — and only
  // this one. The detail view used to rebuild the whole fleet's rows to find
  // its own, which read every sandbox on disk on every request.
  const byId = new Map<string, RegistryRun>();
  if (run) byId.set(id, run);
  const summary = await enrichSummary(runsDir, detail.summary, byId, Date.now());

  const allPosts: TimedPost[] = [];
  const threads: ThreadRow[] = [];
  for (const t of detail.threads) {
    const posts = await readTimedPosts(sandbox, t.name);
    allPosts.push(...posts);
    threads.push({
      ...t,
      created_by: posts[0]?.from ?? null,
      created_at: posts[0]?.at ?? null,
      activity: posts.map((p) => ({ at: p.at, from: p.from, tag: p.tag })),
    });
  }
  // main first, then the busiest thread most recently: what the operator
  // wants to look at is what just moved.
  threads.sort((a, b) => (a.name === "main" ? -1 : b.name === "main" ? 1 : (b.last_at ?? "").localeCompare(a.last_at ?? "") || a.name.localeCompare(b.name)));

  let sentinelInfo: SentinelInfo | null = null;
  if (detail.sentinel) {
    const text = await readFile(join(sandbox, "done", "SWARM_DONE"), "utf8").catch(() => "");
    const fm = parseFrontMatter(text);
    sentinelInfo = { by: fm.by, output: fm.output, reason: fm.reason, at: fm.at };
  }
  const events = await readEvents(sandbox);
  const lastEventByAgent = new Map<string, string>();
  const firstEventByAgent = new Map<string, string>();
  const failuresByAgent = new Map<string, string[]>();
  const compactionsByAgent = new Map<string, string[]>();
  for (const e of events) {
    lastEventByAgent.set(e.agent, hostTime(e));
    if (!firstEventByAgent.has(e.agent)) firstEventByAgent.set(e.agent, hostTime(e));
    if (isFailureEvent(e)) (failuresByAgent.get(e.agent) ?? failuresByAgent.set(e.agent, []).get(e.agent)!).push(e.ts);
    if (e.tool === "compact_done") (compactionsByAgent.get(e.agent) ?? compactionsByAgent.set(e.agent, []).get(e.agent)!).push(e.ts);
  }

  const agents: AgentRow[] = [];
  for (const a of detail.agents) {
    const slice = detail.budget.agents[a.id];
    const threadPosts: Record<string, number> = {};
    for (const p of allPosts) if (p.from === a.id) threadPosts[p.thread] = (threadPosts[p.thread] ?? 0) + 1;
    const failureAt = failuresByAgent.get(a.id) ?? [];
    agents.push({
      ...a,
      callsign: deriveCallsign(allPosts, a.id),
      spent_usd: slice?.spent_usd ?? 0,
      tokens: slice?.tokens ?? 0,
      calls: slice?.calls ?? 0,
      context_tokens: slice?.context_tokens ?? 0,
      context_window: slice?.context_window ?? 0,
      context_ceiling: slice?.context_ceiling ?? 0,
      context_level: slice?.context_level ?? "",
      context_locked: slice?.context_locked === true,
      compactions: slice?.compactions ?? 0,
      compaction_usd: slice?.compaction_usd ?? 0,
      handoffs: slice?.handoffs ?? 0,
      compaction_at: compactionsByAgent.get(a.id) ?? [],
      posts: allPosts.filter((p) => p.from === a.id).length,
      thread_posts: threadPosts,
      first_event_at: firstEventByAgent.get(a.id) ?? null,
      last_event_at: lastEventByAgent.get(a.id) ?? null,
      failures: failureAt.length,
      failure_at: failureAt,
      marker_info: await readMarkerInfo(sandbox, a),
    });
  }

  const layoutRaw = await readFile(join(sandbox, "layout.json"), "utf8").catch(() => "");
  let layout: Record<string, unknown> | null = null;
  if (layoutRaw) {
    try {
      layout = JSON.parse(layoutRaw) as Record<string, unknown>;
    } catch {
      layout = null;
    }
  }

  return {
    ...detail,
    summary,
    agents,
    threads,
    // `goal` is the rendered SWARM.md the agents work from; this is the goal
    // document the operator submitted, which is the part worth carrying into
    // the next run or keeping in the library.
    goal_document: typeof run?.goal === "string" ? run.goal : "",
    registry: run,
    work: await listWorkFiles(sandbox),
    layout,
    violations: events.filter((e) => e.tool === "claim_violation"),
    sentinel_info: sentinelInfo,
    activity: activitySeries(events, summary.started_at || null, summary.finished_at),
    tools: await forgedToolRows(sandbox, events),
    packs: await packViews(run),
    inputs: await inputsView(sandbox, events),
    ledger: await ledgerView(sandbox),
    names: await readNames(sandbox).catch(() => []),
    vms: await vmHealth(sandbox, run),
    custody: await readCustody(sandbox),
  };
}

/**
 * Whether a VM run past its sentinel is still being put away. The hub says
 * so itself (status.json: finished, and not yet finish_done) while its
 * process is up, which covers custody after the registry already says
 * finished. Before the hub starts, while the registry says running, a VM
 * record without its stop time says the same.
 */
async function vmRunFinishing(sandbox: string, state: string): Promise<boolean> {
  const hub = await ownHubDir(sandbox);
  if (hub) {
    try {
      const status = JSON.parse(await readFile(join(hub, "status.json"), "utf8")) as { finished?: unknown; finish_done?: unknown; pid?: unknown };
      if (status.finished === true && status.finish_done !== true && typeof status.pid === "number" && pidAlive(status.pid)) return true;
    } catch {
      // no status: the records below decide
    }
  }
  return state === "running" && (await vmsNotPutAway(sandbox));
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Whether any of a run's VM records still lacks the stop time the VM manager writes when it puts one away. */
async function vmsNotPutAway(sandbox: string): Promise<boolean> {
  const dir = join(sandbox, "vm");
  const names = (await readdir(dir).catch(() => [] as string[])).filter((n) => n.endsWith(".json") && !n.startsWith("."));
  for (const name of names) {
    try {
      const rec = JSON.parse(await readFile(join(dir, name), "utf8")) as { stopped_at?: unknown };
      if (typeof rec.stopped_at !== "string") return true;
    } catch {
      // a torn record says nothing either way
    }
  }
  return false;
}

/**
 * The hub directory a sandbox's hub.dir names, when it is one the harness
 * made for this sandbox, as swarm.sh hub_dir_of decides: under the hubs'
 * parent, and naming this sandbox in its own `sandbox` file. A pane could
 * write hub.dir; it cannot make a directory there.
 */
async function ownHubDir(sandbox: string): Promise<string | null> {
  const hub = (await readFile(join(sandbox, "hub.dir"), "utf8").catch(() => "")).trim();
  if (!hub) return null;
  const parent = await realpath(join(process.env.TMPDIR || "/tmp", "dfirswarm-hubs")).catch(() => "");
  if (!parent || !hub.startsWith(`${parent}/dfs-`) || hub.includes("..")) return null;
  const named = (await readFile(join(hub, "sandbox"), "utf8").catch(() => "")).trim();
  return named && named === (await realpath(sandbox).catch(() => sandbox)) ? hub : null;
}

function ageWords(seconds: number | null): string {
  if (seconds === null) return "an unknown time";
  if (seconds < 90) return `${seconds} s`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} min`;
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} days`;
}

/** Whether a pid runs a command line that has every one of these in it; without ps, the signal's answer. */
function commandHas(pid: number, needles: string[]): Promise<boolean> {
  if (!pidAlive(pid)) return Promise.resolve(false);
  return new Promise((done) => {
    execFile("ps", ["-ww", "-o", "command=", "-p", String(pid)], { timeout: 5000 }, (err, stdout) => {
      if (err) {
        done((err as NodeJS.ErrnoException).code === "ENOENT");
        return;
      }
      const cmd = String(stdout);
      done(needles.every((n) => cmd.includes(n)));
    });
  });
}

type HubHealth = { alive: boolean; tone: "ok" | "warn" | "danger"; detail: string; age: number | null; keeper: boolean | null; stopBegun: boolean };

/**
 * Is the hub up, and is the status on screen its own? The hub writes
 * status.json when it starts and whenever a seat's state or link changes,
 * with no heartbeat, so an old file from a quiet hub is fine. A status
 * written by another process than the one hub.pid names is not: that is an
 * earlier hub's word. The status carries the writer's pid; a hub from before
 * that field is judged by the file times instead. A hub that is down is
 * weighed against its keeper and the stop: brought back, ended on purpose,
 * or nobody's.
 */
async function hubHealth(sandbox: string, hub: string, status: { at: string | null; pid: number | null }, now: number): Promise<HubHealth> {
  const statusMs = status.at ? Date.parse(status.at) : NaN;
  const age = Number.isFinite(statusMs) ? Math.max(0, Math.round((now - statusMs) / 1000)) : null;
  const stopBegun = existsSync(join(hub, ".stop"));
  const keeperPid = Number((await readFile(join(hub, "supervisor.pid"), "utf8").catch(() => "")).trim());
  const keeper = Number.isInteger(keeperPid) && keeperPid > 1 ? await commandHas(keeperPid, ["hub-supervise.sh"]) : null;
  const pidFile = join(sandbox, "hub.pid");
  const pid = Number((await readFile(pidFile, "utf8").catch(() => "")).trim());
  const down = (why: string): HubHealth => {
    if (stopBegun) return { alive: false, tone: "warn", detail: `${why}; the run's stop has begun and ends the hub on purpose`, age, keeper, stopBegun };
    if (keeper) return { alive: false, tone: "warn", detail: `HUB DOWN: ${why}; its keeper (pid ${keeperPid}) is up and brings it back`, age, keeper, stopBegun };
    return { alive: false, tone: "danger", detail: `HUB DOWN: ${why}${keeper === false ? ", and its keeper is not running either, so nothing brings it back" : ""}`, age, keeper, stopBegun };
  };
  if (!Number.isInteger(pid) || pid <= 1) return down("no hub.pid names the hub process");
  // A pid is reused, and hub.pid is only tool-protected: it has to be a
  // vm-hub.ts serving this hub's directory (swarm.sh hub_pid_ours).
  if (!(await commandHas(pid, ["vm-hub.ts", hub]))) return down(`the hub (pid ${pid}) is not running; the states below are what it last wrote, ${ageWords(age)} ago`);
  if (!Number.isFinite(statusMs)) return { alive: false, tone: "warn", detail: `the hub (pid ${pid}) is running but has written no status`, age, keeper, stopBegun };
  if (status.pid !== null ? status.pid !== pid : statusMs < ((await stat(pidFile).catch(() => null))?.mtimeMs ?? -Infinity) - 2000) {
    return { alive: false, tone: "warn", detail: `the hub (pid ${pid}) is running but has not written its status since it started; the states below are an earlier hub's, ${ageWords(age)} old`, age, keeper, stopBegun };
  }
  return { alive: true, tone: "ok", detail: `hub running (pid ${pid}) · status written ${ageWords(age)} ago${keeper === false ? " · its keeper is not running" : ""}`, age, keeper, stopBegun };
}

type VmRecordShape = {
  agent?: unknown;
  name?: unknown;
  cpus?: unknown;
  memory_mib?: unknown;
  image?: { ref?: string; manifest_digest?: string | null; expected_digest?: string };
  probe?: Record<string, unknown>;
  image_fit?: { warnings?: string[]; blockers?: string[] };
  snapshot?: { sha256?: string; error?: string };
  installed_outside_image?: { apt?: Record<string, string>; venv?: Record<string, string> };
  runtime_changed?: { from?: string; to?: string };
  runtime?: { version?: string };
  stopped_at?: unknown;
  mounts?: unknown;
  network?: unknown;
  secrets?: unknown;
};

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/**
 * Each agent's VM: the record the kickoff and stop wrote (vm/<id>.json) and,
 * while the run is up, the hub's live status and whether the hub is up at
 * all, since a dead hub's last status looks like a live one. The hub is
 * found the way the scripts find it: hub.dir must name a directory under the
 * hubs' parent made for this sandbox, since a pane could write hub.dir. The
 * run record, when given, adds what the kickoff did with each pack's secrets.
 */
export async function vmHealth(sandbox: string, run: RegistryRun | null = null, now = Date.now()): Promise<VmHealth[]> {
  const dir = join(sandbox, "vm");
  const names = (await readdir(dir).catch(() => [] as string[])).filter((n) => n.endsWith(".json") && !n.startsWith(".")).sort();
  if (!names.length) return [];
  let live: Record<string, { state?: string; connected?: boolean; since?: string; last_seen?: string }> = {};
  let hubAlive: boolean | null = null;
  let hubDetail: string | null = null;
  let hubAge: number | null = null;
  let hubTone: VmHealth["hub_tone"] = null;
  let hubKeeper: boolean | null = null;
  let hubStopBegun = false;
  let hubFinishing = false;
  const hub = await ownHubDir(sandbox);
  if (hub) {
    let statusAt: string | null = null;
    let statusPid: number | null = null;
    try {
      const status = JSON.parse(await readFile(join(hub, "status.json"), "utf8")) as { at?: unknown; pid?: unknown; agents?: typeof live; finished?: unknown; finish_done?: unknown };
      live = status.agents ?? {};
      statusAt = typeof status.at === "string" ? status.at : null;
      statusPid = typeof status.pid === "number" ? status.pid : null;
      hubFinishing = status.finished === true && status.finish_done !== true;
    } catch {
      live = {};
    }
    const h = await hubHealth(sandbox, hub, { at: statusAt, pid: statusPid }, now);
    hubAlive = h.alive;
    hubDetail = h.detail;
    hubAge = h.age;
    hubTone = h.tone;
    hubKeeper = h.keeper;
    hubStopBegun = h.stopBegun;
    // Finishing is what a live hub is doing; a dead one's last word is not.
    hubFinishing = hubFinishing && h.alive;
  }
  const packSecrets = Object.entries(run?.pack_secrets ?? {}).map(([pack, s]) => ({ pack, names: stringList(s?.names), mode: typeof s?.mode === "string" ? s.mode : "?" }));
  const out: VmHealth[] = [];
  for (const name of names) {
    let rec: VmRecordShape;
    try {
      rec = JSON.parse(await readFile(join(dir, name), "utf8")) as VmRecordShape;
    } catch {
      continue;
    }
    const agent = typeof rec.agent === "string" ? rec.agent : name.replace(/\.json$/, "");
    const image = rec.image ?? {};
    const probe = rec.probe ?? {};
    const fit = rec.image_fit ?? {};
    const snap = rec.snapshot;
    const inv = rec.installed_outside_image;
    const changed = rec.runtime_changed;
    const l = live[agent];
    const net = rec.network && typeof rec.network === "object" ? (rec.network as { default?: unknown; allow_hosts?: unknown; host_ports?: unknown }) : null;
    out.push({
      agent,
      name: typeof rec.name === "string" ? rec.name : null,
      image: { ref: image.ref ?? null, digest: image.manifest_digest ?? null, expected: image.expected_digest ?? null },
      cpus: typeof rec.cpus === "number" ? rec.cpus : null,
      memory_mib: typeof rec.memory_mib === "number" ? rec.memory_mib : null,
      probe: {
        hub: probe.hub === true,
        floor: typeof probe.base === "string" ? probe.base : null,
        inputs: typeof probe.inputs === "string" ? probe.inputs : null,
        clock_skew_s: typeof probe.clock_skew_s === "number" ? probe.clock_skew_s : null,
        fuse: typeof probe.fuse === "boolean" ? probe.fuse : null,
        loop: typeof probe.loop === "boolean" ? probe.loop : null,
        missing: Array.isArray(probe.missing_binaries) ? (probe.missing_binaries as string[]) : [],
      },
      fit_warnings: [...(fit.blockers ?? []), ...(fit.warnings ?? [])],
      live: l
        ? { state: String(l.state ?? "?"), connected: l.connected === true, since: typeof l.since === "string" ? l.since : null, last_seen: typeof l.last_seen === "string" ? l.last_seen : null }
        : null,
      hub_alive: hubAlive,
      hub_detail: hubDetail,
      hub_tone: hubTone,
      hub_keeper_alive: hubKeeper,
      hub_stop_begun: hubStopBegun,
      hub_finishing: hubFinishing,
      hub_status_age_s: hubAge,
      mounts: Array.isArray(rec.mounts)
        ? rec.mounts
            .filter((m): m is Record<string, unknown> => !!m && typeof m === "object")
            .map((m) => ({ host: String(m.host ?? "?"), guest: String(m.guest ?? m.host ?? "?"), mode: m.mode === "rw" ? "rw" : "ro", noexec: m.noexec === true }))
        : [],
      network: net ? { default: typeof net.default === "string" ? net.default : "?", allow_hosts: stringList(net.allow_hosts), host_ports: Array.isArray(net.host_ports) ? net.host_ports.filter((p): p is number => typeof p === "number") : [] } : null,
      secrets: Array.isArray(rec.secrets)
        ? rec.secrets.filter((s): s is Record<string, unknown> => !!s && typeof s === "object").map((s) => ({ name: String(s.name ?? "?"), hosts: stringList(s.hosts) }))
        : [],
      pack_secrets: packSecrets,
      stopped_at: typeof rec.stopped_at === "string" ? rec.stopped_at : null,
      snapshot: !snap ? (typeof rec.stopped_at === "string" ? "not kept" : null) : snap.error ? "failed" : "kept",
      installed_outside: inv ? [...Object.entries(inv.apt ?? {}).map(([k, v]) => `apt ${k} ${v}`), ...Object.entries(inv.venv ?? {}).map(([k, v]) => `venv ${k} ${v}`)] : [],
      runtime: typeof rec.runtime?.version === "string" ? rec.runtime.version : null,
      runtime_changed: changed?.from && changed.to ? `${changed.from} → ${changed.to}` : null,
    });
  }
  return out;
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

/**
 * custody.json, read without following a link planted in its place (the
 * file sits in the run, where a host run's shell can reach), and laid out
 * for the console. Nothing is cut: every changed file, every violation, the
 * summary line whole. A file that is there and cannot be read is itself
 * something to say, not an absence.
 */
export async function readCustody(sandbox: string): Promise<CustodyView | null> {
  let text: string;
  try {
    const fh = await open(join(sandbox, "custody.json"), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try {
      if (!(await fh.stat()).isFile()) return null;
      text = await fh.readFile("utf8");
    } finally {
      await fh.close();
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    const why = code === "ELOOP" ? "custody.json is a link, not the file custody wrote; it was not followed" : `custody.json could not be read (${code ?? (err as Error).message})`;
    return { at: null, summary: why, verdict: "attention", problems: [why], evidence: null, sessions_not_files: [], trace: null, ledger: null, tool_outputs: null, vms: null, incomplete: null };
  }
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(text) as Record<string, unknown>;
    if (!raw || typeof raw !== "object") throw new Error("not an object");
  } catch {
    const why = "custody.json is not readable JSON";
    return { at: null, summary: why, verdict: "attention", problems: [why], evidence: null, sessions_not_files: [], trace: null, ledger: null, tool_outputs: null, vms: null, incomplete: null };
  }
  const problems: string[] = [];

  let evidence: CustodyView["evidence"] = null;
  const inputs = raw.inputs as Record<string, unknown> | null | undefined;
  if (inputs && typeof inputs === "object") {
    if (typeof inputs.unverifiable === "string") {
      evidence = { unverifiable: inputs.unverifiable };
      problems.push(`evidence unverifiable: ${inputs.unverifiable}`);
    } else {
      const skipped = stringList(inputs.skipped);
      evidence = {
        files: num(inputs.files),
        bytes: num(inputs.bytes),
        unchanged: inputs.unchanged === true,
        // A custody from before the field: complete when nothing was skipped.
        complete: typeof inputs.complete === "boolean" ? inputs.complete : skipped.length === 0,
        changed: stringList(inputs.changed),
        missing: stringList(inputs.missing),
        added: stringList(inputs.added),
        skipped,
        manifest_anchored: typeof inputs.manifest_anchored === "boolean" ? inputs.manifest_anchored : null,
      };
      if (evidence.changed.length || evidence.missing.length || evidence.added.length) problems.push(`evidence changed: ${evidence.changed.length} changed, ${evidence.missing.length} missing, ${evidence.added.length} added`);
      if (evidence.manifest_anchored === false) problems.push("the evidence manifest in the run is not the one the kickoff recorded");
      if (!evidence.complete || skipped.length) problems.push(`evidence not fully re-hashed: ${skipped.length} of ${evidence.files} not re-read before the deadline, which the verdict does not cover`);
    }
  }

  const notFiles = stringList((raw.sessions as { not_files?: unknown } | undefined)?.not_files);
  if (notFiles.length) problems.push(`${notFiles.length} name${notFiles.length === 1 ? "" : "s"} under the sessions not a file, sealed as nothing: ${notFiles.join(", ")}`);

  let toolOutputs: CustodyView["tool_outputs"] = null;
  const to = raw.tool_outputs as Record<string, unknown> | undefined;
  if (to && typeof to === "object") {
    toolOutputs = { referenced: num(to.referenced), verified: num(to.verified), missing: stringList(to.missing), mismatched: stringList(to.mismatched), refused: stringList(to.refused) };
    if (toolOutputs.missing.length || toolOutputs.mismatched.length || toolOutputs.refused.length) {
      problems.push(`kept outputs: ${toolOutputs.missing.length} missing, ${toolOutputs.mismatched.length} not matching the trace, ${toolOutputs.refused.length} refused`);
    }
  }

  let trace: CustodyView["trace"] = null;
  const tr = raw.trace as Record<string, unknown> | undefined;
  if (tr && typeof tr === "object") {
    const spilled = Array.isArray(tr.spilled) ? tr.spilled.reduce((n: number, s) => n + num((s as { lines?: unknown })?.lines), 0) : 0;
    const lost = Array.isArray(tr.gaps) ? tr.gaps.reduce((n: number, g) => n + num((g as { missing?: unknown })?.missing), 0) : 0;
    const refusedSpills = Array.isArray(tr.spilled)
      ? tr.spilled
          .filter((x): x is Record<string, unknown> => !!x && typeof x === "object" && typeof (x as { refused?: unknown }).refused === "string")
          .map((x) => ({ path: String(x.path ?? "?"), why: String(x.refused) }))
      : [];
    trace = { lines: num(tr.lines), intact: tr.intact === true, detail: typeof tr.detail === "string" ? tr.detail : "", unverified: num(tr.unverified), disputed: num(tr.disputed), spilled, lost, refused_spills: refusedSpills };
    if (!trace.lines) problems.push("no trace");
    else if (!trace.intact) problems.push(`trace chain not intact${trace.detail ? `: ${trace.detail}` : ""}`);
    if (lost) problems.push(`${lost} trace line${lost === 1 ? "" : "s"} lost (numbered, but in neither the chain nor a spill)`);
    for (const r of refusedSpills) problems.push(`spill not read: ${r.path} is ${r.why}`);
  }

  let ledger: CustodyView["ledger"] = null;
  const lg = raw.ledger as Record<string, unknown> | null | undefined;
  if (lg && typeof lg === "object") {
    ledger = {
      entries: num(lg.entries),
      chained: typeof lg.chained === "number" ? lg.chained : null,
      intact: lg.intact === true,
      detail: typeof lg.detail === "string" ? lg.detail : "",
      missing_from_ledger: stringList(lg.missing_from_ledger),
      not_on_trace: Array.isArray(lg.not_on_trace) ? lg.not_on_trace.filter((n): n is number => typeof n === "number") : [],
    };
    if (ledger.missing_from_ledger.length) problems.push(`${ledger.missing_from_ledger.length} ledger entr${ledger.missing_from_ledger.length === 1 ? "y" : "ies"} on the trace missing from the ledger (deleted)`);
    if (ledger.not_on_trace.length) problems.push(`${ledger.not_on_trace.length} ledger entr${ledger.not_on_trace.length === 1 ? "y" : "ies"} never on the trace, written without the tool (seq ${ledger.not_on_trace.join(", ")})`);
    // custody.ts says "broken" in the detail when the chain itself is; a
    // ledger that only differs from the trace is said above.
    if (!ledger.intact && (ledger.detail.startsWith("broken") || (!ledger.missing_from_ledger.length && !ledger.not_on_trace.length))) problems.push(`ledger chain broken${ledger.detail ? `: ${ledger.detail}` : ""}`);
  }

  let vms: CustodyView["vms"] = null;
  if (Array.isArray(raw.vms)) {
    vms = raw.vms
      .filter((v): v is Record<string, unknown> => !!v && typeof v === "object")
      .map((v) => {
        const snap = v.snapshot as { verified?: unknown; error?: unknown } | null | undefined;
        const outside = (v.installed_outside ?? {}) as { apt?: unknown; venv?: unknown; note?: unknown };
        const changed = v.runtime_changed as { from?: unknown; to?: unknown } | null | undefined;
        const image = typeof v.image === "string" ? v.image : null;
        const expected = typeof v.expected_image === "string" ? v.expected_image : null;
        return {
          agent: String(v.agent ?? "?"),
          record_sha256: typeof v.record_sha256 === "string" ? v.record_sha256 : null,
          stopped: v.stopped === true,
          kept: typeof v.kept === "string" ? v.kept : null,
          snapshot: !snap ? null : typeof snap.error === "string" ? `failed: ${snap.error}` : snap.verified === true ? "verified" : "not verified",
          image,
          expected_image: expected,
          image_differs: !!(image && expected && image !== expected),
          secret_violations: Array.isArray(v.secret_violations)
            ? v.secret_violations
                .filter((x): x is Record<string, unknown> => !!x && typeof x === "object")
                .map((x) => ({ at: String(x.at ?? ""), env: String(x.env ?? ""), host: String(x.host ?? ""), method: String(x.method ?? ""), path: String(x.path ?? ""), action: String(x.action ?? "") }))
            : [],
          installed_outside: [...stringList(outside.apt).map((p) => `apt ${p}`), ...stringList(outside.venv).map((p) => `venv ${p}`)],
          installed_note: typeof outside.note === "string" ? outside.note : null,
          runtime_changed: changed && typeof changed.from === "string" && typeof changed.to === "string" ? `${changed.from} → ${changed.to}` : null,
        };
      });
    const notAway = vms.filter((v) => !v.stopped || v.kept || v.snapshot?.startsWith("failed"));
    if (notAway.length) problems.push(`not put away: ${notAway.map((v) => v.agent).join(", ")}`);
    for (const v of vms) {
      if (v.image_differs) problems.push(`image digest differs: ${v.agent} booted ${v.image}, not ${v.expected_image}`);
      if (v.secret_violations.length) problems.push(`${v.agent}: ${v.secret_violations.length} secret placeholder${v.secret_violations.length === 1 ? "" : "s"} aimed at a host not its own, stopped by msb`);
      if (v.installed_outside.length) problems.push(`${v.agent}: installed outside the image: ${v.installed_outside.join(", ")}`);
      if (v.runtime_changed) problems.push(`${v.agent}: msb changed during the run, ${v.runtime_changed}`);
    }
  }

  const incomplete = typeof raw.incomplete === "string" && raw.incomplete ? raw.incomplete : null;
  if (incomplete) problems.push(`custody incomplete: ${incomplete}`);
  return {
    at: typeof raw.at === "string" ? raw.at : null,
    summary: typeof raw.summary === "string" ? raw.summary : "",
    verdict: problems.length ? "attention" : "clean",
    problems,
    evidence,
    sessions_not_files: notFiles,
    trace,
    ledger,
    tool_outputs: toolOutputs,
    vms,
    incomplete,
  };
}

/** The packs a run carried, joined with what each one holds on this host. */
export async function packViews(run: RegistryRun | null): Promise<PackView[]> {
  const listed = Array.isArray(run?.packs) ? run!.packs! : [];
  if (!listed.length) return [];
  const home = process.env.DFIRSWARM_HOME || join(process.env.HOME || "", ".dfirswarm");
  const out: PackView[] = [];
  for (const p of listed) {
    const dir = join(home, "packs", p.id);
    const view: PackView = {
      id: p.id, version: p.version, manifest_sha256: p.manifest_sha256,
      installed: false, name: p.id, description: "", skills: [], tools: [],
    };
    const manifest = await readFile(join(dir, "pack.json"), "utf8")
      .then((t) => JSON.parse(t) as Record<string, unknown>)
      .catch(() => null);
    if (manifest) {
      view.installed = true;
      if (typeof manifest.name === "string") view.name = manifest.name;
      if (typeof manifest.description === "string") view.description = manifest.description;
    }
    // The index is generated at seal time from every skill's own front matter,
    // so it is the pack's own statement of what it carries.
    const index = await readFile(join(dir, "skills", "INDEX.md"), "utf8").catch(() => "");
    for (const line of index.split("\n")) {
      const m = /^- `([^`]+)`\s+([^:]+):\s*(.*)$/.exec(line.trim());
      if (m) view.skills.push({ id: m[1], title: m[2].trim(), when: m[3].trim() });
    }
    const tools = await readdir(join(dir, "tools"), { withFileTypes: true }).catch(() => []);
    view.tools = tools.filter((d) => d.isDirectory()).map((d) => d.name).sort();
    out.push(view);
  }
  return out;
}

/** The ledger entries, oldest first, and whether the rendered file is there. */
export async function ledgerView(sandbox: string): Promise<LedgerView> {
  const entries = await readLedger(sandbox).catch(() => []);
  const rendered = await stat(join(sandbox, LEDGER_MD)).then((s) => s.isFile()).catch(() => false);
  return { entries, rendered };
}

/** inputs.json joined with the guard, violation and check lines from the trace. */
export async function inputsView(sandbox: string, events: readonly SwarmEvent[]): Promise<InputsView | null> {
  const manifest = await readInputsManifest(sandbox);
  if (!manifest) return null;
  const enforced: Record<string, string> = {};
  for (const e of events) {
    if (e.tool !== "inputs_guard") continue;
    const result = (e.result ?? {}) as { enforced?: unknown };
    if (typeof result.enforced === "string") enforced[e.agent] = result.enforced;
  }
  const checks = events.filter((e) => e.tool === "inputs_check");
  const last = checks.at(-1);
  const lastResult = (last?.result ?? {}) as {
    ok?: unknown;
    content_ok?: unknown;
    checked?: unknown;
    modified?: unknown;
    metadata?: unknown;
    missing?: unknown;
    added?: unknown;
  };
  const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  return {
    source: manifest.source,
    copied_at: manifest.copied_at,
    files: manifest.files,
    bytes: manifest.bytes,
    enforce: manifest.enforce,
    guard: manifest.guard,
    enforced,
    violations: events.filter((e) => e.tool === "inputs_violation"),
    check: last
      ? {
          ok: lastResult.ok === true,
          content_ok: lastResult.content_ok === undefined ? lastResult.ok === true : lastResult.content_ok === true,
          checked: Number(lastResult.checked) || 0,
          modified: strings(lastResult.modified),
          metadata: strings(lastResult.metadata),
          missing: strings(lastResult.missing),
          added: strings(lastResult.added),
          by: last.agent,
          at: last.ts,
        }
      : null,
  };
}

/** Manifests from tools/ joined with the calls the trace recorded under each name. */
export async function forgedToolRows(sandbox: string, events: readonly SwarmEvent[]): Promise<ForgedToolRow[]> {
  const manifests = await listForgedTools(sandbox).catch(() => [] as ForgedToolManifest[]);
  // One pass over the trace, grouped by tool, instead of one filter per manifest.
  const callsByTool = new Map<string, SwarmEvent[]>();
  for (const e of events) {
    if (!isRecord(e.result) || e.result.forged !== true) continue;
    const list = callsByTool.get(e.tool);
    if (list) list.push(e);
    else callsByTool.set(e.tool, [e]);
  }
  return manifests.map((m) => {
    const calls = callsByTool.get(m.name) ?? [];
    return {
      ...m,
      calls: calls.length,
      failures: calls.filter((e) => isRecord(e.result) && e.result.ok === false).length,
      users: [...new Set(calls.map((e) => e.agent))],
      last_used_at: calls.length ? calls[calls.length - 1].ts : null,
    };
  });
}

export type TraceQuery = {
  agent?: string;
  tool?: string;
  q?: string;
  limit?: number;
  order?: "asc" | "desc";
};

export type TracePage = {
  total: number;
  matched: number;
  events: SwarmEvent[];
  agents: string[];
  tools: string[];
  /** Lines and spend per agent over the whole trace, for the filter chips. */
  by_agent: Record<string, { events: number; spent_usd: number }>;
  /**
   * Lines per agent over the *filtered* set — who the matches belong to.
   *
   * `by_agent` deliberately counts the whole trace so the chips do not
   * flicker as a filter narrows. But a caller that asks "which agents
   * produced reasoning?" needs the other number, and answering it by
   * downloading every matching event is a megabyte of prose to count to
   * ten. With `limit=1` this field alone answers it.
   */
  matched_by_agent: Record<string, number>;
};

export async function queryTraces(sandbox: string, query: TraceQuery): Promise<TracePage> {
  const events = await readEvents(sandbox);
  const agents = [...new Set(events.map((e) => e.agent))].sort();
  const tools = [...new Set(events.map((e) => e.tool))].sort();
  const byAgent: TracePage["by_agent"] = {};
  for (const e of events) (byAgent[e.agent] ??= { events: 0, spent_usd: 0 }).events += 1;
  try {
    const budget = JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")) as { agents?: Record<string, { spent_usd?: number }> };
    for (const [id, slice] of Object.entries(budget.agents ?? {})) {
      if (byAgent[id]) byAgent[id].spent_usd = Number(slice?.spent_usd) || 0;
    }
  } catch {
    // no budget yet: chips show lines only
  }
  let out: readonly SwarmEvent[] = events;
  if (query.agent) out = out.filter((e) => e.agent === query.agent);
  if (query.tool) out = out.filter((e) => e.tool === query.tool);
  if (query.q) {
    const needle = query.q.toLowerCase();
    out = out.filter((e) => JSON.stringify(e).toLowerCase().includes(needle));
  }
  const matched = out.length;
  const matchedByAgent: Record<string, number> = {};
  for (const e of out) matchedByAgent[e.agent] = (matchedByAgent[e.agent] ?? 0) + 1;
  const limit = Math.min(Math.max(1, query.limit ?? 500), 5000);
  // `slice` copies, so the shared cached array is never reversed in place.
  const page = out.slice(-limit);
  return {
    total: events.length,
    matched,
    events: query.order === "desc" ? page.reverse() : page,
    agents,
    tools,
    by_agent: byAgent,
    matched_by_agent: matchedByAgent,
  };
}

/** Directories under tools/ that carry a manifest: the ones `swarm.sh tools --save` would keep. */
export async function countForgedTools(sandbox: string): Promise<number> {
  const dir = join(sandbox, "tools");
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  let n = 0;
  for (const e of entries) if (e.isDirectory() && existsSync(join(dir, e.name, "manifest.json"))) n += 1;
  return n;
}
