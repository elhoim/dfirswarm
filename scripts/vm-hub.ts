#!/usr/bin/env node
/**
 * The host end of every agent's VM: the board's only writer, the trace's
 * door, the harness's voice, and the stop that does not depend on the agents.
 *
 * Between two microVMs a shared directory keeps none of the promises the
 * board is built on (spikes/microvm-smoke/shared-fs.sh measured it), so an
 * agent in a VM does not write the board. Its extension sends the call here
 * (extensions/board.ts), and this process runs the same `protocol.ts` against
 * the same files on the host, where there is one kernel and one writer.
 *
 * **Who is asking is the channel, not the message.** Each agent's VM has one
 * vsock port, and msb connects it to exactly one Unix socket here,
 * `<dir>/<agent>.sock`. A request that arrives on it is that agent's, and
 * every function that acts as someone is given that agent whatever the
 * request says. There is no token to steal: another VM cannot open this
 * agent's socket, and nothing in a request can change which socket it came
 * in on.
 *
 * **What an agent may ask for is an agent's business.** The agent table
 * holds the board functions a tool of the agent's calls. The harness's own
 * functions — the stop clock, the harness stop — are not in it: the
 * extension that used to call them runs inside the VM, where anything can
 * call anything, so in a VM they are this process's alone. Every path an
 * agent sends is resolved on the host without following a link the agent
 * planted (protocol.ts `openSandboxFile`), the sentinel is written only when
 * the operator's finish line passes here on the host, and a seat's spend
 * report may only grow.
 *
 * One socket carries four things, told apart by shape:
 *   - a trace line (an object with `tool` and `ts`), forwarded to the trace
 *     collector with this agent's token added, so the collector's own
 *     attribution, chain and anchor apply unchanged;
 *   - a nudge (`kind` and `peer`), the nudge broker's request, delivered here
 *     to the peer's link instead of through Herdr;
 *   - a board call (`t: "rpc"`);
 *   - the agent's link (`t: "hello"`), held open: the harness's prompts go
 *     down it, and the agent's working/idle state comes up it.
 *
 * The admin socket, `<dir>/admin.sock`, is for the harness's own scripts on
 * the host (idle-nudge.sh, await-done.sh, swarm.sh): prompt an agent, read
 * who is working, tell the hub which Herdr pane is whose.
 *
 * And the stop. The extension in each VM steers its own seat as it does on
 * the host; this process enforces the swarm's wall clock and caps from
 * outside, where an agent cannot reach, on a clock of its own: past the
 * limit plus the grace period it writes the sentinel itself, and once the
 * sentinel has stood for the grace period it puts the VMs away, records the
 * run as finished and takes custody.
 *
 *   node --experimental-strip-types scripts/vm-hub.ts <sandbox> --dir DIR
 *        [--run ID] [--vm-cli PATH] [--registry FILE] [--settle-ms N]
 *        [--forging] [--no-snapshot] [--quiet]
 *   node --experimental-strip-types scripts/vm-hub.ts --resume DIR
 *
 * One line of JSON on stdin: `{agents: [...], tokens: {<agent>: <token>},
 * collector: "<socket>"}`. Tokens reach this process the way they reach the
 * collector, on stdin, never argv. What was given is kept in the hub's own
 * directory (0700, on the host, in no VM) so that `--resume` can bring the
 * hub back after a crash with the same tokens and the same clock.
 */
import { execFile } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { stat } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as T from "../extensions/toolchain.ts";
import { claimHolds, messageFor, resolvePeer } from "./nudge-broker.mjs";

/** A board call's reply can be large (an inbox page, the ledger); a request cannot. */
const MAX_REQUEST_BYTES = 64_000_000;
/** How long a quiet non-link connection is kept. `wait` is a long call, not a quiet one. */
const IDLE_MS = 30_000;
/** How often the stop is checked from out here. */
const BACKSTOP_INTERVAL_MS = 15_000;
/** Lines a connection may have waiting before it is paused; resumed below the low mark. */
const PENDING_HIGH = 200;
const PENDING_LOW = 50;
/**
 * Board calls one agent may have running at once, and how many more may
 * wait for a turn. A burst past the first number queues (a VM recording
 * forty findings at once is a burst, not a flood); one past both is refused.
 */
const IN_FLIGHT_MAX = 64;
const QUEUE_MAX = 192;
/**
 * How long a file must have been left alone before a claim on it passes to
 * an agent in another VM. virtio-fs caches a file's size and existence for
 * five seconds in each guest (passthroughfs, CachePolicy::Auto, not
 * configurable in msb 0.7.2), so an agent that takes a file straight from a
 * peer could append at a size that is five seconds old and overwrite the
 * peer's last lines. Past this window every cached view of the file is newer
 * than the peer's last write.
 */
export const SETTLE_MS_DEFAULT = 6_000;

/** Calls the hub records on the trace when they succeed; every refusal is recorded. */
const AUDITED = new Set(["markDone", "forgeTool", "restoreFileVersion", "claimName", "threadOpen", "publishFile"]);

export type HubConfig = {
  sandbox: string;
  dir: string;
  agents: string[];
  tokens: Record<string, string>;
  collector: string;
  run?: string;
  vmCli?: string;
  /** The operator's registry, for the run's state once the hub has finished it. */
  registry?: string;
  settleMs?: number;
  quiet?: boolean;
  /** Tests turn the backstop off and drive it by hand. */
  backstop?: boolean;
  herdrBin?: string;
  /** Whether make_tool is allowed in this run: the hub refuses a forge otherwise. */
  forging?: boolean;
  /** Whether each VM's disk is kept when the hub puts the VMs away. */
  snapshot?: boolean;
};

type AgentState = { state: string; detail?: string; since: string; connected: boolean };

/** What survives a restart: the swarm's stop clock and what the hub already said. */
type HubState = {
  stop_steer?: { reason: P.StopReason; at: number } | null;
  done_since?: number;
  finished?: boolean;
  told?: string[];
  seat_steer?: Record<string, number>;
};

/**
 * A Unix socket path the kernel will take: 104 bytes on macOS. The collector
 * binds inside the sandbox's traces/, which under a long home is past that
 * (measured: every line of a run went to the spill file), so a long path is
 * dialled relative to this process's directory, which main() sets to it.
 */
function reachable(path: string): string {
  if (Buffer.byteLength(path) <= 100) return path;
  const rel = relative(process.cwd(), path);
  return rel && rel.length < path.length ? rel : path;
}

/** `null` in a JSON array is how `undefined` travels; a default parameter needs it back. */
function revive(args: unknown): unknown[] {
  return Array.isArray(args) ? args.map((a) => (a === null ? undefined : a)) : [];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function finiteNonNegative(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n >= 0 ? n : Number.NaN;
}

/**
 * One connection to the collector, kept, with the lines in flight answered
 * in order: the collector writes `{"ok":true}` per line, on the same socket.
 * A line that is not answered in time fails, and the connection is dropped
 * so the next line is not answered with this one's reply.
 */
class CollectorLink {
  private socket: Socket | null = null;
  private waiting: Array<{ done: (ok: boolean) => void; timer: ReturnType<typeof setTimeout> }> = [];
  private buffer = "";
  private readonly path: string;
  private readonly timeoutMs: number;
  constructor(path: string, timeoutMs = 5000) {
    this.path = path;
    this.timeoutMs = timeoutMs;
  }

  private dial(): Socket {
    const s = connect(reachable(this.path));
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      this.buffer += chunk;
      let cut;
      while ((cut = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, cut);
        this.buffer = this.buffer.slice(cut + 1);
        const head = this.waiting.shift();
        if (!head) continue;
        clearTimeout(head.timer);
        let ok = false;
        try {
          ok = JSON.parse(line)?.ok === true;
        } catch {
          ok = false;
        }
        head.done(ok);
      }
    });
    const drop = () => {
      if (this.socket === s) this.socket = null;
      this.buffer = "";
      for (const w of this.waiting.splice(0)) {
        clearTimeout(w.timer);
        w.done(false);
      }
    };
    s.on("error", drop);
    s.on("close", drop);
    return s;
  }

  send(line: string): Promise<boolean> {
    return new Promise((done) => {
      if (!this.socket || this.socket.destroyed) this.socket = this.dial();
      const s = this.socket;
      const entry = {
        done,
        timer: setTimeout(() => {
          const i = this.waiting.indexOf(entry);
          if (i >= 0) this.waiting.splice(i, 1);
          done(false);
          s.destroy();
        }, this.timeoutMs),
      };
      this.waiting.push(entry);
      s.write(line, (err) => {
        if (err) {
          const i = this.waiting.indexOf(entry);
          if (i >= 0) this.waiting.splice(i, 1);
          clearTimeout(entry.timer);
          done(false);
        }
      });
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }
}

/**
 * Every board function an agent in a VM may call, and what it is given.
 * `who` is the agent the channel belongs to; the first argument the agent
 * sent (its sandbox path, or its context) is never used — the hub's own
 * sandbox and the channel's agent replace it. A test holds this table to
 * REMOTE_FUNCTIONS in extensions/board.ts.
 */
export function boardTable(hub: {
  sandbox: string;
  settle: (who: string, rawPath: string) => Promise<void>;
  wrote: (who: string, rawPath: string) => void;
  forging?: boolean;
}) {
  const S = hub.sandbox;
  const as = (who: string): P.SwarmContext => ({ sandboxRoot: S, agentId: who });
  type Call = (who: string, a: unknown[], signal: AbortSignal) => Promise<unknown>;
  const table: Record<string, Call> = {
    applySessionUsage: async (who, a) => {
      // A seat's report of its own spend may only grow: a VM that reported
      // less than before, or a number that is not one, is refused and the
      // row it had stays. (What it reports at all is still its own word;
      // docs/adr/0005 says so, and the wall clock is the brake that is not.)
      const slice = isObject(a[2]) ? (a[2] as Record<string, unknown>) : null;
      if (!slice) throw new Error("usage must be an object");
      const budget = await P.readBudget(S).catch(() => null);
      const before = budget?.agents[who];
      for (const key of ["spent_usd", "tokens", "calls", "input", "output", "cache_read", "cache_write"] as const) {
        const value = finiteNonNegative(slice[key] ?? 0);
        if (Number.isNaN(value)) throw new Error(`usage.${key} is not a non-negative number`);
        const was = before ? Number(before[key] ?? 0) : 0;
        if (value + 1e-9 < was) throw new Error(`usage went backwards: ${key} ${value} < ${was}; a seat's spend only grows`);
      }
      for (const key of ["context_tokens", "context_window", "context_ceiling", "compactions", "compaction_tokens", "compaction_usd", "handoffs"]) {
        if (key in slice && slice[key] !== undefined && Number.isNaN(finiteNonNegative(slice[key]))) throw new Error(`usage.${key} is not a non-negative number`);
      }
      return P.applySessionUsage(S, who, slice as never);
    },
    claimFile: async (who, a) => {
      await hub.settle(who, String(a[1] ?? ""));
      return P.claimFile(as(who), String(a[1] ?? ""), (a[2] as P.ClaimOptions) ?? {});
    },
    claimName: (who, a) => P.claimName(S, who, String(a[2] ?? ""), a[3] as string | undefined),
    correctionsAfter: (who, a) => P.correctionsAfter(S, String(a[1] ?? ""), who),
    fileDiff: (_who, a) => P.fileDiff(S, String(a[1] ?? ""), a[2] as never, a[3] as never),
    forgeTool: (who, a) => {
      if (!hub.forging) throw new Error("tool forging is off for this run (--allow-tool-forging); the hub does not forge");
      return P.forgeTool(as(who), a[1]);
    },
    guardWrite: (who, a) => P.guardWrite(as(who), String(a[1] ?? "")),
    heldBy: (who, a) => P.heldBy(as(who), String(a[1] ?? "")),
    listClaims: () => P.listClaims(S),
    listFileHistory: (_who, a) => P.listFileHistory(S, String(a[1] ?? "")),
    listForgedTools: () => P.listForgedTools(S),
    listLedger: (_who, a) => P.listLedger(S, (a[1] as { kind?: string; limit?: number }) ?? {}),
    listTeam: (who) => P.listTeam(as(who)),
    markDone: async (who, a) => {
      // The sentinel ends every seat, so the finish line is run here, on the
      // host, by the harness, before it is written: what the agent's own
      // extension ran inside its VM is that VM's word. An abandoned run says
      // so in its reason and is not held to the checks; a seat leaving on its
      // own cap writes no sentinel and is not either.
      const args = (a[1] as { reason?: string; outputFile?: string; createSentinel?: boolean }) ?? {};
      const reason = String(args.reason ?? "");
      const endsSwarm = args.createSentinel !== false && reason !== "agent_cap" && !reason.startsWith("ABANDONED: ");
      if (endsSwarm && !(await P.swarmDoneExists(S))) {
        const run = await P.runFinishLine(S).catch(() => null);
        const verdict = P.finishLineVerdict(run, false);
        if (!verdict.proceed) throw new Error(`the harness re-ran the finish line on the host and it is not met: ${verdict.reason}`);
      }
      return P.markDone(as(who), args as never);
    },
    nameOf: (_who, a) => P.nameOf(S, String(a[1] ?? "")),
    postMessage: (who, a) => {
      // An agent's post is its own; `via` is the hub's to set.
      const { via: _via, ...args } = (a[1] as Record<string, unknown>) ?? {};
      return P.postMessage(as(who), args as never);
    },
    readBudget: () => P.readBudget(S),
    readBudgetStatus: (who) => P.readBudgetStatus(as(who)),
    readInbox: (who, a) => P.readInbox(as(who), (a[1] as never) ?? {}),
    readNames: () => P.readNames(S),
    recordEntry: (who, a) => P.recordEntry(as(who), a[1] as never),
    recordFileVersion: async (who, a) => {
      hub.wrote(who, String(a[1] ?? ""));
      return P.recordFileVersion(S, String(a[1] ?? ""), who);
    },
    releaseAllOwned: (who) => P.releaseAllOwned(as(who)),
    releaseFile: (who, a) => P.releaseFile(as(who), String(a[1] ?? "")),
    restoreFileVersion: async (who, a) => {
      hub.wrote(who, String(a[1] ?? ""));
      return P.restoreFileVersion(as(who), String(a[1] ?? ""), Number(a[2]));
    },
    swarmDoneExists: () => P.swarmDoneExists(S),
    systemPost: (who, a) => {
      // The harness's voice, sent from inside a VM: said by the harness code
      // in that agent's VM, and the post says which one.
      const args = (a[1] as Record<string, unknown>) ?? {};
      return P.systemPost(S, { ...(args as { tag: string; body: string }), via: who });
    },
    threadJoin: (who, a) => P.threadJoin(as(who), String(a[1] ?? "")),
    threadOpen: (who, a) => P.threadOpen(as(who), a[1] as never),
    updateToolchainRecord: (who, a) => T.updateToolchainRecord(S, isObject(a[1]) ? { agent: who, inventory: a[1] as never } : undefined),
    waitForSwarmChange: (who, a, signal) =>
      P.waitForSwarmChange(as(who), { ...((a[1] as { seconds?: number; pollMs?: number }) ?? {}), signal }),
  };
  return table;
}

export class Hub {
  readonly cfg: HubConfig;
  readonly roster: string[];
  private servers: Server[] = [];
  /** Every open connection, so stopping does not wait on a held one. */
  private sockets = new Set<Socket>();
  private links = new Map<string, Socket>();
  private queued = new Map<string, { text: string; deliver?: string; kind?: string }[]>();
  private status = new Map<string, AgentState>();
  private panes = new Map<string, string>();
  private told = new Set<string>();
  private lastWrite = new Map<string, { who: string; at: number }>();
  private inFlight = new Map<string, number>();
  private queue = new Map<string, Array<() => void>>();
  private table: ReturnType<typeof boardTable>;
  private backstopTimer: ReturnType<typeof setInterval> | null = null;
  private collector: CollectorLink;
  /** The swarm's stop clock, this process's own: no request can move it. */
  private stopSteer: { reason: P.StopReason; at: number } | null = null;
  /** Per seat: when it was told it is over its own cap. */
  private seatSteer = new Map<string, number>();
  private doneSince = 0;
  private finished = false;
  private finishing: Promise<void> | null = null;

  constructor(cfg: HubConfig) {
    this.cfg = { ...cfg, sandbox: resolve(cfg.sandbox) };
    this.roster = [...cfg.agents];
    for (const id of this.roster) this.status.set(id, { state: "unknown", since: new Date().toISOString(), connected: false });
    this.table = boardTable({
      sandbox: this.cfg.sandbox,
      settle: (who, raw) => this.settle(who, raw),
      wrote: (who, raw) => this.noteWrite(who, raw),
      forging: cfg.forging === true,
    });
    this.collector = new CollectorLink(this.cfg.collector);
  }

  private log(line: string): void {
    if (!this.cfg.quiet) console.log(`vm-hub: ${line}`);
  }

  socketFor(agent: string): string {
    return join(this.cfg.dir, `${agent}.sock`);
  }

  adminSocket(): string {
    return join(this.cfg.dir, "admin.sock");
  }

  statusFile(): string {
    return join(this.cfg.dir, "status.json");
  }

  /** The hub's own trace lines that the collector did not take: on the host, in no VM. */
  spillFile(): string {
    return join(this.cfg.dir, "hub-spill.jsonl");
  }

  private stateFile(): string {
    return join(this.cfg.dir, "hub-state.json");
  }

  async start(): Promise<void> {
    mkdirSync(this.cfg.dir, { recursive: true, mode: 0o700 });
    this.loadState();
    for (const agent of this.roster) {
      await this.listen(this.socketFor(agent), (socket) => this.serveAgent(agent, socket));
    }
    await this.listen(this.adminSocket(), (socket) => this.serveAdmin(socket));
    this.writeStatus();
    if (this.cfg.backstop !== false) {
      this.backstopTimer = setInterval(() => void this.backstop().catch(() => undefined), BACKSTOP_INTERVAL_MS);
    }
  }

  private loadState(): void {
    try {
      const raw = JSON.parse(readFileSync(this.stateFile(), "utf8")) as HubState;
      this.stopSteer = raw.stop_steer ?? null;
      this.doneSince = raw.done_since ?? 0;
      this.finished = raw.finished === true;
      for (const t of raw.told ?? []) this.told.add(t);
      for (const [agent, at] of Object.entries(raw.seat_steer ?? {})) this.seatSteer.set(agent, at);
    } catch {
      // a first start
    }
  }

  private saveState(): void {
    const state: HubState = {
      stop_steer: this.stopSteer,
      done_since: this.doneSince,
      finished: this.finished,
      told: [...this.told],
      seat_steer: Object.fromEntries(this.seatSteer),
    };
    try {
      const tmp = `${this.stateFile()}.tmp`;
      writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
      renameSync(tmp, this.stateFile());
    } catch {
      // the state is also in memory; a restart without it starts the clock again
    }
  }

  private listen(path: string, onSocket: (socket: Socket) => void): Promise<void> {
    return new Promise((resolveListen, reject) => {
      try {
        if (existsSync(path)) unlinkSync(path);
      } catch {
        // the bind says whether it matters
      }
      const server = createServer((socket) => {
        this.sockets.add(socket);
        socket.once("close", () => this.sockets.delete(socket));
        onSocket(socket);
      });
      server.on("error", reject);
      server.listen(path, () => {
        try {
          chmodSync(path, 0o600);
        } catch {
          // a platform that does not honour it; the directory is 0700
        }
        this.servers.push(server);
        resolveListen();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.backstopTimer) clearInterval(this.backstopTimer);
    for (const link of this.links.values()) link.destroy();
    this.links.clear();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.collector.close();
    await Promise.all(this.servers.map((s) => new Promise((r) => s.close(() => r(undefined)))));
    this.servers = [];
  }

  /**
   * Line-at-a-time reader; `onLine` returns true to keep the connection for
   * more. A connection that sends faster than its lines are handled is paused
   * until the backlog drains: one VM in a loop must not grow this process
   * until it dies and takes every peer's board with it.
   */
  private lines(socket: Socket, onLine: (line: string) => Promise<boolean> | boolean, idle = true): void {
    let buffer = "";
    let busy = Promise.resolve(true);
    let pending = 0;
    let paused = false;
    socket.setEncoding("utf8");
    if (idle) socket.setTimeout(IDLE_MS, () => socket.destroy());
    socket.on("error", () => undefined);
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      if (buffer.length > MAX_REQUEST_BYTES) {
        buffer = "";
        socket.destroy();
        return;
      }
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        if (!line.trim()) continue;
        pending++;
        if (pending >= PENDING_HIGH && !paused) {
          paused = true;
          socket.pause();
        }
        busy = busy
          .then((more) => (more ? onLine(line) : false))
          .catch(() => false)
          .finally(() => {
            pending--;
            if (paused && pending <= PENDING_LOW) {
              paused = false;
              socket.resume();
            }
          });
      }
    });
  }

  private reply(socket: Socket, body: unknown, end: boolean): void {
    try {
      const text = `${JSON.stringify(body)}\n`;
      if (end) socket.end(text);
      else socket.write(text);
    } catch {
      // the caller hung up
    }
  }

  private serveAgent(agent: string, socket: Socket): void {
    // Calls in flight on this connection, so a cancel or a hang-up ends them.
    const running = new Map<number, AbortController>();
    socket.once("close", () => {
      for (const c of running.values()) c.abort();
      running.clear();
    });
    this.lines(socket, async (line) => {
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        this.reply(socket, { ok: false, error: "not json" }, true);
        return false;
      }
      if (!isObject(msg)) {
        this.reply(socket, { ok: false, error: "not an object" }, true);
        return false;
      }
      if (msg.t === "hello") {
        this.attachLink(agent, socket);
        return true;
      }
      if (msg.t === "state") {
        this.setState(agent, String(msg.state ?? "unknown"), typeof msg.detail === "string" ? msg.detail : undefined);
        return true;
      }
      if (msg.t === "rpc" && typeof msg.id === "number") {
        // Many calls on one held connection, each answered when it finishes:
        // a VM makes one connection for its board calls instead of one per
        // call, which under load the vsock path refused (measured: 20 of 80
        // concurrent one-shot calls never reached the host).
        socket.setTimeout(0);
        const id = msg.id;
        const controller = new AbortController();
        running.set(id, controller);
        void this.slot(agent).then(async (got) => {
          if (!got) {
            running.delete(id);
            this.reply(socket, { t: "rpc", id, ok: false, error: `too many board calls waiting (${IN_FLIGHT_MAX} running, ${QUEUE_MAX} queued); slow down` }, false);
            return;
          }
          try {
            const result = await this.call(agent, String(msg.fn ?? ""), msg.args, controller.signal);
            this.reply(socket, { t: "rpc", id, ...result }, false);
          } finally {
            running.delete(id);
            this.release(agent);
          }
        });
        return true;
      }
      if (msg.t === "cancel" && typeof msg.id === "number") {
        running.get(msg.id)?.abort();
        return true;
      }
      if (msg.t === "rpc") {
        const controller = new AbortController();
        socket.setTimeout(0);
        socket.once("close", () => controller.abort());
        const result = await this.call(agent, String(msg.fn ?? ""), msg.args, controller.signal);
        this.reply(socket, result, true);
        return false;
      }
      if (typeof msg.kind === "string" && "peer" in msg) {
        const result = await this.nudge(agent, msg.kind, msg.peer);
        this.reply(socket, result, true);
        return false;
      }
      if (typeof msg.tool === "string" && typeof msg.ts === "string") {
        socket.setTimeout(0);
        const ok = await this.forwardTrace(agent, msg);
        this.reply(socket, ok ? { ok: true } : { ok: false, error: "the collector did not take the line" }, false);
        return true;
      }
      this.reply(socket, { ok: false, error: "unknown message" }, true);
      return false;
    });
  }

  /** A turn to run a call as `agent`: now, later when one frees, or never. */
  private slot(agent: string): Promise<boolean> {
    const open = this.inFlight.get(agent) ?? 0;
    if (open < IN_FLIGHT_MAX) {
      this.inFlight.set(agent, open + 1);
      return Promise.resolve(true);
    }
    const waiting = this.queue.get(agent) ?? [];
    if (waiting.length >= QUEUE_MAX) return Promise.resolve(false);
    return new Promise((grant) => {
      waiting.push(() => grant(true));
      this.queue.set(agent, waiting);
    });
  }

  private release(agent: string): void {
    const next = this.queue.get(agent)?.shift();
    if (next) {
      next();
      return;
    }
    this.inFlight.set(agent, Math.max(0, (this.inFlight.get(agent) ?? 1) - 1));
  }

  /**
   * One board call, as `who`. Errors travel as the protocol's own message. A
   * seat the run has recorded dead is not served: its VM may still be up, and
   * a post from it would be a post from someone the record says is gone.
   * What the hub did as the harness's writer is on the trace: every call it
   * refused, and every one that changed what the run is (AUDITED).
   */
  async call(who: string, fn: string, args: unknown, signal: AbortSignal = new AbortController().signal): Promise<{ ok: boolean; result?: unknown; error?: string }> {
    const handler = Object.prototype.hasOwnProperty.call(this.table, fn) ? this.table[fn] : undefined;
    if (!handler) return { ok: false, error: `${fn} is not a board function` };
    if (who !== "system" && existsSync(P.agentDeadPath(this.cfg.sandbox, who))) {
      const error = `${who} is recorded dead (done/agents/${who}.dead); the hub does not serve it`;
      void this.audit(who, fn, { ok: false, error });
      return { ok: false, error };
    }
    try {
      const result = await handler(who, revive(args), signal);
      if (AUDITED.has(fn)) void this.audit(who, fn, { ok: true, ...summarize(fn, result) });
      return { ok: true, result: result === undefined ? null : result };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      void this.audit(who, fn, { ok: false, error });
      return { ok: false, error };
    }
  }

  private audit(who: string, fn: string, result: Record<string, unknown>): Promise<void> {
    return this.event("hub_call", { agent: who, fn }, result);
  }

  private noteWrite(who: string, raw: string): void {
    void P.realPathKey(this.cfg.sandbox, raw)
      .then((key) => this.lastWrite.set(key, { who, at: Date.now() }))
      .catch(() => undefined);
  }

  /**
   * Hold a claim until the file has been still for the settle window, when
   * the last hand on it was someone else's. The caller's own writes are
   * coherent in its own VM and never wait.
   */
  async settle(who: string, raw: string): Promise<void> {
    const window = this.cfg.settleMs ?? SETTLE_MS_DEFAULT;
    if (window <= 0 || !raw) return;
    let key: string;
    try {
      key = await P.realPathKey(this.cfg.sandbox, raw);
    } catch {
      return;
    }
    const mtime = await stat(join(this.cfg.sandbox, key)).then((s) => s.mtimeMs).catch(() => 0);
    const last = this.lastWrite.get(key);
    if (last?.who === who && (!mtime || mtime <= last.at + 1000)) return;
    const touched = Math.max(mtime, last && last.who !== who ? last.at : 0);
    if (!touched) return;
    const wait = touched + window - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, Math.min(wait, window)));
  }

  private forwardTrace(agent: string, record: Record<string, unknown>): Promise<boolean> {
    const { token: _t, gate: _g, ...rest } = record;
    const token = this.cfg.tokens[agent];
    const line = `${JSON.stringify(token ? { ...rest, token } : rest)}\n`;
    return this.sendToCollector(line);
  }

  sendToCollector(line: string): Promise<boolean> {
    if (!this.cfg.collector) return Promise.resolve(false);
    return this.collector.send(line);
  }

  /**
   * The hub's own lines, as the harness (`system`). What the collector does
   * not take is kept in the hub's directory, on the host, where custody
   * counts it: the record that the harness stopped a run must not depend on
   * the collector being up at that moment.
   */
  async event(tool: string, args: Record<string, unknown>, result: Record<string, unknown>): Promise<void> {
    const record = { ts: new Date().toISOString(), agent: "system", tool, args, result };
    const token = this.cfg.tokens.system;
    const line = `${JSON.stringify(token ? { ...record, token } : record)}\n`;
    const ok = await this.sendToCollector(line);
    if (!ok) {
      try {
        appendFileSync(this.spillFile(), `${JSON.stringify(record)}\n`, { mode: 0o600 });
      } catch {
        this.log(`spill failed: ${tool}`);
      }
    }
  }

  private attachLink(agent: string, socket: Socket): void {
    const previous = this.links.get(agent);
    if (previous && previous !== socket) previous.destroy();
    this.links.set(agent, socket);
    socket.setTimeout(0);
    socket.setKeepAlive(true);
    const st = this.status.get(agent);
    if (st) st.connected = true;
    socket.once("close", () => {
      if (this.links.get(agent) === socket) {
        this.links.delete(agent);
        const now = this.status.get(agent);
        if (now) {
          now.connected = false;
          // A seat whose link went down mid-turn is not working, whatever it
          // last said: a crashed VM stayed "working" on the record, and the
          // watchdogs that ask before nudging or reaping left it alone.
          if (now.state === "working" || now.state === "blocked") {
            now.state = "gone";
            now.detail = "link lost";
            now.since = new Date().toISOString();
          }
        }
        this.writeStatus();
        void this.event("hub_link", { agent }, { up: false });
      }
    });
    this.writeStatus();
    const pending = this.queued.get(agent) ?? [];
    this.queued.delete(agent);
    for (const p of pending) this.reply(socket, { t: "prompt", ...p }, false);
    this.log(`${agent}: link up`);
    void this.event("hub_link", { agent }, { up: true });
  }

  /**
   * Put words in front of an agent: they arrive as a user message through
   * the extension's `sendUserMessage`, which starts a turn when the agent is
   * idle. Queued, and delivered on the next hello, only when asked to be.
   */
  prompt(agent: string, text: string, options: { deliver?: "steer" | "followUp"; kind?: string; queue?: boolean } = {}): boolean {
    const link = this.links.get(agent);
    const message = { text, ...(options.deliver ? { deliver: options.deliver } : {}), ...(options.kind ? { kind: options.kind } : {}) };
    if (link && !link.destroyed) {
      this.reply(link, { t: "prompt", ...message }, false);
      return true;
    }
    if (options.queue) {
      const list = this.queued.get(agent) ?? [];
      list.push(message);
      this.queued.set(agent, list);
    }
    return false;
  }

  /** The nudge broker's request, answered here: same kinds, same words, same checks. */
  async nudge(from: string, kind: unknown, peer: unknown): Promise<{ ok: boolean; error?: string; repeat?: boolean }> {
    if (typeof kind !== "string" || typeof peer !== "string") return { ok: false, error: "kind and peer are names" };
    const message = messageFor(kind) as string;
    if (!message) return { ok: false, error: "unknown kind" };
    if (!claimHolds(this.cfg.sandbox, kind)) return { ok: false, error: "the run does not say that" };
    const check = resolvePeer(this.roster, peer, from) as { ok: boolean; error?: string };
    if (!check.ok) return { ok: false, error: check.error };
    const once = `${String(kind)}:${String(peer)}`;
    if (this.told.has(once)) return { ok: true, repeat: true };
    this.told.add(once);
    const ok = this.prompt(String(peer), message, { deliver: "steer", kind: String(kind) });
    if (!ok) this.told.delete(once);
    this.saveState();
    return { ok };
  }

  setState(agent: string, state: string, detail?: string): void {
    const st = this.status.get(agent);
    if (!st) return;
    if (st.state !== state) st.since = new Date().toISOString();
    st.state = state;
    st.detail = detail;
    this.writeStatus();
    const pane = this.panes.get(agent);
    if (pane && ["idle", "working", "blocked", "unknown"].includes(state)) {
      const args = ["pane", "report-agent", pane, "--source", "dfirswarm-vm", "--agent", "pi", "--state", state];
      if (detail) args.push("--message", detail);
      execFile(this.cfg.herdrBin || process.env.HERDR_BIN || "herdr", args, { timeout: 5000 }, () => undefined);
    }
  }

  statusSnapshot(): Record<string, AgentState> {
    return Object.fromEntries(this.status);
  }

  private writeStatus(): void {
    try {
      const tmp = `${this.statusFile()}.tmp`;
      writeFileSync(tmp, `${JSON.stringify({ at: new Date().toISOString(), agents: this.statusSnapshot(), finished: this.finished }, null, 2)}\n`);
      renameSync(tmp, this.statusFile());
    } catch {
      // the admin socket answers the same question
    }
  }

  private serveAdmin(socket: Socket): void {
    this.lines(socket, async (line) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line);
      } catch {
        this.reply(socket, { ok: false, error: "not json" }, true);
        return false;
      }
      switch (msg.op) {
        case "prompt": {
          const agent = String(msg.agent ?? "");
          if (!this.roster.includes(agent)) {
            this.reply(socket, { ok: false, error: "not in this run" }, true);
            return false;
          }
          const delivered = this.prompt(agent, String(msg.text ?? ""), {
            deliver: msg.deliver === "steer" ? "steer" : "followUp",
            kind: typeof msg.kind === "string" ? msg.kind : undefined,
            queue: msg.queue === true,
          });
          this.reply(socket, { ok: delivered, delivered }, true);
          return false;
        }
        case "status":
          this.reply(socket, { ok: true, agents: this.statusSnapshot(), finished: this.finished }, true);
          return false;
        case "panes":
          if (isObject(msg.panes)) {
            for (const [agent, pane] of Object.entries(msg.panes)) {
              if (this.roster.includes(agent) && typeof pane === "string") this.panes.set(agent, pane);
            }
          }
          this.reply(socket, { ok: true }, true);
          return false;
        case "call": {
          // The harness's own board calls from the host, as `system`: the
          // admin socket is the harness's, and it does not act as a seat.
          const result = await this.call("system", String(msg.fn ?? ""), msg.args);
          this.reply(socket, result, true);
          return false;
        }
        case "shutdown":
          this.reply(socket, { ok: true }, true);
          setTimeout(() => void this.stop().then(() => process.exit(0)), 50);
          return false;
        default:
          this.reply(socket, { ok: false, error: "unknown op" }, true);
          return false;
      }
    });
  }

  /**
   * The stop, enforced from outside every VM. The extensions steer and stop
   * as they do on the host; this is what happens when they cannot — a VM
   * wedged in a long command, an agent that never ends a turn. The grace
   * period is measured on this process's clock: the marker in budget.json is
   * for the record, not the decision.
   */
  async backstop(now = Date.now()): Promise<void> {
    const S = this.cfg.sandbox;
    if (!existsSync(S)) {
      await this.stop();
      process.exit(0);
    }
    const done = await P.swarmDoneExists(S);
    if (!done) {
      const budget = await P.readBudget(S).catch(() => null);
      if (!budget) return;
      await this.seatBackstop(budget, now);
      const pressure = P.budgetPressure(budget, now);
      if (!pressure.reason) {
        if (this.stopSteer) {
          // Back under both limits (the operator raised the cap): a later
          // breach gets a fresh steer and a fresh grace period.
          this.stopSteer = null;
          await P.clearStopSteer(S).catch(() => undefined);
          this.saveState();
        }
        return;
      }
      if (!this.stopSteer) {
        this.stopSteer = { reason: pressure.reason, at: now };
        this.saveState();
        await P.markStopSteer(S, pressure.reason).catch(() => undefined);
        const text =
          pressure.reason === "cap"
            ? P.CAP_STEER
            : `Swarm wall clock hit (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes). Call done with reason cannot_complete and stop. Do not start new work.`;
        for (const agent of this.roster) this.prompt(agent, text, { deliver: "steer", kind: "stop_steer" });
        await this.event(pressure.reason === "cap" ? "cap_steer" : "wall_steer", { via: "hub", reason: pressure.reason }, { ok: true });
      }
      if (now - this.stopSteer.at < P.STOP_GRACE_MS) return;
      const stop = await P.harnessStop(S, pressure.reason, `The hub stopped the swarm: ${pressure.reason} passed and the agents did not stop within the grace period.`, { verify: true });
      if (stop.created) {
        await this.event("harness_stop", { via: "hub", reason: pressure.reason }, { created_sentinel: true });
        await P.systemPost(S, { tag: "stop", body: `Harness wrote done/SWARM_DONE (reason ${pressure.reason}). Call done and stop.` }).catch(() => undefined);
      }
      return;
    }
    if (!this.doneSince) {
      this.doneSince = now;
      this.saveState();
      for (const agent of this.roster) {
        if (existsSync(P.agentDonePath(S, agent)) || existsSync(P.agentDeadPath(S, agent))) continue;
        await this.nudge("", "swarm_done", agent);
      }
      return;
    }
    const allOut = this.roster.every((a) => existsSync(P.agentDonePath(S, a)) || existsSync(P.agentDeadPath(S, a)));
    if (this.finished || (!allOut && now - this.doneSince < P.STOP_GRACE_MS)) return;
    this.finished = true;
    this.saveState();
    this.writeStatus();
    this.finishing = this.finishVms(allOut);
    await this.finishing;
  }

  /**
   * A seat over its own cap, or over its model's: told, and a grace period
   * later put away by the hub — its VM stopped and the seat recorded as done
   * on its own cap, the way its extension would have done from inside.
   */
  private async seatBackstop(budget: P.BudgetRecord, now: number): Promise<void> {
    const S = this.cfg.sandbox;
    for (const agent of this.roster) {
      if (existsSync(P.agentDonePath(S, agent)) || existsSync(P.agentDeadPath(S, agent))) continue;
      const mine = P.agentPressure(budget, agent);
      const group = P.modelPressure(budget, budget.agents[agent]?.model);
      if (!mine.over && !group.over) {
        if (this.seatSteer.delete(agent)) this.saveState();
        continue;
      }
      const told = this.seatSteer.get(agent);
      if (!told) {
        this.seatSteer.set(agent, now);
        this.saveState();
        const text = mine.over
          ? `You have reached your own cap ($${mine.spent_usd.toFixed(2)} of $${mine.cap_usd}). Post your findings to the board now and call done with reason agent_cap. The swarm continues without you.`
          : `Your model has spent its ceiling across every seat running it. Post your findings to the board now and call done with reason agent_cap. The swarm continues without you.`;
        this.prompt(agent, text, { deliver: "steer", kind: "agent_cap_steer" });
        await this.event("agent_cap_steer", { via: "hub", agent }, { ok: true });
        continue;
      }
      if (now - told < P.STOP_GRACE_MS) continue;
      await P.markDone({ sandboxRoot: S, agentId: agent }, { reason: "agent_cap", outputFile: "", createSentinel: false }).catch(() => undefined);
      await this.event("agent_cap_stop", { via: "hub", agent }, { ok: true });
      this.seatSteer.delete(agent);
      this.saveState();
      await this.finishOne(agent);
    }
  }

  private vmCliArgs(extra: string[]): string[] {
    const args = ["--experimental-strip-types", "--no-warnings", this.cfg.vmCli as string, "finish", "--run", this.cfg.run as string, "--sandbox", this.cfg.sandbox, ...extra];
    if (this.cfg.snapshot === false) args.push("--no-snapshot");
    return args;
  }

  private runVmCli(args: string[], timeoutMs: number): Promise<{ ok: boolean; out: string }> {
    return new Promise((done) => {
      execFile(process.execPath, args, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
        const out = `${String(stdout).trim()} ${String(stderr).trim()}`.trim();
        done({ ok: !err, out: err ? `${err.message} ${out}`.trim() : out });
      });
    });
  }

  private async finishOne(agent: string): Promise<void> {
    if (!this.cfg.vmCli || !this.cfg.run) return;
    const r = await this.runVmCli(this.vmCliArgs(["--agent", agent]), 20 * 60_000);
    this.log(`finish ${agent}: ${r.ok ? "ok" : "failed"} ${r.out}`);
    await this.event("vm_finish", { via: "hub", agent }, { ok: r.ok, ...(r.ok ? {} : { error: r.out }) });
  }

  /**
   * Put this run's VMs away, through the VM manager, once; then say on the
   * record what happened, not what was about to. Each VM gets its own time,
   * the registry learns the run is finished, and custody is taken on the
   * host, so a run the hub ended does not wait for an operator's `stop` to
   * become a record.
   */
  private async finishVms(allOut: boolean): Promise<void> {
    if (!this.cfg.vmCli || !this.cfg.run) return;
    const r = await this.runVmCli(this.vmCliArgs([]), (this.roster.length + 1) * 20 * 60_000);
    this.log(`finish: ${r.ok ? "ok" : "failed"} ${r.out}`);
    await this.event("vm_finish", { via: "hub", all_out: allOut }, { ok: r.ok, ...(r.ok ? {} : { error: r.out }) });
    if (this.cfg.registry) await updateRegistryState(this.cfg.registry, this.cfg.run, r.ok ? "finished" : "finish_failed").catch((err: Error) => this.log(`registry: ${err.message}`));
    const custody = join(dirname(this.cfg.vmCli), "custody.ts");
    if (existsSync(custody)) {
      const c = await new Promise<{ ok: boolean; out: string }>((done) => {
        execFile(process.execPath, ["--experimental-strip-types", "--no-warnings", custody, this.cfg.sandbox], { timeout: 6 * 60 * 60_000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
          done({ ok: !err, out: `${String(stdout).trim()} ${String(stderr).trim()}`.trim() });
        });
      });
      this.log(`custody: ${c.ok ? "ok" : "failed"} ${c.out}`);
      await this.event("custody", { via: "hub" }, { ok: c.ok, ...(c.ok ? {} : { error: c.out }) });
    }
    this.writeStatus();
  }
}

/** What of a call's result is worth a line on the trace. */
function summarize(fn: string, result: unknown): Record<string, unknown> {
  if (!isObject(result)) return {};
  switch (fn) {
    case "markDone":
      return { created_sentinel: result.created_sentinel === true, reason: result.reason };
    case "forgeTool":
      return { ok: result.ok, name: (result as { manifest?: { name?: string } }).manifest?.name ?? result.name };
    case "restoreFileVersion":
      return { path: result.path, rev: result.rev, ok: result.ok };
    case "claimName":
      return { name: result.name, ok: result.ok };
    case "threadOpen":
      return { thread: result.name ?? result.thread };
    case "publishFile":
      return { path: result.path, sha256: result.sha256, bytes: result.bytes };
    default:
      return {};
  }
}

/** The run's state in the operator's registry, under a lock swarm.sh shares. */
export async function updateRegistryState(registry: string, runId: string, state: string): Promise<void> {
  const lock = `${registry}.lock`;
  for (let i = 0; i < 100; i++) {
    try {
      mkdirSync(lock);
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
      if (i === 99) throw new Error(`the registry is locked (${lock})`);
    }
  }
  try {
    const raw = JSON.parse(readFileSync(registry, "utf8")) as { runs?: Array<Record<string, unknown>> };
    const runs = Array.isArray(raw.runs) ? raw.runs : [];
    for (const r of runs) if (r.id === runId) r.state = state;
    const tmp = `${registry}.tmp`;
    writeFileSync(tmp, `${JSON.stringify({ ...raw, runs }, null, 2)}\n`);
    renameSync(tmp, registry);
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}

async function readStdin(): Promise<string> {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  return input;
}

type HubInput = {
  sandbox: string;
  dir: string;
  agents: string[];
  tokens: Record<string, string>;
  collector: string;
  run?: string;
  vmCli?: string;
  registry?: string;
  settleMs?: number;
  forging: boolean;
  snapshot: boolean;
  quiet: boolean;
};

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  let input: HubInput;
  const resumeDir = opt("--resume");
  if (resumeDir) {
    // Back after a crash, with what the kickoff gave: the hub's directory is
    // the host's, 0700, and no VM mounts it.
    try {
      input = JSON.parse(readFileSync(join(resolve(resumeDir), "hub-input.json"), "utf8")) as HubInput;
    } catch (err) {
      console.error(`vm-hub: cannot resume from ${resumeDir}: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  } else {
    const sandbox = resolve(args[0] ?? "");
    const dir = opt("--dir");
    if (!args[0] || !existsSync(sandbox) || !dir) {
      console.error("vm-hub: usage: vm-hub.ts <sandbox> --dir DIR [--run ID] [--vm-cli PATH] [--registry FILE] [--settle-ms N] [--forging] [--no-snapshot] [--quiet]  (stdin: {agents, tokens, collector}) | --resume DIR");
      process.exit(2);
    }
    let parsed: { agents?: unknown; tokens?: unknown; collector?: unknown };
    try {
      parsed = JSON.parse((await readStdin()).trim() || "{}");
    } catch (err) {
      console.error(`vm-hub: stdin is not JSON (${err instanceof Error ? err.message : err})`);
      process.exit(2);
    }
    const settle = opt("--settle-ms");
    input = {
      sandbox,
      dir: resolve(dir),
      agents: Array.isArray(parsed.agents) ? parsed.agents.filter((a): a is string => typeof a === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(a)) : [],
      tokens: isObject(parsed.tokens) ? (Object.fromEntries(Object.entries(parsed.tokens).filter(([, v]) => typeof v === "string")) as Record<string, string>) : {},
      collector: typeof parsed.collector === "string" ? parsed.collector : join(sandbox, "traces", ".collector.sock"),
      run: opt("--run"),
      vmCli: opt("--vm-cli") ?? join(dirname(fileURLToPath(import.meta.url)), "vm.ts"),
      registry: opt("--registry"),
      settleMs: settle !== undefined ? Number(settle) : undefined,
      forging: args.includes("--forging"),
      snapshot: !args.includes("--no-snapshot"),
      quiet: args.includes("--quiet"),
    };
    mkdirSync(input.dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(input.dir, "hub-input.json"), JSON.stringify(input), { mode: 0o600 });
  }
  // Beside the collector's socket, so a long sandbox path is dialled short.
  try {
    process.chdir(dirname(input.collector));
  } catch {
    // the collector may not be there; the forward says so line by line
  }
  const hub = new Hub(input);
  await hub.start();
  console.error(`vm-hub: up${resumeDir ? " (resumed)" : ""}, ${input.agents.length} agent socket(s) in ${input.dir}`);
  const shutdown = () => void hub.stop().then(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  // Not SIGINT: a run started from the console's terminal shares its process
  // group, and the operator's Ctrl-C there must not take the stop with it.
  process.on("SIGINT", () => undefined);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  void main();
}
