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
 * And the stop. The extension in each VM enforces the caps, as it does on the
 * host; this process enforces them again from outside, where an agent cannot
 * reach: past the wall clock or the cap plus the grace period it writes the
 * sentinel itself, and once the sentinel has stood for the grace period it
 * stops the VMs.
 *
 *   node --experimental-strip-types scripts/vm-hub.ts <sandbox> --dir DIR
 *        [--run ID] [--vm-cli PATH] [--settle-ms N] [--quiet]
 *
 * One line of JSON on stdin: `{agents: [...], tokens: {<agent>: <token>},
 * collector: "<socket>"}`. Tokens reach this process the way they reach the
 * collector, on stdin, never argv or a file.
 */
import { execFile } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
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

export type HubConfig = {
  sandbox: string;
  dir: string;
  agents: string[];
  tokens: Record<string, string>;
  collector: string;
  run?: string;
  vmCli?: string;
  settleMs?: number;
  quiet?: boolean;
  /** Tests turn the backstop off and drive it by hand. */
  backstop?: boolean;
  herdrBin?: string;
};

type AgentState = { state: string; detail?: string; since: string; connected: boolean };

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
}) {
  const S = hub.sandbox;
  const as = (who: string): P.SwarmContext => ({ sandboxRoot: S, agentId: who });
  type Call = (who: string, a: unknown[], signal: AbortSignal) => Promise<unknown>;
  const table: Record<string, Call> = {
    applySessionUsage: (who, a) => P.applySessionUsage(S, who, a[2] as never),
    claimFile: async (who, a) => {
      await hub.settle(who, String(a[1] ?? ""));
      return P.claimFile(as(who), String(a[1] ?? ""), (a[2] as P.ClaimOptions) ?? {});
    },
    claimName: (who, a) => P.claimName(S, who, String(a[2] ?? ""), a[3] as string | undefined),
    clearStopSteer: () => P.clearStopSteer(S),
    correctionsAfter: (who, a) => P.correctionsAfter(S, String(a[1] ?? ""), who),
    fileDiff: (_who, a) => P.fileDiff(S, String(a[1] ?? ""), a[2] as never, a[3] as never),
    forgeTool: (who, a) => P.forgeTool(as(who), a[1]),
    guardWrite: (who, a) => P.guardWrite(as(who), String(a[1] ?? "")),
    harnessStop: (_who, a) => P.harnessStop(S, a[1] as P.StopReason, String(a[2] ?? ""), (a[3] as { verify?: boolean }) ?? {}),
    heldBy: (who, a) => P.heldBy(as(who), String(a[1] ?? "")),
    listClaims: () => P.listClaims(S),
    listFileHistory: (_who, a) => P.listFileHistory(S, String(a[1] ?? "")),
    listForgedTools: () => P.listForgedTools(S),
    listLedger: (_who, a) => P.listLedger(S, (a[1] as { kind?: string; limit?: number }) ?? {}),
    listTeam: (who) => P.listTeam(as(who)),
    markDone: (who, a) => P.markDone(as(who), a[1] as never),
    markStopSteer: (_who, a) => P.markStopSteer(S, a[1] as P.StopReason),
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
    updateToolchainRecord: () => T.updateToolchainRecord(S),
    waitForSwarmChange: (who, a, signal) =>
      P.waitForSwarmChange(as(who), { ...((a[1] as { seconds?: number; pollMs?: number }) ?? {}), signal }),
  };
  return table;
}

export class Hub {
  readonly cfg: HubConfig;
  readonly roster: string[];
  private servers: Server[] = [];
  private links = new Map<string, Socket>();
  private queued = new Map<string, { text: string; deliver?: string; kind?: string }[]>();
  private status = new Map<string, AgentState>();
  private panes = new Map<string, string>();
  private told = new Set<string>();
  private lastWrite = new Map<string, { who: string; at: number }>();
  private table: ReturnType<typeof boardTable>;
  private backstopTimer: ReturnType<typeof setInterval> | null = null;
  private doneSince = 0;
  private finished = false;

  constructor(cfg: HubConfig) {
    this.cfg = { ...cfg, sandbox: resolve(cfg.sandbox) };
    this.roster = [...cfg.agents];
    for (const id of this.roster) this.status.set(id, { state: "unknown", since: new Date().toISOString(), connected: false });
    this.table = boardTable({
      sandbox: this.cfg.sandbox,
      settle: (who, raw) => this.settle(who, raw),
      wrote: (who, raw) => this.noteWrite(who, raw),
    });
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

  async start(): Promise<void> {
    mkdirSync(this.cfg.dir, { recursive: true, mode: 0o700 });
    for (const agent of this.roster) {
      await this.listen(this.socketFor(agent), (socket) => this.serveAgent(agent, socket));
    }
    await this.listen(this.adminSocket(), (socket) => this.serveAdmin(socket));
    this.writeStatus();
    if (this.cfg.backstop !== false) {
      this.backstopTimer = setInterval(() => void this.backstop().catch(() => undefined), BACKSTOP_INTERVAL_MS);
    }
  }

  private listen(path: string, onSocket: (socket: Socket) => void): Promise<void> {
    return new Promise((resolveListen, reject) => {
      try {
        if (existsSync(path)) unlinkSync(path);
      } catch {
        // the bind says whether it matters
      }
      const server = createServer(onSocket);
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
    await Promise.all(this.servers.map((s) => new Promise((r) => s.close(() => r(undefined)))));
    this.servers = [];
  }

  /** Line-at-a-time reader; `onLine` returns true to keep the connection for more. */
  private lines(socket: Socket, onLine: (line: string) => Promise<boolean> | boolean, idle = true): void {
    let buffer = "";
    let busy = Promise.resolve(true);
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
        busy = busy.then((more) => (more ? onLine(line) : false)).catch(() => false);
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
        const ok = await this.forwardTrace(agent, msg);
        this.reply(socket, ok ? { ok: true } : { ok: false, error: "the collector did not take the line" }, false);
        return true;
      }
      this.reply(socket, { ok: false, error: "unknown message" }, true);
      return false;
    });
  }

  /** One board call, as `who`. Errors travel as the protocol's own message. */
  async call(who: string, fn: string, args: unknown, signal: AbortSignal = new AbortController().signal): Promise<{ ok: boolean; result?: unknown; error?: string }> {
    const handler = Object.prototype.hasOwnProperty.call(this.table, fn) ? this.table[fn] : undefined;
    if (!handler) return { ok: false, error: `${fn} is not a board function` };
    try {
      const result = await handler(who, revive(args), signal);
      return { ok: true, result: result === undefined ? null : result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
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
    return new Promise((done) => {
      let settled = false;
      let answer = "";
      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        done(ok);
      };
      const socket = connect(reachable(this.cfg.collector));
      socket.setTimeout(5000, () => finish(false));
      socket.setEncoding("utf8");
      socket.on("error", () => finish(false));
      socket.on("close", () => finish(false));
      socket.on("data", (chunk: string) => {
        answer += chunk;
        const cut = answer.indexOf("\n");
        if (cut < 0) return;
        try {
          finish(JSON.parse(answer.slice(0, cut))?.ok === true);
        } catch {
          finish(false);
        }
      });
      socket.on("connect", () => socket.write(line));
    });
  }

  /** The hub's own lines, as the harness (`system`). */
  async event(tool: string, args: Record<string, unknown>, result: Record<string, unknown>): Promise<void> {
    const record = { ts: new Date().toISOString(), agent: "system", tool, args, result };
    const token = this.cfg.tokens.system;
    await this.sendToCollector(`${JSON.stringify(token ? { ...record, token } : record)}\n`);
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
        if (now) now.connected = false;
        this.writeStatus();
      }
    });
    this.writeStatus();
    const pending = this.queued.get(agent) ?? [];
    this.queued.delete(agent);
    for (const p of pending) this.reply(socket, { t: "prompt", ...p }, false);
    this.log(`${agent}: link up`);
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
      writeFileSync(tmp, `${JSON.stringify({ at: new Date().toISOString(), agents: this.statusSnapshot() }, null, 2)}\n`);
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
          this.reply(socket, { ok: true, agents: this.statusSnapshot() }, true);
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
          // The harness's own board calls from the host, as `system` would make them.
          const result = await this.call(String(msg.as ?? "system"), String(msg.fn ?? ""), msg.args);
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
   * wedged in a long command, an agent that never ends a turn.
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
      const pressure = P.budgetPressure(budget, now);
      if (!pressure.reason) return;
      const marker = await P.markStopSteer(S, pressure.reason);
      if (marker.claimed) {
        const text =
          pressure.reason === "cap"
            ? P.CAP_STEER
            : `Swarm wall clock hit (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes). Call done with reason cannot_complete and stop. Do not start new work.`;
        for (const agent of this.roster) this.prompt(agent, text, { deliver: "steer", kind: "stop_steer" });
        await this.event("wall_steer", { via: "hub", reason: pressure.reason }, { ok: true });
      }
      if (now - Date.parse(marker.at) < P.STOP_GRACE_MS) return;
      const stop = await P.harnessStop(S, pressure.reason, `The hub stopped the swarm: ${pressure.reason} passed and the agents did not stop within the grace period.`, { verify: true });
      if (stop.created) {
        await this.event("harness_stop", { via: "hub", reason: pressure.reason }, { created_sentinel: true });
        await P.systemPost(S, { tag: "stop", body: `Harness wrote done/SWARM_DONE (reason ${pressure.reason}). Call done and stop.` }).catch(() => undefined);
      }
      return;
    }
    if (!this.doneSince) {
      this.doneSince = now;
      for (const agent of this.roster) {
        if (existsSync(P.agentDonePath(S, agent)) || existsSync(P.agentDeadPath(S, agent))) continue;
        await this.nudge("", "swarm_done", agent);
      }
      return;
    }
    const allOut = this.roster.every((a) => existsSync(P.agentDonePath(S, a)) || existsSync(P.agentDeadPath(S, a)));
    if (this.finished || (!allOut && now - this.doneSince < P.STOP_GRACE_MS)) return;
    this.finished = true;
    await this.event("vm_finish", { via: "hub", all_out: allOut }, { ok: true });
    this.finishVms();
  }

  /** Snapshot and stop this run's VMs, through the VM manager, once. */
  private finishVms(): void {
    if (!this.cfg.vmCli || !this.cfg.run) return;
    const script = this.cfg.vmCli;
    execFile(process.execPath, ["--experimental-strip-types", "--no-warnings", script, "finish", "--run", this.cfg.run, "--sandbox", this.cfg.sandbox], { timeout: 15 * 60_000 }, (err, stdout, stderr) => {
      this.log(`finish: ${err ? `failed: ${err.message}` : "ok"} ${String(stdout).trim()} ${String(stderr).trim()}`);
    });
  }
}

async function readStdin(): Promise<string> {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  return input;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const sandbox = resolve(args[0] ?? "");
  const dir = opt("--dir");
  if (!args[0] || !existsSync(sandbox) || !dir) {
    console.error("vm-hub: usage: vm-hub.ts <sandbox> --dir DIR [--run ID] [--vm-cli PATH] [--settle-ms N] [--quiet]  (stdin: {agents, tokens, collector})");
    process.exit(2);
  }
  let parsed: { agents?: unknown; tokens?: unknown; collector?: unknown };
  try {
    parsed = JSON.parse((await readStdin()).trim() || "{}");
  } catch (err) {
    console.error(`vm-hub: stdin is not JSON (${err instanceof Error ? err.message : err})`);
    process.exit(2);
  }
  const agents = Array.isArray(parsed.agents) ? parsed.agents.filter((a): a is string => typeof a === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(a)) : [];
  const tokens = isObject(parsed.tokens) ? Object.fromEntries(Object.entries(parsed.tokens).filter(([, v]) => typeof v === "string")) as Record<string, string> : {};
  const collector = typeof parsed.collector === "string" ? parsed.collector : join(sandbox, "traces", ".collector.sock");
  // Beside the collector's socket, so a long sandbox path is dialled short.
  try {
    process.chdir(dirname(collector));
  } catch {
    // the collector may not be there; the forward says so line by line
  }
  const settle = opt("--settle-ms");
  const hub = new Hub({
    sandbox,
    dir: resolve(dir),
    agents,
    tokens,
    collector,
    run: opt("--run"),
    vmCli: opt("--vm-cli") ?? join(dirname(fileURLToPath(import.meta.url)), "vm.ts"),
    settleMs: settle !== undefined ? Number(settle) : undefined,
    quiet: args.includes("--quiet"),
  });
  await hub.start();
  console.error(`vm-hub: up, ${agents.length} agent socket(s) in ${dir}`);
  const shutdown = () => void hub.stop().then(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  void main();
}

