/**
 * The board, on this machine or on the other side of a VM's wall.
 *
 * On the host every pane shares one kernel, so the protocol's mutexes — an
 * exclusive mkdir, a rename, an O_APPEND — mean what they say, and each pane
 * calls `protocol.ts` directly on the files.
 *
 * An agent in a microVM reaches those files through virtio-fs, and between
 * VMs virtio-fs keeps none of those promises (measured in
 * spikes/microvm-smoke/shared-fs.sh: an O_EXCL-guarded counter lost 494 of
 * 600 increments, O_APPEND lost 495 of 600 lines, a reader missed a renamed
 * file 999 times in 1,000). So in a VM nothing writes the board's files
 * itself: every function here that reads or changes shared state is sent to
 * the hub on the host (scripts/vm-hub.ts), which runs the same `protocol.ts`
 * against the same files as the only writer, with the caller decided by the
 * channel the request arrived on rather than by anything in it.
 *
 * Which of the two happens is decided per call by `SWARM_BOARD_SOCKET`: set,
 * the call goes to the hub; unset, it runs here. The names and signatures are
 * `protocol.ts`'s own, so the extension imports them from here instead and
 * does not change at a single call site.
 */

import { connect, type Socket } from "node:net";
import * as P from "./protocol.ts";
import * as T from "./toolchain.ts";

/** Where the hub listens, as the VM sees it; unset on the host. */
export function boardSocket(env: NodeJS.ProcessEnv = process.env): string {
  return env.SWARM_BOARD_SOCKET || "";
}

/** A call that has not answered in this long is not going to. */
const CALL_TIMEOUT_MS = 120_000;
/** One reply line, however large a result (an inbox page, a ledger) gets. */
const MAX_REPLY_BYTES = 256 * 1024 * 1024;

/** The hub said no, or could not be reached. The message is the hub's own. */
export class BoardError extends Error {
  readonly unreachable: boolean;
  constructor(message: string, unreachable = false) {
    super(message);
    this.name = "BoardError";
    this.unreachable = unreachable;
  }
}

/** A connect the bridge's queue turned away, or a bridge not up yet: nothing was sent. */
function refused(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === "EAGAIN" || code === "ECONNREFUSED" || code === "ENOENT";
}

type Pending = { fn: string; resolve: (value: unknown) => void; reject: (err: Error) => void };

/**
 * One held connection to the hub per process, carrying every board call:
 * each request has an id, each answer names it, and they come back in the
 * order they finish. A VM that opened a connection per call lost a quarter of
 * them under load — the vsock path refused 20 of 80 concurrent connects
 * (measured) — and a held connection is also what lets a `wait` be
 * cancelled without closing anything else.
 */
class HubClient {
  private socket: Socket | null = null;
  private opening: Promise<Socket> | null = null;
  private pending = new Map<number, Pending>();
  private next = 1;
  private buffer = "";
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  private open(): Promise<Socket> {
    if (this.socket && !this.socket.destroyed) return Promise.resolve(this.socket);
    if (this.opening) return this.opening;
    this.opening = (async () => {
      const deadline = Date.now() + 10_000;
      for (let attempt = 0; ; attempt++) {
        try {
          const socket = await new Promise<Socket>((resolve, reject) => {
            const s = connect(this.path);
            s.once("connect", () => resolve(s));
            s.once("error", reject);
          });
          this.attach(socket);
          return socket;
        } catch (err) {
          if (!refused(err) || Date.now() > deadline) throw new BoardError(`the hub is unreachable: ${(err as Error).message}`, true);
          await new Promise((r) => setTimeout(r, Math.min(25 * 2 ** attempt, 500)));
        }
      }
    })().finally(() => {
      this.opening = null;
    });
    return this.opening;
  }

  private attach(socket: Socket): void {
    this.socket = socket;
    this.buffer = "";
    socket.setEncoding("utf8");
    socket.unref();
    socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      if (this.buffer.length > MAX_REPLY_BYTES) {
        socket.destroy(new Error("an answer past the limit"));
        return;
      }
      let cut;
      while ((cut = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, cut);
        this.buffer = this.buffer.slice(cut + 1);
        let msg: { t?: string; id?: number; ok?: boolean; result?: unknown; error?: string };
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        const call = typeof msg.id === "number" ? this.pending.get(msg.id) : undefined;
        if (!call) continue;
        this.pending.delete(msg.id as number);
        if (msg.ok) call.resolve(msg.result);
        else call.reject(new BoardError(msg.error || `${call.fn} failed on the hub`));
      }
    });
    const lost = () => {
      if (this.socket === socket) this.socket = null;
      for (const [id, call] of this.pending) {
        this.pending.delete(id);
        call.reject(new BoardError(`the hub link closed during ${call.fn}`, true));
      }
    };
    socket.on("close", lost);
    socket.on("error", () => undefined);
  }

  async call(fn: string, args: unknown[], options: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<unknown> {
    if (options.signal?.aborted) throw new BoardError("aborted");
    const socket = await this.open();
    const id = this.next++;
    const timeoutMs = options.timeoutMs ?? CALL_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      const done = () => {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
      };
      const timer = setTimeout(() => {
        this.pending.delete(id);
        done();
        reject(new BoardError(`the hub did not answer ${fn} within ${Math.round(timeoutMs / 1000)}s`, true));
      }, timeoutMs);
      const onAbort = () => {
        this.pending.delete(id);
        done();
        try {
          socket.write(`${JSON.stringify({ t: "cancel", id })}\n`);
        } catch {
          // the link is gone, and the call with it
        }
        reject(new BoardError("aborted"));
      };
      options.signal?.addEventListener("abort", onAbort);
      this.pending.set(id, {
        fn,
        resolve: (value) => {
          done();
          resolve(value);
        },
        reject: (err) => {
          done();
          reject(err);
        },
      });
      socket.write(`${JSON.stringify({ t: "rpc", id, fn, args: args.map((a) => (a === undefined ? null : a)) })}\n`);
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }
}

const clients = new Map<string, HubClient>();

/**
 * One board call on the process's held connection to the hub at
 * `socketPath`. `undefined` arguments travel as null, and the hub turns them
 * back, so a default parameter still applies.
 */
export function callBoard(
  socketPath: string,
  fn: string,
  args: unknown[],
  options: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<unknown> {
  let client = clients.get(socketPath);
  if (!client) {
    client = new HubClient(socketPath);
    clients.set(socketPath, client);
  }
  return client.call(fn, args, options);
}

/** Close every held connection (tests; a process that is about to exit). */
export function closeBoardClients(): void {
  for (const c of clients.values()) c.close();
  clients.clear();
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyFn = (...args: any[]) => Promise<any>;

function remote<F extends AnyFn>(name: string, local: F): F {
  return (async (...args: Parameters<F>) => {
    const socket = boardSocket();
    if (!socket) return local(...args);
    return callBoard(socket, name, args);
  }) as F;
}

/**
 * Every function the hub answers. The hub keeps its own table of the same
 * names (scripts/vm-hub.ts), and a test holds the two to each other.
 */
export const REMOTE_FUNCTIONS = [
  "applySessionUsage",
  "claimFile",
  "claimName",
  "clearStopSteer",
  "correctionsAfter",
  "fileDiff",
  "forgeTool",
  "guardWrite",
  "harnessStop",
  "heldBy",
  "listClaims",
  "listFileHistory",
  "listForgedTools",
  "listLedger",
  "listTeam",
  "markDone",
  "markStopSteer",
  "nameOf",
  "postMessage",
  "readBudget",
  "readBudgetStatus",
  "readInbox",
  "readNames",
  "recordEntry",
  "recordFileVersion",
  "releaseAllOwned",
  "releaseFile",
  "restoreFileVersion",
  "swarmDoneExists",
  "systemPost",
  "threadJoin",
  "threadOpen",
  "updateToolchainRecord",
  "waitForSwarmChange",
] as const;

export const applySessionUsage = remote("applySessionUsage", P.applySessionUsage);
export const claimFile = remote("claimFile", P.claimFile);
export const claimName = remote("claimName", P.claimName);
export const clearStopSteer = remote("clearStopSteer", P.clearStopSteer);
export const correctionsAfter = remote("correctionsAfter", P.correctionsAfter);
export const fileDiff = remote("fileDiff", P.fileDiff);
export const forgeTool = remote("forgeTool", P.forgeTool);
export const guardWrite = remote("guardWrite", P.guardWrite);
export const harnessStop = remote("harnessStop", P.harnessStop);
export const heldBy = remote("heldBy", P.heldBy);
export const listClaims = remote("listClaims", P.listClaims);
export const listFileHistory = remote("listFileHistory", P.listFileHistory);
export const listForgedTools = remote("listForgedTools", P.listForgedTools);
export const listLedger = remote("listLedger", P.listLedger);
export const listTeam = remote("listTeam", P.listTeam);
export const markDone = remote("markDone", P.markDone);
export const markStopSteer = remote("markStopSteer", P.markStopSteer);
export const nameOf = remote("nameOf", P.nameOf);
export const postMessage = remote("postMessage", P.postMessage);
export const readBudget = remote("readBudget", P.readBudget);
export const readBudgetStatus = remote("readBudgetStatus", P.readBudgetStatus);
export const readInbox = remote("readInbox", P.readInbox);
export const readNames = remote("readNames", P.readNames);
export const recordEntry = remote("recordEntry", P.recordEntry);
export const recordFileVersion = remote("recordFileVersion", P.recordFileVersion);
export const releaseAllOwned = remote("releaseAllOwned", P.releaseAllOwned);
export const releaseFile = remote("releaseFile", P.releaseFile);
export const restoreFileVersion = remote("restoreFileVersion", P.restoreFileVersion);
export const swarmDoneExists = remote("swarmDoneExists", P.swarmDoneExists);
export const systemPost = remote("systemPost", P.systemPost);
export const threadJoin = remote("threadJoin", P.threadJoin);
export const threadOpen = remote("threadOpen", P.threadOpen);
export const updateToolchainRecord = remote("updateToolchainRecord", T.updateToolchainRecord);

/**
 * `wait` holds its call open for up to five minutes, and an AbortSignal does
 * not cross a socket: the signal closes the connection instead, and the hub
 * ends the wait it was running for it.
 */
export const waitForSwarmChange: typeof P.waitForSwarmChange = async (ctx, options = {}) => {
  const socket = boardSocket();
  if (!socket) return P.waitForSwarmChange(ctx, options);
  const { signal, ...rest } = options;
  const seconds = Math.min(Math.max(1, Math.round(rest.seconds ?? 60)), P.WAIT_MAX_SECONDS);
  const started = Date.now();
  try {
    return (await callBoard(socket, "waitForSwarmChange", [ctx, rest], {
      signal,
      timeoutMs: seconds * 1000 + 60_000,
    })) as P.WaitResult;
  } catch (err) {
    // What the local wait answers when it is aborted, so the caller cannot tell the two apart.
    if (signal?.aborted) return { reason: "timeout", waited_ms: Date.now() - started, detail: "Wait aborted." };
    throw err;
  }
};

/**
 * The harness's side of the conversation: what it tells this agent (a nudge,
 * the kickoff's follow-ups, a stop) and what this agent tells it (working or
 * idle). On the host that is Herdr, which types into the pane and reads the
 * screen; a VM's pane runs `msb exec`, which Herdr cannot see into, so the
 * hub keeps one connection per agent open for it.
 */
export type HubPrompt = { t: "prompt"; text: string; kind?: string; deliver?: "steer" | "followUp" };

export type HubLink = {
  state(state: "working" | "idle" | "blocked", detail?: string): void;
  close(): void;
};

export function openHubLink(
  socketPath: string,
  onPrompt: (prompt: HubPrompt) => void,
  options: { retryMs?: number } = {},
): HubLink {
  let socket: ReturnType<typeof connect> | null = null;
  let closed = false;
  let last: { state: string; detail?: string } | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const retryMs = options.retryMs ?? 2000;

  const send = (body: unknown) => {
    try {
      if (socket && !socket.destroyed) socket.write(`${JSON.stringify(body)}\n`);
    } catch {
      // the next connection says it again
    }
  };

  const open = () => {
    if (closed) return;
    let buffer = "";
    const s = connect(socketPath);
    socket = s;
    s.setEncoding("utf8");
    s.on("connect", () => {
      send({ t: "hello" });
      if (last) send({ t: "state", ...last });
    });
    s.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        try {
          const message = JSON.parse(line) as HubPrompt;
          if (message && message.t === "prompt" && typeof message.text === "string") onPrompt(message);
        } catch {
          // not a message
        }
      }
    });
    const again = () => {
      if (closed || timer) return;
      timer = setTimeout(() => {
        timer = null;
        open();
      }, retryMs);
      timer.unref?.();
    };
    s.on("error", again);
    s.on("close", again);
    s.unref?.();
  };
  open();

  return {
    state(state, detail) {
      last = { state, ...(detail ? { detail } : {}) };
      send({ t: "state", ...last });
    },
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
      socket?.destroy();
    },
  };
}
