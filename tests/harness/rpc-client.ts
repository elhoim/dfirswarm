/**
 * A minimal client for `pi --mode rpc` (LF-delimited JSON on stdin/stdout).
 *
 * Adapted from the reference self-compact build (disler/self-compact-pi-agent,
 * MIT): the same protocol, our extension. It lets a test drive one real Pi
 * process with a scripted provider and read every event Pi emits, so the
 * hand-off transaction is proven through the real CLI with no key, no
 * network and no money.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type RpcEvent = { type: string; [key: string]: unknown };

export type RpcClientOptions = {
  args: string[];
  cwd: string;
  env?: Record<string, string | undefined>;
  /** Every stdout/stderr line is appended here, for a failing test's artefacts. */
  logFile?: string;
};

export class RpcClient {
  readonly events: RpcEvent[] = [];
  readonly stderr: string[] = [];
  exitCode: number | null = null;
  private proc: ChildProcessWithoutNullStreams;
  private buffer = "";
  private waiters: Array<{ pred: (e: RpcEvent) => boolean; resolve: (e: RpcEvent) => void }> = [];
  private exited = false;
  private options: RpcClientOptions;

  constructor(options: RpcClientOptions) {
    this.options = options;
    if (options.logFile) mkdirSync(dirname(options.logFile), { recursive: true });
    this.proc = spawn("pi", ["--mode", "rpc", ...options.args], {
      cwd: options.cwd,
      env: { ...process.env, PI_SKIP_VERSION_CHECK: "1", ...options.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.proc.stdout.setEncoding("utf8");
    this.proc.stdout.on("data", (chunk: string) => this.onData(chunk));
    this.proc.stderr.setEncoding("utf8");
    this.proc.stderr.on("data", (chunk: string) => {
      this.stderr.push(chunk);
      this.log(`[stderr] ${chunk}`);
    });
    this.proc.on("exit", (code) => {
      this.exited = true;
      this.exitCode = code;
      this.log(`[exit] ${code}`);
    });
  }

  private log(line: string) {
    if (!this.options.logFile) return;
    try {
      appendFileSync(this.options.logFile, line.endsWith("\n") ? line : `${line}\n`);
    } catch {
      // a log that cannot be written must not fail the test it serves
    }
  }

  private onData(chunk: string) {
    this.buffer += chunk;
    let index = this.buffer.indexOf("\n");
    while (index !== -1) {
      let line = this.buffer.slice(0, index);
      this.buffer = this.buffer.slice(index + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      if (line.trim()) this.onLine(line);
      index = this.buffer.indexOf("\n");
    }
  }

  private onLine(line: string) {
    this.log(line);
    let event: RpcEvent;
    try {
      event = JSON.parse(line) as RpcEvent;
    } catch {
      return;
    }
    this.events.push(event);
    const remaining: typeof this.waiters = [];
    for (const waiter of this.waiters) {
      if (waiter.pred(event)) waiter.resolve(event);
      else remaining.push(waiter);
    }
    this.waiters = remaining;
  }

  send(command: Record<string, unknown>): void {
    const line = `${JSON.stringify(command)}\n`;
    this.log(`[send] ${line}`);
    this.proc.stdin.write(line);
  }

  /** The first event, already received or still to come, that matches. */
  waitFor(pred: (e: RpcEvent) => boolean, timeoutMs = 30_000, options: { since?: number } = {}): Promise<RpcEvent> {
    const since = options.since ?? 0;
    for (let i = since; i < this.events.length; i++) {
      if (pred(this.events[i]!)) return Promise.resolve(this.events[i]!);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w.resolve !== wrapped);
        reject(new Error(`timed out after ${timeoutMs}ms; last events: ${JSON.stringify(this.events.slice(-6).map((e) => e.type))}; stderr: ${this.stderr.join("").slice(-2000)}`));
      }, timeoutMs);
      const wrapped = (e: RpcEvent) => {
        clearTimeout(timer);
        resolve(e);
      };
      this.waiters.push({ pred, resolve: wrapped });
    });
  }

  async request(command: Record<string, unknown>, timeoutMs = 30_000): Promise<RpcEvent> {
    const id = `req-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const since = this.events.length;
    this.send({ id, ...command });
    return this.waitFor((e) => e.type === "response" && e.id === id, timeoutMs, { since });
  }

  mark(): number {
    return this.events.length;
  }

  async close(): Promise<void> {
    if (this.exited) return;
    try {
      this.proc.stdin.end();
    } catch {
      // already closed
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.proc.kill("SIGKILL");
        resolve();
      }, 5000);
      this.proc.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      this.proc.kill("SIGTERM");
    });
  }
}

export function eventsOfType(events: RpcEvent[], type: string): RpcEvent[] {
  return events.filter((e) => e.type === type);
}

/** The text of a message-shaped object: a string, or the text blocks joined. */
export function messageText(message: unknown): string {
  const content = (message as { content?: unknown })?.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((b) => (b && typeof b === "object" && (b as { type?: string }).type === "text" ? String((b as { text?: string }).text ?? "") : "")).join("\n");
  }
  return "";
}
