/**
 * How a signing secret (an ssh key's passphrase, a FIDO PIN, an e-signature
 * token's PIN) travels, the one way for every kind of key and every caller.
 *
 * The secret is held in a Buffer, in memory only. It is never an argument of
 * any process, never in an environment, never written to a file, a job
 * record or a log. Where it has to reach a program it goes down a pipe on
 * fd 3 of that program:
 *
 * - ssh-keygen asks for a passphrase or a PIN through SSH_ASKPASS; with
 *   SSH_ASKPASS_REQUIRE=force it always does, and scripts/askpass-fd3.sh
 *   answers it with one line read from fd 3, which it inherits;
 * - openssl's PKCS#11 provider reads a token's PIN from
 *   `pin-source=file:/dev/fd/3`.
 *
 * Node creates a child's extra stdio as a socket pair, and a socket cannot
 * be opened again through /dev/fd on Linux, so the program is started through
 * a small bash wrapper whose process substitution turns the secret (written
 * to the wrapper's stdin) into a real pipe on fd 3. The program's own stdin
 * is /dev/null.
 *
 * Where the secret comes from: the terminal, read with echo off
 * (readSecretFromTty); an inherited descriptor, which is how the console's
 * server hands it to scripts/release.ts and scripts/signers.ts
 * (readSecretFromFd). Both give a Buffer, and wipe() zeroes one once used.
 * A JavaScript string cannot be zeroed, which is why nothing here makes one.
 */
import { spawnSync, type SpawnSyncOptions } from "node:child_process";
import { closeSync, openSync, readSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import tty from "node:tty";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The SSH_ASKPASS helper: one line from fd 3 to stdout. */
export const ASKPASS = join(HERE, "askpass-fd3.sh");

/** The longest secret taken: a passphrase, a PIN (a token's is 8 to 20 characters). */
export const SECRET_MAX = 1024;

/** Zero a secret's bytes once they are no longer needed. */
export function wipe(b: Buffer | null | undefined): void {
  if (b) b.fill(0);
}

/**
 * The environment a signing program runs in: the caller's, less anything that
 * would let it sign without the secret or ask for it somewhere else. The
 * ssh-agent socket is dropped when `dropAgent` (the console always drops it:
 * a key held in the agent signs with no passphrase at all), and the X display
 * is dropped so no graphical askpass opens.
 */
export function signingEnv(base: NodeJS.ProcessEnv = process.env, o: { dropAgent?: boolean; askpass?: boolean } = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  for (const k of ["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "WAYLAND_DISPLAY"]) delete env[k];
  if (o.dropAgent) delete env.SSH_AUTH_SOCK;
  if (o.askpass) {
    env.SSH_ASKPASS = ASKPASS;
    env.SSH_ASKPASS_REQUIRE = "force";
  } else {
    // No answer from anywhere but the terminal, or stdin when there is none.
    env.SSH_ASKPASS_REQUIRE = "never";
  }
  return env;
}

export type Ran = { code: number; out: string; err: string; missing: boolean; timedOut: boolean };

/**
 * Run `cmd args` with `secret` on a pipe at its fd 3 (repeated `times` times,
 * one line each: ssh-keygen asks for a new passphrase twice), stdin /dev/null.
 * With no secret, fd 3 is an empty pipe: a program that asks gets nothing.
 */
export function runWithSecret(cmd: string, args: string[], secret: Buffer | null, o: { env?: NodeJS.ProcessEnv; timeoutMs?: number; times?: number; cwd?: string } = {}): Ran {
  const times = Math.max(1, o.times ?? 1);
  const parts: Buffer[] = [];
  for (let i = 0; i < times && secret; i++) parts.push(secret, Buffer.from("\n"));
  const input = Buffer.concat(parts);
  try {
    // $0 is the wrapper's name; "$@" is the program and its arguments, never the secret.
    const r = spawnSync("bash", ["-c", 'exec 3< <(exec cat); exec 0</dev/null; exec "$@"', "dfirswarm-secret", cmd, ...args], {
      input,
      env: o.env ?? process.env,
      cwd: o.cwd,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: o.timeoutMs ?? 120_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    const err = String(r.stderr ?? "");
    const missing = r.status === 127 && /(No such file|not found)/.test(err);
    return { code: r.status ?? 1, out: String(r.stdout ?? ""), err, missing, timedOut: (r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT" || r.signal === "SIGTERM" };
  } finally {
    wipe(input);
  }
}

/**
 * Run `cmd args` with `input` on its stdin, in a session of its own (no
 * controlling terminal). ssh-keygen reads a new key's passphrase from stdin
 * only when it cannot open /dev/tty: from a terminal it would ask there
 * instead, and the pipe would be ignored. Verified with OpenSSH 10.3 and 10.5.
 */
export function runDetachedWithInput(cmd: string, args: string[], input: Buffer, o: { env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): Ran {
  try {
    // `detached` puts the child in a session of its own (setsid) for spawnSync too; the types leave it out.
    const opts = { input, env: o.env ?? process.env, detached: true, stdio: ["pipe", "pipe", "pipe"], timeout: o.timeoutMs ?? 120_000, maxBuffer: 64 * 1024 * 1024 };
    const r = spawnSync(cmd, args, opts as SpawnSyncOptions);
    const missing = (r.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT";
    return { code: r.status ?? 1, out: String(r.stdout ?? ""), err: String(r.stderr ?? ""), missing, timedOut: (r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT" };
  } finally {
    wipe(input);
  }
}

/** A secret handed down an inherited descriptor (the console's pipe): every byte to EOF, less one trailing newline. */
export function readSecretFromFd(fd: number): Buffer {
  const buf = Buffer.alloc(SECRET_MAX + 2);
  let n = 0;
  for (;;) {
    let got = 0;
    try {
      got = readSync(fd, buf, n, buf.length - n, null);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EAGAIN") {
        // A non-blocking pipe with nothing yet: wait a moment for the writer.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
        continue;
      }
      if (code === "EOF") break;
      wipe(buf);
      throw err;
    }
    if (got === 0) break;
    n += got;
    if (n >= buf.length) {
      wipe(buf);
      throw new Error(`the secret on fd ${fd} is longer than ${SECRET_MAX} bytes`);
    }
  }
  try {
    closeSync(fd);
  } catch {
    // closed already, or never ours to close
  }
  let end = n;
  if (end && buf[end - 1] === 0x0a) end -= 1;
  if (end && buf[end - 1] === 0x0d) end -= 1;
  const out = Buffer.from(buf.subarray(0, end));
  wipe(buf);
  return out;
}

/** Whether this process has a terminal to ask on. */
export function hasTty(): boolean {
  try {
    closeSync(openSync("/dev/tty", "r"));
    return true;
  } catch {
    return false;
  }
}

/**
 * One line from the terminal. With `echo: false` (a passphrase, a PIN) the
 * characters are not shown; with it on (a yes or no) they are. Ctrl-C or
 * Ctrl-D on an empty line cancels. The bytes are collected in a Buffer that
 * is zeroed as it is copied out.
 */
export async function readFromTty(prompt: string, o: { echo?: boolean } = {}): Promise<Buffer> {
  let rfd: number;
  let wfd: number;
  try {
    rfd = openSync("/dev/tty", "r");
    wfd = openSync("/dev/tty", "w");
  } catch {
    throw new Error("there is no terminal to ask on");
  }
  writeSync(wfd, prompt);
  const input = new tty.ReadStream(rfd);
  input.setRawMode(true);
  const buf = Buffer.alloc(SECRET_MAX);
  let n = 0;
  try {
    return await new Promise<Buffer>((resolveLine, reject) => {
      input.on("data", (chunk: Buffer) => {
        for (const c of chunk) {
          if (c === 0x03 || (c === 0x04 && n === 0)) {
            chunk.fill(0);
            reject(new Error("cancelled at the terminal"));
            return;
          }
          if (c === 0x0d || c === 0x0a) {
            chunk.fill(0);
            resolveLine(Buffer.from(buf.subarray(0, n)));
            return;
          }
          if (c === 0x7f || c === 0x08) {
            if (n > 0) {
              n -= 1;
              buf[n] = 0;
              if (o.echo) writeSync(wfd, "\b \b");
            }
            continue;
          }
          if (n >= buf.length) {
            chunk.fill(0);
            reject(new Error(`longer than ${SECRET_MAX} bytes`));
            return;
          }
          buf[n++] = c;
          if (o.echo) writeSync(wfd, Buffer.from([c]));
        }
        chunk.fill(0);
      });
      input.on("error", reject);
    });
  } finally {
    wipe(buf);
    try {
      input.setRawMode(false);
    } catch {
      // the terminal went away
    }
    input.destroy();
    writeSync(wfd, "\n");
    closeSync(wfd);
  }
}

/** A yes or no on the terminal: true only for y or yes. */
export async function confirmOnTty(question: string): Promise<boolean> {
  const answer = await readFromTty(`${question} [y/N] `, { echo: true });
  const s = answer.toString("utf8").trim().toLowerCase();
  wipe(answer);
  return s === "y" || s === "yes";
}
