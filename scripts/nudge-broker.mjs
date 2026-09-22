#!/usr/bin/env node
/**
 * The one thing a pane needs Herdr for, and nothing else it could do with it.
 *
 * Herdr's control socket has no authentication of any kind — reading the
 * v0.9.1 source: the connection handler dispatches every method to whoever
 * connected, and the 0600 mode on the socket file is the whole boundary. The
 * path is injected into every pane as `HERDR_SOCKET_PATH`, and the panes run
 * as the same uid as the server. Measured from inside the write guard: the
 * socket answers. So a pane could:
 *
 *   - `layout.apply` a new pane with arbitrary argv and environment, which is
 *     a process outside the seatbelt profile — every write rule, gone;
 *   - `pane.send_text` into a peer's terminal, which is prompt injection with
 *     the harness's own voice;
 *   - `pane.report_agent` for any pane id with a free-form source, which is a
 *     forged lifecycle state for an agent that is not the sender;
 *   - `server.stop`, which ends the run.
 *
 * The write guard therefore denies that socket (`fsguard.sh --no-socket`).
 * But the harness itself used one Herdr call from inside a pane: when an
 * agent's `done` finishes the swarm, it prompts the peers who are sitting
 * idle and will never make another tool call to notice the sentinel.
 *
 * This is that call, and only that call. The pane asks for a `kind`; the
 * message is written here. An agent can wake a peer. It cannot tell a peer
 * anything, which is a smaller privilege than it had when it could run the
 * CLI itself — the socket seal buys something even where seatbelt is not
 * available to enforce it.
 *
 *   node scripts/nudge-broker.mjs <sandbox> [--socket PATH] [--quiet]
 *
 * One line of JSON in — `{"kind":"swarm_done","peer":"<id>"}` — one line of
 * JSON out: `{"ok":true}` or `{"ok":false,"error":"..."}`.
 */
import { spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, unlinkSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** Beside the collector's socket, in the directory the write guard denies. */
export const NUDGE_SOCKET_REL = "traces/.nudge.sock";
const MAX_LINE_BYTES = 8192;
/** A caller that has said nothing for this long is not mid-request. */
const NUDGE_IDLE_MS = 15_000;
/** One pane at a time is the real load; this is far above it. */
const NUDGE_MAX_CONNECTIONS = 32;

/**
 * What a pane may cause a peer to be told. The caller picks a key; it does
 * not supply prose. Adding a kind here is a deliberate act with a diff.
 */
export const MESSAGES = {
  swarm_done:
    "The swarm is finished: done/SWARM_DONE exists. Call done now and stop.",
};

/** ids as swarm.sh mints them; anything else is not a peer. */
const ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * A peer is an id on this run's roster, and not the sender.
 *
 * The roster arrives on stdin at startup and is held in memory. It used to be
 * read from `<sandbox>/team.json` per request — inside the sandbox, which the
 * write guard leaves writable to every pane, so an agent could add any id it
 * liked (the ids of a concurrently running case are in `runs/registry.json`,
 * and reads are open) and then reach that pane. A check against a file the
 * caller can edit is a spell-check, not a boundary.
 */
export function resolvePeer(roster, peer, sender = "") {
  if (typeof peer !== "string" || !ID.test(peer)) return { ok: false, error: "not an id" };
  if (sender && peer === sender) return { ok: false, error: "that is the sender" };
  if (!Array.isArray(roster) || !roster.includes(peer)) return { ok: false, error: "not in this run" };
  return { ok: true };
}

/**
 * Whether the thing the message asserts is actually true.
 *
 * `swarm_done` tells a peer the swarm is finished and it should stop. The
 * broker sent it on request, so any pane could end every other pane's work at
 * any moment — a run-wide kill switch, reachable by the one component that is
 * meant to be a narrowing. The claim is now checked against the sentinel the
 * harness writes, in `done/`, which no pane can forge into existence without
 * the harness agreeing it is done.
 */
export function claimHolds(sandbox, kind) {
  if (kind !== "swarm_done") return true;
  return existsSync(join(sandbox, "done", "SWARM_DONE"));
}

export function messageFor(kind) {
  return Object.prototype.hasOwnProperty.call(MESSAGES, kind) ? MESSAGES[kind] : "";
}

function main(roster = []) {
  const args = process.argv.slice(2);
  const sandbox = resolve(args[0] ?? "");
  const socketIndex = args.indexOf("--socket");
  const socketPath = socketIndex >= 0 ? args[socketIndex + 1] : join(sandbox, NUDGE_SOCKET_REL);
  const quiet = args.includes("--quiet");
  const herdr = process.env.HERDR_BIN || "herdr";

  if (!sandbox || !existsSync(sandbox)) {
    console.error("nudge-broker: usage: nudge-broker.mjs <sandbox> [--roster] [--socket PATH]");
    process.exit(2);
  }

  // A daemon whose run has been deleted has nothing left to broker. Without
  // this it simply stays: 138 of these were found running on the development
  // machine, every one of them holding a socket in a directory that no longer
  // existed, because teardown removes the pid file and the process outlives
  // it whenever the two get out of step.
  const watchdog = setInterval(() => {
    if (!existsSync(sandbox)) process.exit(0);
  }, ORPHAN_CHECK_MS);
  watchdog.unref();

  /** `herdr agent prompt`, run out here where the socket is still reachable. */
  function prompt(peer, message) {
    return new Promise((done) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        done(ok);
      };
      try {
        const child = spawn(herdr, ["agent", "prompt", peer, message], { stdio: "ignore" });
        const timer = setTimeout(() => {
          child.kill();
          finish(false);
        }, 5000);
        child.on("exit", (code) => {
          clearTimeout(timer);
          finish(code === 0);
        });
        child.on("error", () => {
          clearTimeout(timer);
          finish(false);
        });
      } catch {
        finish(false);
      }
    });
  }

  try {
    if (existsSync(socketPath)) unlinkSync(socketPath);
  } catch {
    // left by a crashed broker; the bind below will say if it matters
  }

  /**
   * Peers already told, so a caller cannot make the broker spawn without
   * bound. One measured connection produced 183 `herdr` processes, each one
   * started outside the pane's sandbox profile. A peer only needs telling
   * once per kind, so remembering is both the fix and the right behaviour.
   */
  const told = new Set();

  const server = createServer((socket) => {
    let buffer = "";
    let handled = false;
    socket.setTimeout(NUDGE_IDLE_MS, () => socket.destroy());
    const reply = (body) => {
      try {
        socket.end(`${JSON.stringify(body)}\n`);
      } catch {
        // the pane went away
      }
    };
    socket.on("data", async (chunk) => {
      // One request per connection. Reading further lines let a single
      // connection drive the loop below as often as it liked, and dropping
      // the rest of the chunk silently lost requests that arrived together.
      if (handled) return;
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_LINE_BYTES) {
        socket.destroy();
        return;
      }
      const cut = buffer.indexOf("\n");
      if (cut < 0) return;
      handled = true;
      const line = buffer.slice(0, cut);
      buffer = "";
      let request;
      try {
        request = JSON.parse(line);
      } catch {
        reply({ ok: false, error: "not json" });
        return;
      }
      const message = messageFor(request?.kind);
      if (!message) {
        reply({ ok: false, error: "unknown kind" });
        return;
      }
      if (!claimHolds(sandbox, request.kind)) {
        reply({ ok: false, error: "the run does not say that" });
        return;
      }
      const peer = resolvePeer(roster, request?.peer, typeof request?.from === "string" ? request.from : "");
      if (!peer.ok) {
        reply({ ok: false, error: peer.error });
        return;
      }
      const once = `${request.kind}:${request.peer}`;
      if (told.has(once)) {
        reply({ ok: true, repeat: true });
        return;
      }
      told.add(once);
      const ok = await prompt(request.peer, message);
      if (!ok) told.delete(once);
      if (!quiet) console.log(`nudge-broker: ${request.kind} -> ${request.peer}: ${ok ? "ok" : "missed"}`);
      reply({ ok });
    });
    socket.on("error", () => {
      // a pane that went away mid-write
    });
  });

  server.maxConnections = NUDGE_MAX_CONNECTIONS;

  server.on("error", (err) => {
    console.error(`nudge-broker: ${err.message}`);
    process.exit(1);
  });

  // The same ~104-byte `sun_path` limit the collector works around, for the
  // same reason: this repo's own runs directory is past it.
  const socketDir = dirname(socketPath);
  const socketName = socketPath.slice(socketDir.length + 1);
  process.chdir(socketDir);
  server.listen(socketName, () => {
    // 0600, as Herdr does for its own: the panes share this uid and still
    // connect, and nobody else on the machine can. A socket is a door, and
    // the default umask leaves this one open to every local account.
    try {
      chmodSync(socketName, 0o600);
    } catch {
      // a platform that does not honour it; the directory is still ours
    }
    if (!quiet) console.log(`nudge-broker: ${socketPath}`);
  });

  function shutdown() {
    try {
      server.close();
    } catch {
      // already closing
    }
    try {
      if (existsSync(socketPath)) unlinkSync(socketPath);
    } catch {
      // nothing to clean
    }
    process.exit(0);
  }
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

/** How often a daemon checks that the run it serves still exists. */
const ORPHAN_CHECK_MS = 60_000;

/**
 * Only when run, never when imported.
 *
 * This module exports the decisions it makes so they can be asserted at the
 * resolution where the edge cases are cheap. Without this guard, importing it
 * to do that binds a socket and holds the event loop open — the test hangs,
 * and the reason is nowhere near the test.
 *
 * `pathToFileURL` rather than `file://${process.argv[1]}`: a path with a
 * space in it does not compare equal to its own URL otherwise, and a case
 * directory is exactly where a space turns up.
 */
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (process.argv.includes("--roster")) {
    // On stdin, like the collector's tokens, and for the same reason: what
    // decides who may be reached must not be a file the callers can write.
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("end", () => {
      let roster = [];
      try {
        const parsed = JSON.parse(input.trim() || "[]");
        if (Array.isArray(parsed)) roster = parsed.filter((id) => typeof id === "string");
      } catch {
        console.error("nudge-broker: --roster expected one line of JSON on stdin");
      }
      main(roster);
    });
  } else {
    main();
  }
}
