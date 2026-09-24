#!/usr/bin/env node
/**
 * The trace's writer, outside the agents' reach.
 *
 * `traces/events.jsonl` used to live in the directory the panes can write,
 * owned by the same uid, and the harness compared its size and prefix before
 * and after every shell call to notice a rewrite. That is detection, and the
 * board post it produces says so itself: "Nothing can restore it." On the
 * BelkaCTF #6 run it fired once, and the file turned out to be intact — the
 * loudest integrity alarm of the run was a false positive nobody answered.
 *
 * Three things follow, and this process is all three.
 *
 * **It is the only writer.** It runs outside the pane's sandbox profile; the
 * panes reach it through a Unix socket they may connect to, in a directory
 * they may not write. So the record cannot be edited by what it records.
 *
 * **Every line names its parent.** `prev` is the sha256 of the line before
 * it, computed here, where there is exactly one writer and the chain is
 * therefore trivially correct. An edit or a deletion in the middle breaks it,
 * and the anchor below catches a wholesale rewrite.
 *
 * **Who sent a line is decided here, not claimed there.** Each pane gets its
 * own token in its environment — which on macOS no other process can read
 * (measured), and which Herdr's own API does not expose (measured) — and the
 * collector takes the token map on stdin, where neither argv nor the
 * filesystem can leak it. A line's `agent` is whatever its token says. A line
 * claiming to be someone else is written as what it is, with `claimed_agent`
 * beside it: an attempt on the record is itself a finding.
 *
 *   node scripts/trace-collector.mjs <sandbox> [--socket PATH] [--tokens]
 *                                    [--anchor PATH] [--quiet]
 *
 * With `--tokens`, one line of JSON on stdin: `{"tokens": {"<token>": "<agent id>"},
 * "gate": "<key or empty>"}`, the same line the gate reads.
 * With `--anchor PATH`, the head of the chain is written there after every
 * line — outside the sandbox, so a run that rewrote its whole trace and
 * recomputed the chain still cannot match what the anchor remembers.
 *
 * One line of JSON per message, newline-terminated. Anything that is not an
 * event is refused rather than written: this file is the record.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { appendFileSync, chmodSync, mkdirSync, readFileSync, existsSync, statSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EVENTS_REL = "traces/events.jsonl";
// Inside traces/, which the write guard denies to the panes: a socket they
// could unlink is a socket they could replace.
export const COLLECTOR_SOCKET_REL = "traces/.collector.sock";
/** Bigger than any real event, small enough that one sender cannot exhaust memory. */
const MAX_LINE_BYTES = 64_000_000;
/** A sender that has said nothing for this long is not mid-event. */
const COLLECTOR_IDLE_MS = 30_000;
/** Above any real run; below what a pane could use to exhaust the machine. */
const COLLECTOR_MAX_CONNECTIONS = 32;

const args = process.argv.slice(2);
const sandbox = resolve(args[0] ?? "");
const socketIndex = args.indexOf("--socket");
const socketPath = socketIndex >= 0 ? args[socketIndex + 1] : join(sandbox, COLLECTOR_SOCKET_REL);
const anchorIndex = args.indexOf("--anchor");
const anchorPath = anchorIndex >= 0 ? args[anchorIndex + 1] : "";
const wantTokens = args.includes("--tokens");
const quiet = args.includes("--quiet");

if (!sandbox || !existsSync(sandbox)) {
  console.error("trace-collector: usage: trace-collector.mjs <sandbox> [--socket PATH] [--tokens] [--anchor PATH]");
  process.exit(2);
}

const eventsFile = join(sandbox, EVENTS_REL);
mkdirSync(dirname(eventsFile), { recursive: true });
const eventsAbs = eventsFile;

/** token -> agent id. Empty when the run did not hand any out. */
let tokens = new Map();
/**
 * The gate's key, when a gate stands in front of this collector. On Linux a
 * pane's token is readable by every other pane of the same uid through
 * /proc/<pid>/environ, so the token alone no longer says who sent a line.
 * scripts/trace-gate.py decides that from SO_PEERCRED and the process tree,
 * and marks every line it forwards with this key. The key reaches the gate
 * and this collector on stdin and lives nowhere a pane can read — not in any
 * environment, not on disk. With a key set, a token that arrives without it
 * came straight from a pane, and the line is written unverified.
 */
let gateKey = "";

function lineHash(line) {
  return createHash("sha256").update(line).digest("hex");
}

function sizeOf(file) {
  try {
    return statSync(file).size;
  } catch {
    return 0;
  }
}

/**
 * The file's whole lines. A fragment at the end — no closing newline, left by
 * a writer killed or starved of disk mid-append — is not one of them: it was
 * never acknowledged, and counting it or chaining onto it would make it part
 * of the record.
 */
function wholeLines(text) {
  const all = text.split("\n");
  all.pop();
  return all.filter(Boolean);
}

function countLines(file) {
  try {
    return wholeLines(readFileSync(file, "utf8")).length;
  } catch {
    return 0;
  }
}

/**
 * Resume the chain from a file that already has lines in it — a restarted
 * collector must not begin a second chain in the middle of a run.
 */
function lastHashOf(file) {
  try {
    const all = wholeLines(readFileSync(file, "utf8"));
    if (!all.length) return "";
    return lineHash(all[all.length - 1]);
  } catch {
    return "";
  }
}

/** Whether the file ends partway through a line. */
function endsMidLine(file) {
  try {
    const text = readFileSync(file, "utf8");
    return text.length > 0 && !text.endsWith("\n");
  } catch {
    return false;
  }
}

/** The anchor an earlier collector left, or null when there is none to read. */
function readAnchor() {
  if (!anchorPath) return null;
  try {
    const anchor = JSON.parse(readFileSync(anchorPath, "utf8"));
    const lines = Number(anchor?.lines);
    if (!Number.isInteger(lines) || lines < 0 || typeof anchor.head !== "string") return null;
    return anchor;
  } catch {
    return null;
  }
}

/**
 * How many lines the anchor this collector finds on startup already
 * committed to. A restarted collector used to count the file instead, so a
 * trace cut short while no collector was running came back with an anchor
 * lowered to match, and verified as intact. A `pending` anchor names a line
 * that may never have reached the file, so it commits to one fewer.
 */
function anchoredLines() {
  const anchor = readAnchor();
  if (!anchor) return 0;
  return anchor.pending === true ? Math.max(0, anchor.lines - 1) : anchor.lines;
}

/**
 * Whether these whole lines are the record the anchor describes, by the rules
 * `verifyEventChain` in extensions/protocol.ts applies (mirrored here so the
 * collector needs nothing but node). Null when they are; otherwise what is
 * wrong and where. The collector runs under plain node on every platform, so
 * it does not import the TypeScript.
 */
function disagreement(lines, anchor) {
  let previous = "";
  let chained = 0;
  for (let i = 0; i < lines.length; i += 1) {
    let record;
    try {
      record = JSON.parse(lines[i]);
    } catch {
      return { reason: "edited", at: i + 1 };
    }
    const prev = typeof record?.prev === "string" ? record.prev : null;
    if (prev === null) {
      if (chained) return { reason: "appended", at: i + 1 };
    } else {
      chained += 1;
      if (prev !== previous) return { reason: "edited", at: i + 1 };
    }
    previous = lineHash(lines[i]);
  }
  if (!chained && anchor.lines > 0) return { reason: "head", at: 1 };
  if (lines.length > anchor.lines) return { reason: "appended", at: anchor.lines + 1 };
  if (lines.length === anchor.lines) {
    return previous === anchor.head ? null : { reason: "head", at: lines.length };
  }
  if (anchor.pending === true && lines.length === anchor.lines - 1 && typeof anchor.prev_head === "string") {
    return previous === anchor.prev_head ? null : { reason: "head", at: lines.length };
  }
  return { reason: "shortened", at: lines.length };
}

/** sha256 of the last line written, so the next one can name its parent. */
let previous = lastHashOf(eventsFile);
/**
 * How long this record has ever been — never how long the file is now.
 *
 * It used to be re-read from the file, so truncating the trace and letting
 * the collector write one more line moved the anchor *down* to the shorter
 * count and the record verified as intact. An anchor that forgets is not an
 * anchor: this only ever goes up.
 */
let lineCount = Math.max(countLines(eventsFile), anchoredLines());
/**
 * Bytes in the file after this process's last write, to notice other writers.
 * Unknown until the first write, so that write reads the tail it finds.
 */
let lastSize = -1;
/**
 * Where the file ended before an append that failed partway and could not be
 * cut back, or -1. A full disk fails an append after part of the line is on
 * disk; left there, that fragment has no newline and the next line would be
 * written onto the end of it.
 */
let tornAt = -1;

/**
 * The head of the chain, written where the panes cannot reach it.
 *
 * Without it, anything that can rewrite the whole file can also recompute a
 * consistent chain over the version it prefers. The anchor lives outside the
 * sandbox — which the write guard puts out of a pane's reach — so a rewritten
 * file no longer matches what the record says it should be.
 */
function writeAnchor(head = previous, prevHead = "", pending = false) {
  if (!anchorPath) return;
  try {
    writeFileSync(
      anchorPath,
      `${JSON.stringify({ sandbox, lines: lineCount, head, prev_head: prevHead, pending, at: new Date().toISOString() })}\n`,
      "utf8",
    );
  } catch {
    // an anchor that cannot be written must not stop the record
  }
}

function write(record) {
  if (tornAt >= 0) {
    // Nothing is appended onto a fragment. Until it can be cut off, every
    // line is refused, and the sender spills it as it would any failure.
    try {
      truncateSync(eventsAbs, tornAt);
    } catch (err) {
      throw new Error(`the trace ends in a partial line that could not be cut off: ${err.message}`);
    }
    tornAt = -1;
  }
  // Anything that appends directly is noticed here and the chain picks up
  // from what is actually in the file. `idle-nudge.sh` and `reap.sh` used to
  // do that — they run outside every pane, so the read-only guard does not
  // touch them — and their unchained line broke the *next* collector line,
  // which with the watchdog on by default meant a run calling its own record
  // edited every three minutes. They send through this socket now; this stays
  // because the next such writer should not be a corruption report either.
  const size = sizeOf(eventsFile);
  if (size !== lastSize) {
    // A fragment this process did not write — an earlier collector killed
    // mid-append, another writer — is not cut off: it is not ours to discard.
    // Nor is anything appended onto it, which would fuse the next line into
    // it and leave the record unparseable from there on. The line is
    // refused, the sender spills it, as a pane's own fallback does.
    if (endsMidLine(eventsFile)) {
      throw new Error("the trace ends in a partial line this collector did not write; not appending onto it");
    }
    previous = lastHashOf(eventsFile);
    // Only upwards. A file that shrank under the collector is a record that
    // lost lines, and the anchor has to keep saying how long it was.
    lineCount = Math.max(lineCount, countLines(eventsFile));
  }
  const withChain = { ...record, prev: previous };
  const line = `${JSON.stringify(withChain)}\n`;
  const head = lineHash(line.slice(0, -1));
  // The anchor goes first, naming the line that is about to exist and the one
  // before it. Written after the append instead, there is a window where the
  // file is one line longer than the anchor — indistinguishable from a line
  // appended by something else, which is the whole thing the anchor is for.
  // This way the anchor is never behind, and a reader that catches the window
  // sees a file one line short of an anchor whose `prev_head` it matches.
  const behind = previous;
  lineCount += 1;
  previous = head;
  // Twice, bracketing the append, and the difference is the whole point.
  //
  // Written only afterwards, there is a moment when the file is one line
  // longer than the anchor — indistinguishable from a line appended by
  // something else, which is the case the anchor exists to catch. Written
  // only before, the mirror: a file one line short of the anchor could be
  // the same moment or could be the record's last line deleted, and a reader
  // has to let one of them through.
  //
  // `pending` says which moment this is. Between these two writes a reader
  // may see either length; outside them the anchor names exactly one.
  writeAnchor(head, behind, true);
  try {
    appendFileSync(eventsAbs, line, "utf8");
  } catch (err) {
    // The line never reached the file whole — a full disk, a file gone
    // read-only. The sender is told so and spills it; the chain must not name
    // it, or the next line written would carry a parent that does not exist
    // and the record would read as edited. A full disk usually fails partway,
    // with part of the line already written: cut the file back to where it
    // ended, or the fragment becomes the head and the next line is glued onto
    // it. Then put the head and the anchor back; with `pending` false a reader
    // never consults `prev_head`.
    if (sizeOf(eventsFile) > size) {
      try {
        truncateSync(eventsAbs, size);
      } catch {
        tornAt = size;
      }
    }
    lineCount -= 1;
    previous = behind;
    writeAnchor(behind, "", false);
    throw err;
  }
  writeAnchor(head, behind, false);
  lastSize = sizeOf(eventsFile);
  return true;
}

/**
 * Whose line this is, decided from the token rather than from the body.
 *
 * No tokens handed out: nothing to check, and the record leaves the claim
 * alone. A token that maps: that is the sender, whatever the body says. A
 * token that does not map, or none at all while the run does use them: the
 * line is written and marked unverified, because a record that drops what it
 * cannot attribute is worse than one that says it could not.
 */
export function attribute(record, map = tokens, key = gateKey) {
  // `agent_unverified` and `claimed_agent` are this function's verdict on the
  // sender. A sender that supplies them decides its own verdict: it can stamp
  // its own lines "could not be attributed" and repudiate them later, or
  // spray `claimed_agent` to bury a real forgery in noise. They are dropped
  // from the input for the same reason `prev` is — the record says what the
  // collector found, not what the line asked it to say.
  const { token, gate, agent_unverified: _u, claimed_agent: _c, prev: _p, ...rest } = record;
  if (!map.size) return rest;
  const claimed = typeof rest.agent === "string" ? rest.agent : "";
  // With a gate in front, a token counts only when the gate vouched for it.
  const gated = !key || (typeof gate === "string" && sameSecret(gate, key));
  const known = gated && typeof token === "string" ? map.get(token) : undefined;
  if (!known) return { ...rest, agent: claimed || "unknown", agent_unverified: true };
  if (claimed && claimed !== known) return { ...rest, agent: known, claimed_agent: claimed };
  return { ...rest, agent: known };
}

/** Equal in constant time; a length difference is an ordinary mismatch. */
function sameSecret(a, b) {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Settle the file this collector inherits before any pane can write to it.
 *
 * A fragment at the end — no closing newline — is refused by `write()`, and
 * nothing else ever cuts one this process did not write, so a fragment left
 * by a collector killed mid-append used to refuse every line for the rest of
 * the run. When the anchor accounts for exactly the whole lines before it,
 * the fragment is the line the anchor had promised and never acknowledged:
 * it is moved out to traces/, cut off, and the cut is itself a line of the
 * record. A fragment the anchor does not account for is left where it is.
 */
function reconcile() {
  const anchor = readAnchor();
  if (!anchor) return;
  let bytes;
  try {
    bytes = readFileSync(eventsFile);
  } catch {
    return;
  }
  const cut = bytes.lastIndexOf(0x0a) + 1;
  const whole = wholeLines(bytes.subarray(0, cut).toString("utf8"));
  const wrong = disagreement(whole, anchor);
  if (wrong || cut === bytes.length) return;
  const fragment = bytes.subarray(cut);
  const saved = join(dirname(eventsFile), `events.fragment-${new Date().toISOString().replace(/[:.]/g, "-")}.partial`);
  try {
    writeFileSync(saved, fragment, { flag: "wx" });
    truncateSync(eventsAbs, cut);
  } catch (err) {
    console.error(`trace-collector: could not cut the partial line at the end of the trace: ${err.message}`);
    return;
  }
  console.error(`trace-collector: cut a ${fragment.length}-byte partial line the anchor never acknowledged; kept in ${saved}`);
  write({
    ts: new Date().toISOString(),
    agent: "system",
    tool: "trace_fragment_cut",
    args: { bytes: fragment.length, sha256: createHash("sha256").update(fragment).digest("hex"), saved_to: relative(sandbox, saved) },
    result: { ok: true },
  });
}

/** Tell the sender what became of its line, if it is still listening. */
function reply(socket, body) {
  try {
    if (socket.writable) socket.write(`${JSON.stringify(body)}\n`);
  } catch {
    // the sender hung up; the line is written either way
  }
}

/** How often a daemon checks that the run it serves still exists. */
const ORPHAN_CHECK_MS = 60_000;

function start() {
  // A collector whose sandbox has been deleted is writing into nothing. 169
  // of these were found running on the development machine, left by test runs
  // whose directories were long gone.
  const watchdog = setInterval(() => {
    if (!existsSync(sandbox)) process.exit(0);
  }, ORPHAN_CHECK_MS);
  watchdog.unref();

  try {
    if (existsSync(socketPath)) unlinkSync(socketPath);
  } catch {
    // a socket left by a crashed collector; the bind below will say if it matters
  }

  // Before the socket exists, so no pane's line can land first.
  try {
    reconcile();
  } catch (err) {
    console.error(`trace-collector: could not settle the trace it found: ${err.message}`);
  }

  const server = createServer((socket) => {
    let buffer = "";
    // A sender that goes quiet mid-line holds its buffer open forever. With
    // no cap on either, 300 connections holding 900 KB apiece took the
    // collector from 51 MB to 821 MB — measured — and a pane may connect
    // freely. Neither limit is near anything a real sender does.
    socket.setTimeout(COLLECTOR_IDLE_MS, () => socket.destroy());
    // Decode the stream, not each read: a read boundary can fall inside a
    // UTF-8 sequence, and decoding the halves apart writes U+FFFD into a line
    // that still parses and is then hashed into the chain as if it were true.
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        if (!line.trim()) continue;
        let record;
        try {
          if (line.length > MAX_LINE_BYTES) throw new Error(`${line.length} bytes is past the limit`);
          record = JSON.parse(line);
          if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("not an object");
          if (typeof record.tool !== "string" || typeof record.ts !== "string") throw new Error("not an event");
        } catch (err) {
          // A malformed message is the sender's bug. It is not written: this
          // file is what a case rests on, and a half-line in it is worse than
          // a missing one.
          if (!quiet) console.error(`trace-collector: refused a malformed message: ${err.message}`);
          reply(socket, { ok: false, error: err.message });
          continue;
        }
        try {
          write(attribute(record));
          // The sender is told the line was *written*, not that it was sent.
          // Without this, a refused line — over the size limit, missing
          // `tool` — left the caller believing it had recorded something, and
          // its fallback never ran. An event that vanishes quietly is the one
          // failure this file cannot have.
          reply(socket, { ok: true });
        } catch (err) {
          // Not the sender's bug but this side's: the disk, the file. Said
          // apart from a malformed message, because the fix is somewhere else.
          // Whatever --quiet says: a refused line goes to the spill, which the
          // report does not read, and this log is then the only place that
          // says the record is being refused.
          console.error(`trace-collector: could not write a line: ${err.message}`);
          reply(socket, { ok: false, error: err.message });
        }
      }
      if (buffer.length > MAX_LINE_BYTES) {
        // A sender that never sends a newline would otherwise grow this
        // process until the machine gives out.
        buffer = "";
        socket.destroy();
      }
    });
    socket.on("error", () => {
      // a pane that went away mid-write
    });
  });

  // One sender per pane plus the harness's watchdogs; this is far above what
  // a run uses and far below what exhausts the machine. Past it the kernel
  // queues, so a legitimate sender waits rather than failing.
  server.maxConnections = COLLECTOR_MAX_CONNECTIONS;

  server.on("error", (err) => {
    console.error(`trace-collector: ${err.message}`);
    process.exit(1);
  });

  // A Unix socket path is limited to about 104 bytes, and a sandbox under a
  // long home — `~/Library/CloudStorage/Dropbox/.../runs/<id>/traces/` is 110
  // — is past it. Binding from inside the directory keeps the path the kernel
  // sees short; clients do the same from their own cwd. Without this the
  // collector silently fails to start and every pane writes its own trace.
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
    writeAnchor();
    if (!quiet) console.log(`trace-collector: ${socketPath} -> ${eventsFile}`);
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
  if (wantTokens) {
    // On stdin, because argv is visible to every process of this uid and a file
    // is readable by every pane. A token nobody else can see is the only thing
    // that makes "who sent this" answerable while the panes share a uid.
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("end", () => {
      try {
        const parsed = JSON.parse(input.trim() || "{}");
        // One shape, the one the gate reads too: `{tokens, gate}`. The key is
        // empty when no gate stands in front, and the token then attributes.
        if (!parsed || typeof parsed.tokens !== "object" || parsed.tokens === null) {
          throw new Error("no tokens object");
        }
        tokens = new Map(Object.entries(parsed.tokens).filter(([, v]) => typeof v === "string"));
        gateKey = typeof parsed.gate === "string" ? parsed.gate : "";
      } catch (err) {
        console.error(`trace-collector: --tokens expected one line of JSON on stdin, {tokens, gate} (${err instanceof Error ? err.message : err})`);
      }
      // One line for the log, whatever --quiet says: whether this collector
      // will count a token on its own or only on a line the gate vouched for.
      console.error(`trace-collector: up, ${tokens.size} token(s), gate key: ${gateKey ? "yes" : "no"}`);
      start();
    });
  } else {
    start();
  }
}
