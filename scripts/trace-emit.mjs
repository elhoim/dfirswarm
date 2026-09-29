#!/usr/bin/env node
/**
 * One trace line, from a shell script, through the collector.
 *
 * `idle-nudge.sh` and `reap.sh` are the harness's own watchdogs: they run
 * outside every pane, they have every right to record what they did, and they
 * used to append to `traces/events.jsonl` directly. Their line carried no
 * `prev`, which broke the chain for the *next* line the collector wrote — so
 * a run with the idle watchdog on (the default) reported its own record as
 * edited every three minutes.
 *
 * The fix is not to exempt them. It is to make the collector the only writer
 * in fact as well as in intention, so that an unchained line means what it
 * should: something appended to this record from outside the harness.
 *
 *   printf '%s' "$json" | SWARM_TRACE_TOKEN=... node scripts/trace-emit.mjs <sandbox>
 *
 * Exit 0 when the collector took the line; 1 when it could not be reached
 * (no socket, no connection, no answer); 3 when it answered and refused the
 * line. Why is on stderr. On anything but 0 the caller keeps the line in
 * traces/system-spill.jsonl (scripts/lib/trace.sh), which custody reads as
 * the harness's: never in events.jsonl, where an unchained line is one
 * nobody can vouch for.
 *
 * The socket is dialled from inside its own directory, as the collector
 * binds it: a Unix socket path is at most 103 bytes on macOS (107 on Linux),
 * and a run under a deep SWARM_RUNS_DIR puts traces/.collector.sock past
 * that from any other directory. This process does nothing else, so moving
 * into that directory costs nothing.
 */
import { existsSync } from "node:fs";
import { connect } from "node:net";
import { basename, dirname, join, resolve } from "node:path";

const args = process.argv.slice(2);
const sandbox = resolve(args[0] ?? "");
// From the environment only. `--token T` used to be accepted here and the
// header advertised it — but argv is readable by every process of this uid
// (`ps -ww -ax -o args`), which is the exact property that makes the
// environment the only private channel between panes on this platform. An
// interface that offers to put the token on argv is an interface that will
// eventually be used that way.
const token = process.env.SWARM_TRACE_TOKEN || "";
// The collector's own socket by default; the gate's when the kickoff points
// the sender there (Linux, where the token is not a secret and the gate
// decides who sent the line from the process tree instead).
const socketPath = process.env.SWARM_TRACE_SOCKET || join(sandbox, "traces", ".collector.sock");

if (!sandbox || !existsSync(socketPath)) {
  process.stderr.write(`trace-emit: no collector socket at ${socketPath}\n`);
  process.exit(1);
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  let record;
  try {
    record = JSON.parse(input.trim());
  } catch {
    process.exit(2);
  }
  try {
    process.chdir(dirname(socketPath));
  } catch (err) {
    process.stderr.write(`trace-emit: cannot enter ${dirname(socketPath)}: ${err.code ?? err.message}\n`);
    process.exit(1);
  }
  const socket = connect(basename(socketPath));
  let answer = "";
  const done = (code, why) => {
    if (code !== 0 && why) process.stderr.write(`trace-emit: ${socketPath}: ${why}\n`);
    try {
      socket.destroy();
    } catch {
      // already gone
    }
    process.exit(code);
  };
  socket.setTimeout(2000, () => done(1, "no answer in 2 s"));
  socket.on("error", (err) => done(1, err.code ?? err.message));
  // Exit 0 means *written*, which is what the caller's fallback turns on.
  // It used to mean "flushed to the kernel": a line the collector then
  // refused — too big, missing a field — reported success and was simply
  // gone, with the fallback that exists for exactly that never running.
  //
  // The collector does not hang up after a line, so this waits for the reply
  // rather than for the connection to end.
  socket.on("data", (chunk) => {
    answer += chunk.toString("utf8");
    const cut = answer.indexOf("\n");
    if (cut < 0) return;
    try {
      const reply = JSON.parse(answer.slice(0, cut));
      done(reply?.ok === true ? 0 : 3, `refused: ${reply?.error ?? "not written"}`);
    } catch {
      done(3, "an answer that does not read");
    }
  });
  socket.on("close", () => done(1, "closed before it answered"));
  socket.on("connect", () => {
    socket.write(`${JSON.stringify(token ? { ...record, token } : record)}\n`);
  });
});
