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
 * Exit 0 when the collector took the line. Exit 1 when it did not, and the
 * caller falls back to appending the file itself — a record that loses a line
 * is worse than one with an unchained line in it.
 */
import { existsSync } from "node:fs";
import { connect } from "node:net";
import { basename, dirname, join, relative, resolve } from "node:path";

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

if (!sandbox || !existsSync(socketPath)) process.exit(1);

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
  // The same ~104-byte limit the collector works around, from the other side.
  const here = process.cwd();
  const short = join(relative(here, dirname(socketPath)), basename(socketPath));
  const target = short.length < socketPath.length ? short : socketPath;
  const socket = connect(target);
  let answer = "";
  const done = (code) => {
    try {
      socket.destroy();
    } catch {
      // already gone
    }
    process.exit(code);
  };
  socket.setTimeout(2000, () => done(1));
  socket.on("error", () => done(1));
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
      done(JSON.parse(answer.slice(0, cut))?.ok === true ? 0 : 1);
    } catch {
      done(1);
    }
  });
  socket.on("close", () => done(1));
  socket.on("connect", () => {
    socket.write(`${JSON.stringify(token ? { ...record, token } : record)}\n`);
  });
});
