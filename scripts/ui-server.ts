#!/usr/bin/env node
/**
 * LAN web app for DFIR Swarm: swarms → threads → agents → traces, plus
 * kickoff / stop / reap through scripts/swarm.sh. Reads runs/,
 * pushes changes over SSE, serves the Vite bundle from ui/dist.
 *
 *   node --experimental-strip-types scripts/ui-server.ts [--port N] [--host H] [--runs-dir DIR]
 */
import { randomBytes } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createUiApp, defaultRunsDir, readVersion } from "./ui/app.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv: string[]) {
  const out = {
    port: Number(process.env.SWARM_UI_PORT || 43173),
    // Loopback unless the operator asks for more. What the console shows is
    // case data — the board, the trace, what came out of the evidence — and
    // reads need no token.
    host: process.env.SWARM_UI_HOST || "127.0.0.1",
    runsDir: process.env.SWARM_RUNS_DIR || defaultRunsDir(ROOT),
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (value === undefined) throw new Error(`${arg} needs a value`);
      i += 1;
      return value;
    };
    if (arg === "--port") out.port = Number(next());
    else if (arg.startsWith("--port=")) out.port = Number(arg.slice(7));
    else if (arg === "--host") out.host = next();
    else if (arg === "--runs-dir") out.runsDir = resolve(next());
    else if (arg === "-h" || arg === "--help") {
      console.log("Usage: ui-server.ts [--port N] [--host H] [--runs-dir DIR]");
      process.exit(0);
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!Number.isInteger(out.port) || out.port < 0 || out.port > 65535) throw new Error(`Bad port ${out.port}`);
  return out;
}

const args = parseArgs(process.argv.slice(2));
// Anyone on the LAN may watch; starting a swarm spends money, so that needs
// the token. SWARM_UI_TOKEN="" turns the check off deliberately.
const token =
  process.env.SWARM_UI_TOKEN === undefined
    ? randomBytes(16).toString("hex")
    : process.env.SWARM_UI_TOKEN;
const app = createUiApp({ root: ROOT, runsDir: args.runsDir, token });
const { port } = await app.listen(args.port, args.host);
const shown = args.host === "0.0.0.0" ? "127.0.0.1" : args.host;
// The fragment is never sent to a server, so it does not land in a proxy
// log or a Referer header the way a query parameter would.
const suffix = token ? `/#token=${encodeURIComponent(token)}` : "";
const lan = !["127.0.0.1", "::1", "localhost"].includes(args.host);
console.log(`DFIR Swarm web app v${await readVersion(ROOT)} at http://${shown}:${port}${suffix}  (bound ${args.host}${lan ? ", LAN reachable" : ", this machine only"})`);
console.log(`Reads ${args.runsDir}; actions run scripts/swarm.sh start|stop|reap`);
console.log(
  token
    ? lan
      ? "Watching is open to anyone who can reach this port — the board, the trace and what came out of the evidence; start / stop / reap / restore need the token in this URL."
      : "Reached from this machine only (use an SSH tunnel from elsewhere; --host 0.0.0.0 opens it to the LAN). Start / stop / reap / restore need the token in this URL."
    : "SWARM_UI_TOKEN is empty: anyone who can reach this port can start and stop swarms.",
);
// AGPL s13. Serving this console to other machines is the network interaction
// the section is about, so the offer is printed where the operator running it
// will see it, and shown in the page footer to everyone who opens it.
console.log("AGPL-3.0-or-later. Source: https://github.com/halilozturkci/dfirswarm");

const shutdown = () => {
  app.close().finally(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
