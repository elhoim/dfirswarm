#!/usr/bin/env node
/**
 * One request to the VM hub's admin socket, for the harness's shell scripts
 * (swarm.sh, idle-nudge.sh, await-done.sh), which cannot speak a socket
 * themselves. Prints the hub's answer; exits 0 when it says ok.
 *
 *   node scripts/vm-hub-send.mjs <admin.sock> '{"op":"prompt","agent":"s1a00","text":"..."}'
 *   node scripts/vm-hub-send.mjs <admin.sock> '{"op":"status"}'
 *
 * The request is JSON on argv because it carries words for an agent and a
 * pane id, never a secret; a caller with a secret has no business here.
 */
import { connect } from "node:net";

const [socketPath, body] = process.argv.slice(2);
if (!socketPath || !body) {
  console.error("usage: vm-hub-send.mjs <admin.sock> '<json>'");
  process.exit(2);
}
try {
  JSON.parse(body);
} catch {
  console.error("vm-hub-send: the request is not JSON");
  process.exit(2);
}

let answer = "";
let done = false;
const finish = (code) => {
  if (done) return;
  done = true;
  process.exit(code);
};
const socket = connect(socketPath);
socket.setTimeout(15_000, () => {
  console.error("vm-hub-send: the hub did not answer");
  socket.destroy();
  finish(1);
});
socket.setEncoding("utf8");
socket.on("error", (err) => {
  console.error(`vm-hub-send: ${err.message}`);
  finish(1);
});
socket.on("data", (chunk) => {
  answer += chunk;
});
socket.on("close", () => {
  const line = answer.trim().split("\n")[0] ?? "";
  if (line) console.log(line);
  try {
    finish(JSON.parse(line)?.ok === true ? 0 : 1);
  } catch {
    finish(1);
  }
});
socket.on("connect", () => socket.write(`${body}\n`));
