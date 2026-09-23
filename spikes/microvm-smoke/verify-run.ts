// Host-side verdict on a run whose agent lived in a microVM. Everything here
// reads files the VM could not write (the anchor, the evidence source) or
// could only reach through the collector.
//
//   node --experimental-strip-types verify-run.ts RUNDIR
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verifyEventChain, verifyInputs } from "../../extensions/protocol.ts";

const run = process.argv[2];
if (!run) throw new Error("usage: verify-run.ts RUNDIR");
const sbx = join(run, "sbx");
const team = JSON.parse(readFileSync(join(sbx, "team.json"), "utf8"));
const agent: string = team.agents[0].id;
let failed = 0;
const check = (label: string, ok: boolean, detail = "") => {
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
};

// 1. The trace: chained, anchored, and every line is the agent's own.
const text = readFileSync(join(sbx, "traces", "events.jsonl"), "utf8");
const anchorPath = `${sbx}.trace-anchor.json`;
const anchor = existsSync(anchorPath) ? JSON.parse(readFileSync(anchorPath, "utf8")) : null;
const chain = verifyEventChain(text, anchor);
check("trace hash chain intact and matches the anchor outside the sandbox", chain.ok === true,
  JSON.stringify(chain).slice(0, 200));
const rows = text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
const byAgent = rows.filter((r) => r.agent === agent).length;
const claimed = rows.filter((r) => r.claimed_agent).length;
check("every trace line attributed to the agent by the collector", rows.length > 0 && claimed === 0,
  `${rows.length} lines, ${byAgent} as ${agent}, ${claimed} with a mismatched claim`);
const tools = new Map<string, number>();
for (const r of rows) if (r.tool) tools.set(r.tool, (tools.get(r.tool) ?? 0) + 1);
console.log(`      tool calls in the trace: ${[...tools].map(([t, n]) => `${t}×${n}`).join(", ") || "none"}`);

// 2. The evidence: the harness's own manifest check, then byte-for-byte
//    against the source directory the copy came from.
const inputs = await verifyInputs(sbx);
check("inputs match their manifest (harness verifyInputs)", !!inputs && inputs.ok === true,
  JSON.stringify(inputs).slice(0, 200));
const diff = (() => {
  try { execFileSync("diff", ["-r", join(run, "evidence"), join(sbx, "inputs")]); return ""; }
  catch (e: any) { return String(e.stdout ?? e.message); }
})();
check("inputs/ byte-identical to the evidence source", diff === "", diff.slice(0, 200));

// 3. The goal's own checks, run on the host as await-done would.
const goal = readFileSync(join(run, "goal.md"), "utf8");
const checks = [...goal.split("## Checks")[1].split("##")[0].matchAll(/^- `(.+)`$/gm)].map((m) => m[1]);
for (const c of checks) {
  let ok = true;
  try { execFileSync("bash", ["-c", c], { cwd: sbx, stdio: "pipe" }); } catch { ok = false; }
  check(`goal check: ${c.slice(0, 70)}`, ok);
}

// 4. What the agent left: its findings, its board, its finish line.
const ledger = join(sbx, "ledger", "entries.jsonl");
const entries = existsSync(ledger) ? readFileSync(ledger, "utf8").split("\n").filter(Boolean) : [];
check("findings recorded in the ledger", entries.length > 0, `${entries.length} entr${entries.length === 1 ? "y" : "ies"}`);
const posts = existsSync(join(sbx, "threads", "main")) ? readdirSync(join(sbx, "threads", "main")).length : 0;
console.log(`      board posts on threads/main: ${posts}`);
check("the agent called done", existsSync(join(sbx, "done", "SWARM_DONE")));

console.log(`\n${failed === 0 ? "ALL PASSED" : `${failed} FAILED`}`);
process.exit(failed ? 1 : 0);
