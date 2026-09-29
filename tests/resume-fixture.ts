/**
 * A run of the release fixture as a resume finds it: its team and budget, a
 * sentinel and a seat's done file, and the continuation's work (a ledger
 * entry with its record line on the trace, chained as the fixture's are).
 * Shared by tests/resume.test.ts and tests/resume-review.test.ts.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import * as P from "../extensions/protocol.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { runContext } from "../scripts/release.ts";
import { runLayout } from "../scripts/release-record.ts";
import { reviewsPath } from "../scripts/review.ts";
import type { StoppedRun } from "./release-fixture.ts";

export const quiet = () => undefined;
export const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export const ctxOf = (r: StoppedRun) => runContext(r.root, { run: r.id, runsDir: r.runs });
export const layout = (r: StoppedRun) => runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));

/** The team and the budget a real run has, for the fixture run; a sentinel, and the seats' done files. */
export async function asTeam(r: StoppedRun) {
  await writeFile(join(r.root, "team.json"), JSON.stringify({ swarm_id: r.id, n: 2, agents: [{ id: "a0", role: "worker" }, { id: "a1", role: "worker" }] }));
}
export async function asEnded(r: StoppedRun, o: { minutesAgo?: number; wall?: number } = {}) {
  await asTeam(r);
  const started = new Date(Date.now() - (o.minutesAgo ?? 20) * 60_000).toISOString();
  await writeFile(join(r.root, "budget.json"), JSON.stringify(P.normalizeBudget({ cap_usd: 5, wall_clock_minutes: o.wall ?? 60, started_at: started, stop_policy: "cap-pause", agents: {} })));
  await mkdir(join(r.root, "done", "agents"), { recursive: true });
  await writeFile(join(r.root, P.SENTINEL_REL), `---\nby: a0\noutput: work/report.md\nreason: finished\noutcome: completed\nat: ${new Date(Date.now() - 60_000).toISOString()}\n---\n`);
  await writeFile(join(r.root, "done", "agents", "a0.done"), "---\nby: a0\n---\n");
}

/** The continuation's work: one entry in the ledger, and its record line on the trace, chained as the fixture's are. */
export async function continueWith(r: StoppedRun, value: string) {
  const res = await P.recordEntry({ sandboxRoot: r.root, agentId: "a1" }, { kind: "ioc", value, source: "the continuation", evidence: "read again after the resume" } as P.LedgerInput);
  assert.ok(res.ok, (res as { reason?: string }).reason);
  if (!res.ok) return;
  const trace = (await readFile(join(r.root, P.EVENTS_REL), "utf8")).trimEnd().split("\n");
  const line = JSON.stringify({ ts: new Date().toISOString(), agent: "a1", tool: "record", args: {}, result: { ok: true, seq: res.entry.seq, hash: res.entry.hash }, prev: sha(trace.at(-1)!) });
  await appendFile(join(r.root, P.EVENTS_REL), `${line}\n`);
}

