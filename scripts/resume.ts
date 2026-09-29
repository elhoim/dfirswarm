#!/usr/bin/env node
/**
 * Resuming a run (swarm.sh resume, docs/adr/0013): the same run goes on, in
 * the same sandbox, on the same chains, after a stop or a seal.
 *
 * Nothing the run recorded is rewritten. The ledger, the registers, the trace
 * and the store journal are append-only chains: the continuation appends to
 * them, so every earlier seal (a custody verdict, a release) still verifies
 * as a prefix of what they hold after it, and custody-verify and release
 * verify say so. What marked the run as ended (the sentinel, the operator's
 * STOPPED, the seats' done files, the reaper's ALL_AGENTS_DEAD, the abandon
 * votes) is moved, whole, to done/history/<k>/; the first segment's VM
 * records to vm/earlier-<k>/ and its kept disks beside the snapshots to
 * earlier-<k>/, so the continuation's never overwrite them. The wall clock
 * counts on from where the run stopped, the caps are extended when asked,
 * and a run that would still be over a cap is refused before anything moves.
 *
 * Each seat starts again from its last hand-off note or compaction summary
 * (read from its own Pi sessions, whole, into inbox/<id>/resume.md) with
 * the register, the questions and the ledger as they stand. The resume is
 * the operator's act: on the operator's record (swarm.sh), in budget.json
 * (resumes), and in the custody anchor beside the run (resumes), which is
 * what lets an earlier seal verify as a prefix.
 *
 *   resume.ts prepare <sandbox> --run ID [--by WHO] [--minutes N] [--tokens N] [--usd N]
 *   resume.ts handoff <sandbox> <agent>
 *
 * Prints one JSON line.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { anchorResume, custodyAnchorPath } from "./custody.ts";
import { FETCH_LOG, GRANTS_LOG } from "./net-grants.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** The files that say a run has ended, each moved to done/history/<k>/ on a resume. */
const ENDED = ["SWARM_DONE", "STOPPED", "ALL_AGENTS_DEAD"];

/** The next free done/history/<k>. */
async function nextSegment(sandbox: string): Promise<number> {
  const names = await readdir(join(sandbox, "done", "history")).catch(() => [] as string[]);
  return Math.max(0, ...names.map((n) => Number(/^(\d+)$/.exec(n)?.[1] ?? 0))) + 1;
}

/** When the run's last stretch ended: its stop or its sentinel, else its last trace line, never later than now. */
async function endedAt(sandbox: string, now: number): Promise<number> {
  const o = await P.runOutcome(sandbox).catch(() => null);
  const said = o?.at ? Date.parse(o.at) : NaN;
  if (Number.isFinite(said)) return Math.min(said, now);
  const text = await readFile(join(sandbox, P.EVENTS_REL), "utf8").catch(() => "");
  const last = text.trimEnd().split("\n").at(-1) ?? "";
  try {
    const e = JSON.parse(last) as { ts?: string; recv_ts?: string };
    const t = Date.parse(e.recv_ts || e.ts || "");
    if (Number.isFinite(t)) return Math.min(t, now);
  } catch {
    // no readable last line
  }
  return now;
}

export type Handoff = { agent: string; kind: "hand-off note" | "compaction summary"; text: string; at: string; file: string } | { agent: string; kind: null };

/**
 * A seat's last hand-off: the newest self-compaction note (the seat's own
 * words, verbatim) or compaction summary in its Pi sessions, whichever is
 * later. Read whole; nothing is cut. None when the seat never compacted.
 */
export async function lastHandoff(sandbox: string, agent: string): Promise<Handoff> {
  const dir = join(sandbox, ".pi-sessions", agent);
  const files: string[] = [];
  const walk = async (d: string, depth: number) => {
    if (depth > 4) return;
    for (const n of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      const p = join(d, n.name);
      if (n.isDirectory()) await walk(p, depth + 1);
      else if (n.isFile() && n.name.endsWith(".jsonl")) files.push(p);
    }
  };
  await walk(dir, 0);
  let best: { kind: "hand-off note" | "compaction summary"; text: string; at: string; file: string } | null = null;
  for (const file of files.sort()) {
    const text = await readFile(file, "utf8").catch(() => "");
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      let e: { type?: string; customType?: string; summary?: unknown; details?: { note?: unknown }; timestamp?: string };
      try {
        e = JSON.parse(line);
      } catch {
        continue;
      }
      const at = e.timestamp ?? "";
      let got: { kind: "hand-off note" | "compaction summary"; text: string } | null = null;
      if (e.type === "custom_message" && e.customType === "self-compact-handoff" && typeof e.details?.note === "string" && e.details.note.trim()) got = { kind: "hand-off note", text: e.details.note };
      else if (e.type === "compaction" && typeof e.summary === "string" && e.summary.trim()) got = { kind: "compaction summary", text: e.summary };
      if (got && (!best || at >= best.at)) best = { ...got, at, file: file.slice(sandbox.length + 1) };
    }
  }
  return best ? { agent, ...best } : { agent, kind: null };
}

/**
 * Prepare a resume: the budget first (checked, nothing moves if the run
 * would still be over a cap), then what marked the end moved aside, the
 * budget written, each seat's last hand-off put where it starts from, and
 * the resume anchored beside the run.
 */
export async function prepareResume(sandbox: string, o: { run: string; by: string; minutes?: number; tokens?: number; usd?: number; now?: number }): Promise<Record<string, unknown>> {
  const now = o.now ?? Date.now();
  const before = await P.runOutcome(sandbox).catch(() => ({ outcome: null, by: null, at: null, why: null }));
  const from = before.outcome ?? (existsSync(join(sandbox, "done", "ALL_AGENTS_DEAD")) ? "ended with every agent dead" : "stopped from outside");
  const end = await endedAt(sandbox, now);
  // The budget, in memory: the wall clock to where the run stopped, the caps extended, the stop's marks cleared.
  const budget = await P.readBudget(sandbox);
  for (const [k, v] of Object.entries({ minutes: o.minutes, tokens: o.tokens, usd: o.usd })) if (v !== undefined && (!Number.isFinite(v) || v <= 0)) throw new Error(`--${k} takes a number above zero (got ${v})`);
  const used = P.wallElapsedMs(budget, budget.paused ? Date.parse(budget.paused.at) : end);
  const next: P.BudgetRecord = { ...budget };
  if (next.paused) {
    next.pauses = [...(next.pauses ?? []), { ...next.paused, resumed_at: new Date(now).toISOString(), resumed_by: `${o.by} (resume)` }];
    delete next.paused;
  }
  next.wall_used_ms = used;
  next.wall_base_at = new Date(now).toISOString();
  const set: Partial<Record<P.CapField, number>> = {};
  if (o.minutes) set.wall_clock_minutes = next.wall_clock_minutes + o.minutes;
  if (o.tokens) {
    if (!(Number(next.cap_tokens) > 0)) throw new Error("--tokens: this run has no token cap to extend");
    set.cap_tokens = Math.max(Number(next.cap_tokens), next.tokens) + o.tokens;
  }
  if (o.usd) {
    if (next.metered === false) throw new Error("--usd: this team's dollars are not charged; extend --tokens instead");
    set.cap_usd = Number((Math.max(next.cap_usd, next.spent_usd) + o.usd).toFixed(6));
  }
  Object.assign(next, set);
  next.cap_steer_sent = false;
  delete next.stop_steer_at;
  delete next.stop_reason;
  const pressure = P.budgetPressure(next, now);
  if (pressure.reason) {
    const over = pressure.reason === "wall_clock" ? `its wall clock (${Math.round(used / 60_000)} of ${next.wall_clock_minutes} minutes used): give --minutes N` : P.overCap(next).by === "tokens" ? `its token cap (${next.tokens} of ${next.cap_tokens}): give --tokens N` : `its dollar cap ($${next.spent_usd} of $${next.cap_usd}): give --usd N`;
    throw new Error(`the run would resume over ${over}; nothing was changed`);
  }
  next.resumes = [...(next.resumes ?? []), { at: new Date(now).toISOString(), by: o.by, from }];
  if (Object.keys(set).length) next.cap_changes = [...(next.cap_changes ?? []), { at: new Date(now).toISOString(), by: `${o.by} (resume)`, set, caps: P.capFingerprint(P.normalizeBudget(next)) }];
  const k = await nextSegment(sandbox);
  // The report bytes every release binds, kept by their digest before the
  // continuation can write its own report: an earlier release verifies
  // against them (content-addressed and read-only; a second resume keeps
  // nothing twice).
  const kept = await keepBoundBytes(sandbox);
  // Anchored beside the run, outside it, first: the resume is on record, at
  // the chains' heads as it found them, before anything of the run moves.
  // An anchor that cannot be written refuses the resume with nothing changed.
  const heads = await chainHeads(sandbox);
  try {
    anchorResume(sandbox, { at: new Date(now).toISOString(), by: o.by, from, segment: k, heads });
  } catch (err) {
    throw new Error(`the resume could not be anchored beside the run (${(err as Error).message}); nothing was changed`);
  }
  const anchored = custodyAnchorPath(sandbox);
  // What marked the end, moved whole.
  const hist = join(sandbox, "done", "history", String(k));
  const moved: string[] = [];
  const move = async (from: string, to: string) => {
    if (!existsSync(from)) return;
    await mkdir(join(to, ".."), { recursive: true });
    await rename(from, to);
    moved.push(`${from.slice(sandbox.length + 1)} -> ${to.slice(sandbox.length + 1)}`);
  };
  await mkdir(hist, { recursive: true });
  for (const f of ENDED) await move(join(sandbox, "done", f), join(hist, f));
  await move(join(sandbox, "done", "agents"), join(hist, "agents"));
  await move(join(sandbox, "done", "abandon"), join(hist, "abandon"));
  await mkdir(join(sandbox, "done", "agents"), { recursive: true });
  // The first segment's VM records and kept disks: the continuation's VMs have the same names.
  const vmDir = join(sandbox, "vm");
  if (existsSync(vmDir)) {
    for (const n of (await readdir(vmDir)).filter((x) => !x.startsWith("earlier-") && !x.startsWith("."))) {
      if ((await stat(join(vmDir, n))).isFile()) await move(join(vmDir, n), join(vmDir, `earlier-${k}`, n));
    }
  }
  const snaps = `${sandbox}.vm-snapshots`;
  if (existsSync(snaps)) {
    for (const n of (await readdir(snaps)).filter((x) => !x.startsWith("earlier-") && !x.startsWith("."))) {
      await mkdir(join(snaps, `earlier-${k}`), { recursive: true });
      await rename(join(snaps, n), join(snaps, `earlier-${k}`, n));
      moved.push(`${n} (a kept disk) -> ${snaps.slice(snaps.lastIndexOf("/") + 1)}/earlier-${k}/${n}`);
    }
  }
  await P.withTableLock(sandbox, async (held) => {
    await held.assertOwned();
    await P.writeBudget(sandbox, next);
  });
  // Where each seat starts from: its last hand-off, whole, beside its inbox.
  const team = await P.readTeam(sandbox);
  const handoffs: Array<Record<string, unknown>> = [];
  for (const a of team.agents) {
    const h = await lastHandoff(sandbox, a.id);
    const file = join(sandbox, "inbox", a.id, "resume.md");
    await mkdir(join(sandbox, "inbox", a.id), { recursive: true });
    const body = h.kind
      ? `# Where you were when the run stopped\n\nYour last ${h.kind}, written at ${h.at} (${h.file}), whole:\n\n${h.text}\n`
      : "# Where you were when the run stopped\n\nYou left no hand-off note and no compaction summary. Start from the register: leads (mine, open), questions, the ledger and the board.\n";
    await writeFile(file, body, "utf8");
    handoffs.push({ agent: a.id, kind: h.kind, ...(h.kind ? { chars: h.text.length, at: h.at } : {}), file: `inbox/${a.id}/resume.md`, sha256: sha256(body) });
  }
  // The follow-ups recorded after the done (the question register's after_done) are the continuation's work: one event names them.
  const followUps = await Q.continueFollowUps(sandbox, { segment: k, by: o.by }).catch((err: Error) => `not taken up: ${err.message}`);
  return { ok: true, run: o.run, from, segment: k, moved, wall_used_minutes: Math.round(used / 60_000), set, handoffs, anchored, heads, kept, follow_ups: followUps };
}

/**
 * Keep the report bytes each release binds (its record's report.markdown,
 * the swarm's work/report.md as it was sealed) at release/bound/<sha256>,
 * read-only, when the file still holds them. What was kept, by path.
 */
export async function keepBoundBytes(sandbox: string): Promise<string[]> {
  const out: string[] = [];
  const dir = join(sandbox, "release");
  for (const v of (await readdir(dir).catch(() => [] as string[])).filter((n) => /^v\d+$/.test(n))) {
    let rec: { report?: { markdown?: { path?: string; sha256?: string } | null } };
    try {
      rec = JSON.parse(await readFile(join(dir, v, "release.json"), "utf8"));
    } catch {
      continue;
    }
    const md = rec.report?.markdown;
    if (!md?.path || !md.sha256 || !/^[0-9a-f]{64}$/.test(md.sha256)) continue;
    const target = join(dir, "bound", md.sha256);
    const rel = `release/bound/${md.sha256}`;
    if (existsSync(target)) {
      if (!out.includes(rel)) out.push(rel);
      continue;
    }
    const bytes = await readFile(join(sandbox, md.path)).catch(() => null);
    if (!bytes || sha256(bytes) !== md.sha256) continue;
    await mkdir(join(dir, "bound"), { recursive: true });
    await writeFile(target, bytes, { mode: 0o444, flag: "wx" });
    out.push(rel);
  }
  return out;
}

/** The chains' lengths and heads as the resume found them: what the first segment's seals are prefixes of. */
async function chainHeads(sandbox: string): Promise<Record<string, { lines: number; head: string | null }>> {
  const text = (rel: string) => (existsSync(join(sandbox, rel)) ? readFileSync(join(sandbox, rel), "utf8") : "");
  const lastHash = (t: string): { lines: number; head: string | null } => {
    const lines = t.split("\n").filter((l) => l.trim());
    let head: string | null = null;
    try {
      head = lines.length ? ((JSON.parse(lines.at(-1)!) as { hash?: string }).hash ?? null) : null;
    } catch {
      head = null;
    }
    return { lines: lines.length, head };
  };
  const trace = text(P.EVENTS_REL).split("\n").filter((l) => l.trim());
  return {
    ledger: lastHash(text(P.LEDGER_ENTRIES)),
    attestations: lastHash(text(P.LEDGER_ATTESTATIONS)),
    disputes: lastHash(text(P.LEDGER_DISPUTES)),
    leads: lastHash(text("leads/leads.jsonl")),
    questions: lastHash(text("questions/questions.jsonl")),
    grants: lastHash(text(GRANTS_LOG)),
    fetches: lastHash(text(FETCH_LOG)),
    // The operator requests' chain (extensions/requests.ts), which custody seals and an earlier verdict holds as a prefix.
    requests: lastHash(text("requests/requests.jsonl")),
    // The store sweeps and the finish register, which custody seals the same way.
    sweeps: lastHash(text("ledger/sweeps.jsonl")),
    finish: lastHash(text("leads/finish.jsonl")),
    trace: { lines: trace.length, head: trace.length ? sha256(trace.at(-1)!) : null },
  };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, sandboxArg, ...rest] = argv;
  const emit = (x: unknown) => process.stdout.write(`${JSON.stringify(x)}\n`);
  if (!cmd || !sandboxArg) {
    process.stderr.write("usage: resume.ts prepare <sandbox> --run ID [--by WHO] [--minutes N] [--tokens N] [--usd N]\n       resume.ts handoff <sandbox> <agent>\n");
    return 2;
  }
  const sandbox = resolve(sandboxArg);
  const num = (name: string) => (opt(rest, name) === undefined ? undefined : Number(opt(rest, name)));
  try {
    if (cmd === "prepare") {
      const run = opt(rest, "--run");
      if (!run) throw new Error("--run ID is required");
      emit(await prepareResume(sandbox, { run, by: opt(rest, "--by") ?? "operator", minutes: num("--minutes"), tokens: num("--tokens"), usd: num("--usd") }));
      return 0;
    }
    if (cmd === "handoff") {
      emit(await lastHandoff(sandbox, rest[0] ?? ""));
      return 0;
    }
    process.stderr.write(`resume.ts: unknown command ${cmd}\n`);
    return 2;
  } catch (err) {
    emit({ ok: false, reason: (err as Error).message });
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}
