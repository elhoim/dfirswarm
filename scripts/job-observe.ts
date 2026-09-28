/**
 * EXPERIMENTAL and UNTESTED in a worker VM: reading what scripts/job-observe.py
 * wrote from inside a job's worker (fanotify), and saying how far it can be
 * trusted. Off unless the hub runs with SWARM_JOB_OBSERVE=fanotify-experimental;
 * when off, custody says a declared job's reads within its scope are not
 * observed. Never LD_PRELOAD, and never a log the job itself could write, as
 * evidence of what it read.
 *
 * The log is read as `unknown` unless the collector started, marked every
 * mount, verified line by line (its HMAC key is root's in the worker; the job
 * runs unprivileged), saw the canary the hub planted read before and after
 * the job, and ended cleanly; `partial` when events were dropped (a queue
 * overflow), a mount could not be marked, the collector stalled, or a read
 * outside the declared scope was seen; `complete` only when none of these.
 * What it lists is what was opened (and read through read(2)); a read
 * through mmap shows only as the open.
 */
import { createHmac } from "node:crypto";

export const OBSERVE_ENV = "SWARM_JOB_OBSERVE";
export const OBSERVE_FLAG = "fanotify-experimental";
/** The mount the collector writes to in the worker: not $OUT, and root's alone there. */
export const OBSERVE_GUEST = "/observe";
/** The file the hub plants in a job's view, read by the job's own user before and after its command. */
export const CANARY_NAME = ".observe-canary";

export function observeWanted(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[OBSERVE_ENV] === OBSERVE_FLAG;
}

export type Observation = {
  status: "complete" | "partial" | "unknown";
  /** Every reason it is not complete, in the order found. */
  reasons: string[];
  /** Each path opened, the first line that says so, and what was seen of it. */
  opened: Array<{ path: string; first: number; what: string[] }>;
  /** Paths seen that are not in the declared scope (a view makes these impossible; seen, they say something is wrong). */
  escapes: string[];
  overflow: number;
  lines: number;
  kernel: string | null;
};

type Line = { kind?: string; seq?: number; t?: number; prev?: string; mac?: string; path?: string; what?: string[]; unsupported?: string; marks?: Array<{ mount: string; ok: boolean; error?: string }>; kernel?: string; events?: number; overflow?: number };

/**
 * Read a collector's log. `key` is the hex key it wrote (null: not found,
 * and nothing verifies), `scope` the guest paths the job was given (a path
 * under none of them is an escape), `canary` the canary's guest path, which
 * must be seen opened at least twice (before and after the job's command).
 */
export function readObservation(text: string | null, key: string | null, o: { scope: string[]; canary: string; maxGapMs?: number }): Observation {
  const out: Observation = { status: "unknown", reasons: [], opened: [], escapes: [], overflow: 0, lines: 0, kernel: null };
  const unknown = (why: string) => {
    out.status = "unknown";
    out.reasons.push(why);
    return out;
  };
  if (!text || !text.trim()) return unknown("the collector wrote nothing: it did not start");
  if (!key || !/^[0-9a-f]{64}$/.test(key.trim())) return unknown("the collector's key is missing: no line can be verified");
  const k = Buffer.from(key.trim(), "hex");
  const raw = text.split("\n").filter((l) => l.length);
  const lines: Line[] = [];
  let prev = "";
  for (let i = 0; i < raw.length; i += 1) {
    let rec: Line & Record<string, unknown>;
    try {
      rec = JSON.parse(raw[i]) as Line & Record<string, unknown>;
    } catch {
      return unknown(`line ${i + 1} is not JSON: the log was cut or altered`);
    }
    const { mac, ...body } = rec;
    const canonical = JSON.stringify(sortKeys(body));
    const want = createHmac("sha256", k).update(canonical).digest("hex");
    if (mac !== want) return unknown(`line ${i + 1} does not verify: the log was altered, or written by something other than the collector`);
    if (rec.seq !== i || rec.prev !== prev) return unknown(`line ${i + 1} is out of order or a line before it is missing`);
    prev = String(mac);
    lines.push(rec);
  }
  out.lines = lines.length;
  const start = lines[0];
  if (start?.kind !== "start") return unknown("the log does not begin with the collector's start");
  out.kernel = start.kernel ?? null;
  if (start.unsupported) return unknown(`fanotify is not available in this worker: ${start.unsupported}`);
  const partial: string[] = [];
  for (const m of start.marks ?? []) if (!m.ok) partial.push(`${m.mount} could not be marked (${m.error ?? "error"}): reads there were not seen`);
  if (!(start.marks ?? []).some((m) => m.ok)) return unknown("no mount could be marked");
  const end = lines.at(-1);
  if (end?.kind !== "end") return unknown("the log has no end: the collector died or was killed before the job ended");
  // t is the collector's monotonic clock in microseconds.
  const gap = (o.maxGapMs ?? 5000) * 1000;
  let canary = 0;
  const seen = new Map<string, { first: number; what: Set<string> }>();
  for (let i = 1; i < lines.length; i += 1) {
    const l = lines[i];
    if (typeof l.t === "number" && typeof lines[i - 1].t === "number" && l.t - (lines[i - 1].t as number) > gap) partial.push(`the collector stalled for ${Math.round((l.t - (lines[i - 1].t as number)) / 1000)} ms before line ${i + 1}`);
    if (l.kind === "overflow") out.overflow += 1;
    if (l.kind !== "event" || typeof l.path !== "string") continue;
    if (l.path === o.canary) {
      if ((l.what ?? []).includes("open")) canary += 1;
      continue;
    }
    const s = seen.get(l.path) ?? { first: i, what: new Set<string>() };
    for (const w of l.what ?? []) s.what.add(w);
    seen.set(l.path, s);
    // In scope: a declared object, a file under a declared directory, or a directory on the way to one (a listing).
    const bare = l.path.replace(/ \(deleted\)$/, "");
    if (!o.scope.some((p) => bare === p || bare.startsWith(`${p}/`) || p.startsWith(`${bare}/`)) && !out.escapes.includes(l.path)) out.escapes.push(l.path);
  }
  out.opened = [...seen].map(([path, s]) => ({ path, first: s.first, what: [...s.what].sort() }));
  if (canary < 2) return unknown(`the canary was seen opened ${canary} time(s), not the 2 the job's user made: this kernel or file system does not report these reads`);
  if (out.overflow) partial.push(`the kernel's queue overflowed ${out.overflow} time(s): events were dropped`);
  if (out.escapes.length) partial.push(`${out.escapes.length} path(s) outside the declared scope were seen: ${out.escapes.slice(0, 5).join(", ")}`);
  out.reasons.push(...partial);
  out.status = partial.length ? "partial" : "complete";
  return out;
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]));
  return v;
}

/**
 * The lines run.sh gains with observation on: the collector started as root
 * over the given mounts, the canary read by the job's user, the command run
 * as that user (nobody), the canary read again, the collector stopped.
 * $OUT is opened to the job's user first.
 */
export function observedRun(o: { mounts: string[]; canary: string; cmd: string; user?: string }): string[] {
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const as = `setpriv --reuid=${o.user ?? "65534"} --regid=${o.user ?? "65534"} --clear-groups --`;
  return [
    `python3 /job/observe.py ${OBSERVE_GUEST} ${o.mounts.map(q).join(" ")} & OBSERVER=$!`,
    "sleep 0.5",
    'chmod 0777 "$OUT"',
    `${as} cat ${q(o.canary)} > /dev/null`,
    `${as} ${o.cmd}`,
    "echo $? > /job/exit",
    `${as} cat ${q(o.canary)} > /dev/null`,
    'kill -TERM "$OBSERVER"; wait "$OBSERVER"',
  ];
}
