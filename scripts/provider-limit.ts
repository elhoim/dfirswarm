#!/usr/bin/env node
/**
 * The model provider's limit on every seat (docs/adr/0013, "The provider's
 * limit"). A subscription's usage limit refuses every seat at once, each
 * turn ending in an agent_error ("You have hit your ChatGPT usage limit (pro
 * plan). Try again in ~6904 min.", "Codex error: The usage limit has been
 * reached"). An until-solved run's watchdog then prompted every seat again,
 * half an hour apart, for days, every VM and the hub up, and the operator was
 * never told the run could not go on before a stated time.
 *
 * So the run pauses, whatever its stop policy, when every live seat's last
 * turn ended in a provider error since the last pause was lifted, and either
 * one of them was told to wait half an hour or more, or every one of them was
 * prompted again after its first error and failed again. One seat's error
 * never pauses the run. The harness tries again at the time the provider
 * named (every refused seat having named one: the earliest), or every half
 * hour when none is known, and the same rule pauses the run again if every
 * seat is refused again. Generic: nothing here names a provider; the only
 * reading of the words is the wait they state.
 *
 *   provider-limit.ts tick <sandbox> [--now ISO]
 *       the watchdog's pass: lift the pause when its try is due, or pause the
 *       run when the rule holds; one JSON line, {action: paused|lifted|none}
 *   provider-limit.ts wait <text> [--at ISO]
 *       the wait a provider's error text states, as JSON (null when none)
 */
import { existsSync } from "node:fs";
import { open } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";

// --- the wait a provider's words state ------------------------------------------------------

const UNITS: Array<[RegExp, number]> = [
  [/^(?:milliseconds?|msecs?|ms)$/i, 1],
  [/^(?:seconds?|secs?|s)$/i, 1_000],
  [/^(?:minutes?|mins?|m)$/i, 60_000],
  [/^(?:hours?|hrs?|h)$/i, 3_600_000],
  [/^(?:days?|d)$/i, 86_400_000],
];
const NUM = String.raw`\d+(?:\.\d+)?`;
const UNIT = "milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d";
const PART = String.raw`${NUM}\s*(?:${UNIT})(?![a-z])`;
/** One duration: "~6904 min", "6m0s", "1 hour 30 minutes", "1h, 30m". */
const DURATION = String.raw`(?:about\s+|approximately\s+|approx\.?\s+|~\s*)?(${PART}(?:\s*(?:,|and)?\s*${PART})*)`;
/** A wait said as one: "try again in", "retry after", "resets in", "available again in", "wait for". */
const SAID = new RegExp(String.raw`(?:try(?:ing)?\s+again|retry(?:ing)?|resets?|available(?:\s+again)?|wait(?:ing)?|resumes?|lifts?)\b[^.;\n]{0,24}?\b(?:in|after|for)\s+${DURATION}`, "i");
/** A Retry-After-style number: seconds. */
const RETRY_AFTER = new RegExp(String.raw`retry[-_ ]?after["']?\s*[:=]?\s*(${NUM})(?!\s*[a-z%]|\d|\.\d)`, "i");
/** A time with its zone: "2026-09-30T12:00:00Z", "2026-09-30 12:00 UTC", "…+03:00". */
const ISO = /\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)\s*(Z|UTC|[+-]\d{2}:?\d{2})\b/i;
/** "in N minutes" with nothing before it that says a wait, the last resort. */
const BARE = new RegExp(String.raw`\b(?:in|after)\s+${DURATION}`, "i");

function durationMs(text: string): number | null {
  let total = 0;
  let any = false;
  for (const m of text.matchAll(new RegExp(String.raw`(${NUM})\s*(${UNIT})(?![a-z])`, "gi"))) {
    const unit = UNITS.find(([re]) => re.test(m[2]));
    if (!unit) return null;
    total += Number(m[1]) * unit[1];
    any = true;
  }
  return any && total > 0 ? Math.round(total) : null;
}

export type ProviderWait = { until: number; wait_ms: number; said: string };

/**
 * The wait a provider's error text states, from `at` (when the error was
 * recorded): "try again in ~N min", "in N minutes", "in N hours", "retry
 * after N seconds", a Retry-After number (seconds), or a time with its zone
 * that is after `at`. The first of those forms the text holds, in that
 * order; null when it states none, or none still ahead.
 */
export function parseProviderWait(text: string, at: number): ProviderWait | null {
  if (!text) return null;
  const said = SAID.exec(text);
  if (said) {
    const ms = durationMs(said[1]);
    if (ms) return { until: at + ms, wait_ms: ms, said: said[0] };
  }
  const header = RETRY_AFTER.exec(text);
  if (header) {
    const ms = Math.round(Number(header[1]) * 1_000);
    if (ms > 0) return { until: at + ms, wait_ms: ms, said: header[0] };
  }
  const iso = ISO.exec(text);
  if (iso) {
    const zone = /^utc$/i.test(iso[3]) ? "Z" : iso[3].toUpperCase().replace(/^([+-]\d{2})(\d{2})$/, "$1:$2");
    const t = Date.parse(`${iso[1]}T${iso[2]}${zone}`);
    if (Number.isFinite(t) && t > at) return { until: t, wait_ms: t - at, said: iso[0] };
  }
  const bare = BARE.exec(text);
  if (bare) {
    const ms = durationMs(bare[1]);
    if (ms) return { until: at + ms, wait_ms: ms, said: bare[0] };
  }
  return null;
}

// --- the rule -------------------------------------------------------------------------------

/** One trace row as the rule reads it: who, what, when (the host's clock), and the fields it looks at. */
export type TraceRow = { agent: string; tool: string; at: number; args?: Record<string, unknown>; result?: Record<string, unknown> };

/**
 * Rows a seat's harness writes for it without the seat doing anything (the
 * idle watchdog's list), and a pause's own holds: none of them is a turn
 * that went anywhere.
 */
const BOOKKEEPING = new Set([
  "hub_prompt", "context", "thinking", "tool_loaded", "agent_start", "inputs_guard", "budget_precall_stop", "pause_hold",
  "self_compact", "compact_config", "compact_notice", "compact_warning", "compact_forced", "compact_hold",
  "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled", "compact_held",
]);

/** A prompt that reached the seat: the watchdog's nudge or wake, or the hub's delivery its extension recorded. */
function promptTo(row: TraceRow, id: string): boolean {
  if (row.agent === id) return row.tool === "hub_prompt" && row.result?.ok === true;
  return row.agent === "system" && (row.tool === "idle_nudge" || row.tool === "resume_wake") && row.args?.agent === id && row.result?.ok === true;
}

export type SeatLimit = {
  agent: string;
  /** Its last own row since the last lift is a provider error. */
  refused: boolean;
  model: string | null;
  /** The provider's words on its last error, whole. */
  reason: string | null;
  /** Its provider errors in a row, and when the first and the last were recorded. */
  errors: number;
  first_at: number | null;
  last_at: number | null;
  /** Prompted again after its first error, and refused again after that prompt. */
  retried: boolean;
  /** When it last did anything but fail (0: never). */
  worked_at: number;
  /** The wait its errors state, from the last one that states one, while still ahead. */
  until: number | null;
  wait_ms: number | null;
};

/** Where one seat stands: its provider errors in a row at the end of its trace, and what they said. */
export function seatLimit(rows: TraceRow[], id: string, since: number, now: number): SeatLimit {
  const own = rows.filter((r) => r.agent === id && !BOOKKEEPING.has(r.tool));
  let i = own.length - 1;
  while (i >= 0 && own[i].tool === "agent_error") i--;
  const streak = own.slice(i + 1);
  const last = streak.at(-1);
  const first = streak[0];
  const refused = Boolean(last && last === own.at(-1) && last.at > since);
  const reasonOf = (r: TraceRow) => String(r.result?.reason ?? "");
  let wait: ProviderWait | null = null;
  for (let k = streak.length - 1; k >= 0 && !wait; k--) wait = parseProviderWait(reasonOf(streak[k]), streak[k].at);
  const ahead = wait && wait.until > now ? wait : null;
  return {
    agent: id,
    refused,
    model: last ? String(last.args?.model ?? "") || null : null,
    reason: last ? reasonOf(last) : null,
    errors: streak.length,
    first_at: first?.at ?? null,
    last_at: last?.at ?? null,
    retried: Boolean(first && last && streak.length > 1 && rows.some((r) => promptTo(r, id) && r.at > first.at && r.at < last.at)),
    worked_at: i >= 0 ? own[i].at : 0,
    until: ahead?.until ?? null,
    wait_ms: ahead?.wait_ms ?? null,
  };
}

export type ProviderLimitVerdict = {
  pause: boolean;
  /** Why, or why not, in words. */
  why: string;
  seats: SeatLimit[];
  /** The models refused, and their distinct error texts, whole, one a line. */
  models: string[];
  detail: string;
  /** The earliest end the provider named, when it named one to every refused seat. */
  until: string | null;
  /** A seat worked since the last lift: a pause now begins a new spell. */
  worked_since: boolean;
};

/**
 * The rule. Paused when every live seat (not done, not dead) has, as its last
 * own row since the last lift (`since`), a provider error, and either one of
 * those errors states a wait of half an hour or more still ahead, or every
 * one of those seats was prompted again after its first error and refused
 * again. Pure: the rows are the trace's, in order.
 */
export function providerLimitVerdict(rows: TraceRow[], live: string[], o: { since: number; now: number }): ProviderLimitVerdict {
  const seats = live.map((id) => seatLimit(rows, id, o.since, o.now));
  const none = (why: string): ProviderLimitVerdict => ({ pause: false, why, seats, models: [], detail: "", until: null, worked_since: false });
  if (!seats.length) return none("no seat is live");
  const going = seats.filter((s) => !s.refused);
  if (going.length) return none(`${going.map((s) => s.agent).join(", ")} ${going.length === 1 ? "has" : "have"} no provider error as the last turn since ${o.since ? new Date(o.since).toISOString() : "the start"}`);
  const long = seats.filter((s) => s.wait_ms !== null && s.wait_ms >= P.PROVIDER_LIMIT_LONG_MS);
  const retried = seats.every((s) => s.retried);
  if (!long.length && !retried) {
    return none(`every live seat's last turn ended in a provider error, none was told to wait ${P.PROVIDER_LIMIT_LONG_MS / 60_000} minutes or more, and ${seats.filter((s) => !s.retried).map((s) => s.agent).join(", ")} ${seats.filter((s) => !s.retried).length === 1 ? "has" : "have"} not been refused again after a prompt`);
  }
  const ends = seats.map((s) => s.until);
  const until = ends.every((u): u is number => u !== null) ? new Date(Math.min(...ends)).toISOString() : null;
  const models = [...new Set(seats.map((s) => s.model).filter((m): m is string => Boolean(m)))];
  const detail = [...new Set(seats.map((s) => s.reason).filter((r): r is string => Boolean(r)))].join("\n");
  const why = long.length
    ? `every live seat's last turn ended in a provider error, and ${long[0].agent} was told to wait ${Math.round(long[0].wait_ms! / 60_000)} minutes`
    : "every live seat's last turn ended in a provider error, and each was refused again after it was prompted again";
  return { pause: true, why, seats, models, detail, until, worked_since: seats.some((s) => s.worked_at > o.since) };
}

// --- the trace, read from its end -----------------------------------------------------------

/** The trace's lines from the last to the first, split on newlines before decoding. */
async function* linesBackward(path: string, chunk = 256 * 1024): AsyncGenerator<string> {
  const fh = await open(path, "r").catch(() => null);
  if (!fh) return;
  try {
    let pos = (await fh.stat()).size;
    let carry = Buffer.alloc(0);
    while (pos > 0) {
      const len = Math.min(chunk, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, pos);
      const data = Buffer.concat([buf, carry]);
      let end = data.length;
      for (let i = data.length - 1; i >= 0; i--) {
        if (data[i] !== 0x0a) continue;
        if (end > i + 1) yield data.subarray(i + 1, end).toString("utf8");
        end = i;
      }
      carry = Buffer.from(data.subarray(0, end));
    }
    if (carry.length) yield carry.toString("utf8");
  } finally {
    await fh.close();
  }
}

/**
 * The rows the rule reads for these seats, in trace order: each seat's own,
 * and the prompts that reached it. Read from the end only as far as needed:
 * it stops at once when a seat's last own row is not a provider error since
 * `since` (the run is not paused then), and otherwise at the row before each
 * seat's errors in a row.
 */
export async function readSeatRows(sandbox: string, seats: string[], since: number): Promise<TraceRow[]> {
  const want = new Set(seats);
  const seen = new Set<string>();
  const settled = new Set<string>();
  const out: TraceRow[] = [];
  for await (const line of linesBackward(join(sandbox, P.EVENTS_REL))) {
    if (!line.trim()) continue;
    let e: { agent?: string; tool?: string; ts?: string; recv_ts?: string; args?: Record<string, unknown>; result?: Record<string, unknown> };
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    const agent = String(e.agent ?? "");
    const tool = String(e.tool ?? "");
    const about = agent === "system" ? String(e.args?.agent ?? "") : agent;
    if (!want.has(about)) continue;
    const at = Date.parse(e.recv_ts || e.ts || "");
    if (!Number.isFinite(at)) continue;
    out.push({ agent, tool, at, ...(e.args ? { args: e.args } : {}), ...(e.result && typeof e.result === "object" ? { result: e.result } : {}) });
    if (agent === "system" || BOOKKEEPING.has(tool)) continue;
    if (!seen.has(agent)) {
      seen.add(agent);
      // Its last own row is not a provider error since the last lift: nothing to pause.
      if (tool !== "agent_error" || at <= since) break;
    } else if (tool !== "agent_error") {
      settled.add(agent);
      if (settled.size === want.size) break;
    }
  }
  return out.reverse();
}

/** The seats still in the run: on the team, with no done or dead marker. */
export async function liveSeats(sandbox: string): Promise<string[]> {
  const team = await P.readTeam(sandbox).catch(() => null);
  return (team?.agents ?? []).map((a) => a.id).filter((id) => !existsSync(P.agentDonePath(sandbox, id)) && !existsSync(P.agentDeadPath(sandbox, id)));
}

// --- the watchdog's pass --------------------------------------------------------------------

export type ProviderLimitTick =
  | { action: "none"; why: string; retry_at?: string }
  | { action: "lifted"; pause: P.PauseRecord }
  | { action: "paused"; pause: P.PauseRecord; spell: "new" | "continued"; why: string; retry_at: string; seats: Array<Pick<SeatLimit, "agent" | "model" | "errors" | "retried"> & { until: string | null }> };

/**
 * One pass, as the idle watchdog makes it every interval: under a pause for
 * the provider's limit, lift it when its try is due; otherwise pause the run
 * when the rule holds. Both under the table lock (pauseRun re-reads the rule
 * there, liftProviderLimit the time), so two watchdogs never both act. A new
 * spell is said on the board once; a pause that follows the harness's own
 * try, no seat having worked since, continues the spell before it and is not
 * said again (nor told again: the notice is claimed per spell).
 */
export async function providerLimitTick(sandbox: string, now = Date.now()): Promise<ProviderLimitTick> {
  if ((await P.swarmDoneExists(sandbox)) || existsSync(join(sandbox, P.STOPPED_REL)) || existsSync(join(sandbox, P.ALL_DEAD_REL))) return { action: "none", why: "the run has ended" };
  const budget = await P.readBudget(sandbox).catch(() => null);
  if (!budget) return { action: "none", why: "budget.json does not read" };
  if (budget.paused) {
    if (budget.paused.reason !== "provider_limit") return { action: "none", why: `paused for ${P.pauseReasonWords(budget.paused)}` };
    const lifted = await P.liftProviderLimit(sandbox, now);
    if (lifted) return { action: "lifted", pause: lifted };
    return { action: "none", why: "paused for the model provider's limit", retry_at: new Date(P.providerLimitRetryAt(budget.paused)).toISOString() };
  }
  const live = await liveSeats(sandbox);
  const decide = async (b: P.BudgetRecord) => {
    const lastLift = b.pauses?.at(-1)?.resumed_at;
    const since = lastLift ? Date.parse(lastLift) || 0 : 0;
    return providerLimitVerdict(await readSeatRows(sandbox, live, since), live, { since, now });
  };
  const v = await decide(budget);
  if (!v.pause) return { action: "none", why: v.why };
  const before = budget.pauses?.at(-1);
  const spell = !v.worked_since && before?.reason === "provider_limit" && before.resumed_by === "harness" ? (before.since ?? before.at) : undefined;
  const p = await P.pauseRun(sandbox, "provider_limit", v.detail, now, {
    by: "harness",
    models: v.models,
    ...(v.until ? { until: v.until } : {}),
    ...(spell ? { since: spell } : {}),
    recheck: async (b) => (await decide(b)).pause,
  });
  if (!p.paused) return { action: "none", why: p.already ? "the run is paused already" : "a seat came back before the pause was written" };
  const pause = (await P.readBudget(sandbox)).paused!;
  if (!spell) await P.systemPost(sandbox, { tag: "stop", body: P.providerLimitPost(pause) }).catch(() => undefined);
  return {
    action: "paused",
    pause,
    spell: spell ? "continued" : "new",
    why: v.why,
    retry_at: new Date(P.providerLimitRetryAt(pause)).toISOString(),
    seats: v.seats.map((s) => ({ agent: s.agent, model: s.model, errors: s.errors, retried: s.retried, until: s.until ? new Date(s.until).toISOString() : null })),
  };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, arg, ...rest] = argv;
  const emit = (o: unknown) => process.stdout.write(`${JSON.stringify(o)}\n`);
  const at = (name: string): number => {
    const v = opt(rest, name);
    if (v === undefined) return Date.now();
    const t = Date.parse(v);
    if (!Number.isFinite(t)) throw new Error(`${name} takes an ISO time (got ${JSON.stringify(v)})`);
    return t;
  };
  try {
    if (cmd === "tick" && arg) {
      emit(await providerLimitTick(resolve(arg), at("--now")));
      return 0;
    }
    if (cmd === "wait" && arg !== undefined) {
      const from = at("--at");
      const w = parseProviderWait(arg, from);
      emit(w ? { until: new Date(w.until).toISOString(), wait_ms: w.wait_ms, said: w.said } : null);
      return 0;
    }
  } catch (err) {
    emit({ action: "none", why: (err as Error).message });
    return 1;
  }
  process.stderr.write("usage: provider-limit.ts tick <sandbox> [--now ISO] | wait <text> [--at ISO]\n");
  return 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}
