/**
 * swarm.sh cap: change a live run's caps and tell the swarm.
 *
 *   node scripts/caps.ts <sandbox> [--by NAME] [--usd N] [--tokens N]
 *        [--per-agent-usd N] [--per-agent-tokens N] [--wall-clock MIN]
 *        [--token-alert N[,M...] | none]
 *
 * The change is made under the table lock the usage folds take (setCaps), so
 * the hub's and every seat's next fold keeps it, and is kept in budget.json's
 * cap_changes with the caps it left. A stop steer the run is no longer over is
 * withdrawn, and the board is told either way. Prints one JSON line.
 * --token-alert sets the operator's token marks again (setTokenAlerts): they
 * brake nothing, so they change alone or beside a cap; a mark the run has
 * crossed already is told at the next round.
 */
import * as P from "../extensions/protocol.ts";

const FLAGS: Record<string, P.CapField> = {
  "--usd": "cap_usd",
  "--tokens": "cap_tokens",
  "--per-agent-usd": "cap_per_agent_usd",
  "--per-agent-tokens": "cap_per_agent_tokens",
  "--wall-clock": "wall_clock_minutes",
};

const LABELS: Record<P.CapField, (v: number | null | undefined) => string> = {
  cap_usd: (v) => (v ? `$${v}` : "none"),
  cap_tokens: (v) => (v ? `${v.toLocaleString("en-US")} tokens` : "none"),
  cap_per_agent_usd: (v) => (v ? `$${v} per agent` : "none"),
  cap_per_agent_tokens: (v) => (v ? `${v.toLocaleString("en-US")} tokens per agent` : "none"),
  wall_clock_minutes: (v) => `${v ?? "?"} minutes`,
};

const NAMES: Record<P.CapField, string> = {
  cap_usd: "the spend cap",
  cap_tokens: "the token cap",
  cap_per_agent_usd: "the per-agent spend cap",
  cap_per_agent_tokens: "the per-agent token cap",
  wall_clock_minutes: "the wall clock",
};

function fail(error: string): never {
  process.stdout.write(`${JSON.stringify({ ok: false, error })}\n`);
  process.exit(1);
}

const [sandbox, ...rest] = process.argv.slice(2);
if (!sandbox) fail("usage: caps.ts <sandbox> [--by NAME] [--usd N] [--tokens N] [--per-agent-usd N] [--per-agent-tokens N] [--wall-clock MIN] [--token-alert N[,M...] | none]");
let by = "operator";
const set: Partial<Record<P.CapField, number>> = {};
let marks: number[] | null = null;
for (let i = 0; i < rest.length; i += 2) {
  const flag = rest[i];
  const value = rest[i + 1];
  if (value === undefined) fail(`${flag} needs a value`);
  if (flag === "--by") {
    by = value;
    continue;
  }
  if (flag === "--token-alert") {
    marks = P.parseTokenMarks(value);
    if (!marks) fail(`--token-alert takes token counts, comma-separated, each a whole number or one with k, M or G (200M,1.4G), or none (got ${value})`);
    continue;
  }
  const field = FLAGS[flag];
  if (!field) fail(`unknown option ${flag}`);
  const n = Number(value);
  if (!/^\d+(\.\d+)?$/.test(value) || !Number.isFinite(n)) fail(`${flag} must be a number (got ${value})`);
  set[field] = n;
}

const markWords = (m: number[]) => (m.length ? m.map((n) => n.toLocaleString("en-US")).join(" · ") : "none");

try {
  if (!Object.keys(set).length && !marks) fail("no cap to set: give --usd, --tokens, --per-agent-usd, --per-agent-tokens, --wall-clock or --token-alert");
  const capped = Object.keys(set).length ? await P.setCaps(sandbox, set, by) : null;
  const alerted = marks ? await P.setTokenAlerts(sandbox, marks, by) : null;
  const changes = capped
    ? (Object.keys(set) as P.CapField[]).map((k) => `${NAMES[k]} from ${LABELS[k](capped.before[k])} to ${LABELS[k](capped.budget[k] as number | undefined)}`)
    : [];
  if (alerted) changes.push(`the token alerts from ${markWords(alerted.before)} to ${markWords(alerted.after)} (advisory: a mark the run has crossed already is told at the next round)`);
  const body =
    `The ${by} changed ${changes.join(", ")}.` +
    (capped?.withdrawn ? " The stop is withdrawn: the run goes on, so carry on with what you were doing." : "") +
    (capped?.resumed ? ` The pause (${capped.resumed.reason}, since ${capped.resumed.at}) is lifted: the run goes on.` : "");
  await P.systemPost(sandbox, { tag: "ask", to: "all", body }).catch(() => undefined);
  const after = {
    ...(capped ? Object.fromEntries((Object.keys(set) as P.CapField[]).map((k) => [k, capped.budget[k] ?? null])) : {}),
    ...(alerted ? { token_alerts: alerted.after.length ? alerted.after : null } : {}),
  };
  const before = { ...(capped?.before ?? {}), ...(alerted ? { token_alerts: alerted.before.length ? alerted.before : null } : {}) };
  process.stdout.write(`${JSON.stringify({ ok: true, by, before, after, withdrawn: capped?.withdrawn ?? false, ...(capped?.resumed ? { resumed: capped.resumed } : {}), said: body })}\n`);
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}
