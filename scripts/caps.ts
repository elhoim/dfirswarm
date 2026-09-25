/**
 * swarm.sh cap: change a live run's caps and tell the swarm.
 *
 *   node scripts/caps.ts <sandbox> [--by NAME] [--usd N] [--tokens N]
 *        [--per-agent-usd N] [--per-agent-tokens N] [--wall-clock MIN]
 *
 * The change is made under the table lock the usage folds take (setCaps), so
 * the hub's and every seat's next fold keeps it, and is kept in budget.json's
 * cap_changes with the caps it left. A stop steer the run is no longer over is
 * withdrawn, and the board is told either way. Prints one JSON line.
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
if (!sandbox) fail("usage: caps.ts <sandbox> [--by NAME] [--usd N] [--tokens N] [--per-agent-usd N] [--per-agent-tokens N] [--wall-clock MIN]");
let by = "operator";
const set: Partial<Record<P.CapField, number>> = {};
for (let i = 0; i < rest.length; i += 2) {
  const flag = rest[i];
  const value = rest[i + 1];
  if (value === undefined) fail(`${flag} needs a value`);
  if (flag === "--by") {
    by = value;
    continue;
  }
  const field = FLAGS[flag];
  if (!field) fail(`unknown option ${flag}`);
  const n = Number(value);
  if (!/^\d+(\.\d+)?$/.test(value) || !Number.isFinite(n)) fail(`${flag} must be a number (got ${value})`);
  set[field] = n;
}

try {
  const { budget, before, withdrawn } = await P.setCaps(sandbox, set, by);
  const changes = (Object.keys(set) as P.CapField[]).map(
    (k) => `${NAMES[k]} from ${LABELS[k](before[k])} to ${LABELS[k](budget[k] as number | undefined)}`,
  );
  const body =
    `The ${by} changed ${changes.join(", ")}.` +
    (withdrawn ? " The stop is withdrawn: the run goes on, so carry on with what you were doing." : "");
  await P.systemPost(sandbox, { tag: "ask", to: "all", body }).catch(() => undefined);
  const after = Object.fromEntries((Object.keys(set) as P.CapField[]).map((k) => [k, budget[k] ?? null]));
  process.stdout.write(`${JSON.stringify({ ok: true, by, before, after, withdrawn, said: body })}\n`);
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}
