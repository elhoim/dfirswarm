import { ActivityStrip } from "dfirswarm";

// Full-width stories (cardMode: column). Layout is inline style, never a
// Tailwind utility.
type Bucket = { m: number; c: number };

const sum = (buckets: Bucket[], key: "m" | "c") => buckets.reduce((n, b) => n + b[key], 0);
const series = (from: string | null, to: string | null, buckets: Bucket[]) => ({
  from,
  to,
  messages: sum(buckets, "m"),
  tool_calls: sum(buckets, "c"),
  buckets,
});

// A 25-minute run, one bucket per 50 seconds: intros, a first grind, a lull
// while the team re-plans, a second and heavier grind, then the tail as
// agents write up and end their sessions.
const RUN: Bucket[] = [
  { m: 6, c: 0 }, { m: 9, c: 1 }, { m: 7, c: 4 }, { m: 4, c: 9 }, { m: 3, c: 14 },
  { m: 2, c: 19 }, { m: 5, c: 23 }, { m: 3, c: 26 }, { m: 2, c: 21 }, { m: 1, c: 12 },
  { m: 0, c: 6 }, { m: 2, c: 3 }, { m: 6, c: 2 }, { m: 8, c: 5 }, { m: 4, c: 13 },
  { m: 2, c: 22 }, { m: 1, c: 28 }, { m: 1, c: 31 }, { m: 3, c: 27 }, { m: 2, c: 18 },
  { m: 5, c: 11 }, { m: 7, c: 6 }, { m: 4, c: 9 }, { m: 2, c: 16 }, { m: 1, c: 20 },
  { m: 2, c: 14 }, { m: 4, c: 8 }, { m: 6, c: 4 }, { m: 5, c: 2 }, { m: 3, c: 1 },
];

const caption = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)" } as const;
const stack = { display: "grid", gap: 8 } as const;

/** A whole run, brick for messages over ink for tool calls, wall clock at both ends. */
export const AWholeRun = () => (
  <div style={stack}>
    <span style={caption}>s2cb903 · 9 agents · 25 min, cap not reached</span>
    <ActivityStrip series={series("2026-09-20T09:14:02Z", "2026-09-20T09:39:11Z", RUN)} />
  </div>
);

// The same run's shape with the talking gone: claims, edits and checks with
// almost nothing said between them.
const SILENT: Bucket[] = [
  { m: 4, c: 1 }, { m: 3, c: 6 }, { m: 1, c: 15 }, { m: 0, c: 24 }, { m: 0, c: 29 },
  { m: 0, c: 31 }, { m: 1, c: 28 }, { m: 0, c: 33 }, { m: 0, c: 30 }, { m: 0, c: 26 },
  { m: 0, c: 34 }, { m: 0, c: 29 }, { m: 0, c: 22 }, { m: 1, c: 27 }, { m: 0, c: 31 },
  { m: 0, c: 35 }, { m: 0, c: 33 }, { m: 0, c: 28 }, { m: 0, c: 24 }, { m: 0, c: 30 },
  { m: 0, c: 26 }, { m: 0, c: 19 }, { m: 0, c: 23 }, { m: 0, c: 17 }, { m: 0, c: 21 },
  { m: 0, c: 14 }, { m: 0, c: 11 }, { m: 0, c: 7 }, { m: 0, c: 4 }, { m: 0, c: 2 },
];

/** All tool calls and no messages: a team that has stopped talking to itself. */
export const ATeamThatStoppedTalking = () => (
  <div style={stack}>
    <span style={caption}>s4f11ae · 7 agents · no post since the second minute</span>
    <ActivityStrip series={series("2026-09-20T11:02:40Z", "2026-09-20T11:27:58Z", SILENT)} />
  </div>
);

/** A run whose first tool call has not landed: the strip says so in words. */
export const NothingTracedYet = () => (
  <div style={stack}>
    <span style={caption}>s9d27c0 · prepared, sandbox warming</span>
    <ActivityStrip series={series("2026-09-20T12:41:07Z", null, Array.from({ length: 30 }, () => ({ m: 0, c: 0 })))} />
  </div>
);
