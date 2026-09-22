import { ThreadPulse } from "dfirswarm";

// Layout and legend are inline style, never a Tailwind utility: the shipped
// stylesheet is the app's compiled CSS.
const COLOURS: Record<string, string> = {
  a1: "var(--color-kelp)",
  a2: "var(--color-slate)",
  a3: "var(--color-saffron)",
  a4: "var(--color-moss)",
  a5: "var(--color-brick)",
  a6: "var(--color-kelp-ink)",
  a7: "var(--color-saffron-ink)",
  system: "var(--color-ink-3)",
};
const NAMES: Record<string, string> = {
  a1: "cartographer",
  a2: "sifter",
  a3: "timeline",
  a4: "scribe",
  a5: "persistence",
  a6: "netflow",
  a7: "registry",
  system: "system",
};
const colour = (id: string) => COLOURS[id] ?? "var(--color-ink-3)";
const names = (id: string) => NAMES[id] ?? id;

const stack = { display: "grid", gap: 10 } as const;
const caption = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)" } as const;
const name = { fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-ink)" } as const;
const legend = { display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" } as const;
const legendItem = { display: "flex", alignItems: "center", gap: 5, fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--color-ink-2)" } as const;

const Legend = ({ ids }: { ids: string[] }) => (
  <div style={legend}>
    {ids.map((id) => (
      <span key={id} style={legendItem}>
        <span style={{ width: 6, height: 6, borderRadius: 999, background: colour(id) }} />
        {names(id)}
      </span>
    ))}
  </div>
);

// Four minutes of #recon: the system opens the thread, the team introduces
// itself, claims go out, results come back, and one agent holds the report.
const RECON = [
  { at: "2026-09-20T09:14:04Z", from: "system", tag: "intro" },
  { at: "2026-09-20T09:14:19Z", from: "a1", tag: "intro" },
  { at: "2026-09-20T09:14:33Z", from: "a2", tag: "intro" },
  { at: "2026-09-20T09:14:51Z", from: "a3", tag: "intro" },
  { at: "2026-09-20T09:15:12Z", from: "a4", tag: "intro" },
  { at: "2026-09-20T09:15:40Z", from: "a1", tag: "claim" },
  { at: "2026-09-20T09:15:58Z", from: "a2", tag: "claim" },
  { at: "2026-09-20T09:16:27Z", from: "a3", tag: "ask" },
  { at: "2026-09-20T09:16:44Z", from: "a1", tag: "result" },
  { at: "2026-09-20T09:17:02Z", from: "a4", tag: "claim" },
  { at: "2026-09-20T09:17:21Z", from: "a2", tag: "result" },
  { at: "2026-09-20T09:17:39Z", from: "system", tag: "hold" },
  { at: "2026-09-20T09:17:56Z", from: "a3", tag: "result" },
  { at: "2026-09-20T09:18:21Z", from: "a4", tag: "hold" },
];

/** A four-agent thread: one thin lane per agent, a dot per post, newest ringed. */
export const AThreadWithALanePerAgent = () => (
  <div style={stack}>
    <span style={name}>#recon <span style={caption}>· 14 posts · 09:14 → 09:18</span></span>
    <ThreadPulse
      dots={RECON}
      from="2026-09-20T09:14:00Z"
      to="2026-09-20T09:18:40Z"
      colour={colour}
      names={names}
      lanes={["a1", "a2", "a3", "a4"]}
    />
    <Legend ids={["a1", "a2", "a3", "a4", "system"]} />
  </div>
);

// Seven agents and no lanes: every post is a tick on one row, which is how a
// thirty-agent thread stays readable.
const BUSY = [
  { at: "2026-09-20T11:02:44Z", from: "system", tag: "intro" },
  { at: "2026-09-20T11:02:58Z", from: "a1", tag: "intro" },
  { at: "2026-09-20T11:03:06Z", from: "a5", tag: "claim" },
  { at: "2026-09-20T11:03:19Z", from: "a2", tag: "ask" },
  { at: "2026-09-20T11:03:31Z", from: "a6", tag: "claim" },
  { at: "2026-09-20T11:03:44Z", from: "a3", tag: "result" },
  { at: "2026-09-20T11:03:52Z", from: "a7", tag: "ask" },
  { at: "2026-09-20T11:04:09Z", from: "a4", tag: "result" },
  { at: "2026-09-20T11:04:23Z", from: "a5", tag: "result" },
  { at: "2026-09-20T11:04:38Z", from: "a1", tag: "veto" },
  { at: "2026-09-20T11:04:51Z", from: "a6", tag: "result" },
  { at: "2026-09-20T11:05:14Z", from: "a2", tag: "result" },
  { at: "2026-09-20T11:05:29Z", from: "a7", tag: "claim" },
  { at: "2026-09-20T11:05:47Z", from: "a3", tag: "stop" },
];

/** Without lanes the pulse is a single row of ticks, system posts as diamonds. */
export const OneRowWhenTheTeamIsBig = () => (
  <div style={stack}>
    <span style={name}>#timeline <span style={caption}>· 14 posts · 7 agents · 11:02 → 11:06</span></span>
    <ThreadPulse dots={BUSY} from="2026-09-20T11:02:40Z" to="2026-09-20T11:06:00Z" colour={colour} names={names} />
    <Legend ids={["a1", "a2", "a3", "a4", "a5", "a6", "a7", "system"]} />
  </div>
);

const QUIET = [
  { at: "2026-09-20T09:22:10Z", from: "system", tag: "intro" },
  { at: "2026-09-20T09:22:48Z", from: "a4", tag: "ask" },
  { at: "2026-09-20T09:24:31Z", from: "a1", tag: "hold" },
];

/** Three posts and then nothing: the shape of a thread that went dark. */
export const AThreadThatWentQuiet = () => (
  <div style={stack}>
    <span style={name}>#report <span style={caption}>· 3 posts · last tag hold, 21 min ago</span></span>
    <ThreadPulse
      dots={QUIET}
      from="2026-09-20T09:22:00Z"
      to="2026-09-20T09:31:00Z"
      colour={colour}
      names={names}
      lanes={["a1", "a4"]}
    />
    <Legend ids={["a1", "a4", "system"]} />
  </div>
);
