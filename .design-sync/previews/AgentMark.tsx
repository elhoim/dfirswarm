import { AgentMark, TooltipProvider } from "dfirswarm";

// The mark is a tooltip trigger, so it is previewed inside the provider the
// app mounts at its root — alone it would throw. Layout is inline style, not
// a Tailwind utility: the shipped CSS only carries classes the app uses.
const row = { display: "flex", alignItems: "center", gap: 24 } as const;
const item = { display: "flex", flexDirection: "column", alignItems: "center", gap: 6 } as const;
const caption = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)" } as const;

const MARKERS = [
  ["done", "done"],
  ["active", "working"],
  ["stalled", "stalled"],
  ["dead", "reaped"],
] as const;

/** ✓ done · ● working · ? stalled · ? reaped — the whole vocabulary, at `md`. */
export const TheFourMarkers = () => (
  <TooltipProvider>
    <div style={row}>
      {MARKERS.map(([marker, text]) => (
        <span key={marker} style={item}>
          <AgentMark marker={marker} />
          <span style={caption}>{text}</span>
        </span>
      ))}
    </div>
  </TooltipProvider>
);

/** `sm` is the roster size: the mark beside an agent id in a dense list. */
export const AtSmall = () => (
  <TooltipProvider>
    <div style={row}>
      {MARKERS.map(([marker, text]) => (
        <span key={marker} style={item}>
          <AgentMark marker={marker} size="sm" />
          <span style={caption}>{text}</span>
        </span>
      ))}
    </div>
  </TooltipProvider>
);

const ROSTER = [
  { id: "a1", name: "cartographer", marker: "done", note: "done · session end" },
  { id: "a2", name: "sifter", marker: "active", note: "working · 3 claims" },
  { id: "a3", name: "timeline", marker: "stalled", note: "stalled · idle 11m" },
  { id: "a4", name: "scribe", marker: "dead", note: "reaped · 2 locks released" },
] as const;

const line = { display: "flex", alignItems: "center", gap: 8 } as const;
const idStyle = { fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-ink)" } as const;
const nameStyle = { fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-ink-2)" } as const;
const noteStyle = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)", marginLeft: "auto" } as const;

/** Where it is used: one mark per agent, down the roster of a nine-agent run. */
export const InTheRoster = () => (
  <TooltipProvider>
    <div style={{ display: "grid", gap: 8, maxWidth: 420 }}>
      {ROSTER.map((a) => (
        <span key={a.id} style={line}>
          <AgentMark marker={a.marker} size="sm" />
          <span style={idStyle}>{a.id}</span>
          <span style={nameStyle}>{a.name}</span>
          <span style={noteStyle}>{a.note}</span>
        </span>
      ))}
    </div>
  </TooltipProvider>
);
