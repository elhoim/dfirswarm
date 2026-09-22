import { DarkThreadMark, TooltipProvider } from "dfirswarm";

// The mark is a tooltip trigger and is previewed inside the provider the app
// mounts at its root. Layout is inline style, never a Tailwind utility.
const caption = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)" } as const;

const THREADS = [
  { name: "#recon", posts: 34, last: "result · 12s ago", dark: false },
  { name: "#timeline", posts: 18, last: "ask · 2m ago", dark: false },
  { name: "#persistence", posts: 7, last: "hold · 21m ago", dark: true },
  { name: "#report", posts: 3, last: "veto · 34m ago", dark: true },
];

const row = { display: "flex", alignItems: "baseline", gap: 8, padding: "6px 0", borderBottom: "1px solid var(--color-line)" } as const;
const nameStyle = { fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-ink)" } as const;
const postsStyle = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)" } as const;
const lastStyle = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-2)", marginLeft: "auto" } as const;

/** Where it earns its place: down a thread list, marking the ones gone quiet. */
export const DownTheThreadList = () => (
  <TooltipProvider>
    <div style={{ display: "grid", maxWidth: 440 }}>
      {THREADS.map((t) => (
        <span key={t.name} style={row}>
          <span style={nameStyle}>{t.name}</span>
          <span style={postsStyle}>{t.posts} posts</span>
          {t.dark ? <DarkThreadMark /> : null}
          <span style={lastStyle}>{t.last}</span>
        </span>
      ))}
    </div>
  </TooltipProvider>
);

/** The mark has one state; this is it, at the size it ships. */
export const TheMarkItself = () => (
  <TooltipProvider>
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <DarkThreadMark />
      <span style={caption}>idle past the dim threshold, or last tag was hold / veto / stop</span>
    </div>
  </TooltipProvider>
);
