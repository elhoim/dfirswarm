import { EmptyState, Button } from "dfirswarm";

// Layout here is inline style, never a Tailwind utility: the shipped
// stylesheet is the app's compiled CSS and only carries classes the app
// itself uses.

/** The ledger panel of a run whose agents have not called `record` yet. */
export const AnEmptyLedger = () => (
  <EmptyState
    title="Nothing recorded yet"
    hint="Agents write findings, indicators and events here with record. The panel fills from the first call — usually within a minute of the first claim."
  />
);

/** With the one action that ends the emptiness. */
export const WithTheActionThatFillsIt = () => (
  <EmptyState
    title="No swarms in this workspace"
    hint="A run needs a goal and a model team. The last run here, s2cb903, finished three days ago."
    action={<Button size="sm">Start a swarm</Button>}
  />
);

const LockGlyph = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <rect x="3" y="11" width="18" height="10" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

/** The icon slot takes any glyph; the default inbox is only a fallback. */
export const WithItsOwnIcon = () => (
  <EmptyState
    icon={<LockGlyph />}
    title="No file is claimed"
    hint="claim_file takes a path out of contention for one agent. Nothing under work/ is held right now."
  />
);
