import { Badge } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS, so it only holds classes the app itself uses.
const row = { display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" } as const;
const stack = { display: "flex", flexDirection: "column", gap: 10 } as const;
const caption = { margin: 0, fontSize: 12, lineHeight: 1.5, color: "var(--color-ink-3)" } as const;

/**
 * The trace legend, verbatim from the traces panel: one variant per class of
 * event, so a row's colour is readable before its text is.
 */
export const TraceLegend = () => (
  <div style={stack}>
    <div style={row}>
      <Badge variant="brick">claim_violation</Badge>
      <Badge variant="saffron">reap</Badge>
      <Badge variant="moss">done · session end</Badge>
      <Badge variant="kelp">post · inbox</Badge>
      <Badge variant="slate">claim · release · write</Badge>
    </div>
    <p style={caption}>Every event in a run resolves to one of these five.</p>
  </div>
);

/** The whole `variant` vocabulary, each carrying the meaning it is used for. */
export const Variants = () => (
  <div style={row}>
    <Badge variant="neutral">neutral</Badge>
    <Badge variant="kelp">running</Badge>
    <Badge variant="saffron">stalled</Badge>
    <Badge variant="brick">dead</Badge>
    <Badge variant="slate">claim</Badge>
    <Badge variant="moss">done</Badge>
    <Badge variant="outline">outline</Badge>
  </div>
);

/**
 * Identifiers go in `font-mono`, the way the trace and claims tables set them:
 * a tool name is a token to match, not a word to read.
 */
export const ToolNames = () => (
  <div style={row}>
    <Badge variant="slate" className="font-mono">claim_file</Badge>
    <Badge variant="moss" className="font-mono">release_file</Badge>
    <Badge variant="kelp" className="font-mono">post</Badge>
    <Badge variant="neutral" className="font-mono">make_tool</Badge>
    <Badge variant="brick" className="font-mono">done/SWARM_DONE</Badge>
  </div>
);

/** Two readings of one claim: the confidence a ledger entry carries, and why. */
export const InTheLedger = () => (
  <div style={stack}>
    <div style={row}>
      <Badge variant="moss">high</Badge>
      <Badge variant="saffron">medium</Badge>
      <Badge variant="brick">low</Badge>
    </div>
    <div style={row}>
      <Badge variant="brick">blocked</Badge>
      <Badge variant="brick">no lock held</Badge>
      <Badge variant="saffron">detected after the fact</Badge>
      <Badge variant="neutral">agent-written · runs as a subprocess in the sandbox</Badge>
    </div>
  </div>
);
