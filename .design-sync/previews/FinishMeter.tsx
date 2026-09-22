import type { ReactNode } from "react";
import { FinishMeter } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const stack = { display: "flex", flexDirection: "column", gap: 8 } as const;
const head = { display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 16 } as const;
const sweep = { display: "flex", flexDirection: "column", gap: 20 } as const;

/** The bar is always read with its count: one cell is one check in `SWARM.md`. */
const Labelled = ({ figure, note, children }: { figure: string; note?: ReactNode; children: ReactNode }) => (
  <div style={stack}>
    <div style={head}>
      <span className="label-caps">Finish line</span>
      <span className="font-mono text-[12px] tabular text-ink-2">{figure}</span>
    </div>
    {children}
    {note ? <span className="text-[13px] text-ink-2">{note}</span> : null}
  </div>
);

/** The run that certified: every check in the definition of done passed. */
export const Certified = () => (
  <Labelled figure="9 of 9 · certified" note="the report answers all nine questions with citations; the sentinel was written by s2cb904">
    <FinishMeter passed={9} total={9} pendingTone="neutral" />
  </Labelled>
);

/**
 * Part way through a running swarm. The four that passed are solid; the three
 * still to run are dashed saffron, because "not yet" is not a failure.
 */
export const PartRun = () => (
  <Labelled figure="4 of 7 · in progress" note="three checks have not been run yet — dashed, not brick">
    <FinishMeter passed={4} total={7} pendingTone="saffron" />
  </Labelled>
);

/**
 * The three states side by side, which is the whole point of the dashed cell:
 * six passed (moss), one failed (brick), two not yet run (dashed). A reader
 * can tell a failure from an absence without reading the count.
 */
export const PassedFailedPending = () => (
  <Labelled figure="6 of 9 · 1 failing · 2 not yet" note="work/timeline.md has 38 rows, not the 40 the goal asked for">
    <FinishMeter passed={6} total={9} failed={1} pendingTone="neutral" />
  </Labelled>
);

/** Both pending styles at once, so the dashed cell never reads as a failure. */
export const PendingIsNotFailed = () => (
  <div style={sweep}>
    <Labelled figure="running · 2 of 6 · pending in saffron">
      <FinishMeter passed={2} total={6} pendingTone="saffron" />
    </Labelled>
    <Labelled figure="stopped · 2 of 6 · 1 failing, 3 never run">
      <FinishMeter passed={2} total={6} failed={1} pendingTone="neutral" />
    </Labelled>
  </div>
);
