import type { ReactNode } from "react";
import { Meter, VitalsBand } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const stack = { display: "flex", flexDirection: "column", gap: 6 } as const;
const head = { display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 16 } as const;
const sweep = { display: "flex", flexDirection: "column", gap: 18 } as const;

/** A meter never ships bare: a caption on the left, the figures on the right. */
const Labelled = ({ label, figure, children }: { label: string; figure: string; children: ReactNode }) => (
  <div style={stack}>
    <div style={head}>
      <span className="label-caps">{label}</span>
      <span className="font-mono text-[12px] tabular text-ink-2">{figure}</span>
    </div>
    {children}
  </div>
);

/** Spend against the cap on a running swarm: kelp, because there is room. */
export const AgainstTheCap = () => (
  <Labelled label="Spend" figure="$7.98 of $60 · 13%">
    <Meter pct={13} label="Spend against the cap" />
  </Labelled>
);

/**
 * The tone changes where the harness itself acts, so the bar and the harness
 * never disagree: kelp while there is room, saffron from 80% of the cap,
 * brick at the cap, where the run is stopped.
 */
export const Thresholds = () => (
  <div style={sweep}>
    <Labelled label="Room to work" figure="$7.98 of $60 · 13%">
      <Meter pct={13} tone="kelp" label="Spend against the cap" />
    </Labelled>
    <Labelled label="Near the cap" figure="$49.10 of $60 · 82%">
      <Meter pct={82} tone="saffron" label="Spend near the cap" />
    </Labelled>
    <Labelled label="At the cap" figure="$60.00 of $60 · 100%">
      <Meter pct={100} tone="brick" label="Spend at the cap" />
    </Labelled>
  </div>
);

/** `onDark` swaps the track for the band's line colour, for use in the vitals band. */
export const OnTheBand = () => (
  <VitalsBand>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 32, padding: 24 }}>
      <div style={stack}>
        <div style={head}>
          <span className="label-caps text-band-ink-2">Spend</span>
          <span className="font-mono text-[12px] tabular text-band-ink-2">$7.98 of $60</span>
        </div>
        <Meter pct={13} onDark label="Spend against the cap" />
      </div>
      <div style={stack}>
        <div style={head}>
          <span className="label-caps text-band-ink-2">Wall clock</span>
          <span className="font-mono text-[12px] tabular text-band-ink-2">14.5 of 180 min</span>
        </div>
        <Meter pct={8} onDark label="Elapsed against the wall clock" />
      </div>
    </div>
  </VitalsBand>
);
