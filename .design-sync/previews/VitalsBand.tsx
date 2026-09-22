import { VitalsBand, Vital, Meter } from "dfirswarm";

// Layout here is inline style, never a Tailwind utility: the shipped stylesheet
// is the app's compiled CSS, so it only contains the classes the app itself
// uses. `grid-cols-4` is not among them and silently collapses to one column.
const band = { display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 32, padding: 24 } as const;

/**
 * The four numbers that say whether a run is in trouble, on the one dark
 * surface in a light product. `VitalsBand` is the ground; each figure is a
 * `Vital`, and its bar goes in the `meter` slot.
 */
export const Running = () => (
  <VitalsBand>
    <div style={band}>
      <Vital label="Spend" value="$7.98" tail="/ $60" sub="13% of the cap"
        meter={<Meter pct={13} onDark label="Spend against the cap" />} />
      <Vital label="Wall clock" value="14.5" tail="min" sub="of a 240 min window"
        meter={<Meter pct={6} onDark label="Elapsed against the window" />} />
      <Vital label="Agents" value="7" sub="7 working · 0 done" />
      <Vital label="Finish line" value="0 / 9" sub="checks certified" />
    </div>
  </VitalsBand>
);

/**
 * Near the cap. The figure and its bar change tone at the threshold the harness
 * itself acts on, so the band and the harness never disagree.
 */
export const NearTheCap = () => (
  <VitalsBand>
    <div style={band}>
      <Vital label="Spend" value="$49.10" tail="/ $60" sub="82% of the cap" tone="saffron"
        meter={<Meter pct={82} tone="saffron" onDark label="Spend near the cap" />} />
      <Vital label="Wall clock" value="92.9" tail="min" sub="of a 240 min window"
        meter={<Meter pct={39} onDark label="Elapsed against the window" />} />
      <Vital label="Agents" value="9" sub="6 working · 2 done · 1 dead" />
      <Vital label="Finish line" value="6 / 7" tone="brick" sub="no sentinel written" />
    </div>
  </VitalsBand>
);
