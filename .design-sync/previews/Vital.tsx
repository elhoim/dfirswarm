import { VitalsBand, Vital, Meter } from "dfirswarm";

// `Vital` is written for the dark band and takes its colours from it, so it is
// previewed inside `VitalsBand` — on paper its text would be invisible.
// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const band = (cols: number) =>
  ({ display: "grid", gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`, gap: 32, padding: 24 }) as const;

/**
 * One figure, with every slot filled: the caption, the big serif number, the
 * quiet tail that gives it its unit, the bar in the `meter` slot, and the one
 * line of context under it.
 */
export const Spend = () => (
  <VitalsBand>
    <div style={band(1)}>
      <Vital
        label="Spend"
        value="$7.98"
        tail="/ $60"
        sub="420 calls · 27.1M tokens"
        meter={<Meter pct={13} onDark label="Spend against the cap" />}
      />
    </div>
  </VitalsBand>
);

/**
 * `tone` is the whole variant axis, and it moves where the harness moves:
 * band ink while there is room, saffron from 80% of the cap, brick once a
 * number is the reason the run will end.
 */
export const Tones = () => (
  <VitalsBand>
    <div style={band(3)}>
      <Vital
        label="Spend"
        value="$7.98"
        tail="/ $60"
        sub="13% of the cap"
        meter={<Meter pct={13} onDark label="Spend against the cap" />}
      />
      <Vital
        label="Spend"
        value="$49.10"
        tail="/ $60"
        sub="82% of the cap"
        tone="saffron"
        meter={<Meter pct={82} tone="saffron" onDark label="Spend near the cap" />}
      />
      <Vital
        label="Spend"
        value="$60.00"
        tail="/ $60"
        sub="cap reached · the harness stopped the run"
        tone="brick"
        meter={<Meter pct={100} tone="brick" onDark label="Spend at the cap" />}
      />
    </div>
  </VitalsBand>
);

/** Counts have no bar: the `meter` slot is optional and the figure stands alone. */
export const WithoutAMeter = () => (
  <VitalsBand>
    <div style={band(3)}>
      <Vital label="Agents" value="7" sub="4 gpt-5.4 · 3 deepseek-v4-pro" />
      <Vital label="Wall clock" value="14.5" tail="min" sub="of a 180 min window" />
      <Vital label="Finish line" value="9 / 9" sub="checks certified" />
    </div>
  </VitalsBand>
);
