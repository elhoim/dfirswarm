import { ConfidenceMark } from "dfirswarm";

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 10 };

/**
 * Three pips and a word. Not a colour: the palette spends its accents on
 * state, and painting a hedged sentence brick would read as danger.
 */
export const Levels = () => (
  <div style={col}>
    <ConfidenceMark level="high" />
    <ConfidenceMark level="medium" />
    <ConfidenceMark level="low" />
  </div>
);

/** Confidence nobody stated is not low confidence, and does not look like it. */
export const NotStated = () => (
  <div style={col}>
    <ConfidenceMark level="low" />
    <ConfidenceMark />
  </div>
);

/** Without the word, for a table whose column header already says it. */
export const InAColumn = () => (
  <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
    <ConfidenceMark level="high" label={false} />
    <ConfidenceMark level="medium" label={false} />
    <ConfidenceMark level="low" label={false} />
  </div>
);
