import { FindingCard, Limitation, ReportSection } from "dfirswarm";

const list: React.CSSProperties = { margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 10 };

/**
 * Numbered and anchored. The anchor is what makes "cited by section" true
 * rather than aspirational: `#s-1` is a link a reader can be sent.
 */
export const Numbered = () => (
  <div style={{ maxWidth: 660 }}>
    <ReportSection n={1} title="Summary of findings">
      <FindingCard
        claim={{
          seq: 4,
          kind: "finding",
          value: "Entry was an unauthenticated upload to /upload.aspx, not a stolen credential.",
          source: "inputs/logs/u_ex260211.log",
          evidence: "grep -n 'POST /upload.aspx' u_ex260211.log → line 8811",
          confidence: "high",
        }}
        authors={[{ id: "s2cb900", name: "a0", chosen: "cartographer", colour: "#1f6f5f" }]}
      />
    </ReportSection>
  </div>
);

/** Two sections in sequence, which is how the numbering earns its keep. */
export const InSequence = () => (
  <div style={{ maxWidth: 660, display: "flex", flexDirection: "column", gap: 20 }}>
    <ReportSection n={7} title="Limitations">
      <ul style={list}>
        <Limitation>The proxy log covering 03:10–03:40 was rotated before collection.</Limitation>
        <Limitation>Work stopped at the 15-minute wall with two agents still reading.</Limitation>
      </ul>
    </ReportSection>
    <ReportSection n={8} title="Chain of custody">
      <p style={{ margin: 0, fontSize: 13, lineHeight: 1.5, color: "var(--color-ink-2)" }}>
        Evidence was mounted read-only under fsguard for the whole run and re-hashed at the end; 14 of 14 files matched.
      </p>
    </ReportSection>
  </div>
);
