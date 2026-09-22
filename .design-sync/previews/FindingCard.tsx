import { FindingCard } from "dfirswarm";

const A0 = { id: "s2cb900", name: "a0", chosen: "cartographer", colour: "#1f6f5f" };
const A2 = { id: "s2cb902", name: "a2", chosen: "registry", colour: "#7a5c1e" };
const A3 = { id: "s2cb903", name: "a3", chosen: "timeline", colour: "#2c4660" };

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 10, maxWidth: 660 };

/** A finding is a conclusion, so it is set larger than a row in a table. */
export const Findings = () => (
  <div style={col}>
    <FindingCard
      claim={{
        seq: 4,
        kind: "finding",
        value: "Entry was an unauthenticated upload to /upload.aspx, not a stolen credential.",
        source: "inputs/logs/u_ex260211.log",
        evidence: "grep -n 'POST /upload.aspx' u_ex260211.log → line 8811",
        confidence: "high",
      }}
      authors={[A0]}
    />
    <FindingCard
      claim={{
        seq: 11,
        kind: "finding",
        value: "Persistence was a Run key written 41 seconds after the first shell, under the IIS application pool account.",
        source: "work/extracted/SOFTWARE",
        evidence: "inode 33194-128-4",
        confidence: "medium",
      }}
      authors={[A2, A3]}
    />
  </div>
);

/** A hedged conclusion reads as hedged without being painted as a danger. */
export const LowConfidence = () => (
  <div style={col}>
    <FindingCard
      claim={{
        seq: 18,
        kind: "finding",
        value: "Exfiltration cannot be ruled out: the proxy log for 03:10–03:40 was rotated before collection.",
        source: "inputs/logs/proxy/",
        evidence: "ls -la inputs/logs/proxy/ — no file covers the window",
        confidence: "low",
      }}
      authors={[A3]}
    />
  </div>
);
