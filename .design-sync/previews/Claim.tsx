import { Claim } from "dfirswarm";

const A0 = { id: "s2cb900", name: "a0", chosen: "cartographer", colour: "#1f6f5f" };
const A3 = { id: "s2cb903", name: "a3", chosen: "timeline", colour: "#2c4660" };

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 10, maxWidth: 640 };

/** One record, with everything a reader needs in order to disagree with it. */
export const Cited = () => (
  <div style={col}>
    <Claim
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
  </div>
);

/**
 * An event, which is the one kind that must carry a time. The stamp is UTC
 * and stays UTC: a forensic timeline is read on another machine, in another
 * time zone, by somebody who was not there.
 */
export const AnEvent = () => (
  <div style={col}>
    <Claim
      showTime
      claim={{
        seq: 9,
        kind: "event",
        ts: "2026-02-11T03:14:22Z",
        value: "Webshell dropped at work/extracted/upload.aspx.",
        source: "work/extracted/upload.aspx",
        evidence: "inode 33194-128-4",
        confidence: "medium",
      }}
      authors={[A3]}
    />
  </div>
);

/**
 * The record that cannot be checked. It is marked rather than dropped,
 * because a reader who cannot see it will read the rest as though it were
 * all equally solid.
 */
export const Uncited = () => (
  <div style={col}>
    <Claim
      claim={{
        seq: 21,
        kind: "finding",
        value: "The operator most likely reused the same toolkit seen in the January intrusion.",
        confidence: "low",
      }}
      authors={[A0, A3]}
    />
  </div>
);
