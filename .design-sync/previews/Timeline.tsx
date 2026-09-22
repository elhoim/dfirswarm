import { Timeline } from "dfirswarm";

const INK: Record<string, string> = { s2cb900: "#1f6f5f", s2cb902: "#7a5c1e", s2cb903: "#2c4660" };
const authorsFor = (c: { authors?: string[] }) => (c.authors ?? []).map((id) => ({ id, name: `a${id.slice(-1)}`, colour: INK[id] }));

const EVENTS = [
  {
    seq: 9,
    kind: "event" as const,
    ts: "2026-02-11T03:14:22Z",
    value: "Webshell dropped at work/extracted/upload.aspx.",
    source: "inputs/logs/u_ex260211.log",
    evidence: "line 8811",
    authors: ["s2cb903"],
  },
  {
    seq: 12,
    kind: "event" as const,
    ts: "2026-02-11T03:15:03Z",
    value: "Run key written under the IIS application pool account, 41 seconds after the first shell.",
    source: "work/extracted/SOFTWARE",
    evidence: "inode 33194-128-4",
    authors: ["s2cb902"],
  },
  {
    seq: 14,
    kind: "event" as const,
    ts: "2026-02-11T03:41:58Z",
    value: "Outbound connection to 185.220.101.47:443 from w3wp.exe.",
    source: "inputs/netflow/2026-02-11.csv",
    evidence: "row 21,904",
    authors: ["s2cb900"],
  },
];

/** The same events a reader follows rather than scans: for a narrow column, where six table columns become a scrollbar nobody scrolls. */
export const Narrative = () => (
  <div style={{ maxWidth: 420 }}>
    <Timeline entries={EVENTS} authorsFor={authorsFor} />
  </div>
);

/** Without authors, for the report page that credits its team on the cover. */
export const WithoutAuthors = () => (
  <div style={{ maxWidth: 420 }}>
    <Timeline entries={EVENTS} />
  </div>
);
