import { TimelineTable } from "dfirswarm";

const INK: Record<string, string> = { s2cb900: "#1f6f5f", s2cb902: "#7a5c1e", s2cb903: "#2c4660" };
const CHOSEN: Record<string, string> = { s2cb900: "cartographer", s2cb902: "registry", s2cb903: "timeline" };
const authorsFor = (c: { authors?: string[] }) =>
  (c.authors ?? []).map((id) => ({ id, name: id.slice(-1) === "0" ? "a0" : `a${id.slice(-1)}`, chosen: CHOSEN[id], colour: INK[id] }));

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
    value: "Run key written under the IIS application pool account.",
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
    authors: ["s2cb900", "s2cb903"],
  },
];

/** In time order, UTC, with the exhibit number each row is cited by. */
export const InTimeOrder = () => <TimelineTable entries={EVENTS} authorsFor={authorsFor} />;

/** A row missing half its citation is marked, not quietly left blank. */
export const WithAnUncitedRow = () => (
  <TimelineTable
    entries={[
      ...EVENTS.slice(0, 2),
      {
        seq: 19,
        kind: "event" as const,
        ts: "2026-02-11T04:02:11Z",
        value: "Operator appears to have cleared the security log.",
        authors: ["s2cb903"],
      },
    ]}
    authorsFor={authorsFor}
  />
);

/** Nothing recorded says so, rather than printing an empty table. */
export const NothingRecorded = () => <TimelineTable entries={[]} />;
