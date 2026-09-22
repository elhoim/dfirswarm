import { IndicatorTable } from "dfirswarm";

const INK: Record<string, string> = { s2cb900: "#1f6f5f", s2cb902: "#7a5c1e", s2cb904: "#6b3d7a" };
const authorsFor = (c: { authors?: string[] }) => (c.authors ?? []).map((id) => ({ id, name: `a${id.slice(-1)}`, colour: INK[id] }));

const IOCS = [
  {
    seq: 22,
    kind: "ioc" as const,
    value: "185.220.101.47",
    source: "inputs/netflow/2026-02-11.csv",
    evidence: "row 21,904",
    confidence: "high" as const,
    authors: ["s2cb900"],
  },
  {
    seq: 23,
    kind: "ioc" as const,
    value: "63cc986dec2958e367b2344c1e8bbafe64f9f7f7e5fdb4ecaafe2b75ec9449c9",
    source: "work/extracted/upload.aspx",
    evidence: "shasum -a 256 work/extracted/upload.aspx",
    confidence: "high" as const,
    authors: ["s2cb902"],
  },
  {
    seq: 25,
    kind: "ioc" as const,
    value: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\IISUpdate",
    source: "work/extracted/SOFTWARE",
    evidence: "inode 33194-128-4",
    confidence: "medium" as const,
    authors: ["s2cb904"],
  },
];

/** The part of a report somebody else pastes into a tool, so the value is mono and alone in its column. */
export const Indicators = () => <IndicatorTable entries={IOCS} authorsFor={authorsFor} />;

/** Without the author column, for a report page that names its authors once at the top. */
export const WithoutAuthors = () => <IndicatorTable entries={IOCS} />;

/** An indicator nobody can check is marked: it is the one a reader must not act on. */
export const WithAnUncitedRow = () => (
  <IndicatorTable
    entries={[
      IOCS[0],
      { seq: 31, kind: "ioc" as const, value: "cdn-update[.]net", confidence: "low" as const, authors: ["s2cb904"] },
    ]}
    authorsFor={authorsFor}
  />
);
