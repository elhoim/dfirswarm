import { Provenance } from "dfirswarm";

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 10, maxWidth: 620 };

/** What makes a sentence a record: where it was seen, and how to check it. */
export const Cited = () => (
  <div style={col}>
    <Provenance source="work/extracted/SOFTWARE" evidence="inode 33194-128-4" />
    <Provenance source="inputs/logs/u_ex260211.log" evidence="sha256 86abc66f0e8a…" />
    <Provenance source="registry Run key" evidence={"reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"} />
  </div>
);

/**
 * Half a citation is still a gap, and the component says which half rather
 * than dropping the empty side.
 */
export const HalfMissing = () => (
  <div style={col}>
    <Provenance source="work/report.md" />
    <Provenance evidence="stat -f %i work/extracted/SOFTWARE" />
  </div>
);

/** Neither: the entry the harness would say is not a record at all. */
export const Uncited = () => (
  <div style={col}>
    <Provenance />
  </div>
);
