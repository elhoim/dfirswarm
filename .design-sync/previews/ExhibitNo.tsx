import { ExhibitNo } from "dfirswarm";

const row: React.CSSProperties = { display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" };

/** The number the console, `ledger/ledger.md` and `report.html` all cite. */
export const Default = () => (
  <div style={row}>
    <ExhibitNo seq={1} />
    <ExhibitNo seq={4} />
    <ExhibitNo seq={12} />
    <ExhibitNo seq={137} />
  </div>
);

/** In its real place: at the head of a line, before what it cites. */
export const OnALine = () => (
  <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: 560 }}>
    {[
      { seq: 4, text: "Entry was an unauthenticated upload to /upload.aspx, not a stolen credential." },
      { seq: 7, text: "The webshell wrote to work/extracted/SOFTWARE outside any claim." },
    ].map((e) => (
      <div key={e.seq} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
        <ExhibitNo seq={e.seq} />
        <span style={{ fontSize: 13, lineHeight: 1.45, color: "var(--color-ink)" }}>{e.text}</span>
      </div>
    ))}
  </div>
);
