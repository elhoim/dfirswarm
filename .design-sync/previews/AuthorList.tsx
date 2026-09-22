import { AuthorList } from "dfirswarm";

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 10, maxWidth: 520 };

/** One agent recorded it. */
export const One = () => (
  <div style={col}>
    <AuthorList authors={[{ id: "s2cb903", name: "a3", chosen: "timeline", colour: "#2c4660" }]} />
  </div>
);

/**
 * Two agents recorded the same thing and the harness merged the entries, so
 * both are named. A merged record that credited only the first would lose the
 * fact that it was found twice, independently.
 */
export const Merged = () => (
  <div style={col}>
    <AuthorList
      authors={[
        { id: "s2cb900", name: "a0", chosen: "cartographer", colour: "#1f6f5f" },
        { id: "s2cb903", name: "a3", chosen: "timeline", colour: "#2c4660" },
      ]}
    />
    <AuthorList
      authors={[
        { id: "s2cb901", name: "a1", colour: "#b5542b" },
        { id: "s2cb904", name: "a4", colour: "#6b3d7a" },
        { id: "s2cb906", name: "a6", colour: "#8a5a00" },
      ]}
    />
  </div>
);

/** Nobody: the em dash, not an empty cell that reads as a name you missed. */
export const Nobody = () => (
  <div style={col}>
    <AuthorList authors={[]} />
  </div>
);
