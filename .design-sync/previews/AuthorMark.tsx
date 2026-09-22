import { AuthorMark } from "dfirswarm";

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 8 };

/** An agent in the ink it carries everywhere else in the console. */
export const Default = () => (
  <div style={col}>
    <AuthorMark author={{ id: "s2cb900", colour: "#1f6f5f" }} />
    <AuthorMark author={{ id: "s2cb903", colour: "#2c4660" }} />
    <AuthorMark author={{ id: "s2cb906", colour: "#8a5a00" }} />
  </div>
);

/** With the name it chose for itself, which nobody assigned to it. */
export const Named = () => (
  <div style={col}>
    <AuthorMark author={{ id: "s2cb900", name: "a0", chosen: "cartographer", colour: "#1f6f5f" }} />
    <AuthorMark author={{ id: "s2cb901", name: "a1", chosen: "sifter", colour: "#b5542b" }} />
    <AuthorMark author={{ id: "s2cb903", name: "a3", chosen: "timeline", colour: "#2c4660" }} />
  </div>
);

/** The harness itself, when it is the thing that put a fact on record. */
export const System = () => (
  <div style={col}>
    <AuthorMark author={{ id: "system", colour: "#8b2e2b" }} />
  </div>
);
