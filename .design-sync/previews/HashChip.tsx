import { HashChip, TooltipProvider } from "dfirswarm";

const SHA = "b59cdff1a40f6283bcc81f10919ccbafee20b10aa76481a261ba0b916ddfc41d";

/**
 * The hash a reader can actually compare: twelve characters, the whole thing
 * on hover, click to copy. It is `slate` because slate means locks and files,
 * and this is the strongest statement the console makes about a file.
 */
export const Default = () => (
  <TooltipProvider>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
      <HashChip sha={SHA} />
    </div>
  </TooltipProvider>
);

/** `chars` for a dense list, where eight is still enough to spot a mismatch. */
export const Lengths = () => (
  <TooltipProvider>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
      <HashChip sha={SHA} chars={8} />
      <HashChip sha={SHA} chars={12} />
      <HashChip sha={SHA} chars={16} />
    </div>
  </TooltipProvider>
);

/** No hash is a state, not a blank: a file nobody has hashed says so. */
export const Missing = () => (
  <TooltipProvider>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
      <HashChip sha={SHA} label="sha256 at kickoff" />
      <HashChip sha="" />
    </div>
  </TooltipProvider>
);
