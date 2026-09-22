import { EvidenceRow, TooltipProvider } from "dfirswarm";

const SHA = "86abc66f0e8ac85eefd69a97470f656465875a616fee71a3487554ceef13057e";
const SHA2 = "f9b30696061ab2000619e38b9879b32fdbb32a6fe23a472d3e166c29ab153fd6";

/** The read-only evidence a run was given: path, size, hash. */
export const Inputs = () => (
  <TooltipProvider>
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <EvidenceRow path="inputs/brief.md" bytes={98} sha={SHA} meta={<span>read-only</span>} />
      <EvidenceRow path="inputs/logs/u_ex260211.log" bytes={146} sha={SHA2} meta={<span>read-only</span>} />
    </div>
  </TooltipProvider>
);

/** The artifacts it produced: the same row, with who wrote it and when. */
export const Artifacts = () => (
  <TooltipProvider>
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <EvidenceRow
        path="attack-path.svg"
        bytes={1024}
        sha={SHA}
        selected
        onSelect={() => undefined}
        meta={
          <>
            <span>3 min ago</span>
            <span style={{ fontFamily: "var(--font-mono)" }}>s7a1c00</span>
            <span>2 revisions</span>
          </>
        }
      />
      <EvidenceRow
        path="notes.md"
        bytes={294}
        sha={SHA2}
        onSelect={() => undefined}
        meta={<span>8 min ago</span>}
      />
    </div>
  </TooltipProvider>
);
