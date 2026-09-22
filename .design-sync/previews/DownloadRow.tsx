import { DownloadRow, TooltipProvider } from "dfirswarm";

const SHA = "7c04b2672e668fd2012de71fbc2e5938a5e819a85ec6f838e182e40f3bd41844";

/** A file of the handover, with the number that travels with it. */
export const Dossier = () => (
  <TooltipProvider>
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <DownloadRow
        name="report.html"
        href="#"
        bytes={18510}
        sha={SHA}
        description="The report: cover, evidence, timeline, exhibits, method, artifacts, custody. One file, nothing fetched."
      />
      <DownloadRow name="ledger.jsonl" href="#" bytes={1204} description="The timeline, indicators and findings as the agents recorded them." />
    </div>
  </TooltipProvider>
);

/** A run that never produced the file says so rather than offering a 404. */
export const NotProduced = () => (
  <TooltipProvider>
    <DownloadRow
      name="ledger.md"
      href="#"
      description="The same ledger, rendered."
      disabled
      disabledReason="nothing recorded"
    />
  </TooltipProvider>
);
