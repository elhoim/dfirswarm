import { ReportContents } from "dfirswarm";

const SECTIONS = [
  { n: 1, title: "Summary of findings" },
  { n: 2, title: "Scope and evidence" },
  { n: 3, title: "Timeline" },
  { n: 4, title: "Indicators and findings" },
  { n: 5, title: "Method" },
  { n: 6, title: "Artifacts produced" },
  { n: 7, title: "Limitations" },
  { n: 8, title: "Chain of custody" },
];

/** The eight sections the report always has, numbered to match what a reader will cite. */
export const TheEightSections = () => (
  <div style={{ maxWidth: 420 }}>
    <ReportContents sections={SECTIONS} />
  </div>
);

/** With the swarm's own prose report appended as a ninth, which happens when the run wrote one. */
export const WithTheSwarmsOwnReport = () => (
  <div style={{ maxWidth: 420 }}>
    <ReportContents sections={[...SECTIONS, { n: 9, title: "The swarm's own report (report.md)" }]} />
  </div>
);
