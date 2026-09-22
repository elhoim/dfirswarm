import { ReportCover } from "dfirswarm";

/** The one page allowed to look like a document, and the sentence that says the numbers in it are checkable. */
export const Finished = () => (
  <div style={{ maxWidth: 680 }}>
    <ReportCover
      organisation="Adeo Security"
      caseId="CASE-2026-004"
      runId="s2cb9"
      examiner="H. Ozturkci"
      tool="DFIR Swarm 0.3.0"
      startedAt="2026-02-11T08:57:14Z"
      endedAt="2026-02-11T09:11:44Z"
      generatedAt="2026-02-11T09:14:02Z"
      state="finished"
    />
  </div>
);

/** A run that did not finish says so on the cover, where a reader cannot miss it. */
export const DidNotFinish = () => (
  <div style={{ maxWidth: 680 }}>
    <ReportCover
      caseId="CASE-2026-011"
      runId="s4f1a"
      examiner="H. Ozturkci"
      tool="DFIR Swarm 0.3.0"
      startedAt="2026-03-02T11:20:00Z"
      generatedAt="2026-03-02T11:35:41Z"
      state="did not finish"
      integrity="Work stopped at the wall clock. Every file named here still carries its sha256, but the timeline below ends where the run did, not where the incident did."
    />
  </div>
);

/** No organisation, no case: the minimum a run can be reported under. */
export const Minimal = () => (
  <div style={{ maxWidth: 680 }}>
    <ReportCover runId="s2cb9" generatedAt="2026-02-11T09:14:02Z" />
  </div>
);
