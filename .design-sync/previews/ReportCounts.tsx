import { ReportCounts } from "dfirswarm";

/** What the ledger holds. The fourth number is the one that decides whether the other three are worth anything. */
export const EverythingCited = () => (
  <div style={{ maxWidth: 620 }}>
    <ReportCounts events={18} indicators={7} findings={6} uncited={0} />
  </div>
);

/** A non-zero uncited count is stated in brick, because a reader will otherwise assume it is zero. */
export const SomeUncited = () => (
  <div style={{ maxWidth: 620 }}>
    <ReportCounts events={18} indicators={7} findings={6} uncited={3} />
  </div>
);

/** A run that recorded nothing: four zeros, which is an honest answer and not an empty panel. */
export const NothingRecorded = () => (
  <div style={{ maxWidth: 620 }}>
    <ReportCounts events={0} indicators={0} findings={0} />
  </div>
);
