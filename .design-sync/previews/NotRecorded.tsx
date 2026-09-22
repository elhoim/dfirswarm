import { NotRecorded } from "dfirswarm";

const col: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 10, maxWidth: 620 };

/**
 * Absence, stated. A silent gap reads as "nothing happened", and that is a
 * different claim from "nobody recorded anything".
 */
export const Absences = () => (
  <div style={col}>
    <NotRecorded what="No indicators" why="Nothing was recorded with kind `ioc`." />
    <NotRecorded
      what="No events on the timeline"
      why="The run stopped before any agent called `record` with a dated event, so the timeline is empty rather than short."
    />
  </div>
);

/** Sometimes the absence is the finding, and the note carries the whole explanation. */
export const TheAbsenceIsTheFinding = () => (
  <div style={col}>
    <NotRecorded
      what="No artifacts"
      why="This run wrote nothing under `work/`. The evidence was read and hashed, so an empty work directory here means the swarm carved nothing, not that its output was lost."
    />
  </div>
);
