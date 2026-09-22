import { Chip } from "dfirswarm";

/** One tone per meaning: the whole vocabulary in the order a run uses it. */
export const Tones = () => (
  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
    <Chip tone="kelp">running</Chip>
    <Chip tone="moss">done</Chip>
    <Chip tone="saffron">stalled</Chip>
    <Chip tone="brick">violation</Chip>
    <Chip tone="slate">claim</Chip>
    <Chip tone="neutral">prepared</Chip>
    <Chip tone="band">system</Chip>
  </div>
);

/** `mono` is for identifiers: a swarm id, a path, a tool name. Never for words. */
export const Identifiers = () => (
  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
    <Chip tone="neutral" mono>s2cb903</Chip>
    <Chip tone="slate" mono>work/report.md</Chip>
    <Chip tone="kelp" mono>claim_file</Chip>
    <Chip tone="brick" mono>done/SWARM_DONE</Chip>
  </div>
);
