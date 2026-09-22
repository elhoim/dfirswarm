import { Button } from "dfirswarm";

/** `default` is the only filled variant: one primary action per view. */
export const Variants = () => (
  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
    <Button>Start a swarm</Button>
    <Button variant="secondary">Save to library</Button>
    <Button variant="ghost">Cancel</Button>
    <Button variant="danger">Stop</Button>
    <Button variant="warn">Reap stalled</Button>
    <Button variant="outlineDanger">Discard run</Button>
    <Button variant="link">Open the trace</Button>
  </div>
);

export const Sizes = () => (
  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
    <Button size="sm">Small</Button>
    <Button>Default</Button>
    <Button size="lg">Large</Button>
    <Button disabled>Disabled</Button>
  </div>
);
