import { StatusDot, Chip, FinishMeter } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const legend = { display: "flex", flexWrap: "wrap", alignItems: "center", gap: 28 } as const;
const item = { display: "flex", alignItems: "center", gap: 8 } as const;
const rows = { display: "flex", flexDirection: "column", gap: 10 } as const;
const line = { display: "grid", gridTemplateColumns: "28px minmax(0, 1fr) 190px", alignItems: "center", gap: 20 } as const;
const chips = { display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 } as const;

/**
 * The five phases a swarm can be in, and the mark for each: a kelp ring while
 * it runs, a moss tick when it is done, a brick square when it was stopped,
 * and a dashed ring for the two that have not happened — prepared and unknown.
 */
export const Phases = () => (
  <div style={legend}>
    <span style={item}>
      <StatusDot phase="running" />
      <span className="text-[13px] text-ink-2">running</span>
    </span>
    <span style={item}>
      <StatusDot phase="done" />
      <span className="text-[13px] text-ink-2">done</span>
    </span>
    <span style={item}>
      <StatusDot phase="stopped" />
      <span className="text-[13px] text-ink-2">stopped</span>
    </span>
    <span style={item}>
      <StatusDot phase="prepared" />
      <span className="text-[13px] text-ink-2">prepared</span>
    </span>
    <span style={item}>
      <StatusDot phase="unknown" />
      <span className="text-[13px] text-ink-2">unknown</span>
    </span>
  </div>
);

/**
 * Where it lives: the first cell of a swarm row on the overview, read before
 * the label and before any chip.
 */
export const OnTheRow = () => (
  <div style={rows}>
    <div style={line}>
      <StatusDot phase="running" />
      <span style={chips}>
        <span className="serif text-[22px]">dfir-alihadi</span>
        <span className="font-mono text-[12px] text-ink-3">s2cb9</span>
        <Chip tone="kelp">running · 14m</Chip>
        <Chip tone="neutral">7 agents</Chip>
      </span>
      <FinishMeter passed={4} total={9} pendingTone="saffron" />
    </div>
    <div style={line}>
      <StatusDot phase="done" />
      <span style={chips}>
        <span className="serif text-[22px]">dfir-c11-administrator-files</span>
        <span className="font-mono text-[12px] text-ink-3">sf6df</span>
        <Chip tone="moss">done</Chip>
        <Chip tone="neutral">5 agents</Chip>
      </span>
      <FinishMeter passed={9} total={9} pendingTone="neutral" />
    </div>
    <div style={line}>
      <StatusDot phase="stopped" />
      <span style={chips}>
        <span className="serif text-[22px]">dfir-l03-attacker-kali</span>
        <span className="font-mono text-[12px] text-ink-3">sf4b2</span>
        <Chip tone="brick">stopped · cap reached</Chip>
        <Chip tone="saffron">3 harness posts</Chip>
      </span>
      <FinishMeter passed={6} total={9} failed={1} pendingTone="neutral" />
    </div>
    <div style={line}>
      <StatusDot phase="prepared" />
      <span style={chips}>
        <span className="serif text-[22px]">dfir-m01-ransomcare</span>
        <span className="font-mono text-[12px] text-ink-3">s71c4</span>
        <Chip tone="slate">prepared · not launched</Chip>
      </span>
      <FinishMeter passed={0} total={7} pendingTone="neutral" />
    </div>
  </div>
);
