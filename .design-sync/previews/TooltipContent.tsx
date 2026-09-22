import { Chip, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const stage = { display: "flex", alignItems: "center", justifyContent: "center", minHeight: 150 } as const;
const leftStage = { display: "flex", alignItems: "center", justifyContent: "flex-start", minHeight: 150 } as const;

/**
 * The content is the one dark surface the light console allows outside the
 * vitals band: `ink` ground, `paper` text, and the only place the product
 * writes a full sentence at 12px. Default side — above the trigger.
 */
export const AboveTheTrigger = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <span>
            <Chip tone="kelp">live</Chip>
          </span>
        </TooltipTrigger>
        <TooltipContent>Server-sent events connected. Filesystem watcher active.</TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);

/** `side` is the variant axis: beside the trigger, with a wider `sideOffset`. */
export const BesideTheTrigger = () => (
  <TooltipProvider delayDuration={250}>
    <div style={leftStage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <span>
            <Chip tone="brick">offline</Chip>
          </span>
        </TooltipTrigger>
        <TooltipContent side="right" sideOffset={8}>
          Event stream lost. Retrying every 3 s; data may be stale.
        </TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);

/**
 * At `max-w-xs` a long explanation wraps rather than stretching across the
 * window — which is what lets a tooltip carry a real rule, not just a noun.
 */
export const WrappingExplanation = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <span>
            <Chip tone="neutral">dark</Chip>
          </span>
        </TooltipTrigger>
        <TooltipContent>Idle past the dim threshold, or last tag was hold / veto / stop.</TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);
