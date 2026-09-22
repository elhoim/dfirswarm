import { Button, Chip, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const stage = { display: "flex", alignItems: "center", justifyContent: "center", minHeight: 150 } as const;

/**
 * The trigger is always `asChild` in this console: it renders no element of its
 * own, it adopts the one already there. Here it adopts the header's live chip
 * through a `span`, which is what gives a chip — a non-focusable element —
 * something to hang the hover on.
 */
export const AsChildOnAChip = () => (
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

/**
 * Adopting a `Button` instead: the trigger keeps the button's `danger`
 * treatment and adds the one thing the label leaves out — the command it runs.
 */
export const AsChildOnAButton = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <Button variant="danger" size="sm">
            Stop swarm
          </Button>
        </TooltipTrigger>
        <TooltipContent>swarm.sh stop</TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);

/**
 * A mono identifier as the trigger. The claimed path is the thing on screen;
 * who holds it and for how long is the thing the tooltip adds.
 */
export const AsChildOnAPath = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <span>
            <Chip tone="slate" mono>
              work/report.md
            </Chip>
          </span>
        </TooltipTrigger>
        <TooltipContent>Claimed by s2cb903 · lease expires in 900 s.</TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);
