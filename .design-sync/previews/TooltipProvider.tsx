import { Chip, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const stage = { display: "flex", alignItems: "center", justifyContent: "center", minHeight: 150 } as const;
const row = { display: "flex", alignItems: "center", gap: 10 } as const;

/**
 * The provider renders nothing and owns the timing: one
 * `delayDuration={250}` at the root of the console is why the whole app's
 * tooltips open at the same speed. Every story here is a consumer inside it.
 */
export const ConsoleProvider = () => (
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
 * One provider, several consumers — the header chip, a dark thread, a claimed
 * path. Only the hovered one is open; the other two are waiting on the same
 * delay, which is the provider's whole job.
 */
export const ManyConsumersOneProvider = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <div style={row}>
        <Tooltip>
          <TooltipTrigger asChild>
            <span>
              <Chip tone="kelp">live</Chip>
            </span>
          </TooltipTrigger>
          <TooltipContent>Server-sent events connected. Filesystem watcher active.</TooltipContent>
        </Tooltip>
        <Tooltip defaultOpen>
          <TooltipTrigger asChild>
            <span>
              <Chip tone="neutral">dark</Chip>
            </span>
          </TooltipTrigger>
          <TooltipContent>Idle past the dim threshold, or last tag was hold / veto / stop.</TooltipContent>
        </Tooltip>
        <Tooltip>
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
    </div>
  </TooltipProvider>
);
