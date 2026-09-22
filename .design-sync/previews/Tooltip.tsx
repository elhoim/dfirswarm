import { Chip, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is the app's
// compiled CSS and carries only the classes the app itself uses.
const stage = { display: "flex", alignItems: "center", justifyContent: "center", minHeight: 150 } as const;

/**
 * `Tooltip` is the root: it holds one trigger and one content and nothing else,
 * so the story is the pair, held open. In the console it explains the header's
 * live chip — the sentence a coloured dot cannot say on its own.
 */
export const EventStreamLive = () => (
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

/** The stream is up but the watcher is not: the chip goes quiet, the tooltip says why. */
export const EventStreamPolling = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <span>
            <Chip tone="neutral">live · polling</Chip>
          </span>
        </TooltipTrigger>
        <TooltipContent>Server-sent events connected. Watcher unavailable; polling every 3 s.</TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);

/** Lost. The one state where the tooltip is telling the operator not to trust the numbers. */
export const EventStreamOffline = () => (
  <TooltipProvider delayDuration={250}>
    <div style={stage}>
      <Tooltip defaultOpen>
        <TooltipTrigger asChild>
          <span>
            <Chip tone="brick">offline</Chip>
          </span>
        </TooltipTrigger>
        <TooltipContent>Event stream lost. Retrying every 3 s; data may be stale.</TooltipContent>
      </Tooltip>
    </div>
  </TooltipProvider>
);
