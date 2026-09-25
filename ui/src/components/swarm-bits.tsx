import { Check, Moon } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { compact, money, pct } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Chip } from "@/components/console";
import type { AgentMarker } from "@/lib/types";

/** ✓ done · ? dead/stalled · ● active. */
export function AgentMark({ marker, size = "md", className }: { marker: AgentMarker; size?: "sm" | "md"; className?: string }) {
  const dim = size === "sm" ? "size-4 text-[10px]" : "size-5 text-[12px]";
  const label = marker === "done" ? "done" : marker === "dead" ? "reaped (dead)" : marker === "stalled" ? "stalled, no recent activity" : "active";
  const body =
    marker === "done" ? (
      <span className={cn("inline-flex items-center justify-center rounded-full bg-moss text-white", dim, className)} aria-label={label}>
        <Check className="size-[70%]" strokeWidth={3} />
      </span>
    ) : marker === "dead" ? (
      <span className={cn("inline-flex items-center justify-center rounded-full bg-brick font-bold text-white", dim, className)} aria-label={label}>
        ?
      </span>
    ) : marker === "stalled" ? (
      <span className={cn("inline-flex items-center justify-center rounded-full border-2 border-saffron font-bold text-saffron-ink", dim, className)} aria-label={label}>
        ?
      </span>
    ) : (
      <span className={cn("inline-flex items-center justify-center rounded-full border-2 border-kelp", dim, className)} aria-label={label}>
        <span className="size-[40%] rounded-full bg-kelp" />
      </span>
    );
  return (
    <Tooltip>
      <TooltipTrigger asChild>{body}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

export function markerText(marker: AgentMarker): string {
  return marker === "done" ? "done · session end" : marker === "dead" ? "reaped" : marker === "stalled" ? "stalled" : "working";
}

export function BudgetBar({
  spent,
  cap,
  className,
  compactLabel = false,
  unit = "usd",
}: {
  spent: number;
  cap: number;
  className?: string;
  compactLabel?: boolean;
  /** What the two numbers are. A team of local models is measured in tokens, never in dollars. */
  unit?: "usd" | "tokens";
}) {
  const p = pct(spent, cap);
  const over = cap > 0 && spent >= cap;
  const hot = p >= 80;
  return (
    <div className={cn("min-w-0", className)}>
      <div className="flex items-baseline justify-between gap-2 text-[12px] tabular">
        <span className={cn("font-medium", over ? "text-brick-ink" : "text-ink")}>
          {unit === "tokens" ? compact(spent) : money(spent)}
          <span className="text-ink-3"> / {unit === "tokens" ? `${compact(cap)} tokens` : money(cap, 2)}</span>
        </span>
        {!compactLabel ? <span className={cn("text-ink-3", over && "text-brick-ink")}>{over ? "cap hit" : `${Math.round(p)}%`}</span> : null}
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-paper-3" role="progressbar" aria-valuenow={Math.round(p)} aria-valuemin={0} aria-valuemax={100}>
        <div
          className={cn("h-full rounded-full transition-[width] duration-500", over ? "bg-brick" : hot ? "bg-saffron" : "bg-kelp")}
          style={{ width: `${Math.max(p > 0 ? 2 : 0, p)}%` }}
        />
      </div>
    </div>
  );
}

export function DarkThreadMark({ className }: { className?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn("inline-flex items-center gap-1 text-[11px] text-ink-3", className)}>
          <Moon className="size-3" /> dark
        </span>
      </TooltipTrigger>
      <TooltipContent>Idle past the dim threshold, or last tag was hold / veto / stop.</TooltipContent>
    </Tooltip>
  );
}

/** Where the agents ran: one microVM each, or host processes, unisolated. A record from before the field is a host run. */
export function isolationChip(row: { isolation?: "microvm" | "host" }) {
  return row.isolation === "microvm" ? <Chip tone="kelp">microVM</Chip> : <Chip tone="saffron">host · unisolated</Chip>;
}
