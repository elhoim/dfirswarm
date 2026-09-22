/**
 * The two rhythm instruments of the console.
 *
 * ActivityStrip runs along the foot of a swarm's page: messages against tool
 * calls over the whole run, with the wall-clock at both ends. A run that is
 * all tool calls and no messages is a team that stopped talking; a burst of
 * messages with no calls is a team arguing instead of building.
 *
 * ThreadPulse is one line per thread with a dot per post, coloured by who
 * posted — the shape of a conversation at a glance.
 */
import { useMemo } from "react";
import { clock } from "@/lib/format";
import type { ActivitySeries, ThreadDot } from "@/lib/types";
import { cn } from "@/lib/utils";

export function ActivityStrip({ series, className }: { series: ActivitySeries; className?: string }) {
  const max = Math.max(1, ...series.buckets.map((b) => b.m + b.c));
  const empty = series.messages + series.tool_calls === 0;
  return (
    <div className={cn("flex flex-col gap-1", className)} aria-label="Activity over the run">
      <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-baseline gap-3 font-mono text-[11.5px] tabular text-ink-3">
        <span>{series.from ? clock(series.from) : "—"}</span>
        <span className="text-center">
          <span className="text-brick-ink">{series.messages.toLocaleString()} message{series.messages === 1 ? "" : "s"}</span>
          <span className="mx-2">|</span>
          <span className="text-ink">{series.tool_calls.toLocaleString()} tool call{series.tool_calls === 1 ? "" : "s"}</span>
        </span>
        <span>{series.to ? clock(series.to) : "—"}</span>
      </div>
      <div className="flex h-8 items-end gap-px" aria-hidden>
        {series.buckets.map((b, i) => {
          const total = b.m + b.c;
          const h = total ? Math.max(3, Math.round((total / max) * 32)) : 0;
          const mh = total ? Math.round((b.m / total) * h) : 0;
          return (
            <div key={i} className="flex flex-1 flex-col justify-end" style={{ height: 32 }} title={total ? `${b.m} message${b.m === 1 ? "" : "s"} · ${b.c} tool call${b.c === 1 ? "" : "s"}` : undefined}>
              {total ? (
                <>
                  {mh ? <span className="block w-full bg-brick" style={{ height: mh }} /> : null}
                  {h - mh ? <span className="block w-full bg-ink" style={{ height: h - mh }} /> : null}
                </>
              ) : (
                <span className="block w-full bg-paper-3" style={{ height: 1 }} />
              )}
            </div>
          );
        })}
      </div>
      {empty ? <span className="text-[11.5px] text-ink-3">Nothing traced yet — the strip fills with the first tool call.</span> : null}
    </div>
  );
}

/** Up to this many agents get a lane of their own; past it the pulse is one row of ticks. */
const MAX_LANES = 12;

export function ThreadPulse({
  dots,
  from,
  to,
  colour,
  className,
  names,
  lanes,
}: {
  dots: ThreadDot[];
  from: string | null;
  to: string | null;
  colour: (id: string) => string;
  names?: (id: string) => string;
  className?: string;
  /**
   * Agent ids in seat order. With a small team every agent gets a thin lane
   * of its own and each post is a dot on its author's lane; with a big one
   * the posts are ticks on a single row, so a 10-agent thread and a 30-agent
   * one both stay readable.
   */
  lanes?: string[];
}) {
  const model = useMemo(() => {
    const stamps = dots.map((d) => (d.at ? Date.parse(d.at) : NaN));
    const known = stamps.filter((n) => Number.isFinite(n));
    if (!known.length) return null;
    const startMs = from && Number.isFinite(Date.parse(from)) ? Date.parse(from) : Math.min(...known);
    const endMs = to && Number.isFinite(Date.parse(to)) ? Date.parse(to) : Math.max(Date.now(), ...known);
    const span = Math.max(1, endMs - startMs);
    const placed = dots
      .map((d, i) => ({ ...d, t: stamps[i], x: Number.isFinite(stamps[i]) ? Math.min(1, Math.max(0, (stamps[i] - startMs) / span)) : null }))
      .filter((d): d is ThreadDot & { t: number; x: number } => d.x !== null);
    let newest = -1;
    for (let i = 0; i < placed.length; i++) if (newest < 0 || placed[i].t >= placed[newest].t) newest = i;
    return { placed, newest };
  }, [dots, from, to]);
  const laned = lanes && lanes.length > 0 && lanes.length <= MAX_LANES ? lanes : null;
  const height = laned ? laned.length * 5 + 6 : 14;
  const laneY = (id: string) => {
    if (!laned) return 50;
    const i = laned.indexOf(id);
    return i < 0 ? 50 : ((i + 0.5) / laned.length) * 100;
  };
  return (
    <div className={cn("relative w-full", className)} style={{ height }} aria-label={`${dots.length} post${dots.length === 1 ? "" : "s"}`}>
      {laned ? (
        laned.map((id) => <span key={id} className="absolute left-0 right-0 h-px opacity-35" style={{ top: `${laneY(id)}%`, background: colour(id) }} />)
      ) : (
        <span className="absolute left-0 right-0 top-1/2 h-px -translate-y-1/2 bg-line" />
      )}
      {model?.placed.map((d, i) => {
        const ring = i === model.newest;
        const system = d.from === "system";
        return (
          <span
            key={i}
            className={cn(
              "absolute -translate-x-1/2 -translate-y-1/2",
              laned ? "size-[6px] rounded-full" : "h-[10px] w-[3px] rounded-[1px]",
              system && "size-[8px] rotate-45 rounded-none",
              ring && "ring-2 ring-offset-1 ring-offset-card",
            )}
            style={{ left: `${d.x * 100}%`, top: `${laneY(d.from)}%`, background: colour(d.from), ...(ring ? ({ "--tw-ring-color": colour(d.from) } as Record<string, string>) : {}) }}
            title={`${names ? names(d.from) : d.from} · ${d.tag} · ${clock(d.at)}`}
          />
        );
      })}
    </div>
  );
}
