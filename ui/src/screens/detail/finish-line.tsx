/**
 * The finish line: the goal's own checks, run in the sandbox the way
 * await-done.sh certifies a run. Pending never looks like failed, and the
 * panel says where the checks came from — a swarm cannot rewrite them.
 */
import { useCallback } from "react";
import { Check, CircleDashed, X } from "lucide-react";
import { Chip, FinishMeter, SerifH } from "@/components/console";
import { api } from "@/lib/api";
import { useResource } from "@/lib/live";
import type { SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

function definitionOfDone(goal: string): string {
  const match = goal.match(/^##\s+Definition of done\s*$([\s\S]*?)(?=^#{1,6}\s|\Z)/im);
  return match ? match[1].trim() : "";
}

export function FinishLinePanel({ view, version, compact = false }: { view: SwarmView; version: number; compact?: boolean }) {
  const id = view.summary.id;
  const loader = useCallback(() => api.checks(id), [id]);
  const report = useResource(loader, version, [id]);
  const dod = definitionOfDone(view.goal_document || view.goal);
  const data = report.data;
  const total = data?.total ?? view.summary.checks_total;
  const passed = data?.passed ?? 0;
  const failed = data ? data.checks.filter((c) => !c.ok).length : 0;
  const running = view.summary.phase === "running";
  const certified = Boolean(data && view.sentinel && total > 0 && passed === total);

  const headline = !data
    ? "running the checks…"
    : total === 0
      ? "no checks · the sentinel is the only signal"
      : certified
        ? `${passed} of ${total} · certified`
        : running
          ? `${passed} of ${total}${failed ? ` · ${failed} not yet` : ""}`
          : `${passed} of ${total} · ${failed} failing`;
  const tone = certified ? "moss" : !data ? "neutral" : failed && !running ? "brick" : "saffron";

  return (
    <section className={cn("card flex flex-col gap-2.5 rounded-xl p-[18px_20px]", compact && "p-4")}>
      <div className="flex items-baseline justify-between gap-2">
        <SerifH as="h3" size={22}>
          Finish line
        </SerifH>
        <Chip tone={tone}>{headline}</Chip>
      </div>
      {!compact && dod ? <p className="m-0 text-[12.5px] leading-[1.5] text-ink-2 [text-wrap:pretty]">{dod}</p> : null}
      <FinishMeter passed={passed} total={total} failed={running ? 0 : failed} pendingTone={running ? "saffron" : "neutral"} />
      {!compact && data ? (
        <ul className="m-0 flex list-none flex-col p-0">
          {data.checks.map((c, i) => (
            <li key={i} className="grid grid-cols-[20px_minmax(0,1fr)] items-start gap-2.5 border-t border-paper-2 py-2.5">
              {c.ok ? (
                <Check className="size-[18px] text-moss" strokeWidth={2.6} aria-label="passed" />
              ) : running && !c.timed_out ? (
                <CircleDashed className="size-[18px] text-saffron" strokeWidth={2.2} aria-label="not yet" />
              ) : (
                <X className="size-[18px] text-brick" strokeWidth={2.6} aria-label="failed" />
              )}
              <div className="flex min-w-0 flex-col gap-1">
                <code className="break-all font-mono text-[11.5px] leading-[1.45] text-ink-2">{c.cmd}</code>
                {c.timed_out ? <span className="text-[12px] text-brick-ink">timed out</span> : null}
              </div>
            </li>
          ))}
        </ul>
      ) : null}
      {data?.error ? <span className="text-[12px] text-brick-ink">{data.error}</span> : null}
      {!compact ? (
        <span className="text-[11.5px] text-ink-3">
          {data?.source === "registry"
            ? "Checks are read from the registry, not the sandbox — agents cannot rewrite the finish line."
            : data?.source === "sandbox contract"
              ? "No registry entry for this run: checks were read from the sandbox's own SWARM.md, which agents can reach."
              : "Checks come from the goal document the operator submitted."}
        </span>
      ) : null}
    </section>
  );
}
