/**
 * An agent's reasoning, and the honest account of its absence.
 *
 * THINKING used to be a tab like the others: one line per event, each turn's
 * reasoning clipped to whatever fitted between the clock and the duration —
 * except that the line was blank, because the console read `args.text` and
 * the harness writes the text in the result. Every reasoning event in every
 * run rendered as an empty italic gap.
 *
 * Underneath the bug sat a real fact that the fix must not hide: on BelkaCTF
 * #6 three of ten agents produced no reasoning at all. Their model returns
 * none through the provider's API, while four other models on the same run
 * produced 389 lines between them. So an empty tab has two possible meanings,
 * and the panel now says which one it is looking at instead of "traces/
 * events.jsonl is empty for this selection".
 *
 * Reasoning is prose, so it is set as prose: a block per turn, wrapped, the
 * clock in the margin, and a note under a clipped block saying how much was
 * kept of how much there was.
 */
import type { ReactNode } from "react";
import { useCallback, useMemo } from "react";
import { Brain } from "lucide-react";
import { Pager, usePager } from "@/components/pager";
import { EmptyState, LoadingState } from "@/components/states";
import { api } from "@/lib/api";
import { clock } from "@/lib/format";
import { useResource } from "@/lib/live";
import { shortModel, thinkingCensus, thinkingChars, thinkingText, thinkingTruncated } from "@/lib/thinking";
import type { AgentRow, SwarmEvent, SwarmView } from "@/lib/types";


function list(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/**
 * Why this agent has no reasoning to show — measured, not assumed.
 *
 * One request with `limit=1`: `matched_by_agent` carries the per-agent count
 * over every reasoning line in the run, so the whole answer costs one event
 * of payload instead of a megabyte of prose.
 */
function NoThinking({ view, agent, version }: { view: SwarmView; agent: AgentRow; version: number }) {
  const id = view.summary.id;
  const loader = useCallback(() => api.traces(id, { tool: "thinking", limit: 1 }), [id]);
  const swarm = useResource(loader, version, [id, "thinking-census"]);
  const census = useMemo(
    () => thinkingCensus(agent.id, view.team.agents, swarm.data?.matched_by_agent ?? {}, view.summary.model || "its model"),
    [swarm.data, view.team.agents, view.summary.model, agent.id],
  );

  if (swarm.loading && !swarm.data) return <LoadingState label="Counting reasoning across the run" rows={2} />;

  const { verdict, model, mine, others, total } = census;
  const spoke = others.map((o) => `${shortModel(o.model)} (${o.lines.toLocaleString()})`);
  const peers = mine.agents - 1;

  let title: string;
  let hint: ReactNode;
  if (verdict === "run-silent") {
    title = "No model in this run returned reasoning";
    hint = (
      <>
        Not one of the {view.team.agents.length} agents produced a thinking line. The harness records the reasoning a
        provider sends back; none of these models sent any. What they did is still in TOOLS and MESSAGES.
      </>
    );
  } else if (verdict === "model-silent") {
    title = "This model returns no reasoning";
    hint = (
      <>
        <span className="font-mono">{model}</span> emitted no thinking at all in this run — not for this agent
        {peers > 0 ? <>, and not for the other {peers} agent{peers === 1 ? "" : "s"} on it</> : null}.
        {spoke.length ? (
          <>
            {" "}
            {list(spoke)} did, {total.toLocaleString()} lines between them.
          </>
        ) : null}{" "}
        This is what the provider sent back, not a gap in the recording: the work itself is in TOOLS and MESSAGES.
      </>
    );
  } else {
    title = "This agent left no reasoning";
    hint = (
      <>
        The other agents on <span className="font-mono">{model}</span> produced {mine.lines.toLocaleString()} thinking
        line{mine.lines === 1 ? "" : "s"}; this one produced none.
      </>
    );
  }
  return <EmptyState icon={<Brain />} title={title} hint={hint} />;
}

/** Reasoning, set as prose: one block per turn, the clock in the margin. */
export function ThinkingStream({
  view,
  agent,
  events,
  version,
  colour,
}: {
  view: SwarmView;
  agent: AgentRow;
  events: SwarmEvent[];
  version: number;
  colour: string;
}) {
  const pager = usePager(events, agent.id, 25);
  if (!events.length) return <NoThinking view={view} agent={agent} version={version} />;
  return (
    <div>
    <ol className="m-0 flex list-none flex-col gap-2 p-0" aria-label="Reasoning">
      {pager.rows.map((e, i) => (
        <li key={`${e.ts}-${i}`} className="card rounded-lg p-0">
          <div className="grid gap-x-3 px-3 py-2 sm:grid-cols-[76px_minmax(0,1fr)]">
            <span className="whitespace-nowrap pt-0.5 font-mono text-[11px] tabular text-ink-3" title={e.ts}>
              {clock(e.ts)}
            </span>
            <div style={{ borderLeft: `2px solid ${colour}`, paddingLeft: "0.75rem" }}>
              <p className="m-0 whitespace-pre-wrap break-words text-[13px] leading-[1.6] text-ink-2">{thinkingText(e)}</p>
              {thinkingTruncated(e) ? (
                <p className="m-0 mt-1 font-mono text-[10.5px] text-ink-3">
                  the first {thinkingText(e).length.toLocaleString()} of {thinkingChars(e)!.toLocaleString()} characters
                  · the rest stays in the agent's own session file
                </p>
              ) : null}
            </div>
          </div>
        </li>
      ))}
    </ol>
    <Pager page={pager.page} onPage={pager.set} onSize={pager.setSize} unit="turns" />
    </div>
  );
}
