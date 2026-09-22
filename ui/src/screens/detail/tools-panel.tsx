/**
 * The tools the agents forged for themselves: what each does, who wrote it,
 * which version is live, how often the swarm has called it and whether it
 * failed. Opening one shows the script as it is on disk — agent-written code
 * every peer is running, which is exactly why it should be one click away.
 */
import { useCallback, useMemo } from "react";
import { ArrowLeft, Hammer, Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Chip, PhaseHead, SerifH } from "@/components/console";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { clock, relTime } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import type { ForgedTool, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

function ParamList({ tool }: { tool: ForgedTool }) {
  const entries = Object.entries(tool.params);
  if (!entries.length) return <span className="text-[12px] text-ink-3">no params</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([name, p]) => (
        <span key={name} className="inline-flex h-6 items-center gap-1 rounded-[3px] border border-line px-1.5 font-mono text-[11px]" title={p.description ?? ""}>
          <span className="font-semibold text-ink">{name}</span>
          <span className="text-ink-3">
            {p.required ? "" : "?"}: {p.type}
            {p.enum ? ` ∈ {${p.enum.join(", ")}}` : ""}
          </span>
        </span>
      ))}
    </div>
  );
}

function ToolCard({ tool, colour, names, onOpen }: { tool: ForgedTool; colour: (id: string) => string; names: (id: string) => string; onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen} className="card flex w-full flex-col gap-2 rounded-[10px] p-3 text-left transition-colors hover:bg-paper-2/70" style={{ borderLeft: `3px solid ${colour(tool.by)}` }}>
      <div className="flex flex-wrap items-center gap-2">
        <Hammer className="size-4 text-ink-3" />
        <span className="font-mono text-[14px] font-semibold text-ink">{tool.name}</span>
        <Chip tone="neutral" mono>
          v{tool.version} · {tool.runtime}
        </Chip>
        <span className="text-[12px] text-ink-3">
          by <span className="font-mono font-medium" style={{ color: colour(tool.by) }}>{names(tool.by)}</span> · {relTime(tool.at)}
        </span>
        <span className="ml-auto font-mono text-[11.5px] tabular text-ink-3">
          {tool.calls} call{tool.calls === 1 ? "" : "s"}
          {tool.failures ? <span className="text-brick-ink"> · {tool.failures} failed</span> : null}
          {tool.users.length ? ` · ${tool.users.length} user${tool.users.length === 1 ? "" : "s"}` : ""}
        </span>
      </div>
      <p className="m-0 text-[13px] leading-[1.45] text-ink-2">{tool.description}</p>
      <ParamList tool={tool} />
      {tool.users.length ? (
        <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-ink-3">
          <Users className="size-3.5" />
          {tool.users.map((u) => (
            <span key={u} className="font-mono" style={{ color: colour(u) }}>
              {names(u)}
            </span>
          ))}
          {tool.last_used_at ? <span>· last {relTime(tool.last_used_at)}</span> : null}
        </div>
      ) : null}
    </button>
  );
}

function ToolDetail({ view, tool, version, colour, names, onBack }: { view: SwarmView; tool: ForgedTool; version: number; colour: (id: string) => string; names: (id: string) => string; onBack: () => void }) {
  const loader = useCallback(() => api.tool(view.summary.id, tool.name), [view.summary.id, tool.name]);
  const source = useResource(loader, version, [view.summary.id, tool.name]);
  const calls = useMemo(() => view.traces.filter((e) => e.tool === tool.name).slice(-20).reverse(), [view.traces, tool.name]);
  return (
    <div className="space-y-3">
      <button type="button" onClick={onBack} className="inline-flex items-center gap-1 text-[12px] text-ink-2 hover:text-ink">
        <ArrowLeft className="size-3.5" /> All tools
      </button>
      <div className="card rounded-[10px] p-4" style={{ borderTop: `4px solid ${colour(tool.by)}` }}>
        <div className="flex flex-wrap items-baseline gap-3">
          <SerifH as="h3" size={26} className="font-mono">
            {tool.name}
          </SerifH>
          <Chip tone="neutral" mono>
            v{tool.version} · {tool.runtime} · {tool.timeout_seconds}s timeout
          </Chip>
          <span title={tool.sha256}>
            <Chip tone="neutral" mono>
              {tool.sha256.slice(0, 12)}
            </Chip>
          </span>
        </div>
        <p className="m-0 mt-1.5 font-mono text-[12px] text-ink-3">
          forged by <span style={{ color: colour(tool.by) }}>{names(tool.by)}</span> at {clock(tool.at)} · tools/{tool.name}/{tool.entry}
        </p>
        <p className="m-0 mt-2 text-[13.5px] leading-[1.5] text-ink">{tool.description}</p>
        <div className="mt-2">
          <ParamList tool={tool} />
        </div>
        {tool.example ? <p className="m-0 mt-2 font-mono text-[12px] text-ink-2">Example: {tool.example}</p> : null}
      </div>
      <div>
        <PhaseHead title="The script" summary="as it is on disk — every agent runs these bytes; the manifest's hash has to match" />
        {source.error && !source.data ? <ErrorState error={source.error} onRetry={source.reload} /> : null}
        {source.loading && !source.data ? <LoadingState label="Reading the script" rows={4} /> : null}
        {source.data ? <pre className="card mt-2 max-h-[60vh] overflow-auto rounded-[10px] px-4 py-3 font-mono text-[12px] leading-[1.5] text-ink">{source.data.script}</pre> : null}
      </div>
      <div>
        <PhaseHead title="Recent calls" summary={`${tool.calls} in this run`} />
        {calls.length ? (
          <ol className="mt-2 flex list-none flex-col gap-1 p-0">
            {calls.map((e, i) => {
              const r = (e.result ?? {}) as Record<string, unknown>;
              return (
                <li key={`${e.ts}${i}`} className={cn("grid grid-cols-[86px_110px_minmax(0,1fr)_auto] items-baseline gap-2 rounded-md border px-2.5 py-1.5 font-mono text-[12px]", r.ok === false ? "border-brick/40 bg-brick-soft/50" : "border-line bg-card")}>
                  <span className="tabular text-ink-3">{clock(e.ts)}</span>
                  <span className="truncate font-semibold" style={{ color: colour(e.agent) }}>
                    {names(e.agent)}
                  </span>
                  <span className="truncate text-ink-2">
                    {JSON.stringify(e.args)}
                    {r.ok === false && typeof r.error === "string" ? <span className="text-brick-ink"> → {r.error}</span> : null}
                  </span>
                  <span className="tabular text-ink-3">{typeof r.duration_ms === "number" ? `${r.duration_ms}ms` : ""}</span>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="m-0 mt-2 text-[12.5px] text-ink-3">Nobody has called it yet.</p>
        )}
      </div>
    </div>
  );
}

export function ToolsPanel({ view, selected, onSelect, version }: { view: SwarmView; selected: string | null; onSelect: (name: string | null) => void; version: number }) {
  const colour = useAgentColours(view.agents);
  const names = useAgentNames(view.agents);
  const forging = view.registry?.tool_forging === true;
  const current = selected ? view.tools.find((t) => t.name === selected) ?? null : null;
  if (current) return <ToolDetail view={view} tool={current} version={version} colour={colour} names={names} onBack={() => onSelect(null)} />;
  // An empty tab used to look the same whether forging was off, forging was
  // on and nobody had taken a hint, or a library had simply never been
  // seeded. On the BelkaCTF #6 run the operator read it as "the agents are
  // not forging" while the harness had asked five times; six tools and 79
  // calls later that was wrong. Say which of the three it is.
  const hints = view.traces.filter((e) => e.tool === "forge_hint");
  if (!view.tools.length) {
    return (
      <EmptyState
        icon={<Hammer />}
        title={forging ? (hints.length ? `Nothing forged yet, and the harness has asked ${hints.length}×` : "Nothing forged yet") : "Tool forging is off for this swarm"}
        hint={
          !forging
            ? "Start a swarm with --allow-tool-forging (or the Kickoff switch) and agents can write tools with make_tool and share them. Off by default: a forged tool runs with the same limits as bash."
            : hints.length
              ? `The forge hint has fired ${hints.length} time(s) — an agent repeating the same command was told a tool would carry it — and nobody has written one. A tool pays for itself across runs as much as within one: "swarm.sh tools <id> --save DIR" keeps it, and --tools-from hands it to the next swarm. The hints themselves are in the raw trace under forge_hint.`
              : "An agent that needs a parser, a checker or a converter nobody has can write one with make_tool; it lands here and in every peer's tool list. No library was seeded for this run, so the agents started from nothing."
        }
      />
    );
  }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="flex items-baseline gap-2">
          <span className="text-[14px] font-semibold uppercase tracking-[0.04em] text-ink">Forged tools</span>
          <span className="font-mono text-[12px] tabular text-ink-3">{view.tools.length}</span>
        </span>
        <Badge variant="neutral">agent-written · runs as a subprocess in the sandbox</Badge>
      </div>
      <div className="flex flex-col gap-2">
        {view.tools.map((t) => (
          <ToolCard key={t.name} tool={t} colour={colour} names={names} onOpen={() => onSelect(t.name)} />
        ))}
      </div>
    </div>
  );
}
