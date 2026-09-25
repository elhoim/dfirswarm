/**
 * The method a run carried. A pack ships skills the agents fetch by name, and
 * every fetch is on the trace, so this tab can answer three questions the rest
 * of the console cannot: which method was in force, which parts of it the swarm
 * actually read, and which parts it carried and never opened.
 *
 * The last one matters most. A pack whose skills go unread is weight in the
 * context window and a signal that the index line for that skill does not say
 * when to reach for it.
 */
import { useMemo } from "react";
import { Package } from "lucide-react";
import { Chip, PhaseHead, SerifH } from "@/components/console";
import { EmptyState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { relTime } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import type { SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

type Fetch = { id: string; agent: string; ts: string };

function AgentChips({ agents, colour, names }: {
  agents: string[];
  colour: (id: string) => string;
  names: (id: string) => string;
}) {
  return (
    <span className="flex flex-wrap gap-1">
      {agents.map((a) => (
        <span key={a} className={cn("rounded px-1.5 py-0.5 text-[11px] font-mono", colour(a))} title={a}>
          {names(a)}
        </span>
      ))}
    </span>
  );
}

export function PacksPanel({ view }: { view: SwarmView }) {
  const colour = useAgentColours(view.agents);
  const names = useAgentNames(view.agents);
  const packs = view.packs ?? [];
  const secrets = (view.registry as { pack_secrets?: Record<string, { names?: string[]; mode?: string }> } | null)?.pack_secrets;

  const { fetches, bySkill, indexReads, packOf } = useMemo(() => {
    const fetches: Fetch[] = [];
    let indexReads = 0;
    for (const e of view.traces) {
      if (e.tool !== "skill") continue;
      const id = (e.args as { id?: unknown } | null)?.id;
      // The extension logs an index read as the literal id INDEX; it is a read
      // of the catalogue, not of a skill, and it does not belong in the table.
      if (typeof id === "string" && id.trim() && id.trim() !== "INDEX") {
        fetches.push({ id: id.trim(), agent: e.agent, ts: e.ts });
      } else {
        indexReads += 1;
      }
    }
    const bySkill = new Map<string, { n: number; agents: Set<string>; first: string; last: string }>();
    for (const f of fetches) {
      const row = bySkill.get(f.id) ?? { n: 0, agents: new Set<string>(), first: f.ts, last: f.ts };
      row.n += 1;
      row.agents.add(f.agent);
      if (f.ts < row.first) row.first = f.ts;
      if (f.ts > row.last) row.last = f.ts;
      bySkill.set(f.id, row);
    }
    // Which pack a skill id belongs to. A body is served by the first pack that
    // has it, which is the same order the kickoff resolved.
    const packOf = new Map<string, string>();
    for (const p of packs) for (const s of p.skills) if (!packOf.has(s.id)) packOf.set(s.id, p.id);
    return { fetches, bySkill, indexReads, packOf };
  }, [view.traces, packs]);

  const packTools = useMemo(() => view.tools.filter((t) => typeof t.pack === "string" && t.pack), [view.tools]);

  if (!packs.length) {
    return (
      <EmptyState
        icon={<Package />}
        title="This run carried no pack"
        hint="A pack brings method the agents fetch with the skill tool, tools seeded into the run, and the host binaries a case needs. Start a swarm with --pack (or pick one at Kickoff) and what the swarm consulted shows up here. A run without one behaves exactly as it always has."
      />
    );
  }

  const consulted = [...bySkill.entries()].sort((a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0]));
  const carried = packs.flatMap((p) => p.skills.map((s) => ({ ...s, pack: p.id })));
  const untouched = carried.filter((s) => !bySkill.has(s.id));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <SerifH>The method this run carried</SerifH>
        <span className="text-xs text-muted-foreground">
          {fetches.length} skill {fetches.length === 1 ? "fetch" : "fetches"} across {new Set(fetches.map((f) => f.agent)).size} agent(s)
          {indexReads ? `, and the index read ${indexReads}×` : ""}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {packs.map((p) => {
          const mine = carried.filter((s) => s.pack === p.id);
          const read = mine.filter((s) => bySkill.has(s.id)).length;
          const toolsUsed = packTools.filter((t) => t.pack === p.id && t.calls > 0).length;
          return (
            <div key={p.id} className="rounded-lg border p-3 space-y-2">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-medium">{p.name}</span>
                <Chip>{p.version}</Chip>
              </div>
              <p className="text-xs text-muted-foreground">{p.description}</p>
              <div className="flex flex-wrap gap-3 text-xs">
                <span><b>{read}</b> of {mine.length} skills consulted</span>
                <span><b>{toolsUsed}</b> of {packTools.filter((t) => t.pack === p.id).length} tools called</span>
              </div>
              <p className="font-mono text-[11px] text-muted-foreground">
                manifest {p.manifest_sha256.slice(0, 16)}
                {p.installed ? "" : " · no longer installed on this host"}
              </p>
              {secrets?.[p.id] ? (
                // What the kickoff did with the pack's secrets, from the run
                // record: injected into VMs bound to their hosts, exposed to
                // host panes, withheld, or never set.
                <p className={cn("text-xs [overflow-wrap:anywhere]", secrets[p.id].mode === "exposed" ? "text-brick-ink" : secrets[p.id].mode === "withheld" || secrets[p.id].mode === "not-set" ? "text-saffron-ink" : "text-muted-foreground")}>
                  secrets {(secrets[p.id].names ?? []).join(", ")} · {secrets[p.id].mode ?? "?"}
                </p>
              ) : null}
            </div>
          );
        })}
      </div>

      <div className="space-y-2">
        <PhaseHead title="What the swarm read" />
        {consulted.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-muted-foreground">
                  <th className="py-1 pr-3 font-normal">Skill</th>
                  <th className="py-1 pr-3 font-normal">Pack</th>
                  <th className="py-1 pr-3 font-normal">Fetches</th>
                  <th className="py-1 pr-3 font-normal">Who read it</th>
                  <th className="py-1 font-normal">Last</th>
                </tr>
              </thead>
              <tbody>
                {consulted.map(([id, row]) => (
                  <tr key={id} className="border-t align-top">
                    <td className="py-1.5 pr-3 font-mono text-[12px]">{id}</td>
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground">{packOf.get(id) ?? "unknown"}</td>
                    <td className="py-1.5 pr-3 tabular-nums">{row.n}</td>
                    <td className="py-1.5 pr-3">
                      <AgentChips agents={[...row.agents].sort()} colour={colour} names={names} />
                    </td>
                    <td className="py-1.5 text-xs text-muted-foreground">{relTime(row.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            The packs were loaded and no agent opened a skill. Either the case did not need the method, or the index does not say when to reach for it.
          </p>
        )}
      </div>

      {untouched.length ? (
        <div className="space-y-2">
          <PhaseHead title="Carried, and never opened" />
          <p className="text-xs text-muted-foreground">
            These travelled with the run and no agent asked for them. On a case they do not fit that is right; when the case did need one, its line in the index is not saying so.
          </p>
          <ul className="grid gap-1 sm:grid-cols-2">
            {untouched.map((s) => (
              <li key={s.id} className="text-xs">
                <span className="font-mono">{s.id}</span>
                <span className="text-muted-foreground"> · {s.title}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {packTools.length ? (
        <div className="space-y-2">
          <PhaseHead title="Tools the packs brought" />
          {packTools.some((t) => t.calls > 0) ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-muted-foreground">
                    <th className="py-1 pr-3 font-normal">Tool</th>
                    <th className="py-1 pr-3 font-normal">Pack</th>
                    <th className="py-1 pr-3 font-normal">Calls</th>
                    <th className="py-1 font-normal">Who called it</th>
                  </tr>
                </thead>
                <tbody>
                  {packTools.filter((t) => t.calls > 0).sort((a, b) => b.calls - a.calls).map((t) => (
                    <tr key={t.name} className="border-t align-top">
                      <td className="py-1.5 pr-3 font-mono text-[12px]">{t.name}</td>
                      <td className="py-1.5 pr-3 text-xs text-muted-foreground">{t.pack}</td>
                      <td className="py-1.5 pr-3 tabular-nums">{t.calls}</td>
                      <td className="py-1.5"><AgentChips agents={t.users} colour={colour} names={names} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              None of them was called. The agents worked the evidence with the shell instead, which is a fair answer on a small case and a question worth asking on a large one.
            </p>
          )}
          {packTools.some((t) => t.calls === 0) ? (
            <p className="text-xs text-muted-foreground">
              <span className="text-foreground">Carried, never called:</span>{" "}
              <span className="font-mono">{packTools.filter((t) => t.calls === 0).map((t) => t.name).join(", ")}</span>
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="space-y-2">
        <PhaseHead title="By agent" />
        <ul className="space-y-1 text-sm">
          {view.agents.map((a) => {
            const mine = fetches.filter((f) => f.agent === a.id);
            if (!mine.length) return (
              <li key={a.id} className="text-xs text-muted-foreground">
                <span className={cn("rounded px-1.5 py-0.5 font-mono", colour(a.id))}>{names(a.id)}</span> read no skill
              </li>
            );
            const distinct = [...new Set(mine.map((f) => f.id))];
            return (
              <li key={a.id} className="flex flex-wrap items-baseline gap-2">
                <span className={cn("rounded px-1.5 py-0.5 text-[11px] font-mono", colour(a.id))}>{names(a.id)}</span>
                <span className="text-xs text-muted-foreground">
                  {mine.length} {mine.length === 1 ? "fetch" : "fetches"}, {distinct.length} distinct:
                </span>
                <span className="font-mono text-[11px] text-muted-foreground">{distinct.join(", ")}</span>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
