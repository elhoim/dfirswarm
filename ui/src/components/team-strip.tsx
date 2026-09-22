/**
 * The team, under the run's name, as the answer to "who is doing this?".
 *
 * It used to be a row of model identifiers — `azure-foundry/DeepSeek-V4-Pro`,
 * `lmstudio/qwen3.8-27b-uncensored` — which is the one fact about a mixed
 * team that a reader cannot act on. It does not say who ran on what, what
 * those agents called themselves, which of them finished, or what the
 * expensive half of the bill was spent on. Ten agents and five models is the
 * most interesting thing on the page and it was five grey pills.
 *
 * So: one column per model, the agents on it named underneath with the names
 * they chose for themselves, a dot for how each one ended, and the model's
 * share of the spend. Every name is a link to that agent. On a narrow screen
 * the columns stack; when nothing was mixed there is one column and it still
 * says who is on it.
 */
import { Link } from "react-router-dom";
import type { AgentRow, SwarmView } from "@/lib/types";
import { money } from "@/lib/format";
import { cn } from "@/lib/utils";

type Marker = AgentRow["marker"];

/** done · still working · quiet · reaped. The same vocabulary as the Agents tab. */
function dotClass(marker: Marker): string {
  if (marker === "done") return "bg-moss";
  if (marker === "dead") return "bg-brick";
  if (marker === "stalled") return "bg-saffron";
  return "bg-kelp";
}

function markerWord(marker: Marker): string {
  if (marker === "done") return "finished";
  if (marker === "dead") return "reaped";
  if (marker === "stalled") return "quiet";
  return "working";
}

export function TeamStrip({ view }: { view: SwarmView }) {
  const byId = new Map(view.agents.map((a) => [a.id, a]));
  const nameOf = new Map((view.names ?? []).map((n) => [n.id, n]));
  const spendOf = (id: string) => view.budget?.agents?.[id]?.spent_usd ?? 0;

  // Model → the agents on it, in the order the kickoff assigned them.
  const groups: Array<{ model: string; agents: string[] }> = [];
  for (const member of view.team.agents) {
    const model = member.model || view.summary.model || "no model";
    const group = groups.find((g) => g.model === model);
    if (group) group.agents.push(member.id);
    else groups.push({ model, agents: [member.id] });
  }
  if (!groups.length) return null;

  const unmetered = view.budget?.metered === false;
  const total = groups.reduce((sum, g) => sum + g.agents.reduce((s, id) => s + spendOf(id), 0), 0);

  return (
    <div className="flex flex-wrap items-stretch gap-x-5 gap-y-3 rounded-xl border border-band-line bg-band-2/40 px-4 py-3">
      {groups.map((group) => {
        const spend = group.agents.reduce((s, id) => s + spendOf(id), 0);
        const share = total > 0 ? Math.round((spend / total) * 100) : 0;
        const [provider, ...rest] = group.model.split("/");
        return (
          <div key={group.model} className="min-w-[9.5rem] flex-1 basis-[9.5rem]">
            {/* Two lines, because a model name, its provider and its share of
                the bill on one line wrap in the middle of the name: the
                column read "grok-⏎4.6". The name never wraps now; the
                provider and the money sit under it. */}
            <div className="flex items-baseline justify-between gap-2">
              <span className="truncate font-mono text-[11.5px] text-band-ink" title={group.model}>
                {rest.join("/") || provider}
              </span>
              <span className="shrink-0 font-mono text-[10.5px] tabular text-band-ink-2">
                {unmetered ? "free" : spend > 0 ? money(spend, 2) : "—"}
              </span>
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <span className="truncate font-mono text-[10px] text-band-ink-2">{rest.length ? provider : ""}</span>
              <span className="shrink-0 font-mono text-[10px] tabular text-band-ink-2">
                {!unmetered && spend > 0 ? `${share}%` : ""}
              </span>
            </div>
            <div className="mt-1.5 h-px w-full bg-band-line" />
            <ul className="m-0 mt-1.5 flex list-none flex-col gap-1 p-0">
              {group.agents.map((id) => {
                const agent = byId.get(id);
                const chosen = nameOf.get(id);
                const marker = agent?.marker ?? "active";
                return (
                  <li key={id}>
                    <Link
                      to={`/swarms/${view.summary.id}/agents/${id}`}
                      title={`${chosen?.name ?? id} · ${markerWord(marker)}${chosen?.doing ? ` — ${chosen.doing}` : ""}`}
                      className="group flex items-center gap-1.5 no-underline"
                    >
                      <span className={cn("size-1.5 shrink-0 rounded-full", dotClass(marker))} />
                      <span className="truncate text-[12px] text-band-ink group-hover:underline">
                        {chosen?.name ?? id}
                      </span>
                      {chosen ? <span className="shrink-0 font-mono text-[10px] text-band-ink-2">{id.slice(-2)}</span> : null}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </div>
  );
}
