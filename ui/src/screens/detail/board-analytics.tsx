/**
 * What the board adds up to.
 *
 * The Every-post tab was a list of threads — on most runs, one thread — and
 * then half a page of nothing. But the board is the only record of how a
 * team that was never introduced to itself divided a case up, and all of it
 * is countable: who spoke and in what register, who named whom, when the
 * room went quiet, where somebody said stop, and which files the argument
 * was actually about.
 *
 * Five readings, none of them a summary written by a model. Every number
 * here is counted from the posts in `ui/src/lib/board.ts`, and every name is
 * a link to the agent that said it.
 */
import { useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { Hand, MessageSquareOff } from "lucide-react";
import { SerifH, TagChip } from "@/components/console";
import { ErrorState, LoadingState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { boardStats, TAGS, type BoardStats, type SpeakerRow } from "@/lib/board";
import { clock, compact, shortDuration } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import type { SwarmView, TimedPost } from "@/lib/types";
import { cn } from "@/lib/utils";

/** The tag palette, as fills rather than chips: the same seven colours. */
const TAG_FILL: Record<string, string> = {
  intro: "bg-slate",
  ask: "bg-saffron",
  claim: "bg-kelp",
  result: "bg-moss",
  hold: "bg-saffron",
  veto: "bg-brick",
  stop: "bg-brick",
};

/** Five names is a sentence; ten is a list nobody reads to the end. */
function nameList(list: string[], keep = 4): string {
  if (list.length <= keep) return list.join(", ");
  return `${list.slice(0, keep).join(", ")} and ${list.length - keep} more`;
}

function Card({ title, note, children, className }: { title: string; note?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("card flex min-w-0 flex-col gap-2.5 rounded-xl p-4", className)}>
      <div className="flex items-baseline justify-between gap-3">
        <SerifH as="h3" size={19}>
          {title}
        </SerifH>
        {note ? <span className="shrink-0 text-right text-[11.5px] leading-[1.35] text-ink-3">{note}</span> : null}
      </div>
      {children}
    </section>
  );
}

/** One figure with its caption, in the report's voice rather than a chip's. */
function Figure({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="min-w-0">
      <div className="label-caps">{label}</div>
      <div className="serif mt-0.5 truncate text-[22px] leading-none text-ink">{value}</div>
      {sub ? <div className="mt-1 text-[11.5px] leading-[1.35] text-ink-3">{sub}</div> : null}
    </div>
  );
}

/** The whole board as one bar: how much of it was result, ask, intro, friction. */
function TagBar({ tags, total, className }: { tags: BoardStats["tags"]; total: number; className?: string }) {
  if (!total) return null;
  return (
    <div className={cn("flex h-2.5 w-full overflow-hidden rounded-full bg-paper-3", className)} aria-hidden>
      {tags.map((t) => (
        <span key={t.tag} className={cn("block h-full", TAG_FILL[t.tag] ?? "bg-line-2")} style={{ width: `${(t.n / total) * 100}%` }} title={`${t.tag}: ${t.n}`} />
      ))}
    </div>
  );
}

function SpeakerLine({
  row,
  most,
  swarmId,
  colour,
  names,
}: {
  row: SpeakerRow;
  most: number;
  swarmId: string;
  colour: (id: string) => string;
  names: (id: string) => string;
}) {
  const tags = TAGS.map((tag) => ({ tag, n: row.tags[tag] ?? 0 })).filter((t) => t.n > 0);
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-baseline gap-x-3 gap-y-1 border-b border-line/70 py-1.5 last:border-b-0 sm:grid-cols-[minmax(0,11rem)_minmax(0,1fr)_2.5rem]">
      <Link
        to={`/swarms/${swarmId}/agents/${row.id}`}
        className="truncate font-mono text-[12.5px] font-medium no-underline hover:underline"
        style={{ color: colour(row.id) }}
        title={`${row.name ?? row.id} · ${row.id}`}
      >
        {row.name ?? names(row.id)}
      </Link>
      <span className="col-span-2 flex items-center gap-2 sm:col-span-1">
        <span className="flex h-2 min-w-0 flex-1 overflow-hidden rounded-full bg-paper-3" title={tags.map((t) => `${t.tag} ${t.n}`).join(" · ")}>
          {tags.map((t) => (
            <span key={t.tag} className={cn("block h-full", TAG_FILL[t.tag] ?? "bg-line-2")} style={{ width: `${(t.n / most) * 100}%` }} />
          ))}
        </span>
        <span className="shrink-0 font-mono text-[10.5px] text-ink-3">{compact(row.chars)} ch</span>
      </span>
      <span className="justify-self-end font-mono text-[12px] tabular text-ink-2">{row.posts}</span>
    </li>
  );
}

/**
 * Who named whom.
 *
 * A post addressed to `all` is still a post about somebody, so a row counts
 * every post in which that agent wrote another agent's id, plus the rare
 * directly addressed one. It is the closest thing the board has to a record
 * of who was working with whom — and the empty rows are as telling as the
 * full ones.
 */
function NamingMatrix({ stats, view, colour, names }: { stats: BoardStats; view: SwarmView; colour: (id: string) => string; names: (id: string) => string }) {
  const ids = useMemo(() => {
    const speaking = new Set(stats.speakers.map((s) => s.id));
    const named = new Set(stats.mentions.map((m) => m.to));
    return view.agents.map((a) => a.id).filter((id) => speaking.has(id) || named.has(id));
  }, [stats, view.agents]);
  const cell = useMemo(() => {
    const map = new Map<string, number>();
    for (const m of stats.mentions) map.set(`${m.from} ${m.to}`, m.n);
    return map;
  }, [stats.mentions]);
  const most = Math.max(1, ...stats.mentions.map((m) => m.n));
  if (ids.length < 2) return <p className="m-0 text-[12.5px] text-ink-2">Only one agent ever appeared on the board, so there is nobody to name.</p>;
  if (!stats.mentions.length)
    return (
      <p className="m-0 text-[12.5px] leading-[1.5] text-ink-2">
        Nobody ever named anybody. Every post on this board was addressed to the room, and no agent wrote another's id — a
        team working in parallel rather than together.
      </p>
    );
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-[11px]">
        <thead>
          <tr>
            <th className="w-[8.5rem] px-1 pb-1 text-left font-normal text-ink-3">named →</th>
            {ids.map((id) => (
              <th key={id} className="px-0.5 pb-1 text-center font-mono text-[10px] font-normal" style={{ color: colour(id) }} title={names(id)}>
                {id.slice(-2)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ids.map((from) => (
            <tr key={from}>
              <td className="max-w-[8.5rem] truncate py-0.5 pr-2 text-right font-mono text-[11px]" style={{ color: colour(from) }} title={names(from)}>
                {names(from)}
              </td>
              {ids.map((to) => {
                const n = from === to ? -1 : cell.get(`${from} ${to}`) ?? 0;
                return (
                  <td key={to} className="p-[1px] text-center align-middle">
                    {n < 0 ? (
                      <span className="mx-auto block size-[18px] rounded-[3px] bg-paper-2" aria-hidden />
                    ) : (
                      <span
                        className={cn("mx-auto flex size-[18px] items-center justify-center rounded-[3px] font-mono text-[9.5px] tabular", n ? "text-white" : "bg-paper-3 text-transparent")}
                        style={n ? { backgroundColor: colour(from), opacity: 0.35 + 0.65 * (n / most) } : undefined}
                        title={n ? `${names(from)} named ${names(to)} in ${n} post${n === 1 ? "" : "s"}` : `${names(from)} never named ${names(to)}`}
                      >
                        {n || "0"}
                      </span>
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FrictionList({ posts, colour, names, onOpen }: { posts: TimedPost[]; colour: (id: string) => string; names: (id: string) => string; onOpen: (thread: string) => void }) {
  if (!posts.length) {
    return (
      <p className="m-0 text-[12.5px] leading-[1.5] text-ink-2">
        Nobody held, vetoed or called a stop. The team divided the case and never had to block each other — worth knowing, and rarer than it sounds.
      </p>
    );
  }
  return (
    <ol className="m-0 flex list-none flex-col gap-2 p-0">
      {posts.map((p) => (
        <li key={`${p.thread}-${p.id}`}>
          <button
            type="button"
            onClick={() => onOpen(p.thread)}
            className="w-full rounded-lg border border-line bg-paper-2/50 px-2.5 py-2 text-left transition-colors hover:bg-paper-2"
          >
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px]">
              <TagChip tag={p.tag} />
              {p.from === "system" ? (
                <span className="rounded-[3px] bg-brick px-1.5 font-mono text-[10px] font-semibold uppercase text-white">harness</span>
              ) : null}
              <span className="font-mono font-medium" style={{ color: p.from === "system" ? "var(--brick-ink)" : colour(p.from) }}>
                {p.from === "system" ? "the harness" : p.name ?? names(p.from)}
              </span>
              <span className="font-mono text-ink-3">{clock(p.at)}</span>
              {p.to !== "all" ? <span className="text-ink-3">→ {names(p.to)}</span> : null}
            </div>
            <p className="m-0 mt-1 line-clamp-2 text-[12.5px] leading-[1.45] text-ink-2">{p.body.replace(/\s+/g, " ").trim()}</p>
          </button>
        </li>
      ))}
    </ol>
  );
}

function Artefacts({ stats, view, colour, names }: { stats: BoardStats; view: SwarmView; colour: (id: string) => string; names: (id: string) => string }) {
  const known = useMemo(() => new Set(view.work.map((w) => w.path)), [view.work]);
  if (!stats.artefacts.length) return <p className="m-0 text-[12.5px] text-ink-2">No post cited a path under the run's own directories.</p>;
  const most = stats.artefacts[0].n;
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
      {stats.artefacts.map((a) => (
        <li key={a.path} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2">
          {known.has(a.path) ? (
            <Link
              to={`/swarms/${view.summary.id}/files/${encodeURIComponent(a.path)}`}
              className="truncate font-mono text-[12px] text-ink no-underline hover:underline"
              title={`${a.path} — cited by ${a.by.map((id) => (id === "system" ? "the harness" : names(id))).join(", ")}`}
            >
              {a.path}
            </Link>
          ) : (
            <span
              className="truncate font-mono text-[12px] text-ink-2"
              title={`${a.path} — cited by ${a.by.map((id) => (id === "system" ? "the harness" : names(id))).join(", ")}. Not a file this run kept under work/.`}
            >
              {a.path}
            </span>
          )}
          <span className="flex items-center gap-1.5">
            <span className="flex items-center gap-0.5">
              {a.by.slice(0, 6).map((id) => (
                <span key={id} className="size-1.5 rounded-full" style={{ backgroundColor: id === "system" ? "var(--brick)" : colour(id) }} title={names(id)} />
              ))}
            </span>
            <span className="h-1.5 w-12 overflow-hidden rounded-full bg-paper-3">
              <span className="block h-full rounded-full bg-ink-3" style={{ width: `${(a.n / most) * 100}%` }} />
            </span>
            <span className="w-5 text-right font-mono text-[11px] tabular text-ink-3">{a.n}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

export function BoardAnalytics({ view, version, onOpenThread }: { view: SwarmView; version: number; onOpenThread: (thread: string) => void }) {
  const id = view.summary.id;
  const loader = useCallback(() => api.posts(id), [id]);
  const posts = useResource(loader, version, [id, "posts"]);
  const names = useAgentNames(view.agents);
  const colour = useAgentColours(view.agents);
  const stats = useMemo(
    () => (posts.data ? boardStats(posts.data, view.agents.map((a) => a.id)) : null),
    [posts.data, view.agents],
  );

  if (posts.error && !posts.data) return <ErrorState error={posts.error} onRetry={posts.reload} title="Could not read the board" />;
  if (!stats) return <LoadingState label="Reading every post" rows={4} />;
  if (!stats.posts) return null;

  const voices = stats.posts - stats.system;
  const most = Math.max(1, ...stats.speakers.map((s) => s.posts));
  const loudest = stats.mentions[0];
  const quiet = stats.silences[0];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-baseline gap-2 pt-1">
        <SerifH as="h2" size={24}>
          What the board adds up to
        </SerifH>
        <span className="text-[12px] text-ink-3">counted from the posts, not summarised by a model</span>
      </div>

      <section className="card rounded-xl p-4">
        <div className="grid grid-cols-2 gap-x-5 gap-y-4 sm:grid-cols-3 lg:grid-cols-6">
          <Figure
            label="Posts"
            value={stats.posts.toLocaleString()}
            sub={stats.system ? `${voices} by agents · ${stats.system} by the harness` : `across ${stats.threads} thread${stats.threads === 1 ? "" : "s"}`}
          />
          <Figure label="Written" value={`${compact(stats.chars)} ch`} sub={voices ? `${Math.round(stats.chars / Math.max(1, stats.posts))} characters a post` : undefined} />
          <Figure label="Spoke" value={`${stats.speakers.length} of ${view.agents.length}`} sub={stats.mute.length ? `${stats.mute.map((m) => names(m)).join(", ")} never posted` : "every agent said something"} />
          <Figure label="Span" value={shortDuration(stats.spanMs)} sub={stats.busiest ? `busiest minute ${clock(`${stats.busiest.minute}:00Z`)} · ${stats.busiest.n} posts` : undefined} />
          <Figure label="Median gap" value={shortDuration(stats.medianGapMs)} sub="between one post and the next" />
          <Figure
            label="Longest silence"
            value={quiet ? shortDuration(quiet.ms) : "—"}
            sub={quiet ? `broken by ${quiet.after.name ?? names(quiet.after.from)}` : undefined}
          />
        </div>
        <div className="mt-4 border-t border-line pt-3">
          <TagBar tags={stats.tags} total={voices} />
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
            {stats.tags.map((t) => (
              <span key={t.tag} className="inline-flex items-center gap-1.5 font-mono text-[11px] text-ink-2">
                <span className={cn("size-2 rounded-[2px]", TAG_FILL[t.tag] ?? "bg-line-2")} />
                {t.tag} <span className="tabular text-ink-3">{t.n}</span>
                <span className="text-ink-3">{Math.round((t.n / Math.max(1, voices)) * 100)}%</span>
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Two columns rather than a grid: a card is as tall as what it holds,
          and a long list of holds should not pull an empty half-page of
          whitespace along beside it. */}
      <div className="grid items-start gap-3 lg:grid-cols-2">
       <div className="flex min-w-0 flex-col gap-3">
        <Card title="Who spoke, and in what register" note={<>bar = this agent's tag mix,<br />scaled against the loudest</>}>
          <ul className="m-0 flex list-none flex-col p-0">
            {stats.speakers.map((row) => (
              <SpeakerLine key={row.id} row={row} most={most} swarmId={id} colour={colour} names={names} />
            ))}
          </ul>
          {stats.mute.length ? (
            <p className="m-0 flex items-start gap-1.5 text-[12px] leading-[1.45] text-ink-3">
              <MessageSquareOff className="mt-0.5 size-3.5 shrink-0" />
              {nameList(stats.mute.map((m) => names(m)))} never posted. An agent that says nothing cannot be corrected by anyone.
            </p>
          ) : null}
        </Card>

        <Card title="Where the board caught" note={`${stats.friction.length} hold / veto / stop`}>
          <div className={cn(stats.friction.length > 6 && "max-h-[32rem] overflow-y-auto pr-1")}>
            <FrictionList posts={stats.friction} colour={colour} names={names} onOpen={onOpenThread} />
          </div>
        </Card>
       </div>

       <div className="flex min-w-0 flex-col gap-3">
        <Card
          title="Who named whom"
          note={loudest ? `loudest: ${names(loudest.from)} → ${names(loudest.to)} (${loudest.n})` : undefined}
        >
          <NamingMatrix stats={stats} view={view} colour={colour} names={names} />
          <p className="m-0 text-[11.5px] leading-[1.45] text-ink-3">
            A cell counts the posts in which the row's agent wrote the column agent's id, plus posts addressed to it directly.
            {stats.unnamed.length ? <> Nobody ever named {nameList(stats.unnamed.map((u) => names(u)))}.</> : null}
          </p>
        </Card>

        <Card title="What it was about" note="paths the posts cited">
          <Artefacts stats={stats} view={view} colour={colour} names={names} />
        </Card>

        {stats.silences.length ? (
        <Card title="When the room went quiet" note="the three longest gaps between posts">
          <ol className="m-0 flex list-none flex-col gap-1.5 p-0">
            {stats.silences.map((s) => (
              <li key={`${s.before.thread}-${s.before.id}`} className="border-b border-line/70 pb-1.5 last:border-b-0 last:pb-0">
                <div className="flex flex-wrap items-baseline gap-x-2 text-[12px]">
                  <span className="font-mono tabular text-ink">{shortDuration(s.ms)}</span>
                  <span className="font-mono text-ink-3">from {clock(s.before.at)}</span>
                  <span className="text-ink-3">
                    after{" "}
                    <span className="font-medium" style={{ color: colour(s.before.from) }}>
                      {s.before.name ?? names(s.before.from)}
                    </span>
                  </span>
                </div>
                <p className="m-0 mt-0.5 line-clamp-2 text-[12px] leading-[1.45] text-ink-2">
                  broken by{" "}
                  <span className="font-medium" style={{ color: colour(s.after.from) }}>
                    {s.after.name ?? names(s.after.from)}
                  </span>
                  <span className="italic text-ink-3"> “{s.after.body.replace(/\s+/g, " ").trim().slice(0, 120)}”</span>
                </p>
              </li>
            ))}
          </ol>
        </Card>
        ) : null}
       </div>
      </div>

      <p className="m-0 flex items-start gap-1.5 text-[11px] leading-[1.45] text-ink-3">
        <Hand className="mt-0.5 size-3 shrink-0" />
        Every figure on this page is counted from `threads/` on disk. Nothing here is generated: a name is a link to the agent
        that wrote the post, and a path is a link to the file it cited.
      </p>
    </div>
  );
}
