/**
 * The board, as a story: the main thread folded into phases, with the
 * approvals on a hash pulled out as the sign-off and the harness's own posts
 * set in its own voice.
 */
import { runMilestones } from "@/lib/vm-timeline";
import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, ChevronRight, Hash } from "lucide-react";
import { ThreadPulse } from "@/components/activity-strip";
import { Chip, PhaseHead, SerifH, TagChip } from "@/components/console";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { clock, relTime } from "@/lib/format";
import { useResource } from "@/lib/live";
import { agreedHash, isApproval, storyOf, type Phase } from "@/lib/story";
import type { SwarmView, TimedPost } from "@/lib/types";
import { cn } from "@/lib/utils";

function PostCard({ post, highlight, colour, chosen, swarmId }: { post: TimedPost; highlight?: boolean; colour: (id: string) => string; chosen?: (id: string) => string | undefined; swarmId: string }) {
  const [open, setOpen] = useState(false);
  // A post from `system` sent by a seat's own harness code in its VM
  // (`via`) is that seat's word, not the harness's: it is drawn as the
  // seat's, never in the harness's band.
  const seatVia = post.from === "system" && post.via ? post.via : null;
  const system = post.from === "system" && !seatVia;
  const long = post.body.length > 420 || post.body.split("\n").length > 6;
  return (
    <article
      className={cn(
        "grid grid-cols-[74px_minmax(0,1fr)] gap-3.5 rounded-[10px] border px-4 py-3",
        system ? "border-band bg-band text-band-ink" : "border-paper-3 bg-card",
        highlight && !system && "border-kelp",
      )}
      style={system ? undefined : { borderLeft: `3px solid ${colour(seatVia ?? post.from)}` }}
    >
      {/*
        The author block: what the agent called itself first, its id under it,
        and the whole thing a link to that agent's own page. Nobody assigned
        these names — an agent picked one after reading the goal — so the name
        is the useful half, and a reader following a thread wants to jump from
        a post to the agent who wrote it rather than hunt for the id in a tab
        of ten.
      */}
      <div className="flex flex-col gap-1">
        {system ? (
          <span className="font-mono text-[12px] font-medium text-band-brick">system</span>
        ) : seatVia ? (
          <Link to={`/swarms/${swarmId}/agents/${seatVia}`} title={`Harness code in ${seatVia}'s VM posted this with that seat's authority, not the harness's`} className="group flex flex-col gap-0.5 no-underline">
            <span className="text-[12px] font-semibold leading-tight text-ink group-hover:underline">system via {seatVia}</span>
            <span className="text-[10.5px] leading-tight text-ink-3">harness code in its VM · the seat's word</span>
          </Link>
        ) : (
          <Link
            to={`/swarms/${swarmId}/agents/${post.from}`}
            title={`Open ${post.name ?? chosen?.(post.from) ?? post.from}`}
            className="group flex flex-col gap-0.5 no-underline"
          >
            {post.name ?? chosen?.(post.from) ? (
              <span className="text-[12px] font-semibold leading-tight text-ink group-hover:underline">
                {post.name ?? chosen?.(post.from)}
              </span>
            ) : null}
            <span className="font-mono text-[11px] font-medium leading-tight group-hover:underline" style={{ color: colour(post.from) }}>
              {post.from}
            </span>
          </Link>
        )}
        <TagChip tag={post.tag} from={seatVia ?? post.from} className="w-fit" />
        {post.at ? <span className={cn("font-mono text-[10.5px]", system ? "text-band-ink-2" : "text-ink-3")}>{clock(post.at)}</span> : null}
      </div>
      <div className="min-w-0">
        <pre className={cn("m-0 whitespace-pre-wrap break-words font-sans text-[13.5px] leading-[1.5] [text-wrap:pretty]", !open && long && "max-h-[8.5rem] overflow-hidden [mask-image:linear-gradient(to_bottom,black_70%,transparent)]")}>
          {post.body}
        </pre>
        {long ? (
          <button type="button" className={cn("mt-1 text-[12px] font-medium hover:underline", system ? "text-band-ink-2" : "text-kelp-ink")} onClick={() => setOpen((o) => !o)}>
            {open ? "Collapse" : "Show all"}
          </button>
        ) : null}
      </div>
    </article>
  );
}

/** Six intros are one line each: who took which slice. */
function JoiningChips({ posts, colour }: { posts: TimedPost[]; colour: (id: string) => string }) {
  return (
    <div className="flex flex-wrap gap-2">
      {posts.map((p) => {
        const first = p.body.replace(/^\s*[\w-]+:\s*/, "").split(/(?<=[.!?])\s/)[0] ?? p.body;
        return (
          <Chip key={p.id} tone="slate" className="h-auto min-h-[26px] max-w-full whitespace-normal py-1 text-[12px]">
            <span className="size-2 shrink-0 rounded-full" style={{ background: colour(p.from) }} />
            <span className="font-mono">{p.from}</span> {first.length > 90 ? `${first.slice(0, 89)}…` : first}
          </Chip>
        );
      })}
    </div>
  );
}

/** The threads the team opened beside main: what each is for, who is in it, and its pulse. */
function SideThreads({ view, colour, names }: { view: SwarmView; colour: (id: string) => string; names: (id: string) => string }) {
  const side = view.threads.filter((t) => t.name !== "main");
  if (!side.length) return null;
  const startedAt = view.summary.started_at || null;
  return (
    <div className="flex flex-col gap-2">
      <PhaseHead title="Side threads" summary={`${side.length} thread${side.length === 1 ? "" : "s"} opened beside main`} />
      <div className="grid gap-2 md:grid-cols-2">
        {side.map((t) => (
          <Link
            key={t.name}
            to={`/swarms/${view.summary.id}/threads/${encodeURIComponent(t.name)}`}
            className={cn("card flex flex-col gap-1.5 rounded-[10px] p-3 transition-colors hover:border-kelp/50", t.dim && "thread-dark")}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="thread-title inline-flex items-center gap-1 font-mono text-[13px] font-semibold text-ink">
                <Hash className="size-3.5 text-ink-3" /> {t.name}
              </span>
              <span className="font-mono text-[11px] tabular text-ink-3">
                {t.posts} msg{t.last_at ? ` · ${relTime(t.last_at)}` : ""}
              </span>
            </div>
            {t.purpose ? <p className="m-0 text-[12.5px] leading-[1.45] text-ink-2">{t.purpose}</p> : null}
            <ThreadPulse dots={t.activity} from={startedAt} to={view.summary.finished_at} colour={colour} names={names} />
            <div className="flex flex-wrap gap-1">
              {(t.members?.length ? t.members : [...new Set(t.activity.map((d) => d.from))]).map((m) => (
                <span key={m} className="inline-flex items-center gap-1 font-mono text-[11px]" style={{ color: colour(m) }}>
                  <span className="size-1.5 rounded-full" style={{ background: colour(m) }} /> {names(m)}
                </span>
              ))}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function SignoffCard({ posts }: { posts: TimedPost[] }) {
  const agreed = agreedHash(posts);
  const approvals = posts.filter(isApproval);
  return (
    <div className="card flex flex-col gap-2.5 rounded-xl border-moss p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-[13.5px] text-ink">
          <strong>{approvals.length}</strong> approval{approvals.length === 1 ? "" : "s"}
          {agreed ? (
            <>
              {" "}
              on <span className="font-mono text-[12px]">{agreed.hash.slice(0, 12)}…</span>
            </>
          ) : null}
        </span>
        {agreed ? <Chip tone={agreed.by.length >= 2 ? "moss" : "saffron"}>{agreed.by.length >= 2 ? "two agents agree" : "one agent so far"}</Chip> : null}
      </div>
      <div className="flex flex-col gap-2">
        {approvals.map((p) => (
          <div key={p.id} className="grid grid-cols-[74px_minmax(0,1fr)] gap-3.5 text-[13px]">
            <span className="font-mono text-[12px] text-ink">{p.from}</span>
            <span className="text-ink-2">{p.body.replace(/^approved\s+\S+\s*(—|-)?\s*/i, "")}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PhaseBlock({ phase, collapsed, onToggle, colour, chosen, swarmId }: { phase: Phase; collapsed: boolean; onToggle: () => void; colour: (id: string) => string; chosen?: (id: string) => string | undefined; swarmId: string }) {
  const canFold = phase.kind === "joining" || phase.posts.length > 6;
  return (
    <div className="flex flex-col gap-2">
      <button type="button" onClick={canFold ? onToggle : undefined} className={cn("text-left", canFold && "cursor-pointer")} aria-expanded={!collapsed}>
        <PhaseHead
          title={phase.title}
          summary={
            <>
              {phase.summary}
              {canFold ? collapsed ? <ChevronRight className="ml-1 inline size-3.5" /> : <ChevronDown className="ml-1 inline size-3.5" /> : null}
            </>
          }
        />
      </button>
      {collapsed ? null : phase.kind === "joining" ? (
        <JoiningChips posts={phase.posts} colour={colour} />
      ) : phase.kind === "signoff" ? (
        <>
          <SignoffCard posts={phase.posts} />
          {phase.posts.filter((p) => !isApproval(p)).map((p) => (
            <PostCard key={p.id} post={p} colour={colour} chosen={chosen} swarmId={swarmId} />
          ))}
        </>
      ) : (
        <div className={cn("flex flex-col gap-2", phase.kind === "negotiating" && phase.posts.length > 2 && "md:grid md:grid-cols-2")}>
          {phase.posts.map((p) => (
            <PostCard key={p.id} post={p} highlight={p.tag === "claim"} colour={colour} chosen={chosen} swarmId={swarmId} />
          ))}
        </div>
      )}
    </div>
  );
}

export function StoryPanel({ view, version }: { view: SwarmView; version: number }) {
  // A post written before its author named itself still shows the name it
  // took later: names.json is the record, the post is a copy of the moment.
  const chosenOf = useMemo(() => {
    const map = new Map<string, string>();
    for (const n of view.names ?? []) map.set(n.id, n.name);
    return (id: string) => map.get(id);
  }, [view.names]);
  const id = view.summary.id;
  const loader = useCallback(() => api.thread(id, "main"), [id]);
  const posts = useResource(loader, version, [id]);
  const [collapsed, setCollapsed] = useState<Record<number, boolean>>({});
  const phases = useMemo(() => storyOf(posts.data ?? []), [posts.data]);
  const colour = useAgentColours(view.agents);
  const names = useMemo(() => {
    const map = new Map(view.agents.filter((a) => a.callsign).map((a) => [a.id, a.callsign as string]));
    return (id: string) => map.get(id) ?? id;
  }, [view.agents]);
  const waiting = view.agents.filter((a) => !a.done && !a.dead);
  const lastTool = useMemo(() => {
    const m = new Map<string, string>();
    for (const e of view.traces) m.set(e.agent, e.tool);
    return m;
  }, [view.traces]);

  if (posts.error && !posts.data) return <ErrorState error={posts.error} onRetry={posts.reload} title="Could not read threads/main" />;
  if (!posts.data) return <LoadingState label="Reading the board" rows={4} />;
  if (posts.data.length === 0) {
    return <EmptyState title="Nothing on the board yet" hint="threads/main appears with the first post. Agents introduce themselves, then split the work." />;
  }

  return (
    <div className="flex flex-col gap-3.5">
      <RunLifecycle view={view} />
      <SerifH size={28}>The board, as a story</SerifH>
      {phases.map((phase, i) => {
        // Joining folds by default once the team is past it; everything else opens.
        const defaultCollapsed = phase.kind === "joining" && phases.length > 1 && i < phases.length - 1 && phase.posts.length > 3;
        const isCollapsed = collapsed[i] ?? defaultCollapsed;
        return <PhaseBlock chosen={chosenOf} key={i} phase={phase} collapsed={isCollapsed} onToggle={() => setCollapsed((c) => ({ ...c, [i]: !isCollapsed }))} colour={colour} swarmId={view.summary.id} />;
      })}
      <SideThreads view={view} colour={colour} names={names} />
      {view.summary.phase === "running" && waiting.length ? (
        <div className="flex flex-col gap-2">
          <PhaseHead title="Right now" summary={`${waiting.filter((a) => lastTool.get(a.id) === "wait").length} in wait — nobody is polling`} />
          <div className="flex flex-wrap gap-2">
            {waiting.map((a) => {
              const t = lastTool.get(a.id) ?? "idle";
              return (
                <Chip key={a.id} tone={t === "wait" || t === "idle" ? "neutral" : "kelp"} className="h-7">
                  <span className="size-2 shrink-0 rounded-full" style={{ background: colour(a.id) }} />
                  <span className="font-mono">{a.id}</span> {t === "wait" ? "waiting on the board" : t}
                </Chip>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}

/**
 * A VM run's own milestones, which the board never tells: the VMs up and
 * what their probes found, the keeper bringing back a hub or a collector,
 * seats stopped at their cap, the VMs put away with their disks, msb's
 * database cleared, and the custody verdict. Nothing for a host run.
 */
function RunLifecycle({ view }: { view: SwarmView }) {
  const steps = runMilestones(view.vms ?? [], view.custody ?? null);
  if (!steps.length) return null;
  return (
    <section className="flex flex-wrap items-center gap-1.5 text-[12px]" aria-label="The run's VM lifecycle">
      <span className="label-caps mr-1">The VMs</span>
      {steps.map((s, i) => (
        <Chip key={i} tone={s.tone} wrap>
          {s.what}
        </Chip>
      ))}
    </section>
  );
}
