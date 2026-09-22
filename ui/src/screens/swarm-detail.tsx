import { useCallback, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Skull, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Chip, Meter, Vital, VitalsBand } from "@/components/console";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { JobCard } from "@/components/jobs-drawer";
import { ActivityStrip } from "@/components/activity-strip";
import { TeamStrip } from "@/components/team-strip";
import { api, ApiError } from "@/lib/api";
import { compact, liveElapsed, mmss, money } from "@/lib/format";
import { useNow } from "@/lib/hooks";
import { useLive, useResource, useSwarmVersion } from "@/lib/live";
import { CHECKS_CHANGE_KINDS } from "@/lib/live-version";
import type { SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";
import { StoryPanel } from "./detail/story-panel";
import { FinishLinePanel } from "./detail/finish-line";
import { GRACE_MS, HarnessPanel, LeasesPanel, TeamPanel } from "./detail/instruments";
import { ThreadsPanel } from "./detail/threads-panel";
import { AgentsPanel } from "./detail/agents-panel";
import { TracesPanel } from "./detail/traces-panel";
import { ClaimsPanel } from "./detail/claims-panel";
import { BudgetPanel } from "./detail/budget-panel";
import { FilesPanel } from "./detail/files-panel";
import { InputsPanel } from "./detail/inputs-panel";
import { ReportPanel } from "./detail/report-panel";
import { ArtifactsPanel } from "./detail/artifacts-panel";
import { GoalPanel } from "./detail/goal-panel";
import { PacksPanel } from "./detail/packs-panel";
import { ToolsPanel } from "./detail/tools-panel";
import { LedgerPanel } from "./detail/ledger-panel";

/**
 * Four groups, not eleven peers. The strip had grown to eleven tabs with no
 * order to it, and the evidence hashes were hidden inside `files` where
 * nobody looks for them. Grouping says what each tab is for: the run, the
 * evidence it read and produced, the frame it ran under, and the output.
 */
const TAB_GROUPS = [
  { label: "The run", tabs: ["story", "threads", "traces", "agents"] },
  { label: "Evidence", tabs: ["files", "artifacts", "ledger"] },
  { label: "The frame", tabs: ["goal", "packs", "tools", "claims", "budget"] },
  { label: "Output", tabs: ["report"] },
] as const;
const TABS = TAB_GROUPS.flatMap((g) => g.tabs);
type Tab = (typeof TAB_GROUPS)[number]["tabs"][number];
const TAB_LABEL: Record<Tab, string> = {
  story: "Story",
  threads: "Every post",
  traces: "Raw trace",
  agents: "Agents",
  tools: "Tools",
  ledger: "Ledger",
  claims: "Claims",
  budget: "Budget",
  files: "Files",
  artifacts: "Artifacts",
  goal: "Goal",
  packs: "Packs",
  report: "Report",
};

function ActionBar({ view }: { view: SwarmView }) {
  const live = useLive();
  const [stopOpen, setStopOpen] = useState(false);
  const [reapOpen, setReapOpen] = useState(false);
  const [stall, setStall] = useState("90");
  const [closePanes, setClosePanes] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const job = jobId ? live.jobs[jobId] ?? null : null;
  const id = view.summary.id;
  const canStop = view.summary.state === "running" || view.summary.state === "prepared";

  async function run(fn: () => Promise<{ id: string }>) {
    setError(null);
    try {
      const j = await fn();
      setJobId(j.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    }
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex gap-2">
        <Button variant="secondary" size="sm" className="h-9 border-band-line bg-transparent text-band-ink hover:bg-band-2" onClick={() => setReapOpen(true)} disabled={view.summary.phase === "done"}>
          <Skull /> Reap stalled
        </Button>
        <Button variant="danger" size="sm" className="h-9" onClick={() => setStopOpen(true)} disabled={!canStop} title={canStop ? "swarm.sh stop" : "Already stopped"}>
          <Square className="fill-current" /> Stop swarm
        </Button>
      </div>
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      {job ? (
        <div className="w-full max-w-[520px] text-left">
          <JobCard job={job} compact />
        </div>
      ) : null}

      <Dialog open={stopOpen} onOpenChange={setStopOpen}>
        <DialogContent>
          <DialogTitle>Stop {view.summary.label}?</DialogTitle>
          <DialogDescription>
            Runs <code>scripts/swarm.sh stop {id}</code>: closes the Herdr workspace(s), kills the netguard sidecar, marks the registry <code>stopped</code>. Files in the sandbox stay. This does not write <code>SWARM_DONE</code>.
          </DialogDescription>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setStopOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => {
                setStopOpen(false);
                void run(() => api.stop(id));
              }}
            >
              <Square className="fill-current" /> Stop swarm
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={reapOpen} onOpenChange={setReapOpen}>
        <DialogContent>
          <DialogTitle>Reap stalled agents in {view.summary.label}</DialogTitle>
          <DialogDescription>
            Runs <code>scripts/swarm.sh reap {id} --stall-sec N</code>: any agent silent longer than N seconds gets <code>done/agents/&lt;id&gt;.dead</code>, its leases dropped and a <code>reap</code> trace line. Idempotent.
          </DialogDescription>
          <div className="mt-4 grid gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="stall">Stall threshold (seconds)</Label>
              <Input id="stall" inputMode="numeric" value={stall} onChange={(e) => setStall(e.target.value)} className="w-32 tabular" />
            </div>
            <label className="flex items-center justify-between gap-3 text-[13px]">
              <span>
                Also close the agent's Herdr pane (<code>--stop</code>)
              </span>
              <Switch checked={closePanes} onCheckedChange={setClosePanes} />
            </label>
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setReapOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="warn"
              disabled={!/^\d+$/.test(stall) || Number(stall) < 1}
              onClick={() => {
                setReapOpen(false);
                void run(() => api.reap(id, { stall_sec: Number(stall), stop: closePanes }));
              }}
            >
              <Skull /> Reap now
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function SwarmDetailScreen() {
  const { id = "", tab: rawTab, sub } = useParams();
  const navigate = useNavigate();
  // The view reads nearly everything, so it keys on every kind. Each panel
  // keys on what its own request reads, and nothing else: a claim landing
  // while you read the trace refetches the leases in the view, not the trace
  // page. The finish line runs the goal's own shell checks, so it keys on
  // everything a check could read — which is everything but a lease and a
  // spend fold.
  const version = useSwarmVersion(id);
  const threadsVersion = useSwarmVersion(id, ["threads"]);
  const eventsVersion = useSwarmVersion(id, ["events"]);
  const historyVersion = useSwarmVersion(id, ["history"]);
  const toolsVersion = useSwarmVersion(id, ["tools"]);
  const contractVersion = useSwarmVersion(id, ["contract"]);
  const checksVersion = useSwarmVersion(id, CHECKS_CHANGE_KINDS);
  const loader = useCallback(() => api.swarm(id), [id]);
  const view = useResource(loader, version, [id]);
  const now = useNow(1000);
  const tab: Tab = (TABS as readonly string[]).includes(rawTab ?? "") ? (rawTab as Tab) : "story";

  const setTab = useCallback((next: string) => navigate(`/swarms/${id}/${next}`), [navigate, id]);
  const setSub = useCallback((t: Tab, s: string | null) => navigate(s ? `/swarms/${id}/${t}/${encodeURIComponent(s)}` : `/swarms/${id}/${t}`), [navigate, id]);

  const elapsedLive = useMemo(() => (view.data ? liveElapsed(view.data.summary, now) : 0), [view.data, now]);

  if (view.error && !view.data) {
    const notFound = view.error instanceof ApiError && view.error.status === 404;
    return (
      <div className="mx-auto w-full max-w-[1680px] space-y-3 px-4 py-6 sm:px-10">
        <Link to="/" className="inline-flex items-center gap-1 text-[12px] text-ink-2 hover:text-ink">
          <ArrowLeft className="size-3.5" /> Swarms
        </Link>
        {notFound ? (
          <EmptyState title={`No swarm “${id}”`} hint="It is not in runs/registry.json. It may have been started with another SWARM_RUNS_DIR, or the id is mistyped." />
        ) : (
          <ErrorState error={view.error} onRetry={view.reload} title="Could not load this swarm" />
        )}
      </div>
    );
  }
  if (!view.data) {
    return (
      <div className="mx-auto w-full max-w-[1680px] space-y-3 px-4 py-6 sm:px-10">
        <LoadingState label={`Reading ${id}`} rows={5} />
      </div>
    );
  }

  const d = view.data;
  const s = d.summary;
  const b = d.budget;
  // A team of local models is not charged: its cap is in tokens, and the
  // header measures it that way rather than showing "$0.00 of $0.00".
  const unmetered = b.metered === false;
  const capTokens = typeof b.cap_tokens === "number" && b.cap_tokens > 0 ? b.cap_tokens : 0;
  const capPct = unmetered ? (capTokens > 0 ? (b.tokens / capTokens) * 100 : 0) : s.cap_usd > 0 ? (s.spent_usd / s.cap_usd) * 100 : 0;
  const overCap = unmetered ? capTokens > 0 && b.tokens >= capTokens : s.cap_usd > 0 && s.spent_usd >= s.cap_usd;
  const wallMs = s.wall_clock_minutes * 60_000;
  const wallPct = wallMs > 0 ? (elapsedLive / wallMs) * 100 : 0;
  const overWall = wallMs > 0 && elapsedLive > wallMs;
  const working = d.agents.filter((a) => !a.done && !a.dead).length;
  const doneN = d.agents.filter((a) => a.done).length;
  const deadN = d.agents.filter((a) => a.dead).length;
  // Silent for the stall window but not reaped: in a long tool call, or idle.
  // Not dead, and the header used to say so.
  const stalledN = d.agents.filter((a) => a.stalled && !a.dead && !a.done).length;
  /** Started, never reached a marker: a provider error, a killed turn, a pane that went away. */
  const unmarkedN = d.agents.filter((a) => !a.done && !a.dead).length;
  const steeredAt = b.stop_steer_at ? Date.parse(b.stop_steer_at) : NaN;
  const steering = Number.isFinite(steeredAt) && !d.sentinel && s.phase === "running";
  const graceLeft = steering ? Math.max(0, steeredAt + GRACE_MS - now) : 0;
  const harnessStopped = s.phase === "done" && d.sentinel_info?.by === "harness";

  const stateChip = steering ? (
    <Chip tone="brick" className="bg-brick text-white">
      over {b.stop_reason === "wall_clock" ? "wall clock" : "cap"} · steered
    </Chip>
  ) : harnessStopped ? (
    <Chip tone="brick" className="bg-brick text-white">
      stopped by harness
    </Chip>
  ) : s.phase === "running" ? (
    <Chip tone="kelp" className="bg-kelp text-white">
      running
    </Chip>
  ) : s.phase === "done" ? (
    <Chip tone="moss" className="bg-moss text-white">
      done
    </Chip>
  ) : (
    <Chip tone="band">{s.phase}</Chip>
  );

  return (
    <div className="flex flex-col">
      <VitalsBand>
        <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-5 px-4 py-[22px] sm:px-10">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex min-w-0 flex-col gap-2">
              <nav className="flex items-center gap-2 text-[12.5px] text-band-ink-2" aria-label="Breadcrumb">
                <Link to="/" className="text-band-ink-2 hover:text-band-ink">
                  Swarms
                </Link>
                <span>/</span>
                <span className="text-band-ink">{s.label}</span>
              </nav>
              <div className="flex flex-wrap items-baseline gap-3.5">
                <h1 className="serif m-0 text-[40px] leading-none">{s.label}</h1>
                <span className="font-mono text-[13px] text-band-ink-2">{s.id}</span>
                {stateChip}
                {view.refreshing ? <span className="text-[11px] text-band-ink-2">syncing…</span> : null}
              </div>
              {/*
                The settings this run was started with used to sit here as four
                chips — Herdr panes, hard-kill, tool forging, the inputs guard
                — in the most valuable strip on the page, and every one of them
                was already stated where it is used: the Tools tab says forging
                is on, the Harness panel says hard-kill is off, the Inputs
                panel names the guard per pane. They are now in one place that
                answers the whole question, "How this run was started" on the
                Goal tab, and the band keeps only what an operator could not
                find elsewhere: something that went wrong.
              */}
              {typeof d.layout?.split_failures === "number" && d.layout.split_failures > 0 ? (
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="saffron">{d.layout.split_failures} pane split{d.layout.split_failures === 1 ? "" : "s"} fell back to a new tab</Chip>
                </div>
              ) : null}
            </div>
            <ActionBar view={d} />
          </div>
          {/* The numbers and the team, side by side. The strip spent a week
              under the title, which left the right half of the band empty at
              every width and made a box of names look like the subject of the
              page. The three vitals are what an operator watches; the team is
              what they look up. Both fit the band, neither dominates it. */}
          <div className="grid items-start gap-x-8 gap-y-5 lg:grid-cols-[minmax(0,560px)_minmax(0,1fr)]">
          <div className="grid gap-x-8 gap-y-4 sm:grid-cols-3">
          <Vital
            label={unmetered ? "Tokens / cap" : "Spend / cap"}
            value={unmetered ? compact(b.tokens) : money(s.spent_usd, 2)}
            tail={
              unmetered
                ? capTokens > 0
                  ? `of ${compact(capTokens)}${overCap ? ` · ${(capPct / 100).toFixed(1)}×` : ""}`
                  : "no token cap"
                : overCap
                  ? `of ${money(s.cap_usd, 2)} · ${(capPct / 100).toFixed(1)}×`
                  : `of ${money(s.cap_usd, 2)}`
            }
            tone={overCap ? "brick" : capPct >= 80 ? "saffron" : undefined}
            meter={<Meter pct={capPct} tone={overCap ? "brick" : capPct >= 80 ? "saffron" : "kelp"} onDark label={unmetered ? "tokens against cap" : "spend against cap"} />}
            sub={
              unmetered
                ? overCap
                  ? `${compact(b.tokens - capTokens)} tokens over the cap`
                  : `free · no metered cost${capTokens > 0 ? ` · ${compact(capTokens - b.tokens)} left` : ""}`
                : overCap
                  ? `${money(s.spent_usd - s.cap_usd)} over the cap`
                  : `${money(Math.max(0, s.cap_usd - s.spent_usd), 2)} left of ${money(s.cap_usd, 2)}`
            }
          />
          <Vital
            label={s.phase === "done" ? "Took" : "Wall clock"}
            value={mmss(elapsedLive)}
            tail={wallMs ? `of ${mmss(wallMs)}` : undefined}
            tone={overWall ? "saffron" : undefined}
            meter={<Meter pct={wallPct} tone={overWall ? "saffron" : "band"} onDark label="elapsed against wall clock" />}
          />
          <Vital
            label="Agents"
            // The denominator is the point. A finished run used to read
            // "6 done" when ten agents had started: four of them had ended a
            // provider error or a terminated turn away from a marker, and the
            // header counted only the ones that made it. A reader cannot tell
            // 6 of 6 from 6 of 10, and on the BelkaCTF run the difference was
            // two dead providers.
            value={`${s.phase === "done" ? doneN : working} of ${d.agents.length}`}
            tail={
              s.phase === "done"
                ? `done${unmarkedN ? ` · ${unmarkedN} unfinished` : ""}${deadN ? ` · ${deadN} dead` : ""}`
                : `working · ${doneN} done${deadN ? ` · ${deadN} dead` : ""}${stalledN ? ` · ${stalledN} quiet` : ""}`
            }
            sub={`${compact(s.tokens)} tokens · ${compact(s.calls)} calls`}
          />
          </div>
          {/* Who is doing this, not which identifiers were passed to Pi. */}
          <TeamStrip view={d} />
          </div>

          {/*
            The sections, in the band rather than on the paper. Navigation is
            chrome: it belonged with the run's own identity, not at the top of
            the reader's page, where it took four rows of the most-read area
            and pushed the work itself below the fold. Here it is one row, the
            groups separated by a rule instead of by four labels that looked
            like tabs nobody could click.
          */}
          <div className="-mb-[6px] flex flex-wrap items-center gap-x-1 gap-y-2 pt-1" role="tablist" aria-label="Swarm sections">
            {TAB_GROUPS.map((group, gi) => (
              <div key={group.label} className="flex flex-wrap items-center gap-1" role="group" aria-label={group.label}>
                {gi > 0 ? <span aria-hidden className="mx-2 h-4 w-px bg-band-line" /> : null}
                {group.tabs.map((t) => (
                  <button
                    key={t}
                    type="button"
                    role="tab"
                    aria-selected={tab === t}
                    title={group.label}
                    onClick={() => setTab(t)}
                    className={cn(
                      "h-[30px] rounded-full px-3 text-[12.5px] font-medium transition-colors",
                      tab === t ? "bg-band-ink text-band" : "text-band-ink-2 hover:bg-band-2 hover:text-band-ink",
                    )}
                  >
                    {TAB_LABEL[t]}
                    <span className="ml-1 font-mono text-[11px] opacity-60">
                      {t === "threads" && d.threads.length ? d.threads.reduce((a, th) => a + th.posts, 0) : ""}
                      {t === "traces" ? s.calls : ""}
                      {t === "claims" && d.violations.length ? d.violations.length : ""}
                      {t === "artifacts" && d.work.length ? d.work.length : ""}
                      {t === "tools" && d.tools.length ? d.tools.length : ""}
                      {t === "ledger" && d.ledger?.entries.length ? d.ledger.entries.length : ""}
                    </span>
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      </VitalsBand>

      {steering ? (
        <section className="border-b border-line bg-card">
          <div className="mx-auto grid w-full max-w-[1680px] items-center gap-6 px-4 py-6 sm:px-10 lg:grid-cols-[minmax(0,1fr)_220px]">
            <div className="flex flex-col gap-3.5">
              <div className="flex flex-wrap items-baseline gap-4">
                <span className="serif text-[56px] leading-none text-brick-ink tabular">{mmss(graceLeft)}</span>
                <span className="serif text-[26px] leading-[1.1] text-ink">
                  until the harness writes <span className="font-mono text-[20px]">done/SWARM_DONE</span> itself
                </span>
              </div>
              <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3.5">
                <div className="flex flex-col gap-0.5">
                  <span className="label-caps">steered</span>
                  <span className="font-mono text-[13px]">{new Date(steeredAt).toLocaleTimeString()}</span>
                </div>
                <Meter pct={((GRACE_MS - graceLeft) / GRACE_MS) * 100} tone="brick" className="h-2.5" label="grace period" />
                <div className="flex flex-col gap-0.5 text-right">
                  <span className="label-caps">sentinel</span>
                  <span className="font-mono text-[13px]">{new Date(steeredAt + GRACE_MS).toLocaleTimeString()}</span>
                </div>
              </div>
              <p className="m-0 max-w-[720px] text-[13.5px] leading-[1.5] text-ink-2 [text-wrap:pretty]">
                Every agent was told to call <span className="font-mono">done(cannot_complete)</span> and has not. One clock for the whole swarm: the grace period is measured from the same instant by every agent, and only one of them will create the sentinel.
              </p>
            </div>
            <div className="text-[11.5px] text-ink-3">
              Stop now with the button above, or raise the cap from the shell — <span className="font-mono">budget.json</span> is re-read every 15 s and a raised cap clears the clock.
            </div>
          </div>
        </section>
      ) : null}

      <div className="mx-auto grid w-full max-w-[1680px] gap-7 px-4 py-[26px] sm:px-10 lg:grid-cols-[minmax(0,1fr)_440px]">
        <section className="flex min-w-0 flex-col gap-3.5">
          {tab === "story" ? <StoryPanel view={d} version={threadsVersion} /> : null}
          {tab === "threads" ? <ThreadsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(t) => setSub("threads", t)} version={threadsVersion} /> : null}
          {tab === "traces" ? <TracesPanel view={d} version={eventsVersion} initialAgent={sub ? decodeURIComponent(sub) : undefined} /> : null}
          {tab === "agents" ? <AgentsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(a) => setSub("agents", a)} version={eventsVersion} /> : null}
          {tab === "claims" ? <ClaimsPanel view={d} now={now} /> : null}
          {tab === "budget" ? <BudgetPanel view={d} elapsedMs={elapsedLive} /> : null}
          {tab === "files" ? (
            <div className="space-y-4">
              <InputsPanel view={d} />
              <FilesPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(p) => setSub("files", p)} version={historyVersion} />
            </div>
          ) : null}
          {tab === "artifacts" ? <ArtifactsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(p) => setSub("artifacts", p)} /> : null}
          {tab === "goal" ? <GoalPanel view={d} version={contractVersion} /> : null}
          {tab === "tools" ? <ToolsPanel view={d} selected={sub ? decodeURIComponent(sub) : null} onSelect={(t) => setSub("tools", t)} version={toolsVersion} /> : null}
          {tab === "packs" ? <PacksPanel view={d} /> : null}
          {tab === "ledger" ? <LedgerPanel view={d} /> : null}
          {tab === "report" ? <ReportPanel view={d} /> : null}
        </section>

        <aside className="flex flex-col gap-4">
          <FinishLinePanel view={d} version={checksVersion} />
          <LeasesPanel view={d} now={now} />
          <TeamPanel view={d} onSelect={(a) => setSub("agents", a)} />
          <HarnessPanel view={d} now={now} onShowTraces={() => setTab("traces")} />
        </aside>
      </div>

      {/* the rhythm of the whole run, always in view */}
      <div className="sticky bottom-0 z-30 border-t border-line bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/85">
        <div className="mx-auto w-full max-w-[1680px] px-4 py-2 sm:px-10">
          <ActivityStrip series={d.activity} />
        </div>
      </div>
    </div>
  );
}
